use crate::transcript::part;
use stateful_sha3::{Digest, Sha3_512};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const LEAF_DOMAIN: &[u8] = b"bounded-proof/leaf";

pub fn leaf_prefix_bytes(role_bytes: usize) -> usize {
    4 + LEAF_DOMAIN.len() + 4 + role_bytes + 2 * (4 + 4) + 4 + 128 + 4
}

pub struct Tree {
    pub length: usize,
    pub width: usize,
    pub stage: usize,
    pub role: Vec<u8>,
    pub salts: Vec<[u8; 128]>,
    pub nodes: Vec<[u8; 64]>,
}
impl Drop for Tree {
    fn drop(&mut self) {
        self.salts.zeroize();
    }
}
impl Tree {
    pub fn new(role: &[u8], stage: usize, length: usize, width: usize) -> Self {
        assert!(length.is_power_of_two() && length >= 2);
        let mut salts = vec![[0; 128]; length];
        let mut bytes = Zeroizing::new(vec![0; 65536]);
        for group in salts.chunks_mut(bytes.len() / 128) {
            let length = group.len() * 128;
            crate::random::fill(&mut bytes[..length]);
            for (salt, value) in group.iter_mut().zip(bytes[..length].chunks_exact(128)) {
                salt.copy_from_slice(value);
            }
        }
        Self {
            length,
            width,
            stage,
            role: role.to_vec(),
            salts,
            nodes: vec![[0; 64]; 2 * length],
        }
    }
    pub fn leaf_hash_prefix(&self) -> Sha3_512 {
        let mut hash = Sha3_512::new();
        part(&mut hash, LEAF_DOMAIN);
        part(&mut hash, &self.role);
        part(&mut hash, &(self.stage as u32).to_le_bytes());
        hash
    }
    // The caller retains this public prefix only while role and stage remain fixed.
    pub fn leaf_hasher(&self, index: usize, prefix: &Sha3_512) -> Sha3_512 {
        assert!(index < self.length);
        let mut hash = prefix.clone();
        part(&mut hash, &(index as u32).to_le_bytes());
        part(&mut hash, &self.salts[index]);
        hash.update((self.width as u32).to_le_bytes());
        hash
    }
    pub fn leaf(&mut self, index: usize, hasher: Sha3_512) {
        self.nodes[self.length + index] = hasher.finalize().into();
    }
    pub fn finish(&mut self) {
        let mut start = self.length / 2;
        let mut level = 1;
        while start > 0 {
            let mut prefix = Sha3_512::new();
            part(&mut prefix, b"bounded-proof/node");
            part(&mut prefix, &self.role);
            part(&mut prefix, &(self.stage as u32).to_le_bytes());
            part(&mut prefix, &(level as u32).to_le_bytes());
            for index in start..2 * start {
                let mut hash = prefix.clone();
                part(&mut hash, &self.nodes[2 * index]);
                part(&mut hash, &self.nodes[2 * index + 1]);
                self.nodes[index] = hash.finalize().into();
            }
            start /= 2;
            level += 1;
        }
    }
    pub fn root(&self) -> [u8; 64] {
        self.nodes[1]
    }
    pub fn opening(&self, index: usize, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len(), self.width);
        let mut output = Vec::from((index as u32).to_le_bytes());
        output.extend(data);
        output.extend(self.salts[index]);
        let mut node = self.length + index;
        while node > 1 {
            output.extend(self.nodes[node ^ 1]);
            node /= 2;
        }
        output
    }
    pub fn write_multiproof<W: Write>(
        &self,
        indices: &[usize],
        payloads: &[&[u8]],
        output: &mut W,
    ) {
        assert_eq!(indices.len(), payloads.len());
        assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
        output
            .write_all(&(indices.len() as u32).to_le_bytes())
            .unwrap();
        let mut known = BTreeSet::new();
        for (&index, data) in indices.iter().zip(payloads) {
            assert!(index < self.length);
            assert_eq!(data.len(), self.width);
            output.write_all(&(index as u32).to_le_bytes()).unwrap();
            output.write_all(data).unwrap();
            output.write_all(&self.salts[index]).unwrap();
            let mut node = self.length + index;
            while node > 1 && !known.contains(&node) {
                known.insert(node);
                if known.insert(node ^ 1) {
                    output.write_all(&self.nodes[node ^ 1]).unwrap();
                }
                node /= 2;
            }
        }
    }
    pub fn save(&self, directory: &Path, name: &str) {
        let mut file = BufWriter::with_capacity(
            1 << 20,
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join(name))
                .unwrap(),
        );
        for node in &self.nodes {
            file.write_all(node).unwrap();
        }
        for salt in &self.salts {
            file.write_all(salt).unwrap();
        }
        file.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::hash;
    use stateful_sha3::digest::common::hazmat::SerializableState;

    #[test]
    fn cached_prefixes_preserve_complete_tree_bytes_at_block_boundaries() {
        for role_length in [1, 29, 30, 31, 37, 38, 39, 40, 266, 272, 282, 1024] {
            for stage in [0, 1, 18] {
                for width in [48, 144, 288] {
                    let length = 8usize;
                    let role: Vec<_> = (0..role_length).map(|index| (index % 251) as u8).collect();
                    let salts = (0..length)
                        .map(|index| std::array::from_fn(|byte| (index + byte) as u8))
                        .collect();
                    let mut tree = Tree {
                        length,
                        width,
                        stage,
                        role,
                        salts,
                        nodes: vec![[0; 64]; 2 * length],
                    };
                    let mut reference = tree.nodes.clone();
                    let prefix = tree.leaf_hash_prefix();
                    for index in 0..length {
                        let data: Vec<_> = (0..width)
                            .map(|byte| ((index + byte) % 251) as u8)
                            .collect();
                        reference[length + index] = hash(
                            LEAF_DOMAIN,
                            &[
                                &tree.role,
                                &(stage as u32).to_le_bytes(),
                                &(index as u32).to_le_bytes(),
                                &tree.salts[index],
                                &data,
                            ],
                        );
                        let mut cached = tree.leaf_hasher(index, &prefix);
                        let mut direct = Sha3_512::new();
                        for part_bytes in [
                            LEAF_DOMAIN,
                            &tree.role,
                            &(stage as u32).to_le_bytes(),
                            &(index as u32).to_le_bytes(),
                            &tree.salts[index],
                        ] {
                            part(&mut direct, part_bytes);
                        }
                        direct.update((width as u32).to_le_bytes());
                        assert_eq!(cached.serialize(), direct.serialize());
                        for chunk in data.chunks(13) {
                            cached.update(chunk);
                            direct.update(chunk);
                            assert_eq!(cached.serialize(), direct.serialize());
                        }
                        tree.leaf(index, cached);
                    }
                    for node in (1..length).rev() {
                        let level = length.ilog2() - node.ilog2();
                        reference[node] = hash(
                            b"bounded-proof/node",
                            &[
                                &tree.role,
                                &(stage as u32).to_le_bytes(),
                                &level.to_le_bytes(),
                                &reference[2 * node],
                                &reference[2 * node + 1],
                            ],
                        );
                    }
                    tree.finish();
                    assert_eq!(tree.nodes, reference);
                }
            }
        }
    }
}
