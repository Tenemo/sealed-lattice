use crate::transcript::part;
use parallel_work::{Job, Part, Pipeline, submit, window};
use stateful_sha3::{Digest, Sha3_512};
use std::{collections::BTreeSet, io::Write};
use zeroize::{Zeroize, Zeroizing};

const LEAF_DOMAIN: &[u8] = b"bounded-proof/leaf";

/// A contiguous subtree's inner nodes from its leaves' digests.
pub static NODES: Job = Job {
    kind: 0x0150,
    run: subtree_nodes,
};
/// A contiguous range's leaf digests from its salts and rows, then the
/// inner nodes of the subtree above them.
pub static LEAVES: Job = Job {
    kind: 0x0151,
    run: subtree_leaves,
};

/// The most leaves one subtree job covers.
const SUBTREE_LEAVES: usize = 1 << 14;

/// The public start of every inner node hash of a level.
fn node_prefix(role: &[u8], stage: usize, level: usize) -> Sha3_512 {
    let mut prefix = Sha3_512::new();
    part(&mut prefix, b"bounded-proof/node");
    part(&mut prefix, role);
    part(&mut prefix, &(stage as u32).to_le_bytes());
    part(&mut prefix, &(level as u32).to_le_bytes());
    prefix
}
fn node(prefix: &Sha3_512, left: &[u8], right: &[u8]) -> [u8; 64] {
    let mut hash = prefix.clone();
    part(&mut hash, left);
    part(&mut hash, right);
    hash.finalize().into()
}
// A subtree job's role, stage and leaf count, then the bytes that follow
// them.
fn subtree_header(input: &[u8]) -> (&[u8], usize, usize, &[u8]) {
    let role_length = usize::from(u16::from_le_bytes([input[0], input[1]]));
    let (role, rest) = input[2..].split_at(role_length);
    let number = |bytes: &[u8]| u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let (stage, leaves) = (number(rest), number(&rest[4..]));
    assert!(leaves.is_power_of_two() && (2..=SUBTREE_LEAVES).contains(&leaves));
    (role, stage, leaves, &rest[8..])
}
// Appends the inner nodes above the level's digests, level by level.
fn append_nodes(role: &[u8], stage: usize, mut digests: Vec<[u8; 64]>, output: &mut Vec<u8>) {
    let mut level = 1;
    while digests.len() > 1 {
        let prefix = node_prefix(role, stage, level);
        digests = digests
            .chunks_exact(2)
            .map(|pair| node(&prefix, &pair[0], &pair[1]))
            .collect();
        for digest in &digests {
            output.extend(digest);
        }
        level += 1;
    }
}
fn subtree_nodes(input: &[u8]) -> Vec<u8> {
    let (role, stage, leaves, digests) = subtree_header(input);
    assert_eq!(digests.len(), 64 * leaves);
    let mut output = Vec::with_capacity(64 * (leaves - 1));
    let digests = digests
        .chunks_exact(64)
        .map(|digest| digest.try_into().unwrap())
        .collect();
    append_nodes(role, stage, digests, &mut output);
    output
}
fn subtree_leaves(input: &[u8]) -> Vec<u8> {
    let (role, stage, leaves, rest) = subtree_header(input);
    let number = |bytes: &[u8]| u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let (first, width) = (number(rest), number(&rest[4..]));
    let (salts, rows) = rest[8..].split_at(128 * leaves);
    assert_eq!(rows.len(), width * leaves);
    let prefix = leaf_prefix(role, stage);
    let digests: Vec<[u8; 64]> = salts
        .chunks_exact(128)
        .zip(rows.chunks_exact(width))
        .enumerate()
        .map(|(offset, (salt, row))| {
            let mut hash = leaf_start(&prefix, first + offset, salt.try_into().unwrap(), width);
            hash.update(row);
            hash.finalize().into()
        })
        .collect();
    let mut output = Vec::with_capacity(64 * (2 * leaves - 1));
    for digest in &digests {
        output.extend(digest);
    }
    append_nodes(role, stage, digests, &mut output);
    output
}

pub fn leaf_prefix_bytes(role_bytes: usize) -> usize {
    4 + LEAF_DOMAIN.len() + 4 + role_bytes + 2 * (4 + 4) + 4 + 128 + 4
}

/// The public start of every leaf hash of a role and stage.
pub fn leaf_prefix(role: &[u8], stage: usize) -> Sha3_512 {
    let mut hash = Sha3_512::new();
    part(&mut hash, LEAF_DOMAIN);
    part(&mut hash, role);
    part(&mut hash, &(stage as u32).to_le_bytes());
    hash
}
/// A leaf's hash before its row: the prefix, its index, salt and row width.
pub fn leaf_start(prefix: &Sha3_512, index: usize, salt: &[u8; 128], width: usize) -> Sha3_512 {
    let mut hash = prefix.clone();
    part(&mut hash, &(index as u32).to_le_bytes());
    part(&mut hash, salt);
    hash.update((width as u32).to_le_bytes());
    hash
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
        leaf_prefix(&self.role, self.stage)
    }
    // The caller retains this public prefix only while role and stage remain fixed.
    pub fn leaf_hasher(&self, index: usize, prefix: &Sha3_512) -> Sha3_512 {
        assert!(index < self.length);
        leaf_start(prefix, index, &self.salts[index], self.width)
    }
    pub fn leaf(&mut self, index: usize, hasher: Sha3_512) {
        self.nodes[self.length + index] = hasher.finalize().into();
    }
    fn subtree_leaves(&self) -> usize {
        SUBTREE_LEAVES.min(self.length)
    }
    // The start of a subtree job's input: the role, stage and leaf count.
    fn subtree_header(&self) -> Vec<u8> {
        let mut header = Vec::from((self.role.len() as u16).to_le_bytes());
        header.extend(&self.role);
        header.extend((self.stage as u32).to_le_bytes());
        header.extend((self.subtree_leaves() as u32).to_le_bytes());
        header
    }
    // Writes a subtree job's inner nodes, level by level, above the leaves
    // from the first.
    fn place_nodes(&mut self, first: usize, nodes: &[u8]) {
        let mut nodes = nodes.chunks_exact(64);
        let mut level = 1;
        while self.subtree_leaves() >> level > 0 {
            let start = (self.length + first) >> level;
            for index in start..start + (self.subtree_leaves() >> level) {
                self.nodes[index].copy_from_slice(nodes.next().unwrap());
            }
            level += 1;
        }
        assert!(nodes.next().is_none());
    }
    // Hashes the levels above the subtrees.
    fn finish_above_subtrees(&mut self) {
        let mut level = self.subtree_leaves().ilog2() as usize + 1;
        let mut start = self.length >> level;
        while start > 0 {
            let prefix = node_prefix(&self.role, self.stage, level);
            for index in start..2 * start {
                self.nodes[index] =
                    node(&prefix, &self.nodes[2 * index], &self.nodes[2 * index + 1]);
            }
            start /= 2;
            level += 1;
        }
    }
    /// Hashes every inner node from the leaves' digests.
    pub fn finish(&mut self) {
        let leaves = self.subtree_leaves();
        let header = self.subtree_header();
        let mut pipeline = Pipeline::new(window());
        let mut subtrees = Vec::new();
        for first in (0..self.length).step_by(leaves) {
            let digests = self.nodes[self.length + first..][..leaves].as_flattened();
            let ticket = submit(
                &NODES,
                None,
                &[Part::Bytes(&header), Part::Bytes(digests)],
                64 * (leaves - 1),
            );
            subtrees.extend(pipeline.push(first, ticket));
            for (first, nodes) in subtrees.drain(..) {
                self.place_nodes(first, &nodes);
            }
        }
        for (first, nodes) in pipeline.finish() {
            self.place_nodes(first, &nodes);
        }
        self.finish_above_subtrees();
    }
    /// Hashes every leaf from its salt and its row of the width, in row
    /// order, and every inner node above them.
    pub fn hash_rows(&mut self, rows: &[u8]) {
        assert_eq!(rows.len(), self.length * self.width);
        let leaves = self.subtree_leaves();
        let header = self.subtree_header();
        let mut pipeline = Pipeline::new(window());
        let mut outputs = Vec::new();
        for first in (0..self.length).step_by(leaves) {
            let mut input = Zeroizing::new(Vec::with_capacity(8 + (128 + self.width) * leaves));
            input.extend((first as u32).to_le_bytes());
            input.extend((self.width as u32).to_le_bytes());
            input.extend(self.salts[first..first + leaves].as_flattened());
            input.extend(&rows[self.width * first..self.width * (first + leaves)]);
            let ticket = submit(
                &LEAVES,
                None,
                &[Part::Bytes(&header), Part::Bytes(&input)],
                64 * (2 * leaves - 1),
            );
            outputs.extend(pipeline.push(first, ticket));
            for (first, output) in outputs.drain(..) {
                self.place_leaves(first, &output);
            }
        }
        for (first, output) in pipeline.finish() {
            self.place_leaves(first, &output);
        }
        self.finish_above_subtrees();
    }
    fn place_leaves(&mut self, first: usize, output: &[u8]) {
        let (digests, nodes) = output.split_at(64 * self.subtree_leaves());
        for (offset, digest) in digests.chunks_exact(64).enumerate() {
            self.nodes[self.length + first + offset].copy_from_slice(digest);
        }
        self.place_nodes(first, nodes);
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

    #[test]
    fn subtree_jobs_hash_the_complete_tree_across_several_subtrees() {
        let (length, width, stage) = (4 * SUBTREE_LEAVES, 48, 5u32);
        let role = b"subtree-regression".to_vec();
        let salts: Vec<[u8; 128]> = (0..length)
            .map(|index| std::array::from_fn(|byte| (index * 7 + byte) as u8))
            .collect();
        let rows: Vec<u8> = (0..length * width)
            .map(|index| (index % 251) as u8)
            .collect();
        let mut reference = vec![[0; 64]; 2 * length];
        for index in 0..length {
            reference[length + index] = hash(
                LEAF_DOMAIN,
                &[
                    &role,
                    &stage.to_le_bytes(),
                    &(index as u32).to_le_bytes(),
                    &salts[index],
                    &rows[width * index..width * (index + 1)],
                ],
            );
        }
        for node in (1..length).rev() {
            let level = length.ilog2() - node.ilog2();
            reference[node] = hash(
                b"bounded-proof/node",
                &[
                    &role,
                    &stage.to_le_bytes(),
                    &level.to_le_bytes(),
                    &reference[2 * node],
                    &reference[2 * node + 1],
                ],
            );
        }
        let tree = |nodes| Tree {
            length,
            width,
            stage: stage as usize,
            role: role.clone(),
            salts: salts.clone(),
            nodes,
        };
        let mut hashed = tree(vec![[0; 64]; 2 * length]);
        hashed.hash_rows(&rows);
        assert_eq!(hashed.nodes, reference);
        let mut leaves = vec![[0; 64]; 2 * length];
        leaves[length..].copy_from_slice(&reference[length..]);
        let mut finished = tree(leaves);
        finished.finish();
        assert_eq!(finished.nodes, reference);
    }
}
