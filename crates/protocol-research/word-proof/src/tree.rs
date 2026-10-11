//! A salted Merkle commitment. Each tree draws one secret seed and expands
//! every leaf's salt from it and the leaf's index, so the tree keeps no
//! salts. It keeps its leaves' digests and its inner nodes above the lowest
//! levels, and an opening recomputes those levels from the leaves' digests.
//! A tree whose rows its owner can compute again may forget its leaves'
//! digests once committed; an opening then hashes the leaves of each block
//! below a queried leaf's lowest kept node again from their rows.
use crate::transcript::part;
use parallel_work::ProtocolHash;
use parallel_work::{Job, Part, Pipeline, submit, window};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};
use zeroize::{Zeroize, Zeroizing};

const LEAF_DOMAIN: &[u8] = b"bounded-proof/leaf";
const SALT_DOMAIN: &[u8] = b"bounded-proof/salt";
/// The bytes of the secret seed from which a tree expands its leaves' salts.
pub const SALT_SEED_BYTES: usize = 64;
/// The bytes of one leaf's salt.
pub const SALT_BYTES: usize = 128;
/// The inner levels just above the leaves that a tree does not keep.
const RECOMPUTED_LEVELS: usize = 4;

/// A contiguous subtree's kept inner nodes from its leaves' digests.
pub static NODES: Job = Job {
    kind: 0x0150,
    run: subtree_nodes,
};
/// A contiguous range's leaf digests from the tree's salt seed and its rows,
/// then the kept inner nodes of the subtree above them.
pub static LEAVES: Job = Job {
    kind: 0x0151,
    run: subtree_leaves,
};

/// The most leaves one subtree job covers.
pub(crate) const SUBTREE_LEAVES: usize = 1 << 14;

/// The public start of every inner node hash of a level.
fn node_prefix(role: &[u8], stage: usize, level: usize) -> ProtocolHash {
    let mut prefix = ProtocolHash::new();
    part(&mut prefix, b"bounded-proof/node");
    part(&mut prefix, role);
    part(&mut prefix, &(stage as u32).to_le_bytes());
    part(&mut prefix, &(level as u32).to_le_bytes());
    prefix
}
fn node(prefix: &ProtocolHash, left: &[u8], right: &[u8]) -> [u8; 64] {
    let mut hash = prefix.clone();
    part(&mut hash, left);
    part(&mut hash, right);
    hash.finalize()
}
/// The inner levels above the leaves of a tree of the length that the tree
/// recomputes instead of keeping, which leaves it at least its root.
fn recomputed_levels(length: usize) -> usize {
    RECOMPUTED_LEVELS.min(length.ilog2() as usize - 1)
}
/// A leaf's salt: SHAKE256 over the salt domain, the tree's seed and the
/// leaf's index, each framed by its length.
pub fn salt(seed: &[u8; SALT_SEED_BYTES], index: usize) -> Zeroizing<[u8; SALT_BYTES]> {
    let mut state = Shake256::default();
    for bytes in [SALT_DOMAIN, seed.as_slice(), &(index as u32).to_le_bytes()] {
        Update::update(&mut state, &(bytes.len() as u32).to_le_bytes());
        Update::update(&mut state, bytes);
    }
    let mut salt = Zeroizing::new([0; SALT_BYTES]);
    XofReader::read(&mut state.finalize_xof(), salt.as_mut_slice());
    salt
}
// A subtree job's role, stage, leaf count and the levels it leaves out, then
// the bytes that follow them.
fn subtree_header(input: &[u8]) -> (&[u8], usize, usize, usize, &[u8]) {
    let role_length = usize::from(u16::from_le_bytes([input[0], input[1]]));
    let (role, rest) = input[2..].split_at(role_length);
    let number = |bytes: &[u8]| u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let (stage, leaves, omitted) = (number(rest), number(&rest[4..]), number(&rest[8..]));
    assert!(leaves.is_power_of_two() && (2..=SUBTREE_LEAVES).contains(&leaves));
    assert!(omitted < leaves.ilog2() as usize);
    (role, stage, leaves, omitted, &rest[12..])
}
/// The bytes of a subtree's inner nodes above the omitted levels.
fn kept_node_bytes(leaves: usize, omitted: usize) -> usize {
    64 * ((leaves >> omitted) - 1)
}
// Appends the inner nodes above the level's digests, level by level, from
// the first level above the omitted ones.
fn append_nodes(
    role: &[u8],
    stage: usize,
    omitted: usize,
    mut digests: Vec<[u8; 64]>,
    output: &mut Vec<u8>,
) {
    let mut level = 1;
    while digests.len() > 1 {
        let prefix = node_prefix(role, stage, level);
        let parents = digests.len() / 2;
        for index in 0..parents {
            digests[index] = node(&prefix, &digests[2 * index], &digests[2 * index + 1]);
        }
        digests.truncate(parents);
        if level > omitted {
            for digest in &digests {
                output.extend(digest);
            }
        }
        level += 1;
    }
}
fn subtree_nodes(input: &[u8]) -> Vec<u8> {
    let (role, stage, leaves, omitted, digests) = subtree_header(input);
    assert_eq!(digests.len(), 64 * leaves);
    let mut output = Vec::with_capacity(kept_node_bytes(leaves, omitted));
    let digests = digests
        .chunks_exact(64)
        .map(|digest| digest.try_into().unwrap())
        .collect();
    append_nodes(role, stage, omitted, digests, &mut output);
    output
}
fn subtree_leaves(input: &[u8]) -> Vec<u8> {
    let (role, stage, leaves, omitted, rest) = subtree_header(input);
    let number = |bytes: &[u8]| u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let (first, width) = (number(rest), number(&rest[4..]));
    let seed: &[u8; SALT_SEED_BYTES] = rest[8..8 + SALT_SEED_BYTES].try_into().unwrap();
    let rows = &rest[8 + SALT_SEED_BYTES..];
    assert_eq!(rows.len(), width * leaves);
    let prefix = leaf_prefix(role, stage);
    let digests: Vec<[u8; 64]> = rows
        .chunks_exact(width)
        .enumerate()
        .map(|(offset, row)| {
            let index = first + offset;
            let mut hash = leaf_start(&prefix, index, &salt(seed, index), width);
            hash.update(row);
            hash.finalize()
        })
        .collect();
    let mut output = Vec::with_capacity(64 * leaves + kept_node_bytes(leaves, omitted));
    for digest in &digests {
        output.extend(digest);
    }
    append_nodes(role, stage, omitted, digests, &mut output);
    output
}

pub fn leaf_message_prefix_bytes(role_bytes: usize) -> usize {
    4 + LEAF_DOMAIN.len() + 4 + role_bytes + 2 * (4 + 4) + 4 + SALT_BYTES + 4
}

/// The public start of every leaf hash of a role and stage.
pub fn leaf_prefix(role: &[u8], stage: usize) -> ProtocolHash {
    let mut hash = ProtocolHash::new();
    part(&mut hash, LEAF_DOMAIN);
    part(&mut hash, role);
    part(&mut hash, &(stage as u32).to_le_bytes());
    hash
}
/// A leaf's hash before its row: the prefix, its index, salt and row width.
pub fn leaf_start(
    prefix: &ProtocolHash,
    index: usize,
    salt: &[u8; SALT_BYTES],
    width: usize,
) -> ProtocolHash {
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
    seed: Zeroizing<[u8; SALT_SEED_BYTES]>,
    // The leaves' digests, in leaf order, until the tree forgets them.
    leaves: Vec<[u8; 64]>,
    forgotten: bool,
    // The kept inner nodes in heap order: node `i` has the children `2 i`
    // and `2 i + 1`, and node one is the root.
    upper: Vec<[u8; 64]>,
}
impl Tree {
    pub fn new(role: &[u8], stage: usize, length: usize, width: usize) -> Self {
        let mut seed = Zeroizing::new([0; SALT_SEED_BYTES]);
        crate::random::fill(seed.as_mut_slice());
        Self::with_seed(role, stage, length, width, seed)
    }
    /// A tree whose leaves' salts expand from the seed.
    pub fn with_seed(
        role: &[u8],
        stage: usize,
        length: usize,
        width: usize,
        seed: Zeroizing<[u8; SALT_SEED_BYTES]>,
    ) -> Self {
        assert!(length.is_power_of_two() && length >= 2);
        Self {
            length,
            width,
            stage,
            role: role.to_vec(),
            seed,
            leaves: vec![[0; 64]; length],
            forgotten: false,
            upper: vec![[0; 64]; length >> recomputed_levels(length)],
        }
    }
    /// Forgets the leaves' digests, those committed and those still to come.
    pub fn forget_leaves(&mut self) {
        self.leaves = Vec::new();
        self.forgotten = true;
    }
    // The leaves of a block below one of the lowest kept inner nodes.
    fn block_leaves(&self) -> usize {
        1 << (recomputed_levels(self.length) + 1)
    }
    // The leaves whose rows an opening of the indices reads: the indices,
    // or every leaf of their blocks when the tree forgot its leaves.
    fn opening_leaves(&self, indices: &[usize]) -> Vec<usize> {
        if !self.forgotten {
            return indices.to_vec();
        }
        let span = self.block_leaves();
        let blocks: BTreeSet<usize> = indices.iter().map(|index| index / span).collect();
        blocks
            .into_iter()
            .flat_map(|block| span * block..span * (block + 1))
            .collect()
    }
    // Hashes the leaves of each block of the opening leaves again from their
    // rows, in the leaves' order, for the multiproof's records. Each block
    // must hash to its kept node.
    fn restore<T: AsRef<[u8]>>(&self, multiproof: &mut Multiproof, leaves: &[usize], rows: &[T]) {
        let span = self.block_leaves();
        let levels = recomputed_levels(self.length);
        assert!(leaves.len() == rows.len() && leaves.len().is_multiple_of(span));
        let mut header = Vec::from((self.role.len() as u16).to_le_bytes());
        header.extend(&self.role);
        header.extend((self.stage as u32).to_le_bytes());
        header.extend((span as u32).to_le_bytes());
        header.extend((levels as u32).to_le_bytes());
        let output = 64 * span + kept_node_bytes(span, levels);
        let mut pipeline = Pipeline::new(window());
        let mut restored = Vec::new();
        for (block, rows) in leaves.chunks_exact(span).zip(rows.chunks_exact(span)) {
            let first = block[0];
            assert!(first.is_multiple_of(span) && block.iter().copied().eq(first..first + span));
            let mut input =
                Zeroizing::new(Vec::with_capacity(8 + SALT_SEED_BYTES + self.width * span));
            input.extend((first as u32).to_le_bytes());
            input.extend((self.width as u32).to_le_bytes());
            input.extend(self.seed.as_slice());
            for row in rows {
                assert_eq!(row.as_ref().len(), self.width);
                input.extend(row.as_ref());
            }
            let ticket = submit(
                &LEAVES,
                None,
                &[Part::Bytes(&header), Part::Bytes(&input)],
                output,
            );
            restored.extend(pipeline.push(first, ticket));
            for (first, output) in restored.drain(..) {
                self.place_restored(multiproof, first, &output);
            }
        }
        for (first, output) in pipeline.finish() {
            self.place_restored(multiproof, first, &output);
        }
    }
    fn place_restored(&self, multiproof: &mut Multiproof, first: usize, output: &[u8]) {
        let span = self.block_leaves();
        let (digests, node) = output.split_at(64 * span);
        let ancestor = (self.length + first) / span;
        assert_eq!(node, self.upper[ancestor], "Restored block");
        for (offset, digest) in digests.chunks_exact(64).enumerate() {
            multiproof
                .restored
                .insert(first + offset, digest.try_into().unwrap());
        }
    }
    /// The rows of the indices, from the function that gives the rows of
    /// their opening leaves in the leaves' order: the indices themselves, or
    /// every leaf of their blocks when the tree forgot its leaves, whose
    /// digests the multiproof then holds again. The rows of those blocks'
    /// other leaves, which the opening does not reveal, are zeroized.
    pub fn opened_rows<T: AsRef<[u8]> + Zeroize>(
        &self,
        multiproof: &mut Multiproof,
        indices: &[usize],
        rows: impl FnOnce(&[usize]) -> Vec<T>,
    ) -> Vec<T> {
        let leaves = self.opening_leaves(indices);
        let rows = rows(&leaves);
        assert_eq!(rows.len(), leaves.len());
        if !self.forgotten {
            return rows;
        }
        self.restore(multiproof, &leaves, &rows);
        let mut rows: Vec<Option<T>> = rows.into_iter().map(Some).collect();
        let opened = indices
            .iter()
            .map(|index| rows[leaves.binary_search(index).unwrap()].take().unwrap())
            .collect();
        for row in rows.iter_mut().flatten() {
            row.zeroize();
        }
        opened
    }
    /// The secret seed of the leaves' salts.
    pub fn seed(&self) -> &[u8; SALT_SEED_BYTES] {
        &self.seed
    }
    /// A leaf's salt.
    pub fn salt(&self, index: usize) -> Zeroizing<[u8; SALT_BYTES]> {
        assert!(index < self.length);
        salt(&self.seed, index)
    }
    #[cfg(test)]
    pub fn leaf_hash_prefix(&self) -> ProtocolHash {
        leaf_prefix(&self.role, self.stage)
    }
    // The caller retains this public prefix only while role and stage remain fixed.
    #[cfg(test)]
    pub fn leaf_hasher(&self, index: usize, prefix: &ProtocolHash) -> ProtocolHash {
        leaf_start(prefix, index, &self.salt(index), self.width)
    }
    #[cfg(test)]
    pub fn leaf(&mut self, index: usize, hasher: ProtocolHash) {
        self.leaves[index] = hasher.finalize();
    }
    fn subtree_leaves(&self) -> usize {
        SUBTREE_LEAVES.min(self.length)
    }
    // The start of a subtree job's input: the role, stage, leaf count and
    // the levels the tree does not keep.
    fn subtree_header(&self) -> Vec<u8> {
        let mut header = Vec::from((self.role.len() as u16).to_le_bytes());
        header.extend(&self.role);
        header.extend((self.stage as u32).to_le_bytes());
        header.extend((self.subtree_leaves() as u32).to_le_bytes());
        header.extend((recomputed_levels(self.length) as u32).to_le_bytes());
        header
    }
    // Writes a subtree job's kept inner nodes, level by level, above the
    // leaves from the first.
    fn place_nodes(&mut self, first: usize, nodes: &[u8]) {
        let mut nodes = nodes.chunks_exact(64);
        let mut level = recomputed_levels(self.length) + 1;
        while self.subtree_leaves() >> level > 0 {
            let start = (self.length + first) >> level;
            for index in start..start + (self.subtree_leaves() >> level) {
                self.upper[index].copy_from_slice(nodes.next().unwrap());
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
                self.upper[index] =
                    node(&prefix, &self.upper[2 * index], &self.upper[2 * index + 1]);
            }
            start /= 2;
            level += 1;
        }
    }
    /// Hashes every kept inner node from the leaves' digests.
    #[cfg(test)]
    pub fn finish(&mut self) {
        let leaves = self.subtree_leaves();
        let digests: Vec<Vec<[u8; 64]>> = self.leaves.chunks(leaves).map(<[_]>::to_vec).collect();
        self.finish_from(digests.into_iter());
    }
    /// Hashes every kept inner node from the leaves' digests, which arrive
    /// a subtree at a time in leaf order, and keeps the digests unless the
    /// tree forgets its leaves.
    pub fn finish_from(&mut self, subtrees: impl Iterator<Item = Vec<[u8; 64]>>) {
        let leaves = self.subtree_leaves();
        let header = self.subtree_header();
        let output = kept_node_bytes(leaves, recomputed_levels(self.length));
        let mut pipeline = Pipeline::new(window());
        let mut placed = Vec::new();
        let mut first = 0;
        for digests in subtrees {
            assert_eq!(digests.len(), leaves);
            let ticket = submit(
                &NODES,
                None,
                &[Part::Bytes(&header), Part::Bytes(digests.as_flattened())],
                output,
            );
            if !self.forgotten {
                self.leaves[first..first + leaves].copy_from_slice(&digests);
            }
            placed.extend(pipeline.push(first, ticket));
            for (first, nodes) in placed.drain(..) {
                self.place_nodes(first, &nodes);
            }
            first += leaves;
        }
        assert_eq!(first, self.length);
        for (first, nodes) in pipeline.finish() {
            self.place_nodes(first, &nodes);
        }
        self.finish_above_subtrees();
    }
    /// Hashes every leaf from its salt and its row of the width, which the
    /// function appends by the leaf's index, and every kept inner node above
    /// them.
    pub fn hash_rows(&mut self, row: impl Fn(usize, &mut Vec<u8>)) {
        let leaves = self.subtree_leaves();
        let header = self.subtree_header();
        let output = 64 * leaves + kept_node_bytes(leaves, recomputed_levels(self.length));
        let mut pipeline = Pipeline::new(window());
        let mut outputs = Vec::new();
        for first in (0..self.length).step_by(leaves) {
            let mut input = Zeroizing::new(Vec::with_capacity(
                8 + SALT_SEED_BYTES + self.width * leaves,
            ));
            input.extend((first as u32).to_le_bytes());
            input.extend((self.width as u32).to_le_bytes());
            input.extend(self.seed.as_slice());
            for index in first..first + leaves {
                row(index, &mut input);
            }
            assert_eq!(input.len(), 8 + SALT_SEED_BYTES + self.width * leaves);
            let ticket = submit(
                &LEAVES,
                None,
                &[Part::Bytes(&header), Part::Bytes(&input)],
                output,
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
        if !self.forgotten {
            for (offset, digest) in digests.chunks_exact(64).enumerate() {
                self.leaves[first + offset].copy_from_slice(digest);
            }
        }
        self.place_nodes(first, nodes);
    }
    pub fn root(&self) -> [u8; 64] {
        self.upper[1]
    }
    // The node at the heap index: a leaf's digest, a kept inner node, or a
    // recomputed one from the block of leaves below its lowest kept
    // ancestor. The block serves every recomputed node of the paths of the
    // leaves below that ancestor, so a multiproof keeps only the last one.
    fn node(&self, index: usize, multiproof: &mut Multiproof) -> [u8; 64] {
        let leaf = |index: usize, restored: &BTreeMap<usize, [u8; 64]>| {
            if self.forgotten {
                restored[&index]
            } else {
                self.leaves[index]
            }
        };
        if index >= self.length {
            return leaf(index - self.length, &multiproof.restored);
        }
        if index < self.upper.len() {
            return self.upper[index];
        }
        let levels = recomputed_levels(self.length);
        let depth = self.length.ilog2() as usize - index.ilog2() as usize;
        // The kept ancestor is `levels + 1 - depth` levels above the node.
        let ancestor = index >> (levels + 1 - depth);
        if multiproof
            .block
            .as_ref()
            .is_none_or(|block| block.ancestor != ancestor)
        {
            let span = 1 << (levels + 1);
            let first = (ancestor << (levels + 1)) - self.length;
            let mut nodes = vec![[0; 64]; 2 * span];
            for (offset, node) in nodes[span..].iter_mut().enumerate() {
                *node = leaf(first + offset, &multiproof.restored);
            }
            let prefixes: Vec<_> = (1..=levels)
                .map(|level| node_prefix(&self.role, self.stage, level))
                .collect();
            for local in (2..span).rev() {
                let level = levels + 1 - local.ilog2() as usize;
                nodes[local] = node(
                    &prefixes[level - 1],
                    &nodes[2 * local],
                    &nodes[2 * local + 1],
                );
            }
            multiproof.block = Some(Block { ancestor, nodes });
        }
        let local = index - (ancestor << (levels + 1 - depth)) + (1 << (levels + 1 - depth));
        multiproof.block.as_ref().unwrap().nodes[local]
    }
    /// Writes a multiproof's record of the leaf: its index, row and salt,
    /// and the siblings on its path that no earlier record of the multiproof
    /// gave or passed through. Records follow in increasing leaf order.
    pub fn write_record<W: Write>(
        &self,
        multiproof: &mut Multiproof,
        index: usize,
        data: &[u8],
        output: &mut W,
    ) {
        assert!(index < self.length);
        assert!(multiproof.last.is_none_or(|last| last < index));
        assert_eq!(data.len(), self.width);
        multiproof.last = Some(index);
        output.write_all(&(index as u32).to_le_bytes()).unwrap();
        output.write_all(data).unwrap();
        output.write_all(self.salt(index).as_slice()).unwrap();
        let mut node = self.length + index;
        while node > 1 && !multiproof.known.contains(&node) {
            multiproof.known.insert(node);
            if multiproof.known.insert(node ^ 1) {
                output.write_all(&self.node(node ^ 1, multiproof)).unwrap();
            }
            node /= 2;
        }
    }
    /// Writes the multiproof of the indices, whose opening leaves' rows the
    /// function gives, as [`Tree::opened_rows`] reads them.
    pub fn write_multiproof<T: AsRef<[u8]> + Zeroize, W: Write>(
        &self,
        indices: &[usize],
        rows: impl FnOnce(&[usize]) -> Vec<T>,
        output: &mut W,
    ) {
        output
            .write_all(&(indices.len() as u32).to_le_bytes())
            .unwrap();
        let mut multiproof = Multiproof::default();
        let rows = self.opened_rows(&mut multiproof, indices, rows);
        for (&index, row) in indices.iter().zip(&rows) {
            self.write_record(&mut multiproof, index, row.as_ref(), output);
        }
    }
}
// The recomputed nodes below a kept ancestor, in its local heap order.
struct Block {
    ancestor: usize,
    nodes: Vec<[u8; 64]>,
}
/// A multiproof between its records: the nodes that earlier records gave or
/// passed through, the last record's leaf and the block of its path.
#[derive(Default)]
pub struct Multiproof {
    known: BTreeSet<usize>,
    last: Option<usize>,
    block: Option<Block>,
    // The digests of the forgotten leaves that the opening hashed again.
    restored: BTreeMap<usize, [u8; 64]>,
}

#[cfg(test)]
#[path = "tree-tests.rs"]
mod tests;
