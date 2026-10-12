use super::*;
use crate::transcript::hash;

// Every node of a tree of the leaves, in heap order, hashed directly.
fn reference(role: &[u8], stage: u32, leaves: &[[u8; 64]]) -> Vec<[u8; 64]> {
    let length = leaves.len();
    let mut nodes = vec![[0; 64]; 2 * length];
    nodes[length..].copy_from_slice(leaves);
    for node in (1..length).rev() {
        let level = length.ilog2() - node.ilog2();
        nodes[node] = hash(
            b"bounded-proof/node",
            &[
                role,
                &stage.to_le_bytes(),
                &level.to_le_bytes(),
                &nodes[2 * node],
                &nodes[2 * node + 1],
            ],
        );
    }
    nodes
}
// A leaf's digest hashed directly from its salt and row.
fn leaf(role: &[u8], stage: u32, index: usize, salt: &[u8], row: &[u8]) -> [u8; 64] {
    hash(
        LEAF_DOMAIN,
        &[
            role,
            &stage.to_le_bytes(),
            &(index as u32).to_le_bytes(),
            salt,
            row,
        ],
    )
}
fn seed(value: u8) -> Zeroizing<[u8; SALT_SEED_BYTES]> {
    Zeroizing::new(std::array::from_fn(|byte| value.wrapping_add(byte as u8)))
}

// SHAKE256 over the salt domain, the seed and the index, each after its
// 32-bit little-endian length, computed outside this crate with
// Python's hashlib.
#[test]
fn salts_expand_the_seed_and_index_under_their_framing() {
    let seed = seed(3);
    for (index, expected) in [
        (
            0,
            "7cea4b47a8b4f246ae15498bb4e3eabf1213580a82271696031327c96936621e\
                 588fa2e1c1a658595930ee094a45015f8c27436867f673dafb3742f6e448d5ff\
                 e7e662083782077dfa36bdcdb65421810a74ece7e8a5965a3557e170c5095a0c\
                 ea2bb3ef537a45e06adabfea34d966582d67f6405d1383687b3b898ee44e617d",
        ),
        (
            262_143,
            "b5c97c73405b9d0eaf7103b0a9a2633ebbe5abaadc3a080a66569e1cced2900c\
                 bafa2db5b2da9457c90d236a6b4cd634c6f28f399ce99252fed90a4649f70dba\
                 854d4af574a3662d1b822376197c674a374979f93eb891e12fa3f40a4c8225c5\
                 e367dbf8bdc4af7f6dc7c2db283d348c028c3935f315cc23655a5aaaaaca2c3a",
        ),
    ] {
        let hex: String = salt(&seed, index)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, expected);
    }
    assert_ne!(*salt(&seed, 0), *salt(&seed, 1));
    assert_ne!(*salt(&seed, 7), *salt(&self::seed(4), 7));
}

#[test]
fn cached_prefixes_preserve_complete_tree_bytes_at_block_boundaries() {
    for role_length in [1, 29, 30, 31, 37, 38, 39, 40, 266, 272, 282, 1024] {
        for stage in [0, 1, 18] {
            for width in [48, 144, 288] {
                let length = 8usize;
                let role: Vec<_> = (0..role_length).map(|index| (index % 251) as u8).collect();
                let mut tree = Tree::with_seed(&role, stage, length, width, seed(9));
                let prefix = tree.leaf_hash_prefix();
                let mut leaves = Vec::new();
                for index in 0..length {
                    let data: Vec<_> = (0..width)
                        .map(|byte| ((index + byte) % 251) as u8)
                        .collect();
                    let salt = tree.salt(index);
                    leaves.push(leaf(&role, stage as u32, index, salt.as_slice(), &data));
                    let mut cached = tree.leaf_hasher(index, &prefix);
                    let mut direct = ProtocolHash::new();
                    for part_bytes in [
                        LEAF_DOMAIN,
                        &tree.role,
                        &(stage as u32).to_le_bytes(),
                        &(index as u32).to_le_bytes(),
                        salt.as_slice(),
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
                tree.finish();
                assert_eq!(tree.root(), reference(&role, stage as u32, &leaves)[1]);
            }
        }
    }
}

// Every single opening's complete path and every multiproof's siblings
// equal the directly hashed tree's nodes, across the kept and recomputed
// levels.
fn check_openings(tree: &Tree, nodes: &[[u8; 64]], rows: &[u8], indices: &[usize]) {
    let (length, width) = (tree.length, tree.width);
    let rows_of = |leaves: &[usize]| -> Vec<Vec<u8>> {
        leaves
            .iter()
            .map(|leaf| rows[width * leaf..width * (leaf + 1)].to_vec())
            .collect()
    };
    for &index in indices {
        let row = &rows[width * index..width * (index + 1)];
        let mut opening = Vec::new();
        tree.write_multiproof(&[index], rows_of, &mut opening);
        let mut expected = Vec::from(1u32.to_le_bytes());
        expected.extend((index as u32).to_le_bytes());
        expected.extend(row);
        expected.extend(tree.salt(index).as_slice());
        let mut node = length + index;
        while node > 1 {
            expected.extend(nodes[node ^ 1]);
            node /= 2;
        }
        assert_eq!(opening, expected);
    }
    let payloads: Vec<&[u8]> = indices
        .iter()
        .map(|index| &rows[width * index..width * (index + 1)])
        .collect();
    let mut written = Vec::new();
    tree.write_multiproof(indices, rows_of, &mut written);
    let mut expected = Vec::from((indices.len() as u32).to_le_bytes());
    let mut known = BTreeSet::new();
    for (&index, row) in indices.iter().zip(&payloads) {
        expected.extend((index as u32).to_le_bytes());
        expected.extend(*row);
        expected.extend(tree.salt(index).as_slice());
        let mut node = length + index;
        while node > 1 && !known.contains(&node) {
            known.insert(node);
            if known.insert(node ^ 1) {
                expected.extend(nodes[node ^ 1]);
            }
            node /= 2;
        }
    }
    assert_eq!(written, expected);
}

// Appends each leaf's row of the width from the rows.
fn rows_of(rows: &[u8], width: usize) -> impl Fn(usize, &mut Vec<u8>) + '_ {
    move |index, input| input.extend_from_slice(&rows[width * index..width * (index + 1)])
}

#[test]
fn subtree_jobs_hash_the_complete_tree_across_several_subtrees() {
    let (length, width, stage) = (4 * SUBTREE_LEAVES, 48, 5u32);
    let role = b"subtree-regression".to_vec();
    let rows: Vec<u8> = (0..length * width)
        .map(|index| (index % 251) as u8)
        .collect();
    let tree = |seed| Tree::with_seed(&role, stage as usize, length, width, seed);
    let mut hashed = tree(seed(1));
    hashed.hash_rows(rows_of(&rows, width));
    let leaves: Vec<[u8; 64]> = (0..length)
        .map(|index| {
            leaf(
                &role,
                stage,
                index,
                hashed.salt(index).as_slice(),
                &rows[width * index..width * (index + 1)],
            )
        })
        .collect();
    let nodes = reference(&role, stage, &leaves);
    assert_eq!(hashed.leaves, leaves);
    assert_eq!(hashed.root(), nodes[1]);
    let mut finished = tree(seed(1));
    finished.leaves.copy_from_slice(&leaves);
    finished.finish();
    assert_eq!(finished.upper, hashed.upper);
    let indices = [
        0,
        1,
        2,
        31,
        32,
        33,
        1000,
        SUBTREE_LEAVES - 1,
        SUBTREE_LEAVES,
        length - 1,
    ];
    check_openings(&hashed, &nodes, &rows, &indices);
    // Forgetting the leaves, after or before hashing them, changes no
    // root or opening.
    hashed.forget_leaves();
    check_openings(&hashed, &nodes, &rows, &indices);
    let mut forgetful = tree(seed(1));
    forgetful.forget_leaves();
    forgetful.hash_rows(rows_of(&rows, width));
    assert_eq!(forgetful.upper, finished.upper);
    check_openings(&forgetful, &nodes, &rows, &indices);
    // Another seed commits to other salts.
    let mut other = tree(seed(2));
    other.hash_rows(rows_of(&rows, width));
    assert_ne!(other.root(), hashed.root());
}

#[test]
fn small_trees_keep_their_root_and_recompute_the_rest() {
    let role = b"small-trees".to_vec();
    for length in [2, 4, 8, 16, 32, 64] {
        let width = 48;
        let rows: Vec<u8> = (0..length * width)
            .map(|index| (index * 7 % 251) as u8)
            .collect();
        let mut tree = Tree::with_seed(&role, 7, length, width, seed(5));
        tree.hash_rows(rows_of(&rows, width));
        assert_eq!(tree.upper.len(), length >> recomputed_levels(length));
        let leaves: Vec<[u8; 64]> = (0..length)
            .map(|index| {
                leaf(
                    &role,
                    7,
                    index,
                    tree.salt(index).as_slice(),
                    &rows[width * index..width * (index + 1)],
                )
            })
            .collect();
        let nodes = reference(&role, 7, &leaves);
        assert_eq!(tree.root(), nodes[1]);
        let all: Vec<usize> = (0..length).collect();
        check_openings(&tree, &nodes, &rows, &all);
        tree.forget_leaves();
        check_openings(&tree, &nodes, &rows, &all);
        check_openings(&tree, &nodes, &rows, &[length - 1]);
    }
}

// A tree that forgot its leaves refuses to open rows other than those it
// committed, even at a leaf beside the queried one.
#[test]
#[should_panic(expected = "Restored block")]
fn forgotten_leaves_refuse_other_rows() {
    let (length, width) = (256, 48);
    let rows: Vec<u8> = (0..length * width)
        .map(|index| (index * 5 % 251) as u8)
        .collect();
    let mut tree = Tree::with_seed(b"forgotten", 4, length, width, seed(6));
    tree.hash_rows(rows_of(&rows, width));
    tree.forget_leaves();
    let mut changed = rows.clone();
    changed[width * 33] ^= 1;
    let mut opening = Vec::new();
    tree.write_multiproof(
        &[32],
        |leaves| -> Vec<Vec<u8>> {
            leaves
                .iter()
                .map(|leaf| changed[width * leaf..width * (leaf + 1)].to_vec())
                .collect()
        },
        &mut opening,
    );
}

// A row that counts its zeroizations.
struct CountedRow<'a>(Vec<u8>, &'a std::cell::Cell<usize>);
impl AsRef<[u8]> for CountedRow<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Zeroize for CountedRow<'_> {
    fn zeroize(&mut self) {
        self.0.zeroize();
        self.1.set(self.1.get() + 1);
    }
}

// An opening of a tree that forgot its leaves reads every row of the
// queried leaves' blocks, reveals the queried rows and zeroizes the
// others.
#[test]
fn forgotten_leaves_zeroize_the_rows_an_opening_does_not_reveal() {
    let (length, width) = (256, 48);
    let rows: Vec<u8> = (0..length * width)
        .map(|index| (index * 3 % 251) as u8)
        .collect();
    let mut tree = Tree::with_seed(b"zeroized", 4, length, width, seed(7));
    tree.hash_rows(rows_of(&rows, width));
    tree.forget_leaves();
    let indices = [3, 5, 200];
    let span = tree.block_leaves();
    let blocks: BTreeSet<usize> = indices.iter().map(|index| index / span).collect();
    let zeroized = std::cell::Cell::new(0);
    let mut read = 0;
    let opened = tree.opened_rows(&mut Multiproof::default(), &indices, |leaves| {
        read = leaves.len();
        leaves
            .iter()
            .map(|leaf| CountedRow(rows[width * leaf..width * (leaf + 1)].to_vec(), &zeroized))
            .collect()
    });
    assert_eq!(read, blocks.len() * span);
    assert!(read > indices.len());
    for (row, index) in opened.iter().zip(indices) {
        assert_eq!(row.0, &rows[width * index..width * (index + 1)]);
    }
    assert_eq!(zeroized.get(), read - indices.len());
}
