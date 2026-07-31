use std::collections::{BTreeMap, BTreeSet};

use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::{
    ChallengeField, MERKLE_DIGEST_WORD_LENGTH, aggregate_leaf_hasher, aggregate_node_compressor,
};

pub(super) type CompactMerkleDigest = [u64; MERKLE_DIGEST_WORD_LENGTH];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CompactMerkleCoordinate {
    level: usize,
    node_index: usize,
}

fn checked_query_indices(leaf_count: usize, query_indices: &[usize]) -> Result<(), String> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(
            "aggregate-wide WHIR Merkle leaf count is not a nonzero power of two".to_owned(),
        );
    }
    if query_indices.is_empty()
        || query_indices
            .windows(2)
            .any(|indices| indices[0] >= indices[1])
        || query_indices
            .last()
            .is_some_and(|query_index| *query_index >= leaf_count)
    {
        return Err(
            "aggregate-wide WHIR query indices are not canonical for the Merkle tree".to_owned(),
        );
    }
    Ok(())
}

fn compact_frontier_coordinates(
    leaf_count: usize,
    query_indices: &[usize],
) -> Result<Vec<CompactMerkleCoordinate>, String> {
    checked_query_indices(leaf_count, query_indices)?;
    let query_indices = query_indices
        .iter()
        .copied()
        .map(|query_index| {
            u64::try_from(query_index)
                .map_err(|_| "Merkle query index exceeds the canonical coordinate width".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    crate::bgv::proof_suite::merkle::minimal_frontier_coordinates(&query_indices, leaf_count)
        .map_err(|_| "Merkle frontier coordinates are invalid".to_owned())?
        .into_iter()
        .map(|(level, node_index)| {
            Ok(CompactMerkleCoordinate {
                level: usize::try_from(level)
                    .map_err(|_| "Merkle frontier level exceeds usize".to_owned())?,
                node_index: usize::try_from(node_index)
                    .map_err(|_| "Merkle frontier node index exceeds usize".to_owned())?,
            })
        })
        .collect()
}

pub(super) fn compact_frontier_node_count(
    leaf_count: usize,
    query_indices: &[usize],
) -> Result<usize, String> {
    Ok(compact_frontier_coordinates(leaf_count, query_indices)?.len())
}

pub(super) fn compact_frontier_from_query_paths(
    leaf_count: usize,
    query_indices: &[usize],
    query_paths: &[&[CompactMerkleDigest]],
) -> Result<Vec<CompactMerkleDigest>, String> {
    checked_query_indices(leaf_count, query_indices)?;
    if query_paths.len() != query_indices.len() {
        return Err("aggregate-wide WHIR query path schedule has the wrong shape".to_owned());
    }
    let tree_depth = leaf_count.ilog2() as usize;
    let mut supplied_nodes = BTreeMap::new();
    for (query_index, query_path) in query_indices.iter().copied().zip(query_paths) {
        if query_path.len() != tree_depth {
            return Err("aggregate-wide WHIR query path has the wrong depth".to_owned());
        }
        for (level, digest) in query_path.iter().copied().enumerate() {
            let coordinate = CompactMerkleCoordinate {
                level,
                node_index: (query_index >> level) ^ 1,
            };
            if supplied_nodes
                .insert(coordinate, digest)
                .is_some_and(|previous| previous != digest)
            {
                return Err(
                    "aggregate-wide WHIR query paths disagree at one Merkle coordinate".to_owned(),
                );
            }
        }
    }

    compact_frontier_coordinates(leaf_count, query_indices)?
        .into_iter()
        .map(|coordinate| {
            supplied_nodes.get(&coordinate).copied().ok_or_else(|| {
                "aggregate-wide WHIR query paths omit a required frontier coordinate".to_owned()
            })
        })
        .collect()
}

pub(super) fn reconstruct_query_paths_from_compact_frontier(
    leaf_count: usize,
    query_indices: &[usize],
    opened_rows: &[&[ChallengeField]],
    frontier: &[CompactMerkleDigest],
    expected_root: Option<CompactMerkleDigest>,
) -> Result<Vec<Vec<CompactMerkleDigest>>, String> {
    checked_query_indices(leaf_count, query_indices)?;
    if opened_rows.len() != query_indices.len() || opened_rows.iter().any(|row| row.is_empty()) {
        return Err("aggregate-wide WHIR opened-row schedule has the wrong shape".to_owned());
    }
    let frontier_coordinates = compact_frontier_coordinates(leaf_count, query_indices)?;
    if frontier.len() != frontier_coordinates.len() {
        return Err(format!(
            "aggregate-wide WHIR Merkle frontier has {} nodes, expected {} from verifier-derived coordinates",
            frontier.len(),
            frontier_coordinates.len()
        ));
    }

    let leaf_hasher = aggregate_leaf_hasher();
    let node_compressor = aggregate_node_compressor();
    let maximum_derived_node_count = query_indices
        .len()
        .checked_mul(leaf_count.ilog2() as usize + 1)
        .and_then(|count| count.checked_add(frontier.len()))
        .ok_or_else(|| "aggregate-wide WHIR derived Merkle node count overflowed".to_owned())?;
    let mut derived_nodes = Vec::new();
    derived_nodes
        .try_reserve(maximum_derived_node_count)
        .map_err(|_| "aggregate-wide WHIR derived Merkle node allocation failed".to_owned())?;
    let insert_derived_node = |nodes: &mut Vec<(CompactMerkleCoordinate, CompactMerkleDigest)>,
                               coordinate,
                               digest|
     -> Result<(), String> {
        match nodes.binary_search_by_key(&coordinate, |(coordinate, _)| *coordinate) {
            Ok(_) => Err("aggregate-wide WHIR Merkle nodes overlap at one coordinate".to_owned()),
            Err(insertion_index) => {
                nodes.insert(insertion_index, (coordinate, digest));
                Ok(())
            }
        }
    };
    let get_derived_node = |nodes: &[(CompactMerkleCoordinate, CompactMerkleDigest)],
                            coordinate|
     -> Option<CompactMerkleDigest> {
        nodes
            .binary_search_by_key(&coordinate, |(coordinate, _)| *coordinate)
            .ok()
            .map(|node_index| nodes[node_index].1)
    };
    for (query_index, opened_row) in query_indices.iter().copied().zip(opened_rows) {
        insert_derived_node(
            &mut derived_nodes,
            CompactMerkleCoordinate {
                level: 0,
                node_index: query_index,
            },
            leaf_hasher.hash_iter(opened_row.iter().copied()),
        )?;
    }
    for (coordinate, digest) in frontier_coordinates
        .into_iter()
        .zip(frontier.iter().copied())
    {
        insert_derived_node(&mut derived_nodes, coordinate, digest)?;
    }

    let tree_depth = leaf_count.ilog2() as usize;
    let mut active_node_indices = query_indices.to_vec();
    for level in 0..tree_depth {
        let parent_indices = active_node_indices
            .iter()
            .map(|node_index| node_index >> 1)
            .collect::<Vec<_>>();
        let mut distinct_parent_indices = parent_indices;
        distinct_parent_indices.dedup();
        for parent_index in distinct_parent_indices.iter().copied() {
            let left_coordinate = CompactMerkleCoordinate {
                level,
                node_index: parent_index << 1,
            };
            let right_coordinate = CompactMerkleCoordinate {
                level,
                node_index: (parent_index << 1) | 1,
            };
            let left_digest =
                get_derived_node(&derived_nodes, left_coordinate).ok_or_else(|| {
                    "aggregate-wide WHIR Merkle frontier cannot reconstruct a left child".to_owned()
                })?;
            let right_digest =
                get_derived_node(&derived_nodes, right_coordinate).ok_or_else(|| {
                    "aggregate-wide WHIR Merkle frontier cannot reconstruct a right child"
                        .to_owned()
                })?;
            insert_derived_node(
                &mut derived_nodes,
                CompactMerkleCoordinate {
                    level: level + 1,
                    node_index: parent_index,
                },
                node_compressor.compress([left_digest, right_digest]),
            )?;
        }
        active_node_indices = distinct_parent_indices;
    }
    let reconstructed_root = get_derived_node(
        &derived_nodes,
        CompactMerkleCoordinate {
            level: tree_depth,
            node_index: 0,
        },
    )
    .ok_or_else(|| "aggregate-wide WHIR Merkle frontier did not reconstruct a root".to_owned())?;
    if expected_root.is_some_and(|expected_root| reconstructed_root != expected_root) {
        return Err(
            "aggregate-wide WHIR Merkle frontier does not reconstruct the commitment root"
                .to_owned(),
        );
    }

    query_indices
        .iter()
        .copied()
        .map(|query_index| {
            (0..tree_depth)
                .map(|level| {
                    get_derived_node(
                        &derived_nodes,
                        CompactMerkleCoordinate {
                            level,
                            node_index: (query_index >> level) ^ 1,
                        },
                    )
                    .ok_or_else(|| {
                        "aggregate-wide WHIR Merkle frontier cannot reconstruct a query path"
                            .to_owned()
                    })
                })
                .collect()
        })
        .collect()
}

/// Verifies one materialized bound-tree multiproof from the exact frontier
/// coordinates implied by the verifier-derived leaf indices. The proof never
/// carries coordinates, path lengths, or per-query sibling paths.
pub(super) fn verify_materialized_bound_frontier(
    entry: &crate::bgv::proof_suite::ProofTreeCatalogEntry,
    leaf_count: usize,
    opened_leaves: &[(u64, [u8; 64])],
    frontier: &[[u8; 64]],
    expected_query_count: usize,
) -> Result<(), String> {
    let leaf_count_u64 = u64::try_from(leaf_count)
        .map_err(|_| "bound tree leaf count exceeds the canonical u64 width".to_owned())?;
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || opened_leaves.len() != expected_query_count
        || opened_leaves.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || opened_leaves
            .last()
            .is_some_and(|(leaf_index, _)| *leaf_index >= leaf_count_u64)
    {
        return Err("bound tree opening indices are not canonical".to_owned());
    }
    let opened_leaf_indices = opened_leaves
        .iter()
        .map(|(leaf_index, _)| *leaf_index)
        .collect::<Vec<_>>();
    let expected_frontier_node_count =
        crate::bgv::proof_suite::merkle::minimal_frontier_coordinates(
            &opened_leaf_indices,
            leaf_count,
        )
        .map_err(|error| format!("derive bound authentication frontier: {error:?}"))?
        .len();
    if frontier.len() != expected_frontier_node_count {
        return Err(
            "bound authentication frontier has the wrong coordinate-derived length".to_owned(),
        );
    }

    let mut current = opened_leaves.iter().copied().collect::<BTreeMap<_, _>>();
    let mut frontier_offset = 0_usize;
    for level in 0..leaf_count.trailing_zeros() {
        let mut next = BTreeMap::new();
        let mut processed = BTreeSet::new();
        for index in current.keys().copied().collect::<Vec<_>>() {
            if !processed.insert(index) {
                continue;
            }
            let sibling_index = index ^ 1;
            let sibling_digest = if let Some(digest) = current.get(&sibling_index).copied() {
                processed.insert(sibling_index);
                digest
            } else {
                let digest = frontier
                    .get(frontier_offset)
                    .copied()
                    .ok_or_else(|| "bound authentication frontier is truncated".to_owned())?;
                frontier_offset += 1;
                digest
            };
            let own_digest = *current
                .get(&index)
                .ok_or_else(|| "bound authentication leaf is absent".to_owned())?;
            let (left, right) = if index & 1 == 0 {
                (own_digest, sibling_digest)
            } else {
                (sibling_digest, own_digest)
            };
            let parent_index = index / 2;
            let parent_digest = entry
                .materialized_parent_digest(level + 1, parent_index, left, right)
                .map_err(|error| format!("hash bound parent: {error:?}"))?;
            if next.insert(parent_index, parent_digest).is_some() {
                return Err("bound authentication frontier is non-canonical".to_owned());
            }
        }
        current = next;
    }
    if frontier_offset != frontier.len()
        || current.len() != 1
        || current.get(&0).copied() != entry.bound_root()
    {
        return Err("bound authentication frontier has the wrong root".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    fn complete_tree(
        leaf_count: usize,
    ) -> (
        Vec<Vec<ChallengeField>>,
        CompactMerkleDigest,
        Vec<Vec<CompactMerkleDigest>>,
    ) {
        let rows = (0..leaf_count)
            .map(|leaf_index| {
                vec![
                    ChallengeField::from_u64((leaf_index as u64) + 1),
                    ChallengeField::from_u64((leaf_index as u64) * 7 + 3),
                ]
            })
            .collect::<Vec<_>>();
        let leaf_hasher = aggregate_leaf_hasher();
        let node_compressor = aggregate_node_compressor();
        let mut levels = vec![
            rows.iter()
                .map(|row| leaf_hasher.hash_iter(row.iter().copied()))
                .collect::<Vec<_>>(),
        ];
        while levels.last().expect("tree has leaves").len() > 1 {
            levels.push(
                levels
                    .last()
                    .expect("tree has a preceding level")
                    .chunks_exact(2)
                    .map(|children| node_compressor.compress([children[0], children[1]]))
                    .collect(),
            );
        }
        let paths = (0..leaf_count)
            .map(|leaf_index| {
                (0..leaf_count.ilog2() as usize)
                    .map(|level| levels[level][(leaf_index >> level) ^ 1])
                    .collect()
            })
            .collect();
        (rows, levels.last().expect("tree has a root")[0], paths)
    }

    #[test]
    fn three_of_eight_leaves_use_the_exact_four_node_frontier() {
        let (rows, root, paths) = complete_tree(8);
        let indices = vec![0, 3, 6];
        let selected_paths = indices
            .iter()
            .map(|index| paths[*index].as_slice())
            .collect::<Vec<_>>();
        let selected_rows = indices
            .iter()
            .map(|index| rows[*index].as_slice())
            .collect::<Vec<_>>();
        let frontier = compact_frontier_from_query_paths(8, &indices, &selected_paths)
            .expect("derive the exact frontier");
        assert_eq!(frontier.len(), 4);
        assert_eq!(
            reconstruct_query_paths_from_compact_frontier(
                8,
                &indices,
                &selected_rows,
                &frontier,
                Some(root),
            )
            .expect("reconstruct all individual paths"),
            selected_paths
                .iter()
                .map(|path| path.to_vec())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn opening_every_leaf_needs_no_frontier_nodes() {
        let (rows, root, paths) = complete_tree(8);
        let indices = (0..8).collect::<Vec<_>>();
        let frontier = compact_frontier_from_query_paths(
            8,
            &indices,
            &paths.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
        .expect("derive the empty complete-tree frontier");
        assert!(frontier.is_empty());
        assert_eq!(
            reconstruct_query_paths_from_compact_frontier(
                8,
                &indices,
                &rows.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &frontier,
                Some(root),
            )
            .expect("reconstruct paths from all leaves"),
            paths
        );
    }

    #[test]
    fn frontier_rejects_noncanonical_indices_and_wrong_root_or_count() {
        let (rows, root, paths) = complete_tree(8);
        assert!(compact_frontier_node_count(8, &[3, 3]).is_err());
        let indices = vec![1, 5];
        let selected_paths = indices
            .iter()
            .map(|index| paths[*index].as_slice())
            .collect::<Vec<_>>();
        let selected_rows = indices
            .iter()
            .map(|index| rows[*index].as_slice())
            .collect::<Vec<_>>();
        let frontier = compact_frontier_from_query_paths(8, &indices, &selected_paths)
            .expect("derive the exact frontier");
        assert!(
            reconstruct_query_paths_from_compact_frontier(
                8,
                &indices,
                &selected_rows,
                &frontier[..frontier.len() - 1],
                Some(root),
            )
            .is_err()
        );
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(
            reconstruct_query_paths_from_compact_frontier(
                8,
                &indices,
                &selected_rows,
                &frontier,
                Some(wrong_root),
            )
            .is_err()
        );
    }
}
