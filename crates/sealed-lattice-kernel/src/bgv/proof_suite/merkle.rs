//! Closed proof-tree roles and coordinate-derived compact-frontier geometry.

use zeroize::Zeroize;

use super::ProofBaseFieldElement;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofMerkleError {
    InvalidOpening,
    CountOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum ProofTreeRole {
    BaseOracle = 1,
    AuxiliaryOracle = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum ProofLeafVisibility {
    Public = 1,
    SecretBearing = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub(crate) enum ProofTreeValue {
    Base(ProofBaseFieldElement),
}

pub(in crate::bgv::proof_suite) fn minimal_frontier_coordinates(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
) -> Result<Vec<(u32, u64)>, ProofMerkleError> {
    let coordinate_count =
        scan_minimal_frontier_coordinates(sorted_unique_leaf_indexes, leaf_count, None)?;
    let mut coordinates = Vec::new();
    coordinates
        .try_reserve_exact(coordinate_count)
        .map_err(|_| ProofMerkleError::CountOverflow)?;
    coordinates.resize(coordinate_count, (0, 0));
    scan_minimal_frontier_coordinates(
        sorted_unique_leaf_indexes,
        leaf_count,
        Some(coordinates.as_mut_slice()),
    )?;
    Ok(coordinates)
}

/// Exact worst-case size of a coordinate-derived minimal frontier.
///
/// At each level, an evenly distributed opening set maximizes the number of
/// distinct active parents. Missing children of those parents are precisely
/// the frontier nodes, so the result is attainable rather than a path-count
/// approximation.
pub(in crate::bgv::proof_suite) fn maximum_minimal_frontier_node_count(
    leaf_count: usize,
    opening_count: usize,
) -> Result<usize, ProofMerkleError> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() || opening_count > leaf_count {
        return Err(ProofMerkleError::InvalidOpening);
    }
    if opening_count == 0 {
        return Ok(0);
    }

    let mut frontier_node_count = 0_usize;
    let mut level_node_count = leaf_count;
    let mut active_node_count = opening_count;
    while level_node_count > 1 {
        let parent_node_count = opening_count.min(level_node_count / 2);
        frontier_node_count = frontier_node_count
            .checked_add(
                parent_node_count
                    .checked_mul(2)
                    .and_then(|child_count| child_count.checked_sub(active_node_count))
                    .ok_or(ProofMerkleError::CountOverflow)?,
            )
            .ok_or(ProofMerkleError::CountOverflow)?;
        active_node_count = parent_node_count;
        level_node_count /= 2;
    }
    Ok(frontier_node_count)
}

/// Exact worst-case parent-hash work for a coordinate-derived minimal
/// frontier.
///
/// The queried leaves and derived frontier are the leaves of the verifier's
/// reconstructed full binary subtree. A full binary tree with `k` leaves has
/// exactly `k - 1` parent nodes, so this count stays tied to the same canonical
/// coordinates as the wire-size bound.
#[cfg(test)]
pub(in crate::bgv::proof_suite) fn maximum_minimal_frontier_parent_hash_count(
    leaf_count: usize,
    opening_count: usize,
) -> Result<usize, ProofMerkleError> {
    if opening_count == 0 {
        return Err(ProofMerkleError::InvalidOpening);
    }
    opening_count
        .checked_add(maximum_minimal_frontier_node_count(
            leaf_count,
            opening_count,
        )?)
        .and_then(|leaf_and_frontier_count| leaf_and_frontier_count.checked_sub(1))
        .ok_or(ProofMerkleError::CountOverflow)
}

/// Scans the canonical minimal frontier without constructing transient sets.
/// The first pass obtains the exact output length and the second fills the
/// caller's sole allocation in level-and-node order.
fn scan_minimal_frontier_coordinates(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
    mut output: Option<&mut [(u32, u64)]>,
) -> Result<usize, ProofMerkleError> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(ProofMerkleError::InvalidOpening);
    }
    validate_sorted_unique_leaf_indexes(sorted_unique_leaf_indexes, leaf_count)?;

    let expected_output_length = output.as_ref().map(|coordinates| coordinates.len());
    let mut coordinate_count = 0_usize;
    for level in 0..leaf_count.trailing_zeros() {
        let mut leaf_position = 0_usize;
        while leaf_position < sorted_unique_leaf_indexes.len() {
            let node_index = sorted_unique_leaf_indexes[leaf_position] >> level;
            leaf_position += 1;
            while leaf_position < sorted_unique_leaf_indexes.len()
                && sorted_unique_leaf_indexes[leaf_position] >> level == node_index
            {
                leaf_position += 1;
            }
            if node_index & 1 == 0
                && leaf_position < sorted_unique_leaf_indexes.len()
                && sorted_unique_leaf_indexes[leaf_position] >> level == node_index + 1
            {
                let sibling_index = node_index + 1;
                leaf_position += 1;
                while leaf_position < sorted_unique_leaf_indexes.len()
                    && sorted_unique_leaf_indexes[leaf_position] >> level == sibling_index
                {
                    leaf_position += 1;
                }
                continue;
            }
            if let Some(coordinates) = output.as_deref_mut() {
                *coordinates
                    .get_mut(coordinate_count)
                    .ok_or(ProofMerkleError::InvalidOpening)? = (level, node_index ^ 1);
            }
            coordinate_count = coordinate_count
                .checked_add(1)
                .ok_or(ProofMerkleError::CountOverflow)?;
        }
    }
    if expected_output_length.is_some_and(|length| length != coordinate_count) {
        return Err(ProofMerkleError::InvalidOpening);
    }
    Ok(coordinate_count)
}

fn validate_sorted_unique_leaf_indexes(
    indexes: &[u64],
    leaf_count: usize,
) -> Result<(), ProofMerkleError> {
    if indexes.is_empty()
        || !indexes.windows(2).all(|pair| pair[0] < pair[1])
        || indexes.last().copied().unwrap_or(0)
            >= u64::try_from(leaf_count).map_err(|_| ProofMerkleError::CountOverflow)?
    {
        return Err(ProofMerkleError::InvalidOpening);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_frontier_coordinates_are_canonical_and_minimal() {
        assert_eq!(
            minimal_frontier_coordinates(&[1, 2, 5], 8),
            Ok(vec![(0, 0), (0, 3), (0, 4), (1, 3)]),
        );
        assert_eq!(maximum_minimal_frontier_node_count(8, 3), Ok(4));
        assert_eq!(maximum_minimal_frontier_node_count(8, 8), Ok(0));
        assert_eq!(maximum_minimal_frontier_node_count(1, 1), Ok(0));
        assert_eq!(maximum_minimal_frontier_parent_hash_count(8, 3), Ok(6));
        assert_eq!(maximum_minimal_frontier_parent_hash_count(8, 8), Ok(7));
        assert_eq!(maximum_minimal_frontier_parent_hash_count(1, 1), Ok(0));
    }

    #[test]
    fn parent_hash_ceiling_matches_every_small_coordinate_set() {
        let leaf_count = 8_usize;
        for opening_count in 1..=leaf_count {
            let maximum_coordinate_derived_count = (1_u16..(1_u16 << leaf_count))
                .filter(|mask| mask.count_ones() as usize == opening_count)
                .map(|mask| {
                    let indexes = (0..leaf_count)
                        .filter(|leaf_index| mask & (1_u16 << leaf_index) != 0)
                        .map(|leaf_index| leaf_index as u64)
                        .collect::<Vec<_>>();
                    opening_count
                        + minimal_frontier_coordinates(&indexes, leaf_count)
                            .expect("the exhaustive coordinate set is canonical")
                            .len()
                        - 1
                })
                .max()
                .expect("each opening count has at least one coordinate set");
            assert_eq!(
                maximum_minimal_frontier_parent_hash_count(leaf_count, opening_count),
                Ok(maximum_coordinate_derived_count),
            );
        }
    }

    #[test]
    fn compact_frontier_coordinates_reject_malformed_opening_sets() {
        for indexes in [&[][..], &[2, 1][..], &[1, 1][..], &[8][..]] {
            assert_eq!(
                minimal_frontier_coordinates(indexes, 8),
                Err(ProofMerkleError::InvalidOpening),
            );
        }
        assert_eq!(
            minimal_frontier_coordinates(&[0], 6),
            Err(ProofMerkleError::InvalidOpening),
        );
        assert_eq!(
            maximum_minimal_frontier_node_count(8, 9),
            Err(ProofMerkleError::InvalidOpening),
        );
        assert_eq!(
            maximum_minimal_frontier_parent_hash_count(8, 0),
            Err(ProofMerkleError::InvalidOpening),
        );
        assert_eq!(
            maximum_minimal_frontier_parent_hash_count(8, 9),
            Err(ProofMerkleError::InvalidOpening),
        );
    }
}
