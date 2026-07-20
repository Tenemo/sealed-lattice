use std::ops::Range;

use num_bigint::BigUint;

use crate::bgv::parameters::DATA_PRIMES;
use crate::{
    bgv::parameters::SPECIAL_PRIMES,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) const KEY_SWITCH_DATA_PRIMES_PER_BLOCK: usize = 3;
pub(crate) const KEY_SWITCH_SPECIAL_PRIMES: [u64; SPECIAL_PRIMES.len()] = SPECIAL_PRIMES;

pub(crate) fn key_switch_special_basis_modulus_product() -> BigUint {
    KEY_SWITCH_SPECIAL_PRIMES
        .iter()
        .map(|modulus| BigUint::from(*modulus))
        .product()
}

/// Requires the special-basis modulus to strictly dominate every active
/// decomposition-block modulus. Hybrid modulus down relies on this inequality;
/// equality is not sufficient for centered reconstruction.
pub(crate) fn validate_key_switch_special_basis_dominates_data_blocks(
    data_moduli: &[u64],
    special_moduli: &[u64],
    data_primes_per_block: usize,
) -> CanonicalResult<()> {
    if data_moduli.is_empty()
        || special_moduli.is_empty()
        || data_primes_per_block == 0
        || data_moduli
            .iter()
            .chain(special_moduli)
            .any(|modulus| *modulus < 2)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "hybrid key-switch dominance requires non-empty valid moduli and a positive block size",
        ));
    }
    let special_basis_modulus = special_moduli
        .iter()
        .map(|modulus| BigUint::from(*modulus))
        .product::<BigUint>();
    for data_block in data_moduli.chunks(data_primes_per_block) {
        let data_block_modulus = data_block
            .iter()
            .map(|modulus| BigUint::from(*modulus))
            .product::<BigUint>();
        if special_basis_modulus <= data_block_modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "hybrid key-switch special basis does not strictly dominate an active data block",
            ));
        }
    }
    Ok(())
}

/// Canonical little-endian residue width for one modulus-owned stream.
///
/// The modulus is suite-owned, so the payload does not repeat this width.
pub(crate) fn canonical_residue_byte_length(modulus: u64) -> CanonicalResult<usize> {
    if modulus < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "hybrid key-switch modulus must exceed one",
        ));
    }
    let significant_bit_count = u64::BITS - modulus.leading_zeros();
    usize::try_from(significant_bit_count.div_ceil(8)).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "hybrid key-switch residue width does not fit usize",
        )
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeySwitchDecompositionTopology {
    level: usize,
    data_primes_per_block: usize,
    data_block_ranges: Vec<Range<usize>>,
    extended_moduli: Vec<u64>,
}

impl KeySwitchDecompositionTopology {
    pub(crate) fn for_level(level: usize) -> CanonicalResult<Self> {
        Self::for_level_with_data_primes_per_block(level, KEY_SWITCH_DATA_PRIMES_PER_BLOCK)
    }

    pub(crate) fn for_level_with_data_primes_per_block(
        level: usize,
        data_primes_per_block: usize,
    ) -> CanonicalResult<Self> {
        let data_prime_count = level.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "hybrid key-switch level overflowed",
            )
        })?;
        if data_prime_count > DATA_PRIMES.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "hybrid key-switch level is outside the selected data basis",
            ));
        }
        if data_primes_per_block == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "hybrid key-switch block size must be positive",
            ));
        }

        validate_key_switch_special_basis_dominates_data_blocks(
            &DATA_PRIMES[..data_prime_count],
            &KEY_SWITCH_SPECIAL_PRIMES,
            data_primes_per_block,
        )?;

        let data_block_ranges: Vec<Range<usize>> = (0..data_prime_count)
            .step_by(data_primes_per_block)
            .map(|block_start| {
                block_start..data_prime_count.min(block_start + data_primes_per_block)
            })
            .collect();
        let mut extended_moduli = DATA_PRIMES[..data_prime_count].to_vec();
        extended_moduli.extend(KEY_SWITCH_SPECIAL_PRIMES);

        Ok(Self {
            level,
            data_primes_per_block,
            data_block_ranges,
            extended_moduli,
        })
    }

    pub(crate) fn level(&self) -> usize {
        self.level
    }

    pub(crate) fn data_prime_count(&self) -> usize {
        self.level + 1
    }

    #[cfg(test)]
    pub(crate) fn data_primes_per_block(&self) -> usize {
        self.data_primes_per_block
    }

    pub(crate) fn data_block_count(&self) -> usize {
        self.data_block_ranges.len()
    }

    pub(crate) fn data_block_range(&self, block_index: usize) -> CanonicalResult<Range<usize>> {
        self.data_block_ranges
            .get(block_index)
            .cloned()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "hybrid key-switch block index is outside the decomposition topology",
                )
            })
    }

    pub(crate) fn active_data_moduli(&self) -> &[u64] {
        &self.extended_moduli[..self.data_prime_count()]
    }

    pub(crate) fn extended_moduli(&self) -> &[u64] {
        &self.extended_moduli
    }

    pub(crate) fn extended_limb_count(&self) -> usize {
        self.extended_moduli.len()
    }

    #[cfg(test)]
    pub(crate) fn special_limb_count(&self) -> usize {
        KEY_SWITCH_SPECIAL_PRIMES.len()
    }

    pub(crate) fn canonical_component_wire_byte_length(
        &self,
        ring_degree: usize,
    ) -> CanonicalResult<u64> {
        let bytes_per_coefficient = self.extended_moduli.iter().try_fold(
            0_u64,
            |total, modulus| -> CanonicalResult<u64> {
                let residue_byte_length = canonical_residue_byte_length(*modulus)?;
                total
                    .checked_add(u64::try_from(residue_byte_length).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidProtocolObject,
                            "hybrid key-switch residue width does not fit u64",
                        )
                    })?)
                    .ok_or_else(component_byte_length_overflow)
            },
        )?;
        checked_component_byte_length(self.data_block_count(), ring_degree, bytes_per_coefficient)
    }

    pub(crate) fn resident_component_byte_length(
        &self,
        ring_degree: usize,
    ) -> CanonicalResult<u64> {
        let bytes_per_coefficient = u64::try_from(self.extended_limb_count())
            .ok()
            .and_then(|limb_count| limb_count.checked_mul(u64::from(u64::BITS / 8)))
            .ok_or_else(component_byte_length_overflow)?;
        checked_component_byte_length(self.data_block_count(), ring_degree, bytes_per_coefficient)
    }

    #[cfg(test)]
    pub(crate) fn projection_indices_for_level(
        &self,
        projected_level: usize,
    ) -> CanonicalResult<Vec<usize>> {
        if projected_level > self.level {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "hybrid key-switch projection level exceeds the stored key level",
            ));
        }
        let projected_data_prime_count = projected_level + 1;
        let mut indices = (0..projected_data_prime_count).collect::<Vec<_>>();
        indices
            .extend(self.data_prime_count()..self.data_prime_count() + self.special_limb_count());
        Ok(indices)
    }
}

fn checked_component_byte_length(
    data_block_count: usize,
    ring_degree: usize,
    bytes_per_coefficient: u64,
) -> CanonicalResult<u64> {
    u64::try_from(data_block_count)
        .ok()
        .and_then(|block_count| {
            u64::try_from(ring_degree)
                .ok()
                .and_then(|degree| block_count.checked_mul(degree))
        })
        .and_then(|coefficient_count| coefficient_count.checked_mul(bytes_per_coefficient))
        .ok_or_else(component_byte_length_overflow)
}

fn component_byte_length_overflow() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "hybrid key-switch component byte length overflowed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::parameters::POLYNOMIAL_DEGREE;

    #[test]
    fn topology_uses_contiguous_data_blocks_and_the_full_special_basis() {
        let topology = KeySwitchDecompositionTopology::for_level_with_data_primes_per_block(4, 2)
            .expect("level-four topology");

        assert_eq!(topology.level(), 4);
        assert_eq!(topology.data_primes_per_block(), 2);
        assert_eq!(topology.data_block_count(), 3);
        assert_eq!(topology.data_block_range(0).expect("block zero"), 0..2);
        assert_eq!(topology.data_block_range(1).expect("block one"), 2..4);
        assert_eq!(topology.data_block_range(2).expect("block two"), 4..5);
        assert_eq!(topology.active_data_moduli(), &DATA_PRIMES[..5]);
        assert_eq!(
            topology.extended_moduli(),
            DATA_PRIMES[..5]
                .iter()
                .chain(KEY_SWITCH_SPECIAL_PRIMES.iter())
                .copied()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn lower_level_projection_keeps_the_data_prefix_and_every_special_limb() {
        let topology = KeySwitchDecompositionTopology::for_level(5).expect("level-five topology");

        assert_eq!(
            topology
                .projection_indices_for_level(2)
                .expect("level-two projection"),
            (0..3)
                .chain(6..6 + KEY_SWITCH_SPECIAL_PRIMES.len())
                .collect::<Vec<_>>()
        );
        assert!(topology.projection_indices_for_level(6).is_err());
    }

    #[test]
    fn topology_rejects_invalid_levels_and_block_sizes() {
        assert!(KeySwitchDecompositionTopology::for_level(DATA_PRIMES.len()).is_err());
        assert!(
            KeySwitchDecompositionTopology::for_level_with_data_primes_per_block(1, 0).is_err()
        );
        assert!(KeySwitchDecompositionTopology::for_level_with_data_primes_per_block(1, 3).is_ok());
    }

    #[test]
    fn special_basis_dominance_is_strict_and_covers_every_active_block() {
        assert!(
            validate_key_switch_special_basis_dominates_data_blocks(&[2, 3, 5], &[7], 2).is_ok()
        );
        assert!(
            validate_key_switch_special_basis_dominates_data_blocks(&[2, 3], &[6], 2).is_err(),
            "an equal special and data-block product must be rejected"
        );
        assert!(
            validate_key_switch_special_basis_dominates_data_blocks(&[2, 3], &[5], 2).is_err(),
            "a smaller special-basis product must be rejected"
        );
        assert!(
            validate_key_switch_special_basis_dominates_data_blocks(&[2, 3, 5], &[5], 2).is_err(),
            "every block, not only the final partial block, must be dominated"
        );
        assert!(validate_key_switch_special_basis_dominates_data_blocks(&[], &[7], 1).is_err());
        assert!(validate_key_switch_special_basis_dominates_data_blocks(&[2], &[], 1).is_err());
        assert!(validate_key_switch_special_basis_dominates_data_blocks(&[2], &[7], 0).is_err());
        assert!(validate_key_switch_special_basis_dominates_data_blocks(&[1], &[7], 1).is_err());
    }

    #[test]
    fn every_level_and_block_size_matches_the_exact_dominance_inequality() {
        let special_basis_modulus_product = key_switch_special_basis_modulus_product();
        for level in 0..DATA_PRIMES.len() {
            for data_primes_per_block in 1..=DATA_PRIMES.len() + 1 {
                let expected_to_pass =
                    DATA_PRIMES[..=level]
                        .chunks(data_primes_per_block)
                        .all(|data_block| {
                            let data_block_modulus_product = data_block
                                .iter()
                                .map(|modulus| BigUint::from(*modulus))
                                .product::<BigUint>();
                            special_basis_modulus_product > data_block_modulus_product
                        });
                assert_eq!(
                    KeySwitchDecompositionTopology::for_level_with_data_primes_per_block(
                        level,
                        data_primes_per_block,
                    )
                    .is_ok(),
                    expected_to_pass,
                    "dominance decision drifted at level {level} and block size {data_primes_per_block}",
                );
            }
        }
    }

    #[test]
    fn component_lengths_distinguish_compact_wire_bytes_from_resident_words() {
        let topology = KeySwitchDecompositionTopology::for_level_with_data_primes_per_block(
            DATA_PRIMES.len() - 1,
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
        )
        .expect("full selected topology");
        let coefficient_count = topology
            .data_block_count()
            .checked_mul(POLYNOMIAL_DEGREE)
            .expect("selected component coefficient count");
        let wire_bytes_per_coefficient = topology
            .extended_moduli()
            .iter()
            .map(|modulus| canonical_residue_byte_length(*modulus).expect("selected residue width"))
            .sum::<usize>();
        let expected_wire_byte_length = coefficient_count
            .checked_mul(wire_bytes_per_coefficient)
            .and_then(|length| u64::try_from(length).ok())
            .expect("selected wire length fits u64");
        let expected_resident_byte_length = coefficient_count
            .checked_mul(topology.extended_limb_count())
            .and_then(|length| length.checked_mul(std::mem::size_of::<u64>()))
            .and_then(|length| u64::try_from(length).ok())
            .expect("selected resident length fits u64");

        assert_eq!(
            topology
                .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
                .expect("wire length"),
            expected_wire_byte_length
        );
        assert_eq!(
            topology
                .resident_component_byte_length(POLYNOMIAL_DEGREE)
                .expect("resident length"),
            expected_resident_byte_length
        );
        assert!(expected_wire_byte_length < expected_resident_byte_length);
        assert!(topology.resident_component_byte_length(usize::MAX).is_err());
    }

    #[test]
    fn selected_topology_keeps_exact_block_geometry_with_dominating_special_modulus() {
        let topology = KeySwitchDecompositionTopology::for_level(DATA_PRIMES.len() - 1)
            .expect("full selected topology");
        let special_basis_modulus_product = key_switch_special_basis_modulus_product();
        let selected_block_ranges = [0..3, 3..6, 6..9, 9..12, 12..15, 15..18, 18..21, 21..23];

        assert_eq!(topology.data_block_count(), selected_block_ranges.len());
        for (block_index, expected_block_range) in selected_block_ranges.into_iter().enumerate() {
            let block_range = topology
                .data_block_range(block_index)
                .expect("selected block range");
            assert_eq!(block_range, expected_block_range);
            let data_block_modulus_product = DATA_PRIMES[block_range]
                .iter()
                .map(|modulus| BigUint::from(*modulus))
                .product::<BigUint>();
            assert!(special_basis_modulus_product > data_block_modulus_product);
        }
    }
}
