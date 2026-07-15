use std::ops::Range;

use crate::{
    bgv::parameters::{DATA_PRIMES, SPECIAL_PRIME},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) const KEY_SWITCH_DATA_PRIMES_PER_BLOCK: usize = 1;
pub(crate) const KEY_SWITCH_SPECIAL_PRIMES: [u64; 1] = [SPECIAL_PRIME];

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
                CanonicalErrorCode::InvalidFixture,
                "hybrid key-switch level overflowed",
            )
        })?;
        if data_prime_count > DATA_PRIMES.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "hybrid key-switch level is outside the selected data basis",
            ));
        }
        if data_primes_per_block == 0 || data_primes_per_block > data_prime_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "hybrid key-switch block size must be between one and the active data-prime count",
            ));
        }

        let data_block_ranges = (0..data_prime_count)
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
                    CanonicalErrorCode::InvalidFixture,
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

    pub(crate) fn special_limb_count(&self) -> usize {
        KEY_SWITCH_SPECIAL_PRIMES.len()
    }

    pub(crate) fn projection_indices_for_level(
        &self,
        projected_level: usize,
    ) -> CanonicalResult<Vec<usize>> {
        if projected_level > self.level {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
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

#[cfg(test)]
mod tests {
    use super::*;

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
            vec![0, 1, 2, 6]
        );
        assert!(topology.projection_indices_for_level(6).is_err());
    }

    #[test]
    fn topology_rejects_invalid_levels_and_block_sizes() {
        assert!(KeySwitchDecompositionTopology::for_level(DATA_PRIMES.len()).is_err());
        assert!(
            KeySwitchDecompositionTopology::for_level_with_data_primes_per_block(1, 0).is_err()
        );
        assert!(
            KeySwitchDecompositionTopology::for_level_with_data_primes_per_block(1, 3).is_err()
        );
    }
}
