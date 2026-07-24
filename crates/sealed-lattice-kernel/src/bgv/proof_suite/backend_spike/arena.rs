//! Deterministic non-secret witness for the affine recomposition relation.
//!
//! Every relation instance has four columns, in this order:
//! `low_digit`, `high_digit`, `shifted_secret`, and `negative_indicator`.
//! The rows satisfy the same affine identity as the frozen same-secret
//! backend-bakeoff fragment:
//!
//! ```text
//! low + high * radix - shifted + 1 - negative * ciphertext_modulus = 0.
//! ```
//!
//! Values are regenerated from `(instance, row)` without retaining a witness.
//! This is a performance fixture, not a production witness source.

/// Goldilocks prime field modulus.
pub(crate) const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

pub(crate) const CIPHERTEXT_MODULUS: u64 = 1_953_759_233;
pub(crate) const MATERIAL_RADIX: u64 = 129_140_163;
pub(crate) const MATERIAL_HIGH_DIGIT_MAXIMUM: u64 = 15;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const WITNESS_COLUMNS_PER_RELATION_INSTANCE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArenaGeometry {
    pub(crate) relation_instance_variable_count: u32,
    pub(crate) row_variable_count: u32,
}

impl ArenaGeometry {
    pub(crate) const fn new(
        relation_instance_variable_count: u32,
        row_variable_count: u32,
    ) -> Self {
        Self {
            relation_instance_variable_count,
            row_variable_count,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn relation_instance_count(self) -> usize {
        1usize << self.relation_instance_variable_count
    }

    pub(crate) const fn row_count(self) -> usize {
        1usize << self.row_variable_count
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn witness_column_count(self) -> usize {
        self.relation_instance_count() * WITNESS_COLUMNS_PER_RELATION_INSTANCE
    }

    pub(crate) const fn relation_variable_count(self) -> u32 {
        self.relation_instance_variable_count + self.row_variable_count
    }

    pub(crate) const fn witness_variable_count(self) -> u32 {
        self.relation_variable_count() + 2
    }

    pub(crate) const fn relation_evaluation_count(self) -> usize {
        1usize << self.relation_variable_count()
    }

    pub(crate) const fn stacked_evaluation_count(self) -> usize {
        1usize << self.witness_variable_count()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AffineWitnessRow {
    pub(crate) low_digit: u64,
    pub(crate) high_digit: u64,
    pub(crate) shifted_secret: u64,
    pub(crate) negative_indicator: u64,
}

#[inline]
fn mixed_word(relation_instance_index: usize, row_index: usize) -> u64 {
    let flattened_index = (relation_instance_index as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(row_index as u64);
    flattened_index
        .wrapping_mul(0xbf58_476d_1ce4_e5b9)
        .rotate_left(23)
        ^ flattened_index
            .wrapping_mul(0x94d0_49bb_1331_11eb)
            .rotate_right(17)
}

/// Regenerates one valid, non-secret affine witness row.
#[inline]
pub(crate) fn affine_witness_row_at(
    relation_instance_index: usize,
    row_index: usize,
) -> AffineWitnessRow {
    let mixed = mixed_word(relation_instance_index, row_index);
    let low_digit = mixed % MATERIAL_RADIX;
    let high_digit = mixed.rotate_left(29) % (MATERIAL_HIGH_DIGIT_MAXIMUM + 1);
    let unreduced_shifted_secret = low_digit + high_digit * MATERIAL_RADIX + 1;
    let negative_indicator = u64::from(unreduced_shifted_secret >= CIPHERTEXT_MODULUS);
    let shifted_secret = unreduced_shifted_secret - negative_indicator * CIPHERTEXT_MODULUS;
    AffineWitnessRow {
        low_digit,
        high_digit,
        shifted_secret,
        negative_indicator,
    }
}

/// Returns one witness value from the stacked four-column representation.
/// Component bits are the most significant witness-selector bits, followed by
/// relation-instance bits and row bits.
#[inline]
pub(crate) fn stacked_value_at(geometry: ArenaGeometry, stacked_index: usize) -> u64 {
    debug_assert!(stacked_index < geometry.stacked_evaluation_count());
    let relation_evaluation_count = geometry.relation_evaluation_count();
    let component_index = stacked_index / relation_evaluation_count;
    let relation_index = stacked_index % relation_evaluation_count;
    let relation_instance_index = relation_index / geometry.row_count();
    let row_index = relation_index % geometry.row_count();
    let row = affine_witness_row_at(relation_instance_index, row_index);
    match component_index {
        0 => row.low_digit,
        1 => row.high_digit,
        2 => row.shifted_secret,
        3 => row.negative_indicator,
        _ => unreachable!("the witness has exactly four component columns"),
    }
}

#[inline]
pub(crate) fn relation_residual_at(geometry: ArenaGeometry, relation_index: usize) -> u64 {
    debug_assert!(relation_index < geometry.relation_evaluation_count());
    let relation_instance_index = relation_index / geometry.row_count();
    let row_index = relation_index % geometry.row_count();
    let row = affine_witness_row_at(relation_instance_index, row_index);
    affine_residual(row)
}

#[inline]
pub(crate) fn affine_residual(row: AffineWitnessRow) -> u64 {
    let modulus = u128::from(GOLDILOCKS_MODULUS);
    let positive = u128::from(row.low_digit)
        + u128::from(row.high_digit) * u128::from(MATERIAL_RADIX)
        + 1
        + modulus;
    let negative = u128::from(row.shifted_secret)
        + u128::from(row.negative_indicator) * u128::from(CIPHERTEXT_MODULUS);
    u64::try_from((positive - negative) % modulus)
        .expect("the affine residual is reduced below the field modulus")
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn arena_is_internally_consistent(geometry: ArenaGeometry) -> bool {
    (0..geometry.relation_evaluation_count())
        .all(|relation_index| relation_residual_at(geometry, relation_index) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affine_fixture_exercises_both_reduction_branches() {
        let geometry = ArenaGeometry::new(3, 8);
        let mut saw_unreduced = false;
        let mut saw_reduced = false;
        for relation_index in 0..geometry.relation_evaluation_count() {
            let instance = relation_index / geometry.row_count();
            let row = relation_index % geometry.row_count();
            let witness = affine_witness_row_at(instance, row);
            saw_unreduced |= witness.negative_indicator == 0;
            saw_reduced |= witness.negative_indicator == 1;
            assert_eq!(affine_residual(witness), 0);
            assert!(witness.low_digit < MATERIAL_RADIX);
            assert!(witness.high_digit <= MATERIAL_HIGH_DIGIT_MAXIMUM);
            assert!(witness.shifted_secret < CIPHERTEXT_MODULUS);
        }
        assert!(saw_unreduced);
        assert!(saw_reduced);
    }

    #[test]
    fn stacked_layout_contains_the_four_expected_columns() {
        let geometry = ArenaGeometry::new(1, 3);
        let relation_count = geometry.relation_evaluation_count();
        for relation_index in 0..relation_count {
            let instance = relation_index / geometry.row_count();
            let row_index = relation_index % geometry.row_count();
            let row = affine_witness_row_at(instance, row_index);
            assert_eq!(stacked_value_at(geometry, relation_index), row.low_digit);
            assert_eq!(
                stacked_value_at(geometry, relation_count + relation_index),
                row.high_digit
            );
            assert_eq!(
                stacked_value_at(geometry, 2 * relation_count + relation_index),
                row.shifted_secret
            );
            assert_eq!(
                stacked_value_at(geometry, 3 * relation_count + relation_index),
                row.negative_indicator
            );
        }
    }
}
