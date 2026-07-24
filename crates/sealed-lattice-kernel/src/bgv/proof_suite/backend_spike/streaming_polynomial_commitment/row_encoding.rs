//! Recomputable, randomized row encoding for the streaming commitment.

use p3_dft::{Radix2Bowers, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::GOLDILOCKS_MODULUS;

const ROW_PAD_DOMAIN: &[u8] = b"sealed-lattice/streaming-row-pad/v1";
pub(super) const ROW_CODE_LOG_INV_RATE: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RowEncodingGeometry {
    pub(super) row_count: usize,
    pub(super) witness_values_per_row: usize,
    pub(super) padded_coefficient_count: usize,
    pub(super) encoded_column_count: usize,
}

impl RowEncodingGeometry {
    pub(super) fn new(
        row_count: usize,
        witness_variable_count_per_row: usize,
    ) -> Result<Self, String> {
        if !row_count.is_power_of_two() {
            return Err(format!(
                "row count {row_count} is not a non-zero power of two"
            ));
        }
        Self::new_with_positive_row_count(
            row_count,
            witness_variable_count_per_row,
            ROW_CODE_LOG_INV_RATE,
        )
    }

    /// Geometry for an exact row-weighted batch with a construction-selected
    /// Reed-Solomon rate. A lower rate trades prover time and commitment
    /// memory for fewer authenticated columns in the final proof.
    pub(super) fn new_weighted_batch_with_log_inverse_rate(
        row_count: usize,
        witness_variable_count_per_row: usize,
        log_inverse_rate: usize,
    ) -> Result<Self, String> {
        if row_count == 0 {
            return Err("weighted row batch requires at least one row".to_owned());
        }
        Self::new_with_positive_row_count(
            row_count,
            witness_variable_count_per_row,
            log_inverse_rate,
        )
    }

    fn new_with_positive_row_count(
        row_count: usize,
        witness_variable_count_per_row: usize,
        log_inverse_rate: usize,
    ) -> Result<Self, String> {
        let log_inverse_rate = u32::try_from(log_inverse_rate)
            .map_err(|_| "row code inverse rate exceeds u32".to_owned())?;
        let witness_values_per_row = 1_usize
            .checked_shl(witness_variable_count_per_row as u32)
            .ok_or_else(|| {
                format!("row witness size 2^{witness_variable_count_per_row} exceeds usize")
            })?;
        let padded_coefficient_count = witness_values_per_row
            .checked_mul(2)
            .ok_or_else(|| "padded row coefficient count overflows usize".to_owned())?;
        let encoded_column_count = padded_coefficient_count
            .checked_shl(log_inverse_rate)
            .ok_or_else(|| "encoded row column count overflows usize".to_owned())?;
        if encoded_column_count.ilog2() as usize > Goldilocks::TWO_ADICITY {
            return Err(format!(
                "encoded row domain 2^{} exceeds Goldilocks two-adicity 2^{}",
                encoded_column_count.ilog2(),
                Goldilocks::TWO_ADICITY
            ));
        }
        Ok(Self {
            row_count,
            witness_values_per_row,
            padded_coefficient_count,
            encoded_column_count,
        })
    }

    pub(super) const fn pad_value_count(self) -> usize {
        self.witness_values_per_row
    }

    pub(super) const fn coefficient_variable_count(self) -> usize {
        self.padded_coefficient_count.ilog2() as usize
    }
}

pub(super) fn encode_row(
    geometry: RowEncodingGeometry,
    row_index: usize,
    witness_values: &[Goldilocks],
    secret_pad_seed: &[u8; 32],
) -> Result<Vec<Goldilocks>, String> {
    if row_index >= geometry.row_count {
        return Err(format!(
            "row index {row_index} is outside row count {}",
            geometry.row_count
        ));
    }
    if witness_values.len() != geometry.witness_values_per_row {
        return Err(format!(
            "row {row_index} has {} witness values, expected {}",
            witness_values.len(),
            geometry.witness_values_per_row
        ));
    }

    let mut coefficients = Vec::with_capacity(geometry.encoded_column_count);
    coefficients.extend_from_slice(witness_values);
    coefficients.extend(derive_row_pad(geometry, row_index, secret_pad_seed));
    coefficients.resize(geometry.encoded_column_count, Goldilocks::ZERO);
    Ok(Radix2Bowers.coset_dft(coefficients, Goldilocks::GENERATOR))
}

pub(super) fn padded_row_coefficients(
    geometry: RowEncodingGeometry,
    row_index: usize,
    witness_values: &[Goldilocks],
    secret_pad_seed: &[u8; 32],
) -> Result<Vec<Goldilocks>, String> {
    if row_index >= geometry.row_count {
        return Err(format!(
            "row index {row_index} is outside row count {}",
            geometry.row_count
        ));
    }
    if witness_values.len() != geometry.witness_values_per_row {
        return Err(format!(
            "row {row_index} has {} witness values, expected {}",
            witness_values.len(),
            geometry.witness_values_per_row
        ));
    }
    let mut coefficients = Vec::with_capacity(geometry.padded_coefficient_count);
    coefficients.extend_from_slice(witness_values);
    coefficients.extend(derive_row_pad(geometry, row_index, secret_pad_seed));
    Ok(coefficients)
}

fn derive_row_pad(
    geometry: RowEncodingGeometry,
    row_index: usize,
    secret_pad_seed: &[u8; 32],
) -> Vec<Goldilocks> {
    let mut state = Shake256::default();
    state.update(&(ROW_PAD_DOMAIN.len() as u64).to_le_bytes());
    state.update(ROW_PAD_DOMAIN);
    state.update(secret_pad_seed);
    state.update(&(geometry.row_count as u64).to_le_bytes());
    state.update(&(geometry.witness_values_per_row as u64).to_le_bytes());
    state.update(&(row_index as u64).to_le_bytes());
    let mut reader = state.finalize_xof();
    (0..geometry.pad_value_count())
        .map(|_| {
            loop {
                let mut bytes = [0_u8; 8];
                reader.read(&mut bytes);
                let candidate = u64::from_le_bytes(bytes);
                if candidate < GOLDILOCKS_MODULUS {
                    return Goldilocks::from_u64(candidate);
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeField64;

    use super::*;
    use crate::bgv::proof_suite::backend_spike::streaming_polynomial_commitment::algebra::coset_point;

    fn evaluate_coefficients(coefficients: &[Goldilocks], point: Goldilocks) -> Goldilocks {
        coefficients
            .iter()
            .rev()
            .fold(Goldilocks::ZERO, |evaluation, coefficient| {
                evaluation * point + *coefficient
            })
    }

    fn matrix_rank(mut matrix: Vec<Vec<Goldilocks>>) -> usize {
        if matrix.is_empty() {
            return 0;
        }
        let column_count = matrix[0].len();
        let mut pivot_row = 0_usize;
        for column_index in 0..column_count {
            let Some(nonzero_offset) = matrix[pivot_row..]
                .iter()
                .position(|row| row[column_index] != Goldilocks::ZERO)
            else {
                continue;
            };
            matrix.swap(pivot_row, pivot_row + nonzero_offset);
            let inverse = matrix[pivot_row][column_index].inverse();
            for value in &mut matrix[pivot_row][column_index..] {
                *value *= inverse;
            }
            let normalized_pivot = matrix[pivot_row][column_index..].to_vec();
            for (row_index, row) in matrix.iter_mut().enumerate() {
                if row_index == pivot_row {
                    continue;
                }
                let scale = row[column_index];
                for (value, pivot_value) in row[column_index..].iter_mut().zip(&normalized_pivot) {
                    *value -= scale * *pivot_value;
                }
            }
            pivot_row += 1;
            if pivot_row == matrix.len() {
                break;
            }
        }
        pivot_row
    }

    #[test]
    fn coset_fft_matches_direct_coefficient_evaluation() {
        for witness_variable_count_per_row in 1..=7 {
            let geometry = RowEncodingGeometry::new(8, witness_variable_count_per_row)
                .expect("valid row geometry");
            let witness = (0..geometry.witness_values_per_row)
                .map(|index| Goldilocks::from_u64(index as u64 * 19 + 11))
                .collect::<Vec<_>>();
            let seed = [witness_variable_count_per_row as u8; 32];
            let coefficients =
                padded_row_coefficients(geometry, 3, &witness, &seed).expect("valid padded row");
            let encoded = encode_row(geometry, 3, &witness, &seed).expect("valid encoded row");
            for (column_index, encoded_value) in encoded.iter().enumerate() {
                let point =
                    coset_point(geometry.encoded_column_count.ilog2() as usize, column_index)
                        .expect("valid coset point");
                assert_eq!(
                    *encoded_value,
                    evaluate_coefficients(&coefficients, point),
                    "wrong encoded value at column {column_index}"
                );
            }
        }
    }

    #[test]
    fn row_pads_are_recomputable_and_domain_separated() {
        let geometry = RowEncodingGeometry::new(8, 5).expect("valid row geometry");
        let witness = vec![Goldilocks::ZERO; geometry.witness_values_per_row];
        let first =
            padded_row_coefficients(geometry, 2, &witness, &[7; 32]).expect("valid padded row");
        let repeated =
            padded_row_coefficients(geometry, 2, &witness, &[7; 32]).expect("valid padded row");
        let different_row =
            padded_row_coefficients(geometry, 3, &witness, &[7; 32]).expect("valid padded row");
        let different_seed =
            padded_row_coefficients(geometry, 2, &witness, &[8; 32]).expect("valid padded row");
        assert_eq!(first, repeated);
        assert_ne!(first, different_row);
        assert_ne!(first, different_seed);
        assert!(
            first[geometry.witness_values_per_row..]
                .iter()
                .any(|value| value.as_canonical_u64() != 0)
        );
    }

    #[test]
    fn opened_pad_evaluation_matrix_has_full_row_rank() {
        for witness_variable_count_per_row in 3..=7 {
            let geometry = RowEncodingGeometry::new(8, witness_variable_count_per_row)
                .expect("valid row geometry");
            for query_count in 1..=geometry.pad_value_count().min(12) {
                let points = (0..query_count)
                    .map(|query_index| {
                        coset_point(
                            geometry.encoded_column_count.ilog2() as usize,
                            query_index * 3,
                        )
                        .expect("distinct coset point")
                    })
                    .collect::<Vec<_>>();
                let matrix = points
                    .iter()
                    .map(|point| {
                        let mut power = point.exp_u64(geometry.witness_values_per_row as u64);
                        (0..geometry.pad_value_count())
                            .map(|_| {
                                let value = power;
                                power *= *point;
                                value
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(matrix_rank(matrix), query_count);
            }
        }
    }

    #[test]
    fn target_geometry_has_the_expected_exact_sizes() {
        let geometry = RowEncodingGeometry::new(1 << 10, 16).expect("target row geometry");
        assert_eq!(geometry.witness_values_per_row, 1 << 16);
        assert_eq!(geometry.pad_value_count(), 1 << 16);
        assert_eq!(geometry.padded_coefficient_count, 1 << 17);
        assert_eq!(geometry.encoded_column_count, 1 << 19);
        assert_eq!(geometry.coefficient_variable_count(), 17);
        assert_eq!(
            geometry.row_count * geometry.witness_values_per_row,
            1 << 26
        );
    }

    #[test]
    fn malformed_row_geometry_and_inputs_are_rejected() {
        assert!(RowEncodingGeometry::new(0, 4).is_err());
        assert!(RowEncodingGeometry::new(3, 4).is_err());
        let geometry = RowEncodingGeometry::new(8, 4).expect("valid row geometry");
        let witness = vec![Goldilocks::ZERO; geometry.witness_values_per_row];
        assert!(encode_row(geometry, 8, &witness, &[0; 32]).is_err());
        assert!(encode_row(geometry, 0, &witness[..15], &[0; 32]).is_err());
    }
}
