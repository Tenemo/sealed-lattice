//! Recomputable row encoding with an explicit public or private high half.

#[cfg(test)]
use p3_dft::{Radix2Bowers, TwoAdicSubgroupDft};
#[cfg(test)]
use p3_field::Field;
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

use super::GOLDILOCKS_MODULUS;
use crate::bgv::proof_suite::{
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, ProofBaseFieldElement,
};

pub(super) const PRIVATE_ROW_HIGH_HALF_DOMAIN: &[u8] = b"sealed-lattice/streaming-row-pad/v2";
pub(super) const PRIVATE_ROW_PAD_SEED_BYTE_LENGTH: usize = 64;
pub(super) const PRIVATE_ROW_PAD_PHASE_COUNT: usize = 3;
pub(super) const PRIVATE_ROW_PAD_SEED_MATERIAL_BYTE_LENGTH: usize =
    PRIVATE_ROW_PAD_PHASE_COUNT * PRIVATE_ROW_PAD_SEED_BYTE_LENGTH;
pub(super) type PrivateRowPadSeed = [u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) type PrivateRowPadSeeds = [PrivateRowPadSeed; PRIVATE_ROW_PAD_PHASE_COUNT];
#[cfg(test)]
pub(super) const ROW_CODE_LOG_INV_RATE: usize = 2;

/// Operative high-half choice for a row-code message. The caller supplies the
/// complete canonical low half, including zeros after a partial chunk and in
/// unused suffix slots. Public rows append literal zeros and therefore remain
/// the plain Reed-Solomon encoding of those coefficients. Secret rows append
/// the existing private, domain-separated masking coefficients. Transform
/// slack after the complete coefficient message is always zero-filled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RowCodeHighHalfSource<'seed> {
    CanonicalPublicZeros,
    PrivateMaskSeed(&'seed PrivateRowPadSeed),
}

impl<'seed> From<&'seed PrivateRowPadSeed> for RowCodeHighHalfSource<'seed> {
    fn from(private_seed: &'seed PrivateRowPadSeed) -> Self {
        Self::PrivateMaskSeed(private_seed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RowEncodingError {
    RowIndexOutsideGeometry {
        row_index: usize,
        row_count: usize,
    },
    WitnessValueCountMismatch {
        row_index: usize,
        actual_value_count: usize,
        expected_value_count: usize,
    },
    EncodedRowCapacityInsufficient {
        actual_capacity: usize,
        required_capacity: usize,
    },
    PrivateHighHalfCandidateDrawsExhausted {
        output_index: usize,
    },
}

impl core::fmt::Display for RowEncodingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RowIndexOutsideGeometry {
                row_index,
                row_count,
            } => write!(
                formatter,
                "row index {row_index} is outside row count {row_count}"
            ),
            Self::WitnessValueCountMismatch {
                row_index,
                actual_value_count,
                expected_value_count,
            } => write!(
                formatter,
                "row {row_index} has {actual_value_count} witness values, expected {expected_value_count}"
            ),
            Self::EncodedRowCapacityInsufficient {
                actual_capacity,
                required_capacity,
            } => write!(
                formatter,
                "row buffer capacity {actual_capacity} is below padded-coefficient capacity {required_capacity}"
            ),
            Self::PrivateHighHalfCandidateDrawsExhausted { output_index } => write!(
                formatter,
                "private row high-half output {output_index} exhausted its {PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT} candidate draws"
            ),
        }
    }
}

impl From<RowEncodingError> for String {
    fn from(error: RowEncodingError) -> Self {
        error.to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RowEncodingGeometry {
    pub(super) row_count: usize,
    pub(super) witness_values_per_row: usize,
    pub(super) padded_coefficient_count: usize,
    pub(super) encoded_column_count: usize,
}

impl RowEncodingGeometry {
    #[cfg(test)]
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

    #[cfg(test)]
    pub(super) const fn coefficient_variable_count(self) -> usize {
        self.padded_coefficient_count.ilog2() as usize
    }
}

#[cfg(test)]
pub(super) fn encode_row<'seed>(
    geometry: RowEncodingGeometry,
    row_index: usize,
    witness_values: &[Goldilocks],
    high_half_source: impl Into<RowCodeHighHalfSource<'seed>>,
) -> Result<Vec<Goldilocks>, RowEncodingError> {
    if row_index >= geometry.row_count {
        return Err(RowEncodingError::RowIndexOutsideGeometry {
            row_index,
            row_count: geometry.row_count,
        });
    }
    if witness_values.len() != geometry.witness_values_per_row {
        return Err(RowEncodingError::WitnessValueCountMismatch {
            row_index,
            actual_value_count: witness_values.len(),
            expected_value_count: geometry.witness_values_per_row,
        });
    }

    let mut coefficients = Vec::with_capacity(geometry.encoded_column_count);
    coefficients.extend_from_slice(witness_values);
    append_row_high_half(
        &mut coefficients,
        geometry,
        row_index,
        high_half_source.into(),
    )?;
    coefficients.resize(geometry.encoded_column_count, Goldilocks::ZERO);
    Ok(Radix2Bowers.coset_dft(coefficients, Goldilocks::GENERATOR))
}

pub(super) fn padded_row_coefficients<'seed>(
    geometry: RowEncodingGeometry,
    row_index: usize,
    witness_values: &[Goldilocks],
    high_half_source: impl Into<RowCodeHighHalfSource<'seed>>,
) -> Result<Vec<Goldilocks>, RowEncodingError> {
    if row_index >= geometry.row_count {
        return Err(RowEncodingError::RowIndexOutsideGeometry {
            row_index,
            row_count: geometry.row_count,
        });
    }
    if witness_values.len() != geometry.witness_values_per_row {
        return Err(RowEncodingError::WitnessValueCountMismatch {
            row_index,
            actual_value_count: witness_values.len(),
            expected_value_count: geometry.witness_values_per_row,
        });
    }
    let mut coefficients = Vec::with_capacity(geometry.padded_coefficient_count);
    coefficients.extend_from_slice(witness_values);
    append_row_high_half(
        &mut coefficients,
        geometry,
        row_index,
        high_half_source.into(),
    )?;
    Ok(coefficients)
}

/// Extends an owned base-field witness into the exact padded row message
/// without allocating a second witness-sized vector.
///
/// The caller is expected to reserve the padded-coefficient capacity before
/// loading the witness. A bounded full-domain DFT may reserve more, while an
/// interleaved lane DFT reuses exactly the larger of this message and one
/// output lane.
pub(super) fn padded_base_row_coefficients<'seed>(
    geometry: RowEncodingGeometry,
    row_index: usize,
    mut witness_values: Zeroizing<Vec<ProofBaseFieldElement>>,
    high_half_source: impl Into<RowCodeHighHalfSource<'seed>>,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, RowEncodingError> {
    if row_index >= geometry.row_count {
        return Err(RowEncodingError::RowIndexOutsideGeometry {
            row_index,
            row_count: geometry.row_count,
        });
    }
    if witness_values.len() != geometry.witness_values_per_row {
        return Err(RowEncodingError::WitnessValueCountMismatch {
            row_index,
            actual_value_count: witness_values.len(),
            expected_value_count: geometry.witness_values_per_row,
        });
    }
    if witness_values.capacity() < geometry.padded_coefficient_count {
        return Err(RowEncodingError::EncodedRowCapacityInsufficient {
            actual_capacity: witness_values.capacity(),
            required_capacity: geometry.padded_coefficient_count,
        });
    }

    match high_half_source.into() {
        RowCodeHighHalfSource::CanonicalPublicZeros => {
            witness_values.resize(
                geometry.padded_coefficient_count,
                ProofBaseFieldElement::ZERO,
            );
        }
        RowCodeHighHalfSource::PrivateMaskSeed(private_seed) => {
            let mut reader = private_row_high_half_reader(geometry, row_index, private_seed);
            append_private_row_high_half_from_candidates(
                geometry.pad_value_count(),
                || {
                    let mut bytes = [0_u8; 8];
                    reader.read(&mut bytes);
                    u64::from_le_bytes(bytes)
                },
                |candidate| {
                    witness_values.push(ProofBaseFieldElement::from_reduced(u128::from(candidate)));
                },
            )?;
        }
    }
    Ok(witness_values)
}

fn append_row_high_half(
    coefficients: &mut Vec<Goldilocks>,
    geometry: RowEncodingGeometry,
    row_index: usize,
    high_half_source: RowCodeHighHalfSource<'_>,
) -> Result<(), RowEncodingError> {
    match high_half_source {
        RowCodeHighHalfSource::CanonicalPublicZeros => {
            coefficients.resize(geometry.padded_coefficient_count, Goldilocks::ZERO);
        }
        RowCodeHighHalfSource::PrivateMaskSeed(private_seed) => {
            coefficients.extend(derive_private_row_high_half(
                geometry,
                row_index,
                private_seed,
            )?);
        }
    }
    Ok(())
}

fn derive_private_row_high_half(
    geometry: RowEncodingGeometry,
    row_index: usize,
    private_seed: &PrivateRowPadSeed,
) -> Result<Vec<Goldilocks>, RowEncodingError> {
    let mut reader = private_row_high_half_reader(geometry, row_index, private_seed);
    derive_private_row_high_half_from_candidates(geometry.pad_value_count(), || {
        let mut bytes = [0_u8; 8];
        reader.read(&mut bytes);
        u64::from_le_bytes(bytes)
    })
}

fn private_row_high_half_reader(
    geometry: RowEncodingGeometry,
    row_index: usize,
    private_seed: &PrivateRowPadSeed,
) -> impl XofReader {
    let mut state = Shake256::default();
    visit_private_row_high_half_xof_input_parts(geometry, row_index, private_seed, |part| {
        state.update(part);
    });
    state.finalize_xof()
}

fn visit_private_row_high_half_xof_input_parts(
    geometry: RowEncodingGeometry,
    row_index: usize,
    private_seed: &PrivateRowPadSeed,
    mut visit: impl FnMut(&[u8]),
) {
    let domain_byte_length = (PRIVATE_ROW_HIGH_HALF_DOMAIN.len() as u64).to_le_bytes();
    let row_count = (geometry.row_count as u64).to_le_bytes();
    let witness_values_per_row = (geometry.witness_values_per_row as u64).to_le_bytes();
    let row_index = (row_index as u64).to_le_bytes();
    for part in [
        domain_byte_length.as_slice(),
        PRIVATE_ROW_HIGH_HALF_DOMAIN,
        private_seed.as_slice(),
        row_count.as_slice(),
        witness_values_per_row.as_slice(),
        row_index.as_slice(),
    ] {
        visit(part);
    }
}

#[cfg(test)]
pub(super) fn private_row_high_half_xof_input_bytes(
    geometry: RowEncodingGeometry,
    row_index: usize,
    private_seed: &PrivateRowPadSeed,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    visit_private_row_high_half_xof_input_parts(geometry, row_index, private_seed, |part| {
        bytes.extend_from_slice(part);
    });
    bytes
}

fn derive_private_row_high_half_from_candidates(
    output_count: usize,
    mut next_candidate: impl FnMut() -> u64,
) -> Result<Vec<Goldilocks>, RowEncodingError> {
    let mut high_half = Vec::with_capacity(output_count);
    append_private_row_high_half_from_candidates(output_count, &mut next_candidate, |candidate| {
        high_half.push(Goldilocks::from_u64(candidate))
    })?;
    Ok(high_half)
}

fn append_private_row_high_half_from_candidates(
    output_count: usize,
    mut next_candidate: impl FnMut() -> u64,
    mut append_candidate: impl FnMut(u64),
) -> Result<(), RowEncodingError> {
    'next_output: for output_index in 0..output_count {
        for _ in 0..PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
            let candidate = next_candidate();
            if candidate < GOLDILOCKS_MODULUS {
                append_candidate(candidate);
                continue 'next_output;
            }
        }
        return Err(RowEncodingError::PrivateHighHalfCandidateDrawsExhausted { output_index });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeField64;

    use super::*;
    use crate::bgv::proof_suite::row_code_whir::algebra::coset_point;

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
            let seed = [witness_variable_count_per_row as u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
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
    fn private_high_halves_are_recomputable_domain_separated_and_byte_stable() {
        let geometry = RowEncodingGeometry::new(8, 5).expect("valid row geometry");
        let witness = vec![Goldilocks::ZERO; geometry.witness_values_per_row];
        let private_seed = [7_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        let different_private_seed = [8_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        let first = padded_row_coefficients(
            geometry,
            2,
            &witness,
            RowCodeHighHalfSource::PrivateMaskSeed(&private_seed),
        )
        .expect("valid padded row");
        let repeated = padded_row_coefficients(
            geometry,
            2,
            &witness,
            RowCodeHighHalfSource::PrivateMaskSeed(&private_seed),
        )
        .expect("valid padded row");
        let different_row = padded_row_coefficients(
            geometry,
            3,
            &witness,
            RowCodeHighHalfSource::PrivateMaskSeed(&private_seed),
        )
        .expect("valid padded row");
        let different_seed = padded_row_coefficients(
            geometry,
            2,
            &witness,
            RowCodeHighHalfSource::PrivateMaskSeed(&different_private_seed),
        )
        .expect("valid padded row");
        assert_eq!(first, repeated);
        assert_ne!(first, different_row);
        assert_ne!(first, different_seed);
        let private_high_half_prefix: [u64; 8] = core::array::from_fn(|offset| {
            first[geometry.witness_values_per_row + offset].as_canonical_u64()
        });
        assert_eq!(
            private_high_half_prefix,
            [
                6_645_843_431_585_673_738,
                17_924_498_531_685_365_569,
                1_209_470_546_136_710_254,
                12_909_837_768_841_462_571,
                5_358_607_777_776_252_191,
                11_575_283_767_032_415_302,
                4_077_034_257_465_865_420,
                8_018_090_511_388_552_529,
            ]
        );
        assert!(
            first[geometry.witness_values_per_row..]
                .iter()
                .any(|value| value.as_canonical_u64() != 0)
        );
    }

    #[test]
    fn private_high_half_xof_frame_binds_seed_geometry_and_row() {
        let geometry = RowEncodingGeometry::new(8, 5).expect("valid row geometry");
        let different_row_count =
            RowEncodingGeometry::new(16, 5).expect("valid different row-count geometry");
        let different_witness_width =
            RowEncodingGeometry::new(8, 6).expect("valid different witness-width geometry");
        let seed = [7_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        let different_seed = [8_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        let frame = private_row_high_half_xof_input_bytes(geometry, 2, &seed);
        let domain_start = size_of::<u64>();
        let seed_start = domain_start + PRIVATE_ROW_HIGH_HALF_DOMAIN.len();
        let geometry_start = seed_start + PRIVATE_ROW_PAD_SEED_BYTE_LENGTH;
        let expected_byte_length = geometry_start + 3 * size_of::<u64>();

        assert_eq!(
            PRIVATE_ROW_HIGH_HALF_DOMAIN,
            b"sealed-lattice/streaming-row-pad/v2"
        );
        assert_eq!(frame.len(), expected_byte_length);
        assert_eq!(
            &frame[..domain_start],
            &(PRIVATE_ROW_HIGH_HALF_DOMAIN.len() as u64).to_le_bytes()
        );
        assert_eq!(
            &frame[domain_start..seed_start],
            PRIVATE_ROW_HIGH_HALF_DOMAIN
        );
        assert_eq!(
            &frame[seed_start..geometry_start],
            seed.as_slice(),
            "the complete 512-bit secret prefix is framed before public coordinates",
        );
        assert_eq!(
            &frame[geometry_start..geometry_start + 8],
            &(geometry.row_count as u64).to_le_bytes()
        );
        assert_eq!(
            &frame[geometry_start + 8..geometry_start + 16],
            &(geometry.witness_values_per_row as u64).to_le_bytes()
        );
        assert_eq!(
            &frame[geometry_start + 16..geometry_start + 24],
            &2_u64.to_le_bytes()
        );

        for distinct_frame in [
            private_row_high_half_xof_input_bytes(geometry, 3, &seed),
            private_row_high_half_xof_input_bytes(different_row_count, 2, &seed),
            private_row_high_half_xof_input_bytes(different_witness_width, 2, &seed),
            private_row_high_half_xof_input_bytes(geometry, 2, &different_seed),
        ] {
            assert_ne!(frame, distinct_frame);
        }
    }

    #[test]
    fn both_high_half_modes_preserve_canonical_low_half_suffix_boundaries() {
        const LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT: usize = 1 << 15;
        const LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW: usize = 8;

        let geometry = RowEncodingGeometry::new(8, 18).expect("valid selected row geometry");
        assert_eq!(
            geometry.witness_values_per_row,
            LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT * LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW
        );
        assert_eq!(geometry.padded_coefficient_count, 1 << 19);
        assert_eq!(geometry.encoded_column_count, 1 << 21);
        let mut witness = vec![Goldilocks::ZERO; geometry.witness_values_per_row];
        for (coefficient_index, coefficient) in witness[..LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT]
            .iter_mut()
            .enumerate()
        {
            *coefficient = Goldilocks::from_u64(coefficient_index as u64 + 1);
        }
        let partial_final_logical_chunk_start = LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
        let partial_final_logical_chunk_coefficient_count = 17_usize;
        for (coefficient_offset, coefficient) in witness[partial_final_logical_chunk_start
            ..partial_final_logical_chunk_start + partial_final_logical_chunk_coefficient_count]
            .iter_mut()
            .enumerate()
        {
            *coefficient = Goldilocks::from_u64(100_001 + coefficient_offset as u64);
        }

        let partial_final_logical_chunk_suffix_start =
            partial_final_logical_chunk_start + partial_final_logical_chunk_coefficient_count;
        let partial_final_logical_chunk_end = 2 * LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT;
        let unused_suffix_only_logical_slots_start = partial_final_logical_chunk_end;
        let assert_canonical_low_half_suffixes = |coefficients: &[Goldilocks]| {
            assert_eq!(
                &coefficients[..geometry.witness_values_per_row],
                witness.as_slice()
            );
            assert!(
                coefficients
                    [partial_final_logical_chunk_suffix_start..partial_final_logical_chunk_end]
                    .iter()
                    .all(|coefficient| *coefficient == Goldilocks::ZERO)
            );
            assert!(
                coefficients
                    [unused_suffix_only_logical_slots_start..geometry.witness_values_per_row]
                    .iter()
                    .all(|coefficient| *coefficient == Goldilocks::ZERO)
            );
        };

        for row_index in [0_usize, 4, 7] {
            let public_coefficients = padded_row_coefficients(
                geometry,
                row_index,
                &witness,
                RowCodeHighHalfSource::CanonicalPublicZeros,
            )
            .expect("valid canonical public row");
            assert_canonical_low_half_suffixes(&public_coefficients);
            assert!(
                public_coefficients
                    [geometry.witness_values_per_row..geometry.padded_coefficient_count]
                    .iter()
                    .all(|coefficient| *coefficient == Goldilocks::ZERO)
            );
        }

        let private_seed = [9_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        let private_coefficients = padded_row_coefficients(
            geometry,
            4,
            &witness,
            RowCodeHighHalfSource::PrivateMaskSeed(&private_seed),
        )
        .expect("valid private masked row");
        assert_canonical_low_half_suffixes(&private_coefficients);
        assert!(
            private_coefficients
                [geometry.witness_values_per_row..geometry.padded_coefficient_count]
                .iter()
                .any(|coefficient| *coefficient != Goldilocks::ZERO)
        );
    }

    #[test]
    fn canonical_public_row_equals_direct_plain_reed_solomon_encoding() {
        let geometry = RowEncodingGeometry::new(8, 6).expect("valid row geometry");
        let witness = (0..geometry.witness_values_per_row)
            .map(|coefficient_index| Goldilocks::from_u64(29 * coefficient_index as u64 + 13))
            .collect::<Vec<_>>();
        let encoded = encode_row(
            geometry,
            5,
            &witness,
            RowCodeHighHalfSource::CanonicalPublicZeros,
        )
        .expect("valid canonical public row");

        let mut direct_plain_reed_solomon_coefficients = padded_row_coefficients(
            geometry,
            5,
            &witness,
            RowCodeHighHalfSource::CanonicalPublicZeros,
        )
        .expect("valid canonical public coefficients");
        let transform_slack_start = direct_plain_reed_solomon_coefficients.len();
        direct_plain_reed_solomon_coefficients
            .resize(geometry.encoded_column_count, Goldilocks::ZERO);
        assert!(
            direct_plain_reed_solomon_coefficients[transform_slack_start..]
                .iter()
                .all(|coefficient| *coefficient == Goldilocks::ZERO)
        );
        let direct_plain_reed_solomon_encoding = Radix2Bowers.coset_dft(
            direct_plain_reed_solomon_coefficients,
            Goldilocks::GENERATOR,
        );
        assert_eq!(encoded, direct_plain_reed_solomon_encoding);
    }

    #[test]
    fn zero_private_mask_seed_does_not_alias_canonical_public_zeros() {
        let geometry = RowEncodingGeometry::new(8, 5).expect("valid row geometry");
        let witness = vec![Goldilocks::ZERO; geometry.witness_values_per_row];
        let zero_private_seed = [0_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        let public_source = RowCodeHighHalfSource::CanonicalPublicZeros;
        let private_source = RowCodeHighHalfSource::PrivateMaskSeed(&zero_private_seed);
        assert_ne!(public_source, private_source);

        let public_coefficients = padded_row_coefficients(geometry, 1, &witness, public_source)
            .expect("valid canonical public row");
        let private_coefficients = padded_row_coefficients(geometry, 1, &witness, private_source)
            .expect("valid private masked row");
        assert_eq!(
            &public_coefficients[..geometry.witness_values_per_row],
            &private_coefficients[..geometry.witness_values_per_row]
        );
        assert!(
            public_coefficients[geometry.witness_values_per_row..]
                .iter()
                .all(|coefficient| *coefficient == Goldilocks::ZERO)
        );
        assert!(
            private_coefficients[geometry.witness_values_per_row..]
                .iter()
                .any(|coefficient| *coefficient != Goldilocks::ZERO)
        );
        assert_ne!(public_coefficients, private_coefficients);
    }

    #[test]
    fn bounded_base_row_requires_and_reuses_the_padded_coefficient_capacity() {
        let geometry = RowEncodingGeometry::new_weighted_batch_with_log_inverse_rate(4, 4, 2)
            .expect("the focused geometry is valid");
        let undersized = Zeroizing::new(vec![
            ProofBaseFieldElement::ONE;
            geometry.witness_values_per_row
        ]);
        assert!(matches!(
            padded_base_row_coefficients(
                geometry,
                0,
                undersized,
                RowCodeHighHalfSource::CanonicalPublicZeros,
            ),
            Err(RowEncodingError::EncodedRowCapacityInsufficient {
                required_capacity,
                ..
            }) if required_capacity == geometry.padded_coefficient_count
        ));

        let mut reserved = Vec::new();
        reserved
            .try_reserve_exact(geometry.padded_coefficient_count)
            .expect("the focused coefficient reservation succeeds");
        reserved.resize(geometry.witness_values_per_row, ProofBaseFieldElement::ONE);
        let reserved_capacity = reserved.capacity();
        let padded = padded_base_row_coefficients(
            geometry,
            2,
            Zeroizing::new(reserved),
            RowCodeHighHalfSource::PrivateMaskSeed(&[0x39_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH]),
        )
        .expect("the reserved base row pads in place");
        assert_eq!(padded.len(), geometry.padded_coefficient_count);
        assert_eq!(padded.capacity(), reserved_capacity);
    }

    #[test]
    fn private_high_half_sampling_enforces_the_selected_ceiling_per_output() {
        assert_eq!(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, 128);

        let mut final_allowed_draw_count = 0_usize;
        let accepted_at_ceiling = derive_private_row_high_half_from_candidates(1, || {
            final_allowed_draw_count += 1;
            if final_allowed_draw_count
                == PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT as usize
            {
                GOLDILOCKS_MODULUS - 1
            } else {
                GOLDILOCKS_MODULUS
            }
        })
        .expect("the final candidate within the selected ceiling is accepted");
        assert_eq!(final_allowed_draw_count, 128);
        assert_eq!(
            accepted_at_ceiling,
            vec![Goldilocks::from_u64(GOLDILOCKS_MODULUS - 1)]
        );

        let mut hostile_candidate_draw_count = 0_usize;
        let exhaustion = derive_private_row_high_half_from_candidates(2, || {
            hostile_candidate_draw_count += 1;
            if hostile_candidate_draw_count == 1 {
                7
            } else {
                GOLDILOCKS_MODULUS
            }
        });
        assert_eq!(
            exhaustion,
            Err(RowEncodingError::PrivateHighHalfCandidateDrawsExhausted { output_index: 1 })
        );
        assert_eq!(
            hostile_candidate_draw_count,
            1 + PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT as usize
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
        let private_seed = [0_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        for high_half_source in [
            RowCodeHighHalfSource::CanonicalPublicZeros,
            RowCodeHighHalfSource::PrivateMaskSeed(&private_seed),
        ] {
            assert!(encode_row(geometry, 8, &witness, high_half_source).is_err());
            assert!(encode_row(geometry, 0, &witness[..15], high_half_source).is_err());
        }
    }
}
