use core::fmt;

use aes::Aes256;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use zeroize::Zeroize;

#[cfg(test)]
use crate::tally_circuit::BooleanOperation;
use crate::tally_circuit::{CompiledTallyCircuit, TallyCircuitError, TallyCircuitProfile};

use super::preparation_plaintext::{HeldSubsetKey, sender_subset_slots};
#[cfg(test)]
use super::source::{SCORE_BIT_WIDTH, SCORE_ENCODING_COUNT};
use super::source::{SOURCE_BIT_COUNT, SOURCE_CORRECTION_BYTE_LENGTH};

mod garbling;
mod manifest;

pub(crate) use garbling::{
    ActivationChunkRange, ActivationContext, ActivationEvaluator, LocalActivationMaterial,
    VerifiedTallyTerminal, activation_chunk_ranges, generate_activation_chunk,
};
pub(crate) use manifest::{
    ActivationChunkDescriptor, ActivationManifest, activation_chunk_identity,
    encode_activation_signature_carrier, verify_activation_manifest,
};

pub const COMPLETION_PROFILE_PARTICIPANT_COUNT: usize = 10;
pub const COMPLETION_PROFILE_OPTION_COUNT: u16 = 10;
pub const FIELD_BIT_WIDTH: usize = 4;
pub const LABEL_BYTE_LENGTH: usize = 48;
pub const MATCHED_MASK_BITS_PER_CONJUNCTION: usize = 1 + 3 * FIELD_BIT_WIDTH;

const LOW_SUBSET_SIZE: u16 = 7;
const STATUS_SUBSET_SIZE: u16 = 8;
const SUBSET_STREAM_ADDRESS_VERSION: u8 = 1;
const SOURCE_STREAM_FAMILY: u8 = 1;
const MATCHED_MASK_STREAM_FAMILY: u8 = 2;
const OUTPUT_MASK_STREAM_FAMILY: u8 = 3;
const COMPLETION_PROFILE_BITMAP: u16 = (1_u16 << COMPLETION_PROFILE_PARTICIPANT_COUNT) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TallyActivationError {
    ArithmeticOverflow,
    ContinuationAuthenticationFailed,
    DuplicateResultPosition,
    InvalidCodeword,
    InvalidManifest,
    InvalidSignature,
    InvalidCorrectionInventory,
    InvalidParticipantPosition,
    InvalidSourceSubmissionBitmap,
    InvalidSubsetKeyVector,
    InvalidTerminalOutput,
    InvalidTopCount,
    MalformedActivationChunk,
    MismatchedActivationChunk,
    TallyCircuit,
}

impl fmt::Display for TallyActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArithmeticOverflow => "full-tally activation arithmetic overflow",
            Self::ContinuationAuthenticationFailed => {
                "full-tally continuation authentication failed"
            }
            Self::DuplicateResultPosition => {
                "full-tally activation produced a duplicate result position"
            }
            Self::InvalidCodeword => "full-tally activation codeword is inconsistent",
            Self::InvalidManifest => "full-tally activation manifest is invalid",
            Self::InvalidSignature => "full-tally activation signature is invalid",
            Self::InvalidCorrectionInventory => {
                "full-tally activation source corrections are inconsistent with finality"
            }
            Self::InvalidParticipantPosition => {
                "full-tally activation participant position is invalid"
            }
            Self::InvalidSourceSubmissionBitmap => {
                "full-tally activation source submission bitmap is invalid"
            }
            Self::InvalidSubsetKeyVector => {
                "full-tally activation held subset-key vector is malformed"
            }
            Self::InvalidTerminalOutput => "full-tally activation terminal output is invalid",
            Self::InvalidTopCount => "full-tally activation top count is invalid",
            Self::MalformedActivationChunk => "full-tally activation chunk is malformed",
            Self::MismatchedActivationChunk => {
                "full-tally activation chunks do not share one exact context and range"
            }
            Self::TallyCircuit => "full-tally activation circuit compilation failed",
        })
    }
}

impl std::error::Error for TallyActivationError {}

impl From<TallyCircuitError> for TallyActivationError {
    fn from(_: TallyCircuitError) -> Self {
        Self::TallyCircuit
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Gf16(u8);

impl Gf16 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    const fn new(value: u8) -> Self {
        Self(value & 0x0f)
    }

    const fn as_u8(self) -> u8 {
        self.0
    }

    const fn add(self, right: Self) -> Self {
        Self(self.0 ^ right.0)
    }

    fn multiply(self, right: Self) -> Self {
        let mut left_value = self.0;
        let mut right_value = right.0;
        let mut product = 0_u8;
        for _ in 0..FIELD_BIT_WIDTH {
            product ^= (0_u8.wrapping_sub(right_value & 1)) & left_value;
            let high_bit = left_value >> 3;
            left_value = (left_value << 1) & 0x0f;
            left_value ^= (0_u8.wrapping_sub(high_bit)) & 0x03;
            right_value >>= 1;
        }
        Self::new(product)
    }

    fn power(self, mut exponent: u8) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.multiply(base);
            }
            base = base.multiply(base);
            exponent >>= 1;
        }
        result
    }

    fn inverse(self) -> Option<Self> {
        (self != Self::ZERO).then(|| self.power(14))
    }
}

pub(crate) fn compile_completion_tally(
    top_count: u16,
) -> Result<CompiledTallyCircuit, TallyActivationError> {
    let profile = TallyCircuitProfile::new(
        COMPLETION_PROFILE_PARTICIPANT_COUNT as u16,
        COMPLETION_PROFILE_OPTION_COUNT,
        top_count,
    )
    .map_err(|_| TallyActivationError::InvalidTopCount)?;
    super_compile_tally(profile).map_err(Into::into)
}

fn super_compile_tally(
    profile: TallyCircuitProfile,
) -> Result<CompiledTallyCircuit, TallyCircuitError> {
    crate::tally_circuit::compiler::compile_tally_circuit(profile)
}

fn validate_local_material(
    local_position: u16,
    held_subset_keys: &[HeldSubsetKey],
) -> Result<(), TallyActivationError> {
    if usize::from(local_position) >= COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(TallyActivationError::InvalidParticipantPosition);
    }
    let expected_slots = sender_subset_slots(local_position);
    if held_subset_keys.len() != expected_slots.len()
        || held_subset_keys
            .iter()
            .zip(expected_slots)
            .any(|(key, (family, subset))| key.family != family || key.subset != subset)
    {
        return Err(TallyActivationError::InvalidSubsetKeyVector);
    }
    Ok(())
}

fn validate_source_inventory(
    source_submission_bitmap: u16,
    corrections: &[Option<[u8; SOURCE_CORRECTION_BYTE_LENGTH]>],
) -> Result<(), TallyActivationError> {
    if source_submission_bitmap & !COMPLETION_PROFILE_BITMAP != 0 {
        return Err(TallyActivationError::InvalidSourceSubmissionBitmap);
    }
    if corrections.len() != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(TallyActivationError::InvalidCorrectionInventory);
    }
    for (source_position, correction) in corrections.iter().enumerate() {
        let is_submitted = source_submission_bitmap & (1_u16 << source_position) != 0;
        if is_submitted != correction.is_some() {
            return Err(TallyActivationError::InvalidCorrectionInventory);
        }
    }
    Ok(())
}

fn participant_point(participant_position: u16) -> Result<Gf16, TallyActivationError> {
    if usize::from(participant_position) >= COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(TallyActivationError::InvalidParticipantPosition);
    }
    Ok(Gf16::new(u8::try_from(participant_position + 1).map_err(
        |_| TallyActivationError::InvalidParticipantPosition,
    )?))
}

fn subset_contains(subset: u16, participant_position: u16) -> bool {
    subset & (1_u16 << participant_position) != 0
}

fn outside_subset_product(subset: u16, point: Gf16) -> Gf16 {
    (0_u16..COMPLETION_PROFILE_PARTICIPANT_COUNT as u16)
        .filter(|position| !subset_contains(subset, *position))
        .fold(Gf16::ONE, |product, position| {
            product.multiply(point.add(Gf16::new((position + 1) as u8)))
        })
}

fn normalized_low_subset_polynomial(subset: u16, point: Gf16) -> Gf16 {
    let numerator = outside_subset_product(subset, point);
    let denominator = outside_subset_product(subset, Gf16::ZERO);
    numerator.multiply(
        denominator
            .inverse()
            .expect("completion-profile participant points are nonzero and distinct"),
    )
}

fn subset_stream_block(
    key: &[u8; 32],
    family: u8,
    block_index: usize,
) -> Result<[u8; 16], TallyActivationError> {
    let cipher =
        Aes256::new_from_slice(key).map_err(|_| TallyActivationError::InvalidSubsetKeyVector)?;
    let mut address = Block::<Aes256>::default();
    address[0] = SUBSET_STREAM_ADDRESS_VERSION;
    address[1] = family;
    address[2..6].copy_from_slice(
        &u32::try_from(block_index)
            .map_err(|_| TallyActivationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    cipher.encrypt_block(&mut address);
    let output = address.into();
    address.zeroize();
    Ok(output)
}

fn subset_stream_bit(
    key: &[u8; 32],
    family: u8,
    linear_bit: usize,
) -> Result<u8, TallyActivationError> {
    let block = subset_stream_block(key, family, linear_bit / 128)?;
    Ok((block[(linear_bit % 128) / 8] >> (linear_bit % 8)) & 1)
}

fn subset_stream_field(
    key: &[u8; 32],
    family: u8,
    first_linear_bit: usize,
) -> Result<Gf16, TallyActivationError> {
    let mut value = 0_u8;
    for bit_position in 0..FIELD_BIT_WIDTH {
        value |= subset_stream_bit(key, family, first_linear_bit + bit_position)? << bit_position;
    }
    Ok(Gf16::new(value))
}

fn derive_local_source_share(
    local_position: u16,
    source_position: u16,
    source_bit_ordinal: usize,
    correction: &[u8; SOURCE_CORRECTION_BYTE_LENGTH],
    held_subset_keys: &[HeldSubsetKey],
) -> Result<Gf16, TallyActivationError> {
    let point = participant_point(local_position)?;
    let mut share = Gf16::ZERO;
    for held_key in held_subset_keys {
        if held_key.family != LOW_SUBSET_SIZE || !subset_contains(held_key.subset, source_position)
        {
            continue;
        }
        let source_rank =
            usize::try_from((held_key.subset & ((1_u16 << source_position) - 1)).count_ones())
                .map_err(|_| TallyActivationError::ArithmeticOverflow)?;
        let linear_bit = source_rank
            .checked_mul(SOURCE_BIT_COUNT)
            .and_then(|start| start.checked_add(source_bit_ordinal))
            .ok_or(TallyActivationError::ArithmeticOverflow)?;
        let coefficient = subset_stream_bit(&held_key.key, SOURCE_STREAM_FAMILY, linear_bit)?;
        if coefficient != 0 {
            share = share.add(normalized_low_subset_polynomial(held_key.subset, point));
        }
    }
    let correction_bit = (correction[source_bit_ordinal / 8] >> (source_bit_ordinal % 8)) & 1;
    Ok(share.add(Gf16::new(correction_bit)))
}

fn derive_local_input_shares(
    local_position: u16,
    source_submission_bitmap: u16,
    corrections: &[Option<[u8; SOURCE_CORRECTION_BYTE_LENGTH]>],
    held_subset_keys: &[HeldSubsetKey],
) -> Result<Vec<Gf16>, TallyActivationError> {
    validate_local_material(local_position, held_subset_keys)?;
    validate_source_inventory(source_submission_bitmap, corrections)?;
    let mut shares =
        Vec::with_capacity(COMPLETION_PROFILE_PARTICIPANT_COUNT * (1 + SOURCE_BIT_COUNT));
    for (source_position, correction) in corrections.iter().enumerate() {
        let is_submitted = source_submission_bitmap & (1_u16 << source_position) != 0;
        shares.push(if is_submitted { Gf16::ONE } else { Gf16::ZERO });
        for source_bit_ordinal in 0..SOURCE_BIT_COUNT {
            let share = match correction {
                Some(correction) => derive_local_source_share(
                    local_position,
                    source_position as u16,
                    source_bit_ordinal,
                    correction,
                    held_subset_keys,
                )?,
                None => Gf16::ZERO,
            };
            shares.push(share);
        }
    }
    Ok(shares)
}

fn derive_matched_mask_shares(
    local_position: u16,
    conjunction_ordinal: usize,
    held_subset_keys: &[HeldSubsetKey],
) -> Result<(Gf16, Gf16), TallyActivationError> {
    validate_local_material(local_position, held_subset_keys)?;
    let point = participant_point(local_position)?;
    let coordinate_start = conjunction_ordinal
        .checked_mul(MATCHED_MASK_BITS_PER_CONJUNCTION)
        .ok_or(TallyActivationError::ArithmeticOverflow)?;
    let mut low_mask_share = Gf16::ZERO;
    let mut high_zero_share = Gf16::ZERO;
    for held_key in held_subset_keys {
        if held_key.family != LOW_SUBSET_SIZE {
            continue;
        }
        let normalized_basis = normalized_low_subset_polynomial(held_key.subset, point);
        if subset_stream_bit(&held_key.key, MATCHED_MASK_STREAM_FAMILY, coordinate_start)? != 0 {
            low_mask_share = low_mask_share.add(normalized_basis);
        }
        let outside_product = outside_subset_product(held_key.subset, point);
        for degree in 1..=3_usize {
            let coefficient = subset_stream_field(
                &held_key.key,
                MATCHED_MASK_STREAM_FAMILY,
                coordinate_start + 1 + (degree - 1) * FIELD_BIT_WIDTH,
            )?;
            high_zero_share = high_zero_share.add(
                coefficient
                    .multiply(point.power(degree as u8))
                    .multiply(outside_product),
            );
        }
    }
    Ok((low_mask_share, low_mask_share.add(high_zero_share)))
}

fn derive_output_mask_share(
    local_position: u16,
    output_bit_ordinal: usize,
    held_subset_keys: &[HeldSubsetKey],
) -> Result<Gf16, TallyActivationError> {
    validate_local_material(local_position, held_subset_keys)?;
    let point = participant_point(local_position)?;
    let coordinate_start = output_bit_ordinal
        .checked_mul(FIELD_BIT_WIDTH)
        .ok_or(TallyActivationError::ArithmeticOverflow)?;
    let mut output_mask_share = Gf16::ZERO;
    for held_key in held_subset_keys {
        if held_key.family != STATUS_SUBSET_SIZE {
            continue;
        }
        let coefficient =
            subset_stream_field(&held_key.key, OUTPUT_MASK_STREAM_FAMILY, coordinate_start)?;
        let basis = point.multiply(outside_subset_product(held_key.subset, point));
        output_mask_share = output_mask_share.add(coefficient.multiply(basis));
    }
    Ok(output_mask_share)
}

fn polynomial_evaluate(coefficients: &[Gf16], point: Gf16) -> Gf16 {
    coefficients
        .iter()
        .rev()
        .fold(Gf16::ZERO, |value, coefficient| {
            value.multiply(point).add(*coefficient)
        })
}

fn polynomial_multiply(left: &[Gf16], right: &[Gf16]) -> Vec<Gf16> {
    let mut product = vec![Gf16::ZERO; left.len() + right.len() - 1];
    for (left_degree, left_coefficient) in left.iter().copied().enumerate() {
        for (right_degree, right_coefficient) in right.iter().copied().enumerate() {
            product[left_degree + right_degree] = product[left_degree + right_degree]
                .add(left_coefficient.multiply(right_coefficient));
        }
    }
    product
}

fn interpolate_prefix(values: &[Gf16], degree: usize) -> Result<Vec<Gf16>, TallyActivationError> {
    if values.len() < degree + 1 || degree >= COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(TallyActivationError::InvalidCodeword);
    }
    let mut coefficients = vec![Gf16::ZERO; degree + 1];
    for (value_position, value) in values.iter().copied().enumerate().take(degree + 1) {
        let point = participant_point(value_position as u16)?;
        let mut basis = vec![Gf16::ONE];
        let mut denominator = Gf16::ONE;
        for other_position in 0..=degree {
            if other_position == value_position {
                continue;
            }
            let other_point = participant_point(other_position as u16)?;
            basis = polynomial_multiply(&basis, &[other_point, Gf16::ONE]);
            denominator = denominator.multiply(point.add(other_point));
        }
        let scale = value.multiply(
            denominator
                .inverse()
                .ok_or(TallyActivationError::InvalidCodeword)?,
        );
        for (coefficient, basis_coefficient) in coefficients.iter_mut().zip(basis) {
            *coefficient = coefficient.add(basis_coefficient.multiply(scale));
        }
    }
    Ok(coefficients)
}

fn verify_codeword(values: &[Gf16], degree: usize) -> Result<Gf16, TallyActivationError> {
    if values.len() != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(TallyActivationError::InvalidCodeword);
    }
    let coefficients = interpolate_prefix(values, degree)?;
    for (position, value) in values.iter().copied().enumerate() {
        if polynomial_evaluate(&coefficients, participant_point(position as u16)?) != value {
            return Err(TallyActivationError::InvalidCodeword);
        }
    }
    Ok(coefficients[0])
}

#[cfg(test)]
fn conjunction_count(circuit: &CompiledTallyCircuit) -> usize {
    circuit
        .operations()
        .iter()
        .filter(|operation| matches!(operation, BooleanOperation::Conjunction { .. }))
        .count()
}

#[cfg(test)]
mod tests {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;
    use crate::protocol::source::derive_honest_source_correction;

    fn subset_key(family: u16, subset: u16) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(b"sealed-lattice/test/full-tally/subset-key/v1");
        hasher.update(&family.to_le_bytes());
        hasher.update(&subset.to_le_bytes());
        let mut reader = hasher.finalize_xof();
        let mut key = [0_u8; 32];
        reader.read(&mut key);
        key
    }

    fn held_keys(participant_position: u16) -> Vec<HeldSubsetKey> {
        sender_subset_slots(participant_position)
            .into_iter()
            .map(|(family, subset)| HeldSubsetKey {
                family,
                subset,
                key: subset_key(family, subset),
            })
            .collect()
    }

    fn deterministic_scores(source_position: usize) -> [u8; SCORE_ENCODING_COUNT] {
        core::array::from_fn(|option_position| {
            ((source_position * 7 + option_position * 3 + 15) % 16) as u8
        })
    }

    #[test]
    fn every_source_bit_reconstructs_from_the_complete_subset_inventory() {
        let all_keys = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|position| held_keys(position as u16))
            .collect::<Vec<_>>();
        let scores = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(deterministic_scores)
            .collect::<Vec<_>>();
        let corrections = scores
            .iter()
            .enumerate()
            .map(|(source_position, scores)| {
                derive_honest_source_correction(
                    source_position as u16,
                    scores,
                    &all_keys[source_position],
                )
                .map(Some)
                .expect("source correction derives")
            })
            .collect::<Vec<_>>();
        let source_submission_bitmap = COMPLETION_PROFILE_BITMAP;
        let local_inputs = all_keys
            .iter()
            .enumerate()
            .map(|(local_position, keys)| {
                derive_local_input_shares(
                    local_position as u16,
                    source_submission_bitmap,
                    &corrections,
                    keys,
                )
                .expect("local input shares derive")
            })
            .collect::<Vec<_>>();

        for (source_position, score) in scores.iter().enumerate() {
            let source_wire_start = source_position * (1 + SOURCE_BIT_COUNT);
            let presence_values = local_inputs
                .iter()
                .map(|inputs| inputs[source_wire_start])
                .collect::<Vec<_>>();
            assert_eq!(verify_codeword(&presence_values, 0), Ok(Gf16::ONE));
            for source_bit_ordinal in 0..SOURCE_BIT_COUNT {
                let values = local_inputs
                    .iter()
                    .map(|inputs| inputs[source_wire_start + 1 + source_bit_ordinal])
                    .collect::<Vec<_>>();
                let expected = (score[source_bit_ordinal / SCORE_BIT_WIDTH]
                    >> (source_bit_ordinal % SCORE_BIT_WIDTH))
                    & 1;
                assert_eq!(
                    verify_codeword(&values, 3),
                    Ok(Gf16::new(expected)),
                    "source {source_position}, bit {source_bit_ordinal}"
                );
            }
        }
    }

    #[test]
    fn every_honest_source_vector_has_a_corrupt_invisible_subset_pad() {
        for corrupt_bitmap in 0_u16..=COMPLETION_PROFILE_BITMAP {
            if corrupt_bitmap.count_ones() != 3 {
                continue;
            }
            let hidden_subset = COMPLETION_PROFILE_BITMAP ^ corrupt_bitmap;
            assert_eq!(hidden_subset.count_ones(), 7);
            assert_eq!(
                normalized_low_subset_polynomial(hidden_subset, Gf16::ZERO),
                Gf16::ONE,
            );
            for corrupt_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT as u16 {
                if subset_contains(corrupt_bitmap, corrupt_position) {
                    assert!(!subset_contains(hidden_subset, corrupt_position));
                    assert_eq!(
                        normalized_low_subset_polynomial(
                            hidden_subset,
                            participant_point(corrupt_position).expect("corrupt point"),
                        ),
                        Gf16::ZERO,
                    );
                }
            }
            for honest_source in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT as u16 {
                if !subset_contains(corrupt_bitmap, honest_source) {
                    assert!(subset_contains(hidden_subset, honest_source));
                }
            }
        }
    }

    #[test]
    fn subset_stream_coordinates_are_disjoint_across_the_full_tally() {
        let mut coordinates = std::collections::BTreeSet::new();
        for source_rank in 0..LOW_SUBSET_SIZE as usize {
            for source_bit_ordinal in 0..SOURCE_BIT_COUNT {
                assert!(coordinates.insert((
                    SOURCE_STREAM_FAMILY,
                    source_rank * SOURCE_BIT_COUNT + source_bit_ordinal,
                )));
            }
        }
        let maximum_conjunction_count = 2_962;
        for conjunction_ordinal in 0..maximum_conjunction_count {
            for offset in 0..MATCHED_MASK_BITS_PER_CONJUNCTION {
                assert!(coordinates.insert((
                    MATCHED_MASK_STREAM_FAMILY,
                    conjunction_ordinal * MATCHED_MASK_BITS_PER_CONJUNCTION + offset,
                )));
            }
        }
        let maximum_output_bit_count = 11 + 4 * 10;
        for output_bit_ordinal in 0..maximum_output_bit_count {
            for offset in 0..FIELD_BIT_WIDTH {
                assert!(coordinates.insert((
                    OUTPUT_MASK_STREAM_FAMILY,
                    output_bit_ordinal * FIELD_BIT_WIDTH + offset,
                )));
            }
        }
        assert_eq!(
            coordinates.len(),
            LOW_SUBSET_SIZE as usize * SOURCE_BIT_COUNT
                + maximum_conjunction_count * MATCHED_MASK_BITS_PER_CONJUNCTION
                + maximum_output_bit_count * FIELD_BIT_WIDTH,
        );
    }

    #[test]
    fn abstaining_sources_have_public_zero_inputs() {
        let all_keys = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|position| held_keys(position as u16))
            .collect::<Vec<_>>();
        let corrections = [None; COMPLETION_PROFILE_PARTICIPANT_COUNT];
        for (local_position, keys) in all_keys.iter().enumerate() {
            let shares = derive_local_input_shares(local_position as u16, 0, &corrections, keys)
                .expect("all-abstain shares derive");
            assert!(shares.iter().all(|share| *share == Gf16::ZERO));
        }
    }

    #[test]
    fn every_matched_mask_has_one_binary_constant_at_degrees_three_and_six() {
        let all_keys = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|position| held_keys(position as u16))
            .collect::<Vec<_>>();
        for conjunction_ordinal in [0, 1, 127, 128, 2961] {
            let shares = all_keys
                .iter()
                .enumerate()
                .map(|(position, keys)| {
                    derive_matched_mask_shares(position as u16, conjunction_ordinal, keys)
                        .expect("matched mask shares derive")
                })
                .collect::<Vec<_>>();
            let low = shares.iter().map(|(low, _)| *low).collect::<Vec<_>>();
            let high = shares.iter().map(|(_, high)| *high).collect::<Vec<_>>();
            let low_constant = verify_codeword(&low, 3).expect("low mask codeword");
            let high_constant = verify_codeword(&high, 6).expect("high mask codeword");
            assert!(low_constant.as_u8() <= 1);
            assert_eq!(low_constant, high_constant);
        }
    }

    #[test]
    fn every_terminal_mask_is_degree_three_with_zero_constant() {
        let all_keys = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|position| held_keys(position as u16))
            .collect::<Vec<_>>();
        for output_bit_ordinal in 0..51 {
            let values = all_keys
                .iter()
                .enumerate()
                .map(|(position, keys)| {
                    derive_output_mask_share(position as u16, output_bit_ordinal, keys)
                        .expect("output mask derives")
                })
                .collect::<Vec<_>>();
            assert_eq!(verify_codeword(&values, 3), Ok(Gf16::ZERO));
        }
    }

    #[test]
    fn all_admitted_top_counts_compile_with_derived_output_widths() {
        let expected = [
            (1, 2098, 2153, 15),
            (2, 2290, 2515, 19),
            (3, 2458, 2837, 23),
            (4, 2602, 3113, 27),
            (5, 2722, 3343, 31),
            (6, 2818, 3527, 35),
            (7, 2890, 3665, 39),
            (8, 2938, 3757, 43),
            (9, 2962, 3803, 47),
            (10, 2962, 3803, 51),
        ];
        for (top_count, expected_ands, expected_xors, expected_outputs) in expected {
            let circuit = compile_completion_tally(top_count).expect("profile compiles");
            let ands = conjunction_count(&circuit);
            let xors = circuit
                .operations()
                .iter()
                .filter(|operation| matches!(operation, BooleanOperation::ExclusiveOr { .. }))
                .count();
            assert_eq!(circuit.input_bit_count(), 410);
            assert_eq!(circuit.output_wires().len(), expected_outputs);
            assert_eq!(ands, expected_ands, "topCount={top_count}");
            assert_eq!(xors, expected_xors, "topCount={top_count}");
            assert_eq!(circuit.profile().top_count(), top_count);
            assert_eq!(circuit.profile().participant_count(), 10);
            assert_eq!(circuit.profile().option_count(), 10);
        }
    }

    #[test]
    fn codeword_verification_refuses_one_changed_coordinate() {
        let coefficients = [Gf16::ONE, Gf16::new(7), Gf16::new(3), Gf16::new(12)];
        let mut values = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|position| {
                polynomial_evaluate(
                    &coefficients,
                    participant_point(position as u16).expect("point"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(verify_codeword(&values, 3), Ok(Gf16::ONE));
        values[9] = values[9].add(Gf16::ONE);
        assert_eq!(
            verify_codeword(&values, 3),
            Err(TallyActivationError::InvalidCodeword)
        );
    }
}
