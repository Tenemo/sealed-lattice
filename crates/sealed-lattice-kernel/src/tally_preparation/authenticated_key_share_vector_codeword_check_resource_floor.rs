use crate::{foundation::FOUNDATION_PROFILE, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_release::AuthenticatedKeyFieldCodewordChecker,
    authenticated_key_release_resource_floor::AuthenticatedKeyReleaseResourceFloor,
    authenticated_key_share_vector_codeword_check::{
        MAXIMUM_CODEWORD_CHECK_OUTPUT_FIELD_CHUNK_COUNT,
        MAXIMUM_CODEWORD_CHECK_PAYLOAD_AND_FIELD_BUFFER_COUNT,
        MAXIMUM_CODEWORD_CHECK_RETAINED_BASIS_FIELD_CHUNK_COUNT,
        MAXIMUM_CODEWORD_CHECK_SIMULTANEOUS_PAYLOAD_CHUNK_COUNT,
    },
};

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;

/// Exact algorithm-owned work and live-byte floor for one direct all-roster
/// authenticated-key codeword check.
///
/// This covers descriptor-bound payload hashing, field decoding,
/// interpolation, all nonbasis comparisons, and the Rust payload/field-array
/// live set. It excludes parsed descriptor and manifest allocations and their
/// identity work, bridge copies, allocator metadata, signatures, checkpoints,
/// persistent output, and malicious-preparation provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyShareVectorCodewordCheckResourceFloor {
    pub(crate) participant_count: u64,
    pub(crate) basis_participant_count: u64,
    pub(crate) nonbasis_participant_count: u64,
    pub(crate) verification_key_field_element_count: u64,
    pub(crate) share_vector_chunk_count: u64,
    pub(crate) checked_share_vector_count: u64,
    pub(crate) checked_payload_byte_length: u64,
    pub(crate) decoded_field_element_count: u64,
    pub(crate) reconstructed_field_element_count: u64,
    pub(crate) reconstructed_key_byte_length: u64,
    pub(crate) payload_chunk_hash_invocation_count: u64,
    pub(crate) payload_chunk_hash_absorbed_byte_length: u64,
    pub(crate) payload_chunk_hash_output_byte_length: u64,
    pub(crate) payload_chunk_hash_fixed_keccak_f1600_permutation_count: u64,
    pub(crate) maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count: u64,
    pub(crate) interpolation_coefficient_vector_count: u64,
    pub(crate) field_multiplication_count: u64,
    pub(crate) field_addition_count: u64,
    pub(crate) field_inversion_count: u64,
    pub(crate) constant_time_comparison_count: u64,
    pub(crate) maximum_simultaneous_payload_chunk_count: u64,
    pub(crate) maximum_retained_basis_field_chunk_count: u64,
    pub(crate) maximum_output_field_chunk_count: u64,
    pub(crate) maximum_payload_and_field_buffer_count: u64,
    pub(crate) maximum_payload_chunk_byte_length: u64,
    pub(crate) single_copied_buffer_absolute_bound: u64,
    pub(crate) maximum_single_copied_buffer_headroom: u64,
    pub(crate) maximum_algorithm_live_payload_and_field_byte_length: u64,
}

impl AuthenticatedKeyShareVectorCodewordCheckResourceFloor {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        let key_release = AuthenticatedKeyReleaseResourceFloor::derive(context, circuit)?;
        let checker = AuthenticatedKeyFieldCodewordChecker::new(context.participant_count())?;
        let work = checker.exact_work();
        let participant_count = key_release.participant_count;
        let basis_participant_count = key_release.reconstruction_threshold;
        let nonbasis_participant_count = participant_count
            .checked_sub(basis_participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let verification_key_field_element_count = key_release.verification_key_field_element_count;
        let maximum_payload_chunk_byte_length =
            u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let single_copied_buffer_absolute_bound =
            u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;

        Ok(Self {
            participant_count,
            basis_participant_count,
            nonbasis_participant_count,
            verification_key_field_element_count,
            share_vector_chunk_count: key_release.share_vector_chunk_count_per_sender,
            checked_share_vector_count: participant_count,
            checked_payload_byte_length: key_release.all_roster_share_payload_byte_length,
            decoded_field_element_count: checked_multiply(
                participant_count,
                verification_key_field_element_count,
            )?,
            reconstructed_field_element_count: verification_key_field_element_count,
            reconstructed_key_byte_length: checked_multiply(
                verification_key_field_element_count,
                FIELD_ELEMENT_BYTE_LENGTH,
            )?,
            payload_chunk_hash_invocation_count: checked_multiply(
                participant_count,
                key_release.payload_chunk_hash_invocation_count_per_sender,
            )?,
            payload_chunk_hash_absorbed_byte_length: checked_multiply(
                participant_count,
                key_release.payload_chunk_hash_absorbed_byte_length_per_sender,
            )?,
            payload_chunk_hash_output_byte_length: checked_multiply(
                participant_count,
                key_release.payload_chunk_hash_output_byte_length_per_sender,
            )?,
            payload_chunk_hash_fixed_keccak_f1600_permutation_count: checked_multiply(
                participant_count,
                key_release.payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender,
            )?,
            maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count: key_release
                .maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count,
            interpolation_coefficient_vector_count: work.coefficient_vector_count,
            field_multiplication_count: checked_add(
                work.coefficient_precomputation_field_multiplication_count,
                checked_multiply(
                    verification_key_field_element_count,
                    work.field_multiplication_count_per_checked_field,
                )?,
            )?,
            field_addition_count: checked_add(
                work.coefficient_precomputation_field_addition_count,
                checked_multiply(
                    verification_key_field_element_count,
                    work.field_addition_count_per_checked_field,
                )?,
            )?,
            field_inversion_count: work.coefficient_precomputation_field_inversion_count,
            constant_time_comparison_count: checked_multiply(
                verification_key_field_element_count,
                work.constant_time_comparison_count_per_checked_field,
            )?,
            maximum_simultaneous_payload_chunk_count:
                MAXIMUM_CODEWORD_CHECK_SIMULTANEOUS_PAYLOAD_CHUNK_COUNT,
            maximum_retained_basis_field_chunk_count:
                MAXIMUM_CODEWORD_CHECK_RETAINED_BASIS_FIELD_CHUNK_COUNT,
            maximum_output_field_chunk_count: MAXIMUM_CODEWORD_CHECK_OUTPUT_FIELD_CHUNK_COUNT,
            maximum_payload_and_field_buffer_count:
                MAXIMUM_CODEWORD_CHECK_PAYLOAD_AND_FIELD_BUFFER_COUNT,
            maximum_payload_chunk_byte_length,
            single_copied_buffer_absolute_bound,
            maximum_single_copied_buffer_headroom: single_copied_buffer_absolute_bound
                .checked_sub(maximum_payload_chunk_byte_length)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
            maximum_algorithm_live_payload_and_field_byte_length: checked_multiply(
                MAXIMUM_CODEWORD_CHECK_PAYLOAD_AND_FIELD_BUFFER_COUNT,
                maximum_payload_chunk_byte_length,
            )?,
        })
    }
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
