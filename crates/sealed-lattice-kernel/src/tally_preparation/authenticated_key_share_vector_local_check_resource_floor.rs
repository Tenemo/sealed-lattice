use crate::{foundation::FOUNDATION_PROFILE, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_release::{
        AuthenticatedKeyFieldLocalCheckWork, AuthenticatedKeyFieldLocalChecker,
    },
    authenticated_key_release_resource_floor::AuthenticatedKeyReleaseResourceFloor,
    authenticated_key_share_vector_local_check::{
        MAXIMUM_LOCAL_CHECK_FIELD_ACCUMULATOR_COUNT,
        MAXIMUM_LOCAL_CHECK_PAYLOAD_AND_ACCUMULATOR_BUFFER_COUNT,
        MAXIMUM_LOCAL_CHECK_SIMULTANEOUS_PAYLOAD_CHUNK_COUNT,
    },
};

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;

/// Exact algorithm-owned work and live-byte floor for the streamed local
/// authenticated-key check.
///
/// This covers descriptor-bound payload hashing, field decoding,
/// interpolation, local-point comparison, and the Rust payload/accumulator
/// live set. It excludes bridge copies, allocator metadata, signatures,
/// checkpoints, persistent storage, and malicious-preparation provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyShareVectorLocalCheckResourceFloor {
    pub(crate) participant_count: u64,
    pub(crate) basis_participant_count: u64,
    pub(crate) nonbasis_participant_count: u64,
    pub(crate) verification_key_field_element_count: u64,
    pub(crate) share_vector_chunk_count: u64,
    pub(crate) checked_share_vector_count_per_participant: u64,
    pub(crate) checked_payload_byte_length_per_participant: u64,
    pub(crate) checked_payload_byte_length_all_participants: u64,
    pub(crate) decoded_field_element_count_per_participant: u64,
    pub(crate) decoded_field_element_count_all_participants: u64,
    pub(crate) reconstructed_field_element_count_per_participant: u64,
    pub(crate) reconstructed_key_byte_length_per_participant: u64,
    pub(crate) payload_chunk_hash_invocation_count_per_participant: u64,
    pub(crate) payload_chunk_hash_invocation_count_all_participants: u64,
    pub(crate) payload_chunk_hash_absorbed_byte_length_per_participant: u64,
    pub(crate) payload_chunk_hash_absorbed_byte_length_all_participants: u64,
    pub(crate) payload_chunk_hash_output_byte_length_per_participant: u64,
    pub(crate) payload_chunk_hash_output_byte_length_all_participants: u64,
    pub(crate) payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_participant: u64,
    pub(crate) payload_chunk_hash_fixed_keccak_f1600_permutation_count_all_participants: u64,
    pub(crate) maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count: u64,
    pub(crate) basis_participant_field_multiplication_count: u64,
    pub(crate) basis_participant_field_addition_count: u64,
    pub(crate) basis_participant_field_inversion_count: u64,
    pub(crate) nonbasis_participant_field_multiplication_count: u64,
    pub(crate) nonbasis_participant_field_addition_count: u64,
    pub(crate) nonbasis_participant_field_inversion_count: u64,
    pub(crate) all_participant_field_multiplication_count: u64,
    pub(crate) all_participant_field_addition_count: u64,
    pub(crate) all_participant_field_inversion_count: u64,
    pub(crate) all_participant_constant_time_comparison_count: u64,
    pub(crate) maximum_simultaneous_payload_chunk_count: u64,
    pub(crate) maximum_field_accumulator_count: u64,
    pub(crate) maximum_payload_chunk_byte_length: u64,
    pub(crate) single_copied_buffer_absolute_bound: u64,
    pub(crate) maximum_single_copied_buffer_headroom: u64,
    pub(crate) maximum_algorithm_live_payload_and_accumulator_byte_length: u64,
}

impl AuthenticatedKeyShareVectorLocalCheckResourceFloor {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        let key_release = AuthenticatedKeyReleaseResourceFloor::derive(context, circuit)?;
        let participant_count = key_release.participant_count;
        let basis_participant_count = key_release.reconstruction_threshold;
        let nonbasis_participant_count = participant_count
            .checked_sub(basis_participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let basis_checker = AuthenticatedKeyFieldLocalChecker::new(context.participant_count(), 0)?;
        let nonbasis_position = u16::try_from(basis_participant_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let nonbasis_checker =
            AuthenticatedKeyFieldLocalChecker::new(context.participant_count(), nonbasis_position)?;
        let basis_work = basis_checker.exact_work();
        let nonbasis_work = nonbasis_checker.exact_work();
        let verification_key_field_element_count = key_release.verification_key_field_element_count;
        let checked_share_vector_count_per_participant = basis_participant_count
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        let checked_payload_byte_length_per_participant = checked_multiply(
            checked_share_vector_count_per_participant,
            key_release.share_vector_byte_length_per_sender,
        )?;
        let decoded_field_element_count_per_participant = checked_multiply(
            checked_share_vector_count_per_participant,
            verification_key_field_element_count,
        )?;
        let payload_chunk_hash_invocation_count_per_participant = checked_multiply(
            checked_share_vector_count_per_participant,
            key_release.payload_chunk_hash_invocation_count_per_sender,
        )?;
        let payload_chunk_hash_absorbed_byte_length_per_participant = checked_multiply(
            checked_share_vector_count_per_participant,
            key_release.payload_chunk_hash_absorbed_byte_length_per_sender,
        )?;
        let payload_chunk_hash_output_byte_length_per_participant = checked_multiply(
            checked_share_vector_count_per_participant,
            key_release.payload_chunk_hash_output_byte_length_per_sender,
        )?;
        let payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_participant =
            checked_multiply(
                checked_share_vector_count_per_participant,
                key_release.payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender,
            )?;
        let basis_participant_field_multiplication_count = complete_field_work(
            basis_work,
            verification_key_field_element_count,
            FieldWorkKind::Multiplication,
        )?;
        let basis_participant_field_addition_count = complete_field_work(
            basis_work,
            verification_key_field_element_count,
            FieldWorkKind::Addition,
        )?;
        let nonbasis_participant_field_multiplication_count = complete_field_work(
            nonbasis_work,
            verification_key_field_element_count,
            FieldWorkKind::Multiplication,
        )?;
        let nonbasis_participant_field_addition_count = complete_field_work(
            nonbasis_work,
            verification_key_field_element_count,
            FieldWorkKind::Addition,
        )?;
        let maximum_payload_chunk_byte_length =
            u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let single_copied_buffer_absolute_bound =
            u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let maximum_algorithm_live_payload_and_accumulator_byte_length = checked_multiply(
            MAXIMUM_LOCAL_CHECK_PAYLOAD_AND_ACCUMULATOR_BUFFER_COUNT,
            maximum_payload_chunk_byte_length,
        )?;

        Ok(Self {
            participant_count,
            basis_participant_count,
            nonbasis_participant_count,
            verification_key_field_element_count,
            share_vector_chunk_count: key_release.share_vector_chunk_count_per_sender,
            checked_share_vector_count_per_participant,
            checked_payload_byte_length_per_participant,
            checked_payload_byte_length_all_participants: checked_multiply(
                checked_payload_byte_length_per_participant,
                participant_count,
            )?,
            decoded_field_element_count_per_participant,
            decoded_field_element_count_all_participants: checked_multiply(
                decoded_field_element_count_per_participant,
                participant_count,
            )?,
            reconstructed_field_element_count_per_participant: verification_key_field_element_count,
            reconstructed_key_byte_length_per_participant: checked_multiply(
                verification_key_field_element_count,
                FIELD_ELEMENT_BYTE_LENGTH,
            )?,
            payload_chunk_hash_invocation_count_per_participant,
            payload_chunk_hash_invocation_count_all_participants: checked_multiply(
                payload_chunk_hash_invocation_count_per_participant,
                participant_count,
            )?,
            payload_chunk_hash_absorbed_byte_length_per_participant,
            payload_chunk_hash_absorbed_byte_length_all_participants: checked_multiply(
                payload_chunk_hash_absorbed_byte_length_per_participant,
                participant_count,
            )?,
            payload_chunk_hash_output_byte_length_per_participant,
            payload_chunk_hash_output_byte_length_all_participants: checked_multiply(
                payload_chunk_hash_output_byte_length_per_participant,
                participant_count,
            )?,
            payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_participant,
            payload_chunk_hash_fixed_keccak_f1600_permutation_count_all_participants:
                checked_multiply(
                    payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_participant,
                    participant_count,
                )?,
            maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count: key_release
                .maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count,
            basis_participant_field_multiplication_count,
            basis_participant_field_addition_count,
            basis_participant_field_inversion_count: basis_work
                .coefficient_precomputation_field_inversion_count,
            nonbasis_participant_field_multiplication_count,
            nonbasis_participant_field_addition_count,
            nonbasis_participant_field_inversion_count: nonbasis_work
                .coefficient_precomputation_field_inversion_count,
            all_participant_field_multiplication_count: checked_add(
                checked_multiply(
                    basis_participant_count,
                    basis_participant_field_multiplication_count,
                )?,
                checked_multiply(
                    nonbasis_participant_count,
                    nonbasis_participant_field_multiplication_count,
                )?,
            )?,
            all_participant_field_addition_count: checked_add(
                checked_multiply(
                    basis_participant_count,
                    basis_participant_field_addition_count,
                )?,
                checked_multiply(
                    nonbasis_participant_count,
                    nonbasis_participant_field_addition_count,
                )?,
            )?,
            all_participant_field_inversion_count: checked_add(
                checked_multiply(
                    basis_participant_count,
                    basis_work.coefficient_precomputation_field_inversion_count,
                )?,
                checked_multiply(
                    nonbasis_participant_count,
                    nonbasis_work.coefficient_precomputation_field_inversion_count,
                )?,
            )?,
            all_participant_constant_time_comparison_count: checked_multiply(
                participant_count,
                checked_multiply(
                    verification_key_field_element_count,
                    basis_work.constant_time_comparison_count_per_checked_field,
                )?,
            )?,
            maximum_simultaneous_payload_chunk_count:
                MAXIMUM_LOCAL_CHECK_SIMULTANEOUS_PAYLOAD_CHUNK_COUNT,
            maximum_field_accumulator_count: MAXIMUM_LOCAL_CHECK_FIELD_ACCUMULATOR_COUNT,
            maximum_payload_chunk_byte_length,
            single_copied_buffer_absolute_bound,
            maximum_single_copied_buffer_headroom: single_copied_buffer_absolute_bound
                .checked_sub(maximum_payload_chunk_byte_length)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
            maximum_algorithm_live_payload_and_accumulator_byte_length,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum FieldWorkKind {
    Multiplication,
    Addition,
}

fn complete_field_work(
    work: AuthenticatedKeyFieldLocalCheckWork,
    field_count: u64,
    kind: FieldWorkKind,
) -> Result<u64, TallyPreparationError> {
    let (precomputation, per_field) = match kind {
        FieldWorkKind::Multiplication => (
            work.coefficient_precomputation_field_multiplication_count,
            work.field_multiplication_count_per_checked_field,
        ),
        FieldWorkKind::Addition => (
            work.coefficient_precomputation_field_addition_count,
            work.field_addition_count_per_checked_field,
        ),
    };
    checked_add(precomputation, checked_multiply(field_count, per_field)?)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
