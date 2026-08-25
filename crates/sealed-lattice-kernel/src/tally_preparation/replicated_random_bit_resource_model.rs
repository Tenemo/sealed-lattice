use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    hashing::framed_hash512_preimage,
    tally_circuit::CompiledTallyCircuit,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    replicated_key_ceremony::{
        ReplicatedRandomSharingKeyCoordinate, ReplicatedRandomSharingKeyPurpose,
    },
    replicated_random_bit_catalog::{
        REPLICATED_RANDOM_BIT_CATALOG_IDENTITY_DOMAIN, ReplicatedRandomBitCatalog,
    },
    replicated_random_bit_sharing::for_each_canonical_random_bit_subset,
    replicated_random_bit_stream::{
        replicated_random_bit_chunk_count, replicated_random_bit_chunk_preimage_byte_length,
    },
};

const SHAKE256_RATE_BYTE_LENGTH: u64 = 136;

#[derive(Debug, Clone, Copy, Default)]
struct ParticipantAccumulator {
    key_stream_count: u64,
    chunked_xof_invocation_count: u64,
    component_bit_count: u64,
    emitted_byte_length: u64,
    absorbed_query_byte_length: u64,
    fixed_keccak_f1600_permutation_count: u64,
}

/// Exact local generation census for the unactivated replicated random-bit
/// construction.
///
/// The model enumerates the production key coordinates and invokes the
/// production query encoder for every chunk. Identical subset-key output is
/// generated independently by each member that holds that key, so unique
/// component material and aggregate local generation are reported separately.
/// The unqualified permutation fields count keyed stream expansion; the
/// combined fields add one local derivation of the canonical catalog identity
/// per participant.
/// The model does not claim that prefix-keyed SHAKE256 realizes a
/// pseudorandom function and excludes key-ceremony traffic, retained keys,
/// runtime, allocator overlap, checkpoint framing, and transport bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedRandomBitResourceModel {
    pub(crate) participant_count: u64,
    pub(crate) unique_random_sharing_key_count: u64,
    pub(crate) key_stream_count_per_participant: u64,
    pub(crate) total_local_key_stream_count: u64,
    pub(crate) chunk_count_per_key_stream: u64,
    pub(crate) chunked_xof_invocation_count_per_participant: u64,
    pub(crate) total_chunked_xof_invocation_count: u64,
    pub(crate) semantic_mask_bit_count_per_key: u64,
    pub(crate) additive_correlation_free_point_bit_count_per_key: u64,
    pub(crate) component_bit_count_per_key: u64,
    pub(crate) unique_component_bit_count: u64,
    pub(crate) component_bit_count_per_participant: u64,
    pub(crate) total_locally_generated_component_bit_count: u64,
    pub(crate) emitted_byte_length_per_key: u64,
    pub(crate) unique_emitted_byte_length: u64,
    pub(crate) emitted_byte_length_per_participant: u64,
    pub(crate) total_locally_emitted_byte_length: u64,
    pub(crate) unused_high_bit_count_per_key: u8,
    pub(crate) catalog_canonical_byte_length: u64,
    pub(crate) catalog_identity_preimage_byte_length: u64,
    pub(crate) catalog_identity_fixed_keccak_f1600_permutation_count_per_participant: u64,
    pub(crate) total_catalog_identity_fixed_keccak_f1600_permutation_count: u64,
    pub(crate) minimum_absorbed_query_byte_length_per_participant: u64,
    pub(crate) maximum_absorbed_query_byte_length_per_participant: u64,
    pub(crate) total_absorbed_query_byte_length: u64,
    pub(crate) minimum_fixed_keccak_f1600_permutation_count_per_participant: u64,
    pub(crate) maximum_fixed_keccak_f1600_permutation_count_per_participant: u64,
    pub(crate) total_fixed_keccak_f1600_permutation_count: u64,
    pub(crate) minimum_combined_fixed_keccak_f1600_permutation_count_per_participant: u64,
    pub(crate) maximum_combined_fixed_keccak_f1600_permutation_count_per_participant: u64,
    pub(crate) total_combined_fixed_keccak_f1600_permutation_count: u64,
    pub(crate) maximum_single_query_byte_length: u64,
    pub(crate) maximum_single_output_byte_length: u64,
    pub(crate) maximum_fixed_keccak_f1600_permutation_count_per_chunk: u64,
    pub(crate) maximum_chunk_boundary_recomputation_byte_length: u64,
}

impl ReplicatedRandomBitResourceModel {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let context = TallyPreparationContext::new(
            Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
            [0_u8; 32],
            circuit,
        )?;
        let catalog = ReplicatedRandomBitCatalog::derive(context, circuit)?;
        let catalog_canonical_bytes = catalog.canonical_bytes();
        let catalog_identity_preimage = framed_hash512_preimage(
            REPLICATED_RANDOM_BIT_CATALOG_IDENTITY_DOMAIN,
            &[&catalog_canonical_bytes],
        );
        let catalog_canonical_byte_length = u64::try_from(catalog_canonical_bytes.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let catalog_identity_preimage_byte_length = u64::try_from(catalog_identity_preimage.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let catalog_identity_fixed_keccak_f1600_permutation_count_per_participant = checked_add(
            catalog_identity_preimage_byte_length / SHAKE256_RATE_BYTE_LENGTH,
            checked_ceiling_divide(
                u64::try_from(Hash512::BYTE_LENGTH)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
                SHAKE256_RATE_BYTE_LENGTH,
            )?,
        )?;
        let participant_count = u64::from(context.participant_count());
        let participant_count_usize = usize::from(context.participant_count());
        let chunk_count_per_key_stream = replicated_random_bit_chunk_count(&catalog)?;
        let configured_chunk_byte_length =
            u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mut participants = vec![ParticipantAccumulator::default(); participant_count_usize];
        let mut unique_random_sharing_key_count = 0_u64;
        let mut maximum_single_query_byte_length = 0_u64;
        let mut maximum_single_output_byte_length = 0_u64;
        let mut maximum_fixed_keccak_f1600_permutation_count_per_chunk = 0_u64;

        for_each_canonical_random_bit_subset(context.participant_count(), |subset| {
            let coordinate = ReplicatedRandomSharingKeyCoordinate::new(
                context,
                subset,
                ReplicatedRandomSharingKeyPurpose::RandomSharing,
            )?;
            unique_random_sharing_key_count = checked_add(unique_random_sharing_key_count, 1)?;
            let member_positions = coordinate.member_positions()?;
            for member_position in member_positions {
                let participant = participants
                    .get_mut(usize::from(member_position))
                    .ok_or(TallyPreparationError::GeometryMismatch)?;
                participant.key_stream_count = checked_add(participant.key_stream_count, 1)?;
                participant.component_bit_count =
                    checked_add(participant.component_bit_count, catalog.total_bit_count())?;
                participant.emitted_byte_length = checked_add(
                    participant.emitted_byte_length,
                    catalog.output_byte_length_per_key(),
                )?;

                for chunk_index in 0..chunk_count_per_key_stream {
                    let query_byte_length = replicated_random_bit_chunk_preimage_byte_length(
                        coordinate,
                        &catalog,
                        chunk_index,
                    )?;
                    let output_byte_length = chunk_output_byte_length(
                        catalog.output_byte_length_per_key(),
                        configured_chunk_byte_length,
                        chunk_count_per_key_stream,
                        chunk_index,
                    )?;
                    let complete_absorbed_rate_block_count =
                        query_byte_length / SHAKE256_RATE_BYTE_LENGTH;
                    let output_rate_block_count =
                        checked_ceiling_divide(output_byte_length, SHAKE256_RATE_BYTE_LENGTH)?;
                    let permutation_count =
                        checked_add(complete_absorbed_rate_block_count, output_rate_block_count)?;

                    participant.chunked_xof_invocation_count =
                        checked_add(participant.chunked_xof_invocation_count, 1)?;
                    participant.absorbed_query_byte_length =
                        checked_add(participant.absorbed_query_byte_length, query_byte_length)?;
                    participant.fixed_keccak_f1600_permutation_count = checked_add(
                        participant.fixed_keccak_f1600_permutation_count,
                        permutation_count,
                    )?;
                    maximum_single_query_byte_length =
                        maximum_single_query_byte_length.max(query_byte_length);
                    maximum_single_output_byte_length =
                        maximum_single_output_byte_length.max(output_byte_length);
                    maximum_fixed_keccak_f1600_permutation_count_per_chunk =
                        maximum_fixed_keccak_f1600_permutation_count_per_chunk
                            .max(permutation_count);
                }
            }
            Ok(())
        })?;

        let key_stream_count_per_participant =
            uniform_participant_value(&participants, |participant| participant.key_stream_count)?;
        let chunked_xof_invocation_count_per_participant =
            uniform_participant_value(&participants, |participant| {
                participant.chunked_xof_invocation_count
            })?;
        let component_bit_count_per_participant =
            uniform_participant_value(&participants, |participant| {
                participant.component_bit_count
            })?;
        let emitted_byte_length_per_participant =
            uniform_participant_value(&participants, |participant| {
                participant.emitted_byte_length
            })?;
        let total_local_key_stream_count =
            checked_multiply(key_stream_count_per_participant, participant_count)?;
        let minimum_stream_fixed_keccak_f1600_permutation_count_per_participant =
            minimum_participant_value(&participants, |participant| {
                participant.fixed_keccak_f1600_permutation_count
            })?;
        let maximum_stream_fixed_keccak_f1600_permutation_count_per_participant =
            maximum_participant_value(&participants, |participant| {
                participant.fixed_keccak_f1600_permutation_count
            })?;
        let total_stream_fixed_keccak_f1600_permutation_count =
            sum_participant_values(&participants, |participant| {
                participant.fixed_keccak_f1600_permutation_count
            })?;
        let total_catalog_identity_fixed_keccak_f1600_permutation_count = checked_multiply(
            catalog_identity_fixed_keccak_f1600_permutation_count_per_participant,
            participant_count,
        )?;

        Ok(Self {
            participant_count,
            unique_random_sharing_key_count,
            key_stream_count_per_participant,
            total_local_key_stream_count,
            chunk_count_per_key_stream,
            chunked_xof_invocation_count_per_participant,
            total_chunked_xof_invocation_count: checked_multiply(
                chunked_xof_invocation_count_per_participant,
                participant_count,
            )?,
            semantic_mask_bit_count_per_key: catalog.semantic_mask_bit_count(),
            additive_correlation_free_point_bit_count_per_key: catalog
                .additive_correlation_free_point_bit_count(),
            component_bit_count_per_key: catalog.total_bit_count(),
            unique_component_bit_count: checked_multiply(
                unique_random_sharing_key_count,
                catalog.total_bit_count(),
            )?,
            component_bit_count_per_participant,
            total_locally_generated_component_bit_count: checked_multiply(
                component_bit_count_per_participant,
                participant_count,
            )?,
            emitted_byte_length_per_key: catalog.output_byte_length_per_key(),
            unique_emitted_byte_length: checked_multiply(
                unique_random_sharing_key_count,
                catalog.output_byte_length_per_key(),
            )?,
            emitted_byte_length_per_participant,
            total_locally_emitted_byte_length: checked_multiply(
                emitted_byte_length_per_participant,
                participant_count,
            )?,
            unused_high_bit_count_per_key: catalog.unused_high_bit_count(),
            catalog_canonical_byte_length,
            catalog_identity_preimage_byte_length,
            catalog_identity_fixed_keccak_f1600_permutation_count_per_participant,
            total_catalog_identity_fixed_keccak_f1600_permutation_count,
            minimum_absorbed_query_byte_length_per_participant: minimum_participant_value(
                &participants,
                |participant| participant.absorbed_query_byte_length,
            )?,
            maximum_absorbed_query_byte_length_per_participant: maximum_participant_value(
                &participants,
                |participant| participant.absorbed_query_byte_length,
            )?,
            total_absorbed_query_byte_length: sum_participant_values(
                &participants,
                |participant| participant.absorbed_query_byte_length,
            )?,
            minimum_fixed_keccak_f1600_permutation_count_per_participant:
                minimum_stream_fixed_keccak_f1600_permutation_count_per_participant,
            maximum_fixed_keccak_f1600_permutation_count_per_participant:
                maximum_stream_fixed_keccak_f1600_permutation_count_per_participant,
            total_fixed_keccak_f1600_permutation_count:
                total_stream_fixed_keccak_f1600_permutation_count,
            minimum_combined_fixed_keccak_f1600_permutation_count_per_participant: checked_add(
                minimum_stream_fixed_keccak_f1600_permutation_count_per_participant,
                catalog_identity_fixed_keccak_f1600_permutation_count_per_participant,
            )?,
            maximum_combined_fixed_keccak_f1600_permutation_count_per_participant: checked_add(
                maximum_stream_fixed_keccak_f1600_permutation_count_per_participant,
                catalog_identity_fixed_keccak_f1600_permutation_count_per_participant,
            )?,
            total_combined_fixed_keccak_f1600_permutation_count: checked_add(
                total_stream_fixed_keccak_f1600_permutation_count,
                total_catalog_identity_fixed_keccak_f1600_permutation_count,
            )?,
            maximum_single_query_byte_length,
            maximum_single_output_byte_length,
            maximum_fixed_keccak_f1600_permutation_count_per_chunk,
            maximum_chunk_boundary_recomputation_byte_length: maximum_single_output_byte_length,
        })
    }
}

fn chunk_output_byte_length(
    total_output_byte_length: u64,
    configured_chunk_byte_length: u64,
    chunk_count: u64,
    chunk_index: u64,
) -> Result<u64, TallyPreparationError> {
    if chunk_index >= chunk_count || chunk_count == 0 || total_output_byte_length == 0 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let first_byte_index = checked_multiply(chunk_index, configured_chunk_byte_length)?;
    total_output_byte_length
        .checked_sub(first_byte_index)
        .map(|remaining| remaining.min(configured_chunk_byte_length))
        .filter(|byte_length| *byte_length > 0)
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn uniform_participant_value(
    participants: &[ParticipantAccumulator],
    select: impl Fn(ParticipantAccumulator) -> u64,
) -> Result<u64, TallyPreparationError> {
    let first = participants
        .first()
        .copied()
        .map(&select)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    if participants
        .iter()
        .copied()
        .any(|participant| select(participant) != first)
    {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    Ok(first)
}

fn minimum_participant_value(
    participants: &[ParticipantAccumulator],
    select: impl Fn(ParticipantAccumulator) -> u64,
) -> Result<u64, TallyPreparationError> {
    participants
        .iter()
        .copied()
        .map(select)
        .min()
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn maximum_participant_value(
    participants: &[ParticipantAccumulator],
    select: impl Fn(ParticipantAccumulator) -> u64,
) -> Result<u64, TallyPreparationError> {
    participants
        .iter()
        .copied()
        .map(select)
        .max()
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn sum_participant_values(
    participants: &[ParticipantAccumulator],
    select: impl Fn(ParticipantAccumulator) -> u64,
) -> Result<u64, TallyPreparationError> {
    participants
        .iter()
        .copied()
        .try_fold(0_u64, |sum, participant| {
            checked_add(sum, select(participant))
        })
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    (dividend / divisor)
        .checked_add(u64::from(!dividend.is_multiple_of(divisor)))
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
