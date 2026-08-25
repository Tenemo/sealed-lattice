use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::CompiledTallyCircuit,
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    fixed_roster_beaver_mpc_resource_floor::{
        FixedRosterBeaverMpcResourceFloor, FixedRosterBeaverMpcScheduleFloor,
    },
    replicated_key_ceremony::{
        ReplicatedRandomSharingKeyCoordinate, ReplicatedRandomSharingKeyPurpose,
    },
    replicated_sharing_field_stream::{
        ReplicatedSharingFieldStreamPurpose, replicated_sharing_field_chunk_count,
        replicated_sharing_field_chunk_preimage_byte_length,
    },
};

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedSharingFieldStreamScheduleModel {
    pub(crate) field_stream_count_per_participant: u64,
    pub(crate) naive_per_field_xof_invocation_count_per_participant: u64,
    pub(crate) chunked_xof_invocation_count_per_participant: u64,
    pub(crate) total_chunked_xof_invocation_count: u64,
    pub(crate) field_output_count_per_participant: u64,
    pub(crate) field_output_byte_length_per_participant: u64,
    pub(crate) total_field_output_byte_length: u64,
    pub(crate) minimum_absorbed_query_byte_length_per_participant: u64,
    pub(crate) maximum_absorbed_query_byte_length_per_participant: u64,
    pub(crate) total_absorbed_query_byte_length: u64,
    pub(crate) maximum_single_query_byte_length: u64,
    pub(crate) maximum_single_output_byte_length: u64,
    pub(crate) maximum_chunk_boundary_recomputation_byte_length: u64,
}

/// Exact keyed-XOF invocation and byte census for the unactivated replicated
/// sharing candidate.
///
/// The model invokes the production query encoder for every key-scoped stream
/// and checks both boundary chunks. It treats each completed chunk as a
/// deterministic checkpoint boundary. It does not claim that prefix-keyed
/// SHAKE256 realizes a pseudorandom function, does not turn the conditional
/// common-coefficient authentication schedule into a theorem, and excludes
/// runtime, allocator overlap, checkpoint framing, retained triples, and all
/// transport bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedSharingFieldStreamResourceModel {
    pub(crate) participant_count: u64,
    pub(crate) field_element_byte_length: u64,
    pub(crate) field_element_count_per_full_chunk: u64,
    pub(crate) configured_chunk_byte_length: u64,
    pub(crate) independent_authentication: ReplicatedSharingFieldStreamScheduleModel,
    pub(crate) common_coefficient_authentication: ReplicatedSharingFieldStreamScheduleModel,
}

impl ReplicatedSharingFieldStreamResourceModel {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let beaver_floor = FixedRosterBeaverMpcResourceFloor::derive(circuit)?;
        let context = TallyPreparationContext::new(
            Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
            [0_u8; 32],
            circuit,
        )?;
        let coordinates = ReplicatedRandomSharingKeyCoordinate::all(context)?;
        let configured_chunk_byte_length =
            u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if !configured_chunk_byte_length.is_multiple_of(FIELD_ELEMENT_BYTE_LENGTH) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let field_element_count_per_full_chunk = configured_chunk_byte_length
            .checked_div(FIELD_ELEMENT_BYTE_LENGTH)
            .filter(|count| *count > 0)
            .ok_or(TallyPreparationError::GeometryMismatch)?;

        let independent_streams = [
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::IndependentTripleLeft,
                beaver_floor.multiplication_count,
            ),
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::IndependentTripleRight,
                beaver_floor.multiplication_count,
            ),
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::IndependentTripleReductionMask,
                beaver_floor.multiplication_count,
            ),
            StreamSpecification::zero(
                ReplicatedSharingFieldStreamPurpose::IndependentTripleDegreeDoubleZeroMask,
                beaver_floor.multiplication_count,
            ),
        ];
        let common_coefficient_streams = [
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::OrdinaryTripleLeft,
                beaver_floor.ordinary_multiplication_count,
            ),
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::OrdinaryTripleRight,
                beaver_floor.ordinary_multiplication_count,
            ),
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::OrdinaryTripleReductionMask,
                beaver_floor.ordinary_multiplication_count,
            ),
            StreamSpecification::zero(
                ReplicatedSharingFieldStreamPurpose::OrdinaryTripleDegreeDoubleZeroMask,
                beaver_floor.ordinary_multiplication_count,
            ),
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::AuthenticationCommonCoefficient,
                beaver_floor.common_authentication_coefficient_group_count,
            ),
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::AuthenticationTripleRight,
                beaver_floor.authenticated_tag_multiplication_count,
            ),
            StreamSpecification::random(
                ReplicatedSharingFieldStreamPurpose::AuthenticationTripleReductionMask,
                beaver_floor.authenticated_tag_multiplication_count,
            ),
            StreamSpecification::zero(
                ReplicatedSharingFieldStreamPurpose::AuthenticationTripleDegreeDoubleZeroMask,
                beaver_floor.authenticated_tag_multiplication_count,
            ),
        ];

        Ok(Self {
            participant_count: beaver_floor.participant_count,
            field_element_byte_length: FIELD_ELEMENT_BYTE_LENGTH,
            field_element_count_per_full_chunk,
            configured_chunk_byte_length,
            independent_authentication: derive_schedule_model(
                context,
                &coordinates,
                &independent_streams,
                beaver_floor.independent_authentication,
            )?,
            common_coefficient_authentication: derive_schedule_model(
                context,
                &coordinates,
                &common_coefficient_streams,
                beaver_floor.common_coefficient_authentication,
            )?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct StreamSpecification {
    uses_zero_sharing_key: bool,
    purpose: ReplicatedSharingFieldStreamPurpose,
    field_count: u64,
}

impl StreamSpecification {
    const fn random(purpose: ReplicatedSharingFieldStreamPurpose, field_count: u64) -> Self {
        Self {
            uses_zero_sharing_key: false,
            purpose,
            field_count,
        }
    }

    const fn zero(purpose: ReplicatedSharingFieldStreamPurpose, field_count: u64) -> Self {
        Self {
            uses_zero_sharing_key: true,
            purpose,
            field_count,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ParticipantAccumulator {
    field_stream_count: u64,
    xof_invocation_count: u64,
    field_output_count: u64,
    absorbed_query_byte_length: u64,
}

fn derive_schedule_model(
    context: TallyPreparationContext,
    coordinates: &[ReplicatedRandomSharingKeyCoordinate],
    specifications: &[StreamSpecification],
    expected_floor: FixedRosterBeaverMpcScheduleFloor,
) -> Result<ReplicatedSharingFieldStreamScheduleModel, TallyPreparationError> {
    let participant_count = u64::from(context.participant_count());
    let participant_count_usize = usize::from(context.participant_count());
    let mut participants = vec![ParticipantAccumulator::default(); participant_count_usize];
    let mut maximum_single_query_byte_length = 0_u64;
    let mut maximum_single_output_byte_length = 0_u64;

    for coordinate in coordinates.iter().copied() {
        let coordinate_uses_zero_sharing_key = matches!(
            coordinate.purpose(),
            ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing { .. }
        );
        let member_positions = coordinate.member_positions()?;
        for specification in specifications.iter().copied().filter(|specification| {
            specification.uses_zero_sharing_key == coordinate_uses_zero_sharing_key
        }) {
            let chunk_count = replicated_sharing_field_chunk_count(specification.field_count)?;
            let first_query_byte_length = replicated_sharing_field_chunk_preimage_byte_length(
                coordinate,
                specification.purpose,
                specification.field_count,
                0,
            )?;
            let final_query_byte_length = replicated_sharing_field_chunk_preimage_byte_length(
                coordinate,
                specification.purpose,
                specification.field_count,
                chunk_count
                    .checked_sub(1)
                    .ok_or(TallyPreparationError::GeometryMismatch)?,
            )?;
            if first_query_byte_length != final_query_byte_length {
                return Err(TallyPreparationError::GeometryMismatch);
            }
            let absorbed_query_byte_length =
                checked_multiply(first_query_byte_length, chunk_count)?;
            let output_byte_length =
                checked_multiply(specification.field_count, FIELD_ELEMENT_BYTE_LENGTH)?;
            let maximum_stream_chunk_output_byte_length = output_byte_length.min(
                u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            );
            maximum_single_query_byte_length =
                maximum_single_query_byte_length.max(first_query_byte_length);
            maximum_single_output_byte_length =
                maximum_single_output_byte_length.max(maximum_stream_chunk_output_byte_length);

            for member_position in &member_positions {
                let participant = participants
                    .get_mut(usize::from(*member_position))
                    .ok_or(TallyPreparationError::GeometryMismatch)?;
                participant.field_stream_count = checked_add(participant.field_stream_count, 1)?;
                participant.xof_invocation_count =
                    checked_add(participant.xof_invocation_count, chunk_count)?;
                participant.field_output_count =
                    checked_add(participant.field_output_count, specification.field_count)?;
                participant.absorbed_query_byte_length = checked_add(
                    participant.absorbed_query_byte_length,
                    absorbed_query_byte_length,
                )?;
            }
        }
    }

    let field_stream_count_per_participant =
        uniform_participant_value(&participants, |participant| participant.field_stream_count)?;
    let chunked_xof_invocation_count_per_participant =
        uniform_participant_value(&participants, |participant| {
            participant.xof_invocation_count
        })?;
    let field_output_count_per_participant =
        uniform_participant_value(&participants, |participant| participant.field_output_count)?;
    if field_output_count_per_participant
        != expected_floor.pseudorandom_field_output_count_per_participant
    {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let field_output_byte_length_per_participant = checked_multiply(
        field_output_count_per_participant,
        FIELD_ELEMENT_BYTE_LENGTH,
    )?;
    if field_output_byte_length_per_participant
        != expected_floor.pseudorandom_field_output_byte_length_per_participant
    {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let minimum_absorbed_query_byte_length_per_participant = participants
        .iter()
        .map(|participant| participant.absorbed_query_byte_length)
        .min()
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    let maximum_absorbed_query_byte_length_per_participant = participants
        .iter()
        .map(|participant| participant.absorbed_query_byte_length)
        .max()
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    let total_absorbed_query_byte_length =
        participants.iter().try_fold(0_u64, |total, participant| {
            checked_add(total, participant.absorbed_query_byte_length)
        })?;

    Ok(ReplicatedSharingFieldStreamScheduleModel {
        field_stream_count_per_participant,
        naive_per_field_xof_invocation_count_per_participant: field_output_count_per_participant,
        chunked_xof_invocation_count_per_participant,
        total_chunked_xof_invocation_count: checked_multiply(
            chunked_xof_invocation_count_per_participant,
            participant_count,
        )?,
        field_output_count_per_participant,
        field_output_byte_length_per_participant,
        total_field_output_byte_length: checked_multiply(
            field_output_byte_length_per_participant,
            participant_count,
        )?,
        minimum_absorbed_query_byte_length_per_participant,
        maximum_absorbed_query_byte_length_per_participant,
        total_absorbed_query_byte_length,
        maximum_single_query_byte_length,
        maximum_single_output_byte_length,
        maximum_chunk_boundary_recomputation_byte_length: maximum_single_output_byte_length,
    })
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

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
