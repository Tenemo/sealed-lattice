use crate::tally_circuit::CompiledTallyCircuit;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    preparation_arithmetic_graph::PreparationArithmeticGraph,
    replicated_random_sharing::ReplicatedRandomSharingGeometry,
};

const SCALAR_AUTHENTICATION_COEFFICIENT_COUNT: u64 = 1;
const TRIPLE_RANDOM_SHARING_COUNT: u64 = 3;
const TRIPLE_OPENING_COUNT: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FixedRosterBeaverMpcScheduleFloor {
    pub(crate) degree_three_random_sharing_instance_count: u64,
    pub(crate) degree_six_zero_sharing_component_count: u64,
    pub(crate) pseudorandom_field_output_count_per_participant: u64,
    pub(crate) pseudorandom_field_output_byte_length_per_participant: u64,
    pub(crate) retained_triple_field_element_count_per_participant: u64,
    pub(crate) retained_triple_byte_length_per_participant: u64,
    pub(crate) online_opening_count: u64,
    pub(crate) online_public_field_element_count: u64,
    pub(crate) online_public_byte_length: u64,
    pub(crate) online_upload_byte_length_per_participant: u64,
    pub(crate) combined_public_field_element_count: u64,
    pub(crate) combined_public_byte_length: u64,
    pub(crate) combined_upload_byte_length_per_participant: u64,
}

/// Exact accepted-path field-payload floor for the unactivated fixed-roster
/// pseudorandom-sharing and Beaver-multiplication candidate.
///
/// The conservative schedule gives every multiplication an independent
/// triple. The common-coefficient schedule additionally assumes a proved
/// multi-record authentication construction with one coefficient sharing per
/// holder and value limb, independent record offsets, and correlated triples
/// that reuse only the matching left operand. This module does not prove that
/// construction.
///
/// Both schedules exclude generation of non-triple preparation randomness,
/// commitments, the replicated-key ceremony's commitment and acknowledgement
/// bytes, signatures, framing, private and public output delivery, consensus,
/// retries, checkpoints, downloads, replay, and every fault path. The
/// pseudorandom-output counts also retain the symbolic fixed-function boundary;
/// they are work and byte counts, not a pseudorandom-function security claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FixedRosterBeaverMpcResourceFloor {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) field_element_byte_length: u64,
    pub(crate) multiplication_count: u64,
    pub(crate) authenticated_tag_multiplication_count: u64,
    pub(crate) ordinary_multiplication_count: u64,
    pub(crate) common_authentication_coefficient_group_count: u64,
    pub(crate) independent_authentication_key_field_element_count: u64,
    pub(crate) common_coefficient_authentication_key_field_element_count: u64,
    pub(crate) replicated_key_count: u64,
    pub(crate) replicated_key_count_per_participant: u64,
    pub(crate) replicated_key_byte_length: u64,
    pub(crate) replicated_key_persistent_byte_length_per_participant: u64,
    pub(crate) private_key_component_delivery_byte_length: u64,
    pub(crate) private_key_component_upload_byte_length_per_participant: u64,
    pub(crate) private_key_component_download_byte_length_per_participant: u64,
    pub(crate) key_ceremony_component_peak_byte_length_per_participant: u64,
    pub(crate) triple_reduction_opening_count: u64,
    pub(crate) triple_reduction_public_field_element_count: u64,
    pub(crate) triple_reduction_public_byte_length: u64,
    pub(crate) triple_reduction_upload_byte_length_per_participant: u64,
    pub(crate) independent_authentication: FixedRosterBeaverMpcScheduleFloor,
    pub(crate) common_coefficient_authentication: FixedRosterBeaverMpcScheduleFloor,
}

impl FixedRosterBeaverMpcResourceFloor {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let arithmetic_graph = PreparationArithmeticGraph::derive(circuit)?;
        let sharing_geometry =
            ReplicatedRandomSharingGeometry::derive(circuit.profile().participant_count())?;
        if arithmetic_graph.participant_count != sharing_geometry.participant_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let participant_count = arithmetic_graph.participant_count;
        let field_element_byte_length = u64::try_from(BinaryFieldElement256::CANONICAL_BYTE_LENGTH)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let multiplication_count = arithmetic_graph.total_multiplication_count;
        let authenticated_tag_multiplication_count =
            arithmetic_graph.authenticated_tag_multiplication_count;
        let ordinary_multiplication_count =
            checked_subtract(multiplication_count, authenticated_tag_multiplication_count)?;
        let common_authentication_coefficient_group_count = checked_multiply(
            participant_count,
            checked_add(
                SCALAR_AUTHENTICATION_COEFFICIENT_COUNT,
                arithmetic_graph.label_body_field_limb_count,
            )?,
        )?;
        let independent_authentication_key_field_element_count = checked_add(
            authenticated_tag_multiplication_count,
            arithmetic_graph.authenticated_record_count,
        )?;
        let common_coefficient_authentication_key_field_element_count = checked_add(
            common_authentication_coefficient_group_count,
            arithmetic_graph.authenticated_record_count,
        )?;

        let private_key_component_delivery_byte_length =
            sharing_geometry.remote_key_component_byte_length;
        let private_key_component_upload_byte_length_per_participant = checked_exact_divide(
            private_key_component_delivery_byte_length,
            participant_count,
        )?;
        let private_key_component_download_byte_length_per_participant =
            private_key_component_upload_byte_length_per_participant;
        let replicated_key_persistent_byte_length_per_participant = checked_multiply(
            sharing_geometry.key_count_per_participant,
            sharing_geometry.key_byte_length,
        )?;
        let key_ceremony_component_peak_byte_length_per_participant = checked_add(
            replicated_key_persistent_byte_length_per_participant,
            private_key_component_download_byte_length_per_participant,
        )?;

        let triple_reduction_opening_count = multiplication_count;
        let triple_reduction_public_field_element_count =
            checked_multiply(triple_reduction_opening_count, participant_count)?;
        let triple_reduction_public_byte_length = checked_multiply(
            triple_reduction_public_field_element_count,
            field_element_byte_length,
        )?;
        let triple_reduction_upload_byte_length_per_participant =
            checked_multiply(triple_reduction_opening_count, field_element_byte_length)?;

        let independent_degree_three_random_sharing_instance_count =
            checked_multiply(multiplication_count, TRIPLE_RANDOM_SHARING_COUNT)?;
        let independent_online_opening_count =
            checked_multiply(multiplication_count, TRIPLE_OPENING_COUNT)?;

        // An ordinary triple retains `(a, b, c)`. A common-left
        // authentication triple retains one `a` for each holder/limb group and
        // one `(b, c)` pair for each authenticated multiplication.
        let common_coefficient_degree_three_random_sharing_instance_count = checked_sum(&[
            checked_multiply(ordinary_multiplication_count, TRIPLE_RANDOM_SHARING_COUNT)?,
            checked_multiply(authenticated_tag_multiplication_count, 2)?,
            common_authentication_coefficient_group_count,
        ])?;
        // Ordinary products open both masked operands. Common-left products
        // open the masked coefficient once per group and the other masked
        // operand once per record limb.
        let common_coefficient_online_opening_count = checked_sum(&[
            checked_multiply(ordinary_multiplication_count, TRIPLE_OPENING_COUNT)?,
            authenticated_tag_multiplication_count,
            common_authentication_coefficient_group_count,
        ])?;

        let schedule_geometry = ScheduleGeometry {
            participant_count,
            active_fault_bound: sharing_geometry.active_fault_bound,
            authorized_subset_count_per_participant: sharing_geometry
                .authorized_subset_count_per_participant,
            field_element_byte_length,
            multiplication_count,
            triple_reduction_public_field_element_count,
            triple_reduction_public_byte_length,
            triple_reduction_upload_byte_length_per_participant,
        };

        Ok(Self {
            participant_count,
            active_fault_bound: sharing_geometry.active_fault_bound,
            field_element_byte_length,
            multiplication_count,
            authenticated_tag_multiplication_count,
            ordinary_multiplication_count,
            common_authentication_coefficient_group_count,
            independent_authentication_key_field_element_count,
            common_coefficient_authentication_key_field_element_count,
            replicated_key_count: sharing_geometry.total_key_count,
            replicated_key_count_per_participant: sharing_geometry.key_count_per_participant,
            replicated_key_byte_length: sharing_geometry.key_byte_length,
            replicated_key_persistent_byte_length_per_participant,
            private_key_component_delivery_byte_length,
            private_key_component_upload_byte_length_per_participant,
            private_key_component_download_byte_length_per_participant,
            key_ceremony_component_peak_byte_length_per_participant,
            triple_reduction_opening_count,
            triple_reduction_public_field_element_count,
            triple_reduction_public_byte_length,
            triple_reduction_upload_byte_length_per_participant,
            independent_authentication: derive_schedule_floor(
                independent_degree_three_random_sharing_instance_count,
                independent_online_opening_count,
                schedule_geometry,
            )?,
            common_coefficient_authentication: derive_schedule_floor(
                common_coefficient_degree_three_random_sharing_instance_count,
                common_coefficient_online_opening_count,
                schedule_geometry,
            )?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct ScheduleGeometry {
    participant_count: u64,
    active_fault_bound: u64,
    authorized_subset_count_per_participant: u64,
    field_element_byte_length: u64,
    multiplication_count: u64,
    triple_reduction_public_field_element_count: u64,
    triple_reduction_public_byte_length: u64,
    triple_reduction_upload_byte_length_per_participant: u64,
}

fn derive_schedule_floor(
    degree_three_random_sharing_instance_count: u64,
    online_opening_count: u64,
    geometry: ScheduleGeometry,
) -> Result<FixedRosterBeaverMpcScheduleFloor, TallyPreparationError> {
    let degree_six_zero_sharing_component_count =
        checked_multiply(geometry.multiplication_count, geometry.active_fault_bound)?;
    let pseudorandom_field_output_count_per_participant = checked_multiply(
        checked_add(
            degree_three_random_sharing_instance_count,
            degree_six_zero_sharing_component_count,
        )?,
        geometry.authorized_subset_count_per_participant,
    )?;
    let pseudorandom_field_output_byte_length_per_participant = checked_multiply(
        pseudorandom_field_output_count_per_participant,
        geometry.field_element_byte_length,
    )?;
    let retained_triple_field_element_count_per_participant =
        degree_three_random_sharing_instance_count;
    let retained_triple_byte_length_per_participant = checked_multiply(
        retained_triple_field_element_count_per_participant,
        geometry.field_element_byte_length,
    )?;
    let online_public_field_element_count =
        checked_multiply(online_opening_count, geometry.participant_count)?;
    let online_public_byte_length = checked_multiply(
        online_public_field_element_count,
        geometry.field_element_byte_length,
    )?;
    let online_upload_byte_length_per_participant =
        checked_multiply(online_opening_count, geometry.field_element_byte_length)?;
    let combined_public_field_element_count = checked_add(
        geometry.triple_reduction_public_field_element_count,
        online_public_field_element_count,
    )?;
    let combined_public_byte_length = checked_add(
        geometry.triple_reduction_public_byte_length,
        online_public_byte_length,
    )?;
    let combined_upload_byte_length_per_participant = checked_add(
        geometry.triple_reduction_upload_byte_length_per_participant,
        online_upload_byte_length_per_participant,
    )?;

    Ok(FixedRosterBeaverMpcScheduleFloor {
        degree_three_random_sharing_instance_count,
        degree_six_zero_sharing_component_count,
        pseudorandom_field_output_count_per_participant,
        pseudorandom_field_output_byte_length_per_participant,
        retained_triple_field_element_count_per_participant,
        retained_triple_byte_length_per_participant,
        online_opening_count,
        online_public_field_element_count,
        online_public_byte_length,
        online_upload_byte_length_per_participant,
        combined_public_field_element_count,
        combined_public_byte_length,
        combined_upload_byte_length_per_participant,
    })
}

fn checked_exact_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 || !dividend.is_multiple_of(divisor) {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    Ok(dividend / divisor)
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_subtract(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_sub(right)
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, TallyPreparationError> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, *value))
}
