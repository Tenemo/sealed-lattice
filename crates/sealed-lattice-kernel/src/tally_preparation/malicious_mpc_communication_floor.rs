use crate::{foundation::derive_foundation_roster_parameters, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    garbling_alternative_resource_model::IndependentLabelGarblingResourceLowerBound,
    preparation_arithmetic_graph::PreparationArithmeticGraph,
};

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;
const LABEL_BODY_FIELD_LIMB_COUNT: u64 = 3;

/// Exact remote share-material floors implied by the selected perfect-MPC
/// theorem routes before any concrete VSS realization is compiled.
///
/// The source construction invokes one dealer subprotocol per participant. For
/// each logical output and remote recipient, its optimistic hybrid output has
/// a degree-`t` bivariate result share and a degree-`(2t,t)` verification share.
/// The compact floor omits the duplicate slice intersections and the
/// verification slice constant already determined by the recipient's inputs.
/// This is a lossless encoding floor, not an implementation byte count.
/// Gate-by-gate and maximal-layer routes do not dominate one another for every
/// admitted shape: the former exports each multiplication result, while the
/// latter exports every value that crosses a layer or leaves the final layer.
///
/// The values exclude every VSS/WSS message, complaint branch, broadcast,
/// signature, envelope, root, certificate, random-input protocol, final output
/// delivery, checkpoint, and runtime overlap. They cannot authorize admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PerfectMpcCommunicationFloor {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) field_element_byte_length: u64,
    pub(crate) result_share_separate_slice_field_element_count: u64,
    pub(crate) verification_share_separate_slice_field_element_count: u64,
    pub(crate) separate_slice_field_element_count_per_output_and_recipient: u64,
    pub(crate) overlap_deduplicated_field_element_count_per_output_and_recipient: u64,
    pub(crate) compact_field_element_count_per_output_and_recipient: u64,
    pub(crate) direct_logical_output_count: u64,
    pub(crate) first_layer_logical_output_count: u64,
    pub(crate) second_layer_logical_output_count: u64,
    pub(crate) maximal_layer_logical_output_count: u64,
    pub(crate) direct_separate_slice_remote_byte_length: u64,
    pub(crate) direct_compact_remote_byte_length: u64,
    pub(crate) maximal_layer_separate_slice_remote_byte_length: u64,
    pub(crate) maximal_layer_compact_remote_byte_length: u64,
    pub(crate) maximal_layer_compact_remote_byte_length_per_participant: u64,
    pub(crate) independent_label_direct_logical_output_count: u64,
    pub(crate) independent_label_first_layer_logical_output_count: u64,
    pub(crate) independent_label_second_layer_logical_output_count: u64,
    pub(crate) independent_label_maximal_layer_logical_output_count: u64,
    pub(crate) independent_label_direct_compact_remote_byte_length: u64,
    pub(crate) independent_label_maximal_layer_compact_remote_byte_length: u64,
    pub(crate) independent_label_maximal_layer_compact_remote_byte_length_per_participant: u64,
}

impl PerfectMpcCommunicationFloor {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let arithmetic_graph = PreparationArithmeticGraph::derive(circuit)?;
        let independent_resources = IndependentLabelGarblingResourceLowerBound::derive(circuit)?;
        let participant_count = arithmetic_graph.participant_count;
        let roster_parameters = derive_foundation_roster_parameters(
            circuit.profile().participant_count(),
        )
        .ok_or(TallyPreparationError::ParticipantCountOutOfRange {
            participant_count: circuit.profile().participant_count(),
        })?;
        let active_fault_bound = u64::from(roster_parameters.active_fault_bound);
        if participant_count <= active_fault_bound
            || participant_count <= active_fault_bound.saturating_mul(3)
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let result_share_separate_slice_field_element_count =
            checked_multiply(checked_add(active_fault_bound, 1)?, 2)?;
        let verification_share_separate_slice_field_element_count = checked_add(
            checked_add(checked_multiply(active_fault_bound, 2)?, 1)?,
            checked_add(active_fault_bound, 1)?,
        )?;
        let separate_slice_field_element_count_per_output_and_recipient = checked_add(
            result_share_separate_slice_field_element_count,
            verification_share_separate_slice_field_element_count,
        )?;
        let overlap_deduplicated_field_element_count_per_output_and_recipient =
            separate_slice_field_element_count_per_output_and_recipient
                .checked_sub(2)
                .ok_or(TallyPreparationError::GeometryMismatch)?;
        let compact_field_element_count_per_output_and_recipient =
            overlap_deduplicated_field_element_count_per_output_and_recipient
                .checked_sub(1)
                .ok_or(TallyPreparationError::GeometryMismatch)?;

        let direct_logical_output_count = arithmetic_graph.total_multiplication_count;
        let first_layer_logical_output_count = checked_add(
            arithmetic_graph.first_layer_public_zero_check_count,
            arithmetic_graph.mask_product_multiplication_count,
        )?;
        let second_layer_logical_output_count = checked_sum(&[
            arithmetic_graph.second_layer_row_offset_output_field_element_count,
            arithmetic_graph.authenticated_tag_output_field_element_count,
            arithmetic_graph.additive_correlation_correction_component_count,
        ])?;
        let maximal_layer_logical_output_count = checked_add(
            first_layer_logical_output_count,
            second_layer_logical_output_count,
        )?;

        let direct_separate_slice_remote_byte_length = remote_share_material_byte_length(
            direct_logical_output_count,
            separate_slice_field_element_count_per_output_and_recipient,
            participant_count,
        )?;
        let direct_compact_remote_byte_length = remote_share_material_byte_length(
            direct_logical_output_count,
            compact_field_element_count_per_output_and_recipient,
            participant_count,
        )?;
        let maximal_layer_separate_slice_remote_byte_length = remote_share_material_byte_length(
            maximal_layer_logical_output_count,
            separate_slice_field_element_count_per_output_and_recipient,
            participant_count,
        )?;
        let maximal_layer_compact_remote_byte_length = remote_share_material_byte_length(
            maximal_layer_logical_output_count,
            compact_field_element_count_per_output_and_recipient,
            participant_count,
        )?;
        let maximal_layer_compact_remote_byte_length_per_participant =
            remote_share_material_byte_length_per_participant(
                maximal_layer_logical_output_count,
                compact_field_element_count_per_output_and_recipient,
                participant_count,
            )?;

        let independent_label_fresh_semantic_mask_count = u64::try_from(
            circuit
                .geometry()
                .total_wire_count
                .checked_sub(circuit.geometry().constant_operation_count)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
        )
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let independent_label_row_offset_limb_multiplication_count = checked_multiply(
            checked_multiply(independent_resources.paid_gate_row_count, participant_count)?,
            LABEL_BODY_FIELD_LIMB_COUNT,
        )?;
        let independent_label_first_layer_logical_output_count = checked_add(
            independent_label_fresh_semantic_mask_count,
            independent_resources.conjunction_gate_count,
        )?;
        let independent_label_second_layer_logical_output_count = checked_sum(&[
            independent_label_row_offset_limb_multiplication_count,
            independent_resources.total_share_record_count,
            checked_multiply(independent_resources.paid_gate_row_count, participant_count)?,
        ])?;
        let independent_label_direct_logical_output_count = checked_sum(&[
            independent_label_fresh_semantic_mask_count,
            independent_resources.conjunction_gate_count,
            independent_label_row_offset_limb_multiplication_count,
            independent_resources.total_share_value_field_element_count,
        ])?;
        let independent_label_maximal_layer_logical_output_count = checked_add(
            independent_label_first_layer_logical_output_count,
            independent_label_second_layer_logical_output_count,
        )?;
        let independent_label_direct_compact_remote_byte_length =
            remote_share_material_byte_length(
                independent_label_direct_logical_output_count,
                compact_field_element_count_per_output_and_recipient,
                participant_count,
            )?;
        let independent_label_maximal_layer_compact_remote_byte_length =
            remote_share_material_byte_length(
                independent_label_maximal_layer_logical_output_count,
                compact_field_element_count_per_output_and_recipient,
                participant_count,
            )?;
        let independent_label_maximal_layer_compact_remote_byte_length_per_participant =
            remote_share_material_byte_length_per_participant(
                independent_label_maximal_layer_logical_output_count,
                compact_field_element_count_per_output_and_recipient,
                participant_count,
            )?;

        Ok(Self {
            participant_count,
            active_fault_bound,
            field_element_byte_length: FIELD_ELEMENT_BYTE_LENGTH,
            result_share_separate_slice_field_element_count,
            verification_share_separate_slice_field_element_count,
            separate_slice_field_element_count_per_output_and_recipient,
            overlap_deduplicated_field_element_count_per_output_and_recipient,
            compact_field_element_count_per_output_and_recipient,
            direct_logical_output_count,
            first_layer_logical_output_count,
            second_layer_logical_output_count,
            maximal_layer_logical_output_count,
            direct_separate_slice_remote_byte_length,
            direct_compact_remote_byte_length,
            maximal_layer_separate_slice_remote_byte_length,
            maximal_layer_compact_remote_byte_length,
            maximal_layer_compact_remote_byte_length_per_participant,
            independent_label_direct_logical_output_count,
            independent_label_first_layer_logical_output_count,
            independent_label_second_layer_logical_output_count,
            independent_label_maximal_layer_logical_output_count,
            independent_label_direct_compact_remote_byte_length,
            independent_label_maximal_layer_compact_remote_byte_length,
            independent_label_maximal_layer_compact_remote_byte_length_per_participant,
        })
    }
}

fn remote_share_material_byte_length(
    logical_output_count: u64,
    field_element_count_per_output_and_recipient: u64,
    participant_count: u64,
) -> Result<u64, TallyPreparationError> {
    checked_multiply(
        remote_share_material_field_element_count(
            logical_output_count,
            field_element_count_per_output_and_recipient,
            participant_count,
        )?,
        FIELD_ELEMENT_BYTE_LENGTH,
    )
}

fn remote_share_material_byte_length_per_participant(
    logical_output_count: u64,
    field_element_count_per_output_and_recipient: u64,
    participant_count: u64,
) -> Result<u64, TallyPreparationError> {
    let remote_dealer_count = participant_count
        .checked_sub(1)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    checked_multiply(
        checked_multiply(
            checked_multiply(
                logical_output_count,
                field_element_count_per_output_and_recipient,
            )?,
            remote_dealer_count,
        )?,
        FIELD_ELEMENT_BYTE_LENGTH,
    )
}

fn remote_share_material_field_element_count(
    logical_output_count: u64,
    field_element_count_per_output_and_recipient: u64,
    participant_count: u64,
) -> Result<u64, TallyPreparationError> {
    let remote_recipient_count_per_dealer = participant_count
        .checked_sub(1)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    checked_multiply(
        checked_multiply(
            checked_multiply(
                logical_output_count,
                field_element_count_per_output_and_recipient,
            )?,
            participant_count,
        )?,
        remote_recipient_count_per_dealer,
    )
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
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
