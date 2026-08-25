use crate::{foundation::derive_foundation_roster_parameters, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    garbling_alternative_resource_model::IndependentLabelGarblingResourceLowerBound,
    preparation_arithmetic_graph::PreparationArithmeticGraph,
};

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;
const LABEL_BODY_FIELD_LIMB_COUNT: u64 = 3;
const TRIPLE_SHARING_COUNT: u64 = 3;
const CONSISTENCY_CHECK_COUNT: u64 = 2;
const FAULT_DETECTION_PHASE_COUNT: u64 = 3;

/// Known accepted-path traffic for one arithmetic circuit under the evaluated
/// fixed-roster adaptation of a linear-communication perfect-MPC protocol.
///
/// The byte count includes only explicitly enumerated remote field elements.
/// The participant value is a pigeonhole lower bound: some participant must
/// upload at least that many bytes, but the source protocol does not fix role
/// rotation and therefore does not determine the exact per-participant split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FixedRosterLinearMpcCircuitFloor {
    pub(crate) multiplication_count: u64,
    pub(crate) segment_count: u64,
    pub(crate) padded_multiplication_count: u64,
    pub(crate) known_remote_field_element_count: u64,
    pub(crate) known_remote_byte_length: u64,
    pub(crate) minimum_maximum_participant_upload_byte_length: u64,
    pub(crate) known_fault_detection_bit_length: u64,
}

/// Exact known-message floor for the optimistic accepted path of the evaluated
/// linear-communication perfect-MPC construction after replacing participant
/// elimination with capsule burn.
///
/// The source construction processes `n - 2t` multiplication gates per
/// segment. It normally removes a disputed pair and continues. A fixed-roster
/// ceremony cannot do that, so this model keeps only the no-dispute path and
/// treats every detected fault as terminal. That adaptation still needs a new
/// proof and cannot inherit the source theorem.
///
/// The model expands the source procedures for random triple-sharing,
/// multiplication-tuple generation, evaluator exchange, consistency checks,
/// and batched reconstruction. It excludes consensus traffic, input and random
/// gates, output delivery, signatures, mailbox envelopes, roots, framing,
/// checkpoints, restarts, and every fault path. It is therefore a strict lower
/// bound and cannot authorize admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FixedRosterLinearMpcCommunicationFloor {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) multiplication_batch_size: u64,
    pub(crate) field_element_byte_length: u64,
    pub(crate) triple_sharing_distribution_field_element_count_per_invocation: u64,
    pub(crate) triple_sharing_check_field_element_count_per_invocation: u64,
    pub(crate) triple_sharing_field_element_count_per_invocation: u64,
    pub(crate) batched_reconstruction_field_element_count_per_invocation: u64,
    pub(crate) multiplication_tuple_generation_field_element_count_per_segment: u64,
    pub(crate) evaluation_exchange_field_element_count_per_segment: u64,
    pub(crate) consistency_check_field_element_count_per_segment: u64,
    pub(crate) reconstruction_check_field_element_count_per_segment: u64,
    pub(crate) known_remote_field_element_count_per_segment: u64,
    pub(crate) known_fault_detection_bit_length_per_segment: u64,
    pub(crate) shared_offset: FixedRosterLinearMpcCircuitFloor,
    pub(crate) independent_label: FixedRosterLinearMpcCircuitFloor,
}

impl FixedRosterLinearMpcCommunicationFloor {
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
        if participant_count <= checked_multiply(active_fault_bound, 3)? {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let multiplication_batch_size = participant_count
            .checked_sub(checked_multiply(active_fault_bound, 2)?)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if multiplication_batch_size == 0 {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let remote_recipient_count = participant_count
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let dealer_recipient_pair_count =
            checked_multiply(participant_count, remote_recipient_count)?;
        let triple_sharing_distribution_field_element_count_per_invocation =
            checked_multiply(dealer_recipient_pair_count, TRIPLE_SHARING_COUNT)?;
        let triple_sharing_check_field_element_count_per_invocation = checked_multiply(
            checked_multiply(
                checked_multiply(active_fault_bound, 2)?,
                remote_recipient_count,
            )?,
            TRIPLE_SHARING_COUNT,
        )?;
        let triple_sharing_field_element_count_per_invocation = checked_add(
            triple_sharing_distribution_field_element_count_per_invocation,
            triple_sharing_check_field_element_count_per_invocation,
        )?;
        let batched_reconstruction_field_element_count_per_invocation =
            checked_multiply(dealer_recipient_pair_count, 2)?;
        let multiplication_tuple_generation_field_element_count_per_segment = checked_add(
            checked_multiply(
                triple_sharing_field_element_count_per_invocation,
                TRIPLE_SHARING_COUNT,
            )?,
            batched_reconstruction_field_element_count_per_invocation,
        )?;
        let evaluation_exchange_field_element_count_per_segment = checked_multiply(
            checked_multiply(multiplication_batch_size, remote_recipient_count)?,
            4,
        )?;
        let consistency_check_field_element_count_per_segment = checked_multiply(
            checked_multiply(
                checked_add(multiplication_batch_size, active_fault_bound)?,
                remote_recipient_count,
            )?,
            CONSISTENCY_CHECK_COUNT,
        )?;
        let reconstruction_check_field_element_count_per_segment = checked_multiply(
            batched_reconstruction_field_element_count_per_invocation,
            CONSISTENCY_CHECK_COUNT,
        )?;
        let known_remote_field_element_count_per_segment = checked_sum(&[
            multiplication_tuple_generation_field_element_count_per_segment,
            evaluation_exchange_field_element_count_per_segment,
            consistency_check_field_element_count_per_segment,
            reconstruction_check_field_element_count_per_segment,
        ])?;
        let known_fault_detection_bit_length_per_segment =
            checked_multiply(dealer_recipient_pair_count, FAULT_DETECTION_PHASE_COUNT)?;

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
        let independent_label_multiplication_count = checked_sum(&[
            independent_label_fresh_semantic_mask_count,
            independent_resources.conjunction_gate_count,
            independent_label_row_offset_limb_multiplication_count,
            independent_resources.total_share_value_field_element_count,
        ])?;

        Ok(Self {
            participant_count,
            active_fault_bound,
            multiplication_batch_size,
            field_element_byte_length: FIELD_ELEMENT_BYTE_LENGTH,
            triple_sharing_distribution_field_element_count_per_invocation,
            triple_sharing_check_field_element_count_per_invocation,
            triple_sharing_field_element_count_per_invocation,
            batched_reconstruction_field_element_count_per_invocation,
            multiplication_tuple_generation_field_element_count_per_segment,
            evaluation_exchange_field_element_count_per_segment,
            consistency_check_field_element_count_per_segment,
            reconstruction_check_field_element_count_per_segment,
            known_remote_field_element_count_per_segment,
            known_fault_detection_bit_length_per_segment,
            shared_offset: derive_circuit_floor(
                arithmetic_graph.total_multiplication_count,
                multiplication_batch_size,
                known_remote_field_element_count_per_segment,
                known_fault_detection_bit_length_per_segment,
                participant_count,
            )?,
            independent_label: derive_circuit_floor(
                independent_label_multiplication_count,
                multiplication_batch_size,
                known_remote_field_element_count_per_segment,
                known_fault_detection_bit_length_per_segment,
                participant_count,
            )?,
        })
    }
}

fn derive_circuit_floor(
    multiplication_count: u64,
    multiplication_batch_size: u64,
    remote_field_element_count_per_segment: u64,
    fault_detection_bit_length_per_segment: u64,
    participant_count: u64,
) -> Result<FixedRosterLinearMpcCircuitFloor, TallyPreparationError> {
    let segment_count = checked_ceiling_divide(multiplication_count, multiplication_batch_size)?;
    let padded_multiplication_count = checked_multiply(segment_count, multiplication_batch_size)?;
    let known_remote_field_element_count =
        checked_multiply(segment_count, remote_field_element_count_per_segment)?;
    let known_remote_byte_length =
        checked_multiply(known_remote_field_element_count, FIELD_ELEMENT_BYTE_LENGTH)?;
    let minimum_maximum_participant_upload_byte_length =
        checked_ceiling_divide(known_remote_byte_length, participant_count)?;
    let known_fault_detection_bit_length =
        checked_multiply(segment_count, fault_detection_bit_length_per_segment)?;

    Ok(FixedRosterLinearMpcCircuitFloor {
        multiplication_count,
        segment_count,
        padded_multiplication_count,
        known_remote_field_element_count,
        known_remote_byte_length,
        minimum_maximum_participant_upload_byte_length,
        known_fault_detection_bit_length,
    })
}

fn checked_ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    checked_add(quotient, u64::from(remainder != 0))
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
