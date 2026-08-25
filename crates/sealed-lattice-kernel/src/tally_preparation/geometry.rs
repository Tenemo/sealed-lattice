use crate::tally_circuit::{BooleanOperation, CompiledTallyCircuit};

use super::{BinaryFieldElement256, SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH, TallyPreparationError};

pub(crate) const LABEL_KEY_BYTE_LENGTH: u64 = 32;
pub(crate) const SECRET_LEAF_SALT_BYTE_LENGTH: u64 = 48;
pub(crate) const MAXIMUM_PRIVATE_MASK_BUNDLE_PAYLOAD_BYTE_LENGTH: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TallyPreparationGeometry {
    pub(crate) participant_count: u64,
    pub(crate) wire_count: u64,
    pub(crate) packed_wire_mask_byte_length: u64,
    pub(crate) label_key_count: u64,
    pub(crate) label_key_byte_length: u64,
    pub(crate) score_input_wire_count: u64,
    pub(crate) result_output_wire_count: u64,
    pub(crate) shared_mask_count: u64,
    pub(crate) sharing_random_coefficient_count: u64,
    pub(crate) sharing_random_coefficient_byte_length: u64,
    pub(crate) label_opening_leaf_count: u64,
    pub(crate) present_owner_mask_bundle_leaf_count: u64,
    pub(crate) absence_share_bundle_leaf_count: u64,
    pub(crate) result_share_bundle_leaf_count: u64,
    pub(crate) private_wire_mask_bundle_leaf_count: u64,
    pub(crate) secret_leaf_salt_count: u64,
    pub(crate) secret_leaf_salt_byte_length: u64,
    pub(crate) direct_joint_random_tape_byte_length: u64,
    pub(crate) all_party_explicit_tape_input_byte_length: u64,
    pub(crate) seeded_expansion_kmac_call_count: u64,
    pub(crate) binary_gate_row_count: u64,
    pub(crate) unary_gate_row_count: u64,
    pub(crate) garbled_gate_row_count: u64,
    pub(crate) constant_activation_count: u64,
    pub(crate) correlation_key_contribution_count: u64,
    pub(crate) correlation_selector_contribution_count: u64,
    pub(crate) correlation_contribution_byte_length: u64,
    pub(crate) garbling_kmac_call_count: u64,
    pub(crate) public_garbled_table_byte_length: u64,
}

impl TallyPreparationGeometry {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let circuit_geometry = circuit.geometry();
        let participant_count = u64::from(circuit.profile().participant_count());
        let input_bit_count = u64_from_usize(circuit_geometry.input_bit_count)?;
        let operation_count = u64_from_usize(circuit.operations().len())?;
        let wire_count = checked_add(input_bit_count, operation_count)?;
        if wire_count != u64_from_usize(circuit_geometry.total_wire_count)? {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let mut constant_activation_count = 0_u64;
        let mut conjunction_gate_count = 0_u64;
        let mut exclusive_or_gate_count = 0_u64;
        let mut negation_gate_count = 0_u64;
        for operation in circuit.operations() {
            match operation {
                BooleanOperation::Constant(_) => {
                    constant_activation_count = checked_add(constant_activation_count, 1)?;
                }
                BooleanOperation::ExclusiveOr { .. } => {
                    exclusive_or_gate_count = checked_add(exclusive_or_gate_count, 1)?;
                }
                BooleanOperation::Conjunction { .. } => {
                    conjunction_gate_count = checked_add(conjunction_gate_count, 1)?;
                }
                BooleanOperation::Negation { .. } => {
                    negation_gate_count = checked_add(negation_gate_count, 1)?;
                }
            }
        }
        if constant_activation_count != u64_from_usize(circuit_geometry.constant_operation_count)?
            || conjunction_gate_count != u64_from_usize(circuit_geometry.conjunction_gate_count)?
            || exclusive_or_gate_count != u64_from_usize(circuit_geometry.exclusive_or_gate_count)?
            || negation_gate_count != u64_from_usize(circuit_geometry.negation_gate_count)?
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let score_input_wire_count = u64_from_usize(circuit.private_score_input_wires().count())?;
        if score_input_wire_count != u64_from_usize(circuit_geometry.private_score_input_bit_count)?
            || checked_add(
                u64_from_usize(circuit_geometry.candidate_attempt_presence_input_bit_count)?,
                score_input_wire_count,
            )? != input_bit_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let result_output_wire_count = u64_from_usize(
            circuit
                .ordered_option_position_wires()
                .iter()
                .map(Vec::len)
                .sum(),
        )?;
        if result_output_wire_count != u64_from_usize(circuit_geometry.private_result_bit_count)? {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let packed_wire_mask_byte_length = wire_count.div_ceil(8);
        let label_key_count = checked_product(checked_product(wire_count, 2)?, participant_count)?;
        let label_key_byte_length = checked_product(label_key_count, LABEL_KEY_BYTE_LENGTH)?;
        let shared_mask_count = checked_add(score_input_wire_count, result_output_wire_count)?;
        let sharing_random_coefficient_count = checked_product(shared_mask_count, 3)?;
        let sharing_random_coefficient_byte_length = checked_product(
            sharing_random_coefficient_count,
            u64_from_usize(BinaryFieldElement256::CANONICAL_BYTE_LENGTH)?,
        )?;

        // A label leaf opens exactly one component of exactly one external wire
        // value. Mask and share bundles follow their later authorization unit.
        let label_opening_leaf_count = label_key_count;
        let present_owner_mask_bundle_leaf_count = participant_count;
        let absence_share_bundle_leaf_count =
            checked_product(participant_count, participant_count)?;
        let result_share_bundle_leaf_count = participant_count;
        let private_wire_mask_bundle_leaf_count =
            packed_wire_mask_byte_length.div_ceil(MAXIMUM_PRIVATE_MASK_BUNDLE_PAYLOAD_BYTE_LENGTH);
        let secret_leaf_salt_count = checked_sum(&[
            label_opening_leaf_count,
            present_owner_mask_bundle_leaf_count,
            absence_share_bundle_leaf_count,
            result_share_bundle_leaf_count,
            private_wire_mask_bundle_leaf_count,
        ])?;
        let secret_leaf_salt_byte_length =
            checked_product(secret_leaf_salt_count, SECRET_LEAF_SALT_BYTE_LENGTH)?;

        let direct_joint_random_tape_byte_length = checked_sum(&[
            packed_wire_mask_byte_length,
            label_key_byte_length,
            sharing_random_coefficient_byte_length,
            secret_leaf_salt_byte_length,
        ])?;
        let all_party_explicit_tape_input_byte_length =
            checked_product(direct_joint_random_tape_byte_length, participant_count)?;
        let seeded_expansion_kmac_call_count = direct_joint_random_tape_byte_length
            .div_ceil(u64_from_usize(SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH)?);

        let binary_gate_row_count = checked_product(
            checked_add(conjunction_gate_count, exclusive_or_gate_count)?,
            4,
        )?;
        let unary_gate_row_count = checked_product(negation_gate_count, 2)?;
        let garbled_gate_row_count = checked_add(binary_gate_row_count, unary_gate_row_count)?;
        let correlation_key_contribution_count = checked_product(
            checked_product(garbled_gate_row_count, participant_count)?,
            participant_count,
        )?;
        let correlation_selector_contribution_count =
            checked_product(garbled_gate_row_count, participant_count)?;
        let correlation_contribution_byte_length = checked_add(
            checked_product(correlation_key_contribution_count, LABEL_KEY_BYTE_LENGTH)?,
            correlation_selector_contribution_count,
        )?;
        let garbling_kmac_call_count = correlation_key_contribution_count;
        let active_label_vector_byte_length = checked_add(
            checked_product(participant_count, LABEL_KEY_BYTE_LENGTH)?,
            1,
        )?;
        let public_garbled_table_byte_length = checked_product(
            checked_add(garbled_gate_row_count, constant_activation_count)?,
            active_label_vector_byte_length,
        )?;

        Ok(Self {
            participant_count,
            wire_count,
            packed_wire_mask_byte_length,
            label_key_count,
            label_key_byte_length,
            score_input_wire_count,
            result_output_wire_count,
            shared_mask_count,
            sharing_random_coefficient_count,
            sharing_random_coefficient_byte_length,
            label_opening_leaf_count,
            present_owner_mask_bundle_leaf_count,
            absence_share_bundle_leaf_count,
            result_share_bundle_leaf_count,
            private_wire_mask_bundle_leaf_count,
            secret_leaf_salt_count,
            secret_leaf_salt_byte_length,
            direct_joint_random_tape_byte_length,
            all_party_explicit_tape_input_byte_length,
            seeded_expansion_kmac_call_count,
            binary_gate_row_count,
            unary_gate_row_count,
            garbled_gate_row_count,
            constant_activation_count,
            correlation_key_contribution_count,
            correlation_selector_contribution_count,
            correlation_contribution_byte_length,
            garbling_kmac_call_count,
            public_garbled_table_byte_length,
        })
    }

    pub(crate) fn direct_joint_random_tape_byte_length_usize(
        self,
    ) -> Result<usize, TallyPreparationError> {
        usize::try_from(self.direct_joint_random_tape_byte_length)
            .map_err(|_| TallyPreparationError::IntegerConversion)
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_product(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, TallyPreparationError> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, *value))
}

fn u64_from_usize(value: usize) -> Result<u64, TallyPreparationError> {
    u64::try_from(value).map_err(|_| TallyPreparationError::IntegerConversion)
}
