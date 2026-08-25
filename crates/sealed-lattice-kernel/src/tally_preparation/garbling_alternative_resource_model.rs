use crate::{
    foundation::{DECLARED_ADVERSARIAL_QUERY_BUDGET, Hash512, derive_foundation_roster_parameters},
    tally_circuit::CompiledTallyCircuit,
};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    authenticated_opening::AUTHENTICATED_SHARE_SALT_BYTE_LENGTH,
    garbled_resource_model::GarbledTallyResourceLowerBound,
    label_encoding::{
        LABEL_BODY_FIELD_LIMB_COUNT, LABEL_SHARE_VALUE_BYTE_LENGTH, WIRE_LABEL_BIT_LENGTH,
        garbling_output_byte_length,
    },
};

const BINARY_GATE_ROW_COUNT: u64 = 4;
const UNARY_GATE_ROW_COUNT: u64 = 2;
const BITS_PER_BYTE: u64 = 8;
const ACTIVE_LABEL_COMMITMENT_SALT_BIT_LENGTH: u64 = 640;
const SHORT_LABEL_COMMITMENT_SALT_BIT_LENGTH: u64 = 256;
const ADAPTIVE_REPROGRAMMING_COEFFICIENT: u128 = 4;
const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;
const COMMITMENT_DIGEST_BYTE_LENGTH: u64 = Hash512::BYTE_LENGTH as u64;

/// Lower-bound delta for independently salted affine-label commitments.
///
/// Salting only repairs the label-commitment auxiliary transcript. It does not
/// hide garbling points and therefore does not replace the adaptive-oracle
/// argument. The salt owner must retain both salts and reveal exactly the
/// active one for each fresh label component; withholding leaves activation
/// unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SaltedLabelCommitmentRepairLowerBound {
    pub(crate) label_commitment_count: u64,
    pub(crate) active_label_salt_opening_count: u64,
    pub(crate) selected_salt_bit_length: u64,
    pub(crate) selected_salt_byte_length: u64,
    pub(crate) private_salt_storage_byte_length: u64,
    pub(crate) active_salt_opening_byte_length: u64,
    pub(crate) combined_known_public_lower_bound_with_salts_byte_length: u64,
    pub(crate) short_salt_bit_length: u64,
    pub(crate) declared_adversarial_query_budget: u128,
    pub(crate) conditional_advantage_numerator: u128,
    pub(crate) short_salt_conditional_strict_power_of_two_bound_exponent: u64,
    pub(crate) selected_salt_conditional_strict_power_of_two_bound_exponent: u64,
}

impl SaltedLabelCommitmentRepairLowerBound {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let baseline = GarbledTallyResourceLowerBound::derive(circuit)?;
        let selected_salt_byte_length = ACTIVE_LABEL_COMMITMENT_SALT_BIT_LENGTH
            .checked_div(BITS_PER_BYTE)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if checked_multiply(selected_salt_byte_length, BITS_PER_BYTE)?
            != ACTIVE_LABEL_COMMITMENT_SALT_BIT_LENGTH
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let active_label_salt_opening_count =
            checked_multiply(baseline.fresh_label_wire_count, baseline.participant_count)?;
        let private_salt_storage_byte_length =
            checked_multiply(baseline.label_commitment_count, selected_salt_byte_length)?;
        let active_salt_opening_byte_length =
            checked_multiply(active_label_salt_opening_count, selected_salt_byte_length)?;
        let combined_known_public_lower_bound_with_salts_byte_length = checked_add(
            baseline.combined_known_public_lower_bound_byte_length,
            active_salt_opening_byte_length,
        )?;
        let short_salt_conditional_strict_power_of_two_bound_exponent =
            conditional_strict_bound_exponent(SHORT_LABEL_COMMITMENT_SALT_BIT_LENGTH)?;
        let selected_salt_conditional_strict_power_of_two_bound_exponent =
            conditional_strict_bound_exponent(ACTIVE_LABEL_COMMITMENT_SALT_BIT_LENGTH)?;
        let conditional_advantage_numerator = conditional_advantage_numerator()?;

        Ok(Self {
            label_commitment_count: baseline.label_commitment_count,
            active_label_salt_opening_count,
            selected_salt_bit_length: ACTIVE_LABEL_COMMITMENT_SALT_BIT_LENGTH,
            selected_salt_byte_length,
            private_salt_storage_byte_length,
            active_salt_opening_byte_length,
            combined_known_public_lower_bound_with_salts_byte_length,
            short_salt_bit_length: SHORT_LABEL_COMMITMENT_SALT_BIT_LENGTH,
            declared_adversarial_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            conditional_advantage_numerator,
            short_salt_conditional_strict_power_of_two_bound_exponent,
            selected_salt_conditional_strict_power_of_two_bound_exponent,
        })
    }
}

/// Exact known lower bound for the conservative independent-label baseline.
///
/// XOR and NOT operations become paid garbled gates. This inventory excludes
/// the real malicious preparation protocol and all transport and runtime
/// wrappers, so it is a comparison artifact rather than an admission result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndependentLabelGarblingResourceLowerBound {
    pub(crate) participant_count: u64,
    pub(crate) reconstruction_threshold: u64,
    pub(crate) input_bit_count: u64,
    pub(crate) conjunction_gate_count: u64,
    pub(crate) exclusive_or_gate_count: u64,
    pub(crate) negation_gate_count: u64,
    pub(crate) binary_gate_count: u64,
    pub(crate) evaluated_gate_count: u64,
    pub(crate) paid_gate_row_count: u64,
    pub(crate) constant_activation_vector_count: u64,
    pub(crate) total_labeled_wire_count: u64,
    pub(crate) public_output_bit_count: u64,
    pub(crate) private_result_bit_count: u64,
    pub(crate) garbling_output_bit_length_per_call: u64,
    pub(crate) garbling_output_byte_length_per_call: u64,
    pub(crate) garbling_generation_call_count: u64,
    pub(crate) garbling_evaluation_call_count: u64,
    pub(crate) garbling_share_byte_length_per_participant: u64,
    pub(crate) all_garbling_share_byte_length: u64,
    pub(crate) paid_garbled_row_byte_length: u64,
    pub(crate) constant_activation_vector_byte_length: u64,
    pub(crate) final_garbled_circuit_byte_length: u64,
    pub(crate) label_commitment_count: u64,
    pub(crate) label_commitment_byte_length: u64,
    pub(crate) label_share_record_count: u64,
    pub(crate) scalar_share_record_count: u64,
    pub(crate) total_share_record_count: u64,
    pub(crate) total_share_value_field_element_count: u64,
    pub(crate) dkac_verification_key_field_element_count: u64,
    pub(crate) dkac_tag_generation_field_multiplication_count: u64,
    pub(crate) raw_label_share_storage_byte_length: u64,
    pub(crate) raw_scalar_share_storage_byte_length: u64,
    pub(crate) raw_share_storage_byte_length: u64,
    pub(crate) dkac_commitment_byte_length: u64,
    pub(crate) dkac_salt_byte_length: u64,
    pub(crate) dkac_tag_byte_length: u64,
    pub(crate) dkac_verification_key_byte_length: u64,
    pub(crate) active_label_opening_upper_bound_byte_length: u64,
    pub(crate) input_mask_opening_upper_bound_byte_length: u64,
    pub(crate) active_row_opening_byte_length: u64,
    pub(crate) private_result_release_opening_byte_length: u64,
    pub(crate) public_nonempty_mask_opening_byte_length: u64,
    pub(crate) static_public_lower_bound_byte_length: u64,
    pub(crate) online_public_lower_bound_byte_length: u64,
    pub(crate) combined_known_public_lower_bound_byte_length: u64,
}

impl IndependentLabelGarblingResourceLowerBound {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let geometry = circuit.geometry();
        let participant_count = u64::from(circuit.profile().participant_count());
        let roster_parameters = derive_foundation_roster_parameters(
            circuit.profile().participant_count(),
        )
        .ok_or(TallyPreparationError::ParticipantCountOutOfRange {
            participant_count: circuit.profile().participant_count(),
        })?;
        let reconstruction_threshold = u64::from(roster_parameters.reconstruction_threshold);
        let input_bit_count = u64_from_usize(geometry.input_bit_count)?;
        let conjunction_gate_count = u64_from_usize(geometry.conjunction_gate_count)?;
        let exclusive_or_gate_count = u64_from_usize(geometry.exclusive_or_gate_count)?;
        let negation_gate_count = u64_from_usize(geometry.negation_gate_count)?;
        let binary_gate_count = checked_add(conjunction_gate_count, exclusive_or_gate_count)?;
        let evaluated_gate_count = checked_add(binary_gate_count, negation_gate_count)?;
        let paid_gate_row_count = checked_add(
            checked_multiply(binary_gate_count, BINARY_GATE_ROW_COUNT)?,
            checked_multiply(negation_gate_count, UNARY_GATE_ROW_COUNT)?,
        )?;
        let constant_activation_vector_count = u64_from_usize(geometry.constant_operation_count)?;
        let total_labeled_wire_count = u64_from_usize(geometry.total_wire_count)?;
        let public_output_bit_count = u64_from_usize(geometry.public_output_bit_count)?;
        let private_result_bit_count = u64_from_usize(geometry.private_result_bit_count)?;
        let output_bit_count = checked_add(public_output_bit_count, private_result_bit_count)?;
        let garbling_output_bit_length_per_call =
            checked_multiply(participant_count, u64_from_usize(WIRE_LABEL_BIT_LENGTH)?)?;
        let garbling_output_byte_length_per_call = u64_from_usize(garbling_output_byte_length(
            circuit.profile().participant_count(),
        )?)?;
        let garbling_generation_call_count =
            checked_multiply(participant_count, paid_gate_row_count)?;
        let garbling_evaluation_call_count =
            checked_multiply(participant_count, evaluated_gate_count)?;
        let garbling_share_byte_length_per_participant =
            checked_multiply(paid_gate_row_count, garbling_output_byte_length_per_call)?;
        let all_garbling_share_byte_length = checked_multiply(
            participant_count,
            garbling_share_byte_length_per_participant,
        )?;
        let paid_garbled_row_byte_length = garbling_share_byte_length_per_participant;
        let constant_activation_vector_byte_length = checked_multiply(
            constant_activation_vector_count,
            garbling_output_byte_length_per_call,
        )?;
        let final_garbled_circuit_byte_length = checked_add(
            paid_garbled_row_byte_length,
            constant_activation_vector_byte_length,
        )?;

        let label_commitment_count = checked_multiply(
            checked_multiply(total_labeled_wire_count, 2)?,
            participant_count,
        )?;
        let label_commitment_byte_length =
            checked_multiply(label_commitment_count, COMMITMENT_DIGEST_BYTE_LENGTH)?;
        let label_share_record_count = checked_multiply(
            checked_multiply(checked_multiply(input_bit_count, 2)?, participant_count)?,
            participant_count,
        )?;
        let input_mask_record_count = checked_multiply(input_bit_count, participant_count)?;
        let row_bit_record_count = checked_multiply(paid_gate_row_count, participant_count)?;
        let output_mask_record_count = checked_multiply(output_bit_count, participant_count)?;
        let scalar_share_record_count = checked_sum(&[
            input_mask_record_count,
            row_bit_record_count,
            output_mask_record_count,
        ])?;
        let total_share_record_count =
            checked_add(label_share_record_count, scalar_share_record_count)?;
        let label_share_value_field_element_count = checked_multiply(
            label_share_record_count,
            u64_from_usize(LABEL_BODY_FIELD_LIMB_COUNT)?,
        )?;
        let total_share_value_field_element_count = checked_add(
            label_share_value_field_element_count,
            scalar_share_record_count,
        )?;
        let dkac_verification_key_field_element_count = checked_add(
            checked_multiply(
                label_share_record_count,
                checked_add(u64_from_usize(LABEL_BODY_FIELD_LIMB_COUNT)?, 1)?,
            )?,
            checked_multiply(scalar_share_record_count, 2)?,
        )?;
        let dkac_tag_generation_field_multiplication_count = total_share_value_field_element_count;
        let raw_label_share_storage_byte_length = checked_multiply(
            label_share_record_count,
            u64_from_usize(LABEL_SHARE_VALUE_BYTE_LENGTH)?,
        )?;
        let raw_scalar_share_storage_byte_length =
            checked_multiply(scalar_share_record_count, FIELD_ELEMENT_BYTE_LENGTH)?;
        let raw_share_storage_byte_length = checked_add(
            raw_label_share_storage_byte_length,
            raw_scalar_share_storage_byte_length,
        )?;
        let dkac_commitment_byte_length =
            checked_multiply(total_share_record_count, COMMITMENT_DIGEST_BYTE_LENGTH)?;
        let dkac_salt_byte_length = checked_multiply(
            total_share_record_count,
            u64_from_usize(AUTHENTICATED_SHARE_SALT_BYTE_LENGTH)?,
        )?;
        let dkac_tag_byte_length =
            checked_multiply(total_share_record_count, FIELD_ELEMENT_BYTE_LENGTH)?;
        let dkac_verification_key_byte_length = checked_multiply(
            dkac_verification_key_field_element_count,
            FIELD_ELEMENT_BYTE_LENGTH,
        )?;

        let vector_opening_byte_length = checked_sum(&[
            u64_from_usize(LABEL_SHARE_VALUE_BYTE_LENGTH)?,
            FIELD_ELEMENT_BYTE_LENGTH,
            u64_from_usize(AUTHENTICATED_SHARE_SALT_BYTE_LENGTH)?,
        ])?;
        let scalar_opening_byte_length = checked_sum(&[
            FIELD_ELEMENT_BYTE_LENGTH,
            FIELD_ELEMENT_BYTE_LENGTH,
            u64_from_usize(AUTHENTICATED_SHARE_SALT_BYTE_LENGTH)?,
        ])?;
        let active_label_opening_upper_bound_byte_length = checked_multiply(
            checked_multiply(
                checked_multiply(input_bit_count, participant_count)?,
                reconstruction_threshold,
            )?,
            vector_opening_byte_length,
        )?;
        let input_mask_opening_upper_bound_byte_length = checked_multiply(
            checked_multiply(input_bit_count, reconstruction_threshold)?,
            scalar_opening_byte_length,
        )?;
        let active_row_opening_byte_length = checked_multiply(
            checked_multiply(evaluated_gate_count, reconstruction_threshold)?,
            scalar_opening_byte_length,
        )?;
        let private_result_release_opening_byte_length = checked_multiply(
            checked_multiply(private_result_bit_count, reconstruction_threshold)?,
            scalar_opening_byte_length,
        )?;
        let public_nonempty_mask_opening_byte_length = checked_multiply(
            checked_multiply(public_output_bit_count, reconstruction_threshold)?,
            scalar_opening_byte_length,
        )?;

        let static_public_lower_bound_byte_length = checked_sum(&[
            all_garbling_share_byte_length,
            final_garbled_circuit_byte_length,
            label_commitment_byte_length,
            dkac_commitment_byte_length,
            dkac_verification_key_byte_length,
        ])?;
        let online_public_lower_bound_byte_length = checked_sum(&[
            active_label_opening_upper_bound_byte_length,
            input_mask_opening_upper_bound_byte_length,
            active_row_opening_byte_length,
            private_result_release_opening_byte_length,
            public_nonempty_mask_opening_byte_length,
        ])?;
        let combined_known_public_lower_bound_byte_length = checked_add(
            static_public_lower_bound_byte_length,
            online_public_lower_bound_byte_length,
        )?;

        Ok(Self {
            participant_count,
            reconstruction_threshold,
            input_bit_count,
            conjunction_gate_count,
            exclusive_or_gate_count,
            negation_gate_count,
            binary_gate_count,
            evaluated_gate_count,
            paid_gate_row_count,
            constant_activation_vector_count,
            total_labeled_wire_count,
            public_output_bit_count,
            private_result_bit_count,
            garbling_output_bit_length_per_call,
            garbling_output_byte_length_per_call,
            garbling_generation_call_count,
            garbling_evaluation_call_count,
            garbling_share_byte_length_per_participant,
            all_garbling_share_byte_length,
            paid_garbled_row_byte_length,
            constant_activation_vector_byte_length,
            final_garbled_circuit_byte_length,
            label_commitment_count,
            label_commitment_byte_length,
            label_share_record_count,
            scalar_share_record_count,
            total_share_record_count,
            total_share_value_field_element_count,
            dkac_verification_key_field_element_count,
            dkac_tag_generation_field_multiplication_count,
            raw_label_share_storage_byte_length,
            raw_scalar_share_storage_byte_length,
            raw_share_storage_byte_length,
            dkac_commitment_byte_length,
            dkac_salt_byte_length,
            dkac_tag_byte_length,
            dkac_verification_key_byte_length,
            active_label_opening_upper_bound_byte_length,
            input_mask_opening_upper_bound_byte_length,
            active_row_opening_byte_length,
            private_result_release_opening_byte_length,
            public_nonempty_mask_opening_byte_length,
            static_public_lower_bound_byte_length,
            online_public_lower_bound_byte_length,
            combined_known_public_lower_bound_byte_length,
        })
    }
}

fn conditional_strict_bound_exponent(
    hidden_entropy_bit_length: u64,
) -> Result<u64, TallyPreparationError> {
    if !hidden_entropy_bit_length.is_multiple_of(2) {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let numerator = conditional_advantage_numerator()?;
    let numerator_power_of_two_upper_bound = u64::from(
        u128::BITS
            .checked_sub(numerator.leading_zeros())
            .ok_or(TallyPreparationError::GeometryMismatch)?,
    );
    (hidden_entropy_bit_length / 2)
        .checked_sub(numerator_power_of_two_upper_bound)
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn conditional_advantage_numerator() -> Result<u128, TallyPreparationError> {
    DECLARED_ADVERSARIAL_QUERY_BUDGET
        .checked_mul(ADAPTIVE_REPROGRAMMING_COEFFICIENT)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
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

fn u64_from_usize(value: usize) -> Result<u64, TallyPreparationError> {
    u64::try_from(value).map_err(|_| TallyPreparationError::IntegerConversion)
}
