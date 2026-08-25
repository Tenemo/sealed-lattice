use crate::tally_circuit::CompiledTallyCircuit;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    garbled_resource_model::GarbledTallyResourceLowerBound,
    label_encoding::{LABEL_BODY_BYTE_LENGTH, LABEL_BODY_FIELD_LIMB_COUNT},
    output_sharing::DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
};

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparationMultiplicationFamily {
    SemanticMaskBitness,
    ConjunctionMaskProduct,
    RowOffsetLimbProduct,
    LabelShareTagLimbProduct,
    InputMaskShareTagProduct,
    RowBitShareTagProduct,
    OutputMaskShareTagProduct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparationMultiplicationFamilyGeometry {
    pub(crate) family: PreparationMultiplicationFamily,
    pub(crate) multiplicative_layer: u64,
    pub(crate) operation_count: u64,
    pub(crate) consumes_layer_one_derived_value: bool,
}

/// Exact ideal-arithmetic DAG for the unactivated preparation candidate.
///
/// The graph starts after exact typed random values and private inputs exist.
/// It therefore does not price malicious random-bit generation, VSS, input
/// qualification, canonical 640-bit sampling, message framing, or output
/// delivery. Those are mandatory real-protocol owners. The one-field-share
/// volume is only a lower bound and must not be called MPC communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparationArithmeticGraph {
    pub(crate) participant_count: u64,
    pub(crate) fresh_semantic_mask_count: u64,
    pub(crate) conjunction_gate_count: u64,
    pub(crate) and_row_count: u64,
    pub(crate) output_mask_count: u64,
    pub(crate) label_body_field_limb_count: u64,
    pub(crate) label_body_random_byte_length: u64,
    pub(crate) offset_body_random_byte_length: u64,
    pub(crate) label_body_shamir_secret_count: u64,
    pub(crate) label_limb_shamir_secret_count: u64,
    pub(crate) scalar_shamir_secret_count: u64,
    pub(crate) shamir_random_coefficient_field_element_count: u64,
    pub(crate) shamir_random_coefficient_byte_length: u64,
    pub(crate) additive_correlation_free_component_count: u64,
    pub(crate) additive_correlation_correction_component_count: u64,
    pub(crate) additive_correlation_component_count: u64,
    pub(crate) additive_correlation_free_body_random_byte_length: u64,
    pub(crate) additive_correlation_free_point_bit_count: u64,
    pub(crate) additive_correlation_encoded_byte_length: u64,
    pub(crate) authenticated_record_count: u64,
    pub(crate) authenticated_record_value_field_element_count: u64,
    pub(crate) authenticated_key_field_element_count: u64,
    pub(crate) authenticated_key_byte_length: u64,
    pub(crate) authenticated_salt_byte_length: u64,
    pub(crate) mask_bitness_multiplication_count: u64,
    pub(crate) mask_product_multiplication_count: u64,
    pub(crate) row_offset_limb_multiplication_count: u64,
    pub(crate) label_share_tag_multiplication_count: u64,
    pub(crate) input_mask_share_tag_multiplication_count: u64,
    pub(crate) row_bit_share_tag_multiplication_count: u64,
    pub(crate) output_mask_share_tag_multiplication_count: u64,
    pub(crate) authenticated_tag_multiplication_count: u64,
    pub(crate) first_layer_authenticated_tag_multiplication_count: u64,
    pub(crate) second_layer_authenticated_tag_multiplication_count: u64,
    pub(crate) first_layer_authenticated_tag_output_count: u64,
    pub(crate) second_layer_authenticated_tag_output_count: u64,
    pub(crate) first_layer_multiplication_count: u64,
    pub(crate) second_layer_multiplication_count: u64,
    pub(crate) total_multiplication_count: u64,
    pub(crate) multiplicative_depth: u64,
    pub(crate) first_layer_public_zero_check_count: u64,
    pub(crate) first_layer_derived_row_value_count: u64,
    pub(crate) second_layer_row_offset_output_field_element_count: u64,
    pub(crate) one_field_share_per_participant_lower_bound_byte_length: u64,
}

impl PreparationArithmeticGraph {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let resources = GarbledTallyResourceLowerBound::derive(circuit)?;
        let participant_count = resources.participant_count;
        let label_body_field_limb_count = u64_from_usize(LABEL_BODY_FIELD_LIMB_COUNT)?;
        let label_body_byte_length = u64_from_usize(LABEL_BODY_BYTE_LENGTH)?;
        let sharing_random_coefficient_count = u64::try_from(
            DEGREE_THREE_RECONSTRUCTION_THRESHOLD
                .checked_sub(1)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
        )
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let output_mask_count = checked_add(
            resources.public_output_bit_count,
            resources.private_result_bit_count,
        )?;

        let label_body_random_byte_length = checked_multiply(
            checked_multiply(resources.fresh_label_wire_count, participant_count)?,
            label_body_byte_length,
        )?;
        let offset_body_random_byte_length =
            checked_multiply(participant_count, label_body_byte_length)?;
        let label_body_shamir_secret_count = resources
            .label_share_record_count
            .checked_div(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if checked_multiply(label_body_shamir_secret_count, participant_count)?
            != resources.label_share_record_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let label_limb_shamir_secret_count =
            checked_multiply(label_body_shamir_secret_count, label_body_field_limb_count)?;
        let scalar_shamir_secret_count = resources
            .scalar_share_record_count
            .checked_div(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if checked_multiply(scalar_shamir_secret_count, participant_count)?
            != resources.scalar_share_record_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let shamir_random_coefficient_field_element_count = checked_multiply(
            checked_add(label_limb_shamir_secret_count, scalar_shamir_secret_count)?,
            sharing_random_coefficient_count,
        )?;
        let shamir_random_coefficient_byte_length = checked_multiply(
            shamir_random_coefficient_field_element_count,
            FIELD_ELEMENT_BYTE_LENGTH,
        )?;

        let free_contributor_count = participant_count
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let additive_correlation_correction_component_count =
            checked_multiply(resources.and_row_count, participant_count)?;
        let additive_correlation_free_component_count = checked_multiply(
            additive_correlation_correction_component_count,
            free_contributor_count,
        )?;
        let additive_correlation_component_count = checked_add(
            additive_correlation_free_component_count,
            additive_correlation_correction_component_count,
        )?;
        let additive_correlation_free_body_random_byte_length = checked_multiply(
            additive_correlation_free_component_count,
            label_body_byte_length,
        )?;
        let additive_correlation_free_point_bit_count = additive_correlation_free_component_count;

        let mask_bitness_multiplication_count = resources.fresh_label_wire_count;
        let mask_product_multiplication_count = resources.conjunction_gate_count;
        let row_offset_limb_multiplication_count = checked_multiply(
            additive_correlation_correction_component_count,
            label_body_field_limb_count,
        )?;
        let label_share_tag_multiplication_count = resources.label_share_value_field_element_count;
        let input_mask_share_record_count =
            checked_multiply(resources.input_bit_count, participant_count)?;
        let row_bit_share_record_count =
            checked_multiply(resources.and_row_count, participant_count)?;
        let output_mask_share_record_count =
            checked_multiply(output_mask_count, participant_count)?;
        let input_mask_share_tag_multiplication_count = input_mask_share_record_count;
        let row_bit_share_tag_multiplication_count = row_bit_share_record_count;
        let output_mask_share_tag_multiplication_count = output_mask_share_record_count;
        let authenticated_tag_multiplication_count = checked_sum(&[
            label_share_tag_multiplication_count,
            input_mask_share_tag_multiplication_count,
            row_bit_share_tag_multiplication_count,
            output_mask_share_tag_multiplication_count,
        ])?;
        if authenticated_tag_multiplication_count
            != resources.dkac_tag_generation_field_multiplication_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let first_layer_authenticated_tag_multiplication_count = checked_sum(&[
            label_share_tag_multiplication_count,
            input_mask_share_tag_multiplication_count,
            output_mask_share_tag_multiplication_count,
        ])?;
        let second_layer_authenticated_tag_multiplication_count =
            row_bit_share_tag_multiplication_count;
        let first_layer_authenticated_tag_output_count = checked_sum(&[
            resources.label_share_record_count,
            input_mask_share_record_count,
            output_mask_share_record_count,
        ])?;
        let second_layer_authenticated_tag_output_count = row_bit_share_record_count;

        let first_layer_multiplication_count = checked_sum(&[
            mask_bitness_multiplication_count,
            mask_product_multiplication_count,
            first_layer_authenticated_tag_multiplication_count,
        ])?;
        let second_layer_multiplication_count = checked_add(
            row_offset_limb_multiplication_count,
            second_layer_authenticated_tag_multiplication_count,
        )?;
        let total_multiplication_count = checked_add(
            first_layer_multiplication_count,
            second_layer_multiplication_count,
        )?;
        let one_field_share_per_participant_lower_bound_byte_length = checked_multiply(
            checked_multiply(total_multiplication_count, participant_count)?,
            FIELD_ELEMENT_BYTE_LENGTH,
        )?;

        Ok(Self {
            participant_count,
            fresh_semantic_mask_count: resources.fresh_label_wire_count,
            conjunction_gate_count: resources.conjunction_gate_count,
            and_row_count: resources.and_row_count,
            output_mask_count,
            label_body_field_limb_count,
            label_body_random_byte_length,
            offset_body_random_byte_length,
            label_body_shamir_secret_count,
            label_limb_shamir_secret_count,
            scalar_shamir_secret_count,
            shamir_random_coefficient_field_element_count,
            shamir_random_coefficient_byte_length,
            additive_correlation_free_component_count,
            additive_correlation_correction_component_count,
            additive_correlation_component_count,
            additive_correlation_free_body_random_byte_length,
            additive_correlation_free_point_bit_count,
            additive_correlation_encoded_byte_length: resources.all_garbling_share_byte_length,
            authenticated_record_count: resources.total_share_record_count,
            authenticated_record_value_field_element_count: resources
                .total_share_value_field_element_count,
            authenticated_key_field_element_count: resources
                .dkac_verification_key_field_element_count,
            authenticated_key_byte_length: resources.dkac_verification_key_byte_length,
            authenticated_salt_byte_length: resources.dkac_salt_byte_length,
            mask_bitness_multiplication_count,
            mask_product_multiplication_count,
            row_offset_limb_multiplication_count,
            label_share_tag_multiplication_count,
            input_mask_share_tag_multiplication_count,
            row_bit_share_tag_multiplication_count,
            output_mask_share_tag_multiplication_count,
            authenticated_tag_multiplication_count,
            first_layer_authenticated_tag_multiplication_count,
            second_layer_authenticated_tag_multiplication_count,
            first_layer_authenticated_tag_output_count,
            second_layer_authenticated_tag_output_count,
            first_layer_multiplication_count,
            second_layer_multiplication_count,
            total_multiplication_count,
            multiplicative_depth: 2,
            first_layer_public_zero_check_count: mask_bitness_multiplication_count,
            first_layer_derived_row_value_count: resources.and_row_count,
            second_layer_row_offset_output_field_element_count:
                row_offset_limb_multiplication_count,
            one_field_share_per_participant_lower_bound_byte_length,
        })
    }

    pub(crate) fn multiplication_families(self) -> [PreparationMultiplicationFamilyGeometry; 7] {
        [
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::SemanticMaskBitness,
                multiplicative_layer: 1,
                operation_count: self.mask_bitness_multiplication_count,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::ConjunctionMaskProduct,
                multiplicative_layer: 1,
                operation_count: self.mask_product_multiplication_count,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::LabelShareTagLimbProduct,
                multiplicative_layer: 1,
                operation_count: self.label_share_tag_multiplication_count,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::InputMaskShareTagProduct,
                multiplicative_layer: 1,
                operation_count: self.input_mask_share_tag_multiplication_count,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::OutputMaskShareTagProduct,
                multiplicative_layer: 1,
                operation_count: self.output_mask_share_tag_multiplication_count,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::RowOffsetLimbProduct,
                multiplicative_layer: 2,
                operation_count: self.row_offset_limb_multiplication_count,
                consumes_layer_one_derived_value: true,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::RowBitShareTagProduct,
                multiplicative_layer: 2,
                operation_count: self.row_bit_share_tag_multiplication_count,
                consumes_layer_one_derived_value: true,
            },
        ]
    }
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
