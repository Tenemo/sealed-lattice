use crate::foundation::{CanonicalItem, Hash512, hash_foundation_tuple_512, xof_foundation_tuple};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    label_encoding::{
        LABEL_BODY_BYTE_LENGTH, LabelBody, WIRE_LABEL_BIT_LENGTH, WireLabel,
        decode_garbling_output_components, encode_garbling_output_components,
        garbling_output_byte_length,
    },
};

pub(super) const GARBLING_XOF_DOMAIN: &str = "sealed-lattice/garbled-tally/garbling/v1";
pub(super) const LABEL_COMMITMENT_DOMAIN: &str = "sealed-lattice/garbled-tally/label-commitment/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GarblingGateRow {
    gate_index: u32,
    left_external_bit: bool,
    right_external_bit: bool,
}

impl GarblingGateRow {
    pub(crate) const fn new(
        gate_index: u32,
        left_external_bit: bool,
        right_external_bit: bool,
    ) -> Self {
        Self {
            gate_index,
            left_external_bit,
            right_external_bit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GarblingInputComponentLabels {
    left: WireLabel,
    right: WireLabel,
}

impl GarblingInputComponentLabels {
    pub(crate) const fn new(left: WireLabel, right: WireLabel) -> Self {
        Self { left, right }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AffineLabelCommitments {
    zero: Hash512,
    one: Hash512,
}

impl AffineLabelCommitments {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        wire_index: u32,
        component_owner_position: u16,
        zero_label: WireLabel,
        one_label: WireLabel,
    ) -> Result<Self, TallyPreparationError> {
        if zero_label.point_bit() || !one_label.point_bit() {
            return Err(TallyPreparationError::AffineLabelPointBitMismatch);
        }
        Ok(Self {
            zero: commit_wire_label(
                context,
                wire_index,
                component_owner_position,
                false,
                zero_label,
            )?,
            one: commit_wire_label(
                context,
                wire_index,
                component_owner_position,
                true,
                one_label,
            )?,
        })
    }

    pub(crate) const fn zero(self) -> Hash512 {
        self.zero
    }

    pub(crate) const fn one(self) -> Hash512 {
        self.one
    }

    #[cfg(test)]
    pub(super) const fn from_commitments_for_test(zero: Hash512, one: Hash512) -> Self {
        Self { zero, one }
    }
}

pub(crate) fn derive_affine_wire_label(
    base_body: LabelBody,
    offset_body: LabelBody,
    external_bit: bool,
) -> WireLabel {
    let base_label = WireLabel::new(base_body, false);
    if external_bit {
        base_label.exclusive_or(WireLabel::new(offset_body, true))
    } else {
        base_label
    }
}

pub(crate) fn derive_exclusive_or_wire_label(
    left_label: WireLabel,
    right_label: WireLabel,
) -> WireLabel {
    left_label.exclusive_or(right_label)
}

pub(crate) const fn derive_negated_wire_label(input_label: WireLabel) -> WireLabel {
    input_label
}

pub(crate) fn create_individual_garbling_share(
    context: TallyPreparationContext,
    gate_row: GarblingGateRow,
    contributor_position: u16,
    input_component_labels: GarblingInputComponentLabels,
    correlation_share_components: &[WireLabel],
    output_base_label: WireLabel,
) -> Result<Vec<u8>, TallyPreparationError> {
    let participant_count = context.participant_count();
    validate_contributor_position(participant_count, contributor_position)?;
    validate_component_count(participant_count, correlation_share_components.len())?;
    validate_input_label_point_bit(
        contributor_position,
        "left",
        gate_row.left_external_bit,
        input_component_labels.left,
    )?;
    validate_input_label_point_bit(
        contributor_position,
        "right",
        gate_row.right_external_bit,
        input_component_labels.right,
    )?;
    if output_base_label.point_bit() {
        return Err(TallyPreparationError::GarblingOutputBasePointBitNonzero);
    }

    let mut components = garbling_xof_components(context, gate_row, input_component_labels)?;
    for (component, correlation_share) in components
        .iter_mut()
        .zip(correlation_share_components.iter().copied())
    {
        *component = component.exclusive_or(correlation_share);
    }
    let contributor_index = usize::from(contributor_position);
    components[contributor_index] = components[contributor_index].exclusive_or(output_base_label);
    encode_garbling_output_components(participant_count, &components)
}

pub(crate) fn combine_individual_garbling_shares(
    participant_count: u16,
    individual_share_bytes: &[Vec<u8>],
) -> Result<Vec<u8>, TallyPreparationError> {
    validate_component_count(participant_count, individual_share_bytes.len())?;
    let mut combined_components = zero_component_vector(participant_count)?;
    for share_bytes in individual_share_bytes {
        let share_components = decode_garbling_output_components(participant_count, share_bytes)?;
        xor_component_vectors(&mut combined_components, &share_components)?;
    }
    encode_garbling_output_components(participant_count, &combined_components)
}

pub(crate) fn evaluate_active_and_row(
    context: TallyPreparationContext,
    gate_row: GarblingGateRow,
    active_left_component_labels: &[WireLabel],
    active_right_component_labels: &[WireLabel],
    combined_row_bytes: &[u8],
) -> Result<Vec<WireLabel>, TallyPreparationError> {
    let participant_count = context.participant_count();
    validate_component_count(participant_count, active_left_component_labels.len())?;
    validate_component_count(participant_count, active_right_component_labels.len())?;
    let mut evaluated_components =
        decode_garbling_output_components(participant_count, combined_row_bytes)?;

    for contributor_position in 0..participant_count {
        let contributor_index = usize::from(contributor_position);
        let left_component_label = active_left_component_labels[contributor_index];
        let right_component_label = active_right_component_labels[contributor_index];
        validate_input_label_point_bit(
            contributor_position,
            "left",
            gate_row.left_external_bit,
            left_component_label,
        )?;
        validate_input_label_point_bit(
            contributor_position,
            "right",
            gate_row.right_external_bit,
            right_component_label,
        )?;
        let garbling_output = garbling_xof_components(
            context,
            gate_row,
            GarblingInputComponentLabels::new(left_component_label, right_component_label),
        )?;
        xor_component_vectors(&mut evaluated_components, &garbling_output)?;
    }
    Ok(evaluated_components)
}

pub(crate) fn verify_active_and_output(
    context: TallyPreparationContext,
    output_wire_index: u32,
    evaluated_components: &[WireLabel],
    output_label_commitments: &[AffineLabelCommitments],
    authenticated_row_value: BinaryFieldElement256,
) -> Result<bool, TallyPreparationError> {
    let participant_count = context.participant_count();
    validate_component_count(participant_count, evaluated_components.len())?;
    validate_component_count(participant_count, output_label_commitments.len())?;
    let row_bit = canonical_field_bit(authenticated_row_value)?;
    let first_component_bit = evaluated_components
        .first()
        .ok_or(
            TallyPreparationError::GarblingOutputComponentCountMismatch {
                expected: usize::from(participant_count),
                actual: 0,
            },
        )?
        .point_bit();

    for (component_position, (component, commitments)) in evaluated_components
        .iter()
        .copied()
        .zip(output_label_commitments.iter().copied())
        .enumerate()
    {
        if commitments.zero() == commitments.one() {
            return Err(TallyPreparationError::AffineLabelCommitmentsEqual { component_position });
        }
        if component.point_bit() != first_component_bit {
            return Err(TallyPreparationError::GarblingComponentPointBitMismatch {
                component_position,
            });
        }
        let component_owner_position = u16::try_from(component_position)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let matches_zero = commit_wire_label(
            context,
            output_wire_index,
            component_owner_position,
            false,
            component,
        )? == commitments.zero();
        let matches_one = commit_wire_label(
            context,
            output_wire_index,
            component_owner_position,
            true,
            component,
        )? == commitments.one();
        let matches_exactly_one_commitment = matches_zero ^ matches_one;
        let point_bit_matches_commitment = if component.point_bit() {
            matches_one
        } else {
            matches_zero
        };
        if !matches_exactly_one_commitment || !point_bit_matches_commitment {
            return Err(
                TallyPreparationError::GarblingLabelCommitmentMembershipMismatch {
                    component_position,
                },
            );
        }
    }
    if row_bit != first_component_bit {
        return Err(TallyPreparationError::GarblingAuthenticatedRowBitMismatch);
    }
    Ok(first_component_bit)
}

pub(crate) fn commit_wire_label(
    context: TallyPreparationContext,
    wire_index: u32,
    component_owner_position: u16,
    external_bit: bool,
    label: WireLabel,
) -> Result<Hash512, TallyPreparationError> {
    validate_contributor_position(context.participant_count(), component_owner_position)?;
    Ok(hash_foundation_tuple_512(
        LABEL_COMMITMENT_DOMAIN,
        &[
            CanonicalItem::variable_bytes(context.canonical_bytes())?,
            CanonicalItem::unsigned32(wire_index),
            CanonicalItem::unsigned16(component_owner_position),
            CanonicalItem::boolean(external_bit),
            CanonicalItem::fixed_bytes(label.canonical_bytes())?,
        ],
    )?)
}

pub(super) fn garbling_xof_components(
    context: TallyPreparationContext,
    gate_row: GarblingGateRow,
    input_component_labels: GarblingInputComponentLabels,
) -> Result<Vec<WireLabel>, TallyPreparationError> {
    let participant_count = context.participant_count();
    let output_bit_length = usize::from(participant_count)
        .checked_mul(WIRE_LABEL_BIT_LENGTH)
        .ok_or(TallyPreparationError::ArithmeticOverflow)?;
    let output_byte_length = garbling_output_byte_length(participant_count)?;
    let mut output = xof_foundation_tuple(
        GARBLING_XOF_DOMAIN,
        &[
            CanonicalItem::variable_bytes(context.canonical_bytes())?,
            CanonicalItem::unsigned32(gate_row.gate_index),
            CanonicalItem::boolean(gate_row.left_external_bit),
            CanonicalItem::boolean(gate_row.right_external_bit),
            CanonicalItem::fixed_bytes(input_component_labels.left.canonical_bytes())?,
            CanonicalItem::fixed_bytes(input_component_labels.right.canonical_bytes())?,
            CanonicalItem::unsigned16(participant_count),
            CanonicalItem::unsigned64(
                u64::try_from(output_bit_length)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            ),
        ],
        output_byte_length,
    )?;
    mask_unused_high_bits(&mut output, output_bit_length);
    decode_garbling_output_components(participant_count, &output)
}

fn canonical_field_bit(value: BinaryFieldElement256) -> Result<bool, TallyPreparationError> {
    if value == BinaryFieldElement256::ZERO {
        Ok(false)
    } else if value == BinaryFieldElement256::ONE {
        Ok(true)
    } else {
        Err(TallyPreparationError::GarblingAuthenticatedRowValueNotBit)
    }
}

fn mask_unused_high_bits(output: &mut [u8], output_bit_length: usize) {
    let used_final_byte_bit_count = output_bit_length % 8;
    if used_final_byte_bit_count != 0 {
        let used_bit_mask = (1_u8 << used_final_byte_bit_count) - 1;
        if let Some(final_byte) = output.last_mut() {
            *final_byte &= used_bit_mask;
        }
    }
}

fn validate_contributor_position(
    participant_count: u16,
    contributor_position: u16,
) -> Result<(), TallyPreparationError> {
    if contributor_position >= participant_count {
        return Err(
            TallyPreparationError::GarblingContributorPositionOutOfRange {
                contributor_position,
                participant_count,
            },
        );
    }
    Ok(())
}

fn validate_component_count(
    participant_count: u16,
    component_count: usize,
) -> Result<(), TallyPreparationError> {
    let expected = usize::from(participant_count);
    if component_count != expected {
        return Err(
            TallyPreparationError::GarblingOutputComponentCountMismatch {
                expected,
                actual: component_count,
            },
        );
    }
    Ok(())
}

fn validate_input_label_point_bit(
    component_position: u16,
    input_side: &'static str,
    expected_external_bit: bool,
    label: WireLabel,
) -> Result<(), TallyPreparationError> {
    if label.point_bit() != expected_external_bit {
        return Err(TallyPreparationError::GarblingInputPointBitMismatch {
            component_position,
            input_side,
        });
    }
    Ok(())
}

fn zero_component_vector(participant_count: u16) -> Result<Vec<WireLabel>, TallyPreparationError> {
    let zero_body = LabelBody::from_canonical_bytes(&[0_u8; LABEL_BODY_BYTE_LENGTH])?;
    Ok(vec![
        WireLabel::new(zero_body, false);
        usize::from(participant_count)
    ])
}

fn xor_component_vectors(
    accumulated_components: &mut [WireLabel],
    components: &[WireLabel],
) -> Result<(), TallyPreparationError> {
    if accumulated_components.len() != components.len() {
        return Err(
            TallyPreparationError::GarblingOutputComponentCountMismatch {
                expected: accumulated_components.len(),
                actual: components.len(),
            },
        );
    }
    for (accumulated_component, component) in accumulated_components
        .iter_mut()
        .zip(components.iter().copied())
    {
        *accumulated_component = accumulated_component.exclusive_or(component);
    }
    Ok(())
}
