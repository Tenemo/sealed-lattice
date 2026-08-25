use crate::{foundation::derive_foundation_roster_parameters, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    label_encoding::{
        LABEL_BODY_FIELD_LIMB_COUNT, LABEL_SHARE_VALUE_BYTE_LENGTH, WIRE_LABEL_BIT_LENGTH,
        garbling_output_byte_length,
    },
};

const AND_ROW_COUNT_PER_GATE: u64 = 4;
const COMMITMENT_DIGEST_BYTE_LENGTH: u64 = 64;
const DKAC_SALT_BYTE_LENGTH: u64 = 96;
const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;

/// Exact lower-bound inventory for the unactivated garbled tally construction.
///
/// This inventory deliberately excludes the real malicious preparation
/// protocol, canonical wrappers, mailbox envelopes, signatures, Merkle paths,
/// certificates, checkpoints, replay, repair, and runtime overlap. It cannot
/// authorize protocol admission or workflow acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GarbledTallyResourceLowerBound {
    pub(crate) participant_count: u64,
    pub(crate) reconstruction_threshold: u64,
    pub(crate) input_bit_count: u64,
    pub(crate) conjunction_gate_count: u64,
    pub(crate) public_output_bit_count: u64,
    pub(crate) private_result_bit_count: u64,
    pub(crate) fresh_label_wire_count: u64,
    pub(crate) and_row_count: u64,
    pub(crate) garbling_output_bit_length_per_call: u64,
    pub(crate) garbling_output_byte_length_per_call: u64,
    pub(crate) garbling_output_padding_bit_count_per_call: u64,
    pub(crate) garbling_hash_call_count: u64,
    pub(crate) evaluation_hash_call_count: u64,
    pub(crate) garbling_share_byte_length_per_participant: u64,
    pub(crate) all_garbling_share_byte_length: u64,
    pub(crate) final_garbled_circuit_byte_length: u64,
    pub(crate) label_commitment_count: u64,
    pub(crate) label_commitment_byte_length: u64,
    pub(crate) label_share_record_count: u64,
    pub(crate) scalar_share_record_count: u64,
    pub(crate) total_share_record_count: u64,
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

impl GarbledTallyResourceLowerBound {
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
        let public_output_bit_count = u64_from_usize(geometry.public_output_bit_count)?;
        let private_result_bit_count = u64_from_usize(geometry.private_result_bit_count)?;
        let output_bit_count = checked_add(public_output_bit_count, private_result_bit_count)?;
        let fresh_label_wire_count = checked_add(input_bit_count, conjunction_gate_count)?;
        let and_row_count = checked_multiply(conjunction_gate_count, AND_ROW_COUNT_PER_GATE)?;
        let garbling_output_bit_length_per_call =
            checked_multiply(participant_count, u64_from_usize(WIRE_LABEL_BIT_LENGTH)?)?;
        let garbling_output_byte_length_per_call = u64_from_usize(garbling_output_byte_length(
            circuit.profile().participant_count(),
        )?)?;
        let garbling_output_padding_bit_count_per_call =
            checked_multiply(garbling_output_byte_length_per_call, 8)?
                .checked_sub(garbling_output_bit_length_per_call)
                .ok_or(TallyPreparationError::GeometryMismatch)?;
        let garbling_hash_call_count = checked_multiply(participant_count, and_row_count)?;
        let evaluation_hash_call_count =
            checked_multiply(participant_count, conjunction_gate_count)?;
        let garbling_share_byte_length_per_participant =
            checked_multiply(and_row_count, garbling_output_byte_length_per_call)?;
        let all_garbling_share_byte_length = checked_multiply(
            participant_count,
            garbling_share_byte_length_per_participant,
        )?;
        let final_garbled_circuit_byte_length = garbling_share_byte_length_per_participant;

        let label_commitment_count = checked_multiply(
            checked_multiply(fresh_label_wire_count, 2)?,
            participant_count,
        )?;
        let label_commitment_byte_length =
            checked_multiply(label_commitment_count, COMMITMENT_DIGEST_BYTE_LENGTH)?;
        let label_share_record_count = checked_multiply(
            checked_multiply(checked_multiply(input_bit_count, 2)?, participant_count)?,
            participant_count,
        )?;
        let input_mask_record_count = checked_multiply(input_bit_count, participant_count)?;
        let row_bit_record_count = checked_multiply(and_row_count, participant_count)?;
        let output_mask_record_count = checked_multiply(output_bit_count, participant_count)?;
        let scalar_share_record_count = checked_sum(&[
            input_mask_record_count,
            row_bit_record_count,
            output_mask_record_count,
        ])?;
        let total_share_record_count =
            checked_add(label_share_record_count, scalar_share_record_count)?;
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
        let dkac_salt_byte_length =
            checked_multiply(total_share_record_count, DKAC_SALT_BYTE_LENGTH)?;
        let dkac_tag_byte_length =
            checked_multiply(total_share_record_count, FIELD_ELEMENT_BYTE_LENGTH)?;
        let label_record_verification_key_byte_length = checked_multiply(
            checked_multiply(
                u64_from_usize(LABEL_BODY_FIELD_LIMB_COUNT)?
                    .checked_add(1)
                    .ok_or(TallyPreparationError::ArithmeticOverflow)?,
                FIELD_ELEMENT_BYTE_LENGTH,
            )?,
            label_share_record_count,
        )?;
        let scalar_record_verification_key_byte_length = checked_multiply(
            checked_multiply(2, FIELD_ELEMENT_BYTE_LENGTH)?,
            scalar_share_record_count,
        )?;
        let dkac_verification_key_byte_length = checked_add(
            label_record_verification_key_byte_length,
            scalar_record_verification_key_byte_length,
        )?;

        let vector_opening_byte_length = checked_sum(&[
            u64_from_usize(LABEL_SHARE_VALUE_BYTE_LENGTH)?,
            FIELD_ELEMENT_BYTE_LENGTH,
            DKAC_SALT_BYTE_LENGTH,
        ])?;
        let scalar_opening_byte_length = checked_sum(&[
            FIELD_ELEMENT_BYTE_LENGTH,
            FIELD_ELEMENT_BYTE_LENGTH,
            DKAC_SALT_BYTE_LENGTH,
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
            checked_multiply(conjunction_gate_count, reconstruction_threshold)?,
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
            public_output_bit_count,
            private_result_bit_count,
            fresh_label_wire_count,
            and_row_count,
            garbling_output_bit_length_per_call,
            garbling_output_byte_length_per_call,
            garbling_output_padding_bit_count_per_call,
            garbling_hash_call_count,
            evaluation_hash_call_count,
            garbling_share_byte_length_per_participant,
            all_garbling_share_byte_length,
            final_garbled_circuit_byte_length,
            label_commitment_count,
            label_commitment_byte_length,
            label_share_record_count,
            scalar_share_record_count,
            total_share_record_count,
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
