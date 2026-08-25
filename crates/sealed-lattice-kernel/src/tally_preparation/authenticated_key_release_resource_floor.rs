use crate::{
    foundation::{FOUNDATION_PROFILE, derive_foundation_roster_parameters},
    tally_circuit::CompiledTallyCircuit,
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_share_vector::{
        authenticated_key_share_vector_descriptor_canonical_byte_length,
        authenticated_key_share_vector_payload_chunk_preimage_byte_length,
    },
    authenticated_key_share_vector_codeword_manifest::authenticated_key_share_vector_codeword_manifest_canonical_byte_length,
    authenticated_key_share_vector_manifest::{
        authenticated_key_share_vector_acknowledgement_canonical_byte_length,
        authenticated_key_share_vector_manifest_canonical_byte_length,
    },
    preparation_holder_record_catalog::PreparationHolderRecordInventory,
};

const FIELD_ELEMENT_BYTE_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64;
const HASH512_OUTPUT_BYTE_LENGTH: u64 = 64;
const SHAKE256_RATE_BYTE_LENGTH: u64 = 136;

/// Lower bounds for releasing the authenticated-opening keys.
///
/// A public key vector is the constant term of degree-three Shamir polynomials
/// generated inside preparation. Counting only those constants omits the
/// public correspondence needed to show that they are the keys used before
/// the holder-commitment barrier. The smallest live repair publishes four
/// canonical share vectors and requires all ten participants to acknowledge
/// that the reconstructed polynomials match their private points. Its
/// correctness remains conditional on that signed causal graph. The
/// conservative route publishes all ten vectors so a public verifier can
/// check the degree-three codeword directly.
///
/// The quorum-checked route includes certificate-free descriptors, one
/// source-bound manifest, and all-roster unsigned acknowledgement bodies. It
/// still excludes detached signatures, signature-key binding, state
/// certificates, transition indexes, the derived acknowledgement root,
/// retransmission, checkpoints, and physical storage amplification. The
/// conservative all-roster route includes its payloads, descriptors, and one
/// source-bound codeword manifest. It still excludes signatures, source
/// certification, state transitions, retransmission, checkpoints, and
/// physical storage amplification. This model is an admission floor, not a
/// complete protocol ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyReleaseResourceFloor {
    pub(crate) participant_count: u64,
    pub(crate) reconstruction_threshold: u64,
    pub(crate) holder_record_count: u64,
    pub(crate) verification_key_field_element_count: u64,
    pub(crate) reconstructed_key_byte_length: u64,
    pub(crate) share_vector_byte_length_per_sender: u64,
    pub(crate) share_vector_chunk_count_per_sender: u64,
    pub(crate) final_share_vector_chunk_byte_length: u64,
    pub(crate) share_vector_descriptor_byte_length_per_sender: u64,
    pub(crate) payload_chunk_hash_invocation_count_per_sender: u64,
    pub(crate) payload_chunk_hash_absorbed_byte_length_per_sender: u64,
    pub(crate) payload_chunk_hash_output_byte_length_per_sender: u64,
    pub(crate) payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender: u64,
    pub(crate) maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count: u64,
    pub(crate) quorum_checked_share_sender_count: u64,
    pub(crate) quorum_checked_share_payload_byte_length: u64,
    pub(crate) quorum_checked_share_descriptor_byte_length: u64,
    pub(crate) quorum_checked_share_payload_and_descriptor_byte_length: u64,
    pub(crate) quorum_checked_share_manifest_byte_length: u64,
    pub(crate) acknowledgement_body_byte_length_per_participant: u64,
    pub(crate) all_roster_acknowledgement_body_byte_length: u64,
    pub(crate) quorum_checked_share_control_byte_length: u64,
    pub(crate) quorum_checked_share_payload_and_control_byte_length: u64,
    pub(crate) quorum_checked_additional_byte_length: u64,
    pub(crate) all_roster_share_sender_count: u64,
    pub(crate) all_roster_share_payload_byte_length: u64,
    pub(crate) all_roster_share_descriptor_byte_length: u64,
    pub(crate) all_roster_share_payload_and_descriptor_byte_length: u64,
    pub(crate) all_roster_share_manifest_byte_length: u64,
    pub(crate) all_roster_share_control_byte_length: u64,
    pub(crate) all_roster_share_payload_and_control_byte_length: u64,
    pub(crate) all_roster_additional_byte_length: u64,
}

impl AuthenticatedKeyReleaseResourceFloor {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        let inventory = PreparationHolderRecordInventory::derive(context, circuit)?;
        let roster_parameters =
            derive_foundation_roster_parameters(circuit.profile().participant_count())
                .ok_or(TallyPreparationError::GeometryMismatch)?;
        let participant_count = u64::from(circuit.profile().participant_count());
        let reconstruction_threshold = u64::from(roster_parameters.reconstruction_threshold);
        let verification_key_field_element_count = inventory.verification_key_field_element_count();
        let reconstructed_key_byte_length = checked_multiply(
            verification_key_field_element_count,
            FIELD_ELEMENT_BYTE_LENGTH,
        )?;
        let share_vector_byte_length_per_sender = reconstructed_key_byte_length;
        let configured_chunk_byte_length =
            u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let share_vector_chunk_count_per_sender = checked_ceiling_divide(
            share_vector_byte_length_per_sender,
            configured_chunk_byte_length,
        )?;
        let complete_chunk_count = share_vector_chunk_count_per_sender
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let final_share_vector_chunk_byte_length = share_vector_byte_length_per_sender
            .checked_sub(checked_multiply(
                complete_chunk_count,
                configured_chunk_byte_length,
            )?)
            .filter(|byte_length| *byte_length > 0)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let share_vector_descriptor_byte_length_per_sender =
            authenticated_key_share_vector_descriptor_canonical_byte_length(
                circuit.profile().participant_count(),
                0,
                verification_key_field_element_count,
            )?;
        let mut payload_chunk_hash_absorbed_byte_length_per_sender = 0_u64;
        let mut payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender = 0_u64;
        let mut maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count = 0_u64;
        for chunk_index in 0..share_vector_chunk_count_per_sender {
            let query_byte_length =
                authenticated_key_share_vector_payload_chunk_preimage_byte_length(
                    verification_key_field_element_count,
                    chunk_index,
                )?;
            let permutation_count = checked_add(
                query_byte_length / SHAKE256_RATE_BYTE_LENGTH,
                checked_ceiling_divide(HASH512_OUTPUT_BYTE_LENGTH, SHAKE256_RATE_BYTE_LENGTH)?,
            )?;
            payload_chunk_hash_absorbed_byte_length_per_sender = checked_add(
                payload_chunk_hash_absorbed_byte_length_per_sender,
                query_byte_length,
            )?;
            payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender = checked_add(
                payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender,
                permutation_count,
            )?;
            maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count =
                maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count
                    .max(permutation_count);
        }
        let quorum_checked_share_payload_byte_length = checked_multiply(
            reconstruction_threshold,
            share_vector_byte_length_per_sender,
        )?;
        let quorum_checked_share_descriptor_byte_length = checked_multiply(
            reconstruction_threshold,
            share_vector_descriptor_byte_length_per_sender,
        )?;
        let quorum_checked_share_payload_and_descriptor_byte_length = checked_add(
            quorum_checked_share_payload_byte_length,
            quorum_checked_share_descriptor_byte_length,
        )?;
        let quorum_checked_share_manifest_byte_length =
            authenticated_key_share_vector_manifest_canonical_byte_length(
                circuit.profile().participant_count(),
                verification_key_field_element_count,
            )?;
        let acknowledgement_body_byte_length_per_participant =
            authenticated_key_share_vector_acknowledgement_canonical_byte_length(
                circuit.profile().participant_count(),
                0,
            )?;
        let mut all_roster_acknowledgement_body_byte_length = 0_u64;
        for participant_position in 0..circuit.profile().participant_count() {
            let acknowledgement_body_byte_length =
                authenticated_key_share_vector_acknowledgement_canonical_byte_length(
                    circuit.profile().participant_count(),
                    participant_position,
                )?;
            if acknowledgement_body_byte_length != acknowledgement_body_byte_length_per_participant
            {
                return Err(TallyPreparationError::GeometryMismatch);
            }
            all_roster_acknowledgement_body_byte_length = checked_add(
                all_roster_acknowledgement_body_byte_length,
                acknowledgement_body_byte_length,
            )?;
        }
        let quorum_checked_share_control_byte_length = checked_add(
            checked_add(
                quorum_checked_share_descriptor_byte_length,
                quorum_checked_share_manifest_byte_length,
            )?,
            all_roster_acknowledgement_body_byte_length,
        )?;
        let quorum_checked_share_payload_and_control_byte_length = checked_add(
            quorum_checked_share_payload_byte_length,
            quorum_checked_share_control_byte_length,
        )?;
        let all_roster_share_payload_byte_length =
            checked_multiply(participant_count, share_vector_byte_length_per_sender)?;
        let all_roster_share_descriptor_byte_length = checked_multiply(
            participant_count,
            share_vector_descriptor_byte_length_per_sender,
        )?;
        let all_roster_share_payload_and_descriptor_byte_length = checked_add(
            all_roster_share_payload_byte_length,
            all_roster_share_descriptor_byte_length,
        )?;
        let all_roster_share_manifest_byte_length =
            authenticated_key_share_vector_codeword_manifest_canonical_byte_length(
                circuit.profile().participant_count(),
                verification_key_field_element_count,
            )?;
        let all_roster_share_control_byte_length = checked_add(
            all_roster_share_descriptor_byte_length,
            all_roster_share_manifest_byte_length,
        )?;
        let all_roster_share_payload_and_control_byte_length = checked_add(
            all_roster_share_payload_byte_length,
            all_roster_share_control_byte_length,
        )?;

        Ok(Self {
            participant_count,
            reconstruction_threshold,
            holder_record_count: inventory.record_count(),
            verification_key_field_element_count,
            reconstructed_key_byte_length,
            share_vector_byte_length_per_sender,
            share_vector_chunk_count_per_sender,
            final_share_vector_chunk_byte_length,
            share_vector_descriptor_byte_length_per_sender,
            payload_chunk_hash_invocation_count_per_sender: share_vector_chunk_count_per_sender,
            payload_chunk_hash_absorbed_byte_length_per_sender,
            payload_chunk_hash_output_byte_length_per_sender: checked_multiply(
                share_vector_chunk_count_per_sender,
                HASH512_OUTPUT_BYTE_LENGTH,
            )?,
            payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender,
            maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count,
            quorum_checked_share_sender_count: reconstruction_threshold,
            quorum_checked_share_payload_byte_length,
            quorum_checked_share_descriptor_byte_length,
            quorum_checked_share_payload_and_descriptor_byte_length,
            quorum_checked_share_manifest_byte_length,
            acknowledgement_body_byte_length_per_participant,
            all_roster_acknowledgement_body_byte_length,
            quorum_checked_share_control_byte_length,
            quorum_checked_share_payload_and_control_byte_length,
            quorum_checked_additional_byte_length: checked_subtract(
                quorum_checked_share_payload_and_control_byte_length,
                reconstructed_key_byte_length,
            )?,
            all_roster_share_sender_count: participant_count,
            all_roster_share_payload_byte_length,
            all_roster_share_descriptor_byte_length,
            all_roster_share_payload_and_descriptor_byte_length,
            all_roster_share_manifest_byte_length,
            all_roster_share_control_byte_length,
            all_roster_share_payload_and_control_byte_length,
            all_roster_additional_byte_length: checked_subtract(
                all_roster_share_payload_and_control_byte_length,
                reconstructed_key_byte_length,
            )?,
        })
    }
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_subtract(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_sub(right)
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn checked_ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    (dividend / divisor)
        .checked_add(u64::from(!dividend.is_multiple_of(divisor)))
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
