use crate::foundation::Hash512;

#[cfg(test)]
use crate::tally_circuit::CompiledTallyCircuit;

use super::{
    TallyPreparationContext, TallyPreparationError,
    replicated_key_ceremony::{
        REPLICATED_KEY_COMPONENT_BYTE_LENGTH, create_replicated_key_component,
        replicated_key_commitment_manifest_canonical_byte_length, replicated_key_component_slots,
        replicated_key_delivery_acknowledgement_canonical_byte_length,
    },
    replicated_random_sharing::ReplicatedRandomSharingGeometry,
};

const ACKNOWLEDGEMENT_ROOT_BYTE_LENGTH: u64 = Hash512::BYTE_LENGTH as u64;

/// Exact canonical core bytes emitted by the unactivated replicated-key
/// ceremony model.
///
/// The model invokes the production artifact generators for every canonical
/// component slot. It counts each private component opening once for every
/// remote authorized recipient. It excludes signatures, authenticated-mailbox
/// envelopes and encryption expansion, transition wrappers, indexes, transport
/// roots outside the modeled manifest and acknowledgement root, retransmission,
/// checkpoints, allocator overlap, and storage amplification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedKeyCeremonyResourceModel {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) authorized_subset_size: u64,
    pub(crate) key_count: u64,
    pub(crate) key_count_per_participant: u64,
    pub(crate) component_commitment_count: u64,
    pub(crate) unique_component_opening_count: u64,
    pub(crate) private_component_delivery_count: u64,
    pub(crate) raw_component_byte_length: u64,
    pub(crate) raw_private_component_delivery_byte_length: u64,
    pub(crate) component_commitment_canonical_byte_length: u64,
    pub(crate) unique_component_opening_canonical_byte_length: u64,
    pub(crate) private_delivery_plaintext_byte_length: u64,
    pub(crate) commitment_manifest_canonical_byte_length: u64,
    pub(crate) delivery_acknowledgement_count: u64,
    pub(crate) delivery_acknowledgement_canonical_byte_length: u64,
    pub(crate) acknowledgement_root_byte_length: u64,
    pub(crate) public_core_byte_length: u64,
    pub(crate) maximum_public_commitment_upload_byte_length_per_participant: u64,
    pub(crate) maximum_private_delivery_plaintext_upload_byte_length_per_participant: u64,
    pub(crate) maximum_private_delivery_plaintext_download_byte_length_per_participant: u64,
    pub(crate) maximum_component_custody_byte_length_per_participant: u64,
    pub(crate) combined_key_persistent_byte_length_per_participant: u64,
}

impl ReplicatedKeyCeremonyResourceModel {
    pub(crate) fn derive(context: TallyPreparationContext) -> Result<Self, TallyPreparationError> {
        let geometry = ReplicatedRandomSharingGeometry::derive(context.participant_count())?;
        let participant_count = geometry.participant_count;
        let participant_count_usize = usize::try_from(participant_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let component_commitment_count = geometry.all_member_contribution_count;
        let mut component_commitment_canonical_byte_length = 0_u64;
        let mut unique_component_opening_canonical_byte_length = 0_u64;
        let mut private_delivery_plaintext_byte_length = 0_u64;
        let mut public_uploads = vec![0_u64; participant_count_usize];
        let mut private_uploads = vec![0_u64; participant_count_usize];
        let mut private_downloads = vec![0_u64; participant_count_usize];
        let mut own_component_opening_bytes = vec![0_u64; participant_count_usize];
        let mut observed_component_commitment_count = 0_u64;
        let mut observed_private_delivery_count = 0_u64;

        for (coordinate, contributor_position) in replicated_key_component_slots(context)? {
            observed_component_commitment_count =
                checked_add(observed_component_commitment_count, 1)?;
            let (commitment, opening) = create_replicated_key_component(
                coordinate,
                contributor_position,
                [0_u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH],
            )?;
            let commitment_byte_length = usize_to_u64(commitment.canonical_bytes().len())?;
            let opening_byte_length = usize_to_u64(opening.canonical_bytes().len())?;
            component_commitment_canonical_byte_length = checked_add(
                component_commitment_canonical_byte_length,
                commitment_byte_length,
            )?;
            unique_component_opening_canonical_byte_length = checked_add(
                unique_component_opening_canonical_byte_length,
                opening_byte_length,
            )?;
            let contributor_index = usize::from(contributor_position);
            public_uploads[contributor_index] =
                checked_add(public_uploads[contributor_index], commitment_byte_length)?;
            own_component_opening_bytes[contributor_index] = checked_add(
                own_component_opening_bytes[contributor_index],
                opening_byte_length,
            )?;

            for recipient_position in coordinate.member_positions()? {
                if recipient_position == contributor_position {
                    continue;
                }
                private_delivery_plaintext_byte_length =
                    checked_add(private_delivery_plaintext_byte_length, opening_byte_length)?;
                private_uploads[contributor_index] =
                    checked_add(private_uploads[contributor_index], opening_byte_length)?;
                let recipient_index = usize::from(recipient_position);
                private_downloads[recipient_index] =
                    checked_add(private_downloads[recipient_index], opening_byte_length)?;
                observed_private_delivery_count = checked_add(observed_private_delivery_count, 1)?;
            }
        }
        if observed_component_commitment_count != component_commitment_count
            || observed_private_delivery_count != geometry.remote_key_component_delivery_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let commitment_manifest_canonical_byte_length =
            replicated_key_commitment_manifest_canonical_byte_length(context)?;
        let delivery_acknowledgement_canonical_byte_length = (0..context.participant_count())
            .try_fold(0_u64, |byte_length, recipient_position| {
                checked_add(
                    byte_length,
                    replicated_key_delivery_acknowledgement_canonical_byte_length(
                        context,
                        recipient_position,
                    )?,
                )
            })?;
        let public_core_byte_length = checked_sum(&[
            component_commitment_canonical_byte_length,
            commitment_manifest_canonical_byte_length,
            delivery_acknowledgement_canonical_byte_length,
            ACKNOWLEDGEMENT_ROOT_BYTE_LENGTH,
        ])?;
        let maximum_component_custody_byte_length_per_participant = own_component_opening_bytes
            .iter()
            .zip(&private_downloads)
            .try_fold(0_u64, |maximum_byte_length, (own_bytes, remote_bytes)| {
                Ok::<u64, TallyPreparationError>(
                    maximum_byte_length.max(checked_add(*own_bytes, *remote_bytes)?),
                )
            })?;

        Ok(Self {
            participant_count,
            active_fault_bound: geometry.active_fault_bound,
            authorized_subset_size: geometry.authorized_subset_size,
            key_count: geometry.total_key_count,
            key_count_per_participant: geometry.key_count_per_participant,
            component_commitment_count,
            unique_component_opening_count: component_commitment_count,
            private_component_delivery_count: geometry.remote_key_component_delivery_count,
            raw_component_byte_length: checked_multiply(
                component_commitment_count,
                usize_to_u64(REPLICATED_KEY_COMPONENT_BYTE_LENGTH)?,
            )?,
            raw_private_component_delivery_byte_length: geometry.remote_key_component_byte_length,
            component_commitment_canonical_byte_length,
            unique_component_opening_canonical_byte_length,
            private_delivery_plaintext_byte_length,
            commitment_manifest_canonical_byte_length,
            delivery_acknowledgement_count: participant_count,
            delivery_acknowledgement_canonical_byte_length,
            acknowledgement_root_byte_length: ACKNOWLEDGEMENT_ROOT_BYTE_LENGTH,
            public_core_byte_length,
            maximum_public_commitment_upload_byte_length_per_participant: maximum(&public_uploads)?,
            maximum_private_delivery_plaintext_upload_byte_length_per_participant: maximum(
                &private_uploads,
            )?,
            maximum_private_delivery_plaintext_download_byte_length_per_participant: maximum(
                &private_downloads,
            )?,
            maximum_component_custody_byte_length_per_participant,
            combined_key_persistent_byte_length_per_participant: checked_multiply(
                geometry.key_count_per_participant,
                geometry.key_byte_length,
            )?,
        })
    }

    #[cfg(test)]
    pub(crate) fn derive_for_circuit(
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        let context = TallyPreparationContext::new(
            Hash512::from_bytes([0_u8; 64]),
            Hash512::from_bytes([0_u8; 64]),
            [0_u8; 32],
            circuit,
        )?;
        Self::derive(context)
    }
}

fn maximum(values: &[u64]) -> Result<u64, TallyPreparationError> {
    values
        .iter()
        .copied()
        .max()
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn usize_to_u64(value: usize) -> Result<u64, TallyPreparationError> {
    u64::try_from(value).map_err(|_| TallyPreparationError::IntegerConversion)
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
