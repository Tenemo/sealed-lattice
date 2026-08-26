use crate::foundation::derive_foundation_roster_parameters;
use subtle::ConstantTimeEq;

use super::{
    TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    pseudorandom_zero_sharing_field_stream_320::{
        PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH,
        pseudorandom_zero_sharing_field_chunk_count,
        pseudorandom_zero_sharing_field_elements_per_chunk,
    },
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH,
    },
    pseudorandom_zero_sharing_seed_catalog_320::PseudorandomZeroSharingSeedCatalogInclusionProof320,
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
        PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320,
    },
    pseudorandom_zero_sharing_seed_delivery_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_BODY_BYTE_LENGTH,
    },
    pseudorandom_zero_sharing_seed_mailbox_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        PseudorandomZeroSharingSeedMailboxError320, derive_mailbox_stream_geometry,
        pseudorandom_zero_sharing_seed_mailbox_control_and_tag_byte_length,
        pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length,
    },
    pseudorandom_zero_sharing_subset_seed_320::PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH,
    replicated_random_sharing::{ReplicatedRandomSharingGeometry, ReplicatedRandomSharingSubset},
};

/// Formula-only inputs for the subset-seeded zero-sharing candidate.
///
/// Canonical opening, catalog-proof, mailbox, and terminal widths come from
/// their unactivated codec owners. Signed recipient receipts remain a separate
/// public owner and are not included in this private-delivery model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingResourceInput {
    pub(crate) participant_count: u16,
    pub(crate) zero_sharing_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingResourceModel {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) authorized_subset_size: u64,
    pub(crate) authorized_subset_count: u64,
    pub(crate) authorized_subset_count_per_participant: u64,
    pub(crate) subset_seed_contribution_count: u64,
    pub(crate) remote_subset_seed_opening_delivery_count: u64,
    pub(crate) subset_seed_opening_object_byte_length: u64,
    pub(crate) private_subset_seed_opening_delivery_byte_length: u64,
    pub(crate) pair_seed_opening_delivery_count: u64,
    pub(crate) pair_seed_opening_object_byte_length: u64,
    pub(crate) private_pair_seed_opening_delivery_byte_length: u64,
    pub(crate) seed_catalog_inclusion_proof_delivery_count: u64,
    pub(crate) seed_catalog_inclusion_proof_byte_length: u64,
    pub(crate) private_seed_catalog_inclusion_proof_delivery_byte_length: u64,
    pub(crate) seed_delivery_descriptor_count: u64,
    pub(crate) seed_delivery_descriptor_body_byte_length: u64,
    pub(crate) private_seed_delivery_descriptor_byte_length: u64,
    pub(crate) seed_delivery_plaintext_byte_length_per_stream: u64,
    pub(crate) private_seed_delivery_plaintext_byte_length: u64,
    pub(crate) root_terminal_body_byte_length: u64,
    pub(crate) root_terminal_endorsement_count: u64,
    pub(crate) root_terminal_endorsement_authorization_body_byte_length: u64,
    pub(crate) root_terminal_endorsement_envelope_byte_length: u64,
    pub(crate) root_terminal_certificate_byte_length: u64,
    pub(crate) root_terminal_signature_verification_count: u64,
    pub(crate) ordered_mailbox_stream_count: u64,
    pub(crate) mailbox_chunk_count_per_stream: u64,
    pub(crate) mailbox_chunk_count: u64,
    pub(crate) mailbox_header_body_byte_length: u64,
    pub(crate) private_mailbox_header_byte_length: u64,
    pub(crate) mailbox_manifest_body_byte_length_per_stream: u64,
    pub(crate) private_mailbox_manifest_byte_length: u64,
    pub(crate) mailbox_signature_body_byte_length: u64,
    pub(crate) mailbox_signature_envelope_byte_length: u64,
    pub(crate) private_mailbox_signature_envelope_byte_length: u64,
    pub(crate) mailbox_authentication_tag_byte_length: u64,
    pub(crate) private_mailbox_authentication_tag_byte_length: u64,
    pub(crate) mailbox_control_and_tag_byte_length_per_stream: u64,
    pub(crate) private_mailbox_control_and_tag_byte_length: u64,
    pub(crate) authenticated_private_setup_delivery_byte_length: u64,
    pub(crate) seed_delivery_plaintext_upload_byte_length_per_participant: u64,
    pub(crate) authenticated_private_setup_upload_byte_length_per_participant: u64,
    pub(crate) authenticated_private_setup_download_byte_length_per_participant: u64,
    pub(crate) mailbox_encapsulation_count: u64,
    pub(crate) mailbox_decapsulation_count: u64,
    pub(crate) mailbox_sender_signature_generation_count: u64,
    pub(crate) mailbox_sender_signature_verification_count: u64,
    pub(crate) mailbox_authenticated_encryption_count: u64,
    pub(crate) mailbox_authenticated_decryption_count: u64,
    pub(crate) mailbox_chunk_digest_generation_count: u64,
    pub(crate) mailbox_chunk_digest_verification_count: u64,
    pub(crate) mailbox_sender_key_derivation_count: u64,
    pub(crate) mailbox_recipient_key_derivation_count: u64,
    pub(crate) mailbox_sender_nonce_derivation_count: u64,
    pub(crate) mailbox_recipient_nonce_derivation_count: u64,
    pub(crate) mailbox_recipient_key_identity_generation_count: u64,
    pub(crate) mailbox_recipient_key_identity_verification_count: u64,
    pub(crate) recipient_inventory_body_byte_length_per_participant: u64,
    pub(crate) combined_subset_seed_custody_byte_length_per_participant: u64,
    pub(crate) combined_pair_seed_custody_byte_length_per_participant: u64,
    pub(crate) collective_coin_source_custody_byte_length_per_participant: u64,
    pub(crate) retained_seed_custody_byte_length_per_participant: u64,
    pub(crate) subset_basis_stream_count_per_participant: u64,
    pub(crate) basis_weight_live_byte_length_per_participant: u64,
    pub(crate) basis_precomputation_field_multiplication_count_per_participant: u64,
    pub(crate) field_output_count_per_participant: u64,
    pub(crate) field_output_byte_length_per_participant: u64,
    pub(crate) full_chunk_field_count: u64,
    pub(crate) full_chunk_payload_byte_length: u64,
    pub(crate) field_output_chunk_count_per_participant: u64,
    pub(crate) final_chunk_field_count: u64,
    pub(crate) final_chunk_payload_byte_length: u64,
    pub(crate) stream_field_multiplication_count_per_participant: u64,
    pub(crate) stream_field_addition_count_per_participant: u64,
    pub(crate) zero_codeword_check_field_multiplication_count_per_participant: u64,
    pub(crate) zero_codeword_check_field_addition_count_per_participant: u64,
    pub(crate) zero_codeword_check_comparison_count_per_participant: u64,
    pub(crate) total_field_multiplication_floor_per_participant: u64,
}

impl PseudorandomZeroSharingResourceModel {
    pub(crate) fn derive(
        input: PseudorandomZeroSharingResourceInput,
    ) -> Result<Self, TallyPreparationError> {
        if input.zero_sharing_count == 0 {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let subset_seed_master_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let pair_seed_master_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let collective_coin_source_byte_length = u64::try_from(COLLECTIVE_COIN_SOURCE_BYTE_LENGTH)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let subset_seed_opening_object_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let pair_seed_opening_object_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let seed_catalog_inclusion_proof_byte_length = u64::try_from(
            PseudorandomZeroSharingSeedCatalogInclusionProof320::canonical_byte_length_for_participant_count(
                input.participant_count,
            )?,
        )
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let seed_delivery_descriptor_body_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_BODY_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let recipient_inventory_body_byte_length_per_participant =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_BODY_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mailbox_header_body_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mailbox_signature_body_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mailbox_signature_envelope_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mailbox_authentication_tag_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let root_terminal_body_byte_length =
            u64::try_from(PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let root_terminal_endorsement_authorization_body_byte_length = u64::try_from(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH,
        )
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let root_terminal_endorsement_envelope_byte_length = u64::try_from(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
        )
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let field_element_byte_length = u64::try_from(BinaryFieldElement320::CANONICAL_BYTE_LENGTH)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;

        let geometry = ReplicatedRandomSharingGeometry::derive(input.participant_count)?;
        if geometry.active_fault_bound == 0 {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let root_terminal_endorsement_count = geometry.participant_count;
        let root_terminal_certificate_byte_length = u64::try_from(
            PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320::canonical_byte_length_for_participant_count(
                input.participant_count,
            )
            .map_err(|_| TallyPreparationError::GeometryMismatch)?,
        )
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let root_terminal_signature_verification_count = root_terminal_endorsement_count;
        let subset_seed_contribution_count = checked_multiply(
            geometry.authorized_subset_count,
            geometry.authorized_subset_size,
        )?;
        let remote_recipient_count = geometry
            .authorized_subset_size
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let remote_subset_seed_opening_delivery_count =
            checked_multiply(subset_seed_contribution_count, remote_recipient_count)?;
        let private_subset_seed_opening_delivery_byte_length = checked_multiply(
            remote_subset_seed_opening_delivery_count,
            subset_seed_opening_object_byte_length,
        )?;
        let ordered_mailbox_stream_count = checked_multiply(
            geometry.participant_count,
            geometry
                .participant_count
                .checked_sub(1)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
        )?;
        let pair_seed_opening_delivery_count = ordered_mailbox_stream_count;
        let private_pair_seed_opening_delivery_byte_length = checked_multiply(
            pair_seed_opening_delivery_count,
            pair_seed_opening_object_byte_length,
        )?;
        let seed_catalog_inclusion_proof_delivery_count = checked_add(
            remote_subset_seed_opening_delivery_count,
            pair_seed_opening_delivery_count,
        )?;
        let private_seed_catalog_inclusion_proof_delivery_byte_length = checked_multiply(
            seed_catalog_inclusion_proof_delivery_count,
            seed_catalog_inclusion_proof_byte_length,
        )?;
        let seed_delivery_descriptor_count = ordered_mailbox_stream_count;
        let private_seed_delivery_descriptor_byte_length = checked_multiply(
            seed_delivery_descriptor_count,
            seed_delivery_descriptor_body_byte_length,
        )?;
        let private_seed_delivery_plaintext_byte_length = checked_sum(&[
            private_subset_seed_opening_delivery_byte_length,
            private_pair_seed_opening_delivery_byte_length,
            private_seed_catalog_inclusion_proof_delivery_byte_length,
        ])?;
        let seed_delivery_plaintext_byte_length_per_stream = checked_divide_exact(
            private_seed_delivery_plaintext_byte_length,
            ordered_mailbox_stream_count,
        )?;
        let (mailbox_chunk_count_per_stream, _) =
            derive_mailbox_stream_geometry(seed_delivery_plaintext_byte_length_per_stream)
                .map_err(map_mailbox_resource_error)?;
        let mailbox_chunk_count =
            checked_multiply(ordered_mailbox_stream_count, mailbox_chunk_count_per_stream)?;
        let private_mailbox_header_byte_length = checked_multiply(
            ordered_mailbox_stream_count,
            mailbox_header_body_byte_length,
        )?;
        let mailbox_manifest_body_byte_length_per_stream = u64::try_from(
            pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length(
                mailbox_chunk_count_per_stream,
            )
            .map_err(map_mailbox_resource_error)?,
        )
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let private_mailbox_manifest_byte_length = checked_multiply(
            ordered_mailbox_stream_count,
            mailbox_manifest_body_byte_length_per_stream,
        )?;
        let private_mailbox_signature_envelope_byte_length = checked_multiply(
            ordered_mailbox_stream_count,
            mailbox_signature_envelope_byte_length,
        )?;
        let private_mailbox_authentication_tag_byte_length =
            checked_multiply(mailbox_chunk_count, mailbox_authentication_tag_byte_length)?;
        let mailbox_control_and_tag_byte_length_per_stream =
            pseudorandom_zero_sharing_seed_mailbox_control_and_tag_byte_length(
                mailbox_chunk_count_per_stream,
            )
            .map_err(map_mailbox_resource_error)?;
        let private_mailbox_control_and_tag_byte_length = checked_multiply(
            ordered_mailbox_stream_count,
            mailbox_control_and_tag_byte_length_per_stream,
        )?;
        if private_mailbox_control_and_tag_byte_length
            != checked_sum(&[
                private_mailbox_header_byte_length,
                private_mailbox_manifest_byte_length,
                private_mailbox_signature_envelope_byte_length,
                private_mailbox_authentication_tag_byte_length,
            ])?
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let authenticated_private_setup_delivery_byte_length = checked_add(
            private_seed_delivery_plaintext_byte_length,
            private_mailbox_control_and_tag_byte_length,
        )?;

        let remote_subset_seed_opening_delivery_count_per_participant = checked_multiply(
            geometry.authorized_subset_count_per_participant,
            remote_recipient_count,
        )?;
        let subset_seed_opening_delivery_byte_length_per_participant = checked_multiply(
            remote_subset_seed_opening_delivery_count_per_participant,
            subset_seed_opening_object_byte_length,
        )?;
        let ordered_mailbox_stream_count_per_participant = geometry
            .participant_count
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let pair_seed_opening_delivery_byte_length_per_participant = checked_multiply(
            ordered_mailbox_stream_count_per_participant,
            pair_seed_opening_object_byte_length,
        )?;
        let seed_catalog_inclusion_proof_count_per_participant = checked_add(
            remote_subset_seed_opening_delivery_count_per_participant,
            ordered_mailbox_stream_count_per_participant,
        )?;
        let seed_catalog_inclusion_proof_delivery_byte_length_per_participant = checked_multiply(
            seed_catalog_inclusion_proof_count_per_participant,
            seed_catalog_inclusion_proof_byte_length,
        )?;
        let seed_delivery_descriptor_byte_length_per_participant = checked_multiply(
            ordered_mailbox_stream_count_per_participant,
            seed_delivery_descriptor_body_byte_length,
        )?;
        let seed_delivery_plaintext_upload_byte_length_per_participant = checked_sum(&[
            subset_seed_opening_delivery_byte_length_per_participant,
            pair_seed_opening_delivery_byte_length_per_participant,
            seed_catalog_inclusion_proof_delivery_byte_length_per_participant,
        ])?;
        if checked_multiply(
            seed_delivery_plaintext_upload_byte_length_per_participant,
            geometry.participant_count,
        )? != private_seed_delivery_plaintext_byte_length
            || checked_multiply(
                seed_delivery_descriptor_byte_length_per_participant,
                geometry.participant_count,
            )? != private_seed_delivery_descriptor_byte_length
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let mailbox_control_and_tag_byte_length_per_participant = checked_multiply(
            ordered_mailbox_stream_count_per_participant,
            mailbox_control_and_tag_byte_length_per_stream,
        )?;
        let authenticated_private_setup_upload_byte_length_per_participant = checked_add(
            seed_delivery_plaintext_upload_byte_length_per_participant,
            mailbox_control_and_tag_byte_length_per_participant,
        )?;
        if checked_multiply(
            authenticated_private_setup_upload_byte_length_per_participant,
            geometry.participant_count,
        )? != authenticated_private_setup_delivery_byte_length
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let authenticated_private_setup_download_byte_length_per_participant =
            authenticated_private_setup_upload_byte_length_per_participant;

        let mailbox_encapsulation_count = ordered_mailbox_stream_count;
        let mailbox_decapsulation_count = ordered_mailbox_stream_count;
        let mailbox_sender_signature_generation_count = ordered_mailbox_stream_count;
        let mailbox_sender_signature_verification_count = ordered_mailbox_stream_count;
        let mailbox_authenticated_encryption_count = mailbox_chunk_count;
        let mailbox_authenticated_decryption_count = mailbox_chunk_count;
        let mailbox_chunk_digest_generation_count = mailbox_chunk_count;
        let mailbox_chunk_digest_verification_count = mailbox_chunk_count;
        let mailbox_sender_key_derivation_count = ordered_mailbox_stream_count;
        let mailbox_recipient_key_derivation_count = ordered_mailbox_stream_count;
        let mailbox_sender_nonce_derivation_count = mailbox_chunk_count;
        let mailbox_recipient_nonce_derivation_count = mailbox_chunk_count;
        let mailbox_recipient_key_identity_generation_count = ordered_mailbox_stream_count;
        let mailbox_recipient_key_identity_verification_count = ordered_mailbox_stream_count;

        let combined_subset_seed_custody_byte_length_per_participant = checked_multiply(
            geometry.authorized_subset_count_per_participant,
            subset_seed_master_byte_length,
        )?;
        let combined_pair_seed_custody_byte_length_per_participant = checked_multiply(
            ordered_mailbox_stream_count_per_participant,
            pair_seed_master_byte_length,
        )?;
        let collective_coin_source_custody_byte_length_per_participant =
            collective_coin_source_byte_length;
        let retained_seed_custody_byte_length_per_participant = checked_sum(&[
            combined_subset_seed_custody_byte_length_per_participant,
            combined_pair_seed_custody_byte_length_per_participant,
            collective_coin_source_custody_byte_length_per_participant,
        ])?;
        let subset_basis_stream_count_per_participant = checked_multiply(
            geometry.authorized_subset_count_per_participant,
            geometry.active_fault_bound,
        )?;
        let basis_weight_live_byte_length_per_participant = checked_multiply(
            subset_basis_stream_count_per_participant,
            field_element_byte_length,
        )?;
        let basis_multiplications_per_subset = checked_add(
            geometry.active_fault_bound,
            geometry
                .active_fault_bound
                .checked_sub(1)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
        )?;
        let basis_precomputation_field_multiplication_count_per_participant = checked_multiply(
            geometry.authorized_subset_count_per_participant,
            basis_multiplications_per_subset,
        )?;

        let field_output_count_per_participant = checked_multiply(
            input.zero_sharing_count,
            subset_basis_stream_count_per_participant,
        )?;
        let field_output_byte_length_per_participant = checked_multiply(
            field_output_count_per_participant,
            field_element_byte_length,
        )?;
        let full_chunk_field_count = pseudorandom_zero_sharing_field_elements_per_chunk()?;
        let full_chunk_payload_byte_length =
            checked_multiply(full_chunk_field_count, field_element_byte_length)?;
        let chunk_count_per_subset_basis_stream =
            pseudorandom_zero_sharing_field_chunk_count(input.zero_sharing_count)?;
        let field_output_chunk_count_per_participant = checked_multiply(
            subset_basis_stream_count_per_participant,
            chunk_count_per_subset_basis_stream,
        )?;
        let preceding_full_chunk_count_per_stream = chunk_count_per_subset_basis_stream
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let final_chunk_field_count = input
            .zero_sharing_count
            .checked_sub(checked_multiply(
                preceding_full_chunk_count_per_stream,
                full_chunk_field_count,
            )?)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let final_chunk_payload_byte_length =
            checked_multiply(final_chunk_field_count, field_element_byte_length)?;

        let stream_field_multiplication_count_per_participant = field_output_count_per_participant;
        let stream_field_addition_count_per_participant = field_output_count_per_participant
            .checked_sub(input.zero_sharing_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;

        let zero_codeword_basis_point_count =
            checked_add(checked_multiply(geometry.active_fault_bound, 2)?, 1)?;
        let zero_codeword_interpolation_target_count = checked_add(
            geometry
                .participant_count
                .checked_sub(zero_codeword_basis_point_count)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
            1,
        )?;
        let zero_codeword_check_field_multiplication_count_per_participant = checked_product(&[
            input.zero_sharing_count,
            zero_codeword_interpolation_target_count,
            zero_codeword_basis_point_count,
        ])?;
        let zero_codeword_check_field_addition_count_per_participant = checked_product(&[
            input.zero_sharing_count,
            zero_codeword_interpolation_target_count,
            zero_codeword_basis_point_count
                .checked_sub(1)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
        ])?;
        let zero_codeword_check_comparison_count_per_participant = checked_multiply(
            input.zero_sharing_count,
            zero_codeword_interpolation_target_count,
        )?;
        let total_field_multiplication_floor_per_participant = checked_sum(&[
            basis_precomputation_field_multiplication_count_per_participant,
            stream_field_multiplication_count_per_participant,
            zero_codeword_check_field_multiplication_count_per_participant,
        ])?;

        Ok(Self {
            participant_count: geometry.participant_count,
            active_fault_bound: geometry.active_fault_bound,
            authorized_subset_size: geometry.authorized_subset_size,
            authorized_subset_count: geometry.authorized_subset_count,
            authorized_subset_count_per_participant: geometry
                .authorized_subset_count_per_participant,
            subset_seed_contribution_count,
            remote_subset_seed_opening_delivery_count,
            subset_seed_opening_object_byte_length,
            private_subset_seed_opening_delivery_byte_length,
            pair_seed_opening_delivery_count,
            pair_seed_opening_object_byte_length,
            private_pair_seed_opening_delivery_byte_length,
            seed_catalog_inclusion_proof_delivery_count,
            seed_catalog_inclusion_proof_byte_length,
            private_seed_catalog_inclusion_proof_delivery_byte_length,
            seed_delivery_descriptor_count,
            seed_delivery_descriptor_body_byte_length,
            private_seed_delivery_descriptor_byte_length,
            seed_delivery_plaintext_byte_length_per_stream,
            private_seed_delivery_plaintext_byte_length,
            root_terminal_body_byte_length,
            root_terminal_endorsement_count,
            root_terminal_endorsement_authorization_body_byte_length,
            root_terminal_endorsement_envelope_byte_length,
            root_terminal_certificate_byte_length,
            root_terminal_signature_verification_count,
            ordered_mailbox_stream_count,
            mailbox_chunk_count_per_stream,
            mailbox_chunk_count,
            mailbox_header_body_byte_length,
            private_mailbox_header_byte_length,
            mailbox_manifest_body_byte_length_per_stream,
            private_mailbox_manifest_byte_length,
            mailbox_signature_body_byte_length,
            mailbox_signature_envelope_byte_length,
            private_mailbox_signature_envelope_byte_length,
            mailbox_authentication_tag_byte_length,
            private_mailbox_authentication_tag_byte_length,
            mailbox_control_and_tag_byte_length_per_stream,
            private_mailbox_control_and_tag_byte_length,
            authenticated_private_setup_delivery_byte_length,
            seed_delivery_plaintext_upload_byte_length_per_participant,
            authenticated_private_setup_upload_byte_length_per_participant,
            authenticated_private_setup_download_byte_length_per_participant,
            mailbox_encapsulation_count,
            mailbox_decapsulation_count,
            mailbox_sender_signature_generation_count,
            mailbox_sender_signature_verification_count,
            mailbox_authenticated_encryption_count,
            mailbox_authenticated_decryption_count,
            mailbox_chunk_digest_generation_count,
            mailbox_chunk_digest_verification_count,
            mailbox_sender_key_derivation_count,
            mailbox_recipient_key_derivation_count,
            mailbox_sender_nonce_derivation_count,
            mailbox_recipient_nonce_derivation_count,
            mailbox_recipient_key_identity_generation_count,
            mailbox_recipient_key_identity_verification_count,
            recipient_inventory_body_byte_length_per_participant,
            combined_subset_seed_custody_byte_length_per_participant,
            combined_pair_seed_custody_byte_length_per_participant,
            collective_coin_source_custody_byte_length_per_participant,
            retained_seed_custody_byte_length_per_participant,
            subset_basis_stream_count_per_participant,
            basis_weight_live_byte_length_per_participant,
            basis_precomputation_field_multiplication_count_per_participant,
            field_output_count_per_participant,
            field_output_byte_length_per_participant,
            full_chunk_field_count,
            full_chunk_payload_byte_length,
            field_output_chunk_count_per_participant,
            final_chunk_field_count,
            final_chunk_payload_byte_length,
            stream_field_multiplication_count_per_participant,
            stream_field_addition_count_per_participant,
            zero_codeword_check_field_multiplication_count_per_participant,
            zero_codeword_check_field_addition_count_per_participant,
            zero_codeword_check_comparison_count_per_participant,
            total_field_multiplication_floor_per_participant,
        })
    }
}

/// Checks the all-roster degree-`2t` codeword and its zero constant term.
///
/// The first `2t + 1` canonical roster points determine the polynomial. The
/// checker verifies its value at zero and every remaining roster point. It
/// authenticates no source, root, receipt, state transition, or release and
/// cannot mint a protocol capability.
#[derive(Debug, Clone)]
pub(crate) struct CanonicalZeroSharingCodewordVerifier320 {
    participant_count: u16,
    basis_point_count: usize,
    constant_term_coefficients: Box<[BinaryFieldElement320]>,
    nonbasis_point_coefficients: Box<[Box<[BinaryFieldElement320]>]>,
}

impl CanonicalZeroSharingCodewordVerifier320 {
    pub(crate) fn new(participant_count: u16) -> Result<Self, TallyPreparationError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let basis_point_count = usize::from(roster_parameters.active_fault_bound)
            .checked_mul(2)
            .and_then(|degree| degree.checked_add(1))
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        if basis_point_count >= usize::from(participant_count) {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let basis_points = (0..basis_point_count)
            .map(|roster_position| {
                canonical_evaluation_point_320(
                    participant_count,
                    u16::try_from(roster_position)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let inverse_denominators = basis_points
            .iter()
            .enumerate()
            .map(|(selected_position, selected_point)| {
                basis_points
                    .iter()
                    .enumerate()
                    .filter(|(other_position, _)| *other_position != selected_position)
                    .map(|(_, other_point)| selected_point.add(*other_point))
                    .fold(BinaryFieldElement320::ONE, |product, factor| {
                        product.multiply(factor)
                    })
                    .multiplicative_inverse()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let constant_term_coefficients = interpolation_coefficients(
            &basis_points,
            &inverse_denominators,
            BinaryFieldElement320::ZERO,
        );
        let nonbasis_point_coefficients = (basis_point_count..usize::from(participant_count))
            .map(|roster_position| {
                Ok(interpolation_coefficients(
                    &basis_points,
                    &inverse_denominators,
                    canonical_evaluation_point_320(
                        participant_count,
                        u16::try_from(roster_position)
                            .map_err(|_| TallyPreparationError::IntegerConversion)?,
                    )?,
                )
                .into_boxed_slice())
            })
            .collect::<Result<Vec<_>, TallyPreparationError>>()?;

        Ok(Self {
            participant_count,
            basis_point_count,
            constant_term_coefficients: constant_term_coefficients.into_boxed_slice(),
            nonbasis_point_coefficients: nonbasis_point_coefficients.into_boxed_slice(),
        })
    }

    pub(crate) fn verify(
        &self,
        values: &[BinaryFieldElement320],
    ) -> Result<bool, TallyPreparationError> {
        if values.len() != usize::from(self.participant_count) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let basis_values = &values[..self.basis_point_count];
        let mut validity = interpolate_values(basis_values, &self.constant_term_coefficients)
            .ct_eq(&BinaryFieldElement320::ZERO);
        for (nonbasis_offset, coefficients) in self.nonbasis_point_coefficients.iter().enumerate() {
            let expected_value = interpolate_values(basis_values, coefficients);
            validity &= values[self.basis_point_count + nonbasis_offset].ct_eq(&expected_value);
        }
        Ok(bool::from(validity))
    }
}

pub(crate) fn evaluate_pseudorandom_zero_sharing_subset_at_point(
    subset: ReplicatedRandomSharingSubset,
    pseudorandom_components: &[BinaryFieldElement320],
    evaluation_point: BinaryFieldElement320,
) -> Result<BinaryFieldElement320, TallyPreparationError> {
    if pseudorandom_components.len() != usize::from(subset.active_fault_bound()) {
        return Err(TallyPreparationError::GeometryMismatch);
    }

    let mut current_basis_value = evaluation_point;
    for excluded_position in subset.excluded_positions() {
        current_basis_value = current_basis_value.multiply(evaluation_point.add(
            canonical_evaluation_point_320(subset.participant_count(), excluded_position)?,
        ));
    }

    let mut evaluated_value = BinaryFieldElement320::ZERO;
    for (component_position, component) in pseudorandom_components.iter().copied().enumerate() {
        evaluated_value = evaluated_value.add(component.multiply(current_basis_value));
        if component_position + 1 < pseudorandom_components.len() {
            current_basis_value = current_basis_value.multiply(evaluation_point);
        }
    }
    Ok(evaluated_value)
}

pub(crate) fn canonical_evaluation_point_320(
    participant_count: u16,
    roster_position: u16,
) -> Result<BinaryFieldElement320, TallyPreparationError> {
    derive_foundation_roster_parameters(participant_count)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    if roster_position >= participant_count {
        return Err(TallyPreparationError::RosterPositionOutOfRange {
            roster_position,
            participant_count,
        });
    }
    let point_value = roster_position
        .checked_add(1)
        .ok_or(TallyPreparationError::ArithmeticOverflow)?;
    Ok(BinaryFieldElement320::from_low_polynomial_u16(point_value))
}

fn interpolation_coefficients(
    basis_points: &[BinaryFieldElement320],
    inverse_denominators: &[BinaryFieldElement320],
    evaluation_point: BinaryFieldElement320,
) -> Vec<BinaryFieldElement320> {
    basis_points
        .iter()
        .enumerate()
        .map(|(selected_position, _)| {
            basis_points
                .iter()
                .enumerate()
                .filter(|(other_position, _)| *other_position != selected_position)
                .map(|(_, other_point)| evaluation_point.add(*other_point))
                .fold(BinaryFieldElement320::ONE, |product, factor| {
                    product.multiply(factor)
                })
                .multiply(inverse_denominators[selected_position])
        })
        .collect()
}

fn interpolate_values(
    values: &[BinaryFieldElement320],
    coefficients: &[BinaryFieldElement320],
) -> BinaryFieldElement320 {
    values
        .iter()
        .copied()
        .zip(coefficients.iter().copied())
        .fold(BinaryFieldElement320::ZERO, |sum, (value, coefficient)| {
            sum.add(value.multiply(coefficient))
        })
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_divide_exact(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    let quotient = dividend
        .checked_div(divisor)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    if checked_multiply(quotient, divisor)? != dividend {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    Ok(quotient)
}

fn map_mailbox_resource_error(
    error: PseudorandomZeroSharingSeedMailboxError320,
) -> TallyPreparationError {
    match error {
        PseudorandomZeroSharingSeedMailboxError320::ArithmeticOverflow => {
            TallyPreparationError::ArithmeticOverflow
        }
        PseudorandomZeroSharingSeedMailboxError320::IntegerConversion => {
            TallyPreparationError::IntegerConversion
        }
        _ => TallyPreparationError::GeometryMismatch,
    }
}

fn checked_product(values: &[u64]) -> Result<u64, TallyPreparationError> {
    values
        .iter()
        .try_fold(1_u64, |product, value| checked_multiply(product, *value))
}

fn checked_sum(values: &[u64]) -> Result<u64, TallyPreparationError> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, *value))
}
