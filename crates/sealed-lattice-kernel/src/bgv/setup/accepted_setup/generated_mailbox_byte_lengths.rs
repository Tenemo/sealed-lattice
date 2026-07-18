use crate::{
    bgv::proof_suite::{
        require_verified_recipient_vss_mailbox_envelope,
        require_verified_vss_dealer_terminals_match_public_randomness,
        selected_recipient_private_vss_payload_byte_length,
    },
    foundation::{FOUNDATION_PROFILE, Hash512, RefusalReason},
};

use super::{
    VerifiedPublicRandomness, VerifiedSetupVerificationContext, VerifiedVssQualificationTerminals,
    VerifiedVssShareLinkageTerminal,
};

/// Borrowed generated envelope carriers in canonical dealer-major, then
/// recipient-major order. Positions are supplied by the fixed roster order,
/// not by redundant transport metadata.
pub(in crate::bgv) struct GeneratedPrivateVssMailboxCorpusInput<'input> {
    ordered_canonical_signed_envelope_bytes: &'input [&'input [u8]],
}

impl<'input> GeneratedPrivateVssMailboxCorpusInput<'input> {
    pub(in crate::bgv) const fn new(
        ordered_canonical_signed_envelope_bytes: &'input [&'input [u8]],
    ) -> Self {
        Self {
            ordered_canonical_signed_envelope_bytes,
        }
    }
}

/// Exact generated lengths for one recipient-private mailbox stream and its
/// signed canonical envelope. The stream descriptor is a subdivision of the
/// envelope and is not added to the corpus a second time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv) struct VerifiedGeneratedPrivateVssMailboxByteLengths {
    ciphertext_stream_byte_length: u64,
    ciphertext_descriptor_byte_length: u64,
    canonical_signed_envelope_byte_length: u64,
    complete_recipient_private_wire_byte_length: u64,
}

impl VerifiedGeneratedPrivateVssMailboxByteLengths {
    pub(in crate::bgv) const fn ciphertext_stream_byte_length(self) -> u64 {
        self.ciphertext_stream_byte_length
    }

    pub(in crate::bgv) const fn ciphertext_descriptor_byte_length(self) -> u64 {
        self.ciphertext_descriptor_byte_length
    }

    pub(in crate::bgv) const fn canonical_signed_envelope_byte_length(self) -> u64 {
        self.canonical_signed_envelope_byte_length
    }

    pub(in crate::bgv) const fn complete_recipient_private_wire_byte_length(self) -> u64 {
        self.complete_recipient_private_wire_byte_length
    }
}

/// Opaque runtime accounting authority for the generated recipient-private
/// VSS mailbox corpus. It is constructed while the verified dealer terminals
/// still retain the exact envelope-hash matrix, then remains joined to the
/// compact qualification terminal through its canonical context and ordered
/// dealer object hashes. It is development accounting only and is never
/// serialized or accepted as a substitute for mailbox authentication.
pub(in crate::bgv) struct VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog {
    context: VerifiedSetupVerificationContext,
    public_setup_seed: Hash512,
    setup_proof_context_hash: Hash512,
    ordered_dealer_public_record_object_hashes: Box<[Hash512]>,
    ordered_envelope_hashes: Box<[Hash512]>,
    ordered_mailbox_byte_lengths: Box<[VerifiedGeneratedPrivateVssMailboxByteLengths]>,
    ordered_dealer_upload_byte_lengths: Box<[u64]>,
    ordered_recipient_download_byte_lengths: Box<[u64]>,
    ciphertext_stream_byte_length: u64,
    canonical_signed_envelope_byte_length: u64,
    complete_recipient_private_wire_byte_length: u64,
    maximum_ciphertext_descriptor_byte_length: u64,
    maximum_canonical_signed_envelope_byte_length: u64,
}

impl VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog {
    pub(in crate::bgv) fn from_verified_dealer_terminals(
        verified_public_randomness: &VerifiedPublicRandomness,
        ordered_dealer_terminals: &[VerifiedVssShareLinkageTerminal],
        generated_corpus: GeneratedPrivateVssMailboxCorpusInput<'_>,
    ) -> Result<Self, RefusalReason> {
        require_verified_vss_dealer_terminals_match_public_randomness(
            verified_public_randomness,
            ordered_dealer_terminals,
        )?;
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let mailbox_count = participant_count
            .checked_mul(participant_count)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if generated_corpus
            .ordered_canonical_signed_envelope_bytes
            .len()
            != mailbox_count
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let recipient_private_payload_byte_length =
            selected_recipient_private_vss_payload_byte_length()
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let recipient_private_payload_byte_length_usize =
            usize::try_from(recipient_private_payload_byte_length)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;

        let mut ordered_dealer_public_record_object_hashes = Vec::with_capacity(participant_count);
        let mut ordered_envelope_hashes = Vec::with_capacity(mailbox_count);
        let mut ordered_mailbox_byte_lengths = Vec::with_capacity(mailbox_count);
        let mut ordered_dealer_upload_byte_lengths = vec![0_u64; participant_count];
        let mut ordered_recipient_download_byte_lengths = vec![0_u64; participant_count];
        let mut ciphertext_stream_byte_length = 0_u64;
        let mut canonical_signed_envelope_byte_length = 0_u64;
        let mut maximum_ciphertext_descriptor_byte_length = 0_u64;
        let mut maximum_canonical_signed_envelope_byte_length = 0_u64;

        for (dealer_roster_position, dealer_terminal) in ordered_dealer_terminals.iter().enumerate()
        {
            ordered_dealer_public_record_object_hashes
                .push(Hash512::from_bytes(dealer_terminal.board_object_hash()));
            for recipient_roster_position in 0..participant_count {
                let mailbox_ordinal = dealer_roster_position
                    .checked_mul(participant_count)
                    .and_then(|offset| offset.checked_add(recipient_roster_position))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                let recipient_identity = *verified_public_randomness
                    .ordered_participant_identities()
                    .get(recipient_roster_position)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                let canonical_signed_envelope_bytes = generated_corpus
                    .ordered_canonical_signed_envelope_bytes
                    .get(mailbox_ordinal)
                    .copied()
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                let envelope = require_verified_recipient_vss_mailbox_envelope(
                    verified_public_randomness,
                    dealer_terminal,
                    recipient_identity,
                    u16::try_from(recipient_roster_position)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    canonical_signed_envelope_bytes,
                    recipient_private_payload_byte_length_usize,
                )?;
                let ciphertext_stream_byte_length_for_mailbox =
                    envelope.ciphertext_descriptor.total_byte_length;
                let ciphertext_descriptor_byte_length = u64::try_from(
                    envelope
                        .ciphertext_descriptor
                        .encode()
                        .map_err(|error| error.refusal_reason)?
                        .len(),
                )
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                let canonical_signed_envelope_byte_length_for_mailbox =
                    u64::try_from(canonical_signed_envelope_bytes.len())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                let complete_recipient_private_wire_byte_length_for_mailbox =
                    ciphertext_stream_byte_length_for_mailbox
                        .checked_add(canonical_signed_envelope_byte_length_for_mailbox)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;

                ciphertext_stream_byte_length = ciphertext_stream_byte_length
                    .checked_add(ciphertext_stream_byte_length_for_mailbox)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                canonical_signed_envelope_byte_length = canonical_signed_envelope_byte_length
                    .checked_add(canonical_signed_envelope_byte_length_for_mailbox)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                ordered_dealer_upload_byte_lengths[dealer_roster_position] =
                    ordered_dealer_upload_byte_lengths[dealer_roster_position]
                        .checked_add(complete_recipient_private_wire_byte_length_for_mailbox)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                ordered_recipient_download_byte_lengths[recipient_roster_position] =
                    ordered_recipient_download_byte_lengths[recipient_roster_position]
                        .checked_add(complete_recipient_private_wire_byte_length_for_mailbox)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                maximum_ciphertext_descriptor_byte_length =
                    maximum_ciphertext_descriptor_byte_length
                        .max(ciphertext_descriptor_byte_length);
                maximum_canonical_signed_envelope_byte_length =
                    maximum_canonical_signed_envelope_byte_length
                        .max(canonical_signed_envelope_byte_length_for_mailbox);
                ordered_envelope_hashes.push(
                    envelope
                        .envelope_hash()
                        .map_err(|error| error.refusal_reason)?,
                );
                ordered_mailbox_byte_lengths.push(VerifiedGeneratedPrivateVssMailboxByteLengths {
                    ciphertext_stream_byte_length: ciphertext_stream_byte_length_for_mailbox,
                    ciphertext_descriptor_byte_length,
                    canonical_signed_envelope_byte_length:
                        canonical_signed_envelope_byte_length_for_mailbox,
                    complete_recipient_private_wire_byte_length:
                        complete_recipient_private_wire_byte_length_for_mailbox,
                });
            }
        }
        let complete_recipient_private_wire_byte_length = ciphertext_stream_byte_length
            .checked_add(canonical_signed_envelope_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if ordered_dealer_upload_byte_lengths
            .iter()
            .try_fold(0_u64, |total, byte_length| total.checked_add(*byte_length))
            != Some(complete_recipient_private_wire_byte_length)
            || ordered_recipient_download_byte_lengths
                .iter()
                .try_fold(0_u64, |total, byte_length| total.checked_add(*byte_length))
                != Some(complete_recipient_private_wire_byte_length)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        Ok(Self {
            context: verified_public_randomness.context(),
            public_setup_seed: verified_public_randomness.public_setup_seed(),
            setup_proof_context_hash: verified_public_randomness.setup_proof_context_hash(),
            ordered_dealer_public_record_object_hashes: ordered_dealer_public_record_object_hashes
                .into_boxed_slice(),
            ordered_envelope_hashes: ordered_envelope_hashes.into_boxed_slice(),
            ordered_mailbox_byte_lengths: ordered_mailbox_byte_lengths.into_boxed_slice(),
            ordered_dealer_upload_byte_lengths: ordered_dealer_upload_byte_lengths
                .into_boxed_slice(),
            ordered_recipient_download_byte_lengths: ordered_recipient_download_byte_lengths
                .into_boxed_slice(),
            ciphertext_stream_byte_length,
            canonical_signed_envelope_byte_length,
            complete_recipient_private_wire_byte_length,
            maximum_ciphertext_descriptor_byte_length,
            maximum_canonical_signed_envelope_byte_length,
        })
    }

    pub(in crate::bgv) fn require_matches_verified_qualification(
        &self,
        qualification: &VerifiedVssQualificationTerminals,
    ) -> Result<(), RefusalReason> {
        if self.context != qualification.context()
            || self.public_setup_seed != qualification.public_setup_seed()
            || self.setup_proof_context_hash != qualification.setup_proof_context_hash()
            || self.ordered_dealer_public_record_object_hashes.as_ref()
                != qualification.ordered_dealer_public_record_object_hashes()
        {
            return Err(RefusalReason::WrongContext);
        }
        Ok(())
    }

    pub(in crate::bgv) fn ordered_envelope_hashes(&self) -> &[Hash512] {
        &self.ordered_envelope_hashes
    }

    pub(in crate::bgv) fn ordered_mailbox_byte_lengths(
        &self,
    ) -> &[VerifiedGeneratedPrivateVssMailboxByteLengths] {
        &self.ordered_mailbox_byte_lengths
    }

    pub(in crate::bgv) fn ordered_dealer_upload_byte_lengths(&self) -> &[u64] {
        &self.ordered_dealer_upload_byte_lengths
    }

    pub(in crate::bgv) fn ordered_recipient_download_byte_lengths(&self) -> &[u64] {
        &self.ordered_recipient_download_byte_lengths
    }

    pub(in crate::bgv) const fn ciphertext_stream_byte_length(&self) -> u64 {
        self.ciphertext_stream_byte_length
    }

    pub(in crate::bgv) const fn canonical_signed_envelope_byte_length(&self) -> u64 {
        self.canonical_signed_envelope_byte_length
    }

    pub(in crate::bgv) const fn complete_recipient_private_wire_byte_length(&self) -> u64 {
        self.complete_recipient_private_wire_byte_length
    }

    pub(in crate::bgv) const fn maximum_ciphertext_descriptor_byte_length(&self) -> u64 {
        self.maximum_ciphertext_descriptor_byte_length
    }

    pub(in crate::bgv) const fn maximum_canonical_signed_envelope_byte_length(&self) -> u64 {
        self.maximum_canonical_signed_envelope_byte_length
    }
}
