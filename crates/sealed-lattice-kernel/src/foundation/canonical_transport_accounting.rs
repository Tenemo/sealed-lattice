//! Exact transport accounting derived from canonical foundation objects.

use core::{fmt, mem::size_of};

use super::{
    CanonicalDecodeLimits, FOUNDATION_PROFILE, FoundationSchemaError, Hash512,
    MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH, MAILBOX_GCM_TAG_BYTE_LENGTH,
    MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH, MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH,
    MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, MailboxAssociatedData, MailboxKeyScheduleInput,
    ParticipantIdentity, SignedMailboxEnvelope, StreamDescriptor,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalTransportAccounting {
    payload_byte_length: u64,
    stream_chunk_count: u64,
    stream_descriptor_byte_length: u64,
    mailbox_associated_data_byte_length: u64,
    mailbox_kem_ciphertext_byte_length: u64,
    mailbox_gcm_tag_byte_length: u64,
    mailbox_source_signature_byte_length: u64,
    mailbox_fixed_cryptographic_material_byte_length: u64,
    signed_mailbox_envelope_byte_length: u64,
    boundary_transfer_byte_length: u64,
    maximum_boundary_copied_buffer_byte_length: u64,
    indexed_db_serialized_byte_length: u64,
    indexed_db_additional_copy_peak_byte_length: u64,
    indexed_db_serialization_buffer_peak_byte_length: u64,
    indexed_db_readback_buffer_peak_byte_length: u64,
}

impl CanonicalTransportAccounting {
    pub(crate) const fn payload_byte_length(self) -> u64 {
        self.payload_byte_length
    }

    pub(crate) const fn stream_chunk_count(self) -> u64 {
        self.stream_chunk_count
    }

    pub(crate) const fn stream_descriptor_byte_length(self) -> u64 {
        self.stream_descriptor_byte_length
    }

    pub(crate) const fn mailbox_associated_data_byte_length(self) -> u64 {
        self.mailbox_associated_data_byte_length
    }

    pub(crate) const fn mailbox_kem_ciphertext_byte_length(self) -> u64 {
        self.mailbox_kem_ciphertext_byte_length
    }

    pub(crate) const fn mailbox_gcm_tag_byte_length(self) -> u64 {
        self.mailbox_gcm_tag_byte_length
    }

    pub(crate) const fn mailbox_source_signature_byte_length(self) -> u64 {
        self.mailbox_source_signature_byte_length
    }

    pub(crate) const fn mailbox_fixed_cryptographic_material_byte_length(self) -> u64 {
        self.mailbox_fixed_cryptographic_material_byte_length
    }

    pub(crate) const fn signed_mailbox_envelope_byte_length(self) -> u64 {
        self.signed_mailbox_envelope_byte_length
    }

    /// Cumulative bytes in all one-direction payload-chunk transfers.
    pub(crate) const fn boundary_transfer_byte_length(self) -> u64 {
        self.boundary_transfer_byte_length
    }

    /// Largest payload chunk copied during one boundary call.
    pub(crate) const fn maximum_boundary_copied_buffer_byte_length(self) -> u64 {
        self.maximum_boundary_copied_buffer_byte_length
    }

    /// Cumulative payload bytes submitted to IndexedDB serialization.
    pub(crate) const fn indexed_db_serialized_byte_length(self) -> u64 {
        self.indexed_db_serialized_byte_length
    }

    /// Largest additional copy allocated by one IndexedDB adapter operation.
    pub(crate) const fn indexed_db_additional_copy_peak_byte_length(self) -> u64 {
        self.indexed_db_additional_copy_peak_byte_length
    }

    /// Largest simultaneous source and copied buffers during serialization.
    pub(crate) const fn indexed_db_serialization_buffer_peak_byte_length(self) -> u64 {
        self.indexed_db_serialization_buffer_peak_byte_length
    }

    /// Largest simultaneous stored-value and returned buffers during readback.
    pub(crate) const fn indexed_db_readback_buffer_peak_byte_length(self) -> u64 {
        self.indexed_db_readback_buffer_peak_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalTransportAccountingError {
    EmptyPayload,
    PayloadOutsideSupportedProfile,
    MissingOrderedMaterialRoots,
    OrderedMaterialRootCountOutsideSupportedProfile,
    IntegerOverflow,
    CanonicalObject(FoundationSchemaError),
}

impl fmt::Display for CanonicalTransportAccountingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => formatter.write_str("transport payload must be nonempty"),
            Self::PayloadOutsideSupportedProfile => {
                formatter.write_str("transport payload exceeds the canonical stream profile")
            }
            Self::MissingOrderedMaterialRoots => {
                formatter.write_str("mailbox accounting requires ordered material roots")
            }
            Self::OrderedMaterialRootCountOutsideSupportedProfile => formatter
                .write_str("ordered material-root count exceeds the canonical codec profile"),
            Self::IntegerOverflow => formatter.write_str("transport accounting integer overflow"),
            Self::CanonicalObject(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for CanonicalTransportAccountingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CanonicalObject(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FoundationSchemaError> for CanonicalTransportAccountingError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::CanonicalObject(error)
    }
}

pub(crate) fn derive_canonical_transport_accounting(
    payload_byte_length: u64,
    ordered_material_root_count: usize,
) -> Result<CanonicalTransportAccounting, CanonicalTransportAccountingError> {
    if payload_byte_length == 0 {
        return Err(CanonicalTransportAccountingError::EmptyPayload);
    }
    if payload_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH {
        return Err(CanonicalTransportAccountingError::PayloadOutsideSupportedProfile);
    }
    if ordered_material_root_count == 0 {
        return Err(CanonicalTransportAccountingError::MissingOrderedMaterialRoots);
    }
    if ordered_material_root_count > CanonicalDecodeLimits::default().maximum_item_count {
        return Err(
            CanonicalTransportAccountingError::OrderedMaterialRootCountOutsideSupportedProfile,
        );
    }

    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| CanonicalTransportAccountingError::IntegerOverflow)?;
    let stream_chunk_count = payload_byte_length.div_ceil(stream_chunk_byte_length);
    let stream_chunk_count_usize = usize::try_from(stream_chunk_count)
        .map_err(|_| CanonicalTransportAccountingError::IntegerOverflow)?;

    let stream_descriptor = StreamDescriptor::new(
        payload_byte_length,
        deterministic_hash_catalog(stream_chunk_count_usize, 0x31)?,
        deterministic_hash(0x32, 0)?,
    )?;
    let stream_descriptor_byte_length = encoded_byte_length(stream_descriptor.encode()?)?;

    let key_schedule_input = MailboxKeyScheduleInput {
        suite_id: deterministic_hash(0x41, 0)?,
        ceremony_context_hash: deterministic_hash(0x42, 0)?,
        action_context_hash: deterministic_hash(0x43, 0)?,
        roster_hash: deterministic_hash(0x44, 0)?,
        source_participant_id: ParticipantIdentity::from_bytes(
            [0x51; ParticipantIdentity::BYTE_LENGTH],
        ),
        recipient_participant_id: ParticipantIdentity::from_bytes(
            [0x52; ParticipantIdentity::BYTE_LENGTH],
        ),
        producer_sequence: 1,
        envelope_attempt_identifier: [0x61; MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        statement_hash: deterministic_hash(0x45, 0)?,
        ordered_material_roots: deterministic_hash_catalog(ordered_material_root_count, 0x71)?,
    }
    .checked()?;
    let mailbox_associated_data = MailboxAssociatedData::new(key_schedule_input)?;
    let mailbox_associated_data_byte_length =
        encoded_byte_length(mailbox_associated_data.encode()?)?;

    let kem_ciphertext = [0x81; MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH];
    let gcm_tag = [0x82; MAILBOX_GCM_TAG_BYTE_LENGTH];
    let source_signature = [0x83; MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH];
    let mailbox_kem_ciphertext_byte_length = slice_byte_length(&kem_ciphertext)?;
    let mailbox_gcm_tag_byte_length = slice_byte_length(&gcm_tag)?;
    let mailbox_source_signature_byte_length = slice_byte_length(&source_signature)?;
    let mailbox_fixed_cryptographic_material_byte_length = mailbox_kem_ciphertext_byte_length
        .checked_add(mailbox_gcm_tag_byte_length)
        .and_then(|length| length.checked_add(mailbox_source_signature_byte_length))
        .ok_or(CanonicalTransportAccountingError::IntegerOverflow)?;
    let signed_mailbox_envelope = SignedMailboxEnvelope::new(
        mailbox_associated_data,
        kem_ciphertext,
        stream_descriptor,
        gcm_tag,
        source_signature,
    )?;
    let signed_mailbox_envelope_byte_length =
        encoded_byte_length(signed_mailbox_envelope.encode()?)?;

    let maximum_boundary_copied_buffer_byte_length =
        payload_byte_length.min(stream_chunk_byte_length);
    let source_and_copy_peak_byte_length = maximum_boundary_copied_buffer_byte_length
        .checked_mul(2)
        .ok_or(CanonicalTransportAccountingError::IntegerOverflow)?;

    Ok(CanonicalTransportAccounting {
        payload_byte_length,
        stream_chunk_count,
        stream_descriptor_byte_length,
        mailbox_associated_data_byte_length,
        mailbox_kem_ciphertext_byte_length,
        mailbox_gcm_tag_byte_length,
        mailbox_source_signature_byte_length,
        mailbox_fixed_cryptographic_material_byte_length,
        signed_mailbox_envelope_byte_length,
        boundary_transfer_byte_length: payload_byte_length,
        maximum_boundary_copied_buffer_byte_length,
        indexed_db_serialized_byte_length: payload_byte_length,
        indexed_db_additional_copy_peak_byte_length: maximum_boundary_copied_buffer_byte_length,
        indexed_db_serialization_buffer_peak_byte_length: source_and_copy_peak_byte_length,
        indexed_db_readback_buffer_peak_byte_length: source_and_copy_peak_byte_length,
    })
}

fn deterministic_hash_catalog(
    count: usize,
    prefix: u8,
) -> Result<Vec<Hash512>, CanonicalTransportAccountingError> {
    (0..count)
        .map(|ordinal| deterministic_hash(prefix, ordinal))
        .collect()
}

fn deterministic_hash(
    prefix: u8,
    ordinal: usize,
) -> Result<Hash512, CanonicalTransportAccountingError> {
    let ordinal =
        u64::try_from(ordinal).map_err(|_| CanonicalTransportAccountingError::IntegerOverflow)?;
    let mut bytes = [prefix; Hash512::BYTE_LENGTH];
    bytes[..size_of::<u64>()].copy_from_slice(&ordinal.to_le_bytes());
    Ok(Hash512::from_bytes(bytes))
}

fn encoded_byte_length(encoded: Vec<u8>) -> Result<u64, CanonicalTransportAccountingError> {
    slice_byte_length(&encoded)
}

fn slice_byte_length(bytes: &[u8]) -> Result<u64, CanonicalTransportAccountingError> {
    u64::try_from(bytes.len()).map_err(|_| CanonicalTransportAccountingError::IntegerOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM_CHUNK_BYTE_LENGTH: u64 = 1_048_576;

    #[test]
    fn accounting_rejects_inputs_without_canonical_production_objects() {
        assert_eq!(
            derive_canonical_transport_accounting(0, 1),
            Err(CanonicalTransportAccountingError::EmptyPayload)
        );
        assert_eq!(
            derive_canonical_transport_accounting(MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH + 1, 1),
            Err(CanonicalTransportAccountingError::PayloadOutsideSupportedProfile)
        );
        assert_eq!(
            derive_canonical_transport_accounting(1, 0),
            Err(CanonicalTransportAccountingError::MissingOrderedMaterialRoots)
        );
        assert_eq!(
            derive_canonical_transport_accounting(
                1,
                CanonicalDecodeLimits::default().maximum_item_count + 1,
            ),
            Err(CanonicalTransportAccountingError::OrderedMaterialRootCountOutsideSupportedProfile)
        );
    }

    #[test]
    fn one_mebibyte_boundary_changes_only_chunk_dependent_canonical_bytes() {
        let below = derive_canonical_transport_accounting(STREAM_CHUNK_BYTE_LENGTH - 1, 2)
            .expect("one byte below the chunk boundary is supported");
        let exact = derive_canonical_transport_accounting(STREAM_CHUNK_BYTE_LENGTH, 2)
            .expect("the exact chunk boundary is supported");
        let above = derive_canonical_transport_accounting(STREAM_CHUNK_BYTE_LENGTH + 1, 2)
            .expect("one byte above the chunk boundary is supported");

        assert_eq!(below.stream_chunk_count(), 1);
        assert_eq!(exact.stream_chunk_count(), 1);
        assert_eq!(above.stream_chunk_count(), 2);
        assert_eq!(
            below.stream_descriptor_byte_length(),
            exact.stream_descriptor_byte_length()
        );
        assert_eq!(
            above.stream_descriptor_byte_length(),
            exact.stream_descriptor_byte_length() + Hash512::BYTE_LENGTH as u64
        );
        assert_eq!(
            below.mailbox_associated_data_byte_length(),
            above.mailbox_associated_data_byte_length()
        );
        assert_eq!(
            above.signed_mailbox_envelope_byte_length(),
            exact.signed_mailbox_envelope_byte_length() + Hash512::BYTE_LENGTH as u64
        );

        assert_eq!(
            below.maximum_boundary_copied_buffer_byte_length(),
            STREAM_CHUNK_BYTE_LENGTH - 1
        );
        assert_eq!(
            exact.maximum_boundary_copied_buffer_byte_length(),
            STREAM_CHUNK_BYTE_LENGTH
        );
        assert_eq!(
            above.maximum_boundary_copied_buffer_byte_length(),
            STREAM_CHUNK_BYTE_LENGTH
        );
        assert_eq!(
            above.boundary_transfer_byte_length(),
            STREAM_CHUNK_BYTE_LENGTH + 1
        );
        assert_ne!(
            above.boundary_transfer_byte_length(),
            above.maximum_boundary_copied_buffer_byte_length()
        );
    }

    #[test]
    fn canonical_mailbox_sizes_come_from_full_production_encodings() {
        let one_root = derive_canonical_transport_accounting(1, 1)
            .expect("one-root mailbox accounting is supported");
        let two_roots = derive_canonical_transport_accounting(1, 2)
            .expect("two-root mailbox accounting is supported");
        let maximum_root_count = CanonicalDecodeLimits::default().maximum_item_count;
        let maximum_roots = derive_canonical_transport_accounting(1, maximum_root_count)
            .expect("the maximum canonical root count remains encodable");

        assert_eq!(
            one_root.mailbox_kem_ciphertext_byte_length(),
            MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH as u64
        );
        assert_eq!(
            one_root.mailbox_gcm_tag_byte_length(),
            MAILBOX_GCM_TAG_BYTE_LENGTH as u64
        );
        assert_eq!(
            one_root.mailbox_source_signature_byte_length(),
            MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH as u64
        );
        assert_eq!(
            one_root.mailbox_fixed_cryptographic_material_byte_length(),
            (MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH
                + MAILBOX_GCM_TAG_BYTE_LENGTH
                + MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH) as u64
        );
        assert_eq!(
            two_roots.mailbox_associated_data_byte_length(),
            one_root.mailbox_associated_data_byte_length() + Hash512::BYTE_LENGTH as u64
        );
        assert_eq!(
            two_roots.signed_mailbox_envelope_byte_length(),
            one_root.signed_mailbox_envelope_byte_length() + Hash512::BYTE_LENGTH as u64
        );
        let additional_root_byte_length = u64::try_from(maximum_root_count - 1)
            .expect("the canonical root count fits u64")
            .checked_mul(Hash512::BYTE_LENGTH as u64)
            .expect("the canonical root byte length fits u64");
        assert_eq!(
            maximum_roots.mailbox_associated_data_byte_length(),
            one_root.mailbox_associated_data_byte_length() + additional_root_byte_length
        );
        assert_eq!(
            maximum_roots.signed_mailbox_envelope_byte_length(),
            one_root.signed_mailbox_envelope_byte_length() + additional_root_byte_length
        );
        assert!(
            one_root.signed_mailbox_envelope_byte_length()
                > one_root.mailbox_associated_data_byte_length()
                    + one_root.stream_descriptor_byte_length()
                    + one_root.mailbox_fixed_cryptographic_material_byte_length()
        );
    }

    #[test]
    fn large_payloads_preserve_exact_volume_and_bounded_live_buffers() {
        let cases = [
            (12_058_628, 12),
            (300_941_312, 287),
            (355_467_712, 340),
            (MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, 4_096),
        ];

        for (payload_byte_length, expected_chunk_count) in cases {
            let accounting = derive_canonical_transport_accounting(payload_byte_length, 8)
                .expect("large payload accounting remains inside canonical limits");
            assert_eq!(accounting.payload_byte_length(), payload_byte_length);
            assert_eq!(accounting.stream_chunk_count(), expected_chunk_count);
            assert_eq!(
                accounting.boundary_transfer_byte_length(),
                payload_byte_length
            );
            assert_eq!(
                accounting.indexed_db_serialized_byte_length(),
                payload_byte_length
            );
            assert_eq!(
                accounting.maximum_boundary_copied_buffer_byte_length(),
                STREAM_CHUNK_BYTE_LENGTH
            );
            assert_eq!(
                accounting.indexed_db_additional_copy_peak_byte_length(),
                STREAM_CHUNK_BYTE_LENGTH
            );
            assert_eq!(
                accounting.indexed_db_serialization_buffer_peak_byte_length(),
                STREAM_CHUNK_BYTE_LENGTH * 2
            );
            assert_eq!(
                accounting.indexed_db_readback_buffer_peak_byte_length(),
                STREAM_CHUNK_BYTE_LENGTH * 2
            );
        }
    }

    #[test]
    fn single_chunk_indexed_db_peaks_track_the_actual_short_buffer() {
        let payload_byte_length = 17;
        let accounting = derive_canonical_transport_accounting(payload_byte_length, 1)
            .expect("short transport accounting is supported");

        assert_eq!(
            accounting.boundary_transfer_byte_length(),
            payload_byte_length
        );
        assert_eq!(
            accounting.maximum_boundary_copied_buffer_byte_length(),
            payload_byte_length
        );
        assert_eq!(
            accounting.indexed_db_additional_copy_peak_byte_length(),
            payload_byte_length
        );
        assert_eq!(
            accounting.indexed_db_serialization_buffer_peak_byte_length(),
            payload_byte_length * 2
        );
        assert_eq!(
            accounting.indexed_db_readback_buffer_peak_byte_length(),
            payload_byte_length * 2
        );
    }
}
