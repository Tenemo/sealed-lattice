//! Selected material transport accounting derived from canonical objects.

use core::mem::size_of;

use crate::{
    bgv::{
        evaluator::{
            ballot_aggregation::selected_aggregate_ciphertext_stream_byte_length,
            top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        },
        serialization::two_component_data_ciphertext_canonical_byte_length_ceiling_at_level,
    },
    foundation::{
        AggregatePayload, CanonicalDecodeLimits, FOUNDATION_PROFILE, FoundationObjectType, Hash512,
        ObjectEnvelope, StreamDescriptor,
        canonical_transport_accounting::{
            CanonicalTransportAccounting, derive_canonical_transport_accounting,
        },
        encode_aggregate_carrier, encode_evaluator_replay_carrier,
        selected_sharing_data_prime_coordinates,
    },
};

use super::selected_recipient_private_vss_payload_byte_length;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedMaterialTransportAccountingError {
    SelectedProfile,
    CanonicalEncoding,
    CanonicalTransport,
    IntegerOverflow,
}

/// Exact canonical bytes for the sole implemented private-mailbox payload
/// family. This record deliberately stops at canonical network objects. The
/// browser-local protected-record wrappers and complete JavaScript/WASM call
/// graph have separate production owners and must not be inferred from these
/// byte lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedPrivateVssMailboxTransportAccounting {
    participant_count: u16,
    physical_payload_stream_count: u64,
    ordered_material_root_count_per_envelope: u64,
    canonical_transport_primitive: CanonicalTransportAccounting,
    complete_mailbox_byte_length: u64,
    one_dealer_upload_byte_length: u64,
    one_recipient_download_byte_length: u64,
    ceremony_upload_byte_length: u64,
    ceremony_download_byte_length: u64,
    private_mailbox_corpus_byte_length: u64,
}

impl SelectedPrivateVssMailboxTransportAccounting {
    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn physical_payload_stream_count(self) -> u64 {
        self.physical_payload_stream_count
    }

    pub(crate) const fn ordered_material_root_count_per_envelope(self) -> u64 {
        self.ordered_material_root_count_per_envelope
    }

    pub(crate) const fn canonical_transport_primitive(self) -> CanonicalTransportAccounting {
        self.canonical_transport_primitive
    }

    pub(crate) const fn complete_mailbox_byte_length(self) -> u64 {
        self.complete_mailbox_byte_length
    }

    pub(crate) const fn one_dealer_upload_byte_length(self) -> u64 {
        self.one_dealer_upload_byte_length
    }

    pub(crate) const fn one_recipient_download_byte_length(self) -> u64 {
        self.one_recipient_download_byte_length
    }

    pub(crate) const fn ceremony_upload_byte_length(self) -> u64 {
        self.ceremony_upload_byte_length
    }

    pub(crate) const fn ceremony_download_byte_length(self) -> u64 {
        self.ceremony_download_byte_length
    }

    pub(crate) const fn private_mailbox_corpus_byte_length(self) -> u64 {
        self.private_mailbox_corpus_byte_length
    }
}

const UNSIGNED_PUBLIC_CARRIER_COUNT: u64 = 2;
const UNSIGNED_PUBLIC_PHYSICAL_STREAM_COUNT: u64 = 4;
const TWO_STREAM_COUNT: u64 = 2;
const UNSIGNED_ENVELOPE_BINDING_HASH_COUNT: u64 = 3;

/// Exact canonical bytes for the one selected aggregate carrier and its two
/// fixed-width character-ciphertext streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedAggregatePublicCarrierAccounting {
    selected_ballot_object_hash_count: u64,
    payload_binding_hash_count: u64,
    physical_ciphertext_stream_count: u64,
    one_ciphertext_stream_byte_length: u64,
    one_ciphertext_stream_chunk_count: u64,
    one_stream_descriptor_hash_count: u64,
    one_stream_descriptor_byte_length: u64,
    ciphertext_stream_corpus_byte_length: u64,
    ciphertext_stream_corpus_chunk_count: u64,
    canonical_payload_byte_length: u64,
    canonical_payload_framing_byte_length: u64,
    canonical_envelope_binding_hash_count: u64,
    canonical_envelope_byte_length: u64,
    canonical_envelope_framing_byte_length: u64,
    complete_public_object_byte_length: u64,
}

impl SelectedAggregatePublicCarrierAccounting {
    pub(crate) const fn selected_ballot_object_hash_count(self) -> u64 {
        self.selected_ballot_object_hash_count
    }

    pub(crate) const fn payload_binding_hash_count(self) -> u64 {
        self.payload_binding_hash_count
    }

    pub(crate) const fn physical_ciphertext_stream_count(self) -> u64 {
        self.physical_ciphertext_stream_count
    }

    pub(crate) const fn one_ciphertext_stream_byte_length(self) -> u64 {
        self.one_ciphertext_stream_byte_length
    }

    pub(crate) const fn one_ciphertext_stream_chunk_count(self) -> u64 {
        self.one_ciphertext_stream_chunk_count
    }

    pub(crate) const fn one_stream_descriptor_hash_count(self) -> u64 {
        self.one_stream_descriptor_hash_count
    }

    pub(crate) const fn one_stream_descriptor_byte_length(self) -> u64 {
        self.one_stream_descriptor_byte_length
    }

    pub(crate) const fn ciphertext_stream_corpus_byte_length(self) -> u64 {
        self.ciphertext_stream_corpus_byte_length
    }

    pub(crate) const fn ciphertext_stream_corpus_chunk_count(self) -> u64 {
        self.ciphertext_stream_corpus_chunk_count
    }

    pub(crate) const fn canonical_payload_byte_length(self) -> u64 {
        self.canonical_payload_byte_length
    }

    pub(crate) const fn canonical_payload_framing_byte_length(self) -> u64 {
        self.canonical_payload_framing_byte_length
    }

    pub(crate) const fn canonical_envelope_binding_hash_count(self) -> u64 {
        self.canonical_envelope_binding_hash_count
    }

    pub(crate) const fn canonical_envelope_byte_length(self) -> u64 {
        self.canonical_envelope_byte_length
    }

    pub(crate) const fn canonical_envelope_framing_byte_length(self) -> u64 {
        self.canonical_envelope_framing_byte_length
    }

    pub(crate) const fn complete_public_object_byte_length(self) -> u64 {
        self.complete_public_object_byte_length
    }
}

/// Exact canonical carrier accounting when the two production replay stream
/// descriptors are available. The helper consumes descriptors only; it never
/// allocates or serializes their ciphertext bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorReplayPublicCarrierAccounting {
    payload_binding_hash_count: u64,
    physical_ciphertext_stream_count: u64,
    target_identifier_stream_byte_length: u64,
    target_identifier_stream_chunk_count: u64,
    target_identifier_stream_descriptor_hash_count: u64,
    target_identifier_stream_descriptor_byte_length: u64,
    target_order_stream_byte_length: u64,
    target_order_stream_chunk_count: u64,
    target_order_stream_descriptor_hash_count: u64,
    target_order_stream_descriptor_byte_length: u64,
    ciphertext_stream_corpus_byte_length: u64,
    ciphertext_stream_corpus_chunk_count: u64,
    canonical_payload_byte_length: u64,
    canonical_payload_framing_byte_length: u64,
    canonical_envelope_binding_hash_count: u64,
    canonical_envelope_byte_length: u64,
    canonical_envelope_framing_byte_length: u64,
    complete_public_object_byte_length: u64,
}

impl SelectedEvaluatorReplayPublicCarrierAccounting {
    pub(crate) const fn payload_binding_hash_count(self) -> u64 {
        self.payload_binding_hash_count
    }

    pub(crate) const fn physical_ciphertext_stream_count(self) -> u64 {
        self.physical_ciphertext_stream_count
    }

    pub(crate) const fn target_identifier_stream_byte_length(self) -> u64 {
        self.target_identifier_stream_byte_length
    }

    pub(crate) const fn target_identifier_stream_chunk_count(self) -> u64 {
        self.target_identifier_stream_chunk_count
    }

    pub(crate) const fn target_identifier_stream_descriptor_hash_count(self) -> u64 {
        self.target_identifier_stream_descriptor_hash_count
    }

    pub(crate) const fn target_identifier_stream_descriptor_byte_length(self) -> u64 {
        self.target_identifier_stream_descriptor_byte_length
    }

    pub(crate) const fn target_order_stream_byte_length(self) -> u64 {
        self.target_order_stream_byte_length
    }

    pub(crate) const fn target_order_stream_chunk_count(self) -> u64 {
        self.target_order_stream_chunk_count
    }

    pub(crate) const fn target_order_stream_descriptor_hash_count(self) -> u64 {
        self.target_order_stream_descriptor_hash_count
    }

    pub(crate) const fn target_order_stream_descriptor_byte_length(self) -> u64 {
        self.target_order_stream_descriptor_byte_length
    }

    pub(crate) const fn ciphertext_stream_corpus_byte_length(self) -> u64 {
        self.ciphertext_stream_corpus_byte_length
    }

    pub(crate) const fn ciphertext_stream_corpus_chunk_count(self) -> u64 {
        self.ciphertext_stream_corpus_chunk_count
    }

    pub(crate) const fn canonical_payload_byte_length(self) -> u64 {
        self.canonical_payload_byte_length
    }

    pub(crate) const fn canonical_payload_framing_byte_length(self) -> u64 {
        self.canonical_payload_framing_byte_length
    }

    pub(crate) const fn canonical_envelope_binding_hash_count(self) -> u64 {
        self.canonical_envelope_binding_hash_count
    }

    pub(crate) const fn canonical_envelope_byte_length(self) -> u64 {
        self.canonical_envelope_byte_length
    }

    pub(crate) const fn canonical_envelope_framing_byte_length(self) -> u64 {
        self.canonical_envelope_framing_byte_length
    }

    pub(crate) const fn complete_public_object_byte_length(self) -> u64 {
        self.complete_public_object_byte_length
    }
}

/// Static upper bound for replay transport. Canonical BGV target ciphertexts
/// use value-dependent varuint residues, so this ceiling is not actual traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorReplayCarrierCodecCeilingAccounting {
    carrier_accounting_at_codec_ceiling: SelectedEvaluatorReplayPublicCarrierAccounting,
}

impl SelectedEvaluatorReplayCarrierCodecCeilingAccounting {
    pub(crate) const fn carrier_accounting_at_codec_ceiling(
        self,
    ) -> SelectedEvaluatorReplayPublicCarrierAccounting {
        self.carrier_accounting_at_codec_ceiling
    }

    pub(crate) const fn target_ciphertext_stream_byte_length_ceiling(self) -> u64 {
        self.carrier_accounting_at_codec_ceiling
            .target_identifier_stream_byte_length
    }

    pub(crate) const fn target_ciphertext_stream_chunk_count_ceiling(self) -> u64 {
        self.carrier_accounting_at_codec_ceiling
            .target_identifier_stream_chunk_count
    }

    pub(crate) const fn canonical_envelope_byte_length_ceiling(self) -> u64 {
        self.carrier_accounting_at_codec_ceiling
            .canonical_envelope_byte_length
    }

    pub(crate) const fn complete_public_object_byte_length_ceiling(self) -> u64 {
        self.carrier_accounting_at_codec_ceiling
            .complete_public_object_byte_length
    }
}

/// Production replay preparation can derive both value-dependent stream
/// descriptors, but exact accounting remains unavailable without a canonical
/// selected action/input or a retained descriptor artifact from that action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedExactEvaluatorReplayCarrierAccounting {
    Available(SelectedEvaluatorReplayPublicCarrierAccounting),
    MissingGeneratedEvaluatorReplayDescriptors,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedUnsignedPublicCarrierAccounting {
    aggregate_public_carrier: SelectedAggregatePublicCarrierAccounting,
    evaluator_replay_codec_ceiling: SelectedEvaluatorReplayCarrierCodecCeilingAccounting,
    exact_evaluator_replay: SelectedExactEvaluatorReplayCarrierAccounting,
    unsigned_public_carrier_count: u64,
    unsigned_public_physical_stream_count: u64,
}

impl SelectedUnsignedPublicCarrierAccounting {
    pub(crate) const fn aggregate_public_carrier(self) -> SelectedAggregatePublicCarrierAccounting {
        self.aggregate_public_carrier
    }

    pub(crate) const fn evaluator_replay_codec_ceiling(
        self,
    ) -> SelectedEvaluatorReplayCarrierCodecCeilingAccounting {
        self.evaluator_replay_codec_ceiling
    }

    pub(crate) const fn exact_evaluator_replay(
        self,
    ) -> SelectedExactEvaluatorReplayCarrierAccounting {
        self.exact_evaluator_replay
    }

    pub(crate) const fn unsigned_public_carrier_count(self) -> u64 {
        self.unsigned_public_carrier_count
    }

    pub(crate) const fn unsigned_public_physical_stream_count(self) -> u64 {
        self.unsigned_public_physical_stream_count
    }
}

pub(crate) fn derive_selected_private_vss_mailbox_transport_accounting()
-> Result<SelectedPrivateVssMailboxTransportAccounting, SelectedMaterialTransportAccountingError> {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let participant_count_u64 = u64::from(participant_count);
    let sharing_limb_count = selected_sharing_data_prime_coordinates()
        .map_err(|_| SelectedMaterialTransportAccountingError::SelectedProfile)?
        .len();
    let coefficient_material_root_count = sharing_limb_count
        .checked_mul(usize::from(FOUNDATION_PROFILE.reconstruction_threshold))
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let ordered_material_root_count = coefficient_material_root_count
        .checked_add(sharing_limb_count)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let ordered_material_root_count_per_envelope = u64::try_from(ordered_material_root_count)
        .map_err(|_| SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let payload_byte_length = selected_recipient_private_vss_payload_byte_length()
        .map_err(|_| SelectedMaterialTransportAccountingError::SelectedProfile)?;
    let canonical_transport_primitive =
        derive_canonical_transport_accounting(payload_byte_length, ordered_material_root_count)
            .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalTransport)?;
    let complete_mailbox_byte_length = canonical_transport_primitive
        .payload_byte_length()
        .checked_add(canonical_transport_primitive.signed_mailbox_envelope_byte_length())
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let one_dealer_upload_byte_length = complete_mailbox_byte_length
        .checked_mul(participant_count_u64)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let one_recipient_download_byte_length = one_dealer_upload_byte_length;
    let physical_payload_stream_count = participant_count_u64
        .checked_mul(participant_count_u64)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let ceremony_upload_byte_length = complete_mailbox_byte_length
        .checked_mul(physical_payload_stream_count)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let ceremony_download_byte_length = ceremony_upload_byte_length;

    Ok(SelectedPrivateVssMailboxTransportAccounting {
        participant_count,
        physical_payload_stream_count,
        ordered_material_root_count_per_envelope,
        canonical_transport_primitive,
        complete_mailbox_byte_length,
        one_dealer_upload_byte_length,
        one_recipient_download_byte_length,
        ceremony_upload_byte_length,
        ceremony_download_byte_length,
        private_mailbox_corpus_byte_length: ceremony_upload_byte_length,
    })
}

pub(crate) fn derive_selected_unsigned_public_carrier_accounting()
-> Result<SelectedUnsignedPublicCarrierAccounting, SelectedMaterialTransportAccountingError> {
    Ok(SelectedUnsignedPublicCarrierAccounting {
        aggregate_public_carrier: derive_selected_aggregate_public_carrier_accounting()?,
        evaluator_replay_codec_ceiling:
            derive_selected_evaluator_replay_carrier_codec_ceiling_accounting()?,
        exact_evaluator_replay:
            SelectedExactEvaluatorReplayCarrierAccounting::MissingGeneratedEvaluatorReplayDescriptors,
        unsigned_public_carrier_count: UNSIGNED_PUBLIC_CARRIER_COUNT,
        unsigned_public_physical_stream_count: UNSIGNED_PUBLIC_PHYSICAL_STREAM_COUNT,
    })
}

fn derive_selected_aggregate_public_carrier_accounting()
-> Result<SelectedAggregatePublicCarrierAccounting, SelectedMaterialTransportAccountingError> {
    let selected_ballot_object_hash_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let selected_ballot_object_hash_count_usize =
        usize::try_from(selected_ballot_object_hash_count)
            .map_err(|_| SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let one_ciphertext_stream_byte_length = selected_aggregate_ciphertext_stream_byte_length()
        .map_err(|_| SelectedMaterialTransportAccountingError::SelectedProfile)?;
    let stream_descriptor =
        deterministic_stream_descriptor(one_ciphertext_stream_byte_length, 0x31, 0x32)?;
    let one_ciphertext_stream_chunk_count = descriptor_chunk_count(&stream_descriptor)?;
    let one_stream_descriptor_hash_count = one_ciphertext_stream_chunk_count
        .checked_add(1)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let one_stream_descriptor_byte_length = encoded_byte_length(
        stream_descriptor
            .encode()
            .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?,
    )?;
    let selected_ballot_object_hashes =
        deterministic_hash_catalog(selected_ballot_object_hash_count_usize, 0x41)?;
    let verified_setup_source_hash = deterministic_hash(0x42, 0)?;
    let aggregate_ciphertext_descriptors = [stream_descriptor.clone(), stream_descriptor];
    let carrier = encode_aggregate_carrier(
        deterministic_hash(0x43, 0)?,
        deterministic_hash(0x44, 0)?,
        deterministic_hash(0x45, 0)?,
        verified_setup_source_hash,
        selected_ballot_object_hashes.clone(),
        aggregate_ciphertext_descriptors.clone(),
    )
    .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?;
    let envelope = decode_unsigned_envelope(&carrier, FoundationObjectType::Aggregate)?;
    let payload =
        AggregatePayload::decode(&envelope.payload_bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?;
    if payload.verified_setup_source_hash() != verified_setup_source_hash
        || payload.selected_ballot_object_hashes() != selected_ballot_object_hashes
        || payload.aggregate_ciphertext_descriptors() != &aggregate_ciphertext_descriptors
    {
        return Err(SelectedMaterialTransportAccountingError::CanonicalEncoding);
    }

    let payload_binding_hash_count = selected_ballot_object_hash_count
        .checked_add(1)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let descriptor_corpus_byte_length = one_stream_descriptor_byte_length
        .checked_mul(TWO_STREAM_COUNT)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let canonical_payload_byte_length = slice_byte_length(&envelope.payload_bytes)?;
    let canonical_payload_framing_byte_length = canonical_framing_byte_length(
        canonical_payload_byte_length,
        payload_binding_hash_count,
        descriptor_corpus_byte_length,
    )?;
    let canonical_envelope_byte_length = slice_byte_length(&carrier)?;
    let canonical_envelope_framing_byte_length = canonical_framing_byte_length(
        canonical_envelope_byte_length,
        UNSIGNED_ENVELOPE_BINDING_HASH_COUNT,
        canonical_payload_byte_length,
    )?;
    let ciphertext_stream_corpus_byte_length = one_ciphertext_stream_byte_length
        .checked_mul(TWO_STREAM_COUNT)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let ciphertext_stream_corpus_chunk_count = one_ciphertext_stream_chunk_count
        .checked_mul(TWO_STREAM_COUNT)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let complete_public_object_byte_length = canonical_envelope_byte_length
        .checked_add(ciphertext_stream_corpus_byte_length)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;

    Ok(SelectedAggregatePublicCarrierAccounting {
        selected_ballot_object_hash_count,
        payload_binding_hash_count,
        physical_ciphertext_stream_count: TWO_STREAM_COUNT,
        one_ciphertext_stream_byte_length,
        one_ciphertext_stream_chunk_count,
        one_stream_descriptor_hash_count,
        one_stream_descriptor_byte_length,
        ciphertext_stream_corpus_byte_length,
        ciphertext_stream_corpus_chunk_count,
        canonical_payload_byte_length,
        canonical_payload_framing_byte_length,
        canonical_envelope_binding_hash_count: UNSIGNED_ENVELOPE_BINDING_HASH_COUNT,
        canonical_envelope_byte_length,
        canonical_envelope_framing_byte_length,
        complete_public_object_byte_length,
    })
}

fn derive_selected_evaluator_replay_carrier_codec_ceiling_accounting() -> Result<
    SelectedEvaluatorReplayCarrierCodecCeilingAccounting,
    SelectedMaterialTransportAccountingError,
> {
    let target_ciphertext_stream_byte_length_ceiling =
        two_component_data_ciphertext_canonical_byte_length_ceiling_at_level(
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?;
    let target_identifier_descriptor =
        deterministic_stream_descriptor(target_ciphertext_stream_byte_length_ceiling, 0x51, 0x52)?;
    let target_order_descriptor =
        deterministic_stream_descriptor(target_ciphertext_stream_byte_length_ceiling, 0x53, 0x54)?;
    let carrier_accounting_at_codec_ceiling =
        derive_evaluator_replay_public_carrier_accounting_from_descriptors(
            &target_identifier_descriptor,
            &target_order_descriptor,
        )?;

    Ok(SelectedEvaluatorReplayCarrierCodecCeilingAccounting {
        carrier_accounting_at_codec_ceiling,
    })
}

/// Derives an exact replay carrier from descriptors emitted by production
/// evaluator execution. Passing the descriptors avoids retaining either large
/// target ciphertext solely for accounting.
pub(crate) fn derive_selected_evaluator_replay_public_carrier_accounting(
    target_identifier_descriptor: &StreamDescriptor,
    target_order_descriptor: &StreamDescriptor,
) -> Result<SelectedEvaluatorReplayPublicCarrierAccounting, SelectedMaterialTransportAccountingError>
{
    derive_evaluator_replay_public_carrier_accounting_from_descriptors(
        target_identifier_descriptor,
        target_order_descriptor,
    )
}

fn derive_evaluator_replay_public_carrier_accounting_from_descriptors(
    target_identifier_descriptor: &StreamDescriptor,
    target_order_descriptor: &StreamDescriptor,
) -> Result<SelectedEvaluatorReplayPublicCarrierAccounting, SelectedMaterialTransportAccountingError>
{
    let target_ciphertext_stream_byte_length_ceiling =
        two_component_data_ciphertext_canonical_byte_length_ceiling_at_level(
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?;
    if target_identifier_descriptor.total_byte_length > target_ciphertext_stream_byte_length_ceiling
        || target_order_descriptor.total_byte_length > target_ciphertext_stream_byte_length_ceiling
    {
        return Err(SelectedMaterialTransportAccountingError::SelectedProfile);
    }

    let target_identifier_descriptor_bytes = target_identifier_descriptor
        .encode()
        .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?;
    let target_order_descriptor_bytes = target_order_descriptor
        .encode()
        .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?;
    let target_identifier_stream_descriptor_byte_length =
        slice_byte_length(&target_identifier_descriptor_bytes)?;
    let target_order_stream_descriptor_byte_length =
        slice_byte_length(&target_order_descriptor_bytes)?;
    let target_identifier_stream_chunk_count =
        descriptor_chunk_count(target_identifier_descriptor)?;
    let target_order_stream_chunk_count = descriptor_chunk_count(target_order_descriptor)?;
    let target_identifier_stream_descriptor_hash_count = target_identifier_stream_chunk_count
        .checked_add(1)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let target_order_stream_descriptor_hash_count = target_order_stream_chunk_count
        .checked_add(1)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;

    if StreamDescriptor::decode(
        &target_identifier_descriptor_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?
        != *target_identifier_descriptor
        || StreamDescriptor::decode(
            &target_order_descriptor_bytes,
            &CanonicalDecodeLimits::default(),
        )
        .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?
            != *target_order_descriptor
    {
        return Err(SelectedMaterialTransportAccountingError::CanonicalEncoding);
    }

    let carrier = encode_evaluator_replay_carrier(
        deterministic_hash(0x61, 0)?,
        deterministic_hash(0x62, 0)?,
        deterministic_hash(0x63, 0)?,
        deterministic_hash(0x64, 0)?,
        deterministic_hash(0x65, 0)?,
        target_identifier_descriptor.clone(),
        target_order_descriptor.clone(),
    )
    .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?;
    let envelope = decode_unsigned_envelope(&carrier, FoundationObjectType::EvaluatorReplay)?;
    let payload_binding_hash_count = 2_u64;
    let descriptor_corpus_byte_length = target_identifier_stream_descriptor_byte_length
        .checked_add(target_order_stream_descriptor_byte_length)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let canonical_payload_byte_length = slice_byte_length(&envelope.payload_bytes)?;
    let canonical_payload_framing_byte_length = canonical_framing_byte_length(
        canonical_payload_byte_length,
        payload_binding_hash_count,
        descriptor_corpus_byte_length,
    )?;
    let canonical_envelope_byte_length = slice_byte_length(&carrier)?;
    let canonical_envelope_framing_byte_length = canonical_framing_byte_length(
        canonical_envelope_byte_length,
        UNSIGNED_ENVELOPE_BINDING_HASH_COUNT,
        canonical_payload_byte_length,
    )?;
    let ciphertext_stream_corpus_byte_length = target_identifier_descriptor
        .total_byte_length
        .checked_add(target_order_descriptor.total_byte_length)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let ciphertext_stream_corpus_chunk_count = target_identifier_stream_chunk_count
        .checked_add(target_order_stream_chunk_count)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let complete_public_object_byte_length = canonical_envelope_byte_length
        .checked_add(ciphertext_stream_corpus_byte_length)
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;

    Ok(SelectedEvaluatorReplayPublicCarrierAccounting {
        payload_binding_hash_count,
        physical_ciphertext_stream_count: TWO_STREAM_COUNT,
        target_identifier_stream_byte_length: target_identifier_descriptor.total_byte_length,
        target_identifier_stream_chunk_count,
        target_identifier_stream_descriptor_hash_count,
        target_identifier_stream_descriptor_byte_length,
        target_order_stream_byte_length: target_order_descriptor.total_byte_length,
        target_order_stream_chunk_count,
        target_order_stream_descriptor_hash_count,
        target_order_stream_descriptor_byte_length,
        ciphertext_stream_corpus_byte_length,
        ciphertext_stream_corpus_chunk_count,
        canonical_payload_byte_length,
        canonical_payload_framing_byte_length,
        canonical_envelope_binding_hash_count: UNSIGNED_ENVELOPE_BINDING_HASH_COUNT,
        canonical_envelope_byte_length,
        canonical_envelope_framing_byte_length,
        complete_public_object_byte_length,
    })
}

fn decode_unsigned_envelope(
    carrier: &[u8],
    expected_object_type: FoundationObjectType,
) -> Result<ObjectEnvelope, SelectedMaterialTransportAccountingError> {
    let envelope = ObjectEnvelope::decode(carrier, &CanonicalDecodeLimits::default())
        .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?;
    if envelope.object_type != expected_object_type
        || envelope.producer_participant_id.is_some()
        || envelope.producer_sequence != 0
        || !envelope.ordered_prerequisite_hashes.is_empty()
        || envelope
            .encode()
            .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)?
            != carrier
    {
        return Err(SelectedMaterialTransportAccountingError::CanonicalEncoding);
    }
    Ok(envelope)
}

fn canonical_framing_byte_length(
    canonical_byte_length: u64,
    raw_binding_hash_count: u64,
    nested_canonical_byte_length: u64,
) -> Result<u64, SelectedMaterialTransportAccountingError> {
    let raw_binding_hash_byte_length = raw_binding_hash_count
        .checked_mul(
            u64::try_from(Hash512::BYTE_LENGTH)
                .map_err(|_| SelectedMaterialTransportAccountingError::IntegerOverflow)?,
        )
        .ok_or(SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    canonical_byte_length
        .checked_sub(raw_binding_hash_byte_length)
        .and_then(|length| length.checked_sub(nested_canonical_byte_length))
        .ok_or(SelectedMaterialTransportAccountingError::CanonicalEncoding)
}

fn deterministic_stream_descriptor(
    total_byte_length: u64,
    chunk_digest_prefix: u8,
    full_digest_prefix: u8,
) -> Result<StreamDescriptor, SelectedMaterialTransportAccountingError> {
    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    if total_byte_length == 0 {
        return Err(SelectedMaterialTransportAccountingError::CanonicalEncoding);
    }
    let chunk_count = total_byte_length.div_ceil(stream_chunk_byte_length);
    let chunk_count = usize::try_from(chunk_count)
        .map_err(|_| SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    StreamDescriptor::new(
        total_byte_length,
        deterministic_hash_catalog(chunk_count, chunk_digest_prefix)?,
        deterministic_hash(full_digest_prefix, 0)?,
    )
    .map_err(|_| SelectedMaterialTransportAccountingError::CanonicalEncoding)
}

fn descriptor_chunk_count(
    descriptor: &StreamDescriptor,
) -> Result<u64, SelectedMaterialTransportAccountingError> {
    u64::try_from(descriptor.ordered_chunk_digests.len())
        .map_err(|_| SelectedMaterialTransportAccountingError::IntegerOverflow)
}

fn deterministic_hash_catalog(
    count: usize,
    prefix: u8,
) -> Result<Vec<Hash512>, SelectedMaterialTransportAccountingError> {
    (0..count)
        .map(|ordinal| deterministic_hash(prefix, ordinal))
        .collect()
}

fn deterministic_hash(
    prefix: u8,
    ordinal: usize,
) -> Result<Hash512, SelectedMaterialTransportAccountingError> {
    let ordinal = u64::try_from(ordinal)
        .map_err(|_| SelectedMaterialTransportAccountingError::IntegerOverflow)?;
    let mut bytes = [prefix; Hash512::BYTE_LENGTH];
    bytes[..size_of::<u64>()].copy_from_slice(&ordinal.to_le_bytes());
    Ok(Hash512::from_bytes(bytes))
}

fn encoded_byte_length(encoded: Vec<u8>) -> Result<u64, SelectedMaterialTransportAccountingError> {
    slice_byte_length(&encoded)
}

fn slice_byte_length(bytes: &[u8]) -> Result<u64, SelectedMaterialTransportAccountingError> {
    u64::try_from(bytes.len())
        .map_err(|_| SelectedMaterialTransportAccountingError::IntegerOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_private_vss_mailbox_accounting_counts_each_canonical_object_once() {
        let accounting = derive_selected_private_vss_mailbox_transport_accounting()
            .expect("selected private VSS mailbox accounting derives");
        let transport = accounting.canonical_transport_primitive();
        let participant_count = u64::from(accounting.participant_count());

        assert_eq!(
            accounting.physical_payload_stream_count(),
            participant_count * participant_count
        );
        assert_eq!(
            accounting.complete_mailbox_byte_length(),
            transport.payload_byte_length() + transport.signed_mailbox_envelope_byte_length()
        );
        assert_eq!(
            accounting.one_dealer_upload_byte_length(),
            accounting.complete_mailbox_byte_length() * participant_count
        );
        assert_eq!(
            accounting.one_recipient_download_byte_length(),
            accounting.one_dealer_upload_byte_length()
        );
        assert_eq!(
            accounting.ceremony_upload_byte_length(),
            accounting.complete_mailbox_byte_length() * accounting.physical_payload_stream_count()
        );
        assert_eq!(
            accounting.ceremony_download_byte_length(),
            accounting.ceremony_upload_byte_length()
        );
        assert_eq!(
            accounting.private_mailbox_corpus_byte_length(),
            accounting.ceremony_upload_byte_length()
        );
        assert!(accounting.ordered_material_root_count_per_envelope() > 0);
        assert!(
            transport.signed_mailbox_envelope_byte_length()
                > transport.mailbox_fixed_cryptographic_material_byte_length()
                    + transport.stream_descriptor_byte_length()
        );
    }

    #[test]
    fn canonical_transport_primitives_remain_per_stream_not_route_totals() {
        let accounting = derive_selected_private_vss_mailbox_transport_accounting()
            .expect("selected private VSS mailbox accounting derives");
        let transport = accounting.canonical_transport_primitive();

        assert_eq!(
            transport.boundary_transfer_byte_length(),
            transport.payload_byte_length()
        );
        assert_eq!(
            transport.indexed_db_serialized_byte_length(),
            transport.payload_byte_length()
        );
        assert!(
            accounting.ceremony_upload_byte_length() > transport.boundary_transfer_byte_length()
        );
        assert!(
            accounting.private_mailbox_corpus_byte_length()
                > transport.indexed_db_serialized_byte_length()
        );
    }

    #[test]
    fn selected_unsigned_public_carriers_preserve_exact_and_ceiling_boundaries() {
        let accounting = derive_selected_unsigned_public_carrier_accounting()
            .expect("selected unsigned public carrier accounting derives");
        let aggregate = accounting.aggregate_public_carrier();
        let canonical_hash_byte_length =
            u64::try_from(Hash512::BYTE_LENGTH).expect("hash width fits u64");

        assert_eq!(accounting.unsigned_public_carrier_count(), 2);
        assert_eq!(accounting.unsigned_public_physical_stream_count(), 4);
        assert_eq!(
            aggregate.selected_ballot_object_hash_count(),
            u64::from(FOUNDATION_PROFILE.participant_count)
        );
        assert_eq!(
            aggregate.payload_binding_hash_count(),
            aggregate.selected_ballot_object_hash_count() + 1
        );
        assert_eq!(aggregate.physical_ciphertext_stream_count(), 2);
        assert_eq!(
            aggregate.one_stream_descriptor_hash_count(),
            aggregate.one_ciphertext_stream_chunk_count() + 1
        );
        assert_eq!(
            aggregate.ciphertext_stream_corpus_byte_length(),
            aggregate.one_ciphertext_stream_byte_length() * 2
        );
        assert_eq!(
            aggregate.ciphertext_stream_corpus_chunk_count(),
            aggregate.one_ciphertext_stream_chunk_count() * 2
        );
        assert_eq!(
            aggregate.canonical_payload_byte_length(),
            aggregate.canonical_payload_framing_byte_length()
                + aggregate.payload_binding_hash_count() * canonical_hash_byte_length
                + aggregate.one_stream_descriptor_byte_length() * 2
        );
        assert_eq!(aggregate.canonical_envelope_binding_hash_count(), 3);
        assert_eq!(
            aggregate.canonical_envelope_byte_length(),
            aggregate.canonical_envelope_framing_byte_length()
                + aggregate.canonical_envelope_binding_hash_count() * canonical_hash_byte_length
                + aggregate.canonical_payload_byte_length()
        );
        assert_eq!(
            aggregate.complete_public_object_byte_length(),
            aggregate.canonical_envelope_byte_length()
                + aggregate.ciphertext_stream_corpus_byte_length()
        );

        let replay_ceiling = accounting.evaluator_replay_codec_ceiling();
        let replay = replay_ceiling.carrier_accounting_at_codec_ceiling();
        assert_eq!(replay.payload_binding_hash_count(), 2);
        assert_eq!(replay.physical_ciphertext_stream_count(), 2);
        assert_eq!(
            replay.target_identifier_stream_byte_length(),
            replay_ceiling.target_ciphertext_stream_byte_length_ceiling()
        );
        assert_eq!(
            replay.target_order_stream_byte_length(),
            replay.target_identifier_stream_byte_length()
        );
        assert_eq!(
            replay.target_identifier_stream_chunk_count(),
            replay_ceiling.target_ciphertext_stream_chunk_count_ceiling()
        );
        assert_eq!(
            replay.target_order_stream_chunk_count(),
            replay.target_identifier_stream_chunk_count()
        );
        assert_eq!(
            replay.target_identifier_stream_descriptor_hash_count(),
            replay.target_identifier_stream_chunk_count() + 1
        );
        assert_eq!(
            replay.target_order_stream_descriptor_hash_count(),
            replay.target_order_stream_chunk_count() + 1
        );
        assert_eq!(
            replay.target_order_stream_descriptor_byte_length(),
            replay.target_identifier_stream_descriptor_byte_length()
        );
        assert_eq!(
            replay.ciphertext_stream_corpus_byte_length(),
            replay.target_identifier_stream_byte_length()
                + replay.target_order_stream_byte_length()
        );
        assert_eq!(
            replay.ciphertext_stream_corpus_chunk_count(),
            replay.target_identifier_stream_chunk_count()
                + replay.target_order_stream_chunk_count()
        );
        assert_eq!(
            replay.canonical_payload_byte_length(),
            replay.canonical_payload_framing_byte_length()
                + replay.payload_binding_hash_count() * canonical_hash_byte_length
                + replay.target_identifier_stream_descriptor_byte_length()
                + replay.target_order_stream_descriptor_byte_length()
        );
        assert_eq!(replay.canonical_envelope_binding_hash_count(), 3);
        assert_eq!(
            replay.canonical_envelope_byte_length(),
            replay.canonical_envelope_framing_byte_length()
                + replay.canonical_envelope_binding_hash_count() * canonical_hash_byte_length
                + replay.canonical_payload_byte_length()
        );
        assert_eq!(
            replay_ceiling.canonical_envelope_byte_length_ceiling(),
            replay.canonical_envelope_byte_length()
        );
        assert_eq!(
            replay.complete_public_object_byte_length(),
            replay.canonical_envelope_byte_length() + replay.ciphertext_stream_corpus_byte_length()
        );
        assert_eq!(
            replay_ceiling.complete_public_object_byte_length_ceiling(),
            replay.complete_public_object_byte_length()
        );
        assert_eq!(
            accounting.exact_evaluator_replay(),
            SelectedExactEvaluatorReplayCarrierAccounting::MissingGeneratedEvaluatorReplayDescriptors
        );
    }

    #[test]
    fn exact_replay_carrier_uses_generated_descriptors_without_ciphertext_bodies() {
        let codec_ceiling = two_component_data_ciphertext_canonical_byte_length_ceiling_at_level(
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .expect("selected target codec ceiling derives");
        let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .expect("chunk width fits u64");
        let shorter_length = codec_ceiling
            .checked_sub(chunk_byte_length)
            .expect("selected target ceiling spans multiple chunks");
        let identifier_descriptor = deterministic_stream_descriptor(codec_ceiling, 0x71, 0x72)
            .expect("identifier descriptor");
        let order_descriptor =
            deterministic_stream_descriptor(shorter_length, 0x73, 0x74).expect("order descriptor");

        let exact = derive_selected_evaluator_replay_public_carrier_accounting(
            &identifier_descriptor,
            &order_descriptor,
        )
        .expect("exact replay carrier derives from descriptors");
        assert_eq!(exact.target_identifier_stream_byte_length(), codec_ceiling);
        assert_eq!(exact.target_order_stream_byte_length(), shorter_length);
        assert!(
            exact.target_identifier_stream_chunk_count() > exact.target_order_stream_chunk_count()
        );
        assert!(
            exact.target_identifier_stream_descriptor_byte_length()
                > exact.target_order_stream_descriptor_byte_length()
        );
        let available = SelectedExactEvaluatorReplayCarrierAccounting::Available(exact);
        let SelectedExactEvaluatorReplayCarrierAccounting::Available(available_accounting) =
            available
        else {
            panic!("exact descriptor accounting must remain available");
        };
        assert_eq!(
            available_accounting.complete_public_object_byte_length(),
            exact.complete_public_object_byte_length()
        );

        let over_ceiling_length = codec_ceiling
            .checked_add(1)
            .expect("selected codec ceiling leaves integer headroom");
        let over_ceiling_descriptor =
            deterministic_stream_descriptor(over_ceiling_length, 0x75, 0x76)
                .expect("canonical descriptor can represent the refusal input");
        assert_eq!(
            derive_selected_evaluator_replay_public_carrier_accounting(
                &over_ceiling_descriptor,
                &order_descriptor,
            ),
            Err(SelectedMaterialTransportAccountingError::SelectedProfile)
        );
    }
}
