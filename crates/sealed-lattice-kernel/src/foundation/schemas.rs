use core::{fmt, str};
use std::collections::BTreeSet;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

use super::canonical_tuple::CanonicalDecodeBudget;
use super::{
    CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    Hash512, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ParticipantIdentity, RefusalReason,
    VerificationResult, derive_participant_identity,
    hash_foundation_tuple_512 as hash512,
};

pub const OBJECT_ENVELOPE_SCHEMA_IDENTIFIER: u16 = 0x0100;
pub const SIGNED_CARRIER_SCHEMA_IDENTIFIER: u16 = 0x0101;
pub const ROSTER_ENTRY_SCHEMA_IDENTIFIER: u16 = 0x0114;
pub const ROSTER_SCHEMA_IDENTIFIER: u16 = 0x0115;
pub const STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x1800;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = 3_309;
const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationProfile {
    pub protocol_name: &'static str,
    pub protocol_version: u16,
    pub participant_count: u16,
    pub state_witness_quorum: u16,
    pub stream_chunk_byte_length: usize,
    pub maximum_copied_buffer_byte_length: usize,
}

pub const FOUNDATION_PROFILE: FoundationProfile = FoundationProfile {
    protocol_name: "sealed-lattice",
    protocol_version: 1,
    participant_count: 10,
    state_witness_quorum: 7,
    stream_chunk_byte_length: 1_048_576,
    maximum_copied_buffer_byte_length: 1_572_864,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FoundationObjectType {
    StateReservation = 0x0051,
    StateOutputIntent = 0x0052,
    StateWitnessVote = 0x0053,
    RecoveryTransition = 0x0054,
}

impl FoundationObjectType {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            0x0051 => Some(Self::StateReservation),
            0x0052 => Some(Self::StateOutputIntent),
            0x0053 => Some(Self::StateWitnessVote),
            0x0054 => Some(Self::RecoveryTransition),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundationSchemaError {
    pub refusal_reason: RefusalReason,
    pub message: &'static str,
}

impl FoundationSchemaError {
    pub(super) fn new(refusal_reason: RefusalReason, message: &'static str) -> Self {
        Self {
            refusal_reason,
            message,
        }
    }
}

impl fmt::Display for FoundationSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for FoundationSchemaError {}

impl From<CanonicalCodecError> for FoundationSchemaError {
    fn from(error: CanonicalCodecError) -> Self {
        let refusal_reason = if error.kind == super::CanonicalCodecErrorKind::LimitExceeded {
            RefusalReason::OutsideSupportedProfile
        } else {
            RefusalReason::MalformedEncoding
        };
        Self::new(refusal_reason, "foundation value is not canonical")
    }
}

pub(super) type SchemaResult<Value> = Result<Value, FoundationSchemaError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub roster_position: u16,
    pub signing_verification_key: [u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
}

impl RosterEntry {
    fn validate(&self) -> SchemaResult<()> {
        validate_ml_dsa_65_verification_key(&self.signing_verification_key)
    }

    pub fn participant_identity(&self) -> SchemaResult<ParticipantIdentity> {
        validate_ml_dsa_65_verification_key(&self.signing_verification_key)?;
        Ok(derive_participant_identity(&self.signing_verification_key)?)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            ROSTER_ENTRY_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.roster_position),
                CanonicalItem::fixed_bytes(self.signing_verification_key)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, ROSTER_ENTRY_SCHEMA_IDENTIFIER, 2)?;
        let entry = Self {
            roster_position: read_u16(&tuple.items[0])?,
            signing_verification_key: read_fixed_bytes(&tuple.items[1])?,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    pub entries: Vec<RosterEntry>,
}

impl Roster {
    pub fn new(entries: Vec<RosterEntry>) -> SchemaResult<Self> {
        if entries.len() != usize::from(FOUNDATION_PROFILE.participant_count) {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "roster size does not match the supported profile",
            ));
        }
        let mut signing_keys = BTreeSet::new();
        let mut participant_identities = BTreeSet::new();
        for (expected_position, entry) in entries.iter().enumerate() {
            entry.validate()?;
            let participant_identity =
                derive_participant_identity(&entry.signing_verification_key)?;
            if usize::from(entry.roster_position) != expected_position {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "roster positions must be contiguous and increasing",
                ));
            }
            if !signing_keys.insert(entry.signing_verification_key.as_slice())
                || !participant_identities.insert(participant_identity)
            {
                return Err(FoundationSchemaError::new(
                    RefusalReason::DuplicateIdentity,
                    "roster contains a duplicate identity or signing key",
                ));
            }
        }
        Ok(Self { entries })
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Self::new(self.entries.clone())?;
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                entry
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            ROSTER_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::homogeneous_list(
                CanonicalItemType::NestedTuple,
                &entries,
            )?],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    pub(super) fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        preflight_roster_entry_count(bytes, limits)?;
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, ROSTER_SCHEMA_IDENTIFIER, 1)?;
        let entries = read_nested_tuple_list_with_budget(&tuple.items[0], limits, budget)?
            .iter()
            .map(RosterEntry::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(entries)
    }

    pub fn roster_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/foundation/roster/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDescriptor {
    pub total_byte_length: u64,
    pub ordered_chunk_digests: Vec<Hash512>,
    pub full_object_digest: Hash512,
}

impl StreamDescriptor {
    pub fn new(
        total_byte_length: u64,
        ordered_chunk_digests: Vec<Hash512>,
        full_object_digest: Hash512,
    ) -> SchemaResult<Self> {
        let descriptor = Self {
            total_byte_length,
            ordered_chunk_digests,
            full_object_digest,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub(super) fn validate(&self) -> SchemaResult<()> {
        if self.total_byte_length == 0 {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "streamed objects must be nonempty",
            ));
        }
        let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "stream chunk length does not fit u64",
                )
            })?;
        let expected_chunk_count = 1 + (self.total_byte_length - 1) / chunk_byte_length;
        let actual_chunk_count = u64::try_from(self.ordered_chunk_digests.len()).map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "stream chunk count does not fit u64",
            )
        })?;
        if actual_chunk_count != expected_chunk_count {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "stream chunk count does not match the total byte length",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub(super) fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate()?;
        let chunk_digests = self
            .ordered_chunk_digests
            .iter()
            .map(|digest| CanonicalItem::hash512(digest.into_bytes()))
            .collect::<Vec<_>>();
        Ok(CanonicalTuple::new(
            STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.total_byte_length),
                CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &chunk_digests)?,
                CanonicalItem::hash512(self.full_object_digest.into_bytes()),
            ],
        ))
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        preflight_stream_descriptor_chunk_count(bytes, limits)?;
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        Self::from_tuple(&tuple)
    }

    pub(super) fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER, 3)?;
        Self::new(
            read_u64(&tuple.items[0])?,
            read_hash_list(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectEnvelope {
    pub suite_id: Hash512,
    pub object_type: FoundationObjectType,
    pub ceremony_context_hash: Hash512,
    pub action_context_hash: Hash512,
    pub recovery_epoch: u64,
    pub recovery_transition_hash: Option<Hash512>,
    pub producer_participant_id: Option<ParticipantIdentity>,
    pub producer_sequence: u64,
    pub ordered_prerequisite_hashes: Vec<Hash512>,
    pub payload_bytes: Vec<u8>,
}

impl ObjectEnvelope {
    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let recovery_transition = self
            .recovery_transition_hash
            .map(|hash| CanonicalItem::hash512(hash.into_bytes()));
        let producer = self
            .producer_participant_id
            .map(|identity| CanonicalItem::participant_identity(identity.into_bytes()));
        let prerequisites = self
            .ordered_prerequisite_hashes
            .iter()
            .map(|hash| CanonicalItem::hash512(hash.into_bytes()))
            .collect::<Vec<_>>();
        Ok(CanonicalTuple::new(
            OBJECT_ENVELOPE_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::ascii(FOUNDATION_PROFILE.protocol_name)?,
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::unsigned16(self.object_type.canonical_code()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::unsigned64(self.recovery_epoch),
                CanonicalItem::optional(CanonicalItemType::Hash512, recovery_transition.as_ref())?,
                CanonicalItem::optional(CanonicalItemType::ParticipantIdentity, producer.as_ref())?,
                CanonicalItem::unsigned64(self.producer_sequence),
                CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &prerequisites)?,
                CanonicalItem::variable_bytes(self.payload_bytes.clone())?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    pub(super) fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, OBJECT_ENVELOPE_SCHEMA_IDENTIFIER, 12)?;
        if read_ascii(&tuple.items[0])? != FOUNDATION_PROFILE.protocol_name
            || read_u16(&tuple.items[1])? != FOUNDATION_PROFILE.protocol_version
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::UnsupportedVersionOrSuite,
                "object protocol name or version is unsupported",
            ));
        }
        let object_type = FoundationObjectType::from_canonical_code(read_u16(&tuple.items[3])?)
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::MalformedEncoding,
                    "object family is unassigned",
                )
            })?;
        Ok(Self {
            suite_id: read_hash(&tuple.items[2])?,
            object_type,
            ceremony_context_hash: read_hash(&tuple.items[4])?,
            action_context_hash: read_hash(&tuple.items[5])?,
            recovery_epoch: read_u64(&tuple.items[6])?,
            recovery_transition_hash: read_optional_hash(&tuple.items[7])?,
            producer_participant_id: read_optional_participant_identity(&tuple.items[8])?,
            producer_sequence: read_u64(&tuple.items[9])?,
            ordered_prerequisite_hashes: read_hash_list(&tuple.items[10])?,
            payload_bytes: read_variable_item(&tuple.items[11], CanonicalItemType::RawBytes)?
                .to_vec(),
        })
    }

    pub fn object_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/foundation/object/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCarrier {
    pub envelope: ObjectEnvelope,
    pub signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl SignedCarrier {
    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            SIGNED_CARRIER_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::variable_bytes(self.envelope.encode()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    pub(super) fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, SIGNED_CARRIER_SCHEMA_IDENTIFIER, 2)?;
        Ok(Self {
            envelope: ObjectEnvelope::decode_with_budget(
                read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?,
                limits,
                budget,
            )?,
            signature: read_fixed_bytes(&tuple.items[1])?,
        })
    }

    /// Verifies the carrier against the producer key selected by the external roster.
    pub fn verify_signature(&self, roster: &Roster) -> VerificationResult<()> {
        let Some(producer_participant_id) = self.envelope.producer_participant_id else {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        };
        let mut producer_roster_entry = None;
        for roster_entry in &roster.entries {
            let participant_identity = match roster_entry.participant_identity() {
                Ok(participant_identity) => participant_identity,
                Err(error) => return VerificationResult::refused(error.refusal_reason),
            };
            if participant_identity == producer_participant_id {
                producer_roster_entry = Some(roster_entry);
                break;
            }
        }
        let Some(producer_roster_entry) = producer_roster_entry else {
            return VerificationResult::refused(RefusalReason::WrongContext);
        };
        let roster_hash = match roster.roster_hash() {
            Ok(roster_hash) => roster_hash,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let message = match signature_message(&self.envelope, roster_hash) {
            Ok(message) => message,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let Ok(public_key) =
            ml_dsa_65::PublicKey::try_from_bytes(producer_roster_entry.signing_verification_key)
        else {
            return VerificationResult::refused(RefusalReason::InvalidSignature);
        };
        if !public_key.verify(
            message.as_bytes(),
            &self.signature,
            OBJECT_SIGNATURE_CONTEXT,
        ) {
            return VerificationResult::refused(RefusalReason::InvalidSignature);
        }

        VerificationResult::valid(())
    }
}

/// Derives the version-one signature message from the canonical envelope.
///
/// The producer cannot select or serialize a signature purpose. Deterministic
/// aggregate and evaluator objects are unsigned.
pub fn signature_message(envelope: &ObjectEnvelope, roster_hash: Hash512) -> SchemaResult<Hash512> {
    let signature_purpose = match envelope.object_type {
        FoundationObjectType::StateReservation => "state-reservation-intent",
        FoundationObjectType::StateOutputIntent => "state-output-intent",
        FoundationObjectType::StateWitnessVote => "state-witness-vote",
        FoundationObjectType::RecoveryTransition => "state-recovery-transition",
    };
    Ok(hash512(
        "sealed-lattice/foundation/signature-message/v1",
        &[
            CanonicalItem::hash512(envelope.object_hash()?.into_bytes()),
            CanonicalItem::hash512(roster_hash.into_bytes()),
            CanonicalItem::ascii(signature_purpose)?,
        ],
    )?)
}

fn validate_ml_dsa_65_verification_key(
    key: &[u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
) -> SchemaResult<()> {
    let verification_key = ml_dsa_65::PublicKey::try_from_bytes(*key).map_err(|_| {
        FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "signing verification key is not a canonical ML-DSA-65 public key",
        )
    })?;

    if verification_key.into_bytes() != *key {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "signing verification key is not a canonical ML-DSA-65 public key",
        ));
    }

    Ok(())
}

pub(super) fn require_header(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> SchemaResult<()> {
    if tuple.schema_identifier != schema_identifier || tuple.items.len() != item_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple has the wrong schema or item count",
        ));
    }
    if tuple.schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(FoundationSchemaError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "foundation tuple schema version is unsupported",
        ));
    }
    Ok(())
}

fn preflight_roster_entry_count(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<()> {
    const ITEM_TYPES: [CanonicalItemType; 1] = [CanonicalItemType::HomogeneousList];
    let Some(entry_list_bytes) =
        raw_schema_item(bytes, limits, ROSTER_SCHEMA_IDENTIFIER, &ITEM_TYPES, 0)
    else {
        return Ok(());
    };
    let Some(declared_entry_count) =
        raw_homogeneous_list_count(entry_list_bytes, CanonicalItemType::NestedTuple, limits)
    else {
        return Ok(());
    };
    if declared_entry_count != u32::from(FOUNDATION_PROFILE.participant_count) {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "roster size does not match the supported profile",
        ));
    }
    Ok(())
}

fn preflight_stream_descriptor_chunk_count(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<()> {
    const ITEM_TYPES: [CanonicalItemType; 3] = [
        CanonicalItemType::Unsigned64,
        CanonicalItemType::HomogeneousList,
        CanonicalItemType::Hash512,
    ];

    let Some(total_byte_length_bytes) = raw_schema_item(
        bytes,
        limits,
        STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
        &ITEM_TYPES,
        0,
    ) else {
        return Ok(());
    };
    let Some(total_byte_length) = read_exact_raw_u64(total_byte_length_bytes) else {
        return Ok(());
    };
    if total_byte_length == 0 {
        return Ok(());
    }
    let Some(chunk_digest_list_bytes) = raw_schema_item(
        bytes,
        limits,
        STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
        &ITEM_TYPES,
        1,
    ) else {
        return Ok(());
    };
    let Some(declared_chunk_count) =
        raw_homogeneous_list_count(chunk_digest_list_bytes, CanonicalItemType::Hash512, limits)
    else {
        return Ok(());
    };
    let chunk_byte_length =
        u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length).map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "stream chunk length does not fit u64",
            )
        })?;
    let expected_chunk_count = 1 + (total_byte_length - 1) / chunk_byte_length;
    if u64::from(declared_chunk_count) != expected_chunk_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "stream chunk count does not match the total byte length",
        ));
    }
    Ok(())
}

// This parser borrows only the complete outer schema shape. Its loop is bounded by the
// caller's fixed schema item list, and malformed payloads remain the canonical decoder's job.
fn raw_schema_item<'a>(
    bytes: &'a [u8],
    limits: &CanonicalDecodeLimits,
    expected_schema_identifier: u16,
    expected_item_types: &[CanonicalItemType],
    requested_item_index: usize,
) -> Option<&'a [u8]> {
    const TUPLE_HEADER_BYTE_LENGTH: usize = 8;
    const ITEM_HEADER_BYTE_LENGTH: usize = 6;

    if requested_item_index >= expected_item_types.len()
        || expected_item_types.len() > limits.maximum_item_count
        || bytes.len() > limits.maximum_tuple_byte_length
        || bytes.len() > limits.maximum_cumulative_work_byte_length
    {
        return None;
    }
    let tuple_header = bytes.get(..TUPLE_HEADER_BYTE_LENGTH)?;
    if read_raw_u16(tuple_header, 0)? != expected_schema_identifier
        || read_raw_u16(tuple_header, 2)? != FOUNDATION_SCHEMA_VERSION
        || usize::try_from(read_raw_u32(tuple_header, 4)?).ok()? != expected_item_types.len()
    {
        return None;
    }

    let mut requested_item = None;
    let mut total_item_byte_length = 0usize;
    let mut item_offset = TUPLE_HEADER_BYTE_LENGTH;
    for (item_index, expected_item_type) in expected_item_types.iter().enumerate() {
        let item_header_end = item_offset.checked_add(ITEM_HEADER_BYTE_LENGTH)?;
        let item_header = bytes.get(item_offset..item_header_end)?;
        if read_raw_u16(item_header, 0)? != expected_item_type.canonical_code() {
            return None;
        }
        let item_byte_length = usize::try_from(read_raw_u32(item_header, 2)?).ok()?;
        if item_byte_length > limits.maximum_item_byte_length {
            return None;
        }
        total_item_byte_length = total_item_byte_length.checked_add(item_byte_length)?;
        let item_end = item_header_end.checked_add(item_byte_length)?;
        let item_bytes = bytes.get(item_header_end..item_end)?;
        if item_index == requested_item_index {
            requested_item = Some(item_bytes);
        }
        item_offset = item_end;
    }
    if item_offset != bytes.len()
        || total_item_byte_length > limits.maximum_cumulative_allocation_byte_length
    {
        return None;
    }
    requested_item
}

fn raw_homogeneous_list_count(
    bytes: &[u8],
    expected_element_type: CanonicalItemType,
    limits: &CanonicalDecodeLimits,
) -> Option<u32> {
    if read_raw_u16(bytes, 0)? != expected_element_type.canonical_code() {
        return None;
    }
    let declared_count = read_raw_u32(bytes, 2)?;
    if usize::try_from(declared_count).ok()? > limits.maximum_item_count {
        return None;
    }
    Some(declared_count)
}

fn read_exact_raw_u64(bytes: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn read_raw_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value_end = offset.checked_add(2)?;
    let value: [u8; 2] = bytes.get(offset..value_end)?.try_into().ok()?;
    Some(u16::from_le_bytes(value))
}

fn read_raw_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value_end = offset.checked_add(4)?;
    let value: [u8; 4] = bytes.get(offset..value_end)?.try_into().ok()?;
    Some(u32::from_le_bytes(value))
}

pub(super) fn read_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple item has the wrong semantic type",
        ));
    }
    Ok(item.canonical_bytes())
}

pub(super) fn read_variable_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "foundation tuple item has the wrong semantic type",
        ));
    }
    item.variable_value_bytes().map_err(Into::into)
}

pub(super) fn read_u16(item: &CanonicalItem) -> SchemaResult<u16> {
    let bytes: [u8; 2] = read_item(item, CanonicalItemType::Unsigned16)?
        .try_into()
        .map_err(|_| FoundationSchemaError::new(RefusalReason::MalformedEncoding, "u16 length"))?;
    Ok(u16::from_le_bytes(bytes))
}

pub(super) fn read_u64(item: &CanonicalItem) -> SchemaResult<u64> {
    let bytes: [u8; 8] = read_item(item, CanonicalItemType::Unsigned64)?
        .try_into()
        .map_err(|_| FoundationSchemaError::new(RefusalReason::MalformedEncoding, "u64 length"))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn read_ascii(item: &CanonicalItem) -> SchemaResult<&str> {
    str::from_utf8(read_variable_item(item, CanonicalItemType::Ascii)?).map_err(|_| {
        FoundationSchemaError::new(RefusalReason::MalformedEncoding, "ASCII item is invalid")
    })
}

pub(super) fn read_fixed_bytes<const LENGTH: usize>(
    item: &CanonicalItem,
) -> SchemaResult<[u8; LENGTH]> {
    read_item(item, CanonicalItemType::RawBytes)?
        .try_into()
        .map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "fixed byte string has the wrong length",
            )
        })
}

pub(super) fn read_hash(item: &CanonicalItem) -> SchemaResult<Hash512> {
    let bytes: [u8; 64] = read_item(item, CanonicalItemType::Hash512)?
        .try_into()
        .map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::MalformedEncoding,
                "hash has the wrong length",
            )
        })?;
    Ok(Hash512::from_bytes(bytes))
}

fn read_optional_fixed_64_byte_value(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> SchemaResult<Option<[u8; 64]>> {
    let bytes = read_item(item, CanonicalItemType::Optional)?;
    if bytes.len() < 3 || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_type.canonical_code()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "optional 64-byte value has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 67 => {
            let value: [u8; 64] = bytes[3..].try_into().map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::MalformedEncoding,
                    "optional 64-byte value length is malformed",
                )
            })?;
            Ok(Some(value))
        }
        _ => Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "optional 64-byte value encoding is malformed",
        )),
    }
}

fn read_optional_hash(item: &CanonicalItem) -> SchemaResult<Option<Hash512>> {
    Ok(
        read_optional_fixed_64_byte_value(item, CanonicalItemType::Hash512)?
            .map(Hash512::from_bytes),
    )
}

fn read_optional_participant_identity(
    item: &CanonicalItem,
) -> SchemaResult<Option<ParticipantIdentity>> {
    Ok(
        read_optional_fixed_64_byte_value(item, CanonicalItemType::ParticipantIdentity)?
            .map(ParticipantIdentity::from_bytes),
    )
}

pub(super) fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
) -> SchemaResult<(usize, &[u8])> {
    let bytes = read_item(item, CanonicalItemType::HomogeneousList)?;
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_element_type.canonical_code()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "homogeneous list has the wrong element type",
        ));
    }
    Ok((
        u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize,
        &bytes[6..],
    ))
}

pub(super) fn read_hash_list(item: &CanonicalItem) -> SchemaResult<Vec<Hash512>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Hash512)?;
    if bytes.len()
        != count.checked_mul(64).ok_or_else(|| {
            FoundationSchemaError::new(
                RefusalReason::MalformedEncoding,
                "hash-list length overflows",
            )
        })?
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "hash-list byte length is malformed",
        ));
    }
    bytes
        .chunks_exact(64)
        .map(|chunk| {
            let value: [u8; 64] = chunk.try_into().map_err(|_| {
                FoundationSchemaError::new(RefusalReason::MalformedEncoding, "hash length")
            })?;
            Ok(Hash512::from_bytes(value))
        })
        .collect()
}

pub(super) fn read_nested_tuple_list_with_budget(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
) -> SchemaResult<Vec<CanonicalTuple>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if count > limits.maximum_item_count {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "nested tuple list exceeds the configured count limit",
        ));
    }
    let mut tuples = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let (tuple, consumed) = CanonicalTuple::decode_prefix(&bytes[offset..], limits, budget, 1)?;
        offset = offset.checked_add(consumed).ok_or_else(|| {
            FoundationSchemaError::new(
                RefusalReason::MalformedEncoding,
                "nested tuple list offset overflows",
            )
        })?;
        tuples.push(tuple);
    }
    if offset != bytes.len() {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "nested tuple list contains trailing bytes",
        ));
    }
    Ok(tuples)
}
