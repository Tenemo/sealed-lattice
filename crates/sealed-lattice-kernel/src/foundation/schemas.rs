use core::{fmt, str};
use std::collections::BTreeSet;

use fips203::{ml_kem_768, traits::SerDes as KemSerDes};
use fips204::{
    ml_dsa_65,
    traits::{SerDes as SignatureSerDes, Verifier},
};

use super::canonical_tuple::CanonicalDecodeBudget;
use super::{
    CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    Hash512, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ParticipantIdentity, RefusalReason,
    VerificationResult, derive_participant_identity, hash_foundation_tuple_512 as hash512,
};

pub const OBJECT_ENVELOPE_SCHEMA_IDENTIFIER: u16 = 0x0100;
pub const SIGNED_CARRIER_SCHEMA_IDENTIFIER: u16 = 0x0101;
pub const ROSTER_ENTRY_SCHEMA_IDENTIFIER: u16 = 0x0114;
pub const ROSTER_SCHEMA_IDENTIFIER: u16 = 0x0115;
pub const STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x1800;
pub(super) const EVALUATOR_REPLAY_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1502;
pub const ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH: usize = ml_kem_768::EK_LEN;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
pub const ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = 3_309;
const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";

/// Roster sizes for which the protocol formulas are defined. Only the
/// ten-participant prototype profile is selected and evidence-gated today.
pub const MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT: u16 = 3;
pub const MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT: u16 = 20;
pub(crate) const PROTOTYPE_PARTICIPANT_COUNT: u16 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationRosterParameters {
    pub participant_count: u16,
    pub active_fault_bound: u16,
    pub reconstruction_threshold: u16,
    pub finality_quorum: u16,
    pub state_witness_quorum: u16,
}

/// Derives the roster-dependent protocol parameters without selecting or
/// certifying that roster size. The passive reconstruction bound deliberately
/// remains independent of the strict asynchronous active-fault bound when
/// `n` is divisible by three.
pub const fn derive_foundation_roster_parameters(
    participant_count: u16,
) -> Option<FoundationRosterParameters> {
    if participant_count < MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT
        || participant_count > MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        return None;
    }

    let active_fault_bound = (participant_count - 1) / 3;
    let reconstruction_threshold = participant_count / 3 + 1;
    // Finality needs two signer quorums to intersect in more than f members.
    // State witnessing has an n-1 universe but also permits one independently
    // unsafe witness, which yields the same lower bound.
    let quorum = (participant_count + active_fault_bound) / 2 + 1;

    Some(FoundationRosterParameters {
        participant_count,
        active_fault_bound,
        reconstruction_threshold,
        finality_quorum: quorum,
        state_witness_quorum: quorum,
    })
}

const PROTOTYPE_ROSTER_PARAMETERS: FoundationRosterParameters =
    match derive_foundation_roster_parameters(PROTOTYPE_PARTICIPANT_COUNT) {
        Some(parameters) => parameters,
        None => panic!("the prototype participant count must be configurable"),
    };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationProfile {
    pub protocol_name: &'static str,
    pub protocol_version: u16,
    pub participant_count: u16,
    pub active_fault_bound: u16,
    pub reconstruction_threshold: u16,
    pub finality_quorum: u16,
    pub state_witness_quorum: u16,
    pub option_count: u16,
    pub minimum_score: u16,
    pub maximum_score: u16,
    pub maximum_identifier_byte_length: usize,
    pub stream_chunk_byte_length: usize,
    pub maximum_copied_buffer_byte_length: usize,
}

pub const FOUNDATION_PROFILE: FoundationProfile = FoundationProfile {
    protocol_name: "sealed-lattice",
    protocol_version: 1,
    participant_count: PROTOTYPE_ROSTER_PARAMETERS.participant_count,
    active_fault_bound: PROTOTYPE_ROSTER_PARAMETERS.active_fault_bound,
    reconstruction_threshold: PROTOTYPE_ROSTER_PARAMETERS.reconstruction_threshold,
    finality_quorum: PROTOTYPE_ROSTER_PARAMETERS.finality_quorum,
    state_witness_quorum: PROTOTYPE_ROSTER_PARAMETERS.state_witness_quorum,
    option_count: 20,
    minimum_score: 1,
    maximum_score: 10,
    maximum_identifier_byte_length: 128,
    stream_chunk_byte_length: 1_048_576,
    maximum_copied_buffer_byte_length: 8_388_608,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FoundationObjectType {
    PublicRandomnessCommitment = 0x0001,
    PublicRandomnessReveal = 0x0002,
    SetupIntent = 0x0010,
    PrivateShareAcceptance = 0x0011,
    Complaint = 0x0012,
    PublicSetupRecord = 0x0013,
    BallotPackage = 0x0020,
    BallotCandidateList = 0x0021,
    Aggregate = 0x0030,
    EvaluatorReplay = 0x0040,
    FinalitySignature = 0x0050,
    StateReservation = 0x0051,
    StateOutputIntent = 0x0052,
    StateWitnessVote = 0x0053,
    TargetDecryptionShare = 0x0060,
    StorageRootCommitment = 0x0070,
}

impl FoundationObjectType {
    pub const ALL: [Self; 16] = [
        Self::PublicRandomnessCommitment,
        Self::PublicRandomnessReveal,
        Self::SetupIntent,
        Self::PrivateShareAcceptance,
        Self::Complaint,
        Self::PublicSetupRecord,
        Self::BallotPackage,
        Self::BallotCandidateList,
        Self::Aggregate,
        Self::EvaluatorReplay,
        Self::FinalitySignature,
        Self::StateReservation,
        Self::StateOutputIntent,
        Self::StateWitnessVote,
        Self::TargetDecryptionShare,
        Self::StorageRootCommitment,
    ];

    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            0x0001 => Some(Self::PublicRandomnessCommitment),
            0x0002 => Some(Self::PublicRandomnessReveal),
            0x0010 => Some(Self::SetupIntent),
            0x0011 => Some(Self::PrivateShareAcceptance),
            0x0012 => Some(Self::Complaint),
            0x0013 => Some(Self::PublicSetupRecord),
            0x0020 => Some(Self::BallotPackage),
            0x0021 => Some(Self::BallotCandidateList),
            0x0030 => Some(Self::Aggregate),
            0x0040 => Some(Self::EvaluatorReplay),
            0x0050 => Some(Self::FinalitySignature),
            0x0051 => Some(Self::StateReservation),
            0x0052 => Some(Self::StateOutputIntent),
            0x0053 => Some(Self::StateWitnessVote),
            0x0060 => Some(Self::TargetDecryptionShare),
            0x0070 => Some(Self::StorageRootCommitment),
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
    pub mailbox_encapsulation_key: [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
}

impl RosterEntry {
    pub fn new(
        roster_position: u16,
        signing_verification_key: [u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
        mailbox_encapsulation_key: [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        let entry = Self {
            roster_position,
            signing_verification_key,
            mailbox_encapsulation_key,
        };
        entry.validate()?;
        Ok(entry)
    }

    fn validate(&self) -> SchemaResult<()> {
        if self.roster_position >= MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "roster position is outside the configurable range",
            ));
        }
        validate_ml_kem_768_encapsulation_key(&self.mailbox_encapsulation_key)
    }

    pub fn participant_identity(&self) -> SchemaResult<ParticipantIdentity> {
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
                CanonicalItem::fixed_bytes(self.mailbox_encapsulation_key)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, ROSTER_ENTRY_SCHEMA_IDENTIFIER, 3)?;
        let entry = Self {
            roster_position: read_u16(&tuple.items[0])?,
            signing_verification_key: read_fixed_bytes(&tuple.items[1])?,
            mailbox_encapsulation_key: read_fixed_bytes(&tuple.items[2])?,
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
        validate_roster_entries(&entries)?;
        Ok(Self { entries })
    }

    pub(crate) fn validate(&self) -> SchemaResult<()> {
        validate_roster_entries(&self.entries)
    }

    pub(crate) fn require_selected_profile_size(&self) -> SchemaResult<()> {
        if self.entries.len() != usize::from(FOUNDATION_PROFILE.participant_count) {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "roster size does not match the selected prototype profile",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
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

fn validate_roster_entries(entries: &[RosterEntry]) -> SchemaResult<()> {
    let participant_count = u16::try_from(entries.len()).ok();
    if participant_count
        .and_then(derive_foundation_roster_parameters)
        .is_none()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "roster size is outside the configurable range",
        ));
    }
    let mut signing_keys = BTreeSet::new();
    let mut mailbox_keys = BTreeSet::new();
    let mut participant_identities = BTreeSet::new();
    for (entry_index, entry) in entries.iter().enumerate() {
        entry.validate()?;
        if usize::from(entry.roster_position) != entry_index {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "roster positions must be consecutive and canonically ordered",
            ));
        }
        let participant_identity = derive_participant_identity(&entry.signing_verification_key)?;
        if !signing_keys.insert(entry.signing_verification_key.as_slice())
            || !mailbox_keys.insert(entry.mailbox_encapsulation_key.as_slice())
            || !participant_identities.insert(participant_identity)
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::DuplicateIdentity,
                "roster contains a duplicate identity, signing key, or mailbox key",
            ));
        }
    }
    Ok(())
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

/// The single canonical representation of a deterministic evaluator replay.
/// Board ingestion validates its dependency while the evaluator verifier owns
/// the two streamed ciphertext checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EvaluatorReplayPayload {
    verified_setup_source_hash: Hash512,
    verified_aggregate_source_hash: Hash512,
    target_identifier_descriptor: StreamDescriptor,
    target_order_descriptor: StreamDescriptor,
}

impl EvaluatorReplayPayload {
    pub(super) fn new(
        verified_setup_source_hash: Hash512,
        verified_aggregate_source_hash: Hash512,
        target_identifier_descriptor: StreamDescriptor,
        target_order_descriptor: StreamDescriptor,
    ) -> Self {
        Self {
            verified_setup_source_hash,
            verified_aggregate_source_hash,
            target_identifier_descriptor,
            target_order_descriptor,
        }
    }

    pub(super) const fn verified_setup_source_hash(&self) -> Hash512 {
        self.verified_setup_source_hash
    }

    pub(super) const fn verified_aggregate_source_hash(&self) -> Hash512 {
        self.verified_aggregate_source_hash
    }

    pub(super) const fn target_identifier_descriptor(&self) -> &StreamDescriptor {
        &self.target_identifier_descriptor
    }

    pub(super) const fn target_order_descriptor(&self) -> &StreamDescriptor {
        &self.target_order_descriptor
    }

    pub(super) fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        let target_identifier_tuple = CanonicalTuple::decode(
            &self.target_identifier_descriptor.encode()?,
            &CanonicalDecodeLimits::default(),
        )?;
        let target_order_tuple = CanonicalTuple::decode(
            &self.target_order_descriptor.encode()?,
            &CanonicalDecodeLimits::default(),
        )?;
        Ok(CanonicalTuple::new(
            EVALUATOR_REPLAY_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.verified_setup_source_hash.into_bytes()),
                CanonicalItem::hash512(self.verified_aggregate_source_hash.into_bytes()),
                CanonicalItem::nested_tuple(&target_identifier_tuple)?,
                CanonicalItem::nested_tuple(&target_order_tuple)?,
            ],
        ))
    }

    pub(super) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        Self::from_tuple(&tuple, limits)
    }

    pub(super) fn from_tuple(
        tuple: &CanonicalTuple,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        require_header(tuple, EVALUATOR_REPLAY_PAYLOAD_SCHEMA_IDENTIFIER, 4)?;
        Ok(Self::new(
            read_hash(&tuple.items[0])?,
            read_hash(&tuple.items[1])?,
            read_stream_descriptor_item(&tuple.items[2], limits)?,
            read_stream_descriptor_item(&tuple.items[3], limits)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectEnvelope {
    pub suite_id: Hash512,
    pub object_type: FoundationObjectType,
    pub ceremony_context_hash: Hash512,
    pub action_context_hash: Hash512,
    pub producer_participant_id: Option<ParticipantIdentity>,
    pub producer_sequence: u64,
    pub ordered_prerequisite_hashes: Vec<Hash512>,
    pub payload_bytes: Vec<u8>,
}

impl ObjectEnvelope {
    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
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
                CanonicalItem::optional(CanonicalItemType::ParticipantIdentity, producer.as_ref())?,
                CanonicalItem::unsigned64(self.producer_sequence),
                CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &prerequisites)?,
                CanonicalItem::variable_bytes(&self.payload_bytes)?,
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
        require_header(&tuple, OBJECT_ENVELOPE_SCHEMA_IDENTIFIER, 10)?;
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
            producer_participant_id: read_optional_participant_identity(&tuple.items[6])?,
            producer_sequence: read_u64(&tuple.items[7])?,
            ordered_prerequisite_hashes: read_hash_list(&tuple.items[8])?,
            payload_bytes: read_variable_item(&tuple.items[9], CanonicalItemType::RawBytes)?
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

    /// Verifies the carrier against the producer key selected by the anchored participant roster.
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
        FoundationObjectType::PublicRandomnessCommitment => "public-randomness-commitment",
        FoundationObjectType::PublicRandomnessReveal => "public-randomness-reveal",
        FoundationObjectType::SetupIntent => "setup-intent",
        FoundationObjectType::PrivateShareAcceptance => "private-share-acceptance",
        FoundationObjectType::Complaint => "setup-complaint",
        FoundationObjectType::PublicSetupRecord => "dealer-public-setup",
        FoundationObjectType::BallotPackage => "direct-ballot",
        FoundationObjectType::BallotCandidateList => "ballot-candidate-list",
        FoundationObjectType::Aggregate | FoundationObjectType::EvaluatorReplay => {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "deterministic aggregate and evaluator objects are unsigned",
            ));
        }
        FoundationObjectType::FinalitySignature => "target-finality",
        FoundationObjectType::StateReservation => "state-reservation-intent",
        FoundationObjectType::StateOutputIntent => "state-output-intent",
        FoundationObjectType::StateWitnessVote => "state-witness-vote",
        FoundationObjectType::TargetDecryptionShare => "target-release-output",
        FoundationObjectType::StorageRootCommitment => "storage-root-commitment",
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

fn validate_ml_kem_768_encapsulation_key(
    key: &[u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
) -> SchemaResult<()> {
    let encapsulation_key = ml_kem_768::EncapsKey::try_from_bytes(*key).map_err(|_| {
        FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "mailbox encapsulation key is not a canonical ML-KEM-768 public key",
        )
    })?;

    if encapsulation_key.into_bytes() != *key {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "mailbox encapsulation key is not a canonical ML-KEM-768 public key",
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
    if u16::try_from(declared_entry_count)
        .ok()
        .and_then(derive_foundation_roster_parameters)
        .is_none()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "roster size is outside the configurable range",
        ));
    }
    Ok(())
}

fn preflight_stream_descriptor_chunk_count(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<()> {
    const ITEM_TYPES: [CanonicalItemType; 2] = [
        CanonicalItemType::Unsigned64,
        CanonicalItemType::HomogeneousList,
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

pub(super) fn read_u32(item: &CanonicalItem) -> SchemaResult<u32> {
    let bytes: [u8; 4] = read_item(item, CanonicalItemType::Unsigned32)?
        .try_into()
        .map_err(|_| FoundationSchemaError::new(RefusalReason::MalformedEncoding, "u32 length"))?;
    Ok(u32::from_le_bytes(bytes))
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

fn read_stream_descriptor_item(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<StreamDescriptor> {
    if item.item_type() != CanonicalItemType::NestedTuple {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "evaluator replay stream descriptor has the wrong type",
        ));
    }
    let tuple = CanonicalTuple::decode(item.canonical_bytes(), limits)?;
    StreamDescriptor::from_tuple(&tuple)
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

#[cfg(test)]
mod tests {
    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes},
    };

    use super::*;

    #[test]
    fn configurable_roster_formulas_preserve_their_intersection_bounds() {
        assert_eq!(derive_foundation_roster_parameters(2), None);
        assert_eq!(derive_foundation_roster_parameters(21), None);

        for participant_count in
            MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
        {
            let parameters = derive_foundation_roster_parameters(participant_count)
                .expect("the documented roster range derives parameters");
            let n = i32::from(parameters.participant_count);
            let f = i32::from(parameters.active_fault_bound);
            let finality_quorum = i32::from(parameters.finality_quorum);
            let state_witness_quorum = i32::from(parameters.state_witness_quorum);

            assert_eq!(parameters.active_fault_bound, (participant_count - 1) / 3);
            assert!(n > 3 * f, "the active-fault bound must satisfy n > 3f");
            assert_eq!(
                parameters.reconstruction_threshold,
                participant_count / 3 + 1
            );
            let expected_quorum = (participant_count + parameters.active_fault_bound) / 2 + 1;
            assert_eq!(parameters.finality_quorum, expected_quorum);
            assert_eq!(parameters.state_witness_quorum, expected_quorum);
            assert!(
                2 * finality_quorum - n > f,
                "two finality quorums must share an honest signer"
            );
            assert!(
                2 * state_witness_quorum - (n - 1) > f + 1,
                "two state quorums must share a stable honest witness"
            );
            assert!(state_witness_quorum < n);
        }

        assert_eq!(
            derive_foundation_roster_parameters(PROTOTYPE_PARTICIPANT_COUNT),
            Some(FoundationRosterParameters {
                participant_count: 10,
                active_fault_bound: 3,
                reconstruction_threshold: 4,
                finality_quorum: 7,
                state_witness_quorum: 7,
            })
        );
    }

    fn roster_entries() -> Vec<RosterEntry> {
        (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                let mut signing_seed = [0x13_u8; 32];
                signing_seed[0] = u8::try_from(roster_position + 1).expect("test position fits u8");
                signing_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("reverse test position fits u8");
                let (signing_key, _) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);

                let mut mailbox_seed = [0x47_u8; 32];
                mailbox_seed[0] = u8::try_from(roster_position + 1).expect("test position fits u8");
                let mut mailbox_fallback_seed = [0xb2_u8; 32];
                mailbox_fallback_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("reverse test position fits u8");
                let (mailbox_key, _) =
                    ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);

                RosterEntry {
                    roster_position,
                    signing_verification_key: signing_key.into_bytes(),
                    mailbox_encapsulation_key: mailbox_key.into_bytes(),
                }
            })
            .collect()
    }

    #[test]
    fn roster_round_trip_preserves_both_post_quantum_key_families() {
        let roster = Roster::new(roster_entries()).expect("test roster is valid");
        let encoded = roster.encode().expect("roster encodes");
        let decoded =
            Roster::decode(&encoded, &CanonicalDecodeLimits::default()).expect("roster decodes");
        assert_eq!(decoded, roster);
        assert_eq!(
            decoded.roster_hash().expect("decoded roster hash derives"),
            roster.roster_hash().expect("roster hash derives")
        );

        let tuple = CanonicalTuple::decode(
            &roster.entries[0].encode().expect("entry encodes"),
            &CanonicalDecodeLimits::default(),
        )
        .expect("entry tuple decodes");
        assert_eq!(tuple.items.len(), 3);
        assert_eq!(
            read_u16(&tuple.items[0]).expect("roster position decodes"),
            0
        );
        assert_eq!(
            read_item(&tuple.items[2], CanonicalItemType::RawBytes)
                .expect("mailbox key bytes decode")
                .len(),
            ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH
        );
    }

    #[test]
    fn roster_schema_accepts_a_configurable_nonselected_size() {
        let entries = roster_entries().into_iter().take(3).collect();
        let roster = Roster::new(entries).expect("three-participant roster is structural");
        assert_eq!(
            roster
                .require_selected_profile_size()
                .expect_err("a structural roster is not selected-profile authority")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
        let encoded = roster.encode().expect("structural roster encodes");
        assert_eq!(
            Roster::decode(&encoded, &CanonicalDecodeLimits::default())
                .expect("structural roster decodes"),
            roster
        );
    }

    #[test]
    fn roster_requires_explicit_consecutive_positions_in_canonical_order() {
        let mut duplicate_position = roster_entries();
        duplicate_position[4].roster_position = 3;
        assert_eq!(
            Roster::new(duplicate_position)
                .expect_err("duplicate roster position must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut reordered_positions = roster_entries();
        reordered_positions.swap(2, 7);
        assert_eq!(
            Roster::new(reordered_positions)
                .expect_err("reordered roster positions must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut outside_range = roster_entries()[0].clone();
        outside_range.roster_position = MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT;
        assert_eq!(
            RosterEntry::new(
                outside_range.roster_position,
                outside_range.signing_verification_key,
                outside_range.mailbox_encapsulation_key,
            )
            .expect_err("out-of-range roster position must refuse")
            .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    #[test]
    fn roster_rejects_duplicate_signing_and_mailbox_keys_independently() {
        let entries = roster_entries();

        let mut duplicate_signing_key = entries.clone();
        duplicate_signing_key[6].signing_verification_key =
            duplicate_signing_key[2].signing_verification_key;
        assert_eq!(
            Roster::new(duplicate_signing_key)
                .expect_err("duplicate signing key refuses")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        let mut duplicate_mailbox_key = entries;
        duplicate_mailbox_key[8].mailbox_encapsulation_key =
            duplicate_mailbox_key[1].mailbox_encapsulation_key;
        assert_eq!(
            Roster::new(duplicate_mailbox_key)
                .expect_err("duplicate mailbox key refuses")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );
    }

    #[test]
    fn post_quantum_public_key_validation_matches_their_fips_encodings() {
        let mut malformed_mailbox_key = roster_entries();
        malformed_mailbox_key[0].mailbox_encapsulation_key =
            [0xff; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH];
        assert_eq!(
            Roster::new(malformed_mailbox_key)
                .expect_err("malformed mailbox key refuses")
                .refusal_reason,
            RefusalReason::MalformedEncoding
        );

        // FIPS 204 Algorithm 23 assigns exactly ten bits to every t1 coefficient,
        // so every fixed-width ML-DSA-65 public-key byte string is canonical.
        let arbitrary_signing_key = [0xff; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH];
        let decoded_signing_key = ml_dsa_65::PublicKey::try_from_bytes(arbitrary_signing_key)
            .expect("every fixed-width ML-DSA-65 public key decodes");
        assert_eq!(decoded_signing_key.into_bytes(), arbitrary_signing_key);

        let mut arbitrary_signing_key_roster = roster_entries();
        arbitrary_signing_key_roster[0].signing_verification_key = arbitrary_signing_key;
        Roster::new(arbitrary_signing_key_roster)
            .expect("arbitrary fixed-width ML-DSA-65 public key is canonical");

        let mut wrong_length_entry = CanonicalTuple::decode(
            &roster_entries()[0].encode().expect("entry encodes"),
            &CanonicalDecodeLimits::default(),
        )
        .expect("entry tuple decodes");
        wrong_length_entry.items[1] =
            CanonicalItem::fixed_bytes([0xff; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH - 1])
                .expect("wrong-width test item encodes");
        assert_eq!(
            RosterEntry::decode(
                &wrong_length_entry.encode().expect("entry tuple encodes"),
                &CanonicalDecodeLimits::default(),
            )
            .expect_err("wrong-width signing key refuses")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }

    #[test]
    fn every_assigned_object_type_round_trips_and_unsigned_types_refuse_signing() {
        for object_type in FoundationObjectType::ALL {
            assert_eq!(
                FoundationObjectType::from_canonical_code(object_type.canonical_code()),
                Some(object_type)
            );
        }
        for unassigned_code in [0, 3, 0x000f, 0x0022, 0x0041, 0x0054, 0xffff] {
            assert_eq!(
                FoundationObjectType::from_canonical_code(unassigned_code),
                None
            );
        }

        let signature_purposes = [
            (
                FoundationObjectType::PublicRandomnessCommitment,
                "public-randomness-commitment",
            ),
            (
                FoundationObjectType::PublicRandomnessReveal,
                "public-randomness-reveal",
            ),
            (FoundationObjectType::SetupIntent, "setup-intent"),
            (
                FoundationObjectType::PrivateShareAcceptance,
                "private-share-acceptance",
            ),
            (FoundationObjectType::Complaint, "setup-complaint"),
            (
                FoundationObjectType::PublicSetupRecord,
                "dealer-public-setup",
            ),
            (FoundationObjectType::BallotPackage, "direct-ballot"),
            (
                FoundationObjectType::BallotCandidateList,
                "ballot-candidate-list",
            ),
            (FoundationObjectType::FinalitySignature, "target-finality"),
            (
                FoundationObjectType::StateReservation,
                "state-reservation-intent",
            ),
            (
                FoundationObjectType::StateOutputIntent,
                "state-output-intent",
            ),
            (FoundationObjectType::StateWitnessVote, "state-witness-vote"),
            (
                FoundationObjectType::TargetDecryptionShare,
                "target-release-output",
            ),
            (
                FoundationObjectType::StorageRootCommitment,
                "storage-root-commitment",
            ),
        ];
        let roster_hash = Hash512::from_bytes([0x77; 64]);
        for (object_type, expected_purpose) in signature_purposes {
            let envelope = test_envelope(object_type);
            let expected = hash512(
                "sealed-lattice/foundation/signature-message/v1",
                &[
                    CanonicalItem::hash512(
                        envelope
                            .object_hash()
                            .expect("object hash derives")
                            .into_bytes(),
                    ),
                    CanonicalItem::hash512(roster_hash.into_bytes()),
                    CanonicalItem::ascii(expected_purpose).expect("purpose is printable ASCII"),
                ],
            )
            .expect("expected signature message derives");
            assert_eq!(
                signature_message(&envelope, roster_hash).expect("signature message derives"),
                expected
            );
        }

        for unsigned_type in [
            FoundationObjectType::Aggregate,
            FoundationObjectType::EvaluatorReplay,
        ] {
            assert_eq!(
                signature_message(&test_envelope(unsigned_type), roster_hash)
                    .expect_err("unsigned type refuses a signature purpose")
                    .refusal_reason,
                RefusalReason::WrongTypeOrLength
            );
        }
    }

    fn test_envelope(object_type: FoundationObjectType) -> ObjectEnvelope {
        ObjectEnvelope {
            suite_id: Hash512::from_bytes([0x11; 64]),
            object_type,
            ceremony_context_hash: Hash512::from_bytes([0x22; 64]),
            action_context_hash: Hash512::from_bytes([0x33; 64]),
            producer_participant_id: None,
            producer_sequence: 0,
            ordered_prerequisite_hashes: Vec::new(),
            payload_bytes: vec![0x44],
        }
    }
}
