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
    StabilizedDisplayText, VerificationResult, derive_participant_identity, hash512,
};

pub const OBJECT_ENVELOPE_SCHEMA_IDENTIFIER: u16 = 0x0100;
pub const SIGNED_CARRIER_SCHEMA_IDENTIFIER: u16 = 0x0101;
pub const PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER: u16 = 0x0102;
pub const MANIFEST_SCHEMA_IDENTIFIER: u16 = 0x0110;
pub const OPTION_DEFINITION_SCHEMA_IDENTIFIER: u16 = 0x0111;
pub const ACTION_DEFINITION_SCHEMA_IDENTIFIER: u16 = 0x0112;
pub const BOARD_POLICY_SCHEMA_IDENTIFIER: u16 = 0x0113;
pub const ROSTER_ENTRY_SCHEMA_IDENTIFIER: u16 = 0x0114;
pub const ROSTER_SCHEMA_IDENTIFIER: u16 = 0x0115;
pub const DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0116;
pub const ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x0117;
pub const SUITE_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0118;
pub const STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER: u16 = 0x1800;
pub const MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0200;
pub const MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER: u16 = 0x0201;
pub const SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER: u16 = 0x0202;
pub const PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0400;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = 3_309;
const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";
const ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH: usize = 1_184;
const ML_KEM_768_ENCODED_POLYNOMIAL_VECTOR_BYTE_LENGTH: usize = 1_152;
const ML_KEM_COEFFICIENT_MODULUS: u16 = 3_329;

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
    pub maximum_wasm_memory_byte_length: usize,
}

pub const FOUNDATION_PROFILE: FoundationProfile = FoundationProfile {
    protocol_name: "sealed-lattice",
    protocol_version: 1,
    participant_count: 10,
    active_fault_bound: 3,
    reconstruction_threshold: 4,
    finality_quorum: 7,
    state_witness_quorum: 7,
    option_count: 20,
    minimum_score: 1,
    maximum_score: 10,
    maximum_identifier_byte_length: 128,
    stream_chunk_byte_length: 1_048_576,
    maximum_copied_buffer_byte_length: 1_572_864,
    maximum_wasm_memory_byte_length: 402_653_184,
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
    RecoveryTransition = 0x0054,
    TargetDecryptionShare = 0x0060,
    StorageRootCommitment = 0x0070,
}

impl FoundationObjectType {
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
            0x0054 => Some(Self::RecoveryTransition),
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
pub struct OptionDefinition {
    pub option_index: u16,
    pub option_identifier: String,
    pub display_label: StabilizedDisplayText,
}

impl OptionDefinition {
    pub fn new(
        option_index: u16,
        option_identifier: String,
        display_label: StabilizedDisplayText,
    ) -> SchemaResult<Self> {
        validate_nonempty_ascii(
            &option_identifier,
            "option identifier must be nonempty ASCII",
        )?;
        if display_label.as_str().is_empty() {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "option display label must be nonempty",
            ));
        }
        Ok(Self {
            option_index,
            option_identifier,
            display_label,
        })
    }

    pub fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(
            self.option_index,
            self.option_identifier.clone(),
            self.display_label.clone(),
        )?;
        Ok(CanonicalTuple::new(
            OPTION_DEFINITION_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.option_index),
                CanonicalItem::ascii(&self.option_identifier)?,
                CanonicalItem::display_text(&self.display_label)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, OPTION_DEFINITION_SCHEMA_IDENTIFIER, 3)?;
        Self::new(
            read_u16(&tuple.items[0])?,
            read_ascii(&tuple.items[1])?.to_owned(),
            read_display_text(&tuple.items[2])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub display_title: StabilizedDisplayText,
    pub options: Vec<OptionDefinition>,
}

impl Manifest {
    pub fn new(
        display_title: StabilizedDisplayText,
        options: Vec<OptionDefinition>,
    ) -> SchemaResult<Self> {
        if options.len() != usize::from(FOUNDATION_PROFILE.option_count) {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "manifest must contain exactly twenty options",
            ));
        }
        let mut identifiers = BTreeSet::new();
        for (expected_index, option) in options.iter().enumerate() {
            OptionDefinition::new(
                option.option_index,
                option.option_identifier.clone(),
                option.display_label.clone(),
            )?;
            if usize::from(option.option_index) != expected_index {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "manifest option indexes must be contiguous and increasing",
                ));
            }
            if !identifiers.insert(option.option_identifier.as_str()) {
                return Err(FoundationSchemaError::new(
                    RefusalReason::DuplicateIdentity,
                    "manifest option identifiers must be unique",
                ));
            }
        }
        Ok(Self {
            display_title,
            options,
        })
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Self::new(self.display_title.clone(), self.options.clone())?;
        let option_items = self
            .options
            .iter()
            .map(|option| {
                option
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            MANIFEST_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::display_text(&self.display_title)?,
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &option_items)?,
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
        preflight_manifest_option_count(bytes, limits)?;
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, MANIFEST_SCHEMA_IDENTIFIER, 2)?;
        let display_title = read_display_text(&tuple.items[0])?;
        let option_tuples = read_nested_tuple_list_with_budget(&tuple.items[1], limits, budget)?;
        let options = option_tuples
            .iter()
            .map(OptionDefinition::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(display_title, options)
    }

    pub fn manifest_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/foundation/manifest/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionDefinition {
    pub top_count: u16,
    pub submission_cutoff_unix_milliseconds: u64,
}

impl ActionDefinition {
    pub fn new(top_count: u16, submission_cutoff_unix_milliseconds: u64) -> SchemaResult<Self> {
        if !(1..=FOUNDATION_PROFILE.option_count).contains(&top_count) {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "top count is outside the supported range",
            ));
        }
        Ok(Self {
            top_count,
            submission_cutoff_unix_milliseconds,
        })
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Self::new(self.top_count, self.submission_cutoff_unix_milliseconds)?;
        Ok(CanonicalTuple::new(
            ACTION_DEFINITION_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.top_count),
                CanonicalItem::unsigned64(self.submission_cutoff_unix_milliseconds),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, ACTION_DEFINITION_SCHEMA_IDENTIFIER, 2)?;
        Self::new(read_u16(&tuple.items[0])?, read_u64(&tuple.items[1])?)
    }

    pub fn action_definition_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/foundation/action-definition/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    pub fn submission_cutoff_hash(&self, action_context_hash: Hash512) -> SchemaResult<Hash512> {
        Self::new(self.top_count, self.submission_cutoff_unix_milliseconds)?;
        Ok(hash512(
            "sealed-lattice/foundation/submission-cutoff/v1",
            &[
                CanonicalItem::hash512(action_context_hash.into_bytes()),
                CanonicalItem::unsigned64(self.submission_cutoff_unix_milliseconds),
            ],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardPolicy {
    pub board_origin_identifier: String,
}

impl BoardPolicy {
    pub fn new(board_origin_identifier: String) -> SchemaResult<Self> {
        CanonicalItem::ascii(&board_origin_identifier)?;
        Ok(Self {
            board_origin_identifier,
        })
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Self::new(self.board_origin_identifier.clone())?;
        Ok(CanonicalTuple::new(
            BOARD_POLICY_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::ascii(&self.board_origin_identifier)?],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, BOARD_POLICY_SCHEMA_IDENTIFIER, 1)?;
        Self::new(read_ascii(&tuple.items[0])?.to_owned())
    }

    pub fn board_policy_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/foundation/board-policy/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub roster_position: u16,
    pub signing_verification_key: [u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
    pub mailbox_encapsulation_key: [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
}

impl RosterEntry {
    fn validate(&self) -> SchemaResult<()> {
        validate_ml_dsa_65_verification_key(&self.signing_verification_key)?;
        validate_ml_kem_768_encapsulation_key(&self.mailbox_encapsulation_key)
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
        if entries.len() != usize::from(FOUNDATION_PROFILE.participant_count) {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "roster size does not match the supported profile",
            ));
        }
        let mut signing_keys = BTreeSet::new();
        let mut mailbox_keys = BTreeSet::new();
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
                || !mailbox_keys.insert(entry.mailbox_encapsulation_key.as_slice())
                || !participant_identities.insert(participant_identity)
            {
                return Err(FoundationSchemaError::new(
                    RefusalReason::DuplicateIdentity,
                    "roster contains a duplicate identity or key",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DistributionKind {
    Ternary = 1,
    CenteredBinomial = 2,
}

impl DistributionKind {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Ternary),
            2 => Some(Self::CenteredBinomial),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributionRecord {
    pub purpose: u16,
    pub kind: DistributionKind,
    pub parameter: u64,
}

impl DistributionRecord {
    pub fn new(purpose: u16, kind: DistributionKind, parameter: u64) -> SchemaResult<Self> {
        let expected_kind = match purpose {
            1 | 3 | 8 | 11 => DistributionKind::Ternary,
            2 | 4 | 5 | 6 | 7 | 9 | 10 | 12 => DistributionKind::CenteredBinomial,
            _ => {
                return Err(FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "distribution purpose is not assigned in the supported profile",
                ));
            }
        };
        let expected_parameter = match expected_kind {
            DistributionKind::Ternary => 0,
            DistributionKind::CenteredBinomial => 2,
        };
        if kind != expected_kind || parameter != expected_parameter {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "distribution does not match its supported purpose",
            ));
        }
        Ok(Self {
            purpose,
            kind,
            parameter,
        })
    }

    pub(super) fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(self.purpose, self.kind, self.parameter)?;
        Ok(CanonicalTuple::new(
            DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.purpose),
                CanonicalItem::unsigned16(self.kind.canonical_code()),
                CanonicalItem::unsigned64(self.parameter),
            ],
        ))
    }

    pub(super) fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER, 3)?;
        let kind =
            DistributionKind::from_canonical_code(read_u16(&tuple.items[1])?).ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "distribution kind is not assigned",
                )
            })?;
        Self::new(read_u16(&tuple.items[0])?, kind, read_u64(&tuple.items[2])?)
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        Self::from_tuple(&tuple)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArtifactKind {
    EncoderAndBallotLayout = 1,
    VerifiableSecretSharingProfile = 2,
    LatticeCommitmentProfile = 3,
    ProofProfileSet = 4,
    EvaluatorProgramSet = 5,
    TargetDecryptionProfile = 6,
}

impl ArtifactKind {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::EncoderAndBallotLayout),
            2 => Some(Self::VerifiableSecretSharingProfile),
            3 => Some(Self::LatticeCommitmentProfile),
            4 => Some(Self::ProofProfileSet),
            5 => Some(Self::EvaluatorProgramSet),
            6 => Some(Self::TargetDecryptionProfile),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactReference {
    pub artifact_kind: ArtifactKind,
    pub byte_length: u64,
    pub artifact_hash: Hash512,
}

impl ArtifactReference {
    pub fn new(
        artifact_kind: ArtifactKind,
        byte_length: u64,
        artifact_hash: Hash512,
    ) -> SchemaResult<Self> {
        if byte_length == 0 {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "suite artifacts must be nonempty",
            ));
        }
        Ok(Self {
            artifact_kind,
            byte_length,
            artifact_hash,
        })
    }

    pub fn from_artifact_bytes(
        artifact_kind: ArtifactKind,
        canonical_artifact_bytes: &[u8],
    ) -> SchemaResult<Self> {
        let byte_length = u64::try_from(canonical_artifact_bytes.len()).map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "artifact byte length does not fit u64",
            )
        })?;
        if byte_length == 0 {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "suite artifacts must be nonempty",
            ));
        }
        let artifact_hash = artifact_hash(artifact_kind, byte_length, canonical_artifact_bytes)?;
        Self::new(artifact_kind, byte_length, artifact_hash)
    }

    pub fn verify_artifact_bytes(&self, canonical_artifact_bytes: &[u8]) -> SchemaResult<()> {
        Self::new(self.artifact_kind, self.byte_length, self.artifact_hash)?;
        let actual_byte_length = u64::try_from(canonical_artifact_bytes.len()).map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "artifact byte length does not fit u64",
            )
        })?;
        if actual_byte_length != self.byte_length {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "suite artifact byte length does not match its reference",
            ));
        }
        if artifact_hash(
            self.artifact_kind,
            actual_byte_length,
            canonical_artifact_bytes,
        )? != self.artifact_hash
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongHashOrRoot,
                "suite artifact bytes do not match their reference",
            ));
        }
        Ok(())
    }

    pub(super) fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(self.artifact_kind, self.byte_length, self.artifact_hash)?;
        Ok(CanonicalTuple::new(
            ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.artifact_kind.canonical_code()),
                CanonicalItem::unsigned64(self.byte_length),
                CanonicalItem::hash512(self.artifact_hash.into_bytes()),
            ],
        ))
    }

    pub(super) fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER, 3)?;
        let artifact_kind = ArtifactKind::from_canonical_code(read_u16(&tuple.items[0])?)
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "artifact kind is not assigned",
                )
            })?;
        Self::new(
            artifact_kind,
            read_u64(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
        )
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        Self::from_tuple(&tuple)
    }
}

fn artifact_hash(
    artifact_kind: ArtifactKind,
    byte_length: u64,
    canonical_artifact_bytes: &[u8],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        "sealed-lattice/foundation/suite-artifact/v1",
        &[
            CanonicalItem::unsigned16(artifact_kind.canonical_code()),
            CanonicalItem::unsigned64(byte_length),
            CanonicalItem::variable_bytes(canonical_artifact_bytes)?,
        ],
    )?)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofObjectHeader {
    pub canonical_application_statement: Vec<u8>,
}

impl ProofObjectHeader {
    pub fn encode(&self, limits: &CanonicalDecodeLimits) -> SchemaResult<Vec<u8>> {
        CanonicalTuple::decode(&self.canonical_application_statement, limits)?;
        self.encode_prevalidated()
    }

    pub(super) fn encode_prevalidated(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::variable_bytes(
                &self.canonical_application_statement,
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
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER, 1)?;
        let canonical_application_statement =
            read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?.to_vec();
        CanonicalTuple::decode_with_budget(&canonical_application_statement, limits, budget)?;
        Ok(Self {
            canonical_application_statement,
        })
    }
}

pub fn ceremony_context_hash(
    suite_id: Hash512,
    manifest_hash: Hash512,
    roster_hash: Hash512,
    ceremony_identifier: &str,
) -> SchemaResult<Hash512> {
    validate_context_identifier(ceremony_identifier)?;
    Ok(hash512(
        "sealed-lattice/foundation/ceremony-context/v1",
        &[
            CanonicalItem::hash512(suite_id.into_bytes()),
            CanonicalItem::hash512(manifest_hash.into_bytes()),
            CanonicalItem::hash512(roster_hash.into_bytes()),
            CanonicalItem::ascii(ceremony_identifier)?,
        ],
    )?)
}

pub fn action_context_hash(
    ceremony_context_hash: Hash512,
    action_identifier: &str,
    action_definition_hash: Hash512,
    board_policy_hash: Hash512,
) -> SchemaResult<Hash512> {
    validate_context_identifier(action_identifier)?;
    Ok(hash512(
        "sealed-lattice/foundation/action-context/v1",
        &[
            CanonicalItem::hash512(ceremony_context_hash.into_bytes()),
            CanonicalItem::ascii(action_identifier)?,
            CanonicalItem::hash512(action_definition_hash.into_bytes()),
            CanonicalItem::hash512(board_policy_hash.into_bytes()),
        ],
    )?)
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
        FoundationObjectType::FinalitySignature => "target-finality",
        FoundationObjectType::StateReservation => "state-reservation-intent",
        FoundationObjectType::StateOutputIntent => "state-output-intent",
        FoundationObjectType::StateWitnessVote => "state-witness-vote",
        FoundationObjectType::RecoveryTransition => "state-recovery-transition",
        FoundationObjectType::TargetDecryptionShare => "target-release-output",
        FoundationObjectType::StorageRootCommitment => "storage-root-commitment",
        FoundationObjectType::Aggregate | FoundationObjectType::EvaluatorReplay => {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "deterministic aggregate and evaluator objects are unsigned",
            ));
        }
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

fn validate_context_identifier(identifier: &str) -> SchemaResult<()> {
    if identifier.is_empty() || identifier.len() > FOUNDATION_PROFILE.maximum_identifier_byte_length
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "identifier is empty or exceeds the supported byte limit",
        ));
    }
    CanonicalItem::ascii(identifier)?;
    Ok(())
}

fn validate_nonempty_ascii(value: &str, message: &'static str) -> SchemaResult<()> {
    if value.is_empty() {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            message,
        ));
    }
    CanonicalItem::ascii(value)?;
    Ok(())
}

fn validate_ml_kem_768_encapsulation_key(
    key: &[u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
) -> SchemaResult<()> {
    for packed_coefficients in
        key[..ML_KEM_768_ENCODED_POLYNOMIAL_VECTOR_BYTE_LENGTH].chunks_exact(3)
    {
        let first_coefficient =
            u16::from(packed_coefficients[0]) | (u16::from(packed_coefficients[1] & 0x0f) << 8);
        let second_coefficient =
            (u16::from(packed_coefficients[1]) >> 4) | (u16::from(packed_coefficients[2]) << 4);
        if first_coefficient >= ML_KEM_COEFFICIENT_MODULUS
            || second_coefficient >= ML_KEM_COEFFICIENT_MODULUS
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::MalformedEncoding,
                "mailbox encapsulation key contains a non-canonical coefficient",
            ));
        }
    }
    Ok(())
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

fn preflight_manifest_option_count(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<()> {
    const ITEM_TYPES: [CanonicalItemType; 2] = [
        CanonicalItemType::DisplayText,
        CanonicalItemType::HomogeneousList,
    ];

    let Some(option_list_bytes) =
        raw_schema_item(bytes, limits, MANIFEST_SCHEMA_IDENTIFIER, &ITEM_TYPES, 1)
    else {
        return Ok(());
    };
    let Some(declared_option_count) =
        raw_homogeneous_list_count(option_list_bytes, CanonicalItemType::NestedTuple, limits)
    else {
        return Ok(());
    };
    if declared_option_count != u32::from(FOUNDATION_PROFILE.option_count) {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "manifest must contain exactly twenty options",
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

pub(super) fn optional_u16(value: Option<u16>) -> SchemaResult<CanonicalItem> {
    optional_fixed_integer(
        value,
        CanonicalItemType::Unsigned16,
        CanonicalItem::unsigned16,
    )
}

pub(super) fn optional_u32(value: Option<u32>) -> SchemaResult<CanonicalItem> {
    optional_fixed_integer(
        value,
        CanonicalItemType::Unsigned32,
        CanonicalItem::unsigned32,
    )
}

pub(super) fn optional_u64(value: Option<u64>) -> SchemaResult<CanonicalItem> {
    optional_fixed_integer(
        value,
        CanonicalItemType::Unsigned64,
        CanonicalItem::unsigned64,
    )
}

fn optional_fixed_integer<Value>(
    value: Option<Value>,
    item_type: CanonicalItemType,
    encode: impl FnOnce(Value) -> CanonicalItem,
) -> SchemaResult<CanonicalItem> {
    let item = value.map(encode);
    Ok(CanonicalItem::optional(item_type, item.as_ref())?)
}

pub(super) fn read_optional_u16(item: &CanonicalItem) -> SchemaResult<Option<u16>> {
    read_optional_fixed_integer(item, CanonicalItemType::Unsigned16, u16::from_le_bytes)
}

pub(super) fn read_optional_u32(item: &CanonicalItem) -> SchemaResult<Option<u32>> {
    read_optional_fixed_integer(item, CanonicalItemType::Unsigned32, u32::from_le_bytes)
}

pub(super) fn read_optional_u64(item: &CanonicalItem) -> SchemaResult<Option<u64>> {
    read_optional_fixed_integer(item, CanonicalItemType::Unsigned64, u64::from_le_bytes)
}

fn read_optional_fixed_integer<const BYTE_LENGTH: usize, Value>(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
    decode: impl FnOnce([u8; BYTE_LENGTH]) -> Value,
) -> SchemaResult<Option<Value>> {
    let bytes = read_item(item, CanonicalItemType::Optional)?;
    if bytes.len() < 3 || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_type.canonical_code()
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "optional integer has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 3 + BYTE_LENGTH => {
            let value_bytes: [u8; BYTE_LENGTH] = bytes[3..].try_into().map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::MalformedEncoding,
                    "optional integer length is malformed",
                )
            })?;
            Ok(Some(decode(value_bytes)))
        }
        _ => Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "optional integer encoding is malformed",
        )),
    }
}

pub(super) fn read_ascii(item: &CanonicalItem) -> SchemaResult<&str> {
    str::from_utf8(read_variable_item(item, CanonicalItemType::Ascii)?).map_err(|_| {
        FoundationSchemaError::new(RefusalReason::MalformedEncoding, "ASCII item is invalid")
    })
}

pub(super) fn read_display_text(item: &CanonicalItem) -> SchemaResult<StabilizedDisplayText> {
    StabilizedDisplayText::from_canonical_utf8(read_variable_item(
        item,
        CanonicalItemType::DisplayText,
    )?)
    .map_err(|_| {
        FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "display text is not canonical",
        )
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

pub(super) fn read_nested_tuple_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<Vec<CanonicalTuple>> {
    let mut budget = CanonicalDecodeBudget::new(limits);
    read_nested_tuple_list_with_budget(item, limits, &mut budget)
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

pub(super) fn read_nested_tuple(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<CanonicalTuple> {
    let mut budget = CanonicalDecodeBudget::new(limits);
    read_nested_tuple_with_budget(item, limits, &mut budget)
}

pub(super) fn read_nested_tuple_with_budget(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
    budget: &mut CanonicalDecodeBudget,
) -> SchemaResult<CanonicalTuple> {
    let bytes = read_item(item, CanonicalItemType::NestedTuple)?;
    let (tuple, consumed) = CanonicalTuple::decode_prefix(bytes, limits, budget, 1)?;
    if consumed != bytes.len() {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "nested foundation tuple contains trailing bytes",
        ));
    }
    Ok(tuple)
}

#[cfg(test)]
mod tests {
    use fips204::traits::{KeyGen, Signer};

    use super::*;

    fn display(value: &str) -> StabilizedDisplayText {
        StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).expect("valid display text")
    }

    fn encode_raw_tuple_with_items(
        schema_identifier: u16,
        items: Vec<(CanonicalItemType, Vec<u8>)>,
    ) -> Vec<u8> {
        let item_count = u32::try_from(items.len()).expect("test item count fits u32");
        let encoded_byte_length = items
            .iter()
            .try_fold(8usize, |byte_length, (_, item_bytes)| {
                byte_length
                    .checked_add(6)
                    .and_then(|length| length.checked_add(item_bytes.len()))
            })
            .expect("test tuple length does not overflow");
        let mut encoded = Vec::with_capacity(encoded_byte_length);
        encoded.extend_from_slice(&schema_identifier.to_le_bytes());
        encoded.extend_from_slice(&FOUNDATION_SCHEMA_VERSION.to_le_bytes());
        encoded.extend_from_slice(&item_count.to_le_bytes());
        for (item_type, item_bytes) in items {
            let item_byte_length =
                u32::try_from(item_bytes.len()).expect("test item length fits u32");
            encoded.extend_from_slice(&item_type.canonical_code().to_le_bytes());
            encoded.extend_from_slice(&item_byte_length.to_le_bytes());
            encoded.extend_from_slice(&item_bytes);
        }
        encoded
    }

    fn raw_homogeneous_list_header(
        element_type: CanonicalItemType,
        declared_count: u32,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(6);
        bytes.extend_from_slice(&element_type.canonical_code().to_le_bytes());
        bytes.extend_from_slice(&declared_count.to_le_bytes());
        bytes
    }

    fn manifest() -> Manifest {
        Manifest::new(
            display("Main poll"),
            (0..FOUNDATION_PROFILE.option_count)
                .map(|option_index| {
                    OptionDefinition::new(
                        option_index,
                        format!("option-{option_index}"),
                        display(&format!("Option {option_index}")),
                    )
                    .expect("valid option")
                })
                .collect(),
        )
        .expect("valid manifest")
    }

    fn roster() -> Roster {
        Roster::new(
            (0..FOUNDATION_PROFILE.participant_count)
                .map(|roster_position| RosterEntry {
                    roster_position,
                    signing_verification_key: [u8::try_from(roster_position + 1)
                        .expect("position fits byte");
                        ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
                    mailbox_encapsulation_key: [u8::try_from(roster_position + 1)
                        .expect("position fits byte");
                        ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
                })
                .collect(),
        )
        .expect("valid roster")
    }

    #[test]
    fn manifest_action_board_and_roster_round_trip_canonically() {
        let limits = CanonicalDecodeLimits::default();
        let manifest = manifest();
        let manifest_bytes = manifest.encode().expect("manifest encodes");
        assert_eq!(
            Manifest::decode(&manifest_bytes, &limits).expect("manifest decodes"),
            manifest
        );

        let action = ActionDefinition::new(7, u64::MAX).expect("action");
        let action_bytes = action.encode().expect("action encodes");
        assert_eq!(
            ActionDefinition::decode(&action_bytes, &limits).expect("action decodes"),
            action
        );

        let board = BoardPolicy::new("board.example.invalid".to_owned()).expect("board");
        let board_bytes = board.encode().expect("board encodes");
        assert_eq!(
            BoardPolicy::decode(&board_bytes, &limits).expect("board decodes"),
            board
        );

        let roster = roster();
        let roster_bytes = roster.encode().expect("roster encodes");
        assert_eq!(
            Roster::decode(&roster_bytes, &limits).expect("roster decodes"),
            roster
        );
    }

    #[test]
    fn roster_entry_accepts_generated_and_boundary_ml_dsa_65_encodings() {
        let mut signing_verification_keys = vec![
            [0u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
            [u8::MAX; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
        ];
        for seed in [[0u8; 32], [0x5a; 32], [u8::MAX; 32]] {
            let (verification_key, _) = ml_dsa_65::KG::keygen_from_seed(&seed);
            signing_verification_keys.push(verification_key.into_bytes());
        }

        for (case_index, signing_verification_key) in
            signing_verification_keys.into_iter().enumerate()
        {
            let entry = RosterEntry {
                roster_position: u16::try_from(case_index).expect("test case index fits u16"),
                signing_verification_key,
                mailbox_encapsulation_key: [u8::try_from(case_index + 1)
                    .expect("test case index fits u8");
                    ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
            };

            let encoded = entry.encode().expect("canonical roster entry encodes");
            assert_eq!(
                RosterEntry::decode(&encoded, &CanonicalDecodeLimits::default())
                    .expect("canonical roster entry decodes"),
                entry
            );
        }
    }

    #[test]
    fn roster_entry_refuses_noncanonical_ml_dsa_65_key_carriers() {
        let (verification_key, _) = ml_dsa_65::KG::keygen_from_seed(&[0x36; 32]);
        let verification_key_bytes = verification_key.into_bytes();
        let mailbox_encapsulation_key = [0x03; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH];

        let mut extended_verification_key = verification_key_bytes.to_vec();
        extended_verification_key.push(0);
        let length_prefixed_verification_key =
            CanonicalItem::variable_bytes(verification_key_bytes)
                .expect("test key fits the canonical item limit")
                .canonical_bytes()
                .to_vec();

        for noncanonical_key_bytes in [
            verification_key_bytes[..verification_key_bytes.len() - 1].to_vec(),
            extended_verification_key,
            length_prefixed_verification_key,
        ] {
            let encoded = encode_raw_tuple_with_items(
                ROSTER_ENTRY_SCHEMA_IDENTIFIER,
                vec![
                    (CanonicalItemType::Unsigned16, 0u16.to_le_bytes().to_vec()),
                    (CanonicalItemType::RawBytes, noncanonical_key_bytes),
                    (
                        CanonicalItemType::RawBytes,
                        mailbox_encapsulation_key.to_vec(),
                    ),
                ],
            );

            assert_eq!(
                RosterEntry::decode(&encoded, &CanonicalDecodeLimits::default())
                    .expect_err("noncanonical signing-key carrier must refuse")
                    .refusal_reason,
                RefusalReason::WrongTypeOrLength
            );
        }
    }

    #[test]
    fn supported_distribution_records_round_trip_and_reject_substitutions() {
        let limits = CanonicalDecodeLimits::default();
        for purpose in 1..=12_u16 {
            let (kind, parameter) = match purpose {
                1 | 3 | 8 | 11 => (DistributionKind::Ternary, 0),
                _ => (DistributionKind::CenteredBinomial, 2),
            };
            let record = DistributionRecord::new(purpose, kind, parameter)
                .expect("assigned distribution is supported");
            let encoded = record.encode().expect("distribution encodes");
            assert_eq!(
                DistributionRecord::decode(&encoded, &limits).expect("distribution decodes"),
                record
            );
        }

        for (purpose, kind, parameter) in [
            (0, DistributionKind::Ternary, 0),
            (13, DistributionKind::CenteredBinomial, 2),
            (1, DistributionKind::CenteredBinomial, 2),
            (2, DistributionKind::CenteredBinomial, 0),
            (2, DistributionKind::CenteredBinomial, 3),
        ] {
            assert_eq!(
                DistributionRecord::new(purpose, kind, parameter)
                    .expect_err("unsupported distribution must refuse")
                    .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }

        let unknown_kind = CanonicalTuple::new(
            DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(1),
                CanonicalItem::unsigned16(3),
                CanonicalItem::unsigned64(0),
            ],
        )
        .encode()
        .expect("test tuple encodes");
        assert_eq!(
            DistributionRecord::decode(&unknown_kind, &limits)
                .expect_err("unknown distribution kind must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }

    #[test]
    fn artifact_references_bind_kind_length_and_canonical_bytes() {
        let limits = CanonicalDecodeLimits::default();
        let artifact_bytes = CanonicalTuple::new(
            0x1300,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::unsigned16(7)],
        )
        .encode()
        .expect("representative artifact encodes");
        let reference = ArtifactReference::from_artifact_bytes(
            ArtifactKind::EncoderAndBallotLayout,
            &artifact_bytes,
        )
        .expect("artifact reference derives");
        reference
            .verify_artifact_bytes(&artifact_bytes)
            .expect("matching artifact verifies");

        let encoded = reference.encode().expect("artifact reference encodes");
        assert_eq!(
            ArtifactReference::decode(&encoded, &limits).expect("artifact reference decodes"),
            reference
        );

        let mut substituted_bytes = artifact_bytes.clone();
        substituted_bytes[0] ^= 1;
        assert_eq!(
            reference
                .verify_artifact_bytes(&substituted_bytes)
                .expect_err("substituted artifact bytes must refuse")
                .refusal_reason,
            RefusalReason::WrongHashOrRoot
        );
        assert_eq!(
            reference
                .verify_artifact_bytes(&artifact_bytes[..artifact_bytes.len() - 1])
                .expect_err("truncated artifact bytes must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
        assert_eq!(
            ArtifactReference::from_artifact_bytes(ArtifactKind::EncoderAndBallotLayout, &[],)
                .expect_err("empty artifacts must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let unknown_kind = CanonicalTuple::new(
            ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(7),
                CanonicalItem::unsigned64(1),
                CanonicalItem::hash512([0; 64]),
            ],
        )
        .encode()
        .expect("test tuple encodes");
        assert_eq!(
            ArtifactReference::decode(&unknown_kind, &limits)
                .expect_err("unknown artifact kind must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }

    #[test]
    fn manifest_declared_option_count_refuses_before_nested_tuple_decoding() {
        let display_title = CanonicalItem::display_text(&display("Main poll"))
            .expect("display title item is canonical");
        for declared_option_count in [19_u32, 21] {
            let encoded = encode_raw_tuple_with_items(
                MANIFEST_SCHEMA_IDENTIFIER,
                vec![
                    (
                        CanonicalItemType::DisplayText,
                        display_title.canonical_bytes().to_vec(),
                    ),
                    (
                        CanonicalItemType::HomogeneousList,
                        raw_homogeneous_list_header(
                            CanonicalItemType::NestedTuple,
                            declared_option_count,
                        ),
                    ),
                ],
            );

            assert_eq!(
                Manifest::decode(&encoded, &CanonicalDecodeLimits::default())
                    .expect_err("a non-profile option count must refuse before list decoding")
                    .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }
    }

    #[test]
    fn roster_declared_entry_count_refuses_before_nested_tuple_decoding() {
        for declared_entry_count in [9_u32, 11] {
            let encoded = encode_raw_tuple_with_items(
                ROSTER_SCHEMA_IDENTIFIER,
                vec![(
                    CanonicalItemType::HomogeneousList,
                    raw_homogeneous_list_header(
                        CanonicalItemType::NestedTuple,
                        declared_entry_count,
                    ),
                )],
            );

            assert_eq!(
                Roster::decode(&encoded, &CanonicalDecodeLimits::default())
                    .expect_err("a non-profile roster count must refuse before list decoding")
                    .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }
    }

    #[test]
    fn stream_declared_digest_count_refuses_before_hash_materialization() {
        for declared_digest_count in [0_u32, 2, 4_096] {
            let encoded = encode_raw_tuple_with_items(
                STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
                vec![
                    (CanonicalItemType::Unsigned64, 1_u64.to_le_bytes().to_vec()),
                    (
                        CanonicalItemType::HomogeneousList,
                        raw_homogeneous_list_header(
                            CanonicalItemType::Hash512,
                            declared_digest_count,
                        ),
                    ),
                    (CanonicalItemType::Hash512, vec![0x5a; 64]),
                ],
            );

            assert_eq!(
                StreamDescriptor::decode(&encoded, &CanonicalDecodeLimits::default())
                    .expect_err("an inconsistent digest count must refuse before list decoding")
                    .refusal_reason,
                RefusalReason::WrongTypeOrLength
            );
        }
    }

    #[test]
    fn manifest_refuses_duplicate_identifiers_and_noncontiguous_indexes() {
        let mut duplicate = manifest().options;
        duplicate[19].option_identifier = duplicate[0].option_identifier.clone();
        assert_eq!(
            Manifest::new(display("Poll"), duplicate)
                .expect_err("duplicate identifier must refuse")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        let mut reordered = manifest().options;
        reordered.swap(0, 1);
        assert_eq!(
            Manifest::new(display("Poll"), reordered)
                .expect_err("reordered indexes must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }

    #[test]
    fn roster_refuses_duplicate_keys_and_wrong_positions() {
        let mut duplicate = roster().entries;
        duplicate[9].signing_verification_key = duplicate[0].signing_verification_key;
        assert_eq!(
            Roster::new(duplicate)
                .expect_err("duplicate key must refuse")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        let mut wrong_position = roster().entries;
        wrong_position[4].roster_position = 7;
        assert_eq!(
            Roster::new(wrong_position)
                .expect_err("wrong position must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut noncanonical_mailbox_key = roster().entries;
        noncanonical_mailbox_key[0].mailbox_encapsulation_key =
            [0xff; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH];
        assert_eq!(
            Roster::new(noncanonical_mailbox_key)
                .expect_err("non-canonical ML-KEM coefficient must refuse")
                .refusal_reason,
            RefusalReason::MalformedEncoding
        );
    }

    #[test]
    fn schema_specific_text_rules_do_not_add_identifier_limits() {
        let empty_title_manifest = Manifest::new(display(""), manifest().options)
            .expect("manifest title is permitted to be empty");
        assert_eq!(
            Manifest::decode(
                &empty_title_manifest.encode().expect("manifest encodes"),
                &CanonicalDecodeLimits::default(),
            )
            .expect("manifest decodes"),
            empty_title_manifest
        );

        let long_option_identifier = "x".repeat(
            FOUNDATION_PROFILE
                .maximum_identifier_byte_length
                .checked_add(1)
                .expect("test length does not overflow"),
        );
        OptionDefinition::new(0, long_option_identifier, display("Option"))
            .expect("the context identifier limit does not apply to option identifiers");

        let empty_board =
            BoardPolicy::new(String::new()).expect("empty board origin is valid ASCII");
        assert_eq!(
            BoardPolicy::decode(
                &empty_board.encode().expect("board policy encodes"),
                &CanonicalDecodeLimits::default(),
            )
            .expect("board policy decodes"),
            empty_board
        );

        assert_eq!(
            ceremony_context_hash(
                Hash512::from_bytes([1; 64]),
                Hash512::from_bytes([2; 64]),
                Hash512::from_bytes([3; 64]),
                &"x".repeat(FOUNDATION_PROFILE.maximum_identifier_byte_length + 1),
            )
            .expect_err("overlong ceremony identifier must refuse")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }

    #[test]
    fn object_carrier_and_stream_descriptor_round_trip() {
        let limits = CanonicalDecodeLimits::default();
        let envelope = ObjectEnvelope {
            suite_id: Hash512::from_bytes([1; 64]),
            object_type: FoundationObjectType::StateReservation,
            ceremony_context_hash: Hash512::from_bytes([2; 64]),
            action_context_hash: Hash512::from_bytes([3; 64]),
            recovery_epoch: u64::MAX,
            recovery_transition_hash: Some(Hash512::from_bytes([4; 64])),
            producer_participant_id: Some(ParticipantIdentity::from_bytes([5; 64])),
            producer_sequence: u64::MAX,
            ordered_prerequisite_hashes: vec![Hash512::from_bytes([6; 64])],
            payload_bytes: vec![0, 1, 2, 255],
        };
        let envelope_bytes = envelope.encode().expect("envelope encodes");
        assert_eq!(
            ObjectEnvelope::decode(&envelope_bytes, &limits).expect("envelope decodes"),
            envelope
        );

        let carrier = SignedCarrier {
            envelope,
            signature: [0x5a; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
        };
        let carrier_bytes = carrier.encode().expect("carrier encodes");
        assert_eq!(
            SignedCarrier::decode(&carrier_bytes, &limits).expect("carrier decodes"),
            carrier
        );

        let descriptor = StreamDescriptor {
            total_byte_length: u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .expect("chunk length fits u64")
                + 1,
            ordered_chunk_digests: vec![Hash512::from_bytes([7; 64]), Hash512::from_bytes([8; 64])],
            full_object_digest: Hash512::from_bytes([9; 64]),
        };
        let descriptor_bytes = descriptor.encode().expect("descriptor encodes");
        assert_eq!(
            StreamDescriptor::decode(&descriptor_bytes, &limits).expect("descriptor decodes"),
            descriptor
        );
    }

    #[test]
    fn signed_carrier_verifies_only_for_the_roster_bound_key_message_and_context() {
        let key_seed = [0x31; 32];
        let (producer_public_key, producer_private_key) =
            ml_dsa_65::KG::keygen_from_seed(&key_seed);
        let mut roster_entries = roster().entries;
        roster_entries[0].signing_verification_key = producer_public_key.into_bytes();
        let roster = Roster::new(roster_entries).expect("roster with valid producer key");
        let producer_participant_id = roster.entries[0]
            .participant_identity()
            .expect("producer identity derives");
        let envelope = ObjectEnvelope {
            suite_id: Hash512::from_bytes([1; 64]),
            object_type: FoundationObjectType::StateReservation,
            ceremony_context_hash: Hash512::from_bytes([2; 64]),
            action_context_hash: Hash512::from_bytes([3; 64]),
            recovery_epoch: 4,
            recovery_transition_hash: Some(Hash512::from_bytes([5; 64])),
            producer_participant_id: Some(producer_participant_id),
            producer_sequence: 6,
            ordered_prerequisite_hashes: vec![Hash512::from_bytes([7; 64])],
            payload_bytes: vec![8, 9, 10],
        };
        let message = signature_message(
            &envelope,
            roster.roster_hash().expect("roster hash derives"),
        )
        .expect("signature message derives");
        let signature = producer_private_key
            .try_sign_with_seed(&[0xa5; 32], message.as_bytes(), OBJECT_SIGNATURE_CONTEXT)
            .expect("test signature generates");
        let carrier = SignedCarrier {
            envelope,
            signature,
        };

        assert_eq!(
            carrier.verify_signature(&roster),
            VerificationResult::valid(())
        );

        let mut substituted_signature = carrier.clone();
        substituted_signature.signature[0] ^= 1;
        assert_eq!(
            substituted_signature.verify_signature(&roster),
            VerificationResult::refused(RefusalReason::InvalidSignature)
        );

        let mut wrong_context_signature = carrier.clone();
        wrong_context_signature.signature = producer_private_key
            .try_sign_with_seed(
                &[0xb6; 32],
                message.as_bytes(),
                b"sealed-lattice/object-signature/v2",
            )
            .expect("wrong-context test signature generates");
        assert_eq!(
            wrong_context_signature.verify_signature(&roster),
            VerificationResult::refused(RefusalReason::InvalidSignature)
        );

        let mut wrong_roster_entries = roster.entries.clone();
        wrong_roster_entries[1].signing_verification_key =
            [0xfe; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH];
        let wrong_roster = Roster::new(wrong_roster_entries).expect("distinct alternate roster");
        assert_eq!(
            carrier.verify_signature(&wrong_roster),
            VerificationResult::refused(RefusalReason::InvalidSignature)
        );

        let mut missing_producer = carrier.clone();
        missing_producer.envelope.producer_participant_id = None;
        assert_eq!(
            missing_producer.verify_signature(&roster),
            VerificationResult::refused(RefusalReason::WrongTypeOrLength)
        );

        let mut unknown_producer = carrier;
        unknown_producer.envelope.producer_participant_id =
            Some(ParticipantIdentity::from_bytes([0xff; 64]));
        assert_eq!(
            unknown_producer.verify_signature(&roster),
            VerificationResult::refused(RefusalReason::WrongContext)
        );
    }

    #[test]
    fn mutated_schema_values_and_inconsistent_streams_refuse_encoding() {
        let mut invalid_manifest = manifest();
        invalid_manifest.options[0].display_label = display("");
        assert_eq!(
            invalid_manifest
                .encode()
                .expect_err("empty mutated label must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut invalid_action = ActionDefinition::new(1, 0).expect("valid action");
        invalid_action.top_count = 0;
        assert_eq!(
            invalid_action
                .encode()
                .expect_err("mutated top count must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let mut invalid_roster = roster();
        invalid_roster.entries[9].signing_verification_key =
            invalid_roster.entries[0].signing_verification_key;
        assert_eq!(
            invalid_roster
                .encode()
                .expect_err("mutated duplicate key must refuse")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        for descriptor in [
            StreamDescriptor {
                total_byte_length: 0,
                ordered_chunk_digests: Vec::new(),
                full_object_digest: Hash512::from_bytes([1; 64]),
            },
            StreamDescriptor {
                total_byte_length: 1,
                ordered_chunk_digests: vec![
                    Hash512::from_bytes([2; 64]),
                    Hash512::from_bytes([3; 64]),
                ],
                full_object_digest: Hash512::from_bytes([4; 64]),
            },
        ] {
            assert_eq!(
                descriptor
                    .encode()
                    .expect_err("inconsistent stream descriptor must refuse")
                    .refusal_reason,
                RefusalReason::WrongTypeOrLength
            );
        }
    }

    #[test]
    fn configured_decode_limits_refuse_as_outside_the_supported_profile() {
        let encoded_manifest = manifest().encode().expect("manifest encodes");
        let count_limited = CanonicalDecodeLimits {
            maximum_item_count: usize::from(FOUNDATION_PROFILE.option_count) - 1,
            ..CanonicalDecodeLimits::default()
        };
        assert_eq!(
            Manifest::decode(&encoded_manifest, &count_limited)
                .expect_err("option count above the configured limit must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let length_limited = CanonicalDecodeLimits {
            maximum_tuple_byte_length: encoded_manifest.len() - 1,
            ..CanonicalDecodeLimits::default()
        };
        assert_eq!(
            Manifest::decode(&encoded_manifest, &length_limited)
                .expect_err("tuple length above the configured limit must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    #[test]
    fn context_hashes_bind_every_external_input() {
        let ceremony = ceremony_context_hash(
            Hash512::from_bytes([1; 64]),
            Hash512::from_bytes([2; 64]),
            Hash512::from_bytes([3; 64]),
            "ceremony-one",
        )
        .expect("ceremony context");
        let changed = ceremony_context_hash(
            Hash512::from_bytes([1; 64]),
            Hash512::from_bytes([2; 64]),
            Hash512::from_bytes([3; 64]),
            "ceremony-two",
        )
        .expect("ceremony context");
        assert_ne!(ceremony, changed);

        let action = action_context_hash(
            ceremony,
            "action-one",
            Hash512::from_bytes([4; 64]),
            Hash512::from_bytes([5; 64]),
        )
        .expect("action context");
        let action_changed = action_context_hash(
            ceremony,
            "action-one",
            Hash512::from_bytes([6; 64]),
            Hash512::from_bytes([5; 64]),
        )
        .expect("action context");
        assert_ne!(action, action_changed);

        let action_definition = ActionDefinition::new(7, 1_000).expect("action definition");
        let cutoff = action_definition
            .submission_cutoff_hash(action)
            .expect("submission cutoff hash");
        assert_ne!(
            cutoff,
            action_definition
                .submission_cutoff_hash(action_changed)
                .expect("changed context cutoff hash")
        );
        assert_ne!(
            cutoff,
            ActionDefinition::new(7, 1_001)
                .expect("changed cutoff definition")
                .submission_cutoff_hash(action)
                .expect("changed cutoff hash")
        );
    }

    #[test]
    fn signature_purpose_is_derived_from_the_envelope_family() {
        let base_envelope = ObjectEnvelope {
            suite_id: Hash512::from_bytes([1; 64]),
            object_type: FoundationObjectType::SetupIntent,
            ceremony_context_hash: Hash512::from_bytes([2; 64]),
            action_context_hash: Hash512::from_bytes([3; 64]),
            recovery_epoch: 0,
            recovery_transition_hash: None,
            producer_participant_id: Some(ParticipantIdentity::from_bytes([4; 64])),
            producer_sequence: 0,
            ordered_prerequisite_hashes: Vec::new(),
            payload_bytes: Vec::new(),
        };
        let roster_hash = Hash512::from_bytes([5; 64]);
        for (object_type, expected_purpose) in [
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
                FoundationObjectType::RecoveryTransition,
                "state-recovery-transition",
            ),
            (
                FoundationObjectType::TargetDecryptionShare,
                "target-release-output",
            ),
            (
                FoundationObjectType::StorageRootCommitment,
                "storage-root-commitment",
            ),
        ] {
            let envelope = ObjectEnvelope {
                object_type,
                ..base_envelope.clone()
            };
            let expected = hash512(
                "sealed-lattice/foundation/signature-message/v1",
                &[
                    CanonicalItem::hash512(
                        envelope.object_hash().expect("object hash").into_bytes(),
                    ),
                    CanonicalItem::hash512(roster_hash.into_bytes()),
                    CanonicalItem::ascii(expected_purpose).expect("purpose is ASCII"),
                ],
            )
            .expect("expected signature message");
            assert_eq!(
                signature_message(&envelope, roster_hash).expect("signed family has a purpose"),
                expected
            );
        }

        for object_type in [
            FoundationObjectType::Aggregate,
            FoundationObjectType::EvaluatorReplay,
        ] {
            assert_eq!(
                signature_message(
                    &ObjectEnvelope {
                        object_type,
                        ..base_envelope.clone()
                    },
                    roster_hash,
                )
                .expect_err("unsigned family must refuse signature-message derivation")
                .refusal_reason,
                RefusalReason::WrongTypeOrLength
            );
        }
    }
}
