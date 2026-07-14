use std::collections::BTreeSet;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    FoundationSchemaError, SchemaResult, read_ascii, read_hash, read_list_header,
    read_nested_tuple_list_with_budget, read_u16, read_u32, read_u64, read_variable_item,
    require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    Hash512, RefusalReason, StabilizedDisplayText, hash_foundation_tuple_512 as hash512,
};

pub const MANIFEST_SCHEMA_IDENTIFIER: u16 = 0x0110;
pub const OPTION_DEFINITION_SCHEMA_IDENTIFIER: u16 = 0x0111;
pub const ACTION_DEFINITION_SCHEMA_IDENTIFIER: u16 = 0x0112;
pub const BOARD_POLICY_SCHEMA_IDENTIFIER: u16 = 0x0113;
pub const DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0116;
pub const ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x0117;
pub const SUITE_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0118;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DistributionPurpose {
    SecretContribution = 1,
    PublicKeyError = 2,
    RelinearizationKeyGenerationEphemeralSecret = 3,
    RelinearizationKeyGenerationRoundOneLeftError = 4,
    RelinearizationKeyGenerationRoundOneRightError = 5,
    RelinearizationKeyGenerationRoundTwoError = 6,
    GaloisKeyError = 7,
    BallotEncryptionEphemeralSecret = 8,
    BallotErrorZero = 9,
    BallotErrorOne = 10,
    LatticeCommitmentHidingSecret = 11,
    LatticeCommitmentHidingError = 12,
}

impl DistributionPurpose {
    pub const ALL: [Self; 12] = [
        Self::SecretContribution,
        Self::PublicKeyError,
        Self::RelinearizationKeyGenerationEphemeralSecret,
        Self::RelinearizationKeyGenerationRoundOneLeftError,
        Self::RelinearizationKeyGenerationRoundOneRightError,
        Self::RelinearizationKeyGenerationRoundTwoError,
        Self::GaloisKeyError,
        Self::BallotEncryptionEphemeralSecret,
        Self::BallotErrorZero,
        Self::BallotErrorOne,
        Self::LatticeCommitmentHidingSecret,
        Self::LatticeCommitmentHidingError,
    ];

    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::SecretContribution),
            2 => Some(Self::PublicKeyError),
            3 => Some(Self::RelinearizationKeyGenerationEphemeralSecret),
            4 => Some(Self::RelinearizationKeyGenerationRoundOneLeftError),
            5 => Some(Self::RelinearizationKeyGenerationRoundOneRightError),
            6 => Some(Self::RelinearizationKeyGenerationRoundTwoError),
            7 => Some(Self::GaloisKeyError),
            8 => Some(Self::BallotEncryptionEphemeralSecret),
            9 => Some(Self::BallotErrorZero),
            10 => Some(Self::BallotErrorOne),
            11 => Some(Self::LatticeCommitmentHidingSecret),
            12 => Some(Self::LatticeCommitmentHidingError),
            _ => None,
        }
    }

    const fn expected_distribution(self) -> (DistributionKind, u64) {
        match self {
            Self::SecretContribution
            | Self::RelinearizationKeyGenerationEphemeralSecret
            | Self::BallotEncryptionEphemeralSecret
            | Self::LatticeCommitmentHidingSecret => (DistributionKind::Ternary, 0),
            Self::PublicKeyError
            | Self::RelinearizationKeyGenerationRoundOneLeftError
            | Self::RelinearizationKeyGenerationRoundOneRightError
            | Self::RelinearizationKeyGenerationRoundTwoError
            | Self::GaloisKeyError
            | Self::BallotErrorZero
            | Self::BallotErrorOne
            | Self::LatticeCommitmentHidingError => (DistributionKind::CenteredBinomial, 2),
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SuiteArtifactKind {
    EncoderAndBallotLayout = 1,
    VerifiableSecretSharingProfile = 2,
    LatticeCommitmentProfile = 3,
    ProofProfileSet = 4,
    EvaluatorProgramSet = 5,
    TargetDecryptionProfile = 6,
}

impl SuiteArtifactKind {
    pub const ALL: [Self; 6] = [
        Self::EncoderAndBallotLayout,
        Self::VerifiableSecretSharingProfile,
        Self::LatticeCommitmentProfile,
        Self::ProofProfileSet,
        Self::EvaluatorProgramSet,
        Self::TargetDecryptionProfile,
    ];

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
        let definition = Self {
            option_index,
            option_identifier,
            display_label,
        };
        definition.validate()?;
        Ok(definition)
    }

    fn validate(&self) -> SchemaResult<()> {
        if self.option_index >= FOUNDATION_PROFILE.option_count {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "option index is outside the supported profile",
            ));
        }
        validate_external_identifier(&self.option_identifier, "option identifier is invalid")?;
        if self.display_label.as_str().is_empty() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "option display label must be nonempty",
            ));
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            OPTION_DEFINITION_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.option_index),
                CanonicalItem::nonempty_ascii(&self.option_identifier)?,
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
    pub title: StabilizedDisplayText,
    pub options: Vec<OptionDefinition>,
}

impl Manifest {
    pub fn new(title: StabilizedDisplayText, options: Vec<OptionDefinition>) -> SchemaResult<Self> {
        let manifest = Self { title, options };
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> SchemaResult<()> {
        if self.title.as_str().is_empty() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "manifest title must be nonempty",
            ));
        }
        if self.options.len() != usize::from(FOUNDATION_PROFILE.option_count) {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "manifest option count does not match the supported profile",
            ));
        }

        let mut identifiers = BTreeSet::new();
        for (expected_index, option) in self.options.iter().enumerate() {
            option.validate()?;
            if usize::from(option.option_index) != expected_index {
                return Err(schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "manifest option indexes must be contiguous and increasing",
                ));
            }
            if !identifiers.insert(option.option_identifier.as_str()) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "manifest option identifiers must be unique",
                ));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
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
                CanonicalItem::display_text(&self.title)?,
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &option_items)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, MANIFEST_SCHEMA_IDENTIFIER, 2)?;
        let options = read_nested_tuple_list_with_budget(&tuple.items[1], limits, &mut budget)?
            .iter()
            .map(OptionDefinition::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(read_display_text(&tuple.items[0])?, options)
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
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "top count is outside the supported profile",
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
        validate_external_identifier(
            &board_origin_identifier,
            "board origin identifier is invalid",
        )?;
        Ok(Self {
            board_origin_identifier,
        })
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Self::new(self.board_origin_identifier.clone())?;
        Ok(CanonicalTuple::new(
            BOARD_POLICY_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![CanonicalItem::nonempty_ascii(
                &self.board_origin_identifier,
            )?],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributionRecord {
    pub purpose: DistributionPurpose,
    pub kind: DistributionKind,
    pub parameter: u64,
}

impl DistributionRecord {
    pub fn new(
        purpose: DistributionPurpose,
        kind: DistributionKind,
        parameter: u64,
    ) -> SchemaResult<Self> {
        let expected = purpose.expected_distribution();
        if (kind, parameter) != expected {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "distribution does not match the supported profile",
            ));
        }
        Ok(Self {
            purpose,
            kind,
            parameter,
        })
    }

    pub fn supported_profile_records() -> Vec<Self> {
        DistributionPurpose::ALL
            .into_iter()
            .map(|purpose| {
                let (kind, parameter) = purpose.expected_distribution();
                Self {
                    purpose,
                    kind,
                    parameter,
                }
            })
            .collect()
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        Self::new(self.purpose, self.kind, self.parameter)?;
        Ok(CanonicalTuple::new(
            DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.purpose.canonical_code()),
                CanonicalItem::unsigned16(self.kind.canonical_code()),
                CanonicalItem::unsigned64(self.parameter),
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER, 3)?;
        let purpose = DistributionPurpose::from_canonical_code(read_u16(&tuple.items[0])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "distribution purpose is unassigned",
                )
            })?;
        let kind =
            DistributionKind::from_canonical_code(read_u16(&tuple.items[1])?).ok_or_else(|| {
                schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "distribution kind is unassigned",
                )
            })?;
        Self::new(purpose, kind, read_u64(&tuple.items[2])?)
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactReference {
    pub artifact_kind: SuiteArtifactKind,
    pub byte_length: u64,
    pub artifact_hash: Hash512,
}

impl ArtifactReference {
    pub fn new(
        artifact_kind: SuiteArtifactKind,
        byte_length: u64,
        artifact_hash: Hash512,
    ) -> SchemaResult<Self> {
        if byte_length == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "suite artifact must be nonempty",
            ));
        }
        Ok(Self {
            artifact_kind,
            byte_length,
            artifact_hash,
        })
    }

    pub fn from_canonical_artifact(
        artifact_kind: SuiteArtifactKind,
        canonical_artifact_bytes: &[u8],
    ) -> SchemaResult<Self> {
        let byte_length = u64::try_from(canonical_artifact_bytes.len()).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "suite artifact length does not fit u64",
            )
        })?;
        Self::new(
            artifact_kind,
            byte_length,
            derive_artifact_hash(artifact_kind, canonical_artifact_bytes)?,
        )
    }

    pub fn verify_canonical_artifact(&self, canonical_artifact_bytes: &[u8]) -> SchemaResult<()> {
        let actual_byte_length = u64::try_from(canonical_artifact_bytes.len()).map_err(|_| {
            schema_error(
                RefusalReason::OutsideSupportedProfile,
                "suite artifact length does not fit u64",
            )
        })?;
        if actual_byte_length != self.byte_length
            || derive_artifact_hash(self.artifact_kind, canonical_artifact_bytes)?
                != self.artifact_hash
        {
            return Err(schema_error(
                RefusalReason::WrongHashOrRoot,
                "suite artifact bytes do not match their reference",
            ));
        }
        Ok(())
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
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

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER, 3)?;
        let artifact_kind = SuiteArtifactKind::from_canonical_code(read_u16(&tuple.items[0])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "suite artifact kind is unassigned",
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
        Self::from_tuple(&CanonicalTuple::decode(bytes, limits)?)
    }
}

pub fn derive_artifact_hash(
    artifact_kind: SuiteArtifactKind,
    canonical_artifact_bytes: &[u8],
) -> SchemaResult<Hash512> {
    let byte_length = u64::try_from(canonical_artifact_bytes.len()).map_err(|_| {
        schema_error(
            RefusalReason::OutsideSupportedProfile,
            "suite artifact length does not fit u64",
        )
    })?;
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
pub struct SuiteRecord {
    pub roster_size: u16,
    pub byzantine_bound: u16,
    pub reconstruction_threshold: u16,
    pub finality_quorum: u16,
    pub polynomial_degree: u32,
    pub plaintext_modulus: u64,
    pub ordered_data_primes: Vec<u64>,
    pub ordered_special_primes: Vec<u64>,
    pub ordered_target_data_prime_indexes: Vec<u16>,
    pub ordered_sharing_data_prime_indexes: Vec<u16>,
    pub key_switch_data_primes_per_block: u16,
    pub maximum_ballot_attempts_per_participant: u16,
    pub maximum_recovery_transitions_per_state_key: u16,
    pub maximum_target_share_submissions: u16,
    pub maximum_private_sampler_candidate_draws_per_output: u32,
    pub maximum_public_sampler_candidate_draws_per_output: u32,
    pub maximum_candidate_packages_per_action: u32,
    pub maximum_proof_objects_per_action: u32,
    pub maximum_candidate_bytes_per_participant: u64,
    pub maximum_candidate_bytes_per_action: u64,
    pub maximum_setup_bytes_per_participant: u64,
    pub maximum_proof_bytes_per_action: u64,
    pub maximum_public_corpus_bytes: u64,
    pub maximum_participant_upload_bytes: u64,
    pub maximum_ceremony_upload_bytes: u64,
    pub distributions: Vec<DistributionRecord>,
    pub artifacts: Vec<ArtifactReference>,
}

impl SuiteRecord {
    fn validate(&self) -> SchemaResult<()> {
        self.validate_threshold_profile()?;
        let two_polynomial_degree = self.validate_ring_parameters()?;
        self.validate_moduli(two_polynomial_degree)?;
        self.validate_level_indexes()?;
        self.validate_resource_caps()?;
        self.validate_distributions()?;
        self.validate_artifacts()?;
        Ok(())
    }

    fn validate_threshold_profile(&self) -> SchemaResult<()> {
        if self.roster_size != FOUNDATION_PROFILE.participant_count
            || self.byzantine_bound != FOUNDATION_PROFILE.active_fault_bound
            || self.reconstruction_threshold != FOUNDATION_PROFILE.reconstruction_threshold
            || self.finality_quorum != FOUNDATION_PROFILE.finality_quorum
        {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite threshold values do not match the supported profile",
            ));
        }
        Ok(())
    }

    fn validate_ring_parameters(&self) -> SchemaResult<u64> {
        if self.polynomial_degree == 0 || !self.polynomial_degree.is_power_of_two() {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite polynomial degree must be a nonzero power of two",
            ));
        }
        if !is_prime_u64(self.plaintext_modulus) {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite plaintext modulus must be prime",
            ));
        }
        let two_polynomial_degree = u64::from(self.polynomial_degree)
            .checked_mul(2)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "twice the polynomial degree overflows",
                )
            })?;
        if !(self.plaintext_modulus - 1).is_multiple_of(two_polynomial_degree) {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "plaintext modulus does not support full scalar batching",
            ));
        }
        Ok(two_polynomial_degree)
    }

    fn validate_moduli(&self, two_polynomial_degree: u64) -> SchemaResult<()> {
        if self.ordered_data_primes.is_empty() || self.ordered_special_primes.is_empty() {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "suite data-prime and special-prime lists must be nonempty",
            ));
        }
        let mut distinct_moduli = BTreeSet::new();
        for modulus in self
            .ordered_data_primes
            .iter()
            .chain(&self.ordered_special_primes)
            .copied()
        {
            if modulus == self.plaintext_modulus
                || !is_prime_u64(modulus)
                || modulus % two_polynomial_degree != 1
            {
                return Err(schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "suite coefficient modulus is incompatible with the ring",
                ));
            }
            if !distinct_moduli.insert(modulus) {
                return Err(schema_error(
                    RefusalReason::DuplicateIdentity,
                    "suite coefficient moduli must be pairwise distinct",
                ));
            }
        }

        let data_prime_count = self.ordered_data_primes.len();
        let key_switch_data_prime_count = usize::from(self.key_switch_data_primes_per_block);
        if key_switch_data_prime_count == 0 || key_switch_data_prime_count > data_prime_count {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "key-switch data-prime block size is invalid",
            ));
        }
        Ok(())
    }

    fn validate_level_indexes(&self) -> SchemaResult<()> {
        if self.ordered_target_data_prime_indexes.is_empty()
            || self.ordered_sharing_data_prime_indexes.is_empty()
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "suite target and sharing index lists must be nonempty",
            ));
        }
        for (expected_index, actual_index) in
            self.ordered_target_data_prime_indexes.iter().enumerate()
        {
            if usize::from(*actual_index) != expected_index {
                return Err(schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "target data-prime indexes must be a contiguous prefix",
                ));
            }
        }

        let mut previous_sharing_index = None;
        for sharing_index in &self.ordered_sharing_data_prime_indexes {
            let sharing_index = usize::from(*sharing_index);
            if sharing_index >= self.ordered_data_primes.len()
                || previous_sharing_index.is_some_and(|previous| sharing_index <= previous)
            {
                return Err(schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "sharing data-prime indexes must be increasing and in range",
                ));
            }
            previous_sharing_index = Some(sharing_index);
        }

        for target_index in &self.ordered_target_data_prime_indexes {
            if self
                .ordered_sharing_data_prime_indexes
                .binary_search(target_index)
                .is_err()
            {
                return Err(schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "target data-prime basis must be contained in the sharing basis",
                ));
            }
        }
        Ok(())
    }

    fn validate_resource_caps(&self) -> SchemaResult<()> {
        let positive_u16_values = [
            self.maximum_ballot_attempts_per_participant,
            self.maximum_recovery_transitions_per_state_key,
            self.maximum_target_share_submissions,
        ];
        let positive_u32_values = [
            self.maximum_private_sampler_candidate_draws_per_output,
            self.maximum_public_sampler_candidate_draws_per_output,
            self.maximum_candidate_packages_per_action,
            self.maximum_proof_objects_per_action,
        ];
        let positive_u64_values = [
            self.maximum_candidate_bytes_per_participant,
            self.maximum_candidate_bytes_per_action,
            self.maximum_setup_bytes_per_participant,
            self.maximum_proof_bytes_per_action,
            self.maximum_public_corpus_bytes,
            self.maximum_participant_upload_bytes,
            self.maximum_ceremony_upload_bytes,
        ];
        if positive_u16_values.contains(&0)
            || positive_u32_values.contains(&0)
            || positive_u64_values.contains(&0)
        {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "suite resource maxima must be positive",
            ));
        }
        if self.maximum_target_share_submissions != self.roster_size {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "maximum target-share submissions must equal the roster size",
            ));
        }

        let maximum_possible_candidate_packages = u32::from(self.roster_size)
            .checked_mul(u32::from(self.maximum_ballot_attempts_per_participant))
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "candidate-package count bound overflows",
                )
            })?;
        if self.maximum_candidate_packages_per_action < u32::from(self.roster_size)
            || self.maximum_candidate_packages_per_action > maximum_possible_candidate_packages
        {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "candidate-package count is inconsistent with roster and attempt bounds",
            ));
        }

        let ballot_attempt_count = u64::from(self.maximum_ballot_attempts_per_participant);
        if !self
            .maximum_candidate_bytes_per_participant
            .is_multiple_of(ballot_attempt_count)
        {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "participant candidate-byte cap does not encode a complete package bound",
            ));
        }
        let maximum_complete_ballot_package_bytes =
            self.maximum_candidate_bytes_per_participant / ballot_attempt_count;
        if maximum_complete_ballot_package_bytes == 0 {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "complete ballot-package byte bound must be positive",
            ));
        }
        let expected_action_candidate_bytes = maximum_complete_ballot_package_bytes
            .checked_mul(u64::from(self.maximum_candidate_packages_per_action))
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "action candidate-byte cap overflows",
                )
            })?;
        if self.maximum_candidate_bytes_per_action != expected_action_candidate_bytes {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "action candidate-byte cap is inconsistent with the package cap",
            ));
        }

        if self.maximum_candidate_bytes_per_participant > self.maximum_participant_upload_bytes
            || self.maximum_setup_bytes_per_participant > self.maximum_participant_upload_bytes
            || self.maximum_candidate_bytes_per_participant
                > self.maximum_candidate_bytes_per_action
            || self.maximum_candidate_bytes_per_action > self.maximum_public_corpus_bytes
            || self.maximum_candidate_bytes_per_action > self.maximum_ceremony_upload_bytes
            || self.maximum_proof_bytes_per_action > self.maximum_public_corpus_bytes
            || self.maximum_proof_bytes_per_action > self.maximum_ceremony_upload_bytes
        {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite byte caps are internally inconsistent",
            ));
        }
        Ok(())
    }

    fn validate_distributions(&self) -> SchemaResult<()> {
        if self.distributions.len() != DistributionPurpose::ALL.len() {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite must contain every supported distribution exactly once",
            ));
        }
        for (record, expected_purpose) in self.distributions.iter().zip(DistributionPurpose::ALL) {
            if record.purpose != expected_purpose {
                return Err(schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "suite distributions must be ordered by purpose",
                ));
            }
            Self::validate_distribution(record)?;
        }
        Ok(())
    }

    fn validate_distribution(record: &DistributionRecord) -> SchemaResult<()> {
        DistributionRecord::new(record.purpose, record.kind, record.parameter).map(|_| ())
    }

    fn validate_artifacts(&self) -> SchemaResult<()> {
        if self.artifacts.len() != SuiteArtifactKind::ALL.len() {
            return Err(schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite must contain every required artifact exactly once",
            ));
        }
        for (reference, expected_kind) in self.artifacts.iter().zip(SuiteArtifactKind::ALL) {
            if reference.artifact_kind != expected_kind {
                return Err(schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "suite artifacts must be ordered by kind",
                ));
            }
            ArtifactReference::new(
                reference.artifact_kind,
                reference.byte_length,
                reference.artifact_hash,
            )?;
        }
        Ok(())
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
        let distribution_items = self
            .distributions
            .iter()
            .map(|record| {
                record
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        let artifact_items = self
            .artifacts
            .iter()
            .map(|reference| {
                reference
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;

        Ok(CanonicalTuple::new(
            SUITE_RECORD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.roster_size),
                CanonicalItem::unsigned16(self.byzantine_bound),
                CanonicalItem::unsigned16(self.reconstruction_threshold),
                CanonicalItem::unsigned16(self.finality_quorum),
                CanonicalItem::unsigned32(self.polynomial_degree),
                CanonicalItem::unsigned64(self.plaintext_modulus),
                encode_u64_list(&self.ordered_data_primes)?,
                encode_u64_list(&self.ordered_special_primes)?,
                encode_u16_list(&self.ordered_target_data_prime_indexes)?,
                encode_u16_list(&self.ordered_sharing_data_prime_indexes)?,
                CanonicalItem::unsigned16(self.key_switch_data_primes_per_block),
                CanonicalItem::unsigned16(self.maximum_ballot_attempts_per_participant),
                CanonicalItem::unsigned16(self.maximum_recovery_transitions_per_state_key),
                CanonicalItem::unsigned16(self.maximum_target_share_submissions),
                CanonicalItem::unsigned32(self.maximum_private_sampler_candidate_draws_per_output),
                CanonicalItem::unsigned32(self.maximum_public_sampler_candidate_draws_per_output),
                CanonicalItem::unsigned32(self.maximum_candidate_packages_per_action),
                CanonicalItem::unsigned32(self.maximum_proof_objects_per_action),
                CanonicalItem::unsigned64(self.maximum_candidate_bytes_per_participant),
                CanonicalItem::unsigned64(self.maximum_candidate_bytes_per_action),
                CanonicalItem::unsigned64(self.maximum_setup_bytes_per_participant),
                CanonicalItem::unsigned64(self.maximum_proof_bytes_per_action),
                CanonicalItem::unsigned64(self.maximum_public_corpus_bytes),
                CanonicalItem::unsigned64(self.maximum_participant_upload_bytes),
                CanonicalItem::unsigned64(self.maximum_ceremony_upload_bytes),
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::NestedTuple,
                    &distribution_items,
                )?,
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &artifact_items)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, SUITE_RECORD_SCHEMA_IDENTIFIER, 27)?;
        let distributions =
            read_nested_tuple_list_with_budget(&tuple.items[25], limits, &mut budget)?
                .iter()
                .map(DistributionRecord::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?;
        let artifacts = read_nested_tuple_list_with_budget(&tuple.items[26], limits, &mut budget)?
            .iter()
            .map(ArtifactReference::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        let suite = Self {
            roster_size: read_u16(&tuple.items[0])?,
            byzantine_bound: read_u16(&tuple.items[1])?,
            reconstruction_threshold: read_u16(&tuple.items[2])?,
            finality_quorum: read_u16(&tuple.items[3])?,
            polynomial_degree: read_u32(&tuple.items[4])?,
            plaintext_modulus: read_u64(&tuple.items[5])?,
            ordered_data_primes: read_u64_list(&tuple.items[6])?,
            ordered_special_primes: read_u64_list(&tuple.items[7])?,
            ordered_target_data_prime_indexes: read_u16_list(&tuple.items[8])?,
            ordered_sharing_data_prime_indexes: read_u16_list(&tuple.items[9])?,
            key_switch_data_primes_per_block: read_u16(&tuple.items[10])?,
            maximum_ballot_attempts_per_participant: read_u16(&tuple.items[11])?,
            maximum_recovery_transitions_per_state_key: read_u16(&tuple.items[12])?,
            maximum_target_share_submissions: read_u16(&tuple.items[13])?,
            maximum_private_sampler_candidate_draws_per_output: read_u32(&tuple.items[14])?,
            maximum_public_sampler_candidate_draws_per_output: read_u32(&tuple.items[15])?,
            maximum_candidate_packages_per_action: read_u32(&tuple.items[16])?,
            maximum_proof_objects_per_action: read_u32(&tuple.items[17])?,
            maximum_candidate_bytes_per_participant: read_u64(&tuple.items[18])?,
            maximum_candidate_bytes_per_action: read_u64(&tuple.items[19])?,
            maximum_setup_bytes_per_participant: read_u64(&tuple.items[20])?,
            maximum_proof_bytes_per_action: read_u64(&tuple.items[21])?,
            maximum_public_corpus_bytes: read_u64(&tuple.items[22])?,
            maximum_participant_upload_bytes: read_u64(&tuple.items[23])?,
            maximum_ceremony_upload_bytes: read_u64(&tuple.items[24])?,
            distributions,
            artifacts,
        };
        suite.validate()?;
        Ok(suite)
    }

    pub fn suite_id(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/foundation/suite/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyContext {
    pub suite_id: Hash512,
    pub manifest_hash: Hash512,
    pub roster_hash: Hash512,
    pub ceremony_identifier: String,
}

impl CeremonyContext {
    pub fn new(
        suite_id: Hash512,
        manifest_hash: Hash512,
        roster_hash: Hash512,
        ceremony_identifier: String,
    ) -> SchemaResult<Self> {
        validate_external_identifier(&ceremony_identifier, "ceremony identifier is invalid")?;
        Ok(Self {
            suite_id,
            manifest_hash,
            roster_hash,
            ceremony_identifier,
        })
    }

    pub fn context_hash(&self) -> SchemaResult<Hash512> {
        Self::new(
            self.suite_id,
            self.manifest_hash,
            self.roster_hash,
            self.ceremony_identifier.clone(),
        )?;
        Ok(hash512(
            "sealed-lattice/foundation/ceremony-context/v1",
            &[
                CanonicalItem::ascii(FOUNDATION_PROFILE.protocol_name)?,
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::hash512(self.manifest_hash.into_bytes()),
                CanonicalItem::hash512(self.roster_hash.into_bytes()),
                CanonicalItem::nonempty_ascii(&self.ceremony_identifier)?,
            ],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionContext {
    pub ceremony_context_hash: Hash512,
    pub action_identifier: String,
    pub action_definition_hash: Hash512,
    pub board_policy_hash: Hash512,
}

impl ActionContext {
    pub fn new(
        ceremony_context_hash: Hash512,
        action_identifier: String,
        action_definition_hash: Hash512,
        board_policy_hash: Hash512,
    ) -> SchemaResult<Self> {
        validate_external_identifier(&action_identifier, "action identifier is invalid")?;
        Ok(Self {
            ceremony_context_hash,
            action_identifier,
            action_definition_hash,
            board_policy_hash,
        })
    }

    pub fn context_hash(&self) -> SchemaResult<Hash512> {
        Self::new(
            self.ceremony_context_hash,
            self.action_identifier.clone(),
            self.action_definition_hash,
            self.board_policy_hash,
        )?;
        Ok(hash512(
            "sealed-lattice/foundation/action-context/v1",
            &[
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::nonempty_ascii(&self.action_identifier)?,
                CanonicalItem::hash512(self.action_definition_hash.into_bytes()),
                CanonicalItem::hash512(self.board_policy_hash.into_bytes()),
            ],
        )?)
    }
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

fn validate_external_identifier(value: &str, message: &'static str) -> SchemaResult<()> {
    if value.is_empty() || value.len() > FOUNDATION_PROFILE.maximum_identifier_byte_length {
        return Err(schema_error(RefusalReason::WrongTypeOrLength, message));
    }
    CanonicalItem::nonempty_ascii(value).map_err(|_| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "external identifier must contain printable ASCII",
        )
    })?;
    Ok(())
}

fn read_display_text(item: &CanonicalItem) -> SchemaResult<StabilizedDisplayText> {
    let bytes = read_variable_item(item, CanonicalItemType::DisplayText)?;
    StabilizedDisplayText::from_canonical_utf8(bytes).map_err(|_| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "display text is not canonical stabilized Unicode text",
        )
    })
}

fn encode_u16_list(values: &[u16]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned16)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned16,
        &items,
    )?)
}

fn encode_u64_list(values: &[u64]) -> SchemaResult<CanonicalItem> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned64)
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Unsigned64,
        &items,
    )?)
}

fn read_u16_list(item: &CanonicalItem) -> SchemaResult<Vec<u16>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned16)?;
    let expected_byte_length = count.checked_mul(2).ok_or_else(|| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "u16 list byte length overflows",
        )
    })?;
    if bytes.len() != expected_byte_length {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "u16 list byte length is malformed",
        ));
    }
    bytes
        .chunks_exact(2)
        .map(|chunk| {
            let bytes: [u8; 2] = chunk.try_into().map_err(|_| {
                schema_error(RefusalReason::MalformedEncoding, "u16 list element length")
            })?;
            Ok(u16::from_le_bytes(bytes))
        })
        .collect()
}

fn read_u64_list(item: &CanonicalItem) -> SchemaResult<Vec<u64>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned64)?;
    let expected_byte_length = count.checked_mul(8).ok_or_else(|| {
        schema_error(
            RefusalReason::MalformedEncoding,
            "u64 list byte length overflows",
        )
    })?;
    if bytes.len() != expected_byte_length {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "u64 list byte length is malformed",
        ));
    }
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let bytes: [u8; 8] = chunk.try_into().map_err(|_| {
                schema_error(RefusalReason::MalformedEncoding, "u64 list element length")
            })?;
            Ok(u64::from_le_bytes(bytes))
        })
        .collect()
}

fn is_prime_u64(candidate: u64) -> bool {
    const SMALL_PRIMES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    const DETERMINISTIC_BASES: [u64; 7] =
        [2, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022];

    if candidate < 2 {
        return false;
    }
    for prime in SMALL_PRIMES {
        if candidate.is_multiple_of(prime) {
            return candidate == prime;
        }
    }

    let exponent_of_two = (candidate - 1).trailing_zeros();
    let odd_factor = (candidate - 1) >> exponent_of_two;
    'base: for base in DETERMINISTIC_BASES {
        if base % candidate == 0 {
            continue;
        }
        let mut witness = modular_power(base % candidate, odd_factor, candidate);
        if witness == 1 || witness == candidate - 1 {
            continue;
        }
        for _ in 1..exponent_of_two {
            witness = modular_product(witness, witness, candidate);
            if witness == candidate - 1 {
                continue 'base;
            }
        }
        return false;
    }
    true
}

fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = modular_product(result, base, modulus);
        }
        base = modular_product(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn modular_product(left: u64, right: u64, modulus: u64) -> u64 {
    u64::try_from((u128::from(left) * u128::from(right)) % u128::from(modulus))
        .expect("modular product is smaller than its u64 modulus")
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    fn display_text(value: &str) -> StabilizedDisplayText {
        StabilizedDisplayText::from_ingress_utf8(value.as_bytes())
            .expect("test display text is valid")
    }

    fn test_manifest(title: &str) -> Manifest {
        let options = (0..FOUNDATION_PROFILE.option_count)
            .map(|option_index| {
                OptionDefinition::new(
                    option_index,
                    format!("option-{option_index:02}"),
                    display_text(&format!("Choice {option_index}")),
                )
                .expect("test option is valid")
            })
            .collect();
        Manifest::new(display_text(title), options).expect("test manifest is valid")
    }

    fn artifacts() -> Vec<ArtifactReference> {
        SuiteArtifactKind::ALL
            .into_iter()
            .map(|artifact_kind| {
                ArtifactReference::from_canonical_artifact(
                    artifact_kind,
                    &[
                        u8::try_from(artifact_kind.canonical_code())
                            .expect("test artifact kind fits u8"),
                        0x5a,
                        0xa5,
                    ],
                )
                .expect("test artifact is valid")
            })
            .collect()
    }

    fn suite_record() -> SuiteRecord {
        SuiteRecord {
            roster_size: FOUNDATION_PROFILE.participant_count,
            byzantine_bound: FOUNDATION_PROFILE.active_fault_bound,
            reconstruction_threshold: FOUNDATION_PROFILE.reconstruction_threshold,
            finality_quorum: FOUNDATION_PROFILE.finality_quorum,
            polynomial_degree: 8,
            plaintext_modulus: 17,
            ordered_data_primes: vec![97, 113, 193],
            ordered_special_primes: vec![241],
            ordered_target_data_prime_indexes: vec![0, 1],
            ordered_sharing_data_prime_indexes: vec![0, 1, 2],
            key_switch_data_primes_per_block: 2,
            maximum_ballot_attempts_per_participant: 2,
            maximum_recovery_transitions_per_state_key: 3,
            maximum_target_share_submissions: FOUNDATION_PROFILE.participant_count,
            maximum_private_sampler_candidate_draws_per_output: 64,
            maximum_public_sampler_candidate_draws_per_output: 128,
            maximum_candidate_packages_per_action: 15,
            maximum_proof_objects_per_action: 400,
            maximum_candidate_bytes_per_participant: 2_000,
            maximum_candidate_bytes_per_action: 15_000,
            maximum_setup_bytes_per_participant: 3_000,
            maximum_proof_bytes_per_action: 9_000,
            maximum_public_corpus_bytes: 30_000,
            maximum_participant_upload_bytes: 5_000,
            maximum_ceremony_upload_bytes: 40_000,
            distributions: DistributionRecord::supported_profile_records(),
            artifacts: artifacts(),
        }
    }

    #[test]
    fn manifest_and_context_hashes_bind_every_operative_value() {
        let manifest = test_manifest("Cafe\u{301} poll");
        assert_eq!(manifest.title.as_str(), "Caf\u{e9} poll");
        let manifest_bytes = manifest.encode().expect("manifest encodes");
        assert_eq!(
            Manifest::decode(&manifest_bytes, &CanonicalDecodeLimits::default())
                .expect("manifest decodes"),
            manifest
        );

        let manifest_tuple =
            CanonicalTuple::decode(&manifest_bytes, &CanonicalDecodeLimits::default())
                .expect("manifest tuple decodes");
        assert_eq!(manifest_tuple.items.len(), 2);
        let (option_count, option_bytes) =
            read_list_header(&manifest_tuple.items[1], CanonicalItemType::NestedTuple)
                .expect("option list decodes");
        assert_eq!(option_count, usize::from(FOUNDATION_PROFILE.option_count));
        let first_option = CanonicalTuple::decode_prefix(
            option_bytes,
            &CanonicalDecodeLimits::default(),
            &mut CanonicalDecodeBudget::new(&CanonicalDecodeLimits::default()),
            1,
        )
        .expect("first option decodes")
        .0;
        assert_eq!(first_option.items.len(), 3);

        let action_definition =
            ActionDefinition::new(4, 1_800_000_000_000).expect("action definition is valid");
        let board_policy =
            BoardPolicy::new("https://board.example".to_owned()).expect("board policy is valid");
        let suite_id = suite_record().suite_id().expect("suite ID derives");
        let roster_hash = Hash512::from_bytes([0x31; 64]);
        let ceremony = CeremonyContext::new(
            suite_id,
            manifest.manifest_hash().expect("manifest hash derives"),
            roster_hash,
            "ceremony-2026".to_owned(),
        )
        .expect("ceremony context is valid");
        let ceremony_hash = ceremony.context_hash().expect("ceremony hash derives");
        let action = ActionContext::new(
            ceremony_hash,
            "action-01".to_owned(),
            action_definition
                .action_definition_hash()
                .expect("action-definition hash derives"),
            board_policy
                .board_policy_hash()
                .expect("board-policy hash derives"),
        )
        .expect("action context is valid");
        let action_hash = action.context_hash().expect("action hash derives");

        let changed_manifest = test_manifest("Another poll");
        assert_ne!(
            manifest.manifest_hash().expect("manifest hash derives"),
            changed_manifest
                .manifest_hash()
                .expect("changed manifest hash derives")
        );
        let changed_ceremony = CeremonyContext::new(
            suite_id,
            manifest.manifest_hash().expect("manifest hash derives"),
            roster_hash,
            "ceremony-2027".to_owned(),
        )
        .expect("changed ceremony is valid");
        assert_ne!(
            ceremony_hash,
            changed_ceremony
                .context_hash()
                .expect("changed ceremony hash derives")
        );
        let changed_action = ActionContext::new(
            ceremony_hash,
            "action-02".to_owned(),
            action.action_definition_hash,
            action.board_policy_hash,
        )
        .expect("changed action is valid");
        assert_ne!(
            action_hash,
            changed_action
                .context_hash()
                .expect("changed action hash derives")
        );
        assert_ne!(
            action_definition
                .submission_cutoff_hash(action_hash)
                .expect("cutoff hash derives"),
            action_definition
                .submission_cutoff_hash(changed_action.context_hash().expect("context hash"))
                .expect("changed cutoff hash derives")
        );
    }

    #[test]
    fn manifest_rejects_duplicate_or_disordered_options() {
        let mut duplicate = test_manifest("Duplicate check");
        duplicate.options[7].option_identifier = duplicate.options[3].option_identifier.clone();
        assert_eq!(
            duplicate
                .encode()
                .expect_err("duplicate option refuses")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        let mut disordered = test_manifest("Order check");
        disordered.options.swap(2, 3);
        assert_eq!(
            disordered
                .encode()
                .expect_err("disordered options refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut missing = test_manifest("Count check");
        missing.options.pop();
        assert_eq!(
            missing
                .encode()
                .expect_err("wrong option count refuses")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    #[test]
    fn action_and_external_identifier_boundaries_are_exact() {
        for top_count in [1, FOUNDATION_PROFILE.option_count] {
            let definition =
                ActionDefinition::new(top_count, u64::MAX).expect("boundary top count is valid");
            let bytes = definition.encode().expect("definition encodes");
            assert_eq!(
                ActionDefinition::decode(&bytes, &CanonicalDecodeLimits::default())
                    .expect("definition decodes"),
                definition
            );
        }
        for invalid_top_count in [0, FOUNDATION_PROFILE.option_count + 1, u16::MAX] {
            assert_eq!(
                ActionDefinition::new(invalid_top_count, 0)
                    .expect_err("invalid top count refuses")
                    .refusal_reason,
                RefusalReason::OutsideSupportedProfile
            );
        }

        let exact_limit = "a".repeat(FOUNDATION_PROFILE.maximum_identifier_byte_length);
        BoardPolicy::new(exact_limit).expect("exact identifier limit is valid");
        assert!(
            BoardPolicy::new("a".repeat(FOUNDATION_PROFILE.maximum_identifier_byte_length + 1))
                .is_err()
        );
        assert!(BoardPolicy::new("board\norigin".to_owned()).is_err());
        assert!(BoardPolicy::new(String::new()).is_err());
    }

    #[test]
    fn distribution_and_artifact_records_enforce_closed_assignments() {
        for record in DistributionRecord::supported_profile_records() {
            let bytes = record.encode().expect("distribution encodes");
            assert_eq!(
                DistributionRecord::decode(&bytes, &CanonicalDecodeLimits::default())
                    .expect("distribution decodes"),
                record
            );
        }
        assert!(
            DistributionRecord::new(
                DistributionPurpose::SecretContribution,
                DistributionKind::CenteredBinomial,
                2,
            )
            .is_err()
        );
        assert!(
            DistributionRecord::new(
                DistributionPurpose::PublicKeyError,
                DistributionKind::CenteredBinomial,
                3,
            )
            .is_err()
        );

        let artifact_bytes = b"canonical artifact body";
        let reference = ArtifactReference::from_canonical_artifact(
            SuiteArtifactKind::ProofProfileSet,
            artifact_bytes,
        )
        .expect("artifact reference derives");
        reference
            .verify_canonical_artifact(artifact_bytes)
            .expect("matching artifact verifies");
        assert_eq!(
            reference
                .verify_canonical_artifact(b"canonical artifact bodz")
                .expect_err("changed artifact refuses")
                .refusal_reason,
            RefusalReason::WrongHashOrRoot
        );
        let encoded = reference.encode().expect("artifact reference encodes");
        assert_eq!(
            ArtifactReference::decode(&encoded, &CanonicalDecodeLimits::default())
                .expect("artifact reference decodes"),
            reference
        );
    }

    #[test]
    fn suite_record_round_trip_and_id_cover_all_operative_inputs() {
        let suite = suite_record();
        let encoded = suite.encode().expect("suite encodes");
        let decoded = SuiteRecord::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("suite decodes");
        assert_eq!(decoded, suite);
        assert_eq!(
            decoded.suite_id().expect("decoded suite ID derives"),
            suite.suite_id().expect("suite ID derives")
        );

        let tuple = CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("suite tuple decodes");
        assert_eq!(tuple.items.len(), 27);

        let mut changed_suite = suite.clone();
        changed_suite.maximum_public_sampler_candidate_draws_per_output += 1;
        assert_ne!(
            suite.suite_id().expect("suite ID derives"),
            changed_suite.suite_id().expect("changed suite ID derives")
        );
    }

    #[test]
    fn suite_record_rejects_composite_duplicate_basis_and_cap_errors() {
        let mut composite_modulus = suite_record();
        composite_modulus.ordered_data_primes[0] = 81;
        assert!(composite_modulus.encode().is_err());

        let mut duplicate_modulus = suite_record();
        duplicate_modulus.ordered_special_primes[0] = duplicate_modulus.ordered_data_primes[1];
        assert_eq!(
            duplicate_modulus
                .encode()
                .expect_err("duplicate modulus refuses")
                .refusal_reason,
            RefusalReason::DuplicateIdentity
        );

        let mut nonprefix_target = suite_record();
        nonprefix_target.ordered_target_data_prime_indexes = vec![0, 2];
        assert!(nonprefix_target.encode().is_err());

        let mut target_outside_sharing = suite_record();
        target_outside_sharing.ordered_sharing_data_prime_indexes = vec![0, 2];
        assert!(target_outside_sharing.encode().is_err());

        let mut inconsistent_candidate_bytes = suite_record();
        inconsistent_candidate_bytes.maximum_candidate_bytes_per_action += 1;
        assert!(inconsistent_candidate_bytes.encode().is_err());

        let mut overflow_candidate_count = suite_record();
        overflow_candidate_count.maximum_candidate_packages_per_action = u32::MAX;
        assert!(overflow_candidate_count.encode().is_err());

        let mut reordered_distributions = suite_record();
        reordered_distributions.distributions.swap(0, 1);
        assert!(reordered_distributions.encode().is_err());

        let mut reordered_artifacts = suite_record();
        reordered_artifacts.artifacts.swap(2, 3);
        assert!(reordered_artifacts.encode().is_err());
    }

    #[test]
    fn hostile_suite_encodings_refuse_without_panicking() {
        let encoded = suite_record().encode().expect("suite encodes");
        let mut malformed_values = vec![
            encoded[..encoded.len() - 1].to_vec(),
            {
                let mut bytes = encoded.clone();
                bytes.push(0);
                bytes
            },
            {
                let mut bytes = encoded.clone();
                bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
                bytes
            },
        ];

        let mut oversized_distribution_count = encoded.clone();
        let distribution_payload_offset = tuple_item_payload_offset(&encoded, 25);
        oversized_distribution_count
            [distribution_payload_offset + 2..distribution_payload_offset + 6]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        malformed_values.push(oversized_distribution_count);

        let restrictive_limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: encoded.len(),
            maximum_item_count: 64,
            maximum_item_byte_length: encoded.len(),
            maximum_nesting_depth: 4,
            maximum_cumulative_work_byte_length: encoded.len() * 3,
            maximum_cumulative_allocation_byte_length: encoded.len() * 2,
        };
        for malformed in malformed_values {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                SuiteRecord::decode(&malformed, &restrictive_limits)
            }));
            assert!(outcome.is_ok(), "hostile decoding must not panic");
            assert!(outcome.expect("decode completed").is_err());
        }
    }

    #[test]
    fn deterministic_u64_primality_rejects_strong_pseudoprimes() {
        for prime in [2, 17, 97, 241, 18_446_744_073_709_551_557] {
            assert!(is_prime_u64(prime), "{prime} should be prime");
        }
        for composite in [0, 1, 4, 81, 3_215_031_751, 341_550_071_728_321, u64::MAX] {
            assert!(!is_prime_u64(composite), "{composite} should be composite");
        }
    }

    fn tuple_item_payload_offset(bytes: &[u8], requested_index: usize) -> usize {
        let mut offset = 8;
        for item_index in 0..=requested_index {
            let payload_length = u32::from_le_bytes(
                bytes[offset + 2..offset + 6]
                    .try_into()
                    .expect("test item header is complete"),
            ) as usize;
            let payload_offset = offset + 6;
            if item_index == requested_index {
                return payload_offset;
            }
            offset = payload_offset + payload_length;
        }
        unreachable!("requested test item exists")
    }
}
