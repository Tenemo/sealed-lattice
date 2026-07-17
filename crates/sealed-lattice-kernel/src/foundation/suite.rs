//! Canonical fixed-suite identity and artifact bindings.

use super::canonical_tuple::CanonicalDecodeBudget;
use super::hash::StreamingFoundationTupleHash512;
use super::schemas::{
    SchemaResult, read_hash, read_list_header, read_nested_tuple_list_with_budget, read_u16,
    read_u32, read_u64, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    FoundationRosterParameters, FoundationSchemaError, Hash512, RefusalReason,
    derive_foundation_roster_parameters, hash_foundation_tuple_512,
};
use crate::bgv::{
    evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    key_switch_topology::KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
    parameters::{
        DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES,
        root_parameters_for_modulus, validate_supported_algebraic_parameters,
    },
};

pub const DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0116;
pub const ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER: u16 = 0x0117;
pub const SUITE_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0118;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const SUITE_RECORD_VERSION: u16 = 1;
const KEY_SWITCH_METHOD: u16 = 1;
const KEY_SWITCH_BASIS_CONVERTER: u16 = 1;
const SUITE_HASH_DOMAIN: &str = "sealed-lattice/foundation/suite/v1";
const SUITE_ARTIFACT_HASH_DOMAIN: &str = "sealed-lattice/foundation/suite-artifact/v1";
const ORDERED_SPECIAL_PRIMES: [u64; SPECIAL_PRIMES.len()] = SPECIAL_PRIMES;
const ORDERED_TARGET_DATA_PRIME_INDEXES: [u16; 2] = [0, 1];
const ORDERED_SHARING_DATA_PRIME_INDEXES: [u16; DATA_PRIMES.len()] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    BallotEncryptionErrorZero = 9,
    BallotEncryptionErrorOne = 10,
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
        Self::BallotEncryptionErrorZero,
        Self::BallotEncryptionErrorOne,
        Self::LatticeCommitmentHidingSecret,
        Self::LatticeCommitmentHidingError,
    ];

    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    fn from_canonical_code(code: u16) -> SchemaResult<Self> {
        Self::ALL
            .into_iter()
            .find(|purpose| purpose.canonical_code() == code)
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "distribution purpose is not part of the supported suite",
                )
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DistributionKind {
    Ternary,
    CenteredBinomial { parameter: u64 },
}

impl DistributionKind {
    pub const fn canonical_code(self) -> u16 {
        match self {
            Self::Ternary => 1,
            Self::CenteredBinomial { .. } => 2,
        }
    }

    pub const fn parameter(self) -> u64 {
        match self {
            Self::Ternary => 0,
            Self::CenteredBinomial { parameter } => parameter,
        }
    }

    pub const fn absolute_support_bound(self) -> u64 {
        match self {
            Self::Ternary => 1,
            Self::CenteredBinomial { parameter } => parameter,
        }
    }

    fn from_canonical_parts(kind: u16, parameter: u64) -> SchemaResult<Self> {
        match (kind, parameter) {
            (1, 0) => Ok(Self::Ternary),
            (2, positive_parameter) if positive_parameter > 0 => Ok(Self::CenteredBinomial {
                parameter: positive_parameter,
            }),
            _ => Err(FoundationSchemaError::new(
                RefusalReason::UnsupportedVersionOrSuite,
                "distribution kind and parameter are not supported",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DistributionRecord {
    purpose: DistributionPurpose,
    kind: DistributionKind,
}

impl DistributionRecord {
    pub fn new(purpose: DistributionPurpose, kind: DistributionKind) -> SchemaResult<Self> {
        if matches!(kind, DistributionKind::CenteredBinomial { parameter: 0 }) {
            return Err(FoundationSchemaError::new(
                RefusalReason::UnsupportedVersionOrSuite,
                "centered-binomial distribution parameter must be positive",
            ));
        }
        Ok(Self { purpose, kind })
    }

    const fn ternary(purpose: DistributionPurpose) -> Self {
        Self {
            purpose,
            kind: DistributionKind::Ternary,
        }
    }

    const fn centered_binomial_two(purpose: DistributionPurpose) -> Self {
        Self {
            purpose,
            kind: DistributionKind::CenteredBinomial { parameter: 2 },
        }
    }

    pub const fn purpose(self) -> DistributionPurpose {
        self.purpose
    }

    pub const fn kind(self) -> DistributionKind {
        self.kind
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.purpose.canonical_code()),
                CanonicalItem::unsigned16(self.kind.canonical_code()),
                CanonicalItem::unsigned64(self.kind.parameter()),
            ],
        )
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER, 3)?;
        Self::new(
            DistributionPurpose::from_canonical_code(read_u16(&tuple.items[0])?)?,
            DistributionKind::from_canonical_parts(
                read_u16(&tuple.items[1])?,
                read_u64(&tuple.items[2])?,
            )?,
        )
    }
}

const FIXED_DISTRIBUTIONS: [DistributionRecord; 12] = [
    DistributionRecord::ternary(DistributionPurpose::SecretContribution),
    DistributionRecord::centered_binomial_two(DistributionPurpose::PublicKeyError),
    DistributionRecord::ternary(DistributionPurpose::RelinearizationKeyGenerationEphemeralSecret),
    DistributionRecord::centered_binomial_two(
        DistributionPurpose::RelinearizationKeyGenerationRoundOneLeftError,
    ),
    DistributionRecord::centered_binomial_two(
        DistributionPurpose::RelinearizationKeyGenerationRoundOneRightError,
    ),
    DistributionRecord::centered_binomial_two(
        DistributionPurpose::RelinearizationKeyGenerationRoundTwoError,
    ),
    DistributionRecord::centered_binomial_two(DistributionPurpose::GaloisKeyError),
    DistributionRecord::ternary(DistributionPurpose::BallotEncryptionEphemeralSecret),
    DistributionRecord::centered_binomial_two(DistributionPurpose::BallotEncryptionErrorZero),
    DistributionRecord::centered_binomial_two(DistributionPurpose::BallotEncryptionErrorOne),
    DistributionRecord::ternary(DistributionPurpose::LatticeCommitmentHidingSecret),
    DistributionRecord::ternary(DistributionPurpose::LatticeCommitmentHidingError),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    pub const fn artifact_schema_identifier(self) -> u16 {
        match self {
            Self::EncoderAndBallotLayout => 0x1300,
            Self::VerifiableSecretSharingProfile => 0x2120,
            Self::LatticeCommitmentProfile => 0x2122,
            Self::ProofProfileSet => 0x2200,
            Self::EvaluatorProgramSet => 0x1500,
            Self::TargetDecryptionProfile => 0x1630,
        }
    }

    pub const fn artifact_schema_version(self) -> u16 {
        match self {
            Self::LatticeCommitmentProfile => 3,
            Self::ProofProfileSet => 2,
            Self::EncoderAndBallotLayout
            | Self::VerifiableSecretSharingProfile
            | Self::EvaluatorProgramSet
            | Self::TargetDecryptionProfile => FOUNDATION_SCHEMA_VERSION,
        }
    }

    fn from_canonical_code(code: u16) -> SchemaResult<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.canonical_code() == code)
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "artifact kind is not part of the supported suite",
                )
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactReference {
    artifact_kind: ArtifactKind,
    byte_length: u64,
    artifact_hash: Hash512,
}

impl ArtifactReference {
    pub fn new(
        artifact_kind: ArtifactKind,
        byte_length: u64,
        artifact_hash: Hash512,
    ) -> SchemaResult<Self> {
        if byte_length == 0 {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite artifact byte length must be positive",
            ));
        }
        Ok(Self {
            artifact_kind,
            byte_length,
            artifact_hash,
        })
    }

    pub fn from_canonical_artifact_bytes(
        artifact_kind: ArtifactKind,
        canonical_artifact_bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        let artifact_tuple = CanonicalTuple::decode(canonical_artifact_bytes, limits)?;
        if artifact_tuple.schema_identifier != artifact_kind.artifact_schema_identifier() {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "suite artifact has the wrong canonical schema",
            ));
        }
        if artifact_tuple.schema_version != artifact_kind.artifact_schema_version() {
            return Err(FoundationSchemaError::new(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite artifact schema version is unsupported",
            ));
        }
        let byte_length = u64::try_from(canonical_artifact_bytes.len()).map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite artifact byte length does not fit u64",
            )
        })?;
        let artifact_hash = derive_artifact_hash(artifact_kind, canonical_artifact_bytes)?;
        Self::new(artifact_kind, byte_length, artifact_hash)
    }

    pub const fn artifact_kind(self) -> ArtifactKind {
        self.artifact_kind
    }

    pub const fn byte_length(self) -> u64 {
        self.byte_length
    }

    pub const fn artifact_hash(self) -> Hash512 {
        self.artifact_hash
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.artifact_kind.canonical_code()),
                CanonicalItem::unsigned64(self.byte_length),
                CanonicalItem::hash512(self.artifact_hash.into_bytes()),
            ],
        )
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER, 3)?;
        Self::new(
            ArtifactKind::from_canonical_code(read_u16(&tuple.items[0])?)?,
            read_u64(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteCountLimits {
    maximum_ballot_attempts_per_participant: u16,
    maximum_target_share_submissions: u16,
    maximum_private_sampler_candidate_draws_per_output: u32,
    maximum_public_sampler_candidate_draws_per_output: u32,
    maximum_candidate_packages_per_action: u32,
    maximum_proof_objects_per_action: u32,
}

impl SuiteCountLimits {
    pub(crate) fn new(
        maximum_ballot_attempts_per_participant: u16,
        maximum_target_share_submissions: u16,
        maximum_private_sampler_candidate_draws_per_output: u32,
        maximum_public_sampler_candidate_draws_per_output: u32,
        maximum_candidate_packages_per_action: u32,
        maximum_proof_objects_per_action: u32,
    ) -> SchemaResult<Self> {
        Self::new_for_roster(
            maximum_ballot_attempts_per_participant,
            maximum_target_share_submissions,
            maximum_private_sampler_candidate_draws_per_output,
            maximum_public_sampler_candidate_draws_per_output,
            maximum_candidate_packages_per_action,
            maximum_proof_objects_per_action,
            FOUNDATION_PROFILE.participant_count,
        )
    }

    fn new_for_roster(
        maximum_ballot_attempts_per_participant: u16,
        maximum_target_share_submissions: u16,
        maximum_private_sampler_candidate_draws_per_output: u32,
        maximum_public_sampler_candidate_draws_per_output: u32,
        maximum_candidate_packages_per_action: u32,
        maximum_proof_objects_per_action: u32,
        participant_count: u16,
    ) -> SchemaResult<Self> {
        let limits = Self {
            maximum_ballot_attempts_per_participant,
            maximum_target_share_submissions,
            maximum_private_sampler_candidate_draws_per_output,
            maximum_public_sampler_candidate_draws_per_output,
            maximum_candidate_packages_per_action,
            maximum_proof_objects_per_action,
        };
        limits.validate_for_roster(participant_count)?;
        Ok(limits)
    }

    fn validate_for_roster(self, participant_count: u16) -> SchemaResult<()> {
        if self.maximum_ballot_attempts_per_participant == 0
            || self.maximum_target_share_submissions == 0
            || self.maximum_private_sampler_candidate_draws_per_output == 0
            || self.maximum_public_sampler_candidate_draws_per_output == 0
            || self.maximum_candidate_packages_per_action == 0
            || self.maximum_proof_objects_per_action == 0
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite count maxima must be positive",
            ));
        }
        if self.maximum_target_share_submissions != participant_count {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "target-share submission maximum must equal the roster size",
            ));
        }
        let maximum_candidate_packages = u32::from(participant_count)
            .checked_mul(u32::from(self.maximum_ballot_attempts_per_participant))
            .ok_or_else(cap_overflow)?;
        if self.maximum_candidate_packages_per_action < u32::from(participant_count)
            || self.maximum_candidate_packages_per_action > maximum_candidate_packages
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "candidate-package maximum is inconsistent with the roster and attempt maximum",
            ));
        }
        Ok(())
    }

    pub const fn maximum_ballot_attempts_per_participant(self) -> u16 {
        self.maximum_ballot_attempts_per_participant
    }

    pub const fn maximum_target_share_submissions(self) -> u16 {
        self.maximum_target_share_submissions
    }

    pub const fn maximum_private_sampler_candidate_draws_per_output(self) -> u32 {
        self.maximum_private_sampler_candidate_draws_per_output
    }

    pub const fn maximum_public_sampler_candidate_draws_per_output(self) -> u32 {
        self.maximum_public_sampler_candidate_draws_per_output
    }

    pub const fn maximum_candidate_packages_per_action(self) -> u32 {
        self.maximum_candidate_packages_per_action
    }

    pub const fn maximum_proof_objects_per_action(self) -> u32 {
        self.maximum_proof_objects_per_action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteByteLimits {
    maximum_candidate_bytes_per_participant: u64,
    maximum_candidate_bytes_per_action: u64,
    maximum_setup_bytes_per_participant: u64,
    maximum_proof_bytes_per_action: u64,
    maximum_public_corpus_bytes: u64,
    maximum_participant_upload_bytes: u64,
    maximum_ceremony_upload_bytes: u64,
}

impl SuiteByteLimits {
    pub(crate) fn new(
        maximum_candidate_bytes_per_participant: u64,
        maximum_candidate_bytes_per_action: u64,
        maximum_setup_bytes_per_participant: u64,
        maximum_proof_bytes_per_action: u64,
        maximum_public_corpus_bytes: u64,
        maximum_participant_upload_bytes: u64,
        maximum_ceremony_upload_bytes: u64,
    ) -> SchemaResult<Self> {
        let limits = Self {
            maximum_candidate_bytes_per_participant,
            maximum_candidate_bytes_per_action,
            maximum_setup_bytes_per_participant,
            maximum_proof_bytes_per_action,
            maximum_public_corpus_bytes,
            maximum_participant_upload_bytes,
            maximum_ceremony_upload_bytes,
        };
        limits.validate_positive()?;
        Ok(limits)
    }

    fn validate_positive(self) -> SchemaResult<()> {
        if self.maximum_candidate_bytes_per_participant == 0
            || self.maximum_candidate_bytes_per_action == 0
            || self.maximum_setup_bytes_per_participant == 0
            || self.maximum_proof_bytes_per_action == 0
            || self.maximum_public_corpus_bytes == 0
            || self.maximum_participant_upload_bytes == 0
            || self.maximum_ceremony_upload_bytes == 0
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "suite byte maxima must be positive",
            ));
        }
        Ok(())
    }

    pub const fn maximum_candidate_bytes_per_participant(self) -> u64 {
        self.maximum_candidate_bytes_per_participant
    }

    pub const fn maximum_candidate_bytes_per_action(self) -> u64 {
        self.maximum_candidate_bytes_per_action
    }

    pub const fn maximum_setup_bytes_per_participant(self) -> u64 {
        self.maximum_setup_bytes_per_participant
    }

    pub const fn maximum_proof_bytes_per_action(self) -> u64 {
        self.maximum_proof_bytes_per_action
    }

    pub const fn maximum_public_corpus_bytes(self) -> u64 {
        self.maximum_public_corpus_bytes
    }

    pub const fn maximum_participant_upload_bytes(self) -> u64 {
        self.maximum_participant_upload_bytes
    }

    pub const fn maximum_ceremony_upload_bytes(self) -> u64 {
        self.maximum_ceremony_upload_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteRecord {
    roster_parameters: FoundationRosterParameters,
    count_limits: SuiteCountLimits,
    byte_limits: SuiteByteLimits,
    artifacts: Vec<ArtifactReference>,
}

impl SuiteRecord {
    #[cfg(test)]
    pub(crate) fn new(
        count_limits: SuiteCountLimits,
        byte_limits: SuiteByteLimits,
        artifacts: Vec<ArtifactReference>,
    ) -> SchemaResult<Self> {
        let roster_parameters =
            derive_foundation_roster_parameters(FOUNDATION_PROFILE.participant_count)
                .ok_or_else(unsupported_roster_size)?;
        Self::new_for_roster(roster_parameters, count_limits, byte_limits, artifacts)
    }

    fn new_for_roster(
        roster_parameters: FoundationRosterParameters,
        count_limits: SuiteCountLimits,
        byte_limits: SuiteByteLimits,
        artifacts: Vec<ArtifactReference>,
    ) -> SchemaResult<Self> {
        let record = Self {
            roster_parameters,
            count_limits,
            byte_limits,
            artifacts,
        };
        record.validate()?;
        require_copied_buffer_bound(&record.canonical_tuple()?)?;
        Ok(record)
    }

    pub const fn suite_record_version(&self) -> u16 {
        SUITE_RECORD_VERSION
    }

    pub const fn roster_size(&self) -> u16 {
        self.roster_parameters.participant_count
    }

    pub const fn byzantine_bound(&self) -> u16 {
        self.roster_parameters.active_fault_bound
    }

    pub const fn reconstruction_threshold(&self) -> u16 {
        self.roster_parameters.reconstruction_threshold
    }

    pub const fn finality_quorum(&self) -> u16 {
        self.roster_parameters.finality_quorum
    }

    pub const fn polynomial_degree(&self) -> u32 {
        POLYNOMIAL_DEGREE as u32
    }

    pub const fn plaintext_modulus(&self) -> u64 {
        PLAINTEXT_MODULUS
    }

    pub const fn ordered_data_primes(&self) -> &'static [u64] {
        &DATA_PRIMES
    }

    pub const fn ordered_special_primes(&self) -> &'static [u64] {
        &ORDERED_SPECIAL_PRIMES
    }

    pub const fn ordered_target_data_prime_indexes(&self) -> &'static [u16] {
        &ORDERED_TARGET_DATA_PRIME_INDEXES
    }

    pub const fn ordered_sharing_data_prime_indexes(&self) -> &'static [u16] {
        &ORDERED_SHARING_DATA_PRIME_INDEXES
    }

    pub const fn key_switch_method(&self) -> u16 {
        KEY_SWITCH_METHOD
    }

    pub const fn key_switch_data_primes_per_block(&self) -> u16 {
        KEY_SWITCH_DATA_PRIMES_PER_BLOCK as u16
    }

    pub const fn key_switch_basis_converter(&self) -> u16 {
        KEY_SWITCH_BASIS_CONVERTER
    }

    pub const fn count_limits(&self) -> SuiteCountLimits {
        self.count_limits
    }

    pub const fn byte_limits(&self) -> SuiteByteLimits {
        self.byte_limits
    }

    pub const fn distributions(&self) -> &'static [DistributionRecord] {
        &FIXED_DISTRIBUTIONS
    }

    pub fn artifacts(&self) -> &[ArtifactReference] {
        &self.artifacts
    }

    pub fn artifact(&self, artifact_kind: ArtifactKind) -> &ArtifactReference {
        &self.artifacts[usize::from(artifact_kind.canonical_code() - 1)]
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(self.canonical_tuple()?.encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, SUITE_RECORD_SCHEMA_IDENTIFIER, 29)?;
        let roster_parameters = validate_suite_items(&tuple)?;

        let count_limits = SuiteCountLimits::new_for_roster(
            read_u16(&tuple.items[14])?,
            read_u16(&tuple.items[15])?,
            read_u32(&tuple.items[16])?,
            read_u32(&tuple.items[17])?,
            read_u32(&tuple.items[18])?,
            read_u32(&tuple.items[19])?,
            roster_parameters.participant_count,
        )?;
        let byte_limits = SuiteByteLimits::new(
            read_u64(&tuple.items[20])?,
            read_u64(&tuple.items[21])?,
            read_u64(&tuple.items[22])?,
            read_u64(&tuple.items[23])?,
            read_u64(&tuple.items[24])?,
            read_u64(&tuple.items[25])?,
            read_u64(&tuple.items[26])?,
        )?;
        let distributions =
            read_nested_tuple_list_with_budget(&tuple.items[27], limits, &mut budget)?
                .iter()
                .map(DistributionRecord::from_tuple)
                .collect::<SchemaResult<Vec<_>>>()?;
        if distributions.as_slice() != FIXED_DISTRIBUTIONS {
            return Err(FoundationSchemaError::new(
                RefusalReason::UnsupportedVersionOrSuite,
                "distribution catalog does not match the supported suite",
            ));
        }
        let artifacts = read_nested_tuple_list_with_budget(&tuple.items[28], limits, &mut budget)?
            .iter()
            .map(ArtifactReference::from_tuple)
            .collect::<SchemaResult<Vec<_>>>()?;
        Self::new_for_roster(roster_parameters, count_limits, byte_limits, artifacts)
    }

    pub fn suite_id(&self) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            SUITE_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    fn validate(&self) -> SchemaResult<()> {
        let derived_roster_parameters =
            derive_foundation_roster_parameters(self.roster_parameters.participant_count)
                .ok_or_else(unsupported_roster_size)?;
        if derived_roster_parameters != self.roster_parameters {
            return Err(invalid_roster_parameters());
        }
        self.count_limits
            .validate_for_roster(self.roster_parameters.participant_count)?;
        self.byte_limits.validate_positive()?;
        validate_fixed_algebra()?;
        validate_artifacts(&self.artifacts)?;
        validate_cross_field_limits(self.count_limits, self.byte_limits)
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        self.validate()?;
        let distribution_items = FIXED_DISTRIBUTIONS
            .iter()
            .copied()
            .map(|record| {
                CanonicalItem::nested_tuple(&record.canonical_tuple()).map_err(Into::into)
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        let artifact_items = self
            .artifacts
            .iter()
            .copied()
            .map(|reference| {
                CanonicalItem::nested_tuple(&reference.canonical_tuple()).map_err(Into::into)
            })
            .collect::<SchemaResult<Vec<_>>>()?;

        Ok(CanonicalTuple::new(
            SUITE_RECORD_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(SUITE_RECORD_VERSION),
                CanonicalItem::unsigned16(self.roster_parameters.participant_count),
                CanonicalItem::unsigned16(self.roster_parameters.active_fault_bound),
                CanonicalItem::unsigned16(self.roster_parameters.reconstruction_threshold),
                CanonicalItem::unsigned16(self.roster_parameters.finality_quorum),
                CanonicalItem::unsigned32(fixed_polynomial_degree()?),
                CanonicalItem::unsigned64(PLAINTEXT_MODULUS),
                unsigned64_list(&DATA_PRIMES)?,
                unsigned64_list(&ORDERED_SPECIAL_PRIMES)?,
                unsigned16_list(&ORDERED_TARGET_DATA_PRIME_INDEXES)?,
                unsigned16_list(&ORDERED_SHARING_DATA_PRIME_INDEXES)?,
                CanonicalItem::unsigned16(KEY_SWITCH_METHOD),
                CanonicalItem::unsigned16(fixed_key_switch_data_primes_per_block()?),
                CanonicalItem::unsigned16(KEY_SWITCH_BASIS_CONVERTER),
                CanonicalItem::unsigned16(
                    self.count_limits.maximum_ballot_attempts_per_participant,
                ),
                CanonicalItem::unsigned16(self.count_limits.maximum_target_share_submissions),
                CanonicalItem::unsigned32(
                    self.count_limits
                        .maximum_private_sampler_candidate_draws_per_output,
                ),
                CanonicalItem::unsigned32(
                    self.count_limits
                        .maximum_public_sampler_candidate_draws_per_output,
                ),
                CanonicalItem::unsigned32(self.count_limits.maximum_candidate_packages_per_action),
                CanonicalItem::unsigned32(self.count_limits.maximum_proof_objects_per_action),
                CanonicalItem::unsigned64(self.byte_limits.maximum_candidate_bytes_per_participant),
                CanonicalItem::unsigned64(self.byte_limits.maximum_candidate_bytes_per_action),
                CanonicalItem::unsigned64(self.byte_limits.maximum_setup_bytes_per_participant),
                CanonicalItem::unsigned64(self.byte_limits.maximum_proof_bytes_per_action),
                CanonicalItem::unsigned64(self.byte_limits.maximum_public_corpus_bytes),
                CanonicalItem::unsigned64(self.byte_limits.maximum_participant_upload_bytes),
                CanonicalItem::unsigned64(self.byte_limits.maximum_ceremony_upload_bytes),
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::NestedTuple,
                    &distribution_items,
                )?,
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &artifact_items)?,
            ],
        ))
    }
}

fn validate_suite_items(tuple: &CanonicalTuple) -> SchemaResult<FoundationRosterParameters> {
    let participant_count = read_u16(&tuple.items[1])?;
    let roster_parameters = derive_foundation_roster_parameters(participant_count)
        .ok_or_else(unsupported_roster_size)?;
    if read_u16(&tuple.items[2])? != roster_parameters.active_fault_bound
        || read_u16(&tuple.items[3])? != roster_parameters.reconstruction_threshold
        || read_u16(&tuple.items[4])? != roster_parameters.finality_quorum
    {
        return Err(invalid_roster_parameters());
    }

    let fixed_fields_match = read_u16(&tuple.items[0])? == SUITE_RECORD_VERSION
        && read_u32(&tuple.items[5])? == fixed_polynomial_degree()?
        && read_u64(&tuple.items[6])? == PLAINTEXT_MODULUS
        && read_unsigned64_list(&tuple.items[7])? == DATA_PRIMES
        && read_unsigned64_list(&tuple.items[8])? == ORDERED_SPECIAL_PRIMES
        && read_unsigned16_list(&tuple.items[9])? == ORDERED_TARGET_DATA_PRIME_INDEXES
        && read_unsigned16_list(&tuple.items[10])? == ORDERED_SHARING_DATA_PRIME_INDEXES
        && read_u16(&tuple.items[11])? == KEY_SWITCH_METHOD
        && read_u16(&tuple.items[12])? == fixed_key_switch_data_primes_per_block()?
        && read_u16(&tuple.items[13])? == KEY_SWITCH_BASIS_CONVERTER;
    if !fixed_fields_match {
        return Err(FoundationSchemaError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "suite record does not match the supported fixed algebra",
        ));
    }
    Ok(roster_parameters)
}

fn validate_fixed_algebra() -> SchemaResult<()> {
    if !POLYNOMIAL_DEGREE.is_power_of_two()
        || POLYNOMIAL_DEGREE == 0
        || CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1 != ORDERED_TARGET_DATA_PRIME_INDEXES.len()
        || KEY_SWITCH_DATA_PRIMES_PER_BLOCK == 0
    {
        return Err(invalid_fixed_algebra());
    }
    let twice_polynomial_degree = u64::try_from(POLYNOMIAL_DEGREE)
        .ok()
        .and_then(|degree| degree.checked_mul(2))
        .ok_or_else(invalid_fixed_algebra)?;
    if !(PLAINTEXT_MODULUS - 1).is_multiple_of(twice_polynomial_degree)
        || root_parameters_for_modulus(PLAINTEXT_MODULUS).is_none()
    {
        return Err(invalid_fixed_algebra());
    }
    let mut all_ciphertext_moduli = DATA_PRIMES.to_vec();
    all_ciphertext_moduli.extend(ORDERED_SPECIAL_PRIMES);
    all_ciphertext_moduli.sort_unstable();
    if all_ciphertext_moduli
        .windows(2)
        .any(|pair| pair[0] == pair[1])
        || all_ciphertext_moduli.iter().any(|modulus| {
            *modulus == PLAINTEXT_MODULUS
                || !(*modulus - 1).is_multiple_of(twice_polynomial_degree)
                || root_parameters_for_modulus(*modulus).is_none()
        })
    {
        return Err(invalid_fixed_algebra());
    }
    if ORDERED_TARGET_DATA_PRIME_INDEXES
        .iter()
        .enumerate()
        .any(|(position, index)| usize::from(*index) != position)
        || ORDERED_SHARING_DATA_PRIME_INDEXES
            .iter()
            .enumerate()
            .any(|(position, index)| usize::from(*index) != position)
        || !ORDERED_TARGET_DATA_PRIME_INDEXES
            .iter()
            .all(|index| ORDERED_SHARING_DATA_PRIME_INDEXES.contains(index))
    {
        return Err(invalid_fixed_algebra());
    }
    validate_supported_algebraic_parameters().map_err(|_| invalid_fixed_algebra())
}

fn validate_artifacts(artifacts: &[ArtifactReference]) -> SchemaResult<()> {
    if artifacts.len() != ArtifactKind::ALL.len() {
        return Err(FoundationSchemaError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "suite must contain exactly one reference for every artifact kind",
        ));
    }
    for (reference, expected_kind) in artifacts.iter().zip(ArtifactKind::ALL) {
        if reference.artifact_kind != expected_kind || reference.byte_length == 0 {
            return Err(FoundationSchemaError::new(
                RefusalReason::UnsupportedVersionOrSuite,
                "suite artifact references must be complete and canonically ordered",
            ));
        }
    }
    Ok(())
}

fn validate_cross_field_limits(
    count_limits: SuiteCountLimits,
    byte_limits: SuiteByteLimits,
) -> SchemaResult<()> {
    let ballot_package_byte_ceiling = byte_limits.maximum_candidate_bytes_per_participant
        / u64::from(count_limits.maximum_ballot_attempts_per_participant);
    if ballot_package_byte_ceiling == 0
        || u64::from(count_limits.maximum_ballot_attempts_per_participant)
            .checked_mul(ballot_package_byte_ceiling)
            .ok_or_else(cap_overflow)?
            != byte_limits.maximum_candidate_bytes_per_participant
        || u64::from(count_limits.maximum_candidate_packages_per_action)
            .checked_mul(ballot_package_byte_ceiling)
            .ok_or_else(cap_overflow)?
            != byte_limits.maximum_candidate_bytes_per_action
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "candidate byte maxima do not encode one consistent package ceiling",
        ));
    }
    if byte_limits.maximum_candidate_bytes_per_participant
        > byte_limits.maximum_participant_upload_bytes
        || byte_limits.maximum_setup_bytes_per_participant
            > byte_limits.maximum_participant_upload_bytes
        || byte_limits.maximum_candidate_bytes_per_participant
            > byte_limits.maximum_candidate_bytes_per_action
        || byte_limits.maximum_candidate_bytes_per_action > byte_limits.maximum_public_corpus_bytes
        || byte_limits.maximum_proof_bytes_per_action > byte_limits.maximum_public_corpus_bytes
        || byte_limits.maximum_candidate_bytes_per_action
            > byte_limits.maximum_ceremony_upload_bytes
        || byte_limits.maximum_proof_bytes_per_action > byte_limits.maximum_ceremony_upload_bytes
        || byte_limits.maximum_participant_upload_bytes > byte_limits.maximum_ceremony_upload_bytes
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "suite byte maxima are inconsistent with their containing resource caps",
        ));
    }
    Ok(())
}

fn derive_artifact_hash(
    artifact_kind: ArtifactKind,
    canonical_artifact_bytes: &[u8],
) -> SchemaResult<Hash512> {
    let byte_length = u64::try_from(canonical_artifact_bytes.len()).map_err(|_| {
        FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "suite artifact byte length does not fit u64",
        )
    })?;
    let mut hasher = StreamingFoundationTupleHash512::new_variable_bytes(
        SUITE_ARTIFACT_HASH_DOMAIN,
        &[
            CanonicalItem::unsigned16(artifact_kind.canonical_code()),
            CanonicalItem::unsigned64(byte_length),
        ],
        canonical_artifact_bytes.len(),
    )
    .map_err(|_| artifact_hash_error())?;
    hasher
        .absorb(canonical_artifact_bytes)
        .map_err(|_| artifact_hash_error())?;
    hasher.finalize().map_err(|_| artifact_hash_error())
}

fn unsigned16_list(values: &[u16]) -> SchemaResult<CanonicalItem> {
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

fn unsigned64_list(values: &[u64]) -> SchemaResult<CanonicalItem> {
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

fn read_unsigned16_list(item: &CanonicalItem) -> SchemaResult<Vec<u16>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned16)?;
    let expected_byte_length = count.checked_mul(2).ok_or_else(list_length_error)?;
    if bytes.len() != expected_byte_length {
        return Err(list_length_error());
    }
    bytes
        .chunks_exact(2)
        .map(|chunk| {
            let encoded: [u8; 2] = chunk.try_into().map_err(|_| list_length_error())?;
            Ok(u16::from_le_bytes(encoded))
        })
        .collect()
}

fn read_unsigned64_list(item: &CanonicalItem) -> SchemaResult<Vec<u64>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::Unsigned64)?;
    let expected_byte_length = count.checked_mul(8).ok_or_else(list_length_error)?;
    if bytes.len() != expected_byte_length {
        return Err(list_length_error());
    }
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let encoded: [u8; 8] = chunk.try_into().map_err(|_| list_length_error())?;
            Ok(u64::from_le_bytes(encoded))
        })
        .collect()
}

fn fixed_polynomial_degree() -> SchemaResult<u32> {
    u32::try_from(POLYNOMIAL_DEGREE).map_err(|_| invalid_fixed_algebra())
}

fn fixed_key_switch_data_primes_per_block() -> SchemaResult<u16> {
    u16::try_from(KEY_SWITCH_DATA_PRIMES_PER_BLOCK).map_err(|_| invalid_fixed_algebra())
}

fn require_copied_buffer_bound(tuple: &CanonicalTuple) -> SchemaResult<()> {
    if tuple.encode()?.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "suite record exceeds the supported copied-buffer bound",
        ));
    }
    Ok(())
}

fn invalid_fixed_algebra() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::InvalidArithmeticRelation,
        "fixed suite algebraic parameters are inconsistent",
    )
}

fn invalid_roster_parameters() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::InvalidArithmeticRelation,
        "suite roster parameters do not match the configurable formulas",
    )
}

fn unsupported_roster_size() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::OutsideSupportedProfile,
        "suite roster size is outside the configurable range",
    )
}

fn cap_overflow() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::OutsideSupportedProfile,
        "suite resource-cap arithmetic overflows",
    )
}

fn list_length_error() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::MalformedEncoding,
        "suite list byte length is malformed",
    )
}

fn artifact_hash_error() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::OutsideSupportedProfile,
        "suite artifact hash framing exceeds the supported bounds",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_count_limits() -> SuiteCountLimits {
        SuiteCountLimits::new(3, 10, 64, 128, 20, 100).expect("test count limits are valid")
    }

    fn sample_byte_limits() -> SuiteByteLimits {
        SuiteByteLimits::new(3_000, 20_000, 5_000, 25_000, 50_000, 10_000, 100_000)
            .expect("test byte limits are valid")
    }

    fn sample_artifact_reference(artifact_kind: ArtifactKind) -> ArtifactReference {
        let artifact_tuple = CanonicalTuple::new(
            artifact_kind.artifact_schema_identifier(),
            artifact_kind.artifact_schema_version(),
            vec![CanonicalItem::unsigned16(artifact_kind.canonical_code())],
        );
        let artifact_bytes = artifact_tuple.encode().expect("test artifact encodes");
        ArtifactReference::from_canonical_artifact_bytes(
            artifact_kind,
            &artifact_bytes,
            &CanonicalDecodeLimits::default(),
        )
        .expect("test artifact reference derives")
    }

    fn sample_artifacts() -> Vec<ArtifactReference> {
        ArtifactKind::ALL
            .into_iter()
            .map(sample_artifact_reference)
            .collect()
    }

    fn sample_suite() -> SuiteRecord {
        SuiteRecord::new(
            sample_count_limits(),
            sample_byte_limits(),
            sample_artifacts(),
        )
        .expect("test suite is valid")
    }

    #[test]
    fn suite_round_trip_preserves_the_exact_twenty_nine_item_record_and_identifier() {
        let suite = sample_suite();
        let encoded = suite.encode().expect("suite encodes");
        let tuple = CanonicalTuple::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("suite tuple decodes");
        assert_eq!(tuple.schema_identifier, SUITE_RECORD_SCHEMA_IDENTIFIER);
        assert_eq!(tuple.items.len(), 29);

        let decoded = SuiteRecord::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("suite decodes");
        assert_eq!(decoded, suite);
        assert_eq!(decoded.encode().expect("decoded suite encodes"), encoded);
        assert_eq!(
            decoded
                .suite_id()
                .expect("decoded suite identifier derives"),
            suite.suite_id().expect("suite identifier derives")
        );
        assert_eq!(suite.ordered_target_data_prime_indexes(), &[0, 1]);
        assert_eq!(suite.ordered_sharing_data_prime_indexes().len(), 17);
        assert_eq!(suite.distributions(), FIXED_DISTRIBUTIONS);
    }

    #[test]
    fn suite_schema_derives_a_configurable_nonselected_roster() {
        let roster_parameters =
            derive_foundation_roster_parameters(3).expect("three participants are configurable");
        let mut tuple = sample_suite()
            .canonical_tuple()
            .expect("selected suite tuple derives");
        tuple.items[1] = CanonicalItem::unsigned16(roster_parameters.participant_count);
        tuple.items[2] = CanonicalItem::unsigned16(roster_parameters.active_fault_bound);
        tuple.items[3] = CanonicalItem::unsigned16(roster_parameters.reconstruction_threshold);
        tuple.items[4] = CanonicalItem::unsigned16(roster_parameters.finality_quorum);
        tuple.items[15] = CanonicalItem::unsigned16(roster_parameters.participant_count);
        tuple.items[18] = CanonicalItem::unsigned32(6);
        tuple.items[21] = CanonicalItem::unsigned64(6_000);

        let encoded = tuple.encode().expect("candidate suite encodes");
        let decoded = SuiteRecord::decode(&encoded, &CanonicalDecodeLimits::default())
            .expect("candidate suite is structural");
        assert_eq!(decoded.roster_size(), 3);
        assert_eq!(decoded.byzantine_bound(), 0);
        assert_eq!(decoded.reconstruction_threshold(), 2);
        assert_eq!(decoded.finality_quorum(), 2);
        assert_eq!(
            decoded.encode().expect("candidate suite re-encodes"),
            encoded
        );
    }

    #[test]
    fn suite_schema_refuses_roster_parameters_that_do_not_match_the_formulas() {
        let mut tuple = sample_suite()
            .canonical_tuple()
            .expect("selected suite tuple derives");
        tuple.items[3] = CanonicalItem::unsigned16(FOUNDATION_PROFILE.reconstruction_threshold + 1);
        assert_eq!(
            SuiteRecord::decode(
                &tuple.encode().expect("mutated suite encodes"),
                &CanonicalDecodeLimits::default(),
            )
            .expect_err("self-attested roster thresholds must refuse")
            .refusal_reason,
            RefusalReason::InvalidArithmeticRelation
        );

        let mut outside_range = sample_suite()
            .canonical_tuple()
            .expect("selected suite tuple derives");
        outside_range.items[1] = CanonicalItem::unsigned16(2);
        assert_eq!(
            SuiteRecord::decode(
                &outside_range.encode().expect("mutated suite encodes"),
                &CanonicalDecodeLimits::default(),
            )
            .expect_err("out-of-range roster size must refuse")
            .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    #[test]
    fn suite_decode_refuses_fixed_algebra_and_distribution_drift() {
        let mut wrong_degree = sample_suite()
            .canonical_tuple()
            .expect("suite tuple derives");
        wrong_degree.items[5] = CanonicalItem::unsigned32(fixed_polynomial_degree().unwrap() / 2);
        let wrong_degree_bytes = wrong_degree.encode().expect("mutated suite encodes");
        assert_eq!(
            SuiteRecord::decode(&wrong_degree_bytes, &CanonicalDecodeLimits::default())
                .expect_err("wrong degree must refuse")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );

        let mut wrong_distributions = sample_suite()
            .canonical_tuple()
            .expect("suite tuple derives");
        let mut distribution_tuples = read_nested_tuple_list_with_budget(
            &wrong_distributions.items[27],
            &CanonicalDecodeLimits::default(),
            &mut CanonicalDecodeBudget::new(&CanonicalDecodeLimits::default()),
        )
        .expect("distribution tuples decode");
        distribution_tuples[0].items[2] = CanonicalItem::unsigned64(1);
        let nested_distributions = distribution_tuples
            .iter()
            .map(|tuple| CanonicalItem::nested_tuple(tuple).expect("nested tuple encodes"))
            .collect::<Vec<_>>();
        wrong_distributions.items[27] =
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &nested_distributions)
                .expect("distribution list encodes");
        let wrong_distribution_bytes = wrong_distributions.encode().expect("mutated suite encodes");
        assert_eq!(
            SuiteRecord::decode(&wrong_distribution_bytes, &CanonicalDecodeLimits::default())
                .expect_err("wrong distribution must refuse")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );
    }

    #[test]
    fn suite_requires_one_canonically_ordered_reference_for_each_closed_artifact_kind() {
        let mut missing = sample_artifacts();
        missing.pop();
        assert_eq!(
            SuiteRecord::new(sample_count_limits(), sample_byte_limits(), missing)
                .expect_err("missing artifact must refuse")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );

        let mut reordered = sample_artifacts();
        reordered.swap(2, 3);
        assert_eq!(
            SuiteRecord::new(sample_count_limits(), sample_byte_limits(), reordered)
                .expect_err("reordered artifacts must refuse")
                .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );

        assert_eq!(
            ArtifactReference::new(
                ArtifactKind::ProofProfileSet,
                0,
                Hash512::from_bytes([0; 64])
            )
            .expect_err("empty artifact must refuse")
            .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    #[test]
    fn artifact_reference_binds_kind_length_and_canonical_bytes() {
        let kind = ArtifactKind::ProofProfileSet;
        let first_tuple = CanonicalTuple::new(
            kind.artifact_schema_identifier(),
            kind.artifact_schema_version(),
            vec![CanonicalItem::unsigned16(1)],
        );
        let second_tuple = CanonicalTuple::new(
            kind.artifact_schema_identifier(),
            kind.artifact_schema_version(),
            vec![CanonicalItem::unsigned16(2)],
        );
        let first = ArtifactReference::from_canonical_artifact_bytes(
            kind,
            &first_tuple.encode().expect("first artifact encodes"),
            &CanonicalDecodeLimits::default(),
        )
        .expect("first reference derives");
        let second = ArtifactReference::from_canonical_artifact_bytes(
            kind,
            &second_tuple.encode().expect("second artifact encodes"),
            &CanonicalDecodeLimits::default(),
        )
        .expect("second reference derives");
        assert_ne!(first.artifact_hash(), second.artifact_hash());

        let wrong_schema = CanonicalTuple::new(0x2201, 1, vec![])
            .encode()
            .expect("wrong-schema artifact encodes");
        assert_eq!(
            ArtifactReference::from_canonical_artifact_bytes(
                kind,
                &wrong_schema,
                &CanonicalDecodeLimits::default()
            )
            .expect_err("wrong artifact schema must refuse")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }

    #[test]
    fn lattice_commitment_reference_accepts_only_the_selected_version_three_artifact() {
        let artifact_bytes =
            crate::foundation::suite_artifacts::LatticeCommitmentProfile::selected()
                .and_then(|profile| profile.encode())
                .expect("selected lattice commitment artifact");
        let reference = ArtifactReference::from_canonical_artifact_bytes(
            ArtifactKind::LatticeCommitmentProfile,
            &artifact_bytes,
            &CanonicalDecodeLimits::default(),
        )
        .expect("selected lattice commitment reference");
        assert_eq!(
            reference.artifact_kind(),
            ArtifactKind::LatticeCommitmentProfile
        );

        for retired_version in [1_u16, 2] {
            let mut retired =
                CanonicalTuple::decode(&artifact_bytes, &CanonicalDecodeLimits::default())
                    .expect("selected lattice commitment tuple");
            retired.schema_version = retired_version;
            let retired_bytes = retired.encode().expect("retired artifact bytes");
            assert_eq!(
                ArtifactReference::from_canonical_artifact_bytes(
                    ArtifactKind::LatticeCommitmentProfile,
                    &retired_bytes,
                    &CanonicalDecodeLimits::default(),
                )
                .expect_err("retired lattice commitment artifact must refuse")
                .refusal_reason,
                RefusalReason::UnsupportedVersionOrSuite
            );
        }
    }

    #[test]
    fn resource_caps_refuse_zero_inconsistent_and_unreachable_boundaries() {
        assert_eq!(
            SuiteCountLimits::new(0, 10, 64, 128, 10, 100)
                .expect_err("zero attempt maximum must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
        assert_eq!(
            SuiteCountLimits::new(3, 9, 64, 128, 20, 100)
                .expect_err("target submissions below roster size must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
        assert_eq!(
            SuiteCountLimits::new(3, 10, 64, 128, 31, 100)
                .expect_err("candidate maximum above attempt product must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let inconsistent_candidate_bytes =
            SuiteByteLimits::new(3_001, 20_000, 5_000, 25_000, 50_000, 10_000, 100_000)
                .expect("positive byte limits construct");
        assert_eq!(
            SuiteRecord::new(
                sample_count_limits(),
                inconsistent_candidate_bytes,
                sample_artifacts()
            )
            .expect_err("inconsistent package byte ceiling must refuse")
            .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );

        let unreachable_upload =
            SuiteByteLimits::new(3_000, 20_000, 11_000, 25_000, 50_000, 10_000, 100_000)
                .expect("positive byte limits construct");
        assert_eq!(
            SuiteRecord::new(
                sample_count_limits(),
                unreachable_upload,
                sample_artifacts()
            )
            .expect_err("setup above participant upload must refuse")
            .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    #[test]
    fn suite_decode_honors_caller_limits_before_nested_allocation() {
        let encoded = sample_suite().encode().expect("suite encodes");
        let limits = CanonicalDecodeLimits {
            maximum_item_count: 28,
            ..CanonicalDecodeLimits::default()
        };
        assert_eq!(
            SuiteRecord::decode(&encoded, &limits)
                .expect_err("item limit must refuse")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }
}
