use core::fmt;
use std::collections::BTreeMap;

use tiny_keccak::{Hasher, Kmac};
use zeroize::{Zeroize, Zeroizing};

use super::schemas::{SchemaResult, read_hash, read_item, read_u16, require_header};
use super::{
    CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    FoundationSchemaError, Hash512, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
    ParticipantIdentity, RandomCursor, RefusalReason, hash512,
};

pub const ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0402;

const FOUNDATION_PROTOCOL_VERSION: u16 = 1;
const PRIVATE_RANDOMNESS_CUSTOMIZATION: &[u8] = b"sealed-lattice/private-randomness/v1";
const ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/private-randomness/action-key-hierarchy/v1";
const ACTION_RANDOMNESS_ROOT_BYTE_LENGTH: usize = 64;
const ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH: usize = 64;
const ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH: usize =
    3 * ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH;
const ACTION_RANDOMNESS_DERIVATION_INPUT_CANONICAL_BYTE_LENGTH: usize = 296;
const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const RANDOM_BLOCK_BYTE_LENGTH: usize = 64;
const PROOF_LEAF_SALT_PURPOSE: u16 = 0xfffe;

/// An entropy provider injected by the browser or native host.
///
/// A production implementation must fill the complete destination from a
/// cryptographic operating-system source and return an error when that source
/// is unavailable. The kernel intentionally ships no deterministic production
/// implementation.
pub trait FallibleEntropySource {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropySourceError {
    Unavailable,
}

impl fmt::Display for EntropySourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the cryptographic entropy source is unavailable")
    }
}

impl std::error::Error for EntropySourceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateRandomnessError {
    CandidateDrawLimitExhausted,
    EntropyUnavailable,
    RepeatedAttemptIdentifier,
    UnassignedDomain,
    InvalidModulus,
    InvalidCandidateDrawLimit,
    CounterExhausted,
    ResumeBindingMismatch,
    ResumeAttemptMismatch,
    InvalidResumeStreamSet,
    InvalidResumeCursorSet,
    InvalidResumeSecretState,
    PendingResumeAttempt,
    MissingResumeAttempt,
    CanonicalEncoding(CanonicalCodecError),
}

impl fmt::Display for PrivateRandomnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CandidateDrawLimitExhausted => formatter.write_str(
                "the private-randomness candidate-draw limit was exhausted before deriving an output",
            ),
            Self::EntropyUnavailable => {
                formatter.write_str("the cryptographic entropy source is unavailable")
            }
            Self::RepeatedAttemptIdentifier => {
                formatter.write_str("the entropy source repeated an attempt identifier")
            }
            Self::UnassignedDomain => {
                formatter.write_str("the private-randomness family and purpose are unassigned")
            }
            Self::InvalidModulus => {
                formatter.write_str("the sampling modulus must be greater than one")
            }
            Self::InvalidCandidateDrawLimit => formatter
                .write_str("the private-randomness candidate-draw limit must be positive"),
            Self::CounterExhausted => {
                formatter.write_str("the private-randomness block counter is exhausted")
            }
            Self::ResumeBindingMismatch => formatter.write_str(
                "the private-randomness resume snapshot has the wrong action binding",
            ),
            Self::ResumeAttemptMismatch => formatter.write_str(
                "the private-randomness resume snapshot has the wrong attempt identifier",
            ),
            Self::InvalidResumeStreamSet => formatter.write_str(
                "the private-randomness resume streams are not the exact ordered live set",
            ),
            Self::InvalidResumeCursorSet => formatter.write_str(
                "the public random cursors do not exactly match the secret resume streams",
            ),
            Self::InvalidResumeSecretState => formatter.write_str(
                "the private-randomness resume snapshot contains inconsistent secret state",
            ),
            Self::PendingResumeAttempt => formatter.write_str(
                "the restored private-randomness attempt must be resumed before starting another attempt",
            ),
            Self::MissingResumeAttempt => {
                formatter.write_str("there is no restored private-randomness attempt to resume")
            }
            Self::CanonicalEncoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PrivateRandomnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalCodecError> for PrivateRandomnessError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::CanonicalEncoding(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomnessActionBinding {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_identity: ParticipantIdentity,
}

impl PrivateRandomnessActionBinding {
    pub const fn new(
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        participant_identity: ParticipantIdentity,
    ) -> Self {
        Self {
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            participant_identity,
        }
    }

    pub const fn suite_id(&self) -> Hash512 {
        self.suite_id
    }

    pub const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub const fn participant_identity(&self) -> ParticipantIdentity {
        self.participant_identity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRandomnessDerivationInput {
    binding: PrivateRandomnessActionBinding,
}

impl ActionRandomnessDerivationInput {
    pub const fn new(binding: PrivateRandomnessActionBinding) -> Self {
        Self { binding }
    }

    pub const fn binding(self) -> PrivateRandomnessActionBinding {
        self.binding
    }

    pub fn encode(&self) -> Result<Vec<u8>, CanonicalCodecError> {
        CanonicalTuple::new(
            ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROTOCOL_VERSION),
                CanonicalItem::hash512(self.binding.suite_id.into_bytes()),
                CanonicalItem::hash512(self.binding.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.binding.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.binding.participant_identity.into_bytes()),
            ],
        )
        .encode()
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: limits
                .maximum_tuple_byte_length
                .min(ACTION_RANDOMNESS_DERIVATION_INPUT_CANONICAL_BYTE_LENGTH),
            maximum_item_count: limits.maximum_item_count.min(5),
            maximum_item_byte_length: limits
                .maximum_item_byte_length
                .min(ACTION_RANDOMNESS_DERIVATION_INPUT_CANONICAL_BYTE_LENGTH),
            maximum_nesting_depth: limits.maximum_nesting_depth,
            maximum_cumulative_work_byte_length: limits
                .maximum_cumulative_work_byte_length
                .min(ACTION_RANDOMNESS_DERIVATION_INPUT_CANONICAL_BYTE_LENGTH * 4),
            maximum_cumulative_allocation_byte_length: limits
                .maximum_cumulative_allocation_byte_length
                .min(ACTION_RANDOMNESS_DERIVATION_INPUT_CANONICAL_BYTE_LENGTH * 2),
        };
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(
            &tuple,
            ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            5,
        )?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        let participant_identity_bytes =
            read_item(&tuple.items[4], CanonicalItemType::ParticipantIdentity)?;
        let participant_identity = ParticipantIdentity::from_bytes(
            participant_identity_bytes.try_into().map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "participant identity has the wrong length",
                )
            })?,
        );
        Ok(Self::new(PrivateRandomnessActionBinding::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            participant_identity,
        )))
    }
}

struct ActionRandomnessKeyHierarchy {
    action_randomness_commitment_preimage: Zeroizing<[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]>,
    private_randomness_stream_key: Zeroizing<[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]>,
    proof_coin_key: Zeroizing<[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum SuiteSamplingPurpose {
    SecretContribution = 1,
    PublicKeyError = 2,
    RelinearizationKeyEphemeralSecret = 3,
    RelinearizationKeyRoundOneLeftError = 4,
    RelinearizationKeyRoundOneRightError = 5,
    RelinearizationKeyRoundTwoError = 6,
    GaloisKeyError = 7,
    BallotEncryptionEphemeralSecret = 8,
    BallotEncryptionErrorZero = 9,
    BallotEncryptionErrorOne = 10,
    LatticeCommitmentHidingSecret = 11,
    LatticeCommitmentHidingError = 12,
}

impl SuiteSamplingPurpose {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum VerifiableSecretSharingExpansionRole {
    Coefficient = 1,
    RecipientShare = 2,
    AggregateThresholdShare = 3,
}

impl VerifiableSecretSharingExpansionRole {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum TargetFloodingRole {
    Identifier = 1,
    Order = 2,
}

impl TargetFloodingRole {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }
}

/// A semantic private-randomness domain with no raw public constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivateRandomDomain {
    family: u16,
    purpose: u16,
}

impl PrivateRandomDomain {
    pub const fn suite_sampling(purpose: SuiteSamplingPurpose) -> Self {
        Self {
            family: 0x0116,
            purpose: purpose.canonical_code(),
        }
    }

    pub const fn verifiable_secret_sharing_expansion(
        role: VerifiableSecretSharingExpansionRole,
    ) -> Self {
        Self {
            family: 0x2120,
            purpose: role.canonical_code(),
        }
    }

    pub const fn target_flooding(role: TargetFloodingRole) -> Self {
        Self {
            family: 0x1630,
            purpose: role.canonical_code(),
        }
    }

    /// Constructs the fixed proof-leaf-salt domain for a verified statement
    /// schema. Proof-mask domains remain owned by immutable relation plans so
    /// this module never accepts a caller-selected mask purpose.
    pub fn proof_leaf_salt(
        statement_schema_identifier: u16,
    ) -> Result<Self, PrivateRandomnessError> {
        if !matches!(
            statement_schema_identifier,
            0x1211
                | 0x1212
                | 0x1213
                | 0x1214
                | 0x1215
                | 0x1216
                | 0x1217
                | 0x1218
                | 0x1302
                | 0x1621
                | 0x2110
                | 0x2111
        ) {
            return Err(PrivateRandomnessError::UnassignedDomain);
        }
        Ok(Self {
            family: statement_schema_identifier,
            purpose: PROOF_LEAF_SALT_PURPOSE,
        })
    }

    pub const fn family(self) -> u16 {
        self.family
    }

    pub const fn purpose(self) -> u16 {
        self.purpose
    }
}

/// One live private-randomness stream derived by an authenticated boundary
/// parser. The semantic domain has no raw caller-selected constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateRandomStreamContext {
    stream_key: PrivateRandomStreamKey,
}

impl PrivateRandomStreamContext {
    pub fn new(domain: PrivateRandomDomain, derivation_context_hash: Hash512) -> Self {
        Self {
            stream_key: PrivateRandomStreamKey::new(domain, derivation_context_hash),
        }
    }

    pub const fn family(self) -> u16 {
        self.stream_key.family
    }

    pub const fn purpose(self) -> u16 {
        self.stream_key.purpose
    }

    pub const fn derivation_context_hash(self) -> Hash512 {
        Hash512::from_bytes(self.stream_key.derivation_context_hash)
    }
}

/// Opaque secret state for one authenticated same-attempt resume.
///
/// This value is deliberately neither cloneable nor serializable. It may be
/// retained only inside the authenticated encrypted operation state that owns
/// the matching public manifest. Public manifests receive only `RandomCursor`
/// summaries derived through [`Self::try_derive_random_cursors`].
pub struct PrivateRandomnessResumeSnapshot {
    binding: PrivateRandomnessActionBinding,
    action_randomness_root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>,
    used_attempt_identifiers: Vec<Zeroizing<[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]>>,
    attempt_identifier: Zeroizing<[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]>,
    streams: Vec<PrivateRandomStreamSnapshot>,
}

impl PrivateRandomnessResumeSnapshot {
    /// Derives the complete public cursor list from the secret stream state.
    /// `next_counter` is the next block counter that may be generated. Any
    /// unread suffix of the previously generated block remains only here.
    pub fn try_derive_random_cursors(&self) -> Result<Vec<RandomCursor>, PrivateRandomnessError> {
        self.streams
            .iter()
            .map(|stream| {
                RandomCursor::new(
                    stream.stream_key.family,
                    stream.stream_key.purpose,
                    Hash512::from_bytes(stream.stream_key.derivation_context_hash),
                    stream.next_counter,
                )
                .map_err(|_| PrivateRandomnessError::InvalidResumeSecretState)
            })
            .collect()
    }
}

impl fmt::Debug for PrivateRandomnessResumeSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomnessResumeSnapshot")
            .field("binding", &self.binding)
            .field("action_randomness_root", &"[REDACTED]")
            .field("attempt_identifiers", &"[REDACTED]")
            .field("stream_secret_state", &"[REDACTED]")
            .field("stream_count", &self.streams.len())
            .finish()
    }
}

struct PrivateRandomStreamSnapshot {
    stream_key: PrivateRandomStreamKey,
    next_counter: u64,
    unread_block: Zeroizing<[u8; RANDOM_BLOCK_BYTE_LENGTH]>,
    unread_block_offset: usize,
}

struct PendingPrivateRandomAttempt {
    attempt_identifier: Zeroizing<[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]>,
    streams: BTreeMap<PrivateRandomStreamKey, PrivateRandomStreamCursor>,
}

/// Owns one action's fresh randomness root and prevents attempt reuse.
pub struct ActionPrivateRandomness {
    binding: PrivateRandomnessActionBinding,
    action_randomness_root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>,
    action_randomness_commitment: Hash512,
    private_randomness_stream_key: Zeroizing<[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]>,
    used_attempt_identifiers: Vec<Zeroizing<[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]>>,
    pending_resume_attempt: Option<PendingPrivateRandomAttempt>,
}

impl ActionPrivateRandomness {
    pub fn try_new<EntropySource: FallibleEntropySource + ?Sized>(
        binding: PrivateRandomnessActionBinding,
        entropy_source: &mut EntropySource,
    ) -> Result<Self, PrivateRandomnessError> {
        let mut action_randomness_root = Zeroizing::new([0u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]);
        entropy_source
            .try_fill_bytes(action_randomness_root.as_mut())
            .map_err(|_| PrivateRandomnessError::EntropyUnavailable)?;
        Self::from_root(binding, action_randomness_root, Vec::new(), None)
    }

    pub const fn binding(&self) -> &PrivateRandomnessActionBinding {
        &self.binding
    }

    pub const fn action_randomness_commitment(&self) -> Hash512 {
        self.action_randomness_commitment
    }

    fn from_root(
        binding: PrivateRandomnessActionBinding,
        action_randomness_root: Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>,
        used_attempt_identifiers: Vec<Zeroizing<[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]>>,
        pending_resume_attempt: Option<PendingPrivateRandomAttempt>,
    ) -> Result<Self, PrivateRandomnessError> {
        let key_hierarchy =
            derive_action_randomness_key_hierarchy(&binding, &action_randomness_root)?;
        let action_randomness_commitment = derive_action_randomness_commitment(
            &binding,
            &key_hierarchy.action_randomness_commitment_preimage,
        )?;
        let ActionRandomnessKeyHierarchy {
            private_randomness_stream_key,
            proof_coin_key,
            ..
        } = key_hierarchy;
        // No closed proof-attempt derivation consumes this child yet. Keep it
        // inaccessible and erase it instead of exposing a raw-key interface.
        drop(proof_coin_key);
        Ok(Self {
            binding,
            action_randomness_root,
            action_randomness_commitment,
            private_randomness_stream_key,
            used_attempt_identifiers,
            pending_resume_attempt,
        })
    }

    pub fn try_start_attempt<'action, EntropySource: FallibleEntropySource + ?Sized>(
        &'action mut self,
        entropy_source: &mut EntropySource,
    ) -> Result<PrivateRandomAttempt<'action>, PrivateRandomnessError> {
        if self.pending_resume_attempt.is_some() {
            return Err(PrivateRandomnessError::PendingResumeAttempt);
        }
        let mut attempt_identifier = Zeroizing::new([0u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        entropy_source
            .try_fill_bytes(attempt_identifier.as_mut())
            .map_err(|_| PrivateRandomnessError::EntropyUnavailable)?;

        if self
            .used_attempt_identifiers
            .iter()
            .any(|used_identifier| used_identifier.as_slice() == attempt_identifier.as_slice())
        {
            return Err(PrivateRandomnessError::RepeatedAttemptIdentifier);
        }
        self.used_attempt_identifiers
            .push(attempt_identifier.clone());

        Ok(PrivateRandomAttempt {
            owner: self,
            attempt_identifier,
            streams: BTreeMap::new(),
        })
    }

    /// Restores an opaque snapshot only after its action, attempt, exact live
    /// stream set, public counters, offsets, and unread suffixes all agree.
    pub fn try_restore_from_snapshot(
        expected_binding: PrivateRandomnessActionBinding,
        expected_attempt_identifier: &[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        expected_live_streams: &[PrivateRandomStreamContext],
        expected_random_cursors: &[RandomCursor],
        snapshot: PrivateRandomnessResumeSnapshot,
    ) -> Result<Self, PrivateRandomnessError> {
        validate_private_randomness_resume(
            &snapshot,
            expected_binding,
            expected_attempt_identifier,
            expected_live_streams,
            expected_random_cursors,
        )?;

        let PrivateRandomnessResumeSnapshot {
            binding,
            action_randomness_root,
            used_attempt_identifiers,
            attempt_identifier,
            streams,
        } = snapshot;
        let streams = streams
            .into_iter()
            .map(|stream| {
                (
                    stream.stream_key,
                    PrivateRandomStreamCursor {
                        next_counter: stream.next_counter,
                        unread_block: stream.unread_block,
                        unread_block_offset: stream.unread_block_offset,
                    },
                )
            })
            .collect();

        Self::from_root(
            binding,
            action_randomness_root,
            used_attempt_identifiers,
            Some(PendingPrivateRandomAttempt {
                attempt_identifier,
                streams,
            }),
        )
    }

    /// Takes the already-validated same-attempt state restored by
    /// [`Self::try_restore_from_snapshot`].
    pub fn try_resume_attempt(
        &mut self,
    ) -> Result<PrivateRandomAttempt<'_>, PrivateRandomnessError> {
        let pending_attempt = self
            .pending_resume_attempt
            .take()
            .ok_or(PrivateRandomnessError::MissingResumeAttempt)?;
        Ok(PrivateRandomAttempt {
            owner: self,
            attempt_identifier: pending_attempt.attempt_identifier,
            streams: pending_attempt.streams,
        })
    }
}

impl fmt::Debug for ActionPrivateRandomness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionPrivateRandomness")
            .field("binding", &self.binding)
            .field("action_randomness_root", &"[REDACTED]")
            .field("private_randomness_stream_key", &"[REDACTED]")
            .field(
                "action_randomness_commitment",
                &self.action_randomness_commitment,
            )
            .field(
                "used_attempt_identifier_count",
                &self.used_attempt_identifiers.len(),
            )
            .field(
                "has_pending_resume_attempt",
                &self.pending_resume_attempt.is_some(),
            )
            .finish()
    }
}

/// A fresh randomized attempt. It is deliberately neither cloneable nor
/// serializable; the runtime cursor schema owns authenticated resume.
pub struct PrivateRandomAttempt<'action> {
    owner: &'action mut ActionPrivateRandomness,
    attempt_identifier: Zeroizing<[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]>,
    streams: BTreeMap<PrivateRandomStreamKey, PrivateRandomStreamCursor>,
}

impl PrivateRandomAttempt<'_> {
    pub fn attempt_identifier(&self) -> &[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        &self.attempt_identifier
    }

    /// Captures exactly the boundary parser's ordered live streams for
    /// authenticated encrypted continuation. Streams not yet consumed are
    /// represented by a zero counter and an empty unread suffix.
    pub fn try_create_resume_snapshot(
        &self,
        expected_live_streams: &[PrivateRandomStreamContext],
    ) -> Result<PrivateRandomnessResumeSnapshot, PrivateRandomnessError> {
        validate_live_stream_order(expected_live_streams)?;
        if self.streams.keys().any(|stream_key| {
            expected_live_streams
                .binary_search_by_key(stream_key, |context| context.stream_key)
                .is_err()
        }) {
            return Err(PrivateRandomnessError::InvalidResumeStreamSet);
        }

        let streams = expected_live_streams
            .iter()
            .map(|context| {
                let cursor = self.streams.get(&context.stream_key);
                PrivateRandomStreamSnapshot {
                    stream_key: context.stream_key,
                    next_counter: cursor.map_or(0, |cursor| cursor.next_counter),
                    unread_block: cursor.map_or_else(
                        || Zeroizing::new([0u8; RANDOM_BLOCK_BYTE_LENGTH]),
                        |cursor| zeroizing_copy(&cursor.unread_block),
                    ),
                    unread_block_offset: cursor.map_or(RANDOM_BLOCK_BYTE_LENGTH, |cursor| {
                        cursor.unread_block_offset
                    }),
                }
            })
            .collect();
        let snapshot = PrivateRandomnessResumeSnapshot {
            binding: self.owner.binding,
            action_randomness_root: zeroizing_copy(&self.owner.action_randomness_root),
            used_attempt_identifiers: self
                .owner
                .used_attempt_identifiers
                .iter()
                .map(|identifier| zeroizing_copy(identifier))
                .collect(),
            attempt_identifier: zeroizing_copy(&self.attempt_identifier),
            streams,
        };
        let random_cursors = snapshot.try_derive_random_cursors()?;
        validate_private_randomness_resume(
            &snapshot,
            self.owner.binding,
            &self.attempt_identifier,
            expected_live_streams,
            &random_cursors,
        )?;
        Ok(snapshot)
    }

    /// Consumes the next bytes from exactly one semantic domain cursor.
    pub fn try_fill_bytes(
        &mut self,
        domain: PrivateRandomDomain,
        derivation_context_hash: Hash512,
        destination: &mut [u8],
    ) -> Result<(), PrivateRandomnessError> {
        let stream_key = PrivateRandomStreamKey::new(domain, derivation_context_hash);
        let binding = self.owner.binding;
        let private_randomness_stream_key = &*self.owner.private_randomness_stream_key;
        let attempt_identifier = &*self.attempt_identifier;
        let cursor = self.streams.entry(stream_key).or_default();
        cursor.try_fill_bytes(
            &binding,
            private_randomness_stream_key,
            attempt_identifier,
            stream_key,
            destination,
        )
    }

    /// Samples an unbiased residue from the next bytes of one domain cursor.
    pub fn try_sample_uniform(
        &mut self,
        domain: PrivateRandomDomain,
        derivation_context_hash: Hash512,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, PrivateRandomnessError> {
        if modulus <= 1 {
            return Err(PrivateRandomnessError::InvalidModulus);
        }
        if maximum_candidate_draws_per_output == 0 {
            return Err(PrivateRandomnessError::InvalidCandidateDrawLimit);
        }

        let modulus_bit_length = u64::BITS - modulus.leading_zeros();
        let sample_byte_length =
            usize::try_from(modulus_bit_length.div_ceil(8)).expect("a u64 bit length fits usize");
        let sample_space = 1u128 << (sample_byte_length * 8);
        let acceptance_limit = (sample_space / u128::from(modulus)) * u128::from(modulus);

        for _ in 0..maximum_candidate_draws_per_output {
            let mut candidate_bytes = Zeroizing::new([0u8; size_of::<u64>()]);
            self.try_fill_bytes(
                domain,
                derivation_context_hash,
                &mut candidate_bytes[..sample_byte_length],
            )?;
            let candidate = candidate_bytes[..sample_byte_length]
                .iter()
                .enumerate()
                .fold(0u64, |value, (byte_index, byte)| {
                    value | (u64::from(*byte) << (byte_index * 8))
                });
            if u128::from(candidate) < acceptance_limit {
                return Ok(candidate % modulus);
            }
        }
        Err(PrivateRandomnessError::CandidateDrawLimitExhausted)
    }
}

impl fmt::Debug for PrivateRandomAttempt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRandomAttempt")
            .field("attempt_identifier", &"[REDACTED]")
            .field("open_stream_count", &self.streams.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PrivateRandomStreamKey {
    family: u16,
    purpose: u16,
    derivation_context_hash: [u8; Hash512::BYTE_LENGTH],
}

impl PrivateRandomStreamKey {
    fn new(domain: PrivateRandomDomain, derivation_context_hash: Hash512) -> Self {
        Self {
            family: domain.family,
            purpose: domain.purpose,
            derivation_context_hash: derivation_context_hash.into_bytes(),
        }
    }

    fn from_random_cursor(cursor: &RandomCursor) -> Self {
        Self {
            family: cursor.family,
            purpose: cursor.purpose,
            derivation_context_hash: cursor.derivation_context_hash.into_bytes(),
        }
    }
}

struct PrivateRandomStreamCursor {
    next_counter: u64,
    unread_block: Zeroizing<[u8; RANDOM_BLOCK_BYTE_LENGTH]>,
    unread_block_offset: usize,
}

impl Default for PrivateRandomStreamCursor {
    fn default() -> Self {
        Self {
            next_counter: 0,
            unread_block: Zeroizing::new([0u8; RANDOM_BLOCK_BYTE_LENGTH]),
            unread_block_offset: RANDOM_BLOCK_BYTE_LENGTH,
        }
    }
}

impl PrivateRandomStreamCursor {
    fn try_fill_bytes(
        &mut self,
        binding: &PrivateRandomnessActionBinding,
        private_randomness_stream_key: &[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH],
        attempt_identifier: &[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        stream_key: PrivateRandomStreamKey,
        destination: &mut [u8],
    ) -> Result<(), PrivateRandomnessError> {
        self.preflight_counter_capacity(destination.len())?;
        if let Err(error) = self.try_fill_bytes_after_preflight(
            binding,
            private_randomness_stream_key,
            attempt_identifier,
            stream_key,
            destination,
        ) {
            destination.zeroize();
            return Err(error);
        }
        Ok(())
    }

    fn preflight_counter_capacity(
        &self,
        requested_byte_length: usize,
    ) -> Result<(), PrivateRandomnessError> {
        let unread_byte_length = RANDOM_BLOCK_BYTE_LENGTH - self.unread_block_offset;
        let required_new_byte_length = requested_byte_length.saturating_sub(unread_byte_length);
        let required_new_block_count = required_new_byte_length.div_ceil(RANDOM_BLOCK_BYTE_LENGTH);
        let required_new_block_count = u64::try_from(required_new_block_count)
            .map_err(|_| PrivateRandomnessError::CounterExhausted)?;
        if required_new_block_count > u64::MAX - self.next_counter {
            return Err(PrivateRandomnessError::CounterExhausted);
        }
        Ok(())
    }

    fn try_fill_bytes_after_preflight(
        &mut self,
        binding: &PrivateRandomnessActionBinding,
        private_randomness_stream_key: &[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH],
        attempt_identifier: &[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        stream_key: PrivateRandomStreamKey,
        mut destination: &mut [u8],
    ) -> Result<(), PrivateRandomnessError> {
        while !destination.is_empty() {
            if self.unread_block_offset == RANDOM_BLOCK_BYTE_LENGTH {
                self.unread_block = derive_private_random_block(
                    binding,
                    private_randomness_stream_key,
                    attempt_identifier,
                    stream_key,
                    self.next_counter,
                )?;
                self.next_counter += 1;
                self.unread_block_offset = 0;
            }

            let available_byte_length = RANDOM_BLOCK_BYTE_LENGTH - self.unread_block_offset;
            let copied_byte_length = destination.len().min(available_byte_length);
            let block_start = self.unread_block_offset;
            let block_end = self.unread_block_offset + copied_byte_length;
            destination[..copied_byte_length]
                .copy_from_slice(&self.unread_block[block_start..block_end]);
            self.unread_block[block_start..block_end].zeroize();
            self.unread_block_offset = block_end;
            destination = &mut destination[copied_byte_length..];
        }
        Ok(())
    }
}

fn validate_live_stream_order(
    expected_live_streams: &[PrivateRandomStreamContext],
) -> Result<(), PrivateRandomnessError> {
    if expected_live_streams
        .windows(2)
        .any(|adjacent| adjacent[0].stream_key >= adjacent[1].stream_key)
    {
        return Err(PrivateRandomnessError::InvalidResumeStreamSet);
    }
    Ok(())
}

fn validate_private_randomness_resume(
    snapshot: &PrivateRandomnessResumeSnapshot,
    expected_binding: PrivateRandomnessActionBinding,
    expected_attempt_identifier: &[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    expected_live_streams: &[PrivateRandomStreamContext],
    expected_random_cursors: &[RandomCursor],
) -> Result<(), PrivateRandomnessError> {
    if snapshot.binding != expected_binding {
        return Err(PrivateRandomnessError::ResumeBindingMismatch);
    }
    if snapshot.attempt_identifier.as_slice() != expected_attempt_identifier {
        return Err(PrivateRandomnessError::ResumeAttemptMismatch);
    }
    validate_live_stream_order(expected_live_streams)?;
    if snapshot.streams.len() != expected_live_streams.len()
        || snapshot
            .streams
            .iter()
            .zip(expected_live_streams)
            .any(|(stream, context)| stream.stream_key != context.stream_key)
    {
        return Err(PrivateRandomnessError::InvalidResumeStreamSet);
    }

    if expected_random_cursors.len() != snapshot.streams.len() {
        return Err(PrivateRandomnessError::InvalidResumeCursorSet);
    }
    for (random_cursor, stream) in expected_random_cursors.iter().zip(&snapshot.streams) {
        RandomCursor::new(
            random_cursor.family,
            random_cursor.purpose,
            random_cursor.derivation_context_hash,
            random_cursor.next_counter,
        )
        .map_err(|_| PrivateRandomnessError::InvalidResumeCursorSet)?;
        if PrivateRandomStreamKey::from_random_cursor(random_cursor) != stream.stream_key
            || random_cursor.next_counter != stream.next_counter
        {
            return Err(PrivateRandomnessError::InvalidResumeCursorSet);
        }
    }

    if snapshot
        .used_attempt_identifiers
        .last()
        .is_none_or(|identifier| identifier.as_slice() != snapshot.attempt_identifier.as_slice())
    {
        return Err(PrivateRandomnessError::InvalidResumeSecretState);
    }
    for (identifier_index, identifier) in snapshot.used_attempt_identifiers.iter().enumerate() {
        if snapshot.used_attempt_identifiers[..identifier_index]
            .iter()
            .any(|earlier_identifier| earlier_identifier.as_slice() == identifier.as_slice())
        {
            return Err(PrivateRandomnessError::InvalidResumeSecretState);
        }
    }

    let key_hierarchy = derive_action_randomness_key_hierarchy(
        &snapshot.binding,
        &snapshot.action_randomness_root,
    )?;
    for stream in &snapshot.streams {
        validate_private_random_stream_snapshot(
            stream,
            &snapshot.binding,
            &key_hierarchy.private_randomness_stream_key,
            &snapshot.attempt_identifier,
        )?;
    }
    Ok(())
}

fn validate_private_random_stream_snapshot(
    stream: &PrivateRandomStreamSnapshot,
    binding: &PrivateRandomnessActionBinding,
    private_randomness_stream_key: &[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH],
    attempt_identifier: &[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
) -> Result<(), PrivateRandomnessError> {
    if stream.unread_block_offset > RANDOM_BLOCK_BYTE_LENGTH
        || stream.unread_block[..stream.unread_block_offset]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(PrivateRandomnessError::InvalidResumeSecretState);
    }
    if stream.unread_block_offset == RANDOM_BLOCK_BYTE_LENGTH {
        return Ok(());
    }
    let previous_counter = stream
        .next_counter
        .checked_sub(1)
        .ok_or(PrivateRandomnessError::InvalidResumeSecretState)?;
    let expected_block = derive_private_random_block(
        binding,
        private_randomness_stream_key,
        attempt_identifier,
        stream.stream_key,
        previous_counter,
    )?;
    if stream.unread_block[stream.unread_block_offset..]
        != expected_block[stream.unread_block_offset..]
    {
        return Err(PrivateRandomnessError::InvalidResumeSecretState);
    }
    Ok(())
}

fn zeroizing_copy<const BYTE_LENGTH: usize>(
    source: &[u8; BYTE_LENGTH],
) -> Zeroizing<[u8; BYTE_LENGTH]> {
    Zeroizing::new(*source)
}

struct PrivateRandomBlockInput<'input> {
    binding: &'input PrivateRandomnessActionBinding,
    stream_key: PrivateRandomStreamKey,
    attempt_identifier: &'input [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    counter: u64,
}

impl PrivateRandomBlockInput<'_> {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CanonicalCodecError> {
        Ok(Zeroizing::new(
            CanonicalTuple::new(
                PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
                1,
                vec![
                    CanonicalItem::unsigned16(FOUNDATION_PROTOCOL_VERSION),
                    CanonicalItem::hash512(self.binding.suite_id.into_bytes()),
                    CanonicalItem::hash512(self.binding.ceremony_context_hash.into_bytes()),
                    CanonicalItem::hash512(self.binding.action_context_hash.into_bytes()),
                    CanonicalItem::participant_identity(
                        self.binding.participant_identity.into_bytes(),
                    ),
                    CanonicalItem::unsigned16(self.stream_key.family),
                    CanonicalItem::unsigned16(self.stream_key.purpose),
                    CanonicalItem::hash512(self.stream_key.derivation_context_hash),
                    CanonicalItem::fixed_bytes(self.attempt_identifier)?,
                    CanonicalItem::unsigned64(self.counter),
                ],
            )
            .encode()?,
        ))
    }
}

fn derive_private_random_block(
    binding: &PrivateRandomnessActionBinding,
    private_randomness_stream_key: &[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH],
    attempt_identifier: &[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    stream_key: PrivateRandomStreamKey,
    counter: u64,
) -> Result<Zeroizing<[u8; RANDOM_BLOCK_BYTE_LENGTH]>, PrivateRandomnessError> {
    let input_bytes = PrivateRandomBlockInput {
        binding,
        stream_key,
        attempt_identifier,
        counter,
    }
    .encode()?;
    Ok(kmac256::<RANDOM_BLOCK_BYTE_LENGTH>(
        private_randomness_stream_key,
        &input_bytes,
        PRIVATE_RANDOMNESS_CUSTOMIZATION,
    ))
}

fn derive_action_randomness_key_hierarchy(
    binding: &PrivateRandomnessActionBinding,
    action_randomness_root: &[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
) -> Result<ActionRandomnessKeyHierarchy, PrivateRandomnessError> {
    let derivation_input_bytes =
        Zeroizing::new(ActionRandomnessDerivationInput::new(*binding).encode()?);
    let key_material = kmac256::<ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH>(
        action_randomness_root,
        derivation_input_bytes.as_ref(),
        ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION,
    );
    let mut action_randomness_commitment_preimage =
        Zeroizing::new([0u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]);
    action_randomness_commitment_preimage
        .copy_from_slice(&key_material[..ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]);
    let mut private_randomness_stream_key =
        Zeroizing::new([0u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]);
    private_randomness_stream_key.copy_from_slice(
        &key_material
            [ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH..2 * ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH],
    );
    let mut proof_coin_key = Zeroizing::new([0u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]);
    proof_coin_key.copy_from_slice(&key_material[2 * ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH..]);
    Ok(ActionRandomnessKeyHierarchy {
        action_randomness_commitment_preimage,
        private_randomness_stream_key,
        proof_coin_key,
    })
}

fn derive_action_randomness_commitment(
    binding: &PrivateRandomnessActionBinding,
    action_randomness_commitment_preimage: &[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH],
) -> Result<Hash512, PrivateRandomnessError> {
    let derivation_input_bytes =
        Zeroizing::new(ActionRandomnessDerivationInput::new(*binding).encode()?);
    Ok(hash512(
        "sealed-lattice/private-randomness/action-root-commitment/v1",
        &[
            CanonicalItem::variable_bytes(derivation_input_bytes.as_slice())?,
            CanonicalItem::fixed_bytes(action_randomness_commitment_preimage)?,
        ],
    )?)
}

fn kmac256<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> Zeroizing<[u8; OUTPUT_BYTE_LENGTH]> {
    let mut output = Zeroizing::new([0u8; OUTPUT_BYTE_LENGTH]);
    let mut kmac = Kmac::v256(key, customization);
    kmac.update(message);
    kmac.finalize(output.as_mut());
    output
}

fn require_protocol_version(version: u16) -> SchemaResult<()> {
    if version != FOUNDATION_PROTOCOL_VERSION {
        return Err(FoundationSchemaError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "the private-randomness derivation input has an unsupported protocol version",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::foundation::CanonicalDecodeLimits;

    struct DeterministicTestEntropy {
        bytes: VecDeque<u8>,
    }

    impl DeterministicTestEntropy {
        fn new(bytes: impl IntoIterator<Item = u8>) -> Self {
            Self {
                bytes: bytes.into_iter().collect(),
            }
        }
    }

    impl FallibleEntropySource for DeterministicTestEntropy {
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceError> {
            if self.bytes.len() < destination.len() {
                return Err(EntropySourceError::Unavailable);
            }
            for destination_byte in destination {
                *destination_byte = self
                    .bytes
                    .pop_front()
                    .expect("preflight established enough deterministic test bytes");
            }
            Ok(())
        }
    }

    struct PartiallyFailingTestEntropy;

    impl FallibleEntropySource for PartiallyFailingTestEntropy {
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceError> {
            let written_prefix_byte_length = destination.len().min(7);
            destination[..written_prefix_byte_length].fill(0xa5);
            Err(EntropySourceError::Unavailable)
        }
    }

    fn test_binding() -> PrivateRandomnessActionBinding {
        PrivateRandomnessActionBinding::new(
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x22; 64]),
            Hash512::from_bytes([0x33; 64]),
            ParticipantIdentity::from_bytes([0x44; 64]),
        )
    }

    fn test_stream_key(
        binding: &PrivateRandomnessActionBinding,
        root: &[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
    ) -> Zeroizing<[u8; ACTION_RANDOMNESS_CHILD_KEY_BYTE_LENGTH]> {
        let key_hierarchy = derive_action_randomness_key_hierarchy(binding, root)
            .expect("the fixed action randomness hierarchy derives");
        zeroizing_copy(&key_hierarchy.private_randomness_stream_key)
    }

    fn lowercase_hexadecimal(bytes: &[u8]) -> String {
        const HEXADECIMAL_DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEXADECIMAL_DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(HEXADECIMAL_DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn deterministic_action_and_attempt() -> (ActionPrivateRandomness, DeterministicTestEntropy) {
        let mut entropy_bytes = Vec::new();
        entropy_bytes.extend_from_slice(&[0x51; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]);
        entropy_bytes.extend_from_slice(&[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        let mut entropy = DeterministicTestEntropy::new(entropy_bytes);
        let action = ActionPrivateRandomness::try_new(test_binding(), &mut entropy)
            .expect("deterministic test entropy supplies the action root");
        (action, entropy)
    }

    fn ordered_test_streams() -> Vec<PrivateRandomStreamContext> {
        let mut streams = vec![
            PrivateRandomStreamContext::new(
                PrivateRandomDomain::target_flooding(TargetFloodingRole::Order),
                Hash512::from_bytes([0x43; 64]),
            ),
            PrivateRandomStreamContext::new(
                PrivateRandomDomain::suite_sampling(
                    SuiteSamplingPurpose::BallotEncryptionErrorZero,
                ),
                Hash512::from_bytes([0x42; 64]),
            ),
            PrivateRandomStreamContext::new(
                PrivateRandomDomain::suite_sampling(
                    SuiteSamplingPurpose::BallotEncryptionEphemeralSecret,
                ),
                Hash512::from_bytes([0x41; 64]),
            ),
        ];
        streams.sort_unstable();
        streams
    }

    fn populated_resume_snapshot() -> (
        PrivateRandomnessResumeSnapshot,
        Vec<PrivateRandomStreamContext>,
        Vec<RandomCursor>,
    ) {
        let live_streams = ordered_test_streams();
        let (mut action, mut entropy) = deterministic_action_and_attempt();
        let mut attempt = action
            .try_start_attempt(&mut entropy)
            .expect("test attempt identifier is available");
        let mut consumed_prefix = [0u8; 5];
        attempt
            .try_fill_bytes(
                PrivateRandomDomain::suite_sampling(
                    SuiteSamplingPurpose::BallotEncryptionEphemeralSecret,
                ),
                Hash512::from_bytes([0x41; 64]),
                &mut consumed_prefix,
            )
            .expect("test stream prefix derives");
        let snapshot = attempt
            .try_create_resume_snapshot(&live_streams)
            .expect("the exact live stream set creates a snapshot");
        let random_cursors = snapshot
            .try_derive_random_cursors()
            .expect("snapshot derives assigned public cursors");
        (snapshot, live_streams, random_cursors)
    }

    #[test]
    fn kmac_and_action_randomness_hierarchy_match_known_answer_vectors() {
        let key: Vec<u8> = (0x40u8..=0x5f).collect();
        let expected = [
            0x20, 0xc5, 0x70, 0xc3, 0x13, 0x46, 0xf7, 0x03, 0xc9, 0xac, 0x36, 0xc6, 0x1c, 0x03,
            0xcb, 0x64, 0xc3, 0x97, 0x0d, 0x0c, 0xfc, 0x78, 0x7e, 0x9b, 0x79, 0x59, 0x9d, 0x27,
            0x3a, 0x68, 0xd2, 0xf7, 0xf6, 0x9d, 0x4c, 0xc3, 0xde, 0x9d, 0x10, 0x4a, 0x35, 0x16,
            0x89, 0xf2, 0x7c, 0xf6, 0xf5, 0x95, 0x1f, 0x01, 0x03, 0xf3, 0x3f, 0x4f, 0x24, 0x87,
            0x10, 0x24, 0xd9, 0xc2, 0x77, 0x73, 0xa8, 0xdd,
        ];
        let output = kmac256::<RANDOM_BLOCK_BYTE_LENGTH>(
            &key,
            &[0x00, 0x01, 0x02, 0x03],
            b"My Tagged Application",
        );
        assert_eq!(output.as_slice(), expected);

        let binding = test_binding();
        let input = ActionRandomnessDerivationInput::new(binding);
        let encoded = input.encode().expect("derivation input encodes");
        assert_eq!(
            encoded.len(),
            ACTION_RANDOMNESS_DERIVATION_INPUT_CANONICAL_BYTE_LENGTH
        );
        let decoded =
            ActionRandomnessDerivationInput::decode(&encoded, &CanonicalDecodeLimits::default())
                .expect("derivation input decodes");
        assert_eq!(decoded, input);

        let root = [0x51; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH];
        let hierarchy = derive_action_randomness_key_hierarchy(&binding, &root)
            .expect("action key hierarchy derives");
        let mut combined_key_material =
            Vec::with_capacity(ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH);
        combined_key_material
            .extend_from_slice(hierarchy.action_randomness_commitment_preimage.as_slice());
        combined_key_material.extend_from_slice(hierarchy.private_randomness_stream_key.as_slice());
        combined_key_material.extend_from_slice(hierarchy.proof_coin_key.as_slice());
        assert_eq!(
            lowercase_hexadecimal(&combined_key_material),
            "95fd3c9109de226d218b1a33d438e91f63fcbf8fa3fb53c42aa3593da68e547c2ab7479129b8a1f05a4797cbd35dddbbf52037b8d337ebddf934630fcb437fbaeb5dab1dc7a488b6d7f10f675ce3400dde2e048be6c713e28b2447356c0cdecc93b8b8522d19ade4c732f3d431bbcf36aad895045814d2eb086e96bc44981e85384ddb46cc8a18da84dea567c0c7506e0688c21376c517cc5293c892faae96b2dbb0bb8d22e326d7e52f474db44f286babb3746b69bc124f415889efc972cefd"
        );

        let commitment = derive_action_randomness_commitment(
            &binding,
            &hierarchy.action_randomness_commitment_preimage,
        )
        .expect("action randomness commitment derives");
        assert_eq!(
            commitment.to_lowercase_hex(),
            "b163168184b88a64715dceaf760c1308041a9c5bf0cab3dfe2effcf2752b2e1aab1e960e3626ad8a8d66a5d3a6f4b8f41ad2426cbb6fcfd2cb36bdc67c9c6acd"
        );

        let mut entropy = DeterministicTestEntropy::new(root);
        let action = ActionPrivateRandomness::try_new(binding, &mut entropy)
            .expect("the fixed root constructs the action hierarchy");
        assert_eq!(action.action_randomness_commitment(), commitment);
    }

    #[test]
    fn action_randomness_hierarchy_separates_domains_and_every_public_context_field() {
        let binding = test_binding();
        let root = [0x51; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH];
        let input_bytes = ActionRandomnessDerivationInput::new(binding)
            .encode()
            .expect("derivation input encodes");
        let randomness_material = kmac256::<ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH>(
            &root,
            &input_bytes,
            ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION,
        );
        let storage_domain_material = kmac256::<ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH>(
            &root,
            &input_bytes,
            b"sealed-lattice/local-storage/key-hierarchy/v1",
        );
        assert_ne!(
            randomness_material.as_slice(),
            storage_domain_material.as_slice()
        );

        let base_hierarchy = derive_action_randomness_key_hierarchy(&binding, &root)
            .expect("base hierarchy derives");
        let changed_bindings = [
            PrivateRandomnessActionBinding::new(
                Hash512::from_bytes([0x12; 64]),
                binding.ceremony_context_hash(),
                binding.action_context_hash(),
                binding.participant_identity(),
            ),
            PrivateRandomnessActionBinding::new(
                binding.suite_id(),
                Hash512::from_bytes([0x23; 64]),
                binding.action_context_hash(),
                binding.participant_identity(),
            ),
            PrivateRandomnessActionBinding::new(
                binding.suite_id(),
                binding.ceremony_context_hash(),
                Hash512::from_bytes([0x34; 64]),
                binding.participant_identity(),
            ),
            PrivateRandomnessActionBinding::new(
                binding.suite_id(),
                binding.ceremony_context_hash(),
                binding.action_context_hash(),
                ParticipantIdentity::from_bytes([0x45; 64]),
            ),
        ];
        for changed_binding in changed_bindings {
            let changed_hierarchy = derive_action_randomness_key_hierarchy(&changed_binding, &root)
                .expect("changed-context hierarchy derives");
            assert_ne!(
                base_hierarchy
                    .action_randomness_commitment_preimage
                    .as_slice(),
                changed_hierarchy
                    .action_randomness_commitment_preimage
                    .as_slice(),
            );
            assert_ne!(
                base_hierarchy.private_randomness_stream_key.as_slice(),
                changed_hierarchy.private_randomness_stream_key.as_slice(),
            );
            assert_ne!(
                base_hierarchy.proof_coin_key.as_slice(),
                changed_hierarchy.proof_coin_key.as_slice(),
            );
        }
    }

    #[test]
    fn every_bound_field_and_counter_domain_separates_random_blocks() {
        let binding = test_binding();
        let root = [0x71; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH];
        let private_randomness_stream_key = test_stream_key(&binding, &root);
        let attempt_identifier = [0x72; ATTEMPT_IDENTIFIER_BYTE_LENGTH];
        let base_stream_key = PrivateRandomStreamKey::new(
            PrivateRandomDomain::suite_sampling(SuiteSamplingPurpose::SecretContribution),
            Hash512::from_bytes([0x73; 64]),
        );
        let base = derive_private_random_block(
            &binding,
            &private_randomness_stream_key,
            &attempt_identifier,
            base_stream_key,
            0,
        )
        .expect("base block derives");

        let changed_purpose = derive_private_random_block(
            &binding,
            &private_randomness_stream_key,
            &attempt_identifier,
            PrivateRandomStreamKey::new(
                PrivateRandomDomain::suite_sampling(SuiteSamplingPurpose::PublicKeyError),
                Hash512::from_bytes([0x73; 64]),
            ),
            0,
        )
        .expect("changed-purpose block derives");
        let changed_family = derive_private_random_block(
            &binding,
            &private_randomness_stream_key,
            &attempt_identifier,
            PrivateRandomStreamKey::new(
                PrivateRandomDomain::target_flooding(TargetFloodingRole::Identifier),
                Hash512::from_bytes([0x73; 64]),
            ),
            0,
        )
        .expect("changed-family block derives");
        let changed_context = derive_private_random_block(
            &binding,
            &private_randomness_stream_key,
            &attempt_identifier,
            PrivateRandomStreamKey::new(
                PrivateRandomDomain::suite_sampling(SuiteSamplingPurpose::SecretContribution),
                Hash512::from_bytes([0x74; 64]),
            ),
            0,
        )
        .expect("changed-context block derives");
        let changed_attempt = derive_private_random_block(
            &binding,
            &private_randomness_stream_key,
            &[0x75; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
            base_stream_key,
            0,
        )
        .expect("changed-attempt block derives");
        let changed_counter = derive_private_random_block(
            &binding,
            &private_randomness_stream_key,
            &attempt_identifier,
            base_stream_key,
            1,
        )
        .expect("changed-counter block derives");

        for changed in [
            changed_purpose,
            changed_family,
            changed_context,
            changed_attempt,
            changed_counter,
        ] {
            assert_ne!(base.as_slice(), changed.as_slice());
        }
    }

    #[test]
    fn one_domain_cursor_crosses_blocks_without_reusing_bytes() {
        let (mut action, mut entropy) = deterministic_action_and_attempt();
        let mut attempt = action
            .try_start_attempt(&mut entropy)
            .expect("test attempt identifier is available");
        let domain = PrivateRandomDomain::suite_sampling(
            SuiteSamplingPurpose::BallotEncryptionEphemeralSecret,
        );
        let derivation_context_hash = Hash512::from_bytes([0x81; 64]);
        let mut actual = [0u8; 67];
        attempt
            .try_fill_bytes(domain, derivation_context_hash, &mut actual[..63])
            .expect("first cursor prefix derives");
        attempt
            .try_fill_bytes(domain, derivation_context_hash, &mut actual[63..])
            .expect("the same cursor continues across the block boundary");

        let stream_key = PrivateRandomStreamKey::new(domain, derivation_context_hash);
        let private_randomness_stream_key =
            test_stream_key(&test_binding(), &[0x51; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]);
        let first_block = derive_private_random_block(
            &test_binding(),
            &private_randomness_stream_key,
            &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
            stream_key,
            0,
        )
        .expect("first expected block derives");
        let second_block = derive_private_random_block(
            &test_binding(),
            &private_randomness_stream_key,
            &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
            stream_key,
            1,
        )
        .expect("second expected block derives");
        let mut expected = [0u8; 67];
        expected[..64].copy_from_slice(first_block.as_slice());
        expected[64..].copy_from_slice(&second_block[..3]);

        assert_eq!(actual, expected);
        let cursor = attempt
            .streams
            .get(&stream_key)
            .expect("the semantic stream has one cursor");
        assert_eq!(cursor.next_counter, 2);
        assert_eq!(cursor.unread_block_offset, 3);
        assert_eq!(
            &cursor.unread_block[..3],
            &[0u8; 3],
            "consumed bytes are wiped from the live cursor"
        );
        assert_eq!(&cursor.unread_block[3..], &second_block[3..]);
    }

    #[test]
    fn rejection_sampling_is_unbiased_consumes_rejections_and_handles_full_u64() {
        let (mut action, mut entropy) = deterministic_action_and_attempt();
        let mut attempt = action
            .try_start_attempt(&mut entropy)
            .expect("test attempt identifier is available");
        let domain = PrivateRandomDomain::suite_sampling(SuiteSamplingPurpose::PublicKeyError);
        let derivation_context_hash = Hash512::from_bytes([0x91; 64]);
        let stream_key = PrivateRandomStreamKey::new(domain, derivation_context_hash);
        let mut scripted_block = [0u8; RANDOM_BLOCK_BYTE_LENGTH];
        scripted_block[..3].copy_from_slice(&[250, 251, 7]);
        attempt.streams.insert(
            stream_key,
            PrivateRandomStreamCursor {
                next_counter: 1,
                unread_block: Zeroizing::new(scripted_block),
                unread_block_offset: 0,
            },
        );

        assert_eq!(
            attempt
                .try_sample_uniform(domain, derivation_context_hash, 10, 3)
                .expect("the third candidate is below the acceptance limit"),
            7
        );
        assert_eq!(
            attempt
                .streams
                .get(&stream_key)
                .expect("scripted stream remains open")
                .unread_block_offset,
            3,
            "both rejected bytes and the accepted byte are permanently consumed"
        );

        let second_context = Hash512::from_bytes([0x92; 64]);
        let second_key = PrivateRandomStreamKey::new(domain, second_context);
        let mut second_block = [0u8; RANDOM_BLOCK_BYTE_LENGTH];
        second_block[..2].copy_from_slice(&[0x34, 0x12]);
        attempt.streams.insert(
            second_key,
            PrivateRandomStreamCursor {
                next_counter: 1,
                unread_block: Zeroizing::new(second_block),
                unread_block_offset: 0,
            },
        );
        assert_eq!(
            attempt
                .try_sample_uniform(domain, second_context, 257, 1)
                .expect("two-byte candidate samples modulo 257"),
            0x1234 % 257
        );
        assert_eq!(
            attempt
                .streams
                .get(&second_key)
                .expect("two-byte stream remains open")
                .unread_block_offset,
            2,
            "bitLength(257) requires exactly two bytes"
        );

        let (mut full_width_action, mut full_width_entropy) = deterministic_action_and_attempt();
        let mut full_width_attempt = full_width_action
            .try_start_attempt(&mut full_width_entropy)
            .expect("test attempt identifier is available");
        let full_width_domain = PrivateRandomDomain::target_flooding(TargetFloodingRole::Order);
        let full_width_context = Hash512::from_bytes([0xa1; 64]);
        let full_width_stream_key =
            PrivateRandomStreamKey::new(full_width_domain, full_width_context);
        let mut full_width_block = [0u8; RANDOM_BLOCK_BYTE_LENGTH];
        full_width_block[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        full_width_block[8..16].copy_from_slice(&5u64.to_le_bytes());
        full_width_attempt.streams.insert(
            full_width_stream_key,
            PrivateRandomStreamCursor {
                next_counter: 1,
                unread_block: Zeroizing::new(full_width_block),
                unread_block_offset: 0,
            },
        );

        assert_eq!(
            full_width_attempt
                .try_sample_uniform(full_width_domain, full_width_context, u64::MAX, 2)
                .expect("the rejected maximum is followed by an accepted candidate"),
            5
        );
        assert_eq!(
            full_width_attempt
                .streams
                .get(&full_width_stream_key)
                .expect("full-width stream remains open")
                .unread_block_offset,
            16
        );
    }

    #[test]
    fn sampling_rejects_invalid_inputs_and_candidate_exhaustion_without_reuse() {
        let (mut action, mut entropy) = deterministic_action_and_attempt();
        let mut attempt = action
            .try_start_attempt(&mut entropy)
            .expect("test attempt identifier is available");
        let domain = PrivateRandomDomain::target_flooding(TargetFloodingRole::Identifier);
        let context = Hash512::from_bytes([0xb1; 64]);

        for invalid_modulus in [0, 1] {
            assert_eq!(
                attempt.try_sample_uniform(domain, context, invalid_modulus, 1),
                Err(PrivateRandomnessError::InvalidModulus)
            );
        }
        assert_eq!(
            attempt.try_sample_uniform(domain, context, 2, 0),
            Err(PrivateRandomnessError::InvalidCandidateDrawLimit)
        );
        assert!(attempt.streams.is_empty());

        let (mut limited_action, mut limited_entropy) = deterministic_action_and_attempt();
        let mut limited_attempt = limited_action
            .try_start_attempt(&mut limited_entropy)
            .expect("test attempt identifier is available");
        let limited_domain =
            PrivateRandomDomain::suite_sampling(SuiteSamplingPurpose::PublicKeyError);
        let limited_context = Hash512::from_bytes([0xb2; 64]);
        let limited_stream_key = PrivateRandomStreamKey::new(limited_domain, limited_context);
        let mut scripted_block = [0u8; RANDOM_BLOCK_BYTE_LENGTH];
        scripted_block[..2].copy_from_slice(&[250, 251]);
        limited_attempt.streams.insert(
            limited_stream_key,
            PrivateRandomStreamCursor {
                next_counter: 1,
                unread_block: Zeroizing::new(scripted_block),
                unread_block_offset: 0,
            },
        );

        assert_eq!(
            limited_attempt.try_sample_uniform(limited_domain, limited_context, 10, 2),
            Err(PrivateRandomnessError::CandidateDrawLimitExhausted)
        );
        assert_eq!(
            limited_attempt
                .streams
                .get(&limited_stream_key)
                .expect("scripted stream remains open")
                .unread_block_offset,
            2,
            "every rejected candidate is permanently consumed"
        );
    }

    #[test]
    fn counter_exhaustion_preserves_output_and_allows_only_the_derived_suffix() {
        let mut cursor = PrivateRandomStreamCursor {
            next_counter: u64::MAX,
            unread_block: Zeroizing::new([0xc1; RANDOM_BLOCK_BYTE_LENGTH]),
            unread_block_offset: RANDOM_BLOCK_BYTE_LENGTH,
        };
        let stream_key = PrivateRandomStreamKey::new(
            PrivateRandomDomain::suite_sampling(SuiteSamplingPurpose::SecretContribution),
            Hash512::from_bytes([0xc2; 64]),
        );
        let mut destination = [0xff; 1];
        assert_eq!(
            cursor.try_fill_bytes(
                &test_binding(),
                &[0xc3; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
                &[0xc4; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                stream_key,
                &mut destination,
            ),
            Err(PrivateRandomnessError::CounterExhausted)
        );
        assert_eq!(destination, [0xff], "preflight leaves output untouched");
        assert_eq!(cursor.next_counter, u64::MAX);
        assert_eq!(cursor.unread_block_offset, RANDOM_BLOCK_BYTE_LENGTH);

        let mut block = [0u8; RANDOM_BLOCK_BYTE_LENGTH];
        block[RANDOM_BLOCK_BYTE_LENGTH - 1] = 0xd1;
        let mut suffix_cursor = PrivateRandomStreamCursor {
            next_counter: u64::MAX,
            unread_block: Zeroizing::new(block),
            unread_block_offset: RANDOM_BLOCK_BYTE_LENGTH - 1,
        };
        let stream_key = PrivateRandomStreamKey::new(
            PrivateRandomDomain::target_flooding(TargetFloodingRole::Identifier),
            Hash512::from_bytes([0xd2; 64]),
        );
        let mut last_byte = [0u8; 1];
        suffix_cursor
            .try_fill_bytes(
                &test_binding(),
                &[0xd3; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
                &[0xd4; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                stream_key,
                &mut last_byte,
            )
            .expect("the already-derived suffix does not advance the counter");
        assert_eq!(last_byte, [0xd1]);

        let mut beyond_suffix = [0u8; 1];
        assert_eq!(
            suffix_cursor.try_fill_bytes(
                &test_binding(),
                &[0xd3; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
                &[0xd4; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                stream_key,
                &mut beyond_suffix,
            ),
            Err(PrivateRandomnessError::CounterExhausted)
        );
    }

    #[test]
    fn entropy_failure_aborts_root_and_attempt_creation() {
        assert_eq!(
            ActionPrivateRandomness::try_new(test_binding(), &mut PartiallyFailingTestEntropy)
                .expect_err("partial entropy output must not create an action root"),
            PrivateRandomnessError::EntropyUnavailable
        );

        let mut root_entropy =
            DeterministicTestEntropy::new([0xe1; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]);
        let mut action = ActionPrivateRandomness::try_new(test_binding(), &mut root_entropy)
            .expect("complete root entropy succeeds");
        assert_eq!(
            action
                .try_start_attempt(&mut PartiallyFailingTestEntropy)
                .expect_err("partial attempt entropy must abort"),
            PrivateRandomnessError::EntropyUnavailable
        );
    }

    #[test]
    fn authenticated_resume_preserves_exact_next_bytes_across_block_boundaries() {
        let live_streams = ordered_test_streams();
        let ephemeral_secret_domain = PrivateRandomDomain::suite_sampling(
            SuiteSamplingPurpose::BallotEncryptionEphemeralSecret,
        );
        let error_domain =
            PrivateRandomDomain::suite_sampling(SuiteSamplingPurpose::BallotEncryptionErrorZero);
        let flooding_domain = PrivateRandomDomain::target_flooding(TargetFloodingRole::Order);
        let ephemeral_secret_context = Hash512::from_bytes([0x41; 64]);
        let error_context = Hash512::from_bytes([0x42; 64]);
        let flooding_context = Hash512::from_bytes([0x43; 64]);

        let (mut action, mut entropy) = deterministic_action_and_attempt();
        let mut attempt = action
            .try_start_attempt(&mut entropy)
            .expect("test attempt identifier is available");
        attempt
            .try_fill_bytes(
                ephemeral_secret_domain,
                ephemeral_secret_context,
                &mut [0u8; RANDOM_BLOCK_BYTE_LENGTH - 1],
            )
            .expect("first stream consumes all but one byte of its first block");
        attempt
            .try_fill_bytes(
                error_domain,
                error_context,
                &mut [0u8; RANDOM_BLOCK_BYTE_LENGTH],
            )
            .expect("second stream consumes exactly one complete block");

        let snapshot = attempt
            .try_create_resume_snapshot(&live_streams)
            .expect("the exact live stream set creates a snapshot");
        let random_cursors = snapshot
            .try_derive_random_cursors()
            .expect("snapshot derives assigned public cursors");
        assert_eq!(
            random_cursors
                .iter()
                .map(|cursor| cursor.next_counter)
                .collect::<Vec<_>>(),
            vec![1, 1, 0],
            "a public counter names the next block to generate while the secret snapshot retains any unread suffix"
        );
        assert_eq!(
            snapshot
                .streams
                .iter()
                .map(|stream| stream.unread_block_offset)
                .collect::<Vec<_>>(),
            vec![
                RANDOM_BLOCK_BYTE_LENGTH - 1,
                RANDOM_BLOCK_BYTE_LENGTH,
                RANDOM_BLOCK_BYTE_LENGTH
            ]
        );
        assert!(
            snapshot.streams[0].unread_block[..RANDOM_BLOCK_BYTE_LENGTH - 1]
                .iter()
                .all(|byte| *byte == 0),
            "consumed bytes are not retained in the snapshot"
        );
        assert!(
            snapshot.streams[1]
                .unread_block
                .iter()
                .all(|byte| *byte == 0),
            "a fully consumed block leaves no secret bytes in the snapshot"
        );

        let mut expected_ephemeral_secret_continuation = [0u8; 5];
        let mut expected_error_continuation = [0u8; 3];
        let mut expected_flooding_continuation = [0u8; 4];
        attempt
            .try_fill_bytes(
                ephemeral_secret_domain,
                ephemeral_secret_context,
                &mut expected_ephemeral_secret_continuation,
            )
            .expect("uninterrupted first stream crosses its block boundary");
        attempt
            .try_fill_bytes(
                error_domain,
                error_context,
                &mut expected_error_continuation,
            )
            .expect("uninterrupted second stream begins its next block");
        attempt
            .try_fill_bytes(
                flooding_domain,
                flooding_context,
                &mut expected_flooding_continuation,
            )
            .expect("uninterrupted third stream begins its first block");
        drop(attempt);
        drop(action);

        let mut restored_action = ActionPrivateRandomness::try_restore_from_snapshot(
            test_binding(),
            &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
            &live_streams,
            &random_cursors,
            snapshot,
        )
        .expect("the exact authenticated snapshot restores");
        let mut restored_attempt = restored_action
            .try_resume_attempt()
            .expect("the restored attempt is available exactly once");
        let mut actual_ephemeral_secret_continuation = [0u8; 5];
        let mut actual_error_continuation = [0u8; 3];
        let mut actual_flooding_continuation = [0u8; 4];
        restored_attempt
            .try_fill_bytes(
                ephemeral_secret_domain,
                ephemeral_secret_context,
                &mut actual_ephemeral_secret_continuation,
            )
            .expect("restored first stream crosses its block boundary");
        restored_attempt
            .try_fill_bytes(error_domain, error_context, &mut actual_error_continuation)
            .expect("restored second stream begins its next block");
        restored_attempt
            .try_fill_bytes(
                flooding_domain,
                flooding_context,
                &mut actual_flooding_continuation,
            )
            .expect("restored third stream begins its first block");

        assert_eq!(
            actual_ephemeral_secret_continuation,
            expected_ephemeral_secret_continuation
        );
        assert_eq!(actual_error_continuation, expected_error_continuation);
        assert_eq!(actual_flooding_continuation, expected_flooding_continuation);
    }

    #[test]
    fn snapshot_and_restore_require_exact_stream_action_and_attempt_bindings() {
        let live_streams = ordered_test_streams();
        let (mut action, mut entropy) = deterministic_action_and_attempt();
        let mut attempt = action
            .try_start_attempt(&mut entropy)
            .expect("test attempt identifier is available");
        attempt
            .try_fill_bytes(
                PrivateRandomDomain::suite_sampling(
                    SuiteSamplingPurpose::BallotEncryptionEphemeralSecret,
                ),
                Hash512::from_bytes([0x41; 64]),
                &mut [0u8; 1],
            )
            .expect("one declared stream becomes active");

        let mut disordered_streams = live_streams.clone();
        disordered_streams.swap(0, 1);
        assert_eq!(
            attempt
                .try_create_resume_snapshot(&disordered_streams)
                .expect_err("disordered live contexts must refuse"),
            PrivateRandomnessError::InvalidResumeStreamSet
        );
        let duplicate_streams = vec![live_streams[0], live_streams[0]];
        assert_eq!(
            attempt
                .try_create_resume_snapshot(&duplicate_streams)
                .expect_err("duplicate live contexts must refuse"),
            PrivateRandomnessError::InvalidResumeStreamSet
        );
        assert_eq!(
            attempt
                .try_create_resume_snapshot(&live_streams[1..])
                .expect_err("omitting an active stream must refuse"),
            PrivateRandomnessError::InvalidResumeStreamSet
        );

        let (snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        let wrong_binding = PrivateRandomnessActionBinding::new(
            Hash512::from_bytes([0x91; 64]),
            test_binding().ceremony_context_hash(),
            test_binding().action_context_hash(),
            test_binding().participant_identity(),
        );
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                wrong_binding,
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("a cross-action snapshot must refuse"),
            PrivateRandomnessError::ResumeBindingMismatch
        );

        let (snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x92; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("a cross-attempt snapshot must refuse"),
            PrivateRandomnessError::ResumeAttemptMismatch
        );

        let (snapshot, mut live_streams, random_cursors) = populated_resume_snapshot();
        live_streams[0] = PrivateRandomStreamContext::new(
            PrivateRandomDomain::suite_sampling(
                SuiteSamplingPurpose::BallotEncryptionEphemeralSecret,
            ),
            Hash512::from_bytes([0x99; 64]),
        );
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("a substituted derived context must refuse"),
            PrivateRandomnessError::InvalidResumeStreamSet
        );
    }

    #[test]
    fn restore_rejects_tampered_public_cursors_and_secret_stream_state() {
        let (snapshot, live_streams, mut random_cursors) = populated_resume_snapshot();
        random_cursors.pop();
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("a missing public cursor must refuse"),
            PrivateRandomnessError::InvalidResumeCursorSet
        );

        let (snapshot, live_streams, mut random_cursors) = populated_resume_snapshot();
        random_cursors[1] = random_cursors[0];
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("duplicate public cursors must refuse"),
            PrivateRandomnessError::InvalidResumeCursorSet
        );

        let (snapshot, live_streams, mut random_cursors) = populated_resume_snapshot();
        random_cursors.swap(0, 1);
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("reordered public cursors must refuse"),
            PrivateRandomnessError::InvalidResumeCursorSet
        );

        for wrong_counter in [0, 2] {
            let (snapshot, live_streams, mut random_cursors) = populated_resume_snapshot();
            random_cursors[0].next_counter = wrong_counter;
            assert_eq!(
                ActionPrivateRandomness::try_restore_from_snapshot(
                    test_binding(),
                    &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                    &live_streams,
                    &random_cursors,
                    snapshot,
                )
                .expect_err("a rewound or advanced public cursor must refuse"),
                PrivateRandomnessError::InvalidResumeCursorSet
            );
        }

        let (snapshot, live_streams, mut random_cursors) = populated_resume_snapshot();
        random_cursors[0].derivation_context_hash = Hash512::from_bytes([0xa4; 64]);
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("a wrong public cursor context must refuse"),
            PrivateRandomnessError::InvalidResumeCursorSet
        );

        let (snapshot, live_streams, mut random_cursors) = populated_resume_snapshot();
        random_cursors[0].family = 0;
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("an unassigned public cursor domain must refuse"),
            PrivateRandomnessError::InvalidResumeCursorSet
        );

        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        snapshot.streams[0].unread_block_offset = RANDOM_BLOCK_BYTE_LENGTH + 1;
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("an out-of-range unread offset must refuse"),
            PrivateRandomnessError::InvalidResumeSecretState
        );

        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        snapshot.streams[0].next_counter = 0;
        let mut matching_cursors = random_cursors;
        matching_cursors[0].next_counter = 0;
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &matching_cursors,
                snapshot,
            )
            .expect_err("an unread suffix without a generated block must refuse"),
            PrivateRandomnessError::InvalidResumeSecretState
        );

        let (mut snapshot, live_streams, mut random_cursors) = populated_resume_snapshot();
        snapshot.streams[0].next_counter = 2;
        random_cursors[0].next_counter = 2;
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("a secret counter advanced over unchanged suffix bytes must refuse"),
            PrivateRandomnessError::InvalidResumeSecretState
        );

        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        let unread_offset = snapshot.streams[0].unread_block_offset;
        snapshot.streams[0].unread_block[unread_offset] ^= 1;
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("a changed unread suffix byte must refuse"),
            PrivateRandomnessError::InvalidResumeSecretState
        );

        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        snapshot.streams[0].unread_block[0] = 1;
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("retained consumed bytes must refuse"),
            PrivateRandomnessError::InvalidResumeSecretState
        );

        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        snapshot.streams[1].unread_block[0] = 1;
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("an unused stream cannot carry unread bytes"),
            PrivateRandomnessError::InvalidResumeSecretState
        );
    }

    #[test]
    fn restore_rejects_duplicate_reordered_streams_and_attempt_history() {
        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        snapshot.streams.swap(0, 1);
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("reordered secret streams must refuse"),
            PrivateRandomnessError::InvalidResumeStreamSet
        );

        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        snapshot.streams[1].stream_key = snapshot.streams[0].stream_key;
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("duplicate secret streams must refuse"),
            PrivateRandomnessError::InvalidResumeStreamSet
        );

        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        snapshot.used_attempt_identifiers.clear();
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("missing current attempt history must refuse"),
            PrivateRandomnessError::InvalidResumeSecretState
        );

        let (mut snapshot, live_streams, random_cursors) = populated_resume_snapshot();
        snapshot
            .used_attempt_identifiers
            .push(zeroizing_copy(&snapshot.attempt_identifier));
        assert_eq!(
            ActionPrivateRandomness::try_restore_from_snapshot(
                test_binding(),
                &[0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                &live_streams,
                &random_cursors,
                snapshot,
            )
            .expect_err("duplicate attempt history must refuse"),
            PrivateRandomnessError::InvalidResumeSecretState
        );
    }

    #[test]
    fn restored_attempt_is_single_use_and_preserves_prior_attempt_reuse_detection() {
        let first_attempt_identifier = [0x61; ATTEMPT_IDENTIFIER_BYTE_LENGTH];
        let resumed_attempt_identifier = [0x62; ATTEMPT_IDENTIFIER_BYTE_LENGTH];
        let mut entropy_bytes = Vec::new();
        entropy_bytes.extend_from_slice(&[0x51; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]);
        entropy_bytes.extend_from_slice(&first_attempt_identifier);
        entropy_bytes.extend_from_slice(&resumed_attempt_identifier);
        let mut entropy = DeterministicTestEntropy::new(entropy_bytes);
        let mut action = ActionPrivateRandomness::try_new(test_binding(), &mut entropy)
            .expect("action root entropy succeeds");
        drop(
            action
                .try_start_attempt(&mut entropy)
                .expect("first attempt identifier is fresh"),
        );
        let second_attempt = action
            .try_start_attempt(&mut entropy)
            .expect("second attempt identifier is fresh");
        let snapshot = second_attempt
            .try_create_resume_snapshot(&[])
            .expect("an empty exact stream set can be resumed");
        let random_cursors = snapshot
            .try_derive_random_cursors()
            .expect("the empty stream set has no public cursors");
        drop(second_attempt);
        drop(action);

        let mut restored_action = ActionPrivateRandomness::try_restore_from_snapshot(
            test_binding(),
            &resumed_attempt_identifier,
            &[],
            &random_cursors,
            snapshot,
        )
        .expect("the second attempt restores");
        assert_eq!(
            restored_action
                .try_start_attempt(&mut PartiallyFailingTestEntropy)
                .expect_err("a pending resume cannot be bypassed with a new attempt"),
            PrivateRandomnessError::PendingResumeAttempt
        );
        let resumed_attempt = restored_action
            .try_resume_attempt()
            .expect("the pending attempt resumes once");
        assert_eq!(
            resumed_attempt.attempt_identifier(),
            &resumed_attempt_identifier
        );
        drop(resumed_attempt);
        assert_eq!(
            restored_action
                .try_resume_attempt()
                .expect_err("the restored attempt cannot be resumed twice"),
            PrivateRandomnessError::MissingResumeAttempt
        );

        let mut repeated_entropy = DeterministicTestEntropy::new(first_attempt_identifier);
        assert_eq!(
            restored_action
                .try_start_attempt(&mut repeated_entropy)
                .expect_err("restoration preserves every prior used attempt identifier"),
            PrivateRandomnessError::RepeatedAttemptIdentifier
        );
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let (snapshot, _, _) = populated_resume_snapshot();
        let debug_output = format!("{snapshot:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("81, 81"));
        assert!(!debug_output.contains("98, 98"));
        assert!(!debug_output.contains("unread_block"));

        let mut entropy = DeterministicTestEntropy::new([0xab; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]);
        let action = ActionPrivateRandomness::try_new(test_binding(), &mut entropy)
            .expect("deterministic test root is available");
        let debug_output = format!("{action:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("171, 171"));
    }
}
