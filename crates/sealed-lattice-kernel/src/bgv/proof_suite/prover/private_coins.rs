use std::{
    fmt,
    rc::{Rc, Weak},
};

use crate::{
    foundation::{
        ActionPrivateRandomness, FoundationSchemaError, Hash512, PRIVATE_PROOF_SALT_PURPOSE,
        PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
        PrivateRandomnessKmacInputClassAccounting, ProofApplicationSlotCeilings,
        private_randomness_stream_block_count_for_byte_length,
        private_randomness_stream_block_count_for_modulo_outputs,
        proof_attempt_identifier_derivation_count,
    },
    hashing::{StreamingHash512, hash_framed_parts_512},
};

use super::super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    relation_plan::{
        ProofPrivacyMode, RelationColumnValueType, RelationMaskCoordinate, RelationMaskKind,
        RelationMaskTargetClass, RelationPlanVariant,
    },
};

const COMMON_PROOF_PRIVATE_COIN_COORDINATE_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/private-coin-coordinate/v1";
const COMMON_PROOF_PRIVATE_COIN_REPLAY_CATALOG_DOMAIN: &str =
    "sealed-lattice/common-proof/private-coin-replay-catalog/v1";
const COMMON_PROOF_PRIVATE_COIN_REPLAY_SPAN_DOMAIN: &str =
    "sealed-lattice/common-proof/private-coin-replay-span/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofPrivateRandomnessAccountingError {
    CountOverflow,
    InvalidPlan,
    UnassignedProofFamily,
}

/// Source-owned count of the distinct proof-private KMAC inputs consumed by
/// one physical proof application. Persistent material construction is owned
/// by the committed-material catalog and is deliberately excluded here.
pub(crate) fn common_proof_private_randomness_kmac_input_accounting(
    application_statement_schema_identifier: u16,
    variant: &RelationPlanVariant,
    proof_local_full_salted_leaf_count: u64,
) -> Result<PrivateRandomnessKmacInputClassAccounting, CommonProofPrivateRandomnessAccountingError>
{
    let attempt_identifier_derivation_count =
        proof_attempt_identifier_derivation_count(application_statement_schema_identifier)
            .ok_or(CommonProofPrivateRandomnessAccountingError::UnassignedProofFamily)?;
    let extension_coordinate_count = u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
        .map_err(|_| CommonProofPrivateRandomnessAccountingError::CountOverflow)?;
    let mut mask_stream_block_count = 0_u64;
    for mask in variant.ordered_masks() {
        let coordinate_count = match (mask.mask_kind(), mask.target_class()) {
            (RelationMaskKind::Trace, RelationMaskTargetClass::Column) => {
                let column =
                    variant
                        .ordered_columns()
                        .get(usize::try_from(mask.target_ordinal()).map_err(|_| {
                            CommonProofPrivateRandomnessAccountingError::CountOverflow
                        })?)
                        .ok_or(CommonProofPrivateRandomnessAccountingError::InvalidPlan)?;
                match column.value_type() {
                    RelationColumnValueType::BaseField => 1,
                    RelationColumnValueType::ChallengeExtension => extension_coordinate_count,
                }
            }
            (RelationMaskKind::Telescoping, RelationMaskTargetClass::QuotientComponent)
            | (RelationMaskKind::OpeningBatch, RelationMaskTargetClass::Batch) => {
                extension_coordinate_count
            }
            _ => return Err(CommonProofPrivateRandomnessAccountingError::InvalidPlan),
        };
        let sampled_coordinate_count = mask
            .mask_degree_bound_exclusive()
            .checked_mul(coordinate_count)
            .ok_or(CommonProofPrivateRandomnessAccountingError::CountOverflow)?;
        let block_count = private_randomness_stream_block_count_for_modulo_outputs(
            sampled_coordinate_count,
            PROOF_BASE_FIELD_MODULUS,
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        )
        .ok_or(CommonProofPrivateRandomnessAccountingError::CountOverflow)?;
        mask_stream_block_count = mask_stream_block_count
            .checked_add(block_count)
            .ok_or(CommonProofPrivateRandomnessAccountingError::CountOverflow)?;
    }
    let proof_salt_stream_block_count = private_randomness_stream_block_count_for_byte_length(
        proof_local_full_salted_leaf_count
            .checked_mul(
                u64::try_from(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)
                    .map_err(|_| CommonProofPrivateRandomnessAccountingError::CountOverflow)?,
            )
            .ok_or(CommonProofPrivateRandomnessAccountingError::CountOverflow)?,
    )
    .ok_or(CommonProofPrivateRandomnessAccountingError::CountOverflow)?;
    if (variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing)
        != (proof_local_full_salted_leaf_count != 0)
    {
        return Err(CommonProofPrivateRandomnessAccountingError::InvalidPlan);
    }
    PrivateRandomnessKmacInputClassAccounting::checked_new(
        0,
        attempt_identifier_derivation_count,
        mask_stream_block_count
            .checked_add(proof_salt_stream_block_count)
            .ok_or(CommonProofPrivateRandomnessAccountingError::CountOverflow)?,
        0,
    )
    .ok_or(CommonProofPrivateRandomnessAccountingError::CountOverflow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofPrivateCoinCoordinate {
    purpose_class: u16,
    ordinal: u32,
}

impl CommonProofPrivateCoinCoordinate {
    pub(crate) const fn mask(purpose_class: u16, ordinal: u32) -> Option<Self> {
        if purpose_class >= 1 && purpose_class <= 3 {
            Some(Self {
                purpose_class,
                ordinal,
            })
        } else {
            None
        }
    }

    pub(crate) const fn from_mask(mask: RelationMaskCoordinate) -> Self {
        Self {
            purpose_class: mask.purpose_class(),
            ordinal: mask.mask_ordinal(),
        }
    }

    pub(crate) const fn proof_salt() -> Self {
        Self {
            purpose_class: PRIVATE_PROOF_SALT_PURPOSE,
            ordinal: 0,
        }
    }

    pub(crate) const fn purpose_class(self) -> u16 {
        self.purpose_class
    }

    pub(crate) const fn ordinal(self) -> u32 {
        self.ordinal
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofPrivateCoinCoordinateCapacity {
    trace_mask_count: u32,
    telescoping_mask_count: u32,
    opening_mask_count: u32,
    includes_proof_salt: bool,
}

impl CommonProofPrivateCoinCoordinateCapacity {
    pub(crate) fn from_relation_plan_variant(
        variant: &RelationPlanVariant,
    ) -> Result<Self, CommonProofCheckpointCursorManifestError> {
        let mut counts = [0_u32; 3];
        for mask in variant.ordered_masks() {
            let coordinate = mask.mask_coordinate();
            let class_index = usize::from(coordinate.purpose_class() - 1);
            if class_index >= counts.len() || coordinate.mask_ordinal() != counts[class_index] {
                return Err(CommonProofCheckpointCursorManifestError::CoordinateOrder);
            }
            counts[class_index] = counts[class_index]
                .checked_add(1)
                .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
        }
        let includes_proof_salt = variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing;
        Ok(Self {
            trace_mask_count: counts[RelationMaskKind::Trace as usize - 1],
            telescoping_mask_count: counts[RelationMaskKind::Telescoping as usize - 1],
            opening_mask_count: counts[RelationMaskKind::OpeningBatch as usize - 1],
            includes_proof_salt,
        })
    }

    #[cfg(test)]
    pub(crate) const fn for_test(
        trace_mask_count: u32,
        telescoping_mask_count: u32,
        opening_mask_count: u32,
        includes_proof_salt: bool,
    ) -> Self {
        Self {
            trace_mask_count,
            telescoping_mask_count,
            opening_mask_count,
            includes_proof_salt,
        }
    }

    pub(crate) fn logical_cursor_count(self) -> Option<u32> {
        self.trace_mask_count
            .checked_add(self.telescoping_mask_count)
            .and_then(|count| count.checked_add(self.opening_mask_count))
            .and_then(|count| count.checked_add(self.includes_proof_salt as u32))
    }

    pub(crate) const fn consecutive_coordinate_run_count(self) -> u32 {
        (self.trace_mask_count != 0) as u32
            + (self.telescoping_mask_count != 0) as u32
            + (self.opening_mask_count != 0) as u32
            + self.includes_proof_salt as u32
    }
}

/// Private proof coins are supplied by Rust private-randomness custody.  Each
/// coordinate is an independent stream beginning at counter zero; implementations
/// must delegate to `PrivateRandomnessStream::sample_modulo` and
/// `PrivateRandomnessStream::fill_bytes`, not to a transcript or host PRNG.
pub(crate) trait CommonProofPrivateCoinSource {
    type Error;

    fn sample_modulo(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error>;

    fn fill_raw_bytes(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        destination: &mut [u8],
    ) -> Result<(), Self::Error>;
}

/// In-memory capability for replaying the proof-salt stream within one proof
/// attempt. The cursor already binds the family, statement derivation context,
/// and attempt identifier. The weak instance binding additionally makes a
/// token stale as soon as its exact source is reset or dropped. Tokens are
/// never serialized and contain no private coin bytes.
#[derive(Clone)]
pub(crate) struct CommonProofPrivateCoinReplayCursor {
    source_instance_binding: Weak<()>,
    cursor: PrivateRandomCursor,
}

impl fmt::Debug for CommonProofPrivateCoinReplayCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommonProofPrivateCoinReplayCursor")
            .field("source_instance", &"[REDACTED]")
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl CommonProofPrivateCoinReplayCursor {
    pub(crate) fn new(source_instance_binding: &Rc<()>, cursor: PrivateRandomCursor) -> Self {
        Self {
            source_instance_binding: Rc::downgrade(source_instance_binding),
            cursor,
        }
    }

    pub(crate) fn belongs_to(&self, source_instance_binding: &Rc<()>) -> bool {
        self.source_instance_binding
            .upgrade()
            .is_some_and(|observed| Rc::ptr_eq(&observed, source_instance_binding))
    }

    pub(crate) const fn cursor(&self) -> PrivateRandomCursor {
        self.cursor
    }
}

/// A replayable source can rewind only its proof-salt coordinate and only by
/// presenting a capability captured from that exact live source instance.
/// The caller must compare the terminal cursor after consuming the complete
/// tree span; a partial replay is not an acceptable terminal state.
pub(crate) trait ReplayableCommonProofPrivateCoinSource:
    CommonProofPrivateCoinSource
{
    fn capture_proof_salt_replay_cursor(
        &self,
    ) -> Result<CommonProofPrivateCoinReplayCursor, Self::Error>;

    fn restore_proof_salt_replay_cursor(
        &mut self,
        cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<(), Self::Error>;

    fn proof_salt_replay_cursor_matches(
        &self,
        cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<bool, Self::Error>;
}

#[derive(Clone)]
struct CommonProofPrivateCoinReplaySpanIdentity {
    source_instance_binding: Weak<()>,
    family_schema_identifier: u16,
    derivation_binding_hash: Hash512,
    attempt_identifier: [u8; 32],
    reset_epoch: u64,
    span_identifier: u64,
}

impl fmt::Debug for CommonProofPrivateCoinReplaySpanIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommonProofPrivateCoinReplaySpanIdentity")
            .field("source_instance", &"[REDACTED]")
            .field("family_schema_identifier", &self.family_schema_identifier)
            .field("derivation_binding_hash", &self.derivation_binding_hash)
            .field("attempt_identifier", &"[REDACTED]")
            .field("reset_epoch", &self.reset_epoch)
            .field("span_identifier", &self.span_identifier)
            .finish()
    }
}

impl CommonProofPrivateCoinReplaySpanIdentity {
    fn new(
        source_instance_binding: &Rc<()>,
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_identifier: [u8; 32],
        reset_epoch: u64,
        span_identifier: u64,
    ) -> Self {
        Self {
            source_instance_binding: Rc::downgrade(source_instance_binding),
            family_schema_identifier,
            derivation_binding_hash,
            attempt_identifier,
            reset_epoch,
            span_identifier,
        }
    }

    fn belongs_to(
        &self,
        source_instance_binding: &Rc<()>,
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_identifier: [u8; 32],
        reset_epoch: u64,
    ) -> bool {
        self.source_instance_binding
            .upgrade()
            .is_some_and(|observed| Rc::ptr_eq(&observed, source_instance_binding))
            && self.family_schema_identifier == family_schema_identifier
            && self.derivation_binding_hash == derivation_binding_hash
            && self.attempt_identifier == attempt_identifier
            && self.reset_epoch == reset_epoch
    }
}

fn common_proof_private_coin_cursor_catalog_digest(
    identity: &CommonProofPrivateCoinReplaySpanIdentity,
    cursors: &[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)],
) -> Result<[u8; 64], CommonProofPrivateCoinReplayTokenError> {
    let cursor_part_count = u64::try_from(cursors.len())
        .map_err(|_| CommonProofPrivateCoinReplayTokenError::AllocationLimitExceeded)?
        .checked_mul(2)
        .and_then(|count| count.checked_add(6))
        .ok_or(CommonProofPrivateCoinReplayTokenError::AllocationLimitExceeded)?;
    let mut hasher = StreamingHash512::new(
        COMMON_PROOF_PRIVATE_COIN_REPLAY_CATALOG_DOMAIN,
        cursor_part_count,
    );
    hasher.absorb_part(&identity.family_schema_identifier.to_le_bytes());
    hasher.absorb_part(&identity.derivation_binding_hash.into_bytes());
    hasher.absorb_part(&identity.attempt_identifier);
    hasher.absorb_part(&identity.reset_epoch.to_le_bytes());
    hasher.absorb_part(&identity.span_identifier.to_le_bytes());
    hasher.absorb_part(
        &u64::try_from(cursors.len())
            .map_err(|_| CommonProofPrivateCoinReplayTokenError::AllocationLimitExceeded)?
            .to_le_bytes(),
    );
    for (coordinate, cursor) in cursors {
        let mut coordinate_bytes = [0_u8; 6];
        coordinate_bytes[..2].copy_from_slice(&coordinate.purpose_class().to_le_bytes());
        coordinate_bytes[2..].copy_from_slice(&coordinate.ordinal().to_le_bytes());
        hasher.absorb_part(&coordinate_bytes);
        hasher.absorb_part(
            &cursor
                .encode()
                .map_err(CommonProofPrivateCoinReplayTokenError::CanonicalEncoding)?,
        );
    }
    Ok(hasher.finalize())
}

#[derive(Debug)]
pub(crate) enum CommonProofPrivateCoinReplayTokenError {
    AllocationLimitExceeded,
    CanonicalEncoding(FoundationSchemaError),
}

/// Single-use start capability for capturing one exact all-coordinate replay
/// span. It is source-instance bound and never serialized.
pub(crate) struct CommonProofPrivateCoinReplaySpanStart {
    identity: CommonProofPrivateCoinReplaySpanIdentity,
    start_cursors: Box<[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)]>,
    start_catalog_digest: [u8; 64],
}

impl fmt::Debug for CommonProofPrivateCoinReplaySpanStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommonProofPrivateCoinReplaySpanStart")
            .field("identity", &self.identity)
            .field("cursor_count", &self.start_cursors.len())
            .field("start_catalog_digest", &self.start_catalog_digest)
            .finish()
    }
}

impl CommonProofPrivateCoinReplaySpanStart {
    pub(crate) fn new(
        source_instance_binding: &Rc<()>,
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_identifier: [u8; 32],
        reset_epoch: u64,
        span_identifier: u64,
        start_cursors: Box<[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)]>,
    ) -> Result<Self, CommonProofPrivateCoinReplayTokenError> {
        let identity = CommonProofPrivateCoinReplaySpanIdentity::new(
            source_instance_binding,
            family_schema_identifier,
            derivation_binding_hash,
            attempt_identifier,
            reset_epoch,
            span_identifier,
        );
        let start_catalog_digest =
            common_proof_private_coin_cursor_catalog_digest(&identity, &start_cursors)?;
        Ok(Self {
            identity,
            start_cursors,
            start_catalog_digest,
        })
    }

    pub(crate) fn belongs_to(
        &self,
        source_instance_binding: &Rc<()>,
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_identifier: [u8; 32],
        reset_epoch: u64,
    ) -> bool {
        self.identity.belongs_to(
            source_instance_binding,
            family_schema_identifier,
            derivation_binding_hash,
            attempt_identifier,
            reset_epoch,
        )
    }

    pub(crate) const fn span_identifier(&self) -> u64 {
        self.identity.span_identifier
    }
}

/// Completed exact all-coordinate replay span. It holds only independent
/// private-randomness cursor states and their binding digests, never sampled
/// bytes, polynomial coefficients, field elements, or leaf salts.
#[derive(Clone)]
pub(crate) struct CommonProofPrivateCoinReplaySpan {
    identity: CommonProofPrivateCoinReplaySpanIdentity,
    start_cursors: Box<[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)]>,
    end_cursors: Box<[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)]>,
    start_catalog_digest: [u8; 64],
    end_catalog_digest: [u8; 64],
    binding_hash: [u8; 64],
}

impl fmt::Debug for CommonProofPrivateCoinReplaySpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommonProofPrivateCoinReplaySpan")
            .field("identity", &self.identity)
            .field("start_cursor_count", &self.start_cursors.len())
            .field("end_cursor_count", &self.end_cursors.len())
            .field("start_catalog_digest", &self.start_catalog_digest)
            .field("end_catalog_digest", &self.end_catalog_digest)
            .field("binding_hash", &self.binding_hash)
            .finish()
    }
}

impl CommonProofPrivateCoinReplaySpan {
    pub(crate) fn from_completed_capture(
        start: CommonProofPrivateCoinReplaySpanStart,
        end_cursors: Box<[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)]>,
    ) -> Result<Self, CommonProofPrivateCoinReplayTokenError> {
        let end_catalog_digest =
            common_proof_private_coin_cursor_catalog_digest(&start.identity, &end_cursors)?;
        let binding_hash = hash_framed_parts_512(
            COMMON_PROOF_PRIVATE_COIN_REPLAY_SPAN_DOMAIN,
            &[
                &start.identity.family_schema_identifier.to_le_bytes(),
                &start.identity.derivation_binding_hash.into_bytes(),
                &start.identity.attempt_identifier,
                &start.identity.reset_epoch.to_le_bytes(),
                &start.identity.span_identifier.to_le_bytes(),
                &start.start_catalog_digest,
                &end_catalog_digest,
            ],
        );
        Ok(Self {
            identity: start.identity,
            start_cursors: start.start_cursors,
            end_cursors,
            start_catalog_digest: start.start_catalog_digest,
            end_catalog_digest,
            binding_hash,
        })
    }

    pub(crate) fn belongs_to(
        &self,
        source_instance_binding: &Rc<()>,
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_identifier: [u8; 32],
        reset_epoch: u64,
    ) -> bool {
        self.identity.belongs_to(
            source_instance_binding,
            family_schema_identifier,
            derivation_binding_hash,
            attempt_identifier,
            reset_epoch,
        )
    }

    pub(crate) const fn span_identifier(&self) -> u64 {
        self.identity.span_identifier
    }

    pub(crate) const fn binding_hash(&self) -> [u8; 64] {
        self.binding_hash
    }

    pub(crate) fn start_cursors(
        &self,
    ) -> &[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)] {
        &self.start_cursors
    }

    pub(crate) fn end_cursors(&self) -> &[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)] {
        &self.end_cursors
    }
}

/// Reset-safe in-memory replay lifecycle for every private-coin coordinate
/// consumed by one live proof attempt.
pub(crate) trait ReplayableCommonProofPrivateCoinCatalogSource:
    CommonProofPrivateCoinSource
{
    fn begin_all_coordinate_replay_span(
        &mut self,
    ) -> Result<CommonProofPrivateCoinReplaySpanStart, Self::Error>;

    fn finish_all_coordinate_replay_span(
        &mut self,
        start: CommonProofPrivateCoinReplaySpanStart,
    ) -> Result<CommonProofPrivateCoinReplaySpan, Self::Error>;

    fn restore_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error>;

    fn complete_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error>;

    fn invalidate_all_coordinate_replay_state(&mut self);
}

/// Private proof coins that can expose their exact authenticated stream
/// positions at a completed commitment boundary. The cursors contain no coin
/// bytes and are never used to initialize deterministic-prefix replay: replay
/// always starts each stream at counter zero and compares the resulting
/// cursors with the authenticated checkpoint manifest.
pub(crate) trait CheckpointableCommonProofPrivateCoinSource:
    CommonProofPrivateCoinSource
{
    fn checkpoint_cursor_manifest(
        &self,
    ) -> Result<Vec<u8>, CommonProofCheckpointCursorManifestError>;
}

const COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC: [u8; 8] = *b"SLCPCM03";
const COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_VERSION: u16 = 3;
const COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH: usize = 19;
const COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH: usize = 98;
const COMMON_PROOF_CHECKPOINT_CURSOR_RUN_BYTE_LENGTH: usize = 24;
const COMMON_PROOF_CHECKPOINT_CURSOR_OVERRIDE_BYTE_LENGTH: usize = 14;
pub(crate) const MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_RUN_COUNT: u32 = 4_096;
pub(crate) const MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH: u32 = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofCheckpointCursorManifestRequirement {
    logical_cursor_count: u32,
    consecutive_coordinate_run_count: u32,
    maximum_override_count: u32,
    canonical_manifest_byte_ceiling: u32,
    retained_cursor_state_byte_ceiling: u64,
    encoding_workspace_byte_ceiling: u32,
    pending_manifest_resident_byte_ceiling: u32,
    restore_workspace_byte_ceiling: u64,
    peak_additional_resident_byte_ceiling: u64,
    peak_copied_buffer_byte_length: u32,
}

impl CommonProofCheckpointCursorManifestRequirement {
    pub(crate) const fn logical_cursor_count(self) -> u32 {
        self.logical_cursor_count
    }

    pub(crate) const fn consecutive_coordinate_run_count(self) -> u32 {
        self.consecutive_coordinate_run_count
    }

    pub(crate) const fn maximum_override_count(self) -> u32 {
        self.maximum_override_count
    }

    pub(crate) const fn canonical_manifest_byte_ceiling(self) -> u32 {
        self.canonical_manifest_byte_ceiling
    }

    pub(crate) const fn retained_cursor_state_byte_ceiling(self) -> u64 {
        self.retained_cursor_state_byte_ceiling
    }

    pub(crate) const fn encoding_workspace_byte_ceiling(self) -> u32 {
        self.encoding_workspace_byte_ceiling
    }

    pub(crate) const fn pending_manifest_resident_byte_ceiling(self) -> u32 {
        self.pending_manifest_resident_byte_ceiling
    }

    pub(crate) const fn restore_workspace_byte_ceiling(self) -> u64 {
        self.restore_workspace_byte_ceiling
    }

    pub(crate) const fn peak_additional_resident_byte_ceiling(self) -> u64 {
        self.peak_additional_resident_byte_ceiling
    }

    pub(crate) const fn peak_copied_buffer_byte_length(self) -> u32 {
        self.peak_copied_buffer_byte_length
    }

    pub(crate) const fn fits_absolute_bounds(self) -> bool {
        self.consecutive_coordinate_run_count
            <= MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_RUN_COUNT
            && self.canonical_manifest_byte_ceiling
                <= MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH
            && self.peak_copied_buffer_byte_length
                <= MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofCheckpointCursorManifestError {
    AllocationLimitExceeded,
    CountOverflow,
    IdentityMismatch,
    NonCanonicalEncoding,
    OutsideSupportedProfile,
    CoordinateOrder,
}

#[derive(Clone, Copy)]
struct CommonProofCheckpointCursorRunSummary {
    first_coordinate: CommonProofPrivateCoinCoordinate,
    coordinate_count: u32,
    common_cursor: PrivateRandomCursor,
    override_count: u32,
}

/// Exact compact checkpoint representation for one common-proof coin source.
/// The source-wide family, derivation binding and attempt identifier occur
/// once, including before the first cursor is consumed. Every maximal
/// consecutive ordinal interval inside one purpose class forms one run. A
/// two-pass encoder counts exact state overrides before it writes directly
/// into the sole output allocation; it never constructs an expanded cursor
/// list or a nested run graph.
pub(crate) fn encode_common_proof_checkpoint_cursor_manifest<OrderedCursors>(
    family_schema_identifier: u16,
    derivation_binding_hash: Hash512,
    stream_attempt_identifier: [u8; 32],
    ordered_cursors: OrderedCursors,
) -> Result<Vec<u8>, CommonProofCheckpointCursorManifestError>
where
    OrderedCursors:
        Clone + IntoIterator<Item = (CommonProofPrivateCoinCoordinate, PrivateRandomCursor)>,
{
    let mut run_summaries = [None::<CommonProofCheckpointCursorRunSummary>; 4];
    let mut run_count = 0_usize;
    let mut logical_cursor_count = 0_u32;
    let mut override_count = 0_u32;
    let mut previous_coordinate = None;
    for (coordinate, cursor) in ordered_cursors.clone() {
        validate_manifest_cursor_identity(
            family_schema_identifier,
            derivation_binding_hash,
            stream_attempt_identifier,
            coordinate,
            cursor,
        )?;
        logical_cursor_count = logical_cursor_count
            .checked_add(1)
            .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
        if previous_coordinate.is_some_and(|previous| coordinate <= previous) {
            return Err(CommonProofCheckpointCursorManifestError::CoordinateOrder);
        }
        match run_count
            .checked_sub(1)
            .and_then(|index| run_summaries[index])
        {
            Some(mut run) if coordinate.purpose_class() == run.first_coordinate.purpose_class() => {
                let expected_ordinal = run
                    .first_coordinate
                    .ordinal()
                    .checked_add(run.coordinate_count)
                    .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
                if coordinate.ordinal() != expected_ordinal {
                    return Err(CommonProofCheckpointCursorManifestError::CoordinateOrder);
                }
                run.coordinate_count = run
                    .coordinate_count
                    .checked_add(1)
                    .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
                if !cursor_state_matches(run.common_cursor, cursor) {
                    run.override_count = run
                        .override_count
                        .checked_add(1)
                        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
                    override_count = override_count
                        .checked_add(1)
                        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
                }
                run_summaries[run_count - 1] = Some(run);
            }
            _ => {
                if coordinate.ordinal() != 0 || run_count == run_summaries.len() {
                    return Err(CommonProofCheckpointCursorManifestError::CoordinateOrder);
                }
                run_summaries[run_count] = Some(CommonProofCheckpointCursorRunSummary {
                    first_coordinate: coordinate,
                    coordinate_count: 1,
                    common_cursor: cursor,
                    override_count: 0,
                });
                run_count += 1;
            }
        }
        previous_coordinate = Some(coordinate);
    }
    let run_count = u32::try_from(run_count)
        .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?;
    if run_count > MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_RUN_COUNT {
        return Err(CommonProofCheckpointCursorManifestError::OutsideSupportedProfile);
    }
    let byte_length = COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
        .checked_add(COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH)
        .and_then(|length| {
            length.checked_add(
                usize::try_from(run_count)
                    .ok()?
                    .checked_mul(COMMON_PROOF_CHECKPOINT_CURSOR_RUN_BYTE_LENGTH)?,
            )
        })
        .and_then(|length| {
            length.checked_add(
                usize::try_from(override_count)
                    .ok()?
                    .checked_mul(COMMON_PROOF_CHECKPOINT_CURSOR_OVERRIDE_BYTE_LENGTH)?,
            )
        })
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(byte_length)
        .map_err(|_| CommonProofCheckpointCursorManifestError::AllocationLimitExceeded)?;
    output.extend_from_slice(&COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC);
    output.extend_from_slice(&COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_VERSION.to_le_bytes());
    output.push(1);
    output.extend_from_slice(&run_count.to_le_bytes());
    output.extend_from_slice(&logical_cursor_count.to_le_bytes());
    output.extend_from_slice(&family_schema_identifier.to_le_bytes());
    output.extend_from_slice(&derivation_binding_hash.into_bytes());
    output.extend_from_slice(&stream_attempt_identifier);

    let mut cursor_iterator = ordered_cursors.into_iter();
    for run in run_summaries.into_iter().flatten() {
        let (first_coordinate, first_cursor) = cursor_iterator
            .next()
            .ok_or(CommonProofCheckpointCursorManifestError::NonCanonicalEncoding)?;
        if first_coordinate != run.first_coordinate || first_cursor != run.common_cursor {
            return Err(CommonProofCheckpointCursorManifestError::NonCanonicalEncoding);
        }
        output.extend_from_slice(&first_coordinate.purpose_class().to_le_bytes());
        output.extend_from_slice(&first_coordinate.ordinal().to_le_bytes());
        output.extend_from_slice(&(run.coordinate_count - 1).to_le_bytes());
        output.extend_from_slice(&first_cursor.next_counter().to_le_bytes());
        output.extend_from_slice(
            &encode_cursor_offset(first_cursor.next_unread_bit_offset_in_buffered_block())?
                .to_le_bytes(),
        );
        output.extend_from_slice(&run.override_count.to_le_bytes());
        for coordinate_offset in 1..run.coordinate_count {
            let (coordinate, cursor) = cursor_iterator
                .next()
                .ok_or(CommonProofCheckpointCursorManifestError::NonCanonicalEncoding)?;
            if coordinate.purpose_class() != first_coordinate.purpose_class()
                || coordinate.ordinal()
                    != first_coordinate
                        .ordinal()
                        .checked_add(coordinate_offset)
                        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?
            {
                return Err(CommonProofCheckpointCursorManifestError::CoordinateOrder);
            }
            if !cursor_state_matches(first_cursor, cursor) {
                output.extend_from_slice(&coordinate_offset.to_le_bytes());
                output.extend_from_slice(&cursor.next_counter().to_le_bytes());
                output.extend_from_slice(
                    &encode_cursor_offset(cursor.next_unread_bit_offset_in_buffered_block())?
                        .to_le_bytes(),
                );
            }
        }
    }
    if cursor_iterator.next().is_some() {
        return Err(CommonProofCheckpointCursorManifestError::NonCanonicalEncoding);
    }
    if output.len() != byte_length {
        return Err(CommonProofCheckpointCursorManifestError::NonCanonicalEncoding);
    }
    if output.len()
        > usize::try_from(MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH)
            .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?
    {
        return Err(CommonProofCheckpointCursorManifestError::OutsideSupportedProfile);
    }
    Ok(output)
}

pub(crate) fn common_proof_checkpoint_cursor_manifest_requirement(
    capacity: CommonProofPrivateCoinCoordinateCapacity,
) -> Result<CommonProofCheckpointCursorManifestRequirement, CommonProofCheckpointCursorManifestError>
{
    let maximum_logical_cursor_count = capacity
        .logical_cursor_count()
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let maximum_consecutive_coordinate_run_count = capacity.consecutive_coordinate_run_count();
    if (maximum_logical_cursor_count == 0) != (maximum_consecutive_coordinate_run_count == 0)
        || maximum_consecutive_coordinate_run_count > maximum_logical_cursor_count
    {
        return Err(CommonProofCheckpointCursorManifestError::CoordinateOrder);
    }
    let maximum_override_count = maximum_logical_cursor_count
        .checked_sub(maximum_consecutive_coordinate_run_count)
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let maximum_canonical_byte_length = u32::try_from(
        COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
            .checked_add(COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH)
            .and_then(|length| {
                length.checked_add(
                    usize::try_from(maximum_consecutive_coordinate_run_count)
                        .ok()?
                        .checked_mul(COMMON_PROOF_CHECKPOINT_CURSOR_RUN_BYTE_LENGTH)?,
                )
            })
            .and_then(|length| {
                length.checked_add(
                    usize::try_from(maximum_override_count)
                        .ok()?
                        .checked_mul(COMMON_PROOF_CHECKPOINT_CURSOR_OVERRIDE_BYTE_LENGTH)?,
                )
            })
            .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?,
    )
    .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let allocated_mask_cursor_count = capacity
        .trace_mask_count
        .checked_add(capacity.telescoping_mask_count)
        .and_then(|count| count.checked_add(capacity.opening_mask_count))
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let retained_cursor_state_byte_ceiling =
        u64::try_from(core::mem::size_of::<PrivateRandomnessCommonProofCoinSource>())
            .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?
            .checked_add(
                u64::from(allocated_mask_cursor_count)
                    .checked_mul(
                        u64::try_from(core::mem::size_of::<Option<PrivateRandomCursor>>())
                            .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?,
                    )
                    .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?,
            )
            .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let encoding_workspace_byte_ceiling = u32::try_from(core::mem::size_of::<
        [Option<CommonProofCheckpointCursorRunSummary>; 4],
    >())
    .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let peak_additional_resident_byte_ceiling = retained_cursor_state_byte_ceiling
        .checked_add(u64::from(maximum_canonical_byte_length))
        .and_then(|bytes| bytes.checked_add(u64::from(encoding_workspace_byte_ceiling)))
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    Ok(CommonProofCheckpointCursorManifestRequirement {
        logical_cursor_count: maximum_logical_cursor_count,
        consecutive_coordinate_run_count: maximum_consecutive_coordinate_run_count,
        maximum_override_count,
        canonical_manifest_byte_ceiling: maximum_canonical_byte_length,
        retained_cursor_state_byte_ceiling,
        encoding_workspace_byte_ceiling,
        pending_manifest_resident_byte_ceiling: maximum_canonical_byte_length,
        restore_workspace_byte_ceiling: retained_cursor_state_byte_ceiling,
        peak_additional_resident_byte_ceiling,
        peak_copied_buffer_byte_length: maximum_canonical_byte_length,
    })
}

pub(crate) fn common_proof_checkpoint_cursor_manifest_requirement_for_variant(
    variant: &RelationPlanVariant,
) -> Result<CommonProofCheckpointCursorManifestRequirement, CommonProofCheckpointCursorManifestError>
{
    let capacity = CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(variant)?;
    common_proof_checkpoint_cursor_manifest_requirement(capacity)
}

fn cursor_state_matches(left: PrivateRandomCursor, right: PrivateRandomCursor) -> bool {
    left.next_counter() == right.next_counter()
        && left.next_unread_bit_offset_in_buffered_block()
            == right.next_unread_bit_offset_in_buffered_block()
}

fn encode_cursor_offset(
    offset: Option<u16>,
) -> Result<u16, CommonProofCheckpointCursorManifestError> {
    match offset {
        Some(offset) => offset
            .checked_add(1)
            .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow),
        None => Ok(0),
    }
}

pub(crate) fn common_proof_private_coin_coordinate_derivation_context_hash(
    derivation_binding_hash: Hash512,
    coordinate: CommonProofPrivateCoinCoordinate,
) -> Hash512 {
    Hash512::from_bytes(hash_framed_parts_512(
        COMMON_PROOF_PRIVATE_COIN_COORDINATE_HASH_DOMAIN,
        &[
            &derivation_binding_hash.into_bytes(),
            &coordinate.purpose_class().to_le_bytes(),
            &coordinate.ordinal().to_le_bytes(),
        ],
    ))
}

fn validate_manifest_cursor_identity(
    family_schema_identifier: u16,
    derivation_binding_hash: Hash512,
    stream_attempt_identifier: [u8; 32],
    coordinate: CommonProofPrivateCoinCoordinate,
    cursor: PrivateRandomCursor,
) -> Result<(), CommonProofCheckpointCursorManifestError> {
    if cursor.family() != family_schema_identifier
        || cursor.purpose() != coordinate.purpose_class()
        || cursor.derivation_context_hash()
            != common_proof_private_coin_coordinate_derivation_context_hash(
                derivation_binding_hash,
                coordinate,
            )
        || cursor.stream_attempt_identifier() != stream_attempt_identifier
    {
        return Err(CommonProofCheckpointCursorManifestError::IdentityMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrivateRandomnessCommonProofCoinError {
    Custody(FoundationSchemaError),
    AllocationLimitExceeded,
    CoordinateOutsidePlan,
    DuplicateCursorCoordinate,
    ReplaySourceMismatch,
    ReplayCursorMismatch,
    ReplaySpanAlreadyActive,
    ReplaySpanNotActive,
    ReplayAttemptInvalidated,
}

impl From<FoundationSchemaError> for PrivateRandomnessCommonProofCoinError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Custody(error)
    }
}

impl From<CommonProofPrivateCoinReplayTokenError> for PrivateRandomnessCommonProofCoinError {
    fn from(error: CommonProofPrivateCoinReplayTokenError) -> Self {
        match error {
            CommonProofPrivateCoinReplayTokenError::AllocationLimitExceeded => {
                Self::AllocationLimitExceeded
            }
            CommonProofPrivateCoinReplayTokenError::CanonicalEncoding(error) => {
                Self::Custody(error)
            }
        }
    }
}

#[derive(Clone)]
struct RetainedCommonProofPrivateCoinCursors {
    trace_masks: Box<[Option<PrivateRandomCursor>]>,
    telescoping_masks: Box<[Option<PrivateRandomCursor>]>,
    opening_masks: Box<[Option<PrivateRandomCursor>]>,
    proof_salt: Option<Option<PrivateRandomCursor>>,
}

impl RetainedCommonProofPrivateCoinCursors {
    fn new(
        capacity: CommonProofPrivateCoinCoordinateCapacity,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        fn allocate_slots(
            count: u32,
        ) -> Result<Box<[Option<PrivateRandomCursor>]>, PrivateRandomnessCommonProofCoinError>
        {
            let count = usize::try_from(count)
                .map_err(|_| PrivateRandomnessCommonProofCoinError::AllocationLimitExceeded)?;
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(count)
                .map_err(|_| PrivateRandomnessCommonProofCoinError::AllocationLimitExceeded)?;
            slots.resize(count, None);
            Ok(slots.into_boxed_slice())
        }

        Ok(Self {
            trace_masks: allocate_slots(capacity.trace_mask_count)?,
            telescoping_masks: allocate_slots(capacity.telescoping_mask_count)?,
            opening_masks: allocate_slots(capacity.opening_mask_count)?,
            proof_salt: capacity.includes_proof_salt.then_some(None),
        })
    }

    fn slot(
        &self,
        coordinate: CommonProofPrivateCoinCoordinate,
    ) -> Option<&Option<PrivateRandomCursor>> {
        let ordinal = usize::try_from(coordinate.ordinal()).ok()?;
        match coordinate.purpose_class() {
            1 => self.trace_masks.get(ordinal),
            2 => self.telescoping_masks.get(ordinal),
            3 => self.opening_masks.get(ordinal),
            PRIVATE_PROOF_SALT_PURPOSE if ordinal == 0 => self.proof_salt.as_ref(),
            _ => None,
        }
    }

    fn slot_mut(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
    ) -> Option<&mut Option<PrivateRandomCursor>> {
        let ordinal = usize::try_from(coordinate.ordinal()).ok()?;
        match coordinate.purpose_class() {
            1 => self.trace_masks.get_mut(ordinal),
            2 => self.telescoping_masks.get_mut(ordinal),
            3 => self.opening_masks.get_mut(ordinal),
            PRIVATE_PROOF_SALT_PURPOSE if ordinal == 0 => self.proof_salt.as_mut(),
            _ => None,
        }
    }

    fn cursors(
        &self,
    ) -> impl Iterator<Item = (CommonProofPrivateCoinCoordinate, PrivateRandomCursor)> + Clone + '_
    {
        fn coordinate_cursor(
            purpose_class: u16,
            (ordinal, cursor): (usize, &Option<PrivateRandomCursor>),
        ) -> Option<(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)> {
            Some((
                CommonProofPrivateCoinCoordinate {
                    purpose_class,
                    ordinal: u32::try_from(ordinal).ok()?,
                },
                (*cursor)?,
            ))
        }

        self.trace_masks
            .iter()
            .enumerate()
            .filter_map(|entry| coordinate_cursor(1, entry))
            .chain(
                self.telescoping_masks
                    .iter()
                    .enumerate()
                    .filter_map(|entry| coordinate_cursor(2, entry)),
            )
            .chain(
                self.opening_masks
                    .iter()
                    .enumerate()
                    .filter_map(|entry| coordinate_cursor(3, entry)),
            )
            .chain(self.proof_salt.iter().filter_map(|cursor| {
                cursor.map(|cursor| (CommonProofPrivateCoinCoordinate::proof_salt(), cursor))
            }))
    }

    fn cursor_catalog(
        &self,
    ) -> Result<
        Box<[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)]>,
        PrivateRandomnessCommonProofCoinError,
    > {
        let cursor_count = self.cursors().count();
        let mut cursors = Vec::new();
        cursors
            .try_reserve_exact(cursor_count)
            .map_err(|_| PrivateRandomnessCommonProofCoinError::AllocationLimitExceeded)?;
        cursors.extend(self.cursors());
        Ok(cursors.into_boxed_slice())
    }

    fn clear(&mut self) {
        self.trace_masks.fill(None);
        self.telescoping_masks.fill(None);
        self.opening_masks.fill(None);
        if let Some(proof_salt) = &mut self.proof_salt {
            *proof_salt = None;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofPrivateCoinReplayLifecycle {
    Idle,
    Capturing(u64),
    Replaying(u64),
    Invalidated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PublicOnlyCommonProofCoinError {
    InvalidIdentity,
    PrivateCoordinateUnavailable,
    ReplaySourceMismatch,
    ReplaySpanAlreadyActive,
    ReplaySpanNotActive,
    ReplayAttemptInvalidated,
    ReplayTokenInvalid,
}

/// Explicit zero-private-coordinate authority for public-only proof families.
/// It binds checkpoint and replay state to one local authenticated attempt,
/// but cannot sample masks or proof salts and never creates a private domain.
pub(crate) struct PublicOnlyCommonProofCoinSource {
    family_schema_identifier: u16,
    derivation_binding_hash: Hash512,
    attempt_lineage: [u8; 32],
    replay_instance_binding: Rc<()>,
    replay_reset_epoch: u64,
    next_replay_span_identifier: u64,
    replay_lifecycle: CommonProofPrivateCoinReplayLifecycle,
}

impl PublicOnlyCommonProofCoinSource {
    pub(crate) fn new(
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_lineage: [u8; 32],
    ) -> Result<Self, PublicOnlyCommonProofCoinError> {
        if !ProofApplicationSlotCeilings::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS
            .contains(&family_schema_identifier)
            || derivation_binding_hash == Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH])
            || attempt_lineage == [0_u8; 32]
        {
            return Err(PublicOnlyCommonProofCoinError::InvalidIdentity);
        }
        Ok(Self {
            family_schema_identifier,
            derivation_binding_hash,
            attempt_lineage,
            replay_instance_binding: Rc::new(()),
            replay_reset_epoch: 0,
            next_replay_span_identifier: 1,
            replay_lifecycle: CommonProofPrivateCoinReplayLifecycle::Idle,
        })
    }

    fn validate_span_identity(
        &self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), PublicOnlyCommonProofCoinError> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PublicOnlyCommonProofCoinError::ReplayAttemptInvalidated);
        }
        if !span.belongs_to(
            &self.replay_instance_binding,
            self.family_schema_identifier,
            self.derivation_binding_hash,
            self.attempt_lineage,
            self.replay_reset_epoch,
        ) {
            return Err(PublicOnlyCommonProofCoinError::ReplaySourceMismatch);
        }
        let expected_binding_hash = hash_framed_parts_512(
            COMMON_PROOF_PRIVATE_COIN_REPLAY_SPAN_DOMAIN,
            &[
                &self.family_schema_identifier.to_le_bytes(),
                &self.derivation_binding_hash.into_bytes(),
                &self.attempt_lineage,
                &self.replay_reset_epoch.to_le_bytes(),
                &span.span_identifier().to_le_bytes(),
                &span.start_catalog_digest,
                &span.end_catalog_digest,
            ],
        );
        if span.binding_hash() != expected_binding_hash
            || !span.start_cursors().is_empty()
            || !span.end_cursors().is_empty()
        {
            return Err(PublicOnlyCommonProofCoinError::ReplayTokenInvalid);
        }
        Ok(())
    }

    fn poison_replay_attempt(&mut self) {
        self.replay_lifecycle = CommonProofPrivateCoinReplayLifecycle::Invalidated;
        self.replay_reset_epoch = self.replay_reset_epoch.saturating_add(1);
    }
}

impl CommonProofPrivateCoinSource for PublicOnlyCommonProofCoinSource {
    type Error = PublicOnlyCommonProofCoinError;

    fn sample_modulo(
        &mut self,
        _coordinate: CommonProofPrivateCoinCoordinate,
        _modulus: u64,
        _maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        Err(PublicOnlyCommonProofCoinError::PrivateCoordinateUnavailable)
    }

    fn fill_raw_bytes(
        &mut self,
        _coordinate: CommonProofPrivateCoinCoordinate,
        _destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        Err(PublicOnlyCommonProofCoinError::PrivateCoordinateUnavailable)
    }
}

impl ReplayableCommonProofPrivateCoinSource for PublicOnlyCommonProofCoinSource {
    fn capture_proof_salt_replay_cursor(
        &self,
    ) -> Result<CommonProofPrivateCoinReplayCursor, Self::Error> {
        Err(PublicOnlyCommonProofCoinError::PrivateCoordinateUnavailable)
    }

    fn restore_proof_salt_replay_cursor(
        &mut self,
        _cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<(), Self::Error> {
        Err(PublicOnlyCommonProofCoinError::PrivateCoordinateUnavailable)
    }

    fn proof_salt_replay_cursor_matches(
        &self,
        _cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<bool, Self::Error> {
        Err(PublicOnlyCommonProofCoinError::PrivateCoordinateUnavailable)
    }
}

impl ReplayableCommonProofPrivateCoinCatalogSource for PublicOnlyCommonProofCoinSource {
    fn begin_all_coordinate_replay_span(
        &mut self,
    ) -> Result<CommonProofPrivateCoinReplaySpanStart, Self::Error> {
        match self.replay_lifecycle {
            CommonProofPrivateCoinReplayLifecycle::Idle => {}
            CommonProofPrivateCoinReplayLifecycle::Invalidated => {
                return Err(PublicOnlyCommonProofCoinError::ReplayAttemptInvalidated);
            }
            CommonProofPrivateCoinReplayLifecycle::Capturing(_)
            | CommonProofPrivateCoinReplayLifecycle::Replaying(_) => {
                return Err(PublicOnlyCommonProofCoinError::ReplaySpanAlreadyActive);
            }
        }
        let span_identifier = self.next_replay_span_identifier;
        let Some(next_span_identifier) = self.next_replay_span_identifier.checked_add(1) else {
            self.poison_replay_attempt();
            return Err(PublicOnlyCommonProofCoinError::ReplayAttemptInvalidated);
        };
        self.next_replay_span_identifier = next_span_identifier;
        let start = CommonProofPrivateCoinReplaySpanStart::new(
            &self.replay_instance_binding,
            self.family_schema_identifier,
            self.derivation_binding_hash,
            self.attempt_lineage,
            self.replay_reset_epoch,
            span_identifier,
            Vec::new().into_boxed_slice(),
        )
        .map_err(|_| PublicOnlyCommonProofCoinError::ReplayTokenInvalid)?;
        self.replay_lifecycle = CommonProofPrivateCoinReplayLifecycle::Capturing(span_identifier);
        Ok(start)
    }

    fn finish_all_coordinate_replay_span(
        &mut self,
        start: CommonProofPrivateCoinReplaySpanStart,
    ) -> Result<CommonProofPrivateCoinReplaySpan, Self::Error> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PublicOnlyCommonProofCoinError::ReplayAttemptInvalidated);
        }
        if self.replay_lifecycle
            != CommonProofPrivateCoinReplayLifecycle::Capturing(start.span_identifier())
        {
            self.poison_replay_attempt();
            return Err(PublicOnlyCommonProofCoinError::ReplaySpanNotActive);
        }
        if !start.belongs_to(
            &self.replay_instance_binding,
            self.family_schema_identifier,
            self.derivation_binding_hash,
            self.attempt_lineage,
            self.replay_reset_epoch,
        ) {
            self.poison_replay_attempt();
            return Err(PublicOnlyCommonProofCoinError::ReplaySourceMismatch);
        }
        let span = match CommonProofPrivateCoinReplaySpan::from_completed_capture(
            start,
            Vec::new().into_boxed_slice(),
        ) {
            Ok(span) => span,
            Err(_) => {
                self.poison_replay_attempt();
                return Err(PublicOnlyCommonProofCoinError::ReplayTokenInvalid);
            }
        };
        self.replay_lifecycle = CommonProofPrivateCoinReplayLifecycle::Idle;
        Ok(span)
    }

    fn restore_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error> {
        match self.replay_lifecycle {
            CommonProofPrivateCoinReplayLifecycle::Idle => {}
            CommonProofPrivateCoinReplayLifecycle::Invalidated => {
                return Err(PublicOnlyCommonProofCoinError::ReplayAttemptInvalidated);
            }
            CommonProofPrivateCoinReplayLifecycle::Capturing(_)
            | CommonProofPrivateCoinReplayLifecycle::Replaying(_) => {
                return Err(PublicOnlyCommonProofCoinError::ReplaySpanAlreadyActive);
            }
        }
        if let Err(error) = self.validate_span_identity(span) {
            self.poison_replay_attempt();
            return Err(error);
        }
        self.replay_lifecycle =
            CommonProofPrivateCoinReplayLifecycle::Replaying(span.span_identifier());
        Ok(())
    }

    fn complete_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PublicOnlyCommonProofCoinError::ReplayAttemptInvalidated);
        }
        if self.replay_lifecycle
            != CommonProofPrivateCoinReplayLifecycle::Replaying(span.span_identifier())
        {
            self.poison_replay_attempt();
            return Err(PublicOnlyCommonProofCoinError::ReplaySpanNotActive);
        }
        if let Err(error) = self.validate_span_identity(span) {
            self.poison_replay_attempt();
            return Err(error);
        }
        self.replay_lifecycle = CommonProofPrivateCoinReplayLifecycle::Idle;
        Ok(())
    }

    fn invalidate_all_coordinate_replay_state(&mut self) {
        self.poison_replay_attempt();
    }
}

impl CheckpointableCommonProofPrivateCoinSource for PublicOnlyCommonProofCoinSource {
    fn checkpoint_cursor_manifest(
        &self,
    ) -> Result<Vec<u8>, CommonProofCheckpointCursorManifestError> {
        encode_common_proof_checkpoint_cursor_manifest(
            self.family_schema_identifier,
            self.derivation_binding_hash,
            self.attempt_lineage,
            core::iter::empty::<(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)>(),
        )
    }
}

/// Owns the independent private-randomness cursor for every coordinate consumed by
/// one common-proof attempt.  The caller must authenticate exported cursors as
/// part of the containing attempt record before resuming them.
pub(crate) struct PrivateRandomnessCommonProofCoinSource {
    action_private_randomness: Rc<ActionPrivateRandomness>,
    family_schema_identifier: u16,
    derivation_binding_hash: Hash512,
    attempt_identifier: PrivateRandomnessAttemptIdentifier,
    retained_cursors: RetainedCommonProofPrivateCoinCursors,
    replay_instance_binding: Rc<()>,
    replay_reset_epoch: u64,
    next_replay_span_identifier: u64,
    replay_lifecycle: CommonProofPrivateCoinReplayLifecycle,
}

impl PrivateRandomnessCommonProofCoinSource {
    pub(crate) fn new(
        action_private_randomness: Rc<ActionPrivateRandomness>,
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
        coordinate_capacity: CommonProofPrivateCoinCoordinateCapacity,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        let salt_domain = PrivateRandomnessDomain::from_assigned_pair(
            family_schema_identifier,
            PRIVATE_PROOF_SALT_PURPOSE,
        )?;
        let salt_derivation_context_hash =
            common_proof_private_coin_coordinate_derivation_context_hash(
                derivation_binding_hash,
                CommonProofPrivateCoinCoordinate::proof_salt(),
            );
        drop(action_private_randomness.begin_stream(
            salt_domain,
            salt_derivation_context_hash,
            attempt_identifier,
        )?);
        Ok(Self {
            action_private_randomness,
            family_schema_identifier,
            derivation_binding_hash,
            attempt_identifier,
            retained_cursors: RetainedCommonProofPrivateCoinCursors::new(coordinate_capacity)?,
            replay_instance_binding: Rc::new(()),
            replay_reset_epoch: 0,
            next_replay_span_identifier: 1,
            replay_lifecycle: CommonProofPrivateCoinReplayLifecycle::Idle,
        })
    }

    pub(crate) fn resume(
        action_private_randomness: Rc<ActionPrivateRandomness>,
        family_schema_identifier: u16,
        derivation_binding_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
        coordinate_capacity: CommonProofPrivateCoinCoordinateCapacity,
        authenticated_cursors: impl IntoIterator<
            Item = (CommonProofPrivateCoinCoordinate, PrivateRandomCursor),
        >,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        let mut source = Self::new(
            Rc::clone(&action_private_randomness),
            family_schema_identifier,
            derivation_binding_hash,
            attempt_identifier,
            coordinate_capacity,
        )?;
        for (coordinate, cursor) in authenticated_cursors {
            let domain = PrivateRandomnessDomain::from_assigned_pair(
                family_schema_identifier,
                coordinate.purpose_class(),
            )?;
            let derivation_context_hash =
                common_proof_private_coin_coordinate_derivation_context_hash(
                    derivation_binding_hash,
                    coordinate,
                );
            drop(action_private_randomness.resume_stream(
                domain,
                derivation_context_hash,
                attempt_identifier,
                cursor,
            )?);
            let slot = source
                .retained_cursors
                .slot_mut(coordinate)
                .ok_or(PrivateRandomnessCommonProofCoinError::CoordinateOutsidePlan)?;
            if slot.is_some() {
                return Err(PrivateRandomnessCommonProofCoinError::DuplicateCursorCoordinate);
            }
            *slot = Some(cursor);
        }
        Ok(source)
    }

    pub(crate) fn cursors(
        &self,
    ) -> impl Iterator<Item = (CommonProofPrivateCoinCoordinate, PrivateRandomCursor)> + Clone + '_
    {
        self.retained_cursors.cursors()
    }

    fn stream_identity_for_coordinate(
        &self,
        coordinate: CommonProofPrivateCoinCoordinate,
    ) -> Result<
        (
            PrivateRandomnessDomain,
            Hash512,
            Option<PrivateRandomCursor>,
        ),
        PrivateRandomnessCommonProofCoinError,
    > {
        let domain = PrivateRandomnessDomain::from_assigned_pair(
            self.family_schema_identifier,
            coordinate.purpose_class(),
        )?;
        let derivation_context_hash = common_proof_private_coin_coordinate_derivation_context_hash(
            self.derivation_binding_hash,
            coordinate,
        );
        let retained_cursor = *self
            .retained_cursors
            .slot(coordinate)
            .ok_or(PrivateRandomnessCommonProofCoinError::CoordinateOutsidePlan)?;
        Ok((domain, derivation_context_hash, retained_cursor))
    }

    fn retain_cursor(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        cursor: PrivateRandomCursor,
    ) -> Result<(), PrivateRandomnessCommonProofCoinError> {
        *self
            .retained_cursors
            .slot_mut(coordinate)
            .ok_or(PrivateRandomnessCommonProofCoinError::CoordinateOutsidePlan)? = Some(cursor);
        Ok(())
    }

    fn current_proof_salt_cursor(
        &self,
    ) -> Result<PrivateRandomCursor, PrivateRandomnessCommonProofCoinError> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
        }
        let coordinate = CommonProofPrivateCoinCoordinate::proof_salt();
        let (domain, derivation_context_hash, retained_cursor) =
            self.stream_identity_for_coordinate(coordinate)?;
        if let Some(cursor) = retained_cursor {
            return Ok(cursor);
        }
        let stream = self.action_private_randomness.begin_stream(
            domain,
            derivation_context_hash,
            self.attempt_identifier,
        )?;
        let cursor = stream.cursor();
        drop(stream);
        Ok(cursor)
    }

    fn validate_replay_cursor(
        &self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<PrivateRandomCursor, PrivateRandomnessCommonProofCoinError> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
        }
        if !replay_cursor.belongs_to(&self.replay_instance_binding) {
            return Err(PrivateRandomnessCommonProofCoinError::ReplaySourceMismatch);
        }
        let coordinate = CommonProofPrivateCoinCoordinate::proof_salt();
        let cursor = replay_cursor.cursor();
        validate_manifest_cursor_identity(
            self.family_schema_identifier,
            self.derivation_binding_hash,
            *self.attempt_identifier.as_bytes(),
            coordinate,
            cursor,
        )
        .map_err(|_| PrivateRandomnessCommonProofCoinError::ReplayCursorMismatch)?;
        Ok(cursor)
    }

    fn validate_all_coordinate_replay_span_identity(
        &self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), PrivateRandomnessCommonProofCoinError> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
        }
        if !span.belongs_to(
            &self.replay_instance_binding,
            self.family_schema_identifier,
            self.derivation_binding_hash,
            *self.attempt_identifier.as_bytes(),
            self.replay_reset_epoch,
        ) {
            return Err(PrivateRandomnessCommonProofCoinError::ReplaySourceMismatch);
        }
        let expected_binding_hash = hash_framed_parts_512(
            COMMON_PROOF_PRIVATE_COIN_REPLAY_SPAN_DOMAIN,
            &[
                &self.family_schema_identifier.to_le_bytes(),
                &self.derivation_binding_hash.into_bytes(),
                self.attempt_identifier.as_bytes(),
                &self.replay_reset_epoch.to_le_bytes(),
                &span.span_identifier().to_le_bytes(),
                &span.start_catalog_digest,
                &span.end_catalog_digest,
            ],
        );
        if span.binding_hash() != expected_binding_hash {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayCursorMismatch);
        }
        Ok(())
    }

    fn validate_cursor_catalog(
        &self,
        cursor_catalog: &[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)],
    ) -> Result<(), PrivateRandomnessCommonProofCoinError> {
        let mut previous_coordinate = None;
        for (coordinate, cursor) in cursor_catalog {
            if previous_coordinate.is_some_and(|previous| previous >= *coordinate)
                || self.retained_cursors.slot(*coordinate).is_none()
            {
                return Err(PrivateRandomnessCommonProofCoinError::ReplayCursorMismatch);
            }
            validate_manifest_cursor_identity(
                self.family_schema_identifier,
                self.derivation_binding_hash,
                *self.attempt_identifier.as_bytes(),
                *coordinate,
                *cursor,
            )
            .map_err(|_| PrivateRandomnessCommonProofCoinError::ReplayCursorMismatch)?;
            let domain = PrivateRandomnessDomain::from_assigned_pair(
                self.family_schema_identifier,
                coordinate.purpose_class(),
            )?;
            let derivation_context_hash =
                common_proof_private_coin_coordinate_derivation_context_hash(
                    self.derivation_binding_hash,
                    *coordinate,
                );
            drop(self.action_private_randomness.resume_stream(
                domain,
                derivation_context_hash,
                self.attempt_identifier,
                *cursor,
            )?);
            previous_coordinate = Some(*coordinate);
        }
        Ok(())
    }

    fn restore_cursor_catalog(
        &mut self,
        cursor_catalog: &[(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)],
    ) -> Result<(), PrivateRandomnessCommonProofCoinError> {
        self.validate_cursor_catalog(cursor_catalog)?;
        self.retained_cursors.clear();
        for (coordinate, cursor) in cursor_catalog {
            *self
                .retained_cursors
                .slot_mut(*coordinate)
                .ok_or(PrivateRandomnessCommonProofCoinError::CoordinateOutsidePlan)? =
                Some(*cursor);
        }
        Ok(())
    }

    fn poison_replay_attempt(&mut self) {
        self.replay_lifecycle = CommonProofPrivateCoinReplayLifecycle::Invalidated;
        self.replay_reset_epoch = self.replay_reset_epoch.saturating_add(1);
        self.retained_cursors.clear();
    }
}

impl CommonProofPrivateCoinSource for PrivateRandomnessCommonProofCoinSource {
    type Error = PrivateRandomnessCommonProofCoinError;

    fn sample_modulo(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
        }
        let (domain, derivation_context_hash, retained_cursor) =
            self.stream_identity_for_coordinate(coordinate)?;
        let action_private_randomness = Rc::clone(&self.action_private_randomness);
        let mut stream = match retained_cursor {
            Some(cursor) => action_private_randomness.resume_stream(
                domain,
                derivation_context_hash,
                self.attempt_identifier,
                cursor,
            )?,
            None => action_private_randomness.begin_stream(
                domain,
                derivation_context_hash,
                self.attempt_identifier,
            )?,
        };
        let result = stream
            .sample_modulo(modulus, maximum_candidate_draws_per_output)
            .map_err(PrivateRandomnessCommonProofCoinError::Custody);
        let cursor = stream.cursor();
        drop(stream);
        self.retain_cursor(coordinate, cursor)?;
        result
    }

    fn fill_raw_bytes(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
        }
        let (domain, derivation_context_hash, retained_cursor) =
            self.stream_identity_for_coordinate(coordinate)?;
        let action_private_randomness = Rc::clone(&self.action_private_randomness);
        let mut stream = match retained_cursor {
            Some(cursor) => action_private_randomness.resume_stream(
                domain,
                derivation_context_hash,
                self.attempt_identifier,
                cursor,
            )?,
            None => action_private_randomness.begin_stream(
                domain,
                derivation_context_hash,
                self.attempt_identifier,
            )?,
        };
        let result = stream
            .fill_bytes(destination)
            .map_err(PrivateRandomnessCommonProofCoinError::Custody);
        let cursor = stream.cursor();
        drop(stream);
        self.retain_cursor(coordinate, cursor)?;
        result
    }
}

impl ReplayableCommonProofPrivateCoinSource for PrivateRandomnessCommonProofCoinSource {
    fn capture_proof_salt_replay_cursor(
        &self,
    ) -> Result<CommonProofPrivateCoinReplayCursor, Self::Error> {
        Ok(CommonProofPrivateCoinReplayCursor::new(
            &self.replay_instance_binding,
            self.current_proof_salt_cursor()?,
        ))
    }

    fn restore_proof_salt_replay_cursor(
        &mut self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<(), Self::Error> {
        let cursor = self.validate_replay_cursor(replay_cursor)?;
        let coordinate = CommonProofPrivateCoinCoordinate::proof_salt();
        let (domain, derivation_context_hash, _) =
            self.stream_identity_for_coordinate(coordinate)?;
        drop(self.action_private_randomness.resume_stream(
            domain,
            derivation_context_hash,
            self.attempt_identifier,
            cursor,
        )?);
        self.retain_cursor(coordinate, cursor)
    }

    fn proof_salt_replay_cursor_matches(
        &self,
        replay_cursor: &CommonProofPrivateCoinReplayCursor,
    ) -> Result<bool, Self::Error> {
        let expected_cursor = self.validate_replay_cursor(replay_cursor)?;
        Ok(self.current_proof_salt_cursor()? == expected_cursor)
    }
}

impl ReplayableCommonProofPrivateCoinCatalogSource for PrivateRandomnessCommonProofCoinSource {
    fn begin_all_coordinate_replay_span(
        &mut self,
    ) -> Result<CommonProofPrivateCoinReplaySpanStart, Self::Error> {
        match self.replay_lifecycle {
            CommonProofPrivateCoinReplayLifecycle::Idle => {}
            CommonProofPrivateCoinReplayLifecycle::Invalidated => {
                return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
            }
            CommonProofPrivateCoinReplayLifecycle::Capturing(_)
            | CommonProofPrivateCoinReplayLifecycle::Replaying(_) => {
                return Err(PrivateRandomnessCommonProofCoinError::ReplaySpanAlreadyActive);
            }
        }
        let span_identifier = self.next_replay_span_identifier;
        let Some(next_span_identifier) = self.next_replay_span_identifier.checked_add(1) else {
            self.poison_replay_attempt();
            return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
        };
        self.next_replay_span_identifier = next_span_identifier;
        let start = CommonProofPrivateCoinReplaySpanStart::new(
            &self.replay_instance_binding,
            self.family_schema_identifier,
            self.derivation_binding_hash,
            *self.attempt_identifier.as_bytes(),
            self.replay_reset_epoch,
            span_identifier,
            self.retained_cursors.cursor_catalog()?,
        )
        .map_err(PrivateRandomnessCommonProofCoinError::from)?;
        self.replay_lifecycle = CommonProofPrivateCoinReplayLifecycle::Capturing(span_identifier);
        Ok(start)
    }

    fn finish_all_coordinate_replay_span(
        &mut self,
        start: CommonProofPrivateCoinReplaySpanStart,
    ) -> Result<CommonProofPrivateCoinReplaySpan, Self::Error> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
        }
        if self.replay_lifecycle
            != CommonProofPrivateCoinReplayLifecycle::Capturing(start.span_identifier())
        {
            self.poison_replay_attempt();
            return Err(PrivateRandomnessCommonProofCoinError::ReplaySpanNotActive);
        }
        if !start.belongs_to(
            &self.replay_instance_binding,
            self.family_schema_identifier,
            self.derivation_binding_hash,
            *self.attempt_identifier.as_bytes(),
            self.replay_reset_epoch,
        ) {
            self.poison_replay_attempt();
            return Err(PrivateRandomnessCommonProofCoinError::ReplaySourceMismatch);
        }
        let end_cursors = match self.retained_cursors.cursor_catalog() {
            Ok(cursors) => cursors,
            Err(error) => {
                self.poison_replay_attempt();
                return Err(error);
            }
        };
        let span =
            match CommonProofPrivateCoinReplaySpan::from_completed_capture(start, end_cursors) {
                Ok(span) => span,
                Err(error) => {
                    self.poison_replay_attempt();
                    return Err(PrivateRandomnessCommonProofCoinError::from(error));
                }
            };
        self.replay_lifecycle = CommonProofPrivateCoinReplayLifecycle::Idle;
        Ok(span)
    }

    fn restore_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error> {
        match self.replay_lifecycle {
            CommonProofPrivateCoinReplayLifecycle::Idle => {}
            CommonProofPrivateCoinReplayLifecycle::Invalidated => {
                return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
            }
            CommonProofPrivateCoinReplayLifecycle::Capturing(_)
            | CommonProofPrivateCoinReplayLifecycle::Replaying(_) => {
                return Err(PrivateRandomnessCommonProofCoinError::ReplaySpanAlreadyActive);
            }
        }
        if let Err(error) = self.validate_all_coordinate_replay_span_identity(span) {
            self.poison_replay_attempt();
            return Err(error);
        }
        if let Err(error) = self.restore_cursor_catalog(span.start_cursors()) {
            self.poison_replay_attempt();
            return Err(error);
        }
        self.replay_lifecycle =
            CommonProofPrivateCoinReplayLifecycle::Replaying(span.span_identifier());
        Ok(())
    }

    fn complete_all_coordinate_replay_span(
        &mut self,
        span: &CommonProofPrivateCoinReplaySpan,
    ) -> Result<(), Self::Error> {
        if self.replay_lifecycle == CommonProofPrivateCoinReplayLifecycle::Invalidated {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayAttemptInvalidated);
        }
        if self.replay_lifecycle
            != CommonProofPrivateCoinReplayLifecycle::Replaying(span.span_identifier())
        {
            self.poison_replay_attempt();
            return Err(PrivateRandomnessCommonProofCoinError::ReplaySpanNotActive);
        }
        if let Err(error) = self.validate_all_coordinate_replay_span_identity(span) {
            self.poison_replay_attempt();
            return Err(error);
        }
        let observed_cursors = match self.retained_cursors.cursor_catalog() {
            Ok(cursors) => cursors,
            Err(error) => {
                self.poison_replay_attempt();
                return Err(error);
            }
        };
        let observed_digest = match common_proof_private_coin_cursor_catalog_digest(
            &span.identity,
            &observed_cursors,
        ) {
            Ok(digest) => digest,
            Err(error) => {
                self.poison_replay_attempt();
                return Err(PrivateRandomnessCommonProofCoinError::from(error));
            }
        };
        if observed_cursors.as_ref() != span.end_cursors()
            || observed_digest != span.end_catalog_digest
        {
            self.poison_replay_attempt();
            return Err(PrivateRandomnessCommonProofCoinError::ReplayCursorMismatch);
        }
        self.replay_lifecycle = CommonProofPrivateCoinReplayLifecycle::Idle;
        Ok(())
    }

    fn invalidate_all_coordinate_replay_state(&mut self) {
        self.poison_replay_attempt();
    }
}

impl CheckpointableCommonProofPrivateCoinSource for PrivateRandomnessCommonProofCoinSource {
    fn checkpoint_cursor_manifest(
        &self,
    ) -> Result<Vec<u8>, CommonProofCheckpointCursorManifestError> {
        encode_common_proof_checkpoint_cursor_manifest(
            self.family_schema_identifier,
            self.derivation_binding_hash,
            *self.attempt_identifier.as_bytes(),
            self.cursors(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_cursor_manifest_retains_reset_safe_source_identity() {
        let family_schema_identifier = 0x1217;
        let derivation_binding_hash = [0x53_u8; Hash512::BYTE_LENGTH];
        let stream_attempt_identifier = [0xa6_u8; 32];
        let empty_cursors: [(CommonProofPrivateCoinCoordinate, PrivateRandomCursor); 0] = [];

        let encoded = encode_common_proof_checkpoint_cursor_manifest(
            family_schema_identifier,
            Hash512::from_bytes(derivation_binding_hash),
            stream_attempt_identifier,
            empty_cursors,
        )
        .expect("a checkpoint before the first cursor remains reset-safe");

        assert_eq!(
            encoded.len(),
            COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
                + COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH
        );
        assert_eq!(
            &encoded[..COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC.len()],
            &COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC
        );
        assert_eq!(
            u16::from_le_bytes(encoded[8..10].try_into().expect("version bytes")),
            COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_VERSION
        );
        assert_eq!(encoded[10], 1);
        assert_eq!(
            u32::from_le_bytes(encoded[11..15].try_into().expect("run-count bytes")),
            0
        );
        assert_eq!(
            u32::from_le_bytes(
                encoded[15..19]
                    .try_into()
                    .expect("logical-cursor-count bytes")
            ),
            0
        );
        assert_eq!(
            u16::from_le_bytes(encoded[19..21].try_into().expect("family bytes")),
            family_schema_identifier
        );
        assert_eq!(&encoded[21..85], &derivation_binding_hash);
        assert_eq!(&encoded[85..117], &stream_attempt_identifier);
    }

    #[test]
    fn zero_cursor_capacity_accounts_for_the_unconditional_identity() {
        let requirement = common_proof_checkpoint_cursor_manifest_requirement(
            CommonProofPrivateCoinCoordinateCapacity::for_test(0, 0, 0, false),
        )
        .expect("zero cursor capacity remains representable");

        assert_eq!(requirement.logical_cursor_count(), 0);
        assert_eq!(requirement.consecutive_coordinate_run_count(), 0);
        assert_eq!(requirement.maximum_override_count(), 0);
        assert_eq!(
            requirement.canonical_manifest_byte_ceiling(),
            u32::try_from(
                COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
                    + COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH
            )
            .expect("manifest constants fit u32")
        );
        assert!(requirement.fits_absolute_bounds());
    }

    #[test]
    fn public_only_coin_source_has_no_private_domain_and_replays_only_empty_catalogs() {
        for family_schema_identifier in
            ProofApplicationSlotCeilings::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS
        {
            assert!(
                PublicOnlyCommonProofCoinSource::new(
                    family_schema_identifier,
                    Hash512::from_bytes([0x35_u8; Hash512::BYTE_LENGTH]),
                    [0x74_u8; 32],
                )
                .is_ok()
            );
        }
        for rejected_family in [
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            0xffff,
        ] {
            assert!(matches!(
                PublicOnlyCommonProofCoinSource::new(
                    rejected_family,
                    Hash512::from_bytes([0x35_u8; Hash512::BYTE_LENGTH]),
                    [0x74_u8; 32],
                ),
                Err(PublicOnlyCommonProofCoinError::InvalidIdentity)
            ));
        }

        let family_schema_identifier =
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
        let derivation_binding_hash = Hash512::from_bytes([0x35_u8; Hash512::BYTE_LENGTH]);
        let attempt_lineage = [0x74_u8; 32];
        let mut source = PublicOnlyCommonProofCoinSource::new(
            family_schema_identifier,
            derivation_binding_hash,
            attempt_lineage,
        )
        .expect("the public-only source identity is complete");

        let expected_manifest = encode_common_proof_checkpoint_cursor_manifest(
            family_schema_identifier,
            derivation_binding_hash,
            attempt_lineage,
            core::iter::empty::<(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)>(),
        )
        .expect("the empty cursor catalog is canonical");
        assert_eq!(
            source
                .checkpoint_cursor_manifest()
                .expect("the public-only checkpoint is representable"),
            expected_manifest
        );

        assert!(matches!(
            source.sample_modulo(
                CommonProofPrivateCoinCoordinate::mask(1, 0)
                    .expect("trace-mask coordinates use purpose class one"),
                17,
                8
            ),
            Err(PublicOnlyCommonProofCoinError::PrivateCoordinateUnavailable)
        ));
        assert!(matches!(
            source.fill_raw_bytes(
                CommonProofPrivateCoinCoordinate::proof_salt(),
                &mut [0_u8; 32]
            ),
            Err(PublicOnlyCommonProofCoinError::PrivateCoordinateUnavailable)
        ));
        assert!(matches!(
            source.capture_proof_salt_replay_cursor(),
            Err(PublicOnlyCommonProofCoinError::PrivateCoordinateUnavailable)
        ));

        let start = source
            .begin_all_coordinate_replay_span()
            .expect("an empty public-only replay span can begin");
        assert!(matches!(
            source.begin_all_coordinate_replay_span(),
            Err(PublicOnlyCommonProofCoinError::ReplaySpanAlreadyActive)
        ));
        let span = source
            .finish_all_coordinate_replay_span(start)
            .expect("the empty public-only replay span can finish");
        assert!(span.start_cursors().is_empty());
        assert!(span.end_cursors().is_empty());
        source
            .restore_all_coordinate_replay_span(&span)
            .expect("the exact source can restore its empty replay span");
        source
            .complete_all_coordinate_replay_span(&span)
            .expect("the exact source completes with the same empty catalog");

        let mut other_source = PublicOnlyCommonProofCoinSource::new(
            family_schema_identifier,
            derivation_binding_hash,
            attempt_lineage,
        )
        .expect("the second source has the same public identity but a distinct live authority");
        assert!(matches!(
            other_source.restore_all_coordinate_replay_span(&span),
            Err(PublicOnlyCommonProofCoinError::ReplaySourceMismatch)
        ));
        assert!(matches!(
            other_source.begin_all_coordinate_replay_span(),
            Err(PublicOnlyCommonProofCoinError::ReplayAttemptInvalidated)
        ));
    }
}
