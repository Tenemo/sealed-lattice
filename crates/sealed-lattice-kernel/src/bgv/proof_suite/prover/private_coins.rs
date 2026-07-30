use std::rc::Rc;

#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
use num_bigint::BigUint;

#[cfg(test)]
use crate::foundation::{
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomnessDerivationInput, ActionRandomnessRoot,
    ParticipantIdentity, PersistentProofCoinInput, ProofApplicationSlot,
    ProofApplicationSlotCeilings,
};
#[cfg(test)]
use zeroize::Zeroizing;

use crate::{
    foundation::{
        ActionPrivateRandomness, FoundationSchemaError, Hash512, PRIVATE_PROOF_SALT_PURPOSE,
        PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
    },
    hashing::{StreamingHash512, hash_framed_parts_512},
};

use super::super::relation_plan::{
    ProofPrivacyMode, RelationMaskCoordinate, RelationMaskKind, RelationPlanVariant,
};
#[cfg(test)]
use super::super::relation_plan::{
    RelationColumnOrigin, RelationColumnValueType, RelationMaskTargetClass,
};
#[cfg(test)]
use super::super::{PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE};

const COMMON_PROOF_PRIVATE_COIN_COORDINATE_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/private-coin-coordinate/v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommonProofPrivateCoinCoordinate {
    purpose_class: u16,
    ordinal: u32,
}

impl CommonProofPrivateCoinCoordinate {
    #[cfg(test)]
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

    pub(crate) const fn hiding_argument() -> Self {
        Self {
            purpose_class: 4,
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
    includes_hiding_argument: bool,
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
        // Aggregate-wide WHIR uses an independently keyed private pad for
        // every family. Public-only describes the relation witness, not the
        // construction-level hiding stream; deriving that pad from public
        // transcript data would make the mask publicly recomputable.
        let includes_hiding_argument = true;
        Ok(Self {
            trace_mask_count: counts[RelationMaskKind::Trace as usize - 1],
            telescoping_mask_count: counts[RelationMaskKind::Telescoping as usize - 1],
            opening_mask_count: counts[RelationMaskKind::OpeningBatch as usize - 1],
            includes_proof_salt,
            includes_hiding_argument,
        })
    }

    #[cfg(test)]
    pub(crate) const fn for_test(
        trace_mask_count: u32,
        telescoping_mask_count: u32,
        opening_mask_count: u32,
        includes_proof_salt: bool,
        includes_hiding_argument: bool,
    ) -> Self {
        Self {
            trace_mask_count,
            telescoping_mask_count,
            opening_mask_count,
            includes_proof_salt,
            includes_hiding_argument,
        }
    }

    #[cfg(test)]
    pub(crate) fn logical_cursor_count(self) -> Option<u32> {
        self.trace_mask_count
            .checked_add(self.telescoping_mask_count)
            .and_then(|count| count.checked_add(self.opening_mask_count))
            .and_then(|count| count.checked_add(self.includes_proof_salt as u32))
            .and_then(|count| count.checked_add(self.includes_hiding_argument as u32))
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

    /// Replays a completed modulo-sampling coordinate from its private stream
    /// origin without advancing the retained generation cursor. Implementations
    /// must refuse unless the replay consumes exactly the same private stream
    /// prefix as the original coordinate operation. This is a private custody
    /// operation; transcript bytes and public inputs cannot implement it.
    fn replay_modulo_samples(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        destination: &mut [u64],
    ) -> Result<(), Self::Error>;
}

/// One source-owned private-coin operation, aggregated by its independently
/// derived coordinate. A raw byte fill deliberately has no modulus or
/// rejection-sampling draw ceiling.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofPrivateCoinSamplingOperation {
    ModuloSamples {
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        output_count: u64,
    },
    RawByteFill {
        byte_count: u64,
    },
}

#[cfg(test)]
impl CommonProofPrivateCoinSamplingOperation {
    pub(crate) const fn maximum_candidate_draws_per_output(self) -> Option<u32> {
        match self {
            Self::ModuloSamples {
                maximum_candidate_draws_per_output,
                ..
            } => Some(maximum_candidate_draws_per_output),
            Self::RawByteFill { .. } => None,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofPrivateCoinSamplingCatalogError {
    CountOverflow,
    ConflictingOperation,
    InvalidMask,
    InvalidSampler,
}

/// Exact union bound for bounded private rejection-sampler exhaustion in the
/// uniform-private-coin model. For the production KMAC stream this is the
/// corresponding ideal-PRF premise; a computational claim must carry that PRF
/// reduction explicitly. The fraction is left unreduced so its
/// candidate-space derivation remains inspectable.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofPrivateCoinExhaustionUnionBound {
    numerator: BigUint,
    denominator: BigUint,
}

#[cfg(test)]
impl CommonProofPrivateCoinExhaustionUnionBound {
    pub(crate) fn is_at_most_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.numerator << exponent) <= self.denominator
    }

    #[cfg(test)]
    const fn numerator(&self) -> &BigUint {
        &self.numerator
    }

    #[cfg(test)]
    const fn denominator(&self) -> &BigUint {
        &self.denominator
    }
}

/// Canonical per-coordinate accounting for private proof coins. The static
/// constructor derives every mask draw from the compiled relation variant;
/// callers add only construction-specific raw fills that are outside the mask
/// grammar.
#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommonProofPrivateCoinSamplingCatalog {
    entries: BTreeMap<CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSamplingOperation>,
}

#[cfg(test)]
impl CommonProofPrivateCoinSamplingCatalog {
    pub(crate) fn from_relation_plan_variant(
        variant: &RelationPlanVariant,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<Self, CommonProofPrivateCoinSamplingCatalogError> {
        if maximum_candidate_draws_per_output == 0 {
            return Err(CommonProofPrivateCoinSamplingCatalogError::InvalidMask);
        }
        let mut catalog = Self::default();
        for mask in variant.ordered_masks().iter().copied() {
            let coordinate = CommonProofPrivateCoinCoordinate::from_mask(mask.mask_coordinate());
            let coordinate_count_per_coefficient = match (mask.mask_kind(), mask.target_class()) {
                (RelationMaskKind::Trace, RelationMaskTargetClass::Column) => {
                    let column = variant
                        .ordered_columns()
                        .get(usize::try_from(mask.target_ordinal()).map_err(|_| {
                            CommonProofPrivateCoinSamplingCatalogError::CountOverflow
                        })?)
                        .ok_or(CommonProofPrivateCoinSamplingCatalogError::InvalidMask)?;
                    if !matches!(column.origin(), RelationColumnOrigin::Prover) {
                        return Err(CommonProofPrivateCoinSamplingCatalogError::InvalidMask);
                    }
                    match column.value_type() {
                        RelationColumnValueType::BaseField => 1_u64,
                        RelationColumnValueType::ChallengeExtension => {
                            u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE).map_err(|_| {
                                CommonProofPrivateCoinSamplingCatalogError::CountOverflow
                            })?
                        }
                    }
                }
                (RelationMaskKind::Telescoping, RelationMaskTargetClass::QuotientComponent)
                | (RelationMaskKind::OpeningBatch, RelationMaskTargetClass::Batch) => {
                    u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                        .map_err(|_| CommonProofPrivateCoinSamplingCatalogError::CountOverflow)?
                }
                _ => return Err(CommonProofPrivateCoinSamplingCatalogError::InvalidMask),
            };
            let output_count = mask
                .mask_degree_bound_exclusive()
                .checked_mul(coordinate_count_per_coefficient)
                .ok_or(CommonProofPrivateCoinSamplingCatalogError::CountOverflow)?;
            if output_count == 0
                || catalog
                    .entries
                    .insert(
                        coordinate,
                        CommonProofPrivateCoinSamplingOperation::ModuloSamples {
                            modulus: PROOF_BASE_FIELD_MODULUS,
                            maximum_candidate_draws_per_output,
                            output_count,
                        },
                    )
                    .is_some()
            {
                return Err(CommonProofPrivateCoinSamplingCatalogError::InvalidMask);
            }
        }
        Ok(catalog)
    }

    pub(crate) fn record_raw_byte_fill(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        byte_count: usize,
    ) -> Result<(), CommonProofPrivateCoinSamplingCatalogError> {
        let byte_count = u64::try_from(byte_count)
            .map_err(|_| CommonProofPrivateCoinSamplingCatalogError::CountOverflow)?;
        if byte_count == 0 {
            return Ok(());
        }
        match self.entries.entry(coordinate) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(CommonProofPrivateCoinSamplingOperation::RawByteFill { byte_count });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let CommonProofPrivateCoinSamplingOperation::RawByteFill {
                    byte_count: recorded_byte_count,
                } = entry.get_mut()
                else {
                    return Err(CommonProofPrivateCoinSamplingCatalogError::ConflictingOperation);
                };
                *recorded_byte_count = recorded_byte_count
                    .checked_add(byte_count)
                    .ok_or(CommonProofPrivateCoinSamplingCatalogError::CountOverflow)?;
            }
        }
        Ok(())
    }

    fn record_modulo_sample(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<(), CommonProofPrivateCoinSamplingCatalogError> {
        self.record_modulo_samples(coordinate, modulus, maximum_candidate_draws_per_output, 1)
    }

    pub(crate) fn record_modulo_samples(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        output_count: usize,
    ) -> Result<(), CommonProofPrivateCoinSamplingCatalogError> {
        let output_count = u64::try_from(output_count)
            .map_err(|_| CommonProofPrivateCoinSamplingCatalogError::CountOverflow)?;
        if output_count == 0 {
            return Ok(());
        }
        match self.entries.entry(coordinate) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(CommonProofPrivateCoinSamplingOperation::ModuloSamples {
                    modulus,
                    maximum_candidate_draws_per_output,
                    output_count,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let CommonProofPrivateCoinSamplingOperation::ModuloSamples {
                    modulus: recorded_modulus,
                    maximum_candidate_draws_per_output: recorded_maximum_candidate_draws,
                    output_count: recorded_output_count,
                } = entry.get_mut()
                else {
                    return Err(CommonProofPrivateCoinSamplingCatalogError::ConflictingOperation);
                };
                if *recorded_modulus != modulus
                    || *recorded_maximum_candidate_draws != maximum_candidate_draws_per_output
                {
                    return Err(CommonProofPrivateCoinSamplingCatalogError::ConflictingOperation);
                }
                *recorded_output_count = recorded_output_count
                    .checked_add(output_count)
                    .ok_or(CommonProofPrivateCoinSamplingCatalogError::CountOverflow)?;
            }
        }
        Ok(())
    }

    pub(crate) fn entry(
        &self,
        coordinate: CommonProofPrivateCoinCoordinate,
    ) -> Option<CommonProofPrivateCoinSamplingOperation> {
        self.entries.get(&coordinate).copied()
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn entries(
        &self,
    ) -> impl Iterator<
        Item = (
            CommonProofPrivateCoinCoordinate,
            CommonProofPrivateCoinSamplingOperation,
        ),
    > + '_ {
        self.entries
            .iter()
            .map(|(coordinate, operation)| (*coordinate, *operation))
    }

    pub(crate) fn retaining_coordinates(
        &self,
        mut retain: impl FnMut(CommonProofPrivateCoinCoordinate) -> bool,
    ) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|(coordinate, _)| retain(**coordinate))
                .map(|(coordinate, operation)| (*coordinate, *operation))
                .collect(),
        }
    }

    /// Derives the exact action-level union bound from the live private
    /// sampler in the uniform-private-coin model. A modulus `m` consumes
    /// `L = ceil(bit_length(m) / 8)` bytes, so one candidate draw rejects
    /// exactly `2^(8L) mod m` values. Exhausting one output rejects all `D`
    /// independent uniform candidates. For the production deterministic KMAC
    /// stream, this step relies on the corresponding ideal-PRF premise. Raw
    /// byte fills do not reject and therefore add no term.
    pub(crate) fn exhaustion_union_bound(
        &self,
        application_multiplicity: u32,
    ) -> Result<
        CommonProofPrivateCoinExhaustionUnionBound,
        CommonProofPrivateCoinSamplingCatalogError,
    > {
        if application_multiplicity == 0 {
            return Err(CommonProofPrivateCoinSamplingCatalogError::InvalidSampler);
        }
        let mut union_numerator = BigUint::default();
        let mut union_denominator = BigUint::from(1_u8);
        for operation in self.entries.values().copied() {
            let CommonProofPrivateCoinSamplingOperation::ModuloSamples {
                modulus,
                maximum_candidate_draws_per_output,
                output_count,
            } = operation
            else {
                continue;
            };
            if modulus <= 1 || maximum_candidate_draws_per_output == 0 || output_count == 0 {
                return Err(CommonProofPrivateCoinSamplingCatalogError::InvalidSampler);
            }
            let significant_bit_length = u64::BITS - modulus.leading_zeros();
            let sample_byte_length = significant_bit_length.div_ceil(8);
            let sample_bit_length = usize::try_from(
                sample_byte_length
                    .checked_mul(8)
                    .ok_or(CommonProofPrivateCoinSamplingCatalogError::CountOverflow)?,
            )
            .map_err(|_| CommonProofPrivateCoinSamplingCatalogError::CountOverflow)?;
            let candidate_space = BigUint::from(1_u8) << sample_bit_length;
            let rejected_candidate_count = &candidate_space % BigUint::from(modulus);
            if rejected_candidate_count == BigUint::default() {
                continue;
            }
            let operation_denominator = candidate_space.pow(maximum_candidate_draws_per_output);
            let operation_numerator = rejected_candidate_count
                .pow(maximum_candidate_draws_per_output)
                * BigUint::from(output_count);
            if union_numerator == BigUint::default() {
                union_numerator = operation_numerator;
                union_denominator = operation_denominator;
            } else if union_denominator == operation_denominator {
                union_numerator += operation_numerator;
            } else {
                union_numerator = &union_numerator * &operation_denominator
                    + operation_numerator * &union_denominator;
                union_denominator *= operation_denominator;
            }
        }
        union_numerator *= BigUint::from(application_multiplicity);
        Ok(CommonProofPrivateCoinExhaustionUnionBound {
            numerator: union_numerator,
            denominator: union_denominator,
        })
    }
}

/// Test-only transparent delegate that records successful calls made through
/// the production private-coin trait seam.
#[cfg(test)]
pub(crate) struct RecordingCommonProofPrivateCoinSource<'source, Source> {
    source: &'source mut Source,
    observed_catalog: &'source mut CommonProofPrivateCoinSamplingCatalog,
}

#[cfg(test)]
impl<'source, Source> RecordingCommonProofPrivateCoinSource<'source, Source> {
    pub(crate) fn new(
        source: &'source mut Source,
        observed_catalog: &'source mut CommonProofPrivateCoinSamplingCatalog,
    ) -> Self {
        Self {
            source,
            observed_catalog,
        }
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecordingCommonProofPrivateCoinError<SourceError> {
    Source(SourceError),
    Catalog(CommonProofPrivateCoinSamplingCatalogError),
}

#[cfg(test)]
impl<Source> CommonProofPrivateCoinSource for RecordingCommonProofPrivateCoinSource<'_, Source>
where
    Source: CommonProofPrivateCoinSource,
{
    type Error = RecordingCommonProofPrivateCoinError<Source::Error>;

    fn sample_modulo(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        let sampled = self
            .source
            .sample_modulo(coordinate, modulus, maximum_candidate_draws_per_output)
            .map_err(RecordingCommonProofPrivateCoinError::Source)?;
        self.observed_catalog
            .record_modulo_sample(coordinate, modulus, maximum_candidate_draws_per_output)
            .map_err(RecordingCommonProofPrivateCoinError::Catalog)?;
        Ok(sampled)
    }

    fn fill_raw_bytes(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.source
            .fill_raw_bytes(coordinate, destination)
            .map_err(RecordingCommonProofPrivateCoinError::Source)?;
        self.observed_catalog
            .record_raw_byte_fill(coordinate, destination.len())
            .map_err(RecordingCommonProofPrivateCoinError::Catalog)
    }

    fn replay_modulo_samples(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        destination: &mut [u64],
    ) -> Result<(), Self::Error> {
        self.source
            .replay_modulo_samples(
                coordinate,
                modulus,
                maximum_candidate_draws_per_output,
                destination,
            )
            .map_err(RecordingCommonProofPrivateCoinError::Source)
    }
}

/// Private proof coins that can expose their exact authenticated stream
/// positions at a completed commitment boundary. The cursors contain no coin
/// bytes and are used only to authenticate exact checkpoint resumption.
pub(crate) trait CheckpointableCommonProofPrivateCoinSource:
    CommonProofPrivateCoinSource
{
    fn checkpoint_cursor_manifest(
        &self,
    ) -> Result<Vec<u8>, CommonProofCheckpointCursorManifestError>;
}

pub(crate) const COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC: [u8; 8] = *b"SLCPCM05";
const COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_VERSION: u16 = 5;
const COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH: usize = 15;
const COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH: usize = 98;
const COMMON_PROOF_CHECKPOINT_CURSOR_STATE_DIGEST_BYTE_LENGTH: usize = 64;
const COMMON_PROOF_CHECKPOINT_CURSOR_STATE_RECORD_BYTE_LENGTH: u64 = 16;
const COMMON_PROOF_CHECKPOINT_CURSOR_STATE_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/checkpoint-private-cursor-state/v1";
pub(crate) const MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH: u32 = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct CommonProofCheckpointCursorManifestRequirement {
    logical_cursor_count: u32,
    canonical_manifest_byte_ceiling: u32,
    retained_cursor_state_byte_ceiling: u64,
    encoding_workspace_byte_ceiling: u32,
    pending_manifest_resident_byte_ceiling: u32,
    restore_workspace_byte_ceiling: u64,
    peak_additional_resident_byte_ceiling: u64,
    peak_copied_buffer_byte_length: u32,
}

#[cfg(test)]
impl CommonProofCheckpointCursorManifestRequirement {
    pub(crate) const fn logical_cursor_count(self) -> u32 {
        self.logical_cursor_count
    }

    pub(crate) const fn canonical_manifest_byte_ceiling(self) -> u32 {
        self.canonical_manifest_byte_ceiling
    }

    pub(crate) const fn pending_manifest_resident_byte_ceiling(self) -> u32 {
        self.pending_manifest_resident_byte_ceiling
    }

    pub(crate) const fn peak_copied_buffer_byte_length(self) -> u32 {
        self.peak_copied_buffer_byte_length
    }

    pub(crate) const fn fits_absolute_bounds(self) -> bool {
        self.canonical_manifest_byte_ceiling
            <= MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH
            && self.pending_manifest_resident_byte_ceiling()
                <= MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH
            && self.peak_copied_buffer_byte_length()
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

/// Exact compact checkpoint commitment for one common-proof coin source. The
/// source-wide family, derivation binding and attempt identifier occur once,
/// including before the first cursor is consumed. A two-pass encoder validates
/// canonical order and streams every coordinate and exact cursor position into
/// one domain-separated digest. Checkpoint resume deterministically replays the
/// live private-coin source and recomputes this commitment; it does not rebuild
/// private streams from producer-supplied cursor bytes.
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
    let mut logical_cursor_count = 0_u32;
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
        previous_coordinate = Some(coordinate);
    }
    let byte_length = COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
        .checked_add(COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH)
        .and_then(|length| {
            length.checked_add(COMMON_PROOF_CHECKPOINT_CURSOR_STATE_DIGEST_BYTE_LENGTH)
        })
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    if byte_length
        > usize::try_from(MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH)
            .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?
    {
        return Err(CommonProofCheckpointCursorManifestError::OutsideSupportedProfile);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(byte_length)
        .map_err(|_| CommonProofCheckpointCursorManifestError::AllocationLimitExceeded)?;
    output.extend_from_slice(&COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_MAGIC);
    output.extend_from_slice(&COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_VERSION.to_le_bytes());
    output.push(1);
    output.extend_from_slice(&logical_cursor_count.to_le_bytes());
    output.extend_from_slice(&family_schema_identifier.to_le_bytes());
    output.extend_from_slice(&derivation_binding_hash.into_bytes());
    output.extend_from_slice(&stream_attempt_identifier);

    let cursor_state_byte_length = u64::from(logical_cursor_count)
        .checked_mul(COMMON_PROOF_CHECKPOINT_CURSOR_STATE_RECORD_BYTE_LENGTH)
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let mut cursor_state_hasher =
        StreamingHash512::new(COMMON_PROOF_CHECKPOINT_CURSOR_STATE_HASH_DOMAIN, 1);
    cursor_state_hasher.begin_part(cursor_state_byte_length);
    let mut encoded_logical_cursor_count = 0_u32;
    let mut previous_encoded_coordinate = None;
    for (coordinate, cursor) in ordered_cursors {
        validate_manifest_cursor_identity(
            family_schema_identifier,
            derivation_binding_hash,
            stream_attempt_identifier,
            coordinate,
            cursor,
        )?;
        if previous_encoded_coordinate.is_some_and(|previous| coordinate <= previous) {
            return Err(CommonProofCheckpointCursorManifestError::CoordinateOrder);
        }
        encoded_logical_cursor_count = encoded_logical_cursor_count
            .checked_add(1)
            .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
        cursor_state_hasher.absorb_raw(&coordinate.purpose_class().to_le_bytes());
        cursor_state_hasher.absorb_raw(&coordinate.ordinal().to_le_bytes());
        cursor_state_hasher.absorb_raw(&cursor.next_counter().to_le_bytes());
        cursor_state_hasher.absorb_raw(
            &encode_cursor_offset(cursor.next_unread_bit_offset_in_buffered_block())?.to_le_bytes(),
        );
        previous_encoded_coordinate = Some(coordinate);
    }
    output.extend_from_slice(&cursor_state_hasher.finalize());
    if encoded_logical_cursor_count != logical_cursor_count || output.len() != byte_length {
        return Err(CommonProofCheckpointCursorManifestError::NonCanonicalEncoding);
    }
    Ok(output)
}

#[cfg(test)]
pub(crate) fn common_proof_checkpoint_cursor_manifest_requirement(
    capacity: CommonProofPrivateCoinCoordinateCapacity,
) -> Result<CommonProofCheckpointCursorManifestRequirement, CommonProofCheckpointCursorManifestError>
{
    let maximum_logical_cursor_count = capacity
        .logical_cursor_count()
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    common_proof_checkpoint_cursor_manifest_requirement_from_capacity(
        capacity,
        maximum_logical_cursor_count,
    )
}

#[cfg(test)]
fn common_proof_checkpoint_cursor_manifest_requirement_from_capacity(
    capacity: CommonProofPrivateCoinCoordinateCapacity,
    maximum_logical_cursor_count: u32,
) -> Result<CommonProofCheckpointCursorManifestRequirement, CommonProofCheckpointCursorManifestError>
{
    let maximum_canonical_byte_length = common_proof_checkpoint_cursor_manifest_byte_length()?;
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
                        u64::try_from(core::mem::size_of::<
                            Option<RetainedCommonProofPrivateCoinOperation>,
                        >())
                        .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?,
                    )
                    .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?,
            )
            .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let encoding_workspace_byte_ceiling = u32::try_from(
        core::mem::size_of::<StreamingHash512>()
            .checked_add(core::mem::size_of::<Option<CommonProofPrivateCoinCoordinate>>())
            .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?,
    )
    .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)?;
    let peak_additional_resident_byte_ceiling = retained_cursor_state_byte_ceiling
        .checked_add(u64::from(maximum_canonical_byte_length))
        .and_then(|bytes| bytes.checked_add(u64::from(encoding_workspace_byte_ceiling)))
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    Ok(CommonProofCheckpointCursorManifestRequirement {
        logical_cursor_count: maximum_logical_cursor_count,
        canonical_manifest_byte_ceiling: maximum_canonical_byte_length,
        retained_cursor_state_byte_ceiling,
        encoding_workspace_byte_ceiling,
        pending_manifest_resident_byte_ceiling: maximum_canonical_byte_length,
        restore_workspace_byte_ceiling: retained_cursor_state_byte_ceiling,
        peak_additional_resident_byte_ceiling,
        peak_copied_buffer_byte_length: maximum_canonical_byte_length,
    })
}

#[cfg(test)]
fn common_proof_checkpoint_cursor_manifest_byte_length()
-> Result<u32, CommonProofCheckpointCursorManifestError> {
    u32::try_from(
        COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
            .checked_add(COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH)
            .and_then(|length| {
                length.checked_add(COMMON_PROOF_CHECKPOINT_CURSOR_STATE_DIGEST_BYTE_LENGTH)
            })
            .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?,
    )
    .map_err(|_| CommonProofCheckpointCursorManifestError::CountOverflow)
}

#[cfg(test)]
pub(crate) fn common_proof_checkpoint_cursor_manifest_requirement_for_variant(
    variant: &RelationPlanVariant,
) -> Result<CommonProofCheckpointCursorManifestRequirement, CommonProofCheckpointCursorManifestError>
{
    let capacity = CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(variant)?;
    let maximum_logical_cursor_count = capacity
        .logical_cursor_count()
        .ok_or(CommonProofCheckpointCursorManifestError::CountOverflow)?;
    common_proof_checkpoint_cursor_manifest_requirement_from_capacity(
        capacity,
        maximum_logical_cursor_count,
    )
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
    CountOverflow,
    CoordinateOutsidePlan,
    OperationMismatch,
    ReplayCursorMismatch,
}

impl From<FoundationSchemaError> for PrivateRandomnessCommonProofCoinError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Custody(error)
    }
}

#[derive(Clone, Copy)]
enum RetainedCommonProofPrivateCoinOperation {
    ModuloSamples {
        cursor: PrivateRandomCursor,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        output_count: u64,
    },
    RawByteFill {
        cursor: PrivateRandomCursor,
        byte_count: u64,
    },
}

impl RetainedCommonProofPrivateCoinOperation {
    const fn cursor(self) -> PrivateRandomCursor {
        match self {
            Self::ModuloSamples { cursor, .. } | Self::RawByteFill { cursor, .. } => cursor,
        }
    }
}

#[derive(Clone)]
struct RetainedCommonProofPrivateCoinOperations {
    trace_masks: Box<[Option<RetainedCommonProofPrivateCoinOperation>]>,
    telescoping_masks: Box<[Option<RetainedCommonProofPrivateCoinOperation>]>,
    opening_masks: Box<[Option<RetainedCommonProofPrivateCoinOperation>]>,
    proof_salt: Option<Option<RetainedCommonProofPrivateCoinOperation>>,
    hiding_argument: Option<Option<RetainedCommonProofPrivateCoinOperation>>,
}

impl RetainedCommonProofPrivateCoinOperations {
    fn new(
        capacity: CommonProofPrivateCoinCoordinateCapacity,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        fn allocate_slots(
            count: u32,
        ) -> Result<
            Box<[Option<RetainedCommonProofPrivateCoinOperation>]>,
            PrivateRandomnessCommonProofCoinError,
        > {
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
            hiding_argument: capacity.includes_hiding_argument.then_some(None),
        })
    }

    fn slot(
        &self,
        coordinate: CommonProofPrivateCoinCoordinate,
    ) -> Option<&Option<RetainedCommonProofPrivateCoinOperation>> {
        let ordinal = usize::try_from(coordinate.ordinal()).ok()?;
        match coordinate.purpose_class() {
            1 => self.trace_masks.get(ordinal),
            2 => self.telescoping_masks.get(ordinal),
            3 => self.opening_masks.get(ordinal),
            PRIVATE_PROOF_SALT_PURPOSE if ordinal == 0 => self.proof_salt.as_ref(),
            4 if ordinal == 0 => self.hiding_argument.as_ref(),
            _ => None,
        }
    }

    fn slot_mut(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
    ) -> Option<&mut Option<RetainedCommonProofPrivateCoinOperation>> {
        let ordinal = usize::try_from(coordinate.ordinal()).ok()?;
        match coordinate.purpose_class() {
            1 => self.trace_masks.get_mut(ordinal),
            2 => self.telescoping_masks.get_mut(ordinal),
            3 => self.opening_masks.get_mut(ordinal),
            PRIVATE_PROOF_SALT_PURPOSE if ordinal == 0 => self.proof_salt.as_mut(),
            4 if ordinal == 0 => self.hiding_argument.as_mut(),
            _ => None,
        }
    }

    fn cursors(
        &self,
    ) -> impl Iterator<Item = (CommonProofPrivateCoinCoordinate, PrivateRandomCursor)> + Clone + '_
    {
        fn coordinate_cursor(
            purpose_class: u16,
            (ordinal, operation): (usize, &Option<RetainedCommonProofPrivateCoinOperation>),
        ) -> Option<(CommonProofPrivateCoinCoordinate, PrivateRandomCursor)> {
            Some((
                CommonProofPrivateCoinCoordinate {
                    purpose_class,
                    ordinal: u32::try_from(ordinal).ok()?,
                },
                operation.as_ref().copied()?.cursor(),
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
            .chain(self.hiding_argument.iter().filter_map(|operation| {
                operation.map(|operation| {
                    (
                        CommonProofPrivateCoinCoordinate::hiding_argument(),
                        operation.cursor(),
                    )
                })
            }))
            .chain(self.proof_salt.iter().filter_map(|operation| {
                operation.map(|operation| {
                    (
                        CommonProofPrivateCoinCoordinate::proof_salt(),
                        operation.cursor(),
                    )
                })
            }))
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
    retained_operations: RetainedCommonProofPrivateCoinOperations,
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
            retained_operations: RetainedCommonProofPrivateCoinOperations::new(
                coordinate_capacity,
            )?,
        })
    }

    pub(crate) fn cursors(
        &self,
    ) -> impl Iterator<Item = (CommonProofPrivateCoinCoordinate, PrivateRandomCursor)> + Clone + '_
    {
        self.retained_operations.cursors()
    }

    fn stream_identity_for_coordinate(
        &self,
        coordinate: CommonProofPrivateCoinCoordinate,
    ) -> Result<
        (
            PrivateRandomnessDomain,
            Hash512,
            Option<RetainedCommonProofPrivateCoinOperation>,
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
        let retained_operation = *self
            .retained_operations
            .slot(coordinate)
            .ok_or(PrivateRandomnessCommonProofCoinError::CoordinateOutsidePlan)?;
        Ok((domain, derivation_context_hash, retained_operation))
    }

    fn retain_operation(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        operation: RetainedCommonProofPrivateCoinOperation,
    ) -> Result<(), PrivateRandomnessCommonProofCoinError> {
        *self
            .retained_operations
            .slot_mut(coordinate)
            .ok_or(PrivateRandomnessCommonProofCoinError::CoordinateOutsidePlan)? = Some(operation);
        Ok(())
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
        let (domain, derivation_context_hash, retained_operation) =
            self.stream_identity_for_coordinate(coordinate)?;
        let (retained_cursor, output_count) = match retained_operation {
            Some(RetainedCommonProofPrivateCoinOperation::ModuloSamples {
                cursor,
                modulus: retained_modulus,
                maximum_candidate_draws_per_output: retained_draw_ceiling,
                output_count,
            }) if retained_modulus == modulus
                && retained_draw_ceiling == maximum_candidate_draws_per_output =>
            {
                (Some(cursor), output_count)
            }
            None => (None, 0),
            Some(_) => return Err(PrivateRandomnessCommonProofCoinError::OperationMismatch),
        };
        let next_output_count = output_count
            .checked_add(1)
            .ok_or(PrivateRandomnessCommonProofCoinError::CountOverflow)?;
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
        self.retain_operation(
            coordinate,
            RetainedCommonProofPrivateCoinOperation::ModuloSamples {
                cursor,
                modulus,
                maximum_candidate_draws_per_output,
                output_count: next_output_count,
            },
        )?;
        result
    }

    fn fill_raw_bytes(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let (domain, derivation_context_hash, retained_operation) =
            self.stream_identity_for_coordinate(coordinate)?;
        let (retained_cursor, byte_count) = match retained_operation {
            Some(RetainedCommonProofPrivateCoinOperation::RawByteFill { cursor, byte_count }) => {
                (Some(cursor), byte_count)
            }
            None => (None, 0),
            Some(_) => return Err(PrivateRandomnessCommonProofCoinError::OperationMismatch),
        };
        let next_byte_count = byte_count
            .checked_add(
                u64::try_from(destination.len())
                    .map_err(|_| PrivateRandomnessCommonProofCoinError::CountOverflow)?,
            )
            .ok_or(PrivateRandomnessCommonProofCoinError::CountOverflow)?;
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
        self.retain_operation(
            coordinate,
            RetainedCommonProofPrivateCoinOperation::RawByteFill {
                cursor,
                byte_count: next_byte_count,
            },
        )?;
        result
    }

    fn replay_modulo_samples(
        &mut self,
        coordinate: CommonProofPrivateCoinCoordinate,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
        destination: &mut [u64],
    ) -> Result<(), Self::Error> {
        let (domain, derivation_context_hash, retained_operation) =
            self.stream_identity_for_coordinate(coordinate)?;
        let Some(RetainedCommonProofPrivateCoinOperation::ModuloSamples {
            cursor: expected_cursor,
            modulus: retained_modulus,
            maximum_candidate_draws_per_output: retained_draw_ceiling,
            output_count,
        }) = retained_operation
        else {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayCursorMismatch);
        };
        if retained_modulus != modulus
            || retained_draw_ceiling != maximum_candidate_draws_per_output
            || usize::try_from(output_count).ok() != Some(destination.len())
        {
            return Err(PrivateRandomnessCommonProofCoinError::OperationMismatch);
        }
        let mut stream = self.action_private_randomness.begin_stream(
            domain,
            derivation_context_hash,
            self.attempt_identifier,
        )?;
        for sampled in destination {
            *sampled = stream
                .sample_modulo(modulus, maximum_candidate_draws_per_output)
                .map_err(PrivateRandomnessCommonProofCoinError::Custody)?;
        }
        if stream.cursor() != expected_cursor {
            return Err(PrivateRandomnessCommonProofCoinError::ReplayCursorMismatch);
        }
        Ok(())
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

    fn production_private_coin_source(
        trace_mask_count: u32,
    ) -> PrivateRandomnessCommonProofCoinSource {
        let action_private_randomness = Rc::new(
            ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
                [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
            ))
            .derive(ActionRandomnessDerivationInput::new(
                Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
                ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
            ))
            .expect("the fixed action randomness derives"),
        );
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            Some(0),
            None,
            None,
        )
        .expect("the same-secret family has a canonical proof slot");
        let proof_coin_input = PersistentProofCoinInput::new(
            application_slot,
            Hash512::from_bytes([0x66; Hash512::BYTE_LENGTH]),
        )
        .expect("the same-secret persistent proof input is canonical");
        let mut witness_binding = action_private_randomness
            .begin_persistent_proof_witness_coin_binding(&proof_coin_input)
            .expect("the same-secret witness binding starts");
        witness_binding
            .absorb_canonical_bytes(b"sealed-lattice/test/common-proof-private-coin-replay/v1")
            .expect("the replay-test witness domain is absorbed");
        witness_binding
            .absorb_canonical_bytes(b"exact private coordinate replay witness")
            .expect("the replay-test witness bytes are absorbed");
        let attempt_identifier = witness_binding
            .finish()
            .expect("the same-secret persistent proof attempt derives");
        PrivateRandomnessCommonProofCoinSource::new(
            action_private_randomness,
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            Hash512::from_bytes([0x71; Hash512::BYTE_LENGTH]),
            attempt_identifier,
            CommonProofPrivateCoinCoordinateCapacity::for_test(trace_mask_count, 0, 0, true, true),
        )
        .expect("the production private-coin source accepts the fixed test authority")
    }

    struct SuccessfulRecordingDelegate {
        next_sample: u64,
        replay_sample_start: u64,
        fill_byte: u8,
    }

    impl CommonProofPrivateCoinSource for SuccessfulRecordingDelegate {
        type Error = core::convert::Infallible;

        fn sample_modulo(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            _maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            let sampled = self.next_sample % modulus;
            self.next_sample = self.next_sample.wrapping_add(1);
            Ok(sampled)
        }

        fn fill_raw_bytes(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            destination.fill(self.fill_byte);
            self.fill_byte = self.fill_byte.wrapping_add(1);
            Ok(())
        }

        fn replay_modulo_samples(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            _maximum_candidate_draws_per_output: u32,
            destination: &mut [u64],
        ) -> Result<(), Self::Error> {
            for (sample_ordinal, sampled) in destination.iter_mut().enumerate() {
                *sampled = self.replay_sample_start.wrapping_add(sample_ordinal as u64) % modulus;
            }
            Ok(())
        }
    }

    #[test]
    fn recording_private_coin_source_delegates_and_aggregates_typed_operations() {
        let trace_coordinate =
            CommonProofPrivateCoinCoordinate::mask(1, 7).expect("trace-mask coordinate is valid");
        let salt_coordinate = CommonProofPrivateCoinCoordinate::proof_salt();
        let mut delegate = SuccessfulRecordingDelegate {
            next_sample: 19,
            replay_sample_start: 19,
            fill_byte: 0xa5,
        };
        let mut observed = CommonProofPrivateCoinSamplingCatalog::default();
        {
            let mut recording =
                RecordingCommonProofPrivateCoinSource::new(&mut delegate, &mut observed);

            assert_eq!(recording.sample_modulo(trace_coordinate, 17, 64), Ok(2));
            assert_eq!(recording.sample_modulo(trace_coordinate, 17, 64), Ok(3));
            assert_eq!(recording.sample_modulo(trace_coordinate, 17, 64), Ok(4));
            let mut replayed = [0_u64; 3];
            assert_eq!(
                recording.replay_modulo_samples(trace_coordinate, 17, 64, &mut replayed),
                Ok(())
            );
            assert_eq!(replayed, [2, 3, 4]);
            let mut raw_bytes = [0_u8; 11];
            assert_eq!(
                recording.fill_raw_bytes(salt_coordinate, &mut raw_bytes),
                Ok(())
            );
            assert_eq!(raw_bytes, [0xa5; 11]);
            let mut empty_raw_bytes = [];
            assert_eq!(
                recording.fill_raw_bytes(salt_coordinate, &mut empty_raw_bytes),
                Ok(())
            );
        }

        assert_eq!(delegate.fill_byte, 0xa7);
        assert_eq!(observed.entry_count(), 2);
        assert_eq!(
            observed.entry(trace_coordinate),
            Some(CommonProofPrivateCoinSamplingOperation::ModuloSamples {
                modulus: 17,
                maximum_candidate_draws_per_output: 64,
                output_count: 3,
            })
        );
        let raw_operation = observed
            .entry(salt_coordinate)
            .expect("raw fill was recorded");
        assert_eq!(
            raw_operation,
            CommonProofPrivateCoinSamplingOperation::RawByteFill { byte_count: 11 }
        );
        assert_eq!(raw_operation.maximum_candidate_draws_per_output(), None);

        let exhaustion = observed
            .exhaustion_union_bound(10)
            .expect("derive exact recording-source exhaustion");
        assert_eq!(exhaustion.numerator(), &BigUint::from(30_u8));
        assert_eq!(exhaustion.denominator(), &BigUint::from(256_u16).pow(64));
        assert!(exhaustion.is_at_most_inverse_power_of_two(128));
    }

    #[test]
    fn production_private_coin_replay_round_trips_without_advancing_custody() {
        let coordinate =
            CommonProofPrivateCoinCoordinate::mask(1, 0).expect("trace-mask coordinate is valid");
        let mut source = production_private_coin_source(1);
        let original = (0..37)
            .map(|_| {
                source
                    .sample_modulo(
                        coordinate,
                        PROOF_BASE_FIELD_MODULUS,
                        crate::foundation::SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                    )
                    .expect("the production sampler yields one canonical field coordinate")
            })
            .collect::<Vec<_>>();
        let manifest_before_replay = source
            .checkpoint_cursor_manifest()
            .expect("the consumed coordinate has a canonical checkpoint manifest");
        let cursors_before_replay = source.cursors().collect::<Vec<_>>();

        let mut replayed = vec![0_u64; original.len()];
        source
            .replay_modulo_samples(
                coordinate,
                PROOF_BASE_FIELD_MODULUS,
                crate::foundation::SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
                &mut replayed,
            )
            .expect("the exact private coordinate operation replays");

        assert_eq!(replayed, original);
        assert_eq!(source.cursors().collect::<Vec<_>>(), cursors_before_replay);
        assert_eq!(
            source
                .checkpoint_cursor_manifest()
                .expect("replay preserves the checkpoint manifest"),
            manifest_before_replay
        );
    }

    #[test]
    fn production_private_coin_replay_refuses_unconsumed_or_changed_operations() {
        let coordinate =
            CommonProofPrivateCoinCoordinate::mask(1, 0).expect("trace-mask coordinate is valid");
        let outside_plan_coordinate =
            CommonProofPrivateCoinCoordinate::mask(1, 1).expect("trace-mask coordinate is valid");
        let draw_ceiling =
            crate::foundation::SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT;
        let mut source = production_private_coin_source(1);
        let mut one_sample = [0_u64; 1];
        assert_eq!(
            source.replay_modulo_samples(
                coordinate,
                PROOF_BASE_FIELD_MODULUS,
                draw_ceiling,
                &mut one_sample,
            ),
            Err(PrivateRandomnessCommonProofCoinError::ReplayCursorMismatch)
        );
        assert_eq!(
            source.replay_modulo_samples(
                outside_plan_coordinate,
                PROOF_BASE_FIELD_MODULUS,
                draw_ceiling,
                &mut one_sample,
            ),
            Err(PrivateRandomnessCommonProofCoinError::CoordinateOutsidePlan)
        );

        let original = (0..19)
            .map(|_| {
                source
                    .sample_modulo(coordinate, PROOF_BASE_FIELD_MODULUS, draw_ceiling)
                    .expect("the original private operation samples")
            })
            .collect::<Vec<_>>();
        let manifest = source
            .checkpoint_cursor_manifest()
            .expect("the original operation has a canonical manifest");
        let mut wrong_length = vec![0_u64; original.len() - 1];
        assert_eq!(
            source.replay_modulo_samples(
                coordinate,
                PROOF_BASE_FIELD_MODULUS,
                draw_ceiling,
                &mut wrong_length,
            ),
            Err(PrivateRandomnessCommonProofCoinError::OperationMismatch)
        );
        let mut right_length = vec![0_u64; original.len()];
        assert_eq!(
            source.replay_modulo_samples(
                coordinate,
                PROOF_BASE_FIELD_MODULUS - 2,
                draw_ceiling,
                &mut right_length,
            ),
            Err(PrivateRandomnessCommonProofCoinError::OperationMismatch)
        );
        assert_eq!(
            source.replay_modulo_samples(
                coordinate,
                PROOF_BASE_FIELD_MODULUS,
                draw_ceiling + 1,
                &mut right_length,
            ),
            Err(PrivateRandomnessCommonProofCoinError::OperationMismatch)
        );
        source
            .replay_modulo_samples(
                coordinate,
                PROOF_BASE_FIELD_MODULUS,
                draw_ceiling,
                &mut right_length,
            )
            .expect("failed altered replays do not disturb the exact replay");
        assert_eq!(right_length, original);
        assert_eq!(
            source
                .checkpoint_cursor_manifest()
                .expect("refused replay attempts preserve the manifest"),
            manifest
        );
    }

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
                + COMMON_PROOF_CHECKPOINT_CURSOR_STATE_DIGEST_BYTE_LENGTH
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
            u32::from_le_bytes(
                encoded[11..15]
                    .try_into()
                    .expect("logical-cursor-count bytes")
            ),
            0
        );
        assert_eq!(
            u16::from_le_bytes(encoded[15..17].try_into().expect("family bytes")),
            family_schema_identifier
        );
        assert_eq!(&encoded[17..81], &derivation_binding_hash);
        assert_eq!(&encoded[81..113], &stream_attempt_identifier);
    }

    #[test]
    fn checkpoint_cursor_manifest_commits_all_five_private_coin_purposes() {
        let family_schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let derivation_binding_hash = Hash512::from_bytes([0x6d_u8; Hash512::BYTE_LENGTH]);
        let stream_attempt_identifier = [0x37_u8; 32];
        let ordered_coordinates = [
            CommonProofPrivateCoinCoordinate::mask(1, 0).expect("trace-mask coordinate"),
            CommonProofPrivateCoinCoordinate::mask(1, 1).expect("trace-mask coordinate"),
            CommonProofPrivateCoinCoordinate::mask(2, 0).expect("telescoping-mask coordinate"),
            CommonProofPrivateCoinCoordinate::mask(3, 0).expect("opening-mask coordinate"),
            CommonProofPrivateCoinCoordinate::hiding_argument(),
            CommonProofPrivateCoinCoordinate::proof_salt(),
        ];
        let ordered_cursors = ordered_coordinates
            .into_iter()
            .enumerate()
            .map(|(coordinate_ordinal, coordinate)| {
                let next_counter = if coordinate_ordinal == 1 { 11 } else { 7 };
                let buffered_offset = (coordinate_ordinal == 1).then_some(19);
                let cursor = PrivateRandomCursor::new(
                    family_schema_identifier,
                    coordinate.purpose_class(),
                    common_proof_private_coin_coordinate_derivation_context_hash(
                        derivation_binding_hash,
                        coordinate,
                    ),
                    stream_attempt_identifier,
                    next_counter,
                    buffered_offset,
                )
                .expect("test cursor identity and state are valid");
                (coordinate, cursor)
            })
            .collect::<Vec<_>>();

        let encoded = encode_common_proof_checkpoint_cursor_manifest(
            family_schema_identifier,
            derivation_binding_hash,
            stream_attempt_identifier,
            ordered_cursors.clone(),
        )
        .expect("all five supported purpose runs have a canonical manifest");

        assert_eq!(
            u32::from_le_bytes(
                encoded[11..15]
                    .try_into()
                    .expect("logical-cursor-count bytes")
            ),
            6
        );
        assert_eq!(
            encoded.len(),
            COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
                + COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH
                + COMMON_PROOF_CHECKPOINT_CURSOR_STATE_DIGEST_BYTE_LENGTH
        );

        let requirement = common_proof_checkpoint_cursor_manifest_requirement(
            CommonProofPrivateCoinCoordinateCapacity::for_test(2, 1, 1, true, true),
        )
        .expect("all five private-coin purpose runs fit the bounded workspace");
        assert_eq!(requirement.logical_cursor_count(), 6);
        assert_eq!(
            usize::try_from(requirement.canonical_manifest_byte_ceiling())
                .expect("manifest ceiling fits usize"),
            encoded.len()
        );
        assert!(requirement.fits_absolute_bounds());

        let mut changed_cursor_state = ordered_cursors.clone();
        let changed_coordinate = changed_cursor_state[1].0;
        changed_cursor_state[1].1 = PrivateRandomCursor::new(
            family_schema_identifier,
            changed_coordinate.purpose_class(),
            common_proof_private_coin_coordinate_derivation_context_hash(
                derivation_binding_hash,
                changed_coordinate,
            ),
            stream_attempt_identifier,
            12,
            Some(19),
        )
        .expect("changed test cursor identity and state are valid");
        let changed_state_manifest = encode_common_proof_checkpoint_cursor_manifest(
            family_schema_identifier,
            derivation_binding_hash,
            stream_attempt_identifier,
            changed_cursor_state,
        )
        .expect("a changed exact cursor state remains canonical");
        assert_ne!(
            encoded, changed_state_manifest,
            "the manifest commitment must bind every exact cursor position"
        );

        let mut noncanonical_order = ordered_cursors;
        noncanonical_order.swap(4, 5);
        assert_eq!(
            encode_common_proof_checkpoint_cursor_manifest(
                family_schema_identifier,
                derivation_binding_hash,
                stream_attempt_identifier,
                noncanonical_order,
            ),
            Err(CommonProofCheckpointCursorManifestError::CoordinateOrder)
        );
    }

    #[test]
    fn zero_cursor_capacity_accounts_for_the_unconditional_identity() {
        let requirement = common_proof_checkpoint_cursor_manifest_requirement(
            CommonProofPrivateCoinCoordinateCapacity::for_test(0, 0, 0, false, false),
        )
        .expect("zero cursor capacity remains representable");

        assert_eq!(requirement.logical_cursor_count(), 0);
        assert_eq!(
            requirement.canonical_manifest_byte_ceiling(),
            u32::try_from(
                COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_PREFIX_BYTE_LENGTH
                    + COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_IDENTITY_BYTE_LENGTH
                    + COMMON_PROOF_CHECKPOINT_CURSOR_STATE_DIGEST_BYTE_LENGTH
            )
            .expect("manifest constants fit u32")
        );
        assert!(requirement.fits_absolute_bounds());
    }
}
