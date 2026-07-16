//! Production prover primitives for the suite-bound common transparent proof.
//!
//! This module contains no native-only path.  Large oracle, Merkle, quotient,
//! and FRI material can be persisted through `external_memory`; proof bytes are
//! emitted to a bounded sink and never need to exist as one allocation.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    ActionPrivateRandomness, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, FoundationSchemaError, Hash512, PRIVATE_PROOF_SALT_PURPOSE,
    PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
    PrivateRandomnessStream, ProofObjectHeader, hash_foundation_tuple_512,
};
use crate::hashing::StreamingHash512;

use super::external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
};
use super::external_polynomial::{
    ExternalPolynomialValue, ExternalPolynomialVector, ExternalStockhamTransform,
    ExternalStockhamTransformDirection, ExternalStockhamTransformError,
    ExternalStockhamTransformPlan, ExternalStockhamTransformProgress,
    map_external_polynomial_plan_error, read_external_polynomial_value,
};
use super::relation_plan::{
    BoundTreeConstructionKind, ProofPrivacyMode, RelationColumnDescriptor, RelationColumnOrigin,
    RelationColumnValueType, RelationIntegerLiftCoefficient,
    RelationIntegerLiftComponentDescriptor, RelationIntegerLiftConvolutionKind,
    RelationIntegerLiftConvolutionProductDescriptor, RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    RelationIntegerLiftLinearTermDescriptor,
    RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor, RelationMaskDescriptor,
    RelationMaskKind, RelationMaskTargetClass, RelationOpeningClaimDescriptor,
    RelationOpeningSourceClass, RelationTreeDescriptor,
};
use super::{
    CommonProofChallenge, CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber,
    CommonProofTranscript, CommonProofTranscriptSchedule, CompiledRelationPlan,
    CompleteProofTreeCatalog, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, PROOF_CHALLENGE_EXTENSION_DEGREE,
    ProofBaseFieldElement, ProofBodyError, ProofChallengeExtensionElement, ProofEvaluationDomain,
    ProofFieldError, ProofLeafVisibility, ProofMerkleError, ProofMerkleTreeContext,
    ProofOraclePhasePairLeaf, ProofPolynomialError, ProofProfileError, ProofTreeCatalogEntry,
    ProofTreeCatalogInput, ProofTreeCatalogSource, ProofTreeRole, ProofTreeValue,
    RelationApplicationChallengeAssignment, RelationPlanCheckContext, RelationPlanError,
    RelationPlanVariant, RelationProofTreeInput, StatementOwnedProofTreeInput,
    SuiteModulusReference, TranscriptError, ValidatedRelationPlanArtifact,
    build_complete_proof_tree_catalog, divide_extension_polynomial_by_linear_in_place,
    evaluate_extension_at, extension_polynomial_degree, fold_extension_evaluations,
    fold_extension_evaluations_in_place,
};

const PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER: u16 = 0x0107;
const PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER: u16 = 0x0108;
const PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER: u16 = 0x0106;
const SCHEMA_VERSION: u16 = 1;
const PROOF_SECRET_LEAF_SALT_BYTE_LENGTH: usize = 48;
const PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER: u16 = 0x0105;
const PROOF_MERKLE_NODE_HASH_DOMAIN: &str = "sealed-lattice/proof/merkle/node/v1";
const HASH_BYTE_LENGTH: usize = 64;
const AUTHENTICATION_NODE_CANONICAL_BYTE_LENGTH: usize = 102;
const CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/checkpoint-committed-state/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofProverError {
    CanonicalEncoding,
    InvalidInput,
    InvalidColumn,
    InvalidMask,
    InvalidQuotient,
    InvalidOpening,
    InvalidFriLayer,
    InvalidTree,
    CountOverflow,
    AllocationLimitExceeded,
    ResidentMemoryLimitExceeded,
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
    Merkle(ProofMerkleError),
    Relation(RelationPlanError),
}

impl From<ProofFieldError> for CommonProofProverError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for CommonProofProverError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl From<ProofMerkleError> for CommonProofProverError {
    fn from(error: ProofMerkleError) -> Self {
        Self::Merkle(error)
    }
}

impl From<RelationPlanError> for CommonProofProverError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

/// Private proof coins are supplied by Rust private-randomness custody.  Each
/// purpose is an independent stream beginning at counter zero; implementations
/// must delegate to `PrivateRandomnessStream::sample_modulo` and
/// `PrivateRandomnessStream::fill_bytes`, not to a transcript or host PRNG.
pub(crate) trait CommonProofPrivateCoinSource {
    type Error;

    fn sample_modulo(
        &mut self,
        purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error>;

    fn fill_raw_bytes(&mut self, purpose: u16, destination: &mut [u8]) -> Result<(), Self::Error>;
}

/// Private proof coins that can expose their exact authenticated stream
/// positions at a completed commitment boundary. The cursors contain no coin
/// bytes and are never used to initialize deterministic-prefix replay: replay
/// always starts each stream at counter zero and compares the resulting
/// cursors with the authenticated checkpoint manifest.
pub(crate) trait CheckpointableCommonProofPrivateCoinSource:
    CommonProofPrivateCoinSource
{
    fn checkpoint_cursors(&self) -> Vec<PrivateRandomCursor>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrivateRandomnessCommonProofCoinError {
    Custody(FoundationSchemaError),
    DuplicateCursorPurpose,
}

impl From<FoundationSchemaError> for PrivateRandomnessCommonProofCoinError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Custody(error)
    }
}

/// Owns the independent private-randomness cursor for every purpose consumed by
/// one common-proof attempt.  The caller must authenticate exported cursors as
/// part of the containing attempt record before resuming them.
pub(crate) struct PrivateRandomnessCommonProofCoinSource<'action> {
    action_private_randomness: &'action ActionPrivateRandomness,
    family_schema_identifier: u16,
    derivation_context_hash: Hash512,
    attempt_identifier: PrivateRandomnessAttemptIdentifier,
    cursors_by_purpose: BTreeMap<u16, PrivateRandomCursor>,
}

impl<'action> PrivateRandomnessCommonProofCoinSource<'action> {
    pub(crate) fn new(
        action_private_randomness: &'action ActionPrivateRandomness,
        family_schema_identifier: u16,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        let salt_domain = PrivateRandomnessDomain::from_assigned_pair(
            family_schema_identifier,
            PRIVATE_PROOF_SALT_PURPOSE,
        )?;
        drop(action_private_randomness.begin_stream(
            salt_domain,
            derivation_context_hash,
            attempt_identifier,
        )?);
        Ok(Self {
            action_private_randomness,
            family_schema_identifier,
            derivation_context_hash,
            attempt_identifier,
            cursors_by_purpose: BTreeMap::new(),
        })
    }

    pub(crate) fn resume(
        action_private_randomness: &'action ActionPrivateRandomness,
        family_schema_identifier: u16,
        derivation_context_hash: Hash512,
        attempt_identifier: PrivateRandomnessAttemptIdentifier,
        authenticated_cursors: impl IntoIterator<Item = PrivateRandomCursor>,
    ) -> Result<Self, PrivateRandomnessCommonProofCoinError> {
        let mut source = Self::new(
            action_private_randomness,
            family_schema_identifier,
            derivation_context_hash,
            attempt_identifier,
        )?;
        for cursor in authenticated_cursors {
            let purpose = cursor.purpose();
            let domain =
                PrivateRandomnessDomain::from_assigned_pair(family_schema_identifier, purpose)?;
            drop(action_private_randomness.resume_stream(
                domain,
                derivation_context_hash,
                attempt_identifier,
                cursor,
            )?);
            if source.cursors_by_purpose.insert(purpose, cursor).is_some() {
                return Err(PrivateRandomnessCommonProofCoinError::DuplicateCursorPurpose);
            }
        }
        Ok(source)
    }

    pub(crate) fn cursors(&self) -> impl Iterator<Item = PrivateRandomCursor> + '_ {
        self.cursors_by_purpose.values().copied()
    }

    fn stream_for_purpose(
        &self,
        purpose: u16,
    ) -> Result<PrivateRandomnessStream<'action>, PrivateRandomnessCommonProofCoinError> {
        let domain =
            PrivateRandomnessDomain::from_assigned_pair(self.family_schema_identifier, purpose)?;
        let action_private_randomness: &'action ActionPrivateRandomness =
            self.action_private_randomness;
        match self.cursors_by_purpose.get(&purpose).copied() {
            Some(cursor) => Ok(action_private_randomness.resume_stream(
                domain,
                self.derivation_context_hash,
                self.attempt_identifier,
                cursor,
            )?),
            None => Ok(action_private_randomness.begin_stream(
                domain,
                self.derivation_context_hash,
                self.attempt_identifier,
            )?),
        }
    }

    fn retain_stream_cursor(&mut self, stream: PrivateRandomnessStream<'action>) {
        let cursor = stream.cursor();
        drop(stream);
        self.cursors_by_purpose.insert(cursor.purpose(), cursor);
    }
}

impl CommonProofPrivateCoinSource for PrivateRandomnessCommonProofCoinSource<'_> {
    type Error = PrivateRandomnessCommonProofCoinError;

    fn sample_modulo(
        &mut self,
        purpose: u16,
        modulus: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        let mut stream = self.stream_for_purpose(purpose)?;
        let result = stream
            .sample_modulo(modulus, maximum_candidate_draws_per_output)
            .map_err(PrivateRandomnessCommonProofCoinError::Custody);
        self.retain_stream_cursor(stream);
        result
    }

    fn fill_raw_bytes(&mut self, purpose: u16, destination: &mut [u8]) -> Result<(), Self::Error> {
        let mut stream = self.stream_for_purpose(purpose)?;
        let result = stream
            .fill_bytes(destination)
            .map_err(PrivateRandomnessCommonProofCoinError::Custody);
        self.retain_stream_cursor(stream);
        result
    }
}

impl CheckpointableCommonProofPrivateCoinSource for PrivateRandomnessCommonProofCoinSource<'_> {
    fn checkpoint_cursors(&self) -> Vec<PrivateRandomCursor> {
        self.cursors().collect()
    }
}

/// One plan-addressed source polynomial.  Coefficients are constant-first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofSourcePolynomial {
    Base(Vec<ProofBaseFieldElement>),
    Extension(Vec<ProofChallengeExtensionElement>),
}

impl CommonProofSourcePolynomial {
    pub(crate) fn value_type(&self) -> RelationColumnValueType {
        match self {
            Self::Base(_) => RelationColumnValueType::BaseField,
            Self::Extension(_) => RelationColumnValueType::ChallengeExtension,
        }
    }

    pub(crate) fn coefficient_count(&self) -> usize {
        match self {
            Self::Base(coefficients) => coefficients.len(),
            Self::Extension(coefficients) => coefficients.len(),
        }
    }

    pub(crate) fn evaluate_at(
        &self,
        point: ProofChallengeExtensionElement,
    ) -> ProofChallengeExtensionElement {
        match self {
            Self::Base(coefficients) => coefficients.iter().rev().fold(
                ProofChallengeExtensionElement::ZERO,
                |accumulated, coefficient| {
                    accumulated
                        .multiply(point)
                        .add(ProofChallengeExtensionElement::from_base(*coefficient))
                },
            ),
            Self::Extension(coefficients) => evaluate_extension_at(coefficients, point),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofColumnEvaluations {
    Base(Vec<ProofBaseFieldElement>),
    Extension(Vec<ProofChallengeExtensionElement>),
}

impl CommonProofColumnEvaluations {
    fn extension_value(
        &self,
        position: usize,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        match self {
            Self::Base(values) => values
                .get(position)
                .copied()
                .map(ProofChallengeExtensionElement::from_base),
            Self::Extension(values) => values.get(position).copied(),
        }
        .ok_or(CommonProofProverError::InvalidColumn)
    }

    fn tree_value(&self, position: usize) -> Result<ProofTreeValue, CommonProofProverError> {
        match self {
            Self::Base(values) => values.get(position).copied().map(ProofTreeValue::Base),
            Self::Extension(values) => values.get(position).copied().map(ProofTreeValue::Extension),
        }
        .ok_or(CommonProofProverError::InvalidColumn)
    }
}

/// Evaluates one homogeneous tree row at a time.  Callers should materialize
/// and discard each relation tree before evaluating the next one; peak working
/// memory is therefore one tree row rather than the complete oracle catalog.
pub(crate) fn evaluate_common_proof_tree_columns(
    evaluation_domain: &ProofEvaluationDomain,
    columns: &[CommonProofSourcePolynomial],
    ordered_column_ordinals: &[u32],
) -> Result<Vec<CommonProofColumnEvaluations>, CommonProofProverError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofProverError::InvalidTree);
    }
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(ordered_column_ordinals.len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut expected_value_type = None;
    for column_ordinal in ordered_column_ordinals {
        let column = columns
            .get(
                usize::try_from(*column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let value_type = column.value_type();
        match expected_value_type {
            None => expected_value_type = Some(value_type),
            Some(expected) if expected == value_type => {}
            Some(_) => return Err(CommonProofProverError::InvalidTree),
        }
        evaluations.push(match column {
            CommonProofSourcePolynomial::Base(coefficients) => CommonProofColumnEvaluations::Base(
                evaluation_domain.evaluate_base_polynomial(coefficients)?,
            ),
            CommonProofSourcePolynomial::Extension(coefficients) => {
                CommonProofColumnEvaluations::Extension(
                    evaluation_domain.evaluate_extension_polynomial(coefficients)?,
                )
            }
        });
    }
    Ok(evaluations)
}

/// Evaluates a base tree while auxiliary columns are intentionally absent.
/// The requested ordinals must all have been constructed in the
/// pre-challenge phase.
pub(crate) fn evaluate_pre_challenge_common_proof_tree_columns(
    evaluation_domain: &ProofEvaluationDomain,
    columns: &CommonProofPreChallengeRelationColumns,
    ordered_column_ordinals: &[u32],
) -> Result<Vec<CommonProofColumnEvaluations>, CommonProofProverError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofProverError::InvalidTree);
    }
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(ordered_column_ordinals.len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut expected_value_type = None;
    for column_ordinal in ordered_column_ordinals {
        let column = columns
            .column(*column_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let value_type = column.value_type();
        match expected_value_type {
            None => expected_value_type = Some(value_type),
            Some(expected) if expected == value_type => {}
            Some(_) => return Err(CommonProofProverError::InvalidTree),
        }
        evaluations.push(match column {
            CommonProofSourcePolynomial::Base(coefficients) => CommonProofColumnEvaluations::Base(
                evaluation_domain.evaluate_base_polynomial(coefficients)?,
            ),
            CommonProofSourcePolynomial::Extension(coefficients) => {
                CommonProofColumnEvaluations::Extension(
                    evaluation_domain.evaluate_extension_polynomial(coefficients)?,
                )
            }
        });
    }
    Ok(evaluations)
}

/// Samples one uniform base-field polynomial of degree below the exclusive
/// bound from its plan-assigned private stream.
pub(crate) fn sample_private_base_polynomial<Coins>(
    coins: &mut Coins,
    purpose: u16,
    degree_bound_exclusive: u64,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let coefficient_count = usize::try_from(degree_bound_exclusive)
        .map_err(|_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow))?;
    if coefficient_count == 0 {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    let mut coefficients = Vec::new();
    coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
        })?;
    for _ in 0..coefficient_count {
        let coordinate = coins
            .sample_modulo(
                purpose,
                super::PROOF_BASE_FIELD_MODULUS,
                maximum_candidate_draws_per_output,
            )
            .map_err(CommonProofPrivateCoinError::CoinSource)?;
        coefficients.push(
            ProofBaseFieldElement::from_canonical(coordinate)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
    }
    Ok(coefficients)
}

/// Samples one uniform challenge-extension polynomial.  Coordinates are read
/// in constant-first extension basis order for each increasing coefficient.
pub(crate) fn sample_private_extension_polynomial<Coins>(
    coins: &mut Coins,
    purpose: u16,
    degree_bound_exclusive: u64,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let coefficient_count = usize::try_from(degree_bound_exclusive)
        .map_err(|_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow))?;
    if coefficient_count == 0 {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    let mut coefficients = Vec::new();
    coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
        })?;
    for _ in 0..coefficient_count {
        let mut coordinates = [0_u64; super::PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            *coordinate = coins
                .sample_modulo(
                    purpose,
                    super::PROOF_BASE_FIELD_MODULUS,
                    maximum_candidate_draws_per_output,
                )
                .map_err(CommonProofPrivateCoinError::CoinSource)?;
        }
        coefficients.push(
            ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
    }
    Ok(coefficients)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofPrivateCoinError<CoinError> {
    Prover(CommonProofProverError),
    CoinSource(CoinError),
}

/// Applies `witness + (X^H - 1) mask` without changing coefficient order.
pub(crate) fn apply_trace_mask(
    witness: CommonProofSourcePolynomial,
    trace_domain_size: u64,
    mask: CommonProofSourcePolynomial,
) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
    let trace_domain_size =
        usize::try_from(trace_domain_size).map_err(|_| CommonProofProverError::CountOverflow)?;
    if trace_domain_size == 0 || mask.coefficient_count() == 0 {
        return Err(CommonProofProverError::InvalidMask);
    }
    match (witness, mask) {
        (CommonProofSourcePolynomial::Base(witness), CommonProofSourcePolynomial::Base(mask)) => {
            let output_length = trace_domain_size
                .checked_add(mask.len())
                .ok_or(CommonProofProverError::CountOverflow)?;
            let mut output = vec![ProofBaseFieldElement::ZERO; output_length.max(witness.len())];
            for (destination, coefficient) in output.iter_mut().zip(witness) {
                *destination = destination.add(coefficient);
            }
            for (mask_ordinal, coefficient) in mask.into_iter().enumerate() {
                output[mask_ordinal] = output[mask_ordinal].subtract(coefficient);
                let shifted_ordinal = trace_domain_size
                    .checked_add(mask_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                output[shifted_ordinal] = output[shifted_ordinal].add(coefficient);
            }
            trim_base_polynomial(&mut output);
            Ok(CommonProofSourcePolynomial::Base(output))
        }
        (
            CommonProofSourcePolynomial::Extension(witness),
            CommonProofSourcePolynomial::Extension(mask),
        ) => {
            let output_length = trace_domain_size
                .checked_add(mask.len())
                .ok_or(CommonProofProverError::CountOverflow)?;
            let mut output =
                vec![ProofChallengeExtensionElement::ZERO; output_length.max(witness.len())];
            for (destination, coefficient) in output.iter_mut().zip(witness) {
                *destination = destination.add(coefficient);
            }
            for (mask_ordinal, coefficient) in mask.into_iter().enumerate() {
                output[mask_ordinal] = output[mask_ordinal].subtract(coefficient);
                let shifted_ordinal = trace_domain_size
                    .checked_add(mask_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                output[shifted_ordinal] = output[shifted_ordinal].add(coefficient);
            }
            trim_extension_polynomial(&mut output);
            Ok(CommonProofSourcePolynomial::Extension(output))
        }
        _ => Err(CommonProofProverError::InvalidMask),
    }
}

/// Columns constructed before the common transcript releases the complete
/// non-native challenge vector.  Auxiliary-tree entries remain absent, so a
/// caller cannot accidentally commit a challenge-dependent column early.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofPreChallengeRelationColumns {
    columns: Vec<Option<CommonProofSourcePolynomial>>,
}

impl CommonProofPreChallengeRelationColumns {
    pub(crate) fn column(&self, column_ordinal: u32) -> Option<&CommonProofSourcePolynomial> {
        self.columns
            .get(usize::try_from(column_ordinal).ok()?)
            .and_then(Option::as_ref)
    }
}

/// Constructs and masks every column committed before the application
/// challenges.  Callers provide only the plan's genuine pre-challenge input
/// columns.  Reversed multiplier columns are derived here from their checked
/// source descriptors; supplying either a reversed or an auxiliary column is
/// rejected.
pub(crate) fn construct_pre_challenge_relation_columns<Coins>(
    variant: &RelationPlanVariant,
    mut provided_columns: BTreeMap<u32, CommonProofSourcePolynomial>,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<CommonProofPreChallengeRelationColumns, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let tree_roles =
        proof_created_tree_roles_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let (reversed_columns_by_source, integer_lift_auxiliary_columns) =
        integer_lift_derived_columns(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let reversed_columns = reversed_columns_by_source
        .values()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut columns = vec![None; variant.ordered_columns().len()];

    for (column_index, (column_slot, descriptor)) in columns
        .iter_mut()
        .zip(variant.ordered_columns())
        .enumerate()
    {
        let column_ordinal = u32::try_from(column_index).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let is_auxiliary_tree_column =
            tree_roles.get(&column_ordinal) == Some(&ProofTreeRole::AuxiliaryOracle);
        if reversed_columns.contains(&column_ordinal)
            || integer_lift_auxiliary_columns.contains(&column_ordinal)
            || is_auxiliary_tree_column
        {
            if provided_columns.contains_key(&column_ordinal) {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            continue;
        }
        let source = provided_columns.remove(&column_ordinal).ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
        })?;
        validate_source_column(descriptor, &source, variant.trace_domain_size())
            .map_err(CommonProofPrivateCoinError::Prover)?;
        *column_slot = Some(source);
    }
    if !provided_columns.is_empty() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }

    let trace_domain =
        ProofEvaluationDomain::new_subgroup(usize::try_from(variant.trace_domain_size()).map_err(
            |_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow),
        )?)
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    for (source_ordinal, reversed_ordinal) in reversed_columns_by_source {
        let source = columns
            .get(usize::try_from(source_ordinal).map_err(|_| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let mut reversed_rows =
            base_trace_rows(source, trace_domain).map_err(CommonProofPrivateCoinError::Prover)?;
        reversed_rows.reverse();
        let reversed_polynomial = CommonProofSourcePolynomial::Base(
            trace_domain
                .interpolate_base_polynomial(&reversed_rows)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
        let destination = columns
            .get_mut(usize::try_from(reversed_ordinal).map_err(|_| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        if destination.replace(reversed_polynomial).is_some() {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
    }

    let trace_masks =
        trace_masks_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
        let column_ordinal = u32::try_from(column_index).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        match tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::BaseOracle) => {
                let source = columns[column_index].take().ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
                })?;
                columns[column_index] = Some(mask_relation_column(
                    variant,
                    descriptor,
                    trace_masks.get(&column_ordinal).copied(),
                    source,
                    coins,
                    maximum_candidate_draws_per_output,
                )?);
            }
            Some(ProofTreeRole::AuxiliaryOracle) => {
                if columns[column_index].is_some() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
            Some(_) => {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            }
            None => {
                if columns[column_index].is_none() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
        }
    }
    Ok(CommonProofPreChallengeRelationColumns { columns })
}

/// Synthesizes every auxiliary column from the checked integer-lift
/// descriptors and the complete transcript challenge vector, then applies the
/// plan-assigned masks.  The function handles every batch in one call so no
/// prover message can be inserted between consecutive theta or alpha draws.
pub(crate) fn construct_post_challenge_relation_columns<Coins>(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    mut pre_challenge_columns: CommonProofPreChallengeRelationColumns,
    application_challenges: &[RelationApplicationChallengeAssignment],
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<CommonProofSourcePolynomial>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    if pre_challenge_columns.columns.len() != variant.ordered_columns().len() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let tree_roles =
        proof_created_tree_roles_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let (_, integer_lift_auxiliary_columns) =
        integer_lift_derived_columns(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let trace_masks =
        trace_masks_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;

    for column_index in 0..variant.ordered_columns().len() {
        let column_ordinal = u32::try_from(column_index).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        match tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::AuxiliaryOracle) => {
                if !integer_lift_auxiliary_columns.contains(&column_ordinal)
                    || pre_challenge_columns.columns[column_index].is_some()
                {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
            _ => {
                if pre_challenge_columns.columns[column_index].is_none() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
        }
    }

    let trace_domain =
        ProofEvaluationDomain::new_subgroup(usize::try_from(variant.trace_domain_size()).map_err(
            |_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow),
        )?)
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let auxiliary_trace_row_context = AuxiliaryTraceRowInsertionContext::new(
        variant,
        &tree_roles,
        &trace_masks,
        trace_domain,
        maximum_candidate_draws_per_output,
    );
    let mut trace_rows_by_column = BTreeMap::<u32, Vec<ProofBaseFieldElement>>::new();

    for batch in variant.ordered_integer_lift_batches() {
        let theta = integer_lift_theta(
            variant,
            context,
            batch.modulus_reference(),
            batch.challenge_ordinal(),
            application_challenges,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;

        for permutation in &batch.ordered_negacyclic_automorphism_permutations {
            synthesize_negacyclic_automorphism_permutation(
                variant,
                permutation,
                theta,
                &tree_roles,
                &trace_masks,
                &mut pre_challenge_columns.columns,
                &mut trace_rows_by_column,
                trace_domain,
                coins,
                maximum_candidate_draws_per_output,
            )?;
        }

        for binding in &batch.ordered_reversed_column_bindings {
            ensure_base_trace_rows(
                &pre_challenge_columns.columns,
                &mut trace_rows_by_column,
                binding.source_column_ordinal,
                trace_domain,
            )
            .map_err(CommonProofPrivateCoinError::Prover)?;
            ensure_base_trace_rows(
                &pre_challenge_columns.columns,
                &mut trace_rows_by_column,
                binding.reversed_column_ordinal,
                trace_domain,
            )
            .map_err(CommonProofPrivateCoinError::Prover)?;
            let source_rows = trace_rows_by_column
                .get(&binding.source_column_ordinal)
                .ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
                })?;
            let reversed_rows = trace_rows_by_column
                .get(&binding.reversed_column_ordinal)
                .ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
                })?;
            let prefix_rows = prefix_evaluation_rows(source_rows, theta);
            let suffix_rows = suffix_evaluation_rows(reversed_rows, theta);
            insert_auxiliary_trace_rows(
                auxiliary_trace_row_context,
                &mut pre_challenge_columns.columns,
                binding.source_prefix_evaluation_column_ordinal,
                prefix_rows,
                coins,
            )?;
            insert_auxiliary_trace_rows(
                auxiliary_trace_row_context,
                &mut pre_challenge_columns.columns,
                binding.reversed_suffix_evaluation_column_ordinal,
                suffix_rows,
                coins,
            )?;
        }

        for component in &batch.ordered_components {
            let linear_rows = integer_lift_linear_evaluation_rows(
                context,
                batch.modulus_reference(),
                component,
                theta,
                &pre_challenge_columns.columns,
                &mut trace_rows_by_column,
                trace_domain,
            )
            .map_err(CommonProofPrivateCoinError::Prover)?;
            let mut product_rows = vec![ProofBaseFieldElement::ZERO; trace_domain.size()];

            for product in &component.ordered_convolution_products {
                synthesize_convolution_product(
                    variant,
                    product,
                    theta,
                    &tree_roles,
                    &trace_masks,
                    &mut pre_challenge_columns.columns,
                    &mut trace_rows_by_column,
                    &mut product_rows,
                    trace_domain,
                    coins,
                    maximum_candidate_draws_per_output,
                )?;
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                synthesize_full_ring_product(
                    variant,
                    product,
                    theta,
                    &tree_roles,
                    &trace_masks,
                    &mut pre_challenge_columns.columns,
                    &mut trace_rows_by_column,
                    &mut product_rows,
                    trace_domain,
                    coins,
                    maximum_candidate_draws_per_output,
                )?;
            }

            let accumulator_rows = product_accumulator_rows(&product_rows);
            insert_auxiliary_trace_rows(
                auxiliary_trace_row_context,
                &mut pre_challenge_columns.columns,
                component.linear_evaluation_column_ordinal,
                linear_rows,
                coins,
            )?;
            insert_auxiliary_trace_rows(
                auxiliary_trace_row_context,
                &mut pre_challenge_columns.columns,
                component.product_accumulator_column_ordinal,
                accumulator_rows,
                coins,
            )?;
        }
    }

    let columns = pre_challenge_columns
        .columns
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
        })?;
    validate_column_polynomials(variant, &columns).map_err(CommonProofPrivateCoinError::Prover)?;
    Ok(columns)
}

fn proof_created_tree_roles_by_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, ProofTreeRole>, CommonProofProverError> {
    let mut roles = BTreeMap::new();
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::ProofCreated {
            proof_tree_role,
            ordered_column_ordinals,
        } = tree
        else {
            continue;
        };
        let role = match *proof_tree_role {
            value if value == ProofTreeRole::BaseOracle as u16 => ProofTreeRole::BaseOracle,
            value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                ProofTreeRole::AuxiliaryOracle
            }
            _ => return Err(CommonProofProverError::InvalidTree),
        };
        for column_ordinal in ordered_column_ordinals {
            if roles.insert(*column_ordinal, role).is_some() {
                return Err(CommonProofProverError::InvalidTree);
            }
        }
    }
    Ok(roles)
}

fn integer_lift_derived_columns(
    variant: &RelationPlanVariant,
) -> Result<(BTreeMap<u32, u32>, BTreeSet<u32>), CommonProofProverError> {
    let mut reversed_columns_by_source = BTreeMap::new();
    let mut source_by_reversed_column = BTreeMap::new();
    let mut auxiliary_columns = BTreeSet::new();
    for batch in variant.ordered_integer_lift_batches() {
        for permutation in &batch.ordered_negacyclic_automorphism_permutations {
            auxiliary_columns.extend([
                permutation.source_product_before_column_ordinal,
                permutation.source_low_product_column_ordinal,
                permutation.target_product_before_column_ordinal,
                permutation.target_low_product_column_ordinal,
            ]);
        }
        for binding in &batch.ordered_reversed_column_bindings {
            match reversed_columns_by_source.insert(
                binding.source_column_ordinal,
                binding.reversed_column_ordinal,
            ) {
                Some(existing) if existing != binding.reversed_column_ordinal => {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                _ => {}
            }
            match source_by_reversed_column.insert(
                binding.reversed_column_ordinal,
                binding.source_column_ordinal,
            ) {
                Some(existing) if existing != binding.source_column_ordinal => {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                _ => {}
            }
            auxiliary_columns.extend([
                binding.source_prefix_evaluation_column_ordinal,
                binding.reversed_suffix_evaluation_column_ordinal,
            ]);
        }
        for component in &batch.ordered_components {
            auxiliary_columns.extend([
                component.linear_evaluation_column_ordinal,
                component.product_accumulator_column_ordinal,
            ]);
            for product in &component.ordered_convolution_products {
                auxiliary_columns.extend([
                    product.suffix_evaluation_column_ordinal,
                    product.reversed_transpose_column_ordinal,
                ]);
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                auxiliary_columns.extend([
                    product.multiplicand_low_suffix_evaluation_column_ordinal,
                    product.multiplicand_high_suffix_evaluation_column_ordinal,
                    product.reversed_multiplier_low_transpose_column_ordinal,
                    product.reversed_multiplier_high_transpose_column_ordinal,
                ]);
            }
        }
    }
    if source_by_reversed_column
        .keys()
        .any(|column| auxiliary_columns.contains(column))
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok((reversed_columns_by_source, auxiliary_columns))
}

fn trace_masks_by_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, RelationMaskDescriptor>, CommonProofProverError> {
    let mut masks = BTreeMap::new();
    for mask in variant.ordered_masks().iter().copied().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::Trace
            && mask.target_class() == RelationMaskTargetClass::Column
    }) {
        if masks.insert(mask.target_ordinal(), mask).is_some() {
            return Err(CommonProofProverError::InvalidMask);
        }
    }
    Ok(masks)
}

fn validate_source_column(
    descriptor: &RelationColumnDescriptor,
    source: &CommonProofSourcePolynomial,
    trace_domain_size: u64,
) -> Result<(), CommonProofProverError> {
    // Prover and verifier-sequence inputs are trace polynomials before any
    // proof-owned mask is applied, so their canonical interpolation contains
    // at most one coefficient per trace row. Bound-tree columns are different:
    // their authenticated source already includes the persistent trace mask.
    // Preserve that mask by accepting the complete descriptor-owned degree
    // bound instead of truncating it to the trace domain.
    let maximum_coefficient_count = match descriptor.origin() {
        RelationColumnOrigin::BoundTree { .. } => descriptor.source_degree_bound_exclusive(),
        RelationColumnOrigin::VerifierSequence { .. } | RelationColumnOrigin::Prover => descriptor
            .source_degree_bound_exclusive()
            .min(trace_domain_size),
    };
    if descriptor.value_type() != source.value_type()
        || source.coefficient_count() == 0
        || source.coefficient_count()
            > usize::try_from(maximum_coefficient_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(())
}

fn mask_relation_column<Coins>(
    variant: &RelationPlanVariant,
    descriptor: &RelationColumnDescriptor,
    mask: Option<RelationMaskDescriptor>,
    source: CommonProofSourcePolynomial,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<CommonProofSourcePolynomial, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let constructed = match (descriptor.origin(), mask) {
        (RelationColumnOrigin::Prover, Some(mask))
            if variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing =>
        {
            let sampled = match source.value_type() {
                RelationColumnValueType::BaseField => {
                    CommonProofSourcePolynomial::Base(sample_private_base_polynomial(
                        coins,
                        mask.mask_purpose(),
                        mask.mask_degree_bound_exclusive(),
                        maximum_candidate_draws_per_output,
                    )?)
                }
                RelationColumnValueType::ChallengeExtension => {
                    CommonProofSourcePolynomial::Extension(sample_private_extension_polynomial(
                        coins,
                        mask.mask_purpose(),
                        mask.mask_degree_bound_exclusive(),
                        maximum_candidate_draws_per_output,
                    )?)
                }
            };
            apply_trace_mask(source, variant.trace_domain_size(), sampled)
                .map_err(CommonProofPrivateCoinError::Prover)?
        }
        (RelationColumnOrigin::Prover, _) => {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidMask,
            ));
        }
        (_, None) => source,
        (_, Some(_)) => {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidMask,
            ));
        }
    };
    if constructed.coefficient_count()
        > usize::try_from(descriptor.source_degree_bound_exclusive()).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    Ok(constructed)
}

fn base_trace_rows(
    source: &CommonProofSourcePolynomial,
    trace_domain: ProofEvaluationDomain,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofProverError> {
    let CommonProofSourcePolynomial::Base(coefficients) = source else {
        return Err(CommonProofProverError::InvalidColumn);
    };
    let mut reduced_coefficients = vec![ProofBaseFieldElement::ZERO; trace_domain.size()];
    for (coefficient_ordinal, coefficient) in coefficients.iter().copied().enumerate() {
        let reduced_ordinal = coefficient_ordinal % trace_domain.size();
        reduced_coefficients[reduced_ordinal] =
            reduced_coefficients[reduced_ordinal].add(coefficient);
    }
    trace_domain
        .evaluate_base_polynomial(&reduced_coefficients)
        .map_err(CommonProofProverError::from)
}

fn ensure_base_trace_rows(
    columns: &[Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    column_ordinal: u32,
    trace_domain: ProofEvaluationDomain,
) -> Result<(), CommonProofProverError> {
    if trace_rows_by_column.contains_key(&column_ordinal) {
        return Ok(());
    }
    let source = columns
        .get(usize::try_from(column_ordinal).map_err(|_| CommonProofProverError::CountOverflow)?)
        .and_then(Option::as_ref)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let rows = base_trace_rows(source, trace_domain)?;
    trace_rows_by_column.insert(column_ordinal, rows);
    Ok(())
}

fn integer_lift_theta(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    modulus_reference: SuiteModulusReference,
    challenge_ordinal: u16,
    assignments: &[RelationApplicationChallengeAssignment],
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let modulus_ordinal = variant
        .non_native_modulus_ordinal(modulus_reference)
        .map_err(CommonProofProverError::from)?;
    let expected_challenge = CommonProofChallenge::Theta { modulus_ordinal };
    let mut matching = assignments.iter().copied().filter(|assignment| {
        assignment.challenge() == expected_challenge
            && assignment.repetition_ordinal() == challenge_ordinal
    });
    let value = matching
        .next()
        .map(RelationApplicationChallengeAssignment::value)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    if matching.next().is_some() || value >= context.resolved_modulus(modulus_reference)? {
        return Err(CommonProofProverError::InvalidColumn);
    }
    ProofBaseFieldElement::from_canonical(value).map_err(CommonProofProverError::from)
}

#[allow(clippy::too_many_arguments)]
fn synthesize_negacyclic_automorphism_permutation<Coins>(
    variant: &RelationPlanVariant,
    descriptor: &RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
    theta: ProofBaseFieldElement,
    tree_roles: &BTreeMap<u32, ProofTreeRole>,
    trace_masks: &BTreeMap<u32, RelationMaskDescriptor>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    trace_domain: ProofEvaluationDomain,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let input_columns = [
        descriptor.source_low_column_ordinal,
        descriptor.source_high_column_ordinal,
        descriptor.target_low_column_ordinal,
        descriptor.target_high_column_ordinal,
        descriptor.mapped_low_position_column_ordinal,
        descriptor.low_negation_bit_column_ordinal,
        descriptor.mapped_high_position_column_ordinal,
        descriptor.high_negation_bit_column_ordinal,
        descriptor.target_low_position_column_ordinal,
        descriptor.target_high_position_column_ordinal,
    ];
    for column_ordinal in input_columns {
        ensure_base_trace_rows(columns, trace_rows_by_column, column_ordinal, trace_domain)
            .map_err(CommonProofPrivateCoinError::Prover)?;
    }
    let rows = |column_ordinal| {
        trace_rows_by_column.get(&column_ordinal).ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
        })
    };
    let source_low_rows = rows(descriptor.source_low_column_ordinal)?;
    let source_high_rows = rows(descriptor.source_high_column_ordinal)?;
    let target_low_rows = rows(descriptor.target_low_column_ordinal)?;
    let target_high_rows = rows(descriptor.target_high_column_ordinal)?;
    let mapped_low_position_rows = rows(descriptor.mapped_low_position_column_ordinal)?;
    let low_negation_bit_rows = rows(descriptor.low_negation_bit_column_ordinal)?;
    let mapped_high_position_rows = rows(descriptor.mapped_high_position_column_ordinal)?;
    let high_negation_bit_rows = rows(descriptor.high_negation_bit_column_ordinal)?;
    let target_low_position_rows = rows(descriptor.target_low_position_column_ordinal)?;
    let target_high_position_rows = rows(descriptor.target_high_position_column_ordinal)?;
    let row_count = trace_domain.size();
    if input_columns.iter().any(|column_ordinal| {
        trace_rows_by_column
            .get(column_ordinal)
            .is_none_or(|column_rows| column_rows.len() != row_count)
    }) {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let one = ProofBaseFieldElement::ONE;
    let two = one.add(one);
    let three = two.add(one);
    let encoded_source = |position: ProofBaseFieldElement,
                          negation_bit: ProofBaseFieldElement,
                          value: ProofBaseFieldElement| {
        position
            .multiply(three)
            .add(one)
            .add(value.subtract(negation_bit.multiply(two).multiply(value)))
    };
    let encoded_target = |position: ProofBaseFieldElement, value: ProofBaseFieldElement| {
        position.multiply(three).add(one).add(value)
    };
    let mut source_before_rows = Vec::with_capacity(row_count);
    let mut source_low_product_rows = Vec::with_capacity(row_count);
    let mut target_before_rows = Vec::with_capacity(row_count);
    let mut target_low_product_rows = Vec::with_capacity(row_count);
    let mut source_before = one;
    let mut target_before = one;
    for row_ordinal in 0..row_count {
        source_before_rows.push(source_before);
        target_before_rows.push(target_before);
        let source_low_factor = theta.subtract(encoded_source(
            mapped_low_position_rows[row_ordinal],
            low_negation_bit_rows[row_ordinal],
            source_low_rows[row_ordinal],
        ));
        let source_low_product = source_before.multiply(source_low_factor);
        source_low_product_rows.push(source_low_product);
        let target_low_factor = theta.subtract(encoded_target(
            target_low_position_rows[row_ordinal],
            target_low_rows[row_ordinal],
        ));
        let target_low_product = target_before.multiply(target_low_factor);
        target_low_product_rows.push(target_low_product);
        let source_high_factor = theta.subtract(encoded_source(
            mapped_high_position_rows[row_ordinal],
            high_negation_bit_rows[row_ordinal],
            source_high_rows[row_ordinal],
        ));
        let target_high_factor = theta.subtract(encoded_target(
            target_high_position_rows[row_ordinal],
            target_high_rows[row_ordinal],
        ));
        source_before = source_low_product.multiply(source_high_factor);
        target_before = target_low_product.multiply(target_high_factor);
    }
    let auxiliary_trace_row_context = AuxiliaryTraceRowInsertionContext::new(
        variant,
        tree_roles,
        trace_masks,
        trace_domain,
        maximum_candidate_draws_per_output,
    );
    for (column_ordinal, synthesized_rows) in [
        (
            descriptor.source_product_before_column_ordinal,
            source_before_rows,
        ),
        (
            descriptor.source_low_product_column_ordinal,
            source_low_product_rows,
        ),
        (
            descriptor.target_product_before_column_ordinal,
            target_before_rows,
        ),
        (
            descriptor.target_low_product_column_ordinal,
            target_low_product_rows,
        ),
    ] {
        insert_auxiliary_trace_rows(
            auxiliary_trace_row_context,
            columns,
            column_ordinal,
            synthesized_rows,
            coins,
        )?;
    }
    Ok(())
}

fn prefix_evaluation_rows(
    source_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Vec<ProofBaseFieldElement> {
    let mut output = Vec::with_capacity(source_rows.len());
    let mut prefix = ProofBaseFieldElement::ZERO;
    for source in source_rows {
        prefix = prefix.multiply(theta).add(*source);
        output.push(prefix);
    }
    output
}

fn suffix_evaluation_rows(
    source_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Vec<ProofBaseFieldElement> {
    let mut output = vec![ProofBaseFieldElement::ZERO; source_rows.len()];
    let mut suffix = ProofBaseFieldElement::ZERO;
    for row_ordinal in (0..source_rows.len()).rev() {
        suffix = source_rows[row_ordinal].add(theta.multiply(suffix));
        output[row_ordinal] = suffix;
    }
    output
}

#[derive(Clone, Copy)]
struct AuxiliaryTraceRowInsertionContext<'relation> {
    variant: &'relation RelationPlanVariant,
    tree_roles: &'relation BTreeMap<u32, ProofTreeRole>,
    trace_masks: &'relation BTreeMap<u32, RelationMaskDescriptor>,
    trace_domain: ProofEvaluationDomain,
    maximum_candidate_draws_per_output: u32,
}

impl<'relation> AuxiliaryTraceRowInsertionContext<'relation> {
    fn new(
        variant: &'relation RelationPlanVariant,
        tree_roles: &'relation BTreeMap<u32, ProofTreeRole>,
        trace_masks: &'relation BTreeMap<u32, RelationMaskDescriptor>,
        trace_domain: ProofEvaluationDomain,
        maximum_candidate_draws_per_output: u32,
    ) -> Self {
        Self {
            variant,
            tree_roles,
            trace_masks,
            trace_domain,
            maximum_candidate_draws_per_output,
        }
    }
}

fn insert_auxiliary_trace_rows<Coins>(
    context: AuxiliaryTraceRowInsertionContext<'_>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    column_ordinal: u32,
    rows: Vec<ProofBaseFieldElement>,
    coins: &mut Coins,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    if rows.len() != context.trace_domain.size()
        || context.tree_roles.get(&column_ordinal) != Some(&ProofTreeRole::AuxiliaryOracle)
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let column_index = usize::try_from(column_ordinal)
        .map_err(|_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow))?;
    let descriptor = context
        .variant
        .ordered_columns()
        .get(column_index)
        .ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
        })?;
    if descriptor.value_type() != RelationColumnValueType::BaseField
        || columns
            .get(column_index)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?
            .is_some()
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let source = CommonProofSourcePolynomial::Base(
        context
            .trace_domain
            .interpolate_base_polynomial(&rows)
            .map_err(CommonProofProverError::from)
            .map_err(CommonProofPrivateCoinError::Prover)?,
    );
    let constructed = mask_relation_column(
        context.variant,
        descriptor,
        context.trace_masks.get(&column_ordinal).copied(),
        source,
        coins,
        context.maximum_candidate_draws_per_output,
    )?;
    columns[column_index] = Some(constructed);
    Ok(())
}

fn base_field_constant(value: u64) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    ProofBaseFieldElement::from_canonical(value).map_err(CommonProofProverError::from)
}

fn integer_lift_coefficient_value(
    context: &RelationPlanCheckContext,
    coefficient: RelationIntegerLiftCoefficient,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let value = match coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => value,
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => context
            .resolved_modulus(modulus_reference)?
            .checked_mul(u64::from(multiplier))
            .ok_or(CommonProofProverError::CountOverflow)?,
    };
    base_field_constant(value)
}

fn signed_linear_term_row(
    term: &RelationIntegerLiftLinearTermDescriptor,
    row_ordinal: usize,
    context: &RelationPlanCheckContext,
    trace_rows_by_column: &BTreeMap<u32, Vec<ProofBaseFieldElement>>,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let column_value = trace_rows_by_column
        .get(&term.column_ordinal)
        .and_then(|rows| rows.get(row_ordinal))
        .copied()
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let shifted = column_value.subtract(base_field_constant(term.column_offset)?);
    let value = shifted.multiply(integer_lift_coefficient_value(context, term.coefficient)?);
    Ok(if term.negative { value.negate() } else { value })
}

fn integer_lift_linear_evaluation_rows(
    context: &RelationPlanCheckContext,
    modulus_reference: SuiteModulusReference,
    component: &RelationIntegerLiftComponentDescriptor,
    theta: ProofBaseFieldElement,
    columns: &[Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    trace_domain: ProofEvaluationDomain,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofProverError> {
    ensure_base_trace_rows(
        columns,
        trace_rows_by_column,
        component.quotient_column_ordinal,
        trace_domain,
    )?;
    for term in &component.ordered_linear_terms {
        ensure_base_trace_rows(
            columns,
            trace_rows_by_column,
            term.column_ordinal,
            trace_domain,
        )?;
    }
    let modulus = base_field_constant(context.resolved_modulus(modulus_reference)?)?;
    let quotient_rows = trace_rows_by_column
        .get(&component.quotient_column_ordinal)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let mut coefficient_rows = vec![ProofBaseFieldElement::ZERO; trace_domain.size()];
    for row_ordinal in 0..trace_domain.size() {
        let mut coefficient = ProofBaseFieldElement::ZERO;
        for term in &component.ordered_linear_terms {
            coefficient = coefficient.add(signed_linear_term_row(
                term,
                row_ordinal,
                context,
                trace_rows_by_column,
            )?);
        }
        let quotient_term = modulus.multiply(quotient_rows[row_ordinal]);
        coefficient = coefficient.add(if component.quotient_is_negative {
            quotient_term.negate()
        } else {
            quotient_term
        });
        coefficient_rows[row_ordinal] = coefficient;
    }
    Ok(suffix_evaluation_rows(&coefficient_rows, theta))
}

fn product_accumulator_rows(product_rows: &[ProofBaseFieldElement]) -> Vec<ProofBaseFieldElement> {
    let mut accumulator_rows = vec![ProofBaseFieldElement::ZERO; product_rows.len()];
    for row_ordinal in 0..product_rows.len().saturating_sub(1) {
        accumulator_rows[row_ordinal + 1] =
            accumulator_rows[row_ordinal].add(product_rows[row_ordinal]);
    }
    accumulator_rows
}

fn convolution_transpose_rows(
    kind: RelationIntegerLiftConvolutionKind,
    multiplicand_rows: &[ProofBaseFieldElement],
    suffix_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofProverError> {
    if multiplicand_rows.is_empty() || multiplicand_rows.len() != suffix_rows.len() {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let row_count = multiplicand_rows.len();
    let theta_to_row_count =
        theta.power(u64::try_from(row_count).map_err(|_| CommonProofProverError::CountOverflow)?);
    let last = row_count - 1;
    let mut transpose_rows = vec![ProofBaseFieldElement::ZERO; row_count];
    match kind {
        RelationIntegerLiftConvolutionKind::Negacyclic => {
            transpose_rows[last] = suffix_rows[0];
            let wrap_factor = theta_to_row_count.add(ProofBaseFieldElement::ONE);
            for row_ordinal in (1..row_count).rev() {
                transpose_rows[row_ordinal - 1] = theta
                    .multiply(transpose_rows[row_ordinal])
                    .subtract(wrap_factor.multiply(multiplicand_rows[row_ordinal]));
            }
        }
        RelationIntegerLiftConvolutionKind::OrdinaryLowHalf => {
            transpose_rows[last] = suffix_rows[0];
            for row_ordinal in (0..last).rev() {
                transpose_rows[row_ordinal] = theta
                    .multiply(transpose_rows[row_ordinal + 1])
                    .subtract(theta_to_row_count.multiply(multiplicand_rows[row_ordinal + 1]));
            }
        }
        RelationIntegerLiftConvolutionKind::OrdinaryHighHalf => {
            transpose_rows[last] = ProofBaseFieldElement::ZERO;
            for row_ordinal in (0..last).rev() {
                transpose_rows[row_ordinal] = multiplicand_rows[row_ordinal + 1]
                    .add(theta.multiply(transpose_rows[row_ordinal + 1]));
            }
        }
    }
    Ok(transpose_rows)
}

#[allow(clippy::too_many_arguments)]
fn synthesize_convolution_product<Coins>(
    variant: &RelationPlanVariant,
    product: &RelationIntegerLiftConvolutionProductDescriptor,
    theta: ProofBaseFieldElement,
    tree_roles: &BTreeMap<u32, ProofTreeRole>,
    trace_masks: &BTreeMap<u32, RelationMaskDescriptor>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    product_sum_rows: &mut [ProofBaseFieldElement],
    trace_domain: ProofEvaluationDomain,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    ensure_base_trace_rows(
        columns,
        trace_rows_by_column,
        product.multiplicand_column_ordinal,
        trace_domain,
    )
    .map_err(CommonProofPrivateCoinError::Prover)?;
    ensure_base_trace_rows(
        columns,
        trace_rows_by_column,
        product.reversed_multiplier_column_ordinal,
        trace_domain,
    )
    .map_err(CommonProofPrivateCoinError::Prover)?;
    let offset = base_field_constant(product.multiplier_offset)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let (suffix_rows, transpose_rows, contribution_rows) = {
        let multiplicand_rows = trace_rows_by_column
            .get(&product.multiplicand_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let reversed_multiplier_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let suffix_rows = suffix_evaluation_rows(multiplicand_rows, theta);
        let transpose_rows = convolution_transpose_rows(
            product.convolution_kind,
            multiplicand_rows,
            &suffix_rows,
            theta,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;
        let contribution_rows = transpose_rows
            .iter()
            .copied()
            .zip(reversed_multiplier_rows.iter().copied())
            .map(|(transpose, reversed_multiplier)| {
                let value = transpose.multiply(reversed_multiplier.subtract(offset));
                if product.negative {
                    value.negate()
                } else {
                    value
                }
            })
            .collect::<Vec<_>>();
        (suffix_rows, transpose_rows, contribution_rows)
    };
    if contribution_rows.len() != product_sum_rows.len() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    for (accumulated, contribution) in product_sum_rows.iter_mut().zip(contribution_rows) {
        *accumulated = accumulated.add(contribution);
    }
    let auxiliary_trace_row_context = AuxiliaryTraceRowInsertionContext::new(
        variant,
        tree_roles,
        trace_masks,
        trace_domain,
        maximum_candidate_draws_per_output,
    );
    insert_auxiliary_trace_rows(
        auxiliary_trace_row_context,
        columns,
        product.suffix_evaluation_column_ordinal,
        suffix_rows,
        coins,
    )?;
    insert_auxiliary_trace_rows(
        auxiliary_trace_row_context,
        columns,
        product.reversed_transpose_column_ordinal,
        transpose_rows,
        coins,
    )?;
    Ok(())
}

fn full_ring_transpose_rows(
    selected_half: RelationIntegerLiftFullRingHalf,
    low_multiplier: bool,
    multiplicand_low_rows: &[ProofBaseFieldElement],
    multiplicand_high_rows: &[ProofBaseFieldElement],
    low_suffix_rows: &[ProofBaseFieldElement],
    high_suffix_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofProverError> {
    let row_count = multiplicand_low_rows.len();
    if row_count == 0
        || multiplicand_high_rows.len() != row_count
        || low_suffix_rows.len() != row_count
        || high_suffix_rows.len() != row_count
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let theta_to_half_ring_degree =
        theta.power(u64::try_from(row_count).map_err(|_| CommonProofProverError::CountOverflow)?);
    let last = row_count - 1;
    let mut transpose_rows = vec![ProofBaseFieldElement::ZERO; row_count];
    transpose_rows[last] = match (selected_half, low_multiplier) {
        (RelationIntegerLiftFullRingHalf::Low, true)
        | (RelationIntegerLiftFullRingHalf::High, false) => low_suffix_rows[0],
        (RelationIntegerLiftFullRingHalf::Low, false) => high_suffix_rows[0].negate(),
        (RelationIntegerLiftFullRingHalf::High, true) => high_suffix_rows[0],
    };
    for row_ordinal in (0..last).rev() {
        let low_next = multiplicand_low_rows[row_ordinal + 1];
        let high_next = multiplicand_high_rows[row_ordinal + 1];
        let theta_times_next = theta.multiply(transpose_rows[row_ordinal + 1]);
        transpose_rows[row_ordinal] = match (selected_half, low_multiplier) {
            (RelationIntegerLiftFullRingHalf::Low, true)
            | (RelationIntegerLiftFullRingHalf::High, false) => theta_times_next
                .subtract(theta_to_half_ring_degree.multiply(low_next))
                .subtract(high_next),
            (RelationIntegerLiftFullRingHalf::Low, false) => theta_times_next
                .subtract(low_next)
                .add(theta_to_half_ring_degree.multiply(high_next)),
            (RelationIntegerLiftFullRingHalf::High, true) => theta_times_next
                .add(low_next)
                .subtract(theta_to_half_ring_degree.multiply(high_next)),
        };
    }
    Ok(transpose_rows)
}

#[allow(clippy::too_many_arguments)]
fn synthesize_full_ring_product<Coins>(
    variant: &RelationPlanVariant,
    product: &RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    theta: ProofBaseFieldElement,
    tree_roles: &BTreeMap<u32, ProofTreeRole>,
    trace_masks: &BTreeMap<u32, RelationMaskDescriptor>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    product_sum_rows: &mut [ProofBaseFieldElement],
    trace_domain: ProofEvaluationDomain,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    for column_ordinal in [
        product.multiplicand_low_column_ordinal,
        product.multiplicand_high_column_ordinal,
        product.reversed_multiplier_low_column_ordinal,
        product.reversed_multiplier_high_column_ordinal,
    ] {
        ensure_base_trace_rows(columns, trace_rows_by_column, column_ordinal, trace_domain)
            .map_err(CommonProofPrivateCoinError::Prover)?;
    }
    let low_offset = base_field_constant(product.multiplier_low_offset)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let high_offset = base_field_constant(product.multiplier_high_offset)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let (
        low_suffix_rows,
        high_suffix_rows,
        low_transpose_rows,
        high_transpose_rows,
        contribution_rows,
    ) = {
        let multiplicand_low_rows = trace_rows_by_column
            .get(&product.multiplicand_low_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let multiplicand_high_rows = trace_rows_by_column
            .get(&product.multiplicand_high_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let reversed_multiplier_low_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_low_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let reversed_multiplier_high_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_high_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let low_suffix_rows = suffix_evaluation_rows(multiplicand_low_rows, theta);
        let high_suffix_rows = suffix_evaluation_rows(multiplicand_high_rows, theta);
        let low_transpose_rows = full_ring_transpose_rows(
            product.selected_half,
            true,
            multiplicand_low_rows,
            multiplicand_high_rows,
            &low_suffix_rows,
            &high_suffix_rows,
            theta,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;
        let high_transpose_rows = full_ring_transpose_rows(
            product.selected_half,
            false,
            multiplicand_low_rows,
            multiplicand_high_rows,
            &low_suffix_rows,
            &high_suffix_rows,
            theta,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;
        let mut contribution_rows = Vec::with_capacity(trace_domain.size());
        for row_ordinal in 0..trace_domain.size() {
            let low_product = low_transpose_rows[row_ordinal]
                .multiply(reversed_multiplier_low_rows[row_ordinal].subtract(low_offset));
            let high_product = high_transpose_rows[row_ordinal]
                .multiply(reversed_multiplier_high_rows[row_ordinal].subtract(high_offset));
            let value = low_product.add(high_product);
            contribution_rows.push(if product.negative {
                value.negate()
            } else {
                value
            });
        }
        (
            low_suffix_rows,
            high_suffix_rows,
            low_transpose_rows,
            high_transpose_rows,
            contribution_rows,
        )
    };
    if contribution_rows.len() != product_sum_rows.len() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    for (accumulated, contribution) in product_sum_rows.iter_mut().zip(contribution_rows) {
        *accumulated = accumulated.add(contribution);
    }
    let auxiliary_trace_row_context = AuxiliaryTraceRowInsertionContext::new(
        variant,
        tree_roles,
        trace_masks,
        trace_domain,
        maximum_candidate_draws_per_output,
    );
    for (column_ordinal, rows) in [
        (
            product.multiplicand_low_suffix_evaluation_column_ordinal,
            low_suffix_rows,
        ),
        (
            product.multiplicand_high_suffix_evaluation_column_ordinal,
            high_suffix_rows,
        ),
        (
            product.reversed_multiplier_low_transpose_column_ordinal,
            low_transpose_rows,
        ),
        (
            product.reversed_multiplier_high_transpose_column_ordinal,
            high_transpose_rows,
        ),
    ] {
        insert_auxiliary_trace_rows(
            auxiliary_trace_row_context,
            columns,
            column_ordinal,
            rows,
            coins,
        )?;
    }
    Ok(())
}

fn validate_column_polynomials(
    variant: &RelationPlanVariant,
    columns: &[CommonProofSourcePolynomial],
) -> Result<(), CommonProofProverError> {
    if columns.len() != variant.ordered_columns().len() {
        return Err(CommonProofProverError::InvalidColumn);
    }
    for (descriptor, polynomial) in variant.ordered_columns().iter().zip(columns) {
        if descriptor.value_type() != polynomial.value_type()
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count()
                > usize::try_from(descriptor.source_degree_bound_exclusive())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    Ok(())
}

/// Evaluates the checked relation on the complete evaluation coset and
/// interpolates the one normalized composed quotient polynomial.
#[cfg(test)]
pub(crate) fn construct_composed_quotient_polynomial(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    evaluation_domain: ProofEvaluationDomain,
    columns: &[CommonProofSourcePolynomial],
    application_challenges: &[RelationApplicationChallengeAssignment],
    composition_challenges: &[ProofChallengeExtensionElement],
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    validate_column_polynomials(variant, columns)?;
    if evaluation_domain.size()
        != usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?
        || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
        || evaluation_domain.coset_offset().canonical() != context.evaluation_coset_offset
        || !variant
            .evaluation_domain_size()
            .is_multiple_of(variant.trace_domain_size())
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }

    let column_evaluations = columns
        .iter()
        .map(|column| match column {
            CommonProofSourcePolynomial::Base(coefficients) => evaluation_domain
                .evaluate_base_polynomial(coefficients)
                .map(CommonProofColumnEvaluations::Base),
            CommonProofSourcePolynomial::Extension(coefficients) => evaluation_domain
                .evaluate_extension_polynomial(coefficients)
                .map(CommonProofColumnEvaluations::Extension),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evaluation_size = evaluation_domain.size();
    let trace_rotation_stride =
        usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_domain_size = usize::try_from(variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;

    let mut quotient_evaluations = Vec::new();
    quotient_evaluations
        .try_reserve_exact(evaluation_size)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for evaluation_position in 0..evaluation_size {
        let evaluation_point = ProofChallengeExtensionElement::from_base(
            evaluation_domain.point(evaluation_position)?,
        );
        quotient_evaluations.push(variant.evaluate_composed_quotient_at_point(
            context,
            evaluation_point,
            application_challenges,
            composition_challenges,
            |column_ordinal, rotation_is_negative, rotation_magnitude| {
                let column_index = usize::try_from(column_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                let reduced_rotation =
                    usize::try_from(rotation_magnitude % variant.trace_domain_size())
                        .map_err(|_| RelationPlanError::CountOverflow)?;
                let rotation_offset = reduced_rotation
                    .checked_mul(trace_rotation_stride)
                    .ok_or(RelationPlanError::CountOverflow)?;
                let rotated_position = if rotation_is_negative {
                    evaluation_position
                        .checked_add(evaluation_size)
                        .and_then(|position| position.checked_sub(rotation_offset))
                        .ok_or(RelationPlanError::CountOverflow)?
                        % evaluation_size
                } else {
                    evaluation_position
                        .checked_add(rotation_offset)
                        .ok_or(RelationPlanError::CountOverflow)?
                        % evaluation_size
                };
                if reduced_rotation >= trace_domain_size {
                    return Err(RelationPlanError::InvalidOpening);
                }
                column_evaluations
                    .get(column_index)
                    .ok_or(RelationPlanError::InvalidConstraint)?
                    .extension_value(rotated_position)
                    .map_err(|_| RelationPlanError::InvalidConstraint)
            },
        )?);
    }
    let mut quotient = evaluation_domain.interpolate_extension_polynomial(&quotient_evaluations)?;
    trim_extension_polynomial(&mut quotient);
    Ok(quotient)
}

const COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH: usize = 4_096;

fn required_relation_rotations_by_column(
    variant: &RelationPlanVariant,
) -> Result<Vec<Vec<(bool, u64)>>, CommonProofProverError> {
    let mut rotations_by_column = vec![BTreeSet::new(); variant.ordered_columns().len()];
    for claim in variant.ordered_opening_claims() {
        if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let column_index = usize::try_from(
            claim
                .column_ordinal()
                .ok_or(CommonProofProverError::InvalidOpening)?,
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        let opening_point = variant
            .ordered_opening_points()
            .get(
                usize::try_from(claim.opening_point_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidOpening)?;
        rotations_by_column
            .get_mut(column_index)
            .ok_or(CommonProofProverError::InvalidColumn)?
            .insert(opening_point.trace_rotation());
    }
    rotations_by_column
        .into_iter()
        .map(|rotations| {
            if rotations.is_empty() {
                Err(CommonProofProverError::InvalidColumn)
            } else {
                Ok(rotations.into_iter().collect())
            }
        })
        .collect()
}

fn rotated_relation_evaluation_position(
    evaluation_position: usize,
    evaluation_size: usize,
    trace_domain_size: usize,
    trace_rotation_stride: usize,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Result<usize, CommonProofProverError> {
    let reduced_rotation = usize::try_from(
        rotation_magnitude
            % u64::try_from(trace_domain_size)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
    )
    .map_err(|_| CommonProofProverError::CountOverflow)?;
    if reduced_rotation >= trace_domain_size {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let rotation_offset = reduced_rotation
        .checked_mul(trace_rotation_stride)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if rotation_is_negative {
        evaluation_position
            .checked_add(evaluation_size)
            .and_then(|position| position.checked_sub(rotation_offset))
            .map(|position| position % evaluation_size)
            .ok_or(CommonProofProverError::CountOverflow)
    } else {
        evaluation_position
            .checked_add(rotation_offset)
            .map(|position| position % evaluation_size)
            .ok_or(CommonProofProverError::CountOverflow)
    }
}

struct CommonProofReplayQuotientBuilder {
    evaluation_domain: ProofEvaluationDomain,
    trace_domain_size: usize,
    trace_rotation_stride: usize,
    rotations_by_column: Vec<Vec<(bool, u64)>>,
    block_values_by_column: Vec<Vec<Vec<ProofChallengeExtensionElement>>>,
    block_start: usize,
    next_column_index: usize,
    quotient_evaluations: Vec<ProofChallengeExtensionElement>,
    application_challenges: Vec<RelationApplicationChallengeAssignment>,
    composition_challenges: Vec<ProofChallengeExtensionElement>,
}

impl CommonProofReplayQuotientBuilder {
    fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        evaluation_domain: ProofEvaluationDomain,
        application_challenges: Vec<RelationApplicationChallengeAssignment>,
        composition_challenges: Vec<ProofChallengeExtensionElement>,
    ) -> Result<Self, CommonProofProverError> {
        if evaluation_domain.size()
            != usize::try_from(variant.evaluation_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?
            || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
            || evaluation_domain.coset_offset().canonical() != context.evaluation_coset_offset
            || !variant
                .evaluation_domain_size()
                .is_multiple_of(variant.trace_domain_size())
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let trace_domain_size = usize::try_from(variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let trace_rotation_stride =
            usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let rotations_by_column = required_relation_rotations_by_column(variant)?;
        let mut quotient_evaluations = Vec::new();
        quotient_evaluations
            .try_reserve_exact(evaluation_domain.size())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        Ok(Self {
            evaluation_domain,
            trace_domain_size,
            trace_rotation_stride,
            rotations_by_column,
            block_values_by_column: Vec::new(),
            block_start: 0,
            next_column_index: 0,
            quotient_evaluations,
            application_challenges,
            composition_challenges,
        })
    }

    fn next_column_index(&self) -> Option<usize> {
        (self.block_start < self.evaluation_domain.size()
            && self.next_column_index < self.rotations_by_column.len())
        .then_some(self.next_column_index)
    }

    fn accept_column(
        &mut self,
        column_index: usize,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        if self.next_column_index() != Some(column_index) {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let evaluations = match polynomial {
            CommonProofSourcePolynomial::Base(coefficients) => CommonProofColumnEvaluations::Base(
                self.evaluation_domain
                    .evaluate_base_polynomial(&coefficients)?,
            ),
            CommonProofSourcePolynomial::Extension(mut coefficients) => {
                self.evaluation_domain
                    .evaluate_extension_polynomial_in_place(&mut coefficients)?;
                CommonProofColumnEvaluations::Extension(coefficients)
            }
        };
        let block_end = self
            .block_start
            .checked_add(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(self.evaluation_domain.size());
        let rotations = self
            .rotations_by_column
            .get(column_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let mut values_by_rotation = Vec::new();
        values_by_rotation
            .try_reserve_exact(rotations.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for (rotation_is_negative, rotation_magnitude) in rotations.iter().copied() {
            let mut values = Vec::new();
            values
                .try_reserve_exact(block_end - self.block_start)
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            for evaluation_position in self.block_start..block_end {
                let rotated_position = rotated_relation_evaluation_position(
                    evaluation_position,
                    self.evaluation_domain.size(),
                    self.trace_domain_size,
                    self.trace_rotation_stride,
                    rotation_is_negative,
                    rotation_magnitude,
                )?;
                values.push(evaluations.extension_value(rotated_position)?);
            }
            values_by_rotation.push(values);
        }
        self.block_values_by_column.push(values_by_rotation);
        self.next_column_index = self
            .next_column_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    fn evaluate_ready_block(
        &mut self,
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<bool, CommonProofProverError> {
        if self.block_start >= self.evaluation_domain.size()
            || self.next_column_index != self.rotations_by_column.len()
            || self.block_values_by_column.len() != self.rotations_by_column.len()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let block_end = self
            .block_start
            .checked_add(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(self.evaluation_domain.size());
        for evaluation_position in self.block_start..block_end {
            let block_position = evaluation_position - self.block_start;
            let evaluation_point = ProofChallengeExtensionElement::from_base(
                self.evaluation_domain.point(evaluation_position)?,
            );
            self.quotient_evaluations.push(
                variant
                    .evaluate_composed_quotient_at_point(
                        context,
                        evaluation_point,
                        &self.application_challenges,
                        &self.composition_challenges,
                        |column_ordinal, rotation_is_negative, rotation_magnitude| {
                            let column_index = usize::try_from(column_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?;
                            let rotations = self
                                .rotations_by_column
                                .get(column_index)
                                .ok_or(RelationPlanError::InvalidConstraint)?;
                            let rotation_index = rotations
                                .binary_search(&(rotation_is_negative, rotation_magnitude))
                                .map_err(|_| RelationPlanError::InvalidOpening)?;
                            self.block_values_by_column
                                .get(column_index)
                                .and_then(|values_by_rotation| {
                                    values_by_rotation.get(rotation_index)
                                })
                                .and_then(|values| values.get(block_position))
                                .copied()
                                .ok_or(RelationPlanError::InvalidConstraint)
                        },
                    )
                    .map_err(CommonProofProverError::from)?,
            );
        }
        self.block_values_by_column.clear();
        self.next_column_index = 0;
        self.block_start = block_end;
        Ok(self.block_start == self.evaluation_domain.size())
    }

    fn finish(mut self) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
        if self.block_start != self.evaluation_domain.size()
            || self.quotient_evaluations.len() != self.evaluation_domain.size()
            || !self.block_values_by_column.is_empty()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.evaluation_domain
            .interpolate_extension_polynomial_in_place(&mut self.quotient_evaluations)?;
        trim_extension_polynomial(&mut self.quotient_evaluations);
        Ok(self.quotient_evaluations)
    }
}

/// Splits the unique quotient into constant-first components of width `kHat`.
#[cfg(test)]
pub(crate) fn decompose_composed_quotient(
    quotient: &[ProofChallengeExtensionElement],
    component_count: u32,
    component_stride: u64,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    let component_count =
        usize::try_from(component_count).map_err(|_| CommonProofProverError::CountOverflow)?;
    let component_stride =
        usize::try_from(component_stride).map_err(|_| CommonProofProverError::CountOverflow)?;
    if component_count < 2 || component_stride == 0 || quotient.is_empty() {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let capacity = component_count
        .checked_mul(component_stride)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if quotient.len() > capacity {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let mut components = Vec::new();
    components
        .try_reserve_exact(component_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for component_ordinal in 0..component_count {
        let start = component_ordinal
            .checked_mul(component_stride)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let end = start
            .checked_add(component_stride)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(quotient.len());
        let mut component = if start < quotient.len() {
            quotient[start..end].to_vec()
        } else {
            vec![ProofChallengeExtensionElement::ZERO]
        };
        trim_extension_polynomial(&mut component);
        components.push(component);
    }
    Ok(components)
}

/// Applies the exact neighboring telescoping randomizers to canonical quotient
/// components.  Public-only mode performs no private-randomness call.
#[cfg(test)]
pub(crate) fn construct_quotient_components<Coins>(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    quotient: &[ProofChallengeExtensionElement],
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let mut cursor = CommonProofQuotientComponentCursor::new(variant, context, quotient.to_vec())
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let component_count = cursor.component_count();
    let mut components = Vec::new();
    components.try_reserve_exact(component_count).map_err(|_| {
        CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
    })?;
    while let Some(component) = cursor.next_component(coins, maximum_candidate_draws_per_output)? {
        components.push(component);
    }
    Ok(components)
}

struct CommonProofQuotientComponentCursor {
    quotient: Vec<ProofChallengeExtensionElement>,
    stride: usize,
    component_count: usize,
    component_degree_bound_exclusive: usize,
    telescoping_descriptors: Vec<RelationMaskDescriptor>,
    previous_randomizer: Option<Vec<ProofChallengeExtensionElement>>,
    next_component_index: usize,
}

impl CommonProofQuotientComponentCursor {
    fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        quotient: Vec<ProofChallengeExtensionElement>,
    ) -> Result<Self, CommonProofProverError> {
        let stride = usize::try_from(variant.quotient_decomposition_stride(context)?)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let component_count = usize::try_from(context.quotient_component_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let component_degree_bound_exclusive =
            usize::try_from(context.quotient_component_degree_bound_exclusive)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        if stride == 0
            || component_count < 2
            || component_degree_bound_exclusive == 0
            || quotient.is_empty()
            || quotient.len()
                > stride
                    .checked_mul(component_count)
                    .ok_or(CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let telescoping_descriptors = variant
            .ordered_masks()
            .iter()
            .copied()
            .filter(|mask| {
                mask.mask_kind() == RelationMaskKind::Telescoping
                    && mask.target_class() == RelationMaskTargetClass::QuotientComponent
            })
            .collect::<Vec<_>>();
        match variant.proof_privacy_mode() {
            ProofPrivacyMode::PublicOnly if !variant.ordered_masks().is_empty() => {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::PublicOnly if !telescoping_descriptors.is_empty() => {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::SecretBearing
                if telescoping_descriptors.len() + 1 != component_count
                    || telescoping_descriptors
                        .iter()
                        .enumerate()
                        .any(|(ordinal, mask)| {
                            usize::try_from(mask.target_ordinal()).ok() != Some(ordinal)
                        }) =>
            {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::PublicOnly | ProofPrivacyMode::SecretBearing => {}
        }
        Ok(Self {
            quotient,
            stride,
            component_count,
            component_degree_bound_exclusive,
            telescoping_descriptors,
            previous_randomizer: None,
            next_component_index: 0,
        })
    }

    const fn component_count(&self) -> usize {
        self.component_count
    }

    fn next_component<Coins: CommonProofPrivateCoinSource>(
        &mut self,
        coins: &mut Coins,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<
        Option<Vec<ProofChallengeExtensionElement>>,
        CommonProofPrivateCoinError<Coins::Error>,
    > {
        if self.next_component_index >= self.component_count {
            if self.previous_randomizer.is_some() {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidMask,
                ));
            }
            return Ok(None);
        }
        let component_index = self.next_component_index;
        let mut component = self
            .quotient
            .iter()
            .skip(component_index.checked_mul(self.stride).ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?)
            .take(self.stride)
            .copied()
            .collect::<Vec<_>>();
        if component.is_empty() {
            component.push(ProofChallengeExtensionElement::ZERO);
        }
        let next_randomizer =
            if let Some(descriptor) = self.telescoping_descriptors.get(component_index).copied() {
                let randomizer = sample_private_extension_polynomial(
                    coins,
                    descriptor.mask_purpose(),
                    descriptor.mask_degree_bound_exclusive(),
                    maximum_candidate_draws_per_output,
                )?;
                add_shifted_extension_polynomial(&mut component, &randomizer, self.stride)
                    .map_err(CommonProofPrivateCoinError::Prover)?;
                Some(randomizer)
            } else {
                None
            };
        if let Some(previous_randomizer) = self.previous_randomizer.take() {
            subtract_extension_polynomial(&mut component, &previous_randomizer)
                .map_err(CommonProofPrivateCoinError::Prover)?;
        }
        trim_extension_polynomial(&mut component);
        if component.len() > self.component_degree_bound_exclusive {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidQuotient,
            ));
        }
        self.previous_randomizer = next_randomizer;
        self.next_component_index = self.next_component_index.checked_add(1).ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        Ok(Some(component))
    }
}

/// Samples the separately committed opening-batch polynomial in secret mode.
pub(crate) fn construct_opening_batch_mask<Coins>(
    variant: &RelationPlanVariant,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<Option<Vec<ProofChallengeExtensionElement>>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(None);
    }
    let mut descriptors = variant.ordered_masks().iter().copied().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::OpeningBatch
            && mask.target_class() == RelationMaskTargetClass::Batch
            && mask.target_ordinal() == 0
    });
    let descriptor = descriptors
        .next()
        .ok_or_else(|| CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidMask))?;
    if descriptors.next().is_some() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    Ok(Some(sample_private_extension_polynomial(
        coins,
        descriptor.mask_purpose(),
        descriptor.mask_degree_bound_exclusive(),
        maximum_candidate_draws_per_output,
    )?))
}

/// Emits the opening-claim-ordered DEEP values from the exact source
/// polynomials committed by the prover.
pub(crate) fn evaluate_ordered_deep_openings(
    variant: &RelationPlanVariant,
    columns: &[CommonProofSourcePolynomial],
    quotient_components: &[Vec<ProofChallengeExtensionElement>],
    opening_batch_mask: Option<&[ProofChallengeExtensionElement]>,
    opening_points: &[ProofChallengeExtensionElement],
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    validate_column_polynomials(variant, columns)?;
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(variant.ordered_opening_claims().len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for claim in variant.ordered_opening_claims() {
        let point = opening_points
            .get(
                usize::try_from(claim.opening_point_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        let value = match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => {
                let column_ordinal = claim
                    .column_ordinal()
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                columns
                    .get(
                        usize::try_from(column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidOpening)?
                    .evaluate_at(point)
            }
            RelationOpeningSourceClass::Quotient => {
                if claim.column_ordinal().is_some() {
                    return Err(CommonProofProverError::InvalidOpening);
                }
                let coefficients = quotient_components
                    .get(
                        usize::try_from(claim.source_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                evaluate_extension_at(coefficients, point)
            }
            RelationOpeningSourceClass::BatchMask => {
                if claim.source_ordinal() != 0 || claim.column_ordinal().is_some() {
                    return Err(CommonProofProverError::InvalidOpening);
                }
                evaluate_extension_at(
                    opening_batch_mask.ok_or(CommonProofProverError::InvalidOpening)?,
                    point,
                )
            }
        };
        evaluations.push(value);
    }
    Ok(evaluations)
}

/// Constructs the exact normalized initial-FRI polynomial.  The separately
/// committed batch mask is added directly and its class-three opening claim is
/// still included in the ordered normalized sum.
pub(crate) fn construct_initial_fri_polynomial(
    variant: &RelationPlanVariant,
    columns: &[CommonProofSourcePolynomial],
    quotient_components: &[Vec<ProofChallengeExtensionElement>],
    opening_batch_mask: Option<&[ProofChallengeExtensionElement]>,
    opening_points: &[ProofChallengeExtensionElement],
    deep_evaluations: &[ProofChallengeExtensionElement],
    batching_coefficients: &[ProofChallengeExtensionElement],
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    if deep_evaluations.len() != variant.ordered_opening_claims().len()
        || batching_coefficients.len() != deep_evaluations.len()
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let opening_bound = usize::try_from(variant.opening_degree_bound_exclusive())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if opening_bound <= 1 {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let mut initial = vec![ProofChallengeExtensionElement::ZERO; opening_bound - 1];
    if let Some(mask) = opening_batch_mask {
        if mask.len() > initial.len() {
            return Err(CommonProofProverError::InvalidMask);
        }
        for (destination, coefficient) in initial.iter_mut().zip(mask) {
            *destination = destination.add(*coefficient);
        }
    } else if variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing {
        return Err(CommonProofProverError::InvalidMask);
    }

    for (claim_ordinal, claim) in variant.ordered_opening_claims().iter().enumerate() {
        let mut numerator = Vec::new();
        match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => {
                let column = columns
                    .get(
                        usize::try_from(
                            claim
                                .column_ordinal()
                                .ok_or(CommonProofProverError::InvalidOpening)?,
                        )
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                numerator
                    .try_reserve_exact(column.coefficient_count())
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                match column {
                    CommonProofSourcePolynomial::Base(coefficients) => numerator.extend(
                        coefficients
                            .iter()
                            .copied()
                            .map(ProofChallengeExtensionElement::from_base),
                    ),
                    CommonProofSourcePolynomial::Extension(coefficients) => {
                        numerator.extend_from_slice(coefficients);
                    }
                }
            }
            RelationOpeningSourceClass::Quotient => {
                let coefficients = quotient_components
                    .get(
                        usize::try_from(claim.source_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                numerator
                    .try_reserve_exact(coefficients.len())
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                numerator.extend_from_slice(coefficients);
            }
            RelationOpeningSourceClass::BatchMask => {
                let coefficients =
                    opening_batch_mask.ok_or(CommonProofProverError::InvalidOpening)?;
                numerator
                    .try_reserve_exact(coefficients.len())
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                numerator.extend_from_slice(coefficients);
            }
        }
        let source_bound = usize::try_from(claim.source_degree_bound_exclusive())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if numerator.is_empty() || numerator.len() > source_bound || source_bound > opening_bound {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let opening_point = opening_points
            .get(
                usize::try_from(claim.opening_point_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        numerator[0] = numerator[0].subtract(deep_evaluations[claim_ordinal]);
        let remainder =
            divide_extension_polynomial_by_linear_in_place(&mut numerator, opening_point)?;
        if !remainder.is_zero() {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let shift = opening_bound
            .checked_sub(source_bound)
            .ok_or(CommonProofProverError::InvalidOpening)?;
        let batching_coefficient = batching_coefficients[claim_ordinal];
        for (coefficient_ordinal, coefficient) in numerator.into_iter().enumerate() {
            let destination_ordinal = shift
                .checked_add(coefficient_ordinal)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let destination = initial
                .get_mut(destination_ordinal)
                .ok_or(CommonProofProverError::InvalidOpening)?;
            *destination = destination.add(coefficient.multiply(batching_coefficient));
        }
    }
    trim_extension_polynomial(&mut initial);
    if extension_polynomial_degree(&initial).is_some_and(|degree| degree >= opening_bound - 1) {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    Ok(initial)
}

fn replay_polynomial_key_for_claim(
    claim: &RelationOpeningClaimDescriptor,
) -> Result<CommonProofReplayPolynomialKey, CommonProofProverError> {
    match claim.source_class() {
        RelationOpeningSourceClass::TreeColumn => {
            Ok(CommonProofReplayPolynomialKey::RelationColumn(
                claim
                    .column_ordinal()
                    .ok_or(CommonProofProverError::InvalidOpening)?,
            ))
        }
        RelationOpeningSourceClass::Quotient => {
            if claim.column_ordinal().is_some() {
                return Err(CommonProofProverError::InvalidOpening);
            }
            Ok(CommonProofReplayPolynomialKey::QuotientComponent(
                u16::try_from(claim.source_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ))
        }
        RelationOpeningSourceClass::BatchMask => {
            if claim.source_ordinal() != 0 || claim.column_ordinal().is_some() {
                return Err(CommonProofProverError::InvalidOpening);
            }
            Ok(CommonProofReplayPolynomialKey::OpeningBatchMask)
        }
    }
}

fn evaluate_replay_polynomial_opening(
    claim: &RelationOpeningClaimDescriptor,
    polynomial: &CommonProofSourcePolynomial,
    opening_point: ProofChallengeExtensionElement,
) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
    let source_degree_bound_exclusive = usize::try_from(claim.source_degree_bound_exclusive())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if polynomial.coefficient_count() == 0
        || polynomial.coefficient_count() > source_degree_bound_exclusive
        || (claim.source_class() != RelationOpeningSourceClass::TreeColumn
            && polynomial.value_type() != RelationColumnValueType::ChallengeExtension)
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    Ok(polynomial.evaluate_at(opening_point))
}

fn into_extension_polynomial(
    polynomial: CommonProofSourcePolynomial,
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    match polynomial {
        CommonProofSourcePolynomial::Base(coefficients) => {
            let mut extension_coefficients = Vec::new();
            extension_coefficients
                .try_reserve_exact(coefficients.len())
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            extension_coefficients.extend(
                coefficients
                    .into_iter()
                    .map(ProofChallengeExtensionElement::from_base),
            );
            Ok(extension_coefficients)
        }
        CommonProofSourcePolynomial::Extension(coefficients) => Ok(coefficients),
    }
}

fn add_replay_polynomial_to_initial_fri(
    initial: &mut [ProofChallengeExtensionElement],
    opening_degree_bound_exclusive: usize,
    claim: &RelationOpeningClaimDescriptor,
    polynomial: CommonProofSourcePolynomial,
    opening_point: ProofChallengeExtensionElement,
    deep_evaluation: ProofChallengeExtensionElement,
    batching_coefficient: ProofChallengeExtensionElement,
) -> Result<(), CommonProofProverError> {
    let mut numerator = into_extension_polynomial(polynomial)?;
    let source_degree_bound_exclusive = usize::try_from(claim.source_degree_bound_exclusive())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if numerator.is_empty()
        || numerator.len() > source_degree_bound_exclusive
        || source_degree_bound_exclusive > opening_degree_bound_exclusive
        || initial.len() + 1 != opening_degree_bound_exclusive
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    numerator[0] = numerator[0].subtract(deep_evaluation);
    let remainder = divide_extension_polynomial_by_linear_in_place(&mut numerator, opening_point)?;
    if !remainder.is_zero() {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let shift = opening_degree_bound_exclusive
        .checked_sub(source_degree_bound_exclusive)
        .ok_or(CommonProofProverError::InvalidOpening)?;
    for (coefficient_ordinal, coefficient) in numerator.into_iter().enumerate() {
        let destination_ordinal = shift
            .checked_add(coefficient_ordinal)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination = initial
            .get_mut(destination_ordinal)
            .ok_or(CommonProofProverError::InvalidOpening)?;
        *destination = destination.add(coefficient.multiply(batching_coefficient));
    }
    Ok(())
}

/// Builds one FRI layer only.  Callers persist the returned layer before
/// releasing the previous one, so peak memory is two layers rather than the
/// complete fold chain.
pub(crate) fn construct_next_fri_layer(
    current_evaluations: &[ProofChallengeExtensionElement],
    current_domain: ProofEvaluationDomain,
    challenge: ProofChallengeExtensionElement,
) -> Result<(ProofEvaluationDomain, Vec<ProofChallengeExtensionElement>), CommonProofProverError> {
    if current_evaluations.len() != current_domain.size() {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    let folded = fold_extension_evaluations(current_evaluations, current_domain, challenge)?;
    Ok((current_domain.folded()?, folded))
}

/// Interpolates the final FRI layer and pads to the schedule-fixed exclusive
/// degree bound.  Padding is part of the proof bytes and transcript.
pub(crate) fn construct_fri_terminal_coefficients(
    terminal_evaluations: &[ProofChallengeExtensionElement],
    terminal_domain: ProofEvaluationDomain,
    final_degree_bound_exclusive: u32,
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    let bound = usize::try_from(final_degree_bound_exclusive)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if bound == 0 || terminal_evaluations.len() != terminal_domain.size() {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    let mut coefficients =
        terminal_domain.interpolate_extension_polynomial(terminal_evaluations)?;
    if extension_polynomial_degree(&coefficients).is_some_and(|degree| degree >= bound) {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    coefficients.resize(bound, ProofChallengeExtensionElement::ZERO);
    Ok(coefficients)
}

fn add_shifted_extension_polynomial(
    target: &mut Vec<ProofChallengeExtensionElement>,
    addend: &[ProofChallengeExtensionElement],
    shift: usize,
) -> Result<(), CommonProofProverError> {
    let required = shift
        .checked_add(addend.len())
        .ok_or(CommonProofProverError::CountOverflow)?;
    if target.len() < required {
        target.resize(required, ProofChallengeExtensionElement::ZERO);
    }
    for (ordinal, coefficient) in addend.iter().copied().enumerate() {
        target[shift + ordinal] = target[shift + ordinal].add(coefficient);
    }
    Ok(())
}

fn subtract_extension_polynomial(
    target: &mut Vec<ProofChallengeExtensionElement>,
    subtrahend: &[ProofChallengeExtensionElement],
) -> Result<(), CommonProofProverError> {
    if target.len() < subtrahend.len() {
        target.resize(subtrahend.len(), ProofChallengeExtensionElement::ZERO);
    }
    for (destination, coefficient) in target.iter_mut().zip(subtrahend) {
        *destination = destination.subtract(*coefficient);
    }
    Ok(())
}

fn trim_base_polynomial(coefficients: &mut Vec<ProofBaseFieldElement>) {
    while coefficients.len() > 1 && coefficients.last() == Some(&ProofBaseFieldElement::ZERO) {
        coefficients.pop();
    }
}

fn trim_extension_polynomial(coefficients: &mut Vec<ProofChallengeExtensionElement>) {
    while coefficients.len() > 1
        && coefficients.last() == Some(&ProofChallengeExtensionElement::ZERO)
    {
        coefficients.pop();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofTreeStorageError<StorageError, CoinError> {
    Prover(CommonProofProverError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
    CoinSource(CoinError),
}

/// External-memory location of one common proof-created Merkle tree.  Canonical
/// leaves and every digest level remain random-accessible until the generated
/// liveness plan reaches the proof-query step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredCommonProofMerkleTree {
    tree_catalog_index: u16,
    context: ProofMerkleTreeContext,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    root: [u8; HASH_BYTE_LENGTH],
}

impl StoredCommonProofMerkleTree {
    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn root(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.root
    }

    pub(crate) const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub(crate) const fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_byte_length
    }
}

/// Exact external-memory allocation for one common proof-created Merkle tree.
/// The object identifiers are plan-local and deliberately contain no secret
/// material.  The returned liveness entries can be concatenated with the
/// entries for the other common trees before constructing the executor plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofMerkleStoragePlan {
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    object_plans: Vec<ProofExternalMemoryObjectPlan>,
    canonical_leaf_byte_length: usize,
    next_object_ordinal: u32,
}

impl CommonProofMerkleStoragePlan {
    pub(crate) fn object_plans(&self) -> &[ProofExternalMemoryObjectPlan] {
        &self.object_plans
    }

    pub(crate) const fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_byte_length
    }

    pub(crate) const fn next_object_ordinal(&self) -> u32 {
        self.next_object_ordinal
    }
}

/// Generates the exact object lengths and last-use deletion schedule for one
/// common tree.  Canonical leaf length is derived through the same encoder used
/// by the committed leaf, avoiding a second hand-maintained wire-size formula.
/// Checked relation trees contain base-field rows; quotient, batch-mask, and
/// FRI trees contain extension-field rows.
pub(crate) fn common_proof_merkle_storage_plan(
    catalog_entry: &ProofTreeCatalogEntry,
    first_object_ordinal: u32,
    materialization_step: u32,
    query_step: u32,
) -> Result<CommonProofMerkleStoragePlan, CommonProofProverError> {
    if query_step < materialization_step {
        return Err(CommonProofProverError::InvalidTree);
    }
    let context = catalog_entry
        .common_context()
        .ok_or(CommonProofProverError::InvalidTree)?;
    let value_type = common_proof_tree_value_type(catalog_entry)?;
    let leaf_count = context.leaf_count()?;
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(CommonProofProverError::InvalidTree);
    }
    let canonical_leaf_byte_length = canonical_common_proof_leaf_byte_length(context, value_type)?;
    let stored_leaf_byte_length = u64::try_from(canonical_leaf_byte_length)
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_mul(u64::try_from(leaf_count).map_err(|_| CommonProofProverError::CountOverflow)?)
        .ok_or(CommonProofProverError::CountOverflow)?;

    let leaf_bytes_object = ProofExternalMemoryObject::new(first_object_ordinal);
    let leaf_protection = match context.leaf_visibility() {
        ProofLeafVisibility::Public => ProofExternalMemoryProtection::PublicIntegrity,
        ProofLeafVisibility::SecretBearing => {
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption
        }
    };
    let mut object_plans = vec![ProofExternalMemoryObjectPlan::new(
        leaf_bytes_object,
        leaf_protection,
        stored_leaf_byte_length,
        materialization_step,
        materialization_step,
        query_step,
    )];
    let level_count = usize::try_from(leaf_count.trailing_zeros())
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    object_plans
        .try_reserve_exact(level_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut digest_level_objects = Vec::new();
    digest_level_objects
        .try_reserve_exact(level_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut node_count = leaf_count;
    let mut next_object_ordinal = first_object_ordinal
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    for level_ordinal in 0..level_count {
        let object = ProofExternalMemoryObject::new(next_object_ordinal);
        next_object_ordinal = next_object_ordinal
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let exact_byte_length = u64::try_from(node_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(HASH_BYTE_LENGTH as u64)
            .ok_or(CommonProofProverError::CountOverflow)?;
        // The root is cached in `StoredCommonProofMerkleTree`; unlike every
        // lower level it is never needed to construct an authentication
        // frontier and can be removed when materialization completes.
        let last_use_step = if level_ordinal + 1 == level_count {
            materialization_step
        } else {
            query_step
        };
        digest_level_objects.push(object);
        object_plans.push(ProofExternalMemoryObjectPlan::new(
            object,
            ProofExternalMemoryProtection::PublicIntegrity,
            exact_byte_length,
            materialization_step,
            materialization_step,
            last_use_step,
        ));
        node_count /= 2;
    }
    Ok(CommonProofMerkleStoragePlan {
        leaf_bytes_object,
        digest_level_objects,
        object_plans,
        canonical_leaf_byte_length,
        next_object_ordinal,
    })
}

fn common_proof_tree_value_type(
    catalog_entry: &ProofTreeCatalogEntry,
) -> Result<RelationColumnValueType, CommonProofProverError> {
    match catalog_entry.source() {
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::BaseOracle | ProofTreeRole::AuxiliaryOracle,
            ..
        } => Ok(RelationColumnValueType::BaseField),
        ProofTreeCatalogSource::QuotientComponent { .. }
        | ProofTreeCatalogSource::OpeningBatchMask
        | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
            Ok(RelationColumnValueType::ChallengeExtension)
        }
        ProofTreeCatalogSource::RelationProofCreated { .. }
        | ProofTreeCatalogSource::RelationBoundPublic => Err(CommonProofProverError::InvalidTree),
    }
}

fn canonical_common_proof_leaf_byte_length(
    context: &ProofMerkleTreeContext,
    value_type: RelationColumnValueType,
) -> Result<usize, CommonProofProverError> {
    let row_width =
        usize::try_from(context.row_width()).map_err(|_| CommonProofProverError::CountOverflow)?;
    let empty_value = match value_type {
        RelationColumnValueType::BaseField => ProofTreeValue::Base(ProofBaseFieldElement::ZERO),
        RelationColumnValueType::ChallengeExtension => {
            ProofTreeValue::Extension(ProofChallengeExtensionElement::ZERO)
        }
    };
    let row = vec![empty_value; row_width];
    let secret_salt = (context.leaf_visibility() == ProofLeafVisibility::SecretBearing)
        .then_some([0_u8; PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]);
    Ok(
        ProofOraclePhasePairLeaf::new(context, 0, secret_salt, row.clone(), row)?
            .canonical_bytes()?
            .len(),
    )
}

fn common_proof_tree_value_has_type(
    value: &ProofTreeValue,
    expected_type: RelationColumnValueType,
) -> bool {
    matches!(
        (value, expected_type),
        (ProofTreeValue::Base(_), RelationColumnValueType::BaseField)
            | (
                ProofTreeValue::Extension(_),
                RelationColumnValueType::ChallengeExtension
            )
    )
}

fn common_proof_merkle_storage_plan_matches(
    context: &ProofMerkleTreeContext,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    storage_plan: &CommonProofMerkleStoragePlan,
) -> Result<bool, CommonProofProverError> {
    let expected_object_plan_count = storage_plan
        .digest_level_objects
        .len()
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if storage_plan.object_plans.len() != expected_object_plan_count {
        return Ok(false);
    }
    let leaf_plan = storage_plan
        .object_plans
        .first()
        .copied()
        .ok_or(CommonProofProverError::InvalidTree)?;
    let expected_leaf_protection = match context.leaf_visibility() {
        ProofLeafVisibility::Public => ProofExternalMemoryProtection::PublicIntegrity,
        ProofLeafVisibility::SecretBearing => {
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption
        }
    };
    let expected_leaf_storage_byte_length = u64::try_from(canonical_leaf_byte_length)
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_mul(u64::try_from(leaf_count).map_err(|_| CommonProofProverError::CountOverflow)?)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let materialization_step = leaf_plan.issued_step();
    let query_step = leaf_plan.last_use_step();
    if leaf_plan.object() != storage_plan.leaf_bytes_object
        || leaf_plan.protection() != expected_leaf_protection
        || leaf_plan.exact_byte_length() != expected_leaf_storage_byte_length
        || leaf_plan.seal_step() != materialization_step
        || query_step < materialization_step
    {
        return Ok(false);
    }

    let first_object_ordinal = storage_plan.leaf_bytes_object.ordinal();
    let expected_next_object_ordinal = first_object_ordinal
        .checked_add(
            u32::try_from(expected_object_plan_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )
        .ok_or(CommonProofProverError::CountOverflow)?;
    if storage_plan.next_object_ordinal != expected_next_object_ordinal {
        return Ok(false);
    }

    let mut level_node_count = leaf_count;
    for (level_ordinal, object) in storage_plan.digest_level_objects.iter().enumerate() {
        let plan = storage_plan.object_plans[level_ordinal + 1];
        let expected_object_ordinal = first_object_ordinal
            .checked_add(
                u32::try_from(level_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let expected_byte_length = u64::try_from(level_node_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(HASH_BYTE_LENGTH as u64)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let is_root_level = level_ordinal + 1 == storage_plan.digest_level_objects.len();
        let expected_last_use_step = if is_root_level {
            materialization_step
        } else {
            query_step
        };
        if object.ordinal() != expected_object_ordinal
            || plan.object() != *object
            || plan.protection() != ProofExternalMemoryProtection::PublicIntegrity
            || plan.exact_byte_length() != expected_byte_length
            || plan.issued_step() != materialization_step
            || plan.seal_step() != materialization_step
            || plan.last_use_step() != expected_last_use_step
        {
            return Ok(false);
        }
        level_node_count /= 2;
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofMerkleMaterializerPhase {
    BeginLeafBytes,
    BeginLeafDigests,
    NeedLeafValues,
    WriteLeafBytes,
    WriteLeafDigest,
    FlushLeafBytes,
    FlushLeafDigests,
    SealLeafBytes,
    SealLeafDigests,
    BeginParentLevel,
    ReadLeftChild,
    ReadRightChild,
    WriteParentDigest,
    FlushParentLevel,
    SealParentLevel,
    ReadRoot,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofMerkleMaterializerProgress {
    StorageTransactionCompleted,
    NeedsLeafValues { leaf_index: u64 },
    Complete,
}

/// Resumable common-tree materialization for the browser worker.  Every call
/// to `advance_storage` performs at most one bounded storage transaction.  If
/// the recorder yields, operation-specific offsets and executor state do not
/// advance; replaying the exact operation is therefore safe.  Zero-work phase
/// transitions may occur before that operation is issued.  A secret leaf is
/// sampled and encoded once by `supply_next_leaf` and retained in zeroizing
/// memory across all of its bounded append transactions.
pub(crate) struct CommonProofMerkleMaterializer {
    tree_catalog_index: u16,
    context: ProofMerkleTreeContext,
    value_type: RelationColumnValueType,
    context_hash: [u8; HASH_BYTE_LENGTH],
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    phase: CommonProofMerkleMaterializerPhase,
    next_leaf_index: usize,
    current_leaf_bytes: Zeroizing<Vec<u8>>,
    current_leaf_digest: [u8; HASH_BYTE_LENGTH],
    leaf_bytes_write_chunk: Zeroizing<Vec<u8>>,
    digest_write_chunk: Zeroizing<Vec<u8>>,
    current_byte_offset: usize,
    current_level_ordinal: usize,
    current_parent_index: usize,
    left_child_digest: [u8; HASH_BYTE_LENGTH],
    right_child_digest: [u8; HASH_BYTE_LENGTH],
    root: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofMerkleMaterializer {
    pub(crate) fn new(
        catalog_entry: &ProofTreeCatalogEntry,
        storage_plan: CommonProofMerkleStoragePlan,
    ) -> Result<Self, CommonProofProverError> {
        let context = catalog_entry
            .common_context()
            .cloned()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let context_hash = context.context_hash()?;
        let leaf_count = context.leaf_count()?;
        let value_type = common_proof_tree_value_type(catalog_entry)?;
        let expected_leaf_byte_length =
            canonical_common_proof_leaf_byte_length(&context, value_type)?;
        let expected_level_count = usize::try_from(leaf_count.trailing_zeros())
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || storage_plan.digest_level_objects.len() != expected_level_count
            || storage_plan.canonical_leaf_byte_length != expected_leaf_byte_length
            || !common_proof_merkle_storage_plan_matches(
                &context,
                leaf_count,
                expected_leaf_byte_length,
                &storage_plan,
            )?
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        Ok(Self {
            tree_catalog_index: catalog_entry.tree_catalog_index(),
            context,
            value_type,
            context_hash,
            leaf_count,
            canonical_leaf_byte_length: storage_plan.canonical_leaf_byte_length,
            leaf_bytes_object: storage_plan.leaf_bytes_object,
            digest_level_objects: storage_plan.digest_level_objects,
            phase: CommonProofMerkleMaterializerPhase::BeginLeafBytes,
            next_leaf_index: 0,
            current_leaf_bytes: Zeroizing::new(Vec::new()),
            current_leaf_digest: [0; HASH_BYTE_LENGTH],
            leaf_bytes_write_chunk: Zeroizing::new(Vec::new()),
            digest_write_chunk: Zeroizing::new(Vec::new()),
            current_byte_offset: 0,
            current_level_ordinal: 0,
            current_parent_index: 0,
            left_child_digest: [0; HASH_BYTE_LENGTH],
            right_child_digest: [0; HASH_BYTE_LENGTH],
            root: [0; HASH_BYTE_LENGTH],
        })
    }

    fn fill_write_chunk(
        write_chunk: &mut Vec<u8>,
        source: &[u8],
        source_offset: &mut usize,
        maximum_chunk_byte_length: usize,
    ) -> Result<(), CommonProofProverError> {
        if maximum_chunk_byte_length == 0
            || write_chunk.len() > maximum_chunk_byte_length
            || *source_offset > source.len()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        if write_chunk.len() == maximum_chunk_byte_length || *source_offset == source.len() {
            return Ok(());
        }
        write_chunk
            .try_reserve_exact(maximum_chunk_byte_length - write_chunk.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        let copied_byte_length =
            (maximum_chunk_byte_length - write_chunk.len()).min(source.len() - *source_offset);
        let source_end = source_offset
            .checked_add(copied_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        write_chunk.extend_from_slice(&source[*source_offset..source_end]);
        *source_offset = source_end;
        Ok(())
    }

    fn finish_current_leaf(&mut self) -> Result<(), CommonProofProverError> {
        if self.current_byte_offset != HASH_BYTE_LENGTH || self.next_leaf_index >= self.leaf_count {
            return Err(CommonProofProverError::InvalidTree);
        }
        self.current_leaf_bytes.zeroize();
        self.current_leaf_digest = [0; HASH_BYTE_LENGTH];
        self.current_byte_offset = 0;
        self.next_leaf_index = self
            .next_leaf_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.phase = if self.next_leaf_index == self.leaf_count {
            CommonProofMerkleMaterializerPhase::FlushLeafBytes
        } else {
            CommonProofMerkleMaterializerPhase::NeedLeafValues
        };
        Ok(())
    }

    fn finish_current_parent_digest(&mut self) -> Result<(), CommonProofProverError> {
        if self.current_byte_offset != HASH_BYTE_LENGTH
            || self.current_level_ordinal == 0
            || self.current_level_ordinal >= self.digest_level_objects.len()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        self.current_leaf_digest = [0; HASH_BYTE_LENGTH];
        self.current_byte_offset = 0;
        self.current_parent_index = self
            .current_parent_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let parent_count = self.leaf_count >> self.current_level_ordinal;
        if self.current_parent_index > parent_count {
            return Err(CommonProofProverError::InvalidTree);
        }
        self.phase = if self.current_parent_index == parent_count {
            CommonProofMerkleMaterializerPhase::FlushParentLevel
        } else {
            CommonProofMerkleMaterializerPhase::ReadLeftChild
        };
        Ok(())
    }

    pub(crate) fn supply_next_leaf<Coins>(
        &mut self,
        first_point_values: Vec<ProofTreeValue>,
        opposite_point_values: Vec<ProofTreeValue>,
        coins: &mut Coins,
    ) -> Result<(), CommonProofTreeStorageError<core::convert::Infallible, Coins::Error>>
    where
        Coins: CommonProofPrivateCoinSource,
    {
        let expected_row_width = usize::try_from(self.context.row_width()).map_err(|_| {
            CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
        })?;
        if self.phase != CommonProofMerkleMaterializerPhase::NeedLeafValues
            || self.next_leaf_index >= self.leaf_count
            || first_point_values.len() != expected_row_width
            || opposite_point_values.len() != expected_row_width
            || first_point_values
                .iter()
                .chain(&opposite_point_values)
                .any(|value| !common_proof_tree_value_has_type(value, self.value_type))
        {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let secret_salt = if self.context.leaf_visibility() == ProofLeafVisibility::SecretBearing {
            let mut salt = [0_u8; PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
            coins
                .fill_raw_bytes(PRIVATE_PROOF_SALT_PURPOSE, &mut salt)
                .map_err(CommonProofTreeStorageError::CoinSource)?;
            Some(salt)
        } else {
            None
        };
        let leaf = ProofOraclePhasePairLeaf::new(
            &self.context,
            u64::try_from(self.next_leaf_index).map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
            })?,
            secret_salt,
            first_point_values,
            opposite_point_values,
        )
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofTreeStorageError::Prover)?;
        let canonical_bytes = leaf
            .canonical_bytes()
            .map_err(CommonProofProverError::from)
            .map_err(CommonProofTreeStorageError::Prover)?;
        if canonical_bytes.len() != self.canonical_leaf_byte_length {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        self.current_leaf_digest = leaf
            .digest()
            .map_err(CommonProofProverError::from)
            .map_err(CommonProofTreeStorageError::Prover)?;
        self.current_leaf_bytes = Zeroizing::new(canonical_bytes);
        self.current_byte_offset = 0;
        self.phase = CommonProofMerkleMaterializerPhase::WriteLeafBytes;
        Ok(())
    }

    pub(crate) fn advance_storage<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        CommonProofMerkleMaterializerProgress,
        CommonProofTreeStorageError<Storage::Error, core::convert::Infallible>,
    > {
        let maximum_chunk_byte_length = usize::try_from(executor.maximum_chunk_byte_length())
            .map_err(|_| {
                CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
            })?;
        if maximum_chunk_byte_length == 0 {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }

        loop {
            match self.phase {
                CommonProofMerkleMaterializerPhase::BeginLeafBytes => {
                    executor
                        .begin_object(storage, self.leaf_bytes_object)
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.phase = CommonProofMerkleMaterializerPhase::BeginLeafDigests;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::BeginLeafDigests => {
                    executor
                        .begin_object(storage, self.digest_level_objects[0])
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.phase = CommonProofMerkleMaterializerPhase::NeedLeafValues;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::NeedLeafValues => {
                    return Ok(CommonProofMerkleMaterializerProgress::NeedsLeafValues {
                        leaf_index: u64::try_from(self.next_leaf_index).map_err(|_| {
                            CommonProofTreeStorageError::Prover(
                                CommonProofProverError::CountOverflow,
                            )
                        })?,
                    });
                }
                CommonProofMerkleMaterializerPhase::WriteLeafBytes => {
                    Self::fill_write_chunk(
                        &mut self.leaf_bytes_write_chunk,
                        &self.current_leaf_bytes,
                        &mut self.current_byte_offset,
                        maximum_chunk_byte_length,
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    let leaf_is_buffered =
                        self.current_byte_offset == self.current_leaf_bytes.len();
                    if self.leaf_bytes_write_chunk.len() == maximum_chunk_byte_length {
                        executor
                            .append_object_bytes(
                                storage,
                                self.leaf_bytes_object,
                                &self.leaf_bytes_write_chunk,
                            )
                            .map_err(CommonProofTreeStorageError::Storage)?;
                        self.leaf_bytes_write_chunk.zeroize();
                        if leaf_is_buffered {
                            self.current_byte_offset = 0;
                            self.phase = CommonProofMerkleMaterializerPhase::WriteLeafDigest;
                        }
                        return Ok(
                            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted,
                        );
                    }
                    if !leaf_is_buffered {
                        return Err(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.current_byte_offset = 0;
                    self.phase = CommonProofMerkleMaterializerPhase::WriteLeafDigest;
                }
                CommonProofMerkleMaterializerPhase::WriteLeafDigest => {
                    Self::fill_write_chunk(
                        &mut self.digest_write_chunk,
                        &self.current_leaf_digest,
                        &mut self.current_byte_offset,
                        maximum_chunk_byte_length,
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    let digest_is_buffered = self.current_byte_offset == HASH_BYTE_LENGTH;
                    if self.digest_write_chunk.len() == maximum_chunk_byte_length {
                        executor
                            .append_object_bytes(
                                storage,
                                self.digest_level_objects[0],
                                &self.digest_write_chunk,
                            )
                            .map_err(CommonProofTreeStorageError::Storage)?;
                        self.digest_write_chunk.zeroize();
                        if digest_is_buffered {
                            self.finish_current_leaf()
                                .map_err(CommonProofTreeStorageError::Prover)?;
                        }
                        return Ok(
                            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted,
                        );
                    }
                    if !digest_is_buffered {
                        return Err(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.finish_current_leaf()
                        .map_err(CommonProofTreeStorageError::Prover)?;
                }
                CommonProofMerkleMaterializerPhase::FlushLeafBytes => {
                    if self.leaf_bytes_write_chunk.is_empty() {
                        self.phase = CommonProofMerkleMaterializerPhase::FlushLeafDigests;
                        continue;
                    }
                    executor
                        .append_object_bytes(
                            storage,
                            self.leaf_bytes_object,
                            &self.leaf_bytes_write_chunk,
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.leaf_bytes_write_chunk.zeroize();
                    self.phase = CommonProofMerkleMaterializerPhase::FlushLeafDigests;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::FlushLeafDigests => {
                    if self.digest_write_chunk.is_empty() {
                        self.phase = CommonProofMerkleMaterializerPhase::SealLeafBytes;
                        continue;
                    }
                    executor
                        .append_object_bytes(
                            storage,
                            self.digest_level_objects[0],
                            &self.digest_write_chunk,
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.digest_write_chunk.zeroize();
                    self.phase = CommonProofMerkleMaterializerPhase::SealLeafBytes;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::SealLeafBytes => {
                    executor
                        .seal_object(storage, self.leaf_bytes_object)
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.phase = CommonProofMerkleMaterializerPhase::SealLeafDigests;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::SealLeafDigests => {
                    executor
                        .seal_object(storage, self.digest_level_objects[0])
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_level_ordinal = 1;
                    self.phase = if self.digest_level_objects.len() == 1 {
                        CommonProofMerkleMaterializerPhase::ReadRoot
                    } else {
                        CommonProofMerkleMaterializerPhase::BeginParentLevel
                    };
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::BeginParentLevel => {
                    if !self.digest_write_chunk.is_empty() {
                        return Err(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    let object = *self
                        .digest_level_objects
                        .get(self.current_level_ordinal)
                        .ok_or(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ))?;
                    executor
                        .begin_object(storage, object)
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_parent_index = 0;
                    self.current_byte_offset = 0;
                    self.phase = CommonProofMerkleMaterializerPhase::ReadLeftChild;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::ReadLeftChild => {
                    let child_object = self.digest_level_objects[self.current_level_ordinal - 1];
                    let child_index = self.current_parent_index.checked_mul(2).ok_or(
                        CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow),
                    )?;
                    let storage_offset =
                        stored_hash_chunk_offset(child_index, self.current_byte_offset)
                            .map_err(CommonProofTreeStorageError::Prover)?;
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        HASH_BYTE_LENGTH,
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .read_object_bytes(
                            storage,
                            child_object,
                            storage_offset,
                            &mut self.left_child_digest[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == HASH_BYTE_LENGTH {
                        self.current_byte_offset = 0;
                        self.phase = CommonProofMerkleMaterializerPhase::ReadRightChild;
                    }
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::ReadRightChild => {
                    let child_object = self.digest_level_objects[self.current_level_ordinal - 1];
                    let child_index = self
                        .current_parent_index
                        .checked_mul(2)
                        .and_then(|index| index.checked_add(1))
                        .ok_or(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?;
                    let storage_offset =
                        stored_hash_chunk_offset(child_index, self.current_byte_offset)
                            .map_err(CommonProofTreeStorageError::Prover)?;
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        HASH_BYTE_LENGTH,
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .read_object_bytes(
                            storage,
                            child_object,
                            storage_offset,
                            &mut self.right_child_digest[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == HASH_BYTE_LENGTH {
                        self.current_leaf_digest = common_proof_merkle_node_digest(
                            self.context_hash,
                            u32::try_from(self.current_level_ordinal).map_err(|_| {
                                CommonProofTreeStorageError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                            u64::try_from(self.current_parent_index).map_err(|_| {
                                CommonProofTreeStorageError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                            self.left_child_digest,
                            self.right_child_digest,
                        )
                        .map_err(CommonProofTreeStorageError::Prover)?;
                        self.left_child_digest = [0; HASH_BYTE_LENGTH];
                        self.right_child_digest = [0; HASH_BYTE_LENGTH];
                        self.current_byte_offset = 0;
                        self.phase = CommonProofMerkleMaterializerPhase::WriteParentDigest;
                    }
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::WriteParentDigest => {
                    Self::fill_write_chunk(
                        &mut self.digest_write_chunk,
                        &self.current_leaf_digest,
                        &mut self.current_byte_offset,
                        maximum_chunk_byte_length,
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    let digest_is_buffered = self.current_byte_offset == HASH_BYTE_LENGTH;
                    if self.digest_write_chunk.len() == maximum_chunk_byte_length {
                        executor
                            .append_object_bytes(
                                storage,
                                self.digest_level_objects[self.current_level_ordinal],
                                &self.digest_write_chunk,
                            )
                            .map_err(CommonProofTreeStorageError::Storage)?;
                        self.digest_write_chunk.zeroize();
                        if digest_is_buffered {
                            self.finish_current_parent_digest()
                                .map_err(CommonProofTreeStorageError::Prover)?;
                        }
                        return Ok(
                            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted,
                        );
                    }
                    if !digest_is_buffered {
                        return Err(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.finish_current_parent_digest()
                        .map_err(CommonProofTreeStorageError::Prover)?;
                }
                CommonProofMerkleMaterializerPhase::FlushParentLevel => {
                    if self.digest_write_chunk.is_empty() {
                        self.phase = CommonProofMerkleMaterializerPhase::SealParentLevel;
                        continue;
                    }
                    executor
                        .append_object_bytes(
                            storage,
                            self.digest_level_objects[self.current_level_ordinal],
                            &self.digest_write_chunk,
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.digest_write_chunk.zeroize();
                    self.phase = CommonProofMerkleMaterializerPhase::SealParentLevel;
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::SealParentLevel => {
                    executor
                        .seal_object(
                            storage,
                            self.digest_level_objects[self.current_level_ordinal],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_level_ordinal = self.current_level_ordinal.checked_add(1).ok_or(
                        CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow),
                    )?;
                    self.phase = if self.current_level_ordinal == self.digest_level_objects.len() {
                        self.current_byte_offset = 0;
                        CommonProofMerkleMaterializerPhase::ReadRoot
                    } else {
                        CommonProofMerkleMaterializerPhase::BeginParentLevel
                    };
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::ReadRoot => {
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        HASH_BYTE_LENGTH,
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .read_object_bytes(
                            storage,
                            *self.digest_level_objects.last().ok_or(
                                CommonProofTreeStorageError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ),
                            )?,
                            u64::try_from(self.current_byte_offset).map_err(|_| {
                                CommonProofTreeStorageError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                            &mut self.root[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == HASH_BYTE_LENGTH {
                        self.phase = CommonProofMerkleMaterializerPhase::Complete;
                    }
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::Complete => {
                    return Ok(CommonProofMerkleMaterializerProgress::Complete);
                }
            }
        }
    }

    pub(crate) fn finish(self) -> Result<StoredCommonProofMerkleTree, CommonProofProverError> {
        if self.phase != CommonProofMerkleMaterializerPhase::Complete
            || self.next_leaf_index != self.leaf_count
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        Ok(StoredCommonProofMerkleTree {
            tree_catalog_index: self.tree_catalog_index,
            context: self.context,
            leaf_count: self.leaf_count,
            canonical_leaf_byte_length: self.canonical_leaf_byte_length,
            leaf_bytes_object: self.leaf_bytes_object,
            digest_level_objects: self.digest_level_objects,
            root: self.root,
        })
    }
}

fn next_bounded_offset(
    current_offset: usize,
    exact_byte_length: usize,
    maximum_chunk_byte_length: u32,
) -> Result<usize, CommonProofProverError> {
    if current_offset >= exact_byte_length || maximum_chunk_byte_length == 0 {
        return Err(CommonProofProverError::InvalidTree);
    }
    current_offset
        .checked_add(
            (exact_byte_length - current_offset).min(
                usize::try_from(maximum_chunk_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ),
        )
        .ok_or(CommonProofProverError::CountOverflow)
}

fn stored_hash_chunk_offset(
    hash_index: usize,
    within_hash_offset: usize,
) -> Result<u64, CommonProofProverError> {
    hash_index
        .checked_mul(HASH_BYTE_LENGTH)
        .and_then(|offset| offset.checked_add(within_hash_offset))
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(CommonProofProverError::CountOverflow)
}

fn append_bounded<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    object: ProofExternalMemoryObject,
    bytes: &[u8],
) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
    let maximum_chunk = usize::try_from(executor.maximum_chunk_byte_length()).map_err(|_| {
        ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        )
    })?;
    if maximum_chunk == 0 {
        return Err(ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        ));
    }
    for chunk in bytes.chunks(maximum_chunk) {
        executor.append_object_bytes(storage, object, chunk)?;
    }
    Ok(())
}

fn read_exact_bounded<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    object: ProofExternalMemoryObject,
    offset: u64,
    destination: &mut [u8],
) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
    let maximum_chunk = usize::try_from(executor.maximum_chunk_byte_length()).map_err(|_| {
        ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        )
    })?;
    if maximum_chunk == 0 {
        return Err(ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        ));
    }
    let mut relative_offset = 0_usize;
    for chunk in destination.chunks_mut(maximum_chunk) {
        let absolute_offset = offset
            .checked_add(u64::try_from(relative_offset).map_err(|_| {
                ProofExternalMemoryExecutorError::Execution(
                    super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                )
            })?)
            .ok_or(ProofExternalMemoryExecutorError::Execution(
                super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        executor.read_object_bytes(storage, object, absolute_offset, chunk)?;
        relative_offset += chunk.len();
    }
    Ok(())
}

fn read_stored_hash<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    object: ProofExternalMemoryObject,
    hash_index: usize,
) -> Result<[u8; HASH_BYTE_LENGTH], ProofExternalMemoryExecutorError<Storage::Error>> {
    let offset = hash_index
        .checked_mul(HASH_BYTE_LENGTH)
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        ))?;
    let mut digest = [0_u8; HASH_BYTE_LENGTH];
    read_exact_bounded(executor, storage, object, offset, &mut digest)?;
    Ok(digest)
}

fn common_proof_merkle_node_digest(
    context_hash: [u8; HASH_BYTE_LENGTH],
    level: u32,
    node_index: u64,
    left_child_digest: [u8; HASH_BYTE_LENGTH],
    right_child_digest: [u8; HASH_BYTE_LENGTH],
) -> Result<[u8; HASH_BYTE_LENGTH], CommonProofProverError> {
    if level == 0 {
        return Err(CommonProofProverError::InvalidTree);
    }
    let canonical_bytes = CanonicalTuple::new(
        PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(context_hash),
            CanonicalItem::unsigned32(level),
            CanonicalItem::unsigned64(node_index),
            CanonicalItem::hash512(left_child_digest),
            CanonicalItem::hash512(right_child_digest),
        ],
    )
    .encode()
    .map_err(|_| CommonProofProverError::CanonicalEncoding)?;
    Ok(hash_foundation_tuple_512(
        PROOF_MERKLE_NODE_HASH_DOMAIN,
        &[CanonicalItem::variable_bytes(canonical_bytes)
            .map_err(|_| CommonProofProverError::CanonicalEncoding)?],
    )
    .map_err(|_| CommonProofProverError::CanonicalEncoding)?
    .into_bytes())
}

/// Random-access source needed to encode one catalog-ordered opening.  Bound
/// statement trees implement the same interface from their existing canonical
/// leaf and Merkle stores; common trees use the adapter below.
pub(crate) trait CommonProofOpeningArtifact {
    type Error;

    fn tree_catalog_index(&self) -> u16;
    fn leaf_count(&self) -> usize;
    fn canonical_leaf_byte_length(&self) -> usize;
    fn read_canonical_leaf(
        &mut self,
        leaf_index: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error>;
    fn read_digest(
        &mut self,
        level: u32,
        node_index: u64,
    ) -> Result<[u8; HASH_BYTE_LENGTH], Self::Error>;
}

pub(crate) struct StoredCommonProofOpeningArtifact<'storage, Storage> {
    tree: &'storage StoredCommonProofMerkleTree,
    executor: &'storage mut ProofExternalMemoryExecutor,
    storage: &'storage mut Storage,
}

impl<'storage, Storage> StoredCommonProofOpeningArtifact<'storage, Storage> {
    pub(crate) fn new(
        tree: &'storage StoredCommonProofMerkleTree,
        executor: &'storage mut ProofExternalMemoryExecutor,
        storage: &'storage mut Storage,
    ) -> Self {
        Self {
            tree,
            executor,
            storage,
        }
    }
}

impl<Storage: ProofExternalMemory> CommonProofOpeningArtifact
    for StoredCommonProofOpeningArtifact<'_, Storage>
{
    type Error = ProofExternalMemoryExecutorError<Storage::Error>;

    fn tree_catalog_index(&self) -> u16 {
        self.tree.tree_catalog_index
    }

    fn leaf_count(&self) -> usize {
        self.tree.leaf_count
    }

    fn canonical_leaf_byte_length(&self) -> usize {
        self.tree.canonical_leaf_byte_length
    }

    fn read_canonical_leaf(
        &mut self,
        leaf_index: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        if destination.len() != self.tree.canonical_leaf_byte_length
            || leaf_index
                >= u64::try_from(self.tree.leaf_count).map_err(|_| {
                    ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    )
                })?
        {
            return Err(ProofExternalMemoryExecutorError::Execution(
                super::external_memory::ProofExternalMemoryError::WrongOffsetOrLength,
            ));
        }
        let offset = usize::try_from(leaf_index)
            .ok()
            .and_then(|index| index.checked_mul(self.tree.canonical_leaf_byte_length))
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(ProofExternalMemoryExecutorError::Execution(
                super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        read_exact_bounded(
            self.executor,
            self.storage,
            self.tree.leaf_bytes_object,
            offset,
            destination,
        )
    }

    fn read_digest(
        &mut self,
        level: u32,
        node_index: u64,
    ) -> Result<[u8; HASH_BYTE_LENGTH], Self::Error> {
        let object = self
            .tree
            .digest_level_objects
            .get(usize::try_from(level).map_err(|_| {
                ProofExternalMemoryExecutorError::Execution(
                    super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                )
            })?)
            .copied()
            .ok_or(ProofExternalMemoryExecutorError::Execution(
                super::external_memory::ProofExternalMemoryError::WrongOffsetOrLength,
            ))?;
        read_stored_hash(
            self.executor,
            self.storage,
            object,
            usize::try_from(node_index).map_err(|_| {
                ProofExternalMemoryExecutorError::Execution(
                    super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                )
            })?,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofOpeningPrefetchPhase {
    ReadLeaves,
    ReadFrontier,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofOpeningPrefetchProgress {
    StorageTransactionCompleted,
    Complete,
}

/// One tree's query material, prefetched through resumable IndexedDB reads.
/// This is the largest browser-side query working set: it is capped explicitly,
/// emitted immediately, and then dropped before the next catalog entry.
pub(crate) struct CommonProofOpeningPrefetcher {
    tree_catalog_index: u16,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    opened_leaf_indexes: Vec<u64>,
    opened_leaf_bytes: Zeroizing<Vec<u8>>,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
    phase: CommonProofOpeningPrefetchPhase,
    next_item_index: usize,
    current_byte_offset: usize,
}

impl CommonProofOpeningPrefetcher {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tree: &StoredCommonProofMerkleTree,
        catalog_entry: &ProofTreeCatalogEntry,
        evaluation_domain_size: u64,
        sorted_query_representatives: &[u64],
        maximum_prefetched_byte_length: u64,
    ) -> Result<Self, CommonProofProverError> {
        let expected_context = catalog_entry
            .common_context()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let expected_leaf_count = expected_context.leaf_count()?;
        let expected_leaf_byte_length = canonical_common_proof_leaf_byte_length(
            expected_context,
            common_proof_tree_value_type(catalog_entry)?,
        )?;
        let expected_digest_level_count = usize::try_from(expected_leaf_count.trailing_zeros())
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if tree.tree_catalog_index != catalog_entry.tree_catalog_index()
            || &tree.context != expected_context
            || tree.leaf_count != expected_leaf_count
            || tree.canonical_leaf_byte_length != expected_leaf_byte_length
            || tree.digest_level_objects.len() != expected_digest_level_count
            || maximum_prefetched_byte_length == 0
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let opened_leaf_indexes = opened_leaf_indexes(
            catalog_entry.source(),
            evaluation_domain_size,
            sorted_query_representatives,
        )?;
        let frontier_coordinates =
            minimal_frontier_coordinates(&opened_leaf_indexes, tree.leaf_count)?;
        let opened_leaf_byte_length = opened_leaf_indexes
            .len()
            .checked_mul(tree.canonical_leaf_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let frontier_byte_length = frontier_coordinates
            .len()
            .checked_mul(HASH_BYTE_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let prefetched_byte_length = opened_leaf_byte_length
            .checked_add(frontier_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if u64::try_from(prefetched_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            > maximum_prefetched_byte_length
        {
            return Err(CommonProofProverError::AllocationLimitExceeded);
        }
        let mut opened_leaf_bytes = Vec::new();
        opened_leaf_bytes
            .try_reserve_exact(opened_leaf_byte_length)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        opened_leaf_bytes.resize(opened_leaf_byte_length, 0);
        let mut frontier_digests = Vec::new();
        frontier_digests
            .try_reserve_exact(frontier_coordinates.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        frontier_digests.resize(frontier_coordinates.len(), [0; HASH_BYTE_LENGTH]);
        Ok(Self {
            tree_catalog_index: tree.tree_catalog_index,
            leaf_count: tree.leaf_count,
            canonical_leaf_byte_length: tree.canonical_leaf_byte_length,
            leaf_bytes_object: tree.leaf_bytes_object,
            digest_level_objects: tree.digest_level_objects.clone(),
            opened_leaf_indexes,
            opened_leaf_bytes: Zeroizing::new(opened_leaf_bytes),
            frontier_coordinates,
            frontier_digests,
            phase: CommonProofOpeningPrefetchPhase::ReadLeaves,
            next_item_index: 0,
            current_byte_offset: 0,
        })
    }

    pub(crate) fn advance_storage<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<CommonProofOpeningPrefetchProgress, ProofExternalMemoryExecutorError<Storage::Error>>
    {
        match self.phase {
            CommonProofOpeningPrefetchPhase::ReadLeaves => {
                if self.next_item_index == self.opened_leaf_indexes.len() {
                    self.next_item_index = 0;
                    self.current_byte_offset = 0;
                    self.phase = if self.frontier_coordinates.is_empty() {
                        CommonProofOpeningPrefetchPhase::Complete
                    } else {
                        CommonProofOpeningPrefetchPhase::ReadFrontier
                    };
                    return self.advance_storage(executor, storage);
                }
                let leaf_index = self.opened_leaf_indexes[self.next_item_index];
                let leaf_storage_offset = usize::try_from(leaf_index)
                    .ok()
                    .and_then(|index| index.checked_mul(self.canonical_leaf_byte_length))
                    .and_then(|offset| offset.checked_add(self.current_byte_offset))
                    .and_then(|offset| u64::try_from(offset).ok())
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?;
                let end_within_leaf = next_bounded_offset(
                    self.current_byte_offset,
                    self.canonical_leaf_byte_length,
                    executor.maximum_chunk_byte_length(),
                )
                .map_err(|_| {
                    ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    )
                })?;
                let destination_start = self
                    .next_item_index
                    .checked_mul(self.canonical_leaf_byte_length)
                    .and_then(|offset| offset.checked_add(self.current_byte_offset))
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?;
                let destination_end = destination_start
                    .checked_add(end_within_leaf - self.current_byte_offset)
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?;
                executor.read_object_bytes(
                    storage,
                    self.leaf_bytes_object,
                    leaf_storage_offset,
                    &mut self.opened_leaf_bytes[destination_start..destination_end],
                )?;
                self.current_byte_offset = end_within_leaf;
                if end_within_leaf == self.canonical_leaf_byte_length {
                    self.next_item_index += 1;
                    self.current_byte_offset = 0;
                }
                Ok(CommonProofOpeningPrefetchProgress::StorageTransactionCompleted)
            }
            CommonProofOpeningPrefetchPhase::ReadFrontier => {
                if self.next_item_index == self.frontier_coordinates.len() {
                    self.phase = CommonProofOpeningPrefetchPhase::Complete;
                    return Ok(CommonProofOpeningPrefetchProgress::Complete);
                }
                let (level, node_index) = self.frontier_coordinates[self.next_item_index];
                let object = *self
                    .digest_level_objects
                    .get(usize::try_from(level).map_err(|_| {
                        ProofExternalMemoryExecutorError::Execution(
                            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                        )
                    })?)
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::WrongOffsetOrLength,
                    ))?;
                let storage_offset = usize::try_from(node_index)
                    .ok()
                    .and_then(|index| index.checked_mul(HASH_BYTE_LENGTH))
                    .and_then(|offset| offset.checked_add(self.current_byte_offset))
                    .and_then(|offset| u64::try_from(offset).ok())
                    .ok_or(ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?;
                let end = next_bounded_offset(
                    self.current_byte_offset,
                    HASH_BYTE_LENGTH,
                    executor.maximum_chunk_byte_length(),
                )
                .map_err(|_| {
                    ProofExternalMemoryExecutorError::Execution(
                        super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                    )
                })?;
                executor.read_object_bytes(
                    storage,
                    object,
                    storage_offset,
                    &mut self.frontier_digests[self.next_item_index][self.current_byte_offset..end],
                )?;
                self.current_byte_offset = end;
                if end == HASH_BYTE_LENGTH {
                    self.next_item_index += 1;
                    self.current_byte_offset = 0;
                }
                Ok(CommonProofOpeningPrefetchProgress::StorageTransactionCompleted)
            }
            CommonProofOpeningPrefetchPhase::Complete => {
                Ok(CommonProofOpeningPrefetchProgress::Complete)
            }
        }
    }

    pub(crate) fn finish(
        self,
    ) -> Result<PrefetchedCommonProofOpeningArtifact, CommonProofProverError> {
        if self.phase != CommonProofOpeningPrefetchPhase::Complete {
            return Err(CommonProofProverError::InvalidOpening);
        }
        Ok(PrefetchedCommonProofOpeningArtifact {
            tree_catalog_index: self.tree_catalog_index,
            leaf_count: self.leaf_count,
            canonical_leaf_byte_length: self.canonical_leaf_byte_length,
            opened_leaf_indexes: self.opened_leaf_indexes,
            opened_leaf_bytes: self.opened_leaf_bytes,
            frontier_coordinates: self.frontier_coordinates,
            frontier_digests: self.frontier_digests,
        })
    }
}

pub(crate) struct PrefetchedCommonProofOpeningArtifact {
    tree_catalog_index: u16,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    opened_leaf_indexes: Vec<u64>,
    opened_leaf_bytes: Zeroizing<Vec<u8>>,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<[u8; HASH_BYTE_LENGTH]>,
}

impl CommonProofOpeningArtifact for PrefetchedCommonProofOpeningArtifact {
    type Error = CommonProofProverError;

    fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_byte_length
    }

    fn read_canonical_leaf(
        &mut self,
        leaf_index: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        if destination.len() != self.canonical_leaf_byte_length {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let position = self
            .opened_leaf_indexes
            .binary_search(&leaf_index)
            .map_err(|_| CommonProofProverError::InvalidOpening)?;
        let start = position
            .checked_mul(self.canonical_leaf_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let end = start
            .checked_add(self.canonical_leaf_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        destination.copy_from_slice(
            self.opened_leaf_bytes
                .get(start..end)
                .ok_or(CommonProofProverError::InvalidOpening)?,
        );
        Ok(())
    }

    fn read_digest(
        &mut self,
        level: u32,
        node_index: u64,
    ) -> Result<[u8; HASH_BYTE_LENGTH], Self::Error> {
        let position = self
            .frontier_coordinates
            .binary_search(&(level, node_index))
            .map_err(|_| CommonProofProverError::InvalidOpening)?;
        self.frontier_digests
            .get(position)
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)
    }
}

/// Streaming destination for the canonical header and proof body.  Production
/// implementations bind the final length and digest in the owning stream
/// descriptor; this interface never asks for the accumulated bytes.
pub(crate) trait CommonProofByteSink {
    type Error;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedCommonProofByteSinkError {
    ByteLengthExceeded,
    AllocationLimitExceeded,
}

/// Bounded worker-owned output for one independently appendable proof fragment
/// (the query count or one tree's opening/frontier pair).  The browser appends
/// the fragment durably, absorbs those identical bytes, drops it, and then
/// moves to the next catalog entry.
pub(crate) struct BoundedCommonProofByteSink {
    maximum_byte_length: usize,
    bytes: Vec<u8>,
}

impl BoundedCommonProofByteSink {
    pub(crate) fn new(maximum_byte_length: usize) -> Result<Self, BoundedCommonProofByteSinkError> {
        if maximum_byte_length == 0 {
            return Err(BoundedCommonProofByteSinkError::ByteLengthExceeded);
        }
        Ok(Self {
            maximum_byte_length,
            bytes: Vec::new(),
        })
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl CommonProofByteSink for BoundedCommonProofByteSink {
    type Error = BoundedCommonProofByteSinkError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let next_byte_length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(BoundedCommonProofByteSinkError::ByteLengthExceeded)?;
        if next_byte_length > self.maximum_byte_length {
            return Err(BoundedCommonProofByteSinkError::ByteLengthExceeded);
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| BoundedCommonProofByteSinkError::AllocationLimitExceeded)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

pub(crate) fn canonical_common_proof_query_section_header(
    catalog: &CompleteProofTreeCatalog,
) -> Result<[u8; 4], CommonProofProverError> {
    Ok(u32::try_from(catalog.entries().len())
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .to_le_bytes())
}

/// Encodes one catalog entry's opening/frontier pair as an independently
/// bounded fragment.  Concatenating the query-count header and these fragments
/// in catalog order is exactly the body grammar consumed by `body.rs`.
pub(crate) fn encode_common_proof_query_tree_fragment<Artifact>(
    catalog: &CompleteProofTreeCatalog,
    catalog_index: usize,
    geometry: CommonProofOpeningGeometry,
    sorted_query_representatives: &[u64],
    artifact: &mut Artifact,
    maximum_fragment_byte_length: usize,
) -> Result<Vec<u8>, CommonProofEncodingError<BoundedCommonProofByteSinkError, Artifact::Error>>
where
    Artifact: CommonProofOpeningArtifact,
{
    let entry = catalog
        .entries()
        .get(catalog_index)
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidTree,
        ))?;
    if geometry.tree_catalog_index != entry.tree_catalog_index()
        || geometry.leaf_count == 0
        || !geometry.leaf_count.is_power_of_two()
        || geometry.canonical_leaf_byte_length == 0
        || sorted_query_representatives.is_empty()
        || !sorted_query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_query_representatives
            .last()
            .is_some_and(|representative| *representative >= catalog.evaluation_domain_size() / 2)
    {
        return Err(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidOpening,
        ));
    }
    validate_common_proof_opening_geometry(entry, geometry)
        .map_err(CommonProofEncodingError::Prover)?;
    if artifact.tree_catalog_index() != entry.tree_catalog_index()
        || artifact.leaf_count() != geometry.leaf_count
        || artifact.canonical_leaf_byte_length() != geometry.canonical_leaf_byte_length
    {
        return Err(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }
    let opened_indexes = opened_leaf_indexes(
        entry.source(),
        catalog.evaluation_domain_size(),
        sorted_query_representatives,
    )
    .map_err(CommonProofEncodingError::Prover)?;
    let mut sink = BoundedCommonProofByteSink::new(maximum_fragment_byte_length)
        .map_err(CommonProofEncodingError::Sink)?;
    write_opening_record(
        &mut sink,
        entry.tree_catalog_index(),
        geometry.canonical_leaf_byte_length,
        &opened_indexes,
        artifact,
    )?;
    write_authentication_frontier(
        &mut sink,
        entry.tree_catalog_index(),
        geometry.leaf_count,
        &opened_indexes,
        artifact,
    )?;
    Ok(sink.finish())
}

/// Couples the streamed query-section bytes to the transcript without ever
/// buffering the section.  A fragment reaches the transcript only after the
/// output sink accepts the identical bytes, so a sink failure cannot advance
/// the Fiat-Shamir state past the durable proof stream.
pub(crate) struct CommonProofTranscriptQuerySink<'borrow, Sink> {
    sink: &'borrow mut Sink,
    absorber: &'borrow mut CommonProofQueryOpeningAbsorber,
}

impl<'borrow, Sink> CommonProofTranscriptQuerySink<'borrow, Sink> {
    pub(crate) const fn new(
        sink: &'borrow mut Sink,
        absorber: &'borrow mut CommonProofQueryOpeningAbsorber,
    ) -> Self {
        Self { sink, absorber }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofTranscriptQuerySinkError<SinkError> {
    Sink(SinkError),
    Transcript(TranscriptError),
}

impl<Sink: CommonProofByteSink> CommonProofByteSink for CommonProofTranscriptQuerySink<'_, Sink> {
    type Error = CommonProofTranscriptQuerySinkError<Sink::Error>;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.sink
            .write_bytes(bytes)
            .map_err(CommonProofTranscriptQuerySinkError::Sink)?;
        self.absorber
            .absorb(bytes)
            .map_err(CommonProofTranscriptQuerySinkError::Transcript)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofEncodingError<SinkError, ArtifactError> {
    Prover(CommonProofProverError),
    Sink(SinkError),
    Artifact(ArtifactError),
}

pub(crate) fn canonical_proof_object_header_bytes(
    canonical_application_statement_bytes: &[u8],
) -> Result<Vec<u8>, CommonProofProverError> {
    if canonical_application_statement_bytes.is_empty() {
        return Err(CommonProofProverError::InvalidInput);
    }
    ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.encode())
    .map_err(|_| CommonProofProverError::CanonicalEncoding)
}

/// Writes the canonical proof header followed by the complete pre-query body
/// prefix in the exact order consumed by `body.rs`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_common_proof_prefix<Sink>(
    sink: &mut Sink,
    canonical_header_bytes: &[u8],
    catalog: &CompleteProofTreeCatalog,
    tree_roots: &[[u8; HASH_BYTE_LENGTH]],
    deep_evaluations: &[ProofChallengeExtensionElement],
    terminal_coefficients: &[ProofChallengeExtensionElement],
    transcript_schedule: &CommonProofTranscriptSchedule,
) -> Result<(), CommonProofEncodingError<Sink::Error, core::convert::Infallible>>
where
    Sink: CommonProofByteSink,
{
    let expected_opening_claim_count =
        usize::try_from(transcript_schedule.opening_claim_count())
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?;
    if canonical_header_bytes.is_empty()
        || tree_roots.len() != catalog.entries().len()
        || deep_evaluations.len() != expected_opening_claim_count
        || terminal_coefficients.len()
            != usize::try_from(transcript_schedule.terminal_coefficient_count()).map_err(|_| {
                CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
            })?
    {
        return Err(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    sink.write_bytes(canonical_header_bytes)
        .map_err(CommonProofEncodingError::Sink)?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        matches!(
            source,
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                ..
            }
        )
    })?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        matches!(
            source,
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::AuxiliaryOracle,
                ..
            }
        )
    })?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        matches!(source, ProofTreeCatalogSource::QuotientComponent { .. })
    })?;
    write_extension_list(sink, deep_evaluations)?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        source == ProofTreeCatalogSource::OpeningBatchMask
    })?;
    write_roots_for_phase(sink, catalog, tree_roots, |source| {
        matches!(source, ProofTreeCatalogSource::NonterminalFriLayer { .. })
    })?;
    write_extension_list(sink, terminal_coefficients)?;
    Ok(())
}

fn write_roots_for_phase<Sink>(
    sink: &mut Sink,
    catalog: &CompleteProofTreeCatalog,
    tree_roots: &[[u8; HASH_BYTE_LENGTH]],
    mut belongs_to_phase: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<(), CommonProofEncodingError<Sink::Error, core::convert::Infallible>>
where
    Sink: CommonProofByteSink,
{
    for (entry, root) in catalog.entries().iter().zip(tree_roots) {
        if belongs_to_phase(entry.source()) {
            sink.write_bytes(root)
                .map_err(CommonProofEncodingError::Sink)?;
        }
    }
    Ok(())
}

fn write_extension_list<Sink>(
    sink: &mut Sink,
    values: &[ProofChallengeExtensionElement],
) -> Result<(), CommonProofEncodingError<Sink::Error, core::convert::Infallible>>
where
    Sink: CommonProofByteSink,
{
    write_u16(
        sink,
        CanonicalItemType::ChallengeExtensionElement.canonical_code(),
    )?;
    write_u32(
        sink,
        u32::try_from(values.len())
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?,
    )?;
    for value in values {
        for coordinate in value.canonical_coordinates() {
            sink.write_bytes(&coordinate.to_le_bytes())
                .map_err(CommonProofEncodingError::Sink)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofOpeningGeometry {
    pub(crate) tree_catalog_index: u16,
    pub(crate) leaf_count: usize,
    pub(crate) canonical_leaf_byte_length: usize,
}

/// Computes the exact query-section length before the transcript starts its
/// streamed query-opening round.
pub(crate) fn common_proof_query_section_byte_length(
    catalog: &CompleteProofTreeCatalog,
    geometries: &[CommonProofOpeningGeometry],
    sorted_query_representatives: &[u64],
) -> Result<usize, CommonProofProverError> {
    validate_query_geometry(catalog, geometries, sorted_query_representatives)?;
    let mut byte_length = 4_usize;
    for (entry, geometry) in catalog.entries().iter().zip(geometries) {
        let opened_indexes = opened_leaf_indexes(
            entry.source(),
            catalog.evaluation_domain_size(),
            sorted_query_representatives,
        )?;
        let frontier_count = minimal_frontier_node_count(&opened_indexes, geometry.leaf_count)?;
        let leaf_payload = opened_indexes
            .len()
            .checked_mul(
                geometry
                    .canonical_leaf_byte_length
                    .checked_add(4)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        byte_length = byte_length
            .checked_add(56)
            .and_then(|length| length.checked_add(leaf_payload))
            .and_then(|length| {
                length.checked_add(
                    frontier_count.checked_mul(AUTHENTICATION_NODE_CANONICAL_BYTE_LENGTH)?,
                )
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    if byte_length > u32::MAX as usize {
        return Err(CommonProofProverError::CountOverflow);
    }
    Ok(byte_length)
}

fn validate_query_geometry(
    catalog: &CompleteProofTreeCatalog,
    geometries: &[CommonProofOpeningGeometry],
    sorted_query_representatives: &[u64],
) -> Result<(), CommonProofProverError> {
    if geometries.len() != catalog.entries().len()
        || sorted_query_representatives.is_empty()
        || !sorted_query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_query_representatives
            .last()
            .is_some_and(|representative| *representative >= catalog.evaluation_domain_size() / 2)
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    for (entry, geometry) in catalog.entries().iter().zip(geometries) {
        if geometry.tree_catalog_index != entry.tree_catalog_index()
            || geometry.leaf_count == 0
            || !geometry.leaf_count.is_power_of_two()
            || geometry.canonical_leaf_byte_length == 0
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        validate_common_proof_opening_geometry(entry, *geometry)?;
    }
    Ok(())
}

fn validate_common_proof_opening_geometry(
    catalog_entry: &ProofTreeCatalogEntry,
    geometry: CommonProofOpeningGeometry,
) -> Result<(), CommonProofProverError> {
    let Some(context) = catalog_entry.common_context() else {
        return Ok(());
    };
    let expected_leaf_count = context.leaf_count()?;
    let expected_leaf_byte_length = canonical_common_proof_leaf_byte_length(
        context,
        common_proof_tree_value_type(catalog_entry)?,
    )?;
    if geometry.leaf_count != expected_leaf_count
        || geometry.canonical_leaf_byte_length != expected_leaf_byte_length
    {
        return Err(CommonProofProverError::InvalidTree);
    }
    Ok(())
}

fn write_opening_record<Sink, Artifact>(
    sink: &mut Sink,
    tree_catalog_index: u16,
    canonical_leaf_byte_length: usize,
    opened_indexes: &[u64],
    artifact: &mut Artifact,
) -> Result<(), CommonProofEncodingError<Sink::Error, Artifact::Error>>
where
    Sink: CommonProofByteSink,
    Artifact: CommonProofOpeningArtifact,
{
    write_tuple_header(sink, PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER, 2)?;
    write_u16_item(sink, tree_catalog_index)?;
    let list_payload_length = opened_indexes
        .len()
        .checked_mul(canonical_leaf_byte_length.checked_add(4).ok_or(
            CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow),
        )?)
        .and_then(|length| length.checked_add(6))
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    write_item_header(
        sink,
        CanonicalItemType::HomogeneousList,
        list_payload_length,
    )?;
    write_u16(sink, CanonicalItemType::RawBytes.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(opened_indexes.len())
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?,
    )?;
    let mut leaf_bytes = Zeroizing::new(vec![0_u8; canonical_leaf_byte_length]);
    for leaf_index in opened_indexes {
        write_u32(
            sink,
            u32::try_from(canonical_leaf_byte_length).map_err(|_| {
                CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
            })?,
        )?;
        artifact
            .read_canonical_leaf(*leaf_index, &mut leaf_bytes)
            .map_err(CommonProofEncodingError::Artifact)?;
        sink.write_bytes(&leaf_bytes)
            .map_err(CommonProofEncodingError::Sink)?;
    }
    Ok(())
}

fn write_authentication_frontier<Sink, Artifact>(
    sink: &mut Sink,
    tree_catalog_index: u16,
    leaf_count: usize,
    opened_indexes: &[u64],
    artifact: &mut Artifact,
) -> Result<(), CommonProofEncodingError<Sink::Error, Artifact::Error>>
where
    Sink: CommonProofByteSink,
    Artifact: CommonProofOpeningArtifact,
{
    let frontier_count = minimal_frontier_node_count(opened_indexes, leaf_count)
        .map_err(CommonProofEncodingError::Prover)?;
    write_tuple_header(sink, PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER, 2)?;
    write_u16_item(sink, tree_catalog_index)?;
    let list_payload_length = frontier_count
        .checked_mul(AUTHENTICATION_NODE_CANONICAL_BYTE_LENGTH)
        .and_then(|length| length.checked_add(6))
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    write_item_header(
        sink,
        CanonicalItemType::HomogeneousList,
        list_payload_length,
    )?;
    write_u16(sink, CanonicalItemType::NestedTuple.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(frontier_count)
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?,
    )?;

    let mut required = opened_indexes.iter().copied().collect::<BTreeSet<_>>();
    let mut emitted = 0_usize;
    for level in 0..leaf_count.trailing_zeros() {
        let mut next = BTreeSet::new();
        let mut processed = BTreeSet::new();
        for index in required.iter().copied() {
            if !processed.insert(index) {
                continue;
            }
            let sibling = index ^ 1;
            if required.contains(&sibling) {
                processed.insert(sibling);
            } else {
                let digest = artifact
                    .read_digest(level, sibling)
                    .map_err(CommonProofEncodingError::Artifact)?;
                write_tuple_header(sink, PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER, 3)?;
                write_u32_item(sink, level)?;
                write_u64_item(sink, sibling)?;
                write_hash_item(sink, digest)?;
                emitted += 1;
            }
            next.insert(index / 2);
        }
        required = next;
    }
    if emitted != frontier_count {
        return Err(CommonProofEncodingError::Prover(
            CommonProofProverError::InvalidOpening,
        ));
    }
    Ok(())
}

fn opened_leaf_indexes(
    source: ProofTreeCatalogSource,
    evaluation_domain_size: u64,
    sorted_query_representatives: &[u64],
) -> Result<Vec<u64>, CommonProofProverError> {
    if let ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal } = source {
        let shift = u32::from(fold_ordinal)
            .checked_add(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let leaf_count = evaluation_domain_size
            .checked_shr(shift)
            .filter(|count| *count != 0)
            .ok_or(CommonProofProverError::InvalidTree)?;
        Ok(sorted_query_representatives
            .iter()
            .map(|representative| representative % leaf_count)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    } else {
        Ok(sorted_query_representatives.to_vec())
    }
}

fn minimal_frontier_node_count(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
) -> Result<usize, CommonProofProverError> {
    Ok(minimal_frontier_coordinates(sorted_unique_leaf_indexes, leaf_count)?.len())
}

fn minimal_frontier_coordinates(
    sorted_unique_leaf_indexes: &[u64],
    leaf_count: usize,
) -> Result<Vec<(u32, u64)>, CommonProofProverError> {
    if sorted_unique_leaf_indexes.is_empty()
        || leaf_count == 0
        || !leaf_count.is_power_of_two()
        || !sorted_unique_leaf_indexes
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_unique_leaf_indexes
            .last()
            .is_some_and(|index| usize::try_from(*index).map_or(true, |index| index >= leaf_count))
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let mut required = sorted_unique_leaf_indexes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut coordinates = Vec::new();
    for level in 0..leaf_count.trailing_zeros() {
        let mut next = BTreeSet::new();
        let mut processed = BTreeSet::new();
        for index in required.iter().copied() {
            if !processed.insert(index) {
                continue;
            }
            let sibling = index ^ 1;
            if required.contains(&sibling) {
                processed.insert(sibling);
            } else {
                coordinates
                    .try_reserve(1)
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                coordinates.push((level, sibling));
            }
            next.insert(index / 2);
        }
        required = next;
    }
    Ok(coordinates)
}

fn write_tuple_header<Sink, ArtifactError>(
    sink: &mut Sink,
    schema_identifier: u16,
    item_count: u32,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    sink.write_bytes(&schema_identifier.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)?;
    sink.write_bytes(&SCHEMA_VERSION.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)?;
    sink.write_bytes(&item_count.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)
}

fn write_item_header<Sink, ArtifactError>(
    sink: &mut Sink,
    item_type: CanonicalItemType,
    byte_length: usize,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    write_u16(sink, item_type.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(byte_length)
            .map_err(|_| CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow))?,
    )
}

fn write_u16_item<Sink, ArtifactError>(
    sink: &mut Sink,
    value: u16,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    write_item_header(sink, CanonicalItemType::Unsigned16, 2)?;
    write_u16(sink, value)
}

fn write_u32_item<Sink, ArtifactError>(
    sink: &mut Sink,
    value: u32,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    write_item_header(sink, CanonicalItemType::Unsigned32, 4)?;
    write_u32(sink, value)
}

fn write_u64_item<Sink, ArtifactError>(
    sink: &mut Sink,
    value: u64,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    write_item_header(sink, CanonicalItemType::Unsigned64, 8)?;
    sink.write_bytes(&value.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)
}

fn write_hash_item<Sink, ArtifactError>(
    sink: &mut Sink,
    value: [u8; HASH_BYTE_LENGTH],
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    write_item_header(sink, CanonicalItemType::Hash512, HASH_BYTE_LENGTH)?;
    sink.write_bytes(&value)
        .map_err(CommonProofEncodingError::Sink)
}

fn write_u16<Sink, ArtifactError>(
    sink: &mut Sink,
    value: u16,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    sink.write_bytes(&value.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)
}

fn write_u32<Sink, ArtifactError>(
    sink: &mut Sink,
    value: u32,
) -> Result<(), CommonProofEncodingError<Sink::Error, ArtifactError>>
where
    Sink: CommonProofByteSink,
{
    sink.write_bytes(&value.to_le_bytes())
        .map_err(CommonProofEncodingError::Sink)
}

/// Family-owned access to the statement trees already authenticated while
/// constructing the application statement.  The common prover owns every
/// proof-created tree; this boundary exists only because committed-material
/// and setup-polynomial trees retain their canonical bytes in their owning
/// family stores.
pub(crate) trait CommonProofBoundOpeningProvider {
    type Error;

    fn opening_geometry(
        &self,
        catalog_entry: &ProofTreeCatalogEntry,
    ) -> Result<CommonProofOpeningGeometry, Self::Error>;

    fn encode_bound_opening_fragment(
        &mut self,
        catalog: &CompleteProofTreeCatalog,
        catalog_index: usize,
        geometry: CommonProofOpeningGeometry,
        sorted_query_representatives: &[u64],
        maximum_fragment_byte_length: usize,
    ) -> Result<Vec<u8>, CommonProofEncodingError<BoundedCommonProofByteSinkError, Self::Error>>;
}

/// Complete application-owned inputs for one production common-proof
/// attempt.  Only genuine pre-challenge source columns are accepted:
/// integer-lift reversed and auxiliary columns are always synthesized by the
/// common prover.
pub(crate) struct CommonProofGenerationInput<'input> {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; HASH_BYTE_LENGTH],
    pub(crate) canonical_application_statement_bytes: &'input [u8],
    pub(crate) relation_plan: &'input CompiledRelationPlan,
    pub(crate) relation_context: &'input RelationPlanCheckContext,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) relation_trees: Vec<RelationProofTreeInput>,
    pub(crate) provided_pre_challenge_columns: BTreeMap<u32, CommonProofSourcePolynomial>,
    pub(crate) maximum_external_memory_chunk_byte_length: u32,
    pub(crate) maximum_proof_transport_chunk_byte_length: usize,
    pub(crate) maximum_prefetched_query_byte_length: u64,
}

#[derive(Debug)]
pub(crate) enum CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    Prover(CommonProofProverError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    Body(ProofBodyError),
    Transcript(TranscriptError),
    StoragePlan(ProofExternalMemoryError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
    CoinSource(CoinError),
    Sink(SinkError),
    BoundOpening(BoundOpeningError),
    Cleanup {
        original:
            Box<CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError>>,
        cleanup: ProofExternalMemoryExecutorError<StorageError>,
    },
}

type CommonProofGenerationPollResult<StorageError, CoinError, SinkError, BoundOpeningError> =
    Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError>,
    >;

#[cfg(test)]
type CompletedCommonProofGenerationResult<Storage, Coins, Sink, BoundOpenings> = Result<
    (),
    CommonProofGenerationError<
        <Storage as ProofExternalMemory>::Error,
        <Coins as CommonProofPrivateCoinSource>::Error,
        <Sink as CommonProofByteSink>::Error,
        <BoundOpenings as CommonProofBoundOpeningProvider>::Error,
    >,
>;

struct GeneratedCommonProofStoragePlan {
    external_memory_plan: ProofExternalMemoryPlan,
    tree_plans: BTreeMap<u16, CommonProofMerkleStoragePlan>,
    replay_polynomial_plans:
        BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayPolynomialPlan>,
    relation_evaluation_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CommonProofReplayPolynomialKey {
    RelationColumn(u32),
    QuotientComponent(u16),
    OpeningBatchMask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommonProofReplayPolynomialPlan {
    object: ProofExternalMemoryObject,
    value_type: RelationColumnValueType,
    coefficient_count: usize,
    exact_byte_length: u64,
}

enum CommonProofReplayPolynomialRef<'polynomial> {
    Source(&'polynomial CommonProofSourcePolynomial),
    Extension(&'polynomial [ProofChallengeExtensionElement]),
}

impl CommonProofReplayPolynomialRef<'_> {
    fn value_type(&self) -> RelationColumnValueType {
        match self {
            Self::Source(polynomial) => polynomial.value_type(),
            Self::Extension(_) => RelationColumnValueType::ChallengeExtension,
        }
    }

    fn coefficient_count(&self) -> usize {
        match self {
            Self::Source(polynomial) => polynomial.coefficient_count(),
            Self::Extension(coefficients) => coefficients.len(),
        }
    }

    fn append_coefficient_bytes(
        &self,
        coefficient_index: usize,
        destination: &mut Vec<u8>,
    ) -> Result<(), CommonProofProverError> {
        match self {
            Self::Source(CommonProofSourcePolynomial::Base(coefficients)) => {
                destination.extend_from_slice(
                    &coefficients
                        .get(coefficient_index)
                        .copied()
                        .unwrap_or(ProofBaseFieldElement::ZERO)
                        .canonical()
                        .to_le_bytes(),
                );
            }
            Self::Source(CommonProofSourcePolynomial::Extension(coefficients)) => {
                for coordinate in coefficients
                    .get(coefficient_index)
                    .copied()
                    .unwrap_or(ProofChallengeExtensionElement::ZERO)
                    .canonical_coordinates()
                {
                    destination.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
            Self::Extension(coefficients) => {
                for coordinate in coefficients
                    .get(coefficient_index)
                    .copied()
                    .unwrap_or(ProofChallengeExtensionElement::ZERO)
                    .canonical_coordinates()
                {
                    destination.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayPolynomialWriterPhase {
    Begin,
    Append,
    Seal,
    Complete,
}

struct CommonProofReplayPolynomialWriter {
    plan: CommonProofReplayPolynomialPlan,
    phase: CommonProofReplayPolynomialWriterPhase,
    next_coefficient_index: usize,
    pending_coefficient_bytes: Zeroizing<Vec<u8>>,
    pending_coefficient_byte_offset: usize,
    write_chunk: Zeroizing<Vec<u8>>,
}

impl CommonProofReplayPolynomialWriter {
    fn new(
        plan: CommonProofReplayPolynomialPlan,
        polynomial: CommonProofReplayPolynomialRef<'_>,
    ) -> Result<Self, CommonProofProverError> {
        let expected_byte_length = u64::try_from(plan.coefficient_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(resident_value_byte_length(plan.value_type))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if polynomial.value_type() != plan.value_type
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count() > plan.coefficient_count
            || expected_byte_length != plan.exact_byte_length
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            plan,
            phase: CommonProofReplayPolynomialWriterPhase::Begin,
            next_coefficient_index: 0,
            pending_coefficient_bytes: Zeroizing::new(Vec::new()),
            pending_coefficient_byte_offset: 0,
            write_chunk: Zeroizing::new(Vec::new()),
        })
    }

    fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
        polynomial: CommonProofReplayPolynomialRef<'_>,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if polynomial.value_type() != self.plan.value_type
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count() > self.plan.coefficient_count
        {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        }
        match self.phase {
            CommonProofReplayPolynomialWriterPhase::Begin => {
                executor.begin_object(storage, self.plan.object)?;
                self.phase = CommonProofReplayPolynomialWriterPhase::Append;
                Ok(false)
            }
            CommonProofReplayPolynomialWriterPhase::Append => {
                let value_byte_length =
                    usize::try_from(resident_value_byte_length(self.plan.value_type))
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                let maximum_chunk_byte_length =
                    usize::try_from(executor.maximum_chunk_byte_length())
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                if maximum_chunk_byte_length == 0 {
                    return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
                }
                loop {
                    if self.write_chunk.len() == maximum_chunk_byte_length {
                        executor.append_object_bytes(
                            storage,
                            self.plan.object,
                            &self.write_chunk,
                        )?;
                        self.write_chunk.zeroize();
                        if !self.pending_coefficient_bytes.is_empty()
                            && self.pending_coefficient_byte_offset
                                == self.pending_coefficient_bytes.len()
                        {
                            self.pending_coefficient_bytes.zeroize();
                            self.pending_coefficient_byte_offset = 0;
                            self.next_coefficient_index = self
                                .next_coefficient_index
                                .checked_add(1)
                                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                        }
                        return Ok(false);
                    }
                    if self.pending_coefficient_bytes.is_empty() {
                        if self.next_coefficient_index == self.plan.coefficient_count {
                            if self.write_chunk.is_empty() {
                                executor.seal_object(storage, self.plan.object)?;
                                self.phase = CommonProofReplayPolynomialWriterPhase::Complete;
                                return Ok(true);
                            }
                            executor.append_object_bytes(
                                storage,
                                self.plan.object,
                                &self.write_chunk,
                            )?;
                            self.write_chunk.zeroize();
                            self.phase = CommonProofReplayPolynomialWriterPhase::Seal;
                            return Ok(false);
                        }
                        self.pending_coefficient_bytes
                            .try_reserve_exact(value_byte_length)
                            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                        polynomial
                            .append_coefficient_bytes(
                                self.next_coefficient_index,
                                &mut self.pending_coefficient_bytes,
                            )
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
                        if self.pending_coefficient_bytes.len() != value_byte_length {
                            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
                        }
                        self.pending_coefficient_byte_offset = 0;
                    }
                    if self.pending_coefficient_byte_offset >= self.pending_coefficient_bytes.len()
                        || self.write_chunk.len() > maximum_chunk_byte_length
                    {
                        return Err(ProofExternalMemoryError::InvalidLifecycle.into());
                    }
                    let remaining_chunk_capacity =
                        maximum_chunk_byte_length - self.write_chunk.len();
                    self.write_chunk
                        .try_reserve_exact(remaining_chunk_capacity)
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                    let copied_byte_length = remaining_chunk_capacity.min(
                        self.pending_coefficient_bytes.len() - self.pending_coefficient_byte_offset,
                    );
                    let pending_coefficient_end = self
                        .pending_coefficient_byte_offset
                        .checked_add(copied_byte_length)
                        .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                    self.write_chunk.extend_from_slice(
                        &self.pending_coefficient_bytes
                            [self.pending_coefficient_byte_offset..pending_coefficient_end],
                    );
                    self.pending_coefficient_byte_offset = pending_coefficient_end;
                    if self.write_chunk.len() < maximum_chunk_byte_length
                        && self.pending_coefficient_byte_offset
                            == self.pending_coefficient_bytes.len()
                    {
                        self.pending_coefficient_bytes.zeroize();
                        self.pending_coefficient_byte_offset = 0;
                        self.next_coefficient_index = self
                            .next_coefficient_index
                            .checked_add(1)
                            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                    }
                }
            }
            CommonProofReplayPolynomialWriterPhase::Seal => {
                executor.seal_object(storage, self.plan.object)?;
                self.phase = CommonProofReplayPolynomialWriterPhase::Complete;
                Ok(true)
            }
            CommonProofReplayPolynomialWriterPhase::Complete => Ok(true),
        }
    }
}

enum CommonProofReplayPolynomialCoefficients {
    Base(Vec<ProofBaseFieldElement>),
    Extension(Vec<ProofChallengeExtensionElement>),
}

struct CommonProofReplayPolynomialReader {
    plan: CommonProofReplayPolynomialPlan,
    next_coefficient_index: usize,
    coefficients: CommonProofReplayPolynomialCoefficients,
}

impl CommonProofReplayPolynomialReader {
    fn new(plan: CommonProofReplayPolynomialPlan) -> Result<Self, CommonProofProverError> {
        let expected_byte_length = u64::try_from(plan.coefficient_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(resident_value_byte_length(plan.value_type))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if plan.coefficient_count == 0 || expected_byte_length != plan.exact_byte_length {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let coefficients = match plan.value_type {
            RelationColumnValueType::BaseField => {
                CommonProofReplayPolynomialCoefficients::Base(Vec::new())
            }
            RelationColumnValueType::ChallengeExtension => {
                CommonProofReplayPolynomialCoefficients::Extension(Vec::new())
            }
        };
        Ok(Self {
            plan,
            next_coefficient_index: 0,
            coefficients,
        })
    }

    fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.next_coefficient_index >= self.plan.coefficient_count {
            return Ok(true);
        }
        let value_byte_length = usize::try_from(resident_value_byte_length(self.plan.value_type))
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let maximum_coefficient_count = usize::try_from(executor.maximum_chunk_byte_length())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
            .checked_div(value_byte_length)
            .filter(|count| *count != 0)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let coefficient_count = maximum_coefficient_count
            .min(self.plan.coefficient_count - self.next_coefficient_index);
        let byte_length = coefficient_count
            .checked_mul(value_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(byte_length)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        bytes.resize(byte_length, 0);
        let offset = self
            .next_coefficient_index
            .checked_mul(value_byte_length)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        executor.read_object_bytes(storage, self.plan.object, offset, &mut bytes)?;
        match &mut self.coefficients {
            CommonProofReplayPolynomialCoefficients::Base(coefficients) => {
                coefficients
                    .try_reserve_exact(coefficient_count)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                for encoded in bytes.chunks_exact(8) {
                    let mut value = [0_u8; 8];
                    value.copy_from_slice(encoded);
                    coefficients.push(
                        ProofBaseFieldElement::from_canonical(u64::from_le_bytes(value))
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
                    );
                }
            }
            CommonProofReplayPolynomialCoefficients::Extension(coefficients) => {
                coefficients
                    .try_reserve_exact(coefficient_count)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                for encoded in bytes.chunks_exact(value_byte_length) {
                    let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
                    for (coordinate, coordinate_bytes) in
                        coordinates.iter_mut().zip(encoded.chunks_exact(8))
                    {
                        let mut value = [0_u8; 8];
                        value.copy_from_slice(coordinate_bytes);
                        *coordinate = u64::from_le_bytes(value);
                    }
                    coefficients.push(
                        ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
                    );
                }
            }
        }
        self.next_coefficient_index += coefficient_count;
        Ok(self.next_coefficient_index == self.plan.coefficient_count)
    }

    fn finish(self) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        if self.next_coefficient_index != self.plan.coefficient_count {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(match self.coefficients {
            CommonProofReplayPolynomialCoefficients::Base(mut coefficients) => {
                while coefficients.len() > 1
                    && coefficients.last() == Some(&ProofBaseFieldElement::ZERO)
                {
                    coefficients.pop();
                }
                CommonProofSourcePolynomial::Base(coefficients)
            }
            CommonProofReplayPolynomialCoefficients::Extension(mut coefficients) => {
                trim_extension_polynomial(&mut coefficients);
                CommonProofSourcePolynomial::Extension(coefficients)
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeneratedCommonProofStoragePlanError {
    Prover(CommonProofProverError),
    Storage(ProofExternalMemoryError),
}

fn checked_add_u64(left: u64, right: u64) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    left.checked_add(right)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))
}

fn checked_multiply_u64(
    left: u64,
    right: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    left.checked_mul(right)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))
}

fn ceiling_division_u64(
    numerator: u64,
    denominator: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    if numerator == 0 || denominator == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    Ok(numerator.checked_add(denominator - 1).ok_or(
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
    )? / denominator)
}

fn exact_peak_stored_byte_length(
    object_plans: &[ProofExternalMemoryObjectPlan],
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    let event_count =
        object_plans
            .len()
            .checked_mul(2)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
    let mut liveness_events = Vec::new();
    liveness_events
        .try_reserve_exact(event_count)
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::AllocationLimitExceeded,
            )
        })?;
    for object_plan in object_plans {
        liveness_events.push((
            object_plan.issued_step(),
            true,
            object_plan.exact_byte_length(),
        ));
        liveness_events.push((
            object_plan.last_use_step().checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?,
            false,
            object_plan.exact_byte_length(),
        ));
    }
    liveness_events.sort_unstable_by_key(|(step, is_issuance, _)| (*step, *is_issuance));
    let mut live_byte_length = 0_u64;
    let mut peak_stored_byte_length = 0_u64;
    for (_, is_issuance, byte_length) in liveness_events {
        if is_issuance {
            live_byte_length = checked_add_u64(live_byte_length, byte_length)?;
            peak_stored_byte_length = peak_stored_byte_length.max(live_byte_length);
        } else {
            live_byte_length = live_byte_length.checked_sub(byte_length).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidInput),
            )?;
        }
    }
    if live_byte_length != 0 || peak_stored_byte_length == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    Ok(peak_stored_byte_length)
}

fn common_tree_materialization_write_transaction_count(
    leaf_count: u64,
    canonical_leaf_byte_length: u64,
    chunk_byte_length: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    if !leaf_count.is_power_of_two() {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    let leaf_object_byte_length = checked_multiply_u64(leaf_count, canonical_leaf_byte_length)?;
    let mut transaction_count = ceiling_division_u64(leaf_object_byte_length, chunk_byte_length)?;
    let mut level_node_count = leaf_count;
    loop {
        let level_byte_length = checked_multiply_u64(level_node_count, HASH_BYTE_LENGTH as u64)?;
        transaction_count = checked_add_u64(
            transaction_count,
            ceiling_division_u64(level_byte_length, chunk_byte_length)?,
        )?;
        if level_node_count == 1 {
            break;
        }
        level_node_count /= 2;
    }
    Ok(transaction_count)
}

fn common_tree_materialization_phase(source: ProofTreeCatalogSource) -> Option<u8> {
    match source {
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::BaseOracle,
            ..
        } => Some(0),
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::AuxiliaryOracle,
            ..
        } => Some(1),
        ProofTreeCatalogSource::QuotientComponent { .. } => Some(2),
        ProofTreeCatalogSource::OpeningBatchMask => Some(3),
        ProofTreeCatalogSource::NonterminalFriLayer { .. } => Some(4),
        ProofTreeCatalogSource::RelationProofCreated { .. }
        | ProofTreeCatalogSource::RelationBoundPublic => None,
    }
}

/// Generates the exact object liveness graph for every common tree.  Read and
/// transaction ceilings include worst-case query collisions and frontiers;
/// they are operational limits, never proof fields.
fn generated_common_proof_storage_plan(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    catalog: &CompleteProofTreeCatalog,
    transcript_schedule: &CommonProofTranscriptSchedule,
    maximum_chunk_byte_length: u32,
    include_replay_polynomials: bool,
) -> Result<GeneratedCommonProofStoragePlan, GeneratedCommonProofStoragePlanError> {
    if maximum_chunk_byte_length == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    let mut common_entries = catalog
        .entries()
        .iter()
        .filter_map(|entry| {
            common_tree_materialization_phase(entry.source())
                .map(|phase| (phase, entry.tree_catalog_index(), entry))
        })
        .collect::<Vec<_>>();
    common_entries.sort_unstable_by_key(|(phase, catalog_index, _)| (*phase, *catalog_index));
    if common_entries.is_empty() {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }

    let base_tree_count = common_entries
        .iter()
        .take_while(|(phase, _, _)| *phase == 0)
        .count();
    let relation_replay_step = u32::try_from(base_tree_count).map_err(|_| {
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let transform_pass_count = if include_replay_polynomials {
        u32::try_from(variant.ordered_columns().len())
            .ok()
            .and_then(|column_count| {
                column_count.checked_mul(variant.evaluation_domain_size().trailing_zeros())
            })
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?
    } else {
        0
    };
    let first_relation_transform_step = relation_replay_step
        .checked_add(if include_replay_polynomials { 1 } else { 0 })
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let first_post_challenge_tree_step = first_relation_transform_step
        .checked_add(transform_pass_count)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let mut materialization_steps = BTreeMap::new();
    let mut next_post_challenge_tree_step = first_post_challenge_tree_step;
    for (materialization_index, (phase, catalog_index, _)) in common_entries.iter().enumerate() {
        let materialization_step = if *phase == 0 {
            u32::try_from(materialization_index).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?
        } else {
            let step = next_post_challenge_tree_step;
            next_post_challenge_tree_step = next_post_challenge_tree_step.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
            step
        };
        if materialization_steps
            .insert(*catalog_index, materialization_step)
            .is_some()
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
    }
    let mut last_relation_evaluation_use_steps = BTreeMap::new();
    for (tree_index, descriptor) in variant.ordered_trees().iter().enumerate() {
        let RelationTreeDescriptor::ProofCreated {
            proof_tree_role: 2,
            ordered_column_ordinals,
        } = descriptor
        else {
            continue;
        };
        let tree_catalog_index = u16::try_from(tree_index).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let materialization_step = *materialization_steps.get(&tree_catalog_index).ok_or(
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidTree),
        )?;
        for column_ordinal in ordered_column_ordinals {
            last_relation_evaluation_use_steps
                .entry(*column_ordinal)
                .and_modify(|last_use_step: &mut u32| {
                    *last_use_step = (*last_use_step).max(materialization_step);
                })
                .or_insert(materialization_step);
        }
    }
    let query_step = next_post_challenge_tree_step;
    let step_count =
        query_step
            .checked_add(1)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
    let chunk_byte_length = u64::from(maximum_chunk_byte_length);
    let hash_read_transaction_count =
        ceiling_division_u64(HASH_BYTE_LENGTH as u64, chunk_byte_length)?;
    let maximum_opened_leaf_count = u64::from(transcript_schedule.unique_query_count());

    let mut next_object_ordinal = 0_u32;
    let mut object_plans = Vec::new();
    let mut tree_plans = BTreeMap::new();
    let mut replay_polynomial_plans = BTreeMap::new();
    let mut relation_evaluation_transform_plans = BTreeMap::new();
    let mut maximum_total_written_byte_length = 0_u64;
    let mut maximum_total_read_byte_length = 0_u64;
    let mut maximum_transaction_count = 0_u64;

    for (_, catalog_index, entry) in &common_entries {
        let materialization_step = *materialization_steps.get(catalog_index).ok_or(
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidTree),
        )?;
        let tree_plan = common_proof_merkle_storage_plan(
            entry,
            next_object_ordinal,
            materialization_step,
            query_step,
        )
        .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        next_object_ordinal = tree_plan.next_object_ordinal();
        let context =
            entry
                .common_context()
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
        let leaf_count = u64::try_from(
            context
                .leaf_count()
                .map_err(CommonProofProverError::from)
                .map_err(GeneratedCommonProofStoragePlanError::Prover)?,
        )
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let opened_leaf_count = maximum_opened_leaf_count.min(leaf_count);
        let tree_height = u64::from(leaf_count.trailing_zeros());
        let frontier_node_bound = checked_multiply_u64(opened_leaf_count, tree_height)?;
        let construction_digest_read_count = leaf_count
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        let construction_read_byte_length =
            checked_multiply_u64(construction_digest_read_count, HASH_BYTE_LENGTH as u64)?;
        let query_leaf_read_byte_length = checked_multiply_u64(
            opened_leaf_count,
            u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?,
        )?;
        let query_frontier_read_byte_length =
            checked_multiply_u64(frontier_node_bound, HASH_BYTE_LENGTH as u64)?;
        maximum_total_read_byte_length = checked_add_u64(
            maximum_total_read_byte_length,
            checked_add_u64(
                construction_read_byte_length,
                checked_add_u64(query_leaf_read_byte_length, query_frontier_read_byte_length)?,
            )?,
        )?;
        if matches!(
            entry.source(),
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::AuxiliaryOracle,
                ..
            }
        ) {
            let descriptor = variant
                .ordered_trees()
                .get(usize::from(*catalog_index))
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role: 2,
                ordered_column_ordinals,
            } = descriptor
            else {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            };
            let mut row_byte_length = 0_u64;
            for column_ordinal in ordered_column_ordinals {
                let column = variant
                    .ordered_columns()
                    .get(usize::try_from(*column_ordinal).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                row_byte_length = checked_add_u64(
                    row_byte_length,
                    resident_value_byte_length(column.value_type()),
                )?;
            }
            let paired_leaf_value_count =
                leaf_count
                    .checked_mul(2)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                checked_multiply_u64(paired_leaf_value_count, row_byte_length)?,
            )?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                checked_multiply_u64(
                    paired_leaf_value_count,
                    u64::try_from(ordered_column_ordinals.len()).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?,
                )?,
            )?;
        }

        let object_count = u64::try_from(tree_plan.object_plans().len()).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_multiply_u64(object_count, 2)?,
        )?;
        for object_plan in tree_plan.object_plans() {
            maximum_total_written_byte_length = checked_add_u64(
                maximum_total_written_byte_length,
                object_plan.exact_byte_length(),
            )?;
        }
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            common_tree_materialization_write_transaction_count(
                leaf_count,
                u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                chunk_byte_length,
            )?,
        )?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_multiply_u64(construction_digest_read_count, hash_read_transaction_count)?,
        )?;
        let query_leaf_read_transaction_count = checked_multiply_u64(
            opened_leaf_count,
            ceiling_division_u64(
                u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                chunk_byte_length,
            )?,
        )?;
        let query_frontier_read_transaction_count =
            checked_multiply_u64(frontier_node_bound, hash_read_transaction_count)?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_add_u64(
                query_leaf_read_transaction_count,
                query_frontier_read_transaction_count,
            )?,
        )?;

        object_plans.extend_from_slice(tree_plan.object_plans());
        if tree_plans.insert(*catalog_index, tree_plan).is_some() {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
    }
    if include_replay_polynomials {
        if relation_replay_step >= query_step {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let replay_protection = match variant.proof_privacy_mode() {
            ProofPrivacyMode::PublicOnly => ProofExternalMemoryProtection::PublicIntegrity,
            ProofPrivacyMode::SecretBearing => {
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption
            }
        };
        let mut replay_specifications = Vec::new();
        replay_specifications
            .try_reserve_exact(
                variant
                    .ordered_columns()
                    .len()
                    .checked_add(usize::from(transcript_schedule.quotient_component_count()))
                    .and_then(|count| {
                        count.checked_add(
                            if transcript_schedule.privacy_mode()
                                == CommonProofPrivacyMode::SecretBearing
                            {
                                1
                            } else {
                                0
                            },
                        )
                    })
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?,
            )
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::AllocationLimitExceeded,
                )
            })?;
        for (column_index, column) in variant.ordered_columns().iter().enumerate() {
            replay_specifications.push((
                CommonProofReplayPolynomialKey::RelationColumn(
                    u32::try_from(column_index).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?,
                ),
                column.value_type(),
                usize::try_from(column.source_degree_bound_exclusive()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                relation_replay_step,
            ));
        }
        for (_, catalog_index, entry) in &common_entries {
            match entry.source() {
                ProofTreeCatalogSource::QuotientComponent { component_ordinal } => {
                    replay_specifications.push((
                        CommonProofReplayPolynomialKey::QuotientComponent(component_ordinal),
                        RelationColumnValueType::ChallengeExtension,
                        usize::try_from(relation_context.quotient_component_degree_bound_exclusive)
                            .map_err(|_| {
                                GeneratedCommonProofStoragePlanError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                        *materialization_steps.get(catalog_index).ok_or(
                            GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidTree,
                            ),
                        )?,
                    ));
                }
                ProofTreeCatalogSource::OpeningBatchMask => {
                    let mut descriptors = variant.ordered_masks().iter().copied().filter(|mask| {
                        mask.mask_kind() == RelationMaskKind::OpeningBatch
                            && mask.target_class() == RelationMaskTargetClass::Batch
                            && mask.target_ordinal() == 0
                    });
                    let descriptor =
                        descriptors
                            .next()
                            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidMask,
                            ))?;
                    if descriptors.next().is_some() {
                        return Err(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::InvalidMask,
                        ));
                    }
                    replay_specifications.push((
                        CommonProofReplayPolynomialKey::OpeningBatchMask,
                        RelationColumnValueType::ChallengeExtension,
                        usize::try_from(descriptor.mask_degree_bound_exclusive()).map_err(
                            |_| {
                                GeneratedCommonProofStoragePlanError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            },
                        )?,
                        *materialization_steps.get(catalog_index).ok_or(
                            GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidTree,
                            ),
                        )?,
                    ));
                }
                ProofTreeCatalogSource::RelationProofCreated { .. }
                | ProofTreeCatalogSource::NonterminalFriLayer { .. }
                | ProofTreeCatalogSource::RelationBoundPublic => {}
            }
        }
        let maximum_replay_count = u64::from(transcript_schedule.opening_claim_count())
            .checked_mul(2)
            .and_then(|count| {
                u64::try_from(catalog.entries().len())
                    .ok()
                    .and_then(|catalog_entry_count| count.checked_add(catalog_entry_count))
            })
            .and_then(|count| count.checked_add(u64::from(transcript_schedule.fri_fold_count())))
            .and_then(|count| count.checked_add(4))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        for (key, value_type, coefficient_count, issued_step) in replay_specifications {
            if coefficient_count == 0 || issued_step >= query_step {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
            let exact_byte_length = checked_multiply_u64(
                u64::try_from(coefficient_count).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                resident_value_byte_length(value_type),
            )?;
            let object = ProofExternalMemoryObject::new(next_object_ordinal);
            next_object_ordinal = next_object_ordinal.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
            object_plans.push(ProofExternalMemoryObjectPlan::new(
                object,
                replay_protection,
                exact_byte_length,
                issued_step,
                issued_step,
                query_step,
            ));
            maximum_total_written_byte_length =
                checked_add_u64(maximum_total_written_byte_length, exact_byte_length)?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                checked_multiply_u64(exact_byte_length, maximum_replay_count)?,
            )?;
            let object_chunk_count = ceiling_division_u64(exact_byte_length, chunk_byte_length)?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                checked_add_u64(
                    2,
                    checked_add_u64(
                        object_chunk_count,
                        checked_multiply_u64(object_chunk_count, maximum_replay_count)?,
                    )?,
                )?,
            )?;
            if replay_polynomial_plans
                .insert(
                    key,
                    CommonProofReplayPolynomialPlan {
                        object,
                        value_type,
                        coefficient_count,
                        exact_byte_length,
                    },
                )
                .is_some()
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
        }

        let evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(variant.evaluation_domain_size()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?,
            relation_context.evaluation_coset_offset,
        )
        .map_err(CommonProofProverError::from)
        .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        for (column_index, _) in variant.ordered_columns().iter().enumerate() {
            let column_ordinal = u32::try_from(column_index).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
            let source_plan = replay_polynomial_plans
                .get(&CommonProofReplayPolynomialKey::RelationColumn(
                    column_ordinal,
                ))
                .copied()
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            let source = ExternalPolynomialVector::new(
                source_plan.object,
                source_plan.value_type,
                source_plan.coefficient_count,
            )
            .map_err(map_external_polynomial_plan_error)
            .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
            let first_executor_step = first_relation_transform_step
                .checked_add(
                    column_ordinal
                        .checked_mul(evaluation_domain.size().trailing_zeros())
                        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?,
                )
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            let transform_plan = ExternalStockhamTransformPlan::new(
                evaluation_domain,
                ExternalStockhamTransformDirection::Forward,
                source,
                next_object_ordinal,
                first_executor_step,
                last_relation_evaluation_use_steps
                    .get(&column_ordinal)
                    .copied()
                    .unwrap_or(first_post_challenge_tree_step),
                maximum_chunk_byte_length,
                replay_protection,
            )
            .map_err(map_external_polynomial_plan_error)
            .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
            if transform_plan.next_executor_step()
                != first_executor_step
                    .checked_add(evaluation_domain.size().trailing_zeros())
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            next_object_ordinal = transform_plan.next_object_ordinal();
            maximum_total_written_byte_length = checked_add_u64(
                maximum_total_written_byte_length,
                transform_plan.total_written_byte_length(),
            )?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                transform_plan.total_read_byte_length(),
            )?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                transform_plan.maximum_transaction_count(),
            )?;
            object_plans.extend_from_slice(transform_plan.object_plans());
            if relation_evaluation_transform_plans
                .insert(column_ordinal, transform_plan)
                .is_some()
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
        }
    }
    // One deletion transaction for each materialized root and one final
    // transaction for all query-live leaf/frontier objects.
    maximum_transaction_count = checked_add_u64(
        maximum_transaction_count,
        u64::try_from(common_entries.len())
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?
            .checked_add(1 + u64::from(include_replay_polynomials))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?,
    )?;
    let maximum_transaction_operation_count = u32::try_from(object_plans.len()).map_err(|_| {
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let maximum_stored_byte_length = exact_peak_stored_byte_length(&object_plans)?;
    let external_memory_plan = ProofExternalMemoryPlan::new(
        step_count,
        maximum_chunk_byte_length,
        chunk_byte_length,
        maximum_transaction_operation_count,
        maximum_stored_byte_length,
        maximum_total_written_byte_length,
        maximum_total_read_byte_length,
        maximum_transaction_count,
        object_plans,
    )
    .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
    Ok(GeneratedCommonProofStoragePlan {
        external_memory_plan,
        tree_plans,
        replay_polynomial_plans,
        relation_evaluation_transform_plans,
    })
}

fn validate_generation_relation_trees(
    variant: &RelationPlanVariant,
    relation_trees: &[RelationProofTreeInput],
) -> Result<(), CommonProofProverError> {
    if relation_trees.len() != variant.ordered_trees().len() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for (descriptor, input) in variant.ordered_trees().iter().zip(relation_trees) {
        match (descriptor, input) {
            (
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                },
                RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width,
                    leaf_visibility,
                },
            ) => {
                let expected_role = match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(CommonProofProverError::InvalidTree),
                };
                let expected_width = u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                let expected_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|index| variant.ordered_columns().get(index))
                        .is_some_and(|column| column.origin() == &RelationColumnOrigin::Prover)
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                if *tree_role != expected_role
                    || *row_width != expected_width
                    || *leaf_visibility != expected_visibility
                {
                    return Err(CommonProofProverError::InvalidTree);
                }
                validate_generation_tree_columns(variant, ordered_column_ordinals, None)?;
            }
            (
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    expected_root_source_ordinal,
                    ordered_column_ordinals,
                    ..
                },
                RelationProofTreeInput::BoundPublic(statement_tree),
            ) => {
                validate_generation_tree_columns(
                    variant,
                    ordered_column_ordinals,
                    Some(*expected_root_source_ordinal),
                )?;
                let construction_matches = match (construction_kind, statement_tree) {
                    (
                        BoundTreeConstructionKind::CommittedMaterial,
                        StatementOwnedProofTreeInput::CommittedMaterial { .. },
                    ) => ordered_column_ordinals.len() == 4,
                    (
                        BoundTreeConstructionKind::SetupPolynomial,
                        StatementOwnedProofTreeInput::SetupPolynomial { row_width, .. },
                    ) => usize::try_from(*row_width)
                        .is_ok_and(|width| width == ordered_column_ordinals.len()),
                    _ => false,
                };
                if !construction_matches {
                    return Err(CommonProofProverError::InvalidTree);
                }
            }
            _ => return Err(CommonProofProverError::InvalidTree),
        }
    }
    Ok(())
}

fn validate_generation_tree_columns(
    variant: &RelationPlanVariant,
    ordered_column_ordinals: &[u32],
    expected_bound_root_source_ordinal: Option<u32>,
) -> Result<(), CommonProofProverError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for column_ordinal in ordered_column_ordinals {
        let column = variant
            .ordered_columns()
            .get(
                usize::try_from(*column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if column.value_type() != RelationColumnValueType::BaseField {
            return Err(CommonProofProverError::InvalidTree);
        }
        match (column.origin(), expected_bound_root_source_ordinal) {
            (
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                },
                Some(expected),
            ) if *expected_root_source_ordinal == expected => {}
            (RelationColumnOrigin::BoundTree { .. }, _) | (_, Some(_)) => {
                return Err(CommonProofProverError::InvalidTree);
            }
            (_, None) => {}
        }
    }
    Ok(())
}

fn statement_owned_tree_root(input: &RelationProofTreeInput) -> Option<[u8; HASH_BYTE_LENGTH]> {
    match input {
        RelationProofTreeInput::BoundPublic(
            StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. }
            | StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. },
        ) => Some(*expected_root),
        RelationProofTreeInput::ProofCreated { .. } => None,
    }
}

fn unique_catalog_entry(
    catalog: &CompleteProofTreeCatalog,
    mut predicate: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<&ProofTreeCatalogEntry, CommonProofProverError> {
    let mut matches = catalog
        .entries()
        .iter()
        .filter(|entry| predicate(entry.source()));
    let entry = matches.next().ok_or(CommonProofProverError::InvalidTree)?;
    if matches.next().is_some() {
        return Err(CommonProofProverError::InvalidTree);
    }
    Ok(entry)
}

fn map_private_coin_generation_error<StorageError, CoinError, SinkError, BoundOpeningError>(
    error: CommonProofPrivateCoinError<CoinError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    match error {
        CommonProofPrivateCoinError::Prover(error) => CommonProofGenerationError::Prover(error),
        CommonProofPrivateCoinError::CoinSource(error) => {
            CommonProofGenerationError::CoinSource(error)
        }
    }
}

fn insert_materialized_tree(
    tree: StoredCommonProofMerkleTree,
    tree_roots: &mut [[u8; HASH_BYTE_LENGTH]],
    root_present: &mut [bool],
    stored_trees: &mut BTreeMap<u16, StoredCommonProofMerkleTree>,
) -> Result<(), CommonProofProverError> {
    let catalog_index = tree.tree_catalog_index();
    let tree_index = usize::from(catalog_index);
    let root = tree.root();
    let destination = tree_roots
        .get_mut(tree_index)
        .ok_or(CommonProofProverError::InvalidTree)?;
    let presence = root_present
        .get_mut(tree_index)
        .ok_or(CommonProofProverError::InvalidTree)?;
    if *presence || stored_trees.insert(catalog_index, tree).is_some() {
        return Err(CommonProofProverError::InvalidTree);
    }
    *destination = root;
    *presence = true;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationInitializationError {
    Prover(CommonProofProverError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    Body(ProofBodyError),
    Transcript(TranscriptError),
    StoragePlan(ProofExternalMemoryError),
}

pub(crate) const MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH: u64 = 402_653_184;
const COMMON_PROOF_EXECUTOR_RESIDENT_RESERVE_BYTE_LENGTH: u64 = 33_554_432;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CommonProofResidentMemoryPhase {
    PreparingInputs = 1,
    MaterializingRelationTree = 2,
    DerivingApplicationColumns = 3,
    PersistingRelationColumns = 4,
    ConstructingQuotient = 5,
    MaterializingQuotientTree = 6,
    DerivingOpenings = 7,
    ConstructingInitialFri = 8,
    FoldingFri = 9,
    EmittingQueries = 10,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofResidentMemoryPhasePlan {
    phase: CommonProofResidentMemoryPhase,
    executor_reserve_byte_length: u64,
    relation_column_catalog_byte_length: u64,
    trace_row_cache_byte_length: u64,
    trace_synthesis_scratch_byte_length: u64,
    replay_source_byte_length: u64,
    primary_vector_byte_length: u64,
    secondary_vector_byte_length: u64,
    claim_and_query_metadata_byte_length: u64,
    relation_rotation_block_byte_length: u64,
    external_working_set_byte_length: u64,
    query_prefetch_byte_length: u64,
    stream_window_byte_length: u64,
    total_byte_length: u64,
}

impl CommonProofResidentMemoryPhasePlan {
    pub(crate) const fn phase(&self) -> CommonProofResidentMemoryPhase {
        self.phase
    }

    pub(crate) const fn executor_reserve_byte_length(&self) -> u64 {
        self.executor_reserve_byte_length
    }

    pub(crate) const fn relation_column_catalog_byte_length(&self) -> u64 {
        self.relation_column_catalog_byte_length
    }

    pub(crate) const fn trace_row_cache_byte_length(&self) -> u64 {
        self.trace_row_cache_byte_length
    }

    pub(crate) const fn trace_synthesis_scratch_byte_length(&self) -> u64 {
        self.trace_synthesis_scratch_byte_length
    }

    pub(crate) const fn replay_source_byte_length(&self) -> u64 {
        self.replay_source_byte_length
    }

    pub(crate) const fn primary_vector_byte_length(&self) -> u64 {
        self.primary_vector_byte_length
    }

    pub(crate) const fn secondary_vector_byte_length(&self) -> u64 {
        self.secondary_vector_byte_length
    }

    pub(crate) const fn claim_and_query_metadata_byte_length(&self) -> u64 {
        self.claim_and_query_metadata_byte_length
    }

    pub(crate) const fn relation_rotation_block_byte_length(&self) -> u64 {
        self.relation_rotation_block_byte_length
    }

    pub(crate) const fn external_working_set_byte_length(&self) -> u64 {
        self.external_working_set_byte_length
    }

    pub(crate) const fn query_prefetch_byte_length(&self) -> u64 {
        self.query_prefetch_byte_length
    }

    pub(crate) const fn stream_window_byte_length(&self) -> u64 {
        self.stream_window_byte_length
    }

    pub(crate) const fn total_byte_length(&self) -> u64 {
        self.total_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofResidentMemoryPlan {
    phases: Vec<CommonProofResidentMemoryPhasePlan>,
    peak_byte_length: u64,
}

impl CommonProofResidentMemoryPlan {
    pub(crate) fn phases(&self) -> &[CommonProofResidentMemoryPhasePlan] {
        &self.phases
    }

    pub(crate) const fn peak_byte_length(&self) -> u64 {
        self.peak_byte_length
    }
}

fn checked_resident_add(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_add(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn checked_resident_multiply(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_mul(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn resident_value_byte_length(value_type: RelationColumnValueType) -> u64 {
    match value_type {
        RelationColumnValueType::BaseField => 8,
        RelationColumnValueType::ChallengeExtension => {
            u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE).expect("extension degree fits u64") * 8
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resident_phase_plan(
    phase: CommonProofResidentMemoryPhase,
    relation_column_catalog_byte_length: u64,
    trace_row_cache_byte_length: u64,
    trace_synthesis_scratch_byte_length: u64,
    replay_source_byte_length: u64,
    primary_vector_byte_length: u64,
    secondary_vector_byte_length: u64,
    claim_and_query_metadata_byte_length: u64,
    relation_rotation_block_byte_length: u64,
    external_working_set_byte_length: u64,
    query_prefetch_byte_length: u64,
    stream_window_byte_length: u64,
) -> Result<CommonProofResidentMemoryPhasePlan, CommonProofProverError> {
    let total_byte_length = [
        COMMON_PROOF_EXECUTOR_RESIDENT_RESERVE_BYTE_LENGTH,
        relation_column_catalog_byte_length,
        trace_row_cache_byte_length,
        trace_synthesis_scratch_byte_length,
        replay_source_byte_length,
        primary_vector_byte_length,
        secondary_vector_byte_length,
        claim_and_query_metadata_byte_length,
        relation_rotation_block_byte_length,
        external_working_set_byte_length,
        query_prefetch_byte_length,
        stream_window_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_resident_add)?;
    if total_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
        return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
    }
    Ok(CommonProofResidentMemoryPhasePlan {
        phase,
        executor_reserve_byte_length: COMMON_PROOF_EXECUTOR_RESIDENT_RESERVE_BYTE_LENGTH,
        relation_column_catalog_byte_length,
        trace_row_cache_byte_length,
        trace_synthesis_scratch_byte_length,
        replay_source_byte_length,
        primary_vector_byte_length,
        secondary_vector_byte_length,
        claim_and_query_metadata_byte_length,
        relation_rotation_block_byte_length,
        external_working_set_byte_length,
        query_prefetch_byte_length,
        stream_window_byte_length,
        total_byte_length,
    })
}

/// Derives the hard resident live-set for the implemented external-memory
/// schedule. Every potentially domain-sized state-machine field is assigned to
/// a phase: the complete relation-column catalog and integer-lift row cache,
/// one replay source, quotient and FRI vectors, DEEP/opening metadata, terminal
/// and query vectors, the bounded external materialization, transform, and
/// write working sets, query prefetch, and the acknowledged stream window.
/// Complete Merkle levels and polynomial vectors are external.
pub(crate) fn common_proof_resident_memory_plan(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    transcript_schedule: &CommonProofTranscriptSchedule,
    catalog: &CompleteProofTreeCatalog,
    maximum_prefetched_query_byte_length: u64,
    external_memory_write_chunk_byte_length: u64,
    maximum_stream_window_byte_length: u64,
) -> Result<CommonProofResidentMemoryPlan, CommonProofProverError> {
    if maximum_prefetched_query_byte_length == 0
        || external_memory_write_chunk_byte_length == 0
        || maximum_stream_window_byte_length == 0
        || variant.evaluation_domain_size() != catalog.evaluation_domain_size()
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    let evaluation_domain_size = variant.evaluation_domain_size();
    let trace_domain_size = variant.trace_domain_size();
    let extension_value_byte_length =
        resident_value_byte_length(RelationColumnValueType::ChallengeExtension);
    let base_value_byte_length = resident_value_byte_length(RelationColumnValueType::BaseField);
    let mut relation_column_catalog_byte_length = 0_u64;
    let mut base_column_count = 0_u64;
    let mut maximum_replay_source_byte_length = 0_u64;
    let mut maximum_scalar_lde_byte_length = 0_u64;
    let mut maximum_relation_persistence_external_working_set_byte_length = 0_u64;
    for column in variant.ordered_columns() {
        let value_byte_length = resident_value_byte_length(column.value_type());
        let source_byte_length =
            checked_resident_multiply(column.source_degree_bound_exclusive(), value_byte_length)?;
        relation_column_catalog_byte_length =
            checked_resident_add(relation_column_catalog_byte_length, source_byte_length)?;
        maximum_replay_source_byte_length =
            maximum_replay_source_byte_length.max(source_byte_length);
        maximum_scalar_lde_byte_length = maximum_scalar_lde_byte_length.max(
            checked_resident_multiply(evaluation_domain_size, value_byte_length)?,
        );
        let maximum_scan_element_count = external_memory_write_chunk_byte_length
            .checked_div(value_byte_length)
            .filter(|count| *count != 0)
            .ok_or(CommonProofProverError::InvalidInput)?;
        let stockham_scan_byte_length =
            checked_resident_multiply(maximum_scan_element_count, value_byte_length)?;
        let stockham_working_set_byte_length = checked_resident_add(
            checked_resident_multiply(stockham_scan_byte_length, 3)?,
            external_memory_write_chunk_byte_length,
        )?;
        let replay_writer_working_set_byte_length =
            checked_resident_add(external_memory_write_chunk_byte_length, value_byte_length)?;
        maximum_relation_persistence_external_working_set_byte_length =
            maximum_relation_persistence_external_working_set_byte_length
                .max(stockham_working_set_byte_length)
                .max(replay_writer_working_set_byte_length);
        if column.value_type() == RelationColumnValueType::BaseField {
            base_column_count = checked_resident_add(base_column_count, 1)?;
        }
    }
    if maximum_replay_source_byte_length == 0 || maximum_scalar_lde_byte_length == 0 {
        return Err(CommonProofProverError::InvalidColumn);
    }

    let trace_row_cache_byte_length = checked_resident_multiply(
        checked_resident_multiply(base_column_count, trace_domain_size)?,
        base_value_byte_length,
    )?;
    // The largest integer-lift helper simultaneously owns the product
    // accumulator, two suffix vectors, two transpose vectors, one contribution
    // vector, and the reduced/evaluated scratch pair used while populating the
    // cache. These eight trace vectors are dropped before transcript progress.
    let trace_synthesis_scratch_byte_length = checked_resident_multiply(
        checked_resident_multiply(trace_domain_size, base_value_byte_length)?,
        8,
    )?;

    let mut maximum_relation_merkle_working_set_byte_length = 0_u64;
    let mut maximum_extension_merkle_working_set_byte_length = 0_u64;
    for entry in catalog.entries() {
        let Some(context) = entry.common_context() else {
            continue;
        };
        let leaf_count = u64::try_from(context.leaf_count()?)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if leaf_count == 0 || !leaf_count.is_power_of_two() {
            return Err(CommonProofProverError::InvalidTree);
        }
        let canonical_leaf_byte_length = u64::try_from(canonical_common_proof_leaf_byte_length(
            context,
            common_proof_tree_value_type(entry)?,
        )?)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        // The materializer owns one canonical leaf, both typed phase values,
        // the two child plus one parent digests, and two external-memory write
        // chunks that gather exact object-wide records. All complete levels
        // live in external memory.
        let working_set_byte_length = checked_resident_add(
            checked_resident_add(
                checked_resident_multiply(canonical_leaf_byte_length, 2)?,
                checked_resident_multiply(3, HASH_BYTE_LENGTH as u64)?,
            )?,
            checked_resident_multiply(external_memory_write_chunk_byte_length, 2)?,
        )?;
        match entry.source() {
            ProofTreeCatalogSource::RelationProofCreated { .. } => {
                maximum_relation_merkle_working_set_byte_length =
                    maximum_relation_merkle_working_set_byte_length.max(working_set_byte_length);
            }
            ProofTreeCatalogSource::QuotientComponent { .. }
            | ProofTreeCatalogSource::OpeningBatchMask
            | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
                maximum_extension_merkle_working_set_byte_length =
                    maximum_extension_merkle_working_set_byte_length.max(working_set_byte_length);
            }
            ProofTreeCatalogSource::RelationBoundPublic => {}
        }
    }
    // Relation-column persistence serially writes replay polynomials, runs one
    // Stockham transform, or materializes one relation tree. The state machine
    // never owns these working sets concurrently, so the phase owns their
    // maximum rather than their sum.
    maximum_relation_persistence_external_working_set_byte_length =
        maximum_relation_persistence_external_working_set_byte_length
            .max(maximum_relation_merkle_working_set_byte_length);

    let evaluation_extension_vector_byte_length =
        checked_resident_multiply(evaluation_domain_size, extension_value_byte_length)?;
    let relation_rotation_count = required_relation_rotations_by_column(variant)?
        .into_iter()
        .try_fold(0_u64, |count, rotations| {
            checked_resident_add(
                count,
                u64::try_from(rotations.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
        })?;
    let relation_rotation_block_byte_length = checked_resident_multiply(
        checked_resident_multiply(
            evaluation_domain_size.min(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH as u64),
            relation_rotation_count,
        )?,
        extension_value_byte_length,
    )?;
    let quotient_component_byte_length = checked_resident_multiply(
        relation_context.quotient_component_degree_bound_exclusive,
        extension_value_byte_length,
    )?;
    let opening_accumulator_byte_length = checked_resident_multiply(
        variant
            .opening_degree_bound_exclusive()
            .checked_sub(1)
            .ok_or(CommonProofProverError::InvalidOpening)?,
        extension_value_byte_length,
    )?;
    let quotient_cursor_byte_length = checked_resident_add(
        evaluation_extension_vector_byte_length,
        checked_resident_multiply(quotient_component_byte_length, 2)?,
    )?;
    let opening_claim_count = u64::try_from(variant.ordered_opening_claims().len())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let opening_point_count = variant
        .ordered_opening_claims()
        .iter()
        .map(|claim| u64::from(claim.opening_point_ordinal()) + 1)
        .max()
        .unwrap_or(0);
    let opening_metadata_byte_length = checked_resident_multiply(
        checked_resident_add(
            checked_resident_multiply(opening_claim_count, 2)?,
            opening_point_count,
        )?,
        extension_value_byte_length,
    )?;
    let terminal_coefficient_byte_length = checked_resident_multiply(
        u64::from(relation_context.final_polynomial_degree_bound_exclusive),
        extension_value_byte_length,
    )?;
    let query_representative_byte_length = checked_resident_multiply(
        checked_resident_multiply(u64::from(transcript_schedule.unique_query_count()), 2)?,
        u64::try_from(core::mem::size_of::<u64>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let query_metadata_byte_length = checked_resident_add(
        terminal_coefficient_byte_length,
        query_representative_byte_length,
    )?;

    let phases = vec![
        resident_phase_plan(
            CommonProofResidentMemoryPhase::PreparingInputs,
            relation_column_catalog_byte_length,
            trace_row_cache_byte_length,
            trace_synthesis_scratch_byte_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::MaterializingRelationTree,
            relation_column_catalog_byte_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            maximum_relation_merkle_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::DerivingApplicationColumns,
            relation_column_catalog_byte_length,
            trace_row_cache_byte_length,
            trace_synthesis_scratch_byte_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::PersistingRelationColumns,
            relation_column_catalog_byte_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            maximum_relation_persistence_external_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::ConstructingQuotient,
            0,
            0,
            0,
            maximum_replay_source_byte_length,
            evaluation_extension_vector_byte_length,
            maximum_scalar_lde_byte_length,
            0,
            relation_rotation_block_byte_length,
            0,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::MaterializingQuotientTree,
            0,
            0,
            0,
            0,
            quotient_cursor_byte_length,
            0,
            0,
            0,
            maximum_extension_merkle_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::DerivingOpenings,
            0,
            0,
            0,
            maximum_replay_source_byte_length.max(quotient_component_byte_length),
            quotient_component_byte_length,
            0,
            opening_metadata_byte_length,
            0,
            maximum_extension_merkle_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::ConstructingInitialFri,
            0,
            0,
            0,
            maximum_replay_source_byte_length.max(quotient_component_byte_length),
            opening_accumulator_byte_length,
            0,
            opening_metadata_byte_length,
            0,
            0,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::FoldingFri,
            0,
            0,
            0,
            0,
            evaluation_extension_vector_byte_length,
            0,
            opening_metadata_byte_length,
            0,
            maximum_extension_merkle_working_set_byte_length,
            0,
            maximum_stream_window_byte_length,
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::EmittingQueries,
            0,
            0,
            0,
            0,
            0,
            0,
            query_metadata_byte_length,
            0,
            0,
            maximum_prefetched_query_byte_length,
            maximum_stream_window_byte_length,
        )?,
    ];
    let peak_byte_length = phases
        .iter()
        .map(CommonProofResidentMemoryPhasePlan::total_byte_length)
        .max()
        .ok_or(CommonProofProverError::InvalidInput)?;
    Ok(CommonProofResidentMemoryPlan {
        phases,
        peak_byte_length,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CommonProofGenerationStage {
    PreparingInputs = 1,
    MaterializingBaseTrees = 2,
    DerivingApplicationColumns = 3,
    MaterializingAuxiliaryTrees = 4,
    ConstructingQuotient = 5,
    MaterializingQuotientTrees = 6,
    DerivingDeepOpenings = 7,
    MaterializingOpeningMask = 8,
    FoldingFri = 9,
    EmittingPrefix = 10,
    EmittingQueries = 11,
    Finalizing = 12,
    Complete = 13,
    Cancelled = 14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationPoll {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    OutputFragmentAccepted,
    Complete,
}

/// One replayable commitment-round boundary. The ordinal is the fixed order
/// used by the runtime-build checkpoint profile. The committed-state digest is
/// recomputed from the exact phase position and every tree-root slot; it is
/// evidence for deterministic reconstruction, not a producer-supplied
/// acceptance field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofGenerationCheckpointBoundary {
    safe_boundary_ordinal: u32,
    position: [u8; 16],
    committed_state_digest: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofGenerationCheckpointBoundary {
    pub(crate) const fn safe_boundary_ordinal(self) -> u32 {
        self.safe_boundary_ordinal
    }

    pub(crate) const fn position(self) -> [u8; 16] {
        self.position
    }

    pub(crate) const fn committed_state_digest(self) -> [u8; HASH_BYTE_LENGTH] {
        self.committed_state_digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofGenerationPhase {
    PreparingInputs,
    MaterializingBaseTrees { next_tree_index: usize },
    DerivingApplicationColumns,
    PersistingRelationColumns { next_column_index: usize },
    TransformingRelationColumns { next_column_index: usize },
    MaterializingAuxiliaryTrees { next_tree_index: usize },
    ConstructingQuotient,
    ConstructingQuotientBlocks,
    MaterializingQuotientTrees { next_component_index: usize },
    DerivingDeepOpenings,
    EvaluatingDeepOpenings { next_claim_index: usize },
    MaterializingOpeningMask,
    PreparingFri,
    ConstructingInitialFri { next_claim_index: usize },
    FoldingFri { next_fold_ordinal: u16 },
    FinishingFri,
    EmittingPrefix,
    EmittingQueryHeader,
    EmittingQueries { next_catalog_index: usize },
    Finalizing,
    Complete,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofTreeContinuation {
    Base {
        next_tree_index: usize,
    },
    Auxiliary {
        next_tree_index: usize,
        tree_ordinal: u16,
    },
    Quotient {
        next_component_index: usize,
        component_ordinal: u16,
    },
    OpeningMask,
    Fri {
        fold_ordinal: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayWriteContinuation {
    RelationColumn { next_column_index: usize },
    QuotientComponent,
    OpeningBatchMask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayReadContinuation {
    QuotientBlockColumn { column_index: usize },
    DeepOpening { claim_index: usize },
    OpeningBatchMaskTree,
    OpeningBatchMaskFri,
    InitialFriClaim { claim_index: usize },
}

struct ActiveCommonProofReplayPolynomialWriter {
    key: CommonProofReplayPolynomialKey,
    writer: CommonProofReplayPolynomialWriter,
    continuation: CommonProofReplayWriteContinuation,
}

struct ActiveCommonProofReplayPolynomialReader {
    reader: CommonProofReplayPolynomialReader,
    continuation: CommonProofReplayReadContinuation,
}

struct ActiveRelationColumnTransform {
    column_ordinal: u32,
    transform: ExternalStockhamTransform,
}

struct ActiveRelationTreeLeafReader {
    leaf_index: usize,
    opposite_index: usize,
    column_ordinals: Vec<u32>,
    next_value_index: usize,
    first_values: Vec<ProofTreeValue>,
    opposite_values: Vec<ProofTreeValue>,
}

impl ActiveRelationTreeLeafReader {
    fn new(
        leaf_index: u64,
        evaluation_domain_size: usize,
        column_ordinals: Vec<u32>,
    ) -> Result<Self, CommonProofProverError> {
        if column_ordinals.is_empty() || evaluation_domain_size < 2 {
            return Err(CommonProofProverError::InvalidTree);
        }
        let leaf_index =
            usize::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        let opposite_index = leaf_index
            .checked_add(evaluation_domain_size / 2)
            .filter(|index| *index < evaluation_domain_size)
            .ok_or(CommonProofProverError::InvalidTree)?;
        let mut first_values = Vec::new();
        first_values
            .try_reserve_exact(column_ordinals.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        let mut opposite_values = Vec::new();
        opposite_values
            .try_reserve_exact(column_ordinals.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        Ok(Self {
            leaf_index,
            opposite_index,
            column_ordinals,
            next_value_index: 0,
            first_values,
            opposite_values,
        })
    }
}

struct ActiveCommonProofTreeMaterialization {
    materializer: CommonProofMerkleMaterializer,
    leaf_source: CommonProofTreeLeafSource,
    continuation: CommonProofTreeContinuation,
}

enum CommonProofTreeLeafSource {
    PreChallengeColumns(Vec<u32>),
    RelationColumns(Vec<u32>),
    QuotientComponent,
    OpeningBatchMask,
    FriEvaluations(Vec<ProofChallengeExtensionElement>),
}

fn evaluate_source_polynomial_tree_value(
    polynomial: &CommonProofSourcePolynomial,
    point: ProofBaseFieldElement,
) -> ProofTreeValue {
    match polynomial {
        CommonProofSourcePolynomial::Base(coefficients) => ProofTreeValue::Base(
            coefficients
                .iter()
                .rev()
                .fold(ProofBaseFieldElement::ZERO, |accumulated, coefficient| {
                    accumulated.multiply(point).add(*coefficient)
                }),
        ),
        CommonProofSourcePolynomial::Extension(coefficients) => {
            ProofTreeValue::Extension(evaluate_extension_at(
                coefficients,
                ProofChallengeExtensionElement::from_base(point),
            ))
        }
    }
}

/// Persistent common prover state.  No storage yield restarts a transcript
/// round, re-samples private coins, or regenerates an already accepted output
/// fragment.  The browser owns the external-memory replay and output-chunk
/// acknowledgement loops; this state owns the cryptographic continuation.
pub(crate) struct CommonProofGenerationStateMachine {
    protocol_version: u16,
    suite_identifier: [u8; HASH_BYTE_LENGTH],
    application_statement_schema_identifier: u16,
    canonical_header_bytes: Vec<u8>,
    variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    transcript_schedule: CommonProofTranscriptSchedule,
    evaluation_domain: ProofEvaluationDomain,
    catalog: CompleteProofTreeCatalog,
    resident_memory_plan: CommonProofResidentMemoryPlan,
    relation_trees: Vec<RelationProofTreeInput>,
    provided_pre_challenge_columns: Option<BTreeMap<u32, CommonProofSourcePolynomial>>,
    maximum_prefetched_query_byte_length: u64,
    maximum_output_fragment_byte_length: usize,
    storage_tree_plans: BTreeMap<u16, CommonProofMerkleStoragePlan>,
    replay_polynomial_plans:
        BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayPolynomialPlan>,
    relation_evaluation_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
    relation_evaluation_vectors: BTreeMap<u32, ExternalPolynomialVector>,
    executor: Option<ProofExternalMemoryExecutor>,
    phase: CommonProofGenerationPhase,
    active_tree_materialization: Option<ActiveCommonProofTreeMaterialization>,
    pending_tree_continuation: Option<CommonProofTreeContinuation>,
    active_replay_polynomial_writer: Option<ActiveCommonProofReplayPolynomialWriter>,
    active_replay_polynomial_reader: Option<ActiveCommonProofReplayPolynomialReader>,
    active_relation_column_transform: Option<ActiveRelationColumnTransform>,
    active_relation_tree_leaf_reader: Option<ActiveRelationTreeLeafReader>,
    pre_challenge_columns: Option<CommonProofPreChallengeRelationColumns>,
    columns: Option<Vec<CommonProofSourcePolynomial>>,
    application_challenges: Vec<RelationApplicationChallengeAssignment>,
    quotient_builder: Option<CommonProofReplayQuotientBuilder>,
    quotient_component_cursor: Option<CommonProofQuotientComponentCursor>,
    current_quotient_component: Option<Vec<ProofChallengeExtensionElement>>,
    opening_points: Vec<ProofChallengeExtensionElement>,
    opening_batch_mask: Option<Vec<ProofChallengeExtensionElement>>,
    deep_evaluations: Vec<ProofChallengeExtensionElement>,
    opening_batch_coefficients: Vec<ProofChallengeExtensionElement>,
    initial_fri_polynomial: Option<Vec<ProofChallengeExtensionElement>>,
    fri_domain: Option<ProofEvaluationDomain>,
    fri_evaluations: Option<Vec<ProofChallengeExtensionElement>>,
    terminal_coefficients: Vec<ProofChallengeExtensionElement>,
    sorted_query_representatives: Vec<u64>,
    opening_geometries: Vec<CommonProofOpeningGeometry>,
    tree_roots: Vec<[u8; HASH_BYTE_LENGTH]>,
    root_present: Vec<bool>,
    stored_trees: BTreeMap<u16, StoredCommonProofMerkleTree>,
    transcript: Option<CommonProofTranscript>,
    query_opening_absorber: Option<CommonProofQueryOpeningAbsorber>,
    query_section_byte_length: Option<usize>,
    opening_prefetcher: Option<CommonProofOpeningPrefetcher>,
    pending_output_fragment: Option<Vec<u8>>,
}

impl CommonProofGenerationStateMachine {
    fn active_tree_leaf_values(
        &self,
        leaf_index: u64,
    ) -> Result<(Vec<ProofTreeValue>, Vec<ProofTreeValue>), CommonProofProverError> {
        let leaf_index =
            usize::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        let active = self
            .active_tree_materialization
            .as_ref()
            .ok_or(CommonProofProverError::InvalidTree)?;
        match &active.leaf_source {
            CommonProofTreeLeafSource::FriEvaluations(evaluations) => {
                if evaluations.len() < 2 || !evaluations.len().is_power_of_two() {
                    return Err(CommonProofProverError::InvalidFriLayer);
                }
                let opposite_index = leaf_index
                    .checked_add(evaluations.len() / 2)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                Ok((
                    vec![ProofTreeValue::Extension(
                        *evaluations
                            .get(leaf_index)
                            .ok_or(CommonProofProverError::InvalidFriLayer)?,
                    )],
                    vec![ProofTreeValue::Extension(
                        *evaluations
                            .get(opposite_index)
                            .ok_or(CommonProofProverError::InvalidFriLayer)?,
                    )],
                ))
            }
            leaf_source => {
                let opposite_index = leaf_index
                    .checked_add(self.evaluation_domain.size() / 2)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let first_point = self.evaluation_domain.point(leaf_index)?;
                let opposite_point = self.evaluation_domain.point(opposite_index)?;
                let mut first_values = Vec::new();
                let mut opposite_values = Vec::new();
                let row_width = match leaf_source {
                    CommonProofTreeLeafSource::PreChallengeColumns(column_ordinals)
                    | CommonProofTreeLeafSource::RelationColumns(column_ordinals) => {
                        column_ordinals.len()
                    }
                    CommonProofTreeLeafSource::QuotientComponent
                    | CommonProofTreeLeafSource::OpeningBatchMask => 1,
                    CommonProofTreeLeafSource::FriEvaluations(_) => unreachable!(),
                };
                first_values
                    .try_reserve_exact(row_width)
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                opposite_values
                    .try_reserve_exact(row_width)
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                match leaf_source {
                    CommonProofTreeLeafSource::PreChallengeColumns(column_ordinals) => {
                        let columns = self
                            .pre_challenge_columns
                            .as_ref()
                            .ok_or(CommonProofProverError::InvalidColumn)?;
                        for column_ordinal in column_ordinals {
                            let polynomial = columns
                                .column(*column_ordinal)
                                .ok_or(CommonProofProverError::InvalidColumn)?;
                            first_values.push(evaluate_source_polynomial_tree_value(
                                polynomial,
                                first_point,
                            ));
                            opposite_values.push(evaluate_source_polynomial_tree_value(
                                polynomial,
                                opposite_point,
                            ));
                        }
                    }
                    CommonProofTreeLeafSource::RelationColumns(column_ordinals) => {
                        let _ = column_ordinals;
                        return Err(CommonProofProverError::InvalidTree);
                    }
                    CommonProofTreeLeafSource::QuotientComponent => {
                        let coefficients = self
                            .current_quotient_component
                            .as_ref()
                            .ok_or(CommonProofProverError::InvalidQuotient)?;
                        first_values.push(ProofTreeValue::Extension(evaluate_extension_at(
                            coefficients,
                            ProofChallengeExtensionElement::from_base(first_point),
                        )));
                        opposite_values.push(ProofTreeValue::Extension(evaluate_extension_at(
                            coefficients,
                            ProofChallengeExtensionElement::from_base(opposite_point),
                        )));
                    }
                    CommonProofTreeLeafSource::OpeningBatchMask => {
                        let coefficients = self
                            .opening_batch_mask
                            .as_ref()
                            .ok_or(CommonProofProverError::InvalidMask)?;
                        first_values.push(ProofTreeValue::Extension(evaluate_extension_at(
                            coefficients,
                            ProofChallengeExtensionElement::from_base(first_point),
                        )));
                        opposite_values.push(ProofTreeValue::Extension(evaluate_extension_at(
                            coefficients,
                            ProofChallengeExtensionElement::from_base(opposite_point),
                        )));
                    }
                    CommonProofTreeLeafSource::FriEvaluations(_) => unreachable!(),
                }
                Ok((first_values, opposite_values))
            }
        }
    }

    fn poll_active_tree<Storage, Coins, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, Coins::Error, SinkError, BoundOpeningError>,
    >
    where
        Storage: ProofExternalMemory,
        Coins: CommonProofPrivateCoinSource,
    {
        let progress = {
            let executor = self
                .executor
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?;
            let active = self.active_tree_materialization.as_mut().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
            )?;
            active
                .materializer
                .advance_storage(executor, storage)
                .map_err(|error| match error {
                    CommonProofTreeStorageError::Prover(error) => {
                        CommonProofGenerationError::Prover(error)
                    }
                    CommonProofTreeStorageError::Storage(error) => {
                        CommonProofGenerationError::Storage(error)
                    }
                    CommonProofTreeStorageError::CoinSource(error) => match error {},
                })?
        };
        match progress {
            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted => {
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            CommonProofMerkleMaterializerProgress::NeedsLeafValues { leaf_index } => {
                let relation_column_ordinals =
                    self.active_tree_materialization
                        .as_ref()
                        .and_then(|active| match &active.leaf_source {
                            CommonProofTreeLeafSource::RelationColumns(column_ordinals) => {
                                Some(column_ordinals.clone())
                            }
                            _ => None,
                        });
                if let Some(column_ordinals) = relation_column_ordinals {
                    if self.active_relation_tree_leaf_reader.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.active_relation_tree_leaf_reader = Some(
                        ActiveRelationTreeLeafReader::new(
                            leaf_index,
                            self.evaluation_domain.size(),
                            column_ordinals,
                        )
                        .map_err(CommonProofGenerationError::Prover)?,
                    );
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let (first_values, opposite_values) = self
                    .active_tree_leaf_values(leaf_index)
                    .map_err(CommonProofGenerationError::Prover)?;
                let active = self.active_tree_materialization.as_mut().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                active
                    .materializer
                    .supply_next_leaf(first_values, opposite_values, coins)
                    .map_err(|error| match error {
                        CommonProofTreeStorageError::Prover(error) => {
                            CommonProofGenerationError::Prover(error)
                        }
                        CommonProofTreeStorageError::Storage(error) => match error {
                            ProofExternalMemoryExecutorError::Execution(error) => {
                                CommonProofGenerationError::StoragePlan(error)
                            }
                            ProofExternalMemoryExecutorError::Storage(error)
                            | ProofExternalMemoryExecutorError::StorageCommit(error) => {
                                match error {}
                            }
                            ProofExternalMemoryExecutorError::StorageAbort {
                                operation_error,
                                ..
                            } => match operation_error {},
                        },
                        CommonProofTreeStorageError::CoinSource(error) => {
                            CommonProofGenerationError::CoinSource(error)
                        }
                    })?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofMerkleMaterializerProgress::Complete => {
                let ActiveCommonProofTreeMaterialization {
                    materializer,
                    leaf_source,
                    continuation,
                } = self.active_tree_materialization.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                let tree = materializer
                    .finish()
                    .map_err(CommonProofGenerationError::Prover)?;
                if let CommonProofTreeLeafSource::FriEvaluations(values) = leaf_source {
                    self.fri_evaluations = Some(values);
                }
                insert_materialized_tree(
                    tree,
                    &mut self.tree_roots,
                    &mut self.root_present,
                    &mut self.stored_trees,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                self.pending_tree_continuation = Some(continuation);
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
        }
    }

    pub(crate) fn new<'input>(
        input: CommonProofGenerationInput<'input>,
    ) -> Result<Self, CommonProofGenerationInitializationError> {
        let CommonProofGenerationInput {
            protocol_version,
            suite_identifier,
            canonical_application_statement_bytes,
            relation_plan,
            relation_context,
            schedule_position,
            top_count,
            relation_trees,
            provided_pre_challenge_columns,
            maximum_external_memory_chunk_byte_length,
            maximum_proof_transport_chunk_byte_length,
            maximum_prefetched_query_byte_length,
        } = input;
        if maximum_prefetched_query_byte_length == 0
            || maximum_external_memory_chunk_byte_length
                != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            || maximum_proof_transport_chunk_byte_length != MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        let validated_artifact =
            ValidatedRelationPlanArtifact::from_compiled_plan(relation_plan, relation_context)
                .map_err(CommonProofGenerationInitializationError::Profile)?;
        let canonical_header_bytes =
            canonical_proof_object_header_bytes(canonical_application_statement_bytes)
                .map_err(CommonProofGenerationInitializationError::Prover)?;
        let variant = relation_plan
            .select_variant(schedule_position, top_count)
            .map_err(CommonProofGenerationInitializationError::Relation)?;
        validate_generation_relation_trees(variant, &relation_trees)
            .map_err(CommonProofGenerationInitializationError::Prover)?;
        let transcript_schedule = variant
            .common_proof_transcript_schedule(relation_context)
            .map_err(CommonProofGenerationInitializationError::Relation)?;
        let evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(variant.evaluation_domain_size()).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?,
            relation_context.evaluation_coset_offset,
        )
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofGenerationInitializationError::Prover)?;
        if evaluation_domain.generator().canonical() != relation_context.evaluation_domain_generator
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let catalog = build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier,
                canonical_proof_object_header_bytes: canonical_header_bytes.clone(),
                application_statement_schema_identifier: validated_artifact
                    .application_statement_schema_identifier(),
                proof_field_index: 0,
                evaluation_domain_size: variant.evaluation_domain_size(),
                relation_trees: relation_trees.clone(),
            },
            &transcript_schedule,
        )
        .map_err(CommonProofGenerationInitializationError::Body)?;
        let storage_plan = generated_common_proof_storage_plan(
            variant,
            relation_context,
            &catalog,
            &transcript_schedule,
            maximum_external_memory_chunk_byte_length,
            true,
        )
        .map_err(|error| match error {
            GeneratedCommonProofStoragePlanError::Prover(error) => {
                CommonProofGenerationInitializationError::Prover(error)
            }
            GeneratedCommonProofStoragePlanError::Storage(error) => {
                CommonProofGenerationInitializationError::StoragePlan(error)
            }
        })?;
        let resident_memory_plan = common_proof_resident_memory_plan(
            variant,
            relation_context,
            &transcript_schedule,
            &catalog,
            maximum_prefetched_query_byte_length,
            u64::from(maximum_external_memory_chunk_byte_length),
            u64::try_from(maximum_proof_transport_chunk_byte_length).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?,
        )
        .map_err(CommonProofGenerationInitializationError::Prover)?;
        let executor = ProofExternalMemoryExecutor::new(storage_plan.external_memory_plan)
            .map_err(CommonProofGenerationInitializationError::StoragePlan)?;
        let mut tree_roots = vec![[0_u8; HASH_BYTE_LENGTH]; catalog.entries().len()];
        let mut root_present = vec![false; catalog.entries().len()];
        for (tree_index, relation_tree) in relation_trees.iter().enumerate() {
            if let Some(root) = statement_owned_tree_root(relation_tree) {
                *tree_roots.get_mut(tree_index).ok_or(
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ),
                )? = root;
                *root_present.get_mut(tree_index).ok_or(
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ),
                )? = true;
            }
        }
        Ok(Self {
            protocol_version,
            suite_identifier,
            application_statement_schema_identifier: validated_artifact
                .application_statement_schema_identifier(),
            canonical_header_bytes,
            variant: variant.clone(),
            relation_context: relation_context.clone(),
            transcript_schedule,
            evaluation_domain,
            catalog,
            resident_memory_plan,
            relation_trees,
            provided_pre_challenge_columns: Some(provided_pre_challenge_columns),
            maximum_prefetched_query_byte_length,
            maximum_output_fragment_byte_length: maximum_proof_transport_chunk_byte_length,
            storage_tree_plans: storage_plan.tree_plans,
            replay_polynomial_plans: storage_plan.replay_polynomial_plans,
            relation_evaluation_transform_plans: storage_plan.relation_evaluation_transform_plans,
            relation_evaluation_vectors: BTreeMap::new(),
            executor: Some(executor),
            phase: CommonProofGenerationPhase::PreparingInputs,
            active_tree_materialization: None,
            pending_tree_continuation: None,
            active_replay_polynomial_writer: None,
            active_replay_polynomial_reader: None,
            active_relation_column_transform: None,
            active_relation_tree_leaf_reader: None,
            pre_challenge_columns: None,
            columns: None,
            application_challenges: Vec::new(),
            quotient_builder: None,
            quotient_component_cursor: None,
            current_quotient_component: None,
            opening_points: Vec::new(),
            opening_batch_mask: None,
            deep_evaluations: Vec::new(),
            opening_batch_coefficients: Vec::new(),
            initial_fri_polynomial: None,
            fri_domain: None,
            fri_evaluations: None,
            terminal_coefficients: Vec::new(),
            sorted_query_representatives: Vec::new(),
            opening_geometries: Vec::new(),
            tree_roots,
            root_present,
            stored_trees: BTreeMap::new(),
            transcript: None,
            query_opening_absorber: None,
            query_section_byte_length: None,
            opening_prefetcher: None,
            pending_output_fragment: None,
        })
    }

    pub(crate) const fn stage(&self) -> CommonProofGenerationStage {
        match self.phase {
            CommonProofGenerationPhase::PreparingInputs => {
                CommonProofGenerationStage::PreparingInputs
            }
            CommonProofGenerationPhase::MaterializingBaseTrees { .. } => {
                CommonProofGenerationStage::MaterializingBaseTrees
            }
            CommonProofGenerationPhase::DerivingApplicationColumns => {
                CommonProofGenerationStage::DerivingApplicationColumns
            }
            CommonProofGenerationPhase::PersistingRelationColumns { .. }
            | CommonProofGenerationPhase::TransformingRelationColumns { .. } => {
                CommonProofGenerationStage::DerivingApplicationColumns
            }
            CommonProofGenerationPhase::MaterializingAuxiliaryTrees { .. } => {
                CommonProofGenerationStage::MaterializingAuxiliaryTrees
            }
            CommonProofGenerationPhase::ConstructingQuotient
            | CommonProofGenerationPhase::ConstructingQuotientBlocks => {
                CommonProofGenerationStage::ConstructingQuotient
            }
            CommonProofGenerationPhase::MaterializingQuotientTrees { .. } => {
                CommonProofGenerationStage::MaterializingQuotientTrees
            }
            CommonProofGenerationPhase::DerivingDeepOpenings => {
                CommonProofGenerationStage::DerivingDeepOpenings
            }
            CommonProofGenerationPhase::EvaluatingDeepOpenings { .. } => {
                CommonProofGenerationStage::DerivingDeepOpenings
            }
            CommonProofGenerationPhase::MaterializingOpeningMask => {
                CommonProofGenerationStage::MaterializingOpeningMask
            }
            CommonProofGenerationPhase::PreparingFri
            | CommonProofGenerationPhase::ConstructingInitialFri { .. }
            | CommonProofGenerationPhase::FoldingFri { .. }
            | CommonProofGenerationPhase::FinishingFri => CommonProofGenerationStage::FoldingFri,
            CommonProofGenerationPhase::EmittingPrefix => {
                CommonProofGenerationStage::EmittingPrefix
            }
            CommonProofGenerationPhase::EmittingQueryHeader
            | CommonProofGenerationPhase::EmittingQueries { .. } => {
                CommonProofGenerationStage::EmittingQueries
            }
            CommonProofGenerationPhase::Finalizing => CommonProofGenerationStage::Finalizing,
            CommonProofGenerationPhase::Complete => CommonProofGenerationStage::Complete,
            CommonProofGenerationPhase::Cancelled => CommonProofGenerationStage::Cancelled,
        }
    }

    pub(crate) const fn resident_memory_plan(&self) -> &CommonProofResidentMemoryPlan {
        &self.resident_memory_plan
    }

    #[cfg(test)]
    pub(crate) fn resident_payload_is_empty(&self) -> bool {
        self.provided_pre_challenge_columns.is_none()
            && self.active_tree_materialization.is_none()
            && self.pending_tree_continuation.is_none()
            && self.active_replay_polynomial_writer.is_none()
            && self.active_replay_polynomial_reader.is_none()
            && self.active_relation_column_transform.is_none()
            && self.active_relation_tree_leaf_reader.is_none()
            && self.pre_challenge_columns.is_none()
            && self.columns.is_none()
            && self.application_challenges.is_empty()
            && self.quotient_builder.is_none()
            && self.quotient_component_cursor.is_none()
            && self.current_quotient_component.is_none()
            && self.opening_points.is_empty()
            && self.opening_batch_mask.is_none()
            && self.deep_evaluations.is_empty()
            && self.opening_batch_coefficients.is_empty()
            && self.initial_fri_polynomial.is_none()
            && self.fri_domain.is_none()
            && self.fri_evaluations.is_none()
            && self.terminal_coefficients.is_empty()
            && self.sorted_query_representatives.is_empty()
            && self.opening_geometries.is_empty()
            && self.storage_tree_plans.is_empty()
            && self.replay_polynomial_plans.is_empty()
            && self.relation_evaluation_transform_plans.is_empty()
            && self.relation_evaluation_vectors.is_empty()
            && self.stored_trees.is_empty()
            && self.tree_roots.is_empty()
            && self.root_present.is_empty()
            && self.transcript.is_none()
            && self.query_opening_absorber.is_none()
            && self.query_section_byte_length.is_none()
            && self.opening_prefetcher.is_none()
            && self.pending_output_fragment.is_none()
            && self.relation_trees.is_empty()
            && self.canonical_header_bytes.is_empty()
            && self.executor.is_none()
    }

    pub(crate) fn checkpoint_boundary(&self) -> Option<CommonProofGenerationCheckpointBoundary> {
        // Only completed proof commitment rounds are durable boundaries. In
        // particular, an internal polynomial pass is not independently
        // verifiable proof state even when its scratch object is sealed.
        // Prefix and query extraction are one uncheckpointed output
        // transaction, so no boundary exists after any proof byte is staged.
        if self.active_tree_materialization.is_some()
            || self.pending_tree_continuation.is_some()
            || self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_relation_column_transform.is_some()
            || self.active_relation_tree_leaf_reader.is_some()
            || self.opening_prefetcher.is_some()
            || self.pending_output_fragment.is_some()
        {
            return None;
        }

        let (safe_boundary_ordinal, phase_tag, phase_ordinal) = match self.phase {
            CommonProofGenerationPhase::DerivingApplicationColumns => (1, 1, 0),
            CommonProofGenerationPhase::ConstructingQuotient => (2, 2, 0),
            CommonProofGenerationPhase::DerivingDeepOpenings => (3, 3, 0),
            CommonProofGenerationPhase::PreparingFri => (4, 4, 0),
            CommonProofGenerationPhase::FoldingFri { next_fold_ordinal }
                if next_fold_ordinal > 0
                    && next_fold_ordinal < self.transcript_schedule.fri_fold_count() =>
            {
                (
                    u32::from(next_fold_ordinal).checked_add(4)?,
                    5,
                    u32::from(next_fold_ordinal),
                )
            }
            _ => return None,
        };
        let mut position = [0_u8; 16];
        position[0] = phase_tag;
        position[4..8].copy_from_slice(&safe_boundary_ordinal.to_le_bytes());
        position[8..12].copy_from_slice(&phase_ordinal.to_le_bytes());

        let root_state_byte_length = self.root_present.len().checked_mul(1 + HASH_BYTE_LENGTH)?;
        let mut hasher = StreamingHash512::new(CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN, 2);
        hasher.absorb_part(&position);
        hasher.begin_part(u64::try_from(root_state_byte_length).ok()?);
        for (present, root) in self.root_present.iter().zip(&self.tree_roots) {
            hasher.absorb_raw(&[u8::from(*present)]);
            hasher.absorb_raw(root);
        }
        Some(CommonProofGenerationCheckpointBoundary {
            safe_boundary_ordinal,
            position,
            committed_state_digest: hasher.finalize(),
        })
    }

    fn executor_mut(&mut self) -> Result<&mut ProofExternalMemoryExecutor, CommonProofProverError> {
        self.executor
            .as_mut()
            .ok_or(CommonProofProverError::InvalidInput)
    }

    fn poll_active_relation_column_transform<Storage, CoinError, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError, BoundOpeningError>,
    >
    where
        Storage: ProofExternalMemory,
    {
        let progress = {
            let executor = self
                .executor
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?;
            let active = self.active_relation_column_transform.as_mut().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
            )?;
            active
                .transform
                .advance(executor, storage)
                .map_err(|error| match error {
                    ExternalStockhamTransformError::Polynomial(error) => {
                        CommonProofGenerationError::StoragePlan(map_external_polynomial_plan_error(
                            error,
                        ))
                    }
                    ExternalStockhamTransformError::Storage(error) => {
                        CommonProofGenerationError::Storage(error)
                    }
                })?
        };
        match progress {
            ExternalStockhamTransformProgress::ArithmeticStepCompleted => {
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            ExternalStockhamTransformProgress::StorageTransactionCompleted
            | ExternalStockhamTransformProgress::PassCommitted(_) => {
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            ExternalStockhamTransformProgress::Complete(vector) => {
                let active = self.active_relation_column_transform.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?;
                if self
                    .relation_evaluation_vectors
                    .insert(active.column_ordinal, vector)
                    .is_some()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                let next_column_index = usize::try_from(active.column_ordinal)
                    .ok()
                    .and_then(|index| index.checked_add(1))
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
                self.phase =
                    CommonProofGenerationPhase::TransformingRelationColumns { next_column_index };
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
        }
    }

    fn poll_active_relation_tree_leaf_reader<Storage, Coins, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, Coins::Error, SinkError, BoundOpeningError>,
    >
    where
        Storage: ProofExternalMemory,
        Coins: CommonProofPrivateCoinSource,
    {
        let is_complete = {
            let reader = self.active_relation_tree_leaf_reader.as_ref().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
            )?;
            reader.next_value_index
                >= reader.column_ordinals.len().checked_mul(2).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow),
                )?
        };
        if is_complete {
            let reader = self.active_relation_tree_leaf_reader.take().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
            )?;
            self.active_tree_materialization
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?
                .materializer
                .supply_next_leaf(reader.first_values, reader.opposite_values, coins)
                .map_err(|error| match error {
                    CommonProofTreeStorageError::Prover(error) => {
                        CommonProofGenerationError::Prover(error)
                    }
                    CommonProofTreeStorageError::Storage(error) => match error {
                        ProofExternalMemoryExecutorError::Execution(error) => {
                            CommonProofGenerationError::StoragePlan(error)
                        }
                        ProofExternalMemoryExecutorError::Storage(error)
                        | ProofExternalMemoryExecutorError::StorageCommit(error) => match error {},
                        ProofExternalMemoryExecutorError::StorageAbort {
                            operation_error, ..
                        } => match operation_error {},
                    },
                    CommonProofTreeStorageError::CoinSource(error) => {
                        CommonProofGenerationError::CoinSource(error)
                    }
                })?;
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let (column_ordinal, element_index, is_opposite) = {
            let reader = self.active_relation_tree_leaf_reader.as_ref().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
            )?;
            let row_width = reader.column_ordinals.len();
            let is_opposite = reader.next_value_index >= row_width;
            let column_index = reader.next_value_index % row_width;
            (
                *reader.column_ordinals.get(column_index).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?,
                if is_opposite {
                    reader.opposite_index
                } else {
                    reader.leaf_index
                },
                is_opposite,
            )
        };
        let vector = self
            .relation_evaluation_vectors
            .get(&column_ordinal)
            .copied()
            .ok_or(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
        let value = read_external_polynomial_value(
            self.executor
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?,
            storage,
            vector,
            element_index,
        )
        .map_err(|error| match error {
            ExternalStockhamTransformError::Polynomial(error) => {
                CommonProofGenerationError::StoragePlan(map_external_polynomial_plan_error(error))
            }
            ExternalStockhamTransformError::Storage(error) => {
                CommonProofGenerationError::Storage(error)
            }
        })?;
        let tree_value = match value {
            ExternalPolynomialValue::Base(value) => ProofTreeValue::Base(value),
            ExternalPolynomialValue::Extension(value) => ProofTreeValue::Extension(value),
        };
        let reader = self.active_relation_tree_leaf_reader.as_mut().ok_or(
            CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
        )?;
        if is_opposite {
            reader.opposite_values.push(tree_value);
        } else {
            reader.first_values.push(tree_value);
        }
        reader.next_value_index =
            reader
                .next_value_index
                .checked_add(1)
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
    }

    fn prepare_replay_polynomial_writer(
        &mut self,
        key: CommonProofReplayPolynomialKey,
        continuation: CommonProofReplayWriteContinuation,
    ) -> Result<(), CommonProofProverError> {
        if self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_tree_materialization.is_some()
            || self.pending_tree_continuation.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let plan = self
            .replay_polynomial_plans
            .get(&key)
            .copied()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let polynomial = match key {
            CommonProofReplayPolynomialKey::RelationColumn(column_ordinal) => {
                CommonProofReplayPolynomialRef::Source(
                    self.columns
                        .as_ref()
                        .and_then(|columns| {
                            usize::try_from(column_ordinal)
                                .ok()
                                .and_then(|index| columns.get(index))
                        })
                        .ok_or(CommonProofProverError::InvalidColumn)?,
                )
            }
            CommonProofReplayPolynomialKey::QuotientComponent(_) => {
                CommonProofReplayPolynomialRef::Extension(
                    self.current_quotient_component
                        .as_deref()
                        .ok_or(CommonProofProverError::InvalidQuotient)?,
                )
            }
            CommonProofReplayPolynomialKey::OpeningBatchMask => {
                CommonProofReplayPolynomialRef::Extension(
                    self.opening_batch_mask
                        .as_deref()
                        .ok_or(CommonProofProverError::InvalidMask)?,
                )
            }
        };
        let writer = CommonProofReplayPolynomialWriter::new(plan, polynomial)?;
        self.active_replay_polynomial_writer = Some(ActiveCommonProofReplayPolynomialWriter {
            key,
            writer,
            continuation,
        });
        Ok(())
    }

    fn prepare_replay_polynomial_reader(
        &mut self,
        key: CommonProofReplayPolynomialKey,
        continuation: CommonProofReplayReadContinuation,
    ) -> Result<(), CommonProofProverError> {
        if self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_tree_materialization.is_some()
            || self.pending_tree_continuation.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let plan = self
            .replay_polynomial_plans
            .get(&key)
            .copied()
            .ok_or(CommonProofProverError::InvalidInput)?;
        self.active_replay_polynomial_reader = Some(ActiveCommonProofReplayPolynomialReader {
            reader: CommonProofReplayPolynomialReader::new(plan)?,
            continuation,
        });
        Ok(())
    }

    fn poll_active_replay_polynomial_writer<Storage, CoinError, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError, BoundOpeningError>,
    >
    where
        Storage: ProofExternalMemory,
    {
        let key = self
            .active_replay_polynomial_writer
            .as_ref()
            .ok_or(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            ))?
            .key;
        let polynomial = match key {
            CommonProofReplayPolynomialKey::RelationColumn(column_ordinal) => {
                CommonProofReplayPolynomialRef::Source(
                    self.columns
                        .as_ref()
                        .and_then(|columns| {
                            usize::try_from(column_ordinal)
                                .ok()
                                .and_then(|index| columns.get(index))
                        })
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ))?,
                )
            }
            CommonProofReplayPolynomialKey::QuotientComponent(_) => {
                CommonProofReplayPolynomialRef::Extension(
                    self.current_quotient_component.as_deref().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidQuotient),
                    )?,
                )
            }
            CommonProofReplayPolynomialKey::OpeningBatchMask => {
                CommonProofReplayPolynomialRef::Extension(
                    self.opening_batch_mask.as_deref().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidMask),
                    )?,
                )
            }
        };
        let active = self.active_replay_polynomial_writer.as_mut().ok_or(
            CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
        )?;
        let completed = active
            .writer
            .advance(
                self.executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?,
                storage,
                polynomial,
            )
            .map_err(CommonProofGenerationError::Storage)?;
        if completed {
            let continuation = self
                .active_replay_polynomial_writer
                .take()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?
                .continuation;
            match continuation {
                CommonProofReplayWriteContinuation::RelationColumn { next_column_index } => {
                    self.phase =
                        CommonProofGenerationPhase::PersistingRelationColumns { next_column_index };
                }
                CommonProofReplayWriteContinuation::QuotientComponent => {}
                CommonProofReplayWriteContinuation::OpeningBatchMask => {
                    self.opening_batch_mask = None;
                    self.phase = CommonProofGenerationPhase::EvaluatingDeepOpenings {
                        next_claim_index: 0,
                    };
                }
            }
        }
        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
    }

    fn apply_replay_polynomial_read_continuation(
        &mut self,
        continuation: CommonProofReplayReadContinuation,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        match continuation {
            CommonProofReplayReadContinuation::QuotientBlockColumn { column_index } => {
                let expected_value_type = self
                    .variant
                    .ordered_columns()
                    .get(column_index)
                    .map(RelationColumnDescriptor::value_type)
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                if polynomial.value_type() != expected_value_type {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                self.quotient_builder
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidQuotient)?
                    .accept_column(column_index, polynomial)?;
                self.phase = CommonProofGenerationPhase::ConstructingQuotientBlocks;
            }
            CommonProofReplayReadContinuation::DeepOpening { claim_index } => {
                let claim = *self
                    .variant
                    .ordered_opening_claims()
                    .get(claim_index)
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                let opening_point = self
                    .opening_points
                    .get(
                        usize::try_from(claim.opening_point_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .copied()
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                self.deep_evaluations
                    .push(evaluate_replay_polynomial_opening(
                        &claim,
                        &polynomial,
                        opening_point,
                    )?);
                self.phase = CommonProofGenerationPhase::EvaluatingDeepOpenings {
                    next_claim_index: claim_index
                        .checked_add(1)
                        .ok_or(CommonProofProverError::CountOverflow)?,
                };
            }
            CommonProofReplayReadContinuation::OpeningBatchMaskTree => {
                let CommonProofSourcePolynomial::Extension(coefficients) = polynomial else {
                    return Err(CommonProofProverError::InvalidMask);
                };
                self.opening_batch_mask = Some(coefficients);
                self.phase = CommonProofGenerationPhase::MaterializingOpeningMask;
            }
            CommonProofReplayReadContinuation::OpeningBatchMaskFri => {
                let CommonProofSourcePolynomial::Extension(coefficients) = polynomial else {
                    return Err(CommonProofProverError::InvalidMask);
                };
                let initial = self
                    .initial_fri_polynomial
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidFriLayer)?;
                if coefficients.len() > initial.len() {
                    return Err(CommonProofProverError::InvalidMask);
                }
                for (destination, coefficient) in initial.iter_mut().zip(coefficients) {
                    *destination = destination.add(coefficient);
                }
                self.phase = CommonProofGenerationPhase::ConstructingInitialFri {
                    next_claim_index: 0,
                };
            }
            CommonProofReplayReadContinuation::InitialFriClaim { claim_index } => {
                let claim = *self
                    .variant
                    .ordered_opening_claims()
                    .get(claim_index)
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                let opening_point = self
                    .opening_points
                    .get(
                        usize::try_from(claim.opening_point_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .copied()
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                let deep_evaluation = *self
                    .deep_evaluations
                    .get(claim_index)
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                let batching_coefficient = *self
                    .opening_batch_coefficients
                    .get(claim_index)
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                add_replay_polynomial_to_initial_fri(
                    self.initial_fri_polynomial
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidFriLayer)?,
                    usize::try_from(self.variant.opening_degree_bound_exclusive())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    &claim,
                    polynomial,
                    opening_point,
                    deep_evaluation,
                    batching_coefficient,
                )?;
                self.phase = CommonProofGenerationPhase::ConstructingInitialFri {
                    next_claim_index: claim_index
                        .checked_add(1)
                        .ok_or(CommonProofProverError::CountOverflow)?,
                };
            }
        }
        Ok(())
    }

    fn poll_active_replay_polynomial_reader<Storage, CoinError, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError, BoundOpeningError>,
    >
    where
        Storage: ProofExternalMemory,
    {
        let completed = self
            .active_replay_polynomial_reader
            .as_mut()
            .ok_or(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            ))?
            .reader
            .advance(
                self.executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?,
                storage,
            )
            .map_err(CommonProofGenerationError::Storage)?;
        if completed {
            let active = self.active_replay_polynomial_reader.take().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
            )?;
            let polynomial = active
                .reader
                .finish()
                .map_err(CommonProofGenerationError::Prover)?;
            self.apply_replay_polynomial_read_continuation(active.continuation, polynomial)
                .map_err(CommonProofGenerationError::Prover)?;
            Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
        } else {
            Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
        }
    }

    fn prepare_tree_materialization(
        &mut self,
        catalog_index: usize,
        leaf_source: CommonProofTreeLeafSource,
        continuation: CommonProofTreeContinuation,
    ) -> Result<(), CommonProofProverError> {
        if self.active_tree_materialization.is_some() || self.pending_tree_continuation.is_some() {
            return Err(CommonProofProverError::InvalidTree);
        }
        let current_step = self
            .executor
            .as_ref()
            .ok_or(CommonProofProverError::InvalidInput)?
            .current_step();
        let entry = self
            .catalog
            .entries()
            .get(catalog_index)
            .ok_or(CommonProofProverError::InvalidTree)?;
        let tree_plan = self
            .storage_tree_plans
            .remove(&entry.tree_catalog_index())
            .ok_or(CommonProofProverError::InvalidTree)?;
        let issued_step = tree_plan
            .object_plans()
            .first()
            .map(|plan| plan.issued_step())
            .ok_or(CommonProofProverError::InvalidTree)?;
        if current_step != issued_step {
            return Err(CommonProofProverError::InvalidTree);
        }
        let materializer = CommonProofMerkleMaterializer::new(entry, tree_plan)?;
        self.active_tree_materialization = Some(ActiveCommonProofTreeMaterialization {
            materializer,
            leaf_source,
            continuation,
        });
        Ok(())
    }

    fn apply_tree_continuation(
        &mut self,
        continuation: CommonProofTreeContinuation,
    ) -> Result<(), CommonProofGenerationInitializationError> {
        match continuation {
            CommonProofTreeContinuation::Base { next_tree_index } => {
                self.phase = CommonProofGenerationPhase::MaterializingBaseTrees { next_tree_index };
            }
            CommonProofTreeContinuation::Auxiliary {
                next_tree_index,
                tree_ordinal,
            } => {
                let entry = unique_catalog_entry(&self.catalog, |source| {
                    source
                        == ProofTreeCatalogSource::RelationProofCreated {
                            tree_role: ProofTreeRole::AuxiliaryOracle,
                            tree_ordinal,
                        }
                })
                .map_err(CommonProofGenerationInitializationError::Prover)?;
                self.transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb_auxiliary_root(
                        tree_ordinal,
                        self.tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationInitializationError::Transcript)?;
                self.phase =
                    CommonProofGenerationPhase::MaterializingAuxiliaryTrees { next_tree_index };
            }
            CommonProofTreeContinuation::Quotient {
                next_component_index,
                component_ordinal,
            } => {
                let entry = unique_catalog_entry(&self.catalog, |source| {
                    source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
                })
                .map_err(CommonProofGenerationInitializationError::Prover)?;
                self.transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb_quotient_root(
                        component_ordinal,
                        self.tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationInitializationError::Transcript)?;
                self.current_quotient_component = None;
                self.phase = CommonProofGenerationPhase::MaterializingQuotientTrees {
                    next_component_index,
                };
            }
            CommonProofTreeContinuation::OpeningMask => {
                let entry = unique_catalog_entry(&self.catalog, |source| {
                    source == ProofTreeCatalogSource::OpeningBatchMask
                })
                .map_err(CommonProofGenerationInitializationError::Prover)?;
                self.transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb_opening_batch_mask_root(
                        self.tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationInitializationError::Transcript)?;
                self.opening_batch_mask = None;
                self.phase = CommonProofGenerationPhase::PreparingFri;
            }
            CommonProofTreeContinuation::Fri { fold_ordinal } => {
                let entry = unique_catalog_entry(&self.catalog, |source| {
                    source == ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal }
                })
                .map_err(CommonProofGenerationInitializationError::Prover)?;
                self.transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb_fri_layer_root(
                        fold_ordinal,
                        self.tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationInitializationError::Transcript)?;
                self.phase = CommonProofGenerationPhase::FoldingFri {
                    next_fold_ordinal: fold_ordinal.checked_add(1).ok_or(
                        CommonProofGenerationInitializationError::Prover(
                            CommonProofProverError::CountOverflow,
                        ),
                    )?,
                };
            }
        }
        Ok(())
    }

    pub(crate) fn poll<Storage, Coins, Sink, BoundOpenings>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
        sink: &mut Sink,
        bound_openings: &mut BoundOpenings,
    ) -> CommonProofGenerationPollResult<
        Storage::Error,
        Coins::Error,
        Sink::Error,
        BoundOpenings::Error,
    >
    where
        Storage: ProofExternalMemory,
        Coins: CommonProofPrivateCoinSource,
        Sink: CommonProofByteSink,
        BoundOpenings: CommonProofBoundOpeningProvider,
    {
        if self.phase == CommonProofGenerationPhase::Cancelled {
            return Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        if self.phase == CommonProofGenerationPhase::Complete {
            return Ok(CommonProofGenerationPoll::Complete);
        }
        if let Some(continuation) = self.pending_tree_continuation {
            self.executor
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?
                .complete_step(storage)
                .map_err(CommonProofGenerationError::Storage)?;
            self.pending_tree_continuation = None;
            self.apply_tree_continuation(continuation)
                .map_err(map_generation_initialization_error)?;
            return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
        }
        if self.active_relation_tree_leaf_reader.is_some() {
            return self.poll_active_relation_tree_leaf_reader(storage, coins);
        }
        if self.active_tree_materialization.is_some() {
            return self.poll_active_tree(storage, coins);
        }
        if self.active_replay_polynomial_writer.is_some() {
            return self.poll_active_replay_polynomial_writer(storage);
        }
        if self.active_replay_polynomial_reader.is_some() {
            return self.poll_active_replay_polynomial_reader(storage);
        }
        if self.active_relation_column_transform.is_some() {
            return self.poll_active_relation_column_transform(storage);
        }

        match self.phase {
            CommonProofGenerationPhase::PreparingInputs => {
                let mut opening_geometries = Vec::new();
                opening_geometries
                    .try_reserve_exact(self.catalog.entries().len())
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                for entry in self.catalog.entries() {
                    if let Some(tree_plan) =
                        self.storage_tree_plans.get(&entry.tree_catalog_index())
                    {
                        let leaf_count = entry
                            .common_context()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidTree,
                            ))?
                            .leaf_count()
                            .map_err(CommonProofProverError::from)
                            .map_err(CommonProofGenerationError::Prover)?;
                        opening_geometries.push(CommonProofOpeningGeometry {
                            tree_catalog_index: entry.tree_catalog_index(),
                            leaf_count,
                            canonical_leaf_byte_length: tree_plan.canonical_leaf_byte_length(),
                        });
                    } else if entry.source() == ProofTreeCatalogSource::RelationBoundPublic {
                        opening_geometries.push(
                            bound_openings
                                .opening_geometry(entry)
                                .map_err(CommonProofGenerationError::BoundOpening)?,
                        );
                    } else {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                }
                let provided_columns = self.provided_pre_challenge_columns.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                let pre_challenge_columns = construct_pre_challenge_relation_columns(
                    &self.variant,
                    provided_columns,
                    coins,
                    self.relation_context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                )
                .map_err(map_private_coin_generation_error)?;
                self.opening_geometries = opening_geometries;
                self.pre_challenge_columns = Some(pre_challenge_columns);
                self.phase =
                    CommonProofGenerationPhase::MaterializingBaseTrees { next_tree_index: 0 };
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::MaterializingBaseTrees { next_tree_index } => {
                let next_tree = self
                    .variant
                    .ordered_trees()
                    .iter()
                    .enumerate()
                    .skip(next_tree_index)
                    .find_map(|(tree_index, descriptor)| match descriptor {
                        RelationTreeDescriptor::ProofCreated {
                            proof_tree_role: 1,
                            ordered_column_ordinals,
                        } => Some((tree_index, ordered_column_ordinals.clone())),
                        _ => None,
                    });
                let Some((tree_index, ordered_column_ordinals)) = next_tree else {
                    self.phase = CommonProofGenerationPhase::DerivingApplicationColumns;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                self.prepare_tree_materialization(
                    tree_index,
                    CommonProofTreeLeafSource::PreChallengeColumns(ordered_column_ordinals),
                    CommonProofTreeContinuation::Base {
                        next_tree_index: tree_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::DerivingApplicationColumns => {
                let mut transcript = CommonProofTranscript::new(
                    self.protocol_version,
                    self.suite_identifier,
                    self.application_statement_schema_identifier,
                    &self.canonical_header_bytes,
                    self.transcript_schedule.clone(),
                )
                .map_err(CommonProofGenerationError::Transcript)?;
                for tree_ordinal in self.transcript_schedule.ordered_base_tree_ordinals() {
                    let entry = unique_catalog_entry(&self.catalog, |source| {
                        source
                            == ProofTreeCatalogSource::RelationProofCreated {
                                tree_role: ProofTreeRole::BaseOracle,
                                tree_ordinal: *tree_ordinal,
                            }
                    })
                    .map_err(CommonProofGenerationError::Prover)?;
                    transcript
                        .absorb_base_root(
                            *tree_ordinal,
                            self.tree_roots[usize::from(entry.tree_catalog_index())],
                        )
                        .map_err(CommonProofGenerationError::Transcript)?;
                }
                let mut application_challenges = Vec::new();
                for challenge_group in self
                    .transcript_schedule
                    .ordered_application_challenge_groups()
                {
                    let challenge = challenge_group.challenge();
                    let values = transcript
                        .sample_application_challenge_group(challenge)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    if values.len() != usize::from(challenge_group.coordinate_count()) {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ));
                    }
                    for (repetition_ordinal, value) in values.into_iter().enumerate() {
                        application_challenges.push(
                            RelationApplicationChallengeAssignment::new(
                                challenge,
                                u16::try_from(repetition_ordinal).map_err(|_| {
                                    CommonProofGenerationError::Prover(
                                        CommonProofProverError::CountOverflow,
                                    )
                                })?,
                                value,
                            )
                            .map_err(CommonProofGenerationError::Relation)?,
                        );
                    }
                }
                let pre_challenge_columns =
                    self.pre_challenge_columns
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                let columns = construct_post_challenge_relation_columns(
                    &self.variant,
                    &self.relation_context,
                    pre_challenge_columns,
                    &application_challenges,
                    coins,
                    self.relation_context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                )
                .map_err(map_private_coin_generation_error)?;
                self.application_challenges = application_challenges;
                self.columns = Some(columns);
                self.transcript = Some(transcript);
                self.phase = CommonProofGenerationPhase::PersistingRelationColumns {
                    next_column_index: 0,
                };
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::PersistingRelationColumns { next_column_index } => {
                let column_count = self
                    .columns
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .len();
                if next_column_index >= column_count {
                    self.executor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .complete_step(storage)
                        .map_err(CommonProofGenerationError::Storage)?;
                    self.columns = None;
                    self.phase = CommonProofGenerationPhase::TransformingRelationColumns {
                        next_column_index: 0,
                    };
                    return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
                }
                let column_ordinal = u32::try_from(next_column_index).map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                self.prepare_replay_polynomial_writer(
                    CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                    CommonProofReplayWriteContinuation::RelationColumn {
                        next_column_index: next_column_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::TransformingRelationColumns { next_column_index } => {
                if next_column_index >= self.variant.ordered_columns().len() {
                    if !self.relation_evaluation_transform_plans.is_empty()
                        || self.relation_evaluation_vectors.len()
                            != self.variant.ordered_columns().len()
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                    self.phase = CommonProofGenerationPhase::MaterializingAuxiliaryTrees {
                        next_tree_index: 0,
                    };
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let column_ordinal = u32::try_from(next_column_index).map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                let plan = self
                    .relation_evaluation_transform_plans
                    .remove(&column_ordinal)
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                let transform = ExternalStockhamTransform::new(plan)
                    .map_err(map_external_polynomial_plan_error)
                    .map_err(CommonProofGenerationError::StoragePlan)?;
                self.active_relation_column_transform = Some(ActiveRelationColumnTransform {
                    column_ordinal,
                    transform,
                });
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::MaterializingAuxiliaryTrees { next_tree_index } => {
                let next_tree = self
                    .variant
                    .ordered_trees()
                    .iter()
                    .enumerate()
                    .skip(next_tree_index)
                    .find_map(|(tree_index, descriptor)| match descriptor {
                        RelationTreeDescriptor::ProofCreated {
                            proof_tree_role: 2,
                            ordered_column_ordinals,
                        } => Some((tree_index, ordered_column_ordinals.clone())),
                        _ => None,
                    });
                let Some((tree_index, ordered_column_ordinals)) = next_tree else {
                    self.relation_evaluation_vectors.clear();
                    self.phase = CommonProofGenerationPhase::ConstructingQuotient;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                let tree_ordinal = match self
                    .catalog
                    .entries()
                    .get(tree_index)
                    .map(ProofTreeCatalogEntry::source)
                {
                    Some(ProofTreeCatalogSource::RelationProofCreated {
                        tree_role: ProofTreeRole::AuxiliaryOracle,
                        tree_ordinal,
                    }) => tree_ordinal,
                    _ => {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                };
                self.prepare_tree_materialization(
                    tree_index,
                    CommonProofTreeLeafSource::RelationColumns(ordered_column_ordinals),
                    CommonProofTreeContinuation::Auxiliary {
                        next_tree_index: tree_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                        tree_ordinal,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::ConstructingQuotient => {
                let transcript =
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                let mut composition_challenges = Vec::new();
                for constraint_ordinal in 0..self.transcript_schedule.composition_challenge_count()
                {
                    composition_challenges.push(
                        transcript
                            .sample_composition_challenge(constraint_ordinal)
                            .map_err(CommonProofGenerationError::Transcript)?,
                    );
                }
                self.quotient_builder = Some(
                    CommonProofReplayQuotientBuilder::new(
                        &self.variant,
                        &self.relation_context,
                        self.evaluation_domain,
                        core::mem::take(&mut self.application_challenges),
                        composition_challenges,
                    )
                    .map_err(CommonProofGenerationError::Prover)?,
                );
                self.columns = None;
                self.phase = CommonProofGenerationPhase::ConstructingQuotientBlocks;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::ConstructingQuotientBlocks => {
                if let Some(column_index) = self
                    .quotient_builder
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .next_column_index()
                {
                    self.prepare_replay_polynomial_reader(
                        CommonProofReplayPolynomialKey::RelationColumn(
                            u32::try_from(column_index).map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                        ),
                        CommonProofReplayReadContinuation::QuotientBlockColumn { column_index },
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let completed = self
                    .quotient_builder
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .evaluate_ready_block(&self.variant, &self.relation_context)
                    .map_err(CommonProofGenerationError::Prover)?;
                if !completed {
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let quotient = self
                    .quotient_builder
                    .take()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .finish()
                    .map_err(CommonProofGenerationError::Prover)?;
                self.quotient_component_cursor = Some(
                    CommonProofQuotientComponentCursor::new(
                        &self.variant,
                        &self.relation_context,
                        quotient,
                    )
                    .map_err(CommonProofGenerationError::Prover)?,
                );
                self.phase = CommonProofGenerationPhase::MaterializingQuotientTrees {
                    next_component_index: 0,
                };
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::MaterializingQuotientTrees {
                next_component_index,
            } => {
                if self.current_quotient_component.is_none() {
                    let component = self
                        .quotient_component_cursor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidQuotient,
                        ))?
                        .next_component(
                            coins,
                            self.relation_context
                                .maximum_fiat_shamir_candidate_draws_per_output,
                        )
                        .map_err(map_private_coin_generation_error)?;
                    let Some(component) = component else {
                        self.quotient_component_cursor = None;
                        self.columns = None;
                        self.application_challenges.clear();
                        self.phase = CommonProofGenerationPhase::DerivingDeepOpenings;
                        return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                    };
                    self.current_quotient_component = Some(component);
                    let component_ordinal = u16::try_from(next_component_index).map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                    })?;
                    self.prepare_replay_polynomial_writer(
                        CommonProofReplayPolynomialKey::QuotientComponent(component_ordinal),
                        CommonProofReplayWriteContinuation::QuotientComponent,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let component_ordinal = u16::try_from(next_component_index).map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                let catalog_index = unique_catalog_entry(&self.catalog, |source| {
                    source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
                })
                .map_err(CommonProofGenerationError::Prover)?
                .tree_catalog_index();
                self.prepare_tree_materialization(
                    usize::from(catalog_index),
                    CommonProofTreeLeafSource::QuotientComponent,
                    CommonProofTreeContinuation::Quotient {
                        next_component_index: next_component_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                        component_ordinal,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::DerivingDeepOpenings => {
                let transcript =
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                let mut deep_points = Vec::new();
                for point_ordinal in 0..self.transcript_schedule.deep_point_count() {
                    let mut relation_error = None;
                    let point = transcript.sample_deep_point(point_ordinal, |candidate| match self
                        .variant
                        .deep_point_candidate_is_forbidden(
                            &self.relation_context,
                            point_ordinal,
                            candidate,
                            &deep_points,
                        ) {
                        Ok(forbidden) => forbidden,
                        Err(error) => {
                            relation_error = Some(error);
                            true
                        }
                    });
                    if let Some(error) = relation_error {
                        return Err(CommonProofGenerationError::Relation(error));
                    }
                    deep_points.push(point.map_err(CommonProofGenerationError::Transcript)?);
                }
                let opening_points = self
                    .variant
                    .derive_opening_points(&self.relation_context, &deep_points)
                    .map_err(CommonProofGenerationError::Relation)?;
                let opening_batch_mask = construct_opening_batch_mask(
                    &self.variant,
                    coins,
                    self.relation_context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                )
                .map_err(map_private_coin_generation_error)?;
                self.opening_points = opening_points;
                self.opening_batch_mask = opening_batch_mask;
                self.deep_evaluations.clear();
                self.deep_evaluations
                    .try_reserve_exact(self.variant.ordered_opening_claims().len())
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                if self.transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing
                {
                    self.prepare_replay_polynomial_writer(
                        CommonProofReplayPolynomialKey::OpeningBatchMask,
                        CommonProofReplayWriteContinuation::OpeningBatchMask,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                } else {
                    if self.opening_batch_mask.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidMask,
                        ));
                    }
                    self.phase = CommonProofGenerationPhase::EvaluatingDeepOpenings {
                        next_claim_index: 0,
                    };
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::EvaluatingDeepOpenings { next_claim_index } => {
                let Some(claim) = self
                    .variant
                    .ordered_opening_claims()
                    .get(next_claim_index)
                    .copied()
                else {
                    if self.deep_evaluations.len() != self.variant.ordered_opening_claims().len() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidOpening,
                        ));
                    }
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .absorb_deep_evaluations(&self.deep_evaluations)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    self.phase = CommonProofGenerationPhase::MaterializingOpeningMask;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                self.prepare_replay_polynomial_reader(
                    replay_polynomial_key_for_claim(&claim)
                        .map_err(CommonProofGenerationError::Prover)?,
                    CommonProofReplayReadContinuation::DeepOpening {
                        claim_index: next_claim_index,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::MaterializingOpeningMask => {
                if self.transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing
                {
                    if self.opening_batch_mask.is_none() {
                        self.prepare_replay_polynomial_reader(
                            CommonProofReplayPolynomialKey::OpeningBatchMask,
                            CommonProofReplayReadContinuation::OpeningBatchMaskTree,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                        return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                    }
                    let catalog_index = unique_catalog_entry(&self.catalog, |source| {
                        source == ProofTreeCatalogSource::OpeningBatchMask
                    })
                    .map_err(CommonProofGenerationError::Prover)?
                    .tree_catalog_index();
                    self.prepare_tree_materialization(
                        usize::from(catalog_index),
                        CommonProofTreeLeafSource::OpeningBatchMask,
                        CommonProofTreeContinuation::OpeningMask,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                } else {
                    if self.opening_batch_mask.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidMask,
                        ));
                    }
                    self.phase = CommonProofGenerationPhase::PreparingFri;
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::PreparingFri => {
                let transcript =
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                let mut opening_batch_coefficients = Vec::new();
                let opening_claim_count = usize::try_from(
                    self.transcript_schedule.opening_claim_count(),
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(
                        CommonProofProverError::AllocationLimitExceeded,
                    )
                })?;
                opening_batch_coefficients
                    .try_reserve_exact(opening_claim_count)
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                for claim_ordinal in 0..self.transcript_schedule.opening_claim_count() {
                    opening_batch_coefficients.push(
                        transcript
                            .sample_opening_batch_challenge(claim_ordinal)
                            .map_err(CommonProofGenerationError::Transcript)?,
                    );
                }
                if opening_batch_coefficients.len() != self.variant.ordered_opening_claims().len()
                    || self.deep_evaluations.len() != opening_batch_coefficients.len()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ));
                }
                let opening_degree_bound_exclusive = usize::try_from(
                    self.variant.opening_degree_bound_exclusive(),
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                let initial_coefficient_count = opening_degree_bound_exclusive
                    .checked_sub(1)
                    .filter(|count| *count != 0)
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ))?;
                self.opening_batch_coefficients = opening_batch_coefficients;
                self.initial_fri_polynomial = Some(vec![
                    ProofChallengeExtensionElement::ZERO;
                    initial_coefficient_count
                ]);
                self.phase = CommonProofGenerationPhase::ConstructingInitialFri {
                    next_claim_index: 0,
                };
                if self.transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing
                {
                    self.prepare_replay_polynomial_reader(
                        CommonProofReplayPolynomialKey::OpeningBatchMask,
                        CommonProofReplayReadContinuation::OpeningBatchMaskFri,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::ConstructingInitialFri { next_claim_index } => {
                if let Some(claim) = self
                    .variant
                    .ordered_opening_claims()
                    .get(next_claim_index)
                    .copied()
                {
                    self.prepare_replay_polynomial_reader(
                        replay_polynomial_key_for_claim(&claim)
                            .map_err(CommonProofGenerationError::Prover)?,
                        CommonProofReplayReadContinuation::InitialFriClaim {
                            claim_index: next_claim_index,
                        },
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let mut initial_fri_evaluations = self.initial_fri_polynomial.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidFriLayer),
                )?;
                trim_extension_polynomial(&mut initial_fri_evaluations);
                let opening_degree_bound_exclusive = usize::try_from(
                    self.variant.opening_degree_bound_exclusive(),
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                if extension_polynomial_degree(&initial_fri_evaluations)
                    .is_some_and(|degree| degree >= opening_degree_bound_exclusive - 1)
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidFriLayer,
                    ));
                }
                self.opening_points.clear();
                self.opening_batch_coefficients.clear();
                self.evaluation_domain
                    .evaluate_extension_polynomial_in_place(&mut initial_fri_evaluations)
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofGenerationError::Prover)?;
                self.fri_domain = Some(self.evaluation_domain);
                self.fri_evaluations = Some(initial_fri_evaluations);
                self.phase = CommonProofGenerationPhase::FoldingFri {
                    next_fold_ordinal: 0,
                };
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::FoldingFri { next_fold_ordinal } => {
                if next_fold_ordinal >= self.transcript_schedule.fri_fold_count() {
                    self.phase = CommonProofGenerationPhase::FinishingFri;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let challenge = self
                    .transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .sample_fri_fold_challenge(next_fold_ordinal)
                    .map_err(CommonProofGenerationError::Transcript)?;
                let current_domain =
                    self.fri_domain
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidFriLayer,
                        ))?;
                let mut next_evaluations =
                    self.fri_evaluations
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidFriLayer,
                        ))?;
                fold_extension_evaluations_in_place(
                    &mut next_evaluations,
                    current_domain,
                    challenge,
                )
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofGenerationError::Prover)?;
                let next_domain = current_domain
                    .folded()
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofGenerationError::Prover)?;
                self.fri_domain = Some(next_domain);
                if next_fold_ordinal + 1 < self.transcript_schedule.fri_fold_count() {
                    let catalog_index = unique_catalog_entry(&self.catalog, |source| {
                        source
                            == ProofTreeCatalogSource::NonterminalFriLayer {
                                fold_ordinal: next_fold_ordinal,
                            }
                    })
                    .map_err(CommonProofGenerationError::Prover)?
                    .tree_catalog_index();
                    self.prepare_tree_materialization(
                        usize::from(catalog_index),
                        CommonProofTreeLeafSource::FriEvaluations(next_evaluations),
                        CommonProofTreeContinuation::Fri {
                            fold_ordinal: next_fold_ordinal,
                        },
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                } else {
                    self.fri_evaluations = Some(next_evaluations);
                    self.phase = CommonProofGenerationPhase::FoldingFri {
                        next_fold_ordinal: next_fold_ordinal.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    };
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::FinishingFri => {
                let fri_domain = self.fri_domain.ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidFriLayer,
                ))?;
                let mut terminal_coefficients =
                    self.fri_evaluations
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidFriLayer,
                        ))?;
                fri_domain
                    .interpolate_extension_polynomial_in_place(&mut terminal_coefficients)
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofGenerationError::Prover)?;
                let terminal_coefficient_count = usize::try_from(
                    self.relation_context
                        .final_polynomial_degree_bound_exclusive,
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                if terminal_coefficient_count == 0
                    || extension_polynomial_degree(&terminal_coefficients)
                        .is_some_and(|degree| degree >= terminal_coefficient_count)
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidFriLayer,
                    ));
                }
                terminal_coefficients.resize(
                    terminal_coefficient_count,
                    ProofChallengeExtensionElement::ZERO,
                );
                terminal_coefficients.shrink_to_fit();
                let transcript =
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                transcript
                    .absorb_fri_terminal_coefficients(&terminal_coefficients)
                    .map_err(CommonProofGenerationError::Transcript)?;
                let mut sampled_query_representatives =
                    transcript
                        .sample_query_representatives()
                        .map_err(CommonProofGenerationError::Transcript)?;
                let sorted_query_representatives = transcript
                    .sorted_query_representatives()
                    .map_err(CommonProofGenerationError::Transcript)?;
                sampled_query_representatives.sort_unstable();
                if sampled_query_representatives != sorted_query_representatives
                    || !self.storage_tree_plans.is_empty()
                    || self.root_present.iter().any(|present| !present)
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                let query_section_byte_length = common_proof_query_section_byte_length(
                    &self.catalog,
                    &self.opening_geometries,
                    &sorted_query_representatives,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                let mut prefix_sink =
                    BoundedCommonProofByteSink::new(self.maximum_output_fragment_byte_length)
                        .map_err(map_bounded_fragment_error)?;
                write_common_proof_prefix(
                    &mut prefix_sink,
                    &self.canonical_header_bytes,
                    &self.catalog,
                    &self.tree_roots,
                    &self.deep_evaluations,
                    &terminal_coefficients,
                    &self.transcript_schedule,
                )
                .map_err(|error| match error {
                    CommonProofEncodingError::Prover(error) => {
                        CommonProofGenerationError::Prover(error)
                    }
                    CommonProofEncodingError::Sink(error) => map_bounded_fragment_error(error),
                    CommonProofEncodingError::Artifact(artifact) => match artifact {},
                })?;
                self.terminal_coefficients = terminal_coefficients;
                self.sorted_query_representatives = sorted_query_representatives;
                self.query_section_byte_length = Some(query_section_byte_length);
                self.pending_output_fragment = Some(prefix_sink.finish());
                self.deep_evaluations.clear();
                self.phase = CommonProofGenerationPhase::EmittingPrefix;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::EmittingPrefix => {
                let fragment = self.pending_output_fragment.as_deref().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                sink.write_bytes(fragment)
                    .map_err(CommonProofGenerationError::Sink)?;
                self.pending_output_fragment = None;
                let query_section_byte_length =
                    self.query_section_byte_length
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                self.query_opening_absorber = Some(
                    self.transcript
                        .as_ref()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .begin_query_openings(query_section_byte_length)
                        .map_err(CommonProofGenerationError::Transcript)?,
                );
                self.pending_output_fragment = Some(
                    canonical_common_proof_query_section_header(&self.catalog)
                        .map_err(CommonProofGenerationError::Prover)?
                        .to_vec(),
                );
                self.phase = CommonProofGenerationPhase::EmittingQueryHeader;
                Ok(CommonProofGenerationPoll::OutputFragmentAccepted)
            }
            CommonProofGenerationPhase::EmittingQueryHeader => {
                let fragment = self.pending_output_fragment.as_deref().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                sink.write_bytes(fragment)
                    .map_err(CommonProofGenerationError::Sink)?;
                self.query_opening_absorber
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb(fragment)
                    .map_err(CommonProofGenerationError::Transcript)?;
                self.pending_output_fragment = None;
                self.phase = CommonProofGenerationPhase::EmittingQueries {
                    next_catalog_index: 0,
                };
                Ok(CommonProofGenerationPoll::OutputFragmentAccepted)
            }
            CommonProofGenerationPhase::EmittingQueries { next_catalog_index } => {
                if next_catalog_index >= self.catalog.entries().len() {
                    let absorber = self.query_opening_absorber.take().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?;
                    let mut transcript =
                        self.transcript
                            .take()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?;
                    transcript
                        .finish_query_openings(absorber)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    transcript
                        .finish()
                        .map_err(CommonProofGenerationError::Transcript)?;
                    self.phase = CommonProofGenerationPhase::Finalizing;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                if let Some(fragment) = self.pending_output_fragment.as_deref() {
                    sink.write_bytes(fragment)
                        .map_err(CommonProofGenerationError::Sink)?;
                    self.query_opening_absorber
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .absorb(fragment)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    self.pending_output_fragment = None;
                    self.phase = CommonProofGenerationPhase::EmittingQueries {
                        next_catalog_index: next_catalog_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    };
                    return Ok(CommonProofGenerationPoll::OutputFragmentAccepted);
                }
                let entry = self.catalog.entries().get(next_catalog_index).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                let geometry = *self.opening_geometries.get(next_catalog_index).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                if entry.source() == ProofTreeCatalogSource::RelationBoundPublic {
                    self.pending_output_fragment = Some(
                        bound_openings
                            .encode_bound_opening_fragment(
                                &self.catalog,
                                next_catalog_index,
                                geometry,
                                &self.sorted_query_representatives,
                                self.maximum_output_fragment_byte_length,
                            )
                            .map_err(|error| match error {
                                CommonProofEncodingError::Prover(error) => {
                                    CommonProofGenerationError::Prover(error)
                                }
                                CommonProofEncodingError::Sink(error) => {
                                    map_bounded_fragment_error(error)
                                }
                                CommonProofEncodingError::Artifact(error) => {
                                    CommonProofGenerationError::BoundOpening(error)
                                }
                            })?,
                    );
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                if self.opening_prefetcher.is_none() {
                    let tree = self.stored_trees.get(&entry.tree_catalog_index()).ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                    )?;
                    self.opening_prefetcher = Some(
                        CommonProofOpeningPrefetcher::new(
                            tree,
                            entry,
                            self.catalog.evaluation_domain_size(),
                            &self.sorted_query_representatives,
                            self.maximum_prefetched_query_byte_length,
                        )
                        .map_err(CommonProofGenerationError::Prover)?,
                    );
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let prefetch_progress = self
                    .opening_prefetcher
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ))?
                    .advance_storage(
                        self.executor
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?,
                        storage,
                    )
                    .map_err(CommonProofGenerationError::Storage)?;
                match prefetch_progress {
                    CommonProofOpeningPrefetchProgress::StorageTransactionCompleted => {
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    CommonProofOpeningPrefetchProgress::Complete => {
                        let mut artifact = self
                            .opening_prefetcher
                            .take()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidOpening,
                            ))?
                            .finish()
                            .map_err(CommonProofGenerationError::Prover)?;
                        self.pending_output_fragment = Some(
                            encode_common_proof_query_tree_fragment(
                                &self.catalog,
                                next_catalog_index,
                                geometry,
                                &self.sorted_query_representatives,
                                &mut artifact,
                                self.maximum_output_fragment_byte_length,
                            )
                            .map_err(|error| match error {
                                CommonProofEncodingError::Prover(error) => {
                                    CommonProofGenerationError::Prover(error)
                                }
                                CommonProofEncodingError::Sink(error) => {
                                    map_bounded_fragment_error(error)
                                }
                                CommonProofEncodingError::Artifact(error) => {
                                    CommonProofGenerationError::Prover(error)
                                }
                            })?,
                        );
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                }
            }
            CommonProofGenerationPhase::Finalizing => {
                self.executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .complete_step(storage)
                    .map_err(CommonProofGenerationError::Storage)?;
                self.executor
                    .take()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .finish()
                    .map_err(CommonProofGenerationError::StoragePlan)?;
                self.phase = CommonProofGenerationPhase::Complete;
                Ok(CommonProofGenerationPoll::Complete)
            }
            CommonProofGenerationPhase::Complete => Ok(CommonProofGenerationPoll::Complete),
            CommonProofGenerationPhase::Cancelled => Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            )),
        }
    }

    pub(crate) fn cancel<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.phase == CommonProofGenerationPhase::Cancelled {
            return Ok(());
        }
        if let Some(executor) = self.executor.as_mut() {
            executor.cancel(storage)?;
        }
        self.executor = None;
        self.phase = CommonProofGenerationPhase::Cancelled;
        self.active_tree_materialization = None;
        self.pending_tree_continuation = None;
        self.active_replay_polynomial_writer = None;
        self.active_replay_polynomial_reader = None;
        self.active_relation_column_transform = None;
        self.active_relation_tree_leaf_reader = None;
        self.provided_pre_challenge_columns = None;
        self.pre_challenge_columns = None;
        self.columns = None;
        self.application_challenges = Vec::new();
        self.quotient_builder = None;
        self.quotient_component_cursor = None;
        self.current_quotient_component = None;
        self.opening_points = Vec::new();
        self.opening_batch_mask = None;
        self.deep_evaluations = Vec::new();
        self.opening_batch_coefficients = Vec::new();
        self.initial_fri_polynomial = None;
        self.fri_domain = None;
        self.fri_evaluations = None;
        self.terminal_coefficients = Vec::new();
        self.sorted_query_representatives = Vec::new();
        self.opening_geometries = Vec::new();
        self.storage_tree_plans = BTreeMap::new();
        self.replay_polynomial_plans = BTreeMap::new();
        self.relation_evaluation_transform_plans = BTreeMap::new();
        self.relation_evaluation_vectors = BTreeMap::new();
        self.stored_trees = BTreeMap::new();
        self.tree_roots = Vec::new();
        self.root_present = Vec::new();
        self.transcript = None;
        self.query_opening_absorber = None;
        self.query_section_byte_length = None;
        self.opening_prefetcher = None;
        self.pending_output_fragment = None;
        self.relation_trees = Vec::new();
        self.canonical_header_bytes = Vec::new();
        Ok(())
    }
}

fn map_generation_initialization_error<StorageError, CoinError, SinkError, BoundOpeningError>(
    error: CommonProofGenerationInitializationError,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    match error {
        CommonProofGenerationInitializationError::Prover(error) => {
            CommonProofGenerationError::Prover(error)
        }
        CommonProofGenerationInitializationError::Profile(error) => {
            CommonProofGenerationError::Profile(error)
        }
        CommonProofGenerationInitializationError::Relation(error) => {
            CommonProofGenerationError::Relation(error)
        }
        CommonProofGenerationInitializationError::Body(error) => {
            CommonProofGenerationError::Body(error)
        }
        CommonProofGenerationInitializationError::Transcript(error) => {
            CommonProofGenerationError::Transcript(error)
        }
        CommonProofGenerationInitializationError::StoragePlan(error) => {
            CommonProofGenerationError::StoragePlan(error)
        }
    }
}

fn map_bounded_fragment_error<StorageError, CoinError, SinkError, BoundOpeningError>(
    error: BoundedCommonProofByteSinkError,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    match error {
        BoundedCommonProofByteSinkError::ByteLengthExceeded
        | BoundedCommonProofByteSinkError::AllocationLimitExceeded => {
            CommonProofGenerationError::Prover(CommonProofProverError::AllocationLimitExceeded)
        }
    }
}

#[cfg(test)]
pub(crate) fn generate_common_proof<Storage, Coins, Sink, BoundOpenings>(
    input: CommonProofGenerationInput<'_>,
    storage: &mut Storage,
    coins: &mut Coins,
    sink: &mut Sink,
    bound_openings: &mut BoundOpenings,
) -> CompletedCommonProofGenerationResult<Storage, Coins, Sink, BoundOpenings>
where
    Storage: ProofExternalMemory,
    Coins: CommonProofPrivateCoinSource,
    Sink: CommonProofByteSink,
    BoundOpenings: CommonProofBoundOpeningProvider,
{
    let mut state_machine = CommonProofGenerationStateMachine::new(input)
        .map_err(map_generation_initialization_error)?;
    let generation_result = loop {
        match state_machine.poll(storage, coins, sink, bound_openings) {
            Ok(CommonProofGenerationPoll::Complete) => break Ok(()),
            Ok(
                CommonProofGenerationPoll::ArithmeticStepCompleted
                | CommonProofGenerationPoll::StorageTransactionCompleted
                | CommonProofGenerationPoll::OutputFragmentAccepted,
            ) => {}
            Err(error) => break Err(error),
        }
    };
    match generation_result {
        Ok(()) => Ok(()),
        Err(original) => match state_machine.cancel(storage) {
            Ok(()) => Err(original),
            Err(cleanup) => Err(CommonProofGenerationError::Cleanup {
                original: Box::new(original),
                cleanup,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{
        ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomnessDerivationInput, ActionRandomnessRoot,
        ParticipantIdentity, PersistentProofCoinInput, ProofApplicationSlot,
    };

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("test value is canonical")
    }

    fn extension(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(base(value))
    }

    fn signed_base(value: i64) -> ProofBaseFieldElement {
        if value >= 0 {
            base(value as u64)
        } else {
            base(super::super::PROOF_BASE_FIELD_MODULUS - value.unsigned_abs())
        }
    }

    fn naive_negacyclic_product(
        left: &[ProofBaseFieldElement],
        right: &[ProofBaseFieldElement],
    ) -> Vec<ProofBaseFieldElement> {
        assert_eq!(left.len(), right.len());
        let mut output = vec![ProofBaseFieldElement::ZERO; left.len()];
        for (left_ordinal, left_value) in left.iter().copied().enumerate() {
            for (right_ordinal, right_value) in right.iter().copied().enumerate() {
                let product = left_value.multiply(right_value);
                let sum_ordinal = left_ordinal + right_ordinal;
                if sum_ordinal < left.len() {
                    output[sum_ordinal] = output[sum_ordinal].add(product);
                } else {
                    output[sum_ordinal - left.len()] =
                        output[sum_ordinal - left.len()].subtract(product);
                }
            }
        }
        output
    }

    fn naive_ordinary_product(
        left: &[ProofBaseFieldElement],
        right: &[ProofBaseFieldElement],
    ) -> Vec<ProofBaseFieldElement> {
        assert_eq!(left.len(), right.len());
        let mut output = vec![ProofBaseFieldElement::ZERO; left.len() * 2];
        for (left_ordinal, left_value) in left.iter().copied().enumerate() {
            for (right_ordinal, right_value) in right.iter().copied().enumerate() {
                let sum_ordinal = left_ordinal + right_ordinal;
                output[sum_ordinal] = output[sum_ordinal].add(left_value.multiply(right_value));
            }
        }
        output
    }

    fn theta_fingerprint(
        coefficients: &[ProofBaseFieldElement],
        theta: ProofBaseFieldElement,
    ) -> ProofBaseFieldElement {
        coefficients
            .iter()
            .rev()
            .fold(ProofBaseFieldElement::ZERO, |accumulated, coefficient| {
                accumulated.multiply(theta).add(*coefficient)
            })
    }

    #[test]
    fn trace_mask_changes_coefficients_but_preserves_every_trace_domain_value() {
        let witness = CommonProofSourcePolynomial::Base(vec![base(7), base(11), base(13)]);
        let mask = CommonProofSourcePolynomial::Base(vec![base(17), base(19), base(23)]);
        let masked =
            apply_trace_mask(witness.clone(), 8, mask).expect("valid trace mask is applied");
        assert_ne!(masked, witness);

        let trace_domain = ProofEvaluationDomain::new(8, 7)
            .expect("evaluation domain exposes the trace subgroup generator");
        for position in 0..trace_domain.size() {
            let point =
                ProofChallengeExtensionElement::from_base(trace_domain.generator().power(
                    u64::try_from(position).expect("test position fits the field exponent"),
                ));
            assert_eq!(masked.evaluate_at(point), witness.evaluate_at(point));
        }
    }

    #[test]
    fn trace_mask_rejects_cross_field_application() {
        let result = apply_trace_mask(
            CommonProofSourcePolynomial::Base(vec![base(1)]),
            4,
            CommonProofSourcePolynomial::Extension(vec![extension(2)]),
        );
        assert_eq!(result, Err(CommonProofProverError::InvalidMask));
    }

    #[test]
    fn reversal_fingerprints_cover_zero_one_and_largest_non_native_challenges() {
        let source = [3, -2, 7, 1, -4, 5, 2, -1].map(signed_base).to_vec();
        let mut reversed = source.iter().copied().rev().collect::<Vec<_>>();
        for theta in [base(0), base(1), base(96)] {
            let prefix = prefix_evaluation_rows(&source, theta);
            let suffix = suffix_evaluation_rows(&reversed, theta);
            assert_eq!(prefix[0], source[0]);
            for row_ordinal in 1..source.len() {
                assert_eq!(
                    prefix[row_ordinal],
                    source[row_ordinal].add(theta.multiply(prefix[row_ordinal - 1])),
                );
            }
            assert_eq!(suffix[source.len() - 1], reversed[source.len() - 1]);
            for row_ordinal in 0..source.len() - 1 {
                assert_eq!(
                    suffix[row_ordinal],
                    reversed[row_ordinal].add(theta.multiply(suffix[row_ordinal + 1])),
                );
            }
            assert_eq!(prefix[source.len() - 1], suffix[0]);

            reversed[0] = reversed[0].add(ProofBaseFieldElement::ONE);
            assert_ne!(
                prefix[source.len() - 1],
                suffix_evaluation_rows(&reversed, theta)[0],
            );
            reversed[0] = reversed[0].subtract(ProofBaseFieldElement::ONE);
        }
    }

    #[test]
    fn convolution_transposes_match_all_checked_convolution_kinds() {
        for row_count in [4_usize, 8] {
            let multiplicand = (0..row_count)
                .map(|ordinal| signed_base((ordinal as i64 % 5) - 2))
                .collect::<Vec<_>>();
            let multiplier = (0..row_count)
                .map(|ordinal| signed_base(((ordinal * 3 + 1) as i64 % 7) - 3))
                .collect::<Vec<_>>();
            let reversed_multiplier = multiplier.iter().copied().rev().collect::<Vec<_>>();
            let ordinary = naive_ordinary_product(&multiplicand, &multiplier);
            let negacyclic = naive_negacyclic_product(&multiplicand, &multiplier);
            for theta in [base(0), base(1), base(96)] {
                let suffix = suffix_evaluation_rows(&multiplicand, theta);
                for (kind, expected_coefficients) in [
                    (
                        RelationIntegerLiftConvolutionKind::Negacyclic,
                        negacyclic.as_slice(),
                    ),
                    (
                        RelationIntegerLiftConvolutionKind::OrdinaryLowHalf,
                        &ordinary[..row_count],
                    ),
                    (
                        RelationIntegerLiftConvolutionKind::OrdinaryHighHalf,
                        &ordinary[row_count..],
                    ),
                ] {
                    let transpose = convolution_transpose_rows(kind, &multiplicand, &suffix, theta)
                        .expect("checked transpose rows");
                    let dot_product = transpose
                        .iter()
                        .copied()
                        .zip(reversed_multiplier.iter().copied())
                        .fold(ProofBaseFieldElement::ZERO, |sum, (left, right)| {
                            sum.add(left.multiply(right))
                        });
                    assert_eq!(
                        dot_product,
                        theta_fingerprint(expected_coefficients, theta),
                        "kind={kind:?} row_count={row_count} theta={}",
                        theta.canonical(),
                    );
                }
            }
        }
    }

    #[test]
    fn full_ring_transposes_match_both_negacyclic_product_halves() {
        for half_ring_degree in [4_usize, 8] {
            let multiplicand_low = (0..half_ring_degree)
                .map(|ordinal| signed_base((ordinal as i64 % 5) - 1))
                .collect::<Vec<_>>();
            let multiplicand_high = (0..half_ring_degree)
                .map(|ordinal| signed_base(((ordinal * 2 + 3) as i64 % 7) - 2))
                .collect::<Vec<_>>();
            let multiplier_low = (0..half_ring_degree)
                .map(|ordinal| signed_base(((ordinal * 3 + 2) as i64 % 7) - 3))
                .collect::<Vec<_>>();
            let multiplier_high = (0..half_ring_degree)
                .map(|ordinal| signed_base(((ordinal * 5 + 1) as i64 % 11) - 5))
                .collect::<Vec<_>>();
            let mut multiplicand = multiplicand_low.clone();
            multiplicand.extend_from_slice(&multiplicand_high);
            let mut multiplier = multiplier_low.clone();
            multiplier.extend_from_slice(&multiplier_high);
            let product = naive_negacyclic_product(&multiplicand, &multiplier);
            let reversed_multiplier_low = multiplier_low.iter().copied().rev().collect::<Vec<_>>();
            let reversed_multiplier_high =
                multiplier_high.iter().copied().rev().collect::<Vec<_>>();

            for theta in [base(0), base(1), base(96)] {
                let low_suffix = suffix_evaluation_rows(&multiplicand_low, theta);
                let high_suffix = suffix_evaluation_rows(&multiplicand_high, theta);
                for selected_half in [
                    RelationIntegerLiftFullRingHalf::Low,
                    RelationIntegerLiftFullRingHalf::High,
                ] {
                    let low_transpose = full_ring_transpose_rows(
                        selected_half,
                        true,
                        &multiplicand_low,
                        &multiplicand_high,
                        &low_suffix,
                        &high_suffix,
                        theta,
                    )
                    .expect("low multiplier transpose");
                    let high_transpose = full_ring_transpose_rows(
                        selected_half,
                        false,
                        &multiplicand_low,
                        &multiplicand_high,
                        &low_suffix,
                        &high_suffix,
                        theta,
                    )
                    .expect("high multiplier transpose");
                    let dot_product = (0..half_ring_degree).fold(
                        ProofBaseFieldElement::ZERO,
                        |sum, row_ordinal| {
                            sum.add(
                                low_transpose[row_ordinal]
                                    .multiply(reversed_multiplier_low[row_ordinal]),
                            )
                            .add(
                                high_transpose[row_ordinal]
                                    .multiply(reversed_multiplier_high[row_ordinal]),
                            )
                        },
                    );
                    let selected_coefficients = match selected_half {
                        RelationIntegerLiftFullRingHalf::Low => &product[..half_ring_degree],
                        RelationIntegerLiftFullRingHalf::High => &product[half_ring_degree..],
                    };
                    assert_eq!(
                        dot_product,
                        theta_fingerprint(selected_coefficients, theta),
                        "half={selected_half:?} degree={half_ring_degree} theta={}",
                        theta.canonical(),
                    );

                    let mut mutated = low_transpose;
                    mutated[0] = mutated[0].add(ProofBaseFieldElement::ONE);
                    let mutated_dot_product = (0..half_ring_degree).fold(
                        ProofBaseFieldElement::ZERO,
                        |sum, row_ordinal| {
                            sum.add(
                                mutated[row_ordinal].multiply(reversed_multiplier_low[row_ordinal]),
                            )
                            .add(
                                high_transpose[row_ordinal]
                                    .multiply(reversed_multiplier_high[row_ordinal]),
                            )
                        },
                    );
                    assert_ne!(
                        mutated_dot_product,
                        theta_fingerprint(selected_coefficients, theta),
                    );
                }
            }
        }
    }

    #[test]
    fn product_accumulator_enforces_every_row_and_the_terminal_identity() {
        let product_rows = [4, -3, 7, 2, -5, 1, 6, -2].map(signed_base).to_vec();
        let accumulator = product_accumulator_rows(&product_rows);
        for row_ordinal in 0..product_rows.len() - 1 {
            assert_eq!(
                accumulator[row_ordinal + 1],
                accumulator[row_ordinal].add(product_rows[row_ordinal]),
            );
        }
        let total = product_rows
            .iter()
            .copied()
            .fold(ProofBaseFieldElement::ZERO, ProofBaseFieldElement::add);
        let linear_at_zero = total.negate();
        assert_eq!(
            accumulator[0]
                .subtract(accumulator[accumulator.len() - 1])
                .subtract(product_rows[product_rows.len() - 1])
                .subtract(linear_at_zero),
            ProofBaseFieldElement::ZERO,
        );
        assert_ne!(
            accumulator[0]
                .subtract(accumulator[accumulator.len() - 1])
                .subtract(product_rows[product_rows.len() - 1].add(ProofBaseFieldElement::ONE))
                .subtract(linear_at_zero),
            ProofBaseFieldElement::ZERO,
        );
    }

    #[test]
    fn quotient_decomposition_is_constant_first_and_exactly_reconstructible() {
        let quotient = (1..=11).map(extension).collect::<Vec<_>>();
        let components = decompose_composed_quotient(&quotient, 3, 4)
            .expect("quotient fits the declared decomposition");
        assert_eq!(
            components.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![4, 4, 3]
        );
        assert_eq!(components.concat(), quotient);
        assert_eq!(
            decompose_composed_quotient(&[extension(1); 9], 2, 4),
            Err(CommonProofProverError::InvalidQuotient)
        );
    }

    #[test]
    fn materialization_write_budget_counts_every_bounded_record_append() {
        assert_eq!(
            common_tree_materialization_write_transaction_count(4, 100, 1_024)
                .expect("the leaf object and each digest level fit the transaction count"),
            4,
        );
        assert_eq!(
            common_tree_materialization_write_transaction_count(4, 100, 48)
                .expect("object-wide canonical chunking fits the transaction count"),
            20,
        );
        assert_eq!(
            common_tree_materialization_write_transaction_count(1_u64 << 63, 100, 48),
            Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            )),
        );
    }

    #[test]
    fn proof_header_delegates_to_the_foundation_schema() {
        let statement = CanonicalTuple::new(0x1216, 1, vec![CanonicalItem::unsigned16(7)])
            .encode()
            .expect("test statement encodes");
        let expected = ProofObjectHeader::from_canonical_application_statement(
            statement.clone(),
            &CanonicalDecodeLimits::default(),
        )
        .and_then(|header| header.encode())
        .expect("foundation proof header encodes");
        assert_eq!(
            canonical_proof_object_header_bytes(&statement).expect("prover proof header encodes"),
            expected
        );
        assert_eq!(
            canonical_proof_object_header_bytes(&[]),
            Err(CommonProofProverError::InvalidInput)
        );
    }

    #[test]
    fn private_randomness_coin_source_resumes_exactly_and_keeps_purposes_independent() {
        let suite_identifier = Hash512::from_bytes([0x11; 64]);
        let ceremony_context_hash = Hash512::from_bytes([0x22; 64]);
        let action_context_hash = Hash512::from_bytes([0x33; 64]);
        let participant_identity =
            ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]);
        let action_private_randomness = ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x55; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(ActionRandomnessDerivationInput::new(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            participant_identity,
        ))
        .expect("action private randomness derives");
        let application_slot = ProofApplicationSlot::new(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            0x1211,
            Some(2),
            None,
            None,
        )
        .expect("reset-safe proof slot is assigned");
        let attempt_input =
            PersistentProofCoinInput::new(application_slot, Hash512::from_bytes([0x66; 64]))
                .expect("persistent proof attempt input is valid");
        let attempt_identifier = action_private_randomness
            .persistent_proof_attempt_identifier(&attempt_input)
            .expect("persistent proof attempt derives");
        let derivation_context_hash = Hash512::from_bytes([0x77; 64]);

        let mut uninterrupted = PrivateRandomnessCommonProofCoinSource::new(
            &action_private_randomness,
            0x1211,
            derivation_context_hash,
            attempt_identifier,
        )
        .expect("coin source starts");
        let _first = uninterrupted
            .sample_modulo(1, super::super::PROOF_BASE_FIELD_MODULUS, 64)
            .expect("first purpose-one sample succeeds");
        let authenticated_cursors = uninterrupted.cursors().collect::<Vec<_>>();
        let expected_next = uninterrupted
            .sample_modulo(1, super::super::PROOF_BASE_FIELD_MODULUS, 64)
            .expect("uninterrupted suffix sample succeeds");
        let expected_purpose_two = uninterrupted
            .sample_modulo(2, super::super::PROOF_BASE_FIELD_MODULUS, 64)
            .expect("independent purpose-two sample succeeds");

        let mut resumed = PrivateRandomnessCommonProofCoinSource::resume(
            &action_private_randomness,
            0x1211,
            derivation_context_hash,
            attempt_identifier,
            authenticated_cursors,
        )
        .expect("authenticated cursor resumes");
        assert_eq!(
            resumed
                .sample_modulo(1, super::super::PROOF_BASE_FIELD_MODULUS, 64)
                .expect("resumed suffix sample succeeds"),
            expected_next,
        );
        assert_eq!(
            resumed
                .sample_modulo(2, super::super::PROOF_BASE_FIELD_MODULUS, 64)
                .expect("resumed independent purpose starts at counter zero"),
            expected_purpose_two,
        );
        let duplicate_cursor = resumed
            .cursors()
            .next()
            .expect("at least one cursor was retained");
        assert!(matches!(
            PrivateRandomnessCommonProofCoinSource::resume(
                &action_private_randomness,
                0x1211,
                derivation_context_hash,
                attempt_identifier,
                [duplicate_cursor, duplicate_cursor],
            ),
            Err(PrivateRandomnessCommonProofCoinError::DuplicateCursorPurpose),
        ));
    }
}
