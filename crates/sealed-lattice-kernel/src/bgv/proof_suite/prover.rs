//! Production prover primitives for the suite-bound common transparent proof.
//!
//! This module contains no native-only path.  Large oracle, Merkle, quotient,
//! and FRI material can be persisted through `external_memory`; proof bytes are
//! emitted to a bounded sink and never need to exist as one allocation.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::foundation::{
    ActionPrivateRandomness, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, FoundationSchemaError, Hash512, PRIVATE_PROOF_SALT_PURPOSE,
    PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
    PrivateRandomnessStream, ProofObjectHeader, hash_foundation_tuple_512,
};

use super::{
    CompleteProofTreeCatalog, CommonProofPrivacyMode, CommonProofTranscript,
    CommonProofTranscriptSchedule, CompiledRelationPlan, ProofBodyError,
    CommonProofQueryOpeningAbsorber,
    ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofEvaluationDomain, ProofFieldError, ProofLeafVisibility,
    ProofMerkleError, ProofMerkleTreeContext, ProofOraclePhasePairLeaf,
    ProofPolynomialError, ProofTreeCatalogEntry, ProofTreeCatalogSource,
    ProofTreeRole, ProofTreeValue, RelationApplicationChallengeAssignment,
    RelationPlanCheckContext, RelationPlanError, RelationPlanVariant,
    SuiteModulusReference, ValidatedRelationPlanArtifact,
    CommonProofChallenge, ProofProfileError,
    ProofTreeCatalogInput, RelationProofTreeInput, StatementOwnedProofTreeInput,
    build_complete_proof_tree_catalog,
    divide_extension_polynomial_by_linear, evaluate_extension_at,
    extension_polynomial_degree, fold_extension_evaluations, TranscriptError,
};
use super::external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject,
    ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
    ProofExternalMemoryProtection,
};
use super::relation_plan::{
    BoundTreeConstructionKind, ProofPrivacyMode, RelationColumnDescriptor,
    RelationColumnOrigin, RelationColumnValueType,
    RelationIntegerLiftCoefficient, RelationIntegerLiftComponentDescriptor,
    RelationIntegerLiftConvolutionKind, RelationIntegerLiftConvolutionProductDescriptor,
    RelationIntegerLiftFullRingHalf,
    RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    RelationIntegerLiftLinearTermDescriptor, RelationIntegerLiftReversedColumnBindingDescriptor,
    RelationMaskDescriptor, RelationMaskKind, RelationMaskTargetClass,
    RelationOpeningSourceClass, RelationTreeDescriptor,
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

    fn fill_raw_bytes(
        &mut self,
        purpose: u16,
        destination: &mut [u8],
    ) -> Result<(), Self::Error>;
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
            let domain = PrivateRandomnessDomain::from_assigned_pair(
                family_schema_identifier,
                purpose,
            )?;
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
        let domain = PrivateRandomnessDomain::from_assigned_pair(
            self.family_schema_identifier,
            purpose,
        )?;
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

    fn fill_raw_bytes(
        &mut self,
        purpose: u16,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let mut stream = self.stream_for_purpose(purpose)?;
        let result = stream
            .fill_bytes(destination)
            .map_err(PrivateRandomnessCommonProofCoinError::Custody);
        self.retain_stream_cursor(stream);
        result
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

    fn into_extension_coefficients(self) -> Vec<ProofChallengeExtensionElement> {
        match self {
            Self::Base(coefficients) => coefficients
                .into_iter()
                .map(ProofChallengeExtensionElement::from_base)
                .collect(),
            Self::Extension(coefficients) => coefficients,
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
            Self::Extension(values) => values
                .get(position)
                .copied()
                .map(ProofTreeValue::Extension),
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
            CommonProofSourcePolynomial::Base(coefficients) => {
                CommonProofColumnEvaluations::Base(
                    evaluation_domain.evaluate_base_polynomial(coefficients)?,
                )
            }
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
            CommonProofSourcePolynomial::Base(coefficients) => {
                CommonProofColumnEvaluations::Base(
                    evaluation_domain.evaluate_base_polynomial(coefficients)?,
                )
            }
            CommonProofSourcePolynomial::Extension(coefficients) => {
                CommonProofColumnEvaluations::Extension(
                    evaluation_domain.evaluate_extension_polynomial(coefficients)?,
                )
            }
        });
    }
    Ok(evaluations)
}

/// Returns the two opposite-domain rows represented by one canonical common
/// leaf.  The closure passed to `materialize_common_proof_merkle_tree` can call
/// this directly without constructing a second leaf matrix.
pub(crate) fn common_proof_phase_pair_values(
    column_evaluations: &[CommonProofColumnEvaluations],
    leaf_index: u64,
) -> Result<(Vec<ProofTreeValue>, Vec<ProofTreeValue>), CommonProofProverError> {
    let evaluation_size = column_evaluations
        .first()
        .map(|column| match column {
            CommonProofColumnEvaluations::Base(values) => values.len(),
            CommonProofColumnEvaluations::Extension(values) => values.len(),
        })
        .ok_or(CommonProofProverError::InvalidTree)?;
    if evaluation_size < 2 || !evaluation_size.is_power_of_two() {
        return Err(CommonProofProverError::InvalidTree);
    }
    let first_is_base = matches!(
        column_evaluations.first(),
        Some(CommonProofColumnEvaluations::Base(_))
    );
    let first_position = usize::try_from(leaf_index)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let opposite_position = first_position
        .checked_add(evaluation_size / 2)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if first_position >= evaluation_size / 2
        || column_evaluations.iter().any(|column| match column {
            CommonProofColumnEvaluations::Base(values) => {
                !first_is_base || values.len() != evaluation_size
            }
            CommonProofColumnEvaluations::Extension(values) => {
                first_is_base || values.len() != evaluation_size
            }
        })
    {
        return Err(CommonProofProverError::InvalidTree);
    }
    let mut first_point_values = Vec::new();
    let mut opposite_point_values = Vec::new();
    first_point_values
        .try_reserve_exact(column_evaluations.len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    opposite_point_values
        .try_reserve_exact(column_evaluations.len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for column in column_evaluations {
        first_point_values.push(column.tree_value(first_position)?);
        opposite_point_values.push(column.tree_value(opposite_position)?);
    }
    Ok((first_point_values, opposite_point_values))
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
        .map_err(|_| CommonProofPrivateCoinError::Prover(
            CommonProofProverError::AllocationLimitExceeded,
        ))?;
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
        .map_err(|_| CommonProofPrivateCoinError::Prover(
            CommonProofProverError::AllocationLimitExceeded,
        ))?;
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
    let trace_domain_size = usize::try_from(trace_domain_size)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
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
    pub(crate) fn column(
        &self,
        column_ordinal: u32,
    ) -> Option<&CommonProofSourcePolynomial> {
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
    let tree_roles = proof_created_tree_roles_by_column(variant)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let (reversed_columns_by_source, integer_lift_auxiliary_columns) =
        integer_lift_derived_columns(variant)
            .map_err(CommonProofPrivateCoinError::Prover)?;
    let reversed_columns = reversed_columns_by_source
        .values()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut columns = vec![None; variant.ordered_columns().len()];

    for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
        let column_ordinal = u32::try_from(column_index)
            .map_err(|_| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        let is_auxiliary_tree_column = tree_roles.get(&column_ordinal)
            == Some(&ProofTreeRole::AuxiliaryOracle);
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
        validate_unmasked_column(descriptor, &source, variant.trace_domain_size())
            .map_err(CommonProofPrivateCoinError::Prover)?;
        columns[column_index] = Some(source);
    }
    if !provided_columns.is_empty() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }

    let trace_domain = ProofEvaluationDomain::new_subgroup(
        usize::try_from(variant.trace_domain_size())
            .map_err(|_| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::CountOverflow,
            ))?,
    )
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
        let mut reversed_rows = base_trace_rows(source, trace_domain)
            .map_err(CommonProofPrivateCoinError::Prover)?;
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

    let trace_masks = trace_masks_by_column(variant)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
        let column_ordinal = u32::try_from(column_index)
            .map_err(|_| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        match tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::BaseOracle) => {
                let source = columns[column_index].take().ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    )
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

/// Synthesizes every integer-lift auxiliary column from the checked
/// descriptors and the complete transcript challenge vector, then applies the
/// plan-assigned masks.  The function handles every batch in one call so no
/// prover message can be inserted between consecutive theta or alpha draws.
/// Callers may provide only non-integer-lift auxiliary columns used by other
/// checked relation grammars.
pub(crate) fn construct_post_challenge_relation_columns<Coins>(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    mut pre_challenge_columns: CommonProofPreChallengeRelationColumns,
    mut provided_non_integer_lift_auxiliary_columns:
        BTreeMap<u32, CommonProofSourcePolynomial>,
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
    let tree_roles = proof_created_tree_roles_by_column(variant)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let (_, integer_lift_auxiliary_columns) = integer_lift_derived_columns(variant)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let trace_masks = trace_masks_by_column(variant)
        .map_err(CommonProofPrivateCoinError::Prover)?;

    for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
        let column_ordinal = u32::try_from(column_index)
            .map_err(|_| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        match tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::AuxiliaryOracle)
                if !integer_lift_auxiliary_columns.contains(&column_ordinal) =>
            {
                if pre_challenge_columns.columns[column_index].is_some() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                let source = provided_non_integer_lift_auxiliary_columns
                    .remove(&column_ordinal)
                    .ok_or_else(|| {
                        CommonProofPrivateCoinError::Prover(
                            CommonProofProverError::InvalidColumn,
                        )
                    })?;
                validate_unmasked_column(descriptor, &source, variant.trace_domain_size())
                    .map_err(CommonProofPrivateCoinError::Prover)?;
                pre_challenge_columns.columns[column_index] = Some(mask_relation_column(
                    variant,
                    descriptor,
                    trace_masks.get(&column_ordinal).copied(),
                    source,
                    coins,
                    maximum_candidate_draws_per_output,
                )?);
            }
            Some(ProofTreeRole::AuxiliaryOracle) => {
                if pre_challenge_columns.columns[column_index].is_some()
                    || provided_non_integer_lift_auxiliary_columns
                        .contains_key(&column_ordinal)
                {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
            _ => {
                if pre_challenge_columns.columns[column_index].is_none()
                    || provided_non_integer_lift_auxiliary_columns
                        .contains_key(&column_ordinal)
                {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
        }
    }
    if !provided_non_integer_lift_auxiliary_columns.is_empty() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }

    let trace_domain = ProofEvaluationDomain::new_subgroup(
        usize::try_from(variant.trace_domain_size())
            .map_err(|_| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::CountOverflow,
            ))?,
    )
    .map_err(CommonProofProverError::from)
    .map_err(CommonProofPrivateCoinError::Prover)?;
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
                .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            let reversed_rows = trace_rows_by_column
                .get(&binding.reversed_column_ordinal)
                .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            let prefix_rows = prefix_evaluation_rows(source_rows, theta);
            let suffix_rows = suffix_evaluation_rows(reversed_rows, theta);
            insert_auxiliary_trace_rows(
                variant,
                &tree_roles,
                &trace_masks,
                &mut pre_challenge_columns.columns,
                binding.source_prefix_evaluation_column_ordinal,
                prefix_rows,
                trace_domain,
                coins,
                maximum_candidate_draws_per_output,
            )?;
            insert_auxiliary_trace_rows(
                variant,
                &tree_roles,
                &trace_masks,
                &mut pre_challenge_columns.columns,
                binding.reversed_suffix_evaluation_column_ordinal,
                suffix_rows,
                trace_domain,
                coins,
                maximum_candidate_draws_per_output,
            )?;
        }

        for component in &batch.ordered_components {
            let linear_rows = integer_lift_linear_evaluation_rows(
                variant,
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
                variant,
                &tree_roles,
                &trace_masks,
                &mut pre_challenge_columns.columns,
                component.linear_evaluation_column_ordinal,
                linear_rows,
                trace_domain,
                coins,
                maximum_candidate_draws_per_output,
            )?;
            insert_auxiliary_trace_rows(
                variant,
                &tree_roles,
                &trace_masks,
                &mut pre_challenge_columns.columns,
                component.product_accumulator_column_ordinal,
                accumulator_rows,
                trace_domain,
                coins,
                maximum_candidate_draws_per_output,
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
    validate_column_polynomials(variant, &columns)
        .map_err(CommonProofPrivateCoinError::Prover)?;
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

fn validate_unmasked_column(
    descriptor: &RelationColumnDescriptor,
    source: &CommonProofSourcePolynomial,
    trace_domain_size: u64,
) -> Result<(), CommonProofProverError> {
    let maximum_coefficient_count = descriptor
        .source_degree_bound_exclusive()
        .min(trace_domain_size);
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
                RelationColumnValueType::BaseField => CommonProofSourcePolynomial::Base(
                    sample_private_base_polynomial(
                        coins,
                        mask.mask_purpose(),
                        mask.mask_degree_bound_exclusive(),
                        maximum_candidate_draws_per_output,
                    )?,
                ),
                RelationColumnValueType::ChallengeExtension => {
                    CommonProofSourcePolynomial::Extension(
                        sample_private_extension_polynomial(
                            coins,
                            mask.mask_purpose(),
                            mask.mask_degree_bound_exclusive(),
                            maximum_candidate_draws_per_output,
                        )?,
                    )
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
        .get(
            usize::try_from(column_ordinal)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )
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
    let mut matching = assignments
        .iter()
        .copied()
        .filter(|assignment| {
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

fn insert_auxiliary_trace_rows<Coins>(
    variant: &RelationPlanVariant,
    tree_roles: &BTreeMap<u32, ProofTreeRole>,
    trace_masks: &BTreeMap<u32, RelationMaskDescriptor>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    column_ordinal: u32,
    rows: Vec<ProofBaseFieldElement>,
    trace_domain: ProofEvaluationDomain,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    if rows.len() != trace_domain.size()
        || tree_roles.get(&column_ordinal) != Some(&ProofTreeRole::AuxiliaryOracle)
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let column_index = usize::try_from(column_ordinal).map_err(|_| {
        CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let descriptor = variant.ordered_columns().get(column_index).ok_or_else(|| {
        CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
    })?;
    if descriptor.value_type() != RelationColumnValueType::BaseField
        || columns
            .get(column_index)
            .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?
            .is_some()
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let source = CommonProofSourcePolynomial::Base(
        trace_domain
            .interpolate_base_polynomial(&rows)
            .map_err(CommonProofProverError::from)
            .map_err(CommonProofPrivateCoinError::Prover)?,
    );
    let constructed = mask_relation_column(
        variant,
        descriptor,
        trace_masks.get(&column_ordinal).copied(),
        source,
        coins,
        maximum_candidate_draws_per_output,
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
    _variant: &RelationPlanVariant,
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

fn product_accumulator_rows(
    product_rows: &[ProofBaseFieldElement],
) -> Vec<ProofBaseFieldElement> {
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
    let theta_to_row_count = theta.power(
        u64::try_from(row_count).map_err(|_| CommonProofProverError::CountOverflow)?,
    );
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
                    .subtract(
                        theta_to_row_count.multiply(multiplicand_rows[row_ordinal + 1]),
                    );
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
            .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
        let reversed_multiplier_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_column_ordinal)
            .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
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
                if product.negative { value.negate() } else { value }
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
    insert_auxiliary_trace_rows(
        variant,
        tree_roles,
        trace_masks,
        columns,
        product.suffix_evaluation_column_ordinal,
        suffix_rows,
        trace_domain,
        coins,
        maximum_candidate_draws_per_output,
    )?;
    insert_auxiliary_trace_rows(
        variant,
        tree_roles,
        trace_masks,
        columns,
        product.reversed_transpose_column_ordinal,
        transpose_rows,
        trace_domain,
        coins,
        maximum_candidate_draws_per_output,
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
    let theta_to_half_ring_degree = theta.power(
        u64::try_from(row_count).map_err(|_| CommonProofProverError::CountOverflow)?,
    );
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
        ensure_base_trace_rows(
            columns,
            trace_rows_by_column,
            column_ordinal,
            trace_domain,
        )
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
            .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
        let multiplicand_high_rows = trace_rows_by_column
            .get(&product.multiplicand_high_column_ordinal)
            .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
        let reversed_multiplier_low_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_low_column_ordinal)
            .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
        let reversed_multiplier_high_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_high_column_ordinal)
            .ok_or_else(|| CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
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
            let low_product = low_transpose_rows[row_ordinal].multiply(
                reversed_multiplier_low_rows[row_ordinal].subtract(low_offset),
            );
            let high_product = high_transpose_rows[row_ordinal].multiply(
                reversed_multiplier_high_rows[row_ordinal].subtract(high_offset),
            );
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
            variant,
            tree_roles,
            trace_masks,
            columns,
            column_ordinal,
            rows,
            trace_domain,
            coins,
            maximum_candidate_draws_per_output,
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
        || evaluation_domain.generator().canonical()
            != context.evaluation_domain_generator
        || evaluation_domain.coset_offset().canonical()
            != context.evaluation_coset_offset
        || variant.evaluation_domain_size() % variant.trace_domain_size() != 0
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
    let trace_rotation_stride = usize::try_from(
        variant.evaluation_domain_size() / variant.trace_domain_size(),
    )
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
                let reduced_rotation = usize::try_from(
                    rotation_magnitude % variant.trace_domain_size(),
                )
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
    let mut quotient = evaluation_domain
        .interpolate_extension_polynomial(&quotient_evaluations)?;
    trim_extension_polynomial(&mut quotient);
    Ok(quotient)
}

/// Splits the unique quotient into constant-first components of width `kHat`.
pub(crate) fn decompose_composed_quotient(
    quotient: &[ProofChallengeExtensionElement],
    component_count: u32,
    component_stride: u64,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    let component_count = usize::try_from(component_count)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let component_stride = usize::try_from(component_stride)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
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
    let stride = variant
        .quotient_decomposition_stride(context)
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let mut components = decompose_composed_quotient(
        quotient,
        context.quotient_component_count,
        stride,
    )
    .map_err(CommonProofPrivateCoinError::Prover)?;
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        if !variant.ordered_masks().is_empty() {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidMask,
            ));
        }
        return Ok(components);
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
    if telescoping_descriptors.len() + 1 != components.len()
        || telescoping_descriptors.iter().enumerate().any(|(ordinal, mask)| {
            usize::try_from(mask.target_ordinal()).ok() != Some(ordinal)
        })
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }

    let mut randomizers = Vec::new();
    randomizers
        .try_reserve_exact(telescoping_descriptors.len())
        .map_err(|_| CommonProofPrivateCoinError::Prover(
            CommonProofProverError::AllocationLimitExceeded,
        ))?;
    for descriptor in telescoping_descriptors {
        randomizers.push(sample_private_extension_polynomial(
            coins,
            descriptor.mask_purpose(),
            descriptor.mask_degree_bound_exclusive(),
            maximum_candidate_draws_per_output,
        )?);
    }

    let stride = usize::try_from(stride)
        .map_err(|_| CommonProofPrivateCoinError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    for component_ordinal in 0..components.len() {
        if component_ordinal < randomizers.len() {
            add_shifted_extension_polynomial(
                &mut components[component_ordinal],
                &randomizers[component_ordinal],
                stride,
            )
            .map_err(CommonProofPrivateCoinError::Prover)?;
        }
        if component_ordinal > 0 {
            subtract_extension_polynomial(
                &mut components[component_ordinal],
                &randomizers[component_ordinal - 1],
            )
            .map_err(CommonProofPrivateCoinError::Prover)?;
        }
        trim_extension_polynomial(&mut components[component_ordinal]);
        if components[component_ordinal].len()
            > usize::try_from(context.quotient_component_degree_bound_exclusive)
                .map_err(|_| CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?
        {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidQuotient,
            ));
        }
    }
    Ok(components)
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
    let descriptor = descriptors.next().ok_or_else(|| {
        CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidMask)
    })?;
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
        let source = match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => columns
                .get(
                    usize::try_from(
                        claim.column_ordinal().ok_or(CommonProofProverError::InvalidOpening)?,
                    )
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .cloned()
                .ok_or(CommonProofProverError::InvalidOpening)?
                .into_extension_coefficients(),
            RelationOpeningSourceClass::Quotient => quotient_components
                .get(
                    usize::try_from(claim.source_ordinal())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .cloned()
                .ok_or(CommonProofProverError::InvalidOpening)?,
            RelationOpeningSourceClass::BatchMask => opening_batch_mask
                .map(|coefficients| coefficients.to_vec())
                .ok_or(CommonProofProverError::InvalidOpening)?,
        };
        let source_bound = usize::try_from(claim.source_degree_bound_exclusive())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if source.is_empty() || source.len() > source_bound || source_bound > opening_bound {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let opening_point = opening_points
            .get(
                usize::try_from(claim.opening_point_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .copied()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        let mut numerator = source;
        numerator[0] = numerator[0].subtract(deep_evaluations[claim_ordinal]);
        let (quotient, remainder) =
            divide_extension_polynomial_by_linear(&numerator, opening_point)?;
        if !remainder.is_zero() {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let shift = opening_bound
            .checked_sub(source_bound)
            .ok_or(CommonProofProverError::InvalidOpening)?;
        let batching_coefficient = batching_coefficients[claim_ordinal];
        for (coefficient_ordinal, coefficient) in quotient.into_iter().enumerate() {
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
    if extension_polynomial_degree(&initial)
        .is_some_and(|degree| degree >= opening_bound - 1)
    {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    Ok(initial)
}

/// Builds one FRI layer only.  Callers persist the returned layer before
/// releasing the previous one, so peak memory is two layers rather than the
/// complete fold chain.
pub(crate) fn construct_next_fri_layer(
    current_evaluations: &[ProofChallengeExtensionElement],
    current_domain: ProofEvaluationDomain,
    challenge: ProofChallengeExtensionElement,
) -> Result<
    (ProofEvaluationDomain, Vec<ProofChallengeExtensionElement>),
    CommonProofProverError,
> {
    if current_evaluations.len() != current_domain.size() {
        return Err(CommonProofProverError::InvalidFriLayer);
    }
    let folded = fold_extension_evaluations(
        current_evaluations,
        current_domain,
        challenge,
    )?;
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
    let mut coefficients = terminal_domain
        .interpolate_extension_polynomial(terminal_evaluations)?;
    if extension_polynomial_degree(&coefficients)
        .is_some_and(|degree| degree >= bound)
    {
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
    while coefficients.len() > 1
        && coefficients.last() == Some(&ProofBaseFieldElement::ZERO)
    {
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
    pub(crate) const fn leaf_bytes_object(&self) -> ProofExternalMemoryObject {
        self.leaf_bytes_object
    }

    pub(crate) fn digest_level_objects(&self) -> &[ProofExternalMemoryObject] {
        &self.digest_level_objects
    }

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
        .checked_mul(
            u64::try_from(leaf_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )
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
        | ProofTreeCatalogSource::RelationBoundPublic => {
            Err(CommonProofProverError::InvalidTree)
        }
    }
}

fn canonical_common_proof_leaf_byte_length(
    context: &ProofMerkleTreeContext,
    value_type: RelationColumnValueType,
) -> Result<usize, CommonProofProverError> {
    let row_width = usize::try_from(context.row_width())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let empty_value = match value_type {
        RelationColumnValueType::BaseField => {
            ProofTreeValue::Base(ProofBaseFieldElement::ZERO)
        }
        RelationColumnValueType::ChallengeExtension => {
            ProofTreeValue::Extension(ProofChallengeExtensionElement::ZERO)
        }
    };
    let row = vec![empty_value; row_width];
    let secret_salt = (context.leaf_visibility() == ProofLeafVisibility::SecretBearing)
        .then_some([0_u8; PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]);
    Ok(ProofOraclePhasePairLeaf::new(
        context,
        0,
        secret_salt,
        row.clone(),
        row,
    )?
    .canonical_bytes()?
    .len())
}

fn common_proof_tree_value_has_type(
    value: &ProofTreeValue,
    expected_type: RelationColumnValueType,
) -> bool {
    matches!(
        (value, expected_type),
        (
            ProofTreeValue::Base(_),
            RelationColumnValueType::BaseField
        ) | (
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
        .checked_mul(
            u64::try_from(leaf_count).map_err(|_| CommonProofProverError::CountOverflow)?,
        )
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
    SealLeafBytes,
    SealLeafDigests,
    BeginParentLevel,
    ReadLeftChild,
    ReadRightChild,
    WriteParentDigest,
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
        let expected_leaf_byte_length = canonical_common_proof_leaf_byte_length(
            &context,
            value_type,
        )?;
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
            current_byte_offset: 0,
            current_level_ordinal: 0,
            current_parent_index: 0,
            left_child_digest: [0; HASH_BYTE_LENGTH],
            right_child_digest: [0; HASH_BYTE_LENGTH],
            root: [0; HASH_BYTE_LENGTH],
        })
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
        let secret_salt = if self.context.leaf_visibility()
            == ProofLeafVisibility::SecretBearing
        {
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
                CommonProofTreeStorageError::Prover(
                    CommonProofProverError::CountOverflow,
                )
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
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        self.current_leaf_bytes.len(),
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .append_object_bytes(
                            storage,
                            self.leaf_bytes_object,
                            &self.current_leaf_bytes[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == self.current_leaf_bytes.len() {
                        self.current_byte_offset = 0;
                        self.phase = CommonProofMerkleMaterializerPhase::WriteLeafDigest;
                    }
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::WriteLeafDigest => {
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        HASH_BYTE_LENGTH,
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .append_object_bytes(
                            storage,
                            self.digest_level_objects[0],
                            &self.current_leaf_digest[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == HASH_BYTE_LENGTH {
                        self.current_leaf_bytes = Zeroizing::new(Vec::new());
                        self.current_leaf_digest = [0; HASH_BYTE_LENGTH];
                        self.current_byte_offset = 0;
                        self.next_leaf_index = self
                            .next_leaf_index
                            .checked_add(1)
                            .ok_or(CommonProofTreeStorageError::Prover(
                                CommonProofProverError::CountOverflow,
                            ))?;
                        self.phase = if self.next_leaf_index == self.leaf_count {
                            CommonProofMerkleMaterializerPhase::SealLeafBytes
                        } else {
                            CommonProofMerkleMaterializerPhase::NeedLeafValues
                        };
                    }
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
                    let child_object = self.digest_level_objects
                        [self.current_level_ordinal - 1];
                    let child_index = self
                        .current_parent_index
                        .checked_mul(2)
                        .ok_or(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?;
                    let storage_offset = stored_hash_chunk_offset(
                        child_index,
                        self.current_byte_offset,
                    )
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
                    let child_object = self.digest_level_objects
                        [self.current_level_ordinal - 1];
                    let child_index = self
                        .current_parent_index
                        .checked_mul(2)
                        .and_then(|index| index.checked_add(1))
                        .ok_or(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?;
                    let storage_offset = stored_hash_chunk_offset(
                        child_index,
                        self.current_byte_offset,
                    )
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
                    let end = next_bounded_offset(
                        self.current_byte_offset,
                        HASH_BYTE_LENGTH,
                        executor.maximum_chunk_byte_length(),
                    )
                    .map_err(CommonProofTreeStorageError::Prover)?;
                    executor
                        .append_object_bytes(
                            storage,
                            self.digest_level_objects[self.current_level_ordinal],
                            &self.current_leaf_digest[self.current_byte_offset..end],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_byte_offset = end;
                    if end == HASH_BYTE_LENGTH {
                        self.current_leaf_digest = [0; HASH_BYTE_LENGTH];
                        self.current_byte_offset = 0;
                        self.current_parent_index = self
                            .current_parent_index
                            .checked_add(1)
                            .ok_or(CommonProofTreeStorageError::Prover(
                                CommonProofProverError::CountOverflow,
                            ))?;
                        let parent_count = self.leaf_count >> self.current_level_ordinal;
                        self.phase = if self.current_parent_index == parent_count {
                            CommonProofMerkleMaterializerPhase::SealParentLevel
                        } else {
                            CommonProofMerkleMaterializerPhase::ReadLeftChild
                        };
                    }
                    return Ok(CommonProofMerkleMaterializerProgress::StorageTransactionCompleted);
                }
                CommonProofMerkleMaterializerPhase::SealParentLevel => {
                    executor
                        .seal_object(
                            storage,
                            self.digest_level_objects[self.current_level_ordinal],
                        )
                        .map_err(CommonProofTreeStorageError::Storage)?;
                    self.current_level_ordinal = self
                        .current_level_ordinal
                        .checked_add(1)
                        .ok_or(CommonProofTreeStorageError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?;
                    self.phase = if self.current_level_ordinal
                        == self.digest_level_objects.len()
                    {
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

/// Materializes one common tree with one-leaf working memory.  Calls for
/// secret-bearing relation trees must occur in complete catalog order so the
/// sole `0xfffe` stream is consumed by catalog index and then leaf index.
#[allow(clippy::too_many_arguments)]
pub(crate) fn materialize_common_proof_merkle_tree<Storage, Coins, LeafValues>(
    catalog_entry: &ProofTreeCatalogEntry,
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    leaf_bytes_object: ProofExternalMemoryObject,
    digest_level_objects: Vec<ProofExternalMemoryObject>,
    coins: &mut Coins,
    mut leaf_values: LeafValues,
) -> Result<
    StoredCommonProofMerkleTree,
    CommonProofTreeStorageError<Storage::Error, Coins::Error>,
>
where
    Storage: ProofExternalMemory,
    Coins: CommonProofPrivateCoinSource,
    LeafValues: FnMut(
        u64,
    ) -> Result<(Vec<ProofTreeValue>, Vec<ProofTreeValue>), CommonProofProverError>,
{
    let context = catalog_entry
        .common_context()
        .cloned()
        .ok_or(CommonProofTreeStorageError::Prover(
            CommonProofProverError::InvalidTree,
        ))?;
    let leaf_count = context
        .leaf_count()
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofTreeStorageError::Prover)?;
    let value_type = common_proof_tree_value_type(catalog_entry)
        .map_err(CommonProofTreeStorageError::Prover)?;
    let canonical_leaf_byte_length = canonical_common_proof_leaf_byte_length(
        &context,
        value_type,
    )
    .map_err(CommonProofTreeStorageError::Prover)?;
    let expected_row_width = usize::try_from(context.row_width()).map_err(|_| {
        CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let expected_level_count = usize::try_from(leaf_count.trailing_zeros())
        .map_err(|_| CommonProofTreeStorageError::Prover(
            CommonProofProverError::CountOverflow,
        ))?
        .checked_add(1)
        .ok_or(CommonProofTreeStorageError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || digest_level_objects.len() != expected_level_count
    {
        return Err(CommonProofTreeStorageError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }

    executor
        .begin_object(storage, leaf_bytes_object)
        .map_err(CommonProofTreeStorageError::Storage)?;
    executor
        .begin_object(storage, digest_level_objects[0])
        .map_err(CommonProofTreeStorageError::Storage)?;
    for leaf_index in 0..leaf_count {
        let leaf_index = u64::try_from(leaf_index).map_err(|_| {
            CommonProofTreeStorageError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let (first_point_values, opposite_point_values) = leaf_values(leaf_index)
            .map_err(CommonProofTreeStorageError::Prover)?;
        if first_point_values.len() != expected_row_width
            || opposite_point_values.len() != expected_row_width
            || first_point_values
                .iter()
                .chain(&opposite_point_values)
                .any(|value| !common_proof_tree_value_has_type(value, value_type))
        {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let secret_salt = if context.leaf_visibility()
            == ProofLeafVisibility::SecretBearing
        {
            let mut salt = [0_u8; PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
            coins
                .fill_raw_bytes(PRIVATE_PROOF_SALT_PURPOSE, &mut salt)
                .map_err(CommonProofTreeStorageError::CoinSource)?;
            Some(salt)
        } else {
            None
        };
        let leaf = ProofOraclePhasePairLeaf::new(
            &context,
            leaf_index,
            secret_salt,
            first_point_values,
            opposite_point_values,
        )
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofTreeStorageError::Prover)?;
        let canonical_bytes = Zeroizing::new(
            leaf.canonical_bytes()
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofTreeStorageError::Prover)?,
        );
        if canonical_bytes.len() != canonical_leaf_byte_length {
            return Err(CommonProofTreeStorageError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        append_bounded(
            executor,
            storage,
            leaf_bytes_object,
            &canonical_bytes,
        )
        .map_err(CommonProofTreeStorageError::Storage)?;
        let digest = leaf
            .digest()
            .map_err(CommonProofProverError::from)
            .map_err(CommonProofTreeStorageError::Prover)?;
        append_bounded(
            executor,
            storage,
            digest_level_objects[0],
            &digest,
        )
        .map_err(CommonProofTreeStorageError::Storage)?;
    }
    executor
        .seal_object(storage, leaf_bytes_object)
        .map_err(CommonProofTreeStorageError::Storage)?;
    executor
        .seal_object(storage, digest_level_objects[0])
        .map_err(CommonProofTreeStorageError::Storage)?;

    let context_hash = context
        .context_hash()
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofTreeStorageError::Prover)?;
    let mut child_count = leaf_count;
    for level_ordinal in 1..digest_level_objects.len() {
        let parent_count = child_count / 2;
        let child_object = digest_level_objects[level_ordinal - 1];
        let parent_object = digest_level_objects[level_ordinal];
        executor
            .begin_object(storage, parent_object)
            .map_err(CommonProofTreeStorageError::Storage)?;
        for parent_index in 0..parent_count {
            let left_child_index = parent_index
                .checked_mul(2)
                .ok_or(CommonProofTreeStorageError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            let right_child_index = left_child_index + 1;
            let left = read_stored_hash(
                executor,
                storage,
                child_object,
                left_child_index,
            )
            .map_err(CommonProofTreeStorageError::Storage)?;
            let right = read_stored_hash(
                executor,
                storage,
                child_object,
                right_child_index,
            )
            .map_err(CommonProofTreeStorageError::Storage)?;
            let digest = common_proof_merkle_node_digest(
                context_hash,
                u32::try_from(level_ordinal).map_err(|_| {
                    CommonProofTreeStorageError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                u64::try_from(parent_index).map_err(|_| {
                    CommonProofTreeStorageError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                left,
                right,
            )
            .map_err(CommonProofTreeStorageError::Prover)?;
            append_bounded(executor, storage, parent_object, &digest)
                .map_err(CommonProofTreeStorageError::Storage)?;
        }
        executor
            .seal_object(storage, parent_object)
            .map_err(CommonProofTreeStorageError::Storage)?;
        child_count = parent_count;
    }
    let root = read_stored_hash(
        executor,
        storage,
        *digest_level_objects.last().ok_or(
            CommonProofTreeStorageError::Prover(CommonProofProverError::InvalidTree),
        )?,
        0,
    )
    .map_err(CommonProofTreeStorageError::Storage)?;
    Ok(StoredCommonProofMerkleTree {
        tree_catalog_index: catalog_entry.tree_catalog_index(),
        context,
        leaf_count,
        canonical_leaf_byte_length,
        leaf_bytes_object,
        digest_level_objects,
        root,
    })
}

fn append_bounded<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    object: ProofExternalMemoryObject,
    bytes: &[u8],
) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
    let maximum_chunk = usize::try_from(executor.maximum_chunk_byte_length())
        .map_err(|_| ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        ))?;
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
    let maximum_chunk = usize::try_from(executor.maximum_chunk_byte_length())
        .map_err(|_| ProofExternalMemoryExecutorError::Execution(
            super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
        ))?;
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
        let frontier_coordinates = minimal_frontier_coordinates(
            &opened_leaf_indexes,
            tree.leaf_count,
        )?;
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
    ) -> Result<
        CommonProofOpeningPrefetchProgress,
        ProofExternalMemoryExecutorError<Storage::Error>,
    > {
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
                .map_err(|_| ProofExternalMemoryExecutorError::Execution(
                    super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
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
                .map_err(|_| ProofExternalMemoryExecutorError::Execution(
                    super::external_memory::ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
                executor.read_object_bytes(
                    storage,
                    object,
                    storage_offset,
                    &mut self.frontier_digests[self.next_item_index]
                        [self.current_byte_offset..end],
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
) -> Result<
    Vec<u8>,
    CommonProofEncodingError<BoundedCommonProofByteSinkError, Artifact::Error>,
>
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
        || !sorted_query_representatives.windows(2).all(|pair| pair[0] < pair[1])
        || sorted_query_representatives.last().is_some_and(|representative| {
            *representative >= catalog.evaluation_domain_size() / 2
        })
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

impl<Sink: CommonProofByteSink> CommonProofByteSink
    for CommonProofTranscriptQuerySink<'_, Sink>
{
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
    let expected_opening_claim_count = usize::try_from(
        transcript_schedule.opening_claim_count(),
    )
    .map_err(|_| {
        CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
    })?;
    if canonical_header_bytes.is_empty()
        || tree_roots.len() != catalog.entries().len()
        || deep_evaluations.len() != expected_opening_claim_count
        || terminal_coefficients.len()
            != usize::try_from(transcript_schedule.terminal_coefficient_count())
                .map_err(|_| CommonProofEncodingError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?
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
    write_u16(sink, CanonicalItemType::ChallengeExtensionElement.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(values.len()).map_err(|_| {
            CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
        })?,
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
        let frontier_count = minimal_frontier_node_count(
            &opened_indexes,
            geometry.leaf_count,
        )?;
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
        || !sorted_query_representatives.windows(2).all(|pair| pair[0] < pair[1])
        || sorted_query_representatives.last().is_some_and(|representative| {
            *representative >= catalog.evaluation_domain_size() / 2
        })
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

pub(crate) struct CommonProofQuerySectionWriter<'input, Sink> {
    sink: Sink,
    catalog: &'input CompleteProofTreeCatalog,
    geometries: &'input [CommonProofOpeningGeometry],
    sorted_query_representatives: &'input [u64],
    next_catalog_index: usize,
}

impl<'input, Sink: CommonProofByteSink> CommonProofQuerySectionWriter<'input, Sink> {
    pub(crate) fn new(
        mut sink: Sink,
        catalog: &'input CompleteProofTreeCatalog,
        geometries: &'input [CommonProofOpeningGeometry],
        sorted_query_representatives: &'input [u64],
    ) -> Result<Self, CommonProofEncodingError<Sink::Error, core::convert::Infallible>> {
        validate_query_geometry(catalog, geometries, sorted_query_representatives)
            .map_err(CommonProofEncodingError::Prover)?;
        write_u32(
            &mut sink,
            u32::try_from(catalog.entries().len()).map_err(|_| {
                CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
            })?,
        )?;
        Ok(Self {
            sink,
            catalog,
            geometries,
            sorted_query_representatives,
            next_catalog_index: 0,
        })
    }

    pub(crate) fn write_next_opening<Artifact>(
        &mut self,
        artifact: &mut Artifact,
    ) -> Result<(), CommonProofEncodingError<Sink::Error, Artifact::Error>>
    where
        Artifact: CommonProofOpeningArtifact,
    {
        let entry = self
            .catalog
            .entries()
            .get(self.next_catalog_index)
            .ok_or(CommonProofEncodingError::Prover(
                CommonProofProverError::InvalidOpening,
            ))?;
        let geometry = self
            .geometries
            .get(self.next_catalog_index)
            .copied()
            .ok_or(CommonProofEncodingError::Prover(
                CommonProofProverError::InvalidOpening,
            ))?;
        if artifact.tree_catalog_index() != entry.tree_catalog_index()
            || artifact.leaf_count() != geometry.leaf_count
            || artifact.canonical_leaf_byte_length()
                != geometry.canonical_leaf_byte_length
        {
            return Err(CommonProofEncodingError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let opened_indexes = opened_leaf_indexes(
            entry.source(),
            self.catalog.evaluation_domain_size(),
            self.sorted_query_representatives,
        )
        .map_err(CommonProofEncodingError::Prover)?;
        write_opening_record(
            &mut self.sink,
            entry.tree_catalog_index(),
            geometry.canonical_leaf_byte_length,
            &opened_indexes,
            artifact,
        )?;
        write_authentication_frontier(
            &mut self.sink,
            entry.tree_catalog_index(),
            geometry.leaf_count,
            &opened_indexes,
            artifact,
        )?;
        self.next_catalog_index += 1;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Sink, CommonProofProverError> {
        if self.next_catalog_index != self.catalog.entries().len() {
            return Err(CommonProofProverError::InvalidOpening);
        }
        Ok(self.sink)
    }
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
        .checked_mul(
            canonical_leaf_byte_length
                .checked_add(4)
                .ok_or(CommonProofEncodingError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?,
        )
        .and_then(|length| length.checked_add(6))
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    write_item_header(sink, CanonicalItemType::HomogeneousList, list_payload_length)?;
    write_u16(sink, CanonicalItemType::RawBytes.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(opened_indexes.len()).map_err(|_| {
            CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
        })?,
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
    write_tuple_header(
        sink,
        PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
        2,
    )?;
    write_u16_item(sink, tree_catalog_index)?;
    let list_payload_length = frontier_count
        .checked_mul(AUTHENTICATION_NODE_CANONICAL_BYTE_LENGTH)
        .and_then(|length| length.checked_add(6))
        .ok_or(CommonProofEncodingError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    write_item_header(sink, CanonicalItemType::HomogeneousList, list_payload_length)?;
    write_u16(sink, CanonicalItemType::NestedTuple.canonical_code())?;
    write_u32(
        sink,
        u32::try_from(frontier_count).map_err(|_| {
            CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
        })?,
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
                write_tuple_header(
                    sink,
                    PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER,
                    3,
                )?;
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
        || !sorted_unique_leaf_indexes.windows(2).all(|pair| pair[0] < pair[1])
        || sorted_unique_leaf_indexes.last().is_some_and(|index| {
            usize::try_from(*index).map_or(true, |index| index >= leaf_count)
        })
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
        u32::try_from(byte_length).map_err(|_| {
            CommonProofEncodingError::Prover(CommonProofProverError::CountOverflow)
        })?,
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

    fn write_next_bound_opening<Sink>(
        &mut self,
        catalog_entry: &ProofTreeCatalogEntry,
        writer: &mut CommonProofQuerySectionWriter<'_, Sink>,
    ) -> Result<(), CommonProofEncodingError<Sink::Error, Self::Error>>
    where
        Sink: CommonProofByteSink;
}

/// Complete application-owned inputs for one production common-proof
/// attempt.  Only genuine source columns are accepted: integer-lift reversed
/// and auxiliary columns are always synthesized by the common prover.
pub(crate) struct CommonProofGenerationInput<'input> {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; HASH_BYTE_LENGTH],
    pub(crate) canonical_application_statement_bytes: &'input [u8],
    pub(crate) relation_plan: &'input CompiledRelationPlan,
    pub(crate) relation_context: &'input RelationPlanCheckContext,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) relation_trees: Vec<RelationProofTreeInput>,
    pub(crate) provided_pre_challenge_columns:
        BTreeMap<u32, CommonProofSourcePolynomial>,
    pub(crate) provided_non_integer_lift_auxiliary_columns:
        BTreeMap<u32, CommonProofSourcePolynomial>,
    pub(crate) maximum_external_memory_chunk_byte_length: u32,
    pub(crate) maximum_prefetched_query_byte_length: u64,
}

#[derive(Debug)]
pub(crate) enum CommonProofGenerationError<
    StorageError,
    CoinError,
    SinkError,
    BoundOpeningError,
> {
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
        original: Box<
            CommonProofGenerationError<
                StorageError,
                CoinError,
                SinkError,
                BoundOpeningError,
            >,
        >,
        cleanup: ProofExternalMemoryExecutorError<StorageError>,
    },
}

struct GeneratedCommonProofStoragePlan {
    external_memory_plan: ProofExternalMemoryPlan,
    tree_plans: BTreeMap<u16, CommonProofMerkleStoragePlan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeneratedCommonProofStoragePlanError {
    Prover(CommonProofProverError),
    Storage(ProofExternalMemoryError),
}

fn checked_add_u64(
    left: u64,
    right: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    left.checked_add(right).ok_or(
        GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ),
    )
}

fn checked_multiply_u64(
    left: u64,
    right: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    left.checked_mul(right).ok_or(
        GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ),
    )
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
    Ok(numerator
        .checked_add(denominator - 1)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?
        / denominator)
}

fn common_tree_materialization_phase(
    source: ProofTreeCatalogSource,
) -> Option<u8> {
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
    catalog: &CompleteProofTreeCatalog,
    transcript_schedule: &CommonProofTranscriptSchedule,
    maximum_chunk_byte_length: u32,
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
    common_entries.sort_unstable_by_key(|(phase, catalog_index, _)| {
        (*phase, *catalog_index)
    });
    if common_entries.is_empty() {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }

    let query_step = u32::try_from(common_entries.len()).map_err(|_| {
        GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        )
    })?;
    let step_count = query_step.checked_add(1).ok_or(
        GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ),
    )?;
    let chunk_byte_length = u64::from(maximum_chunk_byte_length);
    let hash_read_transaction_count = ceiling_division_u64(
        HASH_BYTE_LENGTH as u64,
        chunk_byte_length,
    )?;
    let maximum_opened_leaf_count =
        u64::from(transcript_schedule.unique_query_count());

    let mut next_object_ordinal = 0_u32;
    let mut object_plans = Vec::new();
    let mut tree_plans = BTreeMap::new();
    let mut maximum_stored_byte_length = 0_u64;
    let mut maximum_total_written_byte_length = 0_u64;
    let mut maximum_total_read_byte_length = 0_u64;
    let mut maximum_transaction_count = 0_u64;

    for (materialization_index, (_, catalog_index, entry)) in
        common_entries.iter().enumerate()
    {
        let materialization_step = u32::try_from(materialization_index)
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?;
        let tree_plan = common_proof_merkle_storage_plan(
            entry,
            next_object_ordinal,
            materialization_step,
            query_step,
        )
        .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        next_object_ordinal = tree_plan.next_object_ordinal();
        let context = entry.common_context().ok_or(
            GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ),
        )?;
        let leaf_count = u64::try_from(context.leaf_count()?).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            )
        })?;
        let opened_leaf_count = maximum_opened_leaf_count.min(leaf_count);
        let tree_height = u64::from(leaf_count.trailing_zeros());
        let frontier_node_bound =
            checked_multiply_u64(opened_leaf_count, tree_height)?;
        let construction_digest_read_count = leaf_count
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        let construction_read_byte_length = checked_multiply_u64(
            construction_digest_read_count,
            HASH_BYTE_LENGTH as u64,
        )?;
        let query_leaf_read_byte_length = checked_multiply_u64(
            opened_leaf_count,
            u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?,
        )?;
        let query_frontier_read_byte_length = checked_multiply_u64(
            frontier_node_bound,
            HASH_BYTE_LENGTH as u64,
        )?;
        maximum_total_read_byte_length = checked_add_u64(
            maximum_total_read_byte_length,
            checked_add_u64(
                construction_read_byte_length,
                checked_add_u64(
                    query_leaf_read_byte_length,
                    query_frontier_read_byte_length,
                )?,
            )?,
        )?;

        let object_count = u64::try_from(tree_plan.object_plans().len())
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_multiply_u64(object_count, 2)?,
        )?;
        for object_plan in tree_plan.object_plans() {
            maximum_stored_byte_length = checked_add_u64(
                maximum_stored_byte_length,
                object_plan.exact_byte_length(),
            )?;
            maximum_total_written_byte_length = checked_add_u64(
                maximum_total_written_byte_length,
                object_plan.exact_byte_length(),
            )?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                ceiling_division_u64(
                    object_plan.exact_byte_length(),
                    chunk_byte_length,
                )?,
            )?;
        }
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_multiply_u64(
                construction_digest_read_count,
                hash_read_transaction_count,
            )?,
        )?;
        let query_leaf_read_transaction_count = checked_multiply_u64(
            opened_leaf_count,
            ceiling_division_u64(
                u64::try_from(tree_plan.canonical_leaf_byte_length())
                    .map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?,
                chunk_byte_length,
            )?,
        )?;
        let query_frontier_read_transaction_count = checked_multiply_u64(
            frontier_node_bound,
            hash_read_transaction_count,
        )?;
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
    // One deletion transaction for each materialized root and one final
    // transaction for all query-live leaf/frontier objects.
    maximum_transaction_count = checked_add_u64(
        maximum_transaction_count,
        u64::try_from(common_entries.len())
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?
            .checked_add(1)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?,
    )?;
    let maximum_transaction_operation_count =
        u32::try_from(object_plans.len()).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            )
        })?;
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
                let expected_visibility = if ordered_column_ordinals.iter().any(
                    |column_ordinal| {
                        usize::try_from(*column_ordinal)
                            .ok()
                            .and_then(|index| variant.ordered_columns().get(index))
                            .is_some_and(|column| {
                                column.origin() == &RelationColumnOrigin::Prover
                            })
                    },
                ) {
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
                validate_generation_tree_columns(
                    variant,
                    ordered_column_ordinals,
                    None,
                )?;
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
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            row_width,
                            ..
                        },
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
            (RelationColumnOrigin::BoundTree { .. }, _)
            | (_, Some(_)) => return Err(CommonProofProverError::InvalidTree),
            (_, None) => {}
        }
    }
    Ok(())
}

fn statement_owned_tree_root(
    input: &RelationProofTreeInput,
) -> Option<[u8; HASH_BYTE_LENGTH]> {
    match input {
        RelationProofTreeInput::BoundPublic(
            StatementOwnedProofTreeInput::CommittedMaterial {
                expected_root, ..
            }
            | StatementOwnedProofTreeInput::SetupPolynomial {
                expected_root, ..
            },
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
    let entry = matches
        .next()
        .ok_or(CommonProofProverError::InvalidTree)?;
    if matches.next().is_some() {
        return Err(CommonProofProverError::InvalidTree);
    }
    Ok(entry)
}

fn map_private_coin_generation_error<
    StorageError,
    CoinError,
    SinkError,
    BoundOpeningError,
>(
    error: CommonProofPrivateCoinError<CoinError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    match error {
        CommonProofPrivateCoinError::Prover(error) => {
            CommonProofGenerationError::Prover(error)
        }
        CommonProofPrivateCoinError::CoinSource(error) => {
            CommonProofGenerationError::CoinSource(error)
        }
    }
}

fn map_tree_storage_generation_error<
    StorageError,
    CoinError,
    SinkError,
    BoundOpeningError,
>(
    error: CommonProofTreeStorageError<StorageError, CoinError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    match error {
        CommonProofTreeStorageError::Prover(error) => {
            CommonProofGenerationError::Prover(error)
        }
        CommonProofTreeStorageError::Storage(error) => {
            CommonProofGenerationError::Storage(error)
        }
        CommonProofTreeStorageError::CoinSource(error) => {
            CommonProofGenerationError::CoinSource(error)
        }
    }
}

fn materialize_evaluated_common_tree<Storage, Coins>(
    catalog_entry: &ProofTreeCatalogEntry,
    storage_plan: CommonProofMerkleStoragePlan,
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    coins: &mut Coins,
    column_evaluations: &[CommonProofColumnEvaluations],
) -> Result<
    StoredCommonProofMerkleTree,
    CommonProofTreeStorageError<Storage::Error, Coins::Error>,
>
where
    Storage: ProofExternalMemory,
    Coins: CommonProofPrivateCoinSource,
{
    let leaf_bytes_object = storage_plan.leaf_bytes_object();
    let digest_level_objects = storage_plan.digest_level_objects().to_vec();
    materialize_common_proof_merkle_tree(
        catalog_entry,
        executor,
        storage,
        leaf_bytes_object,
        digest_level_objects,
        coins,
        |leaf_index| common_proof_phase_pair_values(column_evaluations, leaf_index),
    )
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

#[allow(clippy::too_many_arguments)]
fn materialize_and_record_common_tree<Storage, Coins>(
    catalog_entry: &ProofTreeCatalogEntry,
    column_evaluations: &[CommonProofColumnEvaluations],
    tree_plans: &mut BTreeMap<u16, CommonProofMerkleStoragePlan>,
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    coins: &mut Coins,
    tree_roots: &mut [[u8; HASH_BYTE_LENGTH]],
    root_present: &mut [bool],
    stored_trees: &mut BTreeMap<u16, StoredCommonProofMerkleTree>,
) -> Result<(), CommonProofTreeStorageError<Storage::Error, Coins::Error>>
where
    Storage: ProofExternalMemory,
    Coins: CommonProofPrivateCoinSource,
{
    let storage_plan = tree_plans
        .remove(&catalog_entry.tree_catalog_index())
        .ok_or(CommonProofTreeStorageError::Prover(
            CommonProofProverError::InvalidTree,
        ))?;
    let issued_step = storage_plan
        .object_plans()
        .first()
        .map(|plan| plan.issued_step())
        .ok_or(CommonProofTreeStorageError::Prover(
            CommonProofProverError::InvalidTree,
        ))?;
    if executor.current_step() != issued_step {
        return Err(CommonProofTreeStorageError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }
    let tree = materialize_evaluated_common_tree(
        catalog_entry,
        storage_plan,
        executor,
        storage,
        coins,
        column_evaluations,
    )?;
    insert_materialized_tree(
        tree,
        tree_roots,
        root_present,
        stored_trees,
    )
    .map_err(CommonProofTreeStorageError::Prover)?;
    executor
        .complete_step(storage)
        .map_err(CommonProofTreeStorageError::Storage)
}

/// Executes the complete common prover state machine from checked source
/// columns through the canonical streamed proof body.  The verifier transcript
/// order is mirrored exactly, including one grouped application vector and one
/// without-replacement query-vector message.  Any failed attempt securely
/// cancels live common-tree storage; a cleanup failure preserves both errors.
pub(crate) fn generate_common_proof<Storage, Coins, Sink, BoundOpenings>(
    input: CommonProofGenerationInput<'_>,
    storage: &mut Storage,
    coins: &mut Coins,
    sink: &mut Sink,
    bound_openings: &mut BoundOpenings,
) -> Result<
    (),
    CommonProofGenerationError<
        Storage::Error,
        Coins::Error,
        Sink::Error,
        BoundOpenings::Error,
    >,
>
where
    Storage: ProofExternalMemory,
    Coins: CommonProofPrivateCoinSource,
    Sink: CommonProofByteSink,
    BoundOpenings: CommonProofBoundOpeningProvider,
{
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
        provided_non_integer_lift_auxiliary_columns,
        maximum_external_memory_chunk_byte_length,
        maximum_prefetched_query_byte_length,
    } = input;
    if maximum_prefetched_query_byte_length == 0 {
        return Err(CommonProofGenerationError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    let validated_artifact = ValidatedRelationPlanArtifact::from_compiled_plan(
        relation_plan,
        relation_context,
    )
    .map_err(CommonProofGenerationError::Profile)?;
    let canonical_header_bytes = canonical_proof_object_header_bytes(
        canonical_application_statement_bytes,
    )
    .map_err(CommonProofGenerationError::Prover)?;
    let variant = relation_plan
        .select_variant(schedule_position, top_count)
        .map_err(CommonProofGenerationError::Relation)?;
    validate_generation_relation_trees(variant, &relation_trees)
        .map_err(CommonProofGenerationError::Prover)?;
    let transcript_schedule = variant
        .common_proof_transcript_schedule(relation_context)
        .map_err(CommonProofGenerationError::Relation)?;
    let evaluation_domain = ProofEvaluationDomain::new(
        usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| {
                CommonProofGenerationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?,
        relation_context.evaluation_coset_offset,
    )
    .map_err(CommonProofProverError::from)
    .map_err(CommonProofGenerationError::Prover)?;
    if evaluation_domain.generator().canonical()
        != relation_context.evaluation_domain_generator
    {
        return Err(CommonProofGenerationError::Prover(
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
    .map_err(CommonProofGenerationError::Body)?;
    let mut storage_plan = generated_common_proof_storage_plan(
        &catalog,
        &transcript_schedule,
        maximum_external_memory_chunk_byte_length,
    )
    .map_err(|error| match error {
        GeneratedCommonProofStoragePlanError::Prover(error) => {
            CommonProofGenerationError::Prover(error)
        }
        GeneratedCommonProofStoragePlanError::Storage(error) => {
            CommonProofGenerationError::StoragePlan(error)
        }
    })?;

    let pre_challenge_columns = construct_pre_challenge_relation_columns(
        variant,
        provided_pre_challenge_columns,
        coins,
        relation_context.maximum_fiat_shamir_candidate_draws_per_output,
    )
    .map_err(map_private_coin_generation_error)?;

    let mut tree_roots = vec![[0_u8; HASH_BYTE_LENGTH]; catalog.entries().len()];
    let mut root_present = vec![false; catalog.entries().len()];
    for (tree_index, relation_tree) in relation_trees.iter().enumerate() {
        if let Some(root) = statement_owned_tree_root(relation_tree) {
            let destination = tree_roots
                .get_mut(tree_index)
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
            let presence = root_present
                .get_mut(tree_index)
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
            *destination = root;
            *presence = true;
        }
    }

    let mut opening_geometries = Vec::new();
    opening_geometries
        .try_reserve_exact(catalog.entries().len())
        .map_err(|_| {
            CommonProofGenerationError::Prover(
                CommonProofProverError::AllocationLimitExceeded,
            )
        })?;
    for entry in catalog.entries() {
        if let Some(tree_plan) = storage_plan
            .tree_plans
            .get(&entry.tree_catalog_index())
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
                canonical_leaf_byte_length: tree_plan
                    .canonical_leaf_byte_length(),
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

    let mut executor = ProofExternalMemoryExecutor::new(
        storage_plan.external_memory_plan,
    )
    .map_err(CommonProofGenerationError::StoragePlan)?;
    let generation_result = (|| {
        let mut stored_trees =
            BTreeMap::<u16, StoredCommonProofMerkleTree>::new();

        for (tree_index, descriptor) in
            variant.ordered_trees().iter().enumerate()
        {
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role: 1,
                ordered_column_ordinals,
            } = descriptor
            else {
                continue;
            };
            let entry = catalog.entries().get(tree_index).ok_or(
                CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ),
            )?;
            let evaluations =
                evaluate_pre_challenge_common_proof_tree_columns(
                    &evaluation_domain,
                    &pre_challenge_columns,
                    ordered_column_ordinals,
                )
                .map_err(CommonProofGenerationError::Prover)?;
            materialize_and_record_common_tree(
                entry,
                &evaluations,
                &mut storage_plan.tree_plans,
                &mut executor,
                storage,
                coins,
                &mut tree_roots,
                &mut root_present,
                &mut stored_trees,
            )
            .map_err(map_tree_storage_generation_error)?;
        }

        let mut transcript = CommonProofTranscript::new(
            protocol_version,
            suite_identifier,
            validated_artifact.application_statement_schema_identifier(),
            &canonical_header_bytes,
            transcript_schedule.clone(),
        )
        .map_err(CommonProofGenerationError::Transcript)?;
        for tree_ordinal in transcript_schedule.ordered_base_tree_ordinals() {
            let entry = unique_catalog_entry(&catalog, |source| {
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
                    tree_roots[usize::from(entry.tree_catalog_index())],
                )
                .map_err(CommonProofGenerationError::Transcript)?;
        }

        let mut application_challenges = Vec::new();
        for challenge_group in
            transcript_schedule.ordered_application_challenge_groups()
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

        let columns = construct_post_challenge_relation_columns(
            variant,
            relation_context,
            pre_challenge_columns,
            provided_non_integer_lift_auxiliary_columns,
            &application_challenges,
            coins,
            relation_context.maximum_fiat_shamir_candidate_draws_per_output,
        )
        .map_err(map_private_coin_generation_error)?;
        for (tree_index, descriptor) in
            variant.ordered_trees().iter().enumerate()
        {
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role: 2,
                ordered_column_ordinals,
            } = descriptor
            else {
                continue;
            };
            let entry = catalog.entries().get(tree_index).ok_or(
                CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ),
            )?;
            let evaluations = evaluate_common_proof_tree_columns(
                &evaluation_domain,
                &columns,
                ordered_column_ordinals,
            )
            .map_err(CommonProofGenerationError::Prover)?;
            materialize_and_record_common_tree(
                entry,
                &evaluations,
                &mut storage_plan.tree_plans,
                &mut executor,
                storage,
                coins,
                &mut tree_roots,
                &mut root_present,
                &mut stored_trees,
            )
            .map_err(map_tree_storage_generation_error)?;
        }
        for tree_ordinal in transcript_schedule.ordered_auxiliary_tree_ordinals() {
            let entry = unique_catalog_entry(&catalog, |source| {
                source
                    == ProofTreeCatalogSource::RelationProofCreated {
                        tree_role: ProofTreeRole::AuxiliaryOracle,
                        tree_ordinal: *tree_ordinal,
                    }
            })
            .map_err(CommonProofGenerationError::Prover)?;
            transcript
                .absorb_auxiliary_root(
                    *tree_ordinal,
                    tree_roots[usize::from(entry.tree_catalog_index())],
                )
                .map_err(CommonProofGenerationError::Transcript)?;
        }

        let mut composition_challenges = Vec::new();
        for constraint_ordinal in
            0..transcript_schedule.composition_challenge_count()
        {
            composition_challenges.push(
                transcript
                    .sample_composition_challenge(constraint_ordinal)
                    .map_err(CommonProofGenerationError::Transcript)?,
            );
        }
        let quotient = construct_composed_quotient_polynomial(
            variant,
            relation_context,
            evaluation_domain,
            &columns,
            &application_challenges,
            &composition_challenges,
        )
        .map_err(CommonProofGenerationError::Prover)?;
        let quotient_components = construct_quotient_components(
            variant,
            relation_context,
            &quotient,
            coins,
            relation_context.maximum_fiat_shamir_candidate_draws_per_output,
        )
        .map_err(map_private_coin_generation_error)?;
        for (component_index, component) in
            quotient_components.iter().enumerate()
        {
            let component_ordinal = u16::try_from(component_index).map_err(|_| {
                CommonProofGenerationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?;
            let entry = unique_catalog_entry(&catalog, |source| {
                source
                    == ProofTreeCatalogSource::QuotientComponent {
                        component_ordinal,
                    }
            })
            .map_err(CommonProofGenerationError::Prover)?;
            let evaluations = vec![CommonProofColumnEvaluations::Extension(
                evaluation_domain
                    .evaluate_extension_polynomial(component)
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofGenerationError::Prover)?,
            )];
            materialize_and_record_common_tree(
                entry,
                &evaluations,
                &mut storage_plan.tree_plans,
                &mut executor,
                storage,
                coins,
                &mut tree_roots,
                &mut root_present,
                &mut stored_trees,
            )
            .map_err(map_tree_storage_generation_error)?;
            transcript
                .absorb_quotient_root(
                    component_ordinal,
                    tree_roots[usize::from(entry.tree_catalog_index())],
                )
                .map_err(CommonProofGenerationError::Transcript)?;
        }

        let mut deep_points = Vec::new();
        for point_ordinal in 0..transcript_schedule.deep_point_count() {
            let mut relation_error = None;
            let point = transcript.sample_deep_point(
                point_ordinal,
                |candidate| match variant.deep_point_candidate_is_forbidden(
                    relation_context,
                    point_ordinal,
                    candidate,
                    &deep_points,
                ) {
                    Ok(forbidden) => forbidden,
                    Err(error) => {
                        relation_error = Some(error);
                        true
                    }
                },
            );
            if let Some(error) = relation_error {
                return Err(CommonProofGenerationError::Relation(error));
            }
            deep_points.push(
                point.map_err(CommonProofGenerationError::Transcript)?,
            );
        }
        let opening_points = variant
            .derive_opening_points(relation_context, &deep_points)
            .map_err(CommonProofGenerationError::Relation)?;
        let opening_batch_mask = construct_opening_batch_mask(
            variant,
            coins,
            relation_context.maximum_fiat_shamir_candidate_draws_per_output,
        )
        .map_err(map_private_coin_generation_error)?;
        let deep_evaluations = evaluate_ordered_deep_openings(
            variant,
            &columns,
            &quotient_components,
            opening_batch_mask.as_deref(),
            &opening_points,
        )
        .map_err(CommonProofGenerationError::Prover)?;
        transcript
            .absorb_deep_evaluations(&deep_evaluations)
            .map_err(CommonProofGenerationError::Transcript)?;

        if transcript_schedule.privacy_mode()
            == CommonProofPrivacyMode::SecretBearing
        {
            let mask = opening_batch_mask.as_ref().ok_or(
                CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidMask,
                ),
            )?;
            let entry = unique_catalog_entry(&catalog, |source| {
                source == ProofTreeCatalogSource::OpeningBatchMask
            })
            .map_err(CommonProofGenerationError::Prover)?;
            let evaluations = vec![CommonProofColumnEvaluations::Extension(
                evaluation_domain
                    .evaluate_extension_polynomial(mask)
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofGenerationError::Prover)?,
            )];
            materialize_and_record_common_tree(
                entry,
                &evaluations,
                &mut storage_plan.tree_plans,
                &mut executor,
                storage,
                coins,
                &mut tree_roots,
                &mut root_present,
                &mut stored_trees,
            )
            .map_err(map_tree_storage_generation_error)?;
            transcript
                .absorb_opening_batch_mask_root(
                    tree_roots[usize::from(entry.tree_catalog_index())],
                )
                .map_err(CommonProofGenerationError::Transcript)?;
        } else if opening_batch_mask.is_some() {
            return Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidMask,
            ));
        }

        let mut opening_batch_coefficients = Vec::new();
        for claim_ordinal in 0..transcript_schedule.opening_claim_count() {
            opening_batch_coefficients.push(
                transcript
                    .sample_opening_batch_challenge(claim_ordinal)
                    .map_err(CommonProofGenerationError::Transcript)?,
            );
        }
        let initial_fri_polynomial = construct_initial_fri_polynomial(
            variant,
            &columns,
            &quotient_components,
            opening_batch_mask.as_deref(),
            &opening_points,
            &deep_evaluations,
            &opening_batch_coefficients,
        )
        .map_err(CommonProofGenerationError::Prover)?;
        let mut fri_domain = evaluation_domain;
        let mut fri_evaluations = fri_domain
            .evaluate_extension_polynomial(&initial_fri_polynomial)
            .map_err(CommonProofProverError::from)
            .map_err(CommonProofGenerationError::Prover)?;
        for fold_ordinal in 0..transcript_schedule.fri_fold_count() {
            let challenge = transcript
                .sample_fri_fold_challenge(fold_ordinal)
                .map_err(CommonProofGenerationError::Transcript)?;
            let (next_domain, next_evaluations) = construct_next_fri_layer(
                &fri_evaluations,
                fri_domain,
                challenge,
            )
            .map_err(CommonProofGenerationError::Prover)?;
            fri_domain = next_domain;
            fri_evaluations = next_evaluations;
            if fold_ordinal + 1 < transcript_schedule.fri_fold_count() {
                let entry = unique_catalog_entry(&catalog, |source| {
                    source
                        == ProofTreeCatalogSource::NonterminalFriLayer {
                            fold_ordinal,
                        }
                })
                .map_err(CommonProofGenerationError::Prover)?;
                let mut evaluations = vec![
                    CommonProofColumnEvaluations::Extension(fri_evaluations),
                ];
                materialize_and_record_common_tree(
                    entry,
                    &evaluations,
                    &mut storage_plan.tree_plans,
                    &mut executor,
                    storage,
                    coins,
                    &mut tree_roots,
                    &mut root_present,
                    &mut stored_trees,
                )
                .map_err(map_tree_storage_generation_error)?;
                fri_evaluations = match evaluations.pop() {
                    Some(CommonProofColumnEvaluations::Extension(values)) => {
                        values
                    }
                    _ => {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidFriLayer,
                        ));
                    }
                };
                transcript
                    .absorb_fri_layer_root(
                        fold_ordinal,
                        tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationError::Transcript)?;
            }
        }
        let terminal_coefficients = construct_fri_terminal_coefficients(
            &fri_evaluations,
            fri_domain,
            relation_context.final_polynomial_degree_bound_exclusive,
        )
        .map_err(CommonProofGenerationError::Prover)?;
        transcript
            .absorb_fri_terminal_coefficients(&terminal_coefficients)
            .map_err(CommonProofGenerationError::Transcript)?;

        let mut sampled_query_representatives = transcript
            .sample_query_representatives()
            .map_err(CommonProofGenerationError::Transcript)?;
        let sorted_query_representatives = transcript
            .sorted_query_representatives()
            .map_err(CommonProofGenerationError::Transcript)?;
        sampled_query_representatives.sort_unstable();
        if sampled_query_representatives != sorted_query_representatives
            || !storage_plan.tree_plans.is_empty()
            || root_present.iter().any(|present| !present)
        {
            return Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let query_section_byte_length =
            common_proof_query_section_byte_length(
                &catalog,
                &opening_geometries,
                &sorted_query_representatives,
            )
            .map_err(CommonProofGenerationError::Prover)?;
        write_common_proof_prefix(
            sink,
            &canonical_header_bytes,
            &catalog,
            &tree_roots,
            &deep_evaluations,
            &terminal_coefficients,
            &transcript_schedule,
        )
        .map_err(|error| match error {
            CommonProofEncodingError::Prover(error) => {
                CommonProofGenerationError::Prover(error)
            }
            CommonProofEncodingError::Sink(error) => {
                CommonProofGenerationError::Sink(error)
            }
            CommonProofEncodingError::Artifact(artifact) => match artifact {},
        })?;

        let mut query_opening_absorber = transcript
            .begin_query_openings(query_section_byte_length)
            .map_err(CommonProofGenerationError::Transcript)?;
        {
            let transcript_sink = CommonProofTranscriptQuerySink::new(
                sink,
                &mut query_opening_absorber,
            );
            let mut writer = CommonProofQuerySectionWriter::new(
                transcript_sink,
                &catalog,
                &opening_geometries,
                &sorted_query_representatives,
            )
            .map_err(|error| match error {
                CommonProofEncodingError::Prover(error) => {
                    CommonProofGenerationError::Prover(error)
                }
                CommonProofEncodingError::Sink(error) => match error {
                    CommonProofTranscriptQuerySinkError::Sink(error) => {
                        CommonProofGenerationError::Sink(error)
                    }
                    CommonProofTranscriptQuerySinkError::Transcript(error) => {
                        CommonProofGenerationError::Transcript(error)
                    }
                },
                CommonProofEncodingError::Artifact(artifact) => match artifact {},
            })?;
            for entry in catalog.entries() {
                if entry.source() == ProofTreeCatalogSource::RelationBoundPublic {
                    bound_openings
                        .write_next_bound_opening(entry, &mut writer)
                        .map_err(|error| match error {
                            CommonProofEncodingError::Prover(error) => {
                                CommonProofGenerationError::Prover(error)
                            }
                            CommonProofEncodingError::Sink(error) => match error {
                                CommonProofTranscriptQuerySinkError::Sink(error) => {
                                    CommonProofGenerationError::Sink(error)
                                }
                                CommonProofTranscriptQuerySinkError::Transcript(error) => {
                                    CommonProofGenerationError::Transcript(error)
                                }
                            },
                            CommonProofEncodingError::Artifact(error) => {
                                CommonProofGenerationError::BoundOpening(error)
                            }
                        })?;
                    continue;
                }
                let tree = stored_trees
                    .get(&entry.tree_catalog_index())
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ))?;
                let mut prefetcher = CommonProofOpeningPrefetcher::new(
                    tree,
                    entry,
                    catalog.evaluation_domain_size(),
                    &sorted_query_representatives,
                    maximum_prefetched_query_byte_length,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                loop {
                    match prefetcher
                        .advance_storage(&mut executor, storage)
                        .map_err(CommonProofGenerationError::Storage)?
                    {
                        CommonProofOpeningPrefetchProgress::StorageTransactionCompleted => {}
                        CommonProofOpeningPrefetchProgress::Complete => break,
                    }
                }
                let mut artifact = prefetcher
                    .finish()
                    .map_err(CommonProofGenerationError::Prover)?;
                writer
                    .write_next_opening(&mut artifact)
                    .map_err(|error| match error {
                        CommonProofEncodingError::Prover(error) => {
                            CommonProofGenerationError::Prover(error)
                        }
                        CommonProofEncodingError::Sink(error) => match error {
                            CommonProofTranscriptQuerySinkError::Sink(error) => {
                                CommonProofGenerationError::Sink(error)
                            }
                            CommonProofTranscriptQuerySinkError::Transcript(error) => {
                                CommonProofGenerationError::Transcript(error)
                            }
                        },
                        CommonProofEncodingError::Artifact(error) => {
                            CommonProofGenerationError::Prover(error)
                        }
                    })?;
            }
            let transcript_sink = writer
                .finish()
                .map_err(CommonProofGenerationError::Prover)?;
            drop(transcript_sink);
        }
        transcript
            .finish_query_openings(query_opening_absorber)
            .map_err(CommonProofGenerationError::Transcript)?;
        transcript
            .finish()
            .map_err(CommonProofGenerationError::Transcript)?;
        executor
            .complete_step(storage)
            .map_err(CommonProofGenerationError::Storage)?;
        Ok(())
    })();

    match generation_result {
        Ok(()) => Ok(()),
        Err(original) => match executor.cancel(storage) {
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
        ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomnessDerivationInput,
        ActionRandomnessRoot, ParticipantIdentity, PersistentProofCoinInput,
        ProofApplicationSlot,
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
                output[sum_ordinal] =
                    output[sum_ordinal].add(left_value.multiply(right_value));
            }
        }
        output
    }

    fn theta_fingerprint(
        coefficients: &[ProofBaseFieldElement],
        theta: ProofBaseFieldElement,
    ) -> ProofBaseFieldElement {
        coefficients.iter().rev().fold(
            ProofBaseFieldElement::ZERO,
            |accumulated, coefficient| accumulated.multiply(theta).add(*coefficient),
        )
    }

    #[test]
    fn trace_mask_changes_coefficients_but_preserves_every_trace_domain_value() {
        let witness = CommonProofSourcePolynomial::Base(vec![base(7), base(11), base(13)]);
        let mask = CommonProofSourcePolynomial::Base(vec![base(17), base(19), base(23)]);
        let masked = apply_trace_mask(witness.clone(), 8, mask)
            .expect("valid trace mask is applied");
        assert_ne!(masked, witness);

        let trace_domain = ProofEvaluationDomain::new(8, 7)
            .expect("evaluation domain exposes the trace subgroup generator");
        for position in 0..trace_domain.size() {
            let point = ProofChallengeExtensionElement::from_base(
                trace_domain.generator().power(
                    u64::try_from(position).expect("test position fits the field exponent"),
                ),
            );
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
        let source = [3, -2, 7, 1, -4, 5, 2, -1]
            .map(signed_base)
            .to_vec();
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
                    let transpose = convolution_transpose_rows(
                        kind,
                        &multiplicand,
                        &suffix,
                        theta,
                    )
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
            let reversed_multiplier_low =
                multiplier_low.iter().copied().rev().collect::<Vec<_>>();
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
                        RelationIntegerLiftFullRingHalf::Low => {
                            &product[..half_ring_degree]
                        }
                        RelationIntegerLiftFullRingHalf::High => {
                            &product[half_ring_degree..]
                        }
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
                                mutated[row_ordinal]
                                    .multiply(reversed_multiplier_low[row_ordinal]),
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
        let product_rows = [4, -3, 7, 2, -5, 1, 6, -2]
            .map(signed_base)
            .to_vec();
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
        assert_eq!(components.iter().map(Vec::len).collect::<Vec<_>>(), vec![4, 4, 3]);
        assert_eq!(components.concat(), quotient);
        assert_eq!(
            decompose_composed_quotient(&[extension(1); 9], 2, 4),
            Err(CommonProofProverError::InvalidQuotient)
        );
    }

    #[test]
    fn phase_pair_values_use_the_exact_opposite_domain_position() {
        let first_column = CommonProofColumnEvaluations::Base(
            (0..8).map(|value| base(value + 1)).collect(),
        );
        let second_column = CommonProofColumnEvaluations::Base(
            (0..8).map(|value| base(value + 21)).collect(),
        );
        let (first, opposite) = common_proof_phase_pair_values(
            &[first_column, second_column],
            2,
        )
        .expect("phase pair is in range");
        assert_eq!(
            first,
            vec![ProofTreeValue::Base(base(3)), ProofTreeValue::Base(base(23))]
        );
        assert_eq!(
            opposite,
            vec![ProofTreeValue::Base(base(7)), ProofTreeValue::Base(base(27))]
        );
    }

    #[test]
    fn phase_pair_values_reject_mixed_or_misaligned_columns() {
        assert_eq!(
            common_proof_phase_pair_values(
                &[
                    CommonProofColumnEvaluations::Base(vec![base(1); 8]),
                    CommonProofColumnEvaluations::Extension(vec![extension(1); 8]),
                ],
                0,
            ),
            Err(CommonProofProverError::InvalidTree)
        );
        assert_eq!(
            common_proof_phase_pair_values(
                &[
                    CommonProofColumnEvaluations::Base(vec![base(1); 8]),
                    CommonProofColumnEvaluations::Base(vec![base(1); 4]),
                ],
                0,
            ),
            Err(CommonProofProverError::InvalidTree)
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
            canonical_proof_object_header_bytes(&statement)
                .expect("prover proof header encodes"),
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
        let action_private_randomness = ActionRandomnessRoot::from_injected_bytes(
            Zeroizing::new([0x55; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]),
        )
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
        let attempt_input = PersistentProofCoinInput::new(
            application_slot,
            Hash512::from_bytes([0x66; 64]),
        )
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
