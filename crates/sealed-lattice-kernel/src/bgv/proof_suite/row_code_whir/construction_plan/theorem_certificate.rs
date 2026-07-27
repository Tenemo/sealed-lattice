//! Executable parameter and failure-partition certificate for the checked
//! row-code WHIR construction.
//!
//! The certificate derives its rows from the production construction plan. It
//! deliberately keeps arithmetic discharge separate from cryptographic
//! assumptions and from the still-required whole-protocol extractor proof.

use std::collections::BTreeSet;

use num_bigint::BigUint;

use super::*;
use crate::bgv::proof_suite::{
    ValidatedRelationPlanArtifact, compile_same_secret_relation_plan,
    selected_same_secret_relation_plan_input,
};

const WHIR_SUMCHECK_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE: u64 = 3;
const SELECTED_AGGREGATE_TABLE_WIDTH: usize = 4;
const SELECTED_OPENING_BATCH_COUNT: usize = 1_008;
const SELECTED_SCALAR_OPENING_COUNT: u64 = 1_782;
/// The independently pinned transcript hash-query ceiling for the selected
/// same-secret plan. It reconciles exactly against the plan-derived
/// oracle-equation census:
///
/// ~~~text
/// initial header root and absorption      1 +     1 =         2
/// response roots                       2,042      =     2,042
/// response bindings                    2,018      =     2,018
/// response absorptions                 2,050      =     2,050
/// accepted challenges                  5,076 * 1  =     5,076
/// challenge handles                    5,076 * 1  =     5,076
/// extension rejection chains   5,066 * 2 * 127    = 1,286,764
/// product expansions               3 * 128 * 1    =       384
/// distinct expansions   (2*387 + 288 + 268 + 266 + 264 + 263) * 16
///                                                 =    33,968
/// total                                             1,337,380
/// ~~~
///
/// The `5,076` accepted challenges partition as `5,066` extension challenges
/// plus `7` distinct-index samplers plus `3` product-space samplers, which is
/// also the logical verifier-message count below. The distinct-sampler row
/// carries `266` accepted direct-bound draws once; the prior-certificate subset
/// selects its first `40` in accepted order and therefore draws nothing extra.
const SELECTED_TRANSCRIPT_HASH_QUERY_COUNT: u64 = 1_337_380;
const SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT: u64 = 5_076;
const CMS19_ADVERSARIAL_QUERY_EXPONENT: usize = 80;
const CMS19_ORACLE_OUTPUT_BIT_LENGTH: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum WhirTheoremCertificateError {
    ArithmeticOverflow,
    InvalidSelectedGeometry,
    IncompleteTranscriptMapping,
    IncompleteOracleEquationMapping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactFraction {
    numerator: u64,
    denominator: u64,
}

impl ExactFraction {
    fn new(numerator: u64, denominator: u64) -> Result<Self, WhirTheoremCertificateError> {
        if denominator == 0 {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let divisor = greatest_common_divisor(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    fn less_than(self, right: Self) -> Result<bool, WhirTheoremCertificateError> {
        let left_product = u128::from(self.numerator)
            .checked_mul(u128::from(right.denominator))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let right_product = u128::from(right.numerator)
            .checked_mul(u128::from(self.denominator))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        Ok(left_product < right_product)
    }

    fn floor_product(self, factor: u64) -> Result<u64, WhirTheoremCertificateError> {
        let product = u128::from(self.numerator)
            .checked_mul(u128::from(factor))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        u64::try_from(product / u128::from(self.denominator))
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)
    }
}

const fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirCodeStateRow {
    epoch_ordinal: u32,
    fold_ordinal: u32,
    domain_size: u64,
    dimension: u64,
    minimum_distance: u64,
    unique_decoding_radius: u64,
    selected_state_error_count_ceiling: u64,
    selected_state_relative_distance: ExactFraction,
    false_state_minimum_error_count: u64,
    false_state_agreement_ceiling: ExactFraction,
    reed_solomon_rate: ExactFraction,
    corollary_four_eleven_proximity_bound: ExactFraction,
    theorem_five_two_strict_distance_ceiling: ExactFraction,
    unique_decoding_list_size_ceiling: u64,
}

impl WhirCodeStateRow {
    fn derive(
        epoch_ordinal: u32,
        fold_ordinal: u32,
        parent_domain_size: u64,
        parent_dimension: u64,
        selected_state_relative_distance: ExactFraction,
    ) -> Result<Self, WhirTheoremCertificateError> {
        let domain_size = parent_domain_size
            .checked_shr(fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let dimension = parent_dimension
            .checked_shr(fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        if dimension >= domain_size {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let minimum_distance = domain_size
            .checked_sub(dimension)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let unique_decoding_radius = minimum_distance
            .checked_sub(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
            / 2;
        let selected_state_error_count_ceiling =
            selected_state_relative_distance.floor_product(domain_size)?;
        let false_state_minimum_error_count = selected_state_error_count_ceiling
            .checked_add(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let false_state_agreement_ceiling = ExactFraction::new(
            domain_size
                .checked_sub(false_state_minimum_error_count)
                .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
            domain_size,
        )?;
        let reed_solomon_rate = ExactFraction::new(dimension, domain_size)?;
        // Corollary 4.11 gives B* = (1 + rho) / 2 in the proved
        // unique-decoding regime. Theorem 5.2 requires delta < 1 - B*,
        // so the state radius uses the greatest integral Hamming radius
        // strictly below that open endpoint. A false state therefore starts
        // at the ordinary unique-decoding radius and retains the same query
        // agreement ceiling used by the selected proof.
        let corollary_four_eleven_proximity_bound = ExactFraction::new(
            domain_size
                .checked_add(dimension)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            domain_size
                .checked_mul(2)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?;
        let theorem_five_two_strict_distance_ceiling = ExactFraction::new(
            domain_size
                .checked_sub(dimension)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            domain_size
                .checked_mul(2)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?;
        if unique_decoding_radius == 0
            || false_state_minimum_error_count > unique_decoding_radius
            || !selected_state_relative_distance
                .less_than(theorem_five_two_strict_distance_ceiling)?
            || !selected_state_relative_distance.less_than(corollary_four_eleven_proximity_bound)?
            || selected_state_error_count_ceiling > unique_decoding_radius
            || unique_decoding_radius
                .checked_mul(2)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
                >= minimum_distance
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }

        Ok(Self {
            epoch_ordinal,
            fold_ordinal,
            domain_size,
            dimension,
            minimum_distance,
            unique_decoding_radius,
            selected_state_error_count_ceiling,
            selected_state_relative_distance,
            false_state_minimum_error_count,
            false_state_agreement_ceiling,
            reed_solomon_rate,
            corollary_four_eleven_proximity_bound,
            theorem_five_two_strict_distance_ceiling,
            unique_decoding_list_size_ceiling: 1,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InterleavedUniqueDecodingRow {
    epoch_ordinal: u32,
    fold_ordinal: u32,
    lane_count: usize,
    constituent_minimum_distance: u64,
    interleaved_minimum_distance: u64,
    selected_state_error_count_ceiling: u64,
    unique_decoding_list_size_ceiling: u64,
    lower_bound_uses_nonzero_component: bool,
    upper_bound_uses_one_nonzero_component: bool,
}

impl InterleavedUniqueDecodingRow {
    fn derive(
        code_state: WhirCodeStateRow,
        lane_count: usize,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if lane_count == 0
            || code_state.unique_decoding_list_size_ceiling != 1
            || code_state.selected_state_error_count_ceiling >= code_state.unique_decoding_radius
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }

        // For the coordinate-wise interleaving of identical linear codes,
        // every nonzero word has a nonzero component and therefore weight at
        // least the constituent minimum distance. Conversely, placing a
        // constituent minimum-weight codeword in one component and zero in
        // every other component attains that distance. The interleaved and
        // constituent distances are therefore equal, so the same strict
        // unique-decoding radius gives list size one.
        Ok(Self {
            epoch_ordinal: code_state.epoch_ordinal,
            fold_ordinal: code_state.fold_ordinal,
            lane_count,
            constituent_minimum_distance: code_state.minimum_distance,
            interleaved_minimum_distance: code_state.minimum_distance,
            selected_state_error_count_ceiling: code_state.selected_state_error_count_ceiling,
            unique_decoding_list_size_ceiling: 1,
            lower_bound_uses_nonzero_component: true,
            upper_bound_uses_one_nonzero_component: true,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirFoldFailureRow {
    epoch_ordinal: u32,
    fold_ordinal: u32,
    transcript_operation_ordinal: u32,
    target_domain_size: u64,
    sumcheck_numerator: u64,
    mutual_correlated_agreement_numerator: u64,
}

impl WhirFoldFailureRow {
    fn total_numerator(self) -> Result<u64, WhirTheoremCertificateError> {
        self.sumcheck_numerator
            .checked_add(self.mutual_correlated_agreement_numerator)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirShiftFailureRow {
    round_ordinal: u32,
    transcript_operation_ordinal: u32,
    query_count: u64,
    list_size: u64,
    algebraic_numerator: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirFinalQueryRow {
    epoch_ordinal: u32,
    query_count: u64,
    bad_agreement: ExactFraction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrefixStackingCertificate {
    source_table_count: usize,
    committed_polynomial_count: usize,
    table_variable_count: usize,
    selector_variable_count: usize,
    stacked_variable_count: usize,
    table_width: usize,
    opening_batch_count: usize,
    scalar_opening_count: u64,
    selector_indices: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateTransitionOwner {
    FixedInitialState,
    ProverMessageCannotRepairFalseState,
    VerifierChallengeWithTypedFailureEvent,
    TerminalDecision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanStatePredicateClause {
    EmptyCanonicalPrefixIsFalse,
    BackwardClosureOverCanonicalProverMove,
    PolynomialProtocolChallenge,
    RelationReductionChallenge,
    OuterRowCodeAgreement,
    BoundIdentityAgreement,
    WhirInitialOutOfDomain,
    WhirOpeningConstraintBatch,
    WhirRoundOutOfDomain {
        epoch_ordinal: u32,
        sample_ordinal: u32,
    },
    WhirRoundConstraintCheckpoint {
        epoch_ordinal: u32,
    },
    WhirConstrainedFold {
        epoch_ordinal: u32,
        fold_ordinal: u32,
    },
    WhirQueryAgreement {
        epoch_ordinal: u32,
    },
    WhirQueryCombination {
        epoch_ordinal: u32,
    },
    WhirFinalSumcheck {
        epoch_ordinal: u32,
        round_ordinal: u32,
    },
    FullCanonicalTranscriptAccepts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanFailureEventClass {
    PolynomialProtocolKnowledge,
    AlgebraicExceptionalSet,
    WithoutReplacementAgreement,
    WhirRoundByRoundProximity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanFailureEventOwner {
    CommonProductChallenge { challenge: CommonProofChallenge },
    CommonExtensionChallenge { challenge: CommonProofChallenge },
    DirectExtensionChallenge { challenge: RowCodeWhirChallenge },
    DistinctQueryVector { role: RowCodeWhirQueryRole },
    WhirExtensionChallenge { role: RowCodeWhirExtensionRole },
}

impl SelectedPlanFailureEventOwner {
    const fn event_class(self) -> SelectedPlanFailureEventClass {
        match self {
            Self::CommonProductChallenge { .. } => {
                SelectedPlanFailureEventClass::PolynomialProtocolKnowledge
            }
            Self::CommonExtensionChallenge { .. } | Self::DirectExtensionChallenge { .. } => {
                SelectedPlanFailureEventClass::AlgebraicExceptionalSet
            }
            Self::DistinctQueryVector { .. } => {
                SelectedPlanFailureEventClass::WithoutReplacementAgreement
            }
            Self::WhirExtensionChallenge { .. } => {
                SelectedPlanFailureEventClass::WhirRoundByRoundProximity
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedPlanStateTransitionRow {
    operation_ordinal: u32,
    predicate_clause: SelectedPlanStatePredicateClause,
    failure_event_owner: Option<SelectedPlanFailureEventOwner>,
    sampler_exhaustion_is_honest_abort: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanProofSectionPredicate {
    RelationPhaseAffineSpan { phase: RowCodeWhirPhase },
    OutOfDomainCompositionAndRegisteredClaims,
    OpeningBatchMaskConsistency,
    AggregateConstrainedPolynomialCommitment,
    PhaseOpeningAuthenticationAndReduction { phase: RowCodeWhirPhase },
    BoundAuthenticationAndReduction { bound_tree_ordinal: u32 },
    ExplicitPointWhirOpening,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedPlanProofSectionStateRow {
    section_ordinal: u32,
    item_count: usize,
    predicate: SelectedPlanProofSectionPredicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanCheckpointStateOwner {
    AuthenticatedSourceAndConstruction,
    CompletedPhaseCommitment { phase: RowCodeWhirPhase },
    RelationEvaluationsAndMask,
    AggregateCommitmentAndQueries,
    CompletedWhirRound { round_ordinal: u32 },
    CompletedCanonicalProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedPlanCheckpointStateRow {
    checkpoint_ordinal: u32,
    next_transcript_operation_ordinal: u32,
    next_proof_section_ordinal: u32,
    owner: SelectedPlanCheckpointStateOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanLifecycleTransition {
    AuthenticatedResume,
    ExplicitAbort,
    Cancellation,
    SamplerExhaustion,
    MaskRankFailure,
    StorageRefusal,
    CompletedProofTransport,
    FreshVerifierAcceptance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedPlanLifecycleStateRow {
    transition: SelectedPlanLifecycleTransition,
    preserves_cryptographic_cursor: bool,
    emits_proof: bool,
    emits_verified_capability: bool,
    requires_fresh_verifier: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedPlanStatePredicateCertificate {
    transition_rows: Vec<SelectedPlanStateTransitionRow>,
    proof_section_rows: Vec<SelectedPlanProofSectionStateRow>,
    checkpoint_rows: Vec<SelectedPlanCheckpointStateRow>,
    lifecycle_rows: Vec<SelectedPlanLifecycleStateRow>,
    canonical_prefix_required: bool,
    single_semantic_witness_required: bool,
    decoded_equation_consistency_required: bool,
    constrained_code_state_required: bool,
    accepting_suffix_required: bool,
}

impl SelectedPlanStatePredicateCertificate {
    fn is_total_for_plan(&self, plan: &RowCodeWhirConstructionPlan) -> bool {
        self.canonical_prefix_required
            && self.single_semantic_witness_required
            && self.decoded_equation_consistency_required
            && self.constrained_code_state_required
            && self.accepting_suffix_required
            && self.transition_rows.len()
                == plan
                    .oracle_equation_catalog()
                    .ok()
                    .map_or(0, |catalog| catalog.operations.len())
            && self.proof_section_rows.len() == plan.proof_sections().len()
            && self.checkpoint_rows.len() == plan.checkpoints().len()
            && self.lifecycle_rows.len() == 8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateEpochRow {
    operation_ordinal: u32,
    predecessor_operation_ordinal: Option<u32>,
    transition_owner: StateTransitionOwner,
    first_equation_slot_ordinal: u64,
    equation_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleEquationRole {
    InitialHeaderRoot,
    InitialAbsorption,
    ResponseRoot,
    ResponseBinding,
    ResponseAbsorption,
    AcceptedChallenge,
    ChallengeHandle,
    RejectedChallenge,
    LinearExpansionBlock,
}

impl OracleEquationRole {
    const fn predecessor_support_count(self) -> u8 {
        match self {
            Self::InitialHeaderRoot | Self::ResponseRoot => 0,
            Self::InitialAbsorption
            | Self::ResponseBinding
            | Self::AcceptedChallenge
            | Self::ChallengeHandle
            | Self::RejectedChallenge
            | Self::LinearExpansionBlock => 1,
            Self::ResponseAbsorption => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleEquationRolePattern {
    Single(OracleEquationRole),
    Alternating {
        first: OracleEquationRole,
        second: OracleEquationRole,
    },
}

impl OracleEquationRolePattern {
    fn maximum_predecessor_support_count(self) -> u8 {
        match self {
            Self::Single(role) => role.predecessor_support_count(),
            Self::Alternating { first, second } => first
                .predecessor_support_count()
                .max(second.predecessor_support_count()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OracleEquationCoverageRow {
    operation_ordinal: u32,
    range_ordinal: u16,
    first_equation_slot_ordinal: u64,
    equation_count: u64,
    role_pattern: OracleEquationRolePattern,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MerkleOracleEquationRole {
    RelationPhase { phase: RowCodeWhirPhase },
    BoundTree { bound_tree_ordinal: u32 },
    WhirEpoch { epoch_ordinal: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MerkleOracleEquationCoverageRow {
    role: MerkleOracleEquationRole,
    leaf_count: usize,
    query_count: usize,
    leaf_hash_query_count: u64,
    parent_hash_query_count: u64,
    accepting_database_equation_count_ceiling: u64,
    predecessor_support_ceiling: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckedRelationPhaseOpeningRow {
    phase: RowCodeWhirPhase,
    leaf_count: usize,
    query_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckedWhirEpochOpeningRow {
    commitment_role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
    epoch_ordinal: u32,
    leaf_count: usize,
    query_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CheckedSuppliedCommitmentOpeningRows {
    relation_phases: Vec<CheckedRelationPhaseOpeningRow>,
    whir_epochs: Vec<CheckedWhirEpochOpeningRow>,
}

impl MerkleOracleEquationCoverageRow {
    fn hash_query_count(self) -> Result<u64, WhirTheoremCertificateError> {
        self.leaf_hash_query_count
            .checked_add(self.parent_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    }
}

fn checked_supplied_commitment_opening_rows(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<CheckedSuppliedCommitmentOpeningRows, WhirTheoremCertificateError> {
    let transcript_plan = plan
        .linear_bcs_transcript_plan()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let mut relation_phases = Vec::new();
    let mut whir_epochs = Vec::new();
    for opening in transcript_plan.supplied_commitment_openings() {
        if opening.query_order
            != linear_bcs_transcript::LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder
            || opening.merkle_traversal_order
                != linear_bcs_transcript::LinearBcsMerkleTraversalOrder::SortedCoordinates
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        match (opening.commitment_role, opening.owner) {
            (
                linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase { phase },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector,
            ) => relation_phases.push(CheckedRelationPhaseOpeningRow {
                phase,
                leaf_count: opening.payload_leaf_count,
                query_count: opening.query_count,
            }),
            (
                commitment_role @ (linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate
                | linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                    ..
                }),
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                    epoch_ordinal,
                },
            ) => whir_epochs.push(CheckedWhirEpochOpeningRow {
                commitment_role,
                epoch_ordinal,
                leaf_count: opening.payload_leaf_count,
                query_count: opening.query_count,
            }),
            _ => return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping),
        }
    }
    if relation_phases
        .iter()
        .map(|row| row.phase)
        .collect::<Vec<_>>()
        != plan.phase_order
        || whir_epochs.len() != 5
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    for (epoch_index, row) in whir_epochs.iter().enumerate() {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let expected_commitment_role = if epoch_ordinal == 0 {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate
        } else {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                round_ordinal: epoch_ordinal - 1,
            }
        };
        if row.epoch_ordinal != epoch_ordinal || row.commitment_role != expected_commitment_role {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    }
    Ok(CheckedSuppliedCommitmentOpeningRows {
        relation_phases,
        whir_epochs,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedVerifierHashRole {
    RelationPlanIdentity,
    RelationPlanVariantIdentity,
    ConstructionPlanIdentity,
    ApplicationStatement,
    PublicSetupVerifierSequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FixedVerifierHashCoverageRow {
    role: FixedVerifierHashRole,
    hash_query_count: u64,
    distinct_equation_count: u64,
    transcript_catalog_equation_overlap_count: u64,
}

impl FixedVerifierHashCoverageRow {
    fn new_equation_count(self) -> Result<u64, WhirTheoremCertificateError> {
        self.distinct_equation_count
            .checked_sub(self.transcript_catalog_equation_overlap_count)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompleteVerifierOracleLedger {
    transcript_equation_count: u64,
    transcript_hash_query_count: u64,
    merkle_rows: Vec<MerkleOracleEquationCoverageRow>,
    fixed_hash_rows: Vec<FixedVerifierHashCoverageRow>,
    complete_equation_count_ceiling: u64,
    complete_hash_query_count: u64,
}

impl CompleteVerifierOracleLedger {
    fn merkle_hash_query_count(&self) -> Result<u64, WhirTheoremCertificateError> {
        self.merkle_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.hash_query_count()?)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    fn fixed_hash_query_count(&self) -> Result<u64, WhirTheoremCertificateError> {
        self.fixed_hash_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    fn fixed_distinct_equation_count(&self) -> Result<u64, WhirTheoremCertificateError> {
        self.fixed_hash_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.distinct_equation_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    fn fixed_new_equation_count(&self) -> Result<u64, WhirTheoremCertificateError> {
        self.fixed_hash_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.new_equation_count()?)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19ArithmeticCertificate {
    adversarial_query_bound: BigUint,
    verifier_hash_query_count: u64,
    accepting_database_equation_count: u64,
    compiler_query_bound: BigUint,
    classical_soundness_multiplier: BigUint,
    ideal_oracle_penalty_numerator: BigUint,
    ideal_oracle_penalty_denominator_bit_length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cms19Transform {
    ModifiedBcsHashChainSectionsEightTwoThroughEightFive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PropositionEightTwelvePartitionCase {
    AcceptingDatabaseContainsCollision,
    CollisionFreeAcceptingDatabaseYieldsFullTranscript,
    EarliestFalseToTrueVerifierStateTransition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatePredicateRequirement {
    ModifiedBcsRuntimeHashChainCorrespondence,
    CanonicalPlanCursorCoverage,
    EmptyTranscriptIsFalse,
    ProverMoveCannotRepairFalseState,
    FullFalseTranscriptIsRejected,
    EveryVerifierChallengeHasOneTypedFailureOwner,
    EveryProofSectionHasOnePredicateOwner,
    EveryCheckpointHasOneStateOwner,
    LifecycleNonAcceptanceAndFreshVerification,
    SelectedUniqueDecodingInequalitiesHold,
    InterleavedDistanceAndListSizeHold,
    ExplicitUniqueDecoderExists,
    ExtractCompleteRelationPhaseCodewords,
    ExtractCompleteBoundCodewords,
    ExtractCompleteWhirEpochCodewords,
    ExplicitPointConstraintExtractorCorrespondence,
    ExtractThetaAndPhaseReductions,
    ExtractCompilerInterpreterRelationWitness,
    ExactFailureMagnitudeCorrespondence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatePredicateDischargeAuthority {
    MissingModifiedBcsRuntimeHashChainCorrespondence,
    GeneratedSelectedPlanStatePredicate,
    GeneratedFailureOwnerPartition,
    CheckedConstructionGeometry,
    CheckedInterleavedDistanceLemma,
    ExplicitBerlekampWelchExtractor,
    MissingTypedAcceptingDatabaseExtractor,
    MissingExplicitPointExtractorCorrespondence,
    MissingWholeRelationExtractor,
    MissingExactFailureMagnitudeCorrespondence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StatePredicateRequirementRow {
    requirement: StatePredicateRequirement,
    discharge_authority: StatePredicateDischargeAuthority,
    is_discharged: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19StatePredicateCertificate {
    requirements: Vec<StatePredicateRequirementRow>,
    proposition_eight_twelve_partition: Vec<PropositionEightTwelvePartitionCase>,
    transcript_incompatibility_count: usize,
}

impl Cms19StatePredicateCertificate {
    fn is_complete(&self) -> bool {
        self.requirements.iter().all(|row| row.is_discharged)
            && self.transcript_incompatibility_count == 0
    }

    fn has_exact_abstract_partition(&self) -> bool {
        self.proposition_eight_twelve_partition
            == [
                PropositionEightTwelvePartitionCase::AcceptingDatabaseContainsCollision,
                PropositionEightTwelvePartitionCase::CollisionFreeAcceptingDatabaseYieldsFullTranscript,
                PropositionEightTwelvePartitionCase::EarliestFalseToTrueVerifierStateTransition,
            ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19ApplicabilityCertificate {
    transform: Cms19Transform,
    transcript_equation_count: u64,
    transcript_hash_query_count: u64,
    claimed_complete_equation_count: u64,
    claimed_complete_hash_query_count: u64,
    equation_count_without_catalog_correspondence: u64,
    hash_query_count_without_catalog_correspondence: u64,
    transcript_predecessor_support_ceiling: u8,
    complete_state_predicate_established: bool,
    syntactic_proposition_eight_twelve_partition_catalogued: bool,
    proposition_eight_twelve_case_split_established: bool,
    complete_query_ledger_correspondence_established: bool,
    modified_bcs_linear_hash_chain_established: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum UndischargedConstructionHypothesis {
    ModifiedBcsRuntimeHashChainCorrespondence,
    ConstructionMaskingCorrespondence,
    CommitmentSubtreeExtraction,
    ExplicitPointConstraintExtractorCorrespondence,
    WholePolynomialProtocolRoundByRoundExtractor,
    CompilerInterpreterSemanticCorrespondence,
    ExactFailureMagnitudeCorrespondence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirFailurePartitionCertificate {
    code_state_rows: Vec<WhirCodeStateRow>,
    interleaved_unique_decoding_rows: Vec<InterleavedUniqueDecodingRow>,
    fold_rows: Vec<WhirFoldFailureRow>,
    shift_rows: Vec<WhirShiftFailureRow>,
    final_query_row: WhirFinalQueryRow,
    initial_constraint_batch_numerator: u64,
    final_sumcheck_numerator: u64,
    prefix_stacking: PrefixStackingCertificate,
    state_epoch_rows: Vec<StateEpochRow>,
    oracle_equation_rows: Vec<OracleEquationCoverageRow>,
    complete_verifier_oracle_ledger: CompleteVerifierOracleLedger,
    selected_plan_state_predicate: SelectedPlanStatePredicateCertificate,
    cms19_state_predicate: Cms19StatePredicateCertificate,
    maximum_transcript_hash_query_count: u64,
    logical_verifier_message_count: u64,
    cms19_arithmetic: Cms19ArithmeticCertificate,
    cms19_applicability: Cms19ApplicabilityCertificate,
    undischarged_hypotheses: BTreeSet<UndischargedConstructionHypothesis>,
}

impl RowCodeWhirFailurePartitionCertificate {
    pub(in crate::bgv::proof_suite) fn fold_numerator(
        &self,
    ) -> Result<u64, WhirTheoremCertificateError> {
        self.fold_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.total_numerator()?)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    pub(in crate::bgv::proof_suite) fn shift_numerator(
        &self,
    ) -> Result<u64, WhirTheoremCertificateError> {
        self.shift_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.algebraic_numerator)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    pub(in crate::bgv::proof_suite) const fn initial_constraint_batch_numerator(&self) -> u64 {
        self.initial_constraint_batch_numerator
    }

    pub(in crate::bgv::proof_suite) const fn final_sumcheck_numerator(&self) -> u64 {
        self.final_sumcheck_numerator
    }

    pub(in crate::bgv::proof_suite) fn is_complete_construction_theorem(&self) -> bool {
        self.undischarged_hypotheses.is_empty()
    }
}

pub(in crate::bgv::proof_suite) fn checked_row_code_whir_failure_partition(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<RowCodeWhirFailurePartitionCertificate, WhirTheoremCertificateError> {
    let parameters = plan.selected_parameters();
    if parameters != RowCodeWhirSelectedParameters::selected()
        || parameters.soundness_assumption != RowCodeWhirSoundnessAssumption::UniqueDecoding
        || parameters.folding_factor != 3
        || plan.whir.rounds.len() != 4
        || plan.whir.initial_sumcheck_round_count != parameters.folding_factor
        || plan.whir.final_round.sumcheck_round_count != 6
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    let encoded_oracles = plan
        .whir
        .rounds
        .iter()
        .map(|round| round.encoded_oracle)
        .chain(std::iter::once(plan.whir.final_round.encoded_oracle))
        .collect::<Vec<_>>();
    let supplied_commitment_openings = checked_supplied_commitment_opening_rows(plan)?;
    let whir_epoch_openings = &supplied_commitment_openings.whir_epochs;
    if encoded_oracles.len() != 5 || whir_epoch_openings.len() != 5 {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    // The displayed epoch geometry is bound to the generated construction plan
    // rather than to a second hand-maintained table. The initial evaluation
    // domain is the committed dimension at the starting rate, every later epoch
    // halves that domain, and the per-epoch query counts are the plan's own
    // accepted-order opening counts. A duplicated literal table would make the
    // theorem check two authorities instead of the one the identity signs.
    let initial_evaluation_domain_size = 1_usize
        .checked_shl(
            u32::try_from(
                parameters
                    .polynomial_commitment_variable_count
                    .checked_add(parameters.starting_log_inverse_rate)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if whir_epoch_openings[0].query_count != parameters.outer_query_count {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let mut code_state_rows = Vec::with_capacity(20);
    let mut interleaved_unique_decoding_rows = Vec::with_capacity(20);
    for epoch_index in 0..encoded_oracles.len() {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let encoded_oracle = encoded_oracles[epoch_index];
        let opening = whir_epoch_openings[epoch_index];
        let expected_evaluation_count = initial_evaluation_domain_size
            .checked_shr(epoch_ordinal)
            .filter(|count| *count > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let preceding_query_count = epoch_index
            .checked_sub(1)
            .map_or(usize::MAX, |preceding_index| {
                whir_epoch_openings[preceding_index].query_count
            });
        if encoded_oracle.evaluation_count != expected_evaluation_count
            || encoded_oracle.leaf_width != parameters.logical_polynomials_per_physical_row
            || encoded_oracle
                .leaf_count
                .checked_mul(encoded_oracle.leaf_width)
                != Some(encoded_oracle.evaluation_count)
            || opening.epoch_ordinal != epoch_ordinal
            || opening.leaf_count != encoded_oracle.leaf_count
            || opening.query_count == 0
            || opening.query_count > preceding_query_count
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let dimension_shift = parameters
            .folding_factor
            .checked_mul(epoch_index)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_dimension = 1_u64
            .checked_shl(
                u32::try_from(
                    parameters
                        .polynomial_commitment_variable_count
                        .checked_sub(dimension_shift)
                        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
                )
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_domain_size = u64::try_from(encoded_oracle.evaluation_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let terminal_fold_ordinal = u32::try_from(parameters.folding_factor)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let terminal_domain_size = parent_domain_size
            .checked_shr(terminal_fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let terminal_dimension = parent_dimension
            .checked_shr(terminal_fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let terminal_unique_decoding_radius = terminal_domain_size
            .checked_sub(terminal_dimension)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
            / 2;
        let selected_error_count_at_terminal = terminal_unique_decoding_radius
            .checked_sub(1)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let selected_state_relative_distance =
            ExactFraction::new(selected_error_count_at_terminal, terminal_domain_size)?;
        for fold_ordinal in 0..=parameters.folding_factor {
            let code_state = WhirCodeStateRow::derive(
                epoch_ordinal,
                u32::try_from(fold_ordinal)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                parent_domain_size,
                parent_dimension,
                selected_state_relative_distance,
            )?;
            interleaved_unique_decoding_rows.push(InterleavedUniqueDecodingRow::derive(
                code_state,
                parameters.logical_polynomials_per_physical_row,
            )?);
            code_state_rows.push(code_state);
        }
    }

    let mut fold_rows = Vec::with_capacity(15);
    for epoch_index in 0..encoded_oracles.len() {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        for fold_index in 0..parameters.folding_factor {
            let fold_ordinal = u32::try_from(fold_index + 1)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
            let transcript_operation_ordinal = find_fold_transcript_operation(
                plan.transcript_operations(),
                epoch_ordinal,
                u32::try_from(fold_index)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )?;
            let target_state = code_state_rows
                .iter()
                .find(|row| row.epoch_ordinal == epoch_ordinal && row.fold_ordinal == fold_ordinal)
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
            fold_rows.push(WhirFoldFailureRow {
                epoch_ordinal,
                fold_ordinal,
                transcript_operation_ordinal,
                target_domain_size: target_state.domain_size,
                sumcheck_numerator: WHIR_SUMCHECK_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
                mutual_correlated_agreement_numerator: target_state.domain_size,
            });
        }
    }

    let mut shift_rows = Vec::with_capacity(plan.whir.rounds.len());
    for round in &plan.whir.rounds {
        let transcript_operation_ordinal =
            find_unique_transcript_operation(plan.transcript_operations(), |operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleExtension {
                        role: RowCodeWhirExtensionRole::RoundCombination { round_ordinal },
                        ..
                    } if *round_ordinal == round.round_ordinal
                )
            })?;
        let query_count = u64::try_from(
            whir_epoch_openings
                .get(
                    usize::try_from(round.round_ordinal)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?
                .query_count,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let list_size = 1_u64;
        shift_rows.push(WhirShiftFailureRow {
            round_ordinal: round.round_ordinal,
            transcript_operation_ordinal,
            query_count,
            list_size,
            algebraic_numerator: list_size
                .checked_mul(
                    query_count
                        .checked_add(1)
                        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        });
    }

    let final_code_state = code_state_rows
        .iter()
        .find(|row| {
            row.epoch_ordinal == 4
                && usize::try_from(row.fold_ordinal).ok() == Some(parameters.folding_factor)
        })
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let final_query_row = WhirFinalQueryRow {
        epoch_ordinal: 4,
        query_count: u64::try_from(
            whir_epoch_openings
                .last()
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?
                .query_count,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        bad_agreement: final_code_state.false_state_agreement_ceiling,
    };

    let prefix_stacking = derive_prefix_stacking_certificate(plan)?;
    let initial_constraint_batch_numerator = prefix_stacking
        .scalar_opening_count
        .checked_sub(1)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let final_sumcheck_numerator = u64::try_from(plan.whir.final_round.sumcheck_round_count)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        .checked_mul(2)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

    let catalog = plan
        .oracle_equation_catalog()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let (state_epoch_rows, oracle_equation_rows) = derive_state_and_equation_rows(&catalog)?;
    let maximum_transcript_hash_query_count = catalog
        .maximum_transcript_hash_query_count()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let logical_verifier_message_count = catalog
        .logical_verifier_message_count()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if maximum_transcript_hash_query_count != SELECTED_TRANSCRIPT_HASH_QUERY_COUNT
        || logical_verifier_message_count != SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    validate_state_and_equation_rows(&catalog, &state_epoch_rows, &oracle_equation_rows)?;
    let selected_plan_state_predicate = derive_selected_plan_state_predicate_certificate(
        plan,
        &catalog,
        &state_epoch_rows,
        &code_state_rows,
    )?;

    let transcript_equation_count = catalog
        .maximum_equation_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let complete_verifier_oracle_ledger = derive_complete_verifier_oracle_ledger(
        plan,
        transcript_equation_count,
        maximum_transcript_hash_query_count,
    )?;
    let cms19_arithmetic = derive_cms19_arithmetic_certificate(
        complete_verifier_oracle_ledger.complete_hash_query_count,
        complete_verifier_oracle_ledger.complete_equation_count_ceiling,
    );
    let cms19_state_predicate = derive_cms19_state_predicate_certificate(
        &selected_plan_state_predicate,
        plan,
        &code_state_rows,
        &interleaved_unique_decoding_rows,
    );
    let cms19_applicability = Cms19ApplicabilityCertificate {
        transform: Cms19Transform::ModifiedBcsHashChainSectionsEightTwoThroughEightFive,
        transcript_equation_count,
        transcript_hash_query_count: maximum_transcript_hash_query_count,
        claimed_complete_equation_count: complete_verifier_oracle_ledger
            .complete_equation_count_ceiling,
        claimed_complete_hash_query_count: complete_verifier_oracle_ledger
            .complete_hash_query_count,
        equation_count_without_catalog_correspondence: 0,
        hash_query_count_without_catalog_correspondence: 0,
        transcript_predecessor_support_ceiling: 2,
        complete_state_predicate_established: cms19_state_predicate.is_complete(),
        syntactic_proposition_eight_twelve_partition_catalogued: cms19_state_predicate
            .has_exact_abstract_partition(),
        proposition_eight_twelve_case_split_established: false,
        complete_query_ledger_correspondence_established: true,
        // The live expansion sampler deliberately uses one typed hash edge per
        // block. CMS19 Section 8 instead alternates a verifier-message edge
        // with a prover-root absorption edge. A catalog with no malformed or
        // branching entries does not prove those two games equivalent.
        modified_bcs_linear_hash_chain_established: false,
    };
    let undischarged_hypotheses = [
        UndischargedConstructionHypothesis::ModifiedBcsRuntimeHashChainCorrespondence,
        UndischargedConstructionHypothesis::ConstructionMaskingCorrespondence,
        UndischargedConstructionHypothesis::CommitmentSubtreeExtraction,
        UndischargedConstructionHypothesis::ExplicitPointConstraintExtractorCorrespondence,
        UndischargedConstructionHypothesis::WholePolynomialProtocolRoundByRoundExtractor,
        UndischargedConstructionHypothesis::CompilerInterpreterSemanticCorrespondence,
        UndischargedConstructionHypothesis::ExactFailureMagnitudeCorrespondence,
    ]
    .into_iter()
    .collect();

    Ok(RowCodeWhirFailurePartitionCertificate {
        code_state_rows,
        interleaved_unique_decoding_rows,
        fold_rows,
        shift_rows,
        final_query_row,
        initial_constraint_batch_numerator,
        final_sumcheck_numerator,
        prefix_stacking,
        state_epoch_rows,
        oracle_equation_rows,
        complete_verifier_oracle_ledger,
        selected_plan_state_predicate,
        cms19_state_predicate,
        maximum_transcript_hash_query_count,
        logical_verifier_message_count,
        cms19_arithmetic,
        cms19_applicability,
        undischarged_hypotheses,
    })
}

fn find_fold_transcript_operation(
    operations: &[RowCodeWhirTranscriptOperation],
    epoch_ordinal: u32,
    local_sumcheck_round_ordinal: u32,
) -> Result<u32, WhirTheoremCertificateError> {
    find_unique_transcript_operation(operations, |operation| {
        if epoch_ordinal == 0 {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::SampleExtension {
                    role: RowCodeWhirExtensionRole::InitialSumcheck { round_ordinal },
                    ..
                } if *round_ordinal == local_sumcheck_round_ordinal
            )
        } else {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::SampleExtension {
                    role: RowCodeWhirExtensionRole::RoundSumcheck {
                        round_ordinal,
                        sumcheck_round_ordinal,
                    },
                    ..
                } if *round_ordinal == epoch_ordinal - 1
                    && *sumcheck_round_ordinal == local_sumcheck_round_ordinal
            )
        }
    })
}

fn find_unique_transcript_operation(
    operations: &[RowCodeWhirTranscriptOperation],
    mut predicate: impl FnMut(&RowCodeWhirTranscriptOperation) -> bool,
) -> Result<u32, WhirTheoremCertificateError> {
    let matching = operations
        .iter()
        .enumerate()
        .filter_map(|(operation_index, operation)| predicate(operation).then_some(operation_index))
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    u32::try_from(matching[0]).map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)
}

fn derive_prefix_stacking_certificate(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<PrefixStackingCertificate, WhirTheoremCertificateError> {
    let parameters = plan.selected_parameters();
    let table_width = plan.aggregate_table_width();
    let padded_width = table_width
        .checked_next_power_of_two()
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let selector_variable_count = usize::try_from(padded_width.ilog2())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let scalar_opening_count = plan.opening_batches.iter().try_fold(
        0_u64,
        |total, batch| -> Result<u64, WhirTheoremCertificateError> {
            if batch.requested_aggregate_column_ordinals.is_empty() {
                return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
            }
            let mut requested_columns = BTreeSet::new();
            for column_ordinal in &batch.requested_aggregate_column_ordinals {
                let column_index = usize::try_from(*column_ordinal)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
                if column_index >= table_width || !requested_columns.insert(column_index) {
                    return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
                }
            }
            total
                .checked_add(
                    u64::try_from(requested_columns.len())
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        },
    )?;
    if table_width != SELECTED_AGGREGATE_TABLE_WIDTH
        || plan.opening_batches.len() != SELECTED_OPENING_BATCH_COUNT
        || scalar_opening_count != SELECTED_SCALAR_OPENING_COUNT
        || parameters
            .table_variable_count
            .checked_add(selector_variable_count)
            != Some(parameters.polynomial_commitment_variable_count)
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    for (batch_index, batch) in plan.opening_batches.iter().enumerate() {
        if usize::try_from(batch.point_ordinal).ok() != Some(batch_index) {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
    }

    let selector_indices = (0..table_width).collect::<Vec<_>>();
    let slot_size = 1_usize
        .checked_shl(
            u32::try_from(parameters.table_variable_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let stacked_size = 1_usize
        .checked_shl(
            u32::try_from(parameters.polynomial_commitment_variable_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if slot_size.checked_mul(padded_width) != Some(stacked_size)
        || selector_indices
            .iter()
            .enumerate()
            .any(|(expected, actual)| expected != *actual)
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    Ok(PrefixStackingCertificate {
        source_table_count: 1,
        committed_polynomial_count: 1,
        table_variable_count: parameters.table_variable_count,
        selector_variable_count,
        stacked_variable_count: parameters.polynomial_commitment_variable_count,
        table_width,
        opening_batch_count: plan.opening_batches.len(),
        scalar_opening_count,
        selector_indices,
    })
}

fn derive_state_and_equation_rows(
    catalog: &RowCodeWhirOracleEquationCatalog,
) -> Result<(Vec<StateEpochRow>, Vec<OracleEquationCoverageRow>), WhirTheoremCertificateError> {
    let mut state_rows = Vec::with_capacity(catalog.operations.len());
    let range_count = catalog
        .operations
        .iter()
        .try_fold(0_usize, |total, operation| {
            total
                .checked_add(operation.ranges.len())
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
    let mut equation_rows = Vec::with_capacity(range_count);
    for operation in &catalog.operations {
        let transition_owner = match &operation.kind {
            RowCodeWhirOracleEquationOperationKind::InitialTranscript => {
                StateTransitionOwner::FixedInitialState
            }
            RowCodeWhirOracleEquationOperationKind::CommonRound(_) => {
                StateTransitionOwner::ProverMessageCannotRepairFalseState
            }
            RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(_)
            | RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(_) => {
                StateTransitionOwner::VerifierChallengeWithTypedFailureEvent
            }
            RowCodeWhirOracleEquationOperationKind::RowCodeWhir { operation, .. } => {
                match operation {
                    RowCodeWhirTranscriptOperation::SampleExtension { .. }
                    | RowCodeWhirTranscriptOperation::SampleDistinctIndices { .. } => {
                        StateTransitionOwner::VerifierChallengeWithTypedFailureEvent
                    }
                    RowCodeWhirTranscriptOperation::FinishProofStream => {
                        StateTransitionOwner::TerminalDecision
                    }
                    RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. }
                    | RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. }
                    | RowCodeWhirTranscriptOperation::ObserveCommitment { .. }
                    | RowCodeWhirTranscriptOperation::ObserveExtensionValues { .. } => {
                        StateTransitionOwner::ProverMessageCannotRepairFalseState
                    }
                }
            }
        };
        state_rows.push(StateEpochRow {
            operation_ordinal: operation.operation_ordinal,
            predecessor_operation_ordinal: operation.predecessor_operation_ordinal,
            transition_owner,
            first_equation_slot_ordinal: operation.first_equation_slot_ordinal,
            equation_count: operation
                .maximum_equation_count()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        });
        for range in &operation.ranges {
            let role_pattern = match range.kind {
                RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot => {
                    OracleEquationRolePattern::Single(OracleEquationRole::InitialHeaderRoot)
                }
                RowCodeWhirOracleEquationRangeKind::InitialAbsorption => {
                    OracleEquationRolePattern::Single(OracleEquationRole::InitialAbsorption)
                }
                RowCodeWhirOracleEquationRangeKind::ResponseRoot => {
                    OracleEquationRolePattern::Single(OracleEquationRole::ResponseRoot)
                }
                RowCodeWhirOracleEquationRangeKind::ResponseBinding => {
                    OracleEquationRolePattern::Single(OracleEquationRole::ResponseBinding)
                }
                RowCodeWhirOracleEquationRangeKind::ResponseAbsorption => {
                    OracleEquationRolePattern::Single(OracleEquationRole::ResponseAbsorption)
                }
                RowCodeWhirOracleEquationRangeKind::AcceptedChallenge => {
                    OracleEquationRolePattern::Single(OracleEquationRole::AcceptedChallenge)
                }
                RowCodeWhirOracleEquationRangeKind::ChallengeHandle => {
                    OracleEquationRolePattern::Single(OracleEquationRole::ChallengeHandle)
                }
                RowCodeWhirOracleEquationRangeKind::ExtensionRejectionChain { .. } => {
                    OracleEquationRolePattern::Alternating {
                        first: OracleEquationRole::RejectedChallenge,
                        second: OracleEquationRole::ChallengeHandle,
                    }
                }
                RowCodeWhirOracleEquationRangeKind::ProductExpansion { .. }
                | RowCodeWhirOracleEquationRangeKind::DistinctExpansion { .. } => {
                    OracleEquationRolePattern::Single(OracleEquationRole::LinearExpansionBlock)
                }
            };
            if role_pattern.maximum_predecessor_support_count() > 2
                || matches!(role_pattern, OracleEquationRolePattern::Alternating { .. })
                    && !range.equation_count.is_multiple_of(2)
            {
                return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
            }
            equation_rows.push(OracleEquationCoverageRow {
                operation_ordinal: operation.operation_ordinal,
                range_ordinal: range.range_ordinal,
                first_equation_slot_ordinal: operation
                    .first_equation_slot_ordinal
                    .checked_add(range.first_equation_offset)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                equation_count: range.equation_count,
                role_pattern,
            });
        }
    }
    Ok((state_rows, equation_rows))
}

fn validate_state_and_equation_rows(
    catalog: &RowCodeWhirOracleEquationCatalog,
    state_rows: &[StateEpochRow],
    equation_rows: &[OracleEquationCoverageRow],
) -> Result<(), WhirTheoremCertificateError> {
    if state_rows.len() != catalog.operations.len()
        || state_rows.last().map(|row| row.transition_owner)
            != Some(StateTransitionOwner::TerminalDecision)
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let mut next_operation_ordinal = 0_u32;
    let mut next_equation_slot_ordinal = 0_u64;
    for state_row in state_rows {
        if state_row.operation_ordinal != next_operation_ordinal
            || state_row.predecessor_operation_ordinal != state_row.operation_ordinal.checked_sub(1)
            || state_row.first_equation_slot_ordinal != next_equation_slot_ordinal
            || state_row.equation_count == 0
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        next_operation_ordinal = next_operation_ordinal
            .checked_add(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        next_equation_slot_ordinal = next_equation_slot_ordinal
            .checked_add(state_row.equation_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    }
    let mut next_covered_equation_slot = 0_u64;
    let expected_ranges = catalog
        .operations
        .iter()
        .flat_map(|operation| {
            operation.ranges.iter().map(move |range| {
                (
                    operation.operation_ordinal,
                    range.range_ordinal,
                    operation.first_equation_slot_ordinal + range.first_equation_offset,
                    range.equation_count,
                )
            })
        })
        .collect::<Vec<_>>();
    if equation_rows.len() != expected_ranges.len() {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    for (equation_row, expected_range) in equation_rows.iter().zip(expected_ranges) {
        if equation_row.first_equation_slot_ordinal != next_covered_equation_slot
            || equation_row.equation_count == 0
            || equation_row
                .role_pattern
                .maximum_predecessor_support_count()
                > 2
            || (
                equation_row.operation_ordinal,
                equation_row.range_ordinal,
                equation_row.first_equation_slot_ordinal,
                equation_row.equation_count,
            ) != expected_range
        {
            return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
        }
        next_covered_equation_slot = next_covered_equation_slot
            .checked_add(equation_row.equation_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    }
    if next_covered_equation_slot != next_equation_slot_ordinal
        || next_covered_equation_slot
            != catalog
                .maximum_equation_count()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(())
}

fn derive_selected_plan_state_predicate_certificate(
    plan: &RowCodeWhirConstructionPlan,
    catalog: &RowCodeWhirOracleEquationCatalog,
    state_epoch_rows: &[StateEpochRow],
    code_state_rows: &[WhirCodeStateRow],
) -> Result<SelectedPlanStatePredicateCertificate, WhirTheoremCertificateError> {
    let final_epoch_ordinal = u32::try_from(plan.whir.rounds.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut transition_rows = Vec::with_capacity(catalog.operations.len());
    for operation in &catalog.operations {
        let (predicate_clause, failure_event_owner, sampler_exhaustion_is_honest_abort) =
            match &operation.kind {
                RowCodeWhirOracleEquationOperationKind::InitialTranscript => (
                    SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse,
                    None,
                    false,
                ),
                RowCodeWhirOracleEquationOperationKind::CommonRound(_) => (
                    SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove,
                    None,
                    false,
                ),
                RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(group) => {
                    if !matches!(
                        group.challenge(),
                        CommonProofChallenge::Theta { .. } | CommonProofChallenge::Alpha { .. }
                    ) {
                        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
                    }
                    (
                        SelectedPlanStatePredicateClause::PolynomialProtocolChallenge,
                        Some(SelectedPlanFailureEventOwner::CommonProductChallenge {
                            challenge: group.challenge(),
                        }),
                        true,
                    )
                }
                RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(challenge) => {
                    if !matches!(
                        challenge,
                        CommonProofChallenge::Composition { .. }
                            | CommonProofChallenge::OutOfDomainPoint { .. }
                            | CommonProofChallenge::OpeningBatch { .. }
                    ) {
                        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
                    }
                    (
                        SelectedPlanStatePredicateClause::RelationReductionChallenge,
                        Some(SelectedPlanFailureEventOwner::CommonExtensionChallenge {
                            challenge: *challenge,
                        }),
                        true,
                    )
                }
                RowCodeWhirOracleEquationOperationKind::RowCodeWhir { operation, .. } => {
                    selected_plan_row_code_whir_transition(
                        operation,
                        final_epoch_ordinal,
                        code_state_rows,
                    )?
                }
            };
        transition_rows.push(SelectedPlanStateTransitionRow {
            operation_ordinal: operation.operation_ordinal,
            predicate_clause,
            failure_event_owner,
            sampler_exhaustion_is_honest_abort,
        });
    }

    let proof_section_rows = plan
        .proof_sections()
        .iter()
        .copied()
        .map(|section| SelectedPlanProofSectionStateRow {
            section_ordinal: section.section_ordinal,
            item_count: section.item_count,
            predicate: match section.role {
                RowCodeWhirProofSectionRole::RelationCommitment { phase } => {
                    SelectedPlanProofSectionPredicate::RelationPhaseAffineSpan { phase }
                }
                RowCodeWhirProofSectionRole::OutOfDomainEvaluations => {
                    SelectedPlanProofSectionPredicate::OutOfDomainCompositionAndRegisteredClaims
                }
                RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations => {
                    SelectedPlanProofSectionPredicate::OpeningBatchMaskConsistency
                }
                RowCodeWhirProofSectionRole::AggregateCommitment => {
                    SelectedPlanProofSectionPredicate::AggregateConstrainedPolynomialCommitment
                }
                RowCodeWhirProofSectionRole::PhaseOpenings { phase } => {
                    SelectedPlanProofSectionPredicate::PhaseOpeningAuthenticationAndReduction {
                        phase,
                    }
                }
                RowCodeWhirProofSectionRole::BoundTreeOpenings { bound_tree_ordinal } => {
                    SelectedPlanProofSectionPredicate::BoundAuthenticationAndReduction {
                        bound_tree_ordinal,
                    }
                }
                RowCodeWhirProofSectionRole::PlainWhir => {
                    SelectedPlanProofSectionPredicate::ExplicitPointWhirOpening
                }
            },
        })
        .collect::<Vec<_>>();

    let checkpoint_rows = plan
        .checkpoints()
        .iter()
        .copied()
        .map(|checkpoint| SelectedPlanCheckpointStateRow {
            checkpoint_ordinal: checkpoint.checkpoint_ordinal,
            next_transcript_operation_ordinal: checkpoint.next_transcript_operation_ordinal,
            next_proof_section_ordinal: checkpoint.next_proof_section_ordinal,
            owner: match checkpoint.boundary {
                RowCodeWhirCheckpointBoundary::SourcesAndConstruction => {
                    SelectedPlanCheckpointStateOwner::AuthenticatedSourceAndConstruction
                }
                RowCodeWhirCheckpointBoundary::PhaseCommitment { phase } => {
                    SelectedPlanCheckpointStateOwner::CompletedPhaseCommitment { phase }
                }
                RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask => {
                    SelectedPlanCheckpointStateOwner::RelationEvaluationsAndMask
                }
                RowCodeWhirCheckpointBoundary::AggregateCommitmentAndQueries => {
                    SelectedPlanCheckpointStateOwner::AggregateCommitmentAndQueries
                }
                RowCodeWhirCheckpointBoundary::WhirRound { round_ordinal } => {
                    SelectedPlanCheckpointStateOwner::CompletedWhirRound { round_ordinal }
                }
                RowCodeWhirCheckpointBoundary::CompletedProofStream => {
                    SelectedPlanCheckpointStateOwner::CompletedCanonicalProof
                }
            },
        })
        .collect::<Vec<_>>();

    let lifecycle_rows = vec![
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::AuthenticatedResume,
            preserves_cryptographic_cursor: true,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::ExplicitAbort,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::Cancellation,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::SamplerExhaustion,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::MaskRankFailure,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::StorageRefusal,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::CompletedProofTransport,
            preserves_cryptographic_cursor: true,
            emits_proof: true,
            emits_verified_capability: false,
            requires_fresh_verifier: true,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::FreshVerifierAcceptance,
            preserves_cryptographic_cursor: true,
            emits_proof: false,
            emits_verified_capability: true,
            requires_fresh_verifier: true,
        },
    ];

    let certificate = SelectedPlanStatePredicateCertificate {
        transition_rows,
        proof_section_rows,
        checkpoint_rows,
        lifecycle_rows,
        canonical_prefix_required: true,
        single_semantic_witness_required: true,
        decoded_equation_consistency_required: true,
        constrained_code_state_required: true,
        accepting_suffix_required: true,
    };
    validate_selected_plan_state_predicate_certificate(
        plan,
        catalog,
        state_epoch_rows,
        code_state_rows,
        &certificate,
    )?;
    Ok(certificate)
}

fn selected_plan_row_code_whir_transition(
    operation: &RowCodeWhirTranscriptOperation,
    final_epoch_ordinal: u32,
    code_state_rows: &[WhirCodeStateRow],
) -> Result<
    (
        SelectedPlanStatePredicateClause,
        Option<SelectedPlanFailureEventOwner>,
        bool,
    ),
    WhirTheoremCertificateError,
> {
    let transition = match operation {
        RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. }
        | RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. }
        | RowCodeWhirTranscriptOperation::ObserveCommitment { .. }
        | RowCodeWhirTranscriptOperation::ObserveExtensionValues { .. } => (
            SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove,
            None,
            false,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::Direct(challenge),
            whir_challenge_ordinal: None,
        } => (
            SelectedPlanStatePredicateClause::RelationReductionChallenge,
            Some(SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: *challenge,
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::InitialOutOfDomainPoint { .. },
            whir_challenge_ordinal: Some(_),
        } => (
            SelectedPlanStatePredicateClause::WhirInitialOutOfDomain,
            Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: match operation {
                    RowCodeWhirTranscriptOperation::SampleExtension { role, .. } => *role,
                    _ => unreachable!(),
                },
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::OpeningBatching,
            whir_challenge_ordinal: Some(_),
        } => (
            SelectedPlanStatePredicateClause::WhirOpeningConstraintBatch,
            Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::OpeningBatching,
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::InitialSumcheck { round_ordinal },
            whir_challenge_ordinal: Some(_),
        } => {
            let fold_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, 0, fold_ordinal)?;
            (
                SelectedPlanStatePredicateClause::WhirConstrainedFold {
                    epoch_ordinal: 0,
                    fold_ordinal,
                },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::InitialSumcheck {
                        round_ordinal: *round_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role:
                RowCodeWhirExtensionRole::RoundOutOfDomainPoint {
                    round_ordinal,
                    sample_ordinal,
                },
            whir_challenge_ordinal: Some(_),
        } => {
            let epoch_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, epoch_ordinal, 0)?;
            (
                SelectedPlanStatePredicateClause::WhirRoundOutOfDomain {
                    epoch_ordinal,
                    sample_ordinal: *sample_ordinal,
                },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::RoundOutOfDomainPoint {
                        round_ordinal: *round_ordinal,
                        sample_ordinal: *sample_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::RoundCheckpoint { round_ordinal },
            whir_challenge_ordinal: Some(_),
        } => {
            let epoch_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, epoch_ordinal, 0)?;
            (
                SelectedPlanStatePredicateClause::WhirRoundConstraintCheckpoint { epoch_ordinal },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::RoundCheckpoint {
                        round_ordinal: *round_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::RoundCombination { round_ordinal },
            whir_challenge_ordinal: Some(_),
        } => {
            let epoch_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, epoch_ordinal, 0)?;
            (
                SelectedPlanStatePredicateClause::WhirQueryCombination { epoch_ordinal },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::RoundCombination {
                        round_ordinal: *round_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role:
                RowCodeWhirExtensionRole::RoundSumcheck {
                    round_ordinal,
                    sumcheck_round_ordinal,
                },
            whir_challenge_ordinal: Some(_),
        } => {
            let epoch_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            let fold_ordinal = sumcheck_round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, epoch_ordinal, fold_ordinal)?;
            (
                SelectedPlanStatePredicateClause::WhirConstrainedFold {
                    epoch_ordinal,
                    fold_ordinal,
                },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::RoundSumcheck {
                        round_ordinal: *round_ordinal,
                        sumcheck_round_ordinal: *sumcheck_round_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::FinalSumcheck { round_ordinal },
            whir_challenge_ordinal: Some(_),
        } => {
            require_code_state(code_state_rows, final_epoch_ordinal, 3)?;
            (
                SelectedPlanStatePredicateClause::WhirFinalSumcheck {
                    epoch_ordinal: final_epoch_ordinal,
                    round_ordinal: *round_ordinal,
                },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::FinalSumcheck {
                        round_ordinal: *round_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleDistinctIndices { role, .. } => {
            let predicate_clause = match *role {
                RowCodeWhirQueryRole::Outer => {
                    SelectedPlanStatePredicateClause::OuterRowCodeAgreement
                }
                RowCodeWhirQueryRole::Bound => {
                    SelectedPlanStatePredicateClause::BoundIdentityAgreement
                }
                RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal } => {
                    require_code_state(code_state_rows, epoch_ordinal, 3)?;
                    SelectedPlanStatePredicateClause::WhirQueryAgreement { epoch_ordinal }
                }
            };
            (
                predicate_clause,
                Some(SelectedPlanFailureEventOwner::DistinctQueryVector { role: *role }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::FinishProofStream => (
            SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts,
            None,
            false,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension { .. } => {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    };
    Ok(transition)
}

fn require_code_state(
    code_state_rows: &[WhirCodeStateRow],
    epoch_ordinal: u32,
    fold_ordinal: u32,
) -> Result<(), WhirTheoremCertificateError> {
    if code_state_rows
        .iter()
        .any(|row| row.epoch_ordinal == epoch_ordinal && row.fold_ordinal == fold_ordinal)
    {
        Ok(())
    } else {
        Err(WhirTheoremCertificateError::IncompleteTranscriptMapping)
    }
}

fn validate_selected_plan_state_predicate_certificate(
    plan: &RowCodeWhirConstructionPlan,
    catalog: &RowCodeWhirOracleEquationCatalog,
    state_epoch_rows: &[StateEpochRow],
    code_state_rows: &[WhirCodeStateRow],
    certificate: &SelectedPlanStatePredicateCertificate,
) -> Result<(), WhirTheoremCertificateError> {
    if !certificate.is_total_for_plan(plan)
        || certificate.transition_rows.len() != state_epoch_rows.len()
        || certificate
            .transition_rows
            .first()
            .map(|row| row.predicate_clause)
            != Some(SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse)
        || certificate
            .transition_rows
            .last()
            .map(|row| row.predicate_clause)
            != Some(SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts)
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    for ((transition_row, state_epoch_row), operation) in certificate
        .transition_rows
        .iter()
        .zip(state_epoch_rows)
        .zip(&catalog.operations)
    {
        if transition_row.operation_ordinal != operation.operation_ordinal
            || transition_row.operation_ordinal != state_epoch_row.operation_ordinal
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let is_verifier_challenge = state_epoch_row.transition_owner
            == StateTransitionOwner::VerifierChallengeWithTypedFailureEvent;
        if is_verifier_challenge != transition_row.failure_event_owner.is_some()
            || is_verifier_challenge != transition_row.sampler_exhaustion_is_honest_abort
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        if let Some(owner) = transition_row.failure_event_owner {
            let expected_class = match transition_row.predicate_clause {
                SelectedPlanStatePredicateClause::PolynomialProtocolChallenge => {
                    SelectedPlanFailureEventClass::PolynomialProtocolKnowledge
                }
                SelectedPlanStatePredicateClause::RelationReductionChallenge => {
                    SelectedPlanFailureEventClass::AlgebraicExceptionalSet
                }
                SelectedPlanStatePredicateClause::OuterRowCodeAgreement
                | SelectedPlanStatePredicateClause::BoundIdentityAgreement
                | SelectedPlanStatePredicateClause::WhirQueryAgreement { .. } => {
                    SelectedPlanFailureEventClass::WithoutReplacementAgreement
                }
                SelectedPlanStatePredicateClause::WhirInitialOutOfDomain
                | SelectedPlanStatePredicateClause::WhirOpeningConstraintBatch
                | SelectedPlanStatePredicateClause::WhirRoundOutOfDomain { .. }
                | SelectedPlanStatePredicateClause::WhirRoundConstraintCheckpoint { .. }
                | SelectedPlanStatePredicateClause::WhirConstrainedFold { .. }
                | SelectedPlanStatePredicateClause::WhirQueryCombination { .. }
                | SelectedPlanStatePredicateClause::WhirFinalSumcheck { .. } => {
                    SelectedPlanFailureEventClass::WhirRoundByRoundProximity
                }
                SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse
                | SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove
                | SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts => {
                    return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
                }
            };
            if owner.event_class() != expected_class {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
        }
    }

    for (section_index, row) in certificate.proof_section_rows.iter().enumerate() {
        if usize::try_from(row.section_ordinal).ok() != Some(section_index) || row.item_count == 0 {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    }
    for (checkpoint_index, row) in certificate.checkpoint_rows.iter().enumerate() {
        if usize::try_from(row.checkpoint_ordinal).ok() != Some(checkpoint_index)
            || usize::try_from(row.next_transcript_operation_ordinal)
                .ok()
                .is_none_or(|ordinal| ordinal > plan.transcript_operations().len())
            || usize::try_from(row.next_proof_section_ordinal)
                .ok()
                .is_none_or(|ordinal| ordinal > plan.proof_sections().len())
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    }
    if certificate.checkpoint_rows.last().map(|row| row.owner)
        != Some(SelectedPlanCheckpointStateOwner::CompletedCanonicalProof)
        || certificate.lifecycle_rows.iter().any(|row| {
            matches!(
                row.transition,
                SelectedPlanLifecycleTransition::ExplicitAbort
                    | SelectedPlanLifecycleTransition::Cancellation
                    | SelectedPlanLifecycleTransition::SamplerExhaustion
                    | SelectedPlanLifecycleTransition::MaskRankFailure
                    | SelectedPlanLifecycleTransition::StorageRefusal
            ) && (row.emits_proof || row.emits_verified_capability)
        })
        || certificate.lifecycle_rows.iter().any(|row| {
            row.emits_verified_capability
                && (row.transition != SelectedPlanLifecycleTransition::FreshVerifierAcceptance
                    || !row.requires_fresh_verifier)
        })
        || code_state_rows.len() != 20
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(())
}

fn checked_tree_height(leaf_count: usize) -> Result<usize, WhirTheoremCertificateError> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    usize::try_from(leaf_count.ilog2()).map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)
}

fn maximum_compact_parent_hash_query_count(
    leaf_count: usize,
    query_count: usize,
) -> Result<u64, WhirTheoremCertificateError> {
    if query_count == 0 || query_count > leaf_count {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let tree_height = checked_tree_height(leaf_count)?;
    (0..tree_height).try_fold(0_u64, |total, depth| {
        let node_count = 1_usize
            .checked_shl(
                u32::try_from(depth)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        total
            .checked_add(
                u64::try_from(query_count.min(node_count))
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })
}

fn derive_merkle_oracle_equation_rows(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<Vec<MerkleOracleEquationCoverageRow>, WhirTheoremCertificateError> {
    let supplied_commitment_openings = checked_supplied_commitment_opening_rows(plan)?;
    let mut rows = Vec::new();
    for opening in &supplied_commitment_openings.relation_phases {
        let leaf_hash_query_count = u64::try_from(opening.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count =
            maximum_compact_parent_hash_query_count(opening.leaf_count, opening.query_count)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::RelationPhase {
                phase: opening.phase,
            },
            leaf_count: opening.leaf_count,
            query_count: opening.query_count,
            leaf_hash_query_count,
            parent_hash_query_count,
            accepting_database_equation_count_ceiling: leaf_hash_query_count
                .checked_add(parent_hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            predecessor_support_ceiling: 2,
        });
    }

    for tree in &plan.bound_trees {
        let leaf_hash_query_count = u64::try_from(tree.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count =
            maximum_compact_parent_hash_query_count(tree.leaf_count, tree.query_count)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::BoundTree {
                bound_tree_ordinal: tree.bound_tree_ordinal,
            },
            leaf_count: tree.leaf_count,
            query_count: tree.query_count,
            leaf_hash_query_count,
            parent_hash_query_count,
            accepting_database_equation_count_ceiling: leaf_hash_query_count
                .checked_add(parent_hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            predecessor_support_ceiling: 2,
        });
    }

    for opening in &supplied_commitment_openings.whir_epochs {
        let tree_height = checked_tree_height(opening.leaf_count)?;
        let leaf_hash_query_count = u64::try_from(opening.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count = leaf_hash_query_count
            .checked_mul(
                u64::try_from(tree_height)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::WhirEpoch {
                epoch_ordinal: opening.epoch_ordinal,
            },
            leaf_count: opening.leaf_count,
            query_count: opening.query_count,
            leaf_hash_query_count,
            parent_hash_query_count,
            // The plain-WHIR verifier checks one complete path per distinct
            // query. Shared path nodes can reduce the measured database, so
            // the call count is a conservative exact ceiling on equations.
            accepting_database_equation_count_ceiling: leaf_hash_query_count
                .checked_add(parent_hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            predecessor_support_ceiling: 2,
        });
    }
    Ok(rows)
}

fn derive_fixed_verifier_hash_rows(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<Vec<FixedVerifierHashCoverageRow>, WhirTheoremCertificateError> {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let compiled_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?,
        &context,
    )
    .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let variant = artifact
        .compiled_plan()
        .select_variant(None, None)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let expected_plan = RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if &expected_plan != plan {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    let verifier_source_ordinals = variant
        .ordered_columns()
        .iter()
        .filter_map(|column| match column.origin() {
            RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                ..
            } => Some(*verifier_source_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    let distinct_verifier_source_ordinals = verifier_source_ordinals
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if verifier_source_ordinals.is_empty() || distinct_verifier_source_ordinals.is_empty() {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let public_setup_hash_query_count = u64::try_from(verifier_source_ordinals.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let public_setup_distinct_equation_count =
        u64::try_from(distinct_verifier_source_ordinals.len())
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;

    Ok(vec![
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::RelationPlanIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            transcript_catalog_equation_overlap_count: 0,
        },
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::RelationPlanVariantIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            transcript_catalog_equation_overlap_count: 0,
        },
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::ConstructionPlanIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            transcript_catalog_equation_overlap_count: 0,
        },
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::ApplicationStatement,
            hash_query_count: 1,
            distinct_equation_count: 1,
            transcript_catalog_equation_overlap_count: 0,
        },
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::PublicSetupVerifierSequence,
            hash_query_count: public_setup_hash_query_count,
            distinct_equation_count: public_setup_distinct_equation_count,
            transcript_catalog_equation_overlap_count: 0,
        },
    ])
}

fn derive_complete_verifier_oracle_ledger(
    plan: &RowCodeWhirConstructionPlan,
    transcript_equation_count: u64,
    transcript_hash_query_count: u64,
) -> Result<CompleteVerifierOracleLedger, WhirTheoremCertificateError> {
    let merkle_rows = derive_merkle_oracle_equation_rows(plan)?;
    let fixed_hash_rows = derive_fixed_verifier_hash_rows(plan)?;
    let provisional = CompleteVerifierOracleLedger {
        transcript_equation_count,
        transcript_hash_query_count,
        merkle_rows,
        fixed_hash_rows,
        complete_equation_count_ceiling: 0,
        complete_hash_query_count: 0,
    };
    let merkle_equation_count_ceiling =
        provisional
            .merkle_rows
            .iter()
            .try_fold(0_u64, |total, row| {
                total
                    .checked_add(row.accepting_database_equation_count_ceiling)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
            })?;
    let fixed_new_equation_count = provisional.fixed_new_equation_count()?;
    let fixed_hash_query_count = provisional.fixed_hash_query_count()?;
    let complete_equation_count_ceiling = transcript_equation_count
        .checked_add(merkle_equation_count_ceiling)
        .and_then(|count| count.checked_add(fixed_new_equation_count))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let complete_hash_query_count = transcript_hash_query_count
        .checked_add(provisional.merkle_hash_query_count()?)
        .and_then(|count| count.checked_add(fixed_hash_query_count))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    Ok(CompleteVerifierOracleLedger {
        complete_equation_count_ceiling,
        complete_hash_query_count,
        ..provisional
    })
}

fn derive_cms19_state_predicate_certificate(
    selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
    plan: &RowCodeWhirConstructionPlan,
    code_state_rows: &[WhirCodeStateRow],
    interleaved_unique_decoding_rows: &[InterleavedUniqueDecodingRow],
) -> Cms19StatePredicateCertificate {
    let selected_plan_state_is_total = selected_plan_state_predicate.is_total_for_plan(plan);
    let selected_geometry_is_strict = code_state_rows.len() == 20
        && code_state_rows.iter().all(|row| {
            row.selected_state_relative_distance
                .less_than(row.theorem_five_two_strict_distance_ceiling)
                .unwrap_or(false)
                && row
                    .selected_state_relative_distance
                    .less_than(row.corollary_four_eleven_proximity_bound)
                    .unwrap_or(false)
                && row.false_state_minimum_error_count <= row.unique_decoding_radius
                && row.unique_decoding_radius.saturating_mul(2) < row.minimum_distance
                && row.unique_decoding_list_size_ceiling == 1
        });
    let interleaved_distance_is_exact = interleaved_unique_decoding_rows.len() == 20
        && interleaved_unique_decoding_rows.iter().all(|row| {
            row.lane_count == plan.parameters.logical_polynomials_per_physical_row
                && row.constituent_minimum_distance == row.interleaved_minimum_distance
                && row.selected_state_error_count_ceiling
                    < (row.interleaved_minimum_distance - 1) / 2
                && row.unique_decoding_list_size_ceiling == 1
                && row.lower_bound_uses_nonzero_component
                && row.upper_bound_uses_one_nonzero_component
        });
    let requirements = [
        (
            StatePredicateRequirement::ModifiedBcsRuntimeHashChainCorrespondence,
            StatePredicateDischargeAuthority::MissingModifiedBcsRuntimeHashChainCorrespondence,
            false,
        ),
        (
            StatePredicateRequirement::CanonicalPlanCursorCoverage,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::EmptyTranscriptIsFalse,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::ProverMoveCannotRepairFalseState,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::FullFalseTranscriptIsRejected,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::EveryVerifierChallengeHasOneTypedFailureOwner,
            StatePredicateDischargeAuthority::GeneratedFailureOwnerPartition,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::EveryProofSectionHasOnePredicateOwner,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::EveryCheckpointHasOneStateOwner,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::LifecycleNonAcceptanceAndFreshVerification,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::SelectedUniqueDecodingInequalitiesHold,
            StatePredicateDischargeAuthority::CheckedConstructionGeometry,
            selected_geometry_is_strict,
        ),
        (
            StatePredicateRequirement::InterleavedDistanceAndListSizeHold,
            StatePredicateDischargeAuthority::CheckedInterleavedDistanceLemma,
            interleaved_distance_is_exact,
        ),
        (
            StatePredicateRequirement::ExplicitUniqueDecoderExists,
            StatePredicateDischargeAuthority::ExplicitBerlekampWelchExtractor,
            selected_geometry_is_strict && interleaved_distance_is_exact,
        ),
        (
            StatePredicateRequirement::ExtractCompleteRelationPhaseCodewords,
            StatePredicateDischargeAuthority::MissingTypedAcceptingDatabaseExtractor,
            false,
        ),
        (
            StatePredicateRequirement::ExtractCompleteBoundCodewords,
            StatePredicateDischargeAuthority::MissingTypedAcceptingDatabaseExtractor,
            false,
        ),
        (
            StatePredicateRequirement::ExtractCompleteWhirEpochCodewords,
            StatePredicateDischargeAuthority::MissingTypedAcceptingDatabaseExtractor,
            false,
        ),
        (
            StatePredicateRequirement::ExplicitPointConstraintExtractorCorrespondence,
            StatePredicateDischargeAuthority::MissingExplicitPointExtractorCorrespondence,
            false,
        ),
        (
            StatePredicateRequirement::ExtractThetaAndPhaseReductions,
            StatePredicateDischargeAuthority::MissingWholeRelationExtractor,
            false,
        ),
        (
            StatePredicateRequirement::ExactFailureMagnitudeCorrespondence,
            StatePredicateDischargeAuthority::MissingExactFailureMagnitudeCorrespondence,
            false,
        ),
        (
            StatePredicateRequirement::ExtractCompilerInterpreterRelationWitness,
            StatePredicateDischargeAuthority::MissingWholeRelationExtractor,
            false,
        ),
    ]
    .into_iter()
    .map(
        |(requirement, discharge_authority, is_discharged)| StatePredicateRequirementRow {
            requirement,
            discharge_authority,
            is_discharged,
        },
    )
    .collect();
    let proposition_eight_twelve_partition = vec![
        PropositionEightTwelvePartitionCase::AcceptingDatabaseContainsCollision,
        PropositionEightTwelvePartitionCase::CollisionFreeAcceptingDatabaseYieldsFullTranscript,
        PropositionEightTwelvePartitionCase::EarliestFalseToTrueVerifierStateTransition,
    ];
    Cms19StatePredicateCertificate {
        requirements,
        proposition_eight_twelve_partition,
        transcript_incompatibility_count: 0,
    }
}

fn derive_cms19_arithmetic_certificate(
    verifier_hash_query_count: u64,
    accepting_database_equation_count: u64,
) -> Cms19ArithmeticCertificate {
    let adversarial_query_bound =
        (BigUint::from(1_u8) << CMS19_ADVERSARIAL_QUERY_EXPONENT) - BigUint::from(1_u8);
    let compiler_query_bound = &adversarial_query_bound + BigUint::from(verifier_hash_query_count);
    let classical_soundness_multiplier =
        BigUint::from(12_u8) * &compiler_query_bound * &compiler_query_bound;
    let ideal_oracle_penalty_numerator = BigUint::from(48_u8)
        * &compiler_query_bound
        * &compiler_query_bound
        * &compiler_query_bound
        + BigUint::from(2_u8) * BigUint::from(accepting_database_equation_count);
    Cms19ArithmeticCertificate {
        adversarial_query_bound,
        verifier_hash_query_count,
        accepting_database_equation_count,
        compiler_query_bound,
        classical_soundness_multiplier,
        ideal_oracle_penalty_numerator,
        ideal_oracle_penalty_denominator_bit_length: CMS19_ORACLE_OUTPUT_BIT_LENGTH,
    }
}

fn selected_same_secret_construction_plan() -> RowCodeWhirConstructionPlan {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected same-secret context exists");
    let compiled_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .expect("the selected same-secret relation input derives"),
        &context,
    )
    .expect("the selected same-secret relation compiles");
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
        .expect("the selected same-secret relation validates");
    RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
        .expect("the selected same-secret construction plan derives")
}

#[test]
fn generated_selected_whir_failure_partition_is_exact_and_mutation_sensitive() {
    let plan = selected_same_secret_construction_plan();
    let certificate = checked_row_code_whir_failure_partition(&plan)
        .expect("the checked WHIR theorem certificate derives");

    assert_eq!(certificate.code_state_rows.len(), 20);
    assert_eq!(certificate.fold_rows.len(), 15);
    assert_eq!(certificate.shift_rows.len(), 4);
    assert_eq!(
        certificate
            .fold_rows
            .chunks(3)
            .map(|rows| {
                rows.iter().try_fold(0_u64, |total, row| {
                    total.checked_add(row.total_numerator().expect("row numerator"))
                })
            })
            .collect::<Option<Vec<_>>>(),
        Some(vec![7_340_041, 3_670_025, 1_835_017, 917_513, 458_761]),
    );
    assert_eq!(certificate.fold_numerator(), Ok(14_221_357));
    assert_eq!(
        certificate
            .shift_rows
            .iter()
            .map(|row| row.algebraic_numerator)
            .collect::<Vec<_>>(),
        [388, 289, 269, 265],
    );
    assert_eq!(certificate.shift_numerator(), Ok(1_211));
    assert_eq!(certificate.initial_constraint_batch_numerator(), 1_781);
    assert_eq!(certificate.final_sumcheck_numerator(), 12);
    assert_eq!(certificate.final_query_row.epoch_ordinal, 4);
    assert_eq!(certificate.final_query_row.query_count, 263);
    // The terminal fold state has domain `65,536` and dimension `64`, so its
    // unique-decoding radius is `32,736` and its selected error ceiling is
    // `32,735`. A false word therefore carries at least `32,736` errors and
    // agrees on at most `65,536 - 32,736 = 32,800` positions, which is
    // `1,025 / 2,048` in lowest terms. Charging `32,801` would credit a false
    // word with one more agreeing position than the strict inequality allows.
    assert_eq!(
        certificate.final_query_row.bad_agreement,
        ExactFraction::new(1_025, 2_048).expect("the fraction is valid"),
    );
    assert_eq!(certificate.prefix_stacking.source_table_count, 1);
    assert_eq!(certificate.prefix_stacking.committed_polynomial_count, 1);
    assert_eq!(certificate.prefix_stacking.table_variable_count, 19);
    assert_eq!(certificate.prefix_stacking.selector_variable_count, 2);
    assert_eq!(certificate.prefix_stacking.stacked_variable_count, 21);
    assert_eq!(certificate.prefix_stacking.table_width, 4);
    assert_eq!(certificate.prefix_stacking.opening_batch_count, 1_008);
    assert_eq!(certificate.prefix_stacking.scalar_opening_count, 1_782);
    assert_eq!(certificate.prefix_stacking.selector_indices, [0, 1, 2, 3]);
    assert!(certificate.code_state_rows.iter().all(|row| {
        row.domain_size > row.dimension
            && row.minimum_distance == row.domain_size - row.dimension + 1
            && row.unique_decoding_radius * 2 < row.minimum_distance
            && row.selected_state_error_count_ceiling < row.unique_decoding_radius
            && row
                .selected_state_relative_distance
                .less_than(row.theorem_five_two_strict_distance_ceiling)
                .expect("the selected radius is strictly inside the theorem interval")
            && row.reed_solomon_rate.numerator > 0
            && row.reed_solomon_rate.denominator > 0
            && row.false_state_minimum_error_count == row.selected_state_error_count_ceiling + 1
            && row.false_state_agreement_ceiling
                == ExactFraction::new(
                    row.domain_size - row.false_state_minimum_error_count,
                    row.domain_size,
                )
                .expect("the false-state agreement ceiling derives")
            && row.unique_decoding_list_size_ceiling == 1
    }));
    assert_eq!(
        certificate
            .fold_rows
            .iter()
            .map(|row| (row.epoch_ordinal, row.fold_ordinal))
            .collect::<Vec<_>>(),
        (0_u32..5)
            .flat_map(|epoch_ordinal| {
                (1_u32..=3).map(move |fold_ordinal| (epoch_ordinal, fold_ordinal))
            })
            .collect::<Vec<_>>(),
    );
    assert!(certificate.fold_rows.iter().all(|row| {
        row.transcript_operation_ordinal > 0
            && row.target_domain_size == row.mutual_correlated_agreement_numerator
            && row.sumcheck_numerator == 3
    }));
    assert!(certificate.shift_rows.iter().all(|row| {
        row.transcript_operation_ordinal > 0
            && row.list_size == 1
            && row.algebraic_numerator == row.query_count + 1
    }));
    assert_eq!(
        certificate
            .shift_rows
            .iter()
            .map(|row| row.round_ordinal)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3],
    );
    assert_eq!(
        certificate.maximum_transcript_hash_query_count,
        SELECTED_TRANSCRIPT_HASH_QUERY_COUNT,
    );
    assert_eq!(
        certificate.logical_verifier_message_count,
        SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT,
    );
    let verifier_ledger = &certificate.complete_verifier_oracle_ledger;
    assert_eq!(verifier_ledger.transcript_equation_count, 1_337_380);
    assert_eq!(verifier_ledger.transcript_hash_query_count, 1_337_380);
    assert_eq!(verifier_ledger.merkle_rows.len(), 19);
    assert_eq!(
        verifier_ledger.merkle_rows[..3]
            .iter()
            .map(|row| (row.role, row.leaf_count, row.query_count))
            .collect::<Vec<_>>(),
        [
            (
                MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Base,
                },
                2_097_152,
                387,
            ),
            (
                MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Auxiliary,
                },
                2_097_152,
                387,
            ),
            (
                MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Quotient,
                },
                2_097_152,
                387,
            ),
        ],
    );
    assert_eq!(
        verifier_ledger.merkle_rows[14..]
            .iter()
            .map(|row| (row.role, row.leaf_count, row.query_count))
            .collect::<Vec<_>>(),
        [
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 },
                1_048_576,
                387,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 1 },
                524_288,
                288,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 2 },
                262_144,
                268,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 3 },
                131_072,
                264,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 4 },
                65_536,
                263,
            ),
        ],
    );
    assert!(
        verifier_ledger
            .merkle_rows
            .iter()
            .all(|row| row.predecessor_support_ceiling <= 2)
    );
    assert_eq!(verifier_ledger.merkle_hash_query_count(), Ok(61_241));
    assert_eq!(
        verifier_ledger.merkle_rows[..3]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("phase row count"))
            }),
        Some(16_626),
    );
    assert_eq!(
        verifier_ledger.merkle_rows[3..14]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("bound row count"))
            }),
        Some(16_413),
    );
    assert_eq!(
        verifier_ledger.merkle_rows[14..]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("WHIR row count"))
            }),
        Some(28_202),
    );
    assert_eq!(verifier_ledger.fixed_hash_rows.len(), 5);
    assert_eq!(verifier_ledger.fixed_hash_query_count(), Ok(22));
    assert_eq!(verifier_ledger.fixed_distinct_equation_count(), Ok(13));
    assert_eq!(verifier_ledger.fixed_new_equation_count(), Ok(13));
    assert!(
        verifier_ledger
            .fixed_hash_rows
            .iter()
            .all(|row| row.transcript_catalog_equation_overlap_count == 0),
    );
    // Both complete ceilings are the transcript ceiling plus the plan's Merkle
    // ceiling of `61,241` plus the fixed rows: `1,337,380 + 61,241 + 13 =
    // 1,398,634` equations and `1,337,380 + 61,241 + 22 = 1,398,643` hash
    // queries. The Merkle and fixed components are independent of the
    // transcript catalog, and the two totals now differ only by the fixed
    // distinct-equation and hash-query rows because the catalog charges one
    // equation per hash query.
    assert_eq!(verifier_ledger.complete_equation_count_ceiling, 1_398_634);
    assert_eq!(verifier_ledger.complete_hash_query_count, 1_398_643);
    // The compiler query ceiling is the full adversarial budget plus every
    // verifier hash query on an accepting path, so it moves with the transcript
    // ceiling rather than being pinned independently.
    assert_eq!(
        certificate.cms19_arithmetic.compiler_query_bound,
        ((BigUint::from(1_u8) << 80_usize) - BigUint::from(1_u8))
            + BigUint::from(verifier_ledger.complete_hash_query_count),
    );
    assert_eq!(
        certificate.cms19_arithmetic.adversarial_query_bound,
        (BigUint::from(1_u8) << 80_usize) - BigUint::from(1_u8),
    );
    assert_eq!(
        certificate.cms19_arithmetic.verifier_hash_query_count,
        1_398_643
    );
    assert_eq!(
        certificate
            .cms19_arithmetic
            .accepting_database_equation_count,
        verifier_ledger.complete_equation_count_ceiling,
    );
    assert_eq!(
        certificate.cms19_arithmetic.classical_soundness_multiplier,
        BigUint::from(12_u8)
            * &certificate.cms19_arithmetic.compiler_query_bound
            * &certificate.cms19_arithmetic.compiler_query_bound,
    );
    assert_eq!(
        certificate.cms19_arithmetic.ideal_oracle_penalty_numerator,
        BigUint::from(48_u8)
            * &certificate.cms19_arithmetic.compiler_query_bound
            * &certificate.cms19_arithmetic.compiler_query_bound
            * &certificate.cms19_arithmetic.compiler_query_bound
            + BigUint::from(2_u8) * BigUint::from(verifier_ledger.complete_equation_count_ceiling),
    );
    assert_eq!(
        certificate
            .cms19_arithmetic
            .ideal_oracle_penalty_denominator_bit_length,
        512,
    );
    assert_eq!(
        certificate.cms19_applicability.transform,
        Cms19Transform::ModifiedBcsHashChainSectionsEightTwoThroughEightFive,
    );
    assert_eq!(
        certificate.cms19_applicability.transcript_equation_count,
        SELECTED_TRANSCRIPT_HASH_QUERY_COUNT,
    );
    assert_eq!(
        certificate.cms19_applicability.transcript_hash_query_count,
        SELECTED_TRANSCRIPT_HASH_QUERY_COUNT,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .claimed_complete_equation_count,
        verifier_ledger.complete_equation_count_ceiling,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .claimed_complete_hash_query_count,
        verifier_ledger.complete_hash_query_count,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .equation_count_without_catalog_correspondence,
        0,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .hash_query_count_without_catalog_correspondence,
        0,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .transcript_predecessor_support_ceiling,
        2,
    );
    assert!(
        !certificate
            .cms19_applicability
            .complete_state_predicate_established
    );
    assert!(
        certificate
            .cms19_applicability
            .syntactic_proposition_eight_twelve_partition_catalogued
    );
    assert!(
        !certificate
            .cms19_applicability
            .proposition_eight_twelve_case_split_established
    );
    assert!(
        certificate
            .cms19_applicability
            .complete_query_ledger_correspondence_established
    );
    assert!(
        !certificate
            .cms19_applicability
            .modified_bcs_linear_hash_chain_established
    );
    assert!(
        certificate
            .cms19_state_predicate
            .has_exact_abstract_partition()
    );
    assert_eq!(
        certificate
            .cms19_state_predicate
            .transcript_incompatibility_count,
        0,
    );
    assert_eq!(certificate.cms19_state_predicate.requirements.len(), 19);
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement == StatePredicateRequirement::SelectedUniqueDecodingInequalitiesHold
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::CheckedConstructionGeometry
                    && row.is_discharged
            }),
    );
    assert!(!certificate.cms19_state_predicate.is_complete());
    assert_eq!(certificate.undischarged_hypotheses.len(), 7);
    assert!(!certificate.is_complete_construction_theorem());

    let mut changed_query_plan = plan.clone();
    changed_query_plan.whir.rounds[0].query_epoch.query_count -= 1;
    assert_eq!(
        checked_row_code_whir_failure_partition(&changed_query_plan),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
    );

    let mut changed_fold_plan = plan.clone();
    changed_fold_plan.whir.rounds[0]
        .encoded_oracle
        .evaluation_count /= 2;
    assert_eq!(
        checked_row_code_whir_failure_partition(&changed_fold_plan),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
    );

    let mut changed_opening_plan = plan.clone();
    changed_opening_plan.opening_batches[0]
        .requested_aggregate_column_ordinals
        .push(0);
    assert_eq!(
        checked_row_code_whir_failure_partition(&changed_opening_plan),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
    );

    let mut missing_equation_row = certificate.oracle_equation_rows.clone();
    missing_equation_row.remove(1);
    assert_eq!(
        validate_state_and_equation_rows(
            &plan.oracle_equation_catalog().expect("the catalog derives"),
            &certificate.state_epoch_rows,
            &missing_equation_row,
        ),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );
}

#[test]
fn independent_unique_decoder_and_explicit_constraint_filter_cover_hostile_words() {
    const MODULUS: u64 = 97;
    const DIMENSION: usize = 4;
    const DOMAIN_SIZE: usize = 12;
    const RADIUS: usize = (DOMAIN_SIZE - DIMENSION) / 2;

    let polynomial = [7_u64, 11, 3, 9];
    let evaluation_points = (1..=DOMAIN_SIZE)
        .map(|point| u64::try_from(point).expect("small point fits u64"))
        .collect::<Vec<_>>();
    let codeword = evaluation_points
        .iter()
        .map(|point| polynomial_evaluation(&polynomial, *point, MODULUS))
        .collect::<Vec<_>>();

    for error_count in [0_usize, 1, RADIUS] {
        let mut received = codeword.clone();
        for error_ordinal in 0..error_count {
            received[error_ordinal] = (received[error_ordinal]
                + u64::try_from(error_ordinal + 1).expect("error fits u64"))
                % MODULUS;
        }
        let decoded = berlekamp_welch_unique_decode(
            &evaluation_points,
            &received,
            DIMENSION,
            RADIUS,
            MODULUS,
            |candidate| candidate == polynomial,
        )
        .expect("every word within the selected radius uniquely decodes");
        assert_eq!(decoded, polynomial);
    }

    let explicit_point = 17_u64;
    let genuine_terminal = polynomial_evaluation(&polynomial, explicit_point, MODULUS);
    let false_terminal = (genuine_terminal + 1) % MODULUS;
    assert!(
        berlekamp_welch_unique_decode(
            &evaluation_points,
            &codeword,
            DIMENSION,
            RADIUS,
            MODULUS,
            |candidate| polynomial_evaluation(candidate, explicit_point, MODULUS) == false_terminal,
        )
        .is_none(),
        "valid Boolean-domain authentication cannot self-authenticate a false explicit-point value",
    );

    let mut beyond_radius = codeword;
    for error_ordinal in 0..=RADIUS {
        beyond_radius[error_ordinal] = (beyond_radius[error_ordinal]
            + u64::try_from(error_ordinal + 1).expect("error fits u64"))
            % MODULUS;
    }
    assert!(
        berlekamp_welch_unique_decode(
            &evaluation_points,
            &beyond_radius,
            DIMENSION,
            RADIUS,
            MODULUS,
            |candidate| candidate == polynomial,
        )
        .is_none(),
    );
}

fn berlekamp_welch_unique_decode(
    evaluation_points: &[u64],
    received_values: &[u64],
    dimension: usize,
    radius: usize,
    modulus: u64,
    constraint_filter: impl Fn(&[u64]) -> bool,
) -> Option<Vec<u64>> {
    if evaluation_points.len() != received_values.len()
        || evaluation_points.len() != dimension.checked_add(radius.checked_mul(2)?)?
        || dimension == 0
        || modulus < 3
    {
        return None;
    }
    let quotient_coefficient_count = dimension.checked_add(radius)?;
    let locator_coefficient_count = radius.checked_add(1)?;
    let unknown_count = quotient_coefficient_count.checked_add(locator_coefficient_count)?;
    let mut matrix = Vec::with_capacity(evaluation_points.len());
    for (&point, &received) in evaluation_points.iter().zip(received_values) {
        let mut row = vec![0_u64; unknown_count];
        let mut power = 1_u64;
        for entry in &mut row[..quotient_coefficient_count] {
            *entry = power;
            power = modular_multiply(power, point, modulus);
        }
        power = 1;
        for entry in &mut row[quotient_coefficient_count..] {
            *entry = modular_negate(modular_multiply(received, power, modulus), modulus);
            power = modular_multiply(power, point, modulus);
        }
        matrix.push(row);
    }
    let solution = homogeneous_nullspace_vector(matrix, modulus)?;
    let quotient_polynomial = solution[..quotient_coefficient_count].to_vec();
    let locator_polynomial = solution[quotient_coefficient_count..].to_vec();
    let mut decoded = exact_polynomial_division(quotient_polynomial, locator_polynomial, modulus)?;
    trim_polynomial(&mut decoded);
    if decoded.len() > dimension {
        return None;
    }
    decoded.resize(dimension, 0);
    let disagreement_count = evaluation_points
        .iter()
        .zip(received_values)
        .filter(|(point, received)| polynomial_evaluation(&decoded, **point, modulus) != **received)
        .count();
    (disagreement_count <= radius && constraint_filter(&decoded)).then_some(decoded)
}

fn homogeneous_nullspace_vector(mut matrix: Vec<Vec<u64>>, modulus: u64) -> Option<Vec<u64>> {
    let row_count = matrix.len();
    let column_count = matrix.first()?.len();
    if matrix.iter().any(|row| row.len() != column_count) {
        return None;
    }
    let mut pivot_columns = Vec::new();
    let mut pivot_row = 0_usize;
    for column in 0..column_count {
        let source_row = (pivot_row..row_count).find(|row| matrix[*row][column] != 0);
        let Some(source_row) = source_row else {
            continue;
        };
        matrix.swap(pivot_row, source_row);
        let inverse = modular_inverse(matrix[pivot_row][column], modulus)?;
        for entry in &mut matrix[pivot_row] {
            *entry = modular_multiply(*entry, inverse, modulus);
        }
        for row in 0..row_count {
            if row == pivot_row || matrix[row][column] == 0 {
                continue;
            }
            let factor = matrix[row][column];
            for entry_index in column..column_count {
                let subtraction = modular_multiply(factor, matrix[pivot_row][entry_index], modulus);
                matrix[row][entry_index] =
                    modular_subtract(matrix[row][entry_index], subtraction, modulus);
            }
        }
        pivot_columns.push(column);
        pivot_row += 1;
        if pivot_row == row_count {
            break;
        }
    }
    let pivot_set = pivot_columns.iter().copied().collect::<BTreeSet<_>>();
    let free_column = (0..column_count).find(|column| !pivot_set.contains(column))?;
    let mut solution = vec![0_u64; column_count];
    solution[free_column] = 1;
    for (row, pivot_column) in pivot_columns.iter().copied().enumerate().rev() {
        let accumulated = ((pivot_column + 1)..column_count).fold(0_u64, |sum, column| {
            (sum + modular_multiply(matrix[row][column], solution[column], modulus)) % modulus
        });
        solution[pivot_column] = modular_negate(accumulated, modulus);
    }
    solution.iter().any(|entry| *entry != 0).then_some(solution)
}

fn exact_polynomial_division(
    mut numerator: Vec<u64>,
    mut denominator: Vec<u64>,
    modulus: u64,
) -> Option<Vec<u64>> {
    trim_polynomial(&mut numerator);
    trim_polynomial(&mut denominator);
    if denominator.is_empty() {
        return None;
    }
    if numerator.len() < denominator.len() {
        return numerator.is_empty().then(Vec::new);
    }
    let mut quotient = vec![0_u64; numerator.len() - denominator.len() + 1];
    let denominator_lead_inverse = modular_inverse(*denominator.last()?, modulus)?;
    while !numerator.is_empty() && numerator.len() >= denominator.len() {
        let degree_difference = numerator.len() - denominator.len();
        let factor = modular_multiply(*numerator.last()?, denominator_lead_inverse, modulus);
        quotient[degree_difference] = factor;
        for (denominator_index, denominator_coefficient) in denominator.iter().enumerate() {
            let numerator_index = degree_difference + denominator_index;
            numerator[numerator_index] = modular_subtract(
                numerator[numerator_index],
                modular_multiply(factor, *denominator_coefficient, modulus),
                modulus,
            );
        }
        trim_polynomial(&mut numerator);
    }
    numerator.is_empty().then_some(quotient)
}

fn trim_polynomial(polynomial: &mut Vec<u64>) {
    while polynomial.last() == Some(&0) {
        polynomial.pop();
    }
}

fn polynomial_evaluation(polynomial: &[u64], point: u64, modulus: u64) -> u64 {
    polynomial
        .iter()
        .rev()
        .fold(0_u64, |accumulated, coefficient| {
            (modular_multiply(accumulated, point, modulus) + *coefficient) % modulus
        })
}

fn modular_multiply(left: u64, right: u64, modulus: u64) -> u64 {
    u64::try_from((u128::from(left) * u128::from(right)) % u128::from(modulus))
        .expect("a modular product fits u64")
}

fn modular_subtract(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        modulus - (right - left)
    }
}

fn modular_negate(value: u64, modulus: u64) -> u64 {
    if value == 0 { 0 } else { modulus - value }
}

fn modular_inverse(value: u64, modulus: u64) -> Option<u64> {
    if value == 0 {
        return None;
    }
    let mut exponent = modulus.checked_sub(2)?;
    let mut base = value;
    let mut result = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = modular_multiply(result, base, modulus);
        }
        base = modular_multiply(base, base, modulus);
        exponent >>= 1;
    }
    (modular_multiply(value, result, modulus) == 1).then_some(result)
}
