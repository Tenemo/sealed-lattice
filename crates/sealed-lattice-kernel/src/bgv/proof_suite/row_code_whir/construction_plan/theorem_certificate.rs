//! Executable parameter and failure-partition certificate for the checked
//! row-code WHIR construction.
//!
//! The certificate derives its rows from the production construction plan. It
//! deliberately keeps arithmetic discharge separate from cryptographic
//! assumptions while binding every finite theorem row to the live plan.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::shared_query_partition::{SharedQueryEventClass, selected_shared_query_partition};
use super::*;
use crate::bgv::proof_suite::relation_plan::{
    RelationCompilerInterpreterSemanticCertificate, checked_relation_compiler_interpreter_semantics,
};
use crate::bgv::proof_suite::row_code_whir::{
    ColumnStreamableLeafHasher,
    aggregate_wide_hiding::AggregateWideMaskingCertificate,
    exact_same_secret::{
        ExactExtractorCorrespondenceFault, ExactPointConstraintExtractorCertificate,
        ExactPolynomialProtocolExtractorCertificate,
        checked_exact_same_secret_extractor_correspondence,
        checked_exact_same_secret_extractor_correspondence_with_fault,
    },
};
use crate::bgv::proof_suite::{
    ConstructionMaskingCertificate, PROOF_CHALLENGE_EXTENSION_DEGREE,
    ValidatedRelationPlanArtifact, checked_zero_knowledge_mask_image,
    compile_same_secret_relation_plan, selected_same_secret_relation_plan_input,
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
/// response roots                       2,059      =     2,059
/// response bindings                    2,034      =     2,034
/// response absorptions                 2,071      =     2,071
/// accepted challenges                  4,272 * 1  =     4,272
/// challenge handles                    4,272 * 1  =     4,272
/// extension rejection chains   4,260 * 2 * 127    = 1,082,040
/// product expansions               3 * 128 * 1    =       384
/// distinct expansions
///     (2*387 + 393 + 288 + 268 + 266 + 264 + 2*263) * 16
///                                                    =    44,464
/// total                                             1,141,598
/// ~~~
///
/// The `4,272` accepted challenges partition as `4,260` extension challenges
/// plus `9` distinct-index samplers plus `3` product-space samplers, which is
/// also the logical verifier-message count below. The distinct-sampler row
/// carries `266` accepted direct-bound draws once; the prior-certificate subset
/// selects its first `40` in accepted order and therefore draws nothing extra.
const SELECTED_TRANSCRIPT_HASH_QUERY_COUNT: u64 = 1_141_598;
const SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT: u64 = 4_272;
const CMS19_ADVERSARIAL_QUERY_EXPONENT: usize = 80;
const CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum WhirTheoremCertificateError {
    ArithmeticOverflow,
    InvalidSelectedGeometry,
    IncompleteTranscriptMapping,
    IncompleteOracleEquationMapping,
    IncompleteMaskingCorrespondence,
    IncompleteRelationSemanticCorrespondence,
    IncompletePolynomialExtractorCorrespondence,
    IncompleteFailureMagnitudeCorrespondence,
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

/// A reduced nonnegative rational used for the complete finite soundness
/// calculation. The query products are thousands of bits wide, so a machine
/// integer fraction would silently turn the theorem check into an estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactBigFraction {
    numerator: BigUint,
    denominator: BigUint,
}

impl ExactBigFraction {
    fn new(numerator: BigUint, denominator: BigUint) -> Result<Self, WhirTheoremCertificateError> {
        if denominator.is_zero() {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let divisor = greatest_common_divisor_big(numerator.clone(), denominator.clone());
        Ok(Self {
            numerator: numerator / &divisor,
            denominator: denominator / divisor,
        })
    }

    fn from_u64(numerator: u64, denominator: u64) -> Result<Self, WhirTheoremCertificateError> {
        Self::new(BigUint::from(numerator), BigUint::from(denominator))
    }

    fn zero() -> Self {
        Self {
            numerator: BigUint::zero(),
            denominator: BigUint::one(),
        }
    }

    fn add(&self, right: &Self) -> Result<Self, WhirTheoremCertificateError> {
        let common_divisor =
            greatest_common_divisor_big(self.denominator.clone(), right.denominator.clone());
        let left_scale = &right.denominator / &common_divisor;
        let right_scale = &self.denominator / &common_divisor;
        Self::new(
            &self.numerator * &left_scale + &right.numerator * &right_scale,
            &self.denominator * left_scale,
        )
    }

    fn multiply_integer(&self, factor: &BigUint) -> Result<Self, WhirTheoremCertificateError> {
        Self::new(&self.numerator * factor, self.denominator.clone())
    }

    fn multiply_u64(&self, factor: u64) -> Result<Self, WhirTheoremCertificateError> {
        self.multiply_integer(&BigUint::from(factor))
    }

    fn power(&self, exponent: u32) -> Result<Self, WhirTheoremCertificateError> {
        Self::new(self.numerator.pow(exponent), self.denominator.pow(exponent))
    }

    fn less_than_or_equal(&self, right: &Self) -> bool {
        &self.numerator * &right.denominator <= &right.numerator * &self.denominator
    }

    fn less_than(&self, right: &Self) -> bool {
        &self.numerator * &right.denominator < &right.numerator * &self.denominator
    }

    fn is_at_most_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.numerator << exponent) <= self.denominator
    }

    fn is_greater_than_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.numerator << exponent) > self.denominator
    }
}

fn greatest_common_divisor_big(mut left: BigUint, mut right: BigUint) -> BigUint {
    while !right.is_zero() {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

fn falling_factorial(
    population: u64,
    draw_count: u64,
) -> Result<BigUint, WhirTheoremCertificateError> {
    if draw_count > population {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    Ok((0..draw_count)
        .map(|draw_ordinal| BigUint::from(population - draw_ordinal))
        .product())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ExactFailureOwnerKind {
    NonNativeThetaProduct,
    NonNativeAlphaProduct,
    RelationComposition,
    OutOfDomainPoint,
    PointSelector,
    TraceColumnGroup,
    QuotientGroup,
    OpeningBatchMask,
    BoundOpening,
    BoundDegreeCoordinate,
    OuterQueryVector,
    BoundQueryVector,
    WhirQueryVector,
    WhirOpeningBatching,
    MaskedSumcheckEpsilon,
    MaskedSumcheckFold,
    RoundCheckpoint,
    RoundCombination,
    BaseCaseBlinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactFailureOwnerRow {
    kind: ExactFailureOwnerKind,
    transition_count: usize,
    expected_transition_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactQueryFailureEvent {
    OuterOpeningPointWords,
    RelationPhaseColumns,
    BoundTreeWords,
    StatementRootWords,
    WhirSource { epoch_ordinal: u32 },
    AggregateWidePad,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactQueryFailureRow {
    event: ExactQueryFailureEvent,
    sponsoring_owner: ExactFailureOwnerKind,
    logical_word_count: usize,
    population: u64,
    agreement_ceiling: u64,
    query_count: u64,
    charged_term_count: u64,
    exact_without_replacement_probability: ExactBigFraction,
    power_probability_ceiling: ExactBigFraction,
}

impl ExactQueryFailureRow {
    fn derive(
        event: ExactQueryFailureEvent,
        sponsoring_owner: ExactFailureOwnerKind,
        logical_word_count: usize,
        population: u64,
        agreement_ceiling: u64,
        query_count: u64,
        charged_term_count: u64,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if logical_word_count == 0
            || population == 0
            || agreement_ceiling >= population
            || query_count == 0
            || query_count > agreement_ceiling
            || charged_term_count == 0
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let exact_without_replacement_probability = ExactBigFraction::new(
            falling_factorial(agreement_ceiling, query_count)?,
            falling_factorial(population, query_count)?,
        )?;
        let power_probability_ceiling = ExactBigFraction::from_u64(agreement_ceiling, population)?
            .power(
                u32::try_from(query_count)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )?;
        if !exact_without_replacement_probability.less_than_or_equal(&power_probability_ceiling) {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        Ok(Self {
            event,
            sponsoring_owner,
            logical_word_count,
            population,
            agreement_ceiling,
            query_count,
            charged_term_count,
            exact_without_replacement_probability,
            power_probability_ceiling,
        })
    }

    fn charged_power_ceiling(&self) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
        self.power_probability_ceiling
            .multiply_u64(self.charged_term_count)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactThetaFailureRow {
    challenge: CommonProofChallenge,
    ordered_bad_polynomial_degrees: Vec<u64>,
    bad_set_numerator: BigUint,
    sample_space_denominator: BigUint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactAlgebraicFailureEvent {
    NonNativeThetaExtraction,
    RelationCompositionBatch,
    OpeningPointExceptionalSets,
    PhaseRowAndSelectorBatching,
    OpeningBatchMaskConsistency,
    BoundOpeningBatch,
    BoundDegreeSuffixes,
    WhirOpeningBatch,
    MaskedSumcheckInitialTransitions,
    MaskedSumcheckFolds,
    RoundCommitmentCheckpoints,
    WhirQueryCombinations,
    AggregateWideBaseBlinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactAlgebraicFailureRow {
    event: ExactAlgebraicFailureEvent,
    owner_kinds: Vec<ExactFailureOwnerKind>,
    theorem_event_count: u64,
    numerator: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactFailureMagnitudeCertificate {
    owner_rows: Vec<ExactFailureOwnerRow>,
    query_rows: Vec<ExactQueryFailureRow>,
    theta_rows: Vec<ExactThetaFailureRow>,
    algebraic_rows: Vec<ExactAlgebraicFailureRow>,
    extension_field_cardinality: BigUint,
    query_failure_probability_ceiling: ExactBigFraction,
    algebraic_failure_probability_ceiling: ExactBigFraction,
    classical_failure_probability_ceiling: ExactBigFraction,
    qrom_failure_probability_ceiling: ExactBigFraction,
    same_secret_family_multiplicity: u64,
    cms19_verifier_hash_query_count: u64,
    cms19_accepting_database_equation_count: u64,
    all_failure_owners_mapped_once: bool,
    exact_query_products_bounded: bool,
    ordinary_family_mass_gate_holds: bool,
    transformed_initial_mass_gate_holds: bool,
    complete_qrom_mass_gate_holds: bool,
}

impl ExactFailureMagnitudeCertificate {
    fn is_complete(&self) -> bool {
        self.owner_rows
            .iter()
            .all(|row| row.transition_count == row.expected_transition_count)
            && self.query_rows.len() == 11
            && self.theta_rows.len() == 3
            && self.algebraic_rows.len() == 13
            && self.same_secret_family_multiplicity == 10
            && self.all_failure_owners_mapped_once
            && self.exact_query_products_bounded
            && self.ordinary_family_mass_gate_holds
            && self.transformed_initial_mass_gate_holds
            && self.complete_qrom_mass_gate_holds
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactFailureMagnitudeFault {
    DropFirstQueryRow,
    ReduceFirstQueryAgreementCeiling,
    DropRelationCompositionOwner,
    ReduceAggregateWideBaseNumerator,
    ChangeVerifierHashQueryCount,
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
    WhirOpeningConstraintBatch,
    WhirMaskedSumcheckBatch {
        batch_ordinal: u32,
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
    AggregateWidePadQueryAgreement,
    WhirBaseCaseBlinding,
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
    AggregateWidePadCommitmentBinding,
    PhaseOpeningAuthenticationAndReduction { phase: RowCodeWhirPhase },
    BoundAuthenticationAndReduction { bound_tree_ordinal: u32 },
    ExplicitPointAggregateWideOpening,
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
    AggregateCommitmentsAndQueries,
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
    RelationPhase {
        phase: RowCodeWhirPhase,
    },
    BoundTree {
        bound_tree_ordinal: u32,
    },
    WhirEpoch {
        epoch_ordinal: u32,
    },
    AggregateWideMask {
        commitment_role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
    },
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
    aggregate_wide_mask_openings: Vec<CheckedWhirEpochOpeningRow>,
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
    let mut aggregate_wide_mask_openings = Vec::new();
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
            (
                commitment_role
                @ (linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad
                | linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource
                | linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad),
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                    epoch_ordinal,
                },
            ) => aggregate_wide_mask_openings.push(CheckedWhirEpochOpeningRow {
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
        || whir_epochs.len()
            != plan
                .whir
                .rounds
                .len()
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
        || aggregate_wide_mask_openings.len() != 3
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
    let final_source_epoch_ordinal = u32::try_from(whir_epochs.len() - 1)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_epoch_ordinal = final_source_epoch_ordinal
        .checked_add(1)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let expected_mask_openings = [
        (
            linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad,
            pad_epoch_ordinal,
        ),
        (
            linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource,
            final_source_epoch_ordinal,
        ),
        (
            linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad,
            pad_epoch_ordinal,
        ),
    ];
    if aggregate_wide_mask_openings
        .iter()
        .map(|row| (row.commitment_role, row.epoch_ordinal))
        .ne(expected_mask_openings)
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(CheckedSuppliedCommitmentOpeningRows {
        relation_phases,
        whir_epochs,
        aggregate_wide_mask_openings,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AggregateLeafOracleCallInventoryRow {
    role: MerkleOracleEquationRole,
    interleaving_width: usize,
    opened_leaf_count: u64,
    initial_hash_query_count: u64,
    transition_hash_query_count: u64,
    final_hash_query_count: u64,
    parent_hash_query_count: u64,
}

/// Exact SHAKE call inventory for the deployed aggregate leaf chain.
///
/// The abstract Merkle ledger treats a leaf hash as one oracle call. Production
/// instead makes one initial call, one transition call per encoded column, and
/// one final call. The initial input is repeated for every opened row and is
/// identical for every commitment with the same interleaving width; transition
/// and final inputs are conservatively distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DeployedAggregateLeafOracleCertificate {
    rows: Vec<AggregateLeafOracleCallInventoryRow>,
    distinct_initial_equation_count: u64,
    repeated_initial_hash_query_count: u64,
    deployed_verifier_hash_query_count: u64,
    deployed_accepting_database_equation_count: u64,
    minimum_oracle_output_bit_length: usize,
    classical_collision_penalty_numerator: BigUint,
    qrom_ideal_oracle_penalty_numerator: BigUint,
    collision_penalty_denominator_bit_length: usize,
    transition_collision_propagates_to_final_leaf: bool,
    uniform_required_output_geometry_established: bool,
}

impl DeployedAggregateLeafOracleCertificate {
    fn classical_collision_penalty_is_below_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.classical_collision_penalty_numerator << exponent)
            < (BigUint::one() << self.collision_penalty_denominator_bit_length)
    }

    fn qrom_ideal_oracle_penalty_is_below_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.qrom_ideal_oracle_penalty_numerator << exponent)
            < (BigUint::one() << self.collision_penalty_denominator_bit_length)
    }

    fn has_complete_call_inventory(&self) -> bool {
        !self.rows.is_empty()
            && self.rows.iter().all(|row| {
                let Ok(interleaving_width) = u64::try_from(row.interleaving_width) else {
                    return false;
                };
                row.interleaving_width > 0
                    && row.opened_leaf_count > 0
                    && row.initial_hash_query_count == row.opened_leaf_count
                    && row.transition_hash_query_count
                        == row.opened_leaf_count.saturating_mul(interleaving_width)
                    && row.final_hash_query_count == row.opened_leaf_count
                    && row.parent_hash_query_count > 0
            })
            && self.distinct_initial_equation_count > 0
            && self.repeated_initial_hash_query_count > 0
            && self.deployed_verifier_hash_query_count > 0
            && self.deployed_accepting_database_equation_count > 0
            && self.minimum_oracle_output_bit_length
                == ColumnStreamableLeafHasher::intermediate_output_bit_length()
            && self.collision_penalty_denominator_bit_length
                == self.minimum_oracle_output_bit_length
            && self.transition_collision_propagates_to_final_leaf
            && self.uniform_required_output_geometry_established
                == (self.minimum_oracle_output_bit_length
                    == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
                    && ColumnStreamableLeafHasher::final_output_bit_length()
                        == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH)
    }

    fn is_eligible_for_uniform_required_output(&self) -> bool {
        self.has_complete_call_inventory() && self.uniform_required_output_geometry_established
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinateDerivedOpeningImplementation {
    RelationColumnCommitment,
    ExactBoundTree,
    AggregateWideWhir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommitmentSubtreeExtractionRow {
    role: MerkleOracleEquationRole,
    implementation: CoordinateDerivedOpeningImplementation,
    leaf_count: usize,
    tree_height: usize,
    query_count: usize,
    leaf_hash_query_count: u64,
    parent_hash_query_count_ceiling: u64,
    predecessor_support_ceiling: u8,
}

/// Checked specialization of the binary-tree extractor from CMS19
/// Definition 6.3 and Lemmas 6.4--6.5 to every protocol Merkle tree reached by
/// the selected verifier.
///
/// The database extractor returns a unique partial tree when the random-oracle
/// database is collision free. It deliberately does not turn unopened leaves
/// into values: they remain undefined, and the production verifier rejects if
/// it needs one. Complete prover messages are a separate case because their
/// roots are recomputed from the fully supplied canonical message.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommitmentSubtreeExtractionCertificate {
    rows: Vec<CommitmentSubtreeExtractionRow>,
    supplied_commitment_root_count: usize,
    bound_tree_root_count: usize,
    canonical_complete_message_count: u64,
    one_edge_sampler_message_count: u64,
    distinct_protocol_tree_role_count: usize,
    collision_free_extraction_is_unique: bool,
    database_growth_preserves_the_extracted_subtree: bool,
    changed_extracted_tree_requires_a_root_or_half_preimage: bool,
    missing_leaf_is_undefined: bool,
    queried_missing_leaf_is_rejected: bool,
    complete_message_roots_are_recomputed: bool,
    compact_frontiers_are_coordinate_derived: bool,
    coordinates_are_derived_from_accepted_transcript_order: bool,
}

impl CommitmentSubtreeExtractionCertificate {
    fn is_complete(&self) -> bool {
        !self.rows.is_empty()
            && self.distinct_protocol_tree_role_count == self.rows.len()
            && self.supplied_commitment_root_count > 0
            && self.bound_tree_root_count > 0
            && self
                .supplied_commitment_root_count
                .checked_add(self.bound_tree_root_count)
                == Some(self.rows.len())
            && self.canonical_complete_message_count > 0
            && self.one_edge_sampler_message_count > 0
            && self.rows.iter().all(|row| {
                row.leaf_count.is_power_of_two()
                    && usize::try_from(row.leaf_count.ilog2()).ok() == Some(row.tree_height)
                    && row.query_count > 0
                    && row.query_count <= row.leaf_count
                    && row.leaf_hash_query_count == row.query_count as u64
                    && row.parent_hash_query_count_ceiling > 0
                    && row.predecessor_support_ceiling <= 2
            })
            && self.collision_free_extraction_is_unique
            && self.database_growth_preserves_the_extracted_subtree
            && self.changed_extracted_tree_requires_a_root_or_half_preimage
            && self.missing_leaf_is_undefined
            && self.queried_missing_leaf_is_rejected
            && self.complete_message_roots_are_recomputed
            && self.compact_frontiers_are_coordinate_derived
            && self.coordinates_are_derived_from_accepted_transcript_order
    }
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
    OriginalBcsStrongStateHashChainSectionEightSix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PropositionEightTwelvePartitionCase {
    AcceptingDatabaseContainsCollision,
    CollisionFreeAcceptingDatabaseYieldsFullTranscript,
    EarliestFalseToTrueVerifierStateTransition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatePredicateRequirement {
    OriginalBcsStrongStateRuntimeHashChainCorrespondence,
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
    GeneratedStrongStateTypedOracleCorrespondence,
    GeneratedSelectedPlanStatePredicate,
    GeneratedFailureOwnerPartition,
    CheckedConstructionGeometry,
    CheckedInterleavedDistanceLemma,
    ExplicitBerlekampWelchExtractor,
    IndependentCompilerInterpreterArithmeticOracle,
    CheckedRoundByRoundPolynomialExtractor,
    CheckedExplicitPointConstraintExtractor,
    CheckedExactFailureMagnitudeCorrespondence,
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

/// Exact correspondence between the live typed oracle graph and the
/// strong-state original-BCS argument described in CMS19 Section 8.6.
///
/// Sampler expansion blocks are verifier randomness generated outside prover
/// response absorption. An incomplete verifier message is represented by
/// `None` and inherits the predecessor state. Filling it is the only operation
/// that can cross from false to true, and the generated state table assigns
/// that fill exactly one failure event. This is the stronger state condition
/// required for the original one-edge challenge chain; it is not the modified
/// two-edge chain from Sections 8.2--8.5.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19StrongStateHashChainCertificate {
    logical_verifier_message_count: u64,
    typed_challenge_transition_count: u64,
    uniquely_owned_fill_transition_count: u64,
    topologically_ordered_equation_count: u64,
    oracle_edge_count: u64,
    sampler_expansion_edge_count: u64,
    prover_response_edge_count: u64,
    transcript_predecessor_support_ceiling: u8,
    undefined_message_inherits_predecessor_state: bool,
    sampler_messages_are_outside_prover_response_absorption: bool,
    typed_oracle_domains_are_pairwise_distinct: bool,
    canonical_oracle_plan_hash: [u8; 64],
}

impl Cms19StrongStateHashChainCertificate {
    fn is_complete(&self) -> bool {
        self.logical_verifier_message_count > 0
            && self.typed_challenge_transition_count == self.logical_verifier_message_count
            && self.uniquely_owned_fill_transition_count == self.logical_verifier_message_count
            && self.topologically_ordered_equation_count > 0
            && self.oracle_edge_count > self.sampler_expansion_edge_count
            && self.sampler_expansion_edge_count > 0
            && self.prover_response_edge_count > 0
            && self.transcript_predecessor_support_ceiling <= 2
            && self.undefined_message_inherits_predecessor_state
            && self.sampler_messages_are_outside_prover_response_absorption
            && self.typed_oracle_domains_are_pairwise_distinct
            && self.canonical_oracle_plan_hash != [0_u8; 64]
    }
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
    strong_state_typed_hash_chain_established: bool,
    deployed_oracle_output_geometry_established: bool,
}

impl Cms19ApplicabilityCertificate {
    fn is_complete(&self) -> bool {
        self.equation_count_without_catalog_correspondence == 0
            && self.hash_query_count_without_catalog_correspondence == 0
            && self.transcript_predecessor_support_ceiling <= 2
            && self.complete_state_predicate_established
            && self.syntactic_proposition_eight_twelve_partition_catalogued
            && self.proposition_eight_twelve_case_split_established
            && self.complete_query_ledger_correspondence_established
            && self.strong_state_typed_hash_chain_established
            && self.deployed_oracle_output_geometry_established
    }
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
    deployed_aggregate_leaf_oracle: DeployedAggregateLeafOracleCertificate,
    commitment_subtree_extraction: CommitmentSubtreeExtractionCertificate,
    selected_plan_state_predicate: SelectedPlanStatePredicateCertificate,
    cms19_state_predicate: Cms19StatePredicateCertificate,
    cms19_strong_state_hash_chain: Cms19StrongStateHashChainCertificate,
    maximum_transcript_hash_query_count: u64,
    logical_verifier_message_count: u64,
    cms19_arithmetic: Cms19ArithmeticCertificate,
    cms19_applicability: Cms19ApplicabilityCertificate,
    exact_failure_magnitude: ExactFailureMagnitudeCertificate,
    construction_masking: ConstructionMaskingCertificate,
    aggregate_wide_masking: AggregateWideMaskingCertificate,
    relation_compiler_interpreter_semantics: RelationCompilerInterpreterSemanticCertificate,
    polynomial_protocol_extractor: ExactPolynomialProtocolExtractorCertificate,
    point_constraint_extractor: ExactPointConstraintExtractorCertificate,
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
        self.commitment_subtree_extraction.is_complete()
            && self.construction_masking.is_complete()
            && self.aggregate_wide_masking.is_complete()
            && self.relation_compiler_interpreter_semantics.is_complete()
            && self.polynomial_protocol_extractor.is_complete()
            && self.point_constraint_extractor.is_complete()
            && self.selected_plan_state_predicate.transition_rows.len()
                == usize::try_from(self.logical_verifier_message_count).unwrap_or(usize::MAX)
                    + self
                        .selected_plan_state_predicate
                        .transition_rows
                        .iter()
                        .filter(|row| row.failure_event_owner.is_none())
                        .count()
            && self.cms19_state_predicate.is_complete()
            && self.cms19_strong_state_hash_chain.is_complete()
            && self.cms19_applicability.is_complete()
            && self
                .deployed_aggregate_leaf_oracle
                .is_eligible_for_uniform_required_output()
            && self.exact_failure_magnitude.is_complete()
    }
}

pub(in crate::bgv::proof_suite) fn checked_row_code_whir_failure_partition(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<RowCodeWhirFailurePartitionCertificate, WhirTheoremCertificateError> {
    let parameters = plan.selected_parameters();
    let hiding_configuration =
        super::super::hiding_whir::selected_hiding_whir_config(parameters)
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if parameters != RowCodeWhirSelectedParameters::selected()
        || parameters.soundness_assumption != RowCodeWhirSoundnessAssumption::UniqueDecoding
        || parameters.folding_factor != 3
        || plan.whir.rounds.len() != hiding_configuration.n_rounds()
        || plan.whir.initial_sumcheck_round_count != hiding_configuration.round_folding_factor(0)
        || plan.whir.final_round.sumcheck_round_count
            != hiding_configuration.inner.final_sumcheck_rounds
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let compiled_relation_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?,
        &relation_context,
    )
    .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let validated_relation_plan = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
        compiled_relation_plan,
        &relation_context,
    )
    .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let relation_variant = validated_relation_plan
        .compiled_plan()
        .select_variant(None, None)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let relation_compiler_interpreter_semantics =
        checked_relation_compiler_interpreter_semantics(relation_variant, &relation_context)
            .map_err(|_| WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence)?;
    if !relation_compiler_interpreter_semantics.is_complete()
        || relation_compiler_interpreter_semantics.canonical_variant_hash()
            != relation_variant.canonical_hash().map_err(|_| {
                WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence
            })?
        || relation_compiler_interpreter_semantics.constraint_count()
            != relation_variant.constraint_count()
    {
        return Err(WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence);
    }
    let expected_construction_plan =
        RowCodeWhirConstructionPlan::for_selected_variant(&validated_relation_plan, None, None)
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if &expected_construction_plan != plan {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let (polynomial_protocol_extractor, point_constraint_extractor) =
        checked_exact_same_secret_extractor_correspondence(
            plan,
            relation_variant,
            &relation_context,
            validated_relation_plan.canonical_plan_hash(),
            relation_variant.canonical_hash().map_err(|_| {
                WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence
            })?,
        )
        .map_err(|_| WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence)?;
    let construction_plan_identity_hash = plan
        .canonical_identity_hash()
        .map_err(|_| WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence)?;
    if !polynomial_protocol_extractor.is_complete()
        || !point_constraint_extractor.is_complete()
        || polynomial_protocol_extractor.construction_plan_identity_hash()
            != construction_plan_identity_hash
        || point_constraint_extractor.construction_plan_identity_hash()
            != construction_plan_identity_hash
    {
        return Err(WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence);
    }
    let construction_masking =
        checked_zero_knowledge_mask_image(relation_variant, &relation_context)
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    let aggregate_wide_masking = AggregateWideMaskingCertificate::derive(&hiding_configuration)
        .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if !construction_masking.is_complete()
        || !aggregate_wide_masking.is_complete()
        || !construction_masking.aggregate_claims_factor_through_masked_openings()
        || !construction_masking.aggregate_wide_views_delegate_to_precommitted_pad()
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
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
    let source_epoch_count = plan
        .whir
        .rounds
        .len()
        .checked_add(1)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if encoded_oracles.len() != source_epoch_count
        || whir_epoch_openings.len() != source_epoch_count
    {
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
    let encoded_oracle_leaf_width = 1_usize
        .checked_shl(
            u32::try_from(parameters.folding_factor)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let code_state_count = source_epoch_count
        .checked_mul(
            parameters
                .folding_factor
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut code_state_rows = Vec::with_capacity(code_state_count);
    let mut interleaved_unique_decoding_rows = Vec::with_capacity(code_state_count);
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
            || encoded_oracle.leaf_width != encoded_oracle_leaf_width
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
        let (
            source_message_dimension,
            source_randomness_dimension,
            source_domain_size,
            source_query_count,
            source_interleaving_width,
        ) = aggregate_wide_masking
            .folded_source_code_geometry(epoch_index)
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        if source_domain_size != encoded_oracle.leaf_count
            || source_query_count != opening.query_count
            || source_interleaving_width != encoded_oracle.leaf_width
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        // The source encoder writes one message segment followed by one
        // independently sampled randomness segment in each interleaved lane;
        // every remaining coefficient is fixed to zero. Consequently the
        // exact image dimension is `(message + randomness) * laneCount`, not
        // the unmasked message dimension and not the next-power-of-two buffer
        // capacity used by the FFT implementation.
        let parent_dimension = u64::try_from(
            source_message_dimension
                .checked_add(source_randomness_dimension)
                .and_then(|dimension| dimension.checked_mul(source_interleaving_width))
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
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
                source_interleaving_width,
            )?);
            code_state_rows.push(code_state);
        }
    }

    let mut fold_rows = Vec::with_capacity(
        source_epoch_count
            .checked_mul(parameters.folding_factor)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
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

    let final_source_epoch_ordinal = u32::try_from(source_epoch_count - 1)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let final_code_state = code_state_rows
        .iter()
        .find(|row| {
            row.epoch_ordinal == final_source_epoch_ordinal
                && usize::try_from(row.fold_ordinal).ok() == Some(parameters.folding_factor)
        })
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let final_query_row = WhirFinalQueryRow {
        epoch_ordinal: final_source_epoch_ordinal,
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
    let final_sumcheck_numerator = 0;

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
    let deployed_aggregate_leaf_oracle = derive_deployed_aggregate_leaf_oracle_certificate(
        plan,
        &aggregate_wide_masking,
        &complete_verifier_oracle_ledger,
    )?;
    let commitment_subtree_extraction = derive_commitment_subtree_extraction_certificate(
        plan,
        &complete_verifier_oracle_ledger.merkle_rows,
    )?;
    let cms19_arithmetic = derive_cms19_arithmetic_certificate(
        complete_verifier_oracle_ledger.complete_hash_query_count,
        complete_verifier_oracle_ledger.complete_equation_count_ceiling,
    );
    let exact_failure_magnitude =
        derive_exact_failure_magnitude_certificate(ExactFailureMagnitudeDerivationInput {
            plan,
            relation_variant,
            catalog: &catalog,
            selected_plan_state_predicate: &selected_plan_state_predicate,
            code_state_rows: &code_state_rows,
            fold_rows: &fold_rows,
            shift_rows: &shift_rows,
            aggregate_wide_masking: &aggregate_wide_masking,
            initial_constraint_batch_numerator,
            logical_verifier_message_count,
            cms19_arithmetic: &cms19_arithmetic,
        })?;
    let cms19_strong_state_hash_chain = derive_cms19_strong_state_hash_chain_certificate(
        plan,
        &catalog,
        &state_epoch_rows,
        &oracle_equation_rows,
        &selected_plan_state_predicate,
        logical_verifier_message_count,
    )?;
    let cms19_state_predicate =
        derive_cms19_state_predicate_certificate(Cms19StatePredicateCertificateInput {
            selected_plan_state_predicate: &selected_plan_state_predicate,
            plan,
            code_state_rows: &code_state_rows,
            interleaved_unique_decoding_rows: &interleaved_unique_decoding_rows,
            strong_state_hash_chain: &cms19_strong_state_hash_chain,
            relation_compiler_interpreter_semantics: &relation_compiler_interpreter_semantics,
            polynomial_protocol_extractor: &polynomial_protocol_extractor,
            point_constraint_extractor: &point_constraint_extractor,
            exact_failure_magnitude: &exact_failure_magnitude,
        });
    let cms19_applicability = Cms19ApplicabilityCertificate {
        transform: Cms19Transform::OriginalBcsStrongStateHashChainSectionEightSix,
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
        proposition_eight_twelve_case_split_established: cms19_state_predicate.is_complete()
            && exact_failure_magnitude.is_complete(),
        complete_query_ledger_correspondence_established: true,
        strong_state_typed_hash_chain_established: cms19_strong_state_hash_chain.is_complete(),
        deployed_oracle_output_geometry_established: deployed_aggregate_leaf_oracle
            .is_eligible_for_uniform_required_output(),
    };
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
        deployed_aggregate_leaf_oracle,
        commitment_subtree_extraction,
        selected_plan_state_predicate,
        cms19_state_predicate,
        cms19_strong_state_hash_chain,
        maximum_transcript_hash_query_count,
        logical_verifier_message_count,
        cms19_arithmetic,
        cms19_applicability,
        exact_failure_magnitude,
        construction_masking,
        aggregate_wide_masking,
        relation_compiler_interpreter_semantics,
        polynomial_protocol_extractor,
        point_constraint_extractor,
    })
}

fn find_fold_transcript_operation(
    operations: &[RowCodeWhirTranscriptOperation],
    epoch_ordinal: u32,
    local_sumcheck_round_ordinal: u32,
) -> Result<u32, WhirTheoremCertificateError> {
    find_unique_transcript_operation(operations, |operation| {
        matches!(
            operation,
            RowCodeWhirTranscriptOperation::SampleExtension {
                role: RowCodeWhirExtensionRole::MaskedSumcheckRound {
                    batch_ordinal,
                    round_ordinal,
                },
                ..
            } if *batch_ordinal == epoch_ordinal
                && *round_ordinal == local_sumcheck_round_ordinal
        )
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
                RowCodeWhirProofSectionRole::AggregateWidePadCommitment => {
                    SelectedPlanProofSectionPredicate::AggregateWidePadCommitmentBinding
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
                RowCodeWhirProofSectionRole::AggregateWideOpening => {
                    SelectedPlanProofSectionPredicate::ExplicitPointAggregateWideOpening
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
                RowCodeWhirCheckpointBoundary::AggregateCommitmentsAndQueries => {
                    SelectedPlanCheckpointStateOwner::AggregateCommitmentsAndQueries
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
            role: RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { batch_ordinal },
            whir_challenge_ordinal: Some(_),
        } => (
            SelectedPlanStatePredicateClause::WhirMaskedSumcheckBatch {
                batch_ordinal: *batch_ordinal,
            },
            Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::MaskedSumcheckEpsilon {
                    batch_ordinal: *batch_ordinal,
                },
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role:
                RowCodeWhirExtensionRole::MaskedSumcheckRound {
                    batch_ordinal,
                    round_ordinal,
                },
            whir_challenge_ordinal: Some(_),
        } => {
            let fold_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, *batch_ordinal, fold_ordinal)?;
            (
                SelectedPlanStatePredicateClause::WhirConstrainedFold {
                    epoch_ordinal: *batch_ordinal,
                    fold_ordinal,
                },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::MaskedSumcheckRound {
                        batch_ordinal: *batch_ordinal,
                        round_ordinal: *round_ordinal,
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
            role: RowCodeWhirExtensionRole::BaseCaseBlinding,
            whir_challenge_ordinal: Some(_),
        } => (
            SelectedPlanStatePredicateClause::WhirBaseCaseBlinding,
            Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::BaseCaseBlinding,
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleDistinctIndices { role, .. } => {
            let predicate_clause = match *role {
                RowCodeWhirQueryRole::Outer => {
                    SelectedPlanStatePredicateClause::OuterRowCodeAgreement
                }
                RowCodeWhirQueryRole::Bound => {
                    SelectedPlanStatePredicateClause::BoundIdentityAgreement
                }
                RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal } => {
                    if epoch_ordinal
                        == final_epoch_ordinal
                            .checked_add(1)
                            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
                    {
                        SelectedPlanStatePredicateClause::AggregateWidePadQueryAgreement
                    } else {
                        require_terminal_code_state(code_state_rows, epoch_ordinal)?;
                        SelectedPlanStatePredicateClause::WhirQueryAgreement { epoch_ordinal }
                    }
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

fn require_terminal_code_state(
    code_state_rows: &[WhirCodeStateRow],
    epoch_ordinal: u32,
) -> Result<(), WhirTheoremCertificateError> {
    if code_state_rows
        .iter()
        .filter(|row| row.epoch_ordinal == epoch_ordinal)
        .map(|row| row.fold_ordinal)
        .max()
        .is_some()
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
                | SelectedPlanStatePredicateClause::WhirQueryAgreement { .. }
                | SelectedPlanStatePredicateClause::AggregateWidePadQueryAgreement => {
                    SelectedPlanFailureEventClass::WithoutReplacementAgreement
                }
                SelectedPlanStatePredicateClause::WhirOpeningConstraintBatch
                | SelectedPlanStatePredicateClause::WhirMaskedSumcheckBatch { .. }
                | SelectedPlanStatePredicateClause::WhirRoundConstraintCheckpoint { .. }
                | SelectedPlanStatePredicateClause::WhirConstrainedFold { .. }
                | SelectedPlanStatePredicateClause::WhirQueryCombination { .. }
                | SelectedPlanStatePredicateClause::WhirBaseCaseBlinding => {
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
        || code_state_rows.len()
            != plan
                .whir
                .rounds
                .len()
                .checked_add(1)
                .and_then(|epoch_count| {
                    plan.parameters
                        .folding_factor
                        .checked_add(1)
                        .and_then(|state_count| epoch_count.checked_mul(state_count))
                })
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
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
        let leaf_hash_query_count = u64::try_from(opening.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count =
            maximum_compact_parent_hash_query_count(opening.leaf_count, opening.query_count)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::WhirEpoch {
                epoch_ordinal: opening.epoch_ordinal,
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
    for opening in &supplied_commitment_openings.aggregate_wide_mask_openings {
        let leaf_hash_query_count = u64::try_from(opening.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count =
            maximum_compact_parent_hash_query_count(opening.leaf_count, opening.query_count)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::AggregateWideMask {
                commitment_role: opening.commitment_role,
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

fn aggregate_leaf_interleaving_width(
    plan: &RowCodeWhirConstructionPlan,
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
    row: MerkleOracleEquationCoverageRow,
) -> Result<Option<usize>, WhirTheoremCertificateError> {
    let expected_geometry = match row.role {
        MerkleOracleEquationRole::WhirEpoch { epoch_ordinal } => {
            let epoch_index = usize::try_from(epoch_ordinal)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
            let encoded_oracle = if epoch_index < plan.whir.rounds.len() {
                plan.whir.rounds[epoch_index].encoded_oracle
            } else if epoch_index == plan.whir.rounds.len() {
                plan.whir.final_round.encoded_oracle
            } else {
                return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
            };
            (
                encoded_oracle.leaf_count,
                row.query_count,
                encoded_oracle.leaf_width,
            )
        }
        MerkleOracleEquationRole::AggregateWideMask { commitment_role } => {
            let (_, _, domain_size, query_count, interleaving_width) = match commitment_role {
                linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad => {
                    aggregate_wide_masking.pad_code_geometry()
                }
                linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource => {
                    aggregate_wide_masking.fresh_source_code_geometry()
                }
                linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad => {
                    aggregate_wide_masking.fresh_pad_code_geometry()
                }
                _ => return Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
            };
            (domain_size, query_count, interleaving_width)
        }
        MerkleOracleEquationRole::RelationPhase { .. }
        | MerkleOracleEquationRole::BoundTree { .. } => return Ok(None),
    };
    if expected_geometry.0 != row.leaf_count
        || expected_geometry.1 != row.query_count
        || expected_geometry.2 == 0
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    Ok(Some(expected_geometry.2))
}

fn derive_deployed_aggregate_leaf_oracle_certificate(
    plan: &RowCodeWhirConstructionPlan,
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
    abstract_ledger: &CompleteVerifierOracleLedger,
) -> Result<DeployedAggregateLeafOracleCertificate, WhirTheoremCertificateError> {
    let mut rows = Vec::new();
    let mut initial_input_widths = BTreeSet::new();
    let mut abstract_leaf_hash_query_count = 0_u64;
    let mut deployed_leaf_hash_query_count = 0_u64;
    let mut deployed_noninitial_equation_count = 0_u64;
    let mut initial_hash_query_count = 0_u64;
    for row in abstract_ledger.merkle_rows.iter().copied() {
        let Some(interleaving_width) =
            aggregate_leaf_interleaving_width(plan, aggregate_wide_masking, row)?
        else {
            continue;
        };
        let opened_leaf_count = u64::try_from(row.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let transition_hash_query_count = opened_leaf_count
            .checked_mul(
                u64::try_from(interleaving_width)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let inventory_row = AggregateLeafOracleCallInventoryRow {
            role: row.role,
            interleaving_width,
            opened_leaf_count,
            initial_hash_query_count: opened_leaf_count,
            transition_hash_query_count,
            final_hash_query_count: opened_leaf_count,
            parent_hash_query_count: row.parent_hash_query_count,
        };
        initial_input_widths.insert(interleaving_width);
        abstract_leaf_hash_query_count = abstract_leaf_hash_query_count
            .checked_add(row.leaf_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let leaf_hash_query_count = inventory_row
            .initial_hash_query_count
            .checked_add(inventory_row.transition_hash_query_count)
            .and_then(|count| count.checked_add(inventory_row.final_hash_query_count))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        deployed_leaf_hash_query_count = deployed_leaf_hash_query_count
            .checked_add(leaf_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let noninitial_equation_count = inventory_row
            .transition_hash_query_count
            .checked_add(inventory_row.final_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        deployed_noninitial_equation_count = deployed_noninitial_equation_count
            .checked_add(noninitial_equation_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        initial_hash_query_count = initial_hash_query_count
            .checked_add(inventory_row.initial_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        rows.push(inventory_row);
    }
    let distinct_initial_equation_count = u64::try_from(initial_input_widths.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let repeated_initial_hash_query_count = initial_hash_query_count
        .checked_sub(distinct_initial_equation_count)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let deployed_verifier_hash_query_count = abstract_ledger
        .complete_hash_query_count
        .checked_sub(abstract_leaf_hash_query_count)
        .and_then(|count| count.checked_add(deployed_leaf_hash_query_count))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let deployed_accepting_database_equation_count = abstract_ledger
        .complete_equation_count_ceiling
        .checked_sub(abstract_leaf_hash_query_count)
        .and_then(|count| count.checked_add(distinct_initial_equation_count))
        .and_then(|count| count.checked_add(deployed_noninitial_equation_count))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let compiler_query_bound = ((BigUint::one() << CMS19_ADVERSARIAL_QUERY_EXPONENT)
        - BigUint::one())
        + BigUint::from(deployed_verifier_hash_query_count);
    let classical_collision_penalty_numerator =
        &compiler_query_bound * (&compiler_query_bound - BigUint::one()) / BigUint::from(2_u8);
    let qrom_ideal_oracle_penalty_numerator = BigUint::from(48_u8)
        * &compiler_query_bound
        * &compiler_query_bound
        * &compiler_query_bound
        + BigUint::from(2_u8) * BigUint::from(deployed_accepting_database_equation_count);
    let minimum_oracle_output_bit_length =
        ColumnStreamableLeafHasher::intermediate_output_bit_length()
            .min(ColumnStreamableLeafHasher::final_output_bit_length());
    Ok(DeployedAggregateLeafOracleCertificate {
        rows,
        distinct_initial_equation_count,
        repeated_initial_hash_query_count,
        deployed_verifier_hash_query_count,
        deployed_accepting_database_equation_count,
        minimum_oracle_output_bit_length,
        classical_collision_penalty_numerator,
        qrom_ideal_oracle_penalty_numerator,
        collision_penalty_denominator_bit_length: minimum_oracle_output_bit_length,
        transition_collision_propagates_to_final_leaf: true,
        uniform_required_output_geometry_established: minimum_oracle_output_bit_length
            == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
            && ColumnStreamableLeafHasher::final_output_bit_length()
                == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
    })
}

fn supplied_commitment_protocol_tree_role(
    role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
) -> Result<MerkleOracleEquationRole, WhirTheoremCertificateError> {
    match role {
        linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase { phase } => {
            Ok(MerkleOracleEquationRole::RelationPhase { phase })
        }
        linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate => {
            Ok(MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 })
        }
        linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound { round_ordinal } => {
            Ok(MerkleOracleEquationRole::WhirEpoch {
                epoch_ordinal: round_ordinal
                    .checked_add(1)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            })
        }
        commitment_role
        @ (linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad
        | linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource
        | linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad) => {
            Ok(MerkleOracleEquationRole::AggregateWideMask { commitment_role })
        }
    }
}

fn coordinate_derived_opening_implementation(
    role: MerkleOracleEquationRole,
) -> CoordinateDerivedOpeningImplementation {
    match role {
        MerkleOracleEquationRole::RelationPhase { .. } => {
            CoordinateDerivedOpeningImplementation::RelationColumnCommitment
        }
        MerkleOracleEquationRole::BoundTree { .. } => {
            CoordinateDerivedOpeningImplementation::ExactBoundTree
        }
        MerkleOracleEquationRole::WhirEpoch { .. }
        | MerkleOracleEquationRole::AggregateWideMask { .. } => {
            CoordinateDerivedOpeningImplementation::AggregateWideWhir
        }
    }
}

fn derive_commitment_subtree_extraction_certificate(
    plan: &RowCodeWhirConstructionPlan,
    merkle_rows: &[MerkleOracleEquationCoverageRow],
) -> Result<CommitmentSubtreeExtractionCertificate, WhirTheoremCertificateError> {
    let transcript_plan = plan
        .linear_bcs_transcript_plan()
        .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    if merkle_rows.is_empty()
        || merkle_rows.iter().enumerate().any(|(row_index, row)| {
            merkle_rows[..row_index]
                .iter()
                .any(|prior| prior.role == row.role)
        })
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }

    let supplied_commitment_root_count = transcript_plan.supplied_commitment_openings().len();
    for opening in transcript_plan.supplied_commitment_openings() {
        if opening.query_order
            != linear_bcs_transcript::LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder
            || opening.merkle_traversal_order
                != linear_bcs_transcript::LinearBcsMerkleTraversalOrder::SortedCoordinates
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let protocol_role = supplied_commitment_protocol_tree_role(opening.commitment_role)?;
        let matching_rows = merkle_rows
            .iter()
            .filter(|row| row.role == protocol_role)
            .collect::<Vec<_>>();
        if matching_rows.len() != 1
            || matching_rows[0].leaf_count != opening.payload_leaf_count
            || matching_rows[0].query_count != opening.query_count
        {
            return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
        }
    }

    let relation_phase_rows = merkle_rows
        .iter()
        .filter_map(|row| match row.role {
            MerkleOracleEquationRole::RelationPhase { phase } => Some(phase),
            _ => None,
        })
        .collect::<Vec<_>>();
    let bound_tree_ordinals = merkle_rows
        .iter()
        .filter_map(|row| match row.role {
            MerkleOracleEquationRole::BoundTree { bound_tree_ordinal } => Some(bound_tree_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    let whir_epoch_ordinals = merkle_rows
        .iter()
        .filter_map(|row| match row.role {
            MerkleOracleEquationRole::WhirEpoch { epoch_ordinal } => Some(epoch_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    let aggregate_wide_role_count = merkle_rows
        .iter()
        .filter(|row| matches!(row.role, MerkleOracleEquationRole::AggregateWideMask { .. }))
        .count();
    if relation_phase_rows != plan.phase_order
        || bound_tree_ordinals
            != (0..plan.bound_trees.len())
                .map(u32::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        || whir_epoch_ordinals
            != (0..=plan.whir.rounds.len())
                .map(u32::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        || aggregate_wide_role_count != 3
        || supplied_commitment_root_count.checked_add(plan.bound_trees.len())
            != Some(merkle_rows.len())
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }

    let mut canonical_complete_message_count = 0_u64;
    let mut one_edge_sampler_message_count = 0_u64;
    for range in transcript_plan.round_ranges() {
        match range.prover_oracle_root {
            linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessage {
                ..
            } => {
                let geometry = range
                    .merkle_geometry()
                    .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?
                    .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
                if geometry.canonical_message_byte_length == 0
                    || geometry.payload_leaf_count == 0
                    || geometry.commitment_hash_query_count == 0
                {
                    return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
                }
                canonical_complete_message_count = canonical_complete_message_count
                    .checked_add(range.round_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            }
            linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. } => {
                one_edge_sampler_message_count = one_edge_sampler_message_count
                    .checked_add(range.round_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            }
            linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment { .. } => {}
        }
    }

    let rows = merkle_rows
        .iter()
        .map(|row| {
            let tree_height = checked_tree_height(row.leaf_count)?;
            let expected_parent_hash_query_count =
                maximum_compact_parent_hash_query_count(row.leaf_count, row.query_count)?;
            if row.leaf_hash_query_count
                != u64::try_from(row.query_count)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                || row.parent_hash_query_count != expected_parent_hash_query_count
                || row.accepting_database_equation_count_ceiling
                    != row
                        .leaf_hash_query_count
                        .checked_add(row.parent_hash_query_count)
                        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
                || row.predecessor_support_ceiling > 2
            {
                return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
            }
            Ok(CommitmentSubtreeExtractionRow {
                role: row.role,
                implementation: coordinate_derived_opening_implementation(row.role),
                leaf_count: row.leaf_count,
                tree_height,
                query_count: row.query_count,
                leaf_hash_query_count: row.leaf_hash_query_count,
                parent_hash_query_count_ceiling: row.parent_hash_query_count,
                predecessor_support_ceiling: row.predecessor_support_ceiling,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let certificate = CommitmentSubtreeExtractionCertificate {
        distinct_protocol_tree_role_count: rows.len(),
        rows,
        supplied_commitment_root_count,
        bound_tree_root_count: plan.bound_trees.len(),
        canonical_complete_message_count,
        one_edge_sampler_message_count,
        // CMS19 Definition 6.3 rejects collisions before expanding a node.
        collision_free_extraction_is_unique: true,
        // CMS19 Lemma 6.4.
        database_growth_preserves_the_extracted_subtree: true,
        // CMS19 Lemma 6.5.
        changed_extracted_tree_requires_a_root_or_half_preimage: true,
        // `leaves(Extract(...))` uses bottom for every absent depth-d node.
        missing_leaf_is_undefined: true,
        // Every production frontier verifier requires every transcript-derived
        // coordinate and reconstructs the committed root before returning.
        queried_missing_leaf_is_rejected: true,
        complete_message_roots_are_recomputed: canonical_complete_message_count > 0,
        compact_frontiers_are_coordinate_derived: true,
        coordinates_are_derived_from_accepted_transcript_order: true,
    };
    if !certificate.is_complete() {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(certificate)
}

fn derive_cms19_strong_state_hash_chain_certificate(
    plan: &RowCodeWhirConstructionPlan,
    catalog: &RowCodeWhirOracleEquationCatalog,
    state_epoch_rows: &[StateEpochRow],
    oracle_equation_rows: &[OracleEquationCoverageRow],
    selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
    logical_verifier_message_count: u64,
) -> Result<Cms19StrongStateHashChainCertificate, WhirTheoremCertificateError> {
    validate_state_and_equation_rows(catalog, state_epoch_rows, oracle_equation_rows)?;
    if !selected_plan_state_predicate.is_total_for_plan(plan)
        || selected_plan_state_predicate.transition_rows.len() != state_epoch_rows.len()
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }

    let typed_challenge_transition_count = state_epoch_rows
        .iter()
        .filter(|row| {
            row.transition_owner == StateTransitionOwner::VerifierChallengeWithTypedFailureEvent
        })
        .try_fold(0_u64, |count, _| {
            count
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
    let uniquely_owned_fill_transition_count = selected_plan_state_predicate
        .transition_rows
        .iter()
        .filter(|row| row.failure_event_owner.is_some())
        .try_fold(0_u64, |count, _| {
            count
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
    let topologically_ordered_equation_count =
        oracle_equation_rows.iter().try_fold(0_u64, |count, row| {
            count
                .checked_add(row.equation_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
    let transcript_predecessor_support_ceiling = oracle_equation_rows
        .iter()
        .map(|row| row.role_pattern.maximum_predecessor_support_count())
        .max()
        .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;

    let oracle_plan = plan
        .linear_bcs_transcript_plan()
        .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    let abstract_oracle_step_count = oracle_plan
        .round_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let sampler_expansion_edge_count = oracle_plan
        .one_edge_sampler_block_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let prover_response_round_count = abstract_oracle_step_count
        .checked_sub(sampler_expansion_edge_count)
        .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    let prover_response_edge_count = prover_response_round_count
        .checked_mul(2)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let oracle_edge_count = oracle_plan
        .chain_hash_query_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    if oracle_edge_count
        != sampler_expansion_edge_count
            .checked_add(prover_response_edge_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let sampler_messages_are_outside_prover_response_absorption = oracle_plan
        .round_ranges()
        .iter()
        .all(|range| match range.prover_oracle_root {
            linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. } => {
                matches!(
                    range.verifier_message_role,
                    linear_bcs_transcript::LinearBcsVerifierMessageRole::SamplerPrefixBlock {
                        ..
                    } | linear_bcs_transcript::LinearBcsVerifierMessageRole::SamplerTerminalBlock {
                        ..
                    }
                )
            }
            linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment { .. }
            | linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessage {
                ..
            } => matches!(
                range.verifier_message_role,
                linear_bcs_transcript::LinearBcsVerifierMessageRole::UnusedRoundMessageBeforeProverOracle {
                    ..
                }
            ),
        });

    let typed_oracle_domains = [
        TRANSCRIPT_INITIAL_DOMAIN,
        TRANSCRIPT_ABSORB_DOMAIN,
        TRANSCRIPT_RESPONSE_ROOT_DOMAIN,
        TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN,
        TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN,
        TRANSCRIPT_RESPONSE_BINDING_DOMAIN,
        TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN,
        PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE,
        DISTINCT_QUERY_VECTOR_SAMPLER_TYPE,
    ];
    let typed_oracle_domains_are_pairwise_distinct = typed_oracle_domains
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        == typed_oracle_domains.len();
    let certificate = Cms19StrongStateHashChainCertificate {
        logical_verifier_message_count,
        typed_challenge_transition_count,
        uniquely_owned_fill_transition_count,
        topologically_ordered_equation_count,
        oracle_edge_count,
        sampler_expansion_edge_count,
        prover_response_edge_count,
        transcript_predecessor_support_ceiling,
        // This is the Section 8.6 state extension: an incomplete verifier
        // message is `None`, and the predicate is defined to equal its
        // predecessor until the complete typed sampler output is filled.
        undefined_message_inherits_predecessor_state: true,
        sampler_messages_are_outside_prover_response_absorption,
        typed_oracle_domains_are_pairwise_distinct,
        canonical_oracle_plan_hash: oracle_plan
            .canonical_hash()
            .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?,
    };
    if !certificate.is_complete()
        || certificate.topologically_ordered_equation_count
            != catalog
                .maximum_equation_count()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(certificate)
}

struct Cms19StatePredicateCertificateInput<'a> {
    selected_plan_state_predicate: &'a SelectedPlanStatePredicateCertificate,
    plan: &'a RowCodeWhirConstructionPlan,
    code_state_rows: &'a [WhirCodeStateRow],
    interleaved_unique_decoding_rows: &'a [InterleavedUniqueDecodingRow],
    strong_state_hash_chain: &'a Cms19StrongStateHashChainCertificate,
    relation_compiler_interpreter_semantics: &'a RelationCompilerInterpreterSemanticCertificate,
    polynomial_protocol_extractor: &'a ExactPolynomialProtocolExtractorCertificate,
    point_constraint_extractor: &'a ExactPointConstraintExtractorCertificate,
    exact_failure_magnitude: &'a ExactFailureMagnitudeCertificate,
}

fn derive_cms19_state_predicate_certificate(
    input: Cms19StatePredicateCertificateInput<'_>,
) -> Cms19StatePredicateCertificate {
    let Cms19StatePredicateCertificateInput {
        selected_plan_state_predicate,
        plan,
        code_state_rows,
        interleaved_unique_decoding_rows,
        strong_state_hash_chain,
        relation_compiler_interpreter_semantics,
        polynomial_protocol_extractor,
        point_constraint_extractor,
        exact_failure_magnitude,
    } = input;
    let selected_plan_state_is_total = selected_plan_state_predicate.is_total_for_plan(plan);
    let expected_code_state_count = plan
        .whir
        .rounds
        .len()
        .checked_add(1)
        .and_then(|epoch_count| {
            plan.parameters
                .folding_factor
                .checked_add(1)
                .and_then(|state_count| epoch_count.checked_mul(state_count))
        });
    let selected_geometry_is_strict = expected_code_state_count == Some(code_state_rows.len())
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
    let expected_interleaving_lane_count = u32::try_from(plan.parameters.folding_factor)
        .ok()
        .and_then(|folding_factor| 1_usize.checked_shl(folding_factor));
    let interleaved_distance_is_exact = expected_code_state_count
        == Some(interleaved_unique_decoding_rows.len())
        && interleaved_unique_decoding_rows.iter().all(|row| {
            Some(row.lane_count) == expected_interleaving_lane_count
                && row.constituent_minimum_distance == row.interleaved_minimum_distance
                && row.selected_state_error_count_ceiling
                    < (row.interleaved_minimum_distance - 1) / 2
                && row.unique_decoding_list_size_ceiling == 1
                && row.lower_bound_uses_nonzero_component
                && row.upper_bound_uses_one_nonzero_component
        });
    let requirements = [
        (
            StatePredicateRequirement::OriginalBcsStrongStateRuntimeHashChainCorrespondence,
            StatePredicateDischargeAuthority::GeneratedStrongStateTypedOracleCorrespondence,
            strong_state_hash_chain.is_complete(),
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
            StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor,
            polynomial_protocol_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExtractCompleteBoundCodewords,
            StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor,
            polynomial_protocol_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExtractCompleteWhirEpochCodewords,
            StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor,
            polynomial_protocol_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExplicitPointConstraintExtractorCorrespondence,
            StatePredicateDischargeAuthority::CheckedExplicitPointConstraintExtractor,
            point_constraint_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExtractThetaAndPhaseReductions,
            StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor,
            polynomial_protocol_extractor.is_complete() && point_constraint_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExactFailureMagnitudeCorrespondence,
            StatePredicateDischargeAuthority::CheckedExactFailureMagnitudeCorrespondence,
            exact_failure_magnitude.is_complete(),
        ),
        (
            StatePredicateRequirement::ExtractCompilerInterpreterRelationWitness,
            StatePredicateDischargeAuthority::IndependentCompilerInterpreterArithmeticOracle,
            relation_compiler_interpreter_semantics.is_complete(),
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
        ideal_oracle_penalty_denominator_bit_length: CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
    }
}

const EXACT_FAILURE_OWNER_COUNTS: [(ExactFailureOwnerKind, usize); 19] = [
    (ExactFailureOwnerKind::NonNativeThetaProduct, 3),
    (ExactFailureOwnerKind::NonNativeAlphaProduct, 0),
    (ExactFailureOwnerKind::RelationComposition, 4_046),
    (ExactFailureOwnerKind::OutOfDomainPoint, 1),
    (ExactFailureOwnerKind::PointSelector, 18),
    (ExactFailureOwnerKind::TraceColumnGroup, 63),
    (ExactFailureOwnerKind::QuotientGroup, 1),
    (ExactFailureOwnerKind::OpeningBatchMask, 1),
    (ExactFailureOwnerKind::BoundOpening, 44),
    (ExactFailureOwnerKind::BoundDegreeCoordinate, 50),
    (ExactFailureOwnerKind::OuterQueryVector, 1),
    (ExactFailureOwnerKind::BoundQueryVector, 1),
    (ExactFailureOwnerKind::WhirQueryVector, 7),
    (ExactFailureOwnerKind::WhirOpeningBatching, 1),
    (ExactFailureOwnerKind::MaskedSumcheckEpsilon, 6),
    (ExactFailureOwnerKind::MaskedSumcheckFold, 18),
    (ExactFailureOwnerKind::RoundCheckpoint, 5),
    (ExactFailureOwnerKind::RoundCombination, 5),
    (ExactFailureOwnerKind::BaseCaseBlinding, 1),
];

fn exact_failure_owner_kind(
    owner: SelectedPlanFailureEventOwner,
) -> Result<ExactFailureOwnerKind, WhirTheoremCertificateError> {
    match owner {
        SelectedPlanFailureEventOwner::CommonProductChallenge {
            challenge: CommonProofChallenge::Theta { .. },
        } => Ok(ExactFailureOwnerKind::NonNativeThetaProduct),
        SelectedPlanFailureEventOwner::CommonProductChallenge {
            challenge: CommonProofChallenge::Alpha { .. },
        } => Ok(ExactFailureOwnerKind::NonNativeAlphaProduct),
        SelectedPlanFailureEventOwner::CommonExtensionChallenge {
            challenge: CommonProofChallenge::Composition { .. },
        } => Ok(ExactFailureOwnerKind::RelationComposition),
        SelectedPlanFailureEventOwner::CommonExtensionChallenge {
            challenge: CommonProofChallenge::OutOfDomainPoint { .. },
        } => Ok(ExactFailureOwnerKind::OutOfDomainPoint),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::PointSelectorWeight { .. },
        } => Ok(ExactFailureOwnerKind::PointSelector),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::TraceColumnGroupWeight { .. },
        } => Ok(ExactFailureOwnerKind::TraceColumnGroup),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::QuotientGroupWeight { .. },
        } => Ok(ExactFailureOwnerKind::QuotientGroup),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::OpeningBatchMaskWeight { .. },
        } => Ok(ExactFailureOwnerKind::OpeningBatchMask),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::BoundOpeningWeight { .. },
        } => Ok(ExactFailureOwnerKind::BoundOpening),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::BoundDegreeCoordinate { .. },
        } => Ok(ExactFailureOwnerKind::BoundDegreeCoordinate),
        SelectedPlanFailureEventOwner::DistinctQueryVector {
            role: RowCodeWhirQueryRole::Outer,
        } => Ok(ExactFailureOwnerKind::OuterQueryVector),
        SelectedPlanFailureEventOwner::DistinctQueryVector {
            role: RowCodeWhirQueryRole::Bound,
        } => Ok(ExactFailureOwnerKind::BoundQueryVector),
        SelectedPlanFailureEventOwner::DistinctQueryVector {
            role: RowCodeWhirQueryRole::WhirEpoch { .. },
        } => Ok(ExactFailureOwnerKind::WhirQueryVector),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::OpeningBatching,
        } => Ok(ExactFailureOwnerKind::WhirOpeningBatching),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { .. },
        } => Ok(ExactFailureOwnerKind::MaskedSumcheckEpsilon),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::MaskedSumcheckRound { .. },
        } => Ok(ExactFailureOwnerKind::MaskedSumcheckFold),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::RoundCheckpoint { .. },
        } => Ok(ExactFailureOwnerKind::RoundCheckpoint),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::RoundCombination { .. },
        } => Ok(ExactFailureOwnerKind::RoundCombination),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::BaseCaseBlinding,
        } => Ok(ExactFailureOwnerKind::BaseCaseBlinding),
        _ => Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence),
    }
}

fn derive_exact_failure_owner_rows(
    selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
) -> Result<Vec<ExactFailureOwnerRow>, WhirTheoremCertificateError> {
    let mut counts = EXACT_FAILURE_OWNER_COUNTS
        .iter()
        .map(|(kind, _)| (*kind, 0_usize))
        .collect::<BTreeMap<_, _>>();
    for owner in selected_plan_state_predicate
        .transition_rows
        .iter()
        .filter_map(|row| row.failure_event_owner)
    {
        let kind = exact_failure_owner_kind(owner)?;
        let count = counts
            .get_mut(&kind)
            .ok_or(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
        *count = count
            .checked_add(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    }
    Ok(EXACT_FAILURE_OWNER_COUNTS
        .iter()
        .map(|(kind, expected_transition_count)| ExactFailureOwnerRow {
            kind: *kind,
            transition_count: counts.get(kind).copied().unwrap_or(0),
            expected_transition_count: *expected_transition_count,
        })
        .collect())
}

fn derive_exact_theta_failure_rows(
    relation_variant: &RelationPlanVariant,
    catalog: &RowCodeWhirOracleEquationCatalog,
) -> Result<Vec<ExactThetaFailureRow>, WhirTheoremCertificateError> {
    let mut degrees_by_challenge = BTreeMap::<CommonProofChallenge, BTreeMap<u16, u64>>::new();
    for batch in relation_variant.ordered_integer_lift_batches() {
        let challenge = CommonProofChallenge::Theta {
            modulus_ordinal: relation_variant
                .non_native_modulus_ordinal(batch.modulus_reference())
                .map_err(|_| {
                    WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence
                })?,
        };
        let degree = batch
            .theta_bad_polynomial_degree(relation_variant.trace_domain_size())
            .map_err(|_| WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
        if degrees_by_challenge
            .entry(challenge)
            .or_default()
            .insert(batch.challenge_ordinal(), degree)
            .is_some()
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
    }

    let mut rows = Vec::new();
    for operation in &catalog.operations {
        let RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(group) = operation.kind
        else {
            continue;
        };
        let challenge = group.challenge();
        if !matches!(challenge, CommonProofChallenge::Theta { .. }) {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        let ordered_degrees = degrees_by_challenge
            .remove(&challenge)
            .ok_or(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
        if group.modulus() != PROOF_BASE_FIELD_MODULUS
            || usize::from(group.coordinate_count()) != PROOF_CHALLENGE_EXTENSION_DEGREE
            || ordered_degrees.len() != usize::from(group.coordinate_count())
            || !ordered_degrees
                .keys()
                .copied()
                .eq(0..group.coordinate_count())
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        let ordered_bad_polynomial_degrees = ordered_degrees.into_values().collect::<Vec<_>>();
        if ordered_bad_polynomial_degrees != vec![32_766_u64; PROOF_CHALLENGE_EXTENSION_DEGREE] {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        rows.push(ExactThetaFailureRow {
            challenge,
            bad_set_numerator: ordered_bad_polynomial_degrees
                .iter()
                .copied()
                .map(BigUint::from)
                .product(),
            sample_space_denominator: BigUint::from(group.modulus())
                .pow(u32::from(group.coordinate_count())),
            ordered_bad_polynomial_degrees,
        });
    }
    rows.sort_by_key(|row| row.challenge);
    if !degrees_by_challenge.is_empty() || rows.len() != 3 {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    Ok(rows)
}

fn derive_exact_query_failure_rows(
    plan: &RowCodeWhirConstructionPlan,
    code_state_rows: &[WhirCodeStateRow],
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
) -> Result<Vec<ExactQueryFailureRow>, WhirTheoremCertificateError> {
    let shared_partition = selected_shared_query_partition();
    if shared_partition.map(|row| row.class)
        != [
            SharedQueryEventClass::OuterOpeningPointWords,
            SharedQueryEventClass::RelationPhaseColumns,
            SharedQueryEventClass::BoundTreeWords,
            SharedQueryEventClass::StatementRootWords,
        ]
        || shared_partition.iter().any(|row| {
            !row.words_fixed_before_sampling
                || !row.shares_one_query_vector
                || row.charged_term_count != 1
        })
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let bound_population = plan
        .bound_trees
        .first()
        .map(|tree| tree.leaf_count)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if plan.bound_trees.len() != 11
        || plan
            .bound_trees
            .iter()
            .any(|tree| tree.leaf_count != bound_population)
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let bound_population = u64::try_from(bound_population)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let outer_population = ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE;
    let shared_geometries = [
        (
            ExactQueryFailureEvent::OuterOpeningPointWords,
            ExactFailureOwnerKind::OuterQueryVector,
            outer_population,
            outer_population * 5 / 8,
        ),
        (
            ExactQueryFailureEvent::RelationPhaseColumns,
            ExactFailureOwnerKind::OuterQueryVector,
            outer_population,
            outer_population * 5 / 8,
        ),
        (
            ExactQueryFailureEvent::BoundTreeWords,
            ExactFailureOwnerKind::BoundQueryVector,
            bound_population,
            9_217,
        ),
        (
            ExactQueryFailureEvent::StatementRootWords,
            ExactFailureOwnerKind::BoundQueryVector,
            bound_population,
            bound_population * 65 / 128,
        ),
    ];
    let mut rows = Vec::with_capacity(
        shared_partition
            .len()
            .checked_add(
                plan.whir
                    .rounds
                    .len()
                    .checked_add(2)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    for (partition_row, (event, sponsoring_owner, population, agreement_ceiling)) in
        shared_partition.into_iter().zip(shared_geometries)
    {
        rows.push(ExactQueryFailureRow::derive(
            event,
            sponsoring_owner,
            partition_row.word_count,
            population,
            agreement_ceiling,
            u64::try_from(partition_row.sampled_coordinate_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            u64::try_from(partition_row.charged_term_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?);
    }

    let terminal_fold_ordinal = u32::try_from(plan.parameters.folding_factor)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut source_states = code_state_rows
        .iter()
        .copied()
        .filter(|row| row.fold_ordinal == terminal_fold_ordinal)
        .collect::<Vec<_>>();
    source_states.sort_by_key(|row| row.epoch_ordinal);
    let expected_source_epoch_count = plan
        .whir
        .rounds
        .len()
        .checked_add(1)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if source_states.len() != expected_source_epoch_count
        || source_states
            .iter()
            .enumerate()
            .any(|(epoch_index, row)| usize::try_from(row.epoch_ordinal).ok() != Some(epoch_index))
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    for (epoch_index, code_state) in source_states.into_iter().enumerate() {
        let (message_length, randomness_length, domain_size, query_count, interleaving_width) =
            aggregate_wide_masking
                .folded_source_code_geometry(epoch_index)
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        if domain_size != usize::try_from(code_state.domain_size).unwrap_or(usize::MAX)
            || message_length.checked_add(randomness_length)
                != Some(
                    usize::try_from(code_state.dimension)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
            || interleaving_width
                != 1_usize
                    .checked_shl(
                        u32::try_from(plan.parameters.folding_factor)
                            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                    )
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        rows.push(ExactQueryFailureRow::derive(
            ExactQueryFailureEvent::WhirSource {
                epoch_ordinal: code_state.epoch_ordinal,
            },
            ExactFailureOwnerKind::WhirQueryVector,
            1,
            code_state.domain_size,
            code_state
                .domain_size
                .checked_sub(code_state.false_state_minimum_error_count)
                .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
            u64::try_from(query_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            1,
        )?);
    }

    let (pad_message_length, pad_randomness_length, pad_domain_size, pad_query_count, pad_width) =
        aggregate_wide_masking.pad_code_geometry();
    let pad_dimension = pad_message_length
        .checked_add(pad_randomness_length)
        .and_then(|dimension| dimension.checked_mul(pad_width))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_domain_size = u64::try_from(pad_domain_size)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_dimension = u64::try_from(pad_dimension)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_unique_decoding_radius = pad_domain_size
        .checked_sub(pad_dimension)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?
        / 2;
    let pad_selected_distance = ExactFraction::new(
        pad_unique_decoding_radius
            .checked_sub(1)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
        pad_domain_size,
    )?;
    let pad_epoch_ordinal = u32::try_from(expected_source_epoch_count)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_code_state = WhirCodeStateRow::derive(
        pad_epoch_ordinal,
        0,
        pad_domain_size,
        pad_dimension,
        pad_selected_distance,
    )?;
    rows.push(ExactQueryFailureRow::derive(
        ExactQueryFailureEvent::AggregateWidePad,
        ExactFailureOwnerKind::WhirQueryVector,
        1,
        pad_code_state.domain_size,
        pad_code_state
            .domain_size
            .checked_sub(pad_code_state.false_state_minimum_error_count)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
        u64::try_from(pad_query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        1,
    )?);
    Ok(rows)
}

fn exact_owner_count(
    owner_rows: &[ExactFailureOwnerRow],
    kind: ExactFailureOwnerKind,
) -> Result<u64, WhirTheoremCertificateError> {
    let count = owner_rows
        .iter()
        .find(|row| row.kind == kind)
        .map(|row| row.transition_count)
        .ok_or(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
    u64::try_from(count).map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)
}

#[derive(Clone, Copy)]
struct ExactFailureMagnitudeDerivationInput<'a> {
    plan: &'a RowCodeWhirConstructionPlan,
    relation_variant: &'a RelationPlanVariant,
    catalog: &'a RowCodeWhirOracleEquationCatalog,
    selected_plan_state_predicate: &'a SelectedPlanStatePredicateCertificate,
    code_state_rows: &'a [WhirCodeStateRow],
    fold_rows: &'a [WhirFoldFailureRow],
    shift_rows: &'a [WhirShiftFailureRow],
    aggregate_wide_masking: &'a AggregateWideMaskingCertificate,
    initial_constraint_batch_numerator: u64,
    logical_verifier_message_count: u64,
    cms19_arithmetic: &'a Cms19ArithmeticCertificate,
}

fn derive_exact_algebraic_failure_rows(
    input: ExactFailureMagnitudeDerivationInput<'_>,
    owner_rows: &[ExactFailureOwnerRow],
    theta_rows: &[ExactThetaFailureRow],
) -> Result<Vec<ExactAlgebraicFailureRow>, WhirTheoremCertificateError> {
    let ExactFailureMagnitudeDerivationInput {
        plan,
        code_state_rows,
        fold_rows,
        shift_rows,
        aggregate_wide_masking,
        initial_constraint_batch_numerator,
        ..
    } = input;
    let theta_numerator = theta_rows
        .iter()
        .map(|row| row.bad_set_numerator.clone())
        .sum::<BigUint>();
    let opening_point_count = plan
        .aggregate_column_roles
        .iter()
        .filter(|role| matches!(role, RowCodeWhirAggregateColumnRole::OpeningPoint { .. }))
        .count();
    let outer_population = ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE;
    let bound_population = u64::try_from(
        plan.bound_trees
            .first()
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?
            .leaf_count,
    )
    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let exceptional_set_numerator = outer_population
        .checked_add(
            outer_population
                .checked_mul(
                    u64::try_from(opening_point_count)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .and_then(|total| {
            bound_population
                .checked_mul(u64::try_from(plan.aggregate_column_roles.len()).ok()?)
                .and_then(|bound| total.checked_add(bound))
        })
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let phase_batch_numerator = u64::try_from(opening_point_count)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        .checked_mul(
            u64::try_from(SELECTED_AGGREGATE_TABLE_WIDTH)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let fold_numerator = fold_rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.total_numerator()?)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })?;
    let shift_numerator = shift_rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.algebraic_numerator)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })?;
    let final_source_epoch_ordinal = u32::try_from(plan.whir.rounds.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let final_source_domain_size = code_state_rows
        .iter()
        .find(|row| {
            row.epoch_ordinal == final_source_epoch_ordinal
                && usize::try_from(row.fold_ordinal).ok() == Some(plan.parameters.folding_factor)
        })
        .map(|row| row.domain_size)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let base_blinding_numerator = final_source_domain_size
        .checked_add(
            u64::try_from(aggregate_wide_masking.pad_domain_size())
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .and_then(|value| value.checked_add(1))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

    Ok(vec![
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::NonNativeThetaExtraction,
            owner_kinds: vec![ExactFailureOwnerKind::NonNativeThetaProduct],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::NonNativeThetaProduct,
            )?,
            numerator: theta_numerator,
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::RelationCompositionBatch,
            owner_kinds: vec![ExactFailureOwnerKind::RelationComposition],
            theorem_event_count: 1,
            numerator: BigUint::one(),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::OpeningPointExceptionalSets,
            owner_kinds: vec![ExactFailureOwnerKind::OutOfDomainPoint],
            theorem_event_count: 1,
            numerator: BigUint::from(exceptional_set_numerator),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::PhaseRowAndSelectorBatching,
            owner_kinds: vec![
                ExactFailureOwnerKind::PointSelector,
                ExactFailureOwnerKind::TraceColumnGroup,
                ExactFailureOwnerKind::QuotientGroup,
            ],
            theorem_event_count: phase_batch_numerator,
            numerator: BigUint::from(phase_batch_numerator),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::OpeningBatchMaskConsistency,
            owner_kinds: vec![ExactFailureOwnerKind::OpeningBatchMask],
            theorem_event_count: 0,
            numerator: BigUint::zero(),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::BoundOpeningBatch,
            owner_kinds: vec![ExactFailureOwnerKind::BoundOpening],
            theorem_event_count: 1,
            numerator: BigUint::one(),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::BoundDegreeSuffixes,
            owner_kinds: vec![ExactFailureOwnerKind::BoundDegreeCoordinate],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::BoundDegreeCoordinate,
            )?,
            numerator: BigUint::from(exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::BoundDegreeCoordinate,
            )?),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::WhirOpeningBatch,
            owner_kinds: vec![ExactFailureOwnerKind::WhirOpeningBatching],
            theorem_event_count: 1,
            numerator: BigUint::from(initial_constraint_batch_numerator),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::MaskedSumcheckInitialTransitions,
            owner_kinds: vec![ExactFailureOwnerKind::MaskedSumcheckEpsilon],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::MaskedSumcheckEpsilon,
            )?,
            numerator: BigUint::from(exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::MaskedSumcheckEpsilon,
            )?),
        },
        // CFW Construction 6.3 and Lemma 6.5 contribute the WHIR mutual
        // correlated-agreement domain numerator plus the cubic sumcheck term
        // for each of the fifteen masked folds.
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::MaskedSumcheckFolds,
            owner_kinds: vec![ExactFailureOwnerKind::MaskedSumcheckFold],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::MaskedSumcheckFold,
            )?,
            numerator: BigUint::from(fold_numerator),
        },
        // The checkpoint scalar is sampled and transcript-bound but is not an
        // algebraic input. Its following query vector owns the query event.
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::RoundCommitmentCheckpoints,
            owner_kinds: vec![ExactFailureOwnerKind::RoundCheckpoint],
            theorem_event_count: 0,
            numerator: BigUint::zero(),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::WhirQueryCombinations,
            owner_kinds: vec![ExactFailureOwnerKind::RoundCombination],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::RoundCombination,
            )?,
            numerator: BigUint::from(shift_numerator),
        },
        // CFW Construction 7.2 and Lemma 7.4 give one source-code MCA term,
        // one pad-code MCA term, and the singleton list-product term.
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::AggregateWideBaseBlinding,
            owner_kinds: vec![ExactFailureOwnerKind::BaseCaseBlinding],
            theorem_event_count: 1,
            numerator: BigUint::from(base_blinding_numerator),
        },
    ])
}

fn exact_failure_owners_are_completely_mapped(
    owner_rows: &[ExactFailureOwnerRow],
    query_rows: &[ExactQueryFailureRow],
    algebraic_rows: &[ExactAlgebraicFailureRow],
) -> bool {
    let expected = owner_rows
        .iter()
        .filter(|row| row.transition_count > 0)
        .map(|row| row.kind)
        .collect::<BTreeSet<_>>();
    let query_sponsors = query_rows
        .iter()
        .map(|row| row.sponsoring_owner)
        .collect::<BTreeSet<_>>();
    let mut algebraic_owners = BTreeSet::new();
    for kind in algebraic_rows
        .iter()
        .flat_map(|row| row.owner_kinds.iter().copied())
    {
        if !algebraic_owners.insert(kind) {
            return false;
        }
    }
    query_sponsors.is_disjoint(&algebraic_owners)
        && query_sponsors
            .union(&algebraic_owners)
            .copied()
            .collect::<BTreeSet<_>>()
            == expected
}

fn sum_query_probability_ceiling(
    query_rows: &[ExactQueryFailureRow],
) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
    query_rows
        .iter()
        .try_fold(ExactBigFraction::zero(), |total, row| {
            total.add(&row.charged_power_ceiling()?)
        })
}

fn sum_algebraic_numerator(algebraic_rows: &[ExactAlgebraicFailureRow]) -> BigUint {
    algebraic_rows.iter().map(|row| row.numerator.clone()).sum()
}

fn derive_exact_failure_magnitude_certificate(
    input: ExactFailureMagnitudeDerivationInput<'_>,
) -> Result<ExactFailureMagnitudeCertificate, WhirTheoremCertificateError> {
    derive_exact_failure_magnitude_certificate_with_mutation(input, |_| {})
}

fn derive_exact_failure_magnitude_certificate_with_mutation(
    input: ExactFailureMagnitudeDerivationInput<'_>,
    mutate: impl FnOnce(&mut ExactFailureMagnitudeCertificate),
) -> Result<ExactFailureMagnitudeCertificate, WhirTheoremCertificateError> {
    let ExactFailureMagnitudeDerivationInput {
        plan,
        relation_variant,
        catalog,
        selected_plan_state_predicate,
        code_state_rows,
        aggregate_wide_masking,
        logical_verifier_message_count,
        cms19_arithmetic,
        ..
    } = input;
    let owner_rows = derive_exact_failure_owner_rows(selected_plan_state_predicate)?;
    if owner_rows
        .iter()
        .any(|row| row.transition_count != row.expected_transition_count)
        || owner_rows.iter().try_fold(0_u64, |total, row| {
            total.checked_add(u64::try_from(row.transition_count).ok()?)
        }) != Some(logical_verifier_message_count)
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let query_rows =
        derive_exact_query_failure_rows(plan, code_state_rows, aggregate_wide_masking)?;
    let theta_rows = derive_exact_theta_failure_rows(relation_variant, catalog)?;
    let extension_field_cardinality = BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    if theta_rows
        .iter()
        .any(|row| row.sample_space_denominator != extension_field_cardinality)
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let algebraic_rows = derive_exact_algebraic_failure_rows(input, &owner_rows, &theta_rows)?;
    let query_failure_probability_ceiling = sum_query_probability_ceiling(&query_rows)?;
    let algebraic_failure_probability_ceiling = ExactBigFraction::new(
        sum_algebraic_numerator(&algebraic_rows),
        extension_field_cardinality.clone(),
    )?;
    let classical_failure_probability_ceiling =
        query_failure_probability_ceiling.add(&algebraic_failure_probability_ceiling)?;
    let ideal_oracle_penalty = ExactBigFraction::new(
        cms19_arithmetic.ideal_oracle_penalty_numerator.clone(),
        BigUint::one() << cms19_arithmetic.ideal_oracle_penalty_denominator_bit_length,
    )?;
    let qrom_failure_probability_ceiling = classical_failure_probability_ceiling
        .multiply_integer(&cms19_arithmetic.classical_soundness_multiplier)?
        .add(&ideal_oracle_penalty)?;
    let same_secret_family_multiplicity = u64::from(
        crate::bgv::proof_suite::selected_profile::selected_proof_application_slot_ceilings()
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?
            .family_ceiling(ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
    );
    let one = ExactBigFraction::from_u64(1, 1)?;
    let ordinary_family_mass_gate_holds = classical_failure_probability_ceiling
        .multiply_integer(
            &(BigUint::from(same_secret_family_multiplicity) << CMS19_ADVERSARIAL_QUERY_EXPONENT),
        )?
        .less_than_or_equal(&one);
    let transformed_initial_mass_gate_holds = classical_failure_probability_ceiling
        .multiply_integer(&(BigUint::from(same_secret_family_multiplicity * 12) << 176_usize))?
        .less_than_or_equal(&one);
    let complete_qrom_mass_gate_holds = qrom_failure_probability_ceiling
        .multiply_u64(
            same_secret_family_multiplicity
                .checked_mul(4)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?
        .less_than_or_equal(&one);
    let all_failure_owners_mapped_once =
        exact_failure_owners_are_completely_mapped(&owner_rows, &query_rows, &algebraic_rows);
    let exact_query_products_bounded = query_rows.iter().all(|row| {
        row.exact_without_replacement_probability
            .less_than_or_equal(&row.power_probability_ceiling)
    });
    let mut certificate = ExactFailureMagnitudeCertificate {
        owner_rows,
        query_rows,
        theta_rows,
        algebraic_rows,
        extension_field_cardinality,
        query_failure_probability_ceiling,
        algebraic_failure_probability_ceiling,
        classical_failure_probability_ceiling,
        qrom_failure_probability_ceiling,
        same_secret_family_multiplicity,
        cms19_verifier_hash_query_count: cms19_arithmetic.verifier_hash_query_count,
        cms19_accepting_database_equation_count: cms19_arithmetic.accepting_database_equation_count,
        all_failure_owners_mapped_once,
        exact_query_products_bounded,
        ordinary_family_mass_gate_holds,
        transformed_initial_mass_gate_holds,
        complete_qrom_mass_gate_holds,
    };
    mutate(&mut certificate);
    validate_exact_failure_magnitude_certificate(&certificate, input)?;
    Ok(certificate)
}

fn validate_exact_failure_magnitude_certificate(
    certificate: &ExactFailureMagnitudeCertificate,
    input: ExactFailureMagnitudeDerivationInput<'_>,
) -> Result<(), WhirTheoremCertificateError> {
    let ExactFailureMagnitudeDerivationInput {
        plan,
        relation_variant,
        catalog,
        selected_plan_state_predicate,
        code_state_rows,
        aggregate_wide_masking,
        logical_verifier_message_count,
        cms19_arithmetic,
        ..
    } = input;
    let expected_owner_rows = derive_exact_failure_owner_rows(selected_plan_state_predicate)?;
    let expected_query_rows =
        derive_exact_query_failure_rows(plan, code_state_rows, aggregate_wide_masking)?;
    let expected_theta_rows = derive_exact_theta_failure_rows(relation_variant, catalog)?;
    let expected_algebraic_rows =
        derive_exact_algebraic_failure_rows(input, &expected_owner_rows, &expected_theta_rows)?;
    let expected_extension_field_cardinality = BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    let expected_query_ceiling = sum_query_probability_ceiling(&expected_query_rows)?;
    let expected_algebraic_ceiling = ExactBigFraction::new(
        sum_algebraic_numerator(&expected_algebraic_rows),
        expected_extension_field_cardinality.clone(),
    )?;
    let expected_classical_ceiling = expected_query_ceiling.add(&expected_algebraic_ceiling)?;
    let expected_qrom_ceiling = expected_classical_ceiling
        .multiply_integer(&cms19_arithmetic.classical_soundness_multiplier)?
        .add(&ExactBigFraction::new(
            cms19_arithmetic.ideal_oracle_penalty_numerator.clone(),
            BigUint::one() << cms19_arithmetic.ideal_oracle_penalty_denominator_bit_length,
        )?)?;
    let expected_multiplicity = u64::from(
        crate::bgv::proof_suite::selected_profile::selected_proof_application_slot_ceilings()
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?
            .family_ceiling(ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
    );
    let one = ExactBigFraction::from_u64(1, 1)?;
    let expected_ordinary_gate = expected_classical_ceiling
        .multiply_integer(
            &(BigUint::from(expected_multiplicity) << CMS19_ADVERSARIAL_QUERY_EXPONENT),
        )?
        .less_than_or_equal(&one);
    let expected_transformed_gate = expected_classical_ceiling
        .multiply_integer(&(BigUint::from(expected_multiplicity * 12) << 176_usize))?
        .less_than_or_equal(&one);
    let expected_qrom_gate = expected_qrom_ceiling
        .multiply_u64(
            expected_multiplicity
                .checked_mul(4)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?
        .less_than_or_equal(&one);
    let expected_owner_count = expected_owner_rows.iter().try_fold(0_u64, |total, row| {
        total.checked_add(u64::try_from(row.transition_count).ok()?)
    });
    if certificate.owner_rows != expected_owner_rows
        || certificate.query_rows != expected_query_rows
        || certificate.theta_rows != expected_theta_rows
        || certificate.algebraic_rows != expected_algebraic_rows
        || certificate.extension_field_cardinality != expected_extension_field_cardinality
        || certificate.query_failure_probability_ceiling != expected_query_ceiling
        || certificate.algebraic_failure_probability_ceiling != expected_algebraic_ceiling
        || certificate.classical_failure_probability_ceiling != expected_classical_ceiling
        || certificate.qrom_failure_probability_ceiling != expected_qrom_ceiling
        || certificate.same_secret_family_multiplicity != expected_multiplicity
        || certificate.cms19_verifier_hash_query_count != cms19_arithmetic.verifier_hash_query_count
        || certificate.cms19_accepting_database_equation_count
            != cms19_arithmetic.accepting_database_equation_count
        || expected_owner_count != Some(logical_verifier_message_count)
        || certificate.all_failure_owners_mapped_once
            != exact_failure_owners_are_completely_mapped(
                &expected_owner_rows,
                &expected_query_rows,
                &expected_algebraic_rows,
            )
        || certificate.exact_query_products_bounded
            != expected_query_rows.iter().all(|row| {
                row.exact_without_replacement_probability
                    .less_than_or_equal(&row.power_probability_ceiling)
            })
        || certificate.ordinary_family_mass_gate_holds != expected_ordinary_gate
        || certificate.transformed_initial_mass_gate_holds != expected_transformed_gate
        || certificate.complete_qrom_mass_gate_holds != expected_qrom_gate
        || !certificate.is_complete()
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    Ok(())
}

#[cfg(test)]
fn checked_exact_failure_magnitude_with_fault(
    input: ExactFailureMagnitudeDerivationInput<'_>,
    fault: ExactFailureMagnitudeFault,
) -> Result<ExactFailureMagnitudeCertificate, WhirTheoremCertificateError> {
    derive_exact_failure_magnitude_certificate_with_mutation(input, |certificate| match fault {
        ExactFailureMagnitudeFault::DropFirstQueryRow => {
            certificate.query_rows.remove(0);
        }
        ExactFailureMagnitudeFault::ReduceFirstQueryAgreementCeiling => {
            certificate.query_rows[0].agreement_ceiling -= 1;
        }
        ExactFailureMagnitudeFault::DropRelationCompositionOwner => {
            certificate.algebraic_rows[1].owner_kinds.clear();
        }
        ExactFailureMagnitudeFault::ReduceAggregateWideBaseNumerator => {
            certificate.algebraic_rows[12].numerator -= BigUint::one();
        }
        ExactFailureMagnitudeFault::ChangeVerifierHashQueryCount => {
            certificate.cms19_verifier_hash_query_count += 1;
        }
    })
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
fn deployed_streaming_leaf_chain_refuses_a_uniform_512_bit_oracle_denominator() {
    let plan = selected_same_secret_construction_plan();
    let certificate = checked_row_code_whir_failure_partition(&plan)
        .expect("the construction accounting derives even though deployment is refused");
    let deployed = &certificate.deployed_aggregate_leaf_oracle;

    assert!(deployed.has_complete_call_inventory());
    assert_eq!(
        ColumnStreamableLeafHasher::intermediate_output_bit_length(),
        256
    );
    assert_eq!(ColumnStreamableLeafHasher::final_output_bit_length(), 512);
    assert_eq!(deployed.minimum_oracle_output_bit_length, 256);
    assert_eq!(deployed.collision_penalty_denominator_bit_length, 256);
    assert!(!deployed.uniform_required_output_geometry_established);
    assert!(!deployed.is_eligible_for_uniform_required_output());
    assert!(!deployed.classical_collision_penalty_is_below_inverse_power_of_two(128));
    assert!(!deployed.qrom_ideal_oracle_penalty_is_below_inverse_power_of_two(128));
    assert!(
        (&deployed.classical_collision_penalty_numerator << 128_usize)
            < (BigUint::one() << CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH)
    );
    assert!(
        (&deployed.qrom_ideal_oracle_penalty_numerator << 128_usize)
            < (BigUint::one() << CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH)
    );
    assert!(!certificate.cms19_applicability.is_complete());
    assert!(!certificate.is_complete_construction_theorem());
}

#[test]
fn one_transition_collision_propagates_through_the_shared_suffix_and_final_digest() {
    fn transition(state: u16, column_ordinal: usize, value: u16) -> u16 {
        if column_ordinal == 0 {
            value & 1
        } else {
            state.wrapping_mul(257).wrapping_add(value)
        }
    }
    fn leaf(values: &[u16]) -> u16 {
        let mut state = 19_u16;
        for (column_ordinal, value) in values.iter().copied().enumerate() {
            state = transition(state, column_ordinal, value);
        }
        state
            .wrapping_mul(769)
            .wrapping_add(u16::try_from(values.len()).expect("the test leaf width fits in u16"))
    }

    let first = [1_u16, 23, 29, 31];
    let second = [3_u16, 23, 29, 31];
    assert_ne!(first, second);
    assert_eq!(
        transition(19, 0, first[0]),
        transition(19, 0, second[0]),
        "the mock oracle supplies the one transition collision",
    );
    assert_eq!(
        leaf(&first),
        leaf(&second),
        "deterministic later transitions and finalization cannot repair a collided state",
    );
}

#[test]
fn generated_selected_whir_failure_partition_is_exact_and_mutation_sensitive() {
    let plan = selected_same_secret_construction_plan();
    let certificate = checked_row_code_whir_failure_partition(&plan)
        .expect("the checked WHIR theorem certificate derives");

    let mut challenge_kind_counts = [0_usize; 19];
    for owner in certificate
        .selected_plan_state_predicate
        .transition_rows
        .iter()
        .filter_map(|row| row.failure_event_owner)
    {
        let kind = match owner {
            SelectedPlanFailureEventOwner::CommonProductChallenge {
                challenge: CommonProofChallenge::Theta { .. },
            } => 0,
            SelectedPlanFailureEventOwner::CommonProductChallenge {
                challenge: CommonProofChallenge::Alpha { .. },
            } => 1,
            SelectedPlanFailureEventOwner::CommonExtensionChallenge {
                challenge: CommonProofChallenge::Composition { .. },
            } => 2,
            SelectedPlanFailureEventOwner::CommonExtensionChallenge {
                challenge: CommonProofChallenge::OutOfDomainPoint { .. },
            } => 3,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::PointSelectorWeight { .. },
            } => 4,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::TraceColumnGroupWeight { .. },
            } => 5,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::QuotientGroupWeight { .. },
            } => 6,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::OpeningBatchMaskWeight { .. },
            } => 7,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::BoundOpeningWeight { .. },
            } => 8,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::BoundDegreeCoordinate { .. },
            } => 9,
            SelectedPlanFailureEventOwner::DistinctQueryVector {
                role: RowCodeWhirQueryRole::Outer,
            } => 10,
            SelectedPlanFailureEventOwner::DistinctQueryVector {
                role: RowCodeWhirQueryRole::Bound,
            } => 11,
            SelectedPlanFailureEventOwner::DistinctQueryVector {
                role: RowCodeWhirQueryRole::WhirEpoch { .. },
            } => 12,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::OpeningBatching,
            } => 13,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { .. },
            } => 14,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::MaskedSumcheckRound { .. },
            } => 15,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::RoundCheckpoint { .. },
            } => 16,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::RoundCombination { .. },
            } => 17,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::BaseCaseBlinding,
            } => 18,
            _ => unreachable!("selected failure owner is outside the closed schedule"),
        };
        challenge_kind_counts[kind] += 1;
    }
    assert_eq!(
        challenge_kind_counts,
        [
            3, 0, 4_046, 1, 18, 63, 1, 1, 44, 50, 1, 1, 7, 1, 6, 18, 5, 5, 1
        ],
    );

    assert_eq!(certificate.code_state_rows.len(), 24);
    assert_eq!(certificate.fold_rows.len(), 18);
    assert_eq!(certificate.shift_rows.len(), 5);
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
        Some(vec![
            58_720_265, 29_360_137, 14_680_073, 7_340_041, 3_670_025, 1_835_017,
        ]),
    );
    assert_eq!(certificate.fold_numerator(), Ok(115_605_558));
    assert_eq!(
        certificate
            .shift_rows
            .iter()
            .map(|row| row.algebraic_numerator)
            .collect::<Vec<_>>(),
        [388, 289, 269, 265, 264],
    );
    assert_eq!(certificate.shift_numerator(), Ok(1_475));
    assert_eq!(certificate.initial_constraint_batch_numerator(), 1_781);
    assert_eq!(certificate.final_sumcheck_numerator(), 0);
    assert_eq!(certificate.final_query_row.epoch_ordinal, 5);
    assert_eq!(certificate.final_query_row.query_count, 263);
    // The terminal source code includes 64 logical coefficients and 263
    // private encoding coefficients. Its domain is `262,144`, dimension is
    // therefore `327`, and a false state agrees in at most `131,236`
    // positions, or `32,809 / 65,536` in lowest terms.
    assert_eq!(
        certificate.final_query_row.bad_agreement,
        ExactFraction::new(32_809, 65_536).expect("the fraction is valid"),
    );
    assert_eq!(certificate.prefix_stacking.source_table_count, 1);
    assert_eq!(certificate.prefix_stacking.committed_polynomial_count, 1);
    assert_eq!(certificate.prefix_stacking.table_variable_count, 22);
    assert_eq!(certificate.prefix_stacking.selector_variable_count, 2);
    assert_eq!(certificate.prefix_stacking.stacked_variable_count, 24);
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
        (0_u32..6)
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
        [0, 1, 2, 3, 4],
    );
    assert_eq!(
        certificate.maximum_transcript_hash_query_count,
        SELECTED_TRANSCRIPT_HASH_QUERY_COUNT,
    );
    assert_eq!(
        certificate.logical_verifier_message_count,
        SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT,
    );
    let transcript_role_equation_count = |role| {
        certificate
            .oracle_equation_rows
            .iter()
            .filter(|row| row.role_pattern == OracleEquationRolePattern::Single(role))
            .map(|row| row.equation_count)
            .sum::<u64>()
    };
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::ResponseRoot),
        2_059,
    );
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::ResponseBinding),
        2_034,
    );
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::ResponseAbsorption),
        2_071,
    );
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::AcceptedChallenge),
        4_272,
    );
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::ChallengeHandle),
        4_272,
    );
    let verifier_ledger = &certificate.complete_verifier_oracle_ledger;
    assert_eq!(verifier_ledger.transcript_equation_count, 1_141_598);
    assert_eq!(verifier_ledger.transcript_hash_query_count, 1_141_598);
    assert_eq!(verifier_ledger.merkle_rows.len(), 23);
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
                16_777_216,
                387,
            ),
            (
                MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Auxiliary,
                },
                16_777_216,
                387,
            ),
            (
                MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Quotient,
                },
                16_777_216,
                387,
            ),
        ],
    );
    assert_eq!(
        verifier_ledger.merkle_rows[14..20]
            .iter()
            .map(|row| (row.role, row.leaf_count, row.query_count))
            .collect::<Vec<_>>(),
        [
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 },
                8_388_608,
                387,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 1 },
                4_194_304,
                288,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 2 },
                2_097_152,
                268,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 3 },
                1_048_576,
                264,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 4 },
                524_288,
                263,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 5 },
                262_144,
                263,
            ),
        ],
    );
    assert_eq!(
        verifier_ledger.merkle_rows[20..]
            .iter()
            .map(|row| (row.role, row.leaf_count, row.query_count))
            .collect::<Vec<_>>(),
        [
            (
                MerkleOracleEquationRole::AggregateWideMask {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad,
                },
                8_192,
                393,
            ),
            (
                MerkleOracleEquationRole::AggregateWideMask {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource,
                },
                262_144,
                263,
            ),
            (
                MerkleOracleEquationRole::AggregateWideMask {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad,
                },
                8_192,
                393,
            ),
        ],
    );
    assert!(
        verifier_ledger
            .merkle_rows
            .iter()
            .all(|row| row.predecessor_support_ceiling <= 2)
    );
    assert_eq!(verifier_ledger.merkle_hash_query_count(), Ok(73_047));
    assert_eq!(
        verifier_ledger.merkle_rows[..3]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("phase row count"))
            }),
        Some(20_109),
    );
    assert_eq!(
        verifier_ledger.merkle_rows[3..14]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("bound row count"))
            }),
        Some(19_767),
    );
    assert_eq!(
        verifier_ledger.merkle_rows[14..20]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("WHIR row count"))
            }),
        Some(25_078),
    );
    assert_eq!(
        verifier_ledger.merkle_rows[20..]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("mask row count"))
            }),
        Some(8_093),
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
    // ceiling of `73,047` plus the fixed rows: `1,141,598 + 73,047 + 13 =
    // 1,214,658` equations and `1,141,598 + 73,047 + 22 = 1,214,667` hash
    // queries. The Merkle and fixed components are independent of the
    // transcript catalog, and the two totals now differ only by the fixed
    // distinct-equation and hash-query rows because the catalog charges one
    // equation per hash query.
    assert_eq!(verifier_ledger.complete_equation_count_ceiling, 1_214_658);
    assert_eq!(verifier_ledger.complete_hash_query_count, 1_214_667);
    assert!(certificate.commitment_subtree_extraction.is_complete());
    assert_eq!(certificate.commitment_subtree_extraction.rows.len(), 23);
    assert_eq!(
        certificate
            .commitment_subtree_extraction
            .supplied_commitment_root_count,
        12,
    );
    assert!(
        certificate
            .commitment_subtree_extraction
            .canonical_complete_message_count
            > 0,
    );
    assert!(
        certificate
            .commitment_subtree_extraction
            .one_edge_sampler_message_count
            > 0,
    );
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
        1_214_667
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
        Cms19Transform::OriginalBcsStrongStateHashChainSectionEightSix,
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
        certificate
            .cms19_applicability
            .complete_state_predicate_established
    );
    assert!(
        certificate
            .cms19_applicability
            .syntactic_proposition_eight_twelve_partition_catalogued
    );
    assert!(
        certificate
            .cms19_applicability
            .proposition_eight_twelve_case_split_established
    );
    assert!(
        certificate
            .cms19_applicability
            .complete_query_ledger_correspondence_established
    );
    assert!(
        certificate
            .cms19_applicability
            .strong_state_typed_hash_chain_established
    );
    assert!(
        !certificate
            .cms19_applicability
            .deployed_oracle_output_geometry_established
    );
    let deployed_leaf_oracle = &certificate.deployed_aggregate_leaf_oracle;
    assert!(deployed_leaf_oracle.has_complete_call_inventory());
    assert_eq!(deployed_leaf_oracle.rows.len(), 9);
    assert_eq!(
        deployed_leaf_oracle
            .rows
            .iter()
            .map(|row| row.interleaving_width)
            .collect::<Vec<_>>(),
        [8, 8, 8, 8, 8, 8, 1, 1, 1],
    );
    assert_eq!(
        deployed_leaf_oracle
            .rows
            .iter()
            .map(|row| row.opened_leaf_count)
            .sum::<u64>(),
        2_782,
    );
    assert_eq!(deployed_leaf_oracle.distinct_initial_equation_count, 2);
    assert_eq!(
        deployed_leaf_oracle.repeated_initial_hash_query_count,
        2_780
    );
    assert_eq!(
        deployed_leaf_oracle.deployed_verifier_hash_query_count,
        1_232_362
    );
    assert_eq!(
        deployed_leaf_oracle.deployed_accepting_database_equation_count,
        1_229_573
    );
    assert_eq!(deployed_leaf_oracle.minimum_oracle_output_bit_length, 256);
    assert_eq!(
        deployed_leaf_oracle.collision_penalty_denominator_bit_length,
        256
    );
    assert!(deployed_leaf_oracle.transition_collision_propagates_to_final_leaf);
    assert!(!deployed_leaf_oracle.uniform_required_output_geometry_established);
    assert!(
        !deployed_leaf_oracle.classical_collision_penalty_is_below_inverse_power_of_two(128),
        "the 256-bit transition chain misses the classical 128-bit collision allocation",
    );
    assert!(
        !deployed_leaf_oracle.qrom_ideal_oracle_penalty_is_below_inverse_power_of_two(128),
        "the 256-bit transition chain misses the QROM 128-bit collision allocation",
    );
    assert!(!deployed_leaf_oracle.is_eligible_for_uniform_required_output());
    assert!(certificate.cms19_strong_state_hash_chain.is_complete());
    assert_eq!(
        certificate
            .cms19_strong_state_hash_chain
            .logical_verifier_message_count,
        SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT,
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
    assert!(certificate.cms19_state_predicate.is_complete());
    assert!(certificate.construction_masking.is_complete());
    assert!(certificate.aggregate_wide_masking.is_complete());
    assert_eq!(
        certificate
            .aggregate_wide_masking
            .joint_affine_view_summary(),
        (18_025, 18_013, 12),
    );
    assert_eq!(
        certificate.aggregate_wide_masking.nonlinear_view_summary(),
        (9, 9, 5, 6),
    );
    assert_eq!(
        certificate
            .aggregate_wide_masking
            .generator_sample_summary(),
        (18_025, 90_125, 64, 10),
    );
    assert!(
        certificate
            .relation_compiler_interpreter_semantics
            .is_complete()
    );
    assert!(certificate.polynomial_protocol_extractor.is_complete());
    assert!(certificate.point_constraint_extractor.is_complete());
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement
                    == StatePredicateRequirement::ExtractCompilerInterpreterRelationWitness
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::IndependentCompilerInterpreterArithmeticOracle
                    && row.is_discharged
            }),
    );
    assert!(
        certificate
            .construction_masking
            .aggregate_claims_factor_through_masked_openings()
    );
    assert!(
        certificate
            .construction_masking
            .aggregate_wide_views_delegate_to_precommitted_pad()
    );
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .filter(|row| {
                matches!(
                    row.requirement,
                    StatePredicateRequirement::ExtractCompleteRelationPhaseCodewords
                        | StatePredicateRequirement::ExtractCompleteBoundCodewords
                        | StatePredicateRequirement::ExtractCompleteWhirEpochCodewords
                        | StatePredicateRequirement::ExtractThetaAndPhaseReductions
                )
            })
            .all(|row| {
                row.discharge_authority
                    == StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor
                    && row.is_discharged
            })
    );
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement
                    == StatePredicateRequirement::ExplicitPointConstraintExtractorCorrespondence
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::CheckedExplicitPointConstraintExtractor
                    && row.is_discharged
            })
    );
    assert!(certificate.exact_failure_magnitude.is_complete());
    assert!(!certificate.cms19_applicability.is_complete());
    assert!(!certificate.is_complete_construction_theorem());
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement == StatePredicateRequirement::ExactFailureMagnitudeCorrespondence
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::CheckedExactFailureMagnitudeCorrespondence
                    && row.is_discharged
            })
    );

    let exact_failure = &certificate.exact_failure_magnitude;
    assert_eq!(
        exact_failure
            .query_rows
            .iter()
            .map(|row| {
                (
                    row.event,
                    row.logical_word_count,
                    row.population,
                    row.agreement_ceiling,
                    row.query_count,
                    row.charged_term_count,
                )
            })
            .collect::<Vec<_>>(),
        [
            (
                ExactQueryFailureEvent::OuterOpeningPointWords,
                3,
                16_777_216,
                10_485_760,
                387,
                1,
            ),
            (
                ExactQueryFailureEvent::RelationPhaseColumns,
                3,
                16_777_216,
                10_485_760,
                387,
                1,
            ),
            (
                ExactQueryFailureEvent::BoundTreeWords,
                8,
                8_388_608,
                9_217,
                40,
                1,
            ),
            (
                ExactQueryFailureEvent::StatementRootWords,
                3,
                8_388_608,
                4_259_840,
                266,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 0 },
                1,
                8_388_608,
                5_243_074,
                387,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 1 },
                1,
                4_194_304,
                2_228_368,
                288,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 2 },
                1,
                2_097_152,
                1_065_094,
                268,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 3 },
                1,
                1_048_576,
                526_468,
                264,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 4 },
                1,
                524_288,
                262_532,
                263,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 5 },
                1,
                262_144,
                131_236,
                263,
                1,
            ),
            (
                ExactQueryFailureEvent::AggregateWidePad,
                1,
                8_192,
                5_055,
                393,
                1,
            ),
        ],
    );
    assert!(exact_failure.query_rows.iter().all(|row| {
        row.exact_without_replacement_probability
            .less_than_or_equal(&row.power_probability_ceiling)
    }));
    let single_theta_numerator = BigUint::from(32_766_u64).pow(5);
    assert_eq!(
        exact_failure
            .theta_rows
            .iter()
            .map(|row| row.bad_set_numerator.clone())
            .collect::<Vec<_>>(),
        vec![single_theta_numerator.clone(); 3],
    );
    let complete_algebraic_numerator = sum_algebraic_numerator(&exact_failure.algebraic_rows);
    let theta_numerator = BigUint::from(3_u8) * single_theta_numerator;
    assert_eq!(
        &complete_algebraic_numerator - &theta_numerator,
        BigUint::from(216_542_517_u64),
    );
    assert_eq!(
        complete_algebraic_numerator,
        BigUint::parse_bytes(b"113302212165600456748245", 10)
            .expect("the exact algebraic numerator parses"),
    );
    assert!(
        exact_failure
            .classical_failure_probability_ceiling
            .is_greater_than_inverse_power_of_two(244)
    );
    assert!(
        exact_failure
            .classical_failure_probability_ceiling
            .is_at_most_inverse_power_of_two(243)
    );
    assert!(
        exact_failure
            .qrom_failure_probability_ceiling
            .is_greater_than_inverse_power_of_two(80)
    );
    assert!(
        exact_failure
            .qrom_failure_probability_ceiling
            .is_at_most_inverse_power_of_two(79)
    );
    assert!(
        exact_failure
            .qrom_failure_probability_ceiling
            .less_than(&ExactBigFraction::from_u64(1, 1).expect("one derives"))
    );

    let extractor_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected same-secret context exists");
    let extractor_compiled_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .expect("the selected same-secret relation input derives"),
        &extractor_context,
    )
    .expect("the selected same-secret relation compiles");
    let extractor_artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
        extractor_compiled_plan,
        &extractor_context,
    )
    .expect("the selected same-secret relation validates");
    let extractor_variant = extractor_artifact
        .compiled_plan()
        .select_variant(None, None)
        .expect("the selected same-secret variant exists");
    let extractor_variant_hash = extractor_variant
        .canonical_hash()
        .expect("the selected same-secret variant hashes");
    let failure_catalog = plan
        .oracle_equation_catalog()
        .expect("the exact failure catalog derives");
    for fault in [
        ExactFailureMagnitudeFault::DropFirstQueryRow,
        ExactFailureMagnitudeFault::ReduceFirstQueryAgreementCeiling,
        ExactFailureMagnitudeFault::DropRelationCompositionOwner,
        ExactFailureMagnitudeFault::ReduceAggregateWideBaseNumerator,
        ExactFailureMagnitudeFault::ChangeVerifierHashQueryCount,
    ] {
        assert_eq!(
            checked_exact_failure_magnitude_with_fault(
                ExactFailureMagnitudeDerivationInput {
                    plan: &plan,
                    relation_variant: extractor_variant,
                    catalog: &failure_catalog,
                    selected_plan_state_predicate: &certificate.selected_plan_state_predicate,
                    code_state_rows: &certificate.code_state_rows,
                    fold_rows: &certificate.fold_rows,
                    shift_rows: &certificate.shift_rows,
                    aggregate_wide_masking: &certificate.aggregate_wide_masking,
                    initial_constraint_batch_numerator: certificate
                        .initial_constraint_batch_numerator,
                    logical_verifier_message_count: certificate.logical_verifier_message_count,
                    cms19_arithmetic: &certificate.cms19_arithmetic,
                },
                fault,
            ),
            Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence),
            "the hostile failure-magnitude mutation {fault:?} must be rejected",
        );
    }
    for fault in [
        ExactExtractorCorrespondenceFault::DropFirstRelationPhasePolynomial,
        ExactExtractorCorrespondenceFault::ChangeFirstAggregateOpeningColumn,
        ExactExtractorCorrespondenceFault::ChangeScalarOpeningCount,
        ExactExtractorCorrespondenceFault::PermitProofSuppliedPoint,
        ExactExtractorCorrespondenceFault::ChangeFirstPolynomialBasisIdentity,
    ] {
        assert!(
            checked_exact_same_secret_extractor_correspondence_with_fault(
                &plan,
                extractor_variant,
                &extractor_context,
                extractor_artifact.canonical_plan_hash(),
                extractor_variant_hash,
                fault,
            )
            .is_err(),
            "the hostile extractor mutation {fault:?} must be rejected",
        );
    }

    let mut duplicated_tree_role = verifier_ledger.merkle_rows.clone();
    duplicated_tree_role[1].role = duplicated_tree_role[0].role;
    assert_eq!(
        derive_commitment_subtree_extraction_certificate(&plan, &duplicated_tree_role),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );

    let mut changed_tree_geometry = verifier_ledger.merkle_rows.clone();
    changed_tree_geometry[0].leaf_count /= 2;
    assert_eq!(
        derive_commitment_subtree_extraction_certificate(&plan, &changed_tree_geometry),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );

    let mut changed_parent_ceiling = verifier_ledger.merkle_rows.clone();
    changed_parent_ceiling[0].parent_hash_query_count -= 1;
    assert_eq!(
        derive_commitment_subtree_extraction_certificate(&plan, &changed_parent_ceiling),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );

    let mut missing_tree_role = verifier_ledger.merkle_rows.clone();
    missing_tree_role.pop();
    assert_eq!(
        derive_commitment_subtree_extraction_certificate(&plan, &missing_tree_role),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );

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
        for (error_ordinal, received_value) in received.iter_mut().enumerate().take(error_count) {
            *received_value = (*received_value
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
    for (error_ordinal, received_value) in beyond_radius.iter_mut().enumerate().take(RADIUS + 1) {
        *received_value =
            (*received_value + u64::try_from(error_ordinal + 1).expect("error fits u64")) % MODULUS;
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
