//! Exact proof-profile security arithmetic.
//!
//! This module is used by deterministic suite generation. Its values are
//! evidence inputs and outputs, never proof fields or verifier verdicts. All
//! comparisons use integers so the selected profile does not depend on host
//! floating-point behavior.

use std::collections::BTreeMap;

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::foundation::ProofApplicationSlotCeilings;

use super::{
    FIRST_PROFILE_APPLICATION_FAMILIES, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_EVALUATION_BLOWUP_FACTOR,
    PROOF_UNIQUE_QUERY_COUNT, CompiledRelationPlan, ProofLeafVisibility,
    ProofTreeCatalogInput, ProofTreeRole, RelationPlanCheckContext,
    RelationProofTreeInput, StatementOwnedProofTreeInput,
    build_complete_proof_tree_catalog, maximum_verifier_tree_hash_equation_count,
};
use super::relation_plan::{BoundTreeConstructionKind, RelationTreeDescriptor};

const PROTOTYPE_WORK_FACTOR_BITS: u32 = 80;
const RANDOM_ORACLE_OUTPUT_BITS: u32 = 512;

// The theorem-facing FRI parameters are deliberately conservative. Generated
// plans have a code rate in [1/16, 1/8], m is three, eta is one hundredth,
// and delta is five eighths. The worst endpoint rho = 1/16 satisfies
// eta < sqrt(rho/(2m)) and delta < 1 - sqrt(rho) - eta by the exact
// squared-integer comparisons below.
const FRI_THEOREM_INTEGER_PARAMETER: u32 = 3;
const FRI_AUXILIARY_NUMERATOR: u32 = 1;
const FRI_AUXILIARY_DENOMINATOR: u32 = 100;
const FRI_DISTANCE_NUMERATOR: u32 = 5;
const FRI_DISTANCE_DENOMINATOR: u32 = 8;

// CMS19 first bounds the compressed-oracle database game by
// 6(t^2 epsilon + 4t^3/2^lambda). Lemma 4.9 then gives a square-root
// oracle/database conversion. Applying (sqrt(a)+sqrt(b))^2 <= 2a+2b gives
// the explicit conservative coefficients below.
const QROM_ROUND_BY_ROUND_COEFFICIENT: u32 = 12;
const QROM_COLLISION_COEFFICIENT: u32 = 48;
const QROM_ORACLE_CONVERSION_COEFFICIENT: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProofSecurityError {
    MissingScenario,
    NonCanonicalScenarioOrder,
    InvalidTopCount,
    MissingFamily,
    UnsupportedFamily,
    NonCanonicalEventOrder,
    InvalidVariantSelector,
    InvalidApplicationSlotCount,
    ApplicationSlotCountMismatch,
    InvalidEvaluationDomain,
    InvalidApplicationError,
    InvalidRandomOracleEquationCount,
    InvalidVerifierRandomOracleQueryCount,
    InvalidRelationPlan,
    InvalidTreeCatalog,
    InvalidTranscriptSchedule,
    CountOverflow,
    FriTheoremHypothesisFailed,
    OrdinaryErrorTargetExceeded,
    RoundByRoundSearchTargetExceeded,
    QromWorkFactorTargetExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RationalUpperBound {
    numerator: BigUint,
    denominator: BigUint,
}

/// An exact theorem input derived from a checked relation plan. This is
/// generator evidence, not a proof-body field or a producer assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofSecurityProbabilityInput {
    numerator: BigUint,
    denominator: BigUint,
}

impl ProofSecurityProbabilityInput {
    pub(crate) fn new(
        numerator: BigUint,
        denominator: BigUint,
    ) -> Result<Self, ProofSecurityError> {
        if denominator.is_zero() || numerator > denominator {
            return Err(ProofSecurityError::InvalidApplicationError);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// Exact `(numerator / denominator)^independent_repetition_count` bound.
    pub(crate) fn repeated_ratio(
        numerator: BigUint,
        denominator: BigUint,
        independent_repetition_count: u16,
    ) -> Result<Self, ProofSecurityError> {
        if denominator.is_zero()
            || numerator > denominator
            || independent_repetition_count == 0
        {
            return Err(ProofSecurityError::InvalidApplicationError);
        }
        Self::new(
            numerator.pow(u32::from(independent_repetition_count)),
            denominator.pow(u32::from(independent_repetition_count)),
        )
    }

    /// Adds two bad-event bounds without assuming independence.
    pub(crate) fn union(&self, right: &Self) -> Result<Self, ProofSecurityError> {
        self.validate()?;
        right.validate()?;
        let numerator = &self.numerator * &right.denominator
            + &right.numerator * &self.denominator;
        let denominator = &self.denominator * &right.denominator;
        if numerator > denominator {
            return Err(ProofSecurityError::InvalidApplicationError);
        }
        Self::new(numerator, denominator)
    }

    /// Selects the larger bound when one fixed invalid witness can make only
    /// one of several mutually exclusive limb failures the worst case.
    pub(crate) fn maximum(&self, right: &Self) -> Result<Self, ProofSecurityError> {
        self.validate()?;
        right.validate()?;
        if &self.numerator * &right.denominator
            >= &right.numerator * &self.denominator
        {
            Ok(self.clone())
        } else {
            Ok(right.clone())
        }
    }

    pub(crate) fn inverse_challenge_extension_cardinality() -> Self {
        Self {
            numerator: BigUint::one(),
            denominator: extension_field_cardinality(),
        }
    }

    fn as_upper_bound(&self) -> RationalUpperBound {
        RationalUpperBound::new(self.numerator.clone(), self.denominator.clone())
    }

    fn validate(&self) -> Result<(), ProofSecurityError> {
        if self.denominator.is_zero() || self.numerator > self.denominator {
            return Err(ProofSecurityError::InvalidApplicationError);
        }
        Ok(())
    }
}

impl RationalUpperBound {
    fn new(numerator: BigUint, denominator: BigUint) -> Self {
        debug_assert!(!denominator.is_zero());
        Self {
            numerator,
            denominator,
        }
    }

    fn zero() -> Self {
        Self::new(BigUint::zero(), BigUint::one())
    }

    fn add(&self, right: &Self) -> Self {
        Self::new(
            &self.numerator * &right.denominator
                + &right.numerator * &self.denominator,
            &self.denominator * &right.denominator,
        )
    }

    fn multiply_integer(&self, multiplier: &BigUint) -> Self {
        Self::new(&self.numerator * multiplier, self.denominator.clone())
    }

    fn maximum(self, right: Self) -> Self {
        if self.is_at_most(&right) { right } else { self }
    }

    fn is_at_most(&self, right: &Self) -> bool {
        &self.numerator * &right.denominator
            <= &right.numerator * &self.denominator
    }

    fn is_strictly_below_ratio(&self, numerator: u32, denominator: u32) -> bool {
        &self.numerator * BigUint::from(denominator)
            < BigUint::from(numerator) * &self.denominator
    }

    fn is_at_most_inverse_power_of_two(&self, exponent: u32) -> bool {
        (&self.numerator << exponent) <= self.denominator
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProofSecurityVariantSelector {
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
}

impl ProofSecurityVariantSelector {
    pub(crate) const fn unscheduled() -> Self {
        Self {
            schedule_position: None,
            top_count: None,
        }
    }

    pub(crate) const fn scheduled(schedule_position: u32) -> Self {
        Self {
            schedule_position: Some(schedule_position),
            top_count: None,
        }
    }

    pub(crate) const fn action_selected(top_count: u16) -> Self {
        Self {
            schedule_position: None,
            top_count: Some(top_count),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofSecurityEventInput {
    application_statement_schema_identifier: u16,
    variant_selector: ProofSecurityVariantSelector,
    application_slot_count: u32,
    evaluation_domain_size: u64,
    initial_fri_degree_bound_exclusive: u64,
    application_round_by_round_error: ProofSecurityProbabilityInput,
    /// Exact maximum number of random-oracle equations in the CMS base-game
    /// output relation, including typed transcript and Merkle equations.
    random_oracle_equation_count: u64,
    /// Exact verifier expansion queries added after the adversary outputs a
    /// candidate proof. These are added to the 2^80-1 adversarial budget.
    verifier_random_oracle_query_count: u64,
}

impl ProofSecurityEventInput {
    /// Derives every theorem input controlled by the checked relation plan.
    /// Callers supply only the suite-derived slot multiplicity; neither the
    /// application bad-event probability nor transcript and Merkle equation
    /// counts can be asserted by an evidence producer.
    pub(crate) fn from_checked_relation_plan(
        relation_plan: &CompiledRelationPlan,
        relation_context: &RelationPlanCheckContext,
        variant_selector: ProofSecurityVariantSelector,
        application_slot_count: u32,
    ) -> Result<Self, ProofSecurityError> {
        if application_slot_count == 0 {
            return Err(ProofSecurityError::InvalidApplicationSlotCount);
        }
        relation_plan
            .check(relation_context)
            .map_err(|_| ProofSecurityError::InvalidRelationPlan)?;
        let variant = relation_plan
            .select_variant(
                variant_selector.schedule_position,
                variant_selector.top_count,
            )
            .map_err(|_| ProofSecurityError::InvalidRelationPlan)?;
        let application_round_by_round_error =
            derive_application_round_by_round_error(variant, relation_context)?;
        let transcript_schedule = variant
            .common_proof_transcript_schedule(relation_context)
            .map_err(|_| ProofSecurityError::InvalidTranscriptSchedule)?;
        let transcript_hash_query_count = transcript_schedule
            .maximum_transcript_hash_query_count()
            .map_err(|_| ProofSecurityError::InvalidTranscriptSchedule)?;
        let relation_trees = security_relation_tree_inputs(variant)?;
        let tree_catalog = build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier: [0_u8; 64],
                canonical_proof_object_header_bytes: vec![0_u8],
                application_statement_schema_identifier: relation_plan
                    .application_statement_schema_identifier(),
                proof_field_index: 0,
                evaluation_domain_size: variant.evaluation_domain_size(),
                relation_trees,
            },
            &transcript_schedule,
        )
        .map_err(|_| ProofSecurityError::InvalidTreeCatalog)?;
        let tree_hash_equation_count = maximum_verifier_tree_hash_equation_count(
            &tree_catalog,
            transcript_schedule.unique_query_count(),
        )
        .map_err(|_| ProofSecurityError::InvalidTreeCatalog)?;
        let random_oracle_equation_count = transcript_hash_query_count
            .checked_add(tree_hash_equation_count)
            .ok_or(ProofSecurityError::CountOverflow)?;

        Ok(Self {
            application_statement_schema_identifier: relation_plan
                .application_statement_schema_identifier(),
            variant_selector,
            application_slot_count,
            evaluation_domain_size: variant.evaluation_domain_size(),
            initial_fri_degree_bound_exclusive: variant
                .opening_degree_bound_exclusive()
                .checked_sub(1)
                .ok_or(ProofSecurityError::InvalidEvaluationDomain)?,
            application_round_by_round_error,
            random_oracle_equation_count,
            verifier_random_oracle_query_count: random_oracle_equation_count,
        })
    }
}

/// Derives the exact algebraic application error from the checked relation.
///
/// Constraint composition contributes one inverse extension-field term: if
/// any normalized constraint polynomial is nonzero, the independent uniform
/// composition coefficient of one such polynomial makes the composed
/// polynomial vanish with probability at most `1 / |E|`. For each non-native
/// modulus, every semantic column and committed reversal is fixed before the
/// corresponding theta vector. A false integer-lift batch therefore yields a
/// nonzero polynomial of degree at most `H - 1`. All repetitions are decoded
/// from one uniform product-space verifier message, so the bad set has density
/// `((H - 1) / q)^T` in `Z_q^T`. Coefficient-local batches evaluate the
/// residual polynomial `r_0 + alpha*r_1 + ...`; its degree is at most one less
/// than the residual count. The two physical-half batches deliberately share
/// one alpha in each repetition: for a fixed invalid witness, one nonzero half
/// polynomial suffices and no union over halves is needed. The complete alpha
/// repetition vector is likewise one product-space verifier message. A fixed
/// invalid witness needs only one invalid modulus in each mechanism, so each
/// mechanism takes the worst modulus before the distinct bad-event mechanisms
/// are unioned.
fn derive_application_round_by_round_error(
    variant: &super::RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<ProofSecurityProbabilityInput, ProofSecurityError> {
    let composition_error =
        ProofSecurityProbabilityInput::inverse_challenge_extension_cardinality();
    let mut repetition_count_by_modulus = BTreeMap::new();
    for batch in variant.ordered_integer_lift_batches() {
        let count = repetition_count_by_modulus
            .entry(batch.modulus_reference())
            .or_insert(0_u16);
        *count = count
            .checked_add(1)
            .ok_or(ProofSecurityError::CountOverflow)?;
    }

    let mut integer_lift_error = ProofSecurityProbabilityInput::new(
        BigUint::zero(),
        BigUint::one(),
    )?;
    let polynomial_degree_bound = variant
        .trace_domain_size()
        .checked_sub(1)
        .ok_or(ProofSecurityError::InvalidEvaluationDomain)?;
    for (modulus_reference, independent_repetition_count) in
        repetition_count_by_modulus
    {
        let modulus = relation_context
            .resolved_modulus(modulus_reference)
            .map_err(|_| ProofSecurityError::InvalidRelationPlan)?;
        let modulus_error = ProofSecurityProbabilityInput::repeated_ratio(
            BigUint::from(polynomial_degree_bound),
            BigUint::from(modulus),
            independent_repetition_count,
        )?;
        integer_lift_error = integer_lift_error.maximum(&modulus_error)?;
    }

    let mut coefficient_local_degree_bounds_by_modulus = BTreeMap::new();
    for batch in variant.ordered_coefficient_local_identity_batches() {
        let residual_count = u64::try_from(batch.ordered_residuals.len())
            .map_err(|_| ProofSecurityError::CountOverflow)?;
        let degree_bound = residual_count
            .checked_sub(1)
            .ok_or(ProofSecurityError::InvalidRelationPlan)?;
        let degree_bound_by_repetition = coefficient_local_degree_bounds_by_modulus
            .entry(batch.modulus_reference)
            .or_insert_with(BTreeMap::new);
        let existing = degree_bound_by_repetition
            .entry(batch.challenge_ordinal)
            .or_insert(0_u64);
        *existing = (*existing).max(degree_bound);
    }
    let mut coefficient_local_error = ProofSecurityProbabilityInput::new(
        BigUint::zero(),
        BigUint::one(),
    )?;
    for (modulus_reference, degree_bound_by_repetition) in
        coefficient_local_degree_bounds_by_modulus
    {
        let independent_repetition_count = u16::try_from(degree_bound_by_repetition.len())
            .map_err(|_| ProofSecurityError::CountOverflow)?;
        let maximum_degree_bound = degree_bound_by_repetition
            .values()
            .copied()
            .max()
            .ok_or(ProofSecurityError::InvalidRelationPlan)?;
        let modulus = relation_context
            .resolved_modulus(modulus_reference)
            .map_err(|_| ProofSecurityError::InvalidRelationPlan)?;
        let modulus_error = ProofSecurityProbabilityInput::repeated_ratio(
            BigUint::from(maximum_degree_bound),
            BigUint::from(modulus),
            independent_repetition_count,
        )?;
        coefficient_local_error = coefficient_local_error.maximum(&modulus_error)?;
    }

    composition_error
        .union(&integer_lift_error)?
        .union(&coefficient_local_error)
}

fn security_relation_tree_inputs(
    variant: &super::RelationPlanVariant,
) -> Result<Vec<RelationProofTreeInput>, ProofSecurityError> {
    let leaf_visibility = match variant.proof_privacy_mode() {
        super::relation_plan::ProofPrivacyMode::PublicOnly => ProofLeafVisibility::Public,
        super::relation_plan::ProofPrivacyMode::SecretBearing => {
            ProofLeafVisibility::SecretBearing
        }
    };
    variant
        .ordered_trees()
        .iter()
        .map(|tree| match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let tree_role = match *proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(ProofSecurityError::InvalidTreeCatalog),
                };
                Ok(RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| ProofSecurityError::CountOverflow)?,
                    leaf_visibility,
                })
            }
            RelationTreeDescriptor::BoundPublic {
                construction_kind,
                ordered_column_ordinals,
                ..
            } => Ok(RelationProofTreeInput::BoundPublic(match *construction_kind {
                BoundTreeConstructionKind::CommittedMaterial => {
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash: [0_u8; 64],
                        expected_root: [0_u8; 64],
                    }
                }
                BoundTreeConstructionKind::SetupPolynomial => {
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        public_polynomial_context_hash: [0_u8; 64],
                        row_width: u32::try_from(ordered_column_ordinals.len())
                            .map_err(|_| ProofSecurityError::CountOverflow)?,
                        expected_root: [0_u8; 64],
                    }
                }
            })),
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofSecurityScenarioInput {
    pub(crate) top_count: u16,
    pub(crate) application_slot_ceilings: ProofApplicationSlotCeilings,
    pub(crate) ordered_events: Vec<ProofSecurityEventInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofSecurityScenarioBounds {
    top_count: u16,
    ordinary_invalid_acceptance: RationalUpperBound,
    multiplicity_weighted_round_by_round_error: RationalUpperBound,
    qrom_invalid_acceptance: RationalUpperBound,
}

impl ProofSecurityScenarioBounds {
    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }
}

/// Validates all twenty action-selected proof scenarios and returns their exact
/// rational upper bounds for reproducible assurance evidence.
pub(crate) fn validate_first_profile_security(
    scenarios: &[ProofSecurityScenarioInput],
) -> Result<Vec<ProofSecurityScenarioBounds>, ProofSecurityError> {
    validate_selected_fri_theorem_parameters()?;
    if scenarios.len() != 20 {
        return Err(ProofSecurityError::MissingScenario);
    }

    let mut bounds = Vec::new();
    bounds
        .try_reserve_exact(scenarios.len())
        .map_err(|_| ProofSecurityError::MissingScenario)?;
    for (scenario_index, scenario) in scenarios.iter().enumerate() {
        let expected_top_count = u16::try_from(scenario_index + 1)
            .map_err(|_| ProofSecurityError::InvalidTopCount)?;
        if scenario.top_count != expected_top_count {
            return Err(ProofSecurityError::NonCanonicalScenarioOrder);
        }
        bounds.push(validate_scenario(scenario)?);
    }
    Ok(bounds)
}

fn validate_scenario(
    scenario: &ProofSecurityScenarioInput,
) -> Result<ProofSecurityScenarioBounds, ProofSecurityError> {
    if !(1..=20).contains(&scenario.top_count) {
        return Err(ProofSecurityError::InvalidTopCount);
    }

    let extension_field_cardinality = extension_field_cardinality();
    let hash_space_size = BigUint::one() << RANDOM_ORACLE_OUTPUT_BITS;
    let adversary_query_bound = (BigUint::one() << PROTOTYPE_WORK_FACTOR_BITS)
        - BigUint::one();

    let mut ordinary_invalid_acceptance = RationalUpperBound::zero();
    let mut weighted_round_by_round_error = RationalUpperBound::zero();
    let mut qrom_invalid_acceptance = RationalUpperBound::zero();
    let mut family_slot_counts = [0_u32; FIRST_PROFILE_APPLICATION_FAMILIES.len()];
    let mut previous_event_key = None;

    for event in &scenario.ordered_events {
        let family_index = FIRST_PROFILE_APPLICATION_FAMILIES
            .iter()
            .position(|family| *family == event.application_statement_schema_identifier)
            .ok_or(ProofSecurityError::UnsupportedFamily)?;
        validate_variant_selector(
            event.application_statement_schema_identifier,
            event.variant_selector,
            scenario.top_count,
        )?;
        let event_key = (
            family_index,
            event.variant_selector.schedule_position,
            event.variant_selector.top_count,
        );
        if previous_event_key.is_some_and(|previous| previous >= event_key) {
            return Err(ProofSecurityError::NonCanonicalEventOrder);
        }
        previous_event_key = Some(event_key);

        if event.application_slot_count == 0 {
            return Err(ProofSecurityError::InvalidApplicationSlotCount);
        }
        family_slot_counts[family_index] = family_slot_counts[family_index]
            .checked_add(event.application_slot_count)
            .ok_or(ProofSecurityError::InvalidApplicationSlotCount)?;

        let round_by_round_error = event_round_by_round_error(
            event,
            &extension_field_cardinality,
        )?;
        let effective_query_bound = &adversary_query_bound
            + BigUint::from(event.verifier_random_oracle_query_count);
        let effective_query_bound_squared =
            &effective_query_bound * &effective_query_bound;
        let effective_query_bound_cubed =
            &effective_query_bound_squared * &effective_query_bound;
        let multiplicity = BigUint::from(event.application_slot_count);
        ordinary_invalid_acceptance = ordinary_invalid_acceptance
            .add(&round_by_round_error.multiply_integer(&multiplicity));

        let weighted_error = round_by_round_error
            .multiply_integer(&BigUint::from(QROM_ROUND_BY_ROUND_COEFFICIENT))
            .multiply_integer(&multiplicity);
        weighted_round_by_round_error = weighted_round_by_round_error.add(&weighted_error);

        let database_round_by_round_term = round_by_round_error
            .multiply_integer(&BigUint::from(QROM_ROUND_BY_ROUND_COEFFICIENT))
            .multiply_integer(&effective_query_bound_squared);
        let hash_terms = RationalUpperBound::new(
            BigUint::from(QROM_COLLISION_COEFFICIENT)
                * &effective_query_bound_cubed
                + BigUint::from(QROM_ORACLE_CONVERSION_COEFFICIENT)
                    * BigUint::from(event.random_oracle_equation_count),
            hash_space_size.clone(),
        );
        let event_qrom_error = database_round_by_round_term
            .add(&hash_terms)
            .multiply_integer(&multiplicity);
        qrom_invalid_acceptance = qrom_invalid_acceptance.add(&event_qrom_error);
    }

    for (family_index, family) in FIRST_PROFILE_APPLICATION_FAMILIES
        .iter()
        .copied()
        .enumerate()
    {
        let expected = scenario
            .application_slot_ceilings
            .family_ceiling(family)
            .ok_or(ProofSecurityError::MissingFamily)?;
        if family_slot_counts[family_index] != expected {
            return Err(ProofSecurityError::ApplicationSlotCountMismatch);
        }
    }

    if !ordinary_invalid_acceptance
        .is_at_most_inverse_power_of_two(PROTOTYPE_WORK_FACTOR_BITS)
    {
        return Err(ProofSecurityError::OrdinaryErrorTargetExceeded);
    }
    if !weighted_round_by_round_error.is_at_most_inverse_power_of_two(
        2 * PROTOTYPE_WORK_FACTOR_BITS + 16,
    ) {
        return Err(ProofSecurityError::RoundByRoundSearchTargetExceeded);
    }
    if !qrom_invalid_acceptance.is_strictly_below_ratio(1, 4) {
        return Err(ProofSecurityError::QromWorkFactorTargetExceeded);
    }

    Ok(ProofSecurityScenarioBounds {
        top_count: scenario.top_count,
        ordinary_invalid_acceptance,
        multiplicity_weighted_round_by_round_error: weighted_round_by_round_error,
        qrom_invalid_acceptance,
    })
}

fn validate_variant_selector(
    family: u16,
    selector: ProofSecurityVariantSelector,
    scenario_top_count: u16,
) -> Result<(), ProofSecurityError> {
    let matches = match family {
        0x1214 | 0x1215 | 0x1216 | 0x1217 => {
            selector.schedule_position.is_some() && selector.top_count.is_none()
        }
        0x1218 => {
            selector.schedule_position.is_none()
                && selector.top_count == Some(scenario_top_count)
        }
        0x1211 | 0x1212 | 0x1213 | 0x1302 | 0x1621 | 0x2110 | 0x2111 => {
            selector == ProofSecurityVariantSelector::unscheduled()
        }
        _ => return Err(ProofSecurityError::UnsupportedFamily),
    };
    if !matches {
        return Err(ProofSecurityError::InvalidVariantSelector);
    }
    Ok(())
}

fn event_round_by_round_error(
    event: &ProofSecurityEventInput,
    extension_field_cardinality: &BigUint,
) -> Result<RationalUpperBound, ProofSecurityError> {
    event.application_round_by_round_error.validate()?;
    if event.evaluation_domain_size == 0
        || !event.evaluation_domain_size.is_power_of_two()
        || event.evaluation_domain_size
            % u64::from(PROOF_EVALUATION_BLOWUP_FACTOR)
            != 0
        || event.evaluation_domain_size / 2 < u64::from(PROOF_UNIQUE_QUERY_COUNT)
        || (PROOF_BASE_FIELD_MODULUS - 1) % event.evaluation_domain_size != 0
    {
        return Err(ProofSecurityError::InvalidEvaluationDomain);
    }
    let opening_degree_bound_exclusive = event
        .initial_fri_degree_bound_exclusive
        .checked_add(1)
        .ok_or(ProofSecurityError::InvalidEvaluationDomain)?;
    let containing_degree_domain = opening_degree_bound_exclusive
        .checked_next_power_of_two()
        .ok_or(ProofSecurityError::InvalidEvaluationDomain)?;
    if event.initial_fri_degree_bound_exclusive <= 1
        || containing_degree_domain
            .checked_mul(u64::from(PROOF_EVALUATION_BLOWUP_FACTOR))
            != Some(event.evaluation_domain_size)
        || event.initial_fri_degree_bound_exclusive
            .checked_mul(16)
            .is_none_or(|scaled_degree| scaled_degree < event.evaluation_domain_size)
        || event.initial_fri_degree_bound_exclusive
            .checked_mul(8)
            .is_none_or(|scaled_degree| scaled_degree > event.evaluation_domain_size)
    {
        return Err(ProofSecurityError::FriTheoremHypothesisFailed);
    }
    if event.random_oracle_equation_count == 0 {
        return Err(ProofSecurityError::InvalidRandomOracleEquationCount);
    }
    if event.verifier_random_oracle_query_count == 0 {
        return Err(ProofSecurityError::InvalidVerifierRandomOracleQueryCount);
    }

    let commitment_term = fri_commitment_term_upper_bound(
        event.evaluation_domain_size,
        extension_field_cardinality,
    );
    let query_term = RationalUpperBound::new(
        BigUint::from(
            FRI_DISTANCE_DENOMINATOR - FRI_DISTANCE_NUMERATOR,
        )
        .pow(PROOF_UNIQUE_QUERY_COUNT),
        BigUint::from(FRI_DISTANCE_DENOMINATOR)
            .pow(PROOF_UNIQUE_QUERY_COUNT),
    );
    let fri_error = commitment_term.maximum(query_term);
    Ok(fri_error.add(&event.application_round_by_round_error.as_upper_bound()))
}

fn fri_commitment_term_upper_bound(
    evaluation_domain_size: u64,
    extension_field_cardinality: &BigUint,
) -> RationalUpperBound {
    // Every generated rate is at least 1/16. At that worst endpoint,
    // rho^(-3/2) = 64. With m=3, (m+1/2)^7 = (7/2)^7, so the complete
    // coefficient is 7^7/6 after exact cancellation.
    let numerator = BigUint::from(7_u32).pow(7)
        * BigUint::from(evaluation_domain_size).pow(2);
    let denominator = BigUint::from(6_u32) * extension_field_cardinality;
    RationalUpperBound::new(numerator, denominator)
}

fn extension_field_cardinality() -> BigUint {
    BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .expect("the selected extension degree fits u32"),
    )
}

fn validate_selected_fri_theorem_parameters() -> Result<(), ProofSecurityError> {
    if PROOF_EVALUATION_BLOWUP_FACTOR != 8
        || FRI_THEOREM_INTEGER_PARAMETER < 3
        || FRI_DISTANCE_NUMERATOR >= FRI_DISTANCE_DENOMINATOR
        || FRI_AUXILIARY_NUMERATOR >= FRI_AUXILIARY_DENOMINATOR
    {
        return Err(ProofSecurityError::FriTheoremHypothesisFailed);
    }

    // eta^2 < rho/(2m), checked at the worst rho = 1/16.
    let auxiliary_left = BigUint::from(FRI_AUXILIARY_NUMERATOR).pow(2)
        * BigUint::from(16_u32)
        * BigUint::from(2 * FRI_THEOREM_INTEGER_PARAMETER);
    let auxiliary_right = BigUint::from(FRI_AUXILIARY_DENOMINATOR).pow(2);
    if auxiliary_left >= auxiliary_right {
        return Err(ProofSecurityError::FriTheoremHypothesisFailed);
    }

    // delta + eta < 1 - sqrt(rho). Both sides are positive, so this is
    // equivalent to (1-delta-eta)^2 > rho. The largest generated rate,
    // rho = 1/8, is the worst endpoint for this hypothesis.
    let common_denominator = BigUint::from(FRI_DISTANCE_DENOMINATOR)
        * BigUint::from(FRI_AUXILIARY_DENOMINATOR);
    let remaining_numerator = &common_denominator
        - BigUint::from(FRI_DISTANCE_NUMERATOR)
            * BigUint::from(FRI_AUXILIARY_DENOMINATOR)
        - BigUint::from(FRI_AUXILIARY_NUMERATOR)
            * BigUint::from(FRI_DISTANCE_DENOMINATOR);
    if BigUint::from(8_u32) * remaining_numerator.pow(2)
        <= common_denominator.pow(2)
    {
        return Err(ProofSecurityError::FriTheoremHypothesisFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        CommittedMaterialRelationPlanInput, PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
        ResolvedSuiteModulus, SuiteModulusReference,
        compile_aggregate_threshold_share_relation_plan,
        compile_vss_share_linkage_relation_plan,
    };

    fn committed_material_security_fixture(
    ) -> (CommittedMaterialRelationPlanInput, RelationPlanCheckContext) {
        let evaluation_domain_size = 256_u64;
        let context = RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
            evaluation_blowup_factor: 2,
            evaluation_domain_generator: crate::bgv::modular_arithmetic::pow_mod(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                PROOF_BASE_FIELD_MODULUS,
            )
            .expect("Goldilocks evaluation-domain generator"),
            evaluation_coset_offset: 7,
            deep_point_count: 1,
            quotient_component_count: 4,
            quotient_component_degree_bound_exclusive: 64,
            fri_fold_count: 4,
            final_polynomial_degree_bound_exclusive: 8,
            unique_query_count: 8,
            non_native_modular_identity_challenge_count: 2,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![ResolvedSuiteModulus::new(
                SuiteModulusReference::data(0),
                97,
            )],
        };
        let input = CommittedMaterialRelationPlanInput {
            ring_degree: 16,
            evaluation_domain_size,
            opening_degree_bound_exclusive: 128,
            material_column_degree_bound_exclusive: 10,
            participant_count: 3,
            threshold: 2,
            sharing_data_modulus_indices: vec![0],
            trace_mask_degree_bound_exclusive: 2,
            first_mask_purpose: 100,
        };
        (input, context)
    }

    fn event(
        family: u16,
        selector: ProofSecurityVariantSelector,
        application_slot_count: u32,
    ) -> ProofSecurityEventInput {
        ProofSecurityEventInput {
            application_statement_schema_identifier: family,
            variant_selector: selector,
            application_slot_count,
            evaluation_domain_size: 1_u64 << 20,
            initial_fri_degree_bound_exclusive: (1_u64 << 17) - 1,
            application_round_by_round_error: ProofSecurityProbabilityInput::new(
                BigUint::one(),
                BigUint::one() << 240,
            )
            .expect("valid exact application error"),
            random_oracle_equation_count: 1_u64 << 32,
            verifier_random_oracle_query_count: 1_u64 << 32,
        }
    }

    fn scenario(top_count: u16) -> ProofSecurityScenarioInput {
        let ceilings = ProofApplicationSlotCeilings::derive(10, 1, 2, 10, 10)
            .expect("slot ceilings derive");
        let ordered_events = vec![
            event(0x1211, ProofSecurityVariantSelector::unscheduled(), 10),
            event(0x1212, ProofSecurityVariantSelector::unscheduled(), 10),
            event(0x1213, ProofSecurityVariantSelector::unscheduled(), 1),
            event(0x1214, ProofSecurityVariantSelector::scheduled(0), 10),
            event(0x1215, ProofSecurityVariantSelector::scheduled(0), 1),
            event(0x1216, ProofSecurityVariantSelector::scheduled(0), 10),
            event(0x1217, ProofSecurityVariantSelector::scheduled(0), 10),
            event(0x1217, ProofSecurityVariantSelector::scheduled(1), 10),
            event(
                0x1218,
                ProofSecurityVariantSelector::action_selected(top_count),
                1,
            ),
            event(0x1302, ProofSecurityVariantSelector::unscheduled(), 10),
            event(0x1621, ProofSecurityVariantSelector::unscheduled(), 10),
            event(0x2110, ProofSecurityVariantSelector::unscheduled(), 10),
            event(0x2111, ProofSecurityVariantSelector::unscheduled(), 10),
        ];
        ProofSecurityScenarioInput {
            top_count,
            application_slot_ceilings: ceilings,
            ordered_events,
        }
    }

    #[test]
    fn selected_profile_passes_exact_fri_and_qrom_gates() {
        let scenarios = (1..=20).map(scenario).collect::<Vec<_>>();
        let bounds = validate_first_profile_security(&scenarios)
            .expect("the selected theorem profile passes");
        assert_eq!(bounds.len(), 20);
        assert_eq!(bounds[0].top_count(), 1);
        assert_eq!(bounds[19].top_count(), 20);
    }

    #[test]
    fn scenario_rejects_missing_slots_and_wrong_variant_binding() {
        let mut missing_slots = (1..=20).map(scenario).collect::<Vec<_>>();
        missing_slots[0].ordered_events[0].application_slot_count -= 1;
        assert_eq!(
            validate_first_profile_security(&missing_slots),
            Err(ProofSecurityError::ApplicationSlotCountMismatch),
        );

        let mut wrong_top_count = (1..=20).map(scenario).collect::<Vec<_>>();
        wrong_top_count[6]
            .ordered_events
            .iter_mut()
            .find(|event| event.application_statement_schema_identifier == 0x1218)
            .expect("action-selected event exists")
            .variant_selector = ProofSecurityVariantSelector::action_selected(8);
        assert_eq!(
            validate_first_profile_security(&wrong_top_count),
            Err(ProofSecurityError::InvalidVariantSelector),
        );
    }

    #[test]
    fn theorem_gates_reject_invalid_application_error_and_tiny_domains() {
        let mut invalid_error = (1..=20).map(scenario).collect::<Vec<_>>();
        invalid_error[0].ordered_events[0]
            .application_round_by_round_error
            .denominator = BigUint::zero();
        assert_eq!(
            validate_first_profile_security(&invalid_error),
            Err(ProofSecurityError::InvalidApplicationError),
        );

        let mut tiny_domain = (1..=20).map(scenario).collect::<Vec<_>>();
        tiny_domain[0].ordered_events[0].evaluation_domain_size = 256;
        assert_eq!(
            validate_first_profile_security(&tiny_domain),
            Err(ProofSecurityError::InvalidEvaluationDomain),
        );
    }

    #[test]
    fn application_error_composition_uses_exact_rationals() {
        let repeated = ProofSecurityProbabilityInput::repeated_ratio(
            BigUint::from(32_768_u32),
            BigUint::from(1_u64 << 60),
            7,
        )
        .expect("valid repeated non-native bound");
        assert_eq!(
            repeated,
            ProofSecurityProbabilityInput::new(
                BigUint::from(32_768_u32).pow(7),
                BigUint::from(1_u64 << 60).pow(7),
            )
            .expect("valid explicit bound"),
        );

        let composition =
            ProofSecurityProbabilityInput::inverse_challenge_extension_cardinality();
        let union = repeated
            .union(&composition)
            .expect("the exact union stays below one");
        assert_eq!(
            union.maximum(&repeated).expect("valid maximum"),
            union,
        );
    }

    #[test]
    fn committed_material_alpha_error_uses_exact_residual_degree_and_repetitions() {
        let (input, context) = committed_material_security_fixture();
        let vss_plan = compile_vss_share_linkage_relation_plan(&input, &context)
            .expect("exact VSS share-linkage plan");
        let vss_error = derive_application_round_by_round_error(
            &vss_plan.variants()[0],
            &context,
        )
        .expect("VSS application error");
        let expected_alpha_error = ProofSecurityProbabilityInput::repeated_ratio(
            BigUint::from(u64::from(input.participant_count) - 1),
            BigUint::from(97_u64),
            context.non_native_modular_identity_challenge_count,
        )
        .expect("exact coefficient-local error");
        let expected_vss_error =
            ProofSecurityProbabilityInput::inverse_challenge_extension_cardinality()
                .union(&expected_alpha_error)
                .expect("composition and alpha errors union exactly");
        assert_eq!(vss_error, expected_vss_error);

        let aggregate_plan = compile_aggregate_threshold_share_relation_plan(&input, &context)
            .expect("exact aggregate-threshold plan");
        let aggregate_error = derive_application_round_by_round_error(
            &aggregate_plan.variants()[0],
            &context,
        )
        .expect("aggregate application error");
        assert_eq!(
            aggregate_error,
            ProofSecurityProbabilityInput::inverse_challenge_extension_cardinality(),
            "the deterministic aggregate relation has no alpha group or alpha error",
        );
    }
}
