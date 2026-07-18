//! Exact ordinary and quantum-random-oracle soundness accounting.
//!
//! This source-owned ledger is derived from the checked application transition
//! catalogs, the simultaneous production opening vector, and the exact action
//! inventory. It is never serialized or accepted from proof bytes.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::foundation::{FOUNDATION_PROFILE, ProofApplicationSlotCeilings};

use super::{
    FIRST_PROFILE_APPLICATION_FAMILIES,
    selected_accounting::{
        SelectedActionProofAccounting, SelectedActionProofVariantAccounting,
        SelectedProofByteAccounting, SelectedProofVariantByteCeiling,
    },
    selected_profile::selected_proof_application_slot_ceilings,
};

const SELECTED_ASSURANCE_EXPONENT: u32 = 80;
const SELECTED_ROUND_BY_ROUND_MARGIN_EXPONENT: u32 = 184;
const IDEAL_XOF_OUTPUT_BIT_LENGTH: u32 = 512;
const CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT: u32 = 12;
const CMS19_DATABASE_TERM_COEFFICIENT: u32 = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedApplicationSoundnessAccountingError {
    CountOverflow,
    InvalidInventory,
    RoundByRoundMarginExceeded { top_count: u16 },
    OrdinaryBoundExceeded { top_count: u16 },
    QuantumRandomOracleBoundExceeded { top_count: u16 },
}

/// An exact non-negative rational bound. The constructor and arithmetic keep
/// the fraction reduced so action-level unions do not accumulate artificial
/// denominator growth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedExactProbabilityBound {
    numerator: BigUint,
    denominator: BigUint,
}

impl SelectedExactProbabilityBound {
    fn new(
        numerator: BigUint,
        denominator: BigUint,
    ) -> Result<Self, SelectedApplicationSoundnessAccountingError> {
        if denominator.is_zero() {
            return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
        }
        if numerator.is_zero() {
            return Ok(Self {
                numerator,
                denominator: BigUint::one(),
            });
        }
        let common_divisor = greatest_common_divisor(numerator.clone(), denominator.clone());
        Ok(Self {
            numerator: numerator / &common_divisor,
            denominator: denominator / common_divisor,
        })
    }

    fn zero() -> Self {
        Self {
            numerator: BigUint::zero(),
            denominator: BigUint::one(),
        }
    }

    pub(crate) const fn numerator(&self) -> &BigUint {
        &self.numerator
    }

    pub(crate) const fn denominator(&self) -> &BigUint {
        &self.denominator
    }

    pub(crate) fn is_at_most_inverse_power_of_two(&self, exponent: u32) -> bool {
        &self.numerator * power_of_two(exponent) <= self.denominator
    }

    pub(crate) fn is_at_most_fraction(&self, numerator: u32, denominator: u32) -> bool {
        denominator != 0
            && &self.numerator * BigUint::from(denominator)
                <= BigUint::from(numerator) * &self.denominator
    }

    fn checked_add(
        &self,
        right: &Self,
    ) -> Result<Self, SelectedApplicationSoundnessAccountingError> {
        let denominator_common_divisor =
            greatest_common_divisor(self.denominator.clone(), right.denominator.clone());
        let left_denominator_multiplier = &right.denominator / &denominator_common_divisor;
        let right_denominator_multiplier = &self.denominator / &denominator_common_divisor;
        Self::new(
            &self.numerator * &left_denominator_multiplier
                + &right.numerator * &right_denominator_multiplier,
            &self.denominator * left_denominator_multiplier,
        )
    }

    fn checked_multiply_integer(
        &self,
        multiplier: impl Into<BigUint>,
    ) -> Result<Self, SelectedApplicationSoundnessAccountingError> {
        Self::new(
            &self.numerator * multiplier.into(),
            self.denominator.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedApplicationSoundnessVariantAccounting {
    variant_catalog_index: usize,
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    physical_application_multiplicity: u32,
    logical_verifier_message_count: u64,
    round_by_round_error_bound: SelectedExactProbabilityBound,
    verifier_ideal_xof_query_count: u64,
    checked_oracle_equation_count: u64,
    quantum_random_oracle_single_event_bound: SelectedExactProbabilityBound,
}

impl SelectedApplicationSoundnessVariantAccounting {
    pub(crate) const fn variant_catalog_index(&self) -> usize {
        self.variant_catalog_index
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn physical_application_multiplicity(&self) -> u32 {
        self.physical_application_multiplicity
    }

    pub(crate) const fn logical_verifier_message_count(&self) -> u64 {
        self.logical_verifier_message_count
    }

    pub(crate) const fn round_by_round_error_bound(&self) -> &SelectedExactProbabilityBound {
        &self.round_by_round_error_bound
    }

    pub(crate) const fn verifier_ideal_xof_query_count(&self) -> u64 {
        self.verifier_ideal_xof_query_count
    }

    pub(crate) const fn checked_oracle_equation_count(&self) -> u64 {
        self.checked_oracle_equation_count
    }

    pub(crate) const fn quantum_random_oracle_single_event_bound(
        &self,
    ) -> &SelectedExactProbabilityBound {
        &self.quantum_random_oracle_single_event_bound
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedActionApplicationSoundnessAccounting {
    top_count: u16,
    variant_rows: Vec<SelectedApplicationSoundnessVariantAccounting>,
    round_by_round_compiler_input_bound: SelectedExactProbabilityBound,
    ordinary_invalid_acceptance_bound: SelectedExactProbabilityBound,
    quantum_random_oracle_invalid_acceptance_bound: SelectedExactProbabilityBound,
}

impl SelectedActionApplicationSoundnessAccounting {
    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) fn variant_rows(&self) -> &[SelectedApplicationSoundnessVariantAccounting] {
        &self.variant_rows
    }

    pub(crate) const fn round_by_round_compiler_input_bound(
        &self,
    ) -> &SelectedExactProbabilityBound {
        &self.round_by_round_compiler_input_bound
    }

    pub(crate) const fn ordinary_invalid_acceptance_bound(&self) -> &SelectedExactProbabilityBound {
        &self.ordinary_invalid_acceptance_bound
    }

    pub(crate) const fn quantum_random_oracle_invalid_acceptance_bound(
        &self,
    ) -> &SelectedExactProbabilityBound {
        &self.quantum_random_oracle_invalid_acceptance_bound
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedApplicationSoundnessAccounting {
    adversary_ideal_xof_query_ceiling: BigUint,
    actions: Vec<SelectedActionApplicationSoundnessAccounting>,
}

impl SelectedApplicationSoundnessAccounting {
    pub(crate) const fn adversary_ideal_xof_query_ceiling(&self) -> &BigUint {
        &self.adversary_ideal_xof_query_ceiling
    }

    pub(crate) fn actions(&self) -> &[SelectedActionApplicationSoundnessAccounting] {
        &self.actions
    }
}

#[derive(Clone, Debug)]
struct SelectedApplicationSoundnessRowSource<'a> {
    variant_catalog_index: usize,
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    physical_application_multiplicity: u32,
    logical_relation_application_count: u32,
    variant: &'a SelectedProofVariantByteCeiling,
}

/// Derives every row and refuses the selected suite construction when its
/// exact ordinary or adaptive-query action union exceeds the selected bound.
pub(crate) fn require_selected_application_soundness_bounds(
    proof_accounting: &SelectedProofByteAccounting,
) -> Result<SelectedApplicationSoundnessAccounting, SelectedApplicationSoundnessAccountingError> {
    let application_slot_ceilings = selected_proof_application_slot_ceilings()
        .map_err(|_| SelectedApplicationSoundnessAccountingError::InvalidInventory)?;
    require_selected_variant_inventory(
        proof_accounting.variant_ceilings(),
        &application_slot_ceilings,
    )?;

    let expected_top_counts = (1..=FOUNDATION_PROFILE.option_count).collect::<BTreeSet<_>>();
    let mut observed_top_counts = BTreeSet::new();
    let mut referenced_variant_catalog_indices = BTreeSet::new();
    let adversary_ideal_xof_query_ceiling =
        power_of_two(SELECTED_ASSURANCE_EXPONENT) - BigUint::one();
    let mut actions = Vec::new();
    actions
        .try_reserve_exact(proof_accounting.actions().len())
        .map_err(|_| SelectedApplicationSoundnessAccountingError::CountOverflow)?;
    for action in proof_accounting.actions() {
        if !observed_top_counts.insert(action.top_count()) {
            return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
        }
        let row_sources =
            selected_action_soundness_row_sources(action, proof_accounting.variant_ceilings())?;
        referenced_variant_catalog_indices.extend(
            row_sources
                .iter()
                .map(|row_source| row_source.variant_catalog_index),
        );
        require_selected_action_inventory(
            action,
            proof_accounting.variant_ceilings(),
            &application_slot_ceilings,
            &row_sources,
        )?;
        actions.push(selected_action_application_soundness_accounting(
            action.top_count(),
            &adversary_ideal_xof_query_ceiling,
            &row_sources,
        )?);
    }
    let expected_variant_catalog_indices =
        (0..proof_accounting.variant_ceilings().len()).collect::<BTreeSet<_>>();
    if observed_top_counts != expected_top_counts
        || referenced_variant_catalog_indices != expected_variant_catalog_indices
    {
        return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
    }

    Ok(SelectedApplicationSoundnessAccounting {
        adversary_ideal_xof_query_ceiling,
        actions,
    })
}

fn selected_action_soundness_row_sources<'a>(
    action: &SelectedActionProofAccounting,
    variants: &'a [SelectedProofVariantByteCeiling],
) -> Result<
    Vec<SelectedApplicationSoundnessRowSource<'a>>,
    SelectedApplicationSoundnessAccountingError,
> {
    action
        .variant_applications()
        .iter()
        .map(|application| selected_soundness_row_source(application, variants))
        .collect()
}

fn selected_soundness_row_source<'a>(
    application: &SelectedActionProofVariantAccounting,
    variants: &'a [SelectedProofVariantByteCeiling],
) -> Result<SelectedApplicationSoundnessRowSource<'a>, SelectedApplicationSoundnessAccountingError>
{
    let variant = variants
        .get(application.variant_catalog_index())
        .ok_or(SelectedApplicationSoundnessAccountingError::InvalidInventory)?;
    Ok(SelectedApplicationSoundnessRowSource {
        variant_catalog_index: application.variant_catalog_index(),
        application_statement_schema_identifier: application
            .application_statement_schema_identifier(),
        schedule_position: application.schedule_position(),
        top_count: application.top_count(),
        physical_application_multiplicity: application.application_multiplicity(),
        logical_relation_application_count: application.logical_relation_application_count(),
        variant,
    })
}

fn require_selected_variant_inventory(
    variants: &[SelectedProofVariantByteCeiling],
    application_slot_ceilings: &ProofApplicationSlotCeilings,
) -> Result<(), SelectedApplicationSoundnessAccountingError> {
    let expected_families = FIRST_PROFILE_APPLICATION_FAMILIES
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut observed_families = BTreeSet::new();
    let mut observed_selectors = BTreeSet::new();
    let mut evaluator_aggregate_top_counts = BTreeSet::new();
    for variant in variants {
        let schema_identifier = variant.application_statement_schema_identifier();
        let is_evaluator_aggregate = schema_identifier
            == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
        match variant.top_count() {
            Some(top_count)
                if is_evaluator_aggregate
                    && variant.schedule_position().is_none()
                    && (1..=FOUNDATION_PROFILE.option_count).contains(&top_count) =>
            {
                evaluator_aggregate_top_counts.insert(top_count);
            }
            None if !is_evaluator_aggregate => {}
            _ => return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory),
        }
        if application_slot_ceilings
            .family_ceiling(schema_identifier)
            .is_none()
            || !observed_selectors.insert((
                schema_identifier,
                variant.schedule_position(),
                variant.top_count(),
            ))
        {
            return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
        }
        observed_families.insert(schema_identifier);
    }
    if observed_families != expected_families
        || evaluator_aggregate_top_counts
            != (1..=FOUNDATION_PROFILE.option_count).collect::<BTreeSet<_>>()
        || application_slot_ceilings.ordered_family_ceilings().len()
            != FIRST_PROFILE_APPLICATION_FAMILIES.len()
    {
        return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
    }
    Ok(())
}

fn require_selected_action_inventory(
    action: &SelectedActionProofAccounting,
    variants: &[SelectedProofVariantByteCeiling],
    application_slot_ceilings: &ProofApplicationSlotCeilings,
    row_sources: &[SelectedApplicationSoundnessRowSource<'_>],
) -> Result<(), SelectedApplicationSoundnessAccountingError> {
    if row_sources.is_empty() {
        return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
    }
    let expected_variant_catalog_indices = variants
        .iter()
        .enumerate()
        .filter(|(_, variant)| {
            variant
                .top_count()
                .is_none_or(|top_count| top_count == action.top_count())
        })
        .map(|(variant_catalog_index, _)| variant_catalog_index)
        .collect::<BTreeSet<_>>();
    let mut observed_variant_catalog_indices = BTreeSet::new();
    let mut observed_family_multiplicities = BTreeMap::<u16, u32>::new();
    let mut physical_proof_object_count = 0_u32;
    let mut logical_relation_application_count = 0_u32;

    for row_source in row_sources {
        let variant = row_source.variant;
        if row_source.physical_application_multiplicity == 0
            || row_source.application_statement_schema_identifier
                != variant.application_statement_schema_identifier()
            || row_source.schedule_position != variant.schedule_position()
            || row_source.top_count != variant.top_count()
            || row_source
                .top_count
                .is_some_and(|top_count| top_count != action.top_count())
            || !observed_variant_catalog_indices.insert(row_source.variant_catalog_index)
        {
            return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
        }
        let expected_logical_relation_application_count = variant
            .logical_relation_count()
            .checked_mul(row_source.physical_application_multiplicity)
            .ok_or(SelectedApplicationSoundnessAccountingError::CountOverflow)?;
        if row_source.logical_relation_application_count
            != expected_logical_relation_application_count
        {
            return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
        }
        let family_multiplicity = observed_family_multiplicities
            .entry(row_source.application_statement_schema_identifier)
            .or_default();
        *family_multiplicity = family_multiplicity
            .checked_add(row_source.physical_application_multiplicity)
            .ok_or(SelectedApplicationSoundnessAccountingError::CountOverflow)?;
        physical_proof_object_count = physical_proof_object_count
            .checked_add(row_source.physical_application_multiplicity)
            .ok_or(SelectedApplicationSoundnessAccountingError::CountOverflow)?;
        logical_relation_application_count = logical_relation_application_count
            .checked_add(row_source.logical_relation_application_count)
            .ok_or(SelectedApplicationSoundnessAccountingError::CountOverflow)?;
    }

    if observed_variant_catalog_indices != expected_variant_catalog_indices
        || physical_proof_object_count != action.physical_proof_object_count()
        || logical_relation_application_count != action.logical_relation_application_count()
        || physical_proof_object_count != application_slot_ceilings.total_application_slot_ceiling()
    {
        return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
    }
    for family in application_slot_ceilings.ordered_family_ceilings() {
        if observed_family_multiplicities.remove(&family.application_statement_schema_identifier)
            != Some(family.application_slot_ceiling)
        {
            return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
        }
    }
    if !observed_family_multiplicities.is_empty() {
        return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
    }
    Ok(())
}

fn selected_action_application_soundness_accounting(
    top_count: u16,
    adversary_ideal_xof_query_ceiling: &BigUint,
    row_sources: &[SelectedApplicationSoundnessRowSource<'_>],
) -> Result<SelectedActionApplicationSoundnessAccounting, SelectedApplicationSoundnessAccountingError>
{
    let mut variant_rows = Vec::new();
    variant_rows
        .try_reserve_exact(row_sources.len())
        .map_err(|_| SelectedApplicationSoundnessAccountingError::CountOverflow)?;
    let mut round_by_round_compiler_input_bound = SelectedExactProbabilityBound::zero();
    let mut ordinary_invalid_acceptance_bound = SelectedExactProbabilityBound::zero();
    let mut quantum_random_oracle_invalid_acceptance_bound = SelectedExactProbabilityBound::zero();

    for row_source in row_sources {
        let variant = row_source.variant;
        let theorem_input = variant.round_by_round_theorem_input();
        if theorem_input.application_statement_schema_identifier()
            != variant.application_statement_schema_identifier()
            || theorem_input.schedule_position() != variant.schedule_position()
            || theorem_input.top_count() != variant.top_count()
        {
            return Err(SelectedApplicationSoundnessAccountingError::InvalidInventory);
        }
        let transition_catalog = theorem_input.transition_catalog();
        let logical_verifier_message_count = u64::try_from(
            transition_catalog
                .ordered_non_native_challenge_bad_sets()
                .len(),
        )
        .map_err(|_| SelectedApplicationSoundnessAccountingError::CountOverflow)?
        .checked_add(u64::from(
            transition_catalog.composition_batching_transition_count(),
        ))
        .and_then(|count| {
            count.checked_add(u64::from(transition_catalog.deep_point_transition_count()))
        })
        .and_then(|count| {
            count.checked_add(u64::from(
                transition_catalog.opening_batch_mca_transition_count(),
            ))
        })
        .and_then(|count| {
            count.checked_add(u64::from(transition_catalog.fri_fold_transition_count()))
        })
        .and_then(|count| {
            count.checked_add(u64::from(
                transition_catalog.query_vector_transition_count(),
            ))
        })
        .filter(|count| *count != 0)
        .ok_or(SelectedApplicationSoundnessAccountingError::CountOverflow)?;
        let selected_round_by_round_error_bound = theorem_input
            .numerical_bounds()
            .round_by_round_error_bound();
        let round_by_round_error_bound = SelectedExactProbabilityBound::new(
            selected_round_by_round_error_bound.numerator().clone(),
            selected_round_by_round_error_bound.denominator().clone(),
        )?;
        let verifier_ideal_xof_query_count = variant
            .verifier_hash_equation_ledger()
            .ideal_xof_query_count();
        let checked_oracle_equation_count = variant
            .verifier_hash_equation_ledger()
            .checked_oracle_equation_count();
        let quantum_random_oracle_single_event_bound =
            cms19_quantum_random_oracle_single_event_bound(
                adversary_ideal_xof_query_ceiling,
                verifier_ideal_xof_query_count,
                checked_oracle_equation_count,
                &round_by_round_error_bound,
            )?;

        let physical_application_multiplicity =
            BigUint::from(row_source.physical_application_multiplicity);
        round_by_round_compiler_input_bound = round_by_round_compiler_input_bound.checked_add(
            &round_by_round_error_bound.checked_multiply_integer(
                BigUint::from(CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT)
                    * &physical_application_multiplicity,
            )?,
        )?;
        let weighted_logical_message_count = logical_verifier_message_count
            .checked_mul(u64::from(row_source.physical_application_multiplicity))
            .ok_or(SelectedApplicationSoundnessAccountingError::CountOverflow)?;
        ordinary_invalid_acceptance_bound = ordinary_invalid_acceptance_bound.checked_add(
            &round_by_round_error_bound
                .checked_multiply_integer(BigUint::from(weighted_logical_message_count))?,
        )?;
        quantum_random_oracle_invalid_acceptance_bound =
            quantum_random_oracle_invalid_acceptance_bound.checked_add(
                &quantum_random_oracle_single_event_bound
                    .checked_multiply_integer(physical_application_multiplicity)?,
            )?;

        variant_rows.push(SelectedApplicationSoundnessVariantAccounting {
            variant_catalog_index: row_source.variant_catalog_index,
            application_statement_schema_identifier: row_source
                .application_statement_schema_identifier,
            schedule_position: row_source.schedule_position,
            top_count: row_source.top_count,
            physical_application_multiplicity: row_source.physical_application_multiplicity,
            logical_verifier_message_count,
            round_by_round_error_bound,
            verifier_ideal_xof_query_count,
            checked_oracle_equation_count,
            quantum_random_oracle_single_event_bound,
        });
    }

    if !round_by_round_compiler_input_bound
        .is_at_most_inverse_power_of_two(SELECTED_ROUND_BY_ROUND_MARGIN_EXPONENT)
    {
        return Err(
            SelectedApplicationSoundnessAccountingError::RoundByRoundMarginExceeded { top_count },
        );
    }
    if !ordinary_invalid_acceptance_bound
        .is_at_most_inverse_power_of_two(SELECTED_ASSURANCE_EXPONENT)
    {
        return Err(
            SelectedApplicationSoundnessAccountingError::OrdinaryBoundExceeded { top_count },
        );
    }
    if !quantum_random_oracle_invalid_acceptance_bound.is_at_most_fraction(1, 4) {
        return Err(
            SelectedApplicationSoundnessAccountingError::QuantumRandomOracleBoundExceeded {
                top_count,
            },
        );
    }

    Ok(SelectedActionApplicationSoundnessAccounting {
        top_count,
        variant_rows,
        round_by_round_compiler_input_bound,
        ordinary_invalid_acceptance_bound,
        quantum_random_oracle_invalid_acceptance_bound,
    })
}

fn cms19_quantum_random_oracle_single_event_bound(
    adversary_ideal_xof_query_ceiling: &BigUint,
    verifier_ideal_xof_query_count: u64,
    checked_oracle_equation_count: u64,
    round_by_round_error_bound: &SelectedExactProbabilityBound,
) -> Result<SelectedExactProbabilityBound, SelectedApplicationSoundnessAccountingError> {
    let combined_query_count =
        adversary_ideal_xof_query_ceiling + BigUint::from(verifier_ideal_xof_query_count);
    let round_by_round_term = SelectedExactProbabilityBound::new(
        BigUint::from(CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT)
            * combined_query_count.pow(2)
            * round_by_round_error_bound.numerator(),
        round_by_round_error_bound.denominator().clone(),
    )?;
    let database_term = SelectedExactProbabilityBound::new(
        BigUint::from(CMS19_DATABASE_TERM_COEFFICIENT) * combined_query_count.pow(3)
            + BigUint::from(2_u8) * checked_oracle_equation_count,
        power_of_two(IDEAL_XOF_OUTPUT_BIT_LENGTH),
    )?;
    round_by_round_term.checked_add(&database_term)
}

fn greatest_common_divisor(mut left: BigUint, mut right: BigUint) -> BigUint {
    while !right.is_zero() {
        let remainder = left % &right;
        left = right;
        right = remainder;
    }
    left
}

fn power_of_two(exponent: u32) -> BigUint {
    BigUint::one() << usize::try_from(exponent).expect("u32 fits usize on supported targets")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT;

    fn selected_accounting() -> SelectedProofByteAccounting {
        super::super::selected_proof_byte_accounting()
            .expect("selected proof accounting and soundness gates derive")
    }

    #[test]
    fn selected_nine_coordinate_rows_pass_and_eight_coordinate_ballot_fails_the_margin() {
        let proof_accounting = selected_accounting();
        let soundness_accounting = require_selected_application_soundness_bounds(&proof_accounting)
            .expect("selected application soundness bounds hold");
        assert_eq!(
            soundness_accounting.adversary_ideal_xof_query_ceiling(),
            &(power_of_two(SELECTED_ASSURANCE_EXPONENT) - BigUint::one()),
        );
        assert_eq!(
            soundness_accounting.actions().len(),
            usize::from(FOUNDATION_PROFILE.option_count),
        );
        assert!(soundness_accounting.actions().iter().all(|action| {
            action
                .round_by_round_compiler_input_bound()
                .is_at_most_inverse_power_of_two(SELECTED_ROUND_BY_ROUND_MARGIN_EXPONENT)
                && action
                    .ordinary_invalid_acceptance_bound()
                    .is_at_most_inverse_power_of_two(SELECTED_ASSURANCE_EXPONENT)
                && action
                    .quantum_random_oracle_invalid_acceptance_bound()
                    .is_at_most_fraction(1, 4)
        }));
        let source_row = soundness_accounting.actions()[0]
            .variant_rows()
            .first()
            .expect("selected action contains a soundness row");
        let one_more_verifier_query = cms19_quantum_random_oracle_single_event_bound(
            soundness_accounting.adversary_ideal_xof_query_ceiling(),
            source_row
                .verifier_ideal_xof_query_count()
                .checked_add(1)
                .expect("source verifier query count fits u64"),
            source_row.checked_oracle_equation_count(),
            source_row.round_by_round_error_bound(),
        )
        .expect("changed verifier-query bound derives");
        let one_more_checked_equation = cms19_quantum_random_oracle_single_event_bound(
            soundness_accounting.adversary_ideal_xof_query_ceiling(),
            source_row.verifier_ideal_xof_query_count(),
            source_row
                .checked_oracle_equation_count()
                .checked_add(1)
                .expect("source checked-equation count fits u64"),
            source_row.round_by_round_error_bound(),
        )
        .expect("changed checked-equation bound derives");
        let source_bound = source_row.quantum_random_oracle_single_event_bound();
        assert!(
            source_bound.numerator() * one_more_verifier_query.denominator()
                < one_more_verifier_query.numerator() * source_bound.denominator()
        );
        assert!(
            source_bound.numerator() * one_more_checked_equation.denominator()
                < one_more_checked_equation.numerator() * source_bound.denominator()
        );

        assert_eq!(PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, 9);
        let ballot_family =
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
        let ballot_variant = proof_accounting
            .variant_ceilings()
            .iter()
            .find(|variant| variant.application_statement_schema_identifier() == ballot_family)
            .expect("selected ballot variant");
        let prior_repetition_count = PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT - 1;
        let prior_ballot_non_native_bound = ballot_variant
            .round_by_round_theorem_input()
            .transition_catalog()
            .ordered_non_native_challenge_bad_sets()
            .iter()
            .map(|group| {
                assert_eq!(
                    group.ordered_coordinate_bounds().len(),
                    usize::from(PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT),
                );
                SelectedExactProbabilityBound::new(
                    group
                        .ordered_coordinate_bounds()
                        .iter()
                        .take(usize::from(prior_repetition_count))
                        .fold(BigUint::one(), |product, coordinate| {
                            product * coordinate.bad_candidate_count_bound()
                        }),
                    BigUint::from(group.coordinate_modulus())
                        .pow(u32::from(prior_repetition_count)),
                )
                .expect("eight-coordinate bad-set fraction derives")
            })
            .reduce(|left, right| {
                if &left.numerator * &right.denominator <= &right.numerator * &left.denominator {
                    right
                } else {
                    left
                }
            })
            .expect("the ballot relation has a non-native challenge row");
        let ballot_multiplicity = selected_proof_application_slot_ceilings()
            .expect("selected application slots derive")
            .family_ceiling(ballot_family)
            .expect("selected ballot multiplicity");
        let prior_weighted_ballot_lower_bound = prior_ballot_non_native_bound
            .checked_multiply_integer(
                BigUint::from(CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT) * ballot_multiplicity,
            )
            .expect("weighted ballot lower bound derives");
        assert!(
            !prior_weighted_ballot_lower_bound
                .is_at_most_inverse_power_of_two(SELECTED_ROUND_BY_ROUND_MARGIN_EXPONENT),
            "eight coordinates fail on the ballot contribution alone",
        );
    }

    #[test]
    fn cms19_bound_refuses_verifier_query_and_equation_count_threshold_crossings() {
        let query_ceiling = power_of_two(SELECTED_ASSURANCE_EXPONENT) - BigUint::one();
        let one_more_query = &query_ceiling + BigUint::one();
        let h_sensitive_error = SelectedExactProbabilityBound::new(
            BigUint::one(),
            BigUint::from(48_u8) * &query_ceiling * &one_more_query,
        )
        .expect("h-sensitive round-by-round error derives");
        let before_h_change = cms19_quantum_random_oracle_single_event_bound(
            &query_ceiling,
            0,
            0,
            &h_sensitive_error,
        )
        .expect("pre-change h bound derives");
        let after_h_change = cms19_quantum_random_oracle_single_event_bound(
            &query_ceiling,
            1,
            0,
            &h_sensitive_error,
        )
        .expect("post-change h bound derives");
        assert!(before_h_change.is_at_most_fraction(1, 4));
        assert!(!after_h_change.is_at_most_fraction(1, 4));

        let xof_denominator = power_of_two(IDEAL_XOF_OUTPUT_BIT_LENGTH);
        let k_sensitive_error_numerator = power_of_two(IDEAL_XOF_OUTPUT_BIT_LENGTH - 2)
            - BigUint::one()
            - BigUint::from(CMS19_DATABASE_TERM_COEFFICIENT) * query_ceiling.pow(3);
        let k_sensitive_error = SelectedExactProbabilityBound::new(
            k_sensitive_error_numerator,
            &xof_denominator * CMS19_ROUND_BY_ROUND_ERROR_COEFFICIENT * query_ceiling.pow(2),
        )
        .expect("k-sensitive round-by-round error derives");
        let before_k_change = cms19_quantum_random_oracle_single_event_bound(
            &query_ceiling,
            0,
            0,
            &k_sensitive_error,
        )
        .expect("pre-change k bound derives");
        let after_k_change = cms19_quantum_random_oracle_single_event_bound(
            &query_ceiling,
            0,
            1,
            &k_sensitive_error,
        )
        .expect("post-change k bound derives");
        assert!(before_k_change.is_at_most_fraction(1, 4));
        assert!(!after_k_change.is_at_most_fraction(1, 4));
    }

    #[test]
    fn action_inventory_drift_is_refused_before_bound_evaluation() {
        let proof_accounting = selected_accounting();
        let action = proof_accounting
            .actions()
            .first()
            .expect("selected action inventory is non-empty");
        let application_slot_ceilings =
            selected_proof_application_slot_ceilings().expect("selected application slots derive");
        let complete_rows =
            selected_action_soundness_row_sources(action, proof_accounting.variant_ceilings())
                .expect("selected action rows derive");
        require_selected_action_inventory(
            action,
            proof_accounting.variant_ceilings(),
            &application_slot_ceilings,
            &complete_rows,
        )
        .expect("source-derived inventory is complete");

        let mut missing_row = complete_rows.clone();
        missing_row.pop();
        assert_eq!(
            require_selected_action_inventory(
                action,
                proof_accounting.variant_ceilings(),
                &application_slot_ceilings,
                &missing_row,
            ),
            Err(SelectedApplicationSoundnessAccountingError::InvalidInventory),
        );

        let mut duplicated_row = complete_rows.clone();
        duplicated_row.push(complete_rows[0].clone());
        assert_eq!(
            require_selected_action_inventory(
                action,
                proof_accounting.variant_ceilings(),
                &application_slot_ceilings,
                &duplicated_row,
            ),
            Err(SelectedApplicationSoundnessAccountingError::InvalidInventory),
        );

        let mut changed_multiplicity = complete_rows;
        changed_multiplicity[0].physical_application_multiplicity = changed_multiplicity[0]
            .physical_application_multiplicity
            .checked_add(1)
            .expect("test multiplicity fits u32");
        assert_eq!(
            require_selected_action_inventory(
                action,
                proof_accounting.variant_ceilings(),
                &application_slot_ceilings,
                &changed_multiplicity,
            ),
            Err(SelectedApplicationSoundnessAccountingError::InvalidInventory),
        );
    }
}
