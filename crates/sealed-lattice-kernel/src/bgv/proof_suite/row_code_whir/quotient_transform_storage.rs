//! Bounded transform planning for quotient materialization.
//!
//! Relation coefficients are reconstructed from authenticated sources and
//! private coordinate replay. Each constraint transforms its required columns into constraint-local external
//! vectors and releases them as soon as that constraint is accumulated. The
//! transform itself runs in place in one domain-sized WASM buffer, then
//! streams its result into external memory. Recomputing a column used by a
//! later constraint keeps peak browser scratch bounded independently of the
//! relation-wide live-column interval graph. Persistent identities are reused
//! only across disjoint lifecycles.

use std::collections::BTreeMap;

use crate::bgv::proof_suite::{
    CommonProofProverError, ProofEvaluationDomain, RelationPlanCheckContext, RelationPlanVariant,
    external_memory::{
        ProofExternalMemoryObject, ProofExternalMemoryObjectPlan, ProofExternalMemoryProtection,
    },
    external_polynomial::{ExternalPolynomialError, ExternalPolynomialVector},
    prover::{
        CommonProofQuotientConstraintTransformKey, CommonProofReplayPolynomialPlan,
        common_proof_quotient_constraint_catalog,
    },
    relation_plan::RelationColumnValueType,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirQuotientColumnSourcePlan {
    value_type: RelationColumnValueType,
    coefficient_count: usize,
}

impl RowCodeWhirQuotientColumnSourcePlan {
    pub(super) const fn new(value_type: RelationColumnValueType, coefficient_count: usize) -> Self {
        Self {
            value_type,
            coefficient_count,
        }
    }

    pub(super) const fn value_type(self) -> RelationColumnValueType {
        self.value_type
    }

    pub(super) const fn coefficient_count(self) -> usize {
        self.coefficient_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirQuotientColumnTransformPlan {
    evaluation_domain: ProofEvaluationDomain,
    source: RowCodeWhirQuotientColumnSourcePlan,
    output: CommonProofReplayPolynomialPlan,
    output_vector: ExternalPolynomialVector,
    object_plans: [ProofExternalMemoryObjectPlan; 1],
    next_executor_step: u32,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count_excluding_deletions: u64,
}

impl RowCodeWhirQuotientColumnTransformPlan {
    pub(super) const fn evaluation_domain(self) -> ProofEvaluationDomain {
        self.evaluation_domain
    }

    pub(super) const fn source(self) -> RowCodeWhirQuotientColumnSourcePlan {
        self.source
    }

    pub(super) const fn output(self) -> CommonProofReplayPolynomialPlan {
        self.output
    }

    pub(super) const fn final_output(self) -> ExternalPolynomialVector {
        self.output_vector
    }

    pub(super) const fn total_written_byte_length(self) -> u64 {
        self.total_written_byte_length
    }

    pub(super) const fn total_read_byte_length(self) -> u64 {
        self.total_read_byte_length
    }

    pub(super) const fn transaction_count_excluding_deletions(self) -> u64 {
        self.transaction_count_excluding_deletions
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PersistentOutputIdentity {
    object: ProofExternalMemoryObject,
    last_use_step: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PersistentOutputLifecycle {
    issued_step: u32,
    last_use_step: u32,
}

pub(in crate::bgv::proof_suite) struct RowCodeWhirQuotientTransformStoragePlan {
    pub(super) transform_plans:
        BTreeMap<CommonProofQuotientConstraintTransformKey, RowCodeWhirQuotientColumnTransformPlan>,
    pub(super) constraint_evaluation_steps: Vec<u32>,
    /// The final step at which each replayed coefficient vector is read by a
    /// constraint-local transform. The combined planner may extend the replay
    /// object's last use for later proof phases.
    pub(super) source_last_use_steps: BTreeMap<u32, u32>,
    pub(super) next_executor_step: u32,
    pub(super) next_free_object_ordinal: u32,
    pub(super) object_plans: Vec<ProofExternalMemoryObjectPlan>,
    pub(super) total_written_byte_length: u64,
    pub(super) total_read_byte_length: u64,
    /// Transform transactions excluding deletions, which the combined
    /// external-memory plan coalesces globally by last-use step.
    pub(super) transaction_count_excluding_deletions: u64,
    pub(super) peak_active_output_count: u32,
}

pub(in crate::bgv::proof_suite) struct RowCodeWhirQuotientTransformStorageRequest<'a> {
    pub(in crate::bgv::proof_suite) variant: &'a RelationPlanVariant,
    pub(in crate::bgv::proof_suite) relation_context: &'a RelationPlanCheckContext,
    pub(in crate::bgv::proof_suite) evaluation_domain: ProofEvaluationDomain,
    pub(in crate::bgv::proof_suite) relation_replay_polynomial_plans:
        &'a BTreeMap<u32, RowCodeWhirQuotientColumnSourcePlan>,
    pub(in crate::bgv::proof_suite) first_free_object_ordinal: u32,
    pub(in crate::bgv::proof_suite) first_executor_step: u32,
    pub(in crate::bgv::proof_suite) maximum_chunk_byte_length: u32,
    pub(in crate::bgv::proof_suite) protection: ProofExternalMemoryProtection,
}

pub(in crate::bgv::proof_suite) fn plan_row_code_whir_quotient_transform_storage(
    request: RowCodeWhirQuotientTransformStorageRequest<'_>,
) -> Result<RowCodeWhirQuotientTransformStoragePlan, CommonProofProverError> {
    let RowCodeWhirQuotientTransformStorageRequest {
        variant,
        relation_context,
        evaluation_domain,
        relation_replay_polynomial_plans,
        first_free_object_ordinal,
        first_executor_step,
        maximum_chunk_byte_length,
        protection,
    } = request;
    if maximum_chunk_byte_length == 0 {
        return Err(CommonProofProverError::InvalidInput);
    }
    validate_quotient_transform_domain(variant, relation_context, evaluation_domain)?;
    validate_relation_replay_polynomial_plans(
        variant,
        evaluation_domain.size(),
        relation_replay_polynomial_plans,
    )?;
    let constraint_catalog = common_proof_quotient_constraint_catalog(variant)?;
    for column_ordinal in constraint_catalog.column_usages().keys() {
        if !relation_replay_polynomial_plans.contains_key(column_ordinal) {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }

    let mut constraint_evaluation_steps = Vec::new();
    constraint_evaluation_steps
        .try_reserve_exact(variant.constraint_count())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut next_executor_step = first_executor_step;
    for columns in constraint_catalog.constraint_columns() {
        let transform_step_count =
            u32::try_from(columns.len()).map_err(|_| CommonProofProverError::CountOverflow)?;
        let evaluation_step = next_executor_step
            .checked_add(transform_step_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if constraint_evaluation_steps
            .last()
            .is_some_and(|previous_step| *previous_step >= evaluation_step)
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        constraint_evaluation_steps.push(evaluation_step);
        next_executor_step = evaluation_step
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    if constraint_evaluation_steps.len() != variant.constraint_count() {
        return Err(CommonProofProverError::InvalidQuotient);
    }

    let mut next_free_object_ordinal = first_free_object_ordinal;
    let mut persistent_output_identities = Vec::<PersistentOutputIdentity>::new();
    let mut output_lifecycles = Vec::<PersistentOutputLifecycle>::new();
    output_lifecycles
        .try_reserve_exact(
            constraint_catalog
                .constraint_columns()
                .iter()
                .map(Vec::len)
                .sum(),
        )
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut transform_plans = BTreeMap::new();
    let mut source_last_use_steps = BTreeMap::new();
    let mut object_plans = Vec::new();
    let mut total_written_byte_length = 0_u64;
    let mut total_read_byte_length = 0_u64;
    let mut transaction_count_excluding_deletions = 0_u64;
    let mut next_transform_step = first_executor_step;

    for (constraint_index, columns) in constraint_catalog.constraint_columns().iter().enumerate() {
        let constraint_ordinal =
            u32::try_from(constraint_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        for column_ordinal in columns {
            let final_output_last_use_step = constraint_evaluation_steps
                .get(constraint_index)
                .copied()
                .ok_or(CommonProofProverError::InvalidQuotient)?;
            let persistent_final_output_object = persistent_output_object(
                &mut persistent_output_identities,
                &mut next_free_object_ordinal,
                next_transform_step,
                final_output_last_use_step,
            )?;
            let source_plan = relation_replay_polynomial_plans
                .get(column_ordinal)
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn)?;
            let output_plan = CommonProofReplayPolynomialPlan::new(
                persistent_final_output_object,
                source_plan.value_type(),
                evaluation_domain.size(),
            )?;
            let output_vector = ExternalPolynomialVector::new(
                output_plan.object(),
                output_plan.value_type(),
                output_plan.coefficient_count(),
            )
            .map_err(map_external_polynomial_error)?;
            let expected_next_transform_step = next_transform_step
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let object_plan = ProofExternalMemoryObjectPlan::new(
                output_plan.object(),
                protection,
                output_plan.exact_byte_length(),
                next_transform_step,
                next_transform_step,
                final_output_last_use_step,
            );
            let maximum_chunk_byte_length = u64::from(maximum_chunk_byte_length);
            let output_append_transaction_count = output_plan
                .exact_byte_length()
                .div_ceil(maximum_chunk_byte_length);
            let transform_plan = RowCodeWhirQuotientColumnTransformPlan {
                evaluation_domain,
                source: source_plan,
                output: output_plan,
                output_vector,
                object_plans: [object_plan],
                next_executor_step: expected_next_transform_step,
                total_written_byte_length: output_plan.exact_byte_length(),
                total_read_byte_length: 0,
                transaction_count_excluding_deletions: output_append_transaction_count
                    .checked_add(2)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            };
            object_plans
                .try_reserve_exact(1)
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            object_plans.push(object_plan);
            total_written_byte_length = total_written_byte_length
                .checked_add(transform_plan.total_written_byte_length())
                .ok_or(CommonProofProverError::CountOverflow)?;
            total_read_byte_length = total_read_byte_length
                .checked_add(transform_plan.total_read_byte_length())
                .ok_or(CommonProofProverError::CountOverflow)?;
            transaction_count_excluding_deletions = transaction_count_excluding_deletions
                .checked_add(transform_plan.transaction_count_excluding_deletions())
                .ok_or(CommonProofProverError::CountOverflow)?;
            let transform_key =
                CommonProofQuotientConstraintTransformKey::new(constraint_ordinal, *column_ordinal);
            if transform_plans
                .insert(transform_key, transform_plan)
                .is_some()
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            source_last_use_steps
                .entry(*column_ordinal)
                .and_modify(|last_use_step| *last_use_step = next_transform_step)
                .or_insert(next_transform_step);
            output_lifecycles.push(PersistentOutputLifecycle {
                issued_step: next_transform_step,
                last_use_step: final_output_last_use_step,
            });
            next_transform_step = expected_next_transform_step;
        }
        if constraint_evaluation_steps.get(constraint_index).copied() != Some(next_transform_step) {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        next_transform_step = next_transform_step
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    if next_transform_step != next_executor_step
        || transform_plans.len()
            != constraint_catalog
                .constraint_columns()
                .iter()
                .map(Vec::len)
                .sum::<usize>()
        || source_last_use_steps.len() != constraint_catalog.column_usages().len()
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }

    let peak_active_output_count = exact_peak_active_output_count(&output_lifecycles)?;
    if usize::try_from(peak_active_output_count)
        .map_err(|_| CommonProofProverError::CountOverflow)?
        != persistent_output_identities.len()
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }

    Ok(RowCodeWhirQuotientTransformStoragePlan {
        transform_plans,
        constraint_evaluation_steps,
        source_last_use_steps,
        next_executor_step,
        next_free_object_ordinal,
        object_plans,
        total_written_byte_length,
        total_read_byte_length,
        transaction_count_excluding_deletions,
        peak_active_output_count,
    })
}

fn validate_quotient_transform_domain(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    evaluation_domain: ProofEvaluationDomain,
) -> Result<(), CommonProofProverError> {
    let trace_domain_size = usize::try_from(variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let relation_evaluation_domain_size = usize::try_from(variant.evaluation_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let quotient_component_degree_bound_exclusive =
        usize::try_from(relation_context.quotient_component_degree_bound_exclusive)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let expected_quotient_domain_size = trace_domain_size
        .max(quotient_component_degree_bound_exclusive)
        .checked_next_power_of_two()
        .ok_or(CommonProofProverError::CountOverflow)?;
    let relation_evaluation_domain = ProofEvaluationDomain::new(
        relation_evaluation_domain_size,
        relation_context.evaluation_coset_offset,
    )
    .map_err(|_| CommonProofProverError::InvalidQuotient)?;

    if trace_domain_size == 0
        || !trace_domain_size.is_power_of_two()
        || evaluation_domain.size() != expected_quotient_domain_size
        || evaluation_domain.size() < trace_domain_size
        || evaluation_domain.size() > relation_evaluation_domain_size
        || !evaluation_domain.size().is_multiple_of(trace_domain_size)
        || evaluation_domain.coset_offset().canonical() != relation_context.evaluation_coset_offset
        || relation_evaluation_domain.generator().canonical()
            != relation_context.evaluation_domain_generator
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    Ok(())
}

fn validate_relation_replay_polynomial_plans(
    variant: &RelationPlanVariant,
    evaluation_domain_size: usize,
    relation_replay_polynomial_plans: &BTreeMap<u32, RowCodeWhirQuotientColumnSourcePlan>,
) -> Result<(), CommonProofProverError> {
    for (column_ordinal, source_plan) in relation_replay_polynomial_plans {
        let descriptor = variant
            .ordered_columns()
            .get(
                usize::try_from(*column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let expected_coefficient_count =
            usize::try_from(descriptor.source_degree_bound_exclusive())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        if source_plan.value_type() != descriptor.value_type()
            || source_plan.coefficient_count() == 0
            || source_plan.coefficient_count() > expected_coefficient_count
            || source_plan.coefficient_count() > evaluation_domain_size
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    Ok(())
}

fn allocate_object(
    next_free_object_ordinal: &mut u32,
) -> Result<ProofExternalMemoryObject, CommonProofProverError> {
    let object = ProofExternalMemoryObject::new(*next_free_object_ordinal);
    *next_free_object_ordinal = (*next_free_object_ordinal)
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    Ok(object)
}

fn persistent_output_object(
    persistent_output_identities: &mut Vec<PersistentOutputIdentity>,
    next_free_object_ordinal: &mut u32,
    issued_step: u32,
    last_use_step: u32,
) -> Result<ProofExternalMemoryObject, CommonProofProverError> {
    if last_use_step < issued_step {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    if let Some(identity) = persistent_output_identities
        .iter_mut()
        .find(|identity| identity.last_use_step < issued_step)
    {
        identity.last_use_step = last_use_step;
        return Ok(identity.object);
    }
    let object = allocate_object(next_free_object_ordinal)?;
    persistent_output_identities
        .try_reserve_exact(1)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    persistent_output_identities.push(PersistentOutputIdentity {
        object,
        last_use_step,
    });
    Ok(object)
}

fn exact_peak_active_output_count(
    lifecycles: &[PersistentOutputLifecycle],
) -> Result<u32, CommonProofProverError> {
    let mut events = BTreeMap::<u32, (u32, u32)>::new();
    for lifecycle in lifecycles {
        if lifecycle.last_use_step < lifecycle.issued_step {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let issuance_count = &mut events.entry(lifecycle.issued_step).or_default().1;
        *issuance_count = issuance_count
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let deletion_step = lifecycle
            .last_use_step
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let deletion_count = &mut events.entry(deletion_step).or_default().0;
        *deletion_count = deletion_count
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    let mut active_output_count = 0_u32;
    let mut peak_active_output_count = 0_u32;
    for (_, (deletion_count, issuance_count)) in events {
        active_output_count = active_output_count
            .checked_sub(deletion_count)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        active_output_count = active_output_count
            .checked_add(issuance_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        peak_active_output_count = peak_active_output_count.max(active_output_count);
    }
    if active_output_count != 0 || peak_active_output_count == 0 {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    Ok(peak_active_output_count)
}

fn map_external_polynomial_error(error: ExternalPolynomialError) -> CommonProofProverError {
    match error {
        ExternalPolynomialError::InvalidVector => CommonProofProverError::InvalidColumn,
        ExternalPolynomialError::CountOverflow => CommonProofProverError::CountOverflow,
        ExternalPolynomialError::AllocationLimitExceeded => {
            CommonProofProverError::AllocationLimitExceeded
        }
        ExternalPolynomialError::Field(error) => CommonProofProverError::Field(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::bgv::proof_suite::{
        CollectivePublicKeyAggregatePlanInput, PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
        PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
        PublicAggregateRelationGeometry, RelationPlanCheckContext, ResolvedSuiteModulus,
        SuiteModulusReference, compile_collective_public_key_aggregate_relation_plan,
    };

    fn modular_product(first: u64, second: u64, modulus: u64) -> u64 {
        ((u128::from(first) * u128::from(second)) % u128::from(modulus)) as u64
    }

    fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
        let mut result = 1_u64;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = modular_product(result, base, modulus);
            }
            exponent >>= 1;
            if exponent > 0 {
                base = modular_product(base, base, modulus);
            }
        }
        result
    }

    fn compact_public_aggregate_context() -> RelationPlanCheckContext {
        let evaluation_domain_size = 128_u64;
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            out_of_domain_point_count: 2,
            quotient_component_count: 2,
            quotient_component_degree_bound_exclusive: 64,
            phase_column_query_coordinate_count: 8,
            non_native_theta_repetition_count: 2,
            non_native_alpha_repetition_count: 2,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![
                ResolvedSuiteModulus::new(SuiteModulusReference::data(0), 97),
                ResolvedSuiteModulus::new(SuiteModulusReference::special(0), 193),
            ],
        }
    }

    fn compact_public_aggregate_input() -> CollectivePublicKeyAggregatePlanInput {
        CollectivePublicKeyAggregatePlanInput {
            geometry: PublicAggregateRelationGeometry {
                ring_degree: 16,
                evaluation_domain_size: 128,
                opening_degree_bound_exclusive: 64,
                public_polynomial_column_degree_bound_exclusive: 8,
                participant_count: 3,
            },
            ordered_component_moduli: vec![
                SuiteModulusReference::data(0),
                SuiteModulusReference::special(0),
            ],
        }
    }

    #[test]
    fn active_output_count_treats_last_use_as_inclusive() {
        let lifecycles = [
            PersistentOutputLifecycle {
                issued_step: 3,
                last_use_step: 8,
            },
            PersistentOutputLifecycle {
                issued_step: 5,
                last_use_step: 5,
            },
            PersistentOutputLifecycle {
                issued_step: 6,
                last_use_step: 9,
            },
            PersistentOutputLifecycle {
                issued_step: 10,
                last_use_step: 12,
            },
        ];
        assert_eq!(exact_peak_active_output_count(&lifecycles), Ok(2));
    }

    #[test]
    fn persistent_output_identity_reuse_requires_disjoint_lifecycles() {
        let mut identities = Vec::new();
        let mut next_free_object_ordinal = 20;
        let first = persistent_output_object(&mut identities, &mut next_free_object_ordinal, 3, 8)
            .expect("the first output identity is allocated");
        let overlapping =
            persistent_output_object(&mut identities, &mut next_free_object_ordinal, 8, 12)
                .expect("an inclusive overlap receives a distinct identity");
        let disjoint =
            persistent_output_object(&mut identities, &mut next_free_object_ordinal, 9, 10)
                .expect("the ended lifecycle identity is reusable");

        assert_ne!(first, overlapping);
        assert_eq!(first, disjoint);
        assert_eq!(identities.len(), 2);
        assert_eq!(next_free_object_ordinal, 22);
    }

    #[test]
    fn quotient_transform_accepts_exact_recomputed_lengths_below_descriptor_ceilings() {
        let relation_context = compact_public_aggregate_context();
        let compiled_plan = compile_collective_public_key_aggregate_relation_plan(
            &compact_public_aggregate_input(),
            &relation_context,
        )
        .expect("the compact aggregate relation compiles");
        let variant = compiled_plan
            .select_variant(None, None)
            .expect("the compact aggregate relation has one variant");
        let evaluation_domain =
            ProofEvaluationDomain::new(64, 7).expect("the compact quotient domain is valid");
        let replay_plans = variant
            .ordered_columns()
            .iter()
            .enumerate()
            .map(|(column_index, descriptor)| {
                let column_ordinal =
                    u32::try_from(column_index).expect("the compact column ordinal fits u32");
                let descriptor_ceiling =
                    usize::try_from(descriptor.source_degree_bound_exclusive())
                        .expect("the compact descriptor ceiling fits usize");
                let exact_coefficient_count = (descriptor_ceiling / 2).max(1);
                let source_plan = RowCodeWhirQuotientColumnSourcePlan::new(
                    descriptor.value_type(),
                    exact_coefficient_count,
                );
                (column_ordinal, source_plan)
            })
            .collect::<BTreeMap<_, _>>();

        validate_relation_replay_polynomial_plans(variant, evaluation_domain.size(), &replay_plans)
            .expect("exact recomputed lengths below descriptor ceilings remain valid");
        plan_row_code_whir_quotient_transform_storage(RowCodeWhirQuotientTransformStorageRequest {
            variant,
            relation_context: &relation_context,
            evaluation_domain,
            relation_replay_polynomial_plans: &replay_plans,
            first_free_object_ordinal: 0,
            first_executor_step: 11,
            maximum_chunk_byte_length: 1_024,
            protection: ProofExternalMemoryProtection::PublicIntegrity,
        })
        .expect("the quotient planner zero-pads exact replay vectors in its transform buffer");
    }

    #[test]
    fn checked_relation_plan_drives_transform_keys_lifetimes_and_accounting() {
        let relation_context = compact_public_aggregate_context();
        let compiled_plan = compile_collective_public_key_aggregate_relation_plan(
            &compact_public_aggregate_input(),
            &relation_context,
        )
        .expect("the compact aggregate relation compiles");
        let variant = compiled_plan
            .select_variant(None, None)
            .expect("the compact aggregate relation has one variant");
        let evaluation_domain =
            ProofEvaluationDomain::new(64, 7).expect("the compact quotient domain is valid");
        let relation_replay_polynomial_plans = variant
            .ordered_columns()
            .iter()
            .enumerate()
            .map(|(column_index, descriptor)| {
                let column_ordinal =
                    u32::try_from(column_index).expect("the compact column ordinal fits u32");
                let coefficient_count = usize::try_from(descriptor.source_degree_bound_exclusive())
                    .expect("the compact coefficient count fits usize");
                let plan = RowCodeWhirQuotientColumnSourcePlan::new(
                    descriptor.value_type(),
                    coefficient_count,
                );
                (column_ordinal, plan)
            })
            .collect::<BTreeMap<_, _>>();
        let first_free_object_ordinal = 0;
        let first_executor_step = 11;
        let plan = plan_row_code_whir_quotient_transform_storage(
            RowCodeWhirQuotientTransformStorageRequest {
                variant,
                relation_context: &relation_context,
                evaluation_domain,
                relation_replay_polynomial_plans: &relation_replay_polynomial_plans,
                first_free_object_ordinal,
                first_executor_step,
                maximum_chunk_byte_length: 1_024,
                protection: ProofExternalMemoryProtection::PublicIntegrity,
            },
        )
        .expect("the compact quotient transform plan is bounded");
        let constraint_catalog = common_proof_quotient_constraint_catalog(variant)
            .expect("the checked relation has a canonical constraint catalog");

        assert_eq!(
            plan.transform_plans.len(),
            constraint_catalog
                .constraint_columns()
                .iter()
                .map(Vec::len)
                .sum::<usize>()
        );
        assert_eq!(
            plan.constraint_evaluation_steps.len(),
            variant.constraint_count()
        );
        assert!(
            plan.constraint_evaluation_steps
                .windows(2)
                .all(|steps| steps[0] < steps[1])
        );
        assert_eq!(
            plan.next_executor_step,
            plan.constraint_evaluation_steps
                .last()
                .copied()
                .expect("the checked relation has constraints")
                + 1
        );

        for (transform_key, transform_plan) in &plan.transform_plans {
            assert!(
                plan.source_last_use_steps
                    .get(&transform_key.column_ordinal())
                    .is_some_and(|last_use_step| {
                        *last_use_step
                            >= transform_plan
                                .object_plans
                                .first()
                                .expect("each transform has one output lifecycle")
                                .issued_step()
                    })
            );
            assert!(
                transform_plan.next_executor_step
                    <= plan.constraint_evaluation_steps[usize::try_from(
                        transform_key.constraint_ordinal()
                    )
                    .expect("the constraint ordinal fits usize")]
            );
        }

        let persistent_output_objects = plan
            .transform_plans
            .values()
            .map(|transform_plan| transform_plan.final_output().object())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            persistent_output_objects.len(),
            usize::try_from(plan.peak_active_output_count)
                .expect("the active output count fits usize")
        );
        assert_eq!(
            plan.next_free_object_ordinal,
            first_free_object_ordinal + plan.peak_active_output_count
        );
        assert_eq!(
            usize::try_from(plan.peak_active_output_count)
                .expect("the active output count fits usize"),
            constraint_catalog
                .constraint_columns()
                .iter()
                .map(Vec::len)
                .max()
                .expect("the checked relation has constraints"),
        );

        let mut lifecycles_by_object =
            BTreeMap::<ProofExternalMemoryObject, Vec<(u32, u32)>>::new();
        for object_plan in &plan.object_plans {
            lifecycles_by_object
                .entry(object_plan.object())
                .or_default()
                .push((object_plan.issued_step(), object_plan.last_use_step()));
        }
        for lifecycles in lifecycles_by_object.values_mut() {
            lifecycles.sort_unstable();
            assert!(
                lifecycles.windows(2).all(|pair| pair[0].1 < pair[1].0),
                "a reused physical identity must have disjoint lifecycles",
            );
        }

        assert_eq!(
            plan.total_written_byte_length,
            plan.transform_plans
                .values()
                .fold(0_u64, |total, transform| {
                    total + transform.total_written_byte_length()
                })
        );
        assert_eq!(
            plan.total_read_byte_length,
            plan.transform_plans
                .values()
                .fold(0_u64, |total, transform| {
                    total + transform.total_read_byte_length()
                })
        );
        assert_eq!(
            plan.transaction_count_excluding_deletions,
            plan.transform_plans
                .values()
                .fold(0_u64, |total, transform| {
                    total + transform.transaction_count_excluding_deletions()
                })
        );
    }
}
