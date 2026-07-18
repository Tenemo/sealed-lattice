//! Production-derived inputs to the application round-by-round theorem.
//!
//! These values are deliberately not part of a proof, statement, certificate,
//! or verifier result. They are recomputed from the checked relation grammar
//! and selected proof context so theorem accounting cannot drift from the
//! auxiliary-column construction or transcript schedule.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;

use super::{
    RelationChallengeRole, RelationExpressionInstruction, RelationPlanCheckContext,
    RelationPlanError, RelationPlanVariant, SuiteModulusReference,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationApplicationChallengeBadSetCoordinate {
    repetition_ordinal: u16,
    bad_polynomial_degree_bound: u64,
    bad_candidate_count_bound: u64,
}

impl RelationApplicationChallengeBadSetCoordinate {
    pub(crate) const fn repetition_ordinal(self) -> u16 {
        self.repetition_ordinal
    }

    pub(crate) const fn bad_polynomial_degree_bound(self) -> u64 {
        self.bad_polynomial_degree_bound
    }

    pub(crate) const fn bad_candidate_count_bound(self) -> u64 {
        self.bad_candidate_count_bound
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationApplicationChallengeBadSetGroup {
    challenge_role: RelationChallengeRole,
    modulus_reference: SuiteModulusReference,
    coordinate_modulus: u64,
    ordered_coordinate_bounds: Vec<RelationApplicationChallengeBadSetCoordinate>,
}

impl RelationApplicationChallengeBadSetGroup {
    pub(crate) const fn challenge_role(&self) -> RelationChallengeRole {
        self.challenge_role
    }

    pub(crate) const fn modulus_reference(&self) -> SuiteModulusReference {
        self.modulus_reference
    }

    pub(crate) const fn coordinate_modulus(&self) -> u64 {
        self.coordinate_modulus
    }

    pub(crate) fn ordered_coordinate_bounds(
        &self,
    ) -> &[RelationApplicationChallengeBadSetCoordinate] {
        &self.ordered_coordinate_bounds
    }

    /// Numerator of the product-space bad-set fraction. Coordinates in one
    /// theta or alpha vector are sampled jointly but uniformly from the full
    /// Cartesian product, so their candidate counts multiply.
    pub(crate) fn product_bad_candidate_count_bound(&self) -> BigUint {
        self.ordered_coordinate_bounds
            .iter()
            .fold(BigUint::from(1_u8), |product, coordinate| {
                product * coordinate.bad_candidate_count_bound
            })
    }

    pub(crate) fn product_space_cardinality(&self) -> BigUint {
        self.ordered_coordinate_bounds
            .iter()
            .fold(BigUint::from(1_u8), |cardinality, _| {
                cardinality * self.coordinate_modulus
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationApplicationDeepAllowedSetRootBound {
    identity_degree_bound: u64,
    extension_field_cardinality: BigUint,
    forbidden_candidate_count_bound: BigUint,
    allowed_candidate_count_lower_bound: BigUint,
    root_count_bound: BigUint,
}

impl RelationApplicationDeepAllowedSetRootBound {
    pub(crate) const fn identity_degree_bound(&self) -> u64 {
        self.identity_degree_bound
    }

    pub(crate) const fn extension_field_cardinality(&self) -> &BigUint {
        &self.extension_field_cardinality
    }

    pub(crate) const fn forbidden_candidate_count_bound(&self) -> &BigUint {
        &self.forbidden_candidate_count_bound
    }

    pub(crate) const fn allowed_candidate_count_lower_bound(&self) -> &BigUint {
        &self.allowed_candidate_count_lower_bound
    }

    pub(crate) const fn root_count_bound(&self) -> &BigUint {
        &self.root_count_bound
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationApplicationRoundByRoundTransitionCatalog {
    ordered_non_native_challenge_bad_sets: Vec<RelationApplicationChallengeBadSetGroup>,
    composition_coefficient_count: u32,
    composition_batching_transition_count: u16,
    deep_point_transition_count: u16,
    deep_allowed_set_root_bound: RelationApplicationDeepAllowedSetRootBound,
    opening_batch_mca_transition_count: u32,
    fri_fold_transition_count: u16,
    query_vector_transition_count: u16,
    query_vector_position_count: u32,
    maximum_candidate_draws_per_output: u32,
}

impl RelationApplicationRoundByRoundTransitionCatalog {
    pub(crate) fn ordered_non_native_challenge_bad_sets(
        &self,
    ) -> &[RelationApplicationChallengeBadSetGroup] {
        &self.ordered_non_native_challenge_bad_sets
    }

    pub(crate) const fn composition_coefficient_count(&self) -> u32 {
        self.composition_coefficient_count
    }

    pub(crate) const fn composition_batching_transition_count(&self) -> u16 {
        self.composition_batching_transition_count
    }

    pub(crate) const fn deep_point_transition_count(&self) -> u16 {
        self.deep_point_transition_count
    }

    pub(crate) const fn deep_allowed_set_root_bound(
        &self,
    ) -> &RelationApplicationDeepAllowedSetRootBound {
        &self.deep_allowed_set_root_bound
    }

    /// The GMW/Batched-FRI mapping treats each ordered opening claim as one
    /// sequential length-two Powers/MCA transition.
    pub(crate) const fn opening_batch_mca_transition_count(&self) -> u32 {
        self.opening_batch_mca_transition_count
    }

    pub(crate) const fn fri_fold_transition_count(&self) -> u16 {
        self.fri_fold_transition_count
    }

    /// The query vector is one product-space verifier message, not one
    /// round-by-round transition per queried position.
    pub(crate) const fn query_vector_transition_count(&self) -> u16 {
        self.query_vector_transition_count
    }

    /// This count is the exponent in the final query transition probability.
    pub(crate) const fn query_vector_position_count(&self) -> u32 {
        self.query_vector_position_count
    }

    /// Exhausting this ceiling refuses proof generation or verification. It is
    /// an availability bound and contributes no invalid-acceptance term.
    pub(crate) const fn maximum_candidate_draws_per_output(&self) -> u32 {
        self.maximum_candidate_draws_per_output
    }
}

impl RelationPlanVariant {
    pub(crate) fn application_non_native_challenge_bad_set_catalog(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<RelationApplicationChallengeBadSetGroup>, RelationPlanError> {
        self.validate_integer_lift_application_constraint_topology(context)?;

        let mut degree_bounds =
            BTreeMap::<(RelationChallengeRole, SuiteModulusReference), BTreeMap<u16, u64>>::new();

        for batch in &self.ordered_integer_lift_batches {
            let degree_bound =
                integer_lift_theta_bad_polynomial_degree_bound(self.trace_domain_size, batch)?;
            let coordinates = degree_bounds
                .entry((
                    RelationChallengeRole::NonNativeTheta,
                    batch.modulus_reference,
                ))
                .or_default();
            if coordinates
                .insert(batch.challenge_ordinal, degree_bound)
                .is_some()
            {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
        }

        for batch in &self.ordered_coefficient_local_identity_batches {
            let constraint = self
                .ordered_constraints
                .get(
                    usize::try_from(batch.constraint_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::InvalidConstraint)?;
            let modulus_ordinal = self.non_native_modulus_ordinal(batch.modulus_reference)?;
            if constraint.numerator_postfix_expression
                != batch.numerator_postfix_expression(modulus_ordinal)?
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let degree_bound = batch
                .ordered_residuals
                .last()
                .filter(|_| {
                    batch
                        .ordered_residuals
                        .iter()
                        .enumerate()
                        .all(|(index, residual)| {
                            u32::try_from(index).ok() == Some(residual.unit_ordinal)
                        })
                })
                .map(|residual| u64::from(residual.unit_ordinal))
                .ok_or(RelationPlanError::InvalidConstraint)?;
            degree_bounds
                .entry((
                    RelationChallengeRole::NonNativeAlpha,
                    batch.modulus_reference,
                ))
                .or_default()
                .entry(batch.challenge_ordinal)
                .and_modify(|current| *current = (*current).max(degree_bound))
                .or_insert(degree_bound);
        }

        let mut transcript_coordinates =
            BTreeMap::<(RelationChallengeRole, SuiteModulusReference), (u64, BTreeSet<u16>)>::new();
        for descriptor in self.derived_challenge_catalog(context)? {
            if !matches!(
                descriptor.role,
                RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha
            ) {
                continue;
            }
            let modulus_ordinal = descriptor
                .role_coordinates
                .first()
                .copied()
                .and_then(|coordinate| u16::try_from(coordinate).ok())
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
            let repetition_ordinal = descriptor
                .role_coordinates
                .get(1)
                .copied()
                .and_then(|coordinate| u16::try_from(coordinate).ok())
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
            let modulus_reference = self
                .ordered_non_native_moduli
                .get(usize::from(modulus_ordinal))
                .copied()
                .ok_or(RelationPlanError::MissingModulus)?;
            let sampling = descriptor.resolved_sampling(self, context)?;
            if sampling.coordinate_count != context.non_native_modular_identity_challenge_count {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            let entry = transcript_coordinates
                .entry((descriptor.role, modulus_reference))
                .or_insert_with(|| (sampling.coordinate_modulus, BTreeSet::new()));
            if entry.0 != sampling.coordinate_modulus {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            entry.1.insert(repetition_ordinal);
        }

        if degree_bounds.keys().copied().collect::<BTreeSet<_>>()
            != transcript_coordinates
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        let expected_repetitions =
            (0..context.non_native_modular_identity_challenge_count).collect::<BTreeSet<_>>();

        degree_bounds
            .into_iter()
            .map(
                |((challenge_role, modulus_reference), coordinate_degrees)| {
                    let (coordinate_modulus, observed_repetitions) = transcript_coordinates
                        .remove(&(challenge_role, modulus_reference))
                        .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                    if observed_repetitions != expected_repetitions
                        || coordinate_degrees.keys().copied().collect::<BTreeSet<_>>()
                            != expected_repetitions
                    {
                        return Err(RelationPlanError::InvalidChallengeCatalog);
                    }
                    let ordered_coordinate_bounds = coordinate_degrees
                        .into_iter()
                        .map(|(repetition_ordinal, bad_polynomial_degree_bound)| {
                            RelationApplicationChallengeBadSetCoordinate {
                                repetition_ordinal,
                                bad_polynomial_degree_bound,
                                bad_candidate_count_bound: bad_polynomial_degree_bound
                                    .min(coordinate_modulus),
                            }
                        })
                        .collect();
                    Ok(RelationApplicationChallengeBadSetGroup {
                        challenge_role,
                        modulus_reference,
                        coordinate_modulus,
                        ordered_coordinate_bounds,
                    })
                },
            )
            .collect()
    }

    pub(crate) fn application_round_by_round_transition_catalog(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<RelationApplicationRoundByRoundTransitionCatalog, RelationPlanError> {
        let ordered_non_native_challenge_bad_sets =
            self.application_non_native_challenge_bad_set_catalog(context)?;
        let composition_coefficient_count = u32::try_from(self.ordered_constraints.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let opening_batch_mca_transition_count = u32::try_from(self.ordered_opening_claims.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        if composition_coefficient_count == 0
            || context.deep_point_count == 0
            || opening_batch_mca_transition_count == 0
            || context.fri_fold_count == 0
            || context.unique_query_count == 0
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }

        let identity_degree_bound = self.application_deep_identity_degree_bound(context)?;
        let extension_field_cardinality = BigUint::from(context.base_field_modulus)
            .pow(u32::from(context.challenge_extension_degree));
        let forbidden_candidate_count_bound =
            self.application_deep_forbidden_candidate_count_bound(context)?;
        if forbidden_candidate_count_bound >= extension_field_cardinality {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        let allowed_candidate_count_lower_bound =
            &extension_field_cardinality - &forbidden_candidate_count_bound;
        let root_count_bound =
            BigUint::from(identity_degree_bound).min(allowed_candidate_count_lower_bound.clone());

        Ok(RelationApplicationRoundByRoundTransitionCatalog {
            ordered_non_native_challenge_bad_sets,
            composition_coefficient_count,
            composition_batching_transition_count: 1,
            deep_point_transition_count: context.deep_point_count,
            deep_allowed_set_root_bound: RelationApplicationDeepAllowedSetRootBound {
                identity_degree_bound,
                extension_field_cardinality,
                forbidden_candidate_count_bound,
                allowed_candidate_count_lower_bound,
                root_count_bound,
            },
            opening_batch_mca_transition_count,
            fri_fold_transition_count: context.fri_fold_count,
            query_vector_transition_count: 1,
            query_vector_position_count: context.unique_query_count,
            maximum_candidate_draws_per_output: context
                .maximum_fiat_shamir_candidate_draws_per_output,
        })
    }

    fn validate_integer_lift_application_constraint_topology(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        let actual_program_counts = self.ordered_constraints.iter().fold(
            BTreeMap::<
                (
                    &[RelationExpressionInstruction],
                    &[RelationExpressionInstruction],
                ),
                usize,
            >::new(),
            |mut counts, constraint| {
                *counts
                    .entry((
                        constraint.numerator_postfix_expression.as_slice(),
                        constraint.zeroifier_postfix_expression.as_slice(),
                    ))
                    .or_default() += 1;
                counts
            },
        );
        for batch in &self.ordered_integer_lift_batches {
            let modulus_ordinal = self.non_native_modulus_ordinal(batch.modulus_reference)?;
            for program in batch.constraint_programs(
                modulus_ordinal,
                self.trace_domain_size,
                self.evaluation_domain_size,
                context,
            )? {
                if actual_program_counts.get(&(
                    program.numerator_postfix_expression.as_slice(),
                    program.zeroifier_postfix_expression.as_slice(),
                )) != Some(&1)
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
            }
        }
        Ok(())
    }
}

fn integer_lift_theta_bad_polynomial_degree_bound(
    trace_domain_size: u64,
    batch: &super::RelationIntegerLiftBatchDescriptor,
) -> Result<u64, RelationPlanError> {
    let linear_identity_degree = trace_domain_size
        .checked_sub(1)
        .ok_or(RelationPlanError::InvalidDomain)?;
    let product_identity_degree = trace_domain_size
        .checked_mul(2)
        .and_then(|degree| degree.checked_sub(2))
        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
    let permutation_identity_degree = trace_domain_size
        .checked_mul(2)
        .and_then(|degree| degree.checked_sub(1))
        .ok_or(RelationPlanError::DegreeBoundExceeded)?;

    let mut maximum_degree = linear_identity_degree;
    if batch.ordered_components.iter().any(|component| {
        !component.ordered_convolution_products.is_empty()
            || !component.ordered_full_ring_negacyclic_products.is_empty()
    }) {
        maximum_degree = maximum_degree.max(product_identity_degree);
    }
    if !batch
        .ordered_negacyclic_automorphism_permutations
        .is_empty()
    {
        // Each side is a monic product of 2*N linear factors. Their leading
        // terms cancel, so a false multiset equality has degree at most 2*N-1.
        maximum_degree = maximum_degree.max(permutation_identity_degree);
    }
    Ok(maximum_degree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;

    #[test]
    fn product_space_probability_multiplies_coordinate_bad_sets() {
        let group = RelationApplicationChallengeBadSetGroup {
            challenge_role: RelationChallengeRole::NonNativeTheta,
            modulus_reference: SuiteModulusReference::data(0),
            coordinate_modulus: 17,
            ordered_coordinate_bounds: vec![
                RelationApplicationChallengeBadSetCoordinate {
                    repetition_ordinal: 0,
                    bad_polynomial_degree_bound: 3,
                    bad_candidate_count_bound: 3,
                },
                RelationApplicationChallengeBadSetCoordinate {
                    repetition_ordinal: 1,
                    bad_polynomial_degree_bound: 5,
                    bad_candidate_count_bound: 5,
                },
            ],
        };
        assert_eq!(
            group.product_bad_candidate_count_bound(),
            BigUint::from(15_u8)
        );
        assert_eq!(
            group.product_space_cardinality(),
            BigUint::from(17_u8).pow(2)
        );
    }

    #[test]
    fn zero_candidate_coordinate_makes_the_complete_bad_set_empty() {
        let group = RelationApplicationChallengeBadSetGroup {
            challenge_role: RelationChallengeRole::NonNativeAlpha,
            modulus_reference: SuiteModulusReference::data(0),
            coordinate_modulus: 17,
            ordered_coordinate_bounds: vec![
                RelationApplicationChallengeBadSetCoordinate {
                    repetition_ordinal: 0,
                    bad_polynomial_degree_bound: 0,
                    bad_candidate_count_bound: 0,
                },
                RelationApplicationChallengeBadSetCoordinate {
                    repetition_ordinal: 1,
                    bad_polynomial_degree_bound: 9,
                    bad_candidate_count_bound: 9,
                },
            ],
        };
        assert!(group.product_bad_candidate_count_bound().is_zero());
    }
}
