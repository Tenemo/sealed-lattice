//! Bounded query-sampling lifecycle for the compact public-key packing ledger.
//!
//! The production common-proof transcript allocates a fixed 64-bit candidate
//! slot array for every distinct-query vector. Each requested index receives
//! at most the suite-owned candidate ceiling; collisions consume slots and an
//! exhausted slot aborts with `CommonChallengeDrawsExhausted`. This module
//! independently derives that algorithm's exact ideal-XOF exhaustion
//! probability from each WHIR and mask domain. The current compact chronology
//! owns one attempt only. A checkpoint resume continues that exact attempt;
//! exhaustion does not silently resample challenges, reuse roots under a new
//! challenge, or claim an unimplemented independent retry.

use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::{
    CompactStaticCatalogError, MaskGroupRole, PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    WhirStaticLedger, checked_add, checked_product,
};

const QUERY_CANDIDATE_BYTE_LENGTH: u64 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExactProbability {
    numerator: BigUint,
    denominator: BigUint,
}

impl ExactProbability {
    pub(super) fn new(
        numerator: BigUint,
        denominator: BigUint,
    ) -> Result<Self, CompactStaticCatalogError> {
        if denominator.is_zero() || numerator > denominator {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let greatest_common_divisor =
            greatest_common_divisor(numerator.clone(), denominator.clone());
        Ok(Self {
            numerator: numerator / &greatest_common_divisor,
            denominator: denominator / greatest_common_divisor,
        })
    }

    pub(super) fn zero() -> Self {
        Self {
            numerator: BigUint::zero(),
            denominator: BigUint::one(),
        }
    }

    pub(super) fn add(&self, right: &Self) -> Result<Self, CompactStaticCatalogError> {
        let common_divisor =
            greatest_common_divisor(self.denominator.clone(), right.denominator.clone());
        let left_scale = &right.denominator / &common_divisor;
        let right_scale = &self.denominator / &common_divisor;
        Self::new(
            &self.numerator * &left_scale + &right.numerator * &right_scale,
            &self.denominator * left_scale,
        )
    }

    pub(super) fn scale(&self, multiplier: &BigUint) -> Result<Self, CompactStaticCatalogError> {
        Self::new(&self.numerator * multiplier, self.denominator.clone())
    }

    pub(super) fn power(&self, exponent: u32) -> Result<Self, CompactStaticCatalogError> {
        Self::new(self.numerator.pow(exponent), self.denominator.pow(exponent))
    }

    pub(super) fn is_at_most_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.numerator << exponent) <= self.denominator
    }

    pub(super) fn is_greater_than(&self, right: &Self) -> bool {
        &self.numerator * &right.denominator > &right.numerator * &self.denominator
    }

    pub(super) fn ceiling_units_at_binary_precision(
        &self,
        precision: usize,
    ) -> Result<BigUint, CompactStaticCatalogError> {
        let scaled_numerator = &self.numerator << precision;
        let quotient = &scaled_numerator / &self.denominator;
        if &quotient * &self.denominator == scaled_numerator {
            Ok(quotient)
        } else {
            Ok(quotient + BigUint::one())
        }
    }
}

fn greatest_common_divisor(mut left: BigUint, mut right: BigUint) -> BigUint {
    while !right.is_zero() {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuerySamplingGroupRole {
    SourceOracle {
        batch_ordinal: u8,
    },
    Mask {
        group_ordinal: u8,
        mask_role: MaskGroupRole,
    },
}

/// Exact symbolic probability
///
/// `1 - product_{accepted=0}^{query_count-1}
///      (1 - (accepted / domain_cardinality)^candidate_draw_ceiling)`.
///
/// Keeping the product factored avoids expanding a multi-million-bit rational
/// merely to retain an exact expression. Every factor is fixed by these three
/// integers and the ideal-XOF independence hypothesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactDistinctQueryExhaustionFormula {
    domain_cardinality: u64,
    query_count: u64,
    candidate_draw_ceiling: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QuerySamplingGroupLedger {
    role: QuerySamplingGroupRole,
    domain_cardinality: u64,
    query_count: u64,
    maximum_candidate_draws_per_query: u32,
    fixed_candidate_slot_count: u64,
    fixed_candidate_byte_length: u64,
    exact_exhaustion_formula: ExactDistinctQueryExhaustionFormula,
    union_bound_exhaustion_probability: ExactProbability,
}

impl QuerySamplingGroupLedger {
    fn derive(
        role: QuerySamplingGroupRole,
        domain_cardinality: u64,
        query_count: u64,
    ) -> Result<Self, CompactStaticCatalogError> {
        if domain_cardinality == 0
            || !domain_cardinality.is_power_of_two()
            || query_count == 0
            || query_count >= domain_cardinality
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let maximum_candidate_draws_per_query =
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;
        if maximum_candidate_draws_per_query == 0 {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }
        let fixed_candidate_slot_count =
            checked_product(&[query_count, u64::from(maximum_candidate_draws_per_query)])?;
        let fixed_candidate_byte_length =
            checked_product(&[fixed_candidate_slot_count, QUERY_CANDIDATE_BYTE_LENGTH])?;

        let domain = BigUint::from(domain_cardinality);
        let slot_probability_denominator = domain.pow(maximum_candidate_draws_per_query);
        let mut slot_probability_numerator_sum = BigUint::zero();
        for accepted_query_count in 0..query_count {
            slot_probability_numerator_sum +=
                BigUint::from(accepted_query_count).pow(maximum_candidate_draws_per_query);
        }
        let union_bound_exhaustion_probability =
            ExactProbability::new(slot_probability_numerator_sum, slot_probability_denominator)?;

        Ok(Self {
            role,
            domain_cardinality,
            query_count,
            maximum_candidate_draws_per_query,
            fixed_candidate_slot_count,
            fixed_candidate_byte_length,
            exact_exhaustion_formula: ExactDistinctQueryExhaustionFormula {
                domain_cardinality,
                query_count,
                candidate_draw_ceiling: maximum_candidate_draws_per_query,
            },
            union_bound_exhaustion_probability,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WhirQuerySamplingLifecycle {
    groups: Vec<QuerySamplingGroupLedger>,
    fixed_candidate_slot_count: u64,
    fixed_candidate_byte_length: u64,
    union_bound_exhaustion_probability: ExactProbability,
}

impl WhirQuerySamplingLifecycle {
    fn derive(whir: &WhirStaticLedger) -> Result<Self, CompactStaticCatalogError> {
        let mut groups = Vec::new();
        for batch_ordinal in 0..whir.query_counts.len() {
            groups.push(QuerySamplingGroupLedger::derive(
                QuerySamplingGroupRole::SourceOracle {
                    batch_ordinal: u8::try_from(batch_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                },
                whir.oracle_heights[batch_ordinal],
                whir.query_counts[batch_ordinal],
            )?);
        }
        for (group_ordinal, group) in whir.mask_groups_in_commitment_order().enumerate() {
            groups.push(QuerySamplingGroupLedger::derive(
                QuerySamplingGroupRole::Mask {
                    group_ordinal: u8::try_from(group_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    mask_role: group.role,
                },
                group.domain_size,
                whir.mask_query_count,
            )?);
        }

        let fixed_candidate_slot_count = groups.iter().try_fold(0_u64, |total, group| {
            checked_add(total, group.fixed_candidate_slot_count)
        })?;
        let fixed_candidate_byte_length = groups.iter().try_fold(0_u64, |total, group| {
            checked_add(total, group.fixed_candidate_byte_length)
        })?;
        let mut union_bound_exhaustion_probability = ExactProbability::zero();
        for group in &groups {
            union_bound_exhaustion_probability = union_bound_exhaustion_probability
                .add(&group.union_bound_exhaustion_probability)?;
        }

        Ok(Self {
            groups,
            fixed_candidate_slot_count,
            fixed_candidate_byte_length,
            union_bound_exhaustion_probability,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingQuerySamplingLifecycle {
    pre_challenge: WhirQuerySamplingLifecycle,
    main: WhirQuerySamplingLifecycle,
    pub(super) query_group_count: u64,
    pub(super) fixed_candidate_slot_count: u64,
    pub(super) fixed_candidate_byte_length: u64,
    pub(super) union_bound_exhaustion_probability_per_attempt: ExactProbability,
    pub(super) maximum_attempt_count: u32,
}

impl PackingQuerySamplingLifecycle {
    pub(super) fn derive(
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
    ) -> Result<Self, CompactStaticCatalogError> {
        let pre_challenge = WhirQuerySamplingLifecycle::derive(pre_challenge_whir)?;
        let main = WhirQuerySamplingLifecycle::derive(main_whir)?;
        let query_group_count = u64::try_from(pre_challenge.groups.len())
            .ok()
            .and_then(|count| {
                u64::try_from(main.groups.len())
                    .ok()
                    .and_then(|main_count| count.checked_add(main_count))
            })
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let fixed_candidate_slot_count = checked_add(
            pre_challenge.fixed_candidate_slot_count,
            main.fixed_candidate_slot_count,
        )?;
        let fixed_candidate_byte_length = checked_add(
            pre_challenge.fixed_candidate_byte_length,
            main.fixed_candidate_byte_length,
        )?;
        let union_bound_exhaustion_probability_per_attempt = pre_challenge
            .union_bound_exhaustion_probability
            .add(&main.union_bound_exhaustion_probability)?;
        let maximum_attempt_count = 1;

        Ok(Self {
            pre_challenge,
            main,
            query_group_count,
            fixed_candidate_slot_count,
            fixed_candidate_byte_length,
            union_bound_exhaustion_probability_per_attempt,
            maximum_attempt_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    #[test]
    fn every_factor_has_twenty_four_fixed_output_query_groups() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_candidate_slot_counts = [1_220_608, 1_236_736, 1_208_320, 1_240_320];
        for (factor, expected_candidate_slot_count) in catalog
            .factor_catalogs
            .iter()
            .zip(expected_candidate_slot_counts)
        {
            let lifecycle = &factor.query_sampling_lifecycle;
            assert_eq!(lifecycle.query_group_count, 24);
            assert_eq!(
                lifecycle.fixed_candidate_slot_count,
                expected_candidate_slot_count
            );
            assert_eq!(
                lifecycle.fixed_candidate_byte_length,
                expected_candidate_slot_count * QUERY_CANDIDATE_BYTE_LENGTH
            );
            assert_eq!(lifecycle.maximum_attempt_count, 1);
        }
    }

    #[test]
    fn query_sampling_groups_follow_source_then_mask_commitment_order() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_source_roles = (0_u8..4)
            .map(|batch_ordinal| QuerySamplingGroupRole::SourceOracle { batch_ordinal })
            .collect::<Vec<_>>();
        let expected_pre_challenge_mask_roles = vec![
            MaskGroupRole::WhirSumcheck { batch_ordinal: 0 },
            MaskGroupRole::WhirCodeSwitch { round_ordinal: 0 },
            MaskGroupRole::WhirSumcheck { batch_ordinal: 1 },
            MaskGroupRole::WhirCodeSwitch { round_ordinal: 1 },
            MaskGroupRole::WhirSumcheck { batch_ordinal: 2 },
            MaskGroupRole::WhirCodeSwitch { round_ordinal: 2 },
            MaskGroupRole::WhirSumcheck { batch_ordinal: 3 },
        ];
        let expected_main_mask_roles = [MaskGroupRole::CfwInner, MaskGroupRole::CfwOuter]
            .into_iter()
            .chain(expected_pre_challenge_mask_roles.iter().copied())
            .collect::<Vec<_>>();

        for factor in &catalog.factor_catalogs {
            assert_eq!(
                factor.query_sampling_lifecycle.pre_challenge.groups[..4]
                    .iter()
                    .map(|group| group.role)
                    .collect::<Vec<_>>(),
                expected_source_roles
            );
            assert_eq!(
                factor.query_sampling_lifecycle.main.groups[..4]
                    .iter()
                    .map(|group| group.role)
                    .collect::<Vec<_>>(),
                expected_source_roles
            );
            assert_eq!(
                factor.query_sampling_lifecycle.pre_challenge.groups[4..]
                    .iter()
                    .enumerate()
                    .map(|(group_ordinal, group)| {
                        let QuerySamplingGroupRole::Mask {
                            group_ordinal: encoded_group_ordinal,
                            mask_role,
                        } = group.role
                        else {
                            panic!("pre-challenge mask query group role");
                        };
                        assert_eq!(usize::from(encoded_group_ordinal), group_ordinal);
                        mask_role
                    })
                    .collect::<Vec<_>>(),
                expected_pre_challenge_mask_roles
            );
            assert_eq!(
                factor.query_sampling_lifecycle.main.groups[4..]
                    .iter()
                    .enumerate()
                    .map(|(group_ordinal, group)| {
                        let QuerySamplingGroupRole::Mask {
                            group_ordinal: encoded_group_ordinal,
                            mask_role,
                        } = group.role
                        else {
                            panic!("main mask query group role");
                        };
                        assert_eq!(usize::from(encoded_group_ordinal), group_ordinal);
                        mask_role
                    })
                    .collect::<Vec<_>>(),
                expected_main_mask_roles
            );
        }
    }

    #[test]
    fn factor_eight_one_attempt_exhaustion_is_between_eighty_three_and_eighty_four_bits() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let factor_eight = &catalog.factor_catalogs[3].query_sampling_lifecycle;

        assert!(
            factor_eight
                .union_bound_exhaustion_probability_per_attempt
                .is_at_most_inverse_power_of_two(83)
        );
        assert!(
            !factor_eight
                .union_bound_exhaustion_probability_per_attempt
                .is_at_most_inverse_power_of_two(84)
        );
    }
}
