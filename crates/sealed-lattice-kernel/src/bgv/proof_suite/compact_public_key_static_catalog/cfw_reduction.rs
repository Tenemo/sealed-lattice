//! Exact CFW reduction geometry for the compact public-key relation.
//!
//! The catalog is derived from the production relation dimension. Its checker
//! walks the mask descriptors and recomputes the theorem, message, verifier,
//! and committed-relation counts rather than trusting a producer verdict.

use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_INNER_ENDPOINT_CLAIM_COUNT, COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER,
    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_MATRIX_COUNT,
    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwError, CompactCfwGeometry,
};
use crate::bgv::proof_suite::relation_plan::CompactPublicKeyRelationCatalog;

use super::{
    CompactStaticCatalogError, GOLDILOCKS_BASE_FIELD_MODULUS, MaskGroupRole,
    MaskGroupStaticSpecification, QUINTIC_EXTENSION_DEGREE, checked_add, checked_product,
};

const INNER_MASK_MESSAGE_LENGTH: u64 = COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH as u64;
const OUTER_MASK_MESSAGE_LENGTH: u64 = COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH as u64;
const INNER_MASK_COUNT_PER_ROUND: u64 = COMPACT_CFW_MATRIX_COUNT as u64;
const INNER_ENDPOINT_CONSTRAINT_COUNT: u64 = COMPACT_CFW_INNER_ENDPOINT_CLAIM_COUNT as u64;
const OUTER_REVEALED_EVALUATION_COUNT_PER_ROUND: u64 = 1;
const GLOBAL_COMMITTED_RELATION_CLAIM_COUNT: u64 = 1;
const FINAL_VALUE_COUNT: u64 = COMPACT_CFW_MATRIX_COUNT as u64;
const AUXILIARY_TARGET_COUNT: u64 = 1;
const JOINT_CONSTRAINT_SOUNDNESS_NUMERATOR: u64 = 2;
const LAST_ROUND_EXCLUDED_ELEMENT_COUNT: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum R1csMatrixRole {
    LeftMultiplicand,
    RightMultiplicand,
    Product,
}

impl R1csMatrixRole {
    const ALL: [Self; 3] = [
        Self::LeftMultiplicand,
        Self::RightMultiplicand,
        Self::Product,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InnerMaskDescriptor {
    mask_ordinal: u64,
    sumcheck_round_ordinal: u32,
    matrix_role: R1csMatrixRole,
    coefficient_count: u64,
    evaluation_at_zero_covector: [u64; INNER_MASK_MESSAGE_LENGTH as usize],
    evaluation_at_one_covector: [u64; INNER_MASK_MESSAGE_LENGTH as usize],
    endpoint_targets: [u64; INNER_ENDPOINT_CONSTRAINT_COUNT as usize],
    independent_random_element_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OuterMaskDescriptor {
    mask_ordinal: u64,
    sumcheck_round_ordinal: u32,
    coefficient_count: u64,
    revealed_evaluation_count: u64,
    independent_random_element_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NonOracleMessageLedger {
    auxiliary_target_count: u64,
    sumcheck_polynomial_count: u64,
    sumcheck_polynomial_element_count: u64,
    outer_evaluation_count: u64,
    final_value_count: u64,
    total_extension_element_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifierRandomnessLedger {
    initial_extension_element_count: u32,
    per_round_extension_element_count: u32,
    sumcheck_round_count: u32,
    joint_constraint_extension_element_count: u32,
    last_round_excluded_element_count: u64,
    total_extension_element_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CfwReductionCatalog {
    relation_variable_count: u64,
    relation_variable_logarithm: u32,
    base_field_characteristic: u64,
    extension_degree: u64,
    inner_mask_application_multiplier: u64,
    sumcheck_round_count: u32,
    inner_masks: Vec<InnerMaskDescriptor>,
    outer_masks: Vec<OuterMaskDescriptor>,
    fresh_mask_randomness_element_count: u64,
    generalized_committed_relation_claim_count: u64,
    non_oracle_messages: NonOracleMessageLedger,
    verifier_randomness: VerifierRandomnessLedger,
    honest_verifier_simulator_oracle_count: u64,
    initial_consistency_soundness_numerator: u64,
    per_round_soundness_numerator: u64,
    joint_constraint_soundness_numerator: u64,
}

impl CfwReductionCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let relation_variable_count = relation.padded_witness_element_count();
        if !relation_variable_count.is_power_of_two() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let implementation_geometry = production_cfw_geometry(relation_variable_count)?;
        let relation_variable_logarithm = relation_variable_count.ilog2();
        let independently_derived_sumcheck_round_count = relation_variable_logarithm
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let sumcheck_round_count = u32::try_from(implementation_geometry.sumcheck_round_count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        if sumcheck_round_count != independently_derived_sumcheck_round_count {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let mut inner_masks = Vec::with_capacity(
            usize::try_from(
                u64::from(sumcheck_round_count)
                    .checked_mul(INNER_MASK_COUNT_PER_ROUND)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        );
        for sumcheck_round_ordinal in 0..sumcheck_round_count {
            for matrix_role in R1csMatrixRole::ALL {
                inner_masks.push(InnerMaskDescriptor {
                    mask_ordinal: u64::try_from(inner_masks.len())
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    sumcheck_round_ordinal,
                    matrix_role,
                    coefficient_count: INNER_MASK_MESSAGE_LENGTH,
                    evaluation_at_zero_covector: [1, 0, 0, 0],
                    evaluation_at_one_covector: [1, 1, 1, 1],
                    endpoint_targets: [0, 0],
                    independent_random_element_count: INNER_MASK_MESSAGE_LENGTH
                        .checked_sub(INNER_ENDPOINT_CONSTRAINT_COUNT)
                        .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                });
            }
        }

        let outer_masks = (0..sumcheck_round_count)
            .map(|sumcheck_round_ordinal| OuterMaskDescriptor {
                mask_ordinal: u64::from(sumcheck_round_ordinal),
                sumcheck_round_ordinal,
                coefficient_count: OUTER_MASK_MESSAGE_LENGTH,
                revealed_evaluation_count: OUTER_REVEALED_EVALUATION_COUNT_PER_ROUND,
                independent_random_element_count: OUTER_MASK_MESSAGE_LENGTH,
            })
            .collect::<Vec<_>>();

        let inner_randomness_element_count =
            inner_masks.iter().try_fold(0_u64, |count, descriptor| {
                checked_add(count, descriptor.independent_random_element_count)
            })?;
        let outer_randomness_element_count =
            outer_masks.iter().try_fold(0_u64, |count, descriptor| {
                checked_add(count, descriptor.independent_random_element_count)
            })?;
        let fresh_mask_randomness_element_count = checked_add(
            inner_randomness_element_count,
            outer_randomness_element_count,
        )?;

        let inner_mask_count = u64::try_from(inner_masks.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let outer_mask_count = u64::try_from(outer_masks.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let generalized_committed_relation_claim_count = [
            GLOBAL_COMMITTED_RELATION_CLAIM_COUNT,
            checked_product(&[inner_mask_count, INNER_ENDPOINT_CONSTRAINT_COUNT])?,
            checked_product(&[outer_mask_count, OUTER_REVEALED_EVALUATION_COUNT_PER_ROUND])?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;

        let sumcheck_polynomial_count = u64::from(sumcheck_round_count);
        let sumcheck_polynomial_element_count =
            checked_product(&[sumcheck_polynomial_count, OUTER_MASK_MESSAGE_LENGTH])?;
        let outer_evaluation_count =
            checked_product(&[outer_mask_count, OUTER_REVEALED_EVALUATION_COUNT_PER_ROUND])?;
        let total_extension_element_count = [
            AUXILIARY_TARGET_COUNT,
            sumcheck_polynomial_element_count,
            outer_evaluation_count,
            FINAL_VALUE_COUNT,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let non_oracle_messages = NonOracleMessageLedger {
            auxiliary_target_count: AUXILIARY_TARGET_COUNT,
            sumcheck_polynomial_count,
            sumcheck_polynomial_element_count,
            outer_evaluation_count,
            final_value_count: FINAL_VALUE_COUNT,
            total_extension_element_count,
        };

        let initial_extension_element_count = sumcheck_round_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let per_round_extension_element_count = 1;
        let joint_constraint_extension_element_count = 1;
        let verifier_randomness_total = [
            u64::from(initial_extension_element_count),
            checked_product(&[
                u64::from(sumcheck_round_count),
                u64::from(per_round_extension_element_count),
            ])?,
            u64::from(joint_constraint_extension_element_count),
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let verifier_randomness = VerifierRandomnessLedger {
            initial_extension_element_count,
            per_round_extension_element_count,
            sumcheck_round_count,
            joint_constraint_extension_element_count,
            last_round_excluded_element_count: LAST_ROUND_EXCLUDED_ELEMENT_COUNT,
            total_extension_element_count: verifier_randomness_total,
        };

        let catalog = Self {
            relation_variable_count,
            relation_variable_logarithm,
            base_field_characteristic: GOLDILOCKS_BASE_FIELD_MODULUS,
            extension_degree: QUINTIC_EXTENSION_DEGREE,
            inner_mask_application_multiplier: COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER,
            sumcheck_round_count,
            inner_masks,
            outer_masks,
            fresh_mask_randomness_element_count,
            generalized_committed_relation_claim_count,
            non_oracle_messages,
            verifier_randomness,
            honest_verifier_simulator_oracle_count: checked_add(
                checked_product(&[4, u64::from(relation_variable_logarithm)])?,
                5,
            )?,
            initial_consistency_soundness_numerator: OUTER_MASK_MESSAGE_LENGTH
                .checked_add(1)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            per_round_soundness_numerator: OUTER_MASK_MESSAGE_LENGTH,
            joint_constraint_soundness_numerator: JOINT_CONSTRAINT_SOUNDNESS_NUMERATOR,
        };
        catalog.check(relation)?;
        Ok(catalog)
    }

    pub(super) fn check(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let expected_relation_variable_count = relation.padded_witness_element_count();
        if !expected_relation_variable_count.is_power_of_two() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let expected_relation_variable_logarithm = expected_relation_variable_count.ilog2();
        let expected_sumcheck_round_count = expected_relation_variable_logarithm
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let implementation_geometry = production_cfw_geometry(expected_relation_variable_count)?;
        let expected_inner_mask_count = checked_product(&[
            u64::from(expected_sumcheck_round_count),
            INNER_MASK_COUNT_PER_ROUND,
        ])?;
        let expected_outer_mask_count = u64::from(expected_sumcheck_round_count);
        let expected_implementation_claim_count = [
            GLOBAL_COMMITTED_RELATION_CLAIM_COUNT,
            checked_product(&[expected_inner_mask_count, INNER_ENDPOINT_CONSTRAINT_COUNT])?,
            expected_outer_mask_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;

        if self.relation_variable_count != expected_relation_variable_count
            || self.relation_variable_logarithm != expected_relation_variable_logarithm
            || self.base_field_characteristic != GOLDILOCKS_BASE_FIELD_MODULUS
            || self.base_field_characteristic % 2 != 1
            || self.extension_degree != QUINTIC_EXTENSION_DEGREE
            || self.inner_mask_application_multiplier
                != COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER
            || self.inner_mask_application_multiplier == 0
            || self.sumcheck_round_count != expected_sumcheck_round_count
            || implementation_geometry.witness_length()
                != usize::try_from(expected_relation_variable_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || implementation_geometry.r1cs_row_count()
                != usize::try_from(
                    expected_relation_variable_count
                        .checked_mul(2)
                        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                )
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || implementation_geometry.sumcheck_round_count()
                != usize::try_from(expected_sumcheck_round_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || implementation_geometry.inner_mask_count()
                != usize::try_from(expected_inner_mask_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || implementation_geometry.outer_mask_count()
                != usize::try_from(expected_outer_mask_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || implementation_geometry.generalized_committed_relation_claim_count()
                != usize::try_from(expected_implementation_claim_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || u64::try_from(self.inner_masks.len()).ok() != Some(expected_inner_mask_count)
            || u64::try_from(self.outer_masks.len()).ok() != Some(expected_outer_mask_count)
            || INNER_MASK_MESSAGE_LENGTH < 4
            || OUTER_MASK_MESSAGE_LENGTH < 2 * INNER_MASK_MESSAGE_LENGTH
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let mut interpreted_inner_randomness_element_count = 0_u64;
        for (mask_ordinal, descriptor) in self.inner_masks.iter().enumerate() {
            let mask_ordinal = u64::try_from(mask_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            let expected_round_ordinal = u32::try_from(
                mask_ordinal
                    .checked_div(INNER_MASK_COUNT_PER_ROUND)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
            )
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            let expected_matrix_role =
                R1csMatrixRole::ALL[usize::try_from(mask_ordinal % INNER_MASK_COUNT_PER_ROUND)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?];
            let interpreted_independent_dimension = descriptor
                .coefficient_count
                .checked_sub(INNER_ENDPOINT_CONSTRAINT_COUNT)
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
            if descriptor.mask_ordinal != mask_ordinal
                || descriptor.sumcheck_round_ordinal != expected_round_ordinal
                || descriptor.matrix_role != expected_matrix_role
                || descriptor.coefficient_count != INNER_MASK_MESSAGE_LENGTH
                || descriptor.evaluation_at_zero_covector != [1, 0, 0, 0]
                || descriptor.evaluation_at_one_covector != [1, 1, 1, 1]
                || descriptor.endpoint_targets != [0, 0]
                || descriptor.independent_random_element_count != interpreted_independent_dimension
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            interpreted_inner_randomness_element_count = checked_add(
                interpreted_inner_randomness_element_count,
                interpreted_independent_dimension,
            )?;
        }

        let mut interpreted_outer_randomness_element_count = 0_u64;
        for (mask_ordinal, descriptor) in self.outer_masks.iter().enumerate() {
            let mask_ordinal = u64::try_from(mask_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            if descriptor.mask_ordinal != mask_ordinal
                || descriptor.sumcheck_round_ordinal
                    != u32::try_from(mask_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
                || descriptor.coefficient_count != OUTER_MASK_MESSAGE_LENGTH
                || descriptor.revealed_evaluation_count != OUTER_REVEALED_EVALUATION_COUNT_PER_ROUND
                || descriptor.independent_random_element_count != descriptor.coefficient_count
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            interpreted_outer_randomness_element_count = checked_add(
                interpreted_outer_randomness_element_count,
                descriptor.independent_random_element_count,
            )?;
        }

        let interpreted_fresh_randomness_element_count = checked_add(
            interpreted_inner_randomness_element_count,
            interpreted_outer_randomness_element_count,
        )?;
        let interpreted_generalized_claim_count = [
            GLOBAL_COMMITTED_RELATION_CLAIM_COUNT,
            checked_product(&[expected_inner_mask_count, INNER_ENDPOINT_CONSTRAINT_COUNT])?,
            checked_product(&[
                expected_outer_mask_count,
                OUTER_REVEALED_EVALUATION_COUNT_PER_ROUND,
            ])?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;

        let expected_sumcheck_polynomial_element_count =
            checked_product(&[expected_outer_mask_count, OUTER_MASK_MESSAGE_LENGTH])?;
        let expected_non_oracle_total = [
            AUXILIARY_TARGET_COUNT,
            expected_sumcheck_polynomial_element_count,
            expected_outer_mask_count,
            FINAL_VALUE_COUNT,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let expected_initial_verifier_randomness = expected_sumcheck_round_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let expected_verifier_randomness_total = checked_add(
            u64::from(expected_initial_verifier_randomness),
            checked_add(u64::from(expected_sumcheck_round_count), 1)?,
        )?;

        if self.fresh_mask_randomness_element_count != interpreted_fresh_randomness_element_count
            || self.generalized_committed_relation_claim_count
                != interpreted_generalized_claim_count
            || self.non_oracle_messages.auxiliary_target_count != AUXILIARY_TARGET_COUNT
            || self.non_oracle_messages.sumcheck_polynomial_count != expected_outer_mask_count
            || self.non_oracle_messages.sumcheck_polynomial_element_count
                != expected_sumcheck_polynomial_element_count
            || self.non_oracle_messages.outer_evaluation_count != expected_outer_mask_count
            || self.non_oracle_messages.final_value_count != FINAL_VALUE_COUNT
            || self.non_oracle_messages.total_extension_element_count != expected_non_oracle_total
            || self.verifier_randomness.initial_extension_element_count
                != expected_initial_verifier_randomness
            || self.verifier_randomness.per_round_extension_element_count != 1
            || self.verifier_randomness.sumcheck_round_count != expected_sumcheck_round_count
            || self
                .verifier_randomness
                .joint_constraint_extension_element_count
                != 1
            || self.verifier_randomness.last_round_excluded_element_count
                != LAST_ROUND_EXCLUDED_ELEMENT_COUNT
            || self.verifier_randomness.total_extension_element_count
                != expected_verifier_randomness_total
            || self.honest_verifier_simulator_oracle_count
                != checked_add(
                    checked_product(&[4, u64::from(expected_relation_variable_logarithm)])?,
                    5,
                )?
            || self.initial_consistency_soundness_numerator != OUTER_MASK_MESSAGE_LENGTH + 1
            || self.per_round_soundness_numerator != OUTER_MASK_MESSAGE_LENGTH
            || self.joint_constraint_soundness_numerator != JOINT_CONSTRAINT_SOUNDNESS_NUMERATOR
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    pub(super) fn mask_group_specifications(&self) -> [MaskGroupStaticSpecification; 2] {
        [
            MaskGroupStaticSpecification {
                role: MaskGroupRole::CfwInner,
                width: self.inner_mask_count(),
                message_length: INNER_MASK_MESSAGE_LENGTH,
                encoding_randomness_length:
                    super::MaskEncodingRandomnessLength::LocalMaskQueryCount,
                committed_encoding_source: super::MaskCommittedEncodingSource::OwnedByThisEpoch,
            },
            MaskGroupStaticSpecification {
                role: MaskGroupRole::CfwOuter,
                width: self.outer_mask_count(),
                message_length: OUTER_MASK_MESSAGE_LENGTH,
                encoding_randomness_length:
                    super::MaskEncodingRandomnessLength::LocalMaskQueryCount,
                committed_encoding_source: super::MaskCommittedEncodingSource::OwnedByThisEpoch,
            },
        ]
    }

    pub(super) fn sumcheck_round_count(&self) -> u32 {
        self.sumcheck_round_count
    }

    pub(super) fn inner_mask_count(&self) -> u64 {
        self.inner_masks.len() as u64
    }

    pub(super) fn outer_mask_count(&self) -> u64 {
        self.outer_masks.len() as u64
    }

    pub(super) const fn inner_mask_message_length(&self) -> u64 {
        INNER_MASK_MESSAGE_LENGTH
    }

    pub(super) const fn outer_mask_message_length(&self) -> u64 {
        OUTER_MASK_MESSAGE_LENGTH
    }

    pub(super) fn fresh_mask_randomness_element_count(&self) -> u64 {
        self.fresh_mask_randomness_element_count
    }

    pub(super) fn generalized_committed_relation_claim_count(&self) -> u64 {
        self.generalized_committed_relation_claim_count
    }

    pub(super) fn auxiliary_target_count(&self) -> u64 {
        self.non_oracle_messages.auxiliary_target_count
    }

    pub(super) fn sumcheck_polynomial_element_count_per_round(&self) -> u64 {
        OUTER_MASK_MESSAGE_LENGTH
    }

    pub(super) fn outer_evaluation_count(&self) -> u64 {
        self.non_oracle_messages.outer_evaluation_count
    }

    pub(super) fn final_value_count(&self) -> u64 {
        self.non_oracle_messages.final_value_count
    }

    pub(super) fn non_oracle_extension_element_count(&self) -> u64 {
        self.non_oracle_messages.total_extension_element_count
    }

    pub(super) fn initial_randomness_element_count(&self) -> u32 {
        self.verifier_randomness.initial_extension_element_count
    }

    pub(super) fn per_round_randomness_element_count(&self) -> u32 {
        self.verifier_randomness.per_round_extension_element_count
    }

    pub(super) fn joint_constraint_randomness_element_count(&self) -> u32 {
        self.verifier_randomness
            .joint_constraint_extension_element_count
    }

    pub(super) fn last_round_excluded_element_count(&self) -> u64 {
        self.verifier_randomness.last_round_excluded_element_count
    }

    pub(super) fn initial_consistency_soundness_numerator(&self) -> u64 {
        self.initial_consistency_soundness_numerator
    }

    pub(super) fn per_round_soundness_numerator(&self) -> u64 {
        self.per_round_soundness_numerator
    }

    pub(super) fn joint_constraint_soundness_numerator(&self) -> u64 {
        self.joint_constraint_soundness_numerator
    }
}

fn production_cfw_geometry(
    relation_variable_count: u64,
) -> Result<CompactCfwGeometry, CompactStaticCatalogError> {
    let witness_length = usize::try_from(relation_variable_count)
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    CompactCfwGeometry::derive(witness_length).map_err(|error| match error {
        CompactCfwError::CountOverflow => CompactStaticCatalogError::ArithmeticOverflow,
        _ => CompactStaticCatalogError::InvalidGeometry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog;

    fn selected_catalog() -> CfwReductionCatalog {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        CfwReductionCatalog::derive(&relation).expect("complete CFW reduction catalog")
    }

    #[test]
    fn selected_relation_derives_the_complete_cfw_reduction() {
        let catalog = selected_catalog();

        assert_eq!(catalog.relation_variable_count, 4_194_304);
        assert_eq!(catalog.relation_variable_logarithm, 22);
        assert_eq!(catalog.sumcheck_round_count, 23);
        assert_eq!(catalog.inner_mask_count(), 69);
        assert_eq!(catalog.outer_mask_count(), 23);
        assert_eq!(catalog.fresh_mask_randomness_element_count(), 322);
        assert_eq!(catalog.generalized_committed_relation_claim_count(), 162);
        assert_eq!(catalog.non_oracle_extension_element_count(), 211);
        assert_eq!(
            catalog.verifier_randomness.total_extension_element_count,
            48
        );
        assert_eq!(catalog.honest_verifier_simulator_oracle_count, 93);
        assert_eq!(catalog.base_field_characteristic % 2, 1);
        assert_eq!(catalog.extension_degree, 5);
    }

    #[test]
    fn inner_masks_bind_both_endpoints_for_every_matrix_and_round() {
        let catalog = selected_catalog();
        for (round_ordinal, round_masks) in catalog.inner_masks.chunks_exact(3).enumerate() {
            assert_eq!(
                round_masks
                    .iter()
                    .map(|mask| mask.matrix_role)
                    .collect::<Vec<_>>(),
                R1csMatrixRole::ALL
            );
            assert!(round_masks.iter().all(|mask| {
                mask.sumcheck_round_ordinal == round_ordinal as u32
                    && mask.evaluation_at_zero_covector == [1, 0, 0, 0]
                    && mask.evaluation_at_one_covector == [1, 1, 1, 1]
                    && mask.endpoint_targets == [0, 0]
                    && mask.independent_random_element_count == 2
            }));
        }
    }

    #[test]
    fn independent_checker_rejects_changed_mask_and_message_geometry() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let catalog =
            CfwReductionCatalog::derive(&relation).expect("complete CFW reduction catalog");

        let mut changed_endpoint = catalog.clone();
        changed_endpoint.inner_masks[7].evaluation_at_one_covector[3] = 0;
        assert_eq!(
            changed_endpoint.check(&relation),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut changed_non_oracle_count = catalog.clone();
        changed_non_oracle_count
            .non_oracle_messages
            .total_extension_element_count += 1;
        assert_eq!(
            changed_non_oracle_count.check(&relation),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut changed_characteristic = catalog.clone();
        changed_characteristic.base_field_characteristic = 2;
        assert_eq!(
            changed_characteristic.check(&relation),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut changed_inner_mask_multiplier = catalog.clone();
        changed_inner_mask_multiplier.inner_mask_application_multiplier = 1;
        assert_eq!(
            changed_inner_mask_multiplier.check(&relation),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }
}
