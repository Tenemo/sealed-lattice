use super::{
    RelationPlanCheckContext, RelationPlanChecker, RelationPlanError, SuiteModulusReference,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrusteeEvaluationKeyDecompositionBlock {
    pub(crate) data_modulus_indices: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrusteeEvaluationKeyPlanInput {
    pub(crate) schedule_position: u32,
    pub(crate) ring_degree: u64,
    pub(crate) trace_domain_size: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) data_moduli: Vec<u64>,
    pub(crate) special_moduli: Vec<u64>,
    pub(crate) plaintext_modulus: u64,
    pub(crate) decomposition_blocks: Vec<TrusteeEvaluationKeyDecompositionBlock>,
    pub(crate) commitment_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_module_rank: u16,
    pub(crate) trace_mask_degree_bound_exclusive: u64,
    pub(crate) quotient_mask_degree_bound_exclusive: u64,
    pub(crate) first_mask_purpose: u16,
}

impl TrusteeEvaluationKeyPlanInput {
    pub(super) fn validate(
        &self,
        check_context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        RelationPlanChecker::new(check_context).check_context()?;

        if self.ring_degree == 0
            || !self.ring_degree.is_power_of_two()
            || self.ring_degree != self.trace_domain_size
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.opening_degree_bound_exclusive <= 1
            || self.data_moduli.is_empty()
            || self.special_moduli.is_empty()
            || self.plaintext_modulus < 3
            || self.decomposition_blocks.is_empty()
            || self.commitment_data_modulus_indices.is_empty()
            || self.commitment_module_rank == 0
            || self.trace_mask_degree_bound_exclusive == 0
            || self.trace_mask_degree_bound_exclusive > self.trace_domain_size
            || self.quotient_mask_degree_bound_exclusive == 0
            || self.first_mask_purpose == 0
            || self.first_mask_purpose >= 0xff00
        {
            return Err(RelationPlanError::InvalidDomain);
        }

        let next_degree_domain = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .ok_or(RelationPlanError::CountOverflow)?;
        let expected_evaluation_domain = next_degree_domain
            .checked_mul(u64::from(check_context.evaluation_blowup_factor))
            .ok_or(RelationPlanError::CountOverflow)?;
        if expected_evaluation_domain != self.evaluation_domain_size
            || !(check_context.base_field_modulus - 1)
                .is_multiple_of(self.evaluation_domain_size)
            || super::modular_power(
                check_context.evaluation_domain_generator,
                self.evaluation_domain_size,
                check_context.base_field_modulus,
            ) != 1
            || super::modular_power(
                check_context.evaluation_domain_generator,
                self.evaluation_domain_size / 2,
                check_context.base_field_modulus,
            ) == 1
            || super::modular_power(
                check_context.evaluation_coset_offset,
                self.trace_domain_size,
                check_context.base_field_modulus,
            ) == 1
        {
            return Err(RelationPlanError::InvalidDomain);
        }

        validate_modulus_catalog(
            &self.data_moduli,
            SuiteModulusReference::data,
            check_context,
        )?;
        validate_modulus_catalog(
            &self.special_moduli,
            SuiteModulusReference::special,
            check_context,
        )?;
        if check_context.resolved_modulus(SuiteModulusReference::plaintext())?
            != self.plaintext_modulus
        {
            return Err(RelationPlanError::InvalidModulus);
        }

        let expected_data_modulus_indices = (0..self.data_moduli.len())
            .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
            .collect::<Result<Vec<_>, _>>()?;
        let flattened_block_indices = self
            .decomposition_blocks
            .iter()
            .flat_map(|block| block.data_modulus_indices.iter().copied())
            .collect::<Vec<_>>();
        if self
            .decomposition_blocks
            .iter()
            .any(|block| block.data_modulus_indices.is_empty())
            || flattened_block_indices != expected_data_modulus_indices
        {
            return Err(RelationPlanError::NonCanonicalOrder);
        }

        if !super::strictly_sorted_unique(&self.commitment_data_modulus_indices)
            || self
                .commitment_data_modulus_indices
                .iter()
                .any(|index| usize::from(*index) >= self.data_moduli.len())
        {
            return Err(RelationPlanError::NonCanonicalOrder);
        }

        Ok(())
    }
}

fn validate_modulus_catalog(
    moduli: &[u64],
    reference: impl Fn(u16) -> SuiteModulusReference,
    check_context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    for (index, expected_modulus) in moduli.iter().copied().enumerate() {
        let index = u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow)?;
        let modulus_reference = reference(index);
        if check_context.resolved_modulus(modulus_reference)? != expected_modulus {
            return Err(RelationPlanError::InvalidModulus);
        }
    }
    Ok(())
}

pub(crate) fn compile_trustee_evaluation_key_relation_plan(
    input: &TrusteeEvaluationKeyPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<super::CompiledRelationPlan, RelationPlanError> {
    input.validate(check_context)?;

    // The exact relation is deliberately fail-closed until its canonical
    // lowering contains all three two-round negacyclic equations over every
    // active data and special limb, the shared cross-limb witnesses, radix-3
    // reduction quotients and carries, and the common-opening lattice-anchor
    // equations. A coefficient-local product or independently opened
    // commitment prime is not an admissible substitute.
    Err(RelationPlanError::MissingExactNegacyclicLowering)
}
