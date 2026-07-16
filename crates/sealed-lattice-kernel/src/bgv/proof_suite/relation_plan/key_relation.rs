use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use crate::bgv::setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES};

use super::*;

const TRIT_RADIX: u64 = 3;
pub(super) const MATERIAL_DIGIT_RADIX: u64 = 129_140_163;
pub(super) const MATERIAL_DIGIT_TRIT_COUNT: usize = 17;
const MODULAR_QUOTIENT_BIT_COUNT: usize = 17;
pub(super) const TRUSTEE_QUOTIENT_LOW_TRIT_COUNT: usize = 9;
pub(super) const TRUSTEE_QUOTIENT_HIGH_RADIX: u16 = 19_683;
pub(super) const TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE: u64 = 49_207;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SameSecretRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) material_column_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) sharing_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_module_rank: u16,
    pub(crate) first_mask_purpose: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicKeyShareRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) data_modulus_indices: Vec<u16>,
    pub(crate) commitment_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_module_rank: u16,
    pub(crate) plaintext_modulus: u64,
    pub(crate) first_mask_purpose: u16,
}

#[derive(Clone, Debug)]
pub(super) struct KeyRelationGeometry {
    ring_degree: u64,
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    material_column_degree_bound_exclusive: Option<u64>,
    public_polynomial_column_degree_bound_exclusive: u64,
    relation_data_modulus_indices: Vec<u16>,
    relation_special_modulus_indices: Vec<u16>,
    relation_target_modulus_indices: Vec<u16>,
    commitment_data_modulus_indices: Vec<u16>,
    commitment_module_rank: u16,
    plaintext_modulus: Option<u64>,
    schedule_position: Option<u32>,
    first_mask_purpose: u16,
}

pub(super) struct TrusteeKeyRelationGeometryInput {
    pub(super) schedule_position: u32,
    pub(super) ring_degree: u64,
    pub(super) evaluation_domain_size: u64,
    pub(super) opening_degree_bound_exclusive: u64,
    pub(super) public_polynomial_column_degree_bound_exclusive: u64,
    pub(super) data_modulus_count: usize,
    pub(super) special_modulus_count: usize,
    pub(super) commitment_data_modulus_indices: Vec<u16>,
    pub(super) commitment_module_rank: u16,
    pub(super) plaintext_modulus: u64,
    pub(super) first_mask_purpose: u16,
}

impl KeyRelationGeometry {
    pub(super) fn for_same_secret(input: &SameSecretRelationPlanInput) -> Self {
        Self {
            ring_degree: input.ring_degree,
            evaluation_domain_size: input.evaluation_domain_size,
            opening_degree_bound_exclusive: input.opening_degree_bound_exclusive,
            material_column_degree_bound_exclusive: Some(
                input.material_column_degree_bound_exclusive,
            ),
            public_polynomial_column_degree_bound_exclusive: input
                .public_polynomial_column_degree_bound_exclusive,
            relation_data_modulus_indices: input.sharing_data_modulus_indices.clone(),
            relation_special_modulus_indices: Vec::new(),
            relation_target_modulus_indices: Vec::new(),
            commitment_data_modulus_indices: input.commitment_data_modulus_indices.clone(),
            commitment_module_rank: input.commitment_module_rank,
            plaintext_modulus: None,
            schedule_position: None,
            first_mask_purpose: input.first_mask_purpose,
        }
    }

    pub(super) fn for_public_key_share(input: &PublicKeyShareRelationPlanInput) -> Self {
        Self {
            ring_degree: input.ring_degree,
            evaluation_domain_size: input.evaluation_domain_size,
            opening_degree_bound_exclusive: input.opening_degree_bound_exclusive,
            material_column_degree_bound_exclusive: None,
            public_polynomial_column_degree_bound_exclusive: input
                .public_polynomial_column_degree_bound_exclusive,
            relation_data_modulus_indices: input.data_modulus_indices.clone(),
            relation_special_modulus_indices: Vec::new(),
            relation_target_modulus_indices: Vec::new(),
            commitment_data_modulus_indices: input.commitment_data_modulus_indices.clone(),
            commitment_module_rank: input.commitment_module_rank,
            plaintext_modulus: Some(input.plaintext_modulus),
            schedule_position: None,
            first_mask_purpose: input.first_mask_purpose,
        }
    }

    pub(super) fn for_trustee(
        input: TrusteeKeyRelationGeometryInput,
    ) -> Result<Self, RelationPlanError> {
        let relation_data_modulus_indices = (0..input.data_modulus_count)
            .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
            .collect::<Result<Vec<_>, _>>()?;
        let relation_special_modulus_indices = (0..input.special_modulus_count)
            .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            ring_degree: input.ring_degree,
            evaluation_domain_size: input.evaluation_domain_size,
            opening_degree_bound_exclusive: input.opening_degree_bound_exclusive,
            material_column_degree_bound_exclusive: None,
            public_polynomial_column_degree_bound_exclusive: input
                .public_polynomial_column_degree_bound_exclusive,
            relation_data_modulus_indices,
            relation_special_modulus_indices,
            relation_target_modulus_indices: Vec::new(),
            commitment_data_modulus_indices: input.commitment_data_modulus_indices,
            commitment_module_rank: input.commitment_module_rank,
            plaintext_modulus: Some(input.plaintext_modulus),
            schedule_position: Some(input.schedule_position),
            first_mask_purpose: input.first_mask_purpose,
        })
    }

    pub(super) fn for_target_release(
        ring_degree: u64,
        evaluation_domain_size: u64,
        opening_degree_bound_exclusive: u64,
        material_column_degree_bound_exclusive: u64,
        public_polynomial_column_degree_bound_exclusive: u64,
        target_modulus_indices: Vec<u16>,
        first_mask_purpose: u16,
    ) -> Self {
        Self {
            ring_degree,
            evaluation_domain_size,
            opening_degree_bound_exclusive,
            material_column_degree_bound_exclusive: Some(material_column_degree_bound_exclusive),
            public_polynomial_column_degree_bound_exclusive,
            relation_data_modulus_indices: Vec::new(),
            relation_special_modulus_indices: Vec::new(),
            relation_target_modulus_indices: target_modulus_indices,
            commitment_data_modulus_indices: Vec::new(),
            commitment_module_rank: 0,
            plaintext_modulus: None,
            schedule_position: None,
            first_mask_purpose,
        }
    }

    fn trace_domain_size(&self) -> Result<u64, RelationPlanError> {
        self.ring_degree
            .checked_div(2)
            .filter(|trace_size| *trace_size > 1 && *trace_size * 2 == self.ring_degree)
            .ok_or(RelationPlanError::InvalidDomain)
    }

    pub(super) fn validate(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<(SuiteModulusReference, u64)>, RelationPlanError> {
        RelationPlanChecker::new(context).check_context()?;
        self.trace_domain_size()?;
        if !self.ring_degree.is_power_of_two()
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.opening_degree_bound_exclusive <= 1
            || self.public_polynomial_column_degree_bound_exclusive == 0
            || self.public_polynomial_column_degree_bound_exclusive
                > self.opening_degree_bound_exclusive
            || self
                .material_column_degree_bound_exclusive
                .is_some_and(|degree| degree == 0 || degree > self.opening_degree_bound_exclusive)
            || (self.relation_data_modulus_indices.is_empty()
                == self.relation_target_modulus_indices.is_empty())
            || (!self.relation_data_modulus_indices.is_empty()
                && !strictly_sorted_unique(&self.relation_data_modulus_indices))
            || (!self.relation_special_modulus_indices.is_empty()
                && !strictly_sorted_unique(&self.relation_special_modulus_indices))
            || (!self.relation_target_modulus_indices.is_empty()
                && !strictly_sorted_unique(&self.relation_target_modulus_indices))
            || (self.commitment_data_modulus_indices.is_empty()
                != (self.commitment_module_rank == 0))
            || (!self.commitment_data_modulus_indices.is_empty()
                && !strictly_sorted_unique(&self.commitment_data_modulus_indices))
            || self.first_mask_purpose == 0
            || self.first_mask_purpose >= 0xff00
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        if !self.commitment_data_modulus_indices.is_empty() {
            let expected_commitment_module_rank = u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
                .map_err(|_| RelationPlanError::CountOverflow)?;
            if self.commitment_module_rank != expected_commitment_module_rank {
                return Err(RelationPlanError::InvalidDomain);
            }
            let expected_commitment_data_modulus_indices = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
                .iter()
                .copied()
                .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
                .collect::<Result<Vec<_>, _>>()?;
            if self.commitment_data_modulus_indices != expected_commitment_data_modulus_indices {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
        }
        let expected_evaluation_domain = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .and_then(|degree_domain| {
                degree_domain.checked_mul(u64::from(context.evaluation_blowup_factor))
            })
            .ok_or(RelationPlanError::CountOverflow)?;
        if expected_evaluation_domain != self.evaluation_domain_size {
            return Err(RelationPlanError::InvalidDomain);
        }
        if self.plaintext_modulus.is_some() {
            let expected_data_modulus_indices = (0..self.relation_data_modulus_indices.len())
                .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
                .collect::<Result<Vec<_>, _>>()?;
            if self.relation_data_modulus_indices != expected_data_modulus_indices
                || self.commitment_data_modulus_indices.iter().any(|index| {
                    self.relation_data_modulus_indices
                        .binary_search(index)
                        .is_err()
                })
            {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
        }

        let all_data_modulus_indices = self
            .relation_data_modulus_indices
            .iter()
            .chain(&self.commitment_data_modulus_indices)
            .copied()
            .collect::<BTreeSet<_>>();
        let mut resolved_moduli = all_data_modulus_indices
            .into_iter()
            .map(|index| {
                let reference = SuiteModulusReference::data(index);
                let modulus = context.resolved_modulus(reference)?;
                if modulus <= self.ring_degree
                    || modulus >= context.base_field_modulus
                    || modulus.is_multiple_of(2)
                {
                    return Err(RelationPlanError::InvalidModulus);
                }
                Ok((reference, modulus))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut resolved_special_moduli = self
            .relation_special_modulus_indices
            .iter()
            .copied()
            .map(|index| {
                let reference = SuiteModulusReference::special(index);
                let modulus = context.resolved_modulus(reference)?;
                if modulus <= self.ring_degree
                    || modulus >= context.base_field_modulus
                    || modulus.is_multiple_of(2)
                {
                    return Err(RelationPlanError::InvalidModulus);
                }
                Ok((reference, modulus))
            })
            .collect::<Result<Vec<_>, _>>()?;
        resolved_moduli.append(&mut resolved_special_moduli);
        let mut resolved_target_moduli = self
            .relation_target_modulus_indices
            .iter()
            .copied()
            .map(|index| {
                let reference = SuiteModulusReference::target(index);
                let modulus = context.resolved_modulus(reference)?;
                if modulus <= self.ring_degree
                    || modulus >= context.base_field_modulus
                    || modulus.is_multiple_of(2)
                {
                    return Err(RelationPlanError::InvalidModulus);
                }
                Ok((reference, modulus))
            })
            .collect::<Result<Vec<_>, _>>()?;
        resolved_moduli.append(&mut resolved_target_moduli);
        if let Some(plaintext_modulus) = self.plaintext_modulus {
            if context.resolved_modulus(SuiteModulusReference::plaintext())? != plaintext_modulus
                || plaintext_modulus < 3
                || resolved_moduli
                    .iter()
                    .any(|(_, modulus)| plaintext_modulus >= *modulus)
            {
                return Err(RelationPlanError::InvalidModulus);
            }
            resolved_moduli.push((SuiteModulusReference::plaintext(), plaintext_modulus));
        }
        resolved_moduli.sort_by_key(|(reference, _)| *reference);
        if !self.commitment_data_modulus_indices.is_empty() {
            self.validate_anchor_lift_bound(context)?;
        }
        Ok(resolved_moduli)
    }

    fn validate_anchor_lift_bound(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        let commitment_moduli = self
            .commitment_data_modulus_indices
            .iter()
            .copied()
            .map(|index| context.resolved_modulus(SuiteModulusReference::data(index)))
            .collect::<Result<Vec<_>, _>>()?;
        let modulus_product = commitment_moduli
            .iter()
            .copied()
            .map(BigUint::from)
            .product::<BigUint>();
        let maximum_modulus = commitment_moduli
            .iter()
            .copied()
            .max()
            .ok_or(RelationPlanError::MissingModulus)?;
        let maximum_centered_matrix_coefficient = (maximum_modulus - 1) / 2;
        let maximum_lift = u128::from(self.commitment_module_rank)
            .checked_add(1)
            .and_then(|term_count| term_count.checked_mul(u128::from(self.ring_degree)))
            .and_then(|coefficient_count| {
                coefficient_count.checked_mul(u128::from(maximum_centered_matrix_coefficient))
            })
            .and_then(|bound| bound.checked_add(4))
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        if modulus_product <= BigUint::from(maximum_lift) * BigUint::from(2_u8) {
            return Err(RelationPlanError::NoWrapBoundViolated);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum KeyVerifierSourceKey {
    StatementRoot {
        field_ordinal: u64,
        list_ordinal: Option<u64>,
    },
    BdlopMatrix {
        data_modulus_index: u16,
        matrix_part: u16,
        row: u16,
        column: u16,
    },
    TrusteeBdlopMatrix {
        data_modulus_index: u16,
        matrix_part: u16,
        row: u16,
        column: u16,
    },
    PublicKeyCommonReference {
        data_modulus_index: u16,
    },
    RelinearizationCommonReference {
        schedule_position: u32,
        decomposition_block_index: u16,
        modulus_reference: SuiteModulusReference,
    },
    GaloisCommonReference {
        schedule_position: u32,
        decomposition_block_index: u16,
        modulus_reference: SuiteModulusReference,
    },
    NegacyclicAutomorphismMapping {
        ring_degree: u64,
        galois_element: u64,
    },
    TargetConvertedRadixDigit {
        target_role: u16,
        component_ordinal: u16,
        target_modulus_index: u16,
        scale: u64,
        radix: u64,
        digit_ordinal: u16,
        digit_count: u16,
    },
    TargetPartialDecryptionRadixDigit {
        target_role: u16,
        target_modulus_index: u16,
        radix: u64,
        digit_ordinal: u16,
        digit_count: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BoundPolynomialRootUse {
    Input,
    Output,
}

#[derive(Clone, Copy)]
pub(super) enum ProofTreePhase {
    Base,
    Auxiliary,
}

#[derive(Clone, Debug)]
pub(super) struct BoundedUnsignedColumn {
    target_column_ordinal: u32,
    ordered_digit_column_ordinals: Vec<u32>,
}

#[derive(Clone, Debug)]
pub(super) struct BoundedMaterialDigitWitnessLayout {
    pub(super) target_column_ordinal: u32,
    pub(super) trit_column_ordinals: Vec<u32>,
}

#[derive(Clone, Debug)]
pub(super) struct UpperBoundComparatorWitnessLayout {
    pub(super) difference_digits: Vec<BoundedMaterialDigitWitnessLayout>,
    pub(super) borrow_column_ordinals: Vec<u32>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SplitIntegerVector {
    pub(super) halves: [u32; 2],
}

#[derive(Clone, Debug)]
pub(super) struct ShiftedSmallVector {
    pub(super) coefficients: SplitIntegerVector,
    pub(super) offset: u64,
}

#[derive(Clone, Debug)]
pub(super) struct ReversibleShiftedSmallVector {
    pub(super) source: ShiftedSmallVector,
    pub(super) reversed: SplitIntegerVector,
}

#[derive(Clone, Debug)]
pub(super) struct AnchorOpeningWitness {
    hiding_secrets: Vec<ReversibleShiftedSmallVector>,
    hiding_errors: Vec<ShiftedSmallVector>,
}

#[derive(Clone, Debug)]
pub(super) struct AnchorQuotientWitness {
    rows: Vec<[u32; 2]>,
}

pub(super) struct AnchorEquationInputs<'input> {
    commitments: &'input [SplitIntegerVector],
    first_matrix: &'input [Vec<SplitIntegerVector>],
    second_matrix: &'input [SplitIntegerVector],
    opening: &'input AnchorOpeningWitness,
    secret: &'input ShiftedSmallVector,
    quotients: &'input AnchorQuotientWitness,
}

impl<'input> AnchorEquationInputs<'input> {
    pub(super) fn new(
        commitments: &'input [SplitIntegerVector],
        first_matrix: &'input [Vec<SplitIntegerVector>],
        second_matrix: &'input [SplitIntegerVector],
        opening: &'input AnchorOpeningWitness,
        secret: &'input ShiftedSmallVector,
        quotients: &'input AnchorQuotientWitness,
    ) -> Self {
        Self {
            commitments,
            first_matrix,
            second_matrix,
            opening,
            secret,
            quotients,
        }
    }
}

pub(super) struct PublicKeyEquationInputs<'input> {
    public_key_share: &'input SplitIntegerVector,
    common_reference: &'input SplitIntegerVector,
    secret: &'input ReversibleShiftedSmallVector,
    error: &'input ShiftedSmallVector,
    quotient_columns: [u32; 2],
}

impl<'input> PublicKeyEquationInputs<'input> {
    pub(super) fn new(
        public_key_share: &'input SplitIntegerVector,
        common_reference: &'input SplitIntegerVector,
        secret: &'input ReversibleShiftedSmallVector,
        error: &'input ShiftedSmallVector,
        quotient_columns: [u32; 2],
    ) -> Self {
        Self {
            public_key_share,
            common_reference,
            secret,
            error,
            quotient_columns,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct TrusteeAnchorOpeningWitness {
    hiding_secrets: Vec<SplitIntegerVector>,
    hiding_errors: Vec<ShiftedSmallVector>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TrusteeRadixThreeQuotientWitness {
    low_quotients: [u32; 2],
    high_carries: [u32; 2],
}

#[derive(Clone, Debug)]
pub(super) struct TargetCommittedMaterialVector {
    pub(super) bound_columns: [u32; 4],
    pub(super) trits_by_half: [Vec<u32>; 2],
    pub(super) upper_bound_comparators: Vec<UpperBoundComparatorWitnessLayout>,
}

#[derive(Clone, Debug)]
pub(super) struct TargetBoundedUnsignedVector {
    pub(super) digit_columns_by_half: [[u32; 2]; 2],
    pub(super) trits_by_half: [Vec<u32>; 2],
    pub(super) upper_bound_comparators: Vec<UpperBoundComparatorWitnessLayout>,
}

#[derive(Clone, Debug)]
pub(super) struct TargetCenteredVector {
    pub(super) value: ShiftedSmallVector,
    pub(super) trits_by_half: [Vec<u32>; 2],
}

#[derive(Default)]
struct PendingIntegerLiftBatch {
    reversed_bindings: BTreeMap<(u32, u32), RelationIntegerLiftReversedColumnBindingDescriptor>,
    negacyclic_automorphism_permutations:
        Vec<RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor>,
    components: Vec<RelationIntegerLiftComponentDescriptor>,
}

pub(super) struct KeyRelationPlanBuilder<'context> {
    application_statement_schema_identifier: u16,
    geometry: &'context KeyRelationGeometry,
    context: &'context RelationPlanCheckContext,
    ordered_non_native_moduli: Vec<SuiteModulusReference>,
    resolved_moduli: BTreeMap<SuiteModulusReference, u64>,
    ordered_verifier_sources: Vec<RelationVerifierSource>,
    source_ordinals: BTreeMap<KeyVerifierSourceKey, u32>,
    ordered_columns: Vec<RelationColumnDescriptor>,
    semantic_cells_by_column: BTreeMap<u32, (SignedIntegerInterval, RelationBoundCertificate)>,
    bound_trees: Vec<RelationTreeDescriptor>,
    base_tree_columns: Vec<u32>,
    auxiliary_tree_columns: Vec<u32>,
    pending_integer_lift_batches: BTreeMap<(SuiteModulusReference, u16), PendingIntegerLiftBatch>,
    ordered_integer_lift_batches: Vec<RelationIntegerLiftBatchDescriptor>,
    ordered_constraints: Vec<RelationConstraintDescriptor>,
}

impl<'context> KeyRelationPlanBuilder<'context> {
    pub(super) fn new(
        application_statement_schema_identifier: u16,
        geometry: &'context KeyRelationGeometry,
        context: &'context RelationPlanCheckContext,
        sources: Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
    ) -> Result<Self, RelationPlanError> {
        let resolved = geometry.validate(context)?;
        let (ordered_verifier_sources, source_ordinals) = canonical_sources(sources)?;
        Ok(Self {
            application_statement_schema_identifier,
            geometry,
            context,
            ordered_non_native_moduli: resolved.iter().map(|(reference, _)| *reference).collect(),
            resolved_moduli: resolved.into_iter().collect(),
            ordered_verifier_sources,
            source_ordinals,
            ordered_columns: Vec::new(),
            semantic_cells_by_column: BTreeMap::new(),
            bound_trees: Vec::new(),
            base_tree_columns: Vec::new(),
            auxiliary_tree_columns: Vec::new(),
            pending_integer_lift_batches: BTreeMap::new(),
            ordered_integer_lift_batches: Vec::new(),
            ordered_constraints: Vec::new(),
        })
    }

    fn modulus(&self, modulus_reference: SuiteModulusReference) -> Result<u64, RelationPlanError> {
        self.resolved_moduli
            .get(&modulus_reference)
            .copied()
            .ok_or(RelationPlanError::MissingModulus)
    }

    fn modulus_ordinal(
        &self,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u16, RelationPlanError> {
        u16::try_from(
            self.ordered_non_native_moduli
                .binary_search(&modulus_reference)
                .map_err(|_| RelationPlanError::MissingModulus)?,
        )
        .map_err(|_| RelationPlanError::CountOverflow)
    }

    fn source_ordinal(&self, key: &KeyVerifierSourceKey) -> Result<u32, RelationPlanError> {
        self.source_ordinals
            .get(key)
            .copied()
            .ok_or(RelationPlanError::InvalidSource)
    }

    fn push_column(
        &mut self,
        origin: RelationColumnOrigin,
        source_degree_bound_exclusive: u64,
        canonical_residue_modulus: Option<SuiteModulusReference>,
        phase: Option<ProofTreePhase>,
    ) -> Result<u32, RelationPlanError> {
        let ordinal = u32::try_from(self.ordered_columns.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        self.ordered_columns.push(RelationColumnDescriptor {
            origin,
            value_type: RelationColumnValueType::BaseField,
            source_degree_bound_exclusive,
            canonical_residue_modulus,
        });
        match phase {
            Some(ProofTreePhase::Base) => self.base_tree_columns.push(ordinal),
            Some(ProofTreePhase::Auxiliary) => self.auxiliary_tree_columns.push(ordinal),
            None => {}
        }
        Ok(ordinal)
    }

    fn push_prover_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
        self.push_column(
            RelationColumnOrigin::Prover,
            self.geometry.trace_domain_size()?,
            None,
            Some(phase),
        )
    }

    fn add_constraint(
        &mut self,
        numerator_postfix_expression: Vec<RelationExpressionInstruction>,
        zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
        enforce_proof_base_field_no_wrap: bool,
    ) -> Result<u32, RelationPlanError> {
        self.add_constraint_with_integer_factors(
            numerator_postfix_expression,
            zeroifier_postfix_expression,
            enforce_proof_base_field_no_wrap,
            Vec::new(),
        )
    }

    fn add_constraint_with_integer_factors(
        &mut self,
        numerator_postfix_expression: Vec<RelationExpressionInstruction>,
        zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
        enforce_proof_base_field_no_wrap: bool,
        ordered_injective_integer_factor_expressions: Vec<Vec<RelationExpressionInstruction>>,
    ) -> Result<u32, RelationPlanError> {
        let ordinal = u32::try_from(self.ordered_constraints.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        self.ordered_constraints.push(RelationConstraintDescriptor {
            constraint_role: 1,
            role_coordinates: vec![u64::from(ordinal)],
            numerator_postfix_expression,
            zeroifier_postfix_expression,
            enforce_proof_base_field_no_wrap,
            ordered_injective_integer_factor_expressions,
        });
        Ok(ordinal)
    }

    fn add_full_trace_constraint(
        &mut self,
        expression: Vec<RelationExpressionInstruction>,
        enforce_no_wrap: bool,
    ) -> Result<u32, RelationPlanError> {
        self.add_constraint(
            expression,
            full_trace_zeroifier_expression(self.geometry.trace_domain_size()?),
            enforce_no_wrap,
        )
    }

    fn insert_semantic_cell(
        &mut self,
        column_ordinal: u32,
        interval: SignedIntegerInterval,
        bound_certificate: RelationBoundCertificate,
    ) -> Result<(), RelationPlanError> {
        if self
            .semantic_cells_by_column
            .insert(column_ordinal, (interval, bound_certificate))
            .is_some()
        {
            return Err(RelationPlanError::InvalidSemanticCell);
        }
        Ok(())
    }

    fn add_trit_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
        let column = self.push_prover_column(phase)?;
        let constraint_ordinal =
            self.add_full_trace_constraint(trinary_constraint_expression(column), false)?;
        self.insert_semantic_cell(
            column,
            SignedIntegerInterval::new(0, 2),
            RelationBoundCertificate::Trinary { constraint_ordinal },
        )?;
        Ok(column)
    }

    fn add_binary_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
        let column = self.push_prover_column(phase)?;
        let constraint_ordinal =
            self.add_full_trace_constraint(binary_constraint_expression(column), false)?;
        self.insert_semantic_cell(
            column,
            SignedIntegerInterval::new(0, 1),
            RelationBoundCertificate::Binary { constraint_ordinal },
        )?;
        Ok(column)
    }

    fn add_finite_integer_set_column(
        &mut self,
        ordered_values: Vec<BigInt>,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        let column = self.push_prover_column(phase)?;
        let (expression, ordered_factor_expressions) = finite_integer_set_constraint_expressions(
            column,
            &ordered_values,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_constraint_with_integer_factors(
            expression,
            full_trace_zeroifier_expression(self.geometry.trace_domain_size()?),
            false,
            ordered_factor_expressions,
        )?;
        self.insert_semantic_cell(
            column,
            SignedIntegerInterval::from_bigints(
                ordered_values
                    .first()
                    .cloned()
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?,
                ordered_values
                    .last()
                    .cloned()
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?,
            )?,
            RelationBoundCertificate::FiniteIntegerSet {
                constraint_ordinal,
                ordered_values,
            },
        )?;
        Ok(column)
    }

    fn add_trit_columns(
        &mut self,
        count: usize,
        phase: ProofTreePhase,
    ) -> Result<Vec<u32>, RelationPlanError> {
        (0..count).map(|_| self.add_trit_column(phase)).collect()
    }

    fn certify_unsigned_recomposition(
        &mut self,
        target_column_ordinal: u32,
        radix: u64,
        ordered_digit_column_ordinals: &[u32],
    ) -> Result<(), RelationPlanError> {
        let expression = radix_recomposition_expression(
            target_column_ordinal,
            radix,
            None,
            ordered_digit_column_ordinals,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let maximum = BigUint::from(radix).pow(
            u32::try_from(ordered_digit_column_ordinals.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
        ) - BigUint::one();
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))?,
            RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal,
                radix,
                ordered_digit_column_ordinals: ordered_digit_column_ordinals.to_vec(),
            },
        )
    }

    fn add_bounded_material_digit(
        &mut self,
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<BoundedMaterialDigitWitnessLayout, RelationPlanError> {
        if maximum >= MATERIAL_DIGIT_RADIX {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let target = self.push_prover_column(phase)?;
        let trit_count = minimum_unsigned_radix_digit_count(maximum, TRIT_RADIX)?;
        let trits = self.add_trit_columns(trit_count, phase)?;
        self.certify_unsigned_recomposition(target, TRIT_RADIX, &trits)?;
        Ok(BoundedMaterialDigitWitnessLayout {
            target_column_ordinal: target,
            trit_column_ordinals: trits,
        })
    }

    fn add_bounded_unsigned_column(
        &mut self,
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<BoundedUnsignedColumn, RelationPlanError> {
        if maximum >= MATERIAL_DIGIT_RADIX {
            return Err(RelationPlanError::IntegerBoundOverflow);
        }
        let bounded_digit = self.add_bounded_material_digit(maximum, phase)?;
        let target_column_ordinal = bounded_digit.target_column_ordinal;
        let maximum_digits = vec![maximum];
        let _ =
            self.add_upper_bound_comparator(&[target_column_ordinal], &maximum_digits, phase)?;
        Ok(BoundedUnsignedColumn {
            target_column_ordinal,
            ordered_digit_column_ordinals: vec![target_column_ordinal],
        })
    }

    fn add_canonical_modulus_column(
        &mut self,
        modulus_reference: SuiteModulusReference,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        let maximum = self
            .context
            .resolved_modulus(modulus_reference)?
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidModulus)?;
        let digit_count = minimum_unsigned_radix_digit_count(maximum, TRIT_RADIX)?;
        let target_column_ordinal = self.push_prover_column(phase)?;
        let ordered_digit_column_ordinals = self.add_trit_columns(digit_count, phase)?;
        let recomposition_constraint_ordinal = self.add_full_trace_constraint(
            radix_recomposition_expression(
                target_column_ordinal,
                TRIT_RADIX,
                None,
                &ordered_digit_column_ordinals,
                self.context.base_field_modulus,
            )?,
            false,
        )?;
        let maximum_digits = fixed_radix_digits(maximum, digit_count, TRIT_RADIX)?;
        let ordered_difference_digit_column_ordinals = self.add_trit_columns(digit_count, phase)?;
        let ordered_borrow_column_ordinals = (0..digit_count.saturating_sub(1))
            .map(|_| self.add_binary_column(phase))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ordered_comparator_constraint_ordinals = Vec::with_capacity(digit_count);
        for digit_ordinal in 0..digit_count {
            ordered_comparator_constraint_ordinals.push(
                self.add_full_trace_constraint(
                    unsigned_radix_comparator_digit_expression(
                        maximum_digits[digit_ordinal],
                        ordered_digit_column_ordinals[digit_ordinal],
                        ordered_difference_digit_column_ordinals[digit_ordinal],
                        digit_ordinal
                            .checked_sub(1)
                            .map(|ordinal| ordered_borrow_column_ordinals[ordinal]),
                        (digit_ordinal + 1 < digit_count)
                            .then(|| ordered_borrow_column_ordinals[digit_ordinal]),
                        TRIT_RADIX,
                    ),
                    true,
                )?,
            );
        }
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))?,
            RelationBoundCertificate::CanonicalModulusRecomposition {
                recomposition_constraint_ordinal,
                modulus_reference,
                radix: TRIT_RADIX,
                ordered_digit_column_ordinals,
                ordered_comparator_constraint_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
            },
        )?;
        Ok(target_column_ordinal)
    }

    fn add_upper_bound_comparator(
        &mut self,
        value_digits: &[u32],
        maximum_digits: &[u64],
        phase: ProofTreePhase,
    ) -> Result<UpperBoundComparatorWitnessLayout, RelationPlanError> {
        if value_digits.is_empty() || value_digits.len() != maximum_digits.len() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut difference_digits = Vec::with_capacity(maximum_digits.len());
        for (digit_ordinal, maximum_digit) in maximum_digits.iter().copied().enumerate() {
            let difference_maximum = if digit_ordinal + 1 == maximum_digits.len() {
                maximum_digit
            } else {
                MATERIAL_DIGIT_RADIX - 1
            };
            difference_digits.push(self.add_bounded_material_digit(difference_maximum, phase)?);
        }
        let borrows = (0..value_digits.len().saturating_sub(1))
            .map(|_| self.add_binary_column(phase))
            .collect::<Result<Vec<_>, _>>()?;
        for digit_ordinal in 0..value_digits.len() {
            let mut terms = vec![integer_constant_term(maximum_digits[digit_ordinal], false)];
            terms.push(integer_column_term(value_digits[digit_ordinal], true));
            if digit_ordinal > 0 {
                terms.push(integer_column_term(borrows[digit_ordinal - 1], true));
            }
            if digit_ordinal + 1 < value_digits.len() {
                terms.push(integer_scaled_column_term(
                    borrows[digit_ordinal],
                    MATERIAL_DIGIT_RADIX,
                    false,
                ));
            }
            terms.push(integer_column_term(
                difference_digits[digit_ordinal].target_column_ordinal,
                true,
            ));
            self.add_full_trace_constraint(sum_integer_terms(terms)?, true)?;
        }
        Ok(UpperBoundComparatorWitnessLayout {
            difference_digits,
            borrow_column_ordinals: borrows,
        })
    }
}

impl KeyRelationPlanBuilder<'_> {
    pub(super) fn finish(mut self) -> Result<CompiledRelationPlan, RelationPlanError> {
        self.finalize_integer_lift_batches()?;
        if self.base_tree_columns.is_empty()
            || self.auxiliary_tree_columns.is_empty()
            || self.ordered_integer_lift_batches.is_empty()
        {
            return Err(RelationPlanError::InvalidRoot);
        }
        let required_rotations_by_column =
            required_column_rotations(&self.ordered_constraints, &[])?;
        if required_rotations_by_column.len() != self.ordered_columns.len() {
            return Err(RelationPlanError::InvalidOpening);
        }
        let trace_mask_degree_bound_exclusive = derived_trace_mask_degree_bound(
            &self.ordered_columns,
            &required_rotations_by_column,
            self.geometry.trace_domain_size()?,
            self.context,
        )?;
        let prover_column_degree_bound_exclusive = self
            .geometry
            .trace_domain_size()?
            .checked_add(trace_mask_degree_bound_exclusive)
            .filter(|degree| *degree <= self.geometry.opening_degree_bound_exclusive)
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        for column in &mut self.ordered_columns {
            if matches!(column.origin, RelationColumnOrigin::Prover) {
                column.source_degree_bound_exclusive = prover_column_degree_bound_exclusive;
            }
        }

        let used_rotations = required_rotations_by_column
            .values()
            .flat_map(|rotations| rotations.iter().copied())
            .collect::<BTreeSet<_>>();
        if !used_rotations.contains(&(false, 0)) {
            return Err(RelationPlanError::InvalidOpening);
        }
        let mut ordered_trees = self.bound_trees;
        ordered_trees.push(RelationTreeDescriptor::ProofCreated {
            proof_tree_role: 1,
            ordered_column_ordinals: self.base_tree_columns,
        });
        ordered_trees.push(RelationTreeDescriptor::ProofCreated {
            proof_tree_role: 2,
            ordered_column_ordinals: self.auxiliary_tree_columns,
        });
        let ordered_semantic_cells = self
            .semantic_cells_by_column
            .into_iter()
            .enumerate()
            .map(
                |(
                    semantic_cell_ordinal,
                    (column_ordinal, (claimed_interval, bound_certificate)),
                )| {
                    Ok(SemanticCellDescriptor {
                        semantic_cell_ordinal: u32::try_from(semantic_cell_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        column_ordinal,
                        claimed_interval,
                        bound_certificate,
                    })
                },
            )
            .collect::<Result<Vec<_>, RelationPlanError>>()?;

        let ordered_opening_points = (0..self.context.deep_point_count)
            .flat_map(|deep_point_ordinal| {
                used_rotations
                    .iter()
                    .map(move |rotation| RelationOpeningPointDescriptor {
                        deep_point_ordinal,
                        trace_rotation_is_negative: rotation.0,
                        trace_rotation_magnitude: rotation.1,
                        conjugate_index: 0,
                    })
            })
            .collect::<Vec<_>>();
        let opening_point_ordinals = ordered_opening_points
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, point)| {
                Ok((
                    point,
                    u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, RelationPlanError>>()?;
        let mut ordered_opening_claims = Vec::new();
        for (tree_ordinal, tree) in ordered_trees.iter().enumerate() {
            for column_ordinal in tree.ordered_column_ordinals() {
                let source_degree_bound_exclusive = self
                    .ordered_columns
                    .get(*column_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidOpening)?
                    .source_degree_bound_exclusive;
                for deep_point_ordinal in 0..self.context.deep_point_count {
                    for rotation in required_rotations_by_column
                        .get(column_ordinal)
                        .ok_or(RelationPlanError::InvalidOpening)?
                    {
                        let opening_point_ordinal = opening_point_ordinals
                            .get(&RelationOpeningPointDescriptor {
                                deep_point_ordinal,
                                trace_rotation_is_negative: rotation.0,
                                trace_rotation_magnitude: rotation.1,
                                conjugate_index: 0,
                            })
                            .copied()
                            .ok_or(RelationPlanError::InvalidOpening)?;
                        ordered_opening_claims.push(RelationOpeningClaimDescriptor {
                            source_class: RelationOpeningSourceClass::TreeColumn,
                            source_ordinal: u32::try_from(tree_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                            column_ordinal: Some(*column_ordinal),
                            opening_point_ordinal,
                            source_degree_bound_exclusive,
                        });
                    }
                }
            }
        }
        for quotient_ordinal in 0..self.context.quotient_component_count {
            for deep_point_ordinal in 0..self.context.deep_point_count {
                let opening_point_ordinal = opening_point_ordinals
                    .get(&RelationOpeningPointDescriptor {
                        deep_point_ordinal,
                        trace_rotation_is_negative: false,
                        trace_rotation_magnitude: 0,
                        conjugate_index: 0,
                    })
                    .copied()
                    .ok_or(RelationPlanError::InvalidOpening)?;
                ordered_opening_claims.push(RelationOpeningClaimDescriptor {
                    source_class: RelationOpeningSourceClass::Quotient,
                    source_ordinal: quotient_ordinal,
                    column_ordinal: None,
                    opening_point_ordinal,
                    source_degree_bound_exclusive: self
                        .context
                        .quotient_component_degree_bound_exclusive,
                });
            }
        }
        ordered_opening_claims.push(RelationOpeningClaimDescriptor {
            source_class: RelationOpeningSourceClass::BatchMask,
            source_ordinal: 0,
            column_ordinal: None,
            opening_point_ordinal: 0,
            source_degree_bound_exclusive: self
                .geometry
                .opening_degree_bound_exclusive
                .checked_sub(1)
                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
        });

        let mut next_mask_purpose = self.geometry.first_mask_purpose;
        let mut ordered_masks = Vec::new();
        for (column_ordinal, column) in self.ordered_columns.iter().enumerate() {
            if matches!(column.origin, RelationColumnOrigin::Prover) {
                ordered_masks.push(RelationMaskDescriptor {
                    mask_purpose: next_mask_purpose,
                    mask_kind: RelationMaskKind::Trace,
                    target_class: RelationMaskTargetClass::Column,
                    target_ordinal: u32::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    mask_degree_bound_exclusive: trace_mask_degree_bound_exclusive,
                });
                next_mask_purpose = next_mask_purpose
                    .checked_add(1)
                    .filter(|purpose| *purpose < 0xff00)
                    .ok_or(RelationPlanError::MaskPurposeExhausted)?;
            }
        }
        let quotient_component_count = self.context.quotient_component_count;
        if quotient_component_count < 2 {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let component_count = u128::from(quotient_component_count);
        let rounded_mask_degree = component_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(u128::from(trace_mask_degree_bound_exclusive)))
            .and_then(|degree| degree.checked_add(component_count - 1))
            .ok_or(RelationPlanError::DegreeBoundExceeded)?
            / component_count;
        let decomposition_stride = self
            .geometry
            .trace_domain_size()?
            .checked_add(
                u64::try_from(rounded_mask_degree)
                    .map_err(|_| RelationPlanError::DegreeBoundExceeded)?,
            )
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let telescoping_degree = self
            .context
            .quotient_component_degree_bound_exclusive
            .checked_sub(decomposition_stride)
            .filter(|degree| *degree != 0)
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        for quotient_ordinal in 0..quotient_component_count - 1 {
            ordered_masks.push(RelationMaskDescriptor {
                mask_purpose: next_mask_purpose,
                mask_kind: RelationMaskKind::Telescoping,
                target_class: RelationMaskTargetClass::QuotientComponent,
                target_ordinal: quotient_ordinal,
                mask_degree_bound_exclusive: telescoping_degree,
            });
            next_mask_purpose = next_mask_purpose
                .checked_add(1)
                .filter(|purpose| *purpose < 0xff00)
                .ok_or(RelationPlanError::MaskPurposeExhausted)?;
        }
        ordered_masks.push(RelationMaskDescriptor {
            mask_purpose: next_mask_purpose,
            mask_kind: RelationMaskKind::OpeningBatch,
            target_class: RelationMaskTargetClass::Batch,
            target_ordinal: 0,
            mask_degree_bound_exclusive: self
                .geometry
                .opening_degree_bound_exclusive
                .checked_sub(1)
                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
        });

        let compiled = CompiledRelationPlan {
            plan: RelationPlan {
                application_statement_schema_identifier: self
                    .application_statement_schema_identifier,
                variants: vec![RelationPlanVariant {
                    schedule_position: self.geometry.schedule_position,
                    top_count: None,
                    proof_privacy_mode: ProofPrivacyMode::SecretBearing,
                    trace_domain_size: self.geometry.trace_domain_size()?,
                    evaluation_domain_size: self.geometry.evaluation_domain_size,
                    opening_degree_bound_exclusive: self.geometry.opening_degree_bound_exclusive,
                    ordered_non_native_moduli: self.ordered_non_native_moduli,
                    ordered_verifier_sources: self.ordered_verifier_sources,
                    ordered_public_samplers: Vec::new(),
                    ordered_columns: self.ordered_columns,
                    ordered_semantic_cells,
                    ordered_radix_convolutions: Vec::new(),
                    ordered_integer_lift_batches: self.ordered_integer_lift_batches,
                    ordered_coefficient_local_identity_batches: Vec::new(),
                    ordered_trees,
                    ordered_constraints: self.ordered_constraints,
                    ordered_opening_points,
                    ordered_opening_claims,
                    ordered_masks,
                }],
            },
        };
        compiled.check(self.context)?;
        Ok(compiled)
    }
}

fn derived_trace_mask_degree_bound(
    ordered_columns: &[RelationColumnDescriptor],
    required_rotations_by_column: &BTreeMap<u32, BTreeSet<(bool, u64)>>,
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    let mut maximum_view_count = 0_u64;
    for (column_ordinal, column) in ordered_columns.iter().enumerate() {
        if !matches!(column.origin, RelationColumnOrigin::Prover) {
            continue;
        }
        let rotation_count = u64::try_from(
            required_rotations_by_column
                .get(&u32::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
                .ok_or(RelationPlanError::InvalidOpening)?
                .len(),
        )
        .map_err(|_| RelationPlanError::CountOverflow)?;
        let deep_opening_view_count = u64::from(context.challenge_extension_degree)
            .checked_mul(u64::from(context.deep_point_count))
            .and_then(|count| count.checked_mul(rotation_count))
            .ok_or(RelationPlanError::CountOverflow)?;
        let query_view_count = u64::from(context.unique_query_count)
            .checked_mul(2)
            .and_then(|count| count.checked_mul(rotation_count))
            .ok_or(RelationPlanError::CountOverflow)?;
        maximum_view_count = maximum_view_count.max(
            deep_opening_view_count
                .checked_add(query_view_count)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
    }
    if maximum_view_count == 0 || maximum_view_count > trace_domain_size {
        Err(RelationPlanError::InvalidMaskGrammar)
    } else {
        Ok(maximum_view_count)
    }
}

pub(super) fn statement_root_source(
    field_ordinal: u64,
    list_ordinal: Option<u64>,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let mut value_path = vec![RelationSelectorPathStep::tuple_field(field_ordinal)];
    if let Some(list_ordinal) = list_ordinal {
        value_path.push(RelationSelectorPathStep {
            step_kind: SelectorPathStepKind::LiteralListIndex,
            argument: list_ordinal,
        });
    }
    (
        KeyVerifierSourceKey::StatementRoot {
            field_ordinal,
            list_ordinal,
        },
        RelationVerifierSource::ApplicationStatement {
            value_path,
            value_layout: RelationValueLayout::scalar_hash(),
        },
    )
}

pub(super) fn bdlop_matrix_source(
    ring_degree: u64,
    data_modulus_index: u16,
    matrix_part: u16,
    row: u16,
    column: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::data(data_modulus_index);
    (
        KeyVerifierSourceKey::BdlopMatrix {
            data_modulus_index,
            matrix_part,
            row,
            column,
        },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 5,
            source_coordinates: vec![
                u64::from(data_modulus_index),
                u64::from(matrix_part),
                u64::from(row),
                u64::from(column),
            ],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: centered_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(super) fn trustee_bdlop_matrix_source(
    ring_degree: u64,
    data_modulus_index: u16,
    matrix_part: u16,
    row: u16,
    column: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::data(data_modulus_index);
    (
        KeyVerifierSourceKey::TrusteeBdlopMatrix {
            data_modulus_index,
            matrix_part,
            row,
            column,
        },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 5,
            source_coordinates: vec![
                u64::from(data_modulus_index),
                u64::from(matrix_part),
                u64::from(row),
                u64::from(column),
            ],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(super) fn relinearization_common_reference_source(
    ring_degree: u64,
    schedule_position: u32,
    decomposition_block_index: u16,
    modulus_reference: SuiteModulusReference,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    (
        KeyVerifierSourceKey::RelinearizationCommonReference {
            schedule_position,
            decomposition_block_index,
            modulus_reference,
        },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 7,
            source_coordinates: vec![
                u64::from(schedule_position),
                u64::from(decomposition_block_index),
                modulus_reference.catalog as u64,
                u64::from(modulus_reference.modulus_index),
            ],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(super) fn galois_common_reference_source(
    ring_degree: u64,
    schedule_position: u32,
    decomposition_block_index: u16,
    modulus_reference: SuiteModulusReference,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    (
        KeyVerifierSourceKey::GaloisCommonReference {
            schedule_position,
            decomposition_block_index,
            modulus_reference,
        },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 8,
            source_coordinates: vec![
                u64::from(schedule_position),
                u64::from(decomposition_block_index),
                modulus_reference.catalog as u64,
                u64::from(modulus_reference.modulus_index),
            ],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(super) fn negacyclic_automorphism_mapping_source(
    ring_degree: u64,
    galois_element: u64,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    (
        KeyVerifierSourceKey::NegacyclicAutomorphismMapping {
            ring_degree,
            galois_element,
        },
        RelationVerifierSource::NegacyclicAutomorphismMapping {
            ring_degree,
            galois_element,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn target_converted_radix_digit_source(
    ring_degree: u64,
    target_role: u16,
    component_ordinal: u16,
    target_modulus_index: u16,
    scale: u64,
    radix: u64,
    digit_ordinal: u16,
    digit_count: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::target(target_modulus_index);
    let key = KeyVerifierSourceKey::TargetConvertedRadixDigit {
        target_role,
        component_ordinal,
        target_modulus_index,
        scale,
        radix,
        digit_ordinal,
        digit_count,
    };
    let source = RelationVerifierSource::Protocol {
        protocol_source_kind: 3,
        source_coordinates: vec![
            u64::from(target_role),
            u64::from(component_ordinal),
            u64::from(target_modulus_index),
        ],
        statement_binding_path: vec![RelationSelectorPathStep::tuple_field(6)],
        value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
    };
    (
        key,
        RelationVerifierSource::RadixDecomposition {
            source: Box::new(source),
            modulus_reference,
            scale,
            radix,
            digit_ordinal,
            digit_count,
        },
    )
}

pub(super) fn target_partial_decryption_radix_digit_source(
    ring_degree: u64,
    target_role: u16,
    target_modulus_index: u16,
    radix: u64,
    digit_ordinal: u16,
    digit_count: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::target(target_modulus_index);
    let key = KeyVerifierSourceKey::TargetPartialDecryptionRadixDigit {
        target_role,
        target_modulus_index,
        radix,
        digit_ordinal,
        digit_count,
    };
    let source = RelationVerifierSource::Protocol {
        protocol_source_kind: 4,
        source_coordinates: vec![u64::from(target_role), u64::from(target_modulus_index)],
        statement_binding_path: vec![RelationSelectorPathStep::tuple_field(
            11_u64 + u64::from(target_role),
        )],
        value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
    };
    (
        key,
        RelationVerifierSource::RadixDecomposition {
            source: Box::new(source),
            modulus_reference,
            scale: 1,
            radix,
            digit_ordinal,
            digit_count,
        },
    )
}

pub(super) fn public_key_common_reference_source(
    ring_degree: u64,
    data_modulus_index: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::data(data_modulus_index);
    (
        KeyVerifierSourceKey::PublicKeyCommonReference { data_modulus_index },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 6,
            source_coordinates: vec![u64::from(data_modulus_index)],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: centered_residue_vector(modulus_reference, ring_degree),
        },
    )
}

fn centered_residue_vector(
    modulus_reference: SuiteModulusReference,
    element_count: u64,
) -> RelationValueLayout {
    RelationValueLayout {
        element_kind: RelationElementKind::Residue,
        residue_modulus: Some(modulus_reference),
        shape: vec![element_count],
        embedding_kind: RelationEmbeddingKind::Centered,
    }
}

fn least_nonnegative_residue_vector(
    modulus_reference: SuiteModulusReference,
    element_count: u64,
) -> RelationValueLayout {
    RelationValueLayout::residue_vector(modulus_reference, element_count)
}

fn canonical_sources(
    sources: Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
) -> Result<
    (
        Vec<RelationVerifierSource>,
        BTreeMap<KeyVerifierSourceKey, u32>,
    ),
    RelationPlanError,
> {
    if sources.is_empty() {
        return Err(RelationPlanError::InvalidSource);
    }
    let mut keyed = sources
        .into_iter()
        .map(|(key, source)| Ok((source.canonical_bytes()?, key, source)))
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if !keyed.windows(2).all(|window| window[0].0 < window[1].0) {
        return Err(RelationPlanError::DuplicateItem);
    }
    let mut ordered_sources = Vec::with_capacity(keyed.len());
    let mut source_ordinals = BTreeMap::new();
    for (ordinal, (_, key, source)) in keyed.into_iter().enumerate() {
        let ordinal = u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        if source_ordinals.insert(key, ordinal).is_some() {
            return Err(RelationPlanError::DuplicateItem);
        }
        ordered_sources.push(source);
    }
    Ok((ordered_sources, source_ordinals))
}

fn fixed_radix_digits(
    mut value: u64,
    count: usize,
    radix: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    if count == 0 || radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut digits = Vec::with_capacity(count);
    for _ in 0..count {
        digits.push(value % radix);
        value /= radix;
    }
    if value != 0 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(digits)
}

fn minimum_unsigned_radix_digit_count(
    maximum: u64,
    radix: u64,
) -> Result<usize, RelationPlanError> {
    if radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut value = maximum;
    let mut count = 1_usize;
    while value >= radix {
        value /= radix;
        count = count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(count)
}

pub(super) fn constant_linear_term(
    column_ordinal: u32,
    column_offset: u64,
    negative: bool,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative,
        column_ordinal,
        column_offset,
        coefficient: RelationIntegerLiftCoefficient::Constant(1),
    }
}

pub(super) fn scaled_constant_linear_term(
    column_ordinal: u32,
    negative: bool,
    coefficient: u64,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative,
        column_ordinal,
        column_offset: 0,
        coefficient: RelationIntegerLiftCoefficient::Constant(coefficient),
    }
}

fn plaintext_scaled_linear_term(
    column_ordinal: u32,
    negative: bool,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative,
        column_ordinal,
        column_offset: 0,
        coefficient: RelationIntegerLiftCoefficient::Modulus {
            modulus_reference: SuiteModulusReference::plaintext(),
            multiplier: 1,
        },
    }
}

fn trustee_quotient_carry_linear_term(
    carry_column_ordinal: u32,
    modulus_reference: SuiteModulusReference,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative: true,
        column_ordinal: carry_column_ordinal,
        column_offset: 0,
        coefficient: RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier: TRUSTEE_QUOTIENT_HIGH_RADIX,
        },
    }
}

pub(super) fn integer_lift_half(
    half_ordinal: usize,
) -> Result<RelationIntegerLiftFullRingHalf, RelationPlanError> {
    match half_ordinal {
        0 => Ok(RelationIntegerLiftFullRingHalf::Low),
        1 => Ok(RelationIntegerLiftFullRingHalf::High),
        _ => Err(RelationPlanError::InvalidConstraint),
    }
}

fn sort_canonical_items<T>(
    items: &mut Vec<T>,
    mut canonical_bytes: impl FnMut(&T) -> Result<Vec<u8>, RelationPlanError>,
) -> Result<(), RelationPlanError> {
    let mut keyed = items
        .drain(..)
        .map(|item| Ok((canonical_bytes(&item)?, item)))
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if keyed.windows(2).any(|window| window[0].0 >= window[1].0) {
        return Err(RelationPlanError::DuplicateItem);
    }
    items.extend(keyed.into_iter().map(|(_, item)| item));
    Ok(())
}

struct IntegerExpressionTerm {
    expression: Vec<RelationExpressionInstruction>,
    negative: bool,
}

fn integer_constant_term(value: u64, negative: bool) -> IntegerExpressionTerm {
    IntegerExpressionTerm {
        expression: vec![RelationExpressionInstruction::BaseFieldConstant(value)],
        negative,
    }
}

fn integer_column_term(column_ordinal: u32, negative: bool) -> IntegerExpressionTerm {
    IntegerExpressionTerm {
        expression: vec![unrotated_column_expression(column_ordinal)],
        negative,
    }
}

fn integer_scaled_column_term(
    column_ordinal: u32,
    multiplier: u64,
    negative: bool,
) -> IntegerExpressionTerm {
    IntegerExpressionTerm {
        expression: vec![
            unrotated_column_expression(column_ordinal),
            RelationExpressionInstruction::BaseFieldConstant(multiplier),
            RelationExpressionInstruction::Multiplication,
        ],
        negative,
    }
}

fn sum_integer_terms(
    terms: Vec<IntegerExpressionTerm>,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut terms = terms.into_iter();
    let first = terms.next().ok_or(RelationPlanError::InvalidConstraint)?;
    let mut expression = first.expression;
    if first.negative {
        expression.push(RelationExpressionInstruction::Negation);
    }
    for term in terms {
        expression.extend(term.expression);
        if term.negative {
            expression.push(RelationExpressionInstruction::Negation);
        }
        expression.push(RelationExpressionInstruction::Addition);
    }
    Ok(expression)
}

impl<'context> KeyRelationPlanBuilder<'context> {
    fn ensure_reversed_vector_bindings(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        vector: &ReversibleShiftedSmallVector,
    ) -> Result<(), RelationPlanError> {
        for half_ordinal in 0..2 {
            let source_column_ordinal = vector.source.coefficients.halves[half_ordinal];
            let reversed_column_ordinal = vector.reversed.halves[half_ordinal];
            let binding_key = (source_column_ordinal, reversed_column_ordinal);
            let already_present = self
                .pending_integer_lift_batches
                .get(&batch_key)
                .is_some_and(|batch| batch.reversed_bindings.contains_key(&binding_key));
            if already_present {
                continue;
            }
            let binding = RelationIntegerLiftReversedColumnBindingDescriptor {
                source_column_ordinal,
                reversed_column_ordinal,
                source_prefix_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                reversed_suffix_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
            };
            if self
                .pending_integer_lift_batches
                .entry(batch_key)
                .or_default()
                .reversed_bindings
                .insert(binding_key, binding)
                .is_some()
            {
                return Err(RelationPlanError::DuplicateItem);
            }
        }
        Ok(())
    }

    pub(super) fn full_ring_product(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        selected_half: RelationIntegerLiftFullRingHalf,
        negative: bool,
        multiplicand: SplitIntegerVector,
        multiplier: &ReversibleShiftedSmallVector,
    ) -> Result<RelationIntegerLiftFullRingNegacyclicProductDescriptor, RelationPlanError> {
        self.ensure_reversed_vector_bindings(batch_key, multiplier)?;
        Ok(RelationIntegerLiftFullRingNegacyclicProductDescriptor {
            negative,
            selected_half,
            multiplicand_low_column_ordinal: multiplicand.halves[0],
            multiplicand_high_column_ordinal: multiplicand.halves[1],
            multiplier_low_column_ordinal: multiplier.source.coefficients.halves[0],
            multiplier_high_column_ordinal: multiplier.source.coefficients.halves[1],
            reversed_multiplier_low_column_ordinal: multiplier.reversed.halves[0],
            reversed_multiplier_high_column_ordinal: multiplier.reversed.halves[1],
            multiplier_low_offset: multiplier.source.offset,
            multiplier_high_offset: multiplier.source.offset,
            multiplicand_low_suffix_evaluation_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            multiplicand_high_suffix_evaluation_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            reversed_multiplier_low_transpose_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            reversed_multiplier_high_transpose_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
        })
    }

    pub(super) fn add_integer_lift_component(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        quotient_column_ordinal: u32,
        mut ordered_linear_terms: Vec<RelationIntegerLiftLinearTermDescriptor>,
        mut ordered_full_ring_negacyclic_products: Vec<
            RelationIntegerLiftFullRingNegacyclicProductDescriptor,
        >,
    ) -> Result<(), RelationPlanError> {
        sort_canonical_items(&mut ordered_linear_terms, |term| term.canonical_bytes())?;
        sort_canonical_items(&mut ordered_full_ring_negacyclic_products, |product| {
            product.canonical_bytes()
        })?;
        let component = RelationIntegerLiftComponentDescriptor {
            quotient_is_negative: true,
            quotient_column_ordinal,
            ordered_linear_terms,
            ordered_convolution_products: Vec::new(),
            ordered_full_ring_negacyclic_products,
            linear_evaluation_column_ordinal: self.push_prover_column(ProofTreePhase::Auxiliary)?,
            product_accumulator_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
        };
        self.pending_integer_lift_batches
            .entry(batch_key)
            .or_default()
            .components
            .push(component);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn add_relinearization_round_one_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        round_one_left: &SplitIntegerVector,
        round_one_right: &SplitIntegerVector,
        common_reference: SplitIntegerVector,
        secret: &ReversibleShiftedSmallVector,
        ephemeral_secret: &ReversibleShiftedSmallVector,
        round_one_left_error: &ShiftedSmallVector,
        round_one_right_error: &ShiftedSmallVector,
        gadget_coefficient: u64,
        left_quotient: TrusteeRadixThreeQuotientWitness,
        right_quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        if secret.source.offset != 0
            || ephemeral_secret.source.offset != 0
            || round_one_left_error.offset != 0
            || round_one_right_error.offset != 0
            || gadget_coefficient >= modulus
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut left_linear_terms = vec![
                constant_linear_term(round_one_left.halves[half_ordinal], 0, false),
                plaintext_scaled_linear_term(
                    round_one_left_error.coefficients.halves[half_ordinal],
                    true,
                ),
                trustee_quotient_carry_linear_term(
                    left_quotient.high_carries[half_ordinal],
                    modulus_reference,
                ),
            ];
            if gadget_coefficient != 0 {
                left_linear_terms.push(scaled_constant_linear_term(
                    secret.source.coefficients.halves[half_ordinal],
                    true,
                    gadget_coefficient,
                ));
            }
            let common_reference_times_ephemeral = self.full_ring_product(
                batch_key,
                selected_half,
                false,
                common_reference,
                ephemeral_secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                left_quotient.low_quotients[half_ordinal],
                left_linear_terms,
                vec![common_reference_times_ephemeral],
            )?;

            let common_reference_times_secret =
                self.full_ring_product(batch_key, selected_half, true, common_reference, secret)?;
            self.add_integer_lift_component(
                batch_key,
                right_quotient.low_quotients[half_ordinal],
                vec![
                    constant_linear_term(round_one_right.halves[half_ordinal], 0, false),
                    plaintext_scaled_linear_term(
                        round_one_right_error.coefficients.halves[half_ordinal],
                        true,
                    ),
                    trustee_quotient_carry_linear_term(
                        right_quotient.high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                vec![common_reference_times_secret],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn add_relinearization_round_two_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        round_two: &SplitIntegerVector,
        aggregate_round_one_left: &ReversibleShiftedSmallVector,
        aggregate_round_one_right: &ReversibleShiftedSmallVector,
        secret: &ReversibleShiftedSmallVector,
        ephemeral_secret: &ReversibleShiftedSmallVector,
        round_two_error: &ShiftedSmallVector,
        quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        let centered_offset = (modulus - 1) / 2;
        if secret.source.offset != 0
            || ephemeral_secret.source.offset != 0
            || round_two_error.offset != 0
            || aggregate_round_one_left.source.offset != centered_offset
            || aggregate_round_one_right.source.offset != centered_offset
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let secret_times_aggregate_left = self.full_ring_product(
                batch_key,
                selected_half,
                true,
                secret.source.coefficients,
                aggregate_round_one_left,
            )?;
            let ephemeral_times_aggregate_right = self.full_ring_product(
                batch_key,
                selected_half,
                true,
                ephemeral_secret.source.coefficients,
                aggregate_round_one_right,
            )?;
            let secret_times_aggregate_right = self.full_ring_product(
                batch_key,
                selected_half,
                false,
                secret.source.coefficients,
                aggregate_round_one_right,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient.low_quotients[half_ordinal],
                vec![
                    constant_linear_term(round_two.halves[half_ordinal], 0, false),
                    plaintext_scaled_linear_term(
                        round_two_error.coefficients.halves[half_ordinal],
                        true,
                    ),
                    trustee_quotient_carry_linear_term(
                        quotient.high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                vec![
                    secret_times_aggregate_left,
                    ephemeral_times_aggregate_right,
                    secret_times_aggregate_right,
                ],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn add_trustee_anchor_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        commitments: &[SplitIntegerVector],
        first_matrix: &[Vec<ReversibleShiftedSmallVector>],
        second_matrix: &[ReversibleShiftedSmallVector],
        opening: &TrusteeAnchorOpeningWitness,
        secret: &ShiftedSmallVector,
        quotients: &[TrusteeRadixThreeQuotientWitness],
    ) -> Result<(), RelationPlanError> {
        let rank = usize::from(self.geometry.commitment_module_rank);
        let centered_offset = (self.modulus(modulus_reference)? - 1) / 2;
        if commitments.len() != rank + 1
            || first_matrix.len() != rank
            || first_matrix.iter().any(|row| row.len() != rank + 1)
            || second_matrix.len() != rank
            || opening.hiding_secrets.len() != rank + 1
            || opening.hiding_errors.len() != rank
            || quotients.len() != rank + 1
            || secret.offset != 0
            || first_matrix
                .iter()
                .flatten()
                .chain(second_matrix)
                .any(|matrix| matrix.source.offset != centered_offset)
            || opening.hiding_errors.iter().any(|value| value.offset != 0)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for row_ordinal in 0..rank {
            for half_ordinal in 0..2 {
                let selected_half = integer_lift_half(half_ordinal)?;
                let mut products = Vec::with_capacity(rank + 1);
                for column_ordinal in 0..=rank {
                    products.push(self.full_ring_product(
                        batch_key,
                        selected_half,
                        true,
                        opening.hiding_secrets[column_ordinal],
                        &first_matrix[row_ordinal][column_ordinal],
                    )?);
                }
                self.add_integer_lift_component(
                    batch_key,
                    quotients[row_ordinal].low_quotients[half_ordinal],
                    vec![
                        constant_linear_term(
                            commitments[row_ordinal].halves[half_ordinal],
                            0,
                            false,
                        ),
                        constant_linear_term(
                            opening.hiding_errors[row_ordinal].coefficients.halves[half_ordinal],
                            0,
                            true,
                        ),
                        trustee_quotient_carry_linear_term(
                            quotients[row_ordinal].high_carries[half_ordinal],
                            modulus_reference,
                        ),
                    ],
                    products,
                )?;
            }
        }

        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut products = Vec::with_capacity(rank);
            for (hiding_secret, second_matrix_column) in
                opening.hiding_secrets.iter().copied().zip(second_matrix)
            {
                products.push(self.full_ring_product(
                    batch_key,
                    selected_half,
                    true,
                    hiding_secret,
                    second_matrix_column,
                )?);
            }
            self.add_integer_lift_component(
                batch_key,
                quotients[rank].low_quotients[half_ordinal],
                vec![
                    constant_linear_term(commitments[rank].halves[half_ordinal], 0, false),
                    constant_linear_term(
                        opening.hiding_secrets[rank].halves[half_ordinal],
                        0,
                        true,
                    ),
                    constant_linear_term(secret.coefficients.halves[half_ordinal], 0, true),
                    trustee_quotient_carry_linear_term(
                        quotients[rank].high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                products,
            )?;
        }
        Ok(())
    }

    pub(super) fn add_anchor_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        inputs: AnchorEquationInputs<'_>,
    ) -> Result<(), RelationPlanError> {
        let AnchorEquationInputs {
            commitments,
            first_matrix,
            second_matrix,
            opening,
            secret,
            quotients,
        } = inputs;
        let rank = usize::from(self.geometry.commitment_module_rank);
        if commitments.len() != rank + 1
            || first_matrix.len() != rank
            || first_matrix.iter().any(|row| row.len() != rank + 1)
            || second_matrix.len() != rank
            || opening.hiding_secrets.len() != rank + 1
            || opening.hiding_errors.len() != rank
            || quotients.rows.len() != rank + 1
            || secret.offset != 1
            || opening
                .hiding_secrets
                .iter()
                .any(|value| value.source.offset != 1)
            || opening.hiding_errors.iter().any(|value| value.offset != 1)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for row_ordinal in 0..rank {
            for half_ordinal in 0..2 {
                let selected_half = integer_lift_half(half_ordinal)?;
                let mut products = Vec::with_capacity(rank + 1);
                for column_ordinal in 0..=rank {
                    products.push(self.full_ring_product(
                        batch_key,
                        selected_half,
                        true,
                        first_matrix[row_ordinal][column_ordinal],
                        &opening.hiding_secrets[column_ordinal],
                    )?);
                }
                self.add_integer_lift_component(
                    batch_key,
                    quotients.rows[row_ordinal][half_ordinal],
                    vec![
                        constant_linear_term(
                            commitments[row_ordinal].halves[half_ordinal],
                            0,
                            false,
                        ),
                        constant_linear_term(
                            opening.hiding_errors[row_ordinal].coefficients.halves[half_ordinal],
                            opening.hiding_errors[row_ordinal].offset,
                            true,
                        ),
                    ],
                    products,
                )?;
            }
        }

        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut products = Vec::with_capacity(rank);
            for (second_matrix_column, hiding_secret) in
                second_matrix.iter().copied().zip(&opening.hiding_secrets)
            {
                products.push(self.full_ring_product(
                    batch_key,
                    selected_half,
                    true,
                    second_matrix_column,
                    hiding_secret,
                )?);
            }
            self.add_integer_lift_component(
                batch_key,
                quotients.rows[rank][half_ordinal],
                vec![
                    constant_linear_term(commitments[rank].halves[half_ordinal], 0, false),
                    constant_linear_term(
                        opening.hiding_secrets[rank].source.coefficients.halves[half_ordinal],
                        opening.hiding_secrets[rank].source.offset,
                        true,
                    ),
                    constant_linear_term(
                        secret.coefficients.halves[half_ordinal],
                        secret.offset,
                        true,
                    ),
                ],
                products,
            )?;
        }
        Ok(())
    }

    pub(super) fn add_public_key_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        inputs: PublicKeyEquationInputs<'_>,
    ) -> Result<(), RelationPlanError> {
        let PublicKeyEquationInputs {
            public_key_share,
            common_reference,
            secret,
            error,
            quotient_columns,
        } = inputs;
        if secret.source.offset != 1 || error.offset != 2 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for (half_ordinal, quotient_column) in quotient_columns.into_iter().enumerate() {
            let product = self.full_ring_product(
                batch_key,
                integer_lift_half(half_ordinal)?,
                false,
                *common_reference,
                secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient_column,
                vec![
                    constant_linear_term(public_key_share.halves[half_ordinal], 0, false),
                    RelationIntegerLiftLinearTermDescriptor {
                        negative: true,
                        column_ordinal: error.coefficients.halves[half_ordinal],
                        column_offset: error.offset,
                        coefficient: RelationIntegerLiftCoefficient::Modulus {
                            modulus_reference: SuiteModulusReference::plaintext(),
                            multiplier: 1,
                        },
                    },
                ],
                vec![product],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn add_galois_key_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        galois_key_share: &SplitIntegerVector,
        common_reference: SplitIntegerVector,
        secret: &ReversibleShiftedSmallVector,
        automorphed_secret: &ShiftedSmallVector,
        error: &ShiftedSmallVector,
        gadget_coefficient: u64,
        quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        if secret.source.offset != 0
            || automorphed_secret.offset != 0
            || error.offset != 0
            || gadget_coefficient >= modulus
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let mut linear_terms = vec![
                constant_linear_term(galois_key_share.halves[half_ordinal], 0, false),
                plaintext_scaled_linear_term(error.coefficients.halves[half_ordinal], true),
                trustee_quotient_carry_linear_term(
                    quotient.high_carries[half_ordinal],
                    modulus_reference,
                ),
            ];
            if gadget_coefficient != 0 {
                linear_terms.push(scaled_constant_linear_term(
                    automorphed_secret.coefficients.halves[half_ordinal],
                    true,
                    gadget_coefficient,
                ));
            }
            let common_reference_times_secret = self.full_ring_product(
                batch_key,
                integer_lift_half(half_ordinal)?,
                false,
                common_reference,
                secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient.low_quotients[half_ordinal],
                linear_terms,
                vec![common_reference_times_secret],
            )?;
        }
        Ok(())
    }

    fn finalize_integer_lift_batches(&mut self) -> Result<(), RelationPlanError> {
        let pending = std::mem::take(&mut self.pending_integer_lift_batches);
        let mut batches = Vec::with_capacity(pending.len());
        for ((modulus_reference, challenge_ordinal), pending_batch) in pending {
            let mut ordered_reversed_column_bindings = pending_batch
                .reversed_bindings
                .into_values()
                .collect::<Vec<_>>();
            sort_canonical_items(&mut ordered_reversed_column_bindings, |binding| {
                binding.canonical_bytes()
            })?;
            let mut ordered_negacyclic_automorphism_permutations =
                pending_batch.negacyclic_automorphism_permutations;
            sort_canonical_items(
                &mut ordered_negacyclic_automorphism_permutations,
                |permutation| permutation.canonical_bytes(),
            )?;
            let mut ordered_components = pending_batch.components;
            sort_canonical_items(&mut ordered_components, |component| {
                component.canonical_bytes()
            })?;
            let batch = RelationIntegerLiftBatchDescriptor {
                modulus_reference,
                challenge_ordinal,
                ordered_reversed_column_bindings,
                ordered_negacyclic_automorphism_permutations,
                ordered_components,
            };
            let modulus_ordinal = self.modulus_ordinal(modulus_reference)?;
            for program in batch.constraint_programs(
                modulus_ordinal,
                self.geometry.trace_domain_size()?,
                self.geometry.evaluation_domain_size,
                self.context,
            )? {
                self.add_constraint(
                    program.numerator_postfix_expression,
                    program.zeroifier_postfix_expression,
                    false,
                )?;
            }
            batches.push(batch);
        }
        sort_canonical_items(&mut batches, |batch| batch.canonical_bytes())?;
        self.ordered_integer_lift_batches = batches;
        Ok(())
    }
}

impl<'context> KeyRelationPlanBuilder<'context> {
    pub(super) fn add_split_verifier_vector(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<SplitIntegerVector, RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let trace_domain_size = self.geometry.trace_domain_size()?;
        let mut halves = Vec::with_capacity(2);
        for half_ordinal in 0..2_u64 {
            halves.push(
                self.push_column(
                    RelationColumnOrigin::VerifierSequence {
                        verifier_source_ordinal: source_ordinal,
                        first_logical_element_index: half_ordinal
                            .checked_mul(trace_domain_size)
                            .ok_or(RelationPlanError::CountOverflow)?,
                        logical_element_stride: 1,
                    },
                    self.geometry
                        .public_polynomial_column_degree_bound_exclusive,
                    Some(modulus_reference),
                    Some(ProofTreePhase::Base),
                )?,
            );
        }
        Ok(SplitIntegerVector {
            halves: halves
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    pub(super) fn add_split_verifier_base_vector(
        &mut self,
        source_key: &KeyVerifierSourceKey,
    ) -> Result<SplitIntegerVector, RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let trace_domain_size = self.geometry.trace_domain_size()?;
        let mut halves = Vec::with_capacity(2);
        for half_ordinal in 0..2_u64 {
            halves.push(
                self.push_column(
                    RelationColumnOrigin::VerifierSequence {
                        verifier_source_ordinal: source_ordinal,
                        first_logical_element_index: half_ordinal
                            .checked_mul(trace_domain_size)
                            .ok_or(RelationPlanError::CountOverflow)?,
                        logical_element_stride: 1,
                    },
                    self.geometry
                        .public_polynomial_column_degree_bound_exclusive,
                    None,
                    Some(ProofTreePhase::Base),
                )?,
            );
        }
        Ok(SplitIntegerVector {
            halves: halves
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    pub(super) fn add_negacyclic_automorphism_permutation(
        &mut self,
        mapping_source_key: &KeyVerifierSourceKey,
        galois_element: u64,
        source: &ReversibleShiftedSmallVector,
        target: &ShiftedSmallVector,
    ) -> Result<(), RelationPlanError> {
        if source.source.offset != 0
            || target.offset != 0
            || source.source.coefficients.halves[0] == source.source.coefficients.halves[1]
            || target.coefficients.halves[0] == target.coefficients.halves[1]
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mapping_source_ordinal = self.source_ordinal(mapping_source_key)?;
        let trace_domain_size = self.geometry.trace_domain_size()?;
        let mut mapping_columns = Vec::with_capacity(6);
        for sequence_ordinal in 0..6_u64 {
            mapping_columns.push(
                self.push_column(
                    RelationColumnOrigin::VerifierSequence {
                        verifier_source_ordinal: mapping_source_ordinal,
                        first_logical_element_index: sequence_ordinal
                            .checked_mul(trace_domain_size)
                            .ok_or(RelationPlanError::CountOverflow)?,
                        logical_element_stride: 1,
                    },
                    trace_domain_size,
                    None,
                    Some(ProofTreePhase::Base),
                )?,
            );
        }
        let mapping_columns: [u32; 6] = mapping_columns
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let challenge_modulus_reference = self
            .ordered_non_native_moduli
            .first()
            .copied()
            .ok_or(RelationPlanError::MissingModulus)?;
        if challenge_modulus_reference != SuiteModulusReference::data(0) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        for challenge_ordinal in 0..self.context.non_native_modular_identity_challenge_count {
            let descriptor = RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor {
                galois_element,
                mapping_verifier_source_ordinal: mapping_source_ordinal,
                source_low_column_ordinal: source.source.coefficients.halves[0],
                source_high_column_ordinal: source.source.coefficients.halves[1],
                target_low_column_ordinal: target.coefficients.halves[0],
                target_high_column_ordinal: target.coefficients.halves[1],
                mapped_low_position_column_ordinal: mapping_columns[0],
                low_negation_bit_column_ordinal: mapping_columns[1],
                mapped_high_position_column_ordinal: mapping_columns[2],
                high_negation_bit_column_ordinal: mapping_columns[3],
                target_low_position_column_ordinal: mapping_columns[4],
                target_high_position_column_ordinal: mapping_columns[5],
                source_product_before_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                source_low_product_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                target_product_before_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                target_low_product_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
            };
            self.pending_integer_lift_batches
                .entry((challenge_modulus_reference, challenge_ordinal))
                .or_default()
                .negacyclic_automorphism_permutations
                .push(descriptor);
        }
        Ok(())
    }

    pub(super) fn add_setup_polynomial_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
        logical_row_count: usize,
        root_use: BoundPolynomialRootUse,
    ) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
        if logical_row_count == 0 {
            return Err(RelationPlanError::InvalidRoot);
        }
        let source_ordinal = self.source_ordinal(source_key)?;
        let mut tree_columns = Vec::with_capacity(
            logical_row_count
                .checked_mul(2)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
        let mut rows = Vec::with_capacity(logical_row_count);
        for _ in 0..logical_row_count {
            let low = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(modulus_reference),
                None,
            )?;
            let high = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(modulus_reference),
                None,
            )?;
            let halves = [low, high];
            tree_columns.extend(halves);
            rows.push(SplitIntegerVector { halves });
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            expected_root_source_ordinal: source_ordinal,
            root_use: match root_use {
                BoundPolynomialRootUse::Input => BoundTreeRootUse::Input,
                BoundPolynomialRootUse::Output => BoundTreeRootUse::Output,
            },
            ordered_column_ordinals: tree_columns,
        });
        Ok(rows)
    }

    pub(super) fn add_setup_polynomial_limb_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        ordered_modulus_references: &[SuiteModulusReference],
        root_use: BoundPolynomialRootUse,
    ) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
        if ordered_modulus_references.is_empty()
            || !strictly_sorted_unique(ordered_modulus_references)
        {
            return Err(RelationPlanError::InvalidRoot);
        }
        let source_ordinal = self.source_ordinal(source_key)?;
        let mut tree_columns = Vec::with_capacity(
            ordered_modulus_references
                .len()
                .checked_mul(2)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
        let mut limbs = Vec::with_capacity(ordered_modulus_references.len());
        for modulus_reference in ordered_modulus_references {
            let low = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(*modulus_reference),
                None,
            )?;
            let high = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(*modulus_reference),
                None,
            )?;
            tree_columns.extend([low, high]);
            limbs.push(SplitIntegerVector {
                halves: [low, high],
            });
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            expected_root_source_ordinal: source_ordinal,
            root_use: match root_use {
                BoundPolynomialRootUse::Input => BoundTreeRootUse::Input,
                BoundPolynomialRootUse::Output => BoundTreeRootUse::Output,
            },
            ordered_column_ordinals: tree_columns,
        });
        Ok(limbs)
    }

    pub(super) fn add_setup_polynomial_rows_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        ordered_row_modulus_references: &[SuiteModulusReference],
        root_use: BoundPolynomialRootUse,
    ) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
        if ordered_row_modulus_references.is_empty() {
            return Err(RelationPlanError::InvalidRoot);
        }
        let source_ordinal = self.source_ordinal(source_key)?;
        let mut tree_columns = Vec::with_capacity(
            ordered_row_modulus_references
                .len()
                .checked_mul(2)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
        let mut rows = Vec::with_capacity(ordered_row_modulus_references.len());
        for modulus_reference in ordered_row_modulus_references {
            self.modulus(*modulus_reference)?;
            let low = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(*modulus_reference),
                None,
            )?;
            let high = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(*modulus_reference),
                None,
            )?;
            tree_columns.extend([low, high]);
            rows.push(SplitIntegerVector {
                halves: [low, high],
            });
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            expected_root_source_ordinal: source_ordinal,
            root_use: match root_use {
                BoundPolynomialRootUse::Input => BoundTreeRootUse::Input,
                BoundPolynomialRootUse::Output => BoundTreeRootUse::Output,
            },
            ordered_column_ordinals: tree_columns,
        });
        Ok(rows)
    }

    pub(super) fn add_committed_material_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<[BoundedUnsignedColumn; 2], RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let modulus = self.modulus(modulus_reference)?;
        let source_degree_bound_exclusive = self
            .geometry
            .material_column_degree_bound_exclusive
            .ok_or(RelationPlanError::InvalidDomain)?;
        let mut bound_columns = Vec::with_capacity(4);
        for _ in 0..4 {
            bound_columns.push(self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                source_degree_bound_exclusive,
                None,
                None,
            )?);
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::CommittedMaterial,
            expected_root_source_ordinal: source_ordinal,
            root_use: BoundTreeRootUse::Input,
            ordered_column_ordinals: bound_columns.clone(),
        });

        let maximum_digits = fixed_radix_digits(modulus - 1, 2, MATERIAL_DIGIT_RADIX)?;
        let mut halves = Vec::with_capacity(2);
        for half_ordinal in 0..2 {
            let low_column = bound_columns[half_ordinal];
            let high_column = bound_columns[2 + half_ordinal];
            let low_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            let high_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            self.certify_unsigned_recomposition(low_column, TRIT_RADIX, &low_trits)?;
            self.certify_unsigned_recomposition(high_column, TRIT_RADIX, &high_trits)?;
            self.add_upper_bound_comparator(
                &[low_column, high_column],
                &maximum_digits,
                ProofTreePhase::Base,
            )?;
            halves.push(BoundedUnsignedColumn {
                target_column_ordinal: low_column,
                ordered_digit_column_ordinals: vec![low_column, high_column],
            });
        }
        halves
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)
    }

    pub(super) fn add_target_committed_material_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<TargetCommittedMaterialVector, RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let modulus = self.modulus(modulus_reference)?;
        let source_degree_bound_exclusive = self
            .geometry
            .material_column_degree_bound_exclusive
            .ok_or(RelationPlanError::InvalidDomain)?;
        let mut bound_columns = Vec::with_capacity(4);
        for _ in 0..4 {
            bound_columns.push(self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                source_degree_bound_exclusive,
                None,
                None,
            )?);
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::CommittedMaterial,
            expected_root_source_ordinal: source_ordinal,
            root_use: BoundTreeRootUse::Input,
            ordered_column_ordinals: bound_columns.clone(),
        });

        let maximum_digits = fixed_radix_digits(modulus - 1, 2, MATERIAL_DIGIT_RADIX)?;
        let mut trits_by_half = Vec::with_capacity(2);
        let mut upper_bound_comparators = Vec::with_capacity(2);
        for half_ordinal in 0..2 {
            let low_column = bound_columns[half_ordinal];
            let high_column = bound_columns[2 + half_ordinal];
            let low_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            let high_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            self.certify_unsigned_recomposition(low_column, TRIT_RADIX, &low_trits)?;
            self.certify_unsigned_recomposition(high_column, TRIT_RADIX, &high_trits)?;
            upper_bound_comparators.push(self.add_upper_bound_comparator(
                &[low_column, high_column],
                &maximum_digits,
                ProofTreePhase::Base,
            )?);
            trits_by_half.push(low_trits.into_iter().chain(high_trits).collect::<Vec<_>>());
        }
        Ok(TargetCommittedMaterialVector {
            bound_columns: bound_columns
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
            trits_by_half: trits_by_half
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
            upper_bound_comparators,
        })
    }

    pub(super) fn add_grouped_trit_limbs(
        &mut self,
        trits_by_half: &[Vec<u32>; 2],
        trits_per_limb: usize,
    ) -> Result<Vec<ReversibleShiftedSmallVector>, RelationPlanError> {
        let split_limbs = self.add_grouped_trit_split_limbs(trits_by_half, trits_per_limb)?;
        split_limbs
            .into_iter()
            .map(|coefficients| {
                Ok(ReversibleShiftedSmallVector {
                    source: ShiftedSmallVector {
                        coefficients,
                        offset: 0,
                    },
                    reversed: SplitIntegerVector {
                        halves: [
                            self.push_prover_column(ProofTreePhase::Base)?,
                            self.push_prover_column(ProofTreePhase::Base)?,
                        ],
                    },
                })
            })
            .collect()
    }

    pub(super) fn add_grouped_trit_split_limbs(
        &mut self,
        trits_by_half: &[Vec<u32>; 2],
        trits_per_limb: usize,
    ) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
        if trits_per_limb == 0
            || trits_by_half[0].is_empty()
            || trits_by_half[0].len() != trits_by_half[1].len()
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let limb_count = trits_by_half[0].len().div_ceil(trits_per_limb);
        let mut limbs = Vec::with_capacity(limb_count);
        for limb_ordinal in 0..limb_count {
            let start = limb_ordinal
                .checked_mul(trits_per_limb)
                .ok_or(RelationPlanError::CountOverflow)?;
            let end = (start + trits_per_limb).min(trits_by_half[0].len());
            let mut halves = [0_u32; 2];
            for half_ordinal in 0..2 {
                halves[half_ordinal] = self.push_prover_column(ProofTreePhase::Base)?;
                self.certify_unsigned_recomposition(
                    halves[half_ordinal],
                    TRIT_RADIX,
                    &trits_by_half[half_ordinal][start..end],
                )?;
            }
            limbs.push(SplitIntegerVector { halves });
        }
        Ok(limbs)
    }

    pub(super) fn add_unsigned_vector_trits(
        &mut self,
        trit_count: usize,
    ) -> Result<[Vec<u32>; 2], RelationPlanError> {
        if trit_count == 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut halves = Vec::with_capacity(2);
        for _ in 0..2 {
            let target = self.push_prover_column(ProofTreePhase::Base)?;
            let trits = self.add_trit_columns(trit_count, ProofTreePhase::Base)?;
            self.certify_unsigned_recomposition(target, TRIT_RADIX, &trits)?;
            halves.push(trits);
        }
        halves
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)
    }

    pub(super) fn add_bounded_unsigned_vector_trits(
        &mut self,
        maximum: u64,
    ) -> Result<TargetBoundedUnsignedVector, RelationPlanError> {
        let maximum_digits = fixed_radix_digits(maximum, 2, MATERIAL_DIGIT_RADIX)?;
        let mut halves = Vec::with_capacity(2);
        let mut digit_columns_by_half = Vec::with_capacity(2);
        let mut upper_bound_comparators = Vec::with_capacity(2);
        for _ in 0..2 {
            let low_digit = self.push_prover_column(ProofTreePhase::Base)?;
            let high_digit = self.push_prover_column(ProofTreePhase::Base)?;
            let low_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            let high_trit_count =
                minimum_unsigned_radix_digit_count(maximum_digits[1], TRIT_RADIX)?;
            let high_trits = self.add_trit_columns(high_trit_count, ProofTreePhase::Base)?;
            self.certify_unsigned_recomposition(low_digit, TRIT_RADIX, &low_trits)?;
            self.certify_unsigned_recomposition(high_digit, TRIT_RADIX, &high_trits)?;
            upper_bound_comparators.push(self.add_upper_bound_comparator(
                &[low_digit, high_digit],
                &maximum_digits,
                ProofTreePhase::Base,
            )?);
            digit_columns_by_half.push([low_digit, high_digit]);
            halves.push(low_trits.into_iter().chain(high_trits).collect::<Vec<_>>());
        }
        Ok(TargetBoundedUnsignedVector {
            digit_columns_by_half: digit_columns_by_half
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
            trits_by_half: halves
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
            upper_bound_comparators,
        })
    }

    pub(super) fn add_centered_split_vector(
        &mut self,
        trit_count: usize,
    ) -> Result<TargetCenteredVector, RelationPlanError> {
        if trit_count == 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let capacity = BigUint::from(TRIT_RADIX)
            .pow(u32::try_from(trit_count).map_err(|_| RelationPlanError::CountOverflow)?);
        let offset = u64::try_from((capacity - BigUint::one()) / BigUint::from(2_u8))
            .map_err(|_| RelationPlanError::IntegerBoundOverflow)?;
        let mut halves = [0_u32; 2];
        let mut trits_by_half = Vec::with_capacity(2);
        for half in &mut halves {
            *half = self.push_prover_column(ProofTreePhase::Base)?;
            let trits = self.add_trit_columns(trit_count, ProofTreePhase::Base)?;
            let offset_magnitude = BigUint::from(offset);
            let expression = radix_recomposition_expression(
                *half,
                TRIT_RADIX,
                Some(&offset_magnitude),
                &trits,
                self.context.base_field_modulus,
            )?;
            let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
            trits_by_half.push(trits.clone());
            self.insert_semantic_cell(
                *half,
                SignedIntegerInterval::new(-i128::from(offset), i128::from(offset)),
                RelationBoundCertificate::ShiftedRadixRecomposition {
                    constraint_ordinal,
                    radix: TRIT_RADIX,
                    offset: offset_magnitude,
                    ordered_digit_column_ordinals: trits,
                },
            )?;
        }
        Ok(TargetCenteredVector {
            value: ShiftedSmallVector {
                coefficients: SplitIntegerVector { halves },
                offset,
            },
            trits_by_half: trits_by_half
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    fn add_fixed_binary_column(&mut self, value: bool) -> Result<u32, RelationPlanError> {
        let column = self.add_binary_column(ProofTreePhase::Base)?;
        let mut equality_expression = vec![unrotated_column_expression(column)];
        if value {
            equality_expression.extend([
                RelationExpressionInstruction::BaseFieldConstant(1),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
            ]);
        }
        self.add_full_trace_constraint(equality_expression, true)?;
        Ok(column)
    }

    pub(super) fn add_zero_column(&mut self) -> Result<u32, RelationPlanError> {
        self.add_fixed_binary_column(false)
    }

    pub(super) fn add_one_column(&mut self) -> Result<u32, RelationPlanError> {
        self.add_fixed_binary_column(true)
    }

    pub(super) fn add_shifted_ternary_vector(
        &mut self,
    ) -> Result<ShiftedSmallVector, RelationPlanError> {
        Ok(ShiftedSmallVector {
            coefficients: SplitIntegerVector {
                halves: [
                    self.add_trit_column(ProofTreePhase::Base)?,
                    self.add_trit_column(ProofTreePhase::Base)?,
                ],
            },
            offset: 1,
        })
    }

    pub(super) fn add_reversible_shifted_ternary_vector(
        &mut self,
    ) -> Result<ReversibleShiftedSmallVector, RelationPlanError> {
        let source = self.add_shifted_ternary_vector()?;
        Ok(ReversibleShiftedSmallVector {
            source,
            reversed: SplitIntegerVector {
                halves: [
                    self.push_prover_column(ProofTreePhase::Base)?,
                    self.push_prover_column(ProofTreePhase::Base)?,
                ],
            },
        })
    }

    pub(super) fn add_signed_ternary_vector(
        &mut self,
    ) -> Result<ShiftedSmallVector, RelationPlanError> {
        let ordered_values = vec![BigInt::from(-1), BigInt::zero(), BigInt::one()];
        Ok(ShiftedSmallVector {
            coefficients: SplitIntegerVector {
                halves: [
                    self.add_finite_integer_set_column(
                        ordered_values.clone(),
                        ProofTreePhase::Base,
                    )?,
                    self.add_finite_integer_set_column(ordered_values, ProofTreePhase::Base)?,
                ],
            },
            offset: 0,
        })
    }

    pub(super) fn add_reversible_signed_ternary_vector(
        &mut self,
    ) -> Result<ReversibleShiftedSmallVector, RelationPlanError> {
        let source = self.add_signed_ternary_vector()?;
        Ok(ReversibleShiftedSmallVector {
            source,
            reversed: SplitIntegerVector {
                halves: [
                    self.push_prover_column(ProofTreePhase::Base)?,
                    self.push_prover_column(ProofTreePhase::Base)?,
                ],
            },
        })
    }

    pub(super) fn add_binary_vector(&mut self) -> Result<[u32; 2], RelationPlanError> {
        Ok([
            self.add_binary_column(ProofTreePhase::Base)?,
            self.add_binary_column(ProofTreePhase::Base)?,
        ])
    }

    pub(super) fn add_shifted_eta_two_vector(
        &mut self,
    ) -> Result<ShiftedSmallVector, RelationPlanError> {
        Ok(ShiftedSmallVector {
            coefficients: SplitIntegerVector {
                halves: [
                    self.add_bounded_unsigned_column(4, ProofTreePhase::Base)?
                        .target_column_ordinal,
                    self.add_bounded_unsigned_column(4, ProofTreePhase::Base)?
                        .target_column_ordinal,
                ],
            },
            offset: 2,
        })
    }

    pub(super) fn add_signed_eta_two_vector(
        &mut self,
    ) -> Result<ShiftedSmallVector, RelationPlanError> {
        let ordered_values = (-2..=2).map(BigInt::from).collect::<Vec<_>>();
        Ok(ShiftedSmallVector {
            coefficients: SplitIntegerVector {
                halves: [
                    self.add_finite_integer_set_column(
                        ordered_values.clone(),
                        ProofTreePhase::Base,
                    )?,
                    self.add_finite_integer_set_column(ordered_values, ProofTreePhase::Base)?,
                ],
            },
            offset: 0,
        })
    }

    pub(super) fn add_recentered_vector(
        &mut self,
        canonical_vector: SplitIntegerVector,
        modulus_reference: SuiteModulusReference,
    ) -> Result<ReversibleShiftedSmallVector, RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        let centered_offset = modulus
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidModulus)?
            / 2;
        let mut shifted_centered_halves = Vec::with_capacity(2);
        let mut reversed_halves = Vec::with_capacity(2);
        for canonical_half in canonical_vector.halves {
            let shifted_centered =
                self.add_canonical_modulus_column(modulus_reference, ProofTreePhase::Base)?;
            let recentering_carry = self.add_binary_column(ProofTreePhase::Base)?;
            let expression = vec![
                unrotated_column_expression(shifted_centered),
                unrotated_column_expression(canonical_half),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
                RelationExpressionInstruction::BaseFieldConstant(centered_offset),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
                unrotated_column_expression(recentering_carry),
                RelationExpressionInstruction::NonNativeModulusConstant {
                    modulus_reference,
                    multiplier: 1,
                },
                RelationExpressionInstruction::Multiplication,
                RelationExpressionInstruction::Addition,
            ];
            self.add_full_trace_constraint(expression, true)?;
            shifted_centered_halves.push(shifted_centered);
            reversed_halves.push(self.push_prover_column(ProofTreePhase::Base)?);
        }
        Ok(ReversibleShiftedSmallVector {
            source: ShiftedSmallVector {
                coefficients: SplitIntegerVector {
                    halves: shifted_centered_halves
                        .try_into()
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
                offset: centered_offset,
            },
            reversed: SplitIntegerVector {
                halves: reversed_halves
                    .try_into()
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            },
        })
    }

    pub(super) fn add_recentered_split_verifier_vector(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<ReversibleShiftedSmallVector, RelationPlanError> {
        let canonical_vector = self.add_split_verifier_vector(source_key, modulus_reference)?;
        self.add_recentered_vector(canonical_vector, modulus_reference)
    }

    pub(super) fn add_anchor_opening_witness(
        &mut self,
    ) -> Result<AnchorOpeningWitness, RelationPlanError> {
        let rank = usize::from(self.geometry.commitment_module_rank);
        let hiding_secrets = (0..=rank)
            .map(|_| self.add_reversible_shifted_ternary_vector())
            .collect::<Result<Vec<_>, _>>()?;
        let hiding_errors = (0..rank)
            .map(|_| self.add_shifted_ternary_vector())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AnchorOpeningWitness {
            hiding_secrets,
            hiding_errors,
        })
    }

    pub(super) fn add_trustee_anchor_opening_witness(
        &mut self,
    ) -> Result<TrusteeAnchorOpeningWitness, RelationPlanError> {
        let rank = usize::from(self.geometry.commitment_module_rank);
        let hiding_secrets = (0..=rank)
            .map(|_| {
                self.add_signed_ternary_vector()
                    .map(|vector| vector.coefficients)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let hiding_errors = (0..rank)
            .map(|_| self.add_signed_ternary_vector())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TrusteeAnchorOpeningWitness {
            hiding_secrets,
            hiding_errors,
        })
    }

    fn add_signed_modular_quotient_column(&mut self) -> Result<u32, RelationPlanError> {
        let target = self.push_prover_column(ProofTreePhase::Base)?;
        let bits = (0..MODULAR_QUOTIENT_BIT_COUNT)
            .map(|_| self.add_binary_column(ProofTreePhase::Base))
            .collect::<Result<Vec<_>, _>>()?;
        let offset = BigUint::one() << (MODULAR_QUOTIENT_BIT_COUNT - 1);
        let expression = radix_recomposition_expression(
            target,
            2,
            Some(&offset),
            &bits,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let maximum = BigInt::from(&offset - BigUint::one());
        self.insert_semantic_cell(
            target,
            SignedIntegerInterval::from_bigints(-BigInt::from(offset.clone()), maximum)?,
            RelationBoundCertificate::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix: 2,
                offset,
                ordered_digit_column_ordinals: bits,
            },
        )?;
        Ok(target)
    }

    fn add_trustee_quotient_low_column(&mut self) -> Result<u32, RelationPlanError> {
        let target = self.push_prover_column(ProofTreePhase::Base)?;
        let trits = self.add_trit_columns(TRUSTEE_QUOTIENT_LOW_TRIT_COUNT, ProofTreePhase::Base)?;
        let radix_power = BigUint::from(TRIT_RADIX).pow(
            u32::try_from(TRUSTEE_QUOTIENT_LOW_TRIT_COUNT)
                .map_err(|_| RelationPlanError::CountOverflow)?,
        );
        let offset = (&radix_power - BigUint::one()) / BigUint::from(2_u8);
        let expression = radix_recomposition_expression(
            target,
            TRIT_RADIX,
            Some(&offset),
            &trits,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let maximum = BigInt::from(&radix_power - BigUint::one()) - BigInt::from(offset.clone());
        self.insert_semantic_cell(
            target,
            SignedIntegerInterval::from_bigints(-BigInt::from(offset.clone()), maximum)?,
            RelationBoundCertificate::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix: TRIT_RADIX,
                offset,
                ordered_digit_column_ordinals: trits,
            },
        )?;
        Ok(target)
    }

    pub(super) fn add_trustee_radix_three_quotient_witness(
        &mut self,
    ) -> Result<TrusteeRadixThreeQuotientWitness, RelationPlanError> {
        let carry_values = (-2..=2).map(BigInt::from).collect::<Vec<_>>();
        Ok(TrusteeRadixThreeQuotientWitness {
            low_quotients: [
                self.add_trustee_quotient_low_column()?,
                self.add_trustee_quotient_low_column()?,
            ],
            high_carries: [
                self.add_finite_integer_set_column(carry_values.clone(), ProofTreePhase::Base)?,
                self.add_finite_integer_set_column(carry_values, ProofTreePhase::Base)?,
            ],
        })
    }

    pub(super) fn add_anchor_quotient_witness(
        &mut self,
    ) -> Result<AnchorQuotientWitness, RelationPlanError> {
        let row_count = usize::from(self.geometry.commitment_module_rank)
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
        let rows = (0..row_count)
            .map(|_| {
                Ok([
                    self.add_signed_modular_quotient_column()?,
                    self.add_signed_modular_quotient_column()?,
                ])
            })
            .collect::<Result<Vec<_>, RelationPlanError>>()?;
        Ok(AnchorQuotientWitness { rows })
    }

    pub(super) fn add_public_key_quotient_witness(
        &mut self,
    ) -> Result<[u32; 2], RelationPlanError> {
        Ok([
            self.add_signed_modular_quotient_column()?,
            self.add_signed_modular_quotient_column()?,
        ])
    }

    pub(super) fn add_material_secret_equality(
        &mut self,
        material: &[BoundedUnsignedColumn; 2],
        secret: &ShiftedSmallVector,
        negative_indicator: &[u32; 2],
        modulus_reference: SuiteModulusReference,
    ) -> Result<(), RelationPlanError> {
        if secret.offset != 1 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        for half_ordinal in 0..2 {
            let material_digits = &material[half_ordinal].ordered_digit_column_ordinals;
            if material_digits.len() != 2 {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let expression = vec![
                unrotated_column_expression(material_digits[0]),
                unrotated_column_expression(material_digits[1]),
                RelationExpressionInstruction::BaseFieldConstant(MATERIAL_DIGIT_RADIX),
                RelationExpressionInstruction::Multiplication,
                RelationExpressionInstruction::Addition,
                unrotated_column_expression(secret.coefficients.halves[half_ordinal]),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
                RelationExpressionInstruction::BaseFieldConstant(1),
                RelationExpressionInstruction::Addition,
                unrotated_column_expression(negative_indicator[half_ordinal]),
                RelationExpressionInstruction::NonNativeModulusConstant {
                    modulus_reference,
                    multiplier: 1,
                },
                RelationExpressionInstruction::Multiplication,
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
            ];
            self.add_full_trace_constraint(expression, true)?;
        }
        Ok(())
    }
}
