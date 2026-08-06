use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
};

use num_bigint::BigUint;

use crate::bgv::setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES};

use super::{
    bounds::{RelationBoundCertificate, RelationConstraintDescriptor, SignedIntegerInterval},
    checking::RelationPlanChecker,
    compiled_plan::RelationPlanCheckContext,
    expressions::strictly_sorted_unique,
    integer_lift::{
        RelationIntegerLiftBatchDescriptor, RelationIntegerLiftComponentDescriptor,
        RelationIntegerLiftLinearTermDescriptor,
        RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
        RelationIntegerLiftReversedColumnBindingDescriptor,
    },
    model::{
        RelationColumnDescriptor, RelationPlanError, RelationTreeDescriptor,
        RelationVerifierSource, SuiteModulusReference,
    },
};

pub(super) const TRIT_RADIX: u64 = 3;
pub(super) const MATERIAL_DIGIT_RADIX: u64 = 129_140_163;
pub(super) const MATERIAL_DIGIT_TRIT_COUNT: usize = 17;
pub(crate) const MODULAR_QUOTIENT_BIT_COUNT: usize = 17;
pub(crate) const MODULAR_QUOTIENT_VALUE_COUNT: u64 = 1_u64 << MODULAR_QUOTIENT_BIT_COUNT;
// The canonical least-nonnegative anchor equation can attain quotient +65,536
// but cannot attain -65,536. Keep all 17-bit values and shift the interval to
// the exact complete range [-65,535, 65,536].
pub(crate) const MODULAR_QUOTIENT_ENCODING_OFFSET: u64 = MODULAR_QUOTIENT_VALUE_COUNT / 2 - 1;
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(crate) const MODULAR_QUOTIENT_MINIMUM: i64 = -(MODULAR_QUOTIENT_ENCODING_OFFSET as i64);
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(crate) const MODULAR_QUOTIENT_MAXIMUM: i64 =
    (MODULAR_QUOTIENT_VALUE_COUNT - MODULAR_QUOTIENT_ENCODING_OFFSET - 1) as i64;
pub(super) const TRUSTEE_QUOTIENT_LOW_TRIT_COUNT: usize = 10;
pub(super) const TRUSTEE_QUOTIENT_HIGH_RADIX: u16 = 59_049;
pub(crate) const TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE: u64 = 147_622;
pub(super) const EXACT_INTEGER_LIFT_RADIX: u64 = TRUSTEE_QUOTIENT_HIGH_RADIX as u64;
pub(super) const EXACT_INTEGER_LIFT_RADIX_TRIT_COUNT: usize = TRUSTEE_QUOTIENT_LOW_TRIT_COUNT;

pub(super) struct ExactRadixDigitColumnCatalog {
    ordered_entries: Box<[(u32, Box<[u32]>)]>,
}

impl ExactRadixDigitColumnCatalog {
    pub(super) fn len(&self) -> usize {
        self.ordered_entries.len()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &(u32, Box<[u32]>)> {
        self.ordered_entries.iter()
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &Box<[u32]>> {
        self.ordered_entries.iter().map(|(_, values)| values)
    }
}

impl FromIterator<(u32, Box<[u32]>)> for ExactRadixDigitColumnCatalog {
    fn from_iter<Entries: IntoIterator<Item = (u32, Box<[u32]>)>>(entries: Entries) -> Self {
        Self {
            ordered_entries: entries.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        }
    }
}

impl<'catalog> IntoIterator for &'catalog ExactRadixDigitColumnCatalog {
    type Item = &'catalog (u32, Box<[u32]>);
    type IntoIter = core::slice::Iter<'catalog, (u32, Box<[u32]>)>;

    fn into_iter(self) -> Self::IntoIter {
        self.ordered_entries.iter()
    }
}

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
        })
    }

    pub(super) fn for_target_release(
        ring_degree: u64,
        evaluation_domain_size: u64,
        opening_degree_bound_exclusive: u64,
        material_column_degree_bound_exclusive: u64,
        public_polynomial_column_degree_bound_exclusive: u64,
        target_modulus_indices: Vec<u16>,
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
        let opening_degree_domain = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .ok_or(RelationPlanError::CountOverflow)?;
        if !self
            .evaluation_domain_size
            .is_multiple_of(opening_degree_domain)
        {
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
    NestedStatementRoot {
        field_ordinal: u64,
        list_ordinal: u64,
        nested_field_ordinal: u64,
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

impl BoundedUnsignedColumn {
    pub(super) fn ordered_digit_column_ordinals(&self) -> &[u32] {
        &self.ordered_digit_column_ordinals
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SplitIntegerVector {
    pub(super) halves: [u32; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ShiftedSmallVector {
    pub(super) coefficients: SplitIntegerVector,
    pub(super) offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ReversibleShiftedSmallVector {
    pub(super) source: ShiftedSmallVector,
}

#[derive(Clone, Debug)]
pub(super) struct AnchorOpeningWitness {
    hiding_secrets: Vec<ReversibleShiftedSmallVector>,
    hiding_errors: Vec<ShiftedSmallVector>,
}

impl AnchorOpeningWitness {
    pub(super) fn hiding_secrets(&self) -> &[ReversibleShiftedSmallVector] {
        &self.hiding_secrets
    }

    pub(super) fn hiding_errors(&self) -> &[ShiftedSmallVector] {
        &self.hiding_errors
    }

    pub(super) fn retained_heap_byte_length(&self) -> Result<u64, RelationPlanError> {
        checked_retained_allocation_sum([
            retained_vector_allocation_byte_length(&self.hiding_secrets),
            retained_vector_allocation_byte_length(&self.hiding_errors),
        ])
    }
}

#[derive(Clone, Debug)]
pub(super) struct AnchorQuotientWitness {
    rows: Vec<[u32; 2]>,
}

impl AnchorQuotientWitness {
    pub(super) fn rows(&self) -> &[[u32; 2]] {
        &self.rows
    }

    pub(super) fn retained_heap_byte_length(&self) -> Result<u64, RelationPlanError> {
        retained_vector_allocation_byte_length(&self.rows)
    }
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
    pub(super) hiding_secrets: Vec<SplitIntegerVector>,
    pub(super) hiding_errors: Vec<ShiftedSmallVector>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TrusteeRadixThreeQuotientWitness {
    pub(super) low_quotients: [u32; 2],
    pub(super) high_carries: [u32; 2],
}

#[derive(Clone, Debug)]
pub(super) struct RecenteredVerifierVectorWitness {
    pub(super) canonical: SplitIntegerVector,
    pub(super) centered: ReversibleShiftedSmallVector,
    pub(super) carry_columns: [u32; 2],
}

#[derive(Clone, Debug)]
pub(super) struct TargetCommittedMaterialVector {
    pub(super) bound_columns: [u32; 4],
    pub(super) trits_by_half: [Vec<u32>; 2],
    pub(super) upper_bound_comparators: Vec<UpperBoundComparatorWitnessLayout>,
}

#[derive(Clone, Debug)]
pub(super) struct TargetBoundedUnsignedVector {
    pub(super) digit_columns_by_half: [Vec<u32>; 2],
    pub(super) trits_by_half: [Vec<u32>; 2],
    pub(super) upper_bound_comparators: Vec<UpperBoundComparatorWitnessLayout>,
}

#[derive(Clone, Debug)]
pub(super) struct TargetCenteredVector {
    pub(super) value: ShiftedSmallVector,
    pub(super) trit_encoding_offset: u64,
    pub(super) trits_by_half: [Vec<u32>; 2],
}

fn retained_vector_allocation_byte_length<Value>(
    values: &Vec<Value>,
) -> Result<u64, RelationPlanError> {
    u64::try_from(values.capacity())
        .ok()
        .and_then(|count| count.checked_mul(size_of::<Value>() as u64))
        .ok_or(RelationPlanError::CountOverflow)
}

fn checked_retained_allocation_sum(
    byte_lengths: impl IntoIterator<Item = Result<u64, RelationPlanError>>,
) -> Result<u64, RelationPlanError> {
    byte_lengths
        .into_iter()
        .try_fold(0_u64, |total, byte_length| {
            total
                .checked_add(byte_length?)
                .ok_or(RelationPlanError::CountOverflow)
        })
}

impl BoundedMaterialDigitWitnessLayout {
    fn retained_heap_byte_length(&self) -> Result<u64, RelationPlanError> {
        retained_vector_allocation_byte_length(&self.trit_column_ordinals)
    }
}

impl UpperBoundComparatorWitnessLayout {
    pub(super) fn retained_heap_byte_length(&self) -> Result<u64, RelationPlanError> {
        checked_retained_allocation_sum(
            [
                retained_vector_allocation_byte_length(&self.difference_digits),
                retained_vector_allocation_byte_length(&self.borrow_column_ordinals),
            ]
            .into_iter()
            .chain(
                self.difference_digits
                    .iter()
                    .map(BoundedMaterialDigitWitnessLayout::retained_heap_byte_length),
            ),
        )
    }
}

impl TargetCommittedMaterialVector {
    pub(super) fn retained_heap_byte_length(&self) -> Result<u64, RelationPlanError> {
        checked_retained_allocation_sum(
            self.trits_by_half
                .iter()
                .map(retained_vector_allocation_byte_length)
                .chain(std::iter::once(retained_vector_allocation_byte_length(
                    &self.upper_bound_comparators,
                )))
                .chain(
                    self.upper_bound_comparators
                        .iter()
                        .map(UpperBoundComparatorWitnessLayout::retained_heap_byte_length),
                ),
        )
    }
}

impl TargetBoundedUnsignedVector {
    pub(super) fn retained_heap_byte_length(&self) -> Result<u64, RelationPlanError> {
        checked_retained_allocation_sum(
            self.digit_columns_by_half
                .iter()
                .chain(&self.trits_by_half)
                .map(retained_vector_allocation_byte_length)
                .chain(std::iter::once(retained_vector_allocation_byte_length(
                    &self.upper_bound_comparators,
                )))
                .chain(
                    self.upper_bound_comparators
                        .iter()
                        .map(UpperBoundComparatorWitnessLayout::retained_heap_byte_length),
                ),
        )
    }
}

impl TargetCenteredVector {
    pub(super) fn retained_heap_byte_length(&self) -> Result<u64, RelationPlanError> {
        checked_retained_allocation_sum(
            self.trits_by_half
                .iter()
                .map(retained_vector_allocation_byte_length),
        )
    }
}

#[derive(Default)]
struct PendingIntegerLiftBatch {
    reversed_bindings: BTreeMap<(u32, u32), RelationIntegerLiftReversedColumnBindingDescriptor>,
    negacyclic_automorphism_permutations:
        Vec<RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor>,
    components: Vec<RelationIntegerLiftComponentDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::bgv::proof_suite::relation_plan) struct PendingFullRingNegacyclicProduct {
    negative: bool,
    selected_half: super::integer_lift::RelationIntegerLiftFullRingHalf,
    multiplicand: SplitIntegerVector,
    multiplier: ReversibleShiftedSmallVector,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FullRingProductAccumulatorDependency {
    negative: bool,
    selected_half: super::integer_lift::RelationIntegerLiftFullRingHalf,
    multiplicand_columns: [u32; 2],
    multiplier_columns: [u32; 2],
    reversed_multiplier_columns: [u32; 2],
    multiplier_offsets: [u64; 2],
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
    exact_radix_digits_by_column: BTreeMap<u32, Vec<u32>>,
    exact_carry_columns_by_component: BTreeMap<
        (
            SuiteModulusReference,
            Vec<RelationIntegerLiftLinearTermDescriptor>,
            Vec<PendingFullRingNegacyclicProduct>,
        ),
        Vec<u32>,
    >,
    full_ring_suffix_columns_by_dependency:
        BTreeMap<((SuiteModulusReference, u16), SplitIntegerVector), [u32; 2]>,
    full_ring_transpose_columns_by_dependency: BTreeMap<
        (
            (SuiteModulusReference, u16),
            super::integer_lift::RelationIntegerLiftFullRingHalf,
            SplitIntegerVector,
        ),
        [u32; 2],
    >,
    linear_evaluation_columns_by_dependency: BTreeMap<
        (
            (SuiteModulusReference, u16),
            Vec<RelationIntegerLiftLinearTermDescriptor>,
        ),
        u32,
    >,
    product_accumulator_columns_by_dependency: BTreeMap<
        (
            (SuiteModulusReference, u16),
            Vec<FullRingProductAccumulatorDependency>,
        ),
        u32,
    >,
    reversed_columns_by_source_halves: BTreeMap<[u32; 2], SplitIntegerVector>,
    bound_trees: Vec<RelationTreeDescriptor>,
    base_tree_columns: Vec<u32>,
    auxiliary_tree_columns: Vec<u32>,
    pending_integer_lift_batches: BTreeMap<(SuiteModulusReference, u16), PendingIntegerLiftBatch>,
    ordered_integer_lift_batches: Vec<RelationIntegerLiftBatchDescriptor>,
    ordered_constraints: Vec<RelationConstraintDescriptor>,
}

impl KeyRelationPlanBuilder<'_> {
    pub(in crate::bgv::proof_suite::relation_plan) fn exact_radix_digits_by_column(
        &self,
    ) -> &BTreeMap<u32, Vec<u32>> {
        &self.exact_radix_digits_by_column
    }
}

mod column_builder;
mod equations;
mod integer_lift;

pub(super) use column_builder::*;
