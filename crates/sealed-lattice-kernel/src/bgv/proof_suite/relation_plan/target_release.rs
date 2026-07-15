use super::key_relation::{
    KeyRelationGeometry, KeyRelationPlanBuilder, KeyVerifierSourceKey, MATERIAL_DIGIT_RADIX,
    ReversibleShiftedSmallVector, ShiftedSmallVector, SplitIntegerVector,
    TargetBoundedUnsignedVector, TargetCenteredVector, TargetCommittedMaterialVector,
    constant_linear_term, integer_lift_half, scaled_constant_linear_term, statement_root_source,
    target_converted_radix_digit_source, target_partial_decryption_radix_digit_source,
};
use super::*;
use crate::bgv::proof_suite::{
    CommittedMaterialTree, CommonProofSourcePolynomial, PROOF_BASE_FIELD_MODULUS,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain, ProofFieldError,
    ProofPolynomialError, VerifiedCommonProof, VerifiedRelationColumnEvaluator,
};

const TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1621;
const MATERIAL_ROOTS_FIELD_ORDINAL: u64 = 10;
const TARGET_ROLE_COUNT: u16 = 2;
const RADIX_TRITS_PER_LIMB: usize = 11;
const RADIX: u64 = 177_147;
const QUOTIENT_DIGIT_TRIT_COUNT: usize = 12;
const CARRY_TRIT_COUNT: usize = 23;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetReleaseCapabilityError {
    WrongApplication,
}

/// Family capability derived by consuming the common verifier's opaque
/// result. Raw proof bytes, roots, and caller-supplied status fields cannot
/// construct this value.
pub(crate) struct VerifiedTargetReleaseProof {
    application_statement_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
}

impl VerifiedTargetReleaseProof {
    pub(crate) fn from_common_proof(
        common_proof: VerifiedCommonProof,
    ) -> Result<Self, TargetReleaseCapabilityError> {
        if common_proof.application_statement_schema_identifier()
            != TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
            || common_proof.schedule_position().is_some()
            || common_proof.top_count().is_some()
        {
            return Err(TargetReleaseCapabilityError::WrongApplication);
        }
        Ok(Self {
            application_statement_hash: common_proof.application_statement_hash(),
            relation_plan_variant_hash: common_proof.relation_plan_variant_hash(),
        })
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }
}

#[derive(Clone, Debug)]
struct TargetReleaseFloodingWitnessLayout {
    bounded_shift: TargetBoundedUnsignedVector,
    grouped_limbs: Vec<SplitIntegerVector>,
}

#[derive(Clone, Debug)]
struct TargetReleaseRoleEquationWitnessLayout {
    scaled_a_digits: Vec<SplitIntegerVector>,
    partial_decryption_digits: Vec<SplitIntegerVector>,
    quotient_digits: Vec<TargetCenteredVector>,
    carry_values: Vec<TargetCenteredVector>,
}

#[derive(Clone, Debug)]
struct TargetReleaseModulusWitnessLayout {
    modulus_reference: SuiteModulusReference,
    modulus: u64,
    material: TargetCommittedMaterialVector,
    share_limbs: Vec<ReversibleShiftedSmallVector>,
    role_equations: Vec<TargetReleaseRoleEquationWitnessLayout>,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledTargetReleaseRelation {
    relation_plan: CompiledRelationPlan,
    ring_degree: usize,
    decryption_scale: u64,
    simulation_scale: u64,
    flooding_bound: u64,
    constant_one_column: u32,
    zero_column: u32,
    flooding_by_role: Vec<TargetReleaseFloodingWitnessLayout>,
    moduli: Vec<TargetReleaseModulusWitnessLayout>,
}

impl CompiledTargetReleaseRelation {
    pub(crate) const fn relation_plan(&self) -> &CompiledRelationPlan {
        &self.relation_plan
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TargetReleaseRoleWitness<'input> {
    /// The converted ciphertext `a` component in least-nonnegative target-prime
    /// residues. The relation applies `decryption_scale` before decomposition.
    pub(crate) converted_a: &'input [u64],
    /// The published, flooded partial decryption in least-nonnegative
    /// target-prime residues.
    pub(crate) partial_decryption: &'input [u64],
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TargetReleaseModulusWitness<'input> {
    pub(crate) committed_share: &'input CommittedMaterialTree,
    pub(crate) threshold_share: &'input [u64],
    pub(crate) roles: [TargetReleaseRoleWitness<'input>; 2],
}

/// Public target inputs rebuilt by the verifier for one target prime. This
/// deliberately excludes the material opening, threshold share, and flooding
/// witness, so a verifier-column evaluator cannot accidentally retain or
/// consult prover-owned secrets.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifiedTargetReleaseModulusInput<'input> {
    pub(crate) roles: [TargetReleaseRoleWitness<'input>; 2],
}

/// Polynomial view of only the plan-owned verifier-sequence columns. It is
/// derived from verified target streams and is the sole target-family adapter
/// consumed by the common verifier.
pub(crate) struct TargetReleaseVerifiedColumnEvaluator {
    columns: BTreeMap<u32, CommonProofSourcePolynomial>,
}

impl VerifiedRelationColumnEvaluator for TargetReleaseVerifiedColumnEvaluator {
    fn evaluate_at_extension_point(
        &mut self,
        column_ordinal: u32,
        point: ProofChallengeExtensionElement,
    ) -> Option<ProofChallengeExtensionElement> {
        self.columns
            .get(&column_ordinal)
            .map(|column| column.evaluate_at(point))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TargetReleaseWitness<'input> {
    pub(crate) flooding_errors_by_role: [&'input [i64]; 2],
    pub(crate) moduli: &'input [TargetReleaseModulusWitness<'input>],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetReleaseWitnessError {
    InvalidWitness,
    CountOverflow,
    IntegerOverflow,
    Relation(RelationPlanError),
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
}

impl From<RelationPlanError> for TargetReleaseWitnessError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<ProofFieldError> for TargetReleaseWitnessError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for TargetReleaseWitnessError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetReleaseRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) material_column_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) target_modulus_indices: Vec<u16>,
    pub(crate) decryption_scale: u64,
    pub(crate) simulation_scale: u64,
    pub(crate) flooding_bound: u64,
    pub(crate) first_mask_purpose: u16,
}

fn minimum_radix_digit_count(maximum: u128) -> Result<usize, RelationPlanError> {
    let mut remaining = maximum;
    let mut count = 1_usize;
    while remaining >= u128::from(RADIX) {
        remaining /= u128::from(RADIX);
        count = count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(count)
}

fn fixed_radix_digits(mut value: u128, count: usize) -> Result<Vec<u64>, RelationPlanError> {
    let mut digits = Vec::with_capacity(count);
    for _ in 0..count {
        digits.push(
            u64::try_from(value % u128::from(RADIX))
                .map_err(|_| RelationPlanError::IntegerBoundOverflow)?,
        );
        value /= u128::from(RADIX);
    }
    if value != 0 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(digits)
}

fn centered_linear_term(
    value: &ShiftedSmallVector,
    half_ordinal: usize,
    coefficient: u64,
    negative: bool,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative,
        column_ordinal: value.coefficients.halves[half_ordinal],
        column_offset: value.offset,
        coefficient: RelationIntegerLiftCoefficient::Constant(coefficient),
    }
}

fn validate_input(
    input: &TargetReleaseRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<Vec<(SuiteModulusReference, u64)>, RelationPlanError> {
    let expected_indices = (0..input.target_modulus_indices.len())
        .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
        .collect::<Result<Vec<_>, _>>()?;
    if input.target_modulus_indices != expected_indices
        || input.decryption_scale == 0
        || input.simulation_scale == 0
        || input.flooding_bound == 0
        || input.flooding_bound.checked_mul(2).is_none()
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    input
        .target_modulus_indices
        .iter()
        .copied()
        .map(|index| {
            let modulus_reference = SuiteModulusReference::target(index);
            let modulus = context.resolved_modulus(modulus_reference)?;
            let scaled_flooding = input
                .flooding_bound
                .checked_mul(input.simulation_scale)
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            if modulus <= input.ring_degree
                || input.flooding_bound >= modulus
                || scaled_flooding >= modulus
                || u128::from(modulus - 1)
                    .checked_mul(u128::from(input.decryption_scale))
                    .is_none()
            {
                return Err(RelationPlanError::InvalidModulus);
            }
            Ok((modulus_reference, modulus))
        })
        .collect()
}

fn target_sources(
    input: &TargetReleaseRelationPlanInput,
    moduli: &[(SuiteModulusReference, u64)],
) -> Result<Vec<(KeyVerifierSourceKey, RelationVerifierSource)>, RelationPlanError> {
    let mut sources = Vec::new();
    for (logical_root_ordinal, (modulus_reference, modulus)) in moduli.iter().copied().enumerate() {
        sources.push(statement_root_source(
            MATERIAL_ROOTS_FIELD_ORDINAL,
            Some(
                u64::try_from(logical_root_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            ),
        ));
        let target_modulus_index = modulus_reference.modulus_index;
        let scaled_a_digit_count = u16::try_from(minimum_radix_digit_count(
            u128::from(modulus - 1) * u128::from(input.decryption_scale),
        )?)
        .map_err(|_| RelationPlanError::CountOverflow)?;
        let partial_decryption_digit_count =
            u16::try_from(minimum_radix_digit_count(u128::from(modulus - 1))?)
                .map_err(|_| RelationPlanError::CountOverflow)?;
        for target_role in 0..TARGET_ROLE_COUNT {
            for digit_ordinal in 0..scaled_a_digit_count {
                sources.push(target_converted_radix_digit_source(
                    input.ring_degree,
                    target_role,
                    1,
                    target_modulus_index,
                    input.decryption_scale,
                    RADIX,
                    digit_ordinal,
                    scaled_a_digit_count,
                ));
            }
            for digit_ordinal in 0..partial_decryption_digit_count {
                sources.push(target_partial_decryption_radix_digit_source(
                    input.ring_degree,
                    target_role,
                    target_modulus_index,
                    RADIX,
                    digit_ordinal,
                    partial_decryption_digit_count,
                ));
            }
        }
    }
    Ok(sources)
}

fn verifier_digit_vectors(
    builder: &mut KeyRelationPlanBuilder<'_>,
    input: &TargetReleaseRelationPlanInput,
    modulus_reference: SuiteModulusReference,
    modulus: u64,
    target_role: u16,
) -> Result<(Vec<SplitIntegerVector>, Vec<SplitIntegerVector>), RelationPlanError> {
    let scaled_a_digit_count = u16::try_from(minimum_radix_digit_count(
        u128::from(modulus - 1) * u128::from(input.decryption_scale),
    )?)
    .map_err(|_| RelationPlanError::CountOverflow)?;
    let partial_decryption_digit_count =
        u16::try_from(minimum_radix_digit_count(u128::from(modulus - 1))?)
            .map_err(|_| RelationPlanError::CountOverflow)?;
    let mut scaled_a_digits = Vec::with_capacity(usize::from(scaled_a_digit_count));
    for digit_ordinal in 0..scaled_a_digit_count {
        scaled_a_digits.push(builder.add_split_verifier_base_vector(
            &KeyVerifierSourceKey::TargetConvertedRadixDigit {
                target_role,
                component_ordinal: 1,
                target_modulus_index: modulus_reference.modulus_index,
                scale: input.decryption_scale,
                radix: RADIX,
                digit_ordinal,
                digit_count: scaled_a_digit_count,
            },
        )?);
    }
    let mut partial_decryption_digits =
        Vec::with_capacity(usize::from(partial_decryption_digit_count));
    for digit_ordinal in 0..partial_decryption_digit_count {
        partial_decryption_digits.push(builder.add_split_verifier_base_vector(
            &KeyVerifierSourceKey::TargetPartialDecryptionRadixDigit {
                target_role,
                target_modulus_index: modulus_reference.modulus_index,
                radix: RADIX,
                digit_ordinal,
                digit_count: partial_decryption_digit_count,
            },
        )?);
    }
    Ok((scaled_a_digits, partial_decryption_digits))
}

#[allow(clippy::too_many_arguments)]
fn add_role_equations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    context: &RelationPlanCheckContext,
    input: &TargetReleaseRelationPlanInput,
    modulus_reference: SuiteModulusReference,
    modulus: u64,
    share_limbs: &[super::key_relation::ReversibleShiftedSmallVector],
    flooding_shift_limbs: &[SplitIntegerVector],
    scaled_a_digits: &[SplitIntegerVector],
    partial_decryption_digits: &[SplitIntegerVector],
    constant_one_column: u32,
    zero_column: u32,
) -> Result<TargetReleaseRoleEquationWitnessLayout, RelationPlanError> {
    let product_layer_count = scaled_a_digits
        .len()
        .checked_add(share_limbs.len())
        .and_then(|count| count.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?;
    let modulus_digits = fixed_radix_digits(
        u128::from(modulus),
        minimum_radix_digit_count(u128::from(modulus))?,
    )?;
    if product_layer_count < modulus_digits.len() {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    let quotient_digit_count = product_layer_count
        .checked_sub(modulus_digits.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(RelationPlanError::CountOverflow)?;
    let maximum_quotient = u128::from(input.decryption_scale)
        .checked_mul(u128::from(input.ring_degree))
        .and_then(|value| value.checked_mul(u128::from(modulus - 1)))
        .and_then(|value| value.checked_add(u128::from(input.simulation_scale)))
        .and_then(|value| value.checked_add(2))
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    let quotient_digit_offset = (3_u128.pow(
        u32::try_from(QUOTIENT_DIGIT_TRIT_COUNT).map_err(|_| RelationPlanError::CountOverflow)?,
    ) - 1)
        / 2;
    let quotient_capacity =
        (0..quotient_digit_count).try_fold(0_u128, |capacity, digit_ordinal| {
            let weight = u128::from(RADIX)
                .checked_pow(
                    u32::try_from(digit_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            capacity
                .checked_add(quotient_digit_offset * weight)
                .ok_or(RelationPlanError::IntegerBoundOverflow)
        })?;
    if quotient_capacity < maximum_quotient {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }

    let quotient_digits = (0..quotient_digit_count)
        .map(|_| builder.add_centered_split_vector(QUOTIENT_DIGIT_TRIT_COUNT))
        .collect::<Result<Vec<_>, _>>()?;
    let carry_values = (0..product_layer_count.saturating_sub(1))
        .map(|_| builder.add_centered_split_vector(CARRY_TRIT_COUNT))
        .collect::<Result<Vec<_>, _>>()?;
    let flooding_constant_digits = fixed_radix_digits(
        u128::from(input.flooding_bound) * u128::from(input.simulation_scale),
        product_layer_count,
    )?;

    for challenge_ordinal in 0..context.non_native_modular_identity_challenge_count {
        let batch_key = (modulus_reference, challenge_ordinal);
        for layer_ordinal in 0..product_layer_count {
            let product_pairs = (0..scaled_a_digits.len())
                .filter_map(|left_digit| {
                    layer_ordinal
                        .checked_sub(left_digit)
                        .filter(|right_digit| *right_digit < share_limbs.len())
                        .map(|right_digit| (left_digit, right_digit))
                })
                .collect::<Vec<_>>();
            if product_pairs.is_empty() {
                return Err(RelationPlanError::InvalidConstraint);
            }
            for half_ordinal in 0..2 {
                let mut linear_terms = Vec::new();
                if let Some(partial_decryption_digit) = partial_decryption_digits.get(layer_ordinal)
                {
                    linear_terms.push(constant_linear_term(
                        partial_decryption_digit.halves[half_ordinal],
                        0,
                        false,
                    ));
                }
                if let Some(flooding_shift_digit) = flooding_shift_limbs.get(layer_ordinal) {
                    linear_terms.push(scaled_constant_linear_term(
                        flooding_shift_digit.halves[half_ordinal],
                        true,
                        input.simulation_scale,
                    ));
                }
                if flooding_constant_digits[layer_ordinal] != 0 {
                    linear_terms.push(scaled_constant_linear_term(
                        constant_one_column,
                        false,
                        flooding_constant_digits[layer_ordinal],
                    ));
                }
                for (modulus_digit_ordinal, modulus_digit) in
                    modulus_digits.iter().copied().enumerate()
                {
                    let Some(quotient_digit_ordinal) =
                        layer_ordinal.checked_sub(modulus_digit_ordinal)
                    else {
                        continue;
                    };
                    if let Some(quotient_digit) = quotient_digits.get(quotient_digit_ordinal) {
                        linear_terms.push(centered_linear_term(
                            &quotient_digit.value,
                            half_ordinal,
                            modulus_digit,
                            true,
                        ));
                    }
                }
                if layer_ordinal > 0 {
                    linear_terms.push(centered_linear_term(
                        &carry_values[layer_ordinal - 1].value,
                        half_ordinal,
                        1,
                        false,
                    ));
                }
                if let Some(next_carry) = carry_values.get(layer_ordinal) {
                    linear_terms.push(centered_linear_term(
                        &next_carry.value,
                        half_ordinal,
                        RADIX,
                        true,
                    ));
                }

                let products = product_pairs
                    .iter()
                    .copied()
                    .map(|(left_digit, right_digit)| {
                        builder.full_ring_product(
                            batch_key,
                            integer_lift_half(half_ordinal)?,
                            true,
                            scaled_a_digits[left_digit],
                            &share_limbs[right_digit],
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                builder.add_integer_lift_component(
                    batch_key,
                    zero_column,
                    linear_terms,
                    products,
                )?;
            }
        }
    }
    Ok(TargetReleaseRoleEquationWitnessLayout {
        scaled_a_digits: scaled_a_digits.to_vec(),
        partial_decryption_digits: partial_decryption_digits.to_vec(),
        quotient_digits,
        carry_values,
    })
}

pub(crate) fn compile_target_release_relation(
    input: &TargetReleaseRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CompiledTargetReleaseRelation, RelationPlanError> {
    let moduli = validate_input(input, context)?;
    let sources = target_sources(input, &moduli)?;
    let geometry = KeyRelationGeometry::for_target_release(
        input.ring_degree,
        input.evaluation_domain_size,
        input.opening_degree_bound_exclusive,
        input.material_column_degree_bound_exclusive,
        input.public_polynomial_column_degree_bound_exclusive,
        input.target_modulus_indices.clone(),
        input.first_mask_purpose,
    );
    let mut builder = KeyRelationPlanBuilder::new(
        TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        context,
        sources,
    )?;
    let constant_one_column = builder.add_one_column()?;
    let zero_column = builder.add_zero_column()?;

    let flooding_shift_maximum = input
        .flooding_bound
        .checked_mul(2)
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    let mut flooding_by_role = Vec::with_capacity(usize::from(TARGET_ROLE_COUNT));
    for _ in 0..TARGET_ROLE_COUNT {
        let bounded_shift = builder.add_bounded_unsigned_vector_trits(flooding_shift_maximum)?;
        let grouped_limbs = builder
            .add_grouped_trit_split_limbs(&bounded_shift.trits_by_half, RADIX_TRITS_PER_LIMB)?;
        flooding_by_role.push(TargetReleaseFloodingWitnessLayout {
            bounded_shift,
            grouped_limbs,
        });
    }

    let mut modulus_layouts = Vec::with_capacity(moduli.len());
    for (logical_root_ordinal, (modulus_reference, modulus)) in moduli.iter().copied().enumerate() {
        let material = builder.add_target_committed_material_root(
            &KeyVerifierSourceKey::StatementRoot {
                field_ordinal: MATERIAL_ROOTS_FIELD_ORDINAL,
                list_ordinal: Some(
                    u64::try_from(logical_root_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                ),
            },
            modulus_reference,
        )?;
        let share_limbs =
            builder.add_grouped_trit_limbs(&material.trits_by_half, RADIX_TRITS_PER_LIMB)?;
        let mut role_equations = Vec::with_capacity(usize::from(TARGET_ROLE_COUNT));
        for target_role in 0..TARGET_ROLE_COUNT {
            let (scaled_a_digits, partial_decryption_digits) = verifier_digit_vectors(
                &mut builder,
                input,
                modulus_reference,
                modulus,
                target_role,
            )?;
            role_equations.push(add_role_equations(
                &mut builder,
                context,
                input,
                modulus_reference,
                modulus,
                &share_limbs,
                &flooding_by_role[usize::from(target_role)].grouped_limbs,
                &scaled_a_digits,
                &partial_decryption_digits,
                constant_one_column,
                zero_column,
            )?);
        }
        modulus_layouts.push(TargetReleaseModulusWitnessLayout {
            modulus_reference,
            modulus,
            material,
            share_limbs,
            role_equations,
        });
    }
    Ok(CompiledTargetReleaseRelation {
        relation_plan: builder.finish()?,
        ring_degree: usize::try_from(input.ring_degree)
            .map_err(|_| RelationPlanError::CountOverflow)?,
        decryption_scale: input.decryption_scale,
        simulation_scale: input.simulation_scale,
        flooding_bound: input.flooding_bound,
        constant_one_column,
        zero_column,
        flooding_by_role,
        moduli: modulus_layouts,
    })
}

pub(crate) fn compile_target_release_relation_plan(
    input: &TargetReleaseRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    Ok(compile_target_release_relation(input, context)?.relation_plan)
}

fn insert_source_polynomial(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    column_ordinal: u32,
    polynomial: CommonProofSourcePolynomial,
) -> Result<(), TargetReleaseWitnessError> {
    if columns.insert(column_ordinal, polynomial).is_some() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(())
}

fn signed_base_field_element(
    value: i128,
) -> Result<ProofBaseFieldElement, TargetReleaseWitnessError> {
    let canonical = if value >= 0 {
        u64::try_from(value).map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?
    } else {
        let magnitude = u64::try_from(
            value
                .checked_abs()
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?,
        )
        .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)?;
        if magnitude >= PROOF_BASE_FIELD_MODULUS {
            return Err(TargetReleaseWitnessError::IntegerOverflow);
        }
        PROOF_BASE_FIELD_MODULUS - magnitude
    };
    Ok(ProofBaseFieldElement::from_canonical(canonical)?)
}

fn interpolate_unsigned_rows(
    trace_domain: ProofEvaluationDomain,
    rows: &[u64],
) -> Result<CommonProofSourcePolynomial, TargetReleaseWitnessError> {
    let rows = rows
        .iter()
        .copied()
        .map(ProofBaseFieldElement::from_canonical)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CommonProofSourcePolynomial::Base(
        trace_domain.interpolate_base_polynomial(&rows)?,
    ))
}

fn interpolate_signed_rows(
    trace_domain: ProofEvaluationDomain,
    rows: &[i128],
) -> Result<CommonProofSourcePolynomial, TargetReleaseWitnessError> {
    let rows = rows
        .iter()
        .copied()
        .map(signed_base_field_element)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CommonProofSourcePolynomial::Base(
        trace_domain.interpolate_base_polynomial(&rows)?,
    ))
}

fn insert_unsigned_half_column(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    column_ordinal: u32,
    rows: &[u64],
) -> Result<(), TargetReleaseWitnessError> {
    if rows.len() != trace_domain.size() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    insert_source_polynomial(
        columns,
        column_ordinal,
        interpolate_unsigned_rows(trace_domain, rows)?,
    )
}

fn insert_signed_half_column(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    column_ordinal: u32,
    rows: &[i128],
) -> Result<(), TargetReleaseWitnessError> {
    if rows.len() != trace_domain.size() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    insert_source_polynomial(
        columns,
        column_ordinal,
        interpolate_signed_rows(trace_domain, rows)?,
    )
}

fn insert_unsigned_ring_vector(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layout: SplitIntegerVector,
    values: &[u64],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len()
        != trace_domain
            .size()
            .checked_mul(2)
            .ok_or(TargetReleaseWitnessError::CountOverflow)?
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    for (half_ordinal, column_ordinal) in layout.halves.iter().copied().enumerate() {
        let start = half_ordinal
            .checked_mul(trace_domain.size())
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        insert_unsigned_half_column(
            columns,
            trace_domain,
            column_ordinal,
            &values[start..start + trace_domain.size()],
        )?;
    }
    Ok(())
}

fn insert_signed_ring_vector(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layout: SplitIntegerVector,
    values: &[i128],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len()
        != trace_domain
            .size()
            .checked_mul(2)
            .ok_or(TargetReleaseWitnessError::CountOverflow)?
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    for (half_ordinal, column_ordinal) in layout.halves.iter().copied().enumerate() {
        let start = half_ordinal
            .checked_mul(trace_domain.size())
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        insert_signed_half_column(
            columns,
            trace_domain,
            column_ordinal,
            &values[start..start + trace_domain.size()],
        )?;
    }
    Ok(())
}

fn unsigned_radix_layers(
    values: &[u64],
    radix: u64,
    layer_count: usize,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    if radix < 2 || layer_count == 0 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut remaining = values.to_vec();
    let mut layers = vec![vec![0_u64; values.len()]; layer_count];
    for layer in &mut layers {
        for (digit, value) in layer.iter_mut().zip(&mut remaining) {
            *digit = *value % radix;
            *value /= radix;
        }
    }
    if remaining.iter().any(|value| *value != 0) {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(layers)
}

fn scaled_residue_radix_layers(
    values: &[u64],
    modulus: u64,
    scale: u64,
    radix: u64,
    layer_count: usize,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    let digit_count =
        u16::try_from(layer_count).map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
    (0..digit_count)
        .map(|digit_ordinal| {
            radix_decompose_scaled_residues(
                values,
                modulus,
                scale,
                radix,
                digit_ordinal,
                digit_count,
            )
            .map_err(TargetReleaseWitnessError::from)
        })
        .collect()
}

fn insert_split_radix_layers(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layouts: &[SplitIntegerVector],
    layers: &[Vec<u64>],
) -> Result<(), TargetReleaseWitnessError> {
    if layouts.len() != layers.len() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    for (layout, values) in layouts.iter().copied().zip(layers) {
        insert_unsigned_ring_vector(columns, trace_domain, layout, values)?;
    }
    Ok(())
}

fn insert_half_trit_columns(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    column_ordinals: &[u32],
    values: &[u64],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len() != trace_domain.size() || column_ordinals.is_empty() {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut remaining = values.to_vec();
    for column_ordinal in column_ordinals {
        let mut rows = Vec::with_capacity(values.len());
        for value in &mut remaining {
            rows.push(*value % 3);
            *value /= 3;
        }
        insert_unsigned_half_column(columns, trace_domain, *column_ordinal, &rows)?;
    }
    if remaining.iter().any(|value| *value != 0) {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(())
}

fn insert_upper_bound_comparator(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layout: &super::key_relation::UpperBoundComparatorWitnessLayout,
    value_digit_layers: &[Vec<u64>],
    maximum_digits: &[u64],
    half_ordinal: usize,
) -> Result<(), TargetReleaseWitnessError> {
    if layout.difference_digits.len() != value_digit_layers.len()
        || value_digit_layers.len() != maximum_digits.len()
        || layout.borrow_column_ordinals.len() + 1 != value_digit_layers.len()
        || half_ordinal >= 2
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let half_start = half_ordinal
        .checked_mul(trace_domain.size())
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    let half_end = half_start
        .checked_add(trace_domain.size())
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    if value_digit_layers
        .iter()
        .any(|layer| layer.len() != trace_domain.size() * 2)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut previous_borrow = vec![0_u64; trace_domain.size()];
    for digit_ordinal in 0..value_digit_layers.len() {
        let value_rows = &value_digit_layers[digit_ordinal][half_start..half_end];
        let mut difference_rows = Vec::with_capacity(trace_domain.size());
        let mut next_borrow = vec![0_u64; trace_domain.size()];
        for row_ordinal in 0..trace_domain.size() {
            let raw_difference = i128::from(maximum_digits[digit_ordinal])
                - i128::from(value_rows[row_ordinal])
                - i128::from(previous_borrow[row_ordinal]);
            let borrow = u64::from(raw_difference < 0);
            if digit_ordinal + 1 == value_digit_layers.len() && borrow != 0 {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            let difference = raw_difference
                .checked_add(i128::from(MATERIAL_DIGIT_RADIX) * i128::from(borrow))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            difference_rows.push(
                u64::try_from(difference).map_err(|_| TargetReleaseWitnessError::InvalidWitness)?,
            );
            next_borrow[row_ordinal] = borrow;
        }
        let difference_layout = &layout.difference_digits[digit_ordinal];
        insert_unsigned_half_column(
            columns,
            trace_domain,
            difference_layout.target_column_ordinal,
            &difference_rows,
        )?;
        insert_half_trit_columns(
            columns,
            trace_domain,
            &difference_layout.trit_column_ordinals,
            &difference_rows,
        )?;
        if let Some(borrow_column_ordinal) = layout.borrow_column_ordinals.get(digit_ordinal) {
            insert_unsigned_half_column(
                columns,
                trace_domain,
                *borrow_column_ordinal,
                &next_borrow,
            )?;
        }
        previous_borrow = next_borrow;
    }
    Ok(())
}

fn insert_bounded_unsigned_vector(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetBoundedUnsignedVector,
    values: &[u64],
    maximum: u64,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    if values.len() != trace_domain.size() * 2
        || values.iter().any(|value| *value > maximum)
        || layout.upper_bound_comparators.len() != 2
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let digit_layers = unsigned_radix_layers(values, MATERIAL_DIGIT_RADIX, 2)?;
    let maximum_digits = fixed_radix_digits(u128::from(maximum), 2)?;
    for half_ordinal in 0..2 {
        for digit_ordinal in 0..2 {
            let half_start = half_ordinal * trace_domain.size();
            insert_unsigned_half_column(
                columns,
                trace_domain,
                layout.digit_columns_by_half[half_ordinal][digit_ordinal],
                &digit_layers[digit_ordinal][half_start..half_start + trace_domain.size()],
            )?;
        }
        let half_start = half_ordinal * trace_domain.size();
        insert_half_trit_columns(
            columns,
            trace_domain,
            &layout.trits_by_half[half_ordinal],
            &values[half_start..half_start + trace_domain.size()],
        )?;
        insert_upper_bound_comparator(
            columns,
            trace_domain,
            &layout.upper_bound_comparators[half_ordinal],
            &digit_layers,
            &maximum_digits,
            half_ordinal,
        )?;
    }
    Ok(digit_layers)
}

fn insert_centered_vector(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetCenteredVector,
    values: &[i128],
) -> Result<(), TargetReleaseWitnessError> {
    if values.len() != trace_domain.size() * 2 || layout.trits_by_half.len() != 2 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let offset = i128::from(layout.value.offset);
    if values
        .iter()
        .any(|value| *value < -offset || *value > offset)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    insert_signed_ring_vector(columns, trace_domain, layout.value.coefficients, values)?;
    for half_ordinal in 0..2 {
        let start = half_ordinal * trace_domain.size();
        let encoded = values[start..start + trace_domain.size()]
            .iter()
            .map(|value| {
                u64::try_from(*value + offset)
                    .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        insert_half_trit_columns(
            columns,
            trace_domain,
            &layout.trits_by_half[half_ordinal],
            &encoded,
        )?;
    }
    Ok(())
}

fn insert_committed_share_columns(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetCommittedMaterialVector,
    tree: &CommittedMaterialTree,
    share: &[u64],
    modulus: u64,
) -> Result<Vec<Vec<u64>>, TargetReleaseWitnessError> {
    if share.len() != trace_domain.size() * 2
        || share.iter().any(|value| *value >= modulus)
        || tree.profile().trace_domain_size() != trace_domain.size()
        || tree.masked_coefficients_by_physical_column().len() != 4
        || layout.upper_bound_comparators.len() != 2
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let digit_layers = unsigned_radix_layers(share, MATERIAL_DIGIT_RADIX, 2)?;
    let maximum_digits = fixed_radix_digits(u128::from(modulus - 1), 2)?;
    for (physical_ordinal, column_ordinal) in layout.bound_columns.iter().copied().enumerate() {
        let digit_ordinal = physical_ordinal / 2;
        let half_ordinal = physical_ordinal % 2;
        let masked_coefficients = tree
            .masked_coefficients_by_physical_column()
            .get(physical_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let trace_values = trace_domain.evaluate_base_polynomial(masked_coefficients)?;
        let start = half_ordinal * trace_domain.size();
        if trace_values
            .iter()
            .zip(&digit_layers[digit_ordinal][start..start + trace_domain.size()])
            .any(|(actual, expected)| actual.canonical() != *expected)
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        insert_source_polynomial(
            columns,
            column_ordinal,
            CommonProofSourcePolynomial::Base(masked_coefficients.clone()),
        )?;
    }
    for half_ordinal in 0..2 {
        let start = half_ordinal * trace_domain.size();
        insert_half_trit_columns(
            columns,
            trace_domain,
            &layout.trits_by_half[half_ordinal],
            &share[start..start + trace_domain.size()],
        )?;
        insert_upper_bound_comparator(
            columns,
            trace_domain,
            &layout.upper_bound_comparators[half_ordinal],
            &digit_layers,
            &maximum_digits,
            half_ordinal,
        )?;
    }
    Ok(digit_layers)
}

struct RadixLayerTransform {
    coefficient_count: usize,
    evaluation_domain: ProofEvaluationDomain,
    evaluations: Vec<Vec<ProofBaseFieldElement>>,
}

impl RadixLayerTransform {
    fn new(layers: &[Vec<u64>]) -> Result<Self, TargetReleaseWitnessError> {
        let coefficient_count = layers
            .first()
            .map(Vec::len)
            .filter(|count| *count >= 2 && count.is_power_of_two())
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        if layers.is_empty()
            || layers.iter().any(|layer| {
                layer.len() != coefficient_count || layer.iter().any(|value| *value >= RADIX)
            })
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let evaluation_domain = ProofEvaluationDomain::new_subgroup(
            coefficient_count
                .checked_mul(2)
                .ok_or(TargetReleaseWitnessError::CountOverflow)?,
        )?;
        let evaluations = layers
            .iter()
            .map(|layer| {
                let coefficients = layer
                    .iter()
                    .copied()
                    .map(ProofBaseFieldElement::from_canonical)
                    .collect::<Result<Vec<_>, _>>()?;
                evaluation_domain
                    .evaluate_base_polynomial(&coefficients)
                    .map_err(TargetReleaseWitnessError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            coefficient_count,
            evaluation_domain,
            evaluations,
        })
    }

    fn multiply_left_layers(
        &self,
        left_layers: &[Vec<u64>],
    ) -> Result<Vec<Vec<i128>>, TargetReleaseWitnessError> {
        if left_layers.is_empty()
            || left_layers.iter().any(|layer| {
                layer.len() != self.coefficient_count || layer.iter().any(|value| *value >= RADIX)
            })
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let layer_count = left_layers
            .len()
            .checked_add(self.evaluations.len())
            .and_then(|count| count.checked_sub(1))
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        let maximum_ordinary_coefficient = u128::try_from(self.coefficient_count)
            .map_err(|_| TargetReleaseWitnessError::CountOverflow)?
            .checked_mul(u128::from(RADIX - 1).pow(2))
            .and_then(|value| {
                value.checked_mul(
                    u128::try_from(left_layers.len().min(self.evaluations.len())).ok()?,
                )
            })
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
        if maximum_ordinary_coefficient >= u128::from(PROOF_BASE_FIELD_MODULUS / 2) {
            return Err(TargetReleaseWitnessError::IntegerOverflow);
        }
        let mut product_evaluations =
            vec![vec![ProofBaseFieldElement::ZERO; self.evaluation_domain.size()]; layer_count];
        for (left_ordinal, left_layer) in left_layers.iter().enumerate() {
            let left_coefficients = left_layer
                .iter()
                .copied()
                .map(ProofBaseFieldElement::from_canonical)
                .collect::<Result<Vec<_>, _>>()?;
            let left_evaluations = self
                .evaluation_domain
                .evaluate_base_polynomial(&left_coefficients)?;
            for (right_ordinal, right_evaluations) in self.evaluations.iter().enumerate() {
                let output = &mut product_evaluations[left_ordinal + right_ordinal];
                for ((destination, left), right) in output
                    .iter_mut()
                    .zip(&left_evaluations)
                    .zip(right_evaluations)
                {
                    *destination = destination.add(left.multiply(*right));
                }
            }
        }
        let mut product_layers = Vec::with_capacity(layer_count);
        for evaluations in product_evaluations {
            let coefficients = self
                .evaluation_domain
                .interpolate_base_polynomial(&evaluations)?;
            let mut folded = Vec::with_capacity(self.coefficient_count);
            for coefficient_ordinal in 0..self.coefficient_count {
                let low = coefficients
                    .get(coefficient_ordinal)
                    .copied()
                    .unwrap_or(ProofBaseFieldElement::ZERO)
                    .canonical();
                let high = coefficients
                    .get(coefficient_ordinal + self.coefficient_count)
                    .copied()
                    .unwrap_or(ProofBaseFieldElement::ZERO)
                    .canonical();
                if u128::from(low) > maximum_ordinary_coefficient
                    || u128::from(high) > maximum_ordinary_coefficient
                {
                    return Err(TargetReleaseWitnessError::IntegerOverflow);
                }
                folded.push(i128::from(low) - i128::from(high));
            }
            product_layers.push(folded);
        }
        Ok(product_layers)
    }
}

fn balanced_radix_layers(
    values: &[i128],
    radix: u64,
    layer_count: usize,
) -> Result<Vec<Vec<i128>>, TargetReleaseWitnessError> {
    if radix < 3 || radix.is_multiple_of(2) || layer_count == 0 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let mut remaining = values.to_vec();
    let mut layers = vec![vec![0_i128; values.len()]; layer_count];
    let radix = i128::from(radix);
    for layer in &mut layers {
        for (digit, value) in layer.iter_mut().zip(&mut remaining) {
            let residue = value.rem_euclid(radix);
            *digit = if residue > radix / 2 {
                residue - radix
            } else {
                residue
            };
            *value = value
                .checked_sub(*digit)
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?
                / radix;
        }
    }
    if remaining.iter().any(|value| *value != 0) {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    Ok(layers)
}

fn checked_product_value(
    product_layers: &[Vec<i128>],
    coefficient_ordinal: usize,
) -> Result<i128, TargetReleaseWitnessError> {
    product_layers
        .iter()
        .rev()
        .try_fold(0_i128, |value, layer| {
            value
                .checked_mul(i128::from(RADIX))
                .and_then(|value| value.checked_add(layer[coefficient_ordinal]))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)
        })
}

#[allow(clippy::too_many_arguments)]
fn insert_role_equation_columns(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetReleaseRoleEquationWitnessLayout,
    role: TargetReleaseRoleWitness<'_>,
    share_transform: &RadixLayerTransform,
    flooding_error: &[i64],
    flooding_shift_layers: &[Vec<u64>],
    modulus: u64,
    decryption_scale: u64,
    simulation_scale: u64,
    flooding_bound: u64,
) -> Result<(), TargetReleaseWitnessError> {
    let (scaled_a_layers, partial_decryption_layers) = insert_role_verifier_columns(
        columns,
        trace_domain,
        layout,
        role,
        modulus,
        decryption_scale,
    )?;
    let ring_degree = trace_domain
        .size()
        .checked_mul(2)
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    if flooding_error.len() != ring_degree {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }

    let product_layers = share_transform.multiply_left_layers(&scaled_a_layers)?;
    let quotient_values = (0..ring_degree)
        .map(|coefficient_ordinal| {
            let product = checked_product_value(&product_layers, coefficient_ordinal)?;
            let flooding_term = i128::from(simulation_scale)
                .checked_mul(i128::from(flooding_error[coefficient_ordinal]))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            let residual = i128::from(role.partial_decryption[coefficient_ordinal])
                .checked_sub(product)
                .and_then(|value| value.checked_sub(flooding_term))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            if residual.rem_euclid(i128::from(modulus)) != 0 {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            Ok(residual / i128::from(modulus))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let quotient_layers =
        balanced_radix_layers(&quotient_values, RADIX, layout.quotient_digits.len())?;
    for (digit_layout, values) in layout.quotient_digits.iter().zip(&quotient_layers) {
        insert_centered_vector(columns, trace_domain, digit_layout, values)?;
    }

    let modulus_digits = fixed_radix_digits(
        u128::from(modulus),
        minimum_radix_digit_count(u128::from(modulus))?,
    )?;
    let flooding_constant_digits = fixed_radix_digits(
        u128::from(flooding_bound) * u128::from(simulation_scale),
        product_layers.len(),
    )?;
    let mut carry_layers = vec![vec![0_i128; ring_degree]; layout.carry_values.len()];
    let mut previous_carry = vec![0_i128; ring_degree];
    for layer_ordinal in 0..product_layers.len() {
        let mut next_carry = vec![0_i128; ring_degree];
        for coefficient_ordinal in 0..ring_degree {
            let mut numerator = i128::from(
                partial_decryption_layers
                    .get(layer_ordinal)
                    .map_or(0, |layer| layer[coefficient_ordinal]),
            )
            .checked_sub(product_layers[layer_ordinal][coefficient_ordinal])
            .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            let shifted_flooding = flooding_shift_layers
                .get(layer_ordinal)
                .map_or(0, |layer| layer[coefficient_ordinal]);
            numerator = numerator
                .checked_sub(
                    i128::from(simulation_scale)
                        .checked_mul(i128::from(shifted_flooding))
                        .ok_or(TargetReleaseWitnessError::IntegerOverflow)?,
                )
                .and_then(|value| {
                    value.checked_add(i128::from(flooding_constant_digits[layer_ordinal]))
                })
                .and_then(|value| value.checked_add(previous_carry[coefficient_ordinal]))
                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
            for (modulus_digit_ordinal, modulus_digit) in modulus_digits.iter().enumerate() {
                let Some(quotient_digit_ordinal) = layer_ordinal.checked_sub(modulus_digit_ordinal)
                else {
                    continue;
                };
                if let Some(quotient_layer) = quotient_layers.get(quotient_digit_ordinal) {
                    numerator = numerator
                        .checked_sub(
                            i128::from(*modulus_digit)
                                .checked_mul(quotient_layer[coefficient_ordinal])
                                .ok_or(TargetReleaseWitnessError::IntegerOverflow)?,
                        )
                        .ok_or(TargetReleaseWitnessError::IntegerOverflow)?;
                }
            }
            if layer_ordinal + 1 == product_layers.len() {
                if numerator != 0 {
                    return Err(TargetReleaseWitnessError::InvalidWitness);
                }
            } else {
                if numerator.rem_euclid(i128::from(RADIX)) != 0 {
                    return Err(TargetReleaseWitnessError::InvalidWitness);
                }
                next_carry[coefficient_ordinal] = numerator / i128::from(RADIX);
            }
        }
        if let Some(destination) = carry_layers.get_mut(layer_ordinal) {
            *destination = next_carry.clone();
        }
        previous_carry = next_carry;
    }
    for (carry_layout, values) in layout.carry_values.iter().zip(&carry_layers) {
        insert_centered_vector(columns, trace_domain, carry_layout, values)?;
    }
    Ok(())
}

fn insert_role_verifier_columns(
    columns: &mut BTreeMap<u32, CommonProofSourcePolynomial>,
    trace_domain: ProofEvaluationDomain,
    layout: &TargetReleaseRoleEquationWitnessLayout,
    role: TargetReleaseRoleWitness<'_>,
    modulus: u64,
    decryption_scale: u64,
) -> Result<(Vec<Vec<u64>>, Vec<Vec<u64>>), TargetReleaseWitnessError> {
    let ring_degree = trace_domain
        .size()
        .checked_mul(2)
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    if role.converted_a.len() != ring_degree
        || role.partial_decryption.len() != ring_degree
        || role.converted_a.iter().any(|value| *value >= modulus)
        || role
            .partial_decryption
            .iter()
            .any(|value| *value >= modulus)
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let scaled_a_layers = scaled_residue_radix_layers(
        role.converted_a,
        modulus,
        decryption_scale,
        RADIX,
        layout.scaled_a_digits.len(),
    )?;
    let partial_decryption_layers = scaled_residue_radix_layers(
        role.partial_decryption,
        modulus,
        1,
        RADIX,
        layout.partial_decryption_digits.len(),
    )?;
    insert_split_radix_layers(
        columns,
        trace_domain,
        &layout.scaled_a_digits,
        &scaled_a_layers,
    )?;
    insert_split_radix_layers(
        columns,
        trace_domain,
        &layout.partial_decryption_digits,
        &partial_decryption_layers,
    )?;
    Ok((scaled_a_layers, partial_decryption_layers))
}

impl CompiledTargetReleaseRelation {
    /// Materializes every genuine pre-challenge column from the typed target
    /// witness. Reversed and challenge-dependent auxiliary columns are omitted
    /// deliberately; the common prover derives those from the checked plan.
    pub(crate) fn provided_pre_challenge_columns(
        &self,
        witness: TargetReleaseWitness<'_>,
    ) -> Result<BTreeMap<u32, CommonProofSourcePolynomial>, TargetReleaseWitnessError> {
        if witness.moduli.len() != self.moduli.len()
            || self.flooding_by_role.len() != usize::from(TARGET_ROLE_COUNT)
            || self.ring_degree < 2
            || !self.ring_degree.is_power_of_two()
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(self.ring_degree / 2)?;
        let mut columns = BTreeMap::new();
        insert_source_polynomial(
            &mut columns,
            self.constant_one_column,
            CommonProofSourcePolynomial::Base(vec![ProofBaseFieldElement::ONE]),
        )?;
        insert_source_polynomial(
            &mut columns,
            self.zero_column,
            CommonProofSourcePolynomial::Base(vec![ProofBaseFieldElement::ZERO]),
        )?;

        let mut flooding_shift_layers_by_role = Vec::with_capacity(2);
        for role_ordinal in 0..2 {
            let flooding_errors = witness.flooding_errors_by_role[role_ordinal];
            if flooding_errors.len() != self.ring_degree
                || flooding_errors
                    .iter()
                    .any(|error| i128::from(*error).abs() > i128::from(self.flooding_bound))
            {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            let shifted = flooding_errors
                .iter()
                .map(|error| {
                    u64::try_from(i128::from(*error) + i128::from(self.flooding_bound))
                        .map_err(|_| TargetReleaseWitnessError::IntegerOverflow)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let flooding_layout = &self.flooding_by_role[role_ordinal];
            insert_bounded_unsigned_vector(
                &mut columns,
                trace_domain,
                &flooding_layout.bounded_shift,
                &shifted,
                self.flooding_bound
                    .checked_mul(2)
                    .ok_or(TargetReleaseWitnessError::IntegerOverflow)?,
            )?;
            let radix_layers =
                unsigned_radix_layers(&shifted, RADIX, flooding_layout.grouped_limbs.len())?;
            insert_split_radix_layers(
                &mut columns,
                trace_domain,
                &flooding_layout.grouped_limbs,
                &radix_layers,
            )?;
            flooding_shift_layers_by_role.push(radix_layers);
        }

        for (modulus_layout, modulus_witness) in self.moduli.iter().zip(witness.moduli) {
            let _material_digits = insert_committed_share_columns(
                &mut columns,
                trace_domain,
                &modulus_layout.material,
                modulus_witness.committed_share,
                modulus_witness.threshold_share,
                modulus_layout.modulus,
            )?;
            let share_layers = unsigned_radix_layers(
                modulus_witness.threshold_share,
                RADIX,
                modulus_layout.share_limbs.len(),
            )?;
            let share_split_layouts = modulus_layout
                .share_limbs
                .iter()
                .map(|limb| limb.source.coefficients)
                .collect::<Vec<_>>();
            insert_split_radix_layers(
                &mut columns,
                trace_domain,
                &share_split_layouts,
                &share_layers,
            )?;
            let share_transform = RadixLayerTransform::new(&share_layers)?;
            if modulus_layout.role_equations.len() != 2 {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            for role_ordinal in 0..2 {
                insert_role_equation_columns(
                    &mut columns,
                    trace_domain,
                    &modulus_layout.role_equations[role_ordinal],
                    modulus_witness.roles[role_ordinal],
                    &share_transform,
                    witness.flooding_errors_by_role[role_ordinal],
                    &flooding_shift_layers_by_role[role_ordinal],
                    modulus_layout.modulus,
                    self.decryption_scale,
                    self.simulation_scale,
                    self.flooding_bound,
                )?;
            }
        }
        Ok(columns)
    }

    /// Builds the verifier-sequence adapter from public streams that have
    /// already been authenticated and reconstructed by the target verifier.
    /// The shape check is exact: every verifier-sequence column in the selected
    /// relation must be present and no prover or bound-tree column may enter
    /// this adapter.
    pub(crate) fn verified_column_evaluator(
        &self,
        public_moduli: &[VerifiedTargetReleaseModulusInput<'_>],
    ) -> Result<TargetReleaseVerifiedColumnEvaluator, TargetReleaseWitnessError> {
        if public_moduli.len() != self.moduli.len()
            || self.ring_degree < 2
            || !self.ring_degree.is_power_of_two()
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(self.ring_degree / 2)?;
        let mut columns = BTreeMap::new();
        for (modulus_layout, public_modulus) in self.moduli.iter().zip(public_moduli) {
            if modulus_layout.role_equations.len() != usize::from(TARGET_ROLE_COUNT) {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
            for role_ordinal in 0..usize::from(TARGET_ROLE_COUNT) {
                insert_role_verifier_columns(
                    &mut columns,
                    trace_domain,
                    &modulus_layout.role_equations[role_ordinal],
                    public_modulus.roles[role_ordinal],
                    modulus_layout.modulus,
                    self.decryption_scale,
                )?;
            }
        }
        let variant = self.relation_plan.select_variant(None, None)?;
        for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
            let column_ordinal = u32::try_from(column_index)
                .map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
            let is_verifier_sequence = matches!(
                descriptor.origin(),
                RelationColumnOrigin::VerifierSequence { .. }
            );
            if columns.contains_key(&column_ordinal) != is_verifier_sequence {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            }
        }
        Ok(TargetReleaseVerifiedColumnEvaluator { columns })
    }
}

fn negacyclic_product_i128(left: &[u64], right: &[u64]) -> Result<Vec<i128>, RelationPlanError> {
    if left.is_empty() || left.len() != right.len() || !left.len().is_power_of_two() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut result = vec![0_i128; left.len()];
    for (left_index, left_value) in left.iter().copied().enumerate() {
        for (right_index, right_value) in right.iter().copied().enumerate() {
            let raw_index = left_index + right_index;
            let product = i128::from(left_value)
                .checked_mul(i128::from(right_value))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            let target_index = raw_index % left.len();
            result[target_index] = if raw_index >= left.len() {
                result[target_index]
                    .checked_sub(product)
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?
            } else {
                result[target_index]
                    .checked_add(product)
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?
            };
        }
    }
    Ok(result)
}

/// Independent executable oracle for the compact radix lowering.  It compares
/// the direct target-ring equation with the schoolbook limb/carry identity;
/// neither side calls the relation-plan compiler or its constraint generator.
pub(crate) fn target_release_radix_semantics_match(
    public_a: &[u64],
    partial_decryption: &[u64],
    share: &[u64],
    flooding_error: &[i64],
    modulus: u64,
    decryption_scale: u64,
    simulation_scale: u64,
) -> Result<bool, RelationPlanError> {
    if public_a.len() != partial_decryption.len()
        || public_a.len() != share.len()
        || public_a.len() != flooding_error.len()
        || public_a
            .iter()
            .chain(partial_decryption)
            .chain(share)
            .any(|value| *value >= modulus)
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let product = negacyclic_product_i128(public_a, share)?;
    let modulus_i128 = i128::from(modulus);
    let mut direct_holds = true;
    let mut exact_quotients = Vec::with_capacity(public_a.len());
    for coefficient_ordinal in 0..public_a.len() {
        let residual = i128::from(partial_decryption[coefficient_ordinal])
            - i128::from(decryption_scale) * product[coefficient_ordinal]
            - i128::from(simulation_scale) * i128::from(flooding_error[coefficient_ordinal]);
        direct_holds &= residual.rem_euclid(modulus_i128) == 0;
        exact_quotients.push(residual / modulus_i128);
    }

    let scaled_a = public_a
        .iter()
        .copied()
        .map(|value| {
            value
                .checked_mul(decryption_scale)
                .ok_or(RelationPlanError::IntegerBoundOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let scaled_product = negacyclic_product_i128(&scaled_a, share)?;
    let compact_holds = (0..public_a.len()).all(|coefficient_ordinal| {
        i128::from(partial_decryption[coefficient_ordinal])
            - scaled_product[coefficient_ordinal]
            - i128::from(simulation_scale) * i128::from(flooding_error[coefficient_ordinal])
            - modulus_i128 * exact_quotients[coefficient_ordinal]
            == 0
    });
    Ok(direct_holds == compact_holds && direct_holds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        CommittedMaterialProfile, CommittedMaterialTreeInput, CommonProofPrivateCoinSource,
        PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
        construct_pre_challenge_relation_columns,
    };

    struct DeterministicPrivateCoins(u64);

    impl CommonProofPrivateCoinSource for DeterministicPrivateCoins {
        type Error = ();

        fn sample_modulo(
            &mut self,
            _purpose: u16,
            modulus: u64,
            _maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            let value = self.0 % modulus;
            self.0 = self.0.wrapping_add(1);
            Ok(value)
        }

        fn fill_raw_bytes(
            &mut self,
            _purpose: u16,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            for byte in destination {
                *byte = self.0 as u8;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn plan_context() -> RelationPlanCheckContext {
        let evaluation_domain_size = 8_192_u64;
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
                as u16,
            evaluation_blowup_factor: 2,
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            deep_point_count: 1,
            quotient_component_count: 4,
            quotient_component_degree_bound_exclusive: 1_024,
            fri_fold_count: 9,
            final_polynomial_degree_bound_exclusive: 8,
            unique_query_count: 8,
            non_native_modular_identity_challenge_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![ResolvedSuiteModulus::new(
                SuiteModulusReference::target(0),
                140_737_488_224_257,
            )],
        }
    }

    #[test]
    fn compact_radix_lowering_matches_direct_negacyclic_release_relation() {
        let modulus = 97_u64;
        let public_a = vec![3, 7, 11, 13, 17, 19, 23, 29];
        let share = vec![5, 2, 9, 1, 4, 8, 6, 3];
        let flooding_error = vec![1, -2, 0, 3, -1, 2, -3, 1];
        let decryption_scale = 4_u64;
        let simulation_scale = 4_u64;
        let product = negacyclic_product_i128(&public_a, &share).expect("product");
        let partial_decryption = product
            .iter()
            .zip(&flooding_error)
            .map(|(product, flooding)| {
                (i128::from(decryption_scale) * product
                    + i128::from(simulation_scale) * i128::from(*flooding))
                .rem_euclid(i128::from(modulus)) as u64
            })
            .collect::<Vec<_>>();
        assert!(
            target_release_radix_semantics_match(
                &public_a,
                &partial_decryption,
                &share,
                &flooding_error,
                modulus,
                decryption_scale,
                simulation_scale,
            )
            .expect("equivalence")
        );

        let mut mutated = partial_decryption;
        mutated[3] = (mutated[3] + 1) % modulus;
        assert!(
            !target_release_radix_semantics_match(
                &public_a,
                &mutated,
                &share,
                &flooding_error,
                modulus,
                decryption_scale,
                simulation_scale,
            )
            .expect("mutation")
        );
    }

    #[test]
    fn verifier_radix_view_is_canonical_and_rejects_non_residues() {
        assert_eq!(
            radix_decompose_scaled_residues(&[0, 96, 42], 97, 4, 9, 1, 3).expect("digits"),
            vec![0, 6, 0]
        );
        assert_eq!(
            radix_decompose_scaled_residues(&[97], 97, 4, 9, 0, 3),
            Err(RelationPlanError::InvalidSource)
        );
    }

    #[test]
    fn target_release_plan_compiles_with_compact_safe_limb_products() {
        let context = plan_context();
        let plan = compile_target_release_relation_plan(
            &TargetReleaseRelationPlanInput {
                ring_degree: 256,
                evaluation_domain_size: 8_192,
                opening_degree_bound_exclusive: 4_096,
                material_column_degree_bound_exclusive: 128,
                public_polynomial_column_degree_bound_exclusive: 256,
                target_modulus_indices: vec![0],
                decryption_scale: 4,
                simulation_scale: 4,
                flooding_bound: 1_000_000,
                first_mask_purpose: 100,
            },
            &context,
        )
        .expect("target release relation plan");
        let variant = plan.select_variant(None, None).expect("variant");
        assert_eq!(variant.ordered_integer_lift_batches().len(), 1);
        assert!(
            variant
                .ordered_integer_lift_batches()
                .iter()
                .flat_map(|batch| &batch.ordered_components)
                .all(|component| !component.ordered_full_ring_negacyclic_products.is_empty())
        );
        super::super::same_secret_anchor::tests::assert_integer_lift_phase_ownership(variant);
    }

    #[test]
    fn typed_target_witness_populates_every_pre_challenge_column_and_rejects_drift() {
        let context = plan_context();
        let ring_degree = 256_usize;
        let material_profile =
            CommittedMaterialProfile::for_common_proof_evaluation_domain(ring_degree, 8_192)
                .expect("material profile");
        let compilation = compile_target_release_relation(
            &TargetReleaseRelationPlanInput {
                ring_degree: ring_degree as u64,
                evaluation_domain_size: 8_192,
                opening_degree_bound_exclusive: 4_096,
                material_column_degree_bound_exclusive: material_profile
                    .material_column_degree_bound_exclusive()
                    as u64,
                public_polynomial_column_degree_bound_exclusive: ring_degree as u64,
                target_modulus_indices: vec![0],
                decryption_scale: 4,
                simulation_scale: 4,
                flooding_bound: 1_000_000,
                first_mask_purpose: 100,
            },
            &context,
        )
        .expect("target relation compilation");
        let modulus = context
            .resolved_modulus(SuiteModulusReference::target(0))
            .expect("target modulus");
        let share = (0..ring_degree)
            .map(|index| ((index * 37 + 11) as u64) % modulus)
            .collect::<Vec<_>>();
        let material_digits =
            unsigned_radix_layers(&share, MATERIAL_DIGIT_RADIX, 2).expect("material digits");
        let committed_share = CommittedMaterialTree::construct(CommittedMaterialTreeInput {
            profile: material_profile,
            material_context_hash: [0x51; 64],
            material_seed: [0x73; 64],
            message_digit_columns: &material_digits,
        })
        .expect("committed share");
        let flooding_identifier = (0..ring_degree)
            .map(|index| i64::try_from(index % 11).expect("small") - 5)
            .collect::<Vec<_>>();
        let flooding_order = (0..ring_degree)
            .map(|index| 7 - i64::try_from(index % 13).expect("small"))
            .collect::<Vec<_>>();
        let converted_identifier = (0..ring_degree)
            .map(|index| ((index * 19 + 3) as u64) % modulus)
            .collect::<Vec<_>>();
        let converted_order = (0..ring_degree)
            .map(|index| ((index * 23 + 9) as u64) % modulus)
            .collect::<Vec<_>>();
        let partial = |converted: &[u64], flooding: &[i64]| {
            negacyclic_product_i128(converted, &share)
                .expect("product")
                .iter()
                .zip(flooding)
                .map(|(product, error)| {
                    (4_i128 * *product + 4_i128 * i128::from(*error))
                        .rem_euclid(i128::from(modulus)) as u64
                })
                .collect::<Vec<_>>()
        };
        let partial_identifier = partial(&converted_identifier, &flooding_identifier);
        let partial_order = partial(&converted_order, &flooding_order);
        let modulus_witness = TargetReleaseModulusWitness {
            committed_share: &committed_share,
            threshold_share: &share,
            roles: [
                TargetReleaseRoleWitness {
                    converted_a: &converted_identifier,
                    partial_decryption: &partial_identifier,
                },
                TargetReleaseRoleWitness {
                    converted_a: &converted_order,
                    partial_decryption: &partial_order,
                },
            ],
        };
        let columns = compilation
            .provided_pre_challenge_columns(TargetReleaseWitness {
                flooding_errors_by_role: [&flooding_identifier, &flooding_order],
                moduli: std::slice::from_ref(&modulus_witness),
            })
            .expect("typed witness columns");
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("target relation variant");
        let mut verified_column_evaluator = compilation
            .verified_column_evaluator(&[VerifiedTargetReleaseModulusInput {
                roles: modulus_witness.roles,
            }])
            .expect("verified public target columns");
        let evaluation_point = ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(7).expect("canonical point"),
        );
        for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
            let column_ordinal = u32::try_from(column_index).expect("column ordinal");
            if matches!(
                descriptor.origin(),
                RelationColumnOrigin::VerifierSequence { .. }
            ) {
                assert_eq!(
                    verified_column_evaluator
                        .evaluate_at_extension_point(column_ordinal, evaluation_point),
                    columns
                        .get(&column_ordinal)
                        .map(|column| column.evaluate_at(evaluation_point)),
                    "the verifier must independently reconstruct column {column_ordinal}",
                );
            } else {
                assert_eq!(
                    verified_column_evaluator
                        .evaluate_at_extension_point(column_ordinal, evaluation_point),
                    None,
                    "a non-verifier column must never enter the public evaluator",
                );
            }
        }
        let pre_challenge_columns = construct_pre_challenge_relation_columns(
            variant,
            columns,
            &mut DeterministicPrivateCoins(1),
            128,
        )
        .expect("every plan-owned pre-challenge column is present and maskable");
        assert!(
            variant
                .ordered_columns()
                .iter()
                .enumerate()
                .filter(|(_, descriptor)| {
                    matches!(descriptor.origin(), RelationColumnOrigin::Prover)
                })
                .any(|(column_ordinal, _)| pre_challenge_columns
                    .column(column_ordinal as u32)
                    .is_some())
        );

        let mut changed_share = share.clone();
        changed_share[17] += 1;
        let changed_modulus_witness = TargetReleaseModulusWitness {
            threshold_share: &changed_share,
            ..modulus_witness
        };
        assert_eq!(
            compilation.provided_pre_challenge_columns(TargetReleaseWitness {
                flooding_errors_by_role: [&flooding_identifier, &flooding_order],
                moduli: std::slice::from_ref(&changed_modulus_witness),
            }),
            Err(TargetReleaseWitnessError::InvalidWitness)
        );

        let mut changed_partial = partial_identifier.clone();
        changed_partial[29] = (changed_partial[29] + 1) % modulus;
        let changed_role_witness = TargetReleaseModulusWitness {
            roles: [
                TargetReleaseRoleWitness {
                    converted_a: &converted_identifier,
                    partial_decryption: &changed_partial,
                },
                modulus_witness.roles[1],
            ],
            ..modulus_witness
        };
        assert_eq!(
            compilation.provided_pre_challenge_columns(TargetReleaseWitness {
                flooding_errors_by_role: [&flooding_identifier, &flooding_order],
                moduli: std::slice::from_ref(&changed_role_witness),
            }),
            Err(TargetReleaseWitnessError::InvalidWitness)
        );

        let mut noncanonical_partial = partial_identifier.clone();
        noncanonical_partial[0] = modulus;
        assert!(matches!(
            compilation.verified_column_evaluator(&[VerifiedTargetReleaseModulusInput {
                roles: [
                    TargetReleaseRoleWitness {
                        converted_a: &converted_identifier,
                        partial_decryption: &noncanonical_partial,
                    },
                    modulus_witness.roles[1],
                ],
            }]),
            Err(TargetReleaseWitnessError::InvalidWitness)
        ));
    }
}
