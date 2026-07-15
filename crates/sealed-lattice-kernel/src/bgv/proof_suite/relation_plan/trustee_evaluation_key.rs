use std::collections::BTreeSet;

use super::key_relation::{
    BoundPolynomialRootUse, KeyRelationGeometry, KeyRelationPlanBuilder, KeyVerifierSourceKey,
    ReversibleShiftedSmallVector, SplitIntegerVector, TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE,
    TrusteeKeyRelationGeometryInput, relinearization_common_reference_source,
    statement_root_source, trustee_bdlop_matrix_source,
};
use super::{
    CompiledRelationPlan, RelationPlanCheckContext, RelationPlanChecker, RelationPlanError,
    RelationVerifierSource, SuiteModulusReference,
};

const RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1214;
const RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1216;
const ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL: u64 = 4;
const ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL: u64 = 5;
const ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL: u64 = 6;
const AGGREGATE_ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL: u64 = 7;
const AGGREGATE_ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL: u64 = 8;
const ROUND_TWO_ROOT_FIELD_ORDINAL: u64 = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrusteeEvaluationKeyDecompositionBlock {
    pub(crate) data_modulus_indices: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrusteeEvaluationKeyRelationGeometry {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) data_moduli: Vec<u64>,
    pub(crate) special_moduli: Vec<u64>,
    pub(crate) plaintext_modulus: u64,
    pub(crate) decomposition_blocks: Vec<TrusteeEvaluationKeyDecompositionBlock>,
    pub(crate) commitment_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_module_rank: u16,
    pub(crate) first_mask_purpose: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelinearizationRoundOneRelationPlanInput {
    pub(crate) schedule_position: u32,
    pub(crate) geometry: TrusteeEvaluationKeyRelationGeometry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelinearizationRoundTwoRelationPlanInput {
    pub(crate) schedule_position: u32,
    pub(crate) geometry: TrusteeEvaluationKeyRelationGeometry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GaloisKeyShareRelationPlanInput {
    pub(crate) schedule_position: u32,
    pub(crate) galois_element: u64,
    pub(crate) geometry: TrusteeEvaluationKeyRelationGeometry,
}

impl TrusteeEvaluationKeyRelationGeometry {
    fn validate_common(
        &self,
        check_context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        RelationPlanChecker::new(check_context).check_context()?;
        if self.ring_degree < 4
            || !self.ring_degree.is_power_of_two()
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.opening_degree_bound_exclusive <= 1
            || self.public_polynomial_column_degree_bound_exclusive == 0
            || self.public_polynomial_column_degree_bound_exclusive
                > self.opening_degree_bound_exclusive
            || self.data_moduli.is_empty()
            || self.special_moduli.is_empty()
            || self.plaintext_modulus < 3
            || self.plaintext_modulus.is_multiple_of(2)
            || self.decomposition_blocks.is_empty()
            || self.commitment_data_modulus_indices.is_empty()
            || self.commitment_module_rank == 0
            || self.first_mask_purpose == 0
            || self.first_mask_purpose >= 0xff00
        {
            return Err(RelationPlanError::InvalidDomain);
        }

        let expected_evaluation_domain = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .and_then(|degree_domain| {
                degree_domain.checked_mul(u64::from(check_context.evaluation_blowup_factor))
            })
            .ok_or(RelationPlanError::CountOverflow)?;
        if expected_evaluation_domain != self.evaluation_domain_size
            || !(check_context.base_field_modulus - 1).is_multiple_of(self.evaluation_domain_size)
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
                self.ring_degree / 2,
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

        let mut distinct_moduli = BTreeSet::new();
        for modulus in self.data_moduli.iter().chain(&self.special_moduli).copied() {
            if modulus <= self.ring_degree
                || modulus >= check_context.base_field_modulus
                || modulus.is_multiple_of(2)
                || self.plaintext_modulus >= modulus
                || !distinct_moduli.insert(modulus)
            {
                return Err(RelationPlanError::InvalidModulus);
            }
        }
        if !distinct_moduli.insert(self.plaintext_modulus) {
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

        self.validate_round_one_quotient_bounds()?;
        self.validate_anchor_quotient_bounds()?;
        Ok(())
    }

    fn validate_round_one_quotient_bounds(&self) -> Result<(), RelationPlanError> {
        for modulus in self.data_moduli.iter().chain(&self.special_moduli).copied() {
            let modulus_minus_one = u128::from(modulus - 1);
            let numerator_bound = u128::from(self.ring_degree)
                .checked_add(2)
                .and_then(|factor| factor.checked_mul(modulus_minus_one))
                .and_then(|bound| bound.checked_add(2_u128 * u128::from(self.plaintext_modulus)))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            validate_quotient_capacity(numerator_bound, modulus)?;
        }
        Ok(())
    }

    fn validate_round_two_quotient_bounds(&self) -> Result<(), RelationPlanError> {
        for modulus in self.data_moduli.iter().chain(&self.special_moduli).copied() {
            let centered_product_bound = u128::from(self.ring_degree)
                .checked_mul(u128::from((modulus - 1) / 2))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            let numerator_bound = centered_product_bound
                .checked_mul(3)
                .and_then(|bound| bound.checked_add(u128::from(modulus - 1)))
                .and_then(|bound| bound.checked_add(2_u128 * u128::from(self.plaintext_modulus)))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            validate_quotient_capacity(numerator_bound, modulus)?;
        }
        Ok(())
    }

    fn validate_anchor_quotient_bounds(&self) -> Result<(), RelationPlanError> {
        let product_count = u128::from(self.commitment_module_rank)
            .checked_add(1)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        for data_modulus_index in self.commitment_data_modulus_indices.iter().copied() {
            let modulus = self.data_moduli[usize::from(data_modulus_index)];
            let product_bound = u128::from(self.ring_degree)
                .checked_mul(u128::from((modulus - 1) / 2))
                .and_then(|bound| bound.checked_mul(product_count))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            let numerator_bound = product_bound
                .checked_add(u128::from(modulus - 1))
                .and_then(|bound| bound.checked_add(2))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            validate_quotient_capacity(numerator_bound, modulus)?;
        }
        Ok(())
    }

    fn ordered_modulus_references(&self) -> Result<Vec<SuiteModulusReference>, RelationPlanError> {
        let mut references = Vec::with_capacity(
            self.data_moduli
                .len()
                .checked_add(self.special_moduli.len())
                .ok_or(RelationPlanError::CountOverflow)?,
        );
        for index in 0..self.data_moduli.len() {
            references.push(SuiteModulusReference::data(
                u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
        for index in 0..self.special_moduli.len() {
            references.push(SuiteModulusReference::special(
                u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
        Ok(references)
    }

    fn ordered_root_row_modulus_references(
        &self,
    ) -> Result<Vec<SuiteModulusReference>, RelationPlanError> {
        let ordered_modulus_references = self.ordered_modulus_references()?;
        let capacity = self
            .decomposition_blocks
            .len()
            .checked_mul(ordered_modulus_references.len())
            .ok_or(RelationPlanError::CountOverflow)?;
        let mut rows = Vec::with_capacity(capacity);
        for _ in &self.decomposition_blocks {
            rows.extend(ordered_modulus_references.iter().copied());
        }
        Ok(rows)
    }

    fn gadget_coefficient(
        &self,
        decomposition_block_index: usize,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u64, RelationPlanError> {
        if modulus_reference.catalog != super::ModulusCatalog::Data
            || !self.decomposition_blocks[decomposition_block_index]
                .data_modulus_indices
                .contains(&modulus_reference.modulus_index)
        {
            return Ok(0);
        }
        let modulus = self.data_moduli[usize::from(modulus_reference.modulus_index)];
        self.special_moduli
            .iter()
            .copied()
            .try_fold(1_u64, |product, special_modulus| {
                let reduced_product =
                    (u128::from(product) * u128::from(special_modulus)) % u128::from(modulus);
                u64::try_from(reduced_product).map_err(|_| RelationPlanError::IntegerBoundOverflow)
            })
    }

    fn key_relation_geometry(
        &self,
        schedule_position: u32,
    ) -> Result<KeyRelationGeometry, RelationPlanError> {
        KeyRelationGeometry::for_trustee(TrusteeKeyRelationGeometryInput {
            schedule_position,
            ring_degree: self.ring_degree,
            evaluation_domain_size: self.evaluation_domain_size,
            opening_degree_bound_exclusive: self.opening_degree_bound_exclusive,
            public_polynomial_column_degree_bound_exclusive: self
                .public_polynomial_column_degree_bound_exclusive,
            data_modulus_count: self.data_moduli.len(),
            special_modulus_count: self.special_moduli.len(),
            commitment_data_modulus_indices: self.commitment_data_modulus_indices.clone(),
            commitment_module_rank: self.commitment_module_rank,
            plaintext_modulus: self.plaintext_modulus,
            first_mask_purpose: self.first_mask_purpose,
        })
    }
}

fn validate_modulus_catalog(
    moduli: &[u64],
    reference: impl Fn(u16) -> SuiteModulusReference,
    check_context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    for (index, expected_modulus) in moduli.iter().copied().enumerate() {
        let index = u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow)?;
        if check_context.resolved_modulus(reference(index))? != expected_modulus {
            return Err(RelationPlanError::InvalidModulus);
        }
    }
    Ok(())
}

fn validate_quotient_capacity(
    numerator_bound: u128,
    modulus: u64,
) -> Result<(), RelationPlanError> {
    let modulus = u128::from(modulus);
    let quotient_bound = numerator_bound
        .checked_add(modulus - 1)
        .ok_or(RelationPlanError::IntegerBoundOverflow)?
        / modulus;
    if quotient_bound > u128::from(TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE) {
        Err(RelationPlanError::IntegerBoundOverflow)
    } else {
        Ok(())
    }
}

fn append_relation_sources(
    sources: &mut Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    schedule_position: u32,
) -> Result<(), RelationPlanError> {
    let rank = usize::from(geometry.commitment_module_rank);
    for (root_ordinal, data_modulus_index) in geometry
        .commitment_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        sources.push(statement_root_source(
            ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL,
            Some(u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?),
        ));
        for row_ordinal in 0..rank {
            for column_ordinal in 0..=rank {
                sources.push(trustee_bdlop_matrix_source(
                    geometry.ring_degree,
                    data_modulus_index,
                    1,
                    u16::try_from(row_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                    u16::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ));
            }
        }
        for column_ordinal in 0..rank {
            sources.push(trustee_bdlop_matrix_source(
                geometry.ring_degree,
                data_modulus_index,
                2,
                0,
                u16::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
    }
    let ordered_modulus_references = geometry.ordered_modulus_references()?;
    for decomposition_block_index in 0..geometry.decomposition_blocks.len() {
        for modulus_reference in ordered_modulus_references.iter().copied() {
            sources.push(relinearization_common_reference_source(
                geometry.ring_degree,
                schedule_position,
                u16::try_from(decomposition_block_index)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                modulus_reference,
            ));
        }
    }
    Ok(())
}

fn statement_root_key(field_ordinal: u64) -> KeyVerifierSourceKey {
    KeyVerifierSourceKey::StatementRoot {
        field_ordinal,
        list_ordinal: None,
    }
}

fn add_statement_root_rows(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    field_ordinal: u64,
    root_use: BoundPolynomialRootUse,
) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
    builder.add_setup_polynomial_rows_root(
        &statement_root_key(field_ordinal),
        &geometry.ordered_root_row_modulus_references()?,
        root_use,
    )
}

#[allow(clippy::too_many_arguments)]
fn add_round_one_relations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    schedule_position: u32,
    round_one_left_rows: &[SplitIntegerVector],
    round_one_right_rows: &[SplitIntegerVector],
    secret: &ReversibleShiftedSmallVector,
    ephemeral_secret: &ReversibleShiftedSmallVector,
    check_context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    let ordered_modulus_references = geometry.ordered_modulus_references()?;
    let expected_row_count = geometry
        .decomposition_blocks
        .len()
        .checked_mul(ordered_modulus_references.len())
        .ok_or(RelationPlanError::CountOverflow)?;
    if round_one_left_rows.len() != expected_row_count
        || round_one_right_rows.len() != expected_row_count
    {
        return Err(RelationPlanError::InvalidRoot);
    }

    for decomposition_block_index in 0..geometry.decomposition_blocks.len() {
        let round_one_left_error = builder.add_signed_eta_two_vector()?;
        let round_one_right_error = builder.add_signed_eta_two_vector()?;
        for (limb_ordinal, modulus_reference) in
            ordered_modulus_references.iter().copied().enumerate()
        {
            let row_ordinal = decomposition_block_index
                .checked_mul(ordered_modulus_references.len())
                .and_then(|start| start.checked_add(limb_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            let source_key = KeyVerifierSourceKey::RelinearizationCommonReference {
                schedule_position,
                decomposition_block_index: u16::try_from(decomposition_block_index)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                modulus_reference,
            };
            let common_reference =
                builder.add_split_verifier_vector(&source_key, modulus_reference)?;
            let left_quotient = builder.add_trustee_radix_three_quotient_witness()?;
            let right_quotient = builder.add_trustee_radix_three_quotient_witness()?;
            let gadget_coefficient =
                geometry.gadget_coefficient(decomposition_block_index, modulus_reference)?;
            for challenge_ordinal in 0..check_context.non_native_modular_identity_challenge_count {
                builder.add_relinearization_round_one_equations(
                    modulus_reference,
                    challenge_ordinal,
                    &round_one_left_rows[row_ordinal],
                    &round_one_right_rows[row_ordinal],
                    common_reference,
                    secret,
                    ephemeral_secret,
                    &round_one_left_error,
                    &round_one_right_error,
                    gadget_coefficient,
                    left_quotient,
                    right_quotient,
                )?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_round_two_relations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    round_two_rows: &[SplitIntegerVector],
    aggregate_round_one_left_rows: &[SplitIntegerVector],
    aggregate_round_one_right_rows: &[SplitIntegerVector],
    secret: &ReversibleShiftedSmallVector,
    ephemeral_secret: &ReversibleShiftedSmallVector,
    check_context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    let ordered_modulus_references = geometry.ordered_modulus_references()?;
    let expected_row_count = geometry
        .decomposition_blocks
        .len()
        .checked_mul(ordered_modulus_references.len())
        .ok_or(RelationPlanError::CountOverflow)?;
    if round_two_rows.len() != expected_row_count
        || aggregate_round_one_left_rows.len() != expected_row_count
        || aggregate_round_one_right_rows.len() != expected_row_count
    {
        return Err(RelationPlanError::InvalidRoot);
    }

    for decomposition_block_index in 0..geometry.decomposition_blocks.len() {
        let round_two_error = builder.add_signed_eta_two_vector()?;
        for (limb_ordinal, modulus_reference) in
            ordered_modulus_references.iter().copied().enumerate()
        {
            let row_ordinal = decomposition_block_index
                .checked_mul(ordered_modulus_references.len())
                .and_then(|start| start.checked_add(limb_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            let aggregate_round_one_left = builder.add_recentered_vector(
                aggregate_round_one_left_rows[row_ordinal],
                modulus_reference,
            )?;
            let aggregate_round_one_right = builder.add_recentered_vector(
                aggregate_round_one_right_rows[row_ordinal],
                modulus_reference,
            )?;
            let quotient = builder.add_trustee_radix_three_quotient_witness()?;
            for challenge_ordinal in 0..check_context.non_native_modular_identity_challenge_count {
                builder.add_relinearization_round_two_equation(
                    modulus_reference,
                    challenge_ordinal,
                    &round_two_rows[row_ordinal],
                    &aggregate_round_one_left,
                    &aggregate_round_one_right,
                    secret,
                    ephemeral_secret,
                    &round_two_error,
                    quotient,
                )?;
            }
        }
    }
    Ok(())
}

fn add_anchor_relations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    secret: &ReversibleShiftedSmallVector,
    check_context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    let rank = usize::from(geometry.commitment_module_rank);
    for (root_ordinal, data_modulus_index) in geometry
        .commitment_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        let modulus_reference = SuiteModulusReference::data(data_modulus_index);
        let opening = builder.add_trustee_anchor_opening_witness()?;
        let commitments = builder.add_setup_polynomial_root(
            &KeyVerifierSourceKey::StatementRoot {
                field_ordinal: ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL,
                list_ordinal: Some(
                    u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ),
            },
            modulus_reference,
            rank.checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
            BoundPolynomialRootUse::Input,
        )?;
        let first_matrix = (0..rank)
            .map(|row_ordinal| {
                (0..=rank)
                    .map(|column_ordinal| {
                        builder.add_recentered_split_verifier_vector(
                            &KeyVerifierSourceKey::TrusteeBdlopMatrix {
                                data_modulus_index,
                                matrix_part: 1,
                                row: u16::try_from(row_ordinal)
                                    .map_err(|_| RelationPlanError::CountOverflow)?,
                                column: u16::try_from(column_ordinal)
                                    .map_err(|_| RelationPlanError::CountOverflow)?,
                            },
                            modulus_reference,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let second_matrix = (0..rank)
            .map(|column_ordinal| {
                builder.add_recentered_split_verifier_vector(
                    &KeyVerifierSourceKey::TrusteeBdlopMatrix {
                        data_modulus_index,
                        matrix_part: 2,
                        row: 0,
                        column: u16::try_from(column_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                    modulus_reference,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let quotients = (0..=rank)
            .map(|_| builder.add_trustee_radix_three_quotient_witness())
            .collect::<Result<Vec<_>, _>>()?;
        for challenge_ordinal in 0..check_context.non_native_modular_identity_challenge_count {
            builder.add_trustee_anchor_equations(
                modulus_reference,
                challenge_ordinal,
                &commitments,
                &first_matrix,
                &second_matrix,
                &opening,
                &secret.source,
                &quotients,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn compile_relinearization_round_one_relation_plan(
    input: &RelinearizationRoundOneRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    input.geometry.validate_common(check_context)?;
    let mut sources = vec![
        statement_root_source(ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL, None),
    ];
    append_relation_sources(&mut sources, &input.geometry, input.schedule_position)?;
    let geometry = input
        .geometry
        .key_relation_geometry(input.schedule_position)?;
    let mut builder = KeyRelationPlanBuilder::new(
        RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        check_context,
        sources,
    )?;
    let secret = builder.add_reversible_signed_ternary_vector()?;
    let ephemeral_secret = builder.add_reversible_signed_ternary_vector()?;
    let round_one_left_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL,
        BoundPolynomialRootUse::Output,
    )?;
    let round_one_right_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL,
        BoundPolynomialRootUse::Output,
    )?;
    add_round_one_relations(
        &mut builder,
        &input.geometry,
        input.schedule_position,
        &round_one_left_rows,
        &round_one_right_rows,
        &secret,
        &ephemeral_secret,
        check_context,
    )?;
    add_anchor_relations(&mut builder, &input.geometry, &secret, check_context)?;
    builder.finish()
}

pub(crate) fn compile_relinearization_round_two_relation_plan(
    input: &RelinearizationRoundTwoRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    input.geometry.validate_common(check_context)?;
    input.geometry.validate_round_two_quotient_bounds()?;
    let mut sources = vec![
        statement_root_source(ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(AGGREGATE_ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(AGGREGATE_ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(ROUND_TWO_ROOT_FIELD_ORDINAL, None),
    ];
    append_relation_sources(&mut sources, &input.geometry, input.schedule_position)?;
    let geometry = input
        .geometry
        .key_relation_geometry(input.schedule_position)?;
    let mut builder = KeyRelationPlanBuilder::new(
        RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        check_context,
        sources,
    )?;
    let secret = builder.add_reversible_signed_ternary_vector()?;
    let ephemeral_secret = builder.add_reversible_signed_ternary_vector()?;
    let round_one_left_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL,
        BoundPolynomialRootUse::Input,
    )?;
    let round_one_right_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL,
        BoundPolynomialRootUse::Input,
    )?;
    let aggregate_round_one_left_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        AGGREGATE_ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL,
        BoundPolynomialRootUse::Input,
    )?;
    let aggregate_round_one_right_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        AGGREGATE_ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL,
        BoundPolynomialRootUse::Input,
    )?;
    let round_two_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        ROUND_TWO_ROOT_FIELD_ORDINAL,
        BoundPolynomialRootUse::Output,
    )?;
    add_round_one_relations(
        &mut builder,
        &input.geometry,
        input.schedule_position,
        &round_one_left_rows,
        &round_one_right_rows,
        &secret,
        &ephemeral_secret,
        check_context,
    )?;
    add_round_two_relations(
        &mut builder,
        &input.geometry,
        &round_two_rows,
        &aggregate_round_one_left_rows,
        &aggregate_round_one_right_rows,
        &secret,
        &ephemeral_secret,
        check_context,
    )?;
    add_anchor_relations(&mut builder, &input.geometry, &secret, check_context)?;
    builder.finish()
}

pub(crate) fn compile_galois_key_share_relation_plan(
    input: &GaloisKeyShareRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    input.geometry.validate_common(check_context)?;
    let automorphism_modulus = input
        .geometry
        .ring_degree
        .checked_mul(2)
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    if input.galois_element <= 1
        || input.galois_element >= automorphism_modulus
        || input.galois_element.is_multiple_of(2)
    {
        return Err(RelationPlanError::InvalidDomain);
    }

    // The current expression grammar has no exact compact permutation for
    // X -> X^g in Z[X]/(X^N + 1). Expanding the automorphism into additive
    // trace rotations exceeds the production zero-knowledge mask-image bound,
    // so emitting a weaker coefficient-local or unbound identity is forbidden.
    Err(RelationPlanError::MissingExactNegacyclicLowering)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use num_bigint::BigInt;

    use super::super::key_relation::{
        TRUSTEE_QUOTIENT_HIGH_RADIX, TRUSTEE_QUOTIENT_LOW_TRIT_COUNT,
    };
    use super::super::same_secret_anchor::tests::{
        TEST_EVALUATION_DOMAIN_SIZE, TEST_OPENING_DEGREE_BOUND_EXCLUSIVE, TEST_RING_DEGREE,
        check_context as key_relation_check_context,
    };
    use super::super::{
        ModulusCatalog, RelationBoundCertificate, RelationEmbeddingKind,
        RelationIntegerLiftCoefficient, RelationVerifierSource, ResolvedSuiteModulus,
        SignedIntegerInterval,
    };
    use super::*;
    use crate::bgv::parameters::{DATA_PRIMES, SPECIAL_PRIME};

    fn check_context() -> RelationPlanCheckContext {
        let mut context = key_relation_check_context(true);
        context.resolved_moduli.insert(
            2,
            ResolvedSuiteModulus::new(SuiteModulusReference::special(0), SPECIAL_PRIME),
        );
        context
    }

    fn geometry() -> TrusteeEvaluationKeyRelationGeometry {
        TrusteeEvaluationKeyRelationGeometry {
            ring_degree: TEST_RING_DEGREE,
            evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
            public_polynomial_column_degree_bound_exclusive: TEST_RING_DEGREE,
            data_moduli: vec![DATA_PRIMES[0], DATA_PRIMES[1]],
            special_moduli: vec![SPECIAL_PRIME],
            plaintext_modulus: 257,
            decomposition_blocks: vec![TrusteeEvaluationKeyDecompositionBlock {
                data_modulus_indices: vec![0, 1],
            }],
            commitment_data_modulus_indices: vec![0, 1],
            commitment_module_rank: 1,
            first_mask_purpose: 100,
        }
    }

    fn round_one_input() -> RelinearizationRoundOneRelationPlanInput {
        RelinearizationRoundOneRelationPlanInput {
            schedule_position: 3,
            geometry: geometry(),
        }
    }

    fn round_two_input() -> RelinearizationRoundTwoRelationPlanInput {
        RelinearizationRoundTwoRelationPlanInput {
            schedule_position: 3,
            geometry: geometry(),
        }
    }

    fn semantic_cells_by_column(
        variant: &super::super::RelationPlanVariant,
    ) -> BTreeMap<u32, &super::super::SemanticCellDescriptor> {
        variant
            .ordered_semantic_cells
            .iter()
            .map(|cell| (cell.column_ordinal, cell))
            .collect()
    }

    fn assert_radix_three_quotients(variant: &super::super::RelationPlanVariant) {
        let semantic_cells = semantic_cells_by_column(variant);
        let mut component_count = 0_usize;
        for batch in &variant.ordered_integer_lift_batches {
            for component in &batch.ordered_components {
                component_count += 1;
                let quotient_cell = semantic_cells
                    .get(&component.quotient_column_ordinal)
                    .expect("quotient semantic cell");
                assert!(matches!(
                    &quotient_cell.bound_certificate,
                    RelationBoundCertificate::ShiftedRadixRecomposition {
                        radix: 3,
                        ordered_digit_column_ordinals,
                        ..
                    } if ordered_digit_column_ordinals.len() == TRUSTEE_QUOTIENT_LOW_TRIT_COUNT
                ));
                let carry_terms = component
                    .ordered_linear_terms
                    .iter()
                    .filter(|term| {
                        matches!(
                            term.coefficient,
                            RelationIntegerLiftCoefficient::Modulus {
                                modulus_reference,
                                multiplier: TRUSTEE_QUOTIENT_HIGH_RADIX,
                            } if modulus_reference == batch.modulus_reference
                        )
                    })
                    .collect::<Vec<_>>();
                assert_eq!(carry_terms.len(), 1);
                let carry_cell = semantic_cells
                    .get(&carry_terms[0].column_ordinal)
                    .expect("quotient carry semantic cell");
                assert_eq!(
                    carry_cell.claimed_interval,
                    SignedIntegerInterval::new(-2, 2)
                );
                assert!(matches!(
                    &carry_cell.bound_certificate,
                    RelationBoundCertificate::FiniteIntegerSet { ordered_values, .. }
                        if ordered_values
                            == &(-2..=2).map(BigInt::from).collect::<Vec<_>>()
                ));
            }
        }
        assert!(component_count > 0);
    }

    #[test]
    fn round_one_plan_covers_all_limbs_with_shared_small_witnesses() {
        let context = check_context();
        let plan = compile_relinearization_round_one_relation_plan(&round_one_input(), &context)
            .expect("round-one relation plan");
        assert_eq!(
            plan.application_statement_schema_identifier(),
            RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
        );
        let variant = plan
            .select_variant(Some(3), None)
            .expect("scheduled round-one variant");
        let batch_moduli = variant
            .ordered_integer_lift_batches
            .iter()
            .map(|batch| batch.modulus_reference)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            batch_moduli,
            BTreeSet::from([
                SuiteModulusReference::data(0),
                SuiteModulusReference::data(1),
                SuiteModulusReference::special(0),
            ])
        );
        for source in &variant.ordered_verifier_sources {
            if let RelationVerifierSource::Protocol {
                protocol_source_kind: 5 | 7,
                value_layout,
                ..
            } = source
            {
                assert_eq!(
                    value_layout.embedding_kind,
                    RelationEmbeddingKind::LeastNonnegative
                );
            }
        }

        let mut round_one_small_multiplier_columns = BTreeSet::new();
        let mut anchor_multiplicands_by_modulus = BTreeMap::new();
        for batch in &variant.ordered_integer_lift_batches {
            let mut anchor_multiplicands = BTreeSet::new();
            for product in batch
                .ordered_components
                .iter()
                .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            {
                if product.multiplier_low_offset == 0 {
                    round_one_small_multiplier_columns
                        .insert(product.multiplier_low_column_ordinal);
                } else {
                    anchor_multiplicands.insert(product.multiplicand_low_column_ordinal);
                }
            }
            if batch.modulus_reference.catalog == ModulusCatalog::Data {
                assert_eq!(anchor_multiplicands.len(), 2);
                anchor_multiplicands_by_modulus
                    .insert(batch.modulus_reference, anchor_multiplicands);
            } else {
                assert!(anchor_multiplicands.is_empty());
            }
        }
        assert_eq!(round_one_small_multiplier_columns.len(), 2);
        let data_zero_opening = &anchor_multiplicands_by_modulus[&SuiteModulusReference::data(0)];
        let data_one_opening = &anchor_multiplicands_by_modulus[&SuiteModulusReference::data(1)];
        assert!(data_zero_opening.is_disjoint(data_one_opening));
        assert_radix_three_quotients(variant);
    }

    #[test]
    fn round_two_plan_reproves_round_one_and_reuses_both_small_witnesses() {
        let context = check_context();
        let plan = compile_relinearization_round_two_relation_plan(&round_two_input(), &context)
            .expect("round-two relation plan");
        assert_eq!(
            plan.application_statement_schema_identifier(),
            RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
        );
        let variant = plan
            .select_variant(Some(3), None)
            .expect("scheduled round-two variant");
        let special_batch = variant
            .ordered_integer_lift_batches
            .iter()
            .find(|batch| batch.modulus_reference == SuiteModulusReference::special(0))
            .expect("special-limb batch");
        assert_eq!(special_batch.ordered_components.len(), 6);
        let round_one_small_columns = special_batch
            .ordered_components
            .iter()
            .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            .filter(|product| product.multiplier_low_offset == 0)
            .map(|product| product.multiplier_low_column_ordinal)
            .collect::<BTreeSet<_>>();
        let round_two_small_columns = special_batch
            .ordered_components
            .iter()
            .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            .filter(|product| product.multiplier_low_offset != 0)
            .map(|product| product.multiplicand_low_column_ordinal)
            .collect::<BTreeSet<_>>();
        assert_eq!(round_one_small_columns.len(), 2);
        assert_eq!(round_two_small_columns, round_one_small_columns);

        let semantic_cells = semantic_cells_by_column(variant);
        for product in special_batch
            .ordered_components
            .iter()
            .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            .filter(|product| product.multiplier_low_offset != 0)
        {
            assert!(matches!(
                semantic_cells
                    .get(&product.multiplier_low_column_ordinal)
                    .map(|cell| &cell.bound_certificate),
                Some(RelationBoundCertificate::CanonicalModulusRecomposition {
                    modulus_reference,
                    radix: 3,
                    ..
                }) if *modulus_reference == SuiteModulusReference::special(0)
            ));
        }
        assert_radix_three_quotients(variant);
    }

    #[test]
    fn relation_inputs_reject_basis_and_quotient_bound_mutations() {
        let context = check_context();
        let mut repeated_data_limb = round_one_input();
        repeated_data_limb.geometry.decomposition_blocks[0].data_modulus_indices = vec![0, 0, 1];
        assert_eq!(
            compile_relinearization_round_one_relation_plan(&repeated_data_limb, &context,),
            Err(RelationPlanError::NonCanonicalOrder)
        );

        let mut wrong_special_modulus = round_one_input();
        wrong_special_modulus.geometry.special_moduli[0] -= 2;
        assert_eq!(
            compile_relinearization_round_one_relation_plan(&wrong_special_modulus, &context,),
            Err(RelationPlanError::InvalidModulus)
        );

        let mut unsupported_anchor_rank = round_one_input();
        unsupported_anchor_rank.geometry.ring_degree = 32_768;
        unsupported_anchor_rank.geometry.commitment_module_rank = 3;
        assert_eq!(
            compile_relinearization_round_one_relation_plan(&unsupported_anchor_rank, &context,),
            Err(RelationPlanError::IntegerBoundOverflow)
        );
    }

    #[test]
    fn galois_relation_validates_the_automorphism_then_fails_closed() {
        let context = check_context();
        let input = GaloisKeyShareRelationPlanInput {
            schedule_position: 4,
            galois_element: 3,
            geometry: geometry(),
        };
        assert_eq!(
            compile_galois_key_share_relation_plan(&input, &context),
            Err(RelationPlanError::MissingExactNegacyclicLowering)
        );
        let mut even_automorphism = input;
        even_automorphism.galois_element = 4;
        assert_eq!(
            compile_galois_key_share_relation_plan(&even_automorphism, &context,),
            Err(RelationPlanError::InvalidDomain)
        );
    }
}
