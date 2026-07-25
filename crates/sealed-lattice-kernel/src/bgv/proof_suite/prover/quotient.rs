use super::{
    BTreeMap, BTreeSet, CheckedRelationApplicationChallenges, CommonProofPrivateCoinCoordinate,
    CommonProofPrivateCoinError, CommonProofPrivateCoinSource, CommonProofProverError,
    ExternalPolynomialVector, ProofChallengeExtensionElement, ProofEvaluationDomain,
    ProofPrivacyMode, RelationApplicationChallengeAssignment, RelationColumnValueType,
    RelationConstraintColumnQuery, RelationMaskDescriptor, RelationMaskKind,
    RelationMaskTargetClass, RelationPlanCheckContext, RelationPlanError, RelationPlanVariant,
    Zeroizing, add_shifted_extension_polynomial, external_value_byte_length,
    sample_private_extension_polynomial, subtract_extension_polynomial, trim_extension_polynomial,
};
#[cfg(test)]
use super::{
    CommonProofSourcePolynomial, ProofExternalMemoryObject,
    relation_columns::CommonProofColumnEvaluations,
};

#[cfg(test)]
pub(super) fn validate_column_polynomials(
    variant: &RelationPlanVariant,
    columns: &[CommonProofSourcePolynomial],
) -> Result<(), CommonProofProverError> {
    if columns.len() != variant.ordered_columns().len() {
        return Err(CommonProofProverError::InvalidColumn);
    }
    for (descriptor, polynomial) in variant.ordered_columns().iter().zip(columns) {
        if descriptor.value_type() != polynomial.value_type()
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count()
                > usize::try_from(descriptor.source_degree_bound_exclusive())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    Ok(())
}

/// Evaluates the checked relation on the complete evaluation coset and
/// interpolates the one normalized composed quotient polynomial.
#[cfg(test)]
pub(crate) fn construct_composed_quotient_polynomial(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    evaluation_domain: ProofEvaluationDomain,
    columns: &[CommonProofSourcePolynomial],
    application_challenges: &[RelationApplicationChallengeAssignment],
    composition_challenges: &[ProofChallengeExtensionElement],
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    validate_column_polynomials(variant, columns)?;
    if evaluation_domain.size()
        != usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?
        || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
        || evaluation_domain.coset_offset().canonical() != context.evaluation_coset_offset
        || !variant
            .evaluation_domain_size()
            .is_multiple_of(variant.trace_domain_size())
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }

    let column_evaluations = columns
        .iter()
        .map(|column| match column {
            CommonProofSourcePolynomial::Base(coefficients) => evaluation_domain
                .evaluate_base_polynomial(coefficients)
                .map(|values| CommonProofColumnEvaluations::Base(Zeroizing::new(values))),
            CommonProofSourcePolynomial::Extension(coefficients) => evaluation_domain
                .evaluate_extension_polynomial(coefficients)
                .map(|values| CommonProofColumnEvaluations::Extension(Zeroizing::new(values))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evaluation_size = evaluation_domain.size();
    let trace_rotation_stride =
        usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_domain_size = usize::try_from(variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;

    let mut quotient_evaluations = Zeroizing::new(Vec::new());
    quotient_evaluations
        .try_reserve_exact(evaluation_size)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for evaluation_position in 0..evaluation_size {
        let evaluation_point = ProofChallengeExtensionElement::from_base(
            evaluation_domain.point(evaluation_position)?,
        );
        quotient_evaluations.push(variant.evaluate_composed_quotient_at_point(
            context,
            evaluation_point,
            application_challenges,
            composition_challenges,
            |column_ordinal, rotation_is_negative, rotation_magnitude| {
                let column_index = usize::try_from(column_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                let reduced_rotation =
                    usize::try_from(rotation_magnitude % variant.trace_domain_size())
                        .map_err(|_| RelationPlanError::CountOverflow)?;
                let rotation_offset = reduced_rotation
                    .checked_mul(trace_rotation_stride)
                    .ok_or(RelationPlanError::CountOverflow)?;
                let rotated_position = if rotation_is_negative {
                    evaluation_position
                        .checked_add(evaluation_size)
                        .and_then(|position| position.checked_sub(rotation_offset))
                        .ok_or(RelationPlanError::CountOverflow)?
                        % evaluation_size
                } else {
                    evaluation_position
                        .checked_add(rotation_offset)
                        .ok_or(RelationPlanError::CountOverflow)?
                        % evaluation_size
                };
                if reduced_rotation >= trace_domain_size {
                    return Err(RelationPlanError::InvalidOpening);
                }
                column_evaluations
                    .get(column_index)
                    .ok_or(RelationPlanError::InvalidConstraint)?
                    .extension_value(rotated_position)
                    .map_err(|_| RelationPlanError::InvalidConstraint)
            },
        )?);
    }
    let mut quotient =
        Zeroizing::new(evaluation_domain.interpolate_extension_polynomial(&quotient_evaluations)?);
    trim_extension_polynomial(&mut quotient);
    Ok(quotient)
}

/// Test oracle for the production constraint-at-a-time schedule. Relation
/// columns are transformed lazily and each completed evaluation vector is
/// reused by every later constraint that consumes the same column.
#[cfg(test)]
pub(crate) fn construct_constraint_stream_composed_quotient_polynomial(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    evaluation_domain: ProofEvaluationDomain,
    columns: &[CommonProofSourcePolynomial],
    application_challenges: &[RelationApplicationChallengeAssignment],
    composition_challenges: &[ProofChallengeExtensionElement],
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    validate_column_polynomials(variant, columns)?;
    if evaluation_domain.size()
        != usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?
        || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
        || evaluation_domain.coset_offset().canonical() != context.evaluation_coset_offset
        || !variant
            .evaluation_domain_size()
            .is_multiple_of(variant.trace_domain_size())
        || composition_challenges.len() != variant.constraint_count()
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let checked_application_challenges =
        variant.checked_application_challenges(context, application_challenges)?;
    let trace_domain_size = usize::try_from(variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_rotation_stride =
        usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut quotient_evaluations = Zeroizing::new(vec![
        ProofChallengeExtensionElement::ZERO;
        evaluation_domain.size()
    ]);
    let mut transformed_column_evaluations = BTreeMap::new();

    for constraint_ordinal in 0..variant.constraint_count() {
        let queries = variant.constraint_column_queries(constraint_ordinal)?;
        for column_ordinal in queries
            .iter()
            .map(|query| query.column_ordinal())
            .collect::<BTreeSet<_>>()
        {
            if transformed_column_evaluations.contains_key(&column_ordinal) {
                continue;
            }
            let column = columns
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .ok_or(CommonProofProverError::InvalidColumn)?;
            let evaluations = match column {
                CommonProofSourcePolynomial::Base(coefficients) => evaluation_domain
                    .evaluate_base_polynomial(coefficients)
                    .map(|values| CommonProofColumnEvaluations::Base(Zeroizing::new(values)))?,
                CommonProofSourcePolynomial::Extension(coefficients) => evaluation_domain
                    .evaluate_extension_polynomial(coefficients)
                    .map(|values| {
                        CommonProofColumnEvaluations::Extension(Zeroizing::new(values))
                    })?,
            };
            if transformed_column_evaluations
                .insert(column_ordinal, evaluations)
                .is_some()
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
        }
        let composition_challenge = composition_challenges
            .get(constraint_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        for evaluation_position in 0..evaluation_domain.size() {
            let evaluation_point = ProofChallengeExtensionElement::from_base(
                evaluation_domain.point(evaluation_position)?,
            );
            let evaluation = variant.evaluate_constraint_at_point(
                context,
                constraint_ordinal,
                evaluation_point,
                &checked_application_challenges,
                &mut |column_ordinal, rotation_is_negative, rotation_magnitude| {
                    let rotated_position = rotated_relation_evaluation_position(
                        evaluation_position,
                        evaluation_domain.size(),
                        trace_domain_size,
                        trace_rotation_stride,
                        rotation_is_negative,
                        rotation_magnitude,
                    )
                    .map_err(|error| match error {
                        CommonProofProverError::CountOverflow => RelationPlanError::CountOverflow,
                        _ => RelationPlanError::InvalidOpening,
                    })?;
                    transformed_column_evaluations
                        .get(&column_ordinal)
                        .ok_or(RelationPlanError::InvalidConstraint)?
                        .extension_value(rotated_position)
                        .map_err(|_| RelationPlanError::InvalidConstraint)
                },
            )?;
            let normalized = evaluation
                .numerator
                .divide(evaluation.zeroifier)
                .map_err(|_| RelationPlanError::InvalidZeroifier)?;
            quotient_evaluations[evaluation_position] = quotient_evaluations[evaluation_position]
                .add(normalized.multiply(composition_challenge));
        }
    }
    evaluation_domain.interpolate_extension_polynomial_in_place(&mut quotient_evaluations)?;
    trim_extension_polynomial(&mut quotient_evaluations);
    Ok(quotient_evaluations)
}

pub(super) const COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH: usize = 4_096;

pub(super) fn rotated_relation_evaluation_position(
    evaluation_position: usize,
    evaluation_size: usize,
    trace_domain_size: usize,
    trace_rotation_stride: usize,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Result<usize, CommonProofProverError> {
    if evaluation_size == 0
        || trace_domain_size == 0
        || trace_rotation_stride == 0
        || evaluation_position >= evaluation_size
        || trace_domain_size.checked_mul(trace_rotation_stride) != Some(evaluation_size)
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let reduced_rotation = usize::try_from(
        rotation_magnitude
            % u64::try_from(trace_domain_size)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
    )
    .map_err(|_| CommonProofProverError::CountOverflow)?;
    if reduced_rotation >= trace_domain_size {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let rotation_offset = reduced_rotation
        .checked_mul(trace_rotation_stride)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if rotation_is_negative {
        evaluation_position
            .checked_add(evaluation_size)
            .and_then(|position| position.checked_sub(rotation_offset))
            .map(|position| position % evaluation_size)
            .ok_or(CommonProofProverError::CountOverflow)
    } else {
        evaluation_position
            .checked_add(rotation_offset)
            .map(|position| position % evaluation_size)
            .ok_or(CommonProofProverError::CountOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CommonProofQuotientConstraintTransformKey {
    constraint_ordinal: u32,
    column_ordinal: u32,
}

impl CommonProofQuotientConstraintTransformKey {
    pub(super) const fn new(constraint_ordinal: u32, column_ordinal: u32) -> Self {
        Self {
            constraint_ordinal,
            column_ordinal,
        }
    }

    pub(super) const fn column_ordinal(self) -> u32 {
        self.column_ordinal
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CommonProofQuotientEvaluationReadRequest {
    transform_key: CommonProofQuotientConstraintTransformKey,
    query_ordinal: usize,
    logical_value_offset: usize,
    vector: ExternalPolynomialVector,
    element_offset: usize,
    element_count: usize,
}

impl CommonProofQuotientEvaluationReadRequest {
    pub(super) const fn vector(self) -> ExternalPolynomialVector {
        self.vector
    }

    pub(super) const fn element_offset(self) -> usize {
        self.element_offset
    }

    pub(super) const fn element_count(self) -> usize {
        self.element_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CommonProofQuotientEvaluationProgress {
    BlockComplete,
    ConstraintComplete,
}

pub(super) struct CommonProofConstraintStreamQuotientBuilder {
    evaluation_domain: ProofEvaluationDomain,
    trace_domain_size: usize,
    trace_rotation_stride: usize,
    column_value_types: Vec<RelationColumnValueType>,
    constraint_queries: Vec<Vec<RelationConstraintColumnQuery>>,
    constraint_columns: Vec<Vec<u32>>,
    remaining_constraint_use_counts: BTreeMap<u32, usize>,
    current_constraint_ordinal: usize,
    next_transform_column_index: usize,
    transformed_columns: BTreeMap<u32, ExternalPolynomialVector>,
    block_start: usize,
    next_query_ordinal: usize,
    next_query_logical_value_offset: usize,
    block_values_by_query: Vec<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    maximum_external_read_chunk_byte_length: usize,
    quotient_evaluations: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    checked_application_challenges: CheckedRelationApplicationChallenges,
    composition_challenges: Vec<ProofChallengeExtensionElement>,
}

impl CommonProofConstraintStreamQuotientBuilder {
    pub(super) fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        evaluation_domain: ProofEvaluationDomain,
        transformed_columns: BTreeMap<u32, ExternalPolynomialVector>,
        application_challenges: Vec<RelationApplicationChallengeAssignment>,
        composition_challenges: Vec<ProofChallengeExtensionElement>,
        maximum_external_read_chunk_byte_length: u32,
    ) -> Result<Self, CommonProofProverError> {
        if evaluation_domain.size()
            != usize::try_from(variant.evaluation_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?
            || evaluation_domain.generator().canonical() != context.evaluation_domain_generator
            || evaluation_domain.coset_offset().canonical() != context.evaluation_coset_offset
            || !variant
                .evaluation_domain_size()
                .is_multiple_of(variant.trace_domain_size())
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        if composition_challenges.len() != variant.constraint_count()
            || maximum_external_read_chunk_byte_length == 0
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let trace_domain_size = usize::try_from(variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let trace_rotation_stride =
            usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let column_value_types = variant
            .ordered_columns()
            .iter()
            .map(|column| column.value_type())
            .collect::<Vec<_>>();
        let mut constraint_queries = Vec::new();
        let mut constraint_columns = Vec::new();
        let mut remaining_constraint_use_counts = BTreeMap::new();
        constraint_queries
            .try_reserve_exact(variant.constraint_count())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        constraint_columns
            .try_reserve_exact(variant.constraint_count())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for constraint_ordinal in 0..variant.constraint_count() {
            let queries = variant.constraint_column_queries(constraint_ordinal)?;
            let columns = queries
                .iter()
                .map(|query| query.column_ordinal())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            for column_ordinal in &columns {
                let value_type = column_value_types
                    .get(
                        usize::try_from(*column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .copied()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let value_byte_length = usize::try_from(external_value_byte_length(value_type))
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                if usize::try_from(maximum_external_read_chunk_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    < value_byte_length
                {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let use_count = remaining_constraint_use_counts
                    .entry(*column_ordinal)
                    .or_insert(0usize);
                *use_count = use_count
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?;
            }
            constraint_queries.push(queries);
            constraint_columns.push(columns);
        }
        validate_seeded_transformed_columns(
            &column_value_types,
            evaluation_domain.size(),
            &remaining_constraint_use_counts,
            &transformed_columns,
        )?;
        let checked_application_challenges =
            variant.checked_application_challenges(context, &application_challenges)?;
        let mut quotient_evaluations = Zeroizing::new(Vec::new());
        quotient_evaluations
            .try_reserve_exact(evaluation_domain.size())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        quotient_evaluations.resize(
            evaluation_domain.size(),
            ProofChallengeExtensionElement::ZERO,
        );
        Ok(Self {
            evaluation_domain,
            trace_domain_size,
            trace_rotation_stride,
            column_value_types,
            constraint_queries,
            constraint_columns,
            remaining_constraint_use_counts,
            current_constraint_ordinal: 0,
            next_transform_column_index: 0,
            transformed_columns,
            block_start: 0,
            next_query_ordinal: 0,
            next_query_logical_value_offset: 0,
            block_values_by_query: Vec::new(),
            maximum_external_read_chunk_byte_length: usize::try_from(
                maximum_external_read_chunk_byte_length,
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?,
            quotient_evaluations,
            checked_application_challenges,
            composition_challenges,
        })
    }

    pub(super) fn next_transform_key(
        &mut self,
    ) -> Result<Option<CommonProofQuotientConstraintTransformKey>, CommonProofProverError> {
        if self.current_constraint_ordinal >= self.constraint_columns.len() {
            return Ok(None);
        }
        let columns = self
            .constraint_columns
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        let Some(column_ordinal) = next_untransformed_column(
            columns,
            &mut self.next_transform_column_index,
            |column_ordinal| self.transformed_columns.contains_key(&column_ordinal),
        )?
        else {
            return Ok(None);
        };
        Ok(Some(CommonProofQuotientConstraintTransformKey::new(
            u32::try_from(self.current_constraint_ordinal)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            column_ordinal,
        )))
    }

    pub(super) fn accept_transformed_column(
        &mut self,
        transform_key: CommonProofQuotientConstraintTransformKey,
        vector: ExternalPolynomialVector,
    ) -> Result<(), CommonProofProverError> {
        if vector.element_count() != self.evaluation_domain.size()
            || self
                .column_value_types
                .get(
                    usize::try_from(transform_key.column_ordinal())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .copied()
                != Some(vector.value_type())
            || self
                .transformed_columns
                .contains_key(&transform_key.column_ordinal())
            || self
                .transformed_columns
                .values()
                .any(|existing_vector| existing_vector.object() == vector.object())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if self.next_transform_key()? != Some(transform_key) {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let previous = self
            .transformed_columns
            .insert(transform_key.column_ordinal(), vector);
        debug_assert!(previous.is_none());
        self.next_transform_column_index = self
            .next_transform_column_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    fn current_block_end(&self) -> Result<usize, CommonProofProverError> {
        let block_end = self
            .block_start
            .checked_add(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(self.evaluation_domain.size());
        if block_end <= self.block_start {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        Ok(block_end)
    }

    pub(super) fn next_read_request(
        &self,
    ) -> Result<Option<CommonProofQuotientEvaluationReadRequest>, CommonProofProverError> {
        if self.current_constraint_ordinal >= self.constraint_queries.len() {
            return Ok(None);
        }
        let columns = self
            .constraint_columns
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        if self.next_transform_column_index != columns.len() {
            return Ok(None);
        }
        let queries = self
            .constraint_queries
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        let Some(query) = queries.get(self.next_query_ordinal).copied() else {
            return Ok(None);
        };
        let vector = self
            .transformed_columns
            .get(&query.column_ordinal())
            .copied()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let block_end = self.current_block_end()?;
        let block_element_count = block_end - self.block_start;
        if self.next_query_logical_value_offset >= block_element_count {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let rotated_block_start = rotated_relation_evaluation_position(
            self.block_start,
            self.evaluation_domain.size(),
            self.trace_domain_size,
            self.trace_rotation_stride,
            query.rotation_is_negative(),
            query.rotation_magnitude(),
        )?;
        let element_offset = rotated_block_start
            .checked_add(self.next_query_logical_value_offset)
            .ok_or(CommonProofProverError::CountOverflow)?
            % self.evaluation_domain.size();
        let maximum_chunk_element_count = self
            .maximum_external_read_chunk_byte_length
            .checked_div(
                usize::try_from(external_value_byte_length(vector.value_type()))
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .filter(|count| *count != 0)
            .ok_or(CommonProofProverError::InvalidInput)?;
        let element_count = (block_element_count - self.next_query_logical_value_offset)
            .min(self.evaluation_domain.size() - element_offset)
            .min(maximum_chunk_element_count);
        if element_count == 0 {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        Ok(Some(CommonProofQuotientEvaluationReadRequest {
            transform_key: CommonProofQuotientConstraintTransformKey::new(
                u32::try_from(self.current_constraint_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                query.column_ordinal(),
            ),
            query_ordinal: self.next_query_ordinal,
            logical_value_offset: self.next_query_logical_value_offset,
            vector,
            element_offset,
            element_count,
        }))
    }

    pub(super) fn accept_read_values(
        &mut self,
        request: CommonProofQuotientEvaluationReadRequest,
        values: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ) -> Result<(), CommonProofProverError> {
        if self.next_read_request()? != Some(request) || values.len() != request.element_count {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let block_element_count = self.current_block_end()? - self.block_start;
        if self.block_values_by_query.len() == request.query_ordinal {
            let mut query_values = Vec::new();
            query_values
                .try_reserve_exact(block_element_count)
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            self.block_values_by_query
                .push(Zeroizing::new(query_values));
        }
        let query_values = self
            .block_values_by_query
            .get_mut(request.query_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        if query_values.len() != request.logical_value_offset {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        query_values.extend(values.iter().copied());
        self.next_query_logical_value_offset = self
            .next_query_logical_value_offset
            .checked_add(values.len())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.next_query_logical_value_offset == block_element_count {
            self.next_query_ordinal = self
                .next_query_ordinal
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            self.next_query_logical_value_offset = 0;
        }
        Ok(())
    }

    pub(super) fn evaluate_ready_block(
        &mut self,
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Result<CommonProofQuotientEvaluationProgress, CommonProofProverError> {
        let queries = self
            .constraint_queries
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        let columns = self
            .constraint_columns
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        if self.block_start >= self.evaluation_domain.size()
            || self.next_transform_column_index != columns.len()
            || columns
                .iter()
                .any(|column_ordinal| !self.transformed_columns.contains_key(column_ordinal))
            || self.next_query_ordinal != queries.len()
            || self.next_query_logical_value_offset != 0
            || self.block_values_by_query.len() != queries.len()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let block_end = self.current_block_end()?;
        let composition_challenge = self
            .composition_challenges
            .get(self.current_constraint_ordinal)
            .copied()
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        for evaluation_position in self.block_start..block_end {
            let block_position = evaluation_position - self.block_start;
            let evaluation_point = ProofChallengeExtensionElement::from_base(
                self.evaluation_domain.point(evaluation_position)?,
            );
            let mut column_value = |column_ordinal, rotation_is_negative, rotation_magnitude| {
                let query_index = queries
                    .binary_search_by_key(
                        &(column_ordinal, rotation_is_negative, rotation_magnitude),
                        |query| {
                            (
                                query.column_ordinal(),
                                query.rotation_is_negative(),
                                query.rotation_magnitude(),
                            )
                        },
                    )
                    .map_err(|_| RelationPlanError::InvalidOpening)?;
                self.block_values_by_query
                    .get(query_index)
                    .and_then(|values| values.get(block_position))
                    .copied()
                    .ok_or(RelationPlanError::InvalidConstraint)
            };
            let evaluation = variant
                .evaluate_constraint_at_point(
                    context,
                    self.current_constraint_ordinal,
                    evaluation_point,
                    &self.checked_application_challenges,
                    &mut column_value,
                )
                .map_err(CommonProofProverError::from)?;
            let normalized = evaluation
                .numerator
                .divide(evaluation.zeroifier)
                .map_err(|_| CommonProofProverError::from(RelationPlanError::InvalidZeroifier))?;
            let quotient_evaluation = self
                .quotient_evaluations
                .get_mut(evaluation_position)
                .ok_or(CommonProofProverError::InvalidQuotient)?;
            *quotient_evaluation =
                quotient_evaluation.add(normalized.multiply(composition_challenge));
        }
        self.block_values_by_query.clear();
        self.next_query_ordinal = 0;
        self.next_query_logical_value_offset = 0;
        self.block_start = block_end;
        Ok(if self.block_start == self.evaluation_domain.size() {
            CommonProofQuotientEvaluationProgress::ConstraintComplete
        } else {
            CommonProofQuotientEvaluationProgress::BlockComplete
        })
    }

    pub(super) fn complete_constraint(&mut self) -> Result<bool, CommonProofProverError> {
        if self.current_constraint_ordinal >= self.constraint_queries.len()
            || self.block_start != self.evaluation_domain.size()
            || !self.block_values_by_query.is_empty()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let constraint_columns = self
            .constraint_columns
            .get(self.current_constraint_ordinal)
            .ok_or(CommonProofProverError::InvalidQuotient)?;
        retire_transformed_columns_after_constraint(
            constraint_columns,
            &mut self.remaining_constraint_use_counts,
            &mut self.transformed_columns,
        )?;
        self.current_constraint_ordinal = self
            .current_constraint_ordinal
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.next_transform_column_index = 0;
        self.block_start = 0;
        self.next_query_ordinal = 0;
        self.next_query_logical_value_offset = 0;
        Ok(self.current_constraint_ordinal == self.constraint_queries.len())
    }

    pub(super) fn finish(
        mut self,
    ) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
        if self.current_constraint_ordinal != self.constraint_queries.len()
            || self.block_start != 0
            || self.quotient_evaluations.len() != self.evaluation_domain.size()
            || !self.block_values_by_query.is_empty()
            || !self.remaining_constraint_use_counts.is_empty()
            || !self.transformed_columns.is_empty()
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.evaluation_domain
            .interpolate_extension_polynomial_in_place(&mut self.quotient_evaluations)?;
        trim_extension_polynomial(&mut self.quotient_evaluations);
        Ok(self.quotient_evaluations)
    }
}

fn validate_seeded_transformed_columns(
    column_value_types: &[RelationColumnValueType],
    evaluation_domain_size: usize,
    remaining_constraint_use_counts: &BTreeMap<u32, usize>,
    transformed_columns: &BTreeMap<u32, ExternalPolynomialVector>,
) -> Result<(), CommonProofProverError> {
    let mut seeded_objects = BTreeSet::new();
    for (column_ordinal, vector) in transformed_columns {
        if vector.element_count() != evaluation_domain_size
            || column_value_types
                .get(
                    usize::try_from(*column_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .copied()
                != Some(vector.value_type())
            || remaining_constraint_use_counts
                .get(column_ordinal)
                .is_none_or(|use_count| *use_count == 0)
            || !seeded_objects.insert(vector.object())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
    }
    Ok(())
}

fn retire_transformed_columns_after_constraint(
    constraint_columns: &[u32],
    remaining_constraint_use_counts: &mut BTreeMap<u32, usize>,
    transformed_columns: &mut BTreeMap<u32, ExternalPolynomialVector>,
) -> Result<(), CommonProofProverError> {
    if constraint_columns.is_empty()
        || constraint_columns
            .windows(2)
            .any(|adjacent| adjacent[0] >= adjacent[1])
        || constraint_columns.iter().any(|column_ordinal| {
            remaining_constraint_use_counts
                .get(column_ordinal)
                .is_none_or(|use_count| *use_count == 0)
                || !transformed_columns.contains_key(column_ordinal)
        })
    {
        return Err(CommonProofProverError::InvalidColumn);
    }

    for column_ordinal in constraint_columns {
        let remaining_use_count = remaining_constraint_use_counts
            .get_mut(column_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        *remaining_use_count = remaining_use_count
            .checked_sub(1)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if *remaining_use_count == 0 {
            remaining_constraint_use_counts.remove(column_ordinal);
            transformed_columns
                .remove(column_ordinal)
                .ok_or(CommonProofProverError::InvalidColumn)?;
        }
    }
    Ok(())
}

fn next_untransformed_column(
    columns: &[u32],
    next_column_index: &mut usize,
    mut column_is_transformed: impl FnMut(u32) -> bool,
) -> Result<Option<u32>, CommonProofProverError> {
    while columns
        .get(*next_column_index)
        .copied()
        .is_some_and(&mut column_is_transformed)
    {
        *next_column_index = next_column_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    Ok(columns.get(*next_column_index).copied())
}

/// Splits the unique quotient into constant-first components of width `kHat`.
#[cfg(test)]
pub(crate) fn decompose_composed_quotient(
    quotient: &[ProofChallengeExtensionElement],
    component_count: u32,
    component_stride: u64,
) -> Result<Vec<Zeroizing<Vec<ProofChallengeExtensionElement>>>, CommonProofProverError> {
    let component_count =
        usize::try_from(component_count).map_err(|_| CommonProofProverError::CountOverflow)?;
    let component_stride =
        usize::try_from(component_stride).map_err(|_| CommonProofProverError::CountOverflow)?;
    if component_count < 2 || component_stride == 0 || quotient.is_empty() {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let capacity = component_count
        .checked_mul(component_stride)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if quotient.len() > capacity {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let mut components = Vec::new();
    components
        .try_reserve_exact(component_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for component_ordinal in 0..component_count {
        let start = component_ordinal
            .checked_mul(component_stride)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let end = start
            .checked_add(component_stride)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(quotient.len());
        let mut component = Zeroizing::new(if start < quotient.len() {
            quotient[start..end].to_vec()
        } else {
            vec![ProofChallengeExtensionElement::ZERO]
        });
        trim_extension_polynomial(&mut component);
        components.push(component);
    }
    Ok(components)
}

pub(crate) struct CommonProofQuotientComponentCursor {
    quotient: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    stride: usize,
    component_count: usize,
    component_degree_bound_exclusive: usize,
    telescoping_descriptors: Vec<RelationMaskDescriptor>,
    previous_randomizer: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    next_component_index: usize,
}

impl CommonProofQuotientComponentCursor {
    pub(crate) fn new(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        quotient: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ) -> Result<Self, CommonProofProverError> {
        let stride = usize::try_from(variant.quotient_decomposition_stride(context)?)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let component_count = usize::try_from(context.quotient_component_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let component_degree_bound_exclusive =
            usize::try_from(context.quotient_component_degree_bound_exclusive)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        if stride == 0
            || component_count < 2
            || component_degree_bound_exclusive == 0
            || quotient.is_empty()
            || quotient.len()
                > stride
                    .checked_mul(component_count)
                    .ok_or(CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let telescoping_descriptors = variant
            .ordered_masks()
            .iter()
            .copied()
            .filter(|mask| {
                mask.mask_kind() == RelationMaskKind::Telescoping
                    && mask.target_class() == RelationMaskTargetClass::QuotientComponent
            })
            .collect::<Vec<_>>();
        match variant.proof_privacy_mode() {
            ProofPrivacyMode::PublicOnly if !variant.ordered_masks().is_empty() => {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::PublicOnly if !telescoping_descriptors.is_empty() => {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::SecretBearing
                if telescoping_descriptors.len() + 1 != component_count
                    || telescoping_descriptors
                        .iter()
                        .enumerate()
                        .any(|(ordinal, mask)| {
                            usize::try_from(mask.target_ordinal()).ok() != Some(ordinal)
                        }) =>
            {
                return Err(CommonProofProverError::InvalidMask);
            }
            ProofPrivacyMode::PublicOnly | ProofPrivacyMode::SecretBearing => {}
        }
        Ok(Self {
            quotient,
            stride,
            component_count,
            component_degree_bound_exclusive,
            telescoping_descriptors,
            previous_randomizer: None,
            next_component_index: 0,
        })
    }

    pub(crate) fn next_component<Coins: CommonProofPrivateCoinSource>(
        &mut self,
        coins: &mut Coins,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<
        Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
        CommonProofPrivateCoinError<Coins::Error>,
    > {
        if self.next_component_index >= self.component_count {
            if self.previous_randomizer.is_some() {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidMask,
                ));
            }
            return Ok(None);
        }
        let component_index = self.next_component_index;
        let mut component = Zeroizing::new(
            self.quotient
                .iter()
                .skip(component_index.checked_mul(self.stride).ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
                })?)
                .take(self.stride)
                .copied()
                .collect::<Vec<_>>(),
        );
        if component.is_empty() {
            component.push(ProofChallengeExtensionElement::ZERO);
        }
        let next_randomizer =
            if let Some(descriptor) = self.telescoping_descriptors.get(component_index).copied() {
                let randomizer = sample_private_extension_polynomial(
                    coins,
                    CommonProofPrivateCoinCoordinate::from_mask(descriptor.mask_coordinate()),
                    descriptor.mask_degree_bound_exclusive(),
                    maximum_candidate_draws_per_output,
                )?;
                add_shifted_extension_polynomial(&mut component, &randomizer, self.stride)
                    .map_err(CommonProofPrivateCoinError::Prover)?;
                Some(randomizer)
            } else {
                None
            };
        if let Some(previous_randomizer) = self.previous_randomizer.take() {
            subtract_extension_polynomial(&mut component, &previous_randomizer)
                .map_err(CommonProofPrivateCoinError::Prover)?;
        }
        trim_extension_polynomial(&mut component);
        if component.len() > self.component_degree_bound_exclusive {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidQuotient,
            ));
        }
        self.previous_randomizer = next_randomizer;
        self.next_component_index = self.next_component_index.checked_add(1).ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        Ok(Some(component))
    }
}

#[cfg(test)]
mod reusable_transform_tests {
    use super::{
        BTreeMap, BTreeSet, CommonProofProverError, ExternalPolynomialVector,
        ProofExternalMemoryObject, RelationColumnValueType, next_untransformed_column,
        retire_transformed_columns_after_constraint, validate_seeded_transformed_columns,
    };

    fn transformed_vector(
        object_ordinal: u32,
        value_type: RelationColumnValueType,
        element_count: usize,
    ) -> ExternalPolynomialVector {
        ExternalPolynomialVector::new(
            ProofExternalMemoryObject::new(object_ordinal),
            value_type,
            element_count,
        )
        .expect("the test vector has a nonzero element count")
    }

    #[test]
    fn transformed_columns_are_requested_once_across_nonconsecutive_constraints() {
        let constraint_columns = [vec![2, 4, 7], vec![9], vec![4, 7], vec![2, 9]];
        let mut transformed_columns = BTreeSet::new();
        let mut transform_requests = Vec::new();

        for columns in constraint_columns {
            let mut next_column_index = 0;
            while let Some(column_ordinal) =
                next_untransformed_column(&columns, &mut next_column_index, |column_ordinal| {
                    transformed_columns.contains(&column_ordinal)
                })
                .expect("the transform request index remains in range")
            {
                transform_requests.push(column_ordinal);
                assert!(transformed_columns.insert(column_ordinal));
                next_column_index += 1;
            }
        }

        assert_eq!(transform_requests, vec![2, 4, 7, 9]);
    }

    #[test]
    fn transformed_columns_retire_only_after_their_last_nonconsecutive_constraint() {
        let base_vector = transformed_vector(20, RelationColumnValueType::BaseField, 16);
        let extension_vector =
            transformed_vector(21, RelationColumnValueType::ChallengeExtension, 16);
        let mut transformed_columns = BTreeMap::from([(2, base_vector), (7, extension_vector)]);
        let mut remaining_constraint_use_counts = BTreeMap::from([(2, 2), (7, 1)]);

        retire_transformed_columns_after_constraint(
            &[2],
            &mut remaining_constraint_use_counts,
            &mut transformed_columns,
        )
        .expect("the first use retains the nonconsecutive column");
        assert_eq!(
            remaining_constraint_use_counts,
            BTreeMap::from([(2, 1), (7, 1)])
        );
        assert_eq!(transformed_columns.get(&2), Some(&base_vector));

        retire_transformed_columns_after_constraint(
            &[7],
            &mut remaining_constraint_use_counts,
            &mut transformed_columns,
        )
        .expect("the single-use extension column retires");
        assert!(!remaining_constraint_use_counts.contains_key(&7));
        assert!(!transformed_columns.contains_key(&7));
        assert_eq!(transformed_columns.get(&2), Some(&base_vector));

        retire_transformed_columns_after_constraint(
            &[2],
            &mut remaining_constraint_use_counts,
            &mut transformed_columns,
        )
        .expect("the final nonconsecutive use retires the base column");
        assert!(remaining_constraint_use_counts.is_empty());
        assert!(transformed_columns.is_empty());
    }

    #[test]
    fn seeded_transformed_columns_reject_wrong_shape_usage_and_object_aliasing() {
        let column_value_types = [
            RelationColumnValueType::BaseField,
            RelationColumnValueType::ChallengeExtension,
            RelationColumnValueType::BaseField,
        ];
        let remaining_constraint_use_counts = BTreeMap::from([(0, 1), (1, 2)]);
        let valid_base_vector = transformed_vector(30, RelationColumnValueType::BaseField, 16);
        let valid_extension_vector =
            transformed_vector(31, RelationColumnValueType::ChallengeExtension, 16);
        assert_eq!(
            validate_seeded_transformed_columns(
                &column_value_types,
                16,
                &remaining_constraint_use_counts,
                &BTreeMap::from([(0, valid_base_vector), (1, valid_extension_vector)]),
            ),
            Ok(()),
        );

        let invalid_seeds = [
            BTreeMap::from([(
                0,
                transformed_vector(32, RelationColumnValueType::BaseField, 8),
            )]),
            BTreeMap::from([(
                0,
                transformed_vector(33, RelationColumnValueType::ChallengeExtension, 16),
            )]),
            BTreeMap::from([(
                2,
                transformed_vector(34, RelationColumnValueType::BaseField, 16),
            )]),
            BTreeMap::from([(
                9,
                transformed_vector(35, RelationColumnValueType::BaseField, 16),
            )]),
            BTreeMap::from([
                (
                    0,
                    transformed_vector(36, RelationColumnValueType::BaseField, 16),
                ),
                (
                    1,
                    transformed_vector(36, RelationColumnValueType::ChallengeExtension, 16),
                ),
            ]),
        ];
        for invalid_seed in invalid_seeds {
            assert_eq!(
                validate_seeded_transformed_columns(
                    &column_value_types,
                    16,
                    &remaining_constraint_use_counts,
                    &invalid_seed,
                ),
                Err(CommonProofProverError::InvalidColumn),
            );
        }
    }

    #[test]
    fn invalid_retirement_does_not_partially_consume_valid_columns() {
        let first_vector = transformed_vector(40, RelationColumnValueType::BaseField, 16);
        let mut transformed_columns = BTreeMap::from([(2, first_vector)]);
        let mut remaining_constraint_use_counts = BTreeMap::from([(2, 1), (7, 1)]);

        assert_eq!(
            retire_transformed_columns_after_constraint(
                &[2, 7],
                &mut remaining_constraint_use_counts,
                &mut transformed_columns,
            ),
            Err(CommonProofProverError::InvalidColumn),
        );
        assert_eq!(
            remaining_constraint_use_counts,
            BTreeMap::from([(2, 1), (7, 1)])
        );
        assert_eq!(transformed_columns, BTreeMap::from([(2, first_vector)]));
    }
}
