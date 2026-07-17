use super::{
    BTreeMap, BTreeSet, CommonProofChallenge, CommonProofPrivateCoinSource, CommonProofProverError,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain, ProofPrivacyMode,
    ProofTreeRole, ProofTreeValue, RelationApplicationChallengeAssignment,
    RelationColumnDescriptor, RelationColumnOrigin, RelationColumnValueType,
    RelationIntegerLiftCoefficient, RelationIntegerLiftComponentDescriptor,
    RelationIntegerLiftConvolutionKind, RelationIntegerLiftConvolutionProductDescriptor,
    RelationIntegerLiftFullRingHalf, RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    RelationIntegerLiftLinearTermDescriptor,
    RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor, RelationMaskDescriptor,
    RelationMaskKind, RelationMaskTargetClass, RelationPlanCheckContext, RelationPlanVariant,
    RelationTreeDescriptor, SuiteModulusReference, evaluate_extension_at, trim_base_polynomial,
    trim_extension_polynomial, validate_column_polynomials,
};

/// One plan-addressed source polynomial.  Coefficients are constant-first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofSourcePolynomial {
    Base(Vec<ProofBaseFieldElement>),
    Extension(Vec<ProofChallengeExtensionElement>),
}

impl CommonProofSourcePolynomial {
    pub(crate) fn value_type(&self) -> RelationColumnValueType {
        match self {
            Self::Base(_) => RelationColumnValueType::BaseField,
            Self::Extension(_) => RelationColumnValueType::ChallengeExtension,
        }
    }

    pub(crate) fn coefficient_count(&self) -> usize {
        match self {
            Self::Base(coefficients) => coefficients.len(),
            Self::Extension(coefficients) => coefficients.len(),
        }
    }

    pub(crate) fn evaluate_at(
        &self,
        point: ProofChallengeExtensionElement,
    ) -> ProofChallengeExtensionElement {
        match self {
            Self::Base(coefficients) => coefficients.iter().rev().fold(
                ProofChallengeExtensionElement::ZERO,
                |accumulated, coefficient| {
                    accumulated
                        .multiply(point)
                        .add(ProofChallengeExtensionElement::from_base(*coefficient))
                },
            ),
            Self::Extension(coefficients) => evaluate_extension_at(coefficients, point),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofColumnEvaluations {
    Base(Vec<ProofBaseFieldElement>),
    Extension(Vec<ProofChallengeExtensionElement>),
}

impl CommonProofColumnEvaluations {
    pub(super) fn extension_value(
        &self,
        position: usize,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        match self {
            Self::Base(values) => values
                .get(position)
                .copied()
                .map(ProofChallengeExtensionElement::from_base),
            Self::Extension(values) => values.get(position).copied(),
        }
        .ok_or(CommonProofProverError::InvalidColumn)
    }

    fn tree_value(&self, position: usize) -> Result<ProofTreeValue, CommonProofProverError> {
        match self {
            Self::Base(values) => values.get(position).copied().map(ProofTreeValue::Base),
            Self::Extension(values) => values.get(position).copied().map(ProofTreeValue::Extension),
        }
        .ok_or(CommonProofProverError::InvalidColumn)
    }
}

/// Evaluates one homogeneous tree row at a time.  Callers should materialize
/// and discard each relation tree before evaluating the next one; peak working
/// memory is therefore one tree row rather than the complete oracle catalog.
pub(crate) fn evaluate_common_proof_tree_columns(
    evaluation_domain: &ProofEvaluationDomain,
    columns: &[CommonProofSourcePolynomial],
    ordered_column_ordinals: &[u32],
) -> Result<Vec<CommonProofColumnEvaluations>, CommonProofProverError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofProverError::InvalidTree);
    }
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(ordered_column_ordinals.len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut expected_value_type = None;
    for column_ordinal in ordered_column_ordinals {
        let column = columns
            .get(
                usize::try_from(*column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let value_type = column.value_type();
        match expected_value_type {
            None => expected_value_type = Some(value_type),
            Some(expected) if expected == value_type => {}
            Some(_) => return Err(CommonProofProverError::InvalidTree),
        }
        evaluations.push(match column {
            CommonProofSourcePolynomial::Base(coefficients) => CommonProofColumnEvaluations::Base(
                evaluation_domain.evaluate_base_polynomial(coefficients)?,
            ),
            CommonProofSourcePolynomial::Extension(coefficients) => {
                CommonProofColumnEvaluations::Extension(
                    evaluation_domain.evaluate_extension_polynomial(coefficients)?,
                )
            }
        });
    }
    Ok(evaluations)
}

/// Evaluates a base tree while auxiliary columns are intentionally absent.
/// The requested ordinals must all have been constructed in the
/// pre-challenge phase.
pub(crate) fn evaluate_pre_challenge_common_proof_tree_columns(
    evaluation_domain: &ProofEvaluationDomain,
    columns: &CommonProofPreChallengeRelationColumns,
    ordered_column_ordinals: &[u32],
) -> Result<Vec<CommonProofColumnEvaluations>, CommonProofProverError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofProverError::InvalidTree);
    }
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(ordered_column_ordinals.len())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut expected_value_type = None;
    for column_ordinal in ordered_column_ordinals {
        let column = columns
            .column(*column_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let value_type = column.value_type();
        match expected_value_type {
            None => expected_value_type = Some(value_type),
            Some(expected) if expected == value_type => {}
            Some(_) => return Err(CommonProofProverError::InvalidTree),
        }
        evaluations.push(match column {
            CommonProofSourcePolynomial::Base(coefficients) => CommonProofColumnEvaluations::Base(
                evaluation_domain.evaluate_base_polynomial(coefficients)?,
            ),
            CommonProofSourcePolynomial::Extension(coefficients) => {
                CommonProofColumnEvaluations::Extension(
                    evaluation_domain.evaluate_extension_polynomial(coefficients)?,
                )
            }
        });
    }
    Ok(evaluations)
}

/// Samples one uniform base-field polynomial of degree below the exclusive
/// bound from its plan-assigned private stream.
pub(crate) fn sample_private_base_polynomial<Coins>(
    coins: &mut Coins,
    purpose: u16,
    degree_bound_exclusive: u64,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let coefficient_count = usize::try_from(degree_bound_exclusive)
        .map_err(|_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow))?;
    if coefficient_count == 0 {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    let mut coefficients = Vec::new();
    coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
        })?;
    for _ in 0..coefficient_count {
        let coordinate = coins
            .sample_modulo(
                purpose,
                super::super::PROOF_BASE_FIELD_MODULUS,
                maximum_candidate_draws_per_output,
            )
            .map_err(CommonProofPrivateCoinError::CoinSource)?;
        coefficients.push(
            ProofBaseFieldElement::from_canonical(coordinate)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
    }
    Ok(coefficients)
}

/// Samples one uniform challenge-extension polynomial.  Coordinates are read
/// in constant-first extension basis order for each increasing coefficient.
pub(crate) fn sample_private_extension_polynomial<Coins>(
    coins: &mut Coins,
    purpose: u16,
    degree_bound_exclusive: u64,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let coefficient_count = usize::try_from(degree_bound_exclusive)
        .map_err(|_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow))?;
    if coefficient_count == 0 {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidMask,
        ));
    }
    let mut coefficients = Vec::new();
    coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::AllocationLimitExceeded)
        })?;
    for _ in 0..coefficient_count {
        let mut coordinates = [0_u64; super::super::PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            *coordinate = coins
                .sample_modulo(
                    purpose,
                    super::super::PROOF_BASE_FIELD_MODULUS,
                    maximum_candidate_draws_per_output,
                )
                .map_err(CommonProofPrivateCoinError::CoinSource)?;
        }
        coefficients.push(
            ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
    }
    Ok(coefficients)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommonProofPrivateCoinError<CoinError> {
    Prover(CommonProofProverError),
    CoinSource(CoinError),
}

/// Applies `witness + (X^H - 1) mask` without changing coefficient order.
pub(crate) fn apply_trace_mask(
    witness: CommonProofSourcePolynomial,
    trace_domain_size: u64,
    mask: CommonProofSourcePolynomial,
) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
    let trace_domain_size =
        usize::try_from(trace_domain_size).map_err(|_| CommonProofProverError::CountOverflow)?;
    if trace_domain_size == 0 || mask.coefficient_count() == 0 {
        return Err(CommonProofProverError::InvalidMask);
    }
    match (witness, mask) {
        (CommonProofSourcePolynomial::Base(witness), CommonProofSourcePolynomial::Base(mask)) => {
            let output_length = trace_domain_size
                .checked_add(mask.len())
                .ok_or(CommonProofProverError::CountOverflow)?;
            let mut output = vec![ProofBaseFieldElement::ZERO; output_length.max(witness.len())];
            for (destination, coefficient) in output.iter_mut().zip(witness) {
                *destination = destination.add(coefficient);
            }
            for (mask_ordinal, coefficient) in mask.into_iter().enumerate() {
                output[mask_ordinal] = output[mask_ordinal].subtract(coefficient);
                let shifted_ordinal = trace_domain_size
                    .checked_add(mask_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                output[shifted_ordinal] = output[shifted_ordinal].add(coefficient);
            }
            trim_base_polynomial(&mut output);
            Ok(CommonProofSourcePolynomial::Base(output))
        }
        (
            CommonProofSourcePolynomial::Extension(witness),
            CommonProofSourcePolynomial::Extension(mask),
        ) => {
            let output_length = trace_domain_size
                .checked_add(mask.len())
                .ok_or(CommonProofProverError::CountOverflow)?;
            let mut output =
                vec![ProofChallengeExtensionElement::ZERO; output_length.max(witness.len())];
            for (destination, coefficient) in output.iter_mut().zip(witness) {
                *destination = destination.add(coefficient);
            }
            for (mask_ordinal, coefficient) in mask.into_iter().enumerate() {
                output[mask_ordinal] = output[mask_ordinal].subtract(coefficient);
                let shifted_ordinal = trace_domain_size
                    .checked_add(mask_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                output[shifted_ordinal] = output[shifted_ordinal].add(coefficient);
            }
            trim_extension_polynomial(&mut output);
            Ok(CommonProofSourcePolynomial::Extension(output))
        }
        _ => Err(CommonProofProverError::InvalidMask),
    }
}

/// Columns constructed before the common transcript releases the complete
/// non-native challenge vector.  Auxiliary-tree entries remain absent, so a
/// caller cannot accidentally commit a challenge-dependent column early.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofPreChallengeRelationColumns {
    columns: Vec<Option<CommonProofSourcePolynomial>>,
}

impl CommonProofPreChallengeRelationColumns {
    pub(crate) fn column(&self, column_ordinal: u32) -> Option<&CommonProofSourcePolynomial> {
        self.columns
            .get(usize::try_from(column_ordinal).ok()?)
            .and_then(Option::as_ref)
    }
}

/// Constructs and masks every column committed before the application
/// challenges.  Callers provide only the plan's genuine pre-challenge input
/// columns.  Reversed multiplier columns are derived here from their checked
/// source descriptors; supplying either a reversed or an auxiliary column is
/// rejected.
pub(crate) fn construct_pre_challenge_relation_columns<Coins>(
    variant: &RelationPlanVariant,
    mut provided_columns: BTreeMap<u32, CommonProofSourcePolynomial>,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<CommonProofPreChallengeRelationColumns, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let tree_roles =
        proof_created_tree_roles_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let (reversed_columns_by_source, integer_lift_auxiliary_columns) =
        integer_lift_derived_columns(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let reversed_columns = reversed_columns_by_source
        .values()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut columns = vec![None; variant.ordered_columns().len()];

    for (column_index, (column_slot, descriptor)) in columns
        .iter_mut()
        .zip(variant.ordered_columns())
        .enumerate()
    {
        let column_ordinal = u32::try_from(column_index).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let is_auxiliary_tree_column =
            tree_roles.get(&column_ordinal) == Some(&ProofTreeRole::AuxiliaryOracle);
        if reversed_columns.contains(&column_ordinal)
            || integer_lift_auxiliary_columns.contains(&column_ordinal)
            || is_auxiliary_tree_column
        {
            if provided_columns.contains_key(&column_ordinal) {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            continue;
        }
        let source = provided_columns.remove(&column_ordinal).ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
        })?;
        validate_source_column(descriptor, &source, variant.trace_domain_size())
            .map_err(CommonProofPrivateCoinError::Prover)?;
        *column_slot = Some(source);
    }
    if !provided_columns.is_empty() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }

    let trace_domain =
        ProofEvaluationDomain::new_subgroup(usize::try_from(variant.trace_domain_size()).map_err(
            |_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow),
        )?)
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    for (source_ordinal, reversed_ordinal) in reversed_columns_by_source {
        let source = columns
            .get(usize::try_from(source_ordinal).map_err(|_| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let mut reversed_rows =
            base_trace_rows(source, trace_domain).map_err(CommonProofPrivateCoinError::Prover)?;
        reversed_rows.reverse();
        let reversed_polynomial = CommonProofSourcePolynomial::Base(
            trace_domain
                .interpolate_base_polynomial(&reversed_rows)
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofPrivateCoinError::Prover)?,
        );
        let destination = columns
            .get_mut(usize::try_from(reversed_ordinal).map_err(|_| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
            })?)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        if destination.replace(reversed_polynomial).is_some() {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
    }

    let trace_masks =
        trace_masks_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
        let column_ordinal = u32::try_from(column_index).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        match tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::BaseOracle) => {
                let source = columns[column_index].take().ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
                })?;
                columns[column_index] = Some(mask_relation_column(
                    variant,
                    descriptor,
                    trace_masks.get(&column_ordinal).copied(),
                    source,
                    coins,
                    maximum_candidate_draws_per_output,
                )?);
            }
            Some(ProofTreeRole::AuxiliaryOracle) => {
                if columns[column_index].is_some() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
            Some(_) => {
                return Err(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            }
            None => {
                if columns[column_index].is_none() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
        }
    }
    Ok(CommonProofPreChallengeRelationColumns { columns })
}

/// Synthesizes every auxiliary column from the checked integer-lift
/// descriptors and the complete transcript challenge vector, then applies the
/// plan-assigned masks.  The function handles every batch in one call so no
/// prover message can be inserted between consecutive theta or alpha draws.
pub(crate) fn construct_post_challenge_relation_columns<Coins>(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    mut pre_challenge_columns: CommonProofPreChallengeRelationColumns,
    application_challenges: &[RelationApplicationChallengeAssignment],
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<CommonProofSourcePolynomial>, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    if pre_challenge_columns.columns.len() != variant.ordered_columns().len() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let tree_roles =
        proof_created_tree_roles_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let (_, integer_lift_auxiliary_columns) =
        integer_lift_derived_columns(variant).map_err(CommonProofPrivateCoinError::Prover)?;
    let trace_masks =
        trace_masks_by_column(variant).map_err(CommonProofPrivateCoinError::Prover)?;

    for column_index in 0..variant.ordered_columns().len() {
        let column_ordinal = u32::try_from(column_index).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?;
        match tree_roles.get(&column_ordinal) {
            Some(ProofTreeRole::AuxiliaryOracle) => {
                if !integer_lift_auxiliary_columns.contains(&column_ordinal)
                    || pre_challenge_columns.columns[column_index].is_some()
                {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
            _ => {
                if pre_challenge_columns.columns[column_index].is_none() {
                    return Err(CommonProofPrivateCoinError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
        }
    }

    let trace_domain =
        ProofEvaluationDomain::new_subgroup(usize::try_from(variant.trace_domain_size()).map_err(
            |_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow),
        )?)
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let auxiliary_trace_row_context = AuxiliaryTraceRowInsertionContext::new(
        variant,
        &tree_roles,
        &trace_masks,
        trace_domain,
        maximum_candidate_draws_per_output,
    );
    let mut trace_rows_by_column = BTreeMap::<u32, Vec<ProofBaseFieldElement>>::new();

    for batch in variant.ordered_integer_lift_batches() {
        let theta = integer_lift_theta(
            variant,
            context,
            batch.modulus_reference(),
            batch.challenge_ordinal(),
            application_challenges,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;

        for permutation in &batch.ordered_negacyclic_automorphism_permutations {
            synthesize_negacyclic_automorphism_permutation(
                variant,
                permutation,
                theta,
                &tree_roles,
                &trace_masks,
                &mut pre_challenge_columns.columns,
                &mut trace_rows_by_column,
                trace_domain,
                coins,
                maximum_candidate_draws_per_output,
            )?;
        }

        for binding in &batch.ordered_reversed_column_bindings {
            ensure_base_trace_rows(
                &pre_challenge_columns.columns,
                &mut trace_rows_by_column,
                binding.source_column_ordinal,
                trace_domain,
            )
            .map_err(CommonProofPrivateCoinError::Prover)?;
            ensure_base_trace_rows(
                &pre_challenge_columns.columns,
                &mut trace_rows_by_column,
                binding.reversed_column_ordinal,
                trace_domain,
            )
            .map_err(CommonProofPrivateCoinError::Prover)?;
            let source_rows = trace_rows_by_column
                .get(&binding.source_column_ordinal)
                .ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
                })?;
            let reversed_rows = trace_rows_by_column
                .get(&binding.reversed_column_ordinal)
                .ok_or_else(|| {
                    CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
                })?;
            let prefix_rows = prefix_evaluation_rows(source_rows, theta);
            let suffix_rows = suffix_evaluation_rows(reversed_rows, theta);
            insert_auxiliary_trace_rows(
                auxiliary_trace_row_context,
                &mut pre_challenge_columns.columns,
                binding.source_prefix_evaluation_column_ordinal,
                prefix_rows,
                coins,
            )?;
            insert_auxiliary_trace_rows(
                auxiliary_trace_row_context,
                &mut pre_challenge_columns.columns,
                binding.reversed_suffix_evaluation_column_ordinal,
                suffix_rows,
                coins,
            )?;
        }

        for component in &batch.ordered_components {
            let linear_rows = integer_lift_linear_evaluation_rows(
                context,
                batch.modulus_reference(),
                component,
                theta,
                &pre_challenge_columns.columns,
                &mut trace_rows_by_column,
                trace_domain,
            )
            .map_err(CommonProofPrivateCoinError::Prover)?;
            let mut product_rows = vec![ProofBaseFieldElement::ZERO; trace_domain.size()];

            for product in &component.ordered_convolution_products {
                synthesize_convolution_product(
                    variant,
                    product,
                    theta,
                    &tree_roles,
                    &trace_masks,
                    &mut pre_challenge_columns.columns,
                    &mut trace_rows_by_column,
                    &mut product_rows,
                    trace_domain,
                    coins,
                    maximum_candidate_draws_per_output,
                )?;
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                synthesize_full_ring_product(
                    variant,
                    product,
                    theta,
                    &tree_roles,
                    &trace_masks,
                    &mut pre_challenge_columns.columns,
                    &mut trace_rows_by_column,
                    &mut product_rows,
                    trace_domain,
                    coins,
                    maximum_candidate_draws_per_output,
                )?;
            }

            let accumulator_rows = product_accumulator_rows(&product_rows);
            insert_auxiliary_trace_rows(
                auxiliary_trace_row_context,
                &mut pre_challenge_columns.columns,
                component.linear_evaluation_column_ordinal,
                linear_rows,
                coins,
            )?;
            insert_auxiliary_trace_rows(
                auxiliary_trace_row_context,
                &mut pre_challenge_columns.columns,
                component.product_accumulator_column_ordinal,
                accumulator_rows,
                coins,
            )?;
        }
    }

    let columns = pre_challenge_columns
        .columns
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
        })?;
    validate_column_polynomials(variant, &columns).map_err(CommonProofPrivateCoinError::Prover)?;
    Ok(columns)
}

fn proof_created_tree_roles_by_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, ProofTreeRole>, CommonProofProverError> {
    let mut roles = BTreeMap::new();
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::ProofCreated {
            proof_tree_role,
            ordered_column_ordinals,
        } = tree
        else {
            continue;
        };
        let role = match *proof_tree_role {
            value if value == ProofTreeRole::BaseOracle as u16 => ProofTreeRole::BaseOracle,
            value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                ProofTreeRole::AuxiliaryOracle
            }
            _ => return Err(CommonProofProverError::InvalidTree),
        };
        for column_ordinal in ordered_column_ordinals {
            if roles.insert(*column_ordinal, role).is_some() {
                return Err(CommonProofProverError::InvalidTree);
            }
        }
    }
    Ok(roles)
}

fn integer_lift_derived_columns(
    variant: &RelationPlanVariant,
) -> Result<(BTreeMap<u32, u32>, BTreeSet<u32>), CommonProofProverError> {
    let mut reversed_columns_by_source = BTreeMap::new();
    let mut source_by_reversed_column = BTreeMap::new();
    let mut auxiliary_columns = BTreeSet::new();
    for batch in variant.ordered_integer_lift_batches() {
        for permutation in &batch.ordered_negacyclic_automorphism_permutations {
            auxiliary_columns.extend([
                permutation.source_product_before_column_ordinal,
                permutation.source_low_product_column_ordinal,
                permutation.target_product_before_column_ordinal,
                permutation.target_low_product_column_ordinal,
            ]);
        }
        for binding in &batch.ordered_reversed_column_bindings {
            match reversed_columns_by_source.insert(
                binding.source_column_ordinal,
                binding.reversed_column_ordinal,
            ) {
                Some(existing) if existing != binding.reversed_column_ordinal => {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                _ => {}
            }
            match source_by_reversed_column.insert(
                binding.reversed_column_ordinal,
                binding.source_column_ordinal,
            ) {
                Some(existing) if existing != binding.source_column_ordinal => {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                _ => {}
            }
            auxiliary_columns.extend([
                binding.source_prefix_evaluation_column_ordinal,
                binding.reversed_suffix_evaluation_column_ordinal,
            ]);
        }
        for component in &batch.ordered_components {
            auxiliary_columns.extend([
                component.linear_evaluation_column_ordinal,
                component.product_accumulator_column_ordinal,
            ]);
            for product in &component.ordered_convolution_products {
                auxiliary_columns.extend([
                    product.suffix_evaluation_column_ordinal,
                    product.reversed_transpose_column_ordinal,
                ]);
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                auxiliary_columns.extend([
                    product.multiplicand_low_suffix_evaluation_column_ordinal,
                    product.multiplicand_high_suffix_evaluation_column_ordinal,
                    product.reversed_multiplier_low_transpose_column_ordinal,
                    product.reversed_multiplier_high_transpose_column_ordinal,
                ]);
            }
        }
    }
    if source_by_reversed_column
        .keys()
        .any(|column| auxiliary_columns.contains(column))
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok((reversed_columns_by_source, auxiliary_columns))
}

fn trace_masks_by_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, RelationMaskDescriptor>, CommonProofProverError> {
    let mut masks = BTreeMap::new();
    for mask in variant.ordered_masks().iter().copied().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::Trace
            && mask.target_class() == RelationMaskTargetClass::Column
    }) {
        if masks.insert(mask.target_ordinal(), mask).is_some() {
            return Err(CommonProofProverError::InvalidMask);
        }
    }
    Ok(masks)
}

fn validate_source_column(
    descriptor: &RelationColumnDescriptor,
    source: &CommonProofSourcePolynomial,
    trace_domain_size: u64,
) -> Result<(), CommonProofProverError> {
    // Prover and verifier-sequence inputs are trace polynomials before any
    // proof-owned mask is applied, so their canonical interpolation contains
    // at most one coefficient per trace row. Bound-tree columns are different:
    // their authenticated source already includes the persistent trace mask.
    // Preserve that mask by accepting the complete descriptor-owned degree
    // bound instead of truncating it to the trace domain.
    let maximum_coefficient_count = match descriptor.origin() {
        RelationColumnOrigin::BoundTree { .. } => descriptor.source_degree_bound_exclusive(),
        RelationColumnOrigin::VerifierSequence { .. } | RelationColumnOrigin::Prover => descriptor
            .source_degree_bound_exclusive()
            .min(trace_domain_size),
    };
    if descriptor.value_type() != source.value_type()
        || source.coefficient_count() == 0
        || source.coefficient_count()
            > usize::try_from(maximum_coefficient_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(())
}

fn mask_relation_column<Coins>(
    variant: &RelationPlanVariant,
    descriptor: &RelationColumnDescriptor,
    mask: Option<RelationMaskDescriptor>,
    source: CommonProofSourcePolynomial,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<CommonProofSourcePolynomial, CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let constructed = match (descriptor.origin(), mask) {
        (RelationColumnOrigin::Prover, Some(mask))
            if variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing =>
        {
            let sampled = match source.value_type() {
                RelationColumnValueType::BaseField => {
                    CommonProofSourcePolynomial::Base(sample_private_base_polynomial(
                        coins,
                        mask.mask_purpose(),
                        mask.mask_degree_bound_exclusive(),
                        maximum_candidate_draws_per_output,
                    )?)
                }
                RelationColumnValueType::ChallengeExtension => {
                    CommonProofSourcePolynomial::Extension(sample_private_extension_polynomial(
                        coins,
                        mask.mask_purpose(),
                        mask.mask_degree_bound_exclusive(),
                        maximum_candidate_draws_per_output,
                    )?)
                }
            };
            apply_trace_mask(source, variant.trace_domain_size(), sampled)
                .map_err(CommonProofPrivateCoinError::Prover)?
        }
        (RelationColumnOrigin::Prover, _) => {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidMask,
            ));
        }
        (_, None) => source,
        (_, Some(_)) => {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidMask,
            ));
        }
    };
    if constructed.coefficient_count()
        > usize::try_from(descriptor.source_degree_bound_exclusive()).map_err(|_| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow)
        })?
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    Ok(constructed)
}

fn base_trace_rows(
    source: &CommonProofSourcePolynomial,
    trace_domain: ProofEvaluationDomain,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofProverError> {
    let CommonProofSourcePolynomial::Base(coefficients) = source else {
        return Err(CommonProofProverError::InvalidColumn);
    };
    let mut reduced_coefficients = vec![ProofBaseFieldElement::ZERO; trace_domain.size()];
    for (coefficient_ordinal, coefficient) in coefficients.iter().copied().enumerate() {
        let reduced_ordinal = coefficient_ordinal % trace_domain.size();
        reduced_coefficients[reduced_ordinal] =
            reduced_coefficients[reduced_ordinal].add(coefficient);
    }
    trace_domain
        .evaluate_base_polynomial(&reduced_coefficients)
        .map_err(CommonProofProverError::from)
}

fn ensure_base_trace_rows(
    columns: &[Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    column_ordinal: u32,
    trace_domain: ProofEvaluationDomain,
) -> Result<(), CommonProofProverError> {
    if trace_rows_by_column.contains_key(&column_ordinal) {
        return Ok(());
    }
    let source = columns
        .get(usize::try_from(column_ordinal).map_err(|_| CommonProofProverError::CountOverflow)?)
        .and_then(Option::as_ref)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let rows = base_trace_rows(source, trace_domain)?;
    trace_rows_by_column.insert(column_ordinal, rows);
    Ok(())
}

fn integer_lift_theta(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    modulus_reference: SuiteModulusReference,
    challenge_ordinal: u16,
    assignments: &[RelationApplicationChallengeAssignment],
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let modulus_ordinal = variant
        .non_native_modulus_ordinal(modulus_reference)
        .map_err(CommonProofProverError::from)?;
    let expected_challenge = CommonProofChallenge::Theta { modulus_ordinal };
    let mut matching = assignments.iter().copied().filter(|assignment| {
        assignment.challenge() == expected_challenge
            && assignment.repetition_ordinal() == challenge_ordinal
    });
    let value = matching
        .next()
        .map(RelationApplicationChallengeAssignment::value)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    if matching.next().is_some() || value >= context.resolved_modulus(modulus_reference)? {
        return Err(CommonProofProverError::InvalidColumn);
    }
    ProofBaseFieldElement::from_canonical(value).map_err(CommonProofProverError::from)
}

#[allow(clippy::too_many_arguments)]
fn synthesize_negacyclic_automorphism_permutation<Coins>(
    variant: &RelationPlanVariant,
    descriptor: &RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
    theta: ProofBaseFieldElement,
    tree_roles: &BTreeMap<u32, ProofTreeRole>,
    trace_masks: &BTreeMap<u32, RelationMaskDescriptor>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    trace_domain: ProofEvaluationDomain,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    let input_columns = [
        descriptor.source_low_column_ordinal,
        descriptor.source_high_column_ordinal,
        descriptor.target_low_column_ordinal,
        descriptor.target_high_column_ordinal,
        descriptor.mapped_low_position_column_ordinal,
        descriptor.low_negation_bit_column_ordinal,
        descriptor.mapped_high_position_column_ordinal,
        descriptor.high_negation_bit_column_ordinal,
        descriptor.target_low_position_column_ordinal,
        descriptor.target_high_position_column_ordinal,
    ];
    for column_ordinal in input_columns {
        ensure_base_trace_rows(columns, trace_rows_by_column, column_ordinal, trace_domain)
            .map_err(CommonProofPrivateCoinError::Prover)?;
    }
    let rows = |column_ordinal| {
        trace_rows_by_column.get(&column_ordinal).ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
        })
    };
    let source_low_rows = rows(descriptor.source_low_column_ordinal)?;
    let source_high_rows = rows(descriptor.source_high_column_ordinal)?;
    let target_low_rows = rows(descriptor.target_low_column_ordinal)?;
    let target_high_rows = rows(descriptor.target_high_column_ordinal)?;
    let mapped_low_position_rows = rows(descriptor.mapped_low_position_column_ordinal)?;
    let low_negation_bit_rows = rows(descriptor.low_negation_bit_column_ordinal)?;
    let mapped_high_position_rows = rows(descriptor.mapped_high_position_column_ordinal)?;
    let high_negation_bit_rows = rows(descriptor.high_negation_bit_column_ordinal)?;
    let target_low_position_rows = rows(descriptor.target_low_position_column_ordinal)?;
    let target_high_position_rows = rows(descriptor.target_high_position_column_ordinal)?;
    let row_count = trace_domain.size();
    if input_columns.iter().any(|column_ordinal| {
        trace_rows_by_column
            .get(column_ordinal)
            .is_none_or(|column_rows| column_rows.len() != row_count)
    }) {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let one = ProofBaseFieldElement::ONE;
    let two = one.add(one);
    let three = two.add(one);
    let encoded_source = |position: ProofBaseFieldElement,
                          negation_bit: ProofBaseFieldElement,
                          value: ProofBaseFieldElement| {
        position
            .multiply(three)
            .add(one)
            .add(value.subtract(negation_bit.multiply(two).multiply(value)))
    };
    let encoded_target = |position: ProofBaseFieldElement, value: ProofBaseFieldElement| {
        position.multiply(three).add(one).add(value)
    };
    let mut source_before_rows = Vec::with_capacity(row_count);
    let mut source_low_product_rows = Vec::with_capacity(row_count);
    let mut target_before_rows = Vec::with_capacity(row_count);
    let mut target_low_product_rows = Vec::with_capacity(row_count);
    let mut source_before = one;
    let mut target_before = one;
    for row_ordinal in 0..row_count {
        source_before_rows.push(source_before);
        target_before_rows.push(target_before);
        let source_low_factor = theta.subtract(encoded_source(
            mapped_low_position_rows[row_ordinal],
            low_negation_bit_rows[row_ordinal],
            source_low_rows[row_ordinal],
        ));
        let source_low_product = source_before.multiply(source_low_factor);
        source_low_product_rows.push(source_low_product);
        let target_low_factor = theta.subtract(encoded_target(
            target_low_position_rows[row_ordinal],
            target_low_rows[row_ordinal],
        ));
        let target_low_product = target_before.multiply(target_low_factor);
        target_low_product_rows.push(target_low_product);
        let source_high_factor = theta.subtract(encoded_source(
            mapped_high_position_rows[row_ordinal],
            high_negation_bit_rows[row_ordinal],
            source_high_rows[row_ordinal],
        ));
        let target_high_factor = theta.subtract(encoded_target(
            target_high_position_rows[row_ordinal],
            target_high_rows[row_ordinal],
        ));
        source_before = source_low_product.multiply(source_high_factor);
        target_before = target_low_product.multiply(target_high_factor);
    }
    let auxiliary_trace_row_context = AuxiliaryTraceRowInsertionContext::new(
        variant,
        tree_roles,
        trace_masks,
        trace_domain,
        maximum_candidate_draws_per_output,
    );
    for (column_ordinal, synthesized_rows) in [
        (
            descriptor.source_product_before_column_ordinal,
            source_before_rows,
        ),
        (
            descriptor.source_low_product_column_ordinal,
            source_low_product_rows,
        ),
        (
            descriptor.target_product_before_column_ordinal,
            target_before_rows,
        ),
        (
            descriptor.target_low_product_column_ordinal,
            target_low_product_rows,
        ),
    ] {
        insert_auxiliary_trace_rows(
            auxiliary_trace_row_context,
            columns,
            column_ordinal,
            synthesized_rows,
            coins,
        )?;
    }
    Ok(())
}

pub(super) fn prefix_evaluation_rows(
    source_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Vec<ProofBaseFieldElement> {
    let mut output = Vec::with_capacity(source_rows.len());
    let mut prefix = ProofBaseFieldElement::ZERO;
    for source in source_rows {
        prefix = prefix.multiply(theta).add(*source);
        output.push(prefix);
    }
    output
}

pub(super) fn suffix_evaluation_rows(
    source_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Vec<ProofBaseFieldElement> {
    let mut output = vec![ProofBaseFieldElement::ZERO; source_rows.len()];
    let mut suffix = ProofBaseFieldElement::ZERO;
    for row_ordinal in (0..source_rows.len()).rev() {
        suffix = source_rows[row_ordinal].add(theta.multiply(suffix));
        output[row_ordinal] = suffix;
    }
    output
}

#[derive(Clone, Copy)]
struct AuxiliaryTraceRowInsertionContext<'relation> {
    variant: &'relation RelationPlanVariant,
    tree_roles: &'relation BTreeMap<u32, ProofTreeRole>,
    trace_masks: &'relation BTreeMap<u32, RelationMaskDescriptor>,
    trace_domain: ProofEvaluationDomain,
    maximum_candidate_draws_per_output: u32,
}

impl<'relation> AuxiliaryTraceRowInsertionContext<'relation> {
    fn new(
        variant: &'relation RelationPlanVariant,
        tree_roles: &'relation BTreeMap<u32, ProofTreeRole>,
        trace_masks: &'relation BTreeMap<u32, RelationMaskDescriptor>,
        trace_domain: ProofEvaluationDomain,
        maximum_candidate_draws_per_output: u32,
    ) -> Self {
        Self {
            variant,
            tree_roles,
            trace_masks,
            trace_domain,
            maximum_candidate_draws_per_output,
        }
    }
}

fn insert_auxiliary_trace_rows<Coins>(
    context: AuxiliaryTraceRowInsertionContext<'_>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    column_ordinal: u32,
    rows: Vec<ProofBaseFieldElement>,
    coins: &mut Coins,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    if rows.len() != context.trace_domain.size()
        || context.tree_roles.get(&column_ordinal) != Some(&ProofTreeRole::AuxiliaryOracle)
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let column_index = usize::try_from(column_ordinal)
        .map_err(|_| CommonProofPrivateCoinError::Prover(CommonProofProverError::CountOverflow))?;
    let descriptor = context
        .variant
        .ordered_columns()
        .get(column_index)
        .ok_or_else(|| {
            CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
        })?;
    if descriptor.value_type() != RelationColumnValueType::BaseField
        || columns
            .get(column_index)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?
            .is_some()
    {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let source = CommonProofSourcePolynomial::Base(
        context
            .trace_domain
            .interpolate_base_polynomial(&rows)
            .map_err(CommonProofProverError::from)
            .map_err(CommonProofPrivateCoinError::Prover)?,
    );
    let constructed = mask_relation_column(
        context.variant,
        descriptor,
        context.trace_masks.get(&column_ordinal).copied(),
        source,
        coins,
        context.maximum_candidate_draws_per_output,
    )?;
    columns[column_index] = Some(constructed);
    Ok(())
}

fn base_field_constant(value: u64) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    ProofBaseFieldElement::from_canonical(value).map_err(CommonProofProverError::from)
}

fn integer_lift_coefficient_value(
    context: &RelationPlanCheckContext,
    coefficient: RelationIntegerLiftCoefficient,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let value = match coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => value,
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => context
            .resolved_modulus(modulus_reference)?
            .checked_mul(u64::from(multiplier))
            .ok_or(CommonProofProverError::CountOverflow)?,
    };
    base_field_constant(value)
}

fn signed_linear_term_row(
    term: &RelationIntegerLiftLinearTermDescriptor,
    row_ordinal: usize,
    context: &RelationPlanCheckContext,
    trace_rows_by_column: &BTreeMap<u32, Vec<ProofBaseFieldElement>>,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let column_value = trace_rows_by_column
        .get(&term.column_ordinal)
        .and_then(|rows| rows.get(row_ordinal))
        .copied()
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let shifted = column_value.subtract(base_field_constant(term.column_offset)?);
    let value = shifted.multiply(integer_lift_coefficient_value(context, term.coefficient)?);
    Ok(if term.negative { value.negate() } else { value })
}

fn integer_lift_linear_evaluation_rows(
    context: &RelationPlanCheckContext,
    modulus_reference: SuiteModulusReference,
    component: &RelationIntegerLiftComponentDescriptor,
    theta: ProofBaseFieldElement,
    columns: &[Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    trace_domain: ProofEvaluationDomain,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofProverError> {
    ensure_base_trace_rows(
        columns,
        trace_rows_by_column,
        component.quotient_column_ordinal,
        trace_domain,
    )?;
    for term in &component.ordered_linear_terms {
        ensure_base_trace_rows(
            columns,
            trace_rows_by_column,
            term.column_ordinal,
            trace_domain,
        )?;
    }
    let modulus = base_field_constant(context.resolved_modulus(modulus_reference)?)?;
    let quotient_rows = trace_rows_by_column
        .get(&component.quotient_column_ordinal)
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let mut coefficient_rows = vec![ProofBaseFieldElement::ZERO; trace_domain.size()];
    for row_ordinal in 0..trace_domain.size() {
        let mut coefficient = ProofBaseFieldElement::ZERO;
        for term in &component.ordered_linear_terms {
            coefficient = coefficient.add(signed_linear_term_row(
                term,
                row_ordinal,
                context,
                trace_rows_by_column,
            )?);
        }
        let quotient_term = modulus.multiply(quotient_rows[row_ordinal]);
        coefficient = coefficient.add(if component.quotient_is_negative {
            quotient_term.negate()
        } else {
            quotient_term
        });
        coefficient_rows[row_ordinal] = coefficient;
    }
    Ok(suffix_evaluation_rows(&coefficient_rows, theta))
}

pub(super) fn product_accumulator_rows(
    product_rows: &[ProofBaseFieldElement],
) -> Vec<ProofBaseFieldElement> {
    let mut accumulator_rows = vec![ProofBaseFieldElement::ZERO; product_rows.len()];
    for row_ordinal in 0..product_rows.len().saturating_sub(1) {
        accumulator_rows[row_ordinal + 1] =
            accumulator_rows[row_ordinal].add(product_rows[row_ordinal]);
    }
    accumulator_rows
}

pub(super) fn convolution_transpose_rows(
    kind: RelationIntegerLiftConvolutionKind,
    multiplicand_rows: &[ProofBaseFieldElement],
    suffix_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofProverError> {
    if multiplicand_rows.is_empty() || multiplicand_rows.len() != suffix_rows.len() {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let row_count = multiplicand_rows.len();
    let theta_to_row_count =
        theta.power(u64::try_from(row_count).map_err(|_| CommonProofProverError::CountOverflow)?);
    let last = row_count - 1;
    let mut transpose_rows = vec![ProofBaseFieldElement::ZERO; row_count];
    match kind {
        RelationIntegerLiftConvolutionKind::Negacyclic => {
            transpose_rows[last] = suffix_rows[0];
            let wrap_factor = theta_to_row_count.add(ProofBaseFieldElement::ONE);
            for row_ordinal in (1..row_count).rev() {
                transpose_rows[row_ordinal - 1] = theta
                    .multiply(transpose_rows[row_ordinal])
                    .subtract(wrap_factor.multiply(multiplicand_rows[row_ordinal]));
            }
        }
        RelationIntegerLiftConvolutionKind::OrdinaryLowHalf => {
            transpose_rows[last] = suffix_rows[0];
            for row_ordinal in (0..last).rev() {
                transpose_rows[row_ordinal] = theta
                    .multiply(transpose_rows[row_ordinal + 1])
                    .subtract(theta_to_row_count.multiply(multiplicand_rows[row_ordinal + 1]));
            }
        }
        RelationIntegerLiftConvolutionKind::OrdinaryHighHalf => {
            transpose_rows[last] = ProofBaseFieldElement::ZERO;
            for row_ordinal in (0..last).rev() {
                transpose_rows[row_ordinal] = multiplicand_rows[row_ordinal + 1]
                    .add(theta.multiply(transpose_rows[row_ordinal + 1]));
            }
        }
    }
    Ok(transpose_rows)
}

#[allow(clippy::too_many_arguments)]
fn synthesize_convolution_product<Coins>(
    variant: &RelationPlanVariant,
    product: &RelationIntegerLiftConvolutionProductDescriptor,
    theta: ProofBaseFieldElement,
    tree_roles: &BTreeMap<u32, ProofTreeRole>,
    trace_masks: &BTreeMap<u32, RelationMaskDescriptor>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    product_sum_rows: &mut [ProofBaseFieldElement],
    trace_domain: ProofEvaluationDomain,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    ensure_base_trace_rows(
        columns,
        trace_rows_by_column,
        product.multiplicand_column_ordinal,
        trace_domain,
    )
    .map_err(CommonProofPrivateCoinError::Prover)?;
    ensure_base_trace_rows(
        columns,
        trace_rows_by_column,
        product.reversed_multiplier_column_ordinal,
        trace_domain,
    )
    .map_err(CommonProofPrivateCoinError::Prover)?;
    let offset = base_field_constant(product.multiplier_offset)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let (suffix_rows, transpose_rows, contribution_rows) = {
        let multiplicand_rows = trace_rows_by_column
            .get(&product.multiplicand_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let reversed_multiplier_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let suffix_rows = suffix_evaluation_rows(multiplicand_rows, theta);
        let transpose_rows = convolution_transpose_rows(
            product.convolution_kind,
            multiplicand_rows,
            &suffix_rows,
            theta,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;
        let contribution_rows = transpose_rows
            .iter()
            .copied()
            .zip(reversed_multiplier_rows.iter().copied())
            .map(|(transpose, reversed_multiplier)| {
                let value = transpose.multiply(reversed_multiplier.subtract(offset));
                if product.negative {
                    value.negate()
                } else {
                    value
                }
            })
            .collect::<Vec<_>>();
        (suffix_rows, transpose_rows, contribution_rows)
    };
    if contribution_rows.len() != product_sum_rows.len() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    for (accumulated, contribution) in product_sum_rows.iter_mut().zip(contribution_rows) {
        *accumulated = accumulated.add(contribution);
    }
    let auxiliary_trace_row_context = AuxiliaryTraceRowInsertionContext::new(
        variant,
        tree_roles,
        trace_masks,
        trace_domain,
        maximum_candidate_draws_per_output,
    );
    insert_auxiliary_trace_rows(
        auxiliary_trace_row_context,
        columns,
        product.suffix_evaluation_column_ordinal,
        suffix_rows,
        coins,
    )?;
    insert_auxiliary_trace_rows(
        auxiliary_trace_row_context,
        columns,
        product.reversed_transpose_column_ordinal,
        transpose_rows,
        coins,
    )?;
    Ok(())
}

pub(super) fn full_ring_transpose_rows(
    selected_half: RelationIntegerLiftFullRingHalf,
    low_multiplier: bool,
    multiplicand_low_rows: &[ProofBaseFieldElement],
    multiplicand_high_rows: &[ProofBaseFieldElement],
    low_suffix_rows: &[ProofBaseFieldElement],
    high_suffix_rows: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> Result<Vec<ProofBaseFieldElement>, CommonProofProverError> {
    let row_count = multiplicand_low_rows.len();
    if row_count == 0
        || multiplicand_high_rows.len() != row_count
        || low_suffix_rows.len() != row_count
        || high_suffix_rows.len() != row_count
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let theta_to_half_ring_degree =
        theta.power(u64::try_from(row_count).map_err(|_| CommonProofProverError::CountOverflow)?);
    let last = row_count - 1;
    let mut transpose_rows = vec![ProofBaseFieldElement::ZERO; row_count];
    transpose_rows[last] = match (selected_half, low_multiplier) {
        (RelationIntegerLiftFullRingHalf::Low, true)
        | (RelationIntegerLiftFullRingHalf::High, false) => low_suffix_rows[0],
        (RelationIntegerLiftFullRingHalf::Low, false) => high_suffix_rows[0].negate(),
        (RelationIntegerLiftFullRingHalf::High, true) => high_suffix_rows[0],
    };
    for row_ordinal in (0..last).rev() {
        let low_next = multiplicand_low_rows[row_ordinal + 1];
        let high_next = multiplicand_high_rows[row_ordinal + 1];
        let theta_times_next = theta.multiply(transpose_rows[row_ordinal + 1]);
        transpose_rows[row_ordinal] = match (selected_half, low_multiplier) {
            (RelationIntegerLiftFullRingHalf::Low, true)
            | (RelationIntegerLiftFullRingHalf::High, false) => theta_times_next
                .subtract(theta_to_half_ring_degree.multiply(low_next))
                .subtract(high_next),
            (RelationIntegerLiftFullRingHalf::Low, false) => theta_times_next
                .subtract(low_next)
                .add(theta_to_half_ring_degree.multiply(high_next)),
            (RelationIntegerLiftFullRingHalf::High, true) => theta_times_next
                .add(low_next)
                .subtract(theta_to_half_ring_degree.multiply(high_next)),
        };
    }
    Ok(transpose_rows)
}

#[allow(clippy::too_many_arguments)]
fn synthesize_full_ring_product<Coins>(
    variant: &RelationPlanVariant,
    product: &RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    theta: ProofBaseFieldElement,
    tree_roles: &BTreeMap<u32, ProofTreeRole>,
    trace_masks: &BTreeMap<u32, RelationMaskDescriptor>,
    columns: &mut [Option<CommonProofSourcePolynomial>],
    trace_rows_by_column: &mut BTreeMap<u32, Vec<ProofBaseFieldElement>>,
    product_sum_rows: &mut [ProofBaseFieldElement],
    trace_domain: ProofEvaluationDomain,
    coins: &mut Coins,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
where
    Coins: CommonProofPrivateCoinSource,
{
    for column_ordinal in [
        product.multiplicand_low_column_ordinal,
        product.multiplicand_high_column_ordinal,
        product.reversed_multiplier_low_column_ordinal,
        product.reversed_multiplier_high_column_ordinal,
    ] {
        ensure_base_trace_rows(columns, trace_rows_by_column, column_ordinal, trace_domain)
            .map_err(CommonProofPrivateCoinError::Prover)?;
    }
    let low_offset = base_field_constant(product.multiplier_low_offset)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let high_offset = base_field_constant(product.multiplier_high_offset)
        .map_err(CommonProofPrivateCoinError::Prover)?;
    let (
        low_suffix_rows,
        high_suffix_rows,
        low_transpose_rows,
        high_transpose_rows,
        contribution_rows,
    ) = {
        let multiplicand_low_rows = trace_rows_by_column
            .get(&product.multiplicand_low_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let multiplicand_high_rows = trace_rows_by_column
            .get(&product.multiplicand_high_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let reversed_multiplier_low_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_low_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let reversed_multiplier_high_rows = trace_rows_by_column
            .get(&product.reversed_multiplier_high_column_ordinal)
            .ok_or_else(|| {
                CommonProofPrivateCoinError::Prover(CommonProofProverError::InvalidColumn)
            })?;
        let low_suffix_rows = suffix_evaluation_rows(multiplicand_low_rows, theta);
        let high_suffix_rows = suffix_evaluation_rows(multiplicand_high_rows, theta);
        let low_transpose_rows = full_ring_transpose_rows(
            product.selected_half,
            true,
            multiplicand_low_rows,
            multiplicand_high_rows,
            &low_suffix_rows,
            &high_suffix_rows,
            theta,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;
        let high_transpose_rows = full_ring_transpose_rows(
            product.selected_half,
            false,
            multiplicand_low_rows,
            multiplicand_high_rows,
            &low_suffix_rows,
            &high_suffix_rows,
            theta,
        )
        .map_err(CommonProofPrivateCoinError::Prover)?;
        let mut contribution_rows = Vec::with_capacity(trace_domain.size());
        for row_ordinal in 0..trace_domain.size() {
            let low_product = low_transpose_rows[row_ordinal]
                .multiply(reversed_multiplier_low_rows[row_ordinal].subtract(low_offset));
            let high_product = high_transpose_rows[row_ordinal]
                .multiply(reversed_multiplier_high_rows[row_ordinal].subtract(high_offset));
            let value = low_product.add(high_product);
            contribution_rows.push(if product.negative {
                value.negate()
            } else {
                value
            });
        }
        (
            low_suffix_rows,
            high_suffix_rows,
            low_transpose_rows,
            high_transpose_rows,
            contribution_rows,
        )
    };
    if contribution_rows.len() != product_sum_rows.len() {
        return Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    for (accumulated, contribution) in product_sum_rows.iter_mut().zip(contribution_rows) {
        *accumulated = accumulated.add(contribution);
    }
    let auxiliary_trace_row_context = AuxiliaryTraceRowInsertionContext::new(
        variant,
        tree_roles,
        trace_masks,
        trace_domain,
        maximum_candidate_draws_per_output,
    );
    for (column_ordinal, rows) in [
        (
            product.multiplicand_low_suffix_evaluation_column_ordinal,
            low_suffix_rows,
        ),
        (
            product.multiplicand_high_suffix_evaluation_column_ordinal,
            high_suffix_rows,
        ),
        (
            product.reversed_multiplier_low_transpose_column_ordinal,
            low_transpose_rows,
        ),
        (
            product.reversed_multiplier_high_transpose_column_ordinal,
            high_transpose_rows,
        ),
    ] {
        insert_auxiliary_trace_rows(
            auxiliary_trace_row_context,
            columns,
            column_ordinal,
            rows,
            coins,
        )?;
    }
    Ok(())
}
