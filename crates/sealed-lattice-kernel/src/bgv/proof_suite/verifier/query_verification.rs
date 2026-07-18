use super::{
    CommonProofVerifierError, CompleteProofTreeCatalog, OpenedFriLayerPair,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofFriQueryState,
    ProofFriQueryVerifier, ProofOpeningClaimEvaluation, ProofTreeCatalogSource, ProofTreeOpening,
    ProofTreeValue, RelationColumnOrigin, RelationColumnValueType, RelationOpeningSourceClass,
    RelationPlanVariant, VerifiedRelationColumnEvaluator, evaluate_normalized_opening_claim_pair,
};

#[derive(Clone, Copy)]
pub(super) struct RuntimeOpeningClaim {
    column_position: Option<usize>,
    source_degree_bound_exclusive: u64,
    opening_point: ProofChallengeExtensionElement,
    opened_value: ProofChallengeExtensionElement,
    batching_coefficient: ProofChallengeExtensionElement,
}

pub(super) fn build_runtime_claim_groups(
    variant: &RelationPlanVariant,
    catalog: &CompleteProofTreeCatalog,
    opening_points: &[ProofChallengeExtensionElement],
    deep_evaluations: &[ProofChallengeExtensionElement],
    batching_coefficients: &[ProofChallengeExtensionElement],
) -> Result<Vec<Vec<RuntimeOpeningClaim>>, CommonProofVerifierError> {
    if deep_evaluations.len() != variant.ordered_opening_claims().len()
        || batching_coefficients.len() != variant.ordered_opening_claims().len()
    {
        return Err(CommonProofVerifierError::InvalidOpeningClaim);
    }
    let mut groups = vec![Vec::new(); catalog.entries().len()];
    for (claim_ordinal, claim) in variant.ordered_opening_claims().iter().copied().enumerate() {
        let (catalog_index, column_position) = match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => {
                let tree_index = usize::try_from(claim.source_ordinal())
                    .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
                if !matches!(
                    catalog
                        .entries()
                        .get(tree_index)
                        .map(|entry| entry.source()),
                    Some(
                        ProofTreeCatalogSource::RelationProofCreated { .. }
                            | ProofTreeCatalogSource::RelationBoundPublic
                    )
                ) {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                let tree = variant
                    .ordered_trees()
                    .get(tree_index)
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let column_ordinal = claim
                    .column_ordinal()
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let mut positions = tree
                    .ordered_column_ordinals()
                    .iter()
                    .enumerate()
                    .filter(|(_, candidate)| **candidate == column_ordinal)
                    .map(|(position, _)| position);
                let position = positions
                    .next()
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                if positions.next().is_some() {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                (tree_index, Some(position))
            }
            RelationOpeningSourceClass::Quotient => {
                if claim.column_ordinal().is_some() {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                let component_ordinal = u16::try_from(claim.source_ordinal())
                    .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
                (
                    catalog_index_for_source(catalog, |source| {
                        source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
                    })?,
                    None,
                )
            }
            RelationOpeningSourceClass::BatchMask => {
                if claim.source_ordinal() != 0 || claim.column_ordinal().is_some() {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                (
                    catalog_index_for_source(catalog, |source| {
                        source == ProofTreeCatalogSource::OpeningBatchMask
                    })?,
                    None,
                )
            }
        };
        let opening_point_index = usize::try_from(claim.opening_point_ordinal())
            .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
        let opening_point = opening_points
            .get(opening_point_index)
            .copied()
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        groups
            .get_mut(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?
            .push(RuntimeOpeningClaim {
                column_position,
                source_degree_bound_exclusive: claim.source_degree_bound_exclusive(),
                opening_point,
                opened_value: deep_evaluations[claim_ordinal],
                batching_coefficient: batching_coefficients[claim_ordinal],
            });
    }
    Ok(groups)
}

fn catalog_index_for_source(
    catalog: &CompleteProofTreeCatalog,
    mut matches_source: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<usize, CommonProofVerifierError> {
    let mut matches = catalog
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches_source(entry.source()));
    let index = matches
        .next()
        .map(|(index, _)| index)
        .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
    if matches.next().is_some() {
        return Err(CommonProofVerifierError::InvalidOpeningClaim);
    }
    Ok(index)
}

pub(super) struct QueryVerificationWorkspace {
    evaluation_domain: ProofEvaluationDomain,
    claim_groups: Vec<Vec<RuntimeOpeningClaim>>,
    accumulated_initial_pairs: Vec<OpenedFriLayerPair>,
    fri_verifier: ProofFriQueryVerifier,
    fri_states: Option<Vec<ProofFriQueryState>>,
    next_catalog_index: usize,
}

impl QueryVerificationWorkspace {
    pub(super) fn new(
        catalog_entry_count: usize,
        evaluation_domain: ProofEvaluationDomain,
        query_representative_count: usize,
        claim_groups: Vec<Vec<RuntimeOpeningClaim>>,
        fri_verifier: ProofFriQueryVerifier,
    ) -> Result<Self, CommonProofVerifierError> {
        if query_representative_count == 0 || claim_groups.len() != catalog_entry_count {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        Ok(QueryVerificationWorkspace {
            evaluation_domain,
            claim_groups,
            accumulated_initial_pairs: vec![
                OpenedFriLayerPair::new(
                    ProofChallengeExtensionElement::ZERO,
                    ProofChallengeExtensionElement::ZERO,
                );
                query_representative_count
            ],
            fri_verifier,
            fri_states: None,
            next_catalog_index: 0,
        })
    }

    pub(super) fn consume_opening<ColumnEvaluator>(
        &mut self,
        opening: ProofTreeOpening<'_>,
        variant: &RelationPlanVariant,
        catalog: &CompleteProofTreeCatalog,
        query_representatives: &[u64],
        evaluate_verified_column: &mut ColumnEvaluator,
    ) -> Result<(), CommonProofVerifierError>
    where
        ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
    {
        let catalog_index = usize::from(opening.catalog_entry().tree_catalog_index());
        if catalog_index != self.next_catalog_index
            || catalog.entries().get(catalog_index) != Some(opening.catalog_entry())
        {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        match opening.catalog_entry().source() {
            ProofTreeCatalogSource::RelationProofCreated { .. }
            | ProofTreeCatalogSource::RelationBoundPublic => {
                self.consume_relation_tree(
                    catalog_index,
                    opening.leaves(),
                    variant,
                    query_representatives,
                    evaluate_verified_column,
                )?;
            }
            ProofTreeCatalogSource::QuotientComponent { .. } => {
                self.consume_single_extension_tree(
                    catalog_index,
                    opening.leaves(),
                    false,
                    variant,
                    query_representatives,
                )?;
            }
            ProofTreeCatalogSource::OpeningBatchMask => {
                self.consume_single_extension_tree(
                    catalog_index,
                    opening.leaves(),
                    true,
                    variant,
                    query_representatives,
                )?;
            }
            ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal } => {
                self.consume_fri_tree(
                    usize::from(fold_ordinal),
                    opening.leaves(),
                    query_representatives,
                )?;
            }
        }
        self.next_catalog_index += 1;
        Ok(())
    }

    fn consume_relation_tree<ColumnEvaluator>(
        &mut self,
        catalog_index: usize,
        leaves: &[super::super::DecodedProofPhasePairLeaf],
        variant: &RelationPlanVariant,
        query_representatives: &[u64],
        evaluate_verified_column: &mut ColumnEvaluator,
    ) -> Result<(), CommonProofVerifierError>
    where
        ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
    {
        let tree = variant
            .ordered_trees()
            .get(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let columns = tree.ordered_column_ordinals();
        let claims = self
            .claim_groups
            .get(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;

        verify_relation_tree_columns(
            leaves,
            columns,
            variant,
            query_representatives,
            self.evaluation_domain,
            evaluate_verified_column,
        )?;

        for (query_index, (leaf, representative)) in leaves
            .iter()
            .zip(query_representatives.iter().copied())
            .enumerate()
        {
            let evaluation_point = self.evaluation_domain.point(
                usize::try_from(representative)
                    .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
            )?;
            for claim in claims {
                let column_position = claim
                    .column_position
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let column_ordinal = *columns
                    .get(column_position)
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let column_index = usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
                let column = variant
                    .ordered_columns()
                    .get(column_index)
                    .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
                let source_pair = opened_pair(leaf, column_position, column.value_type())?;
                add_opening_claim(
                    variant.opening_degree_bound_exclusive(),
                    evaluation_point,
                    *claim,
                    source_pair,
                    &mut self.accumulated_initial_pairs[query_index],
                )?;
            }
        }
        Ok(())
    }

    fn consume_single_extension_tree(
        &mut self,
        catalog_index: usize,
        leaves: &[super::super::DecodedProofPhasePairLeaf],
        add_direct_pair: bool,
        variant: &RelationPlanVariant,
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        let claims = self
            .claim_groups
            .get(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        for (query_index, representative) in query_representatives.iter().copied().enumerate() {
            let leaf = leaf_for_index(leaves, representative)?;
            let source_pair = opened_pair(leaf, 0, RelationColumnValueType::ChallengeExtension)?;
            if add_direct_pair {
                self.accumulated_initial_pairs[query_index] =
                    add_pairs(self.accumulated_initial_pairs[query_index], source_pair);
            }
            let evaluation_point = self.evaluation_domain.point(
                usize::try_from(representative)
                    .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
            )?;
            for claim in claims {
                if claim.column_position.is_some() {
                    return Err(CommonProofVerifierError::InvalidOpeningClaim);
                }
                add_opening_claim(
                    variant.opening_degree_bound_exclusive(),
                    evaluation_point,
                    *claim,
                    source_pair,
                    &mut self.accumulated_initial_pairs[query_index],
                )?;
            }
        }
        Ok(())
    }

    fn consume_fri_tree(
        &mut self,
        fold_ordinal: usize,
        leaves: &[super::super::DecodedProofPhasePairLeaf],
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        if self
            .claim_groups
            .get(self.next_catalog_index)
            .is_none_or(|claims| !claims.is_empty())
        {
            return Err(CommonProofVerifierError::InvalidOpeningClaim);
        }
        self.ensure_fri_states(query_representatives)?;
        let states = self
            .fri_states
            .as_mut()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let shift = u32::try_from(fold_ordinal)
            .ok()
            .and_then(|ordinal| ordinal.checked_add(2))
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let leaf_count = u64::try_from(self.evaluation_domain.size())
            .ok()
            .and_then(|domain_size| domain_size.checked_shr(shift))
            .filter(|leaf_count| *leaf_count != 0)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        for (state, representative) in states.iter_mut().zip(query_representatives.iter().copied())
        {
            let leaf = leaf_for_index(leaves, representative % leaf_count)?;
            let next_pair = opened_pair(leaf, 0, RelationColumnValueType::ChallengeExtension)?;
            self.fri_verifier
                .verify_nonterminal_layer(state, fold_ordinal, next_pair)?;
        }
        Ok(())
    }

    fn ensure_fri_states(
        &mut self,
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        if self.fri_states.is_some() {
            return Ok(());
        }
        let states = query_representatives
            .iter()
            .copied()
            .zip(self.accumulated_initial_pairs.iter().copied())
            .map(|(representative, initial_pair)| {
                self.fri_verifier
                    .begin_query(representative, initial_pair)
                    .map_err(CommonProofVerifierError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.fri_states = Some(states);
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        catalog_entry_count: usize,
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        if self.next_catalog_index != catalog_entry_count {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        self.ensure_fri_states(query_representatives)?;
        for state in self
            .fri_states
            .take()
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?
        {
            self.fri_verifier.finish_query(state)?;
        }
        Ok(())
    }
}

fn verify_relation_tree_columns<ColumnEvaluator>(
    leaves: &[super::super::DecodedProofPhasePairLeaf],
    columns: &[u32],
    variant: &RelationPlanVariant,
    query_representatives: &[u64],
    evaluation_domain: ProofEvaluationDomain,
    evaluate_verified_column: &mut ColumnEvaluator,
) -> Result<(), CommonProofVerifierError>
where
    ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
{
    if leaves.len() != query_representatives.len() {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    for (leaf, representative) in leaves.iter().zip(query_representatives) {
        if leaf.leaf_index() != *representative
            || leaf.first_point_values().len() != columns.len()
            || leaf.opposite_point_values().len() != columns.len()
        {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
    }

    for (column_position, column_ordinal) in columns.iter().copied().enumerate() {
        let column_index = usize::try_from(column_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        let column = variant
            .ordered_columns()
            .get(column_index)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        for (leaf, representative) in leaves.iter().zip(query_representatives.iter().copied()) {
            let pair = opened_pair(leaf, column_position, column.value_type())?;
            if matches!(
                column.origin(),
                RelationColumnOrigin::VerifierSequence { .. }
            ) {
                let expected_pair = evaluate_verified_column
                    .evaluate_at_evaluation_domain_pair(
                        column_ordinal,
                        evaluation_domain,
                        representative,
                    )
                    .ok_or(CommonProofVerifierError::MissingVerifiedColumnValue)?;
                if pair != expected_pair {
                    return Err(CommonProofVerifierError::VerifiedColumnMismatch);
                }
            }
        }
    }
    Ok(())
}

fn leaf_for_index(
    leaves: &[super::super::DecodedProofPhasePairLeaf],
    expected_index: u64,
) -> Result<&super::super::DecodedProofPhasePairLeaf, CommonProofVerifierError> {
    leaves
        .binary_search_by_key(&expected_index, |leaf| leaf.leaf_index())
        .ok()
        .and_then(|index| leaves.get(index))
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)
}

fn opened_pair(
    leaf: &super::super::DecodedProofPhasePairLeaf,
    column_position: usize,
    expected_value_type: RelationColumnValueType,
) -> Result<OpenedFriLayerPair, CommonProofVerifierError> {
    let first = leaf
        .first_point_values()
        .get(column_position)
        .copied()
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
    let opposite = leaf
        .opposite_point_values()
        .get(column_position)
        .copied()
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
    let convert = |value| match (value, expected_value_type) {
        (ProofTreeValue::Base(value), RelationColumnValueType::BaseField) => {
            Ok(ProofChallengeExtensionElement::from_base(value))
        }
        (ProofTreeValue::Extension(value), RelationColumnValueType::ChallengeExtension) => {
            Ok(value)
        }
        _ => Err(CommonProofVerifierError::InvalidTreeLayout),
    };
    Ok(OpenedFriLayerPair::new(convert(first)?, convert(opposite)?))
}

fn add_opening_claim(
    opening_degree_bound_exclusive: u64,
    evaluation_point: super::super::ProofBaseFieldElement,
    claim: RuntimeOpeningClaim,
    source_pair: OpenedFriLayerPair,
    accumulator: &mut OpenedFriLayerPair,
) -> Result<(), CommonProofVerifierError> {
    let term = evaluate_normalized_opening_claim_pair(
        opening_degree_bound_exclusive,
        evaluation_point,
        ProofOpeningClaimEvaluation::new(
            claim.source_degree_bound_exclusive,
            claim.opening_point,
            claim.opened_value,
            source_pair,
            claim.batching_coefficient,
        ),
    )?;
    *accumulator = add_pairs(*accumulator, term);
    Ok(())
}

fn add_pairs(left: OpenedFriLayerPair, right: OpenedFriLayerPair) -> OpenedFriLayerPair {
    OpenedFriLayerPair::new(
        left.first().add(right.first()),
        left.opposite().add(right.opposite()),
    )
}
