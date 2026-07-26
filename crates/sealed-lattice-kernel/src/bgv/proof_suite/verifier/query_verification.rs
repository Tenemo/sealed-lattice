use super::{
    CommonProofVerifierError, CompleteProofTreeCatalog, OpenedFriLayerPair,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofFriQueryState,
    ProofFriQueryVerifier, ProofOpeningClaimEvaluation, ProofTreeCatalogSource, ProofTreeOpening,
    ProofTreeValue, RelationColumnValueType, RelationOpeningSourceClass, RelationPlanVariant,
    evaluate_normalized_opening_claim_pair,
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
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    batching_coefficients: &[ProofChallengeExtensionElement],
) -> Result<Vec<Vec<RuntimeOpeningClaim>>, CommonProofVerifierError> {
    if out_of_domain_evaluations.len() != variant.ordered_opening_claims().len()
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
                opened_value: out_of_domain_evaluations[claim_ordinal],
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
    pub(super) fn maximum_resident_owned_payload_byte_length(
        catalog_entry_count: usize,
        opening_claim_count: usize,
        query_representative_count: usize,
        fri_fold_count: usize,
        terminal_coefficient_count: usize,
    ) -> Option<u64> {
        let payload = |count: usize, value_byte_length: usize| {
            u64::try_from(count)
                .ok()?
                .checked_mul(u64::try_from(value_byte_length).ok()?)
        };
        [
            payload(
                catalog_entry_count,
                core::mem::size_of::<Vec<RuntimeOpeningClaim>>(),
            )?,
            payload(
                opening_claim_count,
                core::mem::size_of::<RuntimeOpeningClaim>(),
            )?,
            payload(
                query_representative_count,
                core::mem::size_of::<OpenedFriLayerPair>(),
            )?,
            payload(
                fri_fold_count,
                core::mem::size_of::<ProofChallengeExtensionElement>(),
            )?,
            payload(
                terminal_coefficient_count,
                core::mem::size_of::<ProofChallengeExtensionElement>(),
            )?,
            payload(
                query_representative_count,
                core::mem::size_of::<ProofFriQueryState>(),
            )?,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
    }

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

    pub(super) fn consume_opening(
        &mut self,
        opening: ProofTreeOpening<'_>,
        variant: &RelationPlanVariant,
        catalog: &CompleteProofTreeCatalog,
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
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

    fn consume_relation_tree(
        &mut self,
        catalog_index: usize,
        leaves: &[super::super::DecodedProofPhasePairLeaf],
        variant: &RelationPlanVariant,
        query_representatives: &[u64],
    ) -> Result<(), CommonProofVerifierError> {
        let tree = variant
            .ordered_trees()
            .get(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let columns = tree.ordered_column_ordinals();
        let claims = self
            .claim_groups
            .get(catalog_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;

        verify_relation_tree_columns(leaves, columns, variant, query_representatives)?;

        accumulate_relation_tree_opening_claims(
            leaves,
            claims,
            query_representatives,
            self.evaluation_domain,
            variant.opening_degree_bound_exclusive(),
            &mut self.accumulated_initial_pairs,
            |column_position| {
                let column_ordinal = *columns.get(column_position)?;
                usize::try_from(column_ordinal)
                    .ok()
                    .and_then(|column_index| variant.ordered_columns().get(column_index))
                    .map(|column| column.value_type())
            },
        )
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

fn verify_relation_tree_columns(
    leaves: &[super::super::DecodedProofPhasePairLeaf],
    columns: &[u32],
    variant: &RelationPlanVariant,
    query_representatives: &[u64],
) -> Result<(), CommonProofVerifierError> {
    verify_relation_tree_column_openings(leaves, columns, query_representatives, |column_ordinal| {
        usize::try_from(column_ordinal)
            .ok()
            .and_then(|column_index| variant.ordered_columns().get(column_index))
            .map(|column| column.value_type())
    })
}

fn verify_relation_tree_column_openings<ResolveColumn>(
    leaves: &[super::super::DecodedProofPhasePairLeaf],
    columns: &[u32],
    query_representatives: &[u64],
    mut resolve_column: ResolveColumn,
) -> Result<(), CommonProofVerifierError>
where
    ResolveColumn: FnMut(u32) -> Option<RelationColumnValueType>,
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
        let value_type =
            resolve_column(column_ordinal).ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        for leaf in leaves {
            opened_pair(leaf, column_position, value_type)?;
        }
    }
    Ok(())
}

fn accumulate_relation_tree_opening_claims<ResolveValueType>(
    leaves: &[super::super::DecodedProofPhasePairLeaf],
    claims: &[RuntimeOpeningClaim],
    query_representatives: &[u64],
    evaluation_domain: ProofEvaluationDomain,
    opening_degree_bound_exclusive: u64,
    accumulated_initial_pairs: &mut [OpenedFriLayerPair],
    mut resolve_value_type: ResolveValueType,
) -> Result<(), CommonProofVerifierError>
where
    ResolveValueType: FnMut(usize) -> Option<RelationColumnValueType>,
{
    if leaves.len() != query_representatives.len()
        || accumulated_initial_pairs.len() != query_representatives.len()
    {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    for (query_index, (leaf, representative)) in leaves
        .iter()
        .zip(query_representatives.iter().copied())
        .enumerate()
    {
        let evaluation_point = evaluation_domain.point(
            usize::try_from(representative)
                .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
        )?;
        for claim in claims {
            let column_position = claim
                .column_position
                .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
            let value_type = resolve_value_type(column_position)
                .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
            let source_pair = opened_pair(leaf, column_position, value_type)?;
            add_opening_claim(
                opening_degree_bound_exclusive,
                evaluation_point,
                *claim,
                source_pair,
                &mut accumulated_initial_pairs[query_index],
            )?;
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

#[cfg(test)]
mod tests {
    use crate::bgv::proof_suite::{
        DecodedProofPhasePairLeaf, PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement,
    };

    use super::*;

    const TEST_COLUMNS: [u32; 4] = [7, 2, 11, 5];
    const TEST_QUERY_REPRESENTATIVES: [u64; 3] = [3, 7, 19];
    const PROVER_COLUMN_POSITION: usize = 1;
    const EXTENSION_COLUMN_POSITION: usize = 2;

    #[test]
    fn relation_claims_remain_bound_to_each_query_after_column_major_verification() {
        let leaves = test_leaves(&TEST_QUERY_REPRESENTATIVES);
        let evaluation_domain = test_evaluation_domain();
        let claims = vec![
            test_runtime_claim(PROVER_COLUMN_POSITION, 3, 71, 5, 11),
            test_runtime_claim(EXTENSION_COLUMN_POSITION, 4, 73, 7, 13),
        ];
        let mut accumulated_pairs = vec![
            OpenedFriLayerPair::new(
                ProofChallengeExtensionElement::ZERO,
                ProofChallengeExtensionElement::ZERO,
            );
            TEST_QUERY_REPRESENTATIVES.len()
        ];
        let mut resolved_column_positions = Vec::new();
        accumulate_relation_tree_opening_claims(
            &leaves,
            &claims,
            &TEST_QUERY_REPRESENTATIVES,
            evaluation_domain,
            8,
            &mut accumulated_pairs,
            |column_position| {
                resolved_column_positions.push(column_position);
                TEST_COLUMNS
                    .get(column_position)
                    .and_then(|column_ordinal| test_column(*column_ordinal))
            },
        )
        .expect("the authenticated relation leaves and claims must be accepted");

        let expected_pairs = leaves
            .iter()
            .zip(TEST_QUERY_REPRESENTATIVES)
            .map(|(leaf, query_representative)| {
                let evaluation_point = evaluation_domain
                    .point(
                        usize::try_from(query_representative)
                            .expect("the query representative fits usize"),
                    )
                    .expect("the query representative is in the evaluation domain");
                claims.iter().copied().try_fold(
                    OpenedFriLayerPair::new(
                        ProofChallengeExtensionElement::ZERO,
                        ProofChallengeExtensionElement::ZERO,
                    ),
                    |accumulated_pair, claim| {
                        let source_pair = opened_pair(
                            leaf,
                            claim
                                .column_position
                                .expect("a relation-tree claim has a column position"),
                            test_column(
                                TEST_COLUMNS[claim.column_position.expect("column position")],
                            )
                            .expect("the test column exists"),
                        )?;
                        let term = evaluate_normalized_opening_claim_pair(
                            8,
                            evaluation_point,
                            ProofOpeningClaimEvaluation::new(
                                claim.source_degree_bound_exclusive,
                                claim.opening_point,
                                claim.opened_value,
                                source_pair,
                                claim.batching_coefficient,
                            ),
                        )?;
                        Ok::<_, CommonProofVerifierError>(add_pairs(accumulated_pair, term))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("the independent query-major claim evaluation succeeds");
        assert_eq!(accumulated_pairs, expected_pairs);
        assert_eq!(
            resolved_column_positions,
            vec![
                PROVER_COLUMN_POSITION,
                EXTENSION_COLUMN_POSITION,
                PROVER_COLUMN_POSITION,
                EXTENSION_COLUMN_POSITION,
                PROVER_COLUMN_POSITION,
                EXTENSION_COLUMN_POSITION,
            ],
        );
    }

    #[test]
    fn prover_columns_require_the_plan_declared_value_type() {
        let leaves = test_leaves(&TEST_QUERY_REPRESENTATIVES);
        let leaf = &leaves[0];
        let mut wrong_first_values = leaf.first_point_values().to_vec();
        wrong_first_values[PROVER_COLUMN_POSITION] =
            wrong_type_value(wrong_first_values[PROVER_COLUMN_POSITION]);
        let wrong_first_leaf = DecodedProofPhasePairLeaf::from_test_values(
            leaf.leaf_index(),
            wrong_first_values,
            leaf.opposite_point_values().to_vec(),
        );
        let mut wrong_first_leaves = leaves.clone();
        wrong_first_leaves[0] = wrong_first_leaf;
        assert_invalid_tree_layout(&wrong_first_leaves);

        let leaf = &leaves[1];
        let mut wrong_opposite_values = leaf.opposite_point_values().to_vec();
        wrong_opposite_values[PROVER_COLUMN_POSITION] =
            wrong_type_value(wrong_opposite_values[PROVER_COLUMN_POSITION]);
        let wrong_opposite_leaf = DecodedProofPhasePairLeaf::from_test_values(
            leaf.leaf_index(),
            leaf.first_point_values().to_vec(),
            wrong_opposite_values,
        );
        let mut wrong_opposite_leaves = leaves.clone();
        wrong_opposite_leaves[1] = wrong_opposite_leaf;
        assert_invalid_tree_layout(&wrong_opposite_leaves);
    }

    #[test]
    fn relation_leaf_count_index_and_width_mismatches_are_refused() {
        let leaves = test_leaves(&TEST_QUERY_REPRESENTATIVES);
        assert_invalid_tree_layout(&leaves[..leaves.len() - 1]);

        let mut wrong_index = leaves.clone();
        let wrong_index_leaf = DecodedProofPhasePairLeaf::from_test_values(
            wrong_index[1].leaf_index() + 1,
            wrong_index[1].first_point_values().to_vec(),
            wrong_index[1].opposite_point_values().to_vec(),
        );
        wrong_index[1] = wrong_index_leaf;
        assert_invalid_tree_layout(&wrong_index);

        let mut short_first_row = leaves.clone();
        let short_first_leaf = DecodedProofPhasePairLeaf::from_test_values(
            short_first_row[0].leaf_index(),
            short_first_row[0].first_point_values()[..TEST_COLUMNS.len() - 1].to_vec(),
            short_first_row[0].opposite_point_values().to_vec(),
        );
        short_first_row[0] = short_first_leaf;
        assert_invalid_tree_layout(&short_first_row);

        let mut long_opposite_row = leaves.clone();
        let mut long_opposite_values = long_opposite_row[2].opposite_point_values().to_vec();
        long_opposite_values.push(ProofTreeValue::Base(ProofBaseFieldElement::ZERO));
        let long_opposite_leaf = DecodedProofPhasePairLeaf::from_test_values(
            long_opposite_row[2].leaf_index(),
            long_opposite_row[2].first_point_values().to_vec(),
            long_opposite_values,
        );
        long_opposite_row[2] = long_opposite_leaf;
        assert_invalid_tree_layout(&long_opposite_row);
    }

    fn test_evaluation_domain() -> ProofEvaluationDomain {
        ProofEvaluationDomain::new(64, 7).expect("the deterministic test domain is valid")
    }

    fn test_column(column_ordinal: u32) -> Option<RelationColumnValueType> {
        match column_ordinal {
            7 | 2 => Some(RelationColumnValueType::BaseField),
            11 | 5 => Some(RelationColumnValueType::ChallengeExtension),
            _ => None,
        }
    }

    fn test_leaves(query_representatives: &[u64]) -> Vec<DecodedProofPhasePairLeaf> {
        query_representatives
            .iter()
            .copied()
            .map(|query_representative| {
                let pairs = TEST_COLUMNS
                    .iter()
                    .copied()
                    .map(|column_ordinal| {
                        non_verifier_pair(
                            column_ordinal,
                            query_representative,
                            test_column(column_ordinal).expect("the test column exists"),
                        )
                    })
                    .collect::<Vec<_>>();
                let first_point_values = TEST_COLUMNS
                    .iter()
                    .zip(&pairs)
                    .map(|(column_ordinal, pair)| {
                        typed_tree_value(
                            test_column(*column_ordinal).expect("the test column exists"),
                            pair.first(),
                        )
                    })
                    .collect();
                let opposite_point_values = TEST_COLUMNS
                    .iter()
                    .zip(&pairs)
                    .map(|(column_ordinal, pair)| {
                        typed_tree_value(
                            test_column(*column_ordinal).expect("the test column exists"),
                            pair.opposite(),
                        )
                    })
                    .collect();
                DecodedProofPhasePairLeaf::from_test_values(
                    query_representative,
                    first_point_values,
                    opposite_point_values,
                )
            })
            .collect()
    }

    fn non_verifier_pair(
        column_ordinal: u32,
        query_representative: u64,
        value_type: RelationColumnValueType,
    ) -> OpenedFriLayerPair {
        deterministic_pair(column_ordinal, query_representative, value_type, 7_000_000)
    }

    fn deterministic_pair(
        column_ordinal: u32,
        query_representative: u64,
        value_type: RelationColumnValueType,
        namespace: u64,
    ) -> OpenedFriLayerPair {
        let first_value =
            namespace + u64::from(column_ordinal) * 100 + query_representative * 2 + 1;
        let opposite_value = first_value + 1;
        let extension = |value| match value_type {
            RelationColumnValueType::BaseField => extension_from_base(value),
            RelationColumnValueType::ChallengeExtension => extension_from_coordinates(value),
        };
        OpenedFriLayerPair::new(extension(first_value), extension(opposite_value))
    }

    fn typed_tree_value(
        value_type: RelationColumnValueType,
        value: ProofChallengeExtensionElement,
    ) -> ProofTreeValue {
        match value_type {
            RelationColumnValueType::BaseField => {
                let coordinates = value.canonical_coordinates();
                assert_eq!(coordinates[1..], [0; PROOF_CHALLENGE_EXTENSION_DEGREE - 1]);
                ProofTreeValue::Base(
                    ProofBaseFieldElement::from_canonical(coordinates[0])
                        .expect("the base coordinate is canonical"),
                )
            }
            RelationColumnValueType::ChallengeExtension => ProofTreeValue::Extension(value),
        }
    }

    fn wrong_type_value(value: ProofTreeValue) -> ProofTreeValue {
        match value {
            ProofTreeValue::Base(value) => {
                ProofTreeValue::Extension(ProofChallengeExtensionElement::from_base(value))
            }
            ProofTreeValue::Extension(value) => ProofTreeValue::Base(
                ProofBaseFieldElement::from_canonical(value.canonical_coordinates()[0])
                    .expect("the first extension coordinate is canonical"),
            ),
        }
    }

    fn extension_from_base(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(value).expect("the test value is canonical"),
        )
    }

    fn extension_from_coordinates(first_coordinate: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_canonical_coordinates([
            first_coordinate,
            first_coordinate + 1,
            first_coordinate + 2,
            first_coordinate + 3,
            first_coordinate + 4,
        ])
        .expect("the deterministic extension coordinates are canonical")
    }

    fn test_runtime_claim(
        column_position: usize,
        source_degree_bound_exclusive: u64,
        opening_point_base: u64,
        opened_value: u64,
        batching_coefficient: u64,
    ) -> RuntimeOpeningClaim {
        RuntimeOpeningClaim {
            column_position: Some(column_position),
            source_degree_bound_exclusive,
            opening_point: ProofChallengeExtensionElement::from_canonical_coordinates([
                opening_point_base,
                1,
                0,
                0,
                0,
            ])
            .expect("the non-base opening point is canonical"),
            opened_value: extension_from_base(opened_value),
            batching_coefficient: extension_from_base(batching_coefficient),
        }
    }

    fn assert_invalid_tree_layout(leaves: &[DecodedProofPhasePairLeaf]) {
        assert_eq!(
            verify_relation_tree_column_openings(
                leaves,
                &TEST_COLUMNS,
                &TEST_QUERY_REPRESENTATIVES,
                test_column,
            ),
            Err(CommonProofVerifierError::InvalidTreeLayout),
        );
    }
}
