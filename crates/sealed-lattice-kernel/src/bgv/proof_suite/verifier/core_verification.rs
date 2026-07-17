use super::{
    BoundTreeConstructionKind, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, CommonProofTranscript, CommonProofVerifierError, CompleteProofTreeCatalog,
    FOUNDATION_PROFILE, OpenedFriLayerPair, PROOF_HEADER_HASH_DOMAIN,
    PROOF_OBJECT_HEADER_SCHEMA_VERSION, ProofApplicationSlotCeilings,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofLeafVisibility,
    ProofTreeCatalogSource, ProofTreeRole, RelationColumnOrigin, RelationColumnValueType,
    RelationOpeningSourceClass, RelationPlanCheckContext, RelationPlanVariant,
    RelationProofTreeInput, RelationSelectorPathStep, RelationTreeDescriptor,
    SelectedApplicationStatementContext, SelectorPathStepKind, StatementOwnedProofTreeInput,
    VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN, VerifiedEvaluatorAuxiliaryRoot,
    VerifiedStatementOwnedTree, decode_selected_application_statement, hash_foundation_tuple_512,
    hash_framed_parts_512, selected_evaluator_aggregate_entry_roots,
    selected_relation_plan_check_context,
};
#[cfg(test)]
use super::{
    CommonProofPrivacyMode, CommonProofVerificationInput, PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
    ProofBodyError, ProofBodyLayout, ProofByteSource, ProofFriQueryVerifier, ProofTreeCatalogInput,
    QueryVerificationWorkspace, RelationApplicationChallengeAssignment, SELECTED_PROOF_FIELD_INDEX,
    ValidatedRelationPlanArtifact, VerifiedCommonProof, build_complete_proof_tree_catalog,
    build_runtime_claim_groups, decode_proof_body_prefix, verify_and_slice_proof_header,
};

/// Resolves plan-addressed verifier-sequence columns from verified statement,
/// suite, slot, sampler, or protocol sources. Proof bytes never supply these
/// values. Implementations retaining a verifier column over the evaluation
/// domain should override the pair method to avoid per-query interpolation.
pub(crate) trait VerifiedRelationColumnEvaluator {
    fn evaluate_at_extension_point(
        &mut self,
        column_ordinal: u32,
        point: ProofChallengeExtensionElement,
    ) -> Option<ProofChallengeExtensionElement>;

    fn evaluate_at_evaluation_domain_pair(
        &mut self,
        column_ordinal: u32,
        evaluation_domain: ProofEvaluationDomain,
        query_representative: u64,
    ) -> Option<OpenedFriLayerPair> {
        let evaluation_point = evaluation_domain
            .point(usize::try_from(query_representative).ok()?)
            .ok()?;
        let first = self.evaluate_at_extension_point(
            column_ordinal,
            ProofChallengeExtensionElement::from_base(evaluation_point),
        )?;
        let opposite = self.evaluate_at_extension_point(
            column_ordinal,
            ProofChallengeExtensionElement::from_base(evaluation_point.negate()),
        )?;
        Some(OpenedFriLayerPair::new(first, opposite))
    }
}

/// Verifies one complete common proof. Returning `None` from a verified-column
/// evaluator fails closed; prover and bound-tree columns never call it.
#[cfg(test)]
pub(crate) fn verify_common_proof<Source, ColumnEvaluator>(
    input: CommonProofVerificationInput<'_, Source>,
    evaluate_verified_column: &mut ColumnEvaluator,
) -> Result<VerifiedCommonProof, CommonProofVerifierError>
where
    Source: ProofByteSource + ?Sized,
    ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
{
    let _validated_artifact = ValidatedRelationPlanArtifact::from_compiled_plan(
        input.relation_plan,
        input.relation_context,
    )?;
    let application_statement = decode_application_statement(
        input.canonical_application_statement_bytes,
        input
            .relation_plan
            .application_statement_schema_identifier(),
        input.protocol_version,
        input.suite_identifier,
        input.schedule_position,
        input.top_count,
        input.relation_context,
    )?;
    validate_evaluator_auxiliary_root_linkage(
        &application_statement,
        input
            .relation_plan
            .application_statement_schema_identifier(),
        input.schedule_position,
        input.top_count,
        input.evaluator_auxiliary_roots,
        input.relation_context,
    )?;
    let canonical_proof_object_header_bytes = CanonicalTuple::new(
        PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
        PROOF_OBJECT_HEADER_SCHEMA_VERSION,
        vec![
            CanonicalItem::variable_bytes(input.canonical_application_statement_bytes)
                .map_err(|_| CommonProofVerifierError::CanonicalEncoding)?,
        ],
    )
    .encode()
    .map_err(|_| CommonProofVerifierError::CanonicalEncoding)?;
    let proof_body_source = verify_and_slice_proof_header(
        input.proof_source,
        input.declared_proof_byte_length,
        input.proof_byte_ceiling,
        &canonical_proof_object_header_bytes,
    )?;
    let proof_body_byte_ceiling = input
        .proof_byte_ceiling
        .checked_sub(canonical_proof_object_header_bytes.len())
        .ok_or(CommonProofVerifierError::InvalidProofHeader)?;

    let variant = input
        .relation_plan
        .select_variant(input.schedule_position, input.top_count)?;
    let transcript_schedule = variant.common_proof_transcript_schedule(input.relation_context)?;
    let evaluation_domain = ProofEvaluationDomain::new(
        usize::try_from(variant.evaluation_domain_size())
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
        input.relation_context.evaluation_coset_offset,
    )?;
    if evaluation_domain.generator().canonical()
        != input.relation_context.evaluation_domain_generator
    {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }

    let relation_trees =
        derive_relation_tree_inputs(variant, &application_statement, input.statement_owned_trees)?;
    let catalog = build_complete_proof_tree_catalog(
        ProofTreeCatalogInput {
            suite_identifier: input.suite_identifier,
            canonical_proof_object_header_bytes: canonical_proof_object_header_bytes.clone(),
            application_statement_schema_identifier: input
                .relation_plan
                .application_statement_schema_identifier(),
            proof_field_index: SELECTED_PROOF_FIELD_INDEX,
            evaluation_domain_size: variant.evaluation_domain_size(),
            relation_trees,
        },
        &transcript_schedule,
    )?;
    let layout = ProofBodyLayout::new(
        catalog,
        &transcript_schedule,
        transcript_schedule.terminal_coefficient_count(),
    )?;
    let pending = decode_proof_body_prefix(
        &proof_body_source,
        proof_body_source.byte_length(),
        proof_body_byte_ceiling,
        &layout,
    )?;

    let mut transcript = CommonProofTranscript::new(
        input.protocol_version,
        input.suite_identifier,
        input
            .relation_plan
            .application_statement_schema_identifier(),
        &canonical_proof_object_header_bytes,
        transcript_schedule.clone(),
    )?;
    absorb_relation_roots(
        &mut transcript,
        layout.catalog(),
        pending.tree_roots(),
        ProofTreeRole::BaseOracle,
        transcript_schedule.ordered_base_tree_ordinals(),
    )?;

    let mut application_challenges = Vec::new();
    application_challenges
        .try_reserve_exact(
            transcript_schedule
                .ordered_application_challenge_groups()
                .iter()
                .try_fold(0_usize, |count, group| {
                    count.checked_add(usize::from(group.coordinate_count()))
                })
                .ok_or(CommonProofVerifierError::InvalidTreeLayout)?,
        )
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for scheduled_group in transcript_schedule.ordered_application_challenge_groups() {
        let challenge = scheduled_group.challenge();
        let values = transcript.sample_application_challenge_group(challenge)?;
        if values.len() != usize::from(scheduled_group.coordinate_count()) {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        for (repetition_ordinal, value) in values.into_iter().enumerate() {
            application_challenges.push(RelationApplicationChallengeAssignment::new(
                challenge,
                u16::try_from(repetition_ordinal)
                    .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
                value,
            )?);
        }
    }

    absorb_relation_roots(
        &mut transcript,
        layout.catalog(),
        pending.tree_roots(),
        ProofTreeRole::AuxiliaryOracle,
        transcript_schedule.ordered_auxiliary_tree_ordinals(),
    )?;

    let mut composition_challenges = Vec::new();
    composition_challenges
        .try_reserve_exact(usize::from(
            transcript_schedule.composition_challenge_count(),
        ))
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for constraint_ordinal in 0..transcript_schedule.composition_challenge_count() {
        composition_challenges.push(transcript.sample_composition_challenge(constraint_ordinal)?);
    }

    for component_ordinal in 0..transcript_schedule.quotient_component_count() {
        transcript.absorb_quotient_root(
            component_ordinal,
            catalog_root(layout.catalog(), pending.tree_roots(), |source| {
                source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
            })?,
        )?;
    }

    let mut deep_points = Vec::new();
    deep_points
        .try_reserve_exact(usize::from(transcript_schedule.deep_point_count()))
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for point_ordinal in 0..transcript_schedule.deep_point_count() {
        let mut relation_error = None;
        let sampled = transcript.sample_deep_point(point_ordinal, |candidate| {
            match variant.deep_point_candidate_is_forbidden(
                input.relation_context,
                point_ordinal,
                candidate,
                &deep_points,
            ) {
                Ok(is_forbidden) => is_forbidden,
                Err(error) => {
                    relation_error = Some(error);
                    true
                }
            }
        });
        if let Some(error) = relation_error {
            return Err(error.into());
        }
        deep_points.push(sampled?);
    }
    let opening_points = variant.derive_opening_points(input.relation_context, &deep_points)?;
    verify_statement_derived_deep_values(
        variant,
        &opening_points,
        pending.deep_evaluations(),
        evaluate_verified_column,
    )?;
    variant.verify_deep_composition(
        input.relation_context,
        &application_challenges,
        &composition_challenges,
        &deep_points,
        pending.deep_evaluations(),
    )?;
    transcript.absorb_deep_evaluations(pending.deep_evaluations())?;

    if transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing {
        transcript.absorb_opening_batch_mask_root(catalog_root(
            layout.catalog(),
            pending.tree_roots(),
            |source| source == ProofTreeCatalogSource::OpeningBatchMask,
        )?)?;
    }

    let mut opening_batch_coefficients = Vec::new();
    let opening_claim_count = usize::try_from(transcript_schedule.opening_claim_count())
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    opening_batch_coefficients
        .try_reserve_exact(opening_claim_count)
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for claim_ordinal in 0..transcript_schedule.opening_claim_count() {
        opening_batch_coefficients.push(transcript.sample_opening_batch_challenge(claim_ordinal)?);
    }

    let mut fri_fold_challenges = Vec::new();
    fri_fold_challenges
        .try_reserve_exact(usize::from(transcript_schedule.fri_fold_count()))
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    for fold_ordinal in 0..transcript_schedule.fri_fold_count() {
        fri_fold_challenges.push(transcript.sample_fri_fold_challenge(fold_ordinal)?);
        if fold_ordinal + 1 < transcript_schedule.fri_fold_count() {
            transcript.absorb_fri_layer_root(
                fold_ordinal,
                catalog_root(layout.catalog(), pending.tree_roots(), |source| {
                    source == ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal }
                })?,
            )?;
        }
    }
    transcript.absorb_fri_terminal_coefficients(pending.terminal_coefficients())?;

    let mut sampled_query_representatives = transcript.sample_query_representatives()?;
    let sorted_query_representatives = transcript.sorted_query_representatives()?;
    sampled_query_representatives.sort_unstable();
    if sampled_query_representatives != sorted_query_representatives {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }

    let claim_groups = build_runtime_claim_groups(
        variant,
        layout.catalog(),
        &opening_points,
        pending.deep_evaluations(),
        &opening_batch_coefficients,
    )?;
    let fri_verifier = ProofFriQueryVerifier::new(
        evaluation_domain,
        fri_fold_challenges,
        pending.terminal_coefficients().to_vec(),
        usize::try_from(
            input
                .relation_context
                .final_polynomial_degree_bound_exclusive,
        )
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
    )?;
    let mut workspace = QueryVerificationWorkspace::new(
        layout.catalog().entries().len(),
        evaluation_domain,
        sorted_query_representatives.len(),
        claim_groups,
        fri_verifier,
    )?;
    let mut query_opening_absorber =
        transcript.begin_query_openings(pending.query_section_byte_length()?)?;
    let mut query_verification_error = None;
    let decode_result = pending.decode_query_section(
        &sorted_query_representatives,
        &mut query_opening_absorber,
        |opening| {
            if let Err(error) = workspace.consume_opening(
                opening,
                variant,
                layout.catalog(),
                &sorted_query_representatives,
                evaluate_verified_column,
            ) {
                query_verification_error = Some(error);
                return Err(ProofBodyError::InvalidLeaf);
            }
            Ok(())
        },
    );
    if let Some(error) = query_verification_error {
        return Err(error);
    }
    let _decoded_body = decode_result?;
    workspace.finish(
        layout.catalog().entries().len(),
        &sorted_query_representatives,
    )?;
    transcript.finish_query_openings(query_opening_absorber)?;
    transcript.finish()?;
    let application_statement_schema_identifier = input
        .relation_plan
        .application_statement_schema_identifier();
    Ok(VerifiedCommonProof {
        protocol_version: input.protocol_version,
        suite_identifier: input.suite_identifier,
        application_statement_schema_identifier,
        application_statement_hash: verified_application_statement_hash(
            input.protocol_version,
            input.suite_identifier,
            application_statement_schema_identifier,
            input.canonical_application_statement_bytes,
        ),
        proof_header_hash: verified_proof_header_hash(&canonical_proof_object_header_bytes)?,
        proof_byte_length: u64::try_from(input.declared_proof_byte_length)
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
        verified_query_count: transcript_schedule.unique_query_count(),
        relation_plan_variant_hash: variant.canonical_hash()?,
        schedule_position: input.schedule_position,
        top_count: input.top_count,
    })
}

pub(crate) fn verified_application_statement_hash(
    protocol_version: u16,
    suite_identifier: [u8; 64],
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: &[u8],
) -> [u8; 64] {
    hash_framed_parts_512(
        VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN,
        &[
            &protocol_version.to_le_bytes(),
            &suite_identifier,
            &application_statement_schema_identifier.to_le_bytes(),
            canonical_application_statement_bytes,
        ],
    )
}

pub(super) fn verified_proof_header_hash(
    canonical_proof_object_header_bytes: &[u8],
) -> Result<[u8; 64], CommonProofVerifierError> {
    hash_foundation_tuple_512(
        PROOF_HEADER_HASH_DOMAIN,
        &[
            CanonicalItem::variable_bytes(canonical_proof_object_header_bytes)
                .map_err(|_| CommonProofVerifierError::CanonicalEncoding)?,
        ],
    )
    .map(|hash| hash.into_bytes())
    .map_err(|_| CommonProofVerifierError::CanonicalEncoding)
}

pub(super) fn decode_application_statement(
    canonical_bytes: &[u8],
    expected_schema_identifier: u16,
    protocol_version: u16,
    suite_identifier: [u8; 64],
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    relation_context: &RelationPlanCheckContext,
) -> Result<CanonicalTuple, CommonProofVerifierError> {
    if canonical_bytes.is_empty()
        || canonical_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    if relation_context == &selected_relation_plan_check_context() {
        return decode_selected_application_statement(
            canonical_bytes,
            expected_schema_identifier,
            SelectedApplicationStatementContext::new(
                protocol_version,
                suite_identifier,
                schedule_position,
                top_count,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement);
    }
    let statement = CanonicalTuple::decode(canonical_bytes, &CanonicalDecodeLimits::default())
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if statement.schema_identifier != expected_schema_identifier
        || statement.schema_version != PROOF_OBJECT_HEADER_SCHEMA_VERSION
        || statement
            .encode()
            .map_err(|_| CommonProofVerifierError::CanonicalEncoding)?
            != canonical_bytes
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    Ok(statement)
}

pub(super) fn validate_evaluator_auxiliary_root_linkage(
    application_statement: &CanonicalTuple,
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    verified_auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
    relation_context: &RelationPlanCheckContext,
) -> Result<(), CommonProofVerifierError> {
    if relation_context != &selected_relation_plan_check_context() {
        return if verified_auxiliary_roots.is_empty() {
            Ok(())
        } else {
            Err(CommonProofVerifierError::InvalidApplicationStatement)
        };
    }
    if application_statement_schema_identifier
        != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
    {
        return if verified_auxiliary_roots.is_empty() {
            Ok(())
        } else {
            Err(CommonProofVerifierError::InvalidApplicationStatement)
        };
    }
    let entry_ordinal =
        schedule_position.ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
    let entry = selected_evaluator_aggregate_entry_roots(
        application_statement,
        top_count.ok_or(CommonProofVerifierError::InvalidApplicationStatement)?,
        entry_ordinal,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if verified_auxiliary_roots.len() != 1
        || entry.entry_ordinal() != entry_ordinal
        || entry.position() != verified_auxiliary_roots[0].position()
        || entry.auxiliary_component_root()
            != verified_auxiliary_roots[0].auxiliary_component_root()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    Ok(())
}

pub(super) fn derive_relation_tree_inputs(
    variant: &RelationPlanVariant,
    application_statement: &CanonicalTuple,
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<Vec<RelationProofTreeInput>, CommonProofVerifierError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(variant.ordered_trees().len())
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    let mut consumed_statement_trees = vec![false; statement_owned_trees.len()];

    for (tree_index, tree) in variant.ordered_trees().iter().enumerate() {
        let ordered_tree_ordinal =
            u32::try_from(tree_index).map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let tree_role = match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(CommonProofVerifierError::InvalidTreeLayout),
                };
                let leaf_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|column_index| variant.ordered_columns().get(column_index))
                        .is_some_and(|column| {
                            matches!(column.origin(), RelationColumnOrigin::Prover)
                        })
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                validate_tree_columns(variant, ordered_column_ordinals, None)?;
                inputs.push(RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
                    leaf_visibility,
                });
            }
            RelationTreeDescriptor::BoundPublic {
                construction_kind,
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } => {
                validate_tree_columns(
                    variant,
                    ordered_column_ordinals,
                    Some(*expected_root_source_ordinal),
                )?;
                let mut matches = statement_owned_trees
                    .iter()
                    .enumerate()
                    .filter(|(_, input)| {
                        input.ordered_tree_ordinal == ordered_tree_ordinal
                            && input.expected_root_source_ordinal == *expected_root_source_ordinal
                    });
                let (input_index, input) = matches
                    .next()
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                if matches.next().is_some() || consumed_statement_trees[input_index] {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                let expected_row_width = ordered_column_ordinals.len();
                let expected_canonical_residue_moduli = ordered_column_ordinals
                    .iter()
                    .map(|column_ordinal| {
                        variant
                            .ordered_columns()
                            .get(*column_ordinal as usize)
                            .map(|column| column.canonical_residue_modulus())
                            .ok_or(CommonProofVerifierError::InvalidTreeLayout)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let construction_matches = match (&input.tree, construction_kind) {
                    (
                        StatementOwnedProofTreeInput::CommittedMaterial { .. },
                        BoundTreeConstructionKind::CommittedMaterial,
                    ) => expected_row_width == 4,
                    (
                        StatementOwnedProofTreeInput::SetupPolynomial { row_width, .. },
                        BoundTreeConstructionKind::SetupPolynomial,
                    ) => usize::try_from(*row_width).is_ok_and(|width| width == expected_row_width),
                    _ => false,
                };
                if !construction_matches
                    || input.ordered_canonical_residue_moduli != expected_canonical_residue_moduli
                {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                let value_path = variant
                    .verifier_source(*expected_root_source_ordinal)
                    .and_then(|source| source.application_statement_scalar_hash_path())
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                let expected_statement_root =
                    select_application_statement_hash(application_statement, value_path)?;
                let supplied_root = match &input.tree {
                    StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. }
                    | StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. } => {
                        *expected_root
                    }
                };
                if supplied_root != expected_statement_root {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                consumed_statement_trees[input_index] = true;
                inputs.push(RelationProofTreeInput::BoundPublic(input.tree.clone()));
            }
        }
    }
    if consumed_statement_trees.iter().any(|consumed| !consumed) {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    Ok(inputs)
}

enum SelectedApplicationStatementValue {
    Tuple(CanonicalTuple),
    Item(CanonicalItem),
}

fn select_application_statement_hash(
    application_statement: &CanonicalTuple,
    value_path: &[RelationSelectorPathStep],
) -> Result<[u8; 64], CommonProofVerifierError> {
    if value_path.is_empty() {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let mut selected = SelectedApplicationStatementValue::Tuple(application_statement.clone());
    for step in value_path {
        selected = match step.step_kind() {
            SelectorPathStepKind::TupleField => {
                let tuple = match selected {
                    SelectedApplicationStatementValue::Tuple(tuple) => tuple,
                    SelectedApplicationStatementValue::Item(item)
                        if item.item_type() == CanonicalItemType::NestedTuple =>
                    {
                        CanonicalTuple::decode(
                            item.canonical_bytes(),
                            &CanonicalDecodeLimits::default(),
                        )
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?
                    }
                    SelectedApplicationStatementValue::Item(_) => {
                        return Err(CommonProofVerifierError::InvalidBoundTree);
                    }
                };
                SelectedApplicationStatementValue::Item(
                    tuple
                        .items
                        .get(
                            usize::try_from(step.argument())
                                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                        )
                        .cloned()
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?,
                )
            }
            SelectorPathStepKind::LiteralListIndex => {
                let SelectedApplicationStatementValue::Item(item) = selected else {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                };
                SelectedApplicationStatementValue::Item(select_homogeneous_list_item(
                    &item,
                    usize::try_from(step.argument())
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                )?)
            }
            _ => return Err(CommonProofVerifierError::InvalidBoundTree),
        };
    }
    let SelectedApplicationStatementValue::Item(item) = selected else {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    };
    if item.item_type() != CanonicalItemType::Hash512 || item.canonical_bytes().len() != 64 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn select_homogeneous_list_item(
    list: &CanonicalItem,
    selected_index: usize,
) -> Result<CanonicalItem, CommonProofVerifierError> {
    if list.item_type() != CanonicalItemType::HomogeneousList {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let bytes = list.canonical_bytes();
    if bytes.len() < 6 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let element_type =
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([bytes[0], bytes[1]]))
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    let element_count =
        usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    if selected_index >= element_count {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let payload = &bytes[6..];
    let selected_bytes = match element_type {
        CanonicalItemType::Hash512 => {
            let expected_byte_length = element_count
                .checked_mul(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            if payload.len() != expected_byte_length {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            let start = selected_index
                .checked_mul(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            let end = start
                .checked_add(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            payload
                .get(start..end)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?
        }
        CanonicalItemType::NestedTuple => {
            let mut offset = 0_usize;
            let mut selected_range = None;
            for element_index in 0..element_count {
                let tuple_byte_length = encoded_tuple_byte_length(
                    payload
                        .get(offset..)
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?,
                )?;
                let next_offset = offset
                    .checked_add(tuple_byte_length)
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                if element_index == selected_index {
                    selected_range = Some((offset, next_offset));
                }
                offset = next_offset;
            }
            if offset != payload.len() {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            let (start, end) = selected_range.ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            payload
                .get(start..end)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?
        }
        _ => return Err(CommonProofVerifierError::InvalidBoundTree),
    };
    CanonicalItem::from_canonical_bytes(
        element_type,
        selected_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn encoded_tuple_byte_length(bytes: &[u8]) -> Result<usize, CommonProofVerifierError> {
    if bytes.len() < 8 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let item_count = usize::try_from(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let header = bytes
            .get(offset..offset + 6)
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([header[0], header[1]]))
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        let value_byte_length = usize::try_from(u32::from_le_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
        offset = offset
            .checked_add(6)
            .and_then(|value| value.checked_add(value_byte_length))
            .filter(|value| *value <= bytes.len())
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    }
    Ok(offset)
}

fn validate_tree_columns(
    variant: &RelationPlanVariant,
    ordered_column_ordinals: &[u32],
    expected_bound_root_source_ordinal: Option<u32>,
) -> Result<(), CommonProofVerifierError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    for column_ordinal in ordered_column_ordinals {
        let column_index = usize::try_from(*column_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        let column = variant
            .ordered_columns()
            .get(column_index)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        if column.value_type() != RelationColumnValueType::BaseField {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        match (column.origin(), expected_bound_root_source_ordinal) {
            (
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                },
                Some(expected),
            ) if *expected_root_source_ordinal == expected => {}
            (RelationColumnOrigin::BoundTree { .. }, _) | (_, Some(_)) => {
                return Err(CommonProofVerifierError::InvalidTreeLayout);
            }
            (_, None) => {}
        }
    }
    Ok(())
}

pub(super) fn absorb_relation_roots(
    transcript: &mut CommonProofTranscript,
    catalog: &CompleteProofTreeCatalog,
    roots: &[[u8; 64]],
    target_role: ProofTreeRole,
    ordered_role_ordinals: &[u16],
) -> Result<(), CommonProofVerifierError> {
    for role_ordinal in ordered_role_ordinals {
        let root = catalog_root(catalog, roots, |source| {
            source
                == ProofTreeCatalogSource::RelationProofCreated {
                    tree_role: target_role,
                    tree_ordinal: *role_ordinal,
                }
        })?;
        match target_role {
            ProofTreeRole::BaseOracle => {
                transcript.absorb_base_root(*role_ordinal, root)?;
            }
            ProofTreeRole::AuxiliaryOracle => {
                transcript.absorb_auxiliary_root(*role_ordinal, root)?;
            }
            _ => return Err(CommonProofVerifierError::InvalidTreeLayout),
        }
    }
    Ok(())
}

pub(super) fn catalog_root(
    catalog: &CompleteProofTreeCatalog,
    roots: &[[u8; 64]],
    mut matches_source: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<[u8; 64], CommonProofVerifierError> {
    if roots.len() != catalog.entries().len() {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    let mut matches = catalog
        .entries()
        .iter()
        .zip(roots)
        .filter(|(entry, _)| matches_source(entry.source()));
    let root = matches
        .next()
        .map(|(_, root)| *root)
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
    if matches.next().is_some() {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    Ok(root)
}

pub(super) fn verify_statement_derived_deep_values<ColumnEvaluator>(
    variant: &RelationPlanVariant,
    opening_points: &[ProofChallengeExtensionElement],
    deep_evaluations: &[ProofChallengeExtensionElement],
    evaluate_verified_column: &mut ColumnEvaluator,
) -> Result<(), CommonProofVerifierError>
where
    ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
{
    if deep_evaluations.len() != variant.ordered_opening_claims().len() {
        return Err(CommonProofVerifierError::InvalidOpeningClaim);
    }
    for (claim_ordinal, claim) in variant.ordered_opening_claims().iter().copied().enumerate() {
        if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let column_ordinal = claim
            .column_ordinal()
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        let column_index = usize::try_from(column_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
        let column = variant
            .ordered_columns()
            .get(column_index)
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        if !matches!(
            column.origin(),
            RelationColumnOrigin::VerifierSequence { .. }
        ) {
            continue;
        }
        let opening_point_index = usize::try_from(claim.opening_point_ordinal())
            .map_err(|_| CommonProofVerifierError::InvalidOpeningClaim)?;
        let point = opening_points
            .get(opening_point_index)
            .copied()
            .ok_or(CommonProofVerifierError::InvalidOpeningClaim)?;
        let expected = evaluate_verified_column
            .evaluate_at_extension_point(column_ordinal, point)
            .ok_or(CommonProofVerifierError::MissingVerifiedColumnValue)?;
        if deep_evaluations[claim_ordinal] != expected {
            return Err(CommonProofVerifierError::VerifiedColumnMismatch);
        }
    }
    Ok(())
}
