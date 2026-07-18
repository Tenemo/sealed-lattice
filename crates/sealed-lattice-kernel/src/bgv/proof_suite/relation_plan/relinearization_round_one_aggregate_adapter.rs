use crate::{
    bgv::{
        proof_suite::evaluator_aggregate_source::{
            CompleteListSetupPolynomialSourceInput,
            SelectedEvaluatorAggregateSourcePolynomialProvider,
        },
        setup::SetupGeneratedRelinearizationAggregateSourceAuthority,
    },
    foundation::{FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings, StreamDescriptor},
    hashing::hash_framed_parts_512,
};

use super::super::{
    CommonProofProverError, CommonProofSourcePolynomialRequestContext, RelationProofTreeInput,
    SelectedApplicationStatementContext, SelectedEvaluatorStoreSource,
    SetupPublicPolynomialContext, SetupPublicPolynomialRootRole,
    VerifiedRelinearizationRoundOneSourceMaterial,
    decode_selected_relinearization_round_one_aggregate_statement,
    verified_application_statement_hash,
};
use super::CompiledRelationPlan;

const RELINEARIZATION_ROUND_ONE_AGGREGATE_SOURCE_BINDING_DOMAIN: &str =
    "sealed-lattice/relinearization-round-one-aggregate/source-binding/v1";
const RELINEARIZATION_ROUND_ONE_AGGREGATE_ORDERED_SOURCE_BINDING_DOMAIN: &str =
    "sealed-lattice/relinearization-round-one-aggregate/ordered-source-binding/v1";
const RELINEARIZATION_ROUND_ONE_AGGREGATE_COMPONENT_BINDING_DOMAIN: &str =
    "sealed-lattice/relinearization-round-one-aggregate/component-binding/v1";
const RELINEARIZATION_ROUND_ONE_AGGREGATE_SOURCE_CATALOG_BINDING_DOMAIN: &str =
    "sealed-lattice/relinearization-round-one-aggregate/source-catalog-binding/v1";

fn stream_descriptor_binding(descriptor: &StreamDescriptor) -> ([u8; 64], [u8; 8]) {
    (
        descriptor.full_object_digest.into_bytes(),
        descriptor.total_byte_length.to_le_bytes(),
    )
}

fn source_binding(
    source: &VerifiedRelinearizationRoundOneSourceMaterial,
) -> [u8; Hash512::BYTE_LENGTH] {
    let proof_descriptor = source.proof_stream_descriptor();
    let (proof_digest, proof_byte_length) = stream_descriptor_binding(proof_descriptor);
    let [left_material, right_material] = source.component_materials();
    let (left_digest, left_byte_length) =
        stream_descriptor_binding(left_material.stream_descriptor());
    let (right_digest, right_byte_length) =
        stream_descriptor_binding(right_material.stream_descriptor());
    let root_pair = source.root_pair();
    hash_framed_parts_512(
        RELINEARIZATION_ROUND_ONE_AGGREGATE_SOURCE_BINDING_DOMAIN,
        &[
            &source.participant_identity(),
            &source.roster_position().to_le_bytes(),
            &source.anchor_commitment_roots()[0],
            &source.anchor_commitment_roots()[1],
            &source.anchor_commitment_roots()[2],
            &proof_digest,
            &proof_byte_length,
            &root_pair[0],
            &left_material.material_root().into_bytes(),
            &left_digest,
            &left_byte_length,
            &root_pair[1],
            &right_material.material_root().into_bytes(),
            &right_digest,
            &right_byte_length,
        ],
    )
}

fn aggregate_component_binding(
    component_role: u16,
    component: &crate::bgv::setup::SetupGeneratedRelinearizationComponentSource,
) -> [u8; Hash512::BYTE_LENGTH] {
    let (stream_digest, stream_byte_length) =
        stream_descriptor_binding(component.stream_descriptor());
    hash_framed_parts_512(
        RELINEARIZATION_ROUND_ONE_AGGREGATE_COMPONENT_BINDING_DOMAIN,
        &[
            &component_role.to_le_bytes(),
            &component.public_polynomial_context_hash(),
            &component.contribution_root(),
            &component.material_root().into_bytes(),
            &stream_digest,
            &stream_byte_length,
        ],
    )
}

fn authenticated_verified_source(
    material: &super::super::VerifiedKeySwitchComponentMaterial,
) -> Result<SelectedEvaluatorStoreSource, CommonProofProverError> {
    Ok(SelectedEvaluatorStoreSource::from_authenticated_authority(
        material.topology().clone(),
        material.material_root().into_bytes(),
        material.stream_descriptor().clone(),
        material
            .begin_authenticated_readback()
            .map_err(|_| CommonProofProverError::InvalidInput)?,
    ))
}

fn authenticated_generated_source(
    component: &crate::bgv::setup::SetupGeneratedRelinearizationComponentSource,
) -> Result<SelectedEvaluatorStoreSource, CommonProofProverError> {
    Ok(SelectedEvaluatorStoreSource::from_authenticated_authority(
        component.topology().clone(),
        component.material_root().into_bytes(),
        component.stream_descriptor().clone(),
        component
            .begin_authenticated_readback()
            .map_err(|_| CommonProofProverError::InvalidInput)?,
    ))
}

/// Prepares the exact ordered-ten `0x1215` complete-list relation. The source
/// corpus layout is derived here from the compact construction order: every
/// left contribution, every right contribution, then the generated left and
/// right aggregates. Relation trees still retain the checked plan's exact
/// left-list/output/right-list/output order. No detached host root, topology,
/// descriptor, or ordinal map participates in the construction.
pub(crate) fn prepare_relinearization_round_one_aggregate_source(
    relation_plan: &CompiledRelationPlan,
    ordered_sources: &[&VerifiedRelinearizationRoundOneSourceMaterial],
    aggregate_authority: &SetupGeneratedRelinearizationAggregateSourceAuthority,
) -> Result<
    (
        Vec<RelationProofTreeInput>,
        SelectedEvaluatorAggregateSourcePolynomialProvider,
        u64,
    ),
    CommonProofProverError,
> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let schedule_position = aggregate_authority.schedule_position();
    if FOUNDATION_PROFILE.participant_count != 10
        || aggregate_authority.protocol_version() != FOUNDATION_PROFILE.protocol_version
        || relation_plan.application_statement_schema_identifier()
            != ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        || ordered_sources.len() != participant_count
        || aggregate_authority.ordered_participant_identities().len() != participant_count
        || aggregate_authority.ordered_anchor_commitment_roots().len() != participant_count
        || aggregate_authority
            .ordered_round_one_proof_stream_descriptors()
            .len()
            != participant_count
        || aggregate_authority.ordered_source_root_pairs().len() != participant_count
    {
        return Err(CommonProofProverError::InvalidInput);
    }

    let canonical_application_statement_bytes =
        aggregate_authority.canonical_application_statement_bytes();
    let statement = decode_selected_relinearization_round_one_aggregate_statement(
        canonical_application_statement_bytes,
        SelectedApplicationStatementContext::new(
            aggregate_authority.protocol_version(),
            aggregate_authority.suite_identifier(),
            Some(schedule_position),
            None,
        ),
    )
    .map_err(|_| CommonProofProverError::InvalidInput)?;
    if statement.setup_proof_context_hash() != aggregate_authority.setup_proof_context_hash()
        || statement.schedule_position() != schedule_position
        || statement.ordered_source_root_pairs() != aggregate_authority.ordered_source_root_pairs()
        || statement.aggregate_left_root() != aggregate_authority.root_pair()[0]
        || statement.aggregate_right_root() != aggregate_authority.root_pair()[1]
    {
        return Err(CommonProofProverError::InvalidInput);
    }

    let relation_plan_hash = relation_plan.canonical_hash()?;
    let relation_plan_variant = relation_plan
        .select_variant(Some(schedule_position), None)?
        .clone();
    let relation_plan_variant_hash = relation_plan_variant.canonical_hash()?;
    let expected_tree_count = participant_count
        .checked_add(1)
        .and_then(|trees_per_component| trees_per_component.checked_mul(2))
        .ok_or(CommonProofProverError::CountOverflow)?;
    if relation_plan_variant.ordered_trees().len() != expected_tree_count {
        return Err(CommonProofProverError::InvalidInput);
    }
    let application_statement_hash = verified_application_statement_hash(
        aggregate_authority.protocol_version(),
        aggregate_authority.suite_identifier(),
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        canonical_application_statement_bytes,
    );

    let mut source_bindings = Vec::new();
    source_bindings
        .try_reserve_exact(participant_count)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut observed_identities = Vec::new();
    observed_identities
        .try_reserve_exact(participant_count)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    for (roster_ordinal, source) in ordered_sources.iter().copied().enumerate() {
        let roster_position =
            u16::try_from(roster_ordinal).map_err(|_| CommonProofProverError::CountOverflow)?;
        if source.protocol_version() != aggregate_authority.protocol_version()
            || source.suite_identifier() != aggregate_authority.suite_identifier()
            || source.ceremony_context_hash() != aggregate_authority.ceremony_context_hash()
            || source.action_context_hash() != aggregate_authority.action_context_hash()
            || source.roster_hash() != aggregate_authority.roster_hash()
            || source.setup_proof_context_hash() != aggregate_authority.setup_proof_context_hash()
            || source.schedule_position() != schedule_position
            || source.roster_position() != roster_position
            || observed_identities.contains(&source.participant_identity())
            || aggregate_authority
                .ordered_participant_identities()
                .get(roster_ordinal)
                != Some(&source.participant_identity())
            || aggregate_authority
                .ordered_anchor_commitment_roots()
                .get(roster_ordinal)
                != Some(&source.anchor_commitment_roots())
            || aggregate_authority
                .ordered_round_one_proof_stream_descriptors()
                .get(roster_ordinal)
                != Some(source.proof_stream_descriptor())
            || aggregate_authority
                .ordered_source_root_pairs()
                .get(roster_ordinal)
                != Some(&source.root_pair())
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        observed_identities.push(source.participant_identity());
        source_bindings.push(source_binding(source));
    }
    let source_binding_parts = source_bindings
        .iter()
        .map(|binding| binding.as_slice())
        .collect::<Vec<_>>();
    let ordered_source_binding = hash_framed_parts_512(
        RELINEARIZATION_ROUND_ONE_AGGREGATE_ORDERED_SOURCE_BINDING_DOMAIN,
        &source_binding_parts,
    );
    let aggregate_left_component = &aggregate_authority.components()[0];
    let aggregate_right_component = &aggregate_authority.components()[1];
    let aggregate_left_binding = aggregate_component_binding(0, aggregate_left_component);
    let aggregate_right_binding = aggregate_component_binding(1, aggregate_right_component);
    let source_catalog_binding = hash_framed_parts_512(
        RELINEARIZATION_ROUND_ONE_AGGREGATE_SOURCE_CATALOG_BINDING_DOMAIN,
        &[
            &aggregate_authority.protocol_version().to_le_bytes(),
            &aggregate_authority.suite_identifier(),
            &aggregate_authority.ceremony_context_hash(),
            &aggregate_authority.action_context_hash(),
            &aggregate_authority.roster_hash(),
            &aggregate_authority.setup_proof_context_hash(),
            &schedule_position.to_le_bytes(),
            &application_statement_hash,
            &relation_plan_hash,
            &relation_plan_variant_hash,
            &ordered_source_binding,
            &aggregate_left_binding,
            &aggregate_right_binding,
        ],
    );

    let request_context = CommonProofSourcePolynomialRequestContext::new(
        aggregate_authority.protocol_version(),
        aggregate_authority.suite_identifier(),
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        application_statement_hash,
        relation_plan_hash,
        relation_plan_variant_hash,
        Some(schedule_position),
        None,
    );
    let mut ordered_source_inputs = Vec::new();
    ordered_source_inputs
        .try_reserve_exact(expected_tree_count)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut ordered_source_storage_byte_offsets = vec![[0_u64; 2]; participant_count];
    let mut storage_byte_offset = 0_u64;
    for component_ordinal in 0..2 {
        for (source_ordinal, source) in ordered_sources.iter().copied().enumerate() {
            ordered_source_storage_byte_offsets[source_ordinal][component_ordinal] =
                storage_byte_offset;
            storage_byte_offset = storage_byte_offset
                .checked_add(
                    source.component_materials()[component_ordinal]
                        .stream_descriptor()
                        .total_byte_length,
                )
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
    }
    let aggregate_storage_byte_offsets = [
        storage_byte_offset,
        storage_byte_offset
            .checked_add(
                aggregate_left_component
                    .stream_descriptor()
                    .total_byte_length,
            )
            .ok_or(CommonProofProverError::CountOverflow)?,
    ];
    let source_corpus_byte_length = aggregate_storage_byte_offsets[1]
        .checked_add(
            aggregate_right_component
                .stream_descriptor()
                .total_byte_length,
        )
        .ok_or(CommonProofProverError::CountOverflow)?;
    for component_ordinal in 0..2 {
        let source_role = match component_ordinal {
            0 => SetupPublicPolynomialRootRole::RelinearizationRoundOneLeft,
            1 => SetupPublicPolynomialRootRole::RelinearizationRoundOneRight,
            _ => return Err(CommonProofProverError::InvalidInput),
        };
        for (source_ordinal, source) in ordered_sources.iter().copied().enumerate() {
            let material = source.component_materials()[component_ordinal];
            let public_polynomial_context_hash = SetupPublicPolynomialContext::new(
                source.setup_proof_context_hash(),
                source_role,
                Some(source.participant_identity()),
                Some(source.roster_position()),
                Some(schedule_position),
                None,
            )
            .and_then(|context| context.context_hash())
            .map_err(|_| CommonProofProverError::InvalidInput)?;
            ordered_source_inputs.push(
                CompleteListSetupPolynomialSourceInput::from_authenticated_source(
                    authenticated_verified_source(material)?,
                    ordered_source_storage_byte_offsets[source_ordinal][component_ordinal],
                    public_polynomial_context_hash,
                    source.root_pair()[component_ordinal],
                ),
            );
        }

        let (aggregate_component, expected_role) = match component_ordinal {
            0 => (
                aggregate_left_component,
                SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneLeft,
            ),
            1 => (
                aggregate_right_component,
                SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneRight,
            ),
            _ => return Err(CommonProofProverError::InvalidInput),
        };
        let aggregate_context_hash = SetupPublicPolynomialContext::new(
            aggregate_authority.setup_proof_context_hash(),
            expected_role,
            None,
            None,
            Some(schedule_position),
            None,
        )
        .and_then(|context| context.context_hash())
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        if aggregate_context_hash != aggregate_component.public_polynomial_context_hash() {
            return Err(CommonProofProverError::InvalidInput);
        }
        ordered_source_inputs.push(
            CompleteListSetupPolynomialSourceInput::from_authenticated_source(
                authenticated_generated_source(aggregate_component)?,
                aggregate_storage_byte_offsets[component_ordinal],
                aggregate_context_hash,
                aggregate_component.contribution_root(),
            ),
        );
    }

    let (relation_trees, provider) =
        SelectedEvaluatorAggregateSourcePolynomialProvider::prepare_complete_list(
            relation_plan,
            relation_plan_variant,
            request_context,
            source_catalog_binding,
            ordered_source_inputs,
        )?;
    Ok((relation_trees, provider, source_corpus_byte_length))
}
