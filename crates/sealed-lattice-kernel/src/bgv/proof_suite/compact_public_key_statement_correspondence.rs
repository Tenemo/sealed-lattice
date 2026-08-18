use crate::{
    bgv::{
        proof_suite::{
            SetupPublicPolynomialRootBuilder, ValidatedRelationPlanArtifact,
            VerifiedCommonProofStatementSource, VerifiedKeyRelationColumnEvaluator,
            VerifiedStatementOwnedTree, compile_public_key_share_relation_with_source_layout,
            selected_public_key_share_relation_plan_input, selected_relation_plan_check_context,
        },
        setup::{VerifiedPublicRandomness, VerifiedSetupPolynomialLowDegreePrerequisite},
    },
    foundation::{
        CanonicalStreamDomain, Hash512, ProofApplicationSlotCeilings, RefusalReason,
        derive_canonical_stream_descriptor,
    },
};

use super::{
    ProofBaseFieldElement, SelectedApplicationStatementContext,
    compact_proof_wire::CompactPublicInputBindings,
    compact_public_key_verifier::VerifiedCompactPublicKeyTransport,
    decode_selected_public_key_share_statement,
    relation_plan::{
        BoundTreeConstructionKind, RelationColumnOrigin, RelationColumnValueType,
        RelationTreeDescriptor, derive_compact_public_key_relation_catalog,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactPublicKeyStatementCorrespondence {
    public_ring_vector_count: u64,
    verified_column_count: u32,
    verifier_sequence_column_count: u32,
    statement_tree_count: u32,
}

impl CompactPublicKeyStatementCorrespondence {
    pub(crate) const fn public_ring_vector_count(self) -> u64 {
        self.public_ring_vector_count
    }

    pub(crate) const fn verified_column_count(self) -> u32 {
        self.verified_column_count
    }

    pub(crate) const fn verifier_sequence_column_count(self) -> u32 {
        self.verifier_sequence_column_count
    }

    pub(crate) const fn statement_tree_count(self) -> u32 {
        self.statement_tree_count
    }
}

/// Recomputes every public compact ring vector from the independently checked
/// statement source. Verifier-sequence columns are regenerated from accepted
/// public randomness, while setup-polynomial columns are accepted only when
/// they reproduce the exact four statement-owned Merkle roots.
pub(crate) fn verify_selected_compact_public_key_statement_correspondence(
    transport: &VerifiedCompactPublicKeyTransport,
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
    setup_polynomial_prerequisite: &VerifiedSetupPolynomialLowDegreePrerequisite,
) -> Result<CompactPublicKeyStatementCorrespondence, RefusalReason> {
    let schema_identifier =
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(schema_identifier)
        .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
    let relation_input = selected_public_key_share_relation_plan_input()
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    let compiled =
        compile_public_key_share_relation_with_source_layout(&relation_input, &relation_context)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    let compiler_variant = compiled
        .relation_plan
        .select_variant(None, None)
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    let statement_variant = statement_source
        .selected_relation_variant()
        .map_err(|_| RefusalReason::WrongContext)?;
    if compiler_variant != statement_variant {
        return Err(RefusalReason::InvalidArithmeticRelation);
    }
    let relation = derive_compact_public_key_relation_catalog(
        &relation_input,
        compiler_variant,
        &compiled.source_layout,
    )
    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    if transport.verifier_inputs().relation != &relation {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }

    let verified_context = verified_public_randomness.context();
    let application_source = statement_source.application_source_authority();
    let recomputed_proof_stream_descriptor = derive_canonical_stream_descriptor(
        CanonicalStreamDomain::PublicKeyShareProof,
        transport.proof_view().canonical_bytes(),
    )?;
    if application_source.proof_stream_descriptor() != &recomputed_proof_stream_descriptor {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    let expected_bindings = CompactPublicInputBindings::new(
        application_source.suite_identifier(),
        statement_source.application_statement_hash(),
        verified_context.manifest_hash(),
        Hash512::from_bytes(relation.relation_plan_variant_hash()),
    );
    if transport.public_input_bindings() != expected_bindings {
        return Err(RefusalReason::WrongContext);
    }

    let statement = decode_selected_public_key_share_statement(
        statement_source.canonical_application_statement_bytes(),
        SelectedApplicationStatementContext::new(
            verified_context.protocol_version(),
            verified_context.suite_identifier().into_bytes(),
            None,
            None,
        ),
    )
    .map_err(|_| RefusalReason::MalformedEncoding)?;
    if setup_polynomial_prerequisite.protocol_version() != verified_context.protocol_version()
        || setup_polynomial_prerequisite.suite_identifier()
            != verified_context.suite_identifier().into_bytes()
        || setup_polynomial_prerequisite.ceremony_context_hash()
            != verified_context.ceremony_context_hash().into_bytes()
        || setup_polynomial_prerequisite.action_context_hash()
            != verified_context.action_context_hash().into_bytes()
        || setup_polynomial_prerequisite.setup_proof_context_hash()
            != statement.setup_proof_context_hash()
        || setup_polynomial_prerequisite.participant_identity() != statement.participant_identity()
        || setup_polynomial_prerequisite.roster_position() != statement.roster_position()
        || setup_polynomial_prerequisite.anchor_commitment_roots()
            != statement.anchor_commitment_roots()
    {
        return Err(RefusalReason::MissingPrerequisite);
    }

    let statement_trees =
        VerifiedStatementOwnedTree::from_verified_accepted_setup_statement_source(
            statement_source,
            verified_public_randomness,
        )
        .map_err(|_| RefusalReason::WrongContext)?;
    let relation_plan_artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
        compiled.relation_plan,
        &relation_context,
    )
    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    let independently_selected_variant = relation_plan_artifact
        .compiled_plan()
        .select_variant(None, None)
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    let verified_column_evaluator =
        VerifiedKeyRelationColumnEvaluator::from_verified_public_randomness(
            verified_public_randomness,
            &relation_plan_artifact,
            independently_selected_variant,
        )?;

    let trace_domain_size = usize::try_from(independently_selected_variant.trace_domain_size())
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let evaluation_domain_size =
        usize::try_from(independently_selected_variant.evaluation_domain_size())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let ring_degree = usize::try_from(relation.ring_degree())
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if trace_domain_size
        .checked_mul(2)
        .filter(|derived_ring_degree| *derived_ring_degree == ring_degree)
        .is_none()
    {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }
    let public_input_view = transport.public_input_view();
    let expected_public_input_element_count = relation
        .public_input_ring_vector_count()
        .checked_mul(relation.ring_degree())
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    if public_input_view.decoded().field_element_count() != expected_public_input_element_count {
        return Err(RefusalReason::WrongTypeOrLength);
    }

    let ordered_columns = independently_selected_variant.ordered_columns();
    let mut public_input_offset_by_column = vec![None; ordered_columns.len()];
    for (vector_ordinal, vector) in relation.ordered_public_vectors().iter().enumerate() {
        let vector_first_element = vector_ordinal
            .checked_mul(ring_degree)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        for (half_ordinal, column_ordinal) in vector.column_ordinals().into_iter().enumerate() {
            let column_index = usize::try_from(column_ordinal)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let first_element = half_ordinal
                .checked_mul(trace_domain_size)
                .and_then(|offset| vector_first_element.checked_add(offset))
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let destination = public_input_offset_by_column
                .get_mut(column_index)
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            if destination.replace(first_element).is_some() {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
        }
    }

    let mut consumed_public_columns = vec![false; ordered_columns.len()];
    let mut verifier_sequence_column_count = 0_u32;
    for (column_index, first_element) in public_input_offset_by_column.iter().enumerate() {
        let Some(first_element) = *first_element else {
            continue;
        };
        let descriptor = &ordered_columns[column_index];
        match descriptor.origin() {
            RelationColumnOrigin::VerifierSequence { .. } => {
                if descriptor.value_type() != RelationColumnValueType::BaseField {
                    return Err(RefusalReason::InvalidArithmeticRelation);
                }
                let expected_rows = verified_column_evaluator.verifier_owned_trace_rows(
                    u32::try_from(column_index)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )?;
                compare_public_input_trace_row(
                    public_input_view.canonical_bytes(),
                    public_input_view.decoded(),
                    first_element,
                    &expected_rows,
                )?;
                consumed_public_columns[column_index] = true;
                verifier_sequence_column_count = verifier_sequence_column_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
            RelationColumnOrigin::BoundTree { .. } => {}
            RelationColumnOrigin::Prover => {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
        }
    }

    let mut statement_tree_count = 0_u32;
    for (ordered_tree_ordinal, descriptor) in independently_selected_variant
        .ordered_trees()
        .iter()
        .enumerate()
    {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            expected_root_source_ordinal,
            ordered_column_ordinals,
            ..
        } = descriptor
        else {
            continue;
        };
        let statement_tree = statement_trees
            .iter()
            .find(|tree| {
                usize::try_from(tree.ordered_tree_ordinal()).ok() == Some(ordered_tree_ordinal)
            })
            .ok_or(RefusalReason::WrongContext)?;
        let expected_row_width = u32::try_from(ordered_column_ordinals.len())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let public_polynomial_context_hash = statement_tree
            .public_polynomial_context_hash()
            .ok_or(RefusalReason::WrongContext)?;
        if statement_tree.expected_root_source_ordinal() != *expected_root_source_ordinal
            || statement_tree.setup_public_polynomial_row_width() != Some(expected_row_width)
            || statement_tree.ordered_canonical_residue_moduli().len()
                != ordered_column_ordinals.len()
        {
            return Err(RefusalReason::WrongContext);
        }
        let mut root_builder = SetupPublicPolynomialRootBuilder::from_verifier_owned_context_hash(
            public_polynomial_context_hash,
            evaluation_domain_size,
            trace_domain_size,
            expected_row_width,
        )
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        for column_ordinal in ordered_column_ordinals {
            let column_index = usize::try_from(*column_ordinal)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let first_element = public_input_offset_by_column
                .get(column_index)
                .copied()
                .flatten()
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            let descriptor = ordered_columns
                .get(column_index)
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            if consumed_public_columns[column_index]
                || !matches!(
                    descriptor.origin(),
                    RelationColumnOrigin::BoundTree {
                        expected_root_source_ordinal: column_root_source_ordinal,
                    } if column_root_source_ordinal == expected_root_source_ordinal
                )
                || descriptor.value_type() != RelationColumnValueType::BaseField
            {
                return Err(RefusalReason::InvalidArithmeticRelation);
            }
            let trace_row = decode_public_input_trace_row(
                public_input_view.canonical_bytes(),
                public_input_view.decoded(),
                first_element,
                trace_domain_size,
            )?;
            root_builder
                .absorb_trace_row(&trace_row)
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            consumed_public_columns[column_index] = true;
        }
        let (recomputed_context_hash, recomputed_root) = root_builder
            .finish()
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        if recomputed_root != statement_tree.expected_root()
            || recomputed_context_hash != public_polynomial_context_hash
        {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        statement_tree_count = statement_tree_count
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
    }

    let verified_column_count = consumed_public_columns
        .iter()
        .filter(|consumed| **consumed)
        .count();
    if consumed_public_columns
        .iter()
        .zip(&public_input_offset_by_column)
        .any(|(consumed, offset)| *consumed != offset.is_some())
        || verified_column_count
            != relation
                .ordered_public_vectors()
                .len()
                .checked_mul(2)
                .ok_or(RefusalReason::OutsideSupportedProfile)?
        || usize::try_from(statement_tree_count).ok() != Some(statement_trees.len())
    {
        return Err(RefusalReason::InvalidArithmeticRelation);
    }

    Ok(CompactPublicKeyStatementCorrespondence {
        public_ring_vector_count: relation.public_input_ring_vector_count(),
        verified_column_count: u32::try_from(verified_column_count)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        verifier_sequence_column_count,
        statement_tree_count,
    })
}

fn compare_public_input_trace_row(
    canonical_public_input_bytes: &[u8],
    decoded_public_input: &super::compact_proof_wire::DecodedCompactPublicInput,
    first_element: usize,
    expected_rows: &[ProofBaseFieldElement],
) -> Result<(), RefusalReason> {
    for (row_ordinal, expected_value) in expected_rows.iter().copied().enumerate() {
        let element_ordinal = first_element
            .checked_add(row_ordinal)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let transported_value = decoded_public_input
            .field_element(canonical_public_input_bytes, element_ordinal)
            .map_err(|_| RefusalReason::MalformedEncoding)?;
        if transported_value != expected_value {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
    }
    Ok(())
}

fn decode_public_input_trace_row(
    canonical_public_input_bytes: &[u8],
    decoded_public_input: &super::compact_proof_wire::DecodedCompactPublicInput,
    first_element: usize,
    trace_domain_size: usize,
) -> Result<Vec<ProofBaseFieldElement>, RefusalReason> {
    let mut trace_row = Vec::new();
    trace_row
        .try_reserve_exact(trace_domain_size)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    for row_ordinal in 0..trace_domain_size {
        let element_ordinal = first_element
            .checked_add(row_ordinal)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        trace_row.push(
            decoded_public_input
                .field_element(canonical_public_input_bytes, element_ordinal)
                .map_err(|_| RefusalReason::MalformedEncoding)?,
        );
    }
    Ok(trace_row)
}
