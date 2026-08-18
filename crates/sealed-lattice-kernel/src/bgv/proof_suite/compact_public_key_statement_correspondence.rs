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
        StreamDescriptor, derive_canonical_stream_descriptor,
    },
};

use super::{
    ProofBaseFieldElement, SelectedApplicationStatementContext,
    compact_proof_wire::CompactPublicInputBindings,
    compact_public_key_algebraic_verifier::AlgebraicallyVerifiedCompactPublicKeyProof,
    compact_public_key_verifier::VerifiedCompactPublicKeyTransport,
    decode_selected_public_key_share_statement,
    relation_plan::{
        BoundTreeConstructionKind, CompactPublicKeyRelationCatalog, RelationColumnOrigin,
        RelationColumnValueType, RelationTreeDescriptor,
        derive_compact_public_key_relation_catalog,
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
    fn require_complete(
        self,
        expected_public_ring_vector_count: u64,
        expected_verified_column_count: usize,
        expected_statement_tree_count: usize,
    ) -> Result<Self, RefusalReason> {
        if self.public_ring_vector_count != expected_public_ring_vector_count
            || usize::try_from(self.verified_column_count).ok()
                != Some(expected_verified_column_count)
            || self.verifier_sequence_column_count == 0
            || usize::try_from(self.statement_tree_count).ok()
                != Some(expected_statement_tree_count)
        {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) const fn public_ring_vector_count(self) -> u64 {
        self.public_ring_vector_count
    }

    #[cfg(test)]
    pub(crate) const fn verified_column_count(self) -> u32 {
        self.verified_column_count
    }

    #[cfg(test)]
    pub(crate) const fn verifier_sequence_column_count(self) -> u32 {
        self.verifier_sequence_column_count
    }

    #[cfg(test)]
    pub(crate) const fn statement_tree_count(self) -> u32 {
        self.statement_tree_count
    }
}

/// Exact accepted-setup terminal fields retained only after one compact proof
/// has passed transport, algebraic verification, and source correspondence.
/// There is no decoder or constructor from caller-provided fields.
pub(in crate::bgv) struct VerifiedCompactPublicKeyAcceptedTerminalSource {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    public_key_share_root: [u8; Hash512::BYTE_LENGTH],
    proof_stream_descriptor: StreamDescriptor,
}

impl VerifiedCompactPublicKeyAcceptedTerminalSource {
    pub(in crate::bgv) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(in crate::bgv) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(in crate::bgv) const fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    pub(in crate::bgv) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(in crate::bgv) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(in crate::bgv) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(in crate::bgv) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(in crate::bgv) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(in crate::bgv) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(in crate::bgv) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(in crate::bgv) const fn public_key_share_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_key_share_root
    }

    pub(in crate::bgv) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }
}

/// Linear verifier-owned bridge from one accepted package statement and its
/// positive same-secret prerequisite to the selected compact relation. The
/// authority owns the exact statement trees and verifier-sequence evaluator;
/// no later operation can substitute detached roots or randomness.
pub(in crate::bgv) struct VerifiedCompactPublicKeyStatementAuthority {
    statement_source: VerifiedCommonProofStatementSource,
    statement_trees: Vec<VerifiedStatementOwnedTree>,
    verified_column_evaluator: VerifiedKeyRelationColumnEvaluator,
    relation: CompactPublicKeyRelationCatalog,
    expected_public_input_bindings: CompactPublicInputBindings,
    terminal_source: VerifiedCompactPublicKeyAcceptedTerminalSource,
}

/// Positive compact proof terminal. Its accepted-setup source can be released
/// only by consuming the algebraic terminal after every public column has
/// independently matched the retained statement authority.
pub(in crate::bgv) struct SourceVerifiedCompactPublicKeyProof {
    _statement_source: VerifiedCommonProofStatementSource,
    _transport: VerifiedCompactPublicKeyTransport,
    #[cfg(test)]
    correspondence: CompactPublicKeyStatementCorrespondence,
    terminal_source: VerifiedCompactPublicKeyAcceptedTerminalSource,
}

impl SourceVerifiedCompactPublicKeyProof {
    pub(in crate::bgv) const fn roster_position(&self) -> u16 {
        self.terminal_source.roster_position()
    }

    #[cfg(test)]
    pub(in crate::bgv) const fn correspondence(&self) -> CompactPublicKeyStatementCorrespondence {
        self.correspondence
    }

    pub(in crate::bgv) fn into_accepted_terminal_source(
        self,
    ) -> VerifiedCompactPublicKeyAcceptedTerminalSource {
        self.terminal_source
    }
}

impl VerifiedCompactPublicKeyStatementAuthority {
    pub(in crate::bgv) const fn expected_public_input_bindings(
        &self,
    ) -> CompactPublicInputBindings {
        self.expected_public_input_bindings
    }

    /// Consumes the exact family statement source and derives every remaining
    /// verifier input from the same accepted public-randomness terminal.
    pub(in crate::bgv) fn from_verified_accepted_setup_sources(
        statement_source: VerifiedCommonProofStatementSource,
        verified_public_randomness: &VerifiedPublicRandomness,
        setup_polynomial_prerequisite: VerifiedSetupPolynomialLowDegreePrerequisite,
    ) -> Result<Self, RefusalReason> {
        let schema_identifier =
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let relation_input = selected_public_key_share_relation_plan_input()
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let compiled = compile_public_key_share_relation_with_source_layout(
            &relation_input,
            &relation_context,
        )
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

        let verified_context = verified_public_randomness.context();
        let application_source = statement_source.application_source_authority();
        let expected_bindings = CompactPublicInputBindings::new(
            application_source.suite_identifier(),
            statement_source.application_statement_hash(),
            verified_context.manifest_hash(),
            Hash512::from_bytes(relation.relation_plan_variant_hash()),
        );
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
        let expected_participant_identity = verified_public_randomness
            .ordered_participant_identities()
            .get(usize::from(statement.roster_position()))
            .ok_or(RefusalReason::WrongContext)?;
        if application_source.application_statement_schema_identifier() != schema_identifier
            || application_source.suite_identifier() != verified_context.suite_identifier()
            || application_source.ceremony_context_hash()
                != verified_context.ceremony_context_hash()
            || application_source.action_context_hash() != verified_context.action_context_hash()
            || application_source.producer_roster_position() != Some(statement.roster_position())
            || application_source.schedule_position().is_some()
            || application_source.producer_sequence().is_some()
            || statement.setup_proof_context_hash()
                != verified_public_randomness
                    .setup_proof_context_hash()
                    .into_bytes()
            || statement.participant_identity() != expected_participant_identity.into_bytes()
            || setup_polynomial_prerequisite.protocol_version()
                != verified_context.protocol_version()
            || setup_polynomial_prerequisite.suite_identifier()
                != verified_context.suite_identifier().into_bytes()
            || setup_polynomial_prerequisite.ceremony_context_hash()
                != verified_context.ceremony_context_hash().into_bytes()
            || setup_polynomial_prerequisite.action_context_hash()
                != verified_context.action_context_hash().into_bytes()
            || setup_polynomial_prerequisite.setup_proof_context_hash()
                != statement.setup_proof_context_hash()
            || setup_polynomial_prerequisite.participant_identity()
                != statement.participant_identity()
            || setup_polynomial_prerequisite.roster_position() != statement.roster_position()
            || setup_polynomial_prerequisite.anchor_commitment_roots()
                != statement.anchor_commitment_roots()
        {
            return Err(RefusalReason::MissingPrerequisite);
        }
        let proof_stream_descriptor = application_source.proof_stream_descriptor().clone();

        let statement_trees =
            VerifiedStatementOwnedTree::from_verified_accepted_setup_statement_source(
                &statement_source,
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

        Ok(Self {
            statement_source,
            statement_trees,
            verified_column_evaluator,
            relation,
            expected_public_input_bindings: expected_bindings,
            terminal_source: VerifiedCompactPublicKeyAcceptedTerminalSource {
                protocol_version: verified_context.protocol_version(),
                suite_identifier: verified_context.suite_identifier().into_bytes(),
                manifest_hash: verified_context.manifest_hash().into_bytes(),
                ceremony_context_hash: verified_context.ceremony_context_hash().into_bytes(),
                action_context_hash: verified_context.action_context_hash().into_bytes(),
                roster_hash: verified_context.roster_hash().into_bytes(),
                setup_proof_context_hash: statement.setup_proof_context_hash(),
                participant_identity: statement.participant_identity(),
                roster_position: statement.roster_position(),
                anchor_commitment_roots: statement.anchor_commitment_roots(),
                public_key_share_root: statement.public_key_share_root(),
                proof_stream_descriptor,
            },
        })
    }

    /// Recomputes every public compact ring vector from the independently
    /// checked statement source. Verifier-sequence columns are regenerated
    /// from accepted public randomness, while setup-polynomial columns are
    /// accepted only when they reproduce the exact four statement-owned roots.
    pub(in crate::bgv) fn bind_algebraically_verified_proof(
        self,
        algebraically_verified_proof: AlgebraicallyVerifiedCompactPublicKeyProof,
    ) -> Result<SourceVerifiedCompactPublicKeyProof, RefusalReason> {
        let transport = algebraically_verified_proof.into_transport();
        let correspondence = self
            .verify_transport_correspondence(&transport)?
            .require_complete(
                self.relation.public_input_ring_vector_count(),
                self.relation
                    .ordered_public_vectors()
                    .len()
                    .checked_mul(2)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
                self.statement_trees.len(),
            )?;
        #[cfg(not(test))]
        let _ = correspondence;
        Ok(SourceVerifiedCompactPublicKeyProof {
            _statement_source: self.statement_source,
            _transport: transport,
            #[cfg(test)]
            correspondence,
            terminal_source: self.terminal_source,
        })
    }

    fn verify_transport_correspondence(
        &self,
        transport: &VerifiedCompactPublicKeyTransport,
    ) -> Result<CompactPublicKeyStatementCorrespondence, RefusalReason> {
        let statement_source = &self.statement_source;
        let relation = &self.relation;
        let statement_trees = &self.statement_trees;
        let verified_column_evaluator = &self.verified_column_evaluator;
        let independently_selected_variant = statement_source
            .selected_relation_variant()
            .map_err(|_| RefusalReason::WrongContext)?;
        if transport.verifier_inputs().relation != relation {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        let recomputed_proof_stream_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::PublicKeyShareProof,
            transport.canonical_proof_bytes(),
        )?;
        if self.terminal_source.proof_stream_descriptor() != &recomputed_proof_stream_descriptor {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        if transport.public_input_bindings() != self.expected_public_input_bindings {
            return Err(RefusalReason::WrongContext);
        }

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
        if public_input_view.decoded().field_element_count() != expected_public_input_element_count
        {
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
            let mut root_builder =
                SetupPublicPolynomialRootBuilder::from_verifier_owned_context_hash(
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
