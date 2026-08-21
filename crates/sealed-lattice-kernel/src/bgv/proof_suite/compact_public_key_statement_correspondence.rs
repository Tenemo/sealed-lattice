use crate::{
    bgv::{
        proof_suite::{
            SetupPublicPolynomialRootBuilder, SetupPublicPolynomialRootConstruction,
            SetupPublicPolynomialRootConstructionPoll, ValidatedRelationPlanArtifact,
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

struct ActiveStatementTreeCorrespondence {
    expected_root: [u8; Hash512::BYTE_LENGTH],
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    expected_root_source_ordinal: u32,
    ordered_column_ordinals: Vec<u32>,
    next_column_index: usize,
    root_builder: Option<SetupPublicPolynomialRootBuilder>,
    root_construction: Option<SetupPublicPolynomialRootConstruction>,
}

/// Pollable verifier-owned reconstruction of every transported public column.
/// Each work unit is one complete verifier-sequence column, one bound-tree
/// source column, or one setup-polynomial evaluation coset. All are safe
/// deterministic replay boundaries over the retained canonical inputs.
pub(in crate::bgv) struct CompactPublicKeyStatementCorrespondenceVerification {
    statement_authority: Option<VerifiedCompactPublicKeyStatementAuthority>,
    transport: Option<VerifiedCompactPublicKeyTransport>,
    trace_domain_size: usize,
    evaluation_domain_size: usize,
    public_input_offset_by_column: Vec<Option<usize>>,
    consumed_public_columns: Vec<bool>,
    next_verifier_column_index: usize,
    next_tree_descriptor_index: usize,
    active_statement_tree: Option<ActiveStatementTreeCorrespondence>,
    verifier_sequence_columns_complete: bool,
    completed_work_unit_count: u32,
    verifier_sequence_column_count: u32,
    statement_tree_count: u32,
    complete_proof: Option<Box<SourceVerifiedCompactPublicKeyProof>>,
}

pub(in crate::bgv) enum CompactPublicKeyStatementCorrespondenceVerificationPoll {
    WorkCompleted {
        completed_work_unit_count: u32,
        checkpoint_safe_boundary_ordinal: u32,
    },
    Complete(Box<SourceVerifiedCompactPublicKeyProof>),
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

    #[cfg(test)]
    pub(super) const fn source_verified_transport(&self) -> &VerifiedCompactPublicKeyTransport {
        &self._transport
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
    pub(in crate::bgv) fn begin_binding_algebraically_verified_proof(
        self,
        algebraically_verified_proof: AlgebraicallyVerifiedCompactPublicKeyProof,
    ) -> Result<CompactPublicKeyStatementCorrespondenceVerification, RefusalReason> {
        let transport = algebraically_verified_proof.into_transport();
        let statement_source = &self.statement_source;
        let relation = &self.relation;
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

        Ok(CompactPublicKeyStatementCorrespondenceVerification {
            consumed_public_columns: vec![false; ordered_columns.len()],
            statement_authority: Some(self),
            transport: Some(transport),
            trace_domain_size,
            evaluation_domain_size,
            public_input_offset_by_column,
            next_verifier_column_index: 0,
            next_tree_descriptor_index: 0,
            active_statement_tree: None,
            verifier_sequence_columns_complete: false,
            completed_work_unit_count: 0,
            verifier_sequence_column_count: 0,
            statement_tree_count: 0,
            complete_proof: None,
        })
    }
}

impl CompactPublicKeyStatementCorrespondenceVerification {
    pub(in crate::bgv) fn advance(
        &mut self,
        maximum_work_unit_count: u32,
    ) -> Result<CompactPublicKeyStatementCorrespondenceVerificationPoll, RefusalReason> {
        if maximum_work_unit_count == 0 {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let mut completed_work_unit_count = 0_u32;
        loop {
            if self.complete_proof.is_some() {
                if completed_work_unit_count != 0 {
                    return self.progress(completed_work_unit_count);
                }
                return Ok(
                    CompactPublicKeyStatementCorrespondenceVerificationPoll::Complete(
                        self.complete_proof
                            .take()
                            .ok_or(RefusalReason::ConsumedState)?,
                    ),
                );
            }
            if completed_work_unit_count == maximum_work_unit_count {
                return self.progress(completed_work_unit_count);
            }

            if !self.verifier_sequence_columns_complete {
                if self.verify_next_verifier_sequence_column()? {
                    completed_work_unit_count = completed_work_unit_count
                        .checked_add(1)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    self.completed_work_unit_count = self
                        .completed_work_unit_count
                        .checked_add(1)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    continue;
                }
                self.verifier_sequence_columns_complete = true;
            }

            if self.active_statement_tree.is_none()
                && !self.prepare_next_statement_tree_correspondence()?
            {
                self.finish_correspondence()?;
                continue;
            }

            let next_column = self.active_statement_tree.as_ref().and_then(|active| {
                active
                    .ordered_column_ordinals
                    .get(active.next_column_index)
                    .copied()
            });
            if let Some(column_ordinal) = next_column {
                self.absorb_statement_tree_column(column_ordinal)?;
                completed_work_unit_count = completed_work_unit_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                self.completed_work_unit_count = self
                    .completed_work_unit_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                continue;
            }

            let active_statement_tree = self
                .active_statement_tree
                .as_mut()
                .ok_or(RefusalReason::ConsumedState)?;
            if active_statement_tree.root_construction.is_none() {
                active_statement_tree.root_construction = Some(
                    active_statement_tree
                        .root_builder
                        .take()
                        .ok_or(RefusalReason::ConsumedState)?
                        .begin_root_construction()
                        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
                );
            }
            let remaining_work_unit_count = maximum_work_unit_count
                .checked_sub(completed_work_unit_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            match active_statement_tree
                .root_construction
                .as_mut()
                .ok_or(RefusalReason::ConsumedState)?
                .advance(remaining_work_unit_count)
                .map_err(|_| RefusalReason::InvalidArithmeticRelation)?
            {
                SetupPublicPolynomialRootConstructionPoll::WorkCompleted {
                    completed_coset_count,
                } => {
                    completed_work_unit_count = completed_work_unit_count
                        .checked_add(completed_coset_count)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    self.completed_work_unit_count = self
                        .completed_work_unit_count
                        .checked_add(completed_coset_count)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                }
                SetupPublicPolynomialRootConstructionPoll::Complete((
                    recomputed_context_hash,
                    recomputed_root,
                )) => {
                    if recomputed_root != active_statement_tree.expected_root
                        || recomputed_context_hash
                            != active_statement_tree.public_polynomial_context_hash
                    {
                        return Err(RefusalReason::WrongHashOrRoot);
                    }
                    self.statement_tree_count = self
                        .statement_tree_count
                        .checked_add(1)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    self.active_statement_tree = None;
                }
            }
        }
    }

    fn progress(
        &self,
        completed_work_unit_count: u32,
    ) -> Result<CompactPublicKeyStatementCorrespondenceVerificationPoll, RefusalReason> {
        if completed_work_unit_count == 0 {
            return Err(RefusalReason::ConsumedState);
        }
        Ok(
            CompactPublicKeyStatementCorrespondenceVerificationPoll::WorkCompleted {
                completed_work_unit_count,
                checkpoint_safe_boundary_ordinal: self
                    .completed_work_unit_count
                    .checked_sub(1)
                    .ok_or(RefusalReason::ConsumedState)?,
            },
        )
    }

    fn verify_next_verifier_sequence_column(&mut self) -> Result<bool, RefusalReason> {
        while self.next_verifier_column_index < self.public_input_offset_by_column.len() {
            let column_index = self.next_verifier_column_index;
            self.next_verifier_column_index = self
                .next_verifier_column_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let Some(first_element) = self.public_input_offset_by_column[column_index] else {
                continue;
            };
            let statement_authority = self
                .statement_authority
                .as_ref()
                .ok_or(RefusalReason::ConsumedState)?;
            let relation_variant = statement_authority
                .statement_source
                .selected_relation_variant()
                .map_err(|_| RefusalReason::WrongContext)?;
            let descriptor = relation_variant
                .ordered_columns()
                .get(column_index)
                .ok_or(RefusalReason::InvalidArithmeticRelation)?;
            match descriptor.origin() {
                RelationColumnOrigin::VerifierSequence { .. } => {
                    if descriptor.value_type() != RelationColumnValueType::BaseField {
                        return Err(RefusalReason::InvalidArithmeticRelation);
                    }
                    let expected_rows = statement_authority
                        .verified_column_evaluator
                        .verifier_owned_trace_rows(
                            u32::try_from(column_index)
                                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                        )?;
                    let transport = self
                        .transport
                        .as_ref()
                        .ok_or(RefusalReason::ConsumedState)?;
                    let public_input_view = transport.public_input_view();
                    compare_public_input_trace_row(
                        public_input_view.canonical_bytes(),
                        public_input_view.decoded(),
                        first_element,
                        &expected_rows,
                    )?;
                    self.consumed_public_columns[column_index] = true;
                    self.verifier_sequence_column_count = self
                        .verifier_sequence_column_count
                        .checked_add(1)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    return Ok(true);
                }
                RelationColumnOrigin::BoundTree { .. } => {}
                RelationColumnOrigin::Prover => {
                    return Err(RefusalReason::InvalidArithmeticRelation);
                }
            }
        }
        Ok(false)
    }

    fn prepare_next_statement_tree_correspondence(&mut self) -> Result<bool, RefusalReason> {
        loop {
            let statement_authority = self
                .statement_authority
                .as_ref()
                .ok_or(RefusalReason::ConsumedState)?;
            let relation_variant = statement_authority
                .statement_source
                .selected_relation_variant()
                .map_err(|_| RefusalReason::WrongContext)?;
            let Some(descriptor) = relation_variant
                .ordered_trees()
                .get(self.next_tree_descriptor_index)
            else {
                return Ok(false);
            };
            let ordered_tree_ordinal = self.next_tree_descriptor_index;
            self.next_tree_descriptor_index = self
                .next_tree_descriptor_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } = descriptor
            else {
                continue;
            };
            let expected_root_source_ordinal = *expected_root_source_ordinal;
            let ordered_column_ordinals = ordered_column_ordinals.clone();
            let statement_tree = statement_authority
                .statement_trees
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
            if statement_tree.expected_root_source_ordinal() != expected_root_source_ordinal
                || statement_tree.setup_public_polynomial_row_width() != Some(expected_row_width)
                || statement_tree.ordered_canonical_residue_moduli().len()
                    != ordered_column_ordinals.len()
            {
                return Err(RefusalReason::WrongContext);
            }
            let root_builder = SetupPublicPolynomialRootBuilder::from_verifier_owned_context_hash(
                public_polynomial_context_hash,
                self.evaluation_domain_size,
                self.trace_domain_size,
                expected_row_width,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            self.active_statement_tree = Some(ActiveStatementTreeCorrespondence {
                expected_root: statement_tree.expected_root(),
                public_polynomial_context_hash,
                expected_root_source_ordinal,
                ordered_column_ordinals,
                next_column_index: 0,
                root_builder: Some(root_builder),
                root_construction: None,
            });
            return Ok(true);
        }
    }

    fn absorb_statement_tree_column(&mut self, column_ordinal: u32) -> Result<(), RefusalReason> {
        let column_index =
            usize::try_from(column_ordinal).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let first_element = self
            .public_input_offset_by_column
            .get(column_index)
            .copied()
            .flatten()
            .ok_or(RefusalReason::InvalidArithmeticRelation)?;
        let expected_root_source_ordinal = self
            .active_statement_tree
            .as_ref()
            .ok_or(RefusalReason::ConsumedState)?
            .expected_root_source_ordinal;
        let statement_authority = self
            .statement_authority
            .as_ref()
            .ok_or(RefusalReason::ConsumedState)?;
        let relation_variant = statement_authority
            .statement_source
            .selected_relation_variant()
            .map_err(|_| RefusalReason::WrongContext)?;
        let descriptor = relation_variant
            .ordered_columns()
            .get(column_index)
            .ok_or(RefusalReason::InvalidArithmeticRelation)?;
        if self.consumed_public_columns[column_index]
            || !matches!(
                descriptor.origin(),
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: column_root_source_ordinal,
                } if *column_root_source_ordinal == expected_root_source_ordinal
            )
            || descriptor.value_type() != RelationColumnValueType::BaseField
        {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        let transport = self
            .transport
            .as_ref()
            .ok_or(RefusalReason::ConsumedState)?;
        let public_input_view = transport.public_input_view();
        let trace_row = decode_public_input_trace_row(
            public_input_view.canonical_bytes(),
            public_input_view.decoded(),
            first_element,
            self.trace_domain_size,
        )?;
        let active_statement_tree = self
            .active_statement_tree
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?;
        active_statement_tree
            .root_builder
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .absorb_trace_row(&trace_row)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        active_statement_tree.next_column_index = active_statement_tree
            .next_column_index
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.consumed_public_columns[column_index] = true;
        Ok(())
    }

    fn finish_correspondence(&mut self) -> Result<(), RefusalReason> {
        let statement_authority = self
            .statement_authority
            .as_ref()
            .ok_or(RefusalReason::ConsumedState)?;
        let verified_column_count = self
            .consumed_public_columns
            .iter()
            .filter(|consumed| **consumed)
            .count();
        if self
            .consumed_public_columns
            .iter()
            .zip(&self.public_input_offset_by_column)
            .any(|(consumed, offset)| *consumed != offset.is_some())
            || verified_column_count
                != statement_authority
                    .relation
                    .ordered_public_vectors()
                    .len()
                    .checked_mul(2)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?
            || usize::try_from(self.statement_tree_count).ok()
                != Some(statement_authority.statement_trees.len())
        {
            return Err(RefusalReason::InvalidArithmeticRelation);
        }
        let correspondence = CompactPublicKeyStatementCorrespondence {
            public_ring_vector_count: statement_authority
                .relation
                .public_input_ring_vector_count(),
            verified_column_count: u32::try_from(verified_column_count)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            verifier_sequence_column_count: self.verifier_sequence_column_count,
            statement_tree_count: self.statement_tree_count,
        }
        .require_complete(
            statement_authority
                .relation
                .public_input_ring_vector_count(),
            statement_authority
                .relation
                .ordered_public_vectors()
                .len()
                .checked_mul(2)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
            statement_authority.statement_trees.len(),
        )?;
        let statement_authority = self
            .statement_authority
            .take()
            .ok_or(RefusalReason::ConsumedState)?;
        let transport = self.transport.take().ok_or(RefusalReason::ConsumedState)?;
        #[cfg(not(test))]
        let _ = correspondence;
        self.complete_proof = Some(Box::new(SourceVerifiedCompactPublicKeyProof {
            _statement_source: statement_authority.statement_source,
            _transport: transport,
            #[cfg(test)]
            correspondence,
            terminal_source: statement_authority.terminal_source,
        }));
        Ok(())
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
