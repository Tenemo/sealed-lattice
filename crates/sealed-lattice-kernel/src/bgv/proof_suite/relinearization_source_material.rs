use crate::{
    bgv::evaluator::candidate_evidence::EvaluatorCandidateInput,
    foundation::{
        CanonicalStreamDomain, FOUNDATION_PROFILE, Hash512, ProofApplicationSlot,
        ProofApplicationSlotCeilings, StreamDescriptor,
    },
};

use super::{
    BorrowedVerifiedCommonProofCapability, BoundTreeConstructionKind, CommonProofVerifierError,
    ComponentMaterialOwnershipBinding, ConsumedVerifiedCommonProofCapability,
    RelationTreeDescriptor, SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, SetupPublicPolynomialContext, SetupPublicPolynomialRootRole,
    VerifiedKeySwitchComponentMaterial, VerifiedStatementOwnedTree,
    VerifiedStreamedProofTreeTerminal,
    application_statement::{
        decode_selected_relinearization_round_one_aggregate_statement,
        decode_selected_relinearization_round_one_statement,
        decode_selected_relinearization_round_two_statement,
    },
    evaluator_source_material::{
        expected_component_column_moduli, material_topology_matches_selected_catalog_level,
    },
    profile::{EvaluatorKeyShareSourceKind, FirstProfileRootTopology},
    relation_plan::BoundTreeRootUse,
    selected_evaluator_entry_positions,
    selected_profile::selected_relation_plans,
    verified_application_statement_hash,
};

const ROUND_TWO_ORDERED_TREE_ORDINAL: u32 = 4;
const ROUND_TWO_ROOT_SOURCE_ORDINAL: u32 = 4;

#[derive(Clone, Copy)]
struct VerifiedRelinearizationProofBinding {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    board_object_hash: [u8; Hash512::BYTE_LENGTH],
    verification_binding_hash: [u8; Hash512::BYTE_LENGTH],
    proof_application_slot_hash: [u8; Hash512::BYTE_LENGTH],
    canonical_proof_application_binding_hash: [u8; Hash512::BYTE_LENGTH],
    application_statement_hash: [u8; Hash512::BYTE_LENGTH],
    proof_header_hash: [u8; Hash512::BYTE_LENGTH],
    proof_stream_full_object_digest: [u8; Hash512::BYTE_LENGTH],
    proof_byte_length: u64,
    verified_query_count: u32,
    relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    relation_plan_variant_hash: [u8; Hash512::BYTE_LENGTH],
}

/// Verifier-owned source pair for one participant's selected relinearization
/// round-one application. Both roots come from recomputed output trees and
/// both component carriers remain descriptor-authenticated until the aggregate
/// proof consumes this authority.
pub(crate) struct VerifiedRelinearizationRoundOneSourceMaterial {
    proof_binding: VerifiedRelinearizationProofBinding,
    proof_stream_descriptor: StreamDescriptor,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    left_tree: VerifiedStatementOwnedTree,
    right_tree: VerifiedStatementOwnedTree,
    left_material: VerifiedKeySwitchComponentMaterial,
    right_material: VerifiedKeySwitchComponentMaterial,
}

pub(crate) struct VerifiedRelinearizationRoundOneSourceMaterialPreflight {
    proof_binding: VerifiedRelinearizationProofBinding,
    proof_stream_descriptor: StreamDescriptor,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
}

impl VerifiedRelinearizationRoundOneSourceMaterialPreflight {
    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) fn complete(
        self,
        _verified_proof: ConsumedVerifiedCommonProofCapability,
        component_trees: [VerifiedStreamedProofTreeTerminal; 2],
        component_materials: [VerifiedKeySwitchComponentMaterial; 2],
    ) -> VerifiedRelinearizationRoundOneSourceMaterial {
        let [left_tree, right_tree] = component_trees;
        let left_tree = left_tree.statement_owned_tree();
        let right_tree = right_tree.statement_owned_tree();
        let [left_material, right_material] = component_materials;
        VerifiedRelinearizationRoundOneSourceMaterial {
            proof_binding: self.proof_binding,
            proof_stream_descriptor: self.proof_stream_descriptor,
            setup_proof_context_hash: self.setup_proof_context_hash,
            participant_identity: self.participant_identity,
            roster_position: self.roster_position,
            schedule_position: self.schedule_position,
            anchor_commitment_roots: self.anchor_commitment_roots,
            left_tree,
            right_tree,
            left_material,
            right_material,
        }
    }
}

impl VerifiedRelinearizationRoundOneSourceMaterial {
    pub(crate) fn from_consumed_common_proof(
        verified_proof: ConsumedVerifiedCommonProofCapability,
        canonical_application_statement_bytes: &[u8],
        component_trees: [VerifiedStreamedProofTreeTerminal; 2],
        component_materials: [VerifiedKeySwitchComponentMaterial; 2],
    ) -> Result<Self, CommonProofVerifierError> {
        let preflight = Self::preflight_from_borrowed_common_proof(
            verified_proof.borrowed(),
            canonical_application_statement_bytes,
            &component_trees,
            &component_materials,
        )?;
        Ok(preflight.complete(verified_proof, component_trees, component_materials))
    }

    pub(crate) fn preflight_from_borrowed_common_proof(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        component_trees: &[VerifiedStreamedProofTreeTerminal; 2],
        component_materials: &[VerifiedKeySwitchComponentMaterial; 2],
    ) -> Result<VerifiedRelinearizationRoundOneSourceMaterialPreflight, CommonProofVerifierError>
    {
        let schedule_position = verified_proof
            .schedule_position()
            .filter(|_| {
                verified_proof.protocol_version() == FOUNDATION_PROFILE.protocol_version
                    && verified_proof.application_statement_schema_identifier()
                        == ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
                    && verified_proof.proof_stream_domain()
                        == CanonicalStreamDomain::RkgRoundOneProof
                    && verified_proof.top_count().is_none()
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        if verified_proof.application_statement_hash()
            != verified_application_statement_hash(
                verified_proof.protocol_version(),
                verified_proof.suite_identifier(),
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                canonical_application_statement_bytes,
            )
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement = decode_selected_relinearization_round_one_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version(),
                verified_proof.suite_identifier(),
                Some(schedule_position),
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let reconstructed_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(verified_proof.suite_identifier()),
            Hash512::from_bytes(verified_proof.ceremony_context_hash()),
            Hash512::from_bytes(verified_proof.action_context_hash()),
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(statement.roster_position()),
            Some(schedule_position),
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if reconstructed_application_slot.into_bytes()
            != verified_proof.proof_application_slot_hash()
            || statement.schedule_position() != schedule_position
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let selected_plan_artifact = selected_relation_plans()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            .into_iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier()
                    == ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let selected_plan = selected_plan_artifact.compiled_plan();
        let selected_variant = selected_plan
            .select_variant(Some(schedule_position), None)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if selected_plan
            .canonical_hash()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            != verified_proof.relation_plan_hash()
            || selected_variant
                .canonical_hash()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                != verified_proof.relation_plan_variant_hash()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let evaluator_position = selected_relinearization_source_position(schedule_position)?;
        let catalog_level = match evaluator_position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { catalog_level } => catalog_level,
            SelectedEvaluatorEntryKind::Galois { .. } => {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
        };
        let selected_candidate = EvaluatorCandidateInput::implemented()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let material_ownership = ComponentMaterialOwnershipBinding::from_verified_application(
            verified_proof.suite_identifier(),
            verified_proof.action_context_hash(),
            verified_proof.application_statement_hash(),
        );
        let expected_roots = [
            statement.round_one_left_root(),
            statement.round_one_right_root(),
        ];
        let expected_roles = [
            SetupPublicPolynomialRootRole::RelinearizationRoundOneLeft,
            SetupPublicPolynomialRootRole::RelinearizationRoundOneRight,
        ];
        for (component_ordinal, ((tree, material), (expected_root, expected_role))) in
            component_trees
                .iter()
                .zip(component_materials)
                .zip(expected_roots.into_iter().zip(expected_roles))
                .enumerate()
        {
            let tree_ordinal = u32::try_from(component_ordinal)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let expected_tree = selected_variant
                .ordered_trees()
                .get(component_ordinal)
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            let (expected_root_source_ordinal, expected_column_count) = match expected_tree {
                RelationTreeDescriptor::BoundPublic {
                    construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                    expected_root_source_ordinal,
                    root_use: BoundTreeRootUse::Output,
                    ordered_column_ordinals,
                } => (*expected_root_source_ordinal, ordered_column_ordinals.len()),
                _ => return Err(CommonProofVerifierError::InvalidApplicationStatement),
            };
            let expected_public_polynomial_context_hash = SetupPublicPolynomialContext::new(
                statement.setup_proof_context_hash(),
                expected_role,
                Some(statement.participant_identity()),
                Some(statement.roster_position()),
                Some(schedule_position),
                None,
            )
            .and_then(|context| context.context_hash())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let expected_column_moduli =
                expected_component_column_moduli(&selected_candidate, material)?;
            if tree.protocol_version() != verified_proof.protocol_version()
                || tree.suite_identifier() != verified_proof.suite_identifier()
                || tree.ceremony_context_hash() != verified_proof.ceremony_context_hash()
                || tree.action_context_hash() != verified_proof.action_context_hash()
                || tree.application_statement_schema_identifier()
                    != ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
                || tree.application_statement_hash() != verified_proof.application_statement_hash()
                || tree.relation_plan_variant_hash()
                    != verified_proof.relation_plan_variant_hash()
                || tree.canonical_application_statement_bytes()
                    != canonical_application_statement_bytes
                || tree.ordered_tree_ordinal() != tree_ordinal
                || tree.expected_root_source_ordinal() != expected_root_source_ordinal
                || tree.setup_proof_context_hash() != statement.setup_proof_context_hash()
                || tree.root_role() != expected_role
                || tree.owner_participant_identity() != Some(statement.participant_identity())
                || tree.owner_roster_position() != Some(statement.roster_position())
                || tree.schedule_position() != Some(schedule_position)
                || tree.public_polynomial_context_hash()
                    != expected_public_polynomial_context_hash
                || tree.root() != expected_root
                || tree.source_polynomial_degree_bound_exclusive()
                    != material.topology().polynomial_degree()
                || usize::try_from(tree.row_width()).ok() != Some(expected_column_count)
                || tree.ordered_canonical_residue_moduli() != expected_column_moduli.as_ref()
                || tree.source_stream_domain() != Some(CanonicalStreamDomain::EvaluatorKeyStore)
                || tree.source_material_root() != Some(material.material_root().into_bytes())
                || tree.source_stream_descriptor() != Some(material.stream_descriptor())
                || !material.binds_ownership(material_ownership)
                || !material_topology_matches_selected_catalog_level(
                    &selected_candidate,
                    catalog_level,
                    material,
                )
            {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
        }
        if component_trees[0].roster_hash() != component_trees[1].roster_hash() {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let proof_binding = VerifiedRelinearizationProofBinding {
            protocol_version: verified_proof.protocol_version(),
            suite_identifier: verified_proof.suite_identifier(),
            ceremony_context_hash: verified_proof.ceremony_context_hash(),
            action_context_hash: verified_proof.action_context_hash(),
            roster_hash: component_trees[0].roster_hash(),
            board_object_hash: verified_proof.board_object_hash(),
            verification_binding_hash: verified_proof.verification_binding_hash(),
            proof_application_slot_hash: verified_proof.proof_application_slot_hash(),
            canonical_proof_application_binding_hash: verified_proof
                .canonical_proof_application_binding_hash(),
            application_statement_hash: verified_proof.application_statement_hash(),
            proof_header_hash: verified_proof.proof_header_hash(),
            proof_stream_full_object_digest: verified_proof.proof_stream_full_object_digest(),
            proof_byte_length: verified_proof.proof_byte_length(),
            verified_query_count: verified_proof.verified_query_count(),
            relation_plan_hash: verified_proof.relation_plan_hash(),
            relation_plan_variant_hash: verified_proof.relation_plan_variant_hash(),
        };
        Ok(VerifiedRelinearizationRoundOneSourceMaterialPreflight {
            proof_binding,
            proof_stream_descriptor: verified_proof.proof_stream_descriptor().clone(),
            setup_proof_context_hash: statement.setup_proof_context_hash(),
            participant_identity: statement.participant_identity(),
            roster_position: statement.roster_position(),
            schedule_position,
            anchor_commitment_roots: statement.anchor_commitment_roots(),
        })
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.proof_binding.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) fn root_pair(&self) -> [[u8; Hash512::BYTE_LENGTH]; 2] {
        [
            self.left_tree.expected_root(),
            self.right_tree.expected_root(),
        ]
    }

    pub(crate) fn rebound_statement_owned_trees(
        &self,
        left_tree_ordinal: u32,
        left_root_source_ordinal: u32,
        right_tree_ordinal: u32,
        right_root_source_ordinal: u32,
    ) -> [VerifiedStatementOwnedTree; 2] {
        [
            self.left_tree
                .with_relation_coordinates(left_tree_ordinal, left_root_source_ordinal),
            self.right_tree
                .with_relation_coordinates(right_tree_ordinal, right_root_source_ordinal),
        ]
    }

    pub(crate) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(crate) const fn component_materials(&self) -> [&VerifiedKeySwitchComponentMaterial; 2] {
        [&self.left_material, &self.right_material]
    }
}

/// Verifier-owned authority for one selected relinearization round-two source.
/// The round-two root comes only from the recomputed proof tree terminal; the
/// component capability separately authenticates replay of the exact compact
/// bytes under the same application binding.
pub(crate) struct VerifiedRelinearizationSourceMaterial {
    proof_binding: VerifiedRelinearizationProofBinding,
    proof_stream_descriptor: StreamDescriptor,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    evaluator_position: SelectedEvaluatorEntryPosition,
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    round_one_right_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_round_one_right_root: [u8; Hash512::BYTE_LENGTH],
    contribution_root: [u8; Hash512::BYTE_LENGTH],
    material: VerifiedKeySwitchComponentMaterial,
}

pub(crate) struct VerifiedRelinearizationSourceMaterialPreflight {
    proof_binding: VerifiedRelinearizationProofBinding,
    proof_stream_descriptor: StreamDescriptor,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    evaluator_position: SelectedEvaluatorEntryPosition,
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    round_one_right_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_round_one_right_root: [u8; Hash512::BYTE_LENGTH],
    contribution_root: [u8; Hash512::BYTE_LENGTH],
}

impl VerifiedRelinearizationSourceMaterialPreflight {
    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) fn complete(
        self,
        _verified_proof: ConsumedVerifiedCommonProofCapability,
        _contribution_tree: VerifiedStreamedProofTreeTerminal,
        material: VerifiedKeySwitchComponentMaterial,
    ) -> VerifiedRelinearizationSourceMaterial {
        VerifiedRelinearizationSourceMaterial {
            proof_binding: self.proof_binding,
            proof_stream_descriptor: self.proof_stream_descriptor,
            setup_proof_context_hash: self.setup_proof_context_hash,
            participant_identity: self.participant_identity,
            roster_position: self.roster_position,
            schedule_position: self.schedule_position,
            evaluator_position: self.evaluator_position,
            public_polynomial_context_hash: self.public_polynomial_context_hash,
            anchor_commitment_roots: self.anchor_commitment_roots,
            round_one_left_root: self.round_one_left_root,
            round_one_right_root: self.round_one_right_root,
            aggregate_round_one_left_root: self.aggregate_round_one_left_root,
            aggregate_round_one_right_root: self.aggregate_round_one_right_root,
            contribution_root: self.contribution_root,
            material,
        }
    }
}

impl VerifiedRelinearizationSourceMaterial {
    pub(crate) fn from_consumed_common_proof(
        verified_proof: ConsumedVerifiedCommonProofCapability,
        canonical_application_statement_bytes: &[u8],
        contribution_tree: VerifiedStreamedProofTreeTerminal,
        material: VerifiedKeySwitchComponentMaterial,
    ) -> Result<Self, CommonProofVerifierError> {
        let preflight = Self::preflight_from_borrowed_common_proof(
            verified_proof.borrowed(),
            canonical_application_statement_bytes,
            &contribution_tree,
            &material,
        )?;
        Ok(preflight.complete(verified_proof, contribution_tree, material))
    }

    pub(crate) fn preflight_from_borrowed_common_proof(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        contribution_tree: &VerifiedStreamedProofTreeTerminal,
        material: &VerifiedKeySwitchComponentMaterial,
    ) -> Result<VerifiedRelinearizationSourceMaterialPreflight, CommonProofVerifierError> {
        let proof_binding = VerifiedRelinearizationProofBinding {
            protocol_version: verified_proof.protocol_version(),
            suite_identifier: verified_proof.suite_identifier(),
            ceremony_context_hash: verified_proof.ceremony_context_hash(),
            action_context_hash: verified_proof.action_context_hash(),
            roster_hash: contribution_tree.roster_hash(),
            board_object_hash: verified_proof.board_object_hash(),
            verification_binding_hash: verified_proof.verification_binding_hash(),
            proof_application_slot_hash: verified_proof.proof_application_slot_hash(),
            canonical_proof_application_binding_hash: verified_proof
                .canonical_proof_application_binding_hash(),
            application_statement_hash: verified_proof.application_statement_hash(),
            proof_header_hash: verified_proof.proof_header_hash(),
            proof_stream_full_object_digest: verified_proof.proof_stream_full_object_digest(),
            proof_byte_length: verified_proof.proof_byte_length(),
            verified_query_count: verified_proof.verified_query_count(),
            relation_plan_hash: verified_proof.relation_plan_hash(),
            relation_plan_variant_hash: verified_proof.relation_plan_variant_hash(),
        };
        let schedule_position = verified_proof
            .schedule_position()
            .filter(|_| {
                verified_proof.protocol_version() == FOUNDATION_PROFILE.protocol_version
                    && verified_proof.application_statement_schema_identifier()
                    == ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
                    && verified_proof.proof_stream_domain()
                        == CanonicalStreamDomain::RkgRoundTwoProof
                    && verified_proof.top_count().is_none()
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        if proof_binding.application_statement_hash
            != verified_application_statement_hash(
                proof_binding.protocol_version,
                proof_binding.suite_identifier,
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                canonical_application_statement_bytes,
            )
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement = decode_selected_relinearization_round_two_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                proof_binding.protocol_version,
                proof_binding.suite_identifier,
                Some(schedule_position),
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let reconstructed_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(proof_binding.suite_identifier),
            Hash512::from_bytes(proof_binding.ceremony_context_hash),
            Hash512::from_bytes(proof_binding.action_context_hash),
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
            Some(statement.roster_position()),
            Some(statement.schedule_position()),
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if reconstructed_application_slot.into_bytes() != proof_binding.proof_application_slot_hash
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let evaluator_position = selected_relinearization_source_position(schedule_position)?;
        let catalog_level = match evaluator_position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { catalog_level } => catalog_level,
            SelectedEvaluatorEntryKind::Galois { .. } => {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
        };
        let expected_public_polynomial_context = SetupPublicPolynomialContext::new(
            statement.setup_proof_context_hash(),
            SetupPublicPolynomialRootRole::RelinearizationRoundTwo,
            Some(statement.participant_identity()),
            Some(statement.roster_position()),
            Some(schedule_position),
            None,
        )
        .and_then(|context| context.context_hash())
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let selected_candidate = EvaluatorCandidateInput::implemented()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let expected_column_moduli =
            expected_component_column_moduli(&selected_candidate, material)?;
        let material_ownership = ComponentMaterialOwnershipBinding::from_verified_application(
            proof_binding.suite_identifier,
            proof_binding.action_context_hash,
            proof_binding.application_statement_hash,
        );
        if contribution_tree.protocol_version() != proof_binding.protocol_version
            || contribution_tree.suite_identifier() != proof_binding.suite_identifier
            || contribution_tree.ceremony_context_hash() != proof_binding.ceremony_context_hash
            || contribution_tree.action_context_hash() != proof_binding.action_context_hash
            || contribution_tree.roster_hash() != proof_binding.roster_hash
            || contribution_tree.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
            || contribution_tree.application_statement_hash()
                != proof_binding.application_statement_hash
            || contribution_tree.relation_plan_variant_hash()
                != proof_binding.relation_plan_variant_hash
            || contribution_tree.canonical_application_statement_bytes()
                != canonical_application_statement_bytes
            || contribution_tree.setup_proof_context_hash()
                != statement.setup_proof_context_hash()
            || contribution_tree.owner_participant_identity()
                != Some(statement.participant_identity())
            || contribution_tree.owner_roster_position() != Some(statement.roster_position())
            || contribution_tree.schedule_position() != Some(schedule_position)
            || contribution_tree.ordered_tree_ordinal() != ROUND_TWO_ORDERED_TREE_ORDINAL
            || contribution_tree.expected_root_source_ordinal()
                != ROUND_TWO_ROOT_SOURCE_ORDINAL
            || contribution_tree.root_role()
                != SetupPublicPolynomialRootRole::RelinearizationRoundTwo
            || contribution_tree.public_polynomial_context_hash()
                != expected_public_polynomial_context
            || contribution_tree.root() != statement.contribution_root()
            || contribution_tree.source_polynomial_degree_bound_exclusive()
                != material.topology().polynomial_degree()
            || contribution_tree.ordered_canonical_residue_moduli()
                != expected_column_moduli.as_ref()
            || material
                .topology()
                .trace_column_count()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                != contribution_tree.ordered_canonical_residue_moduli().len()
            || usize::try_from(contribution_tree.row_width()).ok()
                != Some(contribution_tree.ordered_canonical_residue_moduli().len())
            || contribution_tree.source_stream_domain()
                != Some(CanonicalStreamDomain::EvaluatorKeyStore)
            || contribution_tree.source_material_root()
                != Some(material.material_root().into_bytes())
            || contribution_tree.source_stream_descriptor() != Some(material.stream_descriptor())
            || !material.binds_ownership(material_ownership)
            || !material_topology_matches_selected_catalog_level(
                &selected_candidate,
                catalog_level,
                material,
            )
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        Ok(VerifiedRelinearizationSourceMaterialPreflight {
            proof_binding,
            proof_stream_descriptor: verified_proof.proof_stream_descriptor().clone(),
            setup_proof_context_hash: statement.setup_proof_context_hash(),
            participant_identity: statement.participant_identity(),
            roster_position: statement.roster_position(),
            schedule_position,
            evaluator_position,
            public_polynomial_context_hash: contribution_tree.public_polynomial_context_hash(),
            anchor_commitment_roots: statement.anchor_commitment_roots(),
            round_one_left_root: statement.round_one_left_root(),
            round_one_right_root: statement.round_one_right_root(),
            aggregate_round_one_left_root: statement.aggregate_round_one_left_root(),
            aggregate_round_one_right_root: statement.aggregate_round_one_right_root(),
            contribution_root: statement.contribution_root(),
        })
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn evaluator_position(&self) -> SelectedEvaluatorEntryPosition {
        self.evaluator_position
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_polynomial_context_hash
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) const fn round_one_left_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.round_one_left_root
    }

    pub(crate) const fn round_one_right_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.round_one_right_root
    }

    pub(crate) const fn aggregate_round_one_left_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_round_one_left_root
    }

    pub(crate) const fn aggregate_round_one_right_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_round_one_right_root
    }

    pub(crate) const fn contribution_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.contribution_root
    }

    pub(crate) const fn material(&self) -> &VerifiedKeySwitchComponentMaterial {
        &self.material
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.application_statement_hash
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.proof_binding.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.roster_hash
    }

    pub(crate) const fn proof_header_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.proof_header_hash
    }
}

/// Frozen verifier authority for the selected round-one aggregate. The
/// authority positively joins every participant's recomputed round-one source
/// pair to both recomputed aggregate trees and their authenticated carriers.
pub(crate) struct VerifiedRelinearizationAggregateMaterial {
    proof_binding: VerifiedRelinearizationProofBinding,
    proof_stream_descriptor: StreamDescriptor,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    evaluator_position: SelectedEvaluatorEntryPosition,
    ordered_participant_identities: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_anchor_commitment_roots: Box<[[[u8; Hash512::BYTE_LENGTH]; 3]]>,
    ordered_round_one_proof_stream_descriptors: Box<[StreamDescriptor]>,
    ordered_source_root_pairs: Box<[[[u8; Hash512::BYTE_LENGTH]; 2]]>,
    ordered_round_one_sources: Box<[VerifiedRelinearizationRoundOneSourceMaterial]>,
    aggregate_left_tree: VerifiedStatementOwnedTree,
    aggregate_left_material: VerifiedKeySwitchComponentMaterial,
    aggregate_right_tree: VerifiedStatementOwnedTree,
    aggregate_right_material: VerifiedKeySwitchComponentMaterial,
}

pub(crate) struct VerifiedRelinearizationAggregateMaterialPreflight {
    proof_binding: VerifiedRelinearizationProofBinding,
    proof_stream_descriptor: StreamDescriptor,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    evaluator_position: SelectedEvaluatorEntryPosition,
    ordered_participant_identities: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_anchor_commitment_roots: Box<[[[u8; Hash512::BYTE_LENGTH]; 3]]>,
    ordered_round_one_proof_stream_descriptors: Box<[StreamDescriptor]>,
    ordered_source_root_pairs: Box<[[[u8; Hash512::BYTE_LENGTH]; 2]]>,
}

impl VerifiedRelinearizationAggregateMaterialPreflight {
    pub(crate) fn complete(
        self,
        _verified_proof: ConsumedVerifiedCommonProofCapability,
        ordered_sources: Vec<VerifiedRelinearizationRoundOneSourceMaterial>,
        aggregate_left_tree: VerifiedStreamedProofTreeTerminal,
        aggregate_left_material: VerifiedKeySwitchComponentMaterial,
        aggregate_right_tree: VerifiedStreamedProofTreeTerminal,
        aggregate_right_material: VerifiedKeySwitchComponentMaterial,
    ) -> VerifiedRelinearizationAggregateMaterial {
        let aggregate_left_tree = aggregate_left_tree.statement_owned_tree();
        let aggregate_right_tree = aggregate_right_tree.statement_owned_tree();
        VerifiedRelinearizationAggregateMaterial {
            proof_binding: self.proof_binding,
            proof_stream_descriptor: self.proof_stream_descriptor,
            setup_proof_context_hash: self.setup_proof_context_hash,
            schedule_position: self.schedule_position,
            evaluator_position: self.evaluator_position,
            ordered_participant_identities: self.ordered_participant_identities,
            ordered_anchor_commitment_roots: self.ordered_anchor_commitment_roots,
            ordered_round_one_proof_stream_descriptors: self
                .ordered_round_one_proof_stream_descriptors,
            ordered_source_root_pairs: self.ordered_source_root_pairs,
            ordered_round_one_sources: ordered_sources.into_boxed_slice(),
            aggregate_left_tree,
            aggregate_left_material,
            aggregate_right_tree,
            aggregate_right_material,
        }
    }
}

impl VerifiedRelinearizationAggregateMaterial {
    pub(crate) fn from_consumed_common_proof(
        verified_proof: ConsumedVerifiedCommonProofCapability,
        canonical_application_statement_bytes: &[u8],
        ordered_sources: Vec<VerifiedRelinearizationRoundOneSourceMaterial>,
        aggregate_left_tree: VerifiedStreamedProofTreeTerminal,
        aggregate_left_material: VerifiedKeySwitchComponentMaterial,
        aggregate_right_tree: VerifiedStreamedProofTreeTerminal,
        aggregate_right_material: VerifiedKeySwitchComponentMaterial,
    ) -> Result<Self, CommonProofVerifierError> {
        let preflight = Self::preflight_from_borrowed_common_proof(
            verified_proof.borrowed(),
            canonical_application_statement_bytes,
            &ordered_sources,
            &aggregate_left_tree,
            &aggregate_left_material,
            &aggregate_right_tree,
            &aggregate_right_material,
        )?;
        Ok(preflight.complete(
            verified_proof,
            ordered_sources,
            aggregate_left_tree,
            aggregate_left_material,
            aggregate_right_tree,
            aggregate_right_material,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight_from_borrowed_common_proof(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        ordered_sources: &[VerifiedRelinearizationRoundOneSourceMaterial],
        aggregate_left_tree: &VerifiedStreamedProofTreeTerminal,
        aggregate_left_material: &VerifiedKeySwitchComponentMaterial,
        aggregate_right_tree: &VerifiedStreamedProofTreeTerminal,
        aggregate_right_material: &VerifiedKeySwitchComponentMaterial,
    ) -> Result<VerifiedRelinearizationAggregateMaterialPreflight, CommonProofVerifierError> {
        let schedule_position = verified_proof
            .schedule_position()
            .filter(|_| {
                verified_proof.protocol_version() == FOUNDATION_PROFILE.protocol_version
                    && verified_proof.application_statement_schema_identifier()
                        == ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                    && verified_proof.proof_stream_domain()
                        == CanonicalStreamDomain::RkgRoundOneAggregateProof
                    && verified_proof.top_count().is_none()
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        if verified_proof.application_statement_hash()
            != verified_application_statement_hash(
                verified_proof.protocol_version(),
                verified_proof.suite_identifier(),
                ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                canonical_application_statement_bytes,
            )
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement = decode_selected_relinearization_round_one_aggregate_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version(),
                verified_proof.suite_identifier(),
                Some(schedule_position),
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let setup_proof_context_hash = statement.setup_proof_context_hash();
        if ordered_sources.len() != usize::from(FOUNDATION_PROFILE.participant_count) {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let mut ordered_participant_identities = Vec::new();
        ordered_participant_identities
            .try_reserve_exact(ordered_sources.len())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let mut ordered_anchor_commitment_roots = Vec::new();
        ordered_anchor_commitment_roots
            .try_reserve_exact(ordered_sources.len())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let mut ordered_round_one_proof_stream_descriptors = Vec::new();
        ordered_round_one_proof_stream_descriptors
            .try_reserve_exact(ordered_sources.len())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        for (roster_ordinal, (source, expected_root_pair)) in ordered_sources
            .iter()
            .zip(statement.ordered_source_root_pairs())
            .enumerate()
        {
            let roster_position = u16::try_from(roster_ordinal)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            if source.protocol_version() != verified_proof.protocol_version()
                || source.suite_identifier() != verified_proof.suite_identifier()
                || source.ceremony_context_hash() != verified_proof.ceremony_context_hash()
                || source.action_context_hash() != verified_proof.action_context_hash()
                || source.roster_hash() != aggregate_left_tree.roster_hash()
                || source.setup_proof_context_hash() != setup_proof_context_hash
                || source.roster_position() != roster_position
                || source.schedule_position() != schedule_position
                || source.root_pair() != *expected_root_pair
                || ordered_participant_identities.contains(&source.participant_identity())
            {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
            ordered_participant_identities.push(source.participant_identity());
            ordered_anchor_commitment_roots.push(source.anchor_commitment_roots());
            ordered_round_one_proof_stream_descriptors
                .push(source.proof_stream_descriptor().clone());
        }
        if aggregate_left_tree.roster_hash() != aggregate_right_tree.roster_hash() {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let reconstructed_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(verified_proof.suite_identifier()),
            Hash512::from_bytes(verified_proof.ceremony_context_hash()),
            Hash512::from_bytes(verified_proof.action_context_hash()),
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
            Some(schedule_position),
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if reconstructed_application_slot.into_bytes()
            != verified_proof.proof_application_slot_hash()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let selected_plan_artifact = selected_relation_plans()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            .into_iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier()
                    == ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let selected_plan = selected_plan_artifact.compiled_plan();
        let selected_variant = selected_plan
            .select_variant(Some(schedule_position), None)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if selected_plan
            .canonical_hash()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            != verified_proof.relation_plan_hash()
            || selected_variant
                .canonical_hash()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                != verified_proof.relation_plan_variant_hash()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let participant_tree_count = u32::from(FOUNDATION_PROFILE.participant_count);
        let aggregate_left_tree_ordinal = participant_tree_count;
        let aggregate_right_tree_ordinal = participant_tree_count
            .checked_add(1)
            .and_then(|trees_per_component| trees_per_component.checked_mul(2))
            .and_then(|tree_count| tree_count.checked_sub(1))
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let evaluator_position = selected_relinearization_source_position(schedule_position)?;
        let catalog_level = match evaluator_position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { catalog_level } => catalog_level,
            SelectedEvaluatorEntryKind::Galois { .. } => {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
        };
        let selected_candidate = EvaluatorCandidateInput::implemented()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let material_ownership = ComponentMaterialOwnershipBinding::from_verified_application(
            verified_proof.suite_identifier(),
            verified_proof.action_context_hash(),
            verified_proof.application_statement_hash(),
        );
        for (tree, material, tree_ordinal, expected_root, expected_role) in [
            (
                aggregate_left_tree,
                aggregate_left_material,
                aggregate_left_tree_ordinal,
                statement.aggregate_left_root(),
                SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneLeft,
            ),
            (
                aggregate_right_tree,
                aggregate_right_material,
                aggregate_right_tree_ordinal,
                statement.aggregate_right_root(),
                SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneRight,
            ),
        ] {
            let expected_tree = selected_variant
                .ordered_trees()
                .get(
                    usize::try_from(tree_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?,
                )
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            let (expected_root_source_ordinal, expected_column_count) = match expected_tree {
                RelationTreeDescriptor::BoundPublic {
                    construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                    expected_root_source_ordinal,
                    root_use: BoundTreeRootUse::Output,
                    ordered_column_ordinals,
                } => (*expected_root_source_ordinal, ordered_column_ordinals.len()),
                _ => return Err(CommonProofVerifierError::InvalidApplicationStatement),
            };
            let expected_column_moduli =
                expected_component_column_moduli(&selected_candidate, material)?;
            let expected_public_polynomial_context_hash = SetupPublicPolynomialContext::new(
                setup_proof_context_hash,
                expected_role,
                None,
                None,
                Some(schedule_position),
                None,
            )
            .and_then(|context| context.context_hash())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            if tree.protocol_version() != verified_proof.protocol_version()
                || tree.suite_identifier() != verified_proof.suite_identifier()
                || tree.ceremony_context_hash() != verified_proof.ceremony_context_hash()
                || tree.action_context_hash() != verified_proof.action_context_hash()
                || tree.application_statement_schema_identifier()
                    != ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                || tree.application_statement_hash() != verified_proof.application_statement_hash()
                || tree.relation_plan_variant_hash()
                    != verified_proof.relation_plan_variant_hash()
                || tree.canonical_application_statement_bytes()
                    != canonical_application_statement_bytes
                || tree.ordered_tree_ordinal() != tree_ordinal
                || tree.expected_root_source_ordinal() != expected_root_source_ordinal
                || tree.setup_proof_context_hash() != setup_proof_context_hash
                || tree.root_role() != expected_role
                || tree.owner_participant_identity().is_some()
                || tree.owner_roster_position().is_some()
                || tree.schedule_position() != Some(schedule_position)
                || tree.public_polynomial_context_hash()
                    != expected_public_polynomial_context_hash
                || tree.root() != expected_root
                || tree.source_polynomial_degree_bound_exclusive()
                    != material.topology().polynomial_degree()
                || usize::try_from(tree.row_width()).ok() != Some(expected_column_count)
                || tree.ordered_canonical_residue_moduli() != expected_column_moduli.as_ref()
                || tree.source_stream_domain() != Some(CanonicalStreamDomain::EvaluatorKeyStore)
                || tree.source_material_root() != Some(material.material_root().into_bytes())
                || tree.source_stream_descriptor() != Some(material.stream_descriptor())
                || !material.binds_ownership(material_ownership)
                || !material_topology_matches_selected_catalog_level(
                    &selected_candidate,
                    catalog_level,
                    material,
                )
            {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
        }

        let proof_stream_descriptor = verified_proof.proof_stream_descriptor().clone();
        let proof_binding = VerifiedRelinearizationProofBinding {
            protocol_version: verified_proof.protocol_version(),
            suite_identifier: verified_proof.suite_identifier(),
            ceremony_context_hash: verified_proof.ceremony_context_hash(),
            action_context_hash: verified_proof.action_context_hash(),
            roster_hash: aggregate_right_tree.roster_hash(),
            board_object_hash: verified_proof.board_object_hash(),
            verification_binding_hash: verified_proof.verification_binding_hash(),
            proof_application_slot_hash: verified_proof.proof_application_slot_hash(),
            canonical_proof_application_binding_hash: verified_proof
                .canonical_proof_application_binding_hash(),
            application_statement_hash: verified_proof.application_statement_hash(),
            proof_header_hash: verified_proof.proof_header_hash(),
            proof_stream_full_object_digest: verified_proof.proof_stream_full_object_digest(),
            proof_byte_length: verified_proof.proof_byte_length(),
            verified_query_count: verified_proof.verified_query_count(),
            relation_plan_hash: verified_proof.relation_plan_hash(),
            relation_plan_variant_hash: verified_proof.relation_plan_variant_hash(),
        };
        Ok(VerifiedRelinearizationAggregateMaterialPreflight {
            proof_binding,
            proof_stream_descriptor,
            setup_proof_context_hash,
            schedule_position,
            evaluator_position,
            ordered_participant_identities: ordered_participant_identities.into_boxed_slice(),
            ordered_anchor_commitment_roots: ordered_anchor_commitment_roots.into_boxed_slice(),
            ordered_round_one_proof_stream_descriptors: ordered_round_one_proof_stream_descriptors
                .into_boxed_slice(),
            ordered_source_root_pairs: statement.ordered_source_root_pairs().into(),
        })
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.proof_binding.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn evaluator_position(&self) -> SelectedEvaluatorEntryPosition {
        self.evaluator_position
    }

    pub(crate) fn ordered_source_root_pairs(&self) -> &[[[u8; Hash512::BYTE_LENGTH]; 2]] {
        &self.ordered_source_root_pairs
    }

    pub(crate) fn ordered_participant_identities(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_participant_identities
    }

    pub(crate) fn ordered_anchor_commitment_roots(&self) -> &[[[u8; Hash512::BYTE_LENGTH]; 3]] {
        &self.ordered_anchor_commitment_roots
    }

    pub(crate) fn ordered_round_one_proof_stream_descriptors(&self) -> &[StreamDescriptor] {
        &self.ordered_round_one_proof_stream_descriptors
    }

    pub(crate) fn participant_round_one_statement_trees(
        &self,
        roster_position: u16,
        left_tree_ordinal: u32,
        left_root_source_ordinal: u32,
        right_tree_ordinal: u32,
        right_root_source_ordinal: u32,
    ) -> Option<[VerifiedStatementOwnedTree; 2]> {
        self.ordered_round_one_sources
            .get(usize::from(roster_position))
            .map(|source| {
                source.rebound_statement_owned_trees(
                    left_tree_ordinal,
                    left_root_source_ordinal,
                    right_tree_ordinal,
                    right_root_source_ordinal,
                )
            })
    }

    pub(crate) fn aggregate_left_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_left_tree.expected_root()
    }

    pub(crate) const fn aggregate_left_material(&self) -> &VerifiedKeySwitchComponentMaterial {
        &self.aggregate_left_material
    }

    pub(crate) fn aggregate_right_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_right_tree.expected_root()
    }

    pub(crate) fn rebound_statement_owned_trees(
        &self,
        left_tree_ordinal: u32,
        left_root_source_ordinal: u32,
        right_tree_ordinal: u32,
        right_root_source_ordinal: u32,
    ) -> [VerifiedStatementOwnedTree; 2] {
        [
            self.aggregate_left_tree
                .with_relation_coordinates(left_tree_ordinal, left_root_source_ordinal),
            self.aggregate_right_tree
                .with_relation_coordinates(right_tree_ordinal, right_root_source_ordinal),
        ]
    }

    pub(crate) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(crate) const fn material_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_right_material.material_root().into_bytes()
    }

    pub(crate) const fn stream_descriptor(&self) -> &crate::foundation::StreamDescriptor {
        self.aggregate_right_material.stream_descriptor()
    }

    pub(crate) const fn material(&self) -> &VerifiedKeySwitchComponentMaterial {
        &self.aggregate_right_material
    }

    pub(crate) fn into_material(self) -> VerifiedKeySwitchComponentMaterial {
        self.aggregate_right_material
    }
}

pub(crate) fn selected_relinearization_source_position(
    schedule_position: u32,
) -> Result<SelectedEvaluatorEntryPosition, CommonProofVerifierError> {
    let topology = FirstProfileRootTopology::selected(1)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let entries = topology
        .evaluator_key_entries(FOUNDATION_PROFILE.option_count)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let evaluator_positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if topology.roster_size() != FOUNDATION_PROFILE.participant_count
        || entries.len() != evaluator_positions.len()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let matches = entries
        .iter()
        .copied()
        .zip(evaluator_positions)
        .filter(|(entry, position)| {
            entry.source_kind() == EvaluatorKeyShareSourceKind::Relinearization
                && entry.producer_schedule_position() == schedule_position
                && entry.producer_output_ordinal() == 0
                && position.schedule_position() == schedule_position
                && matches!(
                    position.key_kind(),
                    SelectedEvaluatorEntryKind::Relinearization { .. }
                )
        })
        .map(|(_, position)| position)
        .collect::<Vec<_>>();
    let [position] = matches.as_slice() else {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    };
    Ok(*position)
}
