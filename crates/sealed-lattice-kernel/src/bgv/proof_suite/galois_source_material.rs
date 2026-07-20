use crate::{
    bgv::evaluator::candidate_evidence::EvaluatorCandidateInput,
    foundation::{
        CanonicalStreamDomain, FOUNDATION_PROFILE, Hash512, ProofApplicationSlot,
        ProofApplicationSlotCeilings, StreamDescriptor,
    },
};

use super::evaluator_source_material::{
    expected_component_column_moduli, material_topology_matches_selected_catalog_level,
};
use super::{
    BorrowedVerifiedCommonProofCapability, CommonProofVerifierError,
    ComponentMaterialOwnershipBinding, ConsumedVerifiedCommonProofCapability,
    SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, SetupPublicPolynomialContext, SetupPublicPolynomialRootRole,
    SetupPublicPolynomialTree, VerifiedEvaluatorAuxiliaryRoot, VerifiedKeySwitchComponentMaterial,
    VerifiedStatementOwnedTree, VerifiedStreamedProofTreeTerminal,
    VerifiedStreamedProofTreeTerminalPreflight, decode_selected_galois_key_share_statement,
    selected_evaluator_entry_positions, verified_application_statement_hash,
};

const SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION: u32 = 0;

#[derive(Clone, Copy)]
struct VerifiedGaloisProofBinding {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verification_binding_hash: [u8; Hash512::BYTE_LENGTH],
    proof_application_slot_hash: [u8; Hash512::BYTE_LENGTH],
    canonical_proof_application_binding_hash: [u8; Hash512::BYTE_LENGTH],
    application_statement_hash: [u8; Hash512::BYTE_LENGTH],
    relation_plan_variant_hash: [u8; Hash512::BYTE_LENGTH],
}

/// Verifier-owned authority for one source component in the selected Galois
/// batch. The contribution root is accepted only through the recomputed proof
/// tree terminal; the material capability separately authenticates replay of
/// the exact component bytes under the same application binding.
pub(crate) struct VerifiedGaloisSourceComponent {
    evaluator_position: SelectedEvaluatorEntryPosition,
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    contribution_root: [u8; Hash512::BYTE_LENGTH],
    material: VerifiedKeySwitchComponentMaterial,
}

impl VerifiedGaloisSourceComponent {
    pub(crate) const fn evaluator_position(&self) -> SelectedEvaluatorEntryPosition {
        self.evaluator_position
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_polynomial_context_hash
    }

    pub(crate) const fn contribution_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.contribution_root
    }

    pub(crate) const fn material(&self) -> &VerifiedKeySwitchComponentMaterial {
        &self.material
    }
}

/// One exact 0x1217 application consumed into the selected participant and
/// suite schedule. There is no constructor from roots, descriptors, or copied
/// verifier facts.
pub(crate) struct VerifiedGaloisSourceMaterialBatch {
    proof_binding: VerifiedGaloisProofBinding,
    proof_stream_descriptor: StreamDescriptor,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    batch_schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    ordered_auxiliary_roots: Box<[VerifiedEvaluatorAuxiliaryRoot]>,
    ordered_components: Box<[VerifiedGaloisSourceComponent]>,
}

#[derive(Clone)]
pub(crate) struct GaloisSourceComponentPreflightBinding {
    evaluator_position: SelectedEvaluatorEntryPosition,
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    contribution_root: [u8; Hash512::BYTE_LENGTH],
    material_root: Hash512,
    topology: super::KeySwitchComponentMaterialTopology,
    stream_descriptor: StreamDescriptor,
}

impl GaloisSourceComponentPreflightBinding {
    pub(crate) const fn evaluator_position(&self) -> SelectedEvaluatorEntryPosition {
        self.evaluator_position
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_polynomial_context_hash
    }

    pub(crate) const fn contribution_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.contribution_root
    }

    pub(crate) const fn material_root(&self) -> Hash512 {
        self.material_root
    }

    pub(crate) const fn topology(&self) -> &super::KeySwitchComponentMaterialTopology {
        &self.topology
    }

    pub(crate) const fn stream_descriptor(&self) -> &StreamDescriptor {
        &self.stream_descriptor
    }
}

/// All fallible package, relation-tree, component-material, and generic-proof
/// checks for one Galois terminal. The positive generic proof remains live
/// until the destination catalog also accepts these exact bindings.
pub(crate) struct VerifiedGaloisSourceMaterialBatchPreflight {
    proof_binding: VerifiedGaloisProofBinding,
    proof_stream_descriptor: StreamDescriptor,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    batch_schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    ordered_component_bindings: Box<[GaloisSourceComponentPreflightBinding]>,
    ordered_auxiliary_roots: Box<[VerifiedEvaluatorAuxiliaryRoot]>,
    ordered_tree_preflights: Box<[VerifiedStreamedProofTreeTerminalPreflight]>,
}

impl VerifiedGaloisSourceMaterialBatchPreflight {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_borrowed_common_proof(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        roster_hash: [u8; Hash512::BYTE_LENGTH],
        statement_trees: &[VerifiedStatementOwnedTree],
        ordered_contribution_trees: &[SetupPublicPolynomialTree],
        ordered_materials: &[VerifiedKeySwitchComponentMaterial],
        ordered_auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
    ) -> Result<Self, CommonProofVerifierError> {
        let proof_binding = VerifiedGaloisProofBinding {
            protocol_version: verified_proof.protocol_version(),
            suite_identifier: verified_proof.suite_identifier(),
            ceremony_context_hash: verified_proof.ceremony_context_hash(),
            action_context_hash: verified_proof.action_context_hash(),
            roster_hash,
            verification_binding_hash: verified_proof.verification_binding_hash(),
            proof_application_slot_hash: verified_proof.proof_application_slot_hash(),
            canonical_proof_application_binding_hash: verified_proof
                .canonical_proof_application_binding_hash(),
            application_statement_hash: verified_proof.application_statement_hash(),
            relation_plan_variant_hash: verified_proof.relation_plan_variant_hash(),
        };
        if proof_binding.protocol_version != FOUNDATION_PROFILE.protocol_version
            || verified_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.proof_stream_domain() != CanonicalStreamDomain::GaloisShareProof
            || verified_proof.schedule_position()
                != Some(SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION)
            || verified_proof.top_count().is_some()
            || proof_binding.application_statement_hash
                != verified_application_statement_hash(
                    proof_binding.protocol_version,
                    proof_binding.suite_identifier,
                    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    canonical_application_statement_bytes,
                )
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement = decode_selected_galois_key_share_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                proof_binding.protocol_version,
                proof_binding.suite_identifier,
                Some(SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION),
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let setup_proof_context_hash = statement.setup_proof_context_hash();
        let participant_identity = statement.participant_identity();
        let roster_position = statement.roster_position();
        let batch_schedule_position = statement.batch_schedule_position();
        let reconstructed_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(proof_binding.suite_identifier),
            Hash512::from_bytes(proof_binding.ceremony_context_hash),
            Hash512::from_bytes(proof_binding.action_context_hash),
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(roster_position),
            Some(batch_schedule_position),
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if reconstructed_application_slot.into_bytes() != proof_binding.proof_application_slot_hash
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let statement_roots = statement.ordered_contribution_roots();
        let anchor_commitment_roots = statement.anchor_commitment_roots();
        let selected_positions = selected_galois_source_positions()?;
        if statement_roots.is_empty()
            || statement_roots.len() != selected_positions.len()
            || ordered_contribution_trees.len() != selected_positions.len()
            || ordered_materials.len() != selected_positions.len()
            || ordered_auxiliary_roots.len() != selected_positions.len()
            || ordered_auxiliary_roots
                .iter()
                .zip(&selected_positions)
                .any(|(root, position)| root.position() != *position)
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let material_ownership = ComponentMaterialOwnershipBinding::from_verified_application(
            proof_binding.suite_identifier,
            proof_binding.action_context_hash,
            proof_binding.application_statement_hash,
        );
        let selected_candidate = EvaluatorCandidateInput::implemented()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let mut ordered_component_bindings = Vec::new();
        ordered_component_bindings
            .try_reserve_exact(selected_positions.len())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let mut ordered_tree_preflights = Vec::new();
        ordered_tree_preflights
            .try_reserve_exact(selected_positions.len())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        for (entry_ordinal, (((statement_root, selected_position), contribution_tree), material)) in
            statement_roots
                .iter()
                .copied()
                .zip(selected_positions)
                .zip(ordered_contribution_trees)
                .zip(ordered_materials)
                .enumerate()
        {
            let logical_schedule_position = u32::try_from(entry_ordinal)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let context = SetupPublicPolynomialContext::new(
                setup_proof_context_hash,
                SetupPublicPolynomialRootRole::GaloisKeyShare,
                Some(participant_identity),
                Some(roster_position),
                Some(logical_schedule_position),
                None,
            )
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let public_polynomial_context_hash = context
                .context_hash()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let catalog_level = match selected_position.key_kind() {
                SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => catalog_level,
                SelectedEvaluatorEntryKind::Relinearization { .. } => {
                    return Err(CommonProofVerifierError::InvalidApplicationStatement);
                }
            };
            let expected_column_moduli =
                expected_component_column_moduli(&selected_candidate, material)?;
            let expected_root_source_ordinal = anchor_commitment_roots
                .len()
                .checked_add(entry_ordinal)
                .and_then(|source_ordinal| u32::try_from(source_ordinal).ok())
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            let mut matching_statement_trees = statement_trees.iter().filter(|tree| {
                tree.expected_root_source_ordinal() == expected_root_source_ordinal
                    && tree.expected_root() == statement_root
            });
            let statement_tree = matching_statement_trees
                .next()
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            if matching_statement_trees.next().is_some()
                || contribution_tree.root() != statement_root
                || contribution_tree.public_polynomial_context_hash()
                    != public_polynomial_context_hash
                || contribution_tree.source_polynomial_degree_bound_exclusive()
                    != material
                        .topology()
                        .half_polynomial_degree_bound_exclusive()
                        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                || !material.binds_ownership(material_ownership)
                || !material_topology_matches_selected_catalog_level(
                    &selected_candidate,
                    catalog_level,
                    material,
                )
                || statement_tree.ordered_canonical_residue_moduli()
                    != expected_column_moduli.as_ref()
            {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            let terminal_preflight =
                VerifiedStreamedProofTreeTerminal::preflight_from_recomputed_key_switch_component_tree(
                    verified_proof.verified_proof(),
                    canonical_application_statement_bytes,
                    proof_binding.ceremony_context_hash,
                    proof_binding.action_context_hash,
                    proof_binding.roster_hash,
                    statement_tree.ordered_tree_ordinal(),
                    expected_root_source_ordinal,
                    statement_root,
                    context,
                    expected_column_moduli.into_vec(),
                    material,
                    contribution_tree,
                )?;
            ordered_component_bindings.push(GaloisSourceComponentPreflightBinding {
                evaluator_position: selected_position,
                public_polynomial_context_hash,
                contribution_root: statement_root,
                material_root: material.material_root(),
                topology: material.topology().clone(),
                stream_descriptor: material.stream_descriptor().clone(),
            });
            ordered_tree_preflights.push(terminal_preflight);
        }
        Ok(Self {
            proof_binding,
            proof_stream_descriptor: verified_proof.proof_stream_descriptor().clone(),
            setup_proof_context_hash,
            participant_identity,
            roster_position,
            batch_schedule_position,
            anchor_commitment_roots,
            ordered_component_bindings: ordered_component_bindings.into_boxed_slice(),
            ordered_auxiliary_roots: ordered_auxiliary_roots.to_vec().into_boxed_slice(),
            ordered_tree_preflights: ordered_tree_preflights.into_boxed_slice(),
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

    pub(crate) const fn batch_schedule_position(&self) -> u32 {
        self.batch_schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.proof_binding.application_statement_hash
    }

    pub(crate) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(crate) fn ordered_component_bindings(&self) -> &[GaloisSourceComponentPreflightBinding] {
        &self.ordered_component_bindings
    }

    pub(crate) fn ordered_auxiliary_roots(&self) -> &[VerifiedEvaluatorAuxiliaryRoot] {
        &self.ordered_auxiliary_roots
    }

    pub(crate) fn complete(
        self,
        verified_proof: ConsumedVerifiedCommonProofCapability,
        canonical_application_statement_bytes: &[u8],
        ordered_contribution_trees: Vec<SetupPublicPolynomialTree>,
        ordered_materials: Vec<VerifiedKeySwitchComponentMaterial>,
        ordered_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    ) -> VerifiedGaloisSourceMaterialBatch {
        let borrowed_proof = verified_proof.borrowed();
        assert_eq!(
            borrowed_proof.protocol_version(),
            self.proof_binding.protocol_version
        );
        assert_eq!(
            borrowed_proof.suite_identifier(),
            self.proof_binding.suite_identifier
        );
        assert_eq!(
            borrowed_proof.ceremony_context_hash(),
            self.proof_binding.ceremony_context_hash
        );
        assert_eq!(
            borrowed_proof.action_context_hash(),
            self.proof_binding.action_context_hash
        );
        assert_eq!(
            borrowed_proof.verification_binding_hash(),
            self.proof_binding.verification_binding_hash
        );
        assert_eq!(
            borrowed_proof.proof_application_slot_hash(),
            self.proof_binding.proof_application_slot_hash
        );
        assert_eq!(
            borrowed_proof.canonical_proof_application_binding_hash(),
            self.proof_binding.canonical_proof_application_binding_hash
        );
        assert_eq!(
            borrowed_proof.application_statement_hash(),
            self.proof_binding.application_statement_hash
        );
        assert_eq!(
            borrowed_proof.proof_stream_descriptor(),
            &self.proof_stream_descriptor
        );
        assert_eq!(
            ordered_auxiliary_roots.as_slice(),
            self.ordered_auxiliary_roots.as_ref()
        );
        let ordered_contribution_trees = self
            .ordered_tree_preflights
            .into_vec()
            .into_iter()
            .zip(ordered_contribution_trees)
            .map(|(preflight, tree)| preflight.complete(tree))
            .collect();
        VerifiedGaloisSourceMaterialBatch::from_consumed_common_proof(
            verified_proof,
            canonical_application_statement_bytes,
            ordered_contribution_trees,
            ordered_materials,
            ordered_auxiliary_roots,
        )
        .expect("Galois terminal completion uses the exact preflighted proof and sources")
    }
}

impl VerifiedGaloisSourceMaterialBatch {
    pub(crate) fn from_consumed_common_proof(
        verified_proof: ConsumedVerifiedCommonProofCapability,
        canonical_application_statement_bytes: &[u8],
        ordered_contribution_trees: Vec<VerifiedStreamedProofTreeTerminal>,
        ordered_materials: Vec<VerifiedKeySwitchComponentMaterial>,
        ordered_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    ) -> Result<Self, CommonProofVerifierError> {
        let roster_hash = ordered_contribution_trees
            .first()
            .map(VerifiedStreamedProofTreeTerminal::roster_hash)
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let proof_binding = VerifiedGaloisProofBinding {
            protocol_version: verified_proof.protocol_version(),
            suite_identifier: verified_proof.suite_identifier(),
            ceremony_context_hash: verified_proof.ceremony_context_hash(),
            action_context_hash: verified_proof.action_context_hash(),
            roster_hash,
            verification_binding_hash: verified_proof.verification_binding_hash(),
            proof_application_slot_hash: verified_proof.proof_application_slot_hash(),
            canonical_proof_application_binding_hash: verified_proof
                .canonical_proof_application_binding_hash(),
            application_statement_hash: verified_proof.application_statement_hash(),
            relation_plan_variant_hash: verified_proof.relation_plan_variant_hash(),
        };
        if proof_binding.protocol_version != FOUNDATION_PROFILE.protocol_version
            || verified_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.proof_stream_domain() != CanonicalStreamDomain::GaloisShareProof
            || verified_proof.schedule_position()
                != Some(SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION)
            || verified_proof.top_count().is_some()
            || proof_binding.application_statement_hash
                != verified_application_statement_hash(
                    proof_binding.protocol_version,
                    proof_binding.suite_identifier,
                    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    canonical_application_statement_bytes,
                )
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement = decode_selected_galois_key_share_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                proof_binding.protocol_version,
                proof_binding.suite_identifier,
                Some(SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION),
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let setup_proof_context_hash = statement.setup_proof_context_hash();
        let participant_identity = statement.participant_identity();
        let roster_position = statement.roster_position();
        let batch_schedule_position = statement.batch_schedule_position();
        let reconstructed_application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(proof_binding.suite_identifier),
            Hash512::from_bytes(proof_binding.ceremony_context_hash),
            Hash512::from_bytes(proof_binding.action_context_hash),
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(roster_position),
            Some(batch_schedule_position),
            None,
        )
        .and_then(ProofApplicationSlot::hash)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if reconstructed_application_slot.into_bytes() != proof_binding.proof_application_slot_hash
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let statement_roots = statement.ordered_contribution_roots();
        let selected_positions = selected_galois_source_positions()?;
        if statement_roots.is_empty()
            || statement_roots.len() != selected_positions.len()
            || ordered_contribution_trees.len() != selected_positions.len()
            || ordered_materials.len() != selected_positions.len()
            || ordered_auxiliary_roots.len() != selected_positions.len()
            || ordered_auxiliary_roots
                .iter()
                .zip(&selected_positions)
                .any(|(root, position)| root.position() != *position)
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let material_ownership = ComponentMaterialOwnershipBinding::from_verified_application(
            proof_binding.suite_identifier,
            proof_binding.action_context_hash,
            proof_binding.application_statement_hash,
        );
        let selected_candidate = EvaluatorCandidateInput::implemented()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let mut verified_components = Vec::new();
        verified_components
            .try_reserve_exact(selected_positions.len())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        for (entry_ordinal, (((statement_root, selected_position), contribution_tree), material)) in
            statement_roots
                .iter()
                .copied()
                .zip(selected_positions)
                .zip(ordered_contribution_trees)
                .zip(ordered_materials)
                .enumerate()
        {
            let logical_schedule_position = u32::try_from(entry_ordinal)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let expected_public_polynomial_context = SetupPublicPolynomialContext::new(
                setup_proof_context_hash,
                SetupPublicPolynomialRootRole::GaloisKeyShare,
                Some(participant_identity),
                Some(roster_position),
                Some(logical_schedule_position),
                None,
            )
            .and_then(|context| context.context_hash())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let catalog_level = match selected_position.key_kind() {
                SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => catalog_level,
                SelectedEvaluatorEntryKind::Relinearization { .. } => {
                    return Err(CommonProofVerifierError::InvalidApplicationStatement);
                }
            };
            let expected_column_moduli =
                expected_component_column_moduli(&selected_candidate, &material)?;
            let expected_root_source_ordinal = statement
                .anchor_commitment_roots()
                .len()
                .checked_add(entry_ordinal)
                .and_then(|source_ordinal| u32::try_from(source_ordinal).ok())
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            if contribution_tree.protocol_version() != proof_binding.protocol_version
                || contribution_tree.suite_identifier() != proof_binding.suite_identifier
                || contribution_tree.ceremony_context_hash() != proof_binding.ceremony_context_hash
                || contribution_tree.action_context_hash() != proof_binding.action_context_hash
                || contribution_tree.roster_hash() != proof_binding.roster_hash
                || contribution_tree.application_statement_schema_identifier()
                    != ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                || contribution_tree.application_statement_hash()
                    != proof_binding.application_statement_hash
                || contribution_tree.relation_plan_variant_hash()
                    != proof_binding.relation_plan_variant_hash
                || contribution_tree.canonical_application_statement_bytes()
                    != canonical_application_statement_bytes
                || contribution_tree.setup_proof_context_hash() != setup_proof_context_hash
                || contribution_tree.owner_participant_identity() != Some(participant_identity)
                || contribution_tree.owner_roster_position() != Some(roster_position)
                || contribution_tree.schedule_position() != Some(logical_schedule_position)
                || contribution_tree.ordered_tree_ordinal() != logical_schedule_position
                || contribution_tree.expected_root_source_ordinal() != expected_root_source_ordinal
                || contribution_tree.root_role() != SetupPublicPolynomialRootRole::GaloisKeyShare
                || contribution_tree.public_polynomial_context_hash()
                    != expected_public_polynomial_context
                || contribution_tree.root() != statement_root
                || contribution_tree.source_polynomial_degree_bound_exclusive()
                    != material
                        .topology()
                        .half_polynomial_degree_bound_exclusive()
                        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
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
                || contribution_tree.source_stream_descriptor()
                    != Some(material.stream_descriptor())
                || !material.binds_ownership(material_ownership)
                || !material_topology_matches_selected_catalog_level(
                    &selected_candidate,
                    catalog_level,
                    &material,
                )
                || contribution_tree.ordered_canonical_residue_moduli()
                    != expected_column_moduli.as_ref()
            {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
            verified_components.push(VerifiedGaloisSourceComponent {
                evaluator_position: selected_position,
                public_polynomial_context_hash: contribution_tree.public_polynomial_context_hash(),
                contribution_root: statement_root,
                material,
            });
        }

        Ok(Self {
            proof_binding,
            proof_stream_descriptor: verified_proof.proof_stream_descriptor().clone(),
            setup_proof_context_hash,
            participant_identity,
            roster_position,
            batch_schedule_position,
            anchor_commitment_roots: statement.anchor_commitment_roots(),
            ordered_auxiliary_roots: ordered_auxiliary_roots.into_boxed_slice(),
            ordered_components: verified_components.into_boxed_slice(),
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

    pub(crate) const fn batch_schedule_position(&self) -> u32 {
        self.batch_schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
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

    pub(crate) fn ordered_components(&self) -> &[VerifiedGaloisSourceComponent] {
        &self.ordered_components
    }

    pub(crate) fn ordered_auxiliary_roots(&self) -> &[VerifiedEvaluatorAuxiliaryRoot] {
        &self.ordered_auxiliary_roots
    }
}

fn selected_galois_source_positions()
-> Result<Vec<SelectedEvaluatorEntryPosition>, CommonProofVerifierError> {
    let selected_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let evaluator_positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let mut selected_positions = Vec::new();
    selected_positions
        .try_reserve_exact(selected_candidate.galois_key_schedule.len())
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    for (galois_element, catalog_level) in selected_candidate.galois_key_schedule {
        let matching_positions = evaluator_positions
            .iter()
            .copied()
            .filter(|position| {
                position.key_kind()
                    == SelectedEvaluatorEntryKind::Galois {
                        galois_element,
                        catalog_level,
                    }
            })
            .collect::<Vec<_>>();
        let [position] = matching_positions.as_slice() else {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        };
        if selected_positions.contains(position) {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        selected_positions.push(*position);
    }
    Ok(selected_positions)
}
