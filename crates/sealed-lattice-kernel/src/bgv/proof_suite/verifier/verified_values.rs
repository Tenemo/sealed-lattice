use super::super::{
    ComponentMaterialOwnershipBinding, SetupPublicPolynomialContext,
    VerifiedEvaluatorKeyStoreMaterial, VerifiedKeySwitchComponentMaterial,
    VerifiedRelinearizationAggregateMaterial,
    evaluator_source_material::{
        expected_component_column_moduli, material_topology_matches_selected_catalog_level,
    },
    relation_plan::{BoundTreeConstructionKind, BoundTreeRootUse, RelationTreeDescriptor},
    selected_evaluator_aggregate_relation_plan,
};
use super::{
    CanonicalItemType, CommittedMaterialTree, CommonProofVerifierError, FOUNDATION_PROFILE,
    ProofApplicationSlotCeilings, SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, SetupPublicPolynomialRootRole, SetupPublicPolynomialTree,
    StatementOwnedProofTreeInput, SuiteModulusReference, decode_selected_application_statement,
    selected_evaluator_aggregate_entry_roots_in_order, selected_evaluator_entry_positions,
    verified_application_statement_hash,
};
use crate::bgv::evaluator::candidate_evidence::EvaluatorCandidateInput;
use crate::bgv::proof_suite::ProofBaseFieldElement;
use crate::bgv::setup::VerifiedAcceptedSetupEvaluatorSourceCatalog;
use crate::foundation::{CanonicalStreamDomain, StreamDescriptor, VerifiedCanonicalStreamSummary};

/// Opaque evidence minted only after the complete generated verifier accepts.
/// It binds the exact suite, protocol version, application statement, and
/// selected relation-plan variant. Family code consumes this capability
/// instead of accepting a proof byte string or a caller-supplied verdict.
pub(crate) struct VerifiedCommonProof {
    pub(super) protocol_version: u16,
    pub(super) suite_identifier: [u8; 64],
    pub(super) application_statement_schema_identifier: u16,
    pub(super) application_statement_hash: [u8; 64],
    pub(super) proof_header_hash: [u8; 64],
    pub(super) proof_byte_length: u64,
    pub(super) verified_query_count: u32,
    pub(super) relation_plan_variant_hash: [u8; 64],
    pub(super) schedule_position: Option<u32>,
    pub(super) top_count: Option<u16>,
}

impl VerifiedCommonProof {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; 64] {
        self.suite_identifier
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) const fn proof_header_hash(&self) -> [u8; 64] {
        self.proof_header_hash
    }

    pub(crate) const fn proof_byte_length(&self) -> u64 {
        self.proof_byte_length
    }

    pub(crate) const fn verified_query_count(&self) -> u32 {
        self.verified_query_count
    }

    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    fn binds_application_statement(&self, canonical_application_statement_bytes: &[u8]) -> bool {
        self.application_statement_hash
            == verified_application_statement_hash(
                self.protocol_version,
                self.suite_identifier,
                self.application_statement_schema_identifier,
                canonical_application_statement_bytes,
            )
    }
}

/// One statement-owned tree already resolved from the verified application
/// inputs.  The source ordinal and relation-tree ordinal prevent a caller from
/// substituting another otherwise well-formed root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedStatementOwnedTree {
    pub(super) ordered_tree_ordinal: u32,
    pub(super) expected_root_source_ordinal: u32,
    pub(super) tree: StatementOwnedProofTreeInput,
    pub(super) ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
}

impl VerifiedStatementOwnedTree {
    pub(crate) fn with_relation_coordinates(
        &self,
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
    ) -> Self {
        let mut rebound = self.clone();
        rebound.ordered_tree_ordinal = ordered_tree_ordinal;
        rebound.expected_root_source_ordinal = expected_root_source_ordinal;
        rebound
    }

    pub(crate) const fn expected_root(&self) -> [u8; 64] {
        match &self.tree {
            StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. }
            | StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. } => *expected_root,
        }
    }

    pub(crate) fn from_committed_material_tree(
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        tree: &CommittedMaterialTree,
        ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
    ) -> Self {
        Self {
            ordered_tree_ordinal,
            expected_root_source_ordinal,
            tree: StatementOwnedProofTreeInput::CommittedMaterial {
                material_context_hash: tree.material_context_hash(),
                expected_root: tree.root(),
            },
            ordered_canonical_residue_moduli,
        }
    }

    /// Constructs the verifier-owned tree input only from canonical source
    /// coefficients that the public-polynomial tree implementation already
    /// evaluated and hashed. There is deliberately no constructor accepting a
    /// separately claimed setup-polynomial root.
    pub(crate) fn from_setup_public_polynomial_tree(
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        tree: &SetupPublicPolynomialTree,
        ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
    ) -> Self {
        Self {
            ordered_tree_ordinal,
            expected_root_source_ordinal,
            tree: StatementOwnedProofTreeInput::SetupPolynomial {
                public_polynomial_context_hash: tree.public_polynomial_context_hash(),
                row_width: tree.row_width(),
                expected_root: tree.root(),
            },
            ordered_canonical_residue_moduli,
        }
    }
}

/// Opaque terminal for one public-polynomial tree whose coefficient stream,
/// leaf stream, and Merkle root were recomputed by the verifier. It keeps the
/// exact per-entry modulus prefix and statement coordinates beside the owned
/// tree, so family carriers never accept a detached root or reconstruct source
/// material from decoded JSON.
pub(crate) struct VerifiedStreamedProofTreeTerminal {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    roster_hash: [u8; 64],
    application_statement_schema_identifier: u16,
    application_statement_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    canonical_application_statement_bytes: Box<[u8]>,
    ordered_tree_ordinal: u32,
    expected_root_source_ordinal: u32,
    context: SetupPublicPolynomialContext,
    ordered_canonical_residue_moduli: Box<[Option<SuiteModulusReference>]>,
    source_stream_domain: Option<CanonicalStreamDomain>,
    source_material_root: Option<[u8; 64]>,
    source_stream_descriptor: Option<StreamDescriptor>,
    tree: SetupPublicPolynomialTree,
}

pub(crate) struct VerifiedStreamedProofTreeTerminalPreflight {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    roster_hash: [u8; 64],
    application_statement_schema_identifier: u16,
    application_statement_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    canonical_application_statement_bytes: Box<[u8]>,
    ordered_tree_ordinal: u32,
    expected_root_source_ordinal: u32,
    context: SetupPublicPolynomialContext,
    ordered_canonical_residue_moduli: Box<[Option<SuiteModulusReference>]>,
    source_stream_domain: Option<CanonicalStreamDomain>,
    source_material_root: Option<[u8; 64]>,
    source_stream_descriptor: Option<StreamDescriptor>,
}

impl VerifiedStreamedProofTreeTerminalPreflight {
    pub(crate) fn complete(
        self,
        tree: SetupPublicPolynomialTree,
    ) -> VerifiedStreamedProofTreeTerminal {
        VerifiedStreamedProofTreeTerminal {
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            application_statement_schema_identifier: self.application_statement_schema_identifier,
            application_statement_hash: self.application_statement_hash,
            relation_plan_variant_hash: self.relation_plan_variant_hash,
            canonical_application_statement_bytes: self.canonical_application_statement_bytes,
            ordered_tree_ordinal: self.ordered_tree_ordinal,
            expected_root_source_ordinal: self.expected_root_source_ordinal,
            context: self.context,
            ordered_canonical_residue_moduli: self.ordered_canonical_residue_moduli,
            source_stream_domain: self.source_stream_domain,
            source_material_root: self.source_material_root,
            source_stream_descriptor: self.source_stream_descriptor,
            tree,
        }
    }
}

impl VerifiedStreamedProofTreeTerminal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_recomputed_public_polynomial_tree(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        roster_hash: [u8; 64],
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        expected_statement_root: [u8; 64],
        context: SetupPublicPolynomialContext,
        ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
        tree: SetupPublicPolynomialTree,
    ) -> Result<Self, CommonProofVerifierError> {
        let preflight = Self::preflight_from_recomputed_public_polynomial_tree(
            verified_proof,
            canonical_application_statement_bytes,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            ordered_tree_ordinal,
            expected_root_source_ordinal,
            expected_statement_root,
            context,
            ordered_canonical_residue_moduli,
            &tree,
        )?;
        Ok(preflight.complete(tree))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight_from_recomputed_public_polynomial_tree(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        roster_hash: [u8; 64],
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        expected_statement_root: [u8; 64],
        context: SetupPublicPolynomialContext,
        ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
        tree: &SetupPublicPolynomialTree,
    ) -> Result<VerifiedStreamedProofTreeTerminalPreflight, CommonProofVerifierError> {
        let context_hash = context
            .context_hash()
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
        if !verified_proof.binds_application_statement(canonical_application_statement_bytes)
            || tree.root() != expected_statement_root
            || tree.public_polynomial_context_hash() != context_hash
            || tree.root_role() != context.root_role()
            || tree.schedule_position() != context.schedule_position()
            || usize::try_from(tree.row_width()).ok()
                != Some(ordered_canonical_residue_moduli.len())
            || ordered_canonical_residue_moduli.is_empty()
        {
            return Err(CommonProofVerifierError::InvalidBoundTree);
        }
        Ok(VerifiedStreamedProofTreeTerminalPreflight {
            protocol_version: verified_proof.protocol_version,
            suite_identifier: verified_proof.suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            application_statement_schema_identifier: verified_proof
                .application_statement_schema_identifier,
            application_statement_hash: verified_proof.application_statement_hash,
            relation_plan_variant_hash: verified_proof.relation_plan_variant_hash,
            canonical_application_statement_bytes: canonical_application_statement_bytes
                .to_vec()
                .into_boxed_slice(),
            ordered_tree_ordinal,
            expected_root_source_ordinal,
            context,
            ordered_canonical_residue_moduli: ordered_canonical_residue_moduli.into_boxed_slice(),
            source_stream_domain: None,
            source_material_root: None,
            source_stream_descriptor: None,
        })
    }

    /// Mints a tree terminal whose coefficient columns are proven to be the
    /// low/high decomposition of one exact descriptor-authenticated
    /// key-switch component. The component descriptor is recomputed from the
    /// tree coefficients before it is retained, preventing a tree for one
    /// material object from being paired with another object's readback.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_recomputed_key_switch_component_tree(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        roster_hash: [u8; 64],
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        expected_statement_root: [u8; 64],
        context: SetupPublicPolynomialContext,
        ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
        source_material: &VerifiedKeySwitchComponentMaterial,
        tree: SetupPublicPolynomialTree,
    ) -> Result<Self, CommonProofVerifierError> {
        let preflight = Self::preflight_from_recomputed_key_switch_component_tree(
            verified_proof,
            canonical_application_statement_bytes,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            ordered_tree_ordinal,
            expected_root_source_ordinal,
            expected_statement_root,
            context,
            ordered_canonical_residue_moduli,
            source_material,
            &tree,
        )?;
        Ok(preflight.complete(tree))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight_from_recomputed_key_switch_component_tree(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        roster_hash: [u8; 64],
        ordered_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        expected_statement_root: [u8; 64],
        context: SetupPublicPolynomialContext,
        ordered_canonical_residue_moduli: Vec<Option<SuiteModulusReference>>,
        source_material: &VerifiedKeySwitchComponentMaterial,
        tree: &SetupPublicPolynomialTree,
    ) -> Result<VerifiedStreamedProofTreeTerminalPreflight, CommonProofVerifierError> {
        source_material
            .authenticate_setup_tree_trace_columns(tree.ordered_coefficient_columns())
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
        let mut preflight = Self::preflight_from_recomputed_public_polynomial_tree(
            verified_proof,
            canonical_application_statement_bytes,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            ordered_tree_ordinal,
            expected_root_source_ordinal,
            expected_statement_root,
            context,
            ordered_canonical_residue_moduli,
            tree,
        )?;
        preflight.source_stream_domain = Some(CanonicalStreamDomain::EvaluatorKeyStore);
        preflight.source_material_root = Some(source_material.material_root().into_bytes());
        preflight.source_stream_descriptor = Some(source_material.stream_descriptor().clone());
        Ok(preflight)
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; 64] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; 64] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; 64] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; 64] {
        self.roster_hash
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) const fn ordered_tree_ordinal(&self) -> u32 {
        self.ordered_tree_ordinal
    }

    pub(crate) const fn expected_root_source_ordinal(&self) -> u32 {
        self.expected_root_source_ordinal
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; 64] {
        self.context.setup_proof_context_hash()
    }

    pub(crate) const fn root_role(&self) -> SetupPublicPolynomialRootRole {
        self.context.root_role()
    }

    pub(crate) const fn owner_participant_identity(&self) -> Option<[u8; 64]> {
        self.context.owner_participant_identity()
    }

    pub(crate) const fn owner_roster_position(&self) -> Option<u16> {
        self.context.owner_roster_position()
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.context.schedule_position()
    }

    pub(crate) const fn public_polynomial_context_hash(&self) -> [u8; 64] {
        self.tree.public_polynomial_context_hash()
    }

    pub(crate) fn row_width(&self) -> u32 {
        self.tree.row_width()
    }

    pub(crate) const fn source_polynomial_degree_bound_exclusive(&self) -> usize {
        self.tree.source_polynomial_degree_bound_exclusive()
    }

    pub(crate) fn ordered_canonical_residue_moduli(&self) -> &[Option<SuiteModulusReference>] {
        &self.ordered_canonical_residue_moduli
    }

    pub(crate) const fn source_stream_domain(&self) -> Option<CanonicalStreamDomain> {
        self.source_stream_domain
    }

    pub(crate) const fn source_material_root(&self) -> Option<[u8; 64]> {
        self.source_material_root
    }

    pub(crate) const fn source_stream_descriptor(&self) -> Option<&StreamDescriptor> {
        self.source_stream_descriptor.as_ref()
    }

    pub(crate) fn source_full_object_digest(&self) -> Option<[u8; 64]> {
        self.source_stream_descriptor
            .as_ref()
            .map(|descriptor| descriptor.full_object_digest.into_bytes())
    }

    pub(crate) fn source_total_byte_length(&self) -> Option<u64> {
        self.source_stream_descriptor
            .as_ref()
            .map(|descriptor| descriptor.total_byte_length)
    }

    pub(crate) fn root(&self) -> [u8; 64] {
        self.tree.root()
    }

    pub(crate) fn ordered_coefficient_columns(&self) -> &[Vec<ProofBaseFieldElement>] {
        self.tree.ordered_coefficient_columns()
    }

    pub(crate) fn statement_owned_tree(&self) -> VerifiedStatementOwnedTree {
        VerifiedStatementOwnedTree::from_setup_public_polynomial_tree(
            self.ordered_tree_ordinal,
            self.expected_root_source_ordinal,
            &self.tree,
            self.ordered_canonical_residue_moduli.to_vec(),
        )
    }

    pub(crate) fn into_recomputed_tree(self) -> SetupPublicPolynomialTree {
        self.tree
    }

    pub(crate) fn into_statement_owned_tree_and_material(
        self,
    ) -> (
        VerifiedStatementOwnedTree,
        SetupPublicPolynomialTree,
        Box<[u8]>,
    ) {
        let statement_owned_tree = self.statement_owned_tree();
        (
            statement_owned_tree,
            self.tree,
            self.canonical_application_statement_bytes,
        )
    }

    pub(crate) fn into_evaluator_runtime_root(
        self,
        top_count: u16,
    ) -> Result<VerifiedEvaluatorRuntimeRoot, CommonProofVerifierError> {
        VerifiedEvaluatorRuntimeRoot::from_recomputed_public_polynomial_tree(&self.tree, top_count)
    }
}

/// Verifier-owned linkage for the unproved A component of one evaluator key.
/// Runtime B remains the only component in the evaluator-key aggregate relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedEvaluatorAuxiliaryRoot {
    position: SelectedEvaluatorEntryPosition,
    auxiliary_component_root: [u8; 64],
    source_material_root: Option<[u8; 64]>,
    source_stream_descriptor: Option<StreamDescriptor>,
}

impl VerifiedEvaluatorAuxiliaryRoot {
    /// Retains the relinearization A-component authority from the accepted
    /// aggregate material. The position, root, and authenticated carrier all
    /// come from the verifier-owned aggregate; callers cannot restate them.
    pub(crate) fn from_verified_relinearization_aggregate_material(
        material: &VerifiedRelinearizationAggregateMaterial,
    ) -> Result<Self, CommonProofVerifierError> {
        let position = material.evaluator_position();
        let catalog_level = match position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { catalog_level } => catalog_level,
            SelectedEvaluatorEntryKind::Galois { .. } => {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
        };
        let selected_candidate = EvaluatorCandidateInput::implemented()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if !material_topology_matches_selected_catalog_level(
            &selected_candidate,
            catalog_level,
            material.material(),
        ) {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        Ok(Self {
            position,
            auxiliary_component_root: material.aggregate_right_root(),
            source_material_root: Some(material.material_root()),
            source_stream_descriptor: Some(material.stream_descriptor().clone()),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_verified_relinearization_round_one_aggregate(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<Self, CommonProofVerifierError> {
        let schedule_position = verified_proof
            .schedule_position
            .filter(|_| {
                verified_proof.application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                    && verified_proof.top_count.is_none()
                    && verified_proof.binds_application_statement(
                        canonical_application_statement_bytes,
                    )
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let statement = decode_selected_application_statement(
            canonical_application_statement_bytes,
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version,
                verified_proof.suite_identifier,
                Some(schedule_position),
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let auxiliary_component_root = statement
            .items
            .get(4)
            .filter(|item| {
                item.item_type() == CanonicalItemType::Hash512 && item.canonical_bytes().len() == 64
            })
            .and_then(|item| item.canonical_bytes().try_into().ok())
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let position = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            .into_iter()
            .find(|position| {
                position.schedule_position() == schedule_position
                    && matches!(
                        position.key_kind(),
                        SelectedEvaluatorEntryKind::Relinearization { .. }
                    )
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        Ok(Self {
            position,
            auxiliary_component_root,
            source_material_root: None,
            source_stream_descriptor: None,
        })
    }

    pub(crate) fn from_verified_relinearization_round_one_aggregate_tree(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        aggregate_right_tree: &VerifiedStreamedProofTreeTerminal,
    ) -> Result<Self, CommonProofVerifierError> {
        let schedule_position = verified_proof
            .schedule_position
            .filter(|_| {
                verified_proof.application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                    && verified_proof.top_count.is_none()
                    && verified_proof.binds_application_statement(
                        canonical_application_statement_bytes,
                    )
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let statement = decode_selected_application_statement(
            canonical_application_statement_bytes,
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version,
                verified_proof.suite_identifier,
                Some(schedule_position),
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let auxiliary_component_root = statement
            .items
            .get(4)
            .filter(|item| {
                item.item_type() == CanonicalItemType::Hash512 && item.canonical_bytes().len() == 64
            })
            .and_then(|item| item.canonical_bytes().try_into().ok())
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let position = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            .into_iter()
            .find(|position| {
                position.schedule_position() == schedule_position
                    && matches!(
                        position.key_kind(),
                        SelectedEvaluatorEntryKind::Relinearization { .. }
                    )
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let source_material_root = aggregate_right_tree
            .source_material_root()
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        let source_stream_descriptor = aggregate_right_tree
            .source_stream_descriptor()
            .cloned()
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        if aggregate_right_tree.protocol_version() != verified_proof.protocol_version
            || aggregate_right_tree.suite_identifier() != verified_proof.suite_identifier
            || aggregate_right_tree.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            || aggregate_right_tree.application_statement_hash()
                != verified_proof.application_statement_hash
            || aggregate_right_tree.relation_plan_variant_hash()
                != verified_proof.relation_plan_variant_hash
            || aggregate_right_tree.canonical_application_statement_bytes()
                != canonical_application_statement_bytes
            || aggregate_right_tree.root_role()
                != SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneRight
            || aggregate_right_tree.schedule_position() != Some(schedule_position)
            || aggregate_right_tree.root() != auxiliary_component_root
            || aggregate_right_tree.source_stream_domain()
                != Some(CanonicalStreamDomain::EvaluatorKeyStore)
        {
            return Err(CommonProofVerifierError::InvalidBoundTree);
        }
        Ok(Self {
            position,
            auxiliary_component_root,
            source_material_root: Some(source_material_root),
            source_stream_descriptor: Some(source_stream_descriptor),
        })
    }

    /// Mints the Galois A linkage only from a verifier-recomputed role-11
    /// public-polynomial tree at the exact selected catalog coordinate.
    pub(crate) fn from_galois_common_public_polynomial_tree(
        schedule_position: u32,
        galois_element: usize,
        catalog_level: usize,
        tree: &SetupPublicPolynomialTree,
    ) -> Result<Self, CommonProofVerifierError> {
        let position = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            .into_iter()
            .find(|position| {
                position.schedule_position() == schedule_position
                    && position.key_kind()
                        == SelectedEvaluatorEntryKind::Galois {
                            galois_element,
                            catalog_level,
                        }
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        if tree.root_role() != SetupPublicPolynomialRootRole::GaloisCommon
            || tree.schedule_position() != Some(schedule_position)
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        Ok(Self {
            position,
            auxiliary_component_root: tree.root(),
            source_material_root: None,
            source_stream_descriptor: None,
        })
    }

    pub(crate) const fn position(&self) -> SelectedEvaluatorEntryPosition {
        self.position
    }

    pub(crate) const fn auxiliary_component_root(&self) -> [u8; 64] {
        self.auxiliary_component_root
    }

    pub(crate) const fn source_material_root(&self) -> Option<[u8; 64]> {
        self.source_material_root
    }

    pub(crate) const fn source_stream_descriptor(&self) -> Option<&StreamDescriptor> {
        self.source_stream_descriptor.as_ref()
    }
}

/// Verifier-owned linkage for the runtime component of one evaluator key.
/// The capability can only be minted from a public-polynomial tree whose root
/// was recomputed from canonical coefficients at the exact selected position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedEvaluatorRuntimeRoot {
    position: SelectedEvaluatorEntryPosition,
    runtime_component_root: [u8; 64],
}

impl VerifiedEvaluatorRuntimeRoot {
    pub(crate) fn from_recomputed_public_polynomial_tree(
        tree: &SetupPublicPolynomialTree,
        top_count: u16,
    ) -> Result<Self, CommonProofVerifierError> {
        let schedule_position = tree
            .schedule_position()
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let position = selected_evaluator_entry_positions(top_count)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            .into_iter()
            .find(|position| {
                position.schedule_position() == schedule_position
                    && matches!(
                        (position.key_kind(), tree.root_role()),
                        (
                            SelectedEvaluatorEntryKind::Relinearization { .. },
                            SetupPublicPolynomialRootRole::RelinearizationRuntime,
                        ) | (
                            SelectedEvaluatorEntryKind::Galois { .. },
                            SetupPublicPolynomialRootRole::GaloisRuntime,
                        )
                    )
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        Ok(Self {
            position,
            runtime_component_root: tree.root(),
        })
    }

    pub(crate) const fn position(self) -> SelectedEvaluatorEntryPosition {
        self.position
    }

    pub(crate) const fn runtime_component_root(self) -> [u8; 64] {
        self.runtime_component_root
    }
}

/// Opaque authority for one complete selected evaluator-key store. It is
/// minted only when the full-list proof and the verifier-authenticated store
/// stream bind the same digest; the statement digest alone is never authority.
#[derive(Debug)]
pub(crate) struct VerifiedEvaluatorKeyStore {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    manifest_hash: [u8; 64],
    roster_hash: [u8; 64],
    setup_proof_context_hash: [u8; 64],
    top_count: u16,
    evaluator_key_store_digest: [u8; 64],
    proof_stream_descriptor: Option<StreamDescriptor>,
    ordered_runtime_roots: Box<[VerifiedEvaluatorRuntimeRoot]>,
    verified_evaluator_key_store_stream: VerifiedCanonicalStreamSummary,
    store_material: Option<VerifiedEvaluatorKeyStoreMaterial>,
}

impl VerifiedEvaluatorKeyStore {
    #[cfg(test)]
    pub(crate) fn from_verified_common_proof(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        verified_evaluator_key_store_stream: &VerifiedCanonicalStreamSummary,
        ordered_verified_runtime_roots: &[VerifiedEvaluatorRuntimeRoot],
    ) -> Result<Self, CommonProofVerifierError> {
        Self::from_verified_common_proof_inner(
            verified_proof,
            canonical_application_statement_bytes,
            verified_evaluator_key_store_stream,
            ordered_verified_runtime_roots,
            [0_u8; 64],
            [0_u8; 64],
            [0_u8; 64],
            [0_u8; 64],
            None,
            None,
        )
    }

    /// Constructs only the post-proof carrier needed to exercise production
    /// executor replay in guarded tests. The store material has still passed
    /// the real whole-store and per-component authenticators; this helper does
    /// not create material from a digest or replace the production executor.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authenticated_material_for_executor_tests(
        suite_identifier: [u8; 64],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        manifest_hash: [u8; 64],
        roster_hash: [u8; 64],
        setup_proof_context_hash: [u8; 64],
        proof_stream_descriptor: StreamDescriptor,
        store_material: VerifiedEvaluatorKeyStoreMaterial,
    ) -> Result<Self, CommonProofVerifierError> {
        let top_count = store_material.top_count();
        let canonical_store_summary = store_material.canonical_store_summary().clone();
        let store_descriptor = store_material.store_descriptor();
        if !(1..=FOUNDATION_PROFILE.option_count).contains(&top_count)
            || canonical_store_summary.stream_domain() != CanonicalStreamDomain::EvaluatorKeyStore
            || canonical_store_summary.stream_descriptor() != store_descriptor
            || canonical_store_summary.total_byte_length() != store_descriptor.total_byte_length
            || canonical_store_summary.full_object_digest() != store_descriptor.full_object_digest
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        Ok(Self {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            manifest_hash,
            roster_hash,
            setup_proof_context_hash,
            top_count,
            evaluator_key_store_digest: canonical_store_summary.full_object_digest().into_bytes(),
            proof_stream_descriptor: Some(proof_stream_descriptor),
            ordered_runtime_roots: Vec::new().into_boxed_slice(),
            verified_evaluator_key_store_stream: canonical_store_summary,
            store_material: Some(store_material),
        })
    }

    pub(crate) fn from_verified_common_proof_and_material(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        expected_relation_plan_hash: [u8; 64],
        expected_ceremony_context_hash: [u8; 64],
        expected_action_context_hash: [u8; 64],
        verified_evaluator_source_catalog: &VerifiedAcceptedSetupEvaluatorSourceCatalog,
        proof_stream_descriptor: StreamDescriptor,
        verified_evaluator_key_store_material: VerifiedEvaluatorKeyStoreMaterial,
        ordered_runtime_component_trees: Vec<VerifiedStreamedProofTreeTerminal>,
        ordered_verified_auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
    ) -> Result<Self, CommonProofVerifierError> {
        let top_count = verified_proof
            .top_count
            .filter(|top_count| (1..=FOUNDATION_PROFILE.option_count).contains(top_count))
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let selected_plan = selected_evaluator_aggregate_relation_plan()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let selected_variant = selected_plan
            .select_variant(None, Some(top_count))
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if selected_plan
            .canonical_hash()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
            != expected_relation_plan_hash
            || selected_variant
                .canonical_hash()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                != verified_proof.relation_plan_variant_hash
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement = decode_selected_application_statement(
            canonical_application_statement_bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version,
                verified_proof.suite_identifier,
                None,
                Some(top_count),
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let ordered_statement_roots =
            selected_evaluator_aggregate_entry_roots_in_order(&statement, top_count)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let setup_proof_context_hash: [u8; 64] = statement
            .items
            .first()
            .filter(|item| {
                item.item_type() == CanonicalItemType::Hash512 && item.canonical_bytes().len() == 64
            })
            .and_then(|item| item.canonical_bytes().try_into().ok())
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let ordered_components = verified_evaluator_key_store_material.ordered_components();
        if verified_evaluator_key_store_material.top_count() != top_count
            || proof_stream_descriptor.total_byte_length != verified_proof.proof_byte_length
            || ordered_components.len() != ordered_statement_roots.len()
            || ordered_runtime_component_trees.len() != ordered_statement_roots.len()
            || ordered_verified_auxiliary_roots.len() != ordered_statement_roots.len()
            || verified_evaluator_source_catalog.protocol_version()
                != verified_proof.protocol_version
            || verified_evaluator_source_catalog.suite_identifier()
                != verified_proof.suite_identifier
            || verified_evaluator_source_catalog.ceremony_context_hash()
                != expected_ceremony_context_hash
            || verified_evaluator_source_catalog.action_context_hash()
                != expected_action_context_hash
            || verified_evaluator_source_catalog.setup_proof_context_hash()
                != setup_proof_context_hash
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let roster_hash = ordered_runtime_component_trees
            .first()
            .map(VerifiedStreamedProofTreeTerminal::roster_hash)
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        if verified_evaluator_source_catalog.roster_hash() != roster_hash {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let material_ownership = ComponentMaterialOwnershipBinding::from_verified_application(
            verified_proof.suite_identifier,
            expected_action_context_hash,
            verified_proof.application_statement_hash,
        );
        let selected_candidate = EvaluatorCandidateInput::implemented()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let participant_tree_count = u32::from(FOUNDATION_PROFILE.participant_count);
        let trees_per_entry = participant_tree_count
            .checked_add(1)
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let mut ordered_verified_runtime_roots = Vec::new();
        ordered_verified_runtime_roots
            .try_reserve_exact(ordered_statement_roots.len())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        for (entry_ordinal, (((statement_roots, component), runtime_tree), auxiliary_root)) in
            ordered_statement_roots
                .iter()
                .zip(ordered_components)
                .zip(&ordered_runtime_component_trees)
                .zip(ordered_verified_auxiliary_roots)
                .enumerate()
        {
            let entry_ordinal = u32::try_from(entry_ordinal)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let expected_tree_ordinal = entry_ordinal
                .checked_mul(trees_per_entry)
                .and_then(|ordinal| ordinal.checked_add(participant_tree_count))
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            let expected_tree = selected_variant
                .ordered_trees()
                .get(
                    usize::try_from(expected_tree_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?,
                )
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            let (expected_root_source_ordinal, expected_ordered_column_count) = match expected_tree
            {
                RelationTreeDescriptor::BoundPublic {
                    construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                    expected_root_source_ordinal,
                    root_use: BoundTreeRootUse::Output,
                    ordered_column_ordinals,
                } => (*expected_root_source_ordinal, ordered_column_ordinals.len()),
                _ => return Err(CommonProofVerifierError::InvalidApplicationStatement),
            };
            let position = statement_roots.position();
            if statement_roots
                .source_component_roots()
                .iter()
                .enumerate()
                .any(|(roster_ordinal, statement_source_root)| {
                    u16::try_from(roster_ordinal)
                        .ok()
                        .and_then(|roster_position| {
                            verified_evaluator_source_catalog
                                .component_root(roster_position, position)
                        })
                        .as_ref()
                        != Some(statement_source_root)
                })
            {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
            let catalog_level = match position.key_kind() {
                SelectedEvaluatorEntryKind::Relinearization { catalog_level }
                | SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => catalog_level,
            };
            let expected_root_role = match position.key_kind() {
                SelectedEvaluatorEntryKind::Relinearization { .. } => {
                    SetupPublicPolynomialRootRole::RelinearizationRuntime
                }
                SelectedEvaluatorEntryKind::Galois { .. } => {
                    SetupPublicPolynomialRootRole::GaloisRuntime
                }
            };
            let expected_public_polynomial_context_hash = SetupPublicPolynomialContext::new(
                setup_proof_context_hash,
                expected_root_role,
                None,
                None,
                Some(position.schedule_position()),
                None,
            )
            .and_then(|context| context.context_hash())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let expected_column_moduli =
                expected_component_column_moduli(&selected_candidate, component.material())?;
            if statement_roots.entry_ordinal() != entry_ordinal
                || component.position() != position
                || auxiliary_root.position() != position
                || auxiliary_root.auxiliary_component_root()
                    != statement_roots.auxiliary_component_root()
                || runtime_tree.protocol_version() != verified_proof.protocol_version
                || runtime_tree.suite_identifier() != verified_proof.suite_identifier
                || runtime_tree.ceremony_context_hash() != expected_ceremony_context_hash
                || runtime_tree.action_context_hash() != expected_action_context_hash
                || runtime_tree.roster_hash() != roster_hash
                || runtime_tree.application_statement_schema_identifier()
                    != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                || runtime_tree.application_statement_hash()
                    != verified_proof.application_statement_hash
                || runtime_tree.relation_plan_variant_hash()
                    != verified_proof.relation_plan_variant_hash
                || runtime_tree.canonical_application_statement_bytes()
                    != canonical_application_statement_bytes
                || runtime_tree.ordered_tree_ordinal() != expected_tree_ordinal
                || runtime_tree.expected_root_source_ordinal() != expected_root_source_ordinal
                || runtime_tree.setup_proof_context_hash() != setup_proof_context_hash
                || runtime_tree.root_role() != expected_root_role
                || runtime_tree.owner_participant_identity().is_some()
                || runtime_tree.owner_roster_position().is_some()
                || runtime_tree.schedule_position() != Some(position.schedule_position())
                || runtime_tree.public_polynomial_context_hash()
                    != expected_public_polynomial_context_hash
                || runtime_tree.root() != statement_roots.runtime_component_root()
                || runtime_tree.source_polynomial_degree_bound_exclusive()
                    != component.material().topology().polynomial_degree()
                || usize::try_from(runtime_tree.row_width()).ok()
                    != Some(expected_ordered_column_count)
                || runtime_tree.ordered_canonical_residue_moduli()
                    != expected_column_moduli.as_ref()
                || runtime_tree.source_stream_domain()
                    != Some(CanonicalStreamDomain::EvaluatorKeyStore)
                || runtime_tree.source_material_root()
                    != Some(component.material().material_root().into_bytes())
                || runtime_tree.source_stream_descriptor()
                    != Some(component.material().stream_descriptor())
                || !component.material().binds_ownership(material_ownership)
                || !material_topology_matches_selected_catalog_level(
                    &selected_candidate,
                    catalog_level,
                    component.material(),
                )
            {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
            match position.key_kind() {
                SelectedEvaluatorEntryKind::Relinearization { .. } => {
                    let linked_auxiliary = component
                        .linked_relinearization_auxiliary()
                        .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
                    if auxiliary_root.source_material_root()
                        != Some(linked_auxiliary.material().material_root().into_bytes())
                        || auxiliary_root.source_stream_descriptor()
                            != Some(linked_auxiliary.material().stream_descriptor())
                        || !linked_auxiliary
                            .material()
                            .binds_ownership(material_ownership)
                        || !material_topology_matches_selected_catalog_level(
                            &selected_candidate,
                            catalog_level,
                            linked_auxiliary.material(),
                        )
                    {
                        return Err(CommonProofVerifierError::InvalidApplicationStatement);
                    }
                }
                SelectedEvaluatorEntryKind::Galois { .. } => {
                    if component.linked_relinearization_auxiliary().is_some()
                        || auxiliary_root.source_material_root().is_some()
                        || auxiliary_root.source_stream_descriptor().is_some()
                    {
                        return Err(CommonProofVerifierError::InvalidApplicationStatement);
                    }
                }
            }
            ordered_verified_runtime_roots.push(
                VerifiedEvaluatorRuntimeRoot::from_recomputed_public_polynomial_tree(
                    &runtime_tree.tree,
                    top_count,
                )?,
            );
        }
        let verified_evaluator_key_store_stream = verified_evaluator_key_store_material
            .canonical_store_summary()
            .clone();
        Self::from_verified_common_proof_inner(
            verified_proof,
            canonical_application_statement_bytes,
            &verified_evaluator_key_store_stream,
            &ordered_verified_runtime_roots,
            expected_ceremony_context_hash,
            expected_action_context_hash,
            verified_evaluator_source_catalog.manifest_hash(),
            roster_hash,
            Some(proof_stream_descriptor),
            Some(verified_evaluator_key_store_material),
        )
    }

    fn from_verified_common_proof_inner(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        verified_evaluator_key_store_stream: &VerifiedCanonicalStreamSummary,
        ordered_verified_runtime_roots: &[VerifiedEvaluatorRuntimeRoot],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        manifest_hash: [u8; 64],
        roster_hash: [u8; 64],
        proof_stream_descriptor: Option<StreamDescriptor>,
        store_material: Option<VerifiedEvaluatorKeyStoreMaterial>,
    ) -> Result<Self, CommonProofVerifierError> {
        let top_count = verified_proof
            .top_count
            .filter(|top_count| (1..=FOUNDATION_PROFILE.option_count).contains(top_count))
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        if verified_proof.application_statement_schema_identifier
            != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.schedule_position.is_some()
            || verified_evaluator_key_store_stream.stream_domain()
                != CanonicalStreamDomain::EvaluatorKeyStore
            || !verified_proof.binds_application_statement(canonical_application_statement_bytes)
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement = decode_selected_application_statement(
            canonical_application_statement_bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version,
                verified_proof.suite_identifier,
                None,
                Some(top_count),
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let ordered_statement_roots =
            selected_evaluator_aggregate_entry_roots_in_order(&statement, top_count)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if ordered_statement_roots.is_empty()
            || ordered_statement_roots.len() != ordered_verified_runtime_roots.len()
            || ordered_statement_roots
                .iter()
                .zip(ordered_verified_runtime_roots)
                .enumerate()
                .any(
                    |(entry_ordinal, (statement_roots, verified_runtime_root))| {
                        usize::try_from(statement_roots.entry_ordinal()).ok() != Some(entry_ordinal)
                            || statement_roots.position() != verified_runtime_root.position()
                            || statement_roots.runtime_component_root()
                                != verified_runtime_root.runtime_component_root()
                    },
                )
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement_evaluator_key_store_digest: [u8; 64] = statement
            .items
            .get(2)
            .filter(|item| {
                item.item_type() == CanonicalItemType::Hash512 && item.canonical_bytes().len() == 64
            })
            .and_then(|item| item.canonical_bytes().try_into().ok())
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let setup_proof_context_hash: [u8; 64] = statement
            .items
            .first()
            .filter(|item| {
                item.item_type() == CanonicalItemType::Hash512 && item.canonical_bytes().len() == 64
            })
            .and_then(|item| item.canonical_bytes().try_into().ok())
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let verified_evaluator_key_store_digest = verified_evaluator_key_store_stream
            .full_object_digest()
            .into_bytes();
        if statement_evaluator_key_store_digest != verified_evaluator_key_store_digest {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        Ok(Self {
            protocol_version: verified_proof.protocol_version,
            suite_identifier: verified_proof.suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            manifest_hash,
            roster_hash,
            setup_proof_context_hash,
            top_count,
            evaluator_key_store_digest: verified_evaluator_key_store_digest,
            proof_stream_descriptor,
            ordered_runtime_roots: ordered_verified_runtime_roots.into(),
            verified_evaluator_key_store_stream: verified_evaluator_key_store_stream.clone(),
            store_material,
        })
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; 64] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; 64] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; 64] {
        self.action_context_hash
    }

    pub(crate) const fn manifest_hash(&self) -> [u8; 64] {
        self.manifest_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; 64] {
        self.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; 64] {
        self.setup_proof_context_hash
    }

    pub(crate) fn proof_stream_descriptor(
        &self,
    ) -> Result<&StreamDescriptor, CommonProofVerifierError> {
        self.proof_stream_descriptor
            .as_ref()
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)
    }

    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) const fn evaluator_key_store_digest(&self) -> [u8; 64] {
        self.evaluator_key_store_digest
    }

    pub(crate) fn ordered_runtime_roots(&self) -> &[VerifiedEvaluatorRuntimeRoot] {
        &self.ordered_runtime_roots
    }

    pub(crate) const fn verified_evaluator_key_store_stream(
        &self,
    ) -> &VerifiedCanonicalStreamSummary {
        &self.verified_evaluator_key_store_stream
    }

    pub(crate) fn require_production_replay_material(
        &self,
    ) -> Result<(), CommonProofVerifierError> {
        let material = self
            .store_material
            .as_ref()
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let material_summary = material.canonical_store_summary();
        if self.proof_stream_descriptor.is_none()
            || material.top_count() != self.top_count
            || material_summary.stream_domain()
                != self.verified_evaluator_key_store_stream.stream_domain()
            || material_summary.stream_descriptor()
                != self.verified_evaluator_key_store_stream.stream_descriptor()
            || material_summary.total_byte_length()
                != self.verified_evaluator_key_store_stream.total_byte_length()
            || material_summary.full_object_digest()
                != self
                    .verified_evaluator_key_store_stream
                    .full_object_digest()
            || material_summary.state_exact_output_hash()
                != self
                    .verified_evaluator_key_store_stream
                    .state_exact_output_hash()
            || material.store_descriptor().full_object_digest.into_bytes()
                != self.evaluator_key_store_digest
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        Ok(())
    }

    /// Transfers the authenticated canonical store carrier into the replay
    /// resolver. Production construction always installs this material; the
    /// optional representation exists only so narrow verifier unit tests can
    /// exercise rejection logic without allocating the complete selected
    /// store.
    pub(crate) fn into_replay_material(
        self,
    ) -> Result<VerifiedEvaluatorKeyStoreMaterial, CommonProofVerifierError> {
        self.store_material
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)
    }
}
