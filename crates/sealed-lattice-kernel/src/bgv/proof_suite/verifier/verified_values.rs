use super::super::{
    BorrowedVerifiedCommonProofCapability, CommittedMaterialContext, CommittedMaterialRole,
    ComponentMaterialOwnershipBinding, ConsumedVerifiedCommonProofCapability,
    SetupPublicPolynomialContext, VerifiedCommonProofStatementSource,
    VerifiedEvaluatorKeyStoreMaterial, VerifiedKeySwitchComponentMaterial,
    VerifiedRelinearizationSourceMaterial, decode_selected_aggregate_threshold_share_statement,
    decode_selected_application_statement,
    decode_selected_collective_public_key_aggregate_statement,
    decode_selected_galois_key_share_statement, decode_selected_public_key_share_statement,
    decode_selected_relinearization_round_one_aggregate_statement,
    decode_selected_relinearization_round_one_statement, decode_selected_same_secret_statement,
    decode_selected_vss_share_linkage_statement,
    evaluator_source_material::{
        expected_component_column_moduli, material_topology_matches_selected_catalog_level,
    },
    relation_plan::{
        BoundTreeConstructionKind, BoundTreeRootUse, RelationColumnOrigin, RelationColumnValueType,
        RelationPlanVariant, RelationTreeDescriptor,
    },
    selected_committed_material_relation_plan_input, selected_evaluator_aggregate_relation_plan,
};
#[cfg(test)]
use super::CommittedMaterialTree;
use super::{
    CanonicalItemType, CommonProofVerifierError, FOUNDATION_PROFILE, ProofApplicationSlotCeilings,
    SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, SetupPublicPolynomialRootRole, SetupPublicPolynomialTree,
    StatementOwnedProofTreeInput, SuiteModulusReference,
    selected_evaluator_aggregate_entry_roots_in_order, selected_evaluator_entry_positions,
    verified_application_statement_hash,
};
use crate::bgv::evaluator::candidate_evidence::EvaluatorCandidateInput;
use crate::bgv::proof_suite::application_statement::decode_selected_relinearization_round_two_statement;
use crate::bgv::setup::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, VerifiedAcceptedSetupEvaluatorSourceCatalog,
    VerifiedAcceptedSetupParticipantTargetReleaseLease, VerifiedPublicRandomness,
};
use crate::foundation::{CanonicalStreamDomain, StreamDescriptor, VerifiedCanonicalStreamSummary};
#[cfg(test)]
use crate::foundation::{derive_canonical_stream_descriptor, selected_suite_capability_for_tests};

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

pub(crate) struct VerifiedRowCodeWhirProofFacts {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; 64],
    pub(crate) application_statement_schema_identifier: u16,
    pub(crate) application_statement_hash: [u8; 64],
    pub(crate) proof_header_hash: [u8; 64],
    pub(crate) proof_byte_length: u64,
    pub(crate) verified_query_count: u32,
    pub(crate) relation_plan_variant_hash: [u8; 64],
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
}

impl VerifiedCommonProof {
    pub(crate) const fn from_verified_row_code_whir(facts: VerifiedRowCodeWhirProofFacts) -> Self {
        Self {
            protocol_version: facts.protocol_version,
            suite_identifier: facts.suite_identifier,
            application_statement_schema_identifier: facts.application_statement_schema_identifier,
            application_statement_hash: facts.application_statement_hash,
            proof_header_hash: facts.proof_header_hash,
            proof_byte_length: facts.proof_byte_length,
            verified_query_count: facts.verified_query_count,
            relation_plan_variant_hash: facts.relation_plan_variant_hash,
            schedule_position: facts.schedule_position,
            top_count: facts.top_count,
        }
    }

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
    pub(crate) const fn ordered_tree_ordinal(&self) -> u32 {
        self.ordered_tree_ordinal
    }

    pub(crate) const fn expected_root_source_ordinal(&self) -> u32 {
        self.expected_root_source_ordinal
    }

    pub(crate) fn ordered_canonical_residue_moduli(&self) -> &[Option<SuiteModulusReference>] {
        &self.ordered_canonical_residue_moduli
    }

    pub(crate) const fn statement_owned_tree_input(&self) -> &StatementOwnedProofTreeInput {
        &self.tree
    }

    #[cfg(test)]
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

    #[cfg(test)]
    pub(in crate::bgv) fn with_test_expected_root(&self, expected_root: [u8; 64]) -> Self {
        let mut rebound = self.clone();
        match &mut rebound.tree {
            StatementOwnedProofTreeInput::CommittedMaterial {
                expected_root: rebound_root,
                ..
            }
            | StatementOwnedProofTreeInput::SetupPolynomial {
                expected_root: rebound_root,
                ..
            } => *rebound_root = expected_root,
        }
        rebound
    }

    #[cfg(test)]
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

    /// Resolves the complete `0x1217` statement-tree catalog from one exact
    /// package statement, the positively verified participant RKG source, and
    /// the three descriptor-authenticated Galois component trees. Anchor roots
    /// cannot be supplied independently, and every output root is recomputed
    /// from its component bytes.
    pub(crate) fn from_verified_galois_key_share_statement_sources(
        statement_source: &VerifiedCommonProofStatementSource,
        relinearization_source: &VerifiedRelinearizationSourceMaterial,
        ordered_component_trees: &[&SetupPublicPolynomialTree],
    ) -> Result<Vec<Self>, CommonProofVerifierError> {
        let selected_variant = selected_statement_variant(
            statement_source,
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            statement_source
                .application_source_authority()
                .schedule_position(),
        )?;
        let schedule_position = selected_variant
            .schedule_position()
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let statement = decode_selected_galois_key_share_statement(
            statement_source.canonical_application_statement_bytes(),
            SelectedApplicationStatementContext::new(
                relinearization_source.protocol_version(),
                relinearization_source.suite_identifier(),
                Some(schedule_position),
                None,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let anchor_roots = statement.anchor_commitment_roots();
        let contribution_roots = statement.ordered_contribution_roots();
        if relinearization_source.setup_proof_context_hash() != statement.setup_proof_context_hash()
            || relinearization_source.participant_identity() != statement.participant_identity()
            || relinearization_source.roster_position() != statement.roster_position()
            || relinearization_source.anchor_commitment_roots() != anchor_roots
            || statement.batch_schedule_position() != schedule_position
            || ordered_component_trees.len() != contribution_roots.len()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let mut consumed_anchor_sources = vec![false; anchor_roots.len()];
        let mut consumed_component_sources = vec![false; contribution_roots.len()];
        let mut statement_trees = Vec::new();
        for descriptor in selected_variant.ordered_trees() {
            let RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                expected_root_source_ordinal,
                root_use,
                ..
            } = descriptor
            else {
                continue;
            };
            let (expected_root, public_polynomial_context) = match root_use {
                BoundTreeRootUse::Input => {
                    let anchor_ordinal = usize::try_from(*expected_root_source_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
                    let consumed = consumed_anchor_sources
                        .get_mut(anchor_ordinal)
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                    if *consumed {
                        return Err(CommonProofVerifierError::InvalidBoundTree);
                    }
                    *consumed = true;
                    (
                        anchor_roots[anchor_ordinal],
                        verified_lattice_anchor_context(
                            statement.setup_proof_context_hash(),
                            statement.participant_identity(),
                            statement.roster_position(),
                            anchor_ordinal,
                        )?,
                    )
                }
                BoundTreeRootUse::Output => {
                    let root_source_ordinal = usize::try_from(*expected_root_source_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
                    let component_ordinal = root_source_ordinal
                        .checked_sub(anchor_roots.len())
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                    let consumed = consumed_component_sources
                        .get_mut(component_ordinal)
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                    if *consumed {
                        return Err(CommonProofVerifierError::InvalidBoundTree);
                    }
                    *consumed = true;
                    let tree = *ordered_component_trees
                        .get(component_ordinal)
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                    let context = SetupPublicPolynomialContext::new(
                        statement.setup_proof_context_hash(),
                        SetupPublicPolynomialRootRole::GaloisKeyShare,
                        Some(statement.participant_identity()),
                        Some(statement.roster_position()),
                        Some(
                            u32::try_from(component_ordinal)
                                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                        ),
                        None,
                    )
                    .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
                    if tree.root() != contribution_roots[component_ordinal]
                        || tree.public_polynomial_context_hash()
                            != context
                                .context_hash()
                                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?
                    {
                        return Err(CommonProofVerifierError::InvalidBoundTree);
                    }
                    (tree.root(), context)
                }
            };
            statement_trees.push(verified_setup_polynomial_statement_tree(
                selected_variant,
                statement_trees.len(),
                *root_use,
                expected_root,
                public_polynomial_context,
            )?);
        }
        if consumed_anchor_sources.iter().any(|consumed| !consumed)
            || consumed_component_sources.iter().any(|consumed| !consumed)
        {
            return Err(CommonProofVerifierError::InvalidBoundTree);
        }
        require_complete_bound_tree_catalog(selected_variant, statement_trees)
    }

    /// Resolves the complete selected `0x1218` statement-tree batch from the
    /// positive participant-source catalog and the four runtime component
    /// trees recomputed from the exact evaluator-store bytes. The forty
    /// participant roots and context hashes retain their earlier positive
    /// `0x1216`/`0x1217` authority; no detached root list is accepted here.
    pub(crate) fn from_verified_evaluator_aggregate_statement_sources(
        statement_source: &VerifiedCommonProofStatementSource,
        verified_source_catalog: &VerifiedAcceptedSetupEvaluatorSourceCatalog,
        ordered_runtime_component_trees: &[SetupPublicPolynomialTree],
    ) -> Result<Vec<Self>, CommonProofVerifierError> {
        let selected_variant = statement_source
            .selected_relation_variant()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let top_count = selected_variant
            .top_count()
            .filter(|top_count| *top_count == FOUNDATION_PROFILE.option_count)
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let application_source = statement_source.application_source_authority();
        if application_source.application_statement_schema_identifier()
            != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            || selected_variant.schedule_position().is_some()
            || verified_source_catalog.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || verified_source_catalog.suite_identifier()
                != application_source.suite_identifier().into_bytes()
            || verified_source_catalog.ceremony_context_hash()
                != application_source.ceremony_context_hash().into_bytes()
            || verified_source_catalog.action_context_hash()
                != application_source.action_context_hash().into_bytes()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let statement = decode_selected_application_statement(
            statement_source.canonical_application_statement_bytes(),
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                verified_source_catalog.protocol_version(),
                verified_source_catalog.suite_identifier(),
                None,
                Some(top_count),
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let statement_entries =
            selected_evaluator_aggregate_entry_roots_in_order(&statement, top_count)
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if statement_entries.len() != ordered_runtime_component_trees.len()
            || statement_entries.len()
                != selected_evaluator_entry_positions(top_count)
                    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                    .len()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let expected_tree_count = statement_entries
            .len()
            .checked_mul(
                participant_count
                    .checked_add(1)
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?,
            )
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        let mut statement_trees = Vec::new();
        statement_trees
            .try_reserve_exact(expected_tree_count)
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
        for (entry_ordinal, (entry, runtime_tree)) in statement_entries
            .iter()
            .zip(ordered_runtime_component_trees)
            .enumerate()
        {
            let position = entry.position();
            if entry.entry_ordinal()
                != u32::try_from(entry_ordinal)
                    .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?
                || entry.source_component_roots().len() != participant_count
            {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
            for roster_position in 0..FOUNDATION_PROFILE.participant_count {
                let source_root = verified_source_catalog
                    .component_root(roster_position, position)
                    .filter(|root| {
                        entry
                            .source_component_roots()
                            .get(usize::from(roster_position))
                            == Some(root)
                    })
                    .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
                let context_hash = verified_source_catalog
                    .component_public_polynomial_context_hash(roster_position, position)
                    .filter(|hash| *hash != [0_u8; 64])
                    .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
                statement_trees.push(verified_setup_polynomial_statement_tree_from_context_hash(
                    selected_variant,
                    statement_trees.len(),
                    BoundTreeRootUse::Input,
                    source_root,
                    context_hash,
                )?);
            }

            let runtime_role = match position.key_kind() {
                SelectedEvaluatorEntryKind::Relinearization { .. } => {
                    SetupPublicPolynomialRootRole::RelinearizationRuntime
                }
                SelectedEvaluatorEntryKind::Galois { .. } => {
                    SetupPublicPolynomialRootRole::GaloisRuntime
                }
            };
            let runtime_context = SetupPublicPolynomialContext::new(
                verified_source_catalog.setup_proof_context_hash(),
                runtime_role,
                None,
                None,
                Some(position.schedule_position()),
                None,
            )
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
            if runtime_tree.root() != entry.runtime_component_root()
                || runtime_tree.public_polynomial_context_hash()
                    != runtime_context
                        .context_hash()
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?
            {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            statement_trees.push(verified_setup_polynomial_statement_tree(
                selected_variant,
                statement_trees.len(),
                BoundTreeRootUse::Output,
                runtime_tree.root(),
                runtime_context,
            )?);
        }
        require_complete_bound_tree_catalog(selected_variant, statement_trees)
    }

    /// Resolves every statement-owned tree for the closed accepted-setup
    /// family set directly from the family-minted statement capability. The
    /// selected relation supplies all tree coordinates and column moduli;
    /// verified public randomness supplies the roster and setup context.
    pub(in crate::bgv) fn from_verified_accepted_setup_statement_source(
        statement_source: &VerifiedCommonProofStatementSource,
        verified_public_randomness: &VerifiedPublicRandomness,
    ) -> Result<Vec<Self>, CommonProofVerifierError> {
        let schema_identifier = statement_source
            .application_source_authority()
            .application_statement_schema_identifier();
        match schema_identifier {
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => {
                verified_same_secret_statement_trees(
                    statement_source,
                    verified_public_randomness,
                )
            }
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                verified_public_key_share_statement_trees(
                    statement_source,
                    verified_public_randomness,
                )
            }
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                verified_collective_public_key_statement_trees(
                    statement_source,
                    verified_public_randomness,
                )
            }
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => {
                verified_relinearization_round_one_statement_trees(
                    statement_source,
                    verified_public_randomness,
                )
            }
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                verified_relinearization_round_one_aggregate_statement_trees(
                    statement_source,
                    verified_public_randomness,
                )
            }
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => {
                verified_relinearization_round_two_statement_trees(
                    statement_source,
                    verified_public_randomness,
                )
            }
            _ => Err(CommonProofVerifierError::InvalidApplicationStatement),
        }
    }

    /// Resolves the selected VSS and aggregate-threshold committed-material
    /// trees from an exact board-backed statement capability. Material
    /// contexts are recomputed from the verified setup roster; no transported
    /// root, context hash, relation coordinate, or modulus list is accepted.
    pub(in crate::bgv) fn from_verified_committed_material_statement_source(
        statement_source: &VerifiedCommonProofStatementSource,
        verified_public_randomness: &VerifiedPublicRandomness,
    ) -> Result<Vec<Self>, CommonProofVerifierError> {
        let schema_identifier = statement_source
            .application_source_authority()
            .application_statement_schema_identifier();
        match schema_identifier {
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => {
                verified_vss_share_linkage_statement_trees(
                    statement_source,
                    verified_public_randomness,
                )
            }
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                verified_aggregate_threshold_share_statement_trees(
                    statement_source,
                    verified_public_randomness,
                )
            }
            _ => Err(CommonProofVerifierError::InvalidApplicationStatement),
        }
    }

    /// Resolves the six selected target-share commitment trees from the
    /// accepted setup's nonserializable participant lease. Tree roots and
    /// material contexts are derived from that lease and the exact verified
    /// target-release application source; no transported root or modulus list
    /// enters the verifier.
    pub(crate) fn from_verified_target_release_source(
        statement_source: &VerifiedCommonProofStatementSource,
        accepted_share_lease: &VerifiedAcceptedSetupParticipantTargetReleaseLease,
    ) -> Result<Vec<Self>, CommonProofVerifierError> {
        let application_source = statement_source.application_source_authority();
        let selected_variant = selected_statement_variant(
            statement_source,
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
            None,
        )?;
        if application_source.producer_roster_position()
            != Some(accepted_share_lease.roster_position())
            || application_source.producer_sequence().is_some()
            || selected_variant.top_count().is_some()
            || accepted_share_lease.limb_count() != bound_public_tree_count(selected_variant)
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }

        let mut statement_trees = Vec::new();
        statement_trees
            .try_reserve_exact(accepted_share_lease.limb_count())
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
        for limb_ordinal in 0..accepted_share_lease.limb_count() {
            let statement_tree = accepted_share_lease
                .with_limb(
                    limb_ordinal,
                    |data_modulus_index, _modulus, _threshold_share, committed_share| {
                        let material_context = CommittedMaterialContext::new(
                            application_source.suite_identifier().into_bytes(),
                            application_source.ceremony_context_hash().into_bytes(),
                            application_source.action_context_hash().into_bytes(),
                            accepted_share_lease.participant_identity(),
                            CommittedMaterialRole::AggregateThresholdShare,
                            data_modulus_index,
                            accepted_share_lease.roster_position(),
                        );
                        if committed_share.material_context_hash()
                            != material_context
                                .context_hash()
                                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?
                        {
                            return Err(CommonProofVerifierError::InvalidBoundTree);
                        }
                        verified_committed_material_statement_tree(
                            selected_variant,
                            limb_ordinal,
                            BoundTreeRootUse::Input,
                            committed_share.root(),
                            material_context,
                        )
                    },
                )
                .ok_or(CommonProofVerifierError::InvalidBoundTree)??;
            statement_trees.push(statement_tree);
        }
        require_complete_bound_tree_catalog(selected_variant, statement_trees)
    }
}

fn verified_statement_decode_context(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
    expected_schema_identifier: u16,
) -> Result<SelectedApplicationStatementContext, CommonProofVerifierError> {
    let verified_setup_context = verified_public_randomness.context();
    let application_source_authority = statement_source.application_source_authority();
    let application_slot = statement_source
        .proof_application_binding()
        .application_slot();
    let protocol_version = verified_setup_context.protocol_version();
    let suite_identifier = verified_setup_context.suite_identifier().into_bytes();
    let canonical_statement = statement_source.canonical_application_statement_bytes();
    if protocol_version != FOUNDATION_PROFILE.protocol_version
        || verified_public_randomness
            .ordered_participant_identities()
            .len()
            != usize::from(FOUNDATION_PROFILE.participant_count)
        || application_source_authority.application_statement_schema_identifier()
            != expected_schema_identifier
        || application_source_authority.suite_identifier()
            != verified_setup_context.suite_identifier()
        || application_source_authority.ceremony_context_hash()
            != verified_setup_context.ceremony_context_hash()
        || application_source_authority.action_context_hash()
            != verified_setup_context.action_context_hash()
        || application_slot.suite_identifier() != verified_setup_context.suite_identifier()
        || application_slot.ceremony_context_hash()
            != verified_setup_context.ceremony_context_hash()
        || application_slot.action_context_hash() != verified_setup_context.action_context_hash()
        || application_slot.application_statement_schema_identifier() != expected_schema_identifier
        || application_slot.roster_position()
            != application_source_authority.producer_roster_position()
        || application_slot.schedule_position() != application_source_authority.schedule_position()
        || application_slot.producer_sequence() != application_source_authority.producer_sequence()
        || application_slot.producer_sequence().is_some()
        || statement_source.application_statement_hash().into_bytes()
            != verified_application_statement_hash(
                protocol_version,
                suite_identifier,
                expected_schema_identifier,
                canonical_statement,
            )
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    Ok(SelectedApplicationStatementContext::new(
        protocol_version,
        suite_identifier,
        application_slot.schedule_position(),
        None,
    ))
}

fn require_verified_statement_coordinates(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
    participant: Option<([u8; 64], u16)>,
    schedule_position: Option<u32>,
) -> Result<(), CommonProofVerifierError> {
    let application_source_authority = statement_source.application_source_authority();
    let expected_roster_position = participant.map(|(_, roster_position)| roster_position);
    if application_source_authority.producer_roster_position() != expected_roster_position
        || application_source_authority.schedule_position() != schedule_position
        || participant.is_some_and(|(participant_identity, roster_position)| {
            verified_public_randomness
                .ordered_participant_identities()
                .get(usize::from(roster_position))
                .map(|identity| identity.into_bytes())
                != Some(participant_identity)
        })
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    Ok(())
}

fn selected_statement_variant(
    statement_source: &VerifiedCommonProofStatementSource,
    schema_identifier: u16,
    schedule_position: Option<u32>,
) -> Result<&RelationPlanVariant, CommonProofVerifierError> {
    let selected_variant = statement_source
        .selected_relation_variant()
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if statement_source
        .application_source_authority()
        .application_statement_schema_identifier()
        != schema_identifier
        || selected_variant.schedule_position() != schedule_position
        || selected_variant.top_count().is_some()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    Ok(selected_variant)
}

fn verified_bound_tree_layout(
    selected_variant: &RelationPlanVariant,
    bound_tree_ordinal: usize,
    expected_construction_kind: BoundTreeConstructionKind,
    expected_root_use: BoundTreeRootUse,
) -> Result<(u32, u32, Vec<Option<SuiteModulusReference>>), CommonProofVerifierError> {
    let (ordered_tree_ordinal, descriptor) = selected_variant
        .ordered_trees()
        .iter()
        .enumerate()
        .filter(|(_, descriptor)| matches!(descriptor, RelationTreeDescriptor::BoundPublic { .. }))
        .nth(bound_tree_ordinal)
        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    let (expected_root_source_ordinal, ordered_column_ordinals) = match descriptor {
        RelationTreeDescriptor::BoundPublic {
            construction_kind,
            expected_root_source_ordinal,
            root_use,
            ordered_column_ordinals,
        } if *construction_kind == expected_construction_kind && *root_use == expected_root_use => {
            (*expected_root_source_ordinal, ordered_column_ordinals)
        }
        _ => return Err(CommonProofVerifierError::InvalidBoundTree),
    };
    let ordered_canonical_residue_moduli = ordered_column_ordinals
        .iter()
        .map(|column_ordinal| {
            let column = selected_variant
                .ordered_columns()
                .get(
                    usize::try_from(*column_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                )
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            if column.value_type() != RelationColumnValueType::BaseField
                || !matches!(
                    column.origin(),
                    RelationColumnOrigin::BoundTree {
                        expected_root_source_ordinal: column_root_source_ordinal,
                    } if *column_root_source_ordinal == expected_root_source_ordinal
                )
            {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            Ok(column.canonical_residue_modulus())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ordered_canonical_residue_moduli.is_empty()
        || (expected_construction_kind == BoundTreeConstructionKind::CommittedMaterial
            && ordered_canonical_residue_moduli.iter().any(Option::is_some))
        || (expected_construction_kind == BoundTreeConstructionKind::SetupPolynomial
            && ordered_canonical_residue_moduli.iter().any(Option::is_none))
    {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    Ok((
        u32::try_from(ordered_tree_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
        expected_root_source_ordinal,
        ordered_canonical_residue_moduli,
    ))
}

fn verified_committed_material_statement_tree(
    selected_variant: &RelationPlanVariant,
    ordered_tree_ordinal: usize,
    expected_root_use: BoundTreeRootUse,
    expected_root: [u8; 64],
    material_context: CommittedMaterialContext,
) -> Result<VerifiedStatementOwnedTree, CommonProofVerifierError> {
    let (ordered_tree_ordinal, expected_root_source_ordinal, ordered_canonical_residue_moduli) =
        verified_bound_tree_layout(
            selected_variant,
            ordered_tree_ordinal,
            BoundTreeConstructionKind::CommittedMaterial,
            expected_root_use,
        )?;
    Ok(VerifiedStatementOwnedTree {
        ordered_tree_ordinal,
        expected_root_source_ordinal,
        tree: StatementOwnedProofTreeInput::CommittedMaterial {
            material_context_hash: material_context
                .context_hash()
                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
            expected_root,
        },
        ordered_canonical_residue_moduli,
    })
}

fn verified_setup_polynomial_statement_tree(
    selected_variant: &RelationPlanVariant,
    ordered_tree_ordinal: usize,
    expected_root_use: BoundTreeRootUse,
    expected_root: [u8; 64],
    public_polynomial_context: SetupPublicPolynomialContext,
) -> Result<VerifiedStatementOwnedTree, CommonProofVerifierError> {
    let (ordered_tree_ordinal, expected_root_source_ordinal, ordered_canonical_residue_moduli) =
        verified_bound_tree_layout(
            selected_variant,
            ordered_tree_ordinal,
            BoundTreeConstructionKind::SetupPolynomial,
            expected_root_use,
        )?;
    let row_width = u32::try_from(ordered_canonical_residue_moduli.len())
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    Ok(VerifiedStatementOwnedTree {
        ordered_tree_ordinal,
        expected_root_source_ordinal,
        tree: StatementOwnedProofTreeInput::SetupPolynomial {
            public_polynomial_context_hash: public_polynomial_context
                .context_hash()
                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
            row_width,
            expected_root,
        },
        ordered_canonical_residue_moduli,
    })
}

fn verified_setup_polynomial_statement_tree_from_context_hash(
    selected_variant: &RelationPlanVariant,
    ordered_tree_ordinal: usize,
    expected_root_use: BoundTreeRootUse,
    expected_root: [u8; 64],
    public_polynomial_context_hash: [u8; 64],
) -> Result<VerifiedStatementOwnedTree, CommonProofVerifierError> {
    let (ordered_tree_ordinal, expected_root_source_ordinal, ordered_canonical_residue_moduli) =
        verified_bound_tree_layout(
            selected_variant,
            ordered_tree_ordinal,
            BoundTreeConstructionKind::SetupPolynomial,
            expected_root_use,
        )?;
    Ok(VerifiedStatementOwnedTree {
        ordered_tree_ordinal,
        expected_root_source_ordinal,
        tree: StatementOwnedProofTreeInput::SetupPolynomial {
            public_polynomial_context_hash,
            row_width: u32::try_from(ordered_canonical_residue_moduli.len())
                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
            expected_root,
        },
        ordered_canonical_residue_moduli,
    })
}

fn require_complete_bound_tree_catalog(
    selected_variant: &RelationPlanVariant,
    statement_trees: Vec<VerifiedStatementOwnedTree>,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    if statement_trees.len() != bound_public_tree_count(selected_variant) {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    Ok(statement_trees)
}

fn bound_public_tree_count(selected_variant: &RelationPlanVariant) -> usize {
    selected_variant
        .ordered_trees()
        .iter()
        .filter(|descriptor| matches!(descriptor, RelationTreeDescriptor::BoundPublic { .. }))
        .count()
}

fn verified_lattice_anchor_context(
    setup_proof_context_hash: [u8; 64],
    participant_identity: [u8; 64],
    roster_position: u16,
    anchor_ordinal: usize,
) -> Result<SetupPublicPolynomialContext, CommonProofVerifierError> {
    let commitment_data_prime_index = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .get(anchor_ordinal)
        .copied()
        .and_then(|index| u16::try_from(index).ok())
        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    SetupPublicPolynomialContext::lattice_anchor(
        setup_proof_context_hash,
        participant_identity,
        roster_position,
        commitment_data_prime_index,
    )
    .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn verified_owned_setup_context(
    setup_proof_context_hash: [u8; 64],
    root_role: SetupPublicPolynomialRootRole,
    participant_identity: [u8; 64],
    roster_position: u16,
    schedule_position: Option<u32>,
) -> Result<SetupPublicPolynomialContext, CommonProofVerifierError> {
    SetupPublicPolynomialContext::new(
        setup_proof_context_hash,
        root_role,
        Some(participant_identity),
        Some(roster_position),
        schedule_position,
        None,
    )
    .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn verified_unowned_setup_context(
    setup_proof_context_hash: [u8; 64],
    root_role: SetupPublicPolynomialRootRole,
    schedule_position: Option<u32>,
) -> Result<SetupPublicPolynomialContext, CommonProofVerifierError> {
    SetupPublicPolynomialContext::new(
        setup_proof_context_hash,
        root_role,
        None,
        None,
        schedule_position,
        None,
    )
    .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn verified_same_secret_statement_trees(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    let schema_identifier = ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
    let decode_context = verified_statement_decode_context(
        statement_source,
        verified_public_randomness,
        schema_identifier,
    )?;
    let statement = decode_selected_same_secret_statement(
        statement_source.canonical_application_statement_bytes(),
        decode_context,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    require_verified_statement_coordinates(
        statement_source,
        verified_public_randomness,
        Some((
            statement.participant_identity(),
            statement.roster_position(),
        )),
        None,
    )?;
    if statement.setup_proof_context_hash()
        != verified_public_randomness
            .setup_proof_context_hash()
            .into_bytes()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let selected_variant = selected_statement_variant(statement_source, schema_identifier, None)?;
    let committed_material_input = selected_committed_material_relation_plan_input()
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if statement.ordered_degree_zero_commitment_roots().len()
        != committed_material_input.sharing_data_modulus_indices.len()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let verified_setup_context = verified_public_randomness.context();
    let mut statement_trees = Vec::new();
    statement_trees
        .try_reserve_exact(bound_public_tree_count(selected_variant))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    for (sharing_limb_index, expected_root) in committed_material_input
        .sharing_data_modulus_indices
        .iter()
        .copied()
        .zip(
            statement
                .ordered_degree_zero_commitment_roots()
                .iter()
                .copied(),
        )
    {
        statement_trees.push(verified_committed_material_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Input,
            expected_root,
            CommittedMaterialContext::new(
                verified_setup_context.suite_identifier().into_bytes(),
                verified_setup_context.ceremony_context_hash().into_bytes(),
                verified_setup_context.action_context_hash().into_bytes(),
                statement.participant_identity(),
                CommittedMaterialRole::Coefficient,
                sharing_limb_index,
                0,
            ),
        )?);
    }
    for (anchor_ordinal, expected_root) in
        statement.anchor_commitment_roots().into_iter().enumerate()
    {
        statement_trees.push(verified_setup_polynomial_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Output,
            expected_root,
            verified_lattice_anchor_context(
                statement.setup_proof_context_hash(),
                statement.participant_identity(),
                statement.roster_position(),
                anchor_ordinal,
            )?,
        )?);
    }
    require_complete_bound_tree_catalog(selected_variant, statement_trees)
}

fn verified_public_key_share_statement_trees(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
    let decode_context = verified_statement_decode_context(
        statement_source,
        verified_public_randomness,
        schema_identifier,
    )?;
    let statement = decode_selected_public_key_share_statement(
        statement_source.canonical_application_statement_bytes(),
        decode_context,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    require_verified_statement_coordinates(
        statement_source,
        verified_public_randomness,
        Some((
            statement.participant_identity(),
            statement.roster_position(),
        )),
        None,
    )?;
    if statement.setup_proof_context_hash()
        != verified_public_randomness
            .setup_proof_context_hash()
            .into_bytes()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let selected_variant = selected_statement_variant(statement_source, schema_identifier, None)?;
    let mut statement_trees = Vec::new();
    statement_trees.push(verified_setup_polynomial_statement_tree(
        selected_variant,
        0,
        BoundTreeRootUse::Output,
        statement.public_key_share_root(),
        SetupPublicPolynomialContext::public_key_share(
            statement.setup_proof_context_hash(),
            statement.participant_identity(),
            statement.roster_position(),
        )
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
    )?);
    for (anchor_ordinal, expected_root) in
        statement.anchor_commitment_roots().into_iter().enumerate()
    {
        statement_trees.push(verified_setup_polynomial_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Input,
            expected_root,
            verified_lattice_anchor_context(
                statement.setup_proof_context_hash(),
                statement.participant_identity(),
                statement.roster_position(),
                anchor_ordinal,
            )?,
        )?);
    }
    require_complete_bound_tree_catalog(selected_variant, statement_trees)
}

fn verified_collective_public_key_statement_trees(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let decode_context = verified_statement_decode_context(
        statement_source,
        verified_public_randomness,
        schema_identifier,
    )?;
    let statement = decode_selected_collective_public_key_aggregate_statement(
        statement_source.canonical_application_statement_bytes(),
        decode_context,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    require_verified_statement_coordinates(
        statement_source,
        verified_public_randomness,
        None,
        None,
    )?;
    if statement.setup_proof_context_hash()
        != verified_public_randomness
            .setup_proof_context_hash()
            .into_bytes()
        || statement.ordered_public_key_share_roots().len()
            != verified_public_randomness
                .ordered_participant_identities()
                .len()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let selected_variant = selected_statement_variant(statement_source, schema_identifier, None)?;
    let mut statement_trees = Vec::new();
    for (roster_ordinal, (participant_identity, expected_root)) in verified_public_randomness
        .ordered_participant_identities()
        .iter()
        .zip(statement.ordered_public_key_share_roots())
        .enumerate()
    {
        let roster_position = u16::try_from(roster_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
        statement_trees.push(verified_setup_polynomial_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Input,
            *expected_root,
            SetupPublicPolynomialContext::public_key_share(
                statement.setup_proof_context_hash(),
                participant_identity.into_bytes(),
                roster_position,
            )
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
        )?);
    }
    statement_trees.push(verified_setup_polynomial_statement_tree(
        selected_variant,
        statement_trees.len(),
        BoundTreeRootUse::Output,
        statement.collective_public_key_root(),
        SetupPublicPolynomialContext::collective_public_key(statement.setup_proof_context_hash())
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
    )?);
    require_complete_bound_tree_catalog(selected_variant, statement_trees)
}

fn verified_relinearization_round_one_statement_trees(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER;
    let decode_context = verified_statement_decode_context(
        statement_source,
        verified_public_randomness,
        schema_identifier,
    )?;
    let statement = decode_selected_relinearization_round_one_statement(
        statement_source.canonical_application_statement_bytes(),
        decode_context,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let schedule_position = statement.schedule_position();
    require_verified_statement_coordinates(
        statement_source,
        verified_public_randomness,
        Some((
            statement.participant_identity(),
            statement.roster_position(),
        )),
        Some(schedule_position),
    )?;
    if statement.setup_proof_context_hash()
        != verified_public_randomness
            .setup_proof_context_hash()
            .into_bytes()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let selected_variant =
        selected_statement_variant(statement_source, schema_identifier, Some(schedule_position))?;
    let mut statement_trees = Vec::new();
    for (root_role, expected_root) in [
        (
            SetupPublicPolynomialRootRole::RelinearizationRoundOneLeft,
            statement.round_one_left_root(),
        ),
        (
            SetupPublicPolynomialRootRole::RelinearizationRoundOneRight,
            statement.round_one_right_root(),
        ),
    ] {
        statement_trees.push(verified_setup_polynomial_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Output,
            expected_root,
            verified_owned_setup_context(
                statement.setup_proof_context_hash(),
                root_role,
                statement.participant_identity(),
                statement.roster_position(),
                Some(schedule_position),
            )?,
        )?);
    }
    for (anchor_ordinal, expected_root) in
        statement.anchor_commitment_roots().into_iter().enumerate()
    {
        statement_trees.push(verified_setup_polynomial_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Input,
            expected_root,
            verified_lattice_anchor_context(
                statement.setup_proof_context_hash(),
                statement.participant_identity(),
                statement.roster_position(),
                anchor_ordinal,
            )?,
        )?);
    }
    require_complete_bound_tree_catalog(selected_variant, statement_trees)
}

fn verified_relinearization_round_one_aggregate_statement_trees(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let decode_context = verified_statement_decode_context(
        statement_source,
        verified_public_randomness,
        schema_identifier,
    )?;
    let statement = decode_selected_relinearization_round_one_aggregate_statement(
        statement_source.canonical_application_statement_bytes(),
        decode_context,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let schedule_position = statement.schedule_position();
    require_verified_statement_coordinates(
        statement_source,
        verified_public_randomness,
        None,
        Some(schedule_position),
    )?;
    if statement.setup_proof_context_hash()
        != verified_public_randomness
            .setup_proof_context_hash()
            .into_bytes()
        || statement.ordered_source_root_pairs().len()
            != verified_public_randomness
                .ordered_participant_identities()
                .len()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let selected_variant =
        selected_statement_variant(statement_source, schema_identifier, Some(schedule_position))?;
    let mut statement_trees = Vec::new();
    for (pair_ordinal, aggregate_root_role, aggregate_root) in [
        (
            0_usize,
            SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneLeft,
            statement.aggregate_left_root(),
        ),
        (
            1_usize,
            SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneRight,
            statement.aggregate_right_root(),
        ),
    ] {
        let source_root_role = if pair_ordinal == 0 {
            SetupPublicPolynomialRootRole::RelinearizationRoundOneLeft
        } else {
            SetupPublicPolynomialRootRole::RelinearizationRoundOneRight
        };
        for (roster_ordinal, (participant_identity, root_pair)) in verified_public_randomness
            .ordered_participant_identities()
            .iter()
            .zip(statement.ordered_source_root_pairs())
            .enumerate()
        {
            let roster_position = u16::try_from(roster_ordinal)
                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
            statement_trees.push(verified_setup_polynomial_statement_tree(
                selected_variant,
                statement_trees.len(),
                BoundTreeRootUse::Input,
                root_pair[pair_ordinal],
                verified_owned_setup_context(
                    statement.setup_proof_context_hash(),
                    source_root_role,
                    participant_identity.into_bytes(),
                    roster_position,
                    Some(schedule_position),
                )?,
            )?);
        }
        statement_trees.push(verified_setup_polynomial_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Output,
            aggregate_root,
            verified_unowned_setup_context(
                statement.setup_proof_context_hash(),
                aggregate_root_role,
                Some(schedule_position),
            )?,
        )?);
    }
    require_complete_bound_tree_catalog(selected_variant, statement_trees)
}

fn verified_relinearization_round_two_statement_trees(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER;
    let decode_context = verified_statement_decode_context(
        statement_source,
        verified_public_randomness,
        schema_identifier,
    )?;
    let statement = decode_selected_relinearization_round_two_statement(
        statement_source.canonical_application_statement_bytes(),
        decode_context,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let schedule_position = statement.schedule_position();
    require_verified_statement_coordinates(
        statement_source,
        verified_public_randomness,
        Some((
            statement.participant_identity(),
            statement.roster_position(),
        )),
        Some(schedule_position),
    )?;
    if statement.setup_proof_context_hash()
        != verified_public_randomness
            .setup_proof_context_hash()
            .into_bytes()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let selected_variant =
        selected_statement_variant(statement_source, schema_identifier, Some(schedule_position))?;
    let mut statement_trees = Vec::new();
    for (root_role, participant_owned, expected_root) in [
        (
            SetupPublicPolynomialRootRole::RelinearizationRoundOneLeft,
            true,
            statement.round_one_left_root(),
        ),
        (
            SetupPublicPolynomialRootRole::RelinearizationRoundOneRight,
            true,
            statement.round_one_right_root(),
        ),
        (
            SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneLeft,
            false,
            statement.aggregate_round_one_left_root(),
        ),
        (
            SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneRight,
            false,
            statement.aggregate_round_one_right_root(),
        ),
    ] {
        let public_polynomial_context = if participant_owned {
            verified_owned_setup_context(
                statement.setup_proof_context_hash(),
                root_role,
                statement.participant_identity(),
                statement.roster_position(),
                Some(schedule_position),
            )?
        } else {
            verified_unowned_setup_context(
                statement.setup_proof_context_hash(),
                root_role,
                Some(schedule_position),
            )?
        };
        statement_trees.push(verified_setup_polynomial_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Input,
            expected_root,
            public_polynomial_context,
        )?);
    }
    statement_trees.push(verified_setup_polynomial_statement_tree(
        selected_variant,
        statement_trees.len(),
        BoundTreeRootUse::Output,
        statement.contribution_root(),
        verified_owned_setup_context(
            statement.setup_proof_context_hash(),
            SetupPublicPolynomialRootRole::RelinearizationRoundTwo,
            statement.participant_identity(),
            statement.roster_position(),
            Some(schedule_position),
        )?,
    )?);
    for (anchor_ordinal, expected_root) in
        statement.anchor_commitment_roots().into_iter().enumerate()
    {
        statement_trees.push(verified_setup_polynomial_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Input,
            expected_root,
            verified_lattice_anchor_context(
                statement.setup_proof_context_hash(),
                statement.participant_identity(),
                statement.roster_position(),
                anchor_ordinal,
            )?,
        )?);
    }
    require_complete_bound_tree_catalog(selected_variant, statement_trees)
}

fn verified_vss_share_linkage_statement_trees(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
    let decode_context = verified_statement_decode_context(
        statement_source,
        verified_public_randomness,
        schema_identifier,
    )?;
    let statement = decode_selected_vss_share_linkage_statement(
        statement_source.canonical_application_statement_bytes(),
        decode_context,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    require_verified_statement_coordinates(
        statement_source,
        verified_public_randomness,
        Some((
            statement.participant_identity(),
            statement.roster_position(),
        )),
        None,
    )?;
    let verified_setup_context = verified_public_randomness.context();
    if statement.protocol_version() != verified_setup_context.protocol_version()
        || statement.suite_identifier() != verified_setup_context.suite_identifier().into_bytes()
        || statement.ceremony_context_hash()
            != verified_setup_context.ceremony_context_hash().into_bytes()
        || statement.action_context_hash()
            != verified_setup_context.action_context_hash().into_bytes()
        || statement.roster_hash() != verified_setup_context.roster_hash().into_bytes()
        || statement.public_setup_seed()
            != verified_public_randomness.public_setup_seed().into_bytes()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let selected_variant = selected_statement_variant(statement_source, schema_identifier, None)?;
    let committed_material_input = selected_committed_material_relation_plan_input()
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let sharing_limb_count = committed_material_input.sharing_data_modulus_indices.len();
    let threshold = usize::from(committed_material_input.threshold);
    let participant_count = usize::from(committed_material_input.participant_count);
    let expected_coefficient_root_count = sharing_limb_count
        .checked_mul(threshold)
        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    let expected_recipient_root_count = sharing_limb_count
        .checked_mul(participant_count)
        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    if participant_count
        != verified_public_randomness
            .ordered_participant_identities()
            .len()
        || statement.ordered_coefficient_material_roots().len() != expected_coefficient_root_count
        || statement.ordered_recipient_share_material_roots().len() != expected_recipient_root_count
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let mut statement_trees = Vec::new();
    statement_trees
        .try_reserve_exact(bound_public_tree_count(selected_variant))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    for (sharing_limb_ordinal, sharing_limb_index) in committed_material_input
        .sharing_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        for coefficient_ordinal in 0..threshold {
            let root_ordinal = sharing_limb_ordinal
                .checked_mul(threshold)
                .and_then(|offset| offset.checked_add(coefficient_ordinal))
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            let expected_root = *statement
                .ordered_coefficient_material_roots()
                .get(root_ordinal)
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            statement_trees.push(verified_committed_material_statement_tree(
                selected_variant,
                statement_trees.len(),
                BoundTreeRootUse::Output,
                expected_root,
                CommittedMaterialContext::new(
                    verified_setup_context.suite_identifier().into_bytes(),
                    verified_setup_context.ceremony_context_hash().into_bytes(),
                    verified_setup_context.action_context_hash().into_bytes(),
                    statement.participant_identity(),
                    CommittedMaterialRole::Coefficient,
                    sharing_limb_index,
                    u16::try_from(coefficient_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                ),
            )?);
        }
        for recipient_ordinal in 0..participant_count {
            let root_ordinal = sharing_limb_ordinal
                .checked_mul(participant_count)
                .and_then(|offset| offset.checked_add(recipient_ordinal))
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            let expected_root = *statement
                .ordered_recipient_share_material_roots()
                .get(root_ordinal)
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            statement_trees.push(verified_committed_material_statement_tree(
                selected_variant,
                statement_trees.len(),
                BoundTreeRootUse::Output,
                expected_root,
                CommittedMaterialContext::new(
                    verified_setup_context.suite_identifier().into_bytes(),
                    verified_setup_context.ceremony_context_hash().into_bytes(),
                    verified_setup_context.action_context_hash().into_bytes(),
                    statement.participant_identity(),
                    CommittedMaterialRole::RecipientShare,
                    sharing_limb_index,
                    u16::try_from(recipient_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                ),
            )?);
        }
    }
    require_complete_bound_tree_catalog(selected_variant, statement_trees)
}

fn verified_aggregate_threshold_share_statement_trees(
    statement_source: &VerifiedCommonProofStatementSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<Vec<VerifiedStatementOwnedTree>, CommonProofVerifierError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
    let decode_context = verified_statement_decode_context(
        statement_source,
        verified_public_randomness,
        schema_identifier,
    )?;
    let statement = decode_selected_aggregate_threshold_share_statement(
        statement_source.canonical_application_statement_bytes(),
        decode_context,
    )
    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    require_verified_statement_coordinates(
        statement_source,
        verified_public_randomness,
        Some((
            statement.participant_identity(),
            statement.roster_position(),
        )),
        None,
    )?;
    let verified_setup_context = verified_public_randomness.context();
    if statement.protocol_version() != verified_setup_context.protocol_version()
        || statement.suite_identifier() != verified_setup_context.suite_identifier().into_bytes()
        || statement.ceremony_context_hash()
            != verified_setup_context.ceremony_context_hash().into_bytes()
        || statement.action_context_hash()
            != verified_setup_context.action_context_hash().into_bytes()
        || statement.roster_hash() != verified_setup_context.roster_hash().into_bytes()
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let selected_variant = selected_statement_variant(statement_source, schema_identifier, None)?;
    let committed_material_input = selected_committed_material_relation_plan_input()
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    let sharing_limb_count = committed_material_input.sharing_data_modulus_indices.len();
    let participant_count = usize::from(committed_material_input.participant_count);
    let expected_source_root_count = sharing_limb_count
        .checked_mul(participant_count)
        .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    if participant_count
        != verified_public_randomness
            .ordered_participant_identities()
            .len()
        || statement.ordered_source_share_roots().len() != expected_source_root_count
        || statement.ordered_aggregate_threshold_roots().len() != sharing_limb_count
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let mut statement_trees = Vec::new();
    statement_trees
        .try_reserve_exact(bound_public_tree_count(selected_variant))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    for (sharing_limb_ordinal, sharing_limb_index) in committed_material_input
        .sharing_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        for dealer_ordinal in 0..participant_count {
            let source_root_ordinal = dealer_ordinal
                .checked_mul(sharing_limb_count)
                .and_then(|offset| offset.checked_add(sharing_limb_ordinal))
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            let dealer_identity = verified_public_randomness
                .ordered_participant_identities()
                .get(dealer_ordinal)
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?
                .into_bytes();
            let expected_root = *statement
                .ordered_source_share_roots()
                .get(source_root_ordinal)
                .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
            statement_trees.push(verified_committed_material_statement_tree(
                selected_variant,
                statement_trees.len(),
                BoundTreeRootUse::Input,
                expected_root,
                CommittedMaterialContext::new(
                    verified_setup_context.suite_identifier().into_bytes(),
                    verified_setup_context.ceremony_context_hash().into_bytes(),
                    verified_setup_context.action_context_hash().into_bytes(),
                    dealer_identity,
                    CommittedMaterialRole::RecipientShare,
                    sharing_limb_index,
                    statement.roster_position(),
                ),
            )?);
        }
        let expected_root = *statement
            .ordered_aggregate_threshold_roots()
            .get(sharing_limb_ordinal)
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        statement_trees.push(verified_committed_material_statement_tree(
            selected_variant,
            statement_trees.len(),
            BoundTreeRootUse::Output,
            expected_root,
            CommittedMaterialContext::new(
                verified_setup_context.suite_identifier().into_bytes(),
                verified_setup_context.ceremony_context_hash().into_bytes(),
                verified_setup_context.action_context_hash().into_bytes(),
                statement.participant_identity(),
                CommittedMaterialRole::AggregateThresholdShare,
                sharing_limb_index,
                statement.roster_position(),
            ),
        )?);
    }
    require_complete_bound_tree_catalog(selected_variant, statement_trees)
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
            .authenticate_setup_tree_trace_columns(tree.ordered_trace_rows())
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

    pub(crate) fn root(&self) -> [u8; 64] {
        self.tree.root()
    }

    pub(crate) fn statement_owned_tree(&self) -> VerifiedStatementOwnedTree {
        VerifiedStatementOwnedTree::from_setup_public_polynomial_tree(
            self.ordered_tree_ordinal,
            self.expected_root_source_ordinal,
            &self.tree,
            self.ordered_canonical_residue_moduli.to_vec(),
        )
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
    /// Retains the recomputed RKG A-component authority while constructing the
    /// same-worker evaluator proof. This is generation custody only: accepted
    /// package verification still derives its terminal from the positively
    /// verified aggregate proof and never accepts this local source directly.
    pub(crate) fn from_generated_relinearization_aggregate_source(
        source: &crate::bgv::setup::SetupGeneratedRelinearizationAggregateSourceAuthority,
    ) -> Result<Self, CommonProofVerifierError> {
        let position = source.evaluator_position();
        let catalog_level = match position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { catalog_level } => catalog_level,
            SelectedEvaluatorEntryKind::Galois { .. } => {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
        };
        let selected_candidate = EvaluatorCandidateInput::implemented()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let auxiliary_component = &source.components()[1];
        if !material_topology_matches_selected_catalog_level(
            &selected_candidate,
            catalog_level,
            auxiliary_component.material(),
        ) {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        Ok(Self {
            position,
            auxiliary_component_root: auxiliary_component.contribution_root(),
            source_material_root: Some(auxiliary_component.material_root().into_bytes()),
            source_stream_descriptor: Some(auxiliary_component.stream_descriptor().clone()),
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

    /// Mints the Galois A linkage only from a verifier-recomputed role-11
    /// public-polynomial tree at the exact selected catalog coordinate.
    #[cfg(test)]
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

    /// Mints the same Galois A linkage from the setup-domain incremental root
    /// builder. Both the context hash and root are outputs of that builder;
    /// callers cannot replace the role or schedule with detached metadata.
    pub(crate) fn from_recomputed_galois_common_public_polynomial_root(
        schedule_position: u32,
        galois_element: usize,
        catalog_level: usize,
        context: &SetupPublicPolynomialContext,
        recomputed_context_hash: [u8; 64],
        recomputed_root: [u8; 64],
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
        if context.root_role() != SetupPublicPolynomialRootRole::GaloisCommon
            || context.schedule_position() != Some(schedule_position)
            || context
                .context_hash()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                != recomputed_context_hash
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        Ok(Self {
            position,
            auxiliary_component_root: recomputed_root,
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

/// Borrowed positive validation for the evaluator-store terminal. The five
/// large recomputed trees and the authenticated store material remain in the
/// exact-family session until the same generic proof capability is consumed.
/// Terminal rejection can therefore restore that session without recreating
/// authority from hashes or replaying caller-controlled bytes.
pub(crate) struct VerifiedEvaluatorKeyStorePreflight {
    validated_store: VerifiedEvaluatorKeyStore,
    canonical_application_statement_bytes: Box<[u8]>,
    application_statement_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    ordered_auxiliary_roots: Box<[VerifiedEvaluatorAuxiliaryRoot]>,
    ordered_runtime_tree_preflights: Box<[VerifiedStreamedProofTreeTerminalPreflight]>,
}

impl VerifiedEvaluatorKeyStorePreflight {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_borrowed_common_proof(
        verified_proof: BorrowedVerifiedCommonProofCapability<'_>,
        canonical_application_statement_bytes: &[u8],
        verified_evaluator_source_catalog: &VerifiedAcceptedSetupEvaluatorSourceCatalog,
        verified_evaluator_key_store_material: &VerifiedEvaluatorKeyStoreMaterial,
        statement_trees: &[VerifiedStatementOwnedTree],
        ordered_runtime_component_trees: &[SetupPublicPolynomialTree],
        ordered_verified_auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
    ) -> Result<Self, CommonProofVerifierError> {
        let top_count = verified_proof
            .top_count()
            .filter(|top_count| *top_count == FOUNDATION_PROFILE.option_count)
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let selected_plan = selected_evaluator_aggregate_relation_plan()
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let selected_variant = selected_plan
            .select_variant(None, Some(top_count))
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
        let statement = decode_selected_application_statement(
            canonical_application_statement_bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version(),
                verified_proof.suite_identifier(),
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
        if verified_proof.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || verified_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            || verified_proof.schedule_position().is_some()
            || verified_proof.proof_stream_domain()
                != CanonicalStreamDomain::EvaluatorKeyAggregateProof
            || verified_evaluator_key_store_material.top_count() != top_count
            || verified_proof.proof_stream_descriptor().total_byte_length
                != verified_proof.proof_byte_length()
            || ordered_components.len() != ordered_statement_roots.len()
            || ordered_runtime_component_trees.len() != ordered_statement_roots.len()
            || ordered_verified_auxiliary_roots.len() != ordered_statement_roots.len()
            || verified_evaluator_source_catalog.protocol_version()
                != verified_proof.protocol_version()
            || verified_evaluator_source_catalog.suite_identifier()
                != verified_proof.suite_identifier()
            || verified_evaluator_source_catalog.ceremony_context_hash()
                != verified_proof.ceremony_context_hash()
            || verified_evaluator_source_catalog.action_context_hash()
                != verified_proof.action_context_hash()
            || verified_evaluator_source_catalog.setup_proof_context_hash()
                != setup_proof_context_hash
            || verified_proof.application_statement_hash()
                != verified_application_statement_hash(
                    verified_proof.protocol_version(),
                    verified_proof.suite_identifier(),
                    ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                    canonical_application_statement_bytes,
                )
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let roster_hash = verified_evaluator_source_catalog.roster_hash();
        let material_ownership = ComponentMaterialOwnershipBinding::from_verified_application(
            verified_proof.suite_identifier(),
            verified_proof.action_context_hash(),
            verified_proof.application_statement_hash(),
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
        let mut ordered_runtime_tree_preflights = Vec::new();
        ordered_runtime_tree_preflights
            .try_reserve_exact(ordered_statement_roots.len())
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        for (entry_ordinal, (((statement_roots, component), runtime_tree), auxiliary_root)) in
            ordered_statement_roots
                .iter()
                .zip(ordered_components)
                .zip(ordered_runtime_component_trees)
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
            let context = SetupPublicPolynomialContext::new(
                setup_proof_context_hash,
                expected_root_role,
                None,
                None,
                Some(position.schedule_position()),
                None,
            )
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let expected_public_polynomial_context_hash = context
                .context_hash()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
            let expected_column_moduli =
                expected_component_column_moduli(&selected_candidate, component.material())?;
            let mut matching_statement_trees = statement_trees.iter().filter(|tree| {
                tree.ordered_tree_ordinal() == expected_tree_ordinal
                    && tree.expected_root_source_ordinal() == expected_root_source_ordinal
            });
            let statement_tree = matching_statement_trees
                .next()
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            if matching_statement_trees.next().is_some()
                || statement_roots.entry_ordinal() != entry_ordinal
                || component.position() != position
                || auxiliary_root.position() != position
                || auxiliary_root.auxiliary_component_root()
                    != statement_roots.auxiliary_component_root()
                || statement_tree.expected_root() != statement_roots.runtime_component_root()
                || statement_tree.ordered_canonical_residue_moduli()
                    != expected_column_moduli.as_ref()
                || runtime_tree.public_polynomial_context_hash()
                    != expected_public_polynomial_context_hash
                || runtime_tree.root_role() != expected_root_role
                || runtime_tree.schedule_position() != Some(position.schedule_position())
                || runtime_tree.root() != statement_roots.runtime_component_root()
                || runtime_tree.source_polynomial_degree_bound_exclusive()
                    != component
                        .material()
                        .topology()
                        .half_polynomial_degree_bound_exclusive()
                        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                || usize::try_from(runtime_tree.row_width()).ok()
                    != Some(expected_ordered_column_count)
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
            ordered_runtime_tree_preflights.push(
                VerifiedStreamedProofTreeTerminal::preflight_from_recomputed_key_switch_component_tree(
                    verified_proof.verified_proof(),
                    canonical_application_statement_bytes,
                    verified_proof.ceremony_context_hash(),
                    verified_proof.action_context_hash(),
                    roster_hash,
                    expected_tree_ordinal,
                    expected_root_source_ordinal,
                    statement_roots.runtime_component_root(),
                    context,
                    expected_column_moduli.into_vec(),
                    component.material(),
                    runtime_tree,
                )?,
            );
            ordered_verified_runtime_roots.push(
                VerifiedEvaluatorRuntimeRoot::from_recomputed_public_polynomial_tree(
                    runtime_tree,
                    top_count,
                )?,
            );
        }
        let validated_store = VerifiedEvaluatorKeyStore::from_verified_common_proof_inner(
            VerifiedEvaluatorKeyStoreProofInputs {
                verified_proof: verified_proof.verified_proof(),
                canonical_application_statement_bytes,
            },
            VerifiedEvaluatorKeyStoreMaterialInputs {
                verified_evaluator_key_store_stream: verified_evaluator_key_store_material
                    .canonical_store_summary(),
                ordered_verified_runtime_roots: &ordered_verified_runtime_roots,
                store_material: None,
            },
            VerifiedEvaluatorKeyStoreBindings {
                ceremony_context_hash: verified_proof.ceremony_context_hash(),
                action_context_hash: verified_proof.action_context_hash(),
                manifest_hash: verified_evaluator_source_catalog.manifest_hash(),
                roster_hash,
                proof_stream_descriptor: Some(verified_proof.proof_stream_descriptor().clone()),
            },
        )?;
        Ok(Self {
            validated_store,
            canonical_application_statement_bytes: canonical_application_statement_bytes
                .to_vec()
                .into_boxed_slice(),
            application_statement_hash: verified_proof.application_statement_hash(),
            relation_plan_hash: verified_proof.relation_plan_hash(),
            relation_plan_variant_hash: verified_proof.relation_plan_variant_hash(),
            ordered_auxiliary_roots: ordered_verified_auxiliary_roots.to_vec().into_boxed_slice(),
            ordered_runtime_tree_preflights: ordered_runtime_tree_preflights.into_boxed_slice(),
        })
    }

    pub(crate) fn complete(
        self,
        verified_proof: ConsumedVerifiedCommonProofCapability,
        canonical_application_statement_bytes: &[u8],
        verified_evaluator_key_store_material: VerifiedEvaluatorKeyStoreMaterial,
        ordered_runtime_component_trees: Vec<SetupPublicPolynomialTree>,
        ordered_verified_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    ) -> VerifiedEvaluatorKeyStore {
        let borrowed_proof = verified_proof.borrowed();
        assert_eq!(
            canonical_application_statement_bytes,
            self.canonical_application_statement_bytes.as_ref(),
        );
        assert_eq!(
            borrowed_proof.protocol_version(),
            self.validated_store.protocol_version,
        );
        assert_eq!(
            borrowed_proof.suite_identifier(),
            self.validated_store.suite_identifier,
        );
        assert_eq!(
            borrowed_proof.ceremony_context_hash(),
            self.validated_store.ceremony_context_hash,
        );
        assert_eq!(
            borrowed_proof.action_context_hash(),
            self.validated_store.action_context_hash,
        );
        assert_eq!(
            borrowed_proof.application_statement_hash(),
            self.application_statement_hash,
        );
        assert_eq!(borrowed_proof.relation_plan_hash(), self.relation_plan_hash);
        assert_eq!(
            borrowed_proof.relation_plan_variant_hash(),
            self.relation_plan_variant_hash,
        );
        assert_eq!(
            borrowed_proof.top_count(),
            Some(self.validated_store.top_count)
        );
        assert_eq!(borrowed_proof.schedule_position(), None);
        assert_eq!(
            Some(borrowed_proof.proof_stream_descriptor()),
            self.validated_store.proof_stream_descriptor.as_ref(),
        );
        assert_eq!(
            ordered_verified_auxiliary_roots.as_slice(),
            self.ordered_auxiliary_roots.as_ref(),
        );
        assert_eq!(
            verified_evaluator_key_store_material.top_count(),
            self.validated_store.top_count,
        );
        assert_eq!(
            verified_evaluator_key_store_material
                .canonical_store_summary()
                .stream_descriptor(),
            self.validated_store
                .verified_evaluator_key_store_stream
                .stream_descriptor(),
        );
        assert_eq!(
            verified_evaluator_key_store_material
                .canonical_store_summary()
                .full_object_digest(),
            self.validated_store
                .verified_evaluator_key_store_stream
                .full_object_digest(),
        );
        assert_eq!(
            ordered_runtime_component_trees.len(),
            self.ordered_runtime_tree_preflights.len(),
        );
        for ((tree_preflight, tree), expected_root) in self
            .ordered_runtime_tree_preflights
            .into_vec()
            .into_iter()
            .zip(ordered_runtime_component_trees)
            .zip(&self.validated_store.ordered_runtime_roots)
        {
            let terminal = tree_preflight.complete(tree);
            assert_eq!(terminal.root(), expected_root.runtime_component_root());
        }
        drop(verified_proof);
        let mut validated_store = self.validated_store;
        assert!(validated_store.store_material.is_none());
        validated_store.store_material = Some(verified_evaluator_key_store_material);
        validated_store
    }
}

struct VerifiedEvaluatorKeyStoreProofInputs<'a> {
    verified_proof: &'a VerifiedCommonProof,
    canonical_application_statement_bytes: &'a [u8],
}

struct VerifiedEvaluatorKeyStoreMaterialInputs<'a> {
    verified_evaluator_key_store_stream: &'a VerifiedCanonicalStreamSummary,
    ordered_verified_runtime_roots: &'a [VerifiedEvaluatorRuntimeRoot],
    store_material: Option<VerifiedEvaluatorKeyStoreMaterial>,
}

struct VerifiedEvaluatorKeyStoreBindings {
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    manifest_hash: [u8; 64],
    roster_hash: [u8; 64],
    proof_stream_descriptor: Option<StreamDescriptor>,
}

impl VerifiedEvaluatorKeyStore {
    /// Mints only the replay-store side of the positive type for unit tests.
    /// The store material itself has passed the production authenticated
    /// stream path; the omitted aggregate proof is represented only by a
    /// private, nonempty test descriptor.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_test_authenticated_replay_material(
        protocol_version: u16,
        suite_identifier: [u8; 64],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        manifest_hash: [u8; 64],
        roster_hash: [u8; 64],
        setup_proof_context_hash: [u8; 64],
        store_material: VerifiedEvaluatorKeyStoreMaterial,
    ) -> Result<Self, CommonProofVerifierError> {
        if protocol_version != FOUNDATION_PROFILE.protocol_version
            || suite_identifier != selected_suite_capability_for_tests().suite_identifier()
            || store_material.top_count() != FOUNDATION_PROFILE.option_count
            || store_material.canonical_store_summary().stream_domain()
                != CanonicalStreamDomain::EvaluatorKeyStore
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let proof_stream_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyAggregateProof,
            b"test-minted evaluator-key aggregate proof authority",
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let verified_evaluator_key_store_stream = store_material.canonical_store_summary().clone();
        let evaluator_key_store_digest = store_material
            .store_descriptor()
            .full_object_digest
            .into_bytes();
        let store = Self {
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            manifest_hash,
            roster_hash,
            setup_proof_context_hash,
            top_count: store_material.top_count(),
            evaluator_key_store_digest,
            proof_stream_descriptor: Some(proof_stream_descriptor),
            ordered_runtime_roots: Vec::new().into_boxed_slice(),
            verified_evaluator_key_store_stream,
            store_material: Some(store_material),
        };
        store.require_production_replay_material()?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn from_verified_common_proof(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
        verified_evaluator_key_store_stream: &VerifiedCanonicalStreamSummary,
        ordered_verified_runtime_roots: &[VerifiedEvaluatorRuntimeRoot],
    ) -> Result<Self, CommonProofVerifierError> {
        Self::from_verified_common_proof_inner(
            VerifiedEvaluatorKeyStoreProofInputs {
                verified_proof,
                canonical_application_statement_bytes,
            },
            VerifiedEvaluatorKeyStoreMaterialInputs {
                verified_evaluator_key_store_stream,
                ordered_verified_runtime_roots,
                store_material: None,
            },
            VerifiedEvaluatorKeyStoreBindings {
                ceremony_context_hash: [0_u8; 64],
                action_context_hash: [0_u8; 64],
                manifest_hash: [0_u8; 64],
                roster_hash: [0_u8; 64],
                proof_stream_descriptor: None,
            },
        )
    }

    fn from_verified_common_proof_inner(
        proof_inputs: VerifiedEvaluatorKeyStoreProofInputs<'_>,
        material_inputs: VerifiedEvaluatorKeyStoreMaterialInputs<'_>,
        bindings: VerifiedEvaluatorKeyStoreBindings,
    ) -> Result<Self, CommonProofVerifierError> {
        let VerifiedEvaluatorKeyStoreProofInputs {
            verified_proof,
            canonical_application_statement_bytes,
        } = proof_inputs;
        let VerifiedEvaluatorKeyStoreMaterialInputs {
            verified_evaluator_key_store_stream,
            ordered_verified_runtime_roots,
            store_material,
        } = material_inputs;
        let VerifiedEvaluatorKeyStoreBindings {
            ceremony_context_hash,
            action_context_hash,
            manifest_hash,
            roster_hash,
            proof_stream_descriptor,
        } = bindings;
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

    #[cfg(test)]
    pub(crate) const fn evaluator_key_store_digest(&self) -> [u8; 64] {
        self.evaluator_key_store_digest
    }

    #[cfg(test)]
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
