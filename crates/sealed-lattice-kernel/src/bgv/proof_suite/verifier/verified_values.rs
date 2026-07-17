use super::{
    CanonicalItemType, CommittedMaterialTree, CommonProofVerifierError, FOUNDATION_PROFILE,
    ProofApplicationSlotCeilings, SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, SetupPublicPolynomialRootRole, SetupPublicPolynomialTree,
    StatementOwnedProofTreeInput, SuiteModulusReference, decode_selected_application_statement,
    selected_evaluator_aggregate_entry_roots, selected_evaluator_entry_positions,
    verified_application_statement_hash,
};

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

/// Verifier-owned linkage for the unproved A component of one evaluator key.
/// Runtime B remains the only component in the evaluator-key aggregate relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedEvaluatorAuxiliaryRoot {
    position: SelectedEvaluatorEntryPosition,
    auxiliary_component_root: [u8; 64],
}

impl VerifiedEvaluatorAuxiliaryRoot {
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
        })
    }

    pub(crate) const fn position(self) -> SelectedEvaluatorEntryPosition {
        self.position
    }

    pub(crate) const fn auxiliary_component_root(self) -> [u8; 64] {
        self.auxiliary_component_root
    }
}

/// One evaluator-store entry accepted only after its own aggregate proof has
/// completed. The final store capability is minted from the complete ordered
/// entry set, never from a statement digest alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedEvaluatorAggregateEntry {
    top_count: u16,
    entry_ordinal: u32,
    position: SelectedEvaluatorEntryPosition,
    runtime_component_root: [u8; 64],
    evaluator_key_store_digest: [u8; 64],
}

impl VerifiedEvaluatorAggregateEntry {
    pub(crate) fn from_verified_common_proof(
        verified_proof: &VerifiedCommonProof,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<Self, CommonProofVerifierError> {
        let entry_ordinal = verified_proof
            .schedule_position
            .filter(|_| {
                verified_proof.application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                    && verified_proof.binds_application_statement(
                        canonical_application_statement_bytes,
                    )
            })
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let top_count = verified_proof
            .top_count
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        let statement = decode_selected_application_statement(
            canonical_application_statement_bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                verified_proof.protocol_version,
                verified_proof.suite_identifier,
                Some(entry_ordinal),
                Some(top_count),
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let entry = selected_evaluator_aggregate_entry_roots(&statement, top_count, entry_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let evaluator_key_store_digest = statement
            .items
            .get(2)
            .filter(|item| {
                item.item_type() == CanonicalItemType::Hash512 && item.canonical_bytes().len() == 64
            })
            .and_then(|item| item.canonical_bytes().try_into().ok())
            .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
        Ok(Self {
            top_count,
            entry_ordinal,
            position: entry.position(),
            runtime_component_root: entry.runtime_component_root(),
            evaluator_key_store_digest,
        })
    }

    pub(crate) const fn entry_ordinal(self) -> u32 {
        self.entry_ordinal
    }

    pub(crate) const fn position(self) -> SelectedEvaluatorEntryPosition {
        self.position
    }

    pub(crate) const fn runtime_component_root(self) -> [u8; 64] {
        self.runtime_component_root
    }

    #[cfg(test)]
    pub(super) fn corrupt_evaluator_key_store_digest_for_test(&mut self) {
        self.evaluator_key_store_digest[0] ^= 1;
    }
}

/// Opaque authority for one complete selected evaluator-key store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedEvaluatorKeyStore {
    top_count: u16,
    evaluator_key_store_digest: [u8; 64],
}

impl VerifiedEvaluatorKeyStore {
    pub(crate) fn from_ordered_verified_entries(
        top_count: u16,
        ordered_entries: &[VerifiedEvaluatorAggregateEntry],
    ) -> Result<Self, CommonProofVerifierError> {
        let expected_positions = selected_evaluator_entry_positions(top_count)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if ordered_entries.len() != expected_positions.len() || ordered_entries.is_empty() {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
        let evaluator_key_store_digest = ordered_entries[0].evaluator_key_store_digest;
        for (entry_ordinal, (entry, expected_position)) in
            ordered_entries.iter().zip(expected_positions).enumerate()
        {
            if entry.top_count != top_count
                || entry.entry_ordinal
                    != u32::try_from(entry_ordinal)
                        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?
                || entry.position != expected_position
                || entry.evaluator_key_store_digest != evaluator_key_store_digest
            {
                return Err(CommonProofVerifierError::InvalidApplicationStatement);
            }
        }
        Ok(Self {
            top_count,
            evaluator_key_store_digest,
        })
    }

    pub(crate) const fn top_count(self) -> u16 {
        self.top_count
    }

    pub(crate) const fn evaluator_key_store_digest(self) -> [u8; 64] {
        self.evaluator_key_store_digest
    }
}
