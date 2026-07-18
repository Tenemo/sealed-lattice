use super::{
    BTreeMap, BTreeSet, CommonProofApplicationInputCapabilityHandle,
    CommonProofApplicationInputEntry, CommonProofEvaluatorAuxiliaryRootCapabilityHandle,
    CommonProofEvaluatorAuxiliaryRootEntry, CommonProofPreverificationApplicationSourceEntry,
    CommonProofPreverificationApplicationSourceHandle, CommonProofRuntimeError,
    CommonProofSelectedSuiteCapabilityHandle, CommonProofSelectedSuiteEntry,
    CommonProofStatementTreeCapabilityHandle, CommonProofStatementTreeEntry,
    CommonProofVerificationBinding, CommonProofVerificationStateMachine,
    CommonProofVerifiedColumnEvaluatorCapabilityHandle, CommonProofVerifiedColumnEvaluatorEntry,
    ConsumedCommonProofVerificationInputs, FOUNDATION_PROFILE, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS,
    PollableCommonProofVerificationInput, RefusingVerifiedColumnEvaluator, RelationColumnOrigin,
    SelectedSuiteCapability, VerifiedCommonProofStatementSource, VerifiedEvaluatorAuxiliaryRoot,
    VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree, common_proof_registry_entry_count,
    require_common_proof_registry_entry_capacity, take_nonrepeating_handle,
    verified_application_statement_hash,
};
#[cfg(test)]
use super::{CommonProofRelationPlanCapability, CommonProofRuntimeLimits, StreamDescriptor};

/// Process-local ownership registry between accepted suite/setup/board inputs
/// and the common verifier. Upstream owners mint tree and evaluator handles
/// from their non-constructible verified values. Verification consumes the
/// exact application and all supplied handles atomically after a complete
/// coordinate check; a mismatch leaves every capability live for its owner.
pub(crate) struct CommonProofUpstreamInputRegistry {
    next_suite_handle: u32,
    next_application_handle: u32,
    next_preverification_application_source_handle: u32,
    next_statement_tree_handle: u32,
    next_evaluator_root_handle: u32,
    next_verified_column_evaluator_handle: u32,
    suites: BTreeMap<u32, CommonProofSelectedSuiteEntry>,
    applications: BTreeMap<u32, CommonProofApplicationInputEntry>,
    preverification_application_sources:
        BTreeMap<u32, CommonProofPreverificationApplicationSourceEntry>,
    statement_trees: BTreeMap<u32, CommonProofStatementTreeEntry>,
    evaluator_roots: BTreeMap<u32, CommonProofEvaluatorAuxiliaryRootEntry>,
    verified_column_evaluators: BTreeMap<u32, CommonProofVerifiedColumnEvaluatorEntry>,
}

impl Default for CommonProofUpstreamInputRegistry {
    fn default() -> Self {
        Self {
            next_suite_handle: 1,
            next_application_handle: 1,
            next_preverification_application_source_handle: 1,
            next_statement_tree_handle: 1,
            next_evaluator_root_handle: 1,
            next_verified_column_evaluator_handle: 1,
            suites: BTreeMap::new(),
            applications: BTreeMap::new(),
            preverification_application_sources: BTreeMap::new(),
            statement_trees: BTreeMap::new(),
            evaluator_roots: BTreeMap::new(),
            verified_column_evaluators: BTreeMap::new(),
        }
    }
}

impl CommonProofUpstreamInputRegistry {
    pub(crate) fn entry_count(&self) -> Result<usize, CommonProofRuntimeError> {
        common_proof_registry_entry_count(&[
            self.suites.len(),
            self.applications.len(),
            self.preverification_application_sources.len(),
            self.statement_trees.len(),
            self.evaluator_roots.len(),
            self.verified_column_evaluators.len(),
        ])
    }

    /// Counts proof attempts, not the tree, root, and evaluator handles owned
    /// by the same application. Those supporting handles are still included in
    /// `entry_count` and cannot outlive the worker-process ownership ceiling.
    pub(crate) fn heavy_operation_count(&self) -> Result<usize, CommonProofRuntimeError> {
        common_proof_registry_entry_count(&[
            self.applications.len(),
            self.preverification_application_sources.len(),
        ])
    }

    pub(crate) fn require_entry_capacity(&self) -> Result<(), CommonProofRuntimeError> {
        require_common_proof_registry_entry_capacity(&[
            self.suites.len(),
            self.applications.len(),
            self.preverification_application_sources.len(),
            self.statement_trees.len(),
            self.evaluator_roots.len(),
            self.verified_column_evaluators.len(),
        ])
    }

    #[cfg(test)]
    pub(super) fn insert_test_refusing_verified_column_evaluator(&mut self, identifier: u32) {
        self.verified_column_evaluators.insert(
            identifier,
            CommonProofVerifiedColumnEvaluatorEntry {
                application_handle: identifier,
                evaluator: Box::new(RefusingVerifiedColumnEvaluator),
            },
        );
    }

    pub(crate) fn install_suite(
        &mut self,
        capability: SelectedSuiteCapability,
    ) -> Result<CommonProofSelectedSuiteCapabilityHandle, CommonProofRuntimeError> {
        self.require_entry_capacity()?;
        let handle = take_nonrepeating_handle(&mut self.next_suite_handle)?;
        self.suites
            .insert(handle, CommonProofSelectedSuiteEntry { capability });
        Ok(CommonProofSelectedSuiteCapabilityHandle(handle))
    }

    pub(crate) fn selected_suite(
        &self,
        handle: &CommonProofSelectedSuiteCapabilityHandle,
    ) -> Result<&SelectedSuiteCapability, CommonProofRuntimeError> {
        self.suites
            .get(&handle.0)
            .map(|entry| &entry.capability)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    pub(crate) fn release_suite(&mut self, handle: u32) -> Result<(), CommonProofRuntimeError> {
        self.suites
            .remove(&handle)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    pub(crate) fn install_preverification_application_source(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
    ) -> Result<CommonProofPreverificationApplicationSourceHandle, CommonProofRuntimeError> {
        let suite = self
            .suites
            .get(&suite_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let proof_application_binding = statement_source.proof_application_binding();
        let application_slot = proof_application_binding.application_slot();
        let statement_schema_identifier =
            application_slot.application_statement_schema_identifier();
        let canonical_application_statement_bytes =
            statement_source.canonical_application_statement_bytes();
        let expected_statement_hash = verified_application_statement_hash(
            suite.capability.protocol_version(),
            suite.capability.suite_identifier(),
            statement_schema_identifier,
            canonical_application_statement_bytes,
        );
        let proof_stream_descriptor = proof_application_binding.proof_stream_descriptor();
        let proof_byte_length = usize::try_from(proof_stream_descriptor.total_byte_length)
            .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
        let application_source_authority = statement_source.application_source_authority();
        let producer_and_schedule_coordinates_match = application_slot.roster_position()
            == application_source_authority.producer_roster_position()
            && application_slot.schedule_position()
                == application_source_authority.schedule_position()
            && application_slot.producer_sequence()
                == application_source_authority.producer_sequence();
        if canonical_application_statement_bytes.is_empty()
            || canonical_application_statement_bytes.len()
                > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || proof_byte_length == 0
            || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
            || application_slot.suite_identifier().into_bytes()
                != suite.capability.suite_identifier()
            || statement_source.protocol_version != suite.capability.protocol_version()
            || application_source_authority.suite_identifier().into_bytes()
                != suite.capability.suite_identifier()
            || application_slot.ceremony_context_hash()
                != application_source_authority.ceremony_context_hash()
            || application_slot.action_context_hash()
                != application_source_authority.action_context_hash()
            || application_slot.application_statement_schema_identifier()
                != application_source_authority.application_statement_schema_identifier()
            || !producer_and_schedule_coordinates_match
            || proof_stream_descriptor != application_source_authority.proof_stream_descriptor()
            || statement_source.verification_binding.board_object_hash
                != application_source_authority
                    .application_source_object_hash()
                    .into_bytes()
            || expected_statement_hash != statement_source.application_statement_hash().into_bytes()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let handle =
            take_nonrepeating_handle(&mut self.next_preverification_application_source_handle)?;
        self.preverification_application_sources.insert(
            handle,
            CommonProofPreverificationApplicationSourceEntry {
                source: statement_source,
            },
        );
        Ok(CommonProofPreverificationApplicationSourceHandle(handle))
    }

    /// Consumes one verifier-owned source and promotes it into the sole
    /// application capability that exact-family tree/root adapters may use.
    /// No caller-provided binding, plan, descriptor, or digest enters this
    /// transition.
    pub(crate) fn promote_preverification_application_source(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        application_source_handle: &CommonProofPreverificationApplicationSourceHandle,
    ) -> Result<CommonProofApplicationInputCapabilityHandle, CommonProofRuntimeError> {
        let suite = self
            .suites
            .get(&suite_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let source = self
            .preverification_application_sources
            .get(&application_source_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let application_slot = source.source.proof_application_binding.application_slot();
        let application_source_authority = source.source.application_source_authority();
        if application_source_authority.suite_identifier().into_bytes()
            != suite.capability.suite_identifier()
            || application_slot.suite_identifier().into_bytes()
                != suite.capability.suite_identifier()
            || application_slot.ceremony_context_hash()
                != application_source_authority.ceremony_context_hash()
            || application_slot.action_context_hash()
                != application_source_authority.action_context_hash()
            || application_slot.application_statement_schema_identifier()
                != application_source_authority.application_statement_schema_identifier()
            || application_slot.roster_position()
                != application_source_authority.producer_roster_position()
            || application_slot.schedule_position()
                != application_source_authority.schedule_position()
            || application_slot.producer_sequence()
                != application_source_authority.producer_sequence()
            || source
                .source
                .proof_application_binding
                .proof_stream_descriptor()
                != application_source_authority.proof_stream_descriptor()
            || source.source.protocol_version != suite.capability.protocol_version()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }

        let handle = take_nonrepeating_handle(&mut self.next_application_handle)?;
        let source = self
            .preverification_application_sources
            .remove(&application_source_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .source;
        self.applications.insert(
            handle,
            CommonProofApplicationInputEntry {
                verification_binding: source.verification_binding,
                relation_plan: source.relation_plan,
                protocol_version: source.protocol_version,
                canonical_application_statement_bytes: source.canonical_application_statement_bytes,
                proof_stream_descriptor: source
                    .proof_application_binding
                    .proof_stream_descriptor()
                    .clone(),
                limits: source.limits,
            },
        );
        Ok(CommonProofApplicationInputCapabilityHandle(handle))
    }

    pub(crate) fn release_preverification_application_source(
        &mut self,
        application_source_handle: &CommonProofPreverificationApplicationSourceHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.preverification_application_sources
            .remove(&application_source_handle.0)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    /// Atomically consumes one exact-family source into a verifier that
    /// needs no statement-owned trees or auxiliary roots. The checked plan
    /// still decides whether a verifier-sequence evaluator is required; a
    /// failed transition removes every partially retained application input.
    pub(crate) fn prepare_proof_created_tree_family_verification(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
        verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    ) -> Result<super::PreparedCommonProofVerification, CommonProofRuntimeError> {
        let preverification_handle =
            self.install_preverification_application_source(suite_handle, statement_source)?;
        let application_handle = match self
            .promote_preverification_application_source(suite_handle, &preverification_handle)
        {
            Ok(handle) => handle,
            Err(error) => {
                self.release_preverification_application_source(&preverification_handle)?;
                return Err(error);
            }
        };
        let evaluator_handle = match self
            .mint_verified_column_evaluator(&application_handle, verified_column_evaluator)
        {
            Ok(handle) => handle,
            Err(error) => {
                self.cancel_application(&application_handle)?;
                return Err(error);
            }
        };
        match self.consume_verification_inputs(
            &application_handle,
            &[],
            &[],
            Some(&evaluator_handle),
        ) {
            Ok(inputs) => inputs.prepare(),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    /// Atomically consumes one exact-family source into a verifier whose
    /// checked relation has no verifier-sequence columns. Statement-bound and
    /// proof-created tree roots remain owned by the relation plan and proof;
    /// no caller-supplied evaluator can enter this transition.
    pub(crate) fn prepare_proof_created_tree_family_verification_without_evaluator(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
    ) -> Result<super::PreparedCommonProofVerification, CommonProofRuntimeError> {
        let preverification_handle =
            self.install_preverification_application_source(suite_handle, statement_source)?;
        let application_handle = match self
            .promote_preverification_application_source(suite_handle, &preverification_handle)
        {
            Ok(handle) => handle,
            Err(error) => {
                self.release_preverification_application_source(&preverification_handle)?;
                return Err(error);
            }
        };
        match self.consume_verification_inputs(&application_handle, &[], &[], None) {
            Ok(inputs) => inputs.prepare(),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    /// Atomically prepares an exact-family verifier from verifier-recomputed
    /// statement trees and no verifier-sequence columns. The caller retains
    /// the full recomputed trees; these compact inputs carry only their bound
    /// roots, roles, and relation ordinals into the common verifier.
    pub(crate) fn prepare_statement_tree_family_verification_without_evaluator(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
        statement_trees: Vec<VerifiedStatementOwnedTree>,
    ) -> Result<super::PreparedCommonProofVerification, CommonProofRuntimeError> {
        let preverification_handle =
            self.install_preverification_application_source(suite_handle, statement_source)?;
        let application_handle = match self
            .promote_preverification_application_source(suite_handle, &preverification_handle)
        {
            Ok(handle) => handle,
            Err(error) => {
                self.release_preverification_application_source(&preverification_handle)?;
                return Err(error);
            }
        };
        let mut statement_tree_handles = Vec::new();
        for tree in statement_trees {
            match self.mint_statement_tree(&application_handle, tree) {
                Ok(handle) => statement_tree_handles.push(handle),
                Err(error) => {
                    self.cancel_application(&application_handle)?;
                    return Err(error);
                }
            }
        }
        let borrowed_statement_tree_handles = statement_tree_handles.iter().collect::<Vec<_>>();
        match self.consume_verification_inputs(
            &application_handle,
            &borrowed_statement_tree_handles,
            &[],
            None,
        ) {
            Ok(inputs) => inputs.prepare(),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    /// Atomically prepares an exact-family verifier from verifier-recomputed
    /// statement trees and its verifier-sequence column evaluator. The trees
    /// and evaluator are verifier-minted authorities; no caller-provided root,
    /// column value, or alternate representation enters this transition.
    pub(crate) fn prepare_statement_tree_family_verification(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
        statement_trees: Vec<VerifiedStatementOwnedTree>,
        verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    ) -> Result<super::PreparedCommonProofVerification, CommonProofRuntimeError> {
        let preverification_handle =
            self.install_preverification_application_source(suite_handle, statement_source)?;
        let application_handle = match self
            .promote_preverification_application_source(suite_handle, &preverification_handle)
        {
            Ok(handle) => handle,
            Err(error) => {
                self.release_preverification_application_source(&preverification_handle)?;
                return Err(error);
            }
        };
        let mut statement_tree_handles = Vec::new();
        for tree in statement_trees {
            match self.mint_statement_tree(&application_handle, tree) {
                Ok(handle) => statement_tree_handles.push(handle),
                Err(error) => {
                    self.cancel_application(&application_handle)?;
                    return Err(error);
                }
            }
        }
        let evaluator_handle = match self
            .mint_verified_column_evaluator(&application_handle, verified_column_evaluator)
        {
            Ok(handle) => handle,
            Err(error) => {
                self.cancel_application(&application_handle)?;
                return Err(error);
            }
        };
        let borrowed_statement_tree_handles = statement_tree_handles.iter().collect::<Vec<_>>();
        match self.consume_verification_inputs(
            &application_handle,
            &borrowed_statement_tree_handles,
            &[],
            Some(&evaluator_handle),
        ) {
            Ok(inputs) => inputs.prepare(),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    pub(crate) fn mint_statement_tree(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        tree: VerifiedStatementOwnedTree,
    ) -> Result<CommonProofStatementTreeCapabilityHandle, CommonProofRuntimeError> {
        self.applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        self.require_entry_capacity()?;
        let handle = take_nonrepeating_handle(&mut self.next_statement_tree_handle)?;
        self.statement_trees.insert(
            handle,
            CommonProofStatementTreeEntry {
                application_handle: application_handle.0,
                tree,
            },
        );
        Ok(CommonProofStatementTreeCapabilityHandle(handle))
    }

    pub(crate) fn mint_evaluator_auxiliary_root(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        root: VerifiedEvaluatorAuxiliaryRoot,
    ) -> Result<CommonProofEvaluatorAuxiliaryRootCapabilityHandle, CommonProofRuntimeError> {
        self.applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        self.require_entry_capacity()?;
        let handle = take_nonrepeating_handle(&mut self.next_evaluator_root_handle)?;
        self.evaluator_roots.insert(
            handle,
            CommonProofEvaluatorAuxiliaryRootEntry {
                application_handle: application_handle.0,
                root,
            },
        );
        Ok(CommonProofEvaluatorAuxiliaryRootCapabilityHandle(handle))
    }

    /// Retains the exact-family evaluator for plan-owned verifier-sequence
    /// columns. Families with no such columns must not install one.
    pub(crate) fn mint_verified_column_evaluator(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    ) -> Result<CommonProofVerifiedColumnEvaluatorCapabilityHandle, CommonProofRuntimeError> {
        self.applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if self
            .verified_column_evaluators
            .values()
            .any(|entry| entry.application_handle == application_handle.0)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.require_entry_capacity()?;
        let handle = take_nonrepeating_handle(&mut self.next_verified_column_evaluator_handle)?;
        self.verified_column_evaluators.insert(
            handle,
            CommonProofVerifiedColumnEvaluatorEntry {
                application_handle: application_handle.0,
                evaluator,
            },
        );
        Ok(CommonProofVerifiedColumnEvaluatorCapabilityHandle(handle))
    }

    pub(crate) fn consume_verification_inputs(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        statement_tree_handles: &[&CommonProofStatementTreeCapabilityHandle],
        evaluator_root_handles: &[&CommonProofEvaluatorAuxiliaryRootCapabilityHandle],
        verified_column_evaluator_handle: Option<
            &CommonProofVerifiedColumnEvaluatorCapabilityHandle,
        >,
    ) -> Result<ConsumedCommonProofVerificationInputs, CommonProofRuntimeError> {
        let application = self
            .applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let mut unique_statement_tree_handles = BTreeSet::new();
        for handle in statement_tree_handles {
            if !unique_statement_tree_handles.insert(handle.0) {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let entry = self
                .statement_trees
                .get(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
            if entry.application_handle != application_handle.0 {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
        }
        let mut unique_evaluator_root_handles = BTreeSet::new();
        for handle in evaluator_root_handles {
            if !unique_evaluator_root_handles.insert(handle.0) {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let entry = self
                .evaluator_roots
                .get(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
            if entry.application_handle != application_handle.0 {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
        }
        let selected_variant = application
            .relation_plan
            .relation_plan
            .select_variant(
                application.relation_plan.schedule_position,
                application.relation_plan.top_count,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        let requires_verified_column_evaluator =
            selected_variant.ordered_columns().iter().any(|column| {
                matches!(
                    column.origin(),
                    RelationColumnOrigin::VerifierSequence { .. }
                )
            });
        if requires_verified_column_evaluator != verified_column_evaluator_handle.is_some() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        if let Some(handle) = verified_column_evaluator_handle {
            let entry = self
                .verified_column_evaluators
                .get(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
            if entry.application_handle != application_handle.0 {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
        }

        let statement_owned_trees = statement_tree_handles
            .iter()
            .map(|handle| {
                self.statement_trees
                    .get(&handle.0)
                    .map(|entry| entry.tree.clone())
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let evaluator_auxiliary_roots = evaluator_root_handles
            .iter()
            .map(|handle| {
                self.evaluator_roots
                    .get(&handle.0)
                    .map(|entry| entry.root.clone())
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let validation_state =
            CommonProofVerificationStateMachine::new(PollableCommonProofVerificationInput {
                protocol_version: application.protocol_version,
                suite_identifier: application.verification_binding.suite_identifier,
                canonical_application_statement_bytes: &application
                    .canonical_application_statement_bytes,
                relation_plan: &application.relation_plan.relation_plan,
                relation_context: &application.relation_plan.relation_context,
                schedule_position: application.relation_plan.schedule_position,
                top_count: application.relation_plan.top_count,
                statement_owned_trees: &statement_owned_trees,
                evaluator_auxiliary_roots: &evaluator_auxiliary_roots,
                declared_proof_byte_length: application.limits.proof_byte_length(),
                proof_byte_ceiling: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
                maximum_resident_window_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
                    .checked_mul(MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS)
                    .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?,
            })
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        drop(validation_state);

        let application = self
            .applications
            .remove(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        for handle in statement_tree_handles {
            self.statement_trees
                .remove(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        }
        for handle in evaluator_root_handles {
            self.evaluator_roots
                .remove(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        }
        let verified_column_evaluator = match verified_column_evaluator_handle {
            Some(handle) => {
                self.verified_column_evaluators
                    .remove(&handle.0)
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
                    .evaluator
            }
            None => Box::new(RefusingVerifiedColumnEvaluator),
        };
        Ok(ConsumedCommonProofVerificationInputs {
            verification_binding: application.verification_binding,
            relation_plan: application.relation_plan,
            protocol_version: application.protocol_version,
            canonical_application_statement_bytes: application
                .canonical_application_statement_bytes,
            proof_stream_descriptor: application.proof_stream_descriptor,
            statement_owned_trees,
            evaluator_auxiliary_roots,
            verified_column_evaluator,
            limits: application.limits,
        })
    }

    pub(crate) fn cancel_application(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        self.applications
            .remove(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        self.statement_trees
            .retain(|_, entry| entry.application_handle != application_handle.0);
        self.evaluator_roots
            .retain(|_, entry| entry.application_handle != application_handle.0);
        self.verified_column_evaluators
            .retain(|_, entry| entry.application_handle != application_handle.0);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn install_test_application_fixture(
        &mut self,
        verification_binding: CommonProofVerificationBinding,
        relation_plan: CommonProofRelationPlanCapability,
        protocol_version: u16,
        canonical_application_statement_bytes: &[u8],
        proof_stream_descriptor: StreamDescriptor,
        limits: CommonProofRuntimeLimits,
    ) -> Result<CommonProofApplicationInputCapabilityHandle, CommonProofRuntimeError> {
        if verification_binding.relation_plan_hash != relation_plan.relation_plan_hash()
            || canonical_application_statement_bytes.is_empty()
            || proof_stream_descriptor.total_byte_length
                != verification_binding.proof_application.proof_byte_length
            || proof_stream_descriptor.full_object_digest.into_bytes()
                != verification_binding
                    .proof_application
                    .proof_stream_full_object_digest
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.require_entry_capacity()?;
        let mut statement_bytes = Vec::new();
        statement_bytes
            .try_reserve_exact(canonical_application_statement_bytes.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        statement_bytes.extend_from_slice(canonical_application_statement_bytes);
        let handle = take_nonrepeating_handle(&mut self.next_application_handle)?;
        self.applications.insert(
            handle,
            CommonProofApplicationInputEntry {
                verification_binding,
                relation_plan,
                protocol_version,
                canonical_application_statement_bytes: statement_bytes,
                proof_stream_descriptor,
                limits,
            },
        );
        Ok(CommonProofApplicationInputCapabilityHandle(handle))
    }
}
