use super::{
    BTreeMap, BTreeSet, CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN,
    CommonProofApplicationBinding, CommonProofApplicationInputCapabilityHandle,
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
    SelectedSuiteCapability, VerifiedBoardApplicationSource, VerifiedCommonProofStatementSource,
    VerifiedEvaluatorAuxiliaryRoot, VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree,
    common_proof_registry_entry_count, common_proof_stream_domain, hash_framed_parts_512,
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

    pub(crate) fn release_suite(&mut self, handle: u32) -> Result<(), CommonProofRuntimeError> {
        self.suites
            .remove(&handle)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    pub(crate) fn install_preverification_application_source(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        board_source: &VerifiedBoardApplicationSource,
        statement_source: &VerifiedCommonProofStatementSource,
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
        let producer_coordinates_match = application_slot.roster_position()
            == board_source.producer_roster_position()
            && application_slot
                .producer_sequence()
                .is_none_or(|sequence| sequence == board_source.producer_sequence());
        if canonical_application_statement_bytes.is_empty()
            || canonical_application_statement_bytes.len()
                > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || proof_byte_length == 0
            || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
            || application_slot.suite_identifier().into_bytes()
                != suite.capability.suite_identifier()
            || board_source.suite_identifier().into_bytes() != suite.capability.suite_identifier()
            || application_slot.ceremony_context_hash() != board_source.ceremony_context_hash()
            || application_slot.action_context_hash() != board_source.action_context_hash()
            || !producer_coordinates_match
            || board_source.object_hash() != statement_source.board_object_hash()
            || expected_statement_hash != statement_source.application_statement_hash().into_bytes()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        // Structural suite and board binding alone do not establish that an
        // exact family derived this statement from the accepted board object.
        // Keep production verification closed until a family-owned adapter
        // supplies that derivation. The generic runtime remains available to
        // separately installed checked capabilities in tests.
        Err(CommonProofRuntimeError::InvalidPlanCapability)
    }

    /// Consumes one board-bound source and promotes it into the sole
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
        let proof_application_binding = &source.proof_application_binding;
        let application_slot = proof_application_binding.application_slot();
        if source.board_source.suite_identifier().into_bytes()
            != suite.capability.suite_identifier()
            || application_slot.suite_identifier().into_bytes()
                != suite.capability.suite_identifier()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let canonical_binding_bytes = proof_application_binding
            .encode()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let canonical_binding_hash = hash_framed_parts_512(
            CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN,
            &[&canonical_binding_bytes],
        );
        let statement_schema_identifier =
            application_slot.application_statement_schema_identifier();
        let proof_stream_domain = common_proof_stream_domain(statement_schema_identifier)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let selected_variant = source
            .relation_plan
            .relation_plan
            .select_variant(
                source.relation_plan.schedule_position,
                source.relation_plan.top_count,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        let proof_query_count = selected_variant
            .common_proof_transcript_schedule(&source.relation_plan.relation_context)
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?
            .unique_query_count();
        let proof_stream_descriptor = proof_application_binding.proof_stream_descriptor();
        let application_binding = CommonProofApplicationBinding::new(
            application_slot
                .hash()
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
                .into_bytes(),
            canonical_binding_hash,
            statement_schema_identifier,
            proof_application_binding.proof_header_hash().into_bytes(),
            proof_stream_domain,
            proof_stream_descriptor.full_object_digest.into_bytes(),
            proof_stream_descriptor.total_byte_length,
            proof_query_count,
        )?;
        let verification_binding = CommonProofVerificationBinding::new(
            suite.capability.suite_identifier(),
            source.board_source.ceremony_context_hash().into_bytes(),
            source.board_source.action_context_hash().into_bytes(),
            source.board_source.object_hash().into_bytes(),
            application_binding,
            source.relation_plan.relation_plan_hash(),
        );

        let handle = take_nonrepeating_handle(&mut self.next_application_handle)?;
        let source = self
            .preverification_application_sources
            .remove(&application_source_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        self.applications.insert(
            handle,
            CommonProofApplicationInputEntry {
                verification_binding,
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
                    .map(|entry| entry.root)
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
