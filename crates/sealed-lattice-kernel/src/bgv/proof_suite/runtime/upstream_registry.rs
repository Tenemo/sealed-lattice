use super::super::RelationTreeDescriptor;
use super::super::row_code_whir::{
    VerifiedSameSecretLowDegreePrerequisite,
    exact_same_secret_verification_resident_memory_accounting, prepare_row_code_whir_verification,
    prepare_setup_polynomial_bound_row_code_whir_verification,
};
use super::{
    BTreeMap, BTreeSet, CommonProofApplicationInputCapabilityHandle,
    CommonProofApplicationInputEntry, CommonProofEvaluatorAuxiliaryRootCapabilityHandle,
    CommonProofEvaluatorAuxiliaryRootEntry, CommonProofPreverificationApplicationSourceEntry,
    CommonProofPreverificationApplicationSourceHandle, CommonProofRuntimeError,
    CommonProofSelectedSuiteCapabilityHandle, CommonProofSelectedSuiteEntry,
    CommonProofVerificationStatementSource, CommonProofVerifiedColumnEvaluatorCapabilityHandle,
    CommonProofVerifiedColumnEvaluatorEntry, ConsumedCommonProofVerificationInputs,
    FOUNDATION_PROFILE, MAXIMUM_COMMON_PROOF_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS,
    RefusingVerifiedColumnEvaluator, RelationColumnOrigin, SelectedSuiteCapability,
    VerifiedCommonProofStatementSource, VerifiedEvaluatorAuxiliaryRoot,
    VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree, common_proof_registry_entry_count,
    require_common_proof_registry_entry_capacity, take_nonrepeating_handle,
    verified_application_statement_hash,
};
use crate::bgv::setup::VerifiedSetupPolynomialLowDegreePrerequisite;
fn checked_verification_operation_memory_add(
    left: u64,
    right: u64,
) -> Result<u64, CommonProofRuntimeError> {
    left.checked_add(right)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
}

fn checked_verification_operation_memory_multiply(
    left: u64,
    right: u64,
) -> Result<u64, CommonProofRuntimeError> {
    left.checked_mul(right)
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
}

fn common_proof_verification_operation_resident_byte_length(
    verifier_resident_byte_length: u64,
    evaluator_accounting: super::VerifiedRelationColumnEvaluatorMemoryAccounting,
    proof_chunk_count: usize,
) -> Result<u64, CommonProofRuntimeError> {
    common_proof_verification_operation_resident_byte_length_for_verifier(
        verifier_resident_byte_length,
        evaluator_accounting,
        proof_chunk_count,
    )
}

fn prepare_row_code_whir_validation(
    statement_source: &VerifiedCommonProofStatementSource,
    statement_trees: &[VerifiedStatementOwnedTree],
    auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
    setup_polynomial_prerequisite: Option<&VerifiedSetupPolynomialLowDegreePrerequisite>,
) -> Result<super::super::row_code_whir::PreparedRowCodeWhirVerification, CommonProofRuntimeError> {
    let proof_application_binding = statement_source.proof_application_binding();
    match setup_polynomial_prerequisite {
        Some(prerequisite) => prepare_setup_polynomial_bound_row_code_whir_verification(
            prerequisite,
            statement_source.protocol_version,
            proof_application_binding.application_slot(),
            statement_source.canonical_application_statement_bytes(),
            proof_application_binding.proof_header_hash(),
            proof_application_binding
                .proof_stream_descriptor()
                .total_byte_length,
            &statement_source.relation_plan,
            statement_trees.to_vec(),
            auxiliary_roots.to_vec(),
            Box::new(RefusingVerifiedColumnEvaluator),
        ),
        None => prepare_row_code_whir_verification(
            statement_source.protocol_version,
            proof_application_binding.application_slot(),
            statement_source.canonical_application_statement_bytes(),
            proof_application_binding.proof_header_hash(),
            proof_application_binding
                .proof_stream_descriptor()
                .total_byte_length,
            &statement_source.relation_plan,
            statement_trees.to_vec(),
            auxiliary_roots.to_vec(),
            Box::new(RefusingVerifiedColumnEvaluator),
        ),
    }
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
}

fn common_proof_verification_operation_resident_byte_length_for_verifier(
    verifier_resident_byte_length: u64,
    evaluator_accounting: super::VerifiedRelationColumnEvaluatorMemoryAccounting,
    proof_chunk_count: usize,
) -> Result<u64, CommonProofRuntimeError> {
    let proof_chunk_count = u64::try_from(proof_chunk_count)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let hash_byte_length = u64::try_from(core::mem::size_of::<super::Hash512>())
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let descriptor_digest_payload_byte_length =
        checked_verification_operation_memory_multiply(proof_chunk_count, hash_byte_length)?;
    let ingest_phase_payload_byte_length = checked_verification_operation_memory_add(
        u64::try_from(core::mem::size_of::<super::CanonicalStreamVerifier>())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
        descriptor_digest_payload_byte_length,
    )?;
    let resident_chunk_count = u64::try_from(MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS)
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let resident_chunk_payload_byte_length = checked_verification_operation_memory_multiply(
        resident_chunk_count,
        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
    )?;
    let resident_chunk_catalog_payload_byte_length =
        checked_verification_operation_memory_multiply(
            resident_chunk_count,
            u64::try_from(
                core::mem::size_of::<(usize, Vec<u8>)>()
                    + core::mem::size_of::<super::ResidentCommonProofInputChunk<'static>>(),
            )
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
        )?;
    let readback_phase_payload_byte_length = [
        u64::try_from(core::mem::size_of::<super::CanonicalStreamReadbackVerifier>())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
        descriptor_digest_payload_byte_length,
        checked_verification_operation_memory_multiply(
            proof_chunk_count,
            u64::try_from(core::mem::size_of::<bool>())
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
        )?,
        resident_chunk_payload_byte_length,
        resident_chunk_catalog_payload_byte_length,
        u64::try_from(core::mem::size_of::<
            super::ResidentCommonProofByteSource<'static>,
        >())
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_verification_operation_memory_add)?;
    [
        u64::try_from(core::mem::size_of::<super::CommonProofVerificationWorker>())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
        verifier_resident_byte_length,
        evaluator_accounting.maximum_resident_byte_length(),
        ingest_phase_payload_byte_length.max(readback_phase_payload_byte_length),
    ]
    .into_iter()
    .try_fold(0_u64, checked_verification_operation_memory_add)
}

fn require_common_proof_verification_operation_resident_bound(
    resident_byte_length: u64,
) -> Result<(), CommonProofRuntimeError> {
    if resident_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
        return Err(CommonProofRuntimeError::AllocationLimitExceeded);
    }
    Ok(())
}

/// Process-local ownership registry between accepted suite/setup/board inputs
/// and the common verifier. Upstream owners attach one ordered statement-tree
/// batch to its application and mint evaluator handles from non-constructible
/// verified values. Verification consumes the exact application, its batch,
/// and all supplied handles atomically after a complete coordinate check; a
/// mismatch leaves every capability live for its owner.
pub(crate) struct CommonProofUpstreamInputRegistry {
    next_suite_handle: u32,
    next_application_handle: u32,
    next_preverification_application_source_handle: u32,
    next_verified_column_evaluator_handle: u32,
    suites: BTreeMap<u32, CommonProofSelectedSuiteEntry>,
    applications: BTreeMap<u32, CommonProofApplicationInputEntry>,
    preverification_application_sources:
        BTreeMap<u32, CommonProofPreverificationApplicationSourceEntry>,
    evaluator_roots: BTreeMap<u32, CommonProofEvaluatorAuxiliaryRootEntry>,
    verified_column_evaluators: BTreeMap<u32, CommonProofVerifiedColumnEvaluatorEntry>,
}

impl Default for CommonProofUpstreamInputRegistry {
    fn default() -> Self {
        Self {
            next_suite_handle: 1,
            next_application_handle: 1,
            next_preverification_application_source_handle: 1,
            next_verified_column_evaluator_handle: 1,
            suites: BTreeMap::new(),
            applications: BTreeMap::new(),
            preverification_application_sources: BTreeMap::new(),
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
            self.evaluator_roots.len(),
            self.verified_column_evaluators.len(),
        ])
    }

    /// Counts proof attempts, not the application-owned statement-tree batch
    /// or the root and evaluator handles owned by the same application. The
    /// separately retained handles are still included in `entry_count` and
    /// cannot outlive the worker-process ownership ceiling.
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
        canonical_suite_record_bytes: Vec<u8>,
    ) -> Result<CommonProofSelectedSuiteCapabilityHandle, CommonProofRuntimeError> {
        if canonical_suite_record_bytes.is_empty()
            || canonical_suite_record_bytes.len()
                > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
        {
            return Err(CommonProofRuntimeError::InvalidLimits);
        }
        self.require_entry_capacity()?;
        let handle = take_nonrepeating_handle(&mut self.next_suite_handle)?;
        self.suites.insert(
            handle,
            CommonProofSelectedSuiteEntry {
                capability,
                canonical_suite_record_bytes,
            },
        );
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

    pub(crate) fn canonical_suite_record_bytes(
        &self,
        handle: u32,
    ) -> Result<&[u8], CommonProofRuntimeError> {
        self.suites
            .get(&handle)
            .map(|entry| entry.canonical_suite_record_bytes.as_slice())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn preflight_statement_source_suite_binding(
        &self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: &VerifiedCommonProofStatementSource,
    ) -> Result<(), CommonProofRuntimeError> {
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
            || proof_byte_length > statement_source.limits.maximum_proof_byte_length()
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
        Ok(())
    }

    pub(crate) fn install_preverification_application_source(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
    ) -> Result<CommonProofPreverificationApplicationSourceHandle, CommonProofRuntimeError> {
        self.preflight_statement_source_suite_binding(suite_handle, &statement_source)?;
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
                statement_source: CommonProofVerificationStatementSource::from_exact(source),
                statement_owned_tree_batch: None,
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
        match self.consume_verification_inputs(&application_handle, &[], Some(&evaluator_handle)) {
            Ok(inputs) => Ok(inputs.prepare()),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    fn preflight_same_secret_row_code_whir_verification(
        &self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        evaluator_handle: &CommonProofVerifiedColumnEvaluatorCapabilityHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        let application = self
            .applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let evaluator = self
            .verified_column_evaluators
            .get(&evaluator_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if evaluator.application_handle != application_handle.0 {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }

        let verifier_accounting = exact_same_secret_verification_resident_memory_accounting(
            application.statement_source.relation_plan(),
            application
                .statement_source
                .proof_stream_descriptor()
                .total_byte_length,
            application
                .statement_source
                .canonical_application_statement_bytes(),
        )?;
        let evaluator_accounting = evaluator
            .evaluator
            .memory_accounting()
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        let proof_chunk_count = application
            .statement_source
            .proof_stream_descriptor()
            .ordered_chunk_digests
            .len();
        require_common_proof_verification_operation_resident_bound(
            common_proof_verification_operation_resident_byte_length_for_verifier(
                verifier_accounting.maximum_resident_byte_length(),
                evaluator_accounting,
                proof_chunk_count,
            )?,
        )
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
        match self.consume_verification_inputs(&application_handle, &[], None) {
            Ok(inputs) => Ok(inputs.prepare()),
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
        if let Err(error) =
            self.attach_statement_owned_tree_batch(&application_handle, statement_trees)
        {
            self.cancel_application(&application_handle)?;
            return Err(error);
        }
        match self.consume_verification_inputs(&application_handle, &[], None) {
            Ok(inputs) => Ok(inputs.prepare()),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    /// Validates an exact-family source and its complete verifier-recomputed
    /// tree/root catalog without consuming the unique source. A family can
    /// therefore reserve every downstream owner before the source leaves its
    /// reset-safe package catalog.
    pub(crate) fn preflight_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
        &self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: &VerifiedCommonProofStatementSource,
        statement_trees: &[VerifiedStatementOwnedTree],
        auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
    ) -> Result<(), CommonProofRuntimeError> {
        self.preflight_statement_source_suite_binding(suite_handle, statement_source)?;
        let selected_variant = statement_source
            .relation_plan
            .compiled_plan()
            .select_variant(
                statement_source.relation_plan.schedule_position,
                statement_source.relation_plan.top_count,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        if selected_variant.ordered_columns().iter().any(|column| {
            matches!(
                column.origin(),
                RelationColumnOrigin::VerifierSequence { .. }
            )
        }) {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let declared_proof_byte_length = usize::try_from(
            statement_source
                .proof_application_binding()
                .proof_stream_descriptor()
                .total_byte_length,
        )
        .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
        if declared_proof_byte_length > statement_source.limits.maximum_proof_byte_length() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let validation = prepare_row_code_whir_validation(
            statement_source,
            statement_trees,
            auxiliary_roots,
            None,
        )?;
        let verifier_resident_byte_length = validation
            .maximum_resident_byte_length()
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        let evaluator_memory_accounting = RefusingVerifiedColumnEvaluator
            .memory_accounting()
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        let proof_chunk_count = statement_source
            .application_source_authority()
            .proof_stream_descriptor()
            .ordered_chunk_digests
            .len();
        let verification_operation_resident_byte_length =
            common_proof_verification_operation_resident_byte_length(
                verifier_resident_byte_length,
                evaluator_memory_accounting,
                proof_chunk_count,
            )?;
        require_common_proof_verification_operation_resident_bound(
            verification_operation_resident_byte_length,
        )?;
        drop(validation);
        Ok(())
    }

    /// Consumes the exact source after the borrowed preflight and constructs
    /// the same prepared verifier without any fallible ownership transition.
    /// The repeated state-machine construction is deterministic for the
    /// preflighted inputs; an invariant failure is an implementation defect.
    pub(crate) fn prepare_preflighted_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
        &self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
        statement_trees: Vec<VerifiedStatementOwnedTree>,
        auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    ) -> super::PreparedCommonProofVerification {
        self.preflight_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
            suite_handle,
            &statement_source,
            &statement_trees,
            &auxiliary_roots,
        )
        .expect("preflighted common-proof verifier inputs remain valid during commit");
        ConsumedCommonProofVerificationInputs {
            statement_source: CommonProofVerificationStatementSource::from_exact(statement_source),
            statement_owned_trees: statement_trees,
            evaluator_auxiliary_roots: auxiliary_roots,
            verified_column_evaluator: Box::new(RefusingVerifiedColumnEvaluator),
        }
        .prepare()
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
        if let Err(error) =
            self.attach_statement_owned_tree_batch(&application_handle, statement_trees)
        {
            self.cancel_application(&application_handle)?;
            return Err(error);
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
        match self.consume_verification_inputs(&application_handle, &[], Some(&evaluator_handle)) {
            Ok(inputs) => Ok(inputs.prepare()),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    pub(in crate::bgv) fn prepare_setup_polynomial_bound_row_code_whir_verification(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
        statement_trees: Vec<VerifiedStatementOwnedTree>,
        verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
        prerequisite: VerifiedSetupPolynomialLowDegreePrerequisite,
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
        if let Err(error) =
            self.attach_statement_owned_tree_batch(&application_handle, statement_trees)
        {
            self.cancel_application(&application_handle)?;
            return Err(error);
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
        match self.consume_verification_inputs_with_setup_polynomial_prerequisite(
            &application_handle,
            &[],
            Some(&evaluator_handle),
            &prerequisite,
        ) {
            Ok(inputs) => inputs.prepare_with_setup_polynomial_prerequisite(prerequisite),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    pub(in crate::bgv) fn prepare_same_secret_row_code_whir_verification(
        &mut self,
        suite_handle: &CommonProofSelectedSuiteCapabilityHandle,
        statement_source: VerifiedCommonProofStatementSource,
        statement_trees: Vec<VerifiedStatementOwnedTree>,
        verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
        prerequisite: VerifiedSameSecretLowDegreePrerequisite,
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
        if let Err(error) =
            self.attach_statement_owned_tree_batch(&application_handle, statement_trees)
        {
            self.cancel_application(&application_handle)?;
            return Err(error);
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
        if let Err(error) = self.preflight_same_secret_row_code_whir_verification(
            &application_handle,
            &evaluator_handle,
        ) {
            self.cancel_application(&application_handle)?;
            return Err(error);
        }
        match self.consume_verification_inputs(&application_handle, &[], Some(&evaluator_handle)) {
            Ok(inputs) => inputs.prepare_exact_same_secret(prerequisite),
            Err(error) => {
                self.cancel_application(&application_handle)?;
                Err(error)
            }
        }
    }

    fn expected_statement_tree_count(
        &self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
    ) -> Result<usize, CommonProofRuntimeError> {
        let application = self
            .applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        let relation_plan = application.statement_source.relation_plan();
        let selected_variant = relation_plan
            .compiled_plan()
            .select_variant(relation_plan.schedule_position, relation_plan.top_count)
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
        Ok(selected_variant
            .ordered_trees()
            .iter()
            .filter(|tree| matches!(tree, RelationTreeDescriptor::BoundPublic { .. }))
            .count())
    }

    /// Attaches the complete ordered statement-tree catalog to its application
    /// in one transition. The batch is not a separately addressable registry
    /// object: it is validated with the application and can only be consumed
    /// when the complete verifier input is accepted.
    pub(crate) fn attach_statement_owned_tree_batch(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        ordered_trees: Vec<VerifiedStatementOwnedTree>,
    ) -> Result<(), CommonProofRuntimeError> {
        let expected_tree_count = self.expected_statement_tree_count(application_handle)?;
        if expected_tree_count == 0 || ordered_trees.len() != expected_tree_count {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let application = self
            .applications
            .get_mut(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if application.statement_owned_tree_batch.is_some() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        application.statement_owned_tree_batch = Some(ordered_trees);
        Ok(())
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
        evaluator_root_handles: &[&CommonProofEvaluatorAuxiliaryRootCapabilityHandle],
        verified_column_evaluator_handle: Option<
            &CommonProofVerifiedColumnEvaluatorCapabilityHandle,
        >,
    ) -> Result<ConsumedCommonProofVerificationInputs, CommonProofRuntimeError> {
        self.consume_verification_inputs_with_optional_setup_polynomial_prerequisite(
            application_handle,
            evaluator_root_handles,
            verified_column_evaluator_handle,
            None,
        )
    }

    fn consume_verification_inputs_with_setup_polynomial_prerequisite(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        evaluator_root_handles: &[&CommonProofEvaluatorAuxiliaryRootCapabilityHandle],
        verified_column_evaluator_handle: Option<
            &CommonProofVerifiedColumnEvaluatorCapabilityHandle,
        >,
        prerequisite: &VerifiedSetupPolynomialLowDegreePrerequisite,
    ) -> Result<ConsumedCommonProofVerificationInputs, CommonProofRuntimeError> {
        self.consume_verification_inputs_with_optional_setup_polynomial_prerequisite(
            application_handle,
            evaluator_root_handles,
            verified_column_evaluator_handle,
            Some(prerequisite),
        )
    }

    fn consume_verification_inputs_with_optional_setup_polynomial_prerequisite(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
        evaluator_root_handles: &[&CommonProofEvaluatorAuxiliaryRootCapabilityHandle],
        verified_column_evaluator_handle: Option<
            &CommonProofVerifiedColumnEvaluatorCapabilityHandle,
        >,
        setup_polynomial_prerequisite: Option<&VerifiedSetupPolynomialLowDegreePrerequisite>,
    ) -> Result<ConsumedCommonProofVerificationInputs, CommonProofRuntimeError> {
        let application = self
            .applications
            .get(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
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
        let relation_plan = application.statement_source.relation_plan();
        let selected_variant = relation_plan
            .compiled_plan()
            .select_variant(relation_plan.schedule_position, relation_plan.top_count)
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

        let statement_owned_trees = application
            .statement_owned_tree_batch
            .as_deref()
            .unwrap_or(&[]);
        let evaluator_auxiliary_roots = evaluator_root_handles
            .iter()
            .map(|handle| {
                self.evaluator_roots
                    .get(&handle.0)
                    .map(|entry| entry.root.clone())
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let declared_proof_byte_length = usize::try_from(
            application
                .statement_source
                .proof_stream_descriptor()
                .total_byte_length,
        )
        .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
        if declared_proof_byte_length
            > application
                .statement_source
                .limits()
                .maximum_proof_byte_length()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let validation = prepare_row_code_whir_validation(
            application.statement_source.exact_source()?,
            statement_owned_trees,
            &evaluator_auxiliary_roots,
            setup_polynomial_prerequisite,
        )?;
        let verifier_resident_byte_length = validation
            .maximum_resident_byte_length()
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        let evaluator_memory_accounting = match verified_column_evaluator_handle {
            Some(handle) => self
                .verified_column_evaluators
                .get(&handle.0)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
                .evaluator
                .memory_accounting()
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
            None => RefusingVerifiedColumnEvaluator
                .memory_accounting()
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
        };
        let proof_chunk_count = application
            .statement_source
            .proof_stream_descriptor()
            .ordered_chunk_digests
            .len();
        require_common_proof_verification_operation_resident_bound(
            common_proof_verification_operation_resident_byte_length(
                verifier_resident_byte_length,
                evaluator_memory_accounting,
                proof_chunk_count,
            )?,
        )?;
        drop(validation);

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
        let application = self
            .applications
            .remove(&application_handle.0)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        Ok(ConsumedCommonProofVerificationInputs {
            statement_source: application.statement_source,
            statement_owned_trees: application.statement_owned_tree_batch.unwrap_or_default(),
            evaluator_auxiliary_roots,
            verified_column_evaluator,
        })
    }

    pub(crate) fn cancel_application(
        &mut self,
        application_handle: &CommonProofApplicationInputCapabilityHandle,
    ) -> Result<(), CommonProofRuntimeError> {
        let application_was_present = self.applications.remove(&application_handle.0).is_some();
        self.evaluator_roots
            .retain(|_, entry| entry.application_handle != application_handle.0);
        self.verified_column_evaluators
            .retain(|_, entry| entry.application_handle != application_handle.0);
        if application_was_present {
            Ok(())
        } else {
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_evaluator_memory_accounting()
    -> super::super::VerifiedRelationColumnEvaluatorMemoryAccounting {
        super::super::VerifiedRelationColumnEvaluatorMemoryAccounting::new(0, 0, 0)
            .expect("zero-length evaluator accounting is valid")
    }

    #[test]
    fn successor_verifier_resident_accounting_includes_two_transport_chunks() {
        let resident_byte_length =
            common_proof_verification_operation_resident_byte_length_for_verifier(
                0,
                empty_evaluator_memory_accounting(),
                0,
            )
            .expect("account the bounded successor verifier operation");
        let two_chunk_payload_byte_length = u64::try_from(
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH * MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS,
        )
        .expect("the two-chunk payload length fits u64");

        assert!(resident_byte_length >= two_chunk_payload_byte_length);
    }

    #[test]
    fn successor_verifier_resident_accounting_refuses_overflow() {
        assert_eq!(
            common_proof_verification_operation_resident_byte_length_for_verifier(
                u64::MAX,
                empty_evaluator_memory_accounting(),
                0,
            ),
            Err(CommonProofRuntimeError::AllocationLimitExceeded)
        );
    }

    #[test]
    fn verifier_resident_bound_accepts_the_limit_and_rejects_one_byte_above_it() {
        require_common_proof_verification_operation_resident_bound(
            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        )
        .expect("the exact resident-memory limit remains admissible");
        assert_eq!(
            require_common_proof_verification_operation_resident_bound(
                MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH + 1,
            ),
            Err(CommonProofRuntimeError::AllocationLimitExceeded)
        );
    }
}
