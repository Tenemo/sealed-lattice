use super::{
    BTreeMap, CanonicalStreamReadbackVerifier, CanonicalStreamVerifier,
    CommonProofRelationPlanCapability, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofVerificationBinding, CommonProofVerificationPoll,
    CommonProofVerificationStateMachine, CommonProofVerifierError, HASH_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS, PollableCommonProofVerificationInput,
    RefusalReason, ResidentCommonProofByteSource, ResidentCommonProofInputChunk, StreamDescriptor,
    VerifiedCanonicalStreamSummary, VerifiedCommonProof, VerifiedEvaluatorAuxiliaryRoot,
    VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree, required_chunk_indices,
};

/// One consumed set of positively verified inputs. This value is process local
/// and non-serializable. It can construct the persistent verifier, but it has
/// no constructor from statement roots, relation-plan bytes, or decoded proof
/// binding bytes.
pub(crate) struct ConsumedCommonProofVerificationInputs {
    pub(super) verification_binding: CommonProofVerificationBinding,
    pub(super) relation_plan: CommonProofRelationPlanCapability,
    pub(super) protocol_version: u16,
    pub(super) canonical_application_statement_bytes: Vec<u8>,
    pub(super) proof_stream_descriptor: StreamDescriptor,
    pub(super) statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    pub(super) evaluator_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    pub(super) verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    pub(super) limits: CommonProofRuntimeLimits,
}

impl ConsumedCommonProofVerificationInputs {
    pub(crate) const fn verification_binding(&self) -> CommonProofVerificationBinding {
        self.verification_binding
    }

    pub(crate) const fn relation_plan(&self) -> &CommonProofRelationPlanCapability {
        &self.relation_plan
    }

    pub(crate) const fn proof_stream_descriptor(&self) -> &StreamDescriptor {
        &self.proof_stream_descriptor
    }

    pub(crate) fn pollable_verification_input(&self) -> PollableCommonProofVerificationInput<'_> {
        PollableCommonProofVerificationInput {
            protocol_version: self.protocol_version,
            suite_identifier: self.verification_binding.suite_identifier,
            canonical_application_statement_bytes: &self.canonical_application_statement_bytes,
            relation_plan: &self.relation_plan.relation_plan,
            relation_context: &self.relation_plan.relation_context,
            schedule_position: self.relation_plan.schedule_position,
            top_count: self.relation_plan.top_count,
            statement_owned_trees: &self.statement_owned_trees,
            evaluator_auxiliary_roots: &self.evaluator_auxiliary_roots,
            declared_proof_byte_length: self.limits.proof_byte_length(),
            proof_byte_ceiling: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
            maximum_resident_window_byte_length: MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
                .checked_mul(MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS)
                .unwrap_or(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH),
        }
    }

    pub(crate) fn prepare(
        self,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError> {
        let verifier = CommonProofVerificationStateMachine::new(self.pollable_verification_input())
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        Ok(PreparedCommonProofVerification {
            verification_binding: self.verification_binding,
            relation_plan: self.relation_plan,
            proof_stream_descriptor: self.proof_stream_descriptor,
            verifier,
            verified_column_evaluator: self.verified_column_evaluator,
            limits: self.limits,
        })
    }
}

/// Fully owned verifier input assembled only from upstream capabilities. The
/// generated-WASM boundary can retain this value behind an opaque handle, but
/// cannot construct one from proof bytes, roots, or a relation-plan record.
pub(crate) struct PreparedCommonProofVerification {
    verification_binding: CommonProofVerificationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    proof_stream_descriptor: StreamDescriptor,
    verifier: CommonProofVerificationStateMachine,
    verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    limits: CommonProofRuntimeLimits,
}

impl PreparedCommonProofVerification {
    pub(crate) fn verification_binding_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.verification_binding.binding_hash()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofVerificationWorkerPoll {
    NeedsReadback {
        first_chunk_index: u32,
        second_chunk_index: Option<u32>,
    },
    PrefixAccepted,
    QueryHeaderAccepted,
    QueryTreeAccepted {
        catalog_index: u16,
    },
    Complete,
}

/// Process-local readback traffic observed by one verifier worker. This is a
/// measurement diagnostic only: it is neither serialized nor bound into a
/// proof, verification result, or capability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommonProofVerificationReadbackAccounting {
    logical_required_range_count: u64,
    logical_required_byte_length: u64,
    supplied_full_chunk_count: u64,
    supplied_full_chunk_byte_length: u64,
}

impl CommonProofVerificationReadbackAccounting {
    pub(crate) const fn logical_required_range_count(self) -> u64 {
        self.logical_required_range_count
    }

    pub(crate) const fn logical_required_byte_length(self) -> u64 {
        self.logical_required_byte_length
    }

    pub(crate) const fn supplied_full_chunk_count(self) -> u64 {
        self.supplied_full_chunk_count
    }

    pub(crate) const fn supplied_full_chunk_byte_length(self) -> u64 {
        self.supplied_full_chunk_byte_length
    }

    fn record_logical_required_range(
        &mut self,
        byte_length: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        let byte_length = u64::try_from(byte_length)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.logical_required_range_count = self
            .logical_required_range_count
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.logical_required_byte_length = self
            .logical_required_byte_length
            .checked_add(byte_length)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        Ok(())
    }

    fn record_supplied_full_chunk(
        &mut self,
        byte_length: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        let byte_length = u64::try_from(byte_length)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.supplied_full_chunk_count = self
            .supplied_full_chunk_count
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.supplied_full_chunk_byte_length = self
            .supplied_full_chunk_byte_length
            .checked_add(byte_length)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum CommonProofVerificationWorkerError {
    Runtime(CommonProofRuntimeError),
    Stream(RefusalReason),
    Verifier(CommonProofVerifierError),
}

impl From<CommonProofRuntimeError> for CommonProofVerificationWorkerError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

enum CommonProofVerificationWorkerPhase {
    Ingesting {
        canonical_stream_verifier: Box<CanonicalStreamVerifier>,
        verifier: Box<CommonProofVerificationStateMachine>,
        verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
    },
    Verifying {
        readback_verifier: Box<CanonicalStreamReadbackVerifier>,
        verifier: Box<CommonProofVerificationStateMachine>,
        verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
        resident_chunks: BTreeMap<usize, Vec<u8>>,
    },
    Cancelled,
}

/// One owned, bounded verification operation. Proof bytes are first checked
/// as one canonical sequential stream, then reread from browser storage only
/// through descriptor-authenticated full chunks. The cryptographic decoder
/// sees at most two resident chunks and never receives a caller verdict.
pub(super) struct CommonProofVerificationWorker {
    pub(super) verification_binding: CommonProofVerificationBinding,
    relation_plan: CommonProofRelationPlanCapability,
    proof_stream_descriptor: StreamDescriptor,
    pub(super) limits: CommonProofRuntimeLimits,
    phase: CommonProofVerificationWorkerPhase,
    last_accounted_required_range: Option<super::CommonProofRequiredByteRange>,
    readback_accounting: CommonProofVerificationReadbackAccounting,
}

impl CommonProofVerificationWorker {
    pub(super) fn new(
        prepared: PreparedCommonProofVerification,
    ) -> Result<Self, CommonProofVerificationWorkerError> {
        let stream_domain = prepared
            .verification_binding
            .proof_application
            .proof_stream_domain;
        let canonical_stream_verifier =
            CanonicalStreamVerifier::new(stream_domain, prepared.proof_stream_descriptor.clone())
                .map_err(CommonProofVerificationWorkerError::Stream)?;
        Ok(Self {
            verification_binding: prepared.verification_binding,
            relation_plan: prepared.relation_plan,
            proof_stream_descriptor: prepared.proof_stream_descriptor,
            limits: prepared.limits,
            phase: CommonProofVerificationWorkerPhase::Ingesting {
                canonical_stream_verifier: Box::new(canonical_stream_verifier),
                verifier: Box::new(prepared.verifier),
                verified_column_evaluator: prepared.verified_column_evaluator,
            },
            last_accounted_required_range: None,
            readback_accounting: CommonProofVerificationReadbackAccounting::default(),
        })
    }

    pub(crate) const fn readback_accounting(&self) -> CommonProofVerificationReadbackAccounting {
        self.readback_accounting
    }

    fn account_required_range(
        &mut self,
        required_range: super::CommonProofRequiredByteRange,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.last_accounted_required_range == Some(required_range) {
            return Ok(());
        }
        self.readback_accounting
            .record_logical_required_range(required_range.byte_length())?;
        self.last_accounted_required_range = Some(required_range);
        Ok(())
    }

    pub(super) fn absorb_input_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofVerificationWorkerError> {
        let CommonProofVerificationWorkerPhase::Ingesting {
            canonical_stream_verifier,
            ..
        } = &mut self.phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        canonical_stream_verifier
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .map_err(CommonProofVerificationWorkerError::Stream)
    }

    pub(super) fn finish_input(&mut self) -> Result<(), CommonProofVerificationWorkerError> {
        let phase = core::mem::replace(
            &mut self.phase,
            CommonProofVerificationWorkerPhase::Cancelled,
        );
        let CommonProofVerificationWorkerPhase::Ingesting {
            canonical_stream_verifier,
            verifier,
            verified_column_evaluator,
        } = phase
        else {
            self.phase = phase;
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        let verified_summary = canonical_stream_verifier
            .finish_with_summary()
            .into_result()
            .map_err(CommonProofVerificationWorkerError::Stream)?;
        let readback_verifier = CanonicalStreamReadbackVerifier::new(
            self.verification_binding
                .proof_application
                .proof_stream_domain,
            verified_summary,
        )
        .map_err(CommonProofVerificationWorkerError::Stream)?;
        self.phase = CommonProofVerificationWorkerPhase::Verifying {
            readback_verifier: Box::new(readback_verifier),
            verifier,
            verified_column_evaluator,
            resident_chunks: BTreeMap::new(),
        };
        Ok(())
    }

    fn required_readback_chunks(
        verifier: &CommonProofVerificationStateMachine,
    ) -> Result<(usize, Option<usize>), CommonProofRuntimeError> {
        let required_range = verifier
            .required_byte_range()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        required_chunk_indices(required_range)
    }

    pub(super) fn supply_readback_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofVerificationWorkerError> {
        let required_range = match &self.phase {
            CommonProofVerificationWorkerPhase::Verifying { verifier, .. } => verifier
                .required_byte_range()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
            _ => return Err(CommonProofRuntimeError::WrongOperationPhase.into()),
        };
        self.account_required_range(required_range)?;
        let CommonProofVerificationWorkerPhase::Verifying {
            readback_verifier,
            verifier,
            resident_chunks,
            ..
        } = &mut self.phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        let (first_chunk_index, second_chunk_index) = Self::required_readback_chunks(verifier)?;
        if chunk_index != first_chunk_index && Some(chunk_index) != second_chunk_index {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        readback_verifier
            .authenticate_chunk(chunk_index, chunk_bytes)
            .map_err(CommonProofVerificationWorkerError::Stream)?;
        self.readback_accounting
            .record_supplied_full_chunk(chunk_bytes.len())?;
        if let Some(existing) = resident_chunks.get(&chunk_index) {
            if existing != chunk_bytes {
                return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
            }
            return Ok(());
        }
        if resident_chunks.len() >= MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded.into());
        }
        let mut owned_chunk = Vec::new();
        owned_chunk
            .try_reserve_exact(chunk_bytes.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        owned_chunk.extend_from_slice(chunk_bytes);
        resident_chunks.insert(chunk_index, owned_chunk);
        Ok(())
    }

    pub(super) fn poll(
        &mut self,
    ) -> Result<CommonProofVerificationWorkerPoll, CommonProofVerificationWorkerError> {
        let required_range = match &self.phase {
            CommonProofVerificationWorkerPhase::Verifying { verifier, .. } => {
                verifier.required_byte_range()
            }
            _ => return Err(CommonProofRuntimeError::WrongOperationPhase.into()),
        };
        let Some(required_range) = required_range else {
            return Ok(CommonProofVerificationWorkerPoll::Complete);
        };
        self.account_required_range(required_range)?;
        let CommonProofVerificationWorkerPhase::Verifying {
            verifier,
            verified_column_evaluator,
            resident_chunks,
            ..
        } = &mut self.phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        let (first_chunk_index, second_chunk_index) = Self::required_readback_chunks(verifier)?;
        if !resident_chunks.contains_key(&first_chunk_index)
            || second_chunk_index.is_some_and(|index| !resident_chunks.contains_key(&index))
        {
            return Ok(CommonProofVerificationWorkerPoll::NeedsReadback {
                first_chunk_index: u32::try_from(first_chunk_index)
                    .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
                second_chunk_index: second_chunk_index
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
            });
        }
        let resident_input_chunks = resident_chunks
            .iter()
            .map(|(chunk_index, bytes)| {
                chunk_index
                    .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                    .map(|offset| ResidentCommonProofInputChunk::new(offset, bytes))
                    .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source = ResidentCommonProofByteSource::new(
            self.limits.proof_byte_length(),
            resident_input_chunks,
        )?;
        let result = verifier
            .poll(&source, verified_column_evaluator.as_mut())
            .map_err(CommonProofVerificationWorkerError::Verifier)?;
        resident_chunks.clear();
        self.last_accounted_required_range = None;
        match result {
            CommonProofVerificationPoll::PrefixAccepted => {
                Ok(CommonProofVerificationWorkerPoll::PrefixAccepted)
            }
            CommonProofVerificationPoll::QueryHeaderAccepted => {
                Ok(CommonProofVerificationWorkerPoll::QueryHeaderAccepted)
            }
            CommonProofVerificationPoll::QueryTreeAccepted { catalog_index } => {
                Ok(CommonProofVerificationWorkerPoll::QueryTreeAccepted { catalog_index })
            }
            CommonProofVerificationPoll::Complete => {
                Ok(CommonProofVerificationWorkerPoll::Complete)
            }
        }
    }

    pub(super) fn finish(
        mut self,
    ) -> Result<
        (
            CommonProofVerificationBinding,
            CommonProofRelationPlanCapability,
            VerifiedCommonProof,
            VerifiedCanonicalStreamSummary,
        ),
        CommonProofVerificationWorkerError,
    > {
        let phase = core::mem::replace(
            &mut self.phase,
            CommonProofVerificationWorkerPhase::Cancelled,
        );
        let CommonProofVerificationWorkerPhase::Verifying {
            readback_verifier,
            mut verifier,
            resident_chunks,
            ..
        } = phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        if !resident_chunks.is_empty() {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        }
        let proof = verifier
            .take_verified_common_proof()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let verified_stream = readback_verifier
            .finish()
            .into_result()
            .map_err(CommonProofVerificationWorkerError::Stream)?;
        Ok((
            self.verification_binding,
            self.relation_plan,
            proof,
            verified_stream,
        ))
    }

    pub(super) fn cancel(&mut self) {
        match &mut self.phase {
            CommonProofVerificationWorkerPhase::Ingesting { verifier, .. }
            | CommonProofVerificationWorkerPhase::Verifying { verifier, .. } => verifier.cancel(),
            CommonProofVerificationWorkerPhase::Cancelled => {}
        }
        self.phase = CommonProofVerificationWorkerPhase::Cancelled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readback_accounting_records_exact_logical_and_supplied_bytes() {
        let mut accounting = CommonProofVerificationReadbackAccounting::default();
        accounting
            .record_logical_required_range(17)
            .expect("the logical range fits the diagnostic counters");
        accounting
            .record_logical_required_range(31)
            .expect("the second logical range fits the diagnostic counters");
        accounting
            .record_supplied_full_chunk(64)
            .expect("the supplied chunk fits the diagnostic counters");
        accounting
            .record_supplied_full_chunk(64)
            .expect("an exact repeated chunk remains observable traffic");

        assert_eq!(accounting.logical_required_range_count(), 2);
        assert_eq!(accounting.logical_required_byte_length(), 48);
        assert_eq!(accounting.supplied_full_chunk_count(), 2);
        assert_eq!(accounting.supplied_full_chunk_byte_length(), 128);
    }
}
