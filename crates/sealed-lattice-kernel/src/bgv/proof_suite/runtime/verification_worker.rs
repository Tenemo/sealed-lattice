use super::{
    BTreeMap, CanonicalStreamReadbackVerifier, CanonicalStreamVerifier,
    CommonProofRequiredByteRange, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofVerificationBinding, CommonProofVerificationStatementSource, HASH_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS,
    RefusalReason, ResidentCommonProofByteSource, ResidentCommonProofInputChunk,
    VerifiedCanonicalStreamSummary, VerifiedCommonProof, VerifiedEvaluatorAuxiliaryRoot,
    VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree, required_chunk_indices,
};
use crate::bgv::proof_suite::row_code_whir::{
    ExactSameSecretFinalProofVerification, ExactSameSecretIncrementalVerification,
    PreparedExactSameSecretVerification, PreparedRowCodeWhirVerification,
    RowCodeWhirFinalProofVerification, RowCodeWhirIncrementalVerification,
    VerifiedSameSecretLowDegreePrerequisite, exact_same_secret_verification_runtime_limits,
    prepare_evaluator_source_bound_row_code_whir_verification,
    prepare_exact_same_secret_verification, prepare_row_code_whir_verification,
    prepare_setup_polynomial_bound_row_code_whir_verification,
};
use crate::bgv::{
    proof_suite::VerifiedRowCodeWhirProofFacts,
    setup::{
        VerifiedEvaluatorSourceLowDegreePrerequisite, VerifiedSetupPolynomialLowDegreePrerequisite,
    },
};

enum ConsumedSetupPolynomialBoundPrerequisite {
    PublicKeyShare(Box<VerifiedSetupPolynomialLowDegreePrerequisite>),
    EvaluatorSources(Box<VerifiedEvaluatorSourceLowDegreePrerequisite>),
}

/// One consumed set of positively verified inputs. This value is process local
/// and non-serializable. It can construct the persistent verifier, but it has
/// no constructor from statement roots, relation-plan bytes, or decoded proof
/// binding bytes.
pub(crate) struct ConsumedCommonProofVerificationInputs {
    pub(super) statement_source: CommonProofVerificationStatementSource,
    pub(super) statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    pub(super) evaluator_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    pub(super) verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
}

impl ConsumedCommonProofVerificationInputs {
    pub(crate) fn prepare(self) -> PreparedCommonProofVerification {
        self.prepare_row_code_whir(None)
            .expect("consumed row-code WHIR inputs passed complete validation")
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn prepare_exact_vss_evidence(
        self,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError> {
        self.prepare_row_code_whir(None)
    }

    pub(in crate::bgv) fn prepare_with_setup_polynomial_prerequisite(
        self,
        prerequisite: VerifiedSetupPolynomialLowDegreePrerequisite,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError> {
        self.prepare_row_code_whir(Some(
            ConsumedSetupPolynomialBoundPrerequisite::PublicKeyShare(Box::new(prerequisite)),
        ))
    }

    pub(in crate::bgv) fn prepare_with_evaluator_source_prerequisite(
        self,
        prerequisite: VerifiedEvaluatorSourceLowDegreePrerequisite,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError> {
        self.prepare_row_code_whir(Some(
            ConsumedSetupPolynomialBoundPrerequisite::EvaluatorSources(Box::new(prerequisite)),
        ))
    }

    fn prepare_row_code_whir(
        self,
        setup_polynomial_prerequisite: Option<ConsumedSetupPolynomialBoundPrerequisite>,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError> {
        let Self {
            statement_source,
            statement_owned_trees,
            evaluator_auxiliary_roots,
            verified_column_evaluator,
        } = self;
        let verification_binding = statement_source.verification_binding();
        let canonical_stream_verifier = CanonicalStreamVerifier::new(
            verification_binding.proof_application.proof_stream_domain,
            statement_source.proof_stream_descriptor().clone(),
        )
        .expect("the verified statement source retains one canonical proof descriptor");
        let exact_source = statement_source
            .exact_source()
            .expect("the verifier owns an exact family-minted statement source");
        let relation_plan = statement_source.relation_plan();
        if relation_plan
            .row_code_whir_construction_plan()
            .requires_verified_vss_bound_prerequisite()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let proof_application_binding = exact_source.proof_application_binding();
        let row_code_whir_verifier = match setup_polynomial_prerequisite {
            Some(ConsumedSetupPolynomialBoundPrerequisite::PublicKeyShare(prerequisite)) => {
                prepare_setup_polynomial_bound_row_code_whir_verification(
                    &prerequisite,
                    statement_source.protocol_version(),
                    proof_application_binding.application_slot(),
                    exact_source.canonical_application_statement_bytes(),
                    proof_application_binding.proof_header_hash(),
                    statement_source.proof_stream_descriptor().total_byte_length,
                    relation_plan,
                    statement_owned_trees,
                    evaluator_auxiliary_roots,
                    verified_column_evaluator,
                )
            }
            Some(ConsumedSetupPolynomialBoundPrerequisite::EvaluatorSources(prerequisite)) => {
                prepare_evaluator_source_bound_row_code_whir_verification(
                    &prerequisite,
                    statement_source.protocol_version(),
                    proof_application_binding.application_slot(),
                    exact_source.canonical_application_statement_bytes(),
                    proof_application_binding.proof_header_hash(),
                    statement_source.proof_stream_descriptor().total_byte_length,
                    relation_plan,
                    statement_owned_trees,
                    evaluator_auxiliary_roots,
                    verified_column_evaluator,
                )
            }
            None => prepare_row_code_whir_verification(
                statement_source.protocol_version(),
                proof_application_binding.application_slot(),
                exact_source.canonical_application_statement_bytes(),
                proof_application_binding.proof_header_hash(),
                statement_source.proof_stream_descriptor().total_byte_length,
                relation_plan,
                statement_owned_trees,
                evaluator_auxiliary_roots,
                verified_column_evaluator,
            ),
        }
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let verifier = PreparedCommonProofVerifier::RowCodeWhir {
            verifier: Box::new(row_code_whir_verifier),
            verified_proof_metadata: Box::new(row_code_whir_verified_proof_metadata(
                &statement_source,
                exact_source,
            )),
        };
        Ok(PreparedCommonProofVerification {
            statement_source,
            canonical_stream_verifier: Box::new(canonical_stream_verifier),
            verifier,
        })
    }

    pub(in crate::bgv) fn prepare_exact_same_secret(
        self,
        prerequisite: VerifiedSameSecretLowDegreePrerequisite,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError> {
        let verification_limits = exact_same_secret_verification_runtime_limits(
            self.statement_source.relation_plan(),
            self.statement_source
                .proof_stream_descriptor()
                .total_byte_length,
        )?;
        if !self.evaluator_auxiliary_roots.is_empty()
            || self.statement_source.limits() != verification_limits
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let exact_statement_source = self.statement_source.exact_source()?;
        let exact_verifier = prepare_exact_same_secret_verification(
            prerequisite,
            exact_statement_source,
            self.statement_owned_trees,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let verification_binding = self.statement_source.verification_binding();
        let relation_plan = self.statement_source.relation_plan();
        let verified_proof_metadata = RowCodeWhirVerifiedProofMetadata {
            protocol_version: self.statement_source.protocol_version(),
            suite_identifier: verification_binding.suite_identifier,
            application_statement_schema_identifier: verification_binding
                .proof_application
                .application_statement_schema_identifier,
            application_statement_hash: exact_statement_source
                .application_statement_hash()
                .into_bytes(),
            proof_header_hash: verification_binding.proof_application.proof_header_hash,
            row_code_whir_construction_plan_identity_hash: relation_plan
                .row_code_whir_construction_plan_identity_hash(),
            expected_verified_query_count: relation_plan.proof_query_count()?,
            relation_plan_variant_hash: relation_plan.relation_plan_variant_hash(),
            schedule_position: relation_plan.schedule_position,
            top_count: relation_plan.top_count,
        };
        let canonical_stream_verifier = CanonicalStreamVerifier::new(
            verification_binding.proof_application.proof_stream_domain,
            self.statement_source.proof_stream_descriptor().clone(),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        drop(self.verified_column_evaluator);
        Ok(PreparedCommonProofVerification {
            statement_source: self.statement_source,
            canonical_stream_verifier: Box::new(canonical_stream_verifier),
            verifier: PreparedCommonProofVerifier::ExactSameSecret {
                verifier: Box::new(exact_verifier),
                verified_proof_metadata: Box::new(verified_proof_metadata),
            },
        })
    }
}

struct RowCodeWhirVerifiedProofMetadata {
    protocol_version: u16,
    suite_identifier: [u8; HASH_BYTE_LENGTH],
    application_statement_schema_identifier: u16,
    application_statement_hash: [u8; HASH_BYTE_LENGTH],
    proof_header_hash: [u8; HASH_BYTE_LENGTH],
    row_code_whir_construction_plan_identity_hash: [u8; HASH_BYTE_LENGTH],
    expected_verified_query_count: u32,
    relation_plan_variant_hash: [u8; HASH_BYTE_LENGTH],
    schedule_position: Option<u32>,
    top_count: Option<u16>,
}

fn row_code_whir_verified_proof_metadata(
    statement_source: &CommonProofVerificationStatementSource,
    exact_source: &super::VerifiedCommonProofStatementSource,
) -> RowCodeWhirVerifiedProofMetadata {
    let verification_binding = statement_source.verification_binding();
    let relation_plan = statement_source.relation_plan();
    RowCodeWhirVerifiedProofMetadata {
        protocol_version: statement_source.protocol_version(),
        suite_identifier: verification_binding.suite_identifier,
        application_statement_schema_identifier: verification_binding
            .proof_application
            .application_statement_schema_identifier,
        application_statement_hash: exact_source.application_statement_hash().into_bytes(),
        proof_header_hash: verification_binding.proof_application.proof_header_hash,
        row_code_whir_construction_plan_identity_hash: relation_plan
            .row_code_whir_construction_plan_identity_hash(),
        expected_verified_query_count: relation_plan
            .proof_query_count()
            .expect("the checked query count fits u32"),
        relation_plan_variant_hash: relation_plan.relation_plan_variant_hash(),
        schedule_position: relation_plan.schedule_position(),
        top_count: relation_plan.top_count(),
    }
}

enum PreparedCommonProofVerifier {
    ExactSameSecret {
        verifier: Box<PreparedExactSameSecretVerification>,
        verified_proof_metadata: Box<RowCodeWhirVerifiedProofMetadata>,
    },
    RowCodeWhir {
        verifier: Box<PreparedRowCodeWhirVerification>,
        verified_proof_metadata: Box<RowCodeWhirVerifiedProofMetadata>,
    },
}

/// Fully owned verifier input assembled only from upstream capabilities. The
/// generated-WASM boundary can retain this value behind an opaque handle, but
/// cannot construct one from proof bytes, roots, or a relation-plan record.
pub(crate) struct PreparedCommonProofVerification {
    statement_source: CommonProofVerificationStatementSource,
    canonical_stream_verifier: Box<CanonicalStreamVerifier>,
    verifier: PreparedCommonProofVerifier,
}

impl PreparedCommonProofVerification {
    pub(crate) fn verification_binding_hash(&self) -> [u8; HASH_BYTE_LENGTH] {
        self.statement_source.verification_binding().binding_hash()
    }

    #[cfg(test)]
    pub(crate) fn statement_source(
        &self,
    ) -> Result<&super::VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
        self.statement_source.exact_source()
    }

    #[cfg(test)]
    pub(crate) fn into_statement_source(
        self,
    ) -> Result<super::VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
        self.statement_source.into_exact_source()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofVerificationWorkerPoll {
    NeedsReadback {
        first_chunk_index: u32,
        second_chunk_index: Option<u32>,
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
    Verifier,
}

impl From<CommonProofRuntimeError> for CommonProofVerificationWorkerError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

enum ActiveCommonProofVerifier {
    ExactSameSecret {
        phase: ExactSameSecretActiveVerificationPhase,
        verified_proof_metadata: Box<RowCodeWhirVerifiedProofMetadata>,
    },
    RowCodeWhir {
        phase: RowCodeWhirActiveVerificationPhase,
        verified_proof_metadata: Box<RowCodeWhirVerifiedProofMetadata>,
    },
}

enum ExactSameSecretActiveVerificationPhase {
    Decoding(Box<ExactSameSecretIncrementalVerification>),
    AbsorbingFinalProof(Box<ExactSameSecretFinalProofVerification>),
    Verified(Box<VerifiedCommonProof>),
    Transitioning,
}

enum RowCodeWhirActiveVerificationPhase {
    Decoding(Box<RowCodeWhirIncrementalVerification>),
    AbsorbingFinalProof(Box<RowCodeWhirFinalProofVerification>),
    Verified(Box<VerifiedCommonProof>),
    Transitioning,
}

impl ActiveCommonProofVerifier {
    fn required_byte_range(
        &self,
        declared_proof_byte_length: usize,
    ) -> Result<Option<CommonProofRequiredByteRange>, CommonProofRuntimeError> {
        match self {
            Self::ExactSameSecret { phase, .. } => {
                let consumed_byte_length = match phase {
                    ExactSameSecretActiveVerificationPhase::Decoding(verifier) => {
                        if verifier.is_decoding_complete() {
                            return Ok(None);
                        }
                        verifier.decoded_byte_length()
                    }
                    ExactSameSecretActiveVerificationPhase::AbsorbingFinalProof(verifier) => {
                        verifier.absorbed_byte_length()
                    }
                    ExactSameSecretActiveVerificationPhase::Verified(_) => return Ok(None),
                    ExactSameSecretActiveVerificationPhase::Transitioning => {
                        return Err(CommonProofRuntimeError::WrongOperationPhase);
                    }
                };
                let remaining_byte_length = declared_proof_byte_length
                    .checked_sub(consumed_byte_length)
                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
                if remaining_byte_length == 0 {
                    return Ok(None);
                }
                let byte_length = remaining_byte_length.min(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH);
                CommonProofRequiredByteRange::new(consumed_byte_length, byte_length)
                    .ok_or(CommonProofRuntimeError::InvalidLimits)
                    .map(Some)
            }
            Self::RowCodeWhir { phase, .. } => {
                let consumed_byte_length = match phase {
                    RowCodeWhirActiveVerificationPhase::Decoding(verifier) => {
                        if verifier.is_decoding_complete() {
                            return Ok(None);
                        }
                        verifier.decoded_byte_length()
                    }
                    RowCodeWhirActiveVerificationPhase::AbsorbingFinalProof(verifier) => {
                        verifier.absorbed_byte_length()
                    }
                    RowCodeWhirActiveVerificationPhase::Verified(_) => return Ok(None),
                    RowCodeWhirActiveVerificationPhase::Transitioning => {
                        return Err(CommonProofRuntimeError::WrongOperationPhase);
                    }
                };
                let remaining_byte_length = declared_proof_byte_length
                    .checked_sub(consumed_byte_length)
                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
                if remaining_byte_length == 0 {
                    return Ok(None);
                }
                let byte_length = remaining_byte_length.min(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH);
                CommonProofRequiredByteRange::new(consumed_byte_length, byte_length)
                    .ok_or(CommonProofRuntimeError::InvalidLimits)
                    .map(Some)
            }
        }
    }

    fn cancel(&mut self) {}
}

enum CommonProofVerificationWorkerPhase {
    Ingesting {
        canonical_stream_verifier: Box<CanonicalStreamVerifier>,
        verifier: PreparedCommonProofVerifier,
    },
    Verifying {
        readback_verifier: Box<CanonicalStreamReadbackVerifier>,
        verifier: ActiveCommonProofVerifier,
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
    pub(super) limits: CommonProofRuntimeLimits,
    proof_byte_length: usize,
    phase: CommonProofVerificationWorkerPhase,
    last_accounted_required_range: Option<super::CommonProofRequiredByteRange>,
    readback_accounting: CommonProofVerificationReadbackAccounting,
}

impl CommonProofVerificationWorker {
    pub(super) fn new(
        prepared: PreparedCommonProofVerification,
    ) -> (CommonProofVerificationStatementSource, Self) {
        let verification_binding = prepared.statement_source.verification_binding();
        let limits = prepared.statement_source.limits();
        let proof_byte_length = usize::try_from(
            prepared
                .statement_source
                .proof_stream_descriptor()
                .total_byte_length,
        )
        .expect("the verified proof stream length fits the local address space");
        let statement_source = prepared.statement_source;
        (
            statement_source,
            Self {
                verification_binding,
                limits,
                proof_byte_length,
                phase: CommonProofVerificationWorkerPhase::Ingesting {
                    canonical_stream_verifier: prepared.canonical_stream_verifier,
                    verifier: prepared.verifier,
                },
                last_accounted_required_range: None,
                readback_accounting: CommonProofVerificationReadbackAccounting::default(),
            },
        )
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
        let verifier = match verifier {
            PreparedCommonProofVerifier::ExactSameSecret {
                verifier,
                verified_proof_metadata,
            } => {
                let verifier = (*verifier)
                    .into_incremental()
                    .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                ActiveCommonProofVerifier::ExactSameSecret {
                    phase: ExactSameSecretActiveVerificationPhase::Decoding(Box::new(verifier)),
                    verified_proof_metadata,
                }
            }
            PreparedCommonProofVerifier::RowCodeWhir {
                verifier,
                verified_proof_metadata,
            } => {
                let verifier = (*verifier)
                    .into_incremental()
                    .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                ActiveCommonProofVerifier::RowCodeWhir {
                    phase: RowCodeWhirActiveVerificationPhase::Decoding(Box::new(verifier)),
                    verified_proof_metadata,
                }
            }
        };
        self.phase = CommonProofVerificationWorkerPhase::Verifying {
            readback_verifier: Box::new(readback_verifier),
            verifier,
            resident_chunks: BTreeMap::new(),
        };
        Ok(())
    }

    fn required_readback_chunks(
        required_range: CommonProofRequiredByteRange,
    ) -> Result<(usize, Option<usize>), CommonProofRuntimeError> {
        required_chunk_indices(required_range)
    }

    pub(super) fn supply_readback_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofVerificationWorkerError> {
        let required_range = match &self.phase {
            CommonProofVerificationWorkerPhase::Verifying { verifier, .. } => verifier
                .required_byte_range(self.proof_byte_length)?
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
        let _ = verifier;
        let (first_chunk_index, second_chunk_index) =
            Self::required_readback_chunks(required_range)?;
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
        loop {
            let required_range = match &self.phase {
                CommonProofVerificationWorkerPhase::Verifying { verifier, .. } => {
                    verifier.required_byte_range(self.proof_byte_length)?
                }
                _ => return Err(CommonProofRuntimeError::WrongOperationPhase.into()),
            };
            let Some(required_range) = required_range else {
                let CommonProofVerificationWorkerPhase::Verifying { verifier, .. } =
                    &mut self.phase
                else {
                    return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                };
                if let ActiveCommonProofVerifier::ExactSameSecret {
                    phase,
                    verified_proof_metadata,
                } = verifier
                {
                    match phase {
                        ExactSameSecretActiveVerificationPhase::Decoding(decoder)
                            if decoder.is_decoding_complete() =>
                        {
                            let owned_phase = core::mem::replace(
                                phase,
                                ExactSameSecretActiveVerificationPhase::Transitioning,
                            );
                            let ExactSameSecretActiveVerificationPhase::Decoding(decoder) =
                                owned_phase
                            else {
                                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                            };
                            let final_proof_verification = decoder
                                .finish_decoding()
                                .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                            *phase = ExactSameSecretActiveVerificationPhase::AbsorbingFinalProof(
                                Box::new(final_proof_verification),
                            );
                            continue;
                        }
                        ExactSameSecretActiveVerificationPhase::AbsorbingFinalProof(
                            final_proof_verification,
                        ) if final_proof_verification.absorbed_byte_length()
                            == self.proof_byte_length =>
                        {
                            let owned_phase = core::mem::replace(
                                phase,
                                ExactSameSecretActiveVerificationPhase::Transitioning,
                            );
                            let ExactSameSecretActiveVerificationPhase::AbsorbingFinalProof(
                                final_proof_verification,
                            ) = owned_phase
                            else {
                                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                            };
                            let metrics = final_proof_verification
                                .finish()
                                .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                            let verified_query_count = u32::try_from(metrics.query_count)
                                .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
                            if metrics.proof_byte_length != self.proof_byte_length
                                || verified_query_count
                                    != verified_proof_metadata.expected_verified_query_count
                            {
                                return Err(
                                    CommonProofRuntimeError::WrongVerificationBinding.into()
                                );
                            }
                            *phase = ExactSameSecretActiveVerificationPhase::Verified(Box::new(
                                VerifiedCommonProof::from_verified_row_code_whir(
                                    VerifiedRowCodeWhirProofFacts {
                                        protocol_version: verified_proof_metadata.protocol_version,
                                        suite_identifier: verified_proof_metadata.suite_identifier,
                                        application_statement_schema_identifier:
                                            verified_proof_metadata
                                                .application_statement_schema_identifier,
                                        application_statement_hash: verified_proof_metadata
                                            .application_statement_hash,
                                        proof_header_hash: verified_proof_metadata
                                            .proof_header_hash,
                                        proof_byte_length: u64::try_from(metrics.proof_byte_length)
                                            .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
                                        verified_query_count,
                                        row_code_whir_construction_plan_identity_hash:
                                            verified_proof_metadata
                                                .row_code_whir_construction_plan_identity_hash,
                                        relation_plan_variant_hash: verified_proof_metadata
                                            .relation_plan_variant_hash,
                                        schedule_position: verified_proof_metadata
                                            .schedule_position,
                                        top_count: verified_proof_metadata.top_count,
                                    },
                                ),
                            ));
                        }
                        ExactSameSecretActiveVerificationPhase::Verified(_) => {}
                        _ => {
                            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                        }
                    }
                }
                if let ActiveCommonProofVerifier::RowCodeWhir {
                    phase,
                    verified_proof_metadata,
                } = verifier
                {
                    match phase {
                        RowCodeWhirActiveVerificationPhase::Decoding(decoder)
                            if decoder.is_decoding_complete() =>
                        {
                            let owned_phase = core::mem::replace(
                                phase,
                                RowCodeWhirActiveVerificationPhase::Transitioning,
                            );
                            let RowCodeWhirActiveVerificationPhase::Decoding(decoder) = owned_phase
                            else {
                                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                            };
                            let final_proof_verification = decoder
                                .finish_decoding()
                                .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                            *phase = RowCodeWhirActiveVerificationPhase::AbsorbingFinalProof(
                                Box::new(final_proof_verification),
                            );
                            continue;
                        }
                        RowCodeWhirActiveVerificationPhase::AbsorbingFinalProof(
                            final_proof_verification,
                        ) if final_proof_verification.absorbed_byte_length()
                            == self.proof_byte_length =>
                        {
                            let owned_phase = core::mem::replace(
                                phase,
                                RowCodeWhirActiveVerificationPhase::Transitioning,
                            );
                            let RowCodeWhirActiveVerificationPhase::AbsorbingFinalProof(
                                final_proof_verification,
                            ) = owned_phase
                            else {
                                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                            };
                            let metrics = final_proof_verification
                                .finish()
                                .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                            let verified_query_count = u32::try_from(metrics.query_count)
                                .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
                            if metrics.proof_byte_length != self.proof_byte_length
                                || verified_query_count
                                    != verified_proof_metadata.expected_verified_query_count
                            {
                                return Err(
                                    CommonProofRuntimeError::WrongVerificationBinding.into()
                                );
                            }
                            *phase = RowCodeWhirActiveVerificationPhase::Verified(Box::new(
                                VerifiedCommonProof::from_verified_row_code_whir(
                                    VerifiedRowCodeWhirProofFacts {
                                        protocol_version: verified_proof_metadata.protocol_version,
                                        suite_identifier: verified_proof_metadata.suite_identifier,
                                        application_statement_schema_identifier:
                                            verified_proof_metadata
                                                .application_statement_schema_identifier,
                                        application_statement_hash: verified_proof_metadata
                                            .application_statement_hash,
                                        proof_header_hash: verified_proof_metadata
                                            .proof_header_hash,
                                        proof_byte_length: u64::try_from(metrics.proof_byte_length)
                                            .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
                                        verified_query_count,
                                        row_code_whir_construction_plan_identity_hash:
                                            verified_proof_metadata
                                                .row_code_whir_construction_plan_identity_hash,
                                        relation_plan_variant_hash: verified_proof_metadata
                                            .relation_plan_variant_hash,
                                        schedule_position: verified_proof_metadata
                                            .schedule_position,
                                        top_count: verified_proof_metadata.top_count,
                                    },
                                ),
                            ));
                        }
                        RowCodeWhirActiveVerificationPhase::Verified(_) => {}
                        _ => return Err(CommonProofRuntimeError::WrongOperationPhase.into()),
                    }
                }
                return Ok(CommonProofVerificationWorkerPoll::Complete);
            };
            self.account_required_range(required_range)?;
            let CommonProofVerificationWorkerPhase::Verifying {
                verifier,
                resident_chunks,
                ..
            } = &mut self.phase
            else {
                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
            };
            let (first_chunk_index, second_chunk_index) =
                Self::required_readback_chunks(required_range)?;
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
            match verifier {
                ActiveCommonProofVerifier::ExactSameSecret { phase, .. } => {
                    match phase {
                        ExactSameSecretActiveVerificationPhase::Decoding(decoder) => {
                            if required_range.offset() != decoder.decoded_byte_length() {
                                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                            }
                            let resident_input_chunks = resident_chunks
                                .iter()
                                .map(|(chunk_index, bytes)| {
                                    chunk_index
                                        .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                                        .map(|offset| {
                                            ResidentCommonProofInputChunk::new(offset, bytes)
                                        })
                                        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            let source = ResidentCommonProofByteSource::new(
                                self.proof_byte_length,
                                resident_input_chunks,
                            )?;
                            let available_end_offset = required_range
                                .offset()
                                .checked_add(required_range.byte_length())
                                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                            decoder
                                .consume_available(&source, available_end_offset)
                                .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                        }
                        ExactSameSecretActiveVerificationPhase::AbsorbingFinalProof(
                            final_proof_verification,
                        ) => {
                            if required_range.offset()
                                != final_proof_verification.absorbed_byte_length()
                            {
                                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                            }
                            let required_end_offset = required_range
                                .offset()
                                .checked_add(required_range.byte_length())
                                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                            for chunk_index in [Some(first_chunk_index), second_chunk_index]
                                .into_iter()
                                .flatten()
                            {
                                let chunk = resident_chunks
                                    .get(&chunk_index)
                                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
                                let chunk_offset = chunk_index
                                    .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                                    .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                                let chunk_end_offset = chunk_offset
                                    .checked_add(chunk.len())
                                    .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                                let intersection_start = required_range.offset().max(chunk_offset);
                                let intersection_end = required_end_offset.min(chunk_end_offset);
                                if intersection_start >= intersection_end {
                                    return Err(
                                        CommonProofRuntimeError::WrongVerificationBinding.into()
                                    );
                                }
                                let local_start = intersection_start - chunk_offset;
                                let local_end = intersection_end - chunk_offset;
                                final_proof_verification
                                    .absorb(&chunk[local_start..local_end])
                                    .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                            }
                            if final_proof_verification.absorbed_byte_length()
                                != required_end_offset
                            {
                                return Err(
                                    CommonProofRuntimeError::WrongVerificationBinding.into()
                                );
                            }
                        }
                        ExactSameSecretActiveVerificationPhase::Verified(_)
                        | ExactSameSecretActiveVerificationPhase::Transitioning => {
                            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                        }
                    }
                    resident_chunks.clear();
                    self.last_accounted_required_range = None;
                }
                ActiveCommonProofVerifier::RowCodeWhir { phase, .. } => {
                    match phase {
                        RowCodeWhirActiveVerificationPhase::Decoding(decoder) => {
                            if required_range.offset() != decoder.decoded_byte_length() {
                                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                            }
                            let resident_input_chunks = resident_chunks
                                .iter()
                                .map(|(chunk_index, bytes)| {
                                    chunk_index
                                        .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                                        .map(|offset| {
                                            ResidentCommonProofInputChunk::new(offset, bytes)
                                        })
                                        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            let source = ResidentCommonProofByteSource::new(
                                self.proof_byte_length,
                                resident_input_chunks,
                            )?;
                            let available_end_offset = required_range
                                .offset()
                                .checked_add(required_range.byte_length())
                                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                            decoder
                                .consume_available(&source, available_end_offset)
                                .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                        }
                        RowCodeWhirActiveVerificationPhase::AbsorbingFinalProof(
                            final_proof_verification,
                        ) => {
                            if required_range.offset()
                                != final_proof_verification.absorbed_byte_length()
                            {
                                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                            }
                            let required_end_offset = required_range
                                .offset()
                                .checked_add(required_range.byte_length())
                                .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                            for chunk_index in [Some(first_chunk_index), second_chunk_index]
                                .into_iter()
                                .flatten()
                            {
                                let chunk = resident_chunks
                                    .get(&chunk_index)
                                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
                                let chunk_offset = chunk_index
                                    .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                                    .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                                let chunk_end_offset = chunk_offset
                                    .checked_add(chunk.len())
                                    .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
                                let intersection_start = required_range.offset().max(chunk_offset);
                                let intersection_end = required_end_offset.min(chunk_end_offset);
                                if intersection_start >= intersection_end {
                                    return Err(
                                        CommonProofRuntimeError::WrongVerificationBinding.into()
                                    );
                                }
                                let local_start = intersection_start - chunk_offset;
                                let local_end = intersection_end - chunk_offset;
                                final_proof_verification
                                    .absorb(&chunk[local_start..local_end])
                                    .map_err(|_| CommonProofVerificationWorkerError::Verifier)?;
                            }
                            if final_proof_verification.absorbed_byte_length()
                                != required_end_offset
                            {
                                return Err(
                                    CommonProofRuntimeError::WrongVerificationBinding.into()
                                );
                            }
                        }
                        RowCodeWhirActiveVerificationPhase::Verified(_)
                        | RowCodeWhirActiveVerificationPhase::Transitioning => {
                            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                        }
                    }
                    resident_chunks.clear();
                    self.last_accounted_required_range = None;
                }
            }
        }
    }

    pub(super) fn finish(
        mut self,
    ) -> Result<
        (VerifiedCommonProof, VerifiedCanonicalStreamSummary),
        CommonProofVerificationWorkerError,
    > {
        let phase = core::mem::replace(
            &mut self.phase,
            CommonProofVerificationWorkerPhase::Cancelled,
        );
        let CommonProofVerificationWorkerPhase::Verifying {
            readback_verifier,
            verifier,
            resident_chunks,
            ..
        } = phase
        else {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        };
        if !resident_chunks.is_empty() {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        }
        let proof = match verifier {
            ActiveCommonProofVerifier::ExactSameSecret {
                phase: ExactSameSecretActiveVerificationPhase::Verified(proof),
                ..
            } => *proof,
            ActiveCommonProofVerifier::ExactSameSecret { .. } => {
                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
            }
            ActiveCommonProofVerifier::RowCodeWhir {
                phase: RowCodeWhirActiveVerificationPhase::Verified(proof),
                ..
            } => *proof,
            ActiveCommonProofVerifier::RowCodeWhir { .. } => {
                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
            }
        };
        let verified_stream = readback_verifier
            .finish()
            .into_result()
            .map_err(CommonProofVerificationWorkerError::Stream)?;
        Ok((proof, verified_stream))
    }

    pub(super) fn cancel(&mut self) {
        match &mut self.phase {
            CommonProofVerificationWorkerPhase::Ingesting { .. } => {}
            CommonProofVerificationWorkerPhase::Verifying { verifier, .. } => verifier.cancel(),
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
