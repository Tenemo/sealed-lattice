//! Generated-WASM boundary for installing the operative common-proof suite.
//!
//! A schema-valid suite record is data, not authority. This boundary mints a
//! process-local handle only after the canonical record passes the complete
//! selected-suite derivation. Exact-family operations remain fail-closed until
//! an accepted board object derives the verifier statement and the family owns
//! its private-witness or verified-input capability. There is no alternate
//! fixture suite or raw-plan export.

use core::{mem::size_of, slice};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

use crate::foundation::{
    AuthenticatedCheckpointContinuationSource, CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512,
    LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH, RefusalReason, SelectedSuiteCapability,
    StreamDescriptor, SuiteRecord, VerifiedBoardApplicationSource,
    resolve_browser_worker_authenticated_storage_head_source,
    resolve_browser_worker_authenticated_storage_transition_source, select_suite_record,
};

use super::runtime::{
    CommonProofVerificationReadbackAccounting, ExpectedCommonProofPackageBindings,
    common_proof_registry_entry_count, require_common_proof_worker_process_admission_capacity,
    require_common_proof_worker_process_ownership_limits,
};
use super::{
    AuthenticatedCommonProofGenerationCheckpoint, BorrowedVerifiedCommonProofCapability,
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, CommonProofAuthenticatedSourceReadRequest,
    CommonProofGenerationExternalMemoryAccounting, CommonProofGenerationOperationHandle,
    CommonProofGenerationPreparationError, CommonProofGenerationWorkerError,
    CommonProofGenerationWorkerPoll, CommonProofRuntimeError, CommonProofRuntimeRegistry,
    CommonProofUpstreamInputRegistry, CommonProofVerificationOperationHandle,
    CommonProofVerificationWorkerError, CommonProofVerificationWorkerPoll,
    ConsumedVerifiedCommonProofCapability, DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH,
    ExactSameSecretAuthenticatedTranscriptPrefixRequest, GeneratedCommonProofCapabilityHandle,
    PendingCommonProofAuthorizationHandle, PreparedCommonProofGeneration,
    PreparedCommonProofVerification, PreparedExactSameSecretTranscriptPrefix,
    VerifiedCommonProofCapabilityHandle, durable_authorization_frame_digest,
};

const NO_SECOND_POLL_VALUE: u32 = u32::MAX;
const VERIFICATION_POLL_NEEDS_READBACK: u32 = 1;
const VERIFICATION_POLL_COMPLETE: u32 = 5;
const GENERATION_POLL_PROGRESS: u32 = 1;
const GENERATION_POLL_STORAGE_REQUEST_READY: u32 = 2;
const GENERATION_POLL_OUTPUT_CHUNK_READY: u32 = 3;
const GENERATION_POLL_OUTPUT_READBACK_REQUIRED: u32 = 4;
const GENERATION_POLL_COMPLETE: u32 = 5;
const GENERATION_POLL_CANCELLED: u32 = 6;
const GENERATION_POLL_RESUME_COMPLETE: u32 = 7;
const GENERATION_POLL_AUTHENTICATED_SOURCE_READ_READY: u32 = 8;
const GENERATION_POLL_AUTHENTICATED_TRANSCRIPT_PREFIX_REQUIRED: u32 = 9;
const AUTHENTICATED_SOURCE_READ_REQUEST_BYTE_LENGTH: usize = 160;
const GENERATION_EXTERNAL_MEMORY_ACCOUNTING_WORD_COUNT: usize = 20;
const GENERATION_EXTERNAL_MEMORY_ACCOUNTING_BYTE_LENGTH: usize =
    GENERATION_EXTERNAL_MEMORY_ACCOUNTING_WORD_COUNT * size_of::<u64>();
const VERIFICATION_READBACK_ACCOUNTING_WORD_COUNT: usize = 4;
const VERIFICATION_READBACK_ACCOUNTING_BYTE_LENGTH: usize =
    VERIFICATION_READBACK_ACCOUNTING_WORD_COUNT * size_of::<u64>();

fn write_diagnostic_u64(output: &mut [u8], word_index: usize, value: u64) {
    let offset = word_index * size_of::<u64>();
    output[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
}

fn encode_generation_external_memory_accounting(
    accounting: CommonProofGenerationExternalMemoryAccounting,
) -> [u8; GENERATION_EXTERNAL_MEMORY_ACCOUNTING_BYTE_LENGTH] {
    let requirement = accounting.compiled_requirement();
    let actual = accounting.actual_usage();
    let prefix = accounting.deterministic_prefix_replay_usage();
    let mut output = [0_u8; GENERATION_EXTERNAL_MEMORY_ACCOUNTING_BYTE_LENGTH];
    let values = [
        u64::from(requirement.step_count()),
        u64::from(requirement.maximum_chunk_byte_length()),
        requirement.maximum_transaction_payload_byte_length(),
        u64::from(requirement.distinct_physical_object_count()),
        u64::from(requirement.object_lifecycle_count()),
        requirement.peak_stored_byte_length(),
        requirement.total_written_byte_length(),
        requirement.total_read_byte_length(),
        requirement.transaction_count(),
        actual.total_written_byte_length(),
        actual.total_read_byte_length(),
        actual.peak_stored_byte_length(),
        actual.transaction_count(),
        u64::from(actual.deleted_object_count()),
        if prefix.is_some() { 1 } else { 0 },
        prefix.map_or(0, |usage| usage.total_written_byte_length()),
        prefix.map_or(0, |usage| usage.total_read_byte_length()),
        prefix.map_or(0, |usage| usage.peak_stored_byte_length()),
        prefix.map_or(0, |usage| usage.transaction_count()),
        prefix.map_or(0, |usage| u64::from(usage.deleted_object_count())),
    ];
    for (word_index, value) in values.into_iter().enumerate() {
        write_diagnostic_u64(&mut output, word_index, value);
    }
    output
}

fn encode_verification_readback_accounting(
    accounting: CommonProofVerificationReadbackAccounting,
) -> [u8; VERIFICATION_READBACK_ACCOUNTING_BYTE_LENGTH] {
    let mut output = [0_u8; VERIFICATION_READBACK_ACCOUNTING_BYTE_LENGTH];
    let values = [
        accounting.logical_required_range_count(),
        accounting.logical_required_byte_length(),
        accounting.supplied_full_chunk_count(),
        accounting.supplied_full_chunk_byte_length(),
    ];
    for (word_index, value) in values.into_iter().enumerate() {
        write_diagnostic_u64(&mut output, word_index, value);
    }
    output
}

fn encode_authenticated_source_read_request(
    request: CommonProofAuthenticatedSourceReadRequest,
) -> [u8; AUTHENTICATED_SOURCE_READ_REQUEST_BYTE_LENGTH] {
    let mut encoded = [0_u8; AUTHENTICATED_SOURCE_READ_REQUEST_BYTE_LENGTH];
    encoded[..64].copy_from_slice(&request.source_material_root());
    encoded[64..128].copy_from_slice(&request.source_stream_digest());
    encoded[128..136].copy_from_slice(&request.source_stream_total_byte_length().to_le_bytes());
    encoded[136..144].copy_from_slice(&request.source_stream_byte_offset().to_le_bytes());
    encoded[144..152].copy_from_slice(&request.storage_byte_offset().to_le_bytes());
    encoded[152..156].copy_from_slice(&request.source_byte_length().to_le_bytes());
    encoded[156..160].copy_from_slice(&request.authentication_chunk_index().to_le_bytes());
    encoded
}

#[unsafe(no_mangle)]
pub const extern "C" fn sealed_lattice_common_proof_generation_authenticated_source_request_byte_length()
-> u32 {
    AUTHENTICATED_SOURCE_READ_REQUEST_BYTE_LENGTH as u32
}

#[unsafe(no_mangle)]
pub const extern "C" fn sealed_lattice_common_proof_generation_checkpoint_state_byte_length() -> u32
{
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH as u32
}

#[unsafe(no_mangle)]
pub const extern "C" fn sealed_lattice_common_proof_generation_external_memory_accounting_byte_length()
-> u32 {
    GENERATION_EXTERNAL_MEMORY_ACCOUNTING_BYTE_LENGTH as u32
}

#[unsafe(no_mangle)]
pub const extern "C" fn sealed_lattice_common_proof_verification_readback_accounting_byte_length()
-> u32 {
    VERIFICATION_READBACK_ACCOUNTING_BYTE_LENGTH as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofGenerationFamilyAdapterDescription {
    application_statement_schema_identifier: u16,
    common_proof_runtime_binding_hash: [u8; 64],
    common_proof_generation_authorization_hash: [u8; 64],
    proof_attempt_lineage_identifier: [u8; 32],
}

impl CommonProofGenerationFamilyAdapterDescription {
    pub(crate) const fn new(
        application_statement_schema_identifier: u16,
        common_proof_runtime_binding_hash: [u8; 64],
        common_proof_generation_authorization_hash: [u8; 64],
        proof_attempt_lineage_identifier: [u8; 32],
    ) -> Self {
        Self {
            application_statement_schema_identifier,
            common_proof_runtime_binding_hash,
            common_proof_generation_authorization_hash,
            proof_attempt_lineage_identifier,
        }
    }

    pub(crate) const fn common_proof_runtime_binding_hash(self) -> [u8; 64] {
        self.common_proof_runtime_binding_hash
    }

    pub(crate) const fn application_statement_schema_identifier(self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn common_proof_generation_authorization_hash(self) -> [u8; 64] {
        self.common_proof_generation_authorization_hash
    }

    pub(crate) const fn proof_attempt_lineage_identifier(self) -> [u8; 32] {
        self.proof_attempt_lineage_identifier
    }
}

type ResumeCommonProofGenerationPreparation = Box<
    dyn FnOnce(
        AuthenticatedCheckpointContinuationSource,
    ) -> Result<PreparedCommonProofGeneration, CommonProofGenerationPreparationError>,
>;

pub(crate) struct ResumeCommonProofGenerationFamilyAdapter {
    checkpoint_lineage_identifier: [u8; 32],
    checkpoint_schedule_digest: Hash512,
    description: CommonProofGenerationFamilyAdapterDescription,
    prepare: ResumeCommonProofGenerationPreparation,
}

/// Deferred exact-family prover preparation retained entirely inside Rust.
/// Resume adapters receive continuation authority only after the browser store
/// authenticates and the generic boundary canonically decodes the checkpoint.
pub(crate) enum CommonProofGenerationFamilyAdapter {
    Fresh {
        prepared: Box<PreparedCommonProofGeneration>,
    },
    Resume(Box<ResumeCommonProofGenerationFamilyAdapter>),
}

impl CommonProofGenerationFamilyAdapter {
    pub(crate) fn fresh(prepared: PreparedCommonProofGeneration) -> Self {
        Self::Fresh {
            prepared: Box::new(prepared),
        }
    }

    pub(crate) fn resume(
        description: CommonProofGenerationFamilyAdapterDescription,
        checkpoint_lineage_identifier: [u8; 32],
        checkpoint_schedule_digest: Hash512,
        prepare: ResumeCommonProofGenerationPreparation,
    ) -> Self {
        Self::Resume(Box::new(ResumeCommonProofGenerationFamilyAdapter {
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
            description,
            prepare,
        }))
    }

    pub(crate) fn description(&self) -> CommonProofGenerationFamilyAdapterDescription {
        match self {
            Self::Fresh { prepared } => CommonProofGenerationFamilyAdapterDescription::new(
                prepared.application_statement_schema_identifier(),
                prepared.runtime_binding_hash(),
                prepared.generation_authorization_hash(),
                prepared.proof_attempt_lineage_identifier(),
            ),
            Self::Resume(adapter) => adapter.description,
        }
    }

    fn checkpoint_lineage_identifier(&self) -> [u8; 32] {
        match self {
            Self::Fresh { prepared } => prepared.checkpoint_lineage_identifier(),
            Self::Resume(adapter) => adapter.checkpoint_lineage_identifier,
        }
    }

    fn prepare(
        self,
        authenticated_checkpoint: Option<AuthenticatedCommonProofGenerationCheckpoint>,
    ) -> Result<PreparedCommonProofGeneration, CommonProofGenerationPreparationError> {
        let description = self.description();
        let prepared = match (self, authenticated_checkpoint) {
            (Self::Fresh { prepared }, None) => *prepared,
            (Self::Resume(adapter), Some(checkpoint)) => {
                if checkpoint.stable_attempt_binding_hash()
                    != description.common_proof_runtime_binding_hash
                    || checkpoint.checkpoint_lineage_identifier()
                        != adapter.checkpoint_lineage_identifier
                    || checkpoint.checkpoint_schedule_digest() != adapter.checkpoint_schedule_digest
                {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
                }
                let prepared = (adapter.prepare)(checkpoint.continuation_source())?;
                if !prepared.matches_authenticated_checkpoint(&checkpoint) {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
                }
                prepared
            }
            _ => return Err(CommonProofRuntimeError::WrongVerificationBinding.into()),
        };
        if prepared.application_statement_schema_identifier()
            != description.application_statement_schema_identifier
            || prepared.runtime_binding_hash() != description.common_proof_runtime_binding_hash
            || prepared.generation_authorization_hash()
                != description.common_proof_generation_authorization_hash
            || prepared.proof_attempt_lineage_identifier()
                != description.proof_attempt_lineage_identifier
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        Ok(prepared)
    }
}

/// Exact-family verifier preparation retained until the generic worker starts
/// positive verification over the authenticated committed proof stream.
pub(crate) struct CommonProofVerificationFamilyAdapter {
    prepared: PreparedCommonProofVerification,
}

impl CommonProofVerificationFamilyAdapter {
    pub(crate) const fn new(prepared: PreparedCommonProofVerification) -> Self {
        Self { prepared }
    }

    fn verification_binding_hash(&self) -> [u8; 64] {
        self.prepared.verification_binding_hash()
    }

    #[cfg(test)]
    fn statement_source(
        &self,
    ) -> Result<&super::VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
        self.prepared.statement_source()
    }

    #[cfg(test)]
    fn into_statement_source(
        self,
    ) -> Result<super::VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
        self.prepared.into_statement_source()
    }
}

thread_local! {
    static COMMON_PROOF_WASM_RUNTIME_REGISTRY: RefCell<CommonProofWasmRuntimeRegistry> =
        RefCell::new(CommonProofWasmRuntimeRegistry::default());
}

struct CommonProofWasmRuntimeRegistry {
    next_generation_family_adapter_handle: u32,
    next_verification_family_adapter_handle: u32,
    next_prepared_generation_handle: u32,
    next_prepared_verification_handle: u32,
    generation_family_adapters: BTreeMap<u32, CommonProofGenerationFamilyAdapter>,
    verification_family_adapters: BTreeMap<u32, CommonProofVerificationFamilyAdapter>,
    prepared_generations: BTreeMap<u32, PreparedCommonProofGeneration>,
    prepared_verifications: BTreeMap<u32, PreparedCommonProofVerification>,
    generation_preparation_reservations: BTreeSet<u32>,
    verification_family_adapter_reservations: BTreeSet<u32>,
    runtime: CommonProofRuntimeRegistry,
    upstream_inputs: CommonProofUpstreamInputRegistry,
}

impl Default for CommonProofWasmRuntimeRegistry {
    fn default() -> Self {
        Self {
            next_generation_family_adapter_handle: 1,
            next_verification_family_adapter_handle: 1,
            next_prepared_generation_handle: 1,
            next_prepared_verification_handle: 1,
            generation_family_adapters: BTreeMap::new(),
            verification_family_adapters: BTreeMap::new(),
            prepared_generations: BTreeMap::new(),
            prepared_verifications: BTreeMap::new(),
            generation_preparation_reservations: BTreeSet::new(),
            verification_family_adapter_reservations: BTreeSet::new(),
            runtime: CommonProofRuntimeRegistry::default(),
            upstream_inputs: CommonProofUpstreamInputRegistry::default(),
        }
    }
}

impl CommonProofWasmRuntimeRegistry {
    fn ffi_entry_count(&self) -> Result<usize, CommonProofRuntimeError> {
        common_proof_registry_entry_count(&[
            self.generation_family_adapters.len(),
            self.verification_family_adapters.len(),
            self.prepared_generations.len(),
            self.prepared_verifications.len(),
            self.generation_preparation_reservations.len(),
            self.verification_family_adapter_reservations.len(),
        ])
    }

    fn ffi_heavy_operation_count(&self) -> Result<usize, CommonProofRuntimeError> {
        self.ffi_entry_count()
    }

    fn require_new_entry_capacity(
        &self,
        admits_heavy_operation: bool,
    ) -> Result<(), CommonProofRuntimeError> {
        require_common_proof_worker_process_admission_capacity(
            &[
                self.ffi_entry_count()?,
                self.runtime.entry_count()?,
                self.upstream_inputs.entry_count()?,
            ],
            &[
                self.ffi_heavy_operation_count()?,
                self.runtime.heavy_operation_count()?,
                self.upstream_inputs.heavy_operation_count()?,
            ],
            admits_heavy_operation,
        )
    }

    fn require_neutral_transfer_capacity(&self) -> Result<(), CommonProofRuntimeError> {
        require_common_proof_worker_process_ownership_limits(
            &[
                self.ffi_entry_count()?,
                self.runtime.entry_count()?,
                self.upstream_inputs.entry_count()?,
            ],
            &[
                self.ffi_heavy_operation_count()?,
                self.runtime.heavy_operation_count()?,
                self.upstream_inputs.heavy_operation_count()?,
            ],
        )
    }

    fn issue_prepared_generation_handle(&mut self) -> Result<u32, CommonProofRuntimeError> {
        let handle = self.next_prepared_generation_handle;
        if handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.next_prepared_generation_handle = self
            .next_prepared_generation_handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        Ok(handle)
    }

    fn issue_prepared_verification_handle(&mut self) -> Result<u32, CommonProofRuntimeError> {
        let handle = self.next_prepared_verification_handle;
        if handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.next_prepared_verification_handle = self
            .next_prepared_verification_handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        Ok(handle)
    }

    fn retain_generation_family_adapter(
        &mut self,
        adapter: CommonProofGenerationFamilyAdapter,
    ) -> Result<u32, CommonProofRuntimeError> {
        self.require_new_entry_capacity(true)?;
        let handle = self.next_generation_family_adapter_handle;
        if handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.next_generation_family_adapter_handle = self
            .next_generation_family_adapter_handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.generation_family_adapters.insert(handle, adapter);
        Ok(handle)
    }

    fn retain_verification_family_adapter(
        &mut self,
        adapter: CommonProofVerificationFamilyAdapter,
    ) -> Result<u32, CommonProofRuntimeError> {
        self.require_new_entry_capacity(true)?;
        let handle = self.issue_verification_family_adapter_handle()?;
        self.verification_family_adapters.insert(handle, adapter);
        Ok(handle)
    }

    fn issue_verification_family_adapter_handle(&mut self) -> Result<u32, CommonProofRuntimeError> {
        let handle = self.next_verification_family_adapter_handle;
        if handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.next_verification_family_adapter_handle = self
            .next_verification_family_adapter_handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        Ok(handle)
    }
}

/// Retains a deferred exact-family prover adapter. The generic worker can
/// describe it before storage routing, but only authenticated checkpoint state
/// can activate a resume adapter.
pub(crate) fn retain_common_proof_generation_family_adapter(
    adapter: CommonProofGenerationFamilyAdapter,
) -> Result<u32, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .retain_generation_family_adapter(adapter)
    })
}

/// Borrows one selected-suite capability through its live process-local
/// handle. Exact-family factories can derive their owned adapters inside the
/// callback, but cannot copy, enumerate, or reconstruct suite authority from
/// transported suite bytes.
pub(crate) fn with_common_proof_selected_suite<Output>(
    suite_handle_identifier: u32,
    inspect: impl FnOnce(&SelectedSuiteCapability) -> Output,
) -> Result<Output, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let handle = super::CommonProofSelectedSuiteCapabilityHandle::from_identifier(
            suite_handle_identifier,
        );
        registry
            .upstream_inputs
            .selected_suite(&handle)
            .map(inspect)
    })
}

/// Retains one exact-family verifier adapter assembled from positive upstream
/// capabilities. Proof bytes cannot construct this adapter.
#[cfg(test)]
pub(crate) fn retain_common_proof_verification_family_adapter(
    adapter: CommonProofVerificationFamilyAdapter,
) -> Result<u32, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .retain_verification_family_adapter(adapter)
    })
}

/// Builds and retains one exact-family verifier while the selected-suite and
/// board-derived application capabilities remain inside the common-proof
/// registry. The callback cannot access decoded proof bytes and must consume
/// its upstream inputs into a fully prepared verifier before returning.
pub(crate) fn retain_common_proof_verification_family_adapter_from_upstream(
    prepare: impl FnOnce(
        &mut CommonProofUpstreamInputRegistry,
    ) -> Result<PreparedCommonProofVerification, CommonProofRuntimeError>,
) -> Result<u32, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.require_new_entry_capacity(true)?;
        let prepared = prepare(&mut registry.upstream_inputs)?;
        registry
            .retain_verification_family_adapter(CommonProofVerificationFamilyAdapter::new(prepared))
    })
}

/// Reserves the sole common-runtime destination needed by an exact-family
/// verifier before that family consumes its unique package-owned source.
pub(crate) fn reserve_common_proof_verification_family_adapter()
-> Result<u32, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.require_new_entry_capacity(true)?;
        let handle = registry.issue_verification_family_adapter_handle()?;
        if !registry
            .verification_family_adapter_reservations
            .insert(handle)
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        Ok(handle)
    })
}

/// Runs a borrowed exact-family validation while its reserved common-runtime
/// destination remains live. The callback cannot consume package authority.
pub(crate) fn preflight_reserved_common_proof_verification_family_adapter_from_upstream<Output>(
    reservation_handle: u32,
    preflight: impl FnOnce(&CommonProofUpstreamInputRegistry) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        if !registry
            .verification_family_adapter_reservations
            .contains(&reservation_handle)
        {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        preflight(&registry.upstream_inputs)
    })
}

/// Commits one reserved adapter through an infallible ownership transition.
/// All source, tree, and auxiliary-root validation must have completed through
/// the borrowed preflight before this function is called.
pub(crate) fn commit_reserved_common_proof_verification_family_adapter_from_upstream(
    reservation_handle: u32,
    prepare: impl FnOnce(&CommonProofUpstreamInputRegistry) -> PreparedCommonProofVerification,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        assert!(
            registry
                .verification_family_adapter_reservations
                .remove(&reservation_handle),
            "reserved common-proof verifier adapter remains live during commit"
        );
        let prepared = prepare(&registry.upstream_inputs);
        assert!(
            registry
                .verification_family_adapters
                .insert(
                    reservation_handle,
                    CommonProofVerificationFamilyAdapter::new(prepared),
                )
                .is_none(),
            "reserved common-proof verifier handle is unique"
        );
        reservation_handle
    })
}

pub(crate) fn cancel_common_proof_verification_family_adapter_reservation(
    reservation_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        if registry
            .borrow_mut()
            .verification_family_adapter_reservations
            .remove(&reservation_handle)
        {
            Ok(())
        } else {
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        }
    })
}

/// Restores the exact family-minted statement source from an adapter that did
/// not enter the generic worker. The fallible destination preflight runs while
/// the adapter remains retained; only the infallible callback receives source
/// ownership, so a rejected destination leaves the same adapter retryable.
#[cfg(test)]
pub(crate) fn preflight_and_restore_common_proof_verification_family_adapter_statement_source<
    Preflight,
    Output,
>(
    adapter_handle: u32,
    preflight: impl FnOnce(
        &super::VerifiedCommonProofStatementSource,
    ) -> Result<Preflight, CommonProofRuntimeError>,
    restore: impl FnOnce(super::VerifiedCommonProofStatementSource, Preflight) -> Output,
) -> Result<Output, CommonProofRuntimeError> {
    let preflight = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let source = registry
            .verification_family_adapters
            .get(&adapter_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .statement_source()?;
        preflight(source)
    })?;
    let source = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .verification_family_adapters
            .remove(&adapter_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .into_statement_source()
    })?;
    Ok(restore(source, preflight))
}

/// Restores the exact family-minted statement source from a prepared verifier
/// that never entered the browser worker. The prepared handle stays live when
/// destination preflight refuses the transition.
#[cfg(test)]
pub(crate) fn preflight_and_restore_prepared_common_proof_verification_statement_source<
    Preflight,
    Output,
>(
    prepared_handle: u32,
    preflight: impl FnOnce(
        &super::VerifiedCommonProofStatementSource,
    ) -> Result<Preflight, CommonProofRuntimeError>,
    restore: impl FnOnce(super::VerifiedCommonProofStatementSource, Preflight) -> Output,
) -> Result<Output, CommonProofRuntimeError> {
    let preflight = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let source = registry
            .prepared_verifications
            .get(&prepared_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .statement_source()?;
        preflight(source)
    })?;
    let source = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .prepared_verifications
            .remove(&prepared_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?
            .into_statement_source()
    })?;
    Ok(restore(source, preflight))
}

/// Cancels an active, cancelled, or failed verifier operation and restores its
/// original family-minted statement source. A verifier refusal may consume its
/// decoder state, but it never consumes this independent linear authority.
#[cfg(test)]
pub(crate) fn preflight_and_restore_common_proof_verification_operation_statement_source<
    Preflight,
    Output,
>(
    operation_handle: u32,
    preflight: impl FnOnce(
        &super::VerifiedCommonProofStatementSource,
    ) -> Result<Preflight, CommonProofRuntimeError>,
    restore: impl FnOnce(super::VerifiedCommonProofStatementSource, Preflight) -> Output,
) -> Result<Output, CommonProofRuntimeError> {
    let operation_handle =
        CommonProofVerificationOperationHandle::from_identifier(operation_handle);
    let preflight = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .runtime
            .with_verification_statement_source(operation_handle, preflight)
    })??;
    let source = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .cancel_operation_and_take_statement_source(operation_handle)
    })?;
    Ok(restore(source, preflight))
}

/// Transfers one genuinely completed verifier capability into an exact-family
/// terminal consumer. The callback receives process-local authority, never
/// decoded proof bytes or a caller-supplied verification claim. A callback
/// error is terminal: the consumed verifier authority is not restored.
pub(crate) fn consume_verified_common_proof_with_family_terminal<Output>(
    handle: &VerifiedCommonProofCapabilityHandle,
    consume: impl FnOnce(
        ConsumedVerifiedCommonProofCapability,
    ) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    let capability = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .consume_verified_proof_for_protocol(handle)
    })?;
    consume(capability)
}

/// Runs every fallible exact-family and destination check while the generic
/// verifier capability remains retained, then retires the handle and performs
/// an infallible typed-terminal commit. A rejected preflight is retryable with
/// the same verifier handle.
pub(crate) fn preflight_and_consume_verified_common_proof_with_family_terminal<
    Preflight,
    Output,
>(
    handle: &VerifiedCommonProofCapabilityHandle,
    preflight: impl FnOnce(
        BorrowedVerifiedCommonProofCapability<'_>,
    ) -> Result<Preflight, CommonProofRuntimeError>,
    consume: impl FnOnce(ConsumedVerifiedCommonProofCapability, Preflight) -> Output,
) -> Result<Output, CommonProofRuntimeError> {
    let preflight = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .runtime
            .with_verified_proof_for_protocol(handle, preflight)
    })??;
    let capability = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .consume_verified_proof_for_protocol(handle)
    })?;
    Ok(consume(capability, preflight))
}

/// Retires a generated proof only after an authenticated board source carries
/// its exact output descriptor and generation coordinates.
pub(crate) fn bind_generated_common_proof_to_verified_board_source(
    generated_proof_handle: u32,
    board_source: &VerifiedBoardApplicationSource,
    board_proof_descriptor: &StreamDescriptor,
    canonical_application_statement_bytes: &[u8],
) -> Result<(), CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .bind_generated_proof_to_verified_board_source(
                GeneratedCommonProofCapabilityHandle::from_identifier(generated_proof_handle),
                board_source,
                board_proof_descriptor,
                canonical_application_statement_bytes,
            )
            .map(|_| ())
    })
}

/// Retires one generated collective setup proof only after the exact
/// accepted-package statement source carries its descriptor and binding.
pub(crate) fn bind_generated_common_proof_to_verified_statement_source(
    generated_proof_handle: u32,
    statement_source: &super::VerifiedCommonProofStatementSource,
) -> Result<(), CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .bind_generated_proof_to_verified_statement_source(
                GeneratedCommonProofCapabilityHandle::from_identifier(generated_proof_handle),
                statement_source,
            )
            .map(|_| ())
    })
}

/// Retires an exact joint set of generated collective setup proofs only after
/// every accepted-package statement source has passed borrowed preflight.
/// No capability is consumed when any member is missing, duplicated, or bound
/// to a different package slot.
pub(crate) fn bind_generated_common_proofs_to_verified_statement_sources(
    bindings: &[(u32, &super::VerifiedCommonProofStatementSource)],
) -> Result<(), CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .bind_generated_proofs_to_verified_statement_sources(bindings)
    })
}

pub(crate) fn retire_generated_common_proof_capabilities(
    generated_proof_handles: &[u32],
) -> Result<(), CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .retire_generated_proofs(generated_proof_handles)
    })
}

pub(crate) fn preflight_generated_common_proof_pending_statement(
    generated_proof_handle: u32,
    expected_application_statement_schema_identifier: u16,
    expected_roster_position: Option<u16>,
    expected_schedule_position: Option<u32>,
    canonical_application_statement_bytes: &[u8],
) -> Result<StreamDescriptor, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .runtime
            .preflight_generated_proof_pending_statement(
                &GeneratedCommonProofCapabilityHandle::from_identifier(generated_proof_handle),
                expected_application_statement_schema_identifier,
                expected_roster_position,
                expected_schedule_position,
                canonical_application_statement_bytes,
            )
    })
}

pub(crate) fn preflight_generated_common_proof_attempt_binding(
    generated_proof_handle: u32,
    expected_generation_binding_hash: [u8; 64],
    expected_attempt_identifier: [u8; 32],
) -> Result<(), CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .runtime
            .preflight_generated_proof_attempt_binding(
                &GeneratedCommonProofCapabilityHandle::from_identifier(generated_proof_handle),
                expected_generation_binding_hash,
                expected_attempt_identifier,
            )
    })
}

pub(crate) fn preflight_generated_common_proof_pending_package(
    generated_proof_handle: u32,
    expected_bindings: ExpectedCommonProofPackageBindings<'_>,
) -> Result<StreamDescriptor, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .runtime
            .preflight_generated_proof_pending_package(
                &GeneratedCommonProofCapabilityHandle::from_identifier(generated_proof_handle),
                expected_bindings,
            )
    })
}

/// Borrows one positively verified proof without consuming its exact-family
/// terminal authority and derives the descriptor that may enter a pending
/// canonical package. The checked slot and canonical statement come from the
/// package builder's fixed inventory; no host-supplied descriptor is read.
pub(crate) fn preflight_verified_common_proof_pending_package(
    verified_proof_handle: u32,
    expected_bindings: ExpectedCommonProofPackageBindings<'_>,
) -> Result<StreamDescriptor, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry.borrow().runtime.with_verified_proof_for_protocol(
            &VerifiedCommonProofCapabilityHandle::from_identifier(verified_proof_handle),
            |verified_proof| {
                let statement_source = verified_proof.statement_source()?;
                let source_authority = statement_source.application_source_authority();
                if verified_proof.application_statement_schema_identifier()
                    != expected_bindings.application_statement_schema_identifier
                    || verified_proof.suite_identifier() != expected_bindings.suite_identifier
                    || verified_proof.ceremony_context_hash()
                        != expected_bindings.ceremony_context_hash
                    || verified_proof.action_context_hash() != expected_bindings.action_context_hash
                    || verified_proof.schedule_position() != expected_bindings.schedule_position
                    || source_authority.application_statement_schema_identifier()
                        != expected_bindings.application_statement_schema_identifier
                    || source_authority.producer_roster_position()
                        != expected_bindings.roster_position
                    || source_authority.schedule_position() != expected_bindings.schedule_position
                    || statement_source.canonical_application_statement_bytes()
                        != expected_bindings.canonical_application_statement_bytes
                    || source_authority.proof_stream_descriptor()
                        != verified_proof.proof_stream_descriptor()
                {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding);
                }
                Ok(verified_proof.proof_stream_descriptor().clone())
            },
        )?
    })
}

/// Copies the Rust-derived routing description for one live prover adapter.
///
pub(crate) fn common_proof_generation_authenticated_transcript_prefix_request(
    operation_handle: u32,
) -> Result<ExactSameSecretAuthenticatedTranscriptPrefixRequest, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .runtime
            .generation_authenticated_transcript_prefix_request(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
            )
    })
}

pub(crate) fn supply_common_proof_generation_authenticated_transcript_prefix(
    operation_handle: u32,
    prepared: PreparedExactSameSecretTranscriptPrefix,
) -> Result<(), CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .supply_generation_authenticated_transcript_prefix(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
                prepared,
            )
    })
}

/// # Safety
///
/// Each byte output pointer must name its complete fixed-size writable range.
/// The application-statement schema output pointer must name one writable
/// `u32` in WASM memory. A non-null status pointer must name one writable
/// `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_describe_generation_family_adapter(
    adapter_handle: u32,
    runtime_binding_hash_output_pointer: *mut u8,
    generation_authorization_hash_output_pointer: *mut u8,
    proof_attempt_lineage_identifier_output_pointer: *mut u8,
    checkpoint_lineage_identifier_output_pointer: *mut u8,
    application_statement_schema_identifier_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let adapter = registry
            .generation_family_adapters
            .get(&adapter_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            .map_err(runtime_error_status)?;
        let description = adapter.description();
        let checkpoint_lineage_identifier = adapter.checkpoint_lineage_identifier();
        unsafe {
            copy_exact_output_bytes(
                runtime_binding_hash_output_pointer,
                description.common_proof_runtime_binding_hash.len(),
                &description.common_proof_runtime_binding_hash,
            )?;
            copy_exact_output_bytes(
                generation_authorization_hash_output_pointer,
                description.common_proof_generation_authorization_hash.len(),
                &description.common_proof_generation_authorization_hash,
            )?;
            copy_exact_output_bytes(
                proof_attempt_lineage_identifier_output_pointer,
                description.proof_attempt_lineage_identifier.len(),
                &description.proof_attempt_lineage_identifier,
            )?;
            copy_exact_output_bytes(
                checkpoint_lineage_identifier_output_pointer,
                checkpoint_lineage_identifier.len(),
                &checkpoint_lineage_identifier,
            )?;
            write_required_unsigned32(
                application_statement_schema_identifier_output_pointer,
                u32::from(description.application_statement_schema_identifier),
            )?;
        }
        Ok::<(), u32>(())
    });
    match result {
        Ok(()) => {
            unsafe { write_status(status_pointer, 0) };
            0
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            status
        }
    }
}

/// Copies the Rust-derived public verification binding for one verifier
/// adapter.
///
/// # Safety
///
/// The output pointer must name 64 writable bytes. A non-null status pointer
/// must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_describe_verification_family_adapter(
    adapter_handle: u32,
    verification_binding_hash_output_pointer: *mut u8,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let verification_binding_hash = registry
            .verification_family_adapters
            .get(&adapter_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            .map_err(runtime_error_status)?
            .verification_binding_hash();
        unsafe {
            copy_exact_output_bytes(
                verification_binding_hash_output_pointer,
                verification_binding_hash.len(),
                &verification_binding_hash,
            )
        }
    });
    match result {
        Ok(()) => {
            unsafe { write_status(status_pointer, 0) };
            0
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            status
        }
    }
}

/// Consumes one prover adapter. Empty checkpoint inputs select its fresh path;
/// nonempty inputs must be the exact canonical state and composite generation
/// cursor manifest returned together by authenticated checkpoint custody
/// before any exact-family resume preparation runs.
///
/// # Safety
///
/// Each checkpoint pointer must name its declared readable range. A non-null
/// status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_prepare_generation_family_adapter(
    adapter_handle: u32,
    authenticated_checkpoint_state_pointer: *const u8,
    authenticated_checkpoint_state_byte_length: usize,
    authenticated_generation_cursor_manifest_pointer: *const u8,
    authenticated_generation_cursor_manifest_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let adapter_and_prepared_handle = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.require_neutral_transfer_capacity()?;
        if !registry
            .generation_family_adapters
            .contains_key(&adapter_handle)
        {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        let prepared_handle = registry.issue_prepared_generation_handle()?;
        let adapter = registry
            .generation_family_adapters
            .remove(&adapter_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if !registry
            .generation_preparation_reservations
            .insert(prepared_handle)
        {
            registry
                .generation_family_adapters
                .insert(adapter_handle, adapter);
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        Ok((adapter, prepared_handle))
    });
    let result = adapter_and_prepared_handle
        .map_err(CommonProofGenerationPreparationError::Runtime)
        .and_then(|(adapter, prepared_handle)| {
            let preparation_result = (|| {
                let authenticated_checkpoint_state = unsafe {
                    input_bytes(
                        authenticated_checkpoint_state_pointer,
                        authenticated_checkpoint_state_byte_length,
                    )
                };
                let authenticated_generation_cursor_manifest = unsafe {
                    input_bytes(
                        authenticated_generation_cursor_manifest_pointer,
                        authenticated_generation_cursor_manifest_byte_length,
                    )
                };
                let checkpoint = match (
                    authenticated_checkpoint_state.is_empty(),
                    authenticated_generation_cursor_manifest.is_empty(),
                ) {
                    (true, true) => None,
                    (false, false) => Some(AuthenticatedCommonProofGenerationCheckpoint::decode(
                        authenticated_checkpoint_state,
                        authenticated_generation_cursor_manifest,
                    )?),
                    _ => return Err(CommonProofRuntimeError::WrongVerificationBinding.into()),
                };
                adapter.prepare(checkpoint)
            })();
            COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
                let mut registry = registry.borrow_mut();
                if !registry
                    .generation_preparation_reservations
                    .remove(&prepared_handle)
                {
                    return Err(CommonProofGenerationPreparationError::Runtime(
                        CommonProofRuntimeError::WrongOperationPhase,
                    ));
                }
                preparation_result.map(|prepared| {
                    registry
                        .prepared_generations
                        .insert(prepared_handle, prepared);
                    prepared_handle
                })
            })
        });
    match result {
        Ok(prepared_handle) => {
            unsafe { write_status(status_pointer, 0) };
            prepared_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, generation_preparation_error_status(error)) };
            0
        }
    }
}

/// Consumes one verifier adapter and moves its positive exact-family inputs
/// into the generic persistent verifier registry.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_prepare_verification_family_adapter(
    adapter_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.require_neutral_transfer_capacity()?;
        if !registry
            .verification_family_adapters
            .contains_key(&adapter_handle)
        {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        let prepared_handle = registry.issue_prepared_verification_handle()?;
        let adapter = registry
            .verification_family_adapters
            .remove(&adapter_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        registry
            .prepared_verifications
            .insert(prepared_handle, adapter.prepared);
        Ok(prepared_handle)
    });
    match result {
        Ok(prepared_handle) => {
            unsafe { write_status(status_pointer, 0) };
            prepared_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_discard_generation_family_adapter(
    adapter_handle: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .generation_family_adapters
            .remove(&adapter_handle)
            .map_or_else(
                || runtime_error_status(CommonProofRuntimeError::UnknownOrStaleHandle),
                |_| 0,
            )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_discard_verification_family_adapter(
    adapter_handle: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .verification_family_adapters
            .remove(&adapter_handle)
            .map_or_else(
                || runtime_error_status(CommonProofRuntimeError::UnknownOrStaleHandle),
                |_| 0,
            )
    })
}

/// Permanently discards one exact-family prover preparation that never entered
/// the browser worker driver.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_discard_prepared_generation(handle: u32) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .prepared_generations
            .remove(&handle)
            .map_or_else(
                || runtime_error_status(CommonProofRuntimeError::UnknownOrStaleHandle),
                |_| 0,
            )
    })
}

/// Permanently discards one exact-family verifier preparation that never
/// entered the browser worker driver.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_discard_prepared_verification(handle: u32) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .prepared_verifications
            .remove(&handle)
            .map_or_else(
                || runtime_error_status(CommonProofRuntimeError::UnknownOrStaleHandle),
                |_| 0,
            )
    })
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> &'input [u8] {
    if byte_length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, byte_length) }
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
) -> Result<[u8; BYTE_LENGTH], u32> {
    if pointer.is_null() {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let bytes = unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) };
    bytes
        .try_into()
        .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe {
            status_pointer.write(status);
        }
    }
}

unsafe fn write_required_unsigned32(output_pointer: *mut u32, value: u32) -> Result<(), u32> {
    if output_pointer.is_null() {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    unsafe {
        output_pointer.write(value);
    }
    Ok(())
}

unsafe fn copy_exact_output_bytes(
    output_pointer: *mut u8,
    output_byte_length: usize,
    bytes: &[u8],
) -> Result<(), u32> {
    if output_pointer.is_null() || output_byte_length != bytes.len() {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
    output.copy_from_slice(bytes);
    Ok(())
}

unsafe fn exact_output_bytes_mut<'output>(
    output_pointer: *mut u8,
    output_byte_length: usize,
    expected_byte_length: usize,
) -> Result<&'output mut [u8], u32> {
    if output_pointer.is_null() || output_byte_length != expected_byte_length {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    Ok(unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) })
}

fn select_canonical_suite_record(canonical_suite_record_bytes: &[u8]) -> Result<u32, u32> {
    if canonical_suite_record_bytes.is_empty()
        || canonical_suite_record_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let suite_record = SuiteRecord::decode(
        canonical_suite_record_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|error| refusal_status(error.refusal_reason))?;
    let reencoded_suite_record = suite_record
        .encode()
        .map_err(|error| refusal_status(error.refusal_reason))?;
    if reencoded_suite_record != canonical_suite_record_bytes {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    let selected_suite =
        select_suite_record(&suite_record).map_err(|error| refusal_status(error.refusal_reason))?;
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry
            .require_new_entry_capacity(false)
            .map_err(runtime_error_status)?;
        registry
            .upstream_inputs
            .install_suite(selected_suite, reencoded_suite_record)
            .map(|handle| handle.get())
            .map_err(runtime_error_status)
    })
}

pub(crate) fn runtime_error_status(error: CommonProofRuntimeError) -> u32 {
    match error {
        CommonProofRuntimeError::UnknownOrStaleHandle
        | CommonProofRuntimeError::CancellationRequested
        | CommonProofRuntimeError::WrongOperationPhase => {
            refusal_status(RefusalReason::ConsumedState)
        }
        CommonProofRuntimeError::WrongVerificationBinding => {
            refusal_status(RefusalReason::WrongContext)
        }
        CommonProofRuntimeError::InvalidLimits
        | CommonProofRuntimeError::InvalidPlanCapability
        | CommonProofRuntimeError::TransactionPending
        | CommonProofRuntimeError::TransactionResponseMissing
        | CommonProofRuntimeError::TransactionReplayIncomplete
        | CommonProofRuntimeError::OutputByteLengthExceeded
        | CommonProofRuntimeError::OutputChunkAwaitingCommit
        | CommonProofRuntimeError::OutputChunkAwaitingReadback
        | CommonProofRuntimeError::OutputChunkNotReady
        | CommonProofRuntimeError::OutputWriteReplayMismatch
        | CommonProofRuntimeError::AllocationLimitExceeded
        | CommonProofRuntimeError::AuthenticatedStorageHeadMismatch => {
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

fn verification_worker_error_status(error: CommonProofVerificationWorkerError) -> u32 {
    match error {
        CommonProofVerificationWorkerError::Runtime(error) => runtime_error_status(error),
        CommonProofVerificationWorkerError::Stream(refusal_reason) => {
            refusal_status(refusal_reason)
        }
        CommonProofVerificationWorkerError::Verifier => refusal_status(RefusalReason::InvalidProof),
    }
}

fn generation_worker_error_status(error: CommonProofGenerationWorkerError) -> u32 {
    match error {
        CommonProofGenerationWorkerError::Runtime(error) => runtime_error_status(error),
        CommonProofGenerationWorkerError::AuthenticatedSource => {
            refusal_status(RefusalReason::WrongHashOrRoot)
        }
        CommonProofGenerationWorkerError::Generation(_) => {
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        CommonProofGenerationWorkerError::Cleanup => {
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

fn generation_preparation_error_status(error: CommonProofGenerationPreparationError) -> u32 {
    match error {
        CommonProofGenerationPreparationError::Runtime(error) => runtime_error_status(error),
        CommonProofGenerationPreparationError::Generation(_) => {
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

/// # Safety
///
/// The suite pointer must name its declared readable range. A non-null status
/// pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_select_suite(
    canonical_suite_record_pointer: *const u8,
    canonical_suite_record_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let canonical_suite_record_bytes = unsafe {
        input_bytes(
            canonical_suite_record_pointer,
            canonical_suite_record_byte_length,
        )
    };
    match select_canonical_suite_record(canonical_suite_record_bytes) {
        Ok(handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            handle
        }
        Err(status) => {
            unsafe {
                write_status(status_pointer, status);
            }
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_release_suite(handle: u32) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .upstream_inputs
            .release_suite(handle)
            .map_or_else(runtime_error_status, |()| 0)
    })
}

/// Returns the exact positively selected canonical suite-record length.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_selected_suite_record_byte_length(
    handle: u32,
    status_pointer: *mut u32,
) -> usize {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .upstream_inputs
            .canonical_suite_record_bytes(handle)
            .map(<[u8]>::len)
    });
    match result {
        Ok(byte_length) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            byte_length
        }
        Err(error) => {
            unsafe {
                write_status(status_pointer, runtime_error_status(error));
            }
            0
        }
    }
}

/// Copies the exact canonical bytes retained by positive suite selection.
///
/// # Safety
///
/// The output pointer must name its declared writable range in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_copy_selected_suite_record(
    handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let canonical_suite_record_bytes = match registry
            .upstream_inputs
            .canonical_suite_record_bytes(handle)
        {
            Ok(bytes) => bytes,
            Err(error) => return runtime_error_status(error),
        };
        unsafe {
            copy_exact_output_bytes(
                output_pointer,
                output_byte_length,
                canonical_suite_record_bytes,
            )
        }
        .map_or_else(core::convert::identity, |()| 0)
    })
}

/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_begin_generation(
    prepared_generation_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry
            .require_neutral_transfer_capacity()
            .map_err(CommonProofGenerationWorkerError::Runtime)?;
        let operation_handle = registry
            .runtime
            .preissue_generation_operation_handle()
            .map_err(CommonProofGenerationWorkerError::Runtime)?;
        let prepared = registry
            .prepared_generations
            .remove(&prepared_generation_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            .map_err(CommonProofGenerationWorkerError::Runtime)?;
        registry
            .runtime
            .begin_owned_generation_with_handle(prepared, operation_handle)
    });
    match result {
        Ok(handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            handle.get()
        }
        Err(error) => {
            unsafe {
                write_status(status_pointer, generation_worker_error_status(error));
            }
            0
        }
    }
}

/// Resumes one freshly prepared exact-family prover by replaying its
/// deterministic prefix from counter zero and then reinstalling the exact
/// authenticated transcript cursor at the matched durable boundary. The
/// state and composite cursor manifest must have come from one authenticated
/// custody checkpoint.
///
/// # Safety
///
/// Each checkpoint pointer must name its declared readable range. A non-null
/// status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_resume_generation(
    prepared_generation_handle: u32,
    authenticated_checkpoint_state_pointer: *const u8,
    authenticated_checkpoint_state_byte_length: usize,
    authenticated_generation_cursor_manifest_pointer: *const u8,
    authenticated_generation_cursor_manifest_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let authenticated_checkpoint_state = unsafe {
        input_bytes(
            authenticated_checkpoint_state_pointer,
            authenticated_checkpoint_state_byte_length,
        )
    };
    let authenticated_generation_cursor_manifest = unsafe {
        input_bytes(
            authenticated_generation_cursor_manifest_pointer,
            authenticated_generation_cursor_manifest_byte_length,
        )
    };
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry
            .require_neutral_transfer_capacity()
            .map_err(CommonProofGenerationWorkerError::Runtime)?;
        let operation_handle = registry
            .runtime
            .preissue_generation_operation_handle()
            .map_err(CommonProofGenerationWorkerError::Runtime)?;
        let prepared = registry
            .prepared_generations
            .remove(&prepared_generation_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            .map_err(CommonProofGenerationWorkerError::Runtime)?;
        registry.runtime.resume_owned_generation_with_handle(
            prepared,
            authenticated_checkpoint_state,
            authenticated_generation_cursor_manifest,
            operation_handle,
        )
    });
    match result {
        Ok(handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            handle.get()
        }
        Err(error) => {
            unsafe {
                write_status(status_pointer, generation_worker_error_status(error));
            }
            0
        }
    }
}

/// # Safety
///
/// Every output pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_poll(
    operation_handle: u32,
    poll_kind_pointer: *mut u32,
    primary_value_pointer: *mut u32,
    secondary_value_pointer: *mut u32,
) -> u32 {
    if poll_kind_pointer.is_null()
        || primary_value_pointer.is_null()
        || secondary_value_pointer.is_null()
    {
        return refusal_status(RefusalReason::WrongTypeOrLength);
    }
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry.borrow_mut().runtime.poll_owned_generation(
            CommonProofGenerationOperationHandle::from_identifier(operation_handle),
        )
    });
    let (poll_kind, primary_value, secondary_value) = match result {
        Ok(CommonProofGenerationWorkerPoll::Progress {
            stage,
            checkpoint_ready,
        }) => (
            GENERATION_POLL_PROGRESS,
            stage as u32,
            u32::from(checkpoint_ready),
        ),
        Ok(CommonProofGenerationWorkerPoll::ResumeComplete { stage }) => (
            GENERATION_POLL_RESUME_COMPLETE,
            stage as u32,
            NO_SECOND_POLL_VALUE,
        ),
        Ok(CommonProofGenerationWorkerPoll::StorageRequestReady {
            encoded_request_byte_length,
        }) => (
            GENERATION_POLL_STORAGE_REQUEST_READY,
            encoded_request_byte_length,
            NO_SECOND_POLL_VALUE,
        ),
        Ok(CommonProofGenerationWorkerPoll::AuthenticatedSourceReadReady {
            source_byte_length,
            authentication_chunk_index,
        }) => (
            GENERATION_POLL_AUTHENTICATED_SOURCE_READ_READY,
            source_byte_length,
            authentication_chunk_index,
        ),
        Ok(CommonProofGenerationWorkerPoll::AuthenticatedTranscriptPrefixRequired) => (
            GENERATION_POLL_AUTHENTICATED_TRANSCRIPT_PREFIX_REQUIRED,
            0,
            NO_SECOND_POLL_VALUE,
        ),
        Ok(CommonProofGenerationWorkerPoll::OutputChunkReady {
            chunk_index,
            chunk_byte_length,
        }) => (
            GENERATION_POLL_OUTPUT_CHUNK_READY,
            chunk_index,
            chunk_byte_length,
        ),
        Ok(CommonProofGenerationWorkerPoll::OutputReadbackRequired { chunk_index }) => (
            GENERATION_POLL_OUTPUT_READBACK_REQUIRED,
            chunk_index,
            NO_SECOND_POLL_VALUE,
        ),
        Ok(CommonProofGenerationWorkerPoll::Complete) => {
            (GENERATION_POLL_COMPLETE, 0, NO_SECOND_POLL_VALUE)
        }
        Ok(CommonProofGenerationWorkerPoll::Cancelled) => {
            (GENERATION_POLL_CANCELLED, 0, NO_SECOND_POLL_VALUE)
        }
        Err(error) => return generation_worker_error_status(error),
    };
    unsafe {
        write_status(poll_kind_pointer, poll_kind);
        write_status(primary_value_pointer, primary_value);
        write_status(secondary_value_pointer, secondary_value);
    }
    0
}

/// # Safety
///
/// Every output pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_describe_checkpoint(
    operation_handle: u32,
    safe_boundary_ordinal_pointer: *mut u32,
    state_byte_length_pointer: *mut u32,
    cursor_manifest_byte_length_pointer: *mut u32,
) -> u32 {
    if safe_boundary_ordinal_pointer.is_null()
        || state_byte_length_pointer.is_null()
        || cursor_manifest_byte_length_pointer.is_null()
    {
        return refusal_status(RefusalReason::WrongTypeOrLength);
    }
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let handle = CommonProofGenerationOperationHandle::from_identifier(operation_handle);
        let safe_boundary_ordinal = match registry
            .runtime
            .generation_checkpoint_safe_boundary_ordinal(handle)
        {
            Ok(value) => value,
            Err(error) => return runtime_error_status(error),
        };
        let state_byte_length = match registry.runtime.generation_checkpoint_state(handle) {
            Ok(state) => match u32::try_from(state.len()) {
                Ok(value) => value,
                Err(_) => return refusal_status(RefusalReason::OutsideSupportedProfile),
            },
            Err(error) => return runtime_error_status(error),
        };
        let cursor_manifest_byte_length = match registry
            .runtime
            .generation_checkpoint_cursor_manifest(handle)
        {
            Ok(manifest) => match u32::try_from(manifest.len()) {
                Ok(value) => value,
                Err(_) => return refusal_status(RefusalReason::OutsideSupportedProfile),
            },
            Err(error) => return runtime_error_status(error),
        };
        unsafe {
            write_status(safe_boundary_ordinal_pointer, safe_boundary_ordinal);
            write_status(state_byte_length_pointer, state_byte_length);
            write_status(
                cursor_manifest_byte_length_pointer,
                cursor_manifest_byte_length,
            );
        }
        0
    })
}

/// # Safety
///
/// The output pointer must name exactly the pending checkpoint state's
/// writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_copy_checkpoint_state(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let state = match registry.runtime.generation_checkpoint_state(
            CommonProofGenerationOperationHandle::from_identifier(operation_handle),
        ) {
            Ok(state) => state,
            Err(error) => return runtime_error_status(error),
        };
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, state) }
            .map_or_else(|status| status, |()| 0)
    })
}

/// # Safety
///
/// The output pointer must name exactly the canonical compact cursor manifest's
/// writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_copy_checkpoint_cursor_manifest(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let cursor_manifest = match registry.runtime.generation_checkpoint_cursor_manifest(
            CommonProofGenerationOperationHandle::from_identifier(operation_handle),
        ) {
            Ok(cursor_manifest) => cursor_manifest,
            Err(error) => return runtime_error_status(error),
        };
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, cursor_manifest) }
            .map_or_else(|status| status, |()| 0)
    })
}

/// # Safety
///
/// The output pointer must name one writable 64-byte digest in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let digest = match registry
            .runtime
            .generation_checkpoint_stable_attempt_binding_hash(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
            ) {
            Ok(digest) => digest,
            Err(error) => return runtime_error_status(error),
        };
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, &digest) }
            .map_or_else(|status| status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_generation_acknowledge_checkpoint(
    operation_handle: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .acknowledge_generation_checkpoint(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
            )
            .map_or_else(runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_generation_discard_checkpoint(
    operation_handle: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .discard_generation_checkpoint(CommonProofGenerationOperationHandle::from_identifier(
                operation_handle,
            ))
            .map_or_else(runtime_error_status, |()| 0)
    })
}

/// # Safety
///
/// The output pointer must name exactly the pending request's writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_copy_storage_request(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let operation_handle =
            CommonProofGenerationOperationHandle::from_identifier(operation_handle);
        let expected_byte_length = match registry
            .borrow()
            .runtime
            .generation_storage_request_byte_length(operation_handle)
        {
            Ok(byte_length) => byte_length,
            Err(error) => return runtime_error_status(error),
        };
        let output = match unsafe {
            exact_output_bytes_mut(output_pointer, output_byte_length, expected_byte_length)
        } {
            Ok(output) => output,
            Err(status) => return status,
        };
        registry
            .borrow_mut()
            .runtime
            .encode_generation_storage_request_into(operation_handle, output)
            .map_or_else(runtime_error_status, |()| 0)
    })
}

/// # Safety
///
/// The response pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_supply_storage_response(
    operation_handle: u32,
    response_pointer: *const u8,
    response_byte_length: usize,
) -> u32 {
    let response = unsafe { input_bytes(response_pointer, response_byte_length) };
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .supply_generation_storage_response(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
                response,
            )
            .map_or_else(generation_worker_error_status, |()| 0)
    })
}

/// # Safety
///
/// The output pointer must name exactly the fixed authenticated-source request
/// record's writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_copy_authenticated_source_request(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let request = match registry
            .runtime
            .generation_authenticated_source_read_request(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
            ) {
            Ok(request) => request,
            Err(error) => return runtime_error_status(error),
        };
        let encoded = encode_authenticated_source_read_request(request);
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, &encoded) }
            .map_or_else(|status| status, |()| 0)
    })
}

/// # Safety
///
/// The source pointer must name the exact readable range requested by Rust.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_supply_authenticated_source_range(
    operation_handle: u32,
    source_pointer: *const u8,
    source_byte_length: usize,
) -> u32 {
    let handle = CommonProofGenerationOperationHandle::from_identifier(operation_handle);
    let expected_byte_length = match COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .runtime
            .generation_authenticated_source_read_request(handle)
            .map(|request| request.source_byte_length())
    }) {
        Ok(expected_byte_length) => expected_byte_length,
        Err(error) => return runtime_error_status(error),
    };
    if usize::try_from(expected_byte_length).ok() != Some(source_byte_length) {
        return refusal_status(RefusalReason::WrongTypeOrLength);
    }
    let authenticated_bytes = unsafe { input_bytes(source_pointer, source_byte_length) };
    let authenticated_bytes = Zeroizing::new(authenticated_bytes.to_vec().into_boxed_slice());
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .supply_generation_authenticated_source_range(handle, authenticated_bytes)
            .map_or_else(generation_worker_error_status, |()| 0)
    })
}

/// # Safety
///
/// The output pointer must name exactly the pending chunk's writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_copy_output_chunk(
    operation_handle: u32,
    expected_chunk_index: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let (chunk_index, chunk_bytes) = match registry.runtime.generation_output_chunk(
            CommonProofGenerationOperationHandle::from_identifier(operation_handle),
        ) {
            Ok(pending) => pending,
            Err(error) => return runtime_error_status(error),
        };
        if usize::try_from(expected_chunk_index).ok() != Some(chunk_index) {
            return refusal_status(RefusalReason::WrongContext);
        }
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, chunk_bytes) }
            .map_or_else(|status| status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_generation_acknowledge_output_chunk(
    operation_handle: u32,
    expected_chunk_index: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let handle = CommonProofGenerationOperationHandle::from_identifier(operation_handle);
        let (chunk_index, _) = match registry.runtime.generation_output_chunk(handle) {
            Ok(pending) => pending,
            Err(error) => return runtime_error_status(error),
        };
        if usize::try_from(expected_chunk_index).ok() != Some(chunk_index) {
            return refusal_status(RefusalReason::WrongContext);
        }
        registry
            .runtime
            .acknowledge_generation_output_chunk(handle)
            .map_or_else(generation_worker_error_status, |()| 0)
    })
}

/// # Safety
///
/// The readback pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_confirm_output_readback(
    operation_handle: u32,
    chunk_index: u32,
    readback_pointer: *const u8,
    readback_byte_length: usize,
) -> u32 {
    let readback = unsafe { input_bytes(readback_pointer, readback_byte_length) };
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .confirm_generation_output_readback(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
                chunk_index as usize,
                readback,
            )
            .map_or_else(generation_worker_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_generation_request_cancellation(
    operation_handle: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .request_generation_cancellation(CommonProofGenerationOperationHandle::from_identifier(
                operation_handle,
            ))
            .map_or_else(runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_generation_release_cancelled(
    operation_handle: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .release_cancelled_generation(CommonProofGenerationOperationHandle::from_identifier(
                operation_handle,
            ))
            .map_or_else(runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_generation_retire_failed(
    operation_handle: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .retire_failed_generation(CommonProofGenerationOperationHandle::from_identifier(
                operation_handle,
            ))
            .map_or_else(runtime_error_status, |()| 0)
    })
}

/// Copies process-local production scratch accounting after terminal output
/// authentication and before the generation operation is consumed. The
/// diagnostic record is not a canonical protocol object and is never bound
/// into the generated proof or capability.
///
/// # Safety
///
/// The output pointer must name exactly the diagnostic record's writable
/// range in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_copy_external_memory_accounting(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let accounting = match registry
            .borrow()
            .runtime
            .generation_external_memory_accounting(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
            ) {
            Ok(accounting) => accounting,
            Err(error) => return runtime_error_status(error),
        };
        let encoded = encode_generation_external_memory_accounting(accounting);
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, &encoded) }
            .map_or_else(core::convert::identity, |()| 0)
    })
}

/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_finish(
    operation_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry.borrow_mut().runtime.finish_owned_generation(
            CommonProofGenerationOperationHandle::from_identifier(operation_handle),
        )
    });
    match result {
        Ok(handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            handle.get()
        }
        Err(error) => {
            unsafe {
                write_status(status_pointer, generation_worker_error_status(error));
            }
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_release_generated_proof(handle: u32) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .release_generated_proof(GeneratedCommonProofCapabilityHandle::from_identifier(
                handle,
            ))
            .map_or_else(runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_begin_verification(
    prepared_verification_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry
            .require_neutral_transfer_capacity()
            .map_err(CommonProofVerificationWorkerError::Runtime)?;
        let operation_handle = registry
            .runtime
            .preissue_verification_operation_handle()
            .map_err(CommonProofVerificationWorkerError::Runtime)?;
        let prepared = registry
            .prepared_verifications
            .remove(&prepared_verification_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            .map_err(CommonProofVerificationWorkerError::Runtime)?;
        registry
            .runtime
            .begin_owned_verification_with_handle(prepared, operation_handle)
    });
    match result {
        Ok(handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            handle.get()
        }
        Err(error) => {
            unsafe {
                write_status(status_pointer, verification_worker_error_status(error));
            }
            0
        }
    }
}

/// # Safety
///
/// The chunk pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_verification_absorb_input_chunk(
    operation_handle: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let chunk_bytes = unsafe { input_bytes(chunk_pointer, chunk_byte_length) };
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .absorb_verification_input_chunk(
                CommonProofVerificationOperationHandle::from_identifier(operation_handle),
                chunk_index as usize,
                chunk_bytes,
            )
            .map_or_else(verification_worker_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_verification_finish_input(
    operation_handle: u32,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .finish_verification_input(CommonProofVerificationOperationHandle::from_identifier(
                operation_handle,
            ))
            .map_or_else(verification_worker_error_status, |()| 0)
    })
}

/// # Safety
///
/// Every output pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_verification_poll(
    operation_handle: u32,
    poll_kind_pointer: *mut u32,
    primary_value_pointer: *mut u32,
    secondary_value_pointer: *mut u32,
) -> u32 {
    if poll_kind_pointer.is_null()
        || primary_value_pointer.is_null()
        || secondary_value_pointer.is_null()
    {
        return refusal_status(RefusalReason::WrongTypeOrLength);
    }
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry.borrow_mut().runtime.poll_owned_verification(
            CommonProofVerificationOperationHandle::from_identifier(operation_handle),
        )
    });
    let (poll_kind, primary_value, secondary_value) = match result {
        Ok(CommonProofVerificationWorkerPoll::NeedsReadback {
            first_chunk_index,
            second_chunk_index,
        }) => (
            VERIFICATION_POLL_NEEDS_READBACK,
            first_chunk_index,
            second_chunk_index.unwrap_or(NO_SECOND_POLL_VALUE),
        ),
        Ok(CommonProofVerificationWorkerPoll::Complete) => {
            (VERIFICATION_POLL_COMPLETE, 0, NO_SECOND_POLL_VALUE)
        }
        Err(error) => return verification_worker_error_status(error),
    };
    unsafe {
        write_status(poll_kind_pointer, poll_kind);
        write_status(primary_value_pointer, primary_value);
        write_status(secondary_value_pointer, secondary_value);
    }
    0
}

/// # Safety
///
/// The chunk pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_verification_supply_readback_chunk(
    operation_handle: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let chunk_bytes = unsafe { input_bytes(chunk_pointer, chunk_byte_length) };
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .supply_verification_readback_chunk(
                CommonProofVerificationOperationHandle::from_identifier(operation_handle),
                chunk_index as usize,
                chunk_bytes,
            )
            .map_or_else(verification_worker_error_status, |()| 0)
    })
}

/// Copies process-local verifier traversal traffic before the verification
/// worker is consumed. The diagnostic record is not a proof field, verifier
/// result, capability, or durable authorization input.
///
/// # Safety
///
/// The output pointer must name exactly the diagnostic record's writable
/// range in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_verification_copy_readback_accounting(
    operation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let accounting = match registry.borrow().runtime.verification_readback_accounting(
            CommonProofVerificationOperationHandle::from_identifier(operation_handle),
        ) {
            Ok(accounting) => accounting,
            Err(error) => return runtime_error_status(error),
        };
        let encoded = encode_verification_readback_accounting(accounting);
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, &encoded) }
            .map_or_else(core::convert::identity, |()| 0)
    })
}

/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_verification_finish(
    operation_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry.borrow_mut().runtime.finish_owned_verification(
            CommonProofVerificationOperationHandle::from_identifier(operation_handle),
        )
    });
    match result {
        Ok(handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            handle.get()
        }
        Err(error) => {
            unsafe {
                write_status(status_pointer, verification_worker_error_status(error));
            }
            0
        }
    }
}

#[unsafe(no_mangle)]
pub const extern "C" fn sealed_lattice_common_proof_application_frame_byte_length() -> u32 {
    DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH as u32
}

/// Moves one terminal verifier capability behind a pending durable
/// application and copies only its fixed canonical audit frame. The storage
/// root capability and authenticated head coordinates must remain inside the
/// browser-owned worker.
///
/// # Safety
///
/// Every non-null input pointer must name its fixed-size input in WASM memory.
/// The frame and application-slot output pointers must name writable regions
/// of the exact supplied lengths. A non-null status pointer must name one
/// writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_prepare_application(
    terminal_capability_handle: u32,
    storage_root_handle: u32,
    storage_root_capability_pointer: *const u8,
    predecessor_namespace_sequence: u64,
    predecessor_authenticated_head_digest_pointer: *const u8,
    storage_instance_identity_pointer: *const u8,
    durable_frame_output_pointer: *mut u8,
    durable_frame_output_byte_length: usize,
    proof_application_slot_hash_output_pointer: *mut u8,
    proof_application_slot_hash_output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        let storage_root_capability = unsafe {
            fixed_input::<LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH>(
                storage_root_capability_pointer,
            )
        }?;
        let predecessor_authenticated_head_digest = Hash512::from_bytes(unsafe {
            fixed_input(predecessor_authenticated_head_digest_pointer)
        }?);
        let storage_instance_identity =
            Hash512::from_bytes(unsafe { fixed_input(storage_instance_identity_pointer) }?);
        let source = resolve_browser_worker_authenticated_storage_head_source(
            storage_root_handle,
            &storage_root_capability,
            predecessor_namespace_sequence,
            predecessor_authenticated_head_digest,
            storage_instance_identity,
        )?;
        COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            let mut registry = registry.borrow_mut();
            let prepared = registry
                .runtime
                .prepare_verified_proof_application_from_authenticated_head(
                    &VerifiedCommonProofCapabilityHandle::from_identifier(
                        terminal_capability_handle,
                    ),
                    &source,
                )
                .map_err(runtime_error_status)?;
            let pending_handle_identifier = prepared.pending_handle().get();
            let copy_result = unsafe {
                copy_exact_output_bytes(
                    durable_frame_output_pointer,
                    durable_frame_output_byte_length,
                    prepared.durable_authorization_frame(),
                )
                .and_then(|()| {
                    copy_exact_output_bytes(
                        proof_application_slot_hash_output_pointer,
                        proof_application_slot_hash_output_byte_length,
                        &prepared.proof_application_slot_hash(),
                    )
                })
            };
            if let Err(copy_status) = copy_result {
                registry
                    .runtime
                    .abort_verified_proof_application(prepared.pending_handle())
                    .map_err(runtime_error_status)?;
                return Err(copy_status);
            }
            Ok(pending_handle_identifier)
        })
    })();
    match result {
        Ok(pending_handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            pending_handle
        }
        Err(status) => {
            unsafe {
                write_status(status_pointer, status);
            }
            0
        }
    }
}

/// Confirms a pending proof application only after the browser-owned worker
/// supplies one exact authenticated compare-and-apply transition and the
/// canonical durable frame reread from that transaction.
///
/// # Safety
///
/// Every non-null input pointer must name its fixed-size input in WASM memory.
/// The durable-frame pointer must name exactly the supplied number of readable
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_confirm_application(
    pending_handle: u32,
    storage_root_handle: u32,
    storage_root_capability_pointer: *const u8,
    predecessor_namespace_sequence: u64,
    predecessor_authenticated_head_digest_pointer: *const u8,
    successor_namespace_sequence: u64,
    successor_authenticated_head_digest_pointer: *const u8,
    storage_instance_identity_pointer: *const u8,
    authenticated_durable_frame_pointer: *const u8,
    authenticated_durable_frame_byte_length: usize,
) -> u32 {
    let result = (|| {
        if authenticated_durable_frame_byte_length != DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        let storage_root_capability = unsafe {
            fixed_input::<LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH>(
                storage_root_capability_pointer,
            )
        }?;
        let predecessor_authenticated_head_digest = Hash512::from_bytes(unsafe {
            fixed_input(predecessor_authenticated_head_digest_pointer)
        }?);
        let successor_authenticated_head_digest = Hash512::from_bytes(unsafe {
            fixed_input(successor_authenticated_head_digest_pointer)
        }?);
        let storage_instance_identity =
            Hash512::from_bytes(unsafe { fixed_input(storage_instance_identity_pointer) }?);
        let authenticated_durable_frame = unsafe {
            input_bytes(
                authenticated_durable_frame_pointer,
                authenticated_durable_frame_byte_length,
            )
        };
        if authenticated_durable_frame.len() != DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        let authenticated_record_digest = Hash512::from_bytes(durable_authorization_frame_digest(
            authenticated_durable_frame,
        ));
        let source = resolve_browser_worker_authenticated_storage_transition_source(
            storage_root_handle,
            &storage_root_capability,
            predecessor_namespace_sequence,
            predecessor_authenticated_head_digest,
            successor_namespace_sequence,
            successor_authenticated_head_digest,
            storage_instance_identity,
            authenticated_record_digest,
        )?;
        COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .runtime
                .confirm_verified_proof_application_from_authenticated_transition(
                    &PendingCommonProofAuthorizationHandle::from_identifier(pending_handle),
                    &source,
                )
                .map_err(runtime_error_status)
        })
    })();
    result.map_or_else(|status| status, |()| 0)
}

/// Restores the exact terminal verifier capability after the browser-owned
/// durable application transaction aborts. The pending handle becomes stale.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_abort_application(
    pending_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .abort_verified_proof_application(
                &PendingCommonProofAuthorizationHandle::from_identifier(pending_handle),
            )
            .map_err(runtime_error_status)
    });
    match result {
        Ok(restored_handle) => {
            unsafe {
                write_status(status_pointer, 0);
            }
            restored_handle.get()
        }
        Err(status) => {
            unsafe {
                write_status(status_pointer, status);
            }
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_discard_verified_proof(handle: u32) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .consume_verified_proof_for_protocol(
                &VerifiedCommonProofCapabilityHandle::from_identifier(handle),
            )
            .map(|_| ())
            .map_or_else(runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_common_proof_verification_cancel(operation_handle: u32) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .runtime
            .cancel_operation(CommonProofVerificationOperationHandle::from_identifier(
                operation_handle,
            ))
            .map_or_else(runtime_error_status, |()| 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgv::{
            proof_suite::{
                CommonProofRelationPlanCapability, VerifiedCommonProofStatementSource,
                VerifiedStatementOwnedTree, canonical_selected_vss_share_linkage_statement,
                compile_vss_share_linkage_relation_plan,
                selected_committed_material_relation_plan_input, selected_proof_runtime_limits,
                selected_relation_plan_check_context,
            },
            setup::VerifiedPublicRandomness,
        },
        foundation::{
            ParticipantIdentity, ProofApplicationSlotCeilings, selected_suite_capability_for_tests,
        },
    };
    use core::mem::size_of;
    use std::cell::RefCell;

    struct IsolatedCommonProofWasmRuntimeRegistry;

    impl IsolatedCommonProofWasmRuntimeRegistry {
        fn new() -> Self {
            reset_common_proof_wasm_runtime_registry();
            Self
        }
    }

    impl Drop for IsolatedCommonProofWasmRuntimeRegistry {
        fn drop(&mut self) {
            reset_common_proof_wasm_runtime_registry();
        }
    }

    fn reset_common_proof_wasm_runtime_registry() {
        COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            *registry.borrow_mut() = CommonProofWasmRuntimeRegistry::default();
        });
    }

    fn refusing_generation_family_adapter() -> CommonProofGenerationFamilyAdapter {
        CommonProofGenerationFamilyAdapter::resume(
            CommonProofGenerationFamilyAdapterDescription::new(
                0x1213, [0x11; 64], [0x22; 64], [0x33; 32],
            ),
            [0x44; 32],
            Hash512::from_bytes([0x55; 64]),
            Box::new(|_| Err(CommonProofRuntimeError::WrongVerificationBinding.into())),
        )
    }

    fn test_root(domain: u8, ordinal: usize) -> [u8; Hash512::BYTE_LENGTH] {
        let mut root = [domain; Hash512::BYTE_LENGTH];
        root[..size_of::<u64>()].copy_from_slice(
            &u64::try_from(ordinal)
                .expect("selected catalog ordinal fits u64")
                .to_le_bytes(),
        );
        root[Hash512::BYTE_LENGTH - 1] = domain;
        root
    }

    fn test_proof_stream_descriptor(proof_byte_length: usize) -> StreamDescriptor {
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let chunk_count = proof_byte_length
            .checked_add(chunk_byte_length - 1)
            .expect("selected proof byte length fits usize")
            / chunk_byte_length;
        StreamDescriptor {
            total_byte_length: u64::try_from(proof_byte_length)
                .expect("selected proof byte length fits u64"),
            ordered_chunk_digests: vec![Hash512::from_bytes([0xd1; 64]); chunk_count].into(),
            full_object_digest: Hash512::from_bytes([0xd2; 64]),
        }
    }

    fn exact_vss_prepared_verification_fixture() -> (PreparedCommonProofVerification, usize) {
        let selected_suite = selected_suite_capability_for_tests();
        let suite_identifier = Hash512::from_bytes(selected_suite.suite_identifier());
        let manifest_hash = Hash512::from_bytes([0x18; 64]);
        let ceremony_context_hash = Hash512::from_bytes([0x22; 64]);
        let action_context_hash = Hash512::from_bytes([0x33; 64]);
        let roster_hash = Hash512::from_bytes([0x44; 64]);
        let public_setup_seed = Hash512::from_bytes([0x55; 64]);
        let ordered_participant_identities = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                ParticipantIdentity::from_bytes(test_root(0x70, usize::from(roster_position)))
            })
            .collect::<Vec<_>>();
        let verified_public_randomness = VerifiedPublicRandomness::from_test_values(
            suite_identifier,
            manifest_hash,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            ordered_participant_identities,
            public_setup_seed,
        );
        let relation_input = selected_committed_material_relation_plan_input()
            .expect("selected committed-material relation input");
        let sharing_limb_count = relation_input.sharing_data_modulus_indices.len();
        let reconstruction_threshold = usize::from(relation_input.threshold);
        let participant_count = usize::from(relation_input.participant_count);
        let coefficient_root_count = sharing_limb_count
            .checked_mul(reconstruction_threshold)
            .expect("selected coefficient root count fits usize");
        let recipient_root_count = sharing_limb_count
            .checked_mul(participant_count)
            .expect("selected recipient root count fits usize");
        let ordered_coefficient_roots = (0..coefficient_root_count)
            .map(|root_ordinal| test_root(0xa1, root_ordinal))
            .collect::<Vec<_>>();
        let ordered_recipient_roots = (0..recipient_root_count)
            .map(|root_ordinal| test_root(0xb2, root_ordinal))
            .collect::<Vec<_>>();
        let dealer_roster_position = 3_u16;
        let dealer_identity = verified_public_randomness.ordered_participant_identities()
            [usize::from(dealer_roster_position)]
        .into_bytes();
        let canonical_application_statement_bytes = canonical_selected_vss_share_linkage_statement(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier.into_bytes(),
            ceremony_context_hash.into_bytes(),
            action_context_hash.into_bytes(),
            roster_hash.into_bytes(),
            public_setup_seed.into_bytes(),
            dealer_identity,
            dealer_roster_position,
            &ordered_coefficient_roots,
            &ordered_recipient_roots,
        )
        .expect("selected VSS statement is canonical");
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
            .expect("selected VSS relation context");
        let compiled_relation_plan =
            compile_vss_share_linkage_relation_plan(&relation_input, &relation_context)
                .expect("selected VSS relation plan");
        let selected_variant = compiled_relation_plan
            .select_variant(None, None)
            .expect("selected VSS relation variant");
        let limits = selected_proof_runtime_limits(
            statement_schema_identifier,
            &canonical_application_statement_bytes,
            selected_variant,
        )
        .expect("selected VSS proof limits");
        let proof_byte_length = limits
            .maximum_proof_byte_length()
            .checked_sub(1)
            .expect("the test proof is smaller than the absolute proof bound");
        let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
            &compiled_relation_plan,
            &relation_context,
            None,
            None,
        )
        .expect("selected VSS relation capability");
        let statement_source =
            VerifiedCommonProofStatementSource::from_test_verified_vss_statement_source(
                &verified_public_randomness,
                canonical_application_statement_bytes,
                test_proof_stream_descriptor(proof_byte_length),
                relation_plan,
                limits,
            )
            .expect("exact selected VSS statement source");
        let statement_byte_allocation = statement_source
            .canonical_application_statement_bytes()
            .as_ptr() as usize;
        let statement_trees =
            VerifiedStatementOwnedTree::from_verified_committed_material_statement_source(
                &statement_source,
                &verified_public_randomness,
            )
            .expect("selected VSS statement tree catalog");
        let prepared = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            let mut registry = registry.borrow_mut();
            let suite_handle = registry
                .upstream_inputs
                .install_suite(selected_suite, vec![0x51])
                .expect("selected suite authority is retained");
            registry
                .upstream_inputs
                .prepare_statement_tree_family_verification_without_evaluator(
                    &suite_handle,
                    statement_source,
                    statement_trees,
                )
                .expect("exact VSS verifier is prepared")
        });
        (prepared, statement_byte_allocation)
    }

    #[test]
    fn selected_suite_bytes_have_exact_copy_bounds_and_end_with_the_handle_lifecycle() {
        let _isolated_registry = IsolatedCommonProofWasmRuntimeRegistry::new();
        let exact_suite_bytes = vec![0x31, 0x42, 0x53, 0x64, 0x75];
        let selected_suite_handle = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .upstream_inputs
                .install_suite(
                    selected_suite_capability_for_tests(),
                    exact_suite_bytes.clone(),
                )
                .expect("selected suite and its exact bytes are retained")
                .get()
        });

        let mut status = u32::MAX;
        let byte_length = unsafe {
            sealed_lattice_common_proof_selected_suite_record_byte_length(
                selected_suite_handle,
                &mut status,
            )
        };
        assert_eq!(status, 0);
        assert_eq!(byte_length, exact_suite_bytes.len());

        let mut short_output = vec![0_u8; byte_length - 1];
        assert_eq!(
            unsafe {
                sealed_lattice_common_proof_copy_selected_suite_record(
                    selected_suite_handle,
                    short_output.as_mut_ptr(),
                    short_output.len(),
                )
            },
            refusal_status(RefusalReason::WrongTypeOrLength)
        );

        let mut copied_suite_bytes = vec![0_u8; byte_length];
        assert_eq!(
            unsafe {
                sealed_lattice_common_proof_copy_selected_suite_record(
                    selected_suite_handle,
                    copied_suite_bytes.as_mut_ptr(),
                    copied_suite_bytes.len(),
                )
            },
            0
        );
        assert_eq!(copied_suite_bytes, exact_suite_bytes);

        assert_eq!(
            sealed_lattice_common_proof_release_suite(selected_suite_handle),
            0
        );
        status = u32::MAX;
        assert_eq!(
            unsafe {
                sealed_lattice_common_proof_selected_suite_record_byte_length(
                    selected_suite_handle,
                    &mut status,
                )
            },
            0
        );
        assert_eq!(status, refusal_status(RefusalReason::ConsumedState));
        assert_eq!(
            sealed_lattice_common_proof_release_suite(selected_suite_handle),
            refusal_status(RefusalReason::ConsumedState)
        );
    }

    #[test]
    fn failed_release_keeps_the_original_adapter_and_aggregate_occupancy_live() {
        let _isolated_registry = IsolatedCommonProofWasmRuntimeRegistry::new();
        let adapter_handle =
            retain_common_proof_generation_family_adapter(refusing_generation_family_adapter())
                .expect("the first heavy adapter is retained");
        let occupancy_before_release = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            registry
                .borrow()
                .ffi_entry_count()
                .expect("the retained occupancy is bounded")
        });

        assert_eq!(
            sealed_lattice_common_proof_discard_generation_family_adapter(adapter_handle + 1),
            refusal_status(RefusalReason::ConsumedState),
        );
        COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            assert!(
                registry
                    .generation_family_adapters
                    .contains_key(&adapter_handle),
                "a failed release cannot consume a different live adapter",
            );
            assert_eq!(
                registry
                    .ffi_entry_count()
                    .expect("the retained occupancy remains bounded"),
                occupancy_before_release,
                "a failed release cannot free aggregate capacity",
            );
        });
        assert_eq!(
            sealed_lattice_common_proof_discard_generation_family_adapter(adapter_handle),
            0,
        );
    }

    #[test]
    fn destination_handle_refusal_preserves_the_adapter_source_for_release() {
        let _isolated_registry = IsolatedCommonProofWasmRuntimeRegistry::new();
        let adapter_handle =
            retain_common_proof_generation_family_adapter(refusing_generation_family_adapter())
                .expect("the source adapter is retained");
        COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            registry.borrow_mut().next_prepared_generation_handle = 0;
        });
        let mut status = 0;

        assert_eq!(
            unsafe {
                sealed_lattice_common_proof_prepare_generation_family_adapter(
                    adapter_handle,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    &mut status,
                )
            },
            0,
        );
        assert_eq!(
            status,
            refusal_status(RefusalReason::OutsideSupportedProfile),
        );
        COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            assert!(
                registry
                    .generation_family_adapters
                    .contains_key(&adapter_handle),
                "destination-handle refusal leaves the source owned for an exact retry or release",
            );
            assert!(registry.generation_preparation_reservations.is_empty());
        });
        assert_eq!(
            sealed_lattice_common_proof_discard_generation_family_adapter(adapter_handle),
            0,
        );
    }

    #[test]
    fn verifier_adapter_and_prepared_discard_restore_the_exact_statement_source() {
        let _isolated_registry = IsolatedCommonProofWasmRuntimeRegistry::new();
        let (prepared, statement_byte_allocation) = exact_vss_prepared_verification_fixture();
        let adapter_handle = retain_common_proof_verification_family_adapter(
            CommonProofVerificationFamilyAdapter::new(prepared),
        )
        .expect("the exact verifier adapter is retained");

        let rejected_restore: Result<(), CommonProofRuntimeError> =
            preflight_and_restore_common_proof_verification_family_adapter_statement_source(
                adapter_handle,
                |_| Err(CommonProofRuntimeError::WrongVerificationBinding),
                |_, ()| (),
            );
        assert_eq!(
            rejected_restore,
            Err(CommonProofRuntimeError::WrongVerificationBinding),
            "a rejected destination cannot consume the adapter source",
        );
        let restored_adapter_source = RefCell::new(None);
        preflight_and_restore_common_proof_verification_family_adapter_statement_source(
            adapter_handle,
            |source| {
                assert_eq!(
                    source.canonical_application_statement_bytes().as_ptr() as usize,
                    statement_byte_allocation,
                    "adapter preflight borrows the original statement allocation",
                );
                Ok(())
            },
            |source, ()| {
                *restored_adapter_source.borrow_mut() = Some(source);
            },
        )
        .expect("adapter discard restores its exact statement source");
        let source = restored_adapter_source
            .into_inner()
            .expect("adapter restoration returns one source");
        assert_eq!(
            source.canonical_application_statement_bytes().as_ptr() as usize,
            statement_byte_allocation,
            "adapter restoration moves rather than reconstructs the source",
        );

        let (prepared, prepared_statement_byte_allocation) =
            exact_vss_prepared_verification_fixture();
        let adapter_handle = retain_common_proof_verification_family_adapter(
            CommonProofVerificationFamilyAdapter::new(prepared),
        )
        .expect("the second exact verifier adapter is retained");
        let mut status = u32::MAX;
        let prepared_handle = unsafe {
            sealed_lattice_common_proof_prepare_verification_family_adapter(
                adapter_handle,
                &mut status,
            )
        };
        assert_ne!(prepared_handle, 0);
        assert_eq!(status, 0);
        let restored_prepared_source = RefCell::new(None);
        preflight_and_restore_prepared_common_proof_verification_statement_source(
            prepared_handle,
            |source| {
                assert_eq!(
                    source.canonical_application_statement_bytes().as_ptr() as usize,
                    prepared_statement_byte_allocation,
                );
                Ok(())
            },
            |source, ()| {
                *restored_prepared_source.borrow_mut() = Some(source);
            },
        )
        .expect("prepared-verifier discard restores its exact statement source");
        assert_eq!(
            restored_prepared_source
                .into_inner()
                .expect("prepared restoration returns one source")
                .canonical_application_statement_bytes()
                .as_ptr() as usize,
            prepared_statement_byte_allocation,
            "prepared restoration moves rather than reconstructs the source",
        );
    }

    #[test]
    fn verifier_cancellation_and_failure_restore_the_exact_statement_source() {
        let _isolated_registry = IsolatedCommonProofWasmRuntimeRegistry::new();
        let begin_operation = |prepared: PreparedCommonProofVerification| {
            let adapter_handle = retain_common_proof_verification_family_adapter(
                CommonProofVerificationFamilyAdapter::new(prepared),
            )
            .expect("the exact verifier adapter is retained");
            let mut status = u32::MAX;
            let prepared_handle = unsafe {
                sealed_lattice_common_proof_prepare_verification_family_adapter(
                    adapter_handle,
                    &mut status,
                )
            };
            assert_ne!(prepared_handle, 0);
            assert_eq!(status, 0);
            let operation_handle = unsafe {
                sealed_lattice_common_proof_begin_verification(prepared_handle, &mut status)
            };
            assert_ne!(operation_handle, 0);
            assert_eq!(status, 0);
            operation_handle
        };

        let (prepared, cancellation_statement_byte_allocation) =
            exact_vss_prepared_verification_fixture();
        let operation_handle = begin_operation(prepared);
        let restored_cancelled_source = RefCell::new(None);
        preflight_and_restore_common_proof_verification_operation_statement_source(
            operation_handle,
            |source| {
                assert_eq!(
                    source.canonical_application_statement_bytes().as_ptr() as usize,
                    cancellation_statement_byte_allocation,
                );
                Ok(())
            },
            |source, ()| {
                *restored_cancelled_source.borrow_mut() = Some(source);
            },
        )
        .expect("worker cancellation restores its exact statement source");
        assert_eq!(
            restored_cancelled_source
                .into_inner()
                .expect("cancelled operation returns one source")
                .canonical_application_statement_bytes()
                .as_ptr() as usize,
            cancellation_statement_byte_allocation,
        );

        let (prepared, failed_statement_byte_allocation) =
            exact_vss_prepared_verification_fixture();
        let failed_operation_handle = begin_operation(prepared);
        let mut finish_status = u32::MAX;
        assert_eq!(
            unsafe {
                sealed_lattice_common_proof_verification_finish(
                    failed_operation_handle,
                    &mut finish_status,
                )
            },
            0,
        );
        assert_eq!(
            finish_status,
            refusal_status(RefusalReason::ConsumedState),
            "finishing before canonical input completion is a verifier-phase refusal",
        );
        let restored_failed_source = RefCell::new(None);
        preflight_and_restore_common_proof_verification_operation_statement_source(
            failed_operation_handle,
            |source| {
                assert_eq!(
                    source.canonical_application_statement_bytes().as_ptr() as usize,
                    failed_statement_byte_allocation,
                );
                Ok(())
            },
            |source, ()| {
                *restored_failed_source.borrow_mut() = Some(source);
            },
        )
        .expect("verifier failure retains and restores its exact statement source");
        assert_eq!(
            restored_failed_source
                .into_inner()
                .expect("failed operation returns one source")
                .canonical_application_statement_bytes()
                .as_ptr() as usize,
            failed_statement_byte_allocation,
        );
    }
}
