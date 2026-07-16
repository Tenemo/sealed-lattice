//! Generated-WASM boundary for installing the operative common-proof suite.
//!
//! A schema-valid suite record is data, not authority. This boundary mints a
//! process-local handle only after the canonical record passes the complete
//! selected-suite derivation. The current selected suite remains fail-closed,
//! so a successful proof operation cannot be opened until that blocker is
//! resolved; there is no alternate fixture suite or raw-plan export.

use core::slice;
use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::foundation::{
    CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH,
    RefusalReason, SuiteRecord, resolve_browser_worker_authenticated_storage_head_source,
    resolve_browser_worker_authenticated_storage_transition_source, select_suite_record,
};

use super::{
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, CommonProofGenerationOperationHandle,
    CommonProofGenerationWorkerError, CommonProofGenerationWorkerPoll, CommonProofRuntimeError,
    CommonProofRuntimeRegistry, CommonProofUpstreamInputRegistry,
    CommonProofVerificationOperationHandle, CommonProofVerificationWorkerError,
    CommonProofVerificationWorkerPoll, DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH,
    GeneratedCommonProofCapabilityHandle, PendingCommonProofAuthorizationHandle,
    PreparedCommonProofGeneration, PreparedCommonProofVerification,
    VerifiedCommonProofCapabilityHandle, durable_authorization_frame_digest,
};

const MAXIMUM_RETAINED_PREPARED_GENERATION_COUNT: usize = 64;
const MAXIMUM_RETAINED_PREPARED_VERIFICATION_COUNT: usize = 64;
const NO_SECOND_POLL_VALUE: u32 = u32::MAX;
const VERIFICATION_POLL_NEEDS_READBACK: u32 = 1;
const VERIFICATION_POLL_PREFIX_ACCEPTED: u32 = 2;
const VERIFICATION_POLL_QUERY_HEADER_ACCEPTED: u32 = 3;
const VERIFICATION_POLL_QUERY_TREE_ACCEPTED: u32 = 4;
const VERIFICATION_POLL_COMPLETE: u32 = 5;
const GENERATION_POLL_PROGRESS: u32 = 1;
const GENERATION_POLL_STORAGE_REQUEST_READY: u32 = 2;
const GENERATION_POLL_OUTPUT_CHUNK_READY: u32 = 3;
const GENERATION_POLL_OUTPUT_READBACK_REQUIRED: u32 = 4;
const GENERATION_POLL_COMPLETE: u32 = 5;
const GENERATION_POLL_CANCELLED: u32 = 6;
const GENERATION_POLL_RESUME_COMPLETE: u32 = 7;

#[unsafe(no_mangle)]
pub const extern "C" fn sealed_lattice_common_proof_generation_checkpoint_state_byte_length() -> u32
{
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH as u32
}

thread_local! {
    static COMMON_PROOF_WASM_RUNTIME_REGISTRY: RefCell<CommonProofWasmRuntimeRegistry> =
        RefCell::new(CommonProofWasmRuntimeRegistry::default());
}

struct CommonProofWasmRuntimeRegistry {
    next_prepared_generation_handle: u32,
    next_prepared_verification_handle: u32,
    prepared_generations: BTreeMap<u32, PreparedCommonProofGeneration>,
    prepared_verifications: BTreeMap<u32, PreparedCommonProofVerification>,
    runtime: CommonProofRuntimeRegistry,
    upstream_inputs: CommonProofUpstreamInputRegistry,
}

impl Default for CommonProofWasmRuntimeRegistry {
    fn default() -> Self {
        Self {
            next_prepared_generation_handle: 1,
            next_prepared_verification_handle: 1,
            prepared_generations: BTreeMap::new(),
            prepared_verifications: BTreeMap::new(),
            runtime: CommonProofRuntimeRegistry::default(),
            upstream_inputs: CommonProofUpstreamInputRegistry::default(),
        }
    }
}

impl CommonProofWasmRuntimeRegistry {
    fn retain_prepared_generation(
        &mut self,
        prepared: PreparedCommonProofGeneration,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.prepared_generations.len() >= MAXIMUM_RETAINED_PREPARED_GENERATION_COUNT {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_prepared_generation_handle;
        self.next_prepared_generation_handle = self
            .next_prepared_generation_handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.prepared_generations.insert(handle, prepared);
        Ok(handle)
    }

    fn retain_prepared_verification(
        &mut self,
        prepared: PreparedCommonProofVerification,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.prepared_verifications.len() >= MAXIMUM_RETAINED_PREPARED_VERIFICATION_COUNT {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_prepared_verification_handle;
        self.next_prepared_verification_handle = self
            .next_prepared_verification_handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.prepared_verifications.insert(handle, prepared);
        Ok(handle)
    }
}

/// Retains one exact-family prepared prover for the generated-WASM worker.
/// There is intentionally no exported producer: family code must first join
/// its authenticated action attempt, real witness columns, and bound trees.
pub(crate) fn retain_prepared_common_proof_generation(
    prepared: PreparedCommonProofGeneration,
) -> Result<u32, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().retain_prepared_generation(prepared))
}

/// Retains one exact-family prepared verifier for the generated-WASM worker.
/// There is intentionally no exported producer for this handle; an exact
/// family adapter must first consume its verified board/tree/root sources.
pub(crate) fn retain_prepared_common_proof_verification(
    prepared: PreparedCommonProofVerification,
) -> Result<u32, CommonProofRuntimeError> {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().retain_prepared_verification(prepared))
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
        registry
            .borrow_mut()
            .upstream_inputs
            .install_suite(selected_suite)
            .map(|handle| handle.get())
            .map_err(runtime_error_status)
    })
}

fn runtime_error_status(error: CommonProofRuntimeError) -> u32 {
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
        CommonProofVerificationWorkerError::Verifier(_) => {
            refusal_status(RefusalReason::InvalidProof)
        }
    }
}

fn generation_worker_error_status(error: CommonProofGenerationWorkerError) -> u32 {
    match error {
        CommonProofGenerationWorkerError::Runtime(error) => runtime_error_status(error),
        CommonProofGenerationWorkerError::Generation { .. }
        | CommonProofGenerationWorkerError::Cleanup(_) => {
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
        let prepared = registry
            .prepared_generations
            .remove(&prepared_generation_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            .map_err(CommonProofGenerationWorkerError::Runtime)?;
        registry.runtime.begin_owned_generation(prepared)
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
/// deterministic prefix from counter zero. The state bytes must have come
/// from the authenticated custody checkpoint channel; copied manifest fields
/// cannot construct the `PreparedActionProofAttemptSource` consumed here.
///
/// # Safety
///
/// The checkpoint pointer must name its declared readable range. A non-null
/// status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_resume_generation(
    prepared_generation_handle: u32,
    authenticated_checkpoint_state_pointer: *const u8,
    authenticated_checkpoint_state_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let authenticated_checkpoint_state = unsafe {
        input_bytes(
            authenticated_checkpoint_state_pointer,
            authenticated_checkpoint_state_byte_length,
        )
    };
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let prepared = registry
            .prepared_generations
            .remove(&prepared_generation_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            .map_err(CommonProofGenerationWorkerError::Runtime)?;
        registry
            .runtime
            .resume_owned_generation(prepared, authenticated_checkpoint_state)
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
    cursor_count_pointer: *mut u32,
) -> u32 {
    if safe_boundary_ordinal_pointer.is_null()
        || state_byte_length_pointer.is_null()
        || cursor_count_pointer.is_null()
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
        let cursor_count = match registry.runtime.generation_checkpoint_cursor_count(handle) {
            Ok(count) => match u32::try_from(count) {
                Ok(value) => value,
                Err(_) => return refusal_status(RefusalReason::OutsideSupportedProfile),
            },
            Err(error) => return runtime_error_status(error),
        };
        unsafe {
            write_status(safe_boundary_ordinal_pointer, safe_boundary_ordinal);
            write_status(state_byte_length_pointer, state_byte_length);
            write_status(cursor_count_pointer, cursor_count);
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
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_checkpoint_cursor_byte_length(
    operation_handle: u32,
    cursor_index: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .runtime
            .generation_checkpoint_cursor(
                CommonProofGenerationOperationHandle::from_identifier(operation_handle),
                cursor_index as usize,
            )
            .and_then(|cursor| {
                u32::try_from(cursor.len())
                    .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
            })
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

/// # Safety
///
/// The output pointer must name exactly the selected canonical cursor's
/// writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_common_proof_generation_copy_checkpoint_cursor(
    operation_handle: u32,
    cursor_index: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    COMMON_PROOF_WASM_RUNTIME_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let cursor = match registry.runtime.generation_checkpoint_cursor(
            CommonProofGenerationOperationHandle::from_identifier(operation_handle),
            cursor_index as usize,
        ) {
            Ok(cursor) => cursor,
            Err(error) => return runtime_error_status(error),
        };
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, cursor) }
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
        let registry = registry.borrow();
        let request = match registry.runtime.generation_storage_request(
            CommonProofGenerationOperationHandle::from_identifier(operation_handle),
        ) {
            Ok(request) => request,
            Err(error) => return runtime_error_status(error),
        };
        unsafe { copy_exact_output_bytes(output_pointer, output_byte_length, request) }
            .map_or_else(|status| status, |()| 0)
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
        let prepared = registry
            .prepared_verifications
            .remove(&prepared_verification_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            .map_err(CommonProofVerificationWorkerError::Runtime)?;
        registry.runtime.begin_owned_verification(prepared)
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
        Ok(CommonProofVerificationWorkerPoll::PrefixAccepted) => {
            (VERIFICATION_POLL_PREFIX_ACCEPTED, 0, NO_SECOND_POLL_VALUE)
        }
        Ok(CommonProofVerificationWorkerPoll::QueryHeaderAccepted) => (
            VERIFICATION_POLL_QUERY_HEADER_ACCEPTED,
            0,
            NO_SECOND_POLL_VALUE,
        ),
        Ok(CommonProofVerificationWorkerPoll::QueryTreeAccepted { catalog_index }) => (
            VERIFICATION_POLL_QUERY_TREE_ACCEPTED,
            u32::from(catalog_index),
            NO_SECOND_POLL_VALUE,
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
