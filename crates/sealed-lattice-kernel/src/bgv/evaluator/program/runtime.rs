use core::slice;
use std::cell::RefCell;

use crate::{
    bgv::evaluator::{
        ballot_aggregation_runtime::{
            VerifiedEvaluatorAggregateAuthorityHandle, VerifiedEvaluatorPipelineLease,
            take_verified_evaluator_aggregate_execution_authority,
        },
        program::{
            PreparedSelectedEvaluatorReplay, SelectedEvaluatorExecutionProgress,
            SelectedEvaluatorProgramExecution,
        },
    },
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, RefusalReason,
        release_verified_evaluator_replay, resolve_verified_transcript_objects,
        retain_verified_evaluator_replay,
    },
};

const EVALUATOR_EXECUTION_PROGRESS_VERSION: u16 = 1;
const EVALUATOR_EXECUTION_PROGRESS_STORE_READ_REQUIRED: u16 = 1;
const EVALUATOR_EXECUTION_PROGRESS_COMPLETE: u16 = 2;
pub(crate) const EVALUATOR_EXECUTION_PROGRESS_BYTE_LENGTH: usize = 16;

type RuntimeResult<Value> = Result<Value, u32>;

enum EvaluatorExecutionState {
    Executing(Box<SelectedEvaluatorProgramExecution>),
    Prepared(Box<PreparedSelectedEvaluatorReplay>),
    #[cfg(test)]
    LeaseTestExecuting,
    #[cfg(test)]
    LeaseTestPrepared,
}

struct ActiveEvaluatorExecution {
    handle: u32,
    state: EvaluatorExecutionState,
    pipeline_lease: VerifiedEvaluatorPipelineLease,
}

struct EvaluatorExecutionRuntimeRegistry {
    active_execution: Option<ActiveEvaluatorExecution>,
    next_handle: u32,
}

impl Default for EvaluatorExecutionRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_execution: None,
            next_handle: 1,
        }
    }
}

impl EvaluatorExecutionRuntimeRegistry {
    fn begin(&mut self, verified_aggregate_authority_handle: u32) -> RuntimeResult<u32> {
        let retained_authority =
            take_transferred_authority_before_active_check(self.active_execution.is_some(), || {
                take_verified_evaluator_aggregate_execution_authority(
                    &VerifiedEvaluatorAggregateAuthorityHandle::from_identifier(
                        verified_aggregate_authority_handle,
                    ),
                )
            })
            .map_err(refusal_status)?;
        let (verified_aggregate_authority, pipeline_lease) = retained_authority.into_parts();
        let execution = SelectedEvaluatorProgramExecution::begin(verified_aggregate_authority)
            .map_err(refusal_status)?;
        let handle = take_nonrepeating_handle(&mut self.next_handle)?;
        self.active_execution = Some(ActiveEvaluatorExecution {
            handle,
            state: EvaluatorExecutionState::Executing(Box::new(execution)),
            pipeline_lease,
        });
        Ok(handle)
    }

    fn poll(
        &mut self,
        handle: u32,
    ) -> RuntimeResult<[u8; EVALUATOR_EXECUTION_PROGRESS_BYTE_LENGTH]> {
        let mut active = self.take_matching(handle)?;
        let EvaluatorExecutionState::Executing(execution) = &mut active.state else {
            self.active_execution = Some(active);
            return Err(refusal_status(RefusalReason::ConsumedState));
        };
        let progress = execution.advance();
        match progress {
            Ok(progress) => {
                let encoded = encode_progress(progress)?;
                self.active_execution = Some(active);
                Ok(encoded)
            }
            Err(refusal_reason) => Err(refusal_status(refusal_reason)),
        }
    }

    fn absorb_store_chunk(
        &mut self,
        handle: u32,
        store_byte_offset: u64,
        chunk_bytes: &[u8],
    ) -> RuntimeResult<()> {
        let mut active = self.take_matching(handle)?;
        let EvaluatorExecutionState::Executing(execution) = &mut active.state else {
            self.active_execution = Some(active);
            return Err(refusal_status(RefusalReason::ConsumedState));
        };
        let result = execution.absorb_next_store_chunk(store_byte_offset, chunk_bytes);
        match result {
            Ok(()) => {
                self.active_execution = Some(active);
                Ok(())
            }
            Err(refusal_reason) => Err(refusal_status(refusal_reason)),
        }
    }

    fn finish(&mut self, handle: u32) -> RuntimeResult<()> {
        let active = self.take_matching(handle)?;
        let pipeline_lease = active.pipeline_lease;
        let execution = match active.state {
            EvaluatorExecutionState::Executing(execution) => execution,
            state => {
                self.active_execution = Some(ActiveEvaluatorExecution {
                    handle,
                    state,
                    pipeline_lease,
                });
                return Err(refusal_status(RefusalReason::ConsumedState));
            }
        };
        let prepared = (*execution)
            .finish()
            .and_then(|verified_execution| verified_execution.prepare_replay())
            .map_err(refusal_status)?;
        self.active_execution = Some(ActiveEvaluatorExecution {
            handle,
            state: EvaluatorExecutionState::Prepared(Box::new(prepared)),
            pipeline_lease,
        });
        Ok(())
    }

    fn replay_carrier_byte_length(&self, handle: u32) -> RuntimeResult<usize> {
        let prepared = self.prepared(handle)?;
        let byte_length = prepared.canonical_replay_carrier().len();
        if byte_length == 0
            || byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || u32::try_from(byte_length).is_err()
        {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        Ok(byte_length)
    }

    fn copy_replay_carrier(&self, handle: u32, output: &mut [u8]) -> RuntimeResult<()> {
        let prepared = self.prepared(handle)?;
        let carrier = prepared.canonical_replay_carrier();
        if output.len() != carrier.len() {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        output.copy_from_slice(carrier);
        Ok(())
    }

    fn bind_replay_object(
        &mut self,
        handle: u32,
        replay_object: &crate::foundation::VerifiedTranscriptObject,
    ) -> RuntimeResult<u32> {
        let active = self.take_matching(handle)?;
        let EvaluatorExecutionState::Prepared(prepared) = &active.state else {
            self.active_execution = Some(active);
            return Err(refusal_status(RefusalReason::ConsumedState));
        };
        let verified_replay =
            match prepared.verify_board_object(replay_object, &CanonicalDecodeLimits::default()) {
                Ok(verified_replay) => verified_replay,
                Err(refusal_reason) => {
                    self.active_execution = Some(active);
                    return Err(refusal_status(refusal_reason));
                }
            };
        match retain_verified_evaluator_replay(verified_replay) {
            Ok(verified_replay_handle) => {
                Self::retire_after_success(active);
                Ok(verified_replay_handle)
            }
            Err(status) => {
                self.active_execution = Some(active);
                Err(status)
            }
        }
    }

    fn cancel(&mut self, handle: u32) -> RuntimeResult<()> {
        self.take_matching(handle).map(|_| ())
    }

    fn retire_after_success(active: ActiveEvaluatorExecution) {
        drop(active);
    }

    fn take_matching(&mut self, handle: u32) -> RuntimeResult<ActiveEvaluatorExecution> {
        let active = self
            .active_execution
            .take()
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        if active.handle != handle {
            self.active_execution = Some(active);
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
        Ok(active)
    }

    fn prepared(&self, handle: u32) -> RuntimeResult<&PreparedSelectedEvaluatorReplay> {
        let active = self
            .active_execution
            .as_ref()
            .filter(|active| active.handle == handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        match &active.state {
            EvaluatorExecutionState::Prepared(prepared) => Ok(prepared),
            _ => Err(refusal_status(RefusalReason::ConsumedState)),
        }
    }
}

fn take_transferred_authority_before_active_check<Authority>(
    active_execution_present: bool,
    take_authority: impl FnOnce() -> Result<Authority, RefusalReason>,
) -> Result<Authority, RefusalReason> {
    let authority = take_authority()?;
    if active_execution_present {
        return Err(RefusalReason::OutsideSupportedProfile);
    }
    Ok(authority)
}

thread_local! {
    static EVALUATOR_EXECUTION_RUNTIME_REGISTRY:
        RefCell<EvaluatorExecutionRuntimeRegistry> =
        RefCell::new(EvaluatorExecutionRuntimeRegistry::default());
}

fn begin_evaluator_execution(verified_aggregate_authority_handle: u32) -> RuntimeResult<u32> {
    EVALUATOR_EXECUTION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .begin(verified_aggregate_authority_handle)
    })
}

fn poll_evaluator_execution(
    execution_handle: u32,
) -> RuntimeResult<[u8; EVALUATOR_EXECUTION_PROGRESS_BYTE_LENGTH]> {
    EVALUATOR_EXECUTION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().poll(execution_handle))
}

fn absorb_evaluator_store_chunk(
    execution_handle: u32,
    store_byte_offset: u64,
    chunk_bytes: &[u8],
) -> RuntimeResult<()> {
    EVALUATOR_EXECUTION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .absorb_store_chunk(execution_handle, store_byte_offset, chunk_bytes)
    })
}

fn finish_evaluator_execution(execution_handle: u32) -> RuntimeResult<()> {
    EVALUATOR_EXECUTION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().finish(execution_handle))
}

fn evaluator_replay_carrier_byte_length(execution_handle: u32) -> RuntimeResult<usize> {
    EVALUATOR_EXECUTION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .replay_carrier_byte_length(execution_handle)
    })
}

fn copy_evaluator_replay_carrier(execution_handle: u32, output: &mut [u8]) -> RuntimeResult<()> {
    EVALUATOR_EXECUTION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .copy_replay_carrier(execution_handle, output)
    })
}

fn bind_evaluator_replay_object(
    execution_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    verified_replay_object_handle: u32,
) -> RuntimeResult<u32> {
    let mut verified_objects = resolve_verified_transcript_objects(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[verified_replay_object_handle],
    )?;
    let replay_object = verified_objects
        .pop()
        .ok_or_else(|| refusal_status(RefusalReason::MissingPrerequisite))?;
    EVALUATOR_EXECUTION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .bind_replay_object(execution_handle, &replay_object)
    })
}

fn cancel_evaluator_execution(execution_handle: u32) -> RuntimeResult<()> {
    EVALUATOR_EXECUTION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().cancel(execution_handle))
}

fn encode_progress(
    progress: SelectedEvaluatorExecutionProgress,
) -> RuntimeResult<[u8; EVALUATOR_EXECUTION_PROGRESS_BYTE_LENGTH]> {
    let mut output = [0_u8; EVALUATOR_EXECUTION_PROGRESS_BYTE_LENGTH];
    output[..2].copy_from_slice(&EVALUATOR_EXECUTION_PROGRESS_VERSION.to_le_bytes());
    match progress {
        SelectedEvaluatorExecutionProgress::StoreReadRequired(request) => {
            let byte_length = u32::try_from(request.byte_length())
                .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
            output[2..4]
                .copy_from_slice(&EVALUATOR_EXECUTION_PROGRESS_STORE_READ_REQUIRED.to_le_bytes());
            output[4..12].copy_from_slice(&request.store_byte_offset().to_le_bytes());
            output[12..16].copy_from_slice(&byte_length.to_le_bytes());
        }
        SelectedEvaluatorExecutionProgress::Complete => {
            output[2..4].copy_from_slice(&EVALUATOR_EXECUTION_PROGRESS_COMPLETE.to_le_bytes());
        }
    }
    Ok(output)
}

fn take_nonrepeating_handle(next_handle: &mut u32) -> RuntimeResult<u32> {
    let handle = *next_handle;
    if handle == 0 {
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }
    *next_handle = handle
        .checked_add(1)
        .filter(|next| *next != 0)
        .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    Ok(handle)
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> &'input [u8] {
    if pointer.is_null() || byte_length == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, byte_length) }
    }
}

unsafe fn output_bytes<'output>(
    pointer: *mut u8,
    byte_length: usize,
) -> RuntimeResult<&'output mut [u8]> {
    if pointer.is_null() || byte_length == 0 {
        Err(refusal_status(RefusalReason::WrongTypeOrLength))
    } else {
        Ok(unsafe { slice::from_raw_parts_mut(pointer, byte_length) })
    }
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

/// Begins the sole resident evaluator execution from the opaque aggregate
/// authority that already owns the one accepted-setup store resolver.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_execution_begin(
    verified_aggregate_authority_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match begin_evaluator_execution(verified_aggregate_authority_handle) {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

/// Advances the evaluator until completion or the next authenticated store
/// range. The fixed output record is version, progress code, little-endian
/// store offset, and exact byte length.
///
/// # Safety
///
/// The output pointer must name exactly the declared writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_execution_poll(
    execution_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    if output_byte_length != EVALUATOR_EXECUTION_PROGRESS_BYTE_LENGTH {
        return refusal_status(RefusalReason::WrongTypeOrLength);
    }
    let output = match unsafe { output_bytes(output_pointer, output_byte_length) } {
        Ok(output) => output,
        Err(status) => return status,
    };
    match poll_evaluator_execution(execution_handle) {
        Ok(progress) => {
            output.copy_from_slice(&progress);
            0
        }
        Err(status) => status,
    }
}

/// Supplies exactly the next Rust-requested physical-store range.
///
/// # Safety
///
/// The chunk pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_execution_absorb_store_chunk(
    execution_handle: u32,
    store_byte_offset: u64,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let chunk_bytes = unsafe { input_bytes(chunk_pointer, chunk_byte_length) };
    absorb_evaluator_store_chunk(execution_handle, store_byte_offset, chunk_bytes)
        .map_or_else(|status| status, |()| 0)
}

/// Completes execution and retains only recomputed stream summaries plus the
/// small deterministic replay carrier.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_execution_finish(execution_handle: u32) -> u32 {
    finish_evaluator_execution(execution_handle).map_or_else(|status| status, |()| 0)
}

/// Returns the exact deterministic replay-carrier byte length.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_execution_replay_carrier_byte_length(
    execution_handle: u32,
    status_pointer: *mut u32,
) -> usize {
    match evaluator_replay_carrier_byte_length(execution_handle) {
        Ok(byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            byte_length
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

/// Copies the exact deterministic replay carrier for relay and board
/// ingestion. No ciphertext bytes or internal handles enter the output.
///
/// # Safety
///
/// The output pointer must name exactly the declared writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_execution_copy_replay_carrier(
    execution_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let output = match unsafe { output_bytes(output_pointer, output_byte_length) } {
        Ok(output) => output,
        Err(status) => return status,
    };
    copy_evaluator_replay_carrier(execution_handle, output).map_or_else(|status| status, |()| 0)
}

/// Positively joins the retained recomputation to the byte-identical live
/// board object and mints finality's opaque evaluator-replay capability.
///
/// # Safety
///
/// The board capability pointer must name its declared readable range. A
/// non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_execution_bind_replay_object(
    execution_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    verified_replay_object_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let board_verifier_session_capability = unsafe {
        input_bytes(
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
        )
    };
    match bind_evaluator_replay_object(
        execution_handle,
        board_verifier_session_handle,
        board_verifier_session_capability,
        verified_replay_object_handle,
    ) {
        Ok(verified_replay_handle) => {
            unsafe { write_status(status_pointer, 0) };
            verified_replay_handle
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

/// Cancels an executing or prepared evaluator and drops every retained
/// ciphertext, key buffer, stream summary, and replay carrier.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_execution_cancel(execution_handle: u32) -> u32 {
    cancel_evaluator_execution(execution_handle).map_or_else(|status| status, |()| 0)
}

/// Releases a verified replay capability after finality no longer needs it.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_replay_release(verified_replay_handle: u32) -> u32 {
    release_verified_evaluator_replay(verified_replay_handle).map_or_else(|status| status, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::evaluator::ballot_aggregation_runtime::{
        sealed_lattice_ballot_aggregation_begin, sealed_lattice_ballot_aggregation_cancel,
    };

    fn insert_test_execution(
        registry: &mut EvaluatorExecutionRuntimeRegistry,
        state: EvaluatorExecutionState,
    ) -> u32 {
        let handle = take_nonrepeating_handle(&mut registry.next_handle)
            .expect("test evaluator handle is available");
        registry.active_execution = Some(ActiveEvaluatorExecution {
            handle,
            state,
            pipeline_lease: VerifiedEvaluatorPipelineLease::acquire()
                .expect("test evaluator owns the sole pipeline lease"),
        });
        handle
    }

    fn assert_ballot_aggregation_is_blocked() {
        let mut status = u32::MAX;
        let handle = unsafe { sealed_lattice_ballot_aggregation_begin(71, &mut status) };
        assert_eq!(handle, 0);
        assert_eq!(
            status,
            refusal_status(RefusalReason::OutsideSupportedProfile)
        );
    }

    fn assert_ballot_aggregation_can_start_and_retire() {
        let mut status = u32::MAX;
        let handle = unsafe { sealed_lattice_ballot_aggregation_begin(71, &mut status) };
        assert_ne!(handle, 0);
        assert_eq!(status, 0);
        assert_eq!(sealed_lattice_ballot_aggregation_cancel(handle), 0);
    }

    #[test]
    fn progress_record_encodes_full_width_store_coordinates() {
        let request = crate::bgv::evaluator::replay::EvaluatorKeyStoreReadRequest::from_test_values(
            u64::MAX - 7,
            FOUNDATION_PROFILE.stream_chunk_byte_length,
        );
        let encoded = encode_progress(SelectedEvaluatorExecutionProgress::StoreReadRequired(
            request,
        ))
        .expect("the selected stream chunk length fits the progress record");
        assert_eq!(u16::from_le_bytes(encoded[..2].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(encoded[2..4].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(encoded[4..12].try_into().unwrap()),
            u64::MAX - 7
        );
        assert_eq!(
            u32::from_le_bytes(encoded[12..16].try_into().unwrap()),
            u32::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length).unwrap()
        );
    }

    #[test]
    fn registry_preserves_live_execution_on_wrong_handle_and_exhausts_handles() {
        let mut registry = EvaluatorExecutionRuntimeRegistry::default();
        assert_eq!(
            registry.cancel(41),
            Err(refusal_status(RefusalReason::ConsumedState))
        );
        registry.next_handle = u32::MAX;
        assert_eq!(
            take_nonrepeating_handle(&mut registry.next_handle),
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        );
        assert_eq!(registry.next_handle, u32::MAX);
    }

    #[test]
    fn pipeline_lease_blocks_aggregation_through_executing_and_prepared_lifecycles() {
        let mut executing_registry = EvaluatorExecutionRuntimeRegistry::default();
        let executing_handle = insert_test_execution(
            &mut executing_registry,
            EvaluatorExecutionState::LeaseTestExecuting,
        );
        assert_ballot_aggregation_is_blocked();
        assert_eq!(
            executing_registry.cancel(executing_handle + 1),
            Err(refusal_status(RefusalReason::ConsumedState))
        );
        assert_ballot_aggregation_is_blocked();
        assert_eq!(executing_registry.cancel(executing_handle), Ok(()));
        assert_ballot_aggregation_can_start_and_retire();

        let mut prepared_registry = EvaluatorExecutionRuntimeRegistry::default();
        let prepared_handle = insert_test_execution(
            &mut prepared_registry,
            EvaluatorExecutionState::LeaseTestPrepared,
        );
        assert_ballot_aggregation_is_blocked();
        let prepared = prepared_registry
            .take_matching(prepared_handle)
            .expect("prepared test execution is live");
        EvaluatorExecutionRuntimeRegistry::retire_after_success(prepared);
        assert_ballot_aggregation_can_start_and_retire();
    }

    #[test]
    fn begin_consumes_transferred_authority_before_active_execution_refusal() {
        let take_count = std::cell::Cell::new(0_usize);
        let refusal = take_transferred_authority_before_active_check(true, || {
            take_count.set(take_count.get() + 1);
            VerifiedEvaluatorPipelineLease::acquire()
        })
        .err();
        assert_eq!(refusal, Some(RefusalReason::OutsideSupportedProfile));
        assert_eq!(take_count.get(), 1);

        let replacement = VerifiedEvaluatorPipelineLease::acquire()
            .expect("refused transferred authority released its pipeline lease");
        drop(replacement);
    }
}
