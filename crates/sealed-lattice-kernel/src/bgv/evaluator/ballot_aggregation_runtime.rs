use core::slice;
use std::cell::RefCell;

use crate::{
    bgv::proof_suite::runtime_error_status,
    foundation::{
        CanonicalDecodeLimits, RefusalReason, resolve_verified_action_top_count,
        resolve_verified_transcript_objects,
    },
};

#[cfg(test)]
use super::program::VerifiedEvaluatorAggregateContext;
use super::{
    ballot_aggregation::{IncrementalVerifiedBallotAggregation, VerifiedBallotAggregationError},
    program::VerifiedEvaluatorAggregate,
};

type RuntimeResult<Value> = Result<Value, u32>;

/// Process-local reference to one retained verified aggregate. The integer is
/// only a registry lookup key and cannot reconstruct the authority after its
/// one-shot transfer or discard.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VerifiedEvaluatorAggregateAuthorityHandle(u32);

impl VerifiedEvaluatorAggregateAuthorityHandle {
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn identifier(&self) -> u32 {
        self.0
    }
}

struct ActiveBallotAggregation {
    handle: u32,
    aggregation: IncrementalVerifiedBallotAggregation,
}

struct BallotAggregationRuntimeRegistry {
    active_aggregation: Option<ActiveBallotAggregation>,
    verified_aggregate_authority: Option<(u32, VerifiedEvaluatorAggregate)>,
    next_aggregation_handle: u32,
    next_verified_aggregate_authority_handle: u32,
}

impl Default for BallotAggregationRuntimeRegistry {
    fn default() -> Self {
        Self {
            active_aggregation: None,
            verified_aggregate_authority: None,
            next_aggregation_handle: 1,
            next_verified_aggregate_authority_handle: 1,
        }
    }
}

impl BallotAggregationRuntimeRegistry {
    fn begin(&mut self) -> RuntimeResult<u32> {
        if self.active_aggregation.is_some() || self.verified_aggregate_authority.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        let handle = take_nonrepeating_handle(&mut self.next_aggregation_handle)?;
        self.active_aggregation = Some(ActiveBallotAggregation {
            handle,
            aggregation: IncrementalVerifiedBallotAggregation::new(),
        });
        Ok(handle)
    }

    fn active_mut(
        &mut self,
        handle: u32,
    ) -> RuntimeResult<&mut IncrementalVerifiedBallotAggregation> {
        self.active_aggregation
            .as_mut()
            .filter(|active| active.handle == handle)
            .map(|active| &mut active.aggregation)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
    }

    fn take_active(&mut self, handle: u32) -> RuntimeResult<IncrementalVerifiedBallotAggregation> {
        if self
            .active_aggregation
            .as_ref()
            .is_none_or(|active| active.handle != handle)
        {
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
        self.active_aggregation
            .take()
            .map(|active| active.aggregation)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
    }

    fn retain_verified_aggregate(
        &mut self,
        verified_aggregate: VerifiedEvaluatorAggregate,
    ) -> RuntimeResult<VerifiedEvaluatorAggregateAuthorityHandle> {
        if self.verified_aggregate_authority.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        let handle = take_nonrepeating_handle(&mut self.next_verified_aggregate_authority_handle)?;
        self.verified_aggregate_authority = Some((handle, verified_aggregate));
        Ok(VerifiedEvaluatorAggregateAuthorityHandle(handle))
    }

    fn take_verified_aggregate(
        &mut self,
        handle: &VerifiedEvaluatorAggregateAuthorityHandle,
    ) -> Result<VerifiedEvaluatorAggregate, RefusalReason> {
        if self
            .verified_aggregate_authority
            .as_ref()
            .is_none_or(|(active_handle, _)| *active_handle != handle.0)
        {
            return Err(RefusalReason::ConsumedState);
        }
        self.verified_aggregate_authority
            .take()
            .map(|(_, verified_aggregate)| verified_aggregate)
            .ok_or(RefusalReason::ConsumedState)
    }

    fn discard_verified_aggregate(
        &mut self,
        handle: &VerifiedEvaluatorAggregateAuthorityHandle,
    ) -> RuntimeResult<()> {
        self.take_verified_aggregate(handle)
            .map(|_| ())
            .map_err(refusal_status)
    }
}

thread_local! {
    static BALLOT_AGGREGATION_RUNTIME_REGISTRY:
        RefCell<BallotAggregationRuntimeRegistry> =
        RefCell::new(BallotAggregationRuntimeRegistry::default());
}

fn begin_ballot_aggregation() -> RuntimeResult<u32> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| registry.borrow_mut().begin())
}

fn absorb_verified_ballot_output(
    aggregation_handle: u32,
    verified_ballot_output_handle: u32,
) -> RuntimeResult<()> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .active_mut(aggregation_handle)?
            .absorb_verified_ballot_output(verified_ballot_output_handle)
            .map_err(aggregation_error_status)
    })
}

fn finish_ballot_aggregation(
    aggregation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    verified_aggregate_object_handle: u32,
) -> RuntimeResult<VerifiedEvaluatorAggregateAuthorityHandle> {
    let aggregation = BALLOT_AGGREGATION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().take_active(aggregation_handle))?;
    aggregation.preflight_finish().map_err(refusal_status)?;
    let mut verified_aggregate_objects = resolve_verified_transcript_objects(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[verified_aggregate_object_handle],
    )?;
    let verified_aggregate_object = verified_aggregate_objects
        .pop()
        .ok_or_else(|| refusal_status(RefusalReason::MissingPrerequisite))?;
    let verified_action_top_count = resolve_verified_action_top_count(
        board_verifier_session_handle,
        board_verifier_session_capability,
    )?;
    let verified_aggregate = aggregation
        .finish(
            &verified_aggregate_object,
            verified_action_top_count,
            &CanonicalDecodeLimits::default(),
        )
        .map_err(refusal_status)?;
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .retain_verified_aggregate(verified_aggregate)
    })
}

fn cancel_ballot_aggregation(aggregation_handle: u32) -> RuntimeResult<()> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take_active(aggregation_handle)
            .map(|_| ())
    })
}

/// Transfers the retained authority exactly once into the evaluator runtime.
pub(crate) fn take_verified_evaluator_aggregate_authority(
    handle: &VerifiedEvaluatorAggregateAuthorityHandle,
) -> Result<VerifiedEvaluatorAggregate, RefusalReason> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().take_verified_aggregate(handle))
}

fn discard_verified_evaluator_aggregate_authority(
    handle: &VerifiedEvaluatorAggregateAuthorityHandle,
) -> RuntimeResult<()> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().discard_verified_aggregate(handle))
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

fn aggregation_error_status(error: VerifiedBallotAggregationError) -> u32 {
    match error {
        VerifiedBallotAggregationError::Runtime(error) => runtime_error_status(error),
        VerifiedBallotAggregationError::Refused(refusal_reason) => refusal_status(refusal_reason),
    }
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> &'input [u8] {
    if byte_length == 0 || pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, byte_length) }
    }
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe {
            status_pointer.write(status);
        }
    }
}

/// Begins the sole resident verified-ballot aggregation session.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_aggregation_begin(status_pointer: *mut u32) -> u32 {
    match begin_ballot_aggregation() {
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

/// Consumes one positive ballot-validity output into the running aggregate.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_aggregation_absorb(
    aggregation_handle: u32,
    verified_ballot_output_handle: u32,
) -> u32 {
    absorb_verified_ballot_output(aggregation_handle, verified_ballot_output_handle)
        .map_or_else(|status| status, |()| 0)
}

/// Consumes the aggregation session and matches it against one live,
/// board-verified deterministic aggregate object.
///
/// # Safety
///
/// The board-session capability pointer must name its declared readable range.
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_aggregation_finish(
    aggregation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    verified_aggregate_object_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let board_verifier_session_capability = unsafe {
        input_bytes(
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
        )
    };
    match finish_ballot_aggregation(
        aggregation_handle,
        board_verifier_session_handle,
        board_verifier_session_capability,
        verified_aggregate_object_handle,
    ) {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle.identifier()
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

/// Cancels and clears an unfinished aggregation session.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_aggregation_cancel(aggregation_handle: u32) -> u32 {
    cancel_ballot_aggregation(aggregation_handle).map_or_else(|status| status, |()| 0)
}

/// Permanently discards a verified aggregate authority that will not enter
/// evaluator replay.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_aggregation_discard_verified_aggregate(
    verified_aggregate_authority_handle: u32,
) -> u32 {
    discard_verified_evaluator_aggregate_authority(
        &VerifiedEvaluatorAggregateAuthorityHandle::from_identifier(
            verified_aggregate_authority_handle,
        ),
    )
    .map_or_else(|status| status, |()| 0)
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::bgv::{
        evaluator::engine::Ciphertext,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    };

    fn reset_registry() {
        BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
            *registry.borrow_mut() = BallotAggregationRuntimeRegistry::default();
        });
    }

    #[test]
    fn ffi_session_is_single_resident_poisoned_and_one_shot() {
        reset_registry();
        let mut status = u32::MAX;
        let aggregation_handle = unsafe { sealed_lattice_ballot_aggregation_begin(&mut status) };
        assert_ne!(aggregation_handle, 0);
        assert_eq!(status, 0);

        let duplicate_handle = unsafe { sealed_lattice_ballot_aggregation_begin(&mut status) };
        assert_eq!(duplicate_handle, 0);
        assert_eq!(
            status,
            refusal_status(RefusalReason::OutsideSupportedProfile)
        );

        assert_eq!(
            sealed_lattice_ballot_aggregation_absorb(aggregation_handle, 0),
            refusal_status(RefusalReason::ConsumedState)
        );
        let aggregate_authority_handle = unsafe {
            sealed_lattice_ballot_aggregation_finish(
                aggregation_handle,
                0,
                ptr::null(),
                0,
                0,
                &mut status,
            )
        };
        assert_eq!(aggregate_authority_handle, 0);
        assert_eq!(status, refusal_status(RefusalReason::ConsumedState));
        assert_eq!(
            sealed_lattice_ballot_aggregation_cancel(aggregation_handle),
            refusal_status(RefusalReason::ConsumedState)
        );

        let replacement_handle = unsafe { sealed_lattice_ballot_aggregation_begin(&mut status) };
        assert_ne!(replacement_handle, 0);
        assert_ne!(replacement_handle, aggregation_handle);
        assert_eq!(status, 0);
        assert_eq!(
            sealed_lattice_ballot_aggregation_cancel(replacement_handle),
            0
        );
        assert_eq!(
            sealed_lattice_ballot_aggregation_cancel(replacement_handle),
            refusal_status(RefusalReason::ConsumedState)
        );
        reset_registry();
    }

    #[test]
    fn verified_aggregate_authority_blocks_a_second_resident_aggregate_and_discards_once() {
        reset_registry();
        let aggregate_ciphertext = Ciphertext {
            components: (0..2)
                .map(|_| {
                    DATA_PRIMES
                        .iter()
                        .map(|_| vec![0_u64; POLYNOMIAL_DEGREE])
                        .collect()
                })
                .collect(),
            level: DATA_PRIMES.len() - 1,
            decrypt_scaling: 1,
        };
        let verified_aggregate = VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
            VerifiedEvaluatorAggregateContext::from_verified_sources(
                1, [0x11; 64], [0x22; 64], [0x33; 64], [0x44; 64], [0x55; 64], [0x66; 64],
            ),
            1,
            1,
            aggregate_ciphertext,
        )
        .expect("selected aggregate geometry constructs an authority");
        let authority_handle = BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .retain_verified_aggregate(verified_aggregate)
                .expect("authority is retained")
        });

        let mut status = u32::MAX;
        assert_eq!(
            unsafe { sealed_lattice_ballot_aggregation_begin(&mut status) },
            0
        );
        assert_eq!(
            status,
            refusal_status(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(
            sealed_lattice_ballot_aggregation_discard_verified_aggregate(
                authority_handle.identifier()
            ),
            0
        );
        assert_eq!(
            sealed_lattice_ballot_aggregation_discard_verified_aggregate(
                authority_handle.identifier()
            ),
            refusal_status(RefusalReason::ConsumedState)
        );
        reset_registry();
    }
}
