use core::slice;
use std::cell::{Cell, RefCell};

use crate::{
    bgv::{
        evaluator::replay::{
            EvaluatorKeyStoreReadRequest, VerifiedEvaluatorKeyContext, VerifiedEvaluatorKeyReplay,
        },
        proof_suite::runtime_error_status,
        setup::VerifiedAcceptedSetupAuthorityHandle,
    },
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, RefusalReason,
        resolve_verified_action_top_count, resolve_verified_transcript_objects,
    },
};

use super::{
    ballot_aggregation::{
        IncrementalVerifiedBallotAggregation, PreflightedVerifiedBallot,
        PreparedVerifiedBallotAggregation, TwoStreamPairCharacterProductAccounting,
        VerifiedBallotAggregationError, canonical_two_stream_pair_character_product_accounting,
    },
    program::{
        VerifiedEvaluatorAggregateExecutionAuthority, VerifiedEvaluatorAggregationAuthority,
    },
};

const BALLOT_AGGREGATION_PROGRESS_VERSION: u16 = 2;
const BALLOT_AGGREGATION_PROGRESS_STORE_READ_REQUIRED: u16 = 1;
const BALLOT_AGGREGATION_PROGRESS_BALLOT_ABSORBED: u16 = 2;
const BALLOT_AGGREGATION_PROGRESS_BALLOT_HASH_START: usize = 8;
const BALLOT_AGGREGATION_PROGRESS_SETUP_SOURCE_HASH_START: usize =
    BALLOT_AGGREGATION_PROGRESS_BALLOT_HASH_START + Hash512::BYTE_LENGTH;
pub(crate) const BALLOT_AGGREGATION_PROGRESS_BYTE_LENGTH: usize =
    BALLOT_AGGREGATION_PROGRESS_SETUP_SOURCE_HASH_START + Hash512::BYTE_LENGTH;

type RuntimeResult<Value> = Result<Value, u32>;
type AggregationOperationResult<Value> = Result<Value, BallotAggregationRuntimeError>;

enum BallotAggregationRuntimeError {
    Refused(RefusalReason),
    Core(VerifiedBallotAggregationError),
}

impl From<RefusalReason> for BallotAggregationRuntimeError {
    fn from(reason: RefusalReason) -> Self {
        Self::Refused(reason)
    }
}

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

thread_local! {
    static VERIFIED_EVALUATOR_PIPELINE_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// Worker-local ownership of the sole evaluator pipeline. The lease starts
/// before ballot aggregation and moves with the opaque aggregate authority and
/// evaluator runtime until successful replay binding, cancellation, or drop.
pub(crate) struct VerifiedEvaluatorPipelineLease {
    _private: (),
}

impl VerifiedEvaluatorPipelineLease {
    pub(in crate::bgv::evaluator) fn acquire() -> Result<Self, RefusalReason> {
        VERIFIED_EVALUATOR_PIPELINE_ACTIVE.with(|active| {
            if active.replace(true) {
                Err(RefusalReason::OutsideSupportedProfile)
            } else {
                Ok(Self { _private: () })
            }
        })
    }
}

impl Drop for VerifiedEvaluatorPipelineLease {
    fn drop(&mut self) {
        VERIFIED_EVALUATOR_PIPELINE_ACTIVE.with(|active| active.set(false));
    }
}

/// One-shot cross-runtime handoff. Keeping the lease beside the integrated
/// authority prevents a second aggregation from starting while the authority
/// is retained or evaluator execution is active.
pub(crate) struct RetainedVerifiedEvaluatorAggregateExecutionAuthority {
    execution_authority: VerifiedEvaluatorAggregateExecutionAuthority,
    pipeline_lease: VerifiedEvaluatorPipelineLease,
}

impl RetainedVerifiedEvaluatorAggregateExecutionAuthority {
    pub(crate) fn into_parts(
        self,
    ) -> (
        VerifiedEvaluatorAggregateExecutionAuthority,
        VerifiedEvaluatorPipelineLease,
    ) {
        (self.execution_authority, self.pipeline_lease)
    }
}

struct ActiveBallotAggregation {
    handle: u32,
    state: BallotAggregationState,
    pipeline_lease: Option<VerifiedEvaluatorPipelineLease>,
}

enum BallotAggregationState {
    Aggregating(Box<ExecutingBallotAggregation>),
    Prepared(Box<PreparedBallotAggregation>),
}

struct ExecutingBallotAggregation {
    accepted_setup_authority_handle: VerifiedAcceptedSetupAuthorityHandle,
    aggregation: Option<IncrementalVerifiedBallotAggregation>,
    evaluator_authority: Option<VerifiedEvaluatorAggregationAuthority>,
    pending_ballot: Option<PendingBallotAbsorption>,
    resident_relinearization_key: Option<VerifiedEvaluatorKeyContext>,
    relinearization_key_load_count: usize,
    key_store_read_byte_count: u64,
    key_ntt_transform_count: usize,
    maximum_resident_key_count: usize,
}

struct PendingBallotAbsorption {
    verified_ballot_output_handle: u32,
    preflight: PreflightedVerifiedBallot,
    requires_relinearization_key: bool,
    key_replay: Option<VerifiedEvaluatorKeyReplay>,
}

struct PreparedBallotAggregation {
    aggregation: PreparedVerifiedBallotAggregation,
    evaluator_authority: Option<VerifiedEvaluatorAggregationAuthority>,
    accounting: PreparedBallotAggregationAccounting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparedBallotAggregationAccounting {
    pair_character_product: TwoStreamPairCharacterProductAccounting,
    relinearization_key_load_count: usize,
    key_store_read_byte_count: u64,
    key_ntt_transform_count: usize,
    maximum_resident_key_count: usize,
}

impl PreparedBallotAggregationAccounting {
    fn validate_selected_profile(self) -> Result<(), RefusalReason> {
        let ballot_ciphertext_count = self.pair_character_product.ballot_ciphertext_count;
        if ballot_ciphertext_count == 0 || !ballot_ciphertext_count.is_multiple_of(2) {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let ballot_count = ballot_ciphertext_count / 2;
        if ballot_count > usize::from(FOUNDATION_PROFILE.participant_count) {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        let expected = canonical_two_stream_pair_character_product_accounting(ballot_count)?;
        if self.pair_character_product != expected
            || self.relinearization_key_load_count != expected.relinearization_key_load_count
            || self.maximum_resident_key_count != expected.relinearization_key_load_count
            || self.key_store_read_byte_count != expected.key_store_read_byte_count
            || self.key_ntt_transform_count != expected.key_ntt_transform_count
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(())
    }
}

struct BallotAggregationRuntimeRegistry {
    active_aggregation: Option<ActiveBallotAggregation>,
    verified_aggregate_authority:
        Option<(u32, RetainedVerifiedEvaluatorAggregateExecutionAuthority)>,
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
    fn begin(&mut self, accepted_setup_authority_handle: u32) -> RuntimeResult<u32> {
        if self.active_aggregation.is_some() || self.verified_aggregate_authority.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        let pipeline_lease = VerifiedEvaluatorPipelineLease::acquire().map_err(refusal_status)?;
        let handle = take_nonrepeating_handle(&mut self.next_aggregation_handle)?;
        self.active_aggregation = Some(ActiveBallotAggregation {
            handle,
            state: BallotAggregationState::Aggregating(Box::new(ExecutingBallotAggregation {
                accepted_setup_authority_handle:
                    VerifiedAcceptedSetupAuthorityHandle::from_identifier(
                        accepted_setup_authority_handle,
                    ),
                aggregation: Some(IncrementalVerifiedBallotAggregation::new()),
                evaluator_authority: None,
                pending_ballot: None,
                resident_relinearization_key: None,
                relinearization_key_load_count: 0,
                key_store_read_byte_count: 0,
                key_ntt_transform_count: 0,
                maximum_resident_key_count: 0,
            })),
            pipeline_lease: Some(pipeline_lease),
        });
        Ok(handle)
    }

    fn take_verified_aggregate(
        &mut self,
        handle: &VerifiedEvaluatorAggregateAuthorityHandle,
    ) -> Result<RetainedVerifiedEvaluatorAggregateExecutionAuthority, RefusalReason> {
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

    fn begin_absorb(
        &mut self,
        handle: u32,
        verified_ballot_output_handle: u32,
    ) -> RuntimeResult<()> {
        let mut active = self.take_matching(handle)?;
        let result = match &mut active.state {
            BallotAggregationState::Aggregating(executing) => {
                executing.begin_absorb(verified_ballot_output_handle)
            }
            BallotAggregationState::Prepared(_) => Err(RefusalReason::ConsumedState.into()),
        };
        match result {
            Ok(()) => {
                self.active_aggregation = Some(active);
                Ok(())
            }
            Err(error) => Err(aggregation_runtime_error_status(error)),
        }
    }

    fn poll(
        &mut self,
        handle: u32,
    ) -> RuntimeResult<[u8; BALLOT_AGGREGATION_PROGRESS_BYTE_LENGTH]> {
        let mut active = self.take_matching(handle)?;
        let result = match &mut active.state {
            BallotAggregationState::Aggregating(executing) => executing.poll(),
            BallotAggregationState::Prepared(_) => Err(RefusalReason::ConsumedState.into()),
        };
        match result {
            Ok(progress) => {
                self.active_aggregation = Some(active);
                encode_progress(progress)
            }
            Err(error) => Err(aggregation_runtime_error_status(error)),
        }
    }

    fn absorb_store_chunk(
        &mut self,
        handle: u32,
        store_byte_offset: u64,
        chunk_bytes: &[u8],
    ) -> RuntimeResult<()> {
        let mut active = self.take_matching(handle)?;
        let result = match &mut active.state {
            BallotAggregationState::Aggregating(executing) => {
                executing.absorb_store_chunk(store_byte_offset, chunk_bytes)
            }
            BallotAggregationState::Prepared(_) => Err(RefusalReason::ConsumedState.into()),
        };
        match result {
            Ok(()) => {
                self.active_aggregation = Some(active);
                Ok(())
            }
            Err(error) => Err(aggregation_runtime_error_status(error)),
        }
    }

    fn prepare(&mut self, handle: u32) -> RuntimeResult<()> {
        let active = self.take_matching(handle)?;
        let executing = match active.state {
            BallotAggregationState::Aggregating(executing) => executing,
            state @ BallotAggregationState::Prepared(_) => {
                self.active_aggregation = Some(ActiveBallotAggregation {
                    handle,
                    state,
                    pipeline_lease: active.pipeline_lease,
                });
                return Err(refusal_status(RefusalReason::ConsumedState));
            }
        };
        let prepared = executing
            .prepare()
            .map_err(aggregation_runtime_error_status)?;
        self.active_aggregation = Some(ActiveBallotAggregation {
            handle,
            state: BallotAggregationState::Prepared(Box::new(prepared)),
            pipeline_lease: active.pipeline_lease,
        });
        Ok(())
    }

    fn aggregate_carrier_byte_length(&self, handle: u32) -> RuntimeResult<usize> {
        let carrier = self.prepared(handle)?.aggregation.carrier_bytes();
        if carrier.is_empty()
            || carrier.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || u32::try_from(carrier.len()).is_err()
        {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        Ok(carrier.len())
    }

    fn copy_aggregate_carrier(&self, handle: u32, output: &mut [u8]) -> RuntimeResult<()> {
        let carrier = self.prepared(handle)?.aggregation.carrier_bytes();
        if output.len() != carrier.len() {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        output.copy_from_slice(carrier);
        Ok(())
    }

    fn bind_aggregate_object(
        &mut self,
        handle: u32,
        verified_aggregate_object: &crate::foundation::VerifiedTranscriptObject,
        verified_action_top_count: u16,
    ) -> RuntimeResult<VerifiedEvaluatorAggregateAuthorityHandle> {
        if self.verified_aggregate_authority.is_some() {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        let authority_handle =
            take_nonrepeating_handle(&mut self.next_verified_aggregate_authority_handle)?;
        let mut active = self.take_matching(handle)?;
        let BallotAggregationState::Prepared(prepared) = &mut active.state else {
            self.active_aggregation = Some(active);
            return Err(refusal_status(RefusalReason::ConsumedState));
        };
        if let Err(reason) = prepared.accounting.validate_selected_profile() {
            self.active_aggregation = Some(active);
            return Err(refusal_status(reason));
        }
        let verified_aggregate = match prepared.aggregation.bind_verified_aggregate(
            verified_aggregate_object,
            verified_action_top_count,
            &CanonicalDecodeLimits::default(),
        ) {
            Ok(verified_aggregate) => verified_aggregate,
            Err(reason) => {
                self.active_aggregation = Some(active);
                return Err(refusal_status(reason));
            }
        };
        let evaluator_authority = prepared
            .evaluator_authority
            .take()
            .ok_or_else(|| refusal_status(RefusalReason::MissingPrerequisite))?;
        let integrated_authority = evaluator_authority
            .bind_aggregate(verified_aggregate)
            .map_err(refusal_status)?;
        let pipeline_lease = active
            .pipeline_lease
            .take()
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        self.verified_aggregate_authority = Some((
            authority_handle,
            RetainedVerifiedEvaluatorAggregateExecutionAuthority {
                execution_authority: integrated_authority,
                pipeline_lease,
            },
        ));
        Ok(VerifiedEvaluatorAggregateAuthorityHandle(authority_handle))
    }

    fn cancel(&mut self, handle: u32) -> RuntimeResult<()> {
        self.take_matching(handle).map(|_| ())
    }

    fn take_matching(&mut self, handle: u32) -> RuntimeResult<ActiveBallotAggregation> {
        let active = self
            .active_aggregation
            .take()
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        if active.handle != handle {
            self.active_aggregation = Some(active);
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
        Ok(active)
    }

    fn prepared(&self, handle: u32) -> RuntimeResult<&PreparedBallotAggregation> {
        let active = self
            .active_aggregation
            .as_ref()
            .filter(|active| active.handle == handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
        match &active.state {
            BallotAggregationState::Prepared(prepared) => Ok(prepared),
            BallotAggregationState::Aggregating(_) => {
                Err(refusal_status(RefusalReason::ConsumedState))
            }
        }
    }
}

enum BallotAggregationProgress {
    StoreReadRequired(EvaluatorKeyStoreReadRequest),
    BallotAbsorbed {
        ballot_package_object_hash: [u8; Hash512::BYTE_LENGTH],
        producer_roster_position: u16,
        verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    },
}

impl BallotAggregationProgress {
    fn ballot_absorbed(preflight: PreflightedVerifiedBallot) -> Self {
        Self::BallotAbsorbed {
            ballot_package_object_hash: preflight.ballot_package_object_hash(),
            producer_roster_position: preflight.producer_roster_position(),
            verified_setup_source_hash: preflight.verified_setup_source_hash(),
        }
    }
}

impl ExecutingBallotAggregation {
    fn begin_absorb(
        &mut self,
        verified_ballot_output_handle: u32,
    ) -> AggregationOperationResult<()> {
        if self.pending_ballot.is_some() {
            return Err(RefusalReason::ConsumedState.into());
        }
        let aggregation = self
            .aggregation
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?;
        let preflight =
            aggregation.preflight_verified_ballot_output(verified_ballot_output_handle)?;
        let requires_relinearization_key =
            aggregation.requires_relinearization_key_for_preflight(&preflight)?;

        self.pending_ballot = Some(PendingBallotAbsorption {
            verified_ballot_output_handle,
            preflight,
            requires_relinearization_key,
            key_replay: None,
        });
        Ok(())
    }

    fn poll(&mut self) -> AggregationOperationResult<BallotAggregationProgress> {
        let preflight = self
            .pending_ballot
            .as_ref()
            .ok_or(RefusalReason::ConsumedState)?
            .preflight;
        if self.evaluator_authority.is_none() {
            let evaluator_authority =
                VerifiedEvaluatorAggregationAuthority::take_from_accepted_setup(
                    &self.accepted_setup_authority_handle,
                    |accepted_setup| preflight.matches_verified_accepted_setup(accepted_setup),
                )?;
            self.evaluator_authority = Some(evaluator_authority);
        }

        let requires_relinearization_key = self
            .pending_ballot
            .as_ref()
            .ok_or(RefusalReason::ConsumedState)?
            .requires_relinearization_key;
        if !requires_relinearization_key {
            let pending = self
                .pending_ballot
                .take()
                .ok_or(RefusalReason::ConsumedState)?;
            let progress = BallotAggregationProgress::ballot_absorbed(pending.preflight);
            self.aggregation
                .as_mut()
                .ok_or(RefusalReason::ConsumedState)?
                .commit_preflighted_verified_ballot_output(
                    pending.verified_ballot_output_handle,
                    pending.preflight,
                    None,
                )
                .map_err(BallotAggregationRuntimeError::Core)?;
            return Ok(progress);
        }

        if let Some(key_context) = self.resident_relinearization_key.as_ref() {
            let evaluator_authority = self
                .evaluator_authority
                .as_ref()
                .ok_or(RefusalReason::MissingPrerequisite)?;
            Self::validate_relinearization_context(evaluator_authority, key_context)?;
            let pending = self
                .pending_ballot
                .take()
                .ok_or(RefusalReason::ConsumedState)?;
            let progress = BallotAggregationProgress::ballot_absorbed(pending.preflight);
            self.aggregation
                .as_mut()
                .ok_or(RefusalReason::ConsumedState)?
                .commit_preflighted_verified_ballot_output(
                    pending.verified_ballot_output_handle,
                    pending.preflight,
                    Some(key_context),
                )
                .map_err(BallotAggregationRuntimeError::Core)?;
            return Ok(progress);
        }

        if self
            .pending_ballot
            .as_ref()
            .ok_or(RefusalReason::ConsumedState)?
            .key_replay
            .is_none()
        {
            let key_replay = self
                .evaluator_authority
                .as_ref()
                .ok_or(RefusalReason::MissingPrerequisite)?
                .resolver()
                .begin_relinearization_key_replay()?;
            self.pending_ballot
                .as_mut()
                .ok_or(RefusalReason::ConsumedState)?
                .key_replay = Some(key_replay);
        }
        if let Some(request) = self
            .pending_ballot
            .as_ref()
            .and_then(|pending| pending.key_replay.as_ref())
            .and_then(VerifiedEvaluatorKeyReplay::next_read_request)
        {
            return Ok(BallotAggregationProgress::StoreReadRequired(request));
        }
        let pending = self
            .pending_ballot
            .take()
            .ok_or(RefusalReason::ConsumedState)?;
        let progress = BallotAggregationProgress::ballot_absorbed(pending.preflight);
        let key_context = pending
            .key_replay
            .ok_or(RefusalReason::ConsumedState)?
            .finish()?;
        let evaluator_authority = self
            .evaluator_authority
            .as_ref()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        Self::validate_relinearization_context(evaluator_authority, &key_context)?;
        self.aggregation
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .commit_preflighted_verified_ballot_output(
                pending.verified_ballot_output_handle,
                pending.preflight,
                Some(&key_context),
            )
            .map_err(BallotAggregationRuntimeError::Core)?;
        self.relinearization_key_load_count = self
            .relinearization_key_load_count
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.key_ntt_transform_count = self
            .key_ntt_transform_count
            .checked_add(key_context.ntt_transform_count())
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.maximum_resident_key_count = self.maximum_resident_key_count.max(1);
        self.resident_relinearization_key = Some(key_context);
        Ok(progress)
    }

    fn absorb_store_chunk(
        &mut self,
        store_byte_offset: u64,
        chunk_bytes: &[u8],
    ) -> AggregationOperationResult<()> {
        self.pending_ballot
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .key_replay
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .absorb_next_store_chunk(store_byte_offset, chunk_bytes)?;
        let accepted_byte_count =
            u64::try_from(chunk_bytes.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        self.key_store_read_byte_count = self
            .key_store_read_byte_count
            .checked_add(accepted_byte_count)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        Ok(())
    }

    fn prepare(mut self) -> AggregationOperationResult<PreparedBallotAggregation> {
        if self.pending_ballot.is_some() {
            return Err(RefusalReason::ConsumedState.into());
        }
        let aggregation = self
            .aggregation
            .take()
            .ok_or(RefusalReason::ConsumedState)?;
        let evaluator_authority = self
            .evaluator_authority
            .take()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        if let Some(key_context) = self.resident_relinearization_key.as_ref() {
            Self::validate_relinearization_context(&evaluator_authority, key_context)?;
        }
        let prepared =
            aggregation.prepare_finalization(self.resident_relinearization_key.as_ref())?;
        let accounting = PreparedBallotAggregationAccounting {
            pair_character_product: prepared.accounting(),
            relinearization_key_load_count: self.relinearization_key_load_count,
            key_store_read_byte_count: self.key_store_read_byte_count,
            key_ntt_transform_count: self.key_ntt_transform_count,
            maximum_resident_key_count: self.maximum_resident_key_count,
        };
        accounting.validate_selected_profile()?;
        // The resolver's one-key guard must be released before it is handed to
        // evaluator execution, whose first key opcode may request another key.
        self.resident_relinearization_key.take();
        Ok(PreparedBallotAggregation {
            aggregation: prepared,
            evaluator_authority: Some(evaluator_authority),
            accounting,
        })
    }

    fn validate_relinearization_context(
        evaluator_authority: &VerifiedEvaluatorAggregationAuthority,
        key_context: &VerifiedEvaluatorKeyContext,
    ) -> AggregationOperationResult<()> {
        if key_context.resolver_context_hash()
            != evaluator_authority.evaluator_replay_context_hash()
        {
            return Err(RefusalReason::WrongContext.into());
        }
        Ok(())
    }
}

thread_local! {
    static BALLOT_AGGREGATION_RUNTIME_REGISTRY:
        RefCell<BallotAggregationRuntimeRegistry> =
        RefCell::new(BallotAggregationRuntimeRegistry::default());
}

fn begin_ballot_aggregation(accepted_setup_authority_handle: u32) -> RuntimeResult<u32> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().begin(accepted_setup_authority_handle))
}

fn absorb_verified_ballot_output(
    aggregation_handle: u32,
    verified_ballot_output_handle: u32,
) -> RuntimeResult<()> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .begin_absorb(aggregation_handle, verified_ballot_output_handle)
    })
}

fn poll_ballot_aggregation(
    aggregation_handle: u32,
) -> RuntimeResult<[u8; BALLOT_AGGREGATION_PROGRESS_BYTE_LENGTH]> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().poll(aggregation_handle))
}

fn absorb_ballot_aggregation_store_chunk(
    aggregation_handle: u32,
    store_byte_offset: u64,
    chunk_bytes: &[u8],
) -> RuntimeResult<()> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .absorb_store_chunk(aggregation_handle, store_byte_offset, chunk_bytes)
    })
}

fn prepare_ballot_aggregation(aggregation_handle: u32) -> RuntimeResult<()> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().prepare(aggregation_handle))
}

fn aggregate_carrier_byte_length(aggregation_handle: u32) -> RuntimeResult<usize> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .aggregate_carrier_byte_length(aggregation_handle)
    })
}

fn copy_aggregate_carrier(aggregation_handle: u32, output: &mut [u8]) -> RuntimeResult<()> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
        registry
            .borrow()
            .copy_aggregate_carrier(aggregation_handle, output)
    })
}

fn bind_ballot_aggregate_object(
    aggregation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    verified_aggregate_object_handle: u32,
) -> RuntimeResult<VerifiedEvaluatorAggregateAuthorityHandle> {
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
    BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
        registry.borrow_mut().bind_aggregate_object(
            aggregation_handle,
            &verified_aggregate_object,
            verified_action_top_count,
        )
    })
}

fn cancel_ballot_aggregation(aggregation_handle: u32) -> RuntimeResult<()> {
    BALLOT_AGGREGATION_RUNTIME_REGISTRY
        .with(|registry| registry.borrow_mut().cancel(aggregation_handle))
}

/// Transfers the retained authority exactly once into the evaluator runtime.
pub(crate) fn take_verified_evaluator_aggregate_execution_authority(
    handle: &VerifiedEvaluatorAggregateAuthorityHandle,
) -> Result<RetainedVerifiedEvaluatorAggregateExecutionAuthority, RefusalReason> {
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

fn aggregation_runtime_error_status(error: BallotAggregationRuntimeError) -> u32 {
    match error {
        BallotAggregationRuntimeError::Refused(reason) => refusal_status(reason),
        BallotAggregationRuntimeError::Core(error) => aggregation_error_status(error),
    }
}

fn encode_progress(
    progress: BallotAggregationProgress,
) -> RuntimeResult<[u8; BALLOT_AGGREGATION_PROGRESS_BYTE_LENGTH]> {
    let mut output = [0_u8; BALLOT_AGGREGATION_PROGRESS_BYTE_LENGTH];
    output[..2].copy_from_slice(&BALLOT_AGGREGATION_PROGRESS_VERSION.to_le_bytes());
    match progress {
        BallotAggregationProgress::StoreReadRequired(request) => {
            let byte_length = u32::try_from(request.byte_length())
                .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
            output[2..4]
                .copy_from_slice(&BALLOT_AGGREGATION_PROGRESS_STORE_READ_REQUIRED.to_le_bytes());
            output[4..12].copy_from_slice(&request.store_byte_offset().to_le_bytes());
            output[12..16].copy_from_slice(&byte_length.to_le_bytes());
        }
        BallotAggregationProgress::BallotAbsorbed {
            ballot_package_object_hash,
            producer_roster_position,
            verified_setup_source_hash,
        } => {
            output[2..4]
                .copy_from_slice(&BALLOT_AGGREGATION_PROGRESS_BALLOT_ABSORBED.to_le_bytes());
            output[4..6].copy_from_slice(&producer_roster_position.to_le_bytes());
            output[BALLOT_AGGREGATION_PROGRESS_BALLOT_HASH_START
                ..BALLOT_AGGREGATION_PROGRESS_SETUP_SOURCE_HASH_START]
                .copy_from_slice(&ballot_package_object_hash);
            output[BALLOT_AGGREGATION_PROGRESS_SETUP_SOURCE_HASH_START..]
                .copy_from_slice(&verified_setup_source_hash);
        }
    }
    Ok(output)
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> &'input [u8] {
    if byte_length == 0 || pointer.is_null() {
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
pub unsafe extern "C" fn sealed_lattice_ballot_aggregation_begin(
    accepted_setup_authority_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match begin_ballot_aggregation(accepted_setup_authority_handle) {
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

/// Begins absorption of one positive ballot-validity output. The first ballot
/// completes without a key read; ballot two starts the sole authenticated
/// level-22 relinearization-key replay.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_aggregation_absorb(
    aggregation_handle: u32,
    verified_ballot_output_handle: u32,
) -> u32 {
    absorb_verified_ballot_output(aggregation_handle, verified_ballot_output_handle)
        .map_or_else(|status| status, |()| 0)
}

/// Advances the pending ballot absorption until it either requests the next
/// exact store range or reports that the ballot was absorbed.
///
/// # Safety
///
/// The output pointer must name exactly the declared writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_aggregation_poll(
    aggregation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    if output_byte_length != BALLOT_AGGREGATION_PROGRESS_BYTE_LENGTH {
        return refusal_status(RefusalReason::WrongTypeOrLength);
    }
    let output = match unsafe { output_bytes(output_pointer, output_byte_length) } {
        Ok(output) => output,
        Err(status) => return status,
    };
    match poll_ballot_aggregation(aggregation_handle) {
        Ok(progress) => {
            output.copy_from_slice(&progress);
            0
        }
        Err(status) => status,
    }
}

/// Supplies exactly the next authenticated evaluator-store range requested by
/// aggregation key replay.
///
/// # Safety
///
/// The chunk pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_aggregation_absorb_store_chunk(
    aggregation_handle: u32,
    store_byte_offset: u64,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let chunk_bytes = unsafe { input_bytes(chunk_pointer, chunk_byte_length) };
    absorb_ballot_aggregation_store_chunk(aggregation_handle, store_byte_offset, chunk_bytes)
        .map_or_else(|status| status, |()| 0)
}

/// Finalizes both character-product forests and retains the exact canonical
/// aggregate carrier for publication and retryable board binding.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_aggregation_prepare(aggregation_handle: u32) -> u32 {
    prepare_ballot_aggregation(aggregation_handle).map_or_else(|status| status, |()| 0)
}

/// Returns the exact canonical aggregate-carrier byte length.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_aggregation_aggregate_carrier_byte_length(
    aggregation_handle: u32,
    status_pointer: *mut u32,
) -> usize {
    match aggregate_carrier_byte_length(aggregation_handle) {
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

/// Copies the exact canonical aggregate carrier without exposing ciphertexts
/// or the authenticated evaluator-store authority.
///
/// # Safety
///
/// The output pointer must name exactly the declared writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_aggregation_copy_aggregate_carrier(
    aggregation_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let output = match unsafe { output_bytes(output_pointer, output_byte_length) } {
        Ok(output) => output,
        Err(status) => return status,
    };
    copy_aggregate_carrier(aggregation_handle, output).map_or_else(|status| status, |()| 0)
}

/// Matches the prepared carrier against one live board-verified aggregate
/// object. A mismatch leaves the prepared session available for retry.
///
/// # Safety
///
/// The board-session capability pointer must name its declared readable range.
/// A non-null status pointer must name one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_aggregation_bind_aggregate_object(
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
    match bind_ballot_aggregate_object(
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
    use std::sync::Arc;

    use super::*;
    use crate::{
        bgv::{
            evaluator::{
                engine::decryption_accumulator_to_coefficients,
                pair_character_product::canonical_pair_character_product_schedule,
                top_k::{
                    CHARACTER_OUTPUT_LEVEL, SELECTED_RELINEARIZATION_KEY_LEVEL, TRACE_KEY_LEVEL,
                },
            },
            key_switch_topology::KeySwitchDecompositionTopology,
            parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
            proof_suite::{
                ComponentMaterialOwnershipBinding, KeySwitchComponentMaterialTopology,
                VerifiedBallotValidityOutput, VerifiedEvaluatorKeyStore,
                VerifiedEvaluatorKeyStoreMaterial, consume_verified_ballot_validity_output,
            },
            setup::{
                VerifiedAcceptedSetupAuthorityHandle, take_verified_evaluator_execution_authority,
            },
        },
        foundation::{StreamDescriptor, selected_suite_capability_for_tests},
    };

    const TEST_CEREMONY_CONTEXT_HASH: [u8; 64] = [0x21; 64];
    const TEST_ACTION_CONTEXT_HASH: [u8; 64] = [0x32; 64];
    const TEST_MANIFEST_HASH: [u8; 64] = [0x43; 64];
    const TEST_ROSTER_HASH: [u8; 64] = [0x54; 64];
    const TEST_SETUP_PROOF_CONTEXT_HASH: [u8; 64] = [0x65; 64];
    const TEST_VERIFIED_SETUP_SOURCE_HASH: [u8; 64] = [0x76; 64];
    const TEST_APPLICATION_STATEMENT_HASH: [u8; 64] = [0x87; 64];

    type DeterministicBallotCatalogEntry = (u16, u16, u16, u64, Arc<[u64]>);

    fn reset_registry() {
        BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
            *registry.borrow_mut() = BallotAggregationRuntimeRegistry::default();
        });
    }

    fn selected_minimal_store_byte_lengths() -> (usize, usize) {
        let selected_suite = selected_suite_capability_for_tests();
        let relinearization_component_byte_length = usize::try_from(
            KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
                &selected_suite,
                SELECTED_RELINEARIZATION_KEY_LEVEL,
            )
            .expect("selected relinearization topology")
            .expected_byte_length(),
        )
        .expect("selected relinearization component length fits usize");
        let trace_component_byte_length = usize::try_from(
            KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
                &selected_suite,
                TRACE_KEY_LEVEL,
            )
            .expect("selected trace-key topology")
            .expected_byte_length(),
        )
        .expect("selected trace component length fits usize");
        let total_byte_length = relinearization_component_byte_length
            .checked_mul(2)
            .and_then(|length| length.checked_add(trace_component_byte_length))
            .expect("selected minimal store length fits usize");
        (relinearization_component_byte_length, total_byte_length)
    }

    fn retain_test_accepted_setup(
        store_bytes: Vec<u8>,
    ) -> (VerifiedAcceptedSetupAuthorityHandle, Vec<u8>) {
        let selected_suite = selected_suite_capability_for_tests();
        let ownership_binding = ComponentMaterialOwnershipBinding::from_verified_application(
            selected_suite.suite_identifier(),
            TEST_ACTION_CONTEXT_HASH,
            TEST_APPLICATION_STATEMENT_HASH,
        );
        let (store_material, store_bytes) =
            VerifiedEvaluatorKeyStoreMaterial::from_test_authenticated_minimal_physical_material(
                ownership_binding,
                store_bytes,
            )
            .expect("minimal selected store material authenticates");
        let verified_store = VerifiedEvaluatorKeyStore::from_test_authenticated_replay_material(
            FOUNDATION_PROFILE.protocol_version,
            selected_suite.suite_identifier(),
            TEST_CEREMONY_CONTEXT_HASH,
            TEST_ACTION_CONTEXT_HASH,
            TEST_MANIFEST_HASH,
            TEST_ROSTER_HASH,
            TEST_SETUP_PROOF_CONTEXT_HASH,
            store_material,
        )
        .expect("test-minted replay store preserves selected bindings");
        let accepted_setup =
            VerifiedAcceptedSetupAuthorityHandle::retain_test_minted_with_evaluator_store(
                verified_store,
                TEST_VERIFIED_SETUP_SOURCE_HASH,
            )
            .expect("test-minted accepted setup retains the verified evaluator store");
        (accepted_setup, store_bytes)
    }

    fn ballot_stream_scalar(stream_ordinal: usize, ballot_ordinal: usize) -> u64 {
        match stream_ordinal {
            0 => u64::try_from(2 + ballot_ordinal).expect("selected ballot scalar fits u64"),
            1 => u64::try_from(17 + 2 * ballot_ordinal).expect("selected ballot scalar fits u64"),
            _ => panic!("the selected ballot has exactly two streams"),
        }
    }

    fn ballot_stream_exponent(stream_ordinal: usize, ballot_ordinal: usize) -> usize {
        match stream_ordinal {
            0 => ballot_ordinal,
            1 => 18_usize
                .checked_sub(ballot_ordinal)
                .expect("selected ballot ordinal is at most nine"),
            _ => panic!("the selected ballot has exactly two streams"),
        }
    }

    fn deterministic_ballot_catalog(ballot_ordinal: usize) -> Vec<DeterministicBallotCatalogEntry> {
        let mut catalog = Vec::with_capacity(2 * 2 * DATA_PRIMES.len());
        for stream_ordinal in 0..2 {
            let scalar = ballot_stream_scalar(stream_ordinal, ballot_ordinal);
            let exponent = ballot_stream_exponent(stream_ordinal, ballot_ordinal);
            for component_ordinal in 0..2 {
                for (data_modulus_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
                    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
                    if component_ordinal == 0 {
                        coefficients[exponent] = scalar % modulus;
                    }
                    catalog.push((
                        u16::try_from(stream_ordinal).expect("stream ordinal fits u16"),
                        u16::try_from(component_ordinal).expect("component ordinal fits u16"),
                        u16::try_from(data_modulus_index).expect("data-modulus index fits u16"),
                        modulus,
                        Arc::from(coefficients),
                    ));
                }
            }
        }
        catalog
    }

    fn retain_deterministic_ballot(ballot_ordinal: usize) -> u32 {
        VerifiedBallotValidityOutput::retain_test_minted(
            FOUNDATION_PROFILE.protocol_version,
            selected_suite_capability_for_tests().suite_identifier(),
            TEST_CEREMONY_CONTEXT_HASH,
            TEST_ACTION_CONTEXT_HASH,
            TEST_ROSTER_HASH,
            u16::try_from(ballot_ordinal).expect("producer position fits u16"),
            [u8::try_from(ballot_ordinal + 1).expect("ballot hash byte fits u8"); 64],
            TEST_VERIFIED_SETUP_SOURCE_HASH,
            deterministic_ballot_catalog(ballot_ordinal),
        )
        .expect("test-minted deterministic ballot retains positive authority")
    }

    fn expected_stream_product(ballot_count: usize, stream_ordinal: usize) -> (usize, u64) {
        let exponent = (0..ballot_count)
            .map(|ballot_ordinal| ballot_stream_exponent(stream_ordinal, ballot_ordinal))
            .sum::<usize>()
            + 9 * (usize::from(FOUNDATION_PROFILE.participant_count) - ballot_count);
        let scalar = (0..ballot_count).fold(1_u64, |product, ballot_ordinal| {
            (product * ballot_stream_scalar(stream_ordinal, ballot_ordinal)) % PLAINTEXT_MODULUS
        });
        (exponent, scalar)
    }

    fn assert_prepared_product_and_accounting(
        aggregation_handle: u32,
        ballot_count: usize,
        expected_relinearization_store_byte_count: u64,
        expected_relinearization_ntt_transform_count: usize,
    ) {
        const EXPECTED_MAXIMUM_RESIDENT_CIPHERTEXT_COUNTS: [usize; 10] =
            [3, 5, 5, 7, 7, 7, 7, 9, 9, 9];
        let schedule = canonical_pair_character_product_schedule(ballot_count)
            .expect("selected ballot count has one canonical product schedule");
        BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let prepared = registry
                .prepared(aggregation_handle)
                .expect("aggregation is prepared before cancellation");
            let ciphertexts = prepared.aggregation.ciphertexts_for_test();
            for (stream_ordinal, ciphertext) in ciphertexts.iter().enumerate() {
                assert_eq!(ciphertext.level, CHARACTER_OUTPUT_LEVEL);
                assert_eq!(ciphertext.components.len(), 2);
                let coefficients =
                    decryption_accumulator_to_coefficients(ciphertext, &ciphertext.components[0])
                        .expect("zero-secret deterministic ciphertext decrypts independently");
                let (expected_exponent, expected_scalar) =
                    expected_stream_product(ballot_count, stream_ordinal);
                assert_eq!(coefficients[expected_exponent], expected_scalar);
                assert!(
                    coefficients
                        .iter()
                        .enumerate()
                        .all(|(coefficient_ordinal, value)| {
                            coefficient_ordinal == expected_exponent || *value == 0
                        })
                );
            }
            assert_ne!(
                prepared.aggregation.descriptors()[0].full_object_digest,
                prepared.aggregation.descriptors()[1].full_object_digest
            );

            let product = prepared.accounting.pair_character_product;
            assert_eq!(
                product,
                canonical_two_stream_pair_character_product_accounting(ballot_count)
                    .expect("selected two-stream product accounting derives")
            );
            assert_eq!(product.ballot_ciphertext_count, 2 * ballot_count);
            assert_eq!(
                product.ciphertext_multiplication_count,
                2 * schedule.accounting.ciphertext_multiplication_count
            );
            assert_eq!(
                product.relinearization_count,
                2 * schedule.accounting.relinearization_count
            );
            assert_eq!(
                product.normalization_plaintext_multiplication_count,
                2 * schedule
                    .accounting
                    .normalization_plaintext_multiplication_count
            );
            assert_eq!(
                product.modulus_switch_count,
                2 * schedule.accounting.modulus_switch_count()
            );
            assert_eq!(
                product.modulus_drop_count,
                2 * schedule.accounting.modulus_drop_count()
            );
            assert_eq!(
                product.maximum_resident_ciphertext_count,
                EXPECTED_MAXIMUM_RESIDENT_CIPHERTEXT_COUNTS[ballot_count - 1]
            );

            let expected_key_count = usize::from(ballot_count >= 2);
            assert_eq!(
                prepared.accounting.relinearization_key_load_count,
                expected_key_count
            );
            assert_eq!(product.relinearization_key_load_count, expected_key_count);
            assert_eq!(
                prepared.accounting.maximum_resident_key_count,
                expected_key_count
            );
            assert_eq!(
                prepared.accounting.key_store_read_byte_count,
                if ballot_count >= 2 {
                    expected_relinearization_store_byte_count
                } else {
                    0
                }
            );
            assert_eq!(
                product.key_store_read_byte_count,
                prepared.accounting.key_store_read_byte_count
            );
            assert_eq!(
                prepared.accounting.key_ntt_transform_count,
                if ballot_count >= 2 {
                    expected_relinearization_ntt_transform_count
                } else {
                    0
                }
            );
            assert_eq!(
                product.key_ntt_transform_count,
                prepared.accounting.key_ntt_transform_count
            );
        });
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DeterministicAggregationSnapshot {
        accounting: PreparedBallotAggregationAccounting,
        carrier_bytes: Vec<u8>,
        descriptors: [StreamDescriptor; 2],
        key_store_read_requests: Vec<(u64, usize)>,
    }

    fn execute_deterministic_aggregation(
        store_bytes: Vec<u8>,
        ballot_count: usize,
        expected_relinearization_store_byte_count: u64,
        expected_relinearization_ntt_transform_count: usize,
    ) -> (Vec<u8>, DeterministicAggregationSnapshot) {
        let (accepted_setup, store_bytes) = retain_test_accepted_setup(store_bytes);
        let aggregation_handle = begin_ballot_aggregation(accepted_setup.identifier())
            .expect("selected aggregation begins with the sole pipeline lease");
        let mut observed_store_byte_count = 0_u64;
        let mut expected_next_store_byte_offset = 0_u64;
        let mut key_store_read_requests = Vec::new();

        for ballot_ordinal in 0..ballot_count {
            let verified_ballot_output_handle = retain_deterministic_ballot(ballot_ordinal);
            absorb_verified_ballot_output(aggregation_handle, verified_ballot_output_handle)
                .expect("canonical producer order enters pending absorption");
            let mut ballot_store_read_count = 0_usize;
            loop {
                let progress = poll_ballot_aggregation(aggregation_handle)
                    .expect("selected ballot absorption advances");
                assert_eq!(
                    u16::from_le_bytes(progress[..2].try_into().unwrap()),
                    BALLOT_AGGREGATION_PROGRESS_VERSION
                );
                match u16::from_le_bytes(progress[2..4].try_into().unwrap()) {
                    BALLOT_AGGREGATION_PROGRESS_STORE_READ_REQUIRED => {
                        assert_eq!(ballot_ordinal, 1);
                        assert!(progress[16..].iter().all(|byte| *byte == 0));
                        let store_byte_offset =
                            u64::from_le_bytes(progress[4..12].try_into().unwrap());
                        let chunk_byte_length = usize::try_from(u32::from_le_bytes(
                            progress[12..16].try_into().unwrap(),
                        ))
                        .expect("store request length fits usize");
                        assert_eq!(store_byte_offset, expected_next_store_byte_offset);
                        key_store_read_requests.push((store_byte_offset, chunk_byte_length));
                        let chunk_start = usize::try_from(store_byte_offset)
                            .expect("store request offset fits usize");
                        let chunk_end = chunk_start
                            .checked_add(chunk_byte_length)
                            .expect("store request range fits usize");
                        absorb_ballot_aggregation_store_chunk(
                            aggregation_handle,
                            store_byte_offset,
                            &store_bytes[chunk_start..chunk_end],
                        )
                        .expect("exact requested authenticated store chunk is accepted");
                        let accepted_byte_count = u64::try_from(chunk_byte_length)
                            .expect("accepted chunk length fits u64");
                        observed_store_byte_count = observed_store_byte_count
                            .checked_add(accepted_byte_count)
                            .expect("observed store byte count fits u64");
                        expected_next_store_byte_offset = expected_next_store_byte_offset
                            .checked_add(accepted_byte_count)
                            .expect("next store offset fits u64");
                        ballot_store_read_count += 1;
                    }
                    BALLOT_AGGREGATION_PROGRESS_BALLOT_ABSORBED => {
                        assert_eq!(
                            u16::from_le_bytes(progress[4..6].try_into().unwrap()),
                            u16::try_from(ballot_ordinal)
                                .expect("producer position fits progress record")
                        );
                        assert_eq!(&progress[6..8], &[0, 0]);
                        assert_eq!(
                            &progress[BALLOT_AGGREGATION_PROGRESS_BALLOT_HASH_START
                                ..BALLOT_AGGREGATION_PROGRESS_SETUP_SOURCE_HASH_START],
                            &[u8::try_from(ballot_ordinal + 1).expect("ballot hash byte fits u8");
                                Hash512::BYTE_LENGTH]
                        );
                        assert_eq!(
                            &progress[BALLOT_AGGREGATION_PROGRESS_SETUP_SOURCE_HASH_START..],
                            &TEST_VERIFIED_SETUP_SOURCE_HASH
                        );
                        break;
                    }
                    progress_code => panic!("unexpected aggregation progress {progress_code}"),
                }
            }
            if ballot_ordinal == 0 {
                assert_eq!(ballot_store_read_count, 0);
                assert!(matches!(
                    take_verified_evaluator_execution_authority(&accepted_setup, |_| true),
                    Err(RefusalReason::ConsumedState)
                ));
            } else if ballot_ordinal == 1 {
                assert!(ballot_store_read_count > 0);
            } else {
                assert_eq!(ballot_store_read_count, 0);
            }
            assert!(
                consume_verified_ballot_validity_output(verified_ballot_output_handle).is_err()
            );
        }

        assert_eq!(
            observed_store_byte_count,
            if ballot_count >= 2 {
                expected_relinearization_store_byte_count
            } else {
                0
            }
        );
        prepare_ballot_aggregation(aggregation_handle)
            .expect("both product forests prepare in fixed order");
        assert_prepared_product_and_accounting(
            aggregation_handle,
            ballot_count,
            expected_relinearization_store_byte_count,
            expected_relinearization_ntt_transform_count,
        );
        let snapshot = BALLOT_AGGREGATION_RUNTIME_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let prepared = registry
                .prepared(aggregation_handle)
                .expect("aggregation is prepared before deterministic replay comparison");
            DeterministicAggregationSnapshot {
                accounting: prepared.accounting,
                carrier_bytes: prepared.aggregation.carrier_bytes().to_vec(),
                descriptors: prepared.aggregation.descriptors().clone(),
                key_store_read_requests,
            }
        });

        assert_eq!(
            cancel_ballot_aggregation(aggregation_handle.wrapping_add(1)),
            Err(refusal_status(RefusalReason::ConsumedState))
        );
        assert_eq!(cancel_ballot_aggregation(aggregation_handle), Ok(()));
        assert_eq!(
            cancel_ballot_aggregation(aggregation_handle),
            Err(refusal_status(RefusalReason::ConsumedState))
        );
        accepted_setup
            .release_test_minted()
            .expect("test-minted accepted setup releases after pipeline retirement");
        (store_bytes, snapshot)
    }

    #[test]
    fn ffi_session_is_single_resident_preserves_wrong_handle_and_poison_drops_state() {
        reset_registry();
        let mut status = u32::MAX;
        let aggregation_handle =
            unsafe { sealed_lattice_ballot_aggregation_begin(71, &mut status) };
        assert_ne!(aggregation_handle, 0);
        assert_eq!(status, 0);

        let duplicate_handle = unsafe { sealed_lattice_ballot_aggregation_begin(72, &mut status) };
        assert_eq!(duplicate_handle, 0);
        assert_eq!(
            status,
            refusal_status(RefusalReason::OutsideSupportedProfile)
        );
        assert_eq!(
            sealed_lattice_ballot_aggregation_cancel(aggregation_handle + 1),
            refusal_status(RefusalReason::ConsumedState)
        );

        assert_eq!(
            sealed_lattice_ballot_aggregation_absorb(aggregation_handle, 0),
            refusal_status(RefusalReason::ConsumedState)
        );
        assert_eq!(
            sealed_lattice_ballot_aggregation_cancel(aggregation_handle),
            refusal_status(RefusalReason::ConsumedState)
        );

        let replacement_handle =
            unsafe { sealed_lattice_ballot_aggregation_begin(71, &mut status) };
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
    fn progress_record_distinguishes_store_reads_from_completed_absorption() {
        let request = EvaluatorKeyStoreReadRequest::from_test_values(
            u64::MAX - 11,
            FOUNDATION_PROFILE.stream_chunk_byte_length,
        );
        let encoded = encode_progress(BallotAggregationProgress::StoreReadRequired(request))
            .expect("the selected stream chunk fits the progress record");
        assert_eq!(u16::from_le_bytes(encoded[..2].try_into().unwrap()), 2);
        assert_eq!(u16::from_le_bytes(encoded[2..4].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(encoded[4..12].try_into().unwrap()),
            u64::MAX - 11
        );
        assert_eq!(
            u32::from_le_bytes(encoded[12..16].try_into().unwrap()),
            u32::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length).unwrap()
        );

        assert!(encoded[16..].iter().all(|byte| *byte == 0));

        let absorbed = encode_progress(BallotAggregationProgress::BallotAbsorbed {
            ballot_package_object_hash: [0x41; Hash512::BYTE_LENGTH],
            producer_roster_position: 7,
            verified_setup_source_hash: [0x52; Hash512::BYTE_LENGTH],
        })
        .expect("ballot-absorbed progress encodes");
        assert_eq!(u16::from_le_bytes(absorbed[..2].try_into().unwrap()), 2);
        assert_eq!(u16::from_le_bytes(absorbed[2..4].try_into().unwrap()), 2);
        assert_eq!(u16::from_le_bytes(absorbed[4..6].try_into().unwrap()), 7);
        assert_eq!(&absorbed[6..8], &[0, 0]);
        assert_eq!(
            &absorbed[BALLOT_AGGREGATION_PROGRESS_BALLOT_HASH_START
                ..BALLOT_AGGREGATION_PROGRESS_SETUP_SOURCE_HASH_START],
            &[0x41; Hash512::BYTE_LENGTH]
        );
        assert_eq!(
            &absorbed[BALLOT_AGGREGATION_PROGRESS_SETUP_SOURCE_HASH_START..],
            &[0x52; Hash512::BYTE_LENGTH]
        );
    }

    #[test]
    #[ignore = "guarded selected-suite encrypted product and decryption evidence"]
    fn heavy_rust_kernel_ballot_aggregation_runtime_products_and_decrypts_every_selected_count() {
        reset_registry();
        let (relinearization_component_byte_length, total_store_byte_length) =
            selected_minimal_store_byte_lengths();
        let expected_relinearization_store_byte_count = u64::try_from(
            relinearization_component_byte_length
                .checked_mul(2)
                .expect("two relinearization components fit usize"),
        )
        .expect("relinearization store byte count fits u64");
        let relinearization_topology =
            KeySwitchDecompositionTopology::for_level(SELECTED_RELINEARIZATION_KEY_LEVEL)
                .expect("selected relinearization decomposition topology");
        let expected_relinearization_ntt_transform_count = relinearization_topology
            .data_block_count()
            .checked_mul(relinearization_topology.extended_limb_count())
            .and_then(|count| count.checked_mul(2))
            .expect("selected relinearization transform count fits usize");
        let mut store_bytes = vec![0_u8; total_store_byte_length];

        for ballot_count in 1..=usize::from(FOUNDATION_PROFILE.participant_count) {
            let (returned_store_bytes, fresh_snapshot) = execute_deterministic_aggregation(
                store_bytes,
                ballot_count,
                expected_relinearization_store_byte_count,
                expected_relinearization_ntt_transform_count,
            );
            let (returned_store_bytes, resumed_snapshot) = execute_deterministic_aggregation(
                returned_store_bytes,
                ballot_count,
                expected_relinearization_store_byte_count,
                expected_relinearization_ntt_transform_count,
            );
            assert_eq!(
                resumed_snapshot, fresh_snapshot,
                "freshly reminted authorities must reproduce deterministic aggregation for {ballot_count} ballots"
            );
            store_bytes = returned_store_bytes;
        }
        reset_registry();
    }
}
