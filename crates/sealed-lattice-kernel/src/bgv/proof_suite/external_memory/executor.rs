use zeroize::Zeroizing;

use super::plan::{
    ProofExternalMemory, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
};
use super::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
};

/// Cancellation is owned by the participant-operation worker.  It is checked
/// between every bounded storage transaction and every arithmetic chunk.
pub(crate) trait ProofCancellation {
    fn cancellation_requested(&self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofExternalMemoryObjectState {
    Issued,
    Writing { written_byte_length: u64 },
    Sealed,
    Claimed,
    Consumed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryUsage {
    pub(crate) total_written_byte_length: u64,
    pub(crate) total_read_byte_length: u64,
    pub(crate) peak_stored_byte_length: u64,
    pub(crate) transaction_count: u64,
    pub(crate) deleted_object_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryError {
    InvalidPlan,
    UnknownObject,
    WrongStep,
    InvalidLifecycle,
    WrongOffsetOrLength,
    ResourceLimitExceeded,
    Cancelled,
    Incomplete,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryExecutorError<StorageError> {
    Execution(ProofExternalMemoryError),
    Storage(StorageError),
    StorageAbort {
        operation_error: StorageError,
        abort_error: StorageError,
    },
    StorageCommit(StorageError),
}

impl<StorageError> From<ProofExternalMemoryError>
    for ProofExternalMemoryExecutorError<StorageError>
{
    fn from(error: ProofExternalMemoryError) -> Self {
        Self::Execution(error)
    }
}

/// Stateful plan executor.  It mirrors only small lifecycle metadata; object
/// contents remain in the external store and reads use caller-owned bounded
/// buffers.
pub(crate) struct ProofExternalMemoryExecutor {
    plan: ProofExternalMemoryPlan,
    current_step: u32,
    states: Box<[(ProofExternalMemoryObject, ProofExternalMemoryObjectState)]>,
    current_stored_byte_length: u64,
    usage: ProofExternalMemoryUsage,
    terminal: bool,
}

impl ProofExternalMemoryExecutor {
    pub(crate) fn planned_resident_owned_payload_byte_length(
        plan: &ProofExternalMemoryPlan,
    ) -> Result<u64, ProofExternalMemoryError> {
        let object_plan_catalog_byte_length = u64::try_from(plan.objects.capacity())
            .ok()
            .and_then(|capacity| {
                capacity.checked_mul(
                    u64::try_from(std::mem::size_of::<ProofExternalMemoryObjectPlan>()).ok()?,
                )
            })
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let object_state_catalog_byte_length = u64::try_from(plan.objects.len())
            .ok()
            .and_then(|length| {
                length.checked_mul(
                    u64::try_from(std::mem::size_of::<(
                        ProofExternalMemoryObject,
                        ProofExternalMemoryObjectState,
                    )>())
                    .ok()?,
                )
            })
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        object_plan_catalog_byte_length
            .checked_add(object_state_catalog_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)
    }

    pub(crate) fn new(plan: ProofExternalMemoryPlan) -> Self {
        let mut states = plan
            .objects
            .iter()
            .map(|object| (object.object, ProofExternalMemoryObjectState::Issued))
            .collect::<Vec<_>>();
        states.sort_unstable_by_key(|(object, _)| *object);
        Self {
            plan,
            current_step: 0,
            states: states.into_boxed_slice(),
            current_stored_byte_length: 0,
            usage: ProofExternalMemoryUsage::default(),
            terminal: false,
        }
    }

    pub(crate) const fn current_step(&self) -> u32 {
        self.current_step
    }

    pub(crate) const fn maximum_chunk_byte_length(&self) -> u32 {
        self.plan.maximum_chunk_byte_length
    }

    pub(crate) const fn usage(&self) -> ProofExternalMemoryUsage {
        self.usage
    }

    pub(crate) fn begin_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        let object_plan = self.object_plan(object)?;
        if self.current_step != object_plan.issued_step
            || self.state(object)? != ProofExternalMemoryObjectState::Issued
        {
            return Err(ProofExternalMemoryError::WrongStep.into());
        }
        let next_stored_byte_length = self
            .current_stored_byte_length
            .checked_add(object_plan.exact_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if next_stored_byte_length > self.plan.maximum_stored_byte_length {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }

        self.run_mutating_transaction(storage, 0, |storage| {
            storage.create_object(
                object_plan.object,
                object_plan.protection,
                object_plan.exact_byte_length,
            )
        })?;
        self.set_state(
            object,
            ProofExternalMemoryObjectState::Writing {
                written_byte_length: 0,
            },
        )?;
        self.current_stored_byte_length = next_stored_byte_length;
        self.usage.peak_stored_byte_length = self
            .usage
            .peak_stored_byte_length
            .max(self.current_stored_byte_length);
        Ok(())
    }

    pub(crate) fn append_object_bytes<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
        bytes: &[u8],
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        if bytes.is_empty()
            || bytes.len()
                > usize::try_from(self.plan.maximum_chunk_byte_length)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
        {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        let object_plan = self.object_plan(object)?;
        if self.current_step < object_plan.issued_step || self.current_step > object_plan.seal_step
        {
            return Err(ProofExternalMemoryError::WrongStep.into());
        }
        let ProofExternalMemoryObjectState::Writing {
            written_byte_length,
        } = self.state(object)?
        else {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        };
        let chunk_byte_length = u64::try_from(bytes.len())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let remaining_object_byte_length = object_plan
            .exact_byte_length
            .checked_sub(written_byte_length)
            .ok_or(ProofExternalMemoryError::InvalidLifecycle)?;
        let expected_chunk_byte_length =
            remaining_object_byte_length.min(u64::from(self.plan.maximum_chunk_byte_length));
        if chunk_byte_length != expected_chunk_byte_length {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        let next_object_byte_length = written_byte_length
            .checked_add(chunk_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let next_total_written = self
            .usage
            .total_written_byte_length
            .checked_add(chunk_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if next_object_byte_length > object_plan.exact_byte_length
            || next_total_written > self.plan.maximum_total_written_byte_length
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }

        self.run_mutating_transaction(storage, chunk_byte_length, |storage| {
            storage.append_object_bytes(object, written_byte_length, bytes)
        })?;
        self.set_state(
            object,
            ProofExternalMemoryObjectState::Writing {
                written_byte_length: next_object_byte_length,
            },
        )?;
        self.usage.total_written_byte_length = next_total_written;
        Ok(())
    }

    pub(crate) fn seal_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        let object_plan = self.object_plan(object)?;
        if self.current_step > object_plan.seal_step
            || self.state(object)?
                != (ProofExternalMemoryObjectState::Writing {
                    written_byte_length: object_plan.exact_byte_length,
                })
        {
            return Err(ProofExternalMemoryError::Incomplete.into());
        }
        self.run_mutating_transaction(storage, 0, |storage| storage.seal_object(object))?;
        self.set_state(object, ProofExternalMemoryObjectState::Sealed)?;
        Ok(())
    }

    pub(crate) fn read_object_bytes<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        if destination.is_empty()
            || destination.len()
                > usize::try_from(self.plan.maximum_chunk_byte_length)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
        {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        let object_plan = self.object_plan(object)?;
        if self.current_step < object_plan.seal_step
            || self.current_step > object_plan.last_use_step
            || !matches!(
                self.state(object)?,
                ProofExternalMemoryObjectState::Sealed | ProofExternalMemoryObjectState::Claimed
            )
        {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        }
        let destination_byte_length = u64::try_from(destination.len())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let end = offset
            .checked_add(destination_byte_length)
            .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)?;
        let next_total_read = self
            .usage
            .total_read_byte_length
            .checked_add(destination_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if end > object_plan.exact_byte_length
            || next_total_read > self.plan.maximum_total_read_byte_length
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }

        self.begin_transaction(storage)?;
        if let Err(operation_error) = storage.read_object_bytes(object, offset, destination) {
            return Err(abort_after_storage_error(storage, operation_error));
        }
        if let Err(error) = storage.commit_transaction() {
            return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
        }
        self.record_transaction()?;
        self.set_state(object, ProofExternalMemoryObjectState::Claimed)?;
        self.usage.total_read_byte_length = next_total_read;
        Ok(())
    }

    /// Completes the current liveness step, deleting every object whose exact
    /// last use is this step in one transaction.  A seal deadline cannot be
    /// crossed with an incomplete object.
    pub(crate) fn complete_step<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        for object_plan in &self.plan.objects {
            if object_plan.seal_step == self.current_step
                && matches!(
                    self.state(object_plan.object)?,
                    ProofExternalMemoryObjectState::Issued
                        | ProofExternalMemoryObjectState::Writing { .. }
                )
            {
                return Err(ProofExternalMemoryError::Incomplete.into());
            }
        }

        let due_for_deletion = self
            .plan
            .objects
            .iter()
            .filter(|object| object.last_use_step == self.current_step)
            .copied()
            .collect::<Vec<_>>();
        for object in &due_for_deletion {
            if !matches!(
                self.state(object.object)?,
                ProofExternalMemoryObjectState::Sealed | ProofExternalMemoryObjectState::Claimed
            ) {
                return Err(ProofExternalMemoryError::Incomplete.into());
            }
        }

        if !due_for_deletion.is_empty() {
            self.begin_transaction(storage)?;
            for object in &due_for_deletion {
                if let Err(operation_error) = storage.delete_object(object.object) {
                    return Err(abort_after_storage_error(storage, operation_error));
                }
            }
            if let Err(error) = storage.commit_transaction() {
                return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
            }
            self.record_transaction()?;
            for object in &due_for_deletion {
                self.set_state(object.object, ProofExternalMemoryObjectState::Consumed)?;
                self.current_stored_byte_length = self
                    .current_stored_byte_length
                    .checked_sub(object.exact_byte_length)
                    .ok_or(ProofExternalMemoryError::InvalidLifecycle)?;
                self.usage.deleted_object_count = self
                    .usage
                    .deleted_object_count
                    .checked_add(1)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
            }
        }

        self.current_step = self
            .current_step
            .checked_add(1)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if self.current_step == self.plan.step_count {
            if self.current_stored_byte_length != 0
                || self
                    .states
                    .iter()
                    .any(|(_, state)| *state != ProofExternalMemoryObjectState::Consumed)
            {
                return Err(ProofExternalMemoryError::Incomplete.into());
            }
            self.terminal = true;
        }
        Ok(())
    }

    pub(crate) fn check_cancellation<Storage, Cancellation>(
        &mut self,
        storage: &mut Storage,
        cancellation: &Cancellation,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>>
    where
        Storage: ProofExternalMemory,
        Cancellation: ProofCancellation,
    {
        if !cancellation.cancellation_requested() {
            return Ok(());
        }
        self.cancel(storage)?;
        Err(ProofExternalMemoryError::Cancelled.into())
    }

    /// Idempotently makes every live object unreachable.  The backend's
    /// best-effort physical deletion happens behind the committed transaction.
    pub(crate) fn cancel<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.terminal {
            return Ok(());
        }
        let live_objects = self
            .states
            .iter()
            .filter_map(|(object, state)| {
                matches!(
                    state,
                    ProofExternalMemoryObjectState::Writing { .. }
                        | ProofExternalMemoryObjectState::Sealed
                        | ProofExternalMemoryObjectState::Claimed
                )
                .then_some(*object)
            })
            .collect::<Vec<_>>();
        if !live_objects.is_empty() {
            self.begin_transaction(storage)?;
            for object in &live_objects {
                if let Err(operation_error) = storage.delete_object(*object) {
                    return Err(abort_after_storage_error(storage, operation_error));
                }
            }
            if let Err(error) = storage.commit_transaction() {
                return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
            }
            self.record_transaction()?;
        }
        for (_, state) in self.states.iter_mut() {
            if *state != ProofExternalMemoryObjectState::Consumed {
                *state = ProofExternalMemoryObjectState::Cancelled;
            }
        }
        self.current_stored_byte_length = 0;
        self.terminal = true;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<ProofExternalMemoryUsage, ProofExternalMemoryError> {
        if !self.terminal
            || self.current_step != self.plan.step_count
            || self.current_stored_byte_length != 0
        {
            return Err(ProofExternalMemoryError::Incomplete);
        }
        Ok(self.usage)
    }

    fn object_plan(
        &self,
        object: ProofExternalMemoryObject,
    ) -> Result<ProofExternalMemoryObjectPlan, ProofExternalMemoryError> {
        self.plan
            .objects
            .iter()
            .find(|entry| entry.object == object)
            .copied()
            .ok_or(ProofExternalMemoryError::UnknownObject)
    }

    fn state(
        &self,
        object: ProofExternalMemoryObject,
    ) -> Result<ProofExternalMemoryObjectState, ProofExternalMemoryError> {
        self.states
            .binary_search_by_key(&object, |(catalog_object, _)| *catalog_object)
            .ok()
            .and_then(|index| self.states.get(index))
            .map(|(_, state)| *state)
            .ok_or(ProofExternalMemoryError::UnknownObject)
    }

    fn set_state(
        &mut self,
        object: ProofExternalMemoryObject,
        state: ProofExternalMemoryObjectState,
    ) -> Result<(), ProofExternalMemoryError> {
        let index = self
            .states
            .binary_search_by_key(&object, |(catalog_object, _)| *catalog_object)
            .map_err(|_| ProofExternalMemoryError::UnknownObject)?;
        self.states[index].1 = state;
        Ok(())
    }

    fn require_active(&self) -> Result<(), ProofExternalMemoryError> {
        if self.terminal || self.current_step >= self.plan.step_count {
            return Err(ProofExternalMemoryError::InvalidLifecycle);
        }
        Ok(())
    }

    fn begin_transaction<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.usage.transaction_count >= self.plan.maximum_transaction_count {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }
        storage
            .begin_transaction(
                self.plan.maximum_transaction_payload_byte_length,
                self.plan.maximum_transaction_operation_count,
            )
            .map_err(ProofExternalMemoryExecutorError::Storage)
    }

    fn record_transaction(&mut self) -> Result<(), ProofExternalMemoryError> {
        self.usage.transaction_count = self
            .usage
            .transaction_count
            .checked_add(1)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if self.usage.transaction_count > self.plan.maximum_transaction_count {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn run_mutating_transaction<Storage, Operation>(
        &mut self,
        storage: &mut Storage,
        payload_byte_length: u64,
        operation: Operation,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>>
    where
        Storage: ProofExternalMemory,
        Operation: FnOnce(&mut Storage) -> Result<(), Storage::Error>,
    {
        if payload_byte_length > self.plan.maximum_transaction_payload_byte_length {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }
        self.begin_transaction(storage)?;
        if let Err(operation_error) = operation(storage) {
            return Err(abort_after_storage_error(storage, operation_error));
        }
        if let Err(error) = storage.commit_transaction() {
            return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
        }
        self.record_transaction()?;
        Ok(())
    }
}

fn abort_after_storage_error<Storage: ProofExternalMemory>(
    storage: &mut Storage,
    operation_error: Storage::Error,
) -> ProofExternalMemoryExecutorError<Storage::Error> {
    match storage.abort_transaction() {
        Ok(()) => ProofExternalMemoryExecutorError::Storage(operation_error),
        Err(abort_error) => ProofExternalMemoryExecutorError::StorageAbort {
            operation_error,
            abort_error,
        },
    }
}
