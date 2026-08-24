use zeroize::Zeroizing;

use super::plan::{ProofExternalMemory, ProofExternalMemoryObject, ProofExternalMemoryPlan};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofExternalMemoryObjectState {
    Issued,
    Writing {
        written_byte_length: u64,
        append_count: u64,
    },
    Sealed,
    Claimed,
    Consumed,
    Cancelled,
}

pub(super) const PROOF_EXTERNAL_MEMORY_OBJECT_STATE_BYTE_LENGTH: usize =
    core::mem::size_of::<ProofExternalMemoryObjectState>();

struct ValidatedAppendTransition {
    plan_index: usize,
    written_byte_length: u64,
    chunk_byte_length: u64,
    next_object_byte_length: u64,
    next_append_count: u64,
    next_total_written_byte_length: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryUsage {
    pub(crate) total_written_byte_length: u64,
    pub(crate) total_read_byte_length: u64,
    pub(crate) peak_stored_byte_length: u64,
    pub(crate) transaction_count: u64,
    pub(crate) deleted_object_count: u32,
}

impl ProofExternalMemoryUsage {
    pub(crate) const fn total_written_byte_length(self) -> u64 {
        self.total_written_byte_length
    }

    pub(crate) const fn total_read_byte_length(self) -> u64 {
        self.total_read_byte_length
    }

    pub(crate) const fn peak_stored_byte_length(self) -> u64 {
        self.peak_stored_byte_length
    }

    pub(crate) const fn transaction_count(self) -> u64 {
        self.transaction_count
    }

    pub(crate) const fn deleted_object_count(self) -> u32 {
        self.deleted_object_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryError {
    InvalidPlan,
    UnknownObject,
    WrongStep,
    InvalidLifecycle,
    WrongOffsetOrLength,
    ResourceLimitExceeded,
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
    states: Box<[ProofExternalMemoryObjectState]>,
    current_stored_byte_length: u64,
    usage: ProofExternalMemoryUsage,
    terminal: bool,
}

impl ProofExternalMemoryExecutor {
    pub(crate) fn new(mut plan: ProofExternalMemoryPlan) -> Self {
        plan.objects
            .sort_unstable_by_key(|object| (object.object, object.issued_step));
        let states = vec![ProofExternalMemoryObjectState::Issued; plan.objects.len()];
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

    /// Restores a test-evidence constraint boundary after deterministic replay
    /// has recreated every long-lived source object. Constraint-local output
    /// lifecycles before `restored_step` are absent from the fresh store and
    /// become consumed; future lifecycles remain unissued.
    #[cfg(test)]
    pub(crate) fn restore_completed_constraint_step_prefix(
        &mut self,
        restored_step: u32,
        restored_usage: ProofExternalMemoryUsage,
    ) -> Result<(), ProofExternalMemoryError> {
        self.require_active()?;
        let replayed_step = self.current_step;
        if restored_step <= replayed_step || restored_step >= self.plan.step_count {
            return Err(ProofExternalMemoryError::WrongStep);
        }

        let mut skipped_object_count = 0_u32;
        let mut skipped_written_byte_length = 0_u64;
        for (plan_index, object_plan) in self.plan.objects.iter().copied().enumerate() {
            let state = self.state(plan_index)?;
            if object_plan.last_use_step < replayed_step {
                if state != ProofExternalMemoryObjectState::Consumed {
                    return Err(ProofExternalMemoryError::InvalidLifecycle);
                }
            } else if object_plan.issued_step >= replayed_step
                && object_plan.last_use_step < restored_step
            {
                if state != ProofExternalMemoryObjectState::Issued
                    || object_plan.issued_step >= restored_step
                {
                    return Err(ProofExternalMemoryError::InvalidLifecycle);
                }
                skipped_written_byte_length = skipped_written_byte_length
                    .checked_add(object_plan.exact_byte_length)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                skipped_object_count = skipped_object_count
                    .checked_add(1)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
            } else if object_plan.issued_step < restored_step
                && object_plan.last_use_step >= restored_step
            {
                if !matches!(
                    state,
                    ProofExternalMemoryObjectState::Sealed
                        | ProofExternalMemoryObjectState::Claimed
                ) {
                    return Err(ProofExternalMemoryError::InvalidLifecycle);
                }
            } else if object_plan.issued_step >= restored_step {
                if state != ProofExternalMemoryObjectState::Issued {
                    return Err(ProofExternalMemoryError::InvalidLifecycle);
                }
            } else {
                return Err(ProofExternalMemoryError::InvalidLifecycle);
            }
        }

        let expected_total_written_byte_length = self
            .usage
            .total_written_byte_length
            .checked_add(skipped_written_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let expected_deleted_object_count = self
            .usage
            .deleted_object_count
            .checked_add(skipped_object_count)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if restored_usage.total_written_byte_length != expected_total_written_byte_length
            || restored_usage.total_written_byte_length
                > self.plan.maximum_total_written_byte_length
            || restored_usage.total_read_byte_length < self.usage.total_read_byte_length
            || restored_usage.total_read_byte_length > self.plan.maximum_total_read_byte_length
            || restored_usage.peak_stored_byte_length < self.usage.peak_stored_byte_length
            || restored_usage.peak_stored_byte_length < self.current_stored_byte_length
            || restored_usage.peak_stored_byte_length > self.plan.maximum_stored_byte_length
            || restored_usage.transaction_count < self.usage.transaction_count
            || restored_usage.transaction_count > self.plan.maximum_transaction_count
            || restored_usage.deleted_object_count != expected_deleted_object_count
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }

        for (plan_index, object_plan) in self.plan.objects.iter().copied().enumerate() {
            if object_plan.issued_step >= replayed_step
                && object_plan.issued_step < restored_step
                && object_plan.last_use_step < restored_step
            {
                self.states[plan_index] = ProofExternalMemoryObjectState::Consumed;
            }
        }
        self.current_step = restored_step;
        self.usage = restored_usage;
        Ok(())
    }

    pub(crate) fn begin_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        let plan_index = self.issued_object_plan_index(object)?;
        let object_plan = self.plan.objects[plan_index];
        if self.current_step != object_plan.issued_step
            || self.state(plan_index)? != ProofExternalMemoryObjectState::Issued
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
            plan_index,
            ProofExternalMemoryObjectState::Writing {
                written_byte_length: 0,
                append_count: 0,
            },
        )?;
        self.current_stored_byte_length = next_stored_byte_length;
        self.usage.peak_stored_byte_length = self
            .usage
            .peak_stored_byte_length
            .max(self.current_stored_byte_length);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn append_object_bytes<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
        bytes: &[u8],
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        let transition = self.validate_append_object_bytes(object, bytes.len())?;

        self.run_mutating_transaction(storage, transition.chunk_byte_length, |storage| {
            storage.append_object_bytes(object, transition.written_byte_length, bytes)
        })?;
        self.set_state(
            transition.plan_index,
            ProofExternalMemoryObjectState::Writing {
                written_byte_length: transition.next_object_byte_length,
                append_count: transition.next_append_count,
            },
        )?;
        self.usage.total_written_byte_length = transition.next_total_written_byte_length;
        Ok(())
    }

    pub(crate) fn append_owned_object_bytes<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
        bytes: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        let transition = self.validate_append_object_bytes(object, bytes.len())?;

        self.run_mutating_transaction(storage, transition.chunk_byte_length, |storage| {
            storage.append_owned_object_bytes(object, transition.written_byte_length, bytes)
        })?;
        self.set_state(
            transition.plan_index,
            ProofExternalMemoryObjectState::Writing {
                written_byte_length: transition.next_object_byte_length,
                append_count: transition.next_append_count,
            },
        )?;
        self.usage.total_written_byte_length = transition.next_total_written_byte_length;
        Ok(())
    }

    fn validate_append_object_bytes(
        &self,
        object: ProofExternalMemoryObject,
        byte_length: usize,
    ) -> Result<ValidatedAppendTransition, ProofExternalMemoryError> {
        self.require_active()?;
        if byte_length == 0
            || byte_length
                > usize::try_from(self.plan.maximum_chunk_byte_length)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
        {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength);
        }
        let plan_index = self.active_object_plan_index(object)?;
        let object_plan = self.plan.objects[plan_index];
        if self.current_step < object_plan.issued_step || self.current_step > object_plan.seal_step
        {
            return Err(ProofExternalMemoryError::WrongStep);
        }
        let ProofExternalMemoryObjectState::Writing {
            written_byte_length,
            append_count,
        } = self.state(plan_index)?
        else {
            return Err(ProofExternalMemoryError::InvalidLifecycle);
        };
        let chunk_byte_length = u64::try_from(byte_length)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let remaining_object_byte_length = object_plan
            .exact_byte_length
            .checked_sub(written_byte_length)
            .ok_or(ProofExternalMemoryError::InvalidLifecycle)?;
        let maximum_chunk_byte_length = u64::from(self.plan.maximum_chunk_byte_length);
        let expected_chunk_byte_length =
            remaining_object_byte_length.min(maximum_chunk_byte_length);
        if chunk_byte_length > expected_chunk_byte_length {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength);
        }
        let next_append_count = append_count
            .checked_add(1)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if next_append_count > object_plan.maximum_append_count {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }
        let next_object_byte_length = written_byte_length
            .checked_add(chunk_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let remaining_after_append = object_plan
            .exact_byte_length
            .checked_sub(next_object_byte_length)
            .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)?;
        let remaining_append_capacity = object_plan
            .maximum_append_count
            .checked_sub(next_append_count)
            .and_then(|count| count.checked_mul(maximum_chunk_byte_length))
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if remaining_after_append > remaining_append_capacity {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength);
        }
        let next_total_written_byte_length = self
            .usage
            .total_written_byte_length
            .checked_add(chunk_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if next_object_byte_length > object_plan.exact_byte_length
            || next_total_written_byte_length > self.plan.maximum_total_written_byte_length
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }
        Ok(ValidatedAppendTransition {
            plan_index,
            written_byte_length,
            chunk_byte_length,
            next_object_byte_length,
            next_append_count,
            next_total_written_byte_length,
        })
    }

    pub(crate) fn seal_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        let plan_index = self.active_object_plan_index(object)?;
        let object_plan = self.plan.objects[plan_index];
        if self.current_step > object_plan.seal_step
            || !matches!(
                self.state(plan_index)?,
                ProofExternalMemoryObjectState::Writing {
                    written_byte_length,
                    ..
                } if written_byte_length == object_plan.exact_byte_length
            )
        {
            return Err(ProofExternalMemoryError::Incomplete.into());
        }
        self.run_mutating_transaction(storage, 0, |storage| storage.seal_object(object))?;
        self.set_state(plan_index, ProofExternalMemoryObjectState::Sealed)?;
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
        let plan_index = self.active_object_plan_index(object)?;
        let object_plan = self.plan.objects[plan_index];
        if self.current_step < object_plan.seal_step
            || self.current_step > object_plan.last_use_step
            || !matches!(
                self.state(plan_index)?,
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
        self.set_state(plan_index, ProofExternalMemoryObjectState::Claimed)?;
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
        for (plan_index, object_plan) in self.plan.objects.iter().enumerate() {
            if object_plan.seal_step == self.current_step
                && matches!(
                    self.state(plan_index)?,
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
            .copied()
            .enumerate()
            .filter(|(_, object)| object.last_use_step == self.current_step)
            .collect::<Vec<_>>();
        for (plan_index, _) in &due_for_deletion {
            if !matches!(
                self.state(*plan_index)?,
                ProofExternalMemoryObjectState::Sealed | ProofExternalMemoryObjectState::Claimed
            ) {
                return Err(ProofExternalMemoryError::Incomplete.into());
            }
        }

        if !due_for_deletion.is_empty() {
            self.begin_transaction(storage)?;
            for (_, object) in &due_for_deletion {
                if let Err(operation_error) = storage.delete_object(object.object) {
                    return Err(abort_after_storage_error(storage, operation_error));
                }
            }
            if let Err(error) = storage.commit_transaction() {
                return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
            }
            self.record_transaction()?;
            for (plan_index, object) in &due_for_deletion {
                self.set_state(*plan_index, ProofExternalMemoryObjectState::Consumed)?;
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
                    .any(|state| *state != ProofExternalMemoryObjectState::Consumed)
            {
                return Err(ProofExternalMemoryError::Incomplete.into());
            }
            self.terminal = true;
        }
        Ok(())
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
        let state_is_live = |state: &ProofExternalMemoryObjectState| {
            matches!(
                state,
                ProofExternalMemoryObjectState::Writing { .. }
                    | ProofExternalMemoryObjectState::Sealed
                    | ProofExternalMemoryObjectState::Claimed
            )
        };
        let mut previous_live_object = None;
        let unique_live_object_count = self
            .plan
            .objects
            .iter()
            .zip(self.states.iter())
            .filter(|(_, state)| state_is_live(state))
            .filter(|(object_plan, _)| {
                if previous_live_object == Some(object_plan.object) {
                    false
                } else {
                    previous_live_object = Some(object_plan.object);
                    true
                }
            })
            .count();
        let mut live_objects = Vec::new();
        live_objects
            .try_reserve_exact(unique_live_object_count)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        for (object_plan, _) in self
            .plan
            .objects
            .iter()
            .zip(self.states.iter())
            .filter(|(_, state)| state_is_live(state))
        {
            if live_objects.last().copied() != Some(object_plan.object) {
                live_objects.push(object_plan.object);
            }
        }
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
        for state in self.states.iter_mut() {
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

    fn object_plan_range(
        &self,
        object: ProofExternalMemoryObject,
    ) -> Result<core::ops::Range<usize>, ProofExternalMemoryError> {
        let first = self
            .plan
            .objects
            .partition_point(|entry| entry.object < object);
        let end = self
            .plan
            .objects
            .partition_point(|entry| entry.object <= object);
        if first == end {
            return Err(ProofExternalMemoryError::UnknownObject);
        }
        Ok(first..end)
    }

    fn issued_object_plan_index(
        &self,
        object: ProofExternalMemoryObject,
    ) -> Result<usize, ProofExternalMemoryError> {
        self.object_plan_range(object)?
            .find(|index| self.plan.objects[*index].issued_step == self.current_step)
            .ok_or(ProofExternalMemoryError::WrongStep)
    }

    fn active_object_plan_index(
        &self,
        object: ProofExternalMemoryObject,
    ) -> Result<usize, ProofExternalMemoryError> {
        let range = self.object_plan_range(object)?;
        let candidate_count = self.plan.objects[range.clone()]
            .partition_point(|entry| entry.issued_step <= self.current_step);
        let plan_index = range
            .start
            .checked_add(candidate_count)
            .and_then(|end| end.checked_sub(1))
            .ok_or(ProofExternalMemoryError::WrongStep)?;
        let plan = self.plan.objects[plan_index];
        if self.current_step > plan.last_use_step {
            return Err(ProofExternalMemoryError::WrongStep);
        }
        Ok(plan_index)
    }

    fn state(
        &self,
        plan_index: usize,
    ) -> Result<ProofExternalMemoryObjectState, ProofExternalMemoryError> {
        self.states
            .get(plan_index)
            .copied()
            .ok_or(ProofExternalMemoryError::UnknownObject)
    }

    fn set_state(
        &mut self,
        plan_index: usize,
        state: ProofExternalMemoryObjectState,
    ) -> Result<(), ProofExternalMemoryError> {
        *self
            .states
            .get_mut(plan_index)
            .ok_or(ProofExternalMemoryError::UnknownObject)? = state;
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
