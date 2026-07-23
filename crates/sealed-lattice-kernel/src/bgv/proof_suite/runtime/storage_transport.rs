use super::super::external_memory::EXTERNAL_MEMORY_SINGLE_APPEND_RECYCLER_CAPACITY_CEILING;
use super::{
    CanonicalStreamDomain, CanonicalStreamWriter, CommonProofByteSink, CommonProofRuntimeError,
    CommonProofRuntimeLimits, HASH_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS,
    OUTPUT_WRITE_HASH_DOMAIN, ProofExternalMemory, ProofExternalMemoryProtection,
    ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionRecorder,
    ProofExternalMemoryTransactionReplay, ProofExternalMemoryTransactionRequest, StreamDescriptor,
    Zeroizing, hash_framed_parts_512,
};

/// One transaction pass of a pollable external-memory operation. Recording
/// yields an owned request. Supplying the browser's read results changes the
/// same object into an exact replay pass; the caller resets it only after the
/// cryptographic component reports that the transaction completed.
pub(crate) struct CommonProofStorageTransactionRuntime {
    pass: CommonProofStorageTransactionPass,
    runtime_binding_hash: [u8; HASH_BYTE_LENGTH],
    next_request_sequence: u64,
    operation_encoding_bytes: Zeroizing<Vec<u8>>,
    recycled_append_bytes: Vec<Zeroizing<Vec<u8>>>,
    recycled_read_results: Vec<Zeroizing<Vec<u8>>>,
}

enum CommonProofStorageTransactionPass {
    Recording(ProofExternalMemoryTransactionRecorder),
    RequestReady(ProofExternalMemoryTransactionRequest),
    Replaying(ProofExternalMemoryTransactionReplay),
    Cancelled,
}

#[cfg(test)]
type StorageAllocationIdentity = (usize, usize);
#[cfg(test)]
type PooledStorageIdentities = (
    StorageAllocationIdentity,
    StorageAllocationIdentity,
    Option<StorageAllocationIdentity>,
);

impl Default for CommonProofStorageTransactionRuntime {
    fn default() -> Self {
        Self::for_runtime_binding([0; HASH_BYTE_LENGTH])
    }
}

impl CommonProofStorageTransactionRuntime {
    pub(crate) fn for_runtime_binding(runtime_binding_hash: [u8; HASH_BYTE_LENGTH]) -> Self {
        Self {
            pass: CommonProofStorageTransactionPass::Recording(
                ProofExternalMemoryTransactionRecorder::for_runtime_binding(
                    runtime_binding_hash,
                    1,
                ),
            ),
            runtime_binding_hash,
            next_request_sequence: 1,
            operation_encoding_bytes: Zeroizing::new(Vec::new()),
            recycled_append_bytes: Vec::new(),
            recycled_read_results: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn storage(&mut self) -> &mut Self {
        self
    }

    /// Moves a recorder-yielded request into the host-visible pending state.
    /// Call this only after the component reports `StorageCommit(Yielded)`.
    pub(crate) fn capture_yielded_request(
        &mut self,
    ) -> Result<&ProofExternalMemoryTransactionRequest, CommonProofRuntimeError> {
        let CommonProofStorageTransactionPass::Recording(recorder) = &mut self.pass else {
            return Err(CommonProofRuntimeError::TransactionPending);
        };
        if !self.recycled_append_bytes.is_empty() || self.recycled_append_bytes.capacity() != 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let recycled_append_bytes = recorder.take_recycled_append_bytes();
        if recycled_append_bytes.capacity()
            > EXTERNAL_MEMORY_SINGLE_APPEND_RECYCLER_CAPACITY_CEILING
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let request = recorder
            .take_yielded_request()
            .ok_or(CommonProofRuntimeError::TransactionResponseMissing)?;
        self.recycled_append_bytes = recycled_append_bytes;
        if request.request_sequence() != self.next_request_sequence {
            return Err(CommonProofRuntimeError::TransactionReplayIncomplete);
        }
        self.next_request_sequence = self
            .next_request_sequence
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.pass = CommonProofStorageTransactionPass::RequestReady(request);
        let CommonProofStorageTransactionPass::RequestReady(request) = &self.pass else {
            unreachable!("the request-ready state was just installed")
        };
        Ok(request)
    }

    pub(crate) fn pending_request(&self) -> Option<&ProofExternalMemoryTransactionRequest> {
        match &self.pass {
            CommonProofStorageTransactionPass::RequestReady(request) => Some(request),
            _ => None,
        }
    }

    pub(crate) fn replay_is_active(&self) -> bool {
        matches!(self.pass, CommonProofStorageTransactionPass::Replaying(_))
    }

    pub(crate) fn encode_pending_worker_request(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, CommonProofRuntimeError> {
        self.pending_request()
            .ok_or(CommonProofRuntimeError::TransactionResponseMissing)?
            .encode_worker_request()
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
    }

    #[cfg(any(test, feature = "proof-storage-width-browser-evidence"))]
    pub(crate) fn encode_pending_worker_request_into(
        &mut self,
        encoded_request: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), CommonProofRuntimeError> {
        let CommonProofStorageTransactionPass::RequestReady(request) = &self.pass else {
            return Err(CommonProofRuntimeError::TransactionResponseMissing);
        };
        request
            .encode_worker_request_into(&mut self.operation_encoding_bytes, encoded_request)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
    }

    pub(crate) fn supply_worker_response(
        &mut self,
        encoded_response: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let CommonProofStorageTransactionPass::RequestReady(request) = &self.pass else {
            return Err(CommonProofRuntimeError::TransactionResponseMissing);
        };
        let read_result_count = request.read_result_count();
        let mut read_results = if read_result_count == 0 {
            Vec::new()
        } else {
            core::mem::take(&mut self.recycled_read_results)
        };
        if request
            .decode_worker_response_into(
                encoded_response,
                &mut self.operation_encoding_bytes,
                &mut read_results,
            )
            .is_err()
        {
            if read_result_count != 0 {
                self.recycled_read_results = read_results;
            }
            return Err(CommonProofRuntimeError::TransactionReplayIncomplete);
        }
        self.supply_read_results(read_results)
    }

    pub(crate) fn supply_read_results(
        &mut self,
        read_results: Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<(), CommonProofRuntimeError> {
        let previous = core::mem::replace(
            &mut self.pass,
            CommonProofStorageTransactionPass::Recording(
                ProofExternalMemoryTransactionRecorder::for_runtime_binding(
                    self.runtime_binding_hash,
                    self.next_request_sequence,
                ),
            ),
        );
        let CommonProofStorageTransactionPass::RequestReady(request) = previous else {
            self.pass = previous;
            return Err(CommonProofRuntimeError::TransactionResponseMissing);
        };
        match ProofExternalMemoryTransactionReplay::new(request, read_results) {
            Ok(replay) => {
                self.pass = CommonProofStorageTransactionPass::Replaying(replay);
                Ok(())
            }
            Err(_) => Err(CommonProofRuntimeError::TransactionReplayIncomplete),
        }
    }

    /// Releases replay bytes only after the resumed component advanced its own
    /// state. Calling this while a request is merely pending fails closed.
    pub(crate) fn transaction_completed(&mut self) -> Result<(), CommonProofRuntimeError> {
        if !matches!(
            &self.pass,
            CommonProofStorageTransactionPass::Replaying(replay)
                if replay.transaction_is_complete()
        ) {
            return Err(CommonProofRuntimeError::TransactionReplayIncomplete);
        }
        let previous =
            core::mem::replace(&mut self.pass, CommonProofStorageTransactionPass::Cancelled);
        let CommonProofStorageTransactionPass::Replaying(replay) = previous else {
            unreachable!("the replay state was checked before replacement")
        };
        let (active_operations, read_results) = replay
            .into_recycled_storage(&mut self.recycled_append_bytes)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        if !read_results.is_empty() {
            self.recycled_read_results = read_results;
        }
        self.pass = CommonProofStorageTransactionPass::Recording(
            ProofExternalMemoryTransactionRecorder::with_recycled_storage(
                self.runtime_binding_hash,
                self.next_request_sequence,
                active_operations,
                core::mem::take(&mut self.recycled_append_bytes),
            ),
        );
        Ok(())
    }

    pub(crate) fn cancel(&mut self) {
        self.pass = CommonProofStorageTransactionPass::Cancelled;
        self.next_request_sequence = 0;
    }

    #[cfg(test)]
    pub(crate) fn pooled_storage_identities(&self) -> PooledStorageIdentities {
        (
            (
                self.operation_encoding_bytes.as_ptr() as usize,
                self.operation_encoding_bytes.capacity(),
            ),
            (
                self.recycled_append_bytes.as_ptr() as usize,
                self.recycled_append_bytes.capacity(),
            ),
            self.recycled_read_results
                .first()
                .map(|bytes| (bytes.as_ptr() as usize, bytes.capacity())),
        )
    }
}

impl ProofExternalMemory for CommonProofStorageTransactionRuntime {
    type Error = ProofExternalMemoryTransactionAdapterError;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => {
                storage.begin_transaction(maximum_payload_byte_length, maximum_operation_count)
            }
            CommonProofStorageTransactionPass::Replaying(storage) => {
                storage.begin_transaction(maximum_payload_byte_length, maximum_operation_count)
            }
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn create_object(
        &mut self,
        object: super::super::ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => {
                storage.create_object(object, protection, exact_byte_length)
            }
            CommonProofStorageTransactionPass::Replaying(storage) => {
                storage.create_object(object, protection, exact_byte_length)
            }
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn append_object_bytes(
        &mut self,
        object: super::super::ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => {
                storage.append_object_bytes(object, expected_offset, bytes)
            }
            CommonProofStorageTransactionPass::Replaying(storage) => {
                storage.append_object_bytes(object, expected_offset, bytes)
            }
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn seal_object(
        &mut self,
        object: super::super::ProofExternalMemoryObject,
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.seal_object(object),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.seal_object(object),
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn read_object_bytes(
        &mut self,
        object: super::super::ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => {
                storage.read_object_bytes(object, offset, destination)
            }
            CommonProofStorageTransactionPass::Replaying(storage) => {
                storage.read_object_bytes(object, offset, destination)
            }
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn delete_object(
        &mut self,
        object: super::super::ProofExternalMemoryObject,
    ) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.delete_object(object),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.delete_object(object),
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.commit_transaction(),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.commit_transaction(),
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        match &mut self.pass {
            CommonProofStorageTransactionPass::Recording(storage) => storage.abort_transaction(),
            CommonProofStorageTransactionPass::Replaying(storage) => storage.abort_transaction(),
            CommonProofStorageTransactionPass::RequestReady(_)
            | CommonProofStorageTransactionPass::Cancelled => {
                Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PollableCommonProofByteSinkError {
    ChunkReady,
    ChunkAwaitingCommit,
    ChunkAwaitingReadback,
    ByteLengthExceeded,
    ReplayMismatch,
    AllocationLimitExceeded,
}

struct PendingOutputWrite {
    byte_length: usize,
    digest: [u8; HASH_BYTE_LENGTH],
    consumed_byte_length: usize,
}

/// Canonical proof output sink with one-chunk working memory. A write that
/// reaches a chunk boundary yields `ChunkReady`; after the browser transaction
/// acknowledges that exact chunk, retrying the exact same write continues at
/// the first unconsumed byte.
pub(crate) struct PollableCommonProofByteSink {
    declared_byte_length: usize,
    observed_byte_length: usize,
    next_chunk_index: usize,
    stream_writer: Option<CanonicalStreamWriter>,
    current_chunk: Zeroizing<Vec<u8>>,
    chunk_awaiting_commit: bool,
    chunk_awaiting_readback: bool,
    pending_write: Option<PendingOutputWrite>,
    terminal: bool,
}

impl PollableCommonProofByteSink {
    pub(crate) fn new(
        stream_domain: CanonicalStreamDomain,
        declared_byte_length: usize,
        limits: CommonProofRuntimeLimits,
    ) -> Result<Self, CommonProofRuntimeError> {
        if declared_byte_length == 0 || declared_byte_length > limits.proof_byte_length() {
            return Err(CommonProofRuntimeError::OutputByteLengthExceeded);
        }
        let stream_writer = CanonicalStreamWriter::new(
            stream_domain,
            u64::try_from(declared_byte_length)
                .map_err(|_| CommonProofRuntimeError::OutputByteLengthExceeded)?,
        )
        .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
        Ok(Self {
            declared_byte_length,
            observed_byte_length: 0,
            next_chunk_index: 0,
            stream_writer: Some(stream_writer),
            current_chunk: Zeroizing::new(Vec::new()),
            chunk_awaiting_commit: false,
            chunk_awaiting_readback: false,
            pending_write: None,
            terminal: false,
        })
    }

    pub(crate) fn pending_chunk(&self) -> Option<(usize, &[u8])> {
        self.chunk_awaiting_commit
            .then_some((self.next_chunk_index, self.current_chunk.as_slice()))
    }

    pub(crate) const fn pending_readback_chunk_index(&self) -> Option<usize> {
        if self.chunk_awaiting_readback {
            Some(self.next_chunk_index)
        } else {
            None
        }
    }

    pub(crate) fn complete_output_is_authenticated(&self) -> bool {
        !self.chunk_awaiting_commit
            && !self.chunk_awaiting_readback
            && self.pending_write.is_none()
            && self.observed_byte_length == self.declared_byte_length
            && self.current_chunk.is_empty()
            && !self.terminal
    }

    pub(crate) fn final_partial_chunk_is_ready(&self) -> bool {
        !self.chunk_awaiting_commit
            && !self.chunk_awaiting_readback
            && self.pending_write.is_none()
            && self.observed_byte_length == self.declared_byte_length
            && !self.current_chunk.is_empty()
            && !self.terminal
    }

    pub(crate) fn acknowledge_pending_chunk(&mut self) -> Result<(), CommonProofRuntimeError> {
        if !self.chunk_awaiting_commit || self.current_chunk.is_empty() {
            return Err(CommonProofRuntimeError::OutputChunkNotReady);
        }
        self.chunk_awaiting_commit = false;
        self.chunk_awaiting_readback = true;
        Ok(())
    }

    /// Accepts only a complete reread of the exact staged chunk. The stream
    /// descriptor advances from these reread bytes, never from the producer's
    /// pre-commit buffer or a host acknowledgement alone.
    pub(crate) fn confirm_pending_chunk_readback(
        &mut self,
        chunk_index: usize,
        readback_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        if !self.chunk_awaiting_readback
            || chunk_index != self.next_chunk_index
            || readback_bytes != self.current_chunk.as_slice()
        {
            return Err(CommonProofRuntimeError::OutputWriteReplayMismatch);
        }
        self.stream_writer
            .as_mut()
            .ok_or(CommonProofRuntimeError::OutputChunkNotReady)?
            .absorb_chunk(self.next_chunk_index, readback_bytes)
            .map_err(|_| CommonProofRuntimeError::OutputWriteReplayMismatch)?;
        self.current_chunk.clear();
        self.chunk_awaiting_readback = false;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::OutputByteLengthExceeded)?;
        Ok(())
    }

    /// Makes a non-full final chunk visible for acknowledgement after the
    /// producer has supplied exactly the declared number of bytes.
    pub(crate) fn seal_final_chunk(&mut self) -> Result<(), CommonProofRuntimeError> {
        if self.chunk_awaiting_commit {
            return Err(CommonProofRuntimeError::OutputChunkAwaitingCommit);
        }
        if self.chunk_awaiting_readback {
            return Err(CommonProofRuntimeError::OutputChunkAwaitingReadback);
        }
        if self.observed_byte_length != self.declared_byte_length
            || self.current_chunk.is_empty()
            || self.pending_write.is_some()
        {
            return Err(CommonProofRuntimeError::OutputChunkNotReady);
        }
        self.chunk_awaiting_commit = true;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<StreamDescriptor, CommonProofRuntimeError> {
        if self.chunk_awaiting_commit
            || self.chunk_awaiting_readback
            || !self.current_chunk.is_empty()
            || self.pending_write.is_some()
            || self.observed_byte_length != self.declared_byte_length
            || self.terminal
        {
            return Err(CommonProofRuntimeError::OutputChunkNotReady);
        }
        self.terminal = true;
        self.stream_writer
            .take()
            .ok_or(CommonProofRuntimeError::OutputChunkNotReady)?
            .finish()
            .map_err(|_| CommonProofRuntimeError::OutputWriteReplayMismatch)
    }

    pub(crate) fn cancel(&mut self) {
        self.stream_writer = None;
        self.current_chunk = Zeroizing::new(Vec::new());
        self.chunk_awaiting_commit = false;
        self.chunk_awaiting_readback = false;
        self.pending_write = None;
        self.terminal = true;
    }

    fn expected_current_chunk_byte_length(
        &self,
    ) -> Result<usize, PollableCommonProofByteSinkError> {
        let remaining = self
            .declared_byte_length
            .checked_sub(
                self.next_chunk_index
                    .checked_mul(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                    .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?,
            )
            .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?;
        Ok(remaining.min(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH))
    }
}

impl CommonProofByteSink for PollableCommonProofByteSink {
    type Error = PollableCommonProofByteSinkError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        if self.terminal {
            return Err(PollableCommonProofByteSinkError::ByteLengthExceeded);
        }
        if self.chunk_awaiting_commit {
            return Err(PollableCommonProofByteSinkError::ChunkAwaitingCommit);
        }
        if self.chunk_awaiting_readback {
            return Err(PollableCommonProofByteSinkError::ChunkAwaitingReadback);
        }
        if bytes.is_empty() {
            return self
                .pending_write
                .is_none()
                .then_some(())
                .ok_or(PollableCommonProofByteSinkError::ReplayMismatch);
        }
        if self.pending_write.is_none()
            && self
                .observed_byte_length
                .checked_add(bytes.len())
                .filter(|length| *length <= self.declared_byte_length)
                .is_none()
        {
            return Err(PollableCommonProofByteSinkError::ByteLengthExceeded);
        }
        let digest = hash_framed_parts_512(OUTPUT_WRITE_HASH_DOMAIN, &[bytes]);
        let mut consumed_byte_length = match &self.pending_write {
            Some(pending) if pending.byte_length == bytes.len() && pending.digest == digest => {
                pending.consumed_byte_length
            }
            Some(_) => return Err(PollableCommonProofByteSinkError::ReplayMismatch),
            None => 0,
        };
        if self.pending_write.is_none() {
            self.pending_write = Some(PendingOutputWrite {
                byte_length: bytes.len(),
                digest,
                consumed_byte_length: 0,
            });
        }
        while consumed_byte_length < bytes.len() {
            let expected_chunk_byte_length = self.expected_current_chunk_byte_length()?;
            let available = expected_chunk_byte_length
                .checked_sub(self.current_chunk.len())
                .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?;
            if available == 0 {
                self.chunk_awaiting_commit = true;
                return Err(PollableCommonProofByteSinkError::ChunkReady);
            }
            let copied_byte_length = available.min(bytes.len() - consumed_byte_length);
            let next_observed_byte_length = self
                .observed_byte_length
                .checked_add(copied_byte_length)
                .filter(|length| *length <= self.declared_byte_length)
                .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?;
            self.current_chunk
                .try_reserve_exact(copied_byte_length)
                .map_err(|_| PollableCommonProofByteSinkError::AllocationLimitExceeded)?;
            self.current_chunk.extend_from_slice(
                bytes
                    .get(consumed_byte_length..consumed_byte_length + copied_byte_length)
                    .ok_or(PollableCommonProofByteSinkError::ByteLengthExceeded)?,
            );
            consumed_byte_length += copied_byte_length;
            self.observed_byte_length = next_observed_byte_length;
            self.pending_write
                .as_mut()
                .ok_or(PollableCommonProofByteSinkError::ReplayMismatch)?
                .consumed_byte_length = consumed_byte_length;
            if self.current_chunk.len() == expected_chunk_byte_length {
                self.chunk_awaiting_commit = true;
                return Err(PollableCommonProofByteSinkError::ChunkReady);
            }
        }
        self.pending_write = None;
        Ok(())
    }
}

/// One already-authenticated canonical input chunk. The caller owns the
/// canonical-stream verifier and supplies at most two adjacent chunks around
/// the decoder's current position.
pub(crate) struct ResidentCommonProofInputChunk<'chunk> {
    offset: usize,
    bytes: &'chunk [u8],
}

impl<'chunk> ResidentCommonProofInputChunk<'chunk> {
    pub(crate) const fn new(offset: usize, bytes: &'chunk [u8]) -> Self {
        Self { offset, bytes }
    }
}

/// Read-only window used by `BoundedProofDecoder` and `verify_common_proof`.
/// Missing bytes report truncation; they are never replaced with zeroes or a
/// caller-supplied success marker.
pub(crate) struct ResidentCommonProofByteSource<'chunk> {
    declared_byte_length: usize,
    chunks: Vec<ResidentCommonProofInputChunk<'chunk>>,
}

impl<'chunk> ResidentCommonProofByteSource<'chunk> {
    pub(crate) fn new(
        declared_byte_length: usize,
        chunks: Vec<ResidentCommonProofInputChunk<'chunk>>,
    ) -> Result<Self, CommonProofRuntimeError> {
        if declared_byte_length == 0
            || declared_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
            || chunks.is_empty()
            || chunks.len() > MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS
        {
            return Err(CommonProofRuntimeError::InvalidLimits);
        }
        let mut previous_end = None;
        for chunk in &chunks {
            let end = chunk
                .offset
                .checked_add(chunk.bytes.len())
                .filter(|end| *end <= declared_byte_length)
                .ok_or(CommonProofRuntimeError::InvalidLimits)?;
            if chunk.bytes.is_empty()
                || chunk.bytes.len() > MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
                || previous_end.is_some_and(|previous| chunk.offset < previous)
            {
                return Err(CommonProofRuntimeError::InvalidLimits);
            }
            previous_end = Some(end);
        }
        Ok(Self {
            declared_byte_length,
            chunks,
        })
    }
}

impl super::super::ProofByteSource for ResidentCommonProofByteSource<'_> {
    fn byte_length(&self) -> usize {
        self.declared_byte_length
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if end > self.declared_byte_length {
            return false;
        }
        let mut destination_offset = 0_usize;
        let mut source_offset = offset;
        while destination_offset < destination.len() {
            let Some(chunk) = self.chunks.iter().find(|chunk| {
                source_offset >= chunk.offset
                    && source_offset < chunk.offset.saturating_add(chunk.bytes.len())
            }) else {
                return false;
            };
            let within_chunk_offset = source_offset - chunk.offset;
            let copied_byte_length = (chunk.bytes.len() - within_chunk_offset)
                .min(destination.len() - destination_offset);
            destination[destination_offset..destination_offset + copied_byte_length]
                .copy_from_slice(
                    &chunk.bytes[within_chunk_offset..within_chunk_offset + copied_byte_length],
                );
            destination_offset += copied_byte_length;
            source_offset += copied_byte_length;
        }
        true
    }
}
