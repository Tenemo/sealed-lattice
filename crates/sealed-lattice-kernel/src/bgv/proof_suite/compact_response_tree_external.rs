//! Transactional external-memory lifecycle for compact response trees.
//!
//! One response owns one public-integrity postorder tree object. The object is
//! created and append-only until its root has been committed, then scanned once
//! for the verifier-derived minimal frontier and deleted. Driver state advances
//! only after the corresponding storage transaction commits successfully. The
//! retention coordinator applies that lifecycle to the complete response
//! registry, keeps trees through their exact last verifier-owned query, and
//! deletes every due tree before that verifier move can complete.

use core::mem::size_of;

use zeroize::Zeroizing;

use super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
use super::compact_proof_wire::CompactProofResponseWireGeometry;
use super::compact_response_merkle::{
    COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH, CompactResponseLeafValue,
    CompactResponseMerkleError, CompactResponseMerkleGeometry,
    CompactResponsePostorderFrontierScanner, CompactResponsePostorderMerkleWriter,
    CompactResponseQuerySchedule, expected_postorder_tree_byte_length,
};
use super::external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection, ProofExternalMemoryUsage,
};
use crate::foundation::Hash512;

const RESPONSE_TREE_EXTERNAL_MEMORY_STEP_COUNT: u32 = 2;
const RESPONSE_TREE_EXTERNAL_MEMORY_MAXIMUM_TRANSACTION_OPERATION_COUNT: u32 = 1;
const RESPONSE_TREE_EXTERNAL_MEMORY_FIXED_TRANSACTION_COUNT: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactResponseTreeExternalMemorySetupError {
    Merkle(CompactResponseMerkleError),
    ExternalMemory(ProofExternalMemoryError),
}

impl From<CompactResponseMerkleError> for CompactResponseTreeExternalMemorySetupError {
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::Merkle(error)
    }
}

impl From<ProofExternalMemoryError> for CompactResponseTreeExternalMemorySetupError {
    fn from(error: ProofExternalMemoryError) -> Self {
        Self::ExternalMemory(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactResponseTreeExternalMemoryExecutionError<StorageError> {
    Merkle(CompactResponseMerkleError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
    ExternalMemory(ProofExternalMemoryError),
    WrongPhase,
    AllocationLimitExceeded,
}

impl<StorageError> From<CompactResponseMerkleError>
    for CompactResponseTreeExternalMemoryExecutionError<StorageError>
{
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::Merkle(error)
    }
}

impl<StorageError> From<ProofExternalMemoryExecutorError<StorageError>>
    for CompactResponseTreeExternalMemoryExecutionError<StorageError>
{
    fn from(error: ProofExternalMemoryExecutorError<StorageError>) -> Self {
        Self::Storage(error)
    }
}

impl<StorageError> From<ProofExternalMemoryError>
    for CompactResponseTreeExternalMemoryExecutionError<StorageError>
{
    fn from(error: ProofExternalMemoryError) -> Self {
        Self::ExternalMemory(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseTreeExternalMemoryGeometry {
    tree_byte_length: u64,
    tree_chunk_count: u64,
    transaction_count: u64,
    driver_inline_byte_length: u64,
    executor_owned_heap_byte_length: u64,
}

impl CompactResponseTreeExternalMemoryGeometry {
    pub(crate) fn derive(
        geometry: &CompactResponseMerkleGeometry,
    ) -> Result<Self, CompactResponseTreeExternalMemorySetupError> {
        let plan = compact_response_tree_external_memory_plan(geometry)?;
        let tree_byte_length = expected_postorder_tree_byte_length(geometry)?;
        let tree_chunk_count = tree_byte_length.div_ceil(
            u64::try_from(COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH)
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
        );
        let transaction_count = tree_chunk_count
            .checked_mul(2)
            .and_then(|count| {
                count.checked_add(RESPONSE_TREE_EXTERNAL_MEMORY_FIXED_TRANSACTION_COUNT)
            })
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        let driver_inline_byte_length =
            u64::try_from(size_of::<CompactResponseTreeExternalMemoryDriver<'static>>())
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let executor_owned_heap_byte_length = plan.executor_resident_owned_payload_byte_length()?;
        Ok(Self {
            tree_byte_length,
            tree_chunk_count,
            transaction_count,
            driver_inline_byte_length,
            executor_owned_heap_byte_length,
        })
    }

    pub(crate) const fn tree_byte_length(self) -> u64 {
        self.tree_byte_length
    }

    pub(crate) const fn tree_chunk_count(self) -> u64 {
        self.tree_chunk_count
    }

    pub(crate) const fn transaction_count(self) -> u64 {
        self.transaction_count
    }

    pub(crate) const fn driver_inline_byte_length(self) -> u64 {
        self.driver_inline_byte_length
    }

    pub(crate) const fn executor_owned_heap_byte_length(self) -> u64 {
        self.executor_owned_heap_byte_length
    }
}

fn compact_response_tree_external_memory_plan(
    geometry: &CompactResponseMerkleGeometry,
) -> Result<ProofExternalMemoryPlan, CompactResponseTreeExternalMemorySetupError> {
    let tree_byte_length = expected_postorder_tree_byte_length(geometry)?;
    let maximum_chunk_byte_length = u32::try_from(COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    let tree_chunk_count = tree_byte_length.div_ceil(u64::from(maximum_chunk_byte_length));
    let maximum_transaction_count = tree_chunk_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(RESPONSE_TREE_EXTERNAL_MEMORY_FIXED_TRANSACTION_COUNT))
        .ok_or(CompactResponseMerkleError::CountOverflow)?;
    let object = ProofExternalMemoryObject::new(geometry.response_ordinal());
    ProofExternalMemoryPlan::new(
        RESPONSE_TREE_EXTERNAL_MEMORY_STEP_COUNT,
        maximum_chunk_byte_length,
        u64::from(maximum_chunk_byte_length),
        RESPONSE_TREE_EXTERNAL_MEMORY_MAXIMUM_TRANSACTION_OPERATION_COUNT,
        tree_byte_length,
        tree_byte_length,
        tree_byte_length,
        maximum_transaction_count,
        vec![ProofExternalMemoryObjectPlan::new(
            object,
            ProofExternalMemoryProtection::PublicIntegrity,
            tree_byte_length,
            0,
            0,
            1,
        )],
    )
    .map_err(Into::into)
}

enum CompactResponseTreeExternalMemoryPhase<'geometry> {
    AwaitingObjectCreation(CompactResponsePostorderMerkleWriter<'geometry>),
    Writing(CompactResponsePostorderMerkleWriter<'geometry>),
    ReadyToSeal {
        root: [u8; Hash512::BYTE_LENGTH],
    },
    SealedBeforeStepCompletion {
        root: [u8; Hash512::BYTE_LENGTH],
    },
    Sealed {
        root: [u8; Hash512::BYTE_LENGTH],
    },
    Scanning {
        root: [u8; Hash512::BYTE_LENGTH],
        scanner: CompactResponsePostorderFrontierScanner,
    },
    ReadyToDelete {
        root: [u8; Hash512::BYTE_LENGTH],
        frontier: Vec<[u8; Hash512::BYTE_LENGTH]>,
    },
}

pub(crate) struct CompactResponseTreeExternalMemoryDriver<'geometry> {
    geometry: &'geometry CompactResponseMerkleGeometry,
    object: ProofExternalMemoryObject,
    executor: Option<ProofExternalMemoryExecutor>,
    phase: Option<CompactResponseTreeExternalMemoryPhase<'geometry>>,
}

pub(crate) struct CompactResponseTreeExternalMemoryOutput {
    root: [u8; Hash512::BYTE_LENGTH],
    frontier: Vec<[u8; Hash512::BYTE_LENGTH]>,
    usage: ProofExternalMemoryUsage,
}

impl CompactResponseTreeExternalMemoryOutput {
    pub(crate) const fn root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.root
    }

    pub(crate) fn frontier(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.frontier
    }

    pub(crate) const fn usage(&self) -> ProofExternalMemoryUsage {
        self.usage
    }

    pub(crate) fn into_frontier(self) -> Vec<[u8; Hash512::BYTE_LENGTH]> {
        self.frontier
    }
}

impl<'geometry> CompactResponseTreeExternalMemoryDriver<'geometry> {
    pub(crate) fn new(
        geometry: &'geometry CompactResponseMerkleGeometry,
    ) -> Result<Self, CompactResponseTreeExternalMemorySetupError> {
        let plan = compact_response_tree_external_memory_plan(geometry)?;
        let writer = CompactResponsePostorderMerkleWriter::new(geometry)?;
        Ok(Self {
            geometry,
            object: ProofExternalMemoryObject::new(geometry.response_ordinal()),
            executor: Some(ProofExternalMemoryExecutor::new(plan)),
            phase: Some(CompactResponseTreeExternalMemoryPhase::AwaitingObjectCreation(writer)),
        })
    }

    pub(crate) fn begin_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactResponseTreeExternalMemoryExecutionError<Storage::Error>> {
        if !matches!(
            self.phase,
            Some(CompactResponseTreeExternalMemoryPhase::AwaitingObjectCreation(_))
        ) {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        }
        let object = self.object;
        self.executor_mut()?.begin_object(storage, object)?;
        let Some(CompactResponseTreeExternalMemoryPhase::AwaitingObjectCreation(writer)) =
            self.phase.take()
        else {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        };
        self.phase = Some(CompactResponseTreeExternalMemoryPhase::Writing(writer));
        Ok(())
    }

    pub(crate) fn absorb_leaf(
        &mut self,
        value: CompactResponseLeafValue<'_>,
        leaf_salt: &[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
    ) -> Result<(), CompactResponseMerkleError> {
        let Some(CompactResponseTreeExternalMemoryPhase::Writing(writer)) = &mut self.phase else {
            return Err(CompactResponseMerkleError::WriterIncomplete);
        };
        writer.absorb_leaf(value, leaf_salt)
    }

    pub(crate) fn pending_tree_chunk(&self) -> Option<&[u8]> {
        match &self.phase {
            Some(CompactResponseTreeExternalMemoryPhase::Writing(writer)) => writer.output_chunk(),
            _ => None,
        }
    }

    pub(crate) fn append_pending_tree_chunk<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactResponseTreeExternalMemoryExecutionError<Storage::Error>> {
        let pending_chunk = self
            .pending_tree_chunk()
            .ok_or(CompactResponseMerkleError::OutputChunkUnavailable)?;
        let mut owned_chunk = Zeroizing::new(Vec::new());
        owned_chunk
            .try_reserve_exact(pending_chunk.len())
            .map_err(|_| {
                CompactResponseTreeExternalMemoryExecutionError::AllocationLimitExceeded
            })?;
        if owned_chunk.capacity() != pending_chunk.len() {
            return Err(CompactResponseTreeExternalMemoryExecutionError::AllocationLimitExceeded);
        }
        owned_chunk.extend_from_slice(pending_chunk);
        let object = self.object;
        self.executor_mut()?
            .append_owned_object_bytes(storage, object, &mut owned_chunk)?;
        let Some(CompactResponseTreeExternalMemoryPhase::Writing(writer)) = &mut self.phase else {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        };
        writer.acknowledge_output_chunk()?;
        Ok(())
    }

    pub(crate) fn seal_tree<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        [u8; Hash512::BYTE_LENGTH],
        CompactResponseTreeExternalMemoryExecutionError<Storage::Error>,
    > {
        if matches!(
            self.phase,
            Some(CompactResponseTreeExternalMemoryPhase::Writing(_))
        ) {
            let writer_is_complete = matches!(
                &self.phase,
                Some(CompactResponseTreeExternalMemoryPhase::Writing(writer)) if writer.is_complete()
            );
            if !writer_is_complete {
                return Err(CompactResponseMerkleError::WriterIncomplete.into());
            }
            let Some(CompactResponseTreeExternalMemoryPhase::Writing(writer)) = self.phase.take()
            else {
                return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
            };
            let root = writer.finish()?;
            self.phase = Some(CompactResponseTreeExternalMemoryPhase::ReadyToSeal { root });
        }

        if let Some(CompactResponseTreeExternalMemoryPhase::ReadyToSeal { root }) = self.phase {
            let object = self.object;
            self.executor_mut()?.seal_object(storage, object)?;
            self.phase =
                Some(CompactResponseTreeExternalMemoryPhase::SealedBeforeStepCompletion { root });
        }

        if let Some(CompactResponseTreeExternalMemoryPhase::SealedBeforeStepCompletion { root }) =
            self.phase
        {
            self.executor_mut()?.complete_step(storage)?;
            self.phase = Some(CompactResponseTreeExternalMemoryPhase::Sealed { root });
            return Ok(root);
        }

        Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)
    }

    pub(crate) fn begin_frontier_scan(
        &mut self,
        query_schedule: &CompactResponseQuerySchedule,
    ) -> Result<(), CompactResponseMerkleError> {
        let root = match self.phase {
            Some(CompactResponseTreeExternalMemoryPhase::Sealed { root }) => root,
            _ => return Err(CompactResponseMerkleError::ScannerIncomplete),
        };
        let scanner =
            CompactResponsePostorderFrontierScanner::new(self.geometry, query_schedule.as_slice())?;
        self.phase = Some(CompactResponseTreeExternalMemoryPhase::Scanning { root, scanner });
        Ok(())
    }

    pub(crate) fn read_next_tree_chunk<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<bool, CompactResponseTreeExternalMemoryExecutionError<Storage::Error>> {
        let remaining_byte_length = match &self.phase {
            Some(CompactResponseTreeExternalMemoryPhase::Scanning { scanner, .. }) => {
                scanner.remaining_tree_byte_length()?
            }
            _ => return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase),
        };
        if remaining_byte_length == 0 {
            return Err(CompactResponseMerkleError::ScannerIncomplete.into());
        }
        let chunk_byte_length = usize::try_from(
            remaining_byte_length.min(
                u64::try_from(COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
            ),
        )
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let mut tree_chunk = Vec::new();
        tree_chunk
            .try_reserve_exact(chunk_byte_length)
            .map_err(|_| {
                CompactResponseTreeExternalMemoryExecutionError::AllocationLimitExceeded
            })?;
        if tree_chunk.capacity() != chunk_byte_length {
            return Err(CompactResponseTreeExternalMemoryExecutionError::AllocationLimitExceeded);
        }
        tree_chunk.resize(chunk_byte_length, 0);
        let tree_byte_length = expected_postorder_tree_byte_length(self.geometry)?;
        let read_offset = tree_byte_length
            .checked_sub(remaining_byte_length)
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        let object = self.object;
        self.executor_mut()?
            .read_object_bytes(storage, object, read_offset, &mut tree_chunk)?;
        let Some(CompactResponseTreeExternalMemoryPhase::Scanning { scanner, .. }) =
            &mut self.phase
        else {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        };
        scanner.absorb_tree_chunk(&tree_chunk)?;
        Ok(scanner.is_complete())
    }

    pub(crate) fn finish_frontier_scan<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CompactResponseTreeExternalMemoryOutput,
        CompactResponseTreeExternalMemoryExecutionError<Storage::Error>,
    > {
        if matches!(
            self.phase,
            Some(CompactResponseTreeExternalMemoryPhase::Scanning { .. })
        ) {
            let scanner_is_complete = matches!(
                &self.phase,
                Some(CompactResponseTreeExternalMemoryPhase::Scanning { scanner, .. })
                    if scanner.is_complete()
            );
            if !scanner_is_complete {
                return Err(CompactResponseMerkleError::ScannerIncomplete.into());
            }
            let Some(CompactResponseTreeExternalMemoryPhase::Scanning { root, scanner }) =
                self.phase.take()
            else {
                return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
            };
            let frontier = scanner.finish()?;
            self.phase =
                Some(CompactResponseTreeExternalMemoryPhase::ReadyToDelete { root, frontier });
        }

        if !matches!(
            self.phase,
            Some(CompactResponseTreeExternalMemoryPhase::ReadyToDelete { .. })
        ) {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        }
        self.executor_mut()?.complete_step(storage)?;
        let Some(CompactResponseTreeExternalMemoryPhase::ReadyToDelete { root, frontier }) =
            self.phase.take()
        else {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        };
        let usage = self
            .executor
            .take()
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
            .finish()?;
        Ok(CompactResponseTreeExternalMemoryOutput {
            root,
            frontier,
            usage,
        })
    }

    pub(crate) fn cancel<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactResponseTreeExternalMemoryExecutionError<Storage::Error>> {
        if let Some(executor) = &mut self.executor {
            executor.cancel(storage)?;
        }
        self.phase = None;
        Ok(())
    }

    fn executor_mut<StorageError>(
        &mut self,
    ) -> Result<
        &mut ProofExternalMemoryExecutor,
        CompactResponseTreeExternalMemoryExecutionError<StorageError>,
    > {
        self.executor
            .as_mut()
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)
    }
}

struct CompactResponseTreeLastUseScan {
    verifier_move_ordinal: u32,
    due_response_indices: Vec<usize>,
    next_due_response_offset: usize,
    current_scan_started: bool,
    current_scan_complete: bool,
    current_query_leaf_ordinals: Vec<u64>,
}

pub(crate) struct CompactResponseTreeLastUseOutput {
    response_ordinal: u32,
    query_leaf_ordinals: Vec<u64>,
    output: CompactResponseTreeExternalMemoryOutput,
}

impl CompactResponseTreeLastUseOutput {
    pub(crate) const fn response_ordinal(&self) -> u32 {
        self.response_ordinal
    }

    pub(crate) const fn root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.output.root()
    }

    pub(crate) fn query_leaf_ordinals(&self) -> &[u64] {
        &self.query_leaf_ordinals
    }

    pub(crate) fn frontier(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        self.output.frontier()
    }

    pub(crate) const fn usage(&self) -> ProofExternalMemoryUsage {
        self.output.usage()
    }

    pub(crate) fn into_frontier(self) -> Vec<[u8; Hash512::BYTE_LENGTH]> {
        self.output.into_frontier()
    }
}

pub(crate) enum CompactResponseTreeRetentionPoll {
    StorageTransactionCompleted,
    OpeningReady(CompactResponseTreeLastUseOutput),
    VerifierMoveComplete,
}

/// Coordinates all retained response-tree objects in verifier chronology.
///
/// Each response is written and sealed before its same-ordinal verifier move.
/// Trees remain live until the exact last move selected by their component
/// registry. At that move the coordinator derives the opening schedule from
/// the complete live transcript prefix, scans one bounded storage chunk per
/// poll, returns the canonical frontier, and deletes the object before the move
/// can complete.
pub(crate) struct CompactResponseTreeRetentionDriver<'geometry> {
    merkle_geometries: &'geometry [CompactResponseMerkleGeometry],
    wire_geometries: &'geometry [CompactProofResponseWireGeometry],
    response_drivers: Vec<Option<CompactResponseTreeExternalMemoryDriver<'geometry>>>,
    next_response_index: usize,
    active_response_index: Option<usize>,
    next_verifier_move_index: usize,
    last_use_scan: Option<CompactResponseTreeLastUseScan>,
    current_stored_byte_length: u64,
    aggregate_usage: ProofExternalMemoryUsage,
    terminal: bool,
}

impl<'geometry> CompactResponseTreeRetentionDriver<'geometry> {
    pub(crate) fn new(
        merkle_geometries: &'geometry [CompactResponseMerkleGeometry],
        wire_geometries: &'geometry [CompactProofResponseWireGeometry],
    ) -> Result<Self, CompactResponseTreeExternalMemorySetupError> {
        CompactResponseQuerySchedule::validate_registry(merkle_geometries, wire_geometries)?;
        let mut response_drivers = Vec::new();
        response_drivers
            .try_reserve_exact(merkle_geometries.len())
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        response_drivers.resize_with(merkle_geometries.len(), || None);
        Ok(Self {
            merkle_geometries,
            wire_geometries,
            response_drivers,
            next_response_index: 0,
            active_response_index: None,
            next_verifier_move_index: 0,
            last_use_scan: None,
            current_stored_byte_length: 0,
            aggregate_usage: ProofExternalMemoryUsage::default(),
            terminal: false,
        })
    }

    pub(crate) fn begin_next_response<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactResponseTreeExternalMemoryExecutionError<Storage::Error>> {
        if self.terminal
            || self.active_response_index.is_some()
            || self.last_use_scan.is_some()
            || self.next_response_index >= self.merkle_geometries.len()
            || self.next_response_index != self.next_verifier_move_index
        {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        }
        let response_index = self.next_response_index;
        let tree_byte_length =
            expected_postorder_tree_byte_length(&self.merkle_geometries[response_index])?;
        let next_stored_byte_length = self
            .current_stored_byte_length
            .checked_add(tree_byte_length)
            .ok_or(
                CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?;
        if self.response_drivers[response_index].is_none() {
            self.response_drivers[response_index] = Some(
                CompactResponseTreeExternalMemoryDriver::new(
                    &self.merkle_geometries[response_index],
                )
                .map_err(compact_response_tree_setup_as_execution_error)?,
            );
        }
        self.response_drivers[response_index]
            .as_mut()
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
            .begin_object(storage)?;
        self.current_stored_byte_length = next_stored_byte_length;
        self.aggregate_usage.peak_stored_byte_length = self
            .aggregate_usage
            .peak_stored_byte_length
            .max(next_stored_byte_length);
        self.active_response_index = Some(response_index);
        Ok(())
    }

    pub(crate) fn absorb_next_response_leaf(
        &mut self,
        value: CompactResponseLeafValue<'_>,
        leaf_salt: &[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
    ) -> Result<(), CompactResponseMerkleError> {
        let response_index = self
            .active_response_index
            .ok_or(CompactResponseMerkleError::WriterIncomplete)?;
        self.response_drivers[response_index]
            .as_mut()
            .ok_or(CompactResponseMerkleError::WriterIncomplete)?
            .absorb_leaf(value, leaf_salt)
    }

    pub(crate) fn pending_tree_chunk(&self) -> Option<&[u8]> {
        let response_index = self.active_response_index?;
        self.response_drivers[response_index]
            .as_ref()?
            .pending_tree_chunk()
    }

    pub(crate) fn append_pending_tree_chunk<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactResponseTreeExternalMemoryExecutionError<Storage::Error>> {
        let response_index = self
            .active_response_index
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?;
        self.response_drivers[response_index]
            .as_mut()
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
            .append_pending_tree_chunk(storage)
    }

    pub(crate) fn seal_next_response<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        [u8; Hash512::BYTE_LENGTH],
        CompactResponseTreeExternalMemoryExecutionError<Storage::Error>,
    > {
        let response_index = self
            .active_response_index
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?;
        let root = self.response_drivers[response_index]
            .as_mut()
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
            .seal_tree(storage)?;
        self.next_response_index = self.next_response_index.checked_add(1).ok_or(
            CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ),
        )?;
        self.active_response_index = None;
        Ok(root)
    }

    pub(crate) fn advance_verifier_move<Storage: ProofExternalMemory>(
        &mut self,
        verifier_messages: &[super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage],
        storage: &mut Storage,
    ) -> Result<
        CompactResponseTreeRetentionPoll,
        CompactResponseTreeExternalMemoryExecutionError<Storage::Error>,
    > {
        let expected_message_count = self.next_verifier_move_index.checked_add(1).ok_or(
            CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ),
        )?;
        if self.terminal
            || self.active_response_index.is_some()
            || self.next_response_index != expected_message_count
            || verifier_messages.len() != expected_message_count
        {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        }
        let verifier_move_ordinal = u32::try_from(self.next_verifier_move_index)
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        if self.last_use_scan.is_none() {
            let mut due_response_indices = Vec::new();
            due_response_indices
                .try_reserve_exact(self.next_response_index)
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
            for response_index in 0..self.next_response_index {
                let Some(_) = self.response_drivers[response_index] else {
                    continue;
                };
                let last_query_verifier_move_ordinal =
                    self.merkle_geometries[response_index].last_query_verifier_move_ordinal();
                if last_query_verifier_move_ordinal < verifier_move_ordinal {
                    return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
                }
                if last_query_verifier_move_ordinal == verifier_move_ordinal {
                    due_response_indices.push(response_index);
                }
            }
            self.last_use_scan = Some(CompactResponseTreeLastUseScan {
                verifier_move_ordinal,
                due_response_indices,
                next_due_response_offset: 0,
                current_scan_started: false,
                current_scan_complete: false,
                current_query_leaf_ordinals: Vec::new(),
            });
        }
        if self
            .last_use_scan
            .as_ref()
            .is_none_or(|scan| scan.verifier_move_ordinal != verifier_move_ordinal)
        {
            return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
        }
        let scan_is_complete = self
            .last_use_scan
            .as_ref()
            .is_some_and(|scan| scan.next_due_response_offset == scan.due_response_indices.len());
        if scan_is_complete {
            self.last_use_scan = None;
            self.next_verifier_move_index = expected_message_count;
            if self.next_verifier_move_index == self.merkle_geometries.len() {
                if self.next_response_index != self.merkle_geometries.len()
                    || self.response_drivers.iter().any(Option::is_some)
                    || self.current_stored_byte_length != 0
                {
                    return Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase);
                }
                self.terminal = true;
            }
            return Ok(CompactResponseTreeRetentionPoll::VerifierMoveComplete);
        }

        let response_index = {
            let scan = self
                .last_use_scan
                .as_ref()
                .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?;
            *scan
                .due_response_indices
                .get(scan.next_due_response_offset)
                .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
        };
        let current_scan_started = self
            .last_use_scan
            .as_ref()
            .is_some_and(|scan| scan.current_scan_started);
        if !current_scan_started {
            let query_schedule = CompactResponseQuerySchedule::derive_at_last_query_boundary(
                &self.merkle_geometries[response_index],
                self.wire_geometries,
                verifier_messages,
            )?;
            self.response_drivers[response_index]
                .as_mut()
                .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
                .begin_frontier_scan(&query_schedule)?;
            let scan = self
                .last_use_scan
                .as_mut()
                .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?;
            scan.current_scan_started = true;
            scan.current_query_leaf_ordinals = query_schedule.as_slice().to_vec();
        }
        let current_scan_complete = self
            .last_use_scan
            .as_ref()
            .is_some_and(|scan| scan.current_scan_complete);
        if !current_scan_complete {
            let scan_complete = self.response_drivers[response_index]
                .as_mut()
                .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
                .read_next_tree_chunk(storage)?;
            self.last_use_scan
                .as_mut()
                .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
                .current_scan_complete = scan_complete;
            return Ok(CompactResponseTreeRetentionPoll::StorageTransactionCompleted);
        }

        let output = self.response_drivers[response_index]
            .as_mut()
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?
            .finish_frontier_scan(storage)?;
        self.response_drivers[response_index] = None;
        self.record_completed_tree_usage(response_index, output.usage())?;
        let scan = self
            .last_use_scan
            .as_mut()
            .ok_or(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)?;
        let query_leaf_ordinals = core::mem::take(&mut scan.current_query_leaf_ordinals);
        scan.next_due_response_offset = scan.next_due_response_offset.checked_add(1).ok_or(
            CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ),
        )?;
        scan.current_scan_started = false;
        scan.current_scan_complete = false;
        Ok(CompactResponseTreeRetentionPoll::OpeningReady(
            CompactResponseTreeLastUseOutput {
                response_ordinal: u32::try_from(response_index)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
                query_leaf_ordinals,
                output,
            },
        ))
    }

    pub(crate) fn finish(self) -> Result<ProofExternalMemoryUsage, ProofExternalMemoryError> {
        if !self.terminal
            || self.active_response_index.is_some()
            || self.last_use_scan.is_some()
            || self.next_response_index != self.merkle_geometries.len()
            || self.next_verifier_move_index != self.merkle_geometries.len()
            || self.response_drivers.iter().any(Option::is_some)
            || self.current_stored_byte_length != 0
        {
            return Err(ProofExternalMemoryError::Incomplete);
        }
        Ok(self.aggregate_usage)
    }

    pub(crate) fn cancel<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactResponseTreeExternalMemoryExecutionError<Storage::Error>> {
        for response_index in 0..self.response_drivers.len() {
            let Some(driver) = self.response_drivers[response_index].as_mut() else {
                continue;
            };
            driver.cancel(storage)?;
            self.response_drivers[response_index] = None;
        }
        self.active_response_index = None;
        self.last_use_scan = None;
        self.current_stored_byte_length = 0;
        self.terminal = true;
        Ok(())
    }

    fn record_completed_tree_usage<StorageError>(
        &mut self,
        response_index: usize,
        usage: ProofExternalMemoryUsage,
    ) -> Result<(), CompactResponseTreeExternalMemoryExecutionError<StorageError>> {
        let tree_byte_length =
            expected_postorder_tree_byte_length(&self.merkle_geometries[response_index])?;
        self.current_stored_byte_length = self
            .current_stored_byte_length
            .checked_sub(tree_byte_length)
            .ok_or(
                CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                    ProofExternalMemoryError::InvalidLifecycle,
                ),
            )?;
        self.aggregate_usage.total_written_byte_length = self
            .aggregate_usage
            .total_written_byte_length
            .checked_add(usage.total_written_byte_length())
            .ok_or(
                CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?;
        self.aggregate_usage.total_read_byte_length = self
            .aggregate_usage
            .total_read_byte_length
            .checked_add(usage.total_read_byte_length())
            .ok_or(
                CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?;
        self.aggregate_usage.transaction_count = self
            .aggregate_usage
            .transaction_count
            .checked_add(usage.transaction_count())
            .ok_or(
                CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?;
        self.aggregate_usage.deleted_object_count = self
            .aggregate_usage
            .deleted_object_count
            .checked_add(usage.deleted_object_count())
            .ok_or(
                CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?;
        Ok(())
    }
}

fn compact_response_tree_setup_as_execution_error<StorageError>(
    error: CompactResponseTreeExternalMemorySetupError,
) -> CompactResponseTreeExternalMemoryExecutionError<StorageError> {
    match error {
        CompactResponseTreeExternalMemorySetupError::Merkle(error) => {
            CompactResponseTreeExternalMemoryExecutionError::Merkle(error)
        }
        CompactResponseTreeExternalMemorySetupError::ExternalMemory(error) => {
            CompactResponseTreeExternalMemoryExecutionError::ExternalMemory(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_proof_wire::{
        COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireGeometry,
        CompactProofWireGeometry, CompactPublicInputBindings, CompactPublicInputWireGeometry,
        decode_compact_public_input, encode_compact_public_input,
    };
    use crate::bgv::proof_suite::compact_transcript::CompactProverTranscript;
    use crate::bgv::proof_suite::external_memory::{
        ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionOperation,
        ProofExternalMemoryTransactionRecorder, ProofExternalMemoryTransactionReplay,
        ProofExternalMemoryTransactionRequest, tests::TestStorage,
    };
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
        FixedUniformDistinctQueryGeometry, FixedUniformVerifierMessageGeometry,
        derive_fixed_uniform_verifier_message,
    };
    use crate::bgv::proof_suite::{ProofBaseFieldElement, ProofChallengeExtensionElement};

    enum OwnedLeafValue {
        BaseField(Vec<ProofBaseFieldElement>),
        ExtensionField(Vec<ProofChallengeExtensionElement>),
        Padding,
    }

    impl OwnedLeafValue {
        fn borrowed(&self) -> CompactResponseLeafValue<'_> {
            match self {
                Self::BaseField(values) => CompactResponseLeafValue::BaseField(values),
                Self::ExtensionField(values) => CompactResponseLeafValue::ExtensionField(values),
                Self::Padding => CompactResponseLeafValue::Padding,
            }
        }
    }

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("small base-field value")
    }

    fn extension(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_canonical_coordinates([
            value,
            value + 1,
            value + 2,
            value + 3,
            value + 4,
        ])
        .expect("small extension-field value")
    }

    fn geometry() -> CompactResponseMerkleGeometry {
        use super::super::compact_response_merkle::{
            CompactResponseComponentGeometry, CompactResponseLeafValueKind,
            CompactResponseQuerySelection,
        };

        CompactResponseMerkleGeometry::new(
            0,
            vec![
                CompactResponseComponentGeometry::new(
                    0,
                    2,
                    1,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: 0,
                        distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::BaseField,
                    2,
                ),
                CompactResponseComponentGeometry::new(
                    2,
                    1,
                    1,
                    CompactResponseQuerySelection::EveryLeaf,
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                ),
                CompactResponseComponentGeometry::new(
                    3,
                    1,
                    0,
                    CompactResponseQuerySelection::Unqueried,
                    CompactResponseLeafValueKind::Padding,
                    0,
                ),
            ],
        )
        .expect("small transactional response geometry")
    }

    fn values() -> Vec<OwnedLeafValue> {
        vec![
            OwnedLeafValue::BaseField(vec![base(11), base(13)]),
            OwnedLeafValue::BaseField(vec![base(17), base(19)]),
            OwnedLeafValue::ExtensionField(vec![extension(23)]),
            OwnedLeafValue::Padding,
        ]
    }

    fn wire_and_message() -> (
        CompactProofResponseWireGeometry,
        super::super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage,
    ) {
        let message_geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(2, 1)],
        )
        .expect("one proper query group");
        let message = derive_fixed_uniform_verifier_message(
            Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]),
            0,
            &message_geometry,
        )
        .expect("deterministic verifier message");
        let wire_geometry = CompactProofResponseWireGeometry::new(0, 2, 1, 2, 2, message_geometry)
            .expect("matching response wire geometry");
        (wire_geometry, message)
    }

    fn retained_response_geometries() -> (
        Vec<CompactResponseMerkleGeometry>,
        Vec<CompactProofResponseWireGeometry>,
    ) {
        use super::super::compact_response_merkle::{
            CompactResponseComponentGeometry, CompactResponseLeafValueKind,
            CompactResponseQuerySelection,
        };

        let wire_geometries = vec![
            CompactProofResponseWireGeometry::new(
                0,
                1,
                0,
                1,
                1,
                FixedUniformVerifierMessageGeometry::new(1, 0, 0, Vec::new())
                    .expect("first retained-tree message geometry"),
            )
            .expect("first retained-tree wire geometry"),
            CompactProofResponseWireGeometry::new(
                1,
                1,
                0,
                1,
                0,
                FixedUniformVerifierMessageGeometry::new(1, 0, 0, Vec::new())
                    .expect("second retained-tree message geometry"),
            )
            .expect("second retained-tree wire geometry"),
            CompactProofResponseWireGeometry::new(
                2,
                0,
                1,
                1,
                0,
                FixedUniformVerifierMessageGeometry::new(
                    1,
                    0,
                    0,
                    vec![FixedUniformDistinctQueryGeometry::new(2, 1)],
                )
                .expect("third retained-tree message geometry"),
            )
            .expect("third retained-tree wire geometry"),
        ];
        let merkle_geometries = vec![
            CompactResponseMerkleGeometry::new(
                0,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    2,
                    1,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: 2,
                        distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::BaseField,
                    1,
                )],
            )
            .expect("first retained-tree Merkle geometry"),
            CompactResponseMerkleGeometry::new(
                1,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    1,
                    1,
                    CompactResponseQuerySelection::EveryLeaf,
                    CompactResponseLeafValueKind::BaseField,
                    1,
                )],
            )
            .expect("second retained-tree Merkle geometry"),
            CompactResponseMerkleGeometry::new(
                2,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    1,
                    1,
                    CompactResponseQuerySelection::EveryLeaf,
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                )],
            )
            .expect("third retained-tree Merkle geometry"),
        ];
        (merkle_geometries, wire_geometries)
    }

    fn commit_retained_response(
        driver: &mut CompactResponseTreeRetentionDriver<'_>,
        storage: &mut TestStorage,
        values: &[OwnedLeafValue],
        salts: &[[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]],
    ) -> [u8; Hash512::BYTE_LENGTH] {
        assert_eq!(values.len(), salts.len());
        driver
            .begin_next_response(storage)
            .expect("the retained response object begins");
        for (value, salt) in values.iter().zip(salts) {
            driver
                .absorb_next_response_leaf(value.borrowed(), salt)
                .expect("the retained response accepts one leaf");
            while driver.pending_tree_chunk().is_some() {
                driver
                    .append_pending_tree_chunk(storage)
                    .expect("the retained response chunk commits");
            }
        }
        driver
            .seal_next_response(storage)
            .expect("the retained response tree seals")
    }

    fn complete_retained_verifier_move(
        driver: &mut CompactResponseTreeRetentionDriver<'_>,
        verifier_messages: &[super::super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage],
        storage: &mut TestStorage,
    ) -> Vec<CompactResponseTreeLastUseOutput> {
        let mut outputs = Vec::new();
        loop {
            match driver
                .advance_verifier_move(verifier_messages, storage)
                .expect("the retained verifier move advances")
            {
                CompactResponseTreeRetentionPoll::StorageTransactionCompleted => {}
                CompactResponseTreeRetentionPoll::OpeningReady(output) => outputs.push(output),
                CompactResponseTreeRetentionPoll::VerifierMoveComplete => return outputs,
            }
        }
    }

    fn execute_recorded_transaction(
        request: &ProofExternalMemoryTransactionRequest,
        storage: &mut TestStorage,
    ) -> Vec<Zeroizing<Vec<u8>>> {
        storage
            .begin_transaction(u64::MAX, u32::MAX)
            .expect("the test backend transaction begins");
        let mut read_results = Vec::new();
        for operation in request.operations() {
            match operation {
                ProofExternalMemoryTransactionOperation::Create {
                    object,
                    protection,
                    exact_byte_length,
                } => storage
                    .create_object(*object, *protection, *exact_byte_length)
                    .expect("the test backend object is created"),
                ProofExternalMemoryTransactionOperation::Append {
                    object,
                    expected_offset,
                    bytes,
                } => storage
                    .append_object_bytes(*object, *expected_offset, bytes)
                    .expect("the test backend tree bytes append"),
                ProofExternalMemoryTransactionOperation::Seal { object } => storage
                    .seal_object(*object)
                    .expect("the test backend tree seals"),
                ProofExternalMemoryTransactionOperation::Read {
                    object,
                    offset,
                    byte_length,
                } => {
                    let mut result = Zeroizing::new(vec![
                        0_u8;
                        usize::try_from(*byte_length).expect(
                            "the test read length fits usize"
                        )
                    ]);
                    storage
                        .read_object_bytes(*object, *offset, &mut result)
                        .expect("the test backend tree bytes read");
                    read_results.push(result);
                }
                ProofExternalMemoryTransactionOperation::Delete { object } => storage
                    .delete_object(*object)
                    .expect("the test backend tree deletes"),
            }
        }
        storage
            .commit_transaction()
            .expect("the test backend transaction commits");
        read_results
    }

    macro_rules! record_and_replay_storage_call {
        ($driver:expr, $recorder:expr, $backend:expr, $method:ident) => {{
            assert!(matches!(
                $driver.$method($recorder),
                Err(CompactResponseTreeExternalMemoryExecutionError::Storage(
                    ProofExternalMemoryExecutorError::StorageCommit(
                        ProofExternalMemoryTransactionAdapterError::Yielded
                    )
                ))
            ));
            let request = $recorder
                .take_yielded_request()
                .expect("the transaction driver yielded one request");
            let read_results = execute_recorded_transaction(&request, $backend);
            let mut replay = ProofExternalMemoryTransactionReplay::new(request, read_results)
                .expect("the recorded transaction response matches its request");
            let result = $driver
                .$method(&mut replay)
                .expect("the exact tree transaction replays");
            assert!(replay.transaction_is_complete());
            result
        }};
    }

    #[test]
    fn transaction_driver_writes_scans_and_deletes_one_canonical_tree() {
        let geometry = geometry();
        let (wire_geometry, verifier_message) = wire_and_message();
        let query_schedule =
            CompactResponseQuerySchedule::derive(&geometry, &[wire_geometry], &[verifier_message])
                .expect("verifier-owned global query schedule");
        assert_eq!(query_schedule.as_slice().len(), 2);
        assert_eq!(query_schedule.as_slice()[1], 2);
        assert_eq!(query_schedule.owned_heap_byte_length(), Ok(16));

        let memory_geometry = CompactResponseTreeExternalMemoryGeometry::derive(&geometry).unwrap();
        assert_eq!(memory_geometry.tree_byte_length(), 448);
        assert_eq!(memory_geometry.tree_chunk_count(), 1);
        assert_eq!(memory_geometry.transaction_count(), 5);
        assert!(memory_geometry.driver_inline_byte_length() > 0);
        assert!(memory_geometry.executor_owned_heap_byte_length() > 0);

        let salts = (0_u8..4)
            .map(|ordinal| [ordinal + 1; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH])
            .collect::<Vec<_>>();
        let mut storage = TestStorage::default();
        let mut driver = CompactResponseTreeExternalMemoryDriver::new(&geometry).unwrap();
        driver.begin_object(&mut storage).unwrap();
        for (value, salt) in values().iter().zip(&salts) {
            driver.absorb_leaf(value.borrowed(), salt).unwrap();
            if driver.pending_tree_chunk().is_some() {
                driver.append_pending_tree_chunk(&mut storage).unwrap();
            }
        }
        let root = driver.seal_tree(&mut storage).unwrap();
        driver.begin_frontier_scan(&query_schedule).unwrap();
        assert!(driver.read_next_tree_chunk(&mut storage).unwrap());
        let output = driver.finish_frontier_scan(&mut storage).unwrap();
        assert_eq!(output.root(), root);
        assert!(!output.frontier().is_empty());
        assert_eq!(output.usage().total_written_byte_length(), 448);
        assert_eq!(output.usage().total_read_byte_length(), 448);
        assert_eq!(output.usage().peak_stored_byte_length(), 448);
        assert_eq!(output.usage().transaction_count(), 5);
        assert_eq!(output.usage().deleted_object_count(), 1);
        assert!(!output.into_frontier().is_empty());
    }

    #[test]
    fn transaction_driver_replays_every_storage_boundary_without_advancing_early() {
        let geometry = geometry();
        let (wire_geometry, verifier_message) = wire_and_message();
        let query_schedule =
            CompactResponseQuerySchedule::derive(&geometry, &[wire_geometry], &[verifier_message])
                .expect("verifier-owned global query schedule");
        let salts = (0_u8..4)
            .map(|ordinal| [ordinal + 1; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH])
            .collect::<Vec<_>>();
        let mut backend_storage = TestStorage::default();
        let mut recorder = ProofExternalMemoryTransactionRecorder::new();
        let mut driver = CompactResponseTreeExternalMemoryDriver::new(&geometry).unwrap();

        record_and_replay_storage_call!(driver, &mut recorder, &mut backend_storage, begin_object);
        for (value, salt) in values().iter().zip(&salts) {
            driver.absorb_leaf(value.borrowed(), salt).unwrap();
            if driver.pending_tree_chunk().is_some() {
                record_and_replay_storage_call!(
                    driver,
                    &mut recorder,
                    &mut backend_storage,
                    append_pending_tree_chunk
                );
            }
        }
        let root =
            record_and_replay_storage_call!(driver, &mut recorder, &mut backend_storage, seal_tree);
        driver.begin_frontier_scan(&query_schedule).unwrap();
        assert!(record_and_replay_storage_call!(
            driver,
            &mut recorder,
            &mut backend_storage,
            read_next_tree_chunk
        ));
        let output = record_and_replay_storage_call!(
            driver,
            &mut recorder,
            &mut backend_storage,
            finish_frontier_scan
        );
        assert_eq!(output.root(), root);
        assert_eq!(output.usage().transaction_count(), 5);
        assert_eq!(output.usage().deleted_object_count(), 1);
    }

    #[test]
    fn retention_driver_keeps_delayed_trees_through_live_prefix_last_use() {
        let (merkle_geometries, wire_geometries) = retained_response_geometries();
        let proof_geometry = CompactProofWireGeometry::new(1, wire_geometries)
            .expect("retained-tree proof geometry");
        let public_input_geometry = CompactPublicInputWireGeometry::new(1, 1, 1)
            .expect("retained-tree public-input geometry");
        let public_input_bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x71; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x72; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x73; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x74; Hash512::BYTE_LENGTH]),
        );
        let canonical_public_input_bytes =
            encode_compact_public_input(public_input_geometry, public_input_bindings, &[base(7)])
                .expect("retained-tree public input encodes");
        let decoded_public_input = decode_compact_public_input(
            public_input_geometry,
            public_input_bindings,
            &canonical_public_input_bytes,
        )
        .expect("retained-tree public input decodes");
        let mut transcript = CompactProverTranscript::new(
            &proof_geometry,
            &decoded_public_input,
            &canonical_public_input_bytes,
        )
        .expect("retained-tree transcript starts");
        let mut driver =
            CompactResponseTreeRetentionDriver::new(&merkle_geometries, proof_geometry.responses())
                .expect("retained-tree coordinator starts");
        let mut storage = TestStorage::default();
        let response_values = vec![
            vec![
                OwnedLeafValue::BaseField(vec![base(11)]),
                OwnedLeafValue::BaseField(vec![base(13)]),
            ],
            vec![OwnedLeafValue::BaseField(vec![base(17)])],
            vec![OwnedLeafValue::ExtensionField(vec![extension(19)])],
        ];
        let response_salts = [
            vec![
                [0x81; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
                [0x82; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
            ],
            vec![[0x83; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]],
            vec![[0x84; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]],
        ];
        let round_salts = [
            [0x91; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            [0x92; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            [0x93; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
        ];
        let mut roots = Vec::new();
        let mut verifier_messages = Vec::new();
        let mut opened_response_ordinals = Vec::new();
        let mut delayed_frontier = None;

        for response_index in 0..response_values.len() {
            let root = commit_retained_response(
                &mut driver,
                &mut storage,
                &response_values[response_index],
                &response_salts[response_index],
            );
            roots.push(root);
            let expected_live_object_count_before_move = match response_index {
                0 => 1,
                1 | 2 => 2,
                _ => unreachable!(),
            };
            assert_eq!(
                storage.committed_object_count(),
                expected_live_object_count_before_move
            );
            assert_eq!(
                driver.begin_next_response(&mut storage),
                Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase),
                "the next response cannot start before the current verifier move completes"
            );
            transcript
                .record_response_commitment(root, round_salts[response_index])
                .expect("retained-tree root enters the transcript");
            verifier_messages.push(
                transcript
                    .derive_verifier_message()
                    .expect("retained-tree verifier message derives from the live prefix"),
            );
            if response_index == 0 {
                assert!(matches!(
                    driver.advance_verifier_move(&[], &mut storage),
                    Err(CompactResponseTreeExternalMemoryExecutionError::WrongPhase)
                ));
            }
            let outputs =
                complete_retained_verifier_move(&mut driver, &verifier_messages, &mut storage);
            let expected_opened_ordinals: &[u32] = match response_index {
                0 => &[],
                1 => &[1],
                2 => &[0, 2],
                _ => unreachable!(),
            };
            assert_eq!(
                outputs
                    .iter()
                    .map(CompactResponseTreeLastUseOutput::response_ordinal)
                    .collect::<Vec<_>>(),
                expected_opened_ordinals
            );
            for output in outputs {
                let response_ordinal = output.response_ordinal();
                let response_index = usize::try_from(response_ordinal)
                    .expect("retained response ordinal fits usize");
                let expected_query_schedule =
                    CompactResponseQuerySchedule::derive_at_last_query_boundary(
                        &merkle_geometries[response_index],
                        proof_geometry.responses(),
                        &verifier_messages,
                    )
                    .expect("retained response query schedule derives at exact last use");
                assert_eq!(output.root(), roots[response_index]);
                assert_eq!(
                    output.query_leaf_ordinals(),
                    expected_query_schedule.as_slice()
                );
                assert_eq!(output.usage().deleted_object_count(), 1);
                if response_ordinal == 0 {
                    assert_eq!(output.frontier().len(), 1);
                    delayed_frontier = Some(output.into_frontier());
                } else {
                    assert!(output.frontier().is_empty());
                }
                opened_response_ordinals.push(response_ordinal);
            }
            let expected_live_object_count_after_move = match response_index {
                0 | 1 => 1,
                2 => 0,
                _ => unreachable!(),
            };
            assert_eq!(
                storage.committed_object_count(),
                expected_live_object_count_after_move
            );
        }
        transcript
            .finish()
            .expect("retained-tree transcript consumes every response");
        assert_eq!(opened_response_ordinals, [1, 0, 2]);
        assert_eq!(
            delayed_frontier
                .expect("the delayed response returns its minimal frontier")
                .len(),
            1
        );
        let usage = driver
            .finish()
            .expect("the retained-tree coordinator finishes");
        assert_eq!(usage.total_written_byte_length(), 320);
        assert_eq!(usage.total_read_byte_length(), 320);
        assert_eq!(usage.peak_stored_byte_length(), 256);
        assert_eq!(usage.transaction_count(), 15);
        assert_eq!(usage.deleted_object_count(), 3);
        assert_eq!(storage.committed_transaction_count(), 15);
        assert_eq!(storage.deleted_object_count(), 3);
        assert_eq!(storage.committed_object_count(), 0);
    }

    #[test]
    fn retention_driver_cancels_live_objects_and_remains_idempotent() {
        let (merkle_geometries, wire_geometries) = retained_response_geometries();
        let mut driver =
            CompactResponseTreeRetentionDriver::new(&merkle_geometries, &wire_geometries)
                .expect("retained-tree cancellation coordinator starts");
        let mut storage = TestStorage::default();
        let values = [
            OwnedLeafValue::BaseField(vec![base(29)]),
            OwnedLeafValue::BaseField(vec![base(31)]),
        ];
        let salts = [
            [0xa1; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
            [0xa2; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
        ];
        let root = commit_retained_response(&mut driver, &mut storage, &values, &salts);
        assert_ne!(root, [0_u8; Hash512::BYTE_LENGTH]);
        assert_eq!(storage.committed_object_count(), 1);

        driver
            .cancel(&mut storage)
            .expect("retained-tree cancellation deletes the live object");
        assert_eq!(storage.committed_object_count(), 0);
        assert_eq!(storage.deleted_object_count(), 1);
        assert_eq!(storage.committed_transaction_count(), 4);
        driver
            .cancel(&mut storage)
            .expect("retained-tree cancellation remains idempotent");
        assert_eq!(storage.deleted_object_count(), 1);
        assert_eq!(storage.committed_transaction_count(), 4);
    }
}
