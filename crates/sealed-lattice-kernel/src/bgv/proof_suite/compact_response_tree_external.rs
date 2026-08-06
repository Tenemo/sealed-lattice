//! Transactional external-memory lifecycle for one compact response tree.
//!
//! One response owns one public-integrity postorder tree object. The object is
//! created and append-only until its root has been committed, then scanned once
//! for the verifier-derived minimal frontier and deleted. Driver state advances
//! only after the corresponding storage transaction commits successfully.

use core::mem::size_of;

use zeroize::Zeroizing;

use super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_proof_wire::CompactProofResponseWireGeometry;
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
}
