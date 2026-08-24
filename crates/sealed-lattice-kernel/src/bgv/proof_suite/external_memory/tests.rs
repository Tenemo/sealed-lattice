use super::*;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FILE_BACKED_TEST_STORAGE_IDENTIFIER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestStorageError {
    NoTransaction,
    Duplicate,
    Missing,
    WrongLength,
    Io,
}

#[derive(Clone)]
struct TestObject {
    bytes: Vec<u8>,
    exact_byte_length: usize,
    sealed: bool,
    protection: ProofExternalMemoryProtection,
}

#[derive(Default)]
pub(crate) struct TestStorage {
    committed: BTreeMap<ProofExternalMemoryObject, TestObject>,
    transaction: Option<BTreeMap<ProofExternalMemoryObject, TestObject>>,
    deleted_objects: Vec<ProofExternalMemoryObject>,
    begun_transaction_count: u64,
    committed_transaction_count: u64,
}

impl TestStorage {
    pub(crate) fn committed_object_count(&self) -> usize {
        self.committed.len()
    }

    pub(crate) fn deleted_object_count(&self) -> usize {
        self.deleted_objects.len()
    }

    pub(crate) const fn committed_transaction_count(&self) -> u64 {
        self.committed_transaction_count
    }
}

impl ProofExternalMemory for TestStorage {
    type Error = TestStorageError;

    fn begin_transaction(&mut self, _: u64, _: u32) -> Result<(), Self::Error> {
        if self.transaction.is_some() {
            return Err(TestStorageError::Duplicate);
        }
        self.begun_transaction_count += 1;
        self.transaction = Some(self.committed.clone());
        Ok(())
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?;
        if transaction.contains_key(&object) {
            return Err(TestStorageError::Duplicate);
        }
        transaction.insert(
            object,
            TestObject {
                bytes: Vec::new(),
                exact_byte_length: usize::try_from(exact_byte_length)
                    .map_err(|_| TestStorageError::WrongLength)?,
                sealed: false,
                protection,
            },
        );
        Ok(())
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let object = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .get_mut(&object)
            .ok_or(TestStorageError::Missing)?;
        if object.sealed
            || usize::try_from(expected_offset).ok() != Some(object.bytes.len())
            || object.bytes.len() + bytes.len() > object.exact_byte_length
        {
            return Err(TestStorageError::WrongLength);
        }
        object.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let object = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .get_mut(&object)
            .ok_or(TestStorageError::Missing)?;
        if object.bytes.len() != object.exact_byte_length {
            return Err(TestStorageError::WrongLength);
        }
        object.sealed = true;
        Ok(())
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let object = self
            .transaction
            .as_ref()
            .ok_or(TestStorageError::NoTransaction)?
            .get(&object)
            .ok_or(TestStorageError::Missing)?;
        let offset = usize::try_from(offset).map_err(|_| TestStorageError::WrongLength)?;
        let source = object
            .bytes
            .get(offset..offset + destination.len())
            .ok_or(TestStorageError::WrongLength)?;
        destination.copy_from_slice(source);
        Ok(())
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        self.transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .remove(&object)
            .ok_or(TestStorageError::Missing)?;
        self.deleted_objects.push(object);
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        self.committed = self
            .transaction
            .take()
            .ok_or(TestStorageError::NoTransaction)?;
        self.committed_transaction_count += 1;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        self.transaction
            .take()
            .ok_or(TestStorageError::NoTransaction)?;
        Ok(())
    }
}

#[derive(Clone)]
struct FileBackedTestObject {
    path: PathBuf,
    exact_byte_length: u64,
    current_byte_length: u64,
    sealed: bool,
    protection: ProofExternalMemoryProtection,
}

struct FileBackedTestTransaction {
    objects: BTreeMap<ProofExternalMemoryObject, FileBackedTestObject>,
    created_paths: BTreeSet<PathBuf>,
    declared_byte_length: u64,
}

/// Native evidence storage that keeps external-memory bytes outside the test
/// process while preserving copy-on-write transaction behavior. This is test
/// custody only; browser production uses the transaction recorder and its
/// IndexedDB runtime.
pub(crate) struct FileBackedTestStorage {
    directory: PathBuf,
    committed: BTreeMap<ProofExternalMemoryObject, FileBackedTestObject>,
    transaction: Option<FileBackedTestTransaction>,
    known_paths: BTreeSet<PathBuf>,
    next_file_identifier: u64,
    maximum_declared_byte_length: u64,
}

impl FileBackedTestStorage {
    pub(crate) fn new() -> Result<Self, TestStorageError> {
        let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .ok_or(TestStorageError::Io)?
            .to_path_buf();
        let parent = repository_root.join("temp").join("test-external-memory");
        fs::create_dir_all(&parent).map_err(|_| TestStorageError::Io)?;
        let directory = loop {
            let identifier =
                NEXT_FILE_BACKED_TEST_STORAGE_IDENTIFIER.fetch_add(1, Ordering::Relaxed);
            let candidate =
                parent.join(format!("proof-storage-{}-{identifier}", std::process::id()));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(TestStorageError::Io),
            }
        };
        Ok(Self {
            directory,
            committed: BTreeMap::new(),
            transaction: None,
            known_paths: BTreeSet::new(),
            next_file_identifier: 0,
            maximum_declared_byte_length: 0,
        })
    }

    pub(crate) const fn maximum_declared_byte_length(&self) -> u64 {
        self.maximum_declared_byte_length
    }

    pub(crate) fn committed_declared_byte_length(&self) -> u64 {
        self.committed
            .values()
            .map(|object| object.exact_byte_length)
            .sum()
    }

    pub(crate) fn retained_secret_object_count(&self) -> usize {
        self.committed
            .values()
            .filter(|object| {
                object.protection == ProofExternalMemoryProtection::SecretAuthenticatedEncryption
            })
            .count()
    }

    fn next_object_path(
        &mut self,
        object: ProofExternalMemoryObject,
    ) -> Result<PathBuf, TestStorageError> {
        let file_identifier = self.next_file_identifier;
        self.next_file_identifier = self
            .next_file_identifier
            .checked_add(1)
            .ok_or(TestStorageError::WrongLength)?;
        Ok(self
            .directory
            .join(format!("object-{}-{file_identifier}.bin", object.ordinal())))
    }

    fn copy_object_for_transaction(
        &mut self,
        object: ProofExternalMemoryObject,
    ) -> Result<(), TestStorageError> {
        let transaction_path = self
            .transaction
            .as_ref()
            .ok_or(TestStorageError::NoTransaction)?
            .objects
            .get(&object)
            .ok_or(TestStorageError::Missing)?
            .path
            .clone();
        let Some(committed) = self.committed.get(&object) else {
            return Ok(());
        };
        if transaction_path != committed.path {
            return Ok(());
        }
        let copied_path = self.next_object_path(object)?;
        let mut source = File::open(&transaction_path).map_err(|_| TestStorageError::Io)?;
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&copied_path)
            .map_err(|_| TestStorageError::Io)?;
        self.known_paths.insert(copied_path.clone());
        self.transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .created_paths
            .insert(copied_path.clone());
        std::io::copy(&mut source, &mut destination).map_err(|_| TestStorageError::Io)?;
        destination.flush().map_err(|_| TestStorageError::Io)?;
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?;
        transaction
            .objects
            .get_mut(&object)
            .ok_or(TestStorageError::Missing)?
            .path = copied_path;
        Ok(())
    }

    fn remove_known_file(&mut self, path: &PathBuf) -> Result<(), TestStorageError> {
        fs::remove_file(path).map_err(|_| TestStorageError::Io)?;
        self.known_paths.remove(path);
        Ok(())
    }
}

impl ProofExternalMemory for FileBackedTestStorage {
    type Error = TestStorageError;

    fn begin_transaction(&mut self, _: u64, _: u32) -> Result<(), Self::Error> {
        if self.transaction.is_some() {
            return Err(TestStorageError::Duplicate);
        }
        self.transaction = Some(FileBackedTestTransaction {
            objects: self.committed.clone(),
            created_paths: BTreeSet::new(),
            declared_byte_length: self.committed_declared_byte_length(),
        });
        Ok(())
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        if self
            .transaction
            .as_ref()
            .ok_or(TestStorageError::NoTransaction)?
            .objects
            .contains_key(&object)
        {
            return Err(TestStorageError::Duplicate);
        }
        let path = self.next_object_path(object)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| TestStorageError::Io)?;
        self.known_paths.insert(path.clone());
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?;
        transaction.declared_byte_length = transaction
            .declared_byte_length
            .checked_add(exact_byte_length)
            .ok_or(TestStorageError::WrongLength)?;
        self.maximum_declared_byte_length = self
            .maximum_declared_byte_length
            .max(transaction.declared_byte_length);
        transaction.created_paths.insert(path.clone());
        transaction.objects.insert(
            object,
            FileBackedTestObject {
                path,
                exact_byte_length,
                current_byte_length: 0,
                sealed: false,
                protection,
            },
        );
        Ok(())
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let byte_length = u64::try_from(bytes.len()).map_err(|_| TestStorageError::WrongLength)?;
        let stored = self
            .transaction
            .as_ref()
            .ok_or(TestStorageError::NoTransaction)?
            .objects
            .get(&object)
            .ok_or(TestStorageError::Missing)?;
        let following_byte_length = expected_offset
            .checked_add(byte_length)
            .ok_or(TestStorageError::WrongLength)?;
        if stored.sealed
            || stored.current_byte_length != expected_offset
            || following_byte_length > stored.exact_byte_length
        {
            return Err(TestStorageError::WrongLength);
        }
        self.copy_object_for_transaction(object)?;
        let path = self
            .transaction
            .as_ref()
            .ok_or(TestStorageError::NoTransaction)?
            .objects
            .get(&object)
            .ok_or(TestStorageError::Missing)?
            .path
            .clone();
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|_| TestStorageError::Io)?;
        file.write_all(bytes).map_err(|_| TestStorageError::Io)?;
        self.transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .objects
            .get_mut(&object)
            .ok_or(TestStorageError::Missing)?
            .current_byte_length = following_byte_length;
        Ok(())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let stored = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?
            .objects
            .get_mut(&object)
            .ok_or(TestStorageError::Missing)?;
        if stored.sealed || stored.current_byte_length != stored.exact_byte_length {
            return Err(TestStorageError::WrongLength);
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&stored.path)
            .and_then(|file| file.sync_all())
            .map_err(|_| TestStorageError::Io)?;
        stored.sealed = true;
        Ok(())
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let stored = self
            .transaction
            .as_ref()
            .ok_or(TestStorageError::NoTransaction)?
            .objects
            .get(&object)
            .ok_or(TestStorageError::Missing)?;
        let end = offset
            .checked_add(
                u64::try_from(destination.len()).map_err(|_| TestStorageError::WrongLength)?,
            )
            .ok_or(TestStorageError::WrongLength)?;
        if end > stored.current_byte_length {
            return Err(TestStorageError::WrongLength);
        }
        let mut file = File::open(&stored.path).map_err(|_| TestStorageError::Io)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| TestStorageError::Io)?;
        file.read_exact(destination)
            .map_err(|_| TestStorageError::Io)
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(TestStorageError::NoTransaction)?;
        let removed = transaction
            .objects
            .remove(&object)
            .ok_or(TestStorageError::Missing)?;
        transaction.declared_byte_length = transaction
            .declared_byte_length
            .checked_sub(removed.exact_byte_length)
            .ok_or(TestStorageError::WrongLength)?;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        let transaction = self
            .transaction
            .take()
            .ok_or(TestStorageError::NoTransaction)?;
        let retained_paths = transaction
            .objects
            .values()
            .map(|object| object.path.clone())
            .collect::<BTreeSet<_>>();
        let stale_committed_paths = self
            .committed
            .values()
            .map(|object| object.path.clone())
            .filter(|path| !retained_paths.contains(path))
            .collect::<Vec<_>>();
        let discarded_created_paths = transaction
            .created_paths
            .iter()
            .filter(|path| !retained_paths.contains(*path))
            .cloned()
            .collect::<Vec<_>>();
        for path in stale_committed_paths
            .iter()
            .chain(discarded_created_paths.iter())
        {
            self.remove_known_file(path)?;
        }
        self.committed = transaction.objects;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        let transaction = self
            .transaction
            .take()
            .ok_or(TestStorageError::NoTransaction)?;
        for path in &transaction.created_paths {
            self.remove_known_file(path)?;
        }
        Ok(())
    }
}

impl Drop for FileBackedTestStorage {
    fn drop(&mut self) {
        if let Some(transaction) = self.transaction.take() {
            for path in transaction.created_paths {
                let _ = fs::remove_file(&path);
                self.known_paths.remove(&path);
            }
        }
        for path in core::mem::take(&mut self.known_paths) {
            let _ = fs::remove_file(path);
        }
        let parent = self.directory.parent().map(PathBuf::from);
        let _ = fs::remove_dir(&self.directory);
        if let Some(parent) = parent {
            let _ = fs::remove_dir(parent);
        }
    }
}

fn plan() -> ProofExternalMemoryPlan {
    ProofExternalMemoryPlan::new(
        3,
        4,
        4,
        2,
        12,
        16,
        24,
        32,
        vec![
            ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                8,
                0,
                0,
                2,
            ),
            ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(1),
                ProofExternalMemoryProtection::PublicIntegrity,
                4,
                1,
                1,
                1,
            ),
        ],
    )
    .expect("valid external-memory plan")
}

fn single_object_write_plan(
    maximum_chunk_byte_length: u32,
    exact_byte_length: u64,
) -> ProofExternalMemoryPlan {
    let maximum_transaction_count = exact_byte_length
        .div_ceil(u64::from(maximum_chunk_byte_length))
        .checked_add(3)
        .expect("the test transaction ceiling fits u64");
    ProofExternalMemoryPlan::new(
        1,
        maximum_chunk_byte_length,
        u64::from(maximum_chunk_byte_length),
        1,
        exact_byte_length,
        exact_byte_length,
        1,
        maximum_transaction_count,
        vec![ProofExternalMemoryObjectPlan::new(
            ProofExternalMemoryObject::new(0),
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
            exact_byte_length,
            0,
            0,
            0,
        )],
    )
    .expect("the single-object write plan is valid")
}

#[test]
fn file_backed_test_storage_commits_and_aborts_copy_on_write_transactions() {
    let first = ProofExternalMemoryObject::new(41);
    let aborted_second = ProofExternalMemoryObject::new(42);
    let mut storage = FileBackedTestStorage::new().expect("file-backed test storage opens");
    let directory = storage.directory.clone();

    storage.begin_transaction(32, 4).unwrap();
    storage
        .create_object(
            first,
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
            6,
        )
        .unwrap();
    storage.append_object_bytes(first, 0, &[1, 2, 3]).unwrap();
    storage.commit_transaction().unwrap();
    assert_eq!(storage.committed_declared_byte_length(), 6);
    assert_eq!(storage.retained_secret_object_count(), 1);

    storage.begin_transaction(32, 4).unwrap();
    storage.append_object_bytes(first, 3, &[4, 5, 6]).unwrap();
    storage.seal_object(first).unwrap();
    storage
        .create_object(
            aborted_second,
            ProofExternalMemoryProtection::PublicIntegrity,
            4,
        )
        .unwrap();
    storage
        .append_object_bytes(aborted_second, 0, &[9, 8, 7, 6])
        .unwrap();
    assert_eq!(storage.maximum_declared_byte_length(), 10);
    storage.abort_transaction().unwrap();

    storage.begin_transaction(32, 4).unwrap();
    let mut committed_prefix = [0_u8; 3];
    storage
        .read_object_bytes(first, 0, &mut committed_prefix)
        .unwrap();
    assert_eq!(committed_prefix, [1, 2, 3]);
    assert_eq!(
        storage.read_object_bytes(first, 3, &mut [0_u8; 1]),
        Err(TestStorageError::WrongLength),
        "an aborted copy-on-write append must remain invisible"
    );
    assert_eq!(
        storage.read_object_bytes(aborted_second, 0, &mut [0_u8; 1]),
        Err(TestStorageError::Missing),
        "an object created in an aborted transaction must not survive"
    );
    storage.abort_transaction().unwrap();

    storage.begin_transaction(32, 2).unwrap();
    storage.append_object_bytes(first, 3, &[4, 5, 6]).unwrap();
    storage.seal_object(first).unwrap();
    storage.commit_transaction().unwrap();
    storage.begin_transaction(32, 2).unwrap();
    let mut completed = [0_u8; 6];
    storage.read_object_bytes(first, 0, &mut completed).unwrap();
    assert_eq!(completed, [1, 2, 3, 4, 5, 6]);
    storage.delete_object(first).unwrap();
    storage.commit_transaction().unwrap();
    assert_eq!(storage.committed_declared_byte_length(), 0);
    assert_eq!(storage.retained_secret_object_count(), 0);

    drop(storage);
    assert!(
        !directory.exists(),
        "scratch custody must be removed on drop"
    );
}

#[test]
fn executor_enforces_chunked_writes_random_reads_and_exact_last_use() {
    let first = ProofExternalMemoryObject::new(0);
    let second = ProofExternalMemoryObject::new(1);
    let mut executor = ProofExternalMemoryExecutor::new(plan());
    let mut storage = TestStorage::default();

    executor
        .begin_object(&mut storage, first)
        .expect("first starts");
    executor
        .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
        .expect("first chunk writes");
    executor
        .append_object_bytes(&mut storage, first, &[5, 6, 7, 8])
        .expect("second chunk writes");
    executor
        .seal_object(&mut storage, first)
        .expect("first seals");
    executor
        .complete_step(&mut storage)
        .expect("step zero completes");

    executor
        .begin_object(&mut storage, second)
        .expect("second starts");
    let mut second_object_bytes = Zeroizing::new(vec![9, 10, 11, 12]);
    executor
        .append_owned_object_bytes(&mut storage, second, &mut second_object_bytes)
        .expect("second writes through the optional owned path");
    assert_eq!(
        second_object_bytes.as_slice(),
        &[9, 10, 11, 12],
        "storage without an owned fast path keeps the producer allocation"
    );
    executor
        .seal_object(&mut storage, second)
        .expect("second seals");
    let mut suffix = [0_u8; 3];
    executor
        .read_object_bytes(&mut storage, first, 5, &mut suffix)
        .expect("random suffix read");
    assert_eq!(suffix, [6, 7, 8]);
    executor
        .complete_step(&mut storage)
        .expect("second is deleted");
    assert!(!storage.committed.contains_key(&second));
    assert_eq!(
        storage.committed.get(&first).map(|entry| entry.protection),
        Some(ProofExternalMemoryProtection::SecretAuthenticatedEncryption),
    );

    let mut prefix = [0_u8; 2];
    executor
        .read_object_bytes(&mut storage, first, 0, &mut prefix)
        .expect("first remains through last use");
    assert_eq!(prefix, [1, 2]);
    executor
        .complete_step(&mut storage)
        .expect("final deletion commits");
    let usage = executor.finish().expect("executor finishes");
    assert_eq!(usage.total_written_byte_length, 12);
    assert_eq!(usage.total_read_byte_length, 5);
    assert_eq!(usage.peak_stored_byte_length, 12);
    assert_eq!(usage.deleted_object_count, 2);
    assert!(storage.committed.is_empty());
}

#[test]
fn executor_reuses_one_physical_ordinal_across_non_overlapping_lifecycles() {
    let physical_object = ProofExternalMemoryObject::new(7);
    let reusable_plan = ProofExternalMemoryPlan::new(
        2,
        4,
        4,
        1,
        4,
        8,
        8,
        16,
        vec![
            ProofExternalMemoryObjectPlan::new(
                physical_object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                4,
                0,
                0,
                0,
            ),
            ProofExternalMemoryObjectPlan::new(
                physical_object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                4,
                1,
                1,
                1,
            ),
        ],
    )
    .expect("non-overlapping lifecycles may reuse one physical ordinal");
    assert_eq!(reusable_plan.physical_object_count(), Ok(1));
    assert_eq!(reusable_plan.object_lifecycle_count(), Ok(2));

    let mut executor = ProofExternalMemoryExecutor::new(reusable_plan);
    let mut storage = TestStorage::default();
    for (step, expected_bytes) in [[1_u8, 2, 3, 4], [5_u8, 6, 7, 8]].into_iter().enumerate() {
        executor
            .begin_object(&mut storage, physical_object)
            .expect("the current lifecycle begins after the prior deletion");
        executor
            .append_object_bytes(&mut storage, physical_object, &expected_bytes)
            .expect("the current lifecycle writes exact bytes");
        executor
            .seal_object(&mut storage, physical_object)
            .expect("the current lifecycle seals");
        let mut observed = [0_u8; 4];
        executor
            .read_object_bytes(&mut storage, physical_object, 0, &mut observed)
            .expect("the current lifecycle is the only addressable generation");
        assert_eq!(observed, expected_bytes);
        executor
            .complete_step(&mut storage)
            .unwrap_or_else(|error| panic!("reused lifecycle step {step} failed: {error:?}"));
        assert!(!storage.committed.contains_key(&physical_object));
    }
    let usage = executor.finish().expect("both lifecycles are consumed");
    assert_eq!(usage.total_written_byte_length(), 8);
    assert_eq!(usage.total_read_byte_length(), 8);
    assert_eq!(usage.peak_stored_byte_length(), 4);
    assert_eq!(usage.deleted_object_count(), 2);

    assert_eq!(
        ProofExternalMemoryPlan::new(
            2,
            4,
            4,
            2,
            8,
            8,
            1,
            1,
            vec![
                ProofExternalMemoryObjectPlan::new(
                    physical_object,
                    ProofExternalMemoryProtection::PublicIntegrity,
                    4,
                    0,
                    0,
                    1,
                ),
                ProofExternalMemoryObjectPlan::new(
                    physical_object,
                    ProofExternalMemoryProtection::PublicIntegrity,
                    4,
                    1,
                    1,
                    1,
                ),
            ],
        ),
        Err(ProofExternalMemoryError::InvalidPlan),
        "overlapping lifecycles cannot alias one physical ordinal",
    );
}

#[test]
fn executor_restores_only_completed_constraint_local_lifecycles() {
    let retained_source = ProofExternalMemoryObject::new(20);
    let reusable_transform = ProofExternalMemoryObject::new(21);
    let checkpoint_plan = || {
        ProofExternalMemoryPlan::new(
            6,
            4,
            4,
            2,
            8,
            12,
            64,
            64,
            vec![
                ProofExternalMemoryObjectPlan::new(
                    retained_source,
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    4,
                    0,
                    0,
                    5,
                ),
                ProofExternalMemoryObjectPlan::new(
                    reusable_transform,
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    4,
                    1,
                    1,
                    2,
                ),
                ProofExternalMemoryObjectPlan::new(
                    reusable_transform,
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    4,
                    3,
                    3,
                    4,
                ),
            ],
        )
        .expect("the checkpoint plan has disjoint transform lifecycles")
    };
    let prepare_replayed_prefix = || {
        let mut executor = ProofExternalMemoryExecutor::new(checkpoint_plan());
        let mut storage = TestStorage::default();
        executor
            .begin_object(&mut storage, retained_source)
            .expect("the retained source begins");
        executor
            .append_object_bytes(&mut storage, retained_source, &[1, 2, 3, 4])
            .expect("the retained source writes");
        executor
            .seal_object(&mut storage, retained_source)
            .expect("the retained source seals");
        executor
            .complete_step(&mut storage)
            .expect("deterministic source replay reaches quotient construction");
        (executor, storage)
    };
    let restored_usage = ProofExternalMemoryUsage {
        total_written_byte_length: 8,
        total_read_byte_length: 8,
        peak_stored_byte_length: 8,
        transaction_count: 9,
        deleted_object_count: 1,
    };

    let (mut hostile_executor, _) = prepare_replayed_prefix();
    let mut wrong_written_usage = restored_usage;
    wrong_written_usage.total_written_byte_length -= 1;
    assert_eq!(
        hostile_executor.restore_completed_constraint_step_prefix(3, wrong_written_usage),
        Err(ProofExternalMemoryError::ResourceLimitExceeded),
    );
    let mut wrong_deleted_usage = restored_usage;
    wrong_deleted_usage.deleted_object_count = 0;
    assert_eq!(
        hostile_executor.restore_completed_constraint_step_prefix(3, wrong_deleted_usage),
        Err(ProofExternalMemoryError::ResourceLimitExceeded),
    );
    assert_eq!(
        hostile_executor.restore_completed_constraint_step_prefix(2, restored_usage),
        Err(ProofExternalMemoryError::InvalidLifecycle),
    );

    let (mut executor, mut storage) = prepare_replayed_prefix();
    executor
        .restore_completed_constraint_step_prefix(3, restored_usage)
        .expect("the authenticated completed constraint prefix restores");
    assert_eq!(executor.current_step(), 3);
    assert_eq!(executor.usage(), restored_usage);
    assert_eq!(storage.committed_object_count(), 1);

    executor
        .begin_object(&mut storage, reusable_transform)
        .expect("the reused transform ordinal begins without a stale object");
    executor
        .append_object_bytes(&mut storage, reusable_transform, &[5, 6, 7, 8])
        .expect("the future transform lifecycle writes");
    executor
        .seal_object(&mut storage, reusable_transform)
        .expect("the future transform lifecycle seals");
    executor
        .complete_step(&mut storage)
        .expect("the transform step completes");
    let mut transformed = [0_u8; 4];
    executor
        .read_object_bytes(&mut storage, reusable_transform, 0, &mut transformed)
        .expect("the restored continuation reads the future transform");
    assert_eq!(transformed, [5, 6, 7, 8]);
    let mut retained = [0_u8; 4];
    executor
        .read_object_bytes(&mut storage, retained_source, 0, &mut retained)
        .expect("the source reconstructed by deterministic replay remains live");
    assert_eq!(retained, [1, 2, 3, 4]);
    executor
        .complete_step(&mut storage)
        .expect("the future transform retires at its exact last use");
    executor
        .read_object_bytes(&mut storage, retained_source, 0, &mut retained)
        .expect("the retained source remains readable through its final step");
    executor
        .complete_step(&mut storage)
        .expect("the retained source retires at terminal completion");
    let terminal_usage = executor.finish().expect("the restored executor terminates");
    assert_eq!(terminal_usage.total_written_byte_length(), 12);
    assert_eq!(terminal_usage.total_read_byte_length(), 20);
    assert_eq!(terminal_usage.peak_stored_byte_length(), 8);
    assert_eq!(terminal_usage.deleted_object_count(), 3);
    assert!(storage.committed.is_empty());
}

#[test]
fn executor_accepts_only_full_intermediate_chunks_and_the_exact_declared_tail() {
    let object = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 10));
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, object)
        .expect("the object begins");

    executor
        .append_object_bytes(&mut storage, object, &[1, 2, 3, 4])
        .expect("the first full intermediate chunk appends");
    executor
        .append_object_bytes(&mut storage, object, &[5, 6, 7, 8])
        .expect("the second full intermediate chunk appends");
    executor
        .append_object_bytes(&mut storage, object, &[9, 10])
        .expect("the exact declared tail appends");
    executor
        .seal_object(&mut storage, object)
        .expect("the canonically chunked object seals");

    assert_eq!(
        storage
            .committed
            .get(&object)
            .map(|entry| entry.bytes.as_slice()),
        Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10][..]),
    );
}

#[test]
fn executor_rejects_appends_that_cannot_finish_within_the_planned_record_count() {
    let object = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 6));
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, object)
        .expect("the object begins");
    let transaction_count_after_create = executor.usage().transaction_count;

    for rejected_bytes in [&[][..], &[1][..], &[1, 2, 3, 4, 5][..]] {
        assert_eq!(
            executor.append_object_bytes(&mut storage, object, rejected_bytes),
            Err(ProofExternalMemoryExecutorError::Execution(
                ProofExternalMemoryError::WrongOffsetOrLength,
            )),
        );
        assert_eq!(
            storage
                .committed
                .get(&object)
                .map(|entry| entry.bytes.len()),
            Some(0),
        );
        assert_eq!(
            executor.usage().transaction_count,
            transaction_count_after_create,
        );
    }

    executor
        .append_object_bytes(&mut storage, object, &[1, 2, 3])
        .expect("a short packed segment appends within the declared record count");
    let transaction_count_after_intermediate_chunk = executor.usage().transaction_count;
    assert_eq!(
        executor.append_object_bytes(&mut storage, object, &[4, 5]),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::WrongOffsetOrLength,
        )),
        "a short final record is rejected when it cannot complete the object",
    );
    assert_eq!(
        storage
            .committed
            .get(&object)
            .map(|entry| entry.bytes.as_slice()),
        Some(&[1, 2, 3][..]),
    );
    assert_eq!(
        executor.usage().transaction_count,
        transaction_count_after_intermediate_chunk,
    );
    executor
        .append_object_bytes(&mut storage, object, &[4, 5, 6])
        .expect("the exact tail still appends after refusal");
}

#[test]
fn executor_accepts_packed_segment_boundaries_under_the_exact_append_budget() {
    let object = ProofExternalMemoryObject::new(0);
    let plan = ProofExternalMemoryPlan::new(
        1,
        4,
        4,
        1,
        10,
        10,
        1,
        6,
        vec![
            ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                10,
                3,
                0,
                0,
                0,
            ),
        ],
    )
    .expect("packed object plan is valid");
    let mut executor = ProofExternalMemoryExecutor::new(plan);
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, object)
        .expect("packed object begins");
    executor
        .append_object_bytes(&mut storage, object, &[1, 2, 3, 4])
        .expect("first segment full chunk appends");
    executor
        .append_object_bytes(&mut storage, object, &[5, 6])
        .expect("first segment tail appends at its exact boundary");
    executor
        .append_object_bytes(&mut storage, object, &[7, 8, 9, 10])
        .expect("second segment appends without padding");
    executor
        .seal_object(&mut storage, object)
        .expect("packed object seals");
    assert_eq!(executor.usage().total_written_byte_length(), 10);
    assert_eq!(executor.usage().transaction_count(), 5);
}

#[test]
fn executor_accepts_a_short_object_as_one_exact_chunk() {
    let object = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 3));
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, object)
        .expect("the short object begins");
    assert_eq!(
        executor.append_object_bytes(&mut storage, object, &[1, 2]),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::WrongOffsetOrLength,
        )),
        "a one-byte-short one-chunk object is rejected",
    );
    executor
        .append_object_bytes(&mut storage, object, &[1, 2, 3])
        .expect("the complete one-chunk object appends");
    executor
        .seal_object(&mut storage, object)
        .expect("the complete one-chunk object seals");
}

#[test]
fn plan_and_executor_reject_overrun_incomplete_seal_and_late_use() {
    assert_eq!(
        ProofExternalMemoryPlan::new(
            1,
            8,
            4,
            1,
            8,
            8,
            8,
            8,
            vec![ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::PublicIntegrity,
                8,
                0,
                0,
                0,
            )],
        ),
        Err(ProofExternalMemoryError::InvalidPlan),
    );

    let first = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(plan());
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, first)
        .expect("first starts");
    executor
        .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
        .expect("partial write succeeds");
    assert!(matches!(
        executor.complete_step(&mut storage),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::Incomplete
        )),
    ));
    assert!(matches!(
        executor.append_object_bytes(&mut storage, first, &[0; 5]),
        Err(ProofExternalMemoryExecutorError::Execution(
            ProofExternalMemoryError::WrongOffsetOrLength
        )),
    ));
}

#[test]
fn plan_validation_work_is_bounded_by_object_count_not_step_count() {
    let plan = ProofExternalMemoryPlan::new(
        u32::MAX,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        vec![ProofExternalMemoryObjectPlan::new(
            ProofExternalMemoryObject::new(0),
            ProofExternalMemoryProtection::PublicIntegrity,
            1,
            0,
            0,
            u32::MAX - 1,
        )],
    )
    .expect("large step identifiers do not expand validation work");
    assert_eq!(plan.step_count(), u32::MAX);
}

#[test]
fn browser_scratch_plan_accepts_exact_safety_bounds_and_refuses_one_over() {
    assert_eq!(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT, 4_096);
    assert_eq!(
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        1_073_741_824
    );
    let exact_object_count = u32::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
        .expect("the object-count safety bound fits u32");
    let exact_object_plan = (0..exact_object_count)
        .map(|object_ordinal| {
            ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(object_ordinal),
                ProofExternalMemoryProtection::PublicIntegrity,
                1,
                0,
                0,
                0,
            )
        })
        .collect::<Vec<_>>();
    ProofExternalMemoryPlan::new(
        1,
        1,
        1,
        exact_object_count,
        u64::from(exact_object_count),
        u64::from(exact_object_count),
        1,
        1,
        exact_object_plan,
    )
    .expect("the exact browser object safety bound is accepted");

    let one_over_object_count = exact_object_count + 1;
    let one_over_object_plan = (0..one_over_object_count)
        .map(|object_ordinal| {
            ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(object_ordinal),
                ProofExternalMemoryProtection::PublicIntegrity,
                1,
                0,
                0,
                0,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ProofExternalMemoryPlan::new(
            1,
            1,
            1,
            one_over_object_count,
            u64::from(one_over_object_count),
            u64::from(one_over_object_count),
            1,
            1,
            one_over_object_plan,
        ),
        Err(ProofExternalMemoryError::ResourceLimitExceeded),
    );

    assert_eq!(
        ProofExternalMemoryPlan::new(
            1,
            1,
            1,
            one_over_object_count,
            1,
            1,
            1,
            1,
            vec![ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::PublicIntegrity,
                1,
                0,
                0,
                0,
            )],
        ),
        Err(ProofExternalMemoryError::ResourceLimitExceeded),
        "a caller cannot raise the per-transaction operation ceiling",
    );

    let plan_at_byte_ceiling = |stored_byte_length| {
        ProofExternalMemoryPlan::new(
            1,
            1,
            1,
            1,
            stored_byte_length,
            stored_byte_length,
            1,
            1,
            vec![ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::PublicIntegrity,
                stored_byte_length,
                0,
                0,
                0,
            )],
        )
    };
    plan_at_byte_ceiling(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH)
        .expect("the exact browser scratch-byte safety bound is accepted");
    assert_eq!(
        plan_at_byte_ceiling(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH + 1),
        Err(ProofExternalMemoryError::ResourceLimitExceeded),
    );
}

#[test]
fn browser_transaction_yield_and_exact_replay_change_state_only_after_replay() {
    let first = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(plan());
    let mut recorder = ProofExternalMemoryTransactionRecorder::new();

    assert_eq!(
        executor.begin_object(&mut recorder, first),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    assert_eq!(executor.usage().transaction_count, 0);
    let request = recorder
        .take_yielded_request()
        .expect("create transaction yielded");
    assert_eq!(
        request.operations(),
        &[ProofExternalMemoryTransactionOperation::Create {
            object: first,
            protection: ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
            exact_byte_length: 8,
        }]
    );
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
        .expect("create response has no reads");
    executor
        .begin_object(&mut replay, first)
        .expect("successful IndexedDB create replays");
    assert_eq!(executor.usage().transaction_count, 1);

    assert_eq!(
        executor.append_object_bytes(&mut recorder, first, &[1, 2, 3, 4]),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    let request = recorder
        .take_yielded_request()
        .expect("append transaction yielded");
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
        .expect("append response has no reads");
    executor
        .append_object_bytes(&mut replay, first, &[1, 2, 3, 4])
        .expect("successful IndexedDB append replays");

    assert_eq!(
        executor.append_object_bytes(&mut recorder, first, &[5, 6, 7, 8]),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    let request = recorder
        .take_yielded_request()
        .expect("second append transaction yielded");
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
        .expect("second append response has no reads");
    executor
        .append_object_bytes(&mut replay, first, &[5, 6, 7, 8])
        .expect("successful second IndexedDB append replays");

    assert_eq!(
        executor.seal_object(&mut recorder, first),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    let request = recorder
        .take_yielded_request()
        .expect("seal transaction yielded");
    let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
        .expect("seal response has no reads");
    executor
        .seal_object(&mut replay, first)
        .expect("successful IndexedDB seal replays");
    executor
        .complete_step(&mut recorder)
        .expect("first liveness step has no deletion");

    let mut destination = [0_u8; 4];
    assert_eq!(
        executor.read_object_bytes(&mut recorder, first, 0, &mut destination),
        Err(ProofExternalMemoryExecutorError::StorageCommit(
            ProofExternalMemoryTransactionAdapterError::Yielded,
        ))
    );
    assert_eq!(destination, [0; 4]);
    let request = recorder
        .take_yielded_request()
        .expect("read transaction yielded");
    let mut replay =
        ProofExternalMemoryTransactionReplay::new(request, vec![Zeroizing::new(vec![1, 2, 3, 4])])
            .expect("read response has the exact requested length");
    executor
        .read_object_bytes(&mut replay, first, 0, &mut destination)
        .expect("successful IndexedDB read replays");
    assert_eq!(destination, [1, 2, 3, 4]);
}

#[test]
fn maximum_worker_transaction_buffers_match_static_boundary_accounting() {
    let maximum_payload_byte_length =
        usize::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
            .expect("maximum external-memory payload fits usize");
    let object = ProofExternalMemoryObject::new(0);

    let mut append_recorder = ProofExternalMemoryTransactionRecorder::new();
    append_recorder
        .begin_transaction(
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
            1,
        )
        .expect("maximum append transaction starts");
    append_recorder
        .append_object_bytes(object, 0, &vec![0x5a; maximum_payload_byte_length])
        .expect("maximum append records");
    assert_eq!(
        append_recorder.commit_transaction(),
        Err(ProofExternalMemoryTransactionAdapterError::Yielded),
    );
    let append_request = append_recorder
        .take_yielded_request()
        .expect("maximum append request yielded");
    let encoded_append_request = append_request
        .encode_worker_request()
        .expect("maximum append request encodes");
    let encoded_empty_response = append_request
        .encode_test_worker_response(&[])
        .expect("empty append response encodes");

    let mut read_recorder = ProofExternalMemoryTransactionRecorder::new();
    read_recorder
        .begin_transaction(
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
            1,
        )
        .expect("maximum read transaction starts");
    let mut read_destination = vec![0_u8; maximum_payload_byte_length];
    read_recorder
        .read_object_bytes(object, 0, &mut read_destination)
        .expect("maximum read records");
    assert_eq!(
        read_recorder.commit_transaction(),
        Err(ProofExternalMemoryTransactionAdapterError::Yielded),
    );
    let read_request = read_recorder
        .take_yielded_request()
        .expect("maximum read request yielded");
    let encoded_read_request = read_request
        .encode_worker_request()
        .expect("maximum read request encodes");
    let encoded_read_response = read_request
        .encode_test_worker_response(&[vec![0xa5; maximum_payload_byte_length]])
        .expect("maximum read response encodes");

    assert_eq!(encoded_append_request.len(), 1_048_764);
    assert_eq!(encoded_empty_response.len(), 80);
    assert_eq!(encoded_read_request.len(), 188);
    assert_eq!(encoded_read_response.len(), 1_048_744);
    assert_eq!(
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_APPEND_REQUEST_BYTE_LENGTH,
        u64::try_from(encoded_append_request.len()).expect("append request length fits u64")
    );
    assert_eq!(
        COMMON_PROOF_EXTERNAL_MEMORY_EMPTY_RESPONSE_BYTE_LENGTH,
        u64::try_from(encoded_empty_response.len()).expect("empty response length fits u64")
    );
    assert_eq!(
        COMMON_PROOF_EXTERNAL_MEMORY_READ_REQUEST_BYTE_LENGTH,
        u64::try_from(encoded_read_request.len()).expect("read request length fits u64")
    );
    assert_eq!(
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_READ_RESPONSE_BYTE_LENGTH,
        u64::try_from(encoded_read_response.len()).expect("read response length fits u64")
    );
    assert_eq!(
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_COPIED_BUFFER_BYTE_LENGTH,
        1_048_764
    );
    assert_eq!(
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH,
        1_048_932
    );
}

fn record_worker_response_test_request(
    recorder: &mut ProofExternalMemoryTransactionRecorder,
) -> ProofExternalMemoryTransactionRequest {
    let append_object = ProofExternalMemoryObject::new(2);
    let first_read_object = ProofExternalMemoryObject::new(7);
    let second_read_object = ProofExternalMemoryObject::new(9);
    recorder
        .begin_transaction(64, 4)
        .expect("worker response transaction starts");
    recorder
        .append_object_bytes(append_object, 0, &[9, 8, 7])
        .expect("worker response append records");
    let mut first_read = [0_u8; 4];
    recorder
        .read_object_bytes(first_read_object, 3, &mut first_read)
        .expect("first worker response read records");
    recorder
        .seal_object(append_object)
        .expect("worker response seal records");
    let mut second_read = [0_u8; 3];
    recorder
        .read_object_bytes(second_read_object, 11, &mut second_read)
        .expect("second worker response read records");
    assert_eq!(
        recorder.commit_transaction(),
        Err(ProofExternalMemoryTransactionAdapterError::Yielded),
    );
    recorder
        .take_yielded_request()
        .expect("worker response request yielded")
}

fn encode_worker_test_response(
    request: &ProofExternalMemoryTransactionRequest,
    ordered_results: &[(u32, ProofExternalMemoryObject, u64, &[u8])],
) -> Vec<u8> {
    let request_digest = request
        .request_digest()
        .expect("test request digest derives");
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&EXTERNAL_MEMORY_RESPONSE_MESSAGE_KIND.to_le_bytes());
    encoded.extend_from_slice(&request.request_sequence().to_le_bytes());
    encoded.extend_from_slice(&request_digest);
    encoded.extend_from_slice(
        &u32::try_from(ordered_results.len())
            .expect("test response result count fits u32")
            .to_le_bytes(),
    );
    for (operation_index, object, offset, bytes) in ordered_results {
        encoded.extend_from_slice(&operation_index.to_le_bytes());
        encoded.extend_from_slice(&object.ordinal().to_le_bytes());
        encoded.extend_from_slice(&offset.to_le_bytes());
        encoded.extend_from_slice(
            &u32::try_from(bytes.len())
                .expect("test response byte length fits u32")
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&0_u32.to_le_bytes());
        encoded.extend_from_slice(&external_memory_read_digest(
            &request_digest,
            *operation_index,
            *object,
            *offset,
            bytes,
        ));
        encoded.extend_from_slice(bytes);
    }
    encoded
}

#[test]
fn worker_response_decoder_binds_sequence_operation_object_range_and_digest() {
    let mut recorder = ProofExternalMemoryTransactionRecorder::for_runtime_binding([0x41; 64], 7);
    let request = record_worker_response_test_request(&mut recorder);
    let first_read_object = ProofExternalMemoryObject::new(7);
    let second_read_object = ProofExternalMemoryObject::new(9);
    let ordered_results = [
        (1, first_read_object, 3, &[1, 2, 3, 4][..]),
        (3, second_read_object, 11, &[5, 6, 7][..]),
    ];
    let valid_response = encode_worker_test_response(&request, &ordered_results);
    let decoded_results = request
        .decode_worker_response(&valid_response)
        .expect("exact worker response decodes");
    assert_eq!(
        decoded_results
            .iter()
            .map(|bytes| bytes.as_slice())
            .collect::<Vec<_>>(),
        vec![&[1, 2, 3, 4][..], &[5, 6, 7][..]],
    );

    let mut wrong_sequence = valid_response.clone();
    wrong_sequence[4] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_sequence),
        Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
    );

    let mut wrong_request_digest = valid_response.clone();
    wrong_request_digest[12] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_request_digest),
        Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
    );

    let first_result_offset = EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH;
    let mut wrong_operation_ordinal = valid_response.clone();
    wrong_operation_ordinal[first_result_offset] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_operation_ordinal),
        Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
    );

    let mut wrong_object = valid_response.clone();
    wrong_object[first_result_offset + 4] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_object),
        Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
    );

    let mut wrong_range = valid_response.clone();
    wrong_range[first_result_offset + 8] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_range),
        Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
    );

    let mut wrong_read_digest = valid_response.clone();
    wrong_read_digest[first_result_offset + 24] ^= 1;
    assert_eq!(
        request.decode_worker_response(&wrong_read_digest),
        Err(ProofExternalMemoryTransactionAdapterError::WrongReadDigest),
    );

    let reordered_response = encode_worker_test_response(
        &request,
        &[
            (3, second_read_object, 11, &[5, 6, 7]),
            (1, first_read_object, 3, &[1, 2, 3, 4]),
        ],
    );
    assert_eq!(
        request.decode_worker_response(&reordered_response),
        Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
    );

    let next_request = record_worker_response_test_request(&mut recorder);
    assert_eq!(next_request.request_sequence(), 8);
    assert_eq!(
        next_request.decode_worker_response(&valid_response),
        Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
    );
}

#[test]
fn browser_transaction_boundary_enforces_both_safety_bounds_and_redacts_payloads() {
    let object = ProofExternalMemoryObject::new(7);
    let mut recorder = ProofExternalMemoryTransactionRecorder::new();
    recorder
        .begin_transaction(4, 1)
        .expect("bounded transaction starts");
    recorder
        .append_object_bytes(object, 0, &[0x11, 0x22, 0x33, 0x44])
        .expect("payload at the exact ceiling is accepted");
    assert_eq!(
        recorder.seal_object(object),
        Err(ProofExternalMemoryTransactionAdapterError::OperationCountExceeded),
    );
    recorder
        .abort_transaction()
        .expect("rejected transaction aborts");

    recorder
        .begin_transaction(3, 2)
        .expect("second bounded transaction starts");
    assert_eq!(
        recorder.append_object_bytes(object, 0, &[0x11, 0x22, 0x33, 0x44]),
        Err(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded),
    );
    recorder
        .abort_transaction()
        .expect("overlong payload transaction aborts");

    recorder
        .begin_transaction(3, 1)
        .expect("bounded read transaction starts");
    let mut oversized_read = [0xff; 4];
    assert_eq!(
        recorder.read_object_bytes(object, 0, &mut oversized_read),
        Err(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded),
    );
    assert_eq!(oversized_read, [0; 4]);
    recorder
        .abort_transaction()
        .expect("overlong read transaction aborts");

    let operation = ProofExternalMemoryTransactionOperation::Append {
        object,
        expected_offset: 0,
        bytes: Zeroizing::new(vec![0xde, 0xad, 0xbe, 0xef]),
    };
    let debug_output = format!("{operation:?}");
    assert!(debug_output.contains("[REDACTED]"));
    assert!(debug_output.contains("byte_length: 4"));
}

#[test]
fn cancellation_transactionally_removes_secret_scratch() {
    let first = ProofExternalMemoryObject::new(0);
    let mut executor = ProofExternalMemoryExecutor::new(plan());
    let mut storage = TestStorage::default();
    executor
        .begin_object(&mut storage, first)
        .expect("first starts");
    executor
        .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
        .expect("partial secret scratch writes");
    executor
        .cancel(&mut storage)
        .expect("cancellation removes every live object");
    assert!(storage.committed.is_empty());
}

#[test]
fn cancellation_deletes_sorted_unique_live_objects_once_and_remains_idempotent() {
    let reusable_object = ProofExternalMemoryObject::new(7);
    let concurrent_object = ProofExternalMemoryObject::new(3);
    let cancellation_plan = ProofExternalMemoryPlan::new(
        3,
        4,
        4,
        2,
        8,
        12,
        1,
        16,
        vec![
            ProofExternalMemoryObjectPlan::new(
                reusable_object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                4,
                2,
                2,
                2,
            ),
            ProofExternalMemoryObjectPlan::new(
                reusable_object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                4,
                0,
                0,
                1,
            ),
            ProofExternalMemoryObjectPlan::new(
                concurrent_object,
                ProofExternalMemoryProtection::PublicIntegrity,
                4,
                0,
                0,
                1,
            ),
        ],
    )
    .expect("the future lifecycle does not overlap the live lifecycle");
    let mut executor = ProofExternalMemoryExecutor::new(cancellation_plan);
    let mut storage = TestStorage::default();

    for (object, bytes) in [
        (reusable_object, [1_u8, 2, 3, 4]),
        (concurrent_object, [5_u8, 6, 7, 8]),
    ] {
        executor
            .begin_object(&mut storage, object)
            .expect("the current lifecycle starts");
        executor
            .append_object_bytes(&mut storage, object, &bytes)
            .expect("the current lifecycle writes");
        executor
            .seal_object(&mut storage, object)
            .expect("the current lifecycle seals");
    }
    let begun_transaction_count_before_cancel = storage.begun_transaction_count;
    let committed_transaction_count_before_cancel = storage.committed_transaction_count;

    executor
        .cancel(&mut storage)
        .expect("cancellation deletes each live physical object");
    assert_eq!(
        storage.deleted_objects,
        vec![concurrent_object, reusable_object],
        "the executor plan order provides a sorted, deduplicated cancellation batch",
    );
    assert_eq!(
        storage.begun_transaction_count,
        begun_transaction_count_before_cancel + 1,
    );
    assert_eq!(
        storage.committed_transaction_count,
        committed_transaction_count_before_cancel + 1,
    );
    assert!(storage.committed.is_empty());

    executor
        .cancel(&mut storage)
        .expect("a completed cancellation is idempotent");
    assert_eq!(
        storage.deleted_objects,
        vec![concurrent_object, reusable_object],
    );
    assert_eq!(
        storage.begun_transaction_count,
        begun_transaction_count_before_cancel + 1,
    );
    assert_eq!(
        storage.committed_transaction_count,
        committed_transaction_count_before_cancel + 1,
    );
}
