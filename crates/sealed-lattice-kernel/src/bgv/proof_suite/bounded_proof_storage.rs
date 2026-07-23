//! Backend-neutral bounded storage used by proof-backend preflights.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use super::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    external_memory::{
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BoundedProofStorageObjectHandle(usize);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BoundedProofStorageUsage {
    pub(super) total_read_byte_length: u64,
    pub(super) total_written_byte_length: u64,
    pub(super) transaction_count: u64,
    pub(super) created_object_count: u32,
    pub(super) deleted_object_count: u32,
    pub(super) active_object_count: u32,
    pub(super) peak_active_object_count: u32,
    pub(super) active_stored_byte_length: u64,
    pub(super) peak_stored_byte_length: u64,
    pub(super) cleanup_complete: bool,
}

#[derive(Debug)]
struct BoundedProofStorageObject {
    path: PathBuf,
    byte_length: u64,
    sealed: bool,
    present: bool,
}

#[derive(Debug)]
pub(super) struct BoundedProofStorageCustody {
    directory_path: PathBuf,
    objects: Vec<BoundedProofStorageObject>,
    usage: BoundedProofStorageUsage,
    finished: bool,
}

impl BoundedProofStorageCustody {
    pub(super) fn new(directory_path: PathBuf) -> Result<Self, String> {
        if !directory_path.is_absolute() || directory_path.exists() {
            return Err("bounded proof storage directory must be a new absolute path".to_owned());
        }
        fs::create_dir(&directory_path)
            .map_err(|error| format!("create bounded proof storage directory: {error}"))?;
        Ok(Self {
            directory_path,
            objects: Vec::new(),
            usage: BoundedProofStorageUsage::default(),
            finished: false,
        })
    }

    pub(super) fn create_object(
        &mut self,
        object_name: &str,
    ) -> Result<BoundedProofStorageObjectHandle, String> {
        self.require_active()?;
        validate_object_name(object_name)?;
        if self.objects.len() >= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT {
            return Err("bounded proof storage object cap would be exceeded".to_owned());
        }
        let object_path = self.directory_path.join(object_name);
        if self.objects.iter().any(|object| object.path == object_path) {
            return Err("bounded proof storage object name is duplicated".to_owned());
        }
        let next_created_object_count = self
            .usage
            .created_object_count
            .checked_add(1)
            .ok_or_else(|| "bounded proof storage created-object count overflowed".to_owned())?;
        let next_active_object_count = self
            .usage
            .active_object_count
            .checked_add(1)
            .ok_or_else(|| "bounded proof storage active-object count overflowed".to_owned())?;
        let next_transaction_count = self
            .usage
            .transaction_count
            .checked_add(1)
            .ok_or_else(|| "bounded proof storage transaction count overflowed".to_owned())?;
        File::options()
            .write(true)
            .create_new(true)
            .open(&object_path)
            .map_err(|error| format!("create bounded proof storage object: {error}"))?;

        self.usage.created_object_count = next_created_object_count;
        self.usage.active_object_count = next_active_object_count;
        self.usage.peak_active_object_count = self
            .usage
            .peak_active_object_count
            .max(next_active_object_count);
        self.usage.transaction_count = next_transaction_count;
        self.objects.push(BoundedProofStorageObject {
            path: object_path,
            byte_length: 0,
            sealed: false,
            present: true,
        });
        Ok(BoundedProofStorageObjectHandle(self.objects.len() - 1))
    }

    pub(super) fn append_object(
        &mut self,
        object_handle: BoundedProofStorageObjectHandle,
        bytes: &[u8],
    ) -> Result<(), String> {
        self.require_active()?;
        if bytes.is_empty() {
            return Err("bounded proof storage append must be nonempty".to_owned());
        }
        let object = self.object(object_handle)?;
        if !object.present || object.sealed {
            return Err("bounded proof storage object is unavailable for append".to_owned());
        }
        let added_byte_length = u64::try_from(bytes.len())
            .map_err(|_| "bounded proof storage append length does not fit u64".to_owned())?;
        let next_object_byte_length = object
            .byte_length
            .checked_add(added_byte_length)
            .ok_or_else(|| "bounded proof storage object length overflowed".to_owned())?;
        let next_active_stored_byte_length = self
            .usage
            .active_stored_byte_length
            .checked_add(added_byte_length)
            .ok_or_else(|| "bounded proof storage active byte length overflowed".to_owned())?;
        if next_active_stored_byte_length > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        {
            return Err("bounded proof storage byte cap would be exceeded".to_owned());
        }
        let chunk_count = exact_chunk_count(bytes.len())?;
        self.usage
            .transaction_count
            .checked_add(chunk_count)
            .ok_or_else(|| "bounded proof storage transaction count overflowed".to_owned())?;
        self.usage
            .total_written_byte_length
            .checked_add(added_byte_length)
            .ok_or_else(|| "bounded proof storage written-byte count overflowed".to_owned())?;
        let chunk_byte_length =
            usize::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
                .map_err(|_| "bounded proof storage chunk length does not fit usize".to_owned())?;

        let object_path = object.path.clone();
        let mut object_file = OpenOptions::new()
            .append(true)
            .open(object_path)
            .map_err(|error| format!("open bounded proof storage object for append: {error}"))?;
        for chunk in bytes.chunks(chunk_byte_length) {
            object_file
                .write_all(chunk)
                .map_err(|error| format!("append bounded proof storage object range: {error}"))?;
            let chunk_byte_length = u64::try_from(chunk.len())
                .map_err(|_| "bounded proof storage chunk length does not fit u64".to_owned())?;
            self.usage.total_written_byte_length += chunk_byte_length;
            self.usage.active_stored_byte_length += chunk_byte_length;
            self.usage.transaction_count += 1;
            self.object_mut(object_handle)?.byte_length += chunk_byte_length;
        }
        debug_assert_eq!(
            self.object(object_handle)?.byte_length,
            next_object_byte_length
        );
        debug_assert_eq!(
            self.usage.active_stored_byte_length,
            next_active_stored_byte_length
        );
        self.usage.peak_stored_byte_length = self
            .usage
            .peak_stored_byte_length
            .max(self.usage.active_stored_byte_length);
        Ok(())
    }

    pub(super) fn seal_object(
        &mut self,
        object_handle: BoundedProofStorageObjectHandle,
    ) -> Result<(), String> {
        self.require_active()?;
        let object = self.object(object_handle)?;
        if !object.present || object.sealed || object.byte_length == 0 {
            return Err("bounded proof storage object cannot be sealed".to_owned());
        }
        let next_transaction_count = self
            .usage
            .transaction_count
            .checked_add(1)
            .ok_or_else(|| "bounded proof storage transaction count overflowed".to_owned())?;
        let object_path = object.path.clone();
        let expected_byte_length = object.byte_length;
        let object_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(object_path)
            .map_err(|error| format!("open bounded proof storage object for sealing: {error}"))?;
        object_file
            .sync_all()
            .map_err(|error| format!("durably seal bounded proof storage object: {error}"))?;
        if object_file
            .metadata()
            .map_err(|error| format!("inspect bounded proof storage object: {error}"))?
            .len()
            != expected_byte_length
        {
            return Err("bounded proof storage object length changed before seal".to_owned());
        }
        self.object_mut(object_handle)?.sealed = true;
        self.usage.transaction_count = next_transaction_count;
        Ok(())
    }

    pub(super) fn object_byte_length(
        &self,
        object_handle: BoundedProofStorageObjectHandle,
    ) -> Result<u64, String> {
        let object = self.object(object_handle)?;
        if !object.present || !object.sealed {
            return Err("bounded proof storage object is unavailable for inspection".to_owned());
        }
        Ok(object.byte_length)
    }

    pub(super) fn read_object_range(
        &mut self,
        object_handle: BoundedProofStorageObjectHandle,
        start_byte_offset: u64,
        exact_byte_length: usize,
    ) -> Result<Vec<u8>, String> {
        self.require_active()?;
        if exact_byte_length == 0 {
            return Err("bounded proof storage read must be nonempty".to_owned());
        }
        let read_byte_length = u64::try_from(exact_byte_length)
            .map_err(|_| "bounded proof storage read length does not fit u64".to_owned())?;
        let object = self.object(object_handle)?;
        if !object.present || !object.sealed {
            return Err("bounded proof storage object is unavailable for read".to_owned());
        }
        let end_byte_offset = start_byte_offset
            .checked_add(read_byte_length)
            .ok_or_else(|| "bounded proof storage read boundary overflowed".to_owned())?;
        if end_byte_offset > object.byte_length {
            return Err("bounded proof storage read exceeds the object boundary".to_owned());
        }
        let chunk_count = exact_chunk_count(exact_byte_length)?;
        self.usage
            .transaction_count
            .checked_add(chunk_count)
            .ok_or_else(|| "bounded proof storage transaction count overflowed".to_owned())?;
        self.usage
            .total_read_byte_length
            .checked_add(read_byte_length)
            .ok_or_else(|| "bounded proof storage read-byte count overflowed".to_owned())?;
        let chunk_byte_length =
            usize::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
                .map_err(|_| "bounded proof storage chunk length does not fit usize".to_owned())?;

        let object_path = object.path.clone();
        let mut object_file = File::open(object_path)
            .map_err(|error| format!("open bounded proof storage object for read: {error}"))?;
        object_file
            .seek(SeekFrom::Start(start_byte_offset))
            .map_err(|error| format!("seek bounded proof storage object: {error}"))?;
        let mut bytes = vec![0_u8; exact_byte_length];
        for chunk in bytes.chunks_mut(chunk_byte_length) {
            object_file
                .read_exact(chunk)
                .map_err(|error| format!("read bounded proof storage object range: {error}"))?;
            let chunk_byte_length = u64::try_from(chunk.len())
                .map_err(|_| "bounded proof storage chunk length does not fit u64".to_owned())?;
            self.usage.total_read_byte_length += chunk_byte_length;
            self.usage.transaction_count += 1;
        }
        Ok(bytes)
    }

    pub(super) fn read_complete_object(
        &mut self,
        object_handle: BoundedProofStorageObjectHandle,
    ) -> Result<Vec<u8>, String> {
        let exact_byte_length = usize::try_from(self.object_byte_length(object_handle)?)
            .map_err(|_| "bounded proof storage object length does not fit usize".to_owned())?;
        self.read_object_range(object_handle, 0, exact_byte_length)
    }

    pub(super) fn usage(&self) -> BoundedProofStorageUsage {
        self.usage
    }

    pub(super) fn finish(&mut self) -> Result<BoundedProofStorageUsage, String> {
        self.require_active()?;
        self.usage
            .transaction_count
            .checked_add(u64::from(self.usage.active_object_count))
            .ok_or_else(|| {
                "bounded proof storage transaction count would overflow during cleanup".to_owned()
            })?;
        self.usage
            .deleted_object_count
            .checked_add(self.usage.active_object_count)
            .ok_or_else(|| {
                "bounded proof storage deleted-object count would overflow during cleanup"
                    .to_owned()
            })?;

        let mut first_error = None;
        for object in &mut self.objects {
            if !object.present {
                continue;
            }
            match fs::remove_file(&object.path) {
                Ok(()) => {
                    object.present = false;
                    self.usage.transaction_count += 1;
                    self.usage.deleted_object_count += 1;
                    self.usage.active_object_count -= 1;
                    self.usage.active_stored_byte_length -= object.byte_length;
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(format!(
                            "remove bounded proof storage object {}: {error}",
                            object.path.display()
                        ));
                    }
                }
            }
        }
        if let Err(error) = fs::remove_dir(&self.directory_path)
            && first_error.is_none()
        {
            first_error = Some(format!(
                "remove bounded proof storage directory {}: {error}",
                self.directory_path.display()
            ));
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if self.usage.active_object_count != 0 || self.usage.active_stored_byte_length != 0 {
            return Err(
                "bounded proof storage cleanup accounting retained active custody".to_owned(),
            );
        }
        self.finished = true;
        self.usage.cleanup_complete = true;
        Ok(self.usage)
    }

    fn require_active(&self) -> Result<(), String> {
        if self.finished {
            Err("bounded proof storage custody was already released".to_owned())
        } else {
            Ok(())
        }
    }

    fn object(
        &self,
        object_handle: BoundedProofStorageObjectHandle,
    ) -> Result<&BoundedProofStorageObject, String> {
        self.objects
            .get(object_handle.0)
            .ok_or_else(|| "bounded proof storage object handle is invalid".to_owned())
    }

    fn object_mut(
        &mut self,
        object_handle: BoundedProofStorageObjectHandle,
    ) -> Result<&mut BoundedProofStorageObject, String> {
        self.objects
            .get_mut(object_handle.0)
            .ok_or_else(|| "bounded proof storage object handle is invalid".to_owned())
    }
}

impl Drop for BoundedProofStorageCustody {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        for object in &self.objects {
            if object.present {
                let _ = fs::remove_file(&object.path);
            }
        }
        let _ = fs::remove_dir(&self.directory_path);
    }
}

fn validate_object_name(object_name: &str) -> Result<(), String> {
    let mut components = Path::new(object_name).components();
    if object_name.is_empty()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(
            "bounded proof storage object name must be one normal path component".to_owned(),
        );
    }
    Ok(())
}

fn exact_chunk_count(exact_byte_length: usize) -> Result<u64, String> {
    let exact_byte_length = u64::try_from(exact_byte_length)
        .map_err(|_| "bounded proof storage byte length does not fit u64".to_owned())?;
    let chunk_byte_length = u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
    exact_byte_length
        .checked_add(chunk_byte_length - 1)
        .and_then(|rounded| rounded.checked_div(chunk_byte_length))
        .filter(|count| *count != 0)
        .ok_or_else(|| "bounded proof storage chunk count overflowed".to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn unique_test_directory(label: &str) -> PathBuf {
        let scratch_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("temp");
        fs::create_dir_all(&scratch_root).expect("create repository-local scratch directory");
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        scratch_root.join(format!(
            "bounded-proof-storage-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn bounded_storage_counts_exact_chunked_round_trip_and_cleanup() {
        let directory_path = unique_test_directory("round-trip");
        let mut custody =
            BoundedProofStorageCustody::new(directory_path.clone()).expect("create custody");
        let object = custody.create_object("proof.bin").expect("create object");
        let bytes = vec![
            7_u8;
            usize::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
                .expect("chunk length fits usize")
                + 1
        ];
        custody
            .append_object(object, &bytes)
            .expect("append object");
        custody.seal_object(object).expect("seal object");
        assert_eq!(
            custody.read_complete_object(object).expect("read object"),
            bytes
        );
        let before_cleanup = custody.usage();
        assert_eq!(before_cleanup.total_written_byte_length, bytes.len() as u64);
        assert_eq!(before_cleanup.total_read_byte_length, bytes.len() as u64);
        assert_eq!(before_cleanup.transaction_count, 6);
        assert_eq!(before_cleanup.created_object_count, 1);
        assert_eq!(before_cleanup.peak_active_object_count, 1);
        assert_eq!(before_cleanup.peak_stored_byte_length, bytes.len() as u64);
        assert!(!before_cleanup.cleanup_complete);

        let completed = custody.finish().expect("finish custody");
        assert_eq!(completed.transaction_count, 7);
        assert_eq!(completed.deleted_object_count, 1);
        assert_eq!(completed.active_object_count, 0);
        assert_eq!(completed.active_stored_byte_length, 0);
        assert!(completed.cleanup_complete);
        assert!(!directory_path.exists());
    }

    #[test]
    fn bounded_storage_refuses_unsealed_reads_and_path_traversal() {
        let directory_path = unique_test_directory("refusal");
        let mut custody =
            BoundedProofStorageCustody::new(directory_path.clone()).expect("create custody");
        assert!(custody.create_object("../proof.bin").is_err());
        let object = custody.create_object("proof.bin").expect("create object");
        custody
            .append_object(object, &[1, 2, 3])
            .expect("append object");
        assert!(custody.read_complete_object(object).is_err());
        custody.seal_object(object).expect("seal object");
        assert!(custody.read_object_range(object, 2, 2).is_err());
        custody.finish().expect("finish custody");
        assert!(!directory_path.exists());
    }

    #[test]
    fn bounded_storage_cleanup_attempts_every_object_after_a_failure() {
        let directory_path = unique_test_directory("cleanup-failure");
        let mut custody =
            BoundedProofStorageCustody::new(directory_path.clone()).expect("create custody");
        let first = custody
            .create_object("first.bin")
            .expect("create first object");
        let second = custody
            .create_object("second.bin")
            .expect("create second object");
        custody
            .append_object(first, &[1])
            .expect("append first object");
        custody.seal_object(first).expect("seal first object");
        custody
            .append_object(second, &[2])
            .expect("append second object");
        custody.seal_object(second).expect("seal second object");
        fs::remove_file(custody.object(first).expect("first object").path.clone())
            .expect("inject missing first object");
        let second_path = custody.object(second).expect("second object").path.clone();

        assert!(custody.finish().is_err());
        assert!(!second_path.exists());
        assert_eq!(custody.usage().deleted_object_count, 1);
        assert_eq!(custody.usage().active_object_count, 1);
        drop(custody);
        assert!(!directory_path.exists());
    }
}
