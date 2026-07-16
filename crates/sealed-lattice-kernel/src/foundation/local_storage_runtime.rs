use std::cell::RefCell;
use std::collections::HashSet;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::local_encrypted_storage::LocalRecordSealWithIdentifierInput;
use super::runtime_input::RuntimeInputReader as InputReader;
use super::{
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionStorageRoot, CanonicalDecodeLimits,
    CommonProofExternalMemoryRecordKind, DeviceWrappedStorageRoot, Hash512,
    LOCAL_RECORD_NONCE_BYTE_LENGTH, LocalRecordEnvelope, LocalRecordIdentifierInput,
    LocalRecordType, LocalStorageBinding, ParticipantIdentity, RefusalReason,
    StorageRootCommitmentPayload, derive_local_record_envelope_hash,
    derive_local_record_identifier,
};

pub(crate) const LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW: u32 = 1;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_STAGE_OPENED: u32 = 2;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA: u32 = 4;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_COPY_FOR_DEVICE_WRAP: u32 = 5;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_ENCODE_DEVICE_ENVELOPE: u32 = 6;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DECODE_DEVICE_ENVELOPE: u32 = 7;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_COMMIT: u32 = 8;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DISCARD: u32 = 9;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DESTROY: u32 = 10;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_RESET: u32 = 13;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER: u32 = 14;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD: u32 = 15;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_OPEN_RECORD: u32 = 16;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_HASH_RECORD_ENVELOPE: u32 = 17;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DERIVE_REPAIR_IDENTITY: u32 = 18;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_SEAL_REPAIR_HEAD: u32 = 19;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_OPEN_REPAIR_HEAD: u32 = 20;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DIGEST_REPAIR_HEAD: u32 = 21;

pub(crate) const LOCAL_STORAGE_ROOT_STATUS_RESOURCE_LIMIT: u32 = 0x0001_0000;
pub(crate) const LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE: u32 = 0x0001_0001;
pub(crate) const LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH: u32 = 0x0001_0002;
const HASH_BYTE_LENGTH: usize = 64;
const COMMON_PROOF_EXTERNAL_MEMORY_IDENTIFIER_CONTEXT_BYTE_LENGTH: usize = 32
    + HASH_BYTE_LENGTH
    + 32
    + core::mem::size_of::<u16>()
    + core::mem::size_of::<u32>() * 2
    + core::mem::size_of::<u64>();
#[cfg(test)]
const BINDING_BYTE_LENGTH: usize = HASH_BYTE_LENGTH * 4;
const HANDLE_BYTE_LENGTH: usize = 4;
const MAXIMUM_CHECKPOINT_SOURCE_DIGEST_COUNT: usize = 4_096;
const MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT: u64 = 1 << 30;
const MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT: u64 = 1 << 40;

/// Opaque storage coordinate minted only inside the browser worker after the
/// authenticated store has re-read its current head and the local storage-root
/// registry has accepted the worker-private lease capability. Downstream
/// runtimes consume this source instead of caller-provided head coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BrowserWorkerAuthenticatedStorageHeadSource {
    local_storage_binding: LocalStorageBinding,
    storage_root_commitment: Hash512,
    namespace_sequence: u64,
    authenticated_head_digest: Hash512,
    storage_instance_identity: Hash512,
}

impl BrowserWorkerAuthenticatedStorageHeadSource {
    #[cfg(test)]
    pub(crate) const fn from_test_fixture(
        local_storage_binding: LocalStorageBinding,
        storage_root_commitment: Hash512,
        namespace_sequence: u64,
        authenticated_head_digest: Hash512,
        storage_instance_identity: Hash512,
    ) -> Self {
        Self {
            local_storage_binding,
            storage_root_commitment,
            namespace_sequence,
            authenticated_head_digest,
            storage_instance_identity,
        }
    }

    pub(crate) const fn local_storage_binding(&self) -> LocalStorageBinding {
        self.local_storage_binding
    }

    pub(crate) const fn storage_root_commitment(&self) -> Hash512 {
        self.storage_root_commitment
    }

    pub(crate) const fn namespace_sequence(&self) -> u64 {
        self.namespace_sequence
    }

    pub(crate) const fn authenticated_head_digest(&self) -> Hash512 {
        self.authenticated_head_digest
    }

    pub(crate) const fn storage_instance_identity(&self) -> Hash512 {
        self.storage_instance_identity
    }
}

/// Opaque result of one browser-owned compare-and-apply transaction followed
/// by authenticated exact-record readback. This value must remain impossible
/// to construct from a caller-selected outcome or from a head alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BrowserWorkerAuthenticatedStorageTransitionSource {
    local_storage_binding: LocalStorageBinding,
    storage_root_commitment: Hash512,
    predecessor_namespace_sequence: u64,
    predecessor_authenticated_head_digest: Hash512,
    successor_namespace_sequence: u64,
    successor_authenticated_head_digest: Hash512,
    storage_instance_identity: Hash512,
    authenticated_record_digest: Hash512,
}

impl BrowserWorkerAuthenticatedStorageTransitionSource {
    pub(crate) const fn local_storage_binding(&self) -> LocalStorageBinding {
        self.local_storage_binding
    }

    pub(crate) const fn storage_root_commitment(&self) -> Hash512 {
        self.storage_root_commitment
    }

    pub(crate) const fn predecessor_namespace_sequence(&self) -> u64 {
        self.predecessor_namespace_sequence
    }

    pub(crate) const fn predecessor_authenticated_head_digest(&self) -> Hash512 {
        self.predecessor_authenticated_head_digest
    }

    pub(crate) const fn successor_namespace_sequence(&self) -> u64 {
        self.successor_namespace_sequence
    }

    pub(crate) const fn successor_authenticated_head_digest(&self) -> Hash512 {
        self.successor_authenticated_head_digest
    }

    pub(crate) const fn storage_instance_identity(&self) -> Hash512 {
        self.storage_instance_identity
    }

    pub(crate) const fn authenticated_record_digest(&self) -> Hash512 {
        self.authenticated_record_digest
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_test_fixture(
        local_storage_binding: LocalStorageBinding,
        storage_root_commitment: Hash512,
        predecessor_namespace_sequence: u64,
        predecessor_authenticated_head_digest: Hash512,
        successor_namespace_sequence: u64,
        successor_authenticated_head_digest: Hash512,
        storage_instance_identity: Hash512,
        authenticated_record_digest: Hash512,
    ) -> Self {
        Self {
            local_storage_binding,
            storage_root_commitment,
            predecessor_namespace_sequence,
            predecessor_authenticated_head_digest,
            successor_namespace_sequence,
            successor_authenticated_head_digest,
            storage_instance_identity,
            authenticated_record_digest,
        }
    }
}

struct RootLease {
    capability: Zeroizing<[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH]>,
    handle: u32,
    local_record_seal_invocation_count: u64,
    local_record_sealed_plaintext_byte_length: u64,
    root: ActionStorageRoot,
    sealed_record_versions: HashSet<([u8; HASH_BYTE_LENGTH], u64)>,
}

#[derive(Default)]
struct RootRegistry {
    active: Option<RootLease>,
    next_handle: u32,
    staged: Option<RootLease>,
}

impl RootRegistry {
    fn allocate_handle(&mut self) -> RuntimeResult<u32> {
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(LOCAL_STORAGE_ROOT_STATUS_RESOURCE_LIMIT)?;
        Ok(self.next_handle)
    }

    fn stage(
        &mut self,
        capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
        root: ActionStorageRoot,
    ) -> RuntimeResult<u32> {
        if self.staged.is_some() {
            return Err(LOCAL_STORAGE_ROOT_STATUS_RESOURCE_LIMIT);
        }
        if capability.iter().all(|byte| *byte == 0) {
            return Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH);
        }
        let handle = self.allocate_handle()?;
        self.staged = Some(RootLease {
            capability: Zeroizing::new(capability),
            handle,
            local_record_seal_invocation_count: 0,
            local_record_sealed_plaintext_byte_length: 0,
            root,
            sealed_record_versions: HashSet::new(),
        });
        Ok(handle)
    }

    fn staged(&self, handle: u32, capability: &[u8]) -> RuntimeResult<&RootLease> {
        require_lease(self.staged.as_ref(), handle, capability)
    }

    fn active(&self, handle: u32, capability: &[u8]) -> RuntimeResult<&RootLease> {
        require_lease(self.active.as_ref(), handle, capability)
    }

    fn active_mut(&mut self, handle: u32, capability: &[u8]) -> RuntimeResult<&mut RootLease> {
        require_lease_mut(self.active.as_mut(), handle, capability)
    }

    fn commit(&mut self, handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        require_lease(self.staged.as_ref(), handle, capability)?;
        let staged = self
            .staged
            .take()
            .ok_or(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)?;
        self.active = Some(staged);
        Ok(())
    }

    fn discard(&mut self, handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        require_lease(self.staged.as_ref(), handle, capability)?;
        self.staged = None;
        Ok(())
    }

    fn destroy(&mut self, handle: u32, capability: &[u8]) -> RuntimeResult<()> {
        require_lease(self.active.as_ref(), handle, capability)?;
        self.active = None;
        Ok(())
    }

    fn reset(&mut self) {
        self.staged = None;
        self.active = None;
    }
}

type RuntimeResult<Value> = Result<Value, u32>;

thread_local! {
    static ROOT_REGISTRY: RefCell<RootRegistry> = RefCell::new(RootRegistry::default());
}

/// Joins a freshly authenticated browser-store head to the active local
/// storage root. The opaque storage-root capability never leaves the worker;
/// callers outside that worker therefore cannot mint this source from copied
/// coordinates.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_browser_worker_authenticated_storage_head_source(
    storage_root_handle: u32,
    storage_root_capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    namespace_sequence: u64,
    authenticated_head_digest: Hash512,
    storage_instance_identity: Hash512,
) -> RuntimeResult<BrowserWorkerAuthenticatedStorageHeadSource> {
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(storage_root_handle, storage_root_capability)?;
        Ok(BrowserWorkerAuthenticatedStorageHeadSource {
            local_storage_binding: lease.root.binding(),
            storage_root_commitment: lease.root.storage_root_commitment(),
            namespace_sequence,
            authenticated_head_digest,
            storage_instance_identity,
        })
    })
}

/// Joins one authenticated browser-store compare-and-apply result to the
/// active local storage root. The opaque storage-root capability stays inside
/// the worker, so copied transition coordinates cannot mint this source in a
/// different worker or after the root lease is destroyed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_browser_worker_authenticated_storage_transition_source(
    storage_root_handle: u32,
    storage_root_capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    predecessor_namespace_sequence: u64,
    predecessor_authenticated_head_digest: Hash512,
    successor_namespace_sequence: u64,
    successor_authenticated_head_digest: Hash512,
    storage_instance_identity: Hash512,
    authenticated_record_digest: Hash512,
) -> RuntimeResult<BrowserWorkerAuthenticatedStorageTransitionSource> {
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(storage_root_handle, storage_root_capability)?;
        if predecessor_namespace_sequence.checked_add(1) != Some(successor_namespace_sequence) {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        Ok(BrowserWorkerAuthenticatedStorageTransitionSource {
            local_storage_binding: lease.root.binding(),
            storage_root_commitment: lease.root.storage_root_commitment(),
            predecessor_namespace_sequence,
            predecessor_authenticated_head_digest,
            successor_namespace_sequence,
            successor_authenticated_head_digest,
            storage_instance_identity,
            authenticated_record_digest,
        })
    })
}

pub(crate) fn run_local_storage_root_command(command: u32, input: &[u8]) -> RuntimeResult<Vec<u8>> {
    match command {
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW => stage_new(input),
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_OPENED => stage_opened(input),
        LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA => associated_data(input),
        LOCAL_STORAGE_ROOT_COMMAND_COPY_FOR_DEVICE_WRAP => copy_for_device_wrap(input),
        LOCAL_STORAGE_ROOT_COMMAND_ENCODE_DEVICE_ENVELOPE => encode_device_envelope(input),
        LOCAL_STORAGE_ROOT_COMMAND_DECODE_DEVICE_ENVELOPE => decode_device_envelope(input),
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT => commit(input),
        LOCAL_STORAGE_ROOT_COMMAND_DISCARD => discard(input),
        LOCAL_STORAGE_ROOT_COMMAND_DESTROY => destroy(input),
        LOCAL_STORAGE_ROOT_COMMAND_RESET => reset(input),
        LOCAL_STORAGE_ROOT_COMMAND_DERIVE_RECORD_IDENTIFIER => derive_record_identifier(input),
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_RECORD => seal_record(input),
        LOCAL_STORAGE_ROOT_COMMAND_OPEN_RECORD => open_record(input),
        LOCAL_STORAGE_ROOT_COMMAND_HASH_RECORD_ENVELOPE => hash_record_envelope(input),
        LOCAL_STORAGE_ROOT_COMMAND_DERIVE_REPAIR_IDENTITY => derive_repair_identity(input),
        LOCAL_STORAGE_ROOT_COMMAND_SEAL_REPAIR_HEAD => seal_repair_head(input),
        LOCAL_STORAGE_ROOT_COMMAND_OPEN_REPAIR_HEAD => open_repair_head(input),
        LOCAL_STORAGE_ROOT_COMMAND_DIGEST_REPAIR_HEAD => digest_repair_head(input),
        _ => Err(malformed_status()),
    }
}

fn stage_new(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let binding = read_binding(&mut reader)?;
    let root_bytes = Zeroizing::new(reader.read_array()?);
    reader.finish()?;
    let root = ActionStorageRoot::from_verified_root(binding, root_bytes).map_err(schema_status)?;
    stage_root(capability, root)
}

fn stage_opened(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let binding = read_binding(&mut reader)?;
    let expected_commitment = read_commitment(&mut reader)?;
    let root_bytes = Zeroizing::new(reader.read_array()?);
    reader.finish()?;
    let root = ActionStorageRoot::from_verified_root(binding, root_bytes).map_err(schema_status)?;
    if root.storage_root_commitment() != expected_commitment.storage_root_commitment() {
        return Err(refusal_status(RefusalReason::WrongHashOrRoot));
    }
    stage_root(capability, root)
}

fn stage_root(
    capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    root: ActionStorageRoot,
) -> RuntimeResult<Vec<u8>> {
    let commitment = root.storage_root_commitment();
    let handle = ROOT_REGISTRY.with(|registry| registry.borrow_mut().stage(capability, root))?;
    let mut output = Vec::with_capacity(HANDLE_BYTE_LENGTH + HASH_BYTE_LENGTH);
    output.extend_from_slice(&handle.to_le_bytes());
    output.extend_from_slice(commitment.as_bytes());
    Ok(output)
}

fn associated_data(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let (handle, capability) = read_lease_input(input)?;
    ROOT_REGISTRY.with(|registry| {
        registry
            .borrow()
            .staged(handle, &capability)?
            .root
            .device_wrapping_associated_data()
            .encode()
            .map_err(schema_status)
    })
}

fn copy_for_device_wrap(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let (handle, capability) = read_lease_input(input)?;
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.staged(handle, &capability)?;
        Ok(lease.root.root_bytes().to_vec())
    })
}

fn encode_device_envelope(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = u32::from_le_bytes(reader.read_array()?);
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let nonce = reader.read_array()?;
    let ciphertext = reader.read_array()?;
    let tag = reader.read_array()?;
    reader.finish()?;
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.staged(handle, &capability)?;
        DeviceWrappedStorageRoot::new(
            lease.root.device_wrapping_associated_data(),
            nonce,
            ciphertext,
            tag,
        )
        .encode()
        .map_err(schema_status)
    })
}

fn decode_device_envelope(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let binding = read_binding(&mut reader)?;
    let expected_commitment = read_commitment(&mut reader)?;
    let envelope_bytes = reader.read_remaining();
    if envelope_bytes.is_empty() {
        return Err(malformed_status());
    }
    let envelope =
        DeviceWrappedStorageRoot::decode(envelope_bytes, &CanonicalDecodeLimits::default())
            .map_err(schema_status)?;
    let associated_data = envelope.associated_data();
    if associated_data.binding() != binding {
        return Err(refusal_status(RefusalReason::WrongContext));
    }
    if associated_data.storage_root_commitment() != expected_commitment.storage_root_commitment() {
        return Err(refusal_status(RefusalReason::WrongHashOrRoot));
    }
    let canonical_associated_data = associated_data.encode().map_err(schema_status)?;
    let mut output = Vec::with_capacity(4 + canonical_associated_data.len() + 76);
    let associated_data_length = u32::try_from(canonical_associated_data.len())
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    output.extend_from_slice(&associated_data_length.to_le_bytes());
    output.extend_from_slice(&canonical_associated_data);
    output.extend_from_slice(envelope.nonce());
    output.extend_from_slice(envelope.ciphertext());
    output.extend_from_slice(envelope.tag());
    Ok(output)
}

fn commit(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let (handle, capability) = read_lease_input(input)?;
    ROOT_REGISTRY.with(|registry| registry.borrow_mut().commit(handle, &capability))?;
    Ok(Vec::new())
}

fn discard(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let (handle, capability) = read_lease_input(input)?;
    ROOT_REGISTRY.with(|registry| registry.borrow_mut().discard(handle, &capability))?;
    Ok(Vec::new())
}

fn destroy(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let (handle, capability) = read_lease_input(input)?;
    ROOT_REGISTRY.with(|registry| registry.borrow_mut().destroy(handle, &capability))?;
    Ok(Vec::new())
}

fn reset(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    if !input.is_empty() {
        return Err(malformed_status());
    }
    ROOT_REGISTRY.with(|registry| registry.borrow_mut().reset());
    Ok(Vec::new())
}

fn derive_record_identifier(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let record_type = read_record_type(&mut reader)?;
    let identifier_context = reader.read_remaining();
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(handle, &capability)?;
        Ok(derive_record_identifier_from_context(
            lease.root.binding(),
            record_type,
            identifier_context,
        )?
        .as_bytes()
        .to_vec())
    })
}

fn seal_record(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let request = read_record_request(&mut reader)?;
    if request.record_type == LocalRecordType::ActionRandomness {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let nonce = reader.read_array()?;
    let plaintext = reader.read_remaining();
    ROOT_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let lease = registry.active_mut(request.handle, &request.capability)?;
        seal_record_with_active_lease(
            lease,
            request.action_randomness_commitment,
            request.record_type,
            request.identifier_context,
            request.record_version,
            request.predecessor_record_hash,
            nonce,
            plaintext,
        )
    })
}

fn open_record(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let request = read_record_request(&mut reader)?;
    if request.record_type == LocalRecordType::ActionRandomness {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let envelope_bytes = reader.read_remaining();
    if envelope_bytes.is_empty() {
        return Err(malformed_status());
    }
    let envelope = LocalRecordEnvelope::decode(envelope_bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_status)?;
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(request.handle, &request.capability)?;
        open_record_with_active_lease(
            lease,
            request.action_randomness_commitment,
            request.record_type,
            request.identifier_context,
            request.record_version,
            request.predecessor_record_hash,
            &envelope,
        )
        .map(|mut plaintext| core::mem::take(&mut *plaintext))
    })
}

#[allow(clippy::too_many_arguments)]
fn seal_record_with_active_lease(
    lease: &mut RootLease,
    action_randomness_commitment: Hash512,
    record_type: LocalRecordType,
    identifier_context: &[u8],
    record_version: u64,
    predecessor_record_hash: Option<Hash512>,
    nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
    plaintext: &[u8],
) -> RuntimeResult<Vec<u8>> {
    let record_identifier = derive_record_identifier_from_context(
        lease.root.binding(),
        record_type,
        identifier_context,
    )?;
    let record_version_key = (record_identifier.into_bytes(), record_version);
    if lease.sealed_record_versions.contains(&record_version_key) {
        return Err(refusal_status(RefusalReason::ConsumedState));
    }
    let next_seal_invocation_count = lease
        .local_record_seal_invocation_count
        .checked_add(1)
        .ok_or_else(outside_supported_profile_status)?;
    let plaintext_byte_length =
        u64::try_from(plaintext.len()).map_err(|_| outside_supported_profile_status())?;
    let next_sealed_plaintext_byte_length = lease
        .local_record_sealed_plaintext_byte_length
        .checked_add(plaintext_byte_length)
        .ok_or_else(outside_supported_profile_status)?;
    if next_seal_invocation_count > MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT
        || next_sealed_plaintext_byte_length
            > MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT
    {
        return Err(outside_supported_profile_status());
    }
    let envelope = lease
        .root
        .seal_local_record_with_identifier(LocalRecordSealWithIdentifierInput {
            action_randomness_commitment,
            record_type,
            record_identifier,
            record_version,
            predecessor_record_hash,
            nonce,
            plaintext,
        })
        .map_err(schema_status)?;
    let encoded_envelope = envelope.encode().map_err(schema_status)?;
    lease.sealed_record_versions.insert(record_version_key);
    lease.local_record_seal_invocation_count = next_seal_invocation_count;
    lease.local_record_sealed_plaintext_byte_length = next_sealed_plaintext_byte_length;
    Ok(encoded_envelope)
}

#[allow(clippy::too_many_arguments)]
fn open_record_with_active_lease(
    lease: &RootLease,
    action_randomness_commitment: Hash512,
    record_type: LocalRecordType,
    identifier_context: &[u8],
    record_version: u64,
    predecessor_record_hash: Option<Hash512>,
    envelope: &LocalRecordEnvelope,
) -> RuntimeResult<Zeroizing<Vec<u8>>> {
    let record_identifier = derive_record_identifier_from_context(
        lease.root.binding(),
        record_type,
        identifier_context,
    )?;
    lease
        .root
        .open_local_record_with_identifier(
            action_randomness_commitment,
            record_type,
            record_identifier,
            record_version,
            predecessor_record_hash,
            envelope,
        )
        .into_result()
        .map_err(refusal_status)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_action_randomness_root(
    storage_handle: u32,
    storage_capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    expected_binding: LocalStorageBinding,
    action_randomness_commitment: Hash512,
    record_version: u64,
    predecessor_record_hash: Option<Hash512>,
    nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
    action_randomness_root: &[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
) -> RuntimeResult<Vec<u8>> {
    ROOT_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let lease = registry.active_mut(storage_handle, storage_capability)?;
        if lease.root.binding() != expected_binding {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        seal_record_with_active_lease(
            lease,
            action_randomness_commitment,
            LocalRecordType::ActionRandomness,
            &[],
            record_version,
            predecessor_record_hash,
            nonce,
            action_randomness_root,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn open_action_randomness_root(
    storage_handle: u32,
    storage_capability: &[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    expected_binding: LocalStorageBinding,
    action_randomness_commitment: Hash512,
    record_version: u64,
    predecessor_record_hash: Option<Hash512>,
    canonical_envelope: &[u8],
) -> RuntimeResult<Zeroizing<[u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]>> {
    if canonical_envelope.is_empty() {
        return Err(malformed_status());
    }
    let envelope =
        LocalRecordEnvelope::decode(canonical_envelope, &CanonicalDecodeLimits::default())
            .map_err(schema_status)?;
    if envelope.encode().map_err(schema_status)? != canonical_envelope {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(storage_handle, storage_capability)?;
        if lease.root.binding() != expected_binding {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        let plaintext = open_record_with_active_lease(
            lease,
            action_randomness_commitment,
            LocalRecordType::ActionRandomness,
            &[],
            record_version,
            predecessor_record_hash,
            &envelope,
        )?;
        if plaintext.len() != ACTION_RANDOMNESS_ROOT_BYTE_LENGTH {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        let mut root = Zeroizing::new([0u8; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]);
        root.copy_from_slice(plaintext.as_slice());
        Ok(root)
    })
}

fn hash_record_envelope(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let envelope_bytes = reader.read_remaining();
    if envelope_bytes.is_empty() {
        return Err(malformed_status());
    }
    let envelope = LocalRecordEnvelope::decode(envelope_bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_status)?;
    let canonical_envelope = envelope.encode().map_err(schema_status)?;
    if canonical_envelope != envelope_bytes {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    ROOT_REGISTRY.with(|registry| {
        registry.borrow().active(handle, &capability)?;
        Ok(derive_local_record_envelope_hash(&canonical_envelope)
            .map_err(schema_status)?
            .as_bytes()
            .to_vec())
    })
}

struct AuthenticatedRepairRequest<'input> {
    handle: u32,
    capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    runtime_build_manifest_hash: Hash512,
    namespace: &'input [u8],
}

fn read_authenticated_repair_request<'input>(
    reader: &mut InputReader<'input>,
) -> RuntimeResult<AuthenticatedRepairRequest<'input>> {
    let handle = reader.read_u32()?;
    let capability = reader.read_array()?;
    let runtime_build_manifest_hash = Hash512::from_bytes(reader.read_array()?);
    let namespace = reader.read_length_prefixed_bytes()?;
    if namespace.is_empty()
        || namespace.len() > 64
        || !(namespace[0].is_ascii_lowercase() || namespace[0].is_ascii_digit())
        || !namespace
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || namespace.last() == Some(&b'-')
        || namespace.windows(2).any(|pair| pair == b"--")
    {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    Ok(AuthenticatedRepairRequest {
        handle,
        capability,
        runtime_build_manifest_hash,
        namespace,
    })
}

fn derive_repair_identity(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let request = read_authenticated_repair_request(&mut reader)?;
    reader.finish()?;
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(request.handle, &request.capability)?;
        Ok(lease
            .root
            .authenticated_repair_identity(request.runtime_build_manifest_hash, request.namespace)
            .map_err(schema_status)?
            .into_bytes()
            .to_vec())
    })
}

fn seal_repair_head(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let request = read_authenticated_repair_request(&mut reader)?;
    let nonce = reader.read_array()?;
    let plaintext = reader.read_remaining();
    ROOT_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let lease = registry.active_mut(request.handle, &request.capability)?;
        let next_seal_invocation_count = lease
            .local_record_seal_invocation_count
            .checked_add(1)
            .ok_or_else(outside_supported_profile_status)?;
        let plaintext_byte_length =
            u64::try_from(plaintext.len()).map_err(|_| outside_supported_profile_status())?;
        let next_sealed_plaintext_byte_length = lease
            .local_record_sealed_plaintext_byte_length
            .checked_add(plaintext_byte_length)
            .ok_or_else(outside_supported_profile_status)?;
        if next_seal_invocation_count > MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT
            || next_sealed_plaintext_byte_length
                > MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT
        {
            return Err(outside_supported_profile_status());
        }
        let envelope = lease
            .root
            .seal_authenticated_repair_head(
                request.runtime_build_manifest_hash,
                request.namespace,
                nonce,
                plaintext,
            )
            .map_err(schema_status)?;
        lease.local_record_seal_invocation_count = next_seal_invocation_count;
        lease.local_record_sealed_plaintext_byte_length = next_sealed_plaintext_byte_length;
        Ok(envelope)
    })
}

fn open_repair_head(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let request = read_authenticated_repair_request(&mut reader)?;
    let envelope = reader.read_remaining();
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(request.handle, &request.capability)?;
        lease
            .root
            .open_authenticated_repair_head(
                request.runtime_build_manifest_hash,
                request.namespace,
                envelope,
            )
            .into_result()
            .map(|mut plaintext| core::mem::take(&mut *plaintext))
            .map_err(refusal_status)
    })
}

fn digest_repair_head(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let request = read_authenticated_repair_request(&mut reader)?;
    let sealed_head_bytes = reader.read_remaining();
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(request.handle, &request.capability)?;
        Ok(lease
            .root
            .derive_authenticated_repair_head_digest(
                request.runtime_build_manifest_hash,
                request.namespace,
                sealed_head_bytes,
            )
            .map_err(schema_status)?
            .into_bytes()
            .to_vec())
    })
}

struct RecordRequest<'input> {
    handle: u32,
    capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH],
    action_randomness_commitment: Hash512,
    record_type: LocalRecordType,
    identifier_context: &'input [u8],
    record_version: u64,
    predecessor_record_hash: Option<Hash512>,
}

fn read_record_request<'input>(
    reader: &mut InputReader<'input>,
) -> RuntimeResult<RecordRequest<'input>> {
    let handle = reader.read_u32()?;
    let capability = reader.read_array()?;
    let action_randomness_commitment = Hash512::from_bytes(reader.read_array()?);
    let record_type = read_record_type(reader)?;
    let identifier_context_byte_length =
        usize::try_from(reader.read_u32()?).map_err(|_| malformed_status())?;
    let identifier_context = reader.read_slice(identifier_context_byte_length)?;
    let record_version = reader.read_u64()?;
    let predecessor_record_hash = match reader.read_u8()? {
        0 => None,
        1 => Some(Hash512::from_bytes(reader.read_array()?)),
        _ => return Err(malformed_status()),
    };
    Ok(RecordRequest {
        handle,
        capability,
        action_randomness_commitment,
        record_type,
        identifier_context,
        record_version,
        predecessor_record_hash,
    })
}

fn read_record_type(reader: &mut InputReader<'_>) -> RuntimeResult<LocalRecordType> {
    LocalRecordType::from_canonical_code(reader.read_u16()?)
        .ok_or_else(|| refusal_status(RefusalReason::WrongTypeOrLength))
}

fn derive_record_identifier_from_context(
    binding: LocalStorageBinding,
    record_type: LocalRecordType,
    identifier_context: &[u8],
) -> RuntimeResult<Hash512> {
    let mut reader = InputReader::new(identifier_context);
    let identifier = match record_type {
        LocalRecordType::ActionRandomness => {
            reader.finish()?;
            LocalRecordIdentifierInput::ActionRandomness
        }
        LocalRecordType::SourceVssMaterial => {
            let material_context_hash = Hash512::from_bytes(reader.read_array()?);
            reader.finish()?;
            LocalRecordIdentifierInput::SourceVssMaterial {
                material_context_hash,
            }
        }
        LocalRecordType::AggregateThresholdShare => {
            let recipient_input_root = Hash512::from_bytes(reader.read_array()?);
            reader.finish()?;
            LocalRecordIdentifierInput::AggregateThresholdShare {
                recipient_input_root,
            }
        }
        LocalRecordType::ProofAttempt => {
            let application_slot_hash = Hash512::from_bytes(reader.read_array()?);
            reader.finish()?;
            LocalRecordIdentifierInput::ProofAttempt {
                application_slot_hash,
            }
        }
        LocalRecordType::BallotAttempt => {
            let statement_byte_length =
                usize::try_from(reader.read_u32()?).map_err(|_| malformed_status())?;
            if statement_byte_length == 0 {
                return Err(refusal_status(RefusalReason::WrongTypeOrLength));
            }
            let canonical_ballot_statement_bytes = reader.read_slice(statement_byte_length)?;
            let ballot_encryption_attempt_identifier = reader.read_array()?;
            reader.finish()?;
            return derive_local_record_identifier(
                binding,
                LocalRecordIdentifierInput::BallotAttempt {
                    canonical_ballot_statement_bytes,
                    ballot_encryption_attempt_identifier: &ballot_encryption_attempt_identifier,
                },
            )
            .map_err(schema_status);
        }
        LocalRecordType::ExactOutputChunk => {
            let capability_kind = reader.read_u16()?;
            let exact_output_hash = Hash512::from_bytes(reader.read_array()?);
            let output_chunk_index = reader.read_u64()?;
            reader.finish()?;
            LocalRecordIdentifierInput::ExactOutputChunk {
                capability_kind,
                exact_output_hash,
                output_chunk_index,
            }
        }
        LocalRecordType::SubjectState => {
            let state_key = Hash512::from_bytes(reader.read_array()?);
            reader.finish()?;
            LocalRecordIdentifierInput::SubjectState { state_key }
        }
        LocalRecordType::WitnessState => {
            let state_key = Hash512::from_bytes(reader.read_array()?);
            reader.finish()?;
            LocalRecordIdentifierInput::WitnessState { state_key }
        }
        LocalRecordType::CheckpointManifest => {
            let runtime_build_manifest_hash = Hash512::from_bytes(reader.read_array()?);
            let checkpoint_lineage_identifier = reader.read_array()?;
            let operation_kind = reader.read_u16()?;
            let safe_boundary_ordinal = reader.read_u32()?;
            let source_digest_count =
                usize::try_from(reader.read_u32()?).map_err(|_| malformed_status())?;
            if source_digest_count > MAXIMUM_CHECKPOINT_SOURCE_DIGEST_COUNT {
                return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
            }
            let mut ordered_source_digests = Vec::with_capacity(source_digest_count);
            for _ in 0..source_digest_count {
                ordered_source_digests.push(Hash512::from_bytes(reader.read_array()?));
            }
            reader.finish()?;
            return derive_local_record_identifier(
                binding,
                LocalRecordIdentifierInput::CheckpointManifest {
                    runtime_build_manifest_hash,
                    checkpoint_lineage_identifier: &checkpoint_lineage_identifier,
                    operation_kind,
                    safe_boundary_ordinal,
                    ordered_source_digests: &ordered_source_digests,
                },
            )
            .map_err(schema_status);
        }
        LocalRecordType::CheckpointChunk => {
            let checkpoint_identifier = Hash512::from_bytes(reader.read_array()?);
            let chunk_index = reader.read_u32()?;
            let chunk_digest = Hash512::from_bytes(reader.read_array()?);
            reader.finish()?;
            LocalRecordIdentifierInput::CheckpointChunk {
                checkpoint_identifier,
                chunk_index,
                chunk_digest,
            }
        }
        LocalRecordType::CommonProofExternalMemory => {
            if identifier_context.len()
                != COMMON_PROOF_EXTERNAL_MEMORY_IDENTIFIER_CONTEXT_BYTE_LENGTH
            {
                return Err(malformed_status());
            }
            let common_proof_environment_identifier = reader.read_array()?;
            let common_proof_runtime_binding_hash = Hash512::from_bytes(reader.read_array()?);
            let proof_attempt_lineage_identifier = reader.read_array()?;
            let record_kind =
                CommonProofExternalMemoryRecordKind::from_canonical_code(reader.read_u16()?)
                    .ok_or_else(|| refusal_status(RefusalReason::WrongTypeOrLength))?;
            let object_ordinal = reader.read_u32()?;
            let chunk_ordinal = reader.read_u32()?;
            let byte_offset = reader.read_u64()?;
            reader.finish()?;
            LocalRecordIdentifierInput::CommonProofExternalMemory {
                common_proof_environment_identifier,
                common_proof_runtime_binding_hash,
                proof_attempt_lineage_identifier,
                record_kind,
                object_ordinal,
                chunk_ordinal,
                byte_offset,
            }
        }
    };
    derive_local_record_identifier(binding, identifier).map_err(schema_status)
}

fn read_binding(reader: &mut InputReader<'_>) -> RuntimeResult<LocalStorageBinding> {
    let suite_id = Hash512::from_bytes(reader.read_array()?);
    let ceremony_context_hash = Hash512::from_bytes(reader.read_array()?);
    let action_context_hash = Hash512::from_bytes(reader.read_array()?);
    let participant_id = ParticipantIdentity::from_bytes(reader.read_array()?);
    Ok(LocalStorageBinding::new(
        suite_id,
        ceremony_context_hash,
        action_context_hash,
        participant_id,
    ))
}

fn read_commitment(reader: &mut InputReader<'_>) -> RuntimeResult<StorageRootCommitmentPayload> {
    Ok(StorageRootCommitmentPayload::new(Hash512::from_bytes(
        reader.read_array()?,
    )))
}

fn read_lease_input(
    input: &[u8],
) -> RuntimeResult<(u32, [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH])> {
    if input.len() != HANDLE_BYTE_LENGTH + LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH {
        return Err(malformed_status());
    }
    let mut reader = InputReader::new(input);
    let handle = u32::from_le_bytes(reader.read_array()?);
    let capability = reader.read_array()?;
    reader.finish()?;
    Ok((handle, capability))
}

fn require_lease<'lease>(
    lease: Option<&'lease RootLease>,
    handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'lease RootLease> {
    let lease = lease.ok_or(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)?;
    if lease.handle != handle {
        return Err(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE);
    }
    if capability.len() != LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH
        || !bool::from(lease.capability.as_ref().ct_eq(capability))
    {
        return Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH);
    }
    Ok(lease)
}

fn require_lease_mut<'lease>(
    lease: Option<&'lease mut RootLease>,
    handle: u32,
    capability: &[u8],
) -> RuntimeResult<&'lease mut RootLease> {
    let lease = lease.ok_or(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)?;
    if lease.handle != handle {
        return Err(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE);
    }
    if capability.len() != LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH
        || !bool::from(lease.capability.as_ref().ct_eq(capability))
    {
        return Err(LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH);
    }
    Ok(lease)
}

const fn malformed_status() -> u32 {
    refusal_status(RefusalReason::MalformedEncoding)
}

const fn outside_supported_profile_status() -> u32 {
    refusal_status(RefusalReason::OutsideSupportedProfile)
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn schema_status(error: super::FoundationSchemaError) -> u32 {
    refusal_status(error.refusal_reason)
}

#[cfg(test)]
mod tests;
