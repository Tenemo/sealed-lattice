use core::str;
use std::cell::RefCell;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    ActionStorageRoot, CanonicalDecodeLimits, CanonicalLocalStorageRecoveryIngress,
    DeviceWrappedStorageRoot, Hash512, LocalStorageBinding, ParticipantIdentity, RefusalReason,
    StorageRootCommitmentPayload,
};

pub(crate) const LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH: usize = 32;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW: u32 = 1;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_STAGE_OPENED: u32 = 2;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_STAGE_RECOVERY: u32 = 3;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA: u32 = 4;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_COPY_FOR_DEVICE_WRAP: u32 = 5;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_ENCODE_DEVICE_ENVELOPE: u32 = 6;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DECODE_DEVICE_ENVELOPE: u32 = 7;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_COMMIT: u32 = 8;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DISCARD: u32 = 9;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_DESTROY: u32 = 10;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_PREPARE_RECOVERY: u32 = 11;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_CONFIRM_RECOVERY: u32 = 12;
pub(crate) const LOCAL_STORAGE_ROOT_COMMAND_RESET: u32 = 13;

pub(crate) const LOCAL_STORAGE_ROOT_STATUS_RESOURCE_LIMIT: u32 = 0x0001_0000;
pub(crate) const LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE: u32 = 0x0001_0001;
pub(crate) const LOCAL_STORAGE_ROOT_STATUS_CAPABILITY_MISMATCH: u32 = 0x0001_0002;

const HASH_BYTE_LENGTH: usize = 64;
#[cfg(test)]
const BINDING_BYTE_LENGTH: usize = HASH_BYTE_LENGTH * 4;
const HANDLE_BYTE_LENGTH: usize = 4;
const MUTATION_IDENTIFIER_BYTE_LENGTH: usize = 32;
const RECOVERY_CHECKSUM_BYTE_LENGTH: usize = 16;
const RECOVERY_TEXT_BYTE_LENGTH: usize = 708;

struct RootLease {
    capability: Zeroizing<[u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH]>,
    handle: u32,
    mutation_identifier: Option<[u8; MUTATION_IDENTIFIER_BYTE_LENGTH]>,
    root: ActionStorageRoot,
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
            mutation_identifier: None,
            root,
        });
        Ok(handle)
    }

    fn staged(&self, handle: u32, capability: &[u8]) -> RuntimeResult<&RootLease> {
        require_lease(self.staged.as_ref(), handle, capability)
    }

    fn active(&self, handle: u32, capability: &[u8]) -> RuntimeResult<&RootLease> {
        require_lease(self.active.as_ref(), handle, capability)
    }

    fn commit(
        &mut self,
        handle: u32,
        capability: &[u8],
        mutation_identifier: [u8; MUTATION_IDENTIFIER_BYTE_LENGTH],
    ) -> RuntimeResult<()> {
        require_lease(self.staged.as_ref(), handle, capability)?;
        let mut staged = self
            .staged
            .take()
            .ok_or(LOCAL_STORAGE_ROOT_STATUS_STALE_HANDLE)?;
        staged.mutation_identifier = Some(mutation_identifier);
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

struct InputReader<'input> {
    bytes: &'input [u8],
    offset: usize,
}

impl<'input> InputReader<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_array<const BYTE_LENGTH: usize>(&mut self) -> RuntimeResult<[u8; BYTE_LENGTH]> {
        let end = self
            .offset
            .checked_add(BYTE_LENGTH)
            .ok_or_else(malformed_status)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(malformed_status)?;
        self.offset = end;
        bytes.try_into().map_err(|_| malformed_status())
    }

    fn read_remaining(&mut self) -> &'input [u8] {
        let remaining = &self.bytes[self.offset..];
        self.offset = self.bytes.len();
        remaining
    }

    fn finish(self) -> RuntimeResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(malformed_status())
        }
    }
}

pub(crate) fn run_local_storage_root_command(command: u32, input: &[u8]) -> RuntimeResult<Vec<u8>> {
    match command {
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW => stage_new(input),
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_OPENED => stage_opened(input),
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_RECOVERY => stage_recovery(input),
        LOCAL_STORAGE_ROOT_COMMAND_ASSOCIATED_DATA => associated_data(input),
        LOCAL_STORAGE_ROOT_COMMAND_COPY_FOR_DEVICE_WRAP => copy_for_device_wrap(input),
        LOCAL_STORAGE_ROOT_COMMAND_ENCODE_DEVICE_ENVELOPE => encode_device_envelope(input),
        LOCAL_STORAGE_ROOT_COMMAND_DECODE_DEVICE_ENVELOPE => decode_device_envelope(input),
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT => commit(input),
        LOCAL_STORAGE_ROOT_COMMAND_DISCARD => discard(input),
        LOCAL_STORAGE_ROOT_COMMAND_DESTROY => destroy(input),
        LOCAL_STORAGE_ROOT_COMMAND_PREPARE_RECOVERY => prepare_recovery(input),
        LOCAL_STORAGE_ROOT_COMMAND_CONFIRM_RECOVERY => confirm_recovery(input),
        LOCAL_STORAGE_ROOT_COMMAND_RESET => reset(input),
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

fn stage_recovery(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let binding = read_binding(&mut reader)?;
    let expected_commitment = read_commitment(&mut reader)?;
    let recovery_text_bytes = reader.read_array::<RECOVERY_TEXT_BYTE_LENGTH>()?;
    reader.finish()?;
    let recovery_text = str::from_utf8(&recovery_text_bytes).map_err(|_| malformed_status())?;
    let ingress = CanonicalLocalStorageRecoveryIngress::decode(
        recovery_text,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(schema_status)?;
    let canonical_recovery_text = ingress.canonical_base32().as_bytes().to_vec();
    let root = ingress
        .into_recovery_value()
        .recover(binding, expected_commitment)
        .into_result()
        .map_err(refusal_status)?;
    let mut output = stage_root(capability, root)?;
    output.extend_from_slice(&canonical_recovery_text);
    Ok(output)
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
    let mut reader = InputReader::new(input);
    let handle = u32::from_le_bytes(reader.read_array()?);
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let mutation_identifier = reader.read_array()?;
    reader.finish()?;
    ROOT_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .commit(handle, &capability, mutation_identifier)
    })?;
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

fn prepare_recovery(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = u32::from_le_bytes(reader.read_array()?);
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let mutation_identifier = reader.read_array()?;
    reader.finish()?;
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(handle, &capability)?;
        if lease.mutation_identifier.as_ref() != Some(&mutation_identifier) {
            return Err(refusal_status(RefusalReason::ConsumedState));
        }
        let recovery_value = lease.root.recovery_value().map_err(schema_status)?;
        let canonical_recovery_text = recovery_value
            .to_canonical_base32()
            .map_err(schema_status)?;
        let mut output =
            Vec::with_capacity(RECOVERY_CHECKSUM_BYTE_LENGTH + RECOVERY_TEXT_BYTE_LENGTH);
        output.extend_from_slice(recovery_value.checksum());
        output.extend_from_slice(canonical_recovery_text.as_bytes());
        Ok(output)
    })
}

fn confirm_recovery(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = u32::from_le_bytes(reader.read_array()?);
    let capability: [u8; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH] = reader.read_array()?;
    let recovery_text_bytes = reader.read_array::<RECOVERY_TEXT_BYTE_LENGTH>()?;
    let confirmed_checksum = reader.read_array::<RECOVERY_CHECKSUM_BYTE_LENGTH>()?;
    reader.finish()?;
    let recovery_text = str::from_utf8(&recovery_text_bytes).map_err(|_| malformed_status())?;
    let ingress = CanonicalLocalStorageRecoveryIngress::decode(
        recovery_text,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(schema_status)?;
    if ingress.canonical_base32().as_bytes() != recovery_text_bytes {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    let recovery_value = ingress.into_recovery_value();
    ROOT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let lease = registry.active(handle, &capability)?;
        if recovery_value.binding() != lease.root.binding() {
            return Err(refusal_status(RefusalReason::WrongContext));
        }
        if recovery_value.storage_root_commitment() != lease.root.storage_root_commitment() {
            return Err(refusal_status(RefusalReason::WrongHashOrRoot));
        }
        if !bool::from(recovery_value.checksum().ct_eq(&confirmed_checksum)) {
            return Err(refusal_status(RefusalReason::WrongHashOrRoot));
        }
        Ok(Vec::new())
    })
}

fn reset(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    if !input.is_empty() {
        return Err(malformed_status());
    }
    ROOT_REGISTRY.with(|registry| registry.borrow_mut().reset());
    Ok(Vec::new())
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

const fn malformed_status() -> u32 {
    refusal_status(RefusalReason::MalformedEncoding)
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn schema_status(error: super::FoundationSchemaError) -> u32 {
    refusal_status(error.refusal_reason)
}

#[cfg(test)]
mod tests;
