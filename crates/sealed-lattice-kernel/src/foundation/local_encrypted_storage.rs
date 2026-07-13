use core::{cmp, fmt};

use zeroize::{Zeroize, Zeroizing};

use super::schemas::{
    SchemaResult, read_fixed_bytes, read_hash, read_item, read_u16, read_u64, read_variable_item,
    require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError,
    Hash512, ParticipantIdentity, RefusalReason, VerificationResult,
    hash_foundation_tuple_512 as hash512,
};

pub const DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER: u16 = 0x0300;
pub const STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER: u16 = 0x0302;
pub const STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x0303;
pub const DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER: u16 = 0x0305;

pub const ACTION_STORAGE_ROOT_BYTE_LENGTH: usize = 48;
pub const DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH: usize = 12;
pub const DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH: usize = 16;

const FOUNDATION_PROTOCOL_VERSION: u16 = 1;
const DEVICE_WRAPPED_STORAGE_ROOT_PLAINTEXT_BYTE_LENGTH: u64 = 48;
const RECOVERY_CHECKSUM_BYTE_LENGTH: usize = 16;
const STORAGE_ROOT_COMMITMENT_PAYLOAD_MAXIMUM_BYTE_LENGTH: usize = 78;
const RECOVERY_VALUE_CANONICAL_BYTE_LENGTH: usize = 442;
const RECOVERY_VALUE_BASE32_CHARACTER_LENGTH: usize = 708;
const DEVICE_WRAPPING_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH: usize = 380;
const DEVICE_WRAPPED_STORAGE_ROOT_MAXIMUM_BYTE_LENGTH: usize = 492;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalStorageBinding {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_id: ParticipantIdentity,
}

impl LocalStorageBinding {
    pub const fn new(
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        participant_id: ParticipantIdentity,
    ) -> Self {
        Self {
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            participant_id,
        }
    }

    pub const fn suite_id(self) -> Hash512 {
        self.suite_id
    }

    pub const fn ceremony_context_hash(self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub const fn participant_id(self) -> ParticipantIdentity {
        self.participant_id
    }

    fn canonical_items(self) -> [CanonicalItem; 4] {
        [
            CanonicalItem::hash512(self.suite_id.into_bytes()),
            CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(self.action_context_hash.into_bytes()),
            CanonicalItem::participant_identity(self.participant_id.into_bytes()),
        ]
    }
}

pub struct ActionStorageRoot {
    binding: LocalStorageBinding,
    root: Zeroizing<[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH]>,
    storage_root_commitment: Hash512,
}

impl ActionStorageRoot {
    pub(crate) fn from_verified_root(
        binding: LocalStorageBinding,
        root: Zeroizing<[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH]>,
    ) -> SchemaResult<Self> {
        let storage_root_commitment = derive_storage_root_commitment(binding, &root)?;
        Ok(Self {
            binding,
            root,
            storage_root_commitment,
        })
    }

    pub const fn binding(&self) -> LocalStorageBinding {
        self.binding
    }

    pub const fn storage_root_commitment(&self) -> Hash512 {
        self.storage_root_commitment
    }

    pub(crate) fn root_bytes(&self) -> &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH] {
        &self.root
    }

    pub fn storage_root_commitment_payload(&self) -> StorageRootCommitmentPayload {
        StorageRootCommitmentPayload::new(self.storage_root_commitment)
    }

    pub fn device_wrapping_associated_data(&self) -> DeviceWrappingAssociatedData {
        DeviceWrappingAssociatedData::new(self.binding, self.storage_root_commitment)
    }

    pub fn recovery_value(&self) -> SchemaResult<LocalStorageRecoveryValue> {
        LocalStorageRecoveryValue::new(self.binding, *self.root)
    }
}

impl fmt::Debug for ActionStorageRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionStorageRoot")
            .field("binding", &self.binding)
            .field("root", &"[REDACTED]")
            .field("storage_root_commitment", &self.storage_root_commitment)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageRootCommitmentPayload {
    storage_root_commitment: Hash512,
}

impl StorageRootCommitmentPayload {
    pub const fn new(storage_root_commitment: Hash512) -> Self {
        Self {
            storage_root_commitment,
        }
    }

    pub const fn storage_root_commitment(self) -> Hash512 {
        self.storage_root_commitment
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![CanonicalItem::hash512(
                self.storage_root_commitment.into_bytes(),
            )],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits = bounded_canonical_decode_limits(
            limits,
            STORAGE_ROOT_COMMITMENT_PAYLOAD_MAXIMUM_BYTE_LENGTH,
            1,
        );
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER, 1)?;
        Ok(Self::new(read_hash(&tuple.items[0])?))
    }
}

pub struct LocalStorageRecoveryValue {
    binding: LocalStorageBinding,
    storage_root_commitment: Hash512,
    action_storage_root: Zeroizing<[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH]>,
    checksum: [u8; RECOVERY_CHECKSUM_BYTE_LENGTH],
}

impl LocalStorageRecoveryValue {
    pub fn new(
        binding: LocalStorageBinding,
        action_storage_root: [u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        let action_storage_root = Zeroizing::new(action_storage_root);
        let storage_root_commitment =
            derive_storage_root_commitment(binding, &action_storage_root)?;
        let checksum =
            derive_recovery_checksum(binding, storage_root_commitment, &action_storage_root)?;
        Ok(Self {
            binding,
            storage_root_commitment,
            action_storage_root,
            checksum,
        })
    }

    pub const fn binding(&self) -> LocalStorageBinding {
        self.binding
    }

    pub const fn storage_root_commitment(&self) -> Hash512 {
        self.storage_root_commitment
    }

    pub const fn checksum(&self) -> &[u8; RECOVERY_CHECKSUM_BYTE_LENGTH] {
        &self.checksum
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROTOCOL_VERSION),
                CanonicalItem::hash512(self.binding.suite_id.into_bytes()),
                CanonicalItem::hash512(self.binding.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.binding.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.binding.participant_id.into_bytes()),
                CanonicalItem::hash512(self.storage_root_commitment.into_bytes()),
                CanonicalItem::fixed_bytes(self.action_storage_root.as_ref())?,
                CanonicalItem::fixed_bytes(self.checksum)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits =
            bounded_canonical_decode_limits(limits, RECOVERY_VALUE_CANONICAL_BYTE_LENGTH, 8);
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER, 8)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        let binding = LocalStorageBinding::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_participant_identity(&tuple.items[4])?,
        );
        let value = Self {
            binding,
            storage_root_commitment: read_hash(&tuple.items[5])?,
            action_storage_root: Zeroizing::new(read_fixed_bytes(&tuple.items[6])?),
            checksum: read_fixed_bytes(&tuple.items[7])?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> SchemaResult<()> {
        let expected_commitment =
            derive_storage_root_commitment(self.binding, &self.action_storage_root)?;
        if expected_commitment != self.storage_root_commitment {
            return Err(schema_error(
                RefusalReason::WrongHashOrRoot,
                "the recovery storage-root commitment does not recompute",
            ));
        }
        let expected_checksum = derive_recovery_checksum(
            self.binding,
            self.storage_root_commitment,
            &self.action_storage_root,
        )?;
        if expected_checksum != self.checksum {
            return Err(schema_error(
                RefusalReason::WrongHashOrRoot,
                "the local-storage recovery checksum does not recompute",
            ));
        }
        Ok(())
    }

    pub fn to_canonical_base32(&self) -> SchemaResult<Zeroizing<String>> {
        let bytes = Zeroizing::new(self.encode()?);
        Ok(Zeroizing::new(encode_base32(bytes.as_ref())))
    }

    pub fn recover(
        self,
        expected_binding: LocalStorageBinding,
        externally_verified_commitment: StorageRootCommitmentPayload,
    ) -> VerificationResult<ActionStorageRoot> {
        if let Err(error) = self.validate() {
            return VerificationResult::refused(error.refusal_reason);
        }
        if self.binding != expected_binding {
            return VerificationResult::refused(RefusalReason::WrongContext);
        }
        if self.storage_root_commitment != externally_verified_commitment.storage_root_commitment {
            return VerificationResult::refused(RefusalReason::WrongHashOrRoot);
        }
        match ActionStorageRoot::from_verified_root(self.binding, self.action_storage_root) {
            Ok(root) => VerificationResult::valid(root),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }
}

impl fmt::Debug for LocalStorageRecoveryValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalStorageRecoveryValue")
            .field("binding", &self.binding)
            .field("storage_root_commitment", &self.storage_root_commitment)
            .field("action_storage_root", &"[REDACTED]")
            .field("checksum", &"[REDACTED]")
            .finish()
    }
}

pub struct CanonicalLocalStorageRecoveryIngress {
    canonical_base32: Zeroizing<String>,
    recovery_value: LocalStorageRecoveryValue,
}

impl CanonicalLocalStorageRecoveryIngress {
    pub fn decode(
        case_insensitive_base32: &str,
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        let mut decoded_bytes = Zeroizing::new(decode_base32(case_insensitive_base32)?);
        if decoded_bytes.len() != RECOVERY_VALUE_CANONICAL_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "the local-storage recovery value has the wrong byte length",
            ));
        }
        let recovery_value = LocalStorageRecoveryValue::decode(decoded_bytes.as_ref(), limits)?;
        let canonical_base32 = Zeroizing::new(encode_base32(decoded_bytes.as_ref()));
        decoded_bytes.zeroize();
        Ok(Self {
            canonical_base32,
            recovery_value,
        })
    }

    pub fn canonical_base32(&self) -> &str {
        self.canonical_base32.as_str()
    }

    pub fn into_recovery_value(self) -> LocalStorageRecoveryValue {
        self.recovery_value
    }
}

impl fmt::Debug for CanonicalLocalStorageRecoveryIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalLocalStorageRecoveryIngress")
            .field("canonical_base32", &"[REDACTED]")
            .field("recovery_value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceWrappingAssociatedData {
    binding: LocalStorageBinding,
    storage_root_commitment: Hash512,
}

impl DeviceWrappingAssociatedData {
    pub const fn new(binding: LocalStorageBinding, storage_root_commitment: Hash512) -> Self {
        Self {
            binding,
            storage_root_commitment,
        }
    }

    pub const fn binding(self) -> LocalStorageBinding {
        self.binding
    }

    pub const fn storage_root_commitment(self) -> Hash512 {
        self.storage_root_commitment
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROTOCOL_VERSION),
                CanonicalItem::hash512(self.binding.suite_id.into_bytes()),
                CanonicalItem::hash512(self.binding.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.binding.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.binding.participant_id.into_bytes()),
                CanonicalItem::hash512(self.storage_root_commitment.into_bytes()),
                CanonicalItem::unsigned64(DEVICE_WRAPPED_STORAGE_ROOT_PLAINTEXT_BYTE_LENGTH),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits = bounded_canonical_decode_limits(
            limits,
            DEVICE_WRAPPING_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH,
            7,
        );
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, 7)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        if read_u64(&tuple.items[6])? != DEVICE_WRAPPED_STORAGE_ROOT_PLAINTEXT_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "the device-wrapped root plaintext length must be forty-eight bytes",
            ));
        }
        Ok(Self::new(
            LocalStorageBinding::new(
                read_hash(&tuple.items[1])?,
                read_hash(&tuple.items[2])?,
                read_hash(&tuple.items[3])?,
                read_participant_identity(&tuple.items[4])?,
            ),
            read_hash(&tuple.items[5])?,
        ))
    }

    pub fn verify_opened_storage_root(
        self,
        opened_root: Zeroizing<[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH]>,
        expected_binding: LocalStorageBinding,
        externally_verified_commitment: StorageRootCommitmentPayload,
    ) -> VerificationResult<ActionStorageRoot> {
        if self.binding != expected_binding {
            return VerificationResult::refused(RefusalReason::WrongContext);
        }
        if self.storage_root_commitment != externally_verified_commitment.storage_root_commitment {
            return VerificationResult::refused(RefusalReason::WrongHashOrRoot);
        }
        match ActionStorageRoot::from_verified_root(self.binding, opened_root) {
            Ok(root) if root.storage_root_commitment == self.storage_root_commitment => {
                VerificationResult::valid(root)
            }
            Ok(_) => VerificationResult::refused(RefusalReason::WrongHashOrRoot),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DeviceWrappedStorageRoot {
    associated_data: DeviceWrappingAssociatedData,
    nonce: [u8; DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH],
    ciphertext: [u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
    tag: [u8; DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH],
}

impl DeviceWrappedStorageRoot {
    pub const fn new(
        associated_data: DeviceWrappingAssociatedData,
        nonce: [u8; DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH],
        ciphertext: [u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
        tag: [u8; DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH],
    ) -> Self {
        Self {
            associated_data,
            nonce,
            ciphertext,
            tag,
        }
    }

    pub const fn associated_data(&self) -> DeviceWrappingAssociatedData {
        self.associated_data
    }

    pub const fn nonce(&self) -> &[u8; DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH] {
        &self.nonce
    }

    pub const fn ciphertext(&self) -> &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH] {
        &self.ciphertext
    }

    pub const fn tag(&self) -> &[u8; DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH] {
        &self.tag
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::variable_bytes(self.associated_data.encode()?)?,
                CanonicalItem::fixed_bytes(self.nonce)?,
                CanonicalItem::fixed_bytes(self.ciphertext)?,
                CanonicalItem::fixed_bytes(self.tag)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits = bounded_canonical_decode_limits(
            limits,
            DEVICE_WRAPPED_STORAGE_ROOT_MAXIMUM_BYTE_LENGTH,
            4,
        );
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER, 4)?;
        let associated_data_bytes =
            read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?;
        Ok(Self::new(
            DeviceWrappingAssociatedData::decode(associated_data_bytes, limits)?,
            read_fixed_bytes(&tuple.items[1])?,
            read_fixed_bytes(&tuple.items[2])?,
            read_fixed_bytes(&tuple.items[3])?,
        ))
    }
}

impl fmt::Debug for DeviceWrappedStorageRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceWrappedStorageRoot")
            .field("associated_data", &self.associated_data)
            .field("nonce", &self.nonce)
            .field("ciphertext_byte_length", &self.ciphertext.len())
            .field("tag", &self.tag)
            .finish()
    }
}

fn derive_storage_root_commitment(
    binding: LocalStorageBinding,
    action_storage_root: &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
) -> SchemaResult<Hash512> {
    let mut commitment_items = Vec::from(binding.canonical_items());
    commitment_items.push(CanonicalItem::fixed_bytes(action_storage_root)?);
    Ok(hash512(
        "sealed-lattice/local-storage-root/v2",
        &commitment_items,
    )?)
}

fn derive_recovery_checksum(
    binding: LocalStorageBinding,
    storage_root_commitment: Hash512,
    action_storage_root: &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
) -> SchemaResult<[u8; RECOVERY_CHECKSUM_BYTE_LENGTH]> {
    let digest = hash512(
        "sealed-lattice/local-storage-recovery-checksum/v1",
        &[
            CanonicalItem::unsigned16(FOUNDATION_PROTOCOL_VERSION),
            CanonicalItem::hash512(binding.suite_id.into_bytes()),
            CanonicalItem::hash512(binding.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(binding.action_context_hash.into_bytes()),
            CanonicalItem::participant_identity(binding.participant_id.into_bytes()),
            CanonicalItem::hash512(storage_root_commitment.into_bytes()),
            CanonicalItem::fixed_bytes(action_storage_root)?,
        ],
    )?;
    let mut checksum = [0u8; RECOVERY_CHECKSUM_BYTE_LENGTH];
    checksum.copy_from_slice(&digest.as_bytes()[..RECOVERY_CHECKSUM_BYTE_LENGTH]);
    Ok(checksum)
}

fn require_protocol_version(version: u16) -> SchemaResult<()> {
    if version != FOUNDATION_PROTOCOL_VERSION {
        return Err(schema_error(
            RefusalReason::UnsupportedVersionOrSuite,
            "the local-storage protocol version is unsupported",
        ));
    }
    Ok(())
}

fn read_participant_identity(item: &CanonicalItem) -> SchemaResult<ParticipantIdentity> {
    let bytes: [u8; ParticipantIdentity::BYTE_LENGTH] =
        read_item(item, CanonicalItemType::ParticipantIdentity)?
            .try_into()
            .map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "participant identity has the wrong length",
                )
            })?;
    Ok(ParticipantIdentity::from_bytes(bytes))
}

fn bounded_canonical_decode_limits(
    limits: &CanonicalDecodeLimits,
    maximum_tuple_byte_length: usize,
    maximum_item_count: usize,
) -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: cmp::min(
            limits.maximum_tuple_byte_length,
            maximum_tuple_byte_length,
        ),
        maximum_item_count: cmp::min(limits.maximum_item_count, maximum_item_count),
        maximum_item_byte_length: cmp::min(
            limits.maximum_item_byte_length,
            maximum_tuple_byte_length,
        ),
        maximum_nesting_depth: limits.maximum_nesting_depth,
        maximum_cumulative_work_byte_length: cmp::min(
            limits.maximum_cumulative_work_byte_length,
            maximum_tuple_byte_length.saturating_mul(4),
        ),
        maximum_cumulative_allocation_byte_length: cmp::min(
            limits.maximum_cumulative_allocation_byte_length,
            maximum_tuple_byte_length.saturating_mul(2),
        ),
    }
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let output_length = bytes.len().saturating_mul(8).div_ceil(5);
    let mut output = String::with_capacity(output_length);
    let mut accumulator = 0u16;
    let mut available_bits = 0u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u16::from(*byte);
        available_bits += 8;
        while available_bits >= 5 {
            available_bits -= 5;
            let index = usize::from((accumulator >> available_bits) & 0x1f);
            output.push(char::from(ALPHABET[index]));
        }
        accumulator &= (1u16 << available_bits).wrapping_sub(1);
    }
    if available_bits != 0 {
        let index = usize::from((accumulator << (5 - available_bits)) & 0x1f);
        output.push(char::from(ALPHABET[index]));
    }
    output
}

fn decode_base32(value: &str) -> SchemaResult<Vec<u8>> {
    if value.len() != RECOVERY_VALUE_BASE32_CHARACTER_LENGTH {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "the local-storage recovery text has the wrong length",
        ));
    }
    let mut output = Vec::with_capacity(RECOVERY_VALUE_CANONICAL_BYTE_LENGTH);
    let mut accumulator = 0u16;
    let mut available_bits = 0u8;
    for character in value.bytes() {
        let digit = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a',
            b'2'..=b'7' => character - b'2' + 26,
            _ => {
                return Err(schema_error(
                    RefusalReason::MalformedEncoding,
                    "the local-storage recovery text is not unpadded RFC 4648 base32",
                ));
            }
        };
        accumulator = (accumulator << 5) | u16::from(digit);
        available_bits += 5;
        if available_bits >= 8 {
            available_bits -= 8;
            output.push((accumulator >> available_bits) as u8);
            accumulator &= (1u16 << available_bits).wrapping_sub(1);
        }
    }
    if accumulator != 0 || !encode_base32(&output).eq_ignore_ascii_case(value) {
        output.zeroize();
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "the local-storage recovery text has noncanonical trailing bits",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
