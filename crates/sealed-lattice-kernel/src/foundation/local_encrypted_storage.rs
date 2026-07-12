use core::{cmp, fmt};

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use subtle::ConstantTimeEq;
use tiny_keccak::{Hasher, Kmac};
use zeroize::{Zeroize, Zeroizing};

use super::schemas::{
    SchemaResult, read_fixed_bytes, read_hash, read_item, read_u16, read_u64, read_variable_item,
    require_header,
};
use super::{
    CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    CheckpointManifest, FOUNDATION_PROFILE, FallibleEntropySource, FoundationSchemaError, Hash512,
    ParticipantIdentity, ProofFamily, ProofObjectHeader, RefusalReason, StateCapabilityKind,
    VerificationResult, derive_state_key, hash512,
};

pub const DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER: u16 = 0x0300;
pub const LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER: u16 = 0x0301;
pub const STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER: u16 = 0x0302;
pub const STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x0303;
pub const LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0304;
pub const DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER: u16 = 0x0305;
pub const LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER: u16 = 0x0306;
pub const LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0307;

pub const ACTION_STORAGE_ROOT_BYTE_LENGTH: usize = 48;
pub const LOCAL_RECORD_NONCE_BYTE_LENGTH: usize = 12;
pub const LOCAL_RECORD_TAG_BYTE_LENGTH: usize = 16;
pub const LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH: usize = 32;

const FOUNDATION_PROTOCOL_VERSION: u16 = 1;
const LOCAL_RECORD_KEY_BYTE_LENGTH: usize = 32;
const DEVICE_WRAPPED_STORAGE_ROOT_PLAINTEXT_BYTE_LENGTH: u64 = 48;
const RECOVERY_CHECKSUM_BYTE_LENGTH: usize = 16;
const STORAGE_ROOT_COMMITMENT_PAYLOAD_MAXIMUM_BYTE_LENGTH: usize = 78;
const RECOVERY_VALUE_CANONICAL_BYTE_LENGTH: usize = 442;
const RECOVERY_VALUE_BASE32_CHARACTER_LENGTH: usize = 708;
const DEVICE_WRAPPING_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH: usize = 380;
const DEVICE_WRAPPED_STORAGE_ROOT_MAXIMUM_BYTE_LENGTH: usize = 492;
const LOCAL_RECORD_KEY_INPUT_MAXIMUM_BYTE_LENGTH: usize = 388;
const LOCAL_RECORD_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH: usize = 489;
const MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH: usize =
    FOUNDATION_PROFILE.maximum_copied_buffer_byte_length;
const MAXIMUM_LOCAL_RECORD_ENVELOPE_BYTE_LENGTH: usize =
    MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH + 1_024;

const LOCAL_RECORD_KEY_CUSTOMIZATION: &[u8] = b"sealed-lattice/local-record-key/v1";
const LOCAL_RECORD_AUTHENTICATOR_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/local-record-authenticator/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalStorageOperationError {
    EntropyUnavailable,
    RecordVersionExhausted,
    WrongRecordContext,
    PlaintextTooLarge,
    CryptographicOperationFailed,
    Schema(FoundationSchemaError),
}

impl fmt::Display for LocalStorageOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyUnavailable => {
                formatter.write_str("the cryptographic entropy source is unavailable")
            }
            Self::RecordVersionExhausted => {
                formatter.write_str("the local-record version is exhausted")
            }
            Self::WrongRecordContext => {
                formatter.write_str("the local record is bound to a different storage context")
            }
            Self::PlaintextTooLarge => {
                formatter.write_str("the local-record plaintext exceeds the browser buffer limit")
            }
            Self::CryptographicOperationFailed => {
                formatter.write_str("the local-record cryptographic operation failed")
            }
            Self::Schema(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for LocalStorageOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Schema(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FoundationSchemaError> for LocalStorageOperationError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Schema(error)
    }
}

impl From<CanonicalCodecError> for LocalStorageOperationError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Schema(error.into())
    }
}

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
    pub fn try_generate(
        binding: LocalStorageBinding,
        entropy_source: &mut impl FallibleEntropySource,
    ) -> Result<Self, LocalStorageOperationError> {
        let mut root = Zeroizing::new([0u8; ACTION_STORAGE_ROOT_BYTE_LENGTH]);
        entropy_source
            .try_fill_bytes(root.as_mut())
            .map_err(|_| LocalStorageOperationError::EntropyUnavailable)?;
        Self::from_verified_root(binding, root).map_err(Into::into)
    }

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

    pub fn try_seal_initial_record(
        &self,
        identifier: LocalRecordIdentifier,
        creation_recovery_epoch: u64,
        plaintext: &[u8],
        entropy_source: &mut impl FallibleEntropySource,
    ) -> Result<LocalRecordEnvelope, LocalStorageOperationError> {
        if identifier.binding != self.binding {
            return Err(LocalStorageOperationError::WrongRecordContext);
        }
        let associated_data = LocalRecordAssociatedData::initial(
            identifier,
            creation_recovery_epoch,
            plaintext_byte_length(plaintext)?,
        )?;
        self.try_seal(associated_data, plaintext, entropy_source)
    }

    pub fn try_seal_successor_record(
        &self,
        predecessor: &AuthenticatedLocalRecordEnvelope<'_, '_>,
        creation_recovery_epoch: u64,
        plaintext: &[u8],
        entropy_source: &mut impl FallibleEntropySource,
    ) -> Result<LocalRecordEnvelope, LocalStorageOperationError> {
        if self.binding != predecessor.storage_root.binding
            || self.storage_root_commitment != predecessor.storage_root.storage_root_commitment
        {
            return Err(LocalStorageOperationError::WrongRecordContext);
        }
        let associated_data = LocalRecordAssociatedData::successor(
            predecessor,
            creation_recovery_epoch,
            plaintext_byte_length(plaintext)?,
        )?;
        self.try_seal(associated_data, plaintext, entropy_source)
    }

    fn try_seal(
        &self,
        associated_data: LocalRecordAssociatedData,
        plaintext: &[u8],
        entropy_source: &mut impl FallibleEntropySource,
    ) -> Result<LocalRecordEnvelope, LocalStorageOperationError> {
        if plaintext.len() > MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH {
            return Err(LocalStorageOperationError::PlaintextTooLarge);
        }
        let canonical_associated_data = associated_data.encode()?;
        let key_input = LocalRecordKeyInput::from_associated_data(&associated_data);
        let record_key = self.derive_record_key(&key_input)?;
        let mut nonce = Zeroizing::new([0u8; LOCAL_RECORD_NONCE_BYTE_LENGTH]);
        entropy_source
            .try_fill_bytes(nonce.as_mut())
            .map_err(|_| LocalStorageOperationError::EntropyUnavailable)?;
        let cipher = Aes256GcmSiv::new_from_slice(record_key.as_ref())
            .map_err(|_| LocalStorageOperationError::CryptographicOperationFailed)?;
        let mut ciphertext = Zeroizing::new(plaintext.to_vec());
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(nonce.as_ref()),
                &canonical_associated_data,
                ciphertext.as_mut(),
            )
            .map_err(|_| LocalStorageOperationError::CryptographicOperationFailed)?;
        let mut tag_bytes = [0u8; LOCAL_RECORD_TAG_BYTE_LENGTH];
        tag_bytes.copy_from_slice(&tag);
        let mut envelope = LocalRecordEnvelope {
            associated_data,
            nonce: *nonce,
            ciphertext: core::mem::take(ciphertext.as_mut()),
            tag: tag_bytes,
            record_authenticator: [0u8; LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH],
        };
        envelope.record_authenticator = self.record_authenticator(&envelope)?;
        Ok(envelope)
    }

    pub fn authenticate_envelope<'root, 'envelope>(
        &'root self,
        envelope: &'envelope LocalRecordEnvelope,
        expectation: &LocalRecordExpectation,
    ) -> VerificationResult<AuthenticatedLocalRecordEnvelope<'root, 'envelope>> {
        match self.authenticate_envelope_inner(envelope, expectation) {
            Ok(authenticated) => VerificationResult::valid(authenticated),
            Err(refusal_reason) => VerificationResult::refused(refusal_reason),
        }
    }

    fn authenticate_envelope_inner<'root, 'envelope>(
        &'root self,
        envelope: &'envelope LocalRecordEnvelope,
        expectation: &LocalRecordExpectation,
    ) -> Result<AuthenticatedLocalRecordEnvelope<'root, 'envelope>, RefusalReason> {
        envelope.validate().map_err(|error| error.refusal_reason)?;
        if expectation.identifier.binding != self.binding
            || envelope.associated_data.binding != self.binding
        {
            return Err(RefusalReason::WrongContext);
        }
        if envelope.associated_data.record_type != expectation.identifier.record_type
            || envelope.associated_data.record_identifier != expectation.identifier.identifier
        {
            return Err(RefusalReason::WrongContext);
        }
        if envelope.associated_data.record_version != expectation.record_version
            || envelope.associated_data.predecessor_record_hash
                != expectation.predecessor_record_hash
        {
            return Err(RefusalReason::ConsumedState);
        }
        let expected_authenticator = self
            .record_authenticator(envelope)
            .map_err(|error| operation_error_refusal_reason(&error))?;
        if !bool::from(expected_authenticator.ct_eq(envelope.record_authenticator.as_slice())) {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        let envelope_hash = envelope
            .envelope_hash()
            .map_err(|error| error.refusal_reason)?;
        Ok(AuthenticatedLocalRecordEnvelope {
            storage_root: self,
            envelope,
            envelope_hash,
        })
    }

    fn derive_record_key(
        &self,
        key_input: &LocalRecordKeyInput,
    ) -> Result<Zeroizing<[u8; LOCAL_RECORD_KEY_BYTE_LENGTH]>, LocalStorageOperationError> {
        if key_input.binding != self.binding {
            return Err(LocalStorageOperationError::WrongRecordContext);
        }
        let message = key_input.encode()?;
        Ok(kmac256::<LOCAL_RECORD_KEY_BYTE_LENGTH>(
            self.root.as_ref(),
            &message,
            LOCAL_RECORD_KEY_CUSTOMIZATION,
        ))
    }

    fn record_authenticator(
        &self,
        envelope: &LocalRecordEnvelope,
    ) -> Result<[u8; LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH], LocalStorageOperationError> {
        let message = envelope.authenticator_input_bytes()?;
        let authenticator = kmac256::<LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH>(
            self.root.as_ref(),
            &message,
            LOCAL_RECORD_AUTHENTICATOR_CUSTOMIZATION,
        );
        Ok(*authenticator)
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
        if !bool::from(expected_checksum.ct_eq(self.checksum.as_slice())) {
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
    nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
    ciphertext: [u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
    tag: [u8; LOCAL_RECORD_TAG_BYTE_LENGTH],
}

impl DeviceWrappedStorageRoot {
    pub const fn new(
        associated_data: DeviceWrappingAssociatedData,
        nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
        ciphertext: [u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
        tag: [u8; LOCAL_RECORD_TAG_BYTE_LENGTH],
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

    pub const fn nonce(&self) -> &[u8; LOCAL_RECORD_NONCE_BYTE_LENGTH] {
        &self.nonce
    }

    pub const fn ciphertext(&self) -> &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH] {
        &self.ciphertext
    }

    pub const fn tag(&self) -> &[u8; LOCAL_RECORD_TAG_BYTE_LENGTH] {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum LocalRecordType {
    ActionRandomness = 1,
    PublicCoinPrivateMaterial = 2,
    SourceVerifiableSecretSharingMaterial = 3,
    AggregateThresholdShare = 4,
    ProofAttempt = 5,
    BallotAttempt = 6,
    ExactOutputChunk = 7,
    SubjectState = 8,
    WitnessState = 9,
    CheckpointManifest = 10,
    CheckpointStateChunk = 11,
}

impl LocalRecordType {
    pub const ALL: [Self; 11] = [
        Self::ActionRandomness,
        Self::PublicCoinPrivateMaterial,
        Self::SourceVerifiableSecretSharingMaterial,
        Self::AggregateThresholdShare,
        Self::ProofAttempt,
        Self::BallotAttempt,
        Self::ExactOutputChunk,
        Self::SubjectState,
        Self::WitnessState,
        Self::CheckpointManifest,
        Self::CheckpointStateChunk,
    ];

    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::ActionRandomness),
            2 => Some(Self::PublicCoinPrivateMaterial),
            3 => Some(Self::SourceVerifiableSecretSharingMaterial),
            4 => Some(Self::AggregateThresholdShare),
            5 => Some(Self::ProofAttempt),
            6 => Some(Self::BallotAttempt),
            7 => Some(Self::ExactOutputChunk),
            8 => Some(Self::SubjectState),
            9 => Some(Self::WitnessState),
            10 => Some(Self::CheckpointManifest),
            11 => Some(Self::CheckpointStateChunk),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRecordIdentifier {
    binding: LocalStorageBinding,
    record_type: LocalRecordType,
    identifier: Hash512,
}

impl LocalRecordIdentifier {
    fn from_domain(
        binding: LocalStorageBinding,
        record_type: LocalRecordType,
        domain: &'static str,
        additional_items: &[CanonicalItem],
    ) -> SchemaResult<Self> {
        let mut items = Vec::with_capacity(4 + additional_items.len());
        items.extend_from_slice(&binding.canonical_items());
        items.extend_from_slice(additional_items);
        Ok(Self {
            binding,
            record_type,
            identifier: hash512(domain, &items)?,
        })
    }

    pub fn action_randomness(binding: LocalStorageBinding) -> SchemaResult<Self> {
        Self::from_domain(
            binding,
            LocalRecordType::ActionRandomness,
            "sealed-lattice/local-record-id/action-randomness/v1",
            &[],
        )
    }

    pub fn public_coin_private_material(binding: LocalStorageBinding) -> SchemaResult<Self> {
        Self::from_domain(
            binding,
            LocalRecordType::PublicCoinPrivateMaterial,
            "sealed-lattice/local-record-id/public-coin/v1",
            &[],
        )
    }

    pub fn source_verifiable_secret_sharing_material(
        binding: LocalStorageBinding,
        material_context_hash: Hash512,
    ) -> SchemaResult<Self> {
        Self::from_domain(
            binding,
            LocalRecordType::SourceVerifiableSecretSharingMaterial,
            "sealed-lattice/local-record-id/source-vss-material/v1",
            &[CanonicalItem::hash512(material_context_hash.into_bytes())],
        )
    }

    pub fn aggregate_threshold_share(
        binding: LocalStorageBinding,
        recipient_input_root: Hash512,
    ) -> SchemaResult<Self> {
        Self::from_domain(
            binding,
            LocalRecordType::AggregateThresholdShare,
            "sealed-lattice/local-record-id/aggregate-threshold-share/v1",
            &[CanonicalItem::hash512(recipient_input_root.into_bytes())],
        )
    }

    pub fn proof_attempt(
        binding: LocalStorageBinding,
        proof_header: &ProofObjectHeader,
        attempt_identifier: [u8; 32],
        limits: &CanonicalDecodeLimits,
    ) -> SchemaResult<Self> {
        proof_header.encode(limits)?;
        let statement =
            CanonicalTuple::decode(&proof_header.canonical_application_statement, limits)?;
        if ProofFamily::from_statement_schema_identifier(statement.schema_identifier).is_none()
            || statement.schema_version != FOUNDATION_PROTOCOL_VERSION
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "the proof-attempt statement family is unassigned",
            ));
        }
        Self::from_domain(
            binding,
            LocalRecordType::ProofAttempt,
            "sealed-lattice/local-record-id/proof-attempt/v1",
            &[
                CanonicalItem::variable_bytes(&proof_header.canonical_application_statement)?,
                CanonicalItem::fixed_bytes(attempt_identifier)?,
            ],
        )
    }

    pub fn ballot_attempt(
        binding: LocalStorageBinding,
        canonical_ballot_statement: &CanonicalTuple,
        attempt_identifier: [u8; 32],
    ) -> SchemaResult<Self> {
        if canonical_ballot_statement.schema_identifier
            != ProofFamily::BallotValidity.statement_schema_identifier()
            || canonical_ballot_statement.schema_version != FOUNDATION_PROTOCOL_VERSION
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "the ballot-attempt statement must use the ballot-validity schema",
            ));
        }
        Self::from_domain(
            binding,
            LocalRecordType::BallotAttempt,
            "sealed-lattice/local-record-id/ballot-attempt/v1",
            &[
                CanonicalItem::variable_bytes(canonical_ballot_statement.encode()?)?,
                CanonicalItem::fixed_bytes(attempt_identifier)?,
            ],
        )
    }

    pub fn exact_output_chunk(
        binding: LocalStorageBinding,
        capability_kind: StateCapabilityKind,
        exact_output_hash: Hash512,
        output_chunk_index: u64,
    ) -> SchemaResult<Self> {
        Self::from_domain(
            binding,
            LocalRecordType::ExactOutputChunk,
            "sealed-lattice/local-record-id/exact-output-chunk/v1",
            &[
                CanonicalItem::unsigned16(capability_kind.canonical_code()),
                CanonicalItem::hash512(exact_output_hash.into_bytes()),
                CanonicalItem::unsigned64(output_chunk_index),
            ],
        )
    }

    pub fn subject_state(
        binding: LocalStorageBinding,
        capability_kind: StateCapabilityKind,
    ) -> SchemaResult<Self> {
        let state_key = derive_state_key(
            binding.suite_id,
            binding.ceremony_context_hash,
            binding.action_context_hash,
            binding.participant_id,
            capability_kind,
        )
        .map_err(|error| schema_error(error.refusal_reason, error.message))?;
        Self::from_domain(
            binding,
            LocalRecordType::SubjectState,
            "sealed-lattice/local-record-id/state-subject/v1",
            &[CanonicalItem::hash512(state_key.into_bytes())],
        )
    }

    pub fn witness_state(
        binding: LocalStorageBinding,
        subject_participant_id: ParticipantIdentity,
        capability_kind: StateCapabilityKind,
    ) -> SchemaResult<Self> {
        let state_key = derive_state_key(
            binding.suite_id,
            binding.ceremony_context_hash,
            binding.action_context_hash,
            subject_participant_id,
            capability_kind,
        )
        .map_err(|error| schema_error(error.refusal_reason, error.message))?;
        Self::from_domain(
            binding,
            LocalRecordType::WitnessState,
            "sealed-lattice/local-record-id/state-witness/v1",
            &[CanonicalItem::hash512(state_key.into_bytes())],
        )
    }

    pub fn checkpoint_manifest(
        binding: LocalStorageBinding,
        checkpoint_manifest: &CheckpointManifest,
    ) -> SchemaResult<Self> {
        require_checkpoint_binding(binding, checkpoint_manifest)?;
        Ok(Self {
            binding,
            record_type: LocalRecordType::CheckpointManifest,
            identifier: checkpoint_manifest.checkpoint_identifier()?,
        })
    }

    pub fn checkpoint_state_chunk(
        binding: LocalStorageBinding,
        checkpoint_manifest: &CheckpointManifest,
        chunk_index: u32,
        chunk_digest: Hash512,
    ) -> SchemaResult<Self> {
        require_checkpoint_binding(binding, checkpoint_manifest)?;
        Ok(Self {
            binding,
            record_type: LocalRecordType::CheckpointStateChunk,
            identifier: checkpoint_manifest
                .checkpoint_chunk_identifier(chunk_index, chunk_digest)?,
        })
    }

    pub const fn binding(self) -> LocalStorageBinding {
        self.binding
    }

    pub const fn record_type(self) -> LocalRecordType {
        self.record_type
    }

    pub const fn identifier(self) -> Hash512 {
        self.identifier
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRecordKeyInput {
    binding: LocalStorageBinding,
    record_type: LocalRecordType,
    record_identifier: Hash512,
    record_version: u64,
}

impl LocalRecordKeyInput {
    fn from_associated_data(associated_data: &LocalRecordAssociatedData) -> Self {
        Self {
            binding: associated_data.binding,
            record_type: associated_data.record_type,
            record_identifier: associated_data.record_identifier,
            record_version: associated_data.record_version,
        }
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROTOCOL_VERSION),
                CanonicalItem::hash512(self.binding.suite_id.into_bytes()),
                CanonicalItem::hash512(self.binding.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.binding.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.binding.participant_id.into_bytes()),
                CanonicalItem::unsigned16(self.record_type.canonical_code()),
                CanonicalItem::hash512(self.record_identifier.into_bytes()),
                CanonicalItem::unsigned64(self.record_version),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits =
            bounded_canonical_decode_limits(limits, LOCAL_RECORD_KEY_INPUT_MAXIMUM_BYTE_LENGTH, 8);
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER, 8)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        Ok(Self {
            binding: LocalStorageBinding::new(
                read_hash(&tuple.items[1])?,
                read_hash(&tuple.items[2])?,
                read_hash(&tuple.items[3])?,
                read_participant_identity(&tuple.items[4])?,
            ),
            record_type: read_record_type(&tuple.items[5])?,
            record_identifier: read_hash(&tuple.items[6])?,
            record_version: read_u64(&tuple.items[7])?,
        })
    }

    pub const fn binding(self) -> LocalStorageBinding {
        self.binding
    }

    pub const fn record_type(self) -> LocalRecordType {
        self.record_type
    }

    pub const fn record_identifier(self) -> Hash512 {
        self.record_identifier
    }

    pub const fn record_version(self) -> u64 {
        self.record_version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecordAssociatedData {
    binding: LocalStorageBinding,
    record_type: LocalRecordType,
    record_identifier: Hash512,
    record_version: u64,
    creation_recovery_epoch: u64,
    predecessor_record_hash: Option<Hash512>,
    plaintext_byte_length: u64,
}

impl LocalRecordAssociatedData {
    fn initial(
        identifier: LocalRecordIdentifier,
        creation_recovery_epoch: u64,
        plaintext_byte_length: u64,
    ) -> SchemaResult<Self> {
        Self::new(
            identifier.binding,
            identifier.record_type,
            identifier.identifier,
            0,
            creation_recovery_epoch,
            None,
            plaintext_byte_length,
        )
    }

    fn successor(
        predecessor: &AuthenticatedLocalRecordEnvelope<'_, '_>,
        creation_recovery_epoch: u64,
        plaintext_byte_length: u64,
    ) -> Result<Self, LocalStorageOperationError> {
        let predecessor_data = &predecessor.envelope.associated_data;
        let record_version = predecessor_data
            .record_version
            .checked_add(1)
            .ok_or(LocalStorageOperationError::RecordVersionExhausted)?;
        Ok(Self::new(
            predecessor_data.binding,
            predecessor_data.record_type,
            predecessor_data.record_identifier,
            record_version,
            creation_recovery_epoch,
            Some(predecessor.envelope_hash),
            plaintext_byte_length,
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        binding: LocalStorageBinding,
        record_type: LocalRecordType,
        record_identifier: Hash512,
        record_version: u64,
        creation_recovery_epoch: u64,
        predecessor_record_hash: Option<Hash512>,
        plaintext_byte_length: u64,
    ) -> SchemaResult<Self> {
        if (record_version == 0) != predecessor_record_hash.is_none() {
            return Err(schema_error(
                RefusalReason::ConsumedState,
                "local-record version zero alone omits a predecessor",
            ));
        }
        if plaintext_byte_length > MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH as u64 {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "local-record plaintext exceeds the browser buffer limit",
            ));
        }
        Ok(Self {
            binding,
            record_type,
            record_identifier,
            record_version,
            creation_recovery_epoch,
            predecessor_record_hash,
            plaintext_byte_length,
        })
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Self::new(
            self.binding,
            self.record_type,
            self.record_identifier,
            self.record_version,
            self.creation_recovery_epoch,
            self.predecessor_record_hash,
            self.plaintext_byte_length,
        )?;
        let predecessor_item = self
            .predecessor_record_hash
            .map(|hash| CanonicalItem::hash512(hash.into_bytes()));
        Ok(CanonicalTuple::new(
            LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROTOCOL_VERSION),
                CanonicalItem::hash512(self.binding.suite_id.into_bytes()),
                CanonicalItem::hash512(self.binding.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.binding.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.binding.participant_id.into_bytes()),
                CanonicalItem::unsigned16(self.record_type.canonical_code()),
                CanonicalItem::hash512(self.record_identifier.into_bytes()),
                CanonicalItem::unsigned64(self.record_version),
                CanonicalItem::unsigned64(self.creation_recovery_epoch),
                CanonicalItem::optional(CanonicalItemType::Hash512, predecessor_item.as_ref())?,
                CanonicalItem::unsigned64(self.plaintext_byte_length),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits = bounded_canonical_decode_limits(
            limits,
            LOCAL_RECORD_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH,
            11,
        );
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, 11)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        Self::new(
            LocalStorageBinding::new(
                read_hash(&tuple.items[1])?,
                read_hash(&tuple.items[2])?,
                read_hash(&tuple.items[3])?,
                read_participant_identity(&tuple.items[4])?,
            ),
            read_record_type(&tuple.items[5])?,
            read_hash(&tuple.items[6])?,
            read_u64(&tuple.items[7])?,
            read_u64(&tuple.items[8])?,
            read_optional_hash(&tuple.items[9])?,
            read_u64(&tuple.items[10])?,
        )
    }

    pub const fn binding(&self) -> LocalStorageBinding {
        self.binding
    }

    pub const fn record_type(&self) -> LocalRecordType {
        self.record_type
    }

    pub const fn record_identifier(&self) -> Hash512 {
        self.record_identifier
    }

    pub const fn record_version(&self) -> u64 {
        self.record_version
    }

    pub const fn creation_recovery_epoch(&self) -> u64 {
        self.creation_recovery_epoch
    }

    pub const fn predecessor_record_hash(&self) -> Option<Hash512> {
        self.predecessor_record_hash
    }

    pub const fn plaintext_byte_length(&self) -> u64 {
        self.plaintext_byte_length
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRecordExpectation {
    identifier: LocalRecordIdentifier,
    record_version: u64,
    predecessor_record_hash: Option<Hash512>,
}

impl LocalRecordExpectation {
    pub const fn initial(identifier: LocalRecordIdentifier) -> Self {
        Self {
            identifier,
            record_version: 0,
            predecessor_record_hash: None,
        }
    }

    pub const fn identifier(self) -> LocalRecordIdentifier {
        self.identifier
    }

    pub const fn record_version(self) -> u64 {
        self.record_version
    }

    pub const fn predecessor_record_hash(self) -> Option<Hash512> {
        self.predecessor_record_hash
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LocalRecordEnvelope {
    associated_data: LocalRecordAssociatedData,
    nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
    ciphertext: Vec<u8>,
    tag: [u8; LOCAL_RECORD_TAG_BYTE_LENGTH],
    record_authenticator: [u8; LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH],
}

impl LocalRecordEnvelope {
    fn validate(&self) -> SchemaResult<()> {
        let declared_plaintext_length = usize::try_from(self.associated_data.plaintext_byte_length)
            .map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "local-record plaintext length does not fit this runtime",
                )
            })?;
        if self.ciphertext.len() != declared_plaintext_length
            || self.ciphertext.len() > MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "local-record ciphertext length does not match its associated data",
            ));
        }
        self.associated_data.encode()?;
        Ok(())
    }

    pub fn associated_data(&self) -> &LocalRecordAssociatedData {
        &self.associated_data
    }

    pub const fn nonce(&self) -> &[u8; LOCAL_RECORD_NONCE_BYTE_LENGTH] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub const fn tag(&self) -> &[u8; LOCAL_RECORD_TAG_BYTE_LENGTH] {
        &self.tag
    }

    pub const fn record_authenticator(&self) -> &[u8; LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH] {
        &self.record_authenticator
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
        Ok(CanonicalTuple::new(
            LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::variable_bytes(self.associated_data.encode()?)?,
                CanonicalItem::fixed_bytes(self.nonce)?,
                CanonicalItem::variable_bytes(&self.ciphertext)?,
                CanonicalItem::fixed_bytes(self.tag)?,
                CanonicalItem::fixed_bytes(self.record_authenticator)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits = bounded_local_record_decode_limits(limits);
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER, 5)?;
        let associated_data_bytes =
            read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?;
        let value = Self {
            associated_data: LocalRecordAssociatedData::decode(
                associated_data_bytes,
                &bounded_limits,
            )?,
            nonce: read_fixed_bytes(&tuple.items[1])?,
            ciphertext: read_variable_item(&tuple.items[2], CanonicalItemType::RawBytes)?.to_vec(),
            tag: read_fixed_bytes(&tuple.items[3])?,
            record_authenticator: read_fixed_bytes(&tuple.items[4])?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn envelope_hash(&self) -> SchemaResult<Hash512> {
        Ok(hash512(
            "sealed-lattice/local-record-envelope/v1",
            &[CanonicalItem::variable_bytes(self.encode()?)?],
        )?)
    }

    fn authenticator_input_bytes(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::variable_bytes(self.associated_data.encode()?)?,
                CanonicalItem::fixed_bytes(self.nonce)?,
                CanonicalItem::variable_bytes(&self.ciphertext)?,
                CanonicalItem::fixed_bytes(self.tag)?,
            ],
        )
        .encode()?)
    }
}

impl fmt::Debug for LocalRecordEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRecordEnvelope")
            .field("associated_data", &self.associated_data)
            .field("nonce", &self.nonce)
            .field("ciphertext_byte_length", &self.ciphertext.len())
            .field("tag", &self.tag)
            .field("record_authenticator", &self.record_authenticator)
            .finish()
    }
}

pub struct AuthenticatedLocalRecordEnvelope<'root, 'envelope> {
    storage_root: &'root ActionStorageRoot,
    envelope: &'envelope LocalRecordEnvelope,
    envelope_hash: Hash512,
}

impl<'root, 'envelope> AuthenticatedLocalRecordEnvelope<'root, 'envelope> {
    pub const fn envelope_hash(&self) -> Hash512 {
        self.envelope_hash
    }

    pub fn associated_data(&self) -> &LocalRecordAssociatedData {
        &self.envelope.associated_data
    }

    pub fn successor_expectation(
        &self,
    ) -> Result<LocalRecordExpectation, LocalStorageOperationError> {
        let record_version = self
            .envelope
            .associated_data
            .record_version
            .checked_add(1)
            .ok_or(LocalStorageOperationError::RecordVersionExhausted)?;
        Ok(LocalRecordExpectation {
            identifier: LocalRecordIdentifier {
                binding: self.envelope.associated_data.binding,
                record_type: self.envelope.associated_data.record_type,
                identifier: self.envelope.associated_data.record_identifier,
            },
            record_version,
            predecessor_record_hash: Some(self.envelope_hash),
        })
    }

    pub fn open(self) -> VerificationResult<LocalRecordPlaintext> {
        match self.open_inner() {
            Ok(plaintext) => VerificationResult::valid(plaintext),
            Err(refusal_reason) => VerificationResult::refused(refusal_reason),
        }
    }

    fn open_inner(self) -> Result<LocalRecordPlaintext, RefusalReason> {
        let associated_data_bytes = self
            .envelope
            .associated_data
            .encode()
            .map_err(|error| error.refusal_reason)?;
        let key_input = LocalRecordKeyInput::from_associated_data(&self.envelope.associated_data);
        let record_key = self
            .storage_root
            .derive_record_key(&key_input)
            .map_err(|error| operation_error_refusal_reason(&error))?;
        let cipher = Aes256GcmSiv::new_from_slice(record_key.as_ref())
            .map_err(|_| RefusalReason::WrongHashOrRoot)?;
        let mut plaintext = Zeroizing::new(self.envelope.ciphertext.clone());
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.envelope.nonce),
                &associated_data_bytes,
                plaintext.as_mut(),
                Tag::from_slice(&self.envelope.tag),
            )
            .map_err(|_| RefusalReason::WrongHashOrRoot)?;
        Ok(LocalRecordPlaintext(plaintext))
    }
}

impl fmt::Debug for AuthenticatedLocalRecordEnvelope<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedLocalRecordEnvelope")
            .field("envelope_hash", &self.envelope_hash)
            .field("plaintext", &"[NOT OPENED]")
            .finish()
    }
}

pub struct LocalRecordPlaintext(Zeroizing<Vec<u8>>);

impl LocalRecordPlaintext {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn into_zeroizing_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl fmt::Debug for LocalRecordPlaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRecordPlaintext")
            .field("byte_length", &self.0.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

fn derive_storage_root_commitment(
    binding: LocalStorageBinding,
    action_storage_root: &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
) -> SchemaResult<Hash512> {
    let mut items = Vec::with_capacity(5);
    items.extend_from_slice(&binding.canonical_items());
    items.push(CanonicalItem::fixed_bytes(action_storage_root)?);
    Ok(hash512("sealed-lattice/local-storage-root/v1", &items)?)
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

fn kmac256<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> Zeroizing<[u8; OUTPUT_BYTE_LENGTH]> {
    let mut output = Zeroizing::new([0u8; OUTPUT_BYTE_LENGTH]);
    let mut kmac = Kmac::v256(key, customization);
    kmac.update(message);
    kmac.finalize(output.as_mut());
    output
}

fn plaintext_byte_length(plaintext: &[u8]) -> Result<u64, LocalStorageOperationError> {
    if plaintext.len() > MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH {
        return Err(LocalStorageOperationError::PlaintextTooLarge);
    }
    u64::try_from(plaintext.len()).map_err(|_| LocalStorageOperationError::PlaintextTooLarge)
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

fn require_checkpoint_binding(
    binding: LocalStorageBinding,
    checkpoint_manifest: &CheckpointManifest,
) -> SchemaResult<()> {
    if checkpoint_manifest.suite_id != binding.suite_id
        || checkpoint_manifest.ceremony_context_hash != binding.ceremony_context_hash
        || checkpoint_manifest.action_context_hash != binding.action_context_hash
        || checkpoint_manifest.participant_id != binding.participant_id
    {
        return Err(schema_error(
            RefusalReason::WrongContext,
            "the checkpoint identifier has the wrong local-storage binding",
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

fn read_record_type(item: &CanonicalItem) -> SchemaResult<LocalRecordType> {
    LocalRecordType::from_canonical_code(read_u16(item)?).ok_or_else(|| {
        schema_error(
            RefusalReason::WrongTypeOrLength,
            "the local-record type is unassigned",
        )
    })
}

fn read_optional_hash(item: &CanonicalItem) -> SchemaResult<Option<Hash512>> {
    let bytes = read_item(item, CanonicalItemType::Optional)?;
    if bytes.len() < 3
        || u16::from_le_bytes([bytes[0], bytes[1]]) != CanonicalItemType::Hash512.canonical_code()
    {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "the optional predecessor has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 67 => {
            let hash_bytes: [u8; Hash512::BYTE_LENGTH] = bytes[3..].try_into().map_err(|_| {
                schema_error(
                    RefusalReason::MalformedEncoding,
                    "the optional predecessor hash is malformed",
                )
            })?;
            Ok(Some(Hash512::from_bytes(hash_bytes)))
        }
        _ => Err(schema_error(
            RefusalReason::MalformedEncoding,
            "the optional predecessor encoding is malformed",
        )),
    }
}

fn bounded_local_record_decode_limits(limits: &CanonicalDecodeLimits) -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: cmp::min(
            limits.maximum_tuple_byte_length,
            MAXIMUM_LOCAL_RECORD_ENVELOPE_BYTE_LENGTH,
        ),
        maximum_item_count: cmp::min(limits.maximum_item_count, 11),
        maximum_item_byte_length: cmp::min(
            limits.maximum_item_byte_length,
            MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH + 4,
        ),
        maximum_nesting_depth: limits.maximum_nesting_depth,
        maximum_cumulative_work_byte_length: cmp::min(
            limits.maximum_cumulative_work_byte_length,
            MAXIMUM_LOCAL_RECORD_ENVELOPE_BYTE_LENGTH * 4,
        ),
        maximum_cumulative_allocation_byte_length: cmp::min(
            limits.maximum_cumulative_allocation_byte_length,
            MAXIMUM_LOCAL_RECORD_ENVELOPE_BYTE_LENGTH * 2,
        ),
    }
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

fn operation_error_refusal_reason(error: &LocalStorageOperationError) -> RefusalReason {
    match error {
        LocalStorageOperationError::EntropyUnavailable
        | LocalStorageOperationError::PlaintextTooLarge => RefusalReason::OutsideSupportedProfile,
        LocalStorageOperationError::RecordVersionExhausted => RefusalReason::ConsumedState,
        LocalStorageOperationError::WrongRecordContext => RefusalReason::WrongContext,
        LocalStorageOperationError::CryptographicOperationFailed => RefusalReason::WrongHashOrRoot,
        LocalStorageOperationError::Schema(error) => error.refusal_reason,
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
