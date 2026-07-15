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
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    FoundationSchemaError, Hash512, ParticipantIdentity, RefusalReason, VerificationResult,
    hash_foundation_tuple_512 as hash512,
};

pub const DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER: u16 = 0x0300;
pub const LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER: u16 = 0x0301;
pub const STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER: u16 = 0x0302;
pub const STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x0303;
pub const LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0304;
pub const DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER: u16 = 0x0305;
pub const LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER: u16 = 0x0306;
pub const LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0307;
pub const ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0308;

pub const ACTION_STORAGE_ROOT_BYTE_LENGTH: usize = 48;
pub const DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH: usize = 12;
pub const DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH: usize = 16;
pub const LOCAL_RECORD_NONCE_BYTE_LENGTH: usize = 12;
pub const LOCAL_RECORD_TAG_BYTE_LENGTH: usize = 16;
pub const LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH: usize = 32;
pub const MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH: usize =
    FOUNDATION_PROFILE.stream_chunk_byte_length;

const FOUNDATION_PROTOCOL_VERSION: u16 = 1;
const ACTION_STORAGE_KEY_MATERIAL_BYTE_LENGTH: usize = 192;
const STORAGE_ROOT_COMMITMENT_PREIMAGE_BYTE_LENGTH: usize = 64;
const STORAGE_RECORD_KEY_DERIVATION_KEY_BYTE_LENGTH: usize = 64;
const STORAGE_RECORD_AUTHENTICATOR_KEY_BYTE_LENGTH: usize = 64;
const LOCAL_RECORD_KEY_BYTE_LENGTH: usize = 32;
const DEVICE_WRAPPED_STORAGE_ROOT_PLAINTEXT_BYTE_LENGTH: u64 = 48;
const RECOVERY_CHECKSUM_BYTE_LENGTH: usize = 16;
const ACTION_STORAGE_DERIVATION_INPUT_MAXIMUM_BYTE_LENGTH: usize = 400;
const STORAGE_ROOT_COMMITMENT_PAYLOAD_MAXIMUM_BYTE_LENGTH: usize = 78;
const RECOVERY_VALUE_CANONICAL_BYTE_LENGTH: usize = 442;
const RECOVERY_VALUE_BASE32_CHARACTER_LENGTH: usize = 708;
const DEVICE_WRAPPING_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH: usize = 380;
const DEVICE_WRAPPED_STORAGE_ROOT_MAXIMUM_BYTE_LENGTH: usize = 492;
const LOCAL_RECORD_KEY_INPUT_MAXIMUM_BYTE_LENGTH: usize = 700;
const LOCAL_RECORD_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH: usize = 900;
const LOCAL_RECORD_AUTHENTICATOR_INPUT_MAXIMUM_BYTE_LENGTH: usize =
    MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH
        + LOCAL_RECORD_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH
        + 128;
const LOCAL_RECORD_ENVELOPE_MAXIMUM_BYTE_LENGTH: usize = MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH
    + LOCAL_RECORD_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH
    + 128;

const ACTION_STORAGE_KEY_HIERARCHY_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/local-storage/key-hierarchy/v1";
const LOCAL_RECORD_KEY_CUSTOMIZATION: &[u8] = b"sealed-lattice/local-record-key/v1";
const LOCAL_RECORD_AUTHENTICATOR_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/local-record-authenticator/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LocalRecordType {
    ActionRandomness = 1,
    PublicCoinPrivateMaterial = 2,
    SourceVssMaterial = 3,
    AggregateThresholdShare = 4,
    ProofAttempt = 5,
    BallotAttempt = 6,
    ExactOutputChunk = 7,
    SubjectState = 8,
    WitnessState = 9,
    CheckpointManifest = 10,
    CheckpointChunk = 11,
}

impl LocalRecordType {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::ActionRandomness),
            2 => Some(Self::PublicCoinPrivateMaterial),
            3 => Some(Self::SourceVssMaterial),
            4 => Some(Self::AggregateThresholdShare),
            5 => Some(Self::ProofAttempt),
            6 => Some(Self::BallotAttempt),
            7 => Some(Self::ExactOutputChunk),
            8 => Some(Self::SubjectState),
            9 => Some(Self::WitnessState),
            10 => Some(Self::CheckpointManifest),
            11 => Some(Self::CheckpointChunk),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LocalRecordIdentifierInput<'input> {
    ActionRandomness,
    PublicCoinPrivateMaterial,
    SourceVssMaterial {
        material_context_hash: Hash512,
    },
    AggregateThresholdShare {
        recipient_input_root: Hash512,
    },
    ProofAttempt {
        application_slot_hash: Hash512,
    },
    BallotAttempt {
        canonical_ballot_statement_bytes: &'input [u8],
        ballot_encryption_attempt_identifier: &'input [u8; 32],
    },
    ExactOutputChunk {
        capability_kind: u16,
        exact_output_hash: Hash512,
        output_chunk_index: u64,
    },
    SubjectState {
        state_key: Hash512,
    },
    WitnessState {
        state_key: Hash512,
    },
    CheckpointManifest {
        runtime_build_manifest_hash: Hash512,
        checkpoint_lineage_identifier: &'input [u8; 32],
        operation_kind: u16,
        safe_boundary_ordinal: u32,
        ordered_source_digests: &'input [Hash512],
    },
    CheckpointChunk {
        checkpoint_identifier: Hash512,
        chunk_index: u32,
        chunk_digest: Hash512,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct LocalRecordSealInput<'input> {
    pub action_randomness_commitment: Hash512,
    pub identifier_input: LocalRecordIdentifierInput<'input>,
    pub record_version: u64,
    pub creation_recovery_epoch: u64,
    pub predecessor_record_hash: Option<Hash512>,
    pub nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
    pub plaintext: &'input [u8],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LocalRecordSealWithIdentifierInput<'input> {
    pub action_randomness_commitment: Hash512,
    pub record_type: LocalRecordType,
    pub record_identifier: Hash512,
    pub record_version: u64,
    pub creation_recovery_epoch: u64,
    pub predecessor_record_hash: Option<Hash512>,
    pub nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
    pub plaintext: &'input [u8],
}

impl LocalRecordIdentifierInput<'_> {
    pub const fn record_type(self) -> LocalRecordType {
        match self {
            Self::ActionRandomness => LocalRecordType::ActionRandomness,
            Self::PublicCoinPrivateMaterial => LocalRecordType::PublicCoinPrivateMaterial,
            Self::SourceVssMaterial { .. } => LocalRecordType::SourceVssMaterial,
            Self::AggregateThresholdShare { .. } => LocalRecordType::AggregateThresholdShare,
            Self::ProofAttempt { .. } => LocalRecordType::ProofAttempt,
            Self::BallotAttempt { .. } => LocalRecordType::BallotAttempt,
            Self::ExactOutputChunk { .. } => LocalRecordType::ExactOutputChunk,
            Self::SubjectState { .. } => LocalRecordType::SubjectState,
            Self::WitnessState { .. } => LocalRecordType::WitnessState,
            Self::CheckpointManifest { .. } => LocalRecordType::CheckpointManifest,
            Self::CheckpointChunk { .. } => LocalRecordType::CheckpointChunk,
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionStorageDerivationInput {
    binding: LocalStorageBinding,
}

impl ActionStorageDerivationInput {
    pub const fn new(binding: LocalStorageBinding) -> Self {
        Self { binding }
    }

    pub const fn binding(self) -> LocalStorageBinding {
        self.binding
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::unsigned16(FOUNDATION_PROTOCOL_VERSION),
                CanonicalItem::hash512(self.binding.suite_id.into_bytes()),
                CanonicalItem::hash512(self.binding.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.binding.action_context_hash.into_bytes()),
                CanonicalItem::participant_identity(self.binding.participant_id.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits = bounded_canonical_decode_limits(
            limits,
            ACTION_STORAGE_DERIVATION_INPUT_MAXIMUM_BYTE_LENGTH,
            5,
        );
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER, 5)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        Ok(Self::new(LocalStorageBinding::new(
            read_hash(&tuple.items[1])?,
            read_hash(&tuple.items[2])?,
            read_hash(&tuple.items[3])?,
            read_participant_identity(&tuple.items[4])?,
        )))
    }
}

pub fn derive_local_record_identifier(
    binding: LocalStorageBinding,
    identifier_input: LocalRecordIdentifierInput<'_>,
) -> SchemaResult<Hash512> {
    let binding_items = binding.canonical_items();
    let (domain, items) = match identifier_input {
        LocalRecordIdentifierInput::ActionRandomness => (
            "sealed-lattice/local-record-id/action-randomness/v1",
            Vec::from(binding_items),
        ),
        LocalRecordIdentifierInput::PublicCoinPrivateMaterial => (
            "sealed-lattice/local-record-id/public-coin/v1",
            Vec::from(binding_items),
        ),
        LocalRecordIdentifierInput::SourceVssMaterial {
            material_context_hash,
        } => {
            let mut items = Vec::from(binding_items);
            items.push(CanonicalItem::hash512(material_context_hash.into_bytes()));
            (
                "sealed-lattice/local-record-id/source-vss-material/v1",
                items,
            )
        }
        LocalRecordIdentifierInput::AggregateThresholdShare {
            recipient_input_root,
        } => {
            let mut items = Vec::from(binding_items);
            items.push(CanonicalItem::hash512(recipient_input_root.into_bytes()));
            (
                "sealed-lattice/local-record-id/aggregate-threshold-share/v1",
                items,
            )
        }
        LocalRecordIdentifierInput::ProofAttempt {
            application_slot_hash,
        } => {
            let mut items = Vec::from(binding_items);
            items.push(CanonicalItem::hash512(application_slot_hash.into_bytes()));
            ("sealed-lattice/local-record-id/proof-attempt/v1", items)
        }
        LocalRecordIdentifierInput::BallotAttempt {
            canonical_ballot_statement_bytes,
            ballot_encryption_attempt_identifier,
        } => {
            if canonical_ballot_statement_bytes.is_empty()
                || canonical_ballot_statement_bytes.len()
                    > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            {
                return Err(schema_error(
                    if canonical_ballot_statement_bytes.is_empty() {
                        RefusalReason::WrongTypeOrLength
                    } else {
                        RefusalReason::OutsideSupportedProfile
                    },
                    "the canonical ballot statement length is unsupported",
                ));
            }
            let mut items = Vec::from(binding_items);
            items.push(CanonicalItem::variable_bytes(
                canonical_ballot_statement_bytes,
            )?);
            items.push(CanonicalItem::fixed_bytes(
                ballot_encryption_attempt_identifier,
            )?);
            ("sealed-lattice/local-record-id/ballot-attempt/v1", items)
        }
        LocalRecordIdentifierInput::ExactOutputChunk {
            capability_kind,
            exact_output_hash,
            output_chunk_index,
        } => {
            let mut items = Vec::from(binding_items);
            items.push(CanonicalItem::unsigned16(capability_kind));
            items.push(CanonicalItem::hash512(exact_output_hash.into_bytes()));
            items.push(CanonicalItem::unsigned64(output_chunk_index));
            (
                "sealed-lattice/local-record-id/exact-output-chunk/v1",
                items,
            )
        }
        LocalRecordIdentifierInput::SubjectState { state_key } => {
            let mut items = Vec::from(binding_items);
            items.push(CanonicalItem::hash512(state_key.into_bytes()));
            ("sealed-lattice/local-record-id/state-subject/v1", items)
        }
        LocalRecordIdentifierInput::WitnessState { state_key } => {
            let mut items = Vec::from(binding_items);
            items.push(CanonicalItem::hash512(state_key.into_bytes()));
            ("sealed-lattice/local-record-id/state-witness/v1", items)
        }
        LocalRecordIdentifierInput::CheckpointManifest {
            runtime_build_manifest_hash,
            checkpoint_lineage_identifier,
            operation_kind,
            safe_boundary_ordinal,
            ordered_source_digests,
        } => {
            let source_digest_items = ordered_source_digests
                .iter()
                .map(|digest| CanonicalItem::hash512(digest.into_bytes()))
                .collect::<Vec<_>>();
            let mut items = Vec::with_capacity(10);
            items.push(CanonicalItem::hash512(
                runtime_build_manifest_hash.into_bytes(),
            ));
            items.extend(binding_items);
            items.push(CanonicalItem::fixed_bytes(checkpoint_lineage_identifier)?);
            items.push(CanonicalItem::unsigned16(operation_kind));
            items.push(CanonicalItem::unsigned32(safe_boundary_ordinal));
            items.push(CanonicalItem::homogeneous_list(
                CanonicalItemType::Hash512,
                &source_digest_items,
            )?);
            ("sealed-lattice/runtime/checkpoint/v1", items)
        }
        LocalRecordIdentifierInput::CheckpointChunk {
            checkpoint_identifier,
            chunk_index,
            chunk_digest,
        } => (
            "sealed-lattice/runtime/checkpoint-chunk/v1",
            vec![
                CanonicalItem::hash512(checkpoint_identifier.into_bytes()),
                CanonicalItem::unsigned32(chunk_index),
                CanonicalItem::hash512(chunk_digest.into_bytes()),
            ],
        ),
    };
    Ok(hash512(domain, &items)?)
}

pub struct ActionStorageRoot {
    binding: LocalStorageBinding,
    root: Zeroizing<[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH]>,
    storage_root_commitment: Hash512,
    storage_record_key_derivation_key:
        Zeroizing<[u8; STORAGE_RECORD_KEY_DERIVATION_KEY_BYTE_LENGTH]>,
    storage_record_authenticator_key: Zeroizing<[u8; STORAGE_RECORD_AUTHENTICATOR_KEY_BYTE_LENGTH]>,
}

impl ActionStorageRoot {
    pub(crate) fn from_verified_root(
        binding: LocalStorageBinding,
        root: Zeroizing<[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH]>,
    ) -> SchemaResult<Self> {
        let derived = derive_action_storage_key_material(binding, &root)?;
        Ok(Self {
            binding,
            root,
            storage_root_commitment: derived.storage_root_commitment,
            storage_record_key_derivation_key: derived.storage_record_key_derivation_key,
            storage_record_authenticator_key: derived.storage_record_authenticator_key,
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

    pub fn seal_local_record(
        &self,
        input: LocalRecordSealInput<'_>,
    ) -> SchemaResult<LocalRecordEnvelope> {
        let record_identifier =
            derive_local_record_identifier(self.binding, input.identifier_input)?;
        self.seal_local_record_with_identifier(LocalRecordSealWithIdentifierInput {
            action_randomness_commitment: input.action_randomness_commitment,
            record_type: input.identifier_input.record_type(),
            record_identifier,
            record_version: input.record_version,
            creation_recovery_epoch: input.creation_recovery_epoch,
            predecessor_record_hash: input.predecessor_record_hash,
            nonce: input.nonce,
            plaintext: input.plaintext,
        })
    }

    pub(crate) fn seal_local_record_with_identifier(
        &self,
        input: LocalRecordSealWithIdentifierInput<'_>,
    ) -> SchemaResult<LocalRecordEnvelope> {
        validate_local_record_plaintext_length(input.plaintext.len())?;
        let associated_data = LocalRecordAssociatedData::new(
            self.binding,
            input.action_randomness_commitment,
            input.record_type,
            input.record_identifier,
            input.record_version,
            input.creation_recovery_epoch,
            input.predecessor_record_hash,
            u64::try_from(input.plaintext.len()).map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "the local-record plaintext length does not fit u64",
                )
            })?,
        )?;
        let canonical_associated_data = associated_data.encode()?;
        let record_key = self.derive_record_key(&associated_data)?;
        let cipher = Aes256GcmSiv::new_from_slice(record_key.as_ref()).map_err(|_| {
            schema_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "AES-256-GCM-SIV rejected the fixed local-record key length",
            )
        })?;
        let mut ciphertext = Zeroizing::new(input.plaintext.to_vec());
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&input.nonce),
                &canonical_associated_data,
                ciphertext.as_mut(),
            )
            .map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "AES-256-GCM-SIV refused the bounded local-record plaintext",
                )
            })?;
        let mut tag_bytes = [0u8; LOCAL_RECORD_TAG_BYTE_LENGTH];
        tag_bytes.copy_from_slice(tag.as_slice());
        let record_authenticator = self.derive_record_authenticator(
            &canonical_associated_data,
            &input.nonce,
            &ciphertext,
            &tag_bytes,
        )?;
        LocalRecordEnvelope::new(
            associated_data,
            input.nonce,
            ciphertext.to_vec(),
            tag_bytes,
            record_authenticator,
        )
    }

    pub fn open_local_record(
        &self,
        action_randomness_commitment: Hash512,
        identifier_input: LocalRecordIdentifierInput<'_>,
        record_version: u64,
        creation_recovery_epoch: u64,
        predecessor_record_hash: Option<Hash512>,
        envelope: &LocalRecordEnvelope,
    ) -> VerificationResult<Zeroizing<Vec<u8>>> {
        let expected_identifier =
            match derive_local_record_identifier(self.binding, identifier_input) {
                Ok(identifier) => identifier,
                Err(error) => return VerificationResult::refused(error.refusal_reason),
            };
        self.open_local_record_with_identifier(
            action_randomness_commitment,
            identifier_input.record_type(),
            expected_identifier,
            record_version,
            creation_recovery_epoch,
            predecessor_record_hash,
            envelope,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_local_record_with_identifier(
        &self,
        action_randomness_commitment: Hash512,
        record_type: LocalRecordType,
        expected_identifier: Hash512,
        record_version: u64,
        creation_recovery_epoch: u64,
        predecessor_record_hash: Option<Hash512>,
        envelope: &LocalRecordEnvelope,
    ) -> VerificationResult<Zeroizing<Vec<u8>>> {
        let expected_associated_data = match LocalRecordAssociatedData::new(
            self.binding,
            action_randomness_commitment,
            record_type,
            expected_identifier,
            record_version,
            creation_recovery_epoch,
            predecessor_record_hash,
            envelope.associated_data.plaintext_byte_length,
        ) {
            Ok(associated_data) => associated_data,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        if envelope.associated_data != expected_associated_data {
            return VerificationResult::refused(RefusalReason::WrongContext);
        }
        let canonical_associated_data = match envelope.associated_data.encode() {
            Ok(bytes) => bytes,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let expected_authenticator = match self.derive_record_authenticator(
            &canonical_associated_data,
            &envelope.nonce,
            &envelope.ciphertext,
            &envelope.tag,
        ) {
            Ok(authenticator) => authenticator,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        if !bool::from(
            expected_authenticator
                .as_slice()
                .ct_eq(&envelope.record_authenticator),
        ) {
            return VerificationResult::refused(RefusalReason::WrongHashOrRoot);
        }
        let record_key = match self.derive_record_key(&envelope.associated_data) {
            Ok(key) => key,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let cipher = match Aes256GcmSiv::new_from_slice(record_key.as_ref()) {
            Ok(cipher) => cipher,
            Err(_) => {
                return VerificationResult::refused(RefusalReason::UnsupportedVersionOrSuite);
            }
        };
        let mut plaintext = Zeroizing::new(envelope.ciphertext.clone());
        if cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&envelope.nonce),
                &canonical_associated_data,
                plaintext.as_mut(),
                Tag::from_slice(&envelope.tag),
            )
            .is_err()
        {
            return VerificationResult::refused(RefusalReason::WrongHashOrRoot);
        }
        VerificationResult::valid(plaintext)
    }

    fn derive_record_key(
        &self,
        associated_data: &LocalRecordAssociatedData,
    ) -> SchemaResult<Zeroizing<[u8; LOCAL_RECORD_KEY_BYTE_LENGTH]>> {
        let key_input = LocalRecordKeyInput::from_associated_data(associated_data);
        Ok(Zeroizing::new(kmac256(
            self.storage_record_key_derivation_key.as_ref(),
            &key_input.encode()?,
            LOCAL_RECORD_KEY_CUSTOMIZATION,
        )))
    }

    fn derive_record_authenticator(
        &self,
        canonical_associated_data: &[u8],
        nonce: &[u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
        ciphertext: &[u8],
        tag: &[u8; LOCAL_RECORD_TAG_BYTE_LENGTH],
    ) -> SchemaResult<[u8; LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH]> {
        let authenticator_input = LocalRecordAuthenticatorInput::new(
            canonical_associated_data,
            *nonce,
            ciphertext,
            *tag,
        )?;
        Ok(kmac256(
            self.storage_record_authenticator_key.as_ref(),
            &authenticator_input.encode()?,
            LOCAL_RECORD_AUTHENTICATOR_CUSTOMIZATION,
        ))
    }
}

impl fmt::Debug for ActionStorageRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionStorageRoot")
            .field("binding", &self.binding)
            .field("root", &"[REDACTED]")
            .field("storage_root_commitment", &self.storage_root_commitment)
            .field("storage_record_key_derivation_key", &"[REDACTED]")
            .field("storage_record_authenticator_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRecordKeyInput {
    binding: LocalStorageBinding,
    action_randomness_commitment: Hash512,
    record_type: LocalRecordType,
    record_identifier: Hash512,
    record_version: u64,
}

impl LocalRecordKeyInput {
    pub const fn new(
        binding: LocalStorageBinding,
        action_randomness_commitment: Hash512,
        record_type: LocalRecordType,
        record_identifier: Hash512,
        record_version: u64,
    ) -> Self {
        Self {
            binding,
            action_randomness_commitment,
            record_type,
            record_identifier,
            record_version,
        }
    }

    pub const fn binding(self) -> LocalStorageBinding {
        self.binding
    }

    pub const fn action_randomness_commitment(self) -> Hash512 {
        self.action_randomness_commitment
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

    fn from_associated_data(associated_data: &LocalRecordAssociatedData) -> Self {
        Self::new(
            associated_data.binding,
            associated_data.action_randomness_commitment,
            associated_data.record_type,
            associated_data.record_identifier,
            associated_data.record_version,
        )
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
                CanonicalItem::hash512(self.action_randomness_commitment.into_bytes()),
                CanonicalItem::unsigned16(self.record_type.canonical_code()),
                CanonicalItem::hash512(self.record_identifier.into_bytes()),
                CanonicalItem::unsigned64(self.record_version),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let bounded_limits =
            bounded_canonical_decode_limits(limits, LOCAL_RECORD_KEY_INPUT_MAXIMUM_BYTE_LENGTH, 9);
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER, 9)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        Ok(Self::new(
            LocalStorageBinding::new(
                read_hash(&tuple.items[1])?,
                read_hash(&tuple.items[2])?,
                read_hash(&tuple.items[3])?,
                read_participant_identity(&tuple.items[4])?,
            ),
            read_hash(&tuple.items[5])?,
            read_local_record_type(&tuple.items[6])?,
            read_hash(&tuple.items[7])?,
            read_u64(&tuple.items[8])?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRecordAssociatedData {
    binding: LocalStorageBinding,
    action_randomness_commitment: Hash512,
    record_type: LocalRecordType,
    record_identifier: Hash512,
    record_version: u64,
    creation_recovery_epoch: u64,
    predecessor_record_hash: Option<Hash512>,
    plaintext_byte_length: u64,
}

impl LocalRecordAssociatedData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: LocalStorageBinding,
        action_randomness_commitment: Hash512,
        record_type: LocalRecordType,
        record_identifier: Hash512,
        record_version: u64,
        creation_recovery_epoch: u64,
        predecessor_record_hash: Option<Hash512>,
        plaintext_byte_length: u64,
    ) -> SchemaResult<Self> {
        if (record_version == 0) != predecessor_record_hash.is_none() {
            return Err(schema_error(
                RefusalReason::WrongContext,
                "local-record predecessor presence does not match the record version",
            ));
        }
        let plaintext_byte_length_as_usize =
            usize::try_from(plaintext_byte_length).map_err(|_| {
                schema_error(
                    RefusalReason::OutsideSupportedProfile,
                    "the local-record plaintext length does not fit the runtime",
                )
            })?;
        validate_local_record_plaintext_length(plaintext_byte_length_as_usize)?;
        Ok(Self {
            binding,
            action_randomness_commitment,
            record_type,
            record_identifier,
            record_version,
            creation_recovery_epoch,
            predecessor_record_hash,
            plaintext_byte_length,
        })
    }

    pub const fn binding(self) -> LocalStorageBinding {
        self.binding
    }

    pub const fn action_randomness_commitment(self) -> Hash512 {
        self.action_randomness_commitment
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

    pub const fn creation_recovery_epoch(self) -> u64 {
        self.creation_recovery_epoch
    }

    pub const fn predecessor_record_hash(self) -> Option<Hash512> {
        self.predecessor_record_hash
    }

    pub const fn plaintext_byte_length(self) -> u64 {
        self.plaintext_byte_length
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
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
                CanonicalItem::hash512(self.action_randomness_commitment.into_bytes()),
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
            12,
        );
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, 12)?;
        require_protocol_version(read_u16(&tuple.items[0])?)?;
        Self::new(
            LocalStorageBinding::new(
                read_hash(&tuple.items[1])?,
                read_hash(&tuple.items[2])?,
                read_hash(&tuple.items[3])?,
                read_participant_identity(&tuple.items[4])?,
            ),
            read_hash(&tuple.items[5])?,
            read_local_record_type(&tuple.items[6])?,
            read_hash(&tuple.items[7])?,
            read_u64(&tuple.items[8])?,
            read_u64(&tuple.items[9])?,
            read_optional_hash(&tuple.items[10])?,
            read_u64(&tuple.items[11])?,
        )
    }
}

struct LocalRecordAuthenticatorInput<'input> {
    canonical_associated_data: &'input [u8],
    nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
    ciphertext: &'input [u8],
    tag: [u8; LOCAL_RECORD_TAG_BYTE_LENGTH],
}

impl<'input> LocalRecordAuthenticatorInput<'input> {
    fn new(
        canonical_associated_data: &'input [u8],
        nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
        ciphertext: &'input [u8],
        tag: [u8; LOCAL_RECORD_TAG_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        if canonical_associated_data.len() > LOCAL_RECORD_ASSOCIATED_DATA_MAXIMUM_BYTE_LENGTH {
            return Err(schema_error(
                RefusalReason::OutsideSupportedProfile,
                "the local-record associated data exceeds its bound",
            ));
        }
        validate_local_record_plaintext_length(ciphertext.len())?;
        Ok(Self {
            canonical_associated_data,
            nonce,
            ciphertext,
            tag,
        })
    }

    fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_PROTOCOL_VERSION,
            vec![
                CanonicalItem::variable_bytes(self.canonical_associated_data)?,
                CanonicalItem::fixed_bytes(self.nonce)?,
                CanonicalItem::variable_bytes(self.ciphertext)?,
                CanonicalItem::fixed_bytes(self.tag)?,
            ],
        )
        .encode()?)
    }
}

pub(crate) fn round_trip_local_record_authenticator_input(
    bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> SchemaResult<Vec<u8>> {
    let bounded_limits = bounded_canonical_decode_limits(
        limits,
        LOCAL_RECORD_AUTHENTICATOR_INPUT_MAXIMUM_BYTE_LENGTH,
        4,
    );
    let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
    require_header(
        &tuple,
        LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER,
        4,
    )?;
    let canonical_associated_data =
        read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?;
    let associated_data = LocalRecordAssociatedData::decode(canonical_associated_data, limits)?;
    if associated_data.encode()? != canonical_associated_data {
        return Err(schema_error(
            RefusalReason::MalformedEncoding,
            "the local-record authenticator input contains non-canonical associated data",
        ));
    }
    let nonce = read_fixed_bytes(&tuple.items[1])?;
    let ciphertext = read_variable_item(&tuple.items[2], CanonicalItemType::RawBytes)?;
    if u64::try_from(ciphertext.len()).ok() != Some(associated_data.plaintext_byte_length()) {
        return Err(schema_error(
            RefusalReason::WrongTypeOrLength,
            "the local-record authenticator ciphertext length does not match its associated data",
        ));
    }
    let tag = read_fixed_bytes(&tuple.items[3])?;
    LocalRecordAuthenticatorInput::new(canonical_associated_data, nonce, ciphertext, tag)?.encode()
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
    pub fn new(
        associated_data: LocalRecordAssociatedData,
        nonce: [u8; LOCAL_RECORD_NONCE_BYTE_LENGTH],
        ciphertext: Vec<u8>,
        tag: [u8; LOCAL_RECORD_TAG_BYTE_LENGTH],
        record_authenticator: [u8; LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        validate_local_record_plaintext_length(ciphertext.len())?;
        if u64::try_from(ciphertext.len()).ok() != Some(associated_data.plaintext_byte_length) {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "the local-record ciphertext length does not match its associated data",
            ));
        }
        Ok(Self {
            associated_data,
            nonce,
            ciphertext,
            tag,
            record_authenticator,
        })
    }

    pub const fn associated_data(&self) -> LocalRecordAssociatedData {
        self.associated_data
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
        let bounded_limits =
            bounded_canonical_decode_limits(limits, LOCAL_RECORD_ENVELOPE_MAXIMUM_BYTE_LENGTH, 5);
        let tuple = CanonicalTuple::decode(bytes, &bounded_limits)?;
        require_header(&tuple, LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER, 5)?;
        let associated_data = LocalRecordAssociatedData::decode(
            read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?,
            limits,
        )?;
        Self::new(
            associated_data,
            read_fixed_bytes(&tuple.items[1])?,
            read_variable_item(&tuple.items[2], CanonicalItemType::RawBytes)?.to_vec(),
            read_fixed_bytes(&tuple.items[3])?,
            read_fixed_bytes(&tuple.items[4])?,
        )
    }

    pub fn envelope_hash(&self) -> SchemaResult<Hash512> {
        derive_local_record_envelope_hash(&self.encode()?)
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

pub fn derive_local_record_envelope_hash(
    canonical_local_record_envelope_bytes: &[u8],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        "sealed-lattice/local-record-envelope/v1",
        &[CanonicalItem::variable_bytes(
            canonical_local_record_envelope_bytes,
        )?],
    )?)
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

struct DerivedActionStorageKeyMaterial {
    storage_root_commitment: Hash512,
    storage_record_key_derivation_key:
        Zeroizing<[u8; STORAGE_RECORD_KEY_DERIVATION_KEY_BYTE_LENGTH]>,
    storage_record_authenticator_key: Zeroizing<[u8; STORAGE_RECORD_AUTHENTICATOR_KEY_BYTE_LENGTH]>,
}

fn derive_action_storage_key_material(
    binding: LocalStorageBinding,
    action_storage_root: &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
) -> SchemaResult<DerivedActionStorageKeyMaterial> {
    let canonical_derivation_input = ActionStorageDerivationInput::new(binding).encode()?;
    let key_material = Zeroizing::new(kmac256::<ACTION_STORAGE_KEY_MATERIAL_BYTE_LENGTH>(
        action_storage_root,
        &canonical_derivation_input,
        ACTION_STORAGE_KEY_HIERARCHY_CUSTOMIZATION,
    ));
    let mut commitment_preimage =
        Zeroizing::new([0u8; STORAGE_ROOT_COMMITMENT_PREIMAGE_BYTE_LENGTH]);
    commitment_preimage
        .copy_from_slice(&key_material[..STORAGE_ROOT_COMMITMENT_PREIMAGE_BYTE_LENGTH]);
    let storage_root_commitment = hash512(
        "sealed-lattice/local-storage-root/v1",
        &[
            CanonicalItem::variable_bytes(&canonical_derivation_input)?,
            CanonicalItem::fixed_bytes(commitment_preimage.as_ref())?,
        ],
    )?;
    let mut storage_record_key_derivation_key =
        Zeroizing::new([0u8; STORAGE_RECORD_KEY_DERIVATION_KEY_BYTE_LENGTH]);
    storage_record_key_derivation_key.copy_from_slice(
        &key_material[STORAGE_ROOT_COMMITMENT_PREIMAGE_BYTE_LENGTH
            ..STORAGE_ROOT_COMMITMENT_PREIMAGE_BYTE_LENGTH
                + STORAGE_RECORD_KEY_DERIVATION_KEY_BYTE_LENGTH],
    );
    let mut storage_record_authenticator_key =
        Zeroizing::new([0u8; STORAGE_RECORD_AUTHENTICATOR_KEY_BYTE_LENGTH]);
    storage_record_authenticator_key.copy_from_slice(
        &key_material[STORAGE_ROOT_COMMITMENT_PREIMAGE_BYTE_LENGTH
            + STORAGE_RECORD_KEY_DERIVATION_KEY_BYTE_LENGTH..],
    );
    Ok(DerivedActionStorageKeyMaterial {
        storage_root_commitment,
        storage_record_key_derivation_key,
        storage_record_authenticator_key,
    })
}

fn derive_storage_root_commitment(
    binding: LocalStorageBinding,
    action_storage_root: &[u8; ACTION_STORAGE_ROOT_BYTE_LENGTH],
) -> SchemaResult<Hash512> {
    Ok(derive_action_storage_key_material(binding, action_storage_root)?.storage_root_commitment)
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

fn read_local_record_type(item: &CanonicalItem) -> SchemaResult<LocalRecordType> {
    LocalRecordType::from_canonical_code(read_u16(item)?).ok_or_else(|| {
        schema_error(
            RefusalReason::WrongTypeOrLength,
            "the local-record type is outside the closed assignment",
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
            "the local-record predecessor optional has the wrong contained type",
        ));
    }
    match bytes[2] {
        0 if bytes.len() == 3 => Ok(None),
        1 if bytes.len() == 3 + Hash512::BYTE_LENGTH => {
            let hash_bytes: [u8; Hash512::BYTE_LENGTH] = bytes[3..].try_into().map_err(|_| {
                schema_error(
                    RefusalReason::WrongTypeOrLength,
                    "the local-record predecessor hash has the wrong length",
                )
            })?;
            Ok(Some(Hash512::from_bytes(hash_bytes)))
        }
        _ => Err(schema_error(
            RefusalReason::MalformedEncoding,
            "the local-record predecessor optional is malformed",
        )),
    }
}

fn validate_local_record_plaintext_length(byte_length: usize) -> SchemaResult<()> {
    if byte_length > MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH {
        return Err(schema_error(
            RefusalReason::OutsideSupportedProfile,
            "the local-record plaintext exceeds the stream-chunk bound",
        ));
    }
    Ok(())
}

fn kmac256<const OUTPUT_BYTE_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
) -> [u8; OUTPUT_BYTE_LENGTH] {
    let mut output = [0u8; OUTPUT_BYTE_LENGTH];
    let mut kmac = Kmac::v256(key, customization);
    kmac.update(message);
    kmac.finalize(&mut output);
    output
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
