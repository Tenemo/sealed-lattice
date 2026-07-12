use core::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use fips203::{
    ml_kem_768,
    traits::{Decaps as KemDecaps, Encaps as KemEncaps, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{SerDes as SignatureSerDes, Signer, Verifier},
};
use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::{Zeroize, Zeroizing};

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
    SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER, read_ascii, read_fixed_bytes, read_hash,
    read_hash_list, read_item, read_u16, read_u64, read_variable_item, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalStreamDomain,
    CanonicalStreamVerifier, CanonicalTuple, FOUNDATION_PROFILE, FoundationSchemaError, Hash512,
    ParticipantIdentity, RefusalReason, Roster, StreamDescriptor, VerificationResult,
    derive_canonical_stream_descriptor, hash512,
};

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const MAILBOX_PROTOCOL_VERSION: u16 = 1;
const MAILBOX_KEY_SCHEDULE_DOMAIN: &str = "sealed-lattice/mailbox/key-schedule/v1";
const MAILBOX_DIRECTION: &str = "source-to-recipient";
const MAILBOX_ENVELOPE_VERSION: u16 = 1;
const MAILBOX_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/mailbox-signature/v1";
const KEM_CIPHERTEXT_HASH_DOMAIN: &str = "sealed-lattice/mailbox/kem-ciphertext/v1";
const HKDF_EXTRACT_SALT_DOMAIN: &str = "sealed-lattice/mailbox/hkdf-extract-salt/v1";
const MAILBOX_ENVELOPE_HASH_DOMAIN: &str = "sealed-lattice/mailbox/envelope/v1";
const ML_KEM_768_DECAPSULATION_PKE_KEY_BYTE_LENGTH: usize = 1_152;
const MAILBOX_HKDF_OUTPUT_BYTE_LENGTH: usize = 44;

pub const ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH: usize = ml_kem_768::EK_LEN;
pub const ML_KEM_768_DECAPSULATION_KEY_BYTE_LENGTH: usize = ml_kem_768::DK_LEN;
pub const ML_KEM_768_CIPHERTEXT_BYTE_LENGTH: usize = ml_kem_768::CT_LEN;
pub const ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = ml_dsa_65::SIG_LEN;
pub const ML_DSA_65_SIGNING_KEY_BYTE_LENGTH: usize = ml_dsa_65::SK_LEN;
pub const MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
pub const AES_256_KEY_BYTE_LENGTH: usize = 32;
pub const AES_GCM_NONCE_BYTE_LENGTH: usize = 12;
pub const AES_GCM_TAG_BYTE_LENGTH: usize = 16;

type MailboxResult<Value> = Result<Value, FoundationSchemaError>;

/// The two payload families admitted by the version-one private mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MailboxPayloadType {
    PublicRandomnessRecoveryShare = 1,
    RecipientPrivateVerifiableSecretSharingShare = 2,
}

impl MailboxPayloadType {
    pub const ALL: [Self; 2] = [
        Self::PublicRandomnessRecoveryShare,
        Self::RecipientPrivateVerifiableSecretSharingShare,
    ];

    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    const fn try_from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::PublicRandomnessRecoveryShare),
            2 => Some(Self::RecipientPrivateVerifiableSecretSharingShare),
            _ => None,
        }
    }
}

/// Canonical input to the fixed HKDF-SHA-384 mailbox key schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxKeyScheduleInput {
    pub suite_id: Hash512,
    pub ceremony_context_hash: Hash512,
    pub action_context_hash: Hash512,
    pub roster_hash: Hash512,
    pub source_participant_id: ParticipantIdentity,
    pub recipient_participant_id: ParticipantIdentity,
    pub producer_sequence: u64,
    pub envelope_attempt_identifier: [u8; MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    pub payload_type: MailboxPayloadType,
    pub statement_hash: Hash512,
    pub ordered_material_roots: Vec<Hash512>,
    pub kem_ciphertext_hash: Hash512,
}

impl MailboxKeyScheduleInput {
    const ITEM_COUNT: usize = 16;

    pub fn encode(&self) -> MailboxResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            self.canonical_field_items()?,
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> MailboxResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(
            &tuple,
            MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
            Self::ITEM_COUNT,
        )?;
        Self::from_canonical_field_items(&tuple.items)
    }

    fn canonical_field_items(&self) -> MailboxResult<Vec<CanonicalItem>> {
        let material_roots = self
            .ordered_material_roots
            .iter()
            .map(|root| CanonicalItem::hash512(root.into_bytes()))
            .collect::<Vec<_>>();
        Ok(vec![
            CanonicalItem::nonempty_ascii(MAILBOX_KEY_SCHEDULE_DOMAIN)?,
            CanonicalItem::unsigned16(MAILBOX_PROTOCOL_VERSION),
            CanonicalItem::hash512(self.suite_id.into_bytes()),
            CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(self.action_context_hash.into_bytes()),
            CanonicalItem::hash512(self.roster_hash.into_bytes()),
            CanonicalItem::participant_identity(self.source_participant_id.into_bytes()),
            CanonicalItem::participant_identity(self.recipient_participant_id.into_bytes()),
            CanonicalItem::unsigned64(self.producer_sequence),
            CanonicalItem::fixed_bytes(self.envelope_attempt_identifier)?,
            CanonicalItem::nonempty_ascii(MAILBOX_DIRECTION)?,
            CanonicalItem::unsigned16(self.payload_type.canonical_code()),
            CanonicalItem::unsigned16(1),
            CanonicalItem::hash512(self.statement_hash.into_bytes()),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &material_roots)?,
            CanonicalItem::hash512(self.kem_ciphertext_hash.into_bytes()),
        ])
    }

    fn from_canonical_field_items(items: &[CanonicalItem]) -> MailboxResult<Self> {
        if items.len() != Self::ITEM_COUNT {
            return Err(mailbox_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox key-schedule input has the wrong item count",
            ));
        }
        if read_ascii(&items[0])? != MAILBOX_KEY_SCHEDULE_DOMAIN
            || read_u16(&items[1])? != MAILBOX_PROTOCOL_VERSION
        {
            return Err(mailbox_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "mailbox key-schedule domain or protocol version is unsupported",
            ));
        }
        if read_ascii(&items[10])? != MAILBOX_DIRECTION {
            return Err(mailbox_error(
                RefusalReason::WrongContext,
                "mailbox direction is unsupported",
            ));
        }
        let payload_type = MailboxPayloadType::try_from_canonical_code(read_u16(&items[11])?)
            .ok_or_else(|| {
                mailbox_error(
                    RefusalReason::WrongTypeOrLength,
                    "mailbox payload type is not assigned",
                )
            })?;
        if read_u16(&items[12])? != 1 {
            return Err(mailbox_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "mailbox payload version is unsupported",
            ));
        }

        Ok(Self {
            suite_id: read_hash(&items[2])?,
            ceremony_context_hash: read_hash(&items[3])?,
            action_context_hash: read_hash(&items[4])?,
            roster_hash: read_hash(&items[5])?,
            source_participant_id: read_participant_identity(&items[6])?,
            recipient_participant_id: read_participant_identity(&items[7])?,
            producer_sequence: read_u64(&items[8])?,
            envelope_attempt_identifier: read_fixed_bytes(&items[9])?,
            payload_type,
            statement_hash: read_hash(&items[13])?,
            ordered_material_roots: read_hash_list(&items[14])?,
            kem_ciphertext_hash: read_hash(&items[15])?,
        })
    }
}

/// The complete AES-GCM associated data, with the key-schedule fields in the
/// same canonical order rather than a second producer-selected representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxAssociatedData {
    pub key_schedule_input: MailboxKeyScheduleInput,
    pub plaintext_byte_length: u64,
}

impl MailboxAssociatedData {
    const ITEM_COUNT: usize = MailboxKeyScheduleInput::ITEM_COUNT + 2;

    pub fn new(
        key_schedule_input: MailboxKeyScheduleInput,
        plaintext_byte_length: u64,
    ) -> MailboxResult<Self> {
        validate_plaintext_byte_length(plaintext_byte_length)?;
        Ok(Self {
            key_schedule_input,
            plaintext_byte_length,
        })
    }

    pub fn encode(&self) -> MailboxResult<Vec<u8>> {
        validate_plaintext_byte_length(self.plaintext_byte_length)?;
        let mut items = self.key_schedule_input.canonical_field_items()?;
        items.push(CanonicalItem::unsigned64(self.plaintext_byte_length));
        items.push(CanonicalItem::unsigned16(MAILBOX_ENVELOPE_VERSION));
        Ok(CanonicalTuple::new(
            MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            items,
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> MailboxResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> MailboxResult<Self> {
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(
            &tuple,
            MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
            Self::ITEM_COUNT,
        )?;
        let key_schedule_input = MailboxKeyScheduleInput::from_canonical_field_items(
            &tuple.items[..MailboxKeyScheduleInput::ITEM_COUNT],
        )?;
        let plaintext_byte_length = read_u64(&tuple.items[16])?;
        validate_plaintext_byte_length(plaintext_byte_length)?;
        if read_u16(&tuple.items[17])? != MAILBOX_ENVELOPE_VERSION {
            return Err(mailbox_error(
                RefusalReason::UnsupportedVersionOrSuite,
                "mailbox envelope version is unsupported",
            ));
        }
        Ok(Self {
            key_schedule_input,
            plaintext_byte_length,
        })
    }
}

/// Canonical signed carrier for one private mailbox ciphertext stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMailboxEnvelope {
    pub associated_data: MailboxAssociatedData,
    pub kem_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH],
    pub ciphertext_descriptor: StreamDescriptor,
    pub gcm_tag: [u8; AES_GCM_TAG_BYTE_LENGTH],
    pub source_signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl SignedMailboxEnvelope {
    pub fn encode(&self) -> MailboxResult<Vec<u8>> {
        self.validate_bindings()?;
        Ok(CanonicalTuple::new(
            SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::variable_bytes(self.associated_data.encode()?)?,
                CanonicalItem::fixed_bytes(self.kem_ciphertext)?,
                CanonicalItem::nested_tuple(&self.ciphertext_descriptor.canonical_tuple()?)?,
                CanonicalItem::fixed_bytes(self.gcm_tag)?,
                CanonicalItem::fixed_bytes(self.source_signature)?,
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> MailboxResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    pub(super) fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> MailboxResult<Self> {
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER, 5)?;
        let descriptor_tuple = CanonicalTuple::decode_with_budget(
            read_item(&tuple.items[2], CanonicalItemType::NestedTuple)?,
            limits,
            budget,
        )?;
        let envelope = Self {
            associated_data: MailboxAssociatedData::decode_with_budget(
                read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?,
                limits,
                budget,
            )?,
            kem_ciphertext: read_fixed_bytes(&tuple.items[1])?,
            ciphertext_descriptor: StreamDescriptor::from_tuple(&descriptor_tuple)?,
            gcm_tag: read_fixed_bytes(&tuple.items[3])?,
            source_signature: read_fixed_bytes(&tuple.items[4])?,
        };
        envelope.validate_bindings()?;
        Ok(envelope)
    }

    pub fn envelope_hash(&self) -> MailboxResult<Hash512> {
        self.validate_bindings()?;
        let associated_data_bytes = self.associated_data.encode()?;
        let descriptor_bytes = self.ciphertext_descriptor.encode()?;
        Ok(hash512(
            MAILBOX_ENVELOPE_HASH_DOMAIN,
            &[
                CanonicalItem::variable_bytes(associated_data_bytes)?,
                CanonicalItem::fixed_bytes(self.kem_ciphertext)?,
                CanonicalItem::variable_bytes(descriptor_bytes)?,
                CanonicalItem::fixed_bytes(self.gcm_tag)?,
            ],
        )?)
    }

    /// Authenticates this envelope with the source key selected only from the
    /// external roster. Consuming `self` prevents a post-verification mutation.
    pub fn authenticate(
        self,
        roster: &Roster,
        expected_binding: &MailboxBindingExpectation,
    ) -> VerificationResult<AuthenticatedMailboxEnvelope> {
        match self.authenticate_internal(roster, expected_binding) {
            Ok(authenticated_envelope) => VerificationResult::valid(authenticated_envelope),
            Err(refusal_reason) => VerificationResult::refused(refusal_reason),
        }
    }

    fn authenticate_internal(
        self,
        roster: &Roster,
        expected_binding: &MailboxBindingExpectation,
    ) -> Result<AuthenticatedMailboxEnvelope, RefusalReason> {
        self.validate_bindings()
            .map_err(|error| error.refusal_reason)?;
        let key_schedule_input = &self.associated_data.key_schedule_input;
        let roster_hash = roster.roster_hash().map_err(|error| error.refusal_reason)?;
        if key_schedule_input.roster_hash != roster_hash {
            return Err(RefusalReason::WrongHashOrRoot);
        }
        expected_binding.verify(key_schedule_input)?;

        let source_roster_entry = roster_entry(roster, key_schedule_input.source_participant_id)?;
        let recipient_roster_entry =
            roster_entry(roster, key_schedule_input.recipient_participant_id)?;
        let source_verification_key =
            ml_dsa_65::PublicKey::try_from_bytes(source_roster_entry.signing_verification_key)
                .map_err(|_| RefusalReason::InvalidSignature)?;
        let envelope_hash = self.envelope_hash().map_err(|error| error.refusal_reason)?;
        if !source_verification_key.verify(
            envelope_hash.as_bytes(),
            &self.source_signature,
            MAILBOX_SIGNATURE_CONTEXT,
        ) {
            return Err(RefusalReason::InvalidSignature);
        }

        Ok(AuthenticatedMailboxEnvelope {
            envelope: self,
            recipient_encapsulation_key: recipient_roster_entry.mailbox_encapsulation_key,
        })
    }

    fn validate_bindings(&self) -> MailboxResult<()> {
        validate_plaintext_byte_length(self.associated_data.plaintext_byte_length)?;
        self.ciphertext_descriptor.validate()?;
        if self.ciphertext_descriptor.total_byte_length
            != self.associated_data.plaintext_byte_length
        {
            return Err(mailbox_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox ciphertext descriptor length does not match the authenticated plaintext length",
            ));
        }
        let observed_kem_ciphertext_hash = kem_ciphertext_hash(&self.kem_ciphertext)?;
        if observed_kem_ciphertext_hash
            != self.associated_data.key_schedule_input.kem_ciphertext_hash
        {
            return Err(mailbox_error(
                RefusalReason::WrongHashOrRoot,
                "mailbox KEM ciphertext hash does not match the fixed ciphertext",
            ));
        }
        Ok(())
    }
}

/// Verifier-owned values expected at the mailbox application slot.
///
/// The attempt identifier and KEM ciphertext are intentionally absent: they
/// are fresh producer material, while replay and sequence ownership remains a
/// higher-level state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxBindingExpectation {
    pub suite_id: Hash512,
    pub ceremony_context_hash: Hash512,
    pub action_context_hash: Hash512,
    pub source_participant_id: ParticipantIdentity,
    pub recipient_participant_id: ParticipantIdentity,
    pub producer_sequence: u64,
    pub payload_type: MailboxPayloadType,
    pub statement_hash: Hash512,
    pub ordered_material_roots: Vec<Hash512>,
}

impl MailboxBindingExpectation {
    fn verify(&self, actual: &MailboxKeyScheduleInput) -> Result<(), RefusalReason> {
        if actual.suite_id != self.suite_id
            || actual.ceremony_context_hash != self.ceremony_context_hash
            || actual.action_context_hash != self.action_context_hash
            || actual.source_participant_id != self.source_participant_id
            || actual.recipient_participant_id != self.recipient_participant_id
            || actual.producer_sequence != self.producer_sequence
            || actual.payload_type != self.payload_type
            || actual.statement_hash != self.statement_hash
            || actual.ordered_material_roots != self.ordered_material_roots
        {
            return Err(RefusalReason::WrongContext);
        }
        Ok(())
    }
}

/// A validated ML-KEM-768 decapsulation key kept out of debug output and
/// zeroized when dropped.
pub struct MailboxDecapsulationKey {
    bytes: Box<[u8; ML_KEM_768_DECAPSULATION_KEY_BYTE_LENGTH]>,
}

impl MailboxDecapsulationKey {
    pub fn try_from_bytes(
        mut bytes: [u8; ML_KEM_768_DECAPSULATION_KEY_BYTE_LENGTH],
    ) -> MailboxResult<Self> {
        let decoded_key = ml_kem_768::DecapsKey::try_from_bytes(bytes)
            .map(|decoded_key| Self {
                bytes: Box::new(decoded_key.into_bytes()),
            })
            .map_err(|_| {
                mailbox_error(
                    RefusalReason::MalformedEncoding,
                    "ML-KEM-768 decapsulation key is not canonical",
                )
            });
        bytes.zeroize();
        decoded_key
    }

    fn embedded_encapsulation_key(&self) -> &[u8] {
        &self.bytes[ML_KEM_768_DECAPSULATION_PKE_KEY_BYTE_LENGTH
            ..ML_KEM_768_DECAPSULATION_PKE_KEY_BYTE_LENGTH
                + ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH]
    }
}

impl Drop for MailboxDecapsulationKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for MailboxDecapsulationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MailboxDecapsulationKey([redacted])")
    }
}

/// A validated ML-DSA-65 signing key kept out of serializable protocol values,
/// debug output, and public carriers.
pub struct MailboxSigningKey {
    bytes: Box<[u8; ML_DSA_65_SIGNING_KEY_BYTE_LENGTH]>,
}

impl MailboxSigningKey {
    pub fn try_from_bytes(
        mut bytes: [u8; ML_DSA_65_SIGNING_KEY_BYTE_LENGTH],
    ) -> MailboxResult<Self> {
        let decoded_key = ml_dsa_65::PrivateKey::try_from_bytes(bytes)
            .map(|decoded_key| Self {
                bytes: Box::new(decoded_key.into_bytes()),
            })
            .map_err(|_| {
                mailbox_error(
                    RefusalReason::MalformedEncoding,
                    "ML-DSA-65 signing key is not canonical",
                )
            });
        bytes.zeroize();
        decoded_key
    }

    fn decode(&self) -> MailboxResult<ml_dsa_65::PrivateKey> {
        let mut signing_key_bytes = *self.bytes;
        let signing_key = ml_dsa_65::PrivateKey::try_from_bytes(signing_key_bytes).map_err(|_| {
            mailbox_error(
                RefusalReason::MalformedEncoding,
                "ML-DSA-65 signing key is not canonical",
            )
        });
        signing_key_bytes.zeroize();
        signing_key
    }
}

impl Drop for MailboxSigningKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for MailboxSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MailboxSigningKey([redacted])")
    }
}

/// Fresh producer material derived from the action-private randomness tree.
/// It is single-use and wiped on drop; callers cache the resulting signed
/// envelope and ciphertext bytes for byte-identical retransmission.
pub struct MailboxSealingRandomness {
    envelope_attempt_identifier: [u8; MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    kem_encapsulation_seed: [u8; 32],
    signature_randomness_seed: [u8; 32],
}

impl MailboxSealingRandomness {
    pub const fn new(
        envelope_attempt_identifier: [u8; MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        kem_encapsulation_seed: [u8; 32],
        signature_randomness_seed: [u8; 32],
    ) -> Self {
        Self {
            envelope_attempt_identifier,
            kem_encapsulation_seed,
            signature_randomness_seed,
        }
    }
}

impl Drop for MailboxSealingRandomness {
    fn drop(&mut self) {
        self.envelope_attempt_identifier.zeroize();
        self.kem_encapsulation_seed.zeroize();
        self.signature_randomness_seed.zeroize();
    }
}

impl fmt::Debug for MailboxSealingRandomness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MailboxSealingRandomness([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMailboxPayload {
    pub signed_envelope: SignedMailboxEnvelope,
    pub ciphertext: Vec<u8>,
}

/// Seals and signs one bounded mailbox payload with keys selected only from the
/// external roster. This producer returns bytes or an error; only the opening
/// path returns a verification result.
pub fn seal_mailbox_payload(
    roster: &Roster,
    expected_binding: &MailboxBindingExpectation,
    source_signing_key: &MailboxSigningKey,
    randomness: MailboxSealingRandomness,
    plaintext: &[u8],
) -> MailboxResult<SealedMailboxPayload> {
    let plaintext_byte_length = u64::try_from(plaintext.len()).map_err(|_| {
        mailbox_error(
            RefusalReason::OutsideSupportedProfile,
            "mailbox plaintext length does not fit u64",
        )
    })?;
    validate_plaintext_byte_length(plaintext_byte_length)?;
    if plaintext.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(mailbox_error(
            RefusalReason::OutsideSupportedProfile,
            "in-memory mailbox sealing exceeds the copied-buffer profile",
        ));
    }

    let roster_hash = roster.roster_hash()?;
    let source_roster_entry = roster_entry(roster, expected_binding.source_participant_id)
        .map_err(|reason| mailbox_error(reason, "mailbox source is absent from the roster"))?;
    let recipient_roster_entry = roster_entry(roster, expected_binding.recipient_participant_id)
        .map_err(|reason| mailbox_error(reason, "mailbox recipient is absent from the roster"))?;
    let signing_key = source_signing_key.decode()?;
    if signing_key.get_public_key().into_bytes() != source_roster_entry.signing_verification_key {
        return Err(mailbox_error(
            RefusalReason::WrongContext,
            "mailbox signing key does not match the roster source",
        ));
    }
    let recipient_encapsulation_key =
        ml_kem_768::EncapsKey::try_from_bytes(recipient_roster_entry.mailbox_encapsulation_key)
            .map_err(|_| {
                mailbox_error(
                    RefusalReason::MalformedEncoding,
                    "roster mailbox encapsulation key is not canonical",
                )
            })?;
    let (shared_secret, kem_ciphertext) =
        recipient_encapsulation_key.encaps_from_seed(&randomness.kem_encapsulation_seed);
    let kem_ciphertext = kem_ciphertext.into_bytes();
    let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
    let key_schedule_input = MailboxKeyScheduleInput {
        suite_id: expected_binding.suite_id,
        ceremony_context_hash: expected_binding.ceremony_context_hash,
        action_context_hash: expected_binding.action_context_hash,
        roster_hash,
        source_participant_id: expected_binding.source_participant_id,
        recipient_participant_id: expected_binding.recipient_participant_id,
        producer_sequence: expected_binding.producer_sequence,
        envelope_attempt_identifier: randomness.envelope_attempt_identifier,
        payload_type: expected_binding.payload_type,
        statement_hash: expected_binding.statement_hash,
        ordered_material_roots: expected_binding.ordered_material_roots.clone(),
        kem_ciphertext_hash: kem_ciphertext_hash(&kem_ciphertext)?,
    };
    let associated_data =
        MailboxAssociatedData::new(key_schedule_input.clone(), plaintext_byte_length)?;
    let associated_data_bytes = associated_data.encode()?;
    let key_material = derive_mailbox_key_material(&key_schedule_input, &shared_secret_bytes)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key_material[..AES_256_KEY_BYTE_LENGTH]).map_err(|_| {
            mailbox_error(
                RefusalReason::OutsideSupportedProfile,
                "mailbox AES-256-GCM key length is unsupported",
            )
        })?;
    let nonce = Nonce::from_slice(&key_material[AES_256_KEY_BYTE_LENGTH..]);
    let mut ciphertext = plaintext.to_vec();
    let gcm_tag =
        match cipher.encrypt_in_place_detached(nonce, &associated_data_bytes, &mut ciphertext) {
            Ok(tag) => tag.into(),
            Err(_) => {
                ciphertext.zeroize();
                return Err(mailbox_error(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox AES-256-GCM sealing failed",
                ));
            }
        };
    let ciphertext_descriptor = derive_canonical_stream_descriptor(
        CanonicalStreamDomain::PrivateMailboxCiphertext,
        &ciphertext,
    )
    .map_err(|reason| mailbox_error(reason, "mailbox ciphertext stream is outside the profile"))?;
    let mut signed_envelope = SignedMailboxEnvelope {
        associated_data,
        kem_ciphertext,
        ciphertext_descriptor,
        gcm_tag,
        source_signature: [0u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    };
    let envelope_hash = signed_envelope.envelope_hash()?;
    signed_envelope.source_signature = signing_key
        .try_sign_with_seed(
            &randomness.signature_randomness_seed,
            envelope_hash.as_bytes(),
            MAILBOX_SIGNATURE_CONTEXT,
        )
        .map_err(|_| {
            mailbox_error(
                RefusalReason::OutsideSupportedProfile,
                "ML-DSA-65 mailbox signing failed",
            )
        })?;
    signed_envelope.validate_bindings()?;

    Ok(SealedMailboxPayload {
        signed_envelope,
        ciphertext,
    })
}

/// A mailbox envelope whose source signature and complete public binding have
/// already been verified. This is the only type that exposes decapsulation.
pub struct AuthenticatedMailboxEnvelope {
    envelope: SignedMailboxEnvelope,
    recipient_encapsulation_key: [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
}

impl AuthenticatedMailboxEnvelope {
    pub fn ciphertext_descriptor(&self) -> &StreamDescriptor {
        &self.envelope.ciphertext_descriptor
    }

    pub fn envelope_attempt_identifier(
        &self,
    ) -> &[u8; MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        &self
            .envelope
            .associated_data
            .key_schedule_input
            .envelope_attempt_identifier
    }

    /// Performs ML-KEM decapsulation only after the source signature gate and
    /// binds the private key to the external roster's recipient key.
    pub fn decapsulate(
        self,
        recipient_decapsulation_key: &MailboxDecapsulationKey,
    ) -> VerificationResult<PreparedMailboxOpening> {
        match self.decapsulate_internal(recipient_decapsulation_key) {
            Ok(prepared_opening) => VerificationResult::valid(prepared_opening),
            Err(refusal_reason) => VerificationResult::refused(refusal_reason),
        }
    }

    fn decapsulate_internal(
        self,
        recipient_decapsulation_key: &MailboxDecapsulationKey,
    ) -> Result<PreparedMailboxOpening, RefusalReason> {
        if recipient_decapsulation_key.embedded_encapsulation_key()
            != self.recipient_encapsulation_key
        {
            return Err(RefusalReason::WrongContext);
        }
        let mut decapsulation_key_bytes = *recipient_decapsulation_key.bytes;
        let decapsulation_key = ml_kem_768::DecapsKey::try_from_bytes(decapsulation_key_bytes)
            .map_err(|_| RefusalReason::MalformedEncoding);
        decapsulation_key_bytes.zeroize();
        let decapsulation_key = decapsulation_key?;
        let kem_ciphertext = ml_kem_768::CipherText::try_from_bytes(self.envelope.kem_ciphertext)
            .map_err(|_| RefusalReason::MalformedEncoding)?;
        let shared_secret = decapsulation_key
            .try_decaps(&kem_ciphertext)
            .map_err(|_| RefusalReason::MalformedEncoding)?;
        let shared_secret_bytes = Zeroizing::new(shared_secret.into_bytes());
        let associated_data_bytes = self
            .envelope
            .associated_data
            .encode()
            .map_err(|error| error.refusal_reason)?;
        let key_material = derive_mailbox_key_material(
            &self.envelope.associated_data.key_schedule_input,
            &shared_secret_bytes,
        )
        .map_err(|error| error.refusal_reason)?;
        let mut aes_key = [0u8; AES_256_KEY_BYTE_LENGTH];
        aes_key.copy_from_slice(&key_material[..AES_256_KEY_BYTE_LENGTH]);
        let mut gcm_nonce = [0u8; AES_GCM_NONCE_BYTE_LENGTH];
        gcm_nonce.copy_from_slice(&key_material[AES_256_KEY_BYTE_LENGTH..]);

        Ok(PreparedMailboxOpening {
            aes_key: Zeroizing::new(aes_key),
            gcm_nonce,
            associated_data_bytes,
            ciphertext_descriptor: self.envelope.ciphertext_descriptor,
            gcm_tag: self.envelope.gcm_tag,
        })
    }
}

impl fmt::Debug for AuthenticatedMailboxEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedMailboxEnvelope")
            .field(
                "ciphertext_descriptor",
                &self.envelope.ciphertext_descriptor,
            )
            .finish_non_exhaustive()
    }
}

/// Derived AES-256-GCM material and authenticated metadata for one opening.
/// The plaintext is returned only after the stream descriptor and GCM tag both
/// verify; failed staging bytes are zeroized.
pub struct PreparedMailboxOpening {
    aes_key: Zeroizing<[u8; AES_256_KEY_BYTE_LENGTH]>,
    gcm_nonce: [u8; AES_GCM_NONCE_BYTE_LENGTH],
    associated_data_bytes: Vec<u8>,
    ciphertext_descriptor: StreamDescriptor,
    gcm_tag: [u8; AES_GCM_TAG_BYTE_LENGTH],
}

impl PreparedMailboxOpening {
    pub fn open_ciphertext(self, ciphertext: &[u8]) -> VerificationResult<Vec<u8>> {
        match self.open_ciphertext_internal(ciphertext) {
            Ok(plaintext) => VerificationResult::valid(plaintext),
            Err(refusal_reason) => VerificationResult::refused(refusal_reason),
        }
    }

    fn open_ciphertext_internal(self, ciphertext: &[u8]) -> Result<Vec<u8>, RefusalReason> {
        if ciphertext.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        let mut stream_verifier = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::PrivateMailboxCiphertext,
            self.ciphertext_descriptor,
        )?;
        for (chunk_index, chunk_bytes) in ciphertext
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            stream_verifier
                .absorb_chunk(chunk_index, chunk_bytes)
                .into_result()?;
        }
        stream_verifier.finish().into_result()?;

        let cipher = Aes256Gcm::new_from_slice(self.aes_key.as_ref())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut plaintext = ciphertext.to_vec();
        if cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.gcm_nonce),
                &self.associated_data_bytes,
                &mut plaintext,
                Tag::from_slice(&self.gcm_tag),
            )
            .is_err()
        {
            plaintext.zeroize();
            return Err(RefusalReason::WrongHashOrRoot);
        }
        Ok(plaintext)
    }
}

impl fmt::Debug for PreparedMailboxOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedMailboxOpening")
            .field("ciphertext_descriptor", &self.ciphertext_descriptor)
            .finish_non_exhaustive()
    }
}

pub fn kem_ciphertext_hash(
    kem_ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH],
) -> MailboxResult<Hash512> {
    Ok(hash512(
        KEM_CIPHERTEXT_HASH_DOMAIN,
        &[CanonicalItem::fixed_bytes(kem_ciphertext)?],
    )?)
}

fn derive_mailbox_key_material(
    key_schedule_input: &MailboxKeyScheduleInput,
    shared_secret: &[u8; 32],
) -> MailboxResult<Zeroizing<[u8; MAILBOX_HKDF_OUTPUT_BYTE_LENGTH]>> {
    let extract_salt_hash = hash512(
        HKDF_EXTRACT_SALT_DOMAIN,
        &[
            CanonicalItem::hash512(key_schedule_input.suite_id.into_bytes()),
            CanonicalItem::hash512(key_schedule_input.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(key_schedule_input.action_context_hash.into_bytes()),
            CanonicalItem::hash512(key_schedule_input.roster_hash.into_bytes()),
            CanonicalItem::participant_identity(
                key_schedule_input.source_participant_id.into_bytes(),
            ),
            CanonicalItem::participant_identity(
                key_schedule_input.recipient_participant_id.into_bytes(),
            ),
            CanonicalItem::unsigned64(key_schedule_input.producer_sequence),
            CanonicalItem::fixed_bytes(key_schedule_input.envelope_attempt_identifier)?,
            CanonicalItem::hash512(key_schedule_input.kem_ciphertext_hash.into_bytes()),
        ],
    )?;
    let extract_salt = &extract_salt_hash.as_bytes()[..48];
    let hkdf = Hkdf::<Sha384>::new(Some(extract_salt), shared_secret);
    let mut output = Zeroizing::new([0u8; MAILBOX_HKDF_OUTPUT_BYTE_LENGTH]);
    hkdf.expand(&key_schedule_input.encode()?, output.as_mut())
        .map_err(|_| {
            mailbox_error(
                RefusalReason::OutsideSupportedProfile,
                "mailbox HKDF output length is unsupported",
            )
        })?;
    Ok(output)
}

fn validate_plaintext_byte_length(plaintext_byte_length: u64) -> MailboxResult<()> {
    if plaintext_byte_length == 0 || plaintext_byte_length > u64::from(u32::MAX - 4) {
        return Err(mailbox_error(
            RefusalReason::WrongTypeOrLength,
            "mailbox plaintext length is outside the canonical stream range",
        ));
    }
    Ok(())
}

fn read_participant_identity(item: &CanonicalItem) -> MailboxResult<ParticipantIdentity> {
    let bytes: [u8; 64] = read_item(item, CanonicalItemType::ParticipantIdentity)?
        .try_into()
        .map_err(|_| {
            mailbox_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox participant identity has the wrong length",
            )
        })?;
    Ok(ParticipantIdentity::from_bytes(bytes))
}

fn roster_entry(
    roster: &Roster,
    participant_identity: ParticipantIdentity,
) -> Result<&super::RosterEntry, RefusalReason> {
    for roster_entry in &roster.entries {
        let derived_identity = roster_entry
            .participant_identity()
            .map_err(|error| error.refusal_reason)?;
        if derived_identity == participant_identity {
            return Ok(roster_entry);
        }
    }
    Err(RefusalReason::WrongContext)
}

fn mailbox_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::AeadInPlace;
    use fips203::traits::{
        Decaps as KemDecaps, Encaps as KemEncaps, KeyGen as KemKeyGen, SerDes as KemSerDes,
    };
    use fips204::traits::{KeyGen as SignatureKeyGen, Signer};
    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::foundation::{
        ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, RosterEntry, derive_canonical_stream_descriptor,
    };

    struct TestMailbox {
        roster: Roster,
        source_signing_key: ml_dsa_65::PrivateKey,
        recipient_decapsulation_key: MailboxDecapsulationKey,
        source_participant_id: ParticipantIdentity,
        recipient_participant_id: ParticipantIdentity,
        recipient_encapsulation_key: [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NistMlKemEncapsulationVector {
        source: String,
        source_revision: String,
        group_id: u64,
        test_case_id: u64,
        encapsulation_key: String,
        decapsulation_key: String,
        encapsulation_randomness: String,
        ciphertext: String,
        shared_secret: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NistMlDsaVerificationVector {
        source: String,
        source_revision: String,
        group_id: u64,
        verification_key: String,
        tests: Vec<NistMlDsaVerificationCase>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NistMlDsaVerificationCase {
        test_case_id: u64,
        message: String,
        signature: String,
        expected_valid: bool,
    }

    fn test_mailbox() -> TestMailbox {
        let mut roster_entries =
            Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
        let mut source_signing_key = None;
        let mut recipient_decapsulation_key = None;
        let mut recipient_encapsulation_key = None;
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            let signature_seed =
                [u8::try_from(roster_position + 1).expect("test roster position fits"); 32];
            let (signing_verification_key, signing_key) =
                ml_dsa_65::KG::keygen_from_seed(&signature_seed);
            let (encapsulation_key, decapsulation_key) = ml_kem_768::KG::keygen_from_seed(
                [u8::try_from(roster_position + 31).expect("test seed fits"); 32],
                [u8::try_from(roster_position + 61).expect("test seed fits"); 32],
            );
            let encapsulation_key_bytes = encapsulation_key.into_bytes();
            if roster_position == 0 {
                source_signing_key = Some(signing_key);
            }
            if roster_position == 1 {
                recipient_decapsulation_key = Some(
                    MailboxDecapsulationKey::try_from_bytes(decapsulation_key.into_bytes())
                        .expect("test decapsulation key is canonical"),
                );
                recipient_encapsulation_key = Some(encapsulation_key_bytes);
            }
            roster_entries.push(RosterEntry {
                roster_position,
                signing_verification_key: signing_verification_key.into_bytes(),
                mailbox_encapsulation_key: encapsulation_key_bytes,
            });
        }
        let roster = Roster::new(roster_entries).expect("test roster is valid");
        let source_participant_id = roster.entries[0]
            .participant_identity()
            .expect("source identity derives");
        let recipient_participant_id = roster.entries[1]
            .participant_identity()
            .expect("recipient identity derives");
        TestMailbox {
            roster,
            source_signing_key: source_signing_key.expect("source signing key"),
            recipient_decapsulation_key: recipient_decapsulation_key
                .expect("recipient decapsulation key"),
            source_participant_id,
            recipient_participant_id,
            recipient_encapsulation_key: recipient_encapsulation_key
                .expect("recipient encapsulation key"),
        }
    }

    fn mailbox_key_schedule_input(
        test_mailbox: &TestMailbox,
        kem_ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH],
    ) -> MailboxKeyScheduleInput {
        MailboxKeyScheduleInput {
            suite_id: Hash512::from_bytes([0x11; 64]),
            ceremony_context_hash: Hash512::from_bytes([0x22; 64]),
            action_context_hash: Hash512::from_bytes([0x33; 64]),
            roster_hash: test_mailbox.roster.roster_hash().expect("roster hash"),
            source_participant_id: test_mailbox.source_participant_id,
            recipient_participant_id: test_mailbox.recipient_participant_id,
            producer_sequence: 17,
            envelope_attempt_identifier: [0x44; 32],
            payload_type: MailboxPayloadType::RecipientPrivateVerifiableSecretSharingShare,
            statement_hash: Hash512::from_bytes([0x55; 64]),
            ordered_material_roots: vec![
                Hash512::from_bytes([0x66; 64]),
                Hash512::from_bytes([0x77; 64]),
            ],
            kem_ciphertext_hash: kem_ciphertext_hash(kem_ciphertext).expect("KEM hash"),
        }
    }

    fn expected_binding(key_schedule_input: &MailboxKeyScheduleInput) -> MailboxBindingExpectation {
        MailboxBindingExpectation {
            suite_id: key_schedule_input.suite_id,
            ceremony_context_hash: key_schedule_input.ceremony_context_hash,
            action_context_hash: key_schedule_input.action_context_hash,
            source_participant_id: key_schedule_input.source_participant_id,
            recipient_participant_id: key_schedule_input.recipient_participant_id,
            producer_sequence: key_schedule_input.producer_sequence,
            payload_type: key_schedule_input.payload_type,
            statement_hash: key_schedule_input.statement_hash,
            ordered_material_roots: key_schedule_input.ordered_material_roots.clone(),
        }
    }

    fn signed_envelope(
        test_mailbox: &TestMailbox,
        plaintext: &[u8],
    ) -> (SignedMailboxEnvelope, Vec<u8>) {
        let recipient_encapsulation_key =
            ml_kem_768::EncapsKey::try_from_bytes(test_mailbox.recipient_encapsulation_key)
                .expect("recipient encapsulation key is canonical");
        let (shared_secret, kem_ciphertext) =
            recipient_encapsulation_key.encaps_from_seed(&[0x88; 32]);
        let kem_ciphertext = kem_ciphertext.into_bytes();
        let key_schedule_input = mailbox_key_schedule_input(test_mailbox, &kem_ciphertext);
        let associated_data = MailboxAssociatedData::new(
            key_schedule_input.clone(),
            u64::try_from(plaintext.len()).expect("test plaintext length fits"),
        )
        .expect("associated data");
        let key_material =
            derive_mailbox_key_material(&key_schedule_input, &shared_secret.into_bytes())
                .expect("key material");
        let cipher = Aes256Gcm::new_from_slice(&key_material[..AES_256_KEY_BYTE_LENGTH])
            .expect("AES-256 key length");
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&key_material[AES_256_KEY_BYTE_LENGTH..]),
                &associated_data.encode().expect("associated data bytes"),
                &mut ciphertext,
            )
            .expect("test encryption");
        let ciphertext_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::PrivateMailboxCiphertext,
            &ciphertext,
        )
        .expect("mailbox descriptor");
        let mut envelope = SignedMailboxEnvelope {
            associated_data,
            kem_ciphertext,
            ciphertext_descriptor,
            gcm_tag: tag.into(),
            source_signature: [0u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
        };
        let envelope_hash = envelope.envelope_hash().expect("envelope hash");
        envelope.source_signature = test_mailbox
            .source_signing_key
            .try_sign_with_seed(
                &[0x99; 32],
                envelope_hash.as_bytes(),
                MAILBOX_SIGNATURE_CONTEXT,
            )
            .expect("test mailbox signature");
        (envelope, ciphertext)
    }

    #[test]
    fn production_sealing_round_trips_and_retransmits_byte_identically() {
        let test_mailbox = test_mailbox();
        let binding_template =
            mailbox_key_schedule_input(&test_mailbox, &[0u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH]);
        let expected_binding = expected_binding(&binding_template);
        let signing_key =
            MailboxSigningKey::try_from_bytes(test_mailbox.source_signing_key.into_bytes())
                .expect("test signing key is canonical");
        let plaintext = b"producer-sealed private mailbox payload";

        let seal_once = || {
            seal_mailbox_payload(
                &test_mailbox.roster,
                &expected_binding,
                &signing_key,
                MailboxSealingRandomness::new([0x44; 32], [0x88; 32], [0x99; 32]),
                plaintext,
            )
            .expect("mailbox sealing succeeds")
        };
        let first = seal_once();
        let retransmission = seal_once();
        assert_eq!(first, retransmission);
        assert_eq!(
            first.signed_envelope.encode().expect("envelope encodes"),
            retransmission
                .signed_envelope
                .encode()
                .expect("retransmitted envelope encodes")
        );

        let authenticated = first
            .signed_envelope
            .authenticate(&test_mailbox.roster, &expected_binding)
            .into_result()
            .expect("source signature and binding verify");
        let prepared = authenticated
            .decapsulate(&test_mailbox.recipient_decapsulation_key)
            .into_result()
            .expect("recipient decapsulation succeeds");
        assert_eq!(
            prepared
                .open_ciphertext(&first.ciphertext)
                .into_result()
                .expect("ciphertext authenticates"),
            plaintext
        );
    }

    #[test]
    fn production_sealing_refuses_a_signing_handle_for_another_roster_identity() {
        let test_mailbox = test_mailbox();
        let binding_template =
            mailbox_key_schedule_input(&test_mailbox, &[0u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH]);
        let expected_binding = expected_binding(&binding_template);
        let (_, unrelated_signing_key) = ml_dsa_65::KG::keygen_from_seed(&[0xfe; 32]);
        let unrelated_signing_key =
            MailboxSigningKey::try_from_bytes(unrelated_signing_key.into_bytes())
                .expect("unrelated signing key is canonical");

        assert_eq!(
            seal_mailbox_payload(
                &test_mailbox.roster,
                &expected_binding,
                &unrelated_signing_key,
                MailboxSealingRandomness::new([1; 32], [2; 32], [3; 32]),
                b"must not seal",
            )
            .expect_err("wrong roster signing handle must refuse")
            .refusal_reason,
            RefusalReason::WrongContext
        );
    }

    #[test]
    fn all_mailbox_schemas_round_trip_with_exact_field_order() {
        let test_mailbox = test_mailbox();
        let plaintext = b"canonical private mailbox payload";
        let (envelope, _) = signed_envelope(&test_mailbox, plaintext);
        let limits = CanonicalDecodeLimits::default();

        let key_schedule_bytes = envelope
            .associated_data
            .key_schedule_input
            .encode()
            .expect("key schedule encodes");
        assert_eq!(
            MailboxKeyScheduleInput::decode(&key_schedule_bytes, &limits)
                .expect("key schedule decodes"),
            envelope.associated_data.key_schedule_input
        );
        let associated_data_bytes = envelope
            .associated_data
            .encode()
            .expect("associated data encodes");
        assert_eq!(
            MailboxAssociatedData::decode(&associated_data_bytes, &limits)
                .expect("associated data decodes"),
            envelope.associated_data
        );
        let envelope_bytes = envelope.encode().expect("envelope encodes");
        assert_eq!(
            SignedMailboxEnvelope::decode(&envelope_bytes, &limits).expect("envelope decodes"),
            envelope
        );

        let key_schedule_tuple =
            CanonicalTuple::decode(&key_schedule_bytes, &limits).expect("key schedule tuple");
        let associated_data_tuple =
            CanonicalTuple::decode(&associated_data_bytes, &limits).expect("associated data tuple");
        let envelope_tuple =
            CanonicalTuple::decode(&envelope_bytes, &limits).expect("envelope tuple");
        assert_eq!(key_schedule_tuple.schema_identifier, 0x0200);
        assert_eq!(key_schedule_tuple.items.len(), 16);
        assert_eq!(associated_data_tuple.schema_identifier, 0x0201);
        assert_eq!(associated_data_tuple.items.len(), 18);
        assert_eq!(envelope_tuple.schema_identifier, 0x0202);
        assert_eq!(envelope_tuple.items.len(), 5);

        assert_eq!(
            key_schedule_tuple
                .items
                .iter()
                .map(CanonicalItem::item_type)
                .collect::<Vec<_>>(),
            vec![
                CanonicalItemType::Ascii,
                CanonicalItemType::Unsigned16,
                CanonicalItemType::Hash512,
                CanonicalItemType::Hash512,
                CanonicalItemType::Hash512,
                CanonicalItemType::Hash512,
                CanonicalItemType::ParticipantIdentity,
                CanonicalItemType::ParticipantIdentity,
                CanonicalItemType::Unsigned64,
                CanonicalItemType::RawBytes,
                CanonicalItemType::Ascii,
                CanonicalItemType::Unsigned16,
                CanonicalItemType::Unsigned16,
                CanonicalItemType::Hash512,
                CanonicalItemType::HomogeneousList,
                CanonicalItemType::Hash512,
            ]
        );
        assert_eq!(
            read_ascii(&key_schedule_tuple.items[0]).unwrap(),
            MAILBOX_KEY_SCHEDULE_DOMAIN
        );
        assert_eq!(
            read_u16(&key_schedule_tuple.items[1]).unwrap(),
            MAILBOX_PROTOCOL_VERSION
        );
        assert_eq!(
            read_hash(&key_schedule_tuple.items[2]).unwrap(),
            envelope.associated_data.key_schedule_input.suite_id
        );
        assert_eq!(
            read_hash(&key_schedule_tuple.items[3]).unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .ceremony_context_hash
        );
        assert_eq!(
            read_hash(&key_schedule_tuple.items[4]).unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .action_context_hash
        );
        assert_eq!(
            read_hash(&key_schedule_tuple.items[5]).unwrap(),
            envelope.associated_data.key_schedule_input.roster_hash
        );
        assert_eq!(
            read_participant_identity(&key_schedule_tuple.items[6]).unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .source_participant_id
        );
        assert_eq!(
            read_participant_identity(&key_schedule_tuple.items[7]).unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .recipient_participant_id
        );
        assert_eq!(
            read_u64(&key_schedule_tuple.items[8]).unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .producer_sequence
        );
        assert_eq!(
            read_fixed_bytes::<MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                &key_schedule_tuple.items[9]
            )
            .unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .envelope_attempt_identifier
        );
        assert_eq!(
            read_ascii(&key_schedule_tuple.items[10]).unwrap(),
            MAILBOX_DIRECTION
        );
        assert_eq!(
            read_u16(&key_schedule_tuple.items[11]).unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .payload_type
                .canonical_code()
        );
        assert_eq!(read_u16(&key_schedule_tuple.items[12]).unwrap(), 1);
        assert_eq!(
            read_hash(&key_schedule_tuple.items[13]).unwrap(),
            envelope.associated_data.key_schedule_input.statement_hash
        );
        assert_eq!(
            read_hash_list(&key_schedule_tuple.items[14]).unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .ordered_material_roots
        );
        assert_eq!(
            read_hash(&key_schedule_tuple.items[15]).unwrap(),
            envelope
                .associated_data
                .key_schedule_input
                .kem_ciphertext_hash
        );

        assert_eq!(
            &associated_data_tuple.items[..MailboxKeyScheduleInput::ITEM_COUNT],
            key_schedule_tuple.items.as_slice()
        );
        assert_eq!(
            read_u64(&associated_data_tuple.items[16]).unwrap(),
            plaintext.len() as u64
        );
        assert_eq!(
            read_u16(&associated_data_tuple.items[17]).unwrap(),
            MAILBOX_ENVELOPE_VERSION
        );
        assert_eq!(
            read_variable_item(&envelope_tuple.items[0], CanonicalItemType::RawBytes).unwrap(),
            associated_data_bytes
        );
        assert_eq!(
            read_fixed_bytes::<ML_KEM_768_CIPHERTEXT_BYTE_LENGTH>(&envelope_tuple.items[1])
                .unwrap(),
            envelope.kem_ciphertext
        );
        assert_eq!(
            envelope_tuple.items[2].item_type(),
            CanonicalItemType::NestedTuple
        );
        assert_eq!(
            read_fixed_bytes::<AES_GCM_TAG_BYTE_LENGTH>(&envelope_tuple.items[3]).unwrap(),
            envelope.gcm_tag
        );
        assert_eq!(
            read_fixed_bytes::<ML_DSA_65_SIGNATURE_BYTE_LENGTH>(&envelope_tuple.items[4]).unwrap(),
            envelope.source_signature
        );
    }

    #[test]
    fn fixed_mailbox_key_schedule_vector_pins_framing_extract_and_expand() {
        let key_schedule_input = MailboxKeyScheduleInput {
            suite_id: Hash512::from_bytes([0x11; 64]),
            ceremony_context_hash: Hash512::from_bytes([0x22; 64]),
            action_context_hash: Hash512::from_bytes([0x33; 64]),
            roster_hash: Hash512::from_bytes([0x44; 64]),
            source_participant_id: ParticipantIdentity::from_bytes([0x55; 64]),
            recipient_participant_id: ParticipantIdentity::from_bytes([0x66; 64]),
            producer_sequence: 0x0102_0304_0506_0708,
            envelope_attempt_identifier: [0x77; 32],
            payload_type: MailboxPayloadType::RecipientPrivateVerifiableSecretSharingShare,
            statement_hash: Hash512::from_bytes([0x88; 64]),
            ordered_material_roots: vec![
                Hash512::from_bytes([0x99; 64]),
                Hash512::from_bytes([0xaa; 64]),
            ],
            kem_ciphertext_hash: Hash512::from_bytes([0xbb; 64]),
        };
        let encoded_key_schedule = key_schedule_input.encode().expect("key schedule encodes");
        assert_eq!(encoded_key_schedule.len(), 861);
        assert_eq!(
            lowercase_hex(&Sha256::digest(&encoded_key_schedule)),
            "a7070312302e1b0e6d9746c925bdc0c209af29c7f73677552f3f61d0b76d76dd"
        );

        let key_material = derive_mailbox_key_material(&key_schedule_input, &[0xcc; 32])
            .expect("fixed key schedule derives");
        assert_eq!(
            lowercase_hex(key_material.as_ref()),
            "8939e904a457474bfe2317c32ae4f6061a80945f9e5bad27fb4433d138984fa9fedc06372a7c9b5f92b2e27b"
        );
    }

    #[test]
    fn signature_gate_precedes_decapsulation_and_plaintext_release() {
        let test_mailbox = test_mailbox();
        let plaintext = (0..70_003)
            .map(|index| ((index * 193) & 0xff) as u8)
            .collect::<Vec<_>>();
        let (envelope, ciphertext) = signed_envelope(&test_mailbox, &plaintext);
        let expectation = expected_binding(&envelope.associated_data.key_schedule_input);
        let authenticated = envelope
            .authenticate(&test_mailbox.roster, &expectation)
            .into_result()
            .expect("source signature authenticates");
        let prepared = authenticated
            .decapsulate(&test_mailbox.recipient_decapsulation_key)
            .into_result()
            .expect("recipient key decapsulates only after authentication");
        assert_eq!(
            prepared
                .open_ciphertext(&ciphertext)
                .into_result()
                .expect("descriptor and GCM tag authenticate"),
            plaintext
        );

        let (mut forged, _) = signed_envelope(&test_mailbox, b"forged carrier");
        forged.source_signature[17] ^= 1;
        let forged_expectation = expected_binding(&forged.associated_data.key_schedule_input);
        assert!(matches!(
            forged.authenticate(&test_mailbox.roster, &forged_expectation),
            VerificationResult::Refused {
                refusal_reason: RefusalReason::InvalidSignature
            }
        ));
    }

    #[test]
    fn context_roster_key_stream_and_tag_substitutions_refuse() {
        let test_mailbox = test_mailbox();
        let (envelope, ciphertext) = signed_envelope(&test_mailbox, b"authenticated plaintext");

        let mut wrong_context = expected_binding(&envelope.associated_data.key_schedule_input);
        wrong_context.producer_sequence += 1;
        assert!(matches!(
            envelope
                .clone()
                .authenticate(&test_mailbox.roster, &wrong_context),
            VerificationResult::Refused {
                refusal_reason: RefusalReason::WrongContext
            }
        ));

        let mut wrong_roster_entries = test_mailbox.roster.entries.clone();
        let (alternate_verification_key, _) = ml_dsa_65::KG::keygen_from_seed(&[0xa1; 32]);
        wrong_roster_entries[0].signing_verification_key = alternate_verification_key.into_bytes();
        let wrong_roster = Roster::new(wrong_roster_entries).expect("alternate roster is valid");
        let expectation = expected_binding(&envelope.associated_data.key_schedule_input);
        assert!(matches!(
            envelope.clone().authenticate(&wrong_roster, &expectation),
            VerificationResult::Refused {
                refusal_reason: RefusalReason::WrongHashOrRoot
            }
        ));

        let (alternate_encapsulation_key, alternate_decapsulation_key) =
            ml_kem_768::KG::keygen_from_seed([0xb1; 32], [0xb2; 32]);
        let wrong_private_key =
            MailboxDecapsulationKey::try_from_bytes(alternate_decapsulation_key.into_bytes())
                .expect("alternate private key is canonical");
        let _ = alternate_encapsulation_key;
        let authenticated = envelope
            .clone()
            .authenticate(&test_mailbox.roster, &expectation)
            .into_result()
            .expect("envelope authenticates");
        assert!(matches!(
            authenticated.decapsulate(&wrong_private_key),
            VerificationResult::Refused {
                refusal_reason: RefusalReason::WrongContext
            }
        ));

        let authenticated = envelope
            .authenticate(&test_mailbox.roster, &expectation)
            .into_result()
            .expect("envelope authenticates");
        let prepared = authenticated
            .decapsulate(&test_mailbox.recipient_decapsulation_key)
            .into_result()
            .expect("recipient key decapsulates");
        let mut substituted_ciphertext = ciphertext.clone();
        substituted_ciphertext[0] ^= 1;
        assert!(matches!(
            prepared.open_ciphertext(&substituted_ciphertext),
            VerificationResult::Refused {
                refusal_reason: RefusalReason::WrongHashOrRoot
            }
        ));

        let (mut wrong_tag_envelope, ciphertext) =
            signed_envelope(&test_mailbox, b"tag substitution");
        wrong_tag_envelope.gcm_tag[0] ^= 1;
        let envelope_hash = wrong_tag_envelope
            .envelope_hash()
            .expect("mutated envelope hash");
        wrong_tag_envelope.source_signature = test_mailbox
            .source_signing_key
            .try_sign_with_seed(
                &[0xc1; 32],
                envelope_hash.as_bytes(),
                MAILBOX_SIGNATURE_CONTEXT,
            )
            .expect("valid source signature over the wrong tag");
        let expectation = expected_binding(&wrong_tag_envelope.associated_data.key_schedule_input);
        let prepared = wrong_tag_envelope
            .authenticate(&test_mailbox.roster, &expectation)
            .into_result()
            .expect("source did authenticate this tag")
            .decapsulate(&test_mailbox.recipient_decapsulation_key)
            .into_result()
            .expect("recipient key decapsulates");
        assert!(matches!(
            prepared.open_ciphertext(&ciphertext),
            VerificationResult::Refused {
                refusal_reason: RefusalReason::WrongHashOrRoot
            }
        ));
    }

    #[test]
    fn malformed_versions_lengths_hashes_and_hostile_sizes_refuse() {
        let test_mailbox = test_mailbox();
        let (envelope, _) = signed_envelope(&test_mailbox, b"mailbox boundaries");
        let limits = CanonicalDecodeLimits::default();

        let mut decapsulation_key_with_wrong_public_key_hash =
            *test_mailbox.recipient_decapsulation_key.bytes;
        decapsulation_key_with_wrong_public_key_hash[ML_KEM_768_DECAPSULATION_PKE_KEY_BYTE_LENGTH
            + ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH] ^= 1;
        assert_eq!(
            MailboxDecapsulationKey::try_from_bytes(decapsulation_key_with_wrong_public_key_hash)
                .expect_err("a decapsulation key with the wrong public-key hash must refuse")
                .refusal_reason,
            RefusalReason::MalformedEncoding
        );

        let mut wrong_kem_hash = envelope.clone();
        wrong_kem_hash
            .associated_data
            .key_schedule_input
            .kem_ciphertext_hash = Hash512::from_bytes([0xff; 64]);
        assert_eq!(
            wrong_kem_hash
                .encode()
                .expect_err("wrong KEM hash must refuse")
                .refusal_reason,
            RefusalReason::WrongHashOrRoot
        );

        let mut wrong_length = envelope.clone();
        wrong_length.associated_data.plaintext_byte_length += 1;
        assert_eq!(
            wrong_length
                .encode()
                .expect_err("descriptor length mismatch must refuse")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let mut associated_data_tuple = CanonicalTuple::decode(
            &envelope.associated_data.encode().expect("associated data"),
            &limits,
        )
        .expect("associated-data tuple");
        associated_data_tuple.items[12] = CanonicalItem::unsigned16(2);
        assert_eq!(
            MailboxAssociatedData::decode(
                &associated_data_tuple.encode().expect("mutated tuple"),
                &limits,
            )
            .expect_err("unsupported payload version must refuse")
            .refusal_reason,
            RefusalReason::UnsupportedVersionOrSuite
        );

        associated_data_tuple.items[12] = CanonicalItem::unsigned16(1);
        associated_data_tuple.items[11] = CanonicalItem::unsigned16(0xffff);
        assert_eq!(
            MailboxAssociatedData::decode(
                &associated_data_tuple.encode().expect("mutated tuple"),
                &limits,
            )
            .expect_err("unassigned payload type must refuse")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );

        let encoded = envelope.encode().expect("envelope encodes");
        for truncated_length in [0, 1, 7, encoded.len() - 1] {
            assert!(SignedMailboxEnvelope::decode(&encoded[..truncated_length], &limits).is_err());
        }
        let restrictive_limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: encoded.len() - 1,
            ..limits
        };
        assert_eq!(
            SignedMailboxEnvelope::decode(&encoded, &restrictive_limits)
                .expect_err("configured bound must refuse before allocation")
                .refusal_reason,
            RefusalReason::OutsideSupportedProfile
        );
    }

    #[test]
    fn nist_acvp_ml_dsa_65_key_generation_vector_is_pinned() {
        // NIST ACVP-Server, ML-DSA-keyGen-FIPS204 internal projection,
        // ML-DSA-65 group 2, tcId 26.
        let seed =
            decode_32_byte_hex("70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c");
        let (verification_key, signing_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
        assert_eq!(
            lowercase_hex(&Sha256::digest(verification_key.into_bytes())),
            "646b26b8d09dbc9e865b6a006c693a3127b065e62fab5fbe8b159c416462feb6"
        );
        assert_eq!(
            lowercase_hex(&Sha256::digest(signing_key.into_bytes())),
            "3894dc56a4553781d68ff0d1b6fcf1b4876085ea602fb6f8738def50ed7d4c75"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn nist_acvp_ml_dsa_65_internal_verification_vectors_are_pinned() {
        // NIST currently publishes these ACVP cases for ML-DSA.Verify_internal,
        // before the external API's 0x00 || context-length || context prefix.
        // Keep this primitive pin distinct from the production API round-trip tests.
        let vector: NistMlDsaVerificationVector = serde_json::from_str(include_str!(
            "../../../../test-vectors/nist-ml-dsa-65-verification.json"
        ))
        .expect("selected NIST ACVP vectors are valid JSON");
        assert_eq!(
            vector.source,
            "NIST ACVP-Server ML-DSA-sigVer-FIPS204 internalProjection"
        );
        assert_eq!(
            vector.source_revision,
            "65370b861b96efd30dfe0daae607bde26a78a5c8"
        );
        assert_eq!(vector.group_id, 2);
        assert_eq!(vector.tests.len(), 2);

        let verification_key_bytes: [u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH] =
            decode_hex(&vector.verification_key)
                .try_into()
                .expect("ACVP verification key has the assigned length");
        let verification_key = ml_dsa_65::PublicKey::try_from_bytes(verification_key_bytes)
            .expect("ACVP verification key is canonical");

        for test_case in vector.tests {
            assert!(matches!(test_case.test_case_id, 25 | 26));
            let message = decode_hex(&test_case.message);
            let signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH] = decode_hex(&test_case.signature)
                .try_into()
                .expect("ACVP signature has the assigned length");
            assert_eq!(
                ml_dsa_65::_internal_verify(&verification_key, &message, &signature, &[]),
                test_case.expected_valid,
                "ML-DSA-65 ACVP tcId {}",
                test_case.test_case_id
            );
        }
    }

    #[test]
    fn nist_acvp_ml_kem_768_key_generation_vector_is_pinned() {
        // NIST ACVP-Server, ML-KEM-keyGen-FIPS203 internal projection,
        // ML-KEM-768 tcId 26.
        let d =
            decode_32_byte_hex("e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0");
        let z =
            decode_32_byte_hex("1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0");
        let (encapsulation_key, decapsulation_key) = ml_kem_768::KG::keygen_from_seed(d, z);
        assert_eq!(
            lowercase_hex(&Sha256::digest(encapsulation_key.into_bytes())),
            "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e"
        );
        assert_eq!(
            lowercase_hex(&Sha256::digest(decapsulation_key.into_bytes())),
            "7aab35839207f72b310abe36e2daa1cc7ff6f7fa8941e439967cd47d9b437079"
        );
    }

    #[test]
    fn nist_acvp_ml_kem_768_encapsulation_and_decapsulation_vector_is_pinned() {
        let vector: NistMlKemEncapsulationVector = serde_json::from_str(include_str!(
            "../../../../test-vectors/nist-ml-kem-768-encapsulation.json"
        ))
        .expect("selected NIST ACVP vector is valid JSON");
        assert_eq!(
            vector.source,
            "NIST ACVP-Server ML-KEM-encapDecap-FIPS203 internalProjection"
        );
        assert_eq!(
            vector.source_revision,
            "65370b861b96efd30dfe0daae607bde26a78a5c8"
        );
        assert_eq!((vector.group_id, vector.test_case_id), (2, 26));

        let encapsulation_key_bytes: [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH] =
            decode_hex(&vector.encapsulation_key)
                .try_into()
                .expect("ACVP encapsulation key has the assigned length");
        let decapsulation_key_bytes: [u8; ML_KEM_768_DECAPSULATION_KEY_BYTE_LENGTH] =
            decode_hex(&vector.decapsulation_key)
                .try_into()
                .expect("ACVP decapsulation key has the assigned length");
        let encapsulation_randomness = decode_32_byte_hex(&vector.encapsulation_randomness);
        let expected_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH] =
            decode_hex(&vector.ciphertext)
                .try_into()
                .expect("ACVP ciphertext has the assigned length");
        let expected_shared_secret = decode_32_byte_hex(&vector.shared_secret);

        let encapsulation_key = ml_kem_768::EncapsKey::try_from_bytes(encapsulation_key_bytes)
            .expect("ACVP encapsulation key is canonical");
        let (encapsulated_shared_secret, ciphertext) =
            encapsulation_key.encaps_from_seed(&encapsulation_randomness);
        assert_eq!(ciphertext.into_bytes(), expected_ciphertext);
        assert_eq!(
            encapsulated_shared_secret.into_bytes(),
            expected_shared_secret
        );

        let decapsulation_key = ml_kem_768::DecapsKey::try_from_bytes(decapsulation_key_bytes)
            .expect("ACVP decapsulation key is canonical");
        let ciphertext = ml_kem_768::CipherText::try_from_bytes(expected_ciphertext)
            .expect("ACVP ciphertext has the assigned length");
        assert_eq!(
            decapsulation_key
                .try_decaps(&ciphertext)
                .expect("ACVP ciphertext decapsulates")
                .into_bytes(),
            expected_shared_secret
        );
    }

    #[test]
    fn secret_types_redact_debug_output() {
        let test_mailbox = test_mailbox();
        assert_eq!(
            format!("{:?}", test_mailbox.recipient_decapsulation_key),
            "MailboxDecapsulationKey([redacted])"
        );
        assert_eq!(ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ml_dsa_65::PK_LEN);
    }

    fn decode_32_byte_hex(value: &str) -> [u8; 32] {
        decode_hex(value)
            .try_into()
            .expect("test vector contains exactly 32 bytes")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2));
        (0..value.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&value[index..index + 2], 16).expect("test vector hex is valid")
            })
            .collect()
    }

    fn lowercase_hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write;
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }
}
