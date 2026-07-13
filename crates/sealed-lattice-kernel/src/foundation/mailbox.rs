use core::fmt;

use fips203::ml_kem_768;
use fips204::{
    ml_dsa_65,
    traits::{SerDes as SignatureSerDes, Verifier},
};

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
    SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER, read_ascii, read_fixed_bytes, read_hash,
    read_hash_list, read_item, read_u16, read_u64, read_variable_item, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError,
    Hash512, ParticipantIdentity, RefusalReason, Roster, StreamDescriptor, VerificationResult,
    hash512,
};

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const MAILBOX_PROTOCOL_VERSION: u16 = 1;
const MAILBOX_KEY_SCHEDULE_DOMAIN: &str = "sealed-lattice/mailbox/key-schedule/v1";
const MAILBOX_DIRECTION: &str = "source-to-recipient";
const MAILBOX_PAYLOAD_VERSION: u16 = 1;
const MAILBOX_ENVELOPE_VERSION: u16 = 1;
const MAILBOX_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/mailbox-signature/v1";
const KEM_CIPHERTEXT_HASH_DOMAIN: &str = "sealed-lattice/mailbox/kem-ciphertext/v1";
const MAILBOX_ENVELOPE_HASH_DOMAIN: &str = "sealed-lattice/mailbox/envelope/v1";

pub const ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH: usize = ml_kem_768::EK_LEN;
pub const ML_KEM_768_CIPHERTEXT_BYTE_LENGTH: usize = ml_kem_768::CT_LEN;
pub const ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = ml_dsa_65::SIG_LEN;
pub const MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
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

/// Canonical mailbox key-schedule input carried by the authenticated envelope.
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
            CanonicalItem::unsigned16(MAILBOX_PAYLOAD_VERSION),
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
        if read_u16(&items[12])? != MAILBOX_PAYLOAD_VERSION {
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

        Ok(AuthenticatedMailboxEnvelope { envelope: self })
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

/// A mailbox envelope whose source signature and complete public binding have
/// already been verified.
pub struct AuthenticatedMailboxEnvelope {
    envelope: SignedMailboxEnvelope,
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

pub fn kem_ciphertext_hash(
    kem_ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH],
) -> MailboxResult<Hash512> {
    Ok(hash512(
        KEM_CIPHERTEXT_HASH_DOMAIN,
        &[CanonicalItem::fixed_bytes(kem_ciphertext)?],
    )?)
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
    use fips203::traits::{KeyGen as KemKeyGen, SerDes as KemSerDes};
    use fips204::traits::{KeyGen as SignatureKeyGen, Signer};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::foundation::{
        CanonicalStreamDomain, FOUNDATION_PROFILE, RosterEntry, derive_canonical_stream_descriptor,
    };

    struct TestMailbox {
        roster: Roster,
        source_signing_key: ml_dsa_65::PrivateKey,
        source_participant_id: ParticipantIdentity,
        recipient_participant_id: ParticipantIdentity,
    }

    fn test_mailbox() -> TestMailbox {
        let mut roster_entries =
            Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
        let mut source_signing_key = None;
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            let signature_seed =
                [u8::try_from(roster_position + 1).expect("test roster position fits"); 32];
            let (signing_verification_key, signing_key) =
                ml_dsa_65::KG::keygen_from_seed(&signature_seed);
            let (encapsulation_key, _) = ml_kem_768::KG::keygen_from_seed(
                [u8::try_from(roster_position + 31).expect("test seed fits"); 32],
                [u8::try_from(roster_position + 61).expect("test seed fits"); 32],
            );
            let encapsulation_key_bytes = encapsulation_key.into_bytes();
            if roster_position == 0 {
                source_signing_key = Some(signing_key);
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
            source_participant_id,
            recipient_participant_id,
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

    fn signed_envelope(test_mailbox: &TestMailbox, ciphertext: &[u8]) -> SignedMailboxEnvelope {
        let kem_ciphertext = [0x88; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH];
        let key_schedule_input = mailbox_key_schedule_input(test_mailbox, &kem_ciphertext);
        let associated_data = MailboxAssociatedData::new(
            key_schedule_input,
            u64::try_from(ciphertext.len()).expect("test ciphertext length fits"),
        )
        .expect("associated data");
        let ciphertext_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::PrivateMailboxCiphertext,
            ciphertext,
        )
        .expect("mailbox descriptor");
        let mut envelope = SignedMailboxEnvelope {
            associated_data,
            kem_ciphertext,
            ciphertext_descriptor,
            gcm_tag: [0x5a; AES_GCM_TAG_BYTE_LENGTH],
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
        envelope
    }

    #[test]
    fn all_mailbox_schemas_round_trip_with_exact_field_order() {
        let test_mailbox = test_mailbox();
        let plaintext = b"canonical private mailbox payload";
        let envelope = signed_envelope(&test_mailbox, plaintext);
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
    fn fixed_mailbox_key_schedule_vector_pins_canonical_framing() {
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
    }

    #[test]
    fn signature_gate_authenticates_the_bound_envelope() {
        let test_mailbox = test_mailbox();
        let ciphertext = (0..70_003)
            .map(|index| ((index * 193) & 0xff) as u8)
            .collect::<Vec<_>>();
        let envelope = signed_envelope(&test_mailbox, &ciphertext);
        let expected_descriptor = envelope.ciphertext_descriptor.clone();
        let expected_attempt_identifier = envelope
            .associated_data
            .key_schedule_input
            .envelope_attempt_identifier;
        let expectation = expected_binding(&envelope.associated_data.key_schedule_input);
        let authenticated = envelope
            .authenticate(&test_mailbox.roster, &expectation)
            .into_result()
            .expect("source signature authenticates");
        assert_eq!(authenticated.ciphertext_descriptor(), &expected_descriptor);
        assert_eq!(
            authenticated.envelope_attempt_identifier(),
            &expected_attempt_identifier
        );

        let mut forged = signed_envelope(&test_mailbox, b"forged carrier");
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
    fn context_roster_and_tag_substitutions_refuse() {
        let test_mailbox = test_mailbox();
        let envelope = signed_envelope(&test_mailbox, b"authenticated ciphertext");

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

        let mut wrong_tag_envelope = signed_envelope(&test_mailbox, b"tag substitution");
        wrong_tag_envelope.gcm_tag[0] ^= 1;
        let expectation = expected_binding(&wrong_tag_envelope.associated_data.key_schedule_input);
        assert!(matches!(
            wrong_tag_envelope.authenticate(&test_mailbox.roster, &expectation),
            VerificationResult::Refused {
                refusal_reason: RefusalReason::InvalidSignature
            }
        ));
    }

    #[test]
    fn malformed_versions_lengths_hashes_and_hostile_sizes_refuse() {
        let test_mailbox = test_mailbox();
        let envelope = signed_envelope(&test_mailbox, b"mailbox boundaries");
        let limits = CanonicalDecodeLimits::default();

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

    fn lowercase_hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write;
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }
}
