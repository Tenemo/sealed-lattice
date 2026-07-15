use fips203::ml_kem_768;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    FoundationSchemaError, SchemaResult, read_fixed_bytes, read_hash, read_hash_list, read_item,
    read_u16, read_u64, read_variable_item, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    ParticipantIdentity, RefusalReason, StreamDescriptor, hash_foundation_tuple_512 as hash512,
};

pub const MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0200;
pub const MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER: u16 = 0x0201;
pub const SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER: u16 = 0x0202;
pub const MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
pub const MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH: usize = ml_kem_768::CT_LEN;
pub const MAILBOX_GCM_TAG_BYTE_LENGTH: usize = 16;
pub const MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH: usize = 3_309;
pub const MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH: usize = 48;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;

#[allow(clippy::too_many_arguments)]
pub fn derive_setup_mailbox_slot_hash(
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    source_participant_id: ParticipantIdentity,
    recipient_participant_id: ParticipantIdentity,
    producer_sequence: u64,
    payload_type: MailboxPayloadType,
    statement_hash: Hash512,
    ordered_material_roots: &[Hash512],
) -> SchemaResult<Hash512> {
    validate_mailbox_material_roots(payload_type, ordered_material_roots)?;
    let material_roots = ordered_material_roots
        .iter()
        .map(|root| CanonicalItem::hash512(root.into_bytes()))
        .collect::<Vec<_>>();
    Ok(hash512(
        "sealed-lattice/setup/mailbox-randomness-slot/v1",
        &[
            CanonicalItem::hash512(suite_id.into_bytes()),
            CanonicalItem::hash512(ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(action_context_hash.into_bytes()),
            CanonicalItem::hash512(roster_hash.into_bytes()),
            CanonicalItem::participant_identity(source_participant_id.into_bytes()),
            CanonicalItem::participant_identity(recipient_participant_id.into_bytes()),
            CanonicalItem::unsigned64(producer_sequence),
            CanonicalItem::unsigned16(payload_type.canonical_code()),
            CanonicalItem::unsigned16(1),
            CanonicalItem::hash512(statement_hash.into_bytes()),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &material_roots)?,
        ],
    )?)
}

fn validate_mailbox_material_roots(
    payload_type: MailboxPayloadType,
    ordered_material_roots: &[Hash512],
) -> SchemaResult<()> {
    match payload_type {
        MailboxPayloadType::PublicRandomnessRecoveryShare if !ordered_material_roots.is_empty() => {
            Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "public-randomness recovery mailboxes cannot carry material roots",
            ))
        }
        MailboxPayloadType::RecipientPrivateVssShare if ordered_material_roots.is_empty() => {
            Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "private VSS mailboxes must bind their ordered material roots",
            ))
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MailboxPayloadType {
    PublicRandomnessRecoveryShare = 1,
    RecipientPrivateVssShare = 2,
}

impl MailboxPayloadType {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::PublicRandomnessRecoveryShare),
            2 => Some(Self::RecipientPrivateVssShare),
            _ => None,
        }
    }
}

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
    pub fn checked(self) -> SchemaResult<Self> {
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> SchemaResult<()> {
        validate_mailbox_material_roots(self.payload_type, &self.ordered_material_roots)
    }

    fn canonical_items(&self) -> SchemaResult<Vec<CanonicalItem>> {
        self.validate()?;
        let material_roots = self
            .ordered_material_roots
            .iter()
            .map(|root| CanonicalItem::hash512(root.into_bytes()))
            .collect::<Vec<_>>();
        Ok(vec![
            CanonicalItem::hash512(self.suite_id.into_bytes()),
            CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(self.action_context_hash.into_bytes()),
            CanonicalItem::hash512(self.roster_hash.into_bytes()),
            CanonicalItem::participant_identity(self.source_participant_id.into_bytes()),
            CanonicalItem::participant_identity(self.recipient_participant_id.into_bytes()),
            CanonicalItem::unsigned64(self.producer_sequence),
            CanonicalItem::fixed_bytes(self.envelope_attempt_identifier)?,
            CanonicalItem::unsigned16(self.payload_type.canonical_code()),
            CanonicalItem::hash512(self.statement_hash.into_bytes()),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &material_roots)?,
            CanonicalItem::hash512(self.kem_ciphertext_hash.into_bytes()),
        ])
    }

    fn from_items(items: &[CanonicalItem]) -> SchemaResult<Self> {
        if items.len() != 12 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox key-schedule input has the wrong item count",
            ));
        }
        let payload_type = MailboxPayloadType::from_canonical_code(read_u16(&items[8])?)
            .ok_or_else(|| {
                schema_error(
                    RefusalReason::UnsupportedVersionOrSuite,
                    "mailbox payload type is unassigned",
                )
            })?;
        Self {
            suite_id: read_hash(&items[0])?,
            ceremony_context_hash: read_hash(&items[1])?,
            action_context_hash: read_hash(&items[2])?,
            roster_hash: read_hash(&items[3])?,
            source_participant_id: read_participant_identity(&items[4])?,
            recipient_participant_id: read_participant_identity(&items[5])?,
            producer_sequence: read_u64(&items[6])?,
            envelope_attempt_identifier: read_fixed_bytes(&items[7])?,
            payload_type,
            statement_hash: read_hash(&items[9])?,
            ordered_material_roots: read_hash_list(&items[10])?,
            kem_ciphertext_hash: read_hash(&items[11])?,
        }
        .checked()
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            self.canonical_items()?,
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER, 12)?;
        Self::from_items(&tuple.items)
    }

    pub fn hkdf_extract_salt(&self) -> SchemaResult<[u8; MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH]> {
        self.validate()?;
        let salt_hash = hash512(
            "sealed-lattice/mailbox/hkdf-extract-salt/v1",
            &[
                CanonicalItem::hash512(self.suite_id.into_bytes()),
                CanonicalItem::hash512(self.ceremony_context_hash.into_bytes()),
                CanonicalItem::hash512(self.action_context_hash.into_bytes()),
                CanonicalItem::hash512(self.roster_hash.into_bytes()),
                CanonicalItem::participant_identity(self.source_participant_id.into_bytes()),
                CanonicalItem::participant_identity(self.recipient_participant_id.into_bytes()),
                CanonicalItem::unsigned64(self.producer_sequence),
                CanonicalItem::fixed_bytes(self.envelope_attempt_identifier)?,
                CanonicalItem::hash512(self.kem_ciphertext_hash.into_bytes()),
            ],
        )?;
        let mut salt = [0_u8; MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH];
        salt.copy_from_slice(&salt_hash.as_bytes()[..MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH]);
        Ok(salt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxAssociatedData {
    pub key_schedule_input: MailboxKeyScheduleInput,
    pub plaintext_byte_length: u64,
}

impl MailboxAssociatedData {
    pub fn new(
        key_schedule_input: MailboxKeyScheduleInput,
        plaintext_byte_length: u64,
    ) -> SchemaResult<Self> {
        key_schedule_input.validate()?;
        if plaintext_byte_length == 0 {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox plaintext must be nonempty",
            ));
        }
        Ok(Self {
            key_schedule_input,
            plaintext_byte_length,
        })
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let mut items = self.key_schedule_input.canonical_items()?;
        items.push(CanonicalItem::unsigned64(self.plaintext_byte_length));
        Self::new(self.key_schedule_input.clone(), self.plaintext_byte_length)?;
        Ok(CanonicalTuple::new(
            MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
            FOUNDATION_SCHEMA_VERSION,
            items,
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        Self::decode_with_budget(bytes, limits, &mut budget)
    }

    fn decode_with_budget(
        bytes: &[u8],
        limits: &CanonicalDecodeLimits,
        budget: &mut CanonicalDecodeBudget,
    ) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, budget)?;
        require_header(&tuple, MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, 13)?;
        Self::new(
            MailboxKeyScheduleInput::from_items(&tuple.items[..12])?,
            read_u64(&tuple.items[12])?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMailboxEnvelope {
    pub associated_data: MailboxAssociatedData,
    pub kem_ciphertext: [u8; MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH],
    pub ciphertext_descriptor: StreamDescriptor,
    pub gcm_tag: [u8; MAILBOX_GCM_TAG_BYTE_LENGTH],
    pub source_signature: [u8; MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH],
}

impl SignedMailboxEnvelope {
    pub fn new(
        associated_data: MailboxAssociatedData,
        kem_ciphertext: [u8; MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH],
        ciphertext_descriptor: StreamDescriptor,
        gcm_tag: [u8; MAILBOX_GCM_TAG_BYTE_LENGTH],
        source_signature: [u8; MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH],
    ) -> SchemaResult<Self> {
        let envelope = Self {
            associated_data,
            kem_ciphertext,
            ciphertext_descriptor,
            gcm_tag,
            source_signature,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> SchemaResult<()> {
        MailboxAssociatedData::new(
            self.associated_data.key_schedule_input.clone(),
            self.associated_data.plaintext_byte_length,
        )?;
        self.ciphertext_descriptor.validate()?;
        if self.ciphertext_descriptor.total_byte_length
            != self.associated_data.plaintext_byte_length
        {
            return Err(schema_error(
                RefusalReason::WrongTypeOrLength,
                "mailbox ciphertext length does not match its associated data",
            ));
        }
        if derive_mailbox_kem_ciphertext_hash(&self.kem_ciphertext)?
            != self.associated_data.key_schedule_input.kem_ciphertext_hash
        {
            return Err(schema_error(
                RefusalReason::WrongHashOrRoot,
                "mailbox KEM ciphertext hash does not match its associated data",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        self.validate()?;
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

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER, 5)?;
        let associated_data = MailboxAssociatedData::decode_with_budget(
            read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?,
            limits,
            &mut budget,
        )?;
        let descriptor_tuple = CanonicalTuple::decode_with_budget(
            read_item(&tuple.items[2], CanonicalItemType::NestedTuple)?,
            limits,
            &mut budget,
        )?;
        Self::new(
            associated_data,
            read_fixed_bytes(&tuple.items[1])?,
            StreamDescriptor::from_tuple(&descriptor_tuple)?,
            read_fixed_bytes(&tuple.items[3])?,
            read_fixed_bytes(&tuple.items[4])?,
        )
    }

    pub fn envelope_hash(&self) -> SchemaResult<Hash512> {
        self.validate()?;
        Ok(hash512(
            "sealed-lattice/mailbox/envelope/v1",
            &[
                CanonicalItem::variable_bytes(self.associated_data.encode()?)?,
                CanonicalItem::fixed_bytes(self.kem_ciphertext)?,
                CanonicalItem::variable_bytes(self.ciphertext_descriptor.encode()?)?,
                CanonicalItem::fixed_bytes(self.gcm_tag)?,
            ],
        )?)
    }
}

pub fn derive_mailbox_kem_ciphertext_hash(
    kem_ciphertext: &[u8; MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH],
) -> SchemaResult<Hash512> {
    Ok(hash512(
        "sealed-lattice/mailbox/kem-ciphertext/v1",
        &[CanonicalItem::fixed_bytes(kem_ciphertext)?],
    )?)
}

fn read_participant_identity(item: &CanonicalItem) -> SchemaResult<ParticipantIdentity> {
    let identity: [u8; 64] = read_item(item, CanonicalItemType::ParticipantIdentity)?
        .try_into()
        .map_err(|_| {
            schema_error(
                RefusalReason::WrongTypeOrLength,
                "participant identity has the wrong length",
            )
        })?;
    Ok(ParticipantIdentity::from_bytes(identity))
}

fn schema_error(refusal_reason: RefusalReason, message: &'static str) -> FoundationSchemaError {
    FoundationSchemaError::new(refusal_reason, message)
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    fn key_schedule_input() -> MailboxKeyScheduleInput {
        let kem_ciphertext = [0x5a; MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH];
        MailboxKeyScheduleInput {
            suite_id: Hash512::from_bytes([0x11; 64]),
            ceremony_context_hash: Hash512::from_bytes([0x22; 64]),
            action_context_hash: Hash512::from_bytes([0x33; 64]),
            roster_hash: Hash512::from_bytes([0x44; 64]),
            source_participant_id: ParticipantIdentity::from_bytes([0x55; 64]),
            recipient_participant_id: ParticipantIdentity::from_bytes([0x66; 64]),
            producer_sequence: 7,
            envelope_attempt_identifier: [0x77; MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
            payload_type: MailboxPayloadType::RecipientPrivateVssShare,
            statement_hash: Hash512::from_bytes([0x88; 64]),
            ordered_material_roots: vec![
                Hash512::from_bytes([0x91; 64]),
                Hash512::from_bytes([0x92; 64]),
            ],
            kem_ciphertext_hash: derive_mailbox_kem_ciphertext_hash(&kem_ciphertext)
                .expect("KEM ciphertext hash derives"),
        }
        .checked()
        .expect("key-schedule input is valid")
    }

    fn signed_envelope() -> SignedMailboxEnvelope {
        let plaintext_byte_length = 64;
        let associated_data =
            MailboxAssociatedData::new(key_schedule_input(), plaintext_byte_length)
                .expect("associated data is valid");
        let descriptor =
            StreamDescriptor::new(plaintext_byte_length, vec![Hash512::from_bytes([0xa1; 64])])
                .expect("ciphertext descriptor is valid");
        SignedMailboxEnvelope::new(
            associated_data,
            [0x5a; MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH],
            descriptor,
            [0xb1; MAILBOX_GCM_TAG_BYTE_LENGTH],
            [0xc1; MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH],
        )
        .expect("signed envelope is valid")
    }

    #[test]
    fn compact_mailbox_schemas_round_trip_without_fixed_metadata() {
        let key_schedule = key_schedule_input();
        let key_schedule_bytes = key_schedule.encode().expect("key schedule encodes");
        assert_eq!(
            MailboxKeyScheduleInput::decode(
                &key_schedule_bytes,
                &CanonicalDecodeLimits::default(),
            )
            .expect("key schedule decodes"),
            key_schedule
        );
        assert_eq!(
            CanonicalTuple::decode(&key_schedule_bytes, &CanonicalDecodeLimits::default(),)
                .expect("key-schedule tuple decodes")
                .items
                .len(),
            12
        );

        let associated_data =
            MailboxAssociatedData::new(key_schedule, 64).expect("associated data is valid");
        let associated_data_bytes = associated_data.encode().expect("associated data encodes");
        assert_eq!(
            MailboxAssociatedData::decode(
                &associated_data_bytes,
                &CanonicalDecodeLimits::default(),
            )
            .expect("associated data decodes"),
            associated_data
        );
        assert_eq!(
            CanonicalTuple::decode(&associated_data_bytes, &CanonicalDecodeLimits::default(),)
                .expect("associated-data tuple decodes")
                .items
                .len(),
            13
        );

        let envelope = signed_envelope();
        let envelope_bytes = envelope.encode().expect("signed envelope encodes");
        assert_eq!(
            SignedMailboxEnvelope::decode(&envelope_bytes, &CanonicalDecodeLimits::default(),)
                .expect("signed envelope decodes"),
            envelope
        );
        assert_eq!(
            CanonicalTuple::decode(&envelope_bytes, &CanonicalDecodeLimits::default())
                .expect("envelope tuple decodes")
                .items
                .len(),
            5
        );
    }

    #[test]
    fn envelope_hash_binds_unsigned_envelope_and_excludes_its_signature() {
        let envelope = signed_envelope();
        let expected_hash = envelope.envelope_hash().expect("envelope hash derives");

        let mut changed_tag = envelope.clone();
        changed_tag.gcm_tag[0] ^= 1;
        assert_ne!(
            changed_tag
                .envelope_hash()
                .expect("changed envelope hash derives"),
            expected_hash
        );

        let mut changed_attempt = envelope.clone();
        changed_attempt
            .associated_data
            .key_schedule_input
            .envelope_attempt_identifier[0] ^= 1;
        assert_ne!(
            changed_attempt
                .envelope_hash()
                .expect("changed envelope hash derives"),
            expected_hash
        );

        let mut changed_signature = envelope;
        changed_signature.source_signature[0] ^= 1;
        assert_eq!(
            changed_signature
                .envelope_hash()
                .expect("signature-independent envelope hash derives"),
            expected_hash
        );
    }

    #[test]
    fn key_schedule_salt_binds_encapsulation_but_material_roots_remain_hkdf_info() {
        let input = key_schedule_input();
        let salt = input.hkdf_extract_salt().expect("extract salt derives");
        assert_eq!(salt.len(), MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH);

        let mut changed_attempt = input.clone();
        changed_attempt.envelope_attempt_identifier[31] ^= 1;
        assert_ne!(
            changed_attempt
                .hkdf_extract_salt()
                .expect("changed extract salt derives"),
            salt
        );

        let mut reordered_roots = input;
        reordered_roots.ordered_material_roots.swap(0, 1);
        assert_eq!(
            reordered_roots
                .hkdf_extract_salt()
                .expect("root-independent extract salt derives"),
            salt
        );
        assert_ne!(
            reordered_roots.encode().expect("reordered input encodes"),
            key_schedule_input().encode().expect("input encodes")
        );
    }

    #[test]
    fn payload_root_and_envelope_binding_errors_refuse() {
        let input = key_schedule_input();
        assert!(
            MailboxKeyScheduleInput {
                payload_type: MailboxPayloadType::PublicRandomnessRecoveryShare,
                ..input.clone()
            }
            .checked()
            .is_err()
        );

        let mut missing_private_roots = input.clone();
        missing_private_roots.ordered_material_roots.clear();
        assert!(missing_private_roots.encode().is_err());

        let mut wrong_kem_hash = signed_envelope();
        wrong_kem_hash
            .associated_data
            .key_schedule_input
            .kem_ciphertext_hash = Hash512::from_bytes([0xdd; 64]);
        assert_eq!(
            wrong_kem_hash
                .encode()
                .expect_err("wrong KEM hash refuses")
                .refusal_reason,
            RefusalReason::WrongHashOrRoot
        );

        let mut wrong_ciphertext_length = signed_envelope();
        wrong_ciphertext_length
            .associated_data
            .plaintext_byte_length += 1;
        assert_eq!(
            wrong_ciphertext_length
                .encode()
                .expect_err("wrong ciphertext length refuses")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength
        );
    }

    #[test]
    fn hostile_mailbox_encodings_refuse_without_panicking() {
        let encoded = signed_envelope().encode().expect("envelope encodes");
        let mut malformed_values = vec![
            encoded[..encoded.len() - 1].to_vec(),
            {
                let mut bytes = encoded.clone();
                bytes.push(0);
                bytes
            },
            {
                let mut bytes = encoded.clone();
                bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
                bytes
            },
        ];

        let mut malformed_associated_data =
            key_schedule_input().encode().expect("key schedule encodes");
        let material_roots_payload_offset =
            tuple_item_payload_offset(&malformed_associated_data, 10);
        malformed_associated_data
            [material_roots_payload_offset + 2..material_roots_payload_offset + 6]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        malformed_values.push(malformed_associated_data);

        for malformed in malformed_values {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                if malformed.starts_with(&SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER.to_le_bytes()) {
                    SignedMailboxEnvelope::decode(&malformed, &CanonicalDecodeLimits::default())
                        .map(|_| ())
                } else {
                    MailboxKeyScheduleInput::decode(&malformed, &CanonicalDecodeLimits::default())
                        .map(|_| ())
                }
            }));
            assert!(outcome.is_ok(), "hostile mailbox decode must not panic");
            assert!(outcome.expect("decode completed").is_err());
        }
    }

    fn tuple_item_payload_offset(bytes: &[u8], requested_index: usize) -> usize {
        let mut offset = 8;
        for item_index in 0..=requested_index {
            let payload_length = u32::from_le_bytes(
                bytes[offset + 2..offset + 6]
                    .try_into()
                    .expect("test item header is complete"),
            ) as usize;
            let payload_offset = offset + 6;
            if item_index == requested_index {
                return payload_offset;
            }
            offset = payload_offset + payload_length;
        }
        unreachable!("requested test item exists")
    }
}
