use core::fmt;

use zeroize::Zeroize;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    hash_foundation_tuple_512,
};

use super::authenticated_record::{
    KEY_BYTE_LENGTH as RECORD_KEY_BYTE_LENGTH, PLAINTEXT_BYTE_LENGTH, SEALED_RECORD_BYTE_LENGTH,
    open as open_record, seal as seal_record,
};
use super::pair_encryption::{
    CIPHERTEXT_BYTE_LENGTH as PAIR_CIPHERTEXT_BYTE_LENGTH,
    DECRYPTION_KEY_BYTE_LENGTH as PAIR_DECRYPTION_KEY_BYTE_LENGTH,
    ENCRYPTION_RANDOMNESS_BYTE_LENGTH as PAIR_ENCRYPTION_RANDOMNESS_BYTE_LENGTH,
    decrypt as decrypt_record_key, encrypt as encrypt_record_key, validate_encryption_key,
};

pub const PRIVATE_PREPARATION_HEADER_BYTE_LENGTH: usize = 356;
pub const PRIVATE_PREPARATION_BODY_BYTE_LENGTH: usize = 8
    + 3 * 6
    + PRIVATE_PREPARATION_HEADER_BYTE_LENGTH
    + PAIR_CIPHERTEXT_BYTE_LENGTH
    + SEALED_RECORD_BYTE_LENGTH;

const PRIVATE_PREPARATION_HEADER_SCHEMA_IDENTIFIER: u16 = 0x0203;
const PRIVATE_PREPARATION_BODY_SCHEMA_IDENTIFIER: u16 = 0x0204;
const PRIVATE_PREPARATION_SCHEMA_VERSION: u16 = 1;
const PRIVATE_PREPARATION_PHASE: u16 = 1;
const PRIVATE_PREPARATION_PURPOSE: u16 = 1;
const PRIVATE_PREPARATION_STREAM_ORDINAL: u64 = 0;
const COMPLETION_PROFILE_PARTICIPANT_COUNT: u16 = 10;
const PAIR_ENCRYPTION_KEY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/pair-encryption-key/v1";
const PRIVATE_PREPARATION_BODY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/private-preparation-body/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivatePreparationBodyError {
    AuthenticationFailed,
    InvalidCanonicalEncoding,
    InvalidPairCiphertext,
    InvalidPairEncryptionKey,
    WrongContext,
    WrongItemTypeOrLength,
    WrongParticipantCount,
    WrongParticipantPosition,
    WrongSchema,
}

impl fmt::Display for PrivatePreparationBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthenticationFailed => "private preparation body authentication failed",
            Self::InvalidCanonicalEncoding => "private preparation body is not canonically encoded",
            Self::InvalidPairCiphertext => "private preparation pair ciphertext is invalid",
            Self::InvalidPairEncryptionKey => "private preparation pair key is invalid",
            Self::WrongContext => "private preparation body has the wrong context",
            Self::WrongItemTypeOrLength => {
                "private preparation body field has the wrong type or length"
            }
            Self::WrongParticipantCount => {
                "private preparation body is only defined for the completion profile"
            }
            Self::WrongParticipantPosition => {
                "private preparation sender or recipient position is invalid"
            }
            Self::WrongSchema => "private preparation body has the wrong schema or version",
        })
    }
}

impl std::error::Error for PrivatePreparationBodyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatePreparationContext {
    participant_count: u16,
    action_proposal_identity: Hash512,
    action_key_set_roster_identity: Hash512,
    preparation_attempt: u16,
    predecessor_identity: Hash512,
    sender_position: u16,
    recipient_position: u16,
    pair_encryption_key_identity: Hash512,
}

impl PrivatePreparationContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        participant_count: u16,
        action_proposal_identity: Hash512,
        action_key_set_roster_identity: Hash512,
        preparation_attempt: u16,
        predecessor_identity: Hash512,
        sender_position: u16,
        recipient_position: u16,
        pair_encryption_key: &[u8],
    ) -> Result<Self, PrivatePreparationBodyError> {
        validate_participant_positions(participant_count, sender_position, recipient_position)?;
        validate_encryption_key(pair_encryption_key)
            .map_err(|_| PrivatePreparationBodyError::InvalidPairEncryptionKey)?;
        Ok(Self {
            participant_count,
            action_proposal_identity,
            action_key_set_roster_identity,
            preparation_attempt,
            predecessor_identity,
            sender_position,
            recipient_position,
            pair_encryption_key_identity: pair_encryption_key_identity(pair_encryption_key)?,
        })
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            PRIVATE_PREPARATION_HEADER_SCHEMA_IDENTIFIER,
            PRIVATE_PREPARATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.action_proposal_identity.into_bytes()),
                CanonicalItem::hash512(self.action_key_set_roster_identity.into_bytes()),
                CanonicalItem::unsigned16(self.preparation_attempt),
                CanonicalItem::hash512(self.predecessor_identity.into_bytes()),
                CanonicalItem::unsigned16(PRIVATE_PREPARATION_PHASE),
                CanonicalItem::unsigned16(self.sender_position),
                CanonicalItem::unsigned16(self.recipient_position),
                CanonicalItem::unsigned16(PRIVATE_PREPARATION_PURPOSE),
                CanonicalItem::unsigned64(PRIVATE_PREPARATION_STREAM_ORDINAL),
                CanonicalItem::hash512(self.pair_encryption_key_identity.into_bytes()),
                CanonicalItem::unsigned64(PLAINTEXT_BYTE_LENGTH as u64),
            ],
        )
    }

    pub fn encode(self) -> Result<Vec<u8>, PrivatePreparationBodyError> {
        let encoded = self
            .canonical_tuple()
            .encode()
            .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?;
        if encoded.len() != PRIVATE_PREPARATION_HEADER_BYTE_LENGTH {
            return Err(PrivatePreparationBodyError::InvalidCanonicalEncoding);
        }
        Ok(encoded)
    }

    fn decode(participant_count: u16, bytes: &[u8]) -> Result<Self, PrivatePreparationBodyError> {
        validate_participant_count(participant_count)?;
        if bytes.len() != PRIVATE_PREPARATION_HEADER_BYTE_LENGTH {
            return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
        }
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?;
        require_tuple(&tuple, PRIVATE_PREPARATION_HEADER_SCHEMA_IDENTIFIER, 11)?;
        let context = Self {
            participant_count,
            action_proposal_identity: read_hash512(&tuple.items[0])?,
            action_key_set_roster_identity: read_hash512(&tuple.items[1])?,
            preparation_attempt: read_unsigned16(&tuple.items[2])?,
            predecessor_identity: read_hash512(&tuple.items[3])?,
            sender_position: read_unsigned16(&tuple.items[5])?,
            recipient_position: read_unsigned16(&tuple.items[6])?,
            pair_encryption_key_identity: read_hash512(&tuple.items[9])?,
        };
        validate_participant_positions(
            participant_count,
            context.sender_position,
            context.recipient_position,
        )?;
        if read_unsigned16(&tuple.items[4])? != PRIVATE_PREPARATION_PHASE
            || read_unsigned16(&tuple.items[7])? != PRIVATE_PREPARATION_PURPOSE
            || read_unsigned64(&tuple.items[8])? != PRIVATE_PREPARATION_STREAM_ORDINAL
            || read_unsigned64(&tuple.items[10])? != PLAINTEXT_BYTE_LENGTH as u64
            || context.encode()?.as_slice() != bytes
        {
            return Err(PrivatePreparationBodyError::WrongContext);
        }
        Ok(context)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivatePreparationBody {
    pub(super) context: PrivatePreparationContext,
    encrypted_record_key: [u8; PAIR_CIPHERTEXT_BYTE_LENGTH],
    sealed_record: [u8; SEALED_RECORD_BYTE_LENGTH],
}

impl PrivatePreparationBody {
    pub fn seal(
        context: PrivatePreparationContext,
        pair_encryption_key: &[u8],
        record_key: &[u8],
        pair_encryption_randomness: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, PrivatePreparationBodyError> {
        if pair_encryption_key_identity(pair_encryption_key)?
            != context.pair_encryption_key_identity
        {
            return Err(PrivatePreparationBodyError::WrongContext);
        }
        if record_key.len() != RECORD_KEY_BYTE_LENGTH
            || pair_encryption_randomness.len() != PAIR_ENCRYPTION_RANDOMNESS_BYTE_LENGTH
            || plaintext.len() != PLAINTEXT_BYTE_LENGTH
        {
            return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
        }
        let header = context.encode()?;
        let encrypted_record_key =
            encrypt_record_key(pair_encryption_key, record_key, pair_encryption_randomness)
                .map_err(|_| PrivatePreparationBodyError::InvalidPairCiphertext)?;
        let sealed_record = seal_record(record_key, &header, plaintext)
            .map_err(|_| PrivatePreparationBodyError::AuthenticationFailed)?
            .try_into()
            .map_err(|_| PrivatePreparationBodyError::WrongItemTypeOrLength)?;
        Ok(Self {
            context,
            encrypted_record_key,
            sealed_record,
        })
    }

    fn canonical_tuple(&self) -> Result<CanonicalTuple, PrivatePreparationBodyError> {
        Ok(CanonicalTuple::new(
            PRIVATE_PREPARATION_BODY_SCHEMA_IDENTIFIER,
            PRIVATE_PREPARATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.context.canonical_tuple())
                    .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?,
                CanonicalItem::fixed_bytes(self.encrypted_record_key)
                    .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?,
                CanonicalItem::fixed_bytes(self.sealed_record)
                    .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?,
            ],
        ))
    }

    pub fn encode(&self) -> Result<Vec<u8>, PrivatePreparationBodyError> {
        let encoded = self
            .canonical_tuple()?
            .encode()
            .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?;
        if encoded.len() != PRIVATE_PREPARATION_BODY_BYTE_LENGTH {
            return Err(PrivatePreparationBodyError::InvalidCanonicalEncoding);
        }
        Ok(encoded)
    }

    pub fn decode(
        participant_count: u16,
        bytes: &[u8],
    ) -> Result<Self, PrivatePreparationBodyError> {
        validate_participant_count(participant_count)?;
        if bytes.len() != PRIVATE_PREPARATION_BODY_BYTE_LENGTH {
            return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
        }
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?;
        require_tuple(&tuple, PRIVATE_PREPARATION_BODY_SCHEMA_IDENTIFIER, 3)?;
        if tuple.items[0].item_type() != CanonicalItemType::NestedTuple {
            return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
        }
        let body = Self {
            context: PrivatePreparationContext::decode(
                participant_count,
                tuple.items[0].canonical_bytes(),
            )?,
            encrypted_record_key: read_raw_fixed_bytes(&tuple.items[1])?,
            sealed_record: read_raw_fixed_bytes(&tuple.items[2])?,
        };
        if body.encode()?.as_slice() != bytes {
            return Err(PrivatePreparationBodyError::InvalidCanonicalEncoding);
        }
        Ok(body)
    }

    pub fn body_identity(&self) -> Result<Hash512, PrivatePreparationBodyError> {
        hash_foundation_tuple_512(
            PRIVATE_PREPARATION_BODY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)
                .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?],
        )
        .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)
    }

    pub fn open(
        &self,
        expected_context: PrivatePreparationContext,
        pair_decryption_key: &[u8],
    ) -> Result<Vec<u8>, PrivatePreparationBodyError> {
        if self.context != expected_context
            || pair_decryption_key.len() != PAIR_DECRYPTION_KEY_BYTE_LENGTH
        {
            return Err(PrivatePreparationBodyError::WrongContext);
        }
        let mut record_key = decrypt_record_key(pair_decryption_key, &self.encrypted_record_key)
            .map_err(|_| PrivatePreparationBodyError::InvalidPairCiphertext)?;
        let header = self.context.encode()?;
        let result = open_record(&record_key, &header, &self.sealed_record)
            .map_err(|_| PrivatePreparationBodyError::AuthenticationFailed);
        record_key.zeroize();
        result
    }
}

fn pair_encryption_key_identity(
    pair_encryption_key: &[u8],
) -> Result<Hash512, PrivatePreparationBodyError> {
    validate_encryption_key(pair_encryption_key)
        .map_err(|_| PrivatePreparationBodyError::InvalidPairEncryptionKey)?;
    hash_foundation_tuple_512(
        PAIR_ENCRYPTION_KEY_IDENTITY_DOMAIN,
        &[CanonicalItem::fixed_bytes(pair_encryption_key)
            .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)?],
    )
    .map_err(|_| PrivatePreparationBodyError::InvalidCanonicalEncoding)
}

fn validate_participant_count(participant_count: u16) -> Result<(), PrivatePreparationBodyError> {
    if participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(PrivatePreparationBodyError::WrongParticipantCount);
    }
    Ok(())
}

fn validate_participant_positions(
    participant_count: u16,
    sender_position: u16,
    recipient_position: u16,
) -> Result<(), PrivatePreparationBodyError> {
    validate_participant_count(participant_count)?;
    if sender_position >= participant_count
        || recipient_position >= participant_count
        || sender_position == recipient_position
    {
        return Err(PrivatePreparationBodyError::WrongParticipantPosition);
    }
    Ok(())
}

fn require_tuple(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> Result<(), PrivatePreparationBodyError> {
    if tuple.schema_identifier != schema_identifier
        || tuple.schema_version != PRIVATE_PREPARATION_SCHEMA_VERSION
    {
        return Err(PrivatePreparationBodyError::WrongSchema);
    }
    if tuple.items.len() != item_count {
        return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
    }
    Ok(())
}

fn read_hash512(item: &CanonicalItem) -> Result<Hash512, PrivatePreparationBodyError> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
    }
    Ok(Hash512::from_bytes(read_fixed_bytes(item)?))
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, PrivatePreparationBodyError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
    }
    Ok(u16::from_le_bytes(read_fixed_bytes(item)?))
}

fn read_unsigned64(item: &CanonicalItem) -> Result<u64, PrivatePreparationBodyError> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
    }
    Ok(u64::from_le_bytes(read_fixed_bytes(item)?))
}

fn read_fixed_bytes<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
) -> Result<[u8; BYTE_LENGTH], PrivatePreparationBodyError> {
    if item.canonical_bytes().len() != BYTE_LENGTH {
        return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| PrivatePreparationBodyError::WrongItemTypeOrLength)
}

fn read_raw_fixed_bytes<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
) -> Result<[u8; BYTE_LENGTH], PrivatePreparationBodyError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(PrivatePreparationBodyError::WrongItemTypeOrLength);
    }
    read_fixed_bytes(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::pair_encryption::{
        KEY_GENERATION_RANDOMNESS_BYTE_LENGTH, generate_key_pair,
    };

    fn pseudorandom_bytes<const LENGTH: usize>(seed: u64) -> [u8; LENGTH] {
        let mut state = seed;
        core::array::from_fn(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
    }

    fn fixture() -> (
        PrivatePreparationContext,
        super::super::pair_encryption::PairEncryptionKeyPair,
        [u8; RECORD_KEY_BYTE_LENGTH],
        [u8; PAIR_ENCRYPTION_RANDOMNESS_BYTE_LENGTH],
        Vec<u8>,
    ) {
        let pair =
            generate_key_pair(&pseudorandom_bytes::<KEY_GENERATION_RANDOMNESS_BYTE_LENGTH>(0x91a2))
                .expect("deterministic pair key");
        let context = PrivatePreparationContext::new(
            10,
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x22; 64]),
            7,
            Hash512::from_bytes([0x33; 64]),
            2,
            8,
            &pair.encryption_key,
        )
        .expect("valid private preparation context");
        let plaintext = (0..PLAINTEXT_BYTE_LENGTH)
            .map(|index| ((index * 19 + 23) % 251) as u8)
            .collect();
        (
            context,
            pair,
            [0x47; RECORD_KEY_BYTE_LENGTH],
            pseudorandom_bytes::<PAIR_ENCRYPTION_RANDOMNESS_BYTE_LENGTH>(0x8123),
            plaintext,
        )
    }

    #[test]
    fn exact_body_round_trip_and_identity() {
        let (context, pair, record_key, randomness, plaintext) = fixture();
        let body = PrivatePreparationBody::seal(
            context,
            &pair.encryption_key,
            &record_key,
            &randomness,
            &plaintext,
        )
        .expect("private preparation body seals");
        assert_eq!(context.encode().expect("header encodes").len(), 356);
        let encoded = body.encode().expect("body encodes");
        assert_eq!(encoded.len(), 8_322);
        let decoded = PrivatePreparationBody::decode(10, &encoded).expect("body decodes");
        assert_eq!(decoded.context, context);
        assert_eq!(
            decoded
                .open(context, &pair.decryption_key)
                .expect("body opens"),
            plaintext
        );
        assert_eq!(decoded.body_identity(), body.body_identity());
    }

    #[test]
    fn wrong_context_and_mutations_refuse() {
        let (context, pair, record_key, randomness, plaintext) = fixture();
        let body = PrivatePreparationBody::seal(
            context,
            &pair.encryption_key,
            &record_key,
            &randomness,
            &plaintext,
        )
        .expect("private preparation body seals");
        let mut wrong_context = context;
        wrong_context.preparation_attempt += 1;
        assert_eq!(
            body.open(wrong_context, &pair.decryption_key),
            Err(PrivatePreparationBodyError::WrongContext)
        );

        let mut wrong_schema = body.encode().expect("body encodes");
        wrong_schema[0] ^= 1;
        assert!(PrivatePreparationBody::decode(10, &wrong_schema).is_err());

        let original_identity = body.body_identity().expect("identity hashes");
        let mut pair_ciphertext_mutation = body.encode().expect("body encodes");
        pair_ciphertext_mutation[376] ^= 1;
        let pair_ciphertext_mutation =
            PrivatePreparationBody::decode(10, &pair_ciphertext_mutation)
                .expect("ciphertext mutation remains canonical");
        assert_ne!(
            pair_ciphertext_mutation
                .body_identity()
                .expect("mutated identity hashes"),
            original_identity
        );
        match pair_ciphertext_mutation.open(context, &pair.decryption_key) {
            Ok(candidate) => assert_eq!(candidate, plaintext),
            Err(error) => assert_eq!(error, PrivatePreparationBodyError::AuthenticationFailed),
        }

        let mut record_mutation = body.encode().expect("body encodes");
        record_mutation[PRIVATE_PREPARATION_BODY_BYTE_LENGTH - 1] ^= 1;
        let record_mutation = PrivatePreparationBody::decode(10, &record_mutation)
            .expect("record mutation remains canonical");
        assert_ne!(
            record_mutation
                .body_identity()
                .expect("mutated identity hashes"),
            original_identity
        );
        assert_eq!(
            record_mutation.open(context, &pair.decryption_key),
            Err(PrivatePreparationBodyError::AuthenticationFailed)
        );

        let mut mutated = body.clone();
        mutated.sealed_record[0] ^= 1;
        assert_eq!(
            mutated.open(context, &pair.decryption_key),
            Err(PrivatePreparationBodyError::AuthenticationFailed)
        );
    }

    #[test]
    fn invalid_pair_and_participant_relations_refuse() {
        let (context, pair, record_key, randomness, plaintext) = fixture();
        assert_eq!(
            PrivatePreparationContext::new(
                9,
                context.action_proposal_identity,
                context.action_key_set_roster_identity,
                context.preparation_attempt,
                context.predecessor_identity,
                2,
                8,
                &pair.encryption_key,
            ),
            Err(PrivatePreparationBodyError::WrongParticipantCount)
        );
        assert_eq!(
            PrivatePreparationContext::new(
                10,
                context.action_proposal_identity,
                context.action_key_set_roster_identity,
                context.preparation_attempt,
                context.predecessor_identity,
                2,
                2,
                &pair.encryption_key,
            ),
            Err(PrivatePreparationBodyError::WrongParticipantPosition)
        );

        let other_pair =
            generate_key_pair(&pseudorandom_bytes::<KEY_GENERATION_RANDOMNESS_BYTE_LENGTH>(0x91a3))
                .expect("other pair key");
        assert!(matches!(
            PrivatePreparationBody::seal(
                context,
                &other_pair.encryption_key,
                &record_key,
                &randomness,
                &plaintext,
            ),
            Err(PrivatePreparationBodyError::WrongContext)
        ));
    }
}
