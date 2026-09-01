use core::fmt;
use std::collections::BTreeSet;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    hash_foundation_tuple_512,
};

use super::action_signature::KEY_BYTE_LENGTH as ACTION_SIGNATURE_KEY_BYTE_LENGTH;
use super::pair_encryption::{
    ENCRYPTION_KEY_BYTE_LENGTH as PAIR_ENCRYPTION_KEY_BYTE_LENGTH, validate_encryption_key,
};

pub const ACTION_SIGNATURE_PURPOSE_COUNT: usize = 4;
pub const ACTION_KEY_SET_NONCE_BYTE_LENGTH: usize = 32;
pub const ACTION_KEY_SET_SCHEMA_IDENTIFIER: u16 = 0x0202;

const ACTION_SIGNATURE_VERIFICATION_KEY_SCHEMA_IDENTIFIER: u16 = 0x0200;
const PAIR_ENCRYPTION_KEY_SCHEMA_IDENTIFIER: u16 = 0x0201;
const ACTION_KEY_SET_SCHEMA_VERSION: u16 = 1;
const ACTION_KEY_SET_IDENTITY_DOMAIN: &str = "sealed-lattice/construction/action-key-set/v1";
const ACTION_KEY_SET_ROSTER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/action-key-set-roster/v1";
const NESTED_TUPLE_LIST_HEADER_BYTE_LENGTH: usize = 6;
const TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const TUPLE_ITEM_HEADER_BYTE_LENGTH: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKeySetError {
    DuplicateActionKey,
    InvalidCanonicalEncoding,
    InvalidPairEncryptionKey,
    WrongItemTypeOrLength,
    WrongParticipantCount,
    WrongProposalIdentity,
    WrongRosterPosition,
    WrongSchema,
}

impl fmt::Display for ActionKeySetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateActionKey => "action key set contains a duplicate key or nonce",
            Self::InvalidCanonicalEncoding => "action key set is not canonically encoded",
            Self::InvalidPairEncryptionKey => "action key set contains an invalid pair key",
            Self::WrongItemTypeOrLength => "action key set field has the wrong type or length",
            Self::WrongParticipantCount => {
                "action key set participant count is outside the supported profile"
            }
            Self::WrongProposalIdentity => {
                "action key set does not bind the common proposal identity"
            }
            Self::WrongRosterPosition => "action key set roster position is invalid",
            Self::WrongSchema => "action key set has the wrong schema or version",
        })
    }
}

impl std::error::Error for ActionKeySetError {}

#[derive(Clone, PartialEq, Eq)]
pub struct ActionKeySet {
    participant_count: u16,
    proposal_identity: Hash512,
    roster_position: u16,
    nonce: [u8; ACTION_KEY_SET_NONCE_BYTE_LENGTH],
    action_signature_verification_keys:
        [[u8; ACTION_SIGNATURE_KEY_BYTE_LENGTH]; ACTION_SIGNATURE_PURPOSE_COUNT],
    pair_encryption_keys: Vec<[u8; PAIR_ENCRYPTION_KEY_BYTE_LENGTH]>,
}

impl ActionKeySet {
    pub fn new(
        participant_count: u16,
        proposal_identity: Hash512,
        roster_position: u16,
        nonce: [u8; ACTION_KEY_SET_NONCE_BYTE_LENGTH],
        action_signature_verification_keys: [[u8; ACTION_SIGNATURE_KEY_BYTE_LENGTH];
            ACTION_SIGNATURE_PURPOSE_COUNT],
        pair_encryption_keys: Vec<[u8; PAIR_ENCRYPTION_KEY_BYTE_LENGTH]>,
    ) -> Result<Self, ActionKeySetError> {
        validate_participant_count(participant_count)?;
        if roster_position >= participant_count {
            return Err(ActionKeySetError::WrongRosterPosition);
        }
        if pair_encryption_keys.len() != usize::from(participant_count - 1) {
            return Err(ActionKeySetError::WrongItemTypeOrLength);
        }
        let mut action_signature_keys = BTreeSet::new();
        for key in &action_signature_verification_keys {
            if !action_signature_keys.insert(key.as_slice()) {
                return Err(ActionKeySetError::DuplicateActionKey);
            }
        }
        let mut pair_keys = BTreeSet::new();
        for key in &pair_encryption_keys {
            validate_encryption_key(key)
                .map_err(|_| ActionKeySetError::InvalidPairEncryptionKey)?;
            if !pair_keys.insert(key.as_slice()) {
                return Err(ActionKeySetError::DuplicateActionKey);
            }
        }
        Ok(Self {
            participant_count,
            proposal_identity,
            roster_position,
            nonce,
            action_signature_verification_keys,
            pair_encryption_keys,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ActionKeySetError> {
        let signature_keys = self
            .action_signature_verification_keys
            .iter()
            .map(|key| key_tuple(ACTION_SIGNATURE_VERIFICATION_KEY_SCHEMA_IDENTIFIER, key))
            .collect::<Result<Vec<_>, _>>()?;
        let pair_keys = self
            .pair_encryption_keys
            .iter()
            .map(|key| key_tuple(PAIR_ENCRYPTION_KEY_SCHEMA_IDENTIFIER, key))
            .collect::<Result<Vec<_>, _>>()?;
        CanonicalTuple::new(
            ACTION_KEY_SET_SCHEMA_IDENTIFIER,
            ACTION_KEY_SET_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.proposal_identity.into_bytes()),
                CanonicalItem::unsigned16(self.roster_position),
                CanonicalItem::fixed_bytes(self.nonce)
                    .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)?,
                CanonicalItem::nested_tuple_list(&signature_keys)
                    .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)?,
                CanonicalItem::nested_tuple_list(&pair_keys)
                    .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)?,
            ],
        )
        .encode()
        .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)
    }

    pub fn decode(participant_count: u16, bytes: &[u8]) -> Result<Self, ActionKeySetError> {
        validate_participant_count(participant_count)?;
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)?;
        require_tuple(&tuple, ACTION_KEY_SET_SCHEMA_IDENTIFIER, 5)?;
        let proposal_identity = Hash512::from_bytes(read_fixed_item(&tuple.items[0])?);
        let roster_position = read_unsigned16(&tuple.items[1])?;
        let nonce = read_fixed_item(&tuple.items[2])?;
        let action_signature_verification_keys =
            decode_key_list::<ACTION_SIGNATURE_KEY_BYTE_LENGTH>(
                &tuple.items[3],
                ACTION_SIGNATURE_PURPOSE_COUNT,
                ACTION_SIGNATURE_VERIFICATION_KEY_SCHEMA_IDENTIFIER,
            )?
            .try_into()
            .map_err(|_| ActionKeySetError::WrongItemTypeOrLength)?;
        let pair_encryption_keys = decode_key_list::<PAIR_ENCRYPTION_KEY_BYTE_LENGTH>(
            &tuple.items[4],
            usize::from(participant_count - 1),
            PAIR_ENCRYPTION_KEY_SCHEMA_IDENTIFIER,
        )?;
        let key_set = Self::new(
            participant_count,
            proposal_identity,
            roster_position,
            nonce,
            action_signature_verification_keys,
            pair_encryption_keys,
        )?;
        if key_set.encode()?.as_slice() != bytes {
            return Err(ActionKeySetError::InvalidCanonicalEncoding);
        }
        Ok(key_set)
    }

    pub fn body_identity(&self) -> Result<Hash512, ActionKeySetError> {
        hash_foundation_tuple_512(
            ACTION_KEY_SET_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)
                .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)?],
        )
        .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)
    }

    pub const fn proposal_identity(&self) -> Hash512 {
        self.proposal_identity
    }

    pub const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub fn action_signature_verification_key(
        &self,
        purpose_index: usize,
    ) -> Option<&[u8; ACTION_SIGNATURE_KEY_BYTE_LENGTH]> {
        self.action_signature_verification_keys.get(purpose_index)
    }

    pub fn pair_encryption_key_for_sender(
        &self,
        sender_position: u16,
    ) -> Option<&[u8; PAIR_ENCRYPTION_KEY_BYTE_LENGTH]> {
        if sender_position >= self.participant_count || sender_position == self.roster_position {
            return None;
        }
        let key_index = if sender_position < self.roster_position {
            usize::from(sender_position)
        } else {
            usize::from(sender_position - 1)
        };
        self.pair_encryption_keys.get(key_index)
    }
}

pub fn validate_complete_action_key_set_roster(
    key_sets: &[ActionKeySet],
) -> Result<(), ActionKeySetError> {
    let participant_count =
        u16::try_from(key_sets.len()).map_err(|_| ActionKeySetError::WrongParticipantCount)?;
    validate_participant_count(participant_count)?;
    let proposal_identity = key_sets
        .first()
        .ok_or(ActionKeySetError::WrongParticipantCount)?
        .proposal_identity;
    let mut nonces = BTreeSet::new();
    let mut signature_keys = BTreeSet::new();
    let mut pair_keys = BTreeSet::new();
    for (position, key_set) in key_sets.iter().enumerate() {
        if key_set.participant_count != participant_count
            || usize::from(key_set.roster_position) != position
        {
            return Err(ActionKeySetError::WrongRosterPosition);
        }
        if key_set.proposal_identity != proposal_identity {
            return Err(ActionKeySetError::WrongProposalIdentity);
        }
        if !nonces.insert(key_set.nonce) {
            return Err(ActionKeySetError::DuplicateActionKey);
        }
        for key in &key_set.action_signature_verification_keys {
            if !signature_keys.insert(key.as_slice()) {
                return Err(ActionKeySetError::DuplicateActionKey);
            }
        }
        for key in &key_set.pair_encryption_keys {
            if !pair_keys.insert(key.as_slice()) {
                return Err(ActionKeySetError::DuplicateActionKey);
            }
        }
    }
    Ok(())
}

pub fn action_key_set_roster_identity(
    key_sets: &[ActionKeySet],
) -> Result<Hash512, ActionKeySetError> {
    validate_complete_action_key_set_roster(key_sets)?;
    let encoded_key_sets = key_sets
        .iter()
        .map(ActionKeySet::encode)
        .collect::<Result<Vec<_>, _>>()?;
    let items = encoded_key_sets
        .iter()
        .map(|body| {
            CanonicalItem::variable_bytes(body)
                .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    hash_foundation_tuple_512(ACTION_KEY_SET_ROSTER_IDENTITY_DOMAIN, &items)
        .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)
}

fn validate_participant_count(participant_count: u16) -> Result<(), ActionKeySetError> {
    if !(MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT)
        .contains(&participant_count)
    {
        return Err(ActionKeySetError::WrongParticipantCount);
    }
    Ok(())
}

fn key_tuple<const KEY_BYTE_LENGTH: usize>(
    schema_identifier: u16,
    key: &[u8; KEY_BYTE_LENGTH],
) -> Result<CanonicalTuple, ActionKeySetError> {
    Ok(CanonicalTuple::new(
        schema_identifier,
        ACTION_KEY_SET_SCHEMA_VERSION,
        vec![
            CanonicalItem::fixed_bytes(key)
                .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)?,
        ],
    ))
}

fn require_tuple(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> Result<(), ActionKeySetError> {
    if tuple.schema_identifier != schema_identifier
        || tuple.schema_version != ACTION_KEY_SET_SCHEMA_VERSION
    {
        return Err(ActionKeySetError::WrongSchema);
    }
    if tuple.items.len() != item_count {
        return Err(ActionKeySetError::WrongItemTypeOrLength);
    }
    Ok(())
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, ActionKeySetError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(ActionKeySetError::WrongItemTypeOrLength);
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| ActionKeySetError::WrongItemTypeOrLength)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_fixed_item<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
) -> Result<[u8; BYTE_LENGTH], ActionKeySetError> {
    let expected_type = if BYTE_LENGTH == Hash512::BYTE_LENGTH {
        CanonicalItemType::Hash512
    } else {
        CanonicalItemType::RawBytes
    };
    if item.item_type() != expected_type {
        return Err(ActionKeySetError::WrongItemTypeOrLength);
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| ActionKeySetError::WrongItemTypeOrLength)
}

fn decode_key_list<const KEY_BYTE_LENGTH: usize>(
    item: &CanonicalItem,
    expected_count: usize,
    key_schema_identifier: u16,
) -> Result<Vec<[u8; KEY_BYTE_LENGTH]>, ActionKeySetError> {
    if item.item_type() != CanonicalItemType::HomogeneousList {
        return Err(ActionKeySetError::WrongItemTypeOrLength);
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < NESTED_TUPLE_LIST_HEADER_BYTE_LENGTH
        || u16::from_le_bytes([bytes[0], bytes[1]])
            != CanonicalItemType::NestedTuple.canonical_code()
        || usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
            .map_err(|_| ActionKeySetError::WrongItemTypeOrLength)?
            != expected_count
    {
        return Err(ActionKeySetError::WrongItemTypeOrLength);
    }
    let tuple_byte_length = TUPLE_HEADER_BYTE_LENGTH
        .checked_add(TUPLE_ITEM_HEADER_BYTE_LENGTH)
        .and_then(|length| length.checked_add(KEY_BYTE_LENGTH))
        .ok_or(ActionKeySetError::WrongItemTypeOrLength)?;
    let expected_byte_length = expected_count
        .checked_mul(tuple_byte_length)
        .and_then(|length| length.checked_add(NESTED_TUPLE_LIST_HEADER_BYTE_LENGTH))
        .ok_or(ActionKeySetError::WrongItemTypeOrLength)?;
    if bytes.len() != expected_byte_length {
        return Err(ActionKeySetError::WrongItemTypeOrLength);
    }
    bytes[NESTED_TUPLE_LIST_HEADER_BYTE_LENGTH..]
        .chunks_exact(tuple_byte_length)
        .map(|tuple_bytes| {
            let tuple = CanonicalTuple::decode(tuple_bytes, &CanonicalDecodeLimits::default())
                .map_err(|_| ActionKeySetError::InvalidCanonicalEncoding)?;
            require_tuple(&tuple, key_schema_identifier, 1)?;
            read_fixed_item(&tuple.items[0])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::action_signature::{
        CHAIN_COUNT, CHAIN_VALUE_BYTE_LENGTH, MAXIMUM_FRAGMENT_CHAIN_COUNT,
        derive_verification_key_fragment,
    };
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

    fn signature_verification_key(seed: u64) -> [u8; ACTION_SIGNATURE_KEY_BYTE_LENGTH] {
        let secret_key = pseudorandom_bytes::<ACTION_SIGNATURE_KEY_BYTE_LENGTH>(seed);
        let mut verification_key = [0_u8; ACTION_SIGNATURE_KEY_BYTE_LENGTH];
        for first_chain in (0..CHAIN_COUNT).step_by(MAXIMUM_FRAGMENT_CHAIN_COUNT) {
            let chain_count = MAXIMUM_FRAGMENT_CHAIN_COUNT.min(CHAIN_COUNT - first_chain);
            let start = first_chain * CHAIN_VALUE_BYTE_LENGTH;
            let end = start + chain_count * CHAIN_VALUE_BYTE_LENGTH;
            verification_key[start..end].copy_from_slice(
                &derive_verification_key_fragment(first_chain, &secret_key[start..end])
                    .expect("bounded signature fragment"),
            );
        }
        verification_key
    }

    fn action_key_set(participant_count: u16, roster_position: u16) -> ActionKeySet {
        let signature_keys = core::array::from_fn(|purpose| {
            signature_verification_key(0x1000 + u64::from(roster_position) * 16 + purpose as u64)
        });
        let pair_encryption_keys = (0..participant_count - 1)
            .map(|key_index| {
                let seed = 0x9000 + u64::from(roster_position) * 32 + u64::from(key_index);
                generate_key_pair(
                    &pseudorandom_bytes::<KEY_GENERATION_RANDOMNESS_BYTE_LENGTH>(seed),
                )
                .expect("deterministic sampler tape succeeds")
                .encryption_key
            })
            .collect();
        let mut nonce = [0_u8; ACTION_KEY_SET_NONCE_BYTE_LENGTH];
        nonce[..2].copy_from_slice(&roster_position.to_le_bytes());
        nonce[2] = 0xa7;
        ActionKeySet::new(
            participant_count,
            Hash512::from_bytes([0x31; Hash512::BYTE_LENGTH]),
            roster_position,
            nonce,
            signature_keys,
            pair_encryption_keys,
        )
        .expect("test action key set is valid")
    }

    #[test]
    fn completion_key_set_has_exact_bytes_and_canonical_identity() {
        let key_set = action_key_set(10, 4);
        let encoded = key_set.encode().expect("key set encodes");
        assert_eq!(encoded.len(), 66_954);
        let decoded = ActionKeySet::decode(10, &encoded).expect("key set decodes");
        assert_eq!(decoded.encode().expect("decoded key set encodes"), encoded);
        assert_eq!(decoded.body_identity(), key_set.body_identity());
        assert_eq!(
            decoded
                .pair_encryption_key_for_sender(3)
                .expect("lower sender key"),
            &key_set.pair_encryption_keys[3]
        );
        assert_eq!(
            decoded
                .pair_encryption_key_for_sender(5)
                .expect("higher sender key"),
            &key_set.pair_encryption_keys[4]
        );
        assert!(decoded.pair_encryption_key_for_sender(4).is_none());
    }

    #[test]
    fn complete_roster_rejects_duplicate_or_mispositioned_keys() {
        let mut key_sets = (0..10)
            .map(|position| action_key_set(10, position))
            .collect::<Vec<_>>();
        validate_complete_action_key_set_roster(&key_sets).expect("complete roster is valid");

        key_sets[1].nonce = key_sets[0].nonce;
        assert_eq!(
            validate_complete_action_key_set_roster(&key_sets),
            Err(ActionKeySetError::DuplicateActionKey)
        );
        key_sets[1].nonce[0] ^= 1;
        key_sets.swap(0, 1);
        assert_eq!(
            validate_complete_action_key_set_roster(&key_sets),
            Err(ActionKeySetError::WrongRosterPosition)
        );
    }

    #[test]
    fn malformed_or_reused_keys_refuse() {
        let key_set = action_key_set(3, 0);
        let mut duplicate_signature_keys = key_set.action_signature_verification_keys;
        duplicate_signature_keys[1] = duplicate_signature_keys[0];
        assert!(matches!(
            ActionKeySet::new(
                3,
                key_set.proposal_identity,
                0,
                key_set.nonce,
                duplicate_signature_keys,
                key_set.pair_encryption_keys.clone(),
            ),
            Err(ActionKeySetError::DuplicateActionKey)
        ));

        let mut encoded = key_set.encode().expect("key set encodes");
        encoded[0] ^= 1;
        assert!(matches!(
            ActionKeySet::decode(3, &encoded),
            Err(ActionKeySetError::WrongSchema)
        ));

        let mut invalid_pair_keys = key_set.pair_encryption_keys.clone();
        invalid_pair_keys[0][..3].fill(0xff);
        assert!(matches!(
            ActionKeySet::new(
                3,
                key_set.proposal_identity,
                0,
                key_set.nonce,
                key_set.action_signature_verification_keys,
                invalid_pair_keys,
            ),
            Err(ActionKeySetError::InvalidPairEncryptionKey)
        ));
    }
}
