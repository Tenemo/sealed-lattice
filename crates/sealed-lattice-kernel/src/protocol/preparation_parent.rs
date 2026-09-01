use core::fmt;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    hash_foundation_tuple_512,
};

use super::action_key_set::{ActionKeySet, action_key_set_roster_identity};
use super::action_signature::{KEY_BYTE_LENGTH as ACTION_SIGNATURE_BYTE_LENGTH, verify_complete};
use super::private_preparation_body::{PrivatePreparationBody, PrivatePreparationContext};

pub const SUBSET_COMMITMENT_COUNT: usize = 120;
pub const SUBSET_COMMITMENT_BYTE_LENGTH: usize = 64;
pub const PREPARATION_PARENT_BODY_BYTE_LENGTH: usize = 8
    + 7 * 6
    + 3 * Hash512::BYTE_LENGTH
    + 2 * 2
    + SUBSET_COMMITMENT_COUNT * SUBSET_COMMITMENT_BYTE_LENGTH
    + 9 * Hash512::BYTE_LENGTH;
pub const ACTION_SIGNATURE_CARRIER_BYTE_LENGTH: usize =
    8 + 4 * 6 + 2 + 2 + Hash512::BYTE_LENGTH + ACTION_SIGNATURE_BYTE_LENGTH;

const ACTION_SIGNATURE_CARRIER_SCHEMA_IDENTIFIER: u16 = 0x0205;
const PREPARATION_PARENT_SCHEMA_IDENTIFIER: u16 = 0x0206;
const PREPARATION_SCHEMA_VERSION: u16 = 1;
const COMPLETION_PROFILE_PARTICIPANT_COUNT: u16 = 10;
const PREPARATION_PARENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/preparation-parent/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ActionSignaturePurpose {
    Preparation = 1,
    Source = 2,
    Finality = 3,
    Activation = 4,
}

impl ActionSignaturePurpose {
    fn from_u16(value: u16) -> Result<Self, PreparationParentError> {
        match value {
            1 => Ok(Self::Preparation),
            2 => Ok(Self::Source),
            3 => Ok(Self::Finality),
            4 => Ok(Self::Activation),
            _ => Err(PreparationParentError::WrongSignaturePurpose),
        }
    }

    const fn key_index(self) -> usize {
        self as usize - 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparationParentError {
    DuplicateBodyIdentity,
    InvalidCanonicalEncoding,
    InvalidSignature,
    WrongBodyIdentity,
    WrongContext,
    WrongItemTypeOrLength,
    WrongParticipantCount,
    WrongParticipantPosition,
    WrongSchema,
    WrongSignaturePurpose,
}

impl fmt::Display for PreparationParentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateBodyIdentity => {
                "preparation parent contains a duplicate private-body identity"
            }
            Self::InvalidCanonicalEncoding => {
                "preparation parent or signature is not canonically encoded"
            }
            Self::InvalidSignature => "preparation parent signature is invalid",
            Self::WrongBodyIdentity => {
                "private preparation body is absent from the signed manifest"
            }
            Self::WrongContext => "preparation parent has the wrong context",
            Self::WrongItemTypeOrLength => "preparation parent field has the wrong type or length",
            Self::WrongParticipantCount => {
                "preparation parent is only defined for the completion profile"
            }
            Self::WrongParticipantPosition => {
                "preparation parent sender or recipient position is invalid"
            }
            Self::WrongSchema => "preparation parent has the wrong schema or version",
            Self::WrongSignaturePurpose => "action signature has the wrong purpose",
        })
    }
}

impl std::error::Error for PreparationParentError {}

#[derive(Clone, PartialEq, Eq)]
pub struct ActionSignatureCarrier {
    signer_position: u16,
    purpose: ActionSignaturePurpose,
    body_identity: Hash512,
    signature: [u8; ACTION_SIGNATURE_BYTE_LENGTH],
}

impl ActionSignatureCarrier {
    pub fn new(
        participant_count: u16,
        signer_position: u16,
        purpose: ActionSignaturePurpose,
        body_identity: Hash512,
        signature: &[u8],
    ) -> Result<Self, PreparationParentError> {
        validate_position(participant_count, signer_position)?;
        let signature = signature
            .try_into()
            .map_err(|_| PreparationParentError::WrongItemTypeOrLength)?;
        Ok(Self {
            signer_position,
            purpose,
            body_identity,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PreparationParentError> {
        let encoded = CanonicalTuple::new(
            ACTION_SIGNATURE_CARRIER_SCHEMA_IDENTIFIER,
            PREPARATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.signer_position),
                CanonicalItem::unsigned16(self.purpose as u16),
                CanonicalItem::hash512(self.body_identity.into_bytes()),
                CanonicalItem::fixed_bytes(self.signature)
                    .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)?,
            ],
        )
        .encode()
        .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)?;
        if encoded.len() != ACTION_SIGNATURE_CARRIER_BYTE_LENGTH {
            return Err(PreparationParentError::InvalidCanonicalEncoding);
        }
        Ok(encoded)
    }

    pub fn decode(participant_count: u16, bytes: &[u8]) -> Result<Self, PreparationParentError> {
        validate_participant_count(participant_count)?;
        if bytes.len() != ACTION_SIGNATURE_CARRIER_BYTE_LENGTH {
            return Err(PreparationParentError::WrongItemTypeOrLength);
        }
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)?;
        require_tuple(&tuple, ACTION_SIGNATURE_CARRIER_SCHEMA_IDENTIFIER, 4)?;
        let carrier = Self::new(
            participant_count,
            read_unsigned16(&tuple.items[0])?,
            ActionSignaturePurpose::from_u16(read_unsigned16(&tuple.items[1])?)?,
            read_hash512(&tuple.items[2])?,
            read_raw_bytes(&tuple.items[3])?,
        )?;
        if carrier.encode()?.as_slice() != bytes {
            return Err(PreparationParentError::InvalidCanonicalEncoding);
        }
        Ok(carrier)
    }

    fn verify(
        &self,
        expected_signer: u16,
        expected_purpose: ActionSignaturePurpose,
        expected_body_identity: Hash512,
        verification_key: &[u8],
    ) -> Result<(), PreparationParentError> {
        if self.signer_position != expected_signer
            || self.purpose != expected_purpose
            || self.body_identity != expected_body_identity
        {
            return Err(PreparationParentError::WrongContext);
        }
        if !verify_complete(
            &self.signature,
            verification_key,
            self.body_identity.as_bytes(),
        )
        .map_err(|_| PreparationParentError::InvalidSignature)?
        {
            return Err(PreparationParentError::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparationParent {
    participant_count: u16,
    action_proposal_identity: Hash512,
    action_key_set_roster_identity: Hash512,
    preparation_attempt: u16,
    predecessor_identity: Hash512,
    sender_position: u16,
    subset_commitments: [[u8; SUBSET_COMMITMENT_BYTE_LENGTH]; SUBSET_COMMITMENT_COUNT],
    private_body_identities: Vec<Hash512>,
}

impl PreparationParent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        participant_count: u16,
        action_proposal_identity: Hash512,
        action_key_set_roster_identity: Hash512,
        preparation_attempt: u16,
        predecessor_identity: Hash512,
        sender_position: u16,
        subset_commitments: [[u8; SUBSET_COMMITMENT_BYTE_LENGTH]; SUBSET_COMMITMENT_COUNT],
        private_body_identities: Vec<Hash512>,
    ) -> Result<Self, PreparationParentError> {
        validate_position(participant_count, sender_position)?;
        if private_body_identities.len() != usize::from(participant_count - 1) {
            return Err(PreparationParentError::WrongItemTypeOrLength);
        }
        for (index, identity) in private_body_identities.iter().enumerate() {
            if private_body_identities[..index].contains(identity) {
                return Err(PreparationParentError::DuplicateBodyIdentity);
            }
        }
        Ok(Self {
            participant_count,
            action_proposal_identity,
            action_key_set_roster_identity,
            preparation_attempt,
            predecessor_identity,
            sender_position,
            subset_commitments,
            private_body_identities,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PreparationParentError> {
        let commitment_bytes = self
            .subset_commitments
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let private_body_identity_bytes = self
            .private_body_identities
            .iter()
            .flat_map(|identity| identity.as_bytes().iter().copied())
            .collect::<Vec<_>>();
        let encoded = CanonicalTuple::new(
            PREPARATION_PARENT_SCHEMA_IDENTIFIER,
            PREPARATION_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.action_proposal_identity.into_bytes()),
                CanonicalItem::hash512(self.action_key_set_roster_identity.into_bytes()),
                CanonicalItem::unsigned16(self.preparation_attempt),
                CanonicalItem::hash512(self.predecessor_identity.into_bytes()),
                CanonicalItem::unsigned16(self.sender_position),
                CanonicalItem::fixed_bytes(commitment_bytes)
                    .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)?,
                CanonicalItem::fixed_bytes(private_body_identity_bytes)
                    .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)?,
            ],
        )
        .encode()
        .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)?;
        let expected_length = preparation_parent_body_byte_length(self.participant_count)?;
        if encoded.len() != expected_length {
            return Err(PreparationParentError::InvalidCanonicalEncoding);
        }
        Ok(encoded)
    }

    pub fn decode(participant_count: u16, bytes: &[u8]) -> Result<Self, PreparationParentError> {
        validate_participant_count(participant_count)?;
        if bytes.len() != preparation_parent_body_byte_length(participant_count)? {
            return Err(PreparationParentError::WrongItemTypeOrLength);
        }
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)?;
        require_tuple(&tuple, PREPARATION_PARENT_SCHEMA_IDENTIFIER, 7)?;
        let subset_commitments = read_raw_bytes(&tuple.items[5])?
            .chunks_exact(SUBSET_COMMITMENT_BYTE_LENGTH)
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| PreparationParentError::WrongItemTypeOrLength)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| PreparationParentError::WrongItemTypeOrLength)?;
        let private_body_identities = read_raw_bytes(&tuple.items[6])?
            .chunks_exact(Hash512::BYTE_LENGTH)
            .map(|bytes| {
                Ok(Hash512::from_bytes(bytes.try_into().map_err(|_| {
                    PreparationParentError::WrongItemTypeOrLength
                })?))
            })
            .collect::<Result<Vec<_>, PreparationParentError>>()?;
        let parent = Self::new(
            participant_count,
            read_hash512(&tuple.items[0])?,
            read_hash512(&tuple.items[1])?,
            read_unsigned16(&tuple.items[2])?,
            read_hash512(&tuple.items[3])?,
            read_unsigned16(&tuple.items[4])?,
            subset_commitments,
            private_body_identities,
        )?;
        if parent.encode()?.as_slice() != bytes {
            return Err(PreparationParentError::InvalidCanonicalEncoding);
        }
        Ok(parent)
    }

    pub fn body_identity(&self) -> Result<Hash512, PreparationParentError> {
        hash_foundation_tuple_512(
            PREPARATION_PARENT_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)
                .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)?],
        )
        .map_err(|_| PreparationParentError::InvalidCanonicalEncoding)
    }

    pub(super) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(super) const fn action_proposal_identity(&self) -> Hash512 {
        self.action_proposal_identity
    }

    pub(super) const fn action_key_set_roster_identity(&self) -> Hash512 {
        self.action_key_set_roster_identity
    }

    pub(super) const fn preparation_attempt(&self) -> u16 {
        self.preparation_attempt
    }

    pub(super) const fn predecessor_identity(&self) -> Hash512 {
        self.predecessor_identity
    }

    pub(super) const fn sender_position(&self) -> u16 {
        self.sender_position
    }

    pub(super) fn subset_commitment(
        &self,
        index: usize,
    ) -> Option<&[u8; SUBSET_COMMITMENT_BYTE_LENGTH]> {
        self.subset_commitments.get(index)
    }

    fn private_body_identity_for_recipient(
        &self,
        recipient_position: u16,
    ) -> Result<Hash512, PreparationParentError> {
        if recipient_position >= self.participant_count
            || recipient_position == self.sender_position
        {
            return Err(PreparationParentError::WrongParticipantPosition);
        }
        let index = if recipient_position < self.sender_position {
            usize::from(recipient_position)
        } else {
            usize::from(recipient_position - 1)
        };
        self.private_body_identities
            .get(index)
            .copied()
            .ok_or(PreparationParentError::WrongParticipantPosition)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPrivatePreparationCarrier {
    pub sender_position: u16,
    pub recipient_position: u16,
    pub parent_identity: Hash512,
    pub body_identity: Hash512,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_private_preparation_carrier(
    participant_count: u16,
    expected_action_proposal_identity: Hash512,
    expected_action_key_set_roster_identity: Hash512,
    expected_preparation_attempt: u16,
    expected_predecessor_identity: Hash512,
    recipient_position: u16,
    action_key_sets: &[ActionKeySet],
    parent_bytes: &[u8],
    signature_bytes: &[u8],
    private_body_bytes: &[u8],
) -> Result<VerifiedPrivatePreparationCarrier, PreparationParentError> {
    validate_position(participant_count, recipient_position)?;
    if action_key_sets.len() != usize::from(participant_count)
        || action_key_set_roster_identity(action_key_sets)
            .map_err(|_| PreparationParentError::WrongContext)?
            != expected_action_key_set_roster_identity
        || action_key_sets
            .first()
            .is_none_or(|key_set| key_set.proposal_identity() != expected_action_proposal_identity)
    {
        return Err(PreparationParentError::WrongContext);
    }

    let parent = PreparationParent::decode(participant_count, parent_bytes)?;
    if parent.action_proposal_identity != expected_action_proposal_identity
        || parent.action_key_set_roster_identity != expected_action_key_set_roster_identity
        || parent.preparation_attempt != expected_preparation_attempt
        || parent.predecessor_identity != expected_predecessor_identity
    {
        return Err(PreparationParentError::WrongContext);
    }
    let sender_position = parent.sender_position;
    if sender_position == recipient_position {
        return Err(PreparationParentError::WrongParticipantPosition);
    }
    let parent_identity = parent.body_identity()?;
    let signature = ActionSignatureCarrier::decode(participant_count, signature_bytes)?;
    let sender_key_set = action_key_sets
        .get(usize::from(sender_position))
        .ok_or(PreparationParentError::WrongParticipantPosition)?;
    let verification_key = sender_key_set
        .action_signature_verification_key(ActionSignaturePurpose::Preparation.key_index())
        .ok_or(PreparationParentError::WrongSignaturePurpose)?;
    signature.verify(
        sender_position,
        ActionSignaturePurpose::Preparation,
        parent_identity,
        verification_key,
    )?;

    let recipient_key_set = action_key_sets
        .get(usize::from(recipient_position))
        .ok_or(PreparationParentError::WrongParticipantPosition)?;
    let pair_encryption_key = recipient_key_set
        .pair_encryption_key_for_sender(sender_position)
        .ok_or(PreparationParentError::WrongParticipantPosition)?;
    let expected_private_context = PrivatePreparationContext::new(
        participant_count,
        expected_action_proposal_identity,
        expected_action_key_set_roster_identity,
        expected_preparation_attempt,
        expected_predecessor_identity,
        sender_position,
        recipient_position,
        pair_encryption_key,
    )
    .map_err(|_| PreparationParentError::WrongContext)?;
    let private_body = PrivatePreparationBody::decode(participant_count, private_body_bytes)
        .map_err(|_| PreparationParentError::WrongContext)?;
    if private_body.context != expected_private_context {
        return Err(PreparationParentError::WrongContext);
    }
    let body_identity = private_body
        .body_identity()
        .map_err(|_| PreparationParentError::WrongBodyIdentity)?;
    if parent.private_body_identity_for_recipient(recipient_position)? != body_identity {
        return Err(PreparationParentError::WrongBodyIdentity);
    }

    Ok(VerifiedPrivatePreparationCarrier {
        sender_position,
        recipient_position,
        parent_identity,
        body_identity,
    })
}

pub fn preparation_parent_body_byte_length(
    participant_count: u16,
) -> Result<usize, PreparationParentError> {
    validate_participant_count(participant_count)?;
    Ok(PREPARATION_PARENT_BODY_BYTE_LENGTH)
}

fn validate_participant_count(participant_count: u16) -> Result<(), PreparationParentError> {
    if participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(PreparationParentError::WrongParticipantCount);
    }
    Ok(())
}

fn validate_position(participant_count: u16, position: u16) -> Result<(), PreparationParentError> {
    validate_participant_count(participant_count)?;
    if position >= participant_count {
        return Err(PreparationParentError::WrongParticipantPosition);
    }
    Ok(())
}

fn require_tuple(
    tuple: &CanonicalTuple,
    schema_identifier: u16,
    item_count: usize,
) -> Result<(), PreparationParentError> {
    if tuple.schema_identifier != schema_identifier
        || tuple.schema_version != PREPARATION_SCHEMA_VERSION
    {
        return Err(PreparationParentError::WrongSchema);
    }
    if tuple.items.len() != item_count {
        return Err(PreparationParentError::WrongItemTypeOrLength);
    }
    Ok(())
}

fn read_hash512(item: &CanonicalItem) -> Result<Hash512, PreparationParentError> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(PreparationParentError::WrongItemTypeOrLength);
    }
    Ok(Hash512::from_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| PreparationParentError::WrongItemTypeOrLength)?,
    ))
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, PreparationParentError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(PreparationParentError::WrongItemTypeOrLength);
    }
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| PreparationParentError::WrongItemTypeOrLength)?,
    ))
}

fn read_raw_bytes(item: &CanonicalItem) -> Result<&[u8], PreparationParentError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(PreparationParentError::WrongItemTypeOrLength);
    }
    Ok(item.canonical_bytes())
}
