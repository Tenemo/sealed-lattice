use core::fmt;

use aes::Aes256;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use zeroize::Zeroize;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    hash_foundation_tuple_512,
};

use super::action_key_set::{ActionKeySet, action_key_set_roster_identity};
use super::preparation_parent::{
    ActionSignatureCarrier, ActionSignaturePurpose, PreparationParent,
    verify_preparation_parent_carrier,
};
use super::preparation_plaintext::{
    AFFINE_COEFFICIENT_BYTE_LENGTH, AFFINE_MODULE_VALUE_BYTE_LENGTH,
    CONTRIBUTION_OPENING_BYTE_LENGTH, HeldAffineEvaluation, HeldSubsetKey,
    PreparationMaterialContext, derive_held_affine_evaluations, derive_held_subset_keys,
    sender_subset_slots, verify_local_preparation_material, verify_preparation_plaintext,
};

pub const ABSTENTION_SOURCE_BODY_BYTE_LENGTH: usize = 326;
pub const SUBMITTED_SOURCE_BODY_BYTE_LENGTH: usize = 337;
pub const HELD_SUBSET_KEY_COUNT: usize = 120;
pub const HELD_SUBSET_KEY_BYTE_LENGTH: usize = 32;
pub const HELD_SUBSET_KEY_VECTOR_BYTE_LENGTH: usize =
    HELD_SUBSET_KEY_COUNT * HELD_SUBSET_KEY_BYTE_LENGTH;
pub const HELD_AFFINE_EVALUATION_COUNT: usize = 10;
pub const HELD_AFFINE_EVALUATION_VECTOR_BYTE_LENGTH: usize =
    HELD_AFFINE_EVALUATION_COUNT * 2 * AFFINE_MODULE_VALUE_BYTE_LENGTH;
pub const LOCAL_AFFINE_CONSTANT_VECTOR_BYTE_LENGTH: usize = 2 * AFFINE_MODULE_VALUE_BYTE_LENGTH;
pub const SCORE_ENCODING_COUNT: usize = 10;
pub const SCORE_BIT_WIDTH: usize = 4;
pub const SOURCE_BIT_COUNT: usize = SCORE_ENCODING_COUNT * SCORE_BIT_WIDTH;
pub const SOURCE_CORRECTION_BYTE_LENGTH: usize = SOURCE_BIT_COUNT.div_ceil(8);
pub const SOURCE_ORDINAL: u64 = 0;

const COMPLETION_PROFILE_PARTICIPANT_COUNT: u16 = 10;
const LOW_SUBSET_SIZE: u16 = 7;
const SOURCE_BODY_SCHEMA_IDENTIFIER: u16 = 0x0208;
const SOURCE_BODY_SCHEMA_VERSION: u16 = 1;
const SOURCE_BODY_IDENTITY_DOMAIN: &str = "sealed-lattice/construction/source-body/v1";
const VERIFIED_PREPARATION_ROOT_DOMAIN: &str =
    "sealed-lattice/construction/verified-preparation-root/v1";
const SOURCE_STREAM_ADDRESS_VERSION: u8 = 1;
const SOURCE_STREAM_FAMILY: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SourceDeclaration {
    Abstain = 1,
    Submit = 2,
}

impl SourceDeclaration {
    fn from_u16(value: u16) -> Result<Self, SourceError> {
        match value {
            1 => Ok(Self::Abstain),
            2 => Ok(Self::Submit),
            _ => Err(SourceError::WrongDeclaration),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    DuplicatePreparationIdentity,
    InvalidCanonicalEncoding,
    InvalidSignature,
    NoncanonicalCorrection,
    WrongContext,
    WrongDeclaration,
    WrongItemTypeOrLength,
    WrongParticipantCount,
    WrongParticipantPosition,
    WrongSchema,
    WrongSubsetKeyVector,
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicatePreparationIdentity => {
                "verified preparation contains a duplicate parent identity"
            }
            Self::InvalidCanonicalEncoding => "source body is not canonically encoded",
            Self::InvalidSignature => "source signature is invalid",
            Self::NoncanonicalCorrection => {
                "source score encodings or correction vector are not canonical"
            }
            Self::WrongContext => "source or preparation has the wrong context",
            Self::WrongDeclaration => "source declaration is invalid",
            Self::WrongItemTypeOrLength => "source field has the wrong type or length",
            Self::WrongParticipantCount => {
                "source construction is only defined for the completion profile"
            }
            Self::WrongParticipantPosition => "source participant position is invalid",
            Self::WrongSchema => "source body has the wrong schema or version",
            Self::WrongSubsetKeyVector => "held subset-key vector is malformed",
        })
    }
}

impl std::error::Error for SourceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceContext {
    pub participant_count: u16,
    pub action_proposal_identity: Hash512,
    pub action_key_set_roster_identity: Hash512,
    pub preparation_attempt: u16,
    pub predecessor_identity: Hash512,
    pub verified_preparation_root: Hash512,
    pub sender_position: u16,
    pub source_ordinal: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBody {
    context: SourceContext,
    declaration: SourceDeclaration,
    correction: Option<[u8; SOURCE_CORRECTION_BYTE_LENGTH]>,
}

impl SourceBody {
    pub fn new(
        context: SourceContext,
        declaration: SourceDeclaration,
        correction: Option<[u8; SOURCE_CORRECTION_BYTE_LENGTH]>,
    ) -> Result<Self, SourceError> {
        validate_position(context.participant_count, context.sender_position)?;
        if context.source_ordinal != SOURCE_ORDINAL {
            return Err(SourceError::WrongContext);
        }
        match (declaration, correction) {
            (SourceDeclaration::Abstain, None) => {}
            (SourceDeclaration::Submit, Some(_)) => {}
            _ => return Err(SourceError::WrongDeclaration),
        }
        Ok(Self {
            context,
            declaration,
            correction,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, SourceError> {
        let mut items = vec![
            CanonicalItem::hash512(self.context.action_proposal_identity.into_bytes()),
            CanonicalItem::hash512(self.context.action_key_set_roster_identity.into_bytes()),
            CanonicalItem::unsigned16(self.context.preparation_attempt),
            CanonicalItem::hash512(self.context.predecessor_identity.into_bytes()),
            CanonicalItem::hash512(self.context.verified_preparation_root.into_bytes()),
            CanonicalItem::unsigned16(self.context.sender_position),
            CanonicalItem::unsigned16(self.declaration as u16),
            CanonicalItem::unsigned64(self.context.source_ordinal),
        ];
        if let Some(correction) = self.correction {
            items.push(
                CanonicalItem::fixed_bytes(correction)
                    .map_err(|_| SourceError::InvalidCanonicalEncoding)?,
            );
        }
        let encoded = CanonicalTuple::new(
            SOURCE_BODY_SCHEMA_IDENTIFIER,
            SOURCE_BODY_SCHEMA_VERSION,
            items,
        )
        .encode()
        .map_err(|_| SourceError::InvalidCanonicalEncoding)?;
        let expected_length = match self.declaration {
            SourceDeclaration::Abstain => ABSTENTION_SOURCE_BODY_BYTE_LENGTH,
            SourceDeclaration::Submit => SUBMITTED_SOURCE_BODY_BYTE_LENGTH,
        };
        if encoded.len() != expected_length {
            return Err(SourceError::InvalidCanonicalEncoding);
        }
        Ok(encoded)
    }

    pub fn decode(participant_count: u16, bytes: &[u8]) -> Result<Self, SourceError> {
        validate_participant_count(participant_count)?;
        if bytes.len() != ABSTENTION_SOURCE_BODY_BYTE_LENGTH
            && bytes.len() != SUBMITTED_SOURCE_BODY_BYTE_LENGTH
        {
            return Err(SourceError::WrongItemTypeOrLength);
        }
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| SourceError::InvalidCanonicalEncoding)?;
        if tuple.schema_identifier != SOURCE_BODY_SCHEMA_IDENTIFIER
            || tuple.schema_version != SOURCE_BODY_SCHEMA_VERSION
            || (tuple.items.len() != 8 && tuple.items.len() != 9)
        {
            return Err(SourceError::WrongSchema);
        }
        let declaration = SourceDeclaration::from_u16(read_unsigned16(&tuple.items[6])?)?;
        let correction = match declaration {
            SourceDeclaration::Abstain => {
                if tuple.items.len() != 8 {
                    return Err(SourceError::WrongDeclaration);
                }
                None
            }
            SourceDeclaration::Submit => {
                if tuple.items.len() != 9 {
                    return Err(SourceError::WrongDeclaration);
                }
                let bytes = read_raw_bytes(&tuple.items[8])?;
                if bytes.len() != SOURCE_CORRECTION_BYTE_LENGTH {
                    return Err(SourceError::WrongItemTypeOrLength);
                }
                Some(
                    bytes
                        .try_into()
                        .map_err(|_| SourceError::WrongItemTypeOrLength)?,
                )
            }
        };
        let body = Self::new(
            SourceContext {
                participant_count,
                action_proposal_identity: read_hash512(&tuple.items[0])?,
                action_key_set_roster_identity: read_hash512(&tuple.items[1])?,
                preparation_attempt: read_unsigned16(&tuple.items[2])?,
                predecessor_identity: read_hash512(&tuple.items[3])?,
                verified_preparation_root: read_hash512(&tuple.items[4])?,
                sender_position: read_unsigned16(&tuple.items[5])?,
                source_ordinal: read_unsigned64(&tuple.items[7])?,
            },
            declaration,
            correction,
        )?;
        if body.encode()?.as_slice() != bytes {
            return Err(SourceError::InvalidCanonicalEncoding);
        }
        Ok(body)
    }

    pub fn body_identity(&self) -> Result<Hash512, SourceError> {
        hash_foundation_tuple_512(
            SOURCE_BODY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)
                .map_err(|_| SourceError::InvalidCanonicalEncoding)?],
        )
        .map_err(|_| SourceError::InvalidCanonicalEncoding)
    }
}

pub struct VerifiedCompletePreparation {
    pub root: Hash512,
    pub parent_identities: Vec<Hash512>,
    pub held_subset_keys: Vec<HeldSubsetKey>,
    pub held_affine_evaluations: Vec<HeldAffineEvaluation>,
    pub local_affine_constants: [u8; LOCAL_AFFINE_CONSTANT_VECTOR_BYTE_LENGTH],
}

impl Drop for VerifiedCompletePreparation {
    fn drop(&mut self) {
        self.local_affine_constants.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSource {
    pub sender_position: u16,
    pub declaration: SourceDeclaration,
    pub correction: Option<[u8; SOURCE_CORRECTION_BYTE_LENGTH]>,
    pub body_identity: Hash512,
    pub verified_preparation_root: Hash512,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_complete_preparation(
    context: &PreparationMaterialContext,
    local_position: u16,
    action_key_sets: &[ActionKeySet],
    parent_bodies: &[Vec<u8>],
    parent_signatures: &[Vec<u8>],
    own_opening_bytes: &[u8],
    own_affine_coefficient_bytes: &[u8],
    remote_plaintext_bytes: &[Vec<u8>],
) -> Result<VerifiedCompletePreparation, SourceError> {
    validate_position(COMPLETION_PROFILE_PARTICIPANT_COUNT, local_position)?;
    if context.sender_position != local_position
        || action_key_sets.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        || parent_bodies.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        || parent_signatures.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        || remote_plaintext_bytes.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT - 1)
        || own_opening_bytes.len() != HELD_SUBSET_KEY_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH
        || own_affine_coefficient_bytes.len() != AFFINE_COEFFICIENT_BYTE_LENGTH
        || action_key_set_roster_identity(action_key_sets).map_err(|_| SourceError::WrongContext)?
            != context.action_key_set_roster_identity
    {
        return Err(SourceError::WrongContext);
    }

    let mut parents = Vec::with_capacity(usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT));
    let mut parent_identities =
        Vec::with_capacity(usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT));
    let mut parent_identity_bytes = Vec::with_capacity(
        usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) * Hash512::BYTE_LENGTH,
    );
    for sender_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
        let parent_body = parent_bodies
            .get(usize::from(sender_position))
            .ok_or(SourceError::WrongItemTypeOrLength)?;
        let parent_signature = parent_signatures
            .get(usize::from(sender_position))
            .ok_or(SourceError::WrongItemTypeOrLength)?;
        let verified = verify_preparation_parent_carrier(
            COMPLETION_PROFILE_PARTICIPANT_COUNT,
            context.action_proposal_identity,
            context.action_key_set_roster_identity,
            context.preparation_attempt,
            context.predecessor_identity,
            sender_position,
            action_key_sets,
            parent_body,
            parent_signature,
        )
        .map_err(|_| SourceError::InvalidSignature)?;
        if parent_identity_bytes
            .chunks_exact(Hash512::BYTE_LENGTH)
            .any(|identity| identity == verified.parent_identity.as_bytes())
        {
            return Err(SourceError::DuplicatePreparationIdentity);
        }
        parent_identity_bytes.extend_from_slice(verified.parent_identity.as_bytes());
        parent_identities.push(verified.parent_identity);
        parents.push(
            PreparationParent::decode(COMPLETION_PROFILE_PARTICIPANT_COUNT, parent_body)
                .map_err(|_| SourceError::WrongContext)?,
        );
    }

    let local_parent = parents
        .get(usize::from(local_position))
        .ok_or(SourceError::WrongParticipantPosition)?;
    verify_local_preparation_material(
        local_parent,
        context,
        own_opening_bytes,
        own_affine_coefficient_bytes,
    )
    .map_err(|_| SourceError::WrongContext)?;

    for sender_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
        if sender_position == local_position {
            continue;
        }
        let remote_index = if sender_position < local_position {
            usize::from(sender_position)
        } else {
            usize::from(sender_position - 1)
        };
        let parent = parents
            .get(usize::from(sender_position))
            .ok_or(SourceError::WrongParticipantPosition)?;
        let plaintext = remote_plaintext_bytes
            .get(remote_index)
            .ok_or(SourceError::WrongItemTypeOrLength)?;
        let sender_context = PreparationMaterialContext {
            action_proposal_identity: context.action_proposal_identity,
            action_key_set_roster_identity: context.action_key_set_roster_identity,
            preparation_attempt: context.preparation_attempt,
            predecessor_identity: context.predecessor_identity,
            sender_position,
        };
        verify_preparation_plaintext(parent, &sender_context, local_position, plaintext)
            .map_err(|_| SourceError::WrongContext)?;
    }

    let root = hash_foundation_tuple_512(
        VERIFIED_PREPARATION_ROOT_DOMAIN,
        &[
            CanonicalItem::hash512(context.action_proposal_identity.into_bytes()),
            CanonicalItem::hash512(context.action_key_set_roster_identity.into_bytes()),
            CanonicalItem::unsigned16(context.preparation_attempt),
            CanonicalItem::hash512(context.predecessor_identity.into_bytes()),
            CanonicalItem::fixed_bytes(parent_identity_bytes)
                .map_err(|_| SourceError::InvalidCanonicalEncoding)?,
        ],
    )
    .map_err(|_| SourceError::InvalidCanonicalEncoding)?;
    let held_subset_keys =
        derive_held_subset_keys(local_position, own_opening_bytes, remote_plaintext_bytes)
            .map_err(|_| SourceError::WrongSubsetKeyVector)?;
    let held_affine_evaluations = derive_held_affine_evaluations(
        local_position,
        own_affine_coefficient_bytes,
        remote_plaintext_bytes,
    )
    .map_err(|_| SourceError::WrongContext)?;
    let mut local_affine_constants = [0_u8; LOCAL_AFFINE_CONSTANT_VECTOR_BYTE_LENGTH];
    local_affine_constants[..AFFINE_MODULE_VALUE_BYTE_LENGTH]
        .copy_from_slice(&own_affine_coefficient_bytes[..AFFINE_MODULE_VALUE_BYTE_LENGTH]);
    let affine_b_constant_start = 10 * AFFINE_MODULE_VALUE_BYTE_LENGTH;
    local_affine_constants[AFFINE_MODULE_VALUE_BYTE_LENGTH..].copy_from_slice(
        &own_affine_coefficient_bytes
            [affine_b_constant_start..affine_b_constant_start + AFFINE_MODULE_VALUE_BYTE_LENGTH],
    );
    Ok(VerifiedCompletePreparation {
        root,
        parent_identities,
        held_subset_keys,
        held_affine_evaluations,
        local_affine_constants,
    })
}

pub fn encode_held_subset_keys(
    participant_position: u16,
    held_subset_keys: &[HeldSubsetKey],
) -> Result<Vec<u8>, SourceError> {
    validate_position(COMPLETION_PROFILE_PARTICIPANT_COUNT, participant_position)?;
    let expected_slots = sender_subset_slots(participant_position);
    if held_subset_keys.len() != expected_slots.len()
        || held_subset_keys
            .iter()
            .zip(expected_slots)
            .any(|(key, (family, subset))| key.family != family || key.subset != subset)
    {
        return Err(SourceError::WrongSubsetKeyVector);
    }
    Ok(held_subset_keys.iter().flat_map(|key| key.key).collect())
}

pub fn decode_held_subset_keys(
    participant_position: u16,
    bytes: &[u8],
) -> Result<Vec<HeldSubsetKey>, SourceError> {
    validate_position(COMPLETION_PROFILE_PARTICIPANT_COUNT, participant_position)?;
    let slots = sender_subset_slots(participant_position);
    if bytes.len() != HELD_SUBSET_KEY_VECTOR_BYTE_LENGTH || slots.len() != HELD_SUBSET_KEY_COUNT {
        return Err(SourceError::WrongSubsetKeyVector);
    }
    slots
        .into_iter()
        .zip(bytes.chunks_exact(HELD_SUBSET_KEY_BYTE_LENGTH))
        .map(|((family, subset), key)| {
            Ok(HeldSubsetKey {
                family,
                subset,
                key: key
                    .try_into()
                    .map_err(|_| SourceError::WrongSubsetKeyVector)?,
            })
        })
        .collect()
}

pub fn encode_held_affine_evaluations(
    held_affine_evaluations: &[HeldAffineEvaluation],
) -> Result<Vec<u8>, SourceError> {
    if held_affine_evaluations.len() != HELD_AFFINE_EVALUATION_COUNT
        || held_affine_evaluations
            .iter()
            .enumerate()
            .any(|(position, evaluation)| usize::from(evaluation.receiver_position) != position)
    {
        return Err(SourceError::WrongItemTypeOrLength);
    }
    Ok(held_affine_evaluations
        .iter()
        .flat_map(|evaluation| {
            evaluation
                .affine_a_evaluation
                .into_iter()
                .chain(evaluation.affine_b_evaluation)
        })
        .collect())
}

pub fn decode_held_affine_evaluations(
    bytes: &[u8],
) -> Result<Vec<HeldAffineEvaluation>, SourceError> {
    if bytes.len() != HELD_AFFINE_EVALUATION_VECTOR_BYTE_LENGTH {
        return Err(SourceError::WrongItemTypeOrLength);
    }
    bytes
        .chunks_exact(2 * AFFINE_MODULE_VALUE_BYTE_LENGTH)
        .enumerate()
        .map(|(position, bytes)| {
            Ok(HeldAffineEvaluation {
                receiver_position: u16::try_from(position)
                    .map_err(|_| SourceError::WrongItemTypeOrLength)?,
                affine_a_evaluation: bytes[..AFFINE_MODULE_VALUE_BYTE_LENGTH]
                    .try_into()
                    .map_err(|_| SourceError::WrongItemTypeOrLength)?,
                affine_b_evaluation: bytes[AFFINE_MODULE_VALUE_BYTE_LENGTH..]
                    .try_into()
                    .map_err(|_| SourceError::WrongItemTypeOrLength)?,
            })
        })
        .collect()
}

pub fn derive_honest_source_correction(
    source_position: u16,
    score_encodings: &[u8],
    held_subset_keys: &[HeldSubsetKey],
) -> Result<[u8; SOURCE_CORRECTION_BYTE_LENGTH], SourceError> {
    validate_position(COMPLETION_PROFILE_PARTICIPANT_COUNT, source_position)?;
    if score_encodings.len() != SCORE_ENCODING_COUNT
        || score_encodings
            .iter()
            .any(|score| *score >= (1 << SCORE_BIT_WIDTH))
    {
        return Err(SourceError::NoncanonicalCorrection);
    }
    let expected_slots = sender_subset_slots(source_position);
    if held_subset_keys.len() != expected_slots.len() {
        return Err(SourceError::WrongSubsetKeyVector);
    }
    let mut source_mask = [0_u8; SOURCE_CORRECTION_BYTE_LENGTH];
    let mut source_key_count = 0_usize;
    for (held_key, (expected_family, expected_subset)) in
        held_subset_keys.iter().zip(expected_slots)
    {
        if held_key.family != expected_family || held_key.subset != expected_subset {
            return Err(SourceError::WrongSubsetKeyVector);
        }
        if held_key.family != LOW_SUBSET_SIZE {
            continue;
        }
        if held_key.subset & (1_u16 << source_position) == 0 {
            return Err(SourceError::WrongSubsetKeyVector);
        }
        source_key_count += 1;
        let source_rank = (held_key.subset & ((1_u16 << source_position) - 1)).count_ones();
        let cipher =
            Aes256::new_from_slice(&held_key.key).map_err(|_| SourceError::WrongSubsetKeyVector)?;
        let source_rank =
            usize::try_from(source_rank).map_err(|_| SourceError::WrongSubsetKeyVector)?;
        let source_start_bit = source_rank
            .checked_mul(SOURCE_BIT_COUNT)
            .ok_or(SourceError::WrongSubsetKeyVector)?;
        let source_end_bit = source_start_bit
            .checked_add(SOURCE_BIT_COUNT)
            .ok_or(SourceError::WrongSubsetKeyVector)?;
        for block_index in source_start_bit / 128..=(source_end_bit - 1) / 128 {
            let mut address = Block::<Aes256>::default();
            address[0] = SOURCE_STREAM_ADDRESS_VERSION;
            address[1] = SOURCE_STREAM_FAMILY;
            address[2..6].copy_from_slice(
                &u32::try_from(block_index)
                    .map_err(|_| SourceError::WrongSubsetKeyVector)?
                    .to_le_bytes(),
            );
            cipher.encrypt_block(&mut address);
            let block_start_bit = block_index * 128;
            let overlap_start = source_start_bit.max(block_start_bit);
            let overlap_end = source_end_bit.min(block_start_bit + 128);
            for linear_bit in overlap_start..overlap_end {
                let source_bit_ordinal = linear_bit - source_start_bit;
                let bit_offset = linear_bit - block_start_bit;
                source_mask[source_bit_ordinal / 8] ^=
                    ((address[bit_offset / 8] >> (bit_offset % 8)) & 1) << (source_bit_ordinal % 8);
            }
            address.zeroize();
        }
    }
    if source_key_count != 84 {
        return Err(SourceError::WrongSubsetKeyVector);
    }
    for (score_position, score) in score_encodings.iter().copied().enumerate() {
        for bit_position in 0..SCORE_BIT_WIDTH {
            let source_bit_ordinal = score_position * SCORE_BIT_WIDTH + bit_position;
            source_mask[source_bit_ordinal / 8] ^=
                ((score >> bit_position) & 1) << (source_bit_ordinal % 8);
        }
    }
    Ok(source_mask)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_source_carrier(
    expected_context: SourceContext,
    expected_declaration: Option<SourceDeclaration>,
    action_key_sets: &[ActionKeySet],
    body_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<VerifiedSource, SourceError> {
    validate_position(
        expected_context.participant_count,
        expected_context.sender_position,
    )?;
    if action_key_sets.len() != usize::from(expected_context.participant_count)
        || action_key_set_roster_identity(action_key_sets).map_err(|_| SourceError::WrongContext)?
            != expected_context.action_key_set_roster_identity
        || action_key_sets.first().is_none_or(|key_set| {
            key_set.proposal_identity() != expected_context.action_proposal_identity
        })
    {
        return Err(SourceError::WrongContext);
    }
    let body = SourceBody::decode(expected_context.participant_count, body_bytes)?;
    if body.context != expected_context
        || expected_declaration.is_some_and(|declaration| declaration != body.declaration)
    {
        return Err(SourceError::WrongContext);
    }
    let body_identity = body.body_identity()?;
    let signature =
        ActionSignatureCarrier::decode(expected_context.participant_count, signature_bytes)
            .map_err(|_| SourceError::InvalidSignature)?;
    let sender_key_set = action_key_sets
        .get(usize::from(expected_context.sender_position))
        .ok_or(SourceError::WrongParticipantPosition)?;
    let verification_key = sender_key_set
        .action_signature_verification_key(ActionSignaturePurpose::Source.key_index())
        .ok_or(SourceError::InvalidSignature)?;
    signature
        .verify(
            expected_context.sender_position,
            ActionSignaturePurpose::Source,
            body_identity,
            verification_key,
        )
        .map_err(|_| SourceError::InvalidSignature)?;
    Ok(VerifiedSource {
        sender_position: expected_context.sender_position,
        declaration: body.declaration,
        correction: body.correction,
        body_identity,
        verified_preparation_root: body.context.verified_preparation_root,
    })
}

fn validate_participant_count(participant_count: u16) -> Result<(), SourceError> {
    if participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(SourceError::WrongParticipantCount);
    }
    Ok(())
}

fn validate_position(participant_count: u16, position: u16) -> Result<(), SourceError> {
    validate_participant_count(participant_count)?;
    if position >= participant_count {
        return Err(SourceError::WrongParticipantPosition);
    }
    Ok(())
}

fn read_hash512(item: &CanonicalItem) -> Result<Hash512, SourceError> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(SourceError::WrongItemTypeOrLength);
    }
    Ok(Hash512::from_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| SourceError::WrongItemTypeOrLength)?,
    ))
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, SourceError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(SourceError::WrongItemTypeOrLength);
    }
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| SourceError::WrongItemTypeOrLength)?,
    ))
}

fn read_unsigned64(item: &CanonicalItem) -> Result<u64, SourceError> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(SourceError::WrongItemTypeOrLength);
    }
    Ok(u64::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| SourceError::WrongItemTypeOrLength)?,
    ))
}

fn read_raw_bytes(item: &CanonicalItem) -> Result<&[u8], SourceError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(SourceError::WrongItemTypeOrLength);
    }
    Ok(item.canonical_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> SourceContext {
        SourceContext {
            participant_count: COMPLETION_PROFILE_PARTICIPANT_COUNT,
            action_proposal_identity: Hash512::from_bytes([0x11; 64]),
            action_key_set_roster_identity: Hash512::from_bytes([0x22; 64]),
            preparation_attempt: 7,
            predecessor_identity: Hash512::from_bytes([0x33; 64]),
            verified_preparation_root: Hash512::from_bytes([0x44; 64]),
            sender_position: 0,
            source_ordinal: SOURCE_ORDINAL,
        }
    }

    #[test]
    fn source_bodies_have_exact_variant_lengths_and_round_trip() {
        for (declaration, correction, expected_length) in [
            (
                SourceDeclaration::Abstain,
                None,
                ABSTENTION_SOURCE_BODY_BYTE_LENGTH,
            ),
            (
                SourceDeclaration::Submit,
                Some([0x12, 0x34, 0x56, 0x78, 0x9a]),
                SUBMITTED_SOURCE_BODY_BYTE_LENGTH,
            ),
        ] {
            let body = SourceBody::new(context(), declaration, correction).expect("constructs");
            let encoded = body.encode().expect("encodes");
            assert_eq!(encoded.len(), expected_length);
            assert_eq!(
                SourceBody::decode(COMPLETION_PROFILE_PARTICIPANT_COUNT, &encoded)
                    .expect("decodes"),
                body
            );
        }
    }

    #[test]
    fn source_body_refuses_wrong_variant_and_mutation() {
        assert!(matches!(
            SourceBody::new(context(), SourceDeclaration::Abstain, Some([0; 5])),
            Err(SourceError::WrongDeclaration)
        ));
        let mut encoded = SourceBody::new(
            context(),
            SourceDeclaration::Submit,
            Some([0x01, 0x23, 0x45, 0x67, 0x89]),
        )
        .expect("constructs")
        .encode()
        .expect("encodes");
        encoded.pop();
        assert!(SourceBody::decode(COMPLETION_PROFILE_PARTICIPANT_COUNT, &encoded).is_err());
    }

    #[test]
    fn source_correction_covers_every_score_bit_and_rank() {
        let slots = sender_subset_slots(0);
        let keys = slots
            .iter()
            .enumerate()
            .map(|(index, (family, subset))| HeldSubsetKey {
                family: *family,
                subset: *subset,
                key: [u8::try_from(index).expect("index fits"); 32],
            })
            .collect::<Vec<_>>();
        let zero = derive_honest_source_correction(0, &[0; 10], &keys).expect("derives");
        for score_position in 0..SCORE_ENCODING_COUNT {
            for bit_position in 0..SCORE_BIT_WIDTH {
                let mut scores = [0_u8; SCORE_ENCODING_COUNT];
                scores[score_position] = 1 << bit_position;
                let changed = derive_honest_source_correction(0, &scores, &keys)
                    .expect("derives changed score");
                let bit_ordinal = score_position * SCORE_BIT_WIDTH + bit_position;
                let mut difference = [0_u8; SOURCE_CORRECTION_BYTE_LENGTH];
                for (output, (left, right)) in
                    difference.iter_mut().zip(zero.iter().zip(changed.iter()))
                {
                    *output = left ^ right;
                }
                assert_eq!(difference[bit_ordinal / 8], 1 << (bit_ordinal % 8));
                difference[bit_ordinal / 8] = 0;
                assert_eq!(difference, [0; SOURCE_CORRECTION_BYTE_LENGTH]);
            }
        }
        assert!(matches!(
            derive_honest_source_correction(0, &[0; 9], &keys),
            Err(SourceError::NoncanonicalCorrection)
        ));
        assert!(matches!(
            derive_honest_source_correction(0, &[16; 10], &keys),
            Err(SourceError::NoncanonicalCorrection)
        ));
    }
}
