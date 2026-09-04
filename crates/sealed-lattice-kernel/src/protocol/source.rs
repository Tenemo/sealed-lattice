use core::fmt;

use aes::Aes256;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use zeroize::Zeroize;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
    hash_foundation_tuple_512, kmac256,
};

use super::preparation_parent::{
    ActionSignatureCarrier, ActionSignaturePurpose, PreparationParent,
    verify_preparation_parent_carrier,
};
use super::preparation_plaintext::{
    CONTRIBUTION_OPENING_BYTE_LENGTH, HeldSubsetKey, PAIRWISE_MASTER_VECTOR_BYTE_LENGTH,
    PairwiseMasterInventory, PreparationMaterialContext, derive_held_preparation_material,
    sender_subset_slots, verify_local_preparation_material, verify_preparation_plaintext,
};
use super::roster::{require_roster_identity, signing_verification_key};

pub const ABSTENTION_SOURCE_BODY_BYTE_LENGTH: usize = 326;
pub const SUBMITTED_SOURCE_BODY_BYTE_LENGTH: usize = 337;
pub const HELD_SUBSET_KEY_COUNT: usize = 120;
pub const HELD_SUBSET_KEY_BYTE_LENGTH: usize = 32;
pub const HELD_SUBSET_KEY_VECTOR_BYTE_LENGTH: usize =
    HELD_SUBSET_KEY_COUNT * HELD_SUBSET_KEY_BYTE_LENGTH;
pub const SCORE_ENCODING_COUNT: usize = 10;
pub const SCORE_BIT_WIDTH: usize = 4;
pub const SOURCE_BIT_COUNT: usize = SCORE_ENCODING_COUNT * SCORE_BIT_WIDTH;
pub const SOURCE_CORRECTION_BYTE_LENGTH: usize = SOURCE_BIT_COUNT.div_ceil(8);
pub const SOURCE_ORDINAL: u64 = 0;

const COMPLETION_PROFILE_PARTICIPANT_COUNT: u16 = 10;
const LOW_SUBSET_SIZE: u16 = 7;
const SOURCE_BODY_SCHEMA_IDENTIFIER: u16 = 0x0208;
const SOURCE_BODY_SCHEMA_VERSION: u16 = 3;
const SOURCE_BODY_IDENTITY_DOMAIN: &str = "sealed-lattice/construction/source-body/v3";
const VERIFIED_PREPARATION_ROOT_DOMAIN: &str =
    "sealed-lattice/construction/verified-preparation-root/v2";
const SOURCE_STREAM_ADDRESS_VERSION: u8 = 2;
const SOURCE_STREAM_FAMILY: u8 = 1;
const PADDED_CONTINUATION_SUBKEY_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/padded-continuation/subkey/v2";

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
    AuthenticatedBodyViolation,
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
            Self::AuthenticatedBodyViolation => {
                "authenticated source or preparation bytes violate their public relation"
            }
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
    pub roster_identity: Hash512,
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
            CanonicalItem::hash512(self.context.roster_identity.into_bytes()),
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
                roster_identity: read_hash512(&tuple.items[1])?,
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
        source_body_identity(&self.encode()?)
    }
}

pub struct VerifiedCompletePreparation {
    pub context: PreparationMaterialContext,
    pub root: Hash512,
    pub parent_identities: Vec<Hash512>,
    pub held_subset_keys: Vec<HeldSubsetKey>,
    pub pairwise_masters: PairwiseMasterInventory,
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
    roster: &Roster,
    parent_bodies: &[Vec<u8>],
    parent_signatures: &[Vec<u8>],
    own_opening_bytes: &[u8],
    own_pairwise_master_bytes: &[u8],
    remote_plaintext_bytes: &[Vec<u8>],
) -> Result<VerifiedCompletePreparation, SourceError> {
    validate_position(COMPLETION_PROFILE_PARTICIPANT_COUNT, local_position)?;
    if context.sender_position != local_position
        || parent_bodies.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        || parent_signatures.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        || remote_plaintext_bytes.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT - 1)
        || own_opening_bytes.len() != HELD_SUBSET_KEY_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH
        || own_pairwise_master_bytes.len() != PAIRWISE_MASTER_VECTOR_BYTE_LENGTH
    {
        return Err(SourceError::WrongContext);
    }
    require_roster_identity(roster, context.roster_identity)
        .map_err(|_| SourceError::WrongContext)?;

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
            context.roster_identity,
            context.preparation_attempt,
            context.predecessor_identity,
            sender_position,
            roster,
            parent_body,
            parent_signature,
        )
        .map_err(|error| match error {
            super::preparation_parent::PreparationParentError::AuthenticatedBodyViolation => {
                SourceError::AuthenticatedBodyViolation
            }
            _ => SourceError::InvalidSignature,
        })?;
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
        own_pairwise_master_bytes,
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
            roster_identity: context.roster_identity,
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
            CanonicalItem::hash512(context.roster_identity.into_bytes()),
            CanonicalItem::unsigned16(context.preparation_attempt),
            CanonicalItem::hash512(context.predecessor_identity.into_bytes()),
            CanonicalItem::fixed_bytes(parent_identity_bytes)
                .map_err(|_| SourceError::InvalidCanonicalEncoding)?,
        ],
    )
    .map_err(|_| SourceError::InvalidCanonicalEncoding)?;
    let held_material = derive_held_preparation_material(
        local_position,
        own_opening_bytes,
        own_pairwise_master_bytes,
        remote_plaintext_bytes,
    )
    .map_err(|_| SourceError::WrongSubsetKeyVector)?;
    Ok(VerifiedCompletePreparation {
        context: *context,
        root,
        parent_identities,
        held_subset_keys: held_material.held_subset_keys,
        pairwise_masters: held_material.pairwise_masters,
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

pub fn derive_honest_source_correction(
    context: &SourceContext,
    score_encodings: &[u8],
    held_subset_keys: &[HeldSubsetKey],
) -> Result<[u8; SOURCE_CORRECTION_BYTE_LENGTH], SourceError> {
    validate_position(context.participant_count, context.sender_position)?;
    if context.source_ordinal != SOURCE_ORDINAL {
        return Err(SourceError::WrongContext);
    }
    let source_position = context.sender_position;
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
        let mut source_subkey = derive_source_subkey(context, held_key.subset, &held_key.key);
        let cipher = Aes256::new_from_slice(&source_subkey)
            .map_err(|_| SourceError::WrongSubsetKeyVector)?;
        source_subkey.zeroize();
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

pub fn derive_source_coordinate_shares(
    context: &SourceContext,
    holder_position: u16,
    correction: Option<&[u8; SOURCE_CORRECTION_BYTE_LENGTH]>,
    held_subset_keys: &[HeldSubsetKey],
) -> Result<[u8; SOURCE_BIT_COUNT], SourceError> {
    validate_position(context.participant_count, context.sender_position)?;
    validate_position(context.participant_count, holder_position)?;
    if context.source_ordinal != SOURCE_ORDINAL {
        return Err(SourceError::WrongContext);
    }
    let expected_slots = sender_subset_slots(holder_position);
    if held_subset_keys.len() != expected_slots.len()
        || held_subset_keys
            .iter()
            .zip(expected_slots)
            .any(|(key, (family, subset))| key.family != family || key.subset != subset)
    {
        return Err(SourceError::WrongSubsetKeyVector);
    }
    let mut shares = [0_u8; SOURCE_BIT_COUNT];
    let mut source_key_count = 0_usize;
    for held_key in held_subset_keys {
        if held_key.family != LOW_SUBSET_SIZE
            || held_key.subset & (1_u16 << context.sender_position) == 0
        {
            continue;
        }
        if held_key.subset & (1_u16 << holder_position) == 0 {
            return Err(SourceError::WrongSubsetKeyVector);
        }
        source_key_count += 1;
        let source_rank = (held_key.subset & ((1_u16 << context.sender_position) - 1)).count_ones();
        let mut source_subkey = derive_source_subkey(context, held_key.subset, &held_key.key);
        let cipher = Aes256::new_from_slice(&source_subkey)
            .map_err(|_| SourceError::WrongSubsetKeyVector)?;
        source_subkey.zeroize();
        let source_rank =
            usize::try_from(source_rank).map_err(|_| SourceError::WrongSubsetKeyVector)?;
        let source_start_bit = source_rank
            .checked_mul(SOURCE_BIT_COUNT)
            .ok_or(SourceError::WrongSubsetKeyVector)?;
        let source_end_bit = source_start_bit
            .checked_add(SOURCE_BIT_COUNT)
            .ok_or(SourceError::WrongSubsetKeyVector)?;
        let subset_basis = normalized_subset_basis_at_holder(held_key.subset, holder_position)?;
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
                if (address[bit_offset / 8] >> (bit_offset % 8)) & 1 == 1 {
                    shares[source_bit_ordinal] ^= subset_basis;
                }
            }
            address.zeroize();
        }
    }
    let expected_source_key_count = if holder_position == context.sender_position {
        84
    } else {
        56
    };
    if source_key_count != expected_source_key_count {
        return Err(SourceError::WrongSubsetKeyVector);
    }
    if let Some(correction) = correction {
        for (source_bit_ordinal, share) in shares.iter_mut().enumerate() {
            *share ^= (correction[source_bit_ordinal / 8] >> (source_bit_ordinal % 8)) & 1;
        }
    }
    Ok(shares)
}

fn normalized_subset_basis_at_holder(subset: u16, holder_position: u16) -> Result<u8, SourceError> {
    let admitted_mask = (1_u16 << COMPLETION_PROFILE_PARTICIPANT_COUNT) - 1;
    if subset & !admitted_mask != 0
        || subset.count_ones() != u32::from(LOW_SUBSET_SIZE)
        || subset & (1_u16 << holder_position) == 0
    {
        return Err(SourceError::WrongSubsetKeyVector);
    }
    let point = (holder_position + 1) as u8;
    let mut numerator = 1_u8;
    let mut denominator = 1_u8;
    for participant_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
        if subset & (1_u16 << participant_position) != 0 {
            continue;
        }
        let coordinate = (participant_position + 1) as u8;
        numerator = gf16_multiply(numerator, point ^ coordinate);
        denominator = gf16_multiply(denominator, coordinate);
    }
    let inverse = gf16_inverse(denominator).ok_or(SourceError::WrongSubsetKeyVector)?;
    Ok(gf16_multiply(numerator, inverse))
}

fn gf16_multiply(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0_u8;
    for _ in 0..4 {
        product ^= (0_u8.wrapping_sub(right & 1)) & left;
        let high_bit = left >> 3;
        left = (left << 1) & 0x0f;
        left ^= (0_u8.wrapping_sub(high_bit)) & 0x03;
        right >>= 1;
    }
    product & 0x0f
}

fn gf16_inverse(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }
    let mut result = 1_u8;
    let mut base = value;
    let mut exponent = 14_u8;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = gf16_multiply(result, base);
        }
        base = gf16_multiply(base, base);
        exponent >>= 1;
    }
    Some(result)
}

fn derive_source_subkey(
    context: &SourceContext,
    subset: u16,
    subset_master: &[u8; HELD_SUBSET_KEY_BYTE_LENGTH],
) -> [u8; 32] {
    let mut address = Vec::with_capacity(271);
    address.extend_from_slice(context.action_proposal_identity.as_bytes());
    address.extend_from_slice(context.roster_identity.as_bytes());
    address.extend_from_slice(&context.preparation_attempt.to_le_bytes());
    address.extend_from_slice(context.predecessor_identity.as_bytes());
    address.extend_from_slice(context.verified_preparation_root.as_bytes());
    address.push(SOURCE_STREAM_FAMILY);
    address.extend_from_slice(&subset.to_le_bytes());
    address.extend_from_slice(&context.sender_position.to_le_bytes());
    address.extend_from_slice(&context.source_ordinal.to_le_bytes());
    let output = kmac256(
        subset_master,
        &address,
        PADDED_CONTINUATION_SUBKEY_CUSTOMIZATION,
    );
    address.zeroize();
    output
}

#[allow(clippy::too_many_arguments)]
pub fn verify_source_carrier(
    expected_context: SourceContext,
    expected_declaration: Option<SourceDeclaration>,
    roster: &Roster,
    body_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<VerifiedSource, SourceError> {
    validate_position(
        expected_context.participant_count,
        expected_context.sender_position,
    )?;
    require_roster_identity(roster, expected_context.roster_identity)
        .map_err(|_| SourceError::WrongContext)?;
    let body_identity = source_body_identity(body_bytes)?;
    let signature =
        ActionSignatureCarrier::decode(expected_context.participant_count, signature_bytes)
            .map_err(|_| SourceError::InvalidSignature)?;
    let verification_key = signing_verification_key(roster, expected_context.sender_position)
        .map_err(|_| SourceError::WrongParticipantPosition)?;
    signature
        .verify(
            expected_context.sender_position,
            ActionSignaturePurpose::Source,
            body_identity,
            verification_key,
        )
        .map_err(|_| SourceError::InvalidSignature)?;
    let body = SourceBody::decode(expected_context.participant_count, body_bytes)?;
    if body.context != expected_context {
        let same_one_shot_scope = body.context.participant_count
            == expected_context.participant_count
            && body.context.action_proposal_identity == expected_context.action_proposal_identity
            && body.context.roster_identity == expected_context.roster_identity
            && body.context.preparation_attempt == expected_context.preparation_attempt
            && body.context.predecessor_identity == expected_context.predecessor_identity
            && body.context.verified_preparation_root == expected_context.verified_preparation_root
            && body.context.source_ordinal == expected_context.source_ordinal;
        return Err(if same_one_shot_scope {
            SourceError::AuthenticatedBodyViolation
        } else {
            SourceError::WrongContext
        });
    }
    if expected_declaration.is_some_and(|declaration| declaration != body.declaration) {
        return Err(SourceError::WrongContext);
    }
    Ok(VerifiedSource {
        sender_position: expected_context.sender_position,
        declaration: body.declaration,
        correction: body.correction,
        body_identity,
        verified_preparation_root: body.context.verified_preparation_root,
    })
}

fn source_body_identity(body_bytes: &[u8]) -> Result<Hash512, SourceError> {
    hash_foundation_tuple_512(
        SOURCE_BODY_IDENTITY_DOMAIN,
        &[CanonicalItem::variable_bytes(body_bytes)
            .map_err(|_| SourceError::InvalidCanonicalEncoding)?],
    )
    .map_err(|_| SourceError::InvalidCanonicalEncoding)
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

    fn decode_hex<const BYTE_LENGTH: usize>(hex: &str) -> [u8; BYTE_LENGTH] {
        assert_eq!(hex.len(), 2 * BYTE_LENGTH);
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).expect("valid hex")
        })
    }

    fn context() -> SourceContext {
        SourceContext {
            participant_count: COMPLETION_PROFILE_PARTICIPANT_COUNT,
            action_proposal_identity: Hash512::from_bytes([0x11; 64]),
            roster_identity: Hash512::from_bytes([0x22; 64]),
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

        let mut rejected_version = SourceBody::new(context(), SourceDeclaration::Abstain, None)
            .expect("constructs")
            .encode()
            .expect("encodes");
        rejected_version[2..4].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            SourceBody::decode(COMPLETION_PROFILE_PARTICIPANT_COUNT, &rejected_version),
            Err(SourceError::WrongSchema),
        );
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
        let source_context = context();
        let zero =
            derive_honest_source_correction(&source_context, &[0; 10], &keys).expect("derives");
        for score_position in 0..SCORE_ENCODING_COUNT {
            for bit_position in 0..SCORE_BIT_WIDTH {
                let mut scores = [0_u8; SCORE_ENCODING_COUNT];
                scores[score_position] = 1 << bit_position;
                let changed = derive_honest_source_correction(&source_context, &scores, &keys)
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
            derive_honest_source_correction(&source_context, &[0; 9], &keys),
            Err(SourceError::NoncanonicalCorrection)
        ));
        assert!(matches!(
            derive_honest_source_correction(&source_context, &[16; 10], &keys),
            Err(SourceError::NoncanonicalCorrection)
        ));

        let changed_context = SourceContext {
            verified_preparation_root: Hash512::from_bytes([0x45; 64]),
            ..source_context
        };
        assert_ne!(
            derive_honest_source_correction(&source_context, &[0; 10], &keys)
                .expect("original context derives"),
            derive_honest_source_correction(&changed_context, &[0; 10], &keys)
                .expect("changed context derives"),
        );
    }

    #[test]
    fn source_coordinate_derivation_reconstructs_every_corrected_score_bit() {
        let score_encodings = [1_u8, 10, 2, 9, 3, 8, 4, 7, 5, 6];
        for dealer_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            let source_context = SourceContext {
                sender_position: dealer_position,
                ..context()
            };
            let held_keys = |holder_position| {
                sender_subset_slots(holder_position)
                    .into_iter()
                    .map(|(family, subset)| HeldSubsetKey {
                        family,
                        subset,
                        key: core::array::from_fn(|index| {
                            (u32::from(family) * 17 + u32::from(subset) * 31 + index as u32 * 13)
                                as u8
                        }),
                    })
                    .collect::<Vec<_>>()
            };
            let correction = derive_honest_source_correction(
                &source_context,
                &score_encodings,
                &held_keys(dealer_position),
            )
            .expect("dealer correction derives");
            let shares = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
                .map(|holder_position| {
                    derive_source_coordinate_shares(
                        &source_context,
                        holder_position,
                        Some(&correction),
                        &held_keys(holder_position),
                    )
                    .expect("holder coordinates derive")
                })
                .collect::<Vec<_>>();
            for source_bit_ordinal in 0..SOURCE_BIT_COUNT {
                let expected = (score_encodings[source_bit_ordinal / SCORE_BIT_WIDTH]
                    >> (source_bit_ordinal % SCORE_BIT_WIDTH))
                    & 1;
                let known = core::array::from_fn::<_, 4, _>(|position| {
                    shares[position][source_bit_ordinal]
                });
                assert_eq!(interpolate_four(&known, 0), expected);
                for holder_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
                    assert_eq!(
                        interpolate_four(&known, (holder_position + 1) as u8),
                        shares[usize::from(holder_position)][source_bit_ordinal],
                    );
                }
            }
        }
    }

    fn interpolate_four(values: &[u8; 4], target: u8) -> u8 {
        (0..4).fold(0_u8, |result, position| {
            let point = (position + 1) as u8;
            let mut numerator = 1_u8;
            let mut denominator = 1_u8;
            for other_position in 0..4 {
                if other_position == position {
                    continue;
                }
                let other_point = (other_position + 1) as u8;
                numerator = gf16_multiply(numerator, target ^ other_point);
                denominator = gf16_multiply(denominator, point ^ other_point);
            }
            result
                ^ gf16_multiply(
                    values[position],
                    gf16_multiply(
                        numerator,
                        gf16_inverse(denominator).expect("distinct interpolation points"),
                    ),
                )
        })
    }

    #[test]
    fn source_subkey_matches_independent_kmac_vector() {
        let source_context = SourceContext {
            participant_count: COMPLETION_PROFILE_PARTICIPANT_COUNT,
            action_proposal_identity: Hash512::from_bytes([0x11; 64]),
            roster_identity: Hash512::from_bytes([0x22; 64]),
            preparation_attempt: 0x3344,
            predecessor_identity: Hash512::from_bytes([0x33; 64]),
            verified_preparation_root: Hash512::from_bytes([0x44; 64]),
            sender_position: 0,
            source_ordinal: 0,
        };
        let master = core::array::from_fn(|index| index as u8);
        assert_eq!(
            derive_source_subkey(&source_context, 0x007f, &master),
            decode_hex::<32>("00d27030d682e9d6fe2ce0978a0842422da36594d80b390dc69ea2c35b690a1d",),
        );
    }
}
