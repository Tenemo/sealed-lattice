use core::fmt;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    hash_foundation_tuple_512,
};
use zeroize::{Zeroize, Zeroizing};

use super::preparation_parent::{
    PreparationParent, SUBSET_COMMITMENT_BYTE_LENGTH, SUBSET_COMMITMENT_COUNT,
};

pub const COMPLETION_PROFILE_PARTICIPANT_COUNT: u16 = 10;
pub const CONTRIBUTION_SEED_BYTE_LENGTH: usize = 32;
pub const CONTRIBUTION_SALT_BYTE_LENGTH: usize = 48;
pub const CONTRIBUTION_OPENING_BYTE_LENGTH: usize =
    CONTRIBUTION_SEED_BYTE_LENGTH + CONTRIBUTION_SALT_BYTE_LENGTH;
pub const AFFINE_MODULE_VALUE_BYTE_LENGTH: usize = 48;
pub const AFFINE_COEFFICIENT_COUNT: usize = 14;
pub const AFFINE_COEFFICIENT_BYTE_LENGTH: usize =
    AFFINE_COEFFICIENT_COUNT * AFFINE_MODULE_VALUE_BYTE_LENGTH;
pub const PAIR_OPENING_COUNT: usize = 84;
pub const PAIR_OPENING_BYTE_LENGTH: usize = PAIR_OPENING_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH;
pub const PREPARATION_PLAINTEXT_BYTE_LENGTH: usize =
    8 + 2 * 6 + PAIR_OPENING_BYTE_LENGTH + 2 * AFFINE_MODULE_VALUE_BYTE_LENGTH;

const LOW_SUBSET_SIZE: u16 = 7;
const STATUS_SUBSET_SIZE: u16 = 8;
const LOW_COEFFICIENT_COUNT: usize = 10;
const STATUS_COEFFICIENT_COUNT: usize = 4;
const PREPARATION_PLAINTEXT_SCHEMA_IDENTIFIER: u16 = 0x0207;
const PREPARATION_PLAINTEXT_SCHEMA_VERSION: u16 = 1;
const SUBSET_CONTRIBUTION_PURPOSE: u16 = 1;
const SUBSET_CONTRIBUTION_COMMITMENT_DOMAIN: &str =
    "sealed-lattice/construction/subset-contribution-commitment/v1";
const VERIFIED_PREPARATION_PLAINTEXT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/verified-preparation-plaintext/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparationPlaintextError {
    InvalidAffineMask,
    InvalidCanonicalEncoding,
    WrongCommitment,
    WrongContext,
    WrongItemTypeOrLength,
    WrongParticipantPosition,
    WrongSchema,
}

impl fmt::Display for PreparationPlaintextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAffineMask => "preparation affine mask has a zero constant",
            Self::InvalidCanonicalEncoding => "preparation plaintext is not canonically encoded",
            Self::WrongCommitment => "preparation opening does not match the signed commitment",
            Self::WrongContext => "preparation plaintext has the wrong parent context",
            Self::WrongItemTypeOrLength => {
                "preparation plaintext field has the wrong type or length"
            }
            Self::WrongParticipantPosition => {
                "preparation plaintext sender or recipient position is invalid"
            }
            Self::WrongSchema => "preparation plaintext has the wrong schema or version",
        })
    }
}

impl std::error::Error for PreparationPlaintextError {}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
struct ContributionOpening {
    seed: [u8; CONTRIBUTION_SEED_BYTE_LENGTH],
    salt: [u8; CONTRIBUTION_SALT_BYTE_LENGTH],
}

impl ContributionOpening {
    fn decode(bytes: &[u8]) -> Result<Self, PreparationPlaintextError> {
        if bytes.len() != CONTRIBUTION_OPENING_BYTE_LENGTH {
            return Err(PreparationPlaintextError::WrongItemTypeOrLength);
        }
        Ok(Self {
            seed: bytes[..CONTRIBUTION_SEED_BYTE_LENGTH]
                .try_into()
                .map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)?,
            salt: bytes[CONTRIBUTION_SEED_BYTE_LENGTH..]
                .try_into()
                .map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)?,
        })
    }

    fn append_to(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.seed);
        output.extend_from_slice(&self.salt);
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct PreparationPlaintext {
    openings: [ContributionOpening; PAIR_OPENING_COUNT],
    affine_a_evaluation: [u8; AFFINE_MODULE_VALUE_BYTE_LENGTH],
    affine_b_evaluation: [u8; AFFINE_MODULE_VALUE_BYTE_LENGTH],
}

impl PreparationPlaintext {
    fn new(
        openings: [ContributionOpening; PAIR_OPENING_COUNT],
        affine_a_evaluation: [u8; AFFINE_MODULE_VALUE_BYTE_LENGTH],
        affine_b_evaluation: [u8; AFFINE_MODULE_VALUE_BYTE_LENGTH],
    ) -> Self {
        Self {
            openings,
            affine_a_evaluation,
            affine_b_evaluation,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, PreparationPlaintextError> {
        let mut opening_bytes = Vec::with_capacity(PAIR_OPENING_BYTE_LENGTH);
        for opening in self.openings {
            opening.append_to(&mut opening_bytes);
        }
        let mut affine_bytes = Vec::with_capacity(2 * AFFINE_MODULE_VALUE_BYTE_LENGTH);
        affine_bytes.extend_from_slice(&self.affine_a_evaluation);
        affine_bytes.extend_from_slice(&self.affine_b_evaluation);
        let encoded = CanonicalTuple::new(
            PREPARATION_PLAINTEXT_SCHEMA_IDENTIFIER,
            PREPARATION_PLAINTEXT_SCHEMA_VERSION,
            vec![
                CanonicalItem::fixed_bytes(opening_bytes)
                    .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?,
                CanonicalItem::fixed_bytes(affine_bytes)
                    .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?,
            ],
        )
        .encode()
        .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?;
        if encoded.len() != PREPARATION_PLAINTEXT_BYTE_LENGTH {
            return Err(PreparationPlaintextError::InvalidCanonicalEncoding);
        }
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PreparationPlaintextError> {
        if bytes.len() != PREPARATION_PLAINTEXT_BYTE_LENGTH {
            return Err(PreparationPlaintextError::WrongItemTypeOrLength);
        }
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?;
        if tuple.schema_identifier != PREPARATION_PLAINTEXT_SCHEMA_IDENTIFIER
            || tuple.schema_version != PREPARATION_PLAINTEXT_SCHEMA_VERSION
        {
            return Err(PreparationPlaintextError::WrongSchema);
        }
        if tuple.items.len() != 2
            || tuple.items[0].item_type() != CanonicalItemType::RawBytes
            || tuple.items[1].item_type() != CanonicalItemType::RawBytes
            || tuple.items[0].canonical_bytes().len() != PAIR_OPENING_BYTE_LENGTH
            || tuple.items[1].canonical_bytes().len() != 2 * AFFINE_MODULE_VALUE_BYTE_LENGTH
        {
            return Err(PreparationPlaintextError::WrongItemTypeOrLength);
        }
        let openings = tuple.items[0]
            .canonical_bytes()
            .chunks_exact(CONTRIBUTION_OPENING_BYTE_LENGTH)
            .map(ContributionOpening::decode)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)?;
        let affine_bytes = tuple.items[1].canonical_bytes();
        let plaintext = Self::new(
            openings,
            affine_bytes[..AFFINE_MODULE_VALUE_BYTE_LENGTH]
                .try_into()
                .map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)?,
            affine_bytes[AFFINE_MODULE_VALUE_BYTE_LENGTH..]
                .try_into()
                .map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)?,
        );
        if plaintext.encode()?.as_slice() != bytes {
            return Err(PreparationPlaintextError::InvalidCanonicalEncoding);
        }
        Ok(plaintext)
    }
}

pub struct GeneratedPreparationMaterial {
    pub subset_commitments: [[u8; SUBSET_COMMITMENT_BYTE_LENGTH]; SUBSET_COMMITMENT_COUNT],
    pub recipient_plaintexts: Vec<Vec<u8>>,
}

#[derive(Zeroize)]
pub struct HeldSubsetKey {
    pub family: u16,
    pub subset: u16,
    pub key: [u8; CONTRIBUTION_SEED_BYTE_LENGTH],
}

impl Drop for HeldSubsetKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparationMaterialContext {
    pub action_proposal_identity: Hash512,
    pub action_key_set_roster_identity: Hash512,
    pub preparation_attempt: u16,
    pub predecessor_identity: Hash512,
    pub sender_position: u16,
}

pub fn generate_preparation_material(
    context: &PreparationMaterialContext,
    opening_bytes: &[u8],
    affine_coefficient_bytes: &[u8],
) -> Result<GeneratedPreparationMaterial, PreparationPlaintextError> {
    validate_position(context.sender_position)?;
    if opening_bytes.len() != SUBSET_COMMITMENT_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH
        || affine_coefficient_bytes.len() != AFFINE_COEFFICIENT_BYTE_LENGTH
    {
        return Err(PreparationPlaintextError::WrongItemTypeOrLength);
    }
    let openings = Zeroizing::new(
        opening_bytes
            .chunks_exact(CONTRIBUTION_OPENING_BYTE_LENGTH)
            .map(ContributionOpening::decode)
            .collect::<Result<Vec<_>, _>>()?,
    );
    let affine_coefficients = Zeroizing::new(
        affine_coefficient_bytes
            .chunks_exact(AFFINE_MODULE_VALUE_BYTE_LENGTH)
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)
            })
            .collect::<Result<Vec<[u8; AFFINE_MODULE_VALUE_BYTE_LENGTH]>, _>>()?,
    );
    if affine_coefficients[LOW_COEFFICIENT_COUNT]
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(PreparationPlaintextError::InvalidAffineMask);
    }

    let sender_slots = sender_subset_slots(context.sender_position);
    if sender_slots.len() != SUBSET_COMMITMENT_COUNT || openings.len() != sender_slots.len() {
        return Err(PreparationPlaintextError::WrongItemTypeOrLength);
    }
    let subset_commitments = sender_slots
        .iter()
        .zip(openings.iter())
        .enumerate()
        .map(|(ordinal, ((family, subset), opening))| {
            contribution_commitment(
                context.action_proposal_identity,
                context.action_key_set_roster_identity,
                context.preparation_attempt,
                context.predecessor_identity,
                *family,
                *subset,
                context.sender_position,
                ordinal,
                *opening,
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)?;

    let mut recipient_plaintexts =
        Vec::with_capacity(usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT - 1));
    for recipient_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
        if recipient_position == context.sender_position {
            continue;
        }
        let pair_openings = sender_slots
            .iter()
            .zip(openings.iter())
            .filter_map(|((_family, subset), opening)| {
                subset_contains(*subset, recipient_position).then_some(*opening)
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)?;
        let point = u8::try_from(recipient_position + 1)
            .map_err(|_| PreparationPlaintextError::WrongParticipantPosition)?;
        let affine_a_evaluation =
            evaluate_module_polynomial(&affine_coefficients[..LOW_COEFFICIENT_COUNT], point);
        let affine_b_evaluation = evaluate_module_polynomial(
            &affine_coefficients
                [LOW_COEFFICIENT_COUNT..LOW_COEFFICIENT_COUNT + STATUS_COEFFICIENT_COUNT],
            point,
        );
        recipient_plaintexts.push(
            PreparationPlaintext::new(pair_openings, affine_a_evaluation, affine_b_evaluation)
                .encode()?,
        );
    }
    Ok(GeneratedPreparationMaterial {
        subset_commitments,
        recipient_plaintexts,
    })
}

pub fn verify_local_preparation_material(
    parent: &PreparationParent,
    expected_context: &PreparationMaterialContext,
    opening_bytes: &[u8],
    affine_coefficient_bytes: &[u8],
) -> Result<(), PreparationPlaintextError> {
    if parent.participant_count() != COMPLETION_PROFILE_PARTICIPANT_COUNT
        || parent.action_proposal_identity() != expected_context.action_proposal_identity
        || parent.action_key_set_roster_identity()
            != expected_context.action_key_set_roster_identity
        || parent.preparation_attempt() != expected_context.preparation_attempt
        || parent.predecessor_identity() != expected_context.predecessor_identity
        || parent.sender_position() != expected_context.sender_position
    {
        return Err(PreparationPlaintextError::WrongContext);
    }
    let mut material =
        generate_preparation_material(expected_context, opening_bytes, affine_coefficient_bytes)?;
    let matches = material
        .subset_commitments
        .iter()
        .enumerate()
        .all(|(index, commitment)| parent.subset_commitment(index) == Some(commitment));
    for plaintext in &mut material.recipient_plaintexts {
        plaintext.zeroize();
    }
    if !matches {
        return Err(PreparationPlaintextError::WrongCommitment);
    }
    Ok(())
}

pub fn derive_held_subset_keys(
    participant_position: u16,
    own_opening_bytes: &[u8],
    remote_plaintext_bytes: &[Vec<u8>],
) -> Result<Vec<HeldSubsetKey>, PreparationPlaintextError> {
    validate_position(participant_position)?;
    if own_opening_bytes.len() != SUBSET_COMMITMENT_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH
        || remote_plaintext_bytes.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT - 1)
    {
        return Err(PreparationPlaintextError::WrongItemTypeOrLength);
    }
    let own_openings = Zeroizing::new(
        own_opening_bytes
            .chunks_exact(CONTRIBUTION_OPENING_BYTE_LENGTH)
            .map(ContributionOpening::decode)
            .collect::<Result<Vec<_>, _>>()?,
    );
    let remote_plaintexts = Zeroizing::new(
        remote_plaintext_bytes
            .iter()
            .map(|bytes| PreparationPlaintext::decode(bytes))
            .collect::<Result<Vec<_>, _>>()?,
    );
    let local_slots = sender_subset_slots(participant_position);
    if local_slots.len() != SUBSET_COMMITMENT_COUNT || own_openings.len() != local_slots.len() {
        return Err(PreparationPlaintextError::WrongItemTypeOrLength);
    }

    let mut held_keys = Vec::with_capacity(local_slots.len());
    for (local_slot_index, (family, subset)) in local_slots.into_iter().enumerate() {
        let mut key = own_openings[local_slot_index].seed;
        for sender_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            if sender_position == participant_position || !subset_contains(subset, sender_position)
            {
                continue;
            }
            let remote_index = if sender_position < participant_position {
                usize::from(sender_position)
            } else {
                usize::from(sender_position - 1)
            };
            let plaintext = remote_plaintexts
                .get(remote_index)
                .ok_or(PreparationPlaintextError::WrongItemTypeOrLength)?;
            let pair_opening_index = sender_subset_slots(sender_position)
                .into_iter()
                .filter(|(_sender_family, sender_subset)| {
                    subset_contains(*sender_subset, participant_position)
                })
                .position(|(sender_family, sender_subset)| {
                    sender_family == family && sender_subset == subset
                })
                .ok_or(PreparationPlaintextError::WrongContext)?;
            let opening = plaintext
                .openings
                .get(pair_opening_index)
                .ok_or(PreparationPlaintextError::WrongItemTypeOrLength)?;
            for (key_byte, seed_byte) in key.iter_mut().zip(opening.seed) {
                *key_byte ^= seed_byte;
            }
        }
        held_keys.push(HeldSubsetKey {
            family,
            subset,
            key,
        });
    }
    Ok(held_keys)
}

pub fn verify_preparation_plaintext(
    parent: &PreparationParent,
    expected_context: &PreparationMaterialContext,
    recipient_position: u16,
    bytes: &[u8],
) -> Result<Hash512, PreparationPlaintextError> {
    validate_position(recipient_position)?;
    if parent.participant_count() != COMPLETION_PROFILE_PARTICIPANT_COUNT
        || parent.action_proposal_identity() != expected_context.action_proposal_identity
        || parent.action_key_set_roster_identity()
            != expected_context.action_key_set_roster_identity
        || parent.preparation_attempt() != expected_context.preparation_attempt
        || parent.predecessor_identity() != expected_context.predecessor_identity
        || parent.sender_position() != expected_context.sender_position
        || parent.sender_position() == recipient_position
    {
        return Err(PreparationPlaintextError::WrongContext);
    }
    let plaintext = PreparationPlaintext::decode(bytes)?;
    let sender_slots = sender_subset_slots(parent.sender_position());
    let pair_slot_indices = sender_slots
        .iter()
        .enumerate()
        .filter_map(|(index, (_family, subset))| {
            subset_contains(*subset, recipient_position).then_some(index)
        })
        .collect::<Vec<_>>();
    if pair_slot_indices.len() != PAIR_OPENING_COUNT {
        return Err(PreparationPlaintextError::WrongContext);
    }
    for (pair_index, sender_index) in pair_slot_indices.into_iter().enumerate() {
        let (family, subset) = sender_slots[sender_index];
        let commitment = contribution_commitment(
            parent.action_proposal_identity(),
            parent.action_key_set_roster_identity(),
            parent.preparation_attempt(),
            parent.predecessor_identity(),
            family,
            subset,
            parent.sender_position(),
            sender_index,
            plaintext.openings[pair_index],
        )?;
        if parent.subset_commitment(sender_index) != Some(&commitment) {
            return Err(PreparationPlaintextError::WrongCommitment);
        }
    }
    let parent_identity = parent
        .body_identity()
        .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?;
    hash_foundation_tuple_512(
        VERIFIED_PREPARATION_PLAINTEXT_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(parent_identity.into_bytes()),
            CanonicalItem::unsigned16(recipient_position),
            CanonicalItem::variable_bytes(bytes)
                .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?,
        ],
    )
    .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)
}

#[allow(clippy::too_many_arguments)]
fn contribution_commitment(
    action_proposal_identity: Hash512,
    action_key_set_roster_identity: Hash512,
    preparation_attempt: u16,
    predecessor_identity: Hash512,
    family: u16,
    subset: u16,
    sender_position: u16,
    ordinal: usize,
    opening: ContributionOpening,
) -> Result<[u8; SUBSET_COMMITMENT_BYTE_LENGTH], PreparationPlaintextError> {
    let ordinal =
        u64::try_from(ordinal).map_err(|_| PreparationPlaintextError::WrongItemTypeOrLength)?;
    Ok(hash_foundation_tuple_512(
        SUBSET_CONTRIBUTION_COMMITMENT_DOMAIN,
        &[
            CanonicalItem::hash512(action_proposal_identity.into_bytes()),
            CanonicalItem::hash512(action_key_set_roster_identity.into_bytes()),
            CanonicalItem::unsigned16(preparation_attempt),
            CanonicalItem::hash512(predecessor_identity.into_bytes()),
            CanonicalItem::unsigned16(family),
            CanonicalItem::unsigned16(subset),
            CanonicalItem::unsigned16(sender_position),
            CanonicalItem::unsigned16(SUBSET_CONTRIBUTION_PURPOSE),
            CanonicalItem::unsigned64(ordinal),
            CanonicalItem::fixed_bytes(opening.seed)
                .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?,
            CanonicalItem::fixed_bytes(opening.salt)
                .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?,
        ],
    )
    .map_err(|_| PreparationPlaintextError::InvalidCanonicalEncoding)?
    .into_bytes())
}

pub(super) fn sender_subset_slots(sender_position: u16) -> Vec<(u16, u16)> {
    [LOW_SUBSET_SIZE, STATUS_SUBSET_SIZE]
        .into_iter()
        .flat_map(|family| {
            (0_u16..(1_u16 << COMPLETION_PROFILE_PARTICIPANT_COUNT)).filter_map(move |subset| {
                (subset.count_ones() == u32::from(family)
                    && subset_contains(subset, sender_position))
                .then_some((family, subset))
            })
        })
        .collect()
}

const fn subset_contains(subset: u16, participant_position: u16) -> bool {
    subset & (1_u16 << participant_position) != 0
}

fn evaluate_module_polynomial(
    coefficients: &[[u8; AFFINE_MODULE_VALUE_BYTE_LENGTH]],
    point: u8,
) -> [u8; AFFINE_MODULE_VALUE_BYTE_LENGTH] {
    let mut result = [0_u8; AFFINE_MODULE_VALUE_BYTE_LENGTH];
    for coefficient in coefficients.iter().rev() {
        for (result_byte, coefficient_byte) in result.iter_mut().zip(coefficient) {
            *result_byte = gf16_mul_byte(*result_byte, point) ^ coefficient_byte;
        }
    }
    result
}

fn gf16_mul_byte(value: u8, point: u8) -> u8 {
    gf16_mul(value >> 4, point) << 4 | gf16_mul(value & 0x0f, point)
}

fn gf16_mul(mut left: u8, mut right: u8) -> u8 {
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

fn validate_position(position: u16) -> Result<(), PreparationPlaintextError> {
    if position >= COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(PreparationPlaintextError::WrongParticipantPosition);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_bytes(length: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn context() -> PreparationMaterialContext {
        PreparationMaterialContext {
            action_proposal_identity: Hash512::from_bytes([0x11; 64]),
            action_key_set_roster_identity: Hash512::from_bytes([0x22; 64]),
            preparation_attempt: 7,
            predecessor_identity: Hash512::from_bytes([0x33; 64]),
            sender_position: 2,
        }
    }

    fn generated() -> GeneratedPreparationMaterial {
        generate_preparation_material(
            &context(),
            &deterministic_bytes(
                SUBSET_COMMITMENT_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH,
                0x5001,
            ),
            &deterministic_bytes(AFFINE_COEFFICIENT_BYTE_LENGTH, 0x6001),
        )
        .expect("preparation material generates")
    }

    fn parent(material: &GeneratedPreparationMaterial) -> PreparationParent {
        PreparationParent::new(
            COMPLETION_PROFILE_PARTICIPANT_COUNT,
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x22; 64]),
            7,
            Hash512::from_bytes([0x33; 64]),
            2,
            material.subset_commitments,
            (0_u8..9)
                .map(|index| Hash512::from_bytes([index + 1; 64]))
                .collect(),
        )
        .expect("parent constructs")
    }

    #[test]
    fn exact_generation_and_every_recipient_verification() {
        let material = generated();
        assert_eq!(sender_subset_slots(2).len(), 120);
        assert_eq!(
            sender_subset_slots(2)
                .iter()
                .filter(|(family, _)| *family == LOW_SUBSET_SIZE)
                .count(),
            84
        );
        assert_eq!(material.recipient_plaintexts.len(), 9);
        assert!(
            material
                .recipient_plaintexts
                .iter()
                .all(|plaintext| plaintext.len() == PREPARATION_PLAINTEXT_BYTE_LENGTH)
        );
        let parent = parent(&material);
        for recipient in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            if recipient == 2 {
                continue;
            }
            let index = if recipient < 2 {
                usize::from(recipient)
            } else {
                usize::from(recipient - 1)
            };
            verify_preparation_plaintext(
                &parent,
                &context(),
                recipient,
                &material.recipient_plaintexts[index],
            )
            .expect("recipient plaintext verifies");
        }
    }

    #[test]
    fn mutation_wrong_recipient_and_zero_affine_constant_refuse() {
        let material = generated();
        let parent = parent(&material);
        let mut mutated = material.recipient_plaintexts[7].clone();
        mutated[20] ^= 1;
        assert!(verify_preparation_plaintext(&parent, &context(), 8, &mutated,).is_err());
        assert_eq!(
            verify_preparation_plaintext(&parent, &context(), 7, &material.recipient_plaintexts[7],),
            Err(PreparationPlaintextError::WrongCommitment)
        );

        let mut affine = deterministic_bytes(AFFINE_COEFFICIENT_BYTE_LENGTH, 0x6001);
        affine[LOW_COEFFICIENT_COUNT * AFFINE_MODULE_VALUE_BYTE_LENGTH
            ..(LOW_COEFFICIENT_COUNT + 1) * AFFINE_MODULE_VALUE_BYTE_LENGTH]
            .fill(0);
        assert!(matches!(
            generate_preparation_material(
                &context(),
                &deterministic_bytes(
                    SUBSET_COMMITMENT_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH,
                    0x5001,
                ),
                &affine,
            ),
            Err(PreparationPlaintextError::InvalidAffineMask)
        ));
    }
}
