//! Canonical recipient-private VSS mailbox payloads.

use core::mem::size_of;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    bgv::{
        key_switch_topology::canonical_residue_byte_length,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    },
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    },
};

use super::selected_committed_material_relation_plan_input;

const RECIPIENT_SHARE_LIMB_SCHEMA_IDENTIFIER: u16 = 0x2106;
const RECIPIENT_PRIVATE_VSS_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x2107;
const RECIPIENT_VSS_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const RECIPIENT_SHARE_LIMB_ITEM_COUNT: usize = 3;
const RECIPIENT_PRIVATE_VSS_PAYLOAD_ITEM_COUNT: usize = 2;
const MATERIAL_SEED_BYTE_LENGTH: usize = 64;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_TUPLE_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH: usize = 6;
const VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const CUMULATIVE_DECODE_BUDGET_FACTOR: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecipientPrivateVssPayloadError {
    CanonicalEncoding,
    WrongSchema,
    WrongTypeOrLength,
    WrongValue,
    UnsupportedProfile,
    CountOverflow,
}

pub(crate) struct RecipientShareLimbInput<'input> {
    pub(crate) sharing_limb_index: u16,
    pub(crate) canonical_share_coefficients: &'input [u64],
    pub(crate) recipient_share_material_seed: &'input [u8; MATERIAL_SEED_BYTE_LENGTH],
}

pub(crate) struct DecodedRecipientShareLimb {
    sharing_limb_index: u16,
    canonical_share_coefficients: Zeroizing<Box<[u64]>>,
    recipient_share_material_seed: Zeroizing<[u8; MATERIAL_SEED_BYTE_LENGTH]>,
}

impl DecodedRecipientShareLimb {
    pub(crate) const fn sharing_limb_index(&self) -> u16 {
        self.sharing_limb_index
    }

    pub(crate) fn canonical_share_coefficients(&self) -> &[u64] {
        &self.canonical_share_coefficients
    }

    pub(crate) fn recipient_share_material_seed(&self) -> &[u8; MATERIAL_SEED_BYTE_LENGTH] {
        &self.recipient_share_material_seed
    }
}

pub(crate) struct DecodedRecipientPrivateVssPayload {
    recipient_roster_position: u16,
    ordered_limbs: Box<[DecodedRecipientShareLimb]>,
}

impl DecodedRecipientPrivateVssPayload {
    pub(crate) const fn recipient_roster_position(&self) -> u16 {
        self.recipient_roster_position
    }

    #[cfg(test)]
    pub(crate) fn ordered_limbs(&self) -> &[DecodedRecipientShareLimb] {
        &self.ordered_limbs
    }

    pub(crate) fn into_ordered_limbs(self) -> Box<[DecodedRecipientShareLimb]> {
        self.ordered_limbs
    }
}

struct SelectedRecipientVssPayloadLayout {
    ordered_sharing_limb_indices: Box<[u16]>,
    ordered_moduli: Box<[u64]>,
    ordered_residue_byte_lengths: Box<[usize]>,
    canonical_payload_byte_length: usize,
    canonical_list_byte_length: usize,
}

impl SelectedRecipientVssPayloadLayout {
    fn derive() -> Result<Self, RecipientPrivateVssPayloadError> {
        let relation_input = selected_committed_material_relation_plan_input()
            .map_err(|_| RecipientPrivateVssPayloadError::UnsupportedProfile)?;
        if relation_input.ring_degree
            != u64::try_from(POLYNOMIAL_DEGREE)
                .map_err(|_| RecipientPrivateVssPayloadError::CountOverflow)?
            || relation_input.participant_count != FOUNDATION_PROFILE.participant_count
            || relation_input.sharing_data_modulus_indices.is_empty()
        {
            return Err(RecipientPrivateVssPayloadError::UnsupportedProfile);
        }

        let mut ordered_moduli =
            Vec::with_capacity(relation_input.sharing_data_modulus_indices.len());
        let mut ordered_residue_byte_lengths =
            Vec::with_capacity(relation_input.sharing_data_modulus_indices.len());
        let mut previous_limb_index = None;
        let mut nested_tuple_bytes = 0_usize;
        for sharing_limb_index in relation_input.sharing_data_modulus_indices.iter().copied() {
            if previous_limb_index.is_some_and(|previous| sharing_limb_index <= previous) {
                return Err(RecipientPrivateVssPayloadError::UnsupportedProfile);
            }
            let modulus = DATA_PRIMES
                .get(usize::from(sharing_limb_index))
                .copied()
                .ok_or(RecipientPrivateVssPayloadError::UnsupportedProfile)?;
            let residue_byte_length = canonical_residue_byte_length(modulus)
                .map_err(|_| RecipientPrivateVssPayloadError::UnsupportedProfile)?;
            let coefficient_byte_length = POLYNOMIAL_DEGREE
                .checked_mul(residue_byte_length)
                .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
            nested_tuple_bytes = nested_tuple_bytes
                .checked_add(recipient_share_limb_canonical_byte_length(
                    coefficient_byte_length,
                )?)
                .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
            ordered_moduli.push(modulus);
            ordered_residue_byte_lengths.push(residue_byte_length);
            previous_limb_index = Some(sharing_limb_index);
        }
        let canonical_list_byte_length = HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH
            .checked_add(nested_tuple_bytes)
            .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
        let canonical_payload_byte_length = CANONICAL_TUPLE_HEADER_BYTE_LENGTH
            .checked_add(CANONICAL_TUPLE_ITEM_HEADER_BYTE_LENGTH + size_of::<u16>())
            .and_then(|length| {
                length.checked_add(
                    CANONICAL_TUPLE_ITEM_HEADER_BYTE_LENGTH + canonical_list_byte_length,
                )
            })
            .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
        Ok(Self {
            ordered_sharing_limb_indices: relation_input
                .sharing_data_modulus_indices
                .into_boxed_slice(),
            ordered_moduli: ordered_moduli.into_boxed_slice(),
            ordered_residue_byte_lengths: ordered_residue_byte_lengths.into_boxed_slice(),
            canonical_payload_byte_length,
            canonical_list_byte_length,
        })
    }

    fn decode_limits(&self) -> Result<CanonicalDecodeLimits, RecipientPrivateVssPayloadError> {
        let cumulative_budget = self
            .canonical_payload_byte_length
            .checked_mul(CUMULATIVE_DECODE_BUDGET_FACTOR)
            .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
        Ok(CanonicalDecodeLimits {
            maximum_tuple_byte_length: self.canonical_payload_byte_length,
            maximum_item_count: self
                .ordered_sharing_limb_indices
                .len()
                .max(RECIPIENT_SHARE_LIMB_ITEM_COUNT),
            maximum_item_byte_length: self.canonical_list_byte_length,
            maximum_nesting_depth: 4,
            maximum_cumulative_work_byte_length: cumulative_budget,
            maximum_cumulative_allocation_byte_length: cumulative_budget,
        })
    }
}

fn recipient_share_limb_canonical_byte_length(
    coefficient_byte_length: usize,
) -> Result<usize, RecipientPrivateVssPayloadError> {
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        .checked_add(CANONICAL_TUPLE_ITEM_HEADER_BYTE_LENGTH + size_of::<u16>())
        .and_then(|length| {
            length.checked_add(
                CANONICAL_TUPLE_ITEM_HEADER_BYTE_LENGTH
                    + VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
                    + coefficient_byte_length,
            )
        })
        .and_then(|length| {
            length.checked_add(CANONICAL_TUPLE_ITEM_HEADER_BYTE_LENGTH + MATERIAL_SEED_BYTE_LENGTH)
        })
        .ok_or(RecipientPrivateVssPayloadError::CountOverflow)
}

pub(crate) fn canonical_recipient_private_vss_payload(
    recipient_roster_position: u16,
    ordered_limbs: &[RecipientShareLimbInput<'_>],
) -> Result<Zeroizing<Vec<u8>>, RecipientPrivateVssPayloadError> {
    let layout = SelectedRecipientVssPayloadLayout::derive()?;
    if recipient_roster_position >= FOUNDATION_PROFILE.participant_count
        || ordered_limbs.len() != layout.ordered_sharing_limb_indices.len()
    {
        return Err(RecipientPrivateVssPayloadError::WrongTypeOrLength);
    }
    let limits = layout.decode_limits()?;
    let mut limb_items = Zeroizing::new(Vec::with_capacity(ordered_limbs.len()));
    for (limb_ordinal, limb) in ordered_limbs.iter().enumerate() {
        let expected_limb_index = layout.ordered_sharing_limb_indices[limb_ordinal];
        let modulus = layout.ordered_moduli[limb_ordinal];
        let residue_byte_length = layout.ordered_residue_byte_lengths[limb_ordinal];
        if limb.sharing_limb_index != expected_limb_index
            || limb.canonical_share_coefficients.len() != POLYNOMIAL_DEGREE
            || limb
                .canonical_share_coefficients
                .iter()
                .any(|coefficient| *coefficient >= modulus)
        {
            return Err(RecipientPrivateVssPayloadError::WrongValue);
        }
        let coefficient_byte_length = POLYNOMIAL_DEGREE
            .checked_mul(residue_byte_length)
            .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
        let mut canonical_coefficients =
            Zeroizing::new(Vec::with_capacity(coefficient_byte_length));
        for coefficient in limb.canonical_share_coefficients {
            canonical_coefficients
                .extend_from_slice(&coefficient.to_le_bytes()[..residue_byte_length]);
        }
        let nested_tuple = Zeroizing::new(CanonicalTuple::new(
            RECIPIENT_SHARE_LIMB_SCHEMA_IDENTIFIER,
            RECIPIENT_VSS_PAYLOAD_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(limb.sharing_limb_index),
                CanonicalItem::variable_bytes(&canonical_coefficients)
                    .map_err(|_| RecipientPrivateVssPayloadError::CanonicalEncoding)?,
                CanonicalItem::fixed_bytes(limb.recipient_share_material_seed)
                    .map_err(|_| RecipientPrivateVssPayloadError::CanonicalEncoding)?,
            ],
        ));
        limb_items.push(
            CanonicalItem::nested_tuple_with_limits(&nested_tuple, &limits)
                .map_err(|_| RecipientPrivateVssPayloadError::CanonicalEncoding)?,
        );
    }
    let list_item = CanonicalItem::homogeneous_list_with_limits(
        CanonicalItemType::NestedTuple,
        &limb_items,
        &limits,
    )
    .map_err(|_| RecipientPrivateVssPayloadError::CanonicalEncoding)?;
    let payload = Zeroizing::new(CanonicalTuple::new(
        RECIPIENT_PRIVATE_VSS_PAYLOAD_SCHEMA_IDENTIFIER,
        RECIPIENT_VSS_PAYLOAD_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(recipient_roster_position),
            list_item,
        ],
    ));
    let canonical_bytes = Zeroizing::new(
        payload
            .encode_with_limits(&limits)
            .map_err(|_| RecipientPrivateVssPayloadError::CanonicalEncoding)?,
    );
    if canonical_bytes.len() != layout.canonical_payload_byte_length {
        return Err(RecipientPrivateVssPayloadError::WrongTypeOrLength);
    }
    Ok(canonical_bytes)
}

/// Exact canonical byte length of one selected recipient-private VSS payload.
/// The value is derived from the production relation's sharing-limb catalog,
/// selected moduli, ring degree, and canonical tuple grammar.
#[cfg(test)]
pub(crate) fn selected_recipient_private_vss_payload_byte_length()
-> Result<u64, RecipientPrivateVssPayloadError> {
    u64::try_from(SelectedRecipientVssPayloadLayout::derive()?.canonical_payload_byte_length)
        .map_err(|_| RecipientPrivateVssPayloadError::CountOverflow)
}

pub(crate) fn decode_recipient_private_vss_payload(
    canonical_bytes: &[u8],
) -> Result<DecodedRecipientPrivateVssPayload, RecipientPrivateVssPayloadError> {
    let layout = SelectedRecipientVssPayloadLayout::derive()?;
    if canonical_bytes.len() != layout.canonical_payload_byte_length {
        return Err(RecipientPrivateVssPayloadError::WrongTypeOrLength);
    }
    let limits = layout.decode_limits()?;
    let payload = Zeroizing::new(
        CanonicalTuple::decode(canonical_bytes, &limits)
            .map_err(|_| RecipientPrivateVssPayloadError::CanonicalEncoding)?,
    );
    require_tuple_header(
        &payload,
        RECIPIENT_PRIVATE_VSS_PAYLOAD_SCHEMA_IDENTIFIER,
        RECIPIENT_PRIVATE_VSS_PAYLOAD_ITEM_COUNT,
    )?;
    let recipient_roster_position = read_unsigned16(&payload.items[0])?;
    if recipient_roster_position >= FOUNDATION_PROFILE.participant_count {
        return Err(RecipientPrivateVssPayloadError::WrongValue);
    }
    let list_bytes = payload.items[1].canonical_bytes();
    if payload.items[1].item_type() != CanonicalItemType::HomogeneousList
        || list_bytes.len() != layout.canonical_list_byte_length
        || list_bytes.len() < HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH
        || u16::from_le_bytes([list_bytes[0], list_bytes[1]])
            != CanonicalItemType::NestedTuple.canonical_code()
        || usize::try_from(u32::from_le_bytes([
            list_bytes[2],
            list_bytes[3],
            list_bytes[4],
            list_bytes[5],
        ]))
        .map_err(|_| RecipientPrivateVssPayloadError::CountOverflow)?
            != layout.ordered_sharing_limb_indices.len()
    {
        return Err(RecipientPrivateVssPayloadError::WrongTypeOrLength);
    }

    let mut unread_limb_bytes = &list_bytes[HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH..];
    let mut ordered_limbs = Vec::with_capacity(layout.ordered_sharing_limb_indices.len());
    for limb_ordinal in 0..layout.ordered_sharing_limb_indices.len() {
        let nested_byte_length = canonical_tuple_prefix_byte_length(unread_limb_bytes)?;
        let (nested_bytes, remaining_bytes) = unread_limb_bytes.split_at(nested_byte_length);
        unread_limb_bytes = remaining_bytes;
        let nested_tuple = Zeroizing::new(
            CanonicalTuple::decode(nested_bytes, &limits)
                .map_err(|_| RecipientPrivateVssPayloadError::CanonicalEncoding)?,
        );
        require_tuple_header(
            &nested_tuple,
            RECIPIENT_SHARE_LIMB_SCHEMA_IDENTIFIER,
            RECIPIENT_SHARE_LIMB_ITEM_COUNT,
        )?;
        let sharing_limb_index = read_unsigned16(&nested_tuple.items[0])?;
        if sharing_limb_index != layout.ordered_sharing_limb_indices[limb_ordinal] {
            return Err(RecipientPrivateVssPayloadError::WrongValue);
        }
        let canonical_coefficient_bytes = nested_tuple.items[1]
            .variable_value_bytes()
            .map_err(|_| RecipientPrivateVssPayloadError::WrongTypeOrLength)?;
        let residue_byte_length = layout.ordered_residue_byte_lengths[limb_ordinal];
        let expected_coefficient_byte_length =
            POLYNOMIAL_DEGREE
                .checked_mul(residue_byte_length)
                .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
        if nested_tuple.items[1].item_type() != CanonicalItemType::RawBytes
            || canonical_coefficient_bytes.len() != expected_coefficient_byte_length
            || nested_tuple.items[2].item_type() != CanonicalItemType::RawBytes
            || nested_tuple.items[2].canonical_bytes().len() != MATERIAL_SEED_BYTE_LENGTH
        {
            return Err(RecipientPrivateVssPayloadError::WrongTypeOrLength);
        }
        let modulus = layout.ordered_moduli[limb_ordinal];
        let mut canonical_share_coefficients =
            Zeroizing::new(vec![0_u64; POLYNOMIAL_DEGREE].into_boxed_slice());
        for (destination, encoded_coefficient) in canonical_share_coefficients
            .iter_mut()
            .zip(canonical_coefficient_bytes.chunks_exact(residue_byte_length))
        {
            let mut coefficient_bytes = [0_u8; size_of::<u64>()];
            coefficient_bytes[..residue_byte_length].copy_from_slice(encoded_coefficient);
            let coefficient = u64::from_le_bytes(coefficient_bytes);
            coefficient_bytes.zeroize();
            if coefficient >= modulus {
                return Err(RecipientPrivateVssPayloadError::WrongValue);
            }
            *destination = coefficient;
        }
        let mut material_seed = [0_u8; MATERIAL_SEED_BYTE_LENGTH];
        material_seed.copy_from_slice(nested_tuple.items[2].canonical_bytes());
        ordered_limbs.push(DecodedRecipientShareLimb {
            sharing_limb_index,
            canonical_share_coefficients,
            recipient_share_material_seed: Zeroizing::new(material_seed),
        });
    }
    if !unread_limb_bytes.is_empty() {
        return Err(RecipientPrivateVssPayloadError::WrongTypeOrLength);
    }
    Ok(DecodedRecipientPrivateVssPayload {
        recipient_roster_position,
        ordered_limbs: ordered_limbs.into_boxed_slice(),
    })
}

fn require_tuple_header(
    tuple: &CanonicalTuple,
    expected_schema_identifier: u16,
    expected_item_count: usize,
) -> Result<(), RecipientPrivateVssPayloadError> {
    if tuple.schema_identifier != expected_schema_identifier
        || tuple.schema_version != RECIPIENT_VSS_PAYLOAD_SCHEMA_VERSION
    {
        return Err(RecipientPrivateVssPayloadError::WrongSchema);
    }
    if tuple.items.len() != expected_item_count {
        return Err(RecipientPrivateVssPayloadError::WrongTypeOrLength);
    }
    Ok(())
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, RecipientPrivateVssPayloadError> {
    if item.item_type() != CanonicalItemType::Unsigned16
        || item.canonical_bytes().len() != size_of::<u16>()
    {
        return Err(RecipientPrivateVssPayloadError::WrongTypeOrLength);
    }
    Ok(u16::from_le_bytes([
        item.canonical_bytes()[0],
        item.canonical_bytes()[1],
    ]))
}

fn canonical_tuple_prefix_byte_length(
    bytes: &[u8],
) -> Result<usize, RecipientPrivateVssPayloadError> {
    if bytes.len() < CANONICAL_TUPLE_HEADER_BYTE_LENGTH {
        return Err(RecipientPrivateVssPayloadError::CanonicalEncoding);
    }
    let item_count = usize::try_from(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
        .map_err(|_| RecipientPrivateVssPayloadError::CountOverflow)?;
    let mut byte_offset = CANONICAL_TUPLE_HEADER_BYTE_LENGTH;
    for _ in 0..item_count {
        let header_end = byte_offset
            .checked_add(CANONICAL_TUPLE_ITEM_HEADER_BYTE_LENGTH)
            .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
        if header_end > bytes.len() {
            return Err(RecipientPrivateVssPayloadError::CanonicalEncoding);
        }
        let item_byte_length = usize::try_from(u32::from_le_bytes([
            bytes[byte_offset + 2],
            bytes[byte_offset + 3],
            bytes[byte_offset + 4],
            bytes[byte_offset + 5],
        ]))
        .map_err(|_| RecipientPrivateVssPayloadError::CountOverflow)?;
        byte_offset = header_end
            .checked_add(item_byte_length)
            .ok_or(RecipientPrivateVssPayloadError::CountOverflow)?;
        if byte_offset > bytes.len() {
            return Err(RecipientPrivateVssPayloadError::CanonicalEncoding);
        }
    }
    Ok(byte_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_recipient_private_vss_payload_error<SuccessfulValue>(
        result: Result<SuccessfulValue, RecipientPrivateVssPayloadError>,
        expected_error: RecipientPrivateVssPayloadError,
    ) {
        match result {
            Err(actual_error) => assert_eq!(actual_error, expected_error),
            Ok(_) => panic!("recipient-private VSS payload unexpectedly succeeded"),
        }
    }

    fn test_limbs() -> Vec<(Vec<u64>, [u8; MATERIAL_SEED_BYTE_LENGTH])> {
        SelectedRecipientVssPayloadLayout::derive()
            .expect("selected recipient VSS layout")
            .ordered_moduli
            .iter()
            .copied()
            .enumerate()
            .map(|(limb_ordinal, modulus)| {
                let coefficients = (0..POLYNOMIAL_DEGREE)
                    .map(|coefficient_ordinal| {
                        (u64::try_from(coefficient_ordinal).expect("coefficient index")
                            + u64::try_from(limb_ordinal).expect("limb index") * 17)
                            % modulus
                    })
                    .collect::<Vec<_>>();
                (
                    coefficients,
                    [u8::try_from(limb_ordinal + 1).expect("test limb seed");
                        MATERIAL_SEED_BYTE_LENGTH],
                )
            })
            .collect()
    }

    #[test]
    fn recipient_private_vss_payload_round_trips_every_selected_sharing_limb() {
        let layout =
            SelectedRecipientVssPayloadLayout::derive().expect("selected recipient VSS layout");
        let test_limbs = test_limbs();
        let inputs = layout
            .ordered_sharing_limb_indices
            .iter()
            .copied()
            .zip(&test_limbs)
            .map(
                |(sharing_limb_index, (coefficients, material_seed))| RecipientShareLimbInput {
                    sharing_limb_index,
                    canonical_share_coefficients: coefficients,
                    recipient_share_material_seed: material_seed,
                },
            )
            .collect::<Vec<_>>();
        let canonical_bytes = canonical_recipient_private_vss_payload(
            FOUNDATION_PROFILE.participant_count - 1,
            &inputs,
        )
        .expect("canonical recipient-private VSS payload");
        assert_eq!(canonical_bytes.len(), layout.canonical_payload_byte_length);

        let decoded = decode_recipient_private_vss_payload(&canonical_bytes)
            .expect("decoded recipient-private VSS payload");
        assert_eq!(
            decoded.recipient_roster_position(),
            FOUNDATION_PROFILE.participant_count - 1
        );
        assert_eq!(
            decoded.ordered_limbs().len(),
            layout.ordered_sharing_limb_indices.len()
        );
        for (limb_ordinal, decoded_limb) in decoded.ordered_limbs().iter().enumerate() {
            assert_eq!(
                decoded_limb.sharing_limb_index(),
                layout.ordered_sharing_limb_indices[limb_ordinal]
            );
            assert_eq!(
                decoded_limb.canonical_share_coefficients(),
                test_limbs[limb_ordinal].0
            );
            assert_eq!(
                decoded_limb.recipient_share_material_seed(),
                &test_limbs[limb_ordinal].1
            );
        }
    }

    #[test]
    fn recipient_private_vss_payload_refuses_missing_extra_reordered_substituted_and_noncanonical_limbs()
     {
        let layout =
            SelectedRecipientVssPayloadLayout::derive().expect("selected recipient VSS layout");
        let mut test_limbs = test_limbs();
        let mut inputs = layout
            .ordered_sharing_limb_indices
            .iter()
            .copied()
            .zip(&test_limbs)
            .map(
                |(sharing_limb_index, (coefficients, material_seed))| RecipientShareLimbInput {
                    sharing_limb_index,
                    canonical_share_coefficients: coefficients,
                    recipient_share_material_seed: material_seed,
                },
            )
            .collect::<Vec<_>>();
        let extra_limb_ordinal = inputs.len() - 1;
        inputs.push(RecipientShareLimbInput {
            sharing_limb_index: layout.ordered_sharing_limb_indices[extra_limb_ordinal] + 1,
            canonical_share_coefficients: &test_limbs[extra_limb_ordinal].0,
            recipient_share_material_seed: &test_limbs[extra_limb_ordinal].1,
        });
        assert_recipient_private_vss_payload_error(
            canonical_recipient_private_vss_payload(0, &inputs),
            RecipientPrivateVssPayloadError::WrongTypeOrLength,
        );
        inputs.pop();

        inputs.swap(0, 1);
        assert_recipient_private_vss_payload_error(
            canonical_recipient_private_vss_payload(0, &inputs),
            RecipientPrivateVssPayloadError::WrongValue,
        );
        inputs.swap(0, 1);

        let first_expected_index = inputs[0].sharing_limb_index;
        inputs[0].sharing_limb_index = layout
            .ordered_sharing_limb_indices
            .last()
            .copied()
            .expect("selected sharing basis")
            + 1;
        assert_recipient_private_vss_payload_error(
            canonical_recipient_private_vss_payload(0, &inputs),
            RecipientPrivateVssPayloadError::WrongValue,
        );
        inputs[0].sharing_limb_index = first_expected_index;

        inputs.pop();
        assert_recipient_private_vss_payload_error(
            canonical_recipient_private_vss_payload(0, &inputs),
            RecipientPrivateVssPayloadError::WrongTypeOrLength,
        );

        test_limbs[0].0[POLYNOMIAL_DEGREE - 1] = layout.ordered_moduli[0];
        let invalid_residue_inputs = layout
            .ordered_sharing_limb_indices
            .iter()
            .copied()
            .zip(&test_limbs)
            .map(
                |(sharing_limb_index, (coefficients, material_seed))| RecipientShareLimbInput {
                    sharing_limb_index,
                    canonical_share_coefficients: coefficients,
                    recipient_share_material_seed: material_seed,
                },
            )
            .collect::<Vec<_>>();
        assert_recipient_private_vss_payload_error(
            canonical_recipient_private_vss_payload(0, &invalid_residue_inputs),
            RecipientPrivateVssPayloadError::WrongValue,
        );
    }

    #[test]
    fn recipient_private_vss_payload_refuses_noncanonical_and_truncated_bytes() {
        let layout =
            SelectedRecipientVssPayloadLayout::derive().expect("selected recipient VSS layout");
        let test_limbs = test_limbs();
        let inputs = layout
            .ordered_sharing_limb_indices
            .iter()
            .copied()
            .zip(&test_limbs)
            .map(
                |(sharing_limb_index, (coefficients, material_seed))| RecipientShareLimbInput {
                    sharing_limb_index,
                    canonical_share_coefficients: coefficients,
                    recipient_share_material_seed: material_seed,
                },
            )
            .collect::<Vec<_>>();
        let mut canonical_bytes =
            canonical_recipient_private_vss_payload(0, &inputs).expect("canonical payload");
        canonical_bytes.pop();
        assert_recipient_private_vss_payload_error(
            decode_recipient_private_vss_payload(&canonical_bytes),
            RecipientPrivateVssPayloadError::WrongTypeOrLength,
        );

        let mut canonical_bytes =
            canonical_recipient_private_vss_payload(0, &inputs).expect("canonical payload");
        canonical_bytes[2..4].copy_from_slice(&2_u16.to_le_bytes());
        assert_recipient_private_vss_payload_error(
            decode_recipient_private_vss_payload(&canonical_bytes),
            RecipientPrivateVssPayloadError::WrongSchema,
        );
    }
}
