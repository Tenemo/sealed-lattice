use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    hash_foundation_tuple_512,
};

use super::{
    ActivationChunkRange, ActivationContext, TallyActivationError, activation_chunk_ranges,
    compile_completion_tally,
};
use crate::protocol::action_key_set::{ActionKeySet, validate_complete_action_key_set_roster};
use crate::protocol::preparation_parent::{ActionSignatureCarrier, ActionSignaturePurpose};

const ACTIVATION_MANIFEST_SCHEMA_IDENTIFIER: u16 = 0x020a;
const ACTIVATION_MANIFEST_SCHEMA_VERSION: u16 = 1;
const ACTIVATION_MANIFEST_IDENTITY_DOMAIN: &str =
    "sealed-lattice/construction/activation-manifest/v1";
const ACTIVATION_CHUNK_IDENTITY_DOMAIN: &str = "sealed-lattice/construction/activation-chunk/v1";
const PARTICIPANT_COUNT: u16 = 10;
const MAXIMUM_CHUNK_BYTE_LENGTH: u32 = 480_000;
const INVENTORY_ENTRY_BYTE_LENGTH: usize = 4 + 4 + 1 + 4 + Hash512::BYTE_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivationChunkDescriptor {
    pub(crate) range: ActivationChunkRange,
    pub(crate) byte_length: u32,
    pub(crate) identity: Hash512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivationManifest {
    pub(crate) target_identity: Hash512,
    pub(crate) top_count: u16,
    pub(crate) source_submission_bitmap: u16,
    pub(crate) participant_position: u16,
    pub(crate) chunks: Vec<ActivationChunkDescriptor>,
}

impl ActivationManifest {
    pub(crate) fn new(
        context: &ActivationContext,
        participant_position: u16,
        chunks: Vec<ActivationChunkDescriptor>,
    ) -> Result<Self, TallyActivationError> {
        if participant_position >= PARTICIPANT_COUNT {
            return Err(TallyActivationError::InvalidParticipantPosition);
        }
        if context.source_submission_bitmap == 0
            || context.source_submission_bitmap >= (1 << PARTICIPANT_COUNT)
        {
            return Err(TallyActivationError::InvalidManifest);
        }
        let circuit = compile_completion_tally(context.top_count)?;
        let expected_ranges = activation_chunk_ranges(&circuit)?;
        if chunks.len() != expected_ranges.len()
            || chunks.iter().zip(expected_ranges).any(|(chunk, range)| {
                chunk.range != range
                    || chunk.byte_length == 0
                    || chunk.byte_length > MAXIMUM_CHUNK_BYTE_LENGTH
            })
        {
            return Err(TallyActivationError::InvalidManifest);
        }
        Ok(Self {
            target_identity: Hash512::from_bytes(context.target_identity),
            top_count: context.top_count,
            source_submission_bitmap: context.source_submission_bitmap,
            participant_position,
            chunks,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, TallyActivationError> {
        let inventory = self.encode_inventory()?;
        CanonicalTuple::new(
            ACTIVATION_MANIFEST_SCHEMA_IDENTIFIER,
            ACTIVATION_MANIFEST_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.target_identity.into_bytes()),
                CanonicalItem::unsigned16(self.top_count),
                CanonicalItem::unsigned16(self.source_submission_bitmap),
                CanonicalItem::unsigned16(self.participant_position),
                CanonicalItem::variable_bytes(inventory)
                    .map_err(|_| TallyActivationError::InvalidManifest)?,
            ],
        )
        .encode()
        .map_err(|_| TallyActivationError::InvalidManifest)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, TallyActivationError> {
        let tuple = CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default())
            .map_err(|_| TallyActivationError::InvalidManifest)?;
        if tuple.schema_identifier != ACTIVATION_MANIFEST_SCHEMA_IDENTIFIER
            || tuple.schema_version != ACTIVATION_MANIFEST_SCHEMA_VERSION
            || tuple.items.len() != 5
        {
            return Err(TallyActivationError::InvalidManifest);
        }
        let target_identity = read_hash512(&tuple.items[0])?;
        let top_count = read_unsigned16(&tuple.items[1])?;
        let source_submission_bitmap = read_unsigned16(&tuple.items[2])?;
        let participant_position = read_unsigned16(&tuple.items[3])?;
        let inventory = read_variable_bytes(&tuple.items[4])?;
        let chunks = decode_inventory(inventory)?;
        let corrections = core::array::from_fn(|position| {
            (source_submission_bitmap & (1_u16 << position) != 0)
                .then_some([0_u8; super::SOURCE_CORRECTION_BYTE_LENGTH])
        });
        let context = ActivationContext {
            target_identity: target_identity.into_bytes(),
            top_count,
            source_submission_bitmap,
            source_corrections: corrections,
        };
        let manifest = Self::new(&context, participant_position, chunks)?;
        if manifest.encode()?.as_slice() != bytes {
            return Err(TallyActivationError::InvalidManifest);
        }
        Ok(manifest)
    }

    pub(crate) fn body_identity(&self) -> Result<Hash512, TallyActivationError> {
        hash_foundation_tuple_512(
            ACTIVATION_MANIFEST_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.encode()?)
                .map_err(|_| TallyActivationError::InvalidManifest)?],
        )
        .map_err(|_| TallyActivationError::InvalidManifest)
    }

    fn encode_inventory(&self) -> Result<Vec<u8>, TallyActivationError> {
        let mut bytes = Vec::with_capacity(
            2 + self
                .chunks
                .len()
                .checked_mul(INVENTORY_ENTRY_BYTE_LENGTH)
                .ok_or(TallyActivationError::ArithmeticOverflow)?,
        );
        bytes.extend_from_slice(
            &u16::try_from(self.chunks.len())
                .map_err(|_| TallyActivationError::InvalidManifest)?
                .to_le_bytes(),
        );
        for chunk in &self.chunks {
            bytes.extend_from_slice(&chunk.range.first_operation.to_le_bytes());
            bytes.extend_from_slice(&chunk.range.operation_end.to_le_bytes());
            bytes.push(u8::from(chunk.range.includes_terminal_rekey));
            bytes.extend_from_slice(&chunk.byte_length.to_le_bytes());
            bytes.extend_from_slice(chunk.identity.as_bytes());
        }
        Ok(bytes)
    }
}

pub(crate) fn activation_chunk_identity(chunk: &[u8]) -> Result<Hash512, TallyActivationError> {
    hash_foundation_tuple_512(
        ACTIVATION_CHUNK_IDENTITY_DOMAIN,
        &[CanonicalItem::variable_bytes(chunk)
            .map_err(|_| TallyActivationError::InvalidManifest)?],
    )
    .map_err(|_| TallyActivationError::InvalidManifest)
}

pub(crate) fn encode_activation_signature_carrier(
    participant_position: u16,
    body_identity: Hash512,
    signature: &[u8],
) -> Result<Vec<u8>, TallyActivationError> {
    ActionSignatureCarrier::new(
        PARTICIPANT_COUNT,
        participant_position,
        ActionSignaturePurpose::Activation,
        body_identity,
        signature,
    )
    .map_err(|_| TallyActivationError::InvalidSignature)?
    .encode()
    .map_err(|_| TallyActivationError::InvalidSignature)
}

pub(crate) fn verify_activation_manifest(
    action_key_sets: &[ActionKeySet],
    body_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<ActivationManifest, TallyActivationError> {
    validate_complete_action_key_set_roster(action_key_sets)
        .map_err(|_| TallyActivationError::InvalidSignature)?;
    let manifest = ActivationManifest::decode(body_bytes)?;
    let body_identity = manifest.body_identity()?;
    let carrier = ActionSignatureCarrier::decode(PARTICIPANT_COUNT, signature_bytes)
        .map_err(|_| TallyActivationError::InvalidSignature)?;
    let verification_key = action_key_sets
        .get(usize::from(manifest.participant_position))
        .and_then(|key_set| {
            key_set
                .action_signature_verification_key(ActionSignaturePurpose::Activation.key_index())
        })
        .ok_or(TallyActivationError::InvalidSignature)?;
    carrier
        .verify(
            manifest.participant_position,
            ActionSignaturePurpose::Activation,
            body_identity,
            verification_key,
        )
        .map_err(|_| TallyActivationError::InvalidSignature)?;
    Ok(manifest)
}

fn decode_inventory(bytes: &[u8]) -> Result<Vec<ActivationChunkDescriptor>, TallyActivationError> {
    if bytes.len() < 2 {
        return Err(TallyActivationError::InvalidManifest);
    }
    let count = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    if bytes.len() != 2 + count * INVENTORY_ENTRY_BYTE_LENGTH {
        return Err(TallyActivationError::InvalidManifest);
    }
    bytes[2..]
        .chunks_exact(INVENTORY_ENTRY_BYTE_LENGTH)
        .map(|entry| {
            let flag = entry[8];
            if flag > 1 {
                return Err(TallyActivationError::InvalidManifest);
            }
            Ok(ActivationChunkDescriptor {
                range: ActivationChunkRange {
                    first_operation: u32::from_le_bytes(
                        entry[..4]
                            .try_into()
                            .map_err(|_| TallyActivationError::InvalidManifest)?,
                    ),
                    operation_end: u32::from_le_bytes(
                        entry[4..8]
                            .try_into()
                            .map_err(|_| TallyActivationError::InvalidManifest)?,
                    ),
                    includes_terminal_rekey: flag == 1,
                },
                byte_length: u32::from_le_bytes(
                    entry[9..13]
                        .try_into()
                        .map_err(|_| TallyActivationError::InvalidManifest)?,
                ),
                identity: Hash512::from_bytes(
                    entry[13..]
                        .try_into()
                        .map_err(|_| TallyActivationError::InvalidManifest)?,
                ),
            })
        })
        .collect()
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, TallyActivationError> {
    if item.item_type() != CanonicalItemType::Unsigned16 || item.canonical_bytes().len() != 2 {
        return Err(TallyActivationError::InvalidManifest);
    }
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| TallyActivationError::InvalidManifest)?,
    ))
}

fn read_hash512(item: &CanonicalItem) -> Result<Hash512, TallyActivationError> {
    if item.item_type() != CanonicalItemType::Hash512
        || item.canonical_bytes().len() != Hash512::BYTE_LENGTH
    {
        return Err(TallyActivationError::InvalidManifest);
    }
    Ok(Hash512::from_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| TallyActivationError::InvalidManifest)?,
    ))
}

fn read_variable_bytes(item: &CanonicalItem) -> Result<&[u8], TallyActivationError> {
    if item.item_type() != CanonicalItemType::RawBytes || item.canonical_bytes().len() < 4 {
        return Err(TallyActivationError::InvalidManifest);
    }
    let payload_length = usize::try_from(u32::from_le_bytes(
        item.canonical_bytes()[..4]
            .try_into()
            .map_err(|_| TallyActivationError::InvalidManifest)?,
    ))
    .map_err(|_| TallyActivationError::InvalidManifest)?;
    if payload_length != item.canonical_bytes().len() - 4 {
        return Err(TallyActivationError::InvalidManifest);
    }
    Ok(&item.canonical_bytes()[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trip_binds_every_chunk_identity_and_length() {
        let corrections = [Some([0_u8; super::super::SOURCE_CORRECTION_BYTE_LENGTH]); 10];
        let context = ActivationContext::new([0x42; 64], 10, 0x03ff, corrections).expect("context");
        let circuit = compile_completion_tally(10).expect("circuit");
        let chunks = activation_chunk_ranges(&circuit)
            .expect("ranges")
            .into_iter()
            .enumerate()
            .map(|(index, range)| ActivationChunkDescriptor {
                range,
                byte_length: 1000 + index as u32,
                identity: Hash512::from_bytes([index as u8; 64]),
            })
            .collect();
        let manifest = ActivationManifest::new(&context, 4, chunks).expect("manifest");
        let encoded = manifest.encode().expect("encode");
        assert_eq!(ActivationManifest::decode(&encoded), Ok(manifest.clone()));
        let original_identity = manifest.body_identity().expect("identity");
        let mut mutation = encoded;
        *mutation.last_mut().expect("byte") ^= 1;
        let mutated = ActivationManifest::decode(&mutation).expect("mutation remains canonical");
        assert_ne!(
            mutated.body_identity().expect("identity"),
            original_identity
        );
    }
}
