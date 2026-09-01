use super::{BinaryReader, BinaryWriter, CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::Hash512;
use crate::protocol::action_key_set::{
    ACTION_KEY_SET_NONCE_BYTE_LENGTH, ACTION_SIGNATURE_PURPOSE_COUNT, ActionKeySet,
    action_key_set_roster_identity,
};
use crate::protocol::action_signature::{
    KEY_BYTE_LENGTH as ACTION_SIGNATURE_KEY_BYTE_LENGTH, MESSAGE_BYTE_LENGTH,
    derive_verification_key_fragment, sign_fragment, verify_fragment,
};
use crate::protocol::pair_encryption::{
    ENCRYPTION_KEY_BYTE_LENGTH as PAIR_ENCRYPTION_KEY_BYTE_LENGTH, decrypt, encrypt,
    generate_key_pair,
};
use crate::protocol::preparation_parent::{
    ACTION_SIGNATURE_CARRIER_BYTE_LENGTH, ActionSignatureCarrier, ActionSignaturePurpose,
    PreparationParent, SUBSET_COMMITMENT_BYTE_LENGTH, SUBSET_COMMITMENT_COUNT,
    verify_private_preparation_carrier,
};
use crate::protocol::preparation_plaintext::{
    AFFINE_COEFFICIENT_BYTE_LENGTH, CONTRIBUTION_OPENING_BYTE_LENGTH,
    PREPARATION_PLAINTEXT_BYTE_LENGTH, PreparationMaterialContext, generate_preparation_material,
    verify_preparation_plaintext,
};
use crate::protocol::private_preparation_body::{
    PrivatePreparationBody, PrivatePreparationContext,
};
use crate::protocol::source::{
    SOURCE_ORDINAL, SourceBody, SourceContext, SourceDeclaration, decode_held_subset_keys,
    derive_honest_source_correction, encode_held_subset_keys, verify_complete_preparation,
    verify_source_carrier,
};
use zeroize::{Zeroize, Zeroizing};

const DERIVE_ACTION_SIGNATURE_VERIFICATION_KEY_FRAGMENT: u8 = 1;
const SIGN_ACTION_BODY_IDENTITY_FRAGMENT: u8 = 2;
const VERIFY_ACTION_SIGNATURE_FRAGMENT: u8 = 3;
const GENERATE_PAIR_ENCRYPTION_KEY: u8 = 4;
const ENCRYPT_PAIR_MESSAGE: u8 = 5;
const DECRYPT_PAIR_MESSAGE: u8 = 6;
const ENCODE_ACTION_KEY_SET: u8 = 7;
const VERIFY_ACTION_KEY_SET: u8 = 8;
const VERIFY_ACTION_KEY_SET_ROSTER: u8 = 9;
const SEAL_PRIVATE_PREPARATION_BODY: u8 = 10;
const OPEN_PRIVATE_PREPARATION_BODY: u8 = 11;
const ENCODE_PREPARATION_PARENT: u8 = 12;
const ENCODE_PREPARATION_SIGNATURE_CARRIER: u8 = 13;
const VERIFY_PRIVATE_PREPARATION_CARRIER: u8 = 14;
const GENERATE_PREPARATION_MATERIAL: u8 = 15;
const VERIFY_PREPARATION_PLAINTEXT: u8 = 16;
const RESOLVE_PAIR_ENCRYPTION_KEY: u8 = 17;
const VERIFY_COMPLETE_PREPARATION: u8 = 18;
const DERIVE_HONEST_SOURCE_CORRECTION: u8 = 19;
const ENCODE_SOURCE_BODY: u8 = 20;
const ENCODE_SOURCE_SIGNATURE_CARRIER: u8 = 21;
const VERIFY_SOURCE_CARRIER: u8 = 22;

pub(super) fn run(input: &[u8]) -> CanonicalResult<Vec<u8>> {
    let mut reader = BinaryReader::new(input);
    let payload = match reader.read_u8()? {
        DERIVE_ACTION_SIGNATURE_VERIFICATION_KEY_FRAGMENT => derive_verification_key(&mut reader),
        SIGN_ACTION_BODY_IDENTITY_FRAGMENT => sign(&mut reader),
        VERIFY_ACTION_SIGNATURE_FRAGMENT => verify(&mut reader),
        GENERATE_PAIR_ENCRYPTION_KEY => generate_pair_encryption_key(&mut reader),
        ENCRYPT_PAIR_MESSAGE => encrypt_pair_message(&mut reader),
        DECRYPT_PAIR_MESSAGE => decrypt_pair_message(&mut reader),
        ENCODE_ACTION_KEY_SET => encode_action_key_set(&mut reader),
        VERIFY_ACTION_KEY_SET => verify_action_key_set(&mut reader),
        VERIFY_ACTION_KEY_SET_ROSTER => verify_action_key_set_roster(&mut reader),
        SEAL_PRIVATE_PREPARATION_BODY => seal_private_preparation_body(&mut reader),
        OPEN_PRIVATE_PREPARATION_BODY => open_private_preparation_body(&mut reader),
        ENCODE_PREPARATION_PARENT => encode_preparation_parent(&mut reader),
        ENCODE_PREPARATION_SIGNATURE_CARRIER => encode_preparation_signature_carrier(&mut reader),
        VERIFY_PRIVATE_PREPARATION_CARRIER => verify_private_preparation(&mut reader),
        GENERATE_PREPARATION_MATERIAL => generate_preparation(&mut reader),
        VERIFY_PREPARATION_PLAINTEXT => verify_preparation_plaintext_command(&mut reader),
        RESOLVE_PAIR_ENCRYPTION_KEY => resolve_pair_encryption_key(&mut reader),
        VERIFY_COMPLETE_PREPARATION => verify_complete_preparation_command(&mut reader),
        DERIVE_HONEST_SOURCE_CORRECTION => derive_source_correction_command(&mut reader),
        ENCODE_SOURCE_BODY => encode_source_body(&mut reader),
        ENCODE_SOURCE_SIGNATURE_CARRIER => encode_source_signature_carrier(&mut reader),
        VERIFY_SOURCE_CARRIER => verify_source(&mut reader),
        command => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            format!("unsupported construction command: {command}"),
        )),
    }?;
    reader.finish()?;
    Ok(payload)
}

fn verify_complete_preparation_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let action_proposal_identity = read_hash512(reader)?;
    let action_key_set_roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let local_position = reader.read_u16()?;
    let action_key_sets = (0..participant_count)
        .map(|_| {
            ActionKeySet::decode(participant_count, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut parent_bodies = Vec::with_capacity(usize::from(participant_count));
    let mut parent_signatures = Vec::with_capacity(usize::from(participant_count));
    for _ in 0..participant_count {
        parent_bodies.push(reader.read_bytes()?.to_vec());
        parent_signatures.push(reader.read_bytes()?.to_vec());
    }
    let own_opening_bytes = reader.read_bytes()?;
    let own_affine_coefficient_bytes = reader.read_bytes()?;
    let remote_plaintext_bytes = Zeroizing::new(
        (0..participant_count.saturating_sub(1))
            .map(|_| Ok(reader.read_bytes()?.to_vec()))
            .collect::<CanonicalResult<Vec<_>>>()?,
    );
    let context = PreparationMaterialContext {
        action_proposal_identity,
        action_key_set_roster_identity,
        preparation_attempt,
        predecessor_identity,
        sender_position: local_position,
    };
    let verified = verify_complete_preparation(
        &context,
        local_position,
        &action_key_sets,
        &parent_bodies,
        &parent_signatures,
        own_opening_bytes,
        own_affine_coefficient_bytes,
        &remote_plaintext_bytes,
    )
    .map_err(construction_error)?;
    let mut held_subset_key_bytes =
        encode_held_subset_keys(local_position, &verified.held_subset_keys)
            .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_fixed(verified.root.as_bytes())?;
    for parent_identity in &verified.parent_identities {
        response.write_fixed(parent_identity.as_bytes())?;
    }
    response.write_bytes(&held_subset_key_bytes)?;
    held_subset_key_bytes.zeroize();
    Ok(response.into_bytes())
}

fn derive_source_correction_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let source_position = reader.read_u16()?;
    let input_bit = reader.read_u8()?;
    let held_subset_keys = decode_held_subset_keys(source_position, reader.read_bytes()?)
        .map_err(construction_error)?;
    let correction = derive_honest_source_correction(source_position, input_bit, &held_subset_keys)
        .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_u8(correction)?;
    Ok(response.into_bytes())
}

fn encode_source_body(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let action_proposal_identity = read_hash512(reader)?;
    let action_key_set_roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let verified_preparation_root = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let declaration = match reader.read_u16()? {
        1 => SourceDeclaration::Abstain,
        2 => SourceDeclaration::Submit,
        value => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidEnum,
                format!("unsupported source declaration: {value}"),
            ));
        }
    };
    let correction_bytes = reader.read_bytes()?;
    let correction = match declaration {
        SourceDeclaration::Abstain if correction_bytes.is_empty() => None,
        SourceDeclaration::Submit if correction_bytes.len() == 1 => Some(correction_bytes[0]),
        _ => return Err(malformed_construction_length()),
    };
    let body = SourceBody::new(
        SourceContext {
            participant_count,
            action_proposal_identity,
            action_key_set_roster_identity,
            preparation_attempt,
            predecessor_identity,
            verified_preparation_root,
            sender_position,
            source_ordinal: SOURCE_ORDINAL,
        },
        declaration,
        correction,
    )
    .map_err(construction_error)?;
    let encoded = body.encode().map_err(construction_error)?;
    let identity = body.body_identity().map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&encoded)?;
    response.write_fixed(identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn encode_source_signature_carrier(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let signer_position = reader.read_u16()?;
    let body_identity = read_hash512(reader)?;
    let carrier = ActionSignatureCarrier::new(
        participant_count,
        signer_position,
        ActionSignaturePurpose::Source,
        body_identity,
        reader.read_bytes()?,
    )
    .map_err(construction_error)?;
    bytes_response(&carrier.encode().map_err(construction_error)?)
}

fn verify_source(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let expected_context = SourceContext {
        participant_count,
        action_proposal_identity: read_hash512(reader)?,
        action_key_set_roster_identity: read_hash512(reader)?,
        preparation_attempt: reader.read_u16()?,
        predecessor_identity: read_hash512(reader)?,
        verified_preparation_root: read_hash512(reader)?,
        sender_position: reader.read_u16()?,
        source_ordinal: SOURCE_ORDINAL,
    };
    let expected_declaration = match reader.read_u16()? {
        1 => SourceDeclaration::Abstain,
        2 => SourceDeclaration::Submit,
        value => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidEnum,
                format!("unsupported source declaration: {value}"),
            ));
        }
    };
    let action_key_sets = (0..participant_count)
        .map(|_| {
            ActionKeySet::decode(participant_count, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let verified = verify_source_carrier(
        expected_context,
        Some(expected_declaration),
        &action_key_sets,
        reader.read_bytes()?,
        reader.read_bytes()?,
    )
    .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_u16(verified.sender_position)?;
    response.write_u16(verified.declaration as u16)?;
    response.write_u8(verified.correction.unwrap_or(0xff))?;
    response.write_fixed(verified.body_identity.as_bytes())?;
    response.write_fixed(verified.verified_preparation_root.as_bytes())?;
    Ok(response.into_bytes())
}

fn resolve_pair_encryption_key(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let expected_proposal_identity = read_hash512(reader)?;
    let expected_roster_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let recipient_position = reader.read_u16()?;
    let action_key_sets = (0..participant_count)
        .map(|_| {
            ActionKeySet::decode(participant_count, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    if action_key_sets
        .first()
        .is_none_or(|key_set| key_set.proposal_identity() != expected_proposal_identity)
        || action_key_set_roster_identity(&action_key_sets).map_err(construction_error)?
            != expected_roster_identity
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "action key roster does not match the expected context",
        ));
    }
    let recipient_key_set = action_key_sets
        .get(usize::from(recipient_position))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "recipient position is outside the action key roster",
            )
        })?;
    let encryption_key = recipient_key_set
        .pair_encryption_key_for_sender(sender_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "sender and recipient do not identify a pair key",
            )
        })?;
    Ok(encryption_key.to_vec())
}

fn generate_preparation(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let action_proposal_identity = read_hash512(reader)?;
    let action_key_set_roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let opening_bytes = reader.read_bytes()?;
    if opening_bytes.len() != SUBSET_COMMITMENT_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH {
        return Err(malformed_construction_length());
    }
    let affine_coefficient_bytes = reader.read_bytes()?;
    if affine_coefficient_bytes.len() != AFFINE_COEFFICIENT_BYTE_LENGTH {
        return Err(malformed_construction_length());
    }
    let context = PreparationMaterialContext {
        action_proposal_identity,
        action_key_set_roster_identity,
        preparation_attempt,
        predecessor_identity,
        sender_position,
    };
    let material = generate_preparation_material(&context, opening_bytes, affine_coefficient_bytes)
        .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    for commitment in material.subset_commitments {
        response.write_fixed(&commitment)?;
    }
    for plaintext in material.recipient_plaintexts {
        if plaintext.len() != PREPARATION_PLAINTEXT_BYTE_LENGTH {
            return Err(malformed_construction_length());
        }
        response.write_bytes(&plaintext)?;
    }
    Ok(response.into_bytes())
}

fn verify_preparation_plaintext_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let expected_action_proposal_identity = read_hash512(reader)?;
    let expected_action_key_set_roster_identity = read_hash512(reader)?;
    let expected_preparation_attempt = reader.read_u16()?;
    let expected_predecessor_identity = read_hash512(reader)?;
    let expected_sender_position = reader.read_u16()?;
    let recipient_position = reader.read_u16()?;
    let parent = PreparationParent::decode(participant_count, reader.read_bytes()?)
        .map_err(construction_error)?;
    let context = PreparationMaterialContext {
        action_proposal_identity: expected_action_proposal_identity,
        action_key_set_roster_identity: expected_action_key_set_roster_identity,
        preparation_attempt: expected_preparation_attempt,
        predecessor_identity: expected_predecessor_identity,
        sender_position: expected_sender_position,
    };
    let identity =
        verify_preparation_plaintext(&parent, &context, recipient_position, reader.read_bytes()?)
            .map_err(construction_error)?;
    Ok(identity.into_bytes().to_vec())
}

fn encode_preparation_parent(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let action_proposal_identity = read_hash512(reader)?;
    let action_key_set_roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let subset_commitment_bytes = reader.read_bytes()?;
    if subset_commitment_bytes.len() != SUBSET_COMMITMENT_COUNT * SUBSET_COMMITMENT_BYTE_LENGTH {
        return Err(malformed_construction_length());
    }
    let subset_commitments = subset_commitment_bytes
        .chunks_exact(SUBSET_COMMITMENT_BYTE_LENGTH)
        .map(read_exact_array)
        .collect::<CanonicalResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| malformed_construction_length())?;
    let private_body_identity_bytes = reader.read_bytes()?;
    let expected_identity_count = participant_count
        .checked_sub(1)
        .ok_or_else(malformed_construction_length)?;
    if private_body_identity_bytes.len()
        != usize::from(expected_identity_count) * Hash512::BYTE_LENGTH
    {
        return Err(malformed_construction_length());
    }
    let private_body_identities = private_body_identity_bytes
        .chunks_exact(Hash512::BYTE_LENGTH)
        .map(|bytes| {
            Ok(Hash512::from_bytes(read_exact_array::<
                { Hash512::BYTE_LENGTH },
            >(bytes)?))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let parent = PreparationParent::new(
        participant_count,
        action_proposal_identity,
        action_key_set_roster_identity,
        preparation_attempt,
        predecessor_identity,
        sender_position,
        subset_commitments,
        private_body_identities,
    )
    .map_err(construction_error)?;
    let body = parent.encode().map_err(construction_error)?;
    let identity = parent.body_identity().map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&body)?;
    response.write_fixed(identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn encode_preparation_signature_carrier(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let signer_position = reader.read_u16()?;
    let body_identity = read_hash512(reader)?;
    let carrier = ActionSignatureCarrier::new(
        participant_count,
        signer_position,
        ActionSignaturePurpose::Preparation,
        body_identity,
        reader.read_bytes()?,
    )
    .map_err(construction_error)?;
    let encoded = carrier.encode().map_err(construction_error)?;
    if encoded.len() != ACTION_SIGNATURE_CARRIER_BYTE_LENGTH {
        return Err(malformed_construction_length());
    }
    bytes_response(&encoded)
}

fn verify_private_preparation(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let expected_action_proposal_identity = read_hash512(reader)?;
    let expected_action_key_set_roster_identity = read_hash512(reader)?;
    let expected_preparation_attempt = reader.read_u16()?;
    let expected_predecessor_identity = read_hash512(reader)?;
    let recipient_position = reader.read_u16()?;
    let action_key_sets = (0..participant_count)
        .map(|_| {
            ActionKeySet::decode(participant_count, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let verified = verify_private_preparation_carrier(
        participant_count,
        expected_action_proposal_identity,
        expected_action_key_set_roster_identity,
        expected_preparation_attempt,
        expected_predecessor_identity,
        recipient_position,
        &action_key_sets,
        reader.read_bytes()?,
        reader.read_bytes()?,
        reader.read_bytes()?,
    )
    .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_u16(verified.sender_position)?;
    response.write_u16(verified.recipient_position)?;
    response.write_fixed(verified.parent_identity.as_bytes())?;
    response.write_fixed(verified.body_identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn seal_private_preparation_body(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let action_proposal_identity = read_hash512(reader)?;
    let action_key_set_roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let recipient_position = reader.read_u16()?;
    let pair_encryption_key = reader.read_bytes()?;
    let context = PrivatePreparationContext::new(
        participant_count,
        action_proposal_identity,
        action_key_set_roster_identity,
        preparation_attempt,
        predecessor_identity,
        sender_position,
        recipient_position,
        pair_encryption_key,
    )
    .map_err(construction_error)?;
    let body = PrivatePreparationBody::seal(
        context,
        pair_encryption_key,
        reader.read_bytes()?,
        reader.read_bytes()?,
        reader.read_bytes()?,
    )
    .map_err(construction_error)?;
    let encoded = body.encode().map_err(construction_error)?;
    let identity = body.body_identity().map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&encoded)?;
    response.write_fixed(identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn open_private_preparation_body(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let action_proposal_identity = read_hash512(reader)?;
    let action_key_set_roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let recipient_position = reader.read_u16()?;
    let pair_encryption_key = reader.read_bytes()?;
    let context = PrivatePreparationContext::new(
        participant_count,
        action_proposal_identity,
        action_key_set_roster_identity,
        preparation_attempt,
        predecessor_identity,
        sender_position,
        recipient_position,
        pair_encryption_key,
    )
    .map_err(construction_error)?;
    let pair_decryption_key = reader.read_bytes()?;
    let body = PrivatePreparationBody::decode(participant_count, reader.read_bytes()?)
        .map_err(construction_error)?;
    let mut plaintext = body
        .open(context, pair_decryption_key)
        .map_err(construction_error)?;
    let response = bytes_response(&plaintext);
    plaintext.zeroize();
    response
}

fn encode_action_key_set(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let proposal_identity = read_hash512(reader)?;
    let roster_position = reader.read_u16()?;
    let nonce = read_exact_array::<ACTION_KEY_SET_NONCE_BYTE_LENGTH>(reader.read_bytes()?)?;
    let signature_key_bytes = reader.read_bytes()?;
    let expected_signature_key_bytes = ACTION_SIGNATURE_PURPOSE_COUNT
        .checked_mul(ACTION_SIGNATURE_KEY_BYTE_LENGTH)
        .ok_or_else(malformed_construction_length)?;
    if signature_key_bytes.len() != expected_signature_key_bytes {
        return Err(malformed_construction_length());
    }
    let signature_keys = signature_key_bytes
        .chunks_exact(ACTION_SIGNATURE_KEY_BYTE_LENGTH)
        .map(read_exact_array)
        .collect::<CanonicalResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| malformed_construction_length())?;
    let pair_key_bytes = reader.read_bytes()?;
    let pair_key_count = participant_count
        .checked_sub(1)
        .ok_or_else(malformed_construction_length)?;
    let expected_pair_key_bytes = usize::from(pair_key_count)
        .checked_mul(PAIR_ENCRYPTION_KEY_BYTE_LENGTH)
        .ok_or_else(malformed_construction_length)?;
    if pair_key_bytes.len() != expected_pair_key_bytes {
        return Err(malformed_construction_length());
    }
    let pair_keys = pair_key_bytes
        .chunks_exact(PAIR_ENCRYPTION_KEY_BYTE_LENGTH)
        .map(read_exact_array)
        .collect::<CanonicalResult<Vec<_>>>()?;
    let action_key_set = ActionKeySet::new(
        participant_count,
        proposal_identity,
        roster_position,
        nonce,
        signature_keys,
        pair_keys,
    )
    .map_err(construction_error)?;
    let body = action_key_set.encode().map_err(construction_error)?;
    let identity = action_key_set.body_identity().map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&body)?;
    response.write_fixed(identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn verify_action_key_set(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let expected_proposal_identity = read_hash512(reader)?;
    let expected_roster_position = reader.read_u16()?;
    let action_key_set = ActionKeySet::decode(participant_count, reader.read_bytes()?)
        .map_err(construction_error)?;
    if action_key_set.proposal_identity() != expected_proposal_identity
        || action_key_set.roster_position() != expected_roster_position
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "action key set does not match the expected proposal and position",
        ));
    }
    Ok(action_key_set
        .body_identity()
        .map_err(construction_error)?
        .into_bytes()
        .to_vec())
}

fn verify_action_key_set_roster(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let action_key_sets = (0..participant_count)
        .map(|_| {
            ActionKeySet::decode(participant_count, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    Ok(action_key_set_roster_identity(&action_key_sets)
        .map_err(construction_error)?
        .into_bytes()
        .to_vec())
}

fn read_hash512(reader: &mut BinaryReader<'_>) -> CanonicalResult<Hash512> {
    Ok(Hash512::from_bytes(read_exact_array(
        reader.read_exact(Hash512::BYTE_LENGTH)?,
    )?))
}

fn read_exact_array<const BYTE_LENGTH: usize>(bytes: &[u8]) -> CanonicalResult<[u8; BYTE_LENGTH]> {
    bytes
        .try_into()
        .map_err(|_| malformed_construction_length())
}

fn malformed_construction_length() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::MalformedLength,
        "construction command field has the wrong length",
    )
}

fn generate_pair_encryption_key(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let mut key_pair = generate_key_pair(reader.read_bytes()?).map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&key_pair.encryption_key)?;
    response.write_bytes(&key_pair.decryption_key)?;
    key_pair.zeroize();
    Ok(response.into_bytes())
}

fn encrypt_pair_message(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let encryption_key = reader.read_bytes()?;
    let message = reader.read_bytes()?;
    let randomness = reader.read_bytes()?;
    bytes_response(&encrypt(encryption_key, message, randomness).map_err(construction_error)?)
}

fn decrypt_pair_message(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let decryption_key = reader.read_bytes()?;
    let ciphertext = reader.read_bytes()?;
    bytes_response(&decrypt(decryption_key, ciphertext).map_err(construction_error)?)
}

fn derive_verification_key(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let first_chain = usize::from(reader.read_u16()?);
    let fragment = derive_verification_key_fragment(first_chain, reader.read_bytes()?)
        .map_err(action_signature_error)?;
    bytes_response(&fragment)
}

fn sign(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let first_chain = usize::from(reader.read_u16()?);
    let message = read_message(reader)?;
    let fragment = sign_fragment(first_chain, reader.read_bytes()?, &message)
        .map_err(action_signature_error)?;
    bytes_response(&fragment)
}

fn verify(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let first_chain = usize::from(reader.read_u16()?);
    let message = read_message(reader)?;
    let signature_fragment = reader.read_bytes()?;
    let verification_key_fragment = reader.read_bytes()?;
    let is_valid = verify_fragment(
        first_chain,
        signature_fragment,
        verification_key_fragment,
        &message,
    )
    .map_err(action_signature_error)?;
    let mut response = BinaryWriter::new();
    response.write_u8(u8::from(is_valid))?;
    Ok(response.into_bytes())
}

fn read_message(reader: &mut BinaryReader<'_>) -> CanonicalResult<[u8; MESSAGE_BYTE_LENGTH]> {
    reader
        .read_exact(MESSAGE_BYTE_LENGTH)?
        .try_into()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "action body identity must contain 64 bytes",
            )
        })
}

fn bytes_response(bytes: &[u8]) -> CanonicalResult<Vec<u8>> {
    let mut response = BinaryWriter::new();
    response.write_bytes(bytes)?;
    Ok(response.into_bytes())
}

fn construction_error(error: impl core::fmt::Display) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, error.to_string())
}

fn action_signature_error(error: impl core::fmt::Display) -> CanonicalError {
    construction_error(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::run_construction_command;

    #[test]
    fn command_refuses_oversized_fragments_and_trailing_bytes() {
        let mut oversized = vec![DERIVE_ACTION_SIGNATURE_VERIFICATION_KEY_FRAGMENT];
        oversized.extend_from_slice(&0_u16.to_le_bytes());
        let length = 18_u32 * 48;
        oversized.extend_from_slice(&length.to_le_bytes());
        oversized.extend_from_slice(&vec![0_u8; length as usize]);
        assert_eq!(run_construction_command(&oversized)[0], 1);

        let mut trailing = vec![DERIVE_ACTION_SIGNATURE_VERIFICATION_KEY_FRAGMENT];
        trailing.extend_from_slice(&0_u16.to_le_bytes());
        trailing.extend_from_slice(&48_u32.to_le_bytes());
        trailing.extend_from_slice(&[0_u8; 48]);
        trailing.push(0);
        assert_eq!(run_construction_command(&trailing)[0], 1);
    }
}
