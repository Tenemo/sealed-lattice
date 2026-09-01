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
use crate::protocol::finality::{
    FinalityDerivationContext, FinalityTarget, derive_finality_target,
    encode_finality_signature_carrier, verify_finality_certificate, verify_finality_signature,
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
    SOURCE_CORRECTION_BYTE_LENGTH,
    SOURCE_CORRECTION_BYTE_LENGTH as TALLY_SOURCE_CORRECTION_BYTE_LENGTH, SOURCE_ORDINAL,
    SourceBody, SourceContext, SourceDeclaration, decode_held_affine_evaluations,
    decode_held_subset_keys, derive_honest_source_correction, encode_held_affine_evaluations,
    encode_held_subset_keys, verify_complete_preparation, verify_source_carrier,
};
use crate::protocol::tally_activation::{
    ActivationChunkDescriptor, ActivationChunkRange, ActivationContext, ActivationEvaluator,
    ActivationManifest, LocalActivationMaterial, VerifiedTallyTerminal, activation_chunk_identity,
    activation_chunk_ranges, compile_completion_tally, encode_activation_signature_carrier,
    generate_activation_chunk, verify_activation_manifest,
};
use crate::tally_circuit::BooleanOperation;
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
const DERIVE_FINALITY_TARGET: u8 = 23;
const ENCODE_FINALITY_SIGNATURE_CARRIER: u8 = 24;
const VERIFY_FINALITY_CERTIFICATE: u8 = 25;
const VERIFY_FINALITY_SIGNATURE: u8 = 26;
const PLAN_TALLY_ACTIVATION: u8 = 27;
const GENERATE_TALLY_ACTIVATION_CHUNK: u8 = 28;
const ADVANCE_TALLY_ACTIVATION: u8 = 29;
const IDENTIFY_TALLY_ACTIVATION_CHUNK: u8 = 30;
const ENCODE_TALLY_ACTIVATION_MANIFEST: u8 = 31;
const ENCODE_TALLY_ACTIVATION_SIGNATURE_CARRIER: u8 = 32;
const VERIFY_TALLY_ACTIVATION_MANIFEST: u8 = 33;

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
        DERIVE_FINALITY_TARGET => derive_finality_target_command(&mut reader),
        ENCODE_FINALITY_SIGNATURE_CARRIER => encode_finality_signature_carrier_command(&mut reader),
        VERIFY_FINALITY_CERTIFICATE => verify_finality_certificate_command(&mut reader),
        VERIFY_FINALITY_SIGNATURE => verify_finality_signature_command(&mut reader),
        PLAN_TALLY_ACTIVATION => plan_tally_activation(&mut reader),
        GENERATE_TALLY_ACTIVATION_CHUNK => generate_tally_activation_chunk(&mut reader),
        ADVANCE_TALLY_ACTIVATION => advance_tally_activation(&mut reader),
        IDENTIFY_TALLY_ACTIVATION_CHUNK => identify_tally_activation_chunk(&mut reader),
        ENCODE_TALLY_ACTIVATION_MANIFEST => encode_tally_activation_manifest(&mut reader),
        ENCODE_TALLY_ACTIVATION_SIGNATURE_CARRIER => {
            encode_tally_activation_signature_carrier(&mut reader)
        }
        VERIFY_TALLY_ACTIVATION_MANIFEST => verify_tally_activation_manifest(&mut reader),
        command => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            format!("unsupported construction command: {command}"),
        )),
    }?;
    reader.finish()?;
    Ok(payload)
}

fn read_activation_chunk_descriptor(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<ActivationChunkDescriptor> {
    Ok(ActivationChunkDescriptor {
        range: read_activation_range(reader)?,
        byte_length: reader.read_u32()?,
        identity: read_hash512(reader)?,
    })
}

fn write_activation_chunk_descriptor(
    response: &mut BinaryWriter,
    descriptor: &ActivationChunkDescriptor,
) -> CanonicalResult<()> {
    response.write_u32(descriptor.range.first_operation)?;
    response.write_u32(descriptor.range.operation_end)?;
    response.write_u8(u8::from(descriptor.range.includes_terminal_rekey))?;
    response.write_u32(descriptor.byte_length)?;
    response.write_fixed(descriptor.identity.as_bytes())
}

fn identify_tally_activation_chunk(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let identity = activation_chunk_identity(reader.read_bytes()?).map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_fixed(identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn encode_tally_activation_manifest(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let context = read_activation_context(reader)?;
    let participant_position = reader.read_u16()?;
    let chunk_count = reader.read_u16()?;
    let chunks = (0..chunk_count)
        .map(|_| read_activation_chunk_descriptor(reader))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let manifest = ActivationManifest::new(&context, participant_position, chunks)
        .map_err(construction_error)?;
    let body = manifest.encode().map_err(construction_error)?;
    let identity = manifest.body_identity().map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&body)?;
    response.write_fixed(identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn encode_tally_activation_signature_carrier(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let participant_position = reader.read_u16()?;
    let body_identity = read_hash512(reader)?;
    bytes_response(
        &encode_activation_signature_carrier(
            participant_position,
            body_identity,
            reader.read_bytes()?,
        )
        .map_err(construction_error)?,
    )
}

fn verify_tally_activation_manifest(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let action_key_sets = (0..10)
        .map(|_| ActionKeySet::decode(10, reader.read_bytes()?).map_err(construction_error))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let manifest =
        verify_activation_manifest(&action_key_sets, reader.read_bytes()?, reader.read_bytes()?)
            .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_fixed(manifest.target_identity.as_bytes())?;
    response.write_u16(manifest.top_count)?;
    response.write_u16(manifest.source_submission_bitmap)?;
    response.write_u16(manifest.participant_position)?;
    response.write_u16(
        u16::try_from(manifest.chunks.len()).map_err(|_| malformed_construction_length())?,
    )?;
    for descriptor in &manifest.chunks {
        write_activation_chunk_descriptor(&mut response, descriptor)?;
    }
    Ok(response.into_bytes())
}

fn read_activation_context(reader: &mut BinaryReader<'_>) -> CanonicalResult<ActivationContext> {
    let target_identity = read_hash512(reader)?.into_bytes();
    let top_count = reader.read_u16()?;
    let source_submission_bitmap = reader.read_u16()?;
    let mut source_corrections = [None; 10];
    for correction in &mut source_corrections {
        let is_present = reader.read_u8()?;
        let correction_bytes: [u8; TALLY_SOURCE_CORRECTION_BYTE_LENGTH] = reader
            .read_exact(TALLY_SOURCE_CORRECTION_BYTE_LENGTH)?
            .try_into()
            .map_err(|_| malformed_construction_length())?;
        match is_present {
            0 if correction_bytes.iter().all(|byte| *byte == 0) => {}
            1 => *correction = Some(correction_bytes),
            _ => return Err(malformed_construction_length()),
        }
    }
    ActivationContext::new(
        target_identity,
        top_count,
        source_submission_bitmap,
        source_corrections,
    )
    .map_err(construction_error)
}

fn read_activation_range(reader: &mut BinaryReader<'_>) -> CanonicalResult<ActivationChunkRange> {
    let range = ActivationChunkRange {
        first_operation: reader.read_u32()?,
        operation_end: reader.read_u32()?,
        includes_terminal_rekey: match reader.read_u8()? {
            0 => false,
            1 => true,
            _ => return Err(malformed_construction_length()),
        },
    };
    Ok(range)
}

fn plan_tally_activation(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let top_count = reader.read_u16()?;
    let circuit = compile_completion_tally(top_count).map_err(construction_error)?;
    let ranges = activation_chunk_ranges(&circuit).map_err(construction_error)?;
    let conjunction_count = circuit
        .operations()
        .iter()
        .filter(|operation| matches!(operation, BooleanOperation::Conjunction { .. }))
        .count();
    let mut response = BinaryWriter::new();
    response.write_u32(
        u32::try_from(circuit.operations().len()).map_err(|_| malformed_construction_length())?,
    )?;
    response.write_u32(
        u32::try_from(conjunction_count).map_err(|_| malformed_construction_length())?,
    )?;
    response.write_u16(
        u16::try_from(circuit.output_wires().len()).map_err(|_| malformed_construction_length())?,
    )?;
    response
        .write_u16(u16::try_from(ranges.len()).map_err(|_| malformed_construction_length())?)?;
    for range in ranges {
        response.write_u32(range.first_operation)?;
        response.write_u32(range.operation_end)?;
        response.write_u8(u8::from(range.includes_terminal_rekey))?;
    }
    Ok(response.into_bytes())
}

fn generate_tally_activation_chunk(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let context = read_activation_context(reader)?;
    let participant_position = reader.read_u16()?;
    let activation_seed = reader
        .read_exact(32)?
        .try_into()
        .map_err(|_| malformed_construction_length())?;
    let held_subset_keys = decode_held_subset_keys(participant_position, reader.read_bytes()?)
        .map_err(construction_error)?;
    let held_affine_evaluations =
        decode_held_affine_evaluations(reader.read_bytes()?).map_err(construction_error)?;
    let local_affine_constants = reader
        .read_exact(96)?
        .try_into()
        .map_err(|_| malformed_construction_length())?;
    let range = read_activation_range(reader)?;
    let material = LocalActivationMaterial {
        participant_position,
        activation_seed,
        held_subset_keys,
        held_affine_evaluations,
        local_affine_constants,
    };
    let chunk =
        generate_activation_chunk(&context, &material, range).map_err(construction_error)?;
    bytes_response(&chunk)
}

fn advance_tally_activation(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let context = read_activation_context(reader)?;
    let checkpoint = reader.read_bytes()?;
    let range = read_activation_range(reader)?;
    let action_key_sets = (0..10)
        .map(|_| ActionKeySet::decode(10, reader.read_bytes()?).map_err(construction_error))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let manifests = (0..10)
        .map(|_| {
            verify_activation_manifest(&action_key_sets, reader.read_bytes()?, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let chunks = (0..10)
        .map(|_| Ok(reader.read_bytes()?.to_vec()))
        .collect::<CanonicalResult<Vec<_>>>()?;
    for (position, (manifest, chunk)) in manifests.iter().zip(&chunks).enumerate() {
        if usize::from(manifest.participant_position) != position
            || manifest.target_identity.as_bytes() != &context.target_identity
            || manifest.top_count != context.top_count
            || manifest.source_submission_bitmap != context.source_submission_bitmap
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "activation manifest has the wrong finalized context or participant",
            ));
        }
        let descriptor = manifest
            .chunks
            .iter()
            .find(|descriptor| descriptor.range == range)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "activation manifest does not authorize the requested chunk range",
                )
            })?;
        if usize::try_from(descriptor.byte_length).ok() != Some(chunk.len())
            || descriptor.identity
                != activation_chunk_identity(chunk).map_err(construction_error)?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "activation chunk does not match its signed manifest",
            ));
        }
    }
    let mut evaluator = if checkpoint.is_empty() {
        ActivationEvaluator::new(context.clone()).map_err(construction_error)?
    } else {
        let restored =
            ActivationEvaluator::decode_checkpoint(checkpoint).map_err(construction_error)?;
        if restored.context() != &context {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "activation checkpoint has the wrong semantic context",
            ));
        }
        restored
    };
    evaluator
        .absorb(range, &chunks)
        .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    match evaluator.terminal() {
        None => {
            response.write_u8(1)?;
            response.write_bytes(&evaluator.encode_checkpoint().map_err(construction_error)?)?;
        }
        Some(VerifiedTallyTerminal::NoResult {
            accepted_ballot_authorship,
        }) => {
            response.write_u8(2)?;
            response.write_u16(authorship_bitmap(accepted_ballot_authorship))?;
        }
        Some(VerifiedTallyTerminal::Result {
            accepted_ballot_authorship,
            ordered_option_positions,
        }) => {
            response.write_u8(3)?;
            response.write_u16(authorship_bitmap(accepted_ballot_authorship))?;
            response.write_u16(
                u16::try_from(ordered_option_positions.len())
                    .map_err(|_| malformed_construction_length())?,
            )?;
            for position in ordered_option_positions {
                response.write_u16(*position)?;
            }
        }
    }
    Ok(response.into_bytes())
}

fn authorship_bitmap(authorship: &[bool; 10]) -> u16 {
    authorship
        .iter()
        .enumerate()
        .fold(0_u16, |bitmap, (position, is_accepted)| {
            bitmap | (u16::from(*is_accepted) << position)
        })
}

fn derive_finality_target_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let context = FinalityDerivationContext {
        participant_count,
        runtime_identity: read_hash512(reader)?,
        candidate_build_identity: read_hash512(reader)?,
        action_proposal_identity: read_hash512(reader)?,
        action_key_set_roster_identity: read_hash512(reader)?,
        preparation_attempt: reader.read_u16()?,
        predecessor_identity: read_hash512(reader)?,
        verified_preparation_root: read_hash512(reader)?,
    };
    let action_key_sets = (0..participant_count)
        .map(|_| {
            ActionKeySet::decode(participant_count, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let mut source_declarations = Vec::with_capacity(usize::from(participant_count));
    let mut source_bodies = Vec::with_capacity(usize::from(participant_count));
    let mut source_signatures = Vec::with_capacity(usize::from(participant_count));
    for _ in 0..participant_count {
        source_declarations.push(match reader.read_u16()? {
            1 => SourceDeclaration::Abstain,
            2 => SourceDeclaration::Submit,
            value => {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidEnum,
                    format!("unsupported source declaration: {value}"),
                ));
            }
        });
        source_bodies.push(reader.read_bytes()?.to_vec());
        source_signatures.push(reader.read_bytes()?.to_vec());
    }
    let verified = derive_finality_target(
        context,
        &action_key_sets,
        &source_declarations,
        &source_bodies,
        &source_signatures,
    )
    .map_err(construction_error)?;
    let target_context = verified.target.context();
    let mut response = BinaryWriter::new();
    response.write_bytes(&verified.target_body)?;
    response.write_fixed(verified.target_identity.as_bytes())?;
    response.write_fixed(target_context.source_inventory_root.as_bytes())?;
    for source_identity in &verified.source_body_identities {
        response.write_fixed(source_identity.as_bytes())?;
    }
    response.write_u16(target_context.source_submission_bitmap)?;
    response.write_u16(verified.target.target_kind() as u16)?;
    response.write_u16(verified.target.quorum())?;
    Ok(response.into_bytes())
}

fn encode_finality_signature_carrier_command(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let signer_position = reader.read_u16()?;
    let target_identity = read_hash512(reader)?;
    let signature = reader.read_bytes()?;
    bytes_response(
        &encode_finality_signature_carrier(
            participant_count,
            signer_position,
            target_identity,
            signature,
        )
        .map_err(construction_error)?,
    )
}

fn verify_finality_certificate_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let target = FinalityTarget::decode(reader.read_bytes()?).map_err(construction_error)?;
    if target.context().participant_count != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "finality target has the wrong participant count",
        ));
    }
    let target_identity = target.body_identity().map_err(construction_error)?;
    let action_key_sets = (0..participant_count)
        .map(|_| {
            ActionKeySet::decode(participant_count, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let signature_count = reader.read_u16()?;
    let signatures = (0..signature_count)
        .map(|_| Ok((reader.read_u16()?, reader.read_bytes()?.to_vec())))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let signer_bitmap = verify_finality_certificate(
        participant_count,
        &action_key_sets,
        target_identity,
        &signatures,
    )
    .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_u16(signer_bitmap)?;
    response.write_u16(target.quorum())?;
    response.write_u16(target.target_kind() as u16)?;
    response.write_u16(target.context().source_submission_bitmap)?;
    response.write_fixed(target_identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn verify_finality_signature_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let signer_position = reader.read_u16()?;
    let target_identity = read_hash512(reader)?;
    let action_key_sets = (0..participant_count)
        .map(|_| {
            ActionKeySet::decode(participant_count, reader.read_bytes()?)
                .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    verify_finality_signature(
        participant_count,
        &action_key_sets,
        signer_position,
        target_identity,
        reader.read_bytes()?,
    )
    .map_err(construction_error)?;
    Ok(Vec::new())
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
    let mut held_affine_evaluation_bytes =
        encode_held_affine_evaluations(&verified.held_affine_evaluations)
            .map_err(construction_error)?;
    response.write_bytes(&held_affine_evaluation_bytes)?;
    held_affine_evaluation_bytes.zeroize();
    response.write_fixed(&verified.local_affine_constants)?;
    Ok(response.into_bytes())
}

fn derive_source_correction_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let source_position = reader.read_u16()?;
    let score_encodings = reader.read_bytes()?;
    let held_subset_keys = decode_held_subset_keys(source_position, reader.read_bytes()?)
        .map_err(construction_error)?;
    let correction =
        derive_honest_source_correction(source_position, score_encodings, &held_subset_keys)
            .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_fixed(&correction)?;
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
        SourceDeclaration::Submit if correction_bytes.len() == SOURCE_CORRECTION_BYTE_LENGTH => {
            Some(
                correction_bytes
                    .try_into()
                    .map_err(|_| malformed_construction_length())?,
            )
        }
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
    match verified.correction {
        Some(correction) => response.write_fixed(&correction)?,
        None => response.write_fixed(&[0_u8; SOURCE_CORRECTION_BYTE_LENGTH])?,
    }
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
