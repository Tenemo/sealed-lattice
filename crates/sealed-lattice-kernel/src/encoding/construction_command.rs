use super::{BinaryReader, BinaryWriter, CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::{Hash512, Roster, RosterEntry};
use crate::protocol::action_signature::{
    MESSAGE_BYTE_LENGTH, SIGNING_RANDOMNESS_BYTE_LENGTH,
    generate_key_pair as generate_action_signature_key_pair, sign as sign_action_message,
    verify as verify_action_signature,
};
use crate::protocol::finality::{
    FinalityDerivationContext, FinalityTarget, VerifiedFinalityCapability, derive_finality_target,
    encode_finality_signature_carrier, verify_finality_certificate, verify_finality_signature,
};
use crate::protocol::joint_continuation::{
    AFFINE_MATERIAL_BYTE_LENGTH, JointContinuationPlan, ParticipantGenerationInput,
    derive_affine_material, encode_activation_signature, evaluate_signed_batch,
    generate_participant_body,
};
use crate::protocol::padded_continuation::{
    PaddedParticipantGenerationInput, PaddedTallyEvaluationInitializationInput,
    PaddedTallyGenerationInitializationInput, compile_padded_tally_plan_summary,
    encode_padded_activation_signature, evaluate_next_padded_tally_chunk,
    evaluate_signed_padded_batch, generate_next_padded_tally_chunk, generate_padded_participant,
    initialize_padded_tally_evaluation, initialize_padded_tally_generation,
    padded_participant_payload_byte_length,
};
use crate::protocol::pair_encryption::generate_key_pair;
use crate::protocol::preparation_parent::{
    ACTION_SIGNATURE_CARRIER_BYTE_LENGTH, ActionSignatureCarrier, ActionSignaturePurpose,
    PreparationParent, SUBSET_COMMITMENT_BYTE_LENGTH, SUBSET_COMMITMENT_COUNT,
    action_signature_statement_identity, verify_private_preparation_carrier,
};
use crate::protocol::preparation_plaintext::{
    CONTRIBUTION_OPENING_BYTE_LENGTH, PAIRWISE_MASTER_VECTOR_BYTE_LENGTH,
    PREPARATION_PLAINTEXT_BYTE_LENGTH, PreparationMaterialContext, generate_preparation_material,
    verify_preparation_plaintext,
};
use crate::protocol::private_preparation_body::{
    PrivatePreparationBody, PrivatePreparationContext,
};
use crate::protocol::roster::{
    COMPLETION_PROFILE_PARTICIPANT_COUNT, decode_completion_roster, mailbox_encapsulation_key,
    require_roster_identity, verify_roster_credentials,
};
use crate::protocol::source::{
    SOURCE_CORRECTION_BYTE_LENGTH, SOURCE_ORDINAL, SourceBody, SourceContext, SourceDeclaration,
    decode_held_subset_keys, derive_honest_source_correction, encode_held_subset_keys,
    verify_complete_preparation, verify_source_carrier,
};
use zeroize::{Zeroize, Zeroizing};

const GENERATE_ACTION_SIGNATURE_KEY_PAIR: u8 = 1;
const SIGN_ACTION_BODY_IDENTITY: u8 = 2;
const VERIFY_ACTION_SIGNATURE: u8 = 3;
const GENERATE_PAIR_ENCRYPTION_KEY: u8 = 4;
const REJECTED_PAIR_MESSAGE_COMMAND_START: u8 = 5;
const REJECTED_PAIR_MESSAGE_COMMAND_END: u8 = 6;
const DERIVE_ACTION_SIGNATURE_STATEMENT: u8 = 7;
const ENCODE_COMPLETION_ROSTER: u8 = 8;
const VERIFY_COMPLETION_ROSTER: u8 = 9;
const SEAL_PRIVATE_PREPARATION_BODY: u8 = 10;
const OPEN_PRIVATE_PREPARATION_BODY: u8 = 11;
const ENCODE_PREPARATION_PARENT: u8 = 12;
const ENCODE_PREPARATION_SIGNATURE_CARRIER: u8 = 13;
const VERIFY_PRIVATE_PREPARATION_CARRIER: u8 = 14;
const GENERATE_PREPARATION_MATERIAL: u8 = 15;
const VERIFY_PREPARATION_PLAINTEXT: u8 = 16;
const RESOLVE_ROSTER_MAILBOX_KEY: u8 = 17;
const VERIFY_COMPLETE_PREPARATION: u8 = 18;
const DERIVE_HONEST_SOURCE_CORRECTION: u8 = 19;
const ENCODE_SOURCE_BODY: u8 = 20;
const ENCODE_SOURCE_SIGNATURE_CARRIER: u8 = 21;
const VERIFY_SOURCE_CARRIER: u8 = 22;
const DERIVE_FINALITY_TARGET: u8 = 23;
const ENCODE_FINALITY_SIGNATURE_CARRIER: u8 = 24;
const VERIFY_FINALITY_CERTIFICATE: u8 = 25;
const VERIFY_FINALITY_SIGNATURE: u8 = 26;
const REJECTED_TALLY_ACTIVATION_COMMAND_START: u8 = 27;
const REJECTED_TALLY_ACTIVATION_COMMAND_END: u8 = 33;
const DERIVE_JOINT_CONTINUATION_AFFINE_MATERIAL: u8 = 34;
const GENERATE_JOINT_CONTINUATION_PARTICIPANT_BODY: u8 = 35;
const ENCODE_JOINT_CONTINUATION_ACTIVATION_SIGNATURE: u8 = 36;
const EVALUATE_JOINT_CONTINUATION_BATCH: u8 = 37;
const GENERATE_PADDED_CONTINUATION_PARTICIPANT: u8 = 38;
const ENCODE_PADDED_CONTINUATION_ACTIVATION_SIGNATURE: u8 = 39;
const EVALUATE_PADDED_CONTINUATION_BATCH: u8 = 40;
const VERIFY_ROSTER_CREDENTIALS: u8 = 41;
const COMPILE_PADDED_TALLY_PLAN: u8 = 42;
const INITIALIZE_PADDED_TALLY_GENERATION: u8 = 43;
const GENERATE_NEXT_PADDED_TALLY_CHUNK: u8 = 44;
const INITIALIZE_PADDED_TALLY_EVALUATION: u8 = 45;
const EVALUATE_NEXT_PADDED_TALLY_CHUNK: u8 = 46;

pub(super) fn run(input: &[u8]) -> CanonicalResult<Vec<u8>> {
    let mut reader = BinaryReader::new(input);
    let payload = match reader.read_u8()? {
        GENERATE_ACTION_SIGNATURE_KEY_PAIR => generate_action_signature_key(&mut reader),
        SIGN_ACTION_BODY_IDENTITY => sign(&mut reader),
        VERIFY_ACTION_SIGNATURE => verify(&mut reader),
        GENERATE_PAIR_ENCRYPTION_KEY => generate_pair_encryption_key(&mut reader),
        REJECTED_PAIR_MESSAGE_COMMAND_START..=REJECTED_PAIR_MESSAGE_COMMAND_END => {
            Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "rejected generic mailbox command is tombstoned",
            ))
        }
        DERIVE_ACTION_SIGNATURE_STATEMENT => derive_action_signature_statement(&mut reader),
        ENCODE_COMPLETION_ROSTER => encode_completion_roster(&mut reader),
        VERIFY_COMPLETION_ROSTER => verify_completion_roster(&mut reader),
        SEAL_PRIVATE_PREPARATION_BODY => seal_private_preparation_body(&mut reader),
        OPEN_PRIVATE_PREPARATION_BODY => open_private_preparation_body(&mut reader),
        ENCODE_PREPARATION_PARENT => encode_preparation_parent(&mut reader),
        ENCODE_PREPARATION_SIGNATURE_CARRIER => encode_preparation_signature_carrier(&mut reader),
        VERIFY_PRIVATE_PREPARATION_CARRIER => verify_private_preparation(&mut reader),
        GENERATE_PREPARATION_MATERIAL => generate_preparation(&mut reader),
        VERIFY_PREPARATION_PLAINTEXT => verify_preparation_plaintext_command(&mut reader),
        RESOLVE_ROSTER_MAILBOX_KEY => resolve_roster_mailbox_key(&mut reader),
        VERIFY_COMPLETE_PREPARATION => verify_complete_preparation_command(&mut reader),
        DERIVE_HONEST_SOURCE_CORRECTION => derive_source_correction_command(&mut reader),
        ENCODE_SOURCE_BODY => encode_source_body(&mut reader),
        ENCODE_SOURCE_SIGNATURE_CARRIER => encode_source_signature_carrier(&mut reader),
        VERIFY_SOURCE_CARRIER => verify_source(&mut reader),
        DERIVE_FINALITY_TARGET => derive_finality_target_command(&mut reader),
        ENCODE_FINALITY_SIGNATURE_CARRIER => encode_finality_signature_carrier_command(&mut reader),
        VERIFY_FINALITY_CERTIFICATE => verify_finality_certificate_command(&mut reader),
        VERIFY_FINALITY_SIGNATURE => verify_finality_signature_command(&mut reader),
        REJECTED_TALLY_ACTIVATION_COMMAND_START..=REJECTED_TALLY_ACTIVATION_COMMAND_END => {
            Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "rejected tally activation command is tombstoned",
            ))
        }
        DERIVE_JOINT_CONTINUATION_AFFINE_MATERIAL => {
            derive_joint_continuation_affine_material(&mut reader)
        }
        GENERATE_JOINT_CONTINUATION_PARTICIPANT_BODY => {
            generate_joint_continuation_participant_body(&mut reader)
        }
        ENCODE_JOINT_CONTINUATION_ACTIVATION_SIGNATURE => {
            encode_joint_continuation_activation_signature(&mut reader)
        }
        EVALUATE_JOINT_CONTINUATION_BATCH => evaluate_joint_continuation_batch(&mut reader),
        GENERATE_PADDED_CONTINUATION_PARTICIPANT => {
            generate_padded_continuation_participant(&mut reader)
        }
        ENCODE_PADDED_CONTINUATION_ACTIVATION_SIGNATURE => {
            encode_padded_continuation_activation_signature(&mut reader)
        }
        EVALUATE_PADDED_CONTINUATION_BATCH => evaluate_padded_continuation_batch(&mut reader),
        VERIFY_ROSTER_CREDENTIALS => verify_roster_credentials_command(&mut reader),
        COMPILE_PADDED_TALLY_PLAN => compile_padded_tally_plan(&mut reader),
        INITIALIZE_PADDED_TALLY_GENERATION => {
            initialize_padded_tally_generation_command(&mut reader)
        }
        GENERATE_NEXT_PADDED_TALLY_CHUNK => generate_next_padded_tally_chunk_command(&mut reader),
        INITIALIZE_PADDED_TALLY_EVALUATION => {
            initialize_padded_tally_evaluation_command(&mut reader)
        }
        EVALUATE_NEXT_PADDED_TALLY_CHUNK => evaluate_next_padded_tally_chunk_command(&mut reader),
        command => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            format!("unsupported construction command: {command}"),
        )),
    }?;
    reader.finish()?;
    Ok(payload)
}

fn derive_joint_continuation_affine_material(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let material = derive_affine_material(reader.read_bytes()?).map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_fixed(material.commitment.as_bytes())?;
    for constant in &material.constants {
        response.write_fixed(constant)?;
    }
    for evaluation in &material.evaluations {
        response.write_fixed(&evaluation.affine_a)?;
        response.write_fixed(&evaluation.affine_b)?;
    }
    let response = response.into_bytes();
    if response.len() != AFFINE_MATERIAL_BYTE_LENGTH {
        return Err(malformed_construction_length());
    }
    Ok(response)
}

fn generate_joint_continuation_participant_body(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let (capability, _) = read_verified_finality_capability(reader)?;
    let plan = JointContinuationPlan::decode(reader.read_bytes()?).map_err(construction_error)?;
    let participant_position = reader.read_u16()?;
    let initial_wire_values = reader.read_bytes()?;
    let gate_mask_shares = reader.read_bytes()?;
    let terminal_mask_shares = reader.read_bytes()?;
    let label_entropy = reader.read_bytes()?;
    let own_affine_entropy = reader.read_bytes()?;
    let affine_commitments = reader.read_bytes()?;
    let affine_evaluations = reader.read_bytes()?;
    let generated = generate_participant_body(
        &capability,
        &plan,
        ParticipantGenerationInput {
            participant_position,
            initial_wire_values,
            gate_mask_shares,
            terminal_mask_shares,
            label_entropy,
            own_affine_entropy,
            affine_commitments,
            affine_evaluations,
        },
    )
    .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&generated.body)?;
    response.write_fixed(generated.body_identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn encode_joint_continuation_activation_signature(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    bytes_response(
        &encode_activation_signature(
            reader.read_u16()?,
            read_hash512(reader)?,
            reader.read_bytes()?,
        )
        .map_err(construction_error)?,
    )
}

fn evaluate_joint_continuation_batch(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let (capability, roster) = read_verified_finality_capability(reader)?;
    let plan = JointContinuationPlan::decode(reader.read_bytes()?).map_err(construction_error)?;
    let participant_count = capability.target.context().participant_count;
    let bodies = (0..participant_count)
        .map(|_| Ok(reader.read_bytes()?.to_vec()))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let signatures = (0..participant_count)
        .map(|_| Ok(reader.read_bytes()?.to_vec()))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let evaluated = evaluate_signed_batch(&capability, &roster, &plan, &bodies, &signatures)
        .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_fixed(evaluated.batch_identity.as_bytes())?;
    response.write_u16(
        u16::try_from(evaluated.terminal_bits.len())
            .map_err(|_| malformed_construction_length())?,
    )?;
    for bit in evaluated.terminal_bits {
        response.write_u8(u8::from(bit))?;
    }
    Ok(response.into_bytes())
}

fn generate_padded_continuation_participant(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let (capability, roster) = read_verified_finality_capability(reader)?;
    let plan = JointContinuationPlan::decode(reader.read_bytes()?).map_err(construction_error)?;
    let participant_position = reader.read_u16()?;
    let initial_wire_values = reader.read_bytes()?;
    let gate_mask_shares = reader.read_bytes()?;
    let terminal_mask_shares = reader.read_bytes()?;
    let allocation_nonce = reader.read_bytes()?;
    let label_entropy = reader.read_bytes()?;
    let participant_count = capability.target.context().participant_count;
    let mut parent_bodies = Vec::with_capacity(usize::from(participant_count));
    let mut parent_signatures = Vec::with_capacity(usize::from(participant_count));
    for _ in 0..participant_count {
        parent_bodies.push(reader.read_bytes()?.to_vec());
        parent_signatures.push(reader.read_bytes()?.to_vec());
    }
    let own_opening_bytes = reader.read_bytes()?;
    let own_pairwise_master_bytes = reader.read_bytes()?;
    let remote_plaintext_bytes = Zeroizing::new(
        (0..participant_count.saturating_sub(1))
            .map(|_| Ok(reader.read_bytes()?.to_vec()))
            .collect::<CanonicalResult<Vec<_>>>()?,
    );
    let target = capability.target.context();
    let preparation_context = PreparationMaterialContext {
        action_proposal_identity: target.action_proposal_identity,
        roster_identity: target.roster_identity,
        preparation_attempt: target.preparation_attempt,
        predecessor_identity: target.predecessor_identity,
        sender_position: participant_position,
    };
    let preparation = verify_complete_preparation(
        &preparation_context,
        participant_position,
        &roster,
        &parent_bodies,
        &parent_signatures,
        own_opening_bytes,
        own_pairwise_master_bytes,
        &remote_plaintext_bytes,
    )
    .map_err(construction_error)?;
    let generated = generate_padded_participant(
        &capability,
        &preparation,
        &plan,
        PaddedParticipantGenerationInput {
            participant_position,
            initial_wire_values,
            gate_mask_shares,
            terminal_mask_shares,
            allocation_nonce,
            label_entropy,
        },
    )
    .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&generated.chunk)?;
    response.write_fixed(generated.chunk_identity.as_bytes())?;
    response.write_bytes(&generated.manifest)?;
    response.write_fixed(generated.manifest_identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn encode_padded_continuation_activation_signature(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    bytes_response(
        &encode_padded_activation_signature(
            reader.read_u16()?,
            read_hash512(reader)?,
            reader.read_bytes()?,
        )
        .map_err(construction_error)?,
    )
}

fn evaluate_padded_continuation_batch(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let (capability, roster) = read_verified_finality_capability(reader)?;
    let plan = JointContinuationPlan::decode(reader.read_bytes()?).map_err(construction_error)?;
    padded_participant_payload_byte_length(&plan).map_err(construction_error)?;
    let participant_count = capability.target.context().participant_count;
    let manifests = (0..participant_count)
        .map(|_| Ok(reader.read_bytes()?.to_vec()))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let signatures = (0..participant_count)
        .map(|_| Ok(reader.read_bytes()?.to_vec()))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let chunks = (0..participant_count)
        .map(|_| Ok(reader.read_bytes()?.to_vec()))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let evaluated =
        evaluate_signed_padded_batch(&capability, &roster, &manifests, &signatures, &chunks)
            .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_fixed(evaluated.batch_identity.as_bytes())?;
    response.write_u16(
        u16::try_from(evaluated.terminal_bits.len())
            .map_err(|_| malformed_construction_length())?,
    )?;
    for bit in evaluated.terminal_bits {
        response.write_u8(u8::from(bit))?;
    }
    Ok(response.into_bytes())
}

fn compile_padded_tally_plan(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let summary =
        compile_padded_tally_plan_summary(reader.read_u16()?).map_err(construction_error)?;
    if summary.chunk_byte_lengths.len() != summary.chunk_label_entropy_byte_lengths.len()
        || summary.chunk_byte_lengths.len() != summary.live_wire_counts_after_chunks.len()
    {
        return Err(malformed_construction_length());
    }
    let mut response = BinaryWriter::new();
    response.write_u16(summary.participant_count)?;
    response.write_u16(summary.option_count)?;
    response.write_u16(summary.top_count)?;
    response.write_u32(summary.input_wire_count)?;
    response.write_u32(summary.operation_count)?;
    response.write_u32(summary.constant_count)?;
    response.write_u32(summary.linear_count)?;
    response.write_u32(summary.conjunction_count)?;
    response.write_u32(summary.negation_count)?;
    response.write_u32(summary.output_count)?;
    response.write_u32(summary.wire_count)?;
    response.write_u32(summary.logical_payload_byte_length)?;
    response.write_u32(summary.label_entropy_byte_length)?;
    response.write_u32(summary.manifest_byte_length)?;
    response.write_u32(summary.maximum_live_wire_count)?;
    response.write_u16(
        u16::try_from(summary.chunk_byte_lengths.len())
            .map_err(|_| malformed_construction_length())?,
    )?;
    for ((chunk_byte_length, entropy_byte_length), live_wire_count) in summary
        .chunk_byte_lengths
        .iter()
        .zip(&summary.chunk_label_entropy_byte_lengths)
        .zip(&summary.live_wire_counts_after_chunks)
    {
        response.write_u32(*chunk_byte_length)?;
        response.write_u32(*entropy_byte_length)?;
        response.write_u32(*live_wire_count)?;
    }
    Ok(response.into_bytes())
}

fn initialize_padded_tally_generation_command(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let (capability, roster) = read_verified_finality_capability(reader)?;
    let participant_position = reader.read_u16()?;
    let allocation_nonce = reader.read_bytes()?;
    let checkpoint_key = reader.read_bytes()?;
    let participant_count = capability.target.context().participant_count;
    let mut source_bodies = Vec::with_capacity(usize::from(participant_count));
    let mut source_signatures = Vec::with_capacity(usize::from(participant_count));
    for _ in 0..participant_count {
        source_bodies.push(reader.read_bytes()?.to_vec());
        source_signatures.push(reader.read_bytes()?.to_vec());
    }
    let mut parent_bodies = Vec::with_capacity(usize::from(participant_count));
    let mut parent_signatures = Vec::with_capacity(usize::from(participant_count));
    for _ in 0..participant_count {
        parent_bodies.push(reader.read_bytes()?.to_vec());
        parent_signatures.push(reader.read_bytes()?.to_vec());
    }
    let own_opening_bytes = reader.read_bytes()?;
    let own_pairwise_master_bytes = reader.read_bytes()?;
    let remote_plaintext_bytes = Zeroizing::new(
        (0..participant_count.saturating_sub(1))
            .map(|_| Ok(reader.read_bytes()?.to_vec()))
            .collect::<CanonicalResult<Vec<_>>>()?,
    );
    let target = capability.target.context();
    let preparation_context = PreparationMaterialContext {
        action_proposal_identity: target.action_proposal_identity,
        roster_identity: target.roster_identity,
        preparation_attempt: target.preparation_attempt,
        predecessor_identity: target.predecessor_identity,
        sender_position: participant_position,
    };
    let preparation = verify_complete_preparation(
        &preparation_context,
        participant_position,
        &roster,
        &parent_bodies,
        &parent_signatures,
        own_opening_bytes,
        own_pairwise_master_bytes,
        &remote_plaintext_bytes,
    )
    .map_err(construction_error)?;
    let checkpoint = initialize_padded_tally_generation(
        &capability,
        &roster,
        &preparation,
        PaddedTallyGenerationInitializationInput {
            participant_position,
            source_bodies: &source_bodies,
            source_signatures: &source_signatures,
            allocation_nonce,
            checkpoint_key,
        },
    )
    .map_err(construction_error)?;
    bytes_response(&checkpoint)
}

fn generate_next_padded_tally_chunk_command(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let generated = generate_next_padded_tally_chunk(
        reader.read_bytes()?,
        reader.read_bytes()?,
        reader.read_bytes()?,
    )
    .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_u32(generated.chunk_ordinal)?;
    response.write_bytes(&generated.chunk)?;
    response.write_fixed(generated.chunk_identity.as_bytes())?;
    match (
        generated.next_checkpoint,
        generated.manifest,
        generated.manifest_identity,
    ) {
        (Some(checkpoint), None, None) => {
            response.write_u8(1)?;
            response.write_bytes(&checkpoint)?;
        }
        (None, Some(manifest), Some(manifest_identity)) => {
            response.write_u8(2)?;
            response.write_bytes(&manifest)?;
            response.write_fixed(manifest_identity.as_bytes())?;
        }
        _ => return Err(malformed_construction_length()),
    }
    Ok(response.into_bytes())
}

fn initialize_padded_tally_evaluation_command(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let (capability, roster) = read_verified_finality_capability(reader)?;
    let checkpoint_key = reader.read_bytes()?;
    let participant_count = capability.target.context().participant_count;
    let mut manifests = Vec::with_capacity(usize::from(participant_count));
    let mut signatures = Vec::with_capacity(usize::from(participant_count));
    for _ in 0..participant_count {
        manifests.push(reader.read_bytes()?.to_vec());
        signatures.push(reader.read_bytes()?.to_vec());
    }
    let checkpoint = initialize_padded_tally_evaluation(
        &capability,
        &roster,
        PaddedTallyEvaluationInitializationInput {
            manifests: &manifests,
            signatures: &signatures,
            checkpoint_key,
        },
    )
    .map_err(construction_error)?;
    bytes_response(&checkpoint)
}

fn evaluate_next_padded_tally_chunk_command(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<Vec<u8>> {
    let checkpoint_key = reader.read_bytes()?;
    let checkpoint = reader.read_bytes()?;
    let chunks = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
        .map(|_| Ok(reader.read_bytes()?.to_vec()))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let evaluated = evaluate_next_padded_tally_chunk(checkpoint_key, checkpoint, &chunks)
        .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_u32(evaluated.chunk_ordinal)?;
    match (evaluated.next_checkpoint, evaluated.evaluated) {
        (Some(next_checkpoint), None) => {
            response.write_u8(1)?;
            response.write_bytes(&next_checkpoint)?;
        }
        (None, Some(terminal)) => {
            response.write_u8(2)?;
            response.write_fixed(terminal.batch_identity.as_bytes())?;
            response.write_bytes(&terminal.terminal_body)?;
            response.write_fixed(terminal.terminal_identity.as_bytes())?;
        }
        _ => return Err(malformed_construction_length()),
    }
    Ok(response.into_bytes())
}

fn read_verified_finality_capability(
    reader: &mut BinaryReader<'_>,
) -> CanonicalResult<(VerifiedFinalityCapability, Roster)> {
    let participant_count = reader.read_u16()?;
    let target = FinalityTarget::decode(reader.read_bytes()?).map_err(construction_error)?;
    if target.context().participant_count != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "finality target has the wrong participant count",
        ));
    }
    let roster = read_completion_roster(reader, participant_count)?;
    let signature_count = reader.read_u16()?;
    let signatures = (0..signature_count)
        .map(|_| Ok((reader.read_u16()?, reader.read_bytes()?.to_vec())))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let capability =
        verify_finality_certificate(&target, &roster, &signatures).map_err(construction_error)?;
    Ok((capability, roster))
}

fn derive_finality_target_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let context = FinalityDerivationContext {
        participant_count,
        runtime_identity: read_hash512(reader)?,
        candidate_build_identity: read_hash512(reader)?,
        action_proposal_identity: read_hash512(reader)?,
        action_definition_identity: read_hash512(reader)?,
        roster_identity: read_hash512(reader)?,
        preparation_attempt: reader.read_u16()?,
        predecessor_identity: read_hash512(reader)?,
        verified_preparation_root: read_hash512(reader)?,
        top_count: reader.read_u16()?,
    };
    let roster = read_completion_roster(reader, participant_count)?;
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
        &roster,
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
    response.write_u16(target_context.top_count)?;
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
    let roster = read_completion_roster(reader, participant_count)?;
    let signature_count = reader.read_u16()?;
    let signatures = (0..signature_count)
        .map(|_| Ok((reader.read_u16()?, reader.read_bytes()?.to_vec())))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let capability =
        verify_finality_certificate(&target, &roster, &signatures).map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_u16(capability.target.quorum())?;
    response.write_u16(capability.target.target_kind() as u16)?;
    response.write_u16(capability.target.context().source_submission_bitmap)?;
    response.write_u16(capability.target.context().top_count)?;
    response.write_fixed(capability.target_identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn verify_finality_signature_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let signer_position = reader.read_u16()?;
    let target = FinalityTarget::decode(reader.read_bytes()?).map_err(construction_error)?;
    if target.context().participant_count != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "finality target has the wrong participant count",
        ));
    }
    let roster = read_completion_roster(reader, participant_count)?;
    verify_finality_signature(&target, &roster, signer_position, reader.read_bytes()?)
        .map_err(construction_error)?;
    Ok(Vec::new())
}

fn verify_complete_preparation_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let action_proposal_identity = read_hash512(reader)?;
    let roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let local_position = reader.read_u16()?;
    let roster = read_completion_roster(reader, participant_count)?;
    let mut parent_bodies = Vec::with_capacity(usize::from(participant_count));
    let mut parent_signatures = Vec::with_capacity(usize::from(participant_count));
    for _ in 0..participant_count {
        parent_bodies.push(reader.read_bytes()?.to_vec());
        parent_signatures.push(reader.read_bytes()?.to_vec());
    }
    let own_opening_bytes = reader.read_bytes()?;
    let own_pairwise_master_bytes = reader.read_bytes()?;
    let remote_plaintext_bytes = Zeroizing::new(
        (0..participant_count.saturating_sub(1))
            .map(|_| Ok(reader.read_bytes()?.to_vec()))
            .collect::<CanonicalResult<Vec<_>>>()?,
    );
    let context = PreparationMaterialContext {
        action_proposal_identity,
        roster_identity,
        preparation_attempt,
        predecessor_identity,
        sender_position: local_position,
    };
    let verified = verify_complete_preparation(
        &context,
        local_position,
        &roster,
        &parent_bodies,
        &parent_signatures,
        own_opening_bytes,
        own_pairwise_master_bytes,
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
    let context = SourceContext {
        participant_count: reader.read_u16()?,
        action_proposal_identity: read_hash512(reader)?,
        roster_identity: read_hash512(reader)?,
        preparation_attempt: reader.read_u16()?,
        predecessor_identity: read_hash512(reader)?,
        verified_preparation_root: read_hash512(reader)?,
        sender_position: reader.read_u16()?,
        source_ordinal: SOURCE_ORDINAL,
    };
    let score_encodings = reader.read_bytes()?;
    let held_subset_keys = decode_held_subset_keys(context.sender_position, reader.read_bytes()?)
        .map_err(construction_error)?;
    let correction = derive_honest_source_correction(&context, score_encodings, &held_subset_keys)
        .map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_fixed(&correction)?;
    Ok(response.into_bytes())
}

fn encode_source_body(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let action_proposal_identity = read_hash512(reader)?;
    let roster_identity = read_hash512(reader)?;
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
            roster_identity,
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
        roster_identity: read_hash512(reader)?,
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
    let roster = read_completion_roster(reader, participant_count)?;
    let verified = verify_source_carrier(
        expected_context,
        Some(expected_declaration),
        &roster,
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

fn resolve_roster_mailbox_key(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let expected_roster_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let recipient_position = reader.read_u16()?;
    if sender_position >= participant_count
        || recipient_position >= participant_count
        || sender_position == recipient_position
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "sender and recipient do not identify a mailbox delivery",
        ));
    }
    let roster = read_completion_roster(reader, participant_count)?;
    require_roster_identity(&roster, expected_roster_identity).map_err(construction_error)?;
    let encryption_key =
        mailbox_encapsulation_key(&roster, recipient_position).map_err(construction_error)?;
    Ok(encryption_key.to_vec())
}

fn generate_preparation(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let action_proposal_identity = read_hash512(reader)?;
    let roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let opening_bytes = reader.read_bytes()?;
    let pairwise_master_bytes = reader.read_bytes()?;
    if opening_bytes.len() != SUBSET_COMMITMENT_COUNT * CONTRIBUTION_OPENING_BYTE_LENGTH {
        return Err(malformed_construction_length());
    }
    if pairwise_master_bytes.len() != PAIRWISE_MASTER_VECTOR_BYTE_LENGTH {
        return Err(malformed_construction_length());
    }
    let context = PreparationMaterialContext {
        action_proposal_identity,
        roster_identity,
        preparation_attempt,
        predecessor_identity,
        sender_position,
    };
    let material = generate_preparation_material(&context, opening_bytes, pairwise_master_bytes)
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
    let expected_roster_identity = read_hash512(reader)?;
    let expected_preparation_attempt = reader.read_u16()?;
    let expected_predecessor_identity = read_hash512(reader)?;
    let expected_sender_position = reader.read_u16()?;
    let recipient_position = reader.read_u16()?;
    let parent = PreparationParent::decode(participant_count, reader.read_bytes()?)
        .map_err(construction_error)?;
    let context = PreparationMaterialContext {
        action_proposal_identity: expected_action_proposal_identity,
        roster_identity: expected_roster_identity,
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
    let roster_identity = read_hash512(reader)?;
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
        roster_identity,
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
    let expected_roster_identity = read_hash512(reader)?;
    let expected_preparation_attempt = reader.read_u16()?;
    let expected_predecessor_identity = read_hash512(reader)?;
    let recipient_position = reader.read_u16()?;
    let roster = read_completion_roster(reader, participant_count)?;
    let verified = verify_private_preparation_carrier(
        participant_count,
        expected_action_proposal_identity,
        expected_roster_identity,
        expected_preparation_attempt,
        expected_predecessor_identity,
        recipient_position,
        &roster,
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
    let roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let recipient_position = reader.read_u16()?;
    let pair_encryption_key = reader.read_bytes()?;
    let context = PrivatePreparationContext::new(
        participant_count,
        action_proposal_identity,
        roster_identity,
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
    let roster_identity = read_hash512(reader)?;
    let preparation_attempt = reader.read_u16()?;
    let predecessor_identity = read_hash512(reader)?;
    let sender_position = reader.read_u16()?;
    let recipient_position = reader.read_u16()?;
    let pair_encryption_key = reader.read_bytes()?;
    let context = PrivatePreparationContext::new(
        participant_count,
        action_proposal_identity,
        roster_identity,
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
        .open(context, pair_encryption_key, pair_decryption_key)
        .map_err(construction_error)?;
    let response = bytes_response(&plaintext);
    plaintext.zeroize();
    response
}

fn derive_action_signature_statement(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    if participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "action signatures require the ten-participant completion roster",
        ));
    }
    let signer_position = reader.read_u16()?;
    let purpose = match reader.read_u16()? {
        1 => ActionSignaturePurpose::Preparation,
        2 => ActionSignaturePurpose::Source,
        3 => ActionSignaturePurpose::Finality,
        4 => ActionSignaturePurpose::Activation,
        value => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidEnum,
                format!("unsupported action-signature purpose: {value}"),
            ));
        }
    };
    Ok(
        action_signature_statement_identity(signer_position, purpose, read_hash512(reader)?)
            .map_err(construction_error)?
            .into_bytes()
            .to_vec(),
    )
}

fn encode_completion_roster(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    if participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "construction requires the ten-participant completion roster",
        ));
    }
    let entries = (0..participant_count)
        .map(|position| {
            RosterEntry::new(
                position,
                read_exact_array(reader.read_bytes()?)?,
                read_exact_array(reader.read_bytes()?)?,
            )
            .map_err(construction_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let roster = Roster::new(entries).map_err(construction_error)?;
    let roster_bytes = roster.encode().map_err(construction_error)?;
    let roster_identity = roster.roster_hash().map_err(construction_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&roster_bytes)?;
    response.write_fixed(roster_identity.as_bytes())?;
    Ok(response.into_bytes())
}

fn verify_completion_roster(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let roster = decode_completion_roster(reader.read_bytes()?).map_err(construction_error)?;
    Ok(roster
        .roster_hash()
        .map_err(construction_error)?
        .into_bytes()
        .to_vec())
}

fn verify_roster_credentials_command(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let participant_count = reader.read_u16()?;
    let roster_position = reader.read_u16()?;
    let roster = read_completion_roster(reader, participant_count)?;
    verify_roster_credentials(
        &roster,
        roster_position,
        reader.read_bytes()?,
        reader.read_bytes()?,
    )
    .map_err(construction_error)?;
    Ok(roster
        .roster_hash()
        .map_err(construction_error)?
        .into_bytes()
        .to_vec())
}

fn read_completion_roster(
    reader: &mut BinaryReader<'_>,
    participant_count: u16,
) -> CanonicalResult<Roster> {
    if participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "construction requires the ten-participant completion roster",
        ));
    }
    decode_completion_roster(reader.read_bytes()?).map_err(construction_error)
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

fn generate_action_signature_key(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let mut key_pair =
        generate_action_signature_key_pair(reader.read_bytes()?).map_err(action_signature_error)?;
    let mut response = BinaryWriter::new();
    response.write_bytes(&key_pair.secret_key)?;
    response.write_bytes(&key_pair.verification_key)?;
    key_pair.zeroize();
    Ok(response.into_bytes())
}

fn sign(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let message = read_message(reader)?;
    let secret_key = reader.read_bytes()?;
    let signing_randomness = reader.read_bytes()?;
    if signing_randomness.len() != SIGNING_RANDOMNESS_BYTE_LENGTH {
        return Err(malformed_construction_length());
    }
    bytes_response(
        &sign_action_message(secret_key, signing_randomness, &message)
            .map_err(action_signature_error)?,
    )
}

fn verify(reader: &mut BinaryReader<'_>) -> CanonicalResult<Vec<u8>> {
    let message = read_message(reader)?;
    let signature = reader.read_bytes()?;
    let verification_key = reader.read_bytes()?;
    let is_valid = verify_action_signature(signature, verification_key, &message)
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
    fn action_signature_key_generation_refuses_wrong_lengths_and_trailing_bytes() {
        let mut oversized = vec![GENERATE_ACTION_SIGNATURE_KEY_PAIR];
        let length = 33_u32;
        oversized.extend_from_slice(&length.to_le_bytes());
        oversized.extend_from_slice(&vec![0_u8; length as usize]);
        assert_eq!(run_construction_command(&oversized)[0], 1);

        let mut trailing = vec![GENERATE_ACTION_SIGNATURE_KEY_PAIR];
        trailing.extend_from_slice(&32_u32.to_le_bytes());
        trailing.extend_from_slice(&[0_u8; 32]);
        trailing.push(0);
        assert_eq!(run_construction_command(&trailing)[0], 1);

        let mut obsolete_fragment_shape = vec![GENERATE_ACTION_SIGNATURE_KEY_PAIR];
        obsolete_fragment_shape.extend_from_slice(&0_u16.to_le_bytes());
        obsolete_fragment_shape.extend_from_slice(&48_u32.to_le_bytes());
        obsolete_fragment_shape.extend_from_slice(&[0_u8; 48]);
        assert_eq!(run_construction_command(&obsolete_fragment_shape)[0], 1);
    }

    #[test]
    fn rejected_tally_activation_command_range_is_tombstoned() {
        for command in
            REJECTED_TALLY_ACTIVATION_COMMAND_START..=REJECTED_TALLY_ACTIVATION_COMMAND_END
        {
            let response = run_construction_command(&[command]);
            assert_eq!(response[0], 1, "command {command} must stay rejected");
        }
    }

    #[test]
    fn padded_tally_plan_command_derives_every_admitted_result_width() {
        for top_count in 1..=COMPLETION_PROFILE_PARTICIPANT_COUNT {
            let mut request = vec![COMPILE_PADDED_TALLY_PLAN];
            request.extend_from_slice(&top_count.to_le_bytes());
            let response = run_construction_command(&request);
            assert_eq!(response[0], 0, "topCount {top_count} must compile");
            let mut reader = BinaryReader::new(&response[1..]);
            assert_eq!(
                reader.read_u16().unwrap(),
                COMPLETION_PROFILE_PARTICIPANT_COUNT
            );
            assert_eq!(reader.read_u16().unwrap(), 10);
            assert_eq!(reader.read_u16().unwrap(), top_count);
            assert_eq!(reader.read_u32().unwrap(), 410);
            let _operation_count = reader.read_u32().unwrap();
            assert_eq!(reader.read_u32().unwrap(), 2);
            let _linear_count = reader.read_u32().unwrap();
            let _conjunction_count = reader.read_u32().unwrap();
            let _negation_count = reader.read_u32().unwrap();
            assert_eq!(reader.read_u32().unwrap(), 11 + 4 * u32::from(top_count));
            let _wire_count = reader.read_u32().unwrap();
            let _logical_payload_byte_length = reader.read_u32().unwrap();
            let total_entropy_byte_length = reader.read_u32().unwrap();
            let _manifest_byte_length = reader.read_u32().unwrap();
            assert_eq!(reader.read_u32().unwrap(), 417);
            let chunk_count = reader.read_u16().unwrap();
            let mut chunk_entropy_byte_length = 0_u32;
            let mut last_live_wire_count = None;
            for _ in 0..chunk_count {
                assert!(reader.read_u32().unwrap() <= 480_000);
                chunk_entropy_byte_length += reader.read_u32().unwrap();
                last_live_wire_count = Some(reader.read_u32().unwrap());
            }
            assert_eq!(chunk_entropy_byte_length, total_entropy_byte_length);
            assert_eq!(last_live_wire_count, Some(0));
            reader.finish().unwrap();
        }
        for rejected_top_count in [0_u16, 11] {
            let mut request = vec![COMPILE_PADDED_TALLY_PLAN];
            request.extend_from_slice(&rejected_top_count.to_le_bytes());
            assert_eq!(run_construction_command(&request)[0], 1);
        }
    }
}
