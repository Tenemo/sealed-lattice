use super::*;

use super::json_ingress::parse_transcript_core_request;

use crate::hashing::derive_canonical_object_hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "command")]
enum TranscriptCoreCommand {
    DeriveCanonicalObjectHash,
    ValidateCanonicalFoundationValue,
    DeriveCeremonyContextHash,
    DeriveActionContextHash,
    EncodeMailboxKeyScheduleInput,
    DecodeMailboxKeyScheduleInput,
    EncodeMailboxAssociatedData,
    DecodeMailboxAssociatedData,
    EncodeStreamDescriptor,
    DecodeStreamDescriptor,
    EncodeSignedMailboxEnvelope,
    DecodeSignedMailboxEnvelope,
    DeriveMailboxKemCiphertextHash,
    DeriveMailboxEnvelopeHash,
    DeriveSetupMailboxSlotHash,
    EncodePrivateRandomCursor,
    DecodePrivateRandomCursor,
    DescribeBgvRnsParameters,
    DescribeCollectiveBgvSetupParameters,
    VerifyCollectiveBgvSetup,
    VerifyPrivateVssShareEnvelope,
    GenerateTrusteeEvaluationKeyProof,
    ComputeSetupCommitmentFromOpening,
    ComputeVssCommittedMaterialCommitment,
    GenerateVssShareLinkageProof,
    GenerateSameSecretBridgeProof,
}

fn parse_transcript_core_command(command_name: &str) -> CanonicalResult<TranscriptCoreCommand> {
    serde_json::from_value(json!({ "command": command_name })).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("unsupported command: {command_name}"),
        )
    })
}

pub(super) fn run_transcript_core_command_inner(input: &[u8]) -> CanonicalResult<Value> {
    let request = parse_transcript_core_request(input)?;
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "command must be a string",
            )
        })?;
    let command = parse_transcript_core_command(command)?;

    match command {
        TranscriptCoreCommand::DeriveCanonicalObjectHash => {
            let value = request.get("value").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "value field is required",
                )
            })?;

            Ok(json!({
                "canonicalObjectHash": derive_canonical_object_hash(value)?,
            }))
        }
        TranscriptCoreCommand::ValidateCanonicalFoundationValue => {
            super::foundation_command::validate_canonical_foundation_value(&request)
        }
        TranscriptCoreCommand::DeriveCeremonyContextHash => {
            super::foundation_command::derive_ceremony_context_hash(&request)
        }
        TranscriptCoreCommand::DeriveActionContextHash => {
            super::foundation_command::derive_action_context_hash(&request)
        }
        TranscriptCoreCommand::EncodeMailboxKeyScheduleInput => {
            super::mailbox_command::encode_mailbox_key_schedule_input(&request)
        }
        TranscriptCoreCommand::DecodeMailboxKeyScheduleInput => {
            super::mailbox_command::decode_mailbox_key_schedule_input(&request)
        }
        TranscriptCoreCommand::EncodeMailboxAssociatedData => {
            super::mailbox_command::encode_mailbox_associated_data(&request)
        }
        TranscriptCoreCommand::DecodeMailboxAssociatedData => {
            super::mailbox_command::decode_mailbox_associated_data(&request)
        }
        TranscriptCoreCommand::EncodeStreamDescriptor => {
            super::mailbox_command::encode_stream_descriptor(&request)
        }
        TranscriptCoreCommand::DecodeStreamDescriptor => {
            super::mailbox_command::decode_stream_descriptor(&request)
        }
        TranscriptCoreCommand::EncodeSignedMailboxEnvelope => {
            super::mailbox_command::encode_signed_mailbox_envelope(&request)
        }
        TranscriptCoreCommand::DecodeSignedMailboxEnvelope => {
            super::mailbox_command::decode_signed_mailbox_envelope(&request)
        }
        TranscriptCoreCommand::DeriveMailboxKemCiphertextHash => {
            super::mailbox_command::derive_mailbox_kem_ciphertext_hash_command(&request)
        }
        TranscriptCoreCommand::DeriveMailboxEnvelopeHash => {
            super::mailbox_command::derive_mailbox_envelope_hash_command(&request)
        }
        TranscriptCoreCommand::DeriveSetupMailboxSlotHash => {
            super::mailbox_command::derive_setup_mailbox_slot_hash_command(&request)
        }
        TranscriptCoreCommand::EncodePrivateRandomCursor => {
            super::private_randomness_command::encode_private_random_cursor(&request)
        }
        TranscriptCoreCommand::DecodePrivateRandomCursor => {
            super::private_randomness_command::decode_private_random_cursor(&request)
        }
        TranscriptCoreCommand::VerifyCollectiveBgvSetup => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "accepted setup verification requires an opaque material-ownership session",
        )),
        TranscriptCoreCommand::DescribeBgvRnsParameters
        | TranscriptCoreCommand::DescribeCollectiveBgvSetupParameters
        | TranscriptCoreCommand::VerifyPrivateVssShareEnvelope
        | TranscriptCoreCommand::GenerateTrusteeEvaluationKeyProof
        | TranscriptCoreCommand::ComputeSetupCommitmentFromOpening
        | TranscriptCoreCommand::ComputeVssCommittedMaterialCommitment
        | TranscriptCoreCommand::GenerateVssShareLinkageProof
        | TranscriptCoreCommand::GenerateSameSecretBridgeProof => {
            run_bgv_command(command, &request)
        }
    }
}

pub(super) fn run_accepted_setup_command_inner(
    input: &[u8],
    session_handle: u32,
) -> CanonicalResult<Value> {
    let request = parse_transcript_core_request(input)?;
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "command must be a string",
            )
        })?;
    if parse_transcript_core_command(command)? != TranscriptCoreCommand::VerifyCollectiveBgvSetup {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "accepted-setup session can execute only VerifyCollectiveBgvSetup",
        ));
    }
    crate::bgv::verify_collective_bgv_setup_package_with_session_from_request(
        &request,
        session_handle,
    )
}

fn run_bgv_command(command: TranscriptCoreCommand, request: &Value) -> CanonicalResult<Value> {
    match command {
        TranscriptCoreCommand::DescribeBgvRnsParameters => {
            crate::bgv::commands::describe_bgv_rns_parameters()
        }
        TranscriptCoreCommand::DescribeCollectiveBgvSetupParameters => {
            crate::bgv::commands::describe_collective_bgv_setup_parameters_from_request(request)
        }
        TranscriptCoreCommand::VerifyPrivateVssShareEnvelope => {
            crate::bgv::setup::verify_private_vss_share_envelope_from_request(request)
        }
        TranscriptCoreCommand::GenerateTrusteeEvaluationKeyProof => {
            crate::bgv::setup::generate_trustee_evaluation_key_proof_from_request(request)
        }
        TranscriptCoreCommand::ComputeSetupCommitmentFromOpening => {
            crate::bgv::setup::compute_setup_commitment_from_opening_request(request)
        }
        TranscriptCoreCommand::ComputeVssCommittedMaterialCommitment => {
            crate::bgv::setup::compute_vss_committed_material_commitment_request(request)
        }
        TranscriptCoreCommand::GenerateVssShareLinkageProof => {
            crate::bgv::setup::generate_vss_share_linkage_proof_from_request(request)
        }
        TranscriptCoreCommand::GenerateSameSecretBridgeProof => {
            crate::bgv::setup::generate_same_secret_bridge_proof_from_request(request)
        }
        _ => unreachable!("non-BGV command dispatched to BGV handler"),
    }
}
