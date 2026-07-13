use super::*;

use super::json_ingress::parse_transcript_core_request;

use crate::hashing::derive_canonical_object_hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "command")]
enum TranscriptCoreCommand {
    DeriveCanonicalObjectHash,
    DescribeBgvRnsParameters,
    DescribeCollectiveBgvSetupParameters,
    GenerateBgvPassiveSetup,
    VerifyBgvPassiveSetup,
    VerifyCollectiveBgvSetup,
    VerifyPrivateVssShareEnvelope,
    GeneratePrivateVssShareProof,
    GenerateTrusteeEvaluationKeyProof,
    DescribeTrusteeEvaluationKeyStatement,
    ComputeSetupCommitmentFromOpening,
    VerifyLocalTrusteeSetupState,
    RunDirectEncryptedBallot,
    // Participant-side target-share and proof generation consume local witness
    // material inside the caller's own browser. The staged result-release path
    // still verifies every proof before recombination; exposing local generation
    // does not make an unproved share acceptable.
    GenerateBgvTargetDecryptionShareFromLocalShare,
    GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness,
    DeriveBgvTargetDecryptionResultReleaseSetupContext,
    BeginBgvTargetDecryptionResultRelease,
    AbsorbBgvTargetDecryptionResultReleaseShare,
    FinishBgvTargetDecryptionResultRelease,
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
        TranscriptCoreCommand::VerifyCollectiveBgvSetup => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "accepted setup verification requires an opaque material-ownership session",
        )),
        TranscriptCoreCommand::DescribeBgvRnsParameters
        | TranscriptCoreCommand::DescribeCollectiveBgvSetupParameters
        | TranscriptCoreCommand::GenerateBgvPassiveSetup
        | TranscriptCoreCommand::VerifyBgvPassiveSetup
        | TranscriptCoreCommand::VerifyPrivateVssShareEnvelope
        | TranscriptCoreCommand::GeneratePrivateVssShareProof
        | TranscriptCoreCommand::GenerateTrusteeEvaluationKeyProof
        | TranscriptCoreCommand::ComputeSetupCommitmentFromOpening
        | TranscriptCoreCommand::VerifyLocalTrusteeSetupState
        | TranscriptCoreCommand::RunDirectEncryptedBallot
        | TranscriptCoreCommand::DeriveBgvTargetDecryptionResultReleaseSetupContext
        | TranscriptCoreCommand::BeginBgvTargetDecryptionResultRelease
        | TranscriptCoreCommand::AbsorbBgvTargetDecryptionResultReleaseShare
        | TranscriptCoreCommand::FinishBgvTargetDecryptionResultRelease
        | TranscriptCoreCommand::ComputeVssCommittedMaterialCommitment
        | TranscriptCoreCommand::GenerateVssShareLinkageProof
        | TranscriptCoreCommand::DescribeTrusteeEvaluationKeyStatement
        | TranscriptCoreCommand::GenerateSameSecretBridgeProof
        | TranscriptCoreCommand::GenerateBgvTargetDecryptionShareFromLocalShare
        | TranscriptCoreCommand::GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness => {
            run_bgv_command(command, &request)
        }
    }
}

pub(super) fn run_accepted_setup_command_inner(
    input: &[u8],
    session_handle: u32,
    capability: &[u8; crate::foundation::CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
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
        capability,
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
        TranscriptCoreCommand::GenerateBgvPassiveSetup => {
            crate::bgv::setup::generate_passive_setup_package_from_request(request)
        }
        TranscriptCoreCommand::VerifyBgvPassiveSetup => {
            crate::bgv::setup::verify_passive_setup_package_from_request(request)
        }
        TranscriptCoreCommand::VerifyPrivateVssShareEnvelope => {
            crate::bgv::setup::verify_private_vss_share_envelope_from_request(request)
        }
        TranscriptCoreCommand::GeneratePrivateVssShareProof => {
            crate::bgv::setup::generate_private_vss_share_proof_from_request(request)
        }
        TranscriptCoreCommand::GenerateTrusteeEvaluationKeyProof => {
            crate::bgv::setup::generate_trustee_evaluation_key_proof_from_request(request)
        }
        TranscriptCoreCommand::DescribeTrusteeEvaluationKeyStatement => {
            crate::bgv::setup::describe_trustee_evaluation_key_statement_from_request(request)
        }
        TranscriptCoreCommand::ComputeSetupCommitmentFromOpening => {
            crate::bgv::setup::compute_setup_commitment_from_opening_request(request)
        }
        TranscriptCoreCommand::VerifyLocalTrusteeSetupState => {
            crate::bgv::setup::verify_local_trustee_setup_state_from_request(request)
        }
        TranscriptCoreCommand::RunDirectEncryptedBallot => {
            crate::bgv::direct_ballots::run_direct_encrypted_ballot(request)
        }
        TranscriptCoreCommand::GenerateBgvTargetDecryptionShareFromLocalShare => {
            crate::bgv::target_decryption::generate_bgv_target_decryption_share_from_local_share_request(
                request,
            )
        }
        TranscriptCoreCommand::GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness => {
            crate::bgv::target_decryption::generate_bgv_target_decryption_share_proof_material_from_local_witness_request(
                request,
            )
        }
        TranscriptCoreCommand::DeriveBgvTargetDecryptionResultReleaseSetupContext => {
            crate::bgv::target_decryption::derive_bgv_target_decryption_result_release_setup_context_from_request(
                request,
            )
        }
        TranscriptCoreCommand::BeginBgvTargetDecryptionResultRelease => {
            crate::bgv::target_decryption::begin_bgv_target_decryption_result_release_from_request(
                request,
            )
        }
        TranscriptCoreCommand::AbsorbBgvTargetDecryptionResultReleaseShare => {
            crate::bgv::target_decryption::absorb_bgv_target_decryption_result_release_share_from_request(
                request,
            )
        }
        TranscriptCoreCommand::FinishBgvTargetDecryptionResultRelease => {
            crate::bgv::target_decryption::finish_bgv_target_decryption_result_release_from_request(
                request,
            )
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
