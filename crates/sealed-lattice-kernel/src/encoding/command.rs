use super::*;

use super::json_ingress::parse_transcript_core_request;

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
        CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalTuple, FOUNDATION_PROFILE,
        FoundationSchemaObjectValidationError, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH,
        RefusalReason, derive_participant_identity, hash512 as foundation_hash512,
        validate_foundation_schema_object,
    },
    hashing::derive_canonical_object_hash,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "command")]
enum TranscriptCoreCommand {
    ValidateFoundationCanonicalTuple,
    ValidateFoundationSchemaObject,
    ComputeFoundationHash512,
    DeriveFoundationParticipantIdentity,
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
    EncodeBgvBatchPlaintext,
    ValidateBgvPlaintextObject,
    ValidateBgvCiphertextObject,
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
        TranscriptCoreCommand::ValidateFoundationCanonicalTuple => {
            let limits = CanonicalDecodeLimits::default();
            let canonical_tuple_bytes = read_bounded_hex_field(
                &request,
                "canonicalTupleHex",
                limits.maximum_tuple_byte_length,
            )?;
            let tuple = CanonicalTuple::decode(&canonical_tuple_bytes, &limits)
                .map_err(map_foundation_codec_error)?;
            let reencoded_bytes = tuple.encode().map_err(map_foundation_codec_error)?;

            Ok(json!({
                "canonicalTupleHex": crate::transcript_core::encode_hex(&reencoded_bytes),
                "schemaIdentifier": tuple.schema_identifier,
                "schemaVersion": tuple.schema_version,
                "itemCount": tuple.items.len(),
            }))
        }
        TranscriptCoreCommand::ValidateFoundationSchemaObject => {
            let limits = CanonicalDecodeLimits::default();
            let canonical_object_bytes = read_bounded_hex_field(
                &request,
                "canonicalObjectHex",
                FOUNDATION_PROFILE.maximum_copied_buffer_byte_length,
            )?;
            let validation = validate_foundation_schema_object(&canonical_object_bytes, &limits)
                .map_err(map_foundation_schema_object_validation_error)?;

            Ok(json!({
                "schemaIdentifier": validation.schema_identifier,
                "schemaVersion": validation.schema_version,
                "canonicalByteLength": validation.canonical_byte_length,
            }))
        }
        TranscriptCoreCommand::ComputeFoundationHash512 => {
            let domain = request
                .get("domain")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "domain must be a string",
                    )
                })?;
            let limits = CanonicalDecodeLimits::default();
            let item_tuple_bytes = read_bounded_hex_field(
                &request,
                "canonicalItemsTupleHex",
                limits.maximum_tuple_byte_length,
            )?;
            let item_tuple = CanonicalTuple::decode(&item_tuple_bytes, &limits)
                .map_err(map_foundation_codec_error)?;
            if item_tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
                || item_tuple.schema_version != CANONICAL_TUPLE_VERSION
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "canonicalItemsTupleHex must use the foundation canonical-tuple schema and version",
                ));
            }
            let hash = foundation_hash512(domain, &item_tuple.items)
                .map_err(map_foundation_codec_error)?;

            Ok(json!({
                "hash512": hash.to_lowercase_hex(),
            }))
        }
        TranscriptCoreCommand::DeriveFoundationParticipantIdentity => {
            let signing_verification_key = read_bounded_hex_field(
                &request,
                "signingVerificationKeyHex",
                ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH,
            )?;
            if signing_verification_key.len() != ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!(
                        "signingVerificationKeyHex must encode exactly {ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH} bytes",
                    ),
                ));
            }
            let signing_verification_key: [u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH] =
                signing_verification_key.try_into().map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "signingVerificationKeyHex has the wrong decoded length",
                    )
                })?;
            let participant_identity = derive_participant_identity(&signing_verification_key)
                .map_err(map_foundation_codec_error)?;

            Ok(json!({
                "participantIdentity": participant_identity.to_lowercase_hex(),
            }))
        }
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
        | TranscriptCoreCommand::EncodeBgvBatchPlaintext
        | TranscriptCoreCommand::ValidateBgvPlaintextObject
        | TranscriptCoreCommand::ValidateBgvCiphertextObject
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

fn read_bounded_hex_field(
    request: &Value,
    field_name: &str,
    maximum_byte_length: usize,
) -> CanonicalResult<Vec<u8>> {
    let hex = request
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })?;
    let maximum_hex_length = maximum_byte_length.checked_mul(2).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "maximum hex length does not fit usize",
        )
    })?;
    if hex.len() > maximum_hex_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} exceeds the accepted byte length"),
        ));
    }

    crate::transcript_core::decode_hex(hex)
}

fn map_foundation_codec_error(error: CanonicalCodecError) -> CanonicalError {
    let code = match error.kind {
        CanonicalCodecErrorKind::TrailingBytes => CanonicalErrorCode::TrailingBytes,
        CanonicalCodecErrorKind::UnknownItemType => CanonicalErrorCode::InvalidEnum,
        CanonicalCodecErrorKind::Truncated
        | CanonicalCodecErrorKind::LimitExceeded
        | CanonicalCodecErrorKind::LengthOverflow => CanonicalErrorCode::MalformedLength,
        CanonicalCodecErrorKind::InvalidItem => CanonicalErrorCode::InvalidProtocolObject,
    };
    CanonicalError::new(code, format!("foundation canonical tuple: {error}"))
}

fn map_foundation_schema_object_validation_error(
    error: FoundationSchemaObjectValidationError,
) -> CanonicalError {
    match error {
        FoundationSchemaObjectValidationError::CanonicalCodec(error) => {
            map_foundation_codec_error(error)
        }
        FoundationSchemaObjectValidationError::Schema {
            refusal_reason: RefusalReason::UnsupportedVersionOrSuite,
            message,
        } => CanonicalError::new(CanonicalErrorCode::UnsupportedObjectVersion, message),
        FoundationSchemaObjectValidationError::Schema { message, .. } => {
            CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
        }
        FoundationSchemaObjectValidationError::UnsupportedSchemaIdentifier(schema_identifier) => {
            CanonicalError::new(
                CanonicalErrorCode::UnsupportedObjectType,
                format!(
                    "foundation schema identifier 0x{schema_identifier:04x} is not exposed by this command"
                ),
            )
        }
        FoundationSchemaObjectValidationError::UnsupportedSchemaVersion(schema_version) => {
            CanonicalError::new(
                CanonicalErrorCode::UnsupportedObjectVersion,
                format!("foundation schema version {schema_version} is unsupported"),
            )
        }
        FoundationSchemaObjectValidationError::ReencodingMismatch => CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "foundation schema object does not re-encode byte-identically",
        ),
    }
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
            crate::bgv::commands::generate_bgv_passive_setup(request)
        }
        TranscriptCoreCommand::VerifyBgvPassiveSetup => {
            crate::bgv::commands::verify_bgv_passive_setup(request)
        }
        TranscriptCoreCommand::VerifyPrivateVssShareEnvelope => {
            crate::bgv::commands::verify_private_vss_share_envelope(request)
        }
        TranscriptCoreCommand::GeneratePrivateVssShareProof => {
            crate::bgv::commands::generate_private_vss_share_proof(request)
        }
        TranscriptCoreCommand::GenerateTrusteeEvaluationKeyProof => {
            crate::bgv::commands::generate_trustee_evaluation_key_proof(request)
        }
        TranscriptCoreCommand::DescribeTrusteeEvaluationKeyStatement => {
            crate::bgv::commands::describe_trustee_evaluation_key_statement(request)
        }
        TranscriptCoreCommand::ComputeSetupCommitmentFromOpening => {
            crate::bgv::commands::compute_setup_commitment_from_opening(request)
        }
        TranscriptCoreCommand::VerifyLocalTrusteeSetupState => {
            crate::bgv::commands::verify_local_trustee_setup_state(request)
        }
        TranscriptCoreCommand::EncodeBgvBatchPlaintext => {
            crate::bgv::commands::encode_bgv_batch_plaintext_from_request(request)
        }
        TranscriptCoreCommand::ValidateBgvPlaintextObject => {
            crate::bgv::commands::validate_bgv_plaintext_from_request(request)
        }
        TranscriptCoreCommand::ValidateBgvCiphertextObject => {
            crate::bgv::commands::validate_bgv_ciphertext_from_request(request)
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
            crate::bgv::commands::compute_vss_committed_material_commitment(request)
        }
        TranscriptCoreCommand::GenerateVssShareLinkageProof => {
            crate::bgv::commands::generate_vss_share_linkage_proof(request)
        }
        TranscriptCoreCommand::GenerateSameSecretBridgeProof => {
            crate::bgv::commands::generate_same_secret_bridge_proof(request)
        }
        _ => unreachable!("non-BGV command dispatched to BGV handler"),
    }
}
