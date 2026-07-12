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
    ListCanonicalErrorCodes,
    ComputeChunkRoot,
    HashRaw,
    ValidateFoundationCanonicalTuple,
    ValidateFoundationSchemaObject,
    ComputeFoundationHash512,
    DeriveFoundationParticipantIdentity,
    DeriveCanonicalObjectHash,
    InterpolateShamirConstantTerm,
    EvaluatePlaintextComparison,
    DescribeBgvRnsParameters,
    DescribeBgvOperationRegistry,
    ValidateBgvEvaluatorOperation,
    DescribeCollectiveBgvSetupParameters,
    DeriveCollectiveBgvSetupPublicDerivations,
    GenerateBgvPassiveSetup,
    VerifyBgvPassiveSetup,
    VerifyCollectiveBgvSetup,
    VerifyPrivateVssShareEnvelope,
    GeneratePrivateVssShareProof,
    GenerateTrusteeEvaluationKeyProof,
    DescribeTrusteeEvaluationKeyStatement,
    ComputeSetupCommitmentFromOpening,
    VerifyLocalTrusteeSetupState,
    GenerateBgvEvaluationKeyMaterial,
    EncodeBgvBatchPlaintext,
    ValidateBgvPlaintextObject,
    ValidateBgvCiphertextObject,
    AnalyzeBgvCanonicalObject,
    RunDirectEncryptedBallot,
    // Participant-side target-share and proof generation consume local witness
    // material inside the caller's own browser. The staged result-release path
    // still verifies every proof before recombination; exposing local generation
    // does not make an unproved share acceptable.
    GenerateBgvTargetDecryptionShareFromLocalShare,
    DeriveBgvTargetDecryptionShareProofStatement,
    GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness,
    VerifyBgvTargetDecryptionShareProofMaterial,
    VerifyBgvTargetDecryptionShareProofStatementBinding,
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
        TranscriptCoreCommand::ListCanonicalErrorCodes => Ok(Value::Array(
            ALL_CANONICAL_ERROR_CODES
                .iter()
                .map(|code| Value::String(code.as_str().to_string()))
                .collect(),
        )),
        TranscriptCoreCommand::ComputeChunkRoot => {
            let input_hex = request
                .get("inputHex")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "inputHex must be a string",
                    )
                })?;
            let chunk_size = request
                .get("chunkSize")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "chunkSize must be an integer",
                    )
                })?;
            let bytes = crate::transcript_core::decode_hex(input_hex)?;
            let root = chunk_root(
                &bytes,
                usize::try_from(chunk_size).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidChunkSize,
                        "chunkSize does not fit usize",
                    )
                })?,
            )?;

            Ok(json!({
                "chunkRoot": root,
            }))
        }
        TranscriptCoreCommand::HashRaw => {
            let input_hex = request
                .get("inputHex")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "inputHex must be a string",
                    )
                })?;
            let bytes = crate::transcript_core::decode_hex(input_hex)?;

            Ok(json!({
                "hash512": hash512_hex("transcript-core/raw", &[&bytes]),
            }))
        }
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
        TranscriptCoreCommand::InterpolateShamirConstantTerm => {
            let share_points = read_share_points(&request)?;

            Ok(json!({
                "fieldElement": interpolate_shamir_constant_term(&share_points)?,
            }))
        }
        TranscriptCoreCommand::EvaluatePlaintextComparison => {
            let left_total_score = read_u64_field(&request, "leftTotalScore")?;
            let right_total_score = read_u64_field(&request, "rightTotalScore")?;
            let roster_size = read_u64_field(&request, "rosterSize")?;
            let comparison =
                evaluate_plaintext_comparison(left_total_score, right_total_score, roster_size)?;

            Ok(json!({
                "greaterThan": comparison.greater_than,
                "equal": comparison.equal,
                "scoreDifference": comparison.score_difference,
            }))
        }
        TranscriptCoreCommand::DescribeBgvRnsParameters
        | TranscriptCoreCommand::DescribeBgvOperationRegistry
        | TranscriptCoreCommand::ValidateBgvEvaluatorOperation
        | TranscriptCoreCommand::DescribeCollectiveBgvSetupParameters
        | TranscriptCoreCommand::DeriveCollectiveBgvSetupPublicDerivations
        | TranscriptCoreCommand::GenerateBgvPassiveSetup
        | TranscriptCoreCommand::VerifyBgvPassiveSetup
        | TranscriptCoreCommand::VerifyCollectiveBgvSetup
        | TranscriptCoreCommand::VerifyPrivateVssShareEnvelope
        | TranscriptCoreCommand::GeneratePrivateVssShareProof
        | TranscriptCoreCommand::GenerateTrusteeEvaluationKeyProof
        | TranscriptCoreCommand::ComputeSetupCommitmentFromOpening
        | TranscriptCoreCommand::VerifyLocalTrusteeSetupState
        | TranscriptCoreCommand::GenerateBgvEvaluationKeyMaterial
        | TranscriptCoreCommand::EncodeBgvBatchPlaintext
        | TranscriptCoreCommand::ValidateBgvPlaintextObject
        | TranscriptCoreCommand::ValidateBgvCiphertextObject
        | TranscriptCoreCommand::AnalyzeBgvCanonicalObject
        | TranscriptCoreCommand::RunDirectEncryptedBallot
        | TranscriptCoreCommand::DeriveBgvTargetDecryptionResultReleaseSetupContext
        | TranscriptCoreCommand::BeginBgvTargetDecryptionResultRelease
        | TranscriptCoreCommand::AbsorbBgvTargetDecryptionResultReleaseShare
        | TranscriptCoreCommand::FinishBgvTargetDecryptionResultRelease
        | TranscriptCoreCommand::ComputeVssCommittedMaterialCommitment
        | TranscriptCoreCommand::GenerateVssShareLinkageProof
        | TranscriptCoreCommand::DescribeTrusteeEvaluationKeyStatement
        | TranscriptCoreCommand::GenerateSameSecretBridgeProof => {
            run_bgv_command(command, &request)
        }
        TranscriptCoreCommand::GenerateBgvTargetDecryptionShareFromLocalShare
        | TranscriptCoreCommand::DeriveBgvTargetDecryptionShareProofStatement
        | TranscriptCoreCommand::GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness
        | TranscriptCoreCommand::VerifyBgvTargetDecryptionShareProofMaterial
        | TranscriptCoreCommand::VerifyBgvTargetDecryptionShareProofStatementBinding => {
            run_bgv_command(command, &request)
        }
    }
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
        TranscriptCoreCommand::DescribeBgvOperationRegistry => {
            crate::bgv::commands::describe_bgv_operation_registry()
        }
        TranscriptCoreCommand::ValidateBgvEvaluatorOperation => {
            crate::bgv::commands::validate_bgv_evaluator_operation_from_request(request)
        }
        TranscriptCoreCommand::DescribeCollectiveBgvSetupParameters => {
            crate::bgv::commands::describe_collective_bgv_setup_parameters_from_request(request)
        }
        TranscriptCoreCommand::DeriveCollectiveBgvSetupPublicDerivations => {
            crate::bgv::commands::derive_collective_bgv_setup_public_derivations(request)
        }
        TranscriptCoreCommand::GenerateBgvPassiveSetup => {
            crate::bgv::commands::generate_bgv_passive_setup_from_request(request)
        }
        TranscriptCoreCommand::VerifyBgvPassiveSetup => {
            crate::bgv::commands::verify_bgv_passive_setup_from_request(request)
        }
        TranscriptCoreCommand::VerifyCollectiveBgvSetup => {
            crate::bgv::commands::verify_collective_bgv_setup_from_request(request)
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
        TranscriptCoreCommand::GenerateBgvEvaluationKeyMaterial => {
            crate::bgv::commands::generate_bgv_evaluation_key_material_from_request(request)
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
        TranscriptCoreCommand::AnalyzeBgvCanonicalObject => {
            crate::bgv::commands::analyze_bgv_canonical_object_from_request(request)
        }
        TranscriptCoreCommand::RunDirectEncryptedBallot => {
            crate::bgv::direct_ballots::run_direct_encrypted_ballot(request)
        }
        TranscriptCoreCommand::GenerateBgvTargetDecryptionShareFromLocalShare => {
            crate::bgv::target_decryption::generate_bgv_target_decryption_share_from_local_share_request(
                request,
            )
        }
        TranscriptCoreCommand::DeriveBgvTargetDecryptionShareProofStatement => {
            crate::bgv::target_decryption::derive_bgv_target_decryption_share_proof_statement_from_request(
                request,
            )
        }
        TranscriptCoreCommand::GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness => {
            crate::bgv::target_decryption::generate_bgv_target_decryption_share_proof_material_from_local_witness_request(
                request,
            )
        }
        TranscriptCoreCommand::VerifyBgvTargetDecryptionShareProofMaterial => {
            crate::bgv::target_decryption::verify_bgv_target_decryption_share_proof_material_from_request(
                request,
            )
        }
        TranscriptCoreCommand::VerifyBgvTargetDecryptionShareProofStatementBinding => {
            crate::bgv::target_decryption::verify_bgv_target_decryption_share_proof_statement_binding_from_request(
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

fn read_u64_field(request: &Value, field_name: &str) -> CanonicalResult<u64> {
    request
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-negative integer"),
            )
        })
}

fn read_share_points(request: &Value) -> CanonicalResult<Vec<ShamirSharePoint>> {
    let share_points = request
        .get("sharePoints")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sharePoints must be an array",
            )
        })?;
    if share_points.len() > MAXIMUM_SHAMIR_INTERPOLATION_POINTS {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "at most 50 Shamir shares are supported",
        ));
    }

    share_points
        .iter()
        .map(|share_point| {
            let roster_position = share_point
                .get("rosterPosition")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "share point rosterPosition must be a non-negative integer",
                    )
                })?;
            let value = share_point
                .get("value")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "share point value must be a non-negative integer",
                    )
                })?;

            Ok(ShamirSharePoint {
                roster_position,
                value,
            })
        })
        .collect()
}
