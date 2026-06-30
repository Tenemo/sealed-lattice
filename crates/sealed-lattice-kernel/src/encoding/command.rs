use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "command")]
enum TranscriptCoreCommand {
    ListCanonicalErrorCodes,
    ListReservedRootNamespaces,
    AnalyzeCanonicalObject,
    ComputeChunkRoot,
    HashRaw,
    DeriveProtocolHash,
    InterpolateShamirConstantTerm,
    EvaluatePlaintextComparison,
    VerifyFixture,
    DescribeBgvRnsProfile,
    DescribeBgvOperationRegistry,
    ValidateBgvEvaluatorOperation,
    DescribeBgvPassiveSetupObjectModel,
    DescribeCollectiveBgvSetupProfile,
    DeriveCollectiveBgvSetupPublicDerivations,
    GenerateBgvPassiveSetup,
    VerifyBgvPassiveSetup,
    VerifyCollectiveBgvSetup,
    VerifyPrivateVssShareEnvelope,
    GeneratePrivateVssShareProof,
    GenerateTrusteeEvaluationKeyProof,
    VerifyTrusteeEvaluationKeyProof,
    GenerateCompactVssShareLinkageProof,
    VerifyCompactVssShareLinkageProof,
    VerifyCompactVssShareLinkageProofMaterialSet,
    GenerateCompactSameSecretBridgeProof,
    VerifyCompactSameSecretBridgeProof,
    ComputeSetupCommitmentFromOpening,
    ComputeCompactVssCommitmentFromOpening,
    EncodeCompactVssCommitmentBody,
    DecodeCompactVssCommitmentBody,
    VerifyCompactVssCommitmentOpening,
    VerifyCompactVssCoefficientCommitmentSet,
    VerifyCompactVssRecipientShareCommitmentSet,
    VerifyCompactVssAggregateThresholdCommitmentSet,
    VerifyCompactVssShareLinkageStatement,
    VerifyCompactVssSameSecretBridgeStatementSet,
    VerifyCompactVssSameSecretBridgeProofMaterialSet,
    DeriveThresholdShareCommitments,
    DeriveThresholdShareCommitmentsFromTransport,
    BeginThresholdShareCommitmentsFromTransportStream,
    AbortThresholdShareCommitmentsFromTransportStream,
    AbsorbThresholdShareCommitmentsFromTransportStreamChunk,
    FinishThresholdShareCommitmentsFromTransportStream,
    ReleaseVerifiedTransportedVssMaterial,
    BeginSetupProofMaterialTransportStream,
    AbsorbSetupProofMaterialTransportStreamChunk,
    FinishSetupProofMaterialTransportStream,
    VerifyLocalTrusteeSetupState,
    GenerateBgvEvaluationKeyMaterial,
    EncodeBgvBatchPlaintext,
    ValidateBgvPlaintextObject,
    ValidateBgvCiphertextObject,
    GenerateBgvCiphertextConventionFixture,
    GenerateBgvBaseConversionFixture,
    AnalyzeBgvCanonicalObject,
    RunDirectEncryptedBallot,
    #[cfg(feature = "target-decryption-development-commands")]
    GenerateBgvTargetDecryptionDevelopmentFixture,
    #[cfg(feature = "target-decryption-development-commands")]
    GenerateBgvTargetDecryptionShareFromLocalShare,
    #[cfg(feature = "target-decryption-development-commands")]
    DeriveBgvTargetDecryptionShareProofStatement,
    #[cfg(feature = "target-decryption-development-commands")]
    GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness,
    #[cfg(feature = "target-decryption-development-commands")]
    VerifyBgvTargetDecryptionShareProofMaterial,
    #[cfg(feature = "target-decryption-development-commands")]
    VerifyBgvTargetDecryptionShareBinaryProofMaterial,
    #[cfg(feature = "target-decryption-development-commands")]
    VerifyBgvTargetDecryptionShareProofStatementBinding,
    #[cfg(feature = "target-decryption-development-commands")]
    VerifyAndReleaseBgvTargetDecryptionResult,
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
    let request: Value = serde_json::from_slice(input).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("command JSON is invalid: {error}"),
        )
    })?;
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
        TranscriptCoreCommand::ListReservedRootNamespaces => Ok(Value::Array(
            RESERVED_ROOT_NAMESPACES
                .iter()
                .map(|namespace| Value::String((*namespace).to_string()))
                .collect(),
        )),
        TranscriptCoreCommand::AnalyzeCanonicalObject => {
            let canonical_bytes_hex = request
                .get("canonicalBytesHex")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "canonicalBytesHex must be a string",
                    )
                })?;
            let chunk_size = request
                .get("chunkSize")
                .and_then(Value::as_u64)
                .unwrap_or(16);

            analyze_canonical_object_hex(canonical_bytes_hex, chunk_size)
        }
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
        TranscriptCoreCommand::DeriveProtocolHash => {
            let namespace = read_string_field(&request, "namespace")?;
            let value = request.get("value").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "value field is required",
                )
            })?;

            Ok(json!({
                "protocolHash": derive_protocol_hash(namespace, value)?,
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
        TranscriptCoreCommand::VerifyFixture => {
            let fixture_value = request.get("fixture").ok_or_else(|| {
                CanonicalError::new(CanonicalErrorCode::InvalidFixture, "fixture is required")
            })?;
            let fixture: TranscriptCoreFixture = serde_json::from_value(fixture_value.clone())
                .map_err(|error| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("fixture shape is invalid: {error}"),
                    )
                })?;

            verify_fixture(&fixture)
        }
        TranscriptCoreCommand::DescribeBgvRnsProfile
        | TranscriptCoreCommand::DescribeBgvOperationRegistry
        | TranscriptCoreCommand::ValidateBgvEvaluatorOperation
        | TranscriptCoreCommand::DescribeBgvPassiveSetupObjectModel
        | TranscriptCoreCommand::DescribeCollectiveBgvSetupProfile
        | TranscriptCoreCommand::DeriveCollectiveBgvSetupPublicDerivations
        | TranscriptCoreCommand::GenerateBgvPassiveSetup
        | TranscriptCoreCommand::VerifyBgvPassiveSetup
        | TranscriptCoreCommand::VerifyCollectiveBgvSetup
        | TranscriptCoreCommand::VerifyPrivateVssShareEnvelope
        | TranscriptCoreCommand::GeneratePrivateVssShareProof
        | TranscriptCoreCommand::GenerateTrusteeEvaluationKeyProof
        | TranscriptCoreCommand::VerifyTrusteeEvaluationKeyProof
        | TranscriptCoreCommand::GenerateCompactVssShareLinkageProof
        | TranscriptCoreCommand::VerifyCompactVssShareLinkageProof
        | TranscriptCoreCommand::VerifyCompactVssShareLinkageProofMaterialSet
        | TranscriptCoreCommand::GenerateCompactSameSecretBridgeProof
        | TranscriptCoreCommand::VerifyCompactSameSecretBridgeProof
        | TranscriptCoreCommand::ComputeSetupCommitmentFromOpening
        | TranscriptCoreCommand::ComputeCompactVssCommitmentFromOpening
        | TranscriptCoreCommand::EncodeCompactVssCommitmentBody
        | TranscriptCoreCommand::DecodeCompactVssCommitmentBody
        | TranscriptCoreCommand::VerifyCompactVssCommitmentOpening
        | TranscriptCoreCommand::VerifyCompactVssCoefficientCommitmentSet
        | TranscriptCoreCommand::VerifyCompactVssRecipientShareCommitmentSet
        | TranscriptCoreCommand::VerifyCompactVssAggregateThresholdCommitmentSet
        | TranscriptCoreCommand::VerifyCompactVssShareLinkageStatement
        | TranscriptCoreCommand::VerifyCompactVssSameSecretBridgeStatementSet
        | TranscriptCoreCommand::VerifyCompactVssSameSecretBridgeProofMaterialSet
        | TranscriptCoreCommand::DeriveThresholdShareCommitments
        | TranscriptCoreCommand::DeriveThresholdShareCommitmentsFromTransport
        | TranscriptCoreCommand::BeginThresholdShareCommitmentsFromTransportStream
        | TranscriptCoreCommand::AbortThresholdShareCommitmentsFromTransportStream
        | TranscriptCoreCommand::AbsorbThresholdShareCommitmentsFromTransportStreamChunk
        | TranscriptCoreCommand::FinishThresholdShareCommitmentsFromTransportStream
        | TranscriptCoreCommand::ReleaseVerifiedTransportedVssMaterial
        | TranscriptCoreCommand::BeginSetupProofMaterialTransportStream
        | TranscriptCoreCommand::AbsorbSetupProofMaterialTransportStreamChunk
        | TranscriptCoreCommand::FinishSetupProofMaterialTransportStream
        | TranscriptCoreCommand::VerifyLocalTrusteeSetupState
        | TranscriptCoreCommand::GenerateBgvEvaluationKeyMaterial
        | TranscriptCoreCommand::EncodeBgvBatchPlaintext
        | TranscriptCoreCommand::ValidateBgvPlaintextObject
        | TranscriptCoreCommand::ValidateBgvCiphertextObject
        | TranscriptCoreCommand::GenerateBgvCiphertextConventionFixture
        | TranscriptCoreCommand::GenerateBgvBaseConversionFixture
        | TranscriptCoreCommand::AnalyzeBgvCanonicalObject
        | TranscriptCoreCommand::RunDirectEncryptedBallot => run_bgv_command(command, &request),
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::GenerateBgvTargetDecryptionDevelopmentFixture
        | TranscriptCoreCommand::GenerateBgvTargetDecryptionShareFromLocalShare
        | TranscriptCoreCommand::DeriveBgvTargetDecryptionShareProofStatement
        | TranscriptCoreCommand::GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness
        | TranscriptCoreCommand::VerifyBgvTargetDecryptionShareProofMaterial
        | TranscriptCoreCommand::VerifyBgvTargetDecryptionShareBinaryProofMaterial
        | TranscriptCoreCommand::VerifyBgvTargetDecryptionShareProofStatementBinding
        | TranscriptCoreCommand::VerifyAndReleaseBgvTargetDecryptionResult => {
            run_bgv_command(command, &request)
        }
    }
}

fn run_bgv_command(command: TranscriptCoreCommand, request: &Value) -> CanonicalResult<Value> {
    match command {
        TranscriptCoreCommand::DescribeBgvRnsProfile => {
            crate::bgv::commands::describe_bgv_rns_profile()
        }
        TranscriptCoreCommand::DescribeBgvOperationRegistry => {
            crate::bgv::commands::describe_bgv_operation_registry()
        }
        TranscriptCoreCommand::ValidateBgvEvaluatorOperation => {
            crate::bgv::commands::validate_bgv_evaluator_operation_from_request(request)
        }
        TranscriptCoreCommand::DescribeBgvPassiveSetupObjectModel => {
            crate::bgv::commands::describe_bgv_passive_setup_object_model()
        }
        TranscriptCoreCommand::DescribeCollectiveBgvSetupProfile => {
            crate::bgv::commands::describe_collective_bgv_setup_profile_from_request()
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
        TranscriptCoreCommand::VerifyTrusteeEvaluationKeyProof => {
            crate::bgv::commands::verify_trustee_evaluation_key_proof(request)
        }
        TranscriptCoreCommand::GenerateCompactVssShareLinkageProof => {
            crate::bgv::commands::generate_compact_vss_share_linkage_proof(request)
        }
        TranscriptCoreCommand::VerifyCompactVssShareLinkageProof => {
            crate::bgv::commands::verify_compact_vss_share_linkage_proof(request)
        }
        TranscriptCoreCommand::VerifyCompactVssShareLinkageProofMaterialSet => {
            crate::bgv::commands::verify_compact_vss_share_linkage_proof_material_set(request)
        }
        TranscriptCoreCommand::GenerateCompactSameSecretBridgeProof => {
            crate::bgv::commands::generate_compact_same_secret_bridge_proof(request)
        }
        TranscriptCoreCommand::VerifyCompactSameSecretBridgeProof => {
            crate::bgv::commands::verify_compact_same_secret_bridge_proof(request)
        }
        TranscriptCoreCommand::ComputeSetupCommitmentFromOpening => {
            crate::bgv::commands::compute_setup_commitment_from_opening(request)
        }
        TranscriptCoreCommand::ComputeCompactVssCommitmentFromOpening => {
            crate::bgv::commands::compute_compact_vss_commitment_from_opening(request)
        }
        TranscriptCoreCommand::EncodeCompactVssCommitmentBody => {
            crate::bgv::commands::encode_compact_vss_commitment_body(request)
        }
        TranscriptCoreCommand::DecodeCompactVssCommitmentBody => {
            crate::bgv::commands::decode_compact_vss_commitment_body(request)
        }
        TranscriptCoreCommand::VerifyCompactVssCommitmentOpening => {
            crate::bgv::commands::verify_compact_vss_commitment_opening(request)
        }
        TranscriptCoreCommand::VerifyCompactVssCoefficientCommitmentSet => {
            crate::bgv::commands::verify_compact_vss_coefficient_commitment_set(request)
        }
        TranscriptCoreCommand::VerifyCompactVssRecipientShareCommitmentSet => {
            crate::bgv::commands::verify_compact_vss_recipient_share_commitment_set(request)
        }
        TranscriptCoreCommand::VerifyCompactVssAggregateThresholdCommitmentSet => {
            crate::bgv::commands::verify_compact_vss_aggregate_threshold_commitment_set(request)
        }
        TranscriptCoreCommand::VerifyCompactVssShareLinkageStatement => {
            crate::bgv::commands::verify_compact_vss_share_linkage_statement(request)
        }
        TranscriptCoreCommand::VerifyCompactVssSameSecretBridgeStatementSet => {
            crate::bgv::commands::verify_compact_vss_same_secret_bridge_statement_set(request)
        }
        TranscriptCoreCommand::VerifyCompactVssSameSecretBridgeProofMaterialSet => {
            crate::bgv::commands::verify_compact_vss_same_secret_bridge_proof_material_set(request)
        }
        TranscriptCoreCommand::DeriveThresholdShareCommitments => {
            crate::bgv::commands::derive_threshold_share_commitments(request)
        }
        TranscriptCoreCommand::DeriveThresholdShareCommitmentsFromTransport => {
            crate::bgv::commands::derive_threshold_share_commitments_from_transport(request)
        }
        TranscriptCoreCommand::BeginThresholdShareCommitmentsFromTransportStream => {
            crate::bgv::commands::begin_threshold_share_commitments_from_transport_stream(request)
        }
        TranscriptCoreCommand::AbsorbThresholdShareCommitmentsFromTransportStreamChunk => {
            crate::bgv::commands::absorb_threshold_share_commitments_from_transport_stream_chunk(
                request,
            )
        }
        TranscriptCoreCommand::AbortThresholdShareCommitmentsFromTransportStream => {
            crate::bgv::commands::abort_threshold_share_commitments_from_transport_stream(request)
        }
        TranscriptCoreCommand::FinishThresholdShareCommitmentsFromTransportStream => {
            crate::bgv::commands::finish_threshold_share_commitments_from_transport_stream(request)
        }
        TranscriptCoreCommand::ReleaseVerifiedTransportedVssMaterial => {
            crate::bgv::commands::release_verified_transported_vss_material(request)
        }
        TranscriptCoreCommand::BeginSetupProofMaterialTransportStream => {
            crate::bgv::commands::begin_setup_proof_material_transport_stream(request)
        }
        TranscriptCoreCommand::AbsorbSetupProofMaterialTransportStreamChunk => {
            crate::bgv::commands::absorb_setup_proof_material_transport_stream_chunk(request)
        }
        TranscriptCoreCommand::FinishSetupProofMaterialTransportStream => {
            crate::bgv::commands::finish_setup_proof_material_transport_stream(request)
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
        TranscriptCoreCommand::GenerateBgvCiphertextConventionFixture => {
            crate::bgv::commands::generate_bgv_ciphertext_convention_fixture_from_request(request)
        }
        TranscriptCoreCommand::GenerateBgvBaseConversionFixture => {
            crate::bgv::commands::generate_bgv_base_conversion_fixture_from_request(request)
        }
        TranscriptCoreCommand::AnalyzeBgvCanonicalObject => {
            crate::bgv::commands::analyze_bgv_canonical_object_from_request(request)
        }
        TranscriptCoreCommand::RunDirectEncryptedBallot => {
            crate::bgv::direct_ballots::run_direct_encrypted_ballot(request)
        }
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::GenerateBgvTargetDecryptionDevelopmentFixture => {
            crate::bgv::target_decryption::generate_bgv_target_decryption_development_fixture_from_request(request)
        }
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::GenerateBgvTargetDecryptionShareFromLocalShare => {
            crate::bgv::target_decryption::generate_bgv_target_decryption_share_from_local_share_request(
                request,
            )
        }
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::DeriveBgvTargetDecryptionShareProofStatement => {
            crate::bgv::target_decryption::derive_bgv_target_decryption_share_proof_statement_from_request(
                request,
            )
        }
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness => {
            crate::bgv::target_decryption::generate_bgv_target_decryption_share_proof_material_from_local_witness_request(
                request,
            )
        }
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::VerifyBgvTargetDecryptionShareProofMaterial => {
            crate::bgv::target_decryption::verify_bgv_target_decryption_share_proof_material_from_request(
                request,
            )
        }
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::VerifyBgvTargetDecryptionShareBinaryProofMaterial => {
            crate::bgv::target_decryption::verify_bgv_target_decryption_share_binary_proof_material_from_request(
                request,
            )
        }
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::VerifyBgvTargetDecryptionShareProofStatementBinding => {
            crate::bgv::target_decryption::verify_bgv_target_decryption_share_proof_statement_binding_from_request(
                request,
            )
        }
        #[cfg(feature = "target-decryption-development-commands")]
        TranscriptCoreCommand::VerifyAndReleaseBgvTargetDecryptionResult => {
            crate::bgv::target_decryption::verify_and_release_bgv_target_decryption_result_from_request(
                request,
            )
        }
        _ => unreachable!("non-BGV command dispatched to BGV handler"),
    }
}

fn read_string_field<'a>(request: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    request
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })
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
