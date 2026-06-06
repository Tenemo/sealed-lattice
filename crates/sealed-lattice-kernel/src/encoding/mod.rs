use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    fixtures::{TranscriptCoreFixture, verify_fixture},
    hashing::{RESERVED_ROOT_NAMESPACES, chunk_root, derive_protocol_hash, hash512_hex},
    ring::{
        MAXIMUM_SHAMIR_INTERPOLATION_POINTS, ShamirSharePoint, evaluate_plaintext_comparison,
        interpolate_shamir_constant_term,
    },
    transcript_core::analyze_canonical_object_hex,
};

#[cfg(test)]
pub const MODULE_MARKER: &str = "encoding";
pub const TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION: &str =
    "sealed-lattice-transcript-core-command-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CanonicalErrorCode {
    DuplicateField,
    FieldOrder,
    FixtureMismatch,
    InvalidChunkSize,
    InvalidEnum,
    InvalidFixture,
    InvalidHex,
    InvalidUtf8,
    MalformedLength,
    MalformedMagic,
    MalformedVarUint,
    MissingField,
    NonCanonicalVarUint,
    ProfileComponentMismatch,
    TrailingBytes,
    UnknownField,
    UnknownBaseClaimProfile,
    UnknownMheSecurityClosure,
    UnknownProofProfile,
    UnsupportedCanonicalEnvelopeVersion,
    UnsupportedObjectType,
    UnsupportedObjectVersion,
}

/// All canonical error code variants in declaration order.
///
/// Adding a new variant to `CanonicalErrorCode` requires extending this slice
/// and the exhaustive `match` in `all_canonical_error_codes_is_exhaustive`.
/// The compiler enforces both.
pub const ALL_CANONICAL_ERROR_CODES: &[CanonicalErrorCode] = &[
    CanonicalErrorCode::DuplicateField,
    CanonicalErrorCode::FieldOrder,
    CanonicalErrorCode::FixtureMismatch,
    CanonicalErrorCode::InvalidChunkSize,
    CanonicalErrorCode::InvalidEnum,
    CanonicalErrorCode::InvalidFixture,
    CanonicalErrorCode::InvalidHex,
    CanonicalErrorCode::InvalidUtf8,
    CanonicalErrorCode::MalformedLength,
    CanonicalErrorCode::MalformedMagic,
    CanonicalErrorCode::MalformedVarUint,
    CanonicalErrorCode::MissingField,
    CanonicalErrorCode::NonCanonicalVarUint,
    CanonicalErrorCode::ProfileComponentMismatch,
    CanonicalErrorCode::TrailingBytes,
    CanonicalErrorCode::UnknownField,
    CanonicalErrorCode::UnknownBaseClaimProfile,
    CanonicalErrorCode::UnknownMheSecurityClosure,
    CanonicalErrorCode::UnknownProofProfile,
    CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion,
    CanonicalErrorCode::UnsupportedObjectType,
    CanonicalErrorCode::UnsupportedObjectVersion,
];

impl CanonicalErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DuplicateField => "DuplicateField",
            Self::FieldOrder => "FieldOrder",
            Self::FixtureMismatch => "FixtureMismatch",
            Self::InvalidChunkSize => "InvalidChunkSize",
            Self::InvalidEnum => "InvalidEnum",
            Self::InvalidFixture => "InvalidFixture",
            Self::InvalidHex => "InvalidHex",
            Self::InvalidUtf8 => "InvalidUtf8",
            Self::MalformedLength => "MalformedLength",
            Self::MalformedMagic => "MalformedMagic",
            Self::MalformedVarUint => "MalformedVarUint",
            Self::MissingField => "MissingField",
            Self::NonCanonicalVarUint => "NonCanonicalVarUint",
            Self::ProfileComponentMismatch => "ProfileComponentMismatch",
            Self::TrailingBytes => "TrailingBytes",
            Self::UnknownField => "UnknownField",
            Self::UnknownBaseClaimProfile => "UnknownBaseClaimProfile",
            Self::UnknownMheSecurityClosure => "UnknownMheSecurityClosure",
            Self::UnknownProofProfile => "UnknownProofProfile",
            Self::UnsupportedCanonicalEnvelopeVersion => "UnsupportedCanonicalEnvelopeVersion",
            Self::UnsupportedObjectType => "UnsupportedObjectType",
            Self::UnsupportedObjectVersion => "UnsupportedObjectVersion",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError {
    pub code: CanonicalErrorCode,
    pub message: String,
}

impl CanonicalError {
    pub fn new(code: CanonicalErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn to_json_value(&self) -> Value {
        json!({
            "code": self.code.as_str(),
            "message": self.message,
        })
    }
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for CanonicalError {}

pub type CanonicalResult<T> = Result<T, CanonicalError>;

pub fn roundtrip_bytes(input: &[u8]) -> Vec<u8> {
    input.to_vec()
}

// LEB128: 7 payload bits per byte, high bit set marks a continuation byte.
pub fn encode_varuint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
    output
}

pub fn append_varuint(output: &mut Vec<u8>, value: u64) {
    output.extend(encode_varuint(value));
}

pub fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    append_varuint(output, value.len() as u64);
    output.extend(value);
}

pub fn append_string(output: &mut Vec<u8>, value: &str) {
    append_bytes(output, value.as_bytes());
}

pub struct CanonicalReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CanonicalReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    pub fn read_exact(&mut self, length: usize) -> CanonicalResult<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            CanonicalError::new(CanonicalErrorCode::MalformedLength, "length overflow")
        })?;
        if end > self.bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "length exceeds remaining bytes",
            ));
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;

        Ok(slice)
    }

    pub fn read_varuint(&mut self) -> CanonicalResult<u64> {
        let start = self.offset;
        let mut shift = 0_u32;
        let mut value = 0_u64;

        for index in 0..10 {
            if self.offset >= self.bytes.len() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedVarUint,
                    "varuint is truncated",
                ));
            }

            let byte = self.bytes[self.offset];
            self.offset += 1;
            let payload = u64::from(byte & 0x7f);
            // 10th byte (index 9) carries only 1 usable bit of a u64; payload > 1
            // would overflow, so reject it.
            if index == 9 && payload > 1 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedVarUint,
                    "varuint exceeds u64",
                ));
            }
            value |= payload << shift;

            if byte & 0x80 == 0 {
                // Enforce minimal/canonical encoding: re-encode the decoded value
                // and require the consumed bytes to match exactly.
                let consumed = &self.bytes[start..self.offset];
                if consumed != encode_varuint(value).as_slice() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::NonCanonicalVarUint,
                        "varuint is not minimally encoded",
                    ));
                }

                return Ok(value);
            }

            shift += 7;
        }

        Err(CanonicalError::new(
            CanonicalErrorCode::MalformedVarUint,
            "varuint is too long",
        ))
    }

    pub fn read_bytes(&mut self) -> CanonicalResult<Vec<u8>> {
        let length = usize::try_from(self.read_varuint()?).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "length does not fit usize",
            )
        })?;

        Ok(self.read_exact(length)?.to_vec())
    }

    pub fn read_string(&mut self) -> CanonicalResult<String> {
        String::from_utf8(self.read_bytes()?).map_err(|_| {
            CanonicalError::new(CanonicalErrorCode::InvalidUtf8, "string is not valid UTF-8")
        })
    }
}

pub fn encode_success(value: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "success": true,
        "value": value,
    }))
    .expect("serializing command success response should not fail")
}

pub fn encode_error(error: CanonicalError) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "success": false,
        "error": error.to_json_value(),
    }))
    .expect("serializing command error response should not fail")
}

pub fn run_transcript_core_command(input: &[u8]) -> Vec<u8> {
    let command_result = run_transcript_core_command_inner(input);

    match command_result {
        Ok(value) => encode_success(value),
        Err(error) => encode_error(error),
    }
}

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
    DescribeBallotPrivacyProofBackend,
    VerifyBallotPrivacyLinearProofVector,
    VerifyBallotPrivacyEncodedRelationVector,
    VerifyBallotPrivacyReceiverKeyVector,
    VerifyReceiverKeyProof,
    PrepareReceiverKeyProofGeneration,
    GenerateReceiverKeyProof,
    GenerateBallotProof,
    GenerateBallotComponentProof,
    GenerateBallotProofRecord,
    VerifyBallotProof,
    VerifyClaimBearingBallotPackage,
    GenerateAggregateDerivationProof,
    VerifyAggregateDerivationProof,
    GenerateAggregateBridgeEncryption,
    VerifyAggregateBridgeEncryption,
    EvaluateAggregateBridgeRelation,
    DescribeBgvRnsProfile,
    DescribeBgvOperationRegistry,
    ValidateBgvEvaluatorOperation,
    DescribeMaskedRankRefreshProfile,
    VerifyMaskedRankRefreshTranscript,
    DescribeBgvPassiveSetupObjectModel,
    GenerateBgvPassiveSetup,
    VerifyBgvPassiveSetup,
    GenerateBgvEvaluationKeyMaterial,
    PrepareBgvEvaluationKeyMaterial,
    EncodeBgvBatchPlaintext,
    ValidateBgvPlaintextObject,
    ValidateBgvCiphertextObject,
    GenerateBgvCiphertextConventionFixture,
    GenerateBgvBaseConversionFixture,
    AnalyzeBgvCanonicalObject,
    RejectBgvReferenceOracleArtifact,
    RunDevelopmentTopKEvaluation,
    RunEncryptedAggregateTopKEvaluation,
    RunEncryptedAggregateTopKEvaluationSweep,
}

fn parse_transcript_core_command(command_name: &str) -> CanonicalResult<TranscriptCoreCommand> {
    serde_json::from_value(json!({ "command": command_name })).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("unsupported command: {command_name}"),
        )
    })
}

fn run_transcript_core_command_inner(input: &[u8]) -> CanonicalResult<Value> {
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
        TranscriptCoreCommand::DescribeBallotPrivacyProofBackend
        | TranscriptCoreCommand::VerifyBallotPrivacyLinearProofVector
        | TranscriptCoreCommand::VerifyBallotPrivacyEncodedRelationVector
        | TranscriptCoreCommand::VerifyBallotPrivacyReceiverKeyVector
        | TranscriptCoreCommand::VerifyReceiverKeyProof
        | TranscriptCoreCommand::PrepareReceiverKeyProofGeneration
        | TranscriptCoreCommand::GenerateReceiverKeyProof
        | TranscriptCoreCommand::GenerateBallotProof
        | TranscriptCoreCommand::GenerateBallotComponentProof
        | TranscriptCoreCommand::GenerateBallotProofRecord
        | TranscriptCoreCommand::VerifyBallotProof
        | TranscriptCoreCommand::VerifyClaimBearingBallotPackage
        | TranscriptCoreCommand::GenerateAggregateDerivationProof
        | TranscriptCoreCommand::VerifyAggregateDerivationProof
        | TranscriptCoreCommand::GenerateAggregateBridgeEncryption
        | TranscriptCoreCommand::VerifyAggregateBridgeEncryption
        | TranscriptCoreCommand::EvaluateAggregateBridgeRelation => {
            run_ballot_privacy_command(command, &request)
        }
        TranscriptCoreCommand::DescribeBgvRnsProfile
        | TranscriptCoreCommand::DescribeBgvOperationRegistry
        | TranscriptCoreCommand::ValidateBgvEvaluatorOperation
        | TranscriptCoreCommand::DescribeMaskedRankRefreshProfile
        | TranscriptCoreCommand::VerifyMaskedRankRefreshTranscript
        | TranscriptCoreCommand::DescribeBgvPassiveSetupObjectModel
        | TranscriptCoreCommand::GenerateBgvPassiveSetup
        | TranscriptCoreCommand::VerifyBgvPassiveSetup
        | TranscriptCoreCommand::GenerateBgvEvaluationKeyMaterial
        | TranscriptCoreCommand::PrepareBgvEvaluationKeyMaterial
        | TranscriptCoreCommand::EncodeBgvBatchPlaintext
        | TranscriptCoreCommand::ValidateBgvPlaintextObject
        | TranscriptCoreCommand::ValidateBgvCiphertextObject
        | TranscriptCoreCommand::GenerateBgvCiphertextConventionFixture
        | TranscriptCoreCommand::GenerateBgvBaseConversionFixture
        | TranscriptCoreCommand::AnalyzeBgvCanonicalObject
        | TranscriptCoreCommand::RejectBgvReferenceOracleArtifact
        | TranscriptCoreCommand::RunDevelopmentTopKEvaluation
        | TranscriptCoreCommand::RunEncryptedAggregateTopKEvaluation
        | TranscriptCoreCommand::RunEncryptedAggregateTopKEvaluationSweep => {
            run_bgv_command(command, &request)
        }
    }
}

fn run_ballot_privacy_command(
    command: TranscriptCoreCommand,
    request: &Value,
) -> CanonicalResult<Value> {
    match command {
        TranscriptCoreCommand::DescribeBallotPrivacyProofBackend => {
            Ok(crate::ballot_privacy::describe_proof_backend())
        }
        TranscriptCoreCommand::VerifyBallotPrivacyLinearProofVector => {
            let vector_case = request.get("vectorCase").ok_or_else(|| {
                CanonicalError::new(CanonicalErrorCode::InvalidFixture, "vectorCase is required")
            })?;

            Ok(crate::ballot_privacy::verify_linear_proof_vector_case(
                vector_case,
            ))
        }
        TranscriptCoreCommand::VerifyBallotPrivacyEncodedRelationVector => {
            let vector_case = request.get("vectorCase").ok_or_else(|| {
                CanonicalError::new(CanonicalErrorCode::InvalidFixture, "vectorCase is required")
            })?;

            Ok(crate::ballot_privacy::verify_encoded_relation_vector_case(
                vector_case,
            ))
        }
        TranscriptCoreCommand::VerifyBallotPrivacyReceiverKeyVector => {
            let vector_case = request.get("vectorCase").ok_or_else(|| {
                CanonicalError::new(CanonicalErrorCode::InvalidFixture, "vectorCase is required")
            })?;

            Ok(crate::ballot_privacy::verify_receiver_key_vector_case(
                vector_case,
            ))
        }
        TranscriptCoreCommand::VerifyReceiverKeyProof => {
            Ok(crate::ballot_privacy::verify_receiver_key_proof_from_command_request(request))
        }
        TranscriptCoreCommand::PrepareReceiverKeyProofGeneration => Ok(
            crate::ballot_privacy::prepare_receiver_key_proof_generation_from_command_request(
                request,
            ),
        ),
        TranscriptCoreCommand::GenerateReceiverKeyProof => {
            Ok(crate::ballot_privacy::generate_receiver_key_proof_from_command_request(request))
        }
        TranscriptCoreCommand::GenerateBallotProof => {
            Ok(crate::ballot_privacy::generate_ballot_proof_from_command_request(request))
        }
        TranscriptCoreCommand::GenerateBallotComponentProof => Ok(
            crate::ballot_privacy::generate_ballot_component_proof_from_command_request(request),
        ),
        TranscriptCoreCommand::GenerateBallotProofRecord => {
            Ok(crate::ballot_privacy::generate_ballot_proof_record_from_command_request(request))
        }
        TranscriptCoreCommand::VerifyBallotProof => {
            Ok(crate::ballot_privacy::verify_ballot_proof_from_command_request(request))
        }
        TranscriptCoreCommand::VerifyClaimBearingBallotPackage => {
            let ballot_package = request.get("ballotPackage").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "ballotPackage is required",
                )
            })?;
            let casual_micro_roster_acknowledged = request
                .get("casualMicroRosterAcknowledged")
                .and_then(Value::as_bool)
                == Some(true);
            let dynamic_roster_profile_evidence = request.get("dynamicRosterProfileEvidence");

            Ok(crate::ballot_privacy::verify_claim_bearing_ballot_package(
                ballot_package,
                dynamic_roster_profile_evidence,
                casual_micro_roster_acknowledged,
            ))
        }
        TranscriptCoreCommand::GenerateAggregateDerivationProof => Ok(
            crate::ballot_privacy::generate_aggregate_derivation_proof_from_command_request(
                request,
            ),
        ),
        TranscriptCoreCommand::VerifyAggregateDerivationProof => Ok(
            crate::ballot_privacy::verify_aggregate_derivation_proof_from_command_request(request),
        ),
        TranscriptCoreCommand::GenerateAggregateBridgeEncryption => Ok(
            crate::ballot_privacy::generate_aggregate_bridge_encryption_from_command_request(
                request,
            ),
        ),
        TranscriptCoreCommand::VerifyAggregateBridgeEncryption => Ok(
            crate::ballot_privacy::verify_aggregate_bridge_encryption_from_command_request(request),
        ),
        TranscriptCoreCommand::EvaluateAggregateBridgeRelation => Ok(
            crate::ballot_privacy::evaluate_aggregate_bridge_relation_from_command_request(request),
        ),
        _ => unreachable!("non-ballot command dispatched to ballot privacy handler"),
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
        TranscriptCoreCommand::DescribeMaskedRankRefreshProfile => {
            crate::bgv::commands::describe_masked_rank_refresh_profile()
        }
        TranscriptCoreCommand::VerifyMaskedRankRefreshTranscript => {
            crate::bgv::commands::verify_masked_rank_refresh_transcript_from_request(request)
        }
        TranscriptCoreCommand::DescribeBgvPassiveSetupObjectModel => {
            crate::bgv::commands::describe_bgv_passive_setup_object_model()
        }
        TranscriptCoreCommand::GenerateBgvPassiveSetup => {
            crate::bgv::commands::generate_bgv_passive_setup_from_request(request)
        }
        TranscriptCoreCommand::VerifyBgvPassiveSetup => {
            crate::bgv::commands::verify_bgv_passive_setup_from_request(request)
        }
        TranscriptCoreCommand::GenerateBgvEvaluationKeyMaterial => {
            crate::bgv::commands::generate_bgv_evaluation_key_material_from_request(request)
        }
        TranscriptCoreCommand::PrepareBgvEvaluationKeyMaterial => {
            crate::bgv::evaluator::commands::prepare_bgv_evaluation_key_material_handle(request)
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
        TranscriptCoreCommand::RejectBgvReferenceOracleArtifact => {
            Ok(crate::bgv::commands::reject_bgv_reference_oracle_artifact_from_request(request))
        }
        TranscriptCoreCommand::RunDevelopmentTopKEvaluation => {
            crate::bgv::evaluator::commands::run_development_top_k_evaluation(request)
        }
        TranscriptCoreCommand::RunEncryptedAggregateTopKEvaluation => {
            crate::bgv::evaluator::commands::run_encrypted_aggregate_top_k_evaluation(request)
        }
        TranscriptCoreCommand::RunEncryptedAggregateTopKEvaluationSweep => {
            crate::bgv::evaluator::commands::run_encrypted_aggregate_top_k_evaluation_sweep(request)
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

#[cfg(test)]
mod tests {
    use super::{
        CanonicalErrorCode, CanonicalReader, append_varuint, encode_error, encode_varuint,
    };

    #[test]
    fn varuint_round_trips_boundary_values() {
        for value in [0, 1, 2, 127, 128, 255, 16_384, u32::MAX as u64, u64::MAX] {
            let encoded = encode_varuint(value);
            let mut reader = CanonicalReader::new(&encoded);

            assert_eq!(reader.read_varuint().expect("value should decode"), value);
            assert!(reader.is_finished());
        }
    }

    #[test]
    fn rejects_non_canonical_varuint() {
        let mut reader = CanonicalReader::new(&[0x80, 0x00]);
        let error = reader
            .read_varuint()
            .expect_err("redundant varuint should fail");

        assert_eq!(error.code, CanonicalErrorCode::NonCanonicalVarUint);
    }

    #[test]
    fn append_varuint_uses_canonical_encoding() {
        let mut output = Vec::new();
        append_varuint(&mut output, 128);

        assert_eq!(output, vec![0x80, 0x01]);
    }

    #[test]
    fn command_errors_are_json_encoded() {
        let encoded = encode_error(super::CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "bad command",
        ));
        let response = String::from_utf8(encoded).expect("error should be UTF-8 JSON");

        assert!(response.contains("\"success\":false"));
        assert!(response.contains("\"InvalidFixture\""));
    }

    #[test]
    fn command_rejects_missing_command_with_stable_message() {
        let error = super::run_transcript_core_command_inner(br#"{}"#)
            .expect_err("missing command should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert_eq!(error.message, "command must be a string");
    }

    #[test]
    fn command_rejects_unknown_command_with_stable_message() {
        let error = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "NotACommand"
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("unknown command should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert_eq!(error.message, "unsupported command: NotACommand");
    }

    #[test]
    fn command_derives_protocol_hash_with_kernel_canonical_json() {
        let response = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "DeriveProtocolHash",
                "namespace": "PollSpecHash",
                "value": {
                    "poll": "main"
                }
            })
            .to_string()
            .as_bytes(),
        )
        .expect("protocol hash command should succeed");

        assert_eq!(
            response["protocolHash"],
            "43b28c9a3dcb3e34d75c9936a9930b68fb9f2010b87d43a6a61cbaa85d343d9fd0be2b312a90f404367b9c68793b0dcf02c4dae7351f6e96ded894b92f898cb4"
        );
    }

    #[test]
    fn command_exposes_kernel_field_interpolation() {
        let response = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "InterpolateShamirConstantTerm",
                "sharePoints": [
                    { "rosterPosition": 1, "value": 15 },
                    { "rosterPosition": 2, "value": 25 }
                ]
            })
            .to_string()
            .as_bytes(),
        )
        .expect("field interpolation command should succeed");

        assert_eq!(response["fieldElement"], 5);
    }

    #[test]
    fn command_exposes_plaintext_comparison() {
        let response = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "EvaluatePlaintextComparison",
                "leftTotalScore": 41,
                "rightTotalScore": 40,
                "rosterSize": 5
            })
            .to_string()
            .as_bytes(),
        )
        .expect("plaintext comparison command should succeed");

        assert_eq!(response["greaterThan"], 1);
        assert_eq!(response["equal"], 0);
        assert_eq!(response["scoreDifference"], 1);
    }

    #[test]
    fn command_rejects_duplicate_encrypted_evaluation_sweep_counts_before_setup_loading() {
        let error = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "RunEncryptedAggregateTopKEvaluationSweep",
                "topCounts": [1, 1],
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("duplicate sweep top-counts should fail before setup loading");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert_eq!(error.message, "topCounts must not contain duplicate values");
    }

    #[test]
    fn all_canonical_error_codes_is_exhaustive() {
        // The compiler enforces exhaustiveness here. If a new variant is added
        // to `CanonicalErrorCode`, this match fails and the dev must extend
        // both the match arm and `ALL_CANONICAL_ERROR_CODES`.
        fn ensure_exhaustive(code: CanonicalErrorCode) {
            match code {
                CanonicalErrorCode::DuplicateField
                | CanonicalErrorCode::FieldOrder
                | CanonicalErrorCode::FixtureMismatch
                | CanonicalErrorCode::InvalidChunkSize
                | CanonicalErrorCode::InvalidEnum
                | CanonicalErrorCode::InvalidFixture
                | CanonicalErrorCode::InvalidHex
                | CanonicalErrorCode::InvalidUtf8
                | CanonicalErrorCode::MalformedLength
                | CanonicalErrorCode::MalformedMagic
                | CanonicalErrorCode::MalformedVarUint
                | CanonicalErrorCode::MissingField
                | CanonicalErrorCode::NonCanonicalVarUint
                | CanonicalErrorCode::ProfileComponentMismatch
                | CanonicalErrorCode::TrailingBytes
                | CanonicalErrorCode::UnknownField
                | CanonicalErrorCode::UnknownBaseClaimProfile
                | CanonicalErrorCode::UnknownMheSecurityClosure
                | CanonicalErrorCode::UnknownProofProfile
                | CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion
                | CanonicalErrorCode::UnsupportedObjectType
                | CanonicalErrorCode::UnsupportedObjectVersion => {}
            }
        }

        for code in super::ALL_CANONICAL_ERROR_CODES {
            ensure_exhaustive(code.clone());
        }

        assert_eq!(super::ALL_CANONICAL_ERROR_CODES.len(), 22);
    }
}
