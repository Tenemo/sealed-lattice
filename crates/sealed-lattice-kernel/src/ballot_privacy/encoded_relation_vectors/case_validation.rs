use super::backend_hash_helpers::value_without_field as encoded_relation_value_without_field;
use super::*;
use crate::ballot_privacy::protocol_constants::{
    BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION, BALLOT_PRIVACY_FIELD_MODULUS,
};
use serde_json::{Value, json};

use crate::hashing::derive_protocol_hash;

pub(super) const ENCODED_COORDINATES_PER_OPTION: u64 =
    BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION;
pub(super) const FIELD_MODULUS: u64 = BALLOT_PRIVACY_FIELD_MODULUS;
pub(super) const RELATION_STATEMENT_FORMAT: &str =
    "SparseIntegerRowsModuloGF65537WithBoundGadgets-v1";
pub(super) const RELATION_STATEMENT_HASH_PURPOSE: &str =
    "ballot-privacy-linear-relation-statement-v1";
pub(super) const BACKEND_STATEMENT_FORMAT: &str = "SparseSignedIntegerBackendStatement-v1";
pub(super) const BACKEND_STATEMENT_HASH_PURPOSE: &str = "ballot-privacy-backend-statement-v1";
pub(super) const EXPLICIT_BACKEND_MATRIX_HASH_PURPOSE: &str =
    "ballot-privacy-backend-explicit-matrix-v1";
pub(super) const EXPLICIT_BACKEND_TARGET_VECTOR_HASH_PURPOSE: &str =
    "ballot-privacy-backend-explicit-target-vector-v1";
pub(super) const HASH_EXPANDED_BACKEND_MATRIX_HASH_PURPOSE: &str =
    "ballot-privacy-backend-hash-expanded-matrix-v1";
pub(super) const HASH_EXPANDED_BACKEND_TARGET_VECTOR_HASH_PURPOSE: &str =
    "ballot-privacy-backend-hash-expanded-target-vector-v1";
pub(super) const BACKEND_MATRIX_HASH_PURPOSE: &str = "ballot-privacy-backend-matrix-v1";
pub(super) const BACKEND_TARGET_VECTOR_HASH_PURPOSE: &str =
    "ballot-privacy-backend-target-vector-v1";
pub(super) const BACKEND_BOUNDS_HASH_PURPOSE: &str = "ballot-privacy-backend-bounds-v1";
pub(super) const BACKEND_PROOF_COMPONENTS_HASH_PURPOSE: &str =
    "ballot-privacy-backend-proof-components-v1";
pub(super) const ALGEBRAIC_ROWS_PER_RECEIVER: u64 = 3;
pub(super) const EXPLICIT_ROW_BATCHES_BEFORE_ALGEBRAIC_ROWS: u64 = 2;
pub(super) const EXPLICIT_ROW_BATCHES_WITH_SHARE_COMMITMENT_ROWS: u64 = 3;
pub(super) const OPENING_VARIABLES_PER_RECEIVER: u64 = 64;
pub(super) const ENCRYPTION_BATCH_VARIABLES_PER_RECEIVER: u64 = 2;
pub(super) const SHARE_COMMITMENT_EQUATION_ROWS: u64 = 1_024;
pub(super) const RECEIVER_ENCRYPTION_EQUATION_ROWS: u64 = 1_280;
pub(super) const RECEIVER_KEY_EQUATION_ROWS: u64 = 1_024;
pub(super) const RECEIVER_SHARE_REPRESENTATIVE_BIT_LENGTH: u64 = 17;
pub(super) const RECEIVER_OPENING_RANDOMNESS_BIT_LENGTH: u64 = 12;

pub fn verify_encoded_relation_vector_case_value(vector_case: &Value) -> Value {
    let validation_result = validate_encoded_relation_vector_case(vector_case);

    match validation_result {
        Ok(summary) => json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": summary.case_name,
            "vectorAvailable": true,
            "expectedOutcome": summary.expected_outcome,
            "statusLabels": summary.status_labels,
            "acceptedHashes": summary.accepted_hashes,
            "refusedObjects": [],
            "unresolvedReason": Value::Null
        }),
        Err(message) => json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "statusLabels": [],
            "acceptedHashes": [],
            "refusedObjects": [
                {
                    "code": "InvalidFixture",
                    "message": message
                }
            ],
            "unresolvedReason": "InvalidFixture"
        }),
    }
}

pub(super) struct EncodedRelationVectorSummary {
    accepted_hashes: Vec<String>,
    case_name: String,
    expected_outcome: String,
    status_labels: Vec<&'static str>,
}

pub(super) fn validate_encoded_relation_vector_case(
    vector_case: &Value,
) -> Result<EncodedRelationVectorSummary, String> {
    let case_object = object_field(vector_case, "")?;
    let case_name = string_property(case_object, "caseName")?;
    let expected_outcome = string_property(case_object, "expectedOutcome")?;
    let compiler_accepted = bool_property(case_object, "compilerAccepted")?;

    if case_name.is_empty() {
        return Err("encoded relation vector caseName must not be empty".to_string());
    }
    if !matches!(expected_outcome.as_str(), "accept" | "reject") {
        return Err("encoded relation expectedOutcome must be accept or reject".to_string());
    }

    if compiler_accepted && expected_outcome == "accept" {
        let accepted_hash = validate_accepting_case(case_object)?;
        validate_hash_change_trace(case_object, &accepted_hash)?;

        Ok(EncodedRelationVectorSummary {
            accepted_hashes: vec![accepted_hash],
            case_name,
            expected_outcome,
            status_labels: vec![
                "EncodedRelationStatementParsed",
                "EncodedShareLayoutChecked",
                "EncodedBackendStatementChecked",
                "EncodedRelationHashRecomputed",
            ],
        })
    } else if compiler_accepted && expected_outcome == "reject" {
        validate_preflight_rejecting_case(case_object)?;

        Ok(EncodedRelationVectorSummary {
            accepted_hashes: Vec::new(),
            case_name,
            expected_outcome,
            status_labels: vec![
                "EncodedRelationCompilerAccepted",
                "EncodedBackendStatementRejectVectorChecked",
            ],
        })
    } else {
        validate_rejecting_case(case_object, &expected_outcome)?;

        Ok(EncodedRelationVectorSummary {
            accepted_hashes: Vec::new(),
            case_name,
            expected_outcome,
            status_labels: vec![
                "EncodedRelationCompilerRefusalRecorded",
                "EncodedRelationRejectVectorChecked",
            ],
        })
    }
}

pub(super) fn validate_accepting_case(
    case_object: &serde_json::Map<String, Value>,
) -> Result<String, String> {
    let full_statement = case_object.get("loweredStatement");
    let statement_summary = case_object.get("loweredStatementSummary");

    let accepted_hash = match (full_statement, statement_summary) {
        (Some(statement), None) => validate_full_statement(statement),
        (None, Some(summary)) => validate_statement_summary(summary, case_object),
        (Some(_), Some(_)) => Err(
            "encoded relation accept vector must not include both full statement and summary"
                .to_string(),
        ),
        (None, None) => Err(
            "encoded relation accept vector requires a lowered statement or summary".to_string(),
        ),
    }?;
    validate_component_projection_summaries(case_object)?;
    validate_explicit_component_verification_summaries(case_object)?;
    validate_component_proof_readiness_manifests(case_object)?;
    validate_component_proof_statement_plans(case_object)?;

    Ok(accepted_hash)
}

pub(super) fn validate_preflight_rejecting_case(
    case_object: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    if !case_object.contains_key("loweredStatement") {
        return Err(
            "encoded relation backend preflight reject vector requires a lowered statement"
                .to_string(),
        );
    }
    let trace = object_property(case_object, "trace")?;
    if string_property(trace, "expectedLogicalRejectionLayer")? != "backend-statement-preflight" {
        return Err(
            "encoded relation backend preflight reject vector must name the backend preflight layer"
                .to_string(),
        );
    }
    if let Ok(unexpected_hash) = validate_accepting_case(case_object) {
        return Err(format!(
            "encoded relation backend preflight reject vector unexpectedly validated with hash {unexpected_hash}"
        ));
    }

    Ok(())
}

pub(super) fn validate_rejecting_case(
    case_object: &serde_json::Map<String, Value>,
    expected_outcome: &str,
) -> Result<(), String> {
    if expected_outcome != "reject" {
        return Err(
            "encoded relation rejected vectors must declare expectedOutcome reject".to_string(),
        );
    }
    if case_object.contains_key("loweredStatement")
        || case_object.contains_key("loweredStatementSummary")
    {
        return Err(
            "encoded relation reject vector must not include a lowered statement".to_string(),
        );
    }
    let refusal_messages = array_property(case_object, "refusalMessages")?;
    if refusal_messages.is_empty() {
        return Err("encoded relation reject vector must record refusal messages".to_string());
    }
    if !refusal_messages.iter().all(Value::is_string) {
        return Err("encoded relation refusal messages must be strings".to_string());
    }
    let trace = object_property(case_object, "trace")?;
    if string_property(trace, "expectedLogicalRejectionLayer")? != "relation-compiler" {
        return Err(
            "encoded relation reject vector must name the relation compiler rejection layer"
                .to_string(),
        );
    }

    Ok(())
}

pub(super) fn validate_full_statement(statement: &Value) -> Result<String, String> {
    reject_forbidden_witness_keys(statement)?;
    let statement_object = object_field(statement, "loweredStatement")?;
    let option_count = u64_property(statement_object, "optionCount")?;
    let roster_size = u64_property(statement_object, "rosterSize")?;
    let pvss_threshold = u64_property(statement_object, "pvssThreshold")?;
    let share_vector_width = u64_property(statement_object, "shareVectorWidth")?;
    let encoded_coordinate_count = u64_property(statement_object, "encodedCoordinateCount")?;
    let linear_rows = array_property(statement_object, "linearRows")?;
    let algebraic_rows = array_property(statement_object, "algebraicRows")?;
    let variables = array_property(statement_object, "variables")?;
    let bounds = array_property(statement_object, "bounds")?;
    let backend_statement = object_property(statement_object, "backendStatement")?;
    let relation_statement_hash = string_property(statement_object, "relationStatementHash")?;

    validate_statement_dimensions(EncodedRelationDimensions {
        option_count,
        roster_size,
        pvss_threshold,
        share_vector_width,
        encoded_coordinate_count,
        linear_row_count: linear_rows.len() as u64,
        algebraic_row_count: algebraic_rows.len() as u64,
        variable_count: variables.len() as u64,
        bound_count: bounds.len() as u64,
    })?;
    if string_property(statement_object, "objectType")? != "BallotPrivacyLinearRelationStatement"
        || u64_property(statement_object, "objectVersion")? != 1
        || string_property(statement_object, "relationStatementFormat")?
            != RELATION_STATEMENT_FORMAT
        || u64_property(statement_object, "fieldModulus")? != FIELD_MODULUS
    {
        return Err("encoded relation full statement has an invalid canonical shape".to_string());
    }
    validate_row_kinds(linear_rows)?;
    validate_algebraic_row_kinds(algebraic_rows)?;
    validate_backend_statement(
        backend_statement,
        EncodedRelationDimensions {
            option_count,
            roster_size,
            pvss_threshold,
            share_vector_width,
            encoded_coordinate_count,
            linear_row_count: linear_rows.len() as u64,
            algebraic_row_count: algebraic_rows.len() as u64,
            variable_count: variables.len() as u64,
            bound_count: bounds.len() as u64,
        },
    )?;
    let statement_payload =
        encoded_relation_value_without_field(statement, "relationStatementHash")?;
    let expected_hash = derive_protocol_hash(
        "ChallengeDomainHash",
        &json!({
            "purpose": RELATION_STATEMENT_HASH_PURPOSE,
            "statementPayload": statement_payload,
        }),
    )
    .map_err(|error| format!("encoded relation hash could not be recomputed: {error}"))?;

    if expected_hash != relation_statement_hash {
        return Err(
            "encoded relation statement hash does not match its canonical payload".to_string(),
        );
    }

    Ok(relation_statement_hash)
}

pub(super) fn validate_statement_summary(
    summary: &Value,
    case_object: &serde_json::Map<String, Value>,
) -> Result<String, String> {
    reject_forbidden_witness_keys(summary)?;
    let summary_object = object_field(summary, "loweredStatementSummary")?;
    let trace = object_property(case_object, "trace")?;
    let option_count = u64_property(summary_object, "optionCount")?;
    let roster_size = u64_property(summary_object, "rosterSize")?;
    let pvss_threshold = u64_property(trace, "pvssThreshold")?;
    let share_vector_width = u64_property(summary_object, "shareVectorWidth")?;
    let encoded_coordinate_count = u64_property(summary_object, "encodedCoordinateCount")?;
    let linear_row_count = u64_property(summary_object, "linearRowCount")?;
    let algebraic_row_count = u64_property(summary_object, "algebraicRowCount")?;
    let variable_count = u64_property(summary_object, "variableCount")?;
    let bound_count = u64_property(summary_object, "boundCount")?;
    let backend_column_count = u64_property(summary_object, "backendColumnCount")?;
    let backend_explicit_row_count = u64_property(summary_object, "backendExplicitRowCount")?;
    let backend_hash_expanded_row_count =
        u64_property(summary_object, "backendHashExpandedRowCount")?;
    let backend_proof_component_count = u64_property(summary_object, "backendProofComponentCount")?;
    let backend_row_count = u64_property(summary_object, "backendRowCount")?;
    let backend_row_batch_count = u64_property(summary_object, "backendRowBatchCount")?;
    let relation_statement_hash = string_property(summary_object, "relationStatementHash")?;
    let backend_statement_hash = string_property(summary_object, "backendStatementHash")?;
    let first_linear_row = object_property(summary_object, "firstLinearRow")?;
    let last_linear_row = object_property(summary_object, "lastLinearRow")?;
    let first_algebraic_row = object_property(summary_object, "firstAlgebraicRow")?;
    let last_algebraic_row = object_property(summary_object, "lastAlgebraicRow")?;
    let first_backend_row_batch = object_property(summary_object, "firstBackendRowBatch")?;
    let last_backend_row_batch = object_property(summary_object, "lastBackendRowBatch")?;
    let first_proof_component = object_property(summary_object, "firstProofComponent")?;
    let last_proof_component = object_property(summary_object, "lastProofComponent")?;

    validate_statement_dimensions(EncodedRelationDimensions {
        option_count,
        roster_size,
        pvss_threshold,
        share_vector_width,
        encoded_coordinate_count,
        linear_row_count,
        algebraic_row_count,
        variable_count,
        bound_count,
    })?;
    if string_property(summary_object, "relationStatementFormat")? != RELATION_STATEMENT_FORMAT {
        return Err("encoded relation summary uses the wrong statement format".to_string());
    }
    if string_property(summary_object, "backendStatementFormat")? != BACKEND_STATEMENT_FORMAT {
        return Err("encoded relation summary uses the wrong backend statement format".to_string());
    }
    let last_linear_row_kind = string_property(last_linear_row, "rowKind")?;
    if string_property(first_linear_row, "rowKind")? != "OneHotSum"
        || !matches!(
            last_linear_row_kind.as_str(),
            "ReceiverPayloadOpeningPlaintextBinding" | "ReceiverPayloadOpeningBitDecomposition"
        )
    {
        return Err("encoded relation summary row sentinels are not canonical".to_string());
    }
    if string_property(first_algebraic_row, "rowKind")? != "ShareCommitmentEquation"
        || string_property(last_algebraic_row, "rowKind")? != "ReceiverKeyBinding"
    {
        return Err(
            "encoded relation summary algebraic row sentinels are not canonical".to_string(),
        );
    }
    validate_backend_summary_counts(BackendSummaryCounts {
        backend_column_count,
        backend_hash_expanded_row_count,
        backend_explicit_row_count,
        backend_proof_component_count,
        backend_row_batch_count,
        backend_row_count,
        dimensions: EncodedRelationDimensions {
            option_count,
            roster_size,
            pvss_threshold,
            share_vector_width,
            encoded_coordinate_count,
            linear_row_count,
            algebraic_row_count,
            variable_count,
            bound_count,
        },
    })?;
    let last_backend_batch_kind = string_property(last_backend_row_batch, "batchKind")?;
    let last_backend_row_kind = string_property(last_backend_row_batch, "rowKind")?;
    let receiver_key_backend_batch_is_hash_expanded = last_backend_batch_kind == "HashExpandedRows"
        && last_backend_row_kind == "ReceiverKeyBinding";
    let receiver_key_backend_batch_is_explicit = last_backend_batch_kind == "ExplicitSparseRows"
        && last_backend_row_kind == "ReceiverKeyBindingRows";
    if string_property(first_backend_row_batch, "batchKind")? != "ExplicitSparseRows"
        || string_property(first_backend_row_batch, "rowKind")? != "EncodedScoreFieldRows"
        || !(receiver_key_backend_batch_is_hash_expanded || receiver_key_backend_batch_is_explicit)
    {
        return Err(
            "encoded relation summary backend row-batch sentinels are not canonical".to_string(),
        );
    }
    let last_proof_component_status = string_property(last_proof_component, "proofLoweringStatus")?;
    if string_property(first_proof_component, "componentId")? != "score-and-shamir-field-component"
        || string_property(first_proof_component, "proofLoweringStatus")? != "explicitRowsAvailable"
        || string_property(last_proof_component, "componentId")? != "receiver-key-binding-component"
        || !matches!(
            last_proof_component_status.as_str(),
            "HashExpandedRowsPending" | "explicitRowsAvailable"
        )
    {
        return Err(
            "encoded relation summary proof-component sentinels are not canonical".to_string(),
        );
    }
    validate_hash_string(&backend_statement_hash)?;
    validate_hash_string(&relation_statement_hash)?;

    Ok(relation_statement_hash)
}

pub(super) fn validate_component_projection_summaries(
    case_object: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    let Some(component_projection_summaries_value) =
        case_object.get("componentProjectionSummaries")
    else {
        return Ok(());
    };
    reject_forbidden_witness_keys(component_projection_summaries_value)?;
    let component_projection_summaries = component_projection_summaries_value
        .as_array()
        .ok_or_else(|| {
            "encoded relation component projection summaries must be an array".to_string()
        })?;
    let expected_component_projection_summaries = [
        (
            "score-and-shamir-field-component",
            "65537",
            "encoded-score-field-rows-only",
            vec!["encoded_score_field_rows".to_string()],
            "65536",
        ),
        (
            "payload-plaintext-field-component",
            "65537",
            "payload-plaintext-field-rows-only",
            vec![
                "receiver_payload_plaintext_binding_rows".to_string(),
                "receiver_payload_plaintext_bit_decomposition_rows".to_string(),
            ],
            "65536",
        ),
        (
            "share-commitment-component",
            "18446744069414584321",
            "share-commitment-rows-only",
            vec!["share_commitment_equation_rows".to_string()],
            "1048576",
        ),
    ];
    if component_projection_summaries.len() != expected_component_projection_summaries.len() {
        return Err("encoded relation component projection summary count is invalid".to_string());
    }

    for (summary_value, expected_summary) in component_projection_summaries
        .iter()
        .zip(expected_component_projection_summaries)
    {
        let summary_object = object_field(summary_value, "component projection summary")?;
        let component_id = string_property(summary_object, "componentId")?;
        let coefficient_modulus = string_property(summary_object, "coefficientModulus")?;
        let projection_coverage = string_property(summary_object, "projectionCoverage")?;
        let source_row_batch_names = array_property(summary_object, "sourceRowBatchNames")?;
        let statement_rows = u64_property(summary_object, "statementRows")?;
        let statement_columns = u64_property(summary_object, "statementColumns")?;
        let source_backend_column_count = u64_property(summary_object, "sourceBackendColumnCount")?;
        let ring_degree = u64_property(summary_object, "ringDegree")?;
        let witness_l2_bound_squared = string_property(summary_object, "witnessL2BoundSquared")?;
        let parameter_profile_id = string_property(summary_object, "parameterProfileId")?;
        let linear_statement_hash = string_property(summary_object, "linearStatementHash")?;
        let matrix_hash = string_property(summary_object, "matrixHash")?;
        let target_vector_hash = string_property(summary_object, "targetVectorHash")?;

        if component_id != expected_summary.0
            || coefficient_modulus != expected_summary.1
            || projection_coverage != expected_summary.2
            || statement_rows == 0
            || statement_columns == 0
            || source_backend_column_count != statement_columns
            || witness_l2_bound_squared != expected_summary.4
        {
            return Err(
                "encoded relation component projection summary does not match the explicit component profile"
                    .to_string(),
            );
        }
        let actual_source_row_batch_names = source_row_batch_names
            .iter()
            .map(|value| {
                value.as_str().map(ToString::to_string).ok_or_else(|| {
                    "encoded relation component projection row batch names must be strings"
                        .to_string()
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source_row_batch_names_match = actual_source_row_batch_names == expected_summary.3
            || (component_id == "payload-plaintext-field-component"
                && actual_source_row_batch_names
                    == vec!["receiver_payload_plaintext_binding_rows".to_string()]);
        if !source_row_batch_names_match {
            return Err(
                "encoded relation component projection row batches are invalid".to_string(),
            );
        }
        validate_unsigned_decimal_string(&coefficient_modulus)?;
        validate_unsigned_decimal_string(&witness_l2_bound_squared)?;
        if parameter_profile_id.is_empty() {
            return Err(
                "encoded relation component projection parameter profile is empty".to_string(),
            );
        }
        if ring_degree == 0 || ring_degree & (ring_degree - 1) != 0 {
            return Err("encoded relation component projection ring degree is invalid".to_string());
        }
        validate_hash_string(&linear_statement_hash)?;
        validate_hash_string(&matrix_hash)?;
        validate_hash_string(&target_vector_hash)?;
    }

    Ok(())
}

pub(super) fn validate_explicit_component_verification_summaries(
    case_object: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    let Some(component_verification_summaries_value) =
        case_object.get("explicitComponentVerificationSummaries")
    else {
        return Ok(());
    };
    reject_forbidden_witness_keys(component_verification_summaries_value)?;
    let component_verification_summaries = component_verification_summaries_value
        .as_array()
        .ok_or_else(|| {
            "encoded relation explicit component verification summaries must be an array"
                .to_string()
        })?;
    let expected_summaries = [
        (
            "score-and-shamir-field-component",
            vec!["encoded_score_field_rows".to_string()],
        ),
        (
            "payload-plaintext-field-component",
            vec![
                "receiver_payload_plaintext_binding_rows".to_string(),
                "receiver_payload_plaintext_bit_decomposition_rows".to_string(),
            ],
        ),
        (
            "share-commitment-component",
            vec!["share_commitment_equation_rows".to_string()],
        ),
        (
            "receiver-encryption-component",
            vec!["receiver_payload_encryption_equation_rows".to_string()],
        ),
        (
            "receiver-key-binding-component",
            vec!["receiver_key_binding_rows".to_string()],
        ),
    ];
    if component_verification_summaries.len() != expected_summaries.len() {
        return Err(
            "encoded relation explicit component verification summary count is invalid".to_string(),
        );
    }

    for (summary_value, (expected_component_id, expected_row_batch_names)) in
        component_verification_summaries
            .iter()
            .zip(expected_summaries)
    {
        let summary_object = object_field(summary_value, "explicit component verification")?;
        let component_id = string_property(summary_object, "componentId")?;
        let checked_row_batch_names = array_property(summary_object, "checkedRowBatchNames")?;
        let row_count = u64_property(summary_object, "rowCount")?;
        let verification_status = string_property(summary_object, "verificationStatus")?;
        if component_id != expected_component_id
            || row_count == 0
            || verification_status != "explicitRowsSatisfied"
            || !string_array_equals(checked_row_batch_names, &expected_row_batch_names)
        {
            return Err(
                "encoded relation explicit component verification summary is invalid".to_string(),
            );
        }
    }

    Ok(())
}

pub(super) fn validate_component_proof_readiness_manifests(
    case_object: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    let Some(manifests_value) = case_object.get("componentProofReadinessManifests") else {
        return Ok(());
    };
    reject_forbidden_witness_keys(manifests_value)?;
    let manifests = manifests_value.as_array().ok_or_else(|| {
        "encoded relation component proof-readiness manifests must be an array".to_string()
    })?;
    let expected = [
        (
            "score-and-shamir-field-component",
            "65537",
            64_u64,
            "dense-polynomial-matrix-linear-proof-v1",
            "available-for-small-field-component",
            vec!["encoded_score_field_rows".to_string()],
        ),
        (
            "payload-plaintext-field-component",
            "65537",
            64_u64,
            "sparse-polynomial-matrix-linear-proof-v1",
            "blocked-pending-sparse-proof-statement",
            vec![
                "receiver_payload_plaintext_binding_rows".to_string(),
                "receiver_payload_plaintext_bit_decomposition_rows".to_string(),
            ],
        ),
        (
            "share-commitment-component",
            "18446744069414584321",
            256_u64,
            "sparse-polynomial-matrix-linear-proof-v1",
            "blocked-pending-sparse-proof-statement",
            vec!["share_commitment_equation_rows".to_string()],
        ),
        (
            "receiver-encryption-component",
            "12289",
            256_u64,
            "structured-module-lwe-linear-proof-v1",
            "not-applicable-for-structured-component",
            vec!["receiver_payload_encryption_equation_rows".to_string()],
        ),
        (
            "receiver-key-binding-component",
            "12289",
            0_u64,
            "public-zero-witness-binding-check-v1",
            "not-applicable-for-public-zero-witness-component",
            vec!["receiver_key_binding_rows".to_string()],
        ),
    ];
    if manifests.len() != expected.len() {
        return Err(
            "encoded relation component proof-readiness manifest count is invalid".to_string(),
        );
    }

    let mut dense_matrix_oracle_component_count = 0_u64;
    let mut sparse_or_structured_component_count = 0_u64;
    let mut public_zero_witness_component_count = 0_u64;
    for (
        manifest_value,
        (
            expected_component_id,
            expected_modulus,
            expected_source_ring_degree,
            expected_statement_format,
            expected_oracle_status,
            expected_row_batch_names,
        ),
    ) in manifests.iter().zip(expected)
    {
        let manifest = object_field(manifest_value, "component proof-readiness manifest")?;
        let component_id = string_property(manifest, "componentId")?;
        let coefficient_modulus = string_property(manifest, "coefficientModulus")?;
        let object_type = string_property(manifest, "objectType")?;
        let object_version = u64_property(manifest, "objectVersion")?;
        let proof_lowering_status = string_property(manifest, "proofLoweringStatus")?;
        let proof_statement_format = string_property(manifest, "proofStatementFormat")?;
        let dense_matrix_oracle_status = string_property(manifest, "denseMatrixOracleStatus")?;
        let row_batch_names = array_property(manifest, "rowBatchNames")?;
        let row_count = u64_property(manifest, "rowCount")?;
        let variable_column_count = u64_property(manifest, "variableColumnCount")?;
        if component_id != expected_component_id
            || coefficient_modulus != expected_modulus
            || object_type != "BallotProofComponentProofReadinessManifest"
            || object_version != 1
            || proof_lowering_status != "explicitRowsAvailable"
            || proof_statement_format != expected_statement_format
            || dense_matrix_oracle_status != expected_oracle_status
            || row_count == 0
            || !string_array_equals(row_batch_names, &expected_row_batch_names)
        {
            return Err(
                "encoded relation component proof-readiness manifest has invalid shape".to_string(),
            );
        }

        if expected_source_ring_degree == 0 {
            if !manifest
                .get("recommendedSourceRingDegree")
                .is_some_and(Value::is_null)
                || !manifest
                    .get("denseCoefficientCount")
                    .is_some_and(Value::is_null)
                || variable_column_count != 0
            {
                return Err(
                    "encoded relation zero-witness proof-readiness manifest is invalid".to_string(),
                );
            }
            public_zero_witness_component_count += 1;
        } else {
            let source_ring_degree = u64_property(manifest, "recommendedSourceRingDegree")?;
            let dense_coefficient_count = string_property(manifest, "denseCoefficientCount")?;
            validate_unsigned_decimal_string(&dense_coefficient_count)?;
            let expected_dense_count =
                row_count * variable_column_count * expected_source_ring_degree;
            if source_ring_degree != expected_source_ring_degree
                || dense_coefficient_count != expected_dense_count.to_string()
                || variable_column_count == 0
            {
                return Err(
                    "encoded relation component proof-readiness dense coefficient count is invalid"
                        .to_string(),
                );
            }
        }

        if dense_matrix_oracle_status == "available-for-small-field-component" {
            dense_matrix_oracle_component_count += 1;
        } else if dense_matrix_oracle_status == "not-applicable-for-public-zero-witness-component" {
            if expected_source_ring_degree != 0 {
                return Err(
                    "encoded relation component proof-readiness zero-witness status is invalid"
                        .to_string(),
                );
            }
        } else {
            sparse_or_structured_component_count += 1;
        }
    }

    let summary = object_property(case_object, "proofReadinessSummary")?;
    if bool_property(summary, "fullComponentProofBytesAvailable")?
        || u64_property(summary, "totalComponentCount")? != manifests.len() as u64
        || u64_property(summary, "denseMatrixOracleComponentCount")?
            != dense_matrix_oracle_component_count
        || u64_property(summary, "publicZeroWitnessComponentCount")?
            != public_zero_witness_component_count
        || u64_property(summary, "sparseOrStructuredComponentCount")?
            != sparse_or_structured_component_count
    {
        return Err("encoded relation proof-readiness summary is invalid".to_string());
    }

    Ok(())
}

pub(super) fn validate_optional_unsigned_decimal_property(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
    expected: Option<&str>,
) -> Result<(), String> {
    match expected {
        Some(expected_value) => {
            let actual = string_property(object, field_name)?;
            validate_unsigned_decimal_string(&actual)?;
            if actual != expected_value {
                return Err(format!("{field_name} has an unexpected value"));
            }
        }
        None => {
            if !object.get(field_name).is_some_and(Value::is_null) {
                return Err(format!("{field_name} must be null"));
            }
        }
    }

    Ok(())
}

pub(super) fn validate_optional_u64_property(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
    expected: Option<u64>,
) -> Result<(), String> {
    match expected {
        Some(expected_value) => {
            if u64_property(object, field_name)? != expected_value {
                return Err(format!("{field_name} has an unexpected value"));
            }
        }
        None => {
            if !object.get(field_name).is_some_and(Value::is_null) {
                return Err(format!("{field_name} must be null"));
            }
        }
    }

    Ok(())
}
