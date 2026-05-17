use serde_json::{Value, json};

use crate::hashing::derive_protocol_digest;

use super::{BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE, describe_proof_backend};

const ENCODED_COORDINATES_PER_OPTION: u64 = 11;
const FIELD_MODULUS: u64 = 65_537;
const RELATION_STATEMENT_FORMAT: &str = "SparseIntegerRowsModuloGF65537WithBoundGadgets-v1";
const RELATION_STATEMENT_DIGEST_PURPOSE: &str = "ballot-privacy-linear-relation-statement-v1";
const BACKEND_STATEMENT_FORMAT: &str = "SparseSignedIntegerBackendStatement-v1";
const BACKEND_STATEMENT_DIGEST_PURPOSE: &str = "ballot-privacy-backend-statement-v1";
const EXPLICIT_BACKEND_MATRIX_DIGEST_PURPOSE: &str = "ballot-privacy-backend-explicit-matrix-v1";
const EXPLICIT_BACKEND_TARGET_VECTOR_DIGEST_PURPOSE: &str =
    "ballot-privacy-backend-explicit-target-vector-v1";
const DIGEST_EXPANDED_BACKEND_MATRIX_DIGEST_PURPOSE: &str =
    "ballot-privacy-backend-digest-expanded-matrix-v1";
const DIGEST_EXPANDED_BACKEND_TARGET_VECTOR_DIGEST_PURPOSE: &str =
    "ballot-privacy-backend-digest-expanded-target-vector-v1";
const BACKEND_MATRIX_DIGEST_PURPOSE: &str = "ballot-privacy-backend-matrix-v1";
const BACKEND_TARGET_VECTOR_DIGEST_PURPOSE: &str = "ballot-privacy-backend-target-vector-v1";
const BACKEND_BOUNDS_DIGEST_PURPOSE: &str = "ballot-privacy-backend-bounds-v1";
const BACKEND_PROOF_COMPONENTS_DIGEST_PURPOSE: &str = "ballot-privacy-backend-proof-components-v1";
const ALGEBRAIC_ROWS_PER_RECEIVER: u64 = 3;
const EXPLICIT_ROW_BATCHES_BEFORE_ALGEBRAIC_ROWS: u64 = 2;
const EXPLICIT_ROW_BATCHES_WITH_SHARE_COMMITMENT_ROWS: u64 = 3;
const OPENING_VARIABLES_PER_RECEIVER: u64 = 64;
const ENCRYPTION_BATCH_VARIABLES_PER_RECEIVER: u64 = 2;
const SHARE_COMMITMENT_EQUATION_ROWS: u64 = 1_024;
const RECEIVER_ENCRYPTION_EQUATION_ROWS: u64 = 1_280;
const RECEIVER_KEY_EQUATION_ROWS: u64 = 1_024;

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
            "acceptedDigests": summary.accepted_digests,
            "refusedObjects": [],
            "unresolvedReason": Value::Null
        }),
        Err(message) => json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "statusLabels": [],
            "acceptedDigests": [],
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

struct EncodedRelationVectorSummary {
    accepted_digests: Vec<String>,
    case_name: String,
    expected_outcome: String,
    status_labels: Vec<&'static str>,
}

fn validate_encoded_relation_vector_case(
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
        let accepted_digest = validate_accepting_case(case_object)?;
        validate_digest_change_trace(case_object, &accepted_digest)?;

        Ok(EncodedRelationVectorSummary {
            accepted_digests: vec![accepted_digest],
            case_name,
            expected_outcome,
            status_labels: vec![
                "EncodedRelationStatementParsed",
                "EncodedShareLayoutChecked",
                "EncodedBackendStatementChecked",
                "EncodedRelationDigestRecomputed",
            ],
        })
    } else if compiler_accepted && expected_outcome == "reject" {
        validate_preflight_rejecting_case(case_object)?;

        Ok(EncodedRelationVectorSummary {
            accepted_digests: Vec::new(),
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
            accepted_digests: Vec::new(),
            case_name,
            expected_outcome,
            status_labels: vec![
                "EncodedRelationCompilerRefusalRecorded",
                "EncodedRelationRejectVectorChecked",
            ],
        })
    }
}

fn validate_accepting_case(case_object: &serde_json::Map<String, Value>) -> Result<String, String> {
    let full_statement = case_object.get("loweredStatement");
    let statement_summary = case_object.get("loweredStatementSummary");

    let accepted_digest = match (full_statement, statement_summary) {
        (Some(statement), None) => validate_full_statement(statement),
        (None, Some(summary)) => validate_statement_summary(summary),
        (Some(_), Some(_)) => Err(
            "encoded relation accept vector must not include both full statement and summary"
                .to_string(),
        ),
        (None, None) => Err(
            "encoded relation accept vector requires a lowered statement or summary".to_string(),
        ),
    }?;
    validate_component_projection_summaries(case_object)?;

    Ok(accepted_digest)
}

fn validate_preflight_rejecting_case(
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
    if let Ok(unexpected_digest) = validate_accepting_case(case_object) {
        return Err(format!(
            "encoded relation backend preflight reject vector unexpectedly validated with digest {unexpected_digest}"
        ));
    }

    Ok(())
}

fn validate_rejecting_case(
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

fn validate_full_statement(statement: &Value) -> Result<String, String> {
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
    let relation_statement_digest = string_property(statement_object, "relationStatementDigest")?;

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
    let statement_payload = value_without_field(statement, "relationStatementDigest")?;
    let expected_digest = derive_protocol_digest(
        "ChallengeDomainDigest",
        &json!({
            "purpose": RELATION_STATEMENT_DIGEST_PURPOSE,
            "statementPayload": statement_payload,
        }),
    )
    .map_err(|error| format!("encoded relation digest could not be recomputed: {error}"))?;

    if expected_digest != relation_statement_digest {
        return Err(
            "encoded relation statement digest does not match its canonical payload".to_string(),
        );
    }

    Ok(relation_statement_digest)
}

fn validate_statement_summary(summary: &Value) -> Result<String, String> {
    reject_forbidden_witness_keys(summary)?;
    let summary_object = object_field(summary, "loweredStatementSummary")?;
    let option_count = u64_property(summary_object, "optionCount")?;
    let roster_size = u64_property(summary_object, "rosterSize")?;
    let share_vector_width = u64_property(summary_object, "shareVectorWidth")?;
    let encoded_coordinate_count = u64_property(summary_object, "encodedCoordinateCount")?;
    let linear_row_count = u64_property(summary_object, "linearRowCount")?;
    let algebraic_row_count = u64_property(summary_object, "algebraicRowCount")?;
    let variable_count = u64_property(summary_object, "variableCount")?;
    let bound_count = u64_property(summary_object, "boundCount")?;
    let backend_column_count = u64_property(summary_object, "backendColumnCount")?;
    let backend_explicit_row_count = u64_property(summary_object, "backendExplicitRowCount")?;
    let backend_digest_expanded_row_count =
        u64_property(summary_object, "backendDigestExpandedRowCount")?;
    let backend_proof_component_count = u64_property(summary_object, "backendProofComponentCount")?;
    let backend_row_count = u64_property(summary_object, "backendRowCount")?;
    let backend_row_batch_count = u64_property(summary_object, "backendRowBatchCount")?;
    let relation_statement_digest = string_property(summary_object, "relationStatementDigest")?;
    let backend_statement_digest = string_property(summary_object, "backendStatementDigest")?;
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
        pvss_threshold: infer_threshold_from_counts(
            encoded_coordinate_count,
            roster_size,
            variable_count,
        )?,
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
    if string_property(first_linear_row, "rowKind")? != "OneHotSum"
        || string_property(last_linear_row, "rowKind")? != "ReceiverPayloadOpeningPlaintextBinding"
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
        backend_digest_expanded_row_count,
        backend_explicit_row_count,
        backend_proof_component_count,
        backend_row_batch_count,
        backend_row_count,
        dimensions: EncodedRelationDimensions {
            option_count,
            roster_size,
            pvss_threshold: infer_threshold_from_counts(
                encoded_coordinate_count,
                roster_size,
                variable_count,
            )?,
            share_vector_width,
            encoded_coordinate_count,
            linear_row_count,
            algebraic_row_count,
            variable_count,
            bound_count,
        },
    })?;
    if string_property(first_backend_row_batch, "batchKind")? != "ExplicitSparseRows"
        || string_property(first_backend_row_batch, "rowKind")? != "EncodedScoreFieldRows"
        || string_property(last_backend_row_batch, "batchKind")? != "DigestExpandedRows"
        || string_property(last_backend_row_batch, "rowKind")? != "ReceiverKeyBinding"
    {
        return Err(
            "encoded relation summary backend row-batch sentinels are not canonical".to_string(),
        );
    }
    if string_property(first_proof_component, "componentId")? != "score-and-shamir-field-component"
        || string_property(first_proof_component, "proofLoweringStatus")? != "explicitRowsAvailable"
        || string_property(last_proof_component, "componentId")? != "receiver-key-binding-component"
        || string_property(last_proof_component, "proofLoweringStatus")?
            != "digestExpandedRowsPending"
    {
        return Err(
            "encoded relation summary proof-component sentinels are not canonical".to_string(),
        );
    }
    validate_digest_string(&backend_statement_digest)?;
    validate_digest_string(&relation_statement_digest)?;

    Ok(relation_statement_digest)
}

fn validate_component_projection_summaries(
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
            "encoded_score_field_rows",
            70,
            176,
            "65536",
        ),
        (
            "payload-plaintext-field-component",
            "65537",
            "payload-plaintext-field-rows-only",
            "receiver_payload_plaintext_binding_rows",
            258,
            516,
            "65536",
        ),
        (
            "share-commitment-component",
            "18446744069414584321",
            "share-commitment-rows-only",
            "share_commitment_equation_rows",
            3_072,
            258,
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
        let linear_statement_digest = string_property(summary_object, "linearStatementDigest")?;
        let matrix_digest = string_property(summary_object, "matrixDigest")?;
        let target_vector_digest = string_property(summary_object, "targetVectorDigest")?;

        if component_id != expected_summary.0
            || coefficient_modulus != expected_summary.1
            || projection_coverage != expected_summary.2
            || statement_rows != expected_summary.4
            || statement_columns != expected_summary.5
            || source_backend_column_count != expected_summary.5
            || witness_l2_bound_squared != expected_summary.6
        {
            return Err(
                "encoded relation component projection summary does not match the explicit component profile"
                    .to_string(),
            );
        }
        if !string_array_equals(source_row_batch_names, &[expected_summary.3.to_string()]) {
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
        validate_digest_string(&linear_statement_digest)?;
        validate_digest_string(&matrix_digest)?;
        validate_digest_string(&target_vector_digest)?;
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct EncodedRelationDimensions {
    option_count: u64,
    roster_size: u64,
    pvss_threshold: u64,
    share_vector_width: u64,
    encoded_coordinate_count: u64,
    linear_row_count: u64,
    algebraic_row_count: u64,
    variable_count: u64,
    bound_count: u64,
}

fn validate_statement_dimensions(dimensions: EncodedRelationDimensions) -> Result<(), String> {
    if dimensions.option_count == 0
        || dimensions.option_count > 20
        || dimensions.roster_size == 0
        || dimensions.pvss_threshold == 0
    {
        return Err("encoded relation dimensions are outside supported ranges".to_string());
    }
    if dimensions.share_vector_width != dimensions.option_count * ENCODED_COORDINATES_PER_OPTION
        || dimensions.encoded_coordinate_count != dimensions.share_vector_width
    {
        return Err("encoded relation share-vector width is not encoded-score width".to_string());
    }
    let expected_score_and_shamir_rows =
        dimensions.option_count * 2 + dimensions.roster_size * dimensions.encoded_coordinate_count;
    let expected_payload_plaintext_rows = dimensions.roster_size
        * (dimensions.encoded_coordinate_count + OPENING_VARIABLES_PER_RECEIVER);
    let expected_linear_rows = expected_score_and_shamir_rows + expected_payload_plaintext_rows;
    if dimensions.linear_row_count != expected_linear_rows {
        return Err("encoded relation linear row count does not match dimensions".to_string());
    }
    let expected_algebraic_rows = dimensions.roster_size * ALGEBRAIC_ROWS_PER_RECEIVER;
    if dimensions.algebraic_row_count != expected_algebraic_rows {
        return Err("encoded relation algebraic row count does not match dimensions".to_string());
    }
    let expected_variable_count = dimensions.encoded_coordinate_count
        * (dimensions.pvss_threshold + 2 * dimensions.roster_size)
        + dimensions.roster_size
            * (dimensions.encoded_coordinate_count
                + 2 * OPENING_VARIABLES_PER_RECEIVER
                + ENCRYPTION_BATCH_VARIABLES_PER_RECEIVER);
    if dimensions.variable_count != expected_variable_count {
        return Err("encoded relation variable count does not match dimensions".to_string());
    }
    let expected_bound_count = dimensions.option_count * 10 + 9;
    if dimensions.bound_count != expected_bound_count {
        return Err("encoded relation bound count does not match dimensions".to_string());
    }

    Ok(())
}

struct BackendSummaryCounts {
    backend_column_count: u64,
    backend_digest_expanded_row_count: u64,
    backend_explicit_row_count: u64,
    backend_proof_component_count: u64,
    backend_row_batch_count: u64,
    backend_row_count: u64,
    dimensions: EncodedRelationDimensions,
}

fn expected_digest_expanded_backend_rows(dimensions: EncodedRelationDimensions) -> u64 {
    dimensions.roster_size
        * (SHARE_COMMITMENT_EQUATION_ROWS
            + RECEIVER_ENCRYPTION_EQUATION_ROWS
            + RECEIVER_KEY_EQUATION_ROWS)
}

fn validate_backend_summary_counts(counts: BackendSummaryCounts) -> Result<(), String> {
    if counts.backend_column_count != counts.dimensions.variable_count {
        return Err("encoded relation backend column count does not match variables".to_string());
    }
    if counts.backend_explicit_row_count < counts.dimensions.linear_row_count {
        return Err(
            "encoded relation backend explicit row count is smaller than linear rows".to_string(),
        );
    }
    let explicit_share_commitment_rows =
        counts.backend_explicit_row_count - counts.dimensions.linear_row_count;
    let expected_share_commitment_rows =
        counts.dimensions.roster_size * SHARE_COMMITMENT_EQUATION_ROWS;
    if explicit_share_commitment_rows != 0
        && explicit_share_commitment_rows != expected_share_commitment_rows
    {
        return Err(
            "encoded relation backend explicit row count does not match linear and share commitment rows".to_string(),
        );
    }
    let expected_digest_expanded_rows =
        expected_digest_expanded_backend_rows(counts.dimensions) - explicit_share_commitment_rows;
    if counts.backend_digest_expanded_row_count != expected_digest_expanded_rows {
        return Err(
            "encoded relation backend digest-expanded row count does not match dimensions"
                .to_string(),
        );
    }
    if counts.backend_row_count
        != counts.backend_explicit_row_count + counts.backend_digest_expanded_row_count
    {
        return Err("encoded relation backend row count is inconsistent".to_string());
    }
    let expected_row_batch_count = if explicit_share_commitment_rows == 0 {
        EXPLICIT_ROW_BATCHES_BEFORE_ALGEBRAIC_ROWS + counts.dimensions.algebraic_row_count
    } else {
        EXPLICIT_ROW_BATCHES_WITH_SHARE_COMMITMENT_ROWS + counts.dimensions.algebraic_row_count
            - counts.dimensions.roster_size
    };
    if counts.backend_row_batch_count != expected_row_batch_count {
        return Err("encoded relation backend row-batch count does not match rows".to_string());
    }
    if counts.backend_proof_component_count != 5 {
        return Err(
            "encoded relation backend proof-component count does not match modulus groups"
                .to_string(),
        );
    }

    Ok(())
}

fn infer_threshold_from_counts(
    encoded_coordinate_count: u64,
    roster_size: u64,
    variable_count: u64,
) -> Result<u64, String> {
    if encoded_coordinate_count == 0 {
        return Err("encoded relation summary encoded width is zero".to_string());
    }
    let per_receiver_non_polynomial_variable_count = encoded_coordinate_count
        + 2 * OPENING_VARIABLES_PER_RECEIVER
        + ENCRYPTION_BATCH_VARIABLES_PER_RECEIVER;
    let non_polynomial_variable_count = roster_size * per_receiver_non_polynomial_variable_count;
    if variable_count < non_polynomial_variable_count {
        return Err("encoded relation summary variable count is too small".to_string());
    }
    let polynomial_variable_count = variable_count - non_polynomial_variable_count;
    if !polynomial_variable_count.is_multiple_of(encoded_coordinate_count) {
        return Err(
            "encoded relation summary linear variable count is not divisible by width".to_string(),
        );
    }
    let variables_per_coordinate = polynomial_variable_count / encoded_coordinate_count;
    if variables_per_coordinate < 2 * roster_size {
        return Err("encoded relation summary variable count is too small".to_string());
    }

    Ok(variables_per_coordinate - 2 * roster_size)
}

fn validate_digest_change_trace(
    case_object: &serde_json::Map<String, Value>,
    relation_statement_digest: &str,
) -> Result<(), String> {
    let trace = object_property(case_object, "trace")?;
    let expected_digest_changed = trace
        .get("expectedDigestChanged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !expected_digest_changed {
        return Ok(());
    }
    let baseline_digest = string_property(trace, "baselineRelationStatementDigest")?;
    validate_digest_string(&baseline_digest)?;
    if baseline_digest == relation_statement_digest {
        return Err("encoded relation digest-change vector did not change the digest".to_string());
    }

    Ok(())
}

fn validate_row_kinds(linear_rows: &[Value]) -> Result<(), String> {
    let first_row = linear_rows
        .first()
        .ok_or_else(|| "encoded relation full statement has no rows".to_string())?;
    let last_row = linear_rows
        .last()
        .ok_or_else(|| "encoded relation full statement has no rows".to_string())?;
    if string_property(object_field(first_row, "first row")?, "rowKind")? != "OneHotSum"
        || string_property(object_field(last_row, "last row")?, "rowKind")?
            != "ReceiverPayloadOpeningPlaintextBinding"
    {
        return Err("encoded relation full statement row sentinels are not canonical".to_string());
    }

    Ok(())
}

fn validate_algebraic_row_kinds(algebraic_rows: &[Value]) -> Result<(), String> {
    if algebraic_rows.is_empty() {
        return Err("encoded relation full statement has no algebraic rows".to_string());
    }
    for chunk in algebraic_rows.chunks(ALGEBRAIC_ROWS_PER_RECEIVER as usize) {
        if chunk.len() != ALGEBRAIC_ROWS_PER_RECEIVER as usize {
            return Err("encoded relation algebraic rows are not receiver-batched".to_string());
        }
        let expected_row_kinds = [
            "ShareCommitmentEquation",
            "ReceiverPayloadEncryptionEquation",
            "ReceiverKeyBinding",
        ];
        for (algebraic_row, expected_row_kind) in chunk.iter().zip(expected_row_kinds) {
            let row_object = object_field(algebraic_row, "algebraic row")?;
            if string_property(row_object, "rowKind")? != expected_row_kind {
                return Err(
                    "encoded relation algebraic row batch order is not canonical".to_string(),
                );
            }
            if u64_property(row_object, "equationCount")? == 0 {
                return Err("encoded relation algebraic row equation count is zero".to_string());
            }
            let target_digest = string_property(row_object, "targetDigest")?;
            validate_digest_string(&target_digest)?;
        }
    }

    Ok(())
}

fn validate_backend_statement(
    backend_statement: &serde_json::Map<String, Value>,
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    if string_property(backend_statement, "objectType")? != "BallotPrivacyProofBackendStatement"
        || u64_property(backend_statement, "objectVersion")? != 1
        || string_property(backend_statement, "backendStatementFormat")? != BACKEND_STATEMENT_FORMAT
        || string_property(backend_statement, "sourceRelationStatementFormat")?
            != RELATION_STATEMENT_FORMAT
        || string_property(backend_statement, "relationLabel")? != "BallotPrivacyPvssRelation"
        || u64_property(backend_statement, "fieldModulus")? != FIELD_MODULUS
    {
        return Err(
            "encoded relation backend statement has an invalid canonical shape".to_string(),
        );
    }
    if u64_property(backend_statement, "optionCount")? != dimensions.option_count
        || u64_property(backend_statement, "rosterSize")? != dimensions.roster_size
        || u64_property(backend_statement, "pvssThreshold")? != dimensions.pvss_threshold
        || u64_property(backend_statement, "shareVectorWidth")? != dimensions.share_vector_width
        || u64_property(backend_statement, "encodedCoordinateCount")?
            != dimensions.encoded_coordinate_count
    {
        return Err("encoded relation backend dimensions do not match the statement".to_string());
    }

    let column_count = u64_property(backend_statement, "columnCount")?;
    let explicit_row_count = u64_property(backend_statement, "explicitRowCount")?;
    let digest_expanded_row_count = u64_property(backend_statement, "digestExpandedRowCount")?;
    let row_count = u64_property(backend_statement, "rowCount")?;
    let row_batches = array_property(backend_statement, "rowBatches")?;
    let variable_columns = array_property(backend_statement, "variableColumns")?;
    let backend_bounds = array_property(backend_statement, "bounds")?;
    let proof_components = array_property(backend_statement, "proofComponents")?;

    validate_backend_summary_counts(BackendSummaryCounts {
        backend_column_count: column_count,
        backend_digest_expanded_row_count: digest_expanded_row_count,
        backend_explicit_row_count: explicit_row_count,
        backend_proof_component_count: proof_components.len() as u64,
        backend_row_batch_count: row_batches.len() as u64,
        backend_row_count: row_count,
        dimensions,
    })?;
    validate_backend_variable_columns(variable_columns, column_count)?;
    validate_backend_row_batches(row_batches, column_count, dimensions)?;
    validate_backend_bounds(backend_bounds, column_count, dimensions.bound_count)?;
    validate_backend_proof_components(proof_components, row_batches, column_count)?;

    let matrix_digest = string_property(backend_statement, "matrixDigest")?;
    let target_vector_digest = string_property(backend_statement, "targetVectorDigest")?;
    let bounds_digest = string_property(backend_statement, "boundsDigest")?;
    let proof_components_digest = string_property(backend_statement, "proofComponentsDigest")?;
    let backend_statement_digest = string_property(backend_statement, "backendStatementDigest")?;
    validate_digest_string(&matrix_digest)?;
    validate_digest_string(&target_vector_digest)?;
    validate_digest_string(&bounds_digest)?;
    validate_digest_string(&proof_components_digest)?;
    validate_digest_string(&backend_statement_digest)?;

    let expected_matrix_digest = derive_backend_digest(
        BACKEND_MATRIX_DIGEST_PURPOSE,
        json!({
            "rowBatches": row_batches.iter().map(backend_batch_matrix_summary).collect::<Result<Vec<_>, _>>()?
        }),
    )?;
    let expected_target_vector_digest = derive_backend_digest(
        BACKEND_TARGET_VECTOR_DIGEST_PURPOSE,
        json!({
            "rowBatches": row_batches.iter().map(backend_batch_target_summary).collect::<Result<Vec<_>, _>>()?
        }),
    )?;
    let expected_bounds_digest = derive_backend_digest(
        BACKEND_BOUNDS_DIGEST_PURPOSE,
        json!({
            "bounds": backend_bounds
        }),
    )?;
    let expected_proof_components_digest = derive_backend_digest(
        BACKEND_PROOF_COMPONENTS_DIGEST_PURPOSE,
        json!({
            "proofComponents": proof_components
        }),
    )?;
    let backend_statement_value = Value::Object(backend_statement.clone());
    let backend_statement_payload =
        value_without_field(&backend_statement_value, "backendStatementDigest")?;
    let expected_backend_statement_digest =
        derive_backend_digest(BACKEND_STATEMENT_DIGEST_PURPOSE, backend_statement_payload)?;

    if matrix_digest != expected_matrix_digest {
        return Err(
            "encoded relation backend matrix digest does not match row batches".to_string(),
        );
    }
    if target_vector_digest != expected_target_vector_digest {
        return Err(
            "encoded relation backend target-vector digest does not match row batches".to_string(),
        );
    }
    if bounds_digest != expected_bounds_digest {
        return Err("encoded relation backend bounds digest does not match bounds".to_string());
    }
    if proof_components_digest != expected_proof_components_digest {
        return Err(
            "encoded relation backend proof-components digest does not match components"
                .to_string(),
        );
    }
    if backend_statement_digest != expected_backend_statement_digest {
        return Err(
            "encoded relation backend statement digest does not match its canonical payload"
                .to_string(),
        );
    }

    Ok(())
}

fn validate_backend_variable_columns(
    variable_columns: &[Value],
    column_count: u64,
) -> Result<(), String> {
    if variable_columns.len() as u64 != column_count {
        return Err("encoded relation backend variable column count is inconsistent".to_string());
    }
    let mut variable_names = std::collections::BTreeSet::new();
    for (expected_column_index, variable_column) in variable_columns.iter().enumerate() {
        let variable_column_object = object_field(variable_column, "backend variable column")?;
        if u64_property(variable_column_object, "columnIndex")? != expected_column_index as u64 {
            return Err("encoded relation backend variable columns are not canonical".to_string());
        }
        let variable_name = string_property(variable_column_object, "variableName")?;
        let variable_role = string_property(variable_column_object, "variableRole")?;
        if variable_name.is_empty() || !variable_names.insert(variable_name) {
            return Err("encoded relation backend variable names are not unique".to_string());
        }
        if !matches!(
            variable_role.as_str(),
            "ScalarScoreConstant"
                | "ScoreBucketConstant"
                | "ShamirCoefficient"
                | "ReceiverShare"
                | "ShamirQuotient"
                | "ReceiverPayloadPlaintextShare"
                | "ReceiverPayloadPlaintextOpening"
                | "ShareCommitmentOpening"
                | "ReceiverEncryptionRandomness"
                | "ReceiverEncryptionNoise"
        ) {
            return Err("encoded relation backend variable role is not canonical".to_string());
        }
    }

    Ok(())
}

fn validate_backend_row_batches(
    row_batches: &[Value],
    column_count: u64,
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    let has_explicit_share_commitment_batch = row_batches
        .get(EXPLICIT_ROW_BATCHES_BEFORE_ALGEBRAIC_ROWS as usize)
        .and_then(Value::as_object)
        .and_then(|batch| batch.get("rowKind"))
        .and_then(Value::as_str)
        == Some("ShareCommitmentEquationRows");
    let expected_row_batch_count = if has_explicit_share_commitment_batch {
        EXPLICIT_ROW_BATCHES_WITH_SHARE_COMMITMENT_ROWS + dimensions.algebraic_row_count
            - dimensions.roster_size
    } else {
        EXPLICIT_ROW_BATCHES_BEFORE_ALGEBRAIC_ROWS + dimensions.algebraic_row_count
    };
    if row_batches.len() as u64 != expected_row_batch_count {
        return Err("encoded relation backend row-batch count is invalid".to_string());
    }
    let mut expected_row_offset = 0_u64;
    for (batch_index, batch) in row_batches.iter().enumerate() {
        let batch_object = object_field(batch, "backend row batch")?;
        let batch_kind = string_property(batch_object, "batchKind")?;
        let row_offset = u64_property(batch_object, "rowOffset")?;
        let row_count = u64_property(batch_object, "rowCount")?;
        if row_offset != expected_row_offset || row_count == 0 {
            return Err("encoded relation backend row batches are not contiguous".to_string());
        }
        if batch_index == 0 {
            validate_score_explicit_backend_row_batch(batch_object, column_count, dimensions)?;
        } else if batch_index == 1 {
            validate_payload_explicit_backend_row_batch(batch_object, column_count, dimensions)?;
        } else if batch_index == 2 && has_explicit_share_commitment_batch {
            validate_share_commitment_explicit_backend_row_batch(
                batch_object,
                column_count,
                dimensions,
            )?;
        } else {
            validate_digest_expanded_backend_row_batch(batch_object, column_count, dimensions)?;
        }
        if batch_kind == "ExplicitSparseRows"
            && (batch_index > 1 && !(batch_index == 2 && has_explicit_share_commitment_batch))
        {
            return Err(
                "encoded relation backend explicit rows must precede digest-expanded rows"
                    .to_string(),
            );
        }
        expected_row_offset += row_count;
    }
    let explicit_share_commitment_rows = if has_explicit_share_commitment_batch {
        dimensions.roster_size * SHARE_COMMITMENT_EQUATION_ROWS
    } else {
        0
    };
    let expected_row_count = dimensions.linear_row_count
        + explicit_share_commitment_rows
        + expected_digest_expanded_backend_rows(dimensions)
        - explicit_share_commitment_rows;
    if expected_row_offset != expected_row_count {
        return Err("encoded relation backend row count does not match dimensions".to_string());
    }

    Ok(())
}

fn validate_score_explicit_backend_row_batch(
    batch_object: &serde_json::Map<String, Value>,
    column_count: u64,
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    let expected_score_row_count =
        dimensions.option_count * 2 + dimensions.roster_size * dimensions.encoded_coordinate_count;
    if string_property(batch_object, "batchKind")? != "ExplicitSparseRows"
        || string_property(batch_object, "batchName")? != "encoded_score_field_rows"
        || string_property(batch_object, "rowKind")? != "EncodedScoreFieldRows"
        || string_property(batch_object, "modulus")? != FIELD_MODULUS.to_string()
        || u64_property(batch_object, "rowCount")? != expected_score_row_count
    {
        return Err("encoded relation backend explicit row batch is not canonical".to_string());
    }
    let rows = array_property(batch_object, "rows")?;
    if rows.len() as u64 != expected_score_row_count {
        return Err("encoded relation backend explicit row count is invalid".to_string());
    }
    validate_explicit_backend_rows(
        rows,
        column_count,
        &FIELD_MODULUS.to_string(),
        &[
            "OneHotSum",
            "ScalarScoreConsistency",
            "ShamirEvaluationQuotient",
        ],
    )?;
    validate_batch_digest_pair(
        batch_object,
        EXPLICIT_BACKEND_MATRIX_DIGEST_PURPOSE,
        EXPLICIT_BACKEND_TARGET_VECTOR_DIGEST_PURPOSE,
        explicit_backend_matrix_payload(rows)?,
        explicit_backend_target_payload(rows)?,
    )
}

fn validate_payload_explicit_backend_row_batch(
    batch_object: &serde_json::Map<String, Value>,
    column_count: u64,
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    let expected_payload_row_count = dimensions.roster_size
        * (dimensions.encoded_coordinate_count + OPENING_VARIABLES_PER_RECEIVER);
    if string_property(batch_object, "batchKind")? != "ExplicitSparseRows"
        || string_property(batch_object, "batchName")? != "receiver_payload_plaintext_binding_rows"
        || string_property(batch_object, "rowKind")? != "ReceiverPayloadPlaintextBindingRows"
        || string_property(batch_object, "modulus")? != FIELD_MODULUS.to_string()
        || u64_property(batch_object, "rowCount")? != expected_payload_row_count
    {
        return Err(
            "encoded relation backend payload explicit row batch is not canonical".to_string(),
        );
    }
    let rows = array_property(batch_object, "rows")?;
    if rows.len() as u64 != expected_payload_row_count {
        return Err("encoded relation backend payload explicit row count is invalid".to_string());
    }
    validate_explicit_backend_rows(
        rows,
        column_count,
        &FIELD_MODULUS.to_string(),
        &[
            "ReceiverPayloadSharePlaintextBinding",
            "ReceiverPayloadOpeningPlaintextBinding",
        ],
    )?;
    validate_batch_digest_pair(
        batch_object,
        EXPLICIT_BACKEND_MATRIX_DIGEST_PURPOSE,
        EXPLICIT_BACKEND_TARGET_VECTOR_DIGEST_PURPOSE,
        explicit_backend_matrix_payload(rows)?,
        explicit_backend_target_payload(rows)?,
    )
}

fn validate_share_commitment_explicit_backend_row_batch(
    batch_object: &serde_json::Map<String, Value>,
    column_count: u64,
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    let expected_row_count = dimensions.roster_size * SHARE_COMMITMENT_EQUATION_ROWS;
    if string_property(batch_object, "batchKind")? != "ExplicitSparseRows"
        || string_property(batch_object, "batchName")? != "share_commitment_equation_rows"
        || string_property(batch_object, "rowKind")? != "ShareCommitmentEquationRows"
        || string_property(batch_object, "modulus")? != "18446744069414584321"
        || u64_property(batch_object, "rowCount")? != expected_row_count
    {
        return Err(
            "encoded relation backend share commitment explicit row batch is not canonical"
                .to_string(),
        );
    }
    let rows = array_property(batch_object, "rows")?;
    if rows.len() as u64 != expected_row_count {
        return Err(
            "encoded relation backend share commitment explicit row count is invalid".to_string(),
        );
    }
    validate_explicit_backend_rows(
        rows,
        column_count,
        "18446744069414584321",
        &["ShareCommitmentEquation"],
    )?;
    validate_batch_digest_pair(
        batch_object,
        EXPLICIT_BACKEND_MATRIX_DIGEST_PURPOSE,
        EXPLICIT_BACKEND_TARGET_VECTOR_DIGEST_PURPOSE,
        explicit_backend_matrix_payload(rows)?,
        explicit_backend_target_payload(rows)?,
    )
}

fn validate_explicit_backend_rows(
    rows: &[Value],
    column_count: u64,
    expected_modulus: &str,
    allowed_row_kinds: &[&str],
) -> Result<(), String> {
    for (expected_row_index, row) in rows.iter().enumerate() {
        let row_object = object_field(row, "backend explicit row")?;
        if u64_property(row_object, "rowIndex")? != expected_row_index as u64 {
            return Err(
                "encoded relation backend explicit row indexes are not canonical".to_string(),
            );
        }
        if string_property(row_object, "modulus")? != expected_modulus {
            return Err("encoded relation backend explicit row modulus is invalid".to_string());
        }
        let row_kind = string_property(row_object, "rowKind")?;
        if !allowed_row_kinds
            .iter()
            .any(|allowed_row_kind| row_kind == *allowed_row_kind)
        {
            return Err("encoded relation backend explicit row kind is invalid".to_string());
        }
        validate_signed_decimal_string(&string_property(row_object, "target")?)?;
        let terms = array_property(row_object, "terms")?;
        if terms.is_empty() {
            return Err("encoded relation backend explicit rows must contain terms".to_string());
        }
        for term in terms {
            let term_object = object_field(term, "backend explicit row term")?;
            let column_index = u64_property(term_object, "columnIndex")?;
            if column_index >= column_count {
                return Err(
                    "encoded relation backend explicit term column is out of range".to_string(),
                );
            }
            validate_signed_decimal_string(&string_property(term_object, "coefficient")?)?;
            if string_property(term_object, "variableName")?.is_empty() {
                return Err(
                    "encoded relation backend explicit term variable name is empty".to_string(),
                );
            }
        }
    }

    Ok(())
}

fn validate_digest_expanded_backend_row_batch(
    batch_object: &serde_json::Map<String, Value>,
    column_count: u64,
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    if string_property(batch_object, "batchKind")? != "DigestExpandedRows"
        || batch_object.contains_key("rows")
    {
        return Err(
            "encoded relation backend digest-expanded row batch is not canonical".to_string(),
        );
    }
    let row_kind = string_property(batch_object, "rowKind")?;
    let expected_row_count = match row_kind.as_str() {
        "ShareCommitmentEquation" => SHARE_COMMITMENT_EQUATION_ROWS,
        "ReceiverPayloadEncryptionEquation" => RECEIVER_ENCRYPTION_EQUATION_ROWS,
        "ReceiverKeyBinding" => RECEIVER_KEY_EQUATION_ROWS,
        _ => {
            return Err("encoded relation backend digest-expanded row kind is invalid".to_string());
        }
    };
    if u64_property(batch_object, "rowCount")? != expected_row_count {
        return Err("encoded relation backend digest-expanded row count is invalid".to_string());
    }
    let receiver_roster_position = u64_property(batch_object, "receiverRosterPosition")?;
    if receiver_roster_position == 0 || receiver_roster_position > dimensions.roster_size {
        return Err(
            "encoded relation backend digest-expanded receiver position is invalid".to_string(),
        );
    }
    if string_property(batch_object, "receiverIdentity")?.is_empty()
        || string_property(batch_object, "sourceAlgebraicRowName")?.is_empty()
        || string_property(batch_object, "coefficientExpansionDomain")?.is_empty()
        || string_property(batch_object, "targetExpansionDomain")?.is_empty()
    {
        return Err("encoded relation backend digest-expanded labels are invalid".to_string());
    }
    validate_digest_string(&string_property(batch_object, "targetDigest")?)?;
    validate_digest_map(object_property(batch_object, "publicInputDigests")?)?;
    validate_column_index_array(
        array_property(batch_object, "variableColumnIndices")?,
        column_count,
    )?;
    validate_batch_digest_pair(
        batch_object,
        DIGEST_EXPANDED_BACKEND_MATRIX_DIGEST_PURPOSE,
        DIGEST_EXPANDED_BACKEND_TARGET_VECTOR_DIGEST_PURPOSE,
        digest_expanded_backend_payload(batch_object)?,
        digest_expanded_backend_payload(batch_object)?,
    )
}

fn validate_backend_bounds(
    backend_bounds: &[Value],
    column_count: u64,
    expected_bound_count: u64,
) -> Result<(), String> {
    if backend_bounds.len() as u64 != expected_bound_count {
        return Err("encoded relation backend bound count is invalid".to_string());
    }
    for bound in backend_bounds {
        let bound_object = object_field(bound, "backend bound")?;
        if string_property(bound_object, "boundName")?.is_empty() {
            return Err("encoded relation backend bound name is empty".to_string());
        }
        let bound_kind = string_property(bound_object, "boundKind")?;
        if !matches!(
            bound_kind.as_str(),
            "Boolean" | "CanonicalFieldElement" | "SignedIntegerAbsoluteBound"
        ) {
            return Err("encoded relation backend bound kind is invalid".to_string());
        }
        validate_column_index_array(
            array_property(bound_object, "variableColumnIndices")?,
            column_count,
        )?;
        let variable_names = array_property(bound_object, "variableNames")?;
        if variable_names.len() != array_property(bound_object, "variableColumnIndices")?.len()
            || !variable_names.iter().all(Value::is_string)
        {
            return Err("encoded relation backend bound variables are inconsistent".to_string());
        }
        for field_name in ["absoluteMaximum", "minimum", "maximum"] {
            if let Some(value) = bound_object.get(field_name) {
                validate_signed_decimal_string(
                    value
                        .as_str()
                        .ok_or_else(|| format!("{field_name} must be a decimal string"))?,
                )?;
            }
        }
    }

    Ok(())
}

fn validate_backend_proof_components(
    proof_components: &[Value],
    row_batches: &[Value],
    column_count: u64,
) -> Result<(), String> {
    let expected_component_ids = [
        "score-and-shamir-field-component",
        "payload-plaintext-field-component",
        "share-commitment-component",
        "receiver-encryption-component",
        "receiver-key-binding-component",
    ];
    if proof_components.len() != expected_component_ids.len() {
        return Err("encoded relation backend proof-component count is invalid".to_string());
    }

    for (component_index, expected_component_id) in expected_component_ids.iter().enumerate() {
        let component_object = object_field(
            proof_components
                .get(component_index)
                .ok_or_else(|| "encoded relation backend proof component is missing".to_string())?,
            "backend proof component",
        )?;
        let component_id = string_property(component_object, "componentId")?;
        if component_id != *expected_component_id {
            return Err("encoded relation backend proof-component order is invalid".to_string());
        }

        let matching_batches = row_batches
            .iter()
            .map(|batch| object_field(batch, "backend row batch"))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|batch| {
                string_property(batch, "rowKind")
                    .map(|row_kind| component_id_for_row_kind(&row_kind) == component_id)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if matching_batches.is_empty() {
            return Err("encoded relation backend proof component has no row batches".to_string());
        }
        let coefficient_modulus = string_property(component_object, "coefficientModulus")?;
        let expected_row_count = matching_batches
            .iter()
            .try_fold(0_u64, |row_count, batch| {
                if string_property(batch, "modulus")? != coefficient_modulus {
                    return Err(
                        "encoded relation backend proof-component modulus is inconsistent"
                            .to_string(),
                    );
                }
                Ok(row_count + u64_property(batch, "rowCount")?)
            })?;
        if u64_property(component_object, "rowCount")? != expected_row_count {
            return Err(
                "encoded relation backend proof-component row count is invalid".to_string(),
            );
        }

        let expected_lowering_status = if matching_batches
            .iter()
            .all(|batch| string_property(batch, "batchKind").as_deref() == Ok("ExplicitSparseRows"))
        {
            "explicitRowsAvailable"
        } else {
            "digestExpandedRowsPending"
        };
        if string_property(component_object, "proofLoweringStatus")? != expected_lowering_status {
            return Err(
                "encoded relation backend proof-component lowering status is invalid".to_string(),
            );
        }

        let expected_batch_names = matching_batches
            .iter()
            .map(|batch| string_property(batch, "batchName"))
            .collect::<Result<Vec<_>, _>>()?;
        let row_batch_names = array_property(component_object, "rowBatchNames")?;
        if !string_array_equals(row_batch_names, &expected_batch_names) {
            return Err(
                "encoded relation backend proof-component row-batch names are invalid".to_string(),
            );
        }

        let expected_row_kinds =
            matching_batches
                .iter()
                .try_fold(Vec::<String>::new(), |mut row_kinds, batch| {
                    let row_kind = string_property(batch, "rowKind")?;
                    if !row_kinds.contains(&row_kind) {
                        row_kinds.push(row_kind);
                    }
                    Ok::<Vec<String>, String>(row_kinds)
                })?;
        let row_kinds = array_property(component_object, "rowKinds")?;
        if !string_array_equals(row_kinds, &expected_row_kinds) {
            return Err(
                "encoded relation backend proof-component row kinds are invalid".to_string(),
            );
        }

        let expected_column_indices = matching_batches.iter().try_fold(
            std::collections::BTreeSet::<u64>::new(),
            |mut indices, batch| {
                for value in array_property(batch, "variableColumnIndices")? {
                    let column_index = value.as_u64().ok_or_else(|| {
                        "encoded relation backend column index must be an integer".to_string()
                    })?;
                    indices.insert(column_index);
                }
                Ok::<std::collections::BTreeSet<u64>, String>(indices)
            },
        )?;
        let variable_column_indices = array_property(component_object, "variableColumnIndices")?;
        validate_column_index_array(variable_column_indices, column_count)?;
        if variable_column_indices.len() as u64
            != u64_property(component_object, "variableColumnCount")?
            || variable_column_indices
                .iter()
                .map(|value| {
                    value.as_u64().ok_or_else(|| {
                        "encoded relation backend column index must be an integer".to_string()
                    })
                })
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?
                != expected_column_indices
        {
            return Err(
                "encoded relation backend proof-component variable columns are invalid".to_string(),
            );
        }

        let component_digest = string_property(component_object, "componentDigest")?;
        validate_digest_string(&component_digest)?;
        let component_value = Value::Object(component_object.clone());
        let component_payload = value_without_field(&component_value, "componentDigest")?;
        let expected_component_digest =
            derive_backend_digest(BACKEND_PROOF_COMPONENTS_DIGEST_PURPOSE, component_payload)?;
        if component_digest != expected_component_digest {
            return Err("encoded relation backend proof-component digest is invalid".to_string());
        }
    }

    Ok(())
}

fn component_id_for_row_kind(row_kind: &str) -> &'static str {
    match row_kind {
        "EncodedScoreFieldRows" => "score-and-shamir-field-component",
        "ReceiverPayloadPlaintextBindingRows" => "payload-plaintext-field-component",
        "ShareCommitmentEquationRows" => "share-commitment-component",
        "ShareCommitmentEquation" => "share-commitment-component",
        "ReceiverPayloadEncryptionEquation" => "receiver-encryption-component",
        "ReceiverKeyBinding" => "receiver-key-binding-component",
        _ => "",
    }
}

fn string_array_equals(values: &[Value], expected: &[String]) -> bool {
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(value, expected_value)| value.as_str() == Some(expected_value.as_str()))
}

fn validate_batch_digest_pair(
    batch_object: &serde_json::Map<String, Value>,
    matrix_purpose: &str,
    target_purpose: &str,
    matrix_payload: Value,
    target_payload: Value,
) -> Result<(), String> {
    let matrix_digest = string_property(batch_object, "matrixDigest")?;
    let target_vector_digest = string_property(batch_object, "targetVectorDigest")?;
    validate_digest_string(&matrix_digest)?;
    validate_digest_string(&target_vector_digest)?;
    let expected_matrix_digest = derive_backend_digest(matrix_purpose, matrix_payload)?;
    let expected_target_vector_digest = derive_backend_digest(target_purpose, target_payload)?;
    if matrix_digest != expected_matrix_digest {
        return Err("encoded relation backend batch matrix digest is invalid".to_string());
    }
    if target_vector_digest != expected_target_vector_digest {
        return Err("encoded relation backend batch target-vector digest is invalid".to_string());
    }

    Ok(())
}

fn explicit_backend_matrix_payload(rows: &[Value]) -> Result<Value, String> {
    let mut matrix_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let row_object = object_field(row, "backend explicit row")?;
        matrix_rows.push(json!({
            "rowIndex": u64_property(row_object, "rowIndex")?,
            "rowKind": string_property(row_object, "rowKind")?,
            "rowName": string_property(row_object, "rowName")?,
            "terms": array_property(row_object, "terms")?,
        }));
    }

    Ok(json!({ "rows": matrix_rows }))
}

fn explicit_backend_target_payload(rows: &[Value]) -> Result<Value, String> {
    let mut targets = Vec::with_capacity(rows.len());
    for row in rows {
        let row_object = object_field(row, "backend explicit row")?;
        targets.push(json!({
            "rowIndex": u64_property(row_object, "rowIndex")?,
            "rowKind": string_property(row_object, "rowKind")?,
            "rowName": string_property(row_object, "rowName")?,
            "target": string_property(row_object, "target")?,
        }));
    }

    Ok(json!({ "targets": targets }))
}

fn digest_expanded_backend_payload(
    batch_object: &serde_json::Map<String, Value>,
) -> Result<Value, String> {
    Ok(json!({
        "coefficientExpansionDomain": string_property(batch_object, "coefficientExpansionDomain")?,
        "modulus": string_property(batch_object, "modulus")?,
        "publicInputDigests": object_property(batch_object, "publicInputDigests")?,
        "receiverIdentity": string_property(batch_object, "receiverIdentity")?,
        "receiverRosterPosition": u64_property(batch_object, "receiverRosterPosition")?,
        "rowCount": u64_property(batch_object, "rowCount")?,
        "rowKind": string_property(batch_object, "rowKind")?,
        "sourceAlgebraicRowName": string_property(batch_object, "sourceAlgebraicRowName")?,
        "targetDigest": string_property(batch_object, "targetDigest")?,
        "targetExpansionDomain": string_property(batch_object, "targetExpansionDomain")?,
        "variableColumnIndices": array_property(batch_object, "variableColumnIndices")?,
    }))
}

fn backend_batch_matrix_summary(batch: &Value) -> Result<Value, String> {
    let batch_object = object_field(batch, "backend row batch")?;
    Ok(json!({
        "batchKind": string_property(batch_object, "batchKind")?,
        "batchName": string_property(batch_object, "batchName")?,
        "matrixDigest": string_property(batch_object, "matrixDigest")?,
        "rowCount": u64_property(batch_object, "rowCount")?,
        "rowKind": string_property(batch_object, "rowKind")?,
        "rowOffset": u64_property(batch_object, "rowOffset")?,
    }))
}

fn backend_batch_target_summary(batch: &Value) -> Result<Value, String> {
    let batch_object = object_field(batch, "backend row batch")?;
    Ok(json!({
        "batchKind": string_property(batch_object, "batchKind")?,
        "batchName": string_property(batch_object, "batchName")?,
        "rowCount": u64_property(batch_object, "rowCount")?,
        "rowKind": string_property(batch_object, "rowKind")?,
        "rowOffset": u64_property(batch_object, "rowOffset")?,
        "targetVectorDigest": string_property(batch_object, "targetVectorDigest")?,
    }))
}

fn validate_digest_map(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    if object.is_empty() {
        return Err("encoded relation backend digest map must not be empty".to_string());
    }
    for value in object.values() {
        validate_digest_string(value.as_str().ok_or_else(|| {
            "encoded relation backend digest map value must be a string".to_string()
        })?)?;
    }

    Ok(())
}

fn validate_column_index_array(values: &[Value], column_count: u64) -> Result<(), String> {
    let mut previous_column_index = None;
    for value in values {
        let column_index = value.as_u64().ok_or_else(|| {
            "encoded relation backend column index must be an integer".to_string()
        })?;
        if column_index >= column_count {
            return Err("encoded relation backend column index is out of range".to_string());
        }
        if let Some(previous) = previous_column_index
            && column_index <= previous
        {
            return Err(
                "encoded relation backend column indices must be strictly increasing".to_string(),
            );
        }
        previous_column_index = Some(column_index);
    }

    Ok(())
}

fn reject_forbidden_witness_keys(value: &Value) -> Result<(), String> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "encodedCoordinateShamirCoefficients",
        "errorVector",
        "normalizedScores",
        "privateWitness",
        "ciphertextChunks",
        "encryptionRandomness",
        "openingRandomness",
        "proofRandomness",
        "receiverShareVector",
        "scoreOneHotWitnesses",
        "secretState",
        "secretVector",
        "witness",
    ];

    match value {
        Value::Array(entries) => {
            for entry in entries {
                reject_forbidden_witness_keys(entry)?;
            }
        }
        Value::Object(object) => {
            for (key, entry) in object {
                if FORBIDDEN_KEYS.contains(&key.as_str()) {
                    return Err(format!(
                        "encoded relation vector exposes forbidden witness key {key}"
                    ));
                }
                reject_forbidden_witness_keys(entry)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }

    Ok(())
}

fn validate_digest_string(value: &str) -> Result<(), String> {
    if value.len() != 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("encoded relation digest must be 64 lowercase bytes".to_string());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("encoded relation digest must be lowercase hex".to_string());
    }

    Ok(())
}

fn validate_signed_decimal_string(value: &str) -> Result<(), String> {
    if value.is_empty() || value == "-" || value == "-0" || value.starts_with('+') {
        return Err("encoded relation decimal string is not canonical".to_string());
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("encoded relation decimal string contains non-digits".to_string());
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err("encoded relation decimal string has a leading zero".to_string());
    }

    Ok(())
}

fn validate_unsigned_decimal_string(value: &str) -> Result<(), String> {
    validate_signed_decimal_string(value)?;
    if value.starts_with('-') {
        return Err("encoded relation unsigned decimal string is negative".to_string());
    }

    Ok(())
}

fn derive_backend_digest(purpose: &str, payload: Value) -> Result<String, String> {
    derive_protocol_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": payload,
            "purpose": purpose,
        }),
    )
    .map_err(|error| format!("encoded relation backend digest could not be recomputed: {error}"))
}

fn object_field<'value>(
    value: &'value Value,
    label: &str,
) -> Result<&'value serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object"))
}

fn object_property<'value>(
    object: &'value serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<&'value serde_json::Map<String, Value>, String> {
    object
        .get(field_name)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{field_name} must be a JSON object"))
}

fn array_property<'value>(
    object: &'value serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<&'value Vec<Value>, String> {
    object
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field_name} must be an array"))
}

fn string_property(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<String, String> {
    object
        .get(field_name)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| format!("{field_name} must be a string"))
}

fn u64_property(object: &serde_json::Map<String, Value>, field_name: &str) -> Result<u64, String> {
    object
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{field_name} must be a non-negative integer"))
}

fn bool_property(
    object: &serde_json::Map<String, Value>,
    field_name: &str,
) -> Result<bool, String> {
    object
        .get(field_name)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{field_name} must be a boolean"))
}

fn value_without_field(value: &Value, field_name: &str) -> Result<Value, String> {
    let object = object_field(value, "object")?;
    let mut copied_object = object.clone();
    copied_object.remove(field_name);

    Ok(Value::Object(copied_object))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::verify_encoded_relation_vector_case_value;

    fn generated_case(case_name: &str) -> Value {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json"
        ))
        .expect("encoded relation vector file should parse");

        vectors["cases"]
            .as_array()
            .expect("encoded relation vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == case_name)
            .unwrap_or_else(|| panic!("encoded relation vector case {case_name} should exist"))
            .clone()
    }

    fn expect_mini_case_mutation_rejected(mut mutate_case: impl FnMut(&mut Value)) {
        let mut vector_case = generated_case("mini-encoded-ballot-relation");
        mutate_case(&mut vector_case);

        let verification = verify_encoded_relation_vector_case_value(&vector_case);

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["unresolvedReason"], "InvalidFixture");
    }

    #[test]
    fn verifies_mini_encoded_relation_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "mini-encoded-ballot-relation",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["expectedOutcome"], "accept");
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("EncodedRelationDigestRecomputed"))
        );
    }

    #[test]
    fn verifies_mandatory_encoded_relation_summary_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "mandatory-profile-encoded-ballot-relation",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["expectedOutcome"], "accept");
    }

    #[test]
    fn verifies_explicit_share_commitment_relation_summary_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "mini-encoded-ballot-share-commitment-explicit-relation",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["expectedOutcome"], "accept");
    }

    #[test]
    fn verifies_reject_vector_as_recorded_refusal() {
        let verification =
            verify_encoded_relation_vector_case_value(&generated_case("wrong-quotient-rejects"));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!("EncodedRelationRejectVectorChecked"))
        );
    }

    #[test]
    fn verifies_backend_preflight_reject_vector() {
        let verification = verify_encoded_relation_vector_case_value(&generated_case(
            "noncanonical-backend-coefficient-rejects",
        ));

        assert_eq!(verification["ok"], true);
        assert_eq!(verification["expectedOutcome"], "reject");
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&serde_json::json!(
                    "EncodedBackendStatementRejectVectorChecked"
                ))
        );
    }

    #[test]
    fn rejects_proof_component_metadata_mutations() {
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponents"][0]["rowCount"] =
                json!(71);
        });
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponents"][0]["proofLoweringStatus"] =
                json!("digestExpandedRowsPending");
        });
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponents"][0]["componentDigest"] =
                json!("0".repeat(128));
        });
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponentsDigest"] =
                json!("0".repeat(128));
        });
        expect_mini_case_mutation_rejected(|vector_case| {
            vector_case["loweredStatement"]["backendStatement"]["proofComponents"][1]
                ["variableColumnIndices"]
                .as_array_mut()
                .expect("proof component variable columns should be an array")
                .push(json!(0));
        });
    }
}
