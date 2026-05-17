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
const ALGEBRAIC_ROWS_PER_RECEIVER: u64 = 4;
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

    match (full_statement, statement_summary) {
        (Some(statement), None) => validate_full_statement(statement),
        (None, Some(summary)) => validate_statement_summary(summary),
        (Some(_), Some(_)) => Err(
            "encoded relation accept vector must not include both full statement and summary"
                .to_string(),
        ),
        (None, None) => Err(
            "encoded relation accept vector requires a lowered statement or summary".to_string(),
        ),
    }
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
        || string_property(last_linear_row, "rowKind")? != "ShamirEvaluationQuotient"
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
    validate_digest_string(&backend_statement_digest)?;
    validate_digest_string(&relation_statement_digest)?;

    Ok(relation_statement_digest)
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
    let expected_linear_rows =
        dimensions.option_count * 2 + dimensions.roster_size * dimensions.encoded_coordinate_count;
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
            * (OPENING_VARIABLES_PER_RECEIVER + ENCRYPTION_BATCH_VARIABLES_PER_RECEIVER);
    if dimensions.variable_count != expected_variable_count {
        return Err("encoded relation variable count does not match dimensions".to_string());
    }
    let expected_bound_count = dimensions.option_count * 10 + 7;
    if dimensions.bound_count != expected_bound_count {
        return Err("encoded relation bound count does not match dimensions".to_string());
    }

    Ok(())
}

struct BackendSummaryCounts {
    backend_column_count: u64,
    backend_digest_expanded_row_count: u64,
    backend_explicit_row_count: u64,
    backend_row_batch_count: u64,
    backend_row_count: u64,
    dimensions: EncodedRelationDimensions,
}

fn expected_digest_expanded_backend_rows(dimensions: EncodedRelationDimensions) -> u64 {
    dimensions.roster_size
        * (SHARE_COMMITMENT_EQUATION_ROWS
            + dimensions.encoded_coordinate_count
            + OPENING_VARIABLES_PER_RECEIVER
            + RECEIVER_ENCRYPTION_EQUATION_ROWS
            + RECEIVER_KEY_EQUATION_ROWS)
}

fn validate_backend_summary_counts(counts: BackendSummaryCounts) -> Result<(), String> {
    if counts.backend_column_count != counts.dimensions.variable_count {
        return Err("encoded relation backend column count does not match variables".to_string());
    }
    if counts.backend_explicit_row_count != counts.dimensions.linear_row_count {
        return Err(
            "encoded relation backend explicit row count does not match linear rows".to_string(),
        );
    }
    let expected_digest_expanded_rows = expected_digest_expanded_backend_rows(counts.dimensions);
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
    if counts.backend_row_batch_count != 1 + counts.dimensions.algebraic_row_count {
        return Err("encoded relation backend row-batch count does not match rows".to_string());
    }

    Ok(())
}

fn infer_threshold_from_counts(
    encoded_coordinate_count: u64,
    roster_size: u64,
    variable_count: u64,
) -> Result<u64, String> {
    if encoded_coordinate_count == 0 || !variable_count.is_multiple_of(encoded_coordinate_count) {
        return Err(
            "encoded relation summary variable count is not divisible by width".to_string(),
        );
    }
    let algebraic_batch_variable_count =
        roster_size * (OPENING_VARIABLES_PER_RECEIVER + ENCRYPTION_BATCH_VARIABLES_PER_RECEIVER);
    if variable_count < algebraic_batch_variable_count {
        return Err("encoded relation summary variable count is too small".to_string());
    }
    let linear_variable_count = variable_count - algebraic_batch_variable_count;
    if !linear_variable_count.is_multiple_of(encoded_coordinate_count) {
        return Err(
            "encoded relation summary linear variable count is not divisible by width".to_string(),
        );
    }
    let variables_per_coordinate = linear_variable_count / encoded_coordinate_count;
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
            != "ShamirEvaluationQuotient"
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
            "ReceiverPayloadPlaintextBinding",
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

    validate_backend_summary_counts(BackendSummaryCounts {
        backend_column_count: column_count,
        backend_digest_expanded_row_count: digest_expanded_row_count,
        backend_explicit_row_count: explicit_row_count,
        backend_row_batch_count: row_batches.len() as u64,
        backend_row_count: row_count,
        dimensions,
    })?;
    validate_backend_variable_columns(variable_columns, column_count)?;
    validate_backend_row_batches(row_batches, column_count, dimensions)?;
    validate_backend_bounds(backend_bounds, column_count, dimensions.bound_count)?;

    let matrix_digest = string_property(backend_statement, "matrixDigest")?;
    let target_vector_digest = string_property(backend_statement, "targetVectorDigest")?;
    let bounds_digest = string_property(backend_statement, "boundsDigest")?;
    let backend_statement_digest = string_property(backend_statement, "backendStatementDigest")?;
    validate_digest_string(&matrix_digest)?;
    validate_digest_string(&target_vector_digest)?;
    validate_digest_string(&bounds_digest)?;
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
    if row_batches.len() as u64 != 1 + dimensions.algebraic_row_count {
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
            validate_explicit_backend_row_batch(batch_object, column_count, dimensions)?;
        } else {
            validate_digest_expanded_backend_row_batch(batch_object, column_count, dimensions)?;
        }
        if batch_kind == "ExplicitSparseRows" && batch_index != 0 {
            return Err(
                "encoded relation backend explicit rows must be the first batch".to_string(),
            );
        }
        expected_row_offset += row_count;
    }
    let expected_row_count =
        dimensions.linear_row_count + expected_digest_expanded_backend_rows(dimensions);
    if expected_row_offset != expected_row_count {
        return Err("encoded relation backend row count does not match dimensions".to_string());
    }

    Ok(())
}

fn validate_explicit_backend_row_batch(
    batch_object: &serde_json::Map<String, Value>,
    column_count: u64,
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    if string_property(batch_object, "batchKind")? != "ExplicitSparseRows"
        || string_property(batch_object, "batchName")? != "encoded_score_field_rows"
        || string_property(batch_object, "rowKind")? != "EncodedScoreFieldRows"
        || string_property(batch_object, "modulus")? != FIELD_MODULUS.to_string()
        || u64_property(batch_object, "rowCount")? != dimensions.linear_row_count
    {
        return Err("encoded relation backend explicit row batch is not canonical".to_string());
    }
    let rows = array_property(batch_object, "rows")?;
    if rows.len() as u64 != dimensions.linear_row_count {
        return Err("encoded relation backend explicit row count is invalid".to_string());
    }
    for (expected_row_index, row) in rows.iter().enumerate() {
        let row_object = object_field(row, "backend explicit row")?;
        if u64_property(row_object, "rowIndex")? != expected_row_index as u64 {
            return Err(
                "encoded relation backend explicit row indexes are not canonical".to_string(),
            );
        }
        if string_property(row_object, "modulus")? != FIELD_MODULUS.to_string() {
            return Err("encoded relation backend explicit row modulus is invalid".to_string());
        }
        let row_kind = string_property(row_object, "rowKind")?;
        if !matches!(
            row_kind.as_str(),
            "OneHotSum" | "ScalarScoreConsistency" | "ShamirEvaluationQuotient"
        ) {
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
    validate_batch_digest_pair(
        batch_object,
        EXPLICIT_BACKEND_MATRIX_DIGEST_PURPOSE,
        EXPLICIT_BACKEND_TARGET_VECTOR_DIGEST_PURPOSE,
        explicit_backend_matrix_payload(rows)?,
        explicit_backend_target_payload(rows)?,
    )
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
        "ReceiverPayloadPlaintextBinding" => {
            dimensions.encoded_coordinate_count + OPENING_VARIABLES_PER_RECEIVER
        }
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
        "commitmentPolynomialVector",
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
    use serde_json::Value;

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
}
