use super::backend_digest_helpers::value_without_field as encoded_relation_value_without_field;
use super::case_validation::ENCODED_COORDINATES_PER_OPTION as ENCODED_RELATION_COORDINATES_PER_OPTION;
use super::*;
use crate::ballot_privacy::protocol_constants::{
    RECEIVER_ENCRYPTION_MODULE_DEGREE as ENCODED_RELATION_RECEIVER_ENCRYPTION_MODULE_DEGREE,
    RECEIVER_ENCRYPTION_MODULE_RANK as ENCODED_RELATION_RECEIVER_ENCRYPTION_MODULE_RANK,
};
use serde_json::json;
pub(super) fn validate_component_proof_statement_plans(
    case_object: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    let Some(plans_value) = case_object.get("componentProofStatementPlans") else {
        return Ok(());
    };
    reject_forbidden_witness_keys(plans_value)?;
    let plans = plans_value.as_array().ok_or_else(|| {
        "encoded relation component proof statement plans must be an array".to_string()
    })?;
    let expected = [
        (
            "score-and-shamir-field-component",
            "65537",
            Some(64_u64),
            Some(64_u64),
            "dense-polynomial-matrix-linear-proof-v1",
            "available-for-small-dense-oracle",
            vec!["encoded_score_field_rows".to_string()],
            vec!["153".to_string()],
            Some("197120"),
            None,
            None,
            None,
            None,
        ),
        (
            "payload-plaintext-field-component",
            "65537",
            Some(64_u64),
            Some(64_u64),
            "sparse-polynomial-matrix-linear-proof-v1",
            "requires-sparse-proof-statement",
            vec![
                "receiver_payload_plaintext_binding_rows".to_string(),
                "receiver_payload_plaintext_bit_decomposition_rows".to_string(),
            ],
            vec!["450".to_string(), "3090".to_string()],
            Some("95472000"),
            Some("3540"),
            None,
            None,
            None,
        ),
        (
            "share-commitment-component",
            "18446744069414584321",
            Some(256_u64),
            Some(64_u64),
            "sparse-polynomial-matrix-linear-proof-v1",
            "requires-sparse-proof-statement",
            vec!["share_commitment_equation_rows".to_string()],
            vec!["230400".to_string()],
            Some("176947200"),
            Some("230400"),
            None,
            None,
            None,
        ),
        (
            "receiver-encryption-component",
            "12289",
            Some(256_u64),
            Some(64_u64),
            "structured-module-lwe-linear-proof-v1",
            "requires-structured-proof-statement",
            vec!["receiver_payload_encryption_equation_rows".to_string()],
            vec!["15746865".to_string()],
            Some("119981998080"),
            None,
            Some("15746865"),
            Some(12_u64),
            Some(3_u64),
        ),
        (
            "receiver-key-binding-component",
            "12289",
            None,
            None,
            "public-zero-witness-binding-check-v1",
            "public-zero-witness-binding-check",
            vec!["receiver_key_binding_rows".to_string()],
            vec!["0".to_string()],
            None,
            None,
            None,
            None,
            None,
        ),
    ];
    if plans.len() != expected.len() {
        return Err("encoded relation component proof statement plan count is invalid".to_string());
    }

    for (
        plan_value,
        (
            expected_component_id,
            expected_modulus,
            expected_source_ring_degree,
            expected_proof_ring_degree,
            expected_statement_format,
            expected_availability,
            expected_row_batch_names,
            expected_row_batch_term_counts,
            expected_dense_coefficient_count,
            expected_sparse_term_count,
            expected_structured_witness_term_count,
            expected_structured_chunk_count,
            expected_structured_receiver_count,
        ),
    ) in plans.iter().zip(expected)
    {
        let plan = object_field(plan_value, "component proof statement plan")?;
        let object_type = string_property(plan, "objectType")?;
        let object_version = u64_property(plan, "objectVersion")?;
        let component_id = string_property(plan, "componentId")?;
        let coefficient_modulus = string_property(plan, "coefficientModulus")?;
        let proof_lowering_status = string_property(plan, "proofLoweringStatus")?;
        let proof_statement_format = string_property(plan, "proofStatementFormat")?;
        let proof_bytes_availability = string_property(plan, "proofBytesAvailability")?;
        let relation = string_property(plan, "relation")?;
        let row_batch_names = array_property(plan, "rowBatchNames")?;
        let row_batch_term_counts = array_property(plan, "rowBatchTermCounts")?;
        let row_count = u64_property(plan, "rowCount")?;
        let variable_column_count = u64_property(plan, "variableColumnCount")?;
        if object_type != "BallotProofComponentProofStatementPlan"
            || object_version != 1
            || component_id != expected_component_id
            || coefficient_modulus != expected_modulus
            || proof_lowering_status != "explicitRowsAvailable"
            || proof_statement_format != expected_statement_format
            || proof_bytes_availability != expected_availability
            || relation != "A*w + t = 0"
            || row_count == 0
            || !string_array_equals(row_batch_names, &expected_row_batch_names)
            || !string_array_equals(row_batch_term_counts, &expected_row_batch_term_counts)
        {
            return Err(
                "encoded relation component proof statement plan has invalid shape".to_string(),
            );
        }
        if expected_source_ring_degree.is_none() && variable_column_count != 0 {
            return Err(
                "encoded relation zero-witness proof statement plan has variables".to_string(),
            );
        }
        validate_optional_u64_property(plan, "sourceRingDegree", expected_source_ring_degree)?;
        validate_optional_u64_property(plan, "proofSystemRingDegree", expected_proof_ring_degree)?;
        validate_optional_unsigned_decimal_property(
            plan,
            "denseCoefficientCount",
            expected_dense_coefficient_count,
        )?;
        validate_optional_unsigned_decimal_property(
            plan,
            "sparseTermCount",
            expected_sparse_term_count,
        )?;
        validate_optional_unsigned_decimal_property(
            plan,
            "structuredWitnessTermCount",
            expected_structured_witness_term_count,
        )?;
        validate_optional_u64_property(
            plan,
            "structuredCiphertextChunkCount",
            expected_structured_chunk_count,
        )?;
        validate_optional_u64_property(
            plan,
            "structuredReceiverCount",
            expected_structured_receiver_count,
        )?;
        for digest_field_name in [
            "backendStatementDigest",
            "componentProofStatementDigest",
            "componentStatementDigest",
            "matrixDigest",
            "relationStatementDigest",
            "targetVectorDigest",
        ] {
            validate_digest_string(&string_property(plan, digest_field_name)?)?;
        }
        for digest_array_field_name in [
            "rowBatchMatrixDigests",
            "rowBatchTargetVectorDigests",
            "variableColumnIndices",
        ] {
            let values = array_property(plan, digest_array_field_name)?;
            if digest_array_field_name == "variableColumnIndices" {
                continue;
            }
            for value in values {
                validate_digest_string(value.as_str().ok_or_else(|| {
                    format!("{digest_array_field_name} entries must be strings")
                })?)?;
            }
        }
        let expected_digest = derive_backend_digest(
            "ballot-proof-component-proof-statement-plan-v1",
            encoded_relation_value_without_field(plan_value, "componentProofStatementDigest")?,
        )?;
        if string_property(plan, "componentProofStatementDigest")? != expected_digest {
            return Err(
                "encoded relation component proof statement plan digest is invalid".to_string(),
            );
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct EncodedRelationDimensions {
    pub(super) option_count: u64,
    pub(super) roster_size: u64,
    pub(super) pvss_threshold: u64,
    pub(super) share_vector_width: u64,
    pub(super) encoded_coordinate_count: u64,
    pub(super) linear_row_count: u64,
    pub(super) algebraic_row_count: u64,
    pub(super) variable_count: u64,
    pub(super) bound_count: u64,
}

pub(super) fn validate_statement_dimensions(
    dimensions: EncodedRelationDimensions,
) -> Result<(), String> {
    if dimensions.option_count == 0
        || dimensions.option_count > 20
        || dimensions.roster_size == 0
        || dimensions.pvss_threshold == 0
    {
        return Err("encoded relation dimensions are outside supported ranges".to_string());
    }
    if dimensions.share_vector_width
        != dimensions.option_count * ENCODED_RELATION_COORDINATES_PER_OPTION
        || dimensions.encoded_coordinate_count != dimensions.share_vector_width
    {
        return Err("encoded relation share-vector width is not encoded-score width".to_string());
    }
    let expected_score_and_shamir_rows =
        dimensions.option_count * 2 + dimensions.roster_size * dimensions.encoded_coordinate_count;
    let expected_payload_plaintext_rows = dimensions.roster_size
        * (dimensions.encoded_coordinate_count + OPENING_VARIABLES_PER_RECEIVER);
    let expected_linear_rows_without_payload_bit_decomposition =
        expected_score_and_shamir_rows + expected_payload_plaintext_rows;
    let expected_linear_rows_with_payload_bit_decomposition =
        expected_linear_rows_without_payload_bit_decomposition + expected_payload_plaintext_rows;
    let has_payload_bit_decomposition_rows =
        dimensions.linear_row_count == expected_linear_rows_with_payload_bit_decomposition;
    if dimensions.linear_row_count != expected_linear_rows_without_payload_bit_decomposition
        && !has_payload_bit_decomposition_rows
    {
        return Err("encoded relation linear row count does not match dimensions".to_string());
    }
    let expected_algebraic_rows = dimensions.roster_size * ALGEBRAIC_ROWS_PER_RECEIVER;
    if dimensions.algebraic_row_count != expected_algebraic_rows {
        return Err("encoded relation algebraic row count does not match dimensions".to_string());
    }
    let expected_digest_expanded_variable_count = dimensions.encoded_coordinate_count
        * (dimensions.pvss_threshold + 2 * dimensions.roster_size)
        + dimensions.roster_size
            * (dimensions.encoded_coordinate_count
                + 2 * OPENING_VARIABLES_PER_RECEIVER
                + ENCRYPTION_BATCH_VARIABLES_PER_RECEIVER);
    let receiver_payload_bit_count = dimensions.encoded_coordinate_count
        * RECEIVER_SHARE_REPRESENTATIVE_BIT_LENGTH
        + OPENING_VARIABLES_PER_RECEIVER * RECEIVER_OPENING_RANDOMNESS_BIT_LENGTH;
    let receiver_payload_ciphertext_chunk_count =
        receiver_payload_bit_count.div_ceil(ENCODED_RELATION_RECEIVER_ENCRYPTION_MODULE_DEGREE);
    let receiver_encryption_witness_variables_per_receiver = receiver_payload_ciphertext_chunk_count
        * (2 * ENCODED_RELATION_RECEIVER_ENCRYPTION_MODULE_RANK
            * ENCODED_RELATION_RECEIVER_ENCRYPTION_MODULE_DEGREE
            + ENCODED_RELATION_RECEIVER_ENCRYPTION_MODULE_DEGREE);
    let expected_full_explicit_variable_count = dimensions.encoded_coordinate_count
        * (dimensions.pvss_threshold + 2 * dimensions.roster_size)
        + dimensions.roster_size
            * (dimensions.encoded_coordinate_count
                + 2 * OPENING_VARIABLES_PER_RECEIVER
                + receiver_payload_bit_count
                + receiver_encryption_witness_variables_per_receiver);
    if dimensions.variable_count != expected_digest_expanded_variable_count
        && dimensions.variable_count != expected_full_explicit_variable_count
    {
        return Err("encoded relation variable count does not match dimensions".to_string());
    }
    let expected_bound_count = dimensions.option_count * 10 + 12;
    if dimensions.bound_count != expected_bound_count {
        return Err("encoded relation bound count does not match dimensions".to_string());
    }

    Ok(())
}

pub(super) struct BackendSummaryCounts {
    pub(super) backend_column_count: u64,
    pub(super) backend_digest_expanded_row_count: u64,
    pub(super) backend_explicit_row_count: u64,
    pub(super) backend_proof_component_count: u64,
    pub(super) backend_row_batch_count: u64,
    pub(super) backend_row_count: u64,
    pub(super) dimensions: EncodedRelationDimensions,
}

pub(super) fn expected_digest_expanded_backend_rows(dimensions: EncodedRelationDimensions) -> u64 {
    dimensions.roster_size
        * (SHARE_COMMITMENT_EQUATION_ROWS
            + RECEIVER_ENCRYPTION_EQUATION_ROWS
            + RECEIVER_KEY_EQUATION_ROWS)
}

pub(super) fn expected_receiver_encryption_explicit_rows(
    dimensions: EncodedRelationDimensions,
) -> u64 {
    let receiver_payload_bit_count = dimensions.encoded_coordinate_count
        * RECEIVER_SHARE_REPRESENTATIVE_BIT_LENGTH
        + OPENING_VARIABLES_PER_RECEIVER * RECEIVER_OPENING_RANDOMNESS_BIT_LENGTH;
    let receiver_payload_ciphertext_chunk_count =
        receiver_payload_bit_count.div_ceil(ENCODED_RELATION_RECEIVER_ENCRYPTION_MODULE_DEGREE);

    dimensions.roster_size
        * receiver_payload_ciphertext_chunk_count
        * RECEIVER_ENCRYPTION_EQUATION_ROWS
}

pub(super) fn expected_payload_plaintext_rows(dimensions: EncodedRelationDimensions) -> u64 {
    dimensions.roster_size * (dimensions.encoded_coordinate_count + OPENING_VARIABLES_PER_RECEIVER)
}

pub(super) fn expected_score_and_shamir_rows(dimensions: EncodedRelationDimensions) -> u64 {
    dimensions.option_count * 2 + dimensions.roster_size * dimensions.encoded_coordinate_count
}

pub(super) fn validate_backend_summary_counts(counts: BackendSummaryCounts) -> Result<(), String> {
    if counts.backend_column_count != counts.dimensions.variable_count {
        return Err("encoded relation backend column count does not match variables".to_string());
    }
    if counts.backend_explicit_row_count < counts.dimensions.linear_row_count {
        return Err(
            "encoded relation backend explicit row count is smaller than linear rows".to_string(),
        );
    }
    let explicit_algebraic_rows =
        counts.backend_explicit_row_count - counts.dimensions.linear_row_count;
    let expected_share_commitment_rows =
        counts.dimensions.roster_size * SHARE_COMMITMENT_EQUATION_ROWS;
    let expected_receiver_key_rows = counts.dimensions.roster_size * RECEIVER_KEY_EQUATION_ROWS;
    let expected_full_explicit_algebraic_rows = expected_share_commitment_rows
        + expected_receiver_encryption_explicit_rows(counts.dimensions)
        + expected_receiver_key_rows;
    if explicit_algebraic_rows != 0
        && explicit_algebraic_rows != expected_share_commitment_rows
        && explicit_algebraic_rows != expected_full_explicit_algebraic_rows
    {
        return Err(
            "encoded relation backend explicit row count does not match the explicit component coverage".to_string(),
        );
    }
    let expected_digest_expanded_rows =
        if explicit_algebraic_rows == expected_full_explicit_algebraic_rows {
            0
        } else {
            expected_digest_expanded_backend_rows(counts.dimensions) - explicit_algebraic_rows
        };
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
    let base_linear_rows = expected_score_and_shamir_rows(counts.dimensions)
        + expected_payload_plaintext_rows(counts.dimensions);
    let payload_bit_decomposition_batch_count =
        if counts.dimensions.linear_row_count > base_linear_rows {
            1
        } else {
            0
        };
    let expected_row_batch_count = if explicit_algebraic_rows == 0 {
        EXPLICIT_ROW_BATCHES_BEFORE_ALGEBRAIC_ROWS
            + payload_bit_decomposition_batch_count
            + counts.dimensions.algebraic_row_count
    } else if explicit_algebraic_rows == expected_share_commitment_rows {
        EXPLICIT_ROW_BATCHES_WITH_SHARE_COMMITMENT_ROWS
            + payload_bit_decomposition_batch_count
            + counts.dimensions.algebraic_row_count
            - counts.dimensions.roster_size
    } else {
        EXPLICIT_ROW_BATCHES_WITH_SHARE_COMMITMENT_ROWS + payload_bit_decomposition_batch_count + 2
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

pub(super) fn validate_digest_change_trace(
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

pub(super) fn validate_row_kinds(linear_rows: &[Value]) -> Result<(), String> {
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

pub(super) fn validate_algebraic_row_kinds(algebraic_rows: &[Value]) -> Result<(), String> {
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

pub(super) fn validate_backend_statement(
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
        encoded_relation_value_without_field(&backend_statement_value, "backendStatementDigest")?;
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

pub(super) fn validate_backend_variable_columns(
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

pub(super) fn validate_backend_row_batches(
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

pub(super) fn validate_score_explicit_backend_row_batch(
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

pub(super) fn validate_payload_explicit_backend_row_batch(
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

pub(super) fn validate_share_commitment_explicit_backend_row_batch(
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
