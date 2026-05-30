use super::*;

pub(crate) fn component_proof_backend_rejection(
    operation: &str,
    component_id: &str,
    refused_objects: Vec<Value>,
    unresolved_reason: Value,
) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "statusLabels": [],
        "acceptedHashes": [],
        "refusedObjects": refused_objects,
        "componentId": component_id,
        "unresolvedReason": unresolved_reason
    })
}

// Accepts a JSON number or a canonical decimal string (no leading zeros, except "0" itself), so a
// JSON int and its decimal-string form encode the same value and hash identically.
pub(crate) fn integer_value(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text)
            if text == "0"
                || (!text.starts_with('0') && text.bytes().all(|byte| byte.is_ascii_digit())) =>
        {
            text.parse::<u64>().ok()
        }
        _ => None,
    }
}

pub(crate) fn usize_object_field(value: &Value, field_name: &str) -> Option<usize> {
    object_map(value)?
        .get(field_name)
        .and_then(integer_value)
        .and_then(|field_value| usize::try_from(field_value).ok())
}

pub(crate) fn u64_object_field(value: &Value, field_name: &str) -> Option<u64> {
    object_map(value)?.get(field_name).and_then(integer_value)
}

pub(crate) fn derive_sparse_statement_matrix_hash(matrix_entries: &Value) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "purpose": "ballot-proof-sparse-linear-statement-matrix-v1",
            "sparseStatementMatrixEntries": matrix_entries
        }),
    )
}

pub(crate) fn derive_sparse_target_vector_hash(target_entries: &Value) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "purpose": "ballot-proof-sparse-linear-target-vector-v1",
            "targetVectorEntries": target_entries
        }),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComponentProofBackendError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl ComponentProofBackendError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "BallotPackageInvalid",
            message: message.into(),
        }
    }

    pub(crate) fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: "OperationUnavailable",
            message: message.into(),
        }
    }
}

pub(crate) struct ParsedSparseComponentProofStatement {
    pub(crate) source_statement_matrix: SparsePolynomialMatrix,
    pub(crate) target_vector_coefficients: Vec<Vec<u64>>,
}

#[derive(Clone)]
pub(crate) struct ParsedStructuredReceiverEncryptionStatement {
    pub(crate) statement_hash: String,
    pub(crate) statement_rows: usize,
    pub(crate) statement_columns: usize,
    pub(crate) source_statement_matrix: SparsePolynomialMatrix,
    pub(crate) target_vector_coefficients: Vec<Vec<u64>>,
}

pub(crate) fn parse_sparse_polynomial_entry(
    entry: &Value,
    constant_field_name: &str,
    polynomial_field_name: &str,
    source_ring_degree: usize,
    coefficient_modulus: u64,
    entry_label: &str,
) -> Result<Vec<u64>, ComponentProofBackendError> {
    let entry_object = object_map(entry).ok_or_else(|| {
        ComponentProofBackendError::invalid(format!("{entry_label} must be an object."))
    })?;
    let constant_coefficient = entry_object
        .get(constant_field_name)
        .and_then(integer_value);
    let polynomial_coefficients = entry_object.get(polynomial_field_name);

    match (constant_coefficient, polynomial_coefficients) {
        (Some(coefficient), None) => {
            if coefficient >= coefficient_modulus {
                return Err(ComponentProofBackendError::invalid(format!(
                    "{entry_label} coefficient is not canonical."
                )));
            }
            let mut coefficients = vec![0_u64; source_ring_degree];
            coefficients[0] = coefficient;

            Ok(coefficients)
        }
        (None, Some(polynomial_value)) => {
            let polynomial_array = polynomial_value.as_array().ok_or_else(|| {
                ComponentProofBackendError::invalid(format!(
                    "{entry_label} polynomial coefficients must be an array."
                ))
            })?;
            if polynomial_array.len() != source_ring_degree {
                return Err(ComponentProofBackendError::invalid(format!(
                    "{entry_label} polynomial degree does not match sourceRingDegree."
                )));
            }
            let mut coefficients = Vec::with_capacity(source_ring_degree);
            for coefficient_value in polynomial_array {
                let coefficient = integer_value(coefficient_value).ok_or_else(|| {
                    ComponentProofBackendError::invalid(format!(
                        "{entry_label} polynomial coefficient is not a canonical integer."
                    ))
                })?;
                if coefficient >= coefficient_modulus {
                    return Err(ComponentProofBackendError::invalid(format!(
                        "{entry_label} polynomial coefficient is not canonical."
                    )));
                }
                coefficients.push(coefficient);
            }

            Ok(coefficients)
        }
        (Some(_), Some(_)) => Err(ComponentProofBackendError::invalid(format!(
            "{entry_label} must use either {constant_field_name} or {polynomial_field_name}, not both."
        ))),
        (None, None) => Err(ComponentProofBackendError::invalid(format!(
            "{entry_label} is missing {constant_field_name} or {polynomial_field_name}."
        ))),
    }
}

pub(crate) fn polynomial_is_zero(coefficients: &[u64]) -> bool {
    coefficients.iter().all(|coefficient| *coefficient == 0)
}

pub(crate) fn sparse_matrix_from_sparse_component_statement(
    sparse_statement: &Value,
) -> Result<ParsedSparseComponentProofStatement, ComponentProofBackendError> {
    let statement_rows =
        usize_object_field(sparse_statement, "statementRows").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing statementRows.",
            )
        })?;
    let statement_columns =
        usize_object_field(sparse_statement, "statementColumns").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing statementColumns.",
            )
        })?;
    let source_ring_degree =
        usize_object_field(sparse_statement, "sourceRingDegree").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing sourceRingDegree.",
            )
        })?;
    let coefficient_modulus =
        u64_object_field(sparse_statement, "coefficientModulus").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing coefficientModulus.",
            )
        })?;
    let matrix_entries_value = object_map(sparse_statement)
        .and_then(|object| object.get("sparseStatementMatrixEntries"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing sparseStatementMatrixEntries.",
            )
        })?;
    let matrix_entries = matrix_entries_value.as_array().ok_or_else(|| {
        ComponentProofBackendError::invalid(
            "Sparse component proof statement matrix entries must be an array.",
        )
    })?;
    let target_entries_value = object_map(sparse_statement)
        .and_then(|object| object.get("targetVectorEntries"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing targetVectorEntries.",
            )
        })?;
    let target_entries = target_entries_value.as_array().ok_or_else(|| {
        ComponentProofBackendError::invalid(
            "Sparse component proof statement target entries must be an array.",
        )
    })?;

    if usize_object_field(sparse_statement, "sparseStatementTermCount")
        != Some(matrix_entries.len())
    {
        return Err(ComponentProofBackendError::invalid(
            "Sparse component proof statement matrix term count does not match entries."
                .to_string(),
        ));
    }
    if usize_object_field(sparse_statement, "targetVectorEntryCount") != Some(target_entries.len())
    {
        return Err(ComponentProofBackendError::invalid(
            "Sparse component proof statement target entry count does not match entries."
                .to_string(),
        ));
    }
    if string_field(sparse_statement, "sparseStatementMatrixHash")
        != derive_sparse_statement_matrix_hash(matrix_entries_value).as_deref()
    {
        return Err(ComponentProofBackendError::invalid(
            "Sparse component proof statement matrix hash does not match entries.",
        ));
    }
    if string_field(sparse_statement, "targetVectorHash")
        != derive_sparse_target_vector_hash(target_entries_value).as_deref()
    {
        return Err(ComponentProofBackendError::invalid(
            "Sparse component proof statement target vector hash does not match entries."
                .to_string(),
        ));
    }

    let source_ring =
        PolynomialRing::new(source_ring_degree, coefficient_modulus).map_err(|error| {
            ComponentProofBackendError::invalid(format!(
                "Sparse component proof statement ring is invalid: {}",
                error.message
            ))
        })?;
    let mut sparse_matrix_entries = Vec::with_capacity(matrix_entries.len());
    let mut seen_matrix_positions = BTreeSet::new();
    for matrix_entry in matrix_entries {
        let row_index = usize_object_field(matrix_entry, "rowIndex").ok_or_else(|| {
            ComponentProofBackendError::invalid("Sparse matrix entry is missing rowIndex.")
        })?;
        let column_index = usize_object_field(matrix_entry, "columnIndex").ok_or_else(|| {
            ComponentProofBackendError::invalid("Sparse matrix entry is missing columnIndex.")
        })?;
        let coefficients = parse_sparse_polynomial_entry(
            matrix_entry,
            "constantCoefficient",
            "polynomialCoefficients",
            source_ring_degree,
            coefficient_modulus,
            "Sparse matrix entry",
        )?;
        if row_index >= statement_rows || column_index >= statement_columns {
            return Err(ComponentProofBackendError::invalid(
                "Sparse matrix entry index is outside the statement shape.",
            ));
        }
        // Reject stored zero polynomials and duplicate (row, column) positions to keep the sparse
        // encoding canonical, so the matrix hash is well-defined (one encoding per matrix).
        if polynomial_is_zero(&coefficients) {
            return Err(ComponentProofBackendError::invalid(
                "Sparse matrix entries must not store zero polynomials.",
            ));
        }
        if !seen_matrix_positions.insert((row_index, column_index)) {
            return Err(ComponentProofBackendError::invalid(
                "Sparse matrix entries contain a duplicate position.",
            ));
        }
        sparse_matrix_entries.push(SparsePolynomialMatrixEntry::new(
            row_index,
            column_index,
            coefficients,
        ));
    }
    sparse_matrix_entries.sort_by_key(|entry| (entry.row_index(), entry.column_index()));
    let source_statement_matrix = SparsePolynomialMatrix::new(
        source_ring,
        statement_rows,
        statement_columns,
        sparse_matrix_entries,
    )
    .map_err(|error| {
        ComponentProofBackendError::invalid(format!(
            "Sparse component proof statement matrix is invalid: {}",
            error.message
        ))
    })?;

    let mut target_vector_coefficients = vec![vec![0_u64; source_ring_degree]; statement_rows];
    let mut seen_target_positions = BTreeSet::new();
    for target_entry in target_entries {
        let row_index = usize_object_field(target_entry, "rowIndex").ok_or_else(|| {
            ComponentProofBackendError::invalid("Sparse target entry is missing rowIndex.")
        })?;
        let coefficients = parse_sparse_polynomial_entry(
            target_entry,
            "constantCoefficient",
            "polynomialCoefficients",
            source_ring_degree,
            coefficient_modulus,
            "Sparse target entry",
        )?;
        if row_index >= statement_rows {
            return Err(ComponentProofBackendError::invalid(
                "Sparse target entry index is outside the statement shape.",
            ));
        }
        if polynomial_is_zero(&coefficients) {
            return Err(ComponentProofBackendError::invalid(
                "Sparse target entries must not store zero polynomials.",
            ));
        }
        if !seen_target_positions.insert(row_index) {
            return Err(ComponentProofBackendError::invalid(
                "Sparse target entries contain a duplicate position.",
            ));
        }
        target_vector_coefficients[row_index] = coefficients;
    }

    Ok(ParsedSparseComponentProofStatement {
        source_statement_matrix,
        target_vector_coefficients,
    })
}

#[cfg(test)]
pub(crate) fn dense_matrix_from_sparse_component_statement(
    sparse_statement: &Value,
) -> Result<(Value, Value), ComponentProofBackendError> {
    let parsed_sparse_statement = sparse_matrix_from_sparse_component_statement(sparse_statement)?;
    Ok((
        json!(
            parsed_sparse_statement
                .source_statement_matrix
                .to_dense()
                .map_err(|error| ComponentProofBackendError::invalid(format!(
                    "Sparse component proof statement could not be densified for the test backend: {}",
                    error.message
                )))?
                .entries_by_row()
        ),
        json!(parsed_sparse_statement.target_vector_coefficients),
    ))
}
