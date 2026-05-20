use super::*;

pub(crate) fn matrix_coefficient_representation_from_statement(
    statement: &Value,
    object_name: &str,
) -> crate::encoding::CanonicalResult<LinearProofMatrixCoefficientRepresentation> {
    let Some(value) =
        object_map(statement).and_then(|object| object.get("matrixCoefficientRepresentation"))
    else {
        return Ok(LinearProofMatrixCoefficientRepresentation::default());
    };

    serde_json::from_value(value.clone()).map_err(|error| {
        invalid_preflight(format!(
            "{object_name}.matrixCoefficientRepresentation is malformed: {error}"
        ))
    })
}

pub(crate) fn decode_32_byte_hex(
    hex_value: &str,
    field_name: &str,
) -> crate::encoding::CanonicalResult<[u8; 32]> {
    let bytes = decode_hex(hex_value)?;
    if bytes.len() != 32 {
        return Err(invalid_preflight(format!(
            "{field_name} must encode exactly 32 bytes"
        )));
    }

    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_preflight(format!("{field_name} must encode exactly 32 bytes")))
}

pub(crate) fn source_witness_coefficients(
    secret_state: &Value,
) -> crate::encoding::CanonicalResult<Vec<Vec<i64>>> {
    let secret_state = object_map(secret_state)
        .ok_or_else(|| invalid_preflight("secretState must be an object"))?;
    signed_polynomial_vector_field(secret_state, "sourceWitnessCoefficients")
}

pub(crate) fn receiver_key_source_witness_coefficients(
    secret_state: &Value,
) -> crate::encoding::CanonicalResult<Vec<Vec<i64>>> {
    let secret_state = object_map(secret_state)
        .ok_or_else(|| invalid_preflight("secretState must be an object"))?;
    let mut source_witness_coefficients =
        signed_polynomial_vector_field(secret_state, "secretVector")?;
    source_witness_coefficients
        .extend(signed_polynomial_vector_field(secret_state, "errorVector")?);

    Ok(source_witness_coefficients)
}

pub(crate) fn signed_polynomial_vector_field(
    object: &Map<String, Value>,
    field_name: &str,
) -> crate::encoding::CanonicalResult<Vec<Vec<i64>>> {
    let vector = object
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_preflight(format!("secretState.{field_name} must be an array")))?;

    vector
        .iter()
        .enumerate()
        .map(|(polynomial_index, polynomial)| {
            let coefficients = polynomial.as_array().ok_or_else(|| {
                invalid_preflight(format!(
                    "secretState.{field_name}[{polynomial_index}] must be an array"
                ))
            })?;

            coefficients
                .iter()
                .enumerate()
                .map(|(coefficient_index, coefficient)| {
                    coefficient.as_i64().ok_or_else(|| {
                        invalid_preflight(format!(
                            "secretState.{field_name}[{polynomial_index}][{coefficient_index}] must be a signed integer"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

pub(crate) fn invalid_preflight(message: impl Into<String>) -> crate::encoding::CanonicalError {
    crate::encoding::CanonicalError::new(
        crate::encoding::CanonicalErrorCode::InvalidFixture,
        message,
    )
}

pub(crate) fn string_array_matches_expected(
    value: &Value,
    field_name: &str,
    expected_values: &[&str],
) -> bool {
    let Some(values) = array_field(value, field_name) else {
        return false;
    };

    values.len() == expected_values.len()
        && values
            .iter()
            .zip(expected_values.iter())
            .all(|(actual_value, expected_value)| actual_value.as_str() == Some(*expected_value))
}

pub(crate) fn string_array_length(value: &Value, field_name: &str) -> Option<usize> {
    Some(
        array_field(value, field_name)?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?
            .len(),
    )
}
