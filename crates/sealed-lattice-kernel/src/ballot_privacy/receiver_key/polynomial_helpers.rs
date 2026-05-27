use super::*;

pub(crate) fn parse_receiver_polynomial(
    value: &Value,
    label: &str,
) -> Result<Vec<u64>, ComponentProofBackendError> {
    let coefficients = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if coefficients.len() != RECEIVER_ENCRYPTION_MODULE_DEGREE as usize {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} must have the frozen receiver-encryption degree."
        )));
    }
    coefficients
        .iter()
        .map(|coefficient_value| {
            let coefficient = integer_value(coefficient_value).ok_or_else(|| {
                ComponentProofBackendError::invalid(format!(
                    "{label} coefficient is not a canonical integer."
                ))
            })?;
            if coefficient >= RECEIVER_ENCRYPTION_MODULUS {
                return Err(ComponentProofBackendError::invalid(format!(
                    "{label} coefficient is outside the receiver-encryption modulus."
                )));
            }
            Ok(coefficient)
        })
        .collect()
}

pub(crate) fn parse_receiver_polynomial_vector(
    value: &Value,
    label: &str,
) -> Result<Vec<Vec<u64>>, ComponentProofBackendError> {
    let polynomials = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if polynomials.len() != RECEIVER_ENCRYPTION_MODULE_RANK as usize {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} must have the frozen receiver-encryption module rank."
        )));
    }
    polynomials
        .iter()
        .enumerate()
        .map(|(polynomial_index, polynomial)| {
            parse_receiver_polynomial(
                polynomial,
                &format!("{label} polynomial {polynomial_index}"),
            )
        })
        .collect()
}

pub(crate) fn parse_receiver_column_vector(
    value: &Value,
    expected_length: usize,
    statement_columns: usize,
    label: &str,
) -> Result<Vec<usize>, ComponentProofBackendError> {
    let column_indices = parse_receiver_column_vector_with_max_len(
        value,
        expected_length,
        statement_columns,
        label,
    )?;
    if column_indices.len() != expected_length {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} length does not match the expected receiver-encryption dimension."
        )));
    }

    Ok(column_indices)
}

pub(crate) fn parse_receiver_column_index(
    value: &Value,
    statement_columns: usize,
    label: &str,
) -> Result<usize, ComponentProofBackendError> {
    let column_index = integer_value(value)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(format!("{label} is not a canonical column index."))
        })?;
    if column_index >= statement_columns {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} is outside the statement column range."
        )));
    }

    Ok(column_index)
}

pub(crate) fn parse_receiver_column_vector_with_max_len(
    value: &Value,
    maximum_length: usize,
    statement_columns: usize,
    label: &str,
) -> Result<Vec<usize>, ComponentProofBackendError> {
    let column_values = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if column_values.len() > maximum_length {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} length exceeds the receiver-encryption degree."
        )));
    }
    let mut column_indices = Vec::with_capacity(column_values.len());
    for column_value in column_values {
        let column_index = integer_value(column_value)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(format!(
                    "{label} entry is not a canonical column index."
                ))
            })?;
        if column_index >= statement_columns {
            return Err(ComponentProofBackendError::invalid(format!(
                "{label} entry is outside the statement column range."
            )));
        }
        column_indices.push(column_index);
    }

    Ok(column_indices)
}

#[cfg(test)]
pub(crate) fn parse_receiver_column_matrix(
    value: &Value,
    statement_columns: usize,
    label: &str,
) -> Result<Vec<Vec<usize>>, ComponentProofBackendError> {
    let rows = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if rows.len() != RECEIVER_ENCRYPTION_MODULE_RANK as usize {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} must have the frozen receiver-encryption module rank."
        )));
    }
    rows.iter()
        .enumerate()
        .map(|(row_index, row)| {
            parse_receiver_column_vector(
                row,
                RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
                statement_columns,
                &format!("{label} row {row_index}"),
            )
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn negacyclic_receiver_coefficient(
    polynomial: &[u64],
    output_coefficient_index: usize,
    witness_coefficient_index: usize,
) -> u64 {
    if output_coefficient_index >= witness_coefficient_index {
        polynomial[output_coefficient_index - witness_coefficient_index]
            % RECEIVER_ENCRYPTION_MODULUS
    } else {
        negate_receiver_coefficient(
            polynomial[RECEIVER_ENCRYPTION_MODULE_DEGREE as usize + output_coefficient_index
                - witness_coefficient_index],
        )
    }
}

pub(crate) fn negate_receiver_coefficient(coefficient: u64) -> u64 {
    if coefficient == 0 {
        0
    } else {
        RECEIVER_ENCRYPTION_MODULUS - coefficient
    }
}

pub(crate) fn negate_receiver_polynomial(polynomial: &[u64]) -> Vec<u64> {
    polynomial
        .iter()
        .map(|coefficient| negate_receiver_coefficient(*coefficient))
        .collect()
}

pub(crate) fn receiver_constant_polynomial(coefficient: u64) -> Vec<u64> {
    let mut polynomial = vec![0_u64; RECEIVER_ENCRYPTION_MODULE_DEGREE as usize];
    polynomial[0] = coefficient;
    polynomial
}

pub(crate) fn push_receiver_sparse_entry(
    entries: &mut Vec<SparsePolynomialMatrixEntry>,
    row_index: usize,
    column_index: usize,
    coefficients: Vec<u64>,
) {
    if coefficients.iter().any(|coefficient| *coefficient != 0) {
        entries.push(SparsePolynomialMatrixEntry::new(
            row_index,
            column_index,
            coefficients,
        ));
    }
}

pub(crate) fn parse_share_commitment_polynomial(
    value: &Value,
    label: &str,
) -> Result<Vec<u64>, ComponentProofBackendError> {
    let coefficients = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if coefficients.len() != SHARE_COMMITMENT_MODULE_DEGREE {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} must have the frozen share-commitment degree."
        )));
    }
    coefficients
        .iter()
        .map(|coefficient_value| {
            let coefficient = integer_value(coefficient_value).ok_or_else(|| {
                ComponentProofBackendError::invalid(format!(
                    "{label} coefficient is not a canonical integer."
                ))
            })?;
            if coefficient >= SHARE_COMMITMENT_MODULUS {
                return Err(ComponentProofBackendError::invalid(format!(
                    "{label} coefficient is outside the share-commitment modulus."
                )));
            }
            Ok(coefficient)
        })
        .collect()
}

pub(crate) fn parse_share_commitment_polynomial_vector(
    value: &Value,
    label: &str,
) -> Result<Vec<Vec<u64>>, ComponentProofBackendError> {
    let polynomials = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if polynomials.len() != SHARE_COMMITMENT_MODULE_RANK {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} must have the frozen share-commitment module rank."
        )));
    }
    polynomials
        .iter()
        .enumerate()
        .map(|(polynomial_index, polynomial)| {
            parse_share_commitment_polynomial(
                polynomial,
                &format!("{label} polynomial {polynomial_index}"),
            )
        })
        .collect()
}
