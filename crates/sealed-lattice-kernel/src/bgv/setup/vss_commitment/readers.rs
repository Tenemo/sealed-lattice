use super::*;

pub(super) fn read_vss_public_message_coefficients(
    value: &Value,
    field_name: &str,
    ring_degree: usize,
    message_coefficient_bound: u64,
) -> CanonicalResult<Vec<u64>> {
    if message_coefficient_bound == 0 {
        return Err(invalid_vss_public_input(
            "messageCoefficientBound must be positive",
        ));
    }
    let coefficients = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an array"),
            )
        })?;
    if coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} length must match ringDegree"),
        ));
    }
    coefficients
        .iter()
        .enumerate()
        .map(|(coefficient_index, coefficient)| {
            let value = coefficient.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}.{coefficient_index} must be a non-negative integer"),
                )
            })?;
            if value >= message_coefficient_bound {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "{field_name}.{coefficient_index} must be below messageCoefficientBound"
                    ),
                ));
            }

            Ok(value)
        })
        .collect()
}

pub(super) fn validate_vss_public_commitment_role(commitment_role: &str) -> CanonicalResult<()> {
    match commitment_role {
        "coefficient"
        | "recipient-share"
        | "aggregate-threshold-share"
        | "target-decryption-flooding-noise" => Ok(()),
        _ => Err(invalid_vss_public_input(
            "VSS commitment role is not supported",
        )),
    }
}
