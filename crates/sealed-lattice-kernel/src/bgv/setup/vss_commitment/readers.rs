use super::message_encoding::*;
use super::sampler::*;
use super::*;

pub(crate) fn read_vss_public_randomness_by_column(
    value: &Value,
    field_name: &str,
    ring_degree: usize,
    active_limb_modulus: Option<u64>,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let columns = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an array"),
            )
        })?;
    if columns.len() != VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} must carry the randomness column count"),
        ));
    }
    let randomness_by_column = columns
        .iter()
        .enumerate()
        .map(|(column_index, column)| {
            let coefficients = column.as_array().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}.{column_index} must be an array"),
                )
            })?;
            if coefficients.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name}.{column_index} has the wrong coefficient count"),
                ));
            }
            coefficients
                .iter()
                .enumerate()
                .map(|(coefficient_index, coefficient)| {
                    let value = coefficient.as_i64().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "{field_name}.{column_index}.{coefficient_index} must be a signed integer"
                            ),
                        )
                    })?;
                    if active_limb_modulus.is_some_and(|modulus| value.unsigned_abs() >= modulus) {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "VSS opening randomness coefficient exceeds the active limb modulus",
                        ));
                    }

                    Ok(value)
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    validate_vss_public_randomness_columns(
        &randomness_by_column,
        ring_degree,
        active_limb_modulus,
        field_name,
    )?;

    Ok(randomness_by_column)
}

pub(super) fn compute_vss_public_commitment_from_opening_value(
    opening: &Value,
) -> CanonicalResult<VssPublicCommitmentComputation> {
    let commitment_role = string_at_path(opening, &["commitmentRole"])?;
    let commitment_context = value_at_path(opening, &["commitmentContext"])?;
    let public_matrix_seed_hash = hash_at_path(opening, &["publicMatrixSeedHash"])?;
    let rns_limb_index = usize_at_path(opening, &["rnsLimbIndex"])?;
    let rns_prime = unsigned_at_path(opening, &["rnsPrime"])?;
    let ring_degree = usize_at_path(opening, &["ringDegree"])?;
    let message_coefficient_bound =
        read_optional_u64(opening, "messageCoefficientBound")?.unwrap_or(rns_prime);
    let message_coefficients = read_vss_public_message_coefficients(
        opening,
        "messageCoefficients",
        ring_degree,
        message_coefficient_bound,
    )?;
    let message_digit_columns =
        read_vss_public_message_digit_columns(opening, "messageDigitColumns", ring_degree)?;
    let randomness_by_column =
        read_vss_public_randomness_by_column(opening, "randomnessByColumn", ring_degree, None)?;

    compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
        commitment_role,
        commitment_context,
        public_matrix_seed_hash,
        rns_limb_index,
        rns_prime,
        ring_degree,
        message_coefficients: &message_coefficients,
        message_digit_columns: &message_digit_columns,
        message_coefficient_bound,
        randomness_by_column: &randomness_by_column,
    })
}

pub(super) fn vss_public_commitment_computation_response(
    computation: &VssPublicCommitmentComputation,
) -> Value {
    json!({
        "ok": true,
        "operation": "computeVssPublicCommitmentFromOpening",
        "commitment": computation.commitment,
        "commitmentRoot": computation.commitment_root,
        "openingRoot": computation.opening_root,
        "commitmentContextHash": computation.commitment_context_hash,
        "encodedCommitmentByteLength": vss_public_encoded_commitment_byte_length(),
    })
}

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

pub(super) fn read_vss_public_message_digit_columns(
    value: &Value,
    field_name: &str,
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let columns_value = value.get(field_name).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be an array"),
        )
    })?;
    let columns = columns_value.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be an array"),
        )
    })?;
    if columns.len() != VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} must contain the selected message digit count"),
        ));
    }

    columns
        .iter()
        .enumerate()
        .map(|(digit_index, column)| {
            let values = column.as_array().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}.{digit_index} must be an array"),
                )
            })?;
            if values.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name}.{digit_index} length must match ringDegree"),
                ));
            }

            values
                .iter()
                .enumerate()
                .map(|(coefficient_index, value)| {
                    value.as_u64().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "{field_name}.{digit_index}.{coefficient_index} must be a non-negative integer"
                            ),
                        )
                    })
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<_>>>()
}

pub(super) fn vss_public_message_digit_columns_for_opening(
    message_coefficients: &[u64],
    message_digit_columns: &[Vec<u64>],
    message_coefficient_bound: u64,
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if message_digit_columns.len() != VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS messageDigitColumns must contain the selected message digit count",
        ));
    }
    for (digit_index, column) in message_digit_columns.iter().enumerate() {
        if column.len() != ring_degree {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("VSS messageDigitColumns.{digit_index} length must match ringDegree"),
            ));
        }
    }
    let columns = message_digit_columns.to_vec();

    let digit_weights = (0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT)
        .map(|digit_index| {
            u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE)
                .checked_pow(digit_index as u32)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS message digit weight overflowed",
                    )
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    for (coefficient_index, expected_coefficient) in message_coefficients.iter().enumerate() {
        let mut decoded = 0_u128;
        for (digit_index, column) in columns.iter().enumerate() {
            decoded = decoded
                .checked_add(u128::from(column[coefficient_index]) * digit_weights[digit_index])
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS message digit column decoding overflowed",
                    )
                })?;
        }
        if decoded != u128::from(*expected_coefficient)
            || decoded >= u128::from(message_coefficient_bound)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "VSS message digit columns do not decode to messageCoefficients.{coefficient_index}"
                ),
            ));
        }
    }

    Ok(columns)
}

pub(super) fn validate_vss_public_commitment_role(commitment_role: &str) -> CanonicalResult<()> {
    match commitment_role {
        "coefficient"
        | "recipient-share"
        | "aggregate-threshold-share"
        | "target-decryption-smudging-polynomial-coefficient" => Ok(()),
        _ => Err(invalid_vss_public_input(
            "VSS commitment role is not supported",
        )),
    }
}

pub(super) fn validate_vss_public_randomness_columns(
    randomness_by_column: &[Vec<i64>],
    ring_degree: usize,
    active_limb_modulus: Option<u64>,
    field_name: &str,
) -> CanonicalResult<()> {
    if randomness_by_column.len() != VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} must contain the randomness column count"),
        ));
    }
    for (column_index, column) in randomness_by_column.iter().enumerate() {
        if column.len() != ring_degree {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name}.{column_index} length must match ringDegree"),
            ));
        }
        if let Some(modulus) = active_limb_modulus {
            for coefficient in column {
                if coefficient.unsigned_abs() >= modulus {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "VSS opening randomness coefficient exceeds the active limb modulus",
                    ));
                }
            }
        }
    }

    Ok(())
}

pub(super) struct CommitmentCoordinateInput<'a> {
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) commitment_modulus_index: usize,
    pub(super) output_coordinate_index: usize,
    pub(super) modulus: u64,
    pub(super) message_digit_columns: &'a [Vec<u64>],
    pub(super) randomness_by_column: &'a [Vec<i64>],
}

pub(super) fn commitment_coordinate(input: CommitmentCoordinateInput<'_>) -> CanonicalResult<u64> {
    let mut accumulator = 0_u128;
    let ring_degree = input.message_digit_columns[0].len();
    for digit_index in 0..VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
        let input_column = vss_public_message_digit_column_label_str(digit_index)?;
        let projection_terms = cached_projection_terms(ProjectionTermsInput {
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column,
            ring_degree,
            modulus: input.modulus,
        })?;
        for &(ring_coefficient_index, matrix_residue) in projection_terms.iter() {
            accumulator = add_product_mod(
                accumulator,
                input.message_digit_columns[digit_index][ring_coefficient_index] % input.modulus,
                matrix_residue,
                input.modulus,
            );
        }
    }
    for (randomness_column_index, randomness_column) in
        input.randomness_by_column.iter().enumerate()
    {
        let input_column = vss_public_randomness_column_label(randomness_column_index)?;
        let projection_terms = cached_projection_terms(ProjectionTermsInput {
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            commitment_modulus_index: input.commitment_modulus_index,
            output_coordinate_index: input.output_coordinate_index,
            input_column,
            ring_degree: randomness_column.len(),
            modulus: input.modulus,
        })?;
        for &(ring_coefficient_index, matrix_residue) in projection_terms.iter() {
            accumulator = add_product_mod(
                accumulator,
                signed_integer_to_residue(randomness_column[ring_coefficient_index], input.modulus),
                matrix_residue,
                input.modulus,
            );
        }
    }

    Ok(accumulator as u64)
}
