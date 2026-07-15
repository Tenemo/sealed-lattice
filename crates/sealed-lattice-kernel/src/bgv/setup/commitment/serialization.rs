use super::commitment_parameters::*;
use super::validation::*;
use super::*;

pub(in super::super) fn setup_commitment_root(
    commitment: &SetupCommitmentValue,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&setup_commitment_root_payload(commitment))
}

pub(in super::super) fn setup_commitment_full_value(commitment: &SetupCommitmentValue) -> Value {
    json!({
        "objectType": "SetupCommitment",
        "sourceRnsLimbIndex": commitment.source_rns_limb_index,
        "shamirCoefficientIndex": commitment.shamir_coefficient_index,
        "ringDegree": commitment.ring_degree,
        "commitmentLimbs": commitment.limbs.iter().map(|limb| {
            json!({
                "commitmentModulusIndex": limb.commitment_modulus_index,
                "modulus": limb.modulus,
                "rows": limb.rows,
            })
        }).collect::<Vec<_>>()
    })
}

pub(in super::super) fn parse_setup_commitment_full_value(
    value: &Value,
) -> CanonicalResult<SetupCommitmentValue> {
    if value.get("objectType").and_then(Value::as_str) != Some("SetupCommitment") {
        return Err(invalid_commitment_input(
            "setup commitment objectType must be SetupCommitment",
        ));
    }
    let source_rns_limb_index = read_usize(value, "sourceRnsLimbIndex")?;
    validate_source_rns_limb(source_rns_limb_index)?;
    let shamir_coefficient_index = read_u64(value, "shamirCoefficientIndex")?;
    let ring_degree = read_usize(value, "ringDegree")?;
    validate_ring_degree(ring_degree)?;
    let commitment_limb_values = value
        .get("commitmentLimbs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_commitment_input("setup commitment must include commitmentLimbs"))?;
    if commitment_limb_values.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(invalid_commitment_input(
            "setup commitment must include every selected commitment modulus limb",
        ));
    }

    let mut seen_limb_indices = Vec::new();
    let mut limbs = Vec::with_capacity(commitment_limb_values.len());
    for limb_value in commitment_limb_values {
        let commitment_modulus_index = read_usize(limb_value, "commitmentModulusIndex")?;
        if !SETUP_COMMITMENT_MODULUS_LIMB_INDICES.contains(&commitment_modulus_index) {
            return Err(invalid_commitment_input(
                "setup commitment limb uses a modulus outside the accepted commitment parameters",
            ));
        }
        if seen_limb_indices.contains(&commitment_modulus_index) {
            return Err(invalid_commitment_input(
                "setup commitment limbs must have distinct commitmentModulusIndex values",
            ));
        }
        seen_limb_indices.push(commitment_modulus_index);
        let modulus = read_u64(limb_value, "modulus")?;
        if DATA_PRIMES.get(commitment_modulus_index) != Some(&modulus) {
            return Err(invalid_commitment_input(
                "setup commitment limb modulus does not match the selected commitment modulus",
            ));
        }
        let row_values = limb_value
            .get("rows")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_commitment_input("setup commitment limb must include rows"))?;
        if row_values.len() != SETUP_COMMITMENT_ROW_COUNT {
            return Err(invalid_commitment_input(
                "setup commitment limb must include the selected commitment row count",
            ));
        }
        let rows = row_values
            .iter()
            .map(|row_value| read_residue_row(row_value, ring_degree, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index,
            modulus,
            rows,
        });
    }
    limbs.sort_by_key(|limb| limb.commitment_modulus_index);

    Ok(SetupCommitmentValue {
        source_rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
        limbs,
    })
}

fn setup_commitment_root_payload(commitment: &SetupCommitmentValue) -> Value {
    json!({
        "objectType": "SetupCommitment",
        "sourceRnsLimbIndex": commitment.source_rns_limb_index,
        "shamirCoefficientIndex": commitment.shamir_coefficient_index,
        "ringDegree": commitment.ring_degree,
        "commitmentLimbs": commitment.limbs.iter().map(|limb| {
            json!({
                "commitmentModulusIndex": limb.commitment_modulus_index,
                "modulus": limb.modulus,
                "rowCoefficientHash512": limb.rows.iter().map(|row| {
                    coefficient_vector_hash512(
                        row,
                        "sealed-lattice-bdlop-commitment/row-coefficients",
                    )
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    })
}

pub(super) fn read_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_commitment_input(format!("{field_name} must be a non-negative integer"))
        })
}

pub(super) fn read_usize(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let value = read_u64(value, field_name)?;
    usize::try_from(value)
        .map_err(|_| invalid_commitment_input(format!("{field_name} does not fit usize")))
}

pub(super) fn read_unsigned_message_coefficients(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<u128>> {
    let coefficient_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_commitment_input(format!(
                "{field_name} must be an array of unsigned integers"
            ))
        })?;
    coefficient_values
        .iter()
        .enumerate()
        .map(|(coefficient_index, coefficient_value)| {
            coefficient_value.as_u64().map(u128::from).ok_or_else(|| {
                invalid_commitment_input(format!(
                    "{field_name}[{coefficient_index}] must be a non-negative integer"
                ))
            })
        })
        .collect()
}

pub(super) fn read_randomness_by_column(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<Vec<i128>>> {
    let column_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_commitment_input(format!("{field_name} must be an array of columns"))
        })?;
    column_values
        .iter()
        .enumerate()
        .map(|(column_index, column_value)| {
            let coefficient_values = column_value.as_array().ok_or_else(|| {
                invalid_commitment_input(format!(
                    "{field_name}[{column_index}] must be an array of signed integers"
                ))
            })?;
            coefficient_values
                .iter()
                .enumerate()
                .map(|(coefficient_index, coefficient_value)| {
                    coefficient_value.as_i64().map(i128::from).ok_or_else(|| {
                        invalid_commitment_input(format!(
                            "{field_name}[{column_index}][{coefficient_index}] must be a signed integer"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

fn read_residue_row(value: &Value, ring_degree: usize, modulus: u64) -> CanonicalResult<Vec<u64>> {
    let row = value
        .as_array()
        .ok_or_else(|| invalid_commitment_input("setup commitment row must be an array"))?;
    if row.len() != ring_degree {
        return Err(invalid_commitment_input(
            "setup commitment row length must match the ring degree",
        ));
    }
    row.iter()
        .map(|coefficient| {
            let coefficient = coefficient.as_u64().ok_or_else(|| {
                invalid_commitment_input("setup commitment row coefficients must be integers")
            })?;
            if coefficient >= modulus {
                return Err(invalid_commitment_input(
                    "setup commitment row coefficient is outside the commitment modulus",
                ));
            }
            Ok(coefficient)
        })
        .collect()
}
