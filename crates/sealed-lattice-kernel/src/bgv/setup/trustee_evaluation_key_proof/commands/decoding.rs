use super::*;

// Canonical binary key-switch component vector material: the same format the
// chunked component-material transport carries.
const COMPONENT_MATERIAL_MAGIC: &[u8; 8] = b"SLEKCMV2";

pub(super) fn decode_component_material_bytes(
    material_bytes: &[u8],
    expected_level: usize,
    expected_digit_count: usize,
    expected_ring_degree: usize,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let read_word = |cursor: &mut usize| -> CanonicalResult<u64> {
        let end = cursor
            .checked_add(8)
            .ok_or_else(|| invalid_succinct_setup_proof("component material cursor overflowed"))?;
        let slice = material_bytes
            .get(*cursor..end)
            .ok_or_else(|| invalid_succinct_setup_proof("component material ended unexpectedly"))?;
        *cursor = end;
        let mut word = [0_u8; 8];
        word.copy_from_slice(slice);
        Ok(u64::from_le_bytes(word))
    };
    let magic = material_bytes
        .get(..8)
        .ok_or_else(|| invalid_succinct_setup_proof("component material ended unexpectedly"))?;
    if magic != COMPONENT_MATERIAL_MAGIC {
        return Err(invalid_succinct_setup_proof(
            "component material has the wrong format marker",
        ));
    }
    let mut cursor = 8_usize;
    let limb_count = expected_level
        .checked_add(1)
        .ok_or_else(|| invalid_succinct_setup_proof("component material limb count overflowed"))?;
    let digit_count = expected_digit_count;
    let ring_degree = expected_ring_degree;
    if digit_count != limb_count || limb_count > DATA_PRIMES.len() || ring_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "component material shape does not match the key descriptor level",
        ));
    }
    let mut component_b_by_digit = Vec::with_capacity(digit_count);
    for _ in 0..digit_count {
        let mut by_limb = Vec::with_capacity(limb_count);
        for &limb_prime in DATA_PRIMES.iter().take(limb_count) {
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                let coefficient = read_word(&mut cursor)?;
                if coefficient >= limb_prime {
                    return Err(invalid_succinct_setup_proof(
                        "component material contains noncanonical Q_share residues",
                    ));
                }
                coefficients.push(coefficient);
            }
            by_limb.push(coefficients);
        }
        component_b_by_digit.push(by_limb);
    }
    if cursor != material_bytes.len() {
        return Err(invalid_succinct_setup_proof(
            "component material has trailing bytes",
        ));
    }

    Ok(component_b_by_digit)
}

pub(super) fn read_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be a string")))
}

pub(super) fn read_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!("{field_name} must be a non-negative integer"))
        })
}

#[cfg(test)]
pub(super) fn read_u64_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<u64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|entry| {
            entry.as_u64().ok_or_else(|| {
                invalid_succinct_setup_proof(format!(
                    "{field_name} entries must be non-negative integers"
                ))
            })
        })
        .collect()
}

pub(super) fn read_hex_bytes(value: &Value, field_name: &str) -> CanonicalResult<Vec<u8>> {
    let text = read_string(value, field_name)?;
    decode_hex_bytes(text, field_name)
}

pub(super) fn decode_exact_hex_bytes(
    text: &str,
    expected_byte_length: usize,
    field_name: &str,
) -> CanonicalResult<Vec<u8>> {
    let bytes = decode_hex_bytes(text, field_name)?;
    if bytes.len() != expected_byte_length {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must be {expected_byte_length} bytes of lowercase hex"
        )));
    }

    Ok(bytes)
}

pub(super) fn decode_hex_bytes(text: &str, field_name: &str) -> CanonicalResult<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must contain whole bytes"
        )));
    }
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must be lowercase hex"
        )));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| {
                invalid_succinct_setup_proof(format!("{field_name} must be lowercase hex"))
            })
        })
        .collect()
}

pub(super) fn read_i64_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<i64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|entry| {
            entry.as_i64().ok_or_else(|| {
                invalid_succinct_setup_proof(format!(
                    "{field_name} entries must be signed integers"
                ))
            })
        })
        .collect()
}

pub(super) fn read_string_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<String>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|entry| {
            entry.as_str().map(str::to_string).ok_or_else(|| {
                invalid_succinct_setup_proof(format!("{field_name} entries must be strings"))
            })
        })
        .collect()
}

pub(super) fn read_i64_matrix2(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<i64>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|row| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!("{field_name} rows must be arrays"))
                })?
                .iter()
                .map(|entry| {
                    entry.as_i64().ok_or_else(|| {
                        invalid_succinct_setup_proof(format!(
                            "{field_name} coefficients must be signed integers"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

pub(super) fn read_i64_matrix(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<Vec<Vec<i64>>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|outer| {
            outer
                .as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!(
                        "{field_name} entries must be arrays of arrays"
                    ))
                })?
                .iter()
                .map(|inner| {
                    inner
                        .as_array()
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(format!(
                                "{field_name} inner entries must be arrays"
                            ))
                        })?
                        .iter()
                        .map(|entry| {
                            entry.as_i64().ok_or_else(|| {
                                invalid_succinct_setup_proof(format!(
                                    "{field_name} coefficients must be signed integers"
                                ))
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

pub(super) fn read_u64_matrix(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<u64>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|row| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!("{field_name} rows must be arrays"))
                })?
                .iter()
                .map(|entry| {
                    entry.as_u64().ok_or_else(|| {
                        invalid_succinct_setup_proof(format!(
                            "{field_name} coefficients must be non-negative integers"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

pub(super) fn read_u64_matrix3(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|digit| {
            digit
                .as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!(
                        "{field_name} digits must be arrays of limbs"
                    ))
                })?
                .iter()
                .map(|limb| {
                    limb.as_array()
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(format!(
                                "{field_name} limbs must be coefficient arrays"
                            ))
                        })?
                        .iter()
                        .map(|entry| {
                            entry.as_u64().ok_or_else(|| {
                                invalid_succinct_setup_proof(format!(
                                    "{field_name} coefficients must be non-negative integers"
                                ))
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}
