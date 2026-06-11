use super::*;

use crate::bgv::setup_helpers::decimal_i128_value;

pub(in crate::bgv::setup) fn evaluation_key_share_lnp_relation_proof_bytes_hash(
    proof_family: EvaluationKeyShareProofFamily,
    proof_bytes: &[u8],
) -> String {
    hash512_hex(proof_family.proof_bytes_hash_domain(), &[proof_bytes])
}

pub(super) fn encode_evaluation_key_share_lnp_tbox_prefix(
    proof_family: EvaluationKeyShareProofFamily,
    layout: &super::setup_proof::SetupProofLnpTboxLayout,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = EvaluationKeyShareLnpBitWriter::new();
    encode_evaluation_key_share_lnp_uniform_polyvec(
        proof_family,
        &mut writer,
        EvaluationKeyShareLnpUniformPolyvecEncoding {
            polynomial_count: layout.t_b_polynomial_count,
            proof_ring_degree: layout.proof_ring_degree,
            bit_count: layout.proof_modulus_bit_count,
            modulus: Some(&layout.proof_modulus),
            proof_randomness_seed_hex,
            field_index: 0,
        },
    )?;
    encode_evaluation_key_share_lnp_uniform_polyvec(
        proof_family,
        &mut writer,
        EvaluationKeyShareLnpUniformPolyvecEncoding {
            polynomial_count: layout.h_polynomial_count,
            proof_ring_degree: layout.proof_ring_degree,
            bit_count: layout.proof_modulus_bit_count,
            modulus: Some(&layout.proof_modulus),
            proof_randomness_seed_hex,
            field_index: 1,
        },
    )?;
    encode_evaluation_key_share_lnp_uniform_polyvec(
        proof_family,
        &mut writer,
        EvaluationKeyShareLnpUniformPolyvecEncoding {
            polynomial_count: layout.t_a1_polynomial_count,
            proof_ring_degree: layout.proof_ring_degree,
            bit_count: layout
                .proof_modulus_bit_count
                .checked_sub(layout.compression_dropped_bits)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof("evaluation-key LNP compression underflowed")
                })?,
            modulus: None,
            proof_randomness_seed_hex,
            field_index: 2,
        },
    )?;

    Ok(writer.into_bytes())
}

struct EvaluationKeyShareLnpUniformPolyvecEncoding<'a> {
    polynomial_count: usize,
    proof_ring_degree: usize,
    bit_count: usize,
    modulus: Option<&'a BigUint>,
    proof_randomness_seed_hex: &'a str,
    field_index: u64,
}

fn encode_evaluation_key_share_lnp_uniform_polyvec(
    proof_family: EvaluationKeyShareProofFamily,
    writer: &mut EvaluationKeyShareLnpBitWriter<'_>,
    input: EvaluationKeyShareLnpUniformPolyvecEncoding<'_>,
) -> CanonicalResult<()> {
    let coefficient_count = input
        .polynomial_count
        .checked_mul(input.proof_ring_degree)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(
                "evaluation-key LNP tbox coefficient count overflowed",
            )
        })?;
    for coefficient_index in 0..coefficient_count {
        if input.field_index == 1
            && super::setup_proof::setup_proof_lnp_tbox_h_coefficient_must_be_zero(
                coefficient_index,
                input.proof_ring_degree,
            )
        {
            let zero_residue_bytes = vec![
                0_u8;
                input.bit_count.checked_add(7).ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key LNP tbox bit count overflowed",
                    )
                })? / 8
            ];
            writer.write_little_endian_bytes_bits(&zero_residue_bytes, input.bit_count)?;
            continue;
        }
        let residue_bytes = super::setup_proof::sample_setup_proof_lnp_tbox_uniform_residue_bytes(
            proof_family.tbox_uniform_domain(),
            input.proof_randomness_seed_hex,
            input.field_index,
            coefficient_index,
            input.bit_count,
            input.modulus,
        )?;
        writer.write_little_endian_bytes_bits(&residue_bytes, input.bit_count)?;
    }

    Ok(())
}

#[allow(
    dead_code,
    reason = "borrowed mode is retained for local LNP bit-writer parity"
)]
enum EvaluationKeyShareLnpBitWriterStorage<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a mut Vec<u8>),
}

struct EvaluationKeyShareLnpBitWriter<'a> {
    storage: EvaluationKeyShareLnpBitWriterStorage<'a>,
    bit_offset: usize,
}

impl<'a> EvaluationKeyShareLnpBitWriter<'a> {
    fn new() -> Self {
        Self {
            storage: EvaluationKeyShareLnpBitWriterStorage::Owned(Vec::new()),
            bit_offset: 0,
        }
    }

    #[allow(
        dead_code,
        reason = "borrowed mode is retained for local LNP bit-writer parity"
    )]
    fn from_bytes(bytes: &'a mut Vec<u8>) -> Self {
        let bit_offset = bytes.len() * 8;
        Self {
            storage: EvaluationKeyShareLnpBitWriterStorage::Borrowed(bytes),
            bit_offset,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        match self.storage {
            EvaluationKeyShareLnpBitWriterStorage::Owned(bytes) => bytes,
            EvaluationKeyShareLnpBitWriterStorage::Borrowed(_) => {
                unreachable!("borrowed evaluation-key LNP bit writer is not consumed by value")
            }
        }
    }

    #[allow(
        dead_code,
        reason = "suffix encoding moved to setup_proof shared writer"
    )]
    fn write_u64_le_bits(&mut self, value: u64, bit_count: usize) -> CanonicalResult<()> {
        for bit_index in 0..bit_count {
            let bit = if bit_index < u64::BITS as usize {
                ((value >> bit_index) & 1) == 1
            } else {
                false
            };
            self.write_bit(bit);
        }

        Ok(())
    }

    fn write_little_endian_bytes_bits(
        &mut self,
        bytes: &[u8],
        bit_count: usize,
    ) -> CanonicalResult<()> {
        if bytes
            .len()
            .checked_mul(8)
            .is_none_or(|available_bits| available_bits < bit_count)
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key LNP byte residue is shorter than its declared bit count",
            ));
        }
        for bit_index in 0..bit_count {
            let byte = bytes[bit_index / 8];
            self.write_bit(((byte >> (bit_index % 8)) & 1) == 1);
        }

        Ok(())
    }

    fn write_bit(&mut self, bit: bool) {
        let bytes = match &mut self.storage {
            EvaluationKeyShareLnpBitWriterStorage::Owned(bytes) => bytes,
            EvaluationKeyShareLnpBitWriterStorage::Borrowed(bytes) => bytes,
        };
        if self.bit_offset / 8 == bytes.len() {
            bytes.push(0);
        }
        if bit {
            bytes[self.bit_offset / 8] |= 1_u8 << (self.bit_offset % 8);
        }
        self.bit_offset += 1;
    }

    #[allow(
        dead_code,
        reason = "suffix encoding moved to setup_proof shared writer"
    )]
    fn finish_with_lazer_padding(&mut self) {
        self.write_bit(true);
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(false);
        }
    }
}

pub(super) fn hash_hex_to_fixed_bytes(hash_hex: &str) -> CanonicalResult<[u8; 64]> {
    if hash_hex.len() != 128 {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key hash must be 64 bytes",
        ));
    }
    let mut output = [0_u8; 64];
    for (byte_index, chunk) in hash_hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        output[byte_index] = (high << 4) | low;
    }

    Ok(output)
}

pub(super) fn validate_hex_string(value: &str, field_name: &str) -> CanonicalResult<()> {
    if value.is_empty()
        || value
            .as_bytes()
            .iter()
            .any(|byte| hex_nibble(*byte).is_err())
    {
        return Err(invalid_evaluation_key_share_proof(format!(
            "{field_name} must be non-empty hexadecimal"
        )));
    }

    Ok(())
}

fn hex_nibble(value: u8) -> CanonicalResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid_evaluation_key_share_proof(
            "evaluation-key hash contains a non-hex character",
        )),
    }
}

pub(super) fn read_i128_matrix3(
    proof_bytes: &[u8],
    cursor: &mut usize,
    outer_count: usize,
    middle_count: usize,
    inner_count: usize,
) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    (0..outer_count)
        .map(|_| read_i128_matrix(proof_bytes, cursor, middle_count, inner_count))
        .collect()
}

pub(super) fn read_i128_matrix(
    proof_bytes: &[u8],
    cursor: &mut usize,
    outer_count: usize,
    inner_count: usize,
) -> CanonicalResult<Vec<Vec<i128>>> {
    (0..outer_count)
        .map(|_| read_i128_vector(proof_bytes, cursor, inner_count))
        .collect()
}

pub(super) fn read_signed_big_int_matrix3(
    proof_bytes: &[u8],
    cursor: &mut usize,
    outer_count: usize,
    middle_count: usize,
    inner_count: usize,
) -> CanonicalResult<Vec<Vec<Vec<BigInt>>>> {
    (0..outer_count)
        .map(|_| read_signed_big_int_matrix(proof_bytes, cursor, middle_count, inner_count))
        .collect()
}

fn read_signed_big_int_matrix(
    proof_bytes: &[u8],
    cursor: &mut usize,
    outer_count: usize,
    inner_count: usize,
) -> CanonicalResult<Vec<Vec<BigInt>>> {
    (0..outer_count)
        .map(|_| read_signed_big_int_vector(proof_bytes, cursor, inner_count))
        .collect()
}

fn read_signed_big_int_vector(
    proof_bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> CanonicalResult<Vec<BigInt>> {
    (0..count)
        .map(|_| {
            read_signed_big_int_le_fixed(
                proof_bytes,
                cursor,
                EVALUATION_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT,
            )
        })
        .collect()
}

fn read_signed_big_int_le_fixed(
    proof_bytes: &[u8],
    cursor: &mut usize,
    byte_count: usize,
) -> CanonicalResult<BigInt> {
    let end = cursor.checked_add(byte_count).ok_or_else(|| {
        invalid_evaluation_key_share_proof(
            "evaluation-key signed big-integer read offset overflowed",
        )
    })?;
    let slice = proof_bytes.get(*cursor..end).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key proof ended before a signed big-integer relation commitment",
        )
    })?;
    *cursor = end;

    Ok(BigInt::from_signed_bytes_le(slice))
}

pub(super) fn read_i128_vector(
    proof_bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> CanonicalResult<Vec<i128>> {
    (0..count)
        .map(|_| {
            let bytes = read_fixed::<16>(proof_bytes, cursor)?;
            Ok(i128::from_le_bytes(bytes))
        })
        .collect()
}

pub(super) fn read_u64(proof_bytes: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    let bytes = read_fixed::<8>(proof_bytes, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn read_fixed<const LENGTH: usize>(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; LENGTH]> {
    let end = cursor.checked_add(LENGTH).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key proof cursor overflowed")
    })?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof ended early"))?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

pub(super) fn read_bytes(
    proof_bytes: &[u8],
    cursor: &mut usize,
    length: usize,
) -> CanonicalResult<Vec<u8>> {
    let end = cursor.checked_add(length).ok_or_else(|| {
        invalid_evaluation_key_share_proof("evaluation-key proof cursor overflowed")
    })?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof ended early"))?;
    *cursor = end;

    Ok(bytes.to_vec())
}

pub(super) fn write_i128_matrix3(output: &mut Vec<u8>, values: &[Vec<Vec<i128>>]) {
    for matrix in values {
        write_i128_matrix(output, matrix);
    }
}

pub(super) fn write_signed_big_int_matrix3(
    output: &mut Vec<u8>,
    values: &[Vec<Vec<BigInt>>],
) -> CanonicalResult<()> {
    for matrix in values {
        for vector in matrix {
            for value in vector {
                write_signed_big_int_le_fixed(
                    output,
                    value,
                    EVALUATION_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT,
                )?;
            }
        }
    }

    Ok(())
}

pub(super) fn write_signed_big_int_le_fixed(
    output: &mut Vec<u8>,
    value: &BigInt,
    byte_count: usize,
) -> CanonicalResult<()> {
    let bit_count = byte_count
        .checked_mul(8)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key signed big-integer width is invalid")
        })?;
    let range_limit = BigInt::from(1_u8) << bit_count;
    if value < &(-&range_limit) || value >= &range_limit {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key relation commitment exceeds the fixed signed big-integer encoding width",
        ));
    }
    let extension_byte = if value.sign() == Sign::Minus {
        0xff
    } else {
        0x00
    };
    let encoded = value.to_signed_bytes_le();
    if encoded.len() > byte_count {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key relation commitment is not canonical for the fixed-width signed encoding",
        ));
    }
    let mut fixed = vec![extension_byte; byte_count];
    fixed[..encoded.len()].copy_from_slice(&encoded);
    output.extend_from_slice(&fixed);

    Ok(())
}

pub(super) fn write_i128_matrix(output: &mut Vec<u8>, values: &[Vec<i128>]) {
    for vector in values {
        write_i128_vector(output, vector);
    }
}

pub(super) fn write_setup_commitments(output: &mut Vec<u8>, commitments: &[SetupCommitmentValue]) {
    for commitment in commitments {
        for limb in &commitment.limbs {
            for row in &limb.rows {
                for coefficient in row {
                    output.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) fn write_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn value_usize(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let unsigned = value_u64(value, field_name)?;
    usize::try_from(unsigned)
        .map_err(|_| invalid_evaluation_key_share_proof(format!("{field_name} does not fit usize")))
}

pub(super) fn value_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(format!("{field_name} must be an unsigned integer"))
        })
}

pub(super) fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(format!("{field_name} must be a non-empty string"))
        })
}

pub(super) fn object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof(format!("{field_name} must be an object"))
        })
}

pub(super) fn array_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{field_name} must be an array")))
}

pub(super) fn setup_commitment_values_field(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<SetupCommitmentValue>> {
    array_field(value, field_name)?
        .iter()
        .map(parse_setup_commitment_full_value)
        .collect()
}

pub(super) fn i64_vector_field(value: &Value, field_name: &str) -> CanonicalResult<Vec<i64>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(item_index, item)| {
            decimal_i128_value(item)
                .and_then(|item| i64::try_from(item).ok())
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(format!(
                        "{field_name}.{item_index} must be a signed 64-bit integer"
                    ))
                })
        })
        .collect()
}

pub(super) fn i64_matrix_field(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<i64>>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(row_index, row)| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(format!(
                        "{field_name}.{row_index} must be an array"
                    ))
                })?
                .iter()
                .enumerate()
                .map(|(column_index, item)| {
                    decimal_i128_value(item)
                        .and_then(|item| i64::try_from(item).ok())
                        .ok_or_else(|| {
                            invalid_evaluation_key_share_proof(format!(
                                "{field_name}.{row_index}.{column_index} must be a signed 64-bit integer"
                            ))
                        })
                })
                .collect()
        })
        .collect()
}

pub(super) fn i128_matrix_field(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<Vec<i128>>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(row_index, row)| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(format!(
                        "{field_name}.{row_index} must be an array"
                    ))
                })?
                .iter()
                .enumerate()
                .map(|(column_index, item)| {
                    decimal_i128_value(item).ok_or_else(|| {
                        invalid_evaluation_key_share_proof(format!(
                            "{field_name}.{row_index}.{column_index} must be a signed integer or decimal string"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

pub(super) fn i128_matrix3_field(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    array_field(value, field_name)?
        .iter()
        .enumerate()
        .map(|(outer_index, middle_value)| {
            middle_value
                .as_array()
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(format!(
                        "{field_name}.{outer_index} must be an array"
                    ))
                })?
                .iter()
                .enumerate()
                .map(|(middle_index, inner_value)| {
                    inner_value
                        .as_array()
                        .ok_or_else(|| {
                            invalid_evaluation_key_share_proof(format!(
                                "{field_name}.{outer_index}.{middle_index} must be an array"
                            ))
                        })?
                        .iter()
                        .enumerate()
                        .map(|(inner_index, item)| {
                            decimal_i128_value(item).ok_or_else(|| {
                                invalid_evaluation_key_share_proof(format!(
                                    "{field_name}.{outer_index}.{middle_index}.{inner_index} must be a signed integer or decimal string"
                                ))
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

pub(super) fn evaluation_key_share_proof_family_from_request(
    value: &Value,
) -> CanonicalResult<EvaluationKeyShareProofFamily> {
    match string_field(value, "proofFamily")? {
        "relinearization-key-share" => Ok(EvaluationKeyShareProofFamily::Relinearization),
        "galois-key-share" => Ok(EvaluationKeyShareProofFamily::Galois),
        _ => Err(invalid_evaluation_key_share_proof(
            "proofFamily must be relinearization-key-share or galois-key-share",
        )),
    }
}

pub(super) fn proof_randomness_source(value: &Value) -> CanonicalResult<&'static str> {
    match value
        .get("proofRandomnessSource")
        .and_then(Value::as_str)
        .unwrap_or("fresh-csprng")
    {
        "fresh-csprng" => Ok("fresh-csprng"),
        "development-deterministic-fixture" => Ok("development-deterministic-fixture"),
        _ => Err(invalid_evaluation_key_share_proof(
            "proofRandomnessSource must be fresh-csprng or development-deterministic-fixture",
        )),
    }
}

pub(super) fn validate_lowercase_hash(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_evaluation_key_share_proof(format!(
        "{field_name} must be lowercase 512-bit hex"
    )))
}

pub(super) fn validate_proof_randomness_seed(
    seed_hex: &str,
    field_name: &str,
) -> CanonicalResult<()> {
    validate_lowercase_hash(seed_hex, field_name)
}
