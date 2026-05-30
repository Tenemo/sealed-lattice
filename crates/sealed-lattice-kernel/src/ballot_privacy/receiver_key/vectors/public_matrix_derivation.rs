use serde_json::{Map, Value, json};

#[cfg(test)]
use super::backend_helpers::derive_bytes;
use super::backend_helpers::string_property;
use super::{
    RECEIVER_ENCRYPTION_MODULE_DEGREE, RECEIVER_ENCRYPTION_MODULE_RANK, RECEIVER_ENCRYPTION_MODULUS,
};
use crate::hashing::{derive_protocol_hash, hash512};

const RECEIVER_PUBLIC_MATRIX_EXPANSION_DOMAIN: &str =
    "sealed.vote/internal/receiver-encryption/public-matrix-v1";

// The target vector stores -b, so negating each coefficient (q - t) mod q recovers the actual
// public key b that keyMaterialHash commits to; the recomputed hash must then match.
pub(super) fn validate_key_material_hash_from_target(
    linear_statement: &Map<String, Value>,
    target_vector: &[Vec<u64>],
) -> Result<(), String> {
    let public_key_vector = Value::Array(
        target_vector
            .iter()
            .map(|polynomial| {
                Value::Array(
                    polynomial
                        .iter()
                        .map(|coefficient| {
                            Value::from(
                                (RECEIVER_ENCRYPTION_MODULUS - coefficient)
                                    % RECEIVER_ENCRYPTION_MODULUS,
                            )
                        })
                        .collect(),
                )
            })
            .collect(),
    );
    let expected_key_material_hash = derive_protocol_hash(
        "PublicKeyHash",
        &json!({
            "publicKeyVector": public_key_vector,
            "publicMatrixSeedHash": string_property(linear_statement, "publicMatrixSeedHash")?,
            "receiverEncryptionProfileHash": string_property(linear_statement, "receiverEncryptionProfileHash")?,
        }),
    )
    .map_err(|error| {
        format!("receiver-key linear key material hash could not be recomputed: {error}")
    })?;
    if string_property(linear_statement, "keyMaterialHash")? != expected_key_material_hash {
        return Err(
            "receiver-key linear target vector is not bound to the key material hash".to_string(),
        );
    }

    Ok(())
}

pub(super) fn identity_polynomial(has_unit_coefficient: bool) -> Vec<u64> {
    let mut polynomial = vec![0; RECEIVER_ENCRYPTION_MODULE_DEGREE as usize];
    if has_unit_coefficient {
        polynomial[0] = 1;
    }

    polynomial
}

pub(super) fn derive_receiver_public_matrix(
    receiver_encryption_profile_hash: &str,
    public_matrix_seed_hash: &str,
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    let receiver_encryption_profile_hash_json =
        serde_json::to_string(receiver_encryption_profile_hash)
            .map_err(|error| format!("receiver-key profile hash could not be encoded: {error}"))?;
    let public_matrix_seed_hash_json = serde_json::to_string(public_matrix_seed_hash)
        .map_err(|error| format!("receiver-key matrix seed hash could not be encoded: {error}"))?;
    let mut public_matrix = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_RANK as usize);
    for row_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK {
        let mut matrix_row = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_RANK as usize);
        for column_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK {
            matrix_row.push(derive_receiver_public_matrix_polynomial(
                row_index,
                column_index,
                &receiver_encryption_profile_hash_json,
                &public_matrix_seed_hash_json,
            )?);
        }
        public_matrix.push(matrix_row);
    }

    Ok(public_matrix)
}

fn derive_receiver_public_matrix_polynomial(
    row_index: u64,
    column_index: u64,
    receiver_encryption_profile_hash_json: &str,
    public_matrix_seed_hash_json: &str,
) -> Result<Vec<u64>, String> {
    let mut polynomial = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_DEGREE as usize);
    for coefficient_index in 0..RECEIVER_ENCRYPTION_MODULE_DEGREE {
        polynomial.push(derive_receiver_public_matrix_number(
            row_index,
            column_index,
            coefficient_index,
            receiver_encryption_profile_hash_json,
            public_matrix_seed_hash_json,
        )?);
    }

    Ok(polynomial)
}

fn derive_receiver_public_matrix_number(
    row_index: u64,
    column_index: u64,
    coefficient_index: u64,
    receiver_encryption_profile_hash_json: &str,
    public_matrix_seed_hash_json: &str,
) -> Result<u64, String> {
    let unsigned_word_modulus = 1u128 << 64;
    let rejection_limit =
        unsigned_word_modulus - (unsigned_word_modulus % u128::from(RECEIVER_ENCRYPTION_MODULUS));
    let mut block_counter = 0_u64;

    loop {
        let canonical_payload = receiver_public_matrix_coefficient_payload(
            block_counter,
            coefficient_index,
            row_index,
            column_index,
            receiver_encryption_profile_hash_json,
            public_matrix_seed_hash_json,
        );
        let block = hash512(
            RECEIVER_PUBLIC_MATRIX_EXPANSION_DOMAIN,
            &[canonical_payload.as_bytes()],
        );
        for chunk in block.chunks_exact(8) {
            let candidate = u64::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| "receiver-key uniform chunk has invalid length".to_string())?,
            );
            if u128::from(candidate) < rejection_limit {
                return Ok(
                    (u128::from(candidate) % u128::from(RECEIVER_ENCRYPTION_MODULUS)) as u64,
                );
            }
        }
        block_counter = block_counter
            .checked_add(1)
            .ok_or_else(|| "receiver-key uniform derivation counter overflowed".to_string())?;
    }
}

// Hot-path hand-serialization that MUST byte-match canonical_json of the equivalent nested object
// (guarded by two tests below). Any field-order or whitespace drift would fork the derived public
// matrix from every other implementation.
fn receiver_public_matrix_coefficient_payload(
    block_counter: u64,
    coefficient_index: u64,
    row_index: u64,
    column_index: u64,
    receiver_encryption_profile_hash_json: &str,
    public_matrix_seed_hash_json: &str,
) -> String {
    format!(
        "{{\"blockCounter\":0,\"payload\":{{\"blockCounter\":{block_counter},\"payload\":{{\"coefficientIndex\":{coefficient_index},\"payload\":{{\"columnIndex\":{column_index},\"publicMatrixSeedHash\":{public_matrix_seed_hash_json},\"receiverEncryptionProfileHash\":{receiver_encryption_profile_hash_json},\"rowIndex\":{row_index}}}}}}}}}"
    )
}

pub(crate) fn derive_receiver_encryption_public_matrix(
    receiver_encryption_profile_hash: &str,
    public_matrix_seed_hash: &str,
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    derive_receiver_public_matrix(receiver_encryption_profile_hash, public_matrix_seed_hash)
}

#[cfg(test)]
pub(super) fn derive_uniform_number(
    domain: &str,
    payload: &Value,
    modulus: u64,
) -> Result<u64, String> {
    if modulus == 0 {
        return Err("receiver-key uniform derivation modulus must be nonzero".to_string());
    }
    let unsigned_word_modulus = 1u128 << 64;
    let rejection_limit = unsigned_word_modulus - (unsigned_word_modulus % u128::from(modulus));
    let mut block_counter = 0u64;

    loop {
        let block = derive_bytes(
            domain,
            &json!({
                "blockCounter": block_counter,
                "payload": payload,
            }),
            64,
        )?;
        for chunk in block.chunks_exact(8) {
            let candidate = u64::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| "receiver-key uniform chunk has invalid length".to_string())?,
            );
            if u128::from(candidate) < rejection_limit {
                return Ok((u128::from(candidate) % u128::from(modulus)) as u64);
            }
        }
        block_counter = block_counter
            .checked_add(1)
            .ok_or_else(|| "receiver-key uniform derivation counter overflowed".to_string())?;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::hashing::canonical_json;

    #[test]
    fn specialized_public_matrix_payload_matches_canonical_json() {
        let receiver_encryption_profile_hash = "profile-hash";
        let public_matrix_seed_hash = "seed-hash";
        let receiver_encryption_profile_hash_json =
            serde_json::to_string(receiver_encryption_profile_hash).expect("profile json");
        let public_matrix_seed_hash_json =
            serde_json::to_string(public_matrix_seed_hash).expect("seed json");
        let expected = canonical_json(&json!({
            "blockCounter": 0_u64,
            "payload": {
                "blockCounter": 3_u64,
                "payload": {
                    "coefficientIndex": 11_u64,
                    "payload": {
                        "columnIndex": 5_u64,
                        "publicMatrixSeedHash": public_matrix_seed_hash,
                        "receiverEncryptionProfileHash": receiver_encryption_profile_hash,
                        "rowIndex": 7_u64,
                    },
                },
            },
        }))
        .expect("canonical json");
        let specialized = receiver_public_matrix_coefficient_payload(
            3,
            11,
            7,
            5,
            &receiver_encryption_profile_hash_json,
            &public_matrix_seed_hash_json,
        );

        assert_eq!(specialized, expected);
    }

    #[test]
    fn specialized_public_matrix_number_matches_generic_derivation() {
        let receiver_encryption_profile_hash = "profile-hash";
        let public_matrix_seed_hash = "seed-hash";
        let receiver_encryption_profile_hash_json =
            serde_json::to_string(receiver_encryption_profile_hash).expect("profile json");
        let public_matrix_seed_hash_json =
            serde_json::to_string(public_matrix_seed_hash).expect("seed json");
        let expected = derive_uniform_number(
            RECEIVER_PUBLIC_MATRIX_EXPANSION_DOMAIN,
            &json!({
                "coefficientIndex": 11_u32,
                "payload": {
                    "columnIndex": 5_u32,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "receiverEncryptionProfileHash": receiver_encryption_profile_hash,
                    "rowIndex": 7_u32,
                },
            }),
            RECEIVER_ENCRYPTION_MODULUS,
        )
        .expect("generic public matrix coefficient");
        let specialized = derive_receiver_public_matrix_number(
            7,
            5,
            11,
            &receiver_encryption_profile_hash_json,
            &public_matrix_seed_hash_json,
        )
        .expect("specialized public matrix coefficient");

        assert_eq!(specialized, expected);
    }
}
