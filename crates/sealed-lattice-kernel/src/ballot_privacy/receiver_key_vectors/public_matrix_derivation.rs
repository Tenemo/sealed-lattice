use serde_json::{Map, Value, json};

use super::backend_helpers::{derive_bytes, string_property};
use super::{
    RECEIVER_ENCRYPTION_MODULE_DEGREE, RECEIVER_ENCRYPTION_MODULE_RANK, RECEIVER_ENCRYPTION_MODULUS,
};
use crate::hashing::derive_protocol_digest;

const RECEIVER_PUBLIC_MATRIX_EXPANSION_DOMAIN: &str =
    "sealed.vote/internal/receiver-encryption/public-matrix-v1";

pub(super) fn validate_key_material_digest_from_target(
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
    let expected_key_material_digest = derive_protocol_digest(
        "PublicKeyDigest",
        &json!({
            "publicKeyVector": public_key_vector,
            "publicMatrixSeedDigest": string_property(linear_statement, "publicMatrixSeedDigest")?,
            "receiverEncryptionProfileDigest": string_property(linear_statement, "receiverEncryptionProfileDigest")?,
        }),
    )
    .map_err(|error| {
        format!("receiver-key linear key material digest could not be recomputed: {error}")
    })?;
    if string_property(linear_statement, "keyMaterialDigest")? != expected_key_material_digest {
        return Err(
            "receiver-key linear target vector is not bound to the key material digest".to_string(),
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
    receiver_encryption_profile_digest: &str,
    public_matrix_seed_digest: &str,
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    let mut public_matrix = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_RANK as usize);
    for row_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK {
        let mut matrix_row = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_RANK as usize);
        for column_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK {
            matrix_row.push(derive_number_polynomial(
                RECEIVER_PUBLIC_MATRIX_EXPANSION_DOMAIN,
                &json!({
                    "columnIndex": column_index,
                    "publicMatrixSeedDigest": public_matrix_seed_digest,
                    "receiverEncryptionProfileDigest": receiver_encryption_profile_digest,
                    "rowIndex": row_index,
                }),
            )?);
        }
        public_matrix.push(matrix_row);
    }

    Ok(public_matrix)
}

pub(crate) fn derive_receiver_encryption_public_matrix(
    receiver_encryption_profile_digest: &str,
    public_matrix_seed_digest: &str,
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    derive_receiver_public_matrix(
        receiver_encryption_profile_digest,
        public_matrix_seed_digest,
    )
}

pub(super) fn derive_number_polynomial(domain: &str, payload: &Value) -> Result<Vec<u64>, String> {
    let mut polynomial = Vec::with_capacity(RECEIVER_ENCRYPTION_MODULE_DEGREE as usize);
    for coefficient_index in 0..RECEIVER_ENCRYPTION_MODULE_DEGREE {
        polynomial.push(derive_uniform_number(
            domain,
            &json!({
                "coefficientIndex": coefficient_index,
                "payload": payload,
            }),
            RECEIVER_ENCRYPTION_MODULUS,
        )?);
    }

    Ok(polynomial)
}

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
