use super::validation::{read_u64_object_field, reject_forbidden_public_bridge_fields};
use super::*;
use crate::ballot_privacy::ComponentProofBackendError;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

pub(super) struct BridgePlaintextCoefficientBinding {
    pub(super) commitment: Value,
    pub(super) commitment_hash: String,
    pub(super) opening_witness: Vec<BigInt>,
}

struct PlaintextBindingParameters {
    ring: PolynomialRing,
    message_matrix: Vec<Vec<u64>>,
    randomness_matrix: Vec<Vec<Vec<u64>>>,
}

pub(super) fn plaintext_binding_opening_scalar_count() -> CanonicalResult<usize> {
    plaintext_binding_chunk_count()?
        .checked_mul(SHARE_COMMITMENT_OPENING_DIMENSION)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge plaintext binding opening scalar count overflowed",
            )
        })
}

pub(super) fn generate_plaintext_coefficient_binding(
    plaintext_coefficients: &[u64],
    bridge_proof_profile_hash: &str,
    plaintext_root: &str,
    ciphertext_root: &str,
    prover_randomness_hex: &str,
) -> CanonicalResult<BridgePlaintextCoefficientBinding> {
    let opening_witness = sample_plaintext_binding_opening_witness(
        bridge_proof_profile_hash,
        plaintext_root,
        ciphertext_root,
        prover_randomness_hex,
    )?;
    let commitment_chunks =
        plaintext_binding_commitment_chunks(plaintext_coefficients, &opening_witness)?;
    let commitment_profile_hash = plaintext_binding_profile_hash()?;
    let commitment = json!({
        "objectType": "AggregateBridgePlaintextCoefficientCommitment",
        "objectVersion": 1,
        "scheme": PLAINTEXT_COEFFICIENT_BINDING_SCHEME,
        "bindingStatus": PROOF_FRIENDLY_PLAINTEXT_BINDING_STATUS,
        "commitmentProfileHash": commitment_profile_hash,
        "commitmentFormula": "A_message * plaintextCoefficientChunk + A_randomness * opening mod commitmentModulus",
        "plaintextCoefficientCount": POLYNOMIAL_DEGREE,
        "chunkCount": plaintext_binding_chunk_count()?,
        "chunkDegree": SHARE_COMMITMENT_MODULE_DEGREE,
        "moduleRank": SHARE_COMMITMENT_MODULE_RANK,
        "openingCoordinateCountPerChunk": SHARE_COMMITMENT_OPENING_DIMENSION,
        "openingInfinityNormBound": PLAINTEXT_BINDING_OPENING_INFINITY_NORM_BOUND,
        "commitmentModulus": SHARE_COMMITMENT_MODULUS.to_string(),
        "commitmentChunks": commitment_chunks_value(&commitment_chunks),
        "sameHiddenPlaintextCoefficientVectorRequired": true,
        "currentUse": "internal proof binding only; not result acceptance evidence",
    });
    let commitment_hash = plaintext_coefficient_binding_commitment_hash(&commitment)?;

    Ok(BridgePlaintextCoefficientBinding {
        commitment,
        commitment_hash,
        opening_witness,
    })
}

pub(super) fn plaintext_coefficient_binding_commitment_hash(
    commitment: &Value,
) -> CanonicalResult<String> {
    validate_plaintext_coefficient_binding_commitment_shell(commitment)?;
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-plaintext-coefficient-commitment-v1",
            "plaintextCoefficientCommitment": commitment,
        }),
    )
}

pub(super) fn plaintext_binding_relation_commitment_hash_from_responses(
    bridge_encryption: &Value,
    challenge_scalar: u128,
    plaintext_coefficient_response: &[BigInt],
    plaintext_binding_opening_response: &[BigInt],
) -> CanonicalResult<String> {
    if plaintext_coefficient_response.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding response has an invalid plaintext coefficient count",
        ));
    }
    let expected_opening_count = plaintext_binding_opening_scalar_count()?;
    if plaintext_binding_opening_response.len() != expected_opening_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding response has an invalid opening count",
        ));
    }
    let commitment = required_json_field(
        bridge_encryption,
        "plaintextCoefficientBindingCommitment",
        "bridgeEncryption",
    )?;
    reject_forbidden_public_bridge_fields(
        commitment,
        "bridgeEncryption.plaintextCoefficientBindingCommitment",
    )?;
    validate_plaintext_coefficient_binding_commitment_shell(commitment)?;
    let public_commitment_chunks = read_plaintext_binding_commitment_chunks(commitment)?;
    let relation_commitment_chunks = plaintext_binding_relation_commitment_chunks(
        plaintext_coefficient_response,
        plaintext_binding_opening_response,
        &public_commitment_chunks,
        challenge_scalar,
    )?;

    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-plaintext-binding-relation-commitment-v1",
            "scheme": PLAINTEXT_COEFFICIENT_BINDING_SCHEME,
            "bindingStatus": PROOF_FRIENDLY_PLAINTEXT_BINDING_STATUS,
            "commitmentModulus": SHARE_COMMITMENT_MODULUS.to_string(),
            "commitmentChunks": commitment_chunks_value(&relation_commitment_chunks),
        }),
    )
}

pub(super) fn plaintext_binding_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-plaintext-coefficient-binding-profile-v1",
            "objectType": "AggregateBridgePlaintextCoefficientBindingProfile",
            "objectVersion": 1,
            "scheme": PLAINTEXT_COEFFICIENT_BINDING_SCHEME,
            "commitmentModulus": SHARE_COMMITMENT_MODULUS.to_string(),
            "moduleRank": SHARE_COMMITMENT_MODULE_RANK,
            "moduleDegree": SHARE_COMMITMENT_MODULE_DEGREE,
            "openingCoordinateCountPerChunk": SHARE_COMMITMENT_OPENING_DIMENSION,
            "openingInfinityNormBound": PLAINTEXT_BINDING_OPENING_INFINITY_NORM_BOUND,
            "plaintextCoefficientCount": POLYNOMIAL_DEGREE,
            "chunkCount": plaintext_binding_chunk_count()?,
            "matrixDerivation": "sealed.vote/internal/share-commitment/public-matrices",
            "currentUse": "internal proof binding only; not result acceptance evidence",
        }),
    )
}

fn plaintext_binding_chunk_count() -> CanonicalResult<usize> {
    if !POLYNOMIAL_DEGREE.is_multiple_of(SHARE_COMMITMENT_MODULE_DEGREE) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext coefficient count is not chunk-aligned for the commitment ring",
        ));
    }

    Ok(POLYNOMIAL_DEGREE / SHARE_COMMITMENT_MODULE_DEGREE)
}

pub(super) fn plaintext_binding_commitment_chunks(
    plaintext_coefficients: &[u64],
    opening_witness: &[BigInt],
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    if plaintext_coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding received the wrong plaintext coefficient count",
        ));
    }
    let expected_opening_count = plaintext_binding_opening_scalar_count()?;
    if opening_witness.len() != expected_opening_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding opening witness has the wrong length",
        ));
    }
    let parameters = plaintext_binding_parameters()?;
    plaintext_coefficients
        .chunks_exact(SHARE_COMMITMENT_MODULE_DEGREE)
        .zip(opening_witness.chunks_exact(SHARE_COMMITMENT_OPENING_DIMENSION))
        .map(|(plaintext_chunk, opening_chunk)| {
            plaintext_binding_commitment_chunk(&parameters, plaintext_chunk, opening_chunk)
        })
        .collect()
}

fn plaintext_binding_relation_commitment_chunks(
    plaintext_coefficient_response: &[BigInt],
    opening_response: &[BigInt],
    public_commitment_chunks: &[Vec<Vec<u64>>],
    challenge_scalar: u128,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    if public_commitment_chunks.len() != plaintext_binding_chunk_count()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding public commitment chunk count is invalid",
        ));
    }
    let parameters = plaintext_binding_parameters()?;
    plaintext_coefficient_response
        .chunks_exact(SHARE_COMMITMENT_MODULE_DEGREE)
        .zip(opening_response.chunks_exact(SHARE_COMMITMENT_OPENING_DIMENSION))
        .zip(public_commitment_chunks.iter())
        .map(
            |((plaintext_chunk, opening_chunk), public_commitment_chunk)| {
                plaintext_binding_relation_commitment_chunk(
                    &parameters,
                    plaintext_chunk,
                    opening_chunk,
                    public_commitment_chunk,
                    challenge_scalar,
                )
            },
        )
        .collect()
}

fn plaintext_binding_commitment_chunk(
    parameters: &PlaintextBindingParameters,
    plaintext_chunk: &[u64],
    opening_chunk: &[BigInt],
) -> CanonicalResult<Vec<Vec<u64>>> {
    if plaintext_chunk.len() != SHARE_COMMITMENT_MODULE_DEGREE
        || opening_chunk.len() != SHARE_COMMITMENT_OPENING_DIMENSION
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding chunk dimensions are invalid",
        ));
    }
    let plaintext_polynomial = plaintext_chunk.to_vec();
    parameters
        .ring
        .validate_coefficients(&plaintext_polynomial)?;

    parameters
        .message_matrix
        .iter()
        .zip(parameters.randomness_matrix.iter())
        .map(|(message_polynomial, randomness_row)| {
            let mut output = parameters
                .ring
                .mul_negacyclic(message_polynomial, &plaintext_polynomial)?;
            for (opening_value, randomness_polynomial) in opening_chunk.iter().zip(randomness_row) {
                let opening_residue = signed_bigint_to_share_commitment_residue(opening_value)?;
                parameters.ring.scaled_add_assign(
                    &mut output,
                    opening_residue,
                    randomness_polynomial,
                )?;
            }

            Ok(output)
        })
        .collect()
}

fn plaintext_binding_relation_commitment_chunk(
    parameters: &PlaintextBindingParameters,
    plaintext_response_chunk: &[BigInt],
    opening_response_chunk: &[BigInt],
    public_commitment_chunk: &[Vec<u64>],
    challenge_scalar: u128,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if plaintext_response_chunk.len() != SHARE_COMMITMENT_MODULE_DEGREE
        || opening_response_chunk.len() != SHARE_COMMITMENT_OPENING_DIMENSION
        || public_commitment_chunk.len() != SHARE_COMMITMENT_MODULE_RANK
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding relation chunk dimensions are invalid",
        ));
    }
    let plaintext_response_polynomial = plaintext_response_chunk
        .iter()
        .map(signed_bigint_to_share_commitment_residue)
        .collect::<CanonicalResult<Vec<_>>>()?;
    let challenge_residue = u64::try_from(challenge_scalar % u128::from(SHARE_COMMITMENT_MODULUS))
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge plaintext binding challenge residue does not fit u64",
            )
        })?;

    parameters
        .message_matrix
        .iter()
        .zip(parameters.randomness_matrix.iter())
        .zip(public_commitment_chunk.iter())
        .map(
            |((message_polynomial, randomness_row), public_commitment_polynomial)| {
                parameters
                    .ring
                    .validate_coefficients(public_commitment_polynomial)?;
                let mut output = parameters
                    .ring
                    .mul_negacyclic(message_polynomial, &plaintext_response_polynomial)?;
                for (opening_response, randomness_polynomial) in
                    opening_response_chunk.iter().zip(randomness_row)
                {
                    let opening_response_residue =
                        signed_bigint_to_share_commitment_residue(opening_response)?;
                    parameters.ring.scaled_add_assign(
                        &mut output,
                        opening_response_residue,
                        randomness_polynomial,
                    )?;
                }
                let scaled_public_commitment = parameters
                    .ring
                    .scale(challenge_residue, public_commitment_polynomial)?;
                parameters
                    .ring
                    .sub_assign(&mut output, &scaled_public_commitment)?;

                Ok(output)
            },
        )
        .collect()
}

fn sample_plaintext_binding_opening_witness(
    bridge_proof_profile_hash: &str,
    plaintext_root: &str,
    ciphertext_root: &str,
    prover_randomness_hex: &str,
) -> CanonicalResult<Vec<BigInt>> {
    let opening_count = plaintext_binding_opening_scalar_count()?;
    (0..opening_count)
        .map(|coordinate_index| {
            sample_plaintext_binding_opening_coordinate(
                bridge_proof_profile_hash,
                plaintext_root,
                ciphertext_root,
                prover_randomness_hex,
                coordinate_index,
            )
        })
        .collect()
}

fn sample_plaintext_binding_opening_coordinate(
    bridge_proof_profile_hash: &str,
    plaintext_root: &str,
    ciphertext_root: &str,
    prover_randomness_hex: &str,
    coordinate_index: usize,
) -> CanonicalResult<BigInt> {
    let range_width = u64::try_from(2_i64 * PLAINTEXT_BINDING_OPENING_INFINITY_NORM_BOUND + 1)
        .expect("plaintext binding opening range width fits u64");
    let rejection_limit = u64::MAX - (u64::MAX % range_width);
    let coordinate_index_bytes = u64::try_from(coordinate_index)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge plaintext binding opening coordinate index does not fit u64",
            )
        })?
        .to_le_bytes();
    let mut block_index = 0_u64;

    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            "sealed-lattice-root/aggregate-bridge-plaintext-binding-opening-v1",
            &[
                bridge_proof_profile_hash.as_bytes(),
                plaintext_root.as_bytes(),
                ciphertext_root.as_bytes(),
                prover_randomness_hex.as_bytes(),
                &coordinate_index_bytes,
                &block_index_bytes,
            ],
        );
        for chunk in block.chunks_exact(8) {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(chunk);
            let candidate = u64::from_le_bytes(bytes);
            if candidate < rejection_limit {
                let sampled = i64::try_from(candidate % range_width).expect("range fits i64")
                    - PLAINTEXT_BINDING_OPENING_INFINITY_NORM_BOUND;
                return Ok(BigInt::from(sampled));
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge plaintext binding opening sampler overflowed",
            )
        })?;
    }
}

fn validate_plaintext_coefficient_binding_commitment_shell(
    commitment: &Value,
) -> CanonicalResult<()> {
    let expected_commitment_modulus = SHARE_COMMITMENT_MODULUS.to_string();
    let expected_profile_hash = plaintext_binding_profile_hash()?;
    if string_field(commitment, "objectType")
        != Some("AggregateBridgePlaintextCoefficientCommitment")
        || read_u64_object_field(
            commitment,
            "objectVersion",
            "plaintextCoefficientCommitment",
        )? != 1
        || string_field(commitment, "scheme") != Some(PLAINTEXT_COEFFICIENT_BINDING_SCHEME)
        || string_field(commitment, "bindingStatus")
            != Some(PROOF_FRIENDLY_PLAINTEXT_BINDING_STATUS)
        || read_u64_object_field(
            commitment,
            "plaintextCoefficientCount",
            "plaintextCoefficientCommitment",
        )? != POLYNOMIAL_DEGREE as u64
        || read_u64_object_field(commitment, "chunkDegree", "plaintextCoefficientCommitment")?
            != SHARE_COMMITMENT_MODULE_DEGREE as u64
        || read_u64_object_field(commitment, "moduleRank", "plaintextCoefficientCommitment")?
            != SHARE_COMMITMENT_MODULE_RANK as u64
        || read_u64_object_field(
            commitment,
            "openingCoordinateCountPerChunk",
            "plaintextCoefficientCommitment",
        )? != SHARE_COMMITMENT_OPENING_DIMENSION as u64
        || read_u64_object_field(
            commitment,
            "openingInfinityNormBound",
            "plaintextCoefficientCommitment",
        )? != PLAINTEXT_BINDING_OPENING_INFINITY_NORM_BOUND as u64
        || string_field(commitment, "commitmentModulus")
            != Some(expected_commitment_modulus.as_str())
        || commitment
            .get("sameHiddenPlaintextCoefficientVectorRequired")
            .and_then(Value::as_bool)
            != Some(true)
        || string_field(commitment, "currentUse")
            != Some("internal proof binding only; not result acceptance evidence")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge plaintext coefficient commitment shell is not supported",
        ));
    }
    if string_field(commitment, "commitmentProfileHash") != Some(expected_profile_hash.as_str()) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge plaintext coefficient commitment profile hash is invalid",
        ));
    }
    if read_u64_object_field(commitment, "chunkCount", "plaintextCoefficientCommitment")?
        != plaintext_binding_chunk_count()? as u64
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext coefficient commitment chunk count is invalid",
        ));
    }

    Ok(())
}

pub(super) fn read_plaintext_binding_commitment_chunks(
    commitment: &Value,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let chunks = commitment
        .get("commitmentChunks")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "plaintextCoefficientCommitment.commitmentChunks must be an array",
            )
        })?;
    if chunks.len() != plaintext_binding_chunk_count()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext coefficient commitment has an invalid chunk count",
        ));
    }

    chunks
        .iter()
        .enumerate()
        .map(|(expected_chunk_index, chunk)| {
            if read_u64_object_field(chunk, "chunkIndex", "plaintextCoefficientCommitment.chunk")?
                != expected_chunk_index as u64
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "encrypted aggregate bridge plaintext coefficient commitment chunk index is not canonical",
                ));
            }
            read_commitment_polynomial_vector(chunk)
        })
        .collect()
}

fn read_commitment_polynomial_vector(chunk: &Value) -> CanonicalResult<Vec<Vec<u64>>> {
    let vector = chunk
        .get("commitmentPolynomialVector")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "plaintextCoefficientCommitment.chunk.commitmentPolynomialVector must be an array",
            )
        })?;
    if vector.len() != SHARE_COMMITMENT_MODULE_RANK {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext coefficient commitment vector rank is invalid",
        ));
    }
    vector
        .iter()
        .map(|polynomial| {
            let coefficients = polynomial.as_array().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "plaintextCoefficientCommitment polynomial must be an array",
                )
            })?;
            if coefficients.len() != SHARE_COMMITMENT_MODULE_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "encrypted aggregate bridge plaintext coefficient commitment polynomial degree is invalid",
                ));
            }
            coefficients
                .iter()
                .map(|coefficient| {
                    let coefficient = coefficient.as_str().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "plaintextCoefficientCommitment coefficient must be a decimal string",
                        )
                    })?;
                    let parsed = coefficient.parse::<u64>().map_err(|error| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "plaintextCoefficientCommitment coefficient is not a u64: {error}"
                            ),
                        )
                    })?;
                    if parsed >= SHARE_COMMITMENT_MODULUS {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::ProfileComponentMismatch,
                            "plaintextCoefficientCommitment coefficient is outside the commitment modulus",
                        ));
                    }

                    Ok(parsed)
                })
                .collect()
        })
        .collect()
}

fn commitment_chunks_value(chunks: &[Vec<Vec<u64>>]) -> Value {
    Value::Array(
        chunks
            .iter()
            .enumerate()
            .map(|(chunk_index, chunk)| {
                json!({
                    "chunkIndex": chunk_index,
                    "commitmentPolynomialVector": polynomial_vector_value(chunk),
                })
            })
            .collect(),
    )
}

fn polynomial_vector_value(polynomial_vector: &[Vec<u64>]) -> Value {
    Value::Array(
        polynomial_vector
            .iter()
            .map(|polynomial| {
                Value::Array(
                    polynomial
                        .iter()
                        .map(|coefficient| Value::String(coefficient.to_string()))
                        .collect(),
                )
            })
            .collect(),
    )
}

fn plaintext_binding_ring() -> CanonicalResult<PolynomialRing> {
    PolynomialRing::new(SHARE_COMMITMENT_MODULE_DEGREE, SHARE_COMMITMENT_MODULUS)
}

fn plaintext_binding_parameters() -> CanonicalResult<PlaintextBindingParameters> {
    Ok(PlaintextBindingParameters {
        ring: plaintext_binding_ring()?,
        message_matrix: plaintext_binding_message_matrix()?,
        randomness_matrix: plaintext_binding_randomness_matrix()?,
    })
}

fn plaintext_binding_message_matrix() -> CanonicalResult<Vec<Vec<u64>>> {
    let profile_hash = plaintext_binding_profile_hash()?;
    derive_share_commitment_message_matrix(&profile_hash).map_err(component_error)
}

fn plaintext_binding_randomness_matrix() -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let profile_hash = plaintext_binding_profile_hash()?;
    derive_share_commitment_randomness_matrix(&profile_hash).map_err(component_error)
}

fn signed_bigint_to_share_commitment_residue(value: &BigInt) -> CanonicalResult<u64> {
    let modulus_bigint = BigInt::from(SHARE_COMMITMENT_MODULUS);
    let residue = ((value % &modulus_bigint) + &modulus_bigint) % &modulus_bigint;
    residue.to_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext binding residue does not fit u64",
        )
    })
}

fn component_error(error: ComponentProofBackendError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, error.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::Sign;

    #[test]
    fn plaintext_binding_commitment_rejects_changed_plaintext_response() {
        let mut plaintext_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        plaintext_coefficients[0] = 17;
        plaintext_coefficients[257] = 65_536;
        let binding = generate_plaintext_coefficient_binding(
            &plaintext_coefficients,
            &"1".repeat(128),
            &"2".repeat(128),
            &"3".repeat(128),
            &"4".repeat(64),
        )
        .expect("binding should generate");
        let bridge_encryption = json!({
            "plaintextCoefficientBindingCommitment": binding.commitment,
            "plaintextCoefficientBindingCommitmentHash": binding.commitment_hash,
        });
        let challenge_scalar = 37_u128;
        let plaintext_response = plaintext_coefficients
            .iter()
            .map(|coefficient| BigInt::from(challenge_scalar) * BigInt::from(*coefficient))
            .collect::<Vec<_>>();
        let opening_response = binding
            .opening_witness
            .iter()
            .map(|opening| BigInt::from(challenge_scalar) * opening)
            .collect::<Vec<_>>();
        let honest_commitment = plaintext_binding_relation_commitment_hash_from_responses(
            &bridge_encryption,
            challenge_scalar,
            &plaintext_response,
            &opening_response,
        )
        .expect("honest response should commit");
        let mut changed_plaintext_response = plaintext_response;
        changed_plaintext_response[0] += BigInt::from(1_u8);
        let changed_commitment = plaintext_binding_relation_commitment_hash_from_responses(
            &bridge_encryption,
            challenge_scalar,
            &changed_plaintext_response,
            &opening_response,
        )
        .expect("changed response should still hash");

        assert_ne!(honest_commitment, changed_commitment);
    }

    #[test]
    fn plaintext_binding_relation_reconstructs_prechallenge_commitment() {
        let mut plaintext_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        plaintext_coefficients[0] = 23;
        plaintext_coefficients[SHARE_COMMITMENT_MODULE_DEGREE] = 42;
        let binding = generate_plaintext_coefficient_binding(
            &plaintext_coefficients,
            &"1".repeat(128),
            &"2".repeat(128),
            &"3".repeat(128),
            &"4".repeat(64),
        )
        .expect("binding should generate");
        let bridge_encryption = json!({
            "plaintextCoefficientBindingCommitment": binding.commitment,
            "plaintextCoefficientBindingCommitmentHash": binding.commitment_hash,
        });
        let plaintext_masks = plaintext_coefficients
            .iter()
            .enumerate()
            .map(|(coefficient_index, _)| BigInt::from((coefficient_index % 11) as i64 - 5))
            .collect::<Vec<_>>();
        let opening_masks = binding
            .opening_witness
            .iter()
            .enumerate()
            .map(|(opening_index, _)| BigInt::from((opening_index % 7) as i64 - 3))
            .collect::<Vec<_>>();
        let prechallenge_commitment = plaintext_binding_relation_commitment_hash_from_responses(
            &bridge_encryption,
            0,
            &plaintext_masks,
            &opening_masks,
        )
        .expect("prechallenge commitment should hash");
        let challenge_scalar = 37_u128;
        let challenge = BigInt::from(challenge_scalar);
        let plaintext_response = plaintext_masks
            .iter()
            .zip(plaintext_coefficients.iter())
            .map(|(mask, coefficient)| mask + &challenge * BigInt::from(*coefficient))
            .collect::<Vec<_>>();
        let opening_response = opening_masks
            .iter()
            .zip(binding.opening_witness.iter())
            .map(|(mask, opening)| mask + &challenge * opening)
            .collect::<Vec<_>>();
        let reconstructed_commitment = plaintext_binding_relation_commitment_hash_from_responses(
            &bridge_encryption,
            challenge_scalar,
            &plaintext_response,
            &opening_response,
        )
        .expect("honest response should reconstruct the prechallenge commitment");

        assert_eq!(prechallenge_commitment, reconstructed_commitment);
    }

    #[test]
    fn plaintext_binding_opening_sampler_stays_inside_declared_bound() {
        let openings = sample_plaintext_binding_opening_witness(
            &"1".repeat(128),
            &"2".repeat(128),
            &"3".repeat(128),
            &"4".repeat(64),
        )
        .expect("openings should sample");
        assert_eq!(
            openings.len(),
            plaintext_binding_opening_scalar_count().expect("count")
        );
        for opening in openings {
            let absolute = if opening.sign() == Sign::Minus {
                -opening
            } else {
                opening
            };
            assert!(
                absolute <= BigInt::from(PLAINTEXT_BINDING_OPENING_INFINITY_NORM_BOUND),
                "opening must stay within the binding profile bound"
            );
        }
    }
}
