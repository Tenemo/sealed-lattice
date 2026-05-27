use super::validation::{
    read_u64_object_field, read_usize_object_field, reject_forbidden_public_bridge_fields,
    require_equal_string, require_equal_u64,
};
use super::*;

pub(super) struct BridgeSharedWitnessProverInput<'value> {
    pub(super) setup_package: &'value Value,
    pub(super) bridge_encryption: &'value Value,
    pub(super) proof_input: &'value Value,
    pub(super) bridge_proof_statement_digest: &'value str,
    pub(super) contributor_identity: &'value str,
    pub(super) aggregate_derivation_statement_digest: &'value str,
    pub(super) aggregate_integer_share_vector: &'value [u64],
    pub(super) aggregate_opening_randomness: &'value [i64],
    pub(super) aggregate_reduced_coordinates: &'value [u64],
    pub(super) aggregate_quotient_vector: &'value [u64],
    pub(super) trace: &'value crate::bgv::commands::M9BridgeCiphertextRelationTrace,
    pub(super) prover_randomness_hex: &'value str,
}

pub(super) struct BridgeSharedWitnessProofVerification {
    pub(super) challenge_hex: String,
    pub(super) shared_response_scalar_count: u64,
}

struct BridgeAggregateRelationCommitmentContext {
    parsed_statement: ParsedSparseComponentProofStatement,
    target_vector: PolynomialVector,
}

pub(super) fn generate_bridge_shared_witness_proof(
    input: BridgeSharedWitnessProverInput<'_>,
) -> CanonicalResult<Value> {
    let aggregate_integer_witness = u64_slice_to_i128_vec(input.aggregate_integer_share_vector);
    let aggregate_opening_witness = i64_slice_to_i128_vec(input.aggregate_opening_randomness);
    let aggregate_reduced_witness = u64_slice_to_i128_vec(input.aggregate_reduced_coordinates);
    let aggregate_quotient_witness = u64_slice_to_i128_vec(input.aggregate_quotient_vector);
    let plaintext_coefficient_witness =
        u64_slice_to_i128_vec(&input.trace.plaintext_coefficients_mod_plaintext);
    let randomizer_witness = i64_slice_to_i128_vec(&input.trace.encryption_randomness_coefficients);
    let perturbation_zero_witness =
        i64_slice_to_i128_vec(&input.trace.encryption_error_zero_coefficients);
    let perturbation_one_witness =
        i64_slice_to_i128_vec(&input.trace.encryption_error_one_coefficients);
    let aggregate_relation_context =
        bridge_aggregate_relation_commitment_context(input.proof_input)?;
    let mut checks = Vec::with_capacity(BRIDGE_SHARED_WITNESS_CHECK_COUNT);
    let mut challenge_hex = String::new();

    for check_index in 0..BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        let aggregate_integer_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "aggregate-share",
            aggregate_integer_witness.len(),
        );
        let aggregate_opening_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "aggregate-opening",
            aggregate_opening_witness.len(),
        );
        let aggregate_reduced_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "aggregate-reduced",
            aggregate_reduced_witness.len(),
        );
        let aggregate_quotient_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "aggregate-quotient",
            aggregate_quotient_witness.len(),
        );
        let plaintext_coefficient_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "batch-coefficient",
            plaintext_coefficient_witness.len(),
        );
        let randomizer_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "cipher-randomizer",
            randomizer_witness.len(),
        );
        let perturbation_zero_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "bounded-perturbation-zero",
            perturbation_zero_witness.len(),
        );
        let perturbation_one_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "bounded-perturbation-one",
            perturbation_one_witness.len(),
        );
        let aggregate_commitment_digest = aggregate_relation_commitment_digest_from_responses(
            &aggregate_relation_context,
            &aggregate_integer_mask,
            &aggregate_opening_mask,
            &aggregate_reduced_mask,
            &aggregate_quotient_mask,
            0,
        )?;
        let batch_commitment_digest =
            crate::bgv::commands::m9_bridge_batch_encoding_commitment_digest_from_responses(
                &aggregate_reduced_mask,
                &plaintext_coefficient_mask,
            )?;
        let bgv_commitment_digest =
            crate::bgv::commands::m9_bridge_ciphertext_commitment_digest_from_responses(
                input.setup_package,
                input.contributor_identity,
                input.aggregate_derivation_statement_digest,
                input.bridge_encryption,
                0,
                &plaintext_coefficient_mask,
                &randomizer_mask,
                &perturbation_zero_mask,
                &perturbation_one_mask,
            )?;
        let challenge_scalar = bridge_shared_witness_challenge_scalar(
            input.bridge_proof_statement_digest,
            check_index,
            &aggregate_commitment_digest,
            &batch_commitment_digest,
            &bgv_commitment_digest,
        );
        let check_challenge_hex = bridge_challenge_hex(challenge_scalar);
        challenge_hex.push_str(&check_challenge_hex);

        checks.push(json!({
            "checkIndex": check_index,
            "challengeScalarHex": check_challenge_hex,
            "aggregateRelationCommitmentDigest": aggregate_commitment_digest,
            "batchEncodingCommitmentDigest": batch_commitment_digest,
            "bgvCiphertextCommitmentDigest": bgv_commitment_digest,
            "aggregateShareResponseHex": i128_vector_hex(&response_vector(
                &aggregate_integer_mask,
                challenge_scalar,
                &aggregate_integer_witness,
            )?),
            "aggregateOpeningResponseHex": i128_vector_hex(&response_vector(
                &aggregate_opening_mask,
                challenge_scalar,
                &aggregate_opening_witness,
            )?),
            "aggregateReducedResponseHex": i128_vector_hex(&response_vector(
                &aggregate_reduced_mask,
                challenge_scalar,
                &aggregate_reduced_witness,
            )?),
            "aggregateQuotientResponseHex": i128_vector_hex(&response_vector(
                &aggregate_quotient_mask,
                challenge_scalar,
                &aggregate_quotient_witness,
            )?),
            "batchCoefficientResponseHex": i128_vector_hex(&response_vector(
                &plaintext_coefficient_mask,
                challenge_scalar,
                &plaintext_coefficient_witness,
            )?),
            "cipherRandomizerResponseHex": i128_vector_hex(&response_vector(
                &randomizer_mask,
                challenge_scalar,
                &randomizer_witness,
            )?),
            "boundedPerturbationZeroResponseHex": i128_vector_hex(&response_vector(
                &perturbation_zero_mask,
                challenge_scalar,
                &perturbation_zero_witness,
            )?),
            "boundedPerturbationOneResponseHex": i128_vector_hex(&response_vector(
                &perturbation_one_mask,
                challenge_scalar,
                &perturbation_one_witness,
            )?),
        }));
    }

    let shared_response_scalar_count = shared_response_scalar_count(
        aggregate_integer_witness.len(),
        aggregate_opening_witness.len(),
        aggregate_reduced_witness.len(),
        aggregate_quotient_witness.len(),
    )?;

    Ok(json!({
        "objectType": "AggregateBridgeSharedWitnessProof",
        "objectVersion": 1,
        "proofModel": "fiat-shamir-linear-shared-response-v1",
        "bridgeProofStatementDigest": input.bridge_proof_statement_digest,
        "relationCheckCount": BRIDGE_SHARED_WITNESS_CHECK_COUNT,
        "challengeHex": challenge_hex,
        "sharedResponseScalarCount": shared_response_scalar_count,
        "sameHiddenAggregateCoordinatesLinked": true,
        "checks": checks,
        "responseEncoding": "signed-i128-little-endian-hex-v1",
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_bridge_shared_witness_proof(
    proof_value: &Value,
    component: &Value,
    setup_package: &Value,
    bridge_encryption: &Value,
    bridge_proof_statement_digest: &str,
    contributor_identity: &str,
    aggregate_derivation_statement_digest: &str,
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
) -> CanonicalResult<BridgeSharedWitnessProofVerification> {
    let proof_input = required_json_field(component, "proofInput", "aggregateDerivationComponent")?;
    let shared_proof = required_json_field(proof_value, "bridgeSharedWitnessProof", "bridgeProof")?;
    reject_forbidden_public_bridge_fields(shared_proof, "bridgeProof.bridgeSharedWitnessProof")?;
    if string_field(shared_proof, "objectType") != Some("AggregateBridgeSharedWitnessProof")
        || read_u64_object_field(shared_proof, "objectVersion", "bridgeSharedWitnessProof")? != 1
        || string_field(shared_proof, "proofModel") != Some("fiat-shamir-linear-shared-response-v1")
        || string_field(shared_proof, "responseEncoding")
            != Some("signed-i128-little-endian-hex-v1")
        || shared_proof
            .get("sameHiddenAggregateCoordinatesLinked")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge shared-witness proof shell is not the supported verifier relation",
        ));
    }
    require_equal_string(
        shared_proof,
        "bridgeProofStatementDigest",
        bridge_proof_statement_digest,
        "shared-witness proof statement digest",
    )?;
    let relation_check_count = read_usize_object_field(
        shared_proof,
        "relationCheckCount",
        "bridgeSharedWitnessProof",
    )?;
    if relation_check_count != BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof has an unsupported check count",
        ));
    }
    let expected_aggregate_count =
        usize::try_from(aggregate_reduced_coordinate_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge aggregate reduced coordinate count does not fit usize",
            )
        })?;
    let expected_quotient_count =
        usize::try_from(aggregate_quotient_coordinate_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge aggregate quotient coordinate count does not fit usize",
            )
        })?;
    let expected_shared_response_scalar_count = shared_response_scalar_count(
        expected_aggregate_count,
        SHARE_COMMITMENT_OPENING_DIMENSION,
        expected_aggregate_count,
        expected_quotient_count,
    )?;
    require_equal_u64(
        shared_proof,
        "sharedResponseScalarCount",
        expected_shared_response_scalar_count,
        "shared-witness proof scalar count",
    )?;
    let checks = shared_proof
        .get("checks")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "bridgeSharedWitnessProof.checks must be an array",
            )
        })?;
    if checks.len() != BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof check array has the wrong length",
        ));
    }
    let aggregate_relation_context = bridge_aggregate_relation_commitment_context(proof_input)?;
    let mut challenge_hex = String::new();
    for (check_index, check) in checks.iter().enumerate() {
        require_equal_u64(
            check,
            "checkIndex",
            check_index as u64,
            "shared-witness proof check index",
        )?;
        let challenge_scalar_hex = required_string_field(
            check,
            "challengeScalarHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let challenge_scalar = parse_bridge_challenge_scalar(challenge_scalar_hex)?;
        let aggregate_share_response = read_i128_hex_vector(
            check,
            "aggregateShareResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_opening_response = read_i128_hex_vector(
            check,
            "aggregateOpeningResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_reduced_response = read_i128_hex_vector(
            check,
            "aggregateReducedResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_quotient_response = read_i128_hex_vector(
            check,
            "aggregateQuotientResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let batch_coefficient_response = read_i128_hex_vector(
            check,
            "batchCoefficientResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let cipher_randomizer_response = read_i128_hex_vector(
            check,
            "cipherRandomizerResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let bounded_perturbation_zero_response = read_i128_hex_vector(
            check,
            "boundedPerturbationZeroResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let bounded_perturbation_one_response = read_i128_hex_vector(
            check,
            "boundedPerturbationOneResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        validate_response_lengths(
            &aggregate_share_response,
            &aggregate_opening_response,
            &aggregate_reduced_response,
            &aggregate_quotient_response,
            &batch_coefficient_response,
            &cipher_randomizer_response,
            &bounded_perturbation_zero_response,
            &bounded_perturbation_one_response,
            expected_aggregate_count,
            expected_quotient_count,
        )?;
        let aggregate_commitment_digest = aggregate_relation_commitment_digest_from_responses(
            &aggregate_relation_context,
            &aggregate_share_response,
            &aggregate_opening_response,
            &aggregate_reduced_response,
            &aggregate_quotient_response,
            challenge_scalar,
        )?;
        let batch_commitment_digest =
            crate::bgv::commands::m9_bridge_batch_encoding_commitment_digest_from_responses(
                &aggregate_reduced_response,
                &batch_coefficient_response,
            )?;
        let bgv_commitment_digest =
            crate::bgv::commands::m9_bridge_ciphertext_commitment_digest_from_responses(
                setup_package,
                contributor_identity,
                aggregate_derivation_statement_digest,
                bridge_encryption,
                challenge_scalar,
                &batch_coefficient_response,
                &cipher_randomizer_response,
                &bounded_perturbation_zero_response,
                &bounded_perturbation_one_response,
            )?;
        require_equal_string(
            check,
            "aggregateRelationCommitmentDigest",
            &aggregate_commitment_digest,
            "shared-witness aggregate relation commitment digest",
        )?;
        require_equal_string(
            check,
            "batchEncodingCommitmentDigest",
            &batch_commitment_digest,
            "shared-witness batch encoding commitment digest",
        )?;
        require_equal_string(
            check,
            "bgvCiphertextCommitmentDigest",
            &bgv_commitment_digest,
            "shared-witness BGV ciphertext commitment digest",
        )?;
        let recomputed_challenge_scalar = bridge_shared_witness_challenge_scalar(
            bridge_proof_statement_digest,
            check_index,
            &aggregate_commitment_digest,
            &batch_commitment_digest,
            &bgv_commitment_digest,
        );
        if challenge_scalar != recomputed_challenge_scalar {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge shared-witness proof challenge does not match the Fiat-Shamir transcript",
            ));
        }
        challenge_hex.push_str(challenge_scalar_hex);
    }
    require_equal_string(
        shared_proof,
        "challengeHex",
        &challenge_hex,
        "shared-witness proof challenge transcript",
    )?;

    Ok(BridgeSharedWitnessProofVerification {
        challenge_hex,
        shared_response_scalar_count: expected_shared_response_scalar_count,
    })
}

fn bridge_aggregate_relation_commitment_context(
    proof_input: &Value,
) -> CanonicalResult<BridgeAggregateRelationCommitmentContext> {
    let proof_statement = required_json_field(proof_input, "proofStatement", "proofInput")?;
    let parsed_statement = sparse_matrix_from_sparse_component_statement(proof_statement)
        .map_err(|error| CanonicalError::new(CanonicalErrorCode::InvalidFixture, error.message))?;
    let ring = parsed_statement.source_statement_matrix.ring();
    let target_vector =
        PolynomialVector::new(ring, parsed_statement.target_vector_coefficients.clone())?;

    Ok(BridgeAggregateRelationCommitmentContext {
        parsed_statement,
        target_vector,
    })
}

fn aggregate_relation_commitment_digest_from_responses(
    context: &BridgeAggregateRelationCommitmentContext,
    aggregate_share_response: &[i128],
    aggregate_opening_response: &[i128],
    aggregate_reduced_response: &[i128],
    aggregate_quotient_response: &[i128],
    challenge_scalar: u64,
) -> CanonicalResult<String> {
    let ring = context.parsed_statement.source_statement_matrix.ring();
    let response_entries = aggregate_share_response
        .iter()
        .chain(aggregate_opening_response.iter())
        .chain(aggregate_reduced_response.iter())
        .chain(aggregate_quotient_response.iter())
        .map(|response| constant_response_polynomial(*response, ring.degree(), ring.modulus()))
        .collect::<Vec<_>>();
    let response_vector = PolynomialVector::new(ring, response_entries)?;
    let response_image = context
        .parsed_statement
        .source_statement_matrix
        .multiply_vector(&response_vector)?;
    let challenge_residue =
        u64::try_from(u128::from(challenge_scalar) % u128::from(ring.modulus())).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge challenge residue does not fit u64",
            )
        })?;
    let scaled_target_entries = context
        .target_vector
        .entries()
        .iter()
        .map(|entry| ring.scale(challenge_residue, entry))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let scaled_target = PolynomialVector::new(ring, scaled_target_entries)?;
    let commitment_vector = response_image.add(&scaled_target)?;

    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-relation-commitment-v1",
            "commitmentVector": canonical_polynomial_vector_response(commitment_vector.entries()),
        }),
    )
}

fn sample_bridge_mask_vector(
    statement_digest: &str,
    prover_randomness_hex: &str,
    check_index: usize,
    role: &str,
    length: usize,
) -> Vec<i128> {
    const MASK_COORDINATES_PER_DIGEST: usize = 4;
    const MASK_BYTES_PER_COORDINATE: usize = 15;
    const MASK_MAGNITUDE_BYTES_PER_COORDINATE: usize = 14;

    let check_index_bytes = (check_index as u64).to_le_bytes();
    let mut masks = Vec::with_capacity(length);
    let mut block_index = 0_u64;

    while masks.len() < length {
        let block_index_bytes = block_index.to_le_bytes();
        let digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-mask-v1",
            &[
                statement_digest.as_bytes(),
                prover_randomness_hex.as_bytes(),
                role.as_bytes(),
                &check_index_bytes,
                &block_index_bytes,
            ],
        );
        for lane_index in 0..MASK_COORDINATES_PER_DIGEST {
            if masks.len() == length {
                break;
            }
            let lane_start = lane_index * MASK_BYTES_PER_COORDINATE;
            let lane_end = lane_start + MASK_BYTES_PER_COORDINATE;
            let lane = &digest[lane_start..lane_end];
            let mut magnitude_bytes = [0_u8; 16];
            magnitude_bytes[..MASK_MAGNITUDE_BYTES_PER_COORDINATE]
                .copy_from_slice(&lane[..MASK_MAGNITUDE_BYTES_PER_COORDINATE]);
            let magnitude = i128::from_le_bytes(magnitude_bytes);
            let mask = if lane[MASK_MAGNITUDE_BYTES_PER_COORDINATE] & 1 == 0 {
                magnitude
            } else {
                -magnitude
            };
            masks.push(mask);
        }
        block_index = block_index
            .checked_add(1)
            .expect("bridge mask block index overflowed");
    }

    masks
}

fn bridge_shared_witness_challenge_scalar(
    statement_digest: &str,
    check_index: usize,
    aggregate_commitment_digest: &str,
    batch_commitment_digest: &str,
    bgv_commitment_digest: &str,
) -> u64 {
    let check_index_bytes = (check_index as u64).to_le_bytes();
    let digest = hash512(
        "sealed-lattice-root/aggregate-bridge-shared-witness-challenge-v1",
        &[
            statement_digest.as_bytes(),
            &check_index_bytes,
            aggregate_commitment_digest.as_bytes(),
            batch_commitment_digest.as_bytes(),
            bgv_commitment_digest.as_bytes(),
        ],
    );
    if let Some(challenge) = first_nonzero_u64_chunk(&digest) {
        return challenge;
    }

    let mut retry_index = 1_u64;
    loop {
        let retry_index_bytes = retry_index.to_le_bytes();
        let retry_digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-challenge-retry-v1",
            &[
                statement_digest.as_bytes(),
                &check_index_bytes,
                aggregate_commitment_digest.as_bytes(),
                batch_commitment_digest.as_bytes(),
                bgv_commitment_digest.as_bytes(),
                &retry_index_bytes,
            ],
        );
        if let Some(challenge) = first_nonzero_u64_chunk(&retry_digest) {
            return challenge;
        }
        retry_index = retry_index
            .checked_add(1)
            .expect("bridge challenge retry index overflowed");
    }
}

fn first_nonzero_u64_chunk(digest: &[u8]) -> Option<u64> {
    for chunk in digest.chunks_exact(8) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        let challenge = u64::from_le_bytes(bytes);
        if challenge != 0 {
            return Some(challenge);
        }
    }

    None
}

fn bridge_challenge_hex(challenge_scalar: u64) -> String {
    format!("{challenge_scalar:016x}")
}

fn parse_bridge_challenge_scalar(challenge_scalar_hex: &str) -> CanonicalResult<u64> {
    if challenge_scalar_hex.len() != 16
        || !challenge_scalar_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "M9 bridge shared-witness challenge scalar must be 16 lowercase hex characters",
        ));
    }
    let challenge = u64::from_str_radix(challenge_scalar_hex, 16).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "M9 bridge shared-witness challenge scalar is malformed",
        )
    })?;
    if challenge == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge shared-witness challenge scalar must be non-zero",
        ));
    }

    Ok(challenge)
}

fn response_vector(
    masks: &[i128],
    challenge_scalar: u64,
    witness: &[i128],
) -> CanonicalResult<Vec<i128>> {
    if masks.len() != witness.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge proof mask and witness dimensions do not match",
        ));
    }
    let challenge = i128::from(challenge_scalar);
    masks
        .iter()
        .zip(witness.iter())
        .map(|(mask, witness_value)| {
            let scaled_witness = challenge.checked_mul(*witness_value).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "M9 bridge proof response multiplication overflowed i128",
                )
            })?;
            mask.checked_add(scaled_witness).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "M9 bridge proof response addition overflowed i128",
                )
            })
        })
        .collect()
}

fn constant_response_polynomial(value: i128, degree: usize, modulus: u64) -> Vec<u64> {
    let mut polynomial = vec![0_u64; degree];
    polynomial[0] = signed_i128_to_modulus_residue(value, modulus);

    polynomial
}

fn signed_i128_to_modulus_residue(value: i128, modulus: u64) -> u64 {
    let residue = value.rem_euclid(i128::from(modulus));

    u64::try_from(residue).expect("non-negative i128 residue below a u64 modulus fits u64")
}

fn i128_vector_hex(values: &[i128]) -> String {
    let mut bytes = Vec::with_capacity(values.len() * 16);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    to_hex(&bytes)
}

fn read_i128_hex_vector(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<Vec<i128>> {
    let encoded = required_string_field(value, field_name, object_name)?;
    let bytes = decode_hex(encoded)?;
    if bytes.len() % 16 != 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_name}.{field_name} must encode whole i128 values"),
        ));
    }

    Ok(bytes
        .chunks_exact(16)
        .map(|chunk| {
            let mut value_bytes = [0_u8; 16];
            value_bytes.copy_from_slice(chunk);
            i128::from_le_bytes(value_bytes)
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn validate_response_lengths(
    aggregate_share_response: &[i128],
    aggregate_opening_response: &[i128],
    aggregate_reduced_response: &[i128],
    aggregate_quotient_response: &[i128],
    batch_coefficient_response: &[i128],
    cipher_randomizer_response: &[i128],
    bounded_perturbation_zero_response: &[i128],
    bounded_perturbation_one_response: &[i128],
    expected_aggregate_count: usize,
    expected_quotient_count: usize,
) -> CanonicalResult<()> {
    if aggregate_share_response.len() != expected_aggregate_count
        || aggregate_opening_response.len() != SHARE_COMMITMENT_OPENING_DIMENSION
        || aggregate_reduced_response.len() != expected_aggregate_count
        || aggregate_quotient_response.len() != expected_quotient_count
        || batch_coefficient_response.len() != POLYNOMIAL_DEGREE
        || cipher_randomizer_response.len() != POLYNOMIAL_DEGREE
        || bounded_perturbation_zero_response.len() != POLYNOMIAL_DEGREE
        || bounded_perturbation_one_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof response dimensions do not match the public statement",
        ));
    }

    Ok(())
}

fn shared_response_scalar_count(
    aggregate_share_count: usize,
    aggregate_opening_count: usize,
    aggregate_reduced_count: usize,
    aggregate_quotient_count: usize,
) -> CanonicalResult<u64> {
    let total = aggregate_share_count
        .checked_add(aggregate_opening_count)
        .and_then(|value| value.checked_add(aggregate_reduced_count))
        .and_then(|value| value.checked_add(aggregate_quotient_count))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge shared response scalar count overflowed",
            )
        })?;

    u64::try_from(total).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared response scalar count does not fit u64",
        )
    })
}

fn u64_slice_to_i128_vec(values: &[u64]) -> Vec<i128> {
    values.iter().map(|value| i128::from(*value)).collect()
}

fn i64_slice_to_i128_vec(values: &[i64]) -> Vec<i128> {
    values.iter().map(|value| i128::from(*value)).collect()
}

fn canonical_polynomial_vector_response(entries: &[Vec<u64>]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                Value::Array(
                    entry
                        .iter()
                        .map(|coefficient| Value::String(coefficient.to_string()))
                        .collect(),
                )
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{first_nonzero_u64_chunk, sample_bridge_mask_vector};
    use crate::hashing::hash512;

    fn mask_from_digest_lane(digest: &[u8], lane_index: usize) -> i128 {
        let lane_start = lane_index * 15;
        let lane = &digest[lane_start..lane_start + 15];
        let mut magnitude_bytes = [0_u8; 16];
        magnitude_bytes[..14].copy_from_slice(&lane[..14]);
        let magnitude = i128::from_le_bytes(magnitude_bytes);
        if lane[14] & 1 == 0 {
            magnitude
        } else {
            -magnitude
        }
    }

    #[test]
    fn bridge_mask_sampler_consumes_four_coordinates_per_digest() {
        let statement_digest = "statement-digest";
        let prover_randomness_hex = "001122";
        let role = "aggregate-share";
        let check_index_bytes = 3_u64.to_le_bytes();
        let first_block_index_bytes = 0_u64.to_le_bytes();
        let second_block_index_bytes = 1_u64.to_le_bytes();
        let first_digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-mask-v1",
            &[
                statement_digest.as_bytes(),
                prover_randomness_hex.as_bytes(),
                role.as_bytes(),
                &check_index_bytes,
                &first_block_index_bytes,
            ],
        );
        let second_digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-mask-v1",
            &[
                statement_digest.as_bytes(),
                prover_randomness_hex.as_bytes(),
                role.as_bytes(),
                &check_index_bytes,
                &second_block_index_bytes,
            ],
        );

        let masks = sample_bridge_mask_vector(statement_digest, prover_randomness_hex, 3, role, 5);

        assert_eq!(
            masks,
            vec![
                mask_from_digest_lane(&first_digest, 0),
                mask_from_digest_lane(&first_digest, 1),
                mask_from_digest_lane(&first_digest, 2),
                mask_from_digest_lane(&first_digest, 3),
                mask_from_digest_lane(&second_digest, 0),
            ]
        );
        assert_ne!(
            masks,
            sample_bridge_mask_vector(statement_digest, prover_randomness_hex, 4, role, 5)
        );
    }

    #[test]
    fn bridge_challenge_scanner_returns_first_nonzero_chunk() {
        let mut digest = [0_u8; 64];
        digest[16..24].copy_from_slice(&37_u64.to_le_bytes());
        digest[24..32].copy_from_slice(&41_u64.to_le_bytes());

        assert_eq!(first_nonzero_u64_chunk(&digest), Some(37));
        assert_eq!(first_nonzero_u64_chunk(&[0_u8; 64]), None);
    }
}
