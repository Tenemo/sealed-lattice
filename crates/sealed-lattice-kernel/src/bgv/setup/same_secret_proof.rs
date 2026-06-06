use serde_json::{Value, json};

use crate::{
    bgv::{
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, hash512, hash512_hex, to_hex},
};

use super::commitment::{
    SETUP_COMMITMENT_PROFILE_ID, SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, SetupCommitmentLimb, SetupCommitmentValue,
    linear_combination_setup_commitments, setup_commitment_modulus_product, setup_commitment_root,
    verify_setup_lifted_commitment_opening,
};
use super::setup_proof::SETUP_PROOF_PROFILE_ID;

const SAME_SECRET_INTERNAL_PROOF_MAGIC: &[u8; 8] = b"SLSSP001";
const SAME_SECRET_INTERNAL_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/same-secret/internal-relation-challenge-v1";
const SAME_SECRET_INTERNAL_COMMITMENT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret/internal-relation-commitment-v1";
const SAME_SECRET_INTERNAL_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret/internal-relation-proof-bytes-v1";
const SAME_SECRET_INTERNAL_MESSAGE_MASK_BITS: usize = 32;
const SAME_SECRET_INTERNAL_RANDOMNESS_MASK_BITS: usize = 80;
const SAME_SECRET_INTERNAL_CHALLENGE_BITS: usize = 32;
const SAME_SECRET_INTERNAL_TERNARY_INFINITY_BOUND: i128 = 1;
const SAME_SECRET_INTERNAL_NEGATIVE_INDICATOR_INFINITY_BOUND: i128 = 1;

pub(super) const SAME_SECRET_INTERNAL_PROOF_VERIFICATION_STATUS: &str =
    "internal-relation-verified-claim-pending";
pub(super) const SAME_SECRET_INTERNAL_PROOF_MODEL_STATUS: &str = "internal same-secret relation proof verifies shared integer openings, ternary support, and fixed response bounds; accepted LaZer/LNP soundness and zero-knowledge remain pending";

#[derive(Debug)]
pub(super) struct SameSecretInternalProofVerification {
    pub(super) proof_size_bytes: usize,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) challenge: u64,
}

struct ParsedSameSecretInternalProof {
    challenge: u64,
    relation_commitments: Vec<SetupCommitmentValue>,
    support_commitments: Vec<[u64; 4]>,
    secret_response_coefficients: Vec<i128>,
    negative_indicator_response_coefficients: Vec<i128>,
    randomness_response_by_limb: Vec<Vec<Vec<i128>>>,
    relation_commitment_hash: [u8; 64],
}

pub(super) fn same_secret_internal_relation_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(SAME_SECRET_INTERNAL_PROOF_BYTES_HASH_DOMAIN, &[proof_bytes])
}

pub(super) fn verify_same_secret_internal_relation_proof(
    public_matrix_seed_hash: &str,
    statement_record: &Value,
    constant_commitments: &[SetupCommitmentValue],
    setup_proof_binding: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<SameSecretInternalProofVerification> {
    validate_same_secret_constant_commitments(constant_commitments)?;
    let statement_hash = same_secret_internal_statement_hash(
        statement_record,
        constant_commitments,
        setup_proof_binding,
    )?;
    let parsed_proof = parse_same_secret_internal_relation_proof(
        proof_bytes,
        &statement_hash,
        constant_commitments,
    )?;
    verify_same_secret_response_bounds(
        parsed_proof.challenge,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
        &parsed_proof.randomness_response_by_limb,
    )?;
    verify_same_secret_support_response(
        parsed_proof.challenge,
        &parsed_proof.support_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
    )?;
    verify_same_secret_commitment_responses(
        public_matrix_seed_hash,
        constant_commitments,
        parsed_proof.challenge,
        &parsed_proof.relation_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
        &parsed_proof.randomness_response_by_limb,
    )?;

    Ok(SameSecretInternalProofVerification {
        proof_size_bytes: proof_bytes.len(),
        statement_hash_hex: to_hex(&statement_hash),
        relation_commitment_hash_hex: to_hex(&parsed_proof.relation_commitment_hash),
        challenge: parsed_proof.challenge,
    })
}

fn validate_same_secret_constant_commitments(
    constant_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<()> {
    if constant_commitments.len() != DATA_PRIMES.len() {
        return Err(invalid_same_secret_proof(
            "same-secret proof requires one constant VSS commitment for every Q_share limb",
        ));
    }
    let Some(first_commitment) = constant_commitments.first() else {
        return Err(invalid_same_secret_proof(
            "same-secret proof requires non-empty constant commitments",
        ));
    };
    let ring_degree = first_commitment.ring_degree;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(invalid_same_secret_proof(
            "same-secret proof commitment ring degree is outside the selected profile",
        ));
    }
    for (rns_limb_index, (commitment, rns_prime)) in constant_commitments
        .iter()
        .zip(DATA_PRIMES.iter())
        .enumerate()
    {
        if commitment.source_rns_limb_index != rns_limb_index
            || commitment.source_message_modulus != *rns_prime
            || commitment.shamir_coefficient_index != 0
            || commitment.ring_degree != ring_degree
        {
            return Err(invalid_same_secret_proof(
                "same-secret proof constant commitments must follow the accepted Q_share constant-coefficient order",
            ));
        }
    }

    Ok(())
}

fn same_secret_internal_statement_hash(
    statement_record: &Value,
    constant_commitments: &[SetupCommitmentValue],
    setup_proof_binding: &Value,
) -> CanonicalResult<[u8; 64]> {
    let commitment_roots = constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            Ok(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": commitment.source_message_modulus,
                "shamirCoefficientIndex": 0,
                "commitmentRoot": setup_commitment_root(commitment)?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let statement_json = canonical_json(&json!({
        "objectType": "SameSecretInternalRelationProofStatement",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofBinding": setup_proof_binding,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "proofModelStatus": SAME_SECRET_INTERNAL_PROOF_MODEL_STATUS,
        "sameSecretStatementRoot": statement_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_same_secret_proof("same-secret statement root is required"))?,
        "trusteeSecretCommitmentRoot": statement_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_same_secret_proof("trustee secret commitment root is required"))?,
        "trusteeRosterPosition": statement_record
            .get("trusteeRosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_same_secret_proof("trustee roster position is required"))?,
        "ringDegree": constant_commitments
            .first()
            .map(|commitment| commitment.ring_degree)
            .ok_or_else(|| invalid_same_secret_proof("constant commitments are required"))?,
        "rnsLimbCount": constant_commitments.len(),
        "constantCoefficientCommitmentRoots": commitment_roots,
        "relation": "for one shared ternary integer polynomial s_i, every accepted C_i,l,0 opens to s_i mod q_l",
    }))?;

    Ok(hash512(
        "sealed-lattice/setup/same-secret/internal-relation-statement-v1",
        &[statement_json.as_bytes()],
    ))
}

fn parse_same_secret_internal_relation_proof(
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
    expected_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<ParsedSameSecretInternalProof> {
    let expected_size = same_secret_internal_relation_proof_size(expected_commitments)?;
    if proof_bytes.len() != expected_size {
        return Err(invalid_same_secret_proof(
            "same-secret proof bytes do not match the expected size",
        ));
    }
    let mut cursor = 0_usize;
    let magic = read_fixed::<8>(proof_bytes, &mut cursor)?;
    if &magic != SAME_SECRET_INTERNAL_PROOF_MAGIC {
        return Err(invalid_same_secret_proof(
            "same-secret proof has the wrong format marker",
        ));
    }
    let statement_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    if &statement_hash != expected_statement_hash {
        return Err(invalid_same_secret_proof(
            "same-secret proof is not bound to this statement",
        ));
    }
    let challenge = read_u64(proof_bytes, &mut cursor)?;
    if challenge == 0 {
        return Err(invalid_same_secret_proof(
            "same-secret proof challenge is outside the expected range",
        ));
    }
    if challenge > same_secret_internal_challenge_maximum()? {
        return Err(invalid_same_secret_proof(
            "same-secret proof challenge exceeds the accepted challenge space",
        ));
    }
    let relation_commitments = expected_commitments
        .iter()
        .map(|expected_commitment| {
            read_same_secret_relation_commitment(proof_bytes, &mut cursor, expected_commitment)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let support_commitments = (0..expected_commitments[0].ring_degree)
        .map(|_| {
            Ok([
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
                read_u64(proof_bytes, &mut cursor)?,
            ])
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let secret_response_coefficients = read_i128_vector(
        proof_bytes,
        &mut cursor,
        expected_commitments[0].ring_degree,
    )?;
    let negative_indicator_response_coefficients = read_i128_vector(
        proof_bytes,
        &mut cursor,
        expected_commitments[0].ring_degree,
    )?;
    let randomness_response_by_limb = expected_commitments
        .iter()
        .map(|expected_commitment| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|_| {
                    read_i128_vector(proof_bytes, &mut cursor, expected_commitment.ring_degree)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    if cursor != proof_bytes.len() {
        return Err(invalid_same_secret_proof(
            "same-secret proof has trailing bytes",
        ));
    }
    let encoded_commitments =
        encode_same_secret_relation_commitments(&relation_commitments, &support_commitments)?;
    let relation_commitment_hash = same_secret_internal_relation_commitment_hash(
        expected_statement_hash,
        &encoded_commitments,
    );
    let recomputed_challenge = same_secret_internal_relation_challenge(
        expected_statement_hash,
        &relation_commitment_hash,
    )?;
    if challenge != recomputed_challenge {
        return Err(invalid_same_secret_proof(
            "same-secret proof challenge does not match its commitment",
        ));
    }

    Ok(ParsedSameSecretInternalProof {
        challenge,
        relation_commitments,
        support_commitments,
        secret_response_coefficients,
        negative_indicator_response_coefficients,
        randomness_response_by_limb,
        relation_commitment_hash,
    })
}

fn read_same_secret_relation_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
    expected_commitment: &SetupCommitmentValue,
) -> CanonicalResult<SetupCommitmentValue> {
    let mut limbs = Vec::with_capacity(expected_commitment.limbs.len());
    for expected_limb in &expected_commitment.limbs {
        let mut rows = Vec::with_capacity(expected_limb.rows.len());
        for expected_row in &expected_limb.rows {
            let mut row = Vec::with_capacity(expected_row.len());
            for _ in expected_row {
                let coefficient = read_u64(proof_bytes, cursor)?;
                if coefficient >= expected_limb.modulus {
                    return Err(invalid_same_secret_proof(
                        "same-secret relation commitment coefficient is not canonical",
                    ));
                }
                row.push(coefficient);
            }
            rows.push(row);
        }
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index: expected_limb.commitment_modulus_index,
            modulus: expected_limb.modulus,
            rows,
        });
    }

    Ok(SetupCommitmentValue {
        source_rns_limb_index: expected_commitment.source_rns_limb_index,
        source_message_modulus: expected_commitment.source_message_modulus,
        shamir_coefficient_index: expected_commitment.shamir_coefficient_index,
        ring_degree: expected_commitment.ring_degree,
        limbs,
    })
}

fn verify_same_secret_commitment_responses(
    public_matrix_seed_hash: &str,
    constant_commitments: &[SetupCommitmentValue],
    challenge: u64,
    relation_commitments: &[SetupCommitmentValue],
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
    randomness_response_by_limb: &[Vec<Vec<i128>>],
) -> CanonicalResult<()> {
    if relation_commitments.len() != constant_commitments.len()
        || randomness_response_by_limb.len() != constant_commitments.len()
    {
        return Err(invalid_same_secret_proof(
            "same-secret proof response limb count does not match the statement",
        ));
    }
    for (limb_index, ((constant_commitment, relation_commitment), randomness_response)) in
        constant_commitments
            .iter()
            .zip(relation_commitments.iter())
            .zip(randomness_response_by_limb.iter())
            .enumerate()
    {
        let expected_response_commitment = linear_combination_setup_commitments(&[
            (relation_commitment, 1),
            (constant_commitment, u128::from(challenge)),
        ])?;
        let response_message_coefficients = secret_response_coefficients
            .iter()
            .zip(negative_indicator_response_coefficients.iter())
            .map(|(secret_response, negative_indicator_response)| {
                same_secret_lifted_message_response(
                    *secret_response,
                    *negative_indicator_response,
                    constant_commitment.source_message_modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let response_randomness_bound = same_secret_randomness_response_bound(challenge)?;
        verify_setup_lifted_commitment_opening(
            public_matrix_seed_hash,
            &expected_response_commitment,
            &response_message_coefficients,
            randomness_response,
            response_randomness_bound,
        )
        .map_err(|_| {
            invalid_same_secret_proof(format!(
                "same-secret proof commitment response failed for Q_share limb {limb_index}"
            ))
        })?;
    }

    Ok(())
}

fn verify_same_secret_response_bounds(
    challenge: u64,
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
    randomness_response_by_limb: &[Vec<Vec<i128>>],
) -> CanonicalResult<()> {
    let secret_response_bound = same_secret_message_response_bound(
        challenge,
        SAME_SECRET_INTERNAL_TERNARY_INFINITY_BOUND,
        "same-secret secret response",
    )?;
    let negative_indicator_response_bound = same_secret_message_response_bound(
        challenge,
        SAME_SECRET_INTERNAL_NEGATIVE_INDICATOR_INFINITY_BOUND,
        "same-secret negative-indicator response",
    )?;
    verify_i128_vector_bound(
        secret_response_coefficients,
        secret_response_bound,
        "same-secret secret response",
    )?;
    verify_i128_vector_bound(
        negative_indicator_response_coefficients,
        negative_indicator_response_bound,
        "same-secret negative-indicator response",
    )?;
    let randomness_response_bound = same_secret_randomness_response_bound(challenge)?;
    for limb_columns in randomness_response_by_limb {
        for column in limb_columns {
            verify_i128_vector_bound(
                column,
                randomness_response_bound,
                "same-secret opening-randomness response",
            )?;
        }
    }

    Ok(())
}

fn verify_i128_vector_bound(
    values: &[i128],
    inclusive_bound: i128,
    label: &str,
) -> CanonicalResult<()> {
    for value in values {
        let absolute_value = value.checked_abs().ok_or_else(|| {
            invalid_same_secret_proof(format!("{label} absolute value overflowed"))
        })?;
        if absolute_value > inclusive_bound {
            return Err(invalid_same_secret_proof(format!(
                "{label} exceeds the accepted response bound"
            )));
        }
    }

    Ok(())
}

fn verify_same_secret_support_response(
    challenge: u64,
    support_commitments: &[[u64; 4]],
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
) -> CanonicalResult<()> {
    if support_commitments.len() != secret_response_coefficients.len()
        || negative_indicator_response_coefficients.len() != secret_response_coefficients.len()
    {
        return Err(invalid_same_secret_proof(
            "same-secret support commitment count does not match the secret response",
        ));
    }
    let modulus = DATA_PRIMES[0];
    let challenge_residue = challenge % modulus;
    for (coefficient_index, ((support_commitment, secret_response), negative_response)) in
        support_commitments
            .iter()
            .zip(secret_response_coefficients.iter())
            .zip(negative_indicator_response_coefficients.iter())
            .enumerate()
    {
        verify_boolean_support_response(
            "same-secret negative indicator",
            coefficient_index,
            *negative_response,
            support_commitment[0],
            support_commitment[1],
            challenge_residue,
            modulus,
        )?;
        verify_boolean_support_response(
            "same-secret shifted nonnegative indicator",
            coefficient_index,
            secret_response
                .checked_add(*negative_response)
                .ok_or_else(|| {
                    invalid_same_secret_proof("same-secret shifted support response overflowed")
                })?,
            support_commitment[2],
            support_commitment[3],
            challenge_residue,
            modulus,
        )?;
    }

    Ok(())
}

fn verify_boolean_support_response(
    label: &str,
    coefficient_index: usize,
    response: i128,
    commitment_constant: u64,
    commitment_linear: u64,
    challenge_residue: u64,
    modulus: u64,
) -> CanonicalResult<()> {
    let response_residue = signed_i128_residue_u64(response, modulus)?;
    let response_square = mul_mod(response_residue, response_residue, modulus)?;
    let support_value = sub_mod(
        response_square,
        mul_mod(challenge_residue, response_residue, modulus)?,
        modulus,
    )?;
    let expanded_value = add_mod(
        commitment_constant,
        mul_mod(challenge_residue, commitment_linear, modulus)?,
        modulus,
    )?;
    if support_value != expanded_value {
        return Err(invalid_same_secret_proof(format!(
            "{label} support check failed at coefficient {coefficient_index}"
        )));
    }

    Ok(())
}

fn encode_same_secret_relation_commitments(
    relation_commitments: &[SetupCommitmentValue],
    support_commitments: &[[u64; 4]],
) -> CanonicalResult<Vec<u8>> {
    let byte_count = relation_commitments
        .iter()
        .try_fold(0_usize, |accumulator, commitment| {
            accumulator
                .checked_add(setup_commitment_value_byte_count(commitment)?)
                .ok_or_else(|| {
                    invalid_same_secret_proof("same-secret proof commitment size overflowed")
                })
        })?
        .checked_add(
            support_commitments
                .len()
                .checked_mul(4)
                .and_then(|count| count.checked_mul(8))
                .ok_or_else(|| invalid_same_secret_proof("same-secret support size overflowed"))?,
        )
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof commitment size overflowed"))?;
    let mut encoded = Vec::with_capacity(byte_count);
    for commitment in relation_commitments {
        for limb in &commitment.limbs {
            for row in &limb.rows {
                for coefficient in row {
                    encoded.extend_from_slice(&coefficient.to_le_bytes());
                }
            }
        }
    }
    for support_commitment in support_commitments {
        for value in support_commitment {
            encoded.extend_from_slice(&value.to_le_bytes());
        }
    }

    Ok(encoded)
}

fn same_secret_internal_relation_commitment_hash(
    statement_hash: &[u8; 64],
    encoded_commitments: &[u8],
) -> [u8; 64] {
    hash512(
        SAME_SECRET_INTERNAL_COMMITMENT_HASH_DOMAIN,
        &[statement_hash, encoded_commitments],
    )
}

fn same_secret_internal_relation_challenge(
    statement_hash: &[u8; 64],
    relation_commitment_hash: &[u8; 64],
) -> CanonicalResult<u64> {
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            SAME_SECRET_INTERNAL_CHALLENGE_DOMAIN,
            &[statement_hash, relation_commitment_hash, &block_index_bytes],
        );
        let mut challenge_bytes = [0_u8; 8];
        challenge_bytes[..4].copy_from_slice(&block[..4]);
        let challenge = u64::from_le_bytes(challenge_bytes);
        if challenge != 0 {
            return Ok(challenge);
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_same_secret_proof("same-secret challenge block index overflowed")
        })?;
    }
}

fn same_secret_internal_challenge_maximum() -> CanonicalResult<u64> {
    let challenge_bits = u32::try_from(SAME_SECRET_INTERNAL_CHALLENGE_BITS).map_err(|_| {
        invalid_same_secret_proof("same-secret challenge bit count does not fit u32")
    })?;
    1_u64
        .checked_shl(challenge_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_same_secret_proof("same-secret challenge bound overflowed"))
}

fn same_secret_message_response_bound(
    challenge: u64,
    witness_infinity_bound: i128,
    label: &str,
) -> CanonicalResult<i128> {
    same_secret_response_bound(
        SAME_SECRET_INTERNAL_MESSAGE_MASK_BITS,
        challenge,
        witness_infinity_bound,
        label,
    )
}

fn same_secret_randomness_response_bound(challenge: u64) -> CanonicalResult<i128> {
    same_secret_response_bound(
        SAME_SECRET_INTERNAL_RANDOMNESS_MASK_BITS,
        challenge,
        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        "same-secret opening-randomness response",
    )
}

fn same_secret_response_bound(
    mask_bits: usize,
    challenge: u64,
    witness_infinity_bound: i128,
    label: &str,
) -> CanonicalResult<i128> {
    let mask_bound = same_secret_mask_magnitude_bound(mask_bits, label)?;
    let challenge_term = i128::from(challenge)
        .checked_mul(witness_infinity_bound)
        .ok_or_else(|| invalid_same_secret_proof(format!("{label} bound overflowed")))?;
    mask_bound
        .checked_add(challenge_term)
        .ok_or_else(|| invalid_same_secret_proof(format!("{label} bound overflowed")))
}

fn same_secret_mask_magnitude_bound(mask_bits: usize, label: &str) -> CanonicalResult<i128> {
    let mask_bits = u32::try_from(mask_bits)
        .map_err(|_| invalid_same_secret_proof(format!("{label} mask bit count overflowed")))?;
    1_i128
        .checked_shl(mask_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_same_secret_proof(format!("{label} mask bound overflowed")))
}

fn same_secret_internal_relation_proof_size(
    expected_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<usize> {
    let Some(first_commitment) = expected_commitments.first() else {
        return Err(invalid_same_secret_proof(
            "same-secret proof expected commitments are empty",
        ));
    };
    let commitment_bytes =
        expected_commitments
            .iter()
            .try_fold(0_usize, |accumulator, commitment| {
                accumulator
                    .checked_add(setup_commitment_value_byte_count(commitment)?)
                    .ok_or_else(|| invalid_same_secret_proof("same-secret proof size overflowed"))
            })?;
    let ring_degree = first_commitment.ring_degree;
    let support_bytes = ring_degree
        .checked_mul(4)
        .and_then(|count| count.checked_mul(8))
        .ok_or_else(|| invalid_same_secret_proof("same-secret support proof size overflowed"))?;
    let secret_response_bytes = ring_degree
        .checked_mul(16)
        .ok_or_else(|| invalid_same_secret_proof("same-secret response size overflowed"))?;
    let negative_indicator_response_bytes = ring_degree.checked_mul(16).ok_or_else(|| {
        invalid_same_secret_proof("same-secret negative response size overflowed")
    })?;
    let randomness_response_bytes = expected_commitments
        .len()
        .checked_mul(SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .and_then(|count| count.checked_mul(ring_degree))
        .and_then(|count| count.checked_mul(16))
        .ok_or_else(|| {
            invalid_same_secret_proof("same-secret randomness response size overflowed")
        })?;

    SAME_SECRET_INTERNAL_PROOF_MAGIC
        .len()
        .checked_add(64)
        .and_then(|size| size.checked_add(8))
        .and_then(|size| size.checked_add(commitment_bytes))
        .and_then(|size| size.checked_add(support_bytes))
        .and_then(|size| size.checked_add(secret_response_bytes))
        .and_then(|size| size.checked_add(negative_indicator_response_bytes))
        .and_then(|size| size.checked_add(randomness_response_bytes))
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof size overflowed"))
}

fn setup_commitment_value_byte_count(commitment: &SetupCommitmentValue) -> CanonicalResult<usize> {
    commitment
        .limbs
        .iter()
        .try_fold(0_usize, |accumulator, limb| {
            let limb_count = limb.rows.iter().try_fold(0_usize, |row_accumulator, row| {
                row_accumulator.checked_add(row.len()).ok_or_else(|| {
                    invalid_same_secret_proof("same-secret commitment row size overflowed")
                })
            })?;
            accumulator
                .checked_add(limb_count.checked_mul(8).ok_or_else(|| {
                    invalid_same_secret_proof("same-secret commitment limb size overflowed")
                })?)
                .ok_or_else(|| invalid_same_secret_proof("same-secret commitment size overflowed"))
        })
}

#[cfg(test)]
fn signed_i128_residue_u128(value: i128, modulus: u64) -> CanonicalResult<u128> {
    Ok(u128::from(signed_i128_residue_u64(value, modulus)?))
}

fn signed_i128_residue_u64(value: i128, modulus: u64) -> CanonicalResult<u64> {
    let modulus_wide = i128::from(modulus);
    let mut residue = value % modulus_wide;
    if residue < 0 {
        residue = residue
            .checked_add(modulus_wide)
            .ok_or_else(|| invalid_same_secret_proof("signed residue overflowed"))?;
    }
    u64::try_from(residue).map_err(|_| invalid_same_secret_proof("signed residue does not fit u64"))
}

fn same_secret_lifted_message_response(
    secret_response: i128,
    negative_indicator_response: i128,
    source_message_modulus: u64,
) -> CanonicalResult<u128> {
    let lifted = secret_response
        .checked_add(
            i128::from(source_message_modulus)
                .checked_mul(negative_indicator_response)
                .ok_or_else(|| {
                    invalid_same_secret_proof(
                        "same-secret lifted response multiplication overflowed",
                    )
                })?,
        )
        .ok_or_else(|| invalid_same_secret_proof("same-secret lifted response overflowed"))?;
    if lifted < 0 {
        return Err(invalid_same_secret_proof(
            "same-secret lifted response became negative",
        ));
    }
    let lifted = u128::try_from(lifted)
        .map_err(|_| invalid_same_secret_proof("same-secret lifted response does not fit u128"))?;
    if lifted >= setup_commitment_modulus_product() {
        return Err(invalid_same_secret_proof(
            "same-secret lifted response wraps in the setup commitment modulus product",
        ));
    }

    Ok(lifted)
}

fn read_i128_vector(
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

fn read_u64(proof_bytes: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    let bytes = read_fixed::<8>(proof_bytes, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_fixed<const LENGTH: usize>(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; LENGTH]> {
    let end = cursor
        .checked_add(LENGTH)
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof cursor overflowed"))?;
    let bytes = proof_bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_same_secret_proof("same-secret proof ended early"))?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

fn invalid_same_secret_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
pub(super) struct SameSecretInternalProofWitness {
    pub(super) secret_coefficients: Vec<i64>,
    pub(super) opening_randomness_by_limb: Vec<Vec<Vec<i128>>>,
}

#[cfg(test)]
pub(super) fn generate_same_secret_internal_relation_proof_for_tests(
    public_matrix_seed_hash: &str,
    statement_record: &Value,
    constant_commitments: &[SetupCommitmentValue],
    setup_proof_binding: &Value,
    witness: &SameSecretInternalProofWitness,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    use super::commitment::compute_setup_commitment_for_tests;

    validate_same_secret_constant_commitments(constant_commitments)?;
    if witness.secret_coefficients.len() != constant_commitments[0].ring_degree
        || witness.opening_randomness_by_limb.len() != constant_commitments.len()
    {
        return Err(invalid_same_secret_proof(
            "same-secret proof witness shape does not match constant commitments",
        ));
    }
    let statement_hash = same_secret_internal_statement_hash(
        statement_record,
        constant_commitments,
        setup_proof_binding,
    )?;
    let secret_masks = (0..constant_commitments[0].ring_degree)
        .map(|coefficient_index| {
            sample_same_secret_message_mask_i128(
                &statement_hash,
                proof_randomness_seed_hex,
                0,
                coefficient_index,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_coefficients = witness
        .secret_coefficients
        .iter()
        .map(|coefficient| match *coefficient {
            -1 => Ok(1_i64),
            0 | 1 => Ok(0_i64),
            _ => Err(invalid_same_secret_proof(
                "same-secret witness coefficient must be ternary",
            )),
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_masks = (0..constant_commitments[0].ring_degree)
        .map(|coefficient_index| {
            sample_same_secret_message_mask_i128(
                &statement_hash,
                proof_randomness_seed_hex,
                1,
                coefficient_index,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_masks_by_limb = constant_commitments
        .iter()
        .enumerate()
        .map(|(limb_index, commitment)| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|randomness_column_index| {
                    (0..commitment.ring_degree)
                        .map(|coefficient_index| {
                            sample_same_secret_mask_i128(
                                &statement_hash,
                                proof_randomness_seed_hex,
                                limb_index + 2,
                                randomness_column_index,
                                coefficient_index,
                            )
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let relation_commitments = constant_commitments
        .iter()
        .zip(randomness_masks_by_limb.iter())
        .map(|(commitment, randomness_masks)| {
            let mask_message_coefficients = secret_masks
                .iter()
                .zip(negative_indicator_masks.iter())
                .map(|(secret_mask, negative_mask)| {
                    let lifted_mask = secret_mask
                        .checked_add(
                            i128::from(commitment.source_message_modulus)
                                .checked_mul(*negative_mask)
                                .ok_or_else(|| {
                                    invalid_same_secret_proof(
                                        "same-secret message mask multiplication overflowed",
                                    )
                                })?,
                        )
                        .ok_or_else(|| {
                            invalid_same_secret_proof("same-secret message mask overflowed")
                        })?;
                    if lifted_mask < 0 {
                        return Err(invalid_same_secret_proof(
                            "same-secret message mask must be non-negative",
                        ));
                    }
                    let lifted_mask = u128::try_from(lifted_mask).map_err(|_| {
                        invalid_same_secret_proof("same-secret message mask does not fit u128")
                    })?;
                    if lifted_mask >= setup_commitment_modulus_product() {
                        return Err(invalid_same_secret_proof(
                            "same-secret message mask wraps in the commitment modulus product",
                        ));
                    }
                    Ok(lifted_mask)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            compute_setup_commitment_for_tests(
                public_matrix_seed_hash,
                commitment.source_rns_limb_index,
                commitment.source_message_modulus,
                0,
                &mask_message_coefficients,
                randomness_masks,
                commitment.ring_degree,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let support_commitments = secret_masks
        .iter()
        .zip(negative_indicator_masks.iter())
        .zip(witness.secret_coefficients.iter())
        .zip(negative_indicator_coefficients.iter())
        .map(
            |(((secret_mask, negative_mask), secret), negative_indicator)| {
                same_secret_support_expansion(
                    *secret_mask,
                    *negative_mask,
                    *secret,
                    *negative_indicator,
                    DATA_PRIMES[0],
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;
    let encoded_commitments =
        encode_same_secret_relation_commitments(&relation_commitments, &support_commitments)?;
    let relation_commitment_hash =
        same_secret_internal_relation_commitment_hash(&statement_hash, &encoded_commitments);
    let challenge =
        same_secret_internal_relation_challenge(&statement_hash, &relation_commitment_hash)?;
    let challenge_wide = i128::from(challenge);
    let secret_response_coefficients =
        secret_masks
            .iter()
            .zip(witness.secret_coefficients.iter())
            .map(|(mask, secret)| {
                mask.checked_add(challenge_wide.checked_mul(i128::from(*secret)).ok_or_else(
                    || {
                        invalid_same_secret_proof(
                            "same-secret secret response multiplication overflowed",
                        )
                    },
                )?)
                .ok_or_else(|| invalid_same_secret_proof("same-secret secret response overflowed"))
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_response_coefficients = negative_indicator_masks
        .iter()
        .zip(negative_indicator_coefficients.iter())
        .map(|(mask, indicator)| {
            mask.checked_add(
                challenge_wide
                    .checked_mul(i128::from(*indicator))
                    .ok_or_else(|| {
                        invalid_same_secret_proof(
                            "same-secret negative response multiplication overflowed",
                        )
                    })?,
            )
            .ok_or_else(|| invalid_same_secret_proof("same-secret negative response overflowed"))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_response_by_limb = randomness_masks_by_limb
        .iter()
        .zip(witness.opening_randomness_by_limb.iter())
        .map(|(mask_columns, witness_columns)| {
            if mask_columns.len() != witness_columns.len() {
                return Err(invalid_same_secret_proof(
                    "same-secret randomness witness column count mismatch",
                ));
            }
            mask_columns
                .iter()
                .zip(witness_columns.iter())
                .map(|(mask_column, witness_column)| {
                    if mask_column.len() != witness_column.len() {
                        return Err(invalid_same_secret_proof(
                            "same-secret randomness witness coefficient count mismatch",
                        ));
                    }
                    mask_column
                        .iter()
                        .zip(witness_column.iter())
                        .map(|(mask, opening)| {
                            mask.checked_add(challenge_wide.checked_mul(*opening).ok_or_else(
                                || {
                                    invalid_same_secret_proof(
                                        "same-secret randomness response multiplication overflowed",
                                    )
                                },
                            )?)
                            .ok_or_else(|| {
                                invalid_same_secret_proof(
                                    "same-secret randomness response overflowed",
                                )
                            })
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let mut proof_bytes = Vec::with_capacity(same_secret_internal_relation_proof_size(
        constant_commitments,
    )?);
    proof_bytes.extend_from_slice(SAME_SECRET_INTERNAL_PROOF_MAGIC);
    proof_bytes.extend_from_slice(&statement_hash);
    proof_bytes.extend_from_slice(&challenge.to_le_bytes());
    proof_bytes.extend_from_slice(&encoded_commitments);
    for coefficient in &secret_response_coefficients {
        proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
    }
    for coefficient in &negative_indicator_response_coefficients {
        proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
    }
    for limb_columns in &randomness_response_by_limb {
        for column in limb_columns {
            for coefficient in column {
                proof_bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }

    Ok(proof_bytes)
}

#[cfg(test)]
fn sample_same_secret_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    vector_index: usize,
    column_index: usize,
    coefficient_index: usize,
) -> CanonicalResult<i128> {
    let vector_index_bytes = u64::try_from(vector_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask vector index overflowed"))?
        .to_le_bytes();
    let column_index_bytes = u64::try_from(column_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask column index overflowed"))?
        .to_le_bytes();
    let coefficient_index_bytes = u64::try_from(coefficient_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask coefficient index overflowed"))?
        .to_le_bytes();
    let block = hash512(
        "sealed-lattice/setup/same-secret/internal-relation-mask-v1",
        &[
            statement_hash,
            proof_randomness_seed_hex.as_bytes(),
            &vector_index_bytes,
            &column_index_bytes,
            &coefficient_index_bytes,
        ],
    );
    let magnitude_byte_count = SAME_SECRET_INTERNAL_RANDOMNESS_MASK_BITS.div_ceil(8);
    let mut magnitude_bytes = block[..magnitude_byte_count].to_vec();
    let excess_bits = magnitude_byte_count * 8 - SAME_SECRET_INTERNAL_RANDOMNESS_MASK_BITS;
    if excess_bits > 0 {
        let kept_bits = 8 - excess_bits;
        let mask = (1_u16 << kept_bits) - 1;
        if let Some(last_byte) = magnitude_bytes.last_mut() {
            *last_byte &= u8::try_from(mask).expect("mask fits u8");
        }
    }
    let mut full_bytes = [0_u8; 16];
    full_bytes[..magnitude_bytes.len()].copy_from_slice(&magnitude_bytes);
    let magnitude = i128::from_le_bytes(full_bytes);
    if block[magnitude_byte_count] & 1 == 1 {
        Ok(-magnitude)
    } else {
        Ok(magnitude)
    }
}

#[cfg(test)]
fn sample_same_secret_message_mask_i128(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    vector_index: usize,
    coefficient_index: usize,
) -> CanonicalResult<i128> {
    let vector_index_bytes = u64::try_from(vector_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask vector index overflowed"))?
        .to_le_bytes();
    let coefficient_index_bytes = u64::try_from(coefficient_index)
        .map_err(|_| invalid_same_secret_proof("same-secret mask coefficient index overflowed"))?
        .to_le_bytes();
    let block = hash512(
        "sealed-lattice/setup/same-secret/internal-relation-message-mask-v1",
        &[
            statement_hash,
            proof_randomness_seed_hex.as_bytes(),
            &vector_index_bytes,
            &coefficient_index_bytes,
        ],
    );
    let magnitude_byte_count = SAME_SECRET_INTERNAL_MESSAGE_MASK_BITS.div_ceil(8);
    let mut bytes = [0_u8; 16];
    bytes[..magnitude_byte_count].copy_from_slice(&block[..magnitude_byte_count]);
    let excess_bits = magnitude_byte_count * 8 - SAME_SECRET_INTERNAL_MESSAGE_MASK_BITS;
    if excess_bits > 0 {
        let kept_bits = 8 - excess_bits;
        let mask = (1_u16 << kept_bits) - 1;
        bytes[magnitude_byte_count - 1] &= u8::try_from(mask).expect("mask fits u8");
    }
    Ok(i128::from_le_bytes(bytes))
}

#[cfg(test)]
fn same_secret_support_expansion(
    secret_mask: i128,
    negative_indicator_mask: i128,
    secret: i64,
    negative_indicator: i64,
    modulus: u64,
) -> CanonicalResult<[u64; 4]> {
    if !matches!(secret, -1..=1) || !matches!(negative_indicator, 0..=1) {
        return Err(invalid_same_secret_proof(
            "same-secret witness support values are outside the expected set",
        ));
    }
    let shifted_value = secret
        .checked_add(negative_indicator)
        .ok_or_else(|| invalid_same_secret_proof("same-secret shifted witness overflowed"))?;
    if !matches!(shifted_value, 0..=1) {
        return Err(invalid_same_secret_proof(
            "same-secret shifted witness must be Boolean",
        ));
    }
    let negative_expansion =
        boolean_support_expansion(negative_indicator_mask, negative_indicator, modulus)?;
    let shifted_expansion = boolean_support_expansion(
        secret_mask
            .checked_add(negative_indicator_mask)
            .ok_or_else(|| invalid_same_secret_proof("same-secret shifted mask overflowed"))?,
        shifted_value,
        modulus,
    )?;
    Ok([
        negative_expansion[0],
        negative_expansion[1],
        shifted_expansion[0],
        shifted_expansion[1],
    ])
}

#[cfg(test)]
fn boolean_support_expansion(mask: i128, witness: i64, modulus: u64) -> CanonicalResult<[u64; 2]> {
    if !matches!(witness, 0..=1) {
        return Err(invalid_same_secret_proof(
            "same-secret Boolean support witness must be zero or one",
        ));
    }
    let mask_residue = signed_i128_residue_u64(mask, modulus)?;
    let witness_residue = signed_i128_residue_u64(i128::from(witness), modulus)?;
    let mask_square = mul_mod(mask_residue, mask_residue, modulus)?;
    Ok([
        mask_square,
        sub_mod(
            mul_mod(
                2 % modulus,
                mul_mod(mask_residue, witness_residue, modulus)?,
                modulus,
            )?,
            mask_residue,
            modulus,
        )?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::setup::commitment::{
        compute_setup_commitment_for_tests, setup_commitment_root,
    };
    use crate::hashing::derive_protocol_hash;

    #[test]
    fn same_secret_internal_relation_proof_verifies_shared_ternary_openings() {
        let public_matrix_seed_hash = "11".repeat(64);
        let ring_degree = 8;
        let secret_coefficients = vec![-1, 0, 1, -1, 1, 0, -1, 1];
        let (constant_commitments, opening_randomness_by_limb) = constant_commitments_for_test(
            &public_matrix_seed_hash,
            &secret_coefficients,
            ring_degree,
        );
        let statement_record = statement_record_for_test(&constant_commitments);
        let setup_proof_binding = setup_proof_binding_for_test();
        let witness = SameSecretInternalProofWitness {
            secret_coefficients: secret_coefficients.clone(),
            opening_randomness_by_limb,
        };
        let proof_bytes = generate_same_secret_internal_relation_proof_for_tests(
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &setup_proof_binding,
            &witness,
            &"22".repeat(64),
        )
        .expect("same-secret proof");

        let verification = verify_same_secret_internal_relation_proof(
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &setup_proof_binding,
            &proof_bytes,
        )
        .expect("same-secret proof should verify");

        assert_eq!(verification.proof_size_bytes, proof_bytes.len());
        assert_eq!(verification.statement_hash_hex.len(), 128);
        assert_eq!(verification.relation_commitment_hash_hex.len(), 128);
        assert_ne!(verification.challenge, 0);
        assert_eq!(
            same_secret_internal_relation_proof_bytes_hash(&proof_bytes).len(),
            128
        );
    }

    #[test]
    fn same_secret_internal_relation_proof_binds_setup_proof_profile() {
        let public_matrix_seed_hash = "77".repeat(64);
        let ring_degree = 8;
        let secret_coefficients = vec![-1, 0, 1, -1, 1, 0, -1, 1];
        let (constant_commitments, opening_randomness_by_limb) = constant_commitments_for_test(
            &public_matrix_seed_hash,
            &secret_coefficients,
            ring_degree,
        );
        let statement_record = statement_record_for_test(&constant_commitments);
        let setup_proof_binding = setup_proof_binding_for_test();
        let witness = SameSecretInternalProofWitness {
            secret_coefficients,
            opening_randomness_by_limb,
        };
        let proof_bytes = generate_same_secret_internal_relation_proof_for_tests(
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &setup_proof_binding,
            &witness,
            &"88".repeat(64),
        )
        .expect("same-secret proof");
        let mut drifted_setup_proof_binding = setup_proof_binding;
        drifted_setup_proof_binding["challengeDomainHash"] = json!("bb".repeat(64));

        let error = verify_same_secret_internal_relation_proof(
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &drifted_setup_proof_binding,
            &proof_bytes,
        )
        .expect_err("drifted setup-proof binding should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("statement"));
    }

    #[test]
    fn same_secret_internal_relation_proof_refuses_cross_limb_secret_drift() {
        let public_matrix_seed_hash = "33".repeat(64);
        let ring_degree = 8;
        let secret_coefficients = vec![-1, 0, 1, -1, 1, 0, -1, 1];
        let (mut constant_commitments, opening_randomness_by_limb) = constant_commitments_for_test(
            &public_matrix_seed_hash,
            &secret_coefficients,
            ring_degree,
        );
        let statement_record = statement_record_for_test(&constant_commitments);
        let setup_proof_binding = setup_proof_binding_for_test();
        let witness = SameSecretInternalProofWitness {
            secret_coefficients,
            opening_randomness_by_limb,
        };
        let proof_bytes = generate_same_secret_internal_relation_proof_for_tests(
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &setup_proof_binding,
            &witness,
            &"44".repeat(64),
        )
        .expect("same-secret proof");

        constant_commitments[1].limbs[0].rows[0][0] = (constant_commitments[1].limbs[0].rows[0][0]
            + 1)
            % constant_commitments[1].limbs[0].modulus;
        let error = verify_same_secret_internal_relation_proof(
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &setup_proof_binding,
            &proof_bytes,
        )
        .expect_err("tampered constant commitment should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("same-secret proof"));
    }

    #[test]
    fn same_secret_internal_relation_proof_refuses_tampered_support_response() {
        let public_matrix_seed_hash = "55".repeat(64);
        let ring_degree = 8;
        let secret_coefficients = vec![-1, 0, 1, -1, 1, 0, -1, 1];
        let (constant_commitments, opening_randomness_by_limb) = constant_commitments_for_test(
            &public_matrix_seed_hash,
            &secret_coefficients,
            ring_degree,
        );
        let statement_record = statement_record_for_test(&constant_commitments);
        let setup_proof_binding = setup_proof_binding_for_test();
        let witness = SameSecretInternalProofWitness {
            secret_coefficients,
            opening_randomness_by_limb,
        };
        let mut proof_bytes = generate_same_secret_internal_relation_proof_for_tests(
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &setup_proof_binding,
            &witness,
            &"66".repeat(64),
        )
        .expect("same-secret proof");
        let commitment_bytes = constant_commitments
            .iter()
            .map(setup_commitment_value_byte_count)
            .collect::<CanonicalResult<Vec<_>>>()
            .expect("commitment byte counts")
            .into_iter()
            .sum::<usize>();
        let support_offset = SAME_SECRET_INTERNAL_PROOF_MAGIC.len() + 64 + 8 + commitment_bytes;
        proof_bytes[support_offset] ^= 1;

        let error = verify_same_secret_internal_relation_proof(
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &setup_proof_binding,
            &proof_bytes,
        )
        .expect_err("tampered support commitment should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("challenge") || error.message.contains("support"));
    }

    #[test]
    fn same_secret_internal_relation_proof_refuses_unbounded_response_residue() {
        let challenge = same_secret_internal_challenge_maximum().expect("challenge maximum");
        let accepted_bound = same_secret_message_response_bound(
            challenge,
            SAME_SECRET_INTERNAL_TERNARY_INFINITY_BOUND,
            "test same-secret response",
        )
        .expect("same-secret response bound");
        let oversized_same_residue_response = accepted_bound
            .checked_add(i128::from(DATA_PRIMES[0]))
            .expect("oversized response");

        let error = verify_same_secret_response_bounds(
            challenge,
            &[oversized_same_residue_response],
            &[0],
            &[],
        )
        .expect_err("oversized response should fail before modular support checks");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("response bound"));
    }

    fn constant_commitments_for_test(
        public_matrix_seed_hash: &str,
        secret_coefficients: &[i64],
        ring_degree: usize,
    ) -> (Vec<SetupCommitmentValue>, Vec<Vec<Vec<i128>>>) {
        let opening_randomness_by_limb = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(rns_limb_index, _)| {
                (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                    .map(|randomness_column_index| {
                        (0..ring_degree)
                            .map(|coefficient_index| {
                                match (rns_limb_index + randomness_column_index + coefficient_index)
                                    % 3
                                {
                                    0 => -1,
                                    1 => 0,
                                    _ => 1,
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let constant_commitments = DATA_PRIMES
            .iter()
            .copied()
            .enumerate()
            .map(|(rns_limb_index, rns_prime)| {
                let message_coefficients = secret_coefficients
                    .iter()
                    .map(|coefficient| {
                        signed_i128_residue_u128(i128::from(*coefficient), rns_prime)
                            .expect("secret residue")
                    })
                    .collect::<Vec<_>>();
                compute_setup_commitment_for_tests(
                    public_matrix_seed_hash,
                    rns_limb_index,
                    rns_prime,
                    0,
                    &message_coefficients,
                    &opening_randomness_by_limb[rns_limb_index],
                    ring_degree,
                )
                .expect("constant commitment")
            })
            .collect::<Vec<_>>();

        (constant_commitments, opening_randomness_by_limb)
    }

    fn statement_record_for_test(constant_commitments: &[SetupCommitmentValue]) -> Value {
        let constant_roots = constant_commitments
            .iter()
            .enumerate()
            .map(|(rns_limb_index, commitment)| {
                json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": commitment.source_message_modulus,
                    "shamirCoefficientIndex": 0,
                    "commitmentRoot": setup_commitment_root(commitment).expect("commitment root"),
                })
            })
            .collect::<Vec<_>>();
        let mut statement = json!({
            "objectType": "SameSecretConsistencyStatement",
            "objectVersion": 1,
            "trusteeRosterPosition": 0,
            "trusteeSecretCommitmentRoot": "aa".repeat(64),
            "constantCoefficientCommitmentRoots": constant_roots,
        });
        statement["sameSecretStatementRoot"] = json!(
            derive_protocol_hash("SameSecretConsistencyRoot", &statement)
                .expect("same-secret statement root")
        );
        statement
    }

    fn setup_proof_binding_for_test() -> Value {
        json!({
            "objectType": "SetupProofRecordBinding",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "setupProofProfileHash": "cc".repeat(64),
            "proofSystem": "fixed-lnp-linear-relation-subset",
            "challengeDomain": "sealed-lattice/collective-bgv-setup/lnp-challenge-v1",
            "challengeDomainHash": "dd".repeat(64),
            "challengeBits": 128,
            "challengeCount": 1,
            "challengeCoefficientBound": 2,
            "challengeSpace": "fixed-lnp-small-coefficient-polynomial-challenge-set",
            "challengeSampler": "sealed-lattice-shake256-lazer-autostable-rejection-v1",
            "challengeSeedDomain": "sealed-lattice/collective-bgv-setup/lnp-challenge-seed-v1",
            "challengeStreamDomain": "sealed-lattice/collective-bgv-setup/lnp-challenge-stream-v1",
            "challengeDifferenceInvertibilityStatus": "review-required-before-claim-closure",
            "proofBytesDomain": "sealed-lattice/collective-bgv-setup/lnp-proof-bytes-v1",
            "proofSerialization": "binary",
            "proofBytesAcceptedStatus": "not-accepted-until-family-verifier-is-implemented",
        })
    }
}
