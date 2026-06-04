use std::mem::size_of;

use serde_json::{Value, json};

use super::{
    DIRECT_BALLOT_MAXIMUM_SCORE, DIRECT_BALLOT_OPTION_COUNT, DirectEncryptedBallot,
    setup_package_hash,
};
use crate::{
    bgv::{
        evaluator::engine::{
            DevelopmentBgvKey, encode_slots_to_coefficients, negacyclic_mul, signed_residue,
        },
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        profile::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, PROFILE_ID, profile_hash},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, hash512, hash512_hex, to_hex},
};

const DIRECT_BALLOT_RELATION_PROOF_MAGIC: &[u8; 8] = b"SLDBP001";
const DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS: usize = 4;
const DIRECT_BALLOT_SCORE_BUCKET_COUNT: usize = 10;
const DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS: usize = 2;
const DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS: usize = 3;
const DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS: usize = 5;
const DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS: u32 = 40;
const DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS: u32 = 62;
const DIRECT_BALLOT_RELATION_PROOF_GREEN_BYTES: usize = 5 * 1024 * 1024;
const DIRECT_BALLOT_RELATION_PROOF_YELLOW_BYTES: usize = 20 * 1024 * 1024;

pub(super) struct DirectBallotRelationProofGeneration {
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_size_bytes: usize,
    pub(super) proof_bytes_hash: String,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) challenge: u64,
    pub(super) relation_commitment_bytes: usize,
    pub(super) response_bytes: usize,
    pub(super) relation_commitment_polynomial_count: usize,
    pub(super) shared_response_polynomial_count: usize,
    pub(super) shared_response_scalar_count: usize,
    pub(super) proof_gate: &'static str,
}

#[derive(Debug)]
pub(super) struct DirectBallotRelationProofVerification {
    pub(super) proof_size_bytes: usize,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) challenge: u64,
}

#[derive(Clone)]
struct DirectBallotWitnessVector {
    randomizer_coefficients: Vec<i64>,
    error_zero_coefficients: Vec<i64>,
    error_one_coefficients: Vec<i64>,
    encoding_carry_coefficients: Vec<i64>,
    score_coefficients: Vec<i64>,
    one_hot_coefficients: Vec<Vec<i64>>,
}

struct DirectBallotBgvRelationCommitment {
    component_zero: Vec<u64>,
    component_one: Vec<u64>,
}

struct DirectBallotScoreLinearCommitment {
    bucket_sums: Vec<u64>,
    weighted_differences: Vec<u64>,
}

struct DirectBallotSupportCommitment {
    one_hot_booleanity: Vec<u64>,
    randomizer_support: Vec<u64>,
    error_zero_support: Vec<u64>,
    error_one_support: Vec<u64>,
}

struct ParsedDirectBallotRelationProof {
    challenge: u64,
    bgv_relation_commitments: Vec<DirectBallotBgvRelationCommitment>,
    score_linear_commitment: DirectBallotScoreLinearCommitment,
    support_commitment: DirectBallotSupportCommitment,
    response_vector: DirectBallotWitnessVector,
    relation_commitment_hash: [u8; 64],
}

pub(super) fn generate_direct_ballot_relation_proof(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotRelationProofGeneration> {
    let statement_hash =
        direct_ballot_relation_statement_hash(setup_package, evaluator_key, ballot)?;
    let witness_vector = direct_ballot_witness_vector(ballot)?;
    let mask_vector = sample_direct_ballot_relation_mask_vector(
        &statement_hash,
        &ballot.ciphertext_root,
        proof_randomness_seed_hex,
    )?;
    let bgv_relation_commitments =
        evaluate_direct_ballot_bgv_relation_commitments(evaluator_key, &mask_vector)?;
    let score_linear_commitment = evaluate_direct_ballot_score_linear_commitment(&mask_vector)?;
    let support_commitment =
        evaluate_direct_ballot_support_commitment(&mask_vector, &witness_vector)?;
    let encoded_commitments = encode_direct_ballot_relation_commitments(
        &bgv_relation_commitments,
        &score_linear_commitment,
        &support_commitment,
    )?;
    let relation_commitment_bytes = encoded_commitments.len();
    let relation_commitment_hash =
        direct_ballot_relation_commitment_hash(&statement_hash, &encoded_commitments);
    let challenge = direct_ballot_relation_challenge(&statement_hash, &relation_commitment_hash)?;
    let response_vector =
        direct_ballot_relation_response_vector(&mask_vector, &witness_vector, challenge)?;
    let proof_bytes = encode_direct_ballot_relation_proof(
        &statement_hash,
        challenge,
        &encoded_commitments,
        &response_vector,
    )?;
    let proof_size_bytes = proof_bytes.len();
    let proof_bytes_hash = hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/relation-proof-bytes-v1",
        &[&proof_bytes],
    );

    Ok(DirectBallotRelationProofGeneration {
        proof_bytes,
        proof_size_bytes,
        proof_bytes_hash,
        statement_hash_hex: to_hex(&statement_hash),
        relation_commitment_hash_hex: to_hex(&relation_commitment_hash),
        challenge,
        relation_commitment_bytes,
        response_bytes: direct_ballot_relation_response_bytes(),
        relation_commitment_polynomial_count: DATA_PRIMES.len() * 2,
        shared_response_polynomial_count: DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS,
        shared_response_scalar_count: direct_ballot_relation_response_scalar_count(),
        proof_gate: direct_ballot_relation_proof_gate(proof_size_bytes),
    })
}

pub(super) fn verify_direct_ballot_relation_proof(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
    proof_bytes: &[u8],
) -> CanonicalResult<DirectBallotRelationProofVerification> {
    let expected_statement_hash =
        direct_ballot_relation_statement_hash(setup_package, evaluator_key, ballot)?;
    let parsed_proof = parse_direct_ballot_relation_proof(proof_bytes, &expected_statement_hash)?;
    verify_direct_ballot_relation_response(
        evaluator_key,
        ballot,
        parsed_proof.challenge,
        &parsed_proof.bgv_relation_commitments,
        &parsed_proof.score_linear_commitment,
        &parsed_proof.support_commitment,
        &parsed_proof.response_vector,
    )?;

    Ok(DirectBallotRelationProofVerification {
        proof_size_bytes: proof_bytes.len(),
        statement_hash_hex: to_hex(&expected_statement_hash),
        relation_commitment_hash_hex: to_hex(&parsed_proof.relation_commitment_hash),
        challenge: parsed_proof.challenge,
    })
}

pub(super) fn direct_ballot_relation_proof_gate(proof_size_bytes: usize) -> &'static str {
    if proof_size_bytes <= DIRECT_BALLOT_RELATION_PROOF_GREEN_BYTES {
        "green: proof bytes are within the target size"
    } else if proof_size_bytes <= DIRECT_BALLOT_RELATION_PROOF_YELLOW_BYTES {
        "yellow: proof bytes are large but below the stop threshold"
    } else {
        "red: proof bytes exceed the stop threshold"
    }
}

pub(super) fn direct_ballot_relation_challenge_bits() -> u32 {
    DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS
}

pub(super) fn direct_ballot_relation_response_bytes() -> usize {
    (DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS * POLYNOMIAL_DEGREE
        + direct_ballot_relation_response_scalar_count())
        * size_of::<i64>()
}

pub(super) fn direct_ballot_relation_commitment_bytes() -> usize {
    (DATA_PRIMES.len() * 2 * POLYNOMIAL_DEGREE
        + direct_ballot_score_linear_commitment_scalar_count())
        * size_of::<u64>()
        + direct_ballot_support_commitment_bytes()
}

pub(super) fn direct_ballot_relation_response_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT + DIRECT_BALLOT_OPTION_COUNT * DIRECT_BALLOT_SCORE_BUCKET_COUNT
}

fn direct_ballot_score_linear_commitment_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT * 2
}

fn direct_ballot_support_commitment_bytes() -> usize {
    direct_ballot_support_commitment_scalar_count() * size_of::<u64>()
}

fn direct_ballot_support_commitment_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT
        * DIRECT_BALLOT_SCORE_BUCKET_COUNT
        * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS
        + POLYNOMIAL_DEGREE * DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS
        + 2 * POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS
}

fn direct_ballot_relation_statement_hash(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<[u8; 64]> {
    let public_key_hash = direct_ballot_public_key_hash(evaluator_key)?;
    let statement_json = canonical_json(&json!({
        "objectType": "DirectEncryptedBallotValidityRelationStatement",
        "objectVersion": 3,
        "setupPackageHash": setup_package_hash(setup_package)?,
        "profileId": PROFILE_ID,
        "profileHash": profile_hash()?,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "dataPrimeCount": DATA_PRIMES.len(),
        "publicKeyHash": to_hex(&public_key_hash),
        "ciphertextRoot": ballot.ciphertext_root.as_str(),
        "ciphertextCanonicalByteLength": ballot.ciphertext_canonical_byte_length,
        "voterIdentity": ballot.input.voter_identity.as_str(),
        "actionContextHash": ballot.input.action_context_hash.as_str(),
        "optionCount": DIRECT_BALLOT_OPTION_COUNT,
        "scoreRange": format!("1..={DIRECT_BALLOT_MAXIMUM_SCORE}"),
        "relation": "score and one-hot linear constraints, one-hot Booleanity, randomizer and error support, plus c0=b*u+p*encode(score)+p*e0 and c1=a*u+p*e1 for every BGV data prime"
    }))?;

    Ok(hash512(
        "sealed-lattice/direct-encrypted-ballot/relation-statement-v3",
        &[statement_json.as_bytes()],
    ))
}

fn direct_ballot_public_key_hash(evaluator_key: &DevelopmentBgvKey) -> CanonicalResult<[u8; 64]> {
    let (public_component_zero, public_component_one) = evaluator_key.public_key_components();
    if public_component_zero.len() != DATA_PRIMES.len()
        || public_component_one.len() != DATA_PRIMES.len()
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof requires a full BGV public key",
        ));
    }
    let mut encoded = Vec::with_capacity(DATA_PRIMES.len() * 2 * POLYNOMIAL_DEGREE * 8);
    append_u64(&mut encoded, DATA_PRIMES.len() as u64);
    for modulus in DATA_PRIMES {
        append_u64(&mut encoded, modulus);
    }
    encode_public_key_component(&mut encoded, public_component_zero, "component zero")?;
    encode_public_key_component(&mut encoded, public_component_one, "component one")?;

    Ok(hash512(
        "sealed-lattice/direct-encrypted-ballot/public-key-v1",
        &[&encoded],
    ))
}

fn encode_public_key_component(
    output: &mut Vec<u8>,
    component: &[Vec<u64>],
    label: &str,
) -> CanonicalResult<()> {
    for (limb_index, (limb, modulus)) in component.iter().zip(DATA_PRIMES.iter()).enumerate() {
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot relation proof public key {label} limb {limb_index} has the wrong degree"
            )));
        }
        for coefficient in limb {
            if *coefficient >= *modulus {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot relation proof public key {label} limb {limb_index} has a non-canonical coefficient"
                )));
            }
            append_u64(output, *coefficient);
        }
    }

    Ok(())
}

fn direct_ballot_witness_vector(
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<DirectBallotWitnessVector> {
    Ok(DirectBallotWitnessVector {
        randomizer_coefficients: ballot.encryption_witness.randomizer_coefficients.clone(),
        error_zero_coefficients: ballot.encryption_witness.error_zero_coefficients.clone(),
        error_one_coefficients: ballot.encryption_witness.error_one_coefficients.clone(),
        encoding_carry_coefficients: direct_ballot_encoding_carry_coefficients(ballot)?,
        score_coefficients: ballot
            .input
            .scores
            .iter()
            .map(|coefficient| {
                i64::try_from(*coefficient).map_err(|_| {
                    invalid_direct_ballot_relation_proof(
                        "direct ballot score coefficient does not fit in the proof response type",
                    )
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
        one_hot_coefficients: direct_ballot_one_hot_coefficients(ballot)?,
    })
}

fn direct_ballot_encoding_carry_coefficients(
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<Vec<i64>> {
    let score_encoding_basis = direct_ballot_score_encoding_basis()?;
    let mut carry_coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let mut raw_coefficient = 0_i128;
        for (score, basis_polynomial) in ballot.input.scores.iter().zip(score_encoding_basis.iter())
        {
            raw_coefficient += i128::from(*score) * i128::from(basis_polynomial[coefficient_index]);
        }
        let plaintext_coefficient = i128::from(ballot.plaintext_coefficients[coefficient_index]);
        let difference = raw_coefficient - plaintext_coefficient;
        let plaintext_modulus = i128::from(PLAINTEXT_MODULUS);
        if difference % plaintext_modulus != 0 {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot encoding carry does not match the batch-encoded score polynomial",
            ));
        }
        carry_coefficients.push(i64::try_from(difference / plaintext_modulus).map_err(|_| {
            invalid_direct_ballot_relation_proof(
                "direct ballot encoding carry coefficient does not fit in the proof response type",
            )
        })?);
    }

    Ok(carry_coefficients)
}

fn direct_ballot_one_hot_coefficients(
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<Vec<Vec<i64>>> {
    match &ballot.input.one_hot_witnesses {
        Some(rows) => rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|entry| {
                        i64::try_from(*entry).map_err(|_| {
                            invalid_direct_ballot_relation_proof(
                                "direct ballot one-hot entry does not fit in the proof response type",
                            )
                        })
                    })
                    .collect::<CanonicalResult<Vec<_>>>()
            })
            .collect(),
        None => ballot
            .input
            .scores
            .iter()
            .map(|score| {
                let selected_bucket = usize::try_from(score - 1).map_err(|_| {
                    invalid_direct_ballot_relation_proof(
                        "direct ballot score does not fit in a one-hot bucket index",
                    )
                })?;
                let mut row = vec![0_i64; DIRECT_BALLOT_SCORE_BUCKET_COUNT];
                if selected_bucket >= row.len() {
                    return Err(invalid_direct_ballot_relation_proof(
                        "direct ballot score is outside the one-hot bucket range",
                    ));
                }
                row[selected_bucket] = 1;
                Ok(row)
            })
            .collect(),
    }
}

fn sample_direct_ballot_relation_mask_vector(
    statement_hash: &[u8; 64],
    ciphertext_root: &str,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotWitnessVector> {
    Ok(DirectBallotWitnessVector {
        randomizer_coefficients: sample_direct_ballot_relation_mask_polynomial(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            0,
        )?,
        error_zero_coefficients: sample_direct_ballot_relation_mask_polynomial(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            1,
        )?,
        error_one_coefficients: sample_direct_ballot_relation_mask_polynomial(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            2,
        )?,
        encoding_carry_coefficients: sample_direct_ballot_relation_mask_polynomial(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            3,
        )?,
        score_coefficients: sample_direct_ballot_relation_mask_scalars(
            statement_hash,
            ciphertext_root,
            proof_randomness_seed_hex,
            4,
            DIRECT_BALLOT_OPTION_COUNT,
        )?,
        one_hot_coefficients: (0..DIRECT_BALLOT_OPTION_COUNT)
            .map(|option_index| {
                sample_direct_ballot_relation_mask_scalars(
                    statement_hash,
                    ciphertext_root,
                    proof_randomness_seed_hex,
                    5 + option_index,
                    DIRECT_BALLOT_SCORE_BUCKET_COUNT,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

fn sample_direct_ballot_relation_mask_scalars(
    statement_hash: &[u8; 64],
    ciphertext_root: &str,
    proof_randomness_seed_hex: &str,
    witness_vector_index: usize,
    scalar_count: usize,
) -> CanonicalResult<Vec<i64>> {
    let mut coefficients = Vec::with_capacity(scalar_count);
    let witness_vector_index_bytes = usize_to_u64_bytes(witness_vector_index)?;
    let coefficient_mask = (1_u64 << DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS) - 1;
    let mut block_index = 0_u64;
    while coefficients.len() < scalar_count {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            "sealed-lattice/direct-encrypted-ballot/relation-mask-scalar-v1",
            &[
                statement_hash,
                ciphertext_root.as_bytes(),
                proof_randomness_seed_hex.as_bytes(),
                &witness_vector_index_bytes,
                &block_index_bytes,
            ],
        );
        for chunk in block.chunks_exact(8) {
            let mut value_bytes = [0_u8; 8];
            value_bytes.copy_from_slice(chunk);
            let raw_value = u64::from_le_bytes(value_bytes);
            let magnitude = i64::try_from(raw_value & coefficient_mask).map_err(|_| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot relation scalar mask coefficient does not fit in i64",
                )
            })?;
            let coefficient =
                if (raw_value >> DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS) & 1 == 1 {
                    -magnitude
                } else {
                    magnitude
                };
            coefficients.push(coefficient);
            if coefficients.len() == scalar_count {
                break;
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot relation scalar mask block index overflowed",
            )
        })?;
    }

    Ok(coefficients)
}

fn direct_ballot_score_encoding_basis() -> CanonicalResult<Vec<Vec<u64>>> {
    (0..DIRECT_BALLOT_OPTION_COUNT)
        .map(|option_index| {
            let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
            slots[option_index] = 1;
            encode_slots_to_coefficients(&slots)
        })
        .collect()
}

fn sample_direct_ballot_relation_mask_polynomial(
    statement_hash: &[u8; 64],
    ciphertext_root: &str,
    proof_randomness_seed_hex: &str,
    witness_polynomial_index: usize,
) -> CanonicalResult<Vec<i64>> {
    let mut coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let witness_polynomial_index_bytes = usize_to_u64_bytes(witness_polynomial_index)?;
    let coefficient_mask = (1_u64 << DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS) - 1;
    let mut block_index = 0_u64;
    while coefficients.len() < POLYNOMIAL_DEGREE {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            "sealed-lattice/direct-encrypted-ballot/relation-mask-v1",
            &[
                statement_hash,
                ciphertext_root.as_bytes(),
                proof_randomness_seed_hex.as_bytes(),
                &witness_polynomial_index_bytes,
                &block_index_bytes,
            ],
        );
        for chunk in block.chunks_exact(8) {
            let mut value_bytes = [0_u8; 8];
            value_bytes.copy_from_slice(chunk);
            let raw_value = u64::from_le_bytes(value_bytes);
            let magnitude = i64::try_from(raw_value & coefficient_mask).map_err(|_| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot relation mask coefficient does not fit in i64",
                )
            })?;
            let coefficient =
                if (raw_value >> DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS) & 1 == 1 {
                    -magnitude
                } else {
                    magnitude
                };
            coefficients.push(coefficient);
            if coefficients.len() == POLYNOMIAL_DEGREE {
                break;
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot relation mask block index overflowed",
            )
        })?;
    }

    Ok(coefficients)
}

fn evaluate_direct_ballot_bgv_relation_commitments(
    evaluator_key: &DevelopmentBgvKey,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<Vec<DirectBallotBgvRelationCommitment>> {
    let (public_component_zero, public_component_one) = evaluator_key.public_key_components();
    if public_component_zero.len() != DATA_PRIMES.len()
        || public_component_one.len() != DATA_PRIMES.len()
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof requires a full BGV public key",
        ));
    }
    let score_encoding_basis = direct_ballot_score_encoding_basis()?;
    DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .map(|(limb_index, modulus)| {
            evaluate_direct_ballot_bgv_relation_commitment(
                &public_component_zero[limb_index],
                &public_component_one[limb_index],
                witness_vector,
                &score_encoding_basis,
                modulus,
            )
        })
        .collect()
}

fn evaluate_direct_ballot_bgv_relation_commitment(
    public_component_zero: &[u64],
    public_component_one: &[u64],
    witness_vector: &DirectBallotWitnessVector,
    score_encoding_basis: &[Vec<u64>],
    modulus: u64,
) -> CanonicalResult<DirectBallotBgvRelationCommitment> {
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    if public_component_zero.len() != POLYNOMIAL_DEGREE
        || public_component_one.len() != POLYNOMIAL_DEGREE
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof public key limbs must match the polynomial degree",
        ));
    }
    let randomizer_residues = signed_polynomial_residues(
        &witness_vector.randomizer_coefficients,
        modulus,
        "direct ballot relation randomizer",
    )?;
    let public_key_product = negacyclic_mul(public_component_zero, &randomizer_residues, modulus)?;
    let public_sample_product =
        negacyclic_mul(public_component_one, &randomizer_residues, modulus)?;
    let mut component_zero = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let mut component_one = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let scaled_error_zero = scaled_signed_residue(
            witness_vector.error_zero_coefficients[coefficient_index],
            PLAINTEXT_MODULUS,
            modulus,
        )?;
        let plaintext_residue = encoded_score_with_carry_residue(
            witness_vector,
            score_encoding_basis,
            coefficient_index,
            modulus,
        )?;
        component_zero.push(add_mod(
            add_mod(
                public_key_product[coefficient_index],
                scaled_error_zero,
                modulus,
            )?,
            plaintext_residue,
            modulus,
        )?);

        let scaled_error_one = scaled_signed_residue(
            witness_vector.error_one_coefficients[coefficient_index],
            PLAINTEXT_MODULUS,
            modulus,
        )?;
        component_one.push(add_mod(
            public_sample_product[coefficient_index],
            scaled_error_one,
            modulus,
        )?);
    }

    Ok(DirectBallotBgvRelationCommitment {
        component_zero,
        component_one,
    })
}

fn encoded_score_with_carry_residue(
    witness_vector: &DirectBallotWitnessVector,
    score_encoding_basis: &[Vec<u64>],
    coefficient_index: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    if score_encoding_basis.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot score encoding basis has the wrong option count",
        ));
    }
    let mut coefficient = -i128::from(PLAINTEXT_MODULUS)
        * i128::from(witness_vector.encoding_carry_coefficients[coefficient_index]);
    for (score, basis_polynomial) in witness_vector
        .score_coefficients
        .iter()
        .zip(score_encoding_basis.iter())
    {
        if basis_polynomial.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot score encoding basis has the wrong polynomial degree",
            ));
        }
        coefficient += i128::from(*score) * i128::from(basis_polynomial[coefficient_index]);
    }
    signed_i128_residue(coefficient, modulus)
}

fn verify_direct_ballot_relation_response(
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
    challenge: u64,
    bgv_relation_commitments: &[DirectBallotBgvRelationCommitment],
    score_linear_commitment: &DirectBallotScoreLinearCommitment,
    support_commitment: &DirectBallotSupportCommitment,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    if bgv_relation_commitments.len() != DATA_PRIMES.len()
        || ballot.ciphertext.components.len() != 2
        || ballot.ciphertext.components[0].len() != DATA_PRIMES.len()
        || ballot.ciphertext.components[1].len() != DATA_PRIMES.len()
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof verification requires a full ciphertext and commitment set",
        ));
    }
    let response_relation =
        evaluate_direct_ballot_bgv_relation_commitments(evaluator_key, response_vector)?;
    verify_direct_ballot_score_linear_response(
        challenge,
        score_linear_commitment,
        response_vector,
    )?;
    verify_direct_ballot_support_response(challenge, support_commitment, response_vector)?;
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        if bgv_relation_commitments[limb_index].component_zero.len() != POLYNOMIAL_DEGREE
            || bgv_relation_commitments[limb_index].component_one.len() != POLYNOMIAL_DEGREE
            || response_relation[limb_index].component_zero.len() != POLYNOMIAL_DEGREE
            || response_relation[limb_index].component_one.len() != POLYNOMIAL_DEGREE
        {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot relation proof limb vectors must match the polynomial degree",
            ));
        }
        let challenge_residue = challenge % modulus;
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            let scaled_ciphertext_zero = mul_mod(
                challenge_residue,
                ballot.ciphertext.components[0][limb_index][coefficient_index],
                modulus,
            )?;
            let checked_component_zero = sub_mod(
                response_relation[limb_index].component_zero[coefficient_index],
                scaled_ciphertext_zero,
                modulus,
            )?;
            if checked_component_zero
                != bgv_relation_commitments[limb_index].component_zero[coefficient_index]
            {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot relation proof limb {limb_index} c0 response does not match the public statement"
                )));
            }

            let scaled_ciphertext_one = mul_mod(
                challenge_residue,
                ballot.ciphertext.components[1][limb_index][coefficient_index],
                modulus,
            )?;
            let checked_component_one = sub_mod(
                response_relation[limb_index].component_one[coefficient_index],
                scaled_ciphertext_one,
                modulus,
            )?;
            if checked_component_one
                != bgv_relation_commitments[limb_index].component_one[coefficient_index]
            {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot relation proof limb {limb_index} c1 response does not match the public statement"
                )));
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum DirectBallotSupportKind {
    OneHot,
    Randomizer,
    Error,
}

fn evaluate_direct_ballot_score_linear_commitment(
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<DirectBallotScoreLinearCommitment> {
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    let mut bucket_sums = Vec::with_capacity(DIRECT_BALLOT_OPTION_COUNT);
    let mut weighted_differences = Vec::with_capacity(DIRECT_BALLOT_OPTION_COUNT);
    for option_index in 0..DIRECT_BALLOT_OPTION_COUNT {
        let mut bucket_sum = 0_u64;
        let mut weighted_sum = 0_u64;
        for bucket_index in 0..DIRECT_BALLOT_SCORE_BUCKET_COUNT {
            let bucket_residue = signed_residue(
                witness_vector.one_hot_coefficients[option_index][bucket_index],
                PLAINTEXT_MODULUS,
            );
            bucket_sum = add_mod(bucket_sum, bucket_residue, PLAINTEXT_MODULUS)?;
            let bucket_weight = u64::try_from(bucket_index + 1)
                .expect("score bucket weight fits u64")
                % PLAINTEXT_MODULUS;
            weighted_sum = add_mod(
                weighted_sum,
                mul_mod(bucket_weight, bucket_residue, PLAINTEXT_MODULUS)?,
                PLAINTEXT_MODULUS,
            )?;
        }
        let score_residue = signed_residue(
            witness_vector.score_coefficients[option_index],
            PLAINTEXT_MODULUS,
        );
        bucket_sums.push(bucket_sum);
        weighted_differences.push(sub_mod(score_residue, weighted_sum, PLAINTEXT_MODULUS)?);
    }

    Ok(DirectBallotScoreLinearCommitment {
        bucket_sums,
        weighted_differences,
    })
}

fn verify_direct_ballot_score_linear_response(
    challenge: u64,
    score_linear_commitment: &DirectBallotScoreLinearCommitment,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    let response_commitment = evaluate_direct_ballot_score_linear_commitment(response_vector)?;
    if score_linear_commitment.bucket_sums.len() != DIRECT_BALLOT_OPTION_COUNT
        || score_linear_commitment.weighted_differences.len() != DIRECT_BALLOT_OPTION_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot score linear commitment has the wrong option count",
        ));
    }
    let challenge_residue = challenge % PLAINTEXT_MODULUS;
    for option_index in 0..DIRECT_BALLOT_OPTION_COUNT {
        let checked_bucket_sum = sub_mod(
            response_commitment.bucket_sums[option_index],
            challenge_residue,
            PLAINTEXT_MODULUS,
        )?;
        if checked_bucket_sum != score_linear_commitment.bucket_sums[option_index] {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot score proof option {option_index} one-hot sum response does not match the public statement"
            )));
        }
        if response_commitment.weighted_differences[option_index]
            != score_linear_commitment.weighted_differences[option_index]
        {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot score proof option {option_index} weighted score response does not match the public statement"
            )));
        }
    }

    Ok(())
}

fn evaluate_direct_ballot_support_commitment(
    mask_vector: &DirectBallotWitnessVector,
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<DirectBallotSupportCommitment> {
    validate_direct_ballot_witness_vector_shape(mask_vector)?;
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    let modulus = direct_ballot_support_modulus();
    let mut one_hot_booleanity = Vec::with_capacity(
        DIRECT_BALLOT_OPTION_COUNT
            * DIRECT_BALLOT_SCORE_BUCKET_COUNT
            * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS,
    );
    for (mask_row, witness_row) in mask_vector
        .one_hot_coefficients
        .iter()
        .zip(witness_vector.one_hot_coefficients.iter())
    {
        for (mask, witness) in mask_row.iter().zip(witness_row.iter()) {
            one_hot_booleanity.extend(support_expansion_coefficients(
                DirectBallotSupportKind::OneHot,
                signed_residue(*mask, modulus),
                signed_residue(*witness, modulus),
                modulus,
            )?);
        }
    }

    Ok(DirectBallotSupportCommitment {
        one_hot_booleanity,
        randomizer_support: support_expansion_commitments_for_polynomial(
            DirectBallotSupportKind::Randomizer,
            &mask_vector.randomizer_coefficients,
            &witness_vector.randomizer_coefficients,
            modulus,
        )?,
        error_zero_support: support_expansion_commitments_for_polynomial(
            DirectBallotSupportKind::Error,
            &mask_vector.error_zero_coefficients,
            &witness_vector.error_zero_coefficients,
            modulus,
        )?,
        error_one_support: support_expansion_commitments_for_polynomial(
            DirectBallotSupportKind::Error,
            &mask_vector.error_one_coefficients,
            &witness_vector.error_one_coefficients,
            modulus,
        )?,
    })
}

fn support_expansion_commitments_for_polynomial(
    support_kind: DirectBallotSupportKind,
    mask_polynomial: &[i64],
    witness_polynomial: &[i64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if mask_polynomial.len() != POLYNOMIAL_DEGREE || witness_polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment polynomials must match the BGV degree",
        ));
    }
    let mut commitments =
        Vec::with_capacity(POLYNOMIAL_DEGREE * support_kind.expansion_coefficient_count());
    for (mask, witness) in mask_polynomial.iter().zip(witness_polynomial.iter()) {
        commitments.extend(support_expansion_coefficients(
            support_kind,
            signed_residue(*mask, modulus),
            signed_residue(*witness, modulus),
            modulus,
        )?);
    }

    Ok(commitments)
}

fn verify_direct_ballot_support_response(
    challenge: u64,
    support_commitment: &DirectBallotSupportCommitment,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    validate_direct_ballot_witness_vector_shape(response_vector)?;
    validate_direct_ballot_support_commitment_shape(support_commitment)?;
    let modulus = direct_ballot_support_modulus();
    let challenge_residue = challenge % modulus;
    for (option_index, row) in response_vector.one_hot_coefficients.iter().enumerate() {
        let commitment_offset = option_index
            .checked_mul(DIRECT_BALLOT_SCORE_BUCKET_COUNT)
            .and_then(|offset| {
                offset.checked_mul(DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS)
            })
            .ok_or_else(|| {
                invalid_direct_ballot_relation_proof(
                    "direct ballot one-hot support commitment offset overflowed",
                )
            })?;
        verify_support_response_polynomial(
            &format!("one-hot Booleanity option {option_index}"),
            DirectBallotSupportKind::OneHot,
            row,
            &support_commitment.one_hot_booleanity[commitment_offset
                ..commitment_offset
                    + DIRECT_BALLOT_SCORE_BUCKET_COUNT
                        * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS],
            challenge_residue,
            modulus,
        )?;
    }
    verify_support_response_polynomial(
        "randomizer",
        DirectBallotSupportKind::Randomizer,
        &response_vector.randomizer_coefficients,
        &support_commitment.randomizer_support,
        challenge_residue,
        modulus,
    )?;
    verify_support_response_polynomial(
        "first error",
        DirectBallotSupportKind::Error,
        &response_vector.error_zero_coefficients,
        &support_commitment.error_zero_support,
        challenge_residue,
        modulus,
    )?;
    verify_support_response_polynomial(
        "second error",
        DirectBallotSupportKind::Error,
        &response_vector.error_one_coefficients,
        &support_commitment.error_one_support,
        challenge_residue,
        modulus,
    )
}

fn verify_support_response_polynomial(
    label: &str,
    support_kind: DirectBallotSupportKind,
    response_coefficients: &[i64],
    expansion_commitments: &[u64],
    challenge_residue: u64,
    modulus: u64,
) -> CanonicalResult<()> {
    let expansion_coefficient_count = support_kind.expansion_coefficient_count();
    if expansion_commitments.len() != response_coefficients.len() * expansion_coefficient_count {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot {label} commitment has the wrong length"
        )));
    }
    for (coefficient_index, (response, expansion)) in response_coefficients
        .iter()
        .zip(expansion_commitments.chunks_exact(expansion_coefficient_count))
        .enumerate()
    {
        let response_residue = signed_residue(*response, modulus);
        let support_value =
            support_polynomial_value(support_kind, response_residue, challenge_residue, modulus)?;
        let mut expanded_support_value = 0_u64;
        let mut challenge_power = 1_u64;
        for commitment in expansion {
            expanded_support_value = add_mod(
                expanded_support_value,
                mul_mod(*commitment, challenge_power, modulus)?,
                modulus,
            )?;
            challenge_power = mul_mod(challenge_power, challenge_residue, modulus)?;
        }
        if support_value != expanded_support_value {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot {label} support check failed at coefficient {coefficient_index}"
            )));
        }
    }

    Ok(())
}

fn support_expansion_coefficients(
    support_kind: DirectBallotSupportKind,
    mask: u64,
    witness: u64,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mask_power = powers(mask, 5, modulus)?;
    let witness_power = powers(witness, 5, modulus)?;
    match support_kind {
        DirectBallotSupportKind::OneHot => Ok(vec![
            mask_power[2],
            sub_mod(
                mul_mod(2 % modulus, mul_mod(mask, witness, modulus)?, modulus)?,
                mask,
                modulus,
            )?,
        ]),
        DirectBallotSupportKind::Randomizer => Ok(vec![
            mask_power[3],
            mul_mod(
                3 % modulus,
                mul_mod(mask_power[2], witness, modulus)?,
                modulus,
            )?,
            sub_mod(
                mul_mod(
                    3 % modulus,
                    mul_mod(mask, witness_power[2], modulus)?,
                    modulus,
                )?,
                mask,
                modulus,
            )?,
        ]),
        DirectBallotSupportKind::Error => Ok(vec![
            mask_power[5],
            mul_mod(
                5 % modulus,
                mul_mod(mask_power[4], witness, modulus)?,
                modulus,
            )?,
            sub_mod(
                mul_mod(
                    10 % modulus,
                    mul_mod(mask_power[3], witness_power[2], modulus)?,
                    modulus,
                )?,
                mul_mod(5 % modulus, mask_power[3], modulus)?,
                modulus,
            )?,
            sub_mod(
                mul_mod(
                    10 % modulus,
                    mul_mod(mask_power[2], witness_power[3], modulus)?,
                    modulus,
                )?,
                mul_mod(
                    15 % modulus,
                    mul_mod(mask_power[2], witness, modulus)?,
                    modulus,
                )?,
                modulus,
            )?,
            add_mod(
                sub_mod(
                    mul_mod(
                        5 % modulus,
                        mul_mod(mask, witness_power[4], modulus)?,
                        modulus,
                    )?,
                    mul_mod(
                        15 % modulus,
                        mul_mod(mask, witness_power[2], modulus)?,
                        modulus,
                    )?,
                    modulus,
                )?,
                mul_mod(4 % modulus, mask, modulus)?,
                modulus,
            )?,
        ]),
    }
}

fn support_polynomial_value(
    support_kind: DirectBallotSupportKind,
    value: u64,
    homogenizing_value: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    let value_power = powers(value, 5, modulus)?;
    let homogenizing_power = powers(homogenizing_value, 5, modulus)?;
    match support_kind {
        DirectBallotSupportKind::OneHot => sub_mod(
            value_power[2],
            mul_mod(value, homogenizing_value, modulus)?,
            modulus,
        ),
        DirectBallotSupportKind::Randomizer => sub_mod(
            value_power[3],
            mul_mod(value, homogenizing_power[2], modulus)?,
            modulus,
        ),
        DirectBallotSupportKind::Error => add_mod(
            sub_mod(
                value_power[5],
                mul_mod(
                    mul_mod(5 % modulus, value_power[3], modulus)?,
                    homogenizing_power[2],
                    modulus,
                )?,
                modulus,
            )?,
            mul_mod(
                mul_mod(4 % modulus, value, modulus)?,
                homogenizing_power[4],
                modulus,
            )?,
            modulus,
        ),
    }
}

fn powers(value: u64, highest_power: usize, modulus: u64) -> CanonicalResult<Vec<u64>> {
    let mut powers = vec![1_u64; highest_power + 1];
    for power_index in 1..=highest_power {
        powers[power_index] = mul_mod(powers[power_index - 1], value, modulus)?;
    }

    Ok(powers)
}

impl DirectBallotSupportKind {
    fn expansion_coefficient_count(self) -> usize {
        match self {
            Self::OneHot => DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS,
            Self::Randomizer => DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS,
            Self::Error => DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        }
    }
}

fn direct_ballot_support_modulus() -> u64 {
    DATA_PRIMES[0]
}

fn direct_ballot_relation_response_vector(
    mask_vector: &DirectBallotWitnessVector,
    witness_vector: &DirectBallotWitnessVector,
    challenge: u64,
) -> CanonicalResult<DirectBallotWitnessVector> {
    validate_direct_ballot_witness_vector_shape(mask_vector)?;
    validate_direct_ballot_witness_vector_shape(witness_vector)?;
    Ok(DirectBallotWitnessVector {
        randomizer_coefficients: response_polynomial(
            &mask_vector.randomizer_coefficients,
            &witness_vector.randomizer_coefficients,
            challenge,
            "direct ballot relation randomizer response",
        )?,
        error_zero_coefficients: response_polynomial(
            &mask_vector.error_zero_coefficients,
            &witness_vector.error_zero_coefficients,
            challenge,
            "direct ballot relation first error response",
        )?,
        error_one_coefficients: response_polynomial(
            &mask_vector.error_one_coefficients,
            &witness_vector.error_one_coefficients,
            challenge,
            "direct ballot relation second error response",
        )?,
        encoding_carry_coefficients: response_polynomial(
            &mask_vector.encoding_carry_coefficients,
            &witness_vector.encoding_carry_coefficients,
            challenge,
            "direct ballot relation encoding carry response",
        )?,
        score_coefficients: response_polynomial(
            &mask_vector.score_coefficients,
            &witness_vector.score_coefficients,
            challenge,
            "direct ballot relation score response",
        )?,
        one_hot_coefficients: mask_vector
            .one_hot_coefficients
            .iter()
            .zip(witness_vector.one_hot_coefficients.iter())
            .enumerate()
            .map(|(option_index, (mask_row, witness_row))| {
                response_polynomial(
                    mask_row,
                    witness_row,
                    challenge,
                    &format!("direct ballot relation option {option_index} one-hot response"),
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

fn response_polynomial(
    mask_polynomial: &[i64],
    witness_polynomial: &[i64],
    challenge: u64,
    label: &str,
) -> CanonicalResult<Vec<i64>> {
    if mask_polynomial.len() != witness_polynomial.len() {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} mask and witness lengths must match"
        )));
    }
    if mask_polynomial.is_empty() {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} must not be empty"
        )));
    }
    mask_polynomial
        .iter()
        .zip(witness_polynomial.iter())
        .map(|(mask_coefficient, witness_coefficient)| {
            let response = i128::from(*mask_coefficient)
                + i128::from(challenge) * i128::from(*witness_coefficient);
            i64::try_from(response).map_err(|_| {
                invalid_direct_ballot_relation_proof(format!("{label} does not fit in i64"))
            })
        })
        .collect()
}

fn direct_ballot_relation_challenge(
    statement_hash: &[u8; 64],
    relation_commitment_hash: &[u8; 64],
) -> CanonicalResult<u64> {
    let challenge_mask = (1_u64 << DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS) - 1;
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
            &[statement_hash, relation_commitment_hash, &block_index_bytes],
        );
        for chunk in block.chunks_exact(8) {
            let mut value_bytes = [0_u8; 8];
            value_bytes.copy_from_slice(chunk);
            let challenge = u64::from_le_bytes(value_bytes) & challenge_mask;
            if challenge != 0 {
                return Ok(challenge);
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_direct_ballot_relation_proof(
                "direct ballot relation challenge block index overflowed",
            )
        })?;
    }
}

fn parse_direct_ballot_relation_proof(
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
) -> CanonicalResult<ParsedDirectBallotRelationProof> {
    let expected_size = DIRECT_BALLOT_RELATION_PROOF_MAGIC.len()
        + expected_statement_hash.len()
        + size_of::<u64>()
        + direct_ballot_relation_commitment_bytes()
        + direct_ballot_relation_response_bytes();
    if proof_bytes.len() != expected_size {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof bytes do not match the expected size",
        ));
    }
    let mut cursor = 0_usize;
    if &proof_bytes[..DIRECT_BALLOT_RELATION_PROOF_MAGIC.len()]
        != DIRECT_BALLOT_RELATION_PROOF_MAGIC
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof has the wrong format marker",
        ));
    }
    cursor += DIRECT_BALLOT_RELATION_PROOF_MAGIC.len();
    let statement_hash = read_hash(proof_bytes, &mut cursor)?;
    if &statement_hash != expected_statement_hash {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof is not bound to this statement",
        ));
    }
    let challenge = read_u64(proof_bytes, &mut cursor)?;
    if challenge == 0 || challenge >= (1_u64 << DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS) {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof challenge is outside the expected range",
        ));
    }
    let (bgv_relation_commitments, score_linear_commitment, support_commitment) =
        read_direct_ballot_relation_commitments(proof_bytes, &mut cursor)?;
    let encoded_commitments = encode_direct_ballot_relation_commitments(
        &bgv_relation_commitments,
        &score_linear_commitment,
        &support_commitment,
    )?;
    let relation_commitment_hash =
        direct_ballot_relation_commitment_hash(expected_statement_hash, &encoded_commitments);
    let recomputed_challenge =
        direct_ballot_relation_challenge(expected_statement_hash, &relation_commitment_hash)?;
    if challenge != recomputed_challenge {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof challenge does not match its commitment",
        ));
    }
    let response_vector = read_direct_ballot_relation_response(proof_bytes, &mut cursor)?;
    if cursor != proof_bytes.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof has trailing bytes",
        ));
    }

    Ok(ParsedDirectBallotRelationProof {
        challenge,
        bgv_relation_commitments,
        score_linear_commitment,
        support_commitment,
        response_vector,
        relation_commitment_hash,
    })
}

fn encode_direct_ballot_relation_proof(
    statement_hash: &[u8; 64],
    challenge: u64,
    encoded_commitments: &[u8],
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<Vec<u8>> {
    let mut proof_bytes = Vec::with_capacity(
        DIRECT_BALLOT_RELATION_PROOF_MAGIC.len()
            + statement_hash.len()
            + size_of::<u64>()
            + encoded_commitments.len()
            + direct_ballot_relation_response_bytes(),
    );
    proof_bytes.extend_from_slice(DIRECT_BALLOT_RELATION_PROOF_MAGIC);
    proof_bytes.extend_from_slice(statement_hash);
    append_u64(&mut proof_bytes, challenge);
    proof_bytes.extend_from_slice(encoded_commitments);
    encode_direct_ballot_relation_response(&mut proof_bytes, response_vector)?;

    Ok(proof_bytes)
}

fn encode_direct_ballot_relation_commitments(
    bgv_relation_commitments: &[DirectBallotBgvRelationCommitment],
    score_linear_commitment: &DirectBallotScoreLinearCommitment,
    support_commitment: &DirectBallotSupportCommitment,
) -> CanonicalResult<Vec<u8>> {
    if bgv_relation_commitments.len() != DATA_PRIMES.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof commitment count must match the data-prime count",
        ));
    }
    let mut encoded = Vec::with_capacity(direct_ballot_relation_commitment_bytes());
    for (limb_index, (commitment, modulus)) in bgv_relation_commitments
        .iter()
        .zip(DATA_PRIMES.iter())
        .enumerate()
    {
        encode_residue_polynomial(
            &mut encoded,
            &commitment.component_zero,
            *modulus,
            limb_index,
            "c0",
        )?;
        encode_residue_polynomial(
            &mut encoded,
            &commitment.component_one,
            *modulus,
            limb_index,
            "c1",
        )?;
    }
    encode_score_linear_commitment(&mut encoded, score_linear_commitment)?;
    encode_support_commitment(&mut encoded, support_commitment)?;

    Ok(encoded)
}

fn encode_score_linear_commitment(
    output: &mut Vec<u8>,
    commitment: &DirectBallotScoreLinearCommitment,
) -> CanonicalResult<()> {
    if commitment.bucket_sums.len() != DIRECT_BALLOT_OPTION_COUNT
        || commitment.weighted_differences.len() != DIRECT_BALLOT_OPTION_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot score linear commitment has the wrong option count",
        ));
    }
    for value in commitment
        .bucket_sums
        .iter()
        .chain(commitment.weighted_differences.iter())
    {
        if *value >= PLAINTEXT_MODULUS {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot score linear commitment is not canonical",
            ));
        }
        append_u64(output, *value);
    }

    Ok(())
}

fn encode_support_commitment(
    output: &mut Vec<u8>,
    commitment: &DirectBallotSupportCommitment,
) -> CanonicalResult<()> {
    validate_direct_ballot_support_commitment_shape(commitment)?;
    for value in commitment
        .one_hot_booleanity
        .iter()
        .chain(commitment.randomizer_support.iter())
        .chain(commitment.error_zero_support.iter())
        .chain(commitment.error_one_support.iter())
    {
        append_u64(output, *value);
    }

    Ok(())
}

fn encode_residue_polynomial(
    output: &mut Vec<u8>,
    polynomial: &[u64],
    modulus: u64,
    limb_index: usize,
    component_label: &str,
) -> CanonicalResult<()> {
    if polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "direct ballot relation proof commitment limb {limb_index} {component_label} has the wrong degree"
        )));
    }
    for coefficient in polynomial {
        if *coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot relation proof commitment limb {limb_index} {component_label} has a non-canonical coefficient"
            )));
        }
        append_u64(output, *coefficient);
    }

    Ok(())
}

fn read_direct_ballot_relation_commitments(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<(
    Vec<DirectBallotBgvRelationCommitment>,
    DirectBallotScoreLinearCommitment,
    DirectBallotSupportCommitment,
)> {
    let bgv_commitments = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            Ok(DirectBallotBgvRelationCommitment {
                component_zero: read_residue_polynomial(proof_bytes, cursor, modulus)?,
                component_one: read_residue_polynomial(proof_bytes, cursor, modulus)?,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let score_linear_commitment = read_score_linear_commitment(proof_bytes, cursor)?;
    let support_commitment = read_support_commitment(proof_bytes, cursor)?;

    Ok((bgv_commitments, score_linear_commitment, support_commitment))
}

fn read_score_linear_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<DirectBallotScoreLinearCommitment> {
    let bucket_sums = read_residue_scalars(
        proof_bytes,
        cursor,
        PLAINTEXT_MODULUS,
        DIRECT_BALLOT_OPTION_COUNT,
    )?;
    let weighted_differences = read_residue_scalars(
        proof_bytes,
        cursor,
        PLAINTEXT_MODULUS,
        DIRECT_BALLOT_OPTION_COUNT,
    )?;

    Ok(DirectBallotScoreLinearCommitment {
        bucket_sums,
        weighted_differences,
    })
}

fn read_support_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<DirectBallotSupportCommitment> {
    let modulus = direct_ballot_support_modulus();
    Ok(DirectBallotSupportCommitment {
        one_hot_booleanity: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            DIRECT_BALLOT_OPTION_COUNT
                * DIRECT_BALLOT_SCORE_BUCKET_COUNT
                * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
        randomizer_support: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            POLYNOMIAL_DEGREE * DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
        error_zero_support: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
        error_one_support: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
    })
}

fn read_residue_scalars(
    proof_bytes: &[u8],
    cursor: &mut usize,
    modulus: u64,
    scalar_count: usize,
) -> CanonicalResult<Vec<u64>> {
    let mut scalars = Vec::with_capacity(scalar_count);
    for _ in 0..scalar_count {
        let scalar = read_u64(proof_bytes, cursor)?;
        if scalar >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot relation proof scalar commitment is not canonical",
            ));
        }
        scalars.push(scalar);
    }

    Ok(scalars)
}

fn read_residue_polynomial(
    proof_bytes: &[u8],
    cursor: &mut usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut polynomial = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for _ in 0..POLYNOMIAL_DEGREE {
        let coefficient = read_u64(proof_bytes, cursor)?;
        if coefficient >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot relation proof commitment coefficient is not canonical",
            ));
        }
        polynomial.push(coefficient);
    }

    Ok(polynomial)
}

fn encode_direct_ballot_relation_response(
    output: &mut Vec<u8>,
    response_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    validate_direct_ballot_witness_vector_shape(response_vector)?;
    for polynomial in direct_ballot_witness_polynomials(response_vector) {
        for coefficient in polynomial {
            append_i64(output, *coefficient);
        }
    }
    for coefficient in &response_vector.score_coefficients {
        append_i64(output, *coefficient);
    }
    for row in &response_vector.one_hot_coefficients {
        for coefficient in row {
            append_i64(output, *coefficient);
        }
    }

    Ok(())
}

fn read_direct_ballot_relation_response(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<DirectBallotWitnessVector> {
    Ok(DirectBallotWitnessVector {
        randomizer_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        error_zero_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        error_one_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        encoding_carry_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        score_coefficients: read_signed_scalars(proof_bytes, cursor, DIRECT_BALLOT_OPTION_COUNT)?,
        one_hot_coefficients: (0..DIRECT_BALLOT_OPTION_COUNT)
            .map(|_| read_signed_scalars(proof_bytes, cursor, DIRECT_BALLOT_SCORE_BUCKET_COUNT))
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

fn read_signed_polynomial(proof_bytes: &[u8], cursor: &mut usize) -> CanonicalResult<Vec<i64>> {
    let mut polynomial = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for _ in 0..POLYNOMIAL_DEGREE {
        polynomial.push(read_i64(proof_bytes, cursor)?);
    }

    Ok(polynomial)
}

fn read_signed_scalars(
    proof_bytes: &[u8],
    cursor: &mut usize,
    scalar_count: usize,
) -> CanonicalResult<Vec<i64>> {
    let mut scalars = Vec::with_capacity(scalar_count);
    for _ in 0..scalar_count {
        scalars.push(read_i64(proof_bytes, cursor)?);
    }

    Ok(scalars)
}

fn direct_ballot_relation_commitment_hash(
    statement_hash: &[u8; 64],
    encoded_commitments: &[u8],
) -> [u8; 64] {
    hash512(
        "sealed-lattice/direct-encrypted-ballot/relation-commitment-v1",
        &[statement_hash, encoded_commitments],
    )
}

fn validate_direct_ballot_witness_vector_shape(
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    for (label, polynomial) in [
        (
            "direct ballot relation randomizer",
            witness_vector.randomizer_coefficients.as_slice(),
        ),
        (
            "direct ballot relation first error polynomial",
            witness_vector.error_zero_coefficients.as_slice(),
        ),
        (
            "direct ballot relation second error polynomial",
            witness_vector.error_one_coefficients.as_slice(),
        ),
        (
            "direct ballot relation encoding carry polynomial",
            witness_vector.encoding_carry_coefficients.as_slice(),
        ),
    ] {
        if polynomial.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "{label} must match the polynomial degree"
            )));
        }
    }
    if witness_vector.score_coefficients.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation score response must have one scalar per option",
        ));
    }
    if witness_vector.one_hot_coefficients.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation one-hot response must have one row per option",
        ));
    }
    for (option_index, row) in witness_vector.one_hot_coefficients.iter().enumerate() {
        if row.len() != DIRECT_BALLOT_SCORE_BUCKET_COUNT {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot relation one-hot response row {option_index} must have one scalar per score bucket"
            )));
        }
    }

    Ok(())
}

fn validate_direct_ballot_support_commitment_shape(
    commitment: &DirectBallotSupportCommitment,
) -> CanonicalResult<()> {
    let expected_one_hot_scalars = DIRECT_BALLOT_OPTION_COUNT
        * DIRECT_BALLOT_SCORE_BUCKET_COUNT
        * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS;
    let expected_randomizer_scalars =
        POLYNOMIAL_DEGREE * DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS;
    let expected_error_scalars =
        POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS;
    if commitment.one_hot_booleanity.len() != expected_one_hot_scalars
        || commitment.randomizer_support.len() != expected_randomizer_scalars
        || commitment.error_zero_support.len() != expected_error_scalars
        || commitment.error_one_support.len() != expected_error_scalars
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment has the wrong shape",
        ));
    }
    let modulus = direct_ballot_support_modulus();
    if commitment
        .one_hot_booleanity
        .iter()
        .chain(commitment.randomizer_support.iter())
        .chain(commitment.error_zero_support.iter())
        .chain(commitment.error_one_support.iter())
        .any(|coefficient| *coefficient >= modulus)
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot support commitment is not canonical",
        ));
    }

    Ok(())
}

fn direct_ballot_witness_polynomials(
    witness_vector: &DirectBallotWitnessVector,
) -> [&[i64]; DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS] {
    [
        witness_vector.randomizer_coefficients.as_slice(),
        witness_vector.error_zero_coefficients.as_slice(),
        witness_vector.error_one_coefficients.as_slice(),
        witness_vector.encoding_carry_coefficients.as_slice(),
    ]
}

fn signed_polynomial_residues(
    polynomial: &[i64],
    modulus: u64,
    label: &str,
) -> CanonicalResult<Vec<u64>> {
    if polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_relation_proof(format!(
            "{label} must match the polynomial degree"
        )));
    }
    Ok(polynomial
        .iter()
        .map(|coefficient| signed_residue(*coefficient, modulus))
        .collect())
}

fn scaled_signed_residue(coefficient: i64, scalar: u64, modulus: u64) -> CanonicalResult<u64> {
    mul_mod(
        signed_residue(coefficient, modulus),
        scalar % modulus,
        modulus,
    )
}

fn signed_i128_residue(coefficient: i128, modulus: u64) -> CanonicalResult<u64> {
    let modulus = i128::from(modulus);
    let residue = coefficient.rem_euclid(modulus);
    u64::try_from(residue).map_err(|_| {
        invalid_direct_ballot_relation_proof(
            "direct ballot signed residue does not fit in the modulus type",
        )
    })
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn append_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_hash(input: &[u8], cursor: &mut usize) -> CanonicalResult<[u8; 64]> {
    let end = cursor.checked_add(64).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof cursor overflowed")
    })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof ended early")
    })?;
    let mut hash = [0_u8; 64];
    hash.copy_from_slice(bytes);
    *cursor = end;
    Ok(hash)
}

fn read_u64(input: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    let bytes = read_fixed_bytes::<8>(input, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_i64(input: &[u8], cursor: &mut usize) -> CanonicalResult<i64> {
    let bytes = read_fixed_bytes::<8>(input, cursor)?;
    Ok(i64::from_le_bytes(bytes))
}

fn read_fixed_bytes<const LENGTH: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; LENGTH]> {
    let end = cursor.checked_add(LENGTH).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof cursor overflowed")
    })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot relation proof ended early")
    })?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

fn usize_to_u64_bytes(value: usize) -> CanonicalResult<[u8; 8]> {
    Ok(u64::try_from(value)
        .map_err(|_| {
            invalid_direct_ballot_relation_proof(
                "direct ballot relation proof index does not fit in u64",
            )
        })?
        .to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_ballot_support_polynomial_accepts_valid_small_witnesses() {
        assert_support_check(DirectBallotSupportKind::OneHot, 1, true);
        assert_support_check(DirectBallotSupportKind::Randomizer, -1, true);
        assert_support_check(DirectBallotSupportKind::Error, 2, true);
    }

    #[test]
    fn direct_ballot_support_polynomial_rejects_invalid_small_witnesses() {
        assert_support_check(DirectBallotSupportKind::OneHot, 2, false);
        assert_support_check(DirectBallotSupportKind::Randomizer, 2, false);
        assert_support_check(DirectBallotSupportKind::Error, 3, false);
    }

    fn assert_support_check(
        support_kind: DirectBallotSupportKind,
        witness: i64,
        should_accept: bool,
    ) {
        let modulus = direct_ballot_support_modulus();
        let mask = 7_i64;
        let challenge = 29_u64;
        let expansion = support_expansion_coefficients(
            support_kind,
            signed_residue(mask, modulus),
            signed_residue(witness, modulus),
            modulus,
        )
        .expect("support expansion");
        let response = vec![mask + i64::try_from(challenge).expect("challenge fits i64") * witness];
        let result = verify_support_response_polynomial(
            "test witness",
            support_kind,
            &response,
            &expansion,
            challenge % modulus,
            modulus,
        );

        if should_accept {
            result.expect("valid support witness should pass");
        } else {
            let error = result.expect_err("invalid support witness should reject");
            assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
            assert!(error.message.contains("test witness support check failed"));
        }
    }
}

fn invalid_direct_ballot_relation_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
