use std::mem::size_of;

use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use serde_json::{Value, json};

use super::setup_package_hash;
use crate::{
    bgv::{
        evaluator::engine::{
            Ciphertext, DevelopmentBgvKey, ciphertext_object_root, negacyclic_mul,
        },
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        profile::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, PROFILE_ID, profile_hash},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, hash512, hash512_hex, to_hex},
};

const DIRECT_BALLOT_REFRESH_SHARE_PROOF_MAGIC: &[u8; 8] = b"SLDRS001";
const DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BITS: u32 = 192;
const DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BYTES: usize = 24;
const DIRECT_BALLOT_REFRESH_SHARE_CLAIM_SOUNDNESS_TARGET_BITS: u32 = 128;
const DIRECT_BALLOT_REFRESH_SHARE_MASK_COEFFICIENT_BITS: usize = 360;
const DIRECT_BALLOT_REFRESH_SHARE_RESPONSE_COEFFICIENT_BYTES: usize = 48;
const DIRECT_BALLOT_REFRESH_SHARE_WITNESS_BOUND_BITS: u32 = 2;
const DIRECT_BALLOT_REFRESH_SHARE_SECRET_SUPPORT_EXPANSION_COEFFICIENTS: usize = 3;
const DIRECT_BALLOT_REFRESH_SHARE_ERROR_SUPPORT_EXPANSION_COEFFICIENTS: usize = 5;
const DIRECT_BALLOT_REFRESH_SHARE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/refresh-share-proof-bytes-v1";

pub(super) struct DirectBallotRefreshShareStatement<'a> {
    pub(super) setup_package: &'a Value,
    pub(super) evaluator_key: &'a DevelopmentBgvKey,
    pub(super) input_rank_root: &'a str,
    pub(super) masked_ranks: &'a Ciphertext,
    pub(super) threshold_share_verification_key_hash: &'a str,
    pub(super) trustee_identity: &'a str,
    pub(super) roster_position: usize,
    pub(super) recovery_epoch: u64,
    pub(super) device_epoch: u64,
    pub(super) participant_setup_record_hash: &'a str,
    pub(super) trustee_threshold_verification_key_hash: &'a str,
    pub(super) public_key_share_component_zero: &'a [Vec<u64>],
    pub(super) decryption_share_coefficients: &'a [Vec<u64>],
}

pub(super) struct DirectBallotRefreshShareProofGeneration {
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_size_bytes: usize,
    pub(super) proof_bytes_hash: String,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) challenge: String,
    pub(super) relation_commitment_bytes: usize,
    pub(super) response_bytes: usize,
}

#[derive(Debug)]
pub(super) struct DirectBallotRefreshShareProofVerification {
    pub(super) proof_size_bytes: usize,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) challenge: String,
}

struct DirectBallotRefreshShareRelationCommitment {
    public_key_share_component_zero: Vec<u64>,
    decryption_share: Vec<u64>,
}

struct DirectBallotRefreshShareSupportCommitment {
    secret_support: Vec<u64>,
    error_support: Vec<u64>,
}

struct DirectBallotRefreshShareWitness {
    secret_coefficients: Vec<BigInt>,
    error_coefficients: Vec<BigInt>,
}

struct ParsedDirectBallotRefreshShareProof {
    challenge: BigInt,
    commitments: Vec<DirectBallotRefreshShareRelationCommitment>,
    support_commitment: DirectBallotRefreshShareSupportCommitment,
    response: DirectBallotRefreshShareWitness,
    relation_commitment_hash: [u8; 64],
}

pub(super) fn generate_direct_ballot_refresh_share_proof(
    statement: &DirectBallotRefreshShareStatement<'_>,
    secret_coefficients: &[i64],
    error_coefficients: &[i64],
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotRefreshShareProofGeneration> {
    validate_direct_ballot_refresh_share_statement(statement)?;
    let statement_hash = direct_ballot_refresh_share_statement_hash(statement)?;
    let witness = DirectBallotRefreshShareWitness {
        secret_coefficients: secret_coefficients
            .iter()
            .map(|coefficient| BigInt::from(*coefficient))
            .collect(),
        error_coefficients: error_coefficients
            .iter()
            .map(|coefficient| BigInt::from(*coefficient))
            .collect(),
    };
    validate_direct_ballot_refresh_share_witness(&witness)?;
    let mask = sample_direct_ballot_refresh_share_mask(
        &statement_hash,
        statement.trustee_identity,
        proof_randomness_seed_hex,
    )?;
    let commitments = evaluate_direct_ballot_refresh_share_relation(statement, &mask)?;
    let support_commitment = evaluate_direct_ballot_refresh_share_support_commitment(
        &mask,
        &witness,
        direct_ballot_refresh_share_support_modulus(statement),
    )?;
    let encoded_commitments = encode_direct_ballot_refresh_share_commitments(
        statement,
        &commitments,
        &support_commitment,
    )?;
    let relation_commitment_bytes = encoded_commitments.len();
    let relation_commitment_hash =
        direct_ballot_refresh_share_relation_commitment_hash(&statement_hash, &encoded_commitments);
    let challenge =
        direct_ballot_refresh_share_challenge(&statement_hash, &relation_commitment_hash)?;
    let response = direct_ballot_refresh_share_response(&mask, &witness, &challenge)?;
    let proof_bytes = encode_direct_ballot_refresh_share_proof(
        &statement_hash,
        &challenge,
        &encoded_commitments,
        &response,
    )?;
    let proof_size_bytes = proof_bytes.len();
    let proof_bytes_hash = direct_ballot_refresh_share_proof_bytes_hash(&proof_bytes);

    Ok(DirectBallotRefreshShareProofGeneration {
        proof_bytes,
        proof_size_bytes,
        proof_bytes_hash,
        statement_hash_hex: to_hex(&statement_hash),
        relation_commitment_hash_hex: to_hex(&relation_commitment_hash),
        challenge: challenge.to_string(),
        relation_commitment_bytes,
        response_bytes: direct_ballot_refresh_share_response_bytes(),
    })
}

pub(super) fn verify_direct_ballot_refresh_share_proof(
    statement: &DirectBallotRefreshShareStatement<'_>,
    proof_bytes: &[u8],
) -> CanonicalResult<DirectBallotRefreshShareProofVerification> {
    validate_direct_ballot_refresh_share_statement(statement)?;
    let expected_statement_hash = direct_ballot_refresh_share_statement_hash(statement)?;
    let parsed_proof =
        parse_direct_ballot_refresh_share_proof(statement, proof_bytes, &expected_statement_hash)?;
    verify_direct_ballot_refresh_share_response(
        statement,
        &parsed_proof.challenge,
        &parsed_proof.commitments,
        &parsed_proof.support_commitment,
        &parsed_proof.response,
    )?;

    Ok(DirectBallotRefreshShareProofVerification {
        proof_size_bytes: proof_bytes.len(),
        statement_hash_hex: to_hex(&expected_statement_hash),
        relation_commitment_hash_hex: to_hex(&parsed_proof.relation_commitment_hash),
        challenge: parsed_proof.challenge.to_string(),
    })
}

pub(super) fn direct_ballot_refresh_share_proof_accounting(
    proof_size_bytes_per_share: usize,
    share_count: usize,
) -> CanonicalResult<Value> {
    let independent_repetitions = DIRECT_BALLOT_REFRESH_SHARE_CLAIM_SOUNDNESS_TARGET_BITS
        .div_ceil(DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BITS);
    let support_check_count_per_share = direct_ballot_refresh_share_support_check_count();
    let support_union_loss_bits = ceil_log2_usize(
        support_check_count_per_share
            * direct_ballot_refresh_share_support_maximum_degree()
            * share_count,
    );
    let soundness_after_support_union_bound =
        DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BITS - support_union_loss_bits;
    let response_coordinate_count = 2 * POLYNOMIAL_DEGREE * share_count;
    let response_union_loss_bits = ceil_log2_usize(response_coordinate_count);
    let zero_knowledge_shift_slack_bits =
        u32::try_from(DIRECT_BALLOT_REFRESH_SHARE_MASK_COEFFICIENT_BITS)
            .expect("mask bit count fits u32")
            - DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BITS
            - DIRECT_BALLOT_REFRESH_SHARE_WITNESS_BOUND_BITS
            - response_union_loss_bits;
    let current_opening_proof_bytes = proof_size_bytes_per_share
        .checked_mul(share_count)
        .ok_or_else(|| {
            invalid_direct_ballot_refresh_share_proof(
                "refresh share opening proof byte count overflowed",
            )
        })?;
    let repeated_proof_size_bytes_per_share = checked_repeated_byte_count(
        proof_size_bytes_per_share,
        independent_repetitions,
        "refresh share repeated proof size",
    )?;
    let repeated_opening_proof_bytes = checked_repeated_byte_count(
        current_opening_proof_bytes,
        independent_repetitions,
        "refresh share repeated opening proof size",
    )?;

    Ok(json!({
        "model": "one Fiat-Shamir challenge per submitted trustee refresh-share proof over the internal binary transcript",
        "challengeBits": DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BITS,
        "challengeCountPerShare": 1,
        "shareCount": share_count,
        "proofSizeBytesPerShare": proof_size_bytes_per_share,
        "currentOpeningProofBytes": current_opening_proof_bytes,
        "classicalSoundnessBitsBeforeLossesPerShare": DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BITS,
        "supportCheckCountPerShare": support_check_count_per_share,
        "supportMaximumDegree": direct_ballot_refresh_share_support_maximum_degree(),
        "supportUnionLossBitsAcrossShares": support_union_loss_bits,
        "classicalSoundnessBitsAfterSupportUnionBound": soundness_after_support_union_bound,
        "targetClassicalSoundnessBits": DIRECT_BALLOT_REFRESH_SHARE_CLAIM_SOUNDNESS_TARGET_BITS,
        "minimumIndependentRepetitionsForTarget": independent_repetitions,
        "estimatedRepeatedProofSizeBytesPerShare": repeated_proof_size_bytes_per_share,
        "estimatedRepeatedOpeningProofBytes": repeated_opening_proof_bytes,
        "maskCoefficientBits": DIRECT_BALLOT_REFRESH_SHARE_MASK_COEFFICIENT_BITS,
        "responseCoefficientBytes": DIRECT_BALLOT_REFRESH_SHARE_RESPONSE_COEFFICIENT_BYTES,
        "witnessBoundBitsForMaskShiftAccounting": DIRECT_BALLOT_REFRESH_SHARE_WITNESS_BOUND_BITS,
        "zeroKnowledgeShiftSlackBitsAfterResponseUnionBound": zero_knowledge_shift_slack_bits,
        "unionBound": "The 192-bit Fiat-Shamir challenge leaves more than 128 classical bits after the share-count, support-degree, and support-check union bound for this internal transcript.",
        "zeroKnowledgeAccounting": "The 360-bit masks leave more than 128 bits of shift-hiding slack after response-coordinate union accounting under the bounded refresh-share witness coefficients. The surrounding command reports whether proof masks came from fresh CSPRNG randomness or deterministic fixture randomness; fixture-mask runs remain development evidence only.",
        "decision": "Claim-shaped for proof-of-concept sizing: no naive transcript repetition is needed for submitted refresh-share proofs, but this is still not a public claim-bearing proof until the Fiat-Shamir/QROM review and accepted proof transport boundary are closed."
    }))
}

pub(super) fn direct_ballot_refresh_share_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(
        DIRECT_BALLOT_REFRESH_SHARE_PROOF_BYTES_HASH_DOMAIN,
        &[proof_bytes],
    )
}

fn direct_ballot_refresh_share_statement_hash(
    statement: &DirectBallotRefreshShareStatement<'_>,
) -> CanonicalResult<[u8; 64]> {
    let masked_rank_root = ciphertext_object_root(statement.masked_ranks)?;
    let public_key_share_hash = direct_ballot_refresh_share_residue_hash(
        "refresh-share-public-key-component-zero",
        statement.masked_ranks.primes(),
        statement.public_key_share_component_zero,
    )?;
    let decryption_share_hash = direct_ballot_refresh_share_residue_hash(
        "refresh-share-decryption-share",
        statement.masked_ranks.primes(),
        statement.decryption_share_coefficients,
    )?;
    let statement_json = canonical_json(&json!({
        "objectType": "DirectEncryptedBallotMaskedRankRefreshShareStatement",
        "objectVersion": 1,
        "setupPackageHash": setup_package_hash(statement.setup_package)?,
        "profileId": PROFILE_ID,
        "profileHash": profile_hash()?,
        "activePrimeCount": statement.masked_ranks.primes().len(),
        "activePrimes": statement.masked_ranks.primes(),
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "inputRankRoot": statement.input_rank_root,
        "maskedRankRoot": masked_rank_root,
        "thresholdShareVerificationKeyHash": statement.threshold_share_verification_key_hash,
        "trusteeIdentity": statement.trustee_identity,
        "rosterPosition": statement.roster_position,
        "recoveryEpoch": statement.recovery_epoch,
        "deviceEpoch": statement.device_epoch,
        "participantSetupRecordHash": statement.participant_setup_record_hash,
        "trusteeThresholdVerificationKeyHash": statement.trustee_threshold_verification_key_hash,
        "publicKeyShareComponentZeroHash": public_key_share_hash,
        "decryptionShareHash": decryption_share_hash,
        "relation": "one hidden trustee secret/error witness proves b_i=p*e_i-a*s_i and d_i=c1*s_i for every active BGV data prime, with ternary secret-share support and centered-binomial-eta-2 error-share support"
    }))?;

    Ok(hash512(
        "sealed-lattice/direct-encrypted-ballot/refresh-share-statement-v1",
        &[statement_json.as_bytes()],
    ))
}

fn validate_direct_ballot_refresh_share_statement(
    statement: &DirectBallotRefreshShareStatement<'_>,
) -> CanonicalResult<()> {
    if statement.masked_ranks.components.len() != 2 {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof requires a two-component masked ciphertext",
        ));
    }
    let primes = statement.masked_ranks.primes();
    let (public_component_zero, public_component_one) =
        statement.evaluator_key.public_key_components();
    if public_component_zero.len() < primes.len() || public_component_one.len() < primes.len() {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof requires public key limbs for every active masked ciphertext limb",
        ));
    }
    validate_residue_polynomial_set(
        primes,
        statement.public_key_share_component_zero,
        "refresh share public-key component",
    )?;
    validate_residue_polynomial_set(
        primes,
        statement.decryption_share_coefficients,
        "refresh share decryption share",
    )
}

fn validate_direct_ballot_refresh_share_witness(
    witness: &DirectBallotRefreshShareWitness,
) -> CanonicalResult<()> {
    if witness.secret_coefficients.len() != POLYNOMIAL_DEGREE
        || witness.error_coefficients.len() != POLYNOMIAL_DEGREE
    {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof witness polynomials must match the BGV polynomial degree",
        ));
    }

    Ok(())
}

fn sample_direct_ballot_refresh_share_mask(
    statement_hash: &[u8; 64],
    trustee_identity: &str,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotRefreshShareWitness> {
    Ok(DirectBallotRefreshShareWitness {
        secret_coefficients: sample_direct_ballot_refresh_share_mask_polynomial(
            statement_hash,
            trustee_identity,
            proof_randomness_seed_hex,
            0,
        )?,
        error_coefficients: sample_direct_ballot_refresh_share_mask_polynomial(
            statement_hash,
            trustee_identity,
            proof_randomness_seed_hex,
            1,
        )?,
    })
}

fn sample_direct_ballot_refresh_share_mask_polynomial(
    statement_hash: &[u8; 64],
    trustee_identity: &str,
    proof_randomness_seed_hex: &str,
    witness_vector_index: usize,
) -> CanonicalResult<Vec<BigInt>> {
    let mut coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let witness_vector_index_bytes = usize_to_u64_bytes(witness_vector_index)?;
    while coefficients.len() < POLYNOMIAL_DEGREE {
        let coefficient_index_bytes = usize_to_u64_bytes(coefficients.len())?;
        let block = hash512(
            "sealed-lattice/direct-encrypted-ballot/refresh-share-mask-v1",
            &[
                statement_hash,
                trustee_identity.as_bytes(),
                proof_randomness_seed_hex.as_bytes(),
                &witness_vector_index_bytes,
                &coefficient_index_bytes,
            ],
        );
        coefficients.push(direct_ballot_refresh_share_mask_coefficient(&block)?);
    }

    Ok(coefficients)
}

fn direct_ballot_refresh_share_mask_coefficient(block: &[u8; 64]) -> CanonicalResult<BigInt> {
    let magnitude_byte_count = DIRECT_BALLOT_REFRESH_SHARE_MASK_COEFFICIENT_BITS.div_ceil(8);
    if magnitude_byte_count >= block.len() {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof mask coefficient needs more hash material",
        ));
    }
    let mut magnitude_bytes = block[..magnitude_byte_count].to_vec();
    let excess_bits = magnitude_byte_count * 8 - DIRECT_BALLOT_REFRESH_SHARE_MASK_COEFFICIENT_BITS;
    if excess_bits > 0 {
        let kept_bits = 8 - excess_bits;
        let mask = (1_u16 << kept_bits) - 1;
        if let Some(last_byte) = magnitude_bytes.last_mut() {
            *last_byte &= u8::try_from(mask).expect("mask fits u8");
        }
    }
    let magnitude = BigInt::from_bytes_le(Sign::Plus, &magnitude_bytes);
    if block[magnitude_byte_count] & 1 == 1 {
        Ok(-magnitude)
    } else {
        Ok(magnitude)
    }
}

fn evaluate_direct_ballot_refresh_share_relation(
    statement: &DirectBallotRefreshShareStatement<'_>,
    witness: &DirectBallotRefreshShareWitness,
) -> CanonicalResult<Vec<DirectBallotRefreshShareRelationCommitment>> {
    validate_direct_ballot_refresh_share_witness(witness)?;
    let (_, public_component_one) = statement.evaluator_key.public_key_components();
    statement
        .masked_ranks
        .primes()
        .iter()
        .copied()
        .enumerate()
        .map(|(limb_index, modulus)| {
            let secret_residues = signed_residue_polynomial(
                &witness.secret_coefficients,
                modulus,
                "refresh share secret witness",
            )?;
            let secret_public_sample_product =
                negacyclic_mul(&public_component_one[limb_index], &secret_residues, modulus)?;
            let public_key_share_component_zero = witness
                .error_coefficients
                .iter()
                .zip(secret_public_sample_product.iter())
                .map(|(error_coefficient, product_coefficient)| {
                    let scaled_error = scaled_signed_plaintext_residue(error_coefficient, modulus)?;
                    sub_mod(scaled_error, *product_coefficient, modulus)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            let decryption_share = negacyclic_mul(
                &statement.masked_ranks.components[1][limb_index],
                &secret_residues,
                modulus,
            )?;

            Ok(DirectBallotRefreshShareRelationCommitment {
                public_key_share_component_zero,
                decryption_share,
            })
        })
        .collect()
}

fn direct_ballot_refresh_share_response(
    mask: &DirectBallotRefreshShareWitness,
    witness: &DirectBallotRefreshShareWitness,
    challenge: &BigInt,
) -> CanonicalResult<DirectBallotRefreshShareWitness> {
    validate_direct_ballot_refresh_share_witness(mask)?;
    validate_direct_ballot_refresh_share_witness(witness)?;
    Ok(DirectBallotRefreshShareWitness {
        secret_coefficients: response_polynomial(
            &mask.secret_coefficients,
            &witness.secret_coefficients,
            challenge,
            "refresh share secret response",
        )?,
        error_coefficients: response_polynomial(
            &mask.error_coefficients,
            &witness.error_coefficients,
            challenge,
            "refresh share error response",
        )?,
    })
}

fn response_polynomial(
    mask_polynomial: &[BigInt],
    witness_polynomial: &[BigInt],
    challenge: &BigInt,
    label: &str,
) -> CanonicalResult<Vec<BigInt>> {
    if mask_polynomial.len() != witness_polynomial.len() {
        return Err(invalid_direct_ballot_refresh_share_proof(format!(
            "{label} mask and witness lengths must match"
        )));
    }
    mask_polynomial
        .iter()
        .zip(witness_polynomial.iter())
        .map(|(mask_coefficient, witness_coefficient)| {
            let response = mask_coefficient + challenge * witness_coefficient;
            validate_signed_bigint_fixed_width(&response, label)?;
            Ok(response)
        })
        .collect()
}

fn verify_direct_ballot_refresh_share_response(
    statement: &DirectBallotRefreshShareStatement<'_>,
    challenge: &BigInt,
    commitments: &[DirectBallotRefreshShareRelationCommitment],
    support_commitment: &DirectBallotRefreshShareSupportCommitment,
    response: &DirectBallotRefreshShareWitness,
) -> CanonicalResult<()> {
    let response_relation = evaluate_direct_ballot_refresh_share_relation(statement, response)?;
    if commitments.len() != response_relation.len() {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof commitment count does not match active limbs",
        ));
    }
    for (limb_index, modulus) in statement.masked_ranks.primes().iter().copied().enumerate() {
        let challenge_residue = challenge_residue(challenge, modulus)?;
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            let scaled_public_key_share = mul_mod(
                challenge_residue,
                statement.public_key_share_component_zero[limb_index][coefficient_index],
                modulus,
            )?;
            let checked_public_key_share = sub_mod(
                response_relation[limb_index].public_key_share_component_zero[coefficient_index],
                scaled_public_key_share,
                modulus,
            )?;
            if checked_public_key_share
                != commitments[limb_index].public_key_share_component_zero[coefficient_index]
            {
                return Err(invalid_direct_ballot_refresh_share_proof(format!(
                    "refresh share proof limb {limb_index} public-key share response does not match the statement"
                )));
            }

            let scaled_decryption_share = mul_mod(
                challenge_residue,
                statement.decryption_share_coefficients[limb_index][coefficient_index],
                modulus,
            )?;
            let checked_decryption_share = sub_mod(
                response_relation[limb_index].decryption_share[coefficient_index],
                scaled_decryption_share,
                modulus,
            )?;
            if checked_decryption_share
                != commitments[limb_index].decryption_share[coefficient_index]
            {
                return Err(invalid_direct_ballot_refresh_share_proof(format!(
                    "refresh share proof limb {limb_index} decryption-share response does not match the statement"
                )));
            }
        }
    }

    verify_direct_ballot_refresh_share_support_response(
        statement,
        challenge,
        support_commitment,
        response,
    )
}

fn evaluate_direct_ballot_refresh_share_support_commitment(
    mask: &DirectBallotRefreshShareWitness,
    witness: &DirectBallotRefreshShareWitness,
    modulus: u64,
) -> CanonicalResult<DirectBallotRefreshShareSupportCommitment> {
    validate_direct_ballot_refresh_share_witness(mask)?;
    validate_direct_ballot_refresh_share_witness(witness)?;
    Ok(DirectBallotRefreshShareSupportCommitment {
        secret_support: refresh_share_support_expansion_commitments_for_polynomial(
            DirectBallotRefreshShareSupportKind::Secret,
            &mask.secret_coefficients,
            &witness.secret_coefficients,
            modulus,
        )?,
        error_support: refresh_share_support_expansion_commitments_for_polynomial(
            DirectBallotRefreshShareSupportKind::Error,
            &mask.error_coefficients,
            &witness.error_coefficients,
            modulus,
        )?,
    })
}

fn verify_direct_ballot_refresh_share_support_response(
    statement: &DirectBallotRefreshShareStatement<'_>,
    challenge: &BigInt,
    support_commitment: &DirectBallotRefreshShareSupportCommitment,
    response: &DirectBallotRefreshShareWitness,
) -> CanonicalResult<()> {
    validate_direct_ballot_refresh_share_witness(response)?;
    validate_direct_ballot_refresh_share_support_commitment_shape(support_commitment)?;
    let modulus = direct_ballot_refresh_share_support_modulus(statement);
    let challenge_residue = challenge_residue(challenge, modulus)?;
    verify_refresh_share_support_response_polynomial(
        "secret share",
        DirectBallotRefreshShareSupportKind::Secret,
        &response.secret_coefficients,
        &support_commitment.secret_support,
        challenge_residue,
        modulus,
    )?;
    verify_refresh_share_support_response_polynomial(
        "error share",
        DirectBallotRefreshShareSupportKind::Error,
        &response.error_coefficients,
        &support_commitment.error_support,
        challenge_residue,
        modulus,
    )
}

fn refresh_share_support_expansion_commitments_for_polynomial(
    support_kind: DirectBallotRefreshShareSupportKind,
    mask_polynomial: &[BigInt],
    witness_polynomial: &[BigInt],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if mask_polynomial.len() != POLYNOMIAL_DEGREE || witness_polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share support commitment polynomials must match the BGV degree",
        ));
    }
    let mut commitments =
        Vec::with_capacity(POLYNOMIAL_DEGREE * support_kind.expansion_coefficient_count());
    for (mask, witness) in mask_polynomial.iter().zip(witness_polynomial.iter()) {
        commitments.extend(refresh_share_support_expansion_coefficients(
            support_kind,
            signed_bigint_residue(mask, modulus)?,
            signed_bigint_residue(witness, modulus)?,
            modulus,
        )?);
    }

    Ok(commitments)
}

fn verify_refresh_share_support_response_polynomial(
    label: &str,
    support_kind: DirectBallotRefreshShareSupportKind,
    response_coefficients: &[BigInt],
    expansion_commitments: &[u64],
    challenge_residue: u64,
    modulus: u64,
) -> CanonicalResult<()> {
    let expansion_coefficient_count = support_kind.expansion_coefficient_count();
    if expansion_commitments.len() != response_coefficients.len() * expansion_coefficient_count {
        return Err(invalid_direct_ballot_refresh_share_proof(format!(
            "refresh share {label} support commitment has the wrong length"
        )));
    }
    for (coefficient_index, (response, expansion)) in response_coefficients
        .iter()
        .zip(expansion_commitments.chunks_exact(expansion_coefficient_count))
        .enumerate()
    {
        let response_residue = signed_bigint_residue(response, modulus)?;
        let support_value = refresh_share_support_polynomial_value(
            support_kind,
            response_residue,
            challenge_residue,
            modulus,
        )?;
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
            return Err(invalid_direct_ballot_refresh_share_proof(format!(
                "refresh share {label} support check failed at coefficient {coefficient_index}"
            )));
        }
    }

    Ok(())
}

fn refresh_share_support_expansion_coefficients(
    support_kind: DirectBallotRefreshShareSupportKind,
    mask: u64,
    witness: u64,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mask_power = powers(mask, 5, modulus)?;
    let witness_power = powers(witness, 5, modulus)?;
    match support_kind {
        DirectBallotRefreshShareSupportKind::Secret => Ok(vec![
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
        DirectBallotRefreshShareSupportKind::Error => Ok(vec![
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

fn refresh_share_support_polynomial_value(
    support_kind: DirectBallotRefreshShareSupportKind,
    value: u64,
    homogenizing_value: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    let value_power = powers(value, 5, modulus)?;
    let homogenizing_power = powers(homogenizing_value, 5, modulus)?;
    match support_kind {
        DirectBallotRefreshShareSupportKind::Secret => sub_mod(
            value_power[3],
            mul_mod(value, homogenizing_power[2], modulus)?,
            modulus,
        ),
        DirectBallotRefreshShareSupportKind::Error => add_mod(
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

#[derive(Clone, Copy)]
enum DirectBallotRefreshShareSupportKind {
    Secret,
    Error,
}

impl DirectBallotRefreshShareSupportKind {
    fn expansion_coefficient_count(self) -> usize {
        match self {
            Self::Secret => DIRECT_BALLOT_REFRESH_SHARE_SECRET_SUPPORT_EXPANSION_COEFFICIENTS,
            Self::Error => DIRECT_BALLOT_REFRESH_SHARE_ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        }
    }
}

fn encode_direct_ballot_refresh_share_proof(
    statement_hash: &[u8; 64],
    challenge: &BigInt,
    encoded_commitments: &[u8],
    response: &DirectBallotRefreshShareWitness,
) -> CanonicalResult<Vec<u8>> {
    let mut proof_bytes = Vec::with_capacity(
        DIRECT_BALLOT_REFRESH_SHARE_PROOF_MAGIC.len()
            + statement_hash.len()
            + DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BYTES
            + encoded_commitments.len()
            + direct_ballot_refresh_share_response_bytes(),
    );
    proof_bytes.extend_from_slice(DIRECT_BALLOT_REFRESH_SHARE_PROOF_MAGIC);
    proof_bytes.extend_from_slice(statement_hash);
    append_challenge(&mut proof_bytes, challenge)?;
    proof_bytes.extend_from_slice(encoded_commitments);
    encode_direct_ballot_refresh_share_response(&mut proof_bytes, response)?;

    Ok(proof_bytes)
}

fn parse_direct_ballot_refresh_share_proof(
    statement: &DirectBallotRefreshShareStatement<'_>,
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
) -> CanonicalResult<ParsedDirectBallotRefreshShareProof> {
    let mut cursor = 0_usize;
    let magic = read_fixed_bytes::<8>(proof_bytes, &mut cursor)?;
    if magic != *DIRECT_BALLOT_REFRESH_SHARE_PROOF_MAGIC {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof has an unknown encoding",
        ));
    }
    let statement_hash = read_hash(proof_bytes, &mut cursor)?;
    if statement_hash != *expected_statement_hash {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof statement hash does not match the masked-rank share",
        ));
    }
    let challenge = read_challenge(proof_bytes, &mut cursor)?;
    if challenge.is_zero() {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof challenge is outside the configured challenge space",
        ));
    }
    let commitment_start = cursor;
    let commitments =
        read_direct_ballot_refresh_share_commitments(statement, proof_bytes, &mut cursor)?;
    let support_commitment =
        read_direct_ballot_refresh_share_support_commitment(statement, proof_bytes, &mut cursor)?;
    let encoded_commitments = &proof_bytes[commitment_start..cursor];
    let relation_commitment_hash =
        direct_ballot_refresh_share_relation_commitment_hash(&statement_hash, encoded_commitments);
    let recomputed_challenge =
        direct_ballot_refresh_share_challenge(&statement_hash, &relation_commitment_hash)?;
    if challenge != recomputed_challenge {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof challenge does not match its commitment",
        ));
    }
    let response = read_direct_ballot_refresh_share_response(proof_bytes, &mut cursor)?;
    if cursor != proof_bytes.len() {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof has trailing bytes",
        ));
    }

    Ok(ParsedDirectBallotRefreshShareProof {
        challenge,
        commitments,
        support_commitment,
        response,
        relation_commitment_hash,
    })
}

fn encode_direct_ballot_refresh_share_commitments(
    statement: &DirectBallotRefreshShareStatement<'_>,
    commitments: &[DirectBallotRefreshShareRelationCommitment],
    support_commitment: &DirectBallotRefreshShareSupportCommitment,
) -> CanonicalResult<Vec<u8>> {
    if commitments.len() != statement.masked_ranks.primes().len() {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof commitment count must match active limbs",
        ));
    }
    let mut encoded = Vec::with_capacity(
        statement.masked_ranks.primes().len() * 2 * POLYNOMIAL_DEGREE * size_of::<u64>()
            + direct_ballot_refresh_share_support_commitment_bytes(),
    );
    for (limb_index, (commitment, modulus)) in commitments
        .iter()
        .zip(statement.masked_ranks.primes().iter())
        .enumerate()
    {
        encode_residue_polynomial(
            &mut encoded,
            &commitment.public_key_share_component_zero,
            *modulus,
            limb_index,
            "public-key share",
        )?;
        encode_residue_polynomial(
            &mut encoded,
            &commitment.decryption_share,
            *modulus,
            limb_index,
            "decryption share",
        )?;
    }
    encode_direct_ballot_refresh_share_support_commitment(
        &mut encoded,
        statement,
        support_commitment,
    )?;

    Ok(encoded)
}

fn read_direct_ballot_refresh_share_commitments(
    statement: &DirectBallotRefreshShareStatement<'_>,
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<Vec<DirectBallotRefreshShareRelationCommitment>> {
    statement
        .masked_ranks
        .primes()
        .iter()
        .copied()
        .map(|modulus| {
            Ok(DirectBallotRefreshShareRelationCommitment {
                public_key_share_component_zero: read_residue_polynomial(
                    proof_bytes,
                    cursor,
                    modulus,
                )?,
                decryption_share: read_residue_polynomial(proof_bytes, cursor, modulus)?,
            })
        })
        .collect()
}

fn encode_direct_ballot_refresh_share_support_commitment(
    output: &mut Vec<u8>,
    statement: &DirectBallotRefreshShareStatement<'_>,
    commitment: &DirectBallotRefreshShareSupportCommitment,
) -> CanonicalResult<()> {
    validate_direct_ballot_refresh_share_support_commitment_shape(commitment)?;
    let modulus = direct_ballot_refresh_share_support_modulus(statement);
    for coefficient in commitment
        .secret_support
        .iter()
        .chain(commitment.error_support.iter())
    {
        if *coefficient >= modulus {
            return Err(invalid_direct_ballot_refresh_share_proof(
                "refresh share support commitment is not canonical",
            ));
        }
        append_u64(output, *coefficient);
    }

    Ok(())
}

fn read_direct_ballot_refresh_share_support_commitment(
    statement: &DirectBallotRefreshShareStatement<'_>,
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<DirectBallotRefreshShareSupportCommitment> {
    let modulus = direct_ballot_refresh_share_support_modulus(statement);
    Ok(DirectBallotRefreshShareSupportCommitment {
        secret_support: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            POLYNOMIAL_DEGREE * DIRECT_BALLOT_REFRESH_SHARE_SECRET_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
        error_support: read_residue_scalars(
            proof_bytes,
            cursor,
            modulus,
            POLYNOMIAL_DEGREE * DIRECT_BALLOT_REFRESH_SHARE_ERROR_SUPPORT_EXPANSION_COEFFICIENTS,
        )?,
    })
}

fn encode_direct_ballot_refresh_share_response(
    output: &mut Vec<u8>,
    response: &DirectBallotRefreshShareWitness,
) -> CanonicalResult<()> {
    validate_direct_ballot_refresh_share_witness(response)?;
    for coefficient in &response.secret_coefficients {
        append_signed_bigint_fixed(output, coefficient)?;
    }
    for coefficient in &response.error_coefficients {
        append_signed_bigint_fixed(output, coefficient)?;
    }

    Ok(())
}

fn read_direct_ballot_refresh_share_response(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<DirectBallotRefreshShareWitness> {
    Ok(DirectBallotRefreshShareWitness {
        secret_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
        error_coefficients: read_signed_polynomial(proof_bytes, cursor)?,
    })
}

fn direct_ballot_refresh_share_challenge(
    statement_hash: &[u8; 64],
    relation_commitment_hash: &[u8; 64],
) -> CanonicalResult<BigInt> {
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let challenge_block = hash512(
            "sealed-lattice/direct-encrypted-ballot/refresh-share-challenge-v1",
            &[statement_hash, relation_commitment_hash, &block_index_bytes],
        );
        let challenge = BigInt::from_bytes_le(
            Sign::Plus,
            &challenge_block[..DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BYTES],
        );
        if !challenge.is_zero() {
            return Ok(challenge);
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            invalid_direct_ballot_refresh_share_proof(
                "refresh share proof challenge block index overflowed",
            )
        })?;
    }
}

fn direct_ballot_refresh_share_relation_commitment_hash(
    statement_hash: &[u8; 64],
    encoded_commitments: &[u8],
) -> [u8; 64] {
    hash512(
        "sealed-lattice/direct-encrypted-ballot/refresh-share-relation-commitment-v1",
        &[statement_hash, encoded_commitments],
    )
}

fn direct_ballot_refresh_share_response_bytes() -> usize {
    2 * POLYNOMIAL_DEGREE * DIRECT_BALLOT_REFRESH_SHARE_RESPONSE_COEFFICIENT_BYTES
}

fn direct_ballot_refresh_share_support_check_count() -> usize {
    2 * POLYNOMIAL_DEGREE
}

fn direct_ballot_refresh_share_support_maximum_degree() -> usize {
    5
}

fn direct_ballot_refresh_share_support_commitment_bytes() -> usize {
    POLYNOMIAL_DEGREE
        * (DIRECT_BALLOT_REFRESH_SHARE_SECRET_SUPPORT_EXPANSION_COEFFICIENTS
            + DIRECT_BALLOT_REFRESH_SHARE_ERROR_SUPPORT_EXPANSION_COEFFICIENTS)
        * size_of::<u64>()
}

fn direct_ballot_refresh_share_support_modulus(
    statement: &DirectBallotRefreshShareStatement<'_>,
) -> u64 {
    statement.masked_ranks.primes()[0]
}

fn direct_ballot_refresh_share_residue_hash(
    label: &str,
    primes: &[u64],
    polynomial_set: &[Vec<u64>],
) -> CanonicalResult<String> {
    let mut encoded = Vec::new();
    append_u64(&mut encoded, primes.len() as u64);
    for (limb_index, (polynomial, modulus)) in polynomial_set.iter().zip(primes.iter()).enumerate()
    {
        append_u64(&mut encoded, *modulus);
        encode_residue_polynomial(&mut encoded, polynomial, *modulus, limb_index, label)?;
    }

    Ok(hash512_hex(
        &format!("sealed-lattice/direct-encrypted-ballot/{label}-v1"),
        &[&encoded],
    ))
}

fn validate_residue_polynomial_set(
    primes: &[u64],
    polynomial_set: &[Vec<u64>],
    label: &str,
) -> CanonicalResult<()> {
    if polynomial_set.len() != primes.len() {
        return Err(invalid_direct_ballot_refresh_share_proof(format!(
            "{label} must have one limb per active ciphertext prime"
        )));
    }
    for (limb_index, (polynomial, modulus)) in polynomial_set.iter().zip(primes.iter()).enumerate()
    {
        if polynomial.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_direct_ballot_refresh_share_proof(format!(
                "{label} limb {limb_index} has the wrong coefficient count"
            )));
        }
        if polynomial
            .iter()
            .any(|coefficient| *coefficient >= *modulus)
        {
            return Err(invalid_direct_ballot_refresh_share_proof(format!(
                "{label} limb {limb_index} has a non-canonical coefficient"
            )));
        }
    }

    Ok(())
}

fn validate_direct_ballot_refresh_share_support_commitment_shape(
    commitment: &DirectBallotRefreshShareSupportCommitment,
) -> CanonicalResult<()> {
    if commitment.secret_support.len()
        != POLYNOMIAL_DEGREE * DIRECT_BALLOT_REFRESH_SHARE_SECRET_SUPPORT_EXPANSION_COEFFICIENTS
        || commitment.error_support.len()
            != POLYNOMIAL_DEGREE * DIRECT_BALLOT_REFRESH_SHARE_ERROR_SUPPORT_EXPANSION_COEFFICIENTS
    {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share support commitment has the wrong shape",
        ));
    }

    Ok(())
}

fn encode_residue_polynomial(
    output: &mut Vec<u8>,
    polynomial: &[u64],
    modulus: u64,
    limb_index: usize,
    label: &str,
) -> CanonicalResult<()> {
    if polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_refresh_share_proof(format!(
            "refresh share proof {label} limb {limb_index} has the wrong coefficient count"
        )));
    }
    for coefficient in polynomial {
        if *coefficient >= modulus {
            return Err(invalid_direct_ballot_refresh_share_proof(format!(
                "refresh share proof {label} limb {limb_index} has a non-canonical coefficient"
            )));
        }
        append_u64(output, *coefficient);
    }

    Ok(())
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
            return Err(invalid_direct_ballot_refresh_share_proof(
                "refresh share proof commitment coefficient is not canonical",
            ));
        }
        polynomial.push(coefficient);
    }

    Ok(polynomial)
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
            return Err(invalid_direct_ballot_refresh_share_proof(
                "refresh share proof scalar commitment is not canonical",
            ));
        }
        scalars.push(scalar);
    }

    Ok(scalars)
}

fn read_signed_polynomial(proof_bytes: &[u8], cursor: &mut usize) -> CanonicalResult<Vec<BigInt>> {
    let mut polynomial = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for _ in 0..POLYNOMIAL_DEGREE {
        polynomial.push(read_signed_bigint_fixed(proof_bytes, cursor)?);
    }

    Ok(polynomial)
}

fn signed_residue_polynomial(
    polynomial: &[BigInt],
    modulus: u64,
    label: &str,
) -> CanonicalResult<Vec<u64>> {
    if polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_direct_ballot_refresh_share_proof(format!(
            "{label} must match the BGV polynomial degree"
        )));
    }
    polynomial
        .iter()
        .map(|coefficient| signed_bigint_residue(coefficient, modulus))
        .collect()
}

fn scaled_signed_plaintext_residue(coefficient: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    mul_mod(
        signed_bigint_residue(coefficient, modulus)?,
        PLAINTEXT_MODULUS % modulus,
        modulus,
    )
}

fn signed_bigint_residue(coefficient: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_bigint = BigInt::from(modulus);
    let residue = ((coefficient % &modulus_bigint) + &modulus_bigint) % &modulus_bigint;
    let (_, bytes) = residue.to_bytes_le();
    let mut output = 0_u64;
    for (byte_index, byte) in bytes.iter().enumerate() {
        let shift = byte_index.checked_mul(8).ok_or_else(|| {
            invalid_direct_ballot_refresh_share_proof(
                "refresh share signed residue byte shift overflowed",
            )
        })?;
        if shift >= 64 {
            return Err(invalid_direct_ballot_refresh_share_proof(
                "refresh share signed residue does not fit in the modulus type",
            ));
        }
        output |= u64::from(*byte) << shift;
    }
    if output >= modulus {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share signed residue is not canonical",
        ));
    }
    Ok(output)
}

fn challenge_residue(challenge: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    signed_bigint_residue(challenge, modulus)
}

fn validate_signed_bigint_fixed_width(value: &BigInt, label: &str) -> CanonicalResult<()> {
    let bytes = value.to_signed_bytes_le();
    if bytes.len() > DIRECT_BALLOT_REFRESH_SHARE_RESPONSE_COEFFICIENT_BYTES {
        return Err(invalid_direct_ballot_refresh_share_proof(format!(
            "{label} does not fit in the fixed response encoding"
        )));
    }
    Ok(())
}

fn append_signed_bigint_fixed(output: &mut Vec<u8>, value: &BigInt) -> CanonicalResult<()> {
    validate_signed_bigint_fixed_width(value, "refresh share proof response coefficient")?;
    let mut bytes = value.to_signed_bytes_le();
    let sign_extension = if value.sign() == Sign::Minus {
        0xff
    } else {
        0x00
    };
    bytes.resize(
        DIRECT_BALLOT_REFRESH_SHARE_RESPONSE_COEFFICIENT_BYTES,
        sign_extension,
    );
    output.extend_from_slice(&bytes);
    Ok(())
}

fn read_signed_bigint_fixed(input: &[u8], cursor: &mut usize) -> CanonicalResult<BigInt> {
    let end = cursor
        .checked_add(DIRECT_BALLOT_REFRESH_SHARE_RESPONSE_COEFFICIENT_BYTES)
        .ok_or_else(|| {
            invalid_direct_ballot_refresh_share_proof("refresh share proof cursor overflowed")
        })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_refresh_share_proof("refresh share proof ended early")
    })?;
    *cursor = end;
    Ok(BigInt::from_signed_bytes_le(bytes))
}

fn append_challenge(output: &mut Vec<u8>, challenge: &BigInt) -> CanonicalResult<()> {
    if challenge.sign() == Sign::Minus || challenge.is_zero() {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof challenge is outside the configured challenge space",
        ));
    }
    let (_, mut bytes) = challenge.to_bytes_le();
    if bytes.len() > DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BYTES {
        return Err(invalid_direct_ballot_refresh_share_proof(
            "refresh share proof challenge does not fit its encoding",
        ));
    }
    bytes.resize(DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BYTES, 0);
    output.extend_from_slice(&bytes);
    Ok(())
}

fn read_challenge(input: &[u8], cursor: &mut usize) -> CanonicalResult<BigInt> {
    let end = cursor
        .checked_add(DIRECT_BALLOT_REFRESH_SHARE_CHALLENGE_BYTES)
        .ok_or_else(|| {
            invalid_direct_ballot_refresh_share_proof("refresh share proof cursor overflowed")
        })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_refresh_share_proof("refresh share proof ended early")
    })?;
    *cursor = end;
    Ok(BigInt::from_bytes_le(Sign::Plus, bytes))
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_hash(input: &[u8], cursor: &mut usize) -> CanonicalResult<[u8; 64]> {
    let bytes = read_fixed_bytes::<64>(input, cursor)?;
    Ok(bytes)
}

fn read_u64(input: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    let bytes = read_fixed_bytes::<8>(input, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_fixed_bytes<const LENGTH: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; LENGTH]> {
    let end = cursor.checked_add(LENGTH).ok_or_else(|| {
        invalid_direct_ballot_refresh_share_proof("refresh share proof cursor overflowed")
    })?;
    let bytes = input.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_refresh_share_proof("refresh share proof ended early")
    })?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

fn usize_to_u64_bytes(value: usize) -> CanonicalResult<[u8; 8]> {
    Ok(u64::try_from(value)
        .map_err(|_| {
            invalid_direct_ballot_refresh_share_proof(
                "refresh share proof index does not fit in u64",
            )
        })?
        .to_le_bytes())
}

fn ceil_log2_usize(value: usize) -> u32 {
    if value <= 1 {
        0
    } else {
        usize::BITS - (value - 1).leading_zeros()
    }
}

fn checked_repeated_byte_count(
    byte_count: usize,
    repetitions: u32,
    label: &str,
) -> CanonicalResult<usize> {
    let repetitions = usize::try_from(repetitions).map_err(|_| {
        invalid_direct_ballot_refresh_share_proof(format!(
            "{label} repetition count does not fit usize"
        ))
    })?;

    byte_count
        .checked_mul(repetitions)
        .ok_or_else(|| invalid_direct_ballot_refresh_share_proof(format!("{label} overflowed")))
}

fn invalid_direct_ballot_refresh_share_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
