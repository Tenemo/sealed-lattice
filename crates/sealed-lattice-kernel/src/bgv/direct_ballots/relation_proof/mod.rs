use std::mem::size_of;
mod bgv_relation;
mod challenge;
mod codec;
mod generation;
mod masks;
mod score_relation;
mod statement;
mod support_relation;
mod verification;
mod witness;
use bgv_relation::*;
use challenge::*;
use codec::*;
pub(super) use generation::*;
use masks::*;
use score_relation::*;
use statement::*;
use support_relation::*;
pub(super) use verification::*;
use witness::*;

use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use serde_json::{Value, json};

use super::{DirectEncryptedBallot, OPTION_COUNT, SCORE_BUCKET_COUNT};
use crate::{
    bgv::{
        evaluator::engine::{DevelopmentBgvKey, encode_slots_to_coefficients, negacyclic_mul},
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, hash_framed_parts_512 as hash512, to_hex},
};

const RELATION_PROOF_MAGIC: &[u8; 8] = b"SLDBP002";
const RELATION_WITNESS_POLYNOMIALS: usize = 4;
const ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS: usize = 2;
const RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS: usize = 3;
const ERROR_SUPPORT_EXPANSION_COEFFICIENTS: usize = 5;
const RELATION_PROOF_CHALLENGE_BYTES: usize = 24;
const RELATION_MASK_COEFFICIENT_BITS: usize = 360;
const RELATION_RESPONSE_COEFFICIENT_BYTES: usize = 48;
const RELATION_STATEMENT_HASH_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/relation-statement";

pub(super) const fn direct_ballot_relation_response_scalar_count() -> usize {
    RELATION_WITNESS_POLYNOMIALS * POLYNOMIAL_DEGREE
        + OPTION_COUNT
        + OPTION_COUNT * SCORE_BUCKET_COUNT
}

pub(super) const fn direct_ballot_relation_response_bytes() -> usize {
    direct_ballot_relation_response_scalar_count() * RELATION_RESPONSE_COEFFICIENT_BYTES
}

pub(super) const fn direct_ballot_relation_commitment_bytes() -> usize {
    let bgv_commitment_scalars = DATA_PRIMES.len() * 2 * POLYNOMIAL_DEGREE;
    let score_commitment_scalars = 2 * OPTION_COUNT;
    let support_commitment_scalars =
        OPTION_COUNT * SCORE_BUCKET_COUNT * ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS
            + POLYNOMIAL_DEGREE * RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS
            + 2 * POLYNOMIAL_DEGREE * ERROR_SUPPORT_EXPANSION_COEFFICIENTS;

    (bgv_commitment_scalars + score_commitment_scalars + support_commitment_scalars)
        * size_of::<u64>()
}

#[derive(Clone)]
pub(super) struct DirectBallotRelationProofGeneration {
    pub(super) proof_bytes: Vec<u8>,
}

#[derive(Clone)]
struct DirectBallotWitnessVector {
    randomizer_coefficients: Vec<BigInt>,
    error_zero_coefficients: Vec<BigInt>,
    error_one_coefficients: Vec<BigInt>,
    encoding_carry_coefficients: Vec<BigInt>,
    score_coefficients: Vec<BigInt>,
    one_hot_coefficients: Vec<Vec<BigInt>>,
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
    challenge: BigInt,
    bgv_relation_commitments: Vec<DirectBallotBgvRelationCommitment>,
    score_linear_commitment: DirectBallotScoreLinearCommitment,
    support_commitment: DirectBallotSupportCommitment,
    response_vector: DirectBallotWitnessVector,
}

#[derive(Clone, Copy)]
enum DirectBallotSupportKind {
    OneHot,
    Randomizer,
    Error,
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
        let mask = BigInt::from(7_i64);
        let witness = BigInt::from(witness);
        let challenge = BigInt::from(29_u64);
        let expansion = support_expansion_coefficients(
            support_kind,
            signed_bigint_residue(&mask, modulus).expect("mask residue"),
            signed_bigint_residue(&witness, modulus).expect("witness residue"),
            modulus,
        )
        .expect("support expansion");
        let response = vec![mask + &challenge * witness];
        let result = verify_support_response_polynomial(
            "test witness",
            support_kind,
            &response,
            &expansion,
            challenge_residue(&challenge, modulus).expect("challenge residue"),
            modulus,
        );

        if should_accept {
            result.expect("valid support witness should pass");
        } else {
            let error = result.expect_err("invalid support witness should reject");
            assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
            assert!(error.message.contains("test witness support check failed"));
        }
    }
}
