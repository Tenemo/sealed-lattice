use std::mem::size_of;
mod accounting;
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
pub(super) use accounting::*;
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

use super::{
    DIRECT_BALLOT_MAXIMUM_SCORE, DIRECT_BALLOT_OPTION_COUNT, DIRECT_BALLOT_SCORE_BUCKET_COUNT,
    DirectEncryptedBallot, setup_package_hash,
};
use crate::{
    bgv::{
        evaluator::engine::{DevelopmentBgvKey, encode_slots_to_coefficients, negacyclic_mul},
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, bgv_parameters_hash},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, hash512, hash512_hex, to_hex},
};

const DIRECT_BALLOT_RELATION_PROOF_MAGIC: &[u8; 8] = b"SLDBP001";
const DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS: usize = 4;
const DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS: usize = 2;
const DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS: usize = 3;
const DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS: usize = 5;
const DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS: u32 = 192;
const DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BYTES: usize = 24;
const DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS: usize = 360;
const DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES: usize = 48;
const DIRECT_BALLOT_RELATION_STATEMENT_HASH_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/relation-statement-v4";
const DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/relation-proof-bytes-v1";

#[derive(Clone)]
pub(super) struct DirectBallotRelationProofGeneration {
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_size_bytes: usize,
    pub(super) proof_bytes_hash: String,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) challenge: String,
    pub(super) relation_commitment_bytes: usize,
    pub(super) response_bytes: usize,
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
            assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
            assert!(error.message.contains("test witness support check failed"));
        }
    }
}
