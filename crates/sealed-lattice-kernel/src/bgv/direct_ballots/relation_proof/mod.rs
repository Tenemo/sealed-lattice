use std::mem::size_of;
mod accounting;
mod bgv_relation;
mod challenge;
mod codec;
mod committed_backend;
mod committed_trace_proof;
mod fixed_backend;
mod generation;
mod masks;
mod score_relation;
mod statement;
mod verification;
mod witness;
pub(crate) use accounting::{
    direct_ballot_arithmetic_certificate_hash, direct_ballot_arithmetic_certificate_value,
    direct_ballot_relation_proof_profile_hash, direct_ballot_soundness_certificate_hash,
    direct_ballot_soundness_certificate_value, direct_ballot_verifier_certificate_hash,
    direct_ballot_verifier_certificate_value, direct_ballot_witness_partition_profile_hash,
    direct_ballot_zero_knowledge_certificate_hash, direct_ballot_zero_knowledge_certificate_value,
};
use accounting::{
    direct_ballot_encoder_arithmetic_bounds, direct_ballot_projected_bgv_commitment_scalar_count,
    direct_ballot_projected_bgv_no_wrap_carry_scalar_count,
    direct_ballot_relation_proof_dimension_words, direct_ballot_relation_proof_gate,
    direct_ballot_score_linear_commitment_scalar_count,
};
pub(super) use accounting::{
    direct_ballot_relation_challenge_bits, direct_ballot_relation_commitment_bytes,
    direct_ballot_relation_proof_accounting, direct_ballot_relation_proof_bytes_hash,
    direct_ballot_relation_response_bytes, direct_ballot_relation_response_scalar_count,
};
use bgv_relation::*;
use challenge::*;
#[cfg(test)]
pub(in crate::bgv::direct_ballots) use codec::direct_ballot_relation_proof_header_bytes;
pub(in crate::bgv::direct_ballots) use codec::direct_ballot_relation_proof_public_header;
use codec::*;
use committed_backend::*;
use committed_trace_proof::*;
pub(super) use fixed_backend::DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT;
use fixed_backend::*;
pub(super) use generation::*;
use masks::*;
use score_relation::*;
use statement::*;
pub(super) use verification::*;
use witness::*;

use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive, Zero};
use serde_json::{Value, json};

use super::{
    DIRECT_BALLOT_MAXIMUM_SCORE, DIRECT_BALLOT_MINIMUM_SCORE, DIRECT_BALLOT_OPTION_COUNT,
    DIRECT_BALLOT_SCORE_BUCKET_COUNT, DirectEncryptedBallot, direct_ballot_encoder_matrix_root,
    direct_ballot_reserved_slot_rule_hash, direct_ballot_validity_statement_hash,
};
use crate::{
    bgv::{
        evaluator::engine::{BgvPublicKey, encode_slots_to_coefficients, negacyclic_mul},
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        polynomial_iop::{
            COMMITMENT_BOUND_FACTOR, DEEP_POINT_COUNT, DOMAIN_BLOWUP,
            LOW_DEGREE_FINAL_COEFFICIENT_COUNT, LOW_DEGREE_QUERY_COUNT,
            extension_field::CHALLENGE_EXTENSION_DEGREE,
        },
        profile::{BATCH_ENCODER_ID, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{derive_protocol_hash, hash512, hash512_hex, to_hex},
};

const DIRECT_BALLOT_RELATION_PROOF_MAGIC: &[u8; 8] = b"SLDBP003";
const DIRECT_BALLOT_RELATION_PROOF_FORMAT_VERSION: u64 = 3;
const DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS: usize = 4;
const DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS: u32 = 192;
const DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BYTES: usize = 24;
const DIRECT_BALLOT_RELATION_CLAIM_SOUNDNESS_TARGET_BITS: u32 = 128;
const DIRECT_BALLOT_RELATION_STATEMENT_QUERY_LOSS_BUDGET_BITS: u32 = 40;
const DIRECT_BALLOT_RELATION_QROM_LOSS_BUDGET_BITS: u32 = 64;
const DIRECT_BALLOT_FRI_ENTROPY_CAPACITY_QUERY_SOUNDNESS_PERMILLE: u32 = 930;
const DIRECT_BALLOT_QROM_DIGEST_BITS: u32 = 512;
const DIRECT_BALLOT_RELATION_MASK_COEFFICIENT_BITS: usize = 360;
const DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES: usize = 48;
const DIRECT_BALLOT_PROJECTED_BGV_NO_WRAP_CARRY_RESPONSE_BYTES: usize = 64;
const DIRECT_BALLOT_RELATION_WITNESS_BOUND_BITS: u32 = 16;
const DIRECT_BALLOT_RELATION_PROOF_GREEN_BYTES: usize = 5 * 1024 * 1024;
const DIRECT_BALLOT_RELATION_PROOF_YELLOW_BYTES: usize = 20 * 1024 * 1024;
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
    pub(super) relation_commitment_scalar_count: usize,
    pub(super) shared_response_polynomial_count: usize,
    pub(super) shared_response_scalar_count: usize,
    pub(super) proof_gate: &'static str,
}

#[derive(Debug)]
pub(super) struct DirectBallotRelationProofVerification {
    pub(super) proof_size_bytes: usize,
    pub(super) statement_hash_hex: String,
    pub(super) relation_commitment_hash_hex: String,
    pub(super) challenge: String,
}

#[derive(Clone)]
struct DirectBallotWitnessVector {
    randomizer_coefficients: Vec<BigInt>,
    error_zero_coefficients: Vec<BigInt>,
    error_one_coefficients: Vec<BigInt>,
    encoding_carry_coefficients: Vec<BigInt>,
    score_coefficients: Vec<BigInt>,
    one_hot_coefficients: Vec<Vec<BigInt>>,
    bgv_no_wrap_carry_scalars: Vec<BigInt>,
}

struct DirectBallotBgvRelationCommitment {
    component_zero: Vec<u64>,
    component_one: Vec<u64>,
}

struct DirectBallotScoreLinearCommitment {
    bucket_sums: Vec<BigInt>,
    weighted_differences: Vec<BigInt>,
}

struct ParsedDirectBallotRelationProof {
    challenge: BigInt,
    bgv_relation_commitments: Vec<DirectBallotBgvRelationCommitment>,
    score_linear_commitment: DirectBallotScoreLinearCommitment,
    response_vector: DirectBallotWitnessVector,
    committed_trace_proof_bytes: Vec<u8>,
    relation_commitment_hash: [u8; 64],
}
