use std::collections::BTreeSet;
mod aggregation;
mod command;
mod encryption;
mod evaluator_replay;
mod proof_summary;
mod proof_transport;
mod randomness;
mod request;
mod target_proposal;
mod timing;
use aggregation::*;
pub(crate) use command::run_direct_encrypted_ballot;
use encryption::*;
use evaluator_replay::*;
use proof_summary::*;
use proof_transport::*;
use randomness::*;
use request::*;
use target_proposal::*;
use timing::*;

use serde_json::{Value, json};

mod relation_proof;

use relation_proof::{
    DirectBallotRelationProofGeneration, DirectBallotRelationProofVerification,
    direct_ballot_relation_challenge_bits, direct_ballot_relation_proof_accounting,
    direct_ballot_relation_proof_bytes_hash, direct_ballot_relation_proof_profile_hash,
    generate_direct_ballot_relation_proof, verify_direct_ballot_relation_proof,
};

use crate::{
    bgv::{
        evaluator::{
            circuit::{EvaluatorContext, modulus_switch_to},
            engine::{
                Ciphertext, DevelopmentBgvKey, EncryptionWitness, ciphertext_add,
                ciphertext_canonical_bytes_hex, ciphertext_object_root,
                encode_slots_to_coefficients, negacyclic_mul, signed_residue,
            },
            records::target_layout_hash,
            top_k::{
                SELECTED_EVALUATOR_WORKING_LEVEL, TIE_POLICY,
                evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs,
                pack_direct_score_slots, packed_score_slot,
                project_packed_sparse_target_from_rank_evaluation,
            },
        },
        modular_arithmetic::add_mod,
        profile::{
            DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, PROFILE_ID,
            direct_comparison_profile_hash, profile_hash,
        },
        setup::{
            development_evaluator_key_from_passive_setup_package,
            validate_passive_setup_package_for_encrypted_evaluation,
            validate_private_setup_seed_from_passive_setup_package,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, chunk_root, derive_protocol_hash, hash512_hex},
};

const DIRECT_BALLOT_OPERATION: &str = "runDirectEncryptedBallot";
const DIRECT_BALLOT_OPTION_COUNT: usize = 20;
const DIRECT_BALLOT_MINIMUM_SCORE: u64 = 1;
const DIRECT_BALLOT_MAXIMUM_SCORE: u64 = 10;
const DIRECT_BALLOT_SCORE_BUCKET_COUNT: usize =
    (DIRECT_BALLOT_MAXIMUM_SCORE - DIRECT_BALLOT_MINIMUM_SCORE + 1) as usize;
const DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS: usize = 20;
const DIRECT_BALLOT_DEFAULT_EVALUATOR_WORKING_LEVEL: usize = SELECTED_EVALUATOR_WORKING_LEVEL;
const DIRECT_BALLOT_SINGLE_BALLOT_FULL_TARGET_WORKING_LEVEL: usize = 8;
const DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct DirectBallotInput {
    voter_identity: String,
    action_context_hash: String,
    scores: Vec<u64>,
    one_hot_witnesses: Option<Vec<Vec<u64>>>,
    encryption_seed_hex: String,
}

#[derive(Clone)]
struct DirectEncryptedBallot {
    input: DirectBallotInput,
    slots: Vec<u64>,
    plaintext_coefficients: Vec<u64>,
    ciphertext: Ciphertext,
    encryption_witness: EncryptionWitness,
    encrypted_ballot_hash: String,
    ciphertext_root: String,
    ciphertext_canonical_byte_length: usize,
}

struct DirectBallotAggregationResult {
    report: Value,
    aggregate_ciphertext: Ciphertext,
    aggregate_scores: Vec<u64>,
}

#[derive(Debug)]
struct DirectBallotTopCountRequest {
    top_counts: Vec<usize>,
    report_single_result: bool,
    target_finality_policy_hash: Option<String>,
}

#[cfg(test)]
mod tests;
