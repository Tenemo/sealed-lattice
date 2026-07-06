use std::collections::BTreeSet;
mod aggregation;
mod command;
mod encryption;
mod evaluator_replay;
mod layout;
mod package;
mod proof_summary;
mod proof_transport;
mod randomness;
mod request;
mod setup_handoff;
mod target_proposal;
mod timing;
use aggregation::*;
pub(crate) use command::run_direct_encrypted_ballot;
use encryption::*;
// The end-to-end first-profile evidence test under target_decryption::tests
// replays a genuine ballot aggregate through this production evaluator path
// before releasing it through the proof-backed staged decryption commands.
pub(crate) use evaluator_replay::{
    DirectBallotPackedBatchedPairEvaluatorInput,
    run_direct_ballot_packed_batched_pair_evaluator_for_top_counts,
};
#[cfg(test)]
pub(crate) use evaluator_replay::{
    direct_ballot_comparison_domain_max, direct_ballot_evaluator_working_level,
    direct_ballot_plaintext_target_slots,
};
use proof_summary::*;
use proof_transport::*;
use randomness::*;
use request::*;
use target_proposal::*;
use timing::*;

use serde_json::{Value, json};

mod relation_proof;

use relation_proof::{
    DirectBallotRelationProofGeneration, direct_ballot_relation_proof_bytes_hash,
    direct_ballot_relation_proof_parameters_hash, generate_direct_ballot_relation_proof,
    verify_direct_ballot_relation_proof,
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
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, bgv_parameters_hash},
        setup::{
            development_evaluator_key_from_passive_setup_package,
            validate_passive_setup_package_for_encrypted_evaluation,
            validate_private_setup_seed_from_passive_setup_package,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, chunk_root, hash512_hex},
};

const OPERATION: &str = "runDirectEncryptedBallot";
const OPTION_COUNT: usize = 20;
// pub(crate): the setup-parameter identity binds the bounded-domain evaluator
// profile (score span times roster size) from these score-domain constants.
pub(crate) const MINIMUM_SCORE: u64 = 1;
pub(crate) const MAXIMUM_SCORE: u64 = 10;
const SCORE_BUCKET_COUNT: usize = (MAXIMUM_SCORE - MINIMUM_SCORE + 1) as usize;
const MAXIMUM_PROTOTYPE_BALLOTS: usize = 20;
const DEFAULT_EVALUATOR_WORKING_LEVEL: usize = SELECTED_EVALUATOR_WORKING_LEVEL;
const SINGLE_BALLOT_TARGET_WORKING_LEVEL: usize = 8;
const PROTOTYPE_PROOF_CHUNK_BYTES: usize = 1024 * 1024;

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
