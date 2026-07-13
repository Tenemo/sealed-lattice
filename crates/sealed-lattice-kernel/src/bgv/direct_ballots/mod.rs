#[cfg(test)]
mod aggregation;
#[cfg(test)]
mod encryption;
mod evaluator_replay;
#[cfg(test)]
mod request;
mod target_proposal;
#[cfg(test)]
use aggregation::*;
#[cfg(test)]
use encryption::*;
pub(crate) use evaluator_replay::{
    DirectBallotPackedBatchedPairEvaluatorInput,
    run_direct_ballot_packed_batched_pair_evaluator_for_top_counts,
};
#[cfg(test)]
pub(crate) use evaluator_replay::{
    direct_ballot_comparison_domain_max, direct_ballot_evaluator_working_level,
    direct_ballot_plaintext_target_slots,
};
#[cfg(test)]
use request::*;
use target_proposal::*;

use serde_json::{Value, json};

#[cfg(test)]
mod relation_proof;

#[cfg(test)]
use relation_proof::DirectBallotRelationProofGeneration;
#[cfg(test)]
use relation_proof::{generate_direct_ballot_relation_proof, verify_direct_ballot_relation_proof};

use crate::{
    bgv::{
        evaluator::{
            circuit::{EvaluatorContext, modulus_switch_to},
            engine::{
                Ciphertext, DevelopmentBgvKey, EncryptionWitness, ciphertext_add,
                ciphertext_object_root, encode_slots_to_coefficients, negacyclic_mul,
                signed_residue,
            },
            records::target_layout_hash,
            top_k::{
                SELECTED_EVALUATOR_WORKING_LEVEL,
                evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs,
                pack_direct_score_slots, project_packed_sparse_target_from_rank_evaluation,
            },
        },
        modular_arithmetic::add_mod,
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::hash512_hex,
};

const OPTION_COUNT: usize = 20;
// pub(crate): the setup-parameter identity binds the bounded-domain evaluator
// profile (score span times roster size) from these score-domain constants.
pub(crate) const MINIMUM_SCORE: u64 = 1;
pub(crate) const MAXIMUM_SCORE: u64 = 10;
const SCORE_BUCKET_COUNT: usize = (MAXIMUM_SCORE - MINIMUM_SCORE + 1) as usize;
const DEFAULT_EVALUATOR_WORKING_LEVEL: usize = SELECTED_EVALUATOR_WORKING_LEVEL;
const SINGLE_BALLOT_TARGET_WORKING_LEVEL: usize = 8;

#[cfg(test)]
#[derive(Clone)]
struct DirectBallotInput {
    voter_identity: String,
    action_context_hash: String,
    scores: Vec<u64>,
    one_hot_witnesses: Option<Vec<Vec<u64>>>,
    encryption_seed_hex: String,
}

#[cfg(test)]
#[derive(Clone)]
struct DirectEncryptedBallot {
    input: DirectBallotInput,
    plaintext_coefficients: Vec<u64>,
    ciphertext: Ciphertext,
    encryption_witness: EncryptionWitness,
    ciphertext_root: String,
}

#[cfg(test)]
struct DirectBallotAggregationResult {
    aggregate_ciphertext: Ciphertext,
}

#[cfg(test)]
mod tests;
