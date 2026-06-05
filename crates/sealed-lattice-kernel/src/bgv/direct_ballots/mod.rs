use std::collections::BTreeSet;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
mod aggregation;
mod command;
mod encryption;
mod evaluator_replay;
mod proof_transport;
mod request;
mod target_proposal;
use aggregation::*;
pub(crate) use command::run_direct_encrypted_ballot;
use encryption::*;
use evaluator_replay::*;
use proof_transport::*;
use request::*;
use target_proposal::*;

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
                TIE_POLICY, evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs,
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
const DIRECT_BALLOT_DEFAULT_EVALUATOR_WORKING_LEVEL: usize = 15;
const DIRECT_BALLOT_SINGLE_BALLOT_FULL_TARGET_WORKING_LEVEL: usize = 8;
const DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES: usize = 1024 * 1024;
const DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_FRESH_CSPRNG: &str = "fresh-csprng";
const DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE: &str =
    "development-deterministic-fixture";
const DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_HEX_BYTES: usize = 32;
const DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_FRESH_CSPRNG: &str = "fresh-csprng";
const DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE: &str =
    "development-deterministic-fixture";
const DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_HEX_BYTES: usize = 32;

#[cfg(not(target_arch = "wasm32"))]
struct DirectBallotTimingStart(Instant);

#[cfg(target_arch = "wasm32")]
struct DirectBallotTimingStart;

struct DirectBallotTimingTotal {
    milliseconds: Option<u128>,
}

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

#[derive(Clone, Copy, Eq, PartialEq)]
enum DirectBallotProofMaskRandomnessSource {
    FreshCsprng,
    DevelopmentDeterministicFixture,
}

struct DirectBallotProofMaskRandomness {
    source: DirectBallotProofMaskRandomnessSource,
    ballot_proof_randomness_hexes: Vec<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DirectBallotEncryptionRandomnessSource {
    FreshCsprng,
    DevelopmentDeterministicFixture,
}

struct DirectBallotEncryptionRandomness {
    source: DirectBallotEncryptionRandomnessSource,
    encryption_seed_hexes: Vec<String>,
}

struct DirectBallotRelationProofSummary {
    proof_size_bytes: usize,
    verified_proof_size_bytes: usize,
    proof_bytes_hash: String,
    statement_hash_hex: String,
    verified_statement_hash_hex: String,
    relation_commitment_hash_hex: String,
    verified_relation_commitment_hash_hex: String,
    challenge: String,
    verified_challenge: String,
    relation_commitment_bytes: usize,
    response_bytes: usize,
    relation_commitment_polynomial_count: usize,
    shared_response_polynomial_count: usize,
    shared_response_scalar_count: usize,
    proof_gate: &'static str,
    transported_proof_size_bytes: usize,
    transported_proof_bytes_hash: String,
    proof_chunk_count: usize,
    proof_chunk_merkle_root: String,
    proof_chunk_hashes: Vec<String>,
    public_proof_transport_hash: String,
}

struct DirectBallotBinaryProofTransport {
    proof_bytes: Vec<u8>,
    proof_size_bytes: usize,
    proof_bytes_hash: String,
    chunk_count: usize,
    chunk_merkle_root: String,
    chunk_hashes: Vec<String>,
    public_transport_hash: String,
}

impl DirectBallotTimingStart {
    fn now() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self(Instant::now())
        }
        #[cfg(target_arch = "wasm32")]
        {
            Self
        }
    }

    fn elapsed_milliseconds(&self) -> Option<u128> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Some(self.0.elapsed().as_millis())
        }
        #[cfg(target_arch = "wasm32")]
        {
            None
        }
    }
}

impl DirectBallotTimingTotal {
    fn new() -> Self {
        Self {
            milliseconds: Some(0),
        }
    }

    fn add(&mut self, elapsed_milliseconds: Option<u128>) {
        self.milliseconds = match (self.milliseconds, elapsed_milliseconds) {
            (Some(total), Some(elapsed)) => Some(total + elapsed),
            _ => None,
        };
    }

    fn report_value(&self) -> String {
        direct_ballot_timing_report_value(self.milliseconds)
    }
}

impl DirectBallotRelationProofSummary {
    fn from_verified_proof(
        proof_generation: DirectBallotRelationProofGeneration,
        proof_transport: DirectBallotBinaryProofTransport,
        proof_verification: DirectBallotRelationProofVerification,
    ) -> Self {
        Self {
            proof_size_bytes: proof_generation.proof_size_bytes,
            verified_proof_size_bytes: proof_verification.proof_size_bytes,
            proof_bytes_hash: proof_generation.proof_bytes_hash,
            statement_hash_hex: proof_generation.statement_hash_hex,
            verified_statement_hash_hex: proof_verification.statement_hash_hex,
            relation_commitment_hash_hex: proof_generation.relation_commitment_hash_hex,
            verified_relation_commitment_hash_hex: proof_verification.relation_commitment_hash_hex,
            challenge: proof_generation.challenge,
            verified_challenge: proof_verification.challenge,
            relation_commitment_bytes: proof_generation.relation_commitment_bytes,
            response_bytes: proof_generation.response_bytes,
            relation_commitment_polynomial_count: proof_generation
                .relation_commitment_polynomial_count,
            shared_response_polynomial_count: proof_generation.shared_response_polynomial_count,
            shared_response_scalar_count: proof_generation.shared_response_scalar_count,
            proof_gate: proof_generation.proof_gate,
            transported_proof_size_bytes: proof_transport.proof_size_bytes,
            transported_proof_bytes_hash: proof_transport.proof_bytes_hash,
            proof_chunk_count: proof_transport.chunk_count,
            proof_chunk_merkle_root: proof_transport.chunk_merkle_root,
            proof_chunk_hashes: proof_transport.chunk_hashes,
            public_proof_transport_hash: proof_transport.public_transport_hash,
        }
    }
}

impl DirectBallotProofMaskRandomnessSource {
    fn from_str(value: &str) -> CanonicalResult<Self> {
        match value {
            DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_FRESH_CSPRNG => Ok(Self::FreshCsprng),
            DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE => {
                Ok(Self::DevelopmentDeterministicFixture)
            }
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "proofMaskRandomness.source must be fresh-csprng or development-deterministic-fixture",
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::FreshCsprng => DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_FRESH_CSPRNG,
            Self::DevelopmentDeterministicFixture => {
                DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE
            }
        }
    }
}

impl DirectBallotProofMaskRandomness {
    fn ballot_proof_randomness_hex(&self, ballot_index: usize) -> CanonicalResult<&str> {
        self.ballot_proof_randomness_hexes
            .get(ballot_index)
            .map(String::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "proofMaskRandomness.ballotProofRandomnessHexes does not cover every ballot proof",
                )
            })
    }

    fn report_value(&self) -> Value {
        let source_statement = match self.source {
            DirectBallotProofMaskRandomnessSource::FreshCsprng => {
                "proof masks use caller-supplied fresh CSPRNG randomness; the Rust command validates shape and records only the source and counts"
            }
            DirectBallotProofMaskRandomnessSource::DevelopmentDeterministicFixture => {
                "proof masks use caller-supplied deterministic fixture randomness; this is development evidence only"
            }
        };

        json!({
            "source": self.source.as_str(),
            "ballotProofRandomnessCount": self.ballot_proof_randomness_hexes.len(),
            "randomnessBytesPerProof": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_HEX_BYTES,
            "retention": "proof-mask randomness is consumed to expand proof masks and is not returned in the report",
            "sourceStatement": source_statement
        })
    }
}

impl DirectBallotEncryptionRandomnessSource {
    fn from_str(value: &str) -> CanonicalResult<Self> {
        match value {
            DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_FRESH_CSPRNG => Ok(Self::FreshCsprng),
            DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE => {
                Ok(Self::DevelopmentDeterministicFixture)
            }
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "ballotEncryptionRandomness.source must be fresh-csprng or development-deterministic-fixture",
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::FreshCsprng => DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_FRESH_CSPRNG,
            Self::DevelopmentDeterministicFixture => {
                DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE
            }
        }
    }
}

impl DirectBallotEncryptionRandomness {
    fn encryption_seed_hex(&self, ballot_index: usize) -> CanonicalResult<&str> {
        self.encryption_seed_hexes
            .get(ballot_index)
            .map(String::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "ballotEncryptionRandomness.encryptionSeedHexes does not cover every ballot",
                )
            })
    }

    fn report_value(&self) -> Value {
        let source_statement = match self.source {
            DirectBallotEncryptionRandomnessSource::FreshCsprng => {
                "ballot encryption randomness uses caller-supplied fresh CSPRNG seed material; the Rust command validates shape and records only the source and count"
            }
            DirectBallotEncryptionRandomnessSource::DevelopmentDeterministicFixture => {
                "ballot encryption randomness uses caller-supplied deterministic fixture seed material; this is development evidence only"
            }
        };

        json!({
            "source": self.source.as_str(),
            "ballotEncryptionRandomnessCount": self.encryption_seed_hexes.len(),
            "randomnessBytesPerBallot": DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_HEX_BYTES,
            "retention": "ballot encryption seed material is consumed for encryption and is not returned in the report",
            "sourceStatement": source_statement
        })
    }
}

fn direct_ballot_timing_report_value(elapsed_milliseconds: Option<u128>) -> String {
    elapsed_milliseconds
        .map(|milliseconds| milliseconds.to_string())
        .unwrap_or_else(|| "not measured on wasm32-unknown-unknown".to_string())
}

fn direct_ballot_timing_status() -> &'static str {
    #[cfg(not(target_arch = "wasm32"))]
    {
        "measured"
    }
    #[cfg(target_arch = "wasm32")]
    {
        "not measured on wasm32-unknown-unknown"
    }
}

#[cfg(test)]
mod tests;
