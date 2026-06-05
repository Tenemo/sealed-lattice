use std::collections::BTreeSet;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

use serde_json::{Value, json};

mod refresh_share_proof;
mod relation_proof;

use refresh_share_proof::{
    DirectBallotRefreshShareProofGeneration, DirectBallotRefreshShareStatement,
    direct_ballot_refresh_share_proof_accounting, direct_ballot_refresh_share_proof_bytes_hash,
    generate_direct_ballot_refresh_share_proof, verify_direct_ballot_refresh_share_proof,
};
use relation_proof::{
    DirectBallotRelationProofGeneration, DirectBallotRelationProofVerification,
    direct_ballot_relation_challenge_bits, direct_ballot_relation_proof_accounting,
    direct_ballot_relation_proof_bytes_hash, generate_direct_ballot_relation_proof,
    verify_direct_ballot_relation_proof,
};

use crate::{
    bgv::{
        evaluator::{
            circuit::{EvaluatorContext, modulus_switch_to, normalize_scaling},
            engine::{
                Ciphertext, DevelopmentBgvKey, EncryptionWitness, add_plaintext_coefficients,
                ciphertext_add, ciphertext_canonical_bytes_hex, ciphertext_object_root,
                decryption_accumulator_to_slots, encode_slots_to_coefficients, negacyclic_mul,
                signed_residue,
            },
            prg::DeterministicSampler,
            top_k::{
                evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs,
                pack_direct_score_slots, packed_score_slot, project_packed_sparse_target,
                project_packed_sparse_target_from_rank_evaluation,
            },
        },
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        profile::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, PROFILE_ID, profile_hash},
        setup::{
            development_evaluator_key_from_passive_setup_package,
            development_threshold_secret_shares_from_passive_setup_package,
            validate_passive_setup_package_for_encrypted_evaluation,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, chunk_root, hash512_hex},
};

const DIRECT_BALLOT_OPERATION: &str = "runDirectEncryptedBallotPrototype";
const DIRECT_BALLOT_OPTION_COUNT: usize = 20;
const DIRECT_BALLOT_MINIMUM_SCORE: u64 = 1;
const DIRECT_BALLOT_MAXIMUM_SCORE: u64 = 10;
const DIRECT_BALLOT_PROOF_RING_DEGREE: usize = 64;
const DIRECT_BALLOT_RNS_LIMB_PROOF_COLUMNS: usize = 4;
const DIRECT_BALLOT_RNS_LIMB_PROOF_ROWS: usize = 2;
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

struct DirectEncryptedBallot {
    input: DirectBallotInput,
    slots: Vec<u64>,
    plaintext_coefficients: Vec<u64>,
    ciphertext: Ciphertext,
    encryption_witness: EncryptionWitness,
    ballot_package_hash: String,
    ciphertext_root: String,
    ciphertext_canonical_byte_length: usize,
}

struct DirectBallotAggregationResult {
    report: Value,
    aggregate_ciphertext: Ciphertext,
    aggregate_scores: Vec<u64>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DirectBallotProofMaskRandomnessSource {
    FreshCsprng,
    DevelopmentDeterministicFixture,
}

struct DirectBallotProofMaskRandomness {
    source: DirectBallotProofMaskRandomnessSource,
    ballot_proof_randomness_hexes: Vec<String>,
    refresh_share_proof_randomness_hexes: Vec<String>,
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
}

struct DirectBallotBinaryProofTransport {
    proof_bytes: Vec<u8>,
    proof_size_bytes: usize,
    proof_bytes_hash: String,
    chunk_count: usize,
    chunk_merkle_root: String,
}

struct DirectBallotRankRefreshResult {
    refreshed_packed_ranks: Ciphertext,
    report: Value,
}

#[derive(Debug)]
struct DirectBallotThresholdMaskedOpening {
    opened_masked_rank_slots: Vec<u64>,
    report: Value,
}

struct DirectBallotMaskedRankShareSubmission {
    trustee_identity: String,
    roster_position: usize,
    recovery_epoch: u64,
    device_epoch: u64,
    participant_setup_record_hash: String,
    trustee_threshold_verification_key_hash: String,
    threshold_share_verification_key_hash: String,
    public_key_share_component_zero: Vec<Vec<u64>>,
    decryption_share_coefficients: Vec<Vec<u64>>,
    proof: DirectBallotRefreshShareProofGeneration,
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

    fn refresh_share_proof_randomness_hex(&self, share_index: usize) -> CanonicalResult<&str> {
        self.refresh_share_proof_randomness_hexes
            .get(share_index)
            .map(String::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "proofMaskRandomness.refreshShareProofRandomnessHexes does not cover every refresh-share proof",
                )
            })
    }

    fn validate_refresh_share_count(&self, share_count: usize) -> CanonicalResult<()> {
        if self.refresh_share_proof_randomness_hexes.len() != share_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "proofMaskRandomness.refreshShareProofRandomnessHexes length must match the submitted refresh-share proof count",
            ));
        }

        Ok(())
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
            "refreshShareProofRandomnessCount": self.refresh_share_proof_randomness_hexes.len(),
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

fn chunk_count_for_bytes(byte_count: usize, chunk_size_bytes: usize) -> CanonicalResult<usize> {
    if chunk_size_bytes == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proof transport chunk size must be positive",
        ));
    }
    byte_count
        .checked_add(chunk_size_bytes - 1)
        .map(|rounded| rounded / chunk_size_bytes)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "proof transport chunk count overflowed",
            )
        })
}

fn transport_direct_ballot_binary_proof(
    proof_bytes: &[u8],
    expected_proof_bytes_hash: &str,
    proof_bytes_hash: fn(&[u8]) -> String,
    label: &str,
) -> CanonicalResult<DirectBallotBinaryProofTransport> {
    if proof_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} transport requires non-empty binary proof bytes"),
        ));
    }
    let chunk_count =
        chunk_count_for_bytes(proof_bytes.len(), DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)?;
    let mut transported_proof_bytes = Vec::with_capacity(proof_bytes.len());
    let mut observed_chunk_count = 0_usize;
    for (chunk_index, chunk) in proof_bytes
        .chunks(DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)
        .enumerate()
    {
        if chunk.is_empty() || chunk.len() > DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} transport produced a malformed chunk"),
            ));
        }
        if chunk_index + 1 < chunk_count && chunk.len() != DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} transport has a short non-final chunk"),
            ));
        }
        transported_proof_bytes.extend_from_slice(chunk);
        observed_chunk_count = observed_chunk_count.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} transport chunk count overflowed"),
            )
        })?;
    }
    if observed_chunk_count != chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} transport chunk count does not match the byte length"),
        ));
    }
    let transported_proof_bytes_hash = proof_bytes_hash(&transported_proof_bytes);
    if transported_proof_bytes_hash != expected_proof_bytes_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{label} transported proof bytes do not match the proof hash"),
        ));
    }
    let chunk_merkle_root = chunk_root(
        &transported_proof_bytes,
        DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
    )?;

    Ok(DirectBallotBinaryProofTransport {
        proof_size_bytes: transported_proof_bytes.len(),
        proof_bytes: transported_proof_bytes,
        proof_bytes_hash: transported_proof_bytes_hash,
        chunk_count,
        chunk_merkle_root,
    })
}

pub(crate) fn run_direct_encrypted_ballot_prototype(request: &Value) -> CanonicalResult<Value> {
    let setup_package = required_object_field(request, "setupPackage")?;
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    let private_setup_seed =
        required_string_path(request, &["setupPrivateWitness", "setupSeed"])?.to_string();
    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, &private_setup_seed)?;

    let (ballots, ballot_encryption_randomness) = read_ballots(request)?;
    if ballots.len() > DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot proof experiment currently supports at most twenty ballots",
        ));
    }
    validate_direct_ballot_batch_order(&ballots)?;
    let mut encrypted_ballots = Vec::with_capacity(ballots.len());
    for ballot in ballots {
        let encrypted_ballot = encrypt_direct_ballot(
            setup_package,
            &evaluator_key,
            ballot,
            encrypted_ballots.len(),
        )?;
        validate_direct_ballot_preflight(&evaluator_key, &encrypted_ballot)?;
        encrypted_ballots.push(encrypted_ballot);
    }
    let proof_mask_randomness =
        read_direct_ballot_proof_mask_randomness(request, encrypted_ballots.len())?;

    let mut proof_summaries = Vec::with_capacity(encrypted_ballots.len());
    let mut total_proving_time_milliseconds = DirectBallotTimingTotal::new();
    let mut total_verification_time_milliseconds = DirectBallotTimingTotal::new();
    for (ballot_index, encrypted_ballot) in encrypted_ballots.iter().enumerate() {
        let proof_randomness_hex =
            proof_mask_randomness.ballot_proof_randomness_hex(ballot_index)?;
        let proof_generation_started = DirectBallotTimingStart::now();
        let proof_generation = generate_direct_ballot_relation_proof(
            setup_package,
            &evaluator_key,
            encrypted_ballot,
            proof_randomness_hex,
        )?;
        let proof_transport = transport_direct_ballot_binary_proof(
            &proof_generation.proof_bytes,
            &proof_generation.proof_bytes_hash,
            direct_ballot_relation_proof_bytes_hash,
            "direct ballot relation proof",
        )?;
        total_proving_time_milliseconds.add(proof_generation_started.elapsed_milliseconds());
        let proof_verification_started = DirectBallotTimingStart::now();
        let proof_verification = verify_direct_ballot_relation_proof(
            setup_package,
            &evaluator_key,
            encrypted_ballot,
            &proof_transport.proof_bytes,
        )?;
        total_verification_time_milliseconds.add(proof_verification_started.elapsed_milliseconds());
        proof_summaries.push(DirectBallotRelationProofSummary::from_verified_proof(
            proof_generation,
            proof_transport,
            proof_verification,
        ));
    }
    let first_proof = proof_summaries.first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot proof experiment requires at least one proof",
        )
    })?;
    let total_proof_bytes = proof_summaries
        .iter()
        .map(|proof_summary| proof_summary.proof_size_bytes)
        .sum::<usize>();
    let aggregation_result = verify_direct_ballot_aggregation(&evaluator_key, &encrypted_ballots)?;
    let evaluator_replay = match optional_direct_ballot_top_count(request)? {
        Some(top_count) => run_direct_ballot_packed_batched_pair_evaluator(
            setup_package,
            &evaluator_key,
            &private_setup_seed,
            &proof_mask_randomness,
            &aggregation_result.aggregate_ciphertext,
            &aggregation_result.aggregate_scores,
            encrypted_ballots.len(),
            top_count,
        )?,
        None => json!(
            "Not run in this command. Supply topCount to attempt the packed batched-pair evaluator route over the direct aggregate."
        ),
    };

    let ciphertext_byte_lengths = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ciphertext_canonical_byte_length)
        .collect::<Vec<_>>();
    let ballot_package_hashes = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ballot_package_hash.clone())
        .collect::<Vec<_>>();
    let ciphertext_roots = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ciphertext_root.clone())
        .collect::<Vec<_>>();

    Ok(json!({
        "operation": DIRECT_BALLOT_OPERATION,
        "profile": {
            "profileId": PROFILE_ID,
            "profileHash": profile_hash()?,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "dataPrimeCount": DATA_PRIMES.len()
        },
        "ballotLayout": {
            "optionCount": DIRECT_BALLOT_OPTION_COUNT,
            "scoreSlots": "slots 0 through 19 hold one scalar score per option",
            "reservedSlots": "all remaining slots are zero before encryption",
            "scoreRange": "scores must be integers from 1 through 10"
        },
        "input": {
            "ballotCount": encrypted_ballots.len()
        },
        "ballotPackages": {
            "packageHashes": ballot_package_hashes,
            "ciphertextRoots": ciphertext_roots,
            "ciphertextCanonicalByteLengths": ciphertext_byte_lengths,
            "ballotEncryptionRandomness": ballot_encryption_randomness.report_value(),
            "result": "Direct score slots, one-hot witnesses, batch encoding, all data-limb encryption algebra, and reserved zero slots passed private preflight."
        },
        "proofAttempt": {
            "relation": "all BGV data-prime encryption equations for c0=b*u+p*e0+encode(score) and c1=a*u+p*e1, with score-to-encoding carry linkage",
            "coverage": "all RNS limb encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support are checked by one internal binary transcript; support-union and mask-shift accounting are included for proof-of-concept sizing",
            "proofEncoding": "internal binary feasibility encoding",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "proofRingDegree": DIRECT_BALLOT_PROOF_RING_DEGREE,
            "rnsLimbCount": DATA_PRIMES.len(),
            "statementRowsPerLimb": DIRECT_BALLOT_RNS_LIMB_PROOF_ROWS,
            "statementColumnsPerLimb": DIRECT_BALLOT_RNS_LIMB_PROOF_COLUMNS,
            "totalRnsEquationRows": DATA_PRIMES.len() * DIRECT_BALLOT_RNS_LIMB_PROOF_ROWS,
            "sharedShortResponseVectorLength": direct_ballot_shared_short_response_vector_length(),
            "duplicatedShortResponseVectorLength": direct_ballot_duplicated_short_response_vector_length(),
            "binaryRelationCommitmentBytes": first_proof.relation_commitment_bytes,
            "binarySharedResponseBytes": first_proof.response_bytes,
            "proofCount": proof_summaries.len(),
            "proofSizeBytes": first_proof.proof_size_bytes,
            "verifiedProofSizeBytes": first_proof.verified_proof_size_bytes,
            "totalProofBytes": total_proof_bytes,
            "proofBytesHash": first_proof.proof_bytes_hash,
            "statementHash": first_proof.statement_hash_hex,
            "verifiedStatementHash": first_proof.verified_statement_hash_hex,
            "relationCommitmentHash": first_proof.relation_commitment_hash_hex,
            "verifiedRelationCommitmentHash": first_proof.verified_relation_commitment_hash_hex,
            "challenge": first_proof.challenge.to_string(),
            "verifiedChallenge": first_proof.verified_challenge.to_string(),
            "challengeSoundness": format!("single {}-bit challenge; support-degree union accounting and mask-shift accounting are reported for proof-of-concept sizing, while Fiat-Shamir/QROM review remains open and the proof-mask randomness source is reported separately", direct_ballot_relation_challenge_bits()),
            "proofAccounting": direct_ballot_relation_proof_accounting(first_proof.proof_size_bytes, total_proof_bytes)?,
            "proofTransport": {
                "encoding": "binary proof chunks",
                "status": "each generated proof is framed into fixed-size binary chunks, hash-checked, reassembled, and verified from the transported bytes",
                "retention": "proof chunks and reassembled proof bytes are verified and then dropped; the report keeps hashes, sizes, chunk counts, and chunk Merkle roots only",
                "chunkSizeBytes": DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
                "chunksPerProof": first_proof.proof_chunk_count,
                "chunksForBatch": chunk_count_for_bytes(total_proof_bytes, DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)?,
                "transportedProofSizeBytes": first_proof.transported_proof_size_bytes,
                "transportedProofBytesHash": first_proof.transported_proof_bytes_hash,
                "firstProofChunkMerkleRoot": first_proof.proof_chunk_merkle_root
            },
            "proofMaskRandomness": proof_mask_randomness.report_value(),
            "relationCommitmentPolynomialCount": first_proof.relation_commitment_polynomial_count,
            "sharedResponsePolynomialCount": first_proof.shared_response_polynomial_count,
            "sharedScoreResponseScalarCount": first_proof.shared_response_scalar_count,
            "responseSharing": "one binary response vector is checked against all 17 RNS limb equations, score-linear constraints, and support constraints; response bytes are not duplicated per limb",
            "timingStatus": direct_ballot_timing_status(),
            "provingTimeMilliseconds": total_proving_time_milliseconds.report_value(),
            "verificationTimeMilliseconds": total_verification_time_milliseconds.report_value(),
            "proofGate": first_proof.proof_gate,
            "generation": "Generated and verified one internal binary proof for the all-limb BGV encryption relation, score-linear constraints, and support constraints. The widened transcript removes the naive repetition requirement for proof-of-concept sizing, but this is not public claim-bearing ballot validity.",
            "fullRnsCoverage": "The proof covers all 17 BGV RNS limbs with one shared randomizer, error, encoding-carry, score, and one-hot response vector.",
            "blocker": "Next missing pieces are Fiat-Shamir/QROM review, mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, public accepted proof transport outside this internal command, public accepted ballot encryption randomness rules, and the target-only decryption security model. Runs using development-deterministic-fixture proof masks or ballot-encryption randomness remain fixture evidence only."
        },
        "aggregation": aggregation_result.report,
        "evaluatorReplay": evaluator_replay,
        "decision": "Direct BGV ballot encryption, all-limb private preflight, one widened shared-response validity proof, direct ciphertext aggregation, binary chunk proof transport inside the prototype command, and supplied top-count evaluator replay work on the prototype path. They are still feasibility evidence until Fiat-Shamir/QROM review, mobile evidence, browser/mobile proof-copy evidence, mobile memory evidence, public accepted proof transport, and the target-only decryption security model close."
    }))
}

fn encrypt_direct_ballot(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    ballot: DirectBallotInput,
    _ballot_index: usize,
) -> CanonicalResult<DirectEncryptedBallot> {
    validate_direct_ballot_input(&ballot)?;
    let slots = direct_ballot_slots(&ballot.scores);
    let plaintext_coefficients = encode_slots_to_coefficients(&slots)?;
    let (ciphertext, encryption_witness) = evaluator_key
        .encrypt_coefficients_with_witness(&plaintext_coefficients, &ballot.encryption_seed_hex)?;
    let ciphertext_root = ciphertext_object_root(&ciphertext)?;
    let ciphertext_canonical_bytes_hex = ciphertext_canonical_bytes_hex(&ciphertext)?;
    let ballot_package_hash = direct_ballot_package_hash(
        setup_package,
        &ballot,
        &ciphertext_root,
        ciphertext_canonical_bytes_hex.len() / 2,
    )?;

    Ok(DirectEncryptedBallot {
        input: ballot,
        slots,
        plaintext_coefficients,
        ciphertext,
        encryption_witness,
        ballot_package_hash,
        ciphertext_root,
        ciphertext_canonical_byte_length: ciphertext_canonical_bytes_hex.len() / 2,
    })
}

fn validate_direct_ballot_input(ballot: &DirectBallotInput) -> CanonicalResult<()> {
    if ballot.scores.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot requires exactly twenty scores",
        ));
    }
    for (option_index, score) in ballot.scores.iter().enumerate() {
        if !(DIRECT_BALLOT_MINIMUM_SCORE..=DIRECT_BALLOT_MAXIMUM_SCORE).contains(score) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "direct encrypted ballot score at option {option_index} must be between 1 and 10"
                ),
            ));
        }
    }
    if let Some(one_hot_witnesses) = &ballot.one_hot_witnesses {
        validate_one_hot_witnesses(&ballot.scores, one_hot_witnesses)?;
    }

    Ok(())
}

fn validate_one_hot_witnesses(
    scores: &[u64],
    one_hot_witnesses: &[Vec<u64>],
) -> CanonicalResult<()> {
    if one_hot_witnesses.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot one-hot witness must have one row per option",
        ));
    }
    for (option_index, one_hot_row) in one_hot_witnesses.iter().enumerate() {
        if one_hot_row.len() != usize::try_from(DIRECT_BALLOT_MAXIMUM_SCORE).unwrap() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot one-hot witness rows must have ten entries",
            ));
        }
        if one_hot_row.iter().any(|entry| *entry > 1) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness entries must be zero or one",
            ));
        }
        let one_hot_sum = one_hot_row.iter().sum::<u64>();
        if one_hot_sum != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness must select exactly one score",
            ));
        }
        let derived_score = one_hot_row
            .iter()
            .enumerate()
            .map(|(score_index, indicator)| {
                u64::try_from(score_index + 1).expect("score index fits u64") * indicator
            })
            .sum::<u64>();
        if derived_score != scores[option_index] {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness does not match its scalar score",
            ));
        }
    }

    Ok(())
}

fn validate_direct_ballot_preflight(
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    if ballot.slots.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot slot vector must match the polynomial degree",
        ));
    }
    if ballot.slots[DIRECT_BALLOT_OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot reserved slots must be zero",
        ));
    }
    let decrypted_slots = evaluator_key.decrypt_to_slots(&ballot.ciphertext)?;
    if decrypted_slots[..DIRECT_BALLOT_OPTION_COUNT] != ballot.input.scores[..] {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot does not decrypt to the submitted score slots",
        ));
    }
    if decrypted_slots[DIRECT_BALLOT_OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot decrypts to a non-zero reserved slot",
        ));
    }
    validate_encryption_witness_support(&ballot.encryption_witness)?;
    validate_all_limb_encryption_relation(evaluator_key, ballot)
}

fn validate_encryption_witness_support(witness: &EncryptionWitness) -> CanonicalResult<()> {
    validate_signed_support(
        &witness.randomizer_coefficients,
        1,
        "direct encrypted ballot randomizer",
    )?;
    validate_signed_support(
        &witness.error_zero_coefficients,
        2,
        "direct encrypted ballot first error polynomial",
    )?;
    validate_signed_support(
        &witness.error_one_coefficients,
        2,
        "direct encrypted ballot second error polynomial",
    )
}

fn validate_signed_support(
    coefficients: &[i64],
    maximum_abs: i64,
    label: &str,
) -> CanonicalResult<()> {
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} must match the polynomial degree"),
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| coefficient.abs() > maximum_abs)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{label} has a coefficient outside the expected support"),
        ));
    }

    Ok(())
}

fn validate_all_limb_encryption_relation(
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    let (public_component_zero, public_component_one) = evaluator_key.public_key_components();
    if ballot.ciphertext.components.len() != 2
        || ballot.ciphertext.components[0].len() != DATA_PRIMES.len()
        || ballot.ciphertext.components[1].len() != DATA_PRIMES.len()
        || public_component_zero.len() != DATA_PRIMES.len()
        || public_component_one.len() != DATA_PRIMES.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot RNS limb relation requires two full data-prime ciphertext components and a full public key",
        ));
    }
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        validate_limb_encryption_relation(
            ballot,
            public_component_zero,
            public_component_one,
            limb_index,
            modulus,
        )?;
    }

    Ok(())
}

fn validate_limb_encryption_relation(
    ballot: &DirectEncryptedBallot,
    public_component_zero: &[Vec<u64>],
    public_component_one: &[Vec<u64>],
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<()> {
    let randomizer_residues = ballot
        .encryption_witness
        .randomizer_coefficients
        .iter()
        .map(|coefficient| signed_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let public_key_product = negacyclic_mul(
        &public_component_zero[limb_index],
        &randomizer_residues,
        modulus,
    )?;
    let public_sample_product = negacyclic_mul(
        &public_component_one[limb_index],
        &randomizer_residues,
        modulus,
    )?;
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let expected_component_zero = add_mod(
            add_mod(
                public_key_product[coefficient_index],
                signed_residue(
                    ballot.encryption_witness.error_zero_coefficients[coefficient_index]
                        * i64::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits i64"),
                    modulus,
                ),
                modulus,
            )?,
            ballot.plaintext_coefficients[coefficient_index],
            modulus,
        )?;
        if expected_component_zero != ballot.ciphertext.components[0][limb_index][coefficient_index]
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("direct encrypted ballot RNS limb {limb_index} c0 relation failed"),
            ));
        }
        let expected_component_one = add_mod(
            public_sample_product[coefficient_index],
            signed_residue(
                ballot.encryption_witness.error_one_coefficients[coefficient_index]
                    * i64::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits i64"),
                modulus,
            ),
            modulus,
        )?;
        if expected_component_one != ballot.ciphertext.components[1][limb_index][coefficient_index]
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("direct encrypted ballot RNS limb {limb_index} c1 relation failed"),
            ));
        }
    }

    Ok(())
}

fn direct_ballot_shared_short_response_vector_length() -> usize {
    DIRECT_BALLOT_RNS_LIMB_PROOF_COLUMNS * (POLYNOMIAL_DEGREE / DIRECT_BALLOT_PROOF_RING_DEGREE) + 1
}

fn direct_ballot_duplicated_short_response_vector_length() -> usize {
    direct_ballot_shared_short_response_vector_length() * DATA_PRIMES.len()
}

fn verify_direct_ballot_aggregation(
    evaluator_key: &DevelopmentBgvKey,
    encrypted_ballots: &[DirectEncryptedBallot],
) -> CanonicalResult<DirectBallotAggregationResult> {
    let mut aggregate_ciphertext = encrypted_ballots
        .first()
        .map(|ballot| ballot.ciphertext.clone())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot aggregation requires at least one ballot",
            )
        })?;
    for encrypted_ballot in encrypted_ballots.iter().skip(1) {
        aggregate_ciphertext = ciphertext_add(&aggregate_ciphertext, &encrypted_ballot.ciphertext)?;
    }

    let aggregate_slots = evaluator_key.decrypt_to_slots(&aggregate_ciphertext)?;
    let aggregate_scores = aggregate_slots[..DIRECT_BALLOT_OPTION_COUNT].to_vec();
    let expected_scores = direct_ballot_plaintext_aggregate_scores(encrypted_ballots)?;
    if aggregate_scores != expected_scores {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot aggregate scores do not match the plaintext oracle",
        ));
    }
    if aggregate_slots[DIRECT_BALLOT_OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot aggregate has a non-zero reserved slot",
        ));
    }
    let aggregate_ciphertext_root = ciphertext_object_root(&aggregate_ciphertext)?;
    let aggregate_ciphertext_canonical_bytes_hex =
        ciphertext_canonical_bytes_hex(&aggregate_ciphertext)?;

    let report = json!({
        "result": "Verified the supplied direct ballot proofs, aggregated their ciphertexts, and test-decrypted aggregate score slots to the plaintext oracle.",
        "ballotCount": encrypted_ballots.len(),
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "aggregateCiphertextCanonicalByteLength": aggregate_ciphertext_canonical_bytes_hex.len() / 2,
        "aggregateScores": aggregate_scores,
        "plaintextOracleScores": expected_scores
    });

    Ok(DirectBallotAggregationResult {
        report,
        aggregate_ciphertext,
        aggregate_scores,
    })
}

fn run_direct_ballot_packed_batched_pair_evaluator(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    private_setup_seed: &str,
    proof_mask_randomness: &DirectBallotProofMaskRandomness,
    aggregate_ciphertext: &Ciphertext,
    aggregate_scores: &[u64],
    ballot_count: usize,
    top_count: usize,
) -> CanonicalResult<Value> {
    let mut evaluations = run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
        setup_package,
        evaluator_key,
        private_setup_seed,
        proof_mask_randomness,
        aggregate_ciphertext,
        aggregate_scores,
        ballot_count,
        &[top_count],
    )?;

    Ok(evaluations.remove(0))
}

fn run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    private_setup_seed: &str,
    proof_mask_randomness: &DirectBallotProofMaskRandomness,
    aggregate_ciphertext: &Ciphertext,
    aggregate_scores: &[u64],
    ballot_count: usize,
    top_counts: &[usize],
) -> CanonicalResult<Vec<Value>> {
    if top_counts.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot evaluator requires at least one top count",
        ));
    }
    let score_domain_max = direct_ballot_comparison_domain_max(ballot_count)?;
    let aggregate_ciphertext_root = ciphertext_object_root(aggregate_ciphertext)?;
    let top_count_seed = top_counts
        .iter()
        .map(|top_count| top_count.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let replay_seed = hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/packed-batched-pair-evaluator-seed-v1",
        &[
            private_setup_seed.as_bytes(),
            aggregate_ciphertext_root.as_bytes(),
            top_count_seed.as_bytes(),
        ],
    );
    let working_level = direct_ballot_evaluator_working_level(ballot_count);
    let context = EvaluatorContext::from_key(evaluator_key.clone(), &replay_seed, working_level)?;
    let working_aggregate = modulus_switch_to(aggregate_ciphertext, context.working_level())?;
    let replay_started = DirectBallotTimingStart::now();
    let packed_scores = pack_direct_score_slots(
        &context,
        &working_aggregate,
        DIRECT_BALLOT_OPTION_COUNT,
        &replay_seed,
    )?;
    let packed_score_root = ciphertext_object_root(&packed_scores)?;
    drop(working_aggregate);
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        DIRECT_BALLOT_OPTION_COUNT,
        score_domain_max,
        &replay_seed,
    )?;
    drop(packed_scores);
    let rank_root = ciphertext_object_root(&rank_evaluation.packed_ranks)?;

    let rank_refresh = if top_counts
        .iter()
        .any(|top_count| *top_count != DIRECT_BALLOT_OPTION_COUNT)
    {
        Some(refresh_direct_ballot_packed_ranks_with_masked_opening(
            setup_package,
            private_setup_seed,
            proof_mask_randomness,
            evaluator_key,
            &rank_evaluation.packed_ranks,
            DIRECT_BALLOT_OPTION_COUNT,
            &replay_seed,
        )?)
    } else {
        None
    };

    let mut evaluations = Vec::with_capacity(top_counts.len());
    for top_count in top_counts {
        let (target, target_projection) = if *top_count == DIRECT_BALLOT_OPTION_COUNT {
            (
                project_packed_sparse_target_from_rank_evaluation(
                    &context,
                    &rank_evaluation,
                    DIRECT_BALLOT_OPTION_COUNT,
                    *top_count,
                )?,
                "Projected the full-order target directly from packed ranks; this path is linear for topCount equal to the option count.",
            )
        } else {
            let rank_refresh = rank_refresh.as_ref().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "masked rank refresh was not prepared for prefix target projection",
                )
            })?;
            (
                project_packed_sparse_target(
                    &context,
                    &rank_refresh.refreshed_packed_ranks,
                    DIRECT_BALLOT_OPTION_COUNT,
                    *top_count,
                )?,
                "Development masked rank refresh: masked packed ranks were opened, unmasked internally, and re-encrypted before sparse target projection. This measures the prefix target shape after rank noise is removed and remains a stand-in for a threshold masked refresh.",
            )
        };
        let replay_time_milliseconds = replay_started.elapsed_milliseconds();
        let target_id_slots = evaluator_key.decrypt_to_slots(&target.target_id)?;
        let target_order_slots = evaluator_key.decrypt_to_slots(&target.target_order)?;
        let decoded_target_ids = direct_packed_option_slots(&target_id_slots);
        let decoded_target_orders = direct_packed_option_slots(&target_order_slots);
        let (oracle_target_ids, oracle_target_orders) =
            direct_ballot_plaintext_target_slots(aggregate_scores, *top_count)?;
        if decoded_target_ids != oracle_target_ids || decoded_target_orders != oracle_target_orders
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot packed batched-pair evaluator did not match the plaintext target oracle",
            ));
        }

        evaluations.push(json!({
            "result": "Replayed the packed batched-pair encrypted evaluator over the direct aggregate and test-decrypted the sparse target to the plaintext oracle.",
            "topCount": top_count,
            "scoreDomainMax": score_domain_max,
            "workingLevel": context.working_level(),
            "packedScoreRoot": packed_score_root.clone(),
            "rankRoot": rank_root.clone(),
            "targetProjection": target_projection,
            "rankRefresh": rank_refresh.as_ref().map(|refresh| refresh.report.clone()).unwrap_or_else(|| json!("Not used for full-order projection.")),
            "targetIdRoot": ciphertext_object_root(&target.target_id)?,
            "targetOrderRoot": ciphertext_object_root(&target.target_order)?,
            "decodedTargetIds": decoded_target_ids,
            "decodedTargetOrders": decoded_target_orders,
            "plaintextOracleTargetIds": oracle_target_ids,
            "plaintextOracleTargetOrders": oracle_target_orders,
            "timingStatus": direct_ballot_timing_status(),
            "replayTimeMilliseconds": direct_ballot_timing_report_value(replay_time_milliseconds)
        }));
    }

    Ok(evaluations)
}

fn direct_packed_option_slots(slots: &[u64]) -> Vec<u64> {
    (0..DIRECT_BALLOT_OPTION_COUNT)
        .map(|option| slots[packed_score_slot(option)])
        .collect()
}

fn refresh_direct_ballot_packed_ranks_with_masked_opening(
    setup_package: &Value,
    private_setup_seed: &str,
    proof_mask_randomness: &DirectBallotProofMaskRandomness,
    evaluator_key: &DevelopmentBgvKey,
    packed_ranks: &Ciphertext,
    option_count: usize,
    seed_hex: &str,
) -> CanonicalResult<DirectBallotRankRefreshResult> {
    if option_count == 0 || option_count > DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "masked rank refresh requires a supported option count",
        ));
    }
    let rank_root = ciphertext_object_root(packed_ranks)?;
    let mut sampler = DeterministicSampler::new(
        "sealed-lattice/direct-encrypted-ballot/masked-rank-refresh-mask-v1",
        &[seed_hex.as_bytes(), rank_root.as_bytes()],
    );
    let mask_slots = sampler.uniform_residues(PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE);
    let mask_coefficients = encode_slots_to_coefficients(&mask_slots)?;
    let masked_ranks =
        add_plaintext_coefficients(&normalize_scaling(packed_ranks)?, &mask_coefficients)?;
    let threshold_opening = open_direct_ballot_masked_ranks_with_threshold_shares(
        setup_package,
        private_setup_seed,
        proof_mask_randomness,
        evaluator_key,
        &rank_root,
        &masked_ranks,
    )?;
    let DirectBallotThresholdMaskedOpening {
        opened_masked_rank_slots,
        report: threshold_opening_report,
    } = threshold_opening;
    let refreshed_rank_slots = opened_masked_rank_slots
        .iter()
        .zip(mask_slots.iter())
        .map(|(opened, mask)| sub_mod(*opened, *mask, PLAINTEXT_MODULUS))
        .collect::<CanonicalResult<Vec<_>>>()?;
    for option in 0..option_count {
        let rank = refreshed_rank_slots[packed_score_slot(option)];
        if rank >= u64::try_from(option_count).expect("option count fits u64") {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "masked rank refresh opened a rank outside the expected option domain",
            ));
        }
    }
    let refreshed_packed_ranks = evaluator_key.encrypt_slots(
        &refreshed_rank_slots,
        &format!("{seed_hex}-masked-rank-refresh-reencryption"),
    )?;
    let mask_commitment_hash = direct_ballot_internal_report_hash(
        "masked-rank-refresh-mask-commitment",
        &json!({
            "rankRoot": rank_root.clone(),
            "optionCount": option_count,
            "maskSlots": mask_slots
        }),
    )?;
    let opened_masked_rank_hash = direct_ballot_internal_report_hash(
        "masked-rank-opening",
        &json!({
            "rankRoot": rank_root.clone(),
            "optionCount": option_count,
            "openedMaskedRankSlots": opened_masked_rank_slots
        }),
    )?;
    let report = json!({
        "refresh": "Masked packed ranks, opened the masked slots by verifying submitted trustee refresh-share proofs, unmasked internally, and re-encrypted packed ranks for prefix target projection.",
        "status": "Internal refresh evidence. The mask, opened masked ranks, unmasked ranks, submitted share coefficients, public-key share coefficients, and share proof bytes are not report fields; refresh-share support is checked with widened proof-of-concept soundness and mask-shift accounting.",
        "inputRankRoot": rank_root,
        "maskedRankRoot": ciphertext_object_root(&masked_ranks)?,
        "maskCommitmentHash": mask_commitment_hash,
        "openedMaskedRankHash": opened_masked_rank_hash,
        "thresholdOpening": threshold_opening_report,
        "refreshedRankRoot": ciphertext_object_root(&refreshed_packed_ranks)?,
        "openedValue": "masked ranks only",
        "nextRequiredStep": "Finish Fiat-Shamir/QROM review, mobile evidence, public accepted proof transport, proof-copy measurement, and target-only security before treating this refresh as public claim-bearing target evidence."
    });

    Ok(DirectBallotRankRefreshResult {
        refreshed_packed_ranks,
        report,
    })
}

fn open_direct_ballot_masked_ranks_with_threshold_shares(
    setup_package: &Value,
    private_setup_seed: &str,
    proof_mask_randomness: &DirectBallotProofMaskRandomness,
    evaluator_key: &DevelopmentBgvKey,
    input_rank_root: &str,
    masked_ranks: &Ciphertext,
) -> CanonicalResult<DirectBallotThresholdMaskedOpening> {
    let share_submissions = submit_direct_ballot_masked_rank_refresh_shares(
        setup_package,
        private_setup_seed,
        proof_mask_randomness,
        evaluator_key,
        input_rank_root,
        masked_ranks,
    )?;
    open_direct_ballot_masked_ranks_with_submitted_shares(
        setup_package,
        evaluator_key,
        input_rank_root,
        masked_ranks,
        &share_submissions,
    )
}

fn submit_direct_ballot_masked_rank_refresh_shares(
    setup_package: &Value,
    private_setup_seed: &str,
    proof_mask_randomness: &DirectBallotProofMaskRandomness,
    evaluator_key: &DevelopmentBgvKey,
    input_rank_root: &str,
    masked_ranks: &Ciphertext,
) -> CanonicalResult<Vec<DirectBallotMaskedRankShareSubmission>> {
    if masked_ranks.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold masked rank share submission requires a two-component ciphertext",
        ));
    }
    let threshold_secret_shares = development_threshold_secret_shares_from_passive_setup_package(
        setup_package,
        private_setup_seed,
    )?;
    if threshold_secret_shares.shares.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold masked rank opening requires at least one setup participant share",
        ));
    }
    proof_mask_randomness.validate_refresh_share_count(threshold_secret_shares.shares.len())?;
    let threshold_share_verification_key_hash = threshold_secret_shares
        .threshold_share_verification_key_hash
        .clone();

    threshold_secret_shares
        .shares
        .into_iter()
        .enumerate()
        .map(|(share_index, share)| {
            let public_key_share_component_zero =
                direct_ballot_threshold_public_key_share_component_zero(
                    evaluator_key,
                    masked_ranks.primes().len(),
                    &share.secret_coefficients,
                    &share.error_coefficients,
                )?;
            let decryption_share_coefficients =
                direct_ballot_threshold_decryption_share(masked_ranks, &share.secret_coefficients)?;
            let proof_randomness_hex =
                proof_mask_randomness.refresh_share_proof_randomness_hex(share_index)?;
            let statement = DirectBallotRefreshShareStatement {
                setup_package,
                evaluator_key,
                input_rank_root,
                masked_ranks,
                threshold_share_verification_key_hash: &threshold_share_verification_key_hash,
                trustee_identity: &share.trustee_identity,
                roster_position: share.roster_position,
                recovery_epoch: share.recovery_epoch,
                device_epoch: share.device_epoch,
                participant_setup_record_hash: &share.participant_setup_record_hash,
                trustee_threshold_verification_key_hash: &share
                    .trustee_threshold_verification_key_hash,
                public_key_share_component_zero: &public_key_share_component_zero,
                decryption_share_coefficients: &decryption_share_coefficients,
            };
            let proof = generate_direct_ballot_refresh_share_proof(
                &statement,
                &share.secret_coefficients,
                &share.error_coefficients,
                proof_randomness_hex,
            )?;

            Ok(DirectBallotMaskedRankShareSubmission {
                trustee_identity: share.trustee_identity,
                roster_position: share.roster_position,
                recovery_epoch: share.recovery_epoch,
                device_epoch: share.device_epoch,
                participant_setup_record_hash: share.participant_setup_record_hash,
                trustee_threshold_verification_key_hash: share
                    .trustee_threshold_verification_key_hash,
                threshold_share_verification_key_hash: threshold_share_verification_key_hash
                    .clone(),
                public_key_share_component_zero,
                decryption_share_coefficients,
                proof,
            })
        })
        .collect()
}

fn open_direct_ballot_masked_ranks_with_submitted_shares(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    input_rank_root: &str,
    masked_ranks: &Ciphertext,
    share_submissions: &[DirectBallotMaskedRankShareSubmission],
) -> CanonicalResult<DirectBallotThresholdMaskedOpening> {
    if masked_ranks.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold masked rank opening requires a two-component ciphertext",
        ));
    }
    let participant_count = direct_ballot_setup_participant_count(setup_package)?;
    if share_submissions.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold masked rank opening requires one submitted share per setup participant",
        ));
    }
    let masked_rank_root = ciphertext_object_root(masked_ranks)?;
    let threshold_share_verification_key_hash =
        direct_ballot_threshold_share_verification_key_hash(setup_package)?;
    let mut seen_trustee_identities = BTreeSet::new();
    let mut decryption_accumulator = masked_ranks.components[0].clone();
    let mut public_key_share_sum = direct_ballot_zero_residue_polynomial_set(masked_ranks);
    let mut share_reports = Vec::with_capacity(share_submissions.len());
    let mut total_refresh_share_proof_bytes = 0_usize;
    let mut total_refresh_share_proof_chunks = 0_usize;

    for submission in share_submissions {
        if !seen_trustee_identities.insert(submission.trustee_identity.clone()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "threshold masked rank opening has duplicate trustee share identities",
            ));
        }
        verify_direct_ballot_share_submission_binding(setup_package, submission)?;
        if submission.threshold_share_verification_key_hash != threshold_share_verification_key_hash
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "threshold masked rank share is bound to the wrong threshold verification key",
            ));
        }
        let statement = DirectBallotRefreshShareStatement {
            setup_package,
            evaluator_key,
            input_rank_root,
            masked_ranks,
            threshold_share_verification_key_hash: &threshold_share_verification_key_hash,
            trustee_identity: &submission.trustee_identity,
            roster_position: submission.roster_position,
            recovery_epoch: submission.recovery_epoch,
            device_epoch: submission.device_epoch,
            participant_setup_record_hash: &submission.participant_setup_record_hash,
            trustee_threshold_verification_key_hash: &submission
                .trustee_threshold_verification_key_hash,
            public_key_share_component_zero: &submission.public_key_share_component_zero,
            decryption_share_coefficients: &submission.decryption_share_coefficients,
        };
        let proof_transport = transport_direct_ballot_binary_proof(
            &submission.proof.proof_bytes,
            &submission.proof.proof_bytes_hash,
            direct_ballot_refresh_share_proof_bytes_hash,
            "direct ballot refresh-share proof",
        )?;
        let proof_verification =
            verify_direct_ballot_refresh_share_proof(&statement, &proof_transport.proof_bytes)?;
        total_refresh_share_proof_bytes = total_refresh_share_proof_bytes
            .checked_add(proof_verification.proof_size_bytes)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "threshold masked rank opening proof byte count overflowed",
                )
            })?;
        total_refresh_share_proof_chunks = total_refresh_share_proof_chunks
            .checked_add(proof_transport.chunk_count)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "threshold masked rank opening proof chunk count overflowed",
                )
            })?;
        direct_ballot_accumulate_residue_polynomial_set(
            &mut public_key_share_sum,
            &submission.public_key_share_component_zero,
            masked_ranks.primes(),
        )?;
        for ((accumulator_limb, share_limb), modulus) in decryption_accumulator
            .iter_mut()
            .zip(submission.decryption_share_coefficients.iter())
            .zip(masked_ranks.primes().iter())
        {
            for (accumulator_coefficient, share_coefficient) in
                accumulator_limb.iter_mut().zip(share_limb.iter())
            {
                *accumulator_coefficient =
                    add_mod(*accumulator_coefficient, *share_coefficient, *modulus)?;
            }
        }
        let share_coefficients_hash = direct_ballot_internal_report_hash(
            "threshold-masked-rank-share-coefficients",
            &json!({
                "inputRankRoot": input_rank_root,
                "maskedRankRoot": masked_rank_root.clone(),
                "trusteeIdentity": submission.trustee_identity.clone(),
                "rosterPosition": submission.roster_position,
                "shareCoefficients": submission.decryption_share_coefficients
            }),
        )?;
        let public_key_share_hash = direct_ballot_internal_report_hash(
            "threshold-masked-rank-public-key-share",
            &json!({
                "inputRankRoot": input_rank_root,
                "maskedRankRoot": masked_rank_root.clone(),
                "trusteeIdentity": submission.trustee_identity.clone(),
                "rosterPosition": submission.roster_position,
                "publicKeyShareComponentZero": submission.public_key_share_component_zero
            }),
        )?;
        let share_record = json!({
            "inputRankRoot": input_rank_root,
            "maskedRankRoot": masked_rank_root.clone(),
            "trusteeIdentity": submission.trustee_identity.clone(),
            "rosterPosition": submission.roster_position,
            "recoveryEpoch": submission.recovery_epoch,
            "deviceEpoch": submission.device_epoch,
            "participantSetupRecordHash": submission.participant_setup_record_hash.clone(),
            "trusteeThresholdVerificationKeyHash": submission.trustee_threshold_verification_key_hash.clone(),
            "thresholdShareVerificationKeyHash": submission.threshold_share_verification_key_hash.clone(),
            "publicKeyShareHash": public_key_share_hash,
            "shareCoefficientsHash": share_coefficients_hash,
            "proofBytesHash": submission.proof.proof_bytes_hash.clone(),
            "proofGeneratedSizeBytes": submission.proof.proof_size_bytes,
            "proofTransportedSizeBytes": proof_transport.proof_size_bytes,
            "proofTransportedBytesHash": proof_transport.proof_bytes_hash,
            "proofChunkCount": proof_transport.chunk_count,
            "proofChunkMerkleRoot": proof_transport.chunk_merkle_root,
            "proofGeneratedStatementHash": submission.proof.statement_hash_hex.clone(),
            "proofGeneratedRelationCommitmentHash": submission.proof.relation_commitment_hash_hex.clone(),
            "proofGeneratedChallenge": submission.proof.challenge.to_string(),
            "proofRelationCommitmentBytes": submission.proof.relation_commitment_bytes,
            "proofResponseBytes": submission.proof.response_bytes,
            "proofStatementHash": proof_verification.statement_hash_hex.clone()
        });
        let share_record_hash = direct_ballot_internal_report_hash(
            "threshold-masked-rank-share-record",
            &share_record,
        )?;
        share_reports.push(json!({
            "trusteeIdentity": share_record["trusteeIdentity"],
            "rosterPosition": share_record["rosterPosition"],
            "participantSetupRecordHash": share_record["participantSetupRecordHash"],
            "trusteeThresholdVerificationKeyHash": share_record["trusteeThresholdVerificationKeyHash"],
            "thresholdShareVerificationKeyHash": share_record["thresholdShareVerificationKeyHash"],
            "publicKeyShareHash": share_record["publicKeyShareHash"],
            "shareCoefficientsHash": share_record["shareCoefficientsHash"],
            "proofBytesHash": share_record["proofBytesHash"],
            "proofSizeBytes": proof_verification.proof_size_bytes,
            "proofGeneratedSizeBytes": share_record["proofGeneratedSizeBytes"],
            "proofTransportedSizeBytes": share_record["proofTransportedSizeBytes"],
            "proofTransportedBytesHash": share_record["proofTransportedBytesHash"],
            "proofChunkCount": share_record["proofChunkCount"],
            "proofChunkMerkleRoot": share_record["proofChunkMerkleRoot"],
            "proofRelationCommitmentBytes": share_record["proofRelationCommitmentBytes"],
            "proofResponseBytes": share_record["proofResponseBytes"],
            "proofGeneratedStatementHash": share_record["proofGeneratedStatementHash"],
            "proofStatementHash": proof_verification.statement_hash_hex,
            "proofGeneratedRelationCommitmentHash": share_record["proofGeneratedRelationCommitmentHash"],
            "proofRelationCommitmentHash": proof_verification.relation_commitment_hash_hex,
            "proofGeneratedChallenge": share_record["proofGeneratedChallenge"],
            "proofChallenge": proof_verification.challenge.to_string(),
            "shareRecordHash": share_record_hash
        }));
    }

    verify_direct_ballot_public_key_share_sum(evaluator_key, masked_ranks, &public_key_share_sum)?;

    let opened_masked_rank_slots =
        decryption_accumulator_to_slots(masked_ranks, &decryption_accumulator)?;
    let opening_hash = direct_ballot_internal_report_hash(
        "threshold-masked-rank-opening",
        &json!({
            "inputRankRoot": input_rank_root,
            "maskedRankRoot": masked_rank_root,
            "thresholdShareVerificationKeyHash": threshold_share_verification_key_hash.clone(),
            "shareReports": share_reports.clone(),
            "openedMaskedRankSlots": opened_masked_rank_slots.clone()
        }),
    )?;
    let proof_size_bytes_per_share = total_refresh_share_proof_bytes
        .checked_div(share_reports.len())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "threshold masked rank opening requires at least one share report",
            )
        })?;
    let report = json!({
        "opening": "Masked packed ranks were opened by verifying independently submitted trustee refresh-share proofs, recombining the submitted decryption shares, and checking the submitted public-key shares against the collective public key.",
        "status": "Internal refresh-share evidence. Share coefficients, public-key share coefficients, proof bytes, and opened masked ranks are not report fields; secret-share and error-share support are checked with widened proof-of-concept soundness and mask-shift accounting.",
        "thresholdShareVerificationKeyHash": threshold_share_verification_key_hash,
        "shareCount": share_reports.len(),
        "totalRefreshShareProofBytes": total_refresh_share_proof_bytes,
        "proofTransport": {
            "encoding": "binary proof chunks",
            "status": "each submitted refresh-share proof is framed into fixed-size binary chunks, hash-checked, reassembled, and verified from the transported bytes",
            "chunkSizeBytes": DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
            "chunksForOpening": total_refresh_share_proof_chunks
        },
        "proofAccounting": direct_ballot_refresh_share_proof_accounting(proof_size_bytes_per_share, share_reports.len())?,
        "shareReports": share_reports,
        "openedMaskedRankHash": opening_hash
    });

    Ok(DirectBallotThresholdMaskedOpening {
        opened_masked_rank_slots,
        report,
    })
}

fn direct_ballot_threshold_decryption_share(
    ciphertext: &Ciphertext,
    secret_coefficients: &[i64],
) -> CanonicalResult<Vec<Vec<u64>>> {
    if ciphertext.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold decryption share requires a two-component ciphertext",
        ));
    }
    if secret_coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold decryption share secret must match the polynomial degree",
        ));
    }

    ciphertext
        .primes()
        .iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            let secret_residues = secret_coefficients
                .iter()
                .map(|coefficient| signed_residue(*coefficient, *modulus))
                .collect::<Vec<_>>();
            negacyclic_mul(
                &ciphertext.components[1][limb_index],
                &secret_residues,
                *modulus,
            )
        })
        .collect()
}

fn direct_ballot_threshold_public_key_share_component_zero(
    evaluator_key: &DevelopmentBgvKey,
    active_limb_count: usize,
    secret_coefficients: &[i64],
    error_coefficients: &[i64],
) -> CanonicalResult<Vec<Vec<u64>>> {
    if secret_coefficients.len() != POLYNOMIAL_DEGREE
        || error_coefficients.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold public-key share witness polynomials must match the BGV polynomial degree",
        ));
    }
    let (_, public_component_one) = evaluator_key.public_key_components();
    if active_limb_count > public_component_one.len() || active_limb_count > DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold public-key share requires public-key material for every active limb",
        ));
    }

    DATA_PRIMES
        .iter()
        .copied()
        .take(active_limb_count)
        .enumerate()
        .map(|(limb_index, modulus)| {
            let secret_residues = secret_coefficients
                .iter()
                .map(|coefficient| signed_residue(*coefficient, modulus))
                .collect::<Vec<_>>();
            let public_sample_secret_product =
                negacyclic_mul(&public_component_one[limb_index], &secret_residues, modulus)?;
            error_coefficients
                .iter()
                .zip(public_sample_secret_product.iter())
                .map(|(error_coefficient, product_coefficient)| {
                    let scaled_error = mul_mod(
                        signed_residue(*error_coefficient, modulus),
                        PLAINTEXT_MODULUS % modulus,
                        modulus,
                    )?;
                    sub_mod(scaled_error, *product_coefficient, modulus)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect()
}

fn direct_ballot_zero_residue_polynomial_set(ciphertext: &Ciphertext) -> Vec<Vec<u64>> {
    ciphertext
        .primes()
        .iter()
        .map(|_| vec![0_u64; POLYNOMIAL_DEGREE])
        .collect()
}

fn direct_ballot_accumulate_residue_polynomial_set(
    accumulated_polynomial_set: &mut [Vec<u64>],
    added_polynomial_set: &[Vec<u64>],
    primes: &[u64],
) -> CanonicalResult<()> {
    if accumulated_polynomial_set.len() != primes.len()
        || added_polynomial_set.len() != primes.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "residue polynomial accumulation requires one limb per active data prime",
        ));
    }
    for ((accumulated_limb, added_limb), modulus) in accumulated_polynomial_set
        .iter_mut()
        .zip(added_polynomial_set.iter())
        .zip(primes.iter())
    {
        if accumulated_limb.len() != POLYNOMIAL_DEGREE || added_limb.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "residue polynomial accumulation limbs must match the BGV polynomial degree",
            ));
        }
        for (accumulated_coefficient, added_coefficient) in
            accumulated_limb.iter_mut().zip(added_limb.iter())
        {
            if *added_coefficient >= *modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "residue polynomial accumulation input has a non-canonical coefficient",
                ));
            }
            *accumulated_coefficient =
                add_mod(*accumulated_coefficient, *added_coefficient, *modulus)?;
        }
    }

    Ok(())
}

fn verify_direct_ballot_public_key_share_sum(
    evaluator_key: &DevelopmentBgvKey,
    masked_ranks: &Ciphertext,
    public_key_share_sum: &[Vec<u64>],
) -> CanonicalResult<()> {
    let (collective_public_component_zero, _) = evaluator_key.public_key_components();
    let primes = masked_ranks.primes();
    if public_key_share_sum.len() != primes.len()
        || collective_public_component_zero.len() < primes.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "threshold public-key share sum must cover every active limb",
        ));
    }
    for (limb_index, summed_limb) in public_key_share_sum.iter().enumerate() {
        if summed_limb.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "threshold public-key share sum limbs must match the BGV polynomial degree",
            ));
        }
        for (coefficient_index, summed_coefficient) in summed_limb.iter().enumerate() {
            if *summed_coefficient
                != collective_public_component_zero[limb_index][coefficient_index]
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "submitted threshold public-key shares do not add to the collective public key",
                ));
            }
        }
    }

    Ok(())
}

fn verify_direct_ballot_share_submission_binding(
    setup_package: &Value,
    submission: &DirectBallotMaskedRankShareSubmission,
) -> CanonicalResult<()> {
    let participant =
        direct_ballot_setup_participant_by_identity(setup_package, &submission.trustee_identity)?;
    if read_usize_field(participant, "rosterPosition")? != submission.roster_position
        || read_u64_field(participant, "recoveryEpoch")? != submission.recovery_epoch
        || read_u64_field(participant, "deviceEpoch")? != submission.device_epoch
        || required_string_field(participant, "participantSetupRecordHash")?
            != submission.participant_setup_record_hash
        || required_string_field(participant, "trusteeThresholdVerificationKeyHash")?
            != submission.trustee_threshold_verification_key_hash
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "threshold masked rank share metadata does not match the setup participant record",
        ));
    }

    Ok(())
}

fn direct_ballot_threshold_share_verification_key_hash(
    setup_package: &Value,
) -> CanonicalResult<String> {
    required_string_path(
        setup_package,
        &[
            "thresholdVerificationMaterial",
            "thresholdShareVerificationKeyHash",
        ],
    )
    .map(ToString::to_string)
}

fn direct_ballot_setup_participant_count(setup_package: &Value) -> CanonicalResult<usize> {
    required_array_path(setup_package, &["participants"]).map(|participants| participants.len())
}

fn direct_ballot_setup_participant_by_identity<'a>(
    setup_package: &'a Value,
    trustee_identity: &str,
) -> CanonicalResult<&'a Value> {
    required_array_path(setup_package, &["participants"])?
        .iter()
        .find(|participant| {
            participant.get("trusteeIdentity").and_then(Value::as_str) == Some(trustee_identity)
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "threshold masked rank share identity is not present in the setup package",
            )
        })
}

fn direct_ballot_internal_report_hash(label: &str, value: &Value) -> CanonicalResult<String> {
    let canonical_value = canonical_json(value)?;
    Ok(hash512_hex(
        &format!("sealed-lattice/direct-encrypted-ballot/{label}-v1"),
        &[canonical_value.as_bytes()],
    ))
}

fn direct_ballot_evaluator_working_level(ballot_count: usize) -> usize {
    if ballot_count == 1 {
        DIRECT_BALLOT_SINGLE_BALLOT_FULL_TARGET_WORKING_LEVEL
    } else {
        DIRECT_BALLOT_DEFAULT_EVALUATOR_WORKING_LEVEL
    }
}

fn direct_ballot_plaintext_aggregate_scores(
    encrypted_ballots: &[DirectEncryptedBallot],
) -> CanonicalResult<Vec<u64>> {
    let mut aggregate_scores = vec![0_u64; DIRECT_BALLOT_OPTION_COUNT];
    for encrypted_ballot in encrypted_ballots {
        if encrypted_ballot.input.scores.len() != DIRECT_BALLOT_OPTION_COUNT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot aggregate oracle requires each ballot to have twenty scores",
            ));
        }
        for (aggregate_score, score) in aggregate_scores
            .iter_mut()
            .zip(encrypted_ballot.input.scores.iter())
        {
            *aggregate_score = add_mod(*aggregate_score, *score, PLAINTEXT_MODULUS)?;
        }
    }

    Ok(aggregate_scores)
}

fn direct_ballot_comparison_domain_max(ballot_count: usize) -> CanonicalResult<u64> {
    let ballot_count_u64 = usize_to_u64(ballot_count, "ballot count")?;
    let score_span = DIRECT_BALLOT_MAXIMUM_SCORE - DIRECT_BALLOT_MINIMUM_SCORE;

    score_span.checked_mul(ballot_count_u64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot comparison domain overflowed",
        )
    })
}

fn direct_ballot_plaintext_target_slots(
    aggregate_scores: &[u64],
    top_count: usize,
) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    if aggregate_scores.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot target oracle requires twenty aggregate scores",
        ));
    }
    if top_count == 0 || top_count > DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount must be between one and the direct ballot option count",
        ));
    }

    let mut ranked_options = aggregate_scores
        .iter()
        .enumerate()
        .collect::<Vec<(usize, &u64)>>();
    ranked_options.sort_by(|(left_option, left_score), (right_option, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_option.cmp(right_option))
    });
    let mut ranks_by_option = vec![0_usize; DIRECT_BALLOT_OPTION_COUNT];
    for (rank, (option_index, _)) in ranked_options.iter().enumerate() {
        ranks_by_option[*option_index] = rank;
    }
    let mut target_ids = vec![0_u64; DIRECT_BALLOT_OPTION_COUNT];
    let mut target_orders = vec![0_u64; DIRECT_BALLOT_OPTION_COUNT];
    for (option_index, rank) in ranks_by_option.iter().enumerate() {
        if *rank < top_count {
            target_ids[option_index] = usize_to_u64(option_index + 1, "option identifier")?;
            target_orders[option_index] = usize_to_u64(rank + 1, "target order")?;
        }
    }

    Ok((target_ids, target_orders))
}

fn optional_direct_ballot_top_count(request: &Value) -> CanonicalResult<Option<usize>> {
    let Some(value) = request.get("topCount") else {
        return Ok(None);
    };
    let raw_top_count = value.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "topCount must be an unsigned integer when supplied",
        )
    })?;
    let top_count = usize::try_from(raw_top_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount does not fit usize",
        )
    })?;
    if top_count == 0 || top_count > DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount must be between one and the direct ballot option count",
        ));
    }

    Ok(Some(top_count))
}

fn usize_to_u64(value: usize, name: &str) -> CanonicalResult<u64> {
    u64::try_from(value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{name} does not fit u64"),
        )
    })
}

#[cfg(test)]
fn direct_ballot_proof_randomness_seed(
    private_setup_seed: &str,
    ballot: &DirectEncryptedBallot,
) -> String {
    hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/proof-randomness-seed-v1",
        &[
            private_setup_seed.as_bytes(),
            ballot.ciphertext_root.as_bytes(),
            ballot.input.voter_identity.as_bytes(),
            ballot.input.action_context_hash.as_bytes(),
        ],
    )
}

fn direct_ballot_slots(scores: &[u64]) -> Vec<u64> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    slots[..DIRECT_BALLOT_OPTION_COUNT].copy_from_slice(scores);
    slots
}

fn direct_ballot_package_hash(
    setup_package: &Value,
    ballot: &DirectBallotInput,
    ciphertext_root: &str,
    ciphertext_canonical_byte_length: usize,
) -> CanonicalResult<String> {
    let score_json = canonical_json(&json!(ballot.scores))?;
    let package_json = canonical_json(&json!({
            "setupPackageHash": setup_package_hash(setup_package)?,
            "voterIdentity": ballot.voter_identity,
            "actionContextHash": ballot.action_context_hash,
            "scoreCommitment": hash512_hex(
                "sealed-lattice/direct-encrypted-ballot/score-commitment-v1",
                &[score_json.as_bytes()],
            ),
            "ciphertextRoot": ciphertext_root,
            "ciphertextCanonicalByteLength": ciphertext_canonical_byte_length
    }))?;
    Ok(hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/package-hash-v1",
        &[package_json.as_bytes()],
    ))
}

fn setup_package_hash(setup_package: &Value) -> CanonicalResult<String> {
    setup_package
        .get("setupPackageHash")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupPackageHash must be present",
            )
        })
}

fn read_ballots(
    request: &Value,
) -> CanonicalResult<(Vec<DirectBallotInput>, DirectBallotEncryptionRandomness)> {
    let ballots = request
        .get("ballots")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "ballots must be an array",
            )
        })?;
    if ballots.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot prototype requires at least one ballot",
        ));
    }
    let ballot_encryption_randomness =
        read_direct_ballot_encryption_randomness(request, ballots.len())?;
    let parsed_ballots = ballots
        .iter()
        .enumerate()
        .map(|(ballot_index, ballot)| {
            if ballot.get("encryptionSeedHex").is_some() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "direct encrypted ballot encryption seed material must be supplied through ballotEncryptionRandomness",
                ));
            }
            Ok(DirectBallotInput {
                voter_identity: required_string_field(ballot, "voterIdentity")?.to_string(),
                action_context_hash: required_string_field(ballot, "actionContextHash")?
                    .to_string(),
                scores: required_u64_array(ballot, "scores")?,
                one_hot_witnesses: optional_one_hot_witnesses(ballot)?,
                encryption_seed_hex: ballot_encryption_randomness
                    .encryption_seed_hex(ballot_index)?
                    .to_string(),
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok((parsed_ballots, ballot_encryption_randomness))
}

fn read_direct_ballot_encryption_randomness(
    request: &Value,
    ballot_count: usize,
) -> CanonicalResult<DirectBallotEncryptionRandomness> {
    let value = required_object_field(request, "ballotEncryptionRandomness")?;
    let source =
        DirectBallotEncryptionRandomnessSource::from_str(required_string_field(value, "source")?)?;
    let encryption_seed_hexes = required_string_array_field(value, "encryptionSeedHexes")?;
    if encryption_seed_hexes.len() != ballot_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "ballotEncryptionRandomness.encryptionSeedHexes length must match the ballot count",
        ));
    }
    for (randomness_index, randomness_hex) in encryption_seed_hexes.iter().enumerate() {
        validate_direct_ballot_encryption_randomness_hex(
            randomness_hex,
            &format!("ballotEncryptionRandomness.encryptionSeedHexes[{randomness_index}]"),
        )?;
    }

    Ok(DirectBallotEncryptionRandomness {
        source,
        encryption_seed_hexes,
    })
}

fn read_direct_ballot_proof_mask_randomness(
    request: &Value,
    ballot_count: usize,
) -> CanonicalResult<DirectBallotProofMaskRandomness> {
    let value = required_object_field(request, "proofMaskRandomness")?;
    let source =
        DirectBallotProofMaskRandomnessSource::from_str(required_string_field(value, "source")?)?;
    let ballot_proof_randomness_hexes =
        required_string_array_field(value, "ballotProofRandomnessHexes")?;
    if ballot_proof_randomness_hexes.len() != ballot_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proofMaskRandomness.ballotProofRandomnessHexes length must match the ballot proof count",
        ));
    }
    for (randomness_index, randomness_hex) in ballot_proof_randomness_hexes.iter().enumerate() {
        validate_direct_ballot_proof_randomness_hex(
            randomness_hex,
            &format!("proofMaskRandomness.ballotProofRandomnessHexes[{randomness_index}]"),
        )?;
    }
    let refresh_share_proof_randomness_hexes =
        optional_string_array_field(value, "refreshShareProofRandomnessHexes")?.unwrap_or_default();
    for (randomness_index, randomness_hex) in
        refresh_share_proof_randomness_hexes.iter().enumerate()
    {
        validate_direct_ballot_proof_randomness_hex(
            randomness_hex,
            &format!("proofMaskRandomness.refreshShareProofRandomnessHexes[{randomness_index}]"),
        )?;
    }

    Ok(DirectBallotProofMaskRandomness {
        source,
        ballot_proof_randomness_hexes,
        refresh_share_proof_randomness_hexes,
    })
}

fn validate_direct_ballot_proof_randomness_hex(value: &str, label: &str) -> CanonicalResult<()> {
    validate_direct_ballot_randomness_hex(
        value,
        label,
        DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_HEX_BYTES,
    )
}

fn validate_direct_ballot_encryption_randomness_hex(
    value: &str,
    label: &str,
) -> CanonicalResult<()> {
    validate_direct_ballot_randomness_hex(
        value,
        label,
        DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_HEX_BYTES,
    )
}

fn validate_direct_ballot_randomness_hex(
    value: &str,
    label: &str,
    byte_count: usize,
) -> CanonicalResult<()> {
    let expected_length = byte_count * 2;
    if value.len() != expected_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} must contain {expected_length} lowercase hex characters"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{label} must be lowercase hexadecimal"),
        ));
    }

    Ok(())
}

fn validate_direct_ballot_batch_order(ballots: &[DirectBallotInput]) -> CanonicalResult<()> {
    let mut previous_voter_identity: Option<&str> = None;
    for ballot in ballots {
        if previous_voter_identity == Some(ballot.voter_identity.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot batch contains a duplicate voter identity",
            ));
        }
        if previous_voter_identity.is_some_and(|previous| previous > ballot.voter_identity.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot batch is not in deterministic voter identity order",
            ));
        }
        previous_voter_identity = Some(ballot.voter_identity.as_str());
    }

    Ok(())
}

fn optional_one_hot_witnesses(ballot: &Value) -> CanonicalResult<Option<Vec<Vec<u64>>>> {
    let Some(value) = ballot.get("oneHotWitnesses") else {
        return Ok(None);
    };
    let rows = value.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "oneHotWitnesses must be an array",
        )
    })?;
    rows.iter()
        .map(|row| {
            row.as_array()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "oneHotWitnesses rows must be arrays",
                    )
                })?
                .iter()
                .map(read_u64_value)
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()
        .map(Some)
}

fn required_object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an object"),
            )
        })
}

fn required_string_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a str> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing required field {}", path.join(".")),
            )
        })?;
    }
    current.as_str().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{} must be a string", path.join(".")),
        )
    })
}

fn required_array_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a [Value]> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing required field {}", path.join(".")),
            )
        })?;
    }
    current.as_array().map(Vec::as_slice).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{} must be an array", path.join(".")),
        )
    })
}

fn required_string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })
}

fn read_u64_field(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an unsigned integer"),
            )
        })
}

fn read_usize_field(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let raw_value = read_u64_field(value, field_name)?;
    usize::try_from(raw_value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} does not fit in usize"),
        )
    })
}

fn required_string_array_field(value: &Value, field_name: &str) -> CanonicalResult<Vec<String>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name} must be an array"),
            )
        })?
        .iter()
        .enumerate()
        .map(|(entry_index, entry)| {
            entry.as_str().map(ToString::to_string).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}[{entry_index}] must be a string"),
                )
            })
        })
        .collect()
}

fn optional_string_array_field(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Option<Vec<String>>> {
    if value.get(field_name).is_none() {
        return Ok(None);
    }
    required_string_array_field(value, field_name).map(Some)
}

fn required_u64_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<u64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name} must be an array"),
            )
        })?
        .iter()
        .map(read_u64_value)
        .collect()
}

fn read_u64_value(value: &Value) -> CanonicalResult<u64> {
    value.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "expected an unsigned integer",
        )
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::hashing::derive_protocol_hash;

    use super::*;

    const DIRECT_BALLOT_TEST_SETUP_SEED: &str = "direct-encrypted-ballot-test-setup-seed";
    const DIRECT_BALLOT_TEST_TRUSTEE_COUNT: usize = 3;

    fn direct_ballot_test_proof_mask_randomness(
        ballot_count: usize,
        refresh_share_count: usize,
    ) -> Value {
        json!({
            "source": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
            "ballotProofRandomnessHexes": (0..ballot_count)
                .map(|index| direct_ballot_test_randomness_hex("ballot-proof", index))
                .collect::<Vec<_>>(),
            "refreshShareProofRandomnessHexes": (0..refresh_share_count)
                .map(|index| direct_ballot_test_randomness_hex("refresh-share-proof", index))
                .collect::<Vec<_>>()
        })
    }

    fn direct_ballot_test_ballot_encryption_randomness(ballot_count: usize) -> Value {
        json!({
            "source": DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE,
            "encryptionSeedHexes": (0..ballot_count)
                .map(|index| direct_ballot_test_randomness_hex("ballot-encryption", index))
                .collect::<Vec<_>>()
        })
    }

    fn direct_ballot_test_randomness_hex(label: &str, index: usize) -> String {
        let randomness_hex = hash512_hex(
            "sealed-lattice/direct-encrypted-ballot/test-randomness-v1",
            &[
                DIRECT_BALLOT_TEST_SETUP_SEED.as_bytes(),
                label.as_bytes(),
                index.to_string().as_bytes(),
            ],
        );
        randomness_hex[..DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_HEX_BYTES * 2].to_string()
    }

    #[test]
    fn direct_encrypted_ballot_command_reports_current_proof_status() {
        let setup_package = setup_package();
        let result = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1, 0),
            "ballots": [
                {
                    "voterIdentity": "voter-1",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot test" }),
                    ).expect("action hash"),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                }
            ]
        }))
        .expect("direct encrypted ballot prototype succeeds");

        assert_eq!(
            result["proofAttempt"]["coverage"].as_str(),
            Some(
                "all RNS limb encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support are checked by one internal binary transcript; support-union and mask-shift accounting are included for proof-of-concept sizing"
            )
        );
        assert!(
            result["proofAttempt"]["generation"]
                .as_str()
                .expect("proof generation assessment")
                .starts_with("Generated and verified one internal binary proof")
        );
        assert_eq!(
            result["proofAttempt"]["proofSizeBytes"],
            result["proofAttempt"]["verifiedProofSizeBytes"]
        );
        assert_eq!(
            result["proofAttempt"]["proofSizeBytes"].as_u64(),
            Some(18_626_400)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["challengeBits"].as_u64(),
            Some(192)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["targetClassicalSoundnessBits"].as_u64(),
            Some(128)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["minimumIndependentRepetitionsForTarget"]
                .as_u64(),
            Some(1)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["estimatedRepeatedProofSizeBytes"].as_u64(),
            Some(18_626_400)
        );
        assert!(
            result["proofAttempt"]["proofAccounting"]
                ["classicalSoundnessBitsAfterSupportUnionBound"]
                .as_u64()
                .expect("post-union soundness bits")
                >= 128
        );
        assert!(
            result["proofAttempt"]["proofAccounting"]
                ["zeroKnowledgeShiftSlackBitsAfterResponseUnionBound"]
                .as_u64()
                .expect("zero-knowledge shift slack bits")
                >= 128
        );
        assert!(
            result["proofAttempt"]["proofAccounting"]["decision"]
                .as_str()
                .expect("proof accounting decision")
                .contains("no naive transcript repetition is needed")
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["encoding"].as_str(),
            Some("binary proof chunks")
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["status"].as_str(),
            Some(
                "each generated proof is framed into fixed-size binary chunks, hash-checked, reassembled, and verified from the transported bytes"
            )
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["chunkSizeBytes"].as_u64(),
            Some(
                u64::try_from(DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)
                    .expect("chunk size fits u64")
            )
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["chunksPerProof"].as_u64(),
            Some(18)
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["transportedProofSizeBytes"],
            result["proofAttempt"]["proofSizeBytes"]
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["transportedProofBytesHash"],
            result["proofAttempt"]["proofBytesHash"]
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["firstProofChunkMerkleRoot"]
                .as_str()
                .expect("first proof chunk Merkle root")
                .len(),
            128
        );
        assert_eq!(
            result["proofAttempt"]["proofMaskRandomness"]["source"].as_str(),
            Some(DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE)
        );
        assert_eq!(
            result["proofAttempt"]["proofMaskRandomness"]["ballotProofRandomnessCount"].as_u64(),
            Some(1)
        );
        assert_eq!(
            result["proofAttempt"]["blocker"].as_str(),
            Some(
                "Next missing pieces are Fiat-Shamir/QROM review, mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, public accepted proof transport outside this internal command, public accepted ballot encryption randomness rules, and the target-only decryption security model. Runs using development-deterministic-fixture proof masks or ballot-encryption randomness remain fixture evidence only."
            )
        );
        assert_eq!(
            result["proofAttempt"]["responseSharing"].as_str(),
            Some(
                "one binary response vector is checked against all 17 RNS limb equations, score-linear constraints, and support constraints; response bytes are not duplicated per limb"
            )
        );
        assert_eq!(
            result["proofAttempt"]["sharedScoreResponseScalarCount"].as_u64(),
            Some(
                u64::try_from(relation_proof::direct_ballot_relation_response_scalar_count())
                    .expect("response scalar count fits u64")
            )
        );
        assert_eq!(
            result["proofAttempt"]["rnsLimbCount"].as_u64(),
            Some(u64::try_from(DATA_PRIMES.len()).expect("limb count fits u64"))
        );
        assert_eq!(
            result["proofAttempt"]["sharedShortResponseVectorLength"].as_u64(),
            Some(
                u64::try_from(direct_ballot_shared_short_response_vector_length())
                    .expect("response length fits u64")
            )
        );
        assert_eq!(
            result["proofAttempt"]["duplicatedShortResponseVectorLength"].as_u64(),
            Some(
                u64::try_from(direct_ballot_duplicated_short_response_vector_length())
                    .expect("duplicated response length fits u64")
            )
        );
        assert_eq!(
            result["ballotPackages"]["ciphertextRoots"]
                .as_array()
                .expect("ciphertext roots")
                .len(),
            1
        );
        assert_eq!(
            result["ballotPackages"]["ballotEncryptionRandomness"]["source"].as_str(),
            Some(DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE)
        );
        assert_eq!(
            result["ballotPackages"]["ballotEncryptionRandomness"]
                ["ballotEncryptionRandomnessCount"]
                .as_u64(),
            Some(1)
        );
        assert_eq!(
            result["ballotPackages"]["ballotEncryptionRandomness"]["randomnessBytesPerBallot"]
                .as_u64(),
            Some(32)
        );
        assert!(
            result["ballotPackages"]["ballotEncryptionRandomness"]["retention"]
                .as_str()
                .expect("encryption randomness retention")
                .contains("not returned")
        );
        assert_eq!(result["aggregation"]["ballotCount"].as_u64(), Some(1));
        assert_eq!(
            result["aggregation"]["aggregateScores"].as_array(),
            result["aggregation"]["plaintextOracleScores"].as_array()
        );
        assert_eq!(
            result["aggregation"]["result"].as_str(),
            Some(
                "Verified the supplied direct ballot proofs, aggregated their ciphertexts, and test-decrypted aggregate score slots to the plaintext oracle."
            )
        );
        assert_eq!(
            result["evaluatorReplay"].as_str(),
            Some(
                "Not run in this command. Supply topCount to attempt the packed batched-pair evaluator route over the direct aggregate."
            )
        );
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_more_than_twenty_ballots() {
        let setup_package = setup_package();
        let ballots = (0..=DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS)
            .map(|ballot_index| {
                json!({
                    "voterIdentity": format!("voter-{}", ballot_index + 1),
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({
                            "action": "direct encrypted ballot max batch test",
                            "ballotIndex": ballot_index
                        }),
                    ).expect("action hash"),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                })
            })
            .collect::<Vec<_>>();

        let error = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS + 1),
            "ballots": ballots
        }))
        .expect_err("oversized direct ballot prototype batch must reject before encryption");

        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
        assert!(error.message.contains("supports at most twenty ballots"));
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_missing_ballot_encryption_randomness() {
        let setup_package = setup_package();
        let error = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1, 0),
            "ballots": [
                {
                    "voterIdentity": "voter-missing-encryption-randomness",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot missing encryption randomness test" }),
                    ).expect("action hash"),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                }
            ]
        }))
        .expect_err("missing direct ballot encryption randomness must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("ballotEncryptionRandomness"));
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_ballot_embedded_encryption_seed() {
        let setup_package = setup_package();
        let error = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1, 0),
            "ballots": [
                {
                    "voterIdentity": "voter-embedded-encryption-seed",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot embedded encryption seed test" }),
                    ).expect("action hash"),
                    "encryptionSeedHex": direct_ballot_test_randomness_hex("legacy-ballot-seed", 0),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                }
            ]
        }))
        .expect_err("ballot-embedded encryption seed must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("must be supplied through ballotEncryptionRandomness")
        );
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_duplicate_voter_identity() {
        let setup_package = setup_package();
        let error = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
            "ballots": [
                {
                    "voterIdentity": "duplicate-voter",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot duplicate test", "ballotIndex": 0 }),
                    ).expect("action hash"),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                },
                {
                    "voterIdentity": "duplicate-voter",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot duplicate test", "ballotIndex": 1 }),
                    ).expect("action hash"),
                    "scores": [
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10,
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1
                    ]
                }
            ]
        }))
        .expect_err("duplicate direct ballot voter identity must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("duplicate voter identity"));
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_wrong_voter_order() {
        let setup_package = setup_package();
        let error = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
            "ballots": [
                {
                    "voterIdentity": "voter-b",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot order test", "ballotIndex": 0 }),
                    ).expect("action hash"),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                },
                {
                    "voterIdentity": "voter-a",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot order test", "ballotIndex": 1 }),
                    ).expect("action hash"),
                    "scores": [
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10,
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1
                    ]
                }
            ]
        }))
        .expect_err("out-of-order direct ballot batch must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("deterministic voter identity order"));
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_invalid_score_before_proof_generation() {
        let setup_package = setup_package();
        let error = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "ballots": [
                {
                    "voterIdentity": "voter-invalid-score",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot invalid score test" }),
                    ).expect("action hash"),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 11, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                }
            ]
        }))
        .expect_err("invalid direct ballot score must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("score at option 8"));
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_wrong_setup_seed() {
        let setup_package = setup_package();
        let error = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": "direct-encrypted-ballot-wrong-setup-seed"
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "ballots": [
                {
                    "voterIdentity": "voter-wrong-key",
                    "actionContextHash": derive_protocol_hash(
                        "ActionContextHash",
                        &json!({ "action": "direct encrypted ballot wrong key test" }),
                    ).expect("action hash"),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                }
            ]
        }))
        .expect_err("wrong setup seed must reject before direct ballot encryption");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error
                .message
                .contains("private setup witness seed commitment")
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_verifies() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");

        let proof_verification = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect("proof verification");

        assert_eq!(
            proof_verification.relation_commitment_hash_hex,
            proof_generation.relation_commitment_hash_hex
        );
        assert_eq!(proof_verification.challenge, proof_generation.challenge);
        assert!(proof_generation.proof_size_bytes > 0);
    }

    #[test]
    fn direct_ballot_aggregation_matches_plaintext_oracle_for_multiple_ballots() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let first_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("first encrypted ballot");
        let mut second_input = valid_ballot_input();
        second_input.voter_identity = "voter-aggregation-second".to_string();
        second_input.scores = vec![1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10];
        let second_ballot = encrypt_direct_ballot(&setup_package, &evaluator_key, second_input, 1)
            .expect("second encrypted ballot");

        let aggregation_report =
            verify_direct_ballot_aggregation(&evaluator_key, &[first_ballot, second_ballot])
                .expect("aggregation report");

        assert_eq!(aggregation_report.report["ballotCount"].as_u64(), Some(2));
        assert_eq!(
            aggregation_report.report["aggregateScores"],
            json!([
                11, 10, 10, 9, 9, 8, 8, 7, 7, 6, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20
            ])
        );
        assert_eq!(
            aggregation_report.report["aggregateScores"],
            aggregation_report.report["plaintextOracleScores"]
        );
    }

    #[test]
    #[ignore = "heavy direct ballot evaluator replay candidate; run selectively"]
    fn direct_ballot_packed_batched_pair_evaluator_top_count_20_matches_oracle() {
        assert_direct_ballot_packed_batched_pair_evaluator_matches_oracle(
            DIRECT_BALLOT_OPTION_COUNT,
        );
    }

    #[test]
    #[ignore = "heavy direct ballot evaluator replay candidate; run selectively"]
    fn direct_ballot_top_count_10_matches_oracle_with_masked_refresh() {
        assert_direct_ballot_packed_batched_pair_evaluator_matches_oracle(10);
    }

    #[test]
    #[ignore = "heavy direct ballot evaluator replay candidate; run selectively"]
    fn direct_ballot_top_count_1_matches_oracle_with_masked_refresh() {
        assert_direct_ballot_packed_batched_pair_evaluator_matches_oracle(1);
    }

    #[test]
    #[ignore = "heavy direct ballot all-top-count evaluator replay candidate; run selectively"]
    fn direct_ballot_all_top_counts_match_oracle_with_masked_refresh() {
        let setup_package = setup_package();
        let proof_mask_randomness =
            direct_ballot_test_proof_mask_randomness(1, DIRECT_BALLOT_TEST_TRUSTEE_COUNT);
        let proof_mask_randomness = read_direct_ballot_proof_mask_randomness(
            &json!({ "proofMaskRandomness": proof_mask_randomness }),
            1,
        )
        .expect("proof mask randomness");
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let aggregation = verify_direct_ballot_aggregation(&evaluator_key, &[encrypted_ballot])
            .expect("aggregation");
        let top_counts = (1..=DIRECT_BALLOT_OPTION_COUNT).collect::<Vec<_>>();
        let evaluations = run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
            &setup_package,
            &evaluator_key,
            DIRECT_BALLOT_TEST_SETUP_SEED,
            &proof_mask_randomness,
            &aggregation.aggregate_ciphertext,
            &aggregation.aggregate_scores,
            1,
            &top_counts,
        )
        .expect("all top counts replay");

        assert_eq!(evaluations.len(), top_counts.len());
        for (evaluation, top_count) in evaluations.iter().zip(top_counts.iter()) {
            assert_eq!(
                evaluation["topCount"].as_u64(),
                Some(u64::try_from(*top_count).expect("top count fits u64"))
            );
            assert_eq!(
                evaluation["decodedTargetIds"],
                evaluation["plaintextOracleTargetIds"]
            );
            assert_eq!(
                evaluation["decodedTargetOrders"],
                evaluation["plaintextOracleTargetOrders"]
            );
        }
    }

    #[test]
    fn direct_ballot_masked_rank_refresh_uses_submitted_threshold_share_proofs() {
        let setup_package = setup_package();
        let proof_mask_randomness =
            direct_ballot_test_proof_mask_randomness(0, DIRECT_BALLOT_TEST_TRUSTEE_COUNT);
        let proof_mask_randomness = read_direct_ballot_proof_mask_randomness(
            &json!({ "proofMaskRandomness": proof_mask_randomness }),
            0,
        )
        .expect("proof mask randomness");
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut rank_slots = vec![0_u64; POLYNOMIAL_DEGREE];
        for option in 0..DIRECT_BALLOT_OPTION_COUNT {
            rank_slots[packed_score_slot(option)] = u64::try_from(option).expect("option fits u64");
        }
        let packed_ranks = evaluator_key
            .encrypt_slots(&rank_slots, "direct-ballot-refresh-test-ranks")
            .expect("encrypted ranks");

        let refresh = refresh_direct_ballot_packed_ranks_with_masked_opening(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
            &proof_mask_randomness,
            &evaluator_key,
            &packed_ranks,
            DIRECT_BALLOT_OPTION_COUNT,
            "direct-ballot-refresh-test",
        )
        .expect("masked rank refresh");
        let refreshed_slots = evaluator_key
            .decrypt_to_slots(&refresh.refreshed_packed_ranks)
            .expect("refreshed ranks decrypt");

        for option in 0..DIRECT_BALLOT_OPTION_COUNT {
            assert_eq!(
                refreshed_slots[packed_score_slot(option)],
                rank_slots[packed_score_slot(option)]
            );
        }
        assert_eq!(
            refresh.report["thresholdOpening"]["shareCount"].as_u64(),
            Some(3)
        );
        assert_eq!(
            refresh.report["thresholdOpening"]["proofAccounting"]["targetClassicalSoundnessBits"]
                .as_u64(),
            Some(128)
        );
        assert_eq!(
            refresh.report["thresholdOpening"]["proofAccounting"]
                ["minimumIndependentRepetitionsForTarget"]
                .as_u64(),
            Some(1)
        );
        assert!(
            refresh.report["thresholdOpening"]["proofAccounting"]
                ["classicalSoundnessBitsAfterSupportUnionBound"]
                .as_u64()
                .expect("refresh post-union soundness bits")
                >= 128
        );
        assert!(
            refresh.report["thresholdOpening"]["proofAccounting"]
                ["zeroKnowledgeShiftSlackBitsAfterResponseUnionBound"]
                .as_u64()
                .expect("refresh zero-knowledge shift slack bits")
                >= 128
        );
        assert!(
            refresh.report["thresholdOpening"]["proofAccounting"]["currentOpeningProofBytes"]
                .as_u64()
                .expect("refresh share proof bytes")
                > 0
        );
        assert_eq!(
            refresh.report["thresholdOpening"]["proofTransport"]["encoding"].as_str(),
            Some("binary proof chunks")
        );
        let first_refresh_share_proof_chunk_count =
            refresh.report["thresholdOpening"]["shareReports"][0]["proofChunkCount"]
                .as_u64()
                .expect("refresh share proof chunk count");
        assert_eq!(
            refresh.report["thresholdOpening"]["proofTransport"]["chunksForOpening"].as_u64(),
            Some(first_refresh_share_proof_chunk_count * 3)
        );
        assert!(
            refresh.report["thresholdOpening"]["proofAccounting"]["decision"]
                .as_str()
                .expect("refresh share accounting decision")
                .contains("no naive transcript repetition is needed")
        );
        assert!(
            refresh.report["thresholdOpening"]["openedMaskedRankHash"]
                .as_str()
                .is_some()
        );
        assert!(
            refresh.report["thresholdOpening"]["shareReports"][0]["proofBytesHash"]
                .as_str()
                .is_some()
        );
        assert_eq!(
            refresh.report["thresholdOpening"]["shareReports"][0]["proofTransportedBytesHash"],
            refresh.report["thresholdOpening"]["shareReports"][0]["proofBytesHash"]
        );
        assert_eq!(
            refresh.report["thresholdOpening"]["shareReports"][0]["proofTransportedSizeBytes"],
            refresh.report["thresholdOpening"]["shareReports"][0]["proofSizeBytes"]
        );
        assert_eq!(
            refresh.report["thresholdOpening"]["shareReports"][0]["proofChunkCount"].as_u64(),
            Some(first_refresh_share_proof_chunk_count)
        );
        assert!(first_refresh_share_proof_chunk_count > 1);
        assert_eq!(
            refresh.report["thresholdOpening"]["shareReports"][0]["proofChunkMerkleRoot"]
                .as_str()
                .expect("refresh share proof chunk Merkle root")
                .len(),
            128
        );
        assert!(refresh.report["thresholdOpening"]["openedMaskedRankSlots"].is_null());
        assert!(
            refresh.report["thresholdOpening"]["shareReports"][0]["shareCoefficients"].is_null()
        );
        assert!(
            refresh.report["thresholdOpening"]["shareReports"][0]["publicKeyShareComponentZero"]
                .is_null()
        );
        assert!(refresh.report["thresholdOpening"]["shareReports"][0]["proofBytes"].is_null());
        assert!(refresh.report["maskSlots"].is_null());
    }

    #[test]
    fn direct_ballot_masked_rank_opening_rejects_mutated_refresh_share_proof() {
        let (setup_package, evaluator_key, input_rank_root, masked_ranks, mut submissions) =
            masked_rank_share_submission_fixture();
        let first_submission = submissions
            .first_mut()
            .expect("share submission fixture is non-empty");
        let last_proof_byte = first_submission
            .proof
            .proof_bytes
            .last_mut()
            .expect("proof bytes are non-empty");
        *last_proof_byte ^= 1;

        let error = open_direct_ballot_masked_ranks_with_submitted_shares(
            &setup_package,
            &evaluator_key,
            &input_rank_root,
            &masked_ranks,
            &submissions,
        )
        .expect_err("mutated share proof must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("decryption-share response does not match")
                || error
                    .message
                    .contains("public-key share response does not match")
        );
    }

    #[test]
    fn direct_ballot_masked_rank_opening_rejects_mutated_submitted_share() {
        let (setup_package, evaluator_key, input_rank_root, masked_ranks, mut submissions) =
            masked_rank_share_submission_fixture();
        let modulus = masked_ranks.primes()[0];
        let first_share = submissions
            .first_mut()
            .expect("share submission fixture is non-empty");
        first_share.decryption_share_coefficients[0][0] =
            add_mod(first_share.decryption_share_coefficients[0][0], 1, modulus)
                .expect("mutated share remains canonical");

        let error = open_direct_ballot_masked_ranks_with_submitted_shares(
            &setup_package,
            &evaluator_key,
            &input_rank_root,
            &masked_ranks,
            &submissions,
        )
        .expect_err("mutated submitted share must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("statement hash does not match the masked-rank share")
        );
    }

    #[test]
    fn direct_ballot_refresh_share_proof_rejects_out_of_support_secret_witness() {
        let (setup_package, evaluator_key, input_rank_root, masked_ranks, _) =
            masked_rank_share_submission_fixture();
        let threshold_secret_shares =
            development_threshold_secret_shares_from_passive_setup_package(
                &setup_package,
                DIRECT_BALLOT_TEST_SETUP_SEED,
            )
            .expect("threshold secret shares");
        let threshold_share_verification_key_hash =
            direct_ballot_threshold_share_verification_key_hash(&setup_package)
                .expect("threshold verification key hash");
        let share = threshold_secret_shares
            .shares
            .first()
            .expect("threshold share fixture is non-empty");
        let mut unsupported_secret_coefficients = share.secret_coefficients.clone();
        unsupported_secret_coefficients[0] = 2;
        let public_key_share_component_zero =
            direct_ballot_threshold_public_key_share_component_zero(
                &evaluator_key,
                masked_ranks.primes().len(),
                &unsupported_secret_coefficients,
                &share.error_coefficients,
            )
            .expect("unsupported public-key share statement");
        let decryption_share_coefficients = direct_ballot_threshold_decryption_share(
            &masked_ranks,
            &unsupported_secret_coefficients,
        )
        .expect("unsupported decryption share statement");
        let statement = DirectBallotRefreshShareStatement {
            setup_package: &setup_package,
            evaluator_key: &evaluator_key,
            input_rank_root: &input_rank_root,
            masked_ranks: &masked_ranks,
            threshold_share_verification_key_hash: &threshold_share_verification_key_hash,
            trustee_identity: &share.trustee_identity,
            roster_position: share.roster_position,
            recovery_epoch: share.recovery_epoch,
            device_epoch: share.device_epoch,
            participant_setup_record_hash: &share.participant_setup_record_hash,
            trustee_threshold_verification_key_hash: &share.trustee_threshold_verification_key_hash,
            public_key_share_component_zero: &public_key_share_component_zero,
            decryption_share_coefficients: &decryption_share_coefficients,
        };
        let proof = generate_direct_ballot_refresh_share_proof(
            &statement,
            &unsupported_secret_coefficients,
            &share.error_coefficients,
            "direct-ballot-refresh-unsupported-secret-test",
        )
        .expect("unsupported proof generation still produces bytes");

        let error = verify_direct_ballot_refresh_share_proof(&statement, &proof.proof_bytes)
            .expect_err("unsupported secret witness must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("secret share support check failed"));
    }

    fn masked_rank_share_submission_fixture() -> (
        Value,
        DevelopmentBgvKey,
        String,
        Ciphertext,
        Vec<DirectBallotMaskedRankShareSubmission>,
    ) {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut rank_slots = vec![0_u64; POLYNOMIAL_DEGREE];
        for option in 0..DIRECT_BALLOT_OPTION_COUNT {
            rank_slots[packed_score_slot(option)] = u64::try_from(option).expect("option fits u64");
        }
        let packed_ranks = evaluator_key
            .encrypt_slots(&rank_slots, "direct-ballot-refresh-share-proof-test-ranks")
            .expect("encrypted ranks");
        let input_rank_root = ciphertext_object_root(&packed_ranks).expect("rank root");
        let low_level_ranks = modulus_switch_to(&packed_ranks, 0).expect("low-level ranks");
        let mask_slots = (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| {
                u64::try_from(
                    coefficient_index
                        % usize::try_from(DIRECT_BALLOT_MAXIMUM_SCORE)
                            .expect("maximum score fits usize"),
                )
                .expect("coefficient index fits u64")
            })
            .collect::<Vec<_>>();
        let mask_coefficients =
            encode_slots_to_coefficients(&mask_slots).expect("mask coefficients");
        let masked_ranks = add_plaintext_coefficients(
            &normalize_scaling(&low_level_ranks).expect("normalized ranks"),
            &mask_coefficients,
        )
        .expect("masked ranks");
        let proof_mask_randomness =
            direct_ballot_test_proof_mask_randomness(0, DIRECT_BALLOT_TEST_TRUSTEE_COUNT);
        let proof_mask_randomness = read_direct_ballot_proof_mask_randomness(
            &json!({ "proofMaskRandomness": proof_mask_randomness }),
            0,
        )
        .expect("proof mask randomness");
        let submissions = submit_direct_ballot_masked_rank_refresh_shares(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
            &proof_mask_randomness,
            &evaluator_key,
            &input_rank_root,
            &masked_ranks,
        )
        .expect("share submissions");

        (
            setup_package,
            evaluator_key,
            input_rank_root,
            masked_ranks,
            submissions,
        )
    }

    fn assert_direct_ballot_packed_batched_pair_evaluator_matches_oracle(top_count: usize) {
        let setup_package = setup_package();
        let refresh_share_count = if top_count == DIRECT_BALLOT_OPTION_COUNT {
            0
        } else {
            DIRECT_BALLOT_TEST_TRUSTEE_COUNT
        };
        let result = run_direct_encrypted_ballot_prototype(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1, refresh_share_count),
            "topCount": top_count,
            "ballots": [
                {
                    "voterIdentity": "voter-validation",
                    "actionContextHash": "a".repeat(128),
                    "scores": [
                        10, 9, 8, 7, 6,
                        5, 4, 3, 2, 1,
                        1, 2, 3, 4, 5,
                        6, 7, 8, 9, 10
                    ]
                }
            ]
        }))
        .expect("direct encrypted ballot prototype succeeds");

        assert_eq!(
            result["evaluatorReplay"]["topCount"].as_u64(),
            Some(u64::try_from(top_count).expect("top count fits u64"))
        );
        assert_eq!(
            result["evaluatorReplay"]["decodedTargetIds"],
            result["evaluatorReplay"]["plaintextOracleTargetIds"]
        );
        assert_eq!(
            result["evaluatorReplay"]["decodedTargetOrders"],
            result["evaluatorReplay"]["plaintextOracleTargetOrders"]
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_last_limb_ciphertext_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let last_limb_index = DATA_PRIMES.len() - 1;
        encrypted_ballot.ciphertext.components[0][last_limb_index][0] = add_mod(
            encrypted_ballot.ciphertext.components[0][last_limb_index][0],
            1,
            DATA_PRIMES[last_limb_index],
        )
        .expect("mutated residue");

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated last limb must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error.message.contains("not bound to this statement")
                || error.message.contains("limb 16 c0 response")
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_response_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let mut proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let response_offset =
            8 + 64 + 8 + relation_proof::direct_ballot_relation_commitment_bytes();
        proof_generation.proof_bytes[response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated response must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("randomizer support check failed"));
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_score_response_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let mut proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let score_response_offset = direct_ballot_score_response_offset();
        proof_generation.proof_bytes[score_response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated score response must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("direct ballot score proof option 0"));
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_one_hot_response_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let mut proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let one_hot_response_offset =
            direct_ballot_score_response_offset() + DIRECT_BALLOT_OPTION_COUNT * 8;
        proof_generation.proof_bytes[one_hot_response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated one-hot response must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("direct ballot score proof option 0"));
    }

    #[test]
    fn direct_ballot_relation_proof_rejects_linear_consistent_non_boolean_one_hot_witness() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let mut one_hot_witnesses = one_hot_witnesses_for_scores(&encrypted_ballot.input.scores);
        one_hot_witnesses[0] = vec![0, 0, 0, 0, 0, 0, 0, 65536, 2, 0];
        encrypted_ballot.input.one_hot_witnesses = Some(one_hot_witnesses);
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("non-Boolean one-hot witness must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("one-hot Booleanity option 0 support check failed")
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_commitment_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let mut proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let commitment_offset = 8 + 64 + 8;
        proof_generation.proof_bytes[commitment_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated commitment must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("challenge does not match its commitment")
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_wrong_public_key() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");
        let wrong_setup_package = setup_package_with_seed("direct-encrypted-ballot-wrong-seed");
        let wrong_evaluator_key = development_evaluator_key_from_passive_setup_package(
            &wrong_setup_package,
            "direct-encrypted-ballot-wrong-seed",
        )
        .expect("wrong evaluator key");

        let error = verify_direct_ballot_relation_proof(
            &wrong_setup_package,
            &wrong_evaluator_key,
            &encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("wrong public key must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("not bound to this statement"));
    }

    #[test]
    fn direct_ballot_all_limb_relation_rejects_last_limb_mutation() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        let last_limb_index = DATA_PRIMES.len() - 1;
        encrypted_ballot.ciphertext.components[0][last_limb_index][0] = add_mod(
            encrypted_ballot.ciphertext.components[0][last_limb_index][0],
            1,
            DATA_PRIMES[last_limb_index],
        )
        .expect("mutated residue");

        let error = validate_all_limb_encryption_relation(&evaluator_key, &encrypted_ballot)
            .expect_err("last limb mutation must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("RNS limb 16 c0 relation failed"));
    }

    #[test]
    fn direct_ballot_all_limb_relation_rejects_different_plaintext_witness() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        encrypted_ballot.plaintext_coefficients[0] += 1;

        let error = validate_all_limb_encryption_relation(&evaluator_key, &encrypted_ballot)
            .expect_err("different plaintext witness must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("RNS limb 0 c0 relation failed"));
    }

    #[test]
    fn direct_ballot_support_rejects_out_of_range_randomizer() {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let mut encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                .expect("encrypted ballot");
        encrypted_ballot.encryption_witness.randomizer_coefficients[0] = 2;

        let error = validate_encryption_witness_support(&encrypted_ballot.encryption_witness)
            .expect_err("out-of-range randomizer must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains(
            "direct encrypted ballot randomizer has a coefficient outside the expected support"
        ));
    }

    #[test]
    fn direct_ballot_validation_rejects_out_of_range_scores() {
        let mut ballot = valid_ballot_input();
        ballot.scores[7] = 11;

        let error = validate_direct_ballot_input(&ballot).expect_err("score is out of range");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("direct encrypted ballot score at option 7")
        );
    }

    #[test]
    fn direct_ballot_validation_rejects_mismatched_one_hot_witness() {
        let mut ballot = valid_ballot_input();
        let mut witnesses = ballot
            .scores
            .iter()
            .map(|score| {
                let mut row = vec![0_u64; 10];
                row[usize::try_from(score - 1).expect("score index fits usize")] = 1;
                row
            })
            .collect::<Vec<_>>();
        witnesses[3] = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ballot.one_hot_witnesses = Some(witnesses);

        let error = validate_direct_ballot_input(&ballot).expect_err("witness is inconsistent");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("one-hot witness does not match its scalar score")
        );
    }

    fn valid_ballot_input() -> DirectBallotInput {
        DirectBallotInput {
            voter_identity: "voter-validation".to_string(),
            action_context_hash: "a".repeat(128),
            scores: vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            one_hot_witnesses: None,
            encryption_seed_hex: direct_ballot_test_randomness_hex("ballot-encryption", 0),
        }
    }

    fn one_hot_witnesses_for_scores(scores: &[u64]) -> Vec<Vec<u64>> {
        scores
            .iter()
            .map(|score| {
                let mut row = vec![0_u64; 10];
                row[usize::try_from(score - 1).expect("score index fits usize")] = 1;
                row
            })
            .collect()
    }

    fn direct_ballot_score_response_offset() -> usize {
        8 + 64
            + 8
            + relation_proof::direct_ballot_relation_commitment_bytes()
            + 4 * POLYNOMIAL_DEGREE * 8
    }

    fn setup_package() -> Value {
        setup_package_with_seed(DIRECT_BALLOT_TEST_SETUP_SEED)
    }

    fn setup_package_with_seed(setup_seed: &str) -> Value {
        crate::bgv::commands::generate_bgv_passive_setup_from_request(&json!({
            "ceremonyId": "direct-encrypted-ballot-test-ceremony",
            "manifestHash": derive_protocol_hash(
                "ElectionManifestHash",
                &json!({ "manifest": "direct encrypted ballot test" }),
            ).expect("manifest hash"),
            "rosterHash": derive_protocol_hash(
                "RosterHash",
                &json!({ "roster": "direct encrypted ballot test" }),
            ).expect("roster hash"),
            "thresholdProfileHash": derive_protocol_hash(
                "ThresholdProfileHash",
                &json!({ "threshold": "direct encrypted ballot test" }),
            ).expect("threshold hash"),
            "participants": [
                { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 0 },
                { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 1 },
                { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 2 }
            ],
            "setupSeed": setup_seed
        }))
        .expect("setup package")
    }
}
