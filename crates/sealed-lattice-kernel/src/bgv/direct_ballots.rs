use std::collections::BTreeSet;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

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
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, chunk_root, derive_protocol_hash, hash512_hex},
};

const DIRECT_BALLOT_OPERATION: &str = "runDirectEncryptedBallot";
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
    setup_package: &Value,
    ballot: &DirectEncryptedBallot,
    statement_hash: &str,
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
    let mut chunk_hashes = Vec::with_capacity(chunk_count);
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
        chunk_hashes.push(direct_ballot_proof_chunk_hash(
            expected_proof_bytes_hash,
            chunk_index,
            chunk,
        )?);
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
    verify_direct_ballot_public_proof_transport(
        &transported_proof_bytes,
        expected_proof_bytes_hash,
        &chunk_hashes,
        DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
        &chunk_merkle_root,
    )?;
    let public_transport_hash = direct_ballot_public_proof_transport_hash(
        setup_package,
        ballot,
        statement_hash,
        expected_proof_bytes_hash,
        proof_bytes.len(),
        DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
        chunk_count,
        &chunk_hashes,
        &chunk_merkle_root,
    )?;

    Ok(DirectBallotBinaryProofTransport {
        proof_size_bytes: transported_proof_bytes.len(),
        proof_bytes: transported_proof_bytes,
        proof_bytes_hash: transported_proof_bytes_hash,
        chunk_count,
        chunk_merkle_root,
        chunk_hashes,
        public_transport_hash,
    })
}

fn direct_ballot_proof_chunk_hash(
    proof_bytes_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    validate_direct_ballot_hash_hex(proof_bytes_hash, "proofBytesHash")?;
    Ok(hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/proof-chunk-v1",
        &[
            proof_bytes_hash.as_bytes(),
            &usize_to_u64(chunk_index, "proof chunk index")?.to_le_bytes(),
            chunk,
        ],
    ))
}

fn verify_direct_ballot_public_proof_transport(
    proof_bytes: &[u8],
    expected_proof_bytes_hash: &str,
    expected_chunk_hashes: &[String],
    chunk_size_bytes: usize,
    expected_chunk_merkle_root: &str,
) -> CanonicalResult<()> {
    if proof_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public proof transport requires non-empty proof bytes",
        ));
    }
    validate_direct_ballot_hash_hex(expected_proof_bytes_hash, "proofBytesHash")?;
    validate_direct_ballot_hash_hex(expected_chunk_merkle_root, "proofChunkMerkleRoot")?;
    let expected_chunk_count = chunk_count_for_bytes(proof_bytes.len(), chunk_size_bytes)?;
    if expected_chunk_hashes.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public proof transport chunk hash count does not match proof length",
        ));
    }
    validate_unique_strings(
        expected_chunk_hashes,
        "proofTransport.chunkHashes",
        "contains a duplicate chunk hash",
    )?;
    for (chunk_index, chunk) in proof_bytes.chunks(chunk_size_bytes).enumerate() {
        if chunk.is_empty() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public proof transport contains an empty chunk",
            ));
        }
        if chunk_index + 1 < expected_chunk_count && chunk.len() != chunk_size_bytes {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public proof transport contains a truncated non-final chunk",
            ));
        }
        let expected_chunk_hash = &expected_chunk_hashes[chunk_index];
        validate_direct_ballot_hash_hex(
            expected_chunk_hash,
            &format!("proofTransport.chunkHashes[{chunk_index}]"),
        )?;
        let actual_chunk_hash =
            direct_ballot_proof_chunk_hash(expected_proof_bytes_hash, chunk_index, chunk)?;
        if actual_chunk_hash != *expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("public proof transport chunk {chunk_index} hash does not match"),
            ));
        }
    }
    let actual_proof_bytes_hash = direct_ballot_relation_proof_bytes_hash(proof_bytes);
    if actual_proof_bytes_hash != expected_proof_bytes_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public proof transport full proof hash does not match",
        ));
    }
    let actual_chunk_merkle_root = chunk_root(proof_bytes, chunk_size_bytes)?;
    if actual_chunk_merkle_root != expected_chunk_merkle_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public proof transport chunk Merkle root does not match",
        ));
    }

    Ok(())
}

fn direct_ballot_public_proof_transport_hash(
    setup_package: &Value,
    ballot: &DirectEncryptedBallot,
    statement_hash: &str,
    proof_bytes_hash: &str,
    proof_byte_length: usize,
    chunk_size_bytes: usize,
    chunk_count: usize,
    chunk_hashes: &[String],
    chunk_merkle_root: &str,
) -> CanonicalResult<String> {
    validate_direct_ballot_hash_hex(statement_hash, "statementHash")?;
    validate_direct_ballot_hash_hex(proof_bytes_hash, "proofBytesHash")?;
    validate_direct_ballot_hash_hex(chunk_merkle_root, "proofChunkMerkleRoot")?;
    let collective_public_key_root = required_string_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
    )?;
    let ballot_layout_hash =
        required_string_path(setup_package, &["profileBindings", "encryptedBallotLayoutHash"])?;
    let proof_profile_hash = direct_ballot_relation_proof_profile_hash()?;

    derive_protocol_hash(
        "ProofBytesHash",
        &json!({
            "objectType": "DirectEncryptedBallotProofTransport",
            "objectVersion": 1,
            "proofByteLength": proof_byte_length,
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "chunkHashes": chunk_hashes,
            "chunkMerkleRoot": chunk_merkle_root,
            "fullProofHash": proof_bytes_hash,
            "statementHash": statement_hash,
            "ciphertextRoot": ballot.ciphertext_root,
            "voterIdentity": ballot.input.voter_identity,
            "actionContextHash": ballot.input.action_context_hash,
            "profileId": PROFILE_ID,
            "profileHash": profile_hash()?,
            "collectivePublicKeyRoot": collective_public_key_root,
            "ballotLayoutHash": ballot_layout_hash,
            "proofProfileHash": proof_profile_hash,
        }),
    )
}

pub(crate) fn run_direct_encrypted_ballot(request: &Value) -> CanonicalResult<Value> {
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
            "direct encrypted ballot command currently supports at most twenty ballots",
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
    validate_disjoint_direct_ballot_randomness(
        &ballot_encryption_randomness.encryption_seed_hexes,
        &proof_mask_randomness.ballot_proof_randomness_hexes,
    )?;

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
            setup_package,
            encrypted_ballot,
            &proof_generation.statement_hash_hex,
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
            "direct encrypted ballot command requires at least one proof",
        )
    })?;
    let total_proof_bytes = proof_summaries
        .iter()
        .map(|proof_summary| proof_summary.proof_size_bytes)
        .sum::<usize>();
    let aggregation_result = verify_direct_ballot_aggregation(&evaluator_key, &encrypted_ballots)?;
    let evaluator_replay = match optional_direct_ballot_top_count_request(request)? {
        Some(top_count_request) => {
            let evaluations = run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
                setup_package,
                &evaluator_key,
                &aggregation_result.aggregate_ciphertext,
                &aggregation_result.aggregate_scores,
                encrypted_ballots.len(),
                &top_count_request.top_counts,
                top_count_request.target_finality_policy_hash.as_deref(),
            )?;
            if top_count_request.report_single_result {
                evaluations
                    .into_iter()
                    .next()
                    .expect("single top-count request produces one evaluator report")
            } else {
                Value::Array(evaluations)
            }
        }
        None => json!(
            "Not run in this command. Supply topCount to attempt the packed batched-pair evaluator route over the direct aggregate."
        ),
    };

    let ciphertext_byte_lengths = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ciphertext_canonical_byte_length)
        .collect::<Vec<_>>();
    let encrypted_ballot_hashes = encrypted_ballots
        .iter()
        .map(|ballot| ballot.encrypted_ballot_hash.clone())
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
        "encryptedBallots": {
            "encryptedBallotHashes": encrypted_ballot_hashes,
            "ciphertextRoots": ciphertext_roots,
            "ciphertextCanonicalByteLengths": ciphertext_byte_lengths,
            "ballotEncryptionRandomness": ballot_encryption_randomness.report_value(),
            "result": "Direct score slots, one-hot witnesses, batch encoding, all data-limb encryption algebra, and reserved zero slots passed private preflight."
        },
        "proofAttempt": {
            "relation": "all BGV data-prime encryption equations for c0=b*u+p*e0+encode(score) and c1=a*u+p*e1, with score-to-encoding carry linkage",
            "coverage": "all RNS limb encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support are checked by one internal binary transcript; claim soundness and zero-knowledge are not accepted for the current proof model",
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
            "challengeSoundness": format!("single nominal {}-bit challenge; claim soundness is not accepted because weaker subrelations reduce the challenge modulo smaller rings and the current support-proof model is not accepted", direct_ballot_relation_challenge_bits()),
            "proofAccounting": direct_ballot_relation_proof_accounting(first_proof.proof_size_bytes, total_proof_bytes)?,
            "proofTransport": {
                "encoding": "binary proof chunks",
                "status": "each generated proof is framed into fixed-size binary chunks, chunk-hash checked, root-checked, reassembled, and verified from the transported bytes",
                "retention": "proof chunks and reassembled proof bytes are verified and then dropped; the report keeps hashes, sizes, chunk counts, and chunk Merkle roots only",
                "chunkSizeBytes": DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
                "chunksPerProof": first_proof.proof_chunk_count,
                "chunksForBatch": chunk_count_for_bytes(total_proof_bytes, DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)?,
                "transportedProofSizeBytes": first_proof.transported_proof_size_bytes,
                "transportedProofBytesHash": first_proof.transported_proof_bytes_hash,
                "firstProofChunkMerkleRoot": first_proof.proof_chunk_merkle_root,
                "firstProofChunkHashes": first_proof.proof_chunk_hashes,
                "firstProofPublicTransportHash": first_proof.public_proof_transport_hash,
                "firstProofStatementHash": first_proof.statement_hash_hex,
                "proofProfileHash": direct_ballot_relation_proof_profile_hash()?
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
            "generation": "Generated and verified one internal binary proof for the all-limb BGV encryption relation, score-linear constraints, and support constraints. This is internal relation evidence only; the proof model is not claim-bearing until weakest-relation soundness and zero-knowledge support checks are fixed.",
            "fullRnsCoverage": "The proof covers all 17 BGV RNS limbs with one shared randomizer, error, encoding-carry, score, and one-hot response vector.",
            "blocker": "Next missing pieces are accepted weakest-relation soundness accounting, replacement or formal redesign of witness-dependent support commitments, Fiat-Shamir/QROM review, mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, public package proof transport for an accepted proof profile, public accepted randomness API boundaries, and target-bound threshold PartDec/recombination math. Runs using development-deterministic-fixture proof masks or ballot-encryption randomness remain fixture evidence only."
        },
        "aggregation": aggregation_result.report,
        "evaluatorReplay": evaluator_replay,
        "decision": "Direct BGV ballot encryption, all-limb private preflight, one widened shared-response internal proof, direct ciphertext aggregation, binary chunk proof transport with public hashes, and requested-top-count encrypted sparse target projection are the active path. They are not claim-bearing because proof soundness is not accepted, current support commitments are not accepted as zero-knowledge, mobile evidence is missing, public accepted proof transport is missing, public accepted randomness boundaries are not finalized, and target-bound threshold PartDec/recombination math is not closed."
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
    let encrypted_ballot_hash = direct_encrypted_ballot_hash(
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
        encrypted_ballot_hash,
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
        "result": "Verified the supplied direct ballot proofs, aggregated their ciphertexts, and privately checked the aggregate against the plaintext oracle without publishing aggregate scores.",
        "ballotCount": encrypted_ballots.len(),
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "aggregateCiphertextCanonicalByteLength": aggregate_ciphertext_canonical_bytes_hex.len() / 2,
        "privateCorrectnessCheck": "aggregate score slots matched the plaintext oracle"
    });

    Ok(DirectBallotAggregationResult {
        report,
        aggregate_ciphertext,
        aggregate_scores,
    })
}

fn run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    aggregate_ciphertext: &Ciphertext,
    aggregate_scores: &[u64],
    ballot_count: usize,
    top_counts: &[usize],
    target_finality_policy_hash: Option<&str>,
) -> CanonicalResult<Vec<Value>> {
    if top_counts.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot evaluator requires at least one top count",
        ));
    }
    let score_domain_max = direct_ballot_comparison_domain_max(ballot_count)?;
    let aggregate_ciphertext_root = ciphertext_object_root(aggregate_ciphertext)?;
    let aggregate_ciphertext_canonical_byte_length =
        ciphertext_canonical_bytes_hex(aggregate_ciphertext)?.len() / 2;
    let top_count_seed = top_counts
        .iter()
        .map(|top_count| top_count.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let replay_seed = hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/packed-batched-pair-evaluator-seed-v1",
        &[
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

    let mut evaluations = Vec::with_capacity(top_counts.len());
    for top_count in top_counts {
        let target_layout_root = target_layout_hash(DIRECT_BALLOT_OPTION_COUNT)?;
        let target = project_packed_sparse_target_from_rank_evaluation(
            &context,
            &rank_evaluation,
            DIRECT_BALLOT_OPTION_COUNT,
            *top_count,
        )?;
        let replay_time_milliseconds = replay_started.elapsed_milliseconds();
        let target_id_root = ciphertext_object_root(&target.target_id)?;
        let target_order_root = ciphertext_object_root(&target.target_order)?;
        let target_ciphertext_hash = direct_ballot_target_ciphertext_hash(
            &aggregate_ciphertext_root,
            *top_count,
            &target_layout_root,
            &target_id_root,
            &target_order_root,
        )?;
        let evaluator_replay_context_hash = direct_ballot_evaluator_replay_context_hash(
            setup_package,
            &aggregate_ciphertext_root,
            aggregate_ciphertext_canonical_byte_length,
            ballot_count,
            *top_count,
            score_domain_max,
            context.working_level(),
            &target_layout_root,
        )?;
        let evaluator_replay_record_hash = direct_ballot_evaluator_replay_record_hash(
            setup_package,
            &aggregate_ciphertext_root,
            &evaluator_replay_context_hash,
            &target_ciphertext_hash,
            &target_layout_root,
        )?;
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
        let target_proposal = direct_ballot_target_proposal(
            setup_package,
            &aggregate_ciphertext_root,
            &evaluator_replay_context_hash,
            &evaluator_replay_record_hash,
            &target_ciphertext_hash,
            &target_layout_root,
            target_finality_policy_hash,
        )?;

        evaluations.push(json!({
            "result": "Replayed the packed batched-pair encrypted evaluator over the direct aggregate and produced a sparse encrypted target without opening ranks, comparisons, masks, aggregate scores, or evaluator intermediates.",
            "topCount": top_count,
            "scoreDomainMax": score_domain_max,
            "tiePolicy": TIE_POLICY,
            "workingLevel": context.working_level(),
            "packedScoreRoot": packed_score_root.clone(),
            "rankRoot": rank_root.clone(),
            "targetProjection": "Encrypted sparse target projection completed for the requested top count; intermediate evaluator ciphertexts remain unopened.",
            "targetLayoutHash": target_layout_root,
            "targetIdRoot": target_id_root,
            "targetOrderRoot": target_order_root,
            "targetCiphertextHash": target_ciphertext_hash,
            "evaluatorReplayContextHash": evaluator_replay_context_hash,
            "evaluatorReplayRecordHash": evaluator_replay_record_hash,
            "targetProposal": target_proposal,
            "privateCorrectnessCheck": "The command privately checked the final target ciphertext against the plaintext oracle and does not publish aggregate scores, ranks, comparisons, masks, or decoded target slots in the replay report.",
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
    let mut ranks_by_option = [0_usize; DIRECT_BALLOT_OPTION_COUNT];
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

fn direct_ballot_target_ciphertext_hash(
    aggregate_ciphertext_root: &str,
    top_count: usize,
    target_layout_hash: &str,
    target_id_root: &str,
    target_order_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedSparseTargetProjectionHash",
        &json!({
            "objectType": "EncryptedSparseTargetCiphertext",
            "objectVersion": 1,
            "aggregateCiphertextRoot": aggregate_ciphertext_root,
            "topCount": top_count,
            "tiePolicy": TIE_POLICY,
            "targetLayoutHash": target_layout_hash,
            "targetIdRoot": target_id_root,
            "targetOrderRoot": target_order_root,
            "openedIntermediates": [],
        }),
    )
}

fn direct_ballot_evaluator_replay_context_hash(
    setup_package: &Value,
    aggregate_ciphertext_root: &str,
    aggregate_ciphertext_canonical_byte_length: usize,
    ballot_count: usize,
    top_count: usize,
    score_domain_max: u64,
    working_level: usize,
    target_layout_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EvaluatorReplayContextHash",
        &json!({
            "objectType": "DirectEncryptedBallotEvaluatorReplayContext",
            "objectVersion": 1,
            "setupPackageHash": setup_package_hash(setup_package)?,
            "ceremonyId": required_string_path(setup_package, &["setupInputs", "ceremonyId"])?,
            "manifestHash": required_string_path(setup_package, &["setupInputs", "manifestHash"])?,
            "thresholdProfileHash": required_string_path(setup_package, &["setupInputs", "thresholdProfileHash"])?,
            "aggregateCiphertextRoot": aggregate_ciphertext_root,
            "aggregateCiphertextCanonicalByteLength": aggregate_ciphertext_canonical_byte_length,
            "ballotCount": ballot_count,
            "topCount": top_count,
            "scoreDomainMax": score_domain_max,
            "tiePolicy": TIE_POLICY,
            "workingLevel": working_level,
            "profileHash": profile_hash()?,
            "directComparisonProfileHash": direct_comparison_profile_hash()?,
            "targetLayoutHash": target_layout_hash,
            "intermediateOpeningsAllowed": false,
        }),
    )
}

fn direct_ballot_evaluator_replay_record_hash(
    setup_package: &Value,
    aggregate_ciphertext_root: &str,
    evaluator_replay_context_hash: &str,
    target_ciphertext_hash: &str,
    target_layout_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EvaluatorReplayRecordHash",
        &json!({
            "objectType": "EvaluatorReplayRecord",
            "objectVersion": 1,
            "ceremonyId": required_string_path(setup_package, &["setupInputs", "ceremonyId"])?,
            "electionManifestHash": required_string_path(setup_package, &["setupInputs", "manifestHash"])?,
            "encryptedBallotAggregateHash": aggregate_ciphertext_root,
            "evaluatorReplayProfileHash": direct_comparison_profile_hash()?,
            "evaluatorReplayContextHash": evaluator_replay_context_hash,
            "targetCiphertextHash": target_ciphertext_hash,
            "targetLayoutHash": target_layout_hash,
        }),
    )
}

fn direct_ballot_target_proposal(
    setup_package: &Value,
    aggregate_ciphertext_root: &str,
    evaluator_replay_context_hash: &str,
    evaluator_replay_record_hash: &str,
    target_ciphertext_hash: &str,
    target_layout_hash: &str,
    target_finality_policy_hash: Option<&str>,
) -> CanonicalResult<Value> {
    let Some(target_finality_policy_hash) = target_finality_policy_hash else {
        return Ok(json!({
            "status": "not constructed because targetFinalityPolicyHash was not supplied",
            "requiredForFinality": "target proposal hashing requires the finality policy hash"
        }));
    };

    validate_direct_ballot_hash_hex(target_finality_policy_hash, "targetFinalityPolicyHash")?;
    let proposal_without_hash = json!({
        "ceremonyId": required_string_path(setup_package, &["setupInputs", "ceremonyId"])?,
        "electionManifestHash": required_string_path(setup_package, &["setupInputs", "manifestHash"])?,
        "thresholdProfileHash": required_string_path(setup_package, &["setupInputs", "thresholdProfileHash"])?,
        "evaluatorReplayContextHash": evaluator_replay_context_hash,
        "evaluatorReplayRecordHash": evaluator_replay_record_hash,
        "encryptedBallotAggregateHash": aggregate_ciphertext_root,
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash,
        "evaluatorReplayProfileHash": direct_comparison_profile_hash()?,
        "targetFinalityPolicyHash": target_finality_policy_hash,
    });
    let target_proposal_hash = derive_protocol_hash("TargetProposalHash", &proposal_without_hash)?;

    Ok(json!({
        "targetProposalHash": target_proposal_hash,
        "ceremonyId": proposal_without_hash["ceremonyId"],
        "electionManifestHash": proposal_without_hash["electionManifestHash"],
        "thresholdProfileHash": proposal_without_hash["thresholdProfileHash"],
        "evaluatorReplayContextHash": proposal_without_hash["evaluatorReplayContextHash"],
        "evaluatorReplayRecordHash": proposal_without_hash["evaluatorReplayRecordHash"],
        "encryptedBallotAggregateHash": proposal_without_hash["encryptedBallotAggregateHash"],
        "targetCiphertextHash": proposal_without_hash["targetCiphertextHash"],
        "targetLayoutHash": proposal_without_hash["targetLayoutHash"],
        "evaluatorReplayProfileHash": proposal_without_hash["evaluatorReplayProfileHash"],
        "targetFinalityPolicyHash": proposal_without_hash["targetFinalityPolicyHash"],
    }))
}

fn optional_direct_ballot_top_count_request(
    request: &Value,
) -> CanonicalResult<Option<DirectBallotTopCountRequest>> {
    let has_top_count = request.get("topCount").is_some();
    let has_top_counts = request.get("topCounts").is_some();
    if has_top_count && has_top_counts {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "supply either topCount or topCounts, not both",
        ));
    }
    let target_finality_policy_hash = request
        .get("targetFinalityPolicyHash")
        .and_then(Value::as_str)
        .map(|hash| {
            validate_direct_ballot_hash_hex(hash, "targetFinalityPolicyHash")?;
            Ok(hash.to_string())
        })
        .transpose()?;
    if has_top_counts {
        let values = request
            .get("topCounts")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "topCounts must be an array",
                )
            })?;
        if values.is_empty() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "topCounts must contain at least one top count",
            ));
        }
        let top_counts = values
            .iter()
            .map(read_direct_ballot_top_count_value)
            .collect::<CanonicalResult<Vec<_>>>()?;
        validate_unique_top_counts(&top_counts)?;

        return Ok(Some(DirectBallotTopCountRequest {
            top_counts,
            report_single_result: false,
            target_finality_policy_hash,
        }));
    }

    let Some(value) = request.get("topCount") else {
        return Ok(None);
    };
    let top_count = read_direct_ballot_top_count_value(value)?;

    Ok(Some(DirectBallotTopCountRequest {
        top_counts: vec![top_count],
        report_single_result: true,
        target_finality_policy_hash,
    }))
}

fn read_direct_ballot_top_count_value(value: &Value) -> CanonicalResult<usize> {
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

    Ok(top_count)
}

fn validate_unique_top_counts(top_counts: &[usize]) -> CanonicalResult<()> {
    let mut seen_top_counts = BTreeSet::new();
    for top_count in top_counts {
        if !seen_top_counts.insert(*top_count) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "topCounts must not contain duplicates",
            ));
        }
    }

    Ok(())
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

fn direct_encrypted_ballot_hash(
    setup_package: &Value,
    ballot: &DirectBallotInput,
    ciphertext_root: &str,
    ciphertext_canonical_byte_length: usize,
) -> CanonicalResult<String> {
    let package_json = canonical_json(&json!({
            "setupPackageHash": setup_package_hash(setup_package)?,
            "voterIdentity": ballot.voter_identity,
            "actionContextHash": ballot.action_context_hash,
            "ciphertextRoot": ciphertext_root,
            "ciphertextCanonicalByteLength": ciphertext_canonical_byte_length
    }))?;
    Ok(hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/encrypted-ballot-hash-v1",
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
            "direct encrypted ballot command requires at least one ballot",
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
    validate_unique_direct_ballot_randomness(
        &encryption_seed_hexes,
        "ballotEncryptionRandomness.encryptionSeedHexes",
    )?;

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
    validate_unique_direct_ballot_randomness(
        &ballot_proof_randomness_hexes,
        "proofMaskRandomness.ballotProofRandomnessHexes",
    )?;
    if value.get("refreshShareProofRandomnessHexes").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "proofMaskRandomness.refreshShareProofRandomnessHexes is not accepted because evaluator intermediate openings are not part of the direct ballot path",
        ));
    }

    Ok(DirectBallotProofMaskRandomness {
        source,
        ballot_proof_randomness_hexes,
    })
}

fn validate_unique_direct_ballot_randomness(values: &[String], label: &str) -> CanonicalResult<()> {
    validate_unique_strings(values, label, "repeats direct ballot randomness")
}

fn validate_unique_strings(
    values: &[String],
    label: &str,
    duplicate_message: &str,
) -> CanonicalResult<()> {
    let mut seen_values = BTreeSet::new();
    for (value_index, value) in values.iter().enumerate() {
        if !seen_values.insert(value.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{label}[{value_index}] {duplicate_message}"),
            ));
        }
    }

    Ok(())
}

fn validate_disjoint_direct_ballot_randomness(
    encryption_seed_hexes: &[String],
    proof_randomness_hexes: &[String],
) -> CanonicalResult<()> {
    let encryption_seed_set = encryption_seed_hexes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for (proof_randomness_index, proof_randomness_hex) in proof_randomness_hexes.iter().enumerate()
    {
        if encryption_seed_set.contains(proof_randomness_hex.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "proofMaskRandomness.ballotProofRandomnessHexes[{proof_randomness_index}] must not reuse ballot encryption randomness"
                ),
            ));
        }
    }

    Ok(())
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

fn validate_direct_ballot_hash_hex(value: &str, label: &str) -> CanonicalResult<()> {
    validate_direct_ballot_randomness_hex(value, label, 64)
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
    use std::sync::OnceLock;

    use serde_json::json;

    use crate::hashing::derive_protocol_hash;

    use super::*;

    const DIRECT_BALLOT_TEST_SETUP_SEED: &str = "direct-encrypted-ballot-test-setup-seed";

    struct DirectBallotRelationProofFixture {
        setup_package: Value,
        evaluator_key: DevelopmentBgvKey,
        encrypted_ballot: DirectEncryptedBallot,
        proof_generation: relation_proof::DirectBallotRelationProofGeneration,
    }

    fn direct_ballot_relation_proof_fixture() -> &'static DirectBallotRelationProofFixture {
        static FIXTURE: OnceLock<DirectBallotRelationProofFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let setup_package = setup_package();
            let evaluator_key = development_evaluator_key_from_passive_setup_package(
                &setup_package,
                DIRECT_BALLOT_TEST_SETUP_SEED,
            )
            .expect("evaluator key");
            let encrypted_ballot =
                encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input(), 0)
                    .expect("encrypted ballot");
            let proof_randomness_seed_hex = direct_ballot_proof_randomness_seed(
                DIRECT_BALLOT_TEST_SETUP_SEED,
                &encrypted_ballot,
            );
            let proof_generation = generate_direct_ballot_relation_proof(
                &setup_package,
                &evaluator_key,
                &encrypted_ballot,
                &proof_randomness_seed_hex,
            )
            .expect("proof generation");

            DirectBallotRelationProofFixture {
                setup_package,
                evaluator_key,
                encrypted_ballot,
                proof_generation,
            }
        })
    }

    fn direct_ballot_test_proof_mask_randomness(ballot_count: usize) -> Value {
        json!({
            "source": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
            "ballotProofRandomnessHexes": (0..ballot_count)
                .map(|index| direct_ballot_test_randomness_hex("ballot-proof", index))
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

    fn direct_ballot_test_ballot_json(voter_identity: &str, ballot_index: usize) -> Value {
        json!({
            "voterIdentity": voter_identity,
            "actionContextHash": derive_protocol_hash(
                "ActionContextHash",
                &json!({
                    "action": "direct encrypted ballot randomness rejection test",
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
        let result = run_direct_encrypted_ballot(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
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
        .expect("direct encrypted ballot command succeeds");

        assert_eq!(
            result["proofAttempt"]["coverage"].as_str(),
            Some(
                "all RNS limb encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support are checked by one internal binary transcript; claim soundness and zero-knowledge are not accepted for the current proof model"
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
            result["proofAttempt"]["proofAccounting"]["proofModelAccepted"].as_bool(),
            Some(false)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["weakestRelationEffectiveBitsPerCheck"]
                .as_u64(),
            Some(16)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["supportRelationModulusBits"].as_u64(),
            Some(47)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["targetClassicalSoundnessBits"].as_u64(),
            Some(128)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["minimumIndependentRepetitionsForTarget"],
            Value::Null
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]
                ["estimatedIndependentRepetitionsFromWeakestRelationBeforeUnionLosses"]
                .as_u64(),
            Some(8)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["estimatedRepeatedProofSizeBytes"].as_u64(),
            Some(18_626_400 * 8)
        );
        assert_eq!(
            result["proofAttempt"]["proofAccounting"]["classicalSoundnessBitsAfterSupportUnionBound"],
            Value::Null
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
                .contains("claim soundness is not accepted")
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["encoding"].as_str(),
            Some("binary proof chunks")
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["status"].as_str(),
            Some(
                "each generated proof is framed into fixed-size binary chunks, chunk-hash checked, root-checked, reassembled, and verified from the transported bytes"
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
            result["proofAttempt"]["proofTransport"]["firstProofChunkHashes"]
                .as_array()
                .expect("first proof chunk hashes")
                .len(),
            18
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["firstProofPublicTransportHash"]
                .as_str()
                .expect("first proof public transport hash")
                .len(),
            128
        );
        assert_eq!(
            result["proofAttempt"]["proofTransport"]["proofProfileHash"]
                .as_str()
                .expect("proof profile hash")
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
                "Next missing pieces are accepted weakest-relation soundness accounting, replacement or formal redesign of witness-dependent support commitments, Fiat-Shamir/QROM review, mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, public package proof transport for an accepted proof profile, public accepted randomness API boundaries, and target-bound threshold PartDec/recombination math. Runs using development-deterministic-fixture proof masks or ballot-encryption randomness remain fixture evidence only."
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
            result["encryptedBallots"]["ciphertextRoots"]
                .as_array()
                .expect("ciphertext roots")
                .len(),
            1
        );
        assert_eq!(
            result["encryptedBallots"]["ballotEncryptionRandomness"]["source"].as_str(),
            Some(DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE)
        );
        assert_eq!(
            result["encryptedBallots"]["ballotEncryptionRandomness"]
                ["ballotEncryptionRandomnessCount"]
                .as_u64(),
            Some(1)
        );
        assert_eq!(
            result["encryptedBallots"]["ballotEncryptionRandomness"]["randomnessBytesPerBallot"]
                .as_u64(),
            Some(32)
        );
        assert!(
            result["encryptedBallots"]["ballotEncryptionRandomness"]["retention"]
                .as_str()
                .expect("encryption randomness retention")
                .contains("not returned")
        );
        assert_eq!(result["aggregation"]["ballotCount"].as_u64(), Some(1));
        assert_eq!(
            result["aggregation"]["result"].as_str(),
            Some(
                "Verified the supplied direct ballot proofs, aggregated their ciphertexts, and privately checked the aggregate against the plaintext oracle without publishing aggregate scores."
            )
        );
        assert!(result["aggregation"].get("aggregateScores").is_none());
        assert!(result["aggregation"].get("plaintextOracleScores").is_none());
        assert_eq!(
            result["aggregation"]["privateCorrectnessCheck"].as_str(),
            Some("aggregate score slots matched the plaintext oracle")
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

        let error = run_direct_encrypted_ballot(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS + 1),
            "ballots": ballots
        }))
        .expect_err("oversized direct ballot batch must reject before encryption");

        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
        assert!(error.message.contains("supports at most twenty ballots"));
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_missing_ballot_encryption_randomness() {
        let setup_package = setup_package();
        let error = run_direct_encrypted_ballot(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
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
        let error = run_direct_encrypted_ballot(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
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
    fn direct_encrypted_ballot_command_rejects_reused_encryption_randomness() {
        let setup_package = setup_package();
        let reused_randomness = direct_ballot_test_randomness_hex("reused-encryption", 0);
        let error = run_direct_encrypted_ballot(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": {
                "source": DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE,
                "encryptionSeedHexes": [
                    reused_randomness,
                    reused_randomness
                ]
            },
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(2),
            "ballots": [
                direct_ballot_test_ballot_json("voter-randomness-1", 0),
                direct_ballot_test_ballot_json("voter-randomness-2", 1)
            ]
        }))
        .expect_err("reused ballot encryption randomness must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("repeats direct ballot randomness"));
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_reused_proof_randomness() {
        let setup_package = setup_package();
        let reused_randomness = direct_ballot_test_randomness_hex("reused-proof", 0);
        let error = run_direct_encrypted_ballot(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
            "proofMaskRandomness": {
                "source": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
                "ballotProofRandomnessHexes": [
                    reused_randomness,
                    reused_randomness
                ]
            },
            "ballots": [
                direct_ballot_test_ballot_json("voter-randomness-1", 0),
                direct_ballot_test_ballot_json("voter-randomness-2", 1)
            ]
        }))
        .expect_err("reused proof-mask randomness must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("repeats direct ballot randomness"));
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_proof_and_encryption_randomness_overlap() {
        let setup_package = setup_package();
        let reused_randomness = direct_ballot_test_randomness_hex("cross-purpose-randomness", 0);
        let error = run_direct_encrypted_ballot(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": {
                "source": DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE,
                "encryptionSeedHexes": [reused_randomness]
            },
            "proofMaskRandomness": {
                "source": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
                "ballotProofRandomnessHexes": [reused_randomness]
            },
            "ballots": [
                direct_ballot_test_ballot_json("voter-randomness-1", 0)
            ]
        }))
        .expect_err("proof-mask randomness must not reuse ballot encryption randomness");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains("must not reuse ballot encryption randomness")
        );
    }

    #[test]
    fn direct_encrypted_ballot_command_rejects_duplicate_voter_identity() {
        let setup_package = setup_package();
        let error = run_direct_encrypted_ballot(&json!({
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
        let error = run_direct_encrypted_ballot(&json!({
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
        let error = run_direct_encrypted_ballot(&json!({
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
        let error = run_direct_encrypted_ballot(&json!({
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
        let fixture = direct_ballot_relation_proof_fixture();

        let proof_verification = verify_direct_ballot_relation_proof(
            &fixture.setup_package,
            &fixture.evaluator_key,
            &fixture.encrypted_ballot,
            &fixture.proof_generation.proof_bytes,
        )
        .expect("proof verification");

        assert_eq!(
            proof_verification.relation_commitment_hash_hex,
            fixture.proof_generation.relation_commitment_hash_hex
        );
        assert_eq!(
            proof_verification.challenge,
            fixture.proof_generation.challenge
        );
        assert!(fixture.proof_generation.proof_size_bytes > 0);
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
        assert!(aggregation_report.report.get("aggregateScores").is_none());
        assert!(
            aggregation_report
                .report
                .get("plaintextOracleScores")
                .is_none()
        );
        assert_eq!(
            aggregation_report.report["privateCorrectnessCheck"].as_str(),
            Some("aggregate score slots matched the plaintext oracle")
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
    fn direct_ballot_packed_batched_pair_evaluator_top_count_1_matches_oracle() {
        assert_direct_ballot_packed_batched_pair_evaluator_matches_oracle(1);
    }

    #[test]
    fn direct_ballot_top_counts_reject_duplicates_before_evaluator_replay() {
        let error = optional_direct_ballot_top_count_request(&json!({
            "topCounts": [1, 1]
        }))
        .expect_err("duplicate top counts must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("topCounts must not contain duplicates"));
    }

    #[test]
    fn direct_ballot_public_proof_transport_rejects_wrong_chunk_hash() {
        let fixture = direct_ballot_relation_proof_fixture();
        let transport = transport_direct_ballot_binary_proof(
            &fixture.setup_package,
            &fixture.encrypted_ballot,
            &fixture.proof_generation.statement_hash_hex,
            &fixture.proof_generation.proof_bytes,
            &fixture.proof_generation.proof_bytes_hash,
            direct_ballot_relation_proof_bytes_hash,
            "direct ballot relation proof",
        )
        .expect("proof transport");
        let mut chunk_hashes = transport.chunk_hashes.clone();
        chunk_hashes[0] = "0".repeat(128);

        let error = verify_direct_ballot_public_proof_transport(
            &transport.proof_bytes,
            &transport.proof_bytes_hash,
            &chunk_hashes,
            DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
            &transport.chunk_merkle_root,
        )
        .expect_err("wrong chunk hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("chunk 0 hash does not match"));
    }

    #[test]
    fn direct_ballot_public_proof_transport_rejects_duplicate_chunk_hash() {
        let fixture = direct_ballot_relation_proof_fixture();
        let transport = transport_direct_ballot_binary_proof(
            &fixture.setup_package,
            &fixture.encrypted_ballot,
            &fixture.proof_generation.statement_hash_hex,
            &fixture.proof_generation.proof_bytes,
            &fixture.proof_generation.proof_bytes_hash,
            direct_ballot_relation_proof_bytes_hash,
            "direct ballot relation proof",
        )
        .expect("proof transport");
        let mut chunk_hashes = transport.chunk_hashes.clone();
        chunk_hashes[1] = chunk_hashes[0].clone();

        let error = verify_direct_ballot_public_proof_transport(
            &transport.proof_bytes,
            &transport.proof_bytes_hash,
            &chunk_hashes,
            DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
            &transport.chunk_merkle_root,
        )
        .expect_err("duplicate chunk hash must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("contains a duplicate chunk hash"));
    }

    #[test]
    fn direct_ballot_public_proof_transport_rejects_truncated_proof_bytes() {
        let fixture = direct_ballot_relation_proof_fixture();
        let transport = transport_direct_ballot_binary_proof(
            &fixture.setup_package,
            &fixture.encrypted_ballot,
            &fixture.proof_generation.statement_hash_hex,
            &fixture.proof_generation.proof_bytes,
            &fixture.proof_generation.proof_bytes_hash,
            direct_ballot_relation_proof_bytes_hash,
            "direct ballot relation proof",
        )
        .expect("proof transport");
        let truncated_len = transport
            .proof_bytes
            .len()
            .checked_sub(1)
            .expect("proof has bytes");

        let error = verify_direct_ballot_public_proof_transport(
            &transport.proof_bytes[..truncated_len],
            &transport.proof_bytes_hash,
            &transport.chunk_hashes,
            DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
            &transport.chunk_merkle_root,
        )
        .expect_err("truncated proof bytes must reject");

        assert!(
            error
                .message
                .contains("chunk hash count does not match proof length")
                || error.message.contains("chunk 17 hash does not match")
                || error.message.contains("full proof hash does not match")
                || error.message.contains("chunk Merkle root does not match")
        );
    }

    fn assert_direct_ballot_packed_batched_pair_evaluator_matches_oracle(top_count: usize) {
        let setup_package = setup_package();
        let result = run_direct_encrypted_ballot(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
            },
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
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
        .expect("direct encrypted ballot command succeeds");

        assert_eq!(
            result["evaluatorReplay"]["topCount"].as_u64(),
            Some(u64::try_from(top_count).expect("top count fits u64"))
        );
        assert_eq!(
            result["evaluatorReplay"]["privateCorrectnessCheck"].as_str(),
            Some("The command privately checked the final target ciphertext against the plaintext oracle and does not publish aggregate scores, ranks, comparisons, masks, or decoded target slots in the replay report.")
        );
        assert!(result["evaluatorReplay"].get("decodedTargetIds").is_none());
        assert!(result["evaluatorReplay"].get("decodedTargetOrders").is_none());
        assert!(result["evaluatorReplay"].get("plaintextOracleTargetIds").is_none());
        assert!(result["evaluatorReplay"].get("plaintextOracleTargetOrders").is_none());
        assert_eq!(
            result["evaluatorReplay"]["targetIdRoot"]
                .as_str()
                .expect("target id root")
                .len(),
            128
        );
        assert_eq!(
            result["evaluatorReplay"]["targetOrderRoot"]
                .as_str()
                .expect("target order root")
                .len(),
            128
        );
        assert_eq!(
            result["evaluatorReplay"]["targetCiphertextHash"]
                .as_str()
                .expect("target ciphertext hash")
                .len(),
            128
        );
        assert_eq!(
            result["evaluatorReplay"]["evaluatorReplayContextHash"]
                .as_str()
                .expect("replay context hash")
                .len(),
            128
        );
        assert_eq!(
            result["evaluatorReplay"]["evaluatorReplayRecordHash"]
                .as_str()
                .expect("replay record hash")
                .len(),
            128
        );
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_last_limb_ciphertext_mutation() {
        let fixture = direct_ballot_relation_proof_fixture();
        let mut encrypted_ballot = fixture.encrypted_ballot.clone();
        let last_limb_index = DATA_PRIMES.len() - 1;
        encrypted_ballot.ciphertext.components[0][last_limb_index][0] = add_mod(
            encrypted_ballot.ciphertext.components[0][last_limb_index][0],
            1,
            DATA_PRIMES[last_limb_index],
        )
        .expect("mutated residue");

        let error = verify_direct_ballot_relation_proof(
            &fixture.setup_package,
            &fixture.evaluator_key,
            &encrypted_ballot,
            &fixture.proof_generation.proof_bytes,
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
        let fixture = direct_ballot_relation_proof_fixture();
        let mut proof_generation = fixture.proof_generation.clone();
        let response_offset = direct_ballot_relation_response_offset(&proof_generation.proof_bytes);
        proof_generation.proof_bytes[response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &fixture.setup_package,
            &fixture.evaluator_key,
            &fixture.encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated response must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("randomizer support check failed"));
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_score_response_mutation() {
        let fixture = direct_ballot_relation_proof_fixture();
        let mut proof_generation = fixture.proof_generation.clone();
        let score_response_offset =
            direct_ballot_score_response_offset(&proof_generation.proof_bytes);
        proof_generation.proof_bytes[score_response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &fixture.setup_package,
            &fixture.evaluator_key,
            &fixture.encrypted_ballot,
            &proof_generation.proof_bytes,
        )
        .expect_err("mutated score response must reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("direct ballot score proof option 0"));
    }

    #[test]
    fn direct_ballot_shared_rns_relation_proof_rejects_one_hot_response_mutation() {
        let fixture = direct_ballot_relation_proof_fixture();
        let mut proof_generation = fixture.proof_generation.clone();
        let one_hot_response_offset =
            direct_ballot_score_response_offset(&proof_generation.proof_bytes)
                + DIRECT_BALLOT_OPTION_COUNT * direct_ballot_response_coefficient_bytes();
        proof_generation.proof_bytes[one_hot_response_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &fixture.setup_package,
            &fixture.evaluator_key,
            &fixture.encrypted_ballot,
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
        let fixture = direct_ballot_relation_proof_fixture();
        let mut proof_generation = fixture.proof_generation.clone();
        let commitment_offset =
            direct_ballot_relation_commitment_offset(&proof_generation.proof_bytes);
        proof_generation.proof_bytes[commitment_offset] ^= 1;

        let error = verify_direct_ballot_relation_proof(
            &fixture.setup_package,
            &fixture.evaluator_key,
            &fixture.encrypted_ballot,
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
        let fixture = direct_ballot_relation_proof_fixture();
        let wrong_setup_package = setup_package_with_seed("direct-encrypted-ballot-wrong-seed");
        let wrong_evaluator_key = development_evaluator_key_from_passive_setup_package(
            &wrong_setup_package,
            "direct-encrypted-ballot-wrong-seed",
        )
        .expect("wrong evaluator key");

        let error = verify_direct_ballot_relation_proof(
            &wrong_setup_package,
            &wrong_evaluator_key,
            &fixture.encrypted_ballot,
            &fixture.proof_generation.proof_bytes,
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

    fn direct_ballot_relation_response_offset(proof_bytes: &[u8]) -> usize {
        proof_bytes.len() - relation_proof::direct_ballot_relation_response_bytes()
    }

    fn direct_ballot_relation_commitment_offset(proof_bytes: &[u8]) -> usize {
        direct_ballot_relation_response_offset(proof_bytes)
            - relation_proof::direct_ballot_relation_commitment_bytes()
    }

    fn direct_ballot_response_coefficient_bytes() -> usize {
        relation_proof::direct_ballot_relation_response_bytes()
            / (4 * POLYNOMIAL_DEGREE
                + relation_proof::direct_ballot_relation_response_scalar_count())
    }

    fn direct_ballot_score_response_offset(proof_bytes: &[u8]) -> usize {
        direct_ballot_relation_response_offset(proof_bytes)
            + 4 * POLYNOMIAL_DEGREE * direct_ballot_response_coefficient_bytes()
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
