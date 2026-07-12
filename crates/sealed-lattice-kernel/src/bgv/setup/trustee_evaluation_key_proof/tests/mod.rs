use super::proof_codec::{
    decode_trustee_evaluation_key_proof, decode_trustee_evaluation_key_proof_from_source,
    encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    EvaluationKeyShareKind, PrivateVssShareStatement, SuccinctSetupProofContext,
    TrusteeEvaluationKeyStatement, generate_development_public_key_share_instance,
    generate_development_trustee_instance, generate_development_trustee_instance_with_linkage,
    round_one_aggregate_diagonal_from_components,
};
use super::verifier::verify_evaluation_key_share;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::accepted_setup::describe_collective_bgv_setup_parameters;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentLimb,
    SetupCommitmentValue, setup_commitment_full_value, setup_commitment_root,
};
use crate::bgv::setup::setup_proof::ProofByteSource;
use crate::hashing::derive_canonical_object_hash;

use super::relation::{LimbColumnLayout, QUOTIENT_COLUMN_SUMCHECK_RESIDUAL};
use super::{
    CONSISTENCY_REPETITIONS, DEEP_EVALUATION_POINT_COUNT, DOMAIN_BLOWUP, LOW_DEGREE_QUERY_COUNT,
};

// The trustee evaluation-key proof behavioral suite is split by behavior into
// sibling modules. This module owns the shared imports, fixtures, deterministic
// seeds, statement/request builders, and the cross-cutting size helper
// `folded_layer_path_length` (used by both the codec shape test and the size
// profiler). Each sibling opens with `use super::*;` to reach this surface.
//
// `prover` and the command/family items are re-exported here so the sibling
// tests can keep referencing them through `super::` after the move under this
// `tests/` directory.
use super::{
    describe_target_decryption_share_proof_layout_from_request,
    generate_target_decryption_share_proof_bytes_from_request,
    generate_trustee_evaluation_key_proof_from_request, prover,
    verify_target_decryption_share_proof_bytes_from_request,
};

mod codec_and_commands;
mod relation_algebra;
mod same_secret_bridge;
mod soundness;
mod target_decryption_share;
mod verification;
mod vss_share_linkage;

const SMALL_RING_DEGREE: usize = 128;
// Smallest ring whose rate-1/2 low-degree claim bound folds past the adaptive
// final-coefficient cap, so proofs commit at least one folded Merkle layer.
const FOLDED_LAYER_RING_DEGREE: usize = 8192;
const PROOF_RANDOMNESS_SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const PROOF_RANDOMNESS_NONCE: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

struct TestChunkedProofBytes {
    chunks: Vec<Vec<u8>>,
    total_byte_length: usize,
}

impl TestChunkedProofBytes {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            total_byte_length: chunks.iter().map(Vec::len).sum(),
            chunks,
        }
    }
}

impl ProofByteSource for TestChunkedProofBytes {
    fn byte_length(&self) -> usize {
        self.total_byte_length
    }

    fn copy_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(destination.len()) else {
            return false;
        };
        if end > self.total_byte_length {
            return false;
        }
        let mut skipped_bytes = 0_usize;
        let mut destination_offset = 0_usize;
        for chunk in &self.chunks {
            let chunk_end = skipped_bytes + chunk.len();
            if offset + destination_offset < chunk_end {
                let chunk_offset = (offset + destination_offset).saturating_sub(skipped_bytes);
                let copy_length =
                    (chunk.len() - chunk_offset).min(destination.len() - destination_offset);
                destination[destination_offset..destination_offset + copy_length]
                    .copy_from_slice(&chunk[chunk_offset..chunk_offset + copy_length]);
                destination_offset += copy_length;
                if destination_offset == destination.len() {
                    return true;
                }
            }
            skipped_bytes = chunk_end;
        }
        destination.is_empty()
    }

    fn byte_at(&self, offset: usize) -> Option<u8> {
        let mut remaining_offset = offset;
        for chunk in &self.chunks {
            if remaining_offset < chunk.len() {
                return chunk.get(remaining_offset).copied();
            }
            remaining_offset -= chunk.len();
        }
        None
    }
}

fn folded_layer_path_length(extension_size: usize, fold_index: usize) -> usize {
    let leaf_count = extension_size >> (fold_index + 2);
    leaf_count.trailing_zeros() as usize
}

// The four succinct-setup statement-hash vectors are shared with the TS/WASM
// kernel test (bgv-succinct-setup-statement-hashes),
// pinning byte-identical statement hashes across the Rust and TS provers. The
// values live in test-vectors/succinct-setup-statement-hashes.json; after an
// intended encoding change, regenerate them there rather than editing copies in
// two languages.
fn expected_statement_hash_vectors() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/succinct-setup-statement-hashes.json"
    )))
    .expect("succinct-setup statement-hash vectors must parse")
}

fn round_one(level: usize) -> (EvaluationKeyShareKind, usize) {
    (EvaluationKeyShareKind::RelinearizationRoundOne, level)
}

fn round_two(level: usize) -> (EvaluationKeyShareKind, usize) {
    (EvaluationKeyShareKind::RelinearizationRoundTwo, level)
}

fn rotation(galois_element: usize, level: usize) -> (EvaluationKeyShareKind, usize) {
    (
        EvaluationKeyShareKind::GaloisRotation { galois_element },
        level,
    )
}

fn repeated_hash(byte_pair: &str) -> String {
    byte_pair.repeat(64)
}

// A committed-material VSS commitment plus its holder regeneration inputs, for
// the material-binding families' fixtures (share-linkage, same-secret bridge,
// target-decryption). The seed and context hash are threaded into the witness
// so the prover rebuilds byte-identical trees and the binding rows hold.
struct TestCommittedMaterialCommitment {
    commitment: super::relation::VssShareLinkageCommitment,
    commitment_value: serde_json::Value,
    commitment_root: String,
    material_seed_hex: String,
    context_hash: String,
}

fn test_committed_material_commitment(
    commitment_role: &str,
    commitment_context: serde_json::Value,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
    message_coefficient_bound: u64,
) -> TestCommittedMaterialCommitment {
    let context_bytes =
        serde_json::to_vec(&commitment_context).expect("serialize commitment context for seed");
    let material_seed_hex = crate::hashing::hash512_hex(
        "sealed-lattice/test/vss-committed-material-seed",
        &[commitment_role.as_bytes(), &context_bytes],
    );
    let request = serde_json::json!({
        "commitmentRole": commitment_role,
        "commitmentContext": commitment_context,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "messageCoefficients": message_coefficients,
        "messageCoefficientBound": message_coefficient_bound,
        "materialSeedHex": material_seed_hex,
    });
    let response = crate::bgv::setup::compute_vss_committed_material_commitment_request(&request)
        .expect("committed-material commitment");
    let material_roots_by_commitment_field = response["commitment"]["commitmentFields"]
        .as_array()
        .expect("commitment fields")
        .iter()
        .map(|field| {
            let bytes = crate::transcript_core::decode_hex(
                field["materialRootHex"]
                    .as_str()
                    .expect("material root hex"),
            )
            .expect("material root bytes");
            let digest: super::merkle_commitment::MerkleDigest =
                bytes.as_slice().try_into().expect("full Merkle digest");
            digest
        })
        .collect();

    TestCommittedMaterialCommitment {
        commitment: super::relation::VssShareLinkageCommitment {
            material_roots_by_commitment_field,
        },
        commitment_value: response["commitment"].clone(),
        commitment_root: response["commitmentRoot"]
            .as_str()
            .expect("commitment root")
            .to_string(),
        material_seed_hex,
        context_hash: response["commitmentContextHash"]
            .as_str()
            .expect("context hash")
            .to_string(),
    }
}

fn zero_setup_commitment_for_tests(
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    shamir_coefficient_index: u64,
) -> SetupCommitmentValue {
    SetupCommitmentValue {
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
        ring_degree: SMALL_RING_DEGREE,
        limbs: (0..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
            .map(|commitment_modulus_index| SetupCommitmentLimb {
                commitment_modulus_index,
                modulus: DATA_PRIMES[commitment_modulus_index],
                rows: vec![vec![0_u64; SMALL_RING_DEGREE]; SETUP_COMMITMENT_ROW_COUNT],
            })
            .collect(),
    }
}

fn private_vss_statement_for_context_tests() -> TrusteeEvaluationKeyStatement {
    let source_trustee_commitment_root = repeated_hash("33");
    let private_envelope_aad_hash = repeated_hash("44");
    let share_values_hash = repeated_hash("55");
    TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: super::PRIVATE_VSS_SHARE_PROOF_FAMILY.to_string(),
            ceremony_id: "ceremony-1".to_string(),
            manifest_hash: repeated_hash("11"),
            roster_hash: repeated_hash("22"),
            trustee_identity: "trustee-0".to_string(),
            trustee_roster_position: 0,
            setup_epoch: "setup-epoch-1".to_string(),
            binding_roots: vec![
                (
                    "sourceTrusteeCommitmentRoot".to_string(),
                    source_trustee_commitment_root.clone(),
                ),
                (
                    "privateEnvelopeAadHash".to_string(),
                    private_envelope_aad_hash.clone(),
                ),
                ("shareValuesHash".to_string(), share_values_hash.clone()),
            ],
        },
        ring_degree: SMALL_RING_DEGREE,
        keys: Vec::new(),
        vss_share_linkage: None,
        same_secret_bridge: None,
        same_secret_linkage: None,
        target_decryption_share: None,
        private_vss_share: Some(PrivateVssShareStatement {
            public_matrix_seed_hash: repeated_hash("66"),
            private_envelope_aad_hash,
            source_trustee_identity: "trustee-0".to_string(),
            source_trustee_roster_position: 0,
            recipient_identity: "trustee-2".to_string(),
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            source_rns_limb_index: 0,
            source_message_modulus: DATA_PRIMES[0],
            share_values_hash,
            share_values: vec![0_u64; SMALL_RING_DEGREE],
            coefficient_commitment_roots: vec![
                repeated_hash("77"),
                repeated_hash("88"),
                repeated_hash("99"),
                repeated_hash("aa"),
            ],
            coefficient_commitments: (0..4_u64)
                .map(|shamir_coefficient_index| {
                    zero_setup_commitment_for_tests(0, DATA_PRIMES[0], shamir_coefficient_index)
                })
                .collect(),
        }),
    }
}

fn statement_request_value(
    statement: &super::relation::TrusteeEvaluationKeyStatement,
) -> serde_json::Value {
    let keys = statement
        .keys
        .iter()
        .map(|key| {
            let mut entry = serde_json::json!({
                "proofFamily": match key.kind {
                    EvaluationKeyShareKind::RelinearizationRoundOne => "relinearization-round-one",
                    EvaluationKeyShareKind::RelinearizationRoundTwo => "relinearization-round-two",
                    EvaluationKeyShareKind::GaloisRotation { .. } => "galois-rotation",
                    EvaluationKeyShareKind::PublicKeyShare => "public-key-share",
                },
                "level": key.level,
                "keySwitchDomain": key.key_switch_domain,
                "keySwitchSeedHex": key.key_switch_seed_hex,
                "componentBByDigit": key.component_b_by_digit,
            });
            if let EvaluationKeyShareKind::GaloisRotation { galois_element } = key.kind {
                entry["rotation"] = serde_json::json!(galois_element);
            }
            if !key.round_one_aggregate_diagonal.is_empty() {
                entry["roundOneAggregateDiagonal"] =
                    serde_json::json!(key.round_one_aggregate_diagonal);
            }
            entry
        })
        .collect::<Vec<_>>();
    let mut context_value = serde_json::json!({
        "ceremonyId": statement.context.ceremony_id,
        "manifestHash": statement.context.manifest_hash,
        "rosterHash": statement.context.roster_hash,
        "trusteeIdentity": statement.context.trustee_identity,
        "trusteeRosterPosition": statement.context.trustee_roster_position,
        "setupEpoch": statement.context.setup_epoch,
    });
    for (binding_label, binding_root) in &statement.context.binding_roots {
        context_value[binding_label] = serde_json::json!(binding_root);
    }
    let mut request = serde_json::json!({
        "context": context_value,
        "ringDegree": statement.ring_degree,
        "keys": keys,
    });
    if let Some(linkage) = &statement.same_secret_linkage {
        request["sameSecretLinkage"] = serde_json::json!({
            "publicMatrixSeedHash": linkage.public_matrix_seed_hash,
            "commitments": linkage
                .commitments
                .iter()
                .map(setup_commitment_full_value)
                .collect::<Vec<_>>(),
        });
    }

    request
}

fn zero_i64_vector() -> Vec<i64> {
    vec![0_i64; SMALL_RING_DEGREE]
}

fn zero_u64_vector() -> Vec<u64> {
    vec![0_u64; SMALL_RING_DEGREE]
}

fn zero_opening_randomness() -> Vec<Vec<i64>> {
    vec![zero_i64_vector(); 5]
}

fn zero_setup_commitment_value(
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    shamir_coefficient_index: u64,
) -> SetupCommitmentValue {
    zero_setup_commitment_for_tests(
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
    )
}

fn vector_context_base(binding_roots: serde_json::Value) -> serde_json::Value {
    let mut context = serde_json::json!({
        "ceremonyId": "statement-vector-ceremony",
        "manifestHash": repeated_hash("10"),
        "rosterHash": repeated_hash("20"),
        "trusteeIdentity": "statement-vector-trustee",
        "trusteeRosterPosition": 0,
        "setupEpoch": "statement-vector-epoch",
    });
    for (key, value) in binding_roots
        .as_object()
        .expect("binding roots object")
        .iter()
    {
        context[key] = value.clone();
    }
    context
}

fn proof_randomness_fields(request: &mut serde_json::Value) {
    request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
}

fn generated_proof_bytes(generated: &serde_json::Value) -> Vec<u8> {
    crate::transcript_core::decode_hex(
        generated["proofBytesHex"]
            .as_str()
            .expect("generated proof bytes"),
    )
    .expect("generated proof bytes must decode")
}

fn verify_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    proof_bytes: &[u8],
) -> crate::encoding::CanonicalResult<()> {
    // Mirror the production dispatch: key-bearing statements verify against
    // the atom schedule backend, every other family on the shared engine.
    if crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule::statement_is_key_bearing(
        statement,
    ) {
        return crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule::verify_key_bearing_trustee_evaluation_keys(
            statement, proof_bytes,
        );
    }
    let proof = decode_trustee_evaluation_key_proof(statement, proof_bytes)?;

    verify_evaluation_key_share(statement, &proof)
}

fn verify_generated_proof(
    statement: &TrusteeEvaluationKeyStatement,
    generated: &serde_json::Value,
) {
    verify_proof_bytes(statement, &generated_proof_bytes(generated))
        .expect("generated proof should verify");
}

fn same_secret_statement_hash_vector_request() -> serde_json::Value {
    let commitments = DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .map(|(rns_limb_index, rns_prime)| {
            setup_commitment_full_value(&zero_setup_commitment_value(rns_limb_index, rns_prime, 0))
        })
        .collect::<Vec<_>>();
    let target_material = test_committed_material_commitment(
        "coefficient",
        serde_json::json!({ "testPurpose": "statement-vector-same-secret-bridge" }),
        0,
        DATA_PRIMES[0],
        SMALL_RING_DEGREE,
        &zero_u64_vector(),
        DATA_PRIMES[0],
    );
    let mut request = serde_json::json!({
        "context": vector_context_base(serde_json::json!({})),
        "ringDegree": SMALL_RING_DEGREE,
        "keys": [],
        "sameSecretLinkage": {
            "publicMatrixSeedHash": repeated_hash("40"),
            "commitments": commitments,
        },
        "sameSecretBridge": {
            "publicMatrixSeedHash": repeated_hash("40"),
            "targetBasisHash": crate::bgv::evaluator::top_k::canonical_target_basis_hash()
                .expect("canonical target basis hash"),
            "sourceTrusteeIdentity": "statement-vector-trustee",
            "sourceTrusteeRosterPosition": 0,
            "targetRnsPrimes": [DATA_PRIMES[0]],
            "targetConstantCommitmentRoots": [target_material.commitment_root],
            "targetConstantCommitments": [target_material.commitment_value],
        },
        "secretCoefficients": zero_i64_vector(),
        "errorCoefficientsByKey": [],
        "negativeIndicatorCoefficients": zero_i64_vector(),
        "openingRandomnessByLimb": vec![zero_opening_randomness(); DATA_PRIMES.len()],
        "vssCommittedMaterialSeedsByBoundMessage": [target_material.material_seed_hex],
        "vssCommittedMaterialContextHashesByBoundMessage": [target_material.context_hash],
    });
    proof_randomness_fields(&mut request);
    request
}

fn public_key_share_statement_hash_vector_request() -> serde_json::Value {
    let component_b_by_limb = DATA_PRIMES
        .iter()
        .map(|_| zero_u64_vector())
        .collect::<Vec<_>>();
    let target_material = test_committed_material_commitment(
        "coefficient",
        serde_json::json!({ "testPurpose": "statement-vector-public-key-bridge" }),
        0,
        DATA_PRIMES[0],
        SMALL_RING_DEGREE,
        &zero_u64_vector(),
        DATA_PRIMES[0],
    );
    let mut request = serde_json::json!({
        "context": vector_context_base(serde_json::json!({
            "sameSecretBridgeStatementRoot": repeated_hash("31"),
            "sameSecretBridgeProofRecordRoot": repeated_hash("32"),
        })),
        "ringDegree": SMALL_RING_DEGREE,
        "keys": [{
            "proofFamily": "public-key-share",
            "level": DATA_PRIMES.len() - 1,
            "keySwitchDomain": "accepted-bgv-public-a",
            "keySwitchSeedHex": repeated_hash("41"),
            "componentBByDigit": [component_b_by_limb],
        }],
        "sameSecretBridge": {
            "publicMatrixSeedHash": repeated_hash("41"),
            "targetBasisHash": crate::bgv::evaluator::top_k::canonical_target_basis_hash()
                .expect("canonical target basis hash"),
            "sourceTrusteeIdentity": "statement-vector-trustee",
            "sourceTrusteeRosterPosition": 0,
            "targetRnsPrimes": [DATA_PRIMES[0]],
            "targetConstantCommitmentRoots": [target_material.commitment_root],
            "targetConstantCommitments": [target_material.commitment_value],
        },
        "secretCoefficients": zero_i64_vector(),
        "errorCoefficientsByKey": [[zero_i64_vector()]],
        "negativeIndicatorCoefficients": zero_i64_vector(),
        "vssCommittedMaterialSeedsByBoundMessage": [target_material.material_seed_hex],
        "vssCommittedMaterialContextHashesByBoundMessage": [target_material.context_hash],
    });
    proof_randomness_fields(&mut request);
    request
}

fn trustee_evaluation_key_statement_hash_vector_request() -> serde_json::Value {
    // The key-bearing family links its atom secret to the canonical source
    // constant commitment directly. The TS/WASM vector builds the same source
    // body so both languages pin one statement hash.
    let source_commitment =
        setup_commitment_full_value(&zero_setup_commitment_value(0, DATA_PRIMES[0], 0));
    let mut request = serde_json::json!({
        "context": vector_context_base(serde_json::json!({
            "requiredGaloisSetHash": repeated_hash("33"),
            "evaluatorKeyScheduleRoot": repeated_hash("34"),
            "keySwitchDecompositionHash": repeated_hash("35"),
            "sourceConstantCoefficientCommitmentRoot": repeated_hash("36"),
        })),
        "ringDegree": SMALL_RING_DEGREE,
        "keys": [{
            "proofFamily": "relinearization-round-one",
            "level": 2,
            "keySwitchDomain": "relinearization-round-one",
            "keySwitchSeedHex": repeated_hash("42"),
            "componentBByDigit": [
                [zero_u64_vector(), zero_u64_vector(), zero_u64_vector()],
                [zero_u64_vector(), zero_u64_vector(), zero_u64_vector()],
                [zero_u64_vector(), zero_u64_vector(), zero_u64_vector()],
            ],
        }],
        "sameSecretLinkage": {
            "publicMatrixSeedHash": repeated_hash("43"),
            "commitments": [source_commitment],
        },
        "secretCoefficients": zero_i64_vector(),
        "errorCoefficientsByKey": [[zero_i64_vector(), zero_i64_vector(), zero_i64_vector()]],
        "negativeIndicatorCoefficients": zero_i64_vector(),
        "openingRandomnessByLimb": [zero_opening_randomness()],
    });
    proof_randomness_fields(&mut request);
    request
}

fn private_vss_setup_context_vector() -> serde_json::Value {
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");
    serde_json::json!({
        "ceremonyId": "statement-vector-ceremony",
        "manifestHash": repeated_hash("10"),
        "rosterHash": repeated_hash("20"),
        "setupParametersHash": setup_parameters["setupParametersHash"],
        "setupEpoch": "statement-vector-epoch",
    })
}

fn private_vss_statement_hash_vector_request() -> serde_json::Value {
    let setup_context = private_vss_setup_context_vector();
    let public_matrix_seed_hash = repeated_hash("40");
    let private_envelope_aad_hash = repeated_hash("44");
    let mut coefficient_commitments = Vec::new();
    let mut material_records = Vec::new();
    let mut requested_commitment_roots = Vec::new();
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        for shamir_coefficient_index in 0..4_u64 {
            let commitment =
                zero_setup_commitment_value(rns_limb_index, rns_prime, shamir_coefficient_index);
            let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
            if rns_limb_index == 0 {
                requested_commitment_roots.push(commitment_root.clone());
            }
            coefficient_commitments.push(serde_json::json!({
                "objectType": "VssCoefficientCommitment",
                "ceremonyId": "statement-vector-ceremony",
                "manifestHash": repeated_hash("10"),
                "rosterHash": repeated_hash("20"),
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": "statement-vector-epoch",
                "sourceTrusteeIdentity": "statement-vector-trustee",
                "sourceTrusteeRosterPosition": 0,
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": commitment_root,
            }));
            material_records.push(serde_json::json!({
                "objectType": "VssCoefficientCommitmentMaterial",
                "ceremonyId": "statement-vector-ceremony",
                "manifestHash": repeated_hash("10"),
                "rosterHash": repeated_hash("20"),
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": "statement-vector-epoch",
                "sourceTrusteeIdentity": "statement-vector-trustee",
                "sourceTrusteeRosterPosition": 0,
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": commitment_root,
                "commitment": setup_commitment_full_value(&commitment),
            }));
        }
    }
    let mut source_record = serde_json::json!({
        "objectType": "VssSourceTrusteeCoefficientCommitments",
        "ceremonyId": "statement-vector-ceremony",
        "manifestHash": repeated_hash("10"),
        "rosterHash": repeated_hash("20"),
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": "statement-vector-epoch",
        "sourceTrusteeIdentity": "statement-vector-trustee",
        "sourceTrusteeRosterPosition": 0,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "coefficientCommitments": coefficient_commitments,
    });
    let source_root =
        derive_canonical_object_hash(&source_record).expect("source trustee commitment root");
    source_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(source_root);
    let mut request = serde_json::json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeAadHash": private_envelope_aad_hash,
        "sourceTrusteeCoefficientCommitmentRecord": source_record,
        "sourceTrusteeCoefficientCommitmentMaterialRecords": material_records,
        "recipientIdentity": "statement-vector-recipient",
        "recipientRosterPosition": 2,
        "rnsLimbIndex": 0,
        "rnsPrime": DATA_PRIMES[0],
        "ringDegree": SMALL_RING_DEGREE,
        "shareValues": zero_u64_vector(),
        "coefficientCommitmentRoots": requested_commitment_roots,
        "coefficientMessagesByShamirIndex": vec![zero_u64_vector(); 4],
        "openingRandomnessByShamirIndex": vec![vec![zero_i64_vector(); 5]; 4],
    });
    proof_randomness_fields(&mut request);
    request
}

fn component_material_bytes_for_request_key(
    key: &super::relation::EvaluationKeyShareDescriptor,
    ring_degree: usize,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SLEKCMV1");
    for value in [key.level, ring_degree, key.level + 1, key.level + 1] {
        bytes.extend_from_slice(&(value as u64).to_le_bytes());
    }
    for component_b_by_limb in &key.component_b_by_digit {
        for component_b in component_b_by_limb {
            for coefficient in component_b {
                bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }

    bytes
}
