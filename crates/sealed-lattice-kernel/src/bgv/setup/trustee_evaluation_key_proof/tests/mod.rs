use super::proof_codec::{
    decode_trustee_evaluation_key_proof, decode_trustee_evaluation_key_proof_from_source,
    encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    EvaluationKeyShareKind, PrivateVssShareStatement, SetupProofStatement,
    SuccinctSetupProofContext, TrusteeEvaluationKeyStatement,
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

use super::relation::{LimbColumnLayout, QUOTIENT_COLUMN_SUMCHECK_RESIDUAL};
use super::{
    CONSISTENCY_REPETITIONS, DEEP_EVALUATION_POINT_COUNT, DOMAIN_BLOWUP, LOW_DEGREE_QUERY_COUNT,
};

use super::{generate_trustee_evaluation_key_proof_from_request, prover};

mod codec_and_commands;
mod relation_algebra;
mod soundness;

const SMALL_RING_DEGREE: usize = 128;
// Smallest ring whose rate-1/2 low-degree claim bound folds past the adaptive
// final-coefficient cap, so proofs commit at least one folded Merkle layer.
const FOLDED_LAYER_RING_DEGREE: usize = 8192;
const PROOF_RANDOMNESS_SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

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
}

fn folded_layer_path_length(extension_size: usize, fold_index: usize) -> usize {
    let leaf_count = extension_size >> (fold_index + 2);
    leaf_count.trailing_zeros() as usize
}

// Pins representative statement encodings that cross distinct setup proof
// parsing paths.
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

fn zero_setup_commitment_for_tests(
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
) -> SetupCommitmentValue {
    SetupCommitmentValue {
        source_rns_limb_index,
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
    TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            setup_context_hash: repeated_hash("11"),
            trustee_roster_position: 0,
            binding_roots: Vec::new(),
        },
        ring_degree: SMALL_RING_DEGREE,
        proof: SetupProofStatement::PrivateVssShare(PrivateVssShareStatement {
            public_matrix_seed_hash: repeated_hash("66"),
            private_envelope_aad_hash,
            source_trustee_roster_position: 0,
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            source_rns_limb_index: 0,
            share_values: vec![0_u64; SMALL_RING_DEGREE],
            coefficient_commitment_roots: vec![
                repeated_hash("77"),
                repeated_hash("88"),
                repeated_hash("99"),
                repeated_hash("aa"),
            ],
            coefficient_commitments: (0..4_u64)
                .map(|shamir_coefficient_index| {
                    zero_setup_commitment_for_tests(0, shamir_coefficient_index)
                })
                .collect(),
        }),
    }
}

fn statement_request_value(
    statement: &super::relation::TrusteeEvaluationKeyStatement,
) -> serde_json::Value {
    let keys = statement
        .keys()
        .iter()
        .map(|key| {
            let mut entry = serde_json::json!({
                "proofFamily": match key.kind {
                    EvaluationKeyShareKind::RelinearizationRoundOne => "relinearization-round-one",
                    EvaluationKeyShareKind::RelinearizationRoundTwo => "relinearization-round-two",
                    EvaluationKeyShareKind::GaloisRotation { .. } => "galois-rotation",
                },
                "level": key.level,
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
        "setupContextHash": statement.context.setup_context_hash,
        "trusteeRosterPosition": statement.context.trustee_roster_position,
    });
    for (binding_label, binding_root) in statement
        .family_shape()
        .binding_labels()
        .iter()
        .zip(&statement.context.binding_roots)
    {
        context_value[binding_label] = serde_json::json!(binding_root);
    }
    let mut request = serde_json::json!({
        "context": context_value,
        "keys": keys,
    });
    if let Some(linkage) = statement.same_secret_linkage() {
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

fn proof_generation_request(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &super::relation::TrusteeEvaluationKeyWitness,
) -> serde_json::Value {
    let mut request = statement_request_value(statement);
    request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients());
    request["errorCoefficientsByKey"] = serde_json::json!(witness.error_coefficients_by_key());
    if !witness
        .opening_randomness_by_source_limb_and_commitment_limb()
        .is_empty()
    {
        request["openingRandomnessBySourceLimbAndCommitmentLimb"] =
            serde_json::json!(witness.opening_randomness_by_source_limb_and_commitment_limb());
    }
    proof_randomness_fields(&mut request);
    request
}

fn zero_i64_vector() -> Vec<i64> {
    vec![0_i64; SMALL_RING_DEGREE]
}

fn zero_u64_vector() -> Vec<u64> {
    vec![0_u64; SMALL_RING_DEGREE]
}

fn zero_opening_randomness() -> Vec<Vec<Vec<i64>>> {
    vec![vec![zero_i64_vector(); 5]; SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()]
}

fn zero_setup_commitment_value(
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
) -> SetupCommitmentValue {
    zero_setup_commitment_for_tests(source_rns_limb_index, shamir_coefficient_index)
}

fn vector_context_base(binding_roots: serde_json::Value) -> serde_json::Value {
    let mut context = serde_json::json!({
        "setupContextHash": repeated_hash("10"),
        "trusteeRosterPosition": 0,
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
}

fn generated_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    generated: &serde_json::Value,
) -> Vec<u8> {
    let proof_family = statement.family_shape().proof_family();
    let proof_bytes_hash = generated["proofBytesHash"]
        .as_str()
        .expect("generated proof bytes hash");
    let proof_material = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
        proof_family,
        proof_bytes_hash,
    )
    .expect("generated proof material lookup")
    .expect("generated proof material remains retained");
    assert_eq!(
        proof_family,
        super::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "the retained proof command must produce trustee evaluation-key material"
    );
    let proof_bytes_hash = super::trustee_evaluation_key_proof_material_bytes_hash(&proof_material)
        .expect("generated proof bytes hash");
    assert_eq!(
        generated["proofBytesHash"]
            .as_str()
            .expect("generated proof bytes hash"),
        proof_bytes_hash,
    );

    proof_material.chunks().flatten().copied().collect()
}

fn verify_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    proof_bytes: &[u8],
) -> crate::encoding::CanonicalResult<()> {
    crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule::verify_key_bearing_trustee_evaluation_keys(
        statement, proof_bytes,
    )
}

fn verify_generated_proof(
    statement: &TrusteeEvaluationKeyStatement,
    generated: &serde_json::Value,
) -> Vec<u8> {
    let proof_bytes = generated_proof_bytes(statement, generated);
    verify_proof_bytes(statement, &proof_bytes).expect("generated proof should verify");
    proof_bytes
}

fn trustee_evaluation_key_statement_hash_vector_request() -> serde_json::Value {
    // The key-bearing family links its atom secret to the canonical source
    // constant commitment directly. The TS/WASM vector builds the same source
    // body so both languages pin one statement hash.
    let source_commitment = setup_commitment_full_value(&zero_setup_commitment_value(0, 0));
    let mut request = serde_json::json!({
        "context": vector_context_base(serde_json::json!({
            "evaluatorKeyScheduleRoot": repeated_hash("34"),
        })),
        "keys": [{
            "proofFamily": "relinearization-round-one",
            "level": 2,
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
        "openingRandomnessBySourceLimbAndCommitmentLimb": [zero_opening_randomness()],
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
        "participantCount": 10,
        "setupEpoch": "statement-vector-epoch",
    })
}

fn private_vss_statement_hash_vector_request() -> serde_json::Value {
    let setup_context = private_vss_setup_context_vector();
    let public_matrix_seed_hash = repeated_hash("40");
    let private_envelope_aad_hash = repeated_hash("44");
    let mut coefficient_commitment_roots = Vec::new();
    let mut material_records = Vec::new();
    for rns_limb_index in 0..DATA_PRIMES.len() {
        for shamir_coefficient_index in 0..4_u64 {
            let commitment = zero_setup_commitment_value(rns_limb_index, shamir_coefficient_index);
            let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
            coefficient_commitment_roots.push(commitment_root);
            material_records.push(setup_commitment_full_value(&commitment));
        }
    }
    let source_record = serde_json::json!({
        "objectType": "VssSourceTrusteeCoefficientCommitments",
        "sourceTrusteeIdentity": "statement-vector-trustee",
        "coefficientCommitmentRoots": coefficient_commitment_roots,
    });
    let mut request = serde_json::json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeAadHash": private_envelope_aad_hash,
        "sourceTrusteeRosterPosition": 0,
        "sourceTrusteeCoefficientCommitmentRecord": source_record,
        "sourceTrusteeCoefficientCommitmentMaterialRecords": material_records,
        "recipientRosterPosition": 2,
        "rnsLimbIndex": 0,
        "shareValues": zero_u64_vector(),
        "coefficientMessagesByShamirIndex": vec![zero_u64_vector(); 4],
        "openingRandomnessByShamirIndexAndCommitmentLimb": vec![zero_opening_randomness(); 4],
    });
    request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    request
}

fn component_material_bytes_for_request_key(
    key: &super::relation::EvaluationKeyShareDescriptor,
    ring_degree: usize,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SLEKCMV2");
    for component_b_by_limb in &key.component_b_by_digit {
        for component_b in component_b_by_limb {
            assert_eq!(component_b.len(), ring_degree);
            for coefficient in component_b {
                bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }

    bytes
}
