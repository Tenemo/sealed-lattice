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
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_RANDOMNESS_WIDTH,
    SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentLimb, SetupCommitmentValue,
    setup_commitment_full_value, setup_commitment_root,
};
use crate::bgv::setup::setup_proof::ProofByteSource;

use super::relation::{LimbColumnLayout, QUOTIENT_COLUMN_SUMCHECK_RESIDUAL};
use super::{
    CONSISTENCY_REPETITIONS, DEEP_EVALUATION_POINT_COUNT, DOMAIN_BLOWUP, LOW_DEGREE_QUERY_COUNT,
};

use super::prover;

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

fn repeated_hash(byte_pair: &str) -> String {
    byte_pair.repeat(64)
}

fn zero_setup_commitment_for_tests(
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> SetupCommitmentValue {
    SetupCommitmentValue {
        source_rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
        limbs: (0..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
            .map(|commitment_modulus_index| SetupCommitmentLimb {
                commitment_modulus_index,
                modulus: DATA_PRIMES[commitment_modulus_index],
                rows: vec![vec![0_u64; ring_degree]; SETUP_COMMITMENT_ROW_COUNT],
            })
            .collect(),
    }
}

fn private_vss_statement_for_ring_degree(ring_degree: usize) -> TrusteeEvaluationKeyStatement {
    let source_trustee_commitment_root = repeated_hash("33");
    let private_envelope_aad_hash = repeated_hash("44");
    let coefficient_commitments = (0..4_u64)
        .map(|shamir_coefficient_index| {
            zero_setup_commitment_for_tests(0, shamir_coefficient_index, ring_degree)
        })
        .collect::<Vec<_>>();
    let coefficient_commitment_roots = coefficient_commitments
        .iter()
        .map(|commitment| setup_commitment_root(commitment).expect("zero commitment root"))
        .collect();
    TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            setup_context_hash: repeated_hash("11"),
            trustee_roster_position: 0,
            binding_roots: Vec::new(),
        },
        ring_degree,
        proof: SetupProofStatement::PrivateVssShare(PrivateVssShareStatement {
            public_matrix_seed_hash: repeated_hash("66"),
            private_envelope_aad_hash,
            source_trustee_roster_position: 0,
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            source_rns_limb_index: 0,
            share_values: vec![0_u64; ring_degree],
            coefficient_commitment_roots,
            coefficient_commitments,
        }),
    }
}

fn private_vss_statement_for_context_tests() -> TrusteeEvaluationKeyStatement {
    private_vss_statement_for_ring_degree(SMALL_RING_DEGREE)
}

fn private_vss_proof_fixture(
    ring_degree: usize,
) -> (
    TrusteeEvaluationKeyStatement,
    super::relation::TrusteeEvaluationKeyWitness,
) {
    let statement = private_vss_statement_for_ring_degree(ring_degree);
    let coefficient_count = statement
        .private_vss_share()
        .expect("private VSS statement")
        .coefficient_commitments
        .len();
    let witness = super::relation::TrusteeEvaluationKeyWitness::PrivateVssShare {
        coefficient_messages_by_shamir_index: vec![vec![0_i64; ring_degree]; coefficient_count],
        opening_randomness_by_shamir_index_and_commitment_limb: vec![
            zero_opening_randomness_for_ring_degree(ring_degree);
            coefficient_count
        ],
        carry_witnesses: vec![0_i64; ring_degree],
    };
    (statement, witness)
}

fn zero_u64_vector() -> Vec<u64> {
    vec![0_u64; SMALL_RING_DEGREE]
}

fn zero_opening_randomness_for_ring_degree(ring_degree: usize) -> Vec<Vec<Vec<i64>>> {
    vec![
        vec![vec![0_i64; ring_degree]; SETUP_COMMITMENT_RANDOMNESS_WIDTH];
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
    ]
}

fn zero_opening_randomness() -> Vec<Vec<Vec<i64>>> {
    zero_opening_randomness_for_ring_degree(SMALL_RING_DEGREE)
}

fn zero_setup_commitment_value(
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
) -> SetupCommitmentValue {
    zero_setup_commitment_for_tests(
        source_rns_limb_index,
        shamir_coefficient_index,
        SMALL_RING_DEGREE,
    )
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
