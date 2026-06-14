use super::proof_codec::{
    FIELD_RESIDUE_BYTE_WIDTH, decode_trustee_evaluation_key_proof,
    encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    EvaluationKeyShareKind, PrivateVssShareStatement, SuccinctSetupProofContext,
    TrusteeEvaluationKeyStatement, galois_automorphism_apply, galois_automorphism_transpose_apply,
    generate_development_public_key_share_instance, generate_development_trustee_ceremony_slice,
    generate_development_trustee_instance, generate_development_trustee_instance_with_linkage,
    round_one_aggregate_diagonal_from_components,
};
use super::verifier::verify_evaluation_key_share;
use crate::bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE};
use crate::bgv::setup::accepted_setup::describe_collective_bgv_setup_profile;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentLimb,
    SetupCommitmentValue, setup_commitment_full_value, setup_commitment_root,
};
use crate::hashing::derive_protocol_hash;

use std::collections::BTreeSet;
use std::time::Instant;

use super::extension_field::CHALLENGE_EXTENSION_DEGREE;
use super::merkle_commitment::LEAF_SALT_BYTES;
use super::relation::{
    EvaluationKeyShareDescriptor, LimbColumnLayout, PHASE_TWO_COLUMN_COUNT,
    SameSecretLinkageStatement,
};
use super::{
    COMMITMENT_BOUND_FACTOR, DEEP_POINT_COUNT, DOMAIN_BLOWUP, LOW_DEGREE_FINAL_COEFFICIENT_COUNT,
    LOW_DEGREE_QUERY_COUNT,
};
use crate::bgv::evaluator::records::MAXIMUM_OPTION_COUNT;
use crate::bgv::evaluator::top_k::{
    SELECTED_EVALUATOR_WORKING_LEVEL, direct_score_packing_basis_galois_elements,
    packed_rank_forward_basis_galois_elements, packed_rank_return_basis_galois_elements,
};

// Exact byte accounting of an encoded trustee evaluation-key proof, broken down
// by component. The formulas mirror `proof_codec::encode_trustee_evaluation_key_proof`
// exactly and are self-checked in `profile_trustee_proof_size_breakdown` against a
// real `encode(...).len()`. Sizes are parameterised by `field_element_bytes`,
// `hash_bytes`, and `salt_bytes` so the same function predicts the effect of a
// serialization lever (narrower field residues, narrower hashes) before it is
// implemented. Length-prefix `u64`s are fixed at eight bytes and tracked under
// `length_prefixes` so they are never confused with field or hash bytes.
#[derive(Default, Debug, Clone)]
struct ProofSizeBreakdown {
    length_prefixes: usize,
    commitment_roots: usize,
    masked_consistency_claims: usize,
    deep_evaluations: usize,
    low_degree_fold_roots: usize,
    low_degree_final_coefficients: usize,
    low_degree_query_pairs: usize,
    low_degree_query_paths: usize,
    phase_one_rows: usize,
    phase_one_paths: usize,
    phase_two_rows: usize,
    phase_two_paths: usize,
    leaf_salts: usize,
}

impl ProofSizeBreakdown {
    fn total(&self) -> usize {
        self.length_prefixes
            + self.commitment_roots
            + self.masked_consistency_claims
            + self.deep_evaluations
            + self.low_degree_fold_roots
            + self.low_degree_final_coefficients
            + self.low_degree_query_pairs
            + self.low_degree_query_paths
            + self.phase_one_rows
            + self.phase_one_paths
            + self.phase_two_rows
            + self.phase_two_paths
            + self.leaf_salts
    }

    // Bytes that carry field residues (base or extension), i.e. everything a
    // narrower field encoding would shrink.
    fn field_element_bytes(&self) -> usize {
        self.masked_consistency_claims
            + self.deep_evaluations
            + self.low_degree_final_coefficients
            + self.low_degree_query_pairs
            + self.phase_one_rows
            + self.phase_two_rows
    }

    // Bytes that carry Merkle hashes (roots and authentication paths), i.e.
    // everything a narrower hash digest would shrink.
    fn hash_bytes(&self) -> usize {
        self.commitment_roots
            + self.low_degree_fold_roots
            + self.low_degree_query_paths
            + self.phase_one_paths
            + self.phase_two_paths
    }

    // The per-query authentication path bytes that a batched opening replaces
    // with one shared node set per tree (the roots are unaffected).
    fn path_bytes(&self) -> usize {
        self.low_degree_query_paths + self.phase_one_paths + self.phase_two_paths
    }
}

fn committed_fold_count(extension_size: usize) -> usize {
    let initial_degree_bound = extension_size * COMMITMENT_BOUND_FACTOR / DOMAIN_BLOWUP;
    let fold_ratio = initial_degree_bound / LOW_DEGREE_FINAL_COEFFICIENT_COUNT;
    fold_ratio.trailing_zeros() as usize - 1
}

fn folded_layer_path_length(extension_size: usize, fold_index: usize) -> usize {
    let leaf_count = extension_size >> (fold_index + 2);
    leaf_count.trailing_zeros() as usize
}

fn analyze_proof_size(
    statement: &TrusteeEvaluationKeyStatement,
    field_element_bytes: usize,
    hash_bytes: usize,
    salt_bytes: usize,
) -> ProofSizeBreakdown {
    let extension_element_bytes = CHALLENGE_EXTENSION_DEGREE * field_element_bytes;
    let mut breakdown = ProofSizeBreakdown::default();
    // Proof magic plus the limb-count prefix.
    breakdown.length_prefixes += 8 + 8;
    for limb_index in 0..statement.limb_count() {
        let layout = LimbColumnLayout::new(statement, limb_index).expect("limb layout");
        let trace_size = layout.trace_size;
        let extension_size = trace_size * DOMAIN_BLOWUP;
        let tree_depth = extension_size.trailing_zeros() as usize;
        let phase_one_columns = layout.phase_one_physical_count();
        let total_columns = phase_one_columns + PHASE_TWO_COLUMN_COUNT;
        let claim_count = layout.claim_count();

        breakdown.commitment_roots += 2 * hash_bytes;
        breakdown.masked_consistency_claims += claim_count * field_element_bytes;
        breakdown.deep_evaluations += DEEP_POINT_COUNT * total_columns * extension_element_bytes;

        // Low-degree (batched FRI) proof.
        let folds = committed_fold_count(extension_size);
        breakdown.length_prefixes += 8; // folded-layer-root count
        breakdown.low_degree_fold_roots += folds * hash_bytes;
        breakdown.low_degree_final_coefficients +=
            LOW_DEGREE_FINAL_COEFFICIENT_COUNT * extension_element_bytes;
        for _query in 0..LOW_DEGREE_QUERY_COUNT {
            for fold_index in 0..folds {
                breakdown.low_degree_query_pairs += 2 * extension_element_bytes;
                breakdown.length_prefixes += 8; // path-length prefix
                breakdown.low_degree_query_paths +=
                    folded_layer_path_length(extension_size, fold_index) * hash_bytes;
            }
        }

        // Phase (witness/quotient tree) query openings: two coset-pair slots.
        for _query in 0..LOW_DEGREE_QUERY_COUNT {
            for _slot in 0..2 {
                breakdown.phase_one_rows += phase_one_columns * field_element_bytes;
                breakdown.leaf_salts += salt_bytes;
                breakdown.phase_one_paths += tree_depth * hash_bytes;
                breakdown.phase_two_rows += PHASE_TWO_COLUMN_COUNT * extension_element_bytes;
                breakdown.leaf_salts += salt_bytes;
                breakdown.phase_two_paths += tree_depth * hash_bytes;
            }
        }
    }

    breakdown
}

// A statement carrying only the shape the size analyzer reads (key kinds and
// levels, ring degree, and the linkage commitment count). Component vectors and
// commitment contents are left empty because `LimbColumnLayout` never reads
// them, so the full-profile shape can be analyzed at the production ring degree
// without running the prover or allocating witness material.
fn shape_only_trustee_statement(
    schedule: &[(EvaluationKeyShareKind, usize)],
    ring_degree: usize,
    linkage_commitment_count: usize,
) -> TrusteeEvaluationKeyStatement {
    let keys = schedule
        .iter()
        .map(|(kind, level)| EvaluationKeyShareDescriptor {
            kind: *kind,
            level: *level,
            key_switch_domain: "shape-only".to_string(),
            key_switch_seed_hex: "00".to_string(),
            component_b_by_digit: Vec::new(),
            round_one_aggregate_diagonal: Vec::new(),
        })
        .collect();
    let same_secret_linkage = (linkage_commitment_count > 0).then(|| SameSecretLinkageStatement {
        public_matrix_seed_hash: repeated_hash("00"),
        commitments: (0..linkage_commitment_count)
            .map(
                |index| crate::bgv::setup::commitment::SetupCommitmentValue {
                    source_rns_limb_index: index,
                    source_message_modulus: DATA_PRIMES[index],
                    shamir_coefficient_index: 0,
                    ring_degree,
                    limbs: Vec::new(),
                },
            )
            .collect(),
    });
    TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: super::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY.to_string(),
            ceremony_id: "shape-only".to_string(),
            manifest_hash: repeated_hash("11"),
            roster_hash: repeated_hash("22"),
            trustee_identity: "shape-only".to_string(),
            trustee_roster_position: 0,
            setup_epoch: "shape-only".to_string(),
            binding_roots: Vec::new(),
        },
        ring_degree,
        keys,
        same_secret_linkage,
        private_vss_share: None,
    }
}

// The frozen first-profile evaluation-key schedule shape: relinearization round
// one and round two plus the deduplicated Galois rotation basis, every key at
// the selected evaluator working level (mirrors `selected_rotation_schedule_entries`).
fn full_profile_schedule_shape() -> Vec<(EvaluationKeyShareKind, usize)> {
    let level = SELECTED_EVALUATOR_WORKING_LEVEL;
    let mut schedule = vec![
        (EvaluationKeyShareKind::RelinearizationRoundOne, level),
        (EvaluationKeyShareKind::RelinearizationRoundTwo, level),
    ];
    let mut rotations = BTreeSet::new();
    for galois_element in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)
        .expect("direct score packing basis")
    {
        rotations.insert(galois_element);
    }
    for galois_element in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)
        .expect("packed rank forward basis")
    {
        rotations.insert(galois_element);
    }
    for galois_element in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)
        .expect("packed rank return basis")
    {
        rotations.insert(galois_element);
    }
    for galois_element in rotations {
        schedule.push((
            EvaluationKeyShareKind::GaloisRotation { galois_element },
            level,
        ));
    }
    schedule
}

#[test]
#[ignore = "size profiler: run explicitly to measure proof byte breakdown"]
fn profile_trustee_proof_size_breakdown() {
    // A multi-limb, multi-key, linkage-bearing schedule at a near-full ring
    // degree, so the batched-path node sharing (which depends only on the query
    // count and tree depth, not the key count) matches the full-size ratio.
    let measurement_ring_degree = 16_384_usize;
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "5123e0f0",
        &[
            round_one(6),
            round_two(6),
            rotation(3, 6),
            rotation(5, 5),
            rotation(7, 3),
        ],
        measurement_ring_degree,
        Some(7),
    )
    .expect("development instance");

    let prove_start = Instant::now();
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let prove_elapsed = prove_start.elapsed();
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let verify_start = Instant::now();
    verify_evaluation_key_share(&statement, &proof).expect("verify");
    let verify_elapsed = verify_start.elapsed();

    // The analyzer models the pre-batch encoding (one independent Merkle path per
    // opened leaf), so it equals the size the proof would have without lever 2.
    // The real encoded proof carries batched openings, so the difference is the
    // measured batching saving; batching only ever removes bytes.
    let independent_paths =
        analyze_proof_size(&statement, FIELD_RESIDUE_BYTE_WIDTH, 64, LEAF_SALT_BYTES);
    assert!(
        encoded.len() <= independent_paths.total(),
        "batched encoding must not exceed the independent-path encoding"
    );
    let actual_batched_node_bytes: usize = proof
        .limb_proofs
        .iter()
        .map(|limb| {
            (limb.witness_batch_opening.authentication_nodes.len()
                + limb.quotient_batch_opening.authentication_nodes.len()
                + limb
                    .low_degree
                    .layer_batch_openings
                    .iter()
                    .map(|opening| opening.authentication_nodes.len())
                    .sum::<usize>())
                * 64
        })
        .sum();
    let measured_saving = independent_paths.total() - encoded.len();
    let batched_node_ratio =
        actual_batched_node_bytes as f64 / independent_paths.path_bytes() as f64;
    println!(
        "measurement schedule: ring_degree={measurement_ring_degree} keys={} limbs={} prove={:?} verify={:?}",
        statement.keys.len(),
        statement.limb_count(),
        prove_elapsed,
        verify_elapsed,
    );
    println!(
        "independent-path encoding {} bytes (paths {} bytes) -> batched encoding {} bytes (batched nodes {} bytes): saved {} bytes ({:.1}%); batched nodes are {:.1}% of the independent path bytes",
        independent_paths.total(),
        independent_paths.path_bytes(),
        encoded.len(),
        actual_batched_node_bytes,
        measured_saving,
        100.0 * measured_saving as f64 / independent_paths.total() as f64,
        100.0 * batched_node_ratio,
    );

    // Full first-profile shape at the production ring degree. The analyzer gives
    // the exact independent-path (post lever 1) size; the batched size is
    // estimated by scaling its path bytes by the measured node ratio. The
    // measurement ring is one binary level shallower than full size, and deeper
    // trees share proportionally fewer interior nodes (only the top log2(leaves)
    // levels overlap), so the true full-size batched total is marginally above
    // this estimate; the gate run records the exact value.
    let schedule = full_profile_schedule_shape();
    let linkage_commitment_count = schedule
        .iter()
        .map(|(_, level)| level + 1)
        .max()
        .expect("schedule is non-empty");
    let full = shape_only_trustee_statement(&schedule, POLYNOMIAL_DEGREE, linkage_commitment_count);
    let before_lever_one = analyze_proof_size(&full, 8, 64, LEAF_SALT_BYTES);
    let full_independent = analyze_proof_size(&full, FIELD_RESIDUE_BYTE_WIDTH, 64, LEAF_SALT_BYTES);
    let estimated_full_batched = full_independent.total() as f64
        - full_independent.path_bytes() as f64 * (1.0 - batched_node_ratio);
    let mebibyte = 1024.0 * 1024.0;
    println!(
        "FULL-N shape: ring_degree={POLYNOMIAL_DEGREE} keys={} limbs={}",
        full.keys.len(),
        full.limb_count(),
    );
    println!(
        "FULL-N before lever 1 (8-byte field, independent paths): {:.1} MiB",
        before_lever_one.total() as f64 / mebibyte,
    );
    println!(
        "FULL-N after lever 1 (6-byte field, independent paths): {:.1} MiB | field bytes {:.1} MiB | hash bytes {:.1} MiB (of which paths {:.1} MiB)",
        full_independent.total() as f64 / mebibyte,
        full_independent.field_element_bytes() as f64 / mebibyte,
        full_independent.hash_bytes() as f64 / mebibyte,
        full_independent.path_bytes() as f64 / mebibyte,
    );
    println!(
        "FULL-N after lever 2 (estimated batched paths): ~{:.1} MiB ({:.1}% below lever 1, {:.1}% below the original 8-byte baseline); exact value from the gate run",
        estimated_full_batched / mebibyte,
        100.0 * (full_independent.total() as f64 - estimated_full_batched)
            / full_independent.total() as f64,
        100.0 * (before_lever_one.total() as f64 - estimated_full_batched)
            / before_lever_one.total() as f64,
    );
}

const SMALL_RING_DEGREE: usize = 128;
const PROOF_RANDOMNESS_SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const PROOF_RANDOMNESS_NONCE: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const SAME_SECRET_STATEMENT_HASH_VECTOR: &str = "c300200cb9bde4e95f2129ad4c07ca6fa22a2c236278be5f0be474095f604d3afd0613c791e807dc4e4d942f202ea4f5cac20d5a93745eab3d87abf05a3cf4ee";
const PUBLIC_KEY_SHARE_STATEMENT_HASH_VECTOR: &str = "108d59c7677c2007c43910828650f4a93d7555c63041e5865dcc906ca3b6e114456c85fc963165929bc676aac063307b69ecc18c3abcfa6f0f91a6bbcdff861e";
const PRIVATE_VSS_SHARE_STATEMENT_HASH_VECTOR: &str = "b01e9ec950e257fed5974196c7eda5696e4da96b4b0e3478483c5020f930ee672e49b34cd4e9e88f7b2d27aec11be7c7b44ebae68280168d30ed8c99e7cf8475";
const TRUSTEE_EVALUATION_KEY_STATEMENT_HASH_VECTOR: &str = "11fce9a48c01d57c8b08e2816a9a7704623775fcfdf5afca029ec4d2c32f5c2f070e567c2042e6554f6bbb3f46fe75a4711b8b52ab6626509e0ecd10f307bef0";

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
        same_secret_linkage: None,
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

#[test]
fn honest_round_one_relinearization_proof_round_trips() {
    let (statement, witness) =
        generate_development_trustee_instance("a1b2c3d4", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn honest_round_two_relinearization_proof_round_trips() {
    let (statement, witness) =
        generate_development_trustee_instance("f00dface", &[round_two(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn honest_galois_rotation_proof_round_trips() {
    let (statement, witness) =
        generate_development_trustee_instance("0badf00d", &[rotation(3, 2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn batched_trustee_schedule_round_trips_with_mixed_levels() {
    // One batched proof covering relinearization rounds one and two plus two
    // rotations, with one rotation at a lower level so per-limb active key
    // sets differ across limbs.
    let (statement, witness) = generate_development_trustee_instance(
        "cafe0001",
        &[round_one(2), round_two(2), rotation(3, 2), rotation(5, 1)],
        SMALL_RING_DEGREE,
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    assert_eq!(proof.limb_proofs.len(), 3);
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn galois_transpose_matches_forward_automorphism_inner_product() {
    // The lincheck relies on <u, phi_g(s)> = <M_phi^T u, s>; check it for
    // random vectors against the forward automorphism over a profile prime.
    let modulus = DATA_PRIMES[0];
    let degree = 64_usize;
    let mut seed_value = 0x9e3779b97f4a7c15_u64;
    let mut next = || {
        seed_value ^= seed_value << 13;
        seed_value ^= seed_value >> 7;
        seed_value ^= seed_value << 17;
        seed_value % modulus
    };
    for galois_element in [3_usize, 5, 31, 127] {
        let values = (0..degree).map(|_| next()).collect::<Vec<_>>();
        let vector = (0..degree).map(|_| next()).collect::<Vec<_>>();
        let rotated = galois_automorphism_apply(&values, galois_element, modulus)
            .expect("forward automorphism");
        let transposed = galois_automorphism_transpose_apply(&vector, galois_element, modulus)
            .expect("transpose automorphism");
        let dot = |left: &[u64], right: &[u64]| -> u128 {
            left.iter().zip(right.iter()).fold(0_u128, |total, (a, b)| {
                (total + u128::from(*a) * u128::from(*b)) % u128::from(modulus)
            })
        };
        assert_eq!(
            dot(&vector, &rotated),
            dot(&transposed, &values),
            "transpose identity must hold for element {galois_element}"
        );
    }
}

#[test]
fn tampered_component_material_is_rejected() {
    let (mut statement, witness) =
        generate_development_trustee_instance("0011aabb", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    statement.keys[0].component_b_by_digit[0][0][0] ^= 1;
    let result = verify_evaluation_key_share(&statement, &proof);
    assert!(result.is_err(), "tampered component material must reject");
}

#[test]
fn tampered_deep_evaluation_is_rejected() {
    let (statement, witness) =
        generate_development_trustee_instance("c0ffee11", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let modulus = statement.limb_moduli()[0];
    proof.limb_proofs[0].deep_evaluations[0][0][0] =
        (proof.limb_proofs[0].deep_evaluations[0][0][0] + 1) % modulus;
    let result = verify_evaluation_key_share(&statement, &proof);
    assert!(result.is_err(), "tampered deep evaluation must reject");
}

#[test]
fn tampered_consistency_claim_is_rejected() {
    let (statement, witness) =
        generate_development_trustee_instance("13371337", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    proof.limb_proofs[0].masked_consistency_claims[0] += 1;
    let result = verify_evaluation_key_share(&statement, &proof);
    assert!(result.is_err(), "tampered consistency claim must reject");
}

#[test]
fn forged_secret_inconsistent_across_limbs_is_rejected() {
    // A prover that commits a different secret in one limb field would produce
    // masked consistency claims that disagree across limbs as integers.
    // Emulate that by proving two honest instances with different secrets and
    // splicing one limb proof across them.
    let (statement, witness) =
        generate_development_trustee_instance("aaaa0001", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("first instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let (other_statement, other_witness) =
        generate_development_trustee_instance("bbbb0002", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("second instance");
    let other_proof =
        prove_evaluation_key_share(&other_statement, &other_witness, PROOF_RANDOMNESS_SEED)
            .expect("prove");
    let mut spliced = proof;
    spliced.limb_proofs[0] = other_proof
        .limb_proofs
        .into_iter()
        .next()
        .expect("limb proof");
    let result = verify_evaluation_key_share(&statement, &spliced);
    assert!(
        result.is_err(),
        "a spliced limb proof from a different secret must reject"
    );
}

#[test]
fn round_two_proving_rejects_round_one_source_material() {
    // The confirmed legacy soundness gap: round-two material whose source is
    // not secret * (round-one aggregate) must not prove. Build a round-two
    // descriptor whose component material was formed with the round-one
    // source by copying the round-one components under a round-two kind.
    let (round_one_statement, witness) =
        generate_development_trustee_instance("5a5a5a5a", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("round one");
    let (round_two_statement, _) =
        generate_development_trustee_instance("5a5a5a5a", &[round_two(2)], SMALL_RING_DEGREE)
            .expect("round two");
    let mut malicious = round_two_statement;
    malicious.keys[0].component_b_by_digit =
        round_one_statement.keys[0].component_b_by_digit.clone();
    malicious.keys[0].key_switch_domain = round_one_statement.keys[0].key_switch_domain.clone();
    malicious.keys[0].key_switch_seed_hex = round_one_statement.keys[0].key_switch_seed_hex.clone();
    let result = prove_evaluation_key_share(&malicious, &witness, PROOF_RANDOMNESS_SEED);
    assert!(
        result.is_err(),
        "round-two proving must reject round-one source material"
    );
}

#[test]
fn galois_proof_rejects_a_different_rotation_element() {
    let (statement, witness) =
        generate_development_trustee_instance("feedbee5", &[rotation(3, 2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let mut forged = statement;
    forged.keys[0].kind = EvaluationKeyShareKind::GaloisRotation { galois_element: 5 };
    let result = verify_evaluation_key_share(&forged, &proof);
    assert!(result.is_err(), "a different rotation element must reject");
    let result = prove_evaluation_key_share(&forged, &witness, PROOF_RANDOMNESS_SEED);
    assert!(
        result.is_err(),
        "proving must reject component material from another rotation element"
    );
}

#[test]
fn masked_claims_differ_under_fresh_proof_randomness() {
    // The published consistency claims are smudging-masked: two proofs of the
    // same statement under different proof randomness must publish different
    // claim values, and both must verify.
    let (statement, witness) =
        generate_development_trustee_instance("d00d2bad", &[round_one(1)], SMALL_RING_DEGREE)
            .expect("development instance");
    let first =
        prove_evaluation_key_share(&statement, &witness, "aaaaaaaaaaaaaaaa").expect("prove first");
    let second =
        prove_evaluation_key_share(&statement, &witness, "bbbbbbbbbbbbbbbb").expect("prove second");
    verify_evaluation_key_share(&statement, &first).expect("verify first");
    verify_evaluation_key_share(&statement, &second).expect("verify second");
    assert_ne!(
        first.limb_proofs[0].masked_consistency_claims,
        second.limb_proofs[0].masked_consistency_claims,
        "masked claims must depend on the proof randomness"
    );
}

#[test]
fn honest_proof_with_same_secret_linkage_round_trips() {
    // Level two keeps all three commitment fields active and must carry
    // exactly one same-secret commitment for each active Q_share limb.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "11aa22bb",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    assert!(statement.same_secret_linkage.is_some());
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn same_secret_linkage_rejects_commitments_outside_active_limb_set() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "11aa22cc",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(4),
    )
    .expect("development instance");

    assert!(
        statement.validate_shape().is_err(),
        "extra same-secret linkage commitments must not be accepted outside the active Q_share limb set"
    );
    assert!(
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "proving must refuse a statement whose linkage commitment count does not match the theorem shape"
    );
}

#[test]
fn batched_schedule_with_linkage_round_trips() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "33cc44dd",
        &[round_one(2), round_two(2), rotation(3, 2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn same_secret_linkage_anchor_proof_round_trips_without_keys() {
    // The keyless statement is the per-trustee same-secret linkage anchor:
    // it opens one constant commitment per Q_share limb while the committed
    // rows are checked over the three setup commitment fields.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "99ffeedd",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    assert!(statement.keys.is_empty());
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");

    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let decoded =
        decode_trustee_evaluation_key_proof(&statement, &encoded).expect("decode anchor proof");
    verify_evaluation_key_share(&statement, &decoded).expect("verify decoded");
}

#[test]
fn same_secret_anchor_rejects_partial_q_share_commitment_set() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "77aaccee",
        &[],
        SMALL_RING_DEGREE,
        Some(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()),
    )
    .expect("partial anchor instance");

    assert!(
        statement.validate_shape().is_err(),
        "the keyless same-secret anchor must not accept only the setup commitment-field count"
    );
    assert!(
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "proving must refuse a partial same-secret anchor commitment set"
    );
}

#[test]
fn keyless_statement_without_linkage_is_refused() {
    let (mut statement, witness) = generate_development_trustee_instance_with_linkage(
        "aa00bb11",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    statement.same_secret_linkage = None;
    assert!(
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "a statement with neither keys nor the linkage anchor must be refused"
    );
}

#[test]
fn anchor_rejects_commitments_to_a_different_secret() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "cc22dd33",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    let (other_statement, _) = generate_development_trustee_instance_with_linkage(
        "ee44ff55",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("second anchor instance");
    let mut forged = statement;
    forged.same_secret_linkage = other_statement.same_secret_linkage;
    assert!(
        prove_evaluation_key_share(&forged, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "anchor proving must reject commitments that open to a different secret"
    );
}

#[test]
fn linkage_rejects_commitments_to_a_different_secret() {
    // A trustee whose key-relation secret differs from the committed secret
    // must not be able to produce a proof: the commitment-opening relations
    // fail, so the sumcheck remainder is nonzero at proving time.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "55ee66ff",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("first instance");
    let (other_statement, _) = generate_development_trustee_instance_with_linkage(
        "7788aabb",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("second instance");
    let mut forged = statement;
    forged.same_secret_linkage = other_statement.same_secret_linkage;
    let result = prove_evaluation_key_share(&forged, &witness, PROOF_RANDOMNESS_SEED);
    assert!(
        result.is_err(),
        "proving must reject commitments that open to a different secret"
    );
}

#[test]
fn tampered_linkage_commitment_is_rejected() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "99ffaa00",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let mut tampered = statement;
    let linkage = tampered
        .same_secret_linkage
        .as_mut()
        .expect("linkage present");
    let modulus = linkage.commitments[0].limbs[0].modulus;
    linkage.commitments[0].limbs[0].rows[0][0] =
        (linkage.commitments[0].limbs[0].rows[0][0] + 1) % modulus;
    let result = verify_evaluation_key_share(&tampered, &proof);
    assert!(result.is_err(), "tampered linkage commitment must reject");
}

#[test]
fn proof_codec_round_trips_and_rejects_malformed_bytes() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "c0dec0de",
        &[round_one(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let bytes = encode_trustee_evaluation_key_proof(&proof);
    let decoded = decode_trustee_evaluation_key_proof(&statement, &bytes)
        .expect("decode canonical proof bytes");
    verify_evaluation_key_share(&statement, &decoded).expect("verify decoded proof");

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        decode_trustee_evaluation_key_proof(&statement, &trailing).is_err(),
        "trailing bytes must reject"
    );
    let truncated = &bytes[..bytes.len() - 1];
    assert!(
        decode_trustee_evaluation_key_proof(&statement, truncated).is_err(),
        "truncated bytes must reject"
    );
    let mut flipped = bytes.clone();
    let flip_position = bytes.len() / 2;
    flipped[flip_position] ^= 1;
    let tampered = decode_trustee_evaluation_key_proof(&statement, &flipped);
    if let Ok(tampered_proof) = tampered {
        assert!(
            verify_evaluation_key_share(&statement, &tampered_proof).is_err(),
            "a decoded bit-flipped proof must fail verification"
        );
    }
}

#[test]
fn proof_codec_rejects_low_degree_shape_mismatches_before_verification() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "c0dec0de",
        &[round_one(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    proof.limb_proofs[0]
        .low_degree
        .folded_layer_roots
        .pop()
        .expect("at least one committed folded layer");
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(&statement, &encoded) {
        Ok(_) => panic!("wrong low-degree fold count must reject at decode"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("low-degree committed fold count does not match the statement"),
        "unexpected low-degree fold-count error: {}",
        error.message
    );

    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "dec0ded0",
        &[round_one(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    // A batched folded-layer opening whose node count exceeds its per-layer
    // bound by one is rejected at decode, before any oversized allocation. The
    // bound mirrors the decoder: LOW_DEGREE_QUERY_COUNT openings over a layer of
    // the given depth.
    let layout = LimbColumnLayout::new(&statement, 0).expect("limb layout");
    let extension_size = layout.trace_size * DOMAIN_BLOWUP;
    let maximum_layer_zero_nodes =
        LOW_DEGREE_QUERY_COUNT * folded_layer_path_length(extension_size, 0);
    proof.limb_proofs[0].low_degree.layer_batch_openings[0]
        .authentication_nodes
        .resize(maximum_layer_zero_nodes + 1, [0_u8; 64]);
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(&statement, &encoded) {
        Ok(_) => panic!("an oversized batched opening must reject at decode"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("batched opening node count exceeds the statement bound"),
        "unexpected batched-opening error: {}",
        error.message
    );
}

fn assert_noncanonical_encoded_proof_rejects(
    label: &str,
    mutate_proof: impl FnOnce(&mut super::prover::SuccinctEvaluationKeyProof, u64),
) {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "c0decafe",
        &[round_one(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let modulus = statement.limb_moduli()[0];
    mutate_proof(&mut proof, modulus);
    let encoded = encode_trustee_evaluation_key_proof(&proof);

    assert!(
        decode_trustee_evaluation_key_proof(&statement, &encoded).is_err(),
        "{label} with a noncanonical residue must be rejected by the decoder"
    );
}

#[test]
fn proof_codec_rejects_noncanonical_values_in_every_encoded_area() {
    assert_noncanonical_encoded_proof_rejects("masked consistency claim", |proof, modulus| {
        proof.limb_proofs[0].masked_consistency_claims[0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("deep evaluation coordinate", |proof, modulus| {
        proof.limb_proofs[0].deep_evaluations[0][0][0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("phase-one query row", |proof, modulus| {
        proof.limb_proofs[0].query_openings[0].phase_one_rows[0][0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("phase-two coordinate row", |proof, modulus| {
        proof.limb_proofs[0].query_openings[0].phase_two_rows[0][0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("low-degree final coefficient", |proof, modulus| {
        proof.limb_proofs[0].low_degree.final_coefficients[0][0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("low-degree folded opening", |proof, modulus| {
        proof.limb_proofs[0].low_degree.query_openings[0].folded_layer_pairs[0].pair[0][0] =
            modulus;
    });
}

#[test]
fn proof_codec_rejects_noncanonical_values_for_each_succinct_family_shape() {
    let family_cases = [
        generate_development_trustee_instance_with_linkage(
            "1111aaaa",
            &[],
            SMALL_RING_DEGREE,
            Some(DATA_PRIMES.len()),
        )
        .expect("same-secret anchor instance"),
        generate_development_public_key_share_instance("2222bbbb", SMALL_RING_DEGREE)
            .expect("public-key share instance"),
        generate_development_trustee_instance_with_linkage(
            "3333cccc",
            &[round_one(2), round_two(2), rotation(3, 1)],
            SMALL_RING_DEGREE,
            Some(3),
        )
        .expect("trustee evaluation-key instance"),
    ];

    for (statement, witness) in family_cases {
        let mut proof =
            prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
        proof.limb_proofs[0].masked_consistency_claims[0] = statement.limb_moduli()[0];
        let encoded = encode_trustee_evaluation_key_proof(&proof);
        assert!(
            decode_trustee_evaluation_key_proof(&statement, &encoded).is_err(),
            "noncanonical proof bytes must reject for {}",
            statement.context.proof_family
        );
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
    request["proofRandomnessSource"] = serde_json::json!("development-deterministic-fixture");
    request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
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
    let mut request = serde_json::json!({
        "context": vector_context_base(serde_json::json!({
            "vssCoefficientCommitmentMaterialRoot": repeated_hash("30"),
        })),
        "ringDegree": SMALL_RING_DEGREE,
        "keys": [],
        "sameSecretLinkage": {
            "publicMatrixSeedHash": repeated_hash("40"),
            "commitments": commitments,
        },
        "secretCoefficients": zero_i64_vector(),
        "errorCoefficientsByKey": [],
        "negativeIndicatorCoefficients": zero_i64_vector(),
        "openingRandomnessByLimb": vec![zero_opening_randomness(); DATA_PRIMES.len()],
    });
    proof_randomness_fields(&mut request);
    request
}

fn public_key_share_statement_hash_vector_request() -> serde_json::Value {
    let component_b_by_limb = DATA_PRIMES
        .iter()
        .map(|_| zero_u64_vector())
        .collect::<Vec<_>>();
    let linkage_commitment =
        setup_commitment_full_value(&zero_setup_commitment_value(0, DATA_PRIMES[0], 0));
    let mut request = serde_json::json!({
        "context": vector_context_base(serde_json::json!({
            "sameSecretStatementRoot": repeated_hash("31"),
            "sameSecretProofRoot": repeated_hash("32"),
        })),
        "ringDegree": SMALL_RING_DEGREE,
        "keys": [{
            "proofFamily": "public-key-share",
            "level": DATA_PRIMES.len() - 1,
            "keySwitchDomain": "accepted-bgv-public-a",
            "keySwitchSeedHex": repeated_hash("41"),
            "componentBByDigit": [component_b_by_limb],
        }],
        "sameSecretLinkage": {
            "publicMatrixSeedHash": repeated_hash("41"),
            "commitments": [linkage_commitment],
        },
        "secretCoefficients": zero_i64_vector(),
        "errorCoefficientsByKey": [[zero_i64_vector()]],
        "negativeIndicatorCoefficients": zero_i64_vector(),
        "openingRandomnessByLimb": [zero_opening_randomness()],
    });
    proof_randomness_fields(&mut request);
    request
}

fn trustee_evaluation_key_statement_hash_vector_request() -> serde_json::Value {
    let mut request = serde_json::json!({
        "context": vector_context_base(serde_json::json!({
            "requiredGaloisSetHash": repeated_hash("33"),
            "evaluatorKeyScheduleRoot": repeated_hash("34"),
            "keySwitchDecompositionHash": repeated_hash("35"),
            "sameSecretStatementRoot": repeated_hash("36"),
            "sameSecretProofRoot": repeated_hash("37"),
        })),
        "ringDegree": SMALL_RING_DEGREE,
        "keys": [{
            "proofFamily": "relinearization-round-one",
            "level": 0,
            "keySwitchDomain": "relinearization-round-one",
            "keySwitchSeedHex": repeated_hash("42"),
            "componentBByDigit": [[zero_u64_vector()]],
        }],
        "secretCoefficients": zero_i64_vector(),
        "errorCoefficientsByKey": [[zero_i64_vector()]],
    });
    proof_randomness_fields(&mut request);
    request
}

fn private_vss_setup_context_vector() -> serde_json::Value {
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    serde_json::json!({
        "ceremonyId": "statement-vector-ceremony",
        "manifestHash": repeated_hash("10"),
        "rosterHash": repeated_hash("20"),
        "setupProfileHash": profile["setupProfileHash"],
        "qShareHash": profile["qShareHash"],
        "carryAwareVssShareRelationProfileHash": profile["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": profile["commitmentProfileHash"],
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
                "objectVersion": 1,
                "ceremonyId": "statement-vector-ceremony",
                "manifestHash": repeated_hash("10"),
                "rosterHash": repeated_hash("20"),
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
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
                "objectVersion": 1,
                "ceremonyId": "statement-vector-ceremony",
                "manifestHash": repeated_hash("10"),
                "rosterHash": repeated_hash("20"),
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
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
        "objectVersion": 1,
        "ceremonyId": "statement-vector-ceremony",
        "manifestHash": repeated_hash("10"),
        "rosterHash": repeated_hash("20"),
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": "statement-vector-epoch",
        "sourceTrusteeIdentity": "statement-vector-trustee",
        "sourceTrusteeRosterPosition": 0,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "coefficientCommitments": coefficient_commitments,
    });
    let source_root = derive_protocol_hash("VssCoefficientCommitmentRoot", &source_record)
        .expect("source trustee commitment root");
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

#[test]
fn succinct_setup_statement_hash_vectors_cover_current_families() {
    let same_secret = super::generate_trustee_evaluation_key_proof_from_request(
        &same_secret_statement_hash_vector_request(),
    )
    .expect("same-secret statement vector");
    let public_key = super::generate_trustee_evaluation_key_proof_from_request(
        &public_key_share_statement_hash_vector_request(),
    )
    .expect("public-key statement vector");
    let private_vss =
        crate::bgv::setup::private_vss::generate_private_vss_share_proof_from_request(
            &private_vss_statement_hash_vector_request(),
        )
        .expect("private VSS statement vector");
    let trustee_evaluation_key = super::generate_trustee_evaluation_key_proof_from_request(
        &trustee_evaluation_key_statement_hash_vector_request(),
    )
    .expect("trustee evaluation-key statement vector");

    println!(
        "statement hash vectors: same-secret={}, public-key-share={}, private-vss-share={}, trustee-evaluation-key={}",
        same_secret["statementHash"]
            .as_str()
            .expect("same-secret hash"),
        public_key["statementHash"]
            .as_str()
            .expect("public-key hash"),
        private_vss["privateVssShareProof"]["statementHash"]
            .as_str()
            .expect("private VSS hash"),
        trustee_evaluation_key["statementHash"]
            .as_str()
            .expect("trustee evaluation-key hash"),
    );
    assert_eq!(same_secret["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(
        same_secret["statementHash"],
        SAME_SECRET_STATEMENT_HASH_VECTOR
    );
    assert_eq!(public_key["proofFamily"], "public-key-share");
    assert_eq!(
        public_key["statementHash"],
        PUBLIC_KEY_SHARE_STATEMENT_HASH_VECTOR
    );
    assert_eq!(
        private_vss["privateVssShareProof"]["proofFamily"],
        "vss-opening-carry"
    );
    assert_eq!(
        private_vss["privateVssShareProof"]["statementHash"],
        PRIVATE_VSS_SHARE_STATEMENT_HASH_VECTOR
    );
    assert_eq!(
        trustee_evaluation_key["proofFamily"],
        "trustee-evaluation-key"
    );
    assert_eq!(
        trustee_evaluation_key["statementHash"],
        TRUSTEE_EVALUATION_KEY_STATEMENT_HASH_VECTOR
    );
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

#[test]
fn trustee_proof_commands_round_trip_and_reject_tampered_bytes() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "cdcdabab",
        &[round_one(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSource"] =
        serde_json::json!("development-deterministic-fixture");
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate command");
    assert_eq!(generated["ok"], true);
    assert_eq!(generated["sameSecretLinkageIncluded"], true);
    let proof_bytes_hex = generated["proofBytesHex"].as_str().expect("proof bytes");

    let mut verify_request = statement_request_value(&statement);
    verify_request["proofBytesHex"] = serde_json::json!(proof_bytes_hex);
    let verified = super::verify_trustee_evaluation_key_proof_from_request(&verify_request)
        .expect("verify command");
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["statementHash"], generated["statementHash"]);

    let mut tampered_request = statement_request_value(&statement);
    let mut tampered_hex = proof_bytes_hex.to_string();
    let flip_position = tampered_hex.len() / 2;
    let original = tampered_hex.as_bytes()[flip_position];
    let replacement = if original == b'0' { '1' } else { '0' };
    tampered_hex.replace_range(flip_position..flip_position + 1, &replacement.to_string());
    tampered_request["proofBytesHex"] = serde_json::json!(tampered_hex);
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&tampered_request).is_err(),
        "tampered proof bytes must reject"
    );
}

#[test]
fn trustee_proof_commands_reject_noncanonical_public_statement_material() {
    let (round_two_statement, round_two_witness) =
        generate_development_trustee_instance("feed0102", &[round_two(2)], SMALL_RING_DEGREE)
            .expect("round-two instance");
    let round_two_proof = prove_evaluation_key_share(
        &round_two_statement,
        &round_two_witness,
        PROOF_RANDOMNESS_SEED,
    )
    .expect("round-two proof");
    let round_two_proof_bytes = encode_trustee_evaluation_key_proof(&round_two_proof);

    let mut component_request = statement_request_value(&round_two_statement);
    component_request["proofBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&round_two_proof_bytes));
    component_request["keys"][0]["componentBByDigit"][0][0][0] = serde_json::json!(DATA_PRIMES[0]);
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&component_request).is_err(),
        "out-of-range componentBByDigit values must reject before verification"
    );

    let mut aggregate_request = statement_request_value(&round_two_statement);
    aggregate_request["proofBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&round_two_proof_bytes));
    aggregate_request["keys"][0]["roundOneAggregateDiagonal"][0][0] =
        serde_json::json!(DATA_PRIMES[0]);
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&aggregate_request).is_err(),
        "out-of-range aggregate statement values must reject before verification"
    );

    let (statement, witness) =
        generate_development_trustee_instance("feed0304", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("round-one instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("proof");
    let mut material_bytes =
        component_material_bytes_for_request_key(&statement.keys[0], SMALL_RING_DEGREE);
    let coefficient_offset = 8 + (4 * 8);
    material_bytes[coefficient_offset..coefficient_offset + 8]
        .copy_from_slice(&DATA_PRIMES[0].to_le_bytes());
    let mut material_request = statement_request_value(&statement);
    material_request["proofBytesHex"] = serde_json::json!(crate::hashing::to_hex(
        &encode_trustee_evaluation_key_proof(&proof)
    ));
    material_request["keys"][0]
        .as_object_mut()
        .expect("key object")
        .remove("componentBByDigit");
    material_request["keys"][0]["componentMaterialBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&material_bytes));
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&material_request).is_err(),
        "out-of-range binary component material must reject before verification"
    );
}

#[test]
fn trustee_proof_statements_reject_noncanonical_context_and_hash_fields() {
    let (mut statement, _) = generate_development_trustee_instance_with_linkage(
        "ctxbad01",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    statement.context.setup_epoch = "setup epoch 1".to_string();
    assert!(
        statement.validate_shape().is_err(),
        "setupEpoch with whitespace must be rejected before statement hashing"
    );

    let (mut statement, _) = generate_development_trustee_instance_with_linkage(
        "ctxbad02",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    statement.context.setup_epoch = "setup-epoch-\0-1".to_string();
    assert!(
        statement.validate_shape().is_err(),
        "setupEpoch with a control character must be rejected before statement hashing"
    );

    let (mut statement, _) = generate_development_trustee_instance_with_linkage(
        "ctxbad03",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    statement.context.manifest_hash = "00".repeat(63);
    assert!(
        statement.validate_shape().is_err(),
        "manifestHash must be a complete lowercase 512-bit protocol hash"
    );

    let (mut statement, _) = generate_development_trustee_instance_with_linkage(
        "ctxbad04",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    statement.context.binding_roots[0].1 = "aa".repeat(63);
    assert!(
        statement.validate_shape().is_err(),
        "binding roots must be complete lowercase 512-bit protocol hashes"
    );

    let (mut statement, _) = generate_development_trustee_instance_with_linkage(
        "ctxbad05",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    statement.keys[0].key_switch_domain = "relinearization round one".to_string();
    assert!(
        statement.validate_shape().is_err(),
        "key-switch context tokens must reject whitespace"
    );

    let (mut statement, _) = generate_development_trustee_instance_with_linkage(
        "ctxbad06",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    statement
        .same_secret_linkage
        .as_mut()
        .expect("same-secret linkage")
        .public_matrix_seed_hash = "bb".repeat(63);
    assert!(
        statement.validate_shape().is_err(),
        "same-secret linkage public matrix seed hash must be canonical"
    );
}

#[test]
fn private_vss_statement_rejects_noncanonical_context_and_hash_fields() {
    let statement = private_vss_statement_for_context_tests();
    statement
        .validate_shape()
        .expect("canonical private VSS statement");

    let mut statement = private_vss_statement_for_context_tests();
    statement.context.setup_epoch = "setup epoch 1".to_string();
    assert!(
        statement.validate_shape().is_err(),
        "private VSS setupEpoch with whitespace must be rejected before statement hashing"
    );

    let mut statement = private_vss_statement_for_context_tests();
    statement
        .private_vss_share
        .as_mut()
        .expect("private VSS statement")
        .public_matrix_seed_hash = "66".repeat(63);
    assert!(
        statement.validate_shape().is_err(),
        "private VSS public matrix seed hash must be canonical"
    );

    let mut statement = private_vss_statement_for_context_tests();
    statement
        .private_vss_share
        .as_mut()
        .expect("private VSS statement")
        .coefficient_commitment_roots[0] = "77".repeat(63);
    assert!(
        statement.validate_shape().is_err(),
        "private VSS coefficient commitment roots must be canonical"
    );
}

#[test]
fn statement_hash_length_delimits_setup_epoch_and_linkage_seed() {
    let (mut first_statement, _) = generate_development_trustee_instance_with_linkage(
        "hashctx01",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("first development instance");
    let (mut second_statement, _) = generate_development_trustee_instance_with_linkage(
        "hashctx01",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("second development instance");

    first_statement.context.setup_epoch = "epoch-a".to_string();
    second_statement.context.setup_epoch = "epoch-aa".to_string();
    first_statement.validate_shape().expect("first statement");
    second_statement.validate_shape().expect("second statement");
    let first_epoch_hash = first_statement.statement_hash();
    assert_ne!(
        first_epoch_hash,
        second_statement.statement_hash(),
        "setupEpoch changes must rebind the canonical statement hash"
    );

    let first_linkage = first_statement
        .same_secret_linkage
        .as_mut()
        .expect("first same-secret linkage");
    let mut seed_bytes = first_linkage.public_matrix_seed_hash.clone().into_bytes();
    seed_bytes[0] = if seed_bytes[0] == b'a' { b'b' } else { b'a' };
    first_linkage.public_matrix_seed_hash =
        String::from_utf8(seed_bytes).expect("valid hex seed mutation");
    first_statement
        .validate_shape()
        .expect("mutated statement stays canonical");
    assert_ne!(
        first_epoch_hash,
        first_statement.statement_hash(),
        "same-secret public matrix seed changes must rebind the canonical statement hash"
    );
}

#[test]
fn anchor_proof_commands_round_trip_with_family_label() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "fafa0101",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSource"] =
        serde_json::json!("development-deterministic-fixture");
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate anchor command");
    assert_eq!(generated["ok"], true);
    assert_eq!(generated["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(generated["keyCount"], 0);

    let mut verify_request = statement_request_value(&statement);
    verify_request["proofBytesHex"] = generated["proofBytesHex"].clone();
    let verified = super::verify_trustee_evaluation_key_proof_from_request(&verify_request)
        .expect("verify anchor command");
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(verified["statementHash"], generated["statementHash"]);

    // A keyless request whose context carries the evaluation-key binding
    // labels must be refused: the family decides the expected label list.
    let mut mislabeled_request = statement_request_value(&statement);
    mislabeled_request["context"]["vssCoefficientCommitmentMaterialRoot"] = serde_json::Value::Null;
    mislabeled_request["proofBytesHex"] = generated["proofBytesHex"].clone();
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&mislabeled_request).is_err(),
        "a keyless statement without the anchor binding root must be refused"
    );
}

#[test]
fn multi_trustee_ceremony_slice_round_trips_with_recomputed_aggregate() {
    // Three trustees, each with round-one and round-two relinearization
    // shares and same-secret linkage; every round-two source multiplies the
    // trustee secret by the public aggregate recomputed from the accepted
    // round-one components, the multi-party-realizable flow the package
    // verifier rebinds.
    let instances =
        generate_development_trustee_ceremony_slice("ceremony01", 3, 2, SMALL_RING_DEGREE, 3)
            .expect("ceremony slice");
    assert_eq!(instances.len(), 3);
    for (statement, witness) in &instances {
        assert_eq!(statement.keys.len(), 2);
        assert_eq!(
            statement.keys[1].kind,
            EvaluationKeyShareKind::RelinearizationRoundTwo
        );
        let proof = prove_evaluation_key_share(statement, witness, PROOF_RANDOMNESS_SEED)
            .expect("prove trustee");
        verify_evaluation_key_share(statement, &proof).expect("verify trustee");
    }
    // A tampered aggregate (one residue off in one trustee's round-two
    // statement) must reject: the verifier recomputes the aggregate itself,
    // so a prover cannot substitute a different one.
    let (mut tampered_statement, tampered_witness) =
        generate_development_trustee_ceremony_slice("ceremony01", 3, 2, SMALL_RING_DEGREE, 3)
            .expect("ceremony slice")
            .into_iter()
            .next()
            .expect("first trustee");
    let modulus = tampered_statement.limb_moduli()[0];
    tampered_statement.keys[1].round_one_aggregate_diagonal[0][0] =
        (tampered_statement.keys[1].round_one_aggregate_diagonal[0][0] + 1) % modulus;
    assert!(
        prove_evaluation_key_share(
            &tampered_statement,
            &tampered_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "a substituted aggregate must not prove"
    );
}

#[test]
fn round_one_aggregate_recomputation_rejects_malformed_components() {
    let (statement, _) =
        generate_development_trustee_instance("aggcheck", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("instance");
    let components = vec![&statement.keys[0].component_b_by_digit];
    let aggregate = round_one_aggregate_diagonal_from_components(&components, 2, SMALL_RING_DEGREE)
        .expect("aggregate");
    assert_eq!(aggregate.len(), 3);
    assert!(
        aggregate
            .iter()
            .all(|diagonal| diagonal.len() == SMALL_RING_DEGREE)
    );
    // A single trustee's aggregate equals its own diagonal components.
    for (digit_index, diagonal) in aggregate.iter().enumerate() {
        assert_eq!(
            diagonal,
            &statement.keys[0].component_b_by_digit[digit_index][digit_index]
        );
    }
    assert!(
        round_one_aggregate_diagonal_from_components(&components, 3, SMALL_RING_DEGREE).is_err(),
        "a level above the supplied components must reject"
    );
    assert!(
        round_one_aggregate_diagonal_from_components(&[], 2, SMALL_RING_DEGREE).is_err(),
        "an empty trustee set must reject"
    );
}

#[test]
fn proof_accounting_closes_every_theorem_row_with_margin() {
    let accounting = super::accounting::succinct_evaluation_key_proof_accounting_value()
        .expect("accounting value");
    let accounting_hash = super::accounting::succinct_evaluation_key_proof_accounting_hash()
        .expect("accounting hash");
    assert_eq!(accounting_hash.len(), 128);
    for accepted_row in [
        &accounting["lowDegreeSoundness"]["accepted"],
        &accounting["identitySoundness"]["accepted"],
        &accounting["linearRelationSoundness"]["accepted"],
        &accounting["crossLimbConsistency"]["accepted"],
        &accounting["zeroKnowledge"]["smudgingBudget"]["acceptedForBoundedLeakagePrototype"],
        &accounting["fiatShamir"]["classicalRoundByRoundAccepted"],
        &accounting["sameSecretLinkage"]["accepted"],
    ] {
        assert_eq!(accepted_row, &serde_json::json!(true));
    }
    // These bounds are load-bearing: 128-bit effective soundness depends on the
    // -160 pre-union margin and a named, unproven FRI conjecture, and
    // zero-knowledge is bounded-leakage only -- do not relax them to make the
    // accounting pass.
    assert_eq!(
        accounting["lowDegreeSoundness"]["acceptedUnderNamedFriConjecture"],
        serde_json::json!(true)
    );
    assert_eq!(
        accounting["lowDegreeSoundness"]["acceptedUnderProvenFallback"],
        serde_json::json!(false)
    );
    assert_eq!(
        accounting["fiatShamir"]["qromAccepted"],
        serde_json::json!(false)
    );
    assert_eq!(
        accounting["zeroKnowledge"]["smudgingBudget"]["acceptedFor128BitZeroKnowledge"],
        serde_json::json!(false)
    );
    // Implemented facts the rows must reflect exactly, and the effective
    // soundness target the closure rests on.
    assert_eq!(
        accounting["crossLimbConsistency"]["preUnionCollisionBoundLog2"],
        serde_json::json!(-160)
    );
    assert_eq!(
        accounting["zeroKnowledge"]["maskCoversOpenings"],
        serde_json::json!(true)
    );
    assert!(
        accounting["zeroKnowledge"]["simulatorMarginEvaluations"]
            .as_i64()
            .expect("simulator margin")
            > 0
    );
    assert!(
        accounting["fiatShamir"]["effectiveSoundnessBitsAfterUnion"]
            .as_i64()
            .expect("effective soundness")
            >= 128
    );
    assert!(
        accounting["zeroKnowledge"]["smudgingBudget"]["totalLeakageLog2Approximate"]
            .as_i64()
            .expect("total leakage")
            <= -50
    );
    assert_eq!(
        accounting["argumentShape"]["traceSize"],
        serde_json::json!(crate::bgv::profile::POLYNOMIAL_DEGREE / 2)
    );
}

// Manual full-ring-degree benchmark, #[ignore]d so it never burdens the default
// test lane. Pick a configuration by running the matching wrapper below with
// --ignored; each calls run_full_ring_benchmark with an explicit level and
// schedule. Add another wrapper to benchmark a different level or schedule.
//
//   cargo test -p sealed-lattice-kernel --release \
//     full_ring_degree_benchmark_trustee_level_15 -- --ignored --nocapture
#[derive(Clone, Copy, Debug)]
enum BenchmarkSchedule {
    RoundOne,
    RoundTwo,
    Galois,
    Trustee,
}

fn run_full_ring_benchmark(level: usize, schedule: BenchmarkSchedule) {
    let key_requests = match schedule {
        // A representative trustee slice: both relinearization rounds plus
        // two full-level rotations and two lower-level return rotations.
        BenchmarkSchedule::Trustee => vec![
            round_one(level),
            round_two(level),
            rotation(3, level),
            rotation(2 * POLYNOMIAL_DEGREE - 1, level),
            rotation(5, level.min(6)),
            rotation(7, level.min(6)),
        ],
        BenchmarkSchedule::RoundTwo => vec![round_two(level)],
        BenchmarkSchedule::Galois => vec![rotation(3, level)],
        BenchmarkSchedule::RoundOne => vec![round_one(level)],
    };
    let linkage_commitments = if matches!(schedule, BenchmarkSchedule::Trustee) {
        Some(level + 1)
    } else {
        None
    };
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "5eed5eed5eed5eed",
        &key_requests,
        POLYNOMIAL_DEGREE,
        linkage_commitments,
    )
    .expect("development instance");

    let prove_start = std::time::Instant::now();
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let prove_elapsed = prove_start.elapsed();

    let verify_start = std::time::Instant::now();
    verify_evaluation_key_share(&statement, &proof).expect("verify");
    let verify_elapsed = verify_start.elapsed();

    let proof_bytes = encode_trustee_evaluation_key_proof(&proof).len();
    let limb_count = statement.limb_count();
    let key_count = statement.keys.len();
    println!("succinct evaluation-key prototype benchmark ({schedule:?}, level {level})");
    println!("  ring degree:        {POLYNOMIAL_DEGREE}");
    println!("  keys in batch:      {key_count}");
    println!("  active limbs:       {limb_count}");
    println!(
        "  prove:              {:.3} s ({:.3} s per limb)",
        prove_elapsed.as_secs_f64(),
        prove_elapsed.as_secs_f64() / limb_count as f64
    );
    println!(
        "  verify:             {:.3} s ({:.3} s per limb)",
        verify_elapsed.as_secs_f64(),
        verify_elapsed.as_secs_f64() / limb_count as f64
    );
    println!(
        "  proof size:         {:.3} MiB ({:.1} KiB per limb, {:.3} MiB per key)",
        proof_bytes as f64 / (1024.0 * 1024.0),
        proof_bytes as f64 / 1024.0 / limb_count as f64,
        proof_bytes as f64 / (1024.0 * 1024.0) / key_count as f64
    );
}

#[test]
#[ignore = "manual full-ring succinct proof benchmark"]
fn full_ring_degree_benchmark_round_one_level_15() {
    run_full_ring_benchmark(15, BenchmarkSchedule::RoundOne);
}

#[test]
#[ignore = "manual full-ring succinct proof benchmark"]
fn full_ring_degree_benchmark_round_two_level_15() {
    run_full_ring_benchmark(15, BenchmarkSchedule::RoundTwo);
}

#[test]
#[ignore = "manual full-ring succinct proof benchmark"]
fn full_ring_degree_benchmark_galois_level_15() {
    run_full_ring_benchmark(15, BenchmarkSchedule::Galois);
}

#[test]
#[ignore = "manual full-ring succinct proof benchmark"]
fn full_ring_degree_benchmark_trustee_level_15() {
    run_full_ring_benchmark(15, BenchmarkSchedule::Trustee);
}

#[test]
fn honest_public_key_share_proof_round_trips() {
    let (statement, witness) =
        generate_development_public_key_share_instance("a1b2c3d401", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    assert_eq!(statement.keys.len(), 1);
    assert_eq!(
        statement.keys[0].kind,
        EvaluationKeyShareKind::PublicKeyShare
    );
    // The share spans every Q_share limb.
    assert_eq!(statement.limb_count(), DATA_PRIMES.len());
    assert_eq!(statement.context.proof_family, "public-key-share");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    assert_eq!(proof.limb_proofs.len(), DATA_PRIMES.len());
    verify_evaluation_key_share(&statement, &proof).expect("verify");

    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let decoded = decode_trustee_evaluation_key_proof(&statement, &encoded)
        .expect("decode public-key share proof");
    verify_evaluation_key_share(&statement, &decoded).expect("verify decoded");
}

#[test]
fn public_key_share_rejects_tampered_share_component() {
    let (statement, witness) =
        generate_development_public_key_share_instance("bb22cc33", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    // Flip one published share coefficient: the share relation no longer holds
    // in that limb field, so the verifier rebuilds a different statement.
    let mut tampered = statement;
    tampered.keys[0].component_b_by_digit[0][0][0] ^= 1;
    let result = verify_evaluation_key_share(&tampered, &proof);
    assert!(result.is_err(), "a tampered share component must reject");
}

#[test]
fn public_key_share_rejects_a_secret_outside_the_committed_one() {
    // A trustee whose share secret differs from the anchored committed secret
    // cannot prove: splicing another instance's commitment makes the linkage
    // opening relation fail at proving time.
    let (statement, witness) =
        generate_development_public_key_share_instance("dd44ee55", SMALL_RING_DEGREE)
            .expect("first instance");
    let (other_statement, _) =
        generate_development_public_key_share_instance("ff66aa77", SMALL_RING_DEGREE)
            .expect("second instance");
    let mut forged = statement;
    forged.same_secret_linkage = other_statement.same_secret_linkage;
    assert!(
        prove_evaluation_key_share(&forged, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "a share secret that does not open the committed value must not prove"
    );
}

#[test]
fn public_key_share_rejects_a_foreign_common_reference_polynomial() {
    // The public sample is the seed-derived common reference polynomial. A
    // statement whose seed (key_switch_seed_hex) is swapped recomputes a
    // different a_l, so the honest proof no longer verifies.
    let (statement, witness) =
        generate_development_public_key_share_instance("aa11bb2201", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let mut forged = statement;
    forged.keys[0].key_switch_seed_hex = "00".repeat(64);
    let result = verify_evaluation_key_share(&forged, &proof);
    assert!(
        result.is_err(),
        "a foreign common reference polynomial must reject"
    );
}

#[test]
fn public_key_share_commands_round_trip_with_family_label() {
    let (statement, witness) =
        generate_development_public_key_share_instance("cdcd010201", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSource"] =
        serde_json::json!("development-deterministic-fixture");
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate public-key share command");
    assert_eq!(generated["ok"], true);
    assert_eq!(generated["proofFamily"], "public-key-share");
    assert_eq!(generated["keyCount"], 1);
    assert_eq!(generated["sameSecretLinkageIncluded"], true);
    let expected_accounting_hash =
        super::accounting::succinct_public_key_share_accounting_hash().expect("accounting hash");
    assert_eq!(generated["proofAccountingHash"], expected_accounting_hash);

    let mut verify_request = statement_request_value(&statement);
    verify_request["proofBytesHex"] = generated["proofBytesHex"].clone();
    let verified = super::verify_trustee_evaluation_key_proof_from_request(&verify_request)
        .expect("verify public-key share command");
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["proofFamily"], "public-key-share");
    assert_eq!(verified["statementHash"], generated["statementHash"]);
    assert_eq!(
        verified["proofAccounting"]["proofFamily"],
        "public-key-share"
    );

    // A public-key share request whose context carries the wrong binding
    // labels (the anchor's) must be refused.
    let mut mislabeled = statement_request_value(&statement);
    mislabeled["context"]["sameSecretStatementRoot"] = serde_json::Value::Null;
    mislabeled["proofBytesHex"] = generated["proofBytesHex"].clone();
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&mislabeled).is_err(),
        "a public-key share statement without its binding roots must be refused"
    );
}

#[test]
fn proof_command_binds_randomness_seed_to_nonce_and_statement() {
    let (statement, witness) =
        generate_development_public_key_share_instance("ab12cd34", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSource"] =
        serde_json::json!("development-deterministic-fixture");
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate with nonce");
    assert_eq!(
        generated["proofRandomness"]["binding"],
        "seed and nonce are bound to statement hash, proof family, trustee identity, roster position, and setup epoch before proof masking"
    );

    let mut changed_nonce_request = generate_request.clone();
    changed_nonce_request["proofRandomnessNonceHex"] = serde_json::json!("11".repeat(64));
    let changed_nonce_generated =
        super::generate_trustee_evaluation_key_proof_from_request(&changed_nonce_request)
            .expect("generate with changed nonce");
    assert_ne!(
        generated["proofBytesHex"], changed_nonce_generated["proofBytesHex"],
        "the same seed and statement must not reuse proof masks when the nonce changes"
    );

    let mut short_seed_request = generate_request.clone();
    short_seed_request["proofRandomnessSeedHex"] = serde_json::json!("00".repeat(63));
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&short_seed_request).is_err(),
        "short proof randomness seed material must reject"
    );

    let mut missing_nonce_request = generate_request;
    missing_nonce_request
        .as_object_mut()
        .expect("request object")
        .remove("proofRandomnessNonceHex");
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&missing_nonce_request).is_err(),
        "proof generation without an explicit nonce must reject"
    );
}

#[test]
fn public_key_share_accounting_carries_family_rows() {
    let accounting = super::accounting::succinct_public_key_share_accounting_value()
        .expect("public-key share accounting");
    assert_eq!(accounting["proofFamily"], "public-key-share");
    assert_eq!(accounting["objectType"], "SuccinctPublicKeyShareAccounting");
    // The shared theorem rows stay accepted only in the scoped classical model.
    assert_eq!(accounting["lowDegreeSoundness"]["accepted"], true);
    assert_eq!(
        accounting["lowDegreeSoundness"]["acceptedUnderNamedFriConjecture"],
        true
    );
    assert_eq!(
        accounting["fiatShamir"]["classicalRoundByRoundAccepted"],
        true
    );
    assert_eq!(accounting["fiatShamir"]["qromAccepted"], false);
    assert!(
        accounting["familyRelationRows"]["commonReferenceBinding"].is_string(),
        "the family rows must record the common reference binding"
    );
    assert!(
        accounting["familyRelationRows"]["singleCommitmentLinkageRationale"]
            .as_str()
            .is_some_and(|text| text.contains("limb-zero")),
        "the public-key share accounting must document why the one-commitment linkage opens limb zero"
    );
    assert!(
        accounting["familyRelationRows"]["anchorReference"]
            .as_str()
            .is_some_and(|text| text.contains("opens every Q_share constant commitment")),
        "the public-key share accounting must distinguish its narrower linkage from the same-secret anchor"
    );
}
