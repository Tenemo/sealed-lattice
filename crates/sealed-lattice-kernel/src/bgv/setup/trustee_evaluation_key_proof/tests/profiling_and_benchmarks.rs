use super::*;

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

fn committed_fold_count(initial_degree_bound: usize) -> usize {
    let fold_ratio = initial_degree_bound / LOW_DEGREE_FINAL_COEFFICIENT_COUNT;
    fold_ratio.trailing_zeros() as usize - 1
}

fn add_low_degree_size(
    breakdown: &mut ProofSizeBreakdown,
    extension_size: usize,
    initial_degree_bound: usize,
    extension_element_bytes: usize,
    hash_bytes: usize,
) {
    let folds = committed_fold_count(initial_degree_bound);
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
        breakdown.deep_evaluations +=
            DEEP_EVALUATION_POINT_COUNT * total_columns * extension_element_bytes;

        // Main batched low-degree proof and the residual low-degree proof.
        let commitment_bound = COMMITMENT_BOUND_FACTOR * trace_size;
        add_low_degree_size(
            &mut breakdown,
            extension_size,
            commitment_bound,
            extension_element_bytes,
            hash_bytes,
        );
        add_low_degree_size(
            &mut breakdown,
            extension_size,
            trace_size,
            extension_element_bytes,
            hash_bytes,
        );

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
        for _query in 0..LOW_DEGREE_QUERY_COUNT {
            for _slot in 0..2 {
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
        compact_vss_share_linkage: None,
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
            let batched_node_count = limb.witness_batch_opening.authentication_nodes.len()
                + limb.quotient_batch_opening.authentication_nodes.len()
                + limb
                    .sumcheck_residual_batch_opening
                    .authentication_nodes
                    .len()
                + limb
                    .low_degree
                    .layer_batch_openings
                    .iter()
                    .map(|opening| opening.authentication_nodes.len())
                    .sum::<usize>()
                + limb
                    .sumcheck_residual_low_degree
                    .layer_batch_openings
                    .iter()
                    .map(|opening| opening.authentication_nodes.len())
                    .sum::<usize>();
            batched_node_count * 64
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
