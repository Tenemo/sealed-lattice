use super::*;

#[test]
fn trustee_proof_commands_round_trip_and_reject_tampered_bytes() {
    use super::super::relation::{SameSecretBridgeStatement, VssShareLinkageCommitment};
    use crate::bgv::evaluator::top_k::canonical_target_basis_hash;
    use crate::bgv::setup::vss_commitment::{
        VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT as BRIDGE_RANDOMNESS_COLUMNS,
        VssPublicCommitmentOpeningInput, compute_vss_public_commitment_from_opening,
        vss_public_canonical_message_digit_columns,
    };

    let (mut statement, mut witness) = generate_development_trustee_instance(
        "cdcdabab",
        &[round_one(2), round_two(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
    )
    .expect("development instance");
    // Attach a consistent same-secret bridge anchor over the instance secret,
    // computed by the live commitment function so both the command parser's
    // root recomputation and the atom schedule's linkage opening hold.
    let bridge_seed_hash = repeated_hash("cd");
    let target_rns_prime = DATA_PRIMES[0];
    witness.negative_indicator_coefficients = witness
        .secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect();
    let message_coefficients = witness
        .secret_coefficients
        .iter()
        .zip(witness.negative_indicator_coefficients.iter())
        .map(|(secret_coefficient, negative_indicator)| {
            u64::try_from(
                i128::from(*secret_coefficient)
                    + i128::from(*negative_indicator) * i128::from(target_rns_prime),
            )
            .expect("canonical bridge message")
        })
        .collect::<Vec<_>>();
    let randomness_by_column = (0..BRIDGE_RANDOMNESS_COLUMNS)
        .map(|column_index| {
            (0..SMALL_RING_DEGREE)
                .map(|coefficient_index| {
                    ((33 + column_index as i64 * 11 + coefficient_index as i64 * 13).rem_euclid(3))
                        - 1
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let message_digit_columns =
        vss_public_canonical_message_digit_columns(&message_coefficients, SMALL_RING_DEGREE)
            .expect("bridge message digit columns");
    let computation = compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
        commitment_role: "coefficient",
        commitment_context: &serde_json::json!({ "testPurpose": "atom-command-round-trip" }),
        public_matrix_seed_hash: &bridge_seed_hash,
        rns_limb_index: 0,
        rns_prime: target_rns_prime,
        ring_degree: SMALL_RING_DEGREE,
        message_coefficients: &message_coefficients,
        message_digit_columns: &message_digit_columns,
        message_coefficient_bound: target_rns_prime,
        randomness_by_column: &randomness_by_column,
    })
    .expect("live bridge commitment");
    let coordinates_by_commitment_modulus = computation.commitment["commitmentLimbs"]
        .as_array()
        .expect("commitment limbs")
        .iter()
        .map(|limb| {
            limb["coordinates"]
                .as_array()
                .expect("commitment coordinates")
                .iter()
                .map(|coordinate| coordinate.as_u64().expect("coordinate"))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    statement.same_secret_bridge = Some(SameSecretBridgeStatement {
        public_matrix_seed_hash: bridge_seed_hash,
        source_trustee_identity: statement.context.trustee_identity.clone(),
        source_trustee_roster_position: statement.context.trustee_roster_position,
        target_basis_hash: canonical_target_basis_hash().expect("canonical target basis hash"),
        target_rns_primes: vec![target_rns_prime],
        target_constant_commitment_roots: vec![computation.commitment_root.clone()],
        target_constant_commitments: vec![VssShareLinkageCommitment {
            coordinates_by_commitment_modulus,
        }],
    });
    statement.validate_shape().expect("bridged key statement");
    witness.opening_randomness_by_limb = vec![randomness_by_column];

    let mut generate_request = statement_request_value(&statement);
    let bridge = statement.same_secret_bridge.as_ref().expect("bridge");
    generate_request["sameSecretBridge"] = serde_json::json!({
        "publicMatrixSeedHash": bridge.public_matrix_seed_hash,
        "targetBasisHash": bridge.target_basis_hash,
        "sourceTrusteeIdentity": bridge.source_trustee_identity,
        "sourceTrusteeRosterPosition": bridge.source_trustee_roster_position,
        "targetRnsPrimes": bridge.target_rns_primes,
        "targetConstantCommitmentRoots": bridge.target_constant_commitment_roots,
        "targetConstantCommitments": [computation.commitment.clone()],
    });
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate command");
    verify_generated_proof(&statement, &generated);

    // A key-bearing request without the bridge anchor is refused fail-closed.
    let mut missing_anchor_request = generate_request.clone();
    missing_anchor_request
        .as_object_mut()
        .expect("request object")
        .remove("sameSecretBridge");
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&missing_anchor_request).is_err(),
        "a key-bearing statement without the bridge anchor must be refused"
    );

    let mut tampered_proof_bytes = generated_proof_bytes(&generated);
    let flip_position = tampered_proof_bytes.len() / 2;
    tampered_proof_bytes[flip_position] ^= 1;
    assert!(
        verify_proof_bytes(&statement, &tampered_proof_bytes).is_err(),
        "tampered proof bytes must reject"
    );

    // Statement tampering: a forged Galois element or a substituted round-two
    // aggregate changes the statement hash, so the schedule's per-key
    // transcript binding rejects the honest bytes.
    let honest_proof_bytes = generated_proof_bytes(&generated);
    let mut forged_element_statement =
        super::super::commands::statement_from_request(&generate_request)
            .expect("reparsed statement");
    forged_element_statement.keys[2].kind =
        EvaluationKeyShareKind::GaloisRotation { galois_element: 7 };
    assert!(
        verify_proof_bytes(&forged_element_statement, &honest_proof_bytes).is_err(),
        "a forged rotation element must reject the schedule proof"
    );
    let mut forged_aggregate_statement =
        super::super::commands::statement_from_request(&generate_request)
            .expect("reparsed statement");
    let aggregate_modulus = DATA_PRIMES[0];
    forged_aggregate_statement.keys[1].round_one_aggregate_diagonal[0][0] =
        (forged_aggregate_statement.keys[1].round_one_aggregate_diagonal[0][0] + 1)
            % aggregate_modulus;
    assert!(
        verify_proof_bytes(&forged_aggregate_statement, &honest_proof_bytes).is_err(),
        "a substituted round-two aggregate must reject the schedule proof"
    );
    // A substituted aggregate must not prove either: the witness carries no
    // exact carry decomposition for the forged congruence.
    let mut forged_generate_request = generate_request.clone();
    let original_residue = forged_generate_request["keys"][1]["roundOneAggregateDiagonal"][0][0]
        .as_u64()
        .expect("aggregate residue");
    forged_generate_request["keys"][1]["roundOneAggregateDiagonal"][0][0] =
        serde_json::json!((original_residue + 1) % aggregate_modulus);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&forged_generate_request)
            .is_err(),
        "a substituted round-two aggregate must not prove"
    );
}

#[test]
fn trustee_proof_commands_reject_noncanonical_public_statement_material() {
    let (round_two_statement, round_two_witness) =
        generate_development_trustee_instance("feed0102", &[round_two(2)], SMALL_RING_DEGREE)
            .expect("round-two instance");
    let mut component_request = statement_request_value(&round_two_statement);
    component_request["keys"][0]["componentBByDigit"][0][0][0] = serde_json::json!(DATA_PRIMES[0]);
    component_request["secretCoefficients"] =
        serde_json::json!(round_two_witness.secret_coefficients);
    component_request["errorCoefficientsByKey"] =
        serde_json::json!(round_two_witness.error_coefficients_by_key);
    component_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    component_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&component_request).is_err(),
        "out-of-range componentBByDigit values must reject before proving"
    );

    let mut aggregate_request = statement_request_value(&round_two_statement);
    aggregate_request["keys"][0]["roundOneAggregateDiagonal"][0][0] =
        serde_json::json!(DATA_PRIMES[0]);
    aggregate_request["secretCoefficients"] =
        serde_json::json!(round_two_witness.secret_coefficients);
    aggregate_request["errorCoefficientsByKey"] =
        serde_json::json!(round_two_witness.error_coefficients_by_key);
    aggregate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    aggregate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&aggregate_request).is_err(),
        "out-of-range aggregate statement values must reject before proving"
    );

    let (statement, witness) =
        generate_development_trustee_instance("feed0304", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("round-one instance");
    let mut material_bytes =
        component_material_bytes_for_request_key(&statement.keys[0], SMALL_RING_DEGREE);
    let coefficient_offset = 8 + (4 * 8);
    material_bytes[coefficient_offset..coefficient_offset + 8]
        .copy_from_slice(&DATA_PRIMES[0].to_le_bytes());
    let mut material_request = statement_request_value(&statement);
    material_request["keys"][0]
        .as_object_mut()
        .expect("key object")
        .remove("componentBByDigit");
    material_request["keys"][0]["componentMaterialBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&material_bytes));
    material_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    material_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    material_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    material_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&material_request).is_err(),
        "out-of-range binary component material must reject before proving"
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
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate anchor command");
    assert_eq!(generated["proofFamily"], "same-secret-linkage-anchor");

    verify_generated_proof(&statement, &generated);

    // A keyless request whose context carries the evaluation-key binding
    // labels must be refused: the family decides the expected label list.
    let mut mislabeled_request = statement_request_value(&statement);
    mislabeled_request["context"]["vssCoefficientCommitmentMaterialRoot"] = serde_json::Value::Null;
    mislabeled_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    mislabeled_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    mislabeled_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    mislabeled_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    mislabeled_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&mislabeled_request).is_err(),
        "a keyless statement without the anchor binding root must be refused"
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
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate public-key share command");
    assert_eq!(generated["proofFamily"], "public-key-share");

    verify_generated_proof(&statement, &generated);

    // A public-key share request whose context carries the wrong binding
    // labels (the anchor's) must be refused.
    let mut mislabeled = statement_request_value(&statement);
    mislabeled["context"]["sameSecretStatementRoot"] = serde_json::Value::Null;
    mislabeled["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    mislabeled["errorCoefficientsByKey"] = serde_json::json!(witness.error_coefficients_by_key);
    mislabeled["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    mislabeled["openingRandomnessByLimb"] = serde_json::json!(witness.opening_randomness_by_limb);
    mislabeled["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    mislabeled["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&mislabeled).is_err(),
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
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate with nonce");

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
fn proof_codec_round_trips_and_rejects_malformed_bytes() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "c0dec0de",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
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
    // The adaptive low-degree final layer absorbs the whole recursion below a
    // 4096-coefficient claim bound, so folded-layer shape checks need the
    // smallest ring that still commits a folded Merkle layer.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "c0dec0de",
        &[],
        FOLDED_LAYER_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
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
        "cafe0dd0",
        &[],
        FOLDED_LAYER_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    proof.limb_proofs[0]
        .sumcheck_residual_low_degree
        .folded_layer_roots
        .pop()
        .expect("at least one committed folded layer");
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(&statement, &encoded) {
        Ok(_) => panic!("wrong residual low-degree fold count must reject at decode"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("low-degree committed fold count does not match the statement"),
        "unexpected residual low-degree fold-count error: {}",
        error.message
    );

    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "dec0ded0",
        &[],
        FOLDED_LAYER_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
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
        .resize(maximum_layer_zero_nodes + 1, [0_u8; 32]);
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
        &[],
        FOLDED_LAYER_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
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
        proof.limb_proofs[0].low_degree.query_openings[0].folded_layer_siblings[0].sibling[0] =
            modulus;
    });
    assert_noncanonical_encoded_proof_rejects(
        "residual low-degree final coefficient",
        |proof, modulus| {
            proof.limb_proofs[0]
                .sumcheck_residual_low_degree
                .final_coefficients[0][0] = modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "residual low-degree folded opening",
        |proof, modulus| {
            proof.limb_proofs[0]
                .sumcheck_residual_low_degree
                .query_openings[0]
                .folded_layer_siblings[0]
                .sibling[0] = modulus;
        },
    );
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
