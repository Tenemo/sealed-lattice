use super::*;

#[test]
fn key_bearing_atom_command_round_trips_with_bdlop_source_linkage() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "cdcdabab",
        &[round_one(2), round_two(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(1),
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
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate key-bearing atom proof");
    assert_eq!(generated["proofFamily"], "trustee-evaluation-key");
    verify_generated_proof(&statement, &generated);

    let proof_bytes = generated_proof_bytes(&generated);
    let mut tampered_proof_bytes = proof_bytes.clone();
    let tamper_position = tampered_proof_bytes.len() / 2;
    tampered_proof_bytes[tamper_position] ^= 1;
    assert!(
        verify_proof_bytes(&statement, &tampered_proof_bytes).is_err(),
        "tampered key-bearing proof bytes must be rejected"
    );

    let (mut wrong_commitment_statement, _) = generate_development_trustee_instance_with_linkage(
        "cdcdabab",
        &[round_one(2), round_two(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(1),
    )
    .expect("second development instance");
    let commitment = &mut wrong_commitment_statement
        .same_secret_linkage
        .as_mut()
        .expect("source linkage")
        .commitments[0];
    commitment.limbs[0].rows[0][0] =
        (commitment.limbs[0].rows[0][0] + 1) % commitment.limbs[0].modulus;
    assert!(
        verify_proof_bytes(&wrong_commitment_statement, &proof_bytes).is_err(),
        "a proof must not verify after its BDLOP source commitment is changed"
    );

    let (mut wrong_context_statement, _) = generate_development_trustee_instance_with_linkage(
        "cdcdabab",
        &[round_one(2), round_two(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(1),
    )
    .expect("third development instance");
    wrong_context_statement
        .context
        .binding_roots
        .iter_mut()
        .find(|(label, _)| label == "sourceConstantCoefficientCommitmentRoot")
        .expect("source constant binding root")
        .1 = "f".repeat(128);
    assert!(
        verify_proof_bytes(&wrong_context_statement, &proof_bytes).is_err(),
        "a key proof must not replay under a different exact source-constant root"
    );

    let mut wrong_secret_request = generate_request.clone();
    wrong_secret_request["secretCoefficients"][0] =
        serde_json::json!(if witness.secret_coefficients[0] == 1 {
            0
        } else {
            1
        });
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&wrong_secret_request).is_err(),
        "a wrong key secret must not open the source commitment"
    );

    let mut wrong_randomness_request = generate_request.clone();
    wrong_randomness_request["openingRandomnessByLimb"][0][0][0] =
        serde_json::json!(if witness.opening_randomness_by_limb[0][0][0] == 1 {
            0
        } else {
            1
        });
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&wrong_randomness_request)
            .is_err(),
        "wrong BDLOP opening randomness must be rejected"
    );
}

#[test]
fn key_bearing_atom_command_requires_source_linkage() {
    let (statement, witness) =
        generate_development_trustee_instance("cdcdabac", &[round_one(1)], SMALL_RING_DEGREE)
            .expect("development instance without source linkage");
    let mut request = statement_request_value(&statement);
    request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    request["errorCoefficientsByKey"] = serde_json::json!(witness.error_coefficients_by_key);
    request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&request).is_err(),
        "a key-bearing statement without BDLOP source linkage must be refused"
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
fn public_key_share_commands_round_trip_with_family_label() {
    let generate_request = public_key_share_statement_hash_vector_request();
    let statement = super::super::commands::statement_from_request(&generate_request)
        .expect("public-key share statement");

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate public-key share command");
    assert_eq!(generated["proofFamily"], "public-key-share");

    verify_generated_proof(&statement, &generated);

    // A public-key share request missing one exact bridge binding must be
    // refused.
    let mut mislabeled = generate_request;
    mislabeled["context"]["sameSecretBridgeStatementRoot"] = serde_json::Value::Null;
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&mislabeled).is_err(),
        "a public-key share statement without its binding roots must be refused"
    );
}

#[test]
fn proof_command_binds_randomness_seed_to_nonce_and_statement() {
    let generate_request = public_key_share_statement_hash_vector_request();

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
    let (statement, witness) =
        generate_development_public_key_share_instance("c0dec0de", SMALL_RING_DEGREE)
            .expect("public-key share instance");
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
    let (statement, witness) =
        generate_development_public_key_share_instance("c0dec0de", FOLDED_LAYER_RING_DEGREE)
            .expect("public-key share instance");
    let canonical_proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let canonical_proof_bytes = encode_trustee_evaluation_key_proof(&canonical_proof);
    let mut proof = decode_trustee_evaluation_key_proof(&statement, &canonical_proof_bytes)
        .expect("decode canonical proof");
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

    let mut proof = decode_trustee_evaluation_key_proof(&statement, &canonical_proof_bytes)
        .expect("decode canonical proof");
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

    let mut proof = canonical_proof;
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
    statement: &TrusteeEvaluationKeyStatement,
    canonical_proof_bytes: &[u8],
    mutate_proof: impl FnOnce(&mut super::prover::SuccinctEvaluationKeyProof, u64),
) {
    let mut proof = decode_trustee_evaluation_key_proof(statement, canonical_proof_bytes)
        .expect("decode canonical proof");
    let modulus = statement.limb_moduli()[0];
    mutate_proof(&mut proof, modulus);
    let encoded = encode_trustee_evaluation_key_proof(&proof);

    assert!(
        decode_trustee_evaluation_key_proof(statement, &encoded).is_err(),
        "{label} with a noncanonical residue must be rejected by the decoder"
    );
}

#[test]
fn proof_codec_rejects_noncanonical_values_in_every_encoded_area() {
    let (statement, witness) =
        generate_development_public_key_share_instance("c0decafe", FOLDED_LAYER_RING_DEGREE)
            .expect("public-key share instance");
    let canonical_proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let canonical_proof_bytes = encode_trustee_evaluation_key_proof(&canonical_proof);

    assert_noncanonical_encoded_proof_rejects(
        "masked consistency claim",
        &statement,
        &canonical_proof_bytes,
        |proof, modulus| {
            proof.limb_proofs[0].masked_consistency_claims[0] = modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "deep evaluation coordinate",
        &statement,
        &canonical_proof_bytes,
        |proof, modulus| {
            proof.limb_proofs[0].deep_evaluations[0][0][0] = modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "phase-one query row",
        &statement,
        &canonical_proof_bytes,
        |proof, modulus| {
            proof.limb_proofs[0].query_openings[0].phase_one_rows[0][0] = modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "phase-two coordinate row",
        &statement,
        &canonical_proof_bytes,
        |proof, modulus| {
            proof.limb_proofs[0].query_openings[0].phase_two_rows[0][0] = modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "low-degree final coefficient",
        &statement,
        &canonical_proof_bytes,
        |proof, modulus| {
            proof.limb_proofs[0].low_degree.final_coefficients[0][0] = modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "low-degree folded opening",
        &statement,
        &canonical_proof_bytes,
        |proof, modulus| {
            proof.limb_proofs[0].low_degree.query_openings[0].folded_layer_siblings[0].sibling[0] =
                modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "residual low-degree final coefficient",
        &statement,
        &canonical_proof_bytes,
        |proof, modulus| {
            proof.limb_proofs[0]
                .sumcheck_residual_low_degree
                .final_coefficients[0][0] = modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "residual low-degree folded opening",
        &statement,
        &canonical_proof_bytes,
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
        super::same_secret_bridge::same_secret_bridge_instance(),
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
