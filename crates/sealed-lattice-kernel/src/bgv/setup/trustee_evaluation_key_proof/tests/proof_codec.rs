use super::*;

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
