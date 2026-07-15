use super::*;
use std::sync::OnceLock;

#[test]
fn retained_succinct_setup_statement_hash_vectors_match() {
    let expected_hashes = expected_statement_hash_vectors();

    let trustee_statement = super::super::commands::statement_from_request(
        &trustee_evaluation_key_statement_hash_vector_request(),
    )
    .expect("trustee evaluation-key vector statement");
    assert_eq!(
        crate::hashing::to_hex(&trustee_statement.statement_hash()),
        expected_hashes["trusteeEvaluationKey"]
            .as_str()
            .expect("trustee evaluation-key vector hash")
    );

    let (_, private_vss_statement_hash) =
        crate::bgv::setup::private_vss::generate_private_vss_share_proof_from_request(
            &private_vss_statement_hash_vector_request(),
        )
        .expect("private VSS vector proof generation");
    assert_eq!(
        private_vss_statement_hash,
        expected_hashes["privateVssShare"]
            .as_str()
            .expect("private VSS vector hash")
    );
}

#[test]
fn key_bearing_atom_command_round_trips_with_bdlop_source_linkage() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "cdcdabab",
        &[round_one(2), round_two(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        1,
    )
    .expect("development instance");

    let generate_request = proof_generation_request(&statement, &witness);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate key-bearing atom proof");
    let proof_bytes = verify_generated_proof(&statement, &generated);

    let mut fresh_randomness_request = generate_request.clone();
    fresh_randomness_request["proofRandomnessSeedHex"] = serde_json::json!("42".repeat(64));
    let fresh_randomness_generated =
        super::generate_trustee_evaluation_key_proof_from_request(&fresh_randomness_request)
            .expect("generate key-bearing atom proof with fresh randomness");
    let fresh_randomness_proof_bytes =
        verify_generated_proof(&statement, &fresh_randomness_generated);
    assert_ne!(
        proof_bytes, fresh_randomness_proof_bytes,
        "key-bearing proof commitments must consume the bound private proof randomness"
    );

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
        1,
    )
    .expect("second development instance");
    let commitment = &mut wrong_commitment_statement
        .same_secret_linkage_mut()
        .expect("source linkage")
        .commitments[0];
    commitment.limbs[0].rows[0][0] =
        (commitment.limbs[0].rows[0][0] + 1) % commitment.limbs[0].modulus;
    assert!(
        verify_proof_bytes(&wrong_commitment_statement, &proof_bytes).is_err(),
        "a proof must not verify after its BDLOP source commitment is changed"
    );

    let mut wrong_secret_request = generate_request.clone();
    wrong_secret_request["secretCoefficients"][0] =
        serde_json::json!(if witness.secret_coefficients()[0] == 1 {
            0
        } else {
            1
        });
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&wrong_secret_request).is_err(),
        "a wrong key secret must not open the source commitment"
    );

    let mut nonternary_secret_request = generate_request.clone();
    nonternary_secret_request["secretCoefficients"][0] = serde_json::json!(2);
    let error =
        super::generate_trustee_evaluation_key_proof_from_request(&nonternary_secret_request)
            .expect_err("a nonternary secret must be rejected");
    assert!(
        error.message.contains("only ternary coefficients"),
        "unexpected nonternary-secret error: {}",
        error.message
    );

    let mut wrong_randomness_request = generate_request.clone();
    wrong_randomness_request["openingRandomnessByLimb"][0][0][0] =
        serde_json::json!(if witness.opening_randomness_by_limb()[0][0][0] == 1 {
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
            .expect("development instance");
    let mut request = proof_generation_request(&statement, &witness);
    request
        .as_object_mut()
        .expect("proof-generation request object")
        .remove("sameSecretLinkage");
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
    let mut component_request = proof_generation_request(&round_two_statement, &round_two_witness);
    component_request["keys"][0]["componentBByDigit"][0][0][0] = serde_json::json!(DATA_PRIMES[0]);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&component_request).is_err(),
        "out-of-range componentBByDigit values must reject before proving"
    );

    let mut aggregate_request = proof_generation_request(&round_two_statement, &round_two_witness);
    aggregate_request["keys"][0]["roundOneAggregateDiagonal"][0][0] =
        serde_json::json!(DATA_PRIMES[0]);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&aggregate_request).is_err(),
        "out-of-range aggregate statement values must reject before proving"
    );

    let (statement, witness) =
        generate_development_trustee_instance("feed0304", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("round-one instance");
    let mut material_bytes =
        component_material_bytes_for_request_key(&statement.keys()[0], SMALL_RING_DEGREE);
    let coefficient_offset = 8 + (4 * 8);
    material_bytes[coefficient_offset..coefficient_offset + 8]
        .copy_from_slice(&DATA_PRIMES[0].to_le_bytes());
    let mut material_request = proof_generation_request(&statement, &witness);
    material_request["keys"][0]
        .as_object_mut()
        .expect("key object")
        .remove("componentBByDigit");
    material_request["keys"][0]["componentMaterialBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&material_bytes));
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&material_request).is_err(),
        "out-of-range binary component material must reject before proving"
    );
}

#[test]
fn trustee_evaluation_key_commands_round_trip() {
    let (statement, witness) =
        generate_development_trustee_instance("aabbccdd", &[round_one(1)], SMALL_RING_DEGREE)
            .expect("trustee evaluation-key instance");
    let generate_request = proof_generation_request(&statement, &witness);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate trustee evaluation-key command");

    let _proof_bytes = verify_generated_proof(&statement, &generated);
}

#[test]
fn proof_command_validates_and_consumes_randomness_seed() {
    let (statement, witness) =
        generate_development_trustee_instance("aabbccde", &[round_one(1)], SMALL_RING_DEGREE)
            .expect("trustee evaluation-key instance");
    let generate_request = proof_generation_request(&statement, &witness);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate with private randomness");
    let first_generated_proof_bytes = generated_proof_bytes(&statement, &generated);

    let mut changed_seed_request = generate_request.clone();
    changed_seed_request["proofRandomnessSeedHex"] = serde_json::json!("11".repeat(64));
    let changed_seed_generated =
        super::generate_trustee_evaluation_key_proof_from_request(&changed_seed_request)
            .expect("generate with changed private randomness");
    let changed_seed_proof_bytes = generated_proof_bytes(&statement, &changed_seed_generated);
    assert_ne!(
        generated["proofBytesHash"], changed_seed_generated["proofBytesHash"],
        "different private randomness must produce different proof masks"
    );
    assert_ne!(first_generated_proof_bytes, changed_seed_proof_bytes);

    let mut short_seed_request = generate_request.clone();
    short_seed_request["proofRandomnessSeedHex"] = serde_json::json!("00".repeat(63));
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&short_seed_request).is_err(),
        "short proof randomness seed material must reject"
    );

    let mut missing_seed_request = generate_request;
    missing_seed_request
        .as_object_mut()
        .expect("request object")
        .remove("proofRandomnessSeedHex");
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&missing_seed_request).is_err(),
        "proof generation without private randomness must reject"
    );
}

#[test]
fn proof_codec_round_trips_and_rejects_malformed_bytes() {
    let codec_test_ring_degree = LOW_DEGREE_QUERY_COUNT.next_power_of_two();
    let (statement, witness) =
        generate_development_trustee_instance("c0dec0de", &[round_one(0)], codec_test_ring_degree)
            .expect("trustee evaluation-key instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let bytes = encode_trustee_evaluation_key_proof(&proof);
    assert_eq!(&bytes[..8], b"BGVPRF20");
    let mut previous_grammar_bytes = bytes.clone();
    previous_grammar_bytes[..8].copy_from_slice(b"BGVPRF19");
    assert!(
        decode_trustee_evaluation_key_proof(&statement, &previous_grammar_bytes).is_err(),
        "proof bytes from the previous Merkle-digest grammar must be rejected",
    );
    let decoded = decode_trustee_evaluation_key_proof(&statement, &bytes)
        .expect("decode canonical proof bytes");
    verify_evaluation_key_share(&statement, &decoded).expect("verify decoded proof");
    assert_eq!(
        encode_trustee_evaluation_key_proof(&decoded),
        bytes,
        "decoding and re-encoding must preserve every canonical proof byte"
    );

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
fn proof_codec_decodes_chunked_material_across_adversarial_boundaries() {
    let codec_test_ring_degree = LOW_DEGREE_QUERY_COUNT.next_power_of_two();
    let (statement, witness) =
        generate_development_trustee_instance("c0dec0df", &[round_one(0)], codec_test_ring_degree)
            .expect("trustee evaluation-key instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let bytes = encode_trustee_evaluation_key_proof(&proof);
    let chunk_widths = [3_usize, 5, 7, 11, 257, 4093];
    let mut chunks = Vec::new();
    let mut byte_offset = 0;
    let mut width_index = 0;
    while byte_offset < bytes.len() {
        let chunk_end =
            (byte_offset + chunk_widths[width_index % chunk_widths.len()]).min(bytes.len());
        chunks.push(bytes[byte_offset..chunk_end].to_vec());
        byte_offset = chunk_end;
        width_index += 1;
    }
    let chunked_material = TestChunkedProofBytes::new(chunks);
    let decoded = decode_trustee_evaluation_key_proof_from_source(&statement, &chunked_material)
        .expect("decode proof across chunk boundaries");
    verify_evaluation_key_share(&statement, &decoded).expect("verify chunk-decoded proof");
    assert_eq!(
        encode_trustee_evaluation_key_proof(&decoded),
        bytes,
        "chunked decoding and re-encoding must preserve every canonical proof byte"
    );

    let mut truncated_chunks = chunked_material.chunks.to_vec();
    truncated_chunks.last_mut().expect("final chunk").pop();
    let truncated_material = TestChunkedProofBytes::new(truncated_chunks);
    assert!(
        decode_trustee_evaluation_key_proof_from_source(&statement, &truncated_material).is_err(),
        "a chunked proof truncated at the final byte must reject"
    );
}

fn folded_layer_proof_codec_fixture() -> &'static (TrusteeEvaluationKeyStatement, Vec<u8>) {
    // The adaptive low-degree final layer absorbs the whole recursion below a
    // 4096-coefficient claim bound, so folded-layer shape checks need the
    // smallest ring that still commits a folded Merkle layer.
    static FIXTURE: OnceLock<(TrusteeEvaluationKeyStatement, Vec<u8>)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (statement, witness) = generate_development_trustee_instance(
            "c0dec0de",
            &[round_one(0)],
            FOLDED_LAYER_RING_DEGREE,
        )
        .expect("trustee evaluation-key instance");
        let canonical_proof =
            prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
        let canonical_proof_bytes = encode_trustee_evaluation_key_proof(&canonical_proof);
        (statement, canonical_proof_bytes)
    })
}

#[test]
#[ignore = "heavy Rust kernel proof test; run pnpm run test:rust:kernel:heavy"]
fn heavy_rust_kernel_proof_codec_rejects_low_degree_shape_mismatches_before_verification() {
    let (statement, canonical_proof_bytes) = folded_layer_proof_codec_fixture();
    let mut proof = decode_trustee_evaluation_key_proof(statement, canonical_proof_bytes)
        .expect("decode canonical proof");
    proof.limb_proofs[0]
        .low_degree
        .folded_layer_roots
        .pop()
        .expect("at least one committed folded layer");
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(statement, &encoded) {
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

    let mut proof = decode_trustee_evaluation_key_proof(statement, canonical_proof_bytes)
        .expect("decode canonical proof");
    proof.limb_proofs[0]
        .sumcheck_residual_low_degree
        .folded_layer_roots
        .pop()
        .expect("at least one committed folded layer");
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(statement, &encoded) {
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

    let mut proof = decode_trustee_evaluation_key_proof(statement, canonical_proof_bytes)
        .expect("decode canonical proof");
    // A batched folded-layer opening whose node count exceeds its per-layer
    // bound by one is rejected at decode, before any oversized allocation. The
    // bound mirrors the decoder: LOW_DEGREE_QUERY_COUNT openings over a layer of
    // the given depth.
    let layout = LimbColumnLayout::new(statement, 0).expect("limb layout");
    let extension_size = layout.trace_size * DOMAIN_BLOWUP;
    let maximum_layer_zero_nodes =
        LOW_DEGREE_QUERY_COUNT * folded_layer_path_length(extension_size, 0);
    proof.limb_proofs[0].low_degree.layer_batch_openings[0]
        .authentication_nodes
        .resize(maximum_layer_zero_nodes + 1, [0_u8; 64]);
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(statement, &encoded) {
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
#[ignore = "heavy Rust kernel proof test; run pnpm run test:rust:kernel:heavy"]
fn heavy_rust_kernel_proof_codec_rejects_noncanonical_values_in_every_encoded_area() {
    let (statement, canonical_proof_bytes) = folded_layer_proof_codec_fixture();

    type ProofResidueMutation = fn(&mut super::prover::SuccinctEvaluationKeyProof, u64);
    let mutation_cases: [(&str, ProofResidueMutation); 8] = [
        ("masked consistency claim", |proof, modulus| {
            proof.limb_proofs[0].masked_consistency_claims[0] = modulus;
        }),
        ("deep evaluation coordinate", |proof, modulus| {
            proof.limb_proofs[0].deep_evaluations[0][0][0] = modulus;
        }),
        ("phase-one query row", |proof, modulus| {
            proof.limb_proofs[0].query_openings[0].phase_one_rows[0][0] = modulus;
        }),
        ("phase-two coordinate row", |proof, modulus| {
            proof.limb_proofs[0].query_openings[0].phase_two_rows[0][0] = modulus;
        }),
        ("low-degree final coefficient", |proof, modulus| {
            proof.limb_proofs[0].low_degree.final_coefficients[0][0] = modulus;
        }),
        ("low-degree folded opening", |proof, modulus| {
            proof.limb_proofs[0].low_degree.query_openings[0].folded_layer_siblings[0].sibling[0] =
                modulus;
        }),
        ("residual low-degree final coefficient", |proof, modulus| {
            proof.limb_proofs[0]
                .sumcheck_residual_low_degree
                .final_coefficients[0][0] = modulus;
        }),
        ("residual low-degree folded opening", |proof, modulus| {
            proof.limb_proofs[0]
                .sumcheck_residual_low_degree
                .query_openings[0]
                .folded_layer_siblings[0]
                .sibling[0] = modulus;
        }),
    ];

    for (label, mutate_proof) in mutation_cases {
        assert_noncanonical_encoded_proof_rejects(
            label,
            statement,
            canonical_proof_bytes,
            mutate_proof,
        );
    }
}

#[test]
fn proof_codec_rejects_noncanonical_values_for_retained_trustee_family() {
    let (statement, witness) =
        generate_development_trustee_instance("2222bbbb", &[round_one(0)], SMALL_RING_DEGREE)
            .expect("trustee evaluation-key instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    proof.limb_proofs[0].masked_consistency_claims[0] = statement.limb_moduli()[0];
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    assert!(
        decode_trustee_evaluation_key_proof(&statement, &encoded).is_err(),
        "noncanonical trustee evaluation-key proof bytes must reject"
    );
}
