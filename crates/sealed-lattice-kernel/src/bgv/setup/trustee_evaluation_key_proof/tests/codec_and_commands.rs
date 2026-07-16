use super::*;
use std::sync::OnceLock;

#[test]
fn retained_private_vss_statement_hash_vector_matches() {
    let expected_hashes = expected_statement_hash_vectors();
    let mut private_vss_request = private_vss_statement_hash_vector_request();
    private_vss_request["sourceTrusteeIdentity"] =
        private_vss_request["sourceTrusteeCoefficientCommitmentRecord"]["sourceTrusteeIdentity"]
            .clone();
    let (_, private_vss_statement_hash) =
        crate::bgv::setup::private_vss::generate_private_vss_share_proof_from_request(
            &private_vss_request,
        )
        .expect("private VSS vector proof generation");
    assert_eq!(
        private_vss_statement_hash,
        expected_hashes["privateVssShare"]
            .as_str()
            .expect("private VSS vector hash")
    );
    assert_eq!(
        crate::bgv::setup::derive_succinct_setup_statement_hash_from_request(
            &serde_json::json!({
                "proofFamily": "private-vss-share",
                "setupContext": private_vss_request["setupContext"],
                "publicMatrixSeedHash": private_vss_request["publicMatrixSeedHash"],
                "privateEnvelopeAadHash": private_vss_request["privateEnvelopeAadHash"],
                "sourceTrusteeIdentity": private_vss_request["sourceTrusteeIdentity"],
                "sourceTrusteeRosterPosition": private_vss_request["sourceTrusteeRosterPosition"],
                "recipientRosterPosition": private_vss_request["recipientRosterPosition"],
                "rnsLimbIndex": private_vss_request["rnsLimbIndex"],
                "shareValues": private_vss_request["shareValues"],
                "sourceTrusteeCoefficientCommitmentMaterialRecords": private_vss_request["sourceTrusteeCoefficientCommitmentMaterialRecords"],
            }),
        )
        .expect("private VSS command statement hash")["statementHash"],
        expected_hashes["privateVssShare"]
    );
}

#[test]
fn proof_codec_round_trips_and_rejects_malformed_bytes() {
    let codec_test_ring_degree = LOW_DEGREE_QUERY_COUNT.next_power_of_two();
    let (statement, witness) = private_vss_proof_fixture(codec_test_ring_degree);
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
    let (statement, witness) = private_vss_proof_fixture(codec_test_ring_degree);
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
        let (statement, witness) = private_vss_proof_fixture(FOLDED_LAYER_RING_DEGREE);
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
fn proof_codec_rejects_noncanonical_values_for_retained_private_vss_family() {
    let (statement, witness) = private_vss_proof_fixture(SMALL_RING_DEGREE);
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    proof.limb_proofs[0].masked_consistency_claims[0] = statement.limb_moduli()[0];
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    assert!(
        decode_trustee_evaluation_key_proof(&statement, &encoded).is_err(),
        "noncanonical private VSS proof bytes must reject"
    );
}
