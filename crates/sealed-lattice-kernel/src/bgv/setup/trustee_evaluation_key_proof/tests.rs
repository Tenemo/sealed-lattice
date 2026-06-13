use super::proof_codec::{
    decode_trustee_evaluation_key_proof, encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    EvaluationKeyShareKind, galois_automorphism_apply, galois_automorphism_transpose_apply,
    generate_development_public_key_share_instance, generate_development_trustee_ceremony_slice,
    generate_development_trustee_instance, generate_development_trustee_instance_with_linkage,
    round_one_aggregate_diagonal_from_components,
};
use super::verifier::verify_evaluation_key_share;
use crate::bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE};

const SMALL_RING_DEGREE: usize = 128;
const PROOF_RANDOMNESS_SEED: &str = "00112233445566778899aabbccddeeff";

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
    // Level two keeps all three commitment fields active; four Q_share
    // commitments exercise the linkage relations without the full profile.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "11aa22bb",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(4),
    )
    .expect("development instance");
    assert!(statement.same_secret_linkage.is_some());
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
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
    // only the commitment-opening, support, and cross-limb consistency
    // relations are active, over the three commitment fields.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "99ffeedd",
        &[],
        SMALL_RING_DEGREE,
        Some(3),
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
fn keyless_statement_without_linkage_is_refused() {
    let (mut statement, witness) = generate_development_trustee_instance_with_linkage(
        "aa00bb11",
        &[],
        SMALL_RING_DEGREE,
        Some(3),
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
        Some(3),
    )
    .expect("anchor instance");
    let (other_statement, _) = generate_development_trustee_instance_with_linkage(
        "ee44ff55",
        &[],
        SMALL_RING_DEGREE,
        Some(3),
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

fn statement_request_value(
    statement: &super::relation::TrusteeEvaluationKeyStatement,
) -> serde_json::Value {
    use crate::bgv::setup::commitment::setup_commitment_full_value;
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
    generate_request["proofRandomnessSource"] = serde_json::json!("test-fixed-seed");
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);

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
fn anchor_proof_commands_round_trip_with_family_label() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "fafa0101",
        &[],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("anchor instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSource"] = serde_json::json!("test-fixed-seed");
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);

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
        &accounting["zeroKnowledge"]["smudgingBudget"]["accepted"],
        &accounting["fiatShamir"]["accepted"],
        &accounting["sameSecretLinkage"]["accepted"],
    ] {
        assert_eq!(accepted_row, &serde_json::json!(true));
    }
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

// Gated full-ring-degree benchmark. Runs only when the environment variable
// is set, so it never burdens the default test lane.
//
//   SEALED_LATTICE_RUN_SUCCINCT_PROTOTYPE_BENCHMARK=1 \
//   SEALED_LATTICE_SUCCINCT_PROTOTYPE_LEVEL=15 \
//   SEALED_LATTICE_SUCCINCT_PROTOTYPE_SCHEDULE=trustee \
//   cargo test -p sealed-lattice-kernel --release \
//     trustee_evaluation_key_proof::tests::full_ring_degree_benchmark -- --nocapture
#[test]
fn full_ring_degree_benchmark() {
    if std::env::var("SEALED_LATTICE_RUN_SUCCINCT_PROTOTYPE_BENCHMARK").is_err() {
        return;
    }
    let level = std::env::var("SEALED_LATTICE_SUCCINCT_PROTOTYPE_LEVEL")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(7);
    let schedule_label = std::env::var("SEALED_LATTICE_SUCCINCT_PROTOTYPE_SCHEDULE")
        .unwrap_or_else(|_| "round-one".to_string());
    let key_requests = match schedule_label.as_str() {
        // A representative trustee slice: both relinearization rounds plus
        // two full-level rotations and two lower-level return rotations.
        "trustee" => vec![
            round_one(level),
            round_two(level),
            rotation(3, level),
            rotation(2 * POLYNOMIAL_DEGREE - 1, level),
            rotation(5, level.min(6)),
            rotation(7, level.min(6)),
        ],
        "round-two" => vec![round_two(level)],
        "galois" => vec![rotation(3, level)],
        _ => vec![round_one(level)],
    };
    let linkage_commitments = if schedule_label == "trustee" {
        Some(crate::bgv::profile::DATA_PRIMES.len())
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
    println!("succinct evaluation-key prototype benchmark ({schedule_label})");
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
    generate_request["proofRandomnessSource"] = serde_json::json!("test-fixed-seed");
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);

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
fn public_key_share_accounting_carries_family_rows() {
    let accounting = super::accounting::succinct_public_key_share_accounting_value()
        .expect("public-key share accounting");
    assert_eq!(accounting["proofFamily"], "public-key-share");
    assert_eq!(accounting["objectType"], "SuccinctPublicKeyShareAccounting");
    // The shared theorem rows stay accepted.
    assert_eq!(accounting["lowDegreeSoundness"]["accepted"], true);
    assert_eq!(accounting["fiatShamir"]["accepted"], true);
    assert!(
        accounting["familyRelationRows"]["commonReferenceBinding"].is_string(),
        "the family rows must record the common reference binding"
    );
}
