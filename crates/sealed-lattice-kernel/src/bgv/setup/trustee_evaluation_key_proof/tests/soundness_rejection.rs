use super::*;

#[test]
fn soundness_report_meets_the_conjectured_classical_policy_floor() {
    // The soundness gate is essential: 128-bit effective soundness depends on the
    // pre-union margin and a named, unproven FRI conjecture. The recomputed
    // numeric soundness bound, not self-attested verdict flags, is what the
    // policy enforces.
    let effective_soundness_bits = accounting::succinct_proof_effective_soundness_bits(
        crate::bgv::parameters::POLYNOMIAL_DEGREE / 2,
    )
    .expect("effective soundness bits");
    assert!(effective_soundness_bits >= 128);
    accounting::enforce_current_succinct_proof_soundness_policy(
        crate::bgv::parameters::POLYNOMIAL_DEGREE / 2,
    )
    .expect("conjectured classical policy floor");
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
fn tampered_sumcheck_residual_zero_anchor_is_rejected() {
    let (statement, witness) =
        generate_development_trustee_instance("a11ce000", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let modulus = statement.limb_moduli()[0];
    let layout = LimbColumnLayout::new(&statement, 0).expect("limb layout");
    let residual_column = layout.phase_one_physical_count() + QUOTIENT_COLUMN_SUMCHECK_RESIDUAL;
    let anchor_point_index = DEEP_EVALUATION_POINT_COUNT - 1;
    proof.limb_proofs[0].deep_evaluations[anchor_point_index][residual_column][0] =
        (proof.limb_proofs[0].deep_evaluations[anchor_point_index][residual_column][0] + 1)
            % modulus;
    let result = verify_evaluation_key_share(&statement, &proof);
    assert!(
        result.is_err(),
        "tampering with the residual zero anchor must reject"
    );
}

#[test]
fn tampered_sumcheck_residual_low_degree_proof_is_rejected() {
    let (statement, witness) =
        generate_development_trustee_instance("a11ce001", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let modulus = statement.limb_moduli()[0];
    proof.limb_proofs[0]
        .sumcheck_residual_low_degree
        .final_coefficients[0][0] = (proof.limb_proofs[0]
        .sumcheck_residual_low_degree
        .final_coefficients[0][0]
        + 1)
        % modulus;
    let result = verify_evaluation_key_share(&statement, &proof);
    assert!(
        result.is_err(),
        "tampering with the residual low-degree proof must reject"
    );
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
    // Soundness invariant: round-two material whose source is
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
