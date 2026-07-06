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
        generate_development_public_key_share_instance("0011aabb", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    statement.keys[0].component_b_by_digit[0][0][0] ^= 1;
    let result = verify_evaluation_key_share(&statement, &proof);
    assert!(result.is_err(), "tampered component material must reject");
}

#[test]
fn tampered_deep_evaluation_is_rejected() {
    let (statement, witness) =
        generate_development_public_key_share_instance("c0ffee11", SMALL_RING_DEGREE)
            .expect("public-key share instance");
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
        generate_development_public_key_share_instance("13371337", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    proof.limb_proofs[0].masked_consistency_claims[0] += 1;
    let result = verify_evaluation_key_share(&statement, &proof);
    assert!(result.is_err(), "tampered consistency claim must reject");
}

#[test]
fn tampered_sumcheck_residual_zero_anchor_is_rejected() {
    let (statement, witness) =
        generate_development_public_key_share_instance("a11ce000", SMALL_RING_DEGREE)
            .expect("public-key share instance");
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
        generate_development_public_key_share_instance("a11ce001", SMALL_RING_DEGREE)
            .expect("public-key share instance");
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
        generate_development_public_key_share_instance("aaaa0001", SMALL_RING_DEGREE)
            .expect("first instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let (other_statement, other_witness) =
        generate_development_public_key_share_instance("bbbb0002", SMALL_RING_DEGREE)
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

// Private-VSS message (Shamir coefficient) columns are committed witnesses
// covered by the opening lincheck, but they carry no cross-field consistency
// claim. Only carry and opening-randomness columns are claimed, so the
// consistency set is exactly the logical set minus the message columns. This
// bounds the disclosed smudging leakage to the carry-driven figure. If the
// consistency set includes message columns, the leakage accounting and mask
// sizing both regress, so pin the shape.
#[test]
fn private_vss_consistency_set_excludes_committed_message_columns() {
    let statement = private_vss_statement_for_context_tests();
    let layout = LimbColumnLayout::new(&statement, 0).expect("limb layout");

    // The context statement carries four Shamir coefficient commitments, so the
    // message columns genuinely exist and the exclusion is non-trivial.
    assert_eq!(
        layout.private_vss_coefficient_columns, 4,
        "context statement should expose the four Shamir coefficient message columns"
    );
    assert!(
        layout.private_vss_randomness_columns > 0,
        "context statement should expose opening-randomness columns"
    );

    // The committed (logical) column set is messages + carry + randomness.
    assert_eq!(
        layout.private_vss_logical_columns(),
        layout.private_vss_coefficient_columns + 1 + layout.private_vss_randomness_columns
    );

    // The consistency-claimed set is only carry + randomness; the message
    // columns are excluded.
    assert_eq!(
        layout.consistency_vector_count(),
        1 + layout.private_vss_randomness_columns,
        "the consistency set must be the carry plus the opening-randomness columns only"
    );
    assert_eq!(
        layout.private_vss_logical_columns() - layout.consistency_vector_count(),
        layout.private_vss_coefficient_columns,
        "exactly the message columns are committed without a consistency assertion"
    );
    // The carry must stay in the consistency set: carry consistency plus the
    // public range-checked share pin the polynomial evaluation per recipient.
    // Exactly one non-randomness consistency vector (the carry) must remain.
    assert_eq!(
        layout.consistency_vector_count() - layout.private_vss_randomness_columns,
        1,
        "the carry must remain the one non-randomness consistency vector"
    );

    // The published claim count, which sizes the masks and the alpha challenges,
    // tracks the reduced consistency set, not the full logical set.
    assert_eq!(
        layout.claim_count(),
        layout.consistency_vector_count() * CONSISTENCY_REPETITIONS
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
