use super::*;

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

// Option A invariant: the private-VSS message (Shamir coefficient) columns are
// committed witnesses (they appear in the logical column set and the opening
// lincheck) but they carry no cross-field consistency claim. Only the carry and
// the opening-randomness columns are claimed, so the consistency set is exactly
// the logical set minus the message columns. This is what bounds the disclosed
// smudging leakage to the carry-driven figure instead of the full-range message
// figure. If the consistency set ever silently re-includes the message columns,
// the leakage accounting and the mask sizing both regress, so pin the shape.
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
    // The carry must stay in the consistency set: it is essential to the
    // global sharing-soundness argument that replaces the removed message assertions
    // (carry consistency + the public range-checked share pin the polynomial
    // evaluation per recipient). Dropping it the way
    // the message claims were dropped would silently break soundness, so pin that
    // exactly one non-randomness consistency vector (the carry) remains.
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
