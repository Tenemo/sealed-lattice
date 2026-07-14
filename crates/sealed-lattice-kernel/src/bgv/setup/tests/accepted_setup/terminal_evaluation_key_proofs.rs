use super::*;

// Proof bytes remain outside the package and are resolved from authenticated
// material roots.
fn terminal_evaluation_key_bearing_collective_setup_fixture() -> (
    super::package_fixtures::CollectiveSetupVerificationFixture,
    crate::bgv::setup::AcceptedSetupProofBindingSession,
) {
    let mut fixture = collective_public_key_bearing_collective_setup_fixture();
    let proof_binding_session = fixture.begin_proof_binding_session();
    {
        let package = &mut fixture.package;
        // Relinearization rounds (and the public round-one aggregate diagonals the
        // round-two shares and the trustee statements are proven against).
        let relinearization =
            relinearization_key_share_rounds_fixture(package, proof_binding_session);
        package["relinearizationKeyShareRounds"] = relinearization.rounds;
        let galois = galois_key_share_batches_object(package, proof_binding_session);
        package["galoisKeyShareBatches"] = galois.batches;
        let trustee_proof_fixture = trustee_evaluation_key_proofs_object(
            package,
            &proof_binding_session,
            &relinearization.round_one_aggregate_diagonals_by_level,
        );
        package["trusteeEvaluationKeyProofs"] = trustee_proof_fixture.proof_set;
        rebind_collective_setup_package_hash(package);
    }

    // Trustee-proof construction consumes the cached base-proof bindings while
    // rebuilding its statements. Verification needs those same opaque bindings
    // once more, so restore them into this fixture-owned session.
    fixture.restore_proof_binding_leases(proof_binding_session);

    (fixture, proof_binding_session)
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_terminal_trustee_evaluation_key_proofs_pass_the_evaluation_key_phase() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_terminal_trustee_evaluation_key_proofs_pass_the_evaluation_key_phase",
    );
    let (fixture, proof_binding_session) =
        terminal_evaluation_key_bearing_collective_setup_fixture();

    let result = fixture
        .verify_in_session(proof_binding_session)
        .expect("verification response");
    let context = || serde_json::to_string_pretty(&result).expect("verification result JSON");

    // The reduced development ring means the only permitted refusal is the
    // profile/full-ring boundary, which runs after the evaluation-key phase; the
    // evaluation-key objects were accepted before it. A profile-ring boundary
    // refusal, or a clean accept on a full-ring package, are both consistent with
    // the evaluation-key phase having passed.
    if result["isValid"] == true {
        assert_eq!(result["value"], serde_json::json!({}), "{}", context());
    } else {
        assert_eq!(
            result["refusalReason"],
            "outsideSupportedProfile",
            "reduced-ring terminal package must either accept or stop only at the \
             profile-ring boundary after the evaluation-key phase: {}",
            context()
        );
    }
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_terminal_tampered_trustee_evaluation_key_proof_is_refused() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_terminal_tampered_trustee_evaluation_key_proof_is_refused",
    );
    let (mut fixture, proof_binding_session) =
        terminal_evaluation_key_bearing_collective_setup_fixture();

    replace_first_trustee_evaluation_key_proof_with_tampered_material(
        &mut fixture,
        proof_binding_session,
    );

    let result = fixture
        .verify_in_session(proof_binding_session)
        .expect("verification response");
    let context = || serde_json::to_string_pretty(&result).expect("verification result JSON");

    assert_eq!(result["isValid"], false, "{}", context());
    assert_eq!(result["refusalReason"], "invalidProof", "{}", context());
}

// Replaces the first trustee's proof material with malformed authenticated
// bytes, then rebuilds every byte-derived reference and package binding. This
// keeps transport authentication valid so the rejection reaches the succinct
// relation verifier instead of stopping at a stale hash.
fn replace_first_trustee_evaluation_key_proof_with_tampered_material(
    fixture: &mut super::package_fixtures::CollectiveSetupVerificationFixture,
    proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) {
    let proof_bytes = vec![0x53, 0x4c, 0x45, 0x4b, 0x01, 0xff, 0x00];
    let proof_bytes_hash =
        crate::bgv::setup::trustee_evaluation_key_proof::trustee_evaluation_key_proof_bytes_hash(
            &proof_bytes,
        );
    let proof_record = &mut fixture.package["trusteeEvaluationKeyProofs"]["proofRecords"][0];
    proof_record["proofBytesHash"] = serde_json::json!(proof_bytes_hash);
    let proof_material_root = super::proof_record_fixtures::
        trustee_evaluation_key_proof_material_root_from_fixture_record(proof_record);
    proof_record["proofMaterialRoot"] = serde_json::json!(&proof_material_root);

    authenticate_setup_proof_material_stream_in_session_for_test(
        crate::bgv::setup::trustee_evaluation_key_proof::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        &proof_material_root,
        &proof_bytes,
        proof_binding_session,
    )
    .expect("authenticate tampered trustee proof material stream");

    rebind_collective_setup_package_hash(&mut fixture.package);
}
