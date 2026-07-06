use super::*;

// Assembles a terminal collective BGV setup package whose trustee
// evaluation-key proofs are bound to the same-secret bridge: the
// reduced-ring three-trustee package, plus the public-key share material
// and same-secret-bridge-bound succinct proofs, the collective public key, the
// relinearization rounds, the Galois batches, the same-secret-bridge-bound trustee
// evaluation-key proofs, and the embedded public evaluation-key set. Every
// evaluation-key object embeds its material and proof bytes, so no transported
// material is required.
fn terminal_evaluation_key_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = finalize_collective_setup_package(
        minimal_collective_setup_package_for_participant_count(3),
    );
    // Public-key share material and same-secret-bridge-bound succinct proofs.
    replace_public_key_share_hashes_with_material_hashes(&mut package);
    package["publicKeyShareMaterial"] = public_key_share_material_object(&package);
    package["publicKeyShareSuccinctProofs"] = public_key_share_succinct_proofs_object(&package);
    // Collective public key aggregated from the succinct-proof-bearing shares.
    package["collectivePublicKey"] = collective_public_key_object(&package);
    package["collectivePublicKeyRoot"] =
        package["collectivePublicKey"]["collectivePublicKeyRoot"].clone();
    // Relinearization rounds (and the public round-one aggregate diagonals the
    // round-two shares and the trustee statements are proven against).
    let relinearization = relinearization_key_share_rounds_fixture(&package);
    package["relinearizationKeyShareRounds"] = relinearization.rounds;
    // Galois batches.
    package["galoisKeyShareBatches"] = galois_key_share_batches_object(&package);
    // Same-secret-bridge-bound trustee evaluation-key proofs.
    package["trusteeEvaluationKeyProofs"] = trustee_evaluation_key_proofs_object(
        &package,
        &relinearization.round_one_aggregate_diagonals_by_level,
    );
    // Embedded public evaluation-key set.
    package["evaluationKeys"] = public_evaluation_key_set_object(&package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

// The evaluation-key phase-boundary refusal object path is the pending-object
// path, so the eval-key phase leaving no refusal means the phase accepted the
// same-secret-bridge-bound proofs. A refused-object list containing an eval-key
// refusal reason would fail this check.
fn evaluation_key_phase_refused(result: &serde_json::Value) -> Option<String> {
    result["refusedObjects"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|refusal| {
            let reason = refusal["reasonCode"].as_str()?;
            let path = refusal["objectPath"].as_str().unwrap_or_default();
            let is_evaluation_key = reason.contains("elinearization")
                || reason.contains("alois")
                || reason.contains("EvaluationKey")
                || reason.contains("evaluationKey")
                || path.contains("relinearizationKeyShareRounds")
                || path.contains("galoisKeyShareBatches")
                || path.contains("trusteeEvaluationKeyProofs")
                || path.contains("evaluationKeys");
            is_evaluation_key.then(|| format!("{reason} ({path})"))
        })
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_terminal_trustee_evaluation_key_proofs_pass_the_evaluation_key_phase() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_terminal_trustee_evaluation_key_proofs_pass_the_evaluation_key_phase",
    );
    let package = terminal_evaluation_key_bearing_collective_setup_package();

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");
    let context = || serde_json::to_string_pretty(&result).expect("verification result JSON");

    // The same-secret-bridge-bound relinearization rounds, Galois batches, trustee
    // evaluation-key proofs, and evaluation-key set must all pass their phase:
    // no refusal references any evaluation-key object.
    assert_eq!(
        evaluation_key_phase_refused(&result),
        None,
        "the evaluation-key phase must accept the same-secret-bridge-bound proofs: {}",
        context()
    );
    // The reduced development ring means the only permitted refusal is the
    // profile/full-ring boundary, which runs after the evaluation-key phase; the
    // evaluation-key objects were accepted before it. A profile-ring boundary
    // refusal, or a clean accept on a full-ring package, are both consistent with
    // the evaluation-key phase having passed.
    let refusal_reason = result["refusedObjects"][0]["reasonCode"]
        .as_str()
        .unwrap_or_default();
    assert!(
        result["isValid"] == true
            || refusal_reason == "vssCoefficientCommitmentMaterialOutsideAcceptedRing"
            || refusal_reason == "vssCoefficientCommitmentMaterialOutsideProfile",
        "reduced-ring terminal package must either accept or stop only at the \
         profile-ring boundary after the evaluation-key phase: {}",
        context()
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_terminal_tampered_trustee_evaluation_key_proof_is_refused() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_terminal_tampered_trustee_evaluation_key_proof_is_refused",
    );
    let mut package = terminal_evaluation_key_bearing_collective_setup_package();

    // Flip one byte of the first trustee's embedded proof bytes and rebind the
    // record, set, and package roots so the only inconsistency is the proof
    // content itself. The recomputed statement no longer matches the tampered
    // proof, so the succinct verifier rejects it.
    let proof_bytes_hex = package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["proofBytesHex"]
        .as_str()
        .expect("trustee proof bytes hex");
    let mut proof_bytes = decode_hex(proof_bytes_hex).expect("trustee proof bytes");
    let tampered_position = proof_bytes.len() / 2;
    proof_bytes[tampered_position] ^= 1;
    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["proofBytesHex"] =
        serde_json::json!(to_hex(&proof_bytes));
    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["proofBytesHash"] = serde_json::json!(
        crate::bgv::setup::trustee_evaluation_key_proof::trustee_evaluation_key_proof_bytes_hash(
            &proof_bytes
        )
    );
    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["proofSizeBytes"] =
        serde_json::json!(proof_bytes.len());
    rebind_trustee_evaluation_key_proof_record_root_for_test(&mut package, 0);
    rebind_trustee_evaluation_key_proof_set_root_for_test(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");
    let context = || serde_json::to_string_pretty(&result).expect("verification result JSON");

    // The tampered proof no longer matches the statement the verifier rebuilds,
    // so the succinct evaluation-key verifier rejects it during the
    // relinearization round-one phase, before the reduced-ring boundary is
    // reached. The refusal is reported through isValid/refusedObjects.
    assert_eq!(result["isValid"], false, "{}", context());
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed",
        "{}",
        context()
    );
    assert_eq!(
        result["refusedObjects"][0]["objectPath"],
        "setupPackage.trusteeEvaluationKeyProofs"
    );
    assert!(result["acceptedSetupHandoff"].is_null());
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_empty_evaluation_key_objects_with_collective_public_key_are_not_accepted() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_empty_evaluation_key_objects_with_collective_public_key_are_not_accepted",
    );
    // The pre-terminal package plus public-key material, succinct proofs,
    // and the collective public key, but with the terminal evaluation-key objects
    // left as the empty {} / [] the base package ships. This is the trust-boundary
    // case: a package that declares public runtime material (the collective public
    // key) but carries no evaluation-key material must not reach accepted.
    let mut package = finalize_collective_setup_package(
        minimal_collective_setup_package_for_participant_count(3),
    );
    replace_public_key_share_hashes_with_material_hashes(&mut package);
    package["publicKeyShareMaterial"] = public_key_share_material_object(&package);
    package["publicKeyShareSuccinctProofs"] = public_key_share_succinct_proofs_object(&package);
    package["collectivePublicKey"] = collective_public_key_object(&package);
    package["collectivePublicKeyRoot"] =
        package["collectivePublicKey"]["collectivePublicKeyRoot"].clone();
    rebind_collective_setup_package_hash(&mut package);

    assert_eq!(
        package["relinearizationKeyShareRounds"],
        serde_json::json!({})
    );
    assert_eq!(package["galoisKeyShareBatches"], serde_json::json!([]));
    assert_eq!(package["trusteeEvaluationKeyProofs"], serde_json::json!({}));
    assert_eq!(package["evaluationKeys"], serde_json::json!({}));

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");
    let context = || serde_json::to_string_pretty(&result).expect("verification result JSON");

    // The package must not be accepted: empty terminal evaluation-key material is
    // caught either by the reduced-ring profile boundary (which runs before the
    // terminal required-material gate) or, on a full ring, by the terminal
    // required public evaluation-key material gate that treats the empty
    // evaluationKeys as missing. Either way, isValid remains false.
    assert_eq!(
        result["isValid"],
        false,
        "a package with empty evaluation-key objects and a collective public key must not be accepted: {}",
        context()
    );
    assert!(result["acceptedSetupHandoff"].is_null());
}

// Recomputes one trustee evaluation-key proof record's canonical root after a
// mutation, matching the verifier's own recompute (the whole record minus its
// root field).
fn rebind_trustee_evaluation_key_proof_record_root_for_test(
    package: &mut serde_json::Value,
    record_index: usize,
) {
    let record = &mut package["trusteeEvaluationKeyProofs"]["proofRecords"][record_index];
    record
        .as_object_mut()
        .expect("trustee evaluation-key proof record object")
        .remove("trusteeEvaluationKeyProofRoot");
    record["trusteeEvaluationKeyProofRoot"] = serde_json::json!(
        crate::hashing::derive_canonical_object_hash(record)
            .expect("trustee evaluation-key proof record root")
    );
}

// Recomputes the trustee evaluation-key proof set root after a record mutation.
fn rebind_trustee_evaluation_key_proof_set_root_for_test(package: &mut serde_json::Value) {
    let proof_set = &mut package["trusteeEvaluationKeyProofs"];
    proof_set
        .as_object_mut()
        .expect("trustee evaluation-key proof set object")
        .remove("trusteeEvaluationKeyProofSetRoot");
    proof_set["trusteeEvaluationKeyProofSetRoot"] = serde_json::json!(
        crate::hashing::derive_canonical_object_hash(proof_set)
            .expect("trustee evaluation-key proof set root")
    );
}
