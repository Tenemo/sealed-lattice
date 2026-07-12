use super::package_fixtures::{
    TRUSTEE_EVALUATION_KEY_PROOF_TRANSPORT_CERTIFICATE_FIELDS,
    replace_setup_proof_material_transport_certificate_objects,
};
use super::*;

// Assembles a terminal collective BGV setup package whose trustee
// evaluation-key proofs are bound to the same-secret bridge: the
// reduced-ring three-trustee package, plus the public-key share material and
// same-secret-bridge-bound succinct proofs, the collective public key, the
// relinearization rounds, the Galois batches, the same-secret-bridge-bound
// trustee evaluation-key proofs, and the public evaluation-key set. Proof bytes
// remain outside the package and are resolved from authenticated material roots.
fn terminal_evaluation_key_bearing_collective_setup_fixture()
-> super::package_fixtures::CollectiveSetupVerificationFixture {
    terminal_evaluation_key_bearing_collective_setup_fixture_configured(false)
}

// The terminal package builder, optionally folding the committed-material
// aggregate binding into the embedded evaluation-key set. The existing terminal
// tests build without it (their focus is the trustee-proof and phase behavior);
// the dedicated aggregate-binding test builds with it.
fn terminal_evaluation_key_bearing_collective_setup_fixture_configured(
    with_aggregate_binding: bool,
) -> super::package_fixtures::CollectiveSetupVerificationFixture {
    let mut fixture = collective_public_key_bearing_collective_setup_fixture();
    let package = &mut fixture.package;
    // Relinearization rounds (and the public round-one aggregate diagonals the
    // round-two shares and the trustee statements are proven against).
    let relinearization = relinearization_key_share_rounds_fixture(package);
    package["relinearizationKeyShareRounds"] = relinearization.rounds;
    // Galois batches.
    package["galoisKeyShareBatches"] = galois_key_share_batches_object(package);
    // Same-secret-bridge-bound trustee evaluation-key proofs.
    let trustee_proof_fixture = trustee_evaluation_key_proofs_object(
        package,
        &relinearization.round_one_aggregate_diagonals_by_level,
    );
    package["trusteeEvaluationKeyProofs"] = trustee_proof_fixture.proof_set;
    fixture.verification_request["transportedEvaluationKeyShareProofMaterial"] =
        trustee_proof_fixture.transported_proof_material;
    replace_setup_proof_material_transport_certificate_objects(
        package,
        &fixture.verification_request["transportedEvaluationKeyShareProofMaterial"],
        TRUSTEE_EVALUATION_KEY_PROOF_TRANSPORT_CERTIFICATE_FIELDS,
    );
    // Committed-material aggregate binding: the package record and the transport
    // openings, produced from the same statements the trustee proofs bind. The
    // record is folded into the evaluation-key set (bound by its hash). The
    // embedded (reference-free) set does not trigger the verifier's
    // aggregate-binding crypto check, which runs only for transported full-ring
    // material; folding it here keeps the record present, bound, and reproducible.
    let aggregate_binding = with_aggregate_binding.then(|| {
        let (aggregate_binding, _transported_openings) = evaluation_key_aggregate_binding_object(
            package,
            &relinearization.round_one_aggregate_diagonals_by_level,
        );
        aggregate_binding
    });
    // Embedded public evaluation-key set, with the aggregate binding folded in when
    // requested.
    package["evaluationKeys"] =
        public_evaluation_key_set_object_with_aggregate_binding(package, aggregate_binding);
    rebind_collective_setup_package_hash(package);

    fixture
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
    let fixture = terminal_evaluation_key_bearing_collective_setup_fixture();

    let result =
        verify_collective_bgv_setup_package(&fixture.package, &fixture.verification_request)
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
    let mut fixture = terminal_evaluation_key_bearing_collective_setup_fixture();

    // Flip one byte of the first trustee's authenticated proof material and
    // rebind the record, stream descriptor, certificate, and package roots so
    // the only inconsistency is the proof content itself. The recomputed
    // statement no longer matches the tampered proof, so the succinct verifier
    // rejects it.
    replace_first_trustee_evaluation_key_proof_with_tampered_material(&mut fixture);

    let result =
        verify_collective_bgv_setup_package(&fixture.package, &fixture.verification_request)
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
    let fixture = collective_public_key_bearing_collective_setup_fixture();
    let package = fixture.package;

    assert_eq!(
        package["relinearizationKeyShareRounds"],
        serde_json::json!({})
    );
    assert_eq!(package["galoisKeyShareBatches"], serde_json::json!([]));
    assert_eq!(package["trusteeEvaluationKeyProofs"], serde_json::json!({}));
    assert_eq!(package["evaluationKeys"], serde_json::json!({}));

    let result = verify_collective_bgv_setup_package(&package, &fixture.verification_request)
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
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_terminal_committed_material_aggregate_binding_is_bound_and_well_formed() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_terminal_committed_material_aggregate_binding_is_bound_and_well_formed",
    );
    let fixture = terminal_evaluation_key_bearing_collective_setup_fixture_configured(true);
    let package = fixture.package;
    let participant_count = package["setupContext"]["participantCount"]
        .as_u64()
        .expect("participant count") as usize;

    // The aggregate-binding record is present and bound: the evaluation-key set
    // still recomputes its own hash with the record folded in, so a verifier that
    // recomputes `evaluationKeySetHash` accepts it.
    let evaluation_keys = &package["evaluationKeys"];
    let aggregate_binding = &evaluation_keys["aggregateBinding"];
    assert_eq!(
        aggregate_binding["objectType"], "EvaluationKeyAggregateBindingSet",
        "the folded record must be an aggregate-binding set"
    );
    let mut hashable = evaluation_keys.clone();
    hashable
        .as_object_mut()
        .expect("evaluation-key set object")
        .remove("evaluationKeySetHash");
    assert_eq!(
        evaluation_keys["evaluationKeySetHash"],
        serde_json::json!(
            crate::hashing::derive_canonical_object_hash(&hashable)
                .expect("evaluation key set hash")
        ),
        "the aggregate binding must be bound by the evaluation-key set hash"
    );

    // Every key group carries a full-ring wrap row per digit and one material root
    // per trustee, and each key group's digit count equals its level + 1 (limbs)
    // clamped to the group span.
    let key_groups = aggregate_binding["keyGroups"]
        .as_array()
        .expect("aggregate-binding key groups");
    assert!(
        !key_groups.is_empty(),
        "the aggregate binding must cover at least one runtime key group"
    );
    for key_group in key_groups {
        assert_eq!(
            key_group["objectType"], "EvaluationKeyAggregateBindingKeyGroup",
            "each key group is a key-group record"
        );
        // This terminal fixture uses a reduced development ring, so the record's
        // ring degree is the statement's ring degree (below POLYNOMIAL_DEGREE). The
        // record is self-consistent: its wrap rows span exactly this degree. The
        // verifier requires POLYNOMIAL_DEGREE and would fail-close on this reduced
        // ring, which is the intended full-ring gate.
        let record_ring_degree = key_group["ringDegree"].as_u64().expect("ring degree");
        assert!(
            record_ring_degree > 0,
            "each key group declares a positive ring degree"
        );
        let trustee_roots = key_group["trusteeMaterialRoots"]
            .as_array()
            .expect("trustee material roots");
        assert_eq!(
            trustee_roots.len(),
            participant_count,
            "one material root per trustee"
        );
        for entry in trustee_roots {
            let material_root = entry["materialRoot"].as_str().expect("material root hex");
            assert_eq!(
                material_root.len(),
                64,
                "a material root is a 32-byte Merkle digest in lowercase hex"
            );
            assert!(
                material_root
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "a material root must be lowercase hex"
            );
        }
        // The wrap multiples carry one row per key digit (a key at level L has
        // L + 1 digits), independent of the group's limb span: the aggregate
        // identity binds the full digit set while the residues are restricted to
        // the group's limbs. This matches `verify_material_aggregate`, which
        // requires `wrap_multiples.len() == runtime_key_by_digit.len()`.
        let wrap_multiples = key_group["wrapMultiples"]
            .as_array()
            .expect("wrap multiples");
        let level = key_group["level"].as_u64().expect("level");
        assert_eq!(
            wrap_multiples.len() as u64,
            level + 1,
            "one wrap row per key digit (level + 1)"
        );
        for wrap_row in wrap_multiples {
            assert_eq!(
                wrap_row.as_array().expect("wrap row").len() as u64,
                record_ring_degree,
                "each wrap row spans the record's ring degree"
            );
        }
    }

    // The whole package still passes the evaluation-key phase with the aggregate
    // binding folded in: no refusal references any evaluation-key object.
    let result = verify_collective_bgv_setup_package(&package, &fixture.verification_request)
        .expect("verification response");
    assert_eq!(
        evaluation_key_phase_refused(&result),
        None,
        "the evaluation-key phase must still accept the set with the aggregate binding folded in: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
}

// Replaces the first trustee's retained proof material with a byte-tampered
// proof, then rebuilds every byte-derived reference and package binding. This
// keeps transport authentication valid so the rejection reaches the succinct
// relation verifier instead of stopping at a stale hash or certificate.
fn replace_first_trustee_evaluation_key_proof_with_tampered_material(
    fixture: &mut super::package_fixtures::CollectiveSetupVerificationFixture,
) {
    let original_proof_material_root =
        fixture.package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["proofMaterialRoot"]
            .as_str()
            .expect("trustee proof material root")
            .to_string();
    let retained_proof_material = crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
        crate::bgv::setup::trustee_evaluation_key_proof::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        &original_proof_material_root,
    )
    .expect("trustee proof material lookup")
    .expect("retained trustee proof material");
    let mut proof_bytes = Vec::with_capacity(retained_proof_material.len());
    for chunk in retained_proof_material.chunks() {
        proof_bytes.extend_from_slice(chunk);
    }
    drop(retained_proof_material);
    crate::bgv::setup::evict_verified_canonical_setup_proof_materials(std::slice::from_ref(
        &original_proof_material_root,
    ));

    let tampered_position = proof_bytes.len() / 2;
    proof_bytes[tampered_position] ^= 1;
    let proof_bytes_hash =
        crate::bgv::setup::trustee_evaluation_key_proof::trustee_evaluation_key_proof_bytes_hash(
            &proof_bytes,
        );
    let proof_record = &mut fixture.package["trusteeEvaluationKeyProofs"]["proofRecords"][0];
    proof_record["proofBytesHash"] = serde_json::json!(proof_bytes_hash);
    let proof_material_root = super::proof_record_fixtures::
        trustee_evaluation_key_proof_material_root_from_fixture_record(proof_record);
    proof_record["proofMaterialRoot"] = serde_json::json!(&proof_material_root);

    let transport_hashes = setup_proof_material_transport_hashes(
        crate::bgv::setup::trustee_evaluation_key_proof::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        &proof_bytes,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("tampered trustee proof transport hashes");
    crate::bgv::setup::retain_generated_canonical_proof_material(
        crate::bgv::setup::trustee_evaluation_key_proof::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        proof_material_root.clone(),
        proof_bytes,
    )
    .expect("retain tampered trustee proof material");

    let transported_proof_material = &mut fixture.verification_request["transportedEvaluationKeyShareProofMaterial"]
        ["proofMaterials"][0];
    transported_proof_material["proofMaterialRoot"] = serde_json::json!(proof_material_root);
    transported_proof_material["proofChunkCount"] =
        serde_json::json!(transport_hashes.chunk_hashes.len());
    transported_proof_material["proofTotalByteLength"] =
        serde_json::json!(transport_hashes.total_byte_length);
    transported_proof_material["proofFullObjectHash"] =
        serde_json::json!(transport_hashes.full_object_hash);
    transported_proof_material["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
    transported_proof_material["proofChunkHashes"] =
        serde_json::json!(transport_hashes.chunk_hashes);

    rebind_trustee_evaluation_key_proof_record_root_for_test(&mut fixture.package, 0);
    rebind_trustee_evaluation_key_proof_set_root_for_test(&mut fixture.package);
    replace_setup_proof_material_transport_certificate_objects(
        &mut fixture.package,
        &fixture.verification_request["transportedEvaluationKeyShareProofMaterial"],
        TRUSTEE_EVALUATION_KEY_PROOF_TRANSPORT_CERTIFICATE_FIELDS,
    );
    rebind_collective_setup_package_hash(&mut fixture.package);
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
