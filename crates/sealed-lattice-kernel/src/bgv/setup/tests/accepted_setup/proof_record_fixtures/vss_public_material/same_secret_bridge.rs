use super::*;

struct SameSecretBridgeProofMaterialReference {
    proof_bytes_hash: String,
}

pub(in super::super::super) fn same_secret_bridge_statement_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let statement_records = coefficient_set["sourceTrusteeRecords"]
        .as_array()
        .expect("source coefficient records")
        .iter()
        .enumerate()
        .map(|(source_trustee_roster_position, _source_record)| {
            same_secret_bridge_statement_record(package, source_trustee_roster_position)
        })
        .collect::<Vec<_>>();
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
        .expect("setup context hash");
    serde_json::json!({
        "objectType": "VssSameSecretBridgeStatementSet",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": vss_commitment_ring_degree_from_fixture_package(package),
        "statementRecords": statement_records,
    })
}

pub(super) fn same_secret_bridge_statement_record(
    package: &serde_json::Value,
    source_trustee_roster_position: usize,
) -> serde_json::Value {
    let source_constant_commitments =
        super::super::source_constant_commitments_from_fixture_package(
            package,
            source_trustee_roster_position as u64,
        )
        .iter()
        .map(crate::bgv::setup::commitment::setup_commitment_full_value)
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "VssSameSecretBridgeStatement",
        "sourceConstantCoefficientCommitments": source_constant_commitments,
    })
}

pub(in super::super::super) fn same_secret_bridge_proof_material_set_object(
    package: &serde_json::Value,
) -> VssProofMaterialSetFixture {
    let statement_set = &package["sameSecretBridgeStatementSet"];
    let proof_material_references = statement_set["statementRecords"]
        .as_array()
        .expect("same-secret bridge statement records")
        .iter()
        .enumerate()
        .map(|(trustee_roster_position, statement_record)| {
            same_secret_bridge_proof_material_reference(
                package,
                statement_record,
                trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    VssProofMaterialSetFixture {
        value: serde_json::json!({
            "objectType": "VssSameSecretBridgeProofMaterialSet",
            "proofBytesHashes": proof_material_references
                .iter()
                .map(|reference| reference.proof_bytes_hash.clone())
                .collect::<Vec<_>>(),
        }),
        proof_binding_leases: Vec::new(),
    }
}

fn same_secret_bridge_proof_material_reference(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    trustee_roster_position: usize,
) -> SameSecretBridgeProofMaterialReference {
    let proof_verification_request =
        crate::bgv::setup::same_secret_bridge_proof_verification_request_from_public_records(
            &package["sameSecretBridgeStatementSet"],
            statement_record,
            &package["vssPublicCoefficientCommitmentSet"],
            &package["vssCoefficientCommitments"],
            trustee_roster_position,
        )
        .expect("same-secret bridge proof verification request");
    let proof_bytes_hash = invalid_common_proof_fixture_hash(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
        &proof_verification_request,
    );

    SameSecretBridgeProofMaterialReference { proof_bytes_hash }
}

#[test]
fn vss_public_material_preserves_structure_and_requires_common_proofs() {
    let finalized_fixture = structural_vss_public_material_fixture();
    let package = finalized_fixture.package;
    let trustee_identities = (0..participant_count_from_package(&package))
        .map(|roster_position| format!("trustee-{roster_position}"))
        .collect::<Vec<_>>();
    let share_linkage_request = serde_json::json!({
        "statement": package["vssShareLinkageStatement"],
        "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
        "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
        "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
        "proofMaterialSet": package["vssShareLinkageProofMaterialSet"],
    });
    crate::bgv::setup::vss_commitment::verify_vss_share_linkage_bindings_request(
        &share_linkage_request,
        &trustee_identities,
    )
    .expect("VSS public material structural bindings verify");

    let bridge_request = serde_json::json!({
        "statementSet": package["sameSecretBridgeStatementSet"],
        "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
        "vssCoefficientCommitments": package["vssCoefficientCommitments"],
        "proofMaterialSet": package["sameSecretBridgeProofMaterialSet"],
    });
    crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(&bridge_request)
        .expect("same-secret bridge structural bindings verify");

    let first_statement_record = &package["sameSecretBridgeStatementSet"]["statementRecords"][0];
    let first_proof_verification_request =
        crate::bgv::setup::same_secret_bridge_proof_verification_request_from_public_records(
            &package["sameSecretBridgeStatementSet"],
            first_statement_record,
            &package["vssPublicCoefficientCommitmentSet"],
            &package["vssCoefficientCommitments"],
            0,
        )
        .expect("first same-secret bridge verification request");
    let invalid_proof_bytes = invalid_common_proof_fixture_bytes(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        &first_proof_verification_request,
    );
    let first_proof_bytes_hash = hash512_hex(
        SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
        &[&invalid_proof_bytes],
    );
    assert_eq!(
        package["sameSecretBridgeProofMaterialSet"]["proofBytesHashes"][0], first_proof_bytes_hash,
        "fixture proof reference must bind the authenticated invalid proof bytes",
    );
    authenticate_setup_proof_material_stream_for_test(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        &first_proof_bytes_hash,
        &invalid_proof_bytes,
    )
    .expect("authenticate invalid same-secret bridge proof bytes");
    let common_proof_gate_error =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &bridge_request,
            None,
        )
        .expect_err("authenticated non-proof bytes must not satisfy same-secret acceptance");
    assert_eq!(
        common_proof_gate_error.code,
        crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
    );
    assert_eq!(
        common_proof_gate_error.message,
        "same-secret bridge acceptance requires verification by the common proof suite",
    );

    let mut wrong_source_body_request = bridge_request.clone();
    let source_coefficient = &mut wrong_source_body_request["statementSet"]["statementRecords"][0]
        ["sourceConstantCoefficientCommitments"][0]["commitmentLimbs"][0]["rows"][0][0];
    let original_source_coefficient = source_coefficient
        .as_u64()
        .expect("source commitment coefficient");
    *source_coefficient = serde_json::json!(
        (original_source_coefficient + 1) % crate::bgv::parameters::DATA_PRIMES[0]
    );
    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &wrong_source_body_request,
            None,
        )
        .is_err(),
        "accepted reconstruction must recompute and reject a wrong source commitment body"
    );

    let mut wrong_source_coordinate_request = bridge_request.clone();
    wrong_source_coordinate_request["statementSet"]["statementRecords"][0]
        ["sourceConstantCoefficientCommitments"][0]["sourceRnsLimbIndex"] = serde_json::json!(1);
    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(
            &wrong_source_coordinate_request,
        )
        .is_err(),
        "accepted reconstruction must reject a source body under the wrong limb coordinate"
    );

    let mut reordered_source_request = bridge_request.clone();
    reordered_source_request["statementSet"]["statementRecords"][0]
        ["sourceConstantCoefficientCommitments"]
        .as_array_mut()
        .expect("source commitment carriers")
        .swap(0, 1);
    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(
            &reordered_source_request,
        )
        .is_err(),
        "accepted reconstruction must reject reordered source commitment carriers"
    );

    let mut wrong_source_root_request = bridge_request;
    wrong_source_root_request["vssCoefficientCommitments"]["sourceTrusteeRecords"][0]
        ["coefficientCommitmentRoots"][0] = serde_json::json!("0".repeat(128));
    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &wrong_source_root_request,
            None,
        )
        .is_err(),
        "accepted reconstruction must reject a source root that no longer matches its body"
    );
}
