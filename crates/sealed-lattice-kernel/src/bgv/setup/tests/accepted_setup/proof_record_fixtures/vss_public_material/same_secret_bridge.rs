use super::*;

struct SameSecretBridgeProofMaterialReference {
    proof_bytes_hash: String,
    proof_material_root: String,
    proof_binding_lease: crate::bgv::setup::CanonicalSetupProofBindingLease,
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
        .map(|(source_trustee_roster_position, source_record)| {
            same_secret_bridge_statement_record(
                package,
                source_record,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
        .expect("setup context hash");
    serde_json::json!({
        "objectType": "VssSameSecretBridgeStatementSet",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": vss_commitment_ring_degree_from_fixture_package(package),
        "participantCount": participant_count_from_package(package),
        "qShareRnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": vss_fixture_threshold_degree(package),
        "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"],
        "vssCoefficientCommitmentRoot": package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"],
        "statementRecords": statement_records,
    })
}

pub(super) fn same_secret_bridge_statement_record(
    package: &serde_json::Value,
    source_coefficient_record: &serde_json::Value,
    source_trustee_roster_position: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let source_trustee_identity = source_coefficient_record["sourceTrusteeIdentity"]
        .as_str()
        .expect("source trustee identity");
    let source_constant_commitments =
        super::super::source_constant_commitments_from_fixture_package(
            package,
            source_trustee_roster_position as u64,
        )
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            serde_json::json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "commitment": crate::bgv::setup::commitment::setup_commitment_full_value(commitment),
            })
        })
        .collect::<Vec<_>>();
    let mut statement_record = serde_json::json!({
        "objectType": "VssSameSecretBridgeStatement",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "ringDegree": vss_commitment_ring_degree_from_fixture_package(package),
        "trusteeIdentity": source_trustee_identity,
        "trusteeRosterPosition": source_trustee_roster_position,
        "sourceConstantCoefficientCommitments": source_constant_commitments,
    });
    statement_record["sameSecretBridgeStatementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement_record).expect("same-secret bridge statement root")
    );

    statement_record
}

pub(in super::super::super) fn same_secret_bridge_proof_material_set_object(
    package: &serde_json::Value,
) -> VssProofMaterialSetFixture {
    let statement_set = &package["sameSecretBridgeStatementSet"];
    let proof_record_fixtures = statement_set["statementRecords"]
        .as_array()
        .expect("same-secret bridge statement records")
        .iter()
        .enumerate()
        .map(|(trustee_roster_position, statement_record)| {
            same_secret_bridge_proof_record(package, statement_record, trustee_roster_position)
        })
        .collect::<Vec<_>>();
    VssProofMaterialSetFixture {
        value: serde_json::json!({
            "objectType": "VssSameSecretBridgeProofMaterialSet",
            "proofRecords": proof_record_fixtures
                .iter()
                .map(|fixture| fixture.record.clone())
                .collect::<Vec<_>>(),
        }),
        proof_binding_leases: proof_record_fixtures
            .into_iter()
            .map(|fixture| fixture.proof_binding_lease)
            .collect(),
    }
}

pub(super) fn same_secret_bridge_proof_record(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    trustee_roster_position: usize,
) -> VssProofRecordFixture {
    let proof_material = same_secret_bridge_proof_material_reference(
        package,
        statement_record,
        trustee_roster_position,
    );
    let mut proof_record = serde_json::json!({
        "objectType": "VssSameSecretBridgeProofRecord",
        "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
        "proofBytesHash": proof_material.proof_bytes_hash,
        "proofMaterialRoot": proof_material.proof_material_root,
    });
    proof_record["sameSecretBridgeProofRecordRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_record).expect("same-secret bridge proof record root")
    );

    VssProofRecordFixture {
        record: proof_record,
        proof_binding_lease: proof_material.proof_binding_lease,
    }
}

fn same_secret_bridge_proof_material_reference(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    trustee_roster_position: usize,
) -> SameSecretBridgeProofMaterialReference {
    let request = same_secret_bridge_proof_generation_request(
        package,
        statement_record,
        trustee_roster_position,
    );
    let checkpoint_key = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssSameSecretBridgeProofCheckpointKey",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "statementRoot": statement_record["sameSecretBridgeStatementRoot"],
        "proverRevision": "full-source-linkage-2",
    }))
    .expect("same-secret bridge checkpoint key");
    let proof_bytes = checkpointed_proof_bytes(
        SAME_SECRET_BRIDGE_PROOF_CHECKPOINT_DIRECTORY,
        &checkpoint_key,
        |proof_bytes| {
            verify_same_secret_bridge_proof_source_from_request(&request, proof_bytes).map(|_| ())
        },
        || {
            let generated = generate_same_secret_bridge_proof_from_request(&request)
                .expect("same-secret bridge proof");
            let proof_material_root = generated["proofMaterialRoot"]
                .as_str()
                .expect("same-secret bridge proof material root");
            let proof_bytes_hash = generated["proofBytesHash"]
                .as_str()
                .expect("same-secret bridge proof bytes hash");
            let proof_material = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
                SAME_SECRET_BRIDGE_PROOF_FAMILY,
                proof_material_root,
            )
            .expect("same-secret bridge generated proof material lookup")
            .expect("same-secret bridge generated proof material");
            assert_eq!(
                proof_material
                    .hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN)
                    .expect("same-secret bridge streamed proof bytes hash"),
                proof_bytes_hash,
                "generated same-secret bridge metadata must bind its retained bytes",
            );
            match std::sync::Arc::try_unwrap(proof_material) {
                Ok(proof_material) => proof_material.into_contiguous(),
                Err(_) => panic!(
                    "generated same-secret bridge proof bytes must have one store owner before checkpoint persistence"
                ),
            }
        },
    );
    let proof_bytes_hash = hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
    let proof_material_root = crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        &proof_bytes_hash,
    )
    .expect("same-secret bridge proof material root");
    let proof_verification_request =
        crate::bgv::setup::same_secret_bridge_proof_verification_request_from_public_records(
            &package["sameSecretBridgeStatementSet"],
            statement_record,
            &package["vssPublicCoefficientCommitmentSet"],
            &package["vssCoefficientCommitments"],
            trustee_roster_position,
        )
        .expect("same-secret bridge proof verification request");
    if crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        &proof_material_root,
    )
    .expect("same-secret bridge proof material lookup")
    .is_none()
    {
        authenticate_setup_proof_material_stream_for_test(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &proof_material_root,
            &proof_bytes,
        )
        .expect("authenticate same-secret bridge proof material stream");
    }
    let proof_binding_session =
        crate::bgv::setup::begin_accepted_setup_fixture_proof_binding_session()
            .expect("begin same-secret bridge proof binding session");
    crate::bgv::setup::verify_and_retain_same_secret_bridge_proof_binding(
        &proof_binding_session,
        &proof_material_root,
        &proof_verification_request,
    )
    .expect("verify same-secret bridge proof before releasing its bytes");
    let proof_binding_lease =
        crate::bgv::setup::finish_accepted_setup_fixture_proof_binding_session(
            proof_binding_session,
            &proof_material_root,
        )
        .expect("retain same-secret bridge verifier-owned binding lease");

    SameSecretBridgeProofMaterialReference {
        proof_bytes_hash,
        proof_material_root,
        proof_binding_lease,
    }
}

pub(super) fn same_secret_bridge_proof_generation_request(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    trustee_roster_position: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let target_records = super::same_secret_bridge_target_constant_records_from_fixture_package(
        package,
        trustee_roster_position as u64,
    );
    let bridge_rns_primes = DATA_PRIMES.to_vec();
    let target_constant_commitment_roots = target_records
        .iter()
        .map(|record| record["coefficientCommitmentRoot"].clone())
        .collect::<Vec<_>>();
    let target_constant_commitments = target_records
        .iter()
        .map(|record| record["commitment"].clone())
        .collect::<Vec<_>>();
    let ring_degree = statement_record["ringDegree"]
        .as_u64()
        .expect("bridge ring degree") as usize;
    // Committed-material regeneration inputs follow the same target-commitment
    // order bound by every terminal proof statement that consumes this bridge.
    let super::SameSecretBridgeCommittedMaterialRegenerationInputs {
        seeds_by_bound_message: bound_material_seeds,
        context_hashes_by_bound_message: bound_material_context_hashes,
    } = super::same_secret_bridge_committed_material_regeneration_inputs_from_fixture_package(
        package,
        trustee_roster_position as u64,
    );
    let secret_coefficients = (0..ring_degree)
        .map(|coefficient_position| {
            accepted_vss_secret_coefficient_fixture(
                trustee_roster_position as u64,
                coefficient_position,
            )
        })
        .collect::<Vec<_>>();
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect::<Vec<_>>();
    let source_constant_commitments = statement_record["sourceConstantCoefficientCommitments"]
        .as_array()
        .expect("bridge source constant commitments")
        .iter()
        .map(|record| record["commitment"].clone())
        .collect::<Vec<_>>();
    let source_opening_randomness_by_limb = DATA_PRIMES
        .iter()
        .enumerate()
        .map(|(source_rns_limb_index, _)| {
            vss_public_coefficient_randomness_i64_fixture(
                trustee_roster_position as u64,
                source_rns_limb_index,
                0,
                ring_degree,
            )
        })
        .collect::<Vec<_>>();
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicMaterialFixtureRandomness",
        "fixture": "same-secret-bridge-proof-randomness",
        "trusteeRosterPosition": trustee_roster_position,
    }))
    .expect("same-secret bridge proof randomness seed");
    let proof_randomness_nonce_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicMaterialFixtureRandomness",
        "fixture": "same-secret-bridge-proof-randomness-nonce",
        "trusteeRosterPosition": trustee_roster_position,
    }))
    .expect("same-secret bridge proof randomness nonce");
    serde_json::json!({
        "context": {
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "trusteeIdentity": statement_record["trusteeIdentity"],
            "trusteeRosterPosition": statement_record["trusteeRosterPosition"],
            "setupEpoch": setup_context["setupEpoch"],
        },
        "ringDegree": ring_degree,
        "sameSecretLinkage": {
            "publicMatrixSeedHash": statement_record["publicMatrixSeedHash"],
            "commitments": source_constant_commitments,
        },
        "sameSecretBridge": {
            "publicMatrixSeedHash": statement_record["publicMatrixSeedHash"],
            "setupParametersHash": statement_record["setupParametersHash"],
            "sourceTrusteeIdentity": statement_record["trusteeIdentity"],
            "sourceTrusteeRosterPosition": statement_record["trusteeRosterPosition"],
            "bridgeRnsPrimes": bridge_rns_primes,
            "targetConstantCommitmentRoots": target_constant_commitment_roots,
            "targetConstantCommitments": target_constant_commitments,
        },
        "secretCoefficients": secret_coefficients,
        "negativeIndicatorCoefficients": negative_indicator_coefficients,
        "openingRandomnessByLimb": source_opening_randomness_by_limb,
        "vssCommittedMaterialSeedsByBoundMessage": bound_material_seeds,
        "vssCommittedMaterialContextHashesByBoundMessage": bound_material_context_hashes,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
    })
}

fn vss_public_coefficient_randomness_i64_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .map(|randomness_column_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    match (source_trustee_roster_position as usize
                        + rns_limb_index
                        + shamir_coefficient_index as usize
                        + randomness_column_index
                        + coefficient_position)
                        % 3
                    {
                        0 => -1,
                        1 => 0,
                        _ => 1,
                    }
                })
                .collect()
        })
        .collect()
}

#[test]
fn vss_public_material_fixture_verifies_generated_fields() {
    let mut finalized_fixture = minimal_collective_setup_package_fixture();
    let proof_material_fixture = super::transport::descriptor_backed_vss_proof_material_fixture(
        &mut finalized_fixture.package,
        &finalized_fixture.proof_binding_leases,
    );
    let package = finalized_fixture.package;

    let proof_binding_session = proof_material_fixture.begin_proof_binding_session();
    crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
        &serde_json::json!({
            "statement": package["vssShareLinkageStatement"],
            "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
            "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
            "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
            "proofMaterialSet": package["vssShareLinkageProofMaterialSet"],
            "transportedVssShareLinkageProofMaterial":
                proof_material_fixture.verification_request["transportedVssShareLinkageProofMaterial"],
        }),
        Some(&proof_binding_session),
    )
    .expect("generated VSS public material verifies");

    // The same-secret bridge proves the canonical full source VSS commitment
    // set and the target-basis committed material share one signed ternary
    // secret. Verify both public bridge objects through the same kernel
    // verifier used by accepted setup.
    let bridge_request = serde_json::json!({
        "statementSet": package["sameSecretBridgeStatementSet"],
        "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
        "vssCoefficientCommitments": package["vssCoefficientCommitments"],
        "proofMaterialSet": package["sameSecretBridgeProofMaterialSet"],
        "transportedSameSecretBridgeProofMaterial":
            proof_material_fixture.verification_request["transportedSameSecretBridgeProofMaterial"],
    });
    crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(&bridge_request)
        .expect("generated same-secret bridge statement set verifies");
    crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
        &bridge_request,
        Some(&proof_binding_session),
    )
    .expect("generated same-secret bridge proof material set verifies");
    crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
        proof_binding_session.session_handle,
    )
    .expect("cancel generated VSS public material proof binding session");
    let mut wrong_source_body_request = bridge_request.clone();
    let source_coefficient = &mut wrong_source_body_request["statementSet"]["statementRecords"][0]
        ["sourceConstantCoefficientCommitments"][0]["commitment"]["commitmentLimbs"][0]["rows"][0]
        [0];
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
    wrong_source_coordinate_request["statementSet"]["statementRecords"][0]["sourceConstantCoefficientCommitments"]
        [0]["rnsLimbIndex"] = serde_json::json!(1);
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
    wrong_source_root_request["vssCoefficientCommitments"]["sourceTrusteeRecords"][0]["coefficientCommitments"]
        [0]["commitmentRoot"] = serde_json::json!("0".repeat(128));
    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &wrong_source_root_request,
            None,
        )
        .is_err(),
        "accepted reconstruction must reject a source root that no longer matches its body"
    );
}
