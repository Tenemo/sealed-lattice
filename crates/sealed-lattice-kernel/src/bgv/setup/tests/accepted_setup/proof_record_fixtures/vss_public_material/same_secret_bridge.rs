use super::*;

pub(in super::super::super) fn same_secret_bridge_statement_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let target_basis_hash =
        crate::bgv::evaluator::top_k::canonical_target_basis_hash().expect("target basis hash");
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
                &target_basis_hash,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut statement_set = serde_json::json!({
        "objectType": "VssSameSecretBridgeStatementSet",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": coefficient_set["ringDegree"],
        "participantCount": coefficient_set["participantCount"],
        "targetRnsLimbCount": coefficient_set["rnsLimbCount"],
        "thresholdDegree": coefficient_set["thresholdDegree"],
        "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"],
        "vssCoefficientCommitmentRoot": package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"],
        "integerSupport": SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "statementRecords": statement_records,
    });
    statement_set["sameSecretBridgeStatementSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement_set)
            .expect("same-secret bridge statement set root")
    );

    statement_set
}

pub(super) fn same_secret_bridge_statement_record(
    package: &serde_json::Value,
    source_coefficient_record: &serde_json::Value,
    target_basis_hash: &str,
    source_trustee_roster_position: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let source_trustee_identity = source_coefficient_record["sourceTrusteeIdentity"]
        .as_str()
        .expect("source trustee identity");
    let coefficient_commitments = source_coefficient_record["coefficientCommitments"]
        .as_array()
        .expect("coefficient commitments");
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree") as usize;
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
                "shamirCoefficientIndex": 0,
                "commitment": crate::bgv::setup::commitment::setup_commitment_full_value(commitment),
            })
        })
        .collect::<Vec<_>>();
    let target_constant_records = (0..DATA_PRIMES.len())
        .map(|rns_limb_index| {
            let coefficient_record_index = rns_limb_index
                .checked_mul(threshold_degree)
                .expect("coefficient record index");
            let coefficient_record = &coefficient_commitments[coefficient_record_index];
            (
                serde_json::json!({
                    "rnsLimbIndex": coefficient_record["rnsLimbIndex"],
                    "rnsPrime": coefficient_record["rnsPrime"],
                    "shamirCoefficientIndex": coefficient_record["shamirCoefficientIndex"],
                    "coefficientCommitmentRoot": coefficient_record["coefficientCommitmentRoot"],
                }),
                serde_json::json!({
                    "rnsLimbIndex": coefficient_record["rnsLimbIndex"],
                    "rnsPrime": coefficient_record["rnsPrime"],
                    "shamirCoefficientIndex": coefficient_record["shamirCoefficientIndex"],
                    "commitment": coefficient_record["commitment"],
                }),
            )
        })
        .collect::<Vec<_>>();
    let (target_constant_roots, target_constant_commitments): (Vec<_>, Vec<_>) =
        target_constant_records.into_iter().unzip();
    let mut statement_record = serde_json::json!({
        "objectType": "VssSameSecretBridgeStatement",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "ringDegree": package["vssPublicCoefficientCommitmentSet"]["ringDegree"],
        "trusteeIdentity": source_trustee_identity,
        "trusteeRosterPosition": source_trustee_roster_position,
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "sourceConstantCoefficientCommitments": source_constant_commitments,
        "targetConstantCoefficientCommitmentRoots": target_constant_roots,
        "targetConstantCoefficientCommitments": target_constant_commitments,
        "relation": SAME_SECRET_BRIDGE_RELATION,
    });
    statement_record["sameSecretBridgeStatementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement_record).expect("same-secret bridge statement root")
    );

    statement_record
}

pub(in super::super::super) fn same_secret_bridge_proof_material_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let statement_set = &package["sameSecretBridgeStatementSet"];
    let proof_records = statement_set["statementRecords"]
        .as_array()
        .expect("same-secret bridge statement records")
        .iter()
        .enumerate()
        .map(|(trustee_roster_position, statement_record)| {
            same_secret_bridge_proof_record(package, statement_record, trustee_roster_position)
        })
        .collect::<Vec<_>>();
    let mut proof_material_set = serde_json::json!({
        "objectType": "VssSameSecretBridgeProofMaterialSet",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": statement_set["ceremonyId"],
        "manifestHash": statement_set["manifestHash"],
        "rosterHash": statement_set["rosterHash"],
        "setupParametersHash": statement_set["setupParametersHash"],
        "setupEpoch": statement_set["setupEpoch"],
        "targetBasisHash": statement_set["targetBasisHash"],
        "publicMatrixSeedHash": statement_set["publicMatrixSeedHash"],
        "ringDegree": statement_set["ringDegree"],
        "participantCount": statement_set["participantCount"],
        "targetRnsLimbCount": statement_set["targetRnsLimbCount"],
        "thresholdDegree": statement_set["thresholdDegree"],
        "coefficientCommitmentRoot": statement_set["coefficientCommitmentRoot"],
        "vssCoefficientCommitmentRoot": statement_set["vssCoefficientCommitmentRoot"],
        "sameSecretBridgeStatementSetRoot": statement_set["sameSecretBridgeStatementSetRoot"],
        "proofRecords": proof_records,
    });
    proof_material_set["proofMaterialSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_material_set)
            .expect("same-secret bridge proof material set root")
    );

    proof_material_set
}

pub(super) fn same_secret_bridge_proof_record(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    trustee_roster_position: usize,
) -> serde_json::Value {
    let proof_bytes_hex =
        same_secret_bridge_proof_bytes_hex(package, statement_record, trustee_roster_position);
    let proof_bytes = crate::transcript_core::decode_hex(&proof_bytes_hex)
        .expect("same-secret bridge proof bytes");
    let mut proof_record = serde_json::json!({
        "objectType": "VssSameSecretBridgeProofRecord",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
        "proofBytesHash": hash512_hex(
            SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        ),
        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
    });
    proof_record["sameSecretBridgeProofRecordRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_record).expect("same-secret bridge proof record root")
    );

    proof_record
}

pub(super) fn same_secret_bridge_proof_bytes_hex(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    trustee_roster_position: usize,
) -> String {
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
            let proof_material = crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
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
            proof_material
                .chunks()
                .flat_map(|chunk| chunk.iter().copied())
                .collect()
        },
    );

    to_hex(&proof_bytes)
}

pub(super) fn same_secret_bridge_proof_generation_request(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    trustee_roster_position: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let target_roots = statement_record["targetConstantCoefficientCommitmentRoots"]
        .as_array()
        .expect("bridge target roots");
    let target_commitments = statement_record["targetConstantCoefficientCommitments"]
        .as_array()
        .expect("bridge target commitments");
    let target_rns_primes = target_roots
        .iter()
        .map(|root_record| root_record["rnsPrime"].clone())
        .collect::<Vec<_>>();
    let target_constant_commitment_roots = target_roots
        .iter()
        .map(|root_record| root_record["coefficientCommitmentRoot"].clone())
        .collect::<Vec<_>>();
    let target_constant_commitments = target_commitments
        .iter()
        .map(|commitment_record| commitment_record["commitment"].clone())
        .collect::<Vec<_>>();
    let ring_degree = statement_record["ringDegree"]
        .as_u64()
        .expect("bridge ring degree") as usize;
    // Committed-material regeneration inputs follow the same target-commitment
    // order bound by every terminal proof statement that consumes this bridge.
    let super::SameSecretBridgeCommittedMaterialRegenerationInputs {
        seeds_by_bound_message: bound_material_seeds,
        context_hashes_by_bound_message: bound_material_context_hashes,
    } = super::same_secret_bridge_committed_material_regeneration_inputs_from_statement_record(
        statement_record,
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
            "sourceTrusteeIdentity": statement_record["trusteeIdentity"],
            "sourceTrusteeRosterPosition": statement_record["trusteeRosterPosition"],
            "targetBasisHash": statement_record["targetBasisHash"],
            "targetRnsPrimes": target_rns_primes,
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

fn rebind_same_secret_bridge_object_root(object: &mut serde_json::Value, root_field_name: &str) {
    object
        .as_object_mut()
        .expect("same-secret bridge object")
        .remove(root_field_name);
    let rebound_root =
        derive_canonical_object_hash(object).expect("rebound same-secret bridge object root");
    object[root_field_name] = serde_json::json!(rebound_root);
}

#[test]
fn vss_public_material_fixture_verifies_generated_fields() {
    let mut package = minimal_collective_setup_package();
    let proof_material_fixture =
        super::transport::descriptor_backed_vss_proof_material_fixture(&mut package);
    let _proof_material_eviction_guard =
        crate::bgv::setup::setup_proof::VerifiedSetupProofMaterialEvictionGuard::for_request(
            &proof_material_fixture.verification_request,
        );

    let verification = crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
        &serde_json::json!({
            "statement": package["vssShareLinkageStatement"],
            "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
            "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
            "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
            "proofMaterialSet": package["vssShareLinkageProofMaterialSet"],
            "transportedVssShareLinkageProofMaterial":
                proof_material_fixture.verification_request["transportedVssShareLinkageProofMaterial"],
        }),
    )
    .expect("generated VSS public material verifies");

    assert_eq!(
        verification["proofMaterialSetRoot"],
        package["vssShareLinkageProofMaterialSet"]["proofMaterialSetRoot"],
        "generated VSS verification must recompute the proof material set root"
    );

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
    let bridge_statement_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(&bridge_request)
            .expect("generated same-secret bridge statement set verifies");
    assert_eq!(
        bridge_statement_verification["sameSecretBridgeStatementSetRoot"],
        package["sameSecretBridgeStatementSet"]["sameSecretBridgeStatementSetRoot"],
        "generated bridge statement verification must recompute the statement set root"
    );
    let bridge_proof_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &bridge_request,
        )
        .expect("generated same-secret bridge proof material set verifies");
    assert_eq!(
        bridge_proof_verification["proofMaterialSetRoot"],
        package["sameSecretBridgeProofMaterialSet"]["proofMaterialSetRoot"],
        "generated bridge proof verification must recompute the proof material set root"
    );

    // Replacing a target body and all of its dependent roots creates a
    // self-consistent alternate bridge package. It must still refuse while
    // the authoritative public coefficient set remains unchanged.
    let mut alternate_target_request = bridge_request.clone();
    let alternate_target_body = &mut alternate_target_request["statementSet"]["statementRecords"]
        [0]["targetConstantCoefficientCommitments"][0]["commitment"];
    let original_material_root = alternate_target_body["commitmentFields"][0]["materialRootHex"]
        .as_str()
        .expect("target commitment material root");
    let alternate_material_root = if original_material_root == "0".repeat(64) {
        "f".repeat(64)
    } else {
        "0".repeat(64)
    };
    alternate_target_body["commitmentFields"][0]["materialRootHex"] =
        serde_json::json!(alternate_material_root);
    let alternate_target_root = derive_canonical_object_hash(alternate_target_body)
        .expect("alternate target commitment root");
    alternate_target_request["statementSet"]["statementRecords"][0]["targetConstantCoefficientCommitmentRoots"]
        [0]["coefficientCommitmentRoot"] = serde_json::json!(alternate_target_root);
    rebind_same_secret_bridge_object_root(
        &mut alternate_target_request["statementSet"]["statementRecords"][0],
        "sameSecretBridgeStatementRoot",
    );
    let alternate_statement_root = alternate_target_request["statementSet"]["statementRecords"][0]
        ["sameSecretBridgeStatementRoot"]
        .clone();
    rebind_same_secret_bridge_object_root(
        &mut alternate_target_request["statementSet"],
        "sameSecretBridgeStatementSetRoot",
    );
    let alternate_statement_set_root =
        alternate_target_request["statementSet"]["sameSecretBridgeStatementSetRoot"].clone();
    alternate_target_request["proofMaterialSet"]["sameSecretBridgeStatementSetRoot"] =
        alternate_statement_set_root;
    alternate_target_request["proofMaterialSet"]["proofRecords"][0]["sameSecretBridgeStatementRoot"] =
        alternate_statement_root;
    rebind_same_secret_bridge_object_root(
        &mut alternate_target_request["proofMaterialSet"]["proofRecords"][0],
        "sameSecretBridgeProofRecordRoot",
    );
    rebind_same_secret_bridge_object_root(
        &mut alternate_target_request["proofMaterialSet"],
        "proofMaterialSetRoot",
    );

    let alternate_statement_error =
        crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(
            &alternate_target_request,
        )
        .expect_err("alternate target statement must not replace the authoritative commitment");
    assert_eq!(
        alternate_statement_error.code,
        CanonicalErrorCode::ComponentMismatch
    );
    assert!(alternate_statement_error.message.contains("authoritative"));
    let alternate_proof_error =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &alternate_target_request,
        )
        .expect_err("alternate target proof package must not replace the authoritative commitment");
    assert_eq!(
        alternate_proof_error.code,
        CanonicalErrorCode::ComponentMismatch
    );
    assert!(alternate_proof_error.message.contains("authoritative"));

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
        )
        .is_err(),
        "accepted reconstruction must reject a source root that no longer matches its body"
    );
}
