use super::*;
use super::commitment_sets::*;
use super::share_linkage::*;

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
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
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
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
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
    let same_secret_statement =
        &package["sameSecretConsistency"]["statementRecords"][source_trustee_roster_position];
    let same_secret_proof =
        &package["sameSecretProofs"]["proofRecords"][source_trustee_roster_position];
    let coefficient_commitments = source_coefficient_record["coefficientCommitments"]
        .as_array()
        .expect("coefficient commitments");
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree") as usize;
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
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
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
        "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
        "sameSecretProofRoot": same_secret_proof["sameSecretProofRoot"],
        "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
        "sameSecretProofFamilyBindingRoot": same_secret_statement["sameSecretProofFamilyBindingRoot"],
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
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
    transported_same_secret_proof_material: Option<&serde_json::Value>,
) -> serde_json::Value {
    let statement_set = &package["sameSecretBridgeStatementSet"];
    let proof_records = statement_set["statementRecords"]
        .as_array()
        .expect("same-secret bridge statement records")
        .iter()
        .enumerate()
        .map(|(trustee_roster_position, statement_record)| {
            same_secret_bridge_proof_record(
                package,
                statement_record,
                transported_same_secret_proof_material,
                trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut proof_material_set = serde_json::json!({
        "objectType": "VssSameSecretBridgeProofMaterialSet",
        "objectVersion": 1,
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
        "sameSecretConsistencyRoot": statement_set["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": statement_set["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": statement_set["sameSecretProofFamilyBindingRoot"],
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
    transported_same_secret_proof_material: Option<&serde_json::Value>,
    trustee_roster_position: usize,
) -> serde_json::Value {
    let proof_bytes_hex = same_secret_bridge_proof_bytes_hex(
        package,
        statement_record,
        transported_same_secret_proof_material,
        trustee_roster_position,
    );
    let proof_bytes = crate::transcript_core::decode_hex(&proof_bytes_hex)
        .expect("same-secret bridge proof bytes");
    let mut proof_record = serde_json::json!({
        "objectType": "VssSameSecretBridgeProofRecord",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
        "proofBytesHash": hash512_hex(
            SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        ),
        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
    });
    proof_record["proofRecordRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_record).expect("same-secret bridge proof record root")
    );

    proof_record
}

pub(super) fn same_secret_bridge_proof_bytes_hex(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
    trustee_roster_position: usize,
) -> String {
    let request = same_secret_bridge_proof_generation_request(
        package,
        statement_record,
        transported_same_secret_proof_material,
        trustee_roster_position,
    );
    let checkpoint_key = statement_record["sameSecretBridgeStatementRoot"]
        .as_str()
        .expect("same-secret bridge statement root");
    let proof_bytes = checkpointed_anchor_proof_bytes(
        SAME_SECRET_BRIDGE_PROOF_CHECKPOINT_DIRECTORY,
        checkpoint_key,
        || {
            let generated = generate_same_secret_bridge_proof_from_request(&request)
                .expect("same-secret bridge proof");
            crate::transcript_core::decode_hex(
                generated["proofBytesHex"]
                    .as_str()
                    .expect("same-secret bridge proof bytes hex"),
            )
            .expect("same-secret bridge proof bytes")
        },
    );

    to_hex(&proof_bytes)
}

pub(super) fn same_secret_bridge_proof_generation_request(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
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
    let opening_randomness_by_limb = (0..target_roots.len())
        .map(|rns_limb_index| {
            vss_public_coefficient_randomness_i64_fixture(
                trustee_roster_position as u64,
                rns_limb_index,
                0,
                ring_degree,
            )
        })
        .collect::<Vec<_>>();
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
    let mut request = serde_json::json!({
        "context": {
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "trusteeIdentity": statement_record["trusteeIdentity"],
            "trusteeRosterPosition": statement_record["trusteeRosterPosition"],
            "setupEpoch": setup_context["setupEpoch"],
            "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "sameSecretProofRoot": statement_record["sameSecretProofRoot"],
            "sameSecretProofFamilyBindingRoot": statement_record["sameSecretProofFamilyBindingRoot"],
        },
        "ringDegree": ring_degree,
        "sameSecretBridge": {
            "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "sameSecretProofRoot": statement_record["sameSecretProofRoot"],
            "sameSecretProofFamilyBindingRoot": statement_record["sameSecretProofFamilyBindingRoot"],
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
        "openingRandomnessByLimb": opening_randomness_by_limb,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
    });
    if let Some(transported_material) = transported_same_secret_proof_material {
        request["transportedSameSecretProofMaterial"] = transported_material.clone();
    }

    request
}

pub(in super::super::super) fn vss_public_coefficient_randomness_i64_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
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
pub(super) fn vss_public_material_fixture_verifies_generated_fields() {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["vssShareLinkageStatement"] = vss_share_linkage_statement_object(&package);
    package["vssShareLinkageProofMaterialSet"] =
        vss_share_linkage_proof_material_set_object(&package);

    let verification = crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
        &serde_json::json!({
            "statement": package["vssShareLinkageStatement"],
            "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
            "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
            "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
            "proofMaterialSet": package["vssShareLinkageProofMaterialSet"],
        }),
    )
    .expect("generated VSS public material verifies");

    assert_eq!(verification["ok"], serde_json::json!(true));
    assert_eq!(
        verification["proofRecordCount"],
        serde_json::json!(3 * DATA_PRIMES.len())
    );
    assert_eq!(
        verification["coveredLinkageItemCount"],
        serde_json::json!(3 * 3 * DATA_PRIMES.len())
    );
    assert!(
        verification["proofMaterialSetRoot"].is_string(),
        "generated VSS proof material set must bind a root"
    );

    // The same-secret bridge links the generated coefficient
    // commitments to the accepted same-secret proof over the target key-switch
    // basis. Generate it and verify both the statement set and the bridge proof
    // material set through the kernel commands, so the generator's bridge objects
    // are exercised against the same verifier the accepted-setup path uses. The
    // minimal package carries the same-secret consistency statements but not the
    // proof set the bridge references, so add the same-secret proofs first.
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    package["sameSecretBridgeStatementSet"] = same_secret_bridge_statement_set_object(&package);
    package["sameSecretBridgeProofMaterialSet"] =
        same_secret_bridge_proof_material_set_object(&package, None);
    let bridge_request = serde_json::json!({
        "statementSet": package["sameSecretBridgeStatementSet"],
        "sameSecretConsistency": package["sameSecretConsistency"],
        "sameSecretProofs": package["sameSecretProofs"],
        "proofMaterialSet": package["sameSecretBridgeProofMaterialSet"],
    });
    let bridge_statement_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(&bridge_request)
            .expect("generated same-secret bridge statement set verifies");
    assert_eq!(bridge_statement_verification["ok"], serde_json::json!(true));
    let bridge_proof_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &bridge_request,
        )
        .expect("generated same-secret bridge proof material set verifies");
    assert_eq!(bridge_proof_verification["ok"], serde_json::json!(true));
}

