use super::*;

#[test]
fn private_vss_share_envelope_verifier_accepts_all_q_share_limb_openings() {
    let request = private_vss_share_envelope_request(8);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], true);
    assert_eq!(result["operation"], "verifyPrivateVssShareEnvelope");
    assert_eq!(result["verifierStatus"], "accepted");
    assert_eq!(result["ringDegree"], 8);
    assert_eq!(result["ringDegreeStatus"], "development-reduced-ring");
    assert_eq!(
        result["verifiedRnsLimbCount"],
        serde_json::json!(DATA_PRIMES.len())
    );
    assert_eq!(
        result["verifiedShamirCoefficientCommitmentCount"],
        serde_json::json!(DATA_PRIMES.len() * 4)
    );
    assert_eq!(
        result["verifiedAggregateOpeningCount"],
        serde_json::json!(DATA_PRIMES.len())
    );
    assert_eq!(
        result["limbVerifications"]
            .as_array()
            .expect("limb verifications")
            .len(),
        DATA_PRIMES.len()
    );
    assert!(
        result["privateEnvelopeHash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
    assert!(
        result["localVerificationRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_tampered_share_values() {
    let mut request = private_vss_share_envelope_request(8);
    request["privateEnvelope"]["rnsShareOpenings"][0]["shareValues"][0] =
        serde_json::json!(DATA_PRIMES[0] - 1);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeInvalidOpening"
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_tampered_aggregate_opening() {
    let mut request = private_vss_share_envelope_request(8);
    request["privateEnvelope"]["rnsShareOpenings"][0]["aggregateOpening"]["openingColumns"][0][0] =
        serde_json::json!(9);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeInvalidOpening"
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_leaked_coefficient_messages() {
    let mut request = private_vss_share_envelope_request(8);
    request["privateEnvelope"]["rnsShareOpenings"][0]["coefficientMessage"] =
        serde_json::json!([1, 2, 3]);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeLeaksCoefficientOpening"
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_leaked_per_coefficient_openings() {
    let mut request = private_vss_share_envelope_request(8);
    request["privateEnvelope"]["rnsShareOpenings"][0]["coefficientOpenings"] = serde_json::json!([{
        "objectType": "PrivateVssCoefficientOpening",
        "objectVersion": 1,
        "shamirCoefficientIndex": 0,
        "commitmentRoot": request["privateEnvelope"]["rnsShareOpenings"][0]
            ["coefficientCommitmentRoots"][0],
        "randomnessByColumn": [[0, 0, 0]],
    }]);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeLeaksCoefficientOpening"
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_raw_shamir_coefficients() {
    let mut request = private_vss_share_envelope_request(8);
    request["privateEnvelope"]["rawShamirCoefficientValues"] = serde_json::json!([1, 2, 3]);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeLeaksCoefficientOpening"
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_explicit_constant_coefficient_leak() {
    let mut request = private_vss_share_envelope_request(8);
    request["privateEnvelope"]["F_i,l,0"] = serde_json::json!([1, 2, 3]);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeLeaksCoefficientOpening"
    );
}

fn private_vss_share_envelope_request(ring_degree: usize) -> serde_json::Value {
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let ceremony_id = "ceremony-main";
    let manifest_hash = derive_protocol_hash(
        "ElectionManifestHash",
        &serde_json::json!({ "manifest": "private-vss-envelope-test" }),
    )
    .expect("manifest hash");
    let roster_hash = derive_protocol_hash(
        "RosterHash",
        &serde_json::json!({ "roster": "private-vss-envelope-test" }),
    )
    .expect("roster hash");
    let setup_profile_hash = profile["setupProfileHash"]
        .as_str()
        .expect("setup profile hash");
    let q_share_hash = profile["qShareHash"].as_str().expect("Q_share hash");
    let carry_aware_vss_relation_profile_hash = profile["carryAwareVssShareRelationProfileHash"]
        .as_str()
        .expect("carry-aware VSS relation profile hash");
    let commitment_profile_hash = profile["commitmentProfileHash"]
        .as_str()
        .expect("commitment profile hash");
    let setup_epoch = "setup-epoch-1";
    let setup_context = serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
    });
    let public_matrix_seed_hash = derive_protocol_hash(
        "SetupPublicMatrixSeedHash",
        &serde_json::json!({
            "fixture": "private-vss-envelope-test-public-matrix",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "setupEpoch": setup_epoch,
        }),
    )
    .expect("public matrix seed hash");
    let private_envelope_aad_hash = derive_protocol_hash(
        "PrivateVssEnvelopeAadHash",
        &serde_json::json!({
            "fixture": "private-vss-envelope-aad",
            "recipientRosterPosition": 2,
        }),
    )
    .expect("private VSS envelope AAD hash");

    let mut dealer_coefficient_commitments = Vec::new();
    let mut dealer_coefficient_commitment_material_records = Vec::new();
    let mut rns_share_openings = Vec::new();
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let mut coefficient_openings = Vec::new();
        let mut coefficient_messages_by_shamir_index = Vec::new();
        let mut coefficient_commitment_roots = Vec::new();
        for shamir_coefficient_index in 0..4_u64 {
            let coefficient_message = coefficient_message_fixture(
                rns_limb_index,
                shamir_coefficient_index,
                rns_prime,
                ring_degree,
            );
            let randomness_by_column =
                randomness_fixture(rns_limb_index, shamir_coefficient_index, ring_degree);
            let coefficient_message_wide = coefficient_message
                .iter()
                .map(|coefficient| u128::from(*coefficient))
                .collect::<Vec<_>>();
            let commitment = compute_setup_commitment_for_tests(
                &public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                shamir_coefficient_index,
                &coefficient_message_wide,
                &randomness_by_column,
                ring_degree,
            )
            .expect("setup commitment");
            let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
            coefficient_commitment_roots.push(commitment_root.clone());
            dealer_coefficient_commitments.push(serde_json::json!({
                "objectType": "VssCoefficientCommitment",
                "objectVersion": 1,
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "rosterHash": roster_hash,
                "setupProfileHash": setup_profile_hash,
                "qShareHash": q_share_hash,
                "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                "commitmentProfileHash": commitment_profile_hash,
                "setupEpoch": setup_epoch,
                "dealerIdentity": "trustee-0",
                "dealerRosterPosition": 0,
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": commitment_root.clone(),
                "commitmentChunkRoot": derive_protocol_hash(
                    "VssCoefficientCommitmentRoot",
                    &serde_json::json!({
                        "fixture": "private-vss-commitment-chunk",
                        "rnsLimbIndex": rns_limb_index,
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                ).expect("commitment chunk root"),
                "coefficientVectorHash512": derive_protocol_hash(
                    "VssCoefficientCommitmentRoot",
                    &serde_json::json!({
                        "fixture": "private-vss-coefficient-vector",
                        "rnsLimbIndex": rns_limb_index,
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                ).expect("coefficient vector hash"),
                "openingVerificationStatus": "pending-private-envelope-opening",
            }));
            dealer_coefficient_commitment_material_records.push(serde_json::json!({
                "objectType": "VssCoefficientCommitmentMaterial",
                "objectVersion": 1,
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "rosterHash": roster_hash,
                "setupProfileHash": setup_profile_hash,
                "qShareHash": q_share_hash,
                "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                "commitmentProfileHash": commitment_profile_hash,
                "setupEpoch": setup_epoch,
                "dealerIdentity": "trustee-0",
                "dealerRosterPosition": 0,
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": commitment_root.clone(),
                "commitment": setup_commitment_full_value(&commitment),
            }));
            coefficient_openings.push(serde_json::json!({
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": coefficient_commitment_roots
                    .last()
                    .expect("coefficient commitment root"),
                "randomnessByColumn": randomness_by_column,
            }));
            coefficient_messages_by_shamir_index.push(coefficient_message);
        }
        let (share_values, carry_witnesses_decimal) = share_values_and_carries(
            &coefficient_messages_by_shamir_index,
            2,
            rns_prime,
            ring_degree,
        );
        let aggregate_opening_columns =
            aggregate_opening_columns(&coefficient_openings, 2, ring_degree);
        rns_share_openings.push(serde_json::json!({
            "objectType": "PrivateVssShareLimbOpening",
            "objectVersion": 1,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shareValues": share_values,
            "carryWitnessesDecimal": carry_witnesses_decimal,
            "coefficientCommitmentRoots": coefficient_commitment_roots,
            "aggregateOpening": {
                "objectType": "PrivateVssAggregateOpening",
                "objectVersion": 1,
                "openingColumns": aggregate_opening_columns,
            },
        }));
    }

    let mut dealer_record = serde_json::json!({
        "objectType": "VssDealerCoefficientCommitments",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "dealerIdentity": "trustee-0",
        "dealerRosterPosition": 0,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "coefficientCommitments": dealer_coefficient_commitments,
    });
    dealer_record["dealerCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("VssCoefficientCommitmentRoot", &dealer_record)
            .expect("dealer commitment root")
    );

    let private_envelope = serde_json::json!({
        "objectType": "PrivateVssShareEnvelope",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeAadHash": private_envelope_aad_hash,
        "dealerIdentity": "trustee-0",
        "dealerRosterPosition": 0,
        "recipientIdentity": "trustee-2",
        "recipientRosterPosition": 2,
        "dealerCommitmentRoot": dealer_record["dealerCommitmentRoot"],
        "rnsShareOpenings": rns_share_openings,
    });

    serde_json::json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "dealerCoefficientCommitmentRecord": dealer_record,
        "dealerCoefficientCommitmentMaterialRecords": dealer_coefficient_commitment_material_records,
        "privateEnvelope": private_envelope,
    })
}

fn coefficient_message_fixture(
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    rns_prime: u64,
    ring_degree: usize,
) -> Vec<u64> {
    (0..ring_degree)
        .map(|coefficient_position| {
            let value = ((rns_limb_index as u64 + 1) * (shamir_coefficient_index + 2))
                + (coefficient_position as u64 % 7);
            value % rns_prime
        })
        .collect()
}

fn randomness_fixture(
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i128>> {
    (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .map(|randomness_column_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    match (rns_limb_index
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

fn share_values_and_carries(
    coefficient_messages_by_shamir_index: &[Vec<u64>],
    recipient_roster_position: usize,
    rns_prime: u64,
    ring_degree: usize,
) -> (Vec<u64>, Vec<String>) {
    let trustee_point = u128::from((recipient_roster_position + 1) as u64);
    let mut trustee_point_powers = Vec::new();
    let mut power = 1_u128;
    for _ in 0..coefficient_messages_by_shamir_index.len() {
        trustee_point_powers.push(power);
        power *= trustee_point;
    }

    let mut share_values = Vec::with_capacity(ring_degree);
    let mut carry_witnesses = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let unreduced_value = coefficient_messages_by_shamir_index
            .iter()
            .zip(trustee_point_powers.iter())
            .map(|(coefficient_message, trustee_point_power)| {
                u128::from(coefficient_message[coefficient_position]) * trustee_point_power
            })
            .sum::<u128>();
        share_values.push((unreduced_value % u128::from(rns_prime)) as u64);
        carry_witnesses.push((unreduced_value / u128::from(rns_prime)).to_string());
    }

    (share_values, carry_witnesses)
}

fn aggregate_opening_columns(
    coefficient_openings: &[serde_json::Value],
    recipient_roster_position: usize,
    ring_degree: usize,
) -> Vec<Vec<i128>> {
    let trustee_point = i128::try_from(recipient_roster_position + 1).expect("trustee point");
    let mut trustee_point_powers = Vec::new();
    let mut power = 1_i128;
    for _ in coefficient_openings {
        trustee_point_powers.push(power);
        power *= trustee_point;
    }

    let first_opening = coefficient_openings
        .first()
        .expect("coefficient openings must be non-empty");
    let randomness_width = first_opening["randomnessByColumn"]
        .as_array()
        .expect("randomness columns")
        .len();
    let mut aggregate_columns = vec![vec![0_i128; ring_degree]; randomness_width];
    for (opening, trustee_point_power) in coefficient_openings.iter().zip(trustee_point_powers) {
        let randomness_columns = opening["randomnessByColumn"]
            .as_array()
            .expect("randomness columns");
        for (column_index, randomness_column) in randomness_columns.iter().enumerate() {
            let coefficients = randomness_column.as_array().expect("randomness column");
            for (coefficient_position, coefficient) in coefficients.iter().enumerate() {
                aggregate_columns[column_index][coefficient_position] += coefficient
                    .as_i64()
                    .map(i128::from)
                    .expect("randomness coefficient")
                    * trustee_point_power;
            }
        }
    }

    aggregate_columns
}
