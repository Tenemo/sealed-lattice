use super::*;
use crate::bgv::setup::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    SetupProofMaterialReferenceInput, setup_proof_material_reference_root,
    setup_proof_material_transport_hashes,
};
use crate::transcript_core::decode_hex;

#[test]
fn private_vss_share_envelope_verifier_refuses_plaintext_aggregate_openings() {
    let request = private_vss_share_envelope_request(8);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "verifyPrivateVssShareEnvelope");
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeLeaksAggregateOpening"
    );
    assert_eq!(result["privateEnvelopeHash"], serde_json::Value::Null);
    assert_eq!(result["localVerificationRoot"], serde_json::Value::Null);
}

#[test]
fn private_vss_share_envelope_verifier_refuses_plaintext_carry_witnesses() {
    let mut request = proof_shaped_private_vss_share_envelope_request(8);
    request["privateEnvelope"]["rnsShareOpenings"][0]["carryWitnessesDecimal"] =
        serde_json::json!(["0"]);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeLeaksCarryWitness"
    );
}

#[test]
fn private_vss_share_envelope_verifier_accepts_lnp_private_share_proofs() {
    let request = proof_shaped_private_vss_share_envelope_request(8);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], true);
    assert_eq!(result["operation"], "verifyPrivateVssShareEnvelope");
    assert_eq!(result["verifierStatus"], "accepted");
    assert_eq!(result["refusedObjects"], serde_json::json!([]));
    assert_eq!(
        result["verifiedPrivateVssShareProofCount"],
        serde_json::json!(DATA_PRIMES.len())
    );
    assert_eq!(
        result["limbVerifications"]
            .as_array()
            .expect("limb verifications")
            .len(),
        DATA_PRIMES.len()
    );
    for limb_verification in result["limbVerifications"]
        .as_array()
        .expect("limb verifications")
    {
        assert!(
            limb_verification["privateVssShareProofHash"]
                .as_str()
                .expect("proof hash")
                .len()
                == 128
        );
        assert!(
            limb_verification["proofStatementRoot"]
                .as_str()
                .expect("proof statement root")
                .len()
                == 128
        );
    }
}

#[test]
fn private_vss_lnp_proof_verifier_accepts_centered_message_responses() {
    let ring_degree = 8;
    let request = private_vss_share_envelope_request(ring_degree);
    let setup_context = request["setupContext"].clone();
    let public_matrix_seed_hash = request["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let private_envelope = &request["privateEnvelope"];
    let private_envelope_aad_hash = private_envelope["privateEnvelopeAadHash"]
        .as_str()
        .expect("private envelope AAD hash");
    let source_trustee_commitment_root = private_envelope["sourceTrusteeCommitmentRoot"]
        .as_str()
        .expect("source trustee commitment root");
    let limb_opening = &private_envelope["rnsShareOpenings"][0];
    let rns_prime = limb_opening["rnsPrime"].as_u64().expect("RNS prime");
    let coefficient_messages_by_shamir_index = vec![vec![0_u64; ring_degree]; 4];
    let opening_randomness_by_shamir_index = (0..4_u64)
        .map(|shamir_coefficient_index| {
            randomness_fixture(0, shamir_coefficient_index, ring_degree)
        })
        .collect::<Vec<_>>();
    let coefficient_commitments = opening_randomness_by_shamir_index
        .iter()
        .enumerate()
        .map(|(shamir_coefficient_index, opening_randomness)| {
            compute_setup_commitment_for_tests(
                public_matrix_seed_hash,
                0,
                rns_prime,
                shamir_coefficient_index as u64,
                &vec![0_u128; ring_degree],
                opening_randomness,
                ring_degree,
            )
            .expect("zero coefficient commitment")
        })
        .collect::<Vec<_>>();
    let coefficient_commitment_roots = coefficient_commitments
        .iter()
        .map(|commitment| setup_commitment_root(commitment).expect("commitment root"))
        .collect::<Vec<_>>();
    let share_values = vec![0_u64; ring_degree];
    let share_values_hash = derive_protocol_hash(
        "PrivateVssLocalVerificationRoot",
        &serde_json::json!({
            "objectType": "PrivateVssShareValueVector",
            "objectVersion": 1,
            "rnsLimbIndex": 0,
            "rnsPrime": rns_prime,
            "shareValues": share_values,
        }),
    )
    .expect("share values hash");
    let proof_randomness_seed_hex = derive_protocol_hash(
        "PrivateVssLocalVerificationRoot",
        &serde_json::json!({
            "fixture": "private-vss-centered-message-response",
            "rnsLimbIndex": 0,
        }),
    )
    .expect("private VSS proof randomness seed");
    let proof_record = private_vss_share_lnp_proof_record(PrivateVssShareLnpProofGenerationInput {
        setup_context: &setup_context,
        public_matrix_seed_hash,
        private_envelope_aad_hash,
        source_trustee_identity: "trustee-0",
        source_trustee_roster_position: 0,
        recipient_identity: "trustee-2",
        recipient_roster_position: 2,
        source_trustee_commitment_root,
        rns_limb_index: 0,
        rns_prime,
        ring_degree,
        coefficient_commitment_roots: &coefficient_commitment_roots,
        share_values: &share_values,
        share_values_hash: &share_values_hash,
        coefficient_commitments: &coefficient_commitments,
        witness: &PrivateVssShareLnpProofWitness {
            coefficient_messages_by_shamir_index,
            opening_randomness_by_shamir_index,
            carry_witnesses: vec![0_i128; ring_degree],
        },
        proof_randomness_seed_hex: &proof_randomness_seed_hex,
    })
    .expect("private VSS proof record");
    let message_responses = embedded_private_vss_message_responses(&proof_record, ring_degree, 4);
    assert!(
        message_responses.iter().any(|response| *response < 0),
        "zero-message private VSS proof should expose centered negative response representatives"
    );

    let verification =
        verify_private_vss_share_lnp_relation_proof(PrivateVssShareLnpProofVerificationInput {
            setup_context: &setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_identity: "trustee-0",
            source_trustee_roster_position: 0,
            recipient_identity: "trustee-2",
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            rns_limb_index: 0,
            rns_prime,
            ring_degree,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            share_values_hash: &share_values_hash,
            coefficient_commitments: &coefficient_commitments,
            proof_record: &proof_record,
            transported_proof_material: None,
        })
        .expect("centered private VSS proof verifies");

    assert_eq!(
        verification.proof_bytes_hash,
        proof_record["proofBytesHash"]
            .as_str()
            .expect("proof bytes hash")
    );
}

#[test]
fn private_vss_share_envelope_verifier_accepts_transported_lnp_private_share_proofs() {
    let mut request = proof_shaped_private_vss_share_envelope_request(8);
    let transported_proof_material = move_private_vss_share_proof_bytes_to_transport(&mut request);
    request["transportedPrivateVssShareProofMaterial"] = transported_proof_material;

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], true);
    assert_eq!(result["verifierStatus"], "accepted");
    assert_eq!(
        result["verifiedPrivateVssShareProofCount"],
        serde_json::json!(DATA_PRIMES.len())
    );
    for limb_opening in request["privateEnvelope"]["rnsShareOpenings"]
        .as_array()
        .expect("limb openings")
    {
        let proof_record = &limb_opening["privateVssShareProof"];
        assert_eq!(
            proof_record["proofBytesEncoding"],
            SETUP_PROOF_MATERIAL_ENCODING
        );
        assert!(proof_record.get("proofBytesHex").is_none());
        assert_eq!(
            proof_record["proofMaterialRoot"]
                .as_str()
                .expect("proof material root")
                .len(),
            128
        );
    }
}

#[test]
fn private_vss_share_envelope_verifier_refuses_missing_transported_lnp_private_share_proofs() {
    let mut request = proof_shaped_private_vss_share_envelope_request(8);
    let _transported_proof_material = move_private_vss_share_proof_bytes_to_transport(&mut request);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssShareProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("transportedPrivateVssShareProofMaterial")
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_tampered_transported_lnp_private_share_proof_chunk()
{
    let mut request = proof_shaped_private_vss_share_envelope_request(8);
    let mut transported_proof_material =
        move_private_vss_share_proof_bytes_to_transport(&mut request);
    let first_chunk_hex = transported_proof_material["proofMaterials"][0]["chunks"][0]["bytesHex"]
        .as_str()
        .expect("first transported chunk")
        .to_string();
    let mut tampered_chunk_hex = first_chunk_hex;
    let last_byte = tampered_chunk_hex
        .as_bytes()
        .last()
        .copied()
        .expect("transported chunk is non-empty");
    let replacement = if last_byte == b'0' { '1' } else { '0' };
    tampered_chunk_hex.pop();
    tampered_chunk_hex.push(replacement);
    transported_proof_material["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!(tampered_chunk_hex);
    request["transportedPrivateVssShareProofMaterial"] = transported_proof_material;

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssShareProofVerificationFailed"
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_tampered_lnp_private_share_proof_bytes() {
    let mut request = proof_shaped_private_vss_share_envelope_request(8);
    let proof_bytes_hex = request["privateEnvelope"]["rnsShareOpenings"][0]["privateVssShareProof"]
        ["proofBytesHex"]
        .as_str()
        .expect("proof bytes hex");
    let mut tampered_proof_bytes_hex = proof_bytes_hex.to_string();
    let last_byte = tampered_proof_bytes_hex
        .as_bytes()
        .last()
        .copied()
        .expect("proof bytes hex is non-empty");
    let replacement = if last_byte == b'0' { '1' } else { '0' };
    tampered_proof_bytes_hex.pop();
    tampered_proof_bytes_hex.push(replacement);
    request["privateEnvelope"]["rnsShareOpenings"][0]["privateVssShareProof"]["proofBytesHex"] =
        serde_json::json!(tampered_proof_bytes_hex);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssShareProofVerificationFailed"
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_share_value_drift_after_proof_generation() {
    let mut request = proof_shaped_private_vss_share_envelope_request(8);
    let rns_prime = request["privateEnvelope"]["rnsShareOpenings"][0]["rnsPrime"]
        .as_u64()
        .expect("RNS prime");
    let first_share_value = request["privateEnvelope"]["rnsShareOpenings"][0]["shareValues"][0]
        .as_u64()
        .expect("share value");
    request["privateEnvelope"]["rnsShareOpenings"][0]["shareValues"][0] =
        serde_json::json!((first_share_value + 1) % rns_prime);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssShareProofVerificationFailed"
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

    let mut source_trustee_coefficient_commitments = Vec::new();
    let mut source_trustee_coefficient_commitment_material_records = Vec::new();
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
            source_trustee_coefficient_commitments.push(serde_json::json!({
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
                "sourceTrusteeIdentity": "trustee-0",
                "sourceTrusteeRosterPosition": 0,
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
            source_trustee_coefficient_commitment_material_records.push(serde_json::json!({
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
                "sourceTrusteeIdentity": "trustee-0",
                "sourceTrusteeRosterPosition": 0,
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

    let mut source_trustee_record = serde_json::json!({
        "objectType": "VssSourceTrusteeCoefficientCommitments",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "sourceTrusteeIdentity": "trustee-0",
        "sourceTrusteeRosterPosition": 0,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "coefficientCommitments": source_trustee_coefficient_commitments,
    });
    source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("VssCoefficientCommitmentRoot", &source_trustee_record)
            .expect("source trustee commitment root")
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
        "sourceTrusteeIdentity": "trustee-0",
        "sourceTrusteeRosterPosition": 0,
        "recipientIdentity": "trustee-2",
        "recipientRosterPosition": 2,
        "sourceTrusteeCommitmentRoot": source_trustee_record["sourceTrusteeCommitmentRoot"],
        "rnsShareOpenings": rns_share_openings,
    });

    serde_json::json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeCoefficientCommitmentRecord": source_trustee_record,
        "sourceTrusteeCoefficientCommitmentMaterialRecords": source_trustee_coefficient_commitment_material_records,
        "privateEnvelope": private_envelope,
    })
}

fn proof_shaped_private_vss_share_envelope_request(ring_degree: usize) -> serde_json::Value {
    let mut request = private_vss_share_envelope_request(ring_degree);
    let setup_context = request["setupContext"].clone();
    let public_matrix_seed_hash = request["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash")
        .to_string();
    let private_envelope_aad_hash = request["privateEnvelope"]["privateEnvelopeAadHash"]
        .as_str()
        .expect("private envelope AAD hash")
        .to_string();
    let source_trustee_commitment_root = request["privateEnvelope"]["sourceTrusteeCommitmentRoot"]
        .as_str()
        .expect("source trustee commitment root")
        .to_string();
    let material_records = request["sourceTrusteeCoefficientCommitmentMaterialRecords"]
        .as_array()
        .expect("material records")
        .clone();
    let rns_share_openings = request["privateEnvelope"]["rnsShareOpenings"]
        .as_array_mut()
        .expect("private envelope limb openings");
    for (rns_limb_index, limb_opening) in rns_share_openings.iter_mut().enumerate() {
        let limb_object = limb_opening
            .as_object_mut()
            .expect("private envelope limb opening object");
        let rns_prime = limb_object
            .get("rnsPrime")
            .and_then(serde_json::Value::as_u64)
            .expect("RNS prime");
        let share_values = limb_object
            .get("shareValues")
            .and_then(serde_json::Value::as_array)
            .expect("share values")
            .iter()
            .map(|value| value.as_u64().expect("share value"))
            .collect::<Vec<_>>();
        let coefficient_commitment_roots = limb_object
            .get("coefficientCommitmentRoots")
            .and_then(serde_json::Value::as_array)
            .expect("coefficient commitment roots")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("coefficient commitment root")
                    .to_string()
            })
            .collect::<Vec<_>>();
        let coefficient_commitments = (0..4_u64)
            .map(|shamir_coefficient_index| {
                let material_record = material_records
                    .iter()
                    .find(|record| {
                        record["rnsLimbIndex"].as_u64() == Some(rns_limb_index as u64)
                            && record["shamirCoefficientIndex"].as_u64()
                                == Some(shamir_coefficient_index)
                    })
                    .expect("coefficient commitment material");
                parse_setup_commitment_full_value(&material_record["commitment"])
                    .expect("setup commitment")
            })
            .collect::<Vec<_>>();
        let coefficient_messages_by_shamir_index = (0..4_u64)
            .map(|shamir_coefficient_index| {
                coefficient_message_fixture(
                    rns_limb_index,
                    shamir_coefficient_index,
                    rns_prime,
                    ring_degree,
                )
            })
            .collect::<Vec<_>>();
        let opening_randomness_by_shamir_index = (0..4_u64)
            .map(|shamir_coefficient_index| {
                randomness_fixture(rns_limb_index, shamir_coefficient_index, ring_degree)
            })
            .collect::<Vec<_>>();
        let (expected_share_values, carry_witnesses_decimal) = share_values_and_carries(
            &coefficient_messages_by_shamir_index,
            2,
            rns_prime,
            ring_degree,
        );
        assert_eq!(share_values, expected_share_values);
        let carry_witnesses = carry_witnesses_decimal
            .iter()
            .map(|carry| carry.parse::<i128>().expect("carry witness"))
            .collect::<Vec<_>>();
        let share_values_hash = derive_protocol_hash(
            "PrivateVssLocalVerificationRoot",
            &serde_json::json!({
                "objectType": "PrivateVssShareValueVector",
                "objectVersion": 1,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shareValues": share_values,
            }),
        )
        .expect("share values hash");
        let proof_randomness_seed_hex = derive_protocol_hash(
            "PrivateVssLocalVerificationRoot",
            &serde_json::json!({
                "fixture": "private-vss-share-lnp-proof-randomness",
                "rnsLimbIndex": rns_limb_index,
            }),
        )
        .expect("private VSS proof randomness seed");
        let private_vss_share_proof =
            private_vss_share_lnp_proof_record(PrivateVssShareLnpProofGenerationInput {
                setup_context: &setup_context,
                public_matrix_seed_hash: &public_matrix_seed_hash,
                private_envelope_aad_hash: &private_envelope_aad_hash,
                source_trustee_identity: "trustee-0",
                source_trustee_roster_position: 0,
                recipient_identity: "trustee-2",
                recipient_roster_position: 2,
                source_trustee_commitment_root: &source_trustee_commitment_root,
                rns_limb_index,
                rns_prime,
                ring_degree,
                coefficient_commitment_roots: &coefficient_commitment_roots,
                share_values: &share_values,
                share_values_hash: &share_values_hash,
                coefficient_commitments: &coefficient_commitments,
                witness: &PrivateVssShareLnpProofWitness {
                    coefficient_messages_by_shamir_index,
                    opening_randomness_by_shamir_index,
                    carry_witnesses,
                },
                proof_randomness_seed_hex: &proof_randomness_seed_hex,
            })
            .expect("private VSS share proof");
        limb_object.remove("aggregateOpening");
        limb_object.remove("carryWitnessesDecimal");
        limb_object.insert("privateVssShareProof".to_string(), private_vss_share_proof);
    }

    request
}

fn move_private_vss_share_proof_bytes_to_transport(
    request: &mut serde_json::Value,
) -> serde_json::Value {
    let source_trustee_identity = request["privateEnvelope"]["sourceTrusteeIdentity"]
        .as_str()
        .expect("source trustee identity")
        .to_string();
    let source_trustee_roster_position = request["privateEnvelope"]["sourceTrusteeRosterPosition"]
        .as_u64()
        .expect("source trustee roster position");
    let proof_materials = request["privateEnvelope"]["rnsShareOpenings"]
        .as_array_mut()
        .expect("private VSS limb openings")
        .iter_mut()
        .map(|limb_opening| {
            let proof_record = limb_opening
                .get_mut("privateVssShareProof")
                .expect("private VSS proof record");
            let proof_bytes_hex = proof_record["proofBytesHex"]
                .as_str()
                .expect("embedded proof bytes")
                .to_string();
            let proof_bytes = hex_to_bytes(&proof_bytes_hex);
            let proof_chunks = proof_bytes
                .chunks(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES as usize)
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>();
            let transport_hashes = setup_proof_material_transport_hashes(
                "vss-opening-carry",
                &proof_chunks,
                SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            )
            .expect("private VSS proof transport hashes");
            let proof_material_root =
                setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
                    setup_profile_id: "CollectiveBgvSetup-v1",
                    proof_family: "vss-opening-carry",
                    trustee_identity: &source_trustee_identity,
                    trustee_roster_position: source_trustee_roster_position,
                    statement_hash_hex: proof_record["statementHash"]
                        .as_str()
                        .expect("statement hash"),
                    relation_commitment_hash_hex: proof_record["relationCommitmentHash"]
                        .as_str()
                        .expect("relation commitment hash"),
                    tbox_commitment_prefix_hash: proof_record["tboxCommitmentPrefixHash"]
                        .as_str()
                        .expect("tbox commitment prefix hash"),
                    proof_size_bytes: proof_record["proofSizeBytes"]
                        .as_u64()
                        .expect("proof size bytes"),
                    proof_bytes_hash: proof_record["proofBytesHash"]
                        .as_str()
                        .expect("proof bytes hash"),
                    transport_hashes: &transport_hashes,
                })
                .expect("private VSS transported proof material root");
            proof_record
                .as_object_mut()
                .expect("proof record object")
                .remove("proofBytesHex");
            proof_record["proofBytesEncoding"] = serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING);
            proof_record["proofMaterialRoot"] = serde_json::json!(proof_material_root.clone());
            proof_record["proofChunkSizeBytes"] =
                serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
            proof_record["proofChunkCount"] =
                serde_json::json!(transport_hashes.chunk_hashes.len());
            proof_record["proofTotalByteLength"] =
                serde_json::json!(transport_hashes.total_byte_length);
            proof_record["proofFullObjectHash"] =
                serde_json::json!(transport_hashes.full_object_hash.clone());
            proof_record["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root.clone());
            proof_record["proofChunkHashes"] =
                serde_json::json!(transport_hashes.chunk_hashes.clone());

            serde_json::json!({
                "objectType": "SetupTransportedPrivateVssShareProofMaterial",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "proofFamily": "vss-opening-carry",
                "proofMaterialRoot": proof_material_root,
                "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
                "chunkCount": proof_chunks.len(),
                "totalByteLength": transport_hashes.total_byte_length,
                "fullObjectHash": transport_hashes.full_object_hash.clone(),
                "chunkHashes": transport_hashes.chunk_hashes.clone(),
                "chunkRoot": transport_hashes.chunk_root.clone(),
                "chunks": proof_chunks
                    .iter()
                    .enumerate()
                    .map(|(chunk_index, chunk)| serde_json::json!({
                        "chunkIndex": chunk_index,
                        "bytesHex": bytes_to_hex(chunk),
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "objectType": "SetupTransportedPrivateVssShareProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "vss-opening-carry",
        "proofMaterials": proof_materials,
    })
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "hex string must have even length"
    );
    hex.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = hex_nibble(chunk[0]);
            let low = hex_nibble(chunk[1]);
            (high << 4) | low
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn embedded_private_vss_message_responses(
    proof_record: &serde_json::Value,
    ring_degree: usize,
    coefficient_count: usize,
) -> Vec<i128> {
    let proof_bytes_hex = proof_record["proofBytesHex"]
        .as_str()
        .expect("embedded proof bytes hex");
    let proof_bytes = decode_hex(proof_bytes_hex).expect("embedded proof bytes");
    let mut cursor = 0_usize;

    assert_eq!(
        read_private_vss_proof_fixed::<8>(&proof_bytes, &mut cursor),
        *b"SLVSLNP1"
    );
    cursor += 64;
    cursor += 64;
    cursor += 8;
    let tbox_proof_byte_count =
        usize::try_from(read_private_vss_proof_u64(&proof_bytes, &mut cursor))
            .expect("tbox proof byte count");
    cursor += tbox_proof_byte_count;

    cursor += ring_degree * 16;
    cursor += coefficient_count
        * SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        * SETUP_COMMITMENT_ROW_COUNT
        * ring_degree
        * 8;

    (0..coefficient_count)
        .flat_map(|_| read_private_vss_proof_i128_vector(&proof_bytes, &mut cursor, ring_degree))
        .collect()
}

fn read_private_vss_proof_i128_vector(
    proof_bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Vec<i128> {
    (0..count)
        .map(|_| {
            let bytes = read_private_vss_proof_fixed::<16>(proof_bytes, cursor);
            i128::from_le_bytes(bytes)
        })
        .collect()
}

fn read_private_vss_proof_u64(proof_bytes: &[u8], cursor: &mut usize) -> u64 {
    let bytes = read_private_vss_proof_fixed::<8>(proof_bytes, cursor);
    u64::from_le_bytes(bytes)
}

fn read_private_vss_proof_fixed<const LENGTH: usize>(
    proof_bytes: &[u8],
    cursor: &mut usize,
) -> [u8; LENGTH] {
    let end = cursor.checked_add(LENGTH).expect("proof cursor overflow");
    let slice = proof_bytes
        .get(*cursor..end)
        .expect("proof bytes ended early");
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(slice);
    *cursor = end;
    output
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("hex string contains non-hex byte"),
    }
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
