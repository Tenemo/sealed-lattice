use super::*;
use crate::bgv::setup::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES;

const PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE: usize = 128;

#[test]
fn private_vss_share_envelope_verifier_accepts_succinct_private_share_proofs() {
    let request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "accepts-succinct-private-share-proofs",
    );

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");
    let expected_private_envelope_hash =
        derive_canonical_object_hash(&request["privateEnvelope"]).expect("private envelope hash");

    assert_eq!(result["isValid"], true);
    assert_eq!(
        result["value"]["privateEnvelopeHash"],
        expected_private_envelope_hash
    );
}

#[test]
// Run through the guarded focused Rust runner:
//   pnpm run test:rust:kernel:full-profile-evidence -- private_vss_share_envelope_verifier_accepts_foundation_roster_succinct_private_share_proofs
#[ignore = "foundation-roster private VSS verification; run via the guarded full-profile-evidence runner"]
fn private_vss_share_envelope_verifier_accepts_foundation_roster_succinct_private_share_proofs() {
    let request = proof_shaped_private_vss_share_envelope_request(
        crate::bgv::parameters::POLYNOMIAL_DEGREE,
        "accepts-foundation-roster-succinct-private-share-proofs",
    );

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("foundation-roster private VSS envelope verification");
    let expected_private_envelope_hash =
        derive_canonical_object_hash(&request["privateEnvelope"]).expect("private envelope hash");

    assert_eq!(result["isValid"], true);
    assert_eq!(
        result["value"]["privateEnvelopeHash"],
        expected_private_envelope_hash
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_noncanonical_succinct_context() {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-noncanonical-succinct-context",
    );
    request["setupContext"]["setupEpoch"] = serde_json::json!("setup epoch 1");

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], false);
    assert_eq!(result["refusalReason"], "wrongContext");
}

#[test]
fn private_vss_succinct_proof_verifier_accepts_canonical_record() {
    let ring_degree = PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE;
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
            compute_setup_commitment_for_degree(
                public_matrix_seed_hash,
                0,
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
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssProofRandomnessSeedFixture",
        "fixture": "private-vss-succinct-proof-record",
        "rnsLimbIndex": 0,
    }))
    .expect("private VSS proof randomness seed");
    let proof_bytes_hash = private_vss_share_succinct_proof_bytes_hash_for_tests(
        PrivateVssShareSuccinctProofGenerationInput {
            setup_context: &setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_roster_position: 0,
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            rns_limb_index: 0,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            coefficient_commitments: &coefficient_commitments,
            witness: &PrivateVssShareSuccinctProofWitness {
                coefficient_messages_by_shamir_index,
                opening_randomness_by_shamir_index_and_commitment_limb:
                    opening_randomness_by_shamir_index,
                carry_witnesses: vec![0_i128; ring_degree],
            },
            proof_randomness_seed_hex: &proof_randomness_seed_hex,
        },
    )
    .expect("private VSS proof bytes hash");
    verify_private_vss_share_succinct_relation_proof(
        PrivateVssShareSuccinctProofVerificationInput {
            setup_context: &setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_roster_position: 0,
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            rns_limb_index: 0,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            coefficient_commitments: &coefficient_commitments,
            proof_bytes_hash: &proof_bytes_hash,
        },
    )
    .expect("private VSS succinct proof verifies");
}

// Threshold-many recipients bind one source polynomial across the RNS
// commitment fields. This test verifies the same degree-three commitment at
// four distinct recipient points and confirms that every proof binds identical
// coefficient commitments despite carrying a different share.
#[test]
fn private_vss_succinct_proof_accepts_one_polynomial_across_threshold_recipients() {
    let ring_degree = PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE;
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
    let rns_prime = DATA_PRIMES[0];

    // One committed degree-(t-1) polynomial, shared by every recipient: four
    // non-zero Shamir coefficient messages and their commitments.
    let coefficient_messages_by_shamir_index = (0..4_u64)
        .map(|shamir_coefficient_index| {
            coefficient_message_fixture(0, shamir_coefficient_index, rns_prime, ring_degree)
        })
        .collect::<Vec<_>>();
    let opening_randomness_by_shamir_index = (0..4_u64)
        .map(|shamir_coefficient_index| {
            randomness_fixture(0, shamir_coefficient_index, ring_degree)
        })
        .collect::<Vec<_>>();
    let coefficient_commitments = coefficient_messages_by_shamir_index
        .iter()
        .zip(opening_randomness_by_shamir_index.iter())
        .enumerate()
        .map(
            |(shamir_coefficient_index, (messages, opening_randomness))| {
                let messages_u128 = messages
                    .iter()
                    .map(|value| u128::from(*value))
                    .collect::<Vec<_>>();
                compute_setup_commitment_for_degree(
                    public_matrix_seed_hash,
                    0,
                    shamir_coefficient_index as u64,
                    &messages_u128,
                    opening_randomness,
                    ring_degree,
                )
                .expect("coefficient commitment")
            },
        )
        .collect::<Vec<_>>();
    let coefficient_commitment_roots = coefficient_commitments
        .iter()
        .map(|commitment| setup_commitment_root(commitment).expect("commitment root"))
        .collect::<Vec<_>>();

    // Four distinct recipient points for threshold t = 4, each inside the
    // n = 10 accepted roster fixture.
    for recipient_roster_position in [1_usize, 3, 5, 8] {
        let (share_values, carry_strings) = share_values_and_carries(
            &coefficient_messages_by_shamir_index,
            recipient_roster_position,
            rns_prime,
            ring_degree,
        );
        let carry_witnesses = carry_strings
            .iter()
            .map(|carry| carry.parse::<i128>().expect("carry witness parses"))
            .collect::<Vec<_>>();
        let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "PrivateVssProofRandomnessSeedFixture",
            "fixture": "private-vss-multi-recipient-consistency",
            "recipientRosterPosition": recipient_roster_position,
        }))
        .expect("private VSS proof randomness seed");
        let proof_bytes_hash = private_vss_share_succinct_proof_bytes_hash_for_tests(
            PrivateVssShareSuccinctProofGenerationInput {
                setup_context: &setup_context,
                public_matrix_seed_hash,
                private_envelope_aad_hash,
                source_trustee_roster_position: 0,
                recipient_roster_position: recipient_roster_position as u64,
                source_trustee_commitment_root,
                rns_limb_index: 0,
                coefficient_commitment_roots: &coefficient_commitment_roots,
                share_values: &share_values,
                coefficient_commitments: &coefficient_commitments,
                witness: &PrivateVssShareSuccinctProofWitness {
                    coefficient_messages_by_shamir_index: coefficient_messages_by_shamir_index
                        .clone(),
                    opening_randomness_by_shamir_index_and_commitment_limb:
                        opening_randomness_by_shamir_index.clone(),
                    carry_witnesses,
                },
                proof_randomness_seed_hex: &proof_randomness_seed_hex,
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "proof bytes hash for recipient {recipient_roster_position}: {}",
                error.message
            )
        });
        verify_private_vss_share_succinct_relation_proof(
            PrivateVssShareSuccinctProofVerificationInput {
                setup_context: &setup_context,
                public_matrix_seed_hash,
                private_envelope_aad_hash,
                source_trustee_roster_position: 0,
                recipient_roster_position: recipient_roster_position as u64,
                source_trustee_commitment_root,
                rns_limb_index: 0,
                coefficient_commitment_roots: &coefficient_commitment_roots,
                share_values: &share_values,
                coefficient_commitments: &coefficient_commitments,
                proof_bytes_hash: &proof_bytes_hash,
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "verification for recipient {recipient_roster_position}: {}",
                error.message
            )
        });
    }
}

// The commitment-opening lincheck binds each Shamir coefficient message. This
// tamper preserves the recipient-share relation, randomness, carry, and
// commitments while changing only the witness message, so proof construction
// must reject it at the sumcheck/lincheck stage.
#[test]
fn private_vss_succinct_proof_refuses_message_inconsistent_with_commitment_opening() {
    let ring_degree = PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE;
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
    let opening_randomness_by_shamir_index = (0..4_u64)
        .map(|shamir_coefficient_index| {
            randomness_fixture(0, shamir_coefficient_index, ring_degree)
        })
        .collect::<Vec<_>>();
    // The commitments bind the honest, all-zero coefficient messages.
    let coefficient_commitments = opening_randomness_by_shamir_index
        .iter()
        .enumerate()
        .map(|(shamir_coefficient_index, opening_randomness)| {
            compute_setup_commitment_for_degree(
                public_matrix_seed_hash,
                0,
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

    // Tamper the constant-term message of the first Shamir coefficient at one
    // position. The constant term contributes with trustee-point power one, so the
    // recipient share at that position must move by the same amount to keep the
    // witness Shamir relation satisfied; the carry stays zero. The commitments
    // above still bind the zero message, so the only inconsistency in the witness
    // is between the message column and its commitment opening.
    let tampered_message: u64 = 1;
    let mut coefficient_messages_by_shamir_index = vec![vec![0_u64; ring_degree]; 4];
    coefficient_messages_by_shamir_index[0][0] = tampered_message;
    let mut share_values = vec![0_u64; ring_degree];
    share_values[0] = tampered_message;
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssProofRandomnessSeedFixture",
        "fixture": "private-vss-succinct-proof-tampered-message",
        "rnsLimbIndex": 0,
    }))
    .expect("private VSS proof randomness seed");

    let generation = private_vss_share_succinct_proof_bytes_hash_for_tests(
        PrivateVssShareSuccinctProofGenerationInput {
            setup_context: &setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_roster_position: 0,
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            rns_limb_index: 0,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            coefficient_commitments: &coefficient_commitments,
            witness: &PrivateVssShareSuccinctProofWitness {
                coefficient_messages_by_shamir_index,
                opening_randomness_by_shamir_index_and_commitment_limb:
                    opening_randomness_by_shamir_index,
                carry_witnesses: vec![0_i128; ring_degree],
            },
            proof_randomness_seed_hex: &proof_randomness_seed_hex,
        },
    );

    let error = generation.expect_err(
        "a coefficient message that disagrees with its commitment opening must be refused: \
         the opening lincheck binds the message column even though it carries no consistency claim",
    );
    assert!(
        error.message.contains("sumcheck"),
        "the rejection must come from the commitment-opening lincheck (the batched sumcheck claim), \
         not an earlier shape or share-relation check; got: {}",
        error.message
    );
}

#[test]
fn private_vss_share_envelope_verifier_accepts_authenticated_succinct_private_share_proofs() {
    let request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "accepts-authenticated-succinct-private-share-proofs",
    );

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], true);
}

#[test]
fn private_vss_share_envelope_verifier_refuses_private_share_proof_bytes_hash_drift() {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-private-share-proof-bytes-hash-drift",
    );
    let replacement_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssProofBytesHashDriftFixture",
        "fixture": "private-vss-proof-bytes-hash-drift",
    }))
    .expect("private VSS replacement proof bytes hash");
    let proof_bytes_hash =
        &mut request["privateEnvelope"]["rnsShareOpenings"][0]["privateVssShareProofBytesHash"];
    assert_ne!(
        proof_bytes_hash.as_str().expect("proof bytes hash"),
        replacement_hash
    );
    *proof_bytes_hash = serde_json::json!(replacement_hash);

    assert_private_vss_share_proof_refusal(&request);
}

#[test]
fn private_vss_share_envelope_verifier_refuses_unauthenticated_proof_material_reference() {
    let request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-unauthenticated-proof-material-reference",
    );
    let proof_bytes_hash =
        request["privateEnvelope"]["rnsShareOpenings"][0]["privateVssShareProofBytesHash"]
            .as_str()
            .expect("private VSS proof bytes hash");
    let _removed_proof_material =
        crate::bgv::setup::take_authenticated_canonical_proof_material_bytes(
            "vss-opening-carry",
            proof_bytes_hash,
        )
        .expect("private VSS proof material store lookup")
        .expect("private VSS proof material was retained");

    assert_private_vss_share_proof_refusal(&request);
}

#[test]
fn private_vss_share_envelope_verifier_refuses_share_value_drift_after_proof_generation() {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-share-value-drift-after-proof-generation",
    );
    let rns_prime = DATA_PRIMES[0];
    let first_share_value = request["privateEnvelope"]["rnsShareOpenings"][0]["shareValues"][0]
        .as_u64()
        .expect("share value");
    request["privateEnvelope"]["rnsShareOpenings"][0]["shareValues"][0] =
        serde_json::json!((first_share_value + 1) % rns_prime);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], false);
    assert_eq!(result["refusalReason"], "invalidProof");
}

fn assert_private_vss_share_proof_refusal(request: &serde_json::Value) {
    let result = verify_private_vss_share_envelope_from_request(request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], false);
    assert_eq!(result["refusalReason"], "invalidProof");
}

fn private_vss_share_envelope_request(ring_degree: usize) -> serde_json::Value {
    let ceremony_id = "ceremony-main";
    let manifest_hash = derive_canonical_object_hash(
        &serde_json::json!({ "objectType": "ElectionManifestHash", "manifest": "private-vss-envelope-test" }),
    )
    .expect("manifest hash");
    let roster_hash = derive_canonical_object_hash(
        &serde_json::json!({ "objectType": "RosterHash", "roster": "private-vss-envelope-test" }),
    )
    .expect("roster hash");
    let setup_parameters_hash =
        crate::bgv::setup::accepted_setup::setup_parameters_hash_for_roster(
            &crate::bgv::setup::accepted_setup::roster_parameters_from_participant_count(
                u64::from(crate::foundation::PROTOTYPE_PARTICIPANT_COUNT),
            ),
        )
        .expect("roster-derived setup parameters hash");
    let setup_parameters_hash = setup_parameters_hash.as_str();
    let setup_epoch = "setup-epoch-1";
    let setup_context = serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "participantCount": u64::from(crate::foundation::PROTOTYPE_PARTICIPANT_COUNT),
    });
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(&setup_context)
        .expect("setup context hash");
    let public_matrix_seed_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupPublicMatrixSeedHash",
        "fixture": "private-vss-envelope-test-public-matrix",
        "setupContextHash": setup_context_hash,
    }))
    .expect("public matrix seed hash");
    let private_envelope_aad_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssEnvelopeAadHash",
        "fixture": "private-vss-envelope-aad",
        "recipientRosterPosition": 2,
    }))
    .expect("private VSS envelope AAD hash");

    let mut source_trustee_coefficient_commitment_roots = Vec::new();
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
            let randomness_by_commitment_limb =
                randomness_fixture(rns_limb_index, shamir_coefficient_index, ring_degree);
            let coefficient_message_wide = coefficient_message
                .iter()
                .map(|coefficient| u128::from(*coefficient))
                .collect::<Vec<_>>();
            let commitment = compute_setup_commitment_for_degree(
                &public_matrix_seed_hash,
                rns_limb_index,
                shamir_coefficient_index,
                &coefficient_message_wide,
                &randomness_by_commitment_limb,
                ring_degree,
            )
            .expect("setup commitment");
            let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
            coefficient_commitment_roots.push(commitment_root.clone());
            source_trustee_coefficient_commitment_roots.push(commitment_root.clone());
            source_trustee_coefficient_commitment_material_records
                .push(setup_commitment_full_value(&commitment));
            coefficient_openings.push(serde_json::json!({
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": coefficient_commitment_roots
                    .last()
                    .expect("coefficient commitment root"),
                "randomnessByCommitmentLimb": randomness_by_commitment_limb,
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
            "rnsLimbIndex": rns_limb_index,
            "shareValues": share_values,
            "carryWitnessesDecimal": carry_witnesses_decimal,
            "aggregateOpening": {
                "objectType": "PrivateVssAggregateOpening",
                "openingColumns": aggregate_opening_columns,
            },
        }));
    }

    let source_trustee_commitment_root = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssSourceTrusteeCoefficientCommitments",
        "sourceTrusteeIdentity": "trustee-0",
        "sourceTrusteeRosterPosition": 0,
        "coefficientCommitmentRoots": &source_trustee_coefficient_commitment_roots,
    }))
    .expect("source trustee commitment root");
    let source_trustee_record = serde_json::json!({
        "objectType": "VssSourceTrusteeCoefficientCommitments",
        "sourceTrusteeIdentity": "trustee-0",
        "coefficientCommitmentRoots": source_trustee_coefficient_commitment_roots,
    });

    let private_envelope = serde_json::json!({
        "objectType": "PrivateVssShareEnvelope",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeAadHash": private_envelope_aad_hash,
        "sourceTrusteeIdentity": "trustee-0",
        "sourceTrusteeRosterPosition": 0,
        "recipientIdentity": "trustee-2",
        "recipientRosterPosition": 2,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
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

fn proof_shaped_private_vss_share_envelope_request(
    ring_degree: usize,
    proof_fixture_label: &str,
) -> serde_json::Value {
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
    let source_commitment_roots =
        request["sourceTrusteeCoefficientCommitmentRecord"]["coefficientCommitmentRoots"]
            .as_array()
            .expect("source coefficient commitment roots")
            .clone();
    let rns_share_openings = request["privateEnvelope"]["rnsShareOpenings"]
        .as_array_mut()
        .expect("private envelope limb openings");
    for (rns_limb_index, limb_opening) in rns_share_openings.iter_mut().enumerate() {
        let limb_object = limb_opening
            .as_object_mut()
            .expect("private envelope limb opening object");
        let rns_prime = DATA_PRIMES[rns_limb_index];
        let share_values = limb_object
            .get("shareValues")
            .and_then(serde_json::Value::as_array)
            .expect("share values")
            .iter()
            .map(|value| value.as_u64().expect("share value"))
            .collect::<Vec<_>>();
        let coefficient_commitment_roots = source_commitment_roots
            [rns_limb_index * 4..(rns_limb_index + 1) * 4]
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
                    .get(rns_limb_index * 4 + shamir_coefficient_index as usize)
                    .expect("coefficient commitment material");
                parse_setup_commitment_full_value(material_record).expect("setup commitment")
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
        let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "PrivateVssProofRandomnessSeedFixture",
            "fixture": proof_fixture_label,
            "rnsLimbIndex": rns_limb_index,
        }))
        .expect("private VSS proof randomness seed");
        let private_vss_share_proof_bytes_hash =
            private_vss_share_succinct_proof_bytes_hash_for_tests(
                PrivateVssShareSuccinctProofGenerationInput {
                    setup_context: &setup_context,
                    public_matrix_seed_hash: &public_matrix_seed_hash,
                    private_envelope_aad_hash: &private_envelope_aad_hash,
                    source_trustee_roster_position: 0,
                    recipient_roster_position: 2,
                    source_trustee_commitment_root: &source_trustee_commitment_root,
                    rns_limb_index,
                    coefficient_commitment_roots: &coefficient_commitment_roots,
                    share_values: &share_values,
                    coefficient_commitments: &coefficient_commitments,
                    witness: &PrivateVssShareSuccinctProofWitness {
                        coefficient_messages_by_shamir_index,
                        opening_randomness_by_shamir_index_and_commitment_limb:
                            opening_randomness_by_shamir_index,
                        carry_witnesses,
                    },
                    proof_randomness_seed_hex: &proof_randomness_seed_hex,
                },
            )
            .expect("private VSS share proof");
        limb_object.remove("aggregateOpening");
        limb_object.remove("carryWitnessesDecimal");
        limb_object.insert(
            "privateVssShareProofBytesHash".to_string(),
            serde_json::json!(private_vss_share_proof_bytes_hash),
        );
    }

    request
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
) -> Vec<Vec<Vec<i128>>> {
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .enumerate()
        .map(|(commitment_limb_position, _)| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|randomness_column_index| {
                    (0..ring_degree)
                        .map(|coefficient_position| {
                            let support_position = rns_limb_index
                                + shamir_coefficient_index as usize
                                + commitment_limb_position
                                + randomness_column_index
                                + coefficient_position;
                            match support_position % 3 {
                                0 => -1,
                                1 => 0,
                                _ => 1,
                            }
                        })
                        .collect()
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
) -> Vec<Vec<Vec<i128>>> {
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
    let commitment_limb_count = first_opening["randomnessByCommitmentLimb"]
        .as_array()
        .expect("randomness by commitment limb")
        .len();
    let randomness_width = first_opening["randomnessByCommitmentLimb"][0]
        .as_array()
        .expect("randomness columns")
        .len();
    let mut aggregate_columns =
        vec![vec![vec![0_i128; ring_degree]; randomness_width]; commitment_limb_count];
    for (opening, trustee_point_power) in coefficient_openings.iter().zip(trustee_point_powers) {
        let randomness_by_commitment_limb = opening["randomnessByCommitmentLimb"]
            .as_array()
            .expect("randomness by commitment limb");
        for (commitment_limb_position, randomness_columns) in
            randomness_by_commitment_limb.iter().enumerate()
        {
            for (column_index, randomness_column) in randomness_columns
                .as_array()
                .expect("randomness columns")
                .iter()
                .enumerate()
            {
                let coefficients = randomness_column.as_array().expect("randomness column");
                for (coefficient_position, coefficient) in coefficients.iter().enumerate() {
                    aggregate_columns[commitment_limb_position][column_index]
                        [coefficient_position] += coefficient
                        .as_i64()
                        .map(i128::from)
                        .expect("randomness coefficient")
                        * trustee_point_power;
                }
            }
        }
    }

    aggregate_columns
}
