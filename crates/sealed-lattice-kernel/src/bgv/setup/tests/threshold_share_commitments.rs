use super::*;

#[test]
fn threshold_share_commitment_derivation_recomputes_all_recipient_limb_commitments() {
    let request = threshold_share_commitment_derivation_request(8);

    let result = derive_threshold_share_commitments_from_request(&request)
        .expect("threshold share commitment derivation");

    assert_eq!(result["ok"], true);
    assert_eq!(result["operation"], "deriveThresholdShareCommitments");
    assert_eq!(result["ringDegree"], 8);
    assert_eq!(result["ringDegreeStatus"], "development-reduced-ring");
    assert_eq!(result["participantCount"], 10);
    assert_eq!(result["rnsLimbCount"], serde_json::json!(DATA_PRIMES.len()));
    assert_eq!(result["thresholdDegree"], 4);
    assert_eq!(
        result["derivedLimbCommitmentCount"],
        serde_json::json!(10 * DATA_PRIMES.len())
    );
    assert!(
        result["thresholdShareCommitmentRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );

    let commitment_set = &result["thresholdShareCommitments"];
    assert_eq!(commitment_set["objectType"], "ThresholdShareCommitmentSet");
    let recipient_records = commitment_set["recipientRecords"]
        .as_array()
        .expect("recipient records");
    assert_eq!(recipient_records.len(), 10);
    let last_recipient = &recipient_records[9];
    assert_eq!(last_recipient["recipientIdentity"], "trustee-9");
    assert_eq!(last_recipient["trusteePoint"], 10);
    assert!(
        last_recipient["recipientCommitmentRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
    let first_limb = &last_recipient["limbCommitments"]
        .as_array()
        .expect("limb commitments")[0];
    assert_eq!(first_limb["objectType"], "ThresholdShareCommitment");
    assert_eq!(
        first_limb["shamirCoefficientScalarsDecimal"],
        serde_json::json!(["1", "10", "100", "1000"])
    );
    assert_eq!(
        first_limb["coefficientCommitmentRoots"]
            .as_array()
            .expect("coefficient roots")
            .len(),
        40
    );
    assert!(
        first_limb["thresholdShareCommitmentRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
}

#[test]
fn threshold_share_commitment_derivation_refuses_tampered_full_commitment_material() {
    let mut request = threshold_share_commitment_derivation_request(8);
    let first_row_coefficient =
        request["coefficientCommitments"][0]["commitment"]["commitmentLimbs"][0]["rows"][0][0]
            .as_u64()
            .expect("first commitment coefficient");
    let first_limb_modulus = request["coefficientCommitments"][0]["commitment"]["commitmentLimbs"]
        [0]["modulus"]
        .as_u64()
        .expect("first commitment modulus");
    request["coefficientCommitments"][0]["commitment"]["commitmentLimbs"][0]["rows"][0][0] =
        serde_json::json!((first_row_coefficient + 1) % first_limb_modulus);

    let error = derive_threshold_share_commitments_from_request(&request)
        .expect_err("tampered full commitment material must be refused");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(
        error
            .message
            .contains("full setup commitment material does not match commitmentRoot")
    );
}

#[test]
fn threshold_share_commitment_derivation_consumes_transported_binary_material() {
    let request = threshold_share_commitment_derivation_request(64);
    let json_result = derive_threshold_share_commitments_from_request(&request)
        .expect("JSON threshold share commitment derivation");
    let material_bytes = encode_transport_material_from_request(&request);
    let transported_material = transported_material_value(&material_bytes);
    assert!(
        transported_material["chunkCount"]
            .as_u64()
            .is_some_and(|chunk_count| chunk_count > 1)
    );
    let transport_request = serde_json::json!({
        "setupContext": request["setupContext"],
        "publicMatrixSeedHash": request["publicMatrixSeedHash"],
        "vssCoefficientCommitmentRoot": vss_commitment_root_from_derivation_request(&request),
        "sourceTrusteeCoefficientCommitmentRecords": request["sourceTrusteeCoefficientCommitmentRecords"],
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    });

    let transport_result =
        derive_threshold_share_commitments_from_transport_request(&transport_request)
            .expect("transport threshold share commitment derivation");

    assert_eq!(transport_result["ok"], true);
    assert_eq!(
        transport_result["operation"],
        "deriveThresholdShareCommitmentsFromTransport"
    );
    assert_eq!(transport_result["ringDegree"], 64);
    assert_eq!(
        transport_result["ringDegreeStatus"],
        "development-reduced-ring"
    );
    assert_eq!(
        transport_result["thresholdShareCommitmentRoot"],
        json_result["thresholdShareCommitmentRoot"]
    );
    assert_eq!(
        transport_result["thresholdShareCommitments"],
        json_result["thresholdShareCommitments"]
    );
    assert_eq!(
        transport_result["vssCoefficientCommitmentMaterial"]["materialEncoding"],
        "binary-chunked-full-public-setup-commitment-values"
    );
    assert!(
        transport_result["vssCoefficientCommitmentMaterial"]
            .get("coefficientCommitments")
            .is_none()
    );
}

#[test]
fn threshold_share_commitment_derivation_consumes_streamed_binary_material() {
    let request = threshold_share_commitment_derivation_request(64);
    let material_bytes = encode_transport_material_from_request(&request);
    let transported_material = transported_material_value(&material_bytes);
    let transport_request = serde_json::json!({
        "setupContext": request["setupContext"],
        "publicMatrixSeedHash": request["publicMatrixSeedHash"],
        "vssCoefficientCommitmentRoot": vss_commitment_root_from_derivation_request(&request),
        "sourceTrusteeCoefficientCommitmentRecords": request["sourceTrusteeCoefficientCommitmentRecords"],
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    });
    let transport_result =
        derive_threshold_share_commitments_from_transport_request(&transport_request)
            .expect("transport threshold share commitment derivation");
    let derivation_id = "threshold-share-stream-test";
    let stream_template = transported_material_stream_template_value(
        transport_request
            .get("transportedVssCoefficientCommitmentMaterial")
            .expect("transported material"),
    );

    let begin_result =
        begin_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
            "derivationId": derivation_id,
            "setupContext": request["setupContext"],
            "publicMatrixSeedHash": request["publicMatrixSeedHash"],
            "transportedVssCoefficientCommitmentMaterial": stream_template,
        }))
        .expect("begin stream threshold derivation");
    assert_eq!(
        begin_result["operation"],
        "beginThresholdShareCommitmentsFromTransportStream"
    );

    for chunk in transport_request["transportedVssCoefficientCommitmentMaterial"]["chunks"]
        .as_array()
        .expect("chunks")
    {
        let absorb_result =
            absorb_threshold_share_commitment_transport_derivation_stream_chunk_request(
                &serde_json::json!({
                    "derivationId": derivation_id,
                    "chunkIndex": chunk["chunkIndex"],
                    "bytesHex": chunk["bytesHex"],
                }),
            )
            .expect("absorb stream chunk");
        assert_eq!(
            absorb_result["operation"],
            "absorbThresholdShareCommitmentsFromTransportStreamChunk"
        );
    }

    let stream_result =
        finish_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
            "derivationId": derivation_id,
            "vssCoefficientCommitmentRoot": vss_commitment_root_from_derivation_request(&request),
            "sourceTrusteeCoefficientCommitmentRecords": request["sourceTrusteeCoefficientCommitmentRecords"],
        }))
        .expect("finish stream threshold derivation");

    assert_eq!(
        stream_result["operation"],
        "finishThresholdShareCommitmentsFromTransportStream"
    );
    assert_eq!(
        stream_result["thresholdShareCommitmentRoot"],
        transport_result["thresholdShareCommitmentRoot"]
    );
    assert_eq!(
        stream_result["thresholdShareCommitments"],
        transport_result["thresholdShareCommitments"]
    );
    assert_eq!(
        stream_result["vssCoefficientCommitmentMaterial"],
        transport_result["vssCoefficientCommitmentMaterial"]
    );
    assert_eq!(
        stream_result["verifiedVssCoefficientCommitmentMaterial"]["objectType"],
        "VerifiedVssCoefficientCommitmentMaterial"
    );
    assert_eq!(
        stream_result["verifiedVssCoefficientCommitmentMaterial"]["thresholdShareCommitmentRoot"],
        stream_result["thresholdShareCommitmentRoot"]
    );

    let release_result = release_verified_transported_vss_material_request(&serde_json::json!({
        "verificationId": derivation_id,
    }))
    .expect("release stream-verified material");
    assert_eq!(
        release_result["operation"],
        "releaseVerifiedTransportedVssMaterial"
    );
    assert_eq!(release_result["released"], true);
}

#[test]
fn threshold_share_commitment_stream_refuses_tampered_chunk_bytes() {
    let request = threshold_share_commitment_derivation_request(64);
    let material_bytes = encode_transport_material_from_request(&request);
    let transported_material = transported_material_value(&material_bytes);
    let derivation_id = "threshold-share-stream-tamper-test";
    let manifest = transported_material_manifest_value(&transported_material);
    begin_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
        "derivationId": derivation_id,
        "setupContext": request["setupContext"],
        "publicMatrixSeedHash": request["publicMatrixSeedHash"],
        "transportedVssCoefficientCommitmentMaterial": manifest,
    }))
    .expect("begin stream threshold derivation");
    let first_chunk = &transported_material["chunks"].as_array().expect("chunks")[0];
    let mut tampered_bytes =
        crate::transcript_core::decode_hex(first_chunk["bytesHex"].as_str().expect("chunk bytes"))
            .expect("chunk hex");
    tampered_bytes[0] ^= 0x01;

    let error = absorb_threshold_share_commitment_transport_derivation_stream_chunk_request(
        &serde_json::json!({
            "derivationId": derivation_id,
            "chunkIndex": 0,
            "bytesHex": crate::hashing::to_hex(&tampered_bytes),
        }),
    )
    .expect_err("tampered stream chunk must reject");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(
        error
            .message
            .contains("transport stream chunk bytes do not match the declared chunk hash")
    );
}

#[test]
fn threshold_share_commitment_stream_abort_releases_derivation_id() {
    let request = threshold_share_commitment_derivation_request(8);
    let material_bytes = encode_transport_material_from_request(&request);
    let transported_material = transported_material_value(&material_bytes);
    let stream_template = transported_material_stream_template_value(&transported_material);
    let derivation_id = "threshold-share-stream-abort-test";

    begin_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
        "derivationId": derivation_id,
        "setupContext": request["setupContext"],
        "publicMatrixSeedHash": request["publicMatrixSeedHash"],
        "transportedVssCoefficientCommitmentMaterial": stream_template,
    }))
    .expect("begin stream threshold derivation");

    let abort_result =
        abort_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
            "derivationId": derivation_id,
        }))
        .expect("abort stream threshold derivation");
    assert_eq!(
        abort_result["operation"],
        "abortThresholdShareCommitmentsFromTransportStream"
    );
    assert_eq!(abort_result["aborted"], true);

    let error = absorb_threshold_share_commitment_transport_derivation_stream_chunk_request(
        &serde_json::json!({
            "derivationId": derivation_id,
            "chunkIndex": 0,
            "bytesHex": transported_material["chunks"][0]["bytesHex"],
        }),
    )
    .expect_err("aborted stream must not accept chunks");
    assert!(
        error
            .message
            .contains("transport derivationId is not active")
    );

    begin_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
        "derivationId": derivation_id,
        "setupContext": request["setupContext"],
        "publicMatrixSeedHash": request["publicMatrixSeedHash"],
        "transportedVssCoefficientCommitmentMaterial": transported_material_stream_template_value(&transported_material),
    }))
    .expect("derivation id can be reused after abort");

    abort_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
        "derivationId": derivation_id,
    }))
    .expect("cleanup reused stream threshold derivation");
}

#[test]
fn threshold_share_commitment_stream_refuses_chunk_count_that_does_not_match_total_length() {
    let request = threshold_share_commitment_derivation_request(8);
    let material_bytes = encode_transport_material_from_request(&request);
    let transported_material = transported_material_value(&material_bytes);
    let mut stream_template = transported_material_stream_template_value(&transported_material);
    stream_template["chunkCount"] = serde_json::json!(usize::MAX);

    let error =
        begin_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
            "derivationId": "threshold-share-stream-large-count-test",
            "setupContext": request["setupContext"],
            "publicMatrixSeedHash": request["publicMatrixSeedHash"],
            "transportedVssCoefficientCommitmentMaterial": stream_template,
        }))
        .expect_err("stream header with impossible chunk count must reject");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(
        error
            .message
            .contains("transport chunkCount must match totalByteLength")
    );
}

#[test]
fn threshold_share_commitment_transport_refuses_chunk_hash_drift() {
    let request = threshold_share_commitment_derivation_request(64);
    let material_bytes = encode_transport_material_from_request(&request);
    let mut transported_material = transported_material_value(&material_bytes);
    let first_chunk = &mut transported_material["chunks"]
        .as_array_mut()
        .expect("chunks")[0];
    let mut tampered_bytes =
        crate::transcript_core::decode_hex(first_chunk["bytesHex"].as_str().expect("chunk bytes"))
            .expect("chunk hex");
    tampered_bytes[0] ^= 0x01;
    first_chunk["bytesHex"] = serde_json::json!(crate::hashing::to_hex(&tampered_bytes));
    let transport_request = serde_json::json!({
        "setupContext": request["setupContext"],
        "publicMatrixSeedHash": request["publicMatrixSeedHash"],
        "vssCoefficientCommitmentRoot": vss_commitment_root_from_derivation_request(&request),
        "sourceTrusteeCoefficientCommitmentRecords": request["sourceTrusteeCoefficientCommitmentRecords"],
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    });

    let error = derive_threshold_share_commitments_from_transport_request(&transport_request)
        .expect_err("chunk hash drift must reject");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(
        error
            .message
            .contains("transport fullObjectHash does not match supplied chunk bytes")
    );
}

fn threshold_share_commitment_derivation_request(ring_degree: usize) -> serde_json::Value {
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let ceremony_id = "ceremony-main";
    let manifest_hash = derive_protocol_hash(
        "ElectionManifestHash",
        &serde_json::json!({ "manifest": "threshold-share-commitments-test" }),
    )
    .expect("manifest hash");
    let roster_hash = derive_protocol_hash(
        "RosterHash",
        &serde_json::json!({ "roster": "threshold-share-commitments-test" }),
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
            "fixture": "threshold-share-commitments-public-matrix",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "setupEpoch": setup_epoch,
        }),
    )
    .expect("public matrix seed hash");

    let mut source_trustee_records = Vec::new();
    let mut coefficient_commitment_material = Vec::new();
    for source_trustee_roster_position in 0..10_u64 {
        let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
        let mut coefficient_commitments = Vec::new();
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..4_u64 {
                let coefficient_message = threshold_coefficient_message_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    rns_prime,
                    ring_degree,
                );
                let randomness_by_column = threshold_randomness_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    ring_degree,
                );
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
                coefficient_commitments.push(serde_json::json!({
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
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "commitmentRoot": commitment_root,
                    "commitmentChunkRoot": derive_protocol_hash(
                        "VssCoefficientCommitmentRoot",
                        &serde_json::json!({
                            "fixture": "threshold-share-commitment-chunk",
                            "sourceTrusteeRosterPosition": source_trustee_roster_position,
                            "rnsLimbIndex": rns_limb_index,
                            "shamirCoefficientIndex": shamir_coefficient_index,
                        }),
                    ).expect("commitment chunk root"),
                    "coefficientVectorHash512": derive_protocol_hash(
                        "VssCoefficientCommitmentRoot",
                        &serde_json::json!({
                            "fixture": "threshold-share-coefficient-vector",
                            "sourceTrusteeRosterPosition": source_trustee_roster_position,
                            "rnsLimbIndex": rns_limb_index,
                            "shamirCoefficientIndex": shamir_coefficient_index,
                        }),
                    ).expect("coefficient vector hash"),
                    "openingVerificationStatus": "pending-private-envelope-opening",
                }));
                coefficient_commitment_material.push(serde_json::json!({
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
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "commitmentRoot": commitment_root,
                    "commitment": setup_commitment_full_value(&commitment),
                }));
            }
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
            "sourceTrusteeIdentity": source_trustee_identity,
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "coefficientCommitments": coefficient_commitments,
        });
        source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
            derive_protocol_hash("VssCoefficientCommitmentRoot", &source_trustee_record)
                .expect("source trustee commitment root")
        );
        source_trustee_records.push(source_trustee_record);
    }

    serde_json::json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeCoefficientCommitmentRecords": source_trustee_records,
        "coefficientCommitments": coefficient_commitment_material,
    })
}

fn encode_transport_material_from_request(request: &serde_json::Value) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend(b"SLVSSMAT");
    crate::encoding::append_varuint(&mut output, 1);
    crate::encoding::append_varuint(&mut output, 10);
    crate::encoding::append_varuint(&mut output, 4);
    crate::encoding::append_varuint(&mut output, DATA_PRIMES.len() as u64);
    let ring_degree = request["coefficientCommitments"][0]["commitment"]["ringDegree"]
        .as_u64()
        .expect("ring degree");
    let material_records = request["coefficientCommitments"]
        .as_array()
        .expect("coefficient material records");
    let first_commitment_limbs = material_records[0]["commitment"]["commitmentLimbs"]
        .as_array()
        .expect("commitment limbs");
    let commitment_row_count = first_commitment_limbs[0]["rows"]
        .as_array()
        .expect("commitment rows")
        .len();
    crate::encoding::append_varuint(&mut output, ring_degree);
    crate::encoding::append_varuint(&mut output, first_commitment_limbs.len() as u64);
    crate::encoding::append_varuint(&mut output, commitment_row_count as u64);
    for source_trustee_roster_position in 0..10_u64 {
        for rns_limb_index in 0..DATA_PRIMES.len() {
            for shamir_coefficient_index in 0..4_u64 {
                let record_index = (((source_trustee_roster_position as usize)
                    * DATA_PRIMES.len()
                    + rns_limb_index)
                    * 4)
                    + shamir_coefficient_index as usize;
                let commitment = &material_records[record_index]["commitment"];
                crate::encoding::append_varuint(&mut output, source_trustee_roster_position);
                crate::encoding::append_varuint(&mut output, rns_limb_index as u64);
                crate::encoding::append_varuint(&mut output, shamir_coefficient_index);
                let commitment_limbs = commitment["commitmentLimbs"]
                    .as_array()
                    .expect("commitment limbs");
                for limb in commitment_limbs {
                    crate::encoding::append_varuint(
                        &mut output,
                        limb["commitmentModulusIndex"]
                            .as_u64()
                            .expect("commitment modulus index"),
                    );
                    output.extend(
                        limb["modulus"]
                            .as_u64()
                            .expect("commitment modulus")
                            .to_le_bytes(),
                    );
                    for row in limb["rows"].as_array().expect("commitment rows") {
                        for coefficient in row.as_array().expect("commitment row coefficients") {
                            output.extend(
                                coefficient
                                    .as_u64()
                                    .expect("commitment coefficient")
                                    .to_le_bytes(),
                            );
                        }
                    }
                }
            }
        }
    }

    output
}

fn transported_material_value(material_bytes: &[u8]) -> serde_json::Value {
    let chunks = material_bytes
        .chunks(1_048_576)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let transport_hashes =
        crate::bgv::setup::threshold_share_commitments::setup_vss_material_transport_hashes(
            &chunks, 1_048_576,
        )
        .expect("transport hashes");

    serde_json::json!({
        "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
        "objectVersion": 1,
        "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
        "chunkSizeBytes": 1_048_576,
        "chunkCount": chunks.len(),
        "totalByteLength": material_bytes.len(),
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkHashes": transport_hashes.chunk_hashes,
        "chunkRoot": transport_hashes.chunk_root,
        "chunks": chunks.iter().enumerate().map(|(chunk_index, chunk)| {
            serde_json::json!({
                "chunkIndex": chunk_index,
                "bytesHex": crate::hashing::to_hex(chunk),
            })
        }).collect::<Vec<_>>(),
    })
}

fn transported_material_manifest_value(
    transported_material: &serde_json::Value,
) -> serde_json::Value {
    let mut manifest = transported_material.clone();
    manifest
        .as_object_mut()
        .expect("transported material object")
        .remove("chunks");

    manifest
}

fn transported_material_stream_template_value(
    transported_material: &serde_json::Value,
) -> serde_json::Value {
    let mut template = transported_material_manifest_value(transported_material);
    let template_object = template
        .as_object_mut()
        .expect("transported material object");
    template_object.remove("fullObjectHash");
    template_object.remove("chunkHashes");
    template_object.remove("chunkRoot");

    template
}

fn vss_commitment_root_from_derivation_request(request: &serde_json::Value) -> String {
    let setup_context = &request["setupContext"];
    let mut commitment_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
        "publicMatrixSeedHash": request["publicMatrixSeedHash"],
        "participantCount": 10,
        "thresholdDegree": 4,
        "rnsLimbCount": DATA_PRIMES.len(),
        "sourceTrusteeRecords": request["sourceTrusteeCoefficientCommitmentRecords"],
    });
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        commitment_set[field_name] = setup_context[field_name].clone();
    }

    derive_protocol_hash("VssCoefficientCommitmentRoot", &commitment_set)
        .expect("VSS commitment root")
}

fn threshold_coefficient_message_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    rns_prime: u64,
    ring_degree: usize,
) -> Vec<u64> {
    (0..ring_degree)
        .map(|coefficient_position| {
            let value = ((source_trustee_roster_position + 1) * 17)
                + ((rns_limb_index as u64 + 1) * 5)
                + ((shamir_coefficient_index + 1) * 3)
                + (coefficient_position as u64 % 11);
            value % rns_prime
        })
        .collect()
}

fn threshold_randomness_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i128>> {
    (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
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
