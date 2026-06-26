use super::super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn public_evaluation_key_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let relinearization_rounds = &package["relinearizationKeyShareRounds"];
    let relinearization_rounds_root = relinearization_rounds["relinearizationKeyShareRoundsRoot"]
        .as_str()
        .expect("relinearization rounds root");
    let relinearization_key_roots = schedule["relinearizationLevelSchedule"]
        .as_array()
        .expect("relinearization schedule")
        .iter()
        .map(|level_entry| {
            let level = level_entry["level"].as_u64().expect("relinearization level");
            let decomposition_digit_count = level + 1;
            let round_one_aggregate_root = relinearization_rounds["roundOneAggregateRoots"]
                .as_array()
                .expect("round-one aggregate roots")
                .iter()
                .find(|entry| entry["level"].as_u64() == Some(level))
                .and_then(|entry| entry["roundOneAggregateRoot"].as_str())
                .expect("round-one aggregate root");
            let round_two_aggregate_root = relinearization_rounds["roundTwoAggregateRoots"]
                .as_array()
                .expect("round-two aggregate roots")
                .iter()
                .find(|entry| entry["level"].as_u64() == Some(level))
                .and_then(|entry| entry["roundTwoAggregateRoot"].as_str())
                .expect("round-two aggregate root");
            // The hash preimage must match the verifier's recompute in
            // accepted_setup::evaluation_key_material_transport::expected_roots
            // exactly: object type/version, parameter ids, the material encoding
            // constant, the three binding roots, the rounds root, the level, the
            // digit/limb counts, and the two aggregate roots. No extra narration
            // fields are bound.
            let relinearization_key_root = derive_canonical_object_hash(&serde_json::json!({
                    "objectType": "RelinearizationKeyAggregate",
                    "objectVersion": 1,
                    "materialEncoding": "root-bound-public-key-switch-component-roots",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                    "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                    "relinearizationKeyShareRoundsRoot": relinearization_rounds_root,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "roundOneAggregateRoot": round_one_aggregate_root,
                    "roundTwoAggregateRoot": round_two_aggregate_root,
                }),
            )
            .expect("relinearization key root");
            serde_json::json!({
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "roundOneAggregateRoot": round_one_aggregate_root,
                "roundTwoAggregateRoot": round_two_aggregate_root,
                "relinearizationKeyRoot": relinearization_key_root,
            })
        })
        .collect::<Vec<_>>();

    let mut galois_batches = package["galoisKeyShareBatches"]
        .as_array()
        .expect("Galois key share batches")
        .iter()
        .collect::<Vec<_>>();
    galois_batches.sort_by_key(|batch| {
        batch["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position")
    });
    let galois_key_share_batch_roots = galois_batches
        .iter()
        .map(|batch| {
            serde_json::json!({
                "trusteeIdentity": batch["trusteeIdentity"],
                "trusteeRosterPosition": batch["trusteeRosterPosition"],
                "galoisKeyShareBatchRoot": batch["galoisKeyShareBatchRoot"],
            })
        })
        .collect::<Vec<_>>();
    let galois_key_roots = schedule["requiredGaloisKeySchedule"]
        .as_array()
        .expect("required Galois key schedule")
        .iter()
        .map(|schedule_entry| {
            let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
            let level = schedule_entry["level"].as_u64().expect("level");
            let decomposition_digit_count = level + 1;
            let contributing_share_roots = galois_batches
                .iter()
                .map(|batch| {
                    let material_record = batch["galoisKeyShareMaterialRecords"]
                        .as_array()
                        .expect("Galois key share material records")
                        .iter()
                        .find(|material_record| {
                            material_record["rotation"].as_u64() == Some(rotation)
                                && material_record["level"].as_u64() == Some(level)
                        })
                        .expect("scheduled Galois material record");
                    serde_json::json!({
                        "trusteeIdentity": batch["trusteeIdentity"],
                        "trusteeRosterPosition": batch["trusteeRosterPosition"],
                        "galoisKeyShareRoot": material_record["galoisKeyShareRoot"],
                    })
                })
                .collect::<Vec<_>>();
            // The hash preimage must match the verifier's recompute in
            // expected_galois_key_roots_for_evaluation_keys exactly; no extra
            // narration fields are bound.
            let galois_key_root = derive_canonical_object_hash(&serde_json::json!({
                    "objectType": "GaloisKeyAggregate",
                    "objectVersion": 1,
                    "materialEncoding": "root-bound-public-key-switch-component-roots",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                    "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                    "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                    "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                    "rotation": rotation,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "contributingShareRoots": contributing_share_roots,
                }),
            )
            .expect("Galois key root");
            serde_json::json!({
                "rotation": rotation,
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "galoisKeyRoot": galois_key_root,
                "contributingShareRoots": contributing_share_roots,
            })
        })
        .collect::<Vec<_>>();

    let mut evaluation_keys = serde_json::json!({
        "objectType": "PublicEvaluationKeySet",
        "objectVersion": 1,
        "assemblyStatus": "assembled-from-proof-bearing-shares",
        "materialEncoding": "root-bound-public-key-switch-component-roots",
        "materialSource": "verified-relinearization-and-galois-proof-records",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": super::participant_count_from_package(package),
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
        "relinearizationKeyShareRoundsRoot": relinearization_rounds_root,
        "relinearizationLevelSchedule": schedule["relinearizationLevelSchedule"],
        "relinearizationKeyRoots": relinearization_key_roots,
        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
        "requiredGaloisKeySchedule": schedule["requiredGaloisKeySchedule"],
        "galoisKeyShareBatchRoots": galois_key_share_batch_roots,
        "galoisKeyRoots": galois_key_roots,
        "genericKeySwitchKeyRoots": [],
        "rawKeyBytesEmbedded": false,
        "verifierGeneratedKeyMaterial": false,
    });
    evaluation_keys["evaluationKeySetHash"] = serde_json::json!(
        derive_canonical_object_hash(&evaluation_keys).expect("evaluation key set hash")
    );

    evaluation_keys
}

pub(in super::super) fn add_public_evaluation_key_material_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let manifest = public_evaluation_key_material_manifest(package, &package["evaluationKeys"])
        .expect("public evaluation-key material manifest");
    let material_bytes = encode_public_evaluation_key_material_manifest(&manifest)
        .expect("public evaluation-key material bytes");
    let chunks = proof_bytes_transport_chunks(material_bytes);
    let transport_hashes = public_evaluation_key_material_transport_hashes(&chunks)
        .expect("public evaluation-key material transport hashes");
    let material_root = public_evaluation_key_material_reference_root(
        &package["evaluationKeys"],
        &manifest,
        &transport_hashes,
    )
    .expect("public evaluation-key material root");
    package["evaluationKeys"]["publicEvaluationKeyMaterialEncoding"] =
        serde_json::json!(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING);
    package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"] = serde_json::json!(material_root);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkSizeBytes"] =
        serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkCount"] =
        serde_json::json!(transport_hashes.chunk_hashes.len());
    package["evaluationKeys"]["publicEvaluationKeyMaterialTotalByteLength"] =
        serde_json::json!(transport_hashes.total_byte_length);
    package["evaluationKeys"]["publicEvaluationKeyMaterialFullObjectHash"] =
        serde_json::json!(transport_hashes.full_object_hash);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkRoot"] =
        serde_json::json!(transport_hashes.chunk_root);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkHashes"] =
        serde_json::json!(transport_hashes.chunk_hashes);
    package["evaluationKeys"]
        .as_object_mut()
        .expect("evaluation key set")
        .remove("evaluationKeySetHash");
    package["evaluationKeys"]["evaluationKeySetHash"] = serde_json::json!(
        derive_canonical_object_hash(&package["evaluationKeys"]).expect("evaluation key set hash")
    );
    append_setup_transport_certificate_object(
        package,
        SetupTransportCertificateObjectFixture {
            object_name: "publicEvaluationKeyMaterial",
            object_role: "public-evaluation-key-runtime-material",
            object_root: material_root.clone(),
            byte_length: transport_hashes.total_byte_length,
            full_object_hash: transport_hashes.full_object_hash.clone(),
            chunk_root: transport_hashes.chunk_root.clone(),
            chunk_hashes: transport_hashes.chunk_hashes.clone(),
        },
    );
    rebind_collective_setup_package_hash(package);

    serde_json::json!({
        "objectType": PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
        "publicEvaluationKeyMaterials": [{
            "objectType": PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE,
            "objectVersion": 1,
            "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
            "ceremonyId": package["evaluationKeys"]["ceremonyId"],
            "manifestHash": package["evaluationKeys"]["manifestHash"],
            "rosterHash": package["evaluationKeys"]["rosterHash"],
            "setupParametersHash": package["evaluationKeys"]["setupParametersHash"],
            "setupEpoch": package["evaluationKeys"]["setupEpoch"],
            "evaluationKeySetHash": package["evaluationKeys"]["evaluationKeySetHash"],
            "publicEvaluationKeyMaterialRoot": package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"],
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": package["evaluationKeys"]["publicEvaluationKeyMaterialChunkCount"],
            "totalByteLength": package["evaluationKeys"]["publicEvaluationKeyMaterialTotalByteLength"],
            "fullObjectHash": package["evaluationKeys"]["publicEvaluationKeyMaterialFullObjectHash"],
            "chunkRoot": package["evaluationKeys"]["publicEvaluationKeyMaterialChunkRoot"],
            "chunkHashes": package["evaluationKeys"]["publicEvaluationKeyMaterialChunkHashes"],
            "chunks": chunks
                .into_iter()
                .enumerate()
                .map(|(chunk_index, chunk)| serde_json::json!({
                    "chunkIndex": chunk_index,
                    "bytesHex": to_hex(&chunk),
                }))
                .collect::<Vec<_>>(),
        }],
    })
}
