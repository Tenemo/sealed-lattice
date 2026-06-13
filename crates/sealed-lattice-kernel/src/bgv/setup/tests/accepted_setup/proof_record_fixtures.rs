use super::*;
use rayon::prelude::*;

pub(super) fn setup_proof_binding_for_test_package(
    package: &serde_json::Value,
) -> serde_json::Value {
    let profile = describe_collective_bgv_setup_profile().expect("setup profile");
    assert_eq!(
        package["setupContext"]["setupProfileHash"],
        profile["setupProfileHash"]
    );
    setup_proof_record_binding_value(
        "CollectiveBgvSetup-v1",
        profile["setupProofProfileHash"]
            .as_str()
            .expect("setup proof profile hash"),
    )
    .expect("setup proof record binding")
}

pub(super) struct EvaluationKeyShareFixtureMaterial {
    pub(super) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    pub(super) component_vector_entries: Vec<serde_json::Value>,
    pub(super) component_vector_root: String,
}

// Build one key share's public component material so the trustee
// evaluation-key relation holds: for digit j and limb l,
// b = p * e_j - a_{j,l} (*) s + [l == j] * source_j, with the per-digit
// source supplied as exact lifted integers (round one and Galois) or as
// residues of the public-aggregate product (round two).
pub(super) fn evaluation_key_share_fixture_material(
    proof_family: EvaluationKeyShareProofFamily,
    trustee_roster_position: u64,
    level: u64,
    rotation: Option<u64>,
    ring_degree: usize,
    key_switch_seed_hex: &str,
    relinearization_source_by_digit: Option<&[Vec<i128>]>,
) -> EvaluationKeyShareFixtureMaterial {
    let level = usize::try_from(level).expect("level fits usize");
    let secret_coefficients =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
    let secret_i128 = secret_coefficients
        .iter()
        .map(|coefficient| i128::from(*coefficient))
        .collect::<Vec<_>>();
    let key_switch_domain = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => "relinearization".to_string(),
        EvaluationKeyShareProofFamily::Galois => {
            format!("galois-{}", rotation.expect("Galois rotation"))
        }
    };
    let source_by_digit: Vec<Vec<i128>> = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => relinearization_source_by_digit
            .expect("relinearization source coefficients")
            .to_vec(),
        EvaluationKeyShareProofFamily::Galois => {
            let galois_source = automorphism_i128_for_evaluation_key_fixture(
                &secret_i128,
                usize::try_from(rotation.expect("Galois rotation")).expect("rotation fits usize"),
            )
            .expect("Galois source");
            vec![galois_source; level + 1]
        }
    };
    assert_eq!(source_by_digit.len(), level + 1);
    let mut component_b_by_digit = Vec::new();
    for (digit_index, digit_source) in source_by_digit.iter().enumerate() {
        let error_coefficients = evaluation_key_error_coefficients_for_fixture(
            proof_family,
            trustee_roster_position,
            level,
            rotation,
            digit_index,
            ring_degree,
        );
        let component_b_by_limb = (0..=level)
            .map(|rns_limb_index| {
                let source_for_limb = if rns_limb_index == digit_index {
                    digit_source.clone()
                } else {
                    vec![0_i128; ring_degree]
                };
                key_switch_component_b_for_evaluation_key_fixture(KeySwitchComponentBFixtureInput {
                    key_switch_domain: &key_switch_domain,
                    key_switch_seed_hex,
                    digit_index,
                    source_coefficients: &source_for_limb,
                    secret_coefficients: &secret_coefficients,
                    error_coefficients: &error_coefficients,
                    modulus: DATA_PRIMES[rns_limb_index],
                    ring_degree,
                })
                .expect("evaluation-key component b")
            })
            .collect::<Vec<_>>();
        component_b_by_digit.push(component_b_by_limb);
    }
    let (component_vector_entries, component_vector_root) = evaluation_key_component_vector_entries(
        proof_family,
        &key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &component_b_by_digit,
    );

    EvaluationKeyShareFixtureMaterial {
        component_b_by_digit,
        component_vector_entries,
        component_vector_root,
    }
}

pub(super) fn evaluation_key_secret_coefficients_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
) -> Vec<i64> {
    (0..ring_degree)
        .map(|coefficient_position| {
            accepted_vss_secret_coefficient_fixture(trustee_roster_position, coefficient_position)
        })
        .collect()
}

// Round-one sources: the trustee secret on every digit diagonal.
pub(super) fn relinearization_round_one_source_by_digit_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
    digit_count: usize,
) -> Vec<Vec<i128>> {
    let secret_i128 =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree)
            .into_iter()
            .map(i128::from)
            .collect::<Vec<_>>();

    vec![secret_i128; digit_count]
}

// Round-two sources: the trustee secret times the PUBLIC round-one aggregate
// diagonal, computed per digit field exactly as the package verifier
// recomputes it, so each trustee forms its round-two share from public
// material only.
pub(super) fn relinearization_round_two_source_by_digit_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
    round_one_aggregate_diagonals: &[Vec<u64>],
) -> Vec<Vec<i128>> {
    let secret =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
    round_one_aggregate_diagonals
        .iter()
        .enumerate()
        .map(|(digit_index, aggregate_diagonal)| {
            let modulus = DATA_PRIMES[digit_index];
            let secret_residues = secret
                .iter()
                .map(|coefficient| signed_i64_residue_for_fixture(*coefficient, modulus))
                .collect::<Vec<_>>();
            negacyclic_product_mod(&secret_residues, aggregate_diagonal, modulus)
                .expect("round-two aggregate source product")
                .into_iter()
                .map(i128::from)
                .collect()
        })
        .collect()
}

// The public round-one aggregate diagonals recomputed from the package
// records through the same path the verifier uses.
pub(super) fn round_one_aggregate_diagonals_from_fixture_package(
    package: &serde_json::Value,
    transported_component_material: Option<&serde_json::Value>,
) -> BTreeMap<u64, Vec<Vec<u64>>> {
    round_one_public_aggregate_diagonals_from_package(package, transported_component_material)
        .expect("round-one public aggregate diagonals")
}

fn evaluation_key_error_coefficients_for_fixture(
    proof_family: EvaluationKeyShareProofFamily,
    trustee_roster_position: u64,
    level: usize,
    rotation: Option<u64>,
    digit_index: usize,
    ring_degree: usize,
) -> Vec<i64> {
    let family_offset = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => 13_usize,
        EvaluationKeyShareProofFamily::Galois => {
            usize::try_from(rotation.expect("Galois rotation")).expect("rotation fits usize") % 17
        }
    };
    (0..ring_degree)
        .map(|coefficient_position| {
            match (trustee_roster_position as usize * 41
                + level * 19
                + digit_index * 7
                + coefficient_position * 5
                + family_offset)
                % 5
            {
                0 => -2,
                1 => -1,
                2 => 0,
                3 => 1,
                _ => 2,
            }
        })
        .collect()
}

fn evaluation_key_component_vector_entries(
    proof_family: EvaluationKeyShareProofFamily,
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> (Vec<serde_json::Value>, String) {
    let entries = component_b_by_digit
        .iter()
        .enumerate()
        .flat_map(|(digit_index, component_b_by_limb)| {
            component_b_by_limb
                .iter()
                .enumerate()
                .map(move |(rns_limb_index, coefficients)| {
                    serde_json::json!({
                        "digitIndex": digit_index,
                        "rnsLimbIndex": rns_limb_index,
                        "rnsPrime": DATA_PRIMES[rns_limb_index],
                        "component": "b",
                        "coefficientByteLength": ring_degree * 8,
                        "coefficientVectorHash512": evaluation_key_share_component_vector_hash(coefficients),
                        "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
                    })
                })
        })
        .collect::<Vec<_>>();
    let root = evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &entries,
    )
    .expect("evaluation-key component vector root");

    (entries, root)
}

pub(super) fn relinearization_key_switch_seed_for_test(
    schedule: &serde_json::Value,
    round: &str,
    level: u64,
) -> String {
    derive_protocol_hash(
        "RelinearizationKeyShareSeed",
        &serde_json::json!({
            "objectType": "RelinearizationKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "relinearization-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-level-and-round",
            "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
            "relinearizationCrpRoot": schedule["relinearizationCrpRoot"],
            "round": round,
            "level": level,
        }),
    )
    .expect("relinearization key-switch seed")
}

pub(super) fn galois_key_switch_seed_for_test(
    schedule: &serde_json::Value,
    rotation: u64,
    level: u64,
) -> String {
    derive_protocol_hash(
        "GaloisKeyShareSeed",
        &serde_json::json!({
            "objectType": "GaloisKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "galois-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-rotation-and-level",
            "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
            "galoisKeyCrpRoot": schedule["galoisKeyCrpRoot"],
            "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
            "rotation": rotation,
            "level": level,
        }),
    )
    .expect("Galois key-switch seed")
}

pub(super) fn relinearization_key_share_rounds_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    relinearization_key_share_rounds_object_inner(package, None)
}

pub(super) fn relinearization_key_share_rounds_object_with_terminal_transport(
    package: &serde_json::Value,
    terminal_transport: &mut TerminalEvaluationKeyTransportSinks,
) -> serde_json::Value {
    relinearization_key_share_rounds_object_inner(package, Some(terminal_transport))
}

pub(super) fn galois_key_share_batches_object(package: &serde_json::Value) -> serde_json::Value {
    galois_key_share_batches_object_inner(package, None)
}

pub(super) fn galois_key_share_batches_object_with_terminal_transport(
    package: &serde_json::Value,
    terminal_transport: &mut TerminalEvaluationKeyTransportSinks,
) -> serde_json::Value {
    galois_key_share_batches_object_inner(package, Some(terminal_transport))
}

pub(super) fn public_evaluation_key_set_object(package: &serde_json::Value) -> serde_json::Value {
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
            let relinearization_key_root = derive_protocol_hash(
                "RelinearizationKeyRoot",
                &serde_json::json!({
                    "objectType": "RelinearizationKeyAggregate",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                    "assemblyStatus": "assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate",
                    "materialEncoding": "root-bound-public-key-switch-component-roots",
                    "materialSource": "verified-relinearization-and-galois-proof-records",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                    "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
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
            let galois_key_root = derive_protocol_hash(
                "RotationKeyRoot",
                &serde_json::json!({
                    "objectType": "GaloisKeyAggregate",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                    "assemblyStatus": "assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate",
                    "materialEncoding": "root-bound-public-key-switch-component-roots",
                    "materialSource": "verified-relinearization-and-galois-proof-records",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                    "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
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
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "assemblyStatus": "assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate",
        "materialEncoding": "root-bound-public-key-switch-component-roots",
        "materialSource": "verified-relinearization-and-galois-proof-records",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
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
        derive_protocol_hash("EvaluationKeySetHash", &evaluation_keys)
            .expect("evaluation key set hash")
    );

    evaluation_keys
}

pub(super) fn add_public_evaluation_key_material_transport(
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
        derive_protocol_hash("EvaluationKeySetHash", &package["evaluationKeys"])
            .expect("evaluation key set hash")
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
    rebind_setup_key_correctness_certificate(package);
    rebind_collective_setup_package_hash(package);

    serde_json::json!({
        "objectType": PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
        "publicEvaluationKeyMaterials": [{
            "objectType": PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
            "ceremonyId": package["evaluationKeys"]["ceremonyId"],
            "manifestHash": package["evaluationKeys"]["manifestHash"],
            "rosterHash": package["evaluationKeys"]["rosterHash"],
            "setupProfileHash": package["evaluationKeys"]["setupProfileHash"],
            "qShareHash": package["evaluationKeys"]["qShareHash"],
            "carryAwareVssShareRelationProfileHash": package["evaluationKeys"]["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": package["evaluationKeys"]["commitmentProfileHash"],
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

pub(super) fn collective_public_key_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let material_records = package["publicKeyShareMaterial"]["shareMaterialRecords"]
        .as_array()
        .expect("public-key material records");
    let ring_degree = package["publicKeyShareMaterial"]["ringDegree"]
        .as_u64()
        .expect("ring degree") as usize;
    let mut source_roots = Vec::new();
    let mut aggregate_coefficients_by_limb = (0..DATA_PRIMES.len())
        .map(|_| vec![0_u64; ring_degree])
        .collect::<Vec<_>>();
    for material_record in material_records {
        source_roots.push(serde_json::json!({
            "trusteeIdentity": material_record["trusteeIdentity"],
            "trusteeRosterPosition": material_record["trusteeRosterPosition"],
            "publicKeyShareRoot": material_record["publicKeyShareRoot"],
            "publicKeyShareMaterialRoot": material_record["publicKeyShareMaterialRoot"],
        }));
        for (rns_limb_index, limb) in material_record["shareCoefficientVectorsByLimb"]
            .as_array()
            .expect("share limbs")
            .iter()
            .enumerate()
        {
            let coefficients = coefficient_vector_from_le_hex(
                limb["coefficientsLeHex"].as_str().expect("coefficient hex"),
                ring_degree,
                "public-key share coefficient width",
            )
            .expect("public-key share coefficients");
            for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
                aggregate_coefficients_by_limb[rns_limb_index][coefficient_index] = add_mod(
                    aggregate_coefficients_by_limb[rns_limb_index][coefficient_index],
                    *coefficient,
                    DATA_PRIMES[rns_limb_index],
                )
                .expect("aggregate public-key coefficient");
            }
        }
    }
    let aggregate_limbs = aggregate_coefficients_by_limb
        .iter()
        .enumerate()
        .map(|(rns_limb_index, coefficients)| {
            serde_json::json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "component": "b",
                "coefficientByteLength": ring_degree * 8,
                "coefficientVectorHash512": public_key_share_coefficient_vector_hash(coefficients),
                "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
            })
        })
        .collect::<Vec<_>>();
    let mut collective_public_key = serde_json::json!({
        "objectType": "CollectivePublicKey",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofVerificationStatus": PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "aggregationStatus": "lnp-proof-aggregated-with-accepted-setup-proof-accounting",
        "materialEncoding": "embedded-full-collective-public-key-coefficients",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "publicKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"],
        "publicAPolynomialRoot": package["commonRandomness"]["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"],
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareProofSetRoot": package["publicKeyShareProofs"]["publicKeyShareProofSetRoot"],
        "publicKeyShareMaterialSetRoot": package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"],
        "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
        "sourceShareMaterialRoots": source_roots,
        "aggregateCoefficientVectorsByLimb": aggregate_limbs,
    });
    collective_public_key["collectivePublicKeyRoot"] = serde_json::json!(
        derive_protocol_hash("CollectivePublicKeyRoot", &collective_public_key)
            .expect("collective public-key root")
    );

    collective_public_key
}

pub(super) fn replace_public_key_share_hashes_with_material_hashes(
    package: &mut serde_json::Value,
) {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash")
        .to_string();
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    for trustee_roster_position in 0..10_u64 {
        let (coefficients_by_limb, _) = public_key_share_coefficients_and_errors_for_fixture(
            &public_matrix_seed_hash,
            trustee_roster_position,
            ring_degree,
        );
        let share_hashes = coefficients_by_limb
            .iter()
            .enumerate()
            .map(|(rns_limb_index, coefficients)| {
                serde_json::json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": DATA_PRIMES[rns_limb_index],
                    "component": "b_i",
                    "coefficientVectorHash512": public_key_share_coefficient_vector_hash(coefficients),
                })
            })
            .collect::<Vec<_>>();
        package["publicKeyShares"]["shareRecords"][trustee_roster_position as usize]["shareCoefficientVectorHash512ByLimb"] =
            serde_json::json!(share_hashes);
    }
    rebind_collective_public_key_share_roots(package);
    for trustee_roster_position in 0..10_usize {
        package["publicKeyShareProofs"]["proofRecords"][trustee_roster_position]
            ["publicKeyShareRoot"] =
            package["publicKeyShares"]["shareRecords"][trustee_roster_position]
                ["publicKeyShareRoot"]
                .clone();
    }
    package["publicKeyShareProofs"]["publicKeyShareSetRoot"] =
        package["publicKeyShares"]["publicKeyShareSetRoot"].clone();
    rebind_collective_public_key_share_proof_roots(package);
    package["evaluatorKeySchedule"]["publicKeyShareSetRoot"] =
        package["publicKeyShares"]["publicKeyShareSetRoot"].clone();
    package["evaluatorKeySchedule"]["publicKeyShareProofSetRoot"] =
        package["publicKeyShareProofs"]["publicKeyShareProofSetRoot"].clone();
    rebind_collective_evaluator_key_schedule_root(package);
}

pub(super) fn public_key_share_material_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let public_key_crp_root =
        package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"]
            .as_str()
            .expect("public-key CRP root");
    let public_a_polynomial_root =
        package["commonRandomness"]["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"]
            .as_str()
            .expect("public a root");
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    let mut material_records = Vec::new();
    let mut material_roots = Vec::new();
    for trustee_roster_position in 0..10_u64 {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let (coefficients_by_limb, _) = public_key_share_coefficients_and_errors_for_fixture(
            public_matrix_seed_hash,
            trustee_roster_position,
            ring_degree,
        );
        let limbs = coefficients_by_limb
            .iter()
            .enumerate()
            .map(|(rns_limb_index, coefficients)| {
                serde_json::json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": DATA_PRIMES[rns_limb_index],
                    "component": "b_i",
                    "coefficientByteLength": ring_degree * 8,
                    "coefficientVectorHash512": public_key_share_coefficient_vector_hash(coefficients),
                    "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
                })
            })
            .collect::<Vec<_>>();
        let mut material_record = serde_json::json!({
            "objectType": "PublicKeyShareMaterial",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "public-key-share",
            "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
            "materialEncoding": "embedded-full-public-key-share-coefficients",
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "qShareHash": setup_context["qShareHash"],
            "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": setup_context["commitmentProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "rnsLimbCount": DATA_PRIMES.len(),
            "ringDegree": ring_degree,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicKeyCrpRoot": public_key_crp_root,
            "publicAPolynomialRoot": public_a_polynomial_root,
            "publicKeyShareRoot": package["publicKeyShares"]["shareRecords"][trustee_roster_position as usize]["publicKeyShareRoot"],
            "shareCoefficientVectorsByLimb": limbs,
        });
        material_record["publicKeyShareMaterialRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareRoot", &material_record)
                .expect("public-key share material root")
        );
        material_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareMaterialRoot": material_record["publicKeyShareMaterialRoot"],
        }));
        material_records.push(material_record);
    }
    let mut material_set = serde_json::json!({
        "objectType": "PublicKeyShareMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "materialEncoding": "embedded-full-public-key-share-coefficients",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_key_crp_root,
        "publicAPolynomialRoot": public_a_polynomial_root,
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareMaterialRoots": material_roots,
        "shareMaterialRecords": material_records,
    });
    material_set["publicKeyShareMaterialSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareRoot", &material_set)
            .expect("public-key share material set root")
    );

    material_set
}

pub(super) fn public_key_share_coefficients_and_errors_for_fixture(
    public_matrix_seed_hash: &str,
    trustee_roster_position: u64,
    ring_degree: usize,
) -> (Vec<Vec<u64>>, Vec<Vec<i64>>) {
    let mut coefficients_by_limb = Vec::new();
    let mut error_coefficients_by_limb = Vec::new();
    for (rns_limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let secret_residues = (0..ring_degree)
            .map(|coefficient_position| {
                signed_i64_residue_for_fixture(
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    ),
                    modulus,
                )
            })
            .collect::<Vec<_>>();
        let public_a =
            dense_public_residues(public_matrix_seed_hash, "accepted-bgv-public-a", modulus)
                .into_iter()
                .take(ring_degree)
                .collect::<Vec<_>>();
        let product = negacyclic_product_mod(&public_a, &secret_residues, modulus)
            .expect("public-key product");
        let errors = (0..ring_degree)
            .map(|coefficient_position| {
                accepted_public_key_error_coefficient_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    coefficient_position,
                )
            })
            .collect::<Vec<_>>();
        let coefficients = errors
            .iter()
            .zip(product.iter())
            .map(|(error, product_coefficient)| {
                let scaled_error = mul_mod(
                    PLAINTEXT_MODULUS % modulus,
                    signed_i64_residue_for_fixture(*error, modulus),
                    modulus,
                )
                .expect("scaled error");
                sub_mod(scaled_error, *product_coefficient, modulus).expect("public-key share")
            })
            .collect::<Vec<_>>();
        coefficients_by_limb.push(coefficients);
        error_coefficients_by_limb.push(errors);
    }

    (coefficients_by_limb, error_coefficients_by_limb)
}

fn accepted_public_key_error_coefficient_fixture(
    trustee_roster_position: u64,
    rns_limb_index: usize,
    coefficient_position: usize,
) -> i64 {
    match (trustee_roster_position as usize * 37 + rns_limb_index * 11 + coefficient_position * 5)
        % 5
    {
        0 => -2,
        1 => -1,
        2 => 0,
        3 => 1,
        _ => 2,
    }
}

fn signed_i64_residue_for_fixture(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        u64::try_from(value).expect("non-negative value") % modulus
    } else {
        let magnitude = value.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}

pub(super) fn same_secret_proofs_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let per_trustee_records = (0..10_u64)
        .into_par_iter()
        .map(|trustee_roster_position| {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let statement_record = &statement_records[trustee_roster_position as usize];
        let constant_commitments =
            same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
        let ring_degree = constant_commitments
            .first()
            .expect("constant commitment")
            .ring_degree;
        let statement = crate::bgv::setup::trustee_evaluation_key_proof::TrusteeEvaluationKeyStatement {
            context: crate::bgv::setup::trustee_evaluation_key_proof::SuccinctSetupProofContext {
                proof_family:
                    crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY
                        .to_string(),
                ceremony_id: setup_context["ceremonyId"]
                    .as_str()
                    .expect("ceremony id")
                    .to_string(),
                manifest_hash: setup_context["manifestHash"]
                    .as_str()
                    .expect("manifest hash")
                    .to_string(),
                roster_hash: setup_context["rosterHash"]
                    .as_str()
                    .expect("roster hash")
                    .to_string(),
                trustee_identity: trustee_identity.clone(),
                trustee_roster_position,
                setup_epoch: setup_context["setupEpoch"]
                    .as_str()
                    .expect("setup epoch")
                    .to_string(),
                binding_roots: vec![(
                    "vssCoefficientCommitmentMaterialRoot".to_string(),
                    package["vssCoefficientCommitmentMaterial"]
                        ["vssCoefficientCommitmentMaterialRoot"]
                        .as_str()
                        .expect("vss material root")
                        .to_string(),
                )],
            },
            ring_degree,
            keys: Vec::new(),
            same_secret_linkage: Some(
                crate::bgv::setup::trustee_evaluation_key_proof::SameSecretLinkageStatement {
                    public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
                    commitments: constant_commitments,
                },
            ),
        };
        let witness = TrusteeEvaluationKeyWitness {
            secret_coefficients: (0..ring_degree)
                .map(|coefficient_position| {
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    )
                })
                .collect(),
            error_coefficients_by_key: Vec::new(),
            negative_indicator_coefficients: (0..ring_degree)
                .map(|coefficient_position| {
                    i64::from(
                        accepted_vss_secret_coefficient_fixture(
                            trustee_roster_position,
                            coefficient_position,
                        ) < 0,
                    )
                })
                .collect(),
            opening_randomness_by_limb: (0..DATA_PRIMES.len())
                .map(|rns_limb_index| {
                    accepted_vss_randomness_fixture(
                        trustee_roster_position,
                        rns_limb_index,
                        0,
                        ring_degree,
                    )
                    .into_iter()
                    .map(|column| {
                        column
                            .into_iter()
                            .map(|value| {
                                i64::try_from(value).expect("ternary randomness fits i64")
                            })
                            .collect()
                    })
                    .collect()
                })
                .collect(),
        };
        let proof_randomness_seed_hex = derive_protocol_hash(
            "SameSecretProofRoot",
            &serde_json::json!({
                "fixture": "same-secret-internal-proof-randomness",
                "trusteeRosterPosition": trustee_roster_position,
            }),
        )
        .expect("same-secret proof randomness seed");
        let proof = prove_evaluation_key_share(&statement, &witness, &proof_randomness_seed_hex)
            .expect("same-secret anchor proof");
        let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
        let proof_size_bytes = u64::try_from(proof_bytes.len()).expect("proof size bytes");
        let proof_bytes_hash =
            crate::bgv::setup::trustee_evaluation_key_proof::same_secret_anchor_proof_bytes_hash(
                &proof_bytes,
            );
        let mut proof_record = serde_json::json!({
            "objectType": "SameSecretProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily":
                crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
            "proofVerificationStatus":
                crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_VERIFICATION_STATUS,
            "proofModelStatus":
                crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_MODEL_STATUS,
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "qShareHash": setup_context["qShareHash"],
            "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": setup_context["commitmentProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": statement_record["sameSecretProofFamilyBindingRoot"],
            "statementHash": to_hex(&statement.statement_hash()),
            "proofSizeBytes": proof_size_bytes,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesHex": to_hex(&proof_bytes),
        });
        proof_record["sameSecretProofRoot"] = serde_json::json!(
            derive_protocol_hash("SameSecretProofRoot", &proof_record)
                .expect("same-secret proof root")
        );
        let proof_root_entry = serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
        });
        terminal_phase(&format!("generated same-secret proof trustee {trustee_roster_position}"));

        (proof_root_entry, proof_record)
        })
        .collect::<Vec<_>>();
    let mut proof_records = Vec::new();
    let mut same_secret_proof_roots = Vec::new();
    for (proof_root_entry, proof_record) in per_trustee_records {
        same_secret_proof_roots.push(proof_root_entry);
        proof_records.push(proof_record);
    }
    let mut proof_set = serde_json::json!({
        "objectType": "SameSecretProofSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily":
            crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
        "proofVerificationStatus":
            crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_VERIFICATION_STATUS,
        "proofModelStatus":
            crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_MODEL_STATUS,
        "proofAccountingHash":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_hash()
                .expect("same-secret anchor accounting hash"),
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "vssCoefficientCommitmentMaterialRoot": package["vssCoefficientCommitmentMaterial"]["vssCoefficientCommitmentMaterialRoot"],
        "sameSecretProofRoots": same_secret_proof_roots,
        "proofRecords": proof_records,
    });
    proof_set["sameSecretProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("SameSecretProofRoot", &proof_set)
            .expect("same-secret proof set root")
    );

    proof_set
}

fn relinearization_key_share_rounds_object_inner(
    package: &serde_json::Value,
    mut terminal_transport: Option<&mut TerminalEvaluationKeyTransportSinks>,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let level_schedule = schedule["relinearizationLevelSchedule"]
        .as_array()
        .expect("relinearization level schedule");
    let scheduled_levels = level_schedule
        .iter()
        .map(|level_entry| level_entry["level"].as_u64().expect("level"))
        .collect::<Vec<_>>();

    let mut round_one_records = Vec::new();
    let mut round_one_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    let mut round_one_share_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_record_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_aggregate_diagonals_by_level = BTreeMap::<u64, Vec<Vec<u64>>>::new();
    for level in &scheduled_levels {
        let level = *level;
        for proof_record in same_secret_proofs {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let ring_degree =
                same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
            let key_switch_seed_hex =
                relinearization_key_switch_seed_for_test(schedule, "round-one", level);
            let relinearization_source = relinearization_round_one_source_by_digit_for_fixture(
                trustee_roster_position,
                ring_degree,
                usize::try_from(level).expect("level fits usize") + 1,
            );
            let fixture_material = evaluation_key_share_fixture_material(
                EvaluationKeyShareProofFamily::Relinearization,
                trustee_roster_position,
                level,
                None,
                ring_degree,
                &key_switch_seed_hex,
                Some(&relinearization_source),
            );
            let aggregate_diagonals = round_one_aggregate_diagonals_by_level
                .entry(level)
                .or_insert_with(|| {
                    vec![
                        vec![0_u64; ring_degree];
                        usize::try_from(level).expect("level fits usize") + 1
                    ]
                });
            for (digit_index, aggregate) in aggregate_diagonals.iter_mut().enumerate() {
                for (accumulated, value) in aggregate
                    .iter_mut()
                    .zip(fixture_material.component_b_by_digit[digit_index][digit_index].iter())
                {
                    *accumulated = add_mod(*accumulated, *value, DATA_PRIMES[digit_index])
                        .expect("round-one aggregate accumulation");
                }
            }
            let round_one_share_root = fixture_material.component_vector_root.clone();
            let mut record = serde_json::json!({
                "objectType": "RelinearizationKeyShareRoundOne",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "proofFamily": "relinearization-key-share",
                "proofVerificationStatus": EVALUATION_KEY_SHARE_RECORD_VERIFICATION_STATUS,
                "proofModelStatus": TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS,
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "level": level,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
                "roundOneShareRoot": round_one_share_root,
                "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                "keySwitchDomain": "relinearization",
                "keySwitchSeedHex": key_switch_seed_hex,
                "ringDegree": ring_degree,
                "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                "keySwitchComponentVectors": fixture_material.component_vector_entries,
            });
            if let Some(sinks) = terminal_transport.as_deref_mut() {
                let transported_component_material_set =
                    move_evaluation_key_share_component_vectors_to_compact_transport(
                        &mut record,
                        EvaluationKeyShareProofFamily::Relinearization,
                        &fixture_material,
                    );
                sinks.component_materials.extend(
                    transported_component_material_set["componentMaterials"]
                        .as_array()
                        .expect("component materials")
                        .iter()
                        .cloned(),
                );
            }
            record["roundOneRecordRoot"] = serde_json::json!(
                derive_protocol_hash("RelinearizationRoundOneRecordRoot", &record)
                    .expect("round-one record root")
            );
            let record_root = record["roundOneRecordRoot"]
                .as_str()
                .expect("round-one record root")
                .to_string();
            round_one_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "roundOneRecordRoot": record_root,
                }));
            round_one_share_roots.insert((level, trustee_roster_position), round_one_share_root);
            round_one_record_roots.insert((level, trustee_roster_position), record_root);
            round_one_records.push(record);
        }
    }
    let mut round_one_aggregate_roots = Vec::new();
    let mut round_one_aggregate_root_by_level = BTreeMap::new();
    for level in &scheduled_levels {
        let level = *level;
        let aggregate_root = derive_protocol_hash(
            "RelinearizationRoundOneAggregateRoot",
            &serde_json::json!({
                "objectType": "RelinearizationRoundOneAggregate",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "level": level,
                "roundOneRecordRoots": round_one_roots_by_level
                    .get(&level)
                    .expect("round-one roots by level"),
            }),
        )
        .expect("round-one aggregate root");
        round_one_aggregate_roots.push(serde_json::json!({
            "level": level,
            "roundOneAggregateRoot": aggregate_root,
        }));
        round_one_aggregate_root_by_level.insert(level, aggregate_root);
    }

    let mut round_two_records = Vec::new();
    let mut round_two_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    for level in &scheduled_levels {
        let level = *level;
        for proof_record in same_secret_proofs {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let ring_degree =
                same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
            let key_switch_seed_hex =
                relinearization_key_switch_seed_for_test(schedule, "round-two", level);
            let relinearization_source = relinearization_round_two_source_by_digit_for_fixture(
                trustee_roster_position,
                ring_degree,
                round_one_aggregate_diagonals_by_level
                    .get(&level)
                    .expect("round-one aggregate diagonals"),
            );
            let fixture_material = evaluation_key_share_fixture_material(
                EvaluationKeyShareProofFamily::Relinearization,
                trustee_roster_position,
                level,
                None,
                ring_degree,
                &key_switch_seed_hex,
                Some(&relinearization_source),
            );
            let round_two_share_root = fixture_material.component_vector_root.clone();
            let mut record = serde_json::json!({
                "objectType": "RelinearizationKeyShareRoundTwo",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "proofFamily": "relinearization-key-share",
                "proofVerificationStatus": EVALUATION_KEY_SHARE_RECORD_VERIFICATION_STATUS,
                "proofModelStatus": TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS,
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "level": level,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
                "roundOneShareRoot": round_one_share_roots
                    .get(&(level, trustee_roster_position))
                    .expect("round-one share root"),
                "roundOneRecordRoot": round_one_record_roots
                    .get(&(level, trustee_roster_position))
                    .expect("round-one record root"),
                "roundOneAggregateRoot": round_one_aggregate_root_by_level
                    .get(&level)
                    .expect("round-one aggregate root"),
                "roundTwoShareRoot": round_two_share_root,
                "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                "keySwitchDomain": "relinearization",
                "keySwitchSeedHex": key_switch_seed_hex,
                "ringDegree": ring_degree,
                "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                "keySwitchComponentVectors": fixture_material.component_vector_entries,
            });
            if let Some(sinks) = terminal_transport.as_deref_mut() {
                let transported_component_material_set =
                    move_evaluation_key_share_component_vectors_to_compact_transport(
                        &mut record,
                        EvaluationKeyShareProofFamily::Relinearization,
                        &fixture_material,
                    );
                sinks.component_materials.extend(
                    transported_component_material_set["componentMaterials"]
                        .as_array()
                        .expect("component materials")
                        .iter()
                        .cloned(),
                );
            }
            record["roundTwoRecordRoot"] = serde_json::json!(
                derive_protocol_hash("RelinearizationRoundTwoRecordRoot", &record)
                    .expect("round-two record root")
            );
            let record_root = record["roundTwoRecordRoot"]
                .as_str()
                .expect("round-two record root")
                .to_string();
            round_two_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "roundTwoRecordRoot": record_root,
                }));
            round_two_records.push(record);
        }
    }
    let round_two_aggregate_roots = scheduled_levels
        .iter()
        .map(|level| {
            let aggregate_root = derive_protocol_hash(
                "RelinearizationRoundTwoAggregateRoot",
                &serde_json::json!({
                    "objectType": "RelinearizationRoundTwoAggregate",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "level": level,
                    "roundOneAggregateRoot": round_one_aggregate_root_by_level
                        .get(level)
                        .expect("round-one aggregate root"),
                    "roundTwoRecordRoots": round_two_roots_by_level
                        .get(level)
                        .expect("round-two roots by level"),
                }),
            )
            .expect("round-two aggregate root");
            serde_json::json!({
                "level": level,
                "roundTwoAggregateRoot": aggregate_root,
            })
        })
        .collect::<Vec<_>>();

    let mut rounds = serde_json::json!({
        "objectType": "RelinearizationKeyShareRounds",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "relinearization-key-share",
        "proofVerificationStatus": EVALUATION_KEY_SHARE_RECORD_VERIFICATION_STATUS,
        "proofModelStatus": TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
        "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
        "relinearizationLevelSchedule": schedule["relinearizationLevelSchedule"],
        "roundOneAggregateRoots": round_one_aggregate_roots,
        "roundOneRecords": round_one_records,
        "roundTwoAggregateRoots": round_two_aggregate_roots,
        "roundTwoRecords": round_two_records,
    });
    rounds["relinearizationKeyShareRoundsRoot"] = serde_json::json!(
        derive_protocol_hash("RelinearizationKeyShareRoundsRoot", &rounds)
            .expect("relinearization rounds root")
    );

    rounds
}

fn galois_key_share_batches_object_inner(
    package: &serde_json::Value,
    mut terminal_transport: Option<&mut TerminalEvaluationKeyTransportSinks>,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let required_schedule = schedule["requiredGaloisKeySchedule"]
        .as_array()
        .expect("Galois key schedule");
    let batches = same_secret_proofs
        .iter()
        .map(|proof_record| {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let mut galois_key_share_material_records = Vec::new();
            let galois_key_share_roots = required_schedule
                .iter()
                .map(|schedule_entry| {
                    let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                    let level = schedule_entry["level"].as_u64().expect("level");
                    let ring_degree =
                        same_secret_constant_commitments_from_fixture_package(package, 0)[0]
                            .ring_degree;
                    let key_switch_seed_hex =
                        galois_key_switch_seed_for_test(schedule, rotation, level);
                    let fixture_material = evaluation_key_share_fixture_material(
                        EvaluationKeyShareProofFamily::Galois,
                        trustee_roster_position,
                        level,
                        Some(rotation),
                        ring_degree,
                        &key_switch_seed_hex,
                        None,
                    );
                    let root = fixture_material.component_vector_root.clone();
                    let mut material_record = serde_json::json!({
                        "objectType": "GaloisKeyShareMaterial",
                        "objectVersion": 1,
                        "setupProfileId": "CollectiveBgvSetup-v1",
                        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                        "proofFamily": "galois-key-share",
                        "trusteeIdentity": trustee_identity,
                        "trusteeRosterPosition": trustee_roster_position,
                        "rotation": rotation,
                        "level": level,
                        "galoisKeyShareRoot": root.clone(),
                        "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                        "keySwitchDomain": format!("galois-{rotation}"),
                        "keySwitchSeedHex": key_switch_seed_hex,
                        "ringDegree": ring_degree,
                        "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                        "keySwitchComponentVectors": fixture_material.component_vector_entries,
                    });
                    if let Some(sinks) = terminal_transport.as_deref_mut() {
                        let transported_component_material_set =
                            move_evaluation_key_share_component_vectors_to_compact_transport(
                                &mut material_record,
                                EvaluationKeyShareProofFamily::Galois,
                                &fixture_material,
                            );
                        sinks.component_materials.extend(
                            transported_component_material_set["componentMaterials"]
                                .as_array()
                                .expect("component materials")
                                .iter()
                                .cloned(),
                        );
                    }
                    galois_key_share_material_records.push(material_record);
                    serde_json::json!({
                        "rotation": schedule_entry["rotation"],
                        "level": schedule_entry["level"],
                        "galoisKeyShareRoot": root,
                    })
                })
                .collect::<Vec<_>>();
            let mut batch = serde_json::json!({
                "objectType": "GaloisKeyShareBatch",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "proofFamily": "galois-key-share",
                "proofVerificationStatus": EVALUATION_KEY_SHARE_RECORD_VERIFICATION_STATUS,
                "proofModelStatus": TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS,
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                "requiredGaloisKeySchedule": schedule["requiredGaloisKeySchedule"],
                "galoisKeyShareRoots": galois_key_share_roots,
                "galoisKeyShareMaterialRecords": galois_key_share_material_records,
            });
            batch["galoisKeyShareBatchRoot"] = serde_json::json!(
                derive_protocol_hash("GaloisKeyShareBatchRoot", &batch)
                    .expect("Galois key share batch root")
            );
            batch
        })
        .collect::<Vec<_>>();

    serde_json::Value::Array(batches)
}

// One trustee-batched succinct proof per trustee over the package share
// records, assembled through the same statement-rebuild path the package
// verifier uses, with the deterministic fixture witnesses.
pub(super) fn trustee_evaluation_key_proofs_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    trustee_evaluation_key_proofs_object_inner(package, None, &BTreeMap::new(), None)
}

pub(super) fn trustee_evaluation_key_proofs_object_with_terminal_transport(
    package: &serde_json::Value,
    transported_component_material: &serde_json::Value,
    terminal_transport: &mut TerminalEvaluationKeyTransportSinks,
) -> serde_json::Value {
    // The terminal flow keeps the package VSS material binary-chunked, so the
    // statement rebuild needs the per-trustee constant commitments through
    // the transported map, exactly like the package verifier receives them.
    let transported_constant_commitments = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records")
        .iter()
        .map(|proof_record| {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            (
                trustee_roster_position,
                same_secret_constant_commitments_from_fixture_package(
                    package,
                    trustee_roster_position,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    trustee_evaluation_key_proofs_object_inner(
        package,
        Some(transported_component_material),
        &transported_constant_commitments,
        Some(terminal_transport),
    )
}

fn trustee_evaluation_key_proofs_object_inner(
    package: &serde_json::Value,
    transported_component_material: Option<&serde_json::Value>,
    transported_constant_commitments: &BTreeMap<
        u64,
        Vec<crate::bgv::setup::commitment::SetupCommitmentValue>,
    >,
    mut terminal_transport: Option<&mut TerminalEvaluationKeyTransportSinks>,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let round_one_aggregate_diagonals_by_level =
        round_one_aggregate_diagonals_from_fixture_package(package, transported_component_material);
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    let built_records = same_secret_proofs
        .par_iter()
        .map(|proof_record| {
        let trustee_roster_position = proof_record["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position");
        let trustee_identity = proof_record["trusteeIdentity"]
            .as_str()
            .expect("trustee identity");
        terminal_phase(&format!(
            "generating trustee evaluation-key proof trustee {trustee_roster_position}"
        ));
        let statement =
            trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
                setup_package: package,
                transported_key_switch_component_material: transported_component_material,
                transported_constant_commitments,
                round_one_aggregate_diagonals_by_level: &round_one_aggregate_diagonals_by_level,
                trustee_roster_position,
            })
            .expect("trustee evaluation-key statement");
        let witness = trustee_evaluation_key_witness_for_fixture(
            trustee_roster_position,
            ring_degree,
            &statement,
        );
        let proof_randomness_seed_hex = derive_protocol_hash(
            "TrusteeEvaluationKeyProofRandomness",
            &serde_json::json!({
                "fixture": "trustee-evaluation-key-proof-randomness",
                "trusteeRosterPosition": trustee_roster_position,
            }),
        )
        .expect("trustee proof randomness seed");
        let proof = prove_evaluation_key_share(&statement, &witness, &proof_randomness_seed_hex)
            .expect("trustee evaluation-key proof");
        let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
        terminal_phase(&format!(
            "generated trustee evaluation-key proof trustee {trustee_roster_position} ({} bytes)",
            proof_bytes.len(),
        ));
        let record = serde_json::json!({
            "objectType": "TrusteeEvaluationKeyProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
            "proofVerificationStatus": TRUSTEE_EVALUATION_KEY_PROOF_VERIFICATION_STATUS,
            "proofModelStatus": TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS,
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "qShareHash": setup_context["qShareHash"],
            "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": setup_context["commitmentProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
            "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
            "statementHash": to_hex(&statement.statement_hash()),
            "keyCount": statement.keys.len(),
            "proofSizeBytes": proof_bytes.len(),
            "proofBytesHash": trustee_evaluation_key_proof_bytes_hash(&proof_bytes),
            "proofBytesHex": to_hex(&proof_bytes),
        });
            record
        })
        .collect::<Vec<_>>();
    let mut proof_records = Vec::new();
    for mut record in built_records {
        if let Some(sinks) = terminal_transport.as_deref_mut() {
            let proof_material =
                move_trustee_evaluation_key_proof_record_bytes_to_compact_transport(&mut record);
            sinks.proof_materials.push(proof_material);
        }
        record["trusteeEvaluationKeyProofRoot"] = serde_json::json!(
            derive_protocol_hash("TrusteeEvaluationKeyProofRoot", &record)
                .expect("trustee evaluation-key proof root")
        );
        proof_records.push(record);
    }
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
    let mut proof_set = serde_json::json!({
        "objectType": "TrusteeEvaluationKeyProofSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "proofVerificationStatus": TRUSTEE_EVALUATION_KEY_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS,
        "proofAccountingHash": succinct_evaluation_key_proof_accounting_hash()
            .expect("succinct evaluation-key proof accounting hash"),
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
        "keySwitchDecompositionHash": accepted_key_switch_decomposition_hash()
            .expect("key-switch decomposition hash"),
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
        "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
        "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "relinearizationKeyShareRoundsRoot": package["relinearizationKeyShareRounds"]["relinearizationKeyShareRoundsRoot"],
        "galoisKeyShareBatchRoots": galois_key_share_batch_roots,
        "proofRecords": proof_records,
    });
    proof_set["trusteeEvaluationKeyProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("TrusteeEvaluationKeyProofSetRoot", &proof_set)
            .expect("trustee evaluation-key proof set root")
    );

    proof_set
}

// The deterministic fixture witness for one trustee's batched statement: the
// shared VSS secret, per-key fixture errors in statement order, and the
// same-secret linkage openings.
pub(super) fn trustee_evaluation_key_witness_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
    statement: &crate::bgv::setup::trustee_evaluation_key_proof::TrusteeEvaluationKeyStatement,
) -> TrusteeEvaluationKeyWitness {
    let secret_coefficients =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
    let error_coefficients_by_key = statement
        .keys
        .iter()
        .map(|key| {
            let (proof_family, rotation) = match key.kind {
                EvaluationKeyShareKind::RelinearizationRoundOne
                | EvaluationKeyShareKind::RelinearizationRoundTwo => {
                    (EvaluationKeyShareProofFamily::Relinearization, None)
                }
                EvaluationKeyShareKind::GaloisRotation { galois_element } => (
                    EvaluationKeyShareProofFamily::Galois,
                    Some(u64::try_from(galois_element).expect("rotation fits u64")),
                ),
                EvaluationKeyShareKind::PublicKeyShare => {
                    unreachable!("the evaluation-key witness fixture never carries a public-key share key");
                }
            };
            (0..=key.level)
                .map(|digit_index| {
                    evaluation_key_error_coefficients_for_fixture(
                        proof_family,
                        trustee_roster_position,
                        key.level,
                        rotation,
                        digit_index,
                        ring_degree,
                    )
                })
                .collect()
        })
        .collect();
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect();
    let opening_randomness_by_limb = (0..DATA_PRIMES.len())
        .map(|rns_limb_index| {
            accepted_vss_randomness_fixture(trustee_roster_position, rns_limb_index, 0, ring_degree)
                .into_iter()
                .map(|column| {
                    column
                        .into_iter()
                        .map(|value| i64::try_from(value).expect("ternary randomness fits i64"))
                        .collect()
                })
                .collect()
        })
        .collect();

    TrusteeEvaluationKeyWitness {
        secret_coefficients,
        error_coefficients_by_key,
        negative_indicator_coefficients,
        opening_randomness_by_limb,
    }
}

pub(super) fn public_key_share_lnp_proofs_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_key_share_tbox_parameter_profile_hash =
        crate::bgv::setup::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()
            .expect("public-key share tbox parameter profile hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let public_key_crp_root =
        package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"]
            .as_str()
            .expect("public-key CRP root");
    let public_a_polynomial_root =
        package["commonRandomness"]["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"]
            .as_str()
            .expect("public a root");
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let same_secret_proof_records = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let share_records = package["publicKeyShares"]["shareRecords"]
        .as_array()
        .expect("public-key share records");
    let proof_statement_records = package["publicKeyShareProofs"]["proofRecords"]
        .as_array()
        .expect("public-key proof statement records");
    let material_records = package["publicKeyShareMaterial"]["shareMaterialRecords"]
        .as_array()
        .expect("public-key material records");
    let per_trustee_records = (0..10_u64)
        .into_par_iter()
        .map(|trustee_roster_position| {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let statement_record = &statement_records[trustee_roster_position as usize];
        let same_secret_proof_record = &same_secret_proof_records[trustee_roster_position as usize];
        let share_record = &share_records[trustee_roster_position as usize];
        let proof_statement_record = &proof_statement_records[trustee_roster_position as usize];
        let material_record = &material_records[trustee_roster_position as usize];
        let constant_commitments =
            same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
        let ring_degree = constant_commitments
            .first()
            .expect("constant commitment")
            .ring_degree;
        let (coefficients_by_limb, error_coefficients_by_limb) =
            public_key_share_coefficients_and_errors_for_fixture(
                public_matrix_seed_hash,
                trustee_roster_position,
                ring_degree,
            );
        let witness = PublicKeyShareLnpProofWitness {
            secret_coefficients: (0..ring_degree)
                .map(|coefficient_position| {
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    )
                })
                .collect(),
            opening_randomness_by_limb: (0..DATA_PRIMES.len())
                .map(|rns_limb_index| {
                    accepted_vss_randomness_fixture(
                        trustee_roster_position,
                        rns_limb_index,
                        0,
                        ring_degree,
                    )
                })
                .collect(),
            error_coefficients_by_limb,
        };
        let proof_randomness_seed_hex = derive_protocol_hash(
            "PublicKeyShareProofRoot",
            &serde_json::json!({
                "fixture": "public-key-share-lnp-proof-randomness",
                "trusteeRosterPosition": trustee_roster_position,
            }),
        )
        .expect("public-key proof randomness seed");
        let proof_bytes =
            generate_public_key_share_lnp_relation_proof(PublicKeyShareLnpProofGenerationInput {
                public_matrix_seed_hash,
                public_key_share_record: share_record,
                public_key_share_proof_record: proof_statement_record,
                same_secret_statement_record: statement_record,
                constant_commitments: &constant_commitments,
                public_share_coefficients_by_limb: &coefficients_by_limb,
                setup_proof_binding: &setup_proof_binding,
                witness: &witness,
                proof_randomness_seed_hex: &proof_randomness_seed_hex,
            })
            .expect("public-key proof bytes");
        let verification =
            verify_public_key_share_lnp_relation_proof(PublicKeyShareLnpProofVerificationInput {
                public_matrix_seed_hash,
                public_key_share_record: share_record,
                public_key_share_proof_record: proof_statement_record,
                same_secret_statement_record: statement_record,
                constant_commitments: &constant_commitments,
                public_share_coefficients_by_limb: &coefficients_by_limb,
                setup_proof_binding: &setup_proof_binding,
                proof_bytes: &proof_bytes,
            })
            .expect("public-key proof verification");
        let proof_size_bytes = u64::try_from(proof_bytes.len()).expect("proof size bytes");
        let proof_bytes_hash = public_key_share_lnp_relation_proof_bytes_hash(&proof_bytes);
        let mut proof_record = serde_json::json!({
            "objectType": "PublicKeyShareLnpProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "public-key-share",
            "proofVerificationStatus": PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
            "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
            "setupProofBinding": setup_proof_binding.clone(),
            "publicKeyShareTboxParameterProfileHash": public_key_share_tbox_parameter_profile_hash.clone(),
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "qShareHash": setup_context["qShareHash"],
            "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": setup_context["commitmentProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
            "publicKeyShareProofRoot": proof_statement_record["publicKeyShareProofRoot"],
            "publicKeyShareMaterialRoot": material_record["publicKeyShareMaterialRoot"],
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": same_secret_proof_record["sameSecretProofFamilyBindingRoot"],
            "sameSecretProofRoot": same_secret_proof_record["sameSecretProofRoot"],
            "statementHash": verification.statement_hash_hex,
            "relationCommitmentHash": verification.relation_commitment_hash_hex,
            "tboxCommitmentPrefixHash": verification.tbox_commitment_prefix_hash,
            "z34SeedMaterialHash": verification.z34_seed_material_hash,
            "z34ChallengeSeedHash": verification.z34_challenge_seed_hash,
            "z34ChallengeTailHash": verification.z34_challenge_tail_hash,
            "z34ChallengeRowDomainHash": verification.z34_challenge_row_domain_hash,
            "z34ChallengeZ3RowSetHash": verification.z34_challenge_z3_row_set_hash,
            "z34ChallengeZ4RowSetHash": verification.z34_challenge_z4_row_set_hash,
            "tboxLowerProtocolChallengeHash": verification.tbox_lower_protocol_challenge_hash,
            "z34Z3CheckWindowHash": verification.z34_z3_check_window_hash,
            "z34Z4CheckWindowHash": verification.z34_z4_check_window_hash,
            "z34Z3L2SquaredDecimal": verification.z34_z3_l2_squared_decimal,
            "z34Z4InfinityNormDecimal": verification.z34_z4_infinity_norm_decimal,
            "challenge": verification.challenge.to_string(),
            "proofSizeBytes": proof_size_bytes,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesHex": to_hex(&proof_bytes),
        });
        proof_record["publicKeyShareLnpProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", &proof_record)
                .expect("public-key LNP proof root")
        );
        let proof_root_entry = serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareLnpProofRoot": proof_record["publicKeyShareLnpProofRoot"],
        });
        terminal_phase(&format!("generated public-key proof trustee {trustee_roster_position}"));

        (proof_root_entry, proof_record)
        })
        .collect::<Vec<_>>();
    let mut proof_records = Vec::new();
    let mut proof_roots = Vec::new();
    for (proof_root_entry, proof_record) in per_trustee_records {
        proof_roots.push(proof_root_entry);
        proof_records.push(proof_record);
    }
    let mut proof_set = serde_json::json!({
        "objectType": "PublicKeyShareLnpProofSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofVerificationStatus": PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "setupProofBinding": setup_proof_binding,
        "publicKeyShareTboxParameterProfileHash": public_key_share_tbox_parameter_profile_hash,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_key_crp_root,
        "publicAPolynomialRoot": public_a_polynomial_root,
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareProofSetRoot": package["publicKeyShareProofs"]["publicKeyShareProofSetRoot"],
        "publicKeyShareMaterialSetRoot": package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"],
        "publicKeyShareLnpProofRoots": proof_roots,
        "proofRecords": proof_records,
    });
    proof_set["publicKeyShareLnpProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareProofRoot", &proof_set)
            .expect("public-key LNP proof set root")
    );

    proof_set
}

pub(super) fn same_secret_constant_commitments_from_fixture_package(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> Vec<crate::bgv::setup::commitment::SetupCommitmentValue> {
    let material_set = &package["vssCoefficientCommitmentMaterial"];
    let Some(material_records) = material_set
        .get("coefficientCommitments")
        .and_then(serde_json::Value::as_array)
    else {
        return same_secret_constant_commitments_from_deterministic_fixture(
            package,
            trustee_roster_position,
        );
    };
    let mut commitments_by_limb = BTreeMap::new();
    for material_record in material_records {
        if material_record["sourceTrusteeRosterPosition"].as_u64() != Some(trustee_roster_position)
            || material_record["shamirCoefficientIndex"].as_u64() != Some(0)
        {
            continue;
        }
        let rns_limb_index = material_record["rnsLimbIndex"]
            .as_u64()
            .expect("RNS limb index");
        let commitment = crate::bgv::setup::commitment::parse_setup_commitment_full_value(
            &material_record["commitment"],
        )
        .expect("constant commitment value");
        assert!(
            commitments_by_limb
                .insert(rns_limb_index, commitment)
                .is_none(),
            "duplicate constant commitment limb"
        );
    }
    (0..DATA_PRIMES.len() as u64)
        .map(|rns_limb_index| {
            commitments_by_limb
                .remove(&rns_limb_index)
                .expect("constant commitment limb")
        })
        .collect()
}

fn same_secret_constant_commitments_from_deterministic_fixture(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> Vec<crate::bgv::setup::commitment::SetupCommitmentValue> {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let ring_degree = package["vssCoefficientCommitmentMaterial"]["ringDegree"]
        .as_u64()
        .expect("VSS material ring degree") as usize;
    DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .map(|(rns_limb_index, rns_prime)| {
            let coefficient_message = accepted_vss_coefficient_message_fixture(
                trustee_roster_position,
                rns_limb_index,
                0,
                rns_prime,
                ring_degree,
            );
            let coefficient_message_wide = coefficient_message
                .iter()
                .map(|coefficient| u128::from(*coefficient))
                .collect::<Vec<_>>();
            let randomness_by_column = accepted_vss_randomness_fixture(
                trustee_roster_position,
                rns_limb_index,
                0,
                ring_degree,
            );
            compute_setup_commitment_for_tests(
                public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                0,
                &coefficient_message_wide,
                &randomness_by_column,
                ring_degree,
            )
            .expect("deterministic setup commitment")
        })
        .collect()
}
