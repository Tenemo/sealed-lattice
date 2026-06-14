use super::*;
use rayon::prelude::*;

pub(super) struct EvaluationKeyShareFixtureMaterial {
    pub(super) component_b_by_digit: Vec<Vec<Vec<u64>>>,
    pub(super) component_vector_entries: Vec<serde_json::Value>,
    pub(super) component_vector_root: String,
}

pub(super) struct RelinearizationKeyShareRoundsFixture {
    pub(super) rounds: serde_json::Value,
    pub(super) round_one_aggregate_diagonals_by_level: BTreeMap<u64, Vec<Vec<u64>>>,
}

struct TrusteeEvaluationKeyProofWorkItem {
    trustee_roster_position: u64,
    statement: crate::bgv::setup::trustee_evaluation_key_proof::TrusteeEvaluationKeyStatement,
    record: serde_json::Value,
}

#[derive(Clone)]
struct BuiltTrusteeEvaluationKeyProofRecord {
    record: serde_json::Value,
    transported_proof_material: Option<serde_json::Value>,
}

// Maximum number of trustee evaluation-key provers that run concurrently while
// assembling the first-profile package fixture. Each first-profile prover holds
// its statement, witness, and proof working set, which is several gigabytes, so
// proving all ten trustees at once needs far more than physical memory and
// forces heavy paging. Generating the proofs in batches of this size keeps
// per-trustee proving parallel (each batch member still uses the shared work
// pool for its internal parallelism) while capping concurrent prover memory to
// fit a workstation-class machine.
const TRUSTEE_EVALUATION_KEY_PROOF_GENERATION_BATCH_SIZE: usize = 3;

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
    relinearization_key_share_rounds_object_inner(package, None).rounds
}

pub(super) fn relinearization_key_share_rounds_fixture_with_terminal_transport(
    package: &serde_json::Value,
    terminal_transport: &mut TerminalEvaluationKeyTransportSinks,
) -> RelinearizationKeyShareRoundsFixture {
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
        "proofVerificationStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
        "aggregationStatus": "succinct-proof-aggregated-with-accepted-setup-proof-accounting",
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
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
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
            "proofModelStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
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
        "proofModelStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
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
) -> (Vec<Vec<u64>>, Vec<i64>) {
    // One small centered-binomial error polynomial per trustee, shared across
    // every Q_share limb, so the public-key share relation b_l = p*e - a_l*s
    // holds for the single committed error column the succinct argument proves.
    let error_coefficients = (0..ring_degree)
        .map(|coefficient_position| {
            accepted_public_key_error_coefficient_fixture(
                trustee_roster_position,
                coefficient_position,
            )
        })
        .collect::<Vec<_>>();
    let mut coefficients_by_limb = Vec::new();
    for modulus in DATA_PRIMES.iter().copied() {
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
        let coefficients = error_coefficients
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
    }

    (coefficients_by_limb, error_coefficients)
}

fn accepted_public_key_error_coefficient_fixture(
    trustee_roster_position: u64,
    coefficient_position: usize,
) -> i64 {
    match (trustee_roster_position as usize * 37 + coefficient_position * 5) % 5 {
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
            private_vss_share: None,
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
            private_vss_coefficient_messages_by_shamir_index: Vec::new(),
            private_vss_opening_randomness_by_shamir_index: Vec::new(),
            private_vss_carry_witnesses: Vec::new(),
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
            "ringDegree": ring_degree,
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
) -> RelinearizationKeyShareRoundsFixture {
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
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    for level in &scheduled_levels {
        let level = *level;
        let key_switch_seed_hex =
            relinearization_key_switch_seed_for_test(schedule, "round-one", level);
        // Generate every trustee's key-switch component material for this level
        // in parallel; the deterministic material is then consumed in roster
        // order by the sequential aggregate-accumulation and record-building
        // pass below, so the emitted records and roots are byte-identical.
        let level_materials: Vec<EvaluationKeyShareFixtureMaterial> = same_secret_proofs
            .par_iter()
            .map(|proof_record| {
                let trustee_roster_position = proof_record["trusteeRosterPosition"]
                    .as_u64()
                    .expect("trustee roster position");
                let relinearization_source = relinearization_round_one_source_by_digit_for_fixture(
                    trustee_roster_position,
                    ring_degree,
                    usize::try_from(level).expect("level fits usize") + 1,
                );
                evaluation_key_share_fixture_material(
                    EvaluationKeyShareProofFamily::Relinearization,
                    trustee_roster_position,
                    level,
                    None,
                    ring_degree,
                    &key_switch_seed_hex,
                    Some(&relinearization_source),
                )
            })
            .collect();
        for (proof_record, fixture_material) in same_secret_proofs.iter().zip(level_materials) {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
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
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
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
            });
            if terminal_transport.is_none() {
                record["keySwitchComponentVectors"] =
                    serde_json::Value::Array(fixture_material.component_vector_entries.clone());
            }
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
        let key_switch_seed_hex =
            relinearization_key_switch_seed_for_test(schedule, "round-two", level);
        let round_one_aggregate_diagonals = round_one_aggregate_diagonals_by_level
            .get(&level)
            .expect("round-one aggregate diagonals");
        let level_materials: Vec<EvaluationKeyShareFixtureMaterial> = same_secret_proofs
            .par_iter()
            .map(|proof_record| {
                let trustee_roster_position = proof_record["trusteeRosterPosition"]
                    .as_u64()
                    .expect("trustee roster position");
                let relinearization_source = relinearization_round_two_source_by_digit_for_fixture(
                    trustee_roster_position,
                    ring_degree,
                    round_one_aggregate_diagonals,
                );
                evaluation_key_share_fixture_material(
                    EvaluationKeyShareProofFamily::Relinearization,
                    trustee_roster_position,
                    level,
                    None,
                    ring_degree,
                    &key_switch_seed_hex,
                    Some(&relinearization_source),
                )
            })
            .collect();
        for (proof_record, fixture_material) in same_secret_proofs.iter().zip(level_materials) {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
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
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
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
            });
            if terminal_transport.is_none() {
                record["keySwitchComponentVectors"] =
                    serde_json::Value::Array(fixture_material.component_vector_entries.clone());
            }
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
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
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

    RelinearizationKeyShareRoundsFixture {
        rounds,
        round_one_aggregate_diagonals_by_level,
    }
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
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    // Generate each trustee's Galois key-switch component material across the
    // scheduled rotations in parallel, then consume that trustee's material in
    // schedule order before moving to the next trustee, so peak memory stays
    // bounded to one trustee's rotation materials instead of the full
    // trustee-by-rotation matrix. The per-trustee outer order and per-rotation
    // inner order are preserved, so the emitted batches, roots, and transported
    // component-material order stay byte-identical to sequential generation.
    let batches = same_secret_proofs
        .iter()
        .map(|proof_record| {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let trustee_materials: Vec<EvaluationKeyShareFixtureMaterial> = required_schedule
                .par_iter()
                .map(|schedule_entry| {
                    let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                    let level = schedule_entry["level"].as_u64().expect("level");
                    let key_switch_seed_hex =
                        galois_key_switch_seed_for_test(schedule, rotation, level);
                    evaluation_key_share_fixture_material(
                        EvaluationKeyShareProofFamily::Galois,
                        trustee_roster_position,
                        level,
                        Some(rotation),
                        ring_degree,
                        &key_switch_seed_hex,
                        None,
                    )
                })
                .collect();
            let mut galois_key_share_material_records = Vec::new();
            let galois_key_share_roots = required_schedule
                .iter()
                .zip(trustee_materials)
                .map(|(schedule_entry, fixture_material)| {
                    let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                    let level = schedule_entry["level"].as_u64().expect("level");
                    let key_switch_seed_hex =
                        galois_key_switch_seed_for_test(schedule, rotation, level);
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
                    });
                    if terminal_transport.is_none() {
                        material_record["keySwitchComponentVectors"] =
                            serde_json::Value::Array(fixture_material.component_vector_entries.clone());
                    }
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
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
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
    trustee_evaluation_key_proofs_object_inner(package, None, &BTreeMap::new(), None, None)
}

pub(super) fn trustee_evaluation_key_proofs_object_with_terminal_transport(
    package: &serde_json::Value,
    transported_component_material: &serde_json::Value,
    round_one_aggregate_diagonals_by_level: &BTreeMap<u64, Vec<Vec<u64>>>,
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
        Some(round_one_aggregate_diagonals_by_level),
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
    precomputed_round_one_aggregate_diagonals_by_level: Option<&BTreeMap<u64, Vec<Vec<u64>>>>,
    mut terminal_transport: Option<&mut TerminalEvaluationKeyTransportSinks>,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let computed_round_one_aggregate_diagonals_by_level;
    let round_one_aggregate_diagonals_by_level =
        if let Some(precomputed_aggregates) = precomputed_round_one_aggregate_diagonals_by_level {
            precomputed_aggregates
        } else {
            computed_round_one_aggregate_diagonals_by_level =
                round_one_aggregate_diagonals_from_fixture_package(
                    package,
                    transported_component_material,
                );
            &computed_round_one_aggregate_diagonals_by_level
        };
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    let checkpoint_resume_enabled =
        terminal_transport.is_some() && terminal_accepted_setup_checkpoint_resume_enabled();
    let trustee_proof_batch_size = if terminal_transport.is_some() {
        1
    } else {
        TRUSTEE_EVALUATION_KEY_PROOF_GENERATION_BATCH_SIZE
    };
    let mut built_records: Vec<BuiltTrusteeEvaluationKeyProofRecord> =
        Vec::with_capacity(same_secret_proofs.len());
    for proof_record_batch in same_secret_proofs.chunks(trustee_proof_batch_size) {
        let work_item_batch = proof_record_batch
            .iter()
            .map(|proof_record| {
                let trustee_roster_position = proof_record["trusteeRosterPosition"]
                    .as_u64()
                    .expect("trustee roster position");
                let trustee_identity = proof_record["trusteeIdentity"]
                    .as_str()
                    .expect("trustee identity");
                let statement = trustee_evaluation_key_statement_from_package(
                    &TrusteeEvaluationKeyStatementInputs {
                        setup_package: package,
                        transported_key_switch_component_material: transported_component_material,
                        transported_constant_commitments,
                        round_one_aggregate_diagonals_by_level,
                        trustee_roster_position,
                    },
                )
                .expect("trustee evaluation-key statement");
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
                });

                TrusteeEvaluationKeyProofWorkItem {
                    trustee_roster_position,
                    statement,
                    record,
                }
            })
            .collect::<Vec<_>>();
        let resumed_records = if checkpoint_resume_enabled {
            terminal_trustee_evaluation_key_proof_records_from_checkpoints(&work_item_batch)
        } else {
            BTreeMap::new()
        };
        let built_record_batch: Vec<BuiltTrusteeEvaluationKeyProofRecord> = work_item_batch
            .into_par_iter()
            .map(|work_item| {
                build_trustee_evaluation_key_proof_record(work_item, &resumed_records, ring_degree)
            })
            .collect();
        built_records.extend(built_record_batch);
    }
    let mut proof_records = Vec::new();
    for built_record in built_records {
        let mut record = built_record.record;
        if let Some(sinks) = terminal_transport.as_deref_mut() {
            if let Some(proof_material) = built_record.transported_proof_material {
                sinks.proof_materials.push(proof_material);
            } else {
                let proof_material =
                    move_trustee_evaluation_key_proof_record_bytes_to_compact_transport(
                        &mut record,
                    );
                sinks.proof_materials.push(proof_material);
            }
        }
        record
            .as_object_mut()
            .expect("trustee evaluation-key proof record object")
            .remove("trusteeEvaluationKeyProofRoot");
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
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
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

fn build_trustee_evaluation_key_proof_record(
    work_item: TrusteeEvaluationKeyProofWorkItem,
    resumed_records: &BTreeMap<u64, BuiltTrusteeEvaluationKeyProofRecord>,
    ring_degree: usize,
) -> BuiltTrusteeEvaluationKeyProofRecord {
    if let Some(resumed_record) = resumed_records.get(&work_item.trustee_roster_position) {
        terminal_phase(&format!(
            "resumed trustee evaluation-key proof trustee {} from checkpoint",
            work_item.trustee_roster_position
        ));
        return resumed_record.clone();
    }

    terminal_phase(&format!(
        "generating trustee evaluation-key proof trustee {}",
        work_item.trustee_roster_position
    ));
    let witness = trustee_evaluation_key_witness_for_fixture(
        work_item.trustee_roster_position,
        ring_degree,
        &work_item.statement,
    );
    let proof_randomness_seed_hex = derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &serde_json::json!({
            "fixture": "trustee-evaluation-key-proof-randomness",
            "trusteeRosterPosition": work_item.trustee_roster_position,
        }),
    )
    .expect("trustee proof randomness seed");
    let proof =
        prove_evaluation_key_share(&work_item.statement, &witness, &proof_randomness_seed_hex)
            .unwrap_or_else(|error| {
                panic!(
                    "trustee evaluation-key proof generation failed for trustee {}: {error}; {}",
                    work_item.trustee_roster_position,
                    trustee_evaluation_key_fixture_material_mismatch_summary(
                        work_item.trustee_roster_position,
                        ring_degree,
                        &work_item.statement,
                    )
                )
            });
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    terminal_phase(&format!(
        "generated trustee evaluation-key proof trustee {} ({} bytes)",
        work_item.trustee_roster_position,
        proof_bytes.len(),
    ));
    let record =
        trustee_evaluation_key_record_with_embedded_proof_bytes(work_item.record, &proof_bytes);
    BuiltTrusteeEvaluationKeyProofRecord {
        record,
        transported_proof_material: None,
    }
}

fn terminal_accepted_setup_checkpoint_resume_enabled() -> bool {
    matches!(
        std::env::var("SEALED_LATTICE_RESUME_TEST_CHECKPOINTS").as_deref(),
        Ok("1")
    )
}

fn trustee_evaluation_key_record_with_embedded_proof_bytes(
    mut record: serde_json::Value,
    proof_bytes: &[u8],
) -> serde_json::Value {
    let proof_size_bytes = u64::try_from(proof_bytes.len()).expect("proof size bytes");
    record["proofSizeBytes"] = serde_json::json!(proof_size_bytes);
    record["proofBytesHash"] =
        serde_json::json!(trustee_evaluation_key_proof_bytes_hash(proof_bytes));
    record["proofBytesHex"] = serde_json::json!(to_hex(proof_bytes));

    record
}

fn terminal_trustee_evaluation_key_proof_records_from_checkpoints(
    work_items: &[TrusteeEvaluationKeyProofWorkItem],
) -> BTreeMap<u64, BuiltTrusteeEvaluationKeyProofRecord> {
    let directory = std::path::PathBuf::from("temp")
        .join("test-checkpoints")
        .join("terminal-accepted-setup-material-store")
        .join("trustee-evaluation-key-proof-material");
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return BTreeMap::new();
    };
    let mut resumed_records = BTreeMap::new();
    for entry in entries {
        let entry = entry.expect("terminal proof checkpoint directory entry");
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("bin") {
            continue;
        }
        let Some(stored_material_root) = path.file_stem().and_then(std::ffi::OsStr::to_str) else {
            continue;
        };
        if stored_material_root.len() != 128
            || !stored_material_root
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            continue;
        }
        let proof_bytes = std::fs::read(&path).expect("terminal trustee proof checkpoint bytes");
        let proof_size_bytes = u64::try_from(proof_bytes.len()).expect("proof size bytes");
        let proof_bytes_hash = trustee_evaluation_key_proof_bytes_hash(&proof_bytes);
        let chunks = proof_bytes_transport_chunks(proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("checkpointed trustee proof transport hashes");
        let mut matched_trustee = None;
        for work_item in work_items {
            if resumed_records.contains_key(&work_item.trustee_roster_position) {
                continue;
            }
            let mut record = work_item.record.clone();
            apply_trustee_evaluation_key_proof_transport_fields(
                &mut record,
                proof_size_bytes,
                &proof_bytes_hash,
                &transport_hashes,
            );
            let proof_material_root =
                trustee_evaluation_key_proof_material_root(&record, &transport_hashes)
                    .expect("checkpointed trustee proof material root");
            if proof_material_root != stored_material_root {
                continue;
            }
            record["proofMaterialRoot"] = serde_json::json!(proof_material_root.clone());
            record["trusteeEvaluationKeyProofRoot"] = serde_json::json!(
                derive_protocol_hash("TrusteeEvaluationKeyProofRoot", &record)
                    .expect("transported trustee evaluation-key proof root")
            );
            let proof_material =
                transported_trustee_evaluation_key_proof_material(&record, &transport_hashes);
            register_verified_trustee_evaluation_key_proof_material_chunks(
                &proof_material_root,
                chunks,
            )
            .expect("verified trustee evaluation-key proof material chunks");
            resumed_records.insert(
                work_item.trustee_roster_position,
                BuiltTrusteeEvaluationKeyProofRecord {
                    record,
                    transported_proof_material: Some(proof_material),
                },
            );
            matched_trustee = Some(work_item.trustee_roster_position);
            break;
        }
        if let Some(trustee_roster_position) = matched_trustee {
            terminal_phase(&format!(
                "matched trustee evaluation-key proof checkpoint for trustee {trustee_roster_position}"
            ));
        }
    }

    resumed_records
}

fn apply_trustee_evaluation_key_proof_transport_fields(
    record: &mut serde_json::Value,
    proof_size_bytes: u64,
    proof_bytes_hash: &str,
    transport_hashes: &crate::bgv::setup::setup_proof::SetupProofMaterialTransportHashes,
) {
    record["proofSizeBytes"] = serde_json::json!(proof_size_bytes);
    record["proofBytesHash"] = serde_json::json!(proof_bytes_hash);
    record["proofBytesEncoding"] = serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING);
    record["proofChunkSizeBytes"] = serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
    record["proofChunkCount"] = serde_json::json!(transport_hashes.chunk_hashes.len());
    record["proofTotalByteLength"] = serde_json::json!(transport_hashes.total_byte_length);
    record["proofFullObjectHash"] = serde_json::json!(transport_hashes.full_object_hash);
    record["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
    record["proofChunkHashes"] = serde_json::json!(transport_hashes.chunk_hashes.clone());
}

fn transported_trustee_evaluation_key_proof_material(
    proof_record: &serde_json::Value,
    transport_hashes: &crate::bgv::setup::setup_proof::SetupProofMaterialTransportHashes,
) -> serde_json::Value {
    serde_json::json!({
        "objectType": "SetupTransportedEvaluationKeyShareProofMaterial",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": proof_record["proofMaterialRoot"],
        "proofChunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "proofChunkCount": transport_hashes.chunk_hashes.len(),
        "proofTotalByteLength": transport_hashes.total_byte_length,
        "proofFullObjectHash": proof_record["proofFullObjectHash"],
        "proofChunkRoot": proof_record["proofChunkRoot"],
        "proofChunkHashes": proof_record["proofChunkHashes"],
    })
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
                    unreachable!(
                        "the evaluation-key witness fixture never carries a public-key share key"
                    );
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
    // The same-secret linkage openings cover one commitment per active
    // key-switch limb, matching the truncated linkage commitment set on the
    // statement rather than every Q_share limb.
    let active_key_switch_limb_count = statement
        .keys
        .iter()
        .map(|key| key.level + 1)
        .max()
        .unwrap_or(0);
    let opening_randomness_by_limb = (0..active_key_switch_limb_count)
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
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
    }
}

fn trustee_evaluation_key_fixture_material_mismatch_summary(
    trustee_roster_position: u64,
    ring_degree: usize,
    statement: &crate::bgv::setup::trustee_evaluation_key_proof::TrusteeEvaluationKeyStatement,
) -> String {
    for (key_index, key) in statement.keys.iter().enumerate() {
        let (proof_family, rotation, source_by_digit) = match key.kind {
            EvaluationKeyShareKind::RelinearizationRoundOne => {
                let source_by_digit = relinearization_round_one_source_by_digit_for_fixture(
                    trustee_roster_position,
                    ring_degree,
                    key.level + 1,
                );
                (
                    EvaluationKeyShareProofFamily::Relinearization,
                    None,
                    Some(source_by_digit),
                )
            }
            EvaluationKeyShareKind::RelinearizationRoundTwo => {
                let source_by_digit = relinearization_round_two_source_by_digit_for_fixture(
                    trustee_roster_position,
                    ring_degree,
                    &key.round_one_aggregate_diagonal,
                );
                (
                    EvaluationKeyShareProofFamily::Relinearization,
                    None,
                    Some(source_by_digit),
                )
            }
            EvaluationKeyShareKind::GaloisRotation { galois_element } => (
                EvaluationKeyShareProofFamily::Galois,
                Some(u64::try_from(galois_element).expect("rotation fits u64")),
                None,
            ),
            EvaluationKeyShareKind::PublicKeyShare => {
                return format!("unexpected public-key share key at index {key_index}");
            }
        };
        let expected_material = evaluation_key_share_fixture_material(
            proof_family,
            trustee_roster_position,
            u64::try_from(key.level).expect("key level fits u64"),
            rotation,
            ring_degree,
            &key.key_switch_seed_hex,
            source_by_digit.as_deref(),
        );
        if expected_material.component_b_by_digit == key.component_b_by_digit {
            continue;
        }
        for (digit_index, (expected_by_limb, actual_by_limb)) in expected_material
            .component_b_by_digit
            .iter()
            .zip(key.component_b_by_digit.iter())
            .enumerate()
        {
            for (rns_limb_index, (expected_coefficients, actual_coefficients)) in expected_by_limb
                .iter()
                .zip(actual_by_limb.iter())
                .enumerate()
            {
                if expected_coefficients == actual_coefficients {
                    continue;
                }
                for (coefficient_index, (expected_coefficient, actual_coefficient)) in
                    expected_coefficients
                        .iter()
                        .zip(actual_coefficients.iter())
                        .enumerate()
                {
                    if expected_coefficient != actual_coefficient {
                        return format!(
                            "component material mismatch at key {key_index} ({:?}, level {}, seed {}), digit {digit_index}, limb {rns_limb_index}, coefficient {coefficient_index}: expected {expected_coefficient}, observed {actual_coefficient}",
                            key.kind, key.level, key.key_switch_seed_hex
                        );
                    }
                }
                if expected_coefficients.len() != actual_coefficients.len() {
                    return format!(
                        "component material length mismatch at key {key_index} ({:?}, level {}, seed {}), digit {digit_index}, limb {rns_limb_index}: expected {}, observed {}",
                        key.kind,
                        key.level,
                        key.key_switch_seed_hex,
                        expected_coefficients.len(),
                        actual_coefficients.len()
                    );
                }
            }
            if expected_by_limb.len() != actual_by_limb.len() {
                return format!(
                    "component material limb-count mismatch at key {key_index} ({:?}, level {}, seed {}), digit {digit_index}: expected {}, observed {}",
                    key.kind,
                    key.level,
                    key.key_switch_seed_hex,
                    expected_by_limb.len(),
                    actual_by_limb.len()
                );
            }
        }
        if expected_material.component_b_by_digit.len() != key.component_b_by_digit.len() {
            return format!(
                "component material digit-count mismatch at key {key_index} ({:?}, level {}, seed {}): expected {}, observed {}",
                key.kind,
                key.level,
                key.key_switch_seed_hex,
                expected_material.component_b_by_digit.len(),
                key.component_b_by_digit.len()
            );
        }
        return format!(
            "component material differs at key {key_index} ({:?}, level {}, seed {}) but no differing coefficient was found",
            key.kind, key.level, key.key_switch_seed_hex
        );
    }

    "component material matches the deterministic fixture".to_string()
}

pub(super) fn public_key_share_succinct_proofs_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    use crate::bgv::setup::trustee_evaluation_key_proof::{
        EvaluationKeyShareDescriptor, PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
        PUBLIC_KEY_SHARE_PROOF_FAMILY, PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
        PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS, SameSecretLinkageStatement,
        SuccinctSetupProofContext, TrusteeEvaluationKeyStatement,
        public_key_share_succinct_proof_bytes_hash, succinct_public_key_share_accounting_hash,
    };
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
        let mut constant_commitments =
            same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
        let ring_degree = constant_commitments
            .first()
            .expect("constant commitment")
            .ring_degree;
        let (coefficients_by_limb, error_coefficients) =
            public_key_share_coefficients_and_errors_for_fixture(
                public_matrix_seed_hash,
                trustee_roster_position,
                ring_degree,
            );
        // The pk relation opens only the limb-zero constant commitment.
        let limb_zero_commitment = constant_commitments.remove(0);
        let secret_coefficients = (0..ring_degree)
            .map(|coefficient_position| {
                accepted_vss_secret_coefficient_fixture(
                    trustee_roster_position,
                    coefficient_position,
                )
            })
            .collect::<Vec<_>>();
        let negative_indicator_coefficients = secret_coefficients
            .iter()
            .map(|coefficient| i64::from(*coefficient < 0))
            .collect::<Vec<_>>();
        let limb_zero_opening_randomness =
            accepted_vss_randomness_fixture(trustee_roster_position, 0, 0, ring_degree)
                .into_iter()
                .map(|column| {
                    column
                        .into_iter()
                        .map(|value| i64::try_from(value).expect("ternary randomness fits i64"))
                        .collect::<Vec<i64>>()
                })
                .collect::<Vec<Vec<i64>>>();
        let statement = TrusteeEvaluationKeyStatement {
            context: SuccinctSetupProofContext {
                proof_family: PUBLIC_KEY_SHARE_PROOF_FAMILY.to_string(),
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
                binding_roots: vec![
                    (
                        "sameSecretStatementRoot".to_string(),
                        same_secret_proof_record["sameSecretStatementRoot"]
                            .as_str()
                            .expect("same-secret statement root")
                            .to_string(),
                    ),
                    (
                        "sameSecretProofRoot".to_string(),
                        same_secret_proof_record["sameSecretProofRoot"]
                            .as_str()
                            .expect("same-secret proof root")
                            .to_string(),
                    ),
                ],
            },
            ring_degree,
            keys: vec![EvaluationKeyShareDescriptor {
                kind: EvaluationKeyShareKind::PublicKeyShare,
                level: DATA_PRIMES.len() - 1,
                key_switch_domain: PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL.to_string(),
                key_switch_seed_hex: public_matrix_seed_hash.to_string(),
                component_b_by_digit: vec![coefficients_by_limb],
                round_one_aggregate_diagonal: Vec::new(),
            }],
            same_secret_linkage: Some(SameSecretLinkageStatement {
                public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
                commitments: vec![limb_zero_commitment],
            }),
            private_vss_share: None,
        };
        let witness = TrusteeEvaluationKeyWitness {
            secret_coefficients,
            error_coefficients_by_key: vec![vec![error_coefficients]],
            negative_indicator_coefficients,
            opening_randomness_by_limb: vec![limb_zero_opening_randomness],
            private_vss_coefficient_messages_by_shamir_index: Vec::new(),
            private_vss_opening_randomness_by_shamir_index: Vec::new(),
            private_vss_carry_witnesses: Vec::new(),
        };
        let proof_randomness_seed_hex = derive_protocol_hash(
            "PublicKeyShareProofRoot",
            &serde_json::json!({
                "fixture": "public-key-share-succinct-proof-randomness",
                "trusteeRosterPosition": trustee_roster_position,
            }),
        )
        .expect("public-key share succinct proof randomness seed");
        let proof = prove_evaluation_key_share(&statement, &witness, &proof_randomness_seed_hex)
            .expect("public-key share succinct proof");
        let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
        let proof_size_bytes = u64::try_from(proof_bytes.len()).expect("proof size bytes");
        let proof_bytes_hash = public_key_share_succinct_proof_bytes_hash(&proof_bytes);
        let mut proof_record = serde_json::json!({
            "objectType": "PublicKeyShareSuccinctProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": PUBLIC_KEY_SHARE_PROOF_FAMILY,
            "proofVerificationStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS,
            "proofModelStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
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
            "ringDegree": ring_degree,
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
            "publicKeyShareProofRoot": proof_statement_record["publicKeyShareProofRoot"],
            "publicKeyShareMaterialRoot": material_record["publicKeyShareMaterialRoot"],
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": same_secret_proof_record["sameSecretProofFamilyBindingRoot"],
            "sameSecretProofRoot": same_secret_proof_record["sameSecretProofRoot"],
            "statementHash": to_hex(&statement.statement_hash()),
            "proofSizeBytes": proof_size_bytes,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesHex": to_hex(&proof_bytes),
        });
        proof_record["publicKeyShareSuccinctProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", &proof_record)
                .expect("public-key share succinct proof root")
        );
        let proof_root_entry = serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareSuccinctProofRoot": proof_record["publicKeyShareSuccinctProofRoot"],
        });
        terminal_phase(&format!(
            "generated public-key share succinct proof trustee {trustee_roster_position}"
        ));

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
        "objectType": "PublicKeyShareSuccinctProofSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": PUBLIC_KEY_SHARE_PROOF_FAMILY,
        "proofVerificationStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
        "proofAccountingHash": succinct_public_key_share_accounting_hash()
            .expect("public-key share succinct accounting hash"),
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
        "publicKeyShareSuccinctProofRoots": proof_roots,
        "proofRecords": proof_records,
    });
    proof_set["publicKeyShareSuccinctProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareProofRoot", &proof_set)
            .expect("public-key share succinct proof set root")
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
