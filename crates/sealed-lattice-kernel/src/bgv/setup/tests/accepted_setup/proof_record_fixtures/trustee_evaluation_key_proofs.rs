use super::super::*;
use super::*;
use rayon::prelude::*;

use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn trustee_evaluation_key_proofs_object_with_terminal_transport(
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
    let compact_terminal_proof_transport = terminal_transport.is_some();
    let trustee_proof_batch_size = if terminal_transport.is_some() {
        // Full-ring terminal proving. An explicit
        // SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE (set by the memory-aware heavy
        // test runner from available RAM) is authoritative, so a memory-constrained
        // runner serializes provers and the build is not killed mid-proving no
        // matter how many cores the runner reports. Without an explicit override,
        // run several provers at once to fill a modern multi-core workstation: each
        // prover only saturates a few cores through the shared work pool, so derive
        // concurrency from roughly a quarter of the available cores. Either way,
        // cap by the participant count so the batch never exceeds the trustees
        // being proved.
        explicit_trustee_proof_batch_size_override()
            .or_else(|| {
                std::thread::available_parallelism()
                    .ok()
                    .map(|cores| (cores.get() / 4).max(1))
            })
            .unwrap_or_else(trustee_evaluation_key_proof_generation_batch_size)
            .min(same_secret_proofs.len())
    } else {
        trustee_evaluation_key_proof_generation_batch_size()
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
                    "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
                    "ceremonyId": setup_context["ceremonyId"],
                    "manifestHash": setup_context["manifestHash"],
                    "rosterHash": setup_context["rosterHash"],
                    "setupParametersHash": setup_context["setupParametersHash"],
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
                build_trustee_evaluation_key_proof_record(
                    work_item,
                    &resumed_records,
                    ring_degree,
                    compact_terminal_proof_transport,
                )
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
            derive_canonical_object_hash(&record).expect("trustee evaluation-key proof root")
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
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": participant_count_from_package(package),
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
        derive_canonical_object_hash(&proof_set).expect("trustee evaluation-key proof set root")
    );

    proof_set
}

fn build_trustee_evaluation_key_proof_record(
    work_item: TrusteeEvaluationKeyProofWorkItem,
    resumed_records: &BTreeMap<u64, BuiltTrusteeEvaluationKeyProofRecord>,
    ring_degree: usize,
    compact_terminal_proof_transport: bool,
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
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "TrusteeEvaluationKeyProofRandomness",
        "fixture": "trustee-evaluation-key-proof-randomness",
        "trusteeRosterPosition": work_item.trustee_roster_position,
    }))
    .expect("trustee proof randomness seed");
    let statement_hash_hex = to_hex(&work_item.statement.statement_hash());
    let proof_bytes = checkpointed_anchor_proof_bytes(
        TRUSTEE_EVALUATION_KEY_ANCHOR_PROOF_CHECKPOINT_DIRECTORY,
        &statement_hash_hex,
        || {
            let proof = prove_evaluation_key_share(
                &work_item.statement,
                &witness,
                &proof_randomness_seed_hex,
            )
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
            encode_trustee_evaluation_key_proof(&proof)
        },
    );
    terminal_phase(&format!(
        "generated trustee evaluation-key proof trustee {} ({} bytes)",
        work_item.trustee_roster_position,
        proof_bytes.len(),
    ));
    if compact_terminal_proof_transport {
        return trustee_evaluation_key_record_with_compact_transported_proof_bytes(
            work_item.record,
            proof_bytes,
        );
    }
    let record =
        trustee_evaluation_key_record_with_embedded_proof_bytes(work_item.record, &proof_bytes);
    BuiltTrusteeEvaluationKeyProofRecord {
        record,
        transported_proof_material: None,
    }
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

fn trustee_evaluation_key_record_with_compact_transported_proof_bytes(
    mut record: serde_json::Value,
    proof_bytes: Vec<u8>,
) -> BuiltTrusteeEvaluationKeyProofRecord {
    let proof_size_bytes = u64::try_from(proof_bytes.len()).expect("proof size bytes");
    let proof_bytes_hash = trustee_evaluation_key_proof_bytes_hash(&proof_bytes);
    let chunks = proof_bytes_transport_chunks(proof_bytes);
    let transport_hashes = setup_proof_material_transport_hashes(
        TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("trustee evaluation-key proof transport hashes");
    apply_trustee_evaluation_key_proof_transport_fields(
        &mut record,
        proof_size_bytes,
        &proof_bytes_hash,
        &transport_hashes,
    );
    let proof_material_root =
        trustee_evaluation_key_proof_material_root(&record, &transport_hashes)
            .expect("trustee evaluation-key proof material root");
    record["proofMaterialRoot"] = serde_json::json!(proof_material_root.clone());
    record["trusteeEvaluationKeyProofRoot"] = serde_json::json!(
        derive_canonical_object_hash(&record)
            .expect("transported trustee evaluation-key proof root")
    );
    let proof_material =
        transported_trustee_evaluation_key_proof_material(&record, &transport_hashes);
    register_verified_trustee_evaluation_key_proof_material_chunks(&proof_material_root, chunks)
        .expect("verified trustee evaluation-key proof material chunks");

    BuiltTrusteeEvaluationKeyProofRecord {
        record,
        transported_proof_material: Some(proof_material),
    }
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
                derive_canonical_object_hash(&record)
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
pub(in super::super) fn trustee_evaluation_key_witness_for_fixture(
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
