use super::*;

use crate::hashing::derive_canonical_object_hash;

// Assembles the public evaluation-key set the accepted-setup verifier's
// `verify_public_evaluation_key_set` recomputes: one relinearization key root per
// scheduled level (derived from the verified round-one/round-two aggregate roots)
// and one Galois key root per scheduled rotation (derived from the verified batch
// share roots). The key-root preimages are byte-identical to the verifier's
// `expected_relinearization_key_roots_for_evaluation_keys` and
// `expected_galois_key_roots_for_evaluation_keys`, and the set carries no
// streamed material reference, so the package embeds the whole set and no
// transported public evaluation-key material is required.
// The public evaluation-key set with an optional committed-material aggregate
// binding folded in. When `aggregate_binding` is supplied it is added under
// `aggregateBinding` before the set hash is computed, so it is bound by
// `evaluationKeySetHash` exactly as the verifier recomputes it (the verifier
// removes only `evaluationKeySetHash` and hashes every other field, so a present
// `aggregateBinding` is covered). The binding is produced by
// `evaluation_key_aggregate_binding_object`.
pub(in super::super) fn public_evaluation_key_set_object_with_aggregate_binding(
    package: &serde_json::Value,
    aggregate_binding: Option<serde_json::Value>,
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
            let relinearization_key_root = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "RelinearizationKeyAggregate",
                "materialEncoding": "root-bound-public-key-switch-component-roots",
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "relinearizationKeyShareRoundsRoot": relinearization_rounds_root,
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "roundOneAggregateRoot": round_one_aggregate_root,
                "roundTwoAggregateRoot": round_two_aggregate_root,
            }))
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
            let galois_key_root = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "GaloisKeyAggregate",
                "materialEncoding": "root-bound-public-key-switch-component-roots",
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
                "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                "rotation": rotation,
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "contributingShareRoots": contributing_share_roots,
            }))
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
        "materialEncoding": "root-bound-public-key-switch-component-roots",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": participant_count_from_package(package),
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
        "relinearizationKeyShareRoundsRoot": relinearization_rounds_root,
        "relinearizationLevelSchedule": schedule["relinearizationLevelSchedule"],
        "relinearizationKeyRoots": relinearization_key_roots,
        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
        "requiredGaloisKeySchedule": schedule["requiredGaloisKeySchedule"],
        "galoisKeyShareBatchRoots": galois_key_share_batch_roots,
        "galoisKeyRoots": galois_key_roots,
        "genericKeySwitchKeyRoots": [],
    });
    // Fold the committed-material aggregate binding in before the set hash, so it
    // is bound by `evaluationKeySetHash`. The verifier's aggregate-binding crypto
    // check additionally requires the set to carry a transported-material
    // reference; an embedded (reference-free) set still binds this record by hash.
    if let Some(aggregate_binding) = aggregate_binding {
        evaluation_keys["aggregateBinding"] = aggregate_binding;
    }
    evaluation_keys["evaluationKeySetHash"] = serde_json::json!(
        derive_canonical_object_hash(&evaluation_keys).expect("evaluation key set hash")
    );

    evaluation_keys
}

// Build the committed-material aggregate binding for the package: the
// `evaluationKeys.aggregateBinding` record and the matching transport-request
// object `transportedEvaluationKeyAggregateBindingOpenings`. Reconstructs one
// trustee evaluation-key statement per roster position (the same statement the
// verifier rebuilds), then drives the family backend's creation aggregator to
// commit each trustee's recombined component material, solve the wrap multiples
// against the published runtime key, and open the batched linear evaluations.
//
// `round_one_aggregate_diagonals_by_level` is the per-level public round-one
// aggregate diagonal the round-two statements are proven against, produced by the
// relinearization rounds fixture. Returns `(aggregateBinding, transportedOpenings)`.
pub(in super::super) fn evaluation_key_aggregate_binding_object(
    package: &serde_json::Value,
    proof_material_request: &serde_json::Value,
    round_one_aggregate_diagonals_by_level: &BTreeMap<u64, Vec<Vec<u64>>>,
) -> (serde_json::Value, serde_json::Value) {
    use crate::bgv::setup::accepted_setup::{
        TrusteeEvaluationKeyStatementInputs, trustee_evaluation_key_statement_from_package,
        verified_same_secret_bridge_material_from_package,
    };
    use crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule::prove_evaluation_key_aggregate_binding;

    let participant_count = participant_count_from_package(package);
    let verified_same_secret_bridge = package.get("sameSecretBridgeStatementSet").map(|_| {
        verified_same_secret_bridge_material_from_package(package, proof_material_request)
            .expect("same-secret bridge material")
    });

    let statements_by_trustee = (0..participant_count)
        .map(|trustee_roster_position| {
            trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
                setup_package: package,
                transported_key_switch_component_material: proof_material_request
                    .get("transportedEvaluationKeyShareComponentMaterial"),
                verified_same_secret_bridge: verified_same_secret_bridge.as_ref(),
                round_one_aggregate_diagonals_by_level,
                trustee_roster_position,
            })
            .expect("trustee evaluation-key statement")
        })
        .collect::<Vec<_>>();

    // The aggregator regenerates each atom proof's material commitment from that
    // atom proof's own initial salt seed (derived from the statement hash and the
    // schedule index), so the binding reproduces every atom proof's `material_root`
    // and no separate aggregator salt seed is needed.
    let key_group_bindings = prove_evaluation_key_aggregate_binding(&statements_by_trustee)
        .expect("creation-side aggregate binding");

    let mut key_group_records = Vec::with_capacity(key_group_bindings.len());
    let mut opening_records = Vec::new();
    for binding in &key_group_bindings {
        let trustee_material_roots = binding
            .trustee_material_roots_hex
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, material_root)| {
                serde_json::json!({
                    "trusteeRosterPosition": trustee_roster_position as u64,
                    "materialRoot": material_root,
                })
            })
            .collect::<Vec<_>>();
        for (material_root, opening_bytes_hex) in binding
            .trustee_material_roots_hex
            .iter()
            .zip(binding.opening_bytes_hex.iter())
        {
            opening_records.push(serde_json::json!({
                "materialRoot": material_root,
                "openingBytesHex": opening_bytes_hex,
            }));
        }
        let mut key_group_record = serde_json::json!({
            "objectType": "EvaluationKeyAggregateBindingKeyGroup",
            "level": binding.level,
            "groupStartLimb": binding.group_start_limb as u64,
            "groupLimbCount": binding.group_limb_count as u64,
            // The ring degree the record binds is the statement's ring degree. The
            // verifier requires it to equal POLYNOMIAL_DEGREE; a reduced-ring
            // development package emits its own degree and the verifier fail-closes
            // on the full-ring mismatch, which is the intended behavior.
            "ringDegree": binding.ring_degree as u64,
            "wrapMultiples": binding.wrap_multiples,
            "trusteeMaterialRoots": trustee_material_roots,
        });
        if let Some(rotation) = binding.rotation {
            key_group_record["rotation"] = serde_json::json!(rotation);
        }
        key_group_records.push(key_group_record);
    }

    let aggregate_binding = serde_json::json!({
        "objectType": "EvaluationKeyAggregateBindingSet",
        "keyGroups": key_group_records,
    });
    let transported_openings = serde_json::json!({
        "objectType": "SetupTransportedEvaluationKeyAggregateBindingOpeningSet",
        "openings": opening_records,
    });

    (aggregate_binding, transported_openings)
}
