use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::setup) fn expected_evaluation_key_material_binding(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_inputs = value_at_path(setup_package, &["setupInputs"])?;
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let actual_material = value_at_path(evaluation_keys, &["evaluationKeyMaterialCommitment"])?;
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let key_switch_decomposition_hash =
        string_at_path(evaluation_keys, &["keySwitchDecompositionHash"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_hash = string_at_path(evaluation_keys, &["rotSetHash"])?;

    evaluation_key_material_binding(EvaluationKeyMaterialInput {
        setup_seed_hash: string_at_path(setup_inputs, &["setupSeedHash"])?,
        sampled_relation_checks: value_at_path(
            actual_material,
            &["record", "sampledRelationChecks"],
        )?
        .clone(),
        ceremony_id: string_at_path(setup_inputs, &["ceremonyId"])?,
        manifest_hash: string_at_path(setup_inputs, &["manifestHash"])?,
        roster_hash: string_at_path(setup_inputs, &["rosterHash"])?,
        collective_public_key,
        key_switch_decomposition_hash,
        rot_set,
        rot_set_hash,
    })
    .map(|binding| {
        json!({
            "record": binding.record,
            "materialHash": binding.material_hash,
            "relinearizationKeyRoot": binding.relinearization_key_root,
            "relinearizationKeyRecord": binding.relinearization_key_record,
            "keySwitchKeyRoot": binding.key_switch_key_root,
            "keySwitchKeyRecord": binding.key_switch_key_record,
            "rotationKeyRoots": binding.rotation_key_roots,
            "rotationKeyRecords": binding.rotation_key_records,
        })
    })
}

pub(super) fn evaluation_key_material_binding(
    input: EvaluationKeyMaterialInput<'_>,
) -> CanonicalResult<EvaluationKeyMaterialBinding> {
    let collective_public_key_root =
        string_at_path(input.collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(input.collective_public_key, &["bgvPublicKeyRoot"])?;
    let collective_public_key_coefficient_root = string_at_path(
        input.collective_public_key,
        &["collectivePublicKeyCoefficientRoot"],
    )?;
    let relinearization_levels = selected_relinearization_levels()?;
    let rotation_schedule = selected_rotation_schedule_entries()?;
    let relinearization_stream_entries = relinearization_levels
        .iter()
        .map(|level| {
            let key_stream_seed =
                evaluation_key_stream_seed(input.setup_seed_hash, "relinearization", *level, None);
            json!({
                "level": level,
                "keyStreamSeed": key_stream_seed,
                "sourcePolynomial": "secret-square",
                "digitCount": level + 1,
            })
        })
        .collect::<Vec<_>>();
    let rotation_stream_entries = rotation_schedule
        .iter()
        .map(|entry| {
            let key_stream_seed = evaluation_key_stream_seed(
                input.setup_seed_hash,
                "rotation",
                entry.level,
                Some(entry.rotation),
            );
            json!({
                "rotation": entry.rotation,
                "level": entry.level,
                "purpose": entry.purpose,
                "keyStreamSeed": key_stream_seed,
                "sourcePolynomial": "automorphism(secret)",
                "digitCount": entry.level + 1,
            })
        })
        .collect::<Vec<_>>();
    let relinearization_stream_record = json!({
        "objectType": "BgvRelinearizationKeyMaterialStream",
        "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "componentOrder": ["componentZeroB", "componentOneA"],
        "gadget": "crt-idempotent-per-active-data-prime",
        "entries": relinearization_stream_entries,
    });
    let rotation_stream_record = json!({
        "objectType": "BgvRotationKeyMaterialStream",
        "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "rotSetHash": input.rot_set_hash,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "componentOrder": ["componentZeroB", "componentOneA"],
        "gadget": "crt-idempotent-per-active-data-prime",
        "entries": rotation_stream_entries,
    });
    let relinearization_stream_hash = evaluation_key_stream_hash(
        "relinearization-material-stream",
        &relinearization_stream_record,
    )?;
    let rotation_stream_hash =
        evaluation_key_stream_hash("rotation-material-stream", &rotation_stream_record)?;
    let sampled_relation_checks = input.sampled_relation_checks;
    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "levelSchedule": relinearization_levels,
        "publicRlweSampleCount": total_digit_count(&selected_relinearization_levels()?),
        "keyMaterialStreamHash": relinearization_stream_hash,
    });
    let relinearization_key_root = derive_canonical_object_hash(&relinearization_key_record)?;
    let mut rotation_key_roots = Vec::with_capacity(rotation_schedule.len());
    let mut rotation_key_records = Vec::with_capacity(rotation_schedule.len());
    for entry in &rotation_schedule {
        let entry_stream_record = json!({
            "objectType": "BgvRotationKeyMaterialStreamEntry",
            "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
            "collectivePublicKeyRoot": collective_public_key_root,
            "bgvPublicKeyRoot": bgv_public_key_root,
            "rotSetHash": input.rot_set_hash,
            "rotation": entry.rotation,
            "level": entry.level,
            "purpose": entry.purpose,
            "keyStreamSeed": evaluation_key_stream_seed(
                    input.setup_seed_hash,
                "rotation",
                entry.level,
                Some(entry.rotation),
            ),
            "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        });
        let entry_stream_hash =
            evaluation_key_stream_hash("rotation-material-stream-entry", &entry_stream_record)?;
        let record = json!({
            "objectType": "BgvRotationKey",
            "ceremonyId": input.ceremony_id,
            "rosterHash": input.roster_hash,
            "collectivePublicKeyRoot": collective_public_key_root,
            "rotSetHash": input.rot_set_hash,
            "rotation": entry.rotation,
            "level": entry.level,
            "purpose": entry.purpose,
            "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
            "publicRlweSampleCount": entry.level + 1,
            "keyMaterialStreamHash": entry_stream_hash,
        });
        let root = derive_canonical_object_hash(&record)?;
        rotation_key_roots.push(json!({
            "rotation": entry.rotation,
            "level": entry.level,
            "purpose": entry.purpose,
            "rotationKeyRoot": root,
        }));
        rotation_key_records.push(record);
    }
    let key_switch_stream_record = json!({
        "objectType": "BgvEvaluationKeySwitchMaterialStream",
        "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
        "relinearizationStreamHash": relinearization_stream_hash,
        "rotationStreamHash": rotation_stream_hash,
        "sampledRelationChecks": sampled_relation_checks,
    });
    let key_switch_stream_hash =
        evaluation_key_stream_hash("key-switch-material-stream", &key_switch_stream_record)?;
    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "publicRlweSampleCount": total_digit_count(&selected_relinearization_levels()?)
            + rotation_schedule.iter().map(|entry| entry.level + 1).sum::<usize>(),
        "keyMaterialStreamHash": key_switch_stream_hash,
    });
    let key_switch_key_root = derive_canonical_object_hash(&key_switch_key_record)?;
    let record = json!({
        "objectType": "BgvEvaluationKeyMaterialCommitment",
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "rotSetHash": input.rot_set_hash,
        "rotSet": input.rot_set,
        "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
        "relinearizationKeyRoot": relinearization_key_root,
        "relinearizationStreamHash": relinearization_stream_hash,
        "rotationKeyRoots": rotation_key_roots,
        "rotationStreamHash": rotation_stream_hash,
        "keySwitchKeyRoot": key_switch_key_root,
        "keySwitchStreamHash": key_switch_stream_hash,
        "sampledRelationChecks": sampled_relation_checks,
    });
    let material_hash = derive_canonical_object_hash(&record)?;

    Ok(EvaluationKeyMaterialBinding {
        record,
        material_hash,
        relinearization_key_root,
        relinearization_key_record,
        key_switch_key_root,
        key_switch_key_record,
        rotation_key_roots,
        rotation_key_records,
    })
}
