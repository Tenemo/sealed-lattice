use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::setup) fn expected_evaluation_key_material_binding(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_inputs = value_at_path(setup_package, &["setupInputs"])?;
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_hash = string_at_path(evaluation_keys, &["record", "rotSetHash"])?;

    evaluation_key_material_binding(EvaluationKeyMaterialInput {
        setup_seed_hash: string_at_path(setup_inputs, &["setupSeedHash"])?,
        ceremony_id: string_at_path(setup_inputs, &["ceremonyId"])?,
        manifest_hash: string_at_path(setup_inputs, &["manifestHash"])?,
        roster_hash: string_at_path(setup_inputs, &["rosterHash"])?,
        collective_public_key,
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
                "keyStreamSeed": key_stream_seed,
            })
        })
        .collect::<Vec<_>>();
    let relinearization_stream_record = json!({
        "objectType": "BgvRelinearizationKeyMaterialStream",
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "entries": relinearization_stream_entries,
    });
    let rotation_stream_record = json!({
        "objectType": "BgvRotationKeyMaterialStream",
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "rotSetHash": input.rot_set_hash,
        "entries": rotation_stream_entries,
    });
    let relinearization_stream_hash = evaluation_key_stream_hash(
        "relinearization-material-stream",
        &relinearization_stream_record,
    )?;
    let rotation_stream_hash =
        evaluation_key_stream_hash("rotation-material-stream", &rotation_stream_record)?;
    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "levelSchedule": relinearization_levels,
        "keyMaterialStreamHash": relinearization_stream_hash,
    });
    let relinearization_key_root = derive_canonical_object_hash(&relinearization_key_record)?;
    let mut rotation_key_roots = Vec::with_capacity(rotation_schedule.len());
    let mut rotation_key_records = Vec::with_capacity(rotation_schedule.len());
    for entry in &rotation_schedule {
        let entry_stream_record = json!({
            "objectType": "BgvRotationKeyMaterialStreamEntry",
            "collectivePublicKeyRoot": collective_public_key_root,
            "bgvPublicKeyRoot": bgv_public_key_root,
            "rotSetHash": input.rot_set_hash,
            "rotation": entry.rotation,
            "level": entry.level,
            "keyStreamSeed": evaluation_key_stream_seed(
                    input.setup_seed_hash,
                "rotation",
                entry.level,
                Some(entry.rotation),
            ),
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
            "keyMaterialStreamHash": entry_stream_hash,
        });
        let root = derive_canonical_object_hash(&record)?;
        rotation_key_roots.push(json!({
            "rotation": entry.rotation,
            "level": entry.level,
            "rotationKeyRoot": root,
        }));
        rotation_key_records.push(record);
    }
    let key_switch_stream_record = json!({
        "objectType": "BgvEvaluationKeySwitchMaterialStream",
        "relinearizationStreamHash": relinearization_stream_hash,
        "rotationStreamHash": rotation_stream_hash,
    });
    let key_switch_stream_hash =
        evaluation_key_stream_hash("key-switch-material-stream", &key_switch_stream_record)?;
    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
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
        "rotSetHash": input.rot_set_hash,
        "rotSet": input.rot_set,
        "relinearizationKeyRoot": relinearization_key_root,
        "relinearizationStreamHash": relinearization_stream_hash,
        "rotationKeyRoots": rotation_key_roots,
        "rotationStreamHash": rotation_stream_hash,
        "keySwitchKeyRoot": key_switch_key_root,
        "keySwitchStreamHash": key_switch_stream_hash,
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
