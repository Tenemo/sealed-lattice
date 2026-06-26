use super::*;

pub(in crate::bgv::setup) fn evaluation_keys(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
    key_switch_decomposition_hash: &str,
) -> CanonicalResult<Value> {
    let rot_set = selected_rotation_set()?;
    let rot_set_hash = derive_protocol_hash("RotSetHash", &rot_set)?;
    let collective_public_key_root =
        string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?;
    let participant_identities = input
        .participants
        .iter()
        .map(|participant| participant.trustee_identity.clone())
        .collect::<Vec<_>>();
    let relinearization_levels = selected_relinearization_levels()?;
    let rotation_schedule = selected_rotation_schedule_entries()?;
    let sampled_relation_checks = sampled_evaluation_key_relation_checks(
        &input.private_setup_seed_hash,
        &input.setup_seed_hash,
        &participant_identities,
        &relinearization_levels,
        &rotation_schedule,
    )?;
    let material_binding = evaluation_key_material_binding(EvaluationKeyMaterialInput {
        setup_seed_hash: &input.setup_seed_hash,
        sampled_relation_checks: Value::Array(sampled_relation_checks),
        ceremony_id: &input.ceremony_id,
        manifest_hash: &input.manifest_hash,
        roster_hash: &input.roster_hash,
        collective_public_key,
        key_switch_decomposition_hash,
        rot_set: &rot_set,
        rot_set_hash: &rot_set_hash,
    })?;
    let evaluation_key_record = json!({
        "objectType": "BgvEvaluationKeySet",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "rotSetHash": rot_set_hash,
        "evaluationKeyMaterialCommitmentHash": material_binding.material_hash,
        "relinearizationKeyRoot": material_binding.relinearization_key_root,
        "rotationKeyRoots": material_binding.rotation_key_roots,
        "keySwitchKeyRoot": material_binding.key_switch_key_root,
    });
    let evaluation_key_root = derive_protocol_hash("EvalKeyRoot", &evaluation_key_record)?;

    Ok(json!({
        "record": evaluation_key_record,
        "rotSet": rot_set,
        "rotSetHash": rot_set_hash,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "evaluationKeyMaterialCommitment": {
            "record": material_binding.record,
            "materialHash": material_binding.material_hash,
            "relinearizationKeyRoot": material_binding.relinearization_key_root,
            "relinearizationKeyRecord": material_binding.relinearization_key_record,
            "keySwitchKeyRoot": material_binding.key_switch_key_root,
            "keySwitchKeyRecord": material_binding.key_switch_key_record,
            "rotationKeyRoots": material_binding.rotation_key_roots,
            "rotationKeyRecords": material_binding.rotation_key_records,
        },
        "evaluationKeyMaterialCommitmentHash": material_binding.material_hash,
        "relinearizationKeyRoot": material_binding.relinearization_key_root,
        "keySwitchKeyRoot": material_binding.key_switch_key_root,
        "rotationKeyRoots": material_binding.rotation_key_roots,
        "evaluationKeyRoot": evaluation_key_root,
    }))
}
