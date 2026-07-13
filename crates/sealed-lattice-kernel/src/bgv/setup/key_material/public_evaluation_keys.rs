use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::setup) fn evaluation_keys(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
) -> CanonicalResult<Value> {
    let rot_set = selected_rotation_set()?;
    let rot_set_hash = derive_canonical_object_hash(&rot_set)?;
    let collective_public_key_root =
        string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?;
    let material_binding = evaluation_key_material_binding(EvaluationKeyMaterialInput {
        setup_seed_hash: &input.setup_seed_hash,
        ceremony_id: &input.ceremony_id,
        manifest_hash: &input.manifest_hash,
        roster_hash: &input.roster_hash,
        collective_public_key,
        rot_set: &rot_set,
        rot_set_hash: &rot_set_hash,
    })?;
    let evaluation_key_record = json!({
        "objectType": "BgvEvaluationKeySet",
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "rotSetHash": rot_set_hash,
        "evaluationKeyMaterialCommitmentHash": material_binding.material_hash,
        "relinearizationKeyRoot": material_binding.relinearization_key_root,
        "rotationKeyRoots": material_binding.rotation_key_roots,
        "keySwitchKeyRoot": material_binding.key_switch_key_root,
    });
    let evaluation_key_root = derive_canonical_object_hash(&evaluation_key_record)?;

    Ok(json!({
        "record": evaluation_key_record,
        "rotSet": rot_set,
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
        "evaluationKeyRoot": evaluation_key_root,
    }))
}
