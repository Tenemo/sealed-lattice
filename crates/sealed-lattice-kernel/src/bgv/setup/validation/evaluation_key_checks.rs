use super::*;
use crate::bgv::setup::key_material::expected_evaluation_key_material_binding;

pub(super) fn validate_evaluation_keys(setup_package: &Value) -> CanonicalResult<()> {
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let evaluation_key_record = value_at_path(evaluation_keys, &["record"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_hash = hash_at_path(evaluation_key_record, &["rotSetHash"])?;
    compare_derived_hash(rot_set, rot_set_hash, "rotation set hash")?;
    let collective_public_key_root =
        hash_at_path(evaluation_key_record, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = hash_at_path(evaluation_key_record, &["bgvPublicKeyRoot"])?;
    compare_hash_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
        collective_public_key_root,
        "evaluation key collective public key root",
    )?;
    compare_hash_at_path(
        setup_package,
        &["collectivePublicKey", "bgvPublicKeyRoot"],
        bgv_public_key_root,
        "evaluation key BGV public key root",
    )?;
    let expected_material = expected_evaluation_key_material_binding(setup_package)?;
    let actual_material = value_at_path(evaluation_keys, &["evaluationKeyMaterialCommitment"])?;
    compare_hash_at_path(
        evaluation_key_record,
        &["evaluationKeyMaterialCommitmentHash"],
        string_at_path(&expected_material, &["materialHash"])?,
        "evaluation key material commitment hash",
    )?;
    if actual_material != &expected_material {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "evaluation key material commitment does not match the setup-derived key stream schedule",
        ));
    }

    let relinearization_key_record = value_at_path(actual_material, &["relinearizationKeyRecord"])?;
    let relinearization_key_root = hash_at_path(actual_material, &["relinearizationKeyRoot"])?;
    compare_derived_hash(
        relinearization_key_record,
        relinearization_key_root,
        "relinearization key root",
    )?;
    compare_hash_at_path(
        evaluation_key_record,
        &["relinearizationKeyRoot"],
        relinearization_key_root,
        "evaluation key relinearization root",
    )?;

    let rotation_key_roots = array_at_path(actual_material, &["rotationKeyRoots"])?;
    let expected_rotation_key_roots = array_at_path(&expected_material, &["rotationKeyRoots"])?;
    if rotation_key_roots.len() != expected_rotation_key_roots.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rotation key root count does not match the setup-derived key stream schedule",
        ));
    }
    let mut exported_rotation_values = BTreeSet::new();
    for (rotation_index, rotation_key_root_record) in rotation_key_roots.iter().enumerate() {
        exported_rotation_values.insert(integer_at_path(rotation_key_root_record, &["rotation"])?);
        let expected_rotation_root_record = expected_rotation_key_roots[rotation_index].clone();
        if rotation_key_root_record != &expected_rotation_root_record {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "rotation key root record does not match the setup-derived key stream schedule",
            ));
        }
        let rotation_key_records = array_at_path(actual_material, &["rotationKeyRecords"])?;
        let rotation_key_record = rotation_key_records.get(rotation_index).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "expected rotation key record count does not match the selected rotation set",
            )
        })?;
        compare_derived_hash(
            rotation_key_record,
            hash_at_path(rotation_key_root_record, &["rotationKeyRoot"])?,
            "rotation key root",
        )?;
    }
    validate_rotation_set(rot_set, &exported_rotation_values)?;
    if array_at_path(evaluation_key_record, &["rotationKeyRoots"])? != rotation_key_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "evaluation key record rotation roots do not match exported rotation roots",
        ));
    }

    let key_switch_key_record = value_at_path(actual_material, &["keySwitchKeyRecord"])?;
    let key_switch_key_root = hash_at_path(actual_material, &["keySwitchKeyRoot"])?;
    compare_derived_hash(
        key_switch_key_record,
        key_switch_key_root,
        "key-switch key root",
    )?;
    compare_hash_at_path(
        evaluation_key_record,
        &["keySwitchKeyRoot"],
        key_switch_key_root,
        "evaluation key key-switch root",
    )?;

    let evaluation_key_root = hash_at_path(evaluation_keys, &["evaluationKeyRoot"])?;
    compare_derived_hash(
        evaluation_key_record,
        evaluation_key_root,
        "evaluation key root",
    )
}

fn validate_rotation_set(
    rot_set: &Value,
    exported_rotation_values: &BTreeSet<i64>,
) -> CanonicalResult<()> {
    let declared_rotations = array_at_path(rot_set, &["rotations"])?
        .iter()
        .map(|rotation| {
            rotation.as_i64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "selected rotation set entries must be signed integers",
                )
            })
        })
        .collect::<CanonicalResult<BTreeSet<_>>>()?;
    if &declared_rotations != exported_rotation_values {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "exported rotation keys must cover exactly the selected rotation set",
        ));
    }

    Ok(())
}
