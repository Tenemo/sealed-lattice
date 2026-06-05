use super::*;
use crate::bgv::evaluator::{
    records::MAXIMUM_OPTION_COUNT,
    top_k::{
        direct_score_packing_basis_galois_elements, packed_rank_forward_basis_galois_elements,
        packed_rank_return_basis_galois_elements,
    },
};
use crate::bgv::setup::key_material::expected_evaluation_key_material_binding;

pub(super) fn validate_evaluation_keys(setup_package: &Value) -> CanonicalResult<()> {
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let evaluation_key_record = value_at_path(evaluation_keys, &["record"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_hash = hash_at_path(evaluation_keys, &["rotSetHash"])?;
    compare_derived_hash("RotSetHash", rot_set, rot_set_hash, "rotation set hash")?;
    let key_switch_decomposition_hash =
        hash_at_path(evaluation_keys, &["keySwitchDecompositionHash"])?;
    compare_hash_at_path(
        evaluation_key_record,
        &["keySwitchDecompositionHash"],
        key_switch_decomposition_hash,
        "evaluation key decomposition hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["certificates", "keySwitchDecompositionHash"],
        key_switch_decomposition_hash,
        "certificate key-switch decomposition hash",
    )?;
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
    compare_hash_at_path(
        evaluation_key_record,
        &["rotSetHash"],
        rot_set_hash,
        "evaluation key rotation set hash",
    )?;
    let expected_material = expected_evaluation_key_material_binding(setup_package)?;
    let actual_material = value_at_path(evaluation_keys, &["evaluationKeyMaterialCommitment"])?;
    compare_hash_at_path(
        evaluation_key_record,
        &["evaluationKeyMaterialCommitmentHash"],
        string_at_path(&expected_material, &["materialHash"])?,
        "evaluation key material commitment hash",
    )?;
    compare_hash_at_path(
        evaluation_keys,
        &["evaluationKeyMaterialCommitmentHash"],
        string_at_path(&expected_material, &["materialHash"])?,
        "exported evaluation key material commitment hash",
    )?;
    if actual_material != &expected_material {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation key material commitment does not match the setup-derived key stream schedule",
        ));
    }
    validate_sampled_key_material_checks(value_at_path(
        actual_material,
        &["record", "sampledRelationChecks"],
    )?)?;

    let relinearization_key_record =
        value_at_path(&expected_material, &["relinearizationKeyRecord"])?;
    let relinearization_key_root = hash_at_path(evaluation_keys, &["relinearizationKeyRoot"])?;
    compare_derived_hash(
        "RelinearizationKeyRoot",
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

    let rotation_key_roots = array_at_path(evaluation_keys, &["rotationKeyRoots"])?;
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
                CanonicalErrorCode::ProfileComponentMismatch,
                "rotation key root record does not match the setup-derived key stream schedule",
            ));
        }
        let rotation_key_records = array_at_path(&expected_material, &["rotationKeyRecords"])?;
        let rotation_key_record = rotation_key_records.get(rotation_index).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "expected rotation key record count does not match the selected rotation set",
            )
        })?;
        compare_derived_hash(
            "RotationKeyRoot",
            rotation_key_record,
            hash_at_path(rotation_key_root_record, &["rotationKeyRoot"])?,
            "rotation key root",
        )?;
    }
    validate_required_rotation_groups(rot_set, &exported_rotation_values)?;
    if array_at_path(evaluation_key_record, &["rotationKeyRoots"])? != rotation_key_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation key record rotation roots do not match exported rotation roots",
        ));
    }

    let key_switch_key_record = value_at_path(&expected_material, &["keySwitchKeyRecord"])?;
    let key_switch_key_root = hash_at_path(evaluation_keys, &["keySwitchKeyRoot"])?;
    compare_derived_hash(
        "KeySwitchKeyRoot",
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
        "EvalKeyRoot",
        evaluation_key_record,
        evaluation_key_root,
        "evaluation key root",
    )
}

fn validate_required_rotation_groups(
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
            CanonicalErrorCode::ProfileComponentMismatch,
            "exported rotation keys must cover exactly the selected rotation set",
        ));
    }

    let required_rotation_groups = array_at_path(rot_set, &["requiredRotationGroups"])?;
    let mut seen_purposes = BTreeSet::new();
    for group in required_rotation_groups {
        let purpose = string_at_path(group, &["purpose"])?;
        if !seen_purposes.insert(purpose.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "required rotation group purposes must be unique",
            ));
        }
        let expected_group_rotations =
            expected_required_rotation_group(purpose).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    format!("required rotation group {purpose} is not part of the passive BGV setup profile"),
                )
            })?;
        let mut actual_group_rotations = BTreeSet::new();
        for rotation in array_at_path(group, &["rotations"])? {
            let rotation_value = rotation.as_i64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "required rotation group entries must be signed integers",
                )
            })?;
            actual_group_rotations.insert(rotation_value);
            if !declared_rotations.contains(&rotation_value)
                || !exported_rotation_values.contains(&rotation_value)
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    format!(
                        "required rotation group {purpose} is missing rotation {rotation_value}"
                    ),
                ));
            }
        }
        if actual_group_rotations != expected_group_rotations {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "required rotation group {purpose} does not match the selected BGV setup rotation set"
                ),
            ));
        }
    }
    for purpose in [
        "direct-score-packing-generator-basis",
        "generator-ordered-packed-rank-forward-basis",
        "generator-ordered-packed-rank-return-basis",
    ] {
        if !seen_purposes.contains(purpose) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("required rotation group {purpose} is missing"),
            ));
        }
    }

    Ok(())
}

fn expected_required_rotation_group(purpose: &str) -> Option<BTreeSet<i64>> {
    let rotations = match purpose {
        "direct-score-packing-generator-basis" => {
            direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)
                .ok()?
                .into_iter()
                .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
                .collect::<Vec<_>>()
        }
        "generator-ordered-packed-rank-forward-basis" => {
            packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)
                .ok()?
                .into_iter()
                .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
                .collect::<Vec<_>>()
        }
        "generator-ordered-packed-rank-return-basis" => {
            packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)
                .ok()?
                .into_iter()
                .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
                .collect::<Vec<_>>()
        }
        _ => return None,
    };

    Some(rotations.into_iter().collect())
}

fn validate_sampled_key_material_checks(sampled_checks: &Value) -> CanonicalResult<()> {
    for check in sampled_checks.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation key material sampled checks must be an array",
        )
    })? {
        hash_at_path(check, &["keyStreamSeed"])?;
        for sample in array_at_path(check, &["samples"])? {
            if !bool_at_path(sample, &["relationMatches"])? {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "evaluation key material stream sample does not satisfy the key-switch relation",
                ));
            }
            let expected = unsigned_at_path(sample, &["expectedKeyLimbCoefficient"])?;
            let actual = unsigned_at_path(sample, &["decryptedKeyLimbCoefficient"])?;
            if actual != expected {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "evaluation key material stream sample has an inconsistent relation result",
                ));
            }
        }
    }

    Ok(())
}
