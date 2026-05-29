use super::*;

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
    let relinearization_arithmetic_fixture_hash = validate_development_key_arithmetic_fixture(
        value_at_path(evaluation_keys, &["relinearizationArithmeticFixture"])?,
        DEVELOPMENT_RELINEARIZATION_ARITHMETIC_FIXTURE_ID,
        key_switch_decomposition_hash,
    )?;
    let key_switch_arithmetic_fixture_hash = validate_development_key_arithmetic_fixture(
        value_at_path(evaluation_keys, &["keySwitchArithmeticFixture"])?,
        DEVELOPMENT_KEY_SWITCH_ARITHMETIC_FIXTURE_ID,
        key_switch_decomposition_hash,
    )?;
    compare_hash_at_path(
        evaluation_key_record,
        &["relinearizationArithmeticFixtureHash"],
        &relinearization_arithmetic_fixture_hash,
        "evaluation key relinearization arithmetic fixture hash",
    )?;
    compare_hash_at_path(
        evaluation_key_record,
        &["keySwitchArithmeticFixtureHash"],
        &key_switch_arithmetic_fixture_hash,
        "evaluation key key-switch arithmetic fixture hash",
    )?;

    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
        "rosterHash": hash_at_path(evaluation_key_record, &["rosterHash"])?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 2,
        "arithmeticFixtureHash": relinearization_arithmetic_fixture_hash,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let relinearization_key_root = hash_at_path(evaluation_keys, &["relinearizationKeyRoot"])?;
    compare_derived_hash(
        "RelinearizationKeyRoot",
        &relinearization_key_record,
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
    let rotations = array_at_path(rot_set, &["rotations"])?;
    if rotation_key_roots.len() != rotations.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rotation key root count does not match the provisional rotation set",
        ));
    }
    let mut exported_rotation_values = BTreeSet::new();
    for (rotation_index, rotation_key_root_record) in rotation_key_roots.iter().enumerate() {
        if value_at_path(rotation_key_root_record, &["rotation"])? != &rotations[rotation_index] {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rotation key root order does not match the provisional rotation set",
            ));
        }
        exported_rotation_values.insert(integer_at_path(rotation_key_root_record, &["rotation"])?);
        let rotation_key_record = json!({
            "objectType": "BgvRotationKey",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
            "rosterHash": hash_at_path(evaluation_key_record, &["rosterHash"])?,
            "collectivePublicKeyRoot": collective_public_key_root,
            "rotSetHash": rot_set_hash,
            "rotation": rotations[rotation_index].clone(),
            "keySwitchDecompositionHash": key_switch_decomposition_hash,
            "publicBasisId": BgvBasisKind::Extended.basis_id(),
            "publicRlweSampleCount": 1,
            "maliciousEvaluationKeyProofIncluded": false,
        });
        compare_derived_hash(
            "RotationKeyRoot",
            &rotation_key_record,
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

    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
        "rosterHash": hash_at_path(evaluation_key_record, &["rosterHash"])?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 1,
        "arithmeticFixtureHash": key_switch_arithmetic_fixture_hash,
        "genericKeySwitchApiExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let key_switch_key_root = hash_at_path(evaluation_keys, &["keySwitchKeyRoot"])?;
    compare_derived_hash(
        "KeySwitchKeyRoot",
        &key_switch_key_record,
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
                    "provisional rotation set entries must be signed integers",
                )
            })
        })
        .collect::<CanonicalResult<BTreeSet<_>>>()?;
    if &declared_rotations != exported_rotation_values {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "exported rotation keys must cover exactly the provisional rotation set",
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
                    "required rotation group {purpose} does not match the passive BGV setup fixture set"
                ),
            ));
        }
    }
    for purpose in [
        "bit-sliced-projection",
        "encrypted-aggregate-score-bit-derivation",
        "rank-accumulation",
        "target-projection",
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
        "bit-sliced-projection" => vec![1, 2, 4, 8, 16, -1, -2, -4, -8, -16],
        "encrypted-aggregate-score-bit-derivation" => vec![32, 64, 128, -32, -64, -128],
        "rank-accumulation" => vec![256, 512, 1024, 2048, -256, -512, -1024, -2048],
        "target-projection" => vec![4096, 8192, -4096, -8192],
        _ => return None,
    };

    Some(rotations.into_iter().collect())
}

fn validate_development_key_arithmetic_fixture(
    wrapped_fixture: &Value,
    expected_fixture_id: &str,
    expected_key_switch_decomposition_hash: &str,
) -> CanonicalResult<String> {
    let fixture_record = value_at_path(wrapped_fixture, &["fixture"])?;
    compare_string_at_path(
        fixture_record,
        &["objectType"],
        "BgvDevelopmentKeyArithmeticFixture",
        "development key arithmetic fixture object type",
    )?;
    compare_string_at_path(
        fixture_record,
        &["fixtureId"],
        expected_fixture_id,
        "development key arithmetic fixture id",
    )?;
    compare_hash_at_path(
        fixture_record,
        &["keySwitchDecompositionHash"],
        expected_key_switch_decomposition_hash,
        "development key arithmetic fixture decomposition hash",
    )?;
    compare_string_at_path(
        fixture_record,
        &["rnsArithmeticStatus"],
        "sampled-decompose-recompose-and-modmul-passed",
        "development key arithmetic status",
    )?;
    for sample in array_at_path(fixture_record, &["sampledCoefficientChecks"])? {
        if !bool_at_path(sample, &["recompositionMatches"])? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "development key arithmetic fixture has a failed decomposition check",
            ));
        }
        let modulus = unsigned_at_path(sample, &["modulus"])?;
        let source_coefficient = unsigned_at_path(sample, &["sourceCoefficient"])?;
        let digits = array_at_path(sample, &["decompositionDigits"])?;
        if digits.len() != 3 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "development key arithmetic fixture must use three decomposition digits",
            ));
        }
        let digit_base = 1_u128 << 23;
        let first_digit = u128::from(digits[0].as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "development key arithmetic digits must be non-negative integers",
            )
        })?);
        let second_digit = u128::from(digits[1].as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "development key arithmetic digits must be non-negative integers",
            )
        })?);
        let third_digit = u128::from(digits[2].as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "development key arithmetic digits must be non-negative integers",
            )
        })?);
        let recomposed =
            ((first_digit + digit_base * second_digit + digit_base * digit_base * third_digit)
                % u128::from(modulus)) as u64;
        if recomposed != source_coefficient
            || unsigned_at_path(sample, &["recomposedCoefficient"])? != source_coefficient
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "development key arithmetic fixture decomposition does not recompose",
            ));
        }
    }

    let fixture_hash = development_fixture_hash(fixture_record)?;
    compare_hash_at_path(
        wrapped_fixture,
        &["fixtureHash"],
        &fixture_hash,
        "development key arithmetic fixture hash",
    )?;

    Ok(fixture_hash)
}
