use super::*;

use crate::bgv::evaluator::top_k::SELECTED_EVALUATOR_WORKING_LEVEL;
use crate::hashing::derive_canonical_object_hash;

const PUBLIC_KEY_SWITCH_COMPONENT_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/public-key-switch-component-vector-v1";
const PUBLIC_EVALUATION_KEY_COMPONENT_ENCODING: &str = "component-zero-b-little-endian-u64-coefficient-vectors-with-public-component-one-regenerated-from-stream-seed";

pub(crate) struct PassiveSetupEvaluationKeySeeds {
    pub(crate) relinearization_level: usize,
    pub(crate) relinearization_key_seed: String,
    pub(crate) rotation_key_seeds: BTreeMap<(usize, usize), String>,
}

pub(crate) struct PassiveSetupPublicEvaluationKeys {
    pub(crate) relinearization_key: Option<KeySwitchKey>,
    pub(crate) rotation_keys: BTreeMap<usize, KeySwitchKey>,
}

pub(crate) struct PreparedPassiveSetupPublicEvaluationKeys {
    pub(crate) keys: PassiveSetupPublicEvaluationKeys,
    pub(crate) record: Value,
}

pub(crate) fn evaluation_key_seeds_from_passive_setup_package(
    setup_package: &Value,
    working_level: usize,
) -> CanonicalResult<PassiveSetupEvaluationKeySeeds> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    let setup_seed_hash = string_at_path(setup_package, &["setupInputs", "setupSeedHash"])?;
    if working_level > SELECTED_EVALUATOR_WORKING_LEVEL {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setup-bound evaluator working level is above the selected key schedule level",
        ));
    }
    let relinearization_level = SELECTED_EVALUATOR_WORKING_LEVEL;
    let relinearization_key_seed = key_material::evaluation_key_stream_seed(
        setup_seed_hash,
        "relinearization",
        relinearization_level,
        None,
    );
    let mut rotation_key_seeds = BTreeMap::new();
    let rotation_roots = array_at_path(
        setup_package,
        &[
            "evaluationKeys",
            "evaluationKeyMaterialCommitment",
            "rotationKeyRoots",
        ],
    )?;
    for rotation_root in rotation_roots {
        let rotation = usize_at_path(rotation_root, &["rotation"])?;
        let level = usize_at_path(rotation_root, &["level"])?;
        rotation_key_seeds.insert(
            (rotation, level),
            key_material::evaluation_key_stream_seed(
                setup_seed_hash,
                "rotation",
                level,
                Some(rotation),
            ),
        );
    }

    Ok(PassiveSetupEvaluationKeySeeds {
        relinearization_level,
        relinearization_key_seed,
        rotation_key_seeds,
    })
}

pub(crate) fn generate_passive_setup_public_evaluation_key_material_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let generated = generate_passive_setup_public_evaluation_keys_from_request(request)?;
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let seed_material = evaluation_key_seeds_from_passive_setup_package(
        setup_package,
        usize_at_path(&generated.record, &["workingLevel"])?,
    )?;
    let relinearization_key = generated.keys.relinearization_key.as_ref().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "generated public evaluation-key material is missing the relinearization key",
        )
    })?;
    let relinearization_keys = vec![public_key_switch_material_entry(
        "relinearization",
        "secret-square",
        None,
        seed_material.relinearization_level,
        &seed_material.relinearization_key_seed,
        relinearization_key,
    )?];
    let rotation_keys = generated
        .keys
        .rotation_keys
        .iter()
        .map(|(rotation, key)| {
            let seed = seed_material
                .rotation_key_seeds
                .get(&(*rotation, key.level))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "requested public rotation key is not part of the selected setup rotation set",
                    )
                })?;
            public_key_switch_material_entry(
                "rotation",
                "selected-rotation",
                Some(*rotation),
                key.level,
                seed,
                key,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let mut material = generated.record;
    material["objectType"] = Value::String("BgvPublicEvaluationKeyMaterial".to_string());
    material["componentEncoding"] =
        Value::String(PUBLIC_EVALUATION_KEY_COMPONENT_ENCODING.to_string());
    material["relinearizationKeys"] = Value::Array(relinearization_keys);
    material["rotationKeys"] = Value::Array(rotation_keys);
    let public_material_hash = derive_canonical_object_hash(&material)?;
    material["publicEvaluationKeyMaterialHash"] = Value::String(public_material_hash);

    Ok(material)
}

pub(crate) fn generate_passive_setup_public_evaluation_keys_from_request(
    request: &Value,
) -> CanonicalResult<PreparedPassiveSetupPublicEvaluationKeys> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    let private_setup_seed = string_at_path(request, &["setupPrivateWitness", "setupSeed"])?;
    let working_level = request
        .get("workingLevel")
        .and_then(Value::as_u64)
        .and_then(|level| usize::try_from(level).ok())
        .unwrap_or(DATA_PRIMES.len() - 1);
    if working_level >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material working level is outside the selected data basis",
        ));
    }
    let rotation_requests = read_public_evaluation_key_rotation_requests(request)?;

    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, private_setup_seed)?;
    let seed_material =
        evaluation_key_seeds_from_passive_setup_package(setup_package, working_level)?;
    let mut relinearization_key = generate_relinearization_key(
        &evaluator_key,
        seed_material.relinearization_level,
        &seed_material.relinearization_key_seed,
    )?;
    // Only component-b is transported; component-a is the public uniform RLWE
    // sample, regenerated deterministically from the bound stream seed, so it
    // carries no secret and needs no transport.
    relinearization_key.drop_component_a_ntt();
    let mut rotation_keys = BTreeMap::new();
    for (rotation, level) in rotation_requests {
        let seed = seed_material
            .rotation_key_seeds
            .get(&(rotation, level))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "requested public rotation key is not part of the selected setup rotation set",
                )
            })?;
        let mut key = generate_galois_key(&evaluator_key, rotation, level, seed)?;
        key.drop_component_a_ntt();
        if rotation_keys.insert(rotation, key).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "rotation key requests must not repeat a rotation element",
            ));
        }
    }
    let record = json!({
        "objectType": "PreparedBgvPublicEvaluationKeyMaterial",
        "objectVersion": 1,
        "setupPackageHash": string_at_path(setup_package, &["setupPackageHash"])?,
        "collectivePublicKeyRoot": string_at_path(setup_package, &["collectivePublicKey", "collectivePublicKeyRoot"])?,
        "bgvPublicKeyRoot": string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
        "evaluationKeyRoot": string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
        "keySwitchDecompositionHash": string_at_path(setup_package, &["evaluationKeys", "keySwitchDecompositionHash"])?,
        "rotSetHash": string_at_path(setup_package, &["evaluationKeys", "rotSetHash"])?,
        "workingLevel": seed_material.relinearization_level,
        "relinearizationKeyCount": 1,
        "rotationKeyCount": rotation_keys.len(),
    });

    Ok(PreparedPassiveSetupPublicEvaluationKeys {
        keys: PassiveSetupPublicEvaluationKeys {
            relinearization_key: Some(relinearization_key),
            rotation_keys,
        },
        record,
    })
}

pub(crate) fn public_evaluation_keys_from_material(
    setup_package: &Value,
    material: &Value,
    working_level: usize,
) -> CanonicalResult<PassiveSetupPublicEvaluationKeys> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    compare_string_at_path(
        material,
        &["objectType"],
        "BgvPublicEvaluationKeyMaterial",
        "public evaluation-key material object type",
    )?;
    if usize_at_path(material, &["objectVersion"])? != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "public evaluation-key material object version is unsupported",
        ));
    }
    compare_string_at_path(
        material,
        &["componentEncoding"],
        PUBLIC_EVALUATION_KEY_COMPONENT_ENCODING,
        "public evaluation-key material component encoding",
    )?;
    compare_hash_at_path(
        material,
        &["setupPackageHash"],
        string_at_path(setup_package, &["setupPackageHash"])?,
        "public evaluation-key material setup package hash",
    )?;
    compare_hash_at_path(
        material,
        &["evaluationKeyRoot"],
        string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
        "public evaluation-key material evaluation key root",
    )?;
    compare_hash_at_path(
        material,
        &["collectivePublicKeyRoot"],
        string_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?,
        "public evaluation-key material collective public key root",
    )?;
    compare_hash_at_path(
        material,
        &["bgvPublicKeyRoot"],
        string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
        "public evaluation-key material BGV public key root",
    )?;
    compare_hash_at_path(
        material,
        &["keySwitchDecompositionHash"],
        string_at_path(
            setup_package,
            &["evaluationKeys", "keySwitchDecompositionHash"],
        )?,
        "public evaluation-key material key-switch decomposition hash",
    )?;
    compare_hash_at_path(
        material,
        &["rotSetHash"],
        string_at_path(setup_package, &["evaluationKeys", "rotSetHash"])?,
        "public evaluation-key material rotation set hash",
    )?;
    if usize_at_path(material, &["workingLevel"])? < working_level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public evaluation-key material working level is below the evaluator working level",
        ));
    }
    let mut hash_input = material.clone();
    hash_input
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public evaluation-key material must be an object",
            )
        })?
        .remove("publicEvaluationKeyMaterialHash");
    compare_hash_at_path(
        material,
        &["publicEvaluationKeyMaterialHash"],
        &derive_canonical_object_hash(&hash_input)?,
        "public evaluation-key material hash",
    )?;

    let seed_material =
        evaluation_key_seeds_from_passive_setup_package(setup_package, working_level)?;
    let mut relinearization_key = None;
    for entry in array_at_path(material, &["relinearizationKeys"])? {
        let level = usize_at_path(entry, &["level"])?;
        let seed = string_at_path(entry, &["keyStreamSeed"])?;
        if level != seed_material.relinearization_level
            || seed != seed_material.relinearization_key_seed
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public relinearization key entry does not match the selected key schedule",
            ));
        }
        let key = public_key_switch_material_entry_to_key(entry, "relinearization", None)?;
        if relinearization_key.replace(key).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public evaluation-key material repeats a relinearization key entry",
            ));
        }
    }
    if relinearization_key.is_none() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material is missing the required relinearization key",
        ));
    }

    let mut rotation_keys = BTreeMap::new();
    for entry in array_at_path(material, &["rotationKeys"])? {
        let rotation = usize_at_path(entry, &["rotation"])?;
        let level = usize_at_path(entry, &["level"])?;
        let seed = string_at_path(entry, &["keyStreamSeed"])?;
        if seed_material
            .rotation_key_seeds
            .get(&(rotation, level))
            .map(String::as_str)
            != Some(seed)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public rotation key seed does not match the setup key stream",
            ));
        }
        let key = public_key_switch_material_entry_to_key(entry, "rotation", Some(rotation))?;
        if rotation_keys.insert(rotation, key).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public evaluation-key material repeats a rotation key",
            ));
        }
    }

    Ok(PassiveSetupPublicEvaluationKeys {
        relinearization_key,
        rotation_keys,
    })
}

pub(super) fn read_public_evaluation_key_rotation_requests(
    request: &Value,
) -> CanonicalResult<Vec<(usize, usize)>> {
    match request.get("rotationKeys") {
        // Rotation material is generated only on explicit request. The full
        // committed working-level rotation schedule is too large for one
        // material response (each working-level key carries every
        // decomposition digit), so callers request the rotations they need.
        None => Ok(Vec::new()),
        Some(Value::Array(entries)) => {
            let mut seen = BTreeSet::new();
            entries
                .iter()
                .map(|entry| {
                    let rotation = usize_at_path(entry, &["rotation"])?;
                    let level = usize_at_path(entry, &["level"])?;
                    if !seen.insert((rotation, level)) {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::ComponentMismatch,
                            "rotationKeys must not repeat a rotation and level",
                        ));
                    }

                    Ok((rotation, level))
                })
                .collect()
        }
        Some(_) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rotationKeys must be an array when supplied",
        )),
    }
}

#[cfg(test)]
pub(super) fn selected_public_evaluation_key_rotation_requests()
-> CanonicalResult<Vec<(usize, usize)>> {
    crate::bgv::evaluator::top_k::selected_evaluator_rotation_key_schedule(MAXIMUM_OPTION_COUNT)
}

fn public_key_switch_material_entry(
    key_kind: &str,
    purpose: &str,
    rotation: Option<usize>,
    level: usize,
    seed: &str,
    key: &KeySwitchKey,
) -> CanonicalResult<Value> {
    if key.level != level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "generated public key-switch material level does not match its request",
        ));
    }
    let digits = key
        .components
        .iter()
        .enumerate()
        .map(|(digit_index, component)| {
            let component_b = component.component_b.as_ref().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public key-switch material serialization requires component-b coefficient limbs",
                )
            })?;
            let limbs = component_b
                .iter()
                .enumerate()
                .map(|(limb_index, coefficients)| {
                    json!({
                        "limbIndex": limb_index,
                        "modulus": DATA_PRIMES[limb_index],
                        "componentZeroBLeHex": coefficient_vector_le_hex(coefficients),
                        "componentZeroBHash512": coefficient_vector_hash512(
                            coefficients,
                            PUBLIC_KEY_SWITCH_COMPONENT_VECTOR_HASH_DOMAIN,
                        ),
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({
                "digitIndex": digit_index,
                "limbs": limbs,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "keyKind": key_kind,
        "purpose": purpose,
        "rotation": rotation,
        "level": level,
        "keyStreamSeed": seed,
        "digits": digits,
    }))
}

fn public_key_switch_material_entry_to_key(
    entry: &Value,
    expected_key_kind: &str,
    expected_rotation: Option<usize>,
) -> CanonicalResult<KeySwitchKey> {
    compare_string_at_path(
        entry,
        &["keyKind"],
        expected_key_kind,
        "public key-switch material kind",
    )?;
    match expected_rotation {
        Some(rotation) => {
            if usize_at_path(entry, &["rotation"])? != rotation {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "public rotation key material has the wrong rotation",
                ));
            }
        }
        None if !entry.get("rotation").is_none_or(Value::is_null) => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public relinearization key material must not carry a rotation",
            ));
        }
        None => {}
    }
    let level = usize_at_path(entry, &["level"])?;
    let seed = string_at_path(entry, &["keyStreamSeed"])?;
    let domain = match expected_rotation {
        Some(rotation) => format!("galois-{rotation}"),
        None => "relinearization".to_string(),
    };
    let mut component_b_by_digit = Vec::new();
    for digit in array_at_path(entry, &["digits"])? {
        let digit_index = usize_at_path(digit, &["digitIndex"])?;
        if digit_index != component_b_by_digit.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "public key-switch material digits must be in canonical order",
            ));
        }
        let mut component_b_by_limb = Vec::new();
        for limb in array_at_path(digit, &["limbs"])? {
            let limb_index = usize_at_path(limb, &["limbIndex"])?;
            if limb_index != component_b_by_limb.len() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "public key-switch material limbs must be in canonical order",
                ));
            }
            if unsigned_at_path(limb, &["modulus"])? != DATA_PRIMES[limb_index] {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "public key-switch material limb modulus does not match the selected data basis",
                ));
            }
            let coefficients = coefficient_vector_from_le_hex(
                string_at_path(limb, &["componentZeroBLeHex"])?,
                POLYNOMIAL_DEGREE,
                "public key-switch coefficient vector byte length does not match the selected BGV parameters",
            )?;
            compare_hash_at_path(
                limb,
                &["componentZeroBHash512"],
                &coefficient_vector_hash512(
                    &coefficients,
                    PUBLIC_KEY_SWITCH_COMPONENT_VECTOR_HASH_DOMAIN,
                ),
                "public key-switch material component-zero hash",
            )?;
            component_b_by_limb.push(coefficients);
        }
        component_b_by_digit.push(component_b_by_limb);
    }

    key_switch_key_from_public_component_b(level, &domain, seed, component_b_by_digit)
}
