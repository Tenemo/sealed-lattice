use num_bigint::BigInt;
use serde_json::{Value, json};

use crate::{
    bgv::{
        base_conversion::convert_plaintext_lifted_basis,
        encoding::{decode_batch_plaintext_polynomial, encode_batch_plaintext_slots},
        profile::{
            BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE, aggregate_input_encoding_profile_hash,
            allowed_operation_registry_hash, allowed_operation_registry_value,
            backend_profile_hash, ballot_score_encoding_profile_hash,
            ballot_share_layout_profile_hash, batch_encoder_hash, batch_layout_binding_hash,
            batch_layout_binding_value, canonical_ciphertext_convention_hash,
            encoded_aggregate_layout_hash, layout_hash, profile_hash,
            security_estimator_input_hash, selected_profile_value,
            top_k_evaluator_input_layout_hash,
        },
        serialization::{
            BgvObjectKind, canonical_bytes_hash, canonical_bytes_hex, ciphertext_root,
            parse_bgv_object_hex, plaintext_root, serialize_bgv_object,
        },
        setup::{
            describe_passive_setup_object_model, generate_passive_setup_package_from_request,
            verify_passive_setup_package_from_request,
        },
        validation::{
            bgv_profile_rejection, reject_reference_oracle_artifact,
            reject_unexpected_bgv_request_fields, validate_ciphertext_hex, validate_plaintext_hex,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) use crate::bgv::setup::M9BridgeCiphertextRelationTrace;

pub(crate) fn describe_bgv_rns_profile() -> CanonicalResult<Value> {
    Ok(json!({
        "profile": selected_profile_value(),
        "profileHash": profile_hash()?,
        "backendProfileHash": backend_profile_hash()?,
        "batchEncoderHash": batch_encoder_hash()?,
        "encryptedAggregateInputLayoutHash": layout_hash()?,
        "batchLayoutBinding": batch_layout_binding_value()?,
        "batchLayoutBindingHash": batch_layout_binding_hash()?,
        "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
        "ballotShareLayoutProfileHash": ballot_share_layout_profile_hash()?,
        "aggregateInputEncodingProfileHash": aggregate_input_encoding_profile_hash()?,
        "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
        "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
        "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "securityEstimatorInputHash": security_estimator_input_hash()?,
    }))
}

pub(crate) fn describe_bgv_operation_registry() -> CanonicalResult<Value> {
    Ok(json!({
        "registry": allowed_operation_registry_value()?,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
    }))
}

pub(crate) fn validate_bgv_evaluator_operation_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let operation_name = read_string_field(request, "operation")?;

    let registry = allowed_operation_registry_value()?;
    let allowed_operations = registry
        .get("allowedOperations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "BGV operation registry is missing allowed operations",
            )
        })?;
    if allowed_operations
        .iter()
        .any(|operation| operation.as_str() == Some(operation_name))
    {
        return Ok(json!({
            "ok": true,
            "operation": "validateBgvEvaluatorOperation",
            "acceptedOperation": operation_name,
            "allowedEvaluatorOpsHash": crate::bgv::profile::allowed_operation_registry_hash()?,
            "statusLabels": [
                "BGVEvaluatorOperationAllowed"
            ],
        }));
    }

    Ok(bgv_profile_rejection(
        "validateBgvEvaluatorOperation",
        if registry
            .get("forbiddenOperations")
            .and_then(Value::as_array)
            .is_some_and(|forbidden_operations| {
                forbidden_operations
                    .iter()
                    .any(|operation| operation.as_str() == Some(operation_name))
            })
        {
            "ForbiddenEvaluatorOperation"
        } else {
            "UncertifiedEvaluatorOperation"
        },
        format!(
            "BGV evaluator operation {operation_name} is not part of the selected M7/M10 operation registry"
        ),
        None,
    ))
}

pub(crate) fn describe_bgv_passive_setup_object_model() -> CanonicalResult<Value> {
    describe_passive_setup_object_model()
}

pub(crate) fn generate_bgv_passive_setup_from_request(request: &Value) -> CanonicalResult<Value> {
    generate_passive_setup_package_from_request(request)
}

pub(crate) fn verify_bgv_passive_setup_from_request(request: &Value) -> CanonicalResult<Value> {
    verify_passive_setup_package_from_request(request)
}

pub(crate) fn encode_bgv_batch_plaintext_from_request(request: &Value) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "includeCanonicalBytesHex",
            "layoutBinding",
            "level",
            "slots",
        ],
        "encodeBgvBatchPlaintext",
    )?;
    validate_batch_layout_binding(request)?;
    let slots = read_slots(request)?;
    let level = request
        .get("level")
        .and_then(Value::as_u64)
        .map(usize::try_from)
        .transpose()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "level does not fit usize",
            )
        })?
        .unwrap_or(DATA_PRIMES.len() - 1);
    let include_canonical_bytes_hex = request
        .get("includeCanonicalBytesHex")
        .and_then(Value::as_bool)
        == Some(true);
    let encoded = encode_batch_plaintext_slots(&slots, level)?;
    let canonical_bytes = serialize_bgv_object(
        BgvObjectKind::Plaintext,
        std::slice::from_ref(&encoded.polynomial),
    )?;
    let decoded_slots = decode_batch_plaintext_polynomial(&encoded.polynomial)?;
    if decoded_slots != encoded.slots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::FixtureMismatch,
            "BGV batch encoder failed its internal decode round trip",
        ));
    }
    let plaintext_root = plaintext_root(&canonical_bytes);
    let validation = validate_plaintext_hex(
        &canonical_bytes_hex(&canonical_bytes),
        Some(&plaintext_root),
    )?;
    let mut value = json!({
        "profileHash": profile_hash()?,
        "batchLayoutBindingHash": batch_layout_binding_hash()?,
        "basisId": encoded.polynomial.basis_id,
        "level": encoded.polynomial.level,
        "coefficientCount": encoded.polynomial.coefficient_count,
        "suppliedSlotCount": slots.len(),
        "slotCount": POLYNOMIAL_DEGREE,
        "plaintextRoot": plaintext_root,
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
        "sampledSlots": sample_positions(&encoded.slots),
        "sampledCoefficientsModPlaintext": sample_positions(&encoded.coefficients_mod_plaintext),
        "validation": validation,
        "statusLabels": [
            "BGVBatchEncoded",
            "EncryptedAggregateInputLayoutBound",
            "NativeDecodeRoundTripMatched",
            "PlaintextRootBound"
        ],
    });
    if include_canonical_bytes_hex {
        value["canonicalBytesHex"] = Value::String(canonical_bytes_hex(&canonical_bytes));
    }

    Ok(value)
}

fn validate_batch_layout_binding(request: &Value) -> CanonicalResult<()> {
    let supplied_binding = request.get("layoutBinding").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV batch encoder requires explicit EncryptedAggregateInput layout binding",
        )
    })?;
    let expected_binding = batch_layout_binding_value()?;
    if supplied_binding != &expected_binding {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "BGV batch encoder layout binding does not match the selected EncryptedAggregateInput layout",
        ));
    }

    Ok(())
}

pub(crate) fn validate_bgv_plaintext_from_request(request: &Value) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &["canonicalBytesHex", "expectedPlaintextRoot"],
        "validateBgvPlaintextObject",
    )?;
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let expected_plaintext_root = request.get("expectedPlaintextRoot").and_then(Value::as_str);

    validate_plaintext_hex(canonical_bytes_hex, expected_plaintext_root)
}

pub(crate) fn validate_bgv_ciphertext_from_request(request: &Value) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &["canonicalBytesHex", "expectedCiphertextRoot"],
        "validateBgvCiphertextObject",
    )?;
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let expected_ciphertext_root = request
        .get("expectedCiphertextRoot")
        .and_then(Value::as_str);

    validate_ciphertext_hex(canonical_bytes_hex, expected_ciphertext_root)
}

pub(crate) fn generate_bgv_ciphertext_convention_fixture_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &["includeCanonicalBytesHex", "leftSlots", "rightSlots"],
        "generateBgvCiphertextConventionFixture",
    )?;
    let left_slots = read_named_slots(request, "leftSlots")?;
    let right_slots = read_named_slots(request, "rightSlots")?;
    let left = encode_batch_plaintext_slots(&left_slots, 0)?;
    let right = encode_batch_plaintext_slots(&right_slots, 0)?;
    let canonical_bytes = serialize_bgv_object(
        BgvObjectKind::Ciphertext,
        &[left.polynomial.clone(), right.polynomial.clone()],
    )?;
    let root = ciphertext_root(&canonical_bytes);
    let validation = validate_ciphertext_hex(&canonical_bytes_hex(&canonical_bytes), Some(&root))?;
    let mut value = json!({
        "profileHash": profile_hash()?,
        "ciphertextRoot": root,
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
        "componentCount": 2,
        "validation": validation,
        "statusLabels": [
            "CiphertextConventionFixture",
            "NotEncryptionEvidence",
            "CiphertextRootBound"
        ],
    });
    if request
        .get("includeCanonicalBytesHex")
        .and_then(Value::as_bool)
        == Some(true)
    {
        value["canonicalBytesHex"] = Value::String(canonical_bytes_hex(&canonical_bytes));
    }

    Ok(value)
}

pub(crate) fn generate_bgv_base_conversion_fixture_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(request, &["slots"], "generateBgvBaseConversionFixture")?;
    let slots = read_slots(request)?;
    let encoded = encode_batch_plaintext_slots(&slots, 0)?;
    let converted = convert_plaintext_lifted_basis(&encoded.polynomial, BgvBasisKind::Extended, 1)?;
    let source_bytes = serialize_bgv_object(
        BgvObjectKind::Plaintext,
        std::slice::from_ref(&encoded.polynomial),
    )?;
    let converted_bytes =
        serialize_bgv_object(BgvObjectKind::Plaintext, std::slice::from_ref(&converted))?;

    Ok(json!({
        "sourcePlaintextRoot": plaintext_root(&source_bytes),
        "convertedPlaintextRoot": plaintext_root(&converted_bytes),
        "sourceCanonicalBytesHash512": canonical_bytes_hash(&source_bytes),
        "convertedCanonicalBytesHash512": canonical_bytes_hash(&converted_bytes),
        "sourceBasisId": encoded.polynomial.basis_id,
        "convertedBasisId": converted.basis_id,
        "convertedModulusCount": converted.moduli.len(),
        "sampledConvertedResidues": sample_positions(&converted.residues_by_modulus[1]),
        "statusLabels": [
            "PlaintextLiftedBaseConversion",
            "GenericKeySwitchSurfaceNotExported"
        ],
    }))
}

pub(crate) fn reject_bgv_reference_oracle_artifact_from_request(request: &Value) -> Value {
    let fallback_artifact = json!({ "artifactKind": "unspecified" });
    let artifact = request.get("artifact").unwrap_or(&fallback_artifact);

    reject_reference_oracle_artifact(artifact)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_m9_bridge_ciphertext_relation_trace_from_slots(
    setup_package: &Value,
    contributor_identity: &str,
    aggregate_derivation_component_hash: &str,
    aggregate_derivation_statement_hash: &str,
    post_voting_closed_context_hash: &str,
    reduced_aggregate_slots: &[u64],
    prover_randomness_hex: &str,
    include_canonical_bytes_hex: bool,
) -> CanonicalResult<M9BridgeCiphertextRelationTrace> {
    crate::bgv::setup::generate_m9_bridge_ciphertext_relation_trace_from_slots(
        setup_package,
        contributor_identity,
        aggregate_derivation_component_hash,
        aggregate_derivation_statement_hash,
        post_voting_closed_context_hash,
        reduced_aggregate_slots,
        prover_randomness_hex,
        include_canonical_bytes_hex,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_m9_bridge_ciphertext_public_bindings(
    setup_package: &Value,
    aggregate_derivation_component_hash: &str,
    aggregate_derivation_statement_hash: &str,
    post_voting_closed_context_hash: &str,
    bridge_encryption: &Value,
) -> CanonicalResult<()> {
    crate::bgv::setup::verify_m9_bridge_ciphertext_public_bindings(
        setup_package,
        aggregate_derivation_component_hash,
        aggregate_derivation_statement_hash,
        post_voting_closed_context_hash,
        bridge_encryption,
    )
}

pub(crate) fn m9_bridge_batch_encoding_commitment_hash_from_responses(
    reduced_slot_response: &[BigInt],
    plaintext_coefficient_response: &[BigInt],
) -> CanonicalResult<String> {
    crate::bgv::setup::m9_bridge_batch_encoding_commitment_hash_from_responses(
        reduced_slot_response,
        plaintext_coefficient_response,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn m9_bridge_ciphertext_commitment_hash_from_responses(
    setup_package: &Value,
    contributor_identity: &str,
    aggregate_derivation_statement_hash: &str,
    bridge_encryption: &Value,
    challenge_scalar: u64,
    plaintext_coefficient_response: &[BigInt],
    randomizer_response: &[BigInt],
    perturbation_zero_response: &[BigInt],
    perturbation_one_response: &[BigInt],
) -> CanonicalResult<String> {
    crate::bgv::setup::m9_bridge_ciphertext_commitment_hash_from_responses(
        setup_package,
        contributor_identity,
        aggregate_derivation_statement_hash,
        bridge_encryption,
        challenge_scalar,
        plaintext_coefficient_response,
        randomizer_response,
        perturbation_zero_response,
        perturbation_one_response,
    )
}

pub(crate) fn analyze_bgv_canonical_object_from_request(request: &Value) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &["canonicalBytesHex"],
        "analyzeBgvCanonicalObject",
    )?;
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let object = parse_bgv_object_hex(canonical_bytes_hex)?;

    Ok(json!({
        "objectKind": object.object_kind.as_str(),
        "componentCount": object.components.len(),
        "profileHash": object.components[0].profile_hash,
        "basisId": object.components[0].basis_id,
        "level": object.components[0].level,
        "coefficientCount": object.components[0].coefficient_count,
        "layoutHash": object.components[0].layout_hash,
        "statusLabels": [
            "BGVCanonicalObjectParsed",
            "CoefficientDomainCanonical"
        ],
    }))
}

fn read_slots(request: &Value) -> CanonicalResult<Vec<u64>> {
    read_named_slots(request, "slots")
}

fn read_named_slots(request: &Value, field_name: &str) -> CanonicalResult<Vec<u64>> {
    let slots = request
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an array"),
            )
        })?;
    slots
        .iter()
        .map(|slot| {
            slot.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name} entries must be non-negative integers"),
                )
            })
        })
        .collect()
}

fn read_string_field<'a>(request: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    request
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })
}

fn sample_positions(values: &[u64]) -> Vec<Value> {
    let mut positions = vec![
        0_usize,
        1,
        2,
        17,
        values.len() / 2,
        values.len().saturating_sub(1),
    ];
    positions.sort_unstable();
    positions.dedup();
    positions
        .into_iter()
        .filter_map(|position| {
            values.get(position).map(|value| {
                json!({
                    "position": position,
                    "value": value,
                })
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        describe_bgv_rns_profile, encode_bgv_batch_plaintext_from_request,
        generate_bgv_base_conversion_fixture_from_request,
        generate_bgv_ciphertext_convention_fixture_from_request,
        validate_bgv_plaintext_from_request,
    };

    #[test]
    fn commands_describe_profile_and_encode_plaintext() {
        let profile = describe_bgv_rns_profile().expect("profile description");
        let layout_binding = profile["batchLayoutBinding"].clone();
        assert_eq!(profile["profile"]["polynomialDegree"], 32_768);
        assert_eq!(profile["profile"]["plaintextModulus"], 65_537);
        assert_eq!(
            profile["allowedEvaluatorOpsHash"],
            crate::bgv::profile::allowed_operation_registry_hash()
                .expect("operation registry hash")
        );

        let encoded = encode_bgv_batch_plaintext_from_request(&serde_json::json!({
            "slots": [1, 2, 65_536],
            "level": 0,
            "layoutBinding": layout_binding,
            "includeCanonicalBytesHex": true
        }))
        .expect("encode command");
        assert_eq!(encoded["validation"]["ok"], true);
        assert!(
            encoded["statusLabels"]
                .as_array()
                .expect("labels")
                .contains(&serde_json::json!("EncryptedAggregateInputLayoutBound"))
        );
        assert!(
            encode_bgv_batch_plaintext_from_request(&serde_json::json!({
                "slots": [1, 2, 3],
                "level": 0
            }))
            .is_err()
        );
        let validated = validate_bgv_plaintext_from_request(&serde_json::json!({
            "canonicalBytesHex": encoded["canonicalBytesHex"].as_str().expect("hex"),
            "expectedPlaintextRoot": encoded["plaintextRoot"].as_str().expect("root")
        }))
        .expect("validate command");
        assert_eq!(validated["plaintextRoot"], encoded["plaintextRoot"]);
    }

    #[test]
    fn native_commands_produce_stable_m7_canonical_roots() {
        let profile = describe_bgv_rns_profile().expect("profile description");
        let layout_binding = profile["batchLayoutBinding"].clone();
        let encoded = encode_bgv_batch_plaintext_from_request(&serde_json::json!({
            "slots": [0, 1, 65_536, 17, 99],
            "level": 0,
            "layoutBinding": layout_binding,
            "includeCanonicalBytesHex": true
        }))
        .expect("encoded fixture");

        assert_eq!(
            encoded["plaintextRoot"],
            "92cf108ea1bf78bf8b4acff606df99b2b5d342fe8caac81f1dbc3eaa166b31bf61b2453d57630109422b14e9cbdf8cf327ce56793cb676a10888c5f6c1c12edd"
        );
        assert_eq!(
            encoded["canonicalBytesHash512"],
            "d77e7936e25849fa95ac455dd4b1e2502b9f502491d0657c41035b0c91aa625762f77bdd6e24c236417eeab50d7afdeea376cabf1d737df587de3932b9fc641e"
        );
        assert_eq!(encoded["canonicalByteLength"], 90_441);

        let ciphertext =
            generate_bgv_ciphertext_convention_fixture_from_request(&serde_json::json!({
                "leftSlots": [1, 2, 3],
                "rightSlots": [4, 5, 6],
                "includeCanonicalBytesHex": true
            }))
            .expect("ciphertext fixture");
        assert_eq!(
            ciphertext["ciphertextRoot"],
            "656a13bf2071f4def2cc2de14c41bea2c866c5c78eeedd64074a85c43caf5011eca8d78241f9e0705070d66bc9fb6dceb55cabf5f5fc2dcfa9c7e235284cc87f"
        );
        assert_eq!(
            ciphertext["canonicalBytesHash512"],
            "842135a9284e37b74a4ad6ab7c350449d1126efa3d15a68b1004d8b481adb40e790bd6b0cbc266b6d138ce297d6e9b6c6333900603ab3d5775a76882729159ed"
        );
        assert_eq!(ciphertext["canonicalByteLength"], 180_781);

        let base_conversion =
            generate_bgv_base_conversion_fixture_from_request(&serde_json::json!({
                "slots": [7, 8, 9, 65_536]
            }))
            .expect("base conversion fixture");
        assert_eq!(
            base_conversion["sourcePlaintextRoot"],
            "170b5c709ce3230aa0f731a4973ccb2fb3e1620fc9c8b60c57406b2443c51c69dcc3e97f2134de9af53f1f2735ed618033b89d4cdcadd7d641ad00848c35ba06"
        );
        assert_eq!(
            base_conversion["convertedPlaintextRoot"],
            "f3c721f6e0cf872460caf3b4d52bb7aaabea964d0f1977639f17ae43fa4812a657fbe82f51216c1470a56b9cbf3823ca9dd787f8a10199260b09ee6600118c80"
        );
    }

    #[test]
    fn commands_produce_convention_and_base_conversion_fixtures_without_claiming_encryption() {
        let ciphertext =
            generate_bgv_ciphertext_convention_fixture_from_request(&serde_json::json!({
                "leftSlots": [1, 2, 3],
                "rightSlots": [4, 5, 6]
            }))
            .expect("ciphertext fixture");
        assert!(
            ciphertext["statusLabels"]
                .as_array()
                .expect("labels")
                .contains(&serde_json::json!("NotEncryptionEvidence"))
        );

        let base_conversion =
            generate_bgv_base_conversion_fixture_from_request(&serde_json::json!({
                "slots": [7, 8, 9]
            }))
            .expect("base conversion fixture");
        assert_eq!(base_conversion["convertedModulusCount"], 2);
    }
}
