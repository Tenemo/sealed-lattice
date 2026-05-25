use serde_json::{Value, json};

use crate::{
    bgv::{
        base_conversion::convert_plaintext_lifted_basis,
        encoding::{decode_batch_plaintext_polynomial, encode_batch_plaintext_slots},
        profile::{
            BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE, allowed_operation_registry_value,
            batch_layout_binding_digest, batch_layout_binding_value, profile_digest,
        },
        reports::{
            backend_parameter_certificate_report, describe_profile_report,
            operation_registry_report,
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
            bgv_profile_rejection, bgv_profile_rejection_from_error,
            reject_if_oracle_boundary_fields_present, reject_reference_oracle_artifact,
            validate_ciphertext_hex, validate_plaintext_hex,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) fn describe_bgv_rns_profile() -> CanonicalResult<Value> {
    describe_profile_report()
}

pub(crate) fn describe_bgv_operation_registry() -> CanonicalResult<Value> {
    operation_registry_report()
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
            "allowedEvaluatorOpsDigest": crate::bgv::profile::allowed_operation_registry_digest()?,
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

pub(crate) fn generate_bgv_backend_report() -> CanonicalResult<Value> {
    backend_parameter_certificate_report()
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
    reject_if_oracle_boundary_fields_present(request)?;
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
        "profileDigest": profile_digest()?,
        "batchLayoutBindingDigest": batch_layout_binding_digest()?,
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
    reject_if_oracle_boundary_fields_present(request)?;
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let expected_plaintext_root = request.get("expectedPlaintextRoot").and_then(Value::as_str);

    validate_plaintext_hex(canonical_bytes_hex, expected_plaintext_root)
}

pub(crate) fn validate_bgv_ciphertext_from_request(request: &Value) -> CanonicalResult<Value> {
    reject_if_oracle_boundary_fields_present(request)?;
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let expected_ciphertext_root = request
        .get("expectedCiphertextRoot")
        .and_then(Value::as_str);

    validate_ciphertext_hex(canonical_bytes_hex, expected_ciphertext_root)
}

pub(crate) fn generate_bgv_ciphertext_convention_fixture_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_if_oracle_boundary_fields_present(request)?;
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
        "profileDigest": profile_digest()?,
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
    reject_if_oracle_boundary_fields_present(request)?;
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

pub(crate) fn analyze_bgv_canonical_object_from_request(request: &Value) -> CanonicalResult<Value> {
    reject_if_oracle_boundary_fields_present(request)?;
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let object = parse_bgv_object_hex(canonical_bytes_hex)?;

    Ok(json!({
        "objectKind": object.object_kind.as_str(),
        "componentCount": object.components.len(),
        "profileDigest": object.components[0].profile_digest,
        "basisId": object.components[0].basis_id,
        "level": object.components[0].level,
        "coefficientCount": object.components[0].coefficient_count,
        "layoutDigest": object.components[0].layout_digest,
        "statusLabels": [
            "BGVCanonicalObjectParsed",
            "CoefficientDomainCanonical"
        ],
    }))
}

pub(crate) fn bgv_input_result(operation: &str, result: CanonicalResult<Value>) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => bgv_profile_rejection_from_error(operation, &error),
    }
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
    fn commands_report_profile_and_encode_plaintext() {
        let profile = describe_bgv_rns_profile().expect("profile report");
        let layout_binding = profile["batchLayoutBinding"].clone();
        assert_eq!(profile["profile"]["polynomialDegree"], 32_768);
        assert_eq!(profile["profile"]["plaintextModulus"], 65_537);
        assert!(
            profile["statusLabels"]
                .as_array()
                .expect("labels")
                .contains(&serde_json::json!("M7ImplementationEvidence"))
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
    fn native_commands_emit_stable_m7_canonical_roots() {
        let profile = describe_bgv_rns_profile().expect("profile report");
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
            "59a29e210357f4e860c4c7b44b541956fc2d2ca425eefcb344dbd303420ffa44419674197bf746a0ca4dee937832b925a34ac008194c411c96ad9c6f94285c75"
        );
        assert_eq!(
            encoded["canonicalBytesHash512"],
            "73a193fc97dad594fe063c04e1b0184d57901441ac520e8355f0e176378c1e1877bc86be1ebf9d873c7007551024cdb08b4af32935e7b56993e233c5a1771b70"
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
            "a5096b8c8f0d14bea7895d29254fb0aa1f50fa81bd8345cafdeb88ec36389ef01933478448e81f3ec0ce39bd07f69cfdc4f0022e223d769a6ab43160f5224622"
        );
        assert_eq!(
            ciphertext["canonicalBytesHash512"],
            "f961235b3d1c61e3a4fa70eecb752f940715e7d768a8b7cca0dc8d90649f9b0c813c543f94fa7768a4a3380e57e11397508797d78728c215cb6552aa913c264e"
        );
        assert_eq!(ciphertext["canonicalByteLength"], 180_781);

        let base_conversion =
            generate_bgv_base_conversion_fixture_from_request(&serde_json::json!({
                "slots": [7, 8, 9, 65_536]
            }))
            .expect("base conversion fixture");
        assert_eq!(
            base_conversion["sourcePlaintextRoot"],
            "2cd073e151a0f86fc2c7b504edb6c2ac39c97cd6a143da4bbb83df400cd25b8d9215c59dc1de6e7d28bf72c80ed5faa9ebe97cff538d07ab048780f1ee0fec7f"
        );
        assert_eq!(
            base_conversion["convertedPlaintextRoot"],
            "9eebccb784a8508da0d21089c3ed0e46c476bbee278785e693dcc0cc3e5e1efa51bb6442bc3da9f533947380bcfd16d701d04b3acc7f1e09fd4bdf77745c62a9"
        );
    }

    #[test]
    fn commands_emit_convention_and_base_conversion_fixtures_without_claiming_encryption() {
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
