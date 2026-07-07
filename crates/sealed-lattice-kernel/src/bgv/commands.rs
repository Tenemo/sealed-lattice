use serde_json::{Value, json};

use crate::{
    bgv::{
        base_conversion::convert_plaintext_lifted_basis,
        encoding::{decode_batch_plaintext_polynomial, encode_batch_plaintext_slots},
        parameters::{
            BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE, allowed_operation_registry_value,
            bgv_parameters_hash, bgv_parameters_value,
        },
        serialization::{
            BgvObjectKind, canonical_bytes_hex, ciphertext_root, parse_bgv_object_hex,
            plaintext_root, serialize_bgv_object,
        },
        setup::{
            absorb_evaluation_key_share_component_material_transport_stream_chunk_request,
            absorb_setup_proof_material_transport_stream_chunk_request,
            begin_evaluation_key_share_component_material_transport_stream_request,
            begin_setup_proof_material_transport_stream_request,
            compute_setup_commitment_from_opening_request,
            compute_vss_public_commitment_from_opening_request,
            derive_collective_bgv_setup_public_derivations_from_request,
            describe_collective_bgv_setup_parameters,
            finish_evaluation_key_share_component_material_transport_stream_request,
            finish_setup_proof_material_transport_stream_request,
            generate_passive_setup_package_from_request,
            generate_passive_setup_public_evaluation_key_material_from_request,
            generate_private_vss_share_proof_from_request,
            generate_same_secret_bridge_proof_from_request,
            generate_trustee_evaluation_key_proof_from_request,
            generate_vss_share_linkage_proof_from_request,
            verify_collective_bgv_setup_package_from_request,
            verify_local_trustee_setup_state_from_request,
            verify_passive_setup_package_from_request,
            verify_private_vss_share_envelope_from_request,
        },
        validation::{bgv_operation_rejection, validate_ciphertext_hex, validate_plaintext_hex},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) fn describe_bgv_rns_parameters() -> CanonicalResult<Value> {
    Ok(json!({
        "parameters": bgv_parameters_value(),
        "bgvParametersHash": bgv_parameters_hash()?,
    }))
}

pub(crate) fn describe_bgv_operation_registry() -> CanonicalResult<Value> {
    Ok(json!({
        "registry": allowed_operation_registry_value()?,
        "bgvParametersHash": bgv_parameters_hash()?,
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
            "isValid": true,
            "operation": "validateBgvEvaluatorOperation",
            "acceptedOperation": operation_name,
            "bgvParametersHash": bgv_parameters_hash()?,
        }));
    }

    Ok(bgv_operation_rejection(
        "validateBgvEvaluatorOperation",
        "UncertifiedEvaluatorOperation",
        format!(
            "BGV evaluator operation {operation_name} is not part of the selected BGV-RNS/evaluator operation registry"
        ),
        None,
    ))
}

pub(crate) fn describe_collective_bgv_setup_parameters_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    match request.get("participantCount").and_then(Value::as_u64) {
        Some(participant_count) => {
            crate::bgv::setup::describe_collective_bgv_setup_parameters_for_participant_count(
                participant_count,
            )
        }
        None => describe_collective_bgv_setup_parameters(),
    }
}

pub(crate) fn derive_collective_bgv_setup_public_derivations(
    request: &Value,
) -> CanonicalResult<Value> {
    derive_collective_bgv_setup_public_derivations_from_request(request)
}

pub(crate) fn generate_bgv_passive_setup_from_request(request: &Value) -> CanonicalResult<Value> {
    generate_passive_setup_package_from_request(request)
}

pub(crate) fn verify_bgv_passive_setup_from_request(request: &Value) -> CanonicalResult<Value> {
    verify_passive_setup_package_from_request(request)
}

pub(crate) fn verify_collective_bgv_setup_from_request(request: &Value) -> CanonicalResult<Value> {
    verify_collective_bgv_setup_package_from_request(request)
}

pub(crate) fn verify_private_vss_share_envelope(request: &Value) -> CanonicalResult<Value> {
    verify_private_vss_share_envelope_from_request(request)
}

pub(crate) fn generate_private_vss_share_proof(request: &Value) -> CanonicalResult<Value> {
    generate_private_vss_share_proof_from_request(request)
}

pub(crate) fn generate_trustee_evaluation_key_proof(request: &Value) -> CanonicalResult<Value> {
    generate_trustee_evaluation_key_proof_from_request(request)
}

pub(crate) fn compute_vss_public_commitment_from_opening(
    request: &Value,
) -> CanonicalResult<Value> {
    compute_vss_public_commitment_from_opening_request(request)
}

pub(crate) fn generate_vss_share_linkage_proof(request: &Value) -> CanonicalResult<Value> {
    generate_vss_share_linkage_proof_from_request(request)
}

pub(crate) fn generate_same_secret_bridge_proof(request: &Value) -> CanonicalResult<Value> {
    generate_same_secret_bridge_proof_from_request(request)
}

pub(crate) fn compute_setup_commitment_from_opening(request: &Value) -> CanonicalResult<Value> {
    compute_setup_commitment_from_opening_request(request)
}

pub(crate) fn begin_setup_proof_material_transport_stream(
    request: &Value,
) -> CanonicalResult<Value> {
    begin_setup_proof_material_transport_stream_request(request)
}

pub(crate) fn absorb_setup_proof_material_transport_stream_chunk(
    request: &Value,
) -> CanonicalResult<Value> {
    absorb_setup_proof_material_transport_stream_chunk_request(request)
}

pub(crate) fn finish_setup_proof_material_transport_stream(
    request: &Value,
) -> CanonicalResult<Value> {
    finish_setup_proof_material_transport_stream_request(request)
}

pub(crate) fn begin_evaluation_key_share_component_material_transport_stream(
    request: &Value,
) -> CanonicalResult<Value> {
    begin_evaluation_key_share_component_material_transport_stream_request(request)
}

pub(crate) fn absorb_evaluation_key_share_component_material_transport_stream_chunk(
    request: &Value,
) -> CanonicalResult<Value> {
    absorb_evaluation_key_share_component_material_transport_stream_chunk_request(request)
}

pub(crate) fn finish_evaluation_key_share_component_material_transport_stream(
    request: &Value,
) -> CanonicalResult<Value> {
    finish_evaluation_key_share_component_material_transport_stream_request(request)
}

pub(crate) fn verify_local_trustee_setup_state(request: &Value) -> CanonicalResult<Value> {
    verify_local_trustee_setup_state_from_request(request)
}

pub(crate) fn generate_bgv_evaluation_key_material_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    generate_passive_setup_public_evaluation_key_material_from_request(request)
}

pub(crate) fn encode_bgv_batch_plaintext_from_request(request: &Value) -> CanonicalResult<Value> {
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
        "bgvParametersHash": bgv_parameters_hash()?,
        "basisId": encoded.polynomial.basis_id,
        "level": encoded.polynomial.level,
        "coefficientCount": encoded.polynomial.coefficient_count,
        "suppliedSlotCount": slots.len(),
        "slotCount": POLYNOMIAL_DEGREE,
        "plaintextRoot": plaintext_root,
        "sampledSlots": sample_positions(&encoded.slots),
        "sampledCoefficientsModPlaintext": sample_positions(&encoded.coefficients_mod_plaintext),
        "validation": validation,
    });
    if include_canonical_bytes_hex {
        value["canonicalBytesHex"] = Value::String(canonical_bytes_hex(&canonical_bytes));
    }

    Ok(value)
}

pub(crate) fn validate_bgv_plaintext_from_request(request: &Value) -> CanonicalResult<Value> {
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let expected_plaintext_root = request.get("expectedPlaintextRoot").and_then(Value::as_str);

    validate_plaintext_hex(canonical_bytes_hex, expected_plaintext_root)
}

pub(crate) fn validate_bgv_ciphertext_from_request(request: &Value) -> CanonicalResult<Value> {
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let expected_ciphertext_root = request
        .get("expectedCiphertextRoot")
        .and_then(Value::as_str);

    validate_ciphertext_hex(canonical_bytes_hex, expected_ciphertext_root)
}

pub(crate) fn generate_bgv_ciphertext_convention_fixture_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
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
        "bgvParametersHash": bgv_parameters_hash()?,
        "ciphertextRoot": root,
        "componentCount": 2,
        "validation": validation,
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
        "sourceBasisId": encoded.polynomial.basis_id,
        "convertedBasisId": converted.basis_id,
        "convertedModulusCount": converted.moduli.len(),
        "sampledConvertedResidues": sample_positions(&converted.residues_by_modulus[1]),
    }))
}

pub(crate) fn analyze_bgv_canonical_object_from_request(request: &Value) -> CanonicalResult<Value> {
    let canonical_bytes_hex = read_string_field(request, "canonicalBytesHex")?;
    let object = parse_bgv_object_hex(canonical_bytes_hex)?;

    Ok(json!({
        "objectKind": object.object_kind.as_str(),
        "componentCount": object.components.len(),
        "bgvParametersHash": object.components[0].bgv_parameters_hash,
        "basisId": object.components[0].basis_id,
        "level": object.components[0].level,
        "coefficientCount": object.components[0].coefficient_count,
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
        describe_bgv_rns_parameters, encode_bgv_batch_plaintext_from_request,
        generate_bgv_base_conversion_fixture_from_request,
        generate_bgv_ciphertext_convention_fixture_from_request,
        validate_bgv_plaintext_from_request,
    };

    #[test]
    fn commands_describe_parameters_and_encode_plaintext() {
        let parameters = describe_bgv_rns_parameters().expect("parameters description");
        let layout_binding = parameters["batchLayoutBinding"].clone();
        assert_eq!(parameters["parameters"]["polynomialDegree"], 32_768);
        assert_eq!(parameters["parameters"]["plaintextModulus"], 65_537);
        assert_eq!(
            parameters["bgvParametersHash"],
            crate::bgv::parameters::bgv_parameters_hash().expect("BGV parameters hash")
        );

        let encoded = encode_bgv_batch_plaintext_from_request(&serde_json::json!({
            "slots": [1, 2, 65_536],
            "level": 0,
            "layoutBinding": layout_binding,
            "includeCanonicalBytesHex": true
        }))
        .expect("encode command");
        assert_eq!(encoded["validation"]["isValid"], true);
        assert!(
            encode_bgv_batch_plaintext_from_request(&serde_json::json!({
                "slots": [1, 2, 65_537],
                "level": 0
            }))
            .is_err()
        );
        assert!(
            encode_bgv_batch_plaintext_from_request(&serde_json::json!({
                "slots": [1, 2, 3],
                "level": crate::bgv::parameters::DATA_PRIMES.len()
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
    fn native_commands_produce_stable_bgv_rns_canonical_roots() {
        let parameters = describe_bgv_rns_parameters().expect("parameters description");
        let layout_binding = parameters["batchLayoutBinding"].clone();
        let encoded = encode_bgv_batch_plaintext_from_request(&serde_json::json!({
            "slots": [0, 1, 65_536, 17, 99],
            "level": 0,
            "layoutBinding": layout_binding
        }))
        .expect("encoded fixture");

        assert_eq!(
            encoded["plaintextRoot"],
            "ad3aee0286a714f21117ade0043bd72ca51fb0108afe53e40b111655081bfe26d0fbe1838c3fca581f50747439efaf402dc090ee309d7a5494c7146e2324f63b"
        );

        let ciphertext =
            generate_bgv_ciphertext_convention_fixture_from_request(&serde_json::json!({
                "leftSlots": [1, 2, 3],
                "rightSlots": [4, 5, 6]
            }))
            .expect("ciphertext fixture");
        assert_eq!(
            ciphertext["ciphertextRoot"],
            "4acbb7e4c92e52dbce48bd01cae06fa2e0950ff9ceb0156d8f1945bfa3c753c547c39b8b2b473d5adca0b19936104382d6e1de348963e708ea1119cfa4cddfb3"
        );

        let base_conversion =
            generate_bgv_base_conversion_fixture_from_request(&serde_json::json!({
                "slots": [7, 8, 9, 65_536]
            }))
            .expect("base conversion fixture");
        assert_eq!(
            base_conversion["sourcePlaintextRoot"],
            "63af2d4084b0f4512ec84e58b1eb003cba68a702569b4d738bd3331264e8511747c00a66e331b1f7d09093c6a44246b26c748f1a4b3d5d7436b84af47fe70a53"
        );
        assert_eq!(
            base_conversion["convertedPlaintextRoot"],
            "11cb1d08c18df5c3b47d8f746af569401323c2e3243b65267b9b79afdc24b7ac227b015b2dbc034ac7f9cf8a3dbc61291e3facdad219f1d9e6478d4a72cd6ab9"
        );
    }

    #[test]
    fn commands_produce_convention_and_base_conversion_fixtures_without_claiming_encryption() {
        generate_bgv_ciphertext_convention_fixture_from_request(&serde_json::json!({
            "leftSlots": [1, 2, 3],
            "rightSlots": [4, 5, 6]
        }))
        .expect("ciphertext fixture");

        let base_conversion =
            generate_bgv_base_conversion_fixture_from_request(&serde_json::json!({
                "slots": [7, 8, 9]
            }))
            .expect("base conversion fixture");
        assert_eq!(base_conversion["convertedModulusCount"], 2);
    }
}
