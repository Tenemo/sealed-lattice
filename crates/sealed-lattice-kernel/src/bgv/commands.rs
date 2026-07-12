use serde_json::{Value, json};

use crate::{
    bgv::{
        encoding::{decode_batch_plaintext_polynomial, encode_batch_plaintext_slots},
        parameters::{
            DATA_PRIMES, POLYNOMIAL_DEGREE, allowed_operation_registry_value, bgv_parameters_hash,
            bgv_parameters_value,
        },
        serialization::{
            BgvObjectKind, canonical_bytes_hex, parse_bgv_object_hex, plaintext_root,
            serialize_bgv_object,
        },
        setup::{
            compute_setup_commitment_from_opening_request,
            compute_vss_committed_material_commitment_request,
            derive_collective_bgv_setup_public_derivations_from_request,
            describe_collective_bgv_setup_parameters,
            describe_trustee_evaluation_key_statement_from_request,
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

pub(crate) fn describe_trustee_evaluation_key_statement(request: &Value) -> CanonicalResult<Value> {
    describe_trustee_evaluation_key_statement_from_request(request)
}

pub(crate) fn compute_vss_committed_material_commitment(request: &Value) -> CanonicalResult<Value> {
    compute_vss_committed_material_commitment_request(request)
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
    let slots = request
        .get("slots")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(CanonicalErrorCode::InvalidFixture, "slots must be an array")
        })?;
    slots
        .iter()
        .map(|slot| {
            slot.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "slots entries must be non-negative integers",
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
        validate_bgv_plaintext_from_request,
    };
    use crate::bgv::{
        base_conversion::convert_plaintext_lifted_basis,
        encoding::encode_batch_plaintext_slots,
        parameters::BgvBasisKind,
        serialization::{BgvObjectKind, ciphertext_root, plaintext_root, serialize_bgv_object},
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
        .expect("encoded plaintext");

        assert_eq!(
            encoded["plaintextRoot"],
            "334c485a1f928757939c69db3deee117f791d216aea5c277127723d77e8e2f2d7e20d0c691b999cd988348062a48e5237654af745a0c7c8bbc93a04870a4d173"
        );

        let left = encode_batch_plaintext_slots(&[1, 2, 3], 0).expect("left component");
        let right = encode_batch_plaintext_slots(&[4, 5, 6], 0).expect("right component");
        let ciphertext_bytes = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[left.polynomial, right.polynomial],
        )
        .expect("canonical ciphertext bytes");
        assert_eq!(
            ciphertext_root(&ciphertext_bytes),
            "c67ab9102937ceb90a9fa91c4ca8e78d34bd012039276199884681385ecd80475ca2ccf98d9a1b4136885738d65b48664d0dd3e30c468d44c3fddbcd35e024df"
        );

        let source = encode_batch_plaintext_slots(&[7, 8, 9, 65_536], 0).expect("source plaintext");
        let converted =
            convert_plaintext_lifted_basis(&source.polynomial, BgvBasisKind::Extended, 1)
                .expect("base conversion");
        let source_bytes = serialize_bgv_object(
            BgvObjectKind::Plaintext,
            std::slice::from_ref(&source.polynomial),
        )
        .expect("source canonical bytes");
        let converted_bytes =
            serialize_bgv_object(BgvObjectKind::Plaintext, std::slice::from_ref(&converted))
                .expect("converted canonical bytes");
        assert_eq!(
            plaintext_root(&source_bytes),
            "687b0f77e2f9b356db52f5153ea3c4548a3fdeb49d307446ca256b5154a141f619402cfaf80146992eaa8c32b981c4f13ace18825b9a1d5d06eb8268d041eaf5"
        );
        assert_eq!(
            plaintext_root(&converted_bytes),
            "e1501c3e6558f6fd7576ab1f9d98cdd000b768c5c5e966bda473e8b8d6d525d56c42ec97a20721480c8c4bf4cda91e842e70ef6d6e6e853ec4c234b6b1e994e5"
        );
        assert_eq!(converted.moduli.len(), 2);
        assert_ne!(
            plaintext_root(&source_bytes),
            plaintext_root(&converted_bytes)
        );
    }
}
