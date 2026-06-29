use serde_json::{Value, json};

use crate::{
    bgv::{
        base_conversion::convert_plaintext_lifted_basis,
        encoding::{decode_batch_plaintext_polynomial, encode_batch_plaintext_slots},
        profile::{
            BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE, allowed_operation_registry_hash,
            allowed_operation_registry_value, backend_profile_hash,
            ballot_score_encoding_profile_hash, batch_encoder_hash, batch_layout_binding_hash,
            batch_layout_binding_value, canonical_ciphertext_convention_hash,
            direct_aggregate_layout_hash, direct_comparison_profile_hash,
            encrypted_ballot_aggregate_layout_hash, encrypted_ballot_aggregate_profile_hash,
            encrypted_ballot_layout_hash, profile_hash, security_estimator_input_hash,
            selected_profile_value,
        },
        serialization::{
            BgvObjectKind, canonical_bytes_hash, canonical_bytes_hex, ciphertext_root,
            parse_bgv_object_hex, plaintext_root, serialize_bgv_object,
        },
        setup::{
            abort_threshold_share_commitment_transport_derivation_stream_request,
            absorb_setup_proof_material_transport_stream_chunk_request,
            absorb_threshold_share_commitment_transport_derivation_stream_chunk_request,
            begin_setup_proof_material_transport_stream_request,
            begin_threshold_share_commitment_transport_derivation_stream_request,
            compute_compact_vss_commitment_from_opening_request,
            compute_setup_commitment_from_opening_request,
            decode_compact_vss_commitment_body_request,
            derive_collective_bgv_setup_public_derivations_from_request,
            derive_threshold_share_commitments_from_request,
            derive_threshold_share_commitments_from_transport_request,
            describe_collective_bgv_setup_profile, describe_passive_setup_object_model,
            encode_compact_vss_commitment_body_request,
            finish_setup_proof_material_transport_stream_request,
            finish_threshold_share_commitment_transport_derivation_stream_request,
            generate_compact_same_secret_bridge_proof_from_request,
            generate_compact_vss_share_linkage_proof_from_request,
            generate_passive_setup_package_from_request,
            generate_passive_setup_public_evaluation_key_material_from_request,
            generate_private_vss_share_proof_from_request,
            generate_trustee_evaluation_key_proof_from_request,
            release_verified_transported_vss_material_request,
            verify_collective_bgv_setup_package_from_request,
            verify_compact_same_secret_bridge_proof_from_request,
            verify_compact_vss_aggregate_threshold_commitment_set_request,
            verify_compact_vss_coefficient_commitment_set_request,
            verify_compact_vss_commitment_opening_request,
            verify_compact_vss_recipient_share_commitment_set_request,
            verify_compact_vss_same_secret_bridge_proof_material_set_request,
            verify_compact_vss_same_secret_bridge_statement_set_request,
            verify_compact_vss_share_linkage_proof_from_request,
            verify_compact_vss_share_linkage_statement_request,
            verify_local_trustee_setup_state_from_request,
            verify_passive_setup_package_from_request,
            verify_private_vss_share_envelope_from_request,
            verify_trustee_evaluation_key_proof_from_request,
        },
        validation::{bgv_profile_rejection, validate_ciphertext_hex, validate_plaintext_hex},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) fn describe_bgv_rns_profile() -> CanonicalResult<Value> {
    Ok(json!({
        "profile": selected_profile_value(),
        "profileHash": profile_hash()?,
        "backendProfileHash": backend_profile_hash()?,
        "batchEncoderHash": batch_encoder_hash()?,
        "encryptedBallotAggregateLayoutHash": encrypted_ballot_aggregate_layout_hash()?,
        "batchLayoutBinding": batch_layout_binding_value()?,
        "batchLayoutBindingHash": batch_layout_binding_hash()?,
        "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
        "encryptedBallotLayoutHash": encrypted_ballot_layout_hash()?,
        "encryptedBallotAggregateProfileHash": encrypted_ballot_aggregate_profile_hash()?,
        "directAggregateLayoutHash": direct_aggregate_layout_hash()?,
        "directComparisonProfileHash": direct_comparison_profile_hash()?,
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
            "BGV evaluator operation {operation_name} is not part of the selected BGV-RNS/evaluator operation registry"
        ),
        None,
    ))
}

pub(crate) fn describe_bgv_passive_setup_object_model() -> CanonicalResult<Value> {
    describe_passive_setup_object_model()
}

pub(crate) fn describe_collective_bgv_setup_profile_from_request() -> CanonicalResult<Value> {
    describe_collective_bgv_setup_profile()
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

pub(crate) fn verify_trustee_evaluation_key_proof(request: &Value) -> CanonicalResult<Value> {
    verify_trustee_evaluation_key_proof_from_request(request)
}

pub(crate) fn generate_compact_vss_share_linkage_proof(request: &Value) -> CanonicalResult<Value> {
    generate_compact_vss_share_linkage_proof_from_request(request)
}

pub(crate) fn verify_compact_vss_share_linkage_proof(request: &Value) -> CanonicalResult<Value> {
    verify_compact_vss_share_linkage_proof_from_request(request)
}

pub(crate) fn generate_compact_same_secret_bridge_proof(request: &Value) -> CanonicalResult<Value> {
    generate_compact_same_secret_bridge_proof_from_request(request)
}

pub(crate) fn verify_compact_same_secret_bridge_proof(request: &Value) -> CanonicalResult<Value> {
    verify_compact_same_secret_bridge_proof_from_request(request)
}

pub(crate) fn compute_setup_commitment_from_opening(request: &Value) -> CanonicalResult<Value> {
    compute_setup_commitment_from_opening_request(request)
}

pub(crate) fn compute_compact_vss_commitment_from_opening(
    request: &Value,
) -> CanonicalResult<Value> {
    compute_compact_vss_commitment_from_opening_request(request)
}

pub(crate) fn encode_compact_vss_commitment_body(request: &Value) -> CanonicalResult<Value> {
    encode_compact_vss_commitment_body_request(request)
}

pub(crate) fn decode_compact_vss_commitment_body(request: &Value) -> CanonicalResult<Value> {
    decode_compact_vss_commitment_body_request(request)
}

pub(crate) fn verify_compact_vss_commitment_opening(request: &Value) -> CanonicalResult<Value> {
    verify_compact_vss_commitment_opening_request(request)
}

pub(crate) fn verify_compact_vss_coefficient_commitment_set(
    request: &Value,
) -> CanonicalResult<Value> {
    verify_compact_vss_coefficient_commitment_set_request(request)
}

pub(crate) fn verify_compact_vss_recipient_share_commitment_set(
    request: &Value,
) -> CanonicalResult<Value> {
    verify_compact_vss_recipient_share_commitment_set_request(request)
}

pub(crate) fn verify_compact_vss_aggregate_threshold_commitment_set(
    request: &Value,
) -> CanonicalResult<Value> {
    verify_compact_vss_aggregate_threshold_commitment_set_request(request)
}

pub(crate) fn verify_compact_vss_share_linkage_statement(
    request: &Value,
) -> CanonicalResult<Value> {
    verify_compact_vss_share_linkage_statement_request(request)
}

pub(crate) fn verify_compact_vss_same_secret_bridge_statement_set(
    request: &Value,
) -> CanonicalResult<Value> {
    verify_compact_vss_same_secret_bridge_statement_set_request(request)
}

pub(crate) fn verify_compact_vss_same_secret_bridge_proof_material_set(
    request: &Value,
) -> CanonicalResult<Value> {
    verify_compact_vss_same_secret_bridge_proof_material_set_request(request)
}

pub(crate) fn derive_threshold_share_commitments(request: &Value) -> CanonicalResult<Value> {
    derive_threshold_share_commitments_from_request(request)
}

pub(crate) fn derive_threshold_share_commitments_from_transport(
    request: &Value,
) -> CanonicalResult<Value> {
    derive_threshold_share_commitments_from_transport_request(request)
}

pub(crate) fn begin_threshold_share_commitments_from_transport_stream(
    request: &Value,
) -> CanonicalResult<Value> {
    begin_threshold_share_commitment_transport_derivation_stream_request(request)
}

pub(crate) fn absorb_threshold_share_commitments_from_transport_stream_chunk(
    request: &Value,
) -> CanonicalResult<Value> {
    absorb_threshold_share_commitment_transport_derivation_stream_chunk_request(request)
}

pub(crate) fn finish_threshold_share_commitments_from_transport_stream(
    request: &Value,
) -> CanonicalResult<Value> {
    finish_threshold_share_commitment_transport_derivation_stream_request(request)
}

pub(crate) fn abort_threshold_share_commitments_from_transport_stream(
    request: &Value,
) -> CanonicalResult<Value> {
    abort_threshold_share_commitment_transport_derivation_stream_request(request)
}

pub(crate) fn release_verified_transported_vss_material(request: &Value) -> CanonicalResult<Value> {
    release_verified_transported_vss_material_request(request)
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

pub(crate) fn verify_local_trustee_setup_state(request: &Value) -> CanonicalResult<Value> {
    verify_local_trustee_setup_state_from_request(request)
}

pub(crate) fn generate_bgv_evaluation_key_material_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    generate_passive_setup_public_evaluation_key_material_from_request(request)
}

pub(crate) fn encode_bgv_batch_plaintext_from_request(request: &Value) -> CanonicalResult<Value> {
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
            "BGV batch encoder requires explicit direct encrypted ballot aggregate layout binding",
        )
    })?;
    let expected_binding = batch_layout_binding_value()?;
    if supplied_binding != &expected_binding {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "BGV batch encoder layout binding does not match the selected direct encrypted ballot aggregate layout",
        ));
    }

    Ok(())
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
        "profileHash": profile_hash()?,
        "ciphertextRoot": root,
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
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
        "sourceCanonicalBytesHash512": canonical_bytes_hash(&source_bytes),
        "convertedCanonicalBytesHash512": canonical_bytes_hash(&converted_bytes),
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
        "profileHash": object.components[0].profile_hash,
        "basisId": object.components[0].basis_id,
        "level": object.components[0].level,
        "coefficientCount": object.components[0].coefficient_count,
        "layoutHash": object.components[0].encrypted_ballot_aggregate_layout_hash,
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
    fn native_commands_produce_stable_bgv_rns_canonical_roots() {
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
            "0ed438e393c879787b859758e3c975edf4520b0258d2b42690eeb336c5a72140e265e5e7404b868ade767ee3b29da3c669c9d8db382a8877bb032accd51f8a58"
        );
        assert_eq!(
            encoded["canonicalBytesHash512"],
            "a6c247b2a549934dcf071cb48cb983194ea8ecf6d1c4021cae3750f5385e9fa3db08671d84568ca33614b5a1f581069d441b1fa4c426d266b1c04e8f4d39ee76"
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
            "28abe0e1146052111d852fd130c46ca993f9e30bd6f41a82b7bd060f18516cdca0af82cd2d7691b419a1f940d550424170dccded3c3260d6ca57175c86e569f0"
        );
        assert_eq!(
            ciphertext["canonicalBytesHash512"],
            "5e16cf5cac15f9767873d0f469cf1a014470908652216124e6ec8048cf04238e73d54e37dd7236996e988ea053cca303910cdd4e2dea50a67ef433fbd7ad9e70"
        );
        assert_eq!(ciphertext["canonicalByteLength"], 180_781);

        let base_conversion =
            generate_bgv_base_conversion_fixture_from_request(&serde_json::json!({
                "slots": [7, 8, 9, 65_536]
            }))
            .expect("base conversion fixture");
        assert_eq!(
            base_conversion["sourcePlaintextRoot"],
            "6d0bed44f39f28a28e8cc58fbf3f81885cbab61a31e9166daaa08d4a90c90a29f3fbea28949e0c2169aa395057b3eb02e79b308893a224a7a069d1849d428500"
        );
        assert_eq!(
            base_conversion["convertedPlaintextRoot"],
            "2b8a266d210fc0aab7756fdf57322f7b4c8e1f166eac07409dd9a66b85fc3d8d58732e880b757ecb740c7dd0629e674c0d3ccc4ed9054e0cfcddf60638193144"
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
