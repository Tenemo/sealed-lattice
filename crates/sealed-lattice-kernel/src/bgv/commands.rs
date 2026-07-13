use serde_json::{Value, json};

use crate::{
    bgv::{
        encoding::encode_batch_plaintext_slots,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE, bgv_parameters_hash, bgv_parameters_value},
        serialization::{BgvObjectKind, canonical_bytes_hex, plaintext_root, serialize_bgv_object},
        setup::{
            compute_setup_commitment_from_opening_request,
            compute_vss_committed_material_commitment_request,
            describe_collective_bgv_setup_parameters,
            describe_trustee_evaluation_key_statement_from_request,
            generate_passive_setup_package_from_request,
            generate_private_vss_share_proof_from_request,
            generate_same_secret_bridge_proof_from_request,
            generate_trustee_evaluation_key_proof_from_request,
            generate_vss_share_linkage_proof_from_request,
            verify_local_trustee_setup_state_from_request,
            verify_passive_setup_package_from_request,
            verify_private_vss_share_envelope_from_request,
        },
        validation::{validate_ciphertext_hex, validate_plaintext_hex},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) fn describe_bgv_rns_parameters() -> CanonicalResult<Value> {
    Ok(json!({
        "parameters": bgv_parameters_value(),
        "bgvParametersHash": bgv_parameters_hash()?,
    }))
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

pub(crate) fn generate_bgv_passive_setup(request: &Value) -> CanonicalResult<Value> {
    generate_passive_setup_package_from_request(request)
}

pub(crate) fn verify_bgv_passive_setup(request: &Value) -> CanonicalResult<Value> {
    verify_passive_setup_package_from_request(request)
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
    let plaintext_root = plaintext_root(&canonical_bytes);
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
    use super::encode_bgv_batch_plaintext_from_request;
    use crate::bgv::{
        base_conversion::convert_plaintext_lifted_basis,
        encoding::encode_batch_plaintext_slots,
        parameters::BgvBasisKind,
        serialization::{BgvObjectKind, ciphertext_root, plaintext_root, serialize_bgv_object},
    };

    #[test]
    fn native_commands_produce_stable_bgv_rns_canonical_roots() {
        let encoded = encode_bgv_batch_plaintext_from_request(&serde_json::json!({
            "slots": [0, 1, 65_536, 17, 99],
            "level": 0
        }))
        .expect("encoded plaintext");

        assert_eq!(
            encoded["plaintextRoot"],
            "ead9e37fb807f2f81dc0e368492f3953fd0be8fcbfac7c672960c826179bb2702d000143b121bf972b0241ff7417fd2083d3df14ccaa7f12b0d28f3a0c435178"
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
            "3ade87dc4834fa5f3a044fab0d3affd1b90c0d6e0c50bf65f96e29ec45a2dd68ef3cd7b130312d339ab3b0c121888633bd0028f41d6f05533ece416d80a327b5"
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
            "47a1537207d0988952691bfc60567d09ed4dfd9565c7d7e63978aef23f3e9f9845e95c8748e93e7bb67569f0864d51a4d4f3a776462d4397631128412200e1ae"
        );
        assert_eq!(
            plaintext_root(&converted_bytes),
            "87a6a958ceb361068206c94fe19298d1fb7f6126f931d82668519dee4acea4a88d8bc9985d508bfd07abe5c06456a8f04581c9300cd7d26500829b514437685f"
        );
        assert_eq!(converted.moduli.len(), 2);
        assert_ne!(
            plaintext_root(&source_bytes),
            plaintext_root(&converted_bytes)
        );
    }
}
