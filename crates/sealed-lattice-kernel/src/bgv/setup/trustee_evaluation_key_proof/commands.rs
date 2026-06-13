use serde_json::{Value, json};

use super::accounting::{
    succinct_evaluation_key_proof_accounting_hash, succinct_evaluation_key_proof_accounting_value,
    succinct_public_key_share_accounting_hash, succinct_public_key_share_accounting_value,
    succinct_same_secret_linkage_anchor_accounting_hash,
    succinct_same_secret_linkage_anchor_accounting_value,
};
use super::proof_codec::{
    decode_trustee_evaluation_key_proof, encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, SameSecretLinkageStatement,
    SuccinctSetupProofContext, SuccinctSetupProofFamilyShape, TrusteeEvaluationKeyStatement,
    TrusteeEvaluationKeyWitness,
};
use super::verifier::verify_evaluation_key_share;
use super::*;
use crate::bgv::setup::commitment::parse_setup_commitment_full_value;
use crate::bgv::validation::reject_unexpected_bgv_request_fields;
use crate::hashing::to_hex;

// The model status and accounting object each migrated family carries on its
// command responses. The argument machinery is shared, so only the family
// label, model status, and accounting object differ.
fn family_proof_model_status(shape: SuccinctSetupProofFamilyShape) -> &'static str {
    match shape {
        SuccinctSetupProofFamilyShape::SameSecretLinkageAnchor => {
            SAME_SECRET_LINKAGE_ANCHOR_PROOF_MODEL_STATUS
        }
        SuccinctSetupProofFamilyShape::PublicKeyShare => {
            PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS
        }
        SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => {
            TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS
        }
    }
}

fn family_accounting_hash(shape: SuccinctSetupProofFamilyShape) -> CanonicalResult<String> {
    match shape {
        SuccinctSetupProofFamilyShape::SameSecretLinkageAnchor => {
            succinct_same_secret_linkage_anchor_accounting_hash()
        }
        SuccinctSetupProofFamilyShape::PublicKeyShare => {
            succinct_public_key_share_accounting_hash()
        }
        SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => {
            succinct_evaluation_key_proof_accounting_hash()
        }
    }
}

fn family_accounting_value(shape: SuccinctSetupProofFamilyShape) -> CanonicalResult<Value> {
    match shape {
        SuccinctSetupProofFamilyShape::SameSecretLinkageAnchor => {
            succinct_same_secret_linkage_anchor_accounting_value()
        }
        SuccinctSetupProofFamilyShape::PublicKeyShare => {
            succinct_public_key_share_accounting_value()
        }
        SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => {
            succinct_evaluation_key_proof_accounting_value()
        }
    }
}

// Generate one trustee-batched evaluation-key proof from a JSON request. The
// statement carries the ceremony context, the key descriptors with embedded
// component material, and the same-secret linkage commitments; the witness
// carries the shared secret, per-key errors, and the linkage openings. The
// response returns canonical proof bytes; chunked transport wraps those bytes
// at the protocol layer.
pub(crate) fn generate_trustee_evaluation_key_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "context",
            "ringDegree",
            "keys",
            "sameSecretLinkage",
            "secretCoefficients",
            "errorCoefficientsByKey",
            "negativeIndicatorCoefficients",
            "openingRandomnessByLimb",
            "proofRandomnessSource",
            "proofRandomnessSeedHex",
        ],
        "generateTrusteeEvaluationKeyProof",
    )?;
    let statement = statement_from_request(request)?;
    let secret_coefficients = read_i64_array(request, "secretCoefficients")?;
    let error_coefficients_by_key = match request.get("errorCoefficientsByKey") {
        Some(_) => read_i64_matrix(request, "errorCoefficientsByKey")?,
        None => Vec::new(),
    };
    let negative_indicator_coefficients = match request.get("negativeIndicatorCoefficients") {
        Some(_) => read_i64_array(request, "negativeIndicatorCoefficients")?,
        None => Vec::new(),
    };
    let opening_randomness_by_limb = match request.get("openingRandomnessByLimb") {
        Some(_) => read_i64_matrix(request, "openingRandomnessByLimb")?,
        None => Vec::new(),
    };
    let witness = TrusteeEvaluationKeyWitness {
        secret_coefficients,
        error_coefficients_by_key,
        negative_indicator_coefficients,
        opening_randomness_by_limb,
    };
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_source = read_string(request, "proofRandomnessSource")?;

    let proof = prove_evaluation_key_share(&statement, &witness, proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let shape = statement.family_shape()?;

    Ok(json!({
        "ok": true,
        "operation": "generateTrusteeEvaluationKeyProof",
        "proofFamily": statement.context.proof_family,
        "proofModelStatus": family_proof_model_status(shape),
        "proofAccountingHash": family_accounting_hash(shape)?,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.limb_count(),
        "keyCount": statement.keys.len(),
        "sameSecretLinkageIncluded": statement.same_secret_linkage.is_some(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
        "proofRandomness": {
            "source": proof_randomness_source,
            "retention": "proof randomness seed material is consumed for proof generation and is not returned"
        },
    }))
}

pub(crate) fn verify_trustee_evaluation_key_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "context",
            "ringDegree",
            "keys",
            "sameSecretLinkage",
            "proofBytesHex",
        ],
        "verifyTrusteeEvaluationKeyProof",
    )?;
    let statement = statement_from_request(request)?;
    let proof_bytes = read_hex_bytes(request, "proofBytesHex")?;
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let shape = statement.family_shape()?;

    Ok(json!({
        "ok": true,
        "operation": "verifyTrusteeEvaluationKeyProof",
        "proofFamily": statement.context.proof_family,
        "proofModelStatus": family_proof_model_status(shape),
        "proofAccountingHash": family_accounting_hash(shape)?,
        "proofAccounting": family_accounting_value(shape)?,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.limb_count(),
        "keyCount": statement.keys.len(),
        "sameSecretLinkageIncluded": statement.same_secret_linkage.is_some(),
        "proofByteLength": proof_bytes.len(),
    }))
}

fn statement_from_request(request: &Value) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let key_values = request
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof("keys must be an array"))?;
    let keys = key_values
        .iter()
        .map(key_descriptor_from_value)
        .collect::<CanonicalResult<Vec<_>>>()?;
    // The key kinds decide the family, and the family decides which labeled
    // binding roots the context must carry.
    let shape = SuccinctSetupProofFamilyShape::from_key_kinds(
        &keys.iter().map(|key| key.kind).collect::<Vec<_>>(),
    )?;
    let context = SuccinctSetupProofContext {
        proof_family: shape.proof_family().to_string(),
        ceremony_id: read_string(context_value, "ceremonyId")?.to_string(),
        manifest_hash: read_string(context_value, "manifestHash")?.to_string(),
        roster_hash: read_string(context_value, "rosterHash")?.to_string(),
        trustee_identity: read_string(context_value, "trusteeIdentity")?.to_string(),
        trustee_roster_position: read_u64(context_value, "trusteeRosterPosition")?,
        setup_epoch: read_string(context_value, "setupEpoch")?.to_string(),
        binding_roots: shape
            .binding_labels()
            .iter()
            .map(|label| {
                Ok((
                    (*label).to_string(),
                    read_string(context_value, label)?.to_string(),
                ))
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
    };
    let same_secret_linkage = match request.get("sameSecretLinkage") {
        None | Some(Value::Null) => None,
        Some(linkage_value) => {
            let commitment_values = linkage_value
                .get("commitments")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof("sameSecretLinkage.commitments must be an array")
                })?;
            let commitments = commitment_values
                .iter()
                .map(parse_setup_commitment_full_value)
                .collect::<CanonicalResult<Vec<_>>>()?;
            Some(SameSecretLinkageStatement {
                public_matrix_seed_hash: read_string(linkage_value, "publicMatrixSeedHash")?
                    .to_string(),
                commitments,
            })
        }
    };
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys,
        same_secret_linkage,
    };
    statement.validate_shape()?;

    Ok(statement)
}

fn key_descriptor_from_value(key_value: &Value) -> CanonicalResult<EvaluationKeyShareDescriptor> {
    let kind = match read_string(key_value, "proofFamily")? {
        "relinearization-round-one" => EvaluationKeyShareKind::RelinearizationRoundOne,
        "relinearization-round-two" => EvaluationKeyShareKind::RelinearizationRoundTwo,
        "galois-rotation" => EvaluationKeyShareKind::GaloisRotation {
            galois_element: usize::try_from(read_u64(key_value, "rotation")?)
                .map_err(|_| invalid_succinct_setup_proof("rotation does not fit usize"))?,
        },
        "public-key-share" => EvaluationKeyShareKind::PublicKeyShare,
        unknown => {
            return Err(invalid_succinct_setup_proof(format!(
                "unknown evaluation-key proof family {unknown}"
            )));
        }
    };
    let level = usize::try_from(read_u64(key_value, "level")?)
        .map_err(|_| invalid_succinct_setup_proof("level does not fit usize"))?;
    let component_b_by_digit = match (
        key_value.get("componentBByDigit"),
        key_value.get("componentMaterialBytesHex"),
    ) {
        (Some(_), None) => read_u64_matrix3(key_value, "componentBByDigit")?,
        (None, Some(_)) => decode_component_material_bytes(
            &read_hex_bytes(key_value, "componentMaterialBytesHex")?,
            level,
        )?,
        _ => {
            return Err(invalid_succinct_setup_proof(
                "exactly one of componentBByDigit and componentMaterialBytesHex must be supplied",
            ));
        }
    };
    let round_one_aggregate_diagonal = match key_value.get("roundOneAggregateDiagonal") {
        Some(_) => read_u64_matrix(key_value, "roundOneAggregateDiagonal")?,
        None => Vec::new(),
    };

    Ok(EvaluationKeyShareDescriptor {
        kind,
        level,
        key_switch_domain: read_string(key_value, "keySwitchDomain")?.to_string(),
        key_switch_seed_hex: read_string(key_value, "keySwitchSeedHex")?.to_string(),
        component_b_by_digit,
        round_one_aggregate_diagonal,
    })
}

// Canonical binary key-switch component vector material: the same format the
// chunked component-material transport carries.
const COMPONENT_MATERIAL_MAGIC: &[u8; 8] = b"SLEKCMV1";

fn decode_component_material_bytes(
    material_bytes: &[u8],
    expected_level: usize,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let read_word = |cursor: &mut usize| -> CanonicalResult<u64> {
        let end = cursor
            .checked_add(8)
            .ok_or_else(|| invalid_succinct_setup_proof("component material cursor overflowed"))?;
        let slice = material_bytes
            .get(*cursor..end)
            .ok_or_else(|| invalid_succinct_setup_proof("component material ended unexpectedly"))?;
        *cursor = end;
        let mut word = [0_u8; 8];
        word.copy_from_slice(slice);
        Ok(u64::from_le_bytes(word))
    };
    let magic = material_bytes
        .get(..8)
        .ok_or_else(|| invalid_succinct_setup_proof("component material ended unexpectedly"))?;
    if magic != COMPONENT_MATERIAL_MAGIC {
        return Err(invalid_succinct_setup_proof(
            "component material has the wrong format marker",
        ));
    }
    let mut cursor = 8_usize;
    let level = usize::try_from(read_word(&mut cursor)?)
        .map_err(|_| invalid_succinct_setup_proof("component material level does not fit usize"))?;
    let ring_degree = usize::try_from(read_word(&mut cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("component material ring degree does not fit usize")
    })?;
    let digit_count = usize::try_from(read_word(&mut cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("component material digit count does not fit usize")
    })?;
    let limb_count = usize::try_from(read_word(&mut cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("component material limb count does not fit usize")
    })?;
    if level != expected_level || digit_count != level + 1 || limb_count != level + 1 {
        return Err(invalid_succinct_setup_proof(
            "component material shape does not match the key descriptor level",
        ));
    }
    let mut component_b_by_digit = Vec::with_capacity(digit_count);
    for _ in 0..digit_count {
        let mut by_limb = Vec::with_capacity(limb_count);
        for _ in 0..limb_count {
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                coefficients.push(read_word(&mut cursor)?);
            }
            by_limb.push(coefficients);
        }
        component_b_by_digit.push(by_limb);
    }
    if cursor != material_bytes.len() {
        return Err(invalid_succinct_setup_proof(
            "component material has trailing bytes",
        ));
    }

    Ok(component_b_by_digit)
}

fn read_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be a string")))
}

fn read_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!("{field_name} must be a non-negative integer"))
        })
}

fn read_hex_bytes(value: &Value, field_name: &str) -> CanonicalResult<Vec<u8>> {
    let text = read_string(value, field_name)?;
    if !text.len().is_multiple_of(2) {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must contain whole bytes"
        )));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| {
                invalid_succinct_setup_proof(format!("{field_name} must be lowercase hex"))
            })
        })
        .collect()
}

fn read_i64_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<i64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|entry| {
            entry.as_i64().ok_or_else(|| {
                invalid_succinct_setup_proof(format!(
                    "{field_name} entries must be signed integers"
                ))
            })
        })
        .collect()
}

fn read_i64_matrix(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<Vec<i64>>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|outer| {
            outer
                .as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!(
                        "{field_name} entries must be arrays of arrays"
                    ))
                })?
                .iter()
                .map(|inner| {
                    inner
                        .as_array()
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(format!(
                                "{field_name} inner entries must be arrays"
                            ))
                        })?
                        .iter()
                        .map(|entry| {
                            entry.as_i64().ok_or_else(|| {
                                invalid_succinct_setup_proof(format!(
                                    "{field_name} coefficients must be signed integers"
                                ))
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn read_u64_matrix(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<u64>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|row| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!("{field_name} rows must be arrays"))
                })?
                .iter()
                .map(|entry| {
                    entry.as_u64().ok_or_else(|| {
                        invalid_succinct_setup_proof(format!(
                            "{field_name} coefficients must be non-negative integers"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

fn read_u64_matrix3(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|digit| {
            digit
                .as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!(
                        "{field_name} digits must be arrays of limbs"
                    ))
                })?
                .iter()
                .map(|limb| {
                    limb.as_array()
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(format!(
                                "{field_name} limbs must be coefficient arrays"
                            ))
                        })?
                        .iter()
                        .map(|entry| {
                            entry.as_u64().ok_or_else(|| {
                                invalid_succinct_setup_proof(format!(
                                    "{field_name} coefficients must be non-negative integers"
                                ))
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}
