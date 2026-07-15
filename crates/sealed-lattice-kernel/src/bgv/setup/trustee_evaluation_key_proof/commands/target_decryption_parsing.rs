use super::super::invalid_succinct_setup_proof;
use super::super::relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, VssShareLinkageCommitment,
};
use super::VssPublicCommandCommitmentExpectation;
use super::decoding::{
    decode_component_material_bytes, read_hex_bytes, read_string, read_u64, read_u64_matrix,
    read_u64_matrix3,
};
use crate::bgv::setup_helpers::validate_hash_string;
use crate::encoding::CanonicalResult;
use crate::hashing::derive_canonical_object_hash;
use serde_json::{Value, json};

pub(in crate::bgv::setup) fn vss_share_linkage_commitment_from_value(
    value: &Value,
    expected: VssPublicCommandCommitmentExpectation<'_>,
) -> CanonicalResult<VssShareLinkageCommitment> {
    if read_string(value, "objectType")? != "VssCommittedMaterialCommitment" {
        return Err(invalid_succinct_setup_proof(format!(
            "{}.objectType must be VssCommittedMaterialCommitment",
            expected.field_name
        )));
    }
    let computed_commitment_root = derive_canonical_object_hash(value)?;
    if computed_commitment_root != expected.root {
        return Err(invalid_succinct_setup_proof(format!(
            "{} root does not match its commitment object",
            expected.field_name
        )));
    }
    if read_string(value, "commitmentRole")? != expected.role
        || read_u64(value, "rnsLimbIndex")? != expected.rns_limb_index as u64
        || read_u64(value, "rnsPrime")? != expected.rns_prime
        || read_u64(value, "ringDegree")?
            != u64::try_from(expected.ring_degree)
                .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit u64"))?
    {
        return Err(invalid_succinct_setup_proof(format!(
            "{} metadata must match the share-linkage statement",
            expected.field_name
        )));
    }
    let commitment_context_hash = read_string(value, "commitmentContextHash")?.to_string();
    validate_hash_string(
        &commitment_context_hash,
        &format!("{}.commitmentContextHash", expected.field_name),
    )?;
    let material_root_bytes =
        crate::transcript_core::decode_hex(read_string(value, "materialRootHex")?)?;
    let material_root: super::super::merkle_commitment::MerkleDigest =
        material_root_bytes.as_slice().try_into().map_err(|_| {
            invalid_succinct_setup_proof(format!(
                "{}.materialRootHex must be a full Merkle digest",
                expected.field_name
            ))
        })?;

    Ok(VssShareLinkageCommitment {
        commitment_context_hash,
        material_root,
    })
}

pub(super) fn key_descriptor_from_value(
    key_value: &Value,
    request: &Value,
) -> CanonicalResult<EvaluationKeyShareDescriptor> {
    let kind = match read_string(key_value, "proofFamily")? {
        "relinearization-round-one" => EvaluationKeyShareKind::RelinearizationRoundOne,
        "relinearization-round-two" => EvaluationKeyShareKind::RelinearizationRoundTwo,
        "galois-rotation" => EvaluationKeyShareKind::GaloisRotation {
            galois_element: usize::try_from(read_u64(key_value, "rotation")?)
                .map_err(|_| invalid_succinct_setup_proof("rotation does not fit usize"))?,
        },
        unknown => {
            return Err(invalid_succinct_setup_proof(format!(
                "unknown evaluation-key proof family {unknown}"
            )));
        }
    };
    let level = usize::try_from(read_u64(key_value, "level")?)
        .map_err(|_| invalid_succinct_setup_proof("level does not fit usize"))?;
    let expected_digit_count = level
        .checked_add(1)
        .ok_or_else(|| invalid_succinct_setup_proof("key digit count overflowed"))?;
    let component_b_by_digit = match (
        key_value.get("componentBByDigit"),
        key_value.get("componentMaterialBytesHex"),
    ) {
        (Some(_), None) => read_u64_matrix3(key_value, "componentBByDigit")?,
        (None, Some(_)) => decode_component_material_bytes(
            &read_hex_bytes(key_value, "componentMaterialBytesHex")?,
            level,
            expected_digit_count,
            usize::try_from(read_u64(request, "ringDegree")?)
                .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?,
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
    let (key_switch_domain, key_switch_seed_hex) = {
            let same_secret_linkage = request
                .get("sameSecretLinkage")
                .ok_or_else(|| invalid_succinct_setup_proof("sameSecretLinkage must be present"))?;
            let public_matrix_seed_hash = read_string(same_secret_linkage, "publicMatrixSeedHash")?;
            let context = request
                .get("context")
                .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
            let evaluator_key_schedule_root = read_string(context, "evaluatorKeyScheduleRoot")?;
            match kind {
                EvaluationKeyShareKind::RelinearizationRoundOne => (
                    "relinearization".to_string(),
                    derive_canonical_object_hash(&json!({
                        "objectType": "RelinearizationKeySwitchPublicSampleSeed",
                        "publicMatrixSeedHash": public_matrix_seed_hash,
                        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
                        "round": "round-one",
                        "level": level,
                    }))?,
                ),
                EvaluationKeyShareKind::RelinearizationRoundTwo => (
                    "relinearization".to_string(),
                    derive_canonical_object_hash(&json!({
                        "objectType": "RelinearizationKeySwitchPublicSampleSeed",
                        "publicMatrixSeedHash": public_matrix_seed_hash,
                        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
                        "round": "round-two",
                        "level": level,
                    }))?,
                ),
                EvaluationKeyShareKind::GaloisRotation { galois_element } => (
                    format!("galois-{galois_element}"),
                    derive_canonical_object_hash(&json!({
                        "objectType": "GaloisKeySwitchPublicSampleSeed",
                        "publicMatrixSeedHash": public_matrix_seed_hash,
                        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
                        "rotation": galois_element,
                        "level": level,
                    }))?,
                ),
            }
    };

    Ok(EvaluationKeyShareDescriptor {
        kind,
        level,
        key_switch_domain,
        key_switch_seed_hex,
        component_b_by_digit,
        round_one_aggregate_diagonal,
    })
}
