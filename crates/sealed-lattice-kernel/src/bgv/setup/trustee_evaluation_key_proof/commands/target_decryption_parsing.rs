use super::super::invalid_succinct_setup_proof;
use super::super::relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
    VssShareLinkageCommitment,
};
#[cfg(test)]
use super::super::relation::{
    SetupProofStatement, SuccinctSetupProofFamilyShape, TargetDecryptionShareLimbStatement,
    TargetDecryptionShareRoleStatement, TargetDecryptionShareStatement,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness, VssCommittedMaterialWitness,
};
use super::VssPublicCommandCommitmentExpectation;
use super::decoding::{
    decode_component_material_bytes, read_hex_bytes, read_string, read_u64, read_u64_matrix,
    read_u64_matrix3,
};
#[cfg(test)]
use super::decoding::{read_i64_matrix2, read_string_array, read_u64_array};
#[cfg(test)]
use super::request_parsing::proof_context_from_value;
#[cfg(test)]
use super::{
    TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_ROLE, TARGET_DECRYPTION_PROOF_TARGET_ROLES,
};
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES;
use crate::bgv::setup_helpers::validate_hash_string;
use crate::encoding::CanonicalResult;
use crate::hashing::derive_canonical_object_hash;
use serde_json::{Value, json};

#[cfg(test)]
pub(super) fn target_decryption_share_statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let target_value = request
        .get("targetDecryptionShare")
        .ok_or_else(|| invalid_succinct_setup_proof("targetDecryptionShare must be present"))?;
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::TargetDecryptionShare,
    )?;
    let target_share_proof_statement_root =
        read_string(target_value, "targetShareProofStatementRoot")?;
    if context.binding_roots[0] != target_share_proof_statement_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the target share proof statement root",
        ));
    }

    let public_matrix_seed_hash = read_string(target_value, "publicMatrixSeedHash")?.to_string();
    let trustee_identity = read_string(target_value, "trusteeIdentity")?.to_string();
    let trustee_roster_position = read_u64(target_value, "trusteeRosterPosition")?;
    let smudging_commitment_set = target_value
        .get("smudgingCommitmentSet")
        .ok_or_else(|| invalid_succinct_setup_proof("smudgingCommitmentSet must be present"))?;
    let smudging_commitment_set_root =
        validated_target_decryption_smudging_commitment_set_root(smudging_commitment_set)?;
    let smudging_active_limb_count = target_value
        .get("targetRnsLimbStatements")
        .and_then(Value::as_array)
        .map(Vec::len)
        .filter(|count| *count > 0)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("targetRnsLimbStatements must be a non-empty array")
        })?;
    let smudging_record_count = smudging_commitment_set
        .get("commitmentRecords")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet.commitmentRecords must be an array")
        })?;
    let expected_record_count = TARGET_DECRYPTION_PROOF_TARGET_ROLES
        .len()
        .checked_mul(smudging_active_limb_count)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("target-decryption smudging slice count overflowed")
        })?;
    if smudging_record_count != expected_record_count {
        return Err(invalid_succinct_setup_proof(
            "smudging commitment records must contain one flooding-noise commitment per role and active limb",
        ));
    }
    let active_credential_binding_root =
        read_string(target_value, "activeCredentialBindingRoot")?.to_string();
    let limb_statements = target_decryption_share_limb_statements_from_request(
        target_value,
        smudging_commitment_set,
        ring_degree,
    )?;
    if limb_statements.len() != smudging_active_limb_count
        || limb_statements
            .iter()
            .enumerate()
            .any(|(expected_limb_index, limb_statement)| {
                limb_statement.target_rns_limb_index != expected_limb_index
            })
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption proof must cover every active target limb in canonical order",
        ));
    }
    let aggregate_message_coefficient_bound = limb_statements
        .iter()
        .map(|limb_statement| limb_statement.target_rns_prime)
        .max()
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "target-decryption proof must include at least one active target limb",
            )
        })?;

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        proof: SetupProofStatement::TargetDecryptionShare(TargetDecryptionShareStatement {
            public_matrix_seed_hash,
            trustee_identity,
            trustee_roster_position,
            active_credential_binding_root,
            aggregate_message_coefficient_bound,
            smudging_commitment_set_root,
            limb_statements,
        }),
    };
    statement.validate_shape()?;

    Ok(statement)
}

#[cfg(test)]
pub(super) fn target_decryption_share_limb_statements_from_request(
    target_value: &Value,
    smudging_commitment_set: &Value,
    ring_degree: usize,
) -> CanonicalResult<Vec<TargetDecryptionShareLimbStatement>> {
    let limb_statement_values = target_value
        .get("targetRnsLimbStatements")
        .ok_or_else(|| invalid_succinct_setup_proof("targetRnsLimbStatements must be present"))?
        .as_array()
        .ok_or_else(|| invalid_succinct_setup_proof("targetRnsLimbStatements must be an array"))?;
    if limb_statement_values.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "targetRnsLimbStatements must not be empty",
        ));
    }

    limb_statement_values
        .iter()
        .map(|limb_statement_value| {
            target_decryption_share_limb_statement_from_value(
                limb_statement_value,
                smudging_commitment_set,
                ring_degree,
            )
        })
        .collect()
}

#[cfg(test)]
pub(super) fn target_decryption_share_limb_statement_from_value(
    limb_statement_value: &Value,
    smudging_commitment_set: &Value,
    ring_degree: usize,
) -> CanonicalResult<TargetDecryptionShareLimbStatement> {
    let target_rns_limb_index =
        usize::try_from(read_u64(limb_statement_value, "targetRnsLimbIndex")?)
            .map_err(|_| invalid_succinct_setup_proof("targetRnsLimbIndex does not fit usize"))?;
    let target_rns_prime = DATA_PRIMES
        .get(target_rns_limb_index)
        .copied()
        .ok_or_else(|| {
            invalid_succinct_setup_proof("targetRnsLimbIndex is outside the data-prime basis")
        })?;
    let aggregate_opening_root =
        read_string(limb_statement_value, "aggregateOpeningRoot")?.to_string();
    let aggregate_commitment_value = limb_statement_value
        .get("aggregateCommitment")
        .ok_or_else(|| invalid_succinct_setup_proof("aggregateCommitment must be present"))?;
    let aggregate_commitment_root = derive_canonical_object_hash(aggregate_commitment_value)?;
    let aggregate_commitment = vss_share_linkage_commitment_from_value(
        aggregate_commitment_value,
        VssPublicCommandCommitmentExpectation {
            field_name: "targetDecryptionShare.aggregateCommitment".to_string(),
            root: &aggregate_commitment_root,
            role: "aggregate-threshold-share",
            rns_limb_index: target_rns_limb_index,
            rns_prime: target_rns_prime,
            ring_degree,
        },
    )?;
    let role_statements = target_decryption_share_role_statements_from_request(
        limb_statement_value,
        smudging_commitment_set,
        target_rns_limb_index,
        target_rns_prime,
        ring_degree,
    )?;

    Ok(TargetDecryptionShareLimbStatement {
        target_rns_limb_index,
        target_rns_prime,
        aggregate_commitment_root,
        aggregate_opening_root,
        aggregate_commitment,
        role_statements,
    })
}

#[cfg(test)]
pub(super) fn target_decryption_share_role_statements_from_request(
    target_value: &Value,
    smudging_commitment_set: &Value,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    ring_degree: usize,
) -> CanonicalResult<Vec<TargetDecryptionShareRoleStatement>> {
    let role_statement_values = target_value
        .get("targetRoleStatements")
        .ok_or_else(|| invalid_succinct_setup_proof("targetRoleStatements must be present"))?
        .as_array()
        .ok_or_else(|| invalid_succinct_setup_proof("targetRoleStatements must be an array"))?;
    if role_statement_values.len() != TARGET_DECRYPTION_PROOF_TARGET_ROLES.len() {
        return Err(invalid_succinct_setup_proof(
            "targetRoleStatements must cover the canonical target roles",
        ));
    }

    role_statement_values
        .iter()
        .enumerate()
        .map(|(target_role_index, role_statement_value)| {
            target_decryption_share_role_statement_from_value(
                role_statement_value,
                smudging_commitment_set,
                TARGET_DECRYPTION_PROOF_TARGET_ROLES[target_role_index],
                target_rns_limb_index,
                target_rns_prime,
                ring_degree,
            )
        })
        .collect()
}

#[cfg(test)]
pub(super) fn target_decryption_share_role_statement_from_value(
    role_statement_value: &Value,
    smudging_commitment_set: &Value,
    target_role: &str,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    ring_degree: usize,
) -> CanonicalResult<TargetDecryptionShareRoleStatement> {
    let (flooding_noise_commitment_root, flooding_noise_commitment) =
        target_decryption_flooding_noise_commitment_from_set(
            smudging_commitment_set,
            target_role,
            target_rns_limb_index,
            target_rns_prime,
            ring_degree,
        )?;

    Ok(TargetDecryptionShareRoleStatement {
        target_role: target_role.to_string(),
        target_ciphertext_component_one: read_u64_array(
            role_statement_value,
            "targetCiphertextComponentOne",
        )?,
        released_partial_decryption: read_u64_array(
            role_statement_value,
            "releasedPartialDecryption",
        )?,
        flooding_noise_commitment_root,
        flooding_noise_commitment,
    })
}

#[cfg(test)]
pub(super) fn validated_target_decryption_smudging_commitment_set_root(
    smudging_commitment_set: &Value,
) -> CanonicalResult<String> {
    if read_string(smudging_commitment_set, "objectType")?
        != "TargetDecryptionSmudgingCommitmentSet"
    {
        return Err(invalid_succinct_setup_proof(
            "smudgingCommitmentSet must be TargetDecryptionSmudgingCommitmentSet version 1",
        ));
    }
    let commitment_records = smudging_commitment_set
        .get("commitmentRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet.commitmentRecords must be an array")
        })?;
    derive_canonical_object_hash(&json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "commitmentRecords": commitment_records,
    }))
}

#[cfg(test)]
pub(super) fn target_decryption_flooding_noise_commitment_from_set(
    smudging_commitment_set: &Value,
    target_role: &str,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    ring_degree: usize,
) -> CanonicalResult<(String, VssShareLinkageCommitment)> {
    let records = smudging_commitment_set
        .get("commitmentRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet.commitmentRecords must be an array")
        })?;
    if records.len() % TARGET_DECRYPTION_PROOF_TARGET_ROLES.len() != 0 {
        return Err(invalid_succinct_setup_proof(
            "smudging commitment set has an invalid canonical shape",
        ));
    }
    let target_role_index = TARGET_DECRYPTION_PROOF_TARGET_ROLES
        .iter()
        .position(|role| *role == target_role)
        .ok_or_else(|| invalid_succinct_setup_proof("targetRole is not canonical"))?;
    let records_per_role = records.len() / TARGET_DECRYPTION_PROOF_TARGET_ROLES.len();
    let active_limb_count = records_per_role;
    if target_rns_limb_index >= active_limb_count {
        return Err(invalid_succinct_setup_proof(
            "target RNS limb is outside the smudging commitment set",
        ));
    }
    let first_record_index = target_role_index
        .checked_mul(records_per_role)
        .and_then(|offset| offset.checked_add(target_rns_limb_index))
        .ok_or_else(|| invalid_succinct_setup_proof("smudging record index overflowed"))?;
    let record = records.get(first_record_index).ok_or_else(|| {
        invalid_succinct_setup_proof(
            "smudging commitment set is missing a role and limb commitment",
        )
    })?;
    if read_string(record, "objectType")? != "TargetDecryptionSmudgingCommitment" {
        return Err(invalid_succinct_setup_proof(
            "smudging commitment records must be TargetDecryptionSmudgingCommitment version 1",
        ));
    }
    let commitment_value = record.get("commitment").ok_or_else(|| {
        invalid_succinct_setup_proof("smudging commitment record must include a commitment")
    })?;
    let commitment_root = derive_canonical_object_hash(commitment_value)?;
    let commitment = vss_share_linkage_commitment_from_value(
        commitment_value,
        VssPublicCommandCommitmentExpectation {
            field_name: format!(
                "smudgingCommitmentSet.commitmentRecords.{first_record_index}.commitment"
            ),
            root: &commitment_root,
            role: TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_ROLE,
            rns_limb_index: target_rns_limb_index,
            rns_prime: target_rns_prime,
            ring_degree,
        },
    )?;

    Ok((commitment_root, commitment))
}

#[cfg(test)]
pub(super) fn target_decryption_share_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    Ok(TrusteeEvaluationKeyWitness::TargetDecryptionShare {
        message_vectors: read_i64_matrix2(request, "targetDecryptionMessageVectors")?,
        committed_material: VssCommittedMaterialWitness {
            vss_committed_material_seeds_by_bound_message: read_string_array(
                request,
                "vssCommittedMaterialSeedsByBoundMessage",
            )?,
        },
    })
}

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
    let commitment_fields = value
        .get("commitmentFields")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{}.commitmentFields must be an array",
                expected.field_name
            ))
        })?;
    if commitment_fields.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(invalid_succinct_setup_proof(format!(
            "{}.commitmentFields must cover the commitment fields",
            expected.field_name
        )));
    }
    let mut material_roots_by_commitment_field = Vec::with_capacity(commitment_fields.len());
    for (commitment_field_position, commitment_field) in commitment_fields.iter().enumerate() {
        let expected_modulus_index =
            SETUP_COMMITMENT_MODULUS_LIMB_INDICES[commitment_field_position];
        if read_u64(commitment_field, "commitmentModulusIndex")? != expected_modulus_index as u64 {
            return Err(invalid_succinct_setup_proof(format!(
                "{}.commitmentFields must be ordered by commitmentModulusIndex",
                expected.field_name
            )));
        }
        if read_u64(commitment_field, "modulus")? != DATA_PRIMES[expected_modulus_index] {
            return Err(invalid_succinct_setup_proof(format!(
                "{}.commitmentFields modulus must match the commitment field",
                expected.field_name
            )));
        }
        let material_root_bytes =
            crate::transcript_core::decode_hex(read_string(commitment_field, "materialRootHex")?)?;
        let material_root: super::super::merkle_commitment::MerkleDigest =
            material_root_bytes.as_slice().try_into().map_err(|_| {
                invalid_succinct_setup_proof(format!(
                    "{}.commitmentFields material root must be a full Merkle digest",
                    expected.field_name
                ))
            })?;
        material_roots_by_commitment_field.push(material_root);
    }

    Ok(VssShareLinkageCommitment {
        commitment_context_hash,
        material_roots_by_commitment_field,
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
        "public-key-share" => EvaluationKeyShareKind::PublicKeyShare,
        unknown => {
            return Err(invalid_succinct_setup_proof(format!(
                "unknown evaluation-key proof family {unknown}"
            )));
        }
    };
    let level = usize::try_from(read_u64(key_value, "level")?)
        .map_err(|_| invalid_succinct_setup_proof("level does not fit usize"))?;
    let expected_digit_count = if kind == EvaluationKeyShareKind::PublicKeyShare {
        1
    } else {
        level
            .checked_add(1)
            .ok_or_else(|| invalid_succinct_setup_proof("key digit count overflowed"))?
    };
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
    let (key_switch_domain, key_switch_seed_hex) = match kind {
        EvaluationKeyShareKind::PublicKeyShare => {
            let same_secret_bridge = request
                .get("sameSecretBridge")
                .ok_or_else(|| invalid_succinct_setup_proof("sameSecretBridge must be present"))?;
            (
                PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL.to_string(),
                read_string(same_secret_bridge, "publicMatrixSeedHash")?.to_string(),
            )
        }
        _ => {
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
                EvaluationKeyShareKind::PublicKeyShare => unreachable!(),
            }
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
