use super::decoding::{
    decode_component_material_bytes, read_hex_bytes, read_i64_matrix2, read_string,
    read_string_array, read_u64, read_u64_array, read_u64_matrix, read_u64_matrix3,
};
use super::request_parsing::proof_context_from_value;
use super::{
    TARGET_DECRYPTION_PROOF_TARGET_ROLES, TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
    VssPublicCommandCommitmentExpectation,
};
use super::super::{
    TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND, invalid_succinct_setup_proof,
};
use super::super::relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, SetupProofStatement,
    SuccinctSetupProofFamilyShape, TargetDecryptionShareLimbStatement,
    TargetDecryptionShareRoleStatement, TargetDecryptionShareStatement,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness, VssCommittedMaterialWitness,
    VssShareLinkageCommitment,
};
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES;
use crate::encoding::CanonicalResult;
use crate::hashing::derive_canonical_object_hash;
use serde_json::{Value, json};

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
    if context.binding_roots[2] != smudging_commitment_set_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the smudging commitment set root",
        ));
    }
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
    let smudging_slice_count = TARGET_DECRYPTION_PROOF_TARGET_ROLES
        .len()
        .checked_mul(smudging_active_limb_count)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("target-decryption smudging slice count overflowed")
        })?;
    if smudging_slice_count == 0 || smudging_record_count % smudging_slice_count != 0 {
        return Err(invalid_succinct_setup_proof(
            "smudging commitment records must cover every role and active limb with one canonical degree sequence",
        ));
    }
    let smudging_polynomial_degree = smudging_record_count / smudging_slice_count;
    if smudging_polynomial_degree == 0 {
        return Err(invalid_succinct_setup_proof(
            "target-decryption smudging polynomial degree must be positive",
        ));
    }
    let smudging_coefficient_bound = TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND;
    let smudging_signed_coefficient_offset = TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND;
    let smudging_message_coefficient_bound =
        u64::try_from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND * 2 + 1)
            .map_err(|_| invalid_succinct_setup_proof("smudging coefficient bound is invalid"))?;
    let active_credential_binding_root =
        read_string(target_value, "activeCredentialBindingRoot")?.to_string();
    if context.binding_roots[1] != active_credential_binding_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the active aggregate credential binding root",
        ));
    }
    let limb_statements = target_decryption_share_limb_statements_from_request(
        target_value,
        smudging_commitment_set,
        ring_degree,
        smudging_polynomial_degree,
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

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        proof: SetupProofStatement::TargetDecryptionShare(TargetDecryptionShareStatement {
            public_matrix_seed_hash,
            trustee_identity,
            trustee_roster_position,
            active_credential_binding_root,
            interpolation_point: read_u64(target_value, "interpolationPoint")?,
            aggregate_message_coefficient_bound: read_u64(
                target_value,
                "aggregateMessageCoefficientBound",
            )?,
            smudging_commitment_set_root,
            limb_statements,
            smudging_polynomial_degree,
            smudging_coefficient_bound,
            smudging_signed_coefficient_offset,
            smudging_message_coefficient_bound,
            plaintext_multiple: read_u64(target_value, "plaintextMultiple")?,
        }),
    };
    statement.validate_shape()?;

    Ok(statement)
}

pub(super) fn target_decryption_share_limb_statements_from_request(
    target_value: &Value,
    smudging_commitment_set: &Value,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
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
                smudging_polynomial_degree,
            )
        })
        .collect()
}

pub(super) fn target_decryption_share_limb_statement_from_value(
    limb_statement_value: &Value,
    smudging_commitment_set: &Value,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<TargetDecryptionShareLimbStatement> {
    let target_rns_limb_index =
        usize::try_from(read_u64(limb_statement_value, "targetRnsLimbIndex")?)
            .map_err(|_| invalid_succinct_setup_proof("targetRnsLimbIndex does not fit usize"))?;
    let target_rns_prime = read_u64(limb_statement_value, "targetRnsPrime")?;
    let aggregate_commitment_root =
        read_string(limb_statement_value, "aggregateCommitmentRoot")?.to_string();
    let aggregate_opening_root =
        read_string(limb_statement_value, "aggregateOpeningRoot")?.to_string();
    let aggregate_commitment_value = limb_statement_value
        .get("aggregateCommitment")
        .ok_or_else(|| invalid_succinct_setup_proof("aggregateCommitment must be present"))?;
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
        smudging_polynomial_degree,
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

pub(super) fn target_decryption_share_role_statements_from_request(
    target_value: &Value,
    smudging_commitment_set: &Value,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
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
            let expected_target_role = TARGET_DECRYPTION_PROOF_TARGET_ROLES[target_role_index];
            if read_string(role_statement_value, "targetRole")? != expected_target_role {
                return Err(invalid_succinct_setup_proof(
                    "targetRoleStatements must be in canonical target-role order",
                ));
            }
            target_decryption_share_role_statement_from_value(
                role_statement_value,
                smudging_commitment_set,
                target_rns_limb_index,
                target_rns_prime,
                ring_degree,
                smudging_polynomial_degree,
            )
        })
        .collect()
}

pub(super) fn target_decryption_share_role_statement_from_value(
    role_statement_value: &Value,
    smudging_commitment_set: &Value,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<TargetDecryptionShareRoleStatement> {
    let target_role = read_string(role_statement_value, "targetRole")?.to_string();
    let (smudging_commitment_roots, smudging_commitments) =
        target_decryption_smudging_commitments_from_set(
            smudging_commitment_set,
            &target_role,
            target_rns_limb_index,
            target_rns_prime,
            ring_degree,
            smudging_polynomial_degree,
        )?;

    Ok(TargetDecryptionShareRoleStatement {
        target_role,
        target_ciphertext_component_one: read_u64_array(
            role_statement_value,
            "targetCiphertextComponentOne",
        )?,
        released_partial_decryption: read_u64_array(
            role_statement_value,
            "releasedPartialDecryption",
        )?,
        smudging_commitment_roots,
        smudging_commitments,
    })
}

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
    let root = read_string(smudging_commitment_set, "smudgingCommitmentSetRoot")?;
    let commitment_records = smudging_commitment_set
        .get("commitmentRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet.commitmentRecords must be an array")
        })?;
    let expected_root = derive_canonical_object_hash(&json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "commitmentRecords": commitment_records,
    }))?;
    if root != expected_root {
        return Err(invalid_succinct_setup_proof(
            "smudgingCommitmentSetRoot does not match its canonical payload",
        ));
    }

    Ok(root.to_string())
}

pub(super) fn target_decryption_smudging_commitments_from_set(
    smudging_commitment_set: &Value,
    target_role: &str,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<(Vec<String>, Vec<VssShareLinkageCommitment>)> {
    let records = smudging_commitment_set
        .get("commitmentRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet.commitmentRecords must be an array")
        })?;
    if smudging_polynomial_degree == 0
        || records.len() % TARGET_DECRYPTION_PROOF_TARGET_ROLES.len() != 0
    {
        return Err(invalid_succinct_setup_proof(
            "smudging commitment set has an invalid canonical shape",
        ));
    }
    let target_role_index = TARGET_DECRYPTION_PROOF_TARGET_ROLES
        .iter()
        .position(|role| *role == target_role)
        .ok_or_else(|| invalid_succinct_setup_proof("targetRole is not canonical"))?;
    let records_per_role = records.len() / TARGET_DECRYPTION_PROOF_TARGET_ROLES.len();
    if records_per_role % smudging_polynomial_degree != 0 {
        return Err(invalid_succinct_setup_proof(
            "smudging commitment set does not contain a complete degree sequence per role and limb",
        ));
    }
    let active_limb_count = records_per_role / smudging_polynomial_degree;
    if target_rns_limb_index >= active_limb_count {
        return Err(invalid_succinct_setup_proof(
            "target RNS limb is outside the smudging commitment set",
        ));
    }
    let first_record_index = target_role_index
        .checked_mul(records_per_role)
        .and_then(|offset| {
            target_rns_limb_index
                .checked_mul(smudging_polynomial_degree)
                .and_then(|limb_offset| offset.checked_add(limb_offset))
        })
        .ok_or_else(|| invalid_succinct_setup_proof("smudging record index overflowed"))?;
    let past_last_record_index = first_record_index
        .checked_add(smudging_polynomial_degree)
        .ok_or_else(|| invalid_succinct_setup_proof("smudging record range overflowed"))?;
    let selected_records = records
        .get(first_record_index..past_last_record_index)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "smudging commitment set is missing a target-slice degree sequence",
            )
        })?;
    let mut roots = Vec::with_capacity(smudging_polynomial_degree);
    let mut commitments = Vec::with_capacity(smudging_polynomial_degree);
    for (degree_index, record) in selected_records.iter().enumerate() {
        let record_index = first_record_index + degree_index;
        if read_string(record, "objectType")? != "TargetDecryptionSmudgingCommitment" {
            return Err(invalid_succinct_setup_proof(
                "smudging commitment records must be TargetDecryptionSmudgingCommitment version 1",
            ));
        }
        let commitment_root = read_string(record, "commitmentRoot")?.to_string();
        let commitment_value = record.get("commitment").ok_or_else(|| {
            invalid_succinct_setup_proof("smudging commitment record must include a commitment")
        })?;
        let commitment = vss_share_linkage_commitment_from_value(
            commitment_value,
            VssPublicCommandCommitmentExpectation {
                field_name: format!(
                    "smudgingCommitmentSet.commitmentRecords.{record_index}.commitment"
                ),
                root: &commitment_root,
                role: TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
                rns_limb_index: target_rns_limb_index,
                rns_prime: target_rns_prime,
                ring_degree,
            },
        )?;
        roots.push(commitment_root);
        commitments.push(commitment);
    }

    Ok((roots, commitments))
}

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
            vss_committed_material_context_hashes_by_bound_message: read_string_array(
                request,
                "vssCommittedMaterialContextHashesByBoundMessage",
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
        material_roots_by_commitment_field,
    })
}

pub(super) fn key_descriptor_from_value(
    key_value: &Value,
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
