use super::*;
use super::reconstructed::*;

pub(super) fn verify_statement_record(input: StatementRecordVerificationInput<'_>) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.statement_record, &["objectType"])?,
        "VssSameSecretBridgeStatement",
        "VSS same-secret bridge statement objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["objectVersion"])?,
        1,
        "VSS same-secret bridge statement objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["proofFamily"])?,
        SAME_SECRET_PROOF_FAMILY,
        "VSS same-secret bridge statement proofFamily",
    )?;
    compare_setup_context(input.statement_record, input.statement_set)?;
    compare_required_string(
        hash_at_path(input.statement_record, &["targetBasisHash"])?,
        input.statement_set.target_basis_hash,
        "VSS same-secret bridge statement targetBasisHash",
    )?;
    compare_required_string(
        hash_at_path(input.statement_record, &["publicMatrixSeedHash"])?,
        input.statement_set.public_matrix_seed_hash,
        "VSS same-secret bridge statement publicMatrixSeedHash",
    )?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["ringDegree"])?,
        input.ring_degree as u64,
        "VSS same-secret bridge statement ringDegree",
    )?;

    let trustee_identity = read_non_empty_string(input.statement_record, "trusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["trusteeRosterPosition"])?,
        input.expected_position as u64,
        "VSS same-secret bridge statement trusteeRosterPosition",
    )?;
    let same_secret_statement_root =
        hash_at_path(input.statement_record, &["sameSecretStatementRoot"])?;
    let same_secret_proof_root = hash_at_path(input.statement_record, &["sameSecretProofRoot"])?;
    let trustee_secret_commitment_root =
        hash_at_path(input.statement_record, &["trusteeSecretCommitmentRoot"])?;
    let same_secret_proof_family_binding_root = hash_at_path(
        input.statement_record,
        &["sameSecretProofFamilyBindingRoot"],
    )?;
    compare_required_string(
        same_secret_proof_family_binding_root,
        input.statement_set.same_secret_proof_family_binding_root,
        "VSS same-secret bridge statement sameSecretProofFamilyBindingRoot",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["dataBasisRelation"])?,
        SAME_SECRET_RELATION,
        "VSS same-secret bridge statement dataBasisRelation",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["integerSupport"])?,
        VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "VSS same-secret bridge statement integerSupport",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["signedRepresentativeConvention"])?,
        VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "VSS same-secret bridge statement signedRepresentativeConvention",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["vssPublicCommitmentEncoding"])?,
        VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "VSS same-secret bridge statement vssPublicCommitmentEncoding",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["targetBasisLimbOrder"])?,
        VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "VSS same-secret bridge statement targetBasisLimbOrder",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["relation"])?,
        VSS_SAME_SECRET_BRIDGE_RELATION,
        "VSS same-secret bridge statement relation",
    )?;

    let target_constant_roots = array_at_path(
        input.statement_record,
        &["targetConstantCoefficientCommitmentRoots"],
    )?;
    let target_constant_commitments = array_at_path(
        input.statement_record,
        &["targetConstantCoefficientCommitments"],
    )?;
    if target_constant_roots.len() != input.target_rns_limb_count
        || target_constant_commitments.len() != input.target_rns_limb_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS same-secret bridge statement must bind one target constant root and commitment per target RNS limb",
        ));
    }
    let mut verified_target_constant_commitments = Vec::with_capacity(input.target_rns_limb_count);
    let verified_target_constant_roots = target_constant_roots
        .iter()
        .enumerate()
        .map(|(expected_rns_limb_index, root_record)| {
            let commitment_record = target_constant_commitments
                .get(expected_rns_limb_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS same-secret bridge target constant commitment is missing",
                    )
                })?;
            let rns_limb_index = unsigned_at_path(root_record, &["rnsLimbIndex"])?;
            compare_required_u64(
                rns_limb_index,
                expected_rns_limb_index as u64,
                "VSS same-secret bridge target constant rnsLimbIndex",
            )?;
            let rns_prime = read_positive_u64_at_path(
                root_record,
                &["rnsPrime"],
                "VSS same-secret bridge target constant rnsPrime",
            )?;
            compare_required_u64(
                rns_prime,
                DATA_PRIMES[expected_rns_limb_index],
                "VSS same-secret bridge target constant rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(root_record, &["shamirCoefficientIndex"])?,
                0,
                "VSS same-secret bridge target constant shamirCoefficientIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_record, &["rnsLimbIndex"])?,
                expected_rns_limb_index as u64,
                "VSS same-secret bridge target constant commitment rnsLimbIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_record, &["rnsPrime"])?,
                rns_prime,
                "VSS same-secret bridge target constant commitment rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_record, &["shamirCoefficientIndex"])?,
                0,
                "VSS same-secret bridge target constant commitment shamirCoefficientIndex",
            )?;
            let coefficient_commitment_root =
                hash_at_path(root_record, &["coefficientCommitmentRoot"])?;
            let commitment_body = value_at_path(commitment_record, &["commitment"])?;
            compare_required_string(
                string_at_path(commitment_body, &["objectType"])?,
                "VssPublicCommitment",
                "VSS same-secret bridge target constant commitment objectType",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["objectVersion"])?,
                1,
                "VSS same-secret bridge target constant commitment objectVersion",
            )?;
            compare_required_string(
                string_at_path(commitment_body, &["commitmentRole"])?,
                "coefficient",
                "VSS same-secret bridge target constant commitment role",
            )?;
            compare_required_string(
                hash_at_path(commitment_body, &["publicMatrixSeedHash"])?,
                input.statement_set.public_matrix_seed_hash,
                "VSS same-secret bridge target constant commitment publicMatrixSeedHash",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["rnsLimbIndex"])?,
                expected_rns_limb_index as u64,
                "VSS same-secret bridge target constant commitment body rnsLimbIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["rnsPrime"])?,
                rns_prime,
                "VSS same-secret bridge target constant commitment body rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["ringDegree"])?,
                input.ring_degree as u64,
                "VSS same-secret bridge target constant commitment ringDegree",
            )?;
            compare_required_string(
                &derive_canonical_object_hash(commitment_body)?,
                coefficient_commitment_root,
                "VSS same-secret bridge target constant commitment body root",
            )?;
            verified_target_constant_commitments.push(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": 0,
                "commitment": commitment_body,
            }));

            Ok(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": 0,
                "coefficientCommitmentRoot": coefficient_commitment_root,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let expected_statement_root = derive_canonical_object_hash(&json!({
        "objectType": "VssSameSecretBridgeStatement",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": input.statement_set.ceremony_id,
        "manifestHash": input.statement_set.manifest_hash,
        "rosterHash": input.statement_set.roster_hash,
        "setupParametersHash": input.statement_set.setup_parameters_hash,
        "setupEpoch": input.statement_set.setup_epoch,
        "targetBasisHash": input.statement_set.target_basis_hash,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "ringDegree": input.ring_degree,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "sameSecretStatementRoot": same_secret_statement_root,
        "sameSecretProofRoot": same_secret_proof_root,
        "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "targetConstantCoefficientCommitmentRoots": verified_target_constant_roots,
        "targetConstantCoefficientCommitments": verified_target_constant_commitments,
        "relation": VSS_SAME_SECRET_BRIDGE_RELATION,
    }))?;
    let statement_root = hash_at_path(input.statement_record, &["sameSecretBridgeStatementRoot"])?;
    if expected_statement_root != statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "VSS same-secret bridge statement root does not match its bound roots: expected {expected_statement_root}, got {statement_root}",
            ),
        ));
    }

    Ok(json!({
        "objectType": "VssSameSecretBridgeStatement",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": input.statement_set.ceremony_id,
        "manifestHash": input.statement_set.manifest_hash,
        "rosterHash": input.statement_set.roster_hash,
        "setupParametersHash": input.statement_set.setup_parameters_hash,
        "setupEpoch": input.statement_set.setup_epoch,
        "targetBasisHash": input.statement_set.target_basis_hash,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "ringDegree": input.ring_degree,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "sameSecretStatementRoot": same_secret_statement_root,
        "sameSecretProofRoot": same_secret_proof_root,
        "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "targetConstantCoefficientCommitmentRoots": verified_target_constant_roots,
        "targetConstantCoefficientCommitments": verified_target_constant_commitments,
        "relation": VSS_SAME_SECRET_BRIDGE_RELATION,
        "sameSecretBridgeStatementRoot": statement_root,
    }))
}

pub(super) fn compare_setup_context(
    statement_record: &Value,
    statement_set: StatementSetBinding<'_>,
) -> CanonicalResult<()> {
    for field_name in SETUP_CONTEXT_FIELD_NAMES {
        let expected = match field_name {
            "ceremonyId" => statement_set.ceremony_id,
            "manifestHash" => statement_set.manifest_hash,
            "rosterHash" => statement_set.roster_hash,
            "setupParametersHash" => statement_set.setup_parameters_hash,
            "setupEpoch" => statement_set.setup_epoch,
            _ => unreachable!("unknown same-secret setup context field"),
        };
        let actual = if field_name == "ceremonyId" || field_name == "setupEpoch" {
            string_at_path(statement_record, &[field_name])?
        } else {
            hash_at_path(statement_record, &[field_name])?
        };
        compare_required_string(
            actual,
            expected,
            "VSS same-secret bridge statement setup context",
        )?;
    }

    Ok(())
}

pub(super) fn compare_evidence_context(
    evidence_set: &Value,
    statement_set: StatementSetBinding<'_>,
    description: &str,
) -> CanonicalResult<()> {
    for field_name in SETUP_CONTEXT_FIELD_NAMES {
        let expected = match field_name {
            "ceremonyId" => statement_set.ceremony_id,
            "manifestHash" => statement_set.manifest_hash,
            "rosterHash" => statement_set.roster_hash,
            "setupParametersHash" => statement_set.setup_parameters_hash,
            "setupEpoch" => statement_set.setup_epoch,
            _ => unreachable!("unknown same-secret setup context field"),
        };
        let actual = if field_name == "ceremonyId" || field_name == "setupEpoch" {
            string_at_path(evidence_set, &[field_name])?
        } else {
            hash_at_path(evidence_set, &[field_name])?
        };
        compare_required_string(actual, expected, &format!("{description} setup context"))?;
    }

    Ok(())
}

pub(super) fn value_without_root_field(
    value: &Value,
    root_field_name: &str,
    description: &str,
) -> CanonicalResult<Value> {
    let object = value.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be a JSON object"),
        )
    })?;
    if !object.contains_key(root_field_name) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must include {root_field_name}"),
        ));
    }
    let mut object_without_root = object.clone();
    object_without_root.remove(root_field_name);

    Ok(Value::Object(object_without_root))
}

pub(super) fn read_positive_usize_at_path(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<usize> {
    let field = usize_at_path(value, path)?;
    if field == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be positive"),
        ));
    }

    Ok(field)
}

pub(super) fn read_positive_u64_at_path(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<u64> {
    let field = unsigned_at_path(value, path)?;
    if field == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be positive"),
        ));
    }

    Ok(field)
}

pub(super) fn compare_required_u64(actual: u64, expected: u64, description: &str) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("passive BGV setup package {description} does not match its canonical binding"),
        ));
    }

    Ok(())
}

