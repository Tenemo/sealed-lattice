use super::reconstructed::*;
use super::*;

pub(super) fn verify_statement_record(
    input: StatementRecordVerificationInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.statement_record, &["objectType"])?,
        "VssSameSecretBridgeStatement",
        "VSS same-secret bridge statement objectType",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["proofFamily"])?,
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "VSS same-secret bridge statement proofFamily",
    )?;
    compare_setup_context(input.statement_record, input.statement_set)?;
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
    let source_constant_commitments = super::super::source_constant_commitments::canonical_source_constant_commitments_from_bridge_statement(
        input.vss_coefficient_commitments,
        input.statement_record,
        trustee_identity,
        input.expected_position as u64,
        input.statement_set.public_matrix_seed_hash,
        input.ring_degree,
    )?;
    let verified_source_constant_commitments = source_constant_commitments
        .commitment_values
        .iter()
        .enumerate()
        .map(|(source_rns_limb_index, commitment)| {
            json!({
                "rnsLimbIndex": source_rns_limb_index,
                "rnsPrime": DATA_PRIMES[source_rns_limb_index],
                "shamirCoefficientIndex": 0,
                "commitment": commitment,
            })
        })
        .collect::<Vec<_>>();
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
        string_at_path(input.statement_record, &["qShareLimbOrder"])?,
        VSS_SAME_SECRET_BRIDGE_Q_SHARE_LIMB_ORDER,
        "VSS same-secret bridge statement qShareLimbOrder",
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
    if target_constant_roots.len() != input.q_share_rns_limb_count
        || target_constant_commitments.len() != input.q_share_rns_limb_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS same-secret bridge statement must bind one target constant root and commitment per target RNS limb",
        ));
    }
    let authoritative_source_records =
        array_at_path(input.coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    let authoritative_source_record = authoritative_source_records
        .get(input.expected_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "authoritative VSS coefficient commitments do not cover the bridge trustee",
            )
        })?;
    compare_required_string(
        string_at_path(authoritative_source_record, &["objectType"])?,
        "VssPublicSourceCoefficientCommitments",
        "authoritative bridge target source record objectType",
    )?;
    compare_required_string(
        string_at_path(authoritative_source_record, &["sourceTrusteeIdentity"])?,
        trustee_identity,
        "authoritative bridge target source trustee identity",
    )?;
    compare_required_u64(
        unsigned_at_path(
            authoritative_source_record,
            &["sourceTrusteeRosterPosition"],
        )?,
        input.expected_position as u64,
        "authoritative bridge target source trustee roster position",
    )?;
    compare_required_string(
        hash_at_path(authoritative_source_record, &["publicMatrixSeedHash"])?,
        input.statement_set.public_matrix_seed_hash,
        "authoritative bridge target source publicMatrixSeedHash",
    )?;
    let authoritative_coefficient_records =
        array_at_path(authoritative_source_record, &["coefficientCommitments"])?;
    let expected_authoritative_record_count = input
        .q_share_rns_limb_count
        .checked_mul(input.threshold_degree)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "authoritative bridge target coordinate count overflowed",
            )
        })?;
    if authoritative_coefficient_records.len() != expected_authoritative_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "authoritative VSS coefficient commitments must cover every bridge target coordinate",
        ));
    }
    let mut verified_target_constant_commitments = Vec::with_capacity(input.q_share_rns_limb_count);
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
            let authoritative_record_index = expected_rns_limb_index
                .checked_mul(input.threshold_degree)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "authoritative bridge target record index overflowed",
                    )
                })?;
            let authoritative_record = authoritative_coefficient_records
                .get(authoritative_record_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "authoritative VSS coefficient commitment is missing for a bridge target limb",
                    )
                })?;
            compare_required_string(
                string_at_path(authoritative_record, &["objectType"])?,
                "VssPublicCoefficientCommitment",
                "authoritative bridge target commitment objectType",
            )?;
            compare_required_string(
                string_at_path(authoritative_record, &["sourceTrusteeIdentity"])?,
                trustee_identity,
                "authoritative bridge target commitment trustee identity",
            )?;
            compare_required_u64(
                unsigned_at_path(
                    authoritative_record,
                    &["sourceTrusteeRosterPosition"],
                )?,
                input.expected_position as u64,
                "authoritative bridge target commitment trustee roster position",
            )?;
            compare_required_string(
                hash_at_path(authoritative_record, &["publicMatrixSeedHash"])?,
                input.statement_set.public_matrix_seed_hash,
                "authoritative bridge target commitment publicMatrixSeedHash",
            )?;
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
            let canonical_target_prime = DATA_PRIMES
                .get(expected_rns_limb_index)
                .copied()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS same-secret bridge qShareRnsLimbCount exceeds the available Q_share primes",
                    )
                })?;
            compare_required_u64(
                rns_prime,
                canonical_target_prime,
                "VSS same-secret bridge target constant rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(root_record, &["shamirCoefficientIndex"])?,
                0,
                "VSS same-secret bridge target constant shamirCoefficientIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(authoritative_record, &["rnsLimbIndex"])?,
                expected_rns_limb_index as u64,
                "authoritative bridge target commitment rnsLimbIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(authoritative_record, &["rnsPrime"])?,
                rns_prime,
                "authoritative bridge target commitment rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(authoritative_record, &["shamirCoefficientIndex"])?,
                0,
                "authoritative bridge target commitment shamirCoefficientIndex",
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
            let authoritative_commitment_root =
                hash_at_path(authoritative_record, &["coefficientCommitmentRoot"])?;
            compare_required_string(
                coefficient_commitment_root,
                authoritative_commitment_root,
                "same-secret bridge target root must match the authoritative VSS coefficient commitment",
            )?;
            let commitment_body = value_at_path(commitment_record, &["commitment"])?;
            let authoritative_commitment_body =
                value_at_path(authoritative_record, &["commitment"])?;
            if commitment_body != authoritative_commitment_body {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "same-secret bridge target body must equal the authoritative VSS coefficient commitment body",
                ));
            }
            compare_required_string(
                string_at_path(commitment_body, &["objectType"])?,
                "VssCommittedMaterialCommitment",
                "VSS same-secret bridge target constant commitment objectType",
            )?;
            compare_required_string(
                string_at_path(commitment_body, &["commitmentRole"])?,
                "coefficient",
                "VSS same-secret bridge target constant commitment role",
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
                "commitment": authoritative_commitment_body,
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
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": input.statement_set.ceremony_id,
        "manifestHash": input.statement_set.manifest_hash,
        "rosterHash": input.statement_set.roster_hash,
        "setupParametersHash": input.statement_set.setup_parameters_hash,
        "setupEpoch": input.statement_set.setup_epoch,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "ringDegree": input.ring_degree,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "qShareLimbOrder": VSS_SAME_SECRET_BRIDGE_Q_SHARE_LIMB_ORDER,
        "sourceConstantCoefficientCommitments": verified_source_constant_commitments,
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
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": input.statement_set.ceremony_id,
        "manifestHash": input.statement_set.manifest_hash,
        "rosterHash": input.statement_set.roster_hash,
        "setupParametersHash": input.statement_set.setup_parameters_hash,
        "setupEpoch": input.statement_set.setup_epoch,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "ringDegree": input.ring_degree,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "qShareLimbOrder": VSS_SAME_SECRET_BRIDGE_Q_SHARE_LIMB_ORDER,
        "sourceConstantCoefficientCommitments": verified_source_constant_commitments,
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
