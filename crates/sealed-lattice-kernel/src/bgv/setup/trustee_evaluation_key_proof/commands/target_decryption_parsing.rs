use super::decoding::*;
use super::request_parsing::*;
use super::*;

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
    if context.binding_roots[0].1 != target_share_proof_statement_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the target share proof statement root",
        ));
    }

    let public_matrix_seed_hash = read_string(target_value, "publicMatrixSeedHash")?.to_string();
    let target_basis_hash = read_string(target_value, "targetBasisHash")?.to_string();
    let trustee_identity = read_string(target_value, "trusteeIdentity")?.to_string();
    let trustee_roster_position = read_u64(target_value, "trusteeRosterPosition")?;
    let smudging_commitment_set = target_value
        .get("smudgingCommitmentSet")
        .ok_or_else(|| invalid_succinct_setup_proof("smudgingCommitmentSet must be present"))?;
    let smudging_commitment_set_root =
        validated_target_decryption_smudging_commitment_set_root(smudging_commitment_set)?;
    if context.binding_roots[2].1 != smudging_commitment_set_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the smudging commitment set root",
        ));
    }
    if read_string(smudging_commitment_set, "publicMatrixSeedHash")? != public_matrix_seed_hash
        || read_string(smudging_commitment_set, "targetBasisHash")? != target_basis_hash
        || read_u64(smudging_commitment_set, "ringDegree")? != ring_degree as u64
        || read_string(smudging_commitment_set, "commitmentRole")?
            != TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE
    {
        return Err(invalid_succinct_setup_proof(
            "smudging commitment set metadata must match the target-decryption share statement",
        ));
    }
    let smudging_active_limb_count =
        usize::try_from(read_u64(smudging_commitment_set, "activeRnsLimbCount")?)
            .map_err(|_| invalid_succinct_setup_proof("activeRnsLimbCount does not fit usize"))?;
    let smudging_polynomial_degree = usize::try_from(read_u64(
        smudging_commitment_set,
        "smudgingPolynomialDegree",
    )?)
    .map_err(|_| invalid_succinct_setup_proof("smudgingPolynomialDegree does not fit usize"))?;
    let smudging_coefficient_bound = read_i64(smudging_commitment_set, "smudgingCoefficientBound")?;
    let smudging_signed_coefficient_offset =
        read_i64(smudging_commitment_set, "signedCoefficientOffset")?;
    let smudging_message_coefficient_bound =
        read_u64(smudging_commitment_set, "messageCoefficientBound")?;
    let active_credential_binding_root =
        read_string(target_value, "activeCredentialBindingRoot")?.to_string();
    if context.binding_roots[1].1 != active_credential_binding_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the active aggregate credential binding root",
        ));
    }
    let limb_statements = target_decryption_share_limb_statements_from_request(
        target_value,
        smudging_commitment_set,
        &public_matrix_seed_hash,
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
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        vss_share_linkage: None,
        same_secret_bridge: None,
        target_decryption_share: Some(TargetDecryptionShareStatement {
            public_matrix_seed_hash,
            target_basis_hash,
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

#[cfg(test)]
pub(crate) fn describe_target_decryption_share_proof_layout_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = target_decryption_share_statement_from_request(request)?;
    let target_statement = statement.target_decryption_share.as_ref().ok_or_else(|| {
        invalid_succinct_setup_proof("target-decryption share statement must be present")
    })?;
    let proof_limb_indices = statement.proof_limb_indices();
    let mut limb_summaries = Vec::with_capacity(proof_limb_indices.len());
    for proof_limb_index in &proof_limb_indices {
        let layout = LimbColumnLayout::new(&statement, *proof_limb_index)?;
        let mut message_summaries = Vec::with_capacity(layout.target_decryption_message_columns);
        for local_message_index in 0..layout.target_decryption_message_columns {
            let global_message_index = statement
                .target_decryption_message_global_index(*proof_limb_index, local_message_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption layout message index is outside the statement",
                    )
                })?;
            let claim_kind = match statement
                .target_decryption_message_claim_kind(global_message_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption layout message claim kind is missing",
                    )
                })? {
                TargetDecryptionMessageClaimKind::AggregateOpening => "aggregateOpening",
                TargetDecryptionMessageClaimKind::SmudgingOpening => "smudgingOpening",
            };
            let message_bound = statement
                .target_decryption_message_bound(global_message_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption layout message bound is missing",
                    )
                })?;
            let low_digit_trit_count =
                layout.target_decryption_message_trit_count(local_message_index, 0);
            let high_digit_trit_count =
                layout.target_decryption_message_trit_count(local_message_index, 1);
            let total_trit_count = low_digit_trit_count + high_digit_trit_count;
            message_summaries.push(json!({
                "localMessageIndex": local_message_index,
                "globalMessageIndex": global_message_index,
                "claimKind": claim_kind,
                "messageBound": message_bound,
                "encodingColumnCount": crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT + total_trit_count,
                "lowDigitTritCount": low_digit_trit_count,
                "highDigitTritCount": high_digit_trit_count,
                "totalTritCount": total_trit_count,
            }));
        }
        limb_summaries.push(json!({
            "proofLimbIndex": proof_limb_index,
            "traceSize": layout.trace_size,
            "targetDecryptionMessageColumns": layout.target_decryption_message_columns,
            "targetDecryptionRandomnessColumns": layout.target_decryption_randomness_columns,
            "targetDecryptionMessageEncodingColumns": layout.target_decryption_message_encoding_columns(),
            "claimCount": layout.claim_count(),
            "maskColumnCount": layout.mask_column_count,
            "phaseOnePhysicalColumnCount": layout.phase_one_physical_count(),
            "totalColumnCount": layout.phase_one_physical_count() + PHASE_TWO_COLUMN_COUNT,
            "messages": message_summaries,
        }));
    }

    Ok(json!({
        "objectType": "BgvTargetDecryptionShareProofLayoutDescription",
        "objectVersion": 1,
        "ringDegree": statement.ring_degree,
        "proofLimbIndices": proof_limb_indices,
        "aggregateMessageCoefficientBound": target_statement.aggregate_message_coefficient_bound,
        "smudgingMessageCoefficientBound": target_statement.smudging_message_coefficient_bound,
        "totalMessageCount": statement.target_decryption_total_message_count(),
        "totalMessageDigitCount": statement.target_decryption_total_message_digit_count(),
        "limbs": limb_summaries,
    }))
}

pub(super) fn target_decryption_share_limb_statements_from_request(
    target_value: &Value,
    smudging_commitment_set: &Value,
    public_matrix_seed_hash: &str,
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
                public_matrix_seed_hash,
                ring_degree,
                smudging_polynomial_degree,
            )
        })
        .collect()
}

pub(super) fn target_decryption_share_limb_statement_from_value(
    limb_statement_value: &Value,
    smudging_commitment_set: &Value,
    public_matrix_seed_hash: &str,
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
            public_matrix_seed_hash,
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
        public_matrix_seed_hash,
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
    public_matrix_seed_hash: &str,
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
                public_matrix_seed_hash,
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
    public_matrix_seed_hash: &str,
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
            public_matrix_seed_hash,
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
        || read_u64(smudging_commitment_set, "objectVersion")? != 1
    {
        return Err(invalid_succinct_setup_proof(
            "smudgingCommitmentSet must be TargetDecryptionSmudgingCommitmentSet version 1",
        ));
    }
    let root = read_string(smudging_commitment_set, "smudgingCommitmentSetRoot")?;
    let mut without_root = smudging_commitment_set.clone();
    without_root
        .as_object_mut()
        .ok_or_else(|| invalid_succinct_setup_proof("smudgingCommitmentSet must be an object"))?
        .remove("smudgingCommitmentSetRoot")
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet must include its root")
        })?;
    let expected_root = derive_canonical_object_hash(&without_root)?;
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
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<(Vec<String>, Vec<VssShareLinkageCommitment>)> {
    let records = smudging_commitment_set
        .get("commitmentRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet.commitmentRecords must be an array")
        })?;
    let mut roots_by_degree = vec![None; smudging_polynomial_degree];
    let mut commitments_by_degree = vec![None; smudging_polynomial_degree];

    for (record_index, record) in records.iter().enumerate() {
        if read_string(record, "objectType")? != "TargetDecryptionSmudgingCommitment"
            || read_u64(record, "objectVersion")? != 1
        {
            return Err(invalid_succinct_setup_proof(
                "smudging commitment records must be TargetDecryptionSmudgingCommitment version 1",
            ));
        }
        let record_role = read_string(record, "role")?;
        let record_limb_index = usize::try_from(read_u64(record, "rnsLimbIndex")?)
            .map_err(|_| invalid_succinct_setup_proof("rnsLimbIndex does not fit usize"))?;
        let record_rns_prime = read_u64(record, "rnsPrime")?;
        let polynomial_degree = usize::try_from(read_u64(record, "polynomialDegree")?)
            .map_err(|_| invalid_succinct_setup_proof("polynomialDegree does not fit usize"))?;
        if record_role != target_role
            || record_limb_index != target_rns_limb_index
            || record_rns_prime != target_rns_prime
        {
            continue;
        }
        if polynomial_degree == 0 || polynomial_degree > smudging_polynomial_degree {
            return Err(invalid_succinct_setup_proof(
                "smudging commitment record polynomial degree is outside the statement range",
            ));
        }
        let degree_index = polynomial_degree - 1;
        if roots_by_degree[degree_index].is_some() {
            return Err(invalid_succinct_setup_proof(
                "smudging commitment set has duplicate records for the target slice",
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
                public_matrix_seed_hash,
                rns_limb_index: target_rns_limb_index,
                rns_prime: target_rns_prime,
                ring_degree,
            },
        )?;
        roots_by_degree[degree_index] = Some(commitment_root);
        commitments_by_degree[degree_index] = Some(commitment);
    }

    let roots = roots_by_degree
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "smudging commitment set is missing a target-slice polynomial degree",
            )
        })?;
    let commitments = commitments_by_degree
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "smudging commitment set is missing a target-slice commitment",
            )
        })?;

    Ok((roots, commitments))
}

#[cfg(any(test, feature = "target-decryption-development-commands"))]
pub(super) fn target_decryption_share_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    Ok(TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        vss_public_coefficient_messages_by_shamir_index: Vec::new(),
        vss_public_recipient_share_messages: Vec::new(),
        vss_public_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        vss_public_recipient_share_opening_randomness: Vec::new(),
        vss_public_carry_witnesses: Vec::new(),
        vss_public_recipient_share_messages_by_item: Vec::new(),
        vss_public_recipient_share_opening_randomness_by_item: Vec::new(),
        vss_public_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors: read_i64_matrix2(
            request,
            "targetDecryptionMessageVectors",
        )?,
        target_decryption_opening_randomness_by_commitment: read_i64_matrix(
            request,
            "targetDecryptionOpeningRandomnessByCommitment",
        )?,
    })
}

pub(in crate::bgv::setup) fn vss_share_linkage_commitment_from_value(
    value: &Value,
    expected: VssPublicCommandCommitmentExpectation<'_>,
) -> CanonicalResult<VssShareLinkageCommitment> {
    if read_string(value, "objectType")? != "VssPublicCommitment" {
        return Err(invalid_succinct_setup_proof(format!(
            "{}.objectType must be VssPublicCommitment",
            expected.field_name
        )));
    }
    if read_u64(value, "outputCoordinateCount")? != VSS_PUBLIC_OUTPUT_COORDINATE_COUNT as u64
        || read_u64(value, "randomnessColumnCount")? != VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT as u64
    {
        return Err(invalid_succinct_setup_proof(format!(
            "{} commitment shape does not match the parameters",
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
        || read_string(value, "publicMatrixSeedHash")? != expected.public_matrix_seed_hash
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

    let limbs = value
        .get("commitmentLimbs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{}.commitmentLimbs must be an array",
                expected.field_name
            ))
        })?;
    if limbs.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(invalid_succinct_setup_proof(format!(
            "{}.commitmentLimbs must cover the commitment fields",
            expected.field_name
        )));
    }
    let mut coordinates_by_commitment_modulus = Vec::with_capacity(limbs.len());
    for (expected_limb_index, limb) in limbs.iter().enumerate() {
        if read_u64(limb, "commitmentModulusIndex")? != expected_limb_index as u64 {
            return Err(invalid_succinct_setup_proof(format!(
                "{}.commitmentLimbs must be ordered by commitmentModulusIndex",
                expected.field_name
            )));
        }
        let expected_modulus = DATA_PRIMES[expected_limb_index];
        if read_u64(limb, "modulus")? != expected_modulus {
            return Err(invalid_succinct_setup_proof(format!(
                "{}.commitmentLimbs modulus must match the commitment field",
                expected.field_name
            )));
        }
        let coordinates = limb
            .get("coordinates")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(format!(
                    "{}.commitmentLimbs coordinates must be arrays",
                    expected.field_name
                ))
            })?
            .iter()
            .map(|entry| {
                entry.as_u64().ok_or_else(|| {
                    invalid_succinct_setup_proof(format!(
                        "{}.commitmentLimbs coordinates must be non-negative integers",
                        expected.field_name
                    ))
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        coordinates_by_commitment_modulus.push(coordinates);
    }

    Ok(VssShareLinkageCommitment {
        coordinates_by_commitment_modulus,
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
