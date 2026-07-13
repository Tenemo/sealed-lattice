use super::decoding::*;
use super::share_linkage_transport::*;
use super::*;

pub(super) struct VssShareLinkageMaterialRecordStatementInput<'a> {
    pub(super) proof_statement: &'a Value,
    pub(super) statement: &'a Value,
    pub(super) statement_root: &'a str,
    pub(super) coefficient_commitment_set: &'a Value,
    pub(super) recipient_share_commitment_set: &'a Value,
    pub(super) participant_count: usize,
    pub(super) q_share_rns_limb_count: usize,
    pub(super) threshold_degree: usize,
}

pub(super) struct VssShareLinkagePublicRecordInput<'a> {
    pub(super) item: &'a Value,
    pub(super) coefficient_commitment_set: &'a Value,
    pub(super) recipient_share_commitment_set: &'a Value,
    pub(super) participant_count: usize,
    pub(super) q_share_rns_limb_count: usize,
    pub(super) threshold_degree: usize,
    pub(super) item_index: usize,
}

pub(super) fn compare_string_value(
    actual: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    if actual != expected {
        return Err(invalid_succinct_setup_proof(format!(
            "{description} must match"
        )));
    }

    Ok(())
}

pub(super) fn compare_u64_value(
    actual: u64,
    expected: u64,
    description: &str,
) -> CanonicalResult<()> {
    if actual != expected {
        return Err(invalid_succinct_setup_proof(format!(
            "{description} must match"
        )));
    }

    Ok(())
}

pub(super) fn array_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))
}

pub(super) fn vss_share_linkage_item_values(
    proof_statement: &Value,
) -> CanonicalResult<Vec<&Value>> {
    let mut items = vec![proof_statement];
    match proof_statement.get("additionalLinkageItems") {
        None => {}
        Some(Value::Array(additional_items)) => items.extend(additional_items.iter()),
        Some(_) => {
            return Err(invalid_succinct_setup_proof(
                "vssShareLinkage.additionalLinkageItems must be an array",
            ));
        }
    }

    Ok(items)
}

pub(super) fn verify_vss_share_linkage_material_record_statement(
    input: VssShareLinkageMaterialRecordStatementInput<'_>,
) -> CanonicalResult<Vec<Value>> {
    for (field_name, expected_value) in [
        (
            "publicMatrixSeedHash",
            read_string(input.statement, "publicMatrixSeedHash")?,
        ),
        ("shareLinkageStatementRoot", input.statement_root),
    ] {
        compare_string_value(
            read_string(input.proof_statement, field_name)?,
            expected_value,
            &format!("share-linkage proof statement {field_name}"),
        )?;
    }

    let items = vss_share_linkage_item_values(input.proof_statement)?;
    if items.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof statement must cover at least one item",
        ));
    }
    let mut coverage = Vec::with_capacity(items.len());
    for (item_index, &item) in items.iter().enumerate() {
        coverage.push(verify_vss_share_linkage_item_against_public_records(
            VssShareLinkagePublicRecordInput {
                item,
                coefficient_commitment_set: input.coefficient_commitment_set,
                recipient_share_commitment_set: input.recipient_share_commitment_set,
                participant_count: input.participant_count,
                q_share_rns_limb_count: input.q_share_rns_limb_count,
                threshold_degree: input.threshold_degree,
                item_index,
            },
        )?);
    }

    Ok(coverage)
}

pub(super) fn verify_vss_share_linkage_item_against_public_records(
    input: VssShareLinkagePublicRecordInput<'_>,
) -> CanonicalResult<Value> {
    let item = input.item;
    let coefficient_commitment_set = input.coefficient_commitment_set;
    let recipient_share_commitment_set = input.recipient_share_commitment_set;
    let participant_count = input.participant_count;
    let q_share_rns_limb_count = input.q_share_rns_limb_count;
    let threshold_degree = input.threshold_degree;
    let item_index = input.item_index;
    let source_roster_position = usize::try_from(read_u64(item, "sourceTrusteeRosterPosition")?)
        .map_err(|_| {
            invalid_succinct_setup_proof(
                "share-linkage item sourceTrusteeRosterPosition does not fit usize",
            )
        })?;
    let recipient_roster_position = usize::try_from(read_u64(item, "recipientRosterPosition")?)
        .map_err(|_| {
            invalid_succinct_setup_proof(
                "share-linkage item recipientRosterPosition does not fit usize",
            )
        })?;
    let source_rns_limb_index =
        usize::try_from(read_u64(item, "sourceRnsLimbIndex")?).map_err(|_| {
            invalid_succinct_setup_proof("share-linkage item sourceRnsLimbIndex does not fit usize")
        })?;
    if recipient_roster_position >= participant_count
        || source_rns_limb_index >= q_share_rns_limb_count
    {
        return Err(invalid_succinct_setup_proof(
            "share-linkage item coverage is outside the source statement dimensions",
        ));
    }
    let coefficient_source_records =
        array_field(coefficient_commitment_set, "sourceTrusteeRecords")?;
    let recipient_source_records =
        array_field(recipient_share_commitment_set, "sourceTrusteeRecords")?;
    let coefficient_source_record = coefficient_source_records
        .get(source_roster_position)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage coefficient set is missing the proof source",
            )
        })?;
    let recipient_source_record = recipient_source_records
        .get(source_roster_position)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage recipient-share set is missing the proof source",
            )
        })?;
    let source_trustee_identity = read_string(coefficient_source_record, "sourceTrusteeIdentity")?;
    compare_string_value(
        read_string(item, "sourceTrusteeIdentity")?,
        source_trustee_identity,
        "share-linkage proof item sourceTrusteeIdentity",
    )?;
    compare_string_value(
        read_string(recipient_source_record, "sourceTrusteeIdentity")?,
        source_trustee_identity,
        "share-linkage proof sourceTrusteeIdentity",
    )?;
    for source_record in [coefficient_source_record, recipient_source_record] {
        compare_u64_value(
            read_u64(source_record, "sourceTrusteeRosterPosition")?,
            source_roster_position as u64,
            "share-linkage proof sourceTrusteeRosterPosition",
        )?;
    }
    compare_string_value(
        read_string(item, "sourceCoefficientCommitmentRoot")?,
        read_string(coefficient_source_record, "sourceCoefficientCommitmentRoot")?,
        "share-linkage proof item sourceCoefficientCommitmentRoot",
    )?;
    compare_string_value(
        read_string(item, "sourceRecipientShareCommitmentRoot")?,
        read_string(
            recipient_source_record,
            "sourceRecipientShareCommitmentRoot",
        )?,
        "share-linkage proof item sourceRecipientShareCommitmentRoot",
    )?;

    let source_message_modulus = read_u64(item, "sourceMessageModulus")?;
    let coefficient_commitment_roots = read_string_array(item, "coefficientCommitmentRoots")?;
    let coefficient_commitments = array_field(item, "coefficientCommitments")?;
    if coefficient_commitment_roots.len() != threshold_degree
        || coefficient_commitments.len() != threshold_degree
    {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof item must carry one coefficient commitment per threshold coefficient",
        ));
    }
    let coefficient_records = array_field(coefficient_source_record, "coefficientCommitments")?;
    for coefficient_index in 0..threshold_degree {
        let coefficient_record_index = source_rns_limb_index
            .checked_mul(threshold_degree)
            .and_then(|offset| offset.checked_add(coefficient_index))
            .ok_or_else(|| {
                invalid_succinct_setup_proof("share-linkage coefficient record index overflowed")
            })?;
        let coefficient_record = coefficient_records
            .get(coefficient_record_index)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "share-linkage coefficient set is missing a proof item coefficient",
                )
            })?;
        compare_u64_value(
            read_u64(coefficient_record, "rnsLimbIndex")?,
            source_rns_limb_index as u64,
            "share-linkage proof coefficient rnsLimbIndex",
        )?;
        compare_u64_value(
            read_u64(coefficient_record, "rnsPrime")?,
            source_message_modulus,
            "share-linkage proof coefficient rnsPrime",
        )?;
        compare_u64_value(
            read_u64(coefficient_record, "shamirCoefficientIndex")?,
            coefficient_index as u64,
            "share-linkage proof coefficient shamirCoefficientIndex",
        )?;
        compare_string_value(
            &coefficient_commitment_roots[coefficient_index],
            read_string(coefficient_record, "coefficientCommitmentRoot")?,
            "share-linkage proof coefficientCommitmentRoot",
        )?;
        if coefficient_commitments.get(coefficient_index) != coefficient_record.get("commitment") {
            return Err(invalid_succinct_setup_proof(
                "share-linkage proof coefficient commitment body must match the public coefficient record",
            ));
        }
    }

    let recipient_records = array_field(recipient_source_record, "recipientShareCommitments")?;
    let recipient_record_index = recipient_roster_position
        .checked_mul(q_share_rns_limb_count)
        .and_then(|offset| offset.checked_add(source_rns_limb_index))
        .ok_or_else(|| {
            invalid_succinct_setup_proof("share-linkage recipient record index overflowed")
        })?;
    let recipient_record = recipient_records
        .get(recipient_record_index)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage recipient-share set is missing a proof item recipient",
            )
        })?;
    compare_string_value(
        read_string(item, "recipientIdentity")?,
        read_string(recipient_record, "recipientIdentity")?,
        "share-linkage proof recipientIdentity",
    )?;
    compare_u64_value(
        read_u64(recipient_record, "recipientRosterPosition")?,
        recipient_roster_position as u64,
        "share-linkage proof recipientRosterPosition",
    )?;
    compare_u64_value(
        read_u64(recipient_record, "rnsLimbIndex")?,
        source_rns_limb_index as u64,
        "share-linkage proof recipient rnsLimbIndex",
    )?;
    compare_u64_value(
        read_u64(recipient_record, "rnsPrime")?,
        source_message_modulus,
        "share-linkage proof recipient rnsPrime",
    )?;
    compare_string_value(
        read_string(item, "recipientShareCommitmentRoot")?,
        read_string(recipient_record, "shareCommitmentRoot")?,
        "share-linkage proof recipientShareCommitmentRoot",
    )?;
    if item.get("recipientShareCommitment") != recipient_record.get("commitment") {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof recipient-share commitment body must match the public recipient-share record",
        ));
    }

    Ok(json!({
        "sourceTrusteeRosterPosition": source_roster_position,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": source_rns_limb_index,
        "itemIndex": item_index,
    }))
}

#[cfg(test)]
pub(crate) fn verify_vss_share_linkage_proof_material_set_from_request(
    request: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<()> {
    let statement_verification =
        crate::bgv::setup::vss_commitment::verify_vss_share_linkage_bindings_request(request)?;
    verify_vss_share_linkage_proof_material_set_with_statement_verification(
        request,
        &statement_verification,
        proof_binding_session,
    )
}

pub(in crate::bgv::setup) fn verify_vss_share_linkage_statement_and_proof_material_set_from_request(
    request: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<Value> {
    let statement_verification =
        crate::bgv::setup::vss_commitment::verify_vss_share_linkage_bindings_request(request)?;
    verify_vss_share_linkage_proof_material_set_with_statement_verification(
        request,
        &statement_verification,
        proof_binding_session,
    )?;
    Ok(statement_verification)
}

fn verify_vss_share_linkage_proof_material_set_with_statement_verification(
    request: &Value,
    statement_verification: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<()> {
    let statement = request.get("statement").ok_or_else(|| {
        invalid_succinct_setup_proof("share-linkage material statement must be present")
    })?;
    let statement_root = read_string(statement_verification, "statementRoot")?;
    let participant_count = usize::try_from(read_u64(statement_verification, "participantCount")?)
        .map_err(|_| invalid_succinct_setup_proof("participantCount does not fit usize"))?;
    let q_share_rns_limb_count =
        usize::try_from(read_u64(statement_verification, "qShareRnsLimbCount")?)
            .map_err(|_| invalid_succinct_setup_proof("qShareRnsLimbCount does not fit usize"))?;
    let threshold_degree = usize::try_from(read_u64(statement_verification, "thresholdDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("thresholdDegree does not fit usize"))?;
    let coefficient_commitment_set = request.get("coefficientCommitmentSet").ok_or_else(|| {
        invalid_succinct_setup_proof(
            "share-linkage material coefficientCommitmentSet must be present",
        )
    })?;
    let recipient_share_commitment_set =
        request.get("recipientShareCommitmentSet").ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage material recipientShareCommitmentSet must be present",
            )
        })?;
    let ring_degree = crate::bgv::parameters::POLYNOMIAL_DEGREE;
    let proof_material_set = request.get("proofMaterialSet").ok_or_else(|| {
        invalid_succinct_setup_proof("share-linkage proofMaterialSet must be present")
    })?;

    compare_string_value(
        read_string(proof_material_set, "objectType")?,
        "VssShareLinkageProofMaterialSet",
        "share-linkage proof material set objectType",
    )?;

    let proof_records = proof_material_set
        .get("proofRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage proof material set proofRecords must be an array",
            )
        })?;
    if proof_records.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof material set must contain proof records",
        ));
    }
    let mut covered_items = BTreeSet::new();
    for (proof_record_index, proof_record) in proof_records.iter().enumerate() {
        compare_string_value(
            read_string(proof_record, "objectType")?,
            "VssShareLinkageProofRecord",
            "share-linkage proof record objectType",
        )?;
        let vss_share_linkage = proof_record.get("vssShareLinkage").ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage proof record vssShareLinkage must be present",
            )
        })?;
        let coverage = verify_vss_share_linkage_material_record_statement(
            VssShareLinkageMaterialRecordStatementInput {
                proof_statement: vss_share_linkage,
                statement,
                statement_root,
                coefficient_commitment_set,
                recipient_share_commitment_set,
                participant_count,
                q_share_rns_limb_count,
                threshold_degree,
            },
        )?;
        for coverage_item in &coverage {
            let source_roster_position =
                usize::try_from(read_u64(coverage_item, "sourceTrusteeRosterPosition")?).map_err(
                    |_| {
                        invalid_succinct_setup_proof(
                            "share-linkage coverage sourceTrusteeRosterPosition does not fit usize",
                        )
                    },
                )?;
            let recipient_roster_position =
                usize::try_from(read_u64(coverage_item, "recipientRosterPosition")?).map_err(
                    |_| {
                        invalid_succinct_setup_proof(
                            "share-linkage coverage recipientRosterPosition does not fit usize",
                        )
                    },
                )?;
            let source_rns_limb_index =
                usize::try_from(read_u64(coverage_item, "sourceRnsLimbIndex")?).map_err(|_| {
                    invalid_succinct_setup_proof(
                        "share-linkage coverage sourceRnsLimbIndex does not fit usize",
                    )
                })?;
            if !covered_items.insert((
                source_roster_position,
                recipient_roster_position,
                source_rns_limb_index,
            )) {
                return Err(invalid_succinct_setup_proof(
                    "share-linkage proof material set repeats a source recipient-limb item",
                ));
            }
        }

        let validated_proof_reference = validate_vss_share_linkage_proof_reference(proof_record)?;
        let proof_request = json!({
            "context": {
                "setupContextHash": read_string(statement, "setupContextHash")?,
                "trusteeIdentity": "vss-share-linkage",
                "trusteeRosterPosition": 0,
                "shareLinkageStatementRoot": statement_root,
            },
            "ringDegree": ring_degree,
            "vssShareLinkage": vss_share_linkage,
        });
        let verification_binding_hash = vss_share_linkage_proof_verification_binding_hash(
            &validated_proof_reference.proof_material_root,
            &proof_request,
        )?;
        let proof_material_root = validated_proof_reference.proof_material_root.clone();
        let proof_binding_was_consumed = match proof_binding_session {
            Some(proof_binding_session) => crate::bgv::setup::consume_accepted_setup_proof_binding(
                proof_binding_session.session_handle,
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                &proof_material_root,
                &verification_binding_hash,
            )?,
            None => false,
        };
        if !proof_binding_was_consumed {
            let resolved_proof_bytes = resolve_vss_share_linkage_proof_bytes(
                validated_proof_reference,
                proof_binding_session,
            )?;
            verify_vss_share_linkage_proof_source_from_request(
                &proof_request,
                resolved_proof_bytes.proof_bytes.as_ref(),
            )
            .map_err(|error| {
                CanonicalError::new(
                    error.code,
                    format!(
                        "share-linkage proof record {proof_record_index} did not verify: {}",
                        error.message
                    ),
                )
            })?;
        }
    }

    let expected_coverage_count = participant_count
        .checked_mul(participant_count)
        .and_then(|count| count.checked_mul(q_share_rns_limb_count))
        .ok_or_else(|| invalid_succinct_setup_proof("share-linkage coverage count overflowed"))?;
    if covered_items.len() != expected_coverage_count {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof material set must cover every source, recipient, and Q_share limb exactly once",
        ));
    }
    for source_roster_position in 0..participant_count {
        for recipient_roster_position in 0..participant_count {
            for source_rns_limb_index in 0..q_share_rns_limb_count {
                if !covered_items.contains(&(
                    source_roster_position,
                    recipient_roster_position,
                    source_rns_limb_index,
                )) {
                    return Err(invalid_succinct_setup_proof(
                        "share-linkage proof material set is missing a source recipient-limb item",
                    ));
                }
            }
        }
    }

    Ok(())
}
