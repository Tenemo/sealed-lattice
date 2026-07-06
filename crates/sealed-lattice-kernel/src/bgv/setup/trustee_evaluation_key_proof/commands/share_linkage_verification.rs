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
    pub(super) target_rns_limb_count: usize,
    pub(super) threshold_degree: usize,
}

pub(super) struct VssShareLinkagePublicRecordInput<'a> {
    pub(super) item: &'a Value,
    pub(super) statement: &'a Value,
    pub(super) coefficient_commitment_set: &'a Value,
    pub(super) recipient_share_commitment_set: &'a Value,
    pub(super) participant_count: usize,
    pub(super) target_rns_limb_count: usize,
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
                statement: input.statement,
                coefficient_commitment_set: input.coefficient_commitment_set,
                recipient_share_commitment_set: input.recipient_share_commitment_set,
                participant_count: input.participant_count,
                target_rns_limb_count: input.target_rns_limb_count,
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
    let statement = input.statement;
    let coefficient_commitment_set = input.coefficient_commitment_set;
    let recipient_share_commitment_set = input.recipient_share_commitment_set;
    let participant_count = input.participant_count;
    let target_rns_limb_count = input.target_rns_limb_count;
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
        || source_rns_limb_index >= target_rns_limb_count
    {
        return Err(invalid_succinct_setup_proof(
            "share-linkage item coverage is outside the source statement dimensions",
        ));
    }
    let source_statement_records = array_field(statement, "sourceStatementRecords")?;
    let source_statement = source_statement_records
        .get(source_roster_position)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("share-linkage item source is outside the statement")
        })?;
    compare_string_value(
        read_string(item, "sourceTrusteeIdentity")?,
        read_string(source_statement, "sourceTrusteeIdentity")?,
        "share-linkage proof item sourceTrusteeIdentity",
    )?;
    compare_string_value(
        read_string(item, "sourceCoefficientCommitmentRoot")?,
        read_string(source_statement, "sourceCoefficientCommitmentRoot")?,
        "share-linkage proof item sourceCoefficientCommitmentRoot",
    )?;
    compare_string_value(
        read_string(item, "sourceRecipientShareCommitmentRoot")?,
        read_string(source_statement, "sourceRecipientShareCommitmentRoot")?,
        "share-linkage proof item sourceRecipientShareCommitmentRoot",
    )?;

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
    for source_record in [coefficient_source_record, recipient_source_record] {
        compare_string_value(
            read_string(source_record, "sourceTrusteeIdentity")?,
            read_string(source_statement, "sourceTrusteeIdentity")?,
            "share-linkage proof sourceTrusteeIdentity",
        )?;
        compare_u64_value(
            read_u64(source_record, "sourceTrusteeRosterPosition")?,
            source_roster_position as u64,
            "share-linkage proof sourceTrusteeRosterPosition",
        )?;
    }
    compare_string_value(
        read_string(coefficient_source_record, "sourceCoefficientCommitmentRoot")?,
        read_string(source_statement, "sourceCoefficientCommitmentRoot")?,
        "share-linkage proof sourceCoefficientCommitmentRoot",
    )?;
    compare_string_value(
        read_string(
            recipient_source_record,
            "sourceRecipientShareCommitmentRoot",
        )?,
        read_string(source_statement, "sourceRecipientShareCommitmentRoot")?,
        "share-linkage proof sourceRecipientShareCommitmentRoot",
    )?;

    let source_message_modulus = read_u64(item, "sourceMessageModulus")?;
    let coefficient_commitment_roots = read_string_array(item, "coefficientCommitmentRoots")?;
    let coefficient_opening_roots = read_string_array(item, "coefficientOpeningRoots")?;
    let coefficient_commitments = array_field(item, "coefficientCommitments")?;
    if coefficient_commitment_roots.len() != threshold_degree
        || coefficient_opening_roots.len() != threshold_degree
        || coefficient_commitments.len() != threshold_degree
    {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof item must carry one coefficient commitment per threshold coefficient",
        ));
    }
    let coefficient_records = array_field(coefficient_source_record, "coefficientCommitments")?;
    let source_statement_coefficient_opening_roots =
        array_field(source_statement, "coefficientOpeningRoots")?;
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
        compare_string_value(
            &coefficient_opening_roots[coefficient_index],
            read_string(coefficient_record, "coefficientOpeningRoot")?,
            "share-linkage proof coefficientOpeningRoot",
        )?;
        if source_statement_coefficient_opening_roots
            .get(coefficient_record_index)
            .and_then(Value::as_str)
            != Some(coefficient_opening_roots[coefficient_index].as_str())
        {
            return Err(invalid_succinct_setup_proof(
                "share-linkage proof coefficient opening root must match the source statement",
            ));
        }
        if coefficient_commitments.get(coefficient_index) != coefficient_record.get("commitment") {
            return Err(invalid_succinct_setup_proof(
                "share-linkage proof coefficient commitment body must match the public coefficient record",
            ));
        }
    }

    let recipient_records = array_field(recipient_source_record, "recipientShareCommitments")?;
    let recipient_record_index = recipient_roster_position
        .checked_mul(target_rns_limb_count)
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
    compare_string_value(
        read_string(item, "recipientShareOpeningRoot")?,
        read_string(recipient_record, "shareOpeningRoot")?,
        "share-linkage proof recipientShareOpeningRoot",
    )?;
    let source_statement_recipient_opening_roots =
        array_field(source_statement, "recipientShareOpeningRoots")?;
    if source_statement_recipient_opening_roots
        .get(recipient_record_index)
        .and_then(Value::as_str)
        != Some(read_string(item, "recipientShareOpeningRoot")?)
    {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof recipient opening root must match the source statement",
        ));
    }
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

pub(crate) fn verify_vss_share_linkage_proof_material_set_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = request.get("statement").ok_or_else(|| {
        invalid_succinct_setup_proof("share-linkage material statement must be present")
    })?;
    let statement_verification =
        crate::bgv::setup::vss_commitment::verify_vss_share_linkage_statement_request(request)?;
    let statement_root = read_string(&statement_verification, "statementRoot")?;
    let participant_count = usize::try_from(read_u64(&statement_verification, "participantCount")?)
        .map_err(|_| invalid_succinct_setup_proof("participantCount does not fit usize"))?;
    let target_rns_limb_count =
        usize::try_from(read_u64(&statement_verification, "targetRnsLimbCount")?)
            .map_err(|_| invalid_succinct_setup_proof("targetRnsLimbCount does not fit usize"))?;
    let threshold_degree =
        usize::try_from(read_u64(&statement_verification, "thresholdDegree")?)
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
    let ring_degree = usize::try_from(read_u64(coefficient_commitment_set, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let proof_material_set = request.get("proofMaterialSet").ok_or_else(|| {
        invalid_succinct_setup_proof("share-linkage proofMaterialSet must be present")
    })?;

    compare_string_value(
        read_string(proof_material_set, "objectType")?,
        "VssShareLinkageProofMaterialSet",
        "share-linkage proof material set objectType",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "objectVersion")?,
        1,
        "share-linkage proof material set objectVersion",
    )?;
    for (field_name, expected_value) in [
        ("proofFamily", VSS_SHARE_LINKAGE_PROOF_FAMILY),
        ("ceremonyId", read_string(statement, "ceremonyId")?),
        ("setupEpoch", read_string(statement, "setupEpoch")?),
    ] {
        compare_string_value(
            read_string(proof_material_set, field_name)?,
            expected_value,
            &format!("share-linkage proof material set {field_name}"),
        )?;
    }
    for field_name in [
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "publicMatrixSeedHash",
        "targetBasisHash",
        "coefficientCommitmentRoot",
        "recipientShareCommitmentRoot",
        "aggregateThresholdCommitmentRoot",
    ] {
        compare_string_value(
            read_string(proof_material_set, field_name)?,
            read_string(statement, field_name)?,
            &format!("share-linkage proof material set {field_name}"),
        )?;
    }
    compare_string_value(
        read_string(proof_material_set, "statementRoot")?,
        statement_root,
        "share-linkage proof material set statementRoot",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "participantCount")?,
        participant_count as u64,
        "share-linkage proof material set participantCount",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "targetRnsLimbCount")?,
        target_rns_limb_count as u64,
        "share-linkage proof material set targetRnsLimbCount",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "thresholdDegree")?,
        threshold_degree as u64,
        "share-linkage proof material set thresholdDegree",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "ringDegree")?,
        ring_degree as u64,
        "share-linkage proof material set ringDegree",
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
    let mut verified_records = Vec::with_capacity(proof_records.len());
    let mut total_proof_byte_length = 0usize;
    let mut proof_verification_count = 0usize;
    for (proof_record_index, proof_record) in proof_records.iter().enumerate() {
        compare_string_value(
            read_string(proof_record, "objectType")?,
            "VssShareLinkageProofRecord",
            "share-linkage proof record objectType",
        )?;
        compare_u64_value(
            read_u64(proof_record, "objectVersion")?,
            1,
            "share-linkage proof record objectVersion",
        )?;
        compare_string_value(
            read_string(proof_record, "proofFamily")?,
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            "share-linkage proof record proofFamily",
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
                target_rns_limb_count,
                threshold_degree,
            },
        )?;
        let record_linkage_items = proof_record
            .get("linkageItems")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "share-linkage proof record linkageItems must be an array",
                )
            })?;
        if record_linkage_items.len() != coverage.len() {
            return Err(invalid_succinct_setup_proof(
                "share-linkage proof record linkageItems must match the proof statement coverage",
            ));
        }
        for (item_index, coverage_item) in coverage.iter().enumerate() {
            if record_linkage_items.get(item_index) != Some(coverage_item) {
                return Err(invalid_succinct_setup_proof(
                    "share-linkage proof record linkageItems must be the canonical proof statement coverage",
                ));
            }
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

        let resolved_proof_bytes = resolve_vss_share_linkage_proof_bytes(
            proof_record,
            request,
            &coverage,
            vss_share_linkage,
        )?;
        let proof_bytes = resolved_proof_bytes.proof_bytes;
        total_proof_byte_length = total_proof_byte_length
            .checked_add(proof_bytes.len())
            .ok_or_else(|| {
                invalid_succinct_setup_proof("share-linkage proof material byte length overflowed")
            })?;
        let proof_record_without_root = resolved_proof_bytes.proof_record_without_root;
        let expected_record_root = resolved_proof_bytes.proof_record_root;

        let proof_request = json!({
            "context": {
                "ceremonyId": read_string(statement, "ceremonyId")?,
                "manifestHash": read_string(statement, "manifestHash")?,
                "rosterHash": read_string(statement, "rosterHash")?,
                "trusteeIdentity": "vss-share-linkage",
                "trusteeRosterPosition": 0,
                "setupEpoch": read_string(statement, "setupEpoch")?,
                "shareLinkageStatementRoot": statement_root,
            },
            "ringDegree": ring_degree,
            "vssShareLinkage": vss_share_linkage,
            "proofBytesHex": to_hex(&proof_bytes),
        });
        verify_vss_share_linkage_proof_from_request(&proof_request).map_err(|error| {
            CanonicalError::new(
                error.code,
                format!(
                    "share-linkage proof record {proof_record_index} did not verify: {}",
                    error.message
                ),
            )
        })?;
        proof_verification_count += 1;

        let mut verified_record = proof_record_without_root;
        verified_record["proofRecordRoot"] = json!(expected_record_root);
        verified_records.push(verified_record);
    }

    let expected_coverage_count = participant_count
        .checked_mul(participant_count)
        .and_then(|count| count.checked_mul(target_rns_limb_count))
        .ok_or_else(|| invalid_succinct_setup_proof("share-linkage coverage count overflowed"))?;
    if covered_items.len() != expected_coverage_count {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof material set must cover every source, recipient, and target limb exactly once",
        ));
    }
    for source_roster_position in 0..participant_count {
        for recipient_roster_position in 0..participant_count {
            for source_rns_limb_index in 0..target_rns_limb_count {
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

    let proof_material_set_without_root = json!({
        "objectType": "VssShareLinkageProofMaterialSet",
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "ceremonyId": read_string(statement, "ceremonyId")?,
        "manifestHash": read_string(statement, "manifestHash")?,
        "rosterHash": read_string(statement, "rosterHash")?,
        "setupParametersHash": read_string(statement, "setupParametersHash")?,
        "setupEpoch": read_string(statement, "setupEpoch")?,
        "publicMatrixSeedHash": read_string(statement, "publicMatrixSeedHash")?,
        "targetBasisHash": read_string(statement, "targetBasisHash")?,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": read_string(statement, "coefficientCommitmentRoot")?,
        "recipientShareCommitmentRoot": read_string(statement, "recipientShareCommitmentRoot")?,
        "aggregateThresholdCommitmentRoot": read_string(statement, "aggregateThresholdCommitmentRoot")?,
        "statementRoot": statement_root,
        "proofRecords": verified_records,
    });
    let expected_material_root = derive_canonical_object_hash(&proof_material_set_without_root)?;
    compare_string_value(
        read_string(proof_material_set, "proofMaterialSetRoot")?,
        &expected_material_root,
        "share-linkage proof material set proofMaterialSetRoot",
    )?;

    Ok(json!({
        "ok": true,
        "operation": "verifyVssShareLinkageProofMaterialSet",
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "statementRoot": statement_root,
        "proofMaterialSetRoot": expected_material_root,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "ringDegree": ring_degree,
        "proofRecordCount": proof_records.len(),
        "coveredLinkageItemCount": covered_items.len(),
        "totalProofByteLength": total_proof_byte_length,
        "proofVerificationCount": proof_verification_count,
    }))
}
