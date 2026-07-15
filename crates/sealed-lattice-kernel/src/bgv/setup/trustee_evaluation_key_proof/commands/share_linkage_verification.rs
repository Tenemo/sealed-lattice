use super::decoding::*;
use super::share_linkage_transport::*;
use super::*;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::trustee_evaluation_key_proof::VSS_SHARE_LINKAGE_PROOF_FAMILY;
use crate::encoding::CanonicalError;

pub(in crate::bgv::setup) struct VssShareLinkageMaterialRecordStatementInput<'a> {
    pub(in crate::bgv::setup) coverage_items: &'a [Value],
    pub(in crate::bgv::setup) statement: &'a Value,
    pub(in crate::bgv::setup) coefficient_commitment_set: &'a Value,
    pub(in crate::bgv::setup) recipient_share_commitment_set: &'a Value,
    pub(in crate::bgv::setup) participant_count: usize,
    pub(in crate::bgv::setup) q_share_rns_limb_count: usize,
    pub(in crate::bgv::setup) threshold_degree: usize,
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

pub(in crate::bgv::setup) struct ReconstructedVssShareLinkageStatement {
    pub(in crate::bgv::setup) proof_statement: Value,
    pub(in crate::bgv::setup) coverage: Vec<Value>,
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

pub(in crate::bgv::setup) fn verify_vss_share_linkage_material_record_statement(
    input: VssShareLinkageMaterialRecordStatementInput<'_>,
) -> CanonicalResult<ReconstructedVssShareLinkageStatement> {
    if input.coverage_items.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof record must cover at least one item",
        ));
    }
    let mut coverage = Vec::with_capacity(input.coverage_items.len());
    let mut reconstructed_items = Vec::with_capacity(input.coverage_items.len());
    for (item_index, item) in input.coverage_items.iter().enumerate() {
        let (reconstructed_item, coverage_item) =
            verify_vss_share_linkage_item_against_public_records(
            VssShareLinkagePublicRecordInput {
                item,
                coefficient_commitment_set: input.coefficient_commitment_set,
                recipient_share_commitment_set: input.recipient_share_commitment_set,
                participant_count: input.participant_count,
                q_share_rns_limb_count: input.q_share_rns_limb_count,
                threshold_degree: input.threshold_degree,
                item_index,
            },
        )?;
        reconstructed_items.push(reconstructed_item);
        coverage.push(coverage_item);
    }

    let mut proof_statement = reconstructed_items.remove(0);
    let proof_statement_object = proof_statement.as_object_mut().ok_or_else(|| {
        invalid_succinct_setup_proof("reconstructed share-linkage statement must be an object")
    })?;
    proof_statement_object.insert(
        "publicMatrixSeedHash".to_string(),
        Value::String(read_string(input.statement, "publicMatrixSeedHash")?.to_string()),
    );
    if !reconstructed_items.is_empty() {
        proof_statement_object.insert(
            "additionalLinkageItems".to_string(),
            Value::Array(reconstructed_items),
        );
    }

    Ok(ReconstructedVssShareLinkageStatement {
        proof_statement,
        coverage,
    })
}

pub(super) fn verify_vss_share_linkage_item_against_public_records(
    input: VssShareLinkagePublicRecordInput<'_>,
) -> CanonicalResult<(Value, Value)> {
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
    if source_roster_position >= participant_count
        || recipient_roster_position >= participant_count
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
        read_string(recipient_source_record, "sourceTrusteeIdentity")?,
        source_trustee_identity,
        "share-linkage proof sourceTrusteeIdentity",
    )?;
    let source_coefficient_commitment_root =
        crate::bgv::setup::vss_commitment::vss_public_source_coefficient_record_root(
            coefficient_source_record,
        )?;
    let source_recipient_share_commitment_root =
        crate::bgv::setup::vss_commitment::vss_public_source_recipient_share_record_root(
            recipient_source_record,
        )?;

    let source_message_modulus = DATA_PRIMES
        .get(source_rns_limb_index)
        .copied()
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage item sourceRnsLimbIndex is outside the canonical modulus schedule",
            )
        })?;
    let coefficient_records = array_field(coefficient_source_record, "coefficientCommitments")?;
    let mut coefficient_commitment_roots = Vec::with_capacity(threshold_degree);
    let mut coefficient_commitments = Vec::with_capacity(threshold_degree);
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
        coefficient_commitment_roots.push(
            crate::bgv::setup::vss_commitment::vss_public_commitment_body_root(
                coefficient_record,
            )?,
        );
        coefficient_commitments.push(
            coefficient_record
                .get("commitment")
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "share-linkage coefficient record is missing its commitment body",
                    )
                })?
                .clone(),
        );
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
    let recipient_identity = read_string(recipient_record, "recipientIdentity")?;
    let recipient_share_commitment_root =
        crate::bgv::setup::vss_commitment::vss_public_commitment_body_root(recipient_record)?;
    let recipient_share_commitment = recipient_record
        .get("commitment")
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage recipient-share record is missing its commitment body",
            )
        })?
        .clone();

    let reconstructed_item = json!({
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_roster_position,
        "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
        "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": source_rns_limb_index,
        "sourceMessageModulus": source_message_modulus,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "coefficientCommitments": coefficient_commitments,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "recipientShareCommitment": recipient_share_commitment,
    });
    let coverage = json!({
        "sourceTrusteeRosterPosition": source_roster_position,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": source_rns_limb_index,
        "itemIndex": item_index,
    });
    Ok((reconstructed_item, coverage))
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
    let participant_count = usize::try_from(read_u64(statement_verification, "participantCount")?)
        .map_err(|_| invalid_succinct_setup_proof("participantCount does not fit usize"))?;
    let q_share_rns_limb_count =
        usize::try_from(read_u64(statement_verification, "qShareRnsLimbCount")?)
            .map_err(|_| invalid_succinct_setup_proof("qShareRnsLimbCount does not fit usize"))?;
    let threshold_degree = usize::try_from(read_u64(statement_verification, "thresholdDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("thresholdDegree does not fit usize"))?;
    let ring_degree = usize::try_from(read_u64(statement_verification, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
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
        let coverage_items = array_field(proof_record, "coverage")?;
        let reconstructed = verify_vss_share_linkage_material_record_statement(
            VssShareLinkageMaterialRecordStatementInput {
                coverage_items,
                statement,
                coefficient_commitment_set,
                recipient_share_commitment_set,
                participant_count,
                q_share_rns_limb_count,
                threshold_degree,
            },
        )?;
        for coverage_item in &reconstructed.coverage {
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
            },
            "ringDegree": ring_degree,
            "vssShareLinkage": reconstructed.proof_statement,
        });
        let verification_binding_hash = vss_share_linkage_proof_verification_binding_hash(
            &validated_proof_reference.proof_bytes_hash,
            &proof_request,
        )?;
        let proof_bytes_hash = validated_proof_reference.proof_bytes_hash.clone();
        let proof_binding_was_consumed = match proof_binding_session {
            Some(proof_binding_session) => crate::bgv::setup::consume_accepted_setup_proof_binding(
                proof_binding_session.session_handle,
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                &proof_bytes_hash,
                &verification_binding_hash,
            )?,
            None => false,
        };
        if !proof_binding_was_consumed {
            let proof_bytes = resolve_vss_share_linkage_proof_bytes(
                validated_proof_reference,
                proof_binding_session,
            )?;
            verify_vss_share_linkage_proof_source_from_request(
                &proof_request,
                proof_bytes.as_ref(),
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
