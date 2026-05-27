use super::*;

pub(crate) fn collect_component_bundle_component_refusals(
    component_statement: &Value,
    expected_component_id: &str,
    bundle_digest: Option<&str>,
    statement: &Value,
    linear_statement: &Value,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let component_statement_digest = string_field(component_statement, "componentStatementDigest");
    let expected_component_statement_digest =
        derive_ballot_component_statement_digest(component_statement);
    let row_batch_name_count = string_array_length(component_statement, "rowBatchNames");
    let row_batch_matrix_digest_count =
        string_array_length(component_statement, "rowBatchMatrixDigests");
    let row_batch_target_vector_digest_count =
        string_array_length(component_statement, "rowBatchTargetVectorDigests");
    let variable_column_count = object_map(component_statement)
        .and_then(|object| object.get("variableColumnCount"))
        .and_then(Value::as_u64);
    let variable_column_indices_count = array_field(component_statement, "variableColumnIndices")
        .map(Vec::len)
        .and_then(|count| u64::try_from(count).ok());
    let row_count = object_map(component_statement)
        .and_then(|object| object.get("rowCount"))
        .and_then(Value::as_u64);
    let row_kinds_are_present =
        array_field(component_statement, "rowKinds").is_some_and(|values| {
            !values.is_empty() && values.iter().all(|value| value.as_str().is_some())
        });

    if string_field(component_statement, "objectType") != Some("BallotProofComponentStatement")
        || object_map(component_statement)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_statement, "componentId") != Some(expected_component_id)
        || string_field(component_statement, "coefficientModulus").is_none_or(str::is_empty)
        || string_field(component_statement, "componentDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || component_statement_digest.is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_statement, "matrixDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_statement, "targetVectorDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_statement, "ballotProofStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || row_count.is_none_or(|count| count == 0)
        || !row_kinds_are_present
        || variable_column_count != variable_column_indices_count
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} has an invalid canonical shape."
            ),
            bundle_digest,
        ));
    }
    if expected_component_statement_digest.as_deref() != component_statement_digest {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement digest for {expected_component_id} does not match its canonical payload."
            ),
            bundle_digest,
        ));
    }
    if string_field(component_statement, "backendStatementDigest")
        != string_field(linear_statement, "backendStatementDigest")
        || string_field(component_statement, "relationStatementDigest")
            != string_field(linear_statement, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not bound to the supplied relation and backend statement."
            ),
            bundle_digest,
        ));
    }
    if string_field(component_statement, "ballotProofStatementDigest")
        != string_field(statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not bound to the supplied ballot proof statement."
            ),
            bundle_digest,
        ));
    }
    if string_field(component_statement, "proofLoweringStatus") != Some("explicitRowsAvailable") {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not fully lowered into explicit proof rows."
            ),
            bundle_digest,
        ));
    }
    if row_batch_name_count.is_none()
        || row_batch_matrix_digest_count.is_none()
        || row_batch_target_vector_digest_count.is_none()
        || row_batch_name_count != row_batch_matrix_digest_count
        || row_batch_name_count != row_batch_target_vector_digest_count
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} has inconsistent row-batch digest lists."
            ),
            bundle_digest,
        ));
    }
    if array_field(component_statement, "rowBatchMatrixDigests").is_some_and(|digests| {
        digests.iter().any(|digest| {
            digest
                .as_str()
                .is_none_or(|value| !is_protocol_digest(value))
        })
    }) || array_field(component_statement, "rowBatchTargetVectorDigests").is_some_and(
        |digests| {
            digests.iter().any(|digest| {
                digest
                    .as_str()
                    .is_none_or(|value| !is_protocol_digest(value))
            })
        },
    ) {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} contains a non-digest row-batch reference."
            ),
            bundle_digest,
        ));
    }

    refused_objects
}

pub(crate) fn collect_ballot_component_bundle_refusals(
    statement: &Value,
    ballot_proof: &Value,
    linear_statement: &Value,
    component_bundle_statement: Option<&Value>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let projection_coverage = string_field(linear_statement, "projectionCoverage");

    let Some(component_bundle_statement) = component_bundle_statement else {
        if projection_coverage == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
            || string_field(ballot_proof, "componentBundleStatementDigest").is_some()
        {
            refused_objects.push(structural_refusal(
                "Full encoded-score ballot proof verification requires a public component bundle statement.",
                proof_record_digest,
            ));
        }

        return refused_objects;
    };

    let bundle_digest = string_field(component_bundle_statement, "componentBundleStatementDigest");
    let expected_bundle_digest =
        derive_ballot_component_bundle_statement_digest(component_bundle_statement);

    if string_field(component_bundle_statement, "objectType")
        != Some("BallotProofComponentBundleStatement")
        || object_map(component_bundle_statement)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_bundle_statement, "relationLabel")
            != Some("BallotPrivacyPvssRelation")
        || bundle_digest.is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_bundle_statement, "ballotProofStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || !string_array_matches_expected(
            component_bundle_statement,
            "requiredComponentIds",
            REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        )
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle statement has an invalid canonical shape.",
            proof_record_digest,
        ));
    }
    if expected_bundle_digest.as_deref() != bundle_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle digest does not match its canonical payload.",
            proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "componentBundleStatementDigest") != bundle_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied component bundle statement.",
            proof_record_digest,
        ));
    }
    if string_field(component_bundle_statement, "backendStatementDigest")
        != string_field(linear_statement, "backendStatementDigest")
        || string_field(component_bundle_statement, "relationStatementDigest")
            != string_field(linear_statement, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is not bound to the supplied relation and backend statement.",
            proof_record_digest,
        ));
    }
    if string_field(component_bundle_statement, "ballotProofStatementDigest")
        != string_field(statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is not bound to the supplied ballot proof statement.",
            proof_record_digest,
        ));
    }
    if string_field(component_bundle_statement, "bundleCoverage")
        == Some(COMPONENT_BUNDLE_INCOMPLETE_COVERAGE)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is still incomplete.",
            proof_record_digest,
        ));
    } else if string_field(component_bundle_statement, "bundleCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle has an unknown coverage label.",
            proof_record_digest,
        ));
    }

    let Some(component_statements) = array_field(component_bundle_statement, "componentStatements")
    else {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle must contain component statements.",
            proof_record_digest,
        ));

        return refused_objects;
    };
    if component_statements.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle must contain exactly the required component statements.",
            proof_record_digest,
        ));
    }

    let mut seen_component_ids = BTreeSet::new();
    for (component_index, expected_component_id) in
        REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter().enumerate()
    {
        let Some(component_statement) = component_statements.get(component_index) else {
            continue;
        };
        if let Some(component_id) = string_field(component_statement, "componentId")
            && !seen_component_ids.insert(component_id.to_string())
        {
            refused_objects.push(structural_refusal(
                "Ballot proof component bundle contains a duplicate component statement.",
                proof_record_digest,
            ));
        }
        refused_objects.extend(collect_component_bundle_component_refusals(
            component_statement,
            expected_component_id,
            proof_record_digest,
            statement,
            linear_statement,
        ));
    }

    refused_objects
}

pub(crate) fn collect_component_proof_record_refusals(
    component_proof: &Value,
    expected_component_id: &str,
    proof_record_digest: Option<&str>,
    statement: &Value,
    component_proof_bundle: &Value,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let component_proof_record_digest = string_field(component_proof, "componentProofRecordDigest");
    let expected_component_proof_record_digest =
        derive_ballot_component_proof_record_digest(component_proof);
    let proof_size_bytes = object_map(component_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64);
    let proof_size_bytes_is_valid = proof_size_bytes.is_some_and(|proof_size_bytes| {
        if component_proof_bytes_must_be_empty(expected_component_id) {
            proof_size_bytes == 0
        } else {
            proof_size_bytes > 0
        }
    });

    if string_field(component_proof, "objectType") != Some("BallotProofComponentProofRecord")
        || object_map(component_proof)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_proof, "componentId") != Some(expected_component_id)
        || string_field(component_proof, "proofBackend") != Some("LocalLinearLatticeRelation")
        || component_proof_record_digest.is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "componentStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "backendStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "relationStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "proofRoot")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "proofBytesDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "proofEncodingProfileDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "proofParameterSetDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "publicRandomnessDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "componentProofStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "ballotProofStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || !proof_size_bytes_is_valid
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} has an invalid canonical shape."
            ),
            proof_record_digest,
        ));
    }
    if expected_component_proof_record_digest.as_deref() != component_proof_record_digest {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof digest for {expected_component_id} does not match its canonical payload."
            ),
            proof_record_digest,
        ));
    }
    if string_field(component_proof, "backendStatementDigest")
        != string_field(component_proof_bundle, "backendStatementDigest")
        || string_field(component_proof, "relationStatementDigest")
            != string_field(component_proof_bundle, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} is not bound to the supplied relation and backend statement."
            ),
            proof_record_digest,
        ));
    }
    if string_field(component_proof, "ballotProofStatementDigest")
        != string_field(statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} is not bound to the supplied ballot proof statement."
            ),
            proof_record_digest,
        ));
    }

    refused_objects
}

pub(crate) fn collect_ballot_component_proof_bundle_refusals(
    statement: &Value,
    ballot_proof: &Value,
    component_bundle_statement: Option<&Value>,
    component_proof_bundle: Option<&Value>,
    component_proof_inputs: Option<&Value>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let ballot_proof_component_bundle_digest =
        string_field(ballot_proof, "componentProofBundleDigest");

    if ballot_proof_component_bundle_digest.is_some() && component_proof_bundle.is_none() {
        refused_objects.push(structural_refusal(
            "Ballot proof record references a component proof bundle that was not supplied.",
            proof_record_digest,
        ));

        return refused_objects;
    }
    if component_proof_bundle.is_some() && ballot_proof_component_bundle_digest.is_none() {
        refused_objects.push(structural_refusal(
            "Supplied component proof bundle is not bound by the ballot proof record.",
            proof_record_digest,
        ));
    }
    if component_bundle_statement.is_some_and(|bundle_statement| {
        string_field(bundle_statement, "bundleCoverage")
            == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    }) && component_proof_bundle.is_none()
    {
        refused_objects.push(structural_refusal(
            "Full encoded-score ballot proof verification requires a component proof bundle.",
            proof_record_digest,
        ));
    }
    let Some(component_proof_bundle) = component_proof_bundle else {
        return refused_objects;
    };
    refused_objects.extend(collect_ballot_component_proof_input_refusals(
        ballot_proof,
        component_proof_bundle,
        component_proof_inputs,
    ));

    let component_proof_bundle_digest =
        string_field(component_proof_bundle, "componentProofBundleDigest");
    let expected_component_proof_bundle_digest =
        derive_ballot_component_proof_bundle_digest(component_proof_bundle);

    if string_field(component_proof_bundle, "objectType") != Some("BallotProofComponentProofBundle")
        || object_map(component_proof_bundle)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_proof_bundle, "bundleCoverage")
            != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        || component_proof_bundle_digest.is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof_bundle, "componentBundleStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof_bundle, "backendStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof_bundle, "relationStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof_bundle, "ballotProofStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || !string_array_matches_expected(
            component_proof_bundle,
            "requiredComponentIds",
            REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        )
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle has an invalid canonical shape.",
            proof_record_digest,
        ));
    }
    if expected_component_proof_bundle_digest.as_deref() != component_proof_bundle_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle digest does not match its canonical payload.",
            proof_record_digest,
        ));
    }
    if ballot_proof_component_bundle_digest != component_proof_bundle_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied component proof bundle.",
            proof_record_digest,
        ));
    }
    if string_field(component_proof_bundle, "componentBundleStatementDigest")
        != string_field(ballot_proof, "componentBundleStatementDigest")
        || string_field(component_proof_bundle, "backendStatementDigest")
            != string_field(ballot_proof, "backendStatementDigest")
        || string_field(component_proof_bundle, "relationStatementDigest")
            != string_field(ballot_proof, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied proof statement roots.",
            proof_record_digest,
        ));
    }
    if let Some(component_bundle_statement) = component_bundle_statement
        && string_field(component_proof_bundle, "componentBundleStatementDigest")
            != string_field(component_bundle_statement, "componentBundleStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied component bundle statement.",
            proof_record_digest,
        ));
    }
    if string_field(component_proof_bundle, "ballotProofStatementDigest")
        != string_field(statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied ballot proof statement.",
            proof_record_digest,
        ));
    }

    let Some(component_proofs) = array_field(component_proof_bundle, "componentProofs") else {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle must contain component proofs.",
            proof_record_digest,
        ));

        return refused_objects;
    };
    if component_proofs.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle must contain exactly the required component proofs.",
            proof_record_digest,
        ));
    }

    let mut seen_component_ids = BTreeSet::new();
    for (component_index, expected_component_id) in
        REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter().enumerate()
    {
        let Some(component_proof) = component_proofs.get(component_index) else {
            continue;
        };
        if let Some(component_id) = string_field(component_proof, "componentId")
            && !seen_component_ids.insert(component_id.to_string())
        {
            refused_objects.push(structural_refusal(
                "Ballot proof component proof bundle contains a duplicate component proof.",
                proof_record_digest,
            ));
        }
        if let Some(component_bundle_statement) = component_bundle_statement
            && let Some(component_statement) =
                array_field(component_bundle_statement, "componentStatements")
                    .and_then(|component_statements| component_statements.get(component_index))
            && string_field(component_proof, "componentStatementDigest")
                != string_field(component_statement, "componentStatementDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof for {expected_component_id} is not bound to the supplied component statement."
                ),
                proof_record_digest,
            ));
        }
        refused_objects.extend(collect_component_proof_record_refusals(
            component_proof,
            expected_component_id,
            proof_record_digest,
            statement,
            component_proof_bundle,
        ));
    }

    refused_objects
}

pub(crate) fn supplied_component_proof_statement_digest<'a>(
    proof_statement: &'a Value,
    proof_statement_format: &str,
) -> (Option<String>, Option<&'a str>) {
    match (
        string_field(proof_statement, "objectType"),
        proof_statement_format,
    ) {
        (Some("BallotProofLinearProofStatement"), "dense-polynomial-matrix-linear-proof-v1") => (
            derive_ballot_proof_linear_statement_digest(proof_statement),
            Some("statementDigest"),
        ),
        (
            Some("BallotProofSparseComponentLinearProofStatement"),
            "sparse-polynomial-matrix-linear-proof-v1",
        ) => (
            derive_ballot_sparse_linear_statement_digest(proof_statement),
            Some("statementDigest"),
        ),
        (
            Some("BallotProofComponentProofStatementPlan"),
            "structured-module-lwe-linear-proof-v1" | "public-zero-witness-binding-check-v1",
        ) => (
            derive_ballot_component_proof_statement_plan_digest(proof_statement),
            Some("componentProofStatementDigest"),
        ),
        (
            Some("BallotProofStructuredReceiverEncryptionProofStatement"),
            "structured-module-lwe-linear-proof-v1",
        ) => (
            derive_ballot_structured_receiver_encryption_statement_digest(proof_statement),
            Some("statementDigest"),
        ),
        (
            Some("BallotProofStructuredShareCommitmentProofStatement"),
            "structured-module-sis-share-commitment-v1",
        ) => (
            derive_ballot_structured_share_commitment_statement_digest(proof_statement),
            Some("statementDigest"),
        ),
        _ => (None, None),
    }
}

pub(crate) fn protocol_digest_field(value: &Value, field_name: &str) -> bool {
    string_field(value, field_name).is_some_and(is_protocol_digest)
}

pub(crate) fn unsigned_decimal_string_field(value: &Value, field_name: &str) -> bool {
    string_field(value, field_name).is_some_and(unsigned_decimal_string)
}

pub(crate) fn non_negative_u64_field(value: &Value, field_name: &str) -> Option<u64> {
    object_map(value)?.get(field_name)?.as_u64()
}

pub(crate) fn string_array_field<'value>(
    value: &'value Value,
    field_name: &str,
) -> Option<Vec<&'value str>> {
    array_field(value, field_name)?
        .iter()
        .map(Value::as_str)
        .collect()
}

pub(crate) fn digest_array_field_is_valid(value: &Value, field_name: &str) -> bool {
    array_field(value, field_name).is_some_and(|values| {
        values
            .iter()
            .all(|entry| entry.as_str().is_some_and(is_protocol_digest))
    })
}

pub(crate) fn u64_array_field_is_valid(value: &Value, field_name: &str) -> bool {
    array_field(value, field_name)
        .is_some_and(|values| values.iter().all(|entry| entry.as_u64().is_some()))
}

pub(crate) fn null_field(value: &Value, field_name: &str) -> bool {
    object_map(value)
        .and_then(|object| object.get(field_name))
        .is_some_and(Value::is_null)
}

pub(crate) fn collect_component_proof_statement_plan_shape_refusals(
    proof_statement: &Value,
    expected_component_id: &str,
    proof_record_digest: Option<&str>,
) -> Vec<Value> {
    if string_field(proof_statement, "objectType") != Some("BallotProofComponentProofStatementPlan")
    {
        return Vec::new();
    }

    let row_batch_names = string_array_field(proof_statement, "rowBatchNames");
    let row_batch_term_counts = string_array_field(proof_statement, "rowBatchTermCounts");
    let row_batch_count = row_batch_names
        .as_ref()
        .filter(|names| !names.is_empty())
        .map(Vec::len);
    let row_batch_lengths_match = row_batch_count.is_some_and(|row_batch_count| {
        array_field(proof_statement, "rowBatchMatrixDigests")
            .is_some_and(|digests| digests.len() == row_batch_count)
            && array_field(proof_statement, "rowBatchTargetVectorDigests")
                .is_some_and(|digests| digests.len() == row_batch_count)
            && row_batch_term_counts
                .as_ref()
                .is_some_and(|counts| counts.len() == row_batch_count)
    });
    let variable_column_indices =
        array_field(proof_statement, "variableColumnIndices").map(Vec::len);
    let variable_column_count = non_negative_u64_field(proof_statement, "variableColumnCount");

    let proof_statement_format = string_field(proof_statement, "proofStatementFormat");
    let proof_bytes_availability = string_field(proof_statement, "proofBytesAvailability");

    let common_shape_is_valid = object_map(proof_statement)
        .and_then(|object| object.get("objectVersion"))
        .and_then(Value::as_u64)
        == Some(1)
        && string_field(proof_statement, "componentId") == Some(expected_component_id)
        && proof_statement_format.is_some_and(|format| {
            component_proof_statement_format_is_expected(expected_component_id, format)
        })
        && proof_statement_format
            .zip(proof_bytes_availability)
            .is_some_and(|(format, availability)| {
                component_proof_bytes_availability_is_expected(
                    expected_component_id,
                    format,
                    availability,
                )
            })
        && string_field(proof_statement, "proofLoweringStatus") == Some("explicitRowsAvailable")
        && string_field(proof_statement, "relation") == Some("A*w + t = 0")
        && unsigned_decimal_string_field(proof_statement, "coefficientModulus")
        && protocol_digest_field(proof_statement, "backendStatementDigest")
        && protocol_digest_field(proof_statement, "componentProofStatementDigest")
        && protocol_digest_field(proof_statement, "componentStatementDigest")
        && protocol_digest_field(proof_statement, "matrixDigest")
        && protocol_digest_field(proof_statement, "relationStatementDigest")
        && protocol_digest_field(proof_statement, "targetVectorDigest")
        && digest_array_field_is_valid(proof_statement, "rowBatchMatrixDigests")
        && row_batch_names.is_some()
        && digest_array_field_is_valid(proof_statement, "rowBatchTargetVectorDigests")
        && row_batch_term_counts.as_ref().is_some_and(|term_counts| {
            term_counts
                .iter()
                .all(|term_count| unsigned_decimal_string(term_count))
        })
        && row_batch_lengths_match
        && non_negative_u64_field(proof_statement, "rowCount")
            .is_some_and(|row_count| row_count > 0)
        && variable_column_count.is_some()
        && u64_array_field_is_valid(proof_statement, "variableColumnIndices");

    let component_specific_shape_is_valid = match expected_component_id {
        "receiver-encryption-component" => {
            object_map(proof_statement)
                .and_then(|object| object.get("sourceRingDegree"))
                .and_then(Value::as_u64)
                == Some(256)
                && object_map(proof_statement)
                    .and_then(|object| object.get("proofSystemRingDegree"))
                    .and_then(Value::as_u64)
                    == Some(64)
                && unsigned_decimal_string_field(proof_statement, "denseCoefficientCount")
                && null_field(proof_statement, "sparseTermCount")
                && non_negative_u64_field(proof_statement, "structuredCiphertextChunkCount")
                    .is_some_and(|count| count > 0)
                && non_negative_u64_field(proof_statement, "structuredReceiverCount")
                    .is_some_and(|count| count > 0)
                && string_field(proof_statement, "structuredWitnessTermCount")
                    .is_some_and(|count| unsigned_decimal_string(count) && count != "0")
                && variable_column_count.is_some_and(|count| count > 0)
                && variable_column_indices
                    .zip(variable_column_count)
                    .is_some_and(|(indices_len, column_count)| indices_len as u64 == column_count)
        }
        "receiver-key-binding-component" => {
            null_field(proof_statement, "sourceRingDegree")
                && null_field(proof_statement, "proofSystemRingDegree")
                && null_field(proof_statement, "denseCoefficientCount")
                && null_field(proof_statement, "sparseTermCount")
                && null_field(proof_statement, "structuredCiphertextChunkCount")
                && null_field(proof_statement, "structuredReceiverCount")
                && null_field(proof_statement, "structuredWitnessTermCount")
                && variable_column_count == Some(0)
                && variable_column_indices == Some(0)
                && row_batch_term_counts.as_ref().is_some_and(|term_counts| {
                    term_counts.iter().all(|term_count| *term_count == "0")
                })
        }
        _ => true,
    };

    if common_shape_is_valid && component_specific_shape_is_valid {
        Vec::new()
    } else {
        vec![structural_refusal(
            format!(
                "Ballot proof component proof statement plan for {expected_component_id} has an invalid canonical shape."
            ),
            proof_record_digest,
        )]
    }
}
