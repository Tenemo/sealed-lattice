use super::*;

pub(crate) fn collect_component_bundle_component_refusals(
    component_statement: &Value,
    expected_component_id: &str,
    bundle_hash: Option<&str>,
    statement: &Value,
    linear_statement: &Value,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let component_statement_hash = string_field(component_statement, "componentStatementHash");
    let expected_component_statement_hash =
        derive_ballot_component_statement_hash(component_statement);
    let row_batch_name_count = string_array_length(component_statement, "rowBatchNames");
    let row_batch_matrix_hash_count =
        string_array_length(component_statement, "rowBatchMatrixHashes");
    let row_batch_target_vector_hash_count =
        string_array_length(component_statement, "rowBatchTargetVectorHashes");
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
        || string_field(component_statement, "componentHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || component_statement_hash.is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_statement, "matrixHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_statement, "targetVectorHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_statement, "ballotProofStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || row_count.is_none_or(|count| count == 0)
        || !row_kinds_are_present
        || variable_column_count != variable_column_indices_count
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} has an invalid canonical shape."
            ),
            bundle_hash,
        ));
    }
    if expected_component_statement_hash.as_deref() != component_statement_hash {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement hash for {expected_component_id} does not match its canonical payload."
            ),
            bundle_hash,
        ));
    }
    if string_field(component_statement, "backendStatementHash")
        != string_field(linear_statement, "backendStatementHash")
        || string_field(component_statement, "relationStatementHash")
            != string_field(linear_statement, "relationStatementHash")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not bound to the supplied relation and backend statement."
            ),
            bundle_hash,
        ));
    }
    if string_field(component_statement, "ballotProofStatementHash")
        != string_field(statement, "ballotProofStatementHash")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not bound to the supplied ballot proof statement."
            ),
            bundle_hash,
        ));
    }
    if string_field(component_statement, "proofLoweringStatus") != Some("explicitRowsAvailable") {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not fully lowered into explicit proof rows."
            ),
            bundle_hash,
        ));
    }
    if row_batch_name_count.is_none()
        || row_batch_matrix_hash_count.is_none()
        || row_batch_target_vector_hash_count.is_none()
        || row_batch_name_count != row_batch_matrix_hash_count
        || row_batch_name_count != row_batch_target_vector_hash_count
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} has inconsistent row-batch hash lists."
            ),
            bundle_hash,
        ));
    }
    if array_field(component_statement, "rowBatchMatrixHashes").is_some_and(|hashes| {
        hashes
            .iter()
            .any(|hash| hash.as_str().is_none_or(|value| !is_protocol_hash(value)))
    }) || array_field(component_statement, "rowBatchTargetVectorHashes").is_some_and(|hashes| {
        hashes
            .iter()
            .any(|hash| hash.as_str().is_none_or(|value| !is_protocol_hash(value)))
    }) {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} contains a non-hash row-batch reference."
            ),
            bundle_hash,
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
    let proof_record_hash = string_field(ballot_proof, "ballotProofRecordHash");
    let projection_coverage = string_field(linear_statement, "projectionCoverage");

    let Some(component_bundle_statement) = component_bundle_statement else {
        if projection_coverage == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
            || string_field(ballot_proof, "componentBundleStatementHash").is_some()
        {
            refused_objects.push(structural_refusal(
                "Full encoded-score ballot proof verification requires a public component bundle statement.",
                proof_record_hash,
            ));
        }

        return refused_objects;
    };

    let bundle_hash = string_field(component_bundle_statement, "componentBundleStatementHash");
    let expected_bundle_hash =
        derive_ballot_component_bundle_statement_hash(component_bundle_statement);

    if string_field(component_bundle_statement, "objectType")
        != Some("BallotProofComponentBundleStatement")
        || object_map(component_bundle_statement)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_bundle_statement, "relationLabel")
            != Some("BallotPrivacyPvssRelation")
        || bundle_hash.is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_bundle_statement, "ballotProofStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || !string_array_matches_expected(
            component_bundle_statement,
            "requiredComponentIds",
            REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        )
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle statement has an invalid canonical shape.",
            proof_record_hash,
        ));
    }
    if expected_bundle_hash.as_deref() != bundle_hash {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle hash does not match its canonical payload.",
            proof_record_hash,
        ));
    }
    if string_field(ballot_proof, "componentBundleStatementHash") != bundle_hash {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied component bundle statement.",
            proof_record_hash,
        ));
    }
    if string_field(component_bundle_statement, "backendStatementHash")
        != string_field(linear_statement, "backendStatementHash")
        || string_field(component_bundle_statement, "relationStatementHash")
            != string_field(linear_statement, "relationStatementHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is not bound to the supplied relation and backend statement.",
            proof_record_hash,
        ));
    }
    if string_field(component_bundle_statement, "ballotProofStatementHash")
        != string_field(statement, "ballotProofStatementHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is not bound to the supplied ballot proof statement.",
            proof_record_hash,
        ));
    }
    if string_field(component_bundle_statement, "bundleCoverage")
        == Some(COMPONENT_BUNDLE_INCOMPLETE_COVERAGE)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is still incomplete.",
            proof_record_hash,
        ));
    } else if string_field(component_bundle_statement, "bundleCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle has an unknown coverage label.",
            proof_record_hash,
        ));
    }

    let Some(component_statements) = array_field(component_bundle_statement, "componentStatements")
    else {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle must contain component statements.",
            proof_record_hash,
        ));

        return refused_objects;
    };
    if component_statements.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle must contain exactly the required component statements.",
            proof_record_hash,
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
                proof_record_hash,
            ));
        }
        refused_objects.extend(collect_component_bundle_component_refusals(
            component_statement,
            expected_component_id,
            proof_record_hash,
            statement,
            linear_statement,
        ));
    }

    refused_objects
}

pub(crate) fn collect_component_proof_record_refusals(
    component_proof: &Value,
    expected_component_id: &str,
    proof_record_hash: Option<&str>,
    statement: &Value,
    component_proof_bundle: &Value,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let component_proof_record_hash = string_field(component_proof, "componentProofRecordHash");
    let expected_component_proof_record_hash =
        derive_ballot_component_proof_record_hash(component_proof);
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
        || component_proof_record_hash.is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "componentStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "backendStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "relationStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "proofRoot").is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "proofBytesHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "proofEncodingProfileHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "proofParameterSetHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "publicRandomnessHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "componentProofStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof, "ballotProofStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || !proof_size_bytes_is_valid
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} has an invalid canonical shape."
            ),
            proof_record_hash,
        ));
    }
    if expected_component_proof_record_hash.as_deref() != component_proof_record_hash {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof hash for {expected_component_id} does not match its canonical payload."
            ),
            proof_record_hash,
        ));
    }
    if string_field(component_proof, "backendStatementHash")
        != string_field(component_proof_bundle, "backendStatementHash")
        || string_field(component_proof, "relationStatementHash")
            != string_field(component_proof_bundle, "relationStatementHash")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} is not bound to the supplied relation and backend statement."
            ),
            proof_record_hash,
        ));
    }
    if string_field(component_proof, "ballotProofStatementHash")
        != string_field(statement, "ballotProofStatementHash")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} is not bound to the supplied ballot proof statement."
            ),
            proof_record_hash,
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
    let proof_record_hash = string_field(ballot_proof, "ballotProofRecordHash");
    let ballot_proof_component_bundle_hash = string_field(ballot_proof, "componentProofBundleHash");

    if ballot_proof_component_bundle_hash.is_some() && component_proof_bundle.is_none() {
        refused_objects.push(structural_refusal(
            "Ballot proof record references a component proof bundle that was not supplied.",
            proof_record_hash,
        ));

        return refused_objects;
    }
    if component_proof_bundle.is_some() && ballot_proof_component_bundle_hash.is_none() {
        refused_objects.push(structural_refusal(
            "Supplied component proof bundle is not bound by the ballot proof record.",
            proof_record_hash,
        ));
    }
    if component_bundle_statement.is_some_and(|bundle_statement| {
        string_field(bundle_statement, "bundleCoverage")
            == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    }) && component_proof_bundle.is_none()
    {
        refused_objects.push(structural_refusal(
            "Full encoded-score ballot proof verification requires a component proof bundle.",
            proof_record_hash,
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

    let component_proof_bundle_hash =
        string_field(component_proof_bundle, "componentProofBundleHash");
    let expected_component_proof_bundle_hash =
        derive_ballot_component_proof_bundle_hash(component_proof_bundle);

    if string_field(component_proof_bundle, "objectType") != Some("BallotProofComponentProofBundle")
        || object_map(component_proof_bundle)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_proof_bundle, "bundleCoverage")
            != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        || component_proof_bundle_hash.is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof_bundle, "componentBundleStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof_bundle, "backendStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof_bundle, "relationStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(component_proof_bundle, "ballotProofStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || !string_array_matches_expected(
            component_proof_bundle,
            "requiredComponentIds",
            REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        )
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle has an invalid canonical shape.",
            proof_record_hash,
        ));
    }
    if expected_component_proof_bundle_hash.as_deref() != component_proof_bundle_hash {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle hash does not match its canonical payload.",
            proof_record_hash,
        ));
    }
    if ballot_proof_component_bundle_hash != component_proof_bundle_hash {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied component proof bundle.",
            proof_record_hash,
        ));
    }
    if string_field(component_proof_bundle, "componentBundleStatementHash")
        != string_field(ballot_proof, "componentBundleStatementHash")
        || string_field(component_proof_bundle, "backendStatementHash")
            != string_field(ballot_proof, "backendStatementHash")
        || string_field(component_proof_bundle, "relationStatementHash")
            != string_field(ballot_proof, "relationStatementHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied proof statement roots.",
            proof_record_hash,
        ));
    }
    if let Some(component_bundle_statement) = component_bundle_statement
        && string_field(component_proof_bundle, "componentBundleStatementHash")
            != string_field(component_bundle_statement, "componentBundleStatementHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied component bundle statement.",
            proof_record_hash,
        ));
    }
    if string_field(component_proof_bundle, "ballotProofStatementHash")
        != string_field(statement, "ballotProofStatementHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied ballot proof statement.",
            proof_record_hash,
        ));
    }

    let Some(component_proofs) = array_field(component_proof_bundle, "componentProofs") else {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle must contain component proofs.",
            proof_record_hash,
        ));

        return refused_objects;
    };
    if component_proofs.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle must contain exactly the required component proofs.",
            proof_record_hash,
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
                proof_record_hash,
            ));
        }
        if let Some(component_bundle_statement) = component_bundle_statement
            && let Some(component_statement) =
                array_field(component_bundle_statement, "componentStatements")
                    .and_then(|component_statements| component_statements.get(component_index))
            && string_field(component_proof, "componentStatementHash")
                != string_field(component_statement, "componentStatementHash")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof for {expected_component_id} is not bound to the supplied component statement."
                ),
                proof_record_hash,
            ));
        }
        refused_objects.extend(collect_component_proof_record_refusals(
            component_proof,
            expected_component_id,
            proof_record_hash,
            statement,
            component_proof_bundle,
        ));
    }

    refused_objects
}

pub(crate) fn supplied_component_proof_statement_hash<'a>(
    proof_statement: &'a Value,
    proof_statement_format: &str,
) -> (Option<String>, Option<&'a str>) {
    match (
        string_field(proof_statement, "objectType"),
        proof_statement_format,
    ) {
        (Some("BallotProofLinearProofStatement"), "dense-polynomial-matrix-linear-proof-v1") => (
            derive_ballot_proof_linear_statement_hash(proof_statement),
            Some("statementHash"),
        ),
        (
            Some("BallotProofSparseComponentLinearProofStatement"),
            "sparse-polynomial-matrix-linear-proof-v1",
        ) => (
            derive_ballot_sparse_linear_statement_hash(proof_statement),
            Some("statementHash"),
        ),
        (
            Some("BallotProofComponentProofStatementPlan"),
            "structured-module-lwe-linear-proof-v1" | "public-zero-witness-binding-check-v1",
        ) => (
            derive_ballot_component_proof_statement_plan_hash(proof_statement),
            Some("componentProofStatementHash"),
        ),
        (
            Some("BallotProofStructuredReceiverEncryptionProofStatement"),
            "structured-module-lwe-linear-proof-v1",
        ) => (
            derive_ballot_structured_receiver_encryption_statement_hash(proof_statement),
            Some("statementHash"),
        ),
        (
            Some("BallotProofStructuredShareCommitmentProofStatement"),
            "structured-module-sis-share-commitment-v1",
        ) => (
            derive_ballot_structured_share_commitment_statement_hash(proof_statement),
            Some("statementHash"),
        ),
        _ => (None, None),
    }
}

pub(crate) fn protocol_hash_field(value: &Value, field_name: &str) -> bool {
    string_field(value, field_name).is_some_and(is_protocol_hash)
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

pub(crate) fn hash_array_field_is_valid(value: &Value, field_name: &str) -> bool {
    array_field(value, field_name).is_some_and(|values| {
        values
            .iter()
            .all(|entry| entry.as_str().is_some_and(is_protocol_hash))
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
    proof_record_hash: Option<&str>,
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
        array_field(proof_statement, "rowBatchMatrixHashes")
            .is_some_and(|hashes| hashes.len() == row_batch_count)
            && array_field(proof_statement, "rowBatchTargetVectorHashes")
                .is_some_and(|hashes| hashes.len() == row_batch_count)
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
        && protocol_hash_field(proof_statement, "backendStatementHash")
        && protocol_hash_field(proof_statement, "componentProofStatementHash")
        && protocol_hash_field(proof_statement, "componentStatementHash")
        && protocol_hash_field(proof_statement, "matrixHash")
        && protocol_hash_field(proof_statement, "relationStatementHash")
        && protocol_hash_field(proof_statement, "targetVectorHash")
        && hash_array_field_is_valid(proof_statement, "rowBatchMatrixHashes")
        && row_batch_names.is_some()
        && hash_array_field_is_valid(proof_statement, "rowBatchTargetVectorHashes")
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
            proof_record_hash,
        )]
    }
}
