use super::*;
pub(crate) fn collect_supplied_component_proof_statement_refusals(
    component_proof: &Value,
    expected_component_id: &str,
    proof_input: &Value,
    proof_record_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let Some(proof_statement) =
        object_map(proof_input).and_then(|object| object.get("proofStatement"))
    else {
        return refused_objects;
    };
    if object_map(proof_statement).is_none() {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement object for {expected_component_id} is malformed."
            ),
            proof_record_digest,
        ));
        return refused_objects;
    }

    let proof_statement_format = string_field(proof_input, "proofStatementFormat").unwrap_or("");
    refused_objects.extend(collect_component_proof_statement_plan_shape_refusals(
        proof_statement,
        expected_component_id,
        proof_record_digest,
    ));
    let (expected_statement_digest, digest_field_name) =
        supplied_component_proof_statement_digest(proof_statement, proof_statement_format);
    if expected_statement_digest.is_none() || digest_field_name.is_none() {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement object for {expected_component_id} does not match its declared statement format."
            ),
            proof_record_digest,
        ));
    }
    if string_field(proof_statement, "proofStatementFormat")
        .is_some_and(|supplied_format| supplied_format != proof_statement_format)
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement format for {expected_component_id} does not match the supplied proof input."
            ),
            proof_record_digest,
        ));
    }
    if string_field(proof_statement, "componentId")
        .is_some_and(|component_id| component_id != expected_component_id)
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} is bound to the wrong component."
            ),
            proof_record_digest,
        ));
    }
    if string_field(proof_statement, "componentStatementDigest").is_some()
        && string_field(proof_statement, "componentStatementDigest")
            != string_field(component_proof, "componentStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} is not bound to the component statement."
            ),
            proof_record_digest,
        ));
    }
    match digest_field_name {
        Some("statementDigest") => {
            if string_field(proof_statement, "statementDigest")
                != expected_statement_digest.as_deref()
            {
                refused_objects.push(structural_refusal(
                    format!(
                        "Ballot proof component proof statement digest for {expected_component_id} does not match its canonical payload."
                    ),
                    proof_record_digest,
                ));
            }
        }
        Some("componentProofStatementDigest") => {
            if string_field(proof_statement, "componentProofStatementDigest")
                != expected_statement_digest.as_deref()
            {
                refused_objects.push(structural_refusal(
                    format!(
                        "Ballot proof component proof statement digest for {expected_component_id} does not match its canonical payload."
                    ),
                    proof_record_digest,
                ));
            }
        }
        _ => {}
    }
    if expected_statement_digest.as_deref()
        != string_field(proof_input, "componentProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} does not match the supplied proof input digest."
            ),
            proof_record_digest,
        ));
    }
    if expected_statement_digest.as_deref()
        != string_field(component_proof, "componentProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} does not match the proof record digest."
            ),
            proof_record_digest,
        ));
    }

    refused_objects
}

pub(crate) fn collect_ballot_component_proof_input_refusals(
    ballot_proof: &Value,
    component_proof_bundle: &Value,
    component_proof_inputs: Option<&Value>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let Some(component_proof_inputs) = component_proof_inputs else {
        refused_objects.push(structural_refusal(
            "Full encoded-score ballot proof verification requires public proof inputs for every component proof.",
            proof_record_digest,
        ));

        return refused_objects;
    };
    let Some(component_proof_inputs_array) = component_proof_inputs.as_array() else {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof inputs must be an array.",
            proof_record_digest,
        ));

        return refused_objects;
    };
    if component_proof_inputs_array.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof inputs must contain exactly the required components.",
            proof_record_digest,
        ));
    }

    let mut proof_inputs_by_component = BTreeMap::new();
    for proof_input in component_proof_inputs_array {
        let Some(component_id) = string_field(proof_input, "componentId") else {
            refused_objects.push(structural_refusal(
                "Ballot proof component proof input is missing its component id.",
                proof_record_digest,
            ));
            continue;
        };
        if proof_inputs_by_component
            .insert(component_id.to_string(), proof_input)
            .is_some()
        {
            refused_objects.push(structural_refusal(
                "Ballot proof component proof inputs contain a duplicate component.",
                proof_record_digest,
            ));
        }
    }

    let component_proofs = array_field(component_proof_bundle, "componentProofs")
        .map(|values| values.as_slice())
        .unwrap_or(&[]);
    for (component_index, expected_component_id) in
        REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter().enumerate()
    {
        let Some(component_proof) = component_proofs.get(component_index) else {
            continue;
        };
        let Some(proof_input) = proof_inputs_by_component.get(*expected_component_id) else {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} is missing."
                ),
                proof_record_digest,
            ));
            continue;
        };
        if string_field(proof_input, "componentId") != string_field(component_proof, "componentId")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} is not bound to the matching proof record."
                ),
                proof_record_digest,
            ));
        }
        if string_field(proof_input, "componentProofStatementDigest")
            != string_field(component_proof, "componentProofStatementDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement for {expected_component_id} does not match the proof record."
                ),
                proof_record_digest,
            ));
        }
        if string_field(proof_input, "proofStatementFormat").is_none_or(|proof_statement_format| {
            !ALLOWED_BALLOT_PROOF_COMPONENT_STATEMENT_FORMATS.contains(&proof_statement_format)
        }) {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement format for {expected_component_id} is not supported."
                ),
                proof_record_digest,
            ));
        }
        if !string_field(proof_input, "proofStatementFormat").is_some_and(
            |proof_statement_format| {
                component_proof_statement_format_is_expected(
                    expected_component_id,
                    proof_statement_format,
                )
            },
        ) {
            let expected_format =
                expected_component_proof_statement_format_label(expected_component_id);
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement format for {expected_component_id} must be {expected_format}."
                ),
                proof_record_digest,
            ));
        }
        if component_proof_bytes_must_be_empty(expected_component_id)
            && string_field(proof_input, "proofBytesHex")
                .is_some_and(|proof_bytes_hex| !proof_bytes_hex.is_empty())
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof bytes for {expected_component_id} must be empty for the public-zero witness binding check."
                ),
                proof_record_digest,
            ));
        }
        refused_objects.extend(collect_proof_bytes_refusals(
            string_field(proof_input, "proofBytesHex"),
            string_field(component_proof, "proofBytesDigest"),
            object_map(component_proof)
                .and_then(|object| object.get("proofSizeBytes"))
                .and_then(Value::as_u64),
            proof_record_digest,
            "Ballot proof component",
            component_proof_bytes_must_be_empty(expected_component_id),
        ));
        let expected_proof_encoding_digest = object_map(proof_input)
            .and_then(|object| object.get("proofEncoding"))
            .and_then(derive_ballot_proof_encoding_profile_digest);
        if expected_proof_encoding_digest.as_deref()
            != string_field(component_proof, "proofEncodingProfileDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof encoding for {expected_component_id} does not match the proof record."
                ),
                proof_record_digest,
            ));
        }
        let expected_parameter_set_digest = object_map(proof_input)
            .and_then(|object| object.get("proofParameterSet"))
            .and_then(derive_ballot_proof_parameter_set_digest);
        if expected_parameter_set_digest.as_deref()
            != string_field(component_proof, "proofParameterSetDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof parameter set for {expected_component_id} does not match the proof record."
                ),
                proof_record_digest,
            ));
        }
        let expected_public_randomness_digest = string_field(proof_input, "publicRandomnessHex")
            .and_then(derive_ballot_proof_public_randomness_digest);
        if expected_public_randomness_digest.as_deref()
            != string_field(component_proof, "publicRandomnessDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component public randomness for {expected_component_id} does not match the proof record."
                ),
                proof_record_digest,
            ));
        }
        if string_field(proof_input, "statementDigest")
            != string_field(component_proof, "componentStatementDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} is not bound to the component statement."
                ),
                proof_record_digest,
            ));
        }
        if object_map(proof_input)
            .and_then(|object| object.get("proofStatement"))
            .is_none()
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} must supply its public proof statement object."
                ),
                proof_record_digest,
            ));
        }
        if derive_ballot_component_proof_root(component_proof, proof_input, expected_component_id)
            .as_deref()
            != string_field(component_proof, "proofRoot")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof root for {expected_component_id} does not match the supplied public proof input."
                ),
                proof_record_digest,
            ));
        }
        refused_objects.extend(collect_supplied_component_proof_statement_refusals(
            component_proof,
            expected_component_id,
            proof_input,
            proof_record_digest,
        ));
    }

    refused_objects
}
