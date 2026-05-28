use super::*;
pub(crate) fn collect_supplied_component_proof_statement_refusals(
    component_proof: &Value,
    expected_component_id: &str,
    proof_input: &Value,
    proof_record_hash: Option<&str>,
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
            proof_record_hash,
        ));
        return refused_objects;
    }

    let proof_statement_format = string_field(proof_input, "proofStatementFormat").unwrap_or("");
    refused_objects.extend(collect_component_proof_statement_plan_shape_refusals(
        proof_statement,
        expected_component_id,
        proof_record_hash,
    ));
    let (expected_statement_hash, hash_field_name) =
        supplied_component_proof_statement_hash(proof_statement, proof_statement_format);
    if expected_statement_hash.is_none() || hash_field_name.is_none() {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement object for {expected_component_id} does not match its declared statement format."
            ),
            proof_record_hash,
        ));
    }
    if string_field(proof_statement, "proofStatementFormat")
        .is_some_and(|supplied_format| supplied_format != proof_statement_format)
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement format for {expected_component_id} does not match the supplied proof input."
            ),
            proof_record_hash,
        ));
    }
    if string_field(proof_statement, "componentId")
        .is_some_and(|component_id| component_id != expected_component_id)
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} is bound to the wrong component."
            ),
            proof_record_hash,
        ));
    }
    if string_field(proof_statement, "componentStatementHash").is_some()
        && string_field(proof_statement, "componentStatementHash")
            != string_field(component_proof, "componentStatementHash")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} is not bound to the component statement."
            ),
            proof_record_hash,
        ));
    }
    match hash_field_name {
        Some("statementHash") => {
            if string_field(proof_statement, "statementHash") != expected_statement_hash.as_deref()
            {
                refused_objects.push(structural_refusal(
                    format!(
                        "Ballot proof component proof statement hash for {expected_component_id} does not match its canonical payload."
                    ),
                    proof_record_hash,
                ));
            }
        }
        Some("componentProofStatementHash") => {
            if string_field(proof_statement, "componentProofStatementHash")
                != expected_statement_hash.as_deref()
            {
                refused_objects.push(structural_refusal(
                    format!(
                        "Ballot proof component proof statement hash for {expected_component_id} does not match its canonical payload."
                    ),
                    proof_record_hash,
                ));
            }
        }
        _ => {}
    }
    if expected_statement_hash.as_deref()
        != string_field(proof_input, "componentProofStatementHash")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} does not match the supplied proof input hash."
            ),
            proof_record_hash,
        ));
    }
    if expected_statement_hash.as_deref()
        != string_field(component_proof, "componentProofStatementHash")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} does not match the proof record hash."
            ),
            proof_record_hash,
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
    let proof_record_hash = string_field(ballot_proof, "ballotProofRecordHash");
    let Some(component_proof_inputs) = component_proof_inputs else {
        refused_objects.push(structural_refusal(
            "Full encoded-score ballot proof verification requires public proof inputs for every component proof.",
            proof_record_hash,
        ));

        return refused_objects;
    };
    let Some(component_proof_inputs_array) = component_proof_inputs.as_array() else {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof inputs must be an array.",
            proof_record_hash,
        ));

        return refused_objects;
    };
    if component_proof_inputs_array.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof inputs must contain exactly the required components.",
            proof_record_hash,
        ));
    }

    let mut proof_inputs_by_component = BTreeMap::new();
    for proof_input in component_proof_inputs_array {
        let Some(component_id) = string_field(proof_input, "componentId") else {
            refused_objects.push(structural_refusal(
                "Ballot proof component proof input is missing its component id.",
                proof_record_hash,
            ));
            continue;
        };
        if proof_inputs_by_component
            .insert(component_id.to_string(), proof_input)
            .is_some()
        {
            refused_objects.push(structural_refusal(
                "Ballot proof component proof inputs contain a duplicate component.",
                proof_record_hash,
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
                proof_record_hash,
            ));
            continue;
        };
        if string_field(proof_input, "componentId") != string_field(component_proof, "componentId")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} is not bound to the matching proof record."
                ),
                proof_record_hash,
            ));
        }
        if string_field(proof_input, "componentProofStatementHash")
            != string_field(component_proof, "componentProofStatementHash")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement for {expected_component_id} does not match the proof record."
                ),
                proof_record_hash,
            ));
        }
        if string_field(proof_input, "proofStatementFormat").is_none_or(|proof_statement_format| {
            !ALLOWED_BALLOT_PROOF_COMPONENT_STATEMENT_FORMATS.contains(&proof_statement_format)
        }) {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement format for {expected_component_id} is not supported."
                ),
                proof_record_hash,
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
                proof_record_hash,
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
                proof_record_hash,
            ));
        }
        refused_objects.extend(collect_proof_bytes_refusals(
            string_field(proof_input, "proofBytesHex"),
            string_field(component_proof, "proofBytesHash"),
            object_map(component_proof)
                .and_then(|object| object.get("proofSizeBytes"))
                .and_then(Value::as_u64),
            proof_record_hash,
            "Ballot proof component",
            component_proof_bytes_must_be_empty(expected_component_id),
        ));
        let expected_proof_encoding_hash = object_map(proof_input)
            .and_then(|object| object.get("proofEncoding"))
            .and_then(derive_ballot_proof_encoding_profile_hash);
        if expected_proof_encoding_hash.as_deref()
            != string_field(component_proof, "proofEncodingProfileHash")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof encoding for {expected_component_id} does not match the proof record."
                ),
                proof_record_hash,
            ));
        }
        let expected_parameter_set_hash = object_map(proof_input)
            .and_then(|object| object.get("proofParameterSet"))
            .and_then(derive_ballot_proof_parameter_set_hash);
        if expected_parameter_set_hash.as_deref()
            != string_field(component_proof, "proofParameterSetHash")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof parameter set for {expected_component_id} does not match the proof record."
                ),
                proof_record_hash,
            ));
        }
        let expected_public_randomness_hash = string_field(proof_input, "publicRandomnessHex")
            .and_then(derive_ballot_proof_public_randomness_hash);
        if expected_public_randomness_hash.as_deref()
            != string_field(component_proof, "publicRandomnessHash")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component public randomness for {expected_component_id} does not match the proof record."
                ),
                proof_record_hash,
            ));
        }
        if string_field(proof_input, "statementHash")
            != string_field(component_proof, "componentStatementHash")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} is not bound to the component statement."
                ),
                proof_record_hash,
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
                proof_record_hash,
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
                proof_record_hash,
            ));
        }
        refused_objects.extend(collect_supplied_component_proof_statement_refusals(
            component_proof,
            expected_component_id,
            proof_input,
            proof_record_hash,
        ));
    }

    refused_objects
}
