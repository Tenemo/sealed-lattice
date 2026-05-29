use serde_json::Value;

use super::{
    backend_status::structural_refusal,
    json_helpers::{object_map, string_field},
    linear_proof_parameters::{LinearProofEncoding, LinearProofParameterSet},
};

pub(crate) struct LinearProofBindingValidationInput<'a> {
    pub(crate) proof_record: &'a Value,
    pub(crate) linear_statement: &'a Value,
    pub(crate) parameter_set: &'a Value,
    pub(crate) proof_encoding: &'a Value,
    pub(crate) expected_linear_statement_hash: Option<String>,
    pub(crate) expected_parameter_set_hash: Option<String>,
    pub(crate) expected_proof_encoding_hash: Option<String>,
    pub(crate) expected_public_randomness_hash: Option<String>,
    pub(crate) object_hash: Option<&'a str>,
    pub(crate) parameter_profile_requirement: Option<LinearProofProfileRequirement<'a>>,
    pub(crate) proof_encoding_profile_requirement: Option<LinearProofProfileRequirement<'a>>,
    pub(crate) messages: LinearProofBindingValidationMessages<'a>,
}

pub(crate) struct LinearProofProfileRequirement<'a> {
    pub(crate) profile_id: &'a str,
    pub(crate) refusal_message: &'a str,
}

pub(crate) struct LinearProofBindingValidationMessages<'a> {
    pub(crate) canonical_statement_hash_mismatch: &'a str,
    pub(crate) proof_record_statement_mismatch: &'a str,
    pub(crate) proof_encoding_hash_mismatch: &'a str,
    pub(crate) parameter_set_hash_mismatch: &'a str,
    pub(crate) public_randomness_hash_mismatch: &'a str,
    pub(crate) parameter_set_size_mismatch: &'a str,
    pub(crate) parameter_set_malformed_prefix: &'a str,
    pub(crate) proof_encoding_size_mismatch: &'a str,
    pub(crate) proof_encoding_malformed_prefix: &'a str,
}

pub(crate) fn collect_linear_proof_binding_refusals(
    input: LinearProofBindingValidationInput<'_>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let linear_statement_hash = string_field(input.linear_statement, "statementHash");
    let proof_size_bytes = object_map(input.proof_record)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size_bytes| usize::try_from(proof_size_bytes).ok());

    if linear_statement_hash != input.expected_linear_statement_hash.as_deref() {
        refused_objects.push(structural_refusal(
            input.messages.canonical_statement_hash_mismatch,
            input.object_hash,
        ));
    }
    if let Some(requirement) = input.parameter_profile_requirement
        && string_field(input.parameter_set, "profileId") != Some(requirement.profile_id)
    {
        refused_objects.push(structural_refusal(
            requirement.refusal_message,
            input.object_hash,
        ));
    }
    if let Some(requirement) = input.proof_encoding_profile_requirement
        && string_field(input.proof_encoding, "profileId") != Some(requirement.profile_id)
    {
        refused_objects.push(structural_refusal(
            requirement.refusal_message,
            input.object_hash,
        ));
    }
    if string_field(input.proof_record, "linearStatementHash") != linear_statement_hash {
        refused_objects.push(structural_refusal(
            input.messages.proof_record_statement_mismatch,
            input.object_hash,
        ));
    }
    if string_field(input.proof_record, "proofEncodingProfileHash")
        != input.expected_proof_encoding_hash.as_deref()
    {
        refused_objects.push(structural_refusal(
            input.messages.proof_encoding_hash_mismatch,
            input.object_hash,
        ));
    }
    if string_field(input.proof_record, "proofParameterSetHash")
        != input.expected_parameter_set_hash.as_deref()
    {
        refused_objects.push(structural_refusal(
            input.messages.parameter_set_hash_mismatch,
            input.object_hash,
        ));
    }
    if string_field(input.proof_record, "publicRandomnessHash")
        != input.expected_public_randomness_hash.as_deref()
    {
        refused_objects.push(structural_refusal(
            input.messages.public_randomness_hash_mismatch,
            input.object_hash,
        ));
    }

    match serde_json::from_value::<LinearProofParameterSet>(input.parameter_set.clone()) {
        Ok(parameter_contract)
            if parameter_contract.expected_proof_size_bytes != proof_size_bytes =>
        {
            refused_objects.push(structural_refusal(
                input.messages.parameter_set_size_mismatch,
                input.object_hash,
            ));
        }
        Ok(_) => {}
        Err(error) => refused_objects.push(structural_refusal(
            format!("{}: {error}", input.messages.parameter_set_malformed_prefix),
            input.object_hash,
        )),
    }
    match serde_json::from_value::<LinearProofEncoding>(input.proof_encoding.clone()) {
        Ok(proof_encoding_contract)
            if proof_encoding_contract.expected_proof_size_bytes != proof_size_bytes =>
        {
            refused_objects.push(structural_refusal(
                input.messages.proof_encoding_size_mismatch,
                input.object_hash,
            ));
        }
        Ok(_) => {}
        Err(error) => refused_objects.push(structural_refusal(
            format!(
                "{}: {error}",
                input.messages.proof_encoding_malformed_prefix
            ),
            input.object_hash,
        )),
    }

    refused_objects
}
