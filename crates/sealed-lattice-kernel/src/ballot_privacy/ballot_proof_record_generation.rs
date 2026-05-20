use super::ballot_proof_record_builders::{
    GeneratedBallotProofRecordInput, generated_ballot_proof_record,
    generated_component_proof_bundle, generated_component_proof_input,
    generated_component_proof_record, proof_contract_with_expected_size,
};
use super::ballot_proof_record_inputs::{
    BallotProofRecordGenerationInput, RequiredBallotProofRecordGenerationInput,
};
use super::*;

pub fn generate_ballot_proof_record(input: BallotProofRecordGenerationInput<'_>) -> Value {
    match generate_ballot_proof_record_inner(input) {
        Ok(value) => value,
        Err(error) => {
            structural_rejection("generateBallotProofRecord", vec![error.to_json_value()])
        }
    }
}

pub(crate) fn generate_ballot_proof_record_from_command_request(request: &Value) -> Value {
    generate_ballot_proof_record(BallotProofRecordGenerationInput::from_command_request(
        request,
    ))
}

pub(crate) fn generate_ballot_proof_record_inner(
    input: BallotProofRecordGenerationInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let required_input = RequiredBallotProofRecordGenerationInput::parse(input)?;
    required_input.validate_full_projection_coverage()?;
    let statement = required_input.statement;
    let linear_statement = required_input.linear_statement;
    let parameter_set = required_input.parameter_set;
    let proof_encoding = required_input.proof_encoding;
    let public_randomness_hex = required_input.public_randomness_hex;
    let component_bundle_statement = required_input.component_bundle_statement;
    let secret_state = required_input.secret_state;
    let prover_randomness_hex = required_input.prover_randomness_hex;
    let component_prover_randomness_hexes = required_input.component_prover_randomness_hexes;
    let component_secret_states = required_input.component_secret_states;
    let component_inputs_by_id = required_input.component_inputs_by_id()?;

    let mut generated_component_proofs = Vec::new();
    let mut generated_component_inputs = Vec::new();
    for component_id in REQUIRED_BALLOT_PROOF_COMPONENT_IDS {
        let proof_input = component_inputs_by_id.get(*component_id).ok_or_else(|| {
            invalid_preflight(format!(
                "component proof input for {component_id} is missing"
            ))
        })?;
        let component_prover_randomness_hex =
            component_generation_randomness_hex(component_id, component_prover_randomness_hexes)?;
        let component_secret_state =
            component_generation_secret_state(component_id, secret_state, component_secret_states)?;
        let component_generation_input = BallotComponentProofGenerationInput::from_required_fields(
            component_id,
            proof_input,
            component_secret_state,
            &component_prover_randomness_hex,
        );
        let component_generation =
            generate_ballot_component_proof_inner(component_generation_input).map_err(|error| {
                invalid_preflight(format!(
                    "component proof generation failed for {component_id}: {}",
                    error.message
                ))
            })?;
        let component_generation_label = format!("generated component proof for {component_id}");
        let generated_component_proof =
            generated_proof_bytes(&component_generation, &component_generation_label)?;
        let generated_component_input = generated_component_proof_input(
            proof_input,
            &generated_component_proof.proof_bytes_hex,
            generated_component_proof.proof_size_bytes,
        )?;
        let component_proof = generated_component_proof_record(
            component_id,
            statement,
            component_bundle_statement,
            &generated_component_input,
            &generated_component_proof.proof_bytes_hex,
            generated_component_proof.proof_size_bytes,
        )?;
        generated_component_inputs.push(generated_component_input);
        generated_component_proofs.push(component_proof);
    }
    let component_proof_bundle =
        generated_component_proof_bundle(component_bundle_statement, generated_component_proofs)?;

    let ballot_generation_input = BallotProofGenerationInput::from_required_fields(
        linear_statement,
        parameter_set,
        proof_encoding,
        public_randomness_hex,
        secret_state,
        prover_randomness_hex,
    );
    let ballot_generation =
        generate_ballot_proof_inner(ballot_generation_input).map_err(|error| {
            invalid_preflight(format!(
                "full ballot proof generation failed: {}",
                error.message
            ))
        })?;
    let generated_ballot_proof =
        generated_proof_bytes(&ballot_generation, "generated ballot proof")?;
    let bound_parameter_set = proof_contract_with_expected_size(
        parameter_set,
        generated_ballot_proof.proof_size_bytes,
        "parameterSet",
    )?;
    let bound_proof_encoding = proof_contract_with_expected_size(
        proof_encoding,
        generated_ballot_proof.proof_size_bytes,
        "proofEncoding",
    )?;
    let ballot_proof = generated_ballot_proof_record(GeneratedBallotProofRecordInput {
        statement,
        linear_statement,
        parameter_set: &bound_parameter_set,
        proof_encoding: &bound_proof_encoding,
        public_randomness_hex,
        component_bundle_statement,
        component_proof_bundle: &component_proof_bundle,
        proof_bytes_hex: &generated_ballot_proof.proof_bytes_hex,
        proof_size_bytes: generated_ballot_proof.proof_size_bytes,
    })?;
    let component_proof_inputs = Value::Array(generated_component_inputs);
    let verification = verify_ballot_proof(
        statement,
        &ballot_proof,
        BallotProofVerificationInputs {
            component_bundle_statement: Some(component_bundle_statement),
            component_proof_bundle: Some(&component_proof_bundle),
            component_proof_inputs: Some(&component_proof_inputs),
            linear_statement: Some(linear_statement),
            parameter_set: Some(&bound_parameter_set),
            proof_bytes_hex: Some(&generated_ballot_proof.proof_bytes_hex),
            proof_encoding: Some(&bound_proof_encoding),
            public_randomness_hex: Some(public_randomness_hex),
            component_proof_verification_mode:
                ComponentProofVerificationMode::AlreadyVerifiedDuringGeneration,
            unsafe_small_roster_acknowledged: false,
        },
    );
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(format!(
            "generated ballot proof record did not verify: {verification}"
        )));
    }

    Ok(json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "generateBallotProofRecord",
        "statusLabels": [
            "BallotGeneratedProofVerified",
            "BallotComponentProofBundleGenerated",
            "BallotProofRecordGenerated",
            "BallotProofRecordGeneratedProofVerified"
        ],
        "acceptedDigests": [
            string_field(&ballot_proof, "ballotProofRecordDigest"),
            string_field(&component_proof_bundle, "componentProofBundleDigest"),
            string_field(&ballot_proof, "proofBytesDigest")
        ],
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": true,
        "proofBytesHex": generated_ballot_proof.proof_bytes_hex,
        "proofSizeBytes": generated_ballot_proof.proof_size_bytes,
        "parameterSet": bound_parameter_set,
        "proofEncoding": bound_proof_encoding,
        "ballotProof": ballot_proof,
        "componentProofBundle": component_proof_bundle,
        "componentProofInputs": component_proof_inputs,
        "verification": verification
    }))
}

struct GeneratedProofBytes {
    proof_bytes_hex: String,
    proof_size_bytes: usize,
}

fn generated_proof_bytes(
    generation: &Value,
    label: &str,
) -> crate::encoding::CanonicalResult<GeneratedProofBytes> {
    let proof_bytes_hex = string_field(generation, "proofBytesHex")
        .ok_or_else(|| invalid_preflight(format!("{label} did not return proofBytesHex")))?
        .to_string();
    let proof_size_bytes = object_map(generation)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size| usize::try_from(proof_size).ok())
        .ok_or_else(|| invalid_preflight(format!("{label} did not return proofSizeBytes")))?;

    Ok(GeneratedProofBytes {
        proof_bytes_hex,
        proof_size_bytes,
    })
}

pub(crate) fn component_generation_randomness_hex(
    component_id: &str,
    component_prover_randomness_hexes: &Value,
) -> crate::encoding::CanonicalResult<String> {
    if component_proof_bytes_must_be_empty(component_id) {
        return Ok("00".repeat(32));
    }
    object_map(component_prover_randomness_hexes)
        .and_then(|object| object.get(component_id))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            invalid_preflight(format!(
                "componentProverRandomnessHexes.{component_id} is required for proof generation"
            ))
        })
}

pub(crate) fn component_generation_secret_state<'a>(
    component_id: &str,
    default_secret_state: &'a Value,
    component_secret_states: Option<&'a Value>,
) -> crate::encoding::CanonicalResult<&'a Value> {
    let Some(component_secret_states) = component_secret_states else {
        return Ok(default_secret_state);
    };
    let component_secret_states = object_map(component_secret_states).ok_or_else(|| {
        invalid_preflight("componentSecretStates must be an object for ballot proof generation")
    })?;

    Ok(component_secret_states
        .get(component_id)
        .unwrap_or(default_secret_state))
}
