use super::*;

fn required_package_field_refusal(
    package_hash: Option<&str>,
    field_name: &str,
    field_description: &str,
) -> Value {
    structural_refusal(
        format!(
            "Claim-bearing ballot package verification requires {field_description} in {field_name}."
        ),
        package_hash,
    )
}

fn package_field<'a>(
    package_object: &'a serde_json::Map<String, Value>,
    field_name: &str,
) -> Option<&'a Value> {
    package_object
        .get(field_name)
        .filter(|value| !value.is_null())
}

fn relabel_package_verification(
    mut verification: Value,
    package_hash: Option<&str>,
    ballot_proof_verification: &Value,
) -> Value {
    let Some(verification_object) = verification.as_object_mut() else {
        return verification;
    };

    verification_object.insert(
        "operation".to_string(),
        json!("verifyClaimBearingBallotPackage"),
    );

    if verification_object.get("ok").and_then(Value::as_bool) == Some(true) {
        let mut status_labels = vec![
            json!("ClaimBearingBallotPackageHashRecomputed"),
            json!("ClaimBearingBallotPackageVerified"),
        ];
        if let Some(ballot_status_labels) = ballot_proof_verification
            .as_object()
            .and_then(|object| object.get("statusLabels"))
            .and_then(Value::as_array)
        {
            status_labels.extend(ballot_status_labels.iter().cloned());
        }
        verification_object.insert("statusLabels".to_string(), Value::Array(status_labels));

        let mut accepted_hashes = Vec::new();
        if let Some(package_hash) = package_hash {
            accepted_hashes.push(Value::String(package_hash.to_string()));
        }
        if let Some(ballot_accepted_hashes) = ballot_proof_verification
            .as_object()
            .and_then(|object| object.get("acceptedHashes"))
            .and_then(Value::as_array)
        {
            accepted_hashes.extend(ballot_accepted_hashes.iter().cloned());
        }
        verification_object.insert("acceptedHashes".to_string(), Value::Array(accepted_hashes));
    }

    verification
}

pub fn verify_claim_bearing_ballot_package(
    ballot_package: &Value,
    dynamic_roster_profile_evidence: Option<&Value>,
    casual_micro_roster_acknowledged: bool,
) -> Value {
    let refused_objects = collect_claim_bearing_package_refusals(
        ballot_package,
        dynamic_roster_profile_evidence,
        casual_micro_roster_acknowledged,
    );
    if !refused_objects.is_empty() {
        return structural_rejection("verifyClaimBearingBallotPackage", refused_objects);
    }

    let Some(package_object) = object_map(ballot_package) else {
        return structural_rejection(
            "verifyClaimBearingBallotPackage",
            vec![structural_refusal(
                "Claim-bearing ballot package shell hash or shape is invalid.",
                None,
            )],
        );
    };

    let package_hash = string_field(ballot_package, "ballotPackageHash").or_else(|| {
        package_object
            .get("ballotProofStatement")
            .and_then(|statement| string_field(statement, "ballotPackageHash"))
    });

    let statement = package_object
        .get("ballotProofStatement")
        .unwrap_or(&Value::Null);
    let ballot_proof = package_object.get("ballotProof").unwrap_or(&Value::Null);
    let mut missing_inputs = Vec::new();
    let proof_bytes_hex = string_field(ballot_package, "proofBytesHex");
    let public_randomness_hex = string_field(ballot_package, "publicRandomnessHex");
    let linear_statement = package_field(package_object, "linearStatement");
    let parameter_set = package_field(package_object, "parameterSet");
    let proof_encoding = package_field(package_object, "proofEncoding");
    let component_bundle_statement = package_field(package_object, "componentBundleStatement");
    let component_proof_bundle = package_field(package_object, "componentProofBundle");
    let component_proof_inputs = package_field(package_object, "componentProofInputs");
    let package_dynamic_roster_profile_evidence = dynamic_roster_profile_evidence
        .or_else(|| package_object.get("dynamicRosterProfileEvidence"));

    if proof_bytes_hex.is_none() {
        missing_inputs.push(required_package_field_refusal(
            package_hash,
            "proofBytesHex",
            "public ballot proof bytes",
        ));
    }
    if public_randomness_hex.is_none() {
        missing_inputs.push(required_package_field_refusal(
            package_hash,
            "publicRandomnessHex",
            "public ballot proof randomness",
        ));
    }
    if linear_statement.is_none() {
        missing_inputs.push(required_package_field_refusal(
            package_hash,
            "linearStatement",
            "the public ballot proof linear statement",
        ));
    }
    if parameter_set.is_none() {
        missing_inputs.push(required_package_field_refusal(
            package_hash,
            "parameterSet",
            "the public ballot proof parameter set",
        ));
    }
    if proof_encoding.is_none() {
        missing_inputs.push(required_package_field_refusal(
            package_hash,
            "proofEncoding",
            "the public ballot proof encoding profile",
        ));
    }
    if component_bundle_statement.is_none() {
        missing_inputs.push(required_package_field_refusal(
            package_hash,
            "componentBundleStatement",
            "the public component bundle statement",
        ));
    }
    if component_proof_bundle.is_none() {
        missing_inputs.push(required_package_field_refusal(
            package_hash,
            "componentProofBundle",
            "the full component proof bundle",
        ));
    }
    if component_proof_inputs.is_none() {
        missing_inputs.push(required_package_field_refusal(
            package_hash,
            "componentProofInputs",
            "public verifier inputs for every component proof",
        ));
    }
    if !missing_inputs.is_empty() {
        return structural_rejection("verifyClaimBearingBallotPackage", missing_inputs);
    }

    let ballot_proof_verification = verify_ballot_proof(
        statement,
        ballot_proof,
        BallotProofVerificationInputs {
            component_bundle_statement,
            component_proof_bundle,
            component_proof_inputs,
            dynamic_roster_profile_evidence: package_dynamic_roster_profile_evidence,
            linear_statement,
            parameter_set,
            proof_bytes_hex,
            proof_encoding,
            public_randomness_hex,
            component_proof_verification_mode: ComponentProofVerificationMode::VerifyBackend,
            casual_micro_roster_acknowledged,
        },
    );

    relabel_package_verification(
        ballot_proof_verification.clone(),
        package_hash,
        &ballot_proof_verification,
    )
}

pub fn verify_linear_proof_vector_case(vector_case: &Value) -> Value {
    linear_proof_verifier::verify_linear_proof_vector_case_value(vector_case)
}

pub fn verify_encoded_relation_vector_case(vector_case: &Value) -> Value {
    encoded_relation_vectors::verify_encoded_relation_vector_case_value(vector_case)
}

pub fn verify_receiver_key_vector_case(vector_case: &Value) -> Value {
    receiver_key::verify_receiver_key_vector_case_value(vector_case)
}
