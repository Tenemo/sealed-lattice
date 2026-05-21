use super::*;

pub fn verify_claim_bearing_ballot_package(
    ballot_package: &Value,
    unsafe_small_roster_acknowledged: bool,
) -> Value {
    let refused_objects = collect_claim_bearing_package_shell_refusals(ballot_package);
    if !refused_objects.is_empty() {
        return structural_rejection("verifyClaimBearingBallotPackage", refused_objects);
    }

    let Some(package_object) = object_map(ballot_package) else {
        return structural_rejection(
            "verifyClaimBearingBallotPackage",
            vec![structural_refusal(
                "Claim-bearing ballot package shell digest or shape is invalid.",
                None,
            )],
        );
    };

    let package_digest = string_field(ballot_package, "ballotPackageDigest").or_else(|| {
        package_object
            .get("ballotProofStatement")
            .and_then(|statement| string_field(statement, "ballotPackageDigest"))
    });

    let proof_verification = verify_ballot_proof(
        package_object
            .get("ballotProofStatement")
            .unwrap_or(&Value::Null),
        package_object.get("ballotProof").unwrap_or(&Value::Null),
        BallotProofVerificationInputs {
            component_bundle_statement: package_object.get("componentBundleStatement"),
            component_proof_bundle: package_object.get("componentProofBundle"),
            component_proof_inputs: package_object.get("componentProofInputs"),
            component_proof_verification_mode: ComponentProofVerificationMode::VerifyBackend,
            linear_statement: package_object.get("linearStatement"),
            parameter_set: package_object.get("parameterSet"),
            proof_bytes_hex: package_object.get("proofBytesHex").and_then(Value::as_str),
            proof_encoding: package_object.get("proofEncoding"),
            public_randomness_hex: package_object
                .get("publicRandomnessHex")
                .and_then(Value::as_str),
            unsafe_small_roster_acknowledged,
        },
    );

    if proof_verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return retag_verification_operation(proof_verification, "verifyClaimBearingBallotPackage");
    }

    let mut status_labels = vec![
        json!("ClaimBearingBallotPackageDigestRecomputed"),
        json!("ClaimBearingBallotPackageShellBound"),
        json!("ClaimBearingBallotPackageProofVerified"),
    ];
    if let Some(proof_status_labels) = proof_verification
        .as_object()
        .and_then(|object| object.get("statusLabels"))
        .and_then(Value::as_array)
    {
        status_labels.extend(proof_status_labels.iter().cloned());
    }
    let mut accepted_digests = package_digest
        .map(Value::from)
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(proof_accepted_digests) = proof_verification
        .as_object()
        .and_then(|object| object.get("acceptedDigests"))
        .and_then(Value::as_array)
    {
        accepted_digests.extend(proof_accepted_digests.iter().cloned());
    }

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "verifyClaimBearingBallotPackage",
        "statusLabels": status_labels,
        "acceptedDigests": accepted_digests,
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

fn retag_verification_operation(mut verification: Value, operation: &str) -> Value {
    if let Some(object) = verification.as_object_mut() {
        object.insert("operation".to_owned(), json!(operation));
    }

    verification
}

pub fn verify_linear_proof_vector_case(vector_case: &Value) -> Value {
    linear_proof_verifier::verify_linear_proof_vector_case_value(vector_case)
}

pub fn verify_encoded_relation_vector_case(vector_case: &Value) -> Value {
    encoded_relation_vectors::verify_encoded_relation_vector_case_value(vector_case)
}

pub fn verify_receiver_key_vector_case(vector_case: &Value) -> Value {
    receiver_key_vectors::verify_receiver_key_vector_case_value(vector_case)
}
