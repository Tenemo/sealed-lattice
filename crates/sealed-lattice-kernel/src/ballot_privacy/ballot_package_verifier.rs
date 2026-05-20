use super::*;

pub fn verify_claim_bearing_ballot_package(
    ballot_package: &Value,
    unsafe_small_roster_acknowledged: bool,
) -> Value {
    let refused_objects =
        collect_claim_bearing_package_refusals(ballot_package, unsafe_small_roster_acknowledged);
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
    let statement = package_object
        .get("ballotProofStatement")
        .unwrap_or(&Value::Null);
    let ballot_proof = package_object.get("ballotProof").unwrap_or(&Value::Null);
    let verification = verify_ballot_proof(
        statement,
        ballot_proof,
        BallotProofVerificationInputs {
            component_bundle_statement: package_object.get("componentBundleStatement"),
            component_proof_bundle: package_object.get("componentProofBundle"),
            component_proof_inputs: package_object.get("componentProofInputs"),
            linear_statement: package_object.get("linearStatement"),
            parameter_set: package_object.get("parameterSet"),
            proof_bytes_hex: package_object.get("proofBytesHex").and_then(Value::as_str),
            proof_encoding: package_object.get("proofEncoding"),
            public_randomness_hex: package_object
                .get("publicRandomnessHex")
                .and_then(Value::as_str),
            component_proof_verification_mode: ComponentProofVerificationMode::VerifyBackend,
            unsafe_small_roster_acknowledged,
        },
    );
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "verifyClaimBearingBallotPackage",
            "statusLabels": verification
                .as_object()
                .and_then(|object| object.get("statusLabels"))
                .cloned()
                .unwrap_or_else(|| json!([])),
            "acceptedDigests": verification
                .as_object()
                .and_then(|object| object.get("acceptedDigests"))
                .cloned()
                .unwrap_or_else(|| json!([])),
            "refusedObjects": verification
                .as_object()
                .and_then(|object| object.get("refusedObjects"))
                .cloned()
                .unwrap_or_else(|| json!([
                    {
                        "code": "BallotPackageInvalid",
                        "message": "Claim-bearing ballot package proof verification failed without a structured refusal.",
                        "objectDigest": string_field(ballot_package, "ballotPackageDigest")
                    }
                ])),
            "unresolvedReason": verification
                .as_object()
                .and_then(|object| object.get("unresolvedReason"))
                .cloned()
                .unwrap_or_else(|| json!("BallotPackageInvalid"))
        });
    }

    let mut status_labels = vec![
        json!("BallotPrivacyPackageDigestRecomputed"),
        json!("ReceiverKeyProofRootEvidenceChecked"),
    ];
    if let Some(verification_labels) = verification
        .as_object()
        .and_then(|object| object.get("statusLabels"))
        .and_then(Value::as_array)
    {
        status_labels.extend(verification_labels.iter().cloned());
    }
    let mut accepted_digests = vec![];
    if let Some(package_digest) = string_field(ballot_package, "ballotPackageDigest") {
        accepted_digests.push(json!(package_digest));
    }
    if let Some(evidence_digest) = package_object
        .get("receiverKeyProofRootEvidence")
        .and_then(|evidence| string_field(evidence, "receiverKeyProofRootEvidenceDigest"))
    {
        accepted_digests.push(json!(evidence_digest));
    }
    if let Some(verification_digests) = verification
        .as_object()
        .and_then(|object| object.get("acceptedDigests"))
        .and_then(Value::as_array)
    {
        accepted_digests.extend(verification_digests.iter().cloned());
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

pub fn verify_linear_proof_vector_case(vector_case: &Value) -> Value {
    linear_proof_verifier::verify_linear_proof_vector_case_value(vector_case)
}

pub fn verify_encoded_relation_vector_case(vector_case: &Value) -> Value {
    encoded_relation_vectors::verify_encoded_relation_vector_case_value(vector_case)
}

pub fn verify_receiver_key_vector_case(vector_case: &Value) -> Value {
    receiver_key_vectors::verify_receiver_key_vector_case_value(vector_case)
}
