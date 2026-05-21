use super::*;

const CLAIM_PACKAGE_VERIFIER_DERIVATION_REQUIRED_MESSAGE: &str = "Claim-bearing ballot package verification requires verifier-derived lowered relation statements and trusted public randomness; supplied lowered statements, proof inputs, and public randomness are not accepted as package evidence.";

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

    let package_digest = string_field(ballot_package, "ballotPackageDigest").or_else(|| {
        package_object
            .get("ballotProofStatement")
            .and_then(|statement| string_field(statement, "ballotPackageDigest"))
    });

    structural_rejection(
        "verifyClaimBearingBallotPackage",
        vec![structural_refusal(
            CLAIM_PACKAGE_VERIFIER_DERIVATION_REQUIRED_MESSAGE,
            package_digest,
        )],
    )
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
