use std::collections::BTreeSet;

mod relation_proof;
#[cfg(test)]
mod tests;
mod validation;

use relation_proof::{
    VerifyAggregateRelationProofInput, generate_aggregate_relation_proof,
    verify_aggregate_relation_proof,
};
use validation::{
    collect_aggregate_component_refusals, collect_aggregate_counted_package_preflight_refusals,
    collect_aggregate_counted_package_refusals, collect_aggregate_post_close_context_refusals,
    collect_aggregate_proof_input_refusals,
};

use super::*;

const AGGREGATE_DERIVATION_COMPONENT_ID: &str = "aggregate-derivation-component";
const AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID: &str =
    "aggregate-derivation-linear-compatibility-v1";
const AGGREGATE_DERIVATION_PROOF_ENCODING_PROFILE_ID: &str =
    "aggregate-derivation-linear-proof-encoding-v1";
const AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT: &str =
    "sparse-polynomial-matrix-linear-proof-v1";
const AGGREGATE_DERIVATION_SOURCE_RING_DEGREE: usize = 256;
const AGGREGATE_DERIVATION_PROOF_RING_DEGREE: usize = 64;
const AGGREGATE_DERIVATION_WITNESS_L2_BOUND_SQUARED: u128 = 3_000_000_000_000_000;
const AGGREGATE_DERIVATION_PROOF_MODULUS: u64 = 70_368_744_177_829;
const AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT: usize = 3;
const AGGREGATE_DERIVATION_CHALLENGE_SOUNDNESS_BITS: u64 = 138;

pub(crate) fn generate_aggregate_derivation_proof_from_command_request(request: &Value) -> Value {
    let proof_input =
        match required_json_field(request, "proofInput", "generateAggregateDerivationProof") {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "generateAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let secret_state =
        match required_json_field(request, "secretState", "generateAggregateDerivationProof") {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "generateAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let prover_randomness_hex = match required_string_field(
        request,
        "proverRandomnessHex",
        "generateAggregateDerivationProof",
    ) {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "generateAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };

    let refused_objects = collect_aggregate_proof_input_refusals(proof_input, None, false);
    if !refused_objects.is_empty() {
        return structural_rejection("generateAggregateDerivationProof", refused_objects);
    }

    let generation =
        generate_aggregate_relation_proof(proof_input, secret_state, prover_randomness_hex);

    match generation {
        Ok(generation) => json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "generateAggregateDerivationProof",
            "componentId": AGGREGATE_DERIVATION_COMPONENT_ID,
            "statusLabels": [
                "AggregateDerivationProofGenerated"
            ],
            "acceptedDigests": [],
            "refusedObjects": [],
            "unresolvedReason": Value::Null,
            "generatedProofBytes": true,
            "proofBytesHex": generation.proof_hex,
            "proofSizeBytes": generation.proof_size_bytes,
            "summary": {
                "challengeHex": generation.challenge_hex,
                "relationCommitmentDigest": generation.relation_commitment_digest
            }
        }),
        Err(error) => structural_rejection(
            "generateAggregateDerivationProof",
            vec![error.to_json_value()],
        ),
    }
}

pub(crate) fn verify_aggregate_derivation_proof_from_command_request(request: &Value) -> Value {
    let Some(component) = request.get("component") else {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                "verifyAggregateDerivationProof.component is required for aggregate derivation component checking.",
                None,
            )],
        );
    };
    let counted_ballot_packages = request.get("countedBallotPackages");
    let close_record = request.get("closeRecord");
    let contributor_action_context = request.get("contributorActionContext");
    let unsafe_small_roster_acknowledged = request
        .get("unsafeSmallRosterAcknowledged")
        .and_then(Value::as_bool)
        == Some(true)
        || request
            .get("casualMicroRosterAcknowledged")
            .and_then(Value::as_bool)
            == Some(true);
    let proof_input = match required_json_field(component, "proofInput", "component") {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };
    let object_digest = string_field(component, "aggregateDerivationComponentDigest")
        .or_else(|| string_field(proof_input, "statementDigest"));
    let mut refused_objects =
        collect_aggregate_proof_input_refusals(proof_input, Some(component), true);
    refused_objects.extend(collect_aggregate_component_refusals(component));
    refused_objects.extend(collect_aggregate_post_close_context_refusals(
        close_record,
        contributor_action_context,
        component,
    ));
    refused_objects.extend(collect_aggregate_counted_package_preflight_refusals(
        counted_ballot_packages,
        component,
    ));
    if !refused_objects.is_empty() {
        return structural_rejection("verifyAggregateDerivationProof", refused_objects);
    }

    let proof_statement = match required_json_field(proof_input, "proofStatement", "proofInput") {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };
    let parameter_set_value =
        match required_json_field(proof_input, "proofParameterSet", "proofInput") {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "verifyAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let proof_encoding_value = match required_json_field(proof_input, "proofEncoding", "proofInput")
    {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };
    let public_randomness_hex =
        match required_string_field(proof_input, "publicRandomnessHex", "proofInput") {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "verifyAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let proof_hex = match required_string_field(proof_input, "proofBytesHex", "proofInput") {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };
    if let Err(error) =
        serde_json::from_value::<LinearProofParameterSet>(parameter_set_value.clone())
    {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                format!("Aggregate derivation parameter set is malformed: {error}"),
                object_digest,
            )],
        );
    }
    if let Err(error) = serde_json::from_value::<LinearProofEncoding>(proof_encoding_value.clone())
    {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                format!("Aggregate derivation proof encoding is malformed: {error}"),
                object_digest,
            )],
        );
    }
    let parsed_sparse_statement =
        match sparse_matrix_from_sparse_component_statement(proof_statement) {
            Ok(value) => value,
            Err(error) => {
                return component_proof_backend_rejection(
                    "verifyAggregateDerivationProof",
                    AGGREGATE_DERIVATION_COMPONENT_ID,
                    vec![json!({
                        "code": error.code,
                        "message": error.message,
                        "objectDigest": object_digest
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        match required_json_field(
            proof_statement,
            "targetCoefficientRepresentation",
            "proofInput.proofStatement",
        )
        .and_then(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "Aggregate derivation target coefficient representation is malformed: {error}"
                ))
            })
        }) {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "verifyAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let matrix_coefficient_representation = match matrix_coefficient_representation_from_statement(
        proof_statement,
        "proofInput.proofStatement",
    ) {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };

    if let Err(error) = verify_aggregate_relation_proof(VerifyAggregateRelationProofInput {
        proof_statement,
        public_randomness_hex,
        proof_hex,
        source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
        target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
        matrix_coefficient_representation,
        target_coefficient_representation,
    }) {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                format!(
                    "Aggregate derivation relation proof is invalid: {}",
                    error.message
                ),
                object_digest,
            )],
        );
    }

    let counted_package_refusals = collect_aggregate_counted_package_refusals(
        counted_ballot_packages,
        component,
        unsafe_small_roster_acknowledged,
    );
    if !counted_package_refusals.is_empty() {
        return structural_rejection("verifyAggregateDerivationProof", counted_package_refusals);
    }

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "verifyAggregateDerivationProof",
        "componentId": AGGREGATE_DERIVATION_COMPONENT_ID,
        "statusLabels": [
            "AggregateDerivationRelationChecked",
            "AggregateDerivationProofClaimClosureMissing"
        ],
        "acceptedDigests": object_digest.map(|digest| vec![digest]).unwrap_or_default(),
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}
