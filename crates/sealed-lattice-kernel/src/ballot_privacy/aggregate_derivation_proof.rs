use std::collections::BTreeSet;

use crate::encoding::CanonicalResult;

mod relation_proof;
#[cfg(test)]
mod tests;
mod validation;

use relation_proof::{
    AggregateRelationProofVerification, VerifyAggregateRelationProofInput,
    generate_aggregate_relation_proof, verify_aggregate_relation_proof,
};
use validation::{
    collect_aggregate_component_refusals, collect_aggregate_counted_package_preflight_refusals,
    collect_aggregate_counted_package_refusals, collect_aggregate_post_close_context_refusals,
    collect_aggregate_proof_input_refusals,
};

use super::*;

const AGGREGATE_DERIVATION_COMPONENT_ID: &str = "aggregate-derivation-component";
const AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID: &str =
    "aggregate-derivation-linear-proof-parameter-v1";
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
const MAX_AGGREGATE_DERIVATION_RELATION_PROOF_BYTES: usize = 64 * 1024 * 1024;

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
            "acceptedHashes": [],
            "refusedObjects": [],
            "unresolvedReason": Value::Null,
            "generatedProofBytes": true,
            "proofBytesHex": generation.proof_hex,
            "proofSizeBytes": generation.proof_size_bytes,
            "summary": {
                "challengeHex": generation.challenge_hex,
                "relationCommitmentHash": generation.relation_commitment_hash
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
    let casual_micro_roster_acknowledged = request
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
    let object_hash = string_field(component, "aggregateDerivationComponentHash")
        .or_else(|| string_field(proof_input, "statementHash"));
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
                object_hash,
            )],
        );
    }
    if let Err(error) = serde_json::from_value::<LinearProofEncoding>(proof_encoding_value.clone())
    {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                format!("Aggregate derivation proof encoding is malformed: {error}"),
                object_hash,
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
                        "objectHash": object_hash
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
                object_hash,
            )],
        );
    }

    let counted_package_refusals = collect_aggregate_counted_package_refusals(
        counted_ballot_packages,
        component,
        casual_micro_roster_acknowledged,
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
        "acceptedHashes": object_hash.map(|hash| vec![hash]).unwrap_or_default(),
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

pub(crate) fn verify_aggregate_derivation_relation_subproof_for_component(
    component: &Value,
    proof_hex: &str,
) -> crate::encoding::CanonicalResult<AggregateRelationProofVerification> {
    let proof_input = required_json_field(component, "proofInput", "component")?;
    let mut refused_objects =
        collect_aggregate_proof_input_refusals(proof_input, Some(component), true);
    refused_objects.extend(collect_aggregate_component_refusals(component));
    if !refused_objects.is_empty() {
        let refusal_messages = refused_objects
            .iter()
            .filter_map(|refusal| string_field(refusal, "message"))
            .collect::<Vec<_>>()
            .join(" ");
        return Err(invalid_preflight(format!(
            "Aggregate derivation component binding is invalid for bridge verification: {refusal_messages}"
        )));
    }
    let proof_statement = required_json_field(proof_input, "proofStatement", "proofInput")?;
    let parameter_set_value = required_json_field(proof_input, "proofParameterSet", "proofInput")?;
    let proof_encoding_value = required_json_field(proof_input, "proofEncoding", "proofInput")?;
    let public_randomness_hex =
        required_string_field(proof_input, "publicRandomnessHex", "proofInput")?;
    serde_json::from_value::<LinearProofParameterSet>(parameter_set_value.clone()).map_err(
        |error| {
            invalid_preflight(format!(
                "Aggregate derivation parameter set is malformed: {error}"
            ))
        },
    )?;
    serde_json::from_value::<LinearProofEncoding>(proof_encoding_value.clone()).map_err(
        |error| {
            invalid_preflight(format!(
                "Aggregate derivation proof encoding is malformed: {error}"
            ))
        },
    )?;
    let parsed_sparse_statement = sparse_matrix_from_sparse_component_statement(proof_statement)
        .map_err(|error| invalid_preflight(error.message))?;
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        required_json_field(
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
        })?;
    let matrix_coefficient_representation = matrix_coefficient_representation_from_statement(
        proof_statement,
        "proofInput.proofStatement",
    )?;

    verify_aggregate_relation_proof(VerifyAggregateRelationProofInput {
        proof_statement,
        public_randomness_hex,
        proof_hex,
        source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
        target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
        matrix_coefficient_representation,
        target_coefficient_representation,
    })
}

pub(crate) struct AggregateDerivationWitnessRelationCheck {
    pub(crate) proof_hex: String,
    pub(crate) proof_size_bytes: usize,
    pub(crate) challenge_hex: String,
    pub(crate) relation_commitment_hash: String,
    pub(crate) reduced_field_vector: Vec<u64>,
    pub(crate) quotient_vector: Vec<u64>,
}

pub(crate) fn check_aggregate_derivation_witness_relation(
    proof_input: &Value,
    aggregate_integer_share_vector: &[u64],
    aggregate_opening_randomness: &[i64],
    canonical_turnout: u64,
    prover_randomness_hex: &str,
) -> crate::encoding::CanonicalResult<AggregateDerivationWitnessRelationCheck> {
    if aggregate_integer_share_vector.is_empty()
        || aggregate_integer_share_vector.len() > AGGREGATE_DERIVATION_SOURCE_RING_DEGREE
    {
        return Err(invalid_preflight(
            "M9 bridge aggregate witness share vector has an unsupported width",
        ));
    }
    if aggregate_opening_randomness.len() != SHARE_COMMITMENT_OPENING_DIMENSION {
        return Err(invalid_preflight(
            "M9 bridge aggregate opening randomness has an invalid width",
        ));
    }
    let maximum_aggregate_integer = canonical_turnout
        .checked_mul(BALLOT_PRIVACY_FIELD_MODULUS - 1)
        .ok_or_else(|| invalid_preflight("M9 bridge aggregate witness bound overflowed"))?;
    let mut reduced_field_vector = Vec::with_capacity(aggregate_integer_share_vector.len());
    let mut quotient_vector = Vec::with_capacity(aggregate_integer_share_vector.len());
    for share_coordinate in aggregate_integer_share_vector {
        if *share_coordinate > maximum_aggregate_integer {
            return Err(invalid_preflight(
                "M9 bridge aggregate witness exceeds the no-wraparound certificate bound",
            ));
        }
        let reduced_coordinate = share_coordinate % BALLOT_PRIVACY_FIELD_MODULUS;
        let quotient = (share_coordinate - reduced_coordinate) / BALLOT_PRIVACY_FIELD_MODULUS;
        if quotient > canonical_turnout {
            return Err(invalid_preflight(
                "M9 bridge aggregate quotient exceeds the turnout bound",
            ));
        }
        reduced_field_vector.push(reduced_coordinate);
        quotient_vector.push(quotient);
    }

    let mut source_witness_coefficients = Vec::with_capacity(
        aggregate_integer_share_vector.len()
            + aggregate_opening_randomness.len()
            + reduced_field_vector.len()
            + quotient_vector.len(),
    );
    for share_coordinate in aggregate_integer_share_vector {
        source_witness_coefficients.push(constant_u64_source_witness_polynomial(
            *share_coordinate,
            "integer share coordinate",
        )?);
    }
    for opening_coordinate in aggregate_opening_randomness {
        source_witness_coefficients.push(constant_source_witness_polynomial(*opening_coordinate));
    }
    for reduced_coordinate in &reduced_field_vector {
        source_witness_coefficients.push(constant_u64_source_witness_polynomial(
            *reduced_coordinate,
            "reduced field coordinate",
        )?);
    }
    for quotient_coordinate in &quotient_vector {
        source_witness_coefficients.push(constant_u64_source_witness_polynomial(
            *quotient_coordinate,
            "quotient coordinate",
        )?);
    }
    let secret_state = json!({
        "sourceWitnessCoefficients": source_witness_coefficients,
    });
    let generation =
        generate_aggregate_relation_proof(proof_input, &secret_state, prover_randomness_hex)?;

    Ok(AggregateDerivationWitnessRelationCheck {
        proof_hex: generation.proof_hex,
        proof_size_bytes: generation.proof_size_bytes,
        challenge_hex: generation.challenge_hex,
        relation_commitment_hash: generation.relation_commitment_hash,
        reduced_field_vector,
        quotient_vector,
    })
}

fn constant_source_witness_polynomial(coefficient: i64) -> Vec<i64> {
    let mut polynomial = vec![0_i64; AGGREGATE_DERIVATION_SOURCE_RING_DEGREE];
    polynomial[0] = coefficient;

    polynomial
}

fn constant_u64_source_witness_polynomial(
    coefficient: u64,
    description: &str,
) -> CanonicalResult<Vec<i64>> {
    let signed_coefficient = i64::try_from(coefficient).map_err(|_| {
        invalid_preflight(format!(
            "Bridge aggregate derivation witness {description} exceeds signed proof encoding range",
        ))
    })?;

    Ok(constant_source_witness_polynomial(signed_coefficient))
}
