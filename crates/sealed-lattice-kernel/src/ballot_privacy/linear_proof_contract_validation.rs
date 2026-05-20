use super::protocol_constants::{
    MANDATORY_CLAIM_OPTION_COUNT, MANDATORY_CLAIM_RECEIVER_COUNT,
    MANDATORY_CLAIM_SHARE_VECTOR_WIDTH,
};
use super::*;

const FULL_BALLOT_BINDING_PARAMETER_SOURCE: &str =
    "sealed-lattice/linear-proof/full-ballot-binding-parameters-v1";
const FULL_BALLOT_BINDING_ENCODING_SOURCE: &str =
    "sealed-lattice/linear-proof/full-ballot-binding-encoding-v1";

#[derive(Clone, Copy)]
struct LinearContractExpectation {
    coefficient_modulus: u128,
    encoding_profile_id: &'static str,
    encoding_source: &'static str,
    parameter_profile_id: &'static str,
    parameter_source: &'static str,
    proof_system_ring_degree: u128,
    ring_degree: u128,
    short_response_vector_length: u128,
    statement_columns: u128,
    statement_rows: u128,
    witness_l2_bound_squared: u128,
}

pub(crate) fn collect_mandatory_claim_profile_refusals(
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mandatory_shape_is_present = unsigned_integer_field(statement, "optionCount")
        == Some(MANDATORY_CLAIM_OPTION_COUNT)
        && unsigned_integer_field(statement, "shareVectorWidth")
            == Some(MANDATORY_CLAIM_SHARE_VECTOR_WIDTH)
        && array_field(statement, "receiverPublicKeys").map(Vec::len)
            == Some(MANDATORY_CLAIM_RECEIVER_COUNT)
        && array_field(statement, "receiverPayloads").map(Vec::len)
            == Some(MANDATORY_CLAIM_RECEIVER_COUNT)
        && array_field(statement, "shareCommitments").map(Vec::len)
            == Some(MANDATORY_CLAIM_RECEIVER_COUNT);

    if mandatory_shape_is_present {
        Vec::new()
    } else {
        vec![structural_refusal(
            "Claim-bearing ballot package must use the mandatory 20-option, 20-receiver, width-220 ballot privacy profile.",
            object_digest,
        )]
    }
}

pub(crate) fn collect_full_ballot_binding_contract_refusals(
    linear_statement: &Value,
    parameter_set: &Value,
    proof_encoding: &Value,
    proof_size_bytes: Option<usize>,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let expectation = LinearContractExpectation {
        coefficient_modulus: 65_537,
        encoding_profile_id: FULL_BALLOT_PROOF_ENCODING_PROFILE_ID,
        encoding_source: FULL_BALLOT_BINDING_ENCODING_SOURCE,
        parameter_profile_id: FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
        parameter_source: FULL_BALLOT_BINDING_PARAMETER_SOURCE,
        proof_system_ring_degree: 64,
        ring_degree: 64,
        short_response_vector_length: 2,
        statement_columns: 1,
        statement_rows: 1,
        witness_l2_bound_squared: 65_536,
    };
    let mut refused_objects = collect_linear_statement_contract_refusals(
        linear_statement,
        &expectation,
        object_digest,
        "Full ballot binding linear statement",
    );
    if string_field(linear_statement, "relationBindingKind")
        != Some("component-bundle-and-lowered-relation")
        || string_field(linear_statement, "relationBindingDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(linear_statement, "componentBundleStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
    {
        refused_objects.push(structural_refusal(
            "Full ballot binding linear statement must bind the component bundle and lowered relation.",
            object_digest,
        ));
    }
    refused_objects.extend(collect_parameter_contract_refusals(
        parameter_set,
        &expectation,
        proof_size_bytes,
        object_digest,
        "Full ballot binding parameter set",
        true,
    ));
    refused_objects.extend(collect_encoding_contract_refusals(
        proof_encoding,
        &expectation,
        proof_size_bytes,
        object_digest,
        "Full ballot binding proof encoding",
        true,
    ));

    refused_objects
}

pub(crate) fn collect_mandatory_component_contract_refusals(
    component_proof_bundle: Option<&Value>,
    component_proof_inputs: Option<&Value>,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let Some(component_proof_bundle) = component_proof_bundle else {
        return Vec::new();
    };
    let Some(component_proof_inputs) = component_proof_inputs.and_then(Value::as_array) else {
        return Vec::new();
    };
    let component_proofs = array_field(component_proof_bundle, "componentProofs")
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut refused_objects = Vec::new();

    for (component_index, component_id) in REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter().enumerate() {
        let Some(component_proof) = component_proofs.get(component_index) else {
            continue;
        };
        let Some(proof_input) = component_proof_inputs
            .iter()
            .find(|input| string_field(input, "componentId") == Some(component_id))
        else {
            continue;
        };
        refused_objects.extend(collect_component_contract_refusals(
            component_id,
            component_proof,
            proof_input,
            object_digest,
        ));
    }

    refused_objects
}

fn collect_component_contract_refusals(
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let Some(expectation) = mandatory_component_contract_expectation(component_id) else {
        return vec![structural_refusal(
            format!("Claim-bearing ballot package includes unsupported component {component_id}."),
            object_digest,
        )];
    };
    let mut refused_objects = Vec::new();
    let proof_statement = object_map(proof_input)
        .and_then(|object| object.get("proofStatement"))
        .unwrap_or(&Value::Null);

    if component_id == "receiver-key-binding-component" {
        refused_objects.extend(collect_public_zero_statement_contract_refusals(
            proof_statement,
            object_digest,
        ));
    } else {
        refused_objects.extend(collect_linear_statement_contract_refusals(
            proof_statement,
            &expectation,
            object_digest,
            &format!("Claim-bearing {component_id} proof statement"),
        ));
    }
    if string_field(proof_input, "proofStatementFormat")
        != mandatory_component_statement_format(component_id)
    {
        refused_objects.push(structural_refusal(
            format!("Claim-bearing {component_id} proof statement format is not the frozen mandatory format."),
            object_digest,
        ));
    }
    if string_field(proof_statement, "parameterProfileId") != Some(expectation.parameter_profile_id)
    {
        refused_objects.push(structural_refusal(
            format!("Claim-bearing {component_id} proof statement is not bound to the frozen parameter profile."),
            object_digest,
        ));
    }

    let proof_size_bytes = unsigned_integer_field(component_proof, "proofSizeBytes")
        .and_then(|value| usize::try_from(value).ok());
    let parameter_set = object_map(proof_input)
        .and_then(|object| object.get("proofParameterSet"))
        .unwrap_or(&Value::Null);
    let proof_encoding = object_map(proof_input)
        .and_then(|object| object.get("proofEncoding"))
        .unwrap_or(&Value::Null);

    refused_objects.extend(collect_parameter_contract_refusals(
        parameter_set,
        &expectation,
        proof_size_bytes,
        object_digest,
        &format!("Claim-bearing {component_id} parameter set"),
        component_id != "receiver-key-binding-component",
    ));
    refused_objects.extend(collect_encoding_contract_refusals(
        proof_encoding,
        &expectation,
        proof_size_bytes,
        object_digest,
        &format!("Claim-bearing {component_id} proof encoding"),
        component_id != "receiver-key-binding-component",
    ));

    refused_objects
}

fn mandatory_component_contract_expectation(
    component_id: &str,
) -> Option<LinearContractExpectation> {
    let common_field_encoding = |parameter_profile_id,
                                 parameter_source,
                                 encoding_profile_id,
                                 encoding_source,
                                 coefficient_modulus,
                                 ring_degree,
                                 statement_rows,
                                 statement_columns,
                                 witness_l2_bound_squared| {
        LinearContractExpectation {
            coefficient_modulus,
            encoding_profile_id,
            encoding_source,
            parameter_profile_id,
            parameter_source,
            proof_system_ring_degree: 64,
            ring_degree,
            short_response_vector_length: statement_columns * (ring_degree / 64) + 1,
            statement_columns,
            statement_rows,
            witness_l2_bound_squared,
        }
    };

    match component_id {
        "score-and-shamir-field-component" => Some(common_field_encoding(
            "encoded-score-field-linear-compatibility-v1",
            "sealed-lattice/linear-proof/score-and-shamir-field-component-parameters-v1",
            "encoded-score-field-linear-proof-encoding-v1",
            "sealed-lattice/linear-proof/score-and-shamir-field-component-encoding-v1",
            65_537,
            64,
            82,
            404,
            65_536,
        )),
        "payload-plaintext-field-component" => Some(common_field_encoding(
            "payload-plaintext-field-linear-compatibility-v1",
            "sealed-lattice/linear-proof/payload-plaintext-field-component-parameters-v1",
            "payload-plaintext-field-linear-proof-encoding-v1",
            "sealed-lattice/linear-proof/payload-plaintext-field-component-encoding-v1",
            65_537,
            64,
            200,
            1_800,
            65_536,
        )),
        "share-commitment-component" => Some(common_field_encoding(
            "share-commitment-linear-compatibility-v1",
            "sealed-lattice/linear-proof/share-commitment-component-parameters-v1",
            "share-commitment-linear-proof-encoding-v1",
            "sealed-lattice/linear-proof/share-commitment-component-encoding-v1",
            18_446_744_069_414_584_321,
            64,
            320,
            5_680,
            1_048_576,
        )),
        "receiver-encryption-component" => Some(common_field_encoding(
            "receiver-encryption-linear-compatibility-v1",
            "sealed-lattice/linear-proof/receiver-encryption-component-parameters-v1",
            "receiver-encryption-linear-proof-encoding-v1",
            "sealed-lattice/linear-proof/receiver-encryption-component-encoding-v1",
            12_289,
            256,
            1_800,
            3_600,
            65_536,
        )),
        "receiver-key-binding-component" => Some(LinearContractExpectation {
            coefficient_modulus: 12_289,
            encoding_profile_id: "receiver-encryption-linear-proof-encoding-v1",
            encoding_source: "sealed-lattice/linear-proof/receiver-key-binding-component-encoding-v1",
            parameter_profile_id: "receiver-key-binding-linear-compatibility-v1",
            parameter_source: "sealed-lattice/linear-proof/receiver-key-binding-component-parameters-v1",
            proof_system_ring_degree: 64,
            ring_degree: 64,
            short_response_vector_length: 2,
            statement_columns: 1,
            statement_rows: 1,
            witness_l2_bound_squared: 65_536,
        }),
        _ => None,
    }
}

fn mandatory_component_statement_format(component_id: &str) -> Option<&'static str> {
    match component_id {
        "score-and-shamir-field-component" | "payload-plaintext-field-component" => {
            Some(SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT)
        }
        "share-commitment-component" => Some(STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT),
        "receiver-encryption-component" => {
            Some(STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT)
        }
        "receiver-key-binding-component" => Some(PUBLIC_ZERO_PROOF_STATEMENT_FORMAT),
        _ => None,
    }
}

fn collect_linear_statement_contract_refusals(
    proof_statement: &Value,
    expectation: &LinearContractExpectation,
    object_digest: Option<&str>,
    label: &str,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    if unsigned_integer_field(proof_statement, "coefficientModulus")
        != Some(expectation.coefficient_modulus)
        || unsigned_integer_field(proof_statement, "sourceRingDegree")
            .or_else(|| unsigned_integer_field(proof_statement, "ringDegree"))
            != Some(expectation.ring_degree)
        || unsigned_integer_field(proof_statement, "statementRows")
            != Some(expectation.statement_rows)
        || unsigned_integer_field(proof_statement, "statementColumns")
            != Some(expectation.statement_columns)
        || unsigned_integer_field(proof_statement, "witnessL2BoundSquared")
            != Some(expectation.witness_l2_bound_squared)
    {
        refused_objects.push(structural_refusal(
            format!("{label} does not match the frozen proof dimensions."),
            object_digest,
        ));
    }
    if string_field(proof_statement, "relation") != Some("A*w + t = 0") {
        refused_objects.push(structural_refusal(
            format!("{label} does not use the frozen linear relation."),
            object_digest,
        ));
    }

    refused_objects
}

fn collect_public_zero_statement_contract_refusals(
    proof_statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    if string_field(proof_statement, "objectType") != Some("BallotProofComponentProofStatementPlan")
        || object_map(proof_statement)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(proof_statement, "componentId") != Some("receiver-key-binding-component")
        || string_field(proof_statement, "proofStatementFormat")
            != Some(PUBLIC_ZERO_PROOF_STATEMENT_FORMAT)
        || string_field(proof_statement, "proofBytesAvailability")
            != Some("public-zero-witness-binding-check")
        || string_field(proof_statement, "proofLoweringStatus") != Some("explicitRowsAvailable")
        || string_field(proof_statement, "relation") != Some("A*w + t = 0")
        || unsigned_integer_field(proof_statement, "coefficientModulus") != Some(12_289)
        || unsigned_integer_field(proof_statement, "rowCount") != Some(20_480)
        || unsigned_integer_field(proof_statement, "variableColumnCount") != Some(0)
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing receiver-key-binding-component proof statement does not match the frozen public-zero witness binding contract.",
            object_digest,
        ));
    }

    refused_objects
}

fn collect_parameter_contract_refusals(
    parameter_set: &Value,
    expectation: &LinearContractExpectation,
    proof_size_bytes: Option<usize>,
    object_digest: Option<&str>,
    label: &str,
    require_positive_proof_size: bool,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let expected_proof_size_bytes = proof_size_bytes.map(|value| value as u128);
    let proof_size_is_valid = if require_positive_proof_size {
        expected_proof_size_bytes.is_some_and(|value| value > 0)
    } else {
        expected_proof_size_bytes == Some(0)
    };

    if string_field(parameter_set, "profileId") != Some(expectation.parameter_profile_id)
        || string_field(parameter_set, "source") != Some(expectation.parameter_source)
        || string_field(parameter_set, "relation") != Some("A*w + t = 0")
        || unsigned_integer_field(parameter_set, "ringDegree") != Some(expectation.ring_degree)
        || unsigned_integer_field(parameter_set, "proofSystemRingDegree")
            != Some(expectation.proof_system_ring_degree)
        || unsigned_integer_field(parameter_set, "coefficientModulus")
            != Some(expectation.coefficient_modulus)
        || unsigned_integer_field(parameter_set, "statementRows")
            != Some(expectation.statement_rows)
        || unsigned_integer_field(parameter_set, "statementColumns")
            != Some(expectation.statement_columns)
        || unsigned_integer_field(parameter_set, "witnessL2BoundSquared")
            != Some(expectation.witness_l2_bound_squared)
        || unsigned_integer_field(parameter_set, "expectedProofSizeBytes")
            != expected_proof_size_bytes
        || !proof_size_is_valid
    {
        refused_objects.push(structural_refusal(
            format!("{label} does not match the frozen contract."),
            object_digest,
        ));
    }

    refused_objects
}

fn collect_encoding_contract_refusals(
    proof_encoding: &Value,
    expectation: &LinearContractExpectation,
    proof_size_bytes: Option<usize>,
    object_digest: Option<&str>,
    label: &str,
    require_positive_proof_size: bool,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let expected_proof_size_bytes = proof_size_bytes.map(|value| value as u128);
    let proof_size_is_valid = if require_positive_proof_size {
        expected_proof_size_bytes.is_some_and(|value| value > 0)
    } else {
        expected_proof_size_bytes == Some(0)
    };

    if string_field(proof_encoding, "profileId") != Some(expectation.encoding_profile_id)
        || string_field(proof_encoding, "source") != Some(expectation.encoding_source)
        || unsigned_integer_field(proof_encoding, "ringDegree") != Some(64)
        || unsigned_integer_field(proof_encoding, "coefficientModulus") != Some(70_368_744_177_829)
        || unsigned_integer_field(proof_encoding, "fullSizeCoefficientBitLength") != Some(47)
        || unsigned_integer_field(proof_encoding, "compressedCoefficientBitLength") != Some(35)
        || unsigned_integer_field(proof_encoding, "targetCommitmentVectorLength") != Some(12)
        || unsigned_integer_field(proof_encoding, "hashMaskVectorLength") != Some(2)
        || unsigned_integer_field(proof_encoding, "compressedCommitmentVectorLength") != Some(18)
        || unsigned_integer_field(proof_encoding, "challengeCoefficientModulus") != Some(17)
        || unsigned_integer_field(proof_encoding, "challengeCoefficientBitLength") != Some(5)
        || unsigned_integer_field(proof_encoding, "hintVectorLength") != Some(18)
        || unsigned_integer_field(proof_encoding, "shortResponseVectorLength")
            != Some(expectation.short_response_vector_length)
        || unsigned_integer_field(proof_encoding, "randomnessResponseVectorLength") != Some(41)
        || unsigned_integer_field(proof_encoding, "euclideanResponseVectorLength") != Some(4)
        || unsigned_integer_field(proof_encoding, "infinityResponseVectorLength") != Some(4)
        || unsigned_integer_field(proof_encoding, "shortResponseLog2StandardDeviation") != Some(18)
        || unsigned_integer_field(proof_encoding, "randomnessResponseLog2StandardDeviation")
            != Some(12)
        || unsigned_integer_field(proof_encoding, "euclideanResponseLog2StandardDeviation")
            != Some(14)
        || unsigned_integer_field(proof_encoding, "infinityResponseLog2StandardDeviation")
            != Some(22)
        || unsigned_integer_field(proof_encoding, "expectedProofSizeBytes")
            != expected_proof_size_bytes
        || !proof_size_is_valid
    {
        refused_objects.push(structural_refusal(
            format!("{label} does not match the frozen contract."),
            object_digest,
        ));
    }

    refused_objects
}

fn unsigned_integer_field(value: &Value, field_name: &str) -> Option<u128> {
    match object_map(value)?.get(field_name)? {
        Value::Number(number) => number.as_u64().map(u128::from),
        Value::String(text) if unsigned_decimal_string(text) => text.parse::<u128>().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "label": label,
                "purpose": "linear-proof-contract-validation-test",
            }),
        )
        .expect("test digest should derive")
    }

    fn full_binding_linear_statement() -> Value {
        json!({
            "ballotProofStatementDigest": digest("ballot-proof-statement"),
            "coefficientModulus": "65537",
            "componentBundleStatementDigest": digest("component-bundle-statement"),
            "objectType": "BallotProofLinearProofStatement",
            "objectVersion": 1,
            "parameterProfileId": FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
            "projectionCoverage": FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
            "relation": "A*w + t = 0",
            "relationBindingDigest": digest("relation-binding"),
            "relationBindingKind": "component-bundle-and-lowered-relation",
            "ringDegree": 64,
            "statementColumns": 1,
            "statementRows": 1,
            "witnessL2BoundSquared": "65536",
        })
    }

    fn full_binding_parameter_set(source: &str) -> Value {
        json!({
            "coefficientModulus": "65537",
            "expectedProofSizeBytes": 10,
            "profileId": FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
            "proofSystemRingDegree": 64,
            "relation": "A*w + t = 0",
            "ringDegree": 64,
            "source": source,
            "statementColumns": 1,
            "statementRows": 1,
            "witnessL2BoundSquared": "65536",
        })
    }

    fn full_binding_encoding(source: &str) -> Value {
        json!({
            "challengeCoefficientBitLength": 5,
            "challengeCoefficientModulus": 17,
            "coefficientModulus": "70368744177829",
            "compressedCoefficientBitLength": 35,
            "compressedCommitmentVectorLength": 18,
            "euclideanResponseLog2StandardDeviation": 14,
            "euclideanResponseVectorLength": 4,
            "expectedProofSizeBytes": 10,
            "fullSizeCoefficientBitLength": 47,
            "hashMaskVectorLength": 2,
            "hintVectorLength": 18,
            "infinityResponseLog2StandardDeviation": 22,
            "infinityResponseVectorLength": 4,
            "profileId": FULL_BALLOT_PROOF_ENCODING_PROFILE_ID,
            "randomnessResponseLog2StandardDeviation": 12,
            "randomnessResponseVectorLength": 41,
            "ringDegree": 64,
            "shortResponseLog2StandardDeviation": 18,
            "shortResponseVectorLength": 2,
            "source": source,
            "targetCommitmentVectorLength": 12,
        })
    }

    #[test]
    fn mandatory_claim_profile_requires_twenty_receivers() {
        let statement = json!({
            "optionCount": 20,
            "receiverPayloads": [{}],
            "receiverPublicKeys": [{}],
            "shareCommitments": [{}],
            "shareVectorWidth": 220,
        });

        let refused_objects =
            collect_mandatory_claim_profile_refusals(&statement, Some(&digest("package")));

        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains("mandatory 20-option"))),
            "single-receiver statement must not pass claim-bearing profile checks: {refused_objects:?}"
        );
    }

    #[test]
    fn full_binding_contract_rejects_mutated_profile_source() {
        let linear_statement = full_binding_linear_statement();
        let parameter_set =
            full_binding_parameter_set("sealed-lattice/linear-proof/unfrozen-parameters-v1");
        let proof_encoding = full_binding_encoding(FULL_BALLOT_BINDING_ENCODING_SOURCE);

        let refused_objects = collect_full_ballot_binding_contract_refusals(
            &linear_statement,
            &parameter_set,
            &proof_encoding,
            Some(10),
            Some(&digest("proof-record")),
        );

        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains("parameter set does not match"))),
            "mutated parameter source must be rejected: {refused_objects:?}"
        );
    }

    #[test]
    fn full_binding_contract_requires_component_bundle_binding() {
        let mut linear_statement = full_binding_linear_statement();
        let linear_statement_object = linear_statement
            .as_object_mut()
            .expect("linear statement should be an object");
        linear_statement_object.remove("relationBindingKind");
        let parameter_set = full_binding_parameter_set(FULL_BALLOT_BINDING_PARAMETER_SOURCE);
        let proof_encoding = full_binding_encoding(FULL_BALLOT_BINDING_ENCODING_SOURCE);

        let refused_objects = collect_full_ballot_binding_contract_refusals(
            &linear_statement,
            &parameter_set,
            &proof_encoding,
            Some(10),
            Some(&digest("proof-record")),
        );

        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains("component bundle"))),
            "missing relation binding metadata must be rejected: {refused_objects:?}"
        );
    }

    #[test]
    fn public_zero_statement_contract_is_frozen() {
        let statement = json!({
            "coefficientModulus": "12289",
            "componentId": "receiver-key-binding-component",
            "objectType": "BallotProofComponentProofStatementPlan",
            "objectVersion": 1,
            "proofBytesAvailability": "public-zero-witness-binding-check",
            "proofLoweringStatus": "explicitRowsAvailable",
            "proofStatementFormat": PUBLIC_ZERO_PROOF_STATEMENT_FORMAT,
            "relation": "A*w + t = 0",
            "rowCount": 20_480,
            "variableColumnCount": 0,
        });

        assert!(collect_public_zero_statement_contract_refusals(&statement, None).is_empty());

        let mut mutated_statement = statement;
        mutated_statement["rowCount"] = json!(1);
        let refused_objects =
            collect_public_zero_statement_contract_refusals(&mutated_statement, None);

        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains("public-zero"))),
            "mutated public-zero statement must be rejected: {refused_objects:?}"
        );
    }
}
