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

pub(crate) fn collect_supported_ballot_privacy_dimension_refusals(
    statement: &Value,
    object_digest: Option<&str>,
    unsafe_small_roster_acknowledged: bool,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let option_count = unsigned_integer_field(statement, "optionCount");
    let share_vector_width = unsigned_integer_field(statement, "shareVectorWidth");
    let expected_share_vector_width = option_count.and_then(|value| {
        value.checked_mul(u128::from(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION))
    });
    let participant_count = array_field(statement, "receiverPublicKeys").map(Vec::len);

    if !option_count.is_some_and(|value| {
        (BALLOT_PRIVACY_MINIMUM_OPTION_COUNT..=BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT).contains(&value)
    }) {
        refused_objects.push(structural_refusal(
            "Ballot privacy proof statements must use two to twenty options.",
            object_digest,
        ));
    }
    if share_vector_width != expected_share_vector_width {
        refused_objects.push(structural_refusal(
            "Ballot privacy proof statement shareVectorWidth must equal optionCount times eleven encoded coordinates.",
            object_digest,
        ));
    }
    if !participant_count.is_some_and(|value| {
        (BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT..=BALLOT_PRIVACY_MAXIMUM_PARTICIPANT_COUNT)
            .contains(&value)
    }) {
        refused_objects.push(structural_refusal(
            "Ballot privacy proof statements must use three to fifty participants.",
            object_digest,
        ));
    }
    if participant_count.is_some_and(|value| {
        value < BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT && !unsafe_small_roster_acknowledged
    }) {
        refused_objects.push(structural_refusal(
            "Ballot privacy proof statements with three to nineteen participants require explicit unsafe small-roster acknowledgement.",
            object_digest,
        ));
    }

    refused_objects
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

    fn statement_with_dimensions(option_count: u128, participant_count: usize) -> Value {
        let statement = json!({
            "optionCount": option_count,
            "receiverPayloads": vec![json!({}); participant_count],
            "receiverPublicKeys": vec![json!({}); participant_count],
            "shareCommitments": vec![json!({}); participant_count],
            "shareVectorWidth": option_count * u128::from(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION),
        });

        statement
    }

    #[test]
    fn supported_ballot_privacy_dimensions_accept_safe_range() {
        let statement = statement_with_dimensions(2, 20);
        assert!(
            collect_supported_ballot_privacy_dimension_refusals(
                &statement,
                Some(&digest("package")),
                false,
            )
            .is_empty()
        );

        let statement = statement_with_dimensions(20, 50);
        assert!(
            collect_supported_ballot_privacy_dimension_refusals(
                &statement,
                Some(&digest("package")),
                false,
            )
            .is_empty()
        );
    }

    #[test]
    fn supported_ballot_privacy_dimensions_require_unsafe_acknowledgement() {
        let statement = statement_with_dimensions(20, 3);
        let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
            &statement,
            Some(&digest("package")),
            false,
        );

        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains("unsafe small-roster"))),
            "unacknowledged unsafe small roster must be rejected: {refused_objects:?}"
        );
        assert!(
            collect_supported_ballot_privacy_dimension_refusals(
                &statement,
                Some(&digest("package")),
                true,
            )
            .is_empty()
        );
    }

    #[test]
    fn supported_ballot_privacy_dimensions_reject_out_of_range_values() {
        for (mut statement, expected_message) in [
            (statement_with_dimensions(1, 20), "two to twenty options"),
            (statement_with_dimensions(21, 20), "two to twenty options"),
            (
                statement_with_dimensions(20, 2),
                "three to fifty participants",
            ),
            (
                statement_with_dimensions(20, 51),
                "three to fifty participants",
            ),
        ] {
            if expected_message == "two to twenty options" {
                statement["shareVectorWidth"] = json!(220);
            }
            let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
                &statement,
                Some(&digest("package")),
                true,
            );

            assert!(
                refused_objects
                    .iter()
                    .any(|refusal| string_field(refusal, "message")
                        .is_some_and(|message| message.contains(expected_message))),
                "invalid dimensions must be rejected: {refused_objects:?}"
            );
        }

        let mut statement = statement_with_dimensions(20, 20);
        statement["shareVectorWidth"] = json!(219);
        let refused_objects = collect_supported_ballot_privacy_dimension_refusals(
            &statement,
            Some(&digest("package")),
            false,
        );
        assert!(
            refused_objects
                .iter()
                .any(|refusal| string_field(refusal, "message")
                    .is_some_and(|message| message.contains("shareVectorWidth"))),
            "wrong share vector width must be rejected: {refused_objects:?}"
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
}
