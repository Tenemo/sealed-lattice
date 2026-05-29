use super::*;

const FULL_BALLOT_BINDING_PARAMETER_SOURCE: &str =
    "sealed-lattice/linear-proof/full-ballot-binding-parameters-v1";
const FULL_BALLOT_BINDING_ENCODING_SOURCE: &str =
    "sealed-lattice/linear-proof/full-ballot-binding-encoding-v1";
const FULL_BALLOT_BINDING_HASH_PURPOSE: &str = "ballot-proof-full-relation-binding-v1";
const BACKEND_PROOF_COMPONENTS_HASH_PURPOSE: &str = "ballot-privacy-backend-proof-components-v1";
const FULL_BALLOT_BINDING_COEFFICIENT_MODULUS: u64 = 65_537;
// This coefficient is a proof-bound relation binder, not the Fiat-Shamir
// soundness challenge. The linear proof soundness challenge is derived inside
// the backend proof transcript; this value only separates the component-bundle
// binding row while keeping the witness inside the frozen norm bound.
const FULL_BALLOT_BINDING_SCALAR_COUNT: u64 = 127;
const UNAPPROVED_DYNAMIC_ROSTER_CERTIFICATE_MESSAGE: &str = "Dynamic roster profile evidence must reference an approved roster profile parameter certificate.";

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
    object_hash: Option<&str>,
    dynamic_roster_profile_evidence: Option<&Value>,
    claim_bearing_package: bool,
    casual_micro_roster_acknowledged: bool,
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
            object_hash,
        ));
    }
    if share_vector_width != expected_share_vector_width {
        refused_objects.push(structural_refusal(
            "Ballot privacy proof statement shareVectorWidth must equal optionCount times eleven encoded coordinates.",
            object_hash,
        ));
    }
    if !participant_count.is_some_and(|value| {
        (BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT..=BALLOT_PRIVACY_MAXIMUM_PARTICIPANT_COUNT)
            .contains(&value)
    }) {
        refused_objects.push(structural_refusal(
            "Ballot privacy proof statements must use three to fifty participants.",
            object_hash,
        ));
    }
    if participant_count.is_some_and(|value| value < BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT)
    {
        if claim_bearing_package {
            refused_objects.push(structural_refusal(
                "Claim-bearing ballot privacy proof statements must use at least ten frozen participants.",
                object_hash,
            ));
        } else if !casual_micro_roster_acknowledged {
            refused_objects.push(structural_refusal(
                "Ballot privacy proof statements with three to nine participants require explicit casual micro-roster acknowledgement.",
                object_hash,
            ));
        }
    }
    if participant_count.is_some_and(|value| {
        value >= BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT
            && value != BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT
            && dynamic_roster_profile_evidence.is_none()
    }) {
        refused_objects.push(structural_refusal(
            "Dynamic ballot privacy proof statements require roster profile parameter certificate evidence for the frozen receiver count.",
            object_hash,
        ));
    }
    if let Some(evidence) = dynamic_roster_profile_evidence {
        let evidence_hash = string_field(evidence, "rosterProfileEvidenceHash");
        let expected_evidence_hash = value_without_field(evidence, "rosterProfileEvidenceHash")
            .and_then(|payload| derive_hash("BallotPrivacyRosterProfileEvidenceHash", &payload));
        let dynamic_roster_profile_certificate_hash =
            string_field(evidence, "dynamicRosterProfileCertificateHash");
        let evidence_frozen_roster_size = usize_object_field(evidence, "frozenRosterSize");
        let evidence_option_count = u64_object_field(evidence, "optionCount");
        if string_field(evidence, "objectType") != Some("BallotPrivacyRosterProfileEvidence")
            || u64_object_field(evidence, "objectVersion") != Some(1)
            || string_field(evidence, "profileFamily") != Some("BalancedDefault")
            || string_field(evidence, "receiverCoverageProfile") != Some("AllFrozenRosterReceivers")
            || string_field(evidence, "proofStatementShape") != Some("EncodedScoreBallotProof-v1")
            || evidence_frozen_roster_size != participant_count
            || evidence_option_count.map(u128::from) != option_count
            || string_field(evidence, "thresholdProfileHash")
                != string_field(statement, "thresholdProfileHash")
            || dynamic_roster_profile_certificate_hash.is_none_or(|hash| !is_protocol_hash(hash))
            || expected_evidence_hash.as_deref() != evidence_hash
        {
            refused_objects.push(structural_refusal(
                "Dynamic roster profile evidence is not bound to the ballot proof statement dimensions and threshold profile.",
                object_hash,
            ));
        }
        if dynamic_roster_profile_certificate_hash.is_some_and(is_protocol_hash)
            && !dynamic_roster_profile_certificate_is_approved(
                evidence_frozen_roster_size,
                evidence_option_count,
                string_field(evidence, "thresholdProfileHash"),
                dynamic_roster_profile_certificate_hash,
            )
        {
            refused_objects.push(structural_refusal(
                UNAPPROVED_DYNAMIC_ROSTER_CERTIFICATE_MESSAGE,
                object_hash,
            ));
        }
    }

    refused_objects
}

fn dynamic_roster_profile_certificate_is_approved(
    _frozen_roster_size: Option<usize>,
    _option_count: Option<u64>,
    _threshold_profile_hash: Option<&str>,
    _dynamic_roster_profile_certificate_hash: Option<&str>,
) -> bool {
    false
}

pub(crate) fn collect_full_ballot_binding_contract_refusals(
    linear_statement: &Value,
    parameter_set: &Value,
    proof_encoding: &Value,
    proof_size_bytes: Option<usize>,
    object_hash: Option<&str>,
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
        object_hash,
        "Full ballot binding linear statement",
    );
    if string_field(linear_statement, "relationBindingKind")
        != Some("component-bundle-and-lowered-relation")
        || string_field(linear_statement, "relationBindingHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(linear_statement, "componentBundleStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
    {
        refused_objects.push(structural_refusal(
            "Full ballot binding linear statement must bind the component bundle and lowered relation.",
            object_hash,
        ));
    }
    refused_objects.extend(collect_parameter_contract_refusals(
        parameter_set,
        &expectation,
        proof_size_bytes,
        object_hash,
        "Full ballot binding parameter set",
        true,
    ));
    refused_objects.extend(collect_encoding_contract_refusals(
        proof_encoding,
        &expectation,
        proof_size_bytes,
        object_hash,
        "Full ballot binding proof encoding",
        true,
    ));

    refused_objects
}

pub(crate) fn collect_full_ballot_relation_binding_refusals(
    linear_statement: &Value,
    component_bundle_statement: Option<&Value>,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let Some(component_bundle_statement) = component_bundle_statement else {
        return Vec::new();
    };
    let mut refused_objects = Vec::new();
    let expected_relation_binding_hash =
        derive_full_relation_binding_hash(component_bundle_statement);

    if string_field(linear_statement, "relationBindingHash")
        != expected_relation_binding_hash.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Full ballot binding linear statement relation binding hash does not match the supplied component bundle.",
            object_hash,
        ));
    }
    if !full_ballot_binding_matrix_and_target_are_derived(
        linear_statement,
        expected_relation_binding_hash.as_deref(),
    ) {
        refused_objects.push(structural_refusal(
            "Full ballot binding linear statement matrix and target are not derived from the component bundle relation binding.",
            object_hash,
        ));
    }

    refused_objects
}

fn collect_linear_statement_contract_refusals(
    proof_statement: &Value,
    expectation: &LinearContractExpectation,
    object_hash: Option<&str>,
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
            object_hash,
        ));
    }
    if string_field(proof_statement, "relation") != Some("A*w + t = 0") {
        refused_objects.push(structural_refusal(
            format!("{label} does not use the frozen linear relation."),
            object_hash,
        ));
    }

    refused_objects
}

fn derive_backend_hash(purpose: &str, payload: Value) -> Option<String> {
    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": payload,
            "purpose": purpose,
        }),
    )
}

fn component_statement_as_proof_component(component_statement: &Value) -> Option<Value> {
    let component_object = object_map(component_statement)?;

    Some(json!({
        "coefficientModulus": component_object.get("coefficientModulus")?.clone(),
        "componentId": component_object.get("componentId")?.clone(),
        "proofLoweringStatus": component_object.get("proofLoweringStatus")?.clone(),
        "rowBatchNames": component_object.get("rowBatchNames")?.clone(),
        "rowCount": component_object.get("rowCount")?.clone(),
        "rowKinds": component_object.get("rowKinds")?.clone(),
        "variableColumnCount": component_object.get("variableColumnCount")?.clone(),
        "variableColumnIndices": component_object.get("variableColumnIndices")?.clone(),
        "componentHash": component_object.get("componentHash")?.clone()
    }))
}

pub(crate) fn derive_full_relation_binding_hash(
    component_bundle_statement: &Value,
) -> Option<String> {
    let component_bundle_object = object_map(component_bundle_statement)?;
    let component_statements = component_bundle_object
        .get("componentStatements")
        .and_then(Value::as_array)?;
    let proof_components = component_statements
        .iter()
        .map(component_statement_as_proof_component)
        .collect::<Option<Vec<_>>>()?;
    let proof_components_hash = derive_backend_hash(
        BACKEND_PROOF_COMPONENTS_HASH_PURPOSE,
        json!({
            "proofComponents": proof_components
        }),
    )?;

    derive_hash(
        "ChallengeDomainHash",
        &json!({
            "backendStatementHash": component_bundle_object.get("backendStatementHash")?,
            "componentBundleStatementHash": component_bundle_object.get("componentBundleStatementHash")?,
            "proofComponentsHash": proof_components_hash,
            "purpose": FULL_BALLOT_BINDING_HASH_PURPOSE,
            "relationStatementHash": component_bundle_object.get("relationStatementHash")?
        }),
    )
}

pub(crate) fn binding_scalar_from_hash(relation_binding_hash: &str) -> Option<u64> {
    let prefix = relation_binding_hash.get(..16)?;
    u64::from_str_radix(prefix, 16)
        .ok()
        .map(|value| 1 + (value % FULL_BALLOT_BINDING_SCALAR_COUNT))
}

fn dense_polynomial_is_constant(
    polynomial: &Value,
    expected_constant: u64,
    expected_length: usize,
) -> bool {
    let Some(coefficients) = polynomial.as_array() else {
        return false;
    };
    coefficients.len() == expected_length
        && coefficients
            .iter()
            .enumerate()
            .all(|(coefficient_index, coefficient)| {
                let expected_coefficient = if coefficient_index == 0 {
                    expected_constant
                } else {
                    0
                };

                integer_value(coefficient) == Some(expected_coefficient)
            })
}

fn full_ballot_binding_matrix_and_target_are_derived(
    linear_statement: &Value,
    relation_binding_hash: Option<&str>,
) -> bool {
    let Some(relation_binding_hash) = relation_binding_hash else {
        return false;
    };
    let Some(binding_scalar) = binding_scalar_from_hash(relation_binding_hash) else {
        return false;
    };
    let Some(source_ring_degree) = unsigned_integer_field(linear_statement, "ringDegree")
        .and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(statement_matrix) = object_map(linear_statement)
        .and_then(|object| object.get("statementMatrixCoefficients"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    let Some(target_vector) = object_map(linear_statement)
        .and_then(|object| object.get("targetVectorCoefficients"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    let Some(first_matrix_row) = statement_matrix.first().and_then(Value::as_array) else {
        return false;
    };
    let target_constant = FULL_BALLOT_BINDING_COEFFICIENT_MODULUS - binding_scalar;

    statement_matrix.len() == 1
        && first_matrix_row.len() == 1
        && target_vector.len() == 1
        && dense_polynomial_is_constant(&first_matrix_row[0], 1, source_ring_degree)
        && dense_polynomial_is_constant(&target_vector[0], target_constant, source_ring_degree)
}

fn collect_parameter_contract_refusals(
    parameter_set: &Value,
    expectation: &LinearContractExpectation,
    proof_size_bytes: Option<usize>,
    object_hash: Option<&str>,
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
            object_hash,
        ));
    }

    refused_objects
}

fn collect_encoding_contract_refusals(
    proof_encoding: &Value,
    expectation: &LinearContractExpectation,
    proof_size_bytes: Option<usize>,
    object_hash: Option<&str>,
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
            object_hash,
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
#[path = "contract_validation/tests.rs"]
mod tests;
