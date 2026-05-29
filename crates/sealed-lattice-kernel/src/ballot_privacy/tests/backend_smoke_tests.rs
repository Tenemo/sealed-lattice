use crate::ballot_privacy::{
    linear_proof::parameters::{
        LinearProofParameterSet, encoded_score_field_linear_proof_encoding_contract,
    },
    linear_proof::profile_constants::{
        GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED,
        GENERATED_SHARE_COMMITMENT_COMPONENT_EXACT_NORM_BOUND_SQUARED,
    },
};
use serde_json::{Value, json};

use super::component_statement_tests::test_hash;

#[derive(Default)]
pub(super) struct BallotProofBackendInputParts<'a> {
    pub(super) proof_bytes_hex: Option<&'a str>,
    pub(super) linear_statement: Option<&'a Value>,
    pub(super) public_randomness_hex: Option<&'a str>,
    pub(super) parameter_set: Option<&'a Value>,
    pub(super) proof_encoding: Option<&'a Value>,
    pub(super) component_bundle_statement: Option<&'a Value>,
    pub(super) component_proof_bundle: Option<&'a Value>,
    pub(super) component_proof_inputs: Option<&'a Value>,
}

pub(super) fn ballot_proof_backend_inputs<'a>(
    parts: BallotProofBackendInputParts<'a>,
) -> super::BallotProofVerificationInputs<'a> {
    super::BallotProofVerificationInputs {
        component_bundle_statement: parts.component_bundle_statement,
        component_proof_bundle: parts.component_proof_bundle,
        component_proof_inputs: parts.component_proof_inputs,
        dynamic_roster_profile_evidence: None,
        linear_statement: parts.linear_statement,
        parameter_set: parts.parameter_set,
        proof_bytes_hex: parts.proof_bytes_hex,
        proof_encoding: parts.proof_encoding,
        public_randomness_hex: parts.public_randomness_hex,
        component_proof_verification_mode: super::ComponentProofVerificationMode::VerifyBackend,
        casual_micro_roster_acknowledged: false,
    }
}

pub(super) fn integer_property(value: &Value, field_name: &str) -> usize {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .and_then(|field_value| usize::try_from(field_value).ok())
        .unwrap_or_else(|| panic!("{field_name} should be a usize-compatible integer"))
}

fn apply_statement_matrix_patch(statement_matrix: &mut Value, patch: &Value) {
    let row_index = integer_property(patch, "rowIndex");
    let column_index = integer_property(patch, "columnIndex");
    let coefficient_index = integer_property(patch, "coefficientIndex");
    let coefficient = patch
        .get("coefficient")
        .cloned()
        .expect("statement matrix patch coefficient should exist");

    statement_matrix[row_index][column_index][coefficient_index] = coefficient;
}

fn apply_target_vector_patch(target_vector: &mut Value, patch: &Value) {
    let row_index = integer_property(patch, "rowIndex");
    let coefficient_index = integer_property(patch, "coefficientIndex");
    let coefficient = patch
        .get("coefficient")
        .cloned()
        .expect("target vector patch coefficient should exist");

    target_vector[row_index][coefficient_index] = coefficient;
}

pub(super) fn expand_encoded_score_field_vector_case(
    vectors: &Value,
    compact_case: &Value,
) -> Value {
    let mut statement_matrix = vectors["linearStatement"]["statementMatrixCoefficients"].clone();
    let mut target_vector = vectors["linearStatement"]["targetVectorCoefficients"].clone();
    if let Some(statement_matrix_patch) = compact_case.get("statementMatrixPatch") {
        apply_statement_matrix_patch(&mut statement_matrix, statement_matrix_patch);
    }
    if let Some(target_vector_patch) = compact_case.get("targetVectorPatch") {
        apply_target_vector_patch(&mut target_vector, target_vector_patch);
    }

    json!({
        "caseName": compact_case["caseName"],
        "description": compact_case["description"],
        "mutation": compact_case["mutation"],
        "expectedOutcome": compact_case["expectedOutcome"],
        "upstreamVectorAvailable": compact_case["upstreamVectorAvailable"],
        "parameterSet": vectors["parameterSet"],
        "proofEncoding": vectors["proofEncoding"],
        "publicRandomnessHex": compact_case
            .get("publicRandomnessHex")
            .cloned()
            .unwrap_or_else(|| vectors["publicRandomnessHex"].clone()),
        "statementMatrixCoefficients": statement_matrix,
        "matrixCoefficientRepresentation": vectors
            .get("matrixCoefficientRepresentation")
            .cloned()
            .expect(
                "encoded-score field vectors should define matrixCoefficientRepresentation",
            ),
        "targetVectorCoefficients": target_vector,
        "targetCoefficientRepresentation": vectors["targetCoefficientRepresentation"],
        "proofHex": compact_case
            .get("proofHex")
            .cloned()
            .unwrap_or_else(|| vectors["proofHex"].clone()),
        "expectedProofSizeBytes": vectors["expectedProofSizeBytes"],
        "trace": compact_case["trace"]
    })
}

#[test]
fn ballot_privacy_backend_reports_available_and_rejects_invalid_shells() {
    let statement = json!({
        "objectType": "BallotProofStatement",
        "objectVersion": 1,
        "optionCount": 20,
        "shareVectorWidth": 220,
        "receiverPublicKeys": [],
        "receiverPayloads": [],
        "shareCommitments": []
    });
    let ballot_proof = json!({
        "objectType": "BallotProofRecord",
        "objectVersion": 1,
        "proofBackend": "LocalLinearLatticeRelation",
        "proofSizeBytes": 1024
    });
    let verification = super::verify_ballot_proof(
        &statement,
        &ballot_proof,
        ballot_proof_backend_inputs(BallotProofBackendInputParts::default()),
    );

    assert_eq!(verification["ok"], false);
    assert_eq!(verification["backendAvailable"], true);
    assert_eq!(
        verification["backendStatus"]["portableRustWasmPortRequired"],
        false
    );
    assert!(
        verification["backendStatus"]["requiredComponents"]
            .as_array()
            .expect("backend component list should be an array")
            .is_empty()
    );
    assert_eq!(verification["unresolvedReason"], "BallotPackageInvalid");
}

#[test]
fn ballot_proof_generation_command_emits_verifying_dense_proof_bytes() {
    let mut proof_encoding = encoded_score_field_linear_proof_encoding_contract();
    proof_encoding.profile_id = super::FULL_BALLOT_PROOF_ENCODING_PROFILE_ID.to_string();
    proof_encoding.source =
        "sealed-lattice/linear-proof/full-encoded-score-ballot-test-encoding-v1".to_string();
    proof_encoding.short_response_vector_length = 2;
    let parameter_set = LinearProofParameterSet {
        profile_id: super::FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID.to_string(),
        source: "sealed-lattice/linear-proof/full-encoded-score-ballot-test-parameters-v1"
            .to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: 64,
        proof_system_ring_degree: 64,
        coefficient_modulus: 65_537,
        statement_rows: 1,
        statement_columns: 1,
        witness_l2_bound_squared: GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED as u128,
        expected_proof_size_bytes: None,
    };
    let mut unit_polynomial = vec![0_u64; 64];
    unit_polynomial[0] = 1;
    let mut target_polynomial = vec![0_u64; 64];
    target_polynomial[0] = 65_537 - 5;
    let mut witness_polynomial = vec![0_i64; 64];
    witness_polynomial[0] = 5;
    let linear_statement = json!({
        "objectType": "BallotProofLinearProofStatement",
        "objectVersion": 1,
        "projectionCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        "parameterProfileId": super::FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
        "relation": "A*w + t = 0",
        "statementMatrixCoefficients": [[unit_polynomial]],
        "targetVectorCoefficients": [target_polynomial],
        "targetCoefficientRepresentation": "centeredSignedSourceModulus"
    });
    let parameter_set_value =
        serde_json::to_value(&parameter_set).expect("parameter set should serialize");
    let proof_encoding_value =
        serde_json::to_value(&proof_encoding).expect("proof encoding should serialize");
    let public_randomness_hex = "00".repeat(32);
    let prover_randomness_hex = "07".repeat(32);
    let secret_state = json!({
        "sourceWitnessCoefficients": [witness_polynomial]
    });

    let generation = super::generate_ballot_proof_from_command_request(&json!({
        "linearStatement": linear_statement.clone(),
        "parameterSet": parameter_set_value.clone(),
        "proofEncoding": proof_encoding_value.clone(),
        "publicRandomnessHex": public_randomness_hex.clone(),
        "secretState": secret_state.clone(),
        "proverRandomnessHex": prover_randomness_hex.clone()
    }));

    assert_eq!(
        generation["ok"], true,
        "generated ballot proof should verify: {generation}"
    );
    assert_eq!(generation["generatedProofBytes"], true);
    assert!(
        generation["statusLabels"]
            .as_array()
            .expect("status labels should be present")
            .contains(&json!("BallotGeneratedProofVerified"))
    );
    assert!(
        generation["proofBytesHex"]
            .as_str()
            .expect("proof bytes should be hex")
            .len()
            > 100
    );

    let proof_input = json!({
        "componentId": "score-and-shamir-field-component",
        "proofStatementFormat": "dense-polynomial-matrix-linear-proof-v1",
        "proofStatement": linear_statement,
        "proofParameterSet": parameter_set_value,
        "proofEncoding": proof_encoding_value,
        "publicRandomnessHex": public_randomness_hex
    });
    let component_generation =
        super::generate_ballot_component_proof_from_command_request(&json!({
            "componentId": "score-and-shamir-field-component",
            "proofInput": proof_input,
            "secretState": secret_state.clone(),
            "proverRandomnessHex": prover_randomness_hex
        }));

    assert_eq!(
        component_generation["ok"], true,
        "generated dense component proof should verify: {component_generation}"
    );
    assert!(
        component_generation["statusLabels"]
            .as_array()
            .expect("status labels should be present")
            .contains(&json!("BallotComponentGeneratedProofVerified"))
    );
}

#[test]
fn structured_share_commitment_component_generation_uses_compact_statement() {
    let mut proof_encoding = encoded_score_field_linear_proof_encoding_contract();
    proof_encoding.profile_id = "share-commitment-linear-proof-encoding-v1".to_string();
    proof_encoding.source =
        "sealed-lattice/linear-proof/structured-share-component-test-encoding-v1".to_string();
    proof_encoding.short_response_vector_length = (super::SHARE_COMMITMENT_OPENING_DIMENSION + 1)
        * (super::SHARE_COMMITMENT_MODULE_DEGREE / 64)
        + 1;
    let parameter_set = LinearProofParameterSet {
        profile_id: "share-commitment-linear-proof-parameter-v1".to_string(),
        source: "sealed-lattice/linear-proof/structured-share-component-test-parameters-v1"
            .to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: super::SHARE_COMMITMENT_MODULE_DEGREE,
        proof_system_ring_degree: 64,
        coefficient_modulus: super::SHARE_COMMITMENT_MODULUS,
        statement_rows: super::SHARE_COMMITMENT_MODULE_RANK,
        statement_columns: super::SHARE_COMMITMENT_OPENING_DIMENSION + 1,
        witness_l2_bound_squared: GENERATED_SHARE_COMMITMENT_COMPONENT_EXACT_NORM_BOUND_SQUARED
            as u128,
        expected_proof_size_bytes: None,
    };
    let zero_polynomial = vec![0_u64; super::SHARE_COMMITMENT_MODULE_DEGREE];
    let zero_commitment_vector = vec![zero_polynomial.clone(); super::SHARE_COMMITMENT_MODULE_RANK];
    let mut statement_payload = json!({
        "objectType": "BallotProofStructuredShareCommitmentProofStatement",
        "objectVersion": 1,
        "backendStatementHash": test_hash("structured-share-backend"),
        "ballotProofStatementHash": test_hash("structured-share-ballot-statement"),
        "coefficientModulus": super::SHARE_COMMITMENT_MODULUS.to_string(),
        "componentId": "share-commitment-component",
        "matrixHash": test_hash("structured-share-matrix"),
        "parameterProfileId": "share-commitment-linear-proof-parameter-v1",
        "proofStatementFormat": super::STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT,
        "proofSystemRingDegree": 64,
        "projectionCoverage": "share-commitment-rows-only",
        "receiverRows": [
            {
                "commitmentPolynomialVector": zero_commitment_vector,
                "receiverIdentity": "receiver-1",
                "receiverRosterPosition": 1,
                "rowCount": super::SHARE_COMMITMENT_MODULE_RANK,
                "rowOffsetWithinStatement": 0
            }
        ],
        "relation": "A*w + t = 0",
        "relationStatementHash": test_hash("structured-share-relation"),
        "shareCommitmentProfileHash": test_hash("structured-share-profile"),
        "shareVectorWidth": 1,
        "sourceBackendColumnIndices": (0..(super::SHARE_COMMITMENT_OPENING_DIMENSION + 1)).collect::<Vec<_>>(),
        "sourceRingDegree": super::SHARE_COMMITMENT_MODULE_DEGREE,
        "statementColumns": super::SHARE_COMMITMENT_OPENING_DIMENSION + 1,
        "statementRows": super::SHARE_COMMITMENT_MODULE_RANK,
        "matrixCoefficientRepresentation": "centeredSignedSourceModulus",
        "targetCoefficientRepresentation": "centeredSignedSourceModulus",
        "targetVectorHash": test_hash("structured-share-target"),
        "witnessL2BoundSquared": "1048576"
    });
    let statement_hash =
        super::derive_ballot_structured_share_commitment_statement_hash(&statement_payload)
            .expect("structured share statement hash should derive");
    statement_payload
        .as_object_mut()
        .expect("structured share statement should be an object")
        .insert("statementHash".to_string(), json!(statement_hash));
    let parameter_set_value =
        serde_json::to_value(&parameter_set).expect("parameter set should serialize");
    let proof_encoding_value =
        serde_json::to_value(&proof_encoding).expect("proof encoding should serialize");
    let proof_input = json!({
        "componentId": "share-commitment-component",
        "proofStatementFormat": super::STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT,
        "proofStatement": statement_payload,
        "proofParameterSet": parameter_set_value,
        "proofEncoding": proof_encoding_value,
        "publicRandomnessHex": "33".repeat(32)
    });
    let secret_state = json!({
        "sourceWitnessCoefficients": vec![
            vec![0_i64; super::SHARE_COMMITMENT_MODULE_DEGREE];
            super::SHARE_COMMITMENT_OPENING_DIMENSION + 1
        ]
    });

    let component_generation =
        super::generate_ballot_component_proof_from_command_request(&json!({
            "componentId": "share-commitment-component",
            "proofInput": proof_input.clone(),
            "secretState": secret_state.clone(),
            "proverRandomnessHex": "0c".repeat(32)
        }));

    assert_eq!(
        component_generation["ok"], true,
        "generated structured share component proof should verify: {component_generation}"
    );
    assert!(
        component_generation["statusLabels"]
            .as_array()
            .expect("status labels should be present")
            .contains(&json!("BallotComponentGeneratedProofVerified"))
    );

    let mut mutated_proof_input = proof_input;
    mutated_proof_input["proofStatement"]["receiverRows"][0]["commitmentPolynomialVector"][0][0] =
        json!(1);
    let mutated_generation = super::generate_ballot_component_proof_from_command_request(&json!({
        "componentId": "share-commitment-component",
        "proofInput": mutated_proof_input,
        "secretState": secret_state,
        "proverRandomnessHex": "0c".repeat(32)
    }));
    assert_eq!(mutated_generation["ok"], false);
    assert_eq!(
        mutated_generation["unresolvedReason"],
        "BallotPackageInvalid"
    );
}
