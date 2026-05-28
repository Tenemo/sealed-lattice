use super::proof_record_generation_tests::{
    canonical_receiver_key_witness_polynomial, unit_receiver_key_source_polynomial,
    zero_receiver_key_source_polynomial, zero_receiver_key_witness_polynomial,
};
use super::*;
use crate::ballot_privacy::{
    linear_proof::parameters::{
        receiver_key_linear_parameter_contract, receiver_key_linear_proof_encoding_contract,
    },
    polynomial_ring::PolynomialRing,
};

fn receiver_key_prover_preflight_fixture() -> (Value, Value, Value, Value) {
    let parameter_set = receiver_key_linear_parameter_contract();
    let proof_encoding = receiver_key_linear_proof_encoding_contract();
    let source_ring =
        PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)
            .expect("source ring should validate");
    let mut witness = vec![zero_receiver_key_witness_polynomial(); parameter_set.statement_columns];
    witness[0][0] = 2;
    witness[0][5] = -1;
    witness[1][1] = 1;
    witness[4][0] = -2;
    witness[5][7] = 1;

    let mut statement_matrix =
        vec![
            vec![zero_receiver_key_source_polynomial(); parameter_set.statement_columns];
            parameter_set.statement_rows
        ];
    for (row_index, statement_matrix_row) in statement_matrix
        .iter_mut()
        .enumerate()
        .take(parameter_set.statement_rows)
    {
        statement_matrix_row[row_index] = unit_receiver_key_source_polynomial();
        statement_matrix_row[row_index + 4] = unit_receiver_key_source_polynomial();
    }

    let target_vector = (0..parameter_set.statement_rows)
        .map(|row_index| {
            let secret_polynomial = canonical_receiver_key_witness_polynomial(
                &witness[row_index],
                parameter_set.coefficient_modulus,
            );
            let error_polynomial = canonical_receiver_key_witness_polynomial(
                &witness[row_index + 4],
                parameter_set.coefficient_modulus,
            );
            let public_key_polynomial = source_ring
                .add(&secret_polynomial, &error_polynomial)
                .expect("public key polynomial should add");
            source_ring
                .neg(&public_key_polynomial)
                .expect("target polynomial should negate")
        })
        .collect::<Vec<_>>();
    let linear_statement_payload = json!({
        "ceremonyId": "ceremony-receiver-key-prover-preflight",
        "coefficientModulus": "12289",
        "keyMaterialHash": test_hash("receiver-key-material"),
        "manifestHash": test_hash("manifest"),
        "objectType": "ReceiverKeyLinearProofStatement",
        "objectVersion": 1,
        "publicMatrixSeedHash": test_hash("receiver-matrix-seed"),
        "receiverEncryptionProfileHash": test_hash("receiver-encryption-profile"),
        "receiverIdentity": "receiver-1",
        "receiverPublicKeyHash": test_hash("receiver-public-key"),
        "receiverRosterPosition": 1,
        "recoveryEpoch": 0,
        "relation": "A*w + t = 0",
        "ringDegree": 256,
        "rosterHash": test_hash("roster"),
        "sourceRing": "Z_q[X]/(X^256 + 1)",
        "statementColumns": 8,
        "statementMatrixCoefficients": statement_matrix,
        "statementMatrixHash": test_hash("statement-matrix"),
        "statementProfileId": "receiver-key-linear-module-lwe-statement-v1",
        "statementRows": 4,
        "targetCoefficientRepresentation": "centeredSignedSourceModulus",
        "targetVectorCoefficients": target_vector,
        "targetVectorHash": test_hash("target-vector"),
        "witnessInfinityNormBound": 2,
        "witnessL2BoundSquared": "8192",
        "witnessVectorLayout": [
            "receiver secret polynomial 0",
            "receiver secret polynomial 1",
            "receiver secret polynomial 2",
            "receiver secret polynomial 3",
            "receiver error polynomial 0",
            "receiver error polynomial 1",
            "receiver error polynomial 2",
            "receiver error polynomial 3"
        ]
    });
    let linear_statement_hash =
        super::derive_receiver_key_linear_statement_hash(&linear_statement_payload)
            .expect("linear statement hash should derive");
    let mut linear_statement = linear_statement_payload;
    linear_statement
        .as_object_mut()
        .expect("linear statement should be an object")
        .insert("statementHash".to_string(), json!(linear_statement_hash));
    let secret_state = json!({
        "secretVector": witness[..4].to_vec(),
        "errorVector": witness[4..].to_vec()
    });

    (
        linear_statement,
        json!(parameter_set),
        json!(proof_encoding),
        secret_state,
    )
}

#[test]
fn receiver_key_proof_generation_preflight_checks_source_and_proof_ring_witness() {
    let (linear_statement, parameter_set, proof_encoding, secret_state) =
        receiver_key_prover_preflight_fixture();
    let preparation = super::prepare_receiver_key_proof_generation_from_command_request(&json!({
        "linearStatement": linear_statement.clone(),
        "parameterSet": parameter_set.clone(),
        "proofEncoding": proof_encoding.clone(),
        "publicRandomnessHex": "00".repeat(32),
        "secretState": secret_state.clone(),
        "proverRandomnessHex": "09".repeat(32)
    }));

    assert_eq!(preparation["ok"], true);
    assert_eq!(
        preparation["operation"],
        "prepareReceiverKeyProofGeneration"
    );
    assert_eq!(preparation["generatedProofBytes"], false);
    assert_eq!(preparation["summary"]["relationWitnessPolynomialCount"], 32);
    assert_eq!(preparation["summary"]["shortWitnessPolynomialCount"], 33);
    assert_eq!(
        preparation["summary"]["preparedShortWitnessPolynomialCount"],
        33
    );
    assert_eq!(preparation["summary"]["witnessL2Squared"], "11");
    assert_eq!(preparation["summary"]["normSlack"], "8181");
    assert!(
        preparation["statusLabels"]
            .as_array()
            .expect("status labels should be an array")
            .contains(&json!("ReceiverKeyProofRingWitnessPrepared"))
    );
    assert!(
        preparation["statusLabels"]
            .as_array()
            .expect("status labels should be an array")
            .contains(&json!("ReceiverKeyAbdlopCommitmentPrepared"))
    );
    assert_eq!(
        preparation["summary"]["abdlopCommitment"]["compressedCommitmentPolynomialCount"],
        json!(19)
    );
    assert_eq!(
        preparation["summary"]["abdlopCommitment"]["openingRandomnessPolynomialCount"],
        json!(55)
    );
    assert_eq!(
        preparation["summary"]["abdlopCommitment"]["abdlopCommitmentHash"]
            .as_str()
            .expect("commitment hash should be present")
            .len(),
        64
    );

    let mut wrong_secret_state = secret_state;
    wrong_secret_state["secretVector"][0][0] = json!(3);
    let rejection = super::prepare_receiver_key_proof_generation_from_command_request(&json!({
        "linearStatement": linear_statement.clone(),
        "parameterSet": parameter_set.clone(),
        "proofEncoding": proof_encoding.clone(),
        "publicRandomnessHex": "00".repeat(32),
        "secretState": wrong_secret_state.clone(),
        "proverRandomnessHex": "09".repeat(32)
    }));

    assert_eq!(rejection["ok"], false);
    assert_eq!(rejection["unresolvedReason"], json!("BallotPackageInvalid"));
    assert!(
        rejection["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("source witness")
    );

    let mut unsupported_parameter_set = parameter_set;
    unsupported_parameter_set
        .as_object_mut()
        .expect("parameter set should be an object")
        .insert(
            "profileId".to_string(),
            json!("receiver-key-linear-module-lwe-unsupported-v1"),
        );
    let unsupported_rejection =
        super::prepare_receiver_key_proof_generation_from_command_request(&json!({
            "linearStatement": linear_statement,
            "parameterSet": unsupported_parameter_set,
            "proofEncoding": proof_encoding,
            "publicRandomnessHex": "00".repeat(32),
            "secretState": wrong_secret_state,
            "proverRandomnessHex": "09".repeat(32)
        }));

    assert_eq!(unsupported_rejection["ok"], false);
    assert_eq!(
        unsupported_rejection["unresolvedReason"],
        json!("BallotPackageInvalid")
    );
    assert!(
        unsupported_rejection["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("production receiver-key parameter profile")
    );
}

#[test]
fn proof_byte_bearing_receiver_key_record_verifies_against_linear_backend() {
    let vectors: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json"
    )))
    .expect("receiver-key linear vector file should parse");
    let cases = vectors["cases"]
        .as_array()
        .expect("receiver-key linear vector file should contain cases");
    let valid_case = cases
        .iter()
        .find(|vector_case| vector_case["caseName"] == "valid-receiver-key-linear-proof")
        .expect("valid receiver-key linear vector should exist");
    let mutated_target_case = cases
        .iter()
        .find(|vector_case| vector_case["caseName"] == "mutated-receiver-key-target-vector")
        .expect("mutated receiver-key target vector should exist");
    let proof_bytes_hex = valid_case["proofHex"]
        .as_str()
        .expect("valid vector proofHex should be a string");
    let public_randomness_hex = valid_case["publicRandomnessHex"]
        .as_str()
        .expect("valid vector publicRandomnessHex should be a string");
    let proof_size_bytes = proof_bytes_hex.len() / 2;
    let mut production_parameter_set = json!(receiver_key_linear_parameter_contract());
    production_parameter_set
        .as_object_mut()
        .expect("parameter set should be an object")
        .insert(
            "expectedProofSizeBytes".to_string(),
            json!(proof_size_bytes),
        );
    let mut production_proof_encoding = json!(receiver_key_linear_proof_encoding_contract());
    production_proof_encoding
        .as_object_mut()
        .expect("proof encoding should be an object")
        .insert(
            "expectedProofSizeBytes".to_string(),
            json!(proof_size_bytes),
        );
    let test_hash = |label: &str| {
        super::derive_hash(
            "ChallengeDomainHash",
            &json!({
                "label": label,
                "purpose": "receiver-key-proof-record-native-test"
            }),
        )
        .expect("test hash should derive")
    };
    let create_linear_statement = |target_vector_coefficients: Value| {
        let statement_payload = json!({
            "ceremonyId": "ceremony-receiver-key-proof-record",
            "coefficientModulus": "12289",
            "keyMaterialHash": test_hash("receiver-key-material"),
            "manifestHash": test_hash("manifest"),
            "objectType": "ReceiverKeyLinearProofStatement",
            "objectVersion": 1,
            "publicMatrixSeedHash": test_hash("receiver-matrix-seed"),
            "receiverEncryptionProfileHash": test_hash("receiver-encryption-profile"),
            "receiverIdentity": "receiver-1",
            "receiverPublicKeyHash": test_hash("receiver-public-key"),
            "receiverRosterPosition": 1,
            "recoveryEpoch": 0,
            "relation": "A*w + t = 0",
            "ringDegree": 256,
            "rosterHash": test_hash("roster"),
            "sourceRing": "Z_q[X]/(X^256 + 1)",
            "statementColumns": 8,
            "statementMatrixCoefficients": valid_case["statementMatrixCoefficients"].clone(),
            "statementMatrixHash": test_hash("statement-matrix"),
            "statementProfileId": "receiver-key-linear-module-lwe-statement-v1",
            "statementRows": 4,
            "targetCoefficientRepresentation": "centeredSignedSourceModulus",
            "targetVectorCoefficients": target_vector_coefficients,
            "targetVectorHash": test_hash("target-vector"),
            "witnessInfinityNormBound": 2,
            "witnessL2BoundSquared": "8192",
            "witnessVectorLayout": [
                "receiver secret polynomial 0",
                "receiver secret polynomial 1",
                "receiver secret polynomial 2",
                "receiver secret polynomial 3",
                "receiver error polynomial 0",
                "receiver error polynomial 1",
                "receiver error polynomial 2",
                "receiver error polynomial 3"
            ]
        });
        let statement_hash = super::derive_hash(
            "ChallengeDomainHash",
            &json!({
                "payload": statement_payload,
                "purpose": "receiver-key-linear-proof-statement-v1"
            }),
        )
        .expect("linear statement hash should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("linear statement should be an object")
            .insert("statementHash".to_string(), json!(statement_hash));

        statement
    };
    let create_receiver_key_proof = |linear_statement: &Value,
                                     parameter_set: &Value,
                                     proof_encoding: &Value| {
        let proof_bytes_hash = super::derive_hash(
            "ProofBytesHash",
            &json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_size_bytes
            }),
        )
        .expect("proof bytes hash should derive");
        let proof_encoding_profile_hash =
            super::derive_receiver_key_proof_encoding_profile_hash(proof_encoding)
                .expect("proof encoding profile hash should derive");
        let proof_parameter_set_hash =
            super::derive_receiver_key_proof_parameter_set_hash(parameter_set)
                .expect("proof parameter set hash should derive");
        let public_randomness_hash =
            super::derive_receiver_key_public_randomness_hash(public_randomness_hex)
                .expect("public randomness hash should derive");
        let linear_statement_hash = linear_statement["statementHash"]
            .as_str()
            .expect("linear statement hash should be a string");
        let proof_root = super::derive_hash(
            "ReceiverKeyProofRoot",
            &json!({
                "linearStatementHash": linear_statement_hash,
                "proofBytesHash": proof_bytes_hash,
                "proofEncodingProfileHash": proof_encoding_profile_hash,
                "proofParameterSetHash": proof_parameter_set_hash,
                "publicRandomnessHash": public_randomness_hash,
                "purpose": "receiver-key-linear-proof-record-root-v1"
            }),
        )
        .expect("proof root should derive");
        let proof_payload = json!({
            "backendStatementHash": test_hash("backend-statement"),
            "ceremonyId": "ceremony-receiver-key-proof-record",
            "linearStatementHash": linear_statement_hash,
            "manifestHash": test_hash("manifest"),
            "objectType": "ReceiverKeyProof",
            "objectVersion": 1,
            "proofBackend": "LocalLinearLatticeRelation",
            "proofBytesHash": proof_bytes_hash,
            "proofEncodingProfileHash": proof_encoding_profile_hash,
            "proofParameterSetHash": proof_parameter_set_hash,
            "proofRoot": proof_root,
            "proofSizeBytes": proof_size_bytes,
            "publicRandomnessHash": public_randomness_hash,
            "receiverEncryptionProfileHash": test_hash("receiver-encryption-profile"),
            "receiverIdentity": "receiver-1",
            "receiverPublicKeyHash": test_hash("receiver-public-key"),
            "receiverRosterPosition": 1,
            "recoveryEpoch": 0,
            "rosterHash": test_hash("roster")
        });
        let receiver_key_proof_root = super::derive_hash("ReceiverKeyProofRoot", &proof_payload)
            .expect("receiver key proof root should derive");
        let mut receiver_key_proof = proof_payload;
        receiver_key_proof
            .as_object_mut()
            .expect("receiver key proof should be an object")
            .insert(
                "receiverKeyProofRoot".to_string(),
                json!(receiver_key_proof_root),
            );

        receiver_key_proof
    };

    let valid_linear_statement =
        create_linear_statement(valid_case["targetVectorCoefficients"].clone());
    let valid_receiver_key_proof = create_receiver_key_proof(
        &valid_linear_statement,
        &production_parameter_set,
        &production_proof_encoding,
    );
    let valid_verification = super::verify_receiver_key_proof_from_command_request(&json!({
        "receiverKeyProof": valid_receiver_key_proof.clone(),
        "linearStatement": valid_linear_statement.clone(),
        "proofBytesHex": proof_bytes_hex,
        "publicRandomnessHex": public_randomness_hex,
        "parameterSet": production_parameter_set.clone(),
        "proofEncoding": production_proof_encoding.clone()
    }));

    assert_eq!(valid_verification["ok"], true);
    assert_eq!(valid_verification["unresolvedReason"], Value::Null);
    assert!(
        valid_verification["statusLabels"]
            .as_array()
            .expect("status labels should be an array")
            .contains(&json!("ReceiverKeyLinearProofVerified"))
    );

    let mutated_linear_statement =
        create_linear_statement(mutated_target_case["targetVectorCoefficients"].clone());
    let mutated_receiver_key_proof = create_receiver_key_proof(
        &mutated_linear_statement,
        &production_parameter_set,
        &production_proof_encoding,
    );
    let mutated_verification = super::verify_receiver_key_proof_from_command_request(&json!({
        "receiverKeyProof": mutated_receiver_key_proof,
        "linearStatement": mutated_linear_statement,
        "proofBytesHex": proof_bytes_hex,
        "publicRandomnessHex": public_randomness_hex,
        "parameterSet": production_parameter_set.clone(),
        "proofEncoding": production_proof_encoding.clone()
    }));

    assert_eq!(mutated_verification["ok"], false);
    assert_eq!(mutated_verification["unresolvedReason"], "InvalidFixture");

    let mut wrong_parameter_set = production_parameter_set.clone();
    wrong_parameter_set
        .as_object_mut()
        .expect("parameter set should be an object")
        .insert(
            "profileId".to_string(),
            json!("receiver-key-linear-module-lwe-unsupported-v1"),
        );
    let wrong_parameter_verification =
        super::verify_receiver_key_proof_from_command_request(&json!({
            "receiverKeyProof": valid_receiver_key_proof.clone(),
            "linearStatement": valid_linear_statement.clone(),
            "proofBytesHex": proof_bytes_hex,
            "publicRandomnessHex": public_randomness_hex,
            "parameterSet": wrong_parameter_set,
            "proofEncoding": production_proof_encoding.clone()
        }));

    assert_eq!(wrong_parameter_verification["ok"], false);
    assert_eq!(
        wrong_parameter_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );

    let mut size_unbound_parameter_set = production_parameter_set.clone();
    size_unbound_parameter_set
        .as_object_mut()
        .expect("parameter set should be an object")
        .insert(
            "expectedProofSizeBytes".to_string(),
            json!(proof_size_bytes + 1),
        );
    let size_unbound_receiver_key_proof = create_receiver_key_proof(
        &valid_linear_statement,
        &size_unbound_parameter_set,
        &production_proof_encoding,
    );
    let size_unbound_parameter_verification =
        super::verify_receiver_key_proof_from_command_request(&json!({
            "receiverKeyProof": size_unbound_receiver_key_proof,
            "linearStatement": valid_linear_statement.clone(),
            "proofBytesHex": proof_bytes_hex,
            "publicRandomnessHex": public_randomness_hex,
            "parameterSet": size_unbound_parameter_set,
            "proofEncoding": production_proof_encoding.clone()
        }));

    assert_eq!(size_unbound_parameter_verification["ok"], false);
    assert_eq!(
        size_unbound_parameter_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        size_unbound_parameter_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("byte length")
    );

    let mut size_unbound_proof_encoding = production_proof_encoding.clone();
    size_unbound_proof_encoding
        .as_object_mut()
        .expect("proof encoding should be an object")
        .insert(
            "expectedProofSizeBytes".to_string(),
            json!(proof_size_bytes + 1),
        );
    let size_unbound_encoding_receiver_key_proof = create_receiver_key_proof(
        &valid_linear_statement,
        &production_parameter_set,
        &size_unbound_proof_encoding,
    );
    let size_unbound_encoding_verification =
        super::verify_receiver_key_proof_from_command_request(&json!({
            "receiverKeyProof": size_unbound_encoding_receiver_key_proof,
            "linearStatement": valid_linear_statement,
            "proofBytesHex": proof_bytes_hex,
            "publicRandomnessHex": public_randomness_hex,
            "parameterSet": production_parameter_set,
            "proofEncoding": size_unbound_proof_encoding
        }));

    assert_eq!(size_unbound_encoding_verification["ok"], false);
    assert_eq!(
        size_unbound_encoding_verification["unresolvedReason"],
        "BallotPackageInvalid"
    );
    assert!(
        size_unbound_encoding_verification["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("byte length")
    );
}
