use super::*;

pub(super) fn component_proof_statement_for_test(
    component_id: &str,
    component_statement_hash: &Value,
    component_proof_statement_hash: Option<String>,
    proof_statement_format: &str,
) -> Value {
    if proof_statement_format == "dense-polynomial-matrix-linear-proof-v1" {
        let statement_payload = json!({
            "objectType": "BallotProofLinearProofStatement",
            "objectVersion": 1,
            "componentId": component_id,
            "componentStatementHash": component_statement_hash,
            "proofStatementFormat": proof_statement_format,
        });
        let statement_hash = super::derive_hash(
            "ChallengeDomainHash",
            &json!({
                "payload": statement_payload,
                "purpose": "ballot-proof-linear-proof-statement-v1"
            }),
        )
        .expect("dense component proof statement hash should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("dense component proof statement should be an object")
            .insert("statementHash".to_string(), json!(statement_hash));

        return statement;
    }
    if proof_statement_format == "sparse-polynomial-matrix-linear-proof-v1" {
        let statement_payload = json!({
            "objectType": "BallotProofSparseComponentLinearProofStatement",
            "objectVersion": 1,
            "componentId": component_id,
            "componentStatementHash": component_statement_hash,
            "proofStatementFormat": proof_statement_format,
        });
        let statement_hash = super::derive_hash(
            "ChallengeDomainHash",
            &json!({
                "payload": statement_payload,
                "purpose": "ballot-proof-sparse-linear-proof-statement-v1"
            }),
        )
        .expect("sparse component proof statement hash should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("sparse component proof statement should be an object")
            .insert("statementHash".to_string(), json!(statement_hash));

        return statement;
    }
    let is_structured = proof_statement_format == "structured-module-lwe-linear-proof-v1";
    let statement_payload = json!({
        "backendStatementHash": test_hash(&format!("{component_id}-backend")),
        "coefficientModulus": if component_id == "share-commitment-component" {
            "18446744069414584321"
        } else if component_id == "score-and-shamir-field-component"
            || component_id == "payload-plaintext-field-component" {
            "65537"
        } else {
            "12289"
        },
        "objectType": "BallotProofComponentProofStatementDescriptor",
        "objectVersion": 1,
        "componentId": component_id,
        "componentStatementHash": component_statement_hash,
        "denseCoefficientCount": if is_structured { json!("1024") } else { Value::Null },
        "matrixHash": test_hash(&format!("{component_id}-matrix")),
        "proofBackendRequirement": if is_structured {
            "structured-proof-statement-required"
        } else {
            "public-binding-check-only"
        },
        "proofLoweringStatus": "explicitRowsAvailable",
        "proofStatementFormat": proof_statement_format,
        "proofSystemRingDegree": if is_structured { json!(64) } else { Value::Null },
        "relation": "A*w + t = 0",
        "relationStatementHash": test_hash(&format!("{component_id}-relation")),
        "rowBatchMatrixHashes": [test_hash(&format!("{component_id}-row-matrix"))],
        "rowBatchNames": [if is_structured {
            "receiver_payload_encryption_equation_rows"
        } else {
            "receiver_key_binding_rows"
        }],
        "rowBatchTargetVectorHashes": [test_hash(&format!("{component_id}-row-target"))],
        "rowBatchTermCounts": [if is_structured { "1024" } else { "0" }],
        "rowCount": 1,
        "sparseTermCount": Value::Null,
        "sourceRingDegree": if is_structured { json!(256) } else { Value::Null },
        "structuredCiphertextChunkCount": if is_structured { json!(1) } else { Value::Null },
        "structuredReceiverCount": if is_structured { json!(1) } else { Value::Null },
        "structuredWitnessTermCount": if is_structured { json!("1024") } else { Value::Null },
        "targetVectorHash": test_hash(&format!("{component_id}-target")),
        "variableColumnCount": if is_structured { 1 } else { 0 },
        "variableColumnIndices": if is_structured { json!([0]) } else { json!([]) },
    });
    let canonical_component_proof_statement_hash = super::derive_hash(
        "ChallengeDomainHash",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-proof-statement-descriptor-v1"
        }),
    )
    .expect("component proof statement descriptor hash should derive");
    let mut statement_descriptor = statement_payload;
    statement_descriptor
        .as_object_mut()
        .expect("component proof statement descriptor should be an object")
        .insert(
            "componentProofStatementHash".to_string(),
            json!(
                component_proof_statement_hash.unwrap_or(canonical_component_proof_statement_hash)
            ),
        );

    statement_descriptor
}

pub(super) fn component_proof_for_test(
    component_id: &str,
    component_statement_hash: &Value,
) -> Value {
    let proof_input = component_proof_input_for_test(component_id, component_statement_hash);
    let proof_bytes_hex = proof_input["proofBytesHex"]
        .as_str()
        .expect("component proof bytes should be a string");
    let proof_encoding = proof_input
        .get("proofEncoding")
        .expect("component proof encoding should exist");
    let proof_parameter_set = proof_input
        .get("proofParameterSet")
        .expect("component proof parameter set should exist");
    let public_randomness_hex = proof_input["publicRandomnessHex"]
        .as_str()
        .expect("component proof public randomness should be a string");
    let proof_bytes_hash = proof_bytes_hash_for_test(proof_bytes_hex);
    let proof_encoding_profile_hash =
        super::derive_ballot_proof_encoding_profile_hash(proof_encoding)
            .expect("component proof encoding hash should derive");
    let proof_parameter_set_hash =
        super::derive_ballot_proof_parameter_set_hash(proof_parameter_set)
            .expect("component proof parameter set hash should derive");
    let public_randomness_hash =
        super::derive_ballot_proof_public_randomness_hash(public_randomness_hex)
            .expect("component proof public randomness hash should derive");
    let proof_root = super::derive_hash(
        "ChallengeDomainHash",
        &json!({
            "componentId": component_id,
            "componentProofStatementHash": proof_input["componentProofStatementHash"],
            "componentStatementHash": component_statement_hash,
            "proofBytesHash": proof_bytes_hash,
            "proofEncodingProfileHash": proof_encoding_profile_hash,
            "proofParameterSetHash": proof_parameter_set_hash,
            "proofStatementFormat": proof_input["proofStatementFormat"],
            "publicRandomnessHash": public_randomness_hash,
            "purpose": "ballot-proof-component-proof-root-v1",
            "statementHash": component_statement_hash,
        }),
    )
    .expect("component proof root should derive");
    let component_proof_payload = json!({
        "objectType": "BallotProofComponentProofRecord",
        "objectVersion": 1,
        "backendStatementHash": test_hash("backend-statement"),
        "ballotProofStatementHash": test_hash("ballot-proof-statement"),
        "componentId": component_id,
        "componentProofStatementHash": proof_input["componentProofStatementHash"],
        "componentStatementHash": component_statement_hash,
        "proofBackend": "LocalLinearLatticeRelation",
        "proofBytesHash": proof_bytes_hash,
        "proofEncodingProfileHash": proof_encoding_profile_hash,
        "proofParameterSetHash": proof_parameter_set_hash,
        "proofRoot": proof_root,
        "proofSizeBytes": proof_bytes_hex.len() / 2,
        "publicRandomnessHash": public_randomness_hash,
        "relationStatementHash": test_hash("relation-statement"),
    });
    let component_proof_record_hash =
        super::derive_ballot_component_proof_record_hash(&component_proof_payload)
            .expect("component proof hash should derive");
    let mut component_proof = component_proof_payload;
    component_proof
        .as_object_mut()
        .expect("component proof should be an object")
        .insert(
            "componentProofRecordHash".to_string(),
            json!(component_proof_record_hash),
        );

    component_proof
}

fn component_proof_bundle_for_test(
    component_bundle_statement: &Value,
    component_proofs: Vec<Value>,
) -> Value {
    let component_proof_bundle_payload = json!({
        "objectType": "BallotProofComponentProofBundle",
        "objectVersion": 1,
        "backendStatementHash": test_hash("backend-statement"),
        "ballotProofStatementHash": test_hash("ballot-proof-statement"),
        "bundleCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        "componentBundleStatementHash": component_bundle_statement["componentBundleStatementHash"],
        "componentProofs": component_proofs,
        "relationStatementHash": test_hash("relation-statement"),
        "requiredComponentIds": super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
    });
    let component_proof_bundle_hash =
        super::derive_ballot_component_proof_bundle_hash(&component_proof_bundle_payload)
            .expect("component proof bundle hash should derive");
    let mut component_proof_bundle = component_proof_bundle_payload;
    component_proof_bundle
        .as_object_mut()
        .expect("component proof bundle should be an object")
        .insert(
            "componentProofBundleHash".to_string(),
            json!(component_proof_bundle_hash),
        );

    component_proof_bundle
}

#[test]
fn component_bundle_refusals_cover_incomplete_and_reordered_components() {
    let statement = json!({
        "ballotProofStatementHash": test_hash("ballot-proof-statement")
    });
    let linear_statement = json!({
        "backendStatementHash": test_hash("backend-statement"),
        "projectionCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        "relationStatementHash": test_hash("relation-statement")
    });
    let incomplete_component_statements = super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS
        .iter()
        .enumerate()
        .map(|(component_index, component_id)| {
            component_statement_for_test(
                component_id,
                if component_index == 0 {
                    "explicitRowsAvailable"
                } else {
                    "HashExpandedRowsPending"
                },
            )
        })
        .collect::<Vec<_>>();
    let incomplete_bundle = component_bundle_for_test(
        incomplete_component_statements,
        super::COMPONENT_BUNDLE_INCOMPLETE_COVERAGE,
    );
    let ballot_proof = json!({
        "ballotProofRecordHash": test_hash("ballot-proof-record"),
        "componentBundleStatementHash": incomplete_bundle["componentBundleStatementHash"],
    });
    let incomplete_refusals = super::collect_ballot_component_bundle_refusals(
        &statement,
        &ballot_proof,
        &linear_statement,
        Some(&incomplete_bundle),
    );

    assert!(incomplete_refusals.iter().any(|refusal| {
        refusal["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("still incomplete")
    }));
    assert!(incomplete_refusals.iter().any(|refusal| {
        refusal["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("not fully lowered")
    }));

    let mut reordered_component_statements = super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS
        .iter()
        .map(|component_id| component_statement_for_test(component_id, "explicitRowsAvailable"))
        .collect::<Vec<_>>();
    reordered_component_statements.swap(0, 1);
    let reordered_bundle = component_bundle_for_test(
        reordered_component_statements,
        super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
    );
    let reordered_ballot_proof = json!({
        "ballotProofRecordHash": test_hash("reordered-ballot-proof-record"),
        "componentBundleStatementHash": reordered_bundle["componentBundleStatementHash"],
    });
    let reordered_refusals = super::collect_ballot_component_bundle_refusals(
        &statement,
        &reordered_ballot_proof,
        &linear_statement,
        Some(&reordered_bundle),
    );

    assert!(reordered_refusals.iter().any(|refusal| {
        refusal["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("invalid canonical shape")
    }));
}

#[test]
fn component_proof_bundle_refusals_cover_missing_reordered_and_wrong_statement_binding() {
    let statement = json!({
        "ballotProofStatementHash": test_hash("ballot-proof-statement")
    });
    let component_statements = super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS
        .iter()
        .map(|component_id| component_statement_for_test(component_id, "explicitRowsAvailable"))
        .collect::<Vec<_>>();
    let component_bundle_statement = component_bundle_for_test(
        component_statements.clone(),
        super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
    );
    let component_proofs = component_statements
        .iter()
        .zip(super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter())
        .map(|(component_statement, component_id)| {
            component_proof_for_test(component_id, &component_statement["componentStatementHash"])
        })
        .collect::<Vec<_>>();
    let component_proof_inputs = component_statements
        .iter()
        .zip(super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter())
        .map(|(component_statement, component_id)| {
            component_proof_input_for_test(
                component_id,
                &component_statement["componentStatementHash"],
            )
        })
        .collect::<Vec<_>>();
    let component_proof_bundle =
        component_proof_bundle_for_test(&component_bundle_statement, component_proofs.clone());
    let component_proof_inputs = json!(component_proof_inputs);
    let ballot_proof = json!({
        "backendStatementHash": test_hash("backend-statement"),
        "ballotProofRecordHash": test_hash("ballot-proof-record"),
        "componentBundleStatementHash": component_bundle_statement["componentBundleStatementHash"],
        "componentProofBundleHash": component_proof_bundle["componentProofBundleHash"],
        "relationStatementHash": test_hash("relation-statement"),
    });
    let valid_refusals = super::collect_ballot_component_proof_bundle_refusals(
        &statement,
        &ballot_proof,
        Some(&component_bundle_statement),
        Some(&component_proof_bundle),
        Some(&component_proof_inputs),
    );

    assert!(
        valid_refusals.is_empty(),
        "well-formed component proof bundle should have no structural refusals: {valid_refusals:?}"
    );

    let mut wrong_component_proof_statement_inputs = component_proof_inputs.clone();
    wrong_component_proof_statement_inputs[0]["componentProofStatementHash"] =
        json!(test_hash("wrong-component-proof-statement"));
    let wrong_component_proof_statement_refusals =
        super::collect_ballot_component_proof_bundle_refusals(
            &statement,
            &ballot_proof,
            Some(&component_bundle_statement),
            Some(&component_proof_bundle),
            Some(&wrong_component_proof_statement_inputs),
        );
    assert!(
            wrong_component_proof_statement_refusals
                .iter()
                .any(|refusal| {
                    refusal["message"]
                        .as_str()
                        .expect("refusal message should be a string")
                        .contains("proof statement for score-and-shamir-field-component does not match the proof record")
                })
        );

    let mut wrong_supplied_proof_statement_inputs = component_proof_inputs.clone();
    wrong_supplied_proof_statement_inputs[3]["proofStatement"] = component_proof_statement_for_test(
        "receiver-encryption-component",
        &component_bundle_statement["componentStatements"][3]["componentStatementHash"],
        Some(test_hash(
            "wrong-supplied-component-proof-statement-canonical-hash",
        )),
        "structured-module-lwe-linear-proof-v1",
    );
    let wrong_supplied_proof_statement_refusals =
        super::collect_ballot_component_proof_bundle_refusals(
            &statement,
            &ballot_proof,
            Some(&component_bundle_statement),
            Some(&component_proof_bundle),
            Some(&wrong_supplied_proof_statement_inputs),
        );
    assert!(
            wrong_supplied_proof_statement_refusals
                .iter()
                .any(|refusal| {
                    refusal["message"]
                        .as_str()
                        .expect("refusal message should be a string")
                        .contains(
                            "proof statement hash for receiver-encryption-component does not match its canonical payload",
                        )
                })
        );

    let missing_bundle_refusals = super::collect_ballot_component_proof_bundle_refusals(
        &statement,
        &ballot_proof,
        Some(&component_bundle_statement),
        None,
        None,
    );
    assert!(missing_bundle_refusals.iter().any(|refusal| {
        refusal["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("was not supplied")
    }));

    let mut reordered_component_proofs = component_proofs;
    reordered_component_proofs.swap(0, 1);
    let reordered_proof_bundle =
        component_proof_bundle_for_test(&component_bundle_statement, reordered_component_proofs);
    let reordered_ballot_proof = json!({
        "backendStatementHash": test_hash("backend-statement"),
        "ballotProofRecordHash": test_hash("reordered-ballot-proof-record"),
        "componentBundleStatementHash": component_bundle_statement["componentBundleStatementHash"],
        "componentProofBundleHash": reordered_proof_bundle["componentProofBundleHash"],
        "relationStatementHash": test_hash("relation-statement"),
    });
    let reordered_refusals = super::collect_ballot_component_proof_bundle_refusals(
        &statement,
        &reordered_ballot_proof,
        Some(&component_bundle_statement),
        Some(&reordered_proof_bundle),
        Some(&component_proof_inputs),
    );
    assert!(reordered_refusals.iter().any(|refusal| {
        refusal["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("invalid canonical shape")
    }));

    let mut wrong_statement_proof_bundle = component_proof_bundle;
    wrong_statement_proof_bundle["componentProofs"][0]["componentStatementHash"] =
        json!(test_hash("wrong-component-statement"));
    let wrong_statement_refusals = super::collect_ballot_component_proof_bundle_refusals(
        &statement,
        &ballot_proof,
        Some(&component_bundle_statement),
        Some(&wrong_statement_proof_bundle),
        Some(&component_proof_inputs),
    );
    assert!(wrong_statement_refusals.iter().any(|refusal| {
        refusal["message"]
            .as_str()
            .expect("refusal message should be a string")
            .contains("not bound to the supplied component statement")
    }));
}

#[test]
fn component_backend_rejects_unmatched_and_malformed_bundle_entries() {
    let proof_inputs = json!([]);
    let missing_proof_component_id_bundle = json!({
        "componentProofs": [
            {
                "componentProofRecordHash": test_hash("missing-component-id-proof")
            }
        ]
    });
    let missing_proof_component_id = super::verify_component_proof_bundle_backend(
        "verifyBallotProof",
        None,
        &missing_proof_component_id_bundle,
        Some(&proof_inputs),
    )
    .expect("malformed backend bundle should fail closed");
    assert_eq!(missing_proof_component_id["ok"], false);
    assert!(
        missing_proof_component_id["refusedObjects"][0]["message"]
            .as_str()
            .expect("message should be present")
            .contains("proof record is missing componentId")
    );

    let missing_input_component_id = super::verify_component_proof_bundle_backend(
        "verifyBallotProof",
        None,
        &json!({ "componentProofs": [] }),
        Some(&json!([{}])),
    )
    .expect("malformed backend input should fail closed");
    assert_eq!(missing_input_component_id["ok"], false);
    assert!(
        missing_input_component_id["refusedObjects"][0]["message"]
            .as_str()
            .expect("message should be present")
            .contains("input is missing componentId")
    );

    let unmatched_component_bundle = json!({
        "componentProofs": [
            {
                "componentId": "score-and-shamir-field-component",
                "componentProofRecordHash": test_hash("unmatched-component-proof")
            }
        ]
    });
    let unmatched_component = super::verify_component_proof_bundle_backend(
        "verifyBallotProof",
        None,
        &unmatched_component_bundle,
        Some(&proof_inputs),
    )
    .expect("unmatched backend component should fail closed");
    assert_eq!(unmatched_component["ok"], false);
    assert!(
        unmatched_component["refusedObjects"][0]["message"]
            .as_str()
            .expect("message should be present")
            .contains("has no matching proof input")
    );
}
