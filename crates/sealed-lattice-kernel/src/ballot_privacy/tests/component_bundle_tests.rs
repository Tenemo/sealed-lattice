use super::*;

pub(super) fn component_proof_statement_for_test(
    component_id: &str,
    component_statement_digest: &Value,
    component_proof_statement_digest: Option<String>,
    proof_statement_format: &str,
) -> Value {
    if proof_statement_format == "dense-polynomial-matrix-linear-proof-v1" {
        let statement_payload = json!({
            "objectType": "BallotProofLinearProofStatement",
            "objectVersion": 1,
            "componentId": component_id,
            "componentStatementDigest": component_statement_digest,
            "proofStatementFormat": proof_statement_format,
        });
        let statement_digest = super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "payload": statement_payload,
                "purpose": "ballot-proof-linear-proof-statement-v1"
            }),
        )
        .expect("dense component proof statement digest should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("dense component proof statement should be an object")
            .insert("statementDigest".to_string(), json!(statement_digest));

        return statement;
    }
    if proof_statement_format == "sparse-polynomial-matrix-linear-proof-v1" {
        let statement_payload = json!({
            "objectType": "BallotProofSparseComponentLinearProofStatement",
            "objectVersion": 1,
            "componentId": component_id,
            "componentStatementDigest": component_statement_digest,
            "proofStatementFormat": proof_statement_format,
        });
        let statement_digest = super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "payload": statement_payload,
                "purpose": "ballot-proof-sparse-linear-proof-statement-v1"
            }),
        )
        .expect("sparse component proof statement digest should derive");
        let mut statement = statement_payload;
        statement
            .as_object_mut()
            .expect("sparse component proof statement should be an object")
            .insert("statementDigest".to_string(), json!(statement_digest));

        return statement;
    }
    let is_structured = proof_statement_format == "structured-module-lwe-linear-proof-v1";
    let statement_payload = json!({
        "backendStatementDigest": test_digest(&format!("{component_id}-backend")),
        "coefficientModulus": if component_id == "share-commitment-component" {
            "18446744069414584321"
        } else if component_id == "score-and-shamir-field-component"
            || component_id == "payload-plaintext-field-component" {
            "65537"
        } else {
            "12289"
        },
        "objectType": "BallotProofComponentProofStatementPlan",
        "objectVersion": 1,
        "componentId": component_id,
        "componentStatementDigest": component_statement_digest,
        "denseCoefficientCount": if is_structured { json!("1024") } else { Value::Null },
        "matrixDigest": test_digest(&format!("{component_id}-matrix")),
        "proofBytesAvailability": if is_structured {
            "requires-structured-proof-statement"
        } else {
            "public-zero-witness-binding-check"
        },
        "proofLoweringStatus": "explicitRowsAvailable",
        "proofStatementFormat": proof_statement_format,
        "proofSystemRingDegree": if is_structured { json!(64) } else { Value::Null },
        "relation": "A*w + t = 0",
        "relationStatementDigest": test_digest(&format!("{component_id}-relation")),
        "rowBatchMatrixDigests": [test_digest(&format!("{component_id}-row-matrix"))],
        "rowBatchNames": [if is_structured {
            "receiver_payload_encryption_equation_rows"
        } else {
            "receiver_key_binding_rows"
        }],
        "rowBatchTargetVectorDigests": [test_digest(&format!("{component_id}-row-target"))],
        "rowBatchTermCounts": [if is_structured { "1024" } else { "0" }],
        "rowCount": 1,
        "sparseTermCount": Value::Null,
        "sourceRingDegree": if is_structured { json!(256) } else { Value::Null },
        "structuredCiphertextChunkCount": if is_structured { json!(1) } else { Value::Null },
        "structuredReceiverCount": if is_structured { json!(1) } else { Value::Null },
        "structuredWitnessTermCount": if is_structured { json!("1024") } else { Value::Null },
        "targetVectorDigest": test_digest(&format!("{component_id}-target")),
        "variableColumnCount": if is_structured { 1 } else { 0 },
        "variableColumnIndices": if is_structured { json!([0]) } else { json!([]) },
    });
    let canonical_component_proof_statement_digest = super::derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-proof-statement-plan-v1"
        }),
    )
    .expect("component proof statement plan digest should derive");
    let mut statement_plan = statement_payload;
    statement_plan
        .as_object_mut()
        .expect("component proof statement plan should be an object")
        .insert(
            "componentProofStatementDigest".to_string(),
            json!(
                component_proof_statement_digest
                    .unwrap_or(canonical_component_proof_statement_digest)
            ),
        );

    statement_plan
}

pub(super) fn component_proof_for_test(
    component_id: &str,
    component_statement_digest: &Value,
) -> Value {
    let proof_input = component_proof_input_for_test(component_id, component_statement_digest);
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
    let proof_bytes_digest = proof_bytes_digest_for_test(proof_bytes_hex);
    let proof_encoding_profile_digest =
        super::derive_ballot_proof_encoding_profile_digest(proof_encoding)
            .expect("component proof encoding digest should derive");
    let proof_parameter_set_digest =
        super::derive_ballot_proof_parameter_set_digest(proof_parameter_set)
            .expect("component proof parameter set digest should derive");
    let public_randomness_digest =
        super::derive_ballot_proof_public_randomness_digest(public_randomness_hex)
            .expect("component proof public randomness digest should derive");
    let proof_root = super::derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "componentId": component_id,
            "componentProofStatementDigest": proof_input["componentProofStatementDigest"],
            "componentStatementDigest": component_statement_digest,
            "proofBytesDigest": proof_bytes_digest,
            "proofEncodingProfileDigest": proof_encoding_profile_digest,
            "proofParameterSetDigest": proof_parameter_set_digest,
            "proofStatementFormat": proof_input["proofStatementFormat"],
            "publicRandomnessDigest": public_randomness_digest,
            "purpose": "ballot-proof-component-proof-root-v1",
            "statementDigest": component_statement_digest,
        }),
    )
    .expect("component proof root should derive");
    let component_proof_payload = json!({
        "objectType": "BallotProofComponentProofRecord",
        "objectVersion": 1,
        "backendStatementDigest": test_digest("backend-statement"),
        "ballotProofStatementDigest": test_digest("ballot-proof-statement"),
        "componentId": component_id,
        "componentProofStatementDigest": proof_input["componentProofStatementDigest"],
        "componentStatementDigest": component_statement_digest,
        "proofBackend": "LocalLinearLatticeRelation",
        "proofBytesDigest": proof_bytes_digest,
        "proofEncodingProfileDigest": proof_encoding_profile_digest,
        "proofParameterSetDigest": proof_parameter_set_digest,
        "proofRoot": proof_root,
        "proofSizeBytes": proof_bytes_hex.len() / 2,
        "publicRandomnessDigest": public_randomness_digest,
        "relationStatementDigest": test_digest("relation-statement"),
    });
    let component_proof_record_digest =
        super::derive_ballot_component_proof_record_digest(&component_proof_payload)
            .expect("component proof digest should derive");
    let mut component_proof = component_proof_payload;
    component_proof
        .as_object_mut()
        .expect("component proof should be an object")
        .insert(
            "componentProofRecordDigest".to_string(),
            json!(component_proof_record_digest),
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
        "backendStatementDigest": test_digest("backend-statement"),
        "ballotProofStatementDigest": test_digest("ballot-proof-statement"),
        "bundleCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        "componentBundleStatementDigest": component_bundle_statement["componentBundleStatementDigest"],
        "componentProofs": component_proofs,
        "relationStatementDigest": test_digest("relation-statement"),
        "requiredComponentIds": super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
    });
    let component_proof_bundle_digest =
        super::derive_ballot_component_proof_bundle_digest(&component_proof_bundle_payload)
            .expect("component proof bundle digest should derive");
    let mut component_proof_bundle = component_proof_bundle_payload;
    component_proof_bundle
        .as_object_mut()
        .expect("component proof bundle should be an object")
        .insert(
            "componentProofBundleDigest".to_string(),
            json!(component_proof_bundle_digest),
        );

    component_proof_bundle
}

#[test]
fn component_bundle_refusals_cover_incomplete_and_reordered_components() {
    let statement = json!({
        "ballotProofStatementDigest": test_digest("ballot-proof-statement")
    });
    let linear_statement = json!({
        "backendStatementDigest": test_digest("backend-statement"),
        "projectionCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        "relationStatementDigest": test_digest("relation-statement")
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
                    "digestExpandedRowsPending"
                },
            )
        })
        .collect::<Vec<_>>();
    let incomplete_bundle = component_bundle_for_test(
        incomplete_component_statements,
        super::COMPONENT_BUNDLE_INCOMPLETE_COVERAGE,
    );
    let ballot_proof = json!({
        "ballotProofRecordDigest": test_digest("ballot-proof-record"),
        "componentBundleStatementDigest": incomplete_bundle["componentBundleStatementDigest"],
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
        "ballotProofRecordDigest": test_digest("reordered-ballot-proof-record"),
        "componentBundleStatementDigest": reordered_bundle["componentBundleStatementDigest"],
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
        "ballotProofStatementDigest": test_digest("ballot-proof-statement")
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
            component_proof_for_test(
                component_id,
                &component_statement["componentStatementDigest"],
            )
        })
        .collect::<Vec<_>>();
    let component_proof_inputs = component_statements
        .iter()
        .zip(super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter())
        .map(|(component_statement, component_id)| {
            component_proof_input_for_test(
                component_id,
                &component_statement["componentStatementDigest"],
            )
        })
        .collect::<Vec<_>>();
    let component_proof_bundle =
        component_proof_bundle_for_test(&component_bundle_statement, component_proofs.clone());
    let component_proof_inputs = json!(component_proof_inputs);
    let ballot_proof = json!({
        "backendStatementDigest": test_digest("backend-statement"),
        "ballotProofRecordDigest": test_digest("ballot-proof-record"),
        "componentBundleStatementDigest": component_bundle_statement["componentBundleStatementDigest"],
        "componentProofBundleDigest": component_proof_bundle["componentProofBundleDigest"],
        "relationStatementDigest": test_digest("relation-statement"),
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
    wrong_component_proof_statement_inputs[0]["componentProofStatementDigest"] =
        json!(test_digest("wrong-component-proof-statement"));
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
        &component_bundle_statement["componentStatements"][3]["componentStatementDigest"],
        Some(test_digest(
            "wrong-supplied-component-proof-statement-canonical-digest",
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
                            "proof statement digest for receiver-encryption-component does not match its canonical payload",
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
        "backendStatementDigest": test_digest("backend-statement"),
        "ballotProofRecordDigest": test_digest("reordered-ballot-proof-record"),
        "componentBundleStatementDigest": component_bundle_statement["componentBundleStatementDigest"],
        "componentProofBundleDigest": reordered_proof_bundle["componentProofBundleDigest"],
        "relationStatementDigest": test_digest("relation-statement"),
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
    wrong_statement_proof_bundle["componentProofs"][0]["componentStatementDigest"] =
        json!(test_digest("wrong-component-statement"));
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
                "componentProofRecordDigest": test_digest("missing-component-id-proof")
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
                "componentProofRecordDigest": test_digest("unmatched-component-proof")
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
