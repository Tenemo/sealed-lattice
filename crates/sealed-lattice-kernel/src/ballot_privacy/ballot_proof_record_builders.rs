use super::*;

pub(crate) fn proof_contract_with_expected_size(
    proof_contract: &Value,
    proof_size_bytes: usize,
    field_name: &str,
) -> crate::encoding::CanonicalResult<Value> {
    let mut proof_contract = object_map(proof_contract)
        .ok_or_else(|| invalid_preflight(format!("{field_name} must be an object")))?
        .clone();
    proof_contract.insert(
        "expectedProofSizeBytes".to_string(),
        json!(proof_size_bytes),
    );

    Ok(Value::Object(proof_contract))
}

pub(crate) fn proof_bytes_digest(
    proof_bytes_hex: &str,
    allow_empty: bool,
) -> crate::encoding::CanonicalResult<String> {
    let proof_bytes = decode_hex(proof_bytes_hex).map_err(|_| {
        invalid_preflight("generated proof bytes must be lowercase hexadecimal bytes")
    })?;
    if !allow_empty && proof_bytes.is_empty() {
        return Err(invalid_preflight(
            "generated proof bytes must be non-empty for this proof record",
        ));
    }
    derive_digest(
        "ProofBytesDigest",
        &json!({
            "objectType": "ProofBytes",
            "objectVersion": 1,
            "proofBytesHex": proof_bytes_hex,
            "proofSizeBytes": proof_bytes.len(),
        }),
    )
    .ok_or_else(|| invalid_preflight("generated proof bytes digest could not be derived"))
}

pub(crate) fn generated_component_proof_input(
    proof_input: &Value,
    proof_bytes_hex: &str,
    proof_size_bytes: usize,
) -> crate::encoding::CanonicalResult<Value> {
    let mut proof_input = object_map(proof_input)
        .ok_or_else(|| invalid_preflight("component proof input must be an object"))?
        .clone();
    let parameter_set = proof_input
        .get("proofParameterSet")
        .cloned()
        .ok_or_else(|| invalid_preflight("component proof input is missing proofParameterSet"))?;
    let proof_encoding = proof_input
        .get("proofEncoding")
        .cloned()
        .ok_or_else(|| invalid_preflight("component proof input is missing proofEncoding"))?;
    proof_input.insert(
        "proofParameterSet".to_string(),
        proof_contract_with_expected_size(
            &parameter_set,
            proof_size_bytes,
            "component proof parameter set",
        )?,
    );
    proof_input.insert(
        "proofEncoding".to_string(),
        proof_contract_with_expected_size(
            &proof_encoding,
            proof_size_bytes,
            "component proof encoding",
        )?,
    );
    if !proof_input.contains_key("componentProofStatementDigest") {
        let proof_statement = proof_input
            .get("proofStatement")
            .ok_or_else(|| invalid_preflight("component proof input is missing proofStatement"))?;
        let proof_statement_format = proof_input
            .get("proofStatementFormat")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_preflight("component proof input is missing proofStatementFormat")
            })?;
        if let (Some(component_proof_statement_digest), _) =
            supplied_component_proof_statement_digest(proof_statement, proof_statement_format)
        {
            proof_input.insert(
                "componentProofStatementDigest".to_string(),
                json!(component_proof_statement_digest),
            );
        }
    }
    proof_input.insert("proofBytesHex".to_string(), json!(proof_bytes_hex));

    Ok(Value::Object(proof_input))
}

pub(crate) fn generated_component_proof_record(
    component_id: &str,
    statement: &Value,
    component_bundle_statement: &Value,
    component_proof_input: &Value,
    proof_bytes_hex: &str,
    proof_size_bytes: usize,
) -> crate::encoding::CanonicalResult<Value> {
    let allow_empty_proof_bytes = component_proof_bytes_must_be_empty(component_id);
    let proof_bytes_digest = proof_bytes_digest(proof_bytes_hex, allow_empty_proof_bytes)?;
    let proof_encoding = required_json_field(
        component_proof_input,
        "proofEncoding",
        "componentProofInput",
    )?;
    let proof_parameter_set = required_json_field(
        component_proof_input,
        "proofParameterSet",
        "componentProofInput",
    )?;
    let public_randomness_hex = string_field(component_proof_input, "publicRandomnessHex")
        .ok_or_else(|| invalid_preflight("component proof input is missing publicRandomnessHex"))?;
    let proof_encoding_profile_digest = derive_ballot_proof_encoding_profile_digest(proof_encoding)
        .ok_or_else(|| invalid_preflight("component proof encoding digest could not be derived"))?;
    let proof_parameter_set_digest = derive_ballot_proof_parameter_set_digest(proof_parameter_set)
        .ok_or_else(|| {
            invalid_preflight("component proof parameter-set digest could not be derived")
        })?;
    let public_randomness_digest =
        derive_ballot_proof_public_randomness_digest(public_randomness_hex).ok_or_else(|| {
            invalid_preflight("component proof public randomness digest could not be derived")
        })?;
    let component_statement_digest = string_field(component_proof_input, "statementDigest")
        .ok_or_else(|| invalid_preflight("component proof input is missing statementDigest"))?;

    let mut proof_root_payload = Map::new();
    proof_root_payload.insert("componentId".to_string(), json!(component_id));
    if let Some(component_proof_statement_digest) =
        string_field(component_proof_input, "componentProofStatementDigest")
    {
        proof_root_payload.insert(
            "componentProofStatementDigest".to_string(),
            json!(component_proof_statement_digest),
        );
    }
    proof_root_payload.insert(
        "componentStatementDigest".to_string(),
        json!(component_statement_digest),
    );
    proof_root_payload.insert("proofBytesDigest".to_string(), json!(proof_bytes_digest));
    proof_root_payload.insert(
        "proofEncodingProfileDigest".to_string(),
        json!(proof_encoding_profile_digest),
    );
    proof_root_payload.insert(
        "proofParameterSetDigest".to_string(),
        json!(proof_parameter_set_digest),
    );
    proof_root_payload.insert(
        "proofStatementFormat".to_string(),
        json!(
            string_field(component_proof_input, "proofStatementFormat").ok_or_else(|| {
                invalid_preflight("component proof input is missing proofStatementFormat")
            })?
        ),
    );
    proof_root_payload.insert(
        "publicRandomnessDigest".to_string(),
        json!(public_randomness_digest),
    );
    proof_root_payload.insert(
        "purpose".to_string(),
        json!("ballot-proof-component-proof-root-v1"),
    );
    proof_root_payload.insert(
        "statementDigest".to_string(),
        json!(component_statement_digest),
    );
    let proof_root = derive_digest("ChallengeDomainDigest", &Value::Object(proof_root_payload))
        .ok_or_else(|| invalid_preflight("component proof root could not be derived"))?;

    let mut component_proof_payload = Map::new();
    component_proof_payload.insert(
        "backendStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "backendStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing backendStatementDigest"
                )
            )?
        ),
    );
    if let Some(ballot_proof_statement_digest) =
        string_field(statement, "ballotProofStatementDigest")
    {
        component_proof_payload.insert(
            "ballotProofStatementDigest".to_string(),
            json!(ballot_proof_statement_digest),
        );
    }
    component_proof_payload.insert("componentId".to_string(), json!(component_id));
    if let Some(component_proof_statement_digest) =
        string_field(component_proof_input, "componentProofStatementDigest")
    {
        component_proof_payload.insert(
            "componentProofStatementDigest".to_string(),
            json!(component_proof_statement_digest),
        );
    }
    component_proof_payload.insert(
        "componentStatementDigest".to_string(),
        json!(component_statement_digest),
    );
    component_proof_payload.insert(
        "objectType".to_string(),
        json!("BallotProofComponentProofRecord"),
    );
    component_proof_payload.insert("objectVersion".to_string(), json!(1));
    component_proof_payload.insert(
        "proofBackend".to_string(),
        json!("LocalLinearLatticeRelation"),
    );
    component_proof_payload.insert("proofBytesDigest".to_string(), json!(proof_bytes_digest));
    component_proof_payload.insert(
        "proofEncodingProfileDigest".to_string(),
        json!(proof_encoding_profile_digest),
    );
    component_proof_payload.insert(
        "proofParameterSetDigest".to_string(),
        json!(proof_parameter_set_digest),
    );
    component_proof_payload.insert("proofRoot".to_string(), json!(proof_root));
    component_proof_payload.insert("proofSizeBytes".to_string(), json!(proof_size_bytes));
    component_proof_payload.insert(
        "publicRandomnessDigest".to_string(),
        json!(public_randomness_digest),
    );
    component_proof_payload.insert(
        "relationStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "relationStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing relationStatementDigest"
                )
            )?
        ),
    );
    let component_proof_payload_value = Value::Object(component_proof_payload.clone());
    let component_proof_record_digest = derive_ballot_component_proof_record_digest(
        &component_proof_payload_value,
    )
    .ok_or_else(|| invalid_preflight("component proof record digest could not be derived"))?;
    component_proof_payload.insert(
        "componentProofRecordDigest".to_string(),
        json!(component_proof_record_digest),
    );

    Ok(Value::Object(component_proof_payload))
}

pub(crate) fn generated_component_proof_bundle(
    component_bundle_statement: &Value,
    component_proofs: Vec<Value>,
) -> crate::encoding::CanonicalResult<Value> {
    let mut component_proof_bundle_payload = Map::new();
    component_proof_bundle_payload.insert(
        "backendStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "backendStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing backendStatementDigest"
                )
            )?
        ),
    );
    if let Some(ballot_proof_statement_digest) =
        string_field(component_bundle_statement, "ballotProofStatementDigest")
    {
        component_proof_bundle_payload.insert(
            "ballotProofStatementDigest".to_string(),
            json!(ballot_proof_statement_digest),
        );
    }
    component_proof_bundle_payload.insert(
        "bundleCoverage".to_string(),
        json!(FULL_BALLOT_PROOF_PROJECTION_COVERAGE),
    );
    component_proof_bundle_payload.insert(
        "componentBundleStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "componentBundleStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing componentBundleStatementDigest"
                )
            )?
        ),
    );
    component_proof_bundle_payload.insert("componentProofs".to_string(), json!(component_proofs));
    component_proof_bundle_payload.insert(
        "objectType".to_string(),
        json!("BallotProofComponentProofBundle"),
    );
    component_proof_bundle_payload.insert("objectVersion".to_string(), json!(1));
    component_proof_bundle_payload.insert(
        "relationStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "relationStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing relationStatementDigest"
                )
            )?
        ),
    );
    component_proof_bundle_payload.insert(
        "requiredComponentIds".to_string(),
        json!(REQUIRED_BALLOT_PROOF_COMPONENT_IDS),
    );
    let component_proof_bundle_value = Value::Object(component_proof_bundle_payload.clone());
    let component_proof_bundle_digest = derive_ballot_component_proof_bundle_digest(
        &component_proof_bundle_value,
    )
    .ok_or_else(|| invalid_preflight("component proof bundle digest could not be derived"))?;
    component_proof_bundle_payload.insert(
        "componentProofBundleDigest".to_string(),
        json!(component_proof_bundle_digest),
    );

    Ok(Value::Object(component_proof_bundle_payload))
}

pub(crate) struct GeneratedBallotProofRecordInput<'a> {
    pub(crate) statement: &'a Value,
    pub(crate) linear_statement: &'a Value,
    pub(crate) parameter_set: &'a Value,
    pub(crate) proof_encoding: &'a Value,
    pub(crate) public_randomness_hex: &'a str,
    pub(crate) component_bundle_statement: &'a Value,
    pub(crate) component_proof_bundle: &'a Value,
    pub(crate) proof_bytes_hex: &'a str,
    pub(crate) proof_size_bytes: usize,
}

pub(crate) fn generated_ballot_proof_record(
    input: GeneratedBallotProofRecordInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let statement = input.statement;
    let linear_statement = input.linear_statement;
    let parameter_set = input.parameter_set;
    let proof_encoding = input.proof_encoding;
    let public_randomness_hex = input.public_randomness_hex;
    let component_bundle_statement = input.component_bundle_statement;
    let component_proof_bundle = input.component_proof_bundle;
    let proof_bytes_hex = input.proof_bytes_hex;
    let proof_size_bytes = input.proof_size_bytes;
    let proof_bytes_digest = proof_bytes_digest(proof_bytes_hex, false)?;
    let proof_encoding_profile_digest = derive_ballot_proof_encoding_profile_digest(proof_encoding)
        .ok_or_else(|| invalid_preflight("ballot proof encoding digest could not be derived"))?;
    let proof_parameter_set_digest = derive_ballot_proof_parameter_set_digest(parameter_set)
        .ok_or_else(|| {
            invalid_preflight("ballot proof parameter-set digest could not be derived")
        })?;
    let public_randomness_digest =
        derive_ballot_proof_public_randomness_digest(public_randomness_hex).ok_or_else(|| {
            invalid_preflight("ballot proof public randomness digest could not be derived")
        })?;
    let linear_statement_digest = string_field(linear_statement, "statementDigest")
        .ok_or_else(|| invalid_preflight("linear statement is missing statementDigest"))?;
    let proof_root = derive_digest(
        "BallotProofRecordDigest",
        &json!({
            "linearStatementDigest": linear_statement_digest,
            "proofBytesDigest": proof_bytes_digest,
            "proofEncodingProfileDigest": proof_encoding_profile_digest,
            "proofParameterSetDigest": proof_parameter_set_digest,
            "publicRandomnessDigest": public_randomness_digest,
            "purpose": "ballot-proof-linear-proof-record-root-v1",
        }),
    )
    .ok_or_else(|| invalid_preflight("ballot proof root could not be derived"))?;

    let mut proof_payload = Map::new();
    proof_payload.insert(
        "backendStatementDigest".to_string(),
        json!(
            string_field(linear_statement, "backendStatementDigest").ok_or_else(|| {
                invalid_preflight("linear statement is missing backendStatementDigest")
            })?
        ),
    );
    proof_payload.insert(
        "ballotProofProfileDigest".to_string(),
        json!(
            string_field(statement, "ballotProofProfileDigest").ok_or_else(|| {
                invalid_preflight("statement is missing ballotProofProfileDigest")
            })?
        ),
    );
    proof_payload.insert(
        "ballotProofStatementDigest".to_string(),
        json!(
            string_field(statement, "ballotProofStatementDigest").ok_or_else(|| {
                invalid_preflight("statement is missing ballotProofStatementDigest")
            })?
        ),
    );
    proof_payload.insert(
        "componentBundleStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "componentBundleStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing componentBundleStatementDigest"
                )
            )?
        ),
    );
    proof_payload.insert(
        "componentProofBundleDigest".to_string(),
        json!(
            string_field(component_proof_bundle, "componentProofBundleDigest").ok_or_else(
                || invalid_preflight(
                    "component proof bundle is missing componentProofBundleDigest"
                )
            )?
        ),
    );
    proof_payload.insert(
        "linearStatementDigest".to_string(),
        json!(linear_statement_digest),
    );
    proof_payload.insert("objectType".to_string(), json!("BallotProofRecord"));
    proof_payload.insert("objectVersion".to_string(), json!(1));
    proof_payload.insert(
        "proofBackend".to_string(),
        json!("LocalLinearLatticeRelation"),
    );
    proof_payload.insert("proofBytesDigest".to_string(), json!(proof_bytes_digest));
    proof_payload.insert(
        "proofEncodingProfileDigest".to_string(),
        json!(proof_encoding_profile_digest),
    );
    proof_payload.insert(
        "proofParameterSetDigest".to_string(),
        json!(proof_parameter_set_digest),
    );
    proof_payload.insert("proofRoot".to_string(), json!(proof_root));
    proof_payload.insert("proofSizeBytes".to_string(), json!(proof_size_bytes));
    proof_payload.insert(
        "publicRandomnessDigest".to_string(),
        json!(public_randomness_digest),
    );
    proof_payload.insert(
        "relationStatementDigest".to_string(),
        json!(
            string_field(linear_statement, "relationStatementDigest").ok_or_else(|| {
                invalid_preflight("linear statement is missing relationStatementDigest")
            })?
        ),
    );
    proof_payload.insert(
        "statementMatrixDigest".to_string(),
        json!(
            string_field(linear_statement, "statementMatrixDigest").ok_or_else(|| {
                invalid_preflight("linear statement is missing statementMatrixDigest")
            })?
        ),
    );
    proof_payload.insert(
        "targetVectorDigest".to_string(),
        json!(
            string_field(linear_statement, "targetVectorDigest").ok_or_else(|| {
                invalid_preflight("linear statement is missing targetVectorDigest")
            })?
        ),
    );
    let challenge_digest =
        derive_ballot_proof_challenge_digest(statement, &Value::Object(proof_payload.clone()))
            .ok_or_else(|| {
                invalid_preflight("ballot proof challenge digest could not be derived")
            })?;
    proof_payload.insert("challengeDigest".to_string(), json!(challenge_digest));
    let proof_payload_value = Value::Object(proof_payload.clone());
    let ballot_proof_record_digest = derive_digest("BallotProofRecordDigest", &proof_payload_value)
        .ok_or_else(|| invalid_preflight("ballot proof record digest could not be derived"))?;
    proof_payload.insert(
        "ballotProofRecordDigest".to_string(),
        json!(ballot_proof_record_digest),
    );

    Ok(Value::Object(proof_payload))
}
