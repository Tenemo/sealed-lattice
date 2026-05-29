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

pub(crate) fn proof_bytes_hash(
    proof_bytes_hex: &str,
    allow_empty: bool,
) -> crate::encoding::CanonicalResult<String> {
    let Some(proof_size_bytes) =
        super::hash_helpers::proof_bytes_size_from_lower_hex(proof_bytes_hex, true)
    else {
        return Err(invalid_preflight(
            "generated proof bytes must be lowercase hexadecimal bytes",
        ));
    };
    if !allow_empty && proof_size_bytes == 0 {
        return Err(invalid_preflight(
            "generated proof bytes must be non-empty for this proof record",
        ));
    }
    derive_protocol_hash_for_proof_bytes_payload(proof_bytes_hex, proof_size_bytes)
        .map_err(|_| invalid_preflight("generated proof bytes hash could not be derived"))
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
    if !proof_input.contains_key("componentProofStatementHash") {
        let proof_statement = proof_input
            .get("proofStatement")
            .ok_or_else(|| invalid_preflight("component proof input is missing proofStatement"))?;
        let proof_statement_format = proof_input
            .get("proofStatementFormat")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_preflight("component proof input is missing proofStatementFormat")
            })?;
        if let (Some(component_proof_statement_hash), _) =
            supplied_component_proof_statement_hash(proof_statement, proof_statement_format)
        {
            proof_input.insert(
                "componentProofStatementHash".to_string(),
                json!(component_proof_statement_hash),
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
    let proof_bytes_hash = proof_bytes_hash(proof_bytes_hex, allow_empty_proof_bytes)?;
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
    let proof_encoding_profile_hash = derive_ballot_proof_encoding_profile_hash(proof_encoding)
        .ok_or_else(|| invalid_preflight("component proof encoding hash could not be derived"))?;
    let proof_parameter_set_hash = derive_ballot_proof_parameter_set_hash(proof_parameter_set)
        .ok_or_else(|| {
            invalid_preflight("component proof parameter-set hash could not be derived")
        })?;
    let public_randomness_hash = derive_ballot_proof_public_randomness_hash(public_randomness_hex)
        .ok_or_else(|| {
            invalid_preflight("component proof public randomness hash could not be derived")
        })?;
    let component_statement_hash = string_field(component_proof_input, "statementHash")
        .ok_or_else(|| invalid_preflight("component proof input is missing statementHash"))?;

    let mut proof_root_payload = Map::new();
    proof_root_payload.insert("componentId".to_string(), json!(component_id));
    if let Some(component_proof_statement_hash) =
        string_field(component_proof_input, "componentProofStatementHash")
    {
        proof_root_payload.insert(
            "componentProofStatementHash".to_string(),
            json!(component_proof_statement_hash),
        );
    }
    proof_root_payload.insert(
        "componentStatementHash".to_string(),
        json!(component_statement_hash),
    );
    proof_root_payload.insert("proofBytesHash".to_string(), json!(proof_bytes_hash));
    proof_root_payload.insert(
        "proofEncodingProfileHash".to_string(),
        json!(proof_encoding_profile_hash),
    );
    proof_root_payload.insert(
        "proofParameterSetHash".to_string(),
        json!(proof_parameter_set_hash),
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
        "publicRandomnessHash".to_string(),
        json!(public_randomness_hash),
    );
    proof_root_payload.insert(
        "purpose".to_string(),
        json!("ballot-proof-component-proof-root-v1"),
    );
    proof_root_payload.insert("statementHash".to_string(), json!(component_statement_hash));
    let proof_root = derive_hash("ChallengeDomainHash", &Value::Object(proof_root_payload))
        .ok_or_else(|| invalid_preflight("component proof root could not be derived"))?;

    let mut component_proof_payload = Map::new();
    component_proof_payload.insert(
        "backendStatementHash".to_string(),
        json!(
            string_field(component_bundle_statement, "backendStatementHash").ok_or_else(|| {
                invalid_preflight("component bundle statement is missing backendStatementHash")
            })?
        ),
    );
    if let Some(ballot_proof_statement_hash) = string_field(statement, "ballotProofStatementHash") {
        component_proof_payload.insert(
            "ballotProofStatementHash".to_string(),
            json!(ballot_proof_statement_hash),
        );
    }
    component_proof_payload.insert("componentId".to_string(), json!(component_id));
    if let Some(component_proof_statement_hash) =
        string_field(component_proof_input, "componentProofStatementHash")
    {
        component_proof_payload.insert(
            "componentProofStatementHash".to_string(),
            json!(component_proof_statement_hash),
        );
    }
    component_proof_payload.insert(
        "componentStatementHash".to_string(),
        json!(component_statement_hash),
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
    component_proof_payload.insert("proofBytesHash".to_string(), json!(proof_bytes_hash));
    component_proof_payload.insert(
        "proofEncodingProfileHash".to_string(),
        json!(proof_encoding_profile_hash),
    );
    component_proof_payload.insert(
        "proofParameterSetHash".to_string(),
        json!(proof_parameter_set_hash),
    );
    component_proof_payload.insert("proofRoot".to_string(), json!(proof_root));
    component_proof_payload.insert("proofSizeBytes".to_string(), json!(proof_size_bytes));
    component_proof_payload.insert(
        "publicRandomnessHash".to_string(),
        json!(public_randomness_hash),
    );
    component_proof_payload.insert(
        "relationStatementHash".to_string(),
        json!(
            string_field(component_bundle_statement, "relationStatementHash").ok_or_else(|| {
                invalid_preflight("component bundle statement is missing relationStatementHash")
            })?
        ),
    );
    let component_proof_payload_value = Value::Object(component_proof_payload.clone());
    let component_proof_record_hash =
        derive_ballot_component_proof_record_hash(&component_proof_payload_value)
            .ok_or_else(|| invalid_preflight("component proof record hash could not be derived"))?;
    component_proof_payload.insert(
        "componentProofRecordHash".to_string(),
        json!(component_proof_record_hash),
    );

    Ok(Value::Object(component_proof_payload))
}

pub(crate) fn generated_component_proof_bundle(
    component_bundle_statement: &Value,
    component_proofs: Vec<Value>,
) -> crate::encoding::CanonicalResult<Value> {
    let mut component_proof_bundle_payload = Map::new();
    component_proof_bundle_payload.insert(
        "backendStatementHash".to_string(),
        json!(
            string_field(component_bundle_statement, "backendStatementHash").ok_or_else(|| {
                invalid_preflight("component bundle statement is missing backendStatementHash")
            })?
        ),
    );
    if let Some(ballot_proof_statement_hash) =
        string_field(component_bundle_statement, "ballotProofStatementHash")
    {
        component_proof_bundle_payload.insert(
            "ballotProofStatementHash".to_string(),
            json!(ballot_proof_statement_hash),
        );
    }
    component_proof_bundle_payload.insert(
        "bundleCoverage".to_string(),
        json!(FULL_BALLOT_PROOF_PROJECTION_COVERAGE),
    );
    component_proof_bundle_payload.insert(
        "componentBundleStatementHash".to_string(),
        json!(
            string_field(component_bundle_statement, "componentBundleStatementHash").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing componentBundleStatementHash"
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
        "relationStatementHash".to_string(),
        json!(
            string_field(component_bundle_statement, "relationStatementHash").ok_or_else(|| {
                invalid_preflight("component bundle statement is missing relationStatementHash")
            })?
        ),
    );
    component_proof_bundle_payload.insert(
        "requiredComponentIds".to_string(),
        json!(REQUIRED_BALLOT_PROOF_COMPONENT_IDS),
    );
    let component_proof_bundle_value = Value::Object(component_proof_bundle_payload.clone());
    let component_proof_bundle_hash =
        derive_ballot_component_proof_bundle_hash(&component_proof_bundle_value)
            .ok_or_else(|| invalid_preflight("component proof bundle hash could not be derived"))?;
    component_proof_bundle_payload.insert(
        "componentProofBundleHash".to_string(),
        json!(component_proof_bundle_hash),
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
    let proof_bytes_hash = proof_bytes_hash(proof_bytes_hex, false)?;
    let proof_encoding_profile_hash = derive_ballot_proof_encoding_profile_hash(proof_encoding)
        .ok_or_else(|| invalid_preflight("ballot proof encoding hash could not be derived"))?;
    let proof_parameter_set_hash = derive_ballot_proof_parameter_set_hash(parameter_set)
        .ok_or_else(|| invalid_preflight("ballot proof parameter-set hash could not be derived"))?;
    let public_randomness_hash = derive_ballot_proof_public_randomness_hash(public_randomness_hex)
        .ok_or_else(|| {
            invalid_preflight("ballot proof public randomness hash could not be derived")
        })?;
    let linear_statement_hash = string_field(linear_statement, "statementHash")
        .ok_or_else(|| invalid_preflight("linear statement is missing statementHash"))?;
    let proof_root = derive_hash(
        "BallotProofRecordHash",
        &json!({
            "linearStatementHash": linear_statement_hash,
            "proofBytesHash": proof_bytes_hash,
            "proofEncodingProfileHash": proof_encoding_profile_hash,
            "proofParameterSetHash": proof_parameter_set_hash,
            "publicRandomnessHash": public_randomness_hash,
            "purpose": "ballot-proof-linear-proof-record-root-v1",
        }),
    )
    .ok_or_else(|| invalid_preflight("ballot proof root could not be derived"))?;

    let mut proof_payload = Map::new();
    proof_payload.insert(
        "backendStatementHash".to_string(),
        json!(
            string_field(linear_statement, "backendStatementHash").ok_or_else(|| {
                invalid_preflight("linear statement is missing backendStatementHash")
            })?
        ),
    );
    proof_payload.insert(
        "ballotProofProfileHash".to_string(),
        json!(
            string_field(statement, "ballotProofProfileHash").ok_or_else(|| {
                invalid_preflight("statement is missing ballotProofProfileHash")
            })?
        ),
    );
    proof_payload.insert(
        "ballotProofStatementHash".to_string(),
        json!(
            string_field(statement, "ballotProofStatementHash").ok_or_else(|| {
                invalid_preflight("statement is missing ballotProofStatementHash")
            })?
        ),
    );
    proof_payload.insert(
        "componentBundleStatementHash".to_string(),
        json!(
            string_field(component_bundle_statement, "componentBundleStatementHash").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing componentBundleStatementHash"
                )
            )?
        ),
    );
    proof_payload.insert(
        "componentProofBundleHash".to_string(),
        json!(
            string_field(component_proof_bundle, "componentProofBundleHash").ok_or_else(|| {
                invalid_preflight("component proof bundle is missing componentProofBundleHash")
            })?
        ),
    );
    proof_payload.insert(
        "linearStatementHash".to_string(),
        json!(linear_statement_hash),
    );
    proof_payload.insert("objectType".to_string(), json!("BallotProofRecord"));
    proof_payload.insert("objectVersion".to_string(), json!(1));
    proof_payload.insert(
        "proofBackend".to_string(),
        json!("LocalLinearLatticeRelation"),
    );
    proof_payload.insert("proofBytesHash".to_string(), json!(proof_bytes_hash));
    proof_payload.insert(
        "proofEncodingProfileHash".to_string(),
        json!(proof_encoding_profile_hash),
    );
    proof_payload.insert(
        "proofParameterSetHash".to_string(),
        json!(proof_parameter_set_hash),
    );
    proof_payload.insert("proofRoot".to_string(), json!(proof_root));
    proof_payload.insert("proofSizeBytes".to_string(), json!(proof_size_bytes));
    proof_payload.insert(
        "publicRandomnessHash".to_string(),
        json!(public_randomness_hash),
    );
    proof_payload.insert(
        "relationStatementHash".to_string(),
        json!(
            string_field(linear_statement, "relationStatementHash").ok_or_else(|| {
                invalid_preflight("linear statement is missing relationStatementHash")
            })?
        ),
    );
    proof_payload.insert(
        "statementMatrixHash".to_string(),
        json!(
            string_field(linear_statement, "statementMatrixHash").ok_or_else(|| {
                invalid_preflight("linear statement is missing statementMatrixHash")
            })?
        ),
    );
    proof_payload.insert(
        "targetVectorHash".to_string(),
        json!(
            string_field(linear_statement, "targetVectorHash").ok_or_else(|| {
                invalid_preflight("linear statement is missing targetVectorHash")
            })?
        ),
    );
    let challenge_hash =
        derive_ballot_proof_challenge_hash(statement, &Value::Object(proof_payload.clone()))
            .ok_or_else(|| invalid_preflight("ballot proof challenge hash could not be derived"))?;
    proof_payload.insert("challengeHash".to_string(), json!(challenge_hash));
    let proof_payload_value = Value::Object(proof_payload.clone());
    let ballot_proof_record_hash = derive_hash("BallotProofRecordHash", &proof_payload_value)
        .ok_or_else(|| invalid_preflight("ballot proof record hash could not be derived"))?;
    proof_payload.insert(
        "ballotProofRecordHash".to_string(),
        json!(ballot_proof_record_hash),
    );

    Ok(Value::Object(proof_payload))
}
