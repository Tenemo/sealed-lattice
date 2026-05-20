use super::*;

pub struct BallotProofRecordGenerationInput<'a> {
    pub statement: Option<&'a Value>,
    pub linear_statement: Option<&'a Value>,
    pub parameter_set: Option<&'a Value>,
    pub proof_encoding: Option<&'a Value>,
    pub public_randomness_hex: Option<&'a str>,
    pub component_bundle_statement: Option<&'a Value>,
    pub component_proof_inputs: Option<&'a Value>,
    pub secret_state: Option<&'a Value>,
    pub prover_randomness_hex: Option<&'a str>,
    pub component_prover_randomness_hexes: Option<&'a Value>,
    pub component_secret_states: Option<&'a Value>,
}

struct RequiredBallotProofRecordGenerationInput<'a> {
    statement: &'a Value,
    linear_statement: &'a Value,
    parameter_set: &'a Value,
    proof_encoding: &'a Value,
    public_randomness_hex: &'a str,
    component_bundle_statement: &'a Value,
    component_proof_inputs: &'a Value,
    secret_state: &'a Value,
    prover_randomness_hex: &'a str,
    component_prover_randomness_hexes: &'a Value,
    component_secret_states: Option<&'a Value>,
}

impl<'a> RequiredBallotProofRecordGenerationInput<'a> {
    fn parse(
        input: BallotProofRecordGenerationInput<'a>,
    ) -> crate::encoding::CanonicalResult<Self> {
        Ok(Self {
            statement: input.statement.ok_or_else(|| {
                invalid_preflight("statement is required for ballot proof record generation")
            })?,
            linear_statement: input.linear_statement.ok_or_else(|| {
                invalid_preflight(
                    "linearStatement is required for ballot proof record generation",
                )
            })?,
            parameter_set: input.parameter_set.ok_or_else(|| {
                invalid_preflight("parameterSet is required for ballot proof record generation")
            })?,
            proof_encoding: input.proof_encoding.ok_or_else(|| {
                invalid_preflight("proofEncoding is required for ballot proof record generation")
            })?,
            public_randomness_hex: input.public_randomness_hex.ok_or_else(|| {
                invalid_preflight(
                    "publicRandomnessHex is required for ballot proof record generation",
                )
            })?,
            component_bundle_statement: input.component_bundle_statement.ok_or_else(|| {
                invalid_preflight(
                    "componentBundleStatement is required for ballot proof record generation",
                )
            })?,
            component_proof_inputs: input.component_proof_inputs.ok_or_else(|| {
                invalid_preflight(
                    "componentProofInputs is required for ballot proof record generation",
                )
            })?,
            secret_state: input.secret_state.ok_or_else(|| {
                invalid_preflight("secretState is required for ballot proof record generation")
            })?,
            prover_randomness_hex: input.prover_randomness_hex.ok_or_else(|| {
                invalid_preflight(
                    "proverRandomnessHex is required for ballot proof record generation",
                )
            })?,
            component_prover_randomness_hexes: input
                .component_prover_randomness_hexes
                .ok_or_else(|| {
                    invalid_preflight(
                        "componentProverRandomnessHexes is required for ballot proof record generation",
                    )
                })?,
            component_secret_states: input.component_secret_states,
        })
    }

    fn validate_full_projection_coverage(&self) -> crate::encoding::CanonicalResult<()> {
        if string_field(self.linear_statement, "projectionCoverage")
            != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        {
            return Err(invalid_preflight(
                "ballot proof record generation requires a full encoded-score linear statement",
            ));
        }
        if string_field(self.component_bundle_statement, "bundleCoverage")
            != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        {
            return Err(invalid_preflight(
                "ballot proof record generation requires a full component bundle statement",
            ));
        }

        Ok(())
    }

    fn component_inputs_by_id(
        &self,
    ) -> crate::encoding::CanonicalResult<BTreeMap<&'a str, &'a Value>> {
        let component_inputs_array = self.component_proof_inputs.as_array().ok_or_else(|| {
            invalid_preflight("componentProofInputs must be an array for ballot proof generation")
        })?;
        if component_inputs_array.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
            return Err(invalid_preflight(
                "componentProofInputs must contain exactly the required ballot proof components",
            ));
        }

        let mut component_inputs_by_id = BTreeMap::new();
        for component_input in component_inputs_array {
            let component_id = string_field(component_input, "componentId")
                .ok_or_else(|| invalid_preflight("component proof input is missing componentId"))?;
            if object_map(component_input)
                .is_some_and(|object| object.contains_key("proofBytesHex"))
            {
                return Err(invalid_preflight(
                    "component proof inputs for generation must not pre-supply proofBytesHex",
                ));
            }
            if component_inputs_by_id
                .insert(component_id, component_input)
                .is_some()
            {
                return Err(invalid_preflight(
                    "component proof inputs contain a duplicate component",
                ));
            }
        }

        Ok(component_inputs_by_id)
    }
}

pub fn generate_ballot_proof_record(input: BallotProofRecordGenerationInput<'_>) -> Value {
    match generate_ballot_proof_record_inner(input) {
        Ok(value) => value,
        Err(error) => {
            structural_rejection("generateBallotProofRecord", vec![error.to_json_value()])
        }
    }
}

pub(crate) fn generate_ballot_proof_record_inner(
    input: BallotProofRecordGenerationInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let required_input = RequiredBallotProofRecordGenerationInput::parse(input)?;
    required_input.validate_full_projection_coverage()?;
    let statement = required_input.statement;
    let linear_statement = required_input.linear_statement;
    let parameter_set = required_input.parameter_set;
    let proof_encoding = required_input.proof_encoding;
    let public_randomness_hex = required_input.public_randomness_hex;
    let component_bundle_statement = required_input.component_bundle_statement;
    let secret_state = required_input.secret_state;
    let prover_randomness_hex = required_input.prover_randomness_hex;
    let component_prover_randomness_hexes = required_input.component_prover_randomness_hexes;
    let component_secret_states = required_input.component_secret_states;
    let component_inputs_by_id = required_input.component_inputs_by_id()?;

    let mut generated_component_proofs = Vec::new();
    let mut generated_component_inputs = Vec::new();
    for component_id in REQUIRED_BALLOT_PROOF_COMPONENT_IDS {
        let proof_input = component_inputs_by_id.get(*component_id).ok_or_else(|| {
            invalid_preflight(format!(
                "component proof input for {component_id} is missing"
            ))
        })?;
        let component_prover_randomness_hex =
            component_generation_randomness_hex(component_id, component_prover_randomness_hexes)?;
        let component_secret_state =
            component_generation_secret_state(component_id, secret_state, component_secret_states)?;
        let component_generation = generate_ballot_component_proof_inner(
            Some(component_id),
            Some(proof_input),
            Some(component_secret_state),
            Some(&component_prover_randomness_hex),
        )
        .map_err(|error| {
            invalid_preflight(format!(
                "component proof generation failed for {component_id}: {}",
                error.message
            ))
        })?;
        let component_proof_bytes_hex = string_field(&component_generation, "proofBytesHex")
            .ok_or_else(|| {
                invalid_preflight(format!(
                    "generated component proof for {component_id} did not return proofBytesHex"
                ))
            })?
            .to_string();
        let component_proof_size_bytes = object_map(&component_generation)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64)
            .and_then(|proof_size| usize::try_from(proof_size).ok())
            .ok_or_else(|| {
                invalid_preflight(format!(
                    "generated component proof for {component_id} did not return proofSizeBytes"
                ))
            })?;
        let generated_component_input = generated_component_proof_input(
            proof_input,
            &component_proof_bytes_hex,
            component_proof_size_bytes,
        )?;
        let component_proof = generated_component_proof_record(
            component_id,
            statement,
            component_bundle_statement,
            &generated_component_input,
            &component_proof_bytes_hex,
            component_proof_size_bytes,
        )?;
        generated_component_inputs.push(generated_component_input);
        generated_component_proofs.push(component_proof);
    }
    let component_proof_bundle =
        generated_component_proof_bundle(component_bundle_statement, generated_component_proofs)?;

    let ballot_generation = generate_ballot_proof_inner(
        Some(linear_statement),
        Some(parameter_set),
        Some(proof_encoding),
        Some(public_randomness_hex),
        Some(secret_state),
        Some(prover_randomness_hex),
    )
    .map_err(|error| {
        invalid_preflight(format!(
            "full ballot proof generation failed: {}",
            error.message
        ))
    })?;
    let proof_bytes_hex = string_field(&ballot_generation, "proofBytesHex")
        .ok_or_else(|| invalid_preflight("generated ballot proof did not return proofBytesHex"))?
        .to_string();
    let proof_size_bytes = object_map(&ballot_generation)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size| usize::try_from(proof_size).ok())
        .ok_or_else(|| invalid_preflight("generated ballot proof did not return proofSizeBytes"))?;
    let bound_parameter_set =
        proof_contract_with_expected_size(parameter_set, proof_size_bytes, "parameterSet")?;
    let bound_proof_encoding =
        proof_contract_with_expected_size(proof_encoding, proof_size_bytes, "proofEncoding")?;
    let ballot_proof = generated_ballot_proof_record(GeneratedBallotProofRecordInput {
        statement,
        linear_statement,
        parameter_set: &bound_parameter_set,
        proof_encoding: &bound_proof_encoding,
        public_randomness_hex,
        component_bundle_statement,
        component_proof_bundle: &component_proof_bundle,
        proof_bytes_hex: &proof_bytes_hex,
        proof_size_bytes,
    })?;
    let component_proof_inputs = Value::Array(generated_component_inputs);
    let verification = verify_ballot_proof(
        statement,
        &ballot_proof,
        BallotProofVerificationInputs {
            component_bundle_statement: Some(component_bundle_statement),
            component_proof_bundle: Some(&component_proof_bundle),
            component_proof_inputs: Some(&component_proof_inputs),
            linear_statement: Some(linear_statement),
            parameter_set: Some(&bound_parameter_set),
            proof_bytes_hex: Some(&proof_bytes_hex),
            proof_encoding: Some(&bound_proof_encoding),
            public_randomness_hex: Some(public_randomness_hex),
            skip_component_backend_verification: true,
        },
    );
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(format!(
            "generated ballot proof record did not verify: {verification}"
        )));
    }

    Ok(json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "generateBallotProofRecord",
        "statusLabels": [
            "BallotGeneratedProofVerified",
            "BallotComponentProofBundleGenerated",
            "BallotProofRecordGenerated",
            "BallotProofRecordGeneratedProofVerified"
        ],
        "acceptedDigests": [
            string_field(&ballot_proof, "ballotProofRecordDigest"),
            string_field(&component_proof_bundle, "componentProofBundleDigest"),
            string_field(&ballot_proof, "proofBytesDigest")
        ],
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": true,
        "proofBytesHex": proof_bytes_hex,
        "proofSizeBytes": proof_size_bytes,
        "parameterSet": bound_parameter_set,
        "proofEncoding": bound_proof_encoding,
        "ballotProof": ballot_proof,
        "componentProofBundle": component_proof_bundle,
        "componentProofInputs": component_proof_inputs,
        "verification": verification
    }))
}

pub(crate) fn component_generation_randomness_hex(
    component_id: &str,
    component_prover_randomness_hexes: &Value,
) -> crate::encoding::CanonicalResult<String> {
    if component_proof_bytes_must_be_empty(component_id) {
        return Ok("00".repeat(32));
    }
    object_map(component_prover_randomness_hexes)
        .and_then(|object| object.get(component_id))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            invalid_preflight(format!(
                "componentProverRandomnessHexes.{component_id} is required for proof generation"
            ))
        })
}

pub(crate) fn component_generation_secret_state<'a>(
    component_id: &str,
    default_secret_state: &'a Value,
    component_secret_states: Option<&'a Value>,
) -> crate::encoding::CanonicalResult<&'a Value> {
    let Some(component_secret_states) = component_secret_states else {
        return Ok(default_secret_state);
    };
    let component_secret_states = object_map(component_secret_states).ok_or_else(|| {
        invalid_preflight("componentSecretStates must be an object for ballot proof generation")
    })?;

    Ok(component_secret_states
        .get(component_id)
        .unwrap_or(default_secret_state))
}

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
    statement: &'a Value,
    linear_statement: &'a Value,
    parameter_set: &'a Value,
    proof_encoding: &'a Value,
    public_randomness_hex: &'a str,
    component_bundle_statement: &'a Value,
    component_proof_bundle: &'a Value,
    proof_bytes_hex: &'a str,
    proof_size_bytes: usize,
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
