use super::*;

pub(crate) struct BallotLinearProofVerificationInputs<'a> {
    component_proof_bundle: Option<&'a Value>,
    component_proof_inputs: Option<&'a Value>,
    linear_statement: &'a Value,
    proof_bytes_hex: &'a str,
    public_randomness_hex: &'a str,
    parameter_set: &'a Value,
    proof_encoding: &'a Value,
    component_bundle_statement: Option<&'a Value>,
    component_proof_verification_mode: ComponentProofVerificationMode,
}

pub(crate) struct BallotProofVerificationInputs<'a> {
    pub(crate) proof_bytes_hex: Option<&'a str>,
    pub(crate) linear_statement: Option<&'a Value>,
    pub(crate) public_randomness_hex: Option<&'a str>,
    pub(crate) parameter_set: Option<&'a Value>,
    pub(crate) proof_encoding: Option<&'a Value>,
    pub(crate) component_bundle_statement: Option<&'a Value>,
    pub(crate) component_proof_inputs: Option<&'a Value>,
    pub(crate) component_proof_bundle: Option<&'a Value>,
    pub(crate) dynamic_roster_profile_evidence: Option<&'a Value>,
    pub(crate) component_proof_verification_mode: ComponentProofVerificationMode,
    pub(crate) unsafe_small_roster_acknowledged: bool,
}

pub(crate) struct BallotProofVerificationRequest<'a> {
    statement: &'a Value,
    ballot_proof: &'a Value,
    backend_inputs: BallotProofVerificationInputs<'a>,
}

impl<'a> BallotProofVerificationRequest<'a> {
    pub(crate) fn from_command_request(
        request: &'a Value,
    ) -> crate::encoding::CanonicalResult<Self> {
        Ok(Self {
            statement: required_json_field(request, "statement", "verifyBallotProof")?,
            ballot_proof: required_json_field(request, "ballotProof", "verifyBallotProof")?,
            backend_inputs: BallotProofVerificationInputs {
                component_bundle_statement: object_map(request)
                    .and_then(|object| object.get("componentBundleStatement")),
                component_proof_bundle: object_map(request)
                    .and_then(|object| object.get("componentProofBundle")),
                component_proof_inputs: object_map(request)
                    .and_then(|object| object.get("componentProofInputs")),
                dynamic_roster_profile_evidence: object_map(request)
                    .and_then(|object| object.get("dynamicRosterProfileEvidence")),
                linear_statement: object_map(request)
                    .and_then(|object| object.get("linearStatement")),
                parameter_set: object_map(request).and_then(|object| object.get("parameterSet")),
                proof_bytes_hex: string_field(request, "proofBytesHex"),
                proof_encoding: object_map(request).and_then(|object| object.get("proofEncoding")),
                public_randomness_hex: string_field(request, "publicRandomnessHex"),
                component_proof_verification_mode: ComponentProofVerificationMode::VerifyBackend,
                unsafe_small_roster_acknowledged: object_map(request)
                    .and_then(|object| object.get("unsafeSmallRosterAcknowledged"))
                    .and_then(Value::as_bool)
                    == Some(true)
                    || object_map(request)
                        .and_then(|object| object.get("casualMicroRosterAcknowledged"))
                        .and_then(Value::as_bool)
                        == Some(true),
            },
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ComponentProofVerificationMode {
    VerifyBackend,
    AlreadyVerifiedDuringGeneration,
}

impl ComponentProofVerificationMode {
    fn verifies_component_backend(self) -> bool {
        self == Self::VerifyBackend
    }
}

pub(crate) fn verify_ballot_linear_proof_bytes(
    statement: &Value,
    ballot_proof: &Value,
    backend_inputs: BallotLinearProofVerificationInputs<'_>,
) -> Value {
    let linear_statement = backend_inputs.linear_statement;
    let proof_bytes_hex = backend_inputs.proof_bytes_hex;
    let public_randomness_hex = backend_inputs.public_randomness_hex;
    let parameter_set = backend_inputs.parameter_set;
    let proof_encoding = backend_inputs.proof_encoding;
    let component_bundle_statement = backend_inputs.component_bundle_statement;
    let component_proof_bundle = backend_inputs.component_proof_bundle;
    let component_proof_inputs = backend_inputs.component_proof_inputs;
    let mut refused_objects = Vec::new();
    let ballot_proof_record_hash = string_field(ballot_proof, "ballotProofRecordHash");
    let linear_statement_hash = string_field(linear_statement, "statementHash");
    let expected_proof_encoding_hash = derive_ballot_proof_encoding_profile_hash(proof_encoding);
    let expected_parameter_set_hash = derive_ballot_proof_parameter_set_hash(parameter_set);
    let expected_public_randomness_hash =
        derive_ballot_proof_public_randomness_hash(public_randomness_hex);
    let expected_linear_statement_hash =
        derive_ballot_proof_linear_statement_hash(linear_statement);
    let supplied_parameter_profile_id = string_field(parameter_set, "profileId");
    let linear_statement_parameter_profile_id =
        string_field(linear_statement, "parameterProfileId");
    let linear_statement_projection_coverage = string_field(linear_statement, "projectionCoverage");
    let proof_size_bytes = object_map(ballot_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size_bytes| usize::try_from(proof_size_bytes).ok());

    if linear_statement_parameter_profile_id != supplied_parameter_profile_id {
        refused_objects.push(structural_refusal(
            "Ballot proof linear statement parameter profile does not match the supplied proof parameter set.",
            ballot_proof_record_hash,
        ));
    }
    let requires_full_profile =
        linear_statement_projection_coverage == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE);
    refused_objects.extend(collect_linear_proof_binding_refusals(
        LinearProofBindingValidationInput {
            proof_record: ballot_proof,
            linear_statement,
            parameter_set,
            proof_encoding,
            expected_linear_statement_hash,
            expected_parameter_set_hash,
            expected_proof_encoding_hash,
            expected_public_randomness_hash,
            object_hash: ballot_proof_record_hash,
            parameter_profile_requirement: requires_full_profile.then_some(
                LinearProofProfileRequirement {
                    profile_id: FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
                    refusal_message:
                        "Full encoded-score ballot relation proofs require the dedicated full-relation parameter profile.",
                },
            ),
            proof_encoding_profile_requirement: requires_full_profile.then_some(
                LinearProofProfileRequirement {
                    profile_id: FULL_BALLOT_PROOF_ENCODING_PROFILE_ID,
                    refusal_message:
                        "Full encoded-score ballot relation proofs require the dedicated full-relation proof encoding profile.",
                },
            ),
            messages: LinearProofBindingValidationMessages {
                canonical_statement_hash_mismatch:
                    "Ballot proof linear statement hash does not match its canonical payload.",
                proof_record_statement_mismatch:
                    "Ballot proof record is not bound to the supplied linear statement.",
                proof_encoding_hash_mismatch:
                    "Ballot proof record is not bound to the supplied proof encoding profile.",
                parameter_set_hash_mismatch:
                    "Ballot proof record is not bound to the supplied proof parameter set.",
                public_randomness_hash_mismatch:
                    "Ballot proof record is not bound to the supplied public randomness.",
                parameter_set_size_mismatch:
                    "Ballot proof parameter set is not bound to the proof record byte length.",
                parameter_set_malformed_prefix: "Ballot proof parameter set is malformed",
                proof_encoding_size_mismatch:
                    "Ballot proof encoding is not bound to the proof record byte length.",
                proof_encoding_malformed_prefix: "Ballot proof encoding is malformed",
            },
        },
    ));
    if linear_statement_projection_coverage == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE) {
        refused_objects.extend(collect_full_ballot_binding_contract_refusals(
            linear_statement,
            parameter_set,
            proof_encoding,
            proof_size_bytes,
            ballot_proof_record_hash,
        ));
        refused_objects.extend(collect_full_ballot_relation_binding_refusals(
            linear_statement,
            component_bundle_statement,
            ballot_proof_record_hash,
        ));
    }
    if string_field(ballot_proof, "backendStatementHash")
        != string_field(linear_statement, "backendStatementHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied backend statement.",
            ballot_proof_record_hash,
        ));
    }
    if string_field(ballot_proof, "statementMatrixHash")
        != string_field(linear_statement, "statementMatrixHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied statement matrix.",
            ballot_proof_record_hash,
        ));
    }
    if string_field(ballot_proof, "targetVectorHash")
        != string_field(linear_statement, "targetVectorHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied target vector.",
            ballot_proof_record_hash,
        ));
    }
    if string_field(linear_statement, "relationStatementHash")
        .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "relationStatementHash")
            != string_field(linear_statement, "relationStatementHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the relation statement used by the supplied linear statement.",
            ballot_proof_record_hash,
        ));
    }
    if string_field(linear_statement, "ballotProofStatementHash")
        .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(statement, "ballotProofStatementHash")
            != string_field(linear_statement, "ballotProofStatementHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof linear statement is not bound to the supplied ballot proof statement.",
            ballot_proof_record_hash,
        ));
    }
    refused_objects.extend(collect_ballot_component_bundle_refusals(
        statement,
        ballot_proof,
        linear_statement,
        component_bundle_statement,
    ));
    if !refused_objects.is_empty() {
        return structural_rejection("verifyBallotProof", refused_objects);
    }
    let vector_case = json!({
        "caseName": "ballot-proof-record",
        "description": "Ballot proof record verification through the internal linear proof backend.",
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": object_map(linear_statement)
            .and_then(|object| object.get("statementMatrixCoefficients"))
            .cloned()
            .unwrap_or(Value::Null),
        "targetVectorCoefficients": object_map(linear_statement)
            .and_then(|object| object.get("targetVectorCoefficients"))
            .cloned()
            .unwrap_or(Value::Null),
        "targetCoefficientRepresentation": object_map(linear_statement)
            .and_then(|object| object.get("targetCoefficientRepresentation"))
            .cloned()
            .unwrap_or(Value::Null),
        "proofHex": proof_bytes_hex,
        "expectedProofSizeBytes": object_map(ballot_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .cloned()
            .unwrap_or(Value::Null)
    });
    let proof_verification =
        linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
    if proof_verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "verifyBallotProof",
            "statusLabels": [],
            "acceptedHashes": [],
            "refusedObjects": proof_verification
                .as_object()
                .and_then(|object| object.get("refusedObjects"))
                .cloned()
                .unwrap_or_else(|| json!([
                    {
                        "code": "InvalidFixture",
                        "message": "Ballot proof backend verification failed without a structured refusal."
                    }
                ])),
            "unresolvedReason": proof_verification
                .as_object()
                .and_then(|object| object.get("unresolvedReason"))
                .cloned()
                .unwrap_or_else(|| json!("InvalidFixture"))
        });
    }
    if string_field(linear_statement, "projectionCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        return structural_rejection(
            "verifyBallotProof",
            vec![structural_refusal(
                "Ballot proof linear statement does not cover the full encoded-score ballot relation.",
                ballot_proof_record_hash,
            )],
        );
    }
    let mut component_backend_verified = false;
    if backend_inputs
        .component_proof_verification_mode
        .verifies_component_backend()
        && let Some(component_proof_bundle) = component_proof_bundle
        && let Some(component_backend_result) = verify_component_proof_bundle_backend(
            "verifyBallotProof",
            ballot_proof_record_hash,
            component_proof_bundle,
            component_proof_inputs,
        )
    {
        return component_backend_result;
    } else if backend_inputs
        .component_proof_verification_mode
        .verifies_component_backend()
        && component_proof_bundle.is_some()
    {
        component_backend_verified = true;
    }

    let mut status_labels = vec![
        json!("BallotProofRecordHashRecomputed"),
        json!("BallotProofBytesHashChecked"),
        json!("BallotProofLinearStatementBound"),
        json!("BallotProofLinearProofVerified"),
    ];
    if component_backend_verified {
        status_labels.push(json!("BallotProofComponentProofBundleVerified"));
        status_labels.push(json!("BallotProofComponentLinearProofVerified"));
    }
    if backend_inputs.component_proof_verification_mode
        == ComponentProofVerificationMode::AlreadyVerifiedDuringGeneration
    {
        status_labels.push(json!("BallotProofComponentGeneratedProofsAlreadyVerified"));
    }
    if let Some(proof_status_labels) = proof_verification
        .as_object()
        .and_then(|object| object.get("statusLabels"))
        .and_then(Value::as_array)
    {
        status_labels.extend(proof_status_labels.iter().cloned());
    }
    let accepted_hashes = [
        ballot_proof_record_hash,
        string_field(ballot_proof, "proofBytesHash"),
        linear_statement_hash,
        string_field(ballot_proof, "backendStatementHash"),
    ]
    .into_iter()
    .flatten()
    .map(Value::from)
    .collect::<Vec<_>>();

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "verifyBallotProof",
        "statusLabels": status_labels,
        "acceptedHashes": accepted_hashes,
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

pub(crate) fn verify_ballot_proof(
    statement: &Value,
    ballot_proof: &Value,
    backend_inputs: BallotProofVerificationInputs<'_>,
) -> Value {
    let mut refused_objects = collect_ballot_proof_refusals(
        statement,
        ballot_proof,
        backend_inputs.dynamic_roster_profile_evidence,
        false,
        backend_inputs.unsafe_small_roster_acknowledged,
    );
    refused_objects.extend(collect_proof_bytes_refusals(
        backend_inputs.proof_bytes_hex,
        string_field(ballot_proof, "proofBytesHash"),
        object_map(ballot_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64),
        string_field(ballot_proof, "ballotProofRecordHash"),
        "Ballot",
        false,
    ));
    refused_objects.extend(collect_ballot_component_proof_bundle_refusals(
        statement,
        ballot_proof,
        backend_inputs.component_bundle_statement,
        backend_inputs.component_proof_bundle,
        backend_inputs.component_proof_inputs,
    ));
    if !refused_objects.is_empty() {
        return structural_rejection("verifyBallotProof", refused_objects);
    }

    match (
        backend_inputs.linear_statement,
        backend_inputs.proof_bytes_hex,
        backend_inputs.public_randomness_hex,
        backend_inputs.parameter_set,
        backend_inputs.proof_encoding,
        backend_inputs.component_bundle_statement,
        backend_inputs.component_proof_bundle,
    ) {
        (None, _, None, None, None, None, None) => {}
        (
            Some(linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(parameter_set),
            Some(proof_encoding),
            component_bundle_statement,
            _component_proof_bundle,
        ) => {
            return verify_ballot_linear_proof_bytes(
                statement,
                ballot_proof,
                BallotLinearProofVerificationInputs {
                    component_bundle_statement,
                    component_proof_bundle: backend_inputs.component_proof_bundle,
                    component_proof_inputs: backend_inputs.component_proof_inputs,
                    linear_statement,
                    parameter_set,
                    proof_bytes_hex,
                    proof_encoding,
                    public_randomness_hex,
                    component_proof_verification_mode: backend_inputs
                        .component_proof_verification_mode,
                },
            );
        }
        _ => {
            return structural_rejection(
                "verifyBallotProof",
                vec![structural_refusal(
                    "Ballot proof verification requires proof bytes, public randomness, proof parameters, proof encoding, and the public linear statement together.",
                    string_field(ballot_proof, "ballotProofRecordHash"),
                )],
            );
        }
    }

    structural_rejection(
        "verifyBallotProof",
        vec![structural_refusal(
            "Ballot proof verification requires proof bytes, public randomness, proof parameters, proof encoding, and the public linear statement.",
            string_field(ballot_proof, "ballotProofRecordHash"),
        )],
    )
}

pub(crate) fn verify_ballot_proof_from_command_request(request: &Value) -> Value {
    match BallotProofVerificationRequest::from_command_request(request) {
        Ok(request) => verify_ballot_proof(
            request.statement,
            request.ballot_proof,
            request.backend_inputs,
        ),
        Err(error) => structural_rejection("verifyBallotProof", vec![error.to_json_value()]),
    }
}
