use super::*;

pub(super) fn collect_aggregate_proof_input_refusals(
    proof_input: &Value,
    component: Option<&Value>,
    proof_bytes_required: bool,
) -> Vec<Value> {
    let object_digest = component
        .and_then(|component_value| {
            string_field(component_value, "aggregateDerivationComponentDigest")
        })
        .or_else(|| string_field(proof_input, "statementDigest"));
    let mut refused_objects = Vec::new();
    if string_field(proof_input, "componentId") != Some(AGGREGATE_DERIVATION_COMPONENT_ID) {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must use aggregate-derivation-component.",
            object_digest,
        ));
    }
    if string_field(proof_input, "proofStatementFormat")
        != Some(AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must use sparse-polynomial-matrix-linear-proof-v1.",
            object_digest,
        ));
    }
    if proof_bytes_required {
        match string_field(proof_input, "proofBytesHex") {
            Some(proof_bytes_hex)
                if !proof_bytes_hex.is_empty()
                    && proof_bytes_hex.len().is_multiple_of(2)
                    && proof_bytes_hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {}
            _ => refused_objects.push(structural_refusal(
                "Aggregate derivation proof bytes must be non-empty lowercase hexadecimal bytes.",
                object_digest,
            )),
        }
    }
    let Some(proof_statement) = proof_input.get("proofStatement") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofStatement.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(parameter_set) = proof_input.get("proofParameterSet") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofParameterSet.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(proof_encoding) = proof_input.get("proofEncoding") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofEncoding.",
            object_digest,
        ));

        return refused_objects;
    };
    let statement_rows = usize_object_field(proof_statement, "statementRows");
    let statement_columns = usize_object_field(proof_statement, "statementColumns");
    let share_vector_width =
        statement_rows.and_then(|rows| rows.checked_sub(SHARE_COMMITMENT_MODULE_RANK));
    let expected_columns = share_vector_width.and_then(|width| {
        width
            .checked_mul(3)?
            .checked_add(SHARE_COMMITMENT_OPENING_DIMENSION)
    });
    let expected_short_response_length = statement_columns.and_then(|columns| {
        columns
            .checked_mul(
                AGGREGATE_DERIVATION_SOURCE_RING_DEGREE / AGGREGATE_DERIVATION_PROOF_RING_DEGREE,
            )?
            .checked_add(1)
    });

    if string_field(proof_statement, "componentId") != Some(AGGREGATE_DERIVATION_COMPONENT_ID)
        || string_field(proof_statement, "parameterProfileId")
            != Some(AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID)
        || string_field(proof_statement, "proofStatementFormat")
            != Some(AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT)
        || string_field(proof_statement, "projectionCoverage")
            != Some("aggregate-derivation-full-encoded-layout")
        || string_field(proof_statement, "matrixCoefficientRepresentation")
            != Some("centeredSignedSourceModulus")
        || string_field(proof_statement, "targetCoefficientRepresentation")
            != Some("centeredSignedSourceModulus")
        || string_field(proof_statement, "coefficientModulus")
            != Some(&SHARE_COMMITMENT_MODULUS.to_string())
        || usize_object_field(proof_statement, "sourceRingDegree")
            != Some(AGGREGATE_DERIVATION_SOURCE_RING_DEGREE)
        || statement_rows.is_none()
        || statement_columns.is_none()
        || expected_columns != statement_columns
        || u64_object_field(proof_statement, "witnessL2BoundSquared")
            != Some(AGGREGATE_DERIVATION_WITNESS_L2_BOUND_SQUARED as u64)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation sparse proof statement shape is invalid.",
            object_digest,
        ));
    }
    let Some(share_vector_width) = share_vector_width else {
        return refused_objects;
    };
    if share_vector_width == 0
        || share_vector_width % (BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION as usize) != 0
        || share_vector_width
            > usize::try_from(BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT)
                .ok()
                .and_then(|maximum_option_count| {
                    maximum_option_count
                        .checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION as usize)
                })
                .unwrap_or(0)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation must use the full scalar-plus-one-hot encoded layout.",
            object_digest,
        ));
    }
    if string_field(parameter_set, "profileId") != Some(AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID)
        || string_field(parameter_set, "coefficientModulus")
            != Some(&SHARE_COMMITMENT_MODULUS.to_string())
        || usize_object_field(parameter_set, "ringDegree")
            != Some(AGGREGATE_DERIVATION_SOURCE_RING_DEGREE)
        || usize_object_field(parameter_set, "proofSystemRingDegree")
            != Some(AGGREGATE_DERIVATION_PROOF_RING_DEGREE)
        || usize_object_field(parameter_set, "statementRows") != statement_rows
        || usize_object_field(parameter_set, "statementColumns") != statement_columns
        || u64_object_field(parameter_set, "witnessL2BoundSquared")
            != Some(AGGREGATE_DERIVATION_WITNESS_L2_BOUND_SQUARED as u64)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation parameter set is not bound to the proof statement.",
            object_digest,
        ));
    }
    if string_field(proof_encoding, "profileId")
        != Some(AGGREGATE_DERIVATION_PROOF_ENCODING_PROFILE_ID)
        || u64_object_field(proof_encoding, "coefficientModulus")
            != Some(AGGREGATE_DERIVATION_PROOF_MODULUS)
        || usize_object_field(proof_encoding, "ringDegree")
            != Some(AGGREGATE_DERIVATION_PROOF_RING_DEGREE)
        || usize_object_field(proof_encoding, "shortResponseVectorLength")
            != expected_short_response_length
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof encoding is not bound to the proof statement.",
            object_digest,
        ));
    }
    if let Some(statement_digest) = string_field(proof_statement, "statementDigest") {
        let expected_statement_digest =
            derive_aggregate_sparse_linear_statement_digest(proof_statement);
        if expected_statement_digest.as_deref() != Some(statement_digest) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation proof statement digest does not match its canonical payload.",
                Some(statement_digest),
            ));
        }
        if string_field(proof_input, "componentProofStatementDigest") != Some(statement_digest) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation proof input is not bound to the proof statement digest.",
                Some(statement_digest),
            ));
        }
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof statement is missing statementDigest.",
            object_digest,
        ));
    }
    if let Some(component_value) = component
        && let Some(statement) = component_value.get("statement")
        && let Some(challenge_domain_digest) = string_field(statement, "challengeDomainDigest")
        && challenge_domain_digest.len() >= 64
        && string_field(proof_input, "publicRandomnessHex") != Some(&challenge_domain_digest[..64])
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation public randomness must be verifier-derived from the statement challenge domain.",
            object_digest,
        ));
    }

    refused_objects
}

fn derive_aggregate_sparse_linear_statement_digest(proof_statement: &Value) -> Option<String> {
    let statement_payload = value_without_field(proof_statement, "statementDigest")?;
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "aggregate-derivation-sparse-linear-proof-statement-v1"
        }),
    )
}

pub(super) fn collect_aggregate_post_close_context_refusals(
    close_record: Option<&Value>,
    contributor_action_context: Option<&Value>,
    component: &Value,
) -> Vec<Value> {
    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects = Vec::new();
    let Some(statement) = component.get("statement") else {
        return refused_objects;
    };

    if let Some(close_record_value) = close_record {
        refused_objects.extend(collect_aggregate_close_record_refusals(
            close_record_value,
            statement,
            object_digest,
        ));
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires closeRecord evidence for the voting-closed board head.",
            object_digest,
        ));
    }

    if let Some(action_context_value) = contributor_action_context {
        refused_objects.extend(collect_aggregate_action_context_refusals(
            action_context_value,
            statement,
            object_digest,
        ));
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires contributorActionContext evidence.",
            object_digest,
        ));
    }

    refused_objects
}

fn derive_close_record_digest_from_value(close_record: &Value) -> Option<String> {
    derive_digest(
        "CloseRecordDigest",
        &json!({
            "boardPosition": u64_object_field(close_record, "boardPosition")?,
            "boardSequence": u64_object_field(close_record, "boardSequence")?,
            "ceremonyId": string_field(close_record, "ceremonyId")?,
            "closeKind": string_field(close_record, "closeKind")?,
            "closedBoardHeadDigest": string_field(close_record, "closedBoardHeadDigest")?,
            "electionManifestDigest": string_field(close_record, "electionManifestDigest")?,
            "objectType": string_field(close_record, "objectType")?,
            "objectVersion": u64_object_field(close_record, "objectVersion")?,
            "organizerIdentity": string_field(close_record, "organizerIdentity")?
        }),
    )
}

fn derive_post_voting_closed_context_digest_from_value(close_record: &Value) -> Option<String> {
    derive_digest(
        "PostVotingClosedContextDigest",
        &json!({
            "ceremonyId": string_field(close_record, "ceremonyId")?,
            "closeRecordDigest": string_field(close_record, "closeRecordDigest")?,
            "electionManifestDigest": string_field(close_record, "electionManifestDigest")?,
            "votingClosedBoardHeadDigest": string_field(close_record, "closedBoardHeadDigest")?
        }),
    )
}

fn collect_aggregate_close_record_refusals(
    close_record: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let close_record_digest = string_field(close_record, "closeRecordDigest");
    let mut refused_objects = Vec::new();
    let close_record_shape_is_valid = string_field(close_record, "objectType")
        == Some("CloseRecord")
        && u64_object_field(close_record, "objectVersion") == Some(1)
        && string_field(close_record, "closeKind") == Some("VotingClosed")
        && string_field(close_record, "ceremonyId").is_some_and(|value| !value.is_empty())
        && string_field(close_record, "electionManifestDigest").is_some()
        && string_field(close_record, "closedBoardHeadDigest").is_some()
        && string_field(close_record, "postVotingClosedContextDigest").is_some()
        && u64_object_field(close_record, "boardSequence").is_some()
        && u64_object_field(close_record, "boardPosition").is_some()
        && string_field(close_record, "organizerIdentity").is_some_and(|value| !value.is_empty());
    if !close_record_shape_is_valid {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord evidence must be a canonical VotingClosed close record.",
            close_record_digest.or(object_digest),
        ));

        return refused_objects;
    }

    if derive_close_record_digest_from_value(close_record).as_deref() != close_record_digest {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord digest does not match its canonical payload.",
            close_record_digest.or(object_digest),
        ));
    }
    let expected_post_context_digest =
        derive_post_voting_closed_context_digest_from_value(close_record);
    if expected_post_context_digest.as_deref()
        != string_field(close_record, "postVotingClosedContextDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord does not bind the canonical post-voting closed context digest.",
            close_record_digest.or(object_digest),
        ));
    }
    if string_field(close_record, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(close_record, "electionManifestDigest")
            != string_field(statement, "manifestDigest")
        || close_record_digest != string_field(statement, "closeRecordDigest")
        || string_field(close_record, "closedBoardHeadDigest")
            != string_field(statement, "votingClosedBoardHeadDigest")
        || string_field(close_record, "postVotingClosedContextDigest")
            != string_field(statement, "postVotingClosedContextDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord evidence is not bound to the aggregate statement voting-closed context.",
            close_record_digest.or(object_digest),
        ));
    }

    refused_objects
}

fn derive_action_context_digest_from_value(action_context: &Value) -> Option<String> {
    derive_digest(
        "ActionContextDigest",
        &json!({
            "acceptedRecoveryEpochUpdateDigest": action_context.get("acceptedRecoveryEpochUpdateDigest")?.clone(),
            "actionSequence": u64_object_field(action_context, "actionSequence")?,
            "boardHeadDigest": string_field(action_context, "boardHeadDigest")?,
            "boardSequence": u64_object_field(action_context, "boardSequence")?,
            "ceremonyId": string_field(action_context, "ceremonyId")?,
            "contextDigest": string_field(action_context, "contextDigest")?,
            "deviceEpoch": u64_object_field(action_context, "deviceEpoch")?,
            "electionManifestDigest": string_field(action_context, "electionManifestDigest")?,
            "recoveryEpoch": u64_object_field(action_context, "recoveryEpoch")?,
            "recoveryPolicyDigest": string_field(action_context, "recoveryPolicyDigest")?,
            "rosterExternalAcceptanceDigest": action_context.get("rosterExternalAcceptanceDigest")?.clone(),
            "signerIdentity": string_field(action_context, "signerIdentity")?
        }),
    )
}

fn collect_aggregate_action_context_refusals(
    action_context: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let action_context_digest = string_field(action_context, "actionContextDigest");
    let mut refused_objects = Vec::new();
    let action_context_shape_is_valid = action_context_digest.is_some()
        && string_field(action_context, "ceremonyId").is_some_and(|value| !value.is_empty())
        && string_field(action_context, "electionManifestDigest").is_some()
        && string_field(action_context, "signerIdentity").is_some_and(|value| !value.is_empty())
        && string_field(action_context, "boardHeadDigest").is_some()
        && u64_object_field(action_context, "boardSequence").is_some()
        && u64_object_field(action_context, "recoveryEpoch").is_some()
        && u64_object_field(action_context, "deviceEpoch").is_some()
        && u64_object_field(action_context, "actionSequence").is_some()
        && string_field(action_context, "recoveryPolicyDigest").is_some()
        && action_context
            .get("acceptedRecoveryEpochUpdateDigest")
            .is_some()
        && action_context
            .get("rosterExternalAcceptanceDigest")
            .is_some()
        && string_field(action_context, "contextDigest").is_some();
    if !action_context_shape_is_valid {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext evidence must be canonical.",
            action_context_digest.or(object_digest),
        ));

        return refused_objects;
    }

    if derive_action_context_digest_from_value(action_context).as_deref() != action_context_digest {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext digest does not match its canonical payload.",
            action_context_digest.or(object_digest),
        ));
    }
    if action_context_digest != string_field(statement, "contributorActionContextDigest")
        || string_field(action_context, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(action_context, "electionManifestDigest")
            != string_field(statement, "manifestDigest")
        || string_field(action_context, "signerIdentity")
            != string_field(statement, "contributorIdentity")
        || string_field(action_context, "boardHeadDigest")
            != string_field(statement, "votingClosedBoardHeadDigest")
        || string_field(action_context, "contextDigest")
            != string_field(statement, "postVotingClosedContextDigest")
        || action_context
            .get("rosterExternalAcceptanceDigest")
            .and_then(Value::as_str)
            != string_field(statement, "contributorRosterExternalAcceptanceDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext evidence is not bound to the aggregate statement contributor and post-close context.",
            action_context_digest.or(object_digest),
        ));
    }

    refused_objects
}

pub(super) fn collect_aggregate_counted_package_preflight_refusals(
    counted_ballot_packages: Option<&Value>,
    component: &Value,
) -> Vec<Value> {
    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects = Vec::new();
    let Some(packages) = counted_ballot_packages.and_then(Value::as_array) else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires countedBallotPackages so the verifier can route the counted set through accepted M5 package verification.",
            object_digest,
        ));

        return refused_objects;
    };
    if packages.is_empty() {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires at least one counted ballot package.",
            object_digest,
        ));

        return refused_objects;
    }

    let mut seen_package_digests = BTreeSet::new();
    for package in packages {
        let package_digest = string_field(package, "ballotPackageDigest");
        let Some(package_digest) = package_digest else {
            refused_objects.push(structural_refusal(
                "Aggregate derivation counted package is missing ballotPackageDigest.",
                object_digest,
            ));
            continue;
        };
        if !seen_package_digests.insert(package_digest.to_string()) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation counted ballot packages must not contain duplicates.",
                Some(package_digest),
            ));
        }

        let missing_field_names = [
            ("proofBytesHex", package.get("proofBytesHex")),
            ("linearStatement", package.get("linearStatement")),
            ("parameterSet", package.get("parameterSet")),
            ("proofEncoding", package.get("proofEncoding")),
            ("publicRandomnessHex", package.get("publicRandomnessHex")),
            (
                "componentBundleStatement",
                package.get("componentBundleStatement"),
            ),
            ("componentProofBundle", package.get("componentProofBundle")),
            ("componentProofInputs", package.get("componentProofInputs")),
        ]
        .into_iter()
        .filter_map(|(field_name, value)| value.is_none().then_some(field_name))
        .collect::<Vec<_>>();
        if !missing_field_names.is_empty() {
            refused_objects.push(structural_refusal(
                format!(
                    "Aggregate derivation counted ballot packages must carry proof-byte-bearing M5 verifier inputs; missing {}.",
                    missing_field_names.join(", ")
                ),
                Some(package_digest),
            ));
        }
    }

    refused_objects
}

pub(super) fn collect_aggregate_counted_package_refusals(
    counted_ballot_packages: Option<&Value>,
    component: &Value,
    unsafe_small_roster_acknowledged: bool,
) -> Vec<Value> {
    let preflight_refusals =
        collect_aggregate_counted_package_preflight_refusals(counted_ballot_packages, component);
    if !preflight_refusals.is_empty() {
        return preflight_refusals;
    }

    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects = Vec::new();
    let packages = counted_ballot_packages
        .and_then(Value::as_array)
        .expect("counted package preflight guarantees an array");

    let Some(statement) = component.get("statement") else {
        return refused_objects;
    };
    let Some(aggregate_commitment) = component.get("aggregateCommitment") else {
        return refused_objects;
    };

    let mut ordered_packages = Vec::new();
    for package in packages {
        let package_digest = string_field(package, "ballotPackageDigest");
        let dynamic_roster_profile_evidence =
            object_map(package).and_then(|object| object.get("dynamicRosterProfileEvidence"));
        let verification = verify_claim_bearing_ballot_package(
            package,
            dynamic_roster_profile_evidence,
            unsafe_small_roster_acknowledged,
        );
        if verification.get("ok").and_then(Value::as_bool) != Some(true) {
            refused_objects.push(structural_refusal(
                format!(
                    "Aggregate derivation counted package must verify through the accepted M5 Rust/WASM verifier before inclusion. {}",
                    verification_refusal_summary(&verification)
                ),
                package_digest.or(object_digest),
            ));
        }
        ordered_packages.push(package);
    }
    ordered_packages.sort_by(|left_package, right_package| {
        string_field(left_package, "ballotPackageDigest")
            .unwrap_or("")
            .cmp(string_field(right_package, "ballotPackageDigest").unwrap_or(""))
    });

    refused_objects.extend(collect_counted_package_binding_refusals(
        &ordered_packages,
        statement,
        aggregate_commitment,
        object_digest,
    ));

    refused_objects
}

fn verification_refusal_summary(verification: &Value) -> String {
    let refusal_messages = verification
        .get("refusedObjects")
        .and_then(Value::as_array)
        .map(|refusals| {
            refusals
                .iter()
                .filter_map(|refusal| string_field(refusal, "message"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    if !refusal_messages.is_empty() {
        return refusal_messages;
    }

    verification
        .get("unresolvedReason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty())
        .unwrap_or("No verifier refusal detail was returned.")
        .to_string()
}

fn collect_counted_package_binding_refusals(
    ordered_packages: &[&Value],
    statement: &Value,
    aggregate_commitment: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let Some(contributor_identity) = string_field(statement, "contributorIdentity") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement is missing contributor identity.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(contributor_roster_position) =
        positive_roster_position(statement, "contributorRosterPosition")
    else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement is missing contributor roster position.",
            object_digest,
        ));

        return refused_objects;
    };

    let mut package_digests = Vec::new();
    let mut expected_package_references = Vec::new();
    let mut share_commitment_vectors = Vec::new();
    for package in ordered_packages {
        if let Some(package_digest) = string_field(package, "ballotPackageDigest") {
            package_digests.push(Value::String(package_digest.to_string()));
        }
        refused_objects.extend(collect_counted_package_context_refusals(
            package,
            statement,
            object_digest,
        ));
        match package_reference_for_contributor(
            package,
            contributor_identity,
            contributor_roster_position,
        ) {
            Some(reference) => expected_package_references.push(reference),
            None => refused_objects.push(structural_refusal(
                "Aggregate derivation counted package does not address the contributor in both receiver-payload and share-commitment references.",
                string_field(package, "ballotPackageDigest").or(object_digest),
            )),
        }
        match share_commitment_vector_for_contributor(
            package,
            contributor_identity,
            contributor_roster_position,
        ) {
            Some(vector) => share_commitment_vectors.push(vector),
            None => refused_objects.push(structural_refusal(
                "Aggregate derivation counted package does not carry a valid public share commitment polynomial vector for the contributor.",
                string_field(package, "ballotPackageDigest").or(object_digest),
            )),
        }
    }

    let statement_package_references = array_field(statement, "packageReferences");
    if statement_package_references != Some(&expected_package_references) {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement package references are not derived from the accepted counted M5 packages.",
            object_digest,
        ));
    }

    if let Some(expected_ballot_set_digest) =
        derive_counted_package_ballot_set_digest(statement, package_digests)
        && string_field(statement, "ballotSetDigest") != Some(expected_ballot_set_digest.as_str())
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation ballot-set digest is not derived from the accepted counted M5 packages and post-close context.",
            object_digest,
        ));
    }

    if let Some(expected_commitment_vector) =
        summed_share_commitment_vector(&share_commitment_vectors)
    {
        let expected_commitment_value = Value::Array(
            expected_commitment_vector
                .iter()
                .map(|polynomial| {
                    Value::Array(
                        polynomial
                            .iter()
                            .map(|coefficient| Value::String(coefficient.clone()))
                            .collect(),
                    )
                })
                .collect(),
        );
        if aggregate_commitment.get("commitmentPolynomialVector")
            != Some(&expected_commitment_value)
        {
            refused_objects.push(structural_refusal(
                "Aggregate share commitment polynomial vector is not the homomorphic sum of the accepted counted package commitments addressed to the contributor.",
                string_field(aggregate_commitment, "aggregateShareCommitmentDigest").or(object_digest),
            ));
        }
        if let Some(share_commitment_profile_digest) =
            string_field(statement, "shareCommitmentProfileDigest")
            && let Some(expected_body_digest) = derive_digest(
                "AggregateShareCommitmentDigest",
                &json!({
                    "commitmentPolynomialVector": expected_commitment_vector,
                    "profileDigest": share_commitment_profile_digest,
                    "purpose": "aggregate-share-commitment-body-v1"
                }),
            )
            && string_field(aggregate_commitment, "commitmentBodyDigest")
                != Some(expected_body_digest.as_str())
        {
            refused_objects.push(structural_refusal(
                "Aggregate share commitment body digest is not derived from the accepted counted package commitment sum.",
                string_field(aggregate_commitment, "aggregateShareCommitmentDigest").or(object_digest),
            ));
        }
    }

    refused_objects
}

fn collect_counted_package_context_refusals(
    package: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let Some(ballot_statement) = package.get("ballotProofStatement") else {
        return refused_objects;
    };
    let context_fields = [
        "ceremonyId",
        "manifestDigest",
        "rosterDigest",
        "pollSpecDigest",
        "thresholdProfileDigest",
        "shareCommitmentProfileDigest",
        "receiverEncryptionProfileDigest",
        "ballotScoreEncodingProfileDigest",
        "ballotShareLayoutProfileDigest",
        "aggregateInputEncodingProfileDigest",
        "encodedShareVectorLayoutDigest",
        "encodedAggregateLayoutDigest",
        "shareCommitmentMessageBoundCertDigest",
    ];
    if context_fields.iter().any(|field_name| {
        string_field(ballot_statement, field_name) != string_field(statement, field_name)
    }) || usize_object_field(ballot_statement, "optionCount")
        != usize_object_field(statement, "optionCount")
        || usize_object_field(ballot_statement, "shareVectorWidth")
            != usize_object_field(statement, "shareVectorWidth")
        || array_field(ballot_statement, "receiverPublicKeys").map(Vec::len)
            != usize_object_field(statement, "participantCount")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation counted package context does not match the aggregate statement context.",
            string_field(package, "ballotPackageDigest").or(object_digest),
        ));
    }

    refused_objects
}

fn package_reference_for_contributor(
    package: &Value,
    contributor_identity: &str,
    contributor_roster_position: u64,
) -> Option<Value> {
    let ballot_statement = package.get("ballotProofStatement")?;
    let payload_reference = array_field(ballot_statement, "receiverPayloads")?
        .iter()
        .find(|reference| {
            string_field(reference, "receiverIdentity") == Some(contributor_identity)
                && positive_roster_position(reference, "receiverRosterPosition")
                    == Some(contributor_roster_position)
        })?;
    let commitment_reference = array_field(ballot_statement, "shareCommitments")?
        .iter()
        .find(|reference| {
            string_field(reference, "receiverIdentity") == Some(contributor_identity)
                && positive_roster_position(reference, "receiverRosterPosition")
                    == Some(contributor_roster_position)
        })?;

    Some(json!({
        "ballotPackageDigest": string_field(package, "ballotPackageDigest")?,
        "ballotProofStatementDigest": string_field(ballot_statement, "ballotProofStatementDigest")?,
        "receiverPayloadCiphertextRoot": string_field(payload_reference, "receiverPayloadCiphertextRoot")?,
        "receiverPayloadDigest": string_field(payload_reference, "receiverPayloadDigest")?,
        "shareCommitmentDigest": string_field(commitment_reference, "shareCommitmentDigest")?
    }))
}

fn share_commitment_vector_for_contributor(
    package: &Value,
    contributor_identity: &str,
    contributor_roster_position: u64,
) -> Option<Vec<Vec<String>>> {
    let share_commitment = array_field(package, "shareCommitments")?
        .iter()
        .find(|commitment| {
            string_field(commitment, "receiverIdentity") == Some(contributor_identity)
                && positive_roster_position(commitment, "receiverRosterPosition")
                    == Some(contributor_roster_position)
        })?;

    commitment_polynomial_vector_from_value(share_commitment.get("commitmentPolynomialVector")?)
}

fn commitment_polynomial_vector_from_value(value: &Value) -> Option<Vec<Vec<String>>> {
    let vector = value.as_array()?;
    if vector.len() != SHARE_COMMITMENT_MODULE_RANK {
        return None;
    }

    vector
        .iter()
        .map(|polynomial| {
            let coefficients = polynomial.as_array()?;
            if coefficients.len() != SHARE_COMMITMENT_MODULE_DEGREE {
                return None;
            }
            coefficients
                .iter()
                .map(|coefficient| {
                    let coefficient_string = coefficient.as_str()?;
                    let coefficient_value = coefficient_string.parse::<u64>().ok()?;
                    if !unsigned_decimal_string(coefficient_string)
                        || coefficient_value >= SHARE_COMMITMENT_MODULUS
                    {
                        return None;
                    }

                    Some(coefficient_string.to_string())
                })
                .collect::<Option<Vec<_>>>()
        })
        .collect()
}

fn summed_share_commitment_vector(vectors: &[Vec<Vec<String>>]) -> Option<Vec<Vec<String>>> {
    if vectors.is_empty() {
        return None;
    }
    let mut summed_vector =
        vec![vec!["0".to_string(); SHARE_COMMITMENT_MODULE_DEGREE]; SHARE_COMMITMENT_MODULE_RANK];
    for vector in vectors {
        if vector.len() != SHARE_COMMITMENT_MODULE_RANK {
            return None;
        }
        for (polynomial_index, polynomial) in vector.iter().enumerate() {
            if polynomial.len() != SHARE_COMMITMENT_MODULE_DEGREE {
                return None;
            }
            for (coefficient_index, coefficient) in polynomial.iter().enumerate() {
                let left = summed_vector[polynomial_index][coefficient_index]
                    .parse::<u64>()
                    .ok()?;
                let right = coefficient.parse::<u64>().ok()?;
                let sum =
                    (u128::from(left) + u128::from(right)) % u128::from(SHARE_COMMITMENT_MODULUS);
                summed_vector[polynomial_index][coefficient_index] = sum.to_string();
            }
        }
    }

    Some(summed_vector)
}

fn derive_counted_package_ballot_set_digest(
    statement: &Value,
    package_digests: Vec<Value>,
) -> Option<String> {
    derive_digest(
        "BallotSetDigest",
        &json!({
            "ballotPackageDigests": package_digests,
            "closeRecordDigest": string_field(statement, "closeRecordDigest")?,
            "manifestDigest": string_field(statement, "manifestDigest")?,
            "pollSpecDigest": string_field(statement, "pollSpecDigest")?,
            "postVotingClosedContextDigest": string_field(statement, "postVotingClosedContextDigest")?,
            "purpose": "m6-post-close-counted-m5-ballot-set-v1",
            "rosterDigest": string_field(statement, "rosterDigest")?,
            "thresholdProfileDigest": string_field(statement, "thresholdProfileDigest")?,
            "votingClosedBoardHeadDigest": string_field(statement, "votingClosedBoardHeadDigest")?
        }),
    )
}

pub(super) fn collect_aggregate_component_refusals(component: &Value) -> Vec<Value> {
    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects =
        collect_forbidden_witness_field_refusals(component, object_digest, "component");
    let Some(statement) = component.get("statement") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include statement.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(aggregate_commitment) = component.get("aggregateCommitment") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include aggregateCommitment.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(certificate) = component.get("shareCommitmentMessageBoundCert") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include a no-wraparound certificate.",
            object_digest,
        ));

        return refused_objects;
    };

    refused_objects.extend(collect_aggregate_statement_refusals(
        statement,
        object_digest,
    ));
    refused_objects.extend(collect_aggregate_commitment_refusals(
        aggregate_commitment,
        statement,
        object_digest,
    ));
    refused_objects.extend(collect_aggregate_certificate_refusals(
        certificate,
        statement,
        object_digest,
    ));

    refused_objects
}

fn collect_aggregate_statement_refusals(
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let statement_digest = string_field(statement, "aggregateDerivationStatementDigest");
    let expected_statement_digest =
        value_without_field(statement, "aggregateDerivationStatementDigest").and_then(
            |statement_payload| {
                derive_digest(
                    "AggregateDerivationComponentDigest",
                    &json!({
                        "purpose": "aggregate-derivation-statement-v1",
                        "statement": statement_payload
                    }),
                )
            },
        );
    let option_count = u64_object_field(statement, "optionCount").unwrap_or(0);
    let participant_count = usize_object_field(statement, "participantCount").unwrap_or(0);
    let unsafe_small_roster_acknowledged = statement
        .get("unsafeSmallRosterAcknowledged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let small_roster_acknowledgement_matches_policy =
        if participant_count < BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT {
            unsafe_small_roster_acknowledged
        } else {
            !unsafe_small_roster_acknowledged
        };
    let share_vector_width = usize_object_field(statement, "shareVectorWidth").unwrap_or(0);
    let expected_width = option_count.checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION);
    let package_references = array_field(statement, "packageReferences");

    if string_field(statement, "objectType") != Some("AggregateDerivationStatement")
        || u64_object_field(statement, "objectVersion") != Some(1)
        || statement_digest.is_none()
        || expected_statement_digest.as_deref() != statement_digest
        || string_field(statement, "proofProfileId") != Some("aggregate-derivation-linear-proof-v1")
        || string_field(statement, "proofParameterProfileId")
            != Some(AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID)
        || string_field(statement, "proofEncodingProfileId")
            != Some(AGGREGATE_DERIVATION_PROOF_ENCODING_PROFILE_ID)
        || option_count < BALLOT_PRIVACY_MINIMUM_OPTION_COUNT as u64
        || option_count > BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT as u64
        || expected_width.and_then(|width| usize::try_from(width).ok()) != Some(share_vector_width)
        || !(BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT
            ..=BALLOT_PRIVACY_MAXIMUM_PARTICIPANT_COUNT)
            .contains(&participant_count)
        || package_references.is_none_or(|references| !package_references_are_canonical(references))
        || !small_roster_acknowledgement_matches_policy
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement digest, profile, or dimension policy is invalid.",
            object_digest,
        ));
    }
    refused_objects
}

fn package_references_are_canonical(package_references: &[Value]) -> bool {
    let mut seen_package_digests = BTreeSet::new();
    let mut previous_package_digest: Option<&str> = None;

    for package_reference in package_references {
        let Some(package_digest) = string_field(package_reference, "ballotPackageDigest") else {
            return false;
        };
        if previous_package_digest.is_some_and(|previous| previous > package_digest) {
            return false;
        }
        if !seen_package_digests.insert(package_digest) {
            return false;
        }
        previous_package_digest = Some(package_digest);
    }

    true
}

fn collect_aggregate_commitment_refusals(
    aggregate_commitment: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let commitment_digest = string_field(aggregate_commitment, "aggregateShareCommitmentDigest");
    let expected_commitment_digest =
        value_without_field(aggregate_commitment, "aggregateShareCommitmentDigest").and_then(
            |commitment_payload| {
                derive_digest("AggregateShareCommitmentDigest", &commitment_payload)
            },
        );
    let commitment_polynomial_vector =
        array_field(aggregate_commitment, "commitmentPolynomialVector");
    let vector_shape_is_valid = commitment_polynomial_vector.is_some_and(|vector| {
        vector.len() == SHARE_COMMITMENT_MODULE_RANK
            && vector.iter().all(|polynomial| {
                polynomial.as_array().is_some_and(|coefficients| {
                    coefficients.len() == SHARE_COMMITMENT_MODULE_DEGREE
                        && coefficients.iter().all(|coefficient| {
                            integer_value(coefficient)
                                .is_some_and(|coefficient| coefficient < SHARE_COMMITMENT_MODULUS)
                        })
                })
            })
    });

    if string_field(aggregate_commitment, "objectType") != Some("AggregateShareCommitment")
        || u64_object_field(aggregate_commitment, "objectVersion") != Some(1)
        || commitment_digest.is_none()
        || expected_commitment_digest.as_deref() != commitment_digest
        || commitment_digest != string_field(statement, "aggregateShareCommitmentDigest")
        || string_field(aggregate_commitment, "ballotSetDigest")
            != string_field(statement, "ballotSetDigest")
        || string_field(aggregate_commitment, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(aggregate_commitment, "manifestDigest")
            != string_field(statement, "manifestDigest")
        || string_field(aggregate_commitment, "rosterDigest")
            != string_field(statement, "rosterDigest")
        || string_field(aggregate_commitment, "pollSpecDigest")
            != string_field(statement, "pollSpecDigest")
        || string_field(aggregate_commitment, "contributorIdentity")
            != string_field(statement, "contributorIdentity")
        || usize_object_field(aggregate_commitment, "contributorRosterPosition")
            != usize_object_field(statement, "contributorRosterPosition")
        || string_field(aggregate_commitment, "shareCommitmentProfileDigest")
            != string_field(statement, "shareCommitmentProfileDigest")
        || usize_object_field(aggregate_commitment, "shareVectorWidth")
            != usize_object_field(statement, "shareVectorWidth")
        || !vector_shape_is_valid
    {
        refused_objects.push(structural_refusal(
            "Aggregate share commitment digest, context, or polynomial shape is invalid.",
            object_digest,
        ));
    }

    refused_objects
}

fn collect_aggregate_certificate_refusals(
    certificate: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let certificate_digest = string_field(certificate, "shareCommitmentMessageBoundCertDigest");
    let expected_certificate_digest =
        value_without_field(certificate, "shareCommitmentMessageBoundCertDigest").and_then(
            |certificate_payload| {
                derive_digest(
                    "ShareCommitmentMessageBoundCertDigest",
                    &certificate_payload,
                )
            },
        );
    let maximum_canonical_turnout = u64_object_field(certificate, "maximumCanonicalTurnout");
    let maximum_aggregate_integer = u64_object_field(certificate, "maximumAggregateInteger");
    let opening_single_bound = u64_object_field(certificate, "openingRandomnessSingleBound");
    let opening_aggregate_bound = u64_object_field(certificate, "openingRandomnessAggregateBound");
    let quotient_bound = u64_object_field(certificate, "quotientBoundForAggregateReduction");
    let expected_maximum_aggregate_integer = maximum_canonical_turnout
        .and_then(|turnout| turnout.checked_mul(BALLOT_PRIVACY_FIELD_MODULUS - 1));
    let expected_opening_aggregate_bound = maximum_canonical_turnout
        .zip(opening_single_bound)
        .and_then(|(turnout, bound)| turnout.checked_mul(bound));
    let commitment_message_bound_allows_no_wrap =
        string_field(certificate, "commitmentMessageBound")
            .and_then(|bound| bound.parse::<u128>().ok())
            .zip(maximum_aggregate_integer.map(u128::from))
            .is_some_and(|(bound, maximum)| maximum < bound);
    let no_wrap_flags = certificate
        .get("noWraparoundCondition")
        .and_then(object_map);

    if string_field(certificate, "objectType") != Some("ShareCommitmentMessageBoundCert")
        || u64_object_field(certificate, "objectVersion") != Some(1)
        || certificate_digest.is_none()
        || expected_certificate_digest.as_deref() != certificate_digest
        || certificate_digest != string_field(statement, "shareCommitmentMessageBoundCertDigest")
        || string_field(certificate, "shareCommitmentProfileDigest")
            != string_field(statement, "shareCommitmentProfileDigest")
        || usize_object_field(certificate, "shareVectorWidth")
            != usize_object_field(statement, "shareVectorWidth")
        || maximum_canonical_turnout
            .zip(u64_object_field(statement, "canonicalTurnout"))
            .is_none_or(|(maximum_turnout, actual_turnout)| maximum_turnout < actual_turnout)
        || maximum_aggregate_integer != expected_maximum_aggregate_integer
        || opening_aggregate_bound != expected_opening_aggregate_bound
        || quotient_bound != maximum_canonical_turnout
        || !commitment_message_bound_allows_no_wrap
        || no_wrap_flags
            .and_then(|flags| flags.get("maximumAggregateIntegerLessThanCommitmentMessageBound"))
            .and_then(Value::as_bool)
            != Some(true)
        || no_wrap_flags
            .and_then(|flags| flags.get("openingRandomnessAggregateBoundMatchesTurnout"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation no-wraparound certificate is invalid or permits wraparound.",
            object_digest,
        ));
    }

    refused_objects
}

fn collect_forbidden_witness_field_refusals(
    value: &Value,
    object_digest: Option<&str>,
    path: &str,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    match value {
        Value::Array(array) => {
            for (item_index, item) in array.iter().enumerate() {
                refused_objects.extend(collect_forbidden_witness_field_refusals(
                    item,
                    object_digest,
                    &format!("{path}[{item_index}]"),
                ));
            }
        }
        Value::Object(object) => {
            for (field_name, field_value) in object {
                if forbidden_public_witness_field(field_name) {
                    refused_objects.push(structural_refusal(
                        format!(
                            "Aggregate derivation public component must not expose witness field {path}.{field_name}."
                        ),
                        object_digest,
                    ));
                } else {
                    refused_objects.extend(collect_forbidden_witness_field_refusals(
                        field_value,
                        object_digest,
                        &format!("{path}.{field_name}"),
                    ));
                }
            }
        }
        _ => {}
    }

    refused_objects
}

fn forbidden_public_witness_field(field_name: &str) -> bool {
    matches!(
        field_name,
        "aggregateIntegerShareVector"
            | "aggregateHistogram"
            | "aggregateOpeningRandomness"
            | "aggregateScore"
            | "aggregateScoreBits"
            | "aggregateShareVector"
            | "bridgeWitness"
            | "openingRandomness"
            | "plaintext"
            | "plaintextComparisonInputs"
            | "plaintextScoreBitInputs"
            | "proofWitness"
            | "quotient"
            | "rawAggregateWitness"
            | "receiverPlaintext"
            | "receiverSecretState"
            | "reducedFieldVector"
            | "secretState"
            | "sourceWitnessCoefficients"
            | "aggregateInputPlaintext"
            | "tPvss"
            | "t_pvss"
            | "witness"
    )
}
