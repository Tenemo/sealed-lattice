use super::*;

pub(in crate::ballot_privacy::aggregate_derivation_proof) fn collect_aggregate_component_refusals(
    component: &Value,
) -> Vec<Value> {
    let object_hash = string_field(component, "aggregateDerivationComponentHash");
    let mut refused_objects =
        collect_forbidden_witness_field_refusals(component, object_hash, "component");
    let Some(statement) = component.get("statement") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include statement.",
            object_hash,
        ));

        return refused_objects;
    };
    let Some(aggregate_commitment) = component.get("aggregateCommitment") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include aggregateCommitment.",
            object_hash,
        ));

        return refused_objects;
    };
    let Some(certificate) = component.get("shareCommitmentMessageBoundCert") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include a no-wraparound certificate.",
            object_hash,
        ));

        return refused_objects;
    };
    let Some(proof_input) = component.get("proofInput") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include proofInput.",
            object_hash,
        ));

        return refused_objects;
    };
    let Some(proof_record) = component.get("proofRecord") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include proofRecord.",
            object_hash,
        ));

        return refused_objects;
    };

    refused_objects.extend(collect_aggregate_statement_refusals(statement, object_hash));
    refused_objects.extend(collect_aggregate_commitment_refusals(
        aggregate_commitment,
        statement,
        object_hash,
    ));
    refused_objects.extend(collect_aggregate_certificate_refusals(
        certificate,
        statement,
        object_hash,
    ));
    refused_objects.extend(collect_aggregate_proof_record_refusals(
        proof_input,
        proof_record,
        statement,
        aggregate_commitment,
        object_hash,
    ));
    refused_objects.extend(collect_aggregate_component_hash_refusals(
        component,
        object_hash,
    ));

    refused_objects
}

fn collect_aggregate_statement_refusals(
    statement: &Value,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let statement_hash = string_field(statement, "aggregateDerivationStatementHash");
    let expected_statement_hash =
        value_without_field(statement, "aggregateDerivationStatementHash").and_then(
            |statement_payload| {
                derive_hash(
                    "AggregateDerivationComponentHash",
                    &json!({
                        "purpose": "aggregate-derivation-statement-v1",
                        "statement": statement_payload
                    }),
                )
            },
        );
    let option_count = u64_object_field(statement, "optionCount").unwrap_or(0);
    let participant_count = usize_object_field(statement, "participantCount").unwrap_or(0);
    let casual_micro_roster_acknowledged = statement
        .get("casualMicroRosterAcknowledged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let small_roster_acknowledgement_matches_policy =
        if participant_count < BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT {
            casual_micro_roster_acknowledged
        } else {
            !casual_micro_roster_acknowledged
        };
    let share_vector_width = usize_object_field(statement, "shareVectorWidth").unwrap_or(0);
    let expected_width = option_count.checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION);
    let package_references = array_field(statement, "packageReferences");

    if string_field(statement, "objectType") != Some("AggregateDerivationStatement")
        || u64_object_field(statement, "objectVersion") != Some(1)
        || statement_hash.is_none()
        || expected_statement_hash.as_deref() != statement_hash
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
            "Aggregate derivation statement hash, profile, or dimension policy is invalid.",
            object_hash,
        ));
    }
    refused_objects
}

fn package_references_are_canonical(package_references: &[Value]) -> bool {
    let mut seen_package_hashes = BTreeSet::new();
    let mut previous_package_hash: Option<&str> = None;

    for package_reference in package_references {
        let Some(package_hash) = string_field(package_reference, "ballotPackageHash") else {
            return false;
        };
        if previous_package_hash.is_some_and(|previous| previous > package_hash) {
            return false;
        }
        if !seen_package_hashes.insert(package_hash) {
            return false;
        }
        previous_package_hash = Some(package_hash);
    }

    true
}

fn collect_aggregate_commitment_refusals(
    aggregate_commitment: &Value,
    statement: &Value,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let commitment_hash = string_field(aggregate_commitment, "aggregateShareCommitmentHash");
    let expected_commitment_hash =
        value_without_field(aggregate_commitment, "aggregateShareCommitmentHash").and_then(
            |commitment_payload| derive_hash("AggregateShareCommitmentHash", &commitment_payload),
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
        || commitment_hash.is_none()
        || expected_commitment_hash.as_deref() != commitment_hash
        || commitment_hash != string_field(statement, "aggregateShareCommitmentHash")
        || string_field(aggregate_commitment, "ballotSetHash")
            != string_field(statement, "ballotSetHash")
        || string_field(aggregate_commitment, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(aggregate_commitment, "manifestHash")
            != string_field(statement, "manifestHash")
        || string_field(aggregate_commitment, "rosterHash") != string_field(statement, "rosterHash")
        || string_field(aggregate_commitment, "pollSpecHash")
            != string_field(statement, "pollSpecHash")
        || string_field(aggregate_commitment, "contributorIdentity")
            != string_field(statement, "contributorIdentity")
        || usize_object_field(aggregate_commitment, "contributorRosterPosition")
            != usize_object_field(statement, "contributorRosterPosition")
        || string_field(aggregate_commitment, "shareCommitmentProfileHash")
            != string_field(statement, "shareCommitmentProfileHash")
        || usize_object_field(aggregate_commitment, "shareVectorWidth")
            != usize_object_field(statement, "shareVectorWidth")
        || !vector_shape_is_valid
    {
        refused_objects.push(structural_refusal(
            "Aggregate share commitment hash, context, or polynomial shape is invalid.",
            object_hash,
        ));
    }

    refused_objects
}

fn collect_aggregate_certificate_refusals(
    certificate: &Value,
    statement: &Value,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let certificate_hash = string_field(certificate, "shareCommitmentMessageBoundCertHash");
    let expected_certificate_hash =
        value_without_field(certificate, "shareCommitmentMessageBoundCertHash").and_then(
            |certificate_payload| {
                derive_hash("ShareCommitmentMessageBoundCertHash", &certificate_payload)
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
        || certificate_hash.is_none()
        || expected_certificate_hash.as_deref() != certificate_hash
        || certificate_hash != string_field(statement, "shareCommitmentMessageBoundCertHash")
        || string_field(certificate, "shareCommitmentProfileHash")
            != string_field(statement, "shareCommitmentProfileHash")
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
            object_hash,
        ));
    }

    refused_objects
}

fn collect_aggregate_proof_record_refusals(
    proof_input: &Value,
    proof_record: &Value,
    statement: &Value,
    aggregate_commitment: &Value,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let proof_record_hash = string_field(proof_record, "aggregateDerivationProofRecordHash");
    let expected_proof_record_hash =
        value_without_field(proof_record, "aggregateDerivationProofRecordHash").and_then(
            |proof_record_payload| {
                derive_hash(
                    "AggregateDerivationComponentHash",
                    &json!({
                        "proofRecord": proof_record_payload,
                        "purpose": "aggregate-derivation-proof-record-v1"
                    }),
                )
            },
        );
    let proof_bytes_hex = string_field(proof_input, "proofBytesHex");
    let expected_proof_bytes_hash = proof_bytes_hex.and_then(derive_proof_bytes_hash);
    let proof_size_bytes = proof_bytes_hex.and_then(|proof_bytes| {
        proof_bytes
            .len()
            .is_multiple_of(2)
            .then_some((proof_bytes.len() / 2) as u64)
    });

    if string_field(proof_record, "objectType") != Some("AggregateDerivationProofRecord")
        || u64_object_field(proof_record, "objectVersion") != Some(1)
        || proof_record_hash.is_none()
        || expected_proof_record_hash.as_deref() != proof_record_hash
        || string_field(proof_record, "aggregateDerivationStatementHash")
            != string_field(statement, "aggregateDerivationStatementHash")
        || string_field(proof_record, "aggregateShareCommitmentHash")
            != string_field(aggregate_commitment, "aggregateShareCommitmentHash")
        || string_field(proof_record, "componentId") != Some(AGGREGATE_DERIVATION_COMPONENT_ID)
        || string_field(proof_input, "componentId") != Some(AGGREGATE_DERIVATION_COMPONENT_ID)
        || string_field(proof_input, "proofStatementFormat")
            != Some(AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT)
        || string_field(proof_input, "statementHash")
            != string_field(statement, "aggregateDerivationStatementHash")
        || string_field(proof_input, "componentProofStatementHash")
            != string_field(proof_record, "componentProofStatementHash")
        || expected_proof_bytes_hash.as_deref() != string_field(proof_record, "proofBytesHash")
        || proof_size_bytes != u64_object_field(proof_record, "proofSizeBytes")
        || string_field(proof_record, "proofRoot").is_none_or(|hash| !is_protocol_hash(hash))
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof record or proof input is invalid.",
            proof_record_hash.or(object_hash),
        ));
    }

    refused_objects
}

fn collect_aggregate_component_hash_refusals(
    component: &Value,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let Some(component_hash) = string_field(component, "aggregateDerivationComponentHash") else {
        return vec![structural_refusal(
            "Aggregate derivation component hash is missing.",
            object_hash,
        )];
    };
    let expected_component_hash =
        value_without_field(component, "aggregateDerivationComponentHash").and_then(
            |component_payload| {
                derive_hash(
                    "AggregateDerivationComponentHash",
                    &json!({
                        "component": component_payload,
                        "purpose": "aggregate-derivation-component-v1"
                    }),
                )
            },
        );

    if expected_component_hash.as_deref() != Some(component_hash) {
        return vec![structural_refusal(
            "Aggregate derivation component hash does not match its canonical payload.",
            Some(component_hash),
        )];
    }

    Vec::new()
}

fn derive_proof_bytes_hash(proof_bytes_hex: &str) -> Option<String> {
    if proof_bytes_hex.is_empty()
        || !proof_bytes_hex.len().is_multiple_of(2)
        || !proof_bytes_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    derive_hash(
        "ProofBytesHash",
        &json!({
            "objectType": "ProofBytes",
            "objectVersion": 1,
            "proofBytesHex": proof_bytes_hex,
            "proofSizeBytes": proof_bytes_hex.len() / 2,
        }),
    )
}

fn collect_forbidden_witness_field_refusals(
    value: &Value,
    object_hash: Option<&str>,
    path: &str,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    match value {
        Value::Array(array) => {
            for (item_index, item) in array.iter().enumerate() {
                refused_objects.extend(collect_forbidden_witness_field_refusals(
                    item,
                    object_hash,
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
                        object_hash,
                    ));
                } else {
                    refused_objects.extend(collect_forbidden_witness_field_refusals(
                        field_value,
                        object_hash,
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
