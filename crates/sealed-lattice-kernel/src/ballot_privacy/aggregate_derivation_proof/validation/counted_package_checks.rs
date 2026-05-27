use super::*;

pub(in crate::ballot_privacy::aggregate_derivation_proof) fn collect_aggregate_counted_package_preflight_refusals(
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

pub(in crate::ballot_privacy::aggregate_derivation_proof) fn collect_aggregate_counted_package_refusals(
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
