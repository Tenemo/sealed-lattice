use super::*;

pub(in crate::ballot_privacy::aggregate_derivation_proof) fn collect_aggregate_counted_package_preflight_refusals(
    counted_ballot_packages: Option<&Value>,
    component: &Value,
) -> Vec<Value> {
    let object_hash = string_field(component, "aggregateDerivationComponentHash");
    let mut refused_objects = Vec::new();
    let Some(packages) = counted_ballot_packages.and_then(Value::as_array) else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires countedBallotPackages so the verifier can route the counted set through accepted ballot package verification.",
            object_hash,
        ));

        return refused_objects;
    };
    if packages.is_empty() {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires at least one counted ballot package.",
            object_hash,
        ));

        return refused_objects;
    }

    let mut seen_package_hashes = BTreeSet::new();
    for package in packages {
        let package_hash = string_field(package, "ballotPackageHash");
        let Some(package_hash) = package_hash else {
            refused_objects.push(structural_refusal(
                "Aggregate derivation counted package is missing ballotPackageHash.",
                object_hash,
            ));
            continue;
        };
        if !seen_package_hashes.insert(package_hash.to_string()) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation counted ballot packages must not contain duplicates.",
                Some(package_hash),
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
                    "Aggregate derivation counted ballot packages must carry proof-byte-bearing accepted ballot verifier inputs; missing {}.",
                    missing_field_names.join(", ")
                ),
                Some(package_hash),
            ));
        }
    }

    refused_objects
}

pub(in crate::ballot_privacy::aggregate_derivation_proof) fn collect_aggregate_counted_package_refusals(
    counted_ballot_packages: Option<&Value>,
    component: &Value,
    casual_micro_roster_acknowledged: bool,
) -> Vec<Value> {
    let preflight_refusals =
        collect_aggregate_counted_package_preflight_refusals(counted_ballot_packages, component);
    if !preflight_refusals.is_empty() {
        return preflight_refusals;
    }

    let object_hash = string_field(component, "aggregateDerivationComponentHash");
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
        let package_hash = string_field(package, "ballotPackageHash");
        let dynamic_roster_profile_evidence =
            object_map(package).and_then(|object| object.get("dynamicRosterProfileEvidence"));
        let verification = verify_claim_bearing_ballot_package(
            package,
            dynamic_roster_profile_evidence,
            casual_micro_roster_acknowledged,
        );
        if verification.get("ok").and_then(Value::as_bool) != Some(true) {
            refused_objects.push(structural_refusal(
                format!(
                    "Aggregate derivation counted package must verify through the accepted ballot Rust/WASM verifier before inclusion. {}",
                    verification_refusal_summary(&verification)
                ),
                package_hash.or(object_hash),
            ));
        }
        ordered_packages.push(package);
    }
    ordered_packages.sort_by(|left_package, right_package| {
        string_field(left_package, "ballotPackageHash")
            .unwrap_or("")
            .cmp(string_field(right_package, "ballotPackageHash").unwrap_or(""))
    });

    refused_objects.extend(collect_counted_package_binding_refusals(
        &ordered_packages,
        statement,
        aggregate_commitment,
        object_hash,
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
    object_hash: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let Some(contributor_identity) = string_field(statement, "contributorIdentity") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement is missing contributor identity.",
            object_hash,
        ));

        return refused_objects;
    };
    let Some(contributor_roster_position) =
        positive_roster_position(statement, "contributorRosterPosition")
    else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement is missing contributor roster position.",
            object_hash,
        ));

        return refused_objects;
    };

    let mut package_hashes = Vec::new();
    let mut expected_package_references = Vec::new();
    let mut share_commitment_vectors = Vec::new();
    for package in ordered_packages {
        if let Some(package_hash) = string_field(package, "ballotPackageHash") {
            package_hashes.push(Value::String(package_hash.to_string()));
        }
        refused_objects.extend(collect_counted_package_context_refusals(
            package,
            statement,
            object_hash,
        ));
        match package_reference_for_contributor(
            package,
            contributor_identity,
            contributor_roster_position,
        ) {
            Some(reference) => expected_package_references.push(reference),
            None => refused_objects.push(structural_refusal(
                "Aggregate derivation counted package does not address the contributor in both receiver-payload and share-commitment references.",
                string_field(package, "ballotPackageHash").or(object_hash),
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
                string_field(package, "ballotPackageHash").or(object_hash),
            )),
        }
    }

    let statement_package_references = array_field(statement, "packageReferences");
    if statement_package_references != Some(&expected_package_references) {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement package references are not derived from the accepted counted ballot packages.",
            object_hash,
        ));
    }

    if let Some(expected_ballot_set_hash) =
        derive_counted_package_ballot_set_hash(statement, package_hashes)
        && string_field(statement, "ballotSetHash") != Some(expected_ballot_set_hash.as_str())
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation ballot-set hash is not derived from the accepted counted ballot packages and post-close context.",
            object_hash,
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
                string_field(aggregate_commitment, "aggregateShareCommitmentHash").or(object_hash),
            ));
        }
        if let Some(share_commitment_profile_hash) =
            string_field(statement, "shareCommitmentProfileHash")
            && let Some(expected_body_hash) = derive_hash(
                "AggregateShareCommitmentHash",
                &json!({
                    "commitmentPolynomialVector": expected_commitment_vector,
                    "profileHash": share_commitment_profile_hash,
                    "purpose": "aggregate-share-commitment-body-v1"
                }),
            )
            && string_field(aggregate_commitment, "commitmentBodyHash")
                != Some(expected_body_hash.as_str())
        {
            refused_objects.push(structural_refusal(
                "Aggregate share commitment body hash is not derived from the accepted counted package commitment sum.",
                string_field(aggregate_commitment, "aggregateShareCommitmentHash").or(object_hash),
            ));
        }
    }

    refused_objects
}

fn collect_counted_package_context_refusals(
    package: &Value,
    statement: &Value,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let Some(ballot_statement) = package.get("ballotProofStatement") else {
        return refused_objects;
    };
    let context_fields = [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "pollSpecHash",
        "thresholdProfileHash",
        "shareCommitmentProfileHash",
        "receiverEncryptionProfileHash",
        "ballotScoreEncodingProfileHash",
        "ballotShareLayoutProfileHash",
        "aggregateInputEncodingProfileHash",
        "encodedShareVectorLayoutHash",
        "encodedAggregateLayoutHash",
        "shareCommitmentMessageBoundCertHash",
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
            string_field(package, "ballotPackageHash").or(object_hash),
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
        "ballotPackageHash": string_field(package, "ballotPackageHash")?,
        "ballotProofStatementHash": string_field(ballot_statement, "ballotProofStatementHash")?,
        "receiverPayloadCiphertextRoot": string_field(payload_reference, "receiverPayloadCiphertextRoot")?,
        "receiverPayloadHash": string_field(payload_reference, "receiverPayloadHash")?,
        "shareCommitmentHash": string_field(commitment_reference, "shareCommitmentHash")?
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

fn derive_counted_package_ballot_set_hash(
    statement: &Value,
    package_hashes: Vec<Value>,
) -> Option<String> {
    derive_hash(
        "BallotSetHash",
        &json!({
            "ballotPackageHashes": package_hashes,
            "closeRecordHash": string_field(statement, "closeRecordHash")?,
            "manifestHash": string_field(statement, "manifestHash")?,
            "pollSpecHash": string_field(statement, "pollSpecHash")?,
            "postVotingClosedContextHash": string_field(statement, "postVotingClosedContextHash")?,
            "purpose": "post-close-counted-accepted-ballot-package-set-v1",
            "rosterHash": string_field(statement, "rosterHash")?,
            "thresholdProfileHash": string_field(statement, "thresholdProfileHash")?,
            "votingClosedBoardHeadHash": string_field(statement, "votingClosedBoardHeadHash")?
        }),
    )
}
