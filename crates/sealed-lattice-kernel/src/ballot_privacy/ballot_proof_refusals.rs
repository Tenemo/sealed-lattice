use super::*;

pub(crate) fn collect_ballot_proof_refusals(
    statement: &Value,
    ballot_proof: &Value,
    unsafe_small_roster_acknowledged: bool,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let statement_digest = string_field(statement, "ballotProofStatementDigest");
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let proof_size_bytes = object_map(ballot_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64);
    let expected_statement_digest = value_without_field(statement, "ballotProofStatementDigest")
        .and_then(|payload| derive_digest("BallotProofStatementDigest", &payload));
    let expected_proof_record_digest = value_without_field(ballot_proof, "ballotProofRecordDigest")
        .and_then(|payload| derive_digest("BallotProofRecordDigest", &payload));
    let expected_challenge_digest = derive_ballot_proof_challenge_digest(statement, ballot_proof);

    if string_field(statement, "objectType") != Some("BallotProofStatement")
        || object_map(statement)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || object_map(statement)
            .and_then(|object| object.get("shareVectorWidth"))
            .and_then(Value::as_u64)
            != encoded_share_vector_width(statement)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof statement has an invalid canonical shape.",
            statement_digest,
        ));
    }
    if expected_statement_digest.as_deref() != statement_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof statement digest does not match its canonical payload.",
            statement_digest,
        ));
    }
    refused_objects.extend(collect_supported_ballot_privacy_dimension_refusals(
        statement,
        statement_digest,
        unsafe_small_roster_acknowledged,
    ));

    let receiver_public_keys = object_map(statement)
        .and_then(|object| object.get("receiverPublicKeys"))
        .and_then(Value::as_array);
    let receiver_payloads = object_map(statement)
        .and_then(|object| object.get("receiverPayloads"))
        .and_then(Value::as_array);
    let share_commitments = object_map(statement)
        .and_then(|object| object.get("shareCommitments"))
        .and_then(Value::as_array);
    refused_objects.extend(collect_receiver_reference_refusals(
        receiver_public_keys,
        statement_digest,
        "Ballot proof receiver-key references",
    ));
    refused_objects.extend(collect_receiver_reference_refusals(
        receiver_payloads,
        statement_digest,
        "Ballot proof receiver-payload references",
    ));
    refused_objects.extend(collect_receiver_reference_refusals(
        share_commitments,
        statement_digest,
        "Ballot proof share-commitment references",
    ));
    if receiver_public_keys.is_none_or(Vec::is_empty)
        || receiver_public_keys.map(Vec::len) != receiver_payloads.map(Vec::len)
        || receiver_public_keys.map(Vec::len) != share_commitments.map(Vec::len)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof statement must bind the same non-empty receiver set across keys, payloads, and commitments.",
            statement_digest,
        ));
    }

    if string_field(ballot_proof, "objectType") != Some("BallotProofRecord")
        || object_map(ballot_proof)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(ballot_proof, "proofBackend") != Some("LocalLinearLatticeRelation")
        || string_field(ballot_proof, "backendStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "componentBundleStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "componentProofBundleDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "relationStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "linearStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "statementMatrixDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "targetVectorDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "proofRoot").is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "proofBytesDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "proofEncodingProfileDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "proofParameterSetDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "publicRandomnessDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || proof_size_bytes.is_none_or(|proof_size_bytes| proof_size_bytes == 0)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record has an invalid canonical shape.",
            proof_record_digest,
        ));
    }
    let proof_backend_metadata_field_count = [
        string_field(ballot_proof, "backendStatementDigest").is_some(),
        string_field(ballot_proof, "linearStatementDigest").is_some(),
        string_field(ballot_proof, "statementMatrixDigest").is_some(),
        string_field(ballot_proof, "targetVectorDigest").is_some(),
        string_field(ballot_proof, "proofEncodingProfileDigest").is_some(),
        string_field(ballot_proof, "proofParameterSetDigest").is_some(),
        string_field(ballot_proof, "publicRandomnessDigest").is_some(),
    ]
    .iter()
    .filter(|field_present| **field_present)
    .count();
    if proof_backend_metadata_field_count > 0 && proof_backend_metadata_field_count != 7 {
        refused_objects.push(structural_refusal(
            "Ballot proof backend metadata must be complete when any backend proof field is present.",
            proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "ballotProofStatementDigest") != statement_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied statement.",
            proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "ballotProofProfileDigest")
        != string_field(statement, "ballotProofProfileDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the statement proof profile.",
            proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "challengeDigest") != expected_challenge_digest.as_deref() {
        refused_objects.push(structural_refusal(
            "Ballot proof challenge digest does not match the statement and proof roots.",
            proof_record_digest,
        ));
    }
    if expected_proof_record_digest.as_deref() != proof_record_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record digest does not match its canonical payload.",
            proof_record_digest,
        ));
    }

    refused_objects
}

pub(crate) fn collect_proof_bytes_refusals(
    proof_bytes_hex: Option<&str>,
    expected_proof_bytes_digest: Option<&str>,
    expected_proof_size_bytes: Option<u64>,
    proof_record_digest: Option<&str>,
    proof_label: &str,
    allow_empty_proof_bytes: bool,
) -> Vec<Value> {
    let Some(proof_bytes_hex) = proof_bytes_hex else {
        return Vec::new();
    };
    let mut refused_objects = Vec::new();
    let proof_bytes = match decode_hex(proof_bytes_hex) {
        Ok(proof_bytes) if allow_empty_proof_bytes || !proof_bytes.is_empty() => proof_bytes,
        _ => {
            let required_shape = if allow_empty_proof_bytes {
                "lowercase hexadecimal bytes"
            } else {
                "non-empty lowercase hexadecimal bytes"
            };
            refused_objects.push(structural_refusal(
                format!("{proof_label} proof bytes must be {required_shape}."),
                proof_record_digest,
            ));

            return refused_objects;
        }
    };
    let proof_size_bytes = proof_bytes.len() as u64;
    let proof_bytes_digest = derive_digest(
        "ProofBytesDigest",
        &json!({
            "objectType": "ProofBytes",
            "objectVersion": 1,
            "proofBytesHex": proof_bytes_hex,
            "proofSizeBytes": proof_size_bytes,
        }),
    );

    if Some(proof_size_bytes) != expected_proof_size_bytes {
        refused_objects.push(structural_refusal(
            format!("{proof_label} proof byte length does not match the proof record."),
            proof_record_digest,
        ));
    }
    if proof_bytes_digest.as_deref() != expected_proof_bytes_digest {
        refused_objects.push(structural_refusal(
            format!("{proof_label} proof bytes do not match the proof record digest."),
            proof_record_digest,
        ));
    }

    refused_objects
}

pub(crate) fn collect_receiver_payload_refusals(receiver_payload: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let payload_digest = string_field(receiver_payload, "receiverPayloadDigest");
    let expected_ciphertext_root = match (
        string_field(receiver_payload, "ceremonyId"),
        string_field(receiver_payload, "manifestDigest"),
        string_field(receiver_payload, "payloadContextDigest"),
        string_field(receiver_payload, "receiverEncryptionProfileDigest"),
        string_field(receiver_payload, "receiverIdentity"),
        string_field(receiver_payload, "receiverPublicKeyDigest"),
        positive_roster_position(receiver_payload, "receiverRosterPosition"),
        string_field(receiver_payload, "ciphertextBodyDigest"),
    ) {
        (
            Some(ceremony_id),
            Some(manifest_digest),
            Some(payload_context_digest),
            Some(receiver_encryption_profile_digest),
            Some(receiver_identity),
            Some(receiver_public_key_digest),
            Some(receiver_roster_position),
            Some(ciphertext_body_digest),
        ) => derive_digest(
            "ReceiverPayloadCiphertextRoot",
            &json!({
                "ceremonyId": ceremony_id,
                "ciphertextBodyDigest": ciphertext_body_digest,
                "manifestDigest": manifest_digest,
                "payloadContextDigest": payload_context_digest,
                "receiverEncryptionProfileDigest": receiver_encryption_profile_digest,
                "receiverIdentity": receiver_identity,
                "receiverPublicKeyDigest": receiver_public_key_digest,
                "receiverRosterPosition": receiver_roster_position,
            }),
        ),
        _ => None,
    };
    let expected_payload_digest = value_without_field(receiver_payload, "receiverPayloadDigest")
        .and_then(|payload| derive_digest("ReceiverPayloadDigest", &payload));

    if string_field(receiver_payload, "objectType") != Some("ReceiverPayload")
        || object_map(receiver_payload)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(receiver_payload, "receiverPayloadCiphertextRoot")
            != expected_ciphertext_root.as_deref()
        || payload_digest != expected_payload_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver payload shell digest or shape is invalid.",
            payload_digest,
        ));
    }
    for forbidden_field in [
        "receiverShareVector",
        "shareCommitmentOpening",
        "receiverEncryptionRandomness",
        "receiverEncryptionNoise",
        "proofWitness",
    ] {
        if object_map(receiver_payload).is_some_and(|object| object.contains_key(forbidden_field)) {
            refused_objects.push(structural_refusal(
                "Receiver payload shell must not expose witness material.",
                payload_digest,
            ));
            break;
        }
    }

    refused_objects
}

pub(crate) fn collect_share_commitment_refusals(share_commitment: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let share_commitment_digest = string_field(share_commitment, "shareCommitmentDigest");
    let expected_digest = value_without_field(share_commitment, "shareCommitmentDigest")
        .and_then(|payload| derive_digest("ShareCommitmentDigest", &payload));

    if string_field(share_commitment, "objectType") != Some("ShareCommitment")
        || object_map(share_commitment)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || object_map(share_commitment)
            .and_then(|object| object.get("shareVectorWidth"))
            .and_then(Value::as_u64)
            .is_none_or(|share_vector_width| share_vector_width == 0)
        || share_commitment_digest != expected_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Share commitment shell digest or shape is invalid.",
            share_commitment_digest,
        ));
    }
    for forbidden_field in ["openingRandomness", "receiverShareVector", "proofWitness"] {
        if object_map(share_commitment).is_some_and(|object| object.contains_key(forbidden_field)) {
            refused_objects.push(structural_refusal(
                "Share commitment shell must not expose witness material.",
                share_commitment_digest,
            ));
            break;
        }
    }

    refused_objects
}

pub(crate) fn reference_map(references: Option<&Vec<Value>>) -> BTreeMap<String, &Value> {
    let mut mapped_references = BTreeMap::new();
    if let Some(references) = references {
        for reference in references {
            if let Some(reference_key) = receiver_reference_key(reference) {
                mapped_references.insert(reference_key, reference);
            }
        }
    }

    mapped_references
}

pub(crate) fn collect_claim_bearing_package_shell_refusals(ballot_package: &Value) -> Vec<Value> {
    let Some(package_object) = object_map(ballot_package) else {
        return vec![structural_refusal(
            "Claim-bearing ballot package shell digest or shape is invalid.",
            None,
        )];
    };
    let statement = package_object
        .get("ballotProofStatement")
        .unwrap_or(&Value::Null);
    let mut refused_objects = collect_receiver_key_proof_root_evidence_refusals(
        package_object
            .get("receiverKeyProofRootEvidence")
            .unwrap_or(&Value::Null),
        statement,
    );
    let package_digest = string_field(ballot_package, "ballotPackageDigest");
    let expected_package_digest = derive_claim_bearing_ballot_package_digest(ballot_package);

    if string_field(ballot_package, "objectType") != Some("ClaimBearingBallotPackage")
        || package_object.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || package_digest != string_field(statement, "ballotPackageDigest")
        || expected_package_digest.as_deref() != package_digest
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package shell digest or shape is invalid.",
            package_digest,
        ));
    }
    if package_object.contains_key("componentProofBundle")
        && !package_object.contains_key("proofBytesHex")
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package verification requires the public ballot proof bytes when a component proof bundle is supplied.",
            package_digest,
        ));
    }
    if package_object.contains_key("componentProofBundle")
        && !package_object.contains_key("componentBundleStatement")
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package verification requires the public component bundle statement when a component proof bundle is supplied.",
            package_digest,
        ));
    }

    let statement_receiver_key_references = reference_map(
        object_map(statement)
            .and_then(|object| object.get("receiverPublicKeys"))
            .and_then(Value::as_array),
    );
    let statement_payload_references = reference_map(
        object_map(statement)
            .and_then(|object| object.get("receiverPayloads"))
            .and_then(Value::as_array),
    );
    let statement_commitment_references = reference_map(
        object_map(statement)
            .and_then(|object| object.get("shareCommitments"))
            .and_then(Value::as_array),
    );
    let receiver_payloads = package_object
        .get("receiverPayloads")
        .and_then(Value::as_array);
    let share_commitments = package_object
        .get("shareCommitments")
        .and_then(Value::as_array);

    if receiver_payloads.map(Vec::len)
        != object_map(statement)
            .and_then(|object| object.get("receiverPayloads"))
            .and_then(Value::as_array)
            .map(Vec::len)
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package must include every receiver payload referenced by the statement.",
            package_digest,
        ));
    }
    if share_commitments.map(Vec::len)
        != object_map(statement)
            .and_then(|object| object.get("shareCommitments"))
            .and_then(Value::as_array)
            .map(Vec::len)
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package must include every share commitment referenced by the statement.",
            package_digest,
        ));
    }

    for receiver_payload in receiver_payloads.into_iter().flatten() {
        refused_objects.extend(collect_receiver_payload_refusals(receiver_payload));
        let receiver_reference_key = receiver_reference_key(receiver_payload);
        let payload_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_payload_references.get(key).copied());
        let receiver_key_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_receiver_key_references.get(key).copied());

        if payload_reference.and_then(|reference| string_field(reference, "receiverPayloadDigest"))
            != string_field(receiver_payload, "receiverPayloadDigest")
            || payload_reference
                .and_then(|reference| string_field(reference, "receiverPayloadCiphertextRoot"))
                != string_field(receiver_payload, "receiverPayloadCiphertextRoot")
        {
            refused_objects.push(structural_refusal(
                "Receiver payload shell is not bound to the ballot proof statement reference.",
                string_field(receiver_payload, "receiverPayloadDigest"),
            ));
        }
        if receiver_key_reference
            .and_then(|reference| string_field(reference, "receiverPublicKeyDigest"))
            != string_field(receiver_payload, "receiverPublicKeyDigest")
            || string_field(receiver_payload, "ceremonyId") != string_field(statement, "ceremonyId")
            || string_field(receiver_payload, "manifestDigest")
                != string_field(statement, "manifestDigest")
            || string_field(receiver_payload, "rosterDigest")
                != string_field(statement, "rosterDigest")
            || string_field(receiver_payload, "pollSpecDigest")
                != string_field(statement, "pollSpecDigest")
            || string_field(receiver_payload, "voterIdentityDigest")
                != string_field(statement, "voterIdentityDigest")
            || string_field(receiver_payload, "receiverEncryptionProfileDigest")
                != string_field(statement, "receiverEncryptionProfileDigest")
        {
            refused_objects.push(structural_refusal(
                "Receiver payload shell is not bound to the statement context or receiver key.",
                string_field(receiver_payload, "receiverPayloadDigest"),
            ));
        }
    }

    for share_commitment in share_commitments.into_iter().flatten() {
        refused_objects.extend(collect_share_commitment_refusals(share_commitment));
        let receiver_reference_key = receiver_reference_key(share_commitment);
        let commitment_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_commitment_references.get(key).copied());
        let receiver_key_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_receiver_key_references.get(key).copied());

        if commitment_reference
            .and_then(|reference| string_field(reference, "shareCommitmentDigest"))
            != string_field(share_commitment, "shareCommitmentDigest")
        {
            refused_objects.push(structural_refusal(
                "Share commitment shell is not bound to the ballot proof statement reference.",
                string_field(share_commitment, "shareCommitmentDigest"),
            ));
        }
        if receiver_key_reference.and_then(|reference| string_field(reference, "receiverIdentity"))
            != string_field(share_commitment, "receiverIdentity")
            || receiver_key_reference
                .and_then(|reference| positive_roster_position(reference, "receiverRosterPosition"))
                != positive_roster_position(share_commitment, "receiverRosterPosition")
            || string_field(share_commitment, "ceremonyId") != string_field(statement, "ceremonyId")
            || string_field(share_commitment, "manifestDigest")
                != string_field(statement, "manifestDigest")
            || string_field(share_commitment, "rosterDigest")
                != string_field(statement, "rosterDigest")
            || object_map(share_commitment)
                .and_then(|object| object.get("shareVectorWidth"))
                .and_then(Value::as_u64)
                != object_map(statement)
                    .and_then(|object| object.get("shareVectorWidth"))
                    .and_then(Value::as_u64)
            || string_field(share_commitment, "shareCommitmentProfileDigest")
                != string_field(statement, "shareCommitmentProfileDigest")
        {
            refused_objects.push(structural_refusal(
                "Share commitment shell is not bound to the statement context or receiver set.",
                string_field(share_commitment, "shareCommitmentDigest"),
            ));
        }
    }

    refused_objects
}
