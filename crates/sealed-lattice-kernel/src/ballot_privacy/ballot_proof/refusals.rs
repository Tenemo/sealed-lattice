use super::*;

pub(crate) fn collect_ballot_proof_refusals(
    statement: &Value,
    ballot_proof: &Value,
    dynamic_roster_profile_evidence: Option<&Value>,
    claim_bearing_package: bool,
    unsafe_small_roster_acknowledged: bool,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let statement_hash = string_field(statement, "ballotProofStatementHash");
    let proof_record_hash = string_field(ballot_proof, "ballotProofRecordHash");
    let proof_size_bytes = object_map(ballot_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64);
    let expected_statement_hash = value_without_field(statement, "ballotProofStatementHash")
        .and_then(|payload| derive_hash("BallotProofStatementHash", &payload));
    let expected_proof_record_hash = value_without_field(ballot_proof, "ballotProofRecordHash")
        .and_then(|payload| derive_hash("BallotProofRecordHash", &payload));
    let expected_challenge_hash = derive_ballot_proof_challenge_hash(statement, ballot_proof);

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
            statement_hash,
        ));
    }
    if expected_statement_hash.as_deref() != statement_hash {
        refused_objects.push(structural_refusal(
            "Ballot proof statement hash does not match its canonical payload.",
            statement_hash,
        ));
    }
    refused_objects.extend(collect_supported_ballot_privacy_dimension_refusals(
        statement,
        statement_hash,
        dynamic_roster_profile_evidence,
        claim_bearing_package,
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
        statement_hash,
        "Ballot proof receiver-key references",
    ));
    refused_objects.extend(collect_receiver_reference_refusals(
        receiver_payloads,
        statement_hash,
        "Ballot proof receiver-payload references",
    ));
    refused_objects.extend(collect_receiver_reference_refusals(
        share_commitments,
        statement_hash,
        "Ballot proof share-commitment references",
    ));
    if receiver_public_keys.is_none_or(Vec::is_empty)
        || receiver_public_keys.map(Vec::len) != receiver_payloads.map(Vec::len)
        || receiver_public_keys.map(Vec::len) != share_commitments.map(Vec::len)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof statement must bind the same non-empty receiver set across keys, payloads, and commitments.",
            statement_hash,
        ));
    }

    if string_field(ballot_proof, "objectType") != Some("BallotProofRecord")
        || object_map(ballot_proof)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(ballot_proof, "proofBackend") != Some("LocalLinearLatticeRelation")
        || string_field(ballot_proof, "backendStatementHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "componentBundleStatementHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "componentProofBundleHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "relationStatementHash")
            .is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "linearStatementHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "statementMatrixHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "targetVectorHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "proofRoot").is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "proofBytesHash").is_none_or(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "proofEncodingProfileHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "proofParameterSetHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || string_field(ballot_proof, "publicRandomnessHash")
            .is_some_and(|hash| !is_protocol_hash(hash))
        || proof_size_bytes.is_none_or(|proof_size_bytes| proof_size_bytes == 0)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record has an invalid canonical shape.",
            proof_record_hash,
        ));
    }
    let proof_backend_metadata_field_count = [
        string_field(ballot_proof, "backendStatementHash").is_some(),
        string_field(ballot_proof, "linearStatementHash").is_some(),
        string_field(ballot_proof, "statementMatrixHash").is_some(),
        string_field(ballot_proof, "targetVectorHash").is_some(),
        string_field(ballot_proof, "proofEncodingProfileHash").is_some(),
        string_field(ballot_proof, "proofParameterSetHash").is_some(),
        string_field(ballot_proof, "publicRandomnessHash").is_some(),
    ]
    .iter()
    .filter(|field_present| **field_present)
    .count();
    if proof_backend_metadata_field_count > 0 && proof_backend_metadata_field_count != 7 {
        refused_objects.push(structural_refusal(
            "Ballot proof backend metadata must include all backend proof fields.",
            proof_record_hash,
        ));
    }
    if string_field(ballot_proof, "ballotProofStatementHash") != statement_hash {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied statement.",
            proof_record_hash,
        ));
    }
    if string_field(ballot_proof, "ballotProofProfileHash")
        != string_field(statement, "ballotProofProfileHash")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the statement proof profile.",
            proof_record_hash,
        ));
    }
    if string_field(ballot_proof, "challengeHash") != expected_challenge_hash.as_deref() {
        refused_objects.push(structural_refusal(
            "Ballot proof challenge hash does not match the statement and proof roots.",
            proof_record_hash,
        ));
    }
    if expected_proof_record_hash.as_deref() != proof_record_hash {
        refused_objects.push(structural_refusal(
            "Ballot proof record hash does not match its canonical payload.",
            proof_record_hash,
        ));
    }

    refused_objects
}

pub(crate) fn collect_proof_bytes_refusals(
    proof_bytes_hex: Option<&str>,
    expected_proof_bytes_hash: Option<&str>,
    expected_proof_size_bytes: Option<u64>,
    proof_record_hash: Option<&str>,
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
                proof_record_hash,
            ));

            return refused_objects;
        }
    };
    let proof_size_bytes = proof_bytes.len() as u64;
    let proof_bytes_hash = derive_hash(
        "ProofBytesHash",
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
            proof_record_hash,
        ));
    }
    if proof_bytes_hash.as_deref() != expected_proof_bytes_hash {
        refused_objects.push(structural_refusal(
            format!("{proof_label} proof bytes do not match the proof record hash."),
            proof_record_hash,
        ));
    }

    refused_objects
}

pub(crate) fn collect_receiver_payload_refusals(receiver_payload: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let payload_hash = string_field(receiver_payload, "receiverPayloadHash");
    let expected_ciphertext_root = match (
        string_field(receiver_payload, "ceremonyId"),
        string_field(receiver_payload, "manifestHash"),
        string_field(receiver_payload, "payloadContextHash"),
        string_field(receiver_payload, "receiverEncryptionProfileHash"),
        string_field(receiver_payload, "receiverIdentity"),
        string_field(receiver_payload, "receiverPublicKeyHash"),
        positive_roster_position(receiver_payload, "receiverRosterPosition"),
        string_field(receiver_payload, "ciphertextBodyHash"),
    ) {
        (
            Some(ceremony_id),
            Some(manifest_hash),
            Some(payload_context_hash),
            Some(receiver_encryption_profile_hash),
            Some(receiver_identity),
            Some(receiver_public_key_hash),
            Some(receiver_roster_position),
            Some(ciphertext_body_hash),
        ) => derive_hash(
            "ReceiverPayloadCiphertextRoot",
            &json!({
                "ceremonyId": ceremony_id,
                "ciphertextBodyHash": ciphertext_body_hash,
                "manifestHash": manifest_hash,
                "payloadContextHash": payload_context_hash,
                "receiverEncryptionProfileHash": receiver_encryption_profile_hash,
                "receiverIdentity": receiver_identity,
                "receiverPublicKeyHash": receiver_public_key_hash,
                "receiverRosterPosition": receiver_roster_position,
            }),
        ),
        _ => None,
    };
    let expected_payload_hash = value_without_field(receiver_payload, "receiverPayloadHash")
        .and_then(|payload| derive_hash("ReceiverPayloadHash", &payload));

    if string_field(receiver_payload, "objectType") != Some("ReceiverPayload")
        || object_map(receiver_payload)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(receiver_payload, "receiverPayloadCiphertextRoot")
            != expected_ciphertext_root.as_deref()
        || payload_hash != expected_payload_hash.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver payload shell hash or shape is invalid.",
            payload_hash,
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
                payload_hash,
            ));
            break;
        }
    }

    refused_objects
}

pub(crate) fn collect_share_commitment_refusals(share_commitment: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let share_commitment_hash = string_field(share_commitment, "shareCommitmentHash");
    let expected_hash = value_without_field(share_commitment, "shareCommitmentHash")
        .and_then(|payload| derive_hash("ShareCommitmentHash", &payload));

    if string_field(share_commitment, "objectType") != Some("ShareCommitment")
        || object_map(share_commitment)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || object_map(share_commitment)
            .and_then(|object| object.get("shareVectorWidth"))
            .and_then(Value::as_u64)
            .is_none_or(|share_vector_width| share_vector_width == 0)
        || share_commitment_hash != expected_hash.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Share commitment shell hash or shape is invalid.",
            share_commitment_hash,
        ));
    }
    for forbidden_field in ["openingRandomness", "receiverShareVector", "proofWitness"] {
        if object_map(share_commitment).is_some_and(|object| object.contains_key(forbidden_field)) {
            refused_objects.push(structural_refusal(
                "Share commitment shell must not expose witness material.",
                share_commitment_hash,
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

fn non_null_package_field<'a>(
    package_object: &'a serde_json::Map<String, Value>,
    field_name: &str,
) -> Option<&'a Value> {
    package_object
        .get(field_name)
        .filter(|value| !value.is_null())
}

pub(crate) fn collect_claim_bearing_package_refusals(
    ballot_package: &Value,
    dynamic_roster_profile_evidence: Option<&Value>,
    unsafe_small_roster_acknowledged: bool,
) -> Vec<Value> {
    let Some(package_object) = object_map(ballot_package) else {
        return vec![structural_refusal(
            "Claim-bearing ballot package shell hash or shape is invalid.",
            None,
        )];
    };
    let statement = package_object
        .get("ballotProofStatement")
        .unwrap_or(&Value::Null);
    let ballot_proof = package_object.get("ballotProof").unwrap_or(&Value::Null);
    let component_bundle_statement =
        non_null_package_field(package_object, "componentBundleStatement");
    let component_proof_bundle = non_null_package_field(package_object, "componentProofBundle");
    let component_proof_inputs = non_null_package_field(package_object, "componentProofInputs");
    let package_dynamic_roster_profile_evidence = dynamic_roster_profile_evidence
        .or_else(|| package_object.get("dynamicRosterProfileEvidence"));
    let mut refused_objects = collect_ballot_proof_refusals(
        statement,
        ballot_proof,
        package_dynamic_roster_profile_evidence,
        true,
        unsafe_small_roster_acknowledged,
    );
    refused_objects.extend(collect_proof_bytes_refusals(
        package_object.get("proofBytesHex").and_then(Value::as_str),
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
        component_bundle_statement,
        component_proof_bundle,
        component_proof_inputs,
    ));
    refused_objects.extend(collect_receiver_key_proof_root_evidence_refusals(
        package_object
            .get("receiverKeyProofRootEvidence")
            .unwrap_or(&Value::Null),
        statement,
    ));
    let package_hash = string_field(ballot_package, "ballotPackageHash");
    let expected_package_hash = derive_claim_bearing_ballot_package_hash(ballot_package);

    if string_field(ballot_package, "objectType") != Some("ClaimBearingBallotPackage")
        || package_object.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || package_hash != string_field(statement, "ballotPackageHash")
        || expected_package_hash.as_deref() != package_hash
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package shell hash or shape is invalid.",
            package_hash,
        ));
    }
    if component_proof_bundle.is_some() && !package_object.contains_key("proofBytesHex") {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package verification requires the public ballot proof bytes when a component proof bundle is supplied.",
            package_hash,
        ));
    }
    if component_proof_bundle.is_some() && component_bundle_statement.is_none() {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package verification requires the public component bundle statement when a component proof bundle is supplied.",
            package_hash,
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
            package_hash,
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
            package_hash,
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

        if payload_reference.and_then(|reference| string_field(reference, "receiverPayloadHash"))
            != string_field(receiver_payload, "receiverPayloadHash")
            || payload_reference
                .and_then(|reference| string_field(reference, "receiverPayloadCiphertextRoot"))
                != string_field(receiver_payload, "receiverPayloadCiphertextRoot")
        {
            refused_objects.push(structural_refusal(
                "Receiver payload shell is not bound to the ballot proof statement reference.",
                string_field(receiver_payload, "receiverPayloadHash"),
            ));
        }
        if receiver_key_reference
            .and_then(|reference| string_field(reference, "receiverPublicKeyHash"))
            != string_field(receiver_payload, "receiverPublicKeyHash")
            || string_field(receiver_payload, "ceremonyId") != string_field(statement, "ceremonyId")
            || string_field(receiver_payload, "manifestHash")
                != string_field(statement, "manifestHash")
            || string_field(receiver_payload, "rosterHash") != string_field(statement, "rosterHash")
            || string_field(receiver_payload, "pollSpecHash")
                != string_field(statement, "pollSpecHash")
            || string_field(receiver_payload, "voterIdentityHash")
                != string_field(statement, "voterIdentityHash")
            || string_field(receiver_payload, "receiverEncryptionProfileHash")
                != string_field(statement, "receiverEncryptionProfileHash")
        {
            refused_objects.push(structural_refusal(
                "Receiver payload shell is not bound to the statement context or receiver key.",
                string_field(receiver_payload, "receiverPayloadHash"),
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

        if commitment_reference.and_then(|reference| string_field(reference, "shareCommitmentHash"))
            != string_field(share_commitment, "shareCommitmentHash")
        {
            refused_objects.push(structural_refusal(
                "Share commitment shell is not bound to the ballot proof statement reference.",
                string_field(share_commitment, "shareCommitmentHash"),
            ));
        }
        if receiver_key_reference.and_then(|reference| string_field(reference, "receiverIdentity"))
            != string_field(share_commitment, "receiverIdentity")
            || receiver_key_reference
                .and_then(|reference| positive_roster_position(reference, "receiverRosterPosition"))
                != positive_roster_position(share_commitment, "receiverRosterPosition")
            || string_field(share_commitment, "ceremonyId") != string_field(statement, "ceremonyId")
            || string_field(share_commitment, "manifestHash")
                != string_field(statement, "manifestHash")
            || string_field(share_commitment, "rosterHash") != string_field(statement, "rosterHash")
            || object_map(share_commitment)
                .and_then(|object| object.get("shareVectorWidth"))
                .and_then(Value::as_u64)
                != object_map(statement)
                    .and_then(|object| object.get("shareVectorWidth"))
                    .and_then(Value::as_u64)
            || string_field(share_commitment, "shareCommitmentProfileHash")
                != string_field(statement, "shareCommitmentProfileHash")
        {
            refused_objects.push(structural_refusal(
                "Share commitment shell is not bound to the statement context or receiver set.",
                string_field(share_commitment, "shareCommitmentHash"),
            ));
        }
    }

    refused_objects
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::collect_ballot_proof_refusals;

    fn base_statement(hash: &str) -> serde_json::Value {
        json!({
            "objectType": "BallotProofStatement",
            "objectVersion": 1,
            "ballotProofStatementHash": hash,
            "ballotProofProfileHash": hash,
            "optionCount": 1,
            "shareVectorWidth": 13,
            "receiverPublicKeys": [],
            "receiverPayloads": [],
            "shareCommitments": []
        })
    }

    fn base_ballot_proof(hash: &str) -> serde_json::Value {
        json!({
            "objectType": "BallotProofRecord",
            "objectVersion": 1,
            "ballotProofRecordHash": hash,
            "ballotProofStatementHash": hash,
            "ballotProofProfileHash": hash,
            "challengeHash": hash,
            "proofBackend": "LocalLinearLatticeRelation",
            "proofBytesHash": hash,
            "proofRoot": hash,
            "proofSizeBytes": 1,
            "relationStatementHash": hash
        })
    }

    #[test]
    fn ballot_proof_record_allows_absent_backend_metadata() {
        let hash = "1".repeat(128);
        let statement = base_statement(&hash);
        let ballot_proof = base_ballot_proof(&hash);

        let refusals = collect_ballot_proof_refusals(&statement, &ballot_proof, None, false, false);

        assert!(!refusals.iter().any(|refusal| {
            refusal["message"]
                .as_str()
                .is_some_and(|message| message.contains("backend metadata"))
        }));
    }

    #[test]
    fn ballot_proof_record_rejects_partial_backend_metadata() {
        let hash = "1".repeat(128);
        let statement = base_statement(&hash);
        let mut ballot_proof = base_ballot_proof(&hash);
        ballot_proof["backendStatementHash"] = json!(hash);

        let refusals = collect_ballot_proof_refusals(&statement, &ballot_proof, None, false, false);

        assert!(refusals.iter().any(|refusal| {
            refusal["message"]
                .as_str()
                .is_some_and(|message| message.contains("backend metadata"))
        }));
    }
}
