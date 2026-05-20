use super::*;

pub(crate) fn collect_receiver_key_proof_refusals(
    receiver_key_proof: &Value,
    proof_bytes_hex: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let object_digest = string_field(receiver_key_proof, "receiverKeyProofRoot");
    let expected_digest = value_without_field(receiver_key_proof, "receiverKeyProofRoot")
        .and_then(|payload| derive_digest("ReceiverKeyProofRoot", &payload));
    let proof_size_bytes = object_map(receiver_key_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64);

    if string_field(receiver_key_proof, "objectType") != Some("ReceiverKeyProof")
        || object_map(receiver_key_proof)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(receiver_key_proof, "proofBackend") != Some("LocalLinearLatticeRelation")
        || string_field(receiver_key_proof, "proofRoot")
            .is_none_or(|proof_root| !is_protocol_digest(proof_root))
        || string_field(receiver_key_proof, "backendStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "linearStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "proofBytesDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "proofEncodingProfileDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "proofParameterSetDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "publicRandomnessDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || proof_size_bytes.is_some_and(|size| size == 0)
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof shell has an invalid canonical shape.",
            object_digest,
        ));
    }
    let proof_metadata_field_count = [
        string_field(receiver_key_proof, "linearStatementDigest").is_some(),
        string_field(receiver_key_proof, "proofBytesDigest").is_some(),
        string_field(receiver_key_proof, "proofEncodingProfileDigest").is_some(),
        string_field(receiver_key_proof, "proofParameterSetDigest").is_some(),
        string_field(receiver_key_proof, "publicRandomnessDigest").is_some(),
        proof_size_bytes.is_some(),
    ]
    .iter()
    .filter(|field_present| **field_present)
    .count();
    if proof_metadata_field_count > 0 && proof_metadata_field_count != 6 {
        refused_objects.push(structural_refusal(
            "Receiver key proof byte metadata must be complete when any proof-byte field is present.",
            object_digest,
        ));
    }
    if proof_bytes_hex.is_some() && string_field(receiver_key_proof, "proofBytesDigest").is_none() {
        refused_objects.push(structural_refusal(
            "Receiver key proof bytes require a proof-byte-bearing receiver key proof record.",
            object_digest,
        ));
    }
    refused_objects.extend(collect_proof_bytes_refusals(
        proof_bytes_hex,
        string_field(receiver_key_proof, "proofBytesDigest"),
        proof_size_bytes,
        object_digest,
        "Receiver key",
        false,
    ));
    if expected_digest.as_deref() != object_digest {
        refused_objects.push(structural_refusal(
            "Receiver key proof root does not match its canonical payload.",
            object_digest,
        ));
    }

    refused_objects
}

pub(crate) fn derive_receiver_key_proof_root_evidence_digest(evidence: &Value) -> Option<String> {
    let evidence_payload = value_without_field(evidence, "receiverKeyProofRootEvidenceDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": evidence_payload,
            "purpose": "receiver-key-proof-root-evidence-v1"
        }),
    )
}

pub(crate) fn collect_receiver_key_proof_root_evidence_refusals(
    evidence: &Value,
    statement: &Value,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let object_digest = string_field(evidence, "receiverKeyProofRootEvidenceDigest");
    let expected_digest = derive_receiver_key_proof_root_evidence_digest(evidence);
    let statement_receiver_key_references = reference_map(
        object_map(statement)
            .and_then(|object| object.get("receiverPublicKeys"))
            .and_then(Value::as_array),
    );
    let evidence_receiver_key_references = object_map(evidence)
        .and_then(|object| object.get("receiverPublicKeys"))
        .and_then(Value::as_array);
    let accepted_receiver_key_proof_count = object_map(evidence)
        .and_then(|object| object.get("acceptedReceiverKeyProofCount"))
        .and_then(Value::as_u64);
    let statement_receiver_key_count = object_map(statement)
        .and_then(|object| object.get("receiverPublicKeys"))
        .and_then(Value::as_array)
        .map(Vec::len);

    if string_field(evidence, "objectType") != Some("ReceiverKeyProofRootEvidence")
        || object_map(evidence)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(evidence, "evidenceStatus") != Some("ReceiverKeyProofRootAccepted")
        || object_digest.is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(evidence, "receiverKeyRoot")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(evidence, "receiverKeyProofRoot")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || accepted_receiver_key_proof_count.is_none_or(|count| count == 0)
    {
        refused_objects.push(structural_refusal(
            "Receiver-key proof root evidence has an invalid canonical shape.",
            object_digest,
        ));
    }
    if expected_digest.as_deref() != object_digest {
        refused_objects.push(structural_refusal(
            "Receiver-key proof root evidence digest does not match its canonical payload.",
            object_digest,
        ));
    }
    refused_objects.extend(collect_receiver_reference_refusals(
        evidence_receiver_key_references,
        object_digest,
        "Receiver-key proof root evidence receiver-key references",
    ));
    if string_field(evidence, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(evidence, "manifestDigest") != string_field(statement, "manifestDigest")
        || string_field(evidence, "rosterDigest") != string_field(statement, "rosterDigest")
        || string_field(evidence, "receiverKeyRoot") != string_field(statement, "receiverKeyRoot")
        || string_field(evidence, "receiverKeyProofRoot")
            != string_field(statement, "receiverKeyProofRoot")
        || evidence_receiver_key_references.map(Vec::len) != statement_receiver_key_count
        || accepted_receiver_key_proof_count.map(|count| count as usize)
            != statement_receiver_key_count
    {
        refused_objects.push(structural_refusal(
            "Receiver-key proof root evidence is not bound to the ballot proof statement receiver set.",
            object_digest,
        ));
    }
    for receiver_key_reference in evidence_receiver_key_references.into_iter().flatten() {
        let receiver_reference_key = receiver_reference_key(receiver_key_reference);
        let statement_receiver_key_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_receiver_key_references.get(key).copied());

        if statement_receiver_key_reference
            .and_then(|reference| string_field(reference, "receiverPublicKeyDigest"))
            != string_field(receiver_key_reference, "receiverPublicKeyDigest")
        {
            refused_objects.push(structural_refusal(
                "Receiver-key proof root evidence includes a receiver key outside the ballot proof statement.",
                object_digest,
            ));
        }
    }

    refused_objects
}

pub(crate) fn derive_claim_bearing_ballot_package_digest(ballot_package: &Value) -> Option<String> {
    let package_object = object_map(ballot_package)?;
    let statement = package_object.get("ballotProofStatement")?;
    let statement_payload = value_without_fields(
        statement,
        &["ballotProofStatementDigest", "ballotPackageDigest"],
    )?;

    derive_digest(
        "BallotPackageDigest",
        &json!({
            "objectType": "ClaimBearingBallotPackage",
            "objectVersion": 1,
            "ballotProofStatement": statement_payload,
            "receiverKeyProofRootEvidence": package_object.get("receiverKeyProofRootEvidence")?,
            "receiverPayloads": package_object.get("receiverPayloads")?,
            "shareCommitments": package_object.get("shareCommitments")?
        }),
    )
}
