use super::*;

use crate::hashing::derive_canonical_object_hash;

#[test]
fn collective_setup_verifier_refuses_malformed_private_vss_envelope_commitments() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_private_vss_envelope_commitments",
    );
    assert_minimal_collective_setup_package_refused(
        "private VSS envelope commitments replaced with an array",
        |package| {
            package["privateVssEnvelopeCommitments"] = serde_json::json!([]);
        },
        "privateVssEnvelopeCommitmentsNotObject",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope AAD hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["privateEnvelopeAadHash"] =
                serde_json::json!(valid_hash('4'));
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEnvelopeAadHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelopeHash"] =
                serde_json::json!(valid_hash('6'));
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope binding",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["ciphertextContentType"] = serde_json::json!("wrong-private-vss-envelope");
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeBindingMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope KEM ciphertext hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["kemCiphertextHash"] = serde_json::json!(valid_hash('9'));
            rebind_first_private_vss_encrypted_envelope_hash(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeKemCiphertextHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope ciphertext bytes hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["ciphertextBytesHash"] = serde_json::json!(valid_hash('8'));
            rebind_first_private_vss_encrypted_envelope_hash(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeCiphertextBytesHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope recipient mailbox public-key hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["recipientMailboxPublicKeyHash"] =
                serde_json::json!(valid_hash('7'));
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEnvelopeMailboxPublicKeyMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope recipient mailbox public-key bytes hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["recipientMailboxPublicKeyBytesHash"] = serde_json::json!(valid_hash('3'));
            rebind_first_private_vss_encrypted_envelope_hash(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeMailboxPublicKeyBytesHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope commitment root",
        |package| {
            package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"] =
                serde_json::json!(valid_hash('5'));
        },
        "privateVssEnvelopeCommitmentRootMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_share_acceptance_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_share_acceptance_records",
    );
    assert_minimal_collective_setup_package_refused(
        "VSS share acceptances replaced with an array",
        |package| {
            package["vssShareAcceptances"] = serde_json::json!([]);
        },
        "vssShareAcceptancesNotObject",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong VSS share acceptance source trustee commitment root",
        |package| {
            package["vssShareAcceptances"]["acceptanceRecords"][0]["sourceTrusteeCommitmentRoot"] =
                serde_json::json!(valid_hash('3'));
            rebind_collective_vss_acceptance_root(package);
        },
        "vssShareAcceptanceSourceTrusteeCommitmentRootMismatch",
    );

    assert_minimal_collective_setup_package_refused_without_handoff(
        "drifted private VSS envelope local verification root",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["localVerificationRoot"] =
                serde_json::json!(valid_hash('9'));
            rebind_first_private_vss_envelope_commitment_record_root(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "vssShareAcceptancePrivateEnvelopeRootMismatch",
    );

    assert_minimal_collective_setup_package_refused_without_handoff(
        "wrong VSS share acceptance local verification root",
        |package| {
            package["vssShareAcceptances"]["acceptanceRecords"][0]["localVerificationRoot"] =
                serde_json::json!(valid_hash('4'));
            rebind_collective_vss_acceptance_root(package);
        },
        "vssShareAcceptanceLocalVerificationRootMismatch",
    );

    assert_minimal_collective_setup_package_refused_without_handoff(
        "wrong VSS share acceptance private envelope hash",
        |package| {
            package["vssShareAcceptances"]["acceptanceRecords"][0]["privateEnvelopeHash"] =
                serde_json::json!(valid_hash('8'));
            rebind_collective_vss_acceptance_root(package);
        },
        "vssShareAcceptancePrivateEnvelopeHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "tampered VSS share acceptance signature",
        |package| {
            let acceptance_record = &mut package["vssShareAcceptances"]["acceptanceRecords"][0];
            let signature_envelope = acceptance_record
                .get_mut("signatureEnvelope")
                .expect("signature envelope");
            let signature_bytes_hex = signature_envelope["signatureBytesHex"]
                .as_str()
                .expect("signature bytes")
                .to_string();
            let replacement_prefix = if signature_bytes_hex.starts_with("00") {
                "01"
            } else {
                "00"
            };
            let mut tampered_signature_bytes_hex = signature_bytes_hex;
            tampered_signature_bytes_hex.replace_range(0..2, replacement_prefix);
            signature_envelope["signatureBytesHex"] =
                serde_json::json!(tampered_signature_bytes_hex);
            let signature_envelope_hash = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "ProtocolSignatureEnvelope",
                "profile": signature_envelope["profile"],
                "publicKeyBytesHex": signature_envelope["publicKeyBytesHex"],
                "publicKeyHash": signature_envelope["publicKeyHash"],
                "signatureBytesHex": signature_envelope["signatureBytesHex"],
                "signedRoot": signature_envelope["signedRoot"],
            }))
            .expect("signature envelope hash");
            signature_envelope["signatureHash"] =
                serde_json::json!(signature_envelope_hash.clone());
            acceptance_record["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
            rebind_collective_vss_acceptance_root(package);
        },
        "InvalidSignature",
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_aggregate_threshold_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_aggregate_threshold_proofs",
    );

    assert_minimal_collective_setup_package_refused(
        "missing aggregate threshold proof",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"]
                .as_array_mut()
                .expect("aggregate threshold proofs")
                .pop();
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "duplicate aggregate threshold proof coordinate",
        |package| {
            let proofs =
                package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"]
                    .as_array_mut()
                    .expect("aggregate threshold proofs");
            proofs[1] = proofs[0].clone();
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "cross-wired aggregate threshold proof statement",
        |package| {
            let proofs =
                package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"]
                    .as_array_mut()
                    .expect("aggregate threshold proofs");
            let first_statement = proofs[0]["vssShareLinkage"].clone();
            proofs[0]["vssShareLinkage"] = proofs[1]["vssShareLinkage"].clone();
            proofs[1]["vssShareLinkage"] = first_statement;
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "aggregate threshold proof without aggregate mode",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["isThresholdAggregate"] = serde_json::json!(false);
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold source commitment root",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["coefficientCommitmentRoots"][0] = serde_json::json!(valid_hash('0'));
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold source opening root",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["coefficientOpeningRoots"][0] = serde_json::json!(valid_hash('1'));
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold commitment root",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["recipientShareCommitmentRoot"] = serde_json::json!(valid_hash('f'));
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold opening root",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["recipientShareOpeningRoot"] = serde_json::json!(valid_hash('e'));
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold recipient identity",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["recipientIdentity"] = serde_json::json!("wrong aggregate recipient");
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold source identity",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["sourceTrusteeIdentity"] = serde_json::json!("wrong aggregate source");
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold recipient position",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["recipientRosterPosition"] = serde_json::json!(1);
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold source position",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["sourceTrusteeRosterPosition"] = serde_json::json!(1);
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong aggregate threshold summand count",
        |package| {
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]
                ["vssShareLinkage"]["coefficientCommitmentRoots"]
                .as_array_mut()
                .expect("aggregate threshold summand roots")
                .pop();
        },
        "vssPublicMaterialMalformed",
    );

    assert_minimal_collective_setup_package_refused(
        "tampered aggregate threshold proof authentication bytes",
        |package| {
            let proof_bytes_base64 =
                package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]
                    ["proofBytesBase64"]
                    .as_str()
                    .expect("aggregate threshold proof bytes");
            let mut proof_bytes = crate::transcript_core::decode_standard_base64(
                proof_bytes_base64,
                "aggregate threshold proof bytes",
            )
            .expect("decoded aggregate threshold proof bytes");
            let final_proof_byte = proof_bytes
                .last_mut()
                .expect("aggregate threshold proof must not be empty");
            *final_proof_byte ^= 0x01;
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"][0]["proofBytesBase64"] =
                serde_json::json!(crate::transcript_core::encode_standard_base64(&proof_bytes));
        },
        "vssPublicMaterialMalformed",
    );
}
