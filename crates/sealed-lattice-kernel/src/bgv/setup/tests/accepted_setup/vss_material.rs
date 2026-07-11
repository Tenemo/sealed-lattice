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

fn compact_aggregate_threshold_proof_context(
    fixture: &serde_json::Value,
) -> crate::bgv::setup::VssAggregateThresholdProofContext<'_> {
    let setup_context = &fixture["setupContext"];
    let aggregate_threshold_commitment_set = &fixture["vssPublicAggregateThresholdCommitmentSet"];

    crate::bgv::setup::VssAggregateThresholdProofContext {
        ceremony_id: setup_context["ceremonyId"].as_str().expect("ceremony id"),
        manifest_hash: setup_context["manifestHash"]
            .as_str()
            .expect("manifest hash"),
        roster_hash: setup_context["rosterHash"].as_str().expect("roster hash"),
        setup_epoch: setup_context["setupEpoch"].as_str().expect("setup epoch"),
        public_matrix_seed_hash: aggregate_threshold_commitment_set["publicMatrixSeedHash"]
            .as_str()
            .expect("public matrix seed hash"),
        ring_degree: usize::try_from(
            aggregate_threshold_commitment_set["ringDegree"]
                .as_u64()
                .expect("ring degree"),
        )
        .expect("ring degree fits usize"),
        participant_count: usize::try_from(
            aggregate_threshold_commitment_set["participantCount"]
                .as_u64()
                .expect("participant count"),
        )
        .expect("participant count fits usize"),
        rns_limb_count: usize::try_from(
            aggregate_threshold_commitment_set["rnsLimbCount"]
                .as_u64()
                .expect("RNS limb count"),
        )
        .expect("RNS limb count fits usize"),
    }
}

fn verify_compact_aggregate_threshold_proofs(
    fixture: &serde_json::Value,
    aggregate_threshold_commitment_set: &serde_json::Value,
) -> crate::encoding::CanonicalResult<()> {
    crate::bgv::setup::verify_vss_public_aggregate_threshold_proofs(
        &fixture["vssPublicCoefficientCommitmentSet"],
        &fixture["vssPublicRecipientShareCommitmentSet"],
        aggregate_threshold_commitment_set,
        &compact_aggregate_threshold_proof_context(fixture),
    )
}

fn rebind_aggregate_threshold_statement_root(statement: &mut serde_json::Value) {
    let mut statement_root_input = statement.clone();
    statement_root_input
        .as_object_mut()
        .expect("aggregate threshold proof statement")
        .remove("shareLinkageStatementRoot");
    statement["shareLinkageStatementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement_root_input)
            .expect("aggregate threshold proof statement root")
    );
}

fn assert_compact_aggregate_threshold_proofs_refused(
    fixture: &serde_json::Value,
    case_label: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_error_code: CanonicalErrorCode,
    expected_message_fragment: Option<&str>,
) {
    let mut aggregate_threshold_commitment_set =
        fixture["vssPublicAggregateThresholdCommitmentSet"].clone();
    mutate(&mut aggregate_threshold_commitment_set);
    let error =
        verify_compact_aggregate_threshold_proofs(fixture, &aggregate_threshold_commitment_set)
            .expect_err(case_label);
    assert_eq!(
        error.code, expected_error_code,
        "{case_label}: unexpected error: {error}"
    );
    if let Some(expected_message_fragment) = expected_message_fragment {
        assert!(
            error.message.contains(expected_message_fragment),
            "{case_label}: error did not contain {expected_message_fragment:?}: {error}"
        );
    } else {
        assert!(
            !error.message.is_empty(),
            "{case_label}: rejection must carry a diagnostic message"
        );
    }
}

#[test]
fn collective_setup_verifier_refuses_malformed_aggregate_threshold_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_aggregate_threshold_proofs",
    );
    let fixture = compact_aggregate_threshold_proof_fixture();
    verify_compact_aggregate_threshold_proofs(
        &fixture,
        &fixture["vssPublicAggregateThresholdCommitmentSet"],
    )
    .expect("compact aggregate threshold proof fixture must verify");

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "missing aggregate threshold proof",
        |aggregate_threshold_commitment_set| {
            aggregate_threshold_commitment_set["aggregateThresholdProofs"]
                .as_array_mut()
                .expect("aggregate threshold proofs")
                .pop();
        },
        CanonicalErrorCode::MalformedLength,
        Some("proofs must cover every aggregate record"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "duplicate aggregate threshold proof coordinate",
        |aggregate_threshold_commitment_set| {
            let proofs = aggregate_threshold_commitment_set["aggregateThresholdProofs"]
                .as_array_mut()
                .expect("aggregate threshold proofs");
            proofs[1] = proofs[0].clone();
        },
        CanonicalErrorCode::MalformedLength,
        Some("one proof per recipient limb"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "cross-wired aggregate threshold proof statement",
        |aggregate_threshold_commitment_set| {
            let proofs = aggregate_threshold_commitment_set["aggregateThresholdProofs"]
                .as_array_mut()
                .expect("aggregate threshold proofs");
            let first_statement = proofs[0]["vssShareLinkage"].clone();
            proofs[0]["vssShareLinkage"] = proofs[1]["vssShareLinkage"].clone();
            proofs[1]["vssShareLinkage"] = first_statement;
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof source trustee identity"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "aggregate threshold proof without aggregate mode",
        |aggregate_threshold_commitment_set| {
            aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["isThresholdAggregate"] = serde_json::json!(false);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("must set isThresholdAggregate"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "aggregate threshold proof missing aggregate mode",
        |aggregate_threshold_commitment_set| {
            aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]["vssShareLinkage"]
                .as_object_mut()
                .expect("aggregate threshold proof statement")
                .remove("isThresholdAggregate");
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("must set isThresholdAggregate"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "aggregate threshold proof with a non-canonical statement root",
        |aggregate_threshold_commitment_set| {
            aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]["vssShareLinkage"]
                ["shareLinkageStatementRoot"] = serde_json::json!(valid_hash('c'));
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof share-linkage statement root"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold source commitment root",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["coefficientCommitmentRoots"][0] = serde_json::json!(valid_hash('0'));
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof source share commitment root"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold source opening root",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["coefficientOpeningRoots"][0] = serde_json::json!(valid_hash('1'));
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof source share opening root"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold commitment root",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["recipientShareCommitmentRoot"] = serde_json::json!(valid_hash('f'));
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof threshold-share commitment root"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold opening root",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["recipientShareOpeningRoot"] = serde_json::json!(valid_hash('e'));
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof threshold-share opening root"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold recipient identity",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["recipientIdentity"] = serde_json::json!("wrong aggregate recipient");
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof recipient identity"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold source identity",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["sourceTrusteeIdentity"] = serde_json::json!("wrong aggregate source");
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof source trustee identity"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold recipient position",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["recipientRosterPosition"] = serde_json::json!(1);
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof recipient roster position"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold source position",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["sourceTrusteeRosterPosition"] = serde_json::json!(1);
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("VSS aggregate proof source trustee roster position"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "wrong aggregate threshold summand count",
        |aggregate_threshold_commitment_set| {
            let statement = &mut aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]
                ["vssShareLinkage"];
            statement["coefficientCommitmentRoots"]
                .as_array_mut()
                .expect("aggregate threshold summand roots")
                .pop();
            rebind_aggregate_threshold_statement_root(statement);
        },
        CanonicalErrorCode::MalformedLength,
        Some("must sum one source share per participant"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "tampered aggregate threshold proof authentication bytes",
        |aggregate_threshold_commitment_set| {
            let proof_bytes_base64 = aggregate_threshold_commitment_set["aggregateThresholdProofs"]
                [0]["proofBytesBase64"]
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
            aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]["proofBytesBase64"] =
                serde_json::json!(crate::transcript_core::encode_standard_base64(&proof_bytes));
        },
        CanonicalErrorCode::InvalidProtocolObject,
        None,
    );
}
