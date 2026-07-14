use super::*;

use crate::hashing::derive_canonical_object_hash;

#[test]
#[ignore = "ten-participant proof-bearing accepted-setup evidence; run via its dedicated guarded lane"]
fn ten_participant_vss_proof_bearing_collective_setup_package_passes_preterminal_accepted_setup() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "ten_participant_vss_proof_bearing_collective_setup_package_passes_preterminal_accepted_setup",
    );
    let fixture = ten_participant_descriptor_backed_vss_collective_setup_fixture();
    assert_eq!(
        fixture.package["setupContext"]["participantCount"],
        serde_json::json!(10),
        "the dedicated evidence lane must exercise the ten-participant profile",
    );

    let result = fixture
        .verify()
        .expect("ten-participant accepted-setup verification response");
    assert_eq!(result["isValid"], false, "unexpected result: {result}");
    assert_eq!(result["refusalReason"], "missingPrerequisite");
}

fn install_signed_vss_complaint(package: &mut serde_json::Value) {
    let setup_context = package["setupContext"].clone();
    let accepted_pair = &package["vssShareAcceptances"]["acceptanceRecords"][0];
    let source_trustee_roster_position = accepted_pair["sourceTrusteeRosterPosition"]
        .as_u64()
        .expect("accepted source trustee roster position");
    let recipient_roster_position = accepted_pair["recipientRosterPosition"]
        .as_u64()
        .expect("accepted recipient roster position");
    let envelope_reference = package["privateVssEnvelopeCommitments"]["envelopeReferences"]
        .as_array()
        .expect("private VSS envelope references")
        .iter()
        .find(|envelope_reference| {
            envelope_reference["sourceTrusteeRosterPosition"] == source_trustee_roster_position
                && envelope_reference["recipientRosterPosition"] == recipient_roster_position
        })
        .expect("accepted pair private VSS envelope reference");
    let source_trustee_identity = envelope_reference["sourceTrusteeIdentity"]
        .as_str()
        .expect("source trustee identity");
    let recipient_identity = envelope_reference["recipientIdentity"]
        .as_str()
        .expect("recipient identity");
    let source_trustee_record = &package["vssPublicCoefficientCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize];
    let source_trustee_commitment_root = source_trustee_record
        .get("sourceCoefficientCommitmentRoot")
        .or_else(|| source_trustee_record.get("sourceTrusteeCommitmentRoot"))
        .and_then(serde_json::Value::as_str)
        .expect("source trustee commitment root");
    let private_envelope_hash = envelope_reference["privateEnvelopeHash"]
        .as_str()
        .expect("private envelope hash");
    let complaint_evidence_root = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssComplaintEvidence",
        "privateEnvelopeHash": private_envelope_hash,
        "failure": "share-opening-mismatch",
    }))
    .expect("complaint evidence root");
    let complaint_payload = serde_json::json!({
        "objectType": "VssShareComplaint",
        "setupContextHash": crate::bgv::setup::accepted_setup::setup_context_hash(&setup_context)
            .expect("setup context hash"),
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
        "privateVssEnvelopeCommitmentRoot": package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"],
        "privateEnvelopeHash": private_envelope_hash,
        "complaintEvidenceRoot": complaint_evidence_root,
        "complaintReasonCode": "shareOpeningMismatch",
        "recoveryEpoch": 0,
        "deviceEpoch": 0,
    });
    let complaint_root =
        derive_canonical_object_hash(&complaint_payload).expect("VSS complaint root");
    let complaint_context_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssShareComplaintSignatureContext",
        "payloadRoot": complaint_root,
    }))
    .expect("VSS complaint signature context hash");
    let signature_fixture = create_protocol_signature_fixture(
        &format!("{recipient_identity}-setup-signing"),
        serde_json::json!({
            "objectType": "VssShareComplaint",
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "objectRoot": complaint_root,
            "signerRole": "Trustee",
            "signerIdentity": recipient_identity,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "contextHash": complaint_context_hash,
        }),
    )
    .expect("VSS complaint signature fixture");
    assert_eq!(
        signature_fixture.public_key_hash,
        package["setupIntent"]["trusteeRegistrations"][recipient_roster_position as usize]["signatureEnvelope"]
            ["publicKeyHash"]
    );

    package["vssComplaints"] = serde_json::json!({
        "objectType": "VssComplaintSet",
        "complaintRecords": [{
            "objectType": "VssShareComplaint",
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "recipientRosterPosition": recipient_roster_position,
            "complaintEvidenceRoot": complaint_evidence_root,
            "complaintReasonCode": "shareOpeningMismatch",
            "signatureEnvelope": signature_fixture.envelope,
        }],
    });
}

#[test]
fn valid_vss_complaint_aborts_accepted_setup() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("valid_vss_complaint_aborts_accepted_setup");
    assert_minimal_collective_setup_package_refused(
        "valid signed VSS complaint",
        install_signed_vss_complaint,
        "invalidArithmeticRelation",
    );
}

#[test]
fn collective_setup_verifier_refuses_tampered_vss_complaint_payloads() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_tampered_vss_complaint_payloads",
    );
    type ComplaintMutation = fn(&mut serde_json::Value);
    let mutation_cases: &[(&str, ComplaintMutation)] = &[
        ("tampered VSS complaint evidence root", |package| {
            install_signed_vss_complaint(package);
            package["vssComplaints"]["complaintRecords"][0]["complaintEvidenceRoot"] =
                serde_json::json!(valid_hash('8'));
        }),
        ("tampered VSS complaint reason code", |package| {
            install_signed_vss_complaint(package);
            package["vssComplaints"]["complaintRecords"][0]["complaintReasonCode"] =
                serde_json::json!("differentComplaintReason");
        }),
    ];

    for (case_label, mutate) in mutation_cases {
        assert_minimal_collective_setup_package_refused(case_label, *mutate, "wrongHashOrRoot");
    }
}

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
        "malformedEncoding",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope AAD",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["privateEnvelopeAad"]["recipientIdentity"] = serde_json::json!("trustee-9");
            rebind_first_private_vss_encrypted_envelope_hash(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "wrongHashOrRoot",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelopeHash"] =
                serde_json::json!(valid_hash('6'));
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "wrongHashOrRoot",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope recipient mailbox public-key hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["recipientMailboxPublicKeyHash"] = serde_json::json!(valid_hash('7'));
            rebind_first_private_vss_encrypted_envelope_hash(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "wrongHashOrRoot",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope commitment root",
        |package| {
            package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"] =
                serde_json::json!(valid_hash('5'));
        },
        "wrongHashOrRoot",
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_share_acceptance_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_share_acceptance_records",
    );
    type AcceptanceMutation = fn(&mut serde_json::Value);
    let mutation_cases: &[(&str, AcceptanceMutation, &str)] = &[
        (
            "VSS share acceptances replaced with an array",
            |package| package["vssShareAcceptances"] = serde_json::json!([]),
            "malformedEncoding",
        ),
        (
            "wrong VSS share acceptance object type",
            |package| {
                package["vssShareAcceptances"]["acceptanceRecords"][0]["objectType"] =
                    serde_json::json!("VssShareComplaint");
            },
            "wrongTypeOrLength",
        ),
        (
            "non-integer VSS share acceptance source position",
            |package| {
                package["vssShareAcceptances"]["acceptanceRecords"][0]["sourceTrusteeRosterPosition"] =
                    serde_json::json!("0");
            },
            "missingPrerequisite",
        ),
        (
            "duplicate VSS share acceptance pair",
            |package| {
                package["vssShareAcceptances"]["acceptanceRecords"][1] =
                    package["vssShareAcceptances"]["acceptanceRecords"][0].clone();
            },
            "equivocation",
        ),
        (
            "VSS share acceptance rebound to another recipient",
            |package| {
                package["vssShareAcceptances"]["acceptanceRecords"][0]["recipientRosterPosition"] =
                    serde_json::json!(1);
            },
            "wrongHashOrRoot",
        ),
        (
            "drifted private VSS envelope local verification root",
            |package| {
                package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["localVerificationRoot"] =
                    serde_json::json!(valid_hash('9'));
                rebind_collective_private_vss_envelope_commitment_root(package);
            },
            "wrongHashOrRoot",
        ),
        (
            "wrong signed VSS share acceptance object root",
            |package| {
                package["vssShareAcceptances"]["acceptanceRecords"][0]["signatureEnvelope"]["signedRoot"]
                    ["objectRoot"] = serde_json::json!(valid_hash('4'));
            },
            "wrongHashOrRoot",
        ),
        (
            "tampered VSS share acceptance signature",
            |package| {
                let signature_envelope =
                    package["vssShareAcceptances"]["acceptanceRecords"][0]["signatureEnvelope"]
                        .as_object_mut()
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
                signature_envelope.insert(
                    "signatureBytesHex".to_string(),
                    serde_json::json!(tampered_signature_bytes_hex),
                );
            },
            "invalidSignature",
        ),
    ];

    for (case_label, mutate, expected_refusal_reason) in mutation_cases {
        assert_minimal_collective_setup_package_refused(
            case_label,
            *mutate,
            expected_refusal_reason,
        );
    }
}

fn compact_aggregate_threshold_proof_context(
    fixture: &serde_json::Value,
) -> crate::bgv::setup::VssAggregateThresholdProofContext<'_> {
    let setup_context = &fixture["setupContext"];
    let aggregate_threshold_commitment_set = &fixture["vssPublicAggregateThresholdCommitmentSet"];

    crate::bgv::setup::VssAggregateThresholdProofContext {
        setup_context_hash: crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
            .expect("setup context hash"),
        public_matrix_seed_hash: aggregate_threshold_commitment_set["publicMatrixSeedHash"]
            .as_str()
            .expect("public matrix seed hash"),
        ring_degree: vss_commitment_ring_degree_from_fixture_package(fixture),
        participant_count: proof_record_fixtures::participant_count_from_package(fixture)
            .try_into()
            .expect("participant count fits usize"),
        rns_limb_count: DATA_PRIMES.len(),
    }
}

fn verify_compact_aggregate_threshold_proofs(
    fixture: &CompactAggregateThresholdProofFixture,
    aggregate_threshold_commitment_set: &serde_json::Value,
) -> crate::encoding::CanonicalResult<()> {
    let proof_binding_session = crate::bgv::setup::AcceptedSetupProofBindingSession::begin_fresh()?;
    for proof_binding_lease in &fixture.proof_binding_leases {
        crate::bgv::setup::restore_accepted_setup_proof_binding_lease(
            proof_binding_session.session_handle,
            proof_binding_lease,
        )?;
    }
    let package = &fixture.package;
    let verification = crate::bgv::setup::verify_vss_public_aggregate_threshold_proofs(
        Some(&proof_binding_session),
        &package["vssPublicCoefficientCommitmentSet"],
        &package["vssPublicRecipientShareCommitmentSet"],
        aggregate_threshold_commitment_set,
        &compact_aggregate_threshold_proof_context(package),
    );
    match verification {
        Ok(()) => crate::bgv::setup::finish_accepted_setup_proof_binding_session(
            proof_binding_session.session_handle,
        ),
        Err(error) => {
            crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
                proof_binding_session.session_handle,
            )?;
            Err(error)
        }
    }
}

fn assert_compact_aggregate_threshold_proofs_refused(
    fixture: &CompactAggregateThresholdProofFixture,
    case_label: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_error_code: CanonicalErrorCode,
    expected_message_fragment: Option<&str>,
) {
    let mut aggregate_threshold_commitment_set =
        fixture.package["vssPublicAggregateThresholdCommitmentSet"].clone();
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
    let package = &fixture.package;
    verify_compact_aggregate_threshold_proofs(
        &fixture,
        &package["vssPublicAggregateThresholdCommitmentSet"],
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
        "duplicate aggregate threshold proof reference",
        |aggregate_threshold_commitment_set| {
            let proofs = aggregate_threshold_commitment_set["aggregateThresholdProofs"]
                .as_array_mut()
                .expect("aggregate threshold proofs");
            proofs[1] = proofs[0].clone();
        },
        CanonicalErrorCode::MalformedLength,
        Some("unique proof material"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "cross-wired aggregate threshold proof references",
        |aggregate_threshold_commitment_set| {
            let proofs = aggregate_threshold_commitment_set["aggregateThresholdProofs"]
                .as_array_mut()
                .expect("aggregate threshold proofs");
            proofs.swap(0, 1);
        },
        CanonicalErrorCode::InvalidProtocolObject,
        None,
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "tampered aggregate threshold proof bytes hash",
        |aggregate_threshold_commitment_set| {
            aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]["proofBytesHash"] =
                serde_json::json!(valid_hash('a'));
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("proof material root"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "tampered aggregate threshold proof material root",
        |aggregate_threshold_commitment_set| {
            aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]["proofMaterialRoot"] =
                serde_json::json!(valid_hash('b'));
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("proof material root"),
    );

    assert_compact_aggregate_threshold_proofs_refused(
        &fixture,
        "aggregate threshold proof hash type mismatch",
        |aggregate_threshold_commitment_set| {
            aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]["proofBytesHash"] =
                serde_json::json!(17);
        },
        CanonicalErrorCode::InvalidFixture,
        None,
    );
}
