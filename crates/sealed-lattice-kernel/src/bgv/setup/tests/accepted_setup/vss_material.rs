use super::*;

use crate::hashing::derive_canonical_object_hash;

#[test]
fn production_setup_profile_refuses_a_reduced_ring_before_proof_verification() {
    let fixture = minimal_collective_setup_package_fixture();
    let result = verify_collective_bgv_setup_package(&fixture.package, &serde_json::json!({}))
        .expect("production-profile accepted-setup verification response");

    assert_eq!(result["isValid"], false, "unexpected result: {result}");
    assert_eq!(
        result["refusalReason"], "outsideSupportedProfile",
        "the fixed production profile must reject before it needs restored proof material: {result}",
    );
}

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
    let source_trustee_identity = package["setupIntent"]["trusteeRegistrations"]
        [source_trustee_roster_position as usize]["trusteeIdentity"]
        .as_str()
        .expect("source trustee identity");
    let recipient_identity = package["setupIntent"]["trusteeRegistrations"]
        [recipient_roster_position as usize]["trusteeIdentity"]
        .as_str()
        .expect("recipient identity");
    let trustee_identities = package["setupIntent"]["trusteeRegistrations"]
        .as_array()
        .expect("trustee registrations")
        .iter()
        .map(|registration| {
            registration["trusteeIdentity"]
                .as_str()
                .expect("trustee identity")
                .to_string()
        })
        .collect::<Vec<_>>();
    let source_trustee_record = &package["vssPublicCoefficientCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize];
    let source_trustee_commitment_root =
        crate::bgv::setup::vss_commitment::vss_public_source_coefficient_record_root(
            source_trustee_record,
            source_trustee_identity,
        )
        .expect("source trustee commitment root");
    let vss_coefficient_commitment_root =
        crate::bgv::setup::vss_commitment::vss_public_coefficient_commitment_set_root(
            &package["vssPublicCoefficientCommitmentSet"],
            &trustee_identities,
        )
        .expect("VSS coefficient commitment root");
    let private_vss_envelope_commitment_root = derive_canonical_object_hash(
        &private_vss_envelope_commitment_set_root_input(&serde_json::json!({
            "objectType": "PrivateVssEnvelopeCommitmentSet",
            "setupContextHash": crate::bgv::setup::accepted_setup::setup_context_hash(&setup_context)
                .expect("setup context hash"),
            "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
            "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
            "envelopeReferences": package["privateVssEnvelopeCommitments"]["envelopeReferences"],
        })),
    )
    .expect("private VSS envelope commitment root");
    let private_envelope_hash = envelope_reference["privateEnvelopeHash"]
        .as_str()
        .expect("private envelope hash");
    let complaint_payload = serde_json::json!({
        "objectType": "VssShareComplaint",
        "setupContextHash": crate::bgv::setup::accepted_setup::setup_context_hash(&setup_context)
            .expect("setup context hash"),
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "privateEnvelopeHash": private_envelope_hash,
    });
    let complaint_root =
        derive_canonical_object_hash(&complaint_payload).expect("VSS complaint root");
    let signature_fixture = create_protocol_signature_fixture(
        &format!("{recipient_identity}-setup-signing"),
        serde_json::json!({
            "objectType": "VssShareComplaint",
            "objectRoot": complaint_root,
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
fn collective_setup_verifier_refuses_malformed_private_vss_envelope_commitments() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_private_vss_envelope_commitments",
    );
    type PrivateVssEnvelopeMutation = fn(&mut serde_json::Value);
    let mutation_cases: &[(&str, PrivateVssEnvelopeMutation, &str)] = &[
        (
            "private VSS envelope commitments replaced with an array",
            |package| package["privateVssEnvelopeCommitments"] = serde_json::json!([]),
            "malformedEncoding",
        ),
        (
            "wrong private VSS encrypted envelope hash",
            |package| {
                package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelopeHash"] =
                    serde_json::json!(valid_hash('6'));
            },
            "wrongHashOrRoot",
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
            "wrongTypeOrLength",
        ),
        (
            "missing VSS share acceptance source position",
            |package| {
                package["vssShareAcceptances"]["acceptanceRecords"][0]
                    .as_object_mut()
                    .expect("VSS share acceptance record")
                    .remove("sourceTrusteeRosterPosition");
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

fn compact_aggregate_threshold_proof_context<'a>(
    fixture: &'a serde_json::Value,
    trustee_identities: &'a [String],
) -> crate::bgv::setup::VssAggregateThresholdProofContext<'a> {
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
        trustee_identities,
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
    let trustee_identities = (0..proof_record_fixtures::participant_count_from_package(package))
        .map(|roster_position| format!("trustee-{roster_position}"))
        .collect::<Vec<_>>();
    let verification = crate::bgv::setup::verify_vss_public_aggregate_threshold_proofs(
        Some(&proof_binding_session),
        &package["vssPublicCoefficientCommitmentSet"],
        &package["vssPublicRecipientShareCommitmentSet"],
        aggregate_threshold_commitment_set,
        &compact_aggregate_threshold_proof_context(package, &trustee_identities),
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

    type AggregateThresholdProofMutation = fn(&mut serde_json::Value);
    type AggregateThresholdProofMutationCase = (
        &'static str,
        AggregateThresholdProofMutation,
        CanonicalErrorCode,
        Option<&'static str>,
    );
    let mutation_cases: &[AggregateThresholdProofMutationCase] = &[
        (
            "missing aggregate threshold proof",
            |aggregate_threshold_commitment_set| {
                aggregate_threshold_commitment_set["aggregateThresholdProofBytesHashes"]
                    .as_array_mut()
                    .expect("aggregate threshold proofs")
                    .pop();
            },
            CanonicalErrorCode::MalformedLength,
            Some("proofs must cover every aggregate record"),
        ),
        (
            "duplicate aggregate threshold proof reference",
            |aggregate_threshold_commitment_set| {
                let proofs =
                    aggregate_threshold_commitment_set["aggregateThresholdProofBytesHashes"]
                        .as_array_mut()
                        .expect("aggregate threshold proofs");
                proofs[1] = proofs[0].clone();
            },
            CanonicalErrorCode::MalformedLength,
            Some("unique proof material"),
        ),
        (
            "cross-wired aggregate threshold proof references",
            |aggregate_threshold_commitment_set| {
                let proofs =
                    aggregate_threshold_commitment_set["aggregateThresholdProofBytesHashes"]
                        .as_array_mut()
                        .expect("aggregate threshold proofs");
                proofs.swap(0, 1);
            },
            CanonicalErrorCode::InvalidProtocolObject,
            None,
        ),
        (
            "tampered aggregate threshold proof bytes hash",
            |aggregate_threshold_commitment_set| {
                aggregate_threshold_commitment_set["aggregateThresholdProofBytesHashes"][0] =
                    serde_json::json!(valid_hash('a'));
            },
            CanonicalErrorCode::ComponentMismatch,
            Some("proof material root"),
        ),
        (
            "aggregate threshold proof hash type mismatch",
            |aggregate_threshold_commitment_set| {
                aggregate_threshold_commitment_set["aggregateThresholdProofBytesHashes"][0] =
                    serde_json::json!(17);
            },
            CanonicalErrorCode::InvalidProtocolObject,
            None,
        ),
    ];

    for (case_label, mutate, expected_error_code, expected_message_fragment) in mutation_cases {
        assert_compact_aggregate_threshold_proofs_refused(
            &fixture,
            case_label,
            *mutate,
            expected_error_code.clone(),
            *expected_message_fragment,
        );
    }
}
