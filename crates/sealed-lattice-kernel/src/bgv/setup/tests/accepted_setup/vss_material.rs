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
    let refused_objects = result["refusedObjects"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !refused_objects.is_empty()
            && refused_objects.iter().all(|refusal| {
                refusal["reasonCode"] == "setupObjectMissing"
                    && matches!(
                        refusal["objectPath"].as_str(),
                        Some("setupPackage.publicKeyShareMaterial")
                            | Some("setupPackage.publicKeyShareSuccinctProofs")
                            | Some("setupPackage.collectivePublicKey")
                            | Some("setupPackage.collectivePublicKeyRoot")
                    )
            }),
        "the ten-participant proof-bearing package must pass every preterminal accepted-setup check: {result}",
    );
}

#[test]
fn valid_vss_complaint_aborts_accepted_setup() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("valid_vss_complaint_aborts_accepted_setup");
    assert_minimal_collective_setup_package_refused(
        "valid signed VSS complaint",
        |package| {
            let setup_context = package["setupContext"].clone();
            let accepted_pair = package["vssShareAcceptances"]["acceptanceRecords"][0].clone();
            let complaint_evidence_root = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "VssComplaintEvidence",
                "privateEnvelopeHash": accepted_pair["privateEnvelopeHash"],
                "failure": "share-opening-mismatch",
            }))
            .expect("complaint evidence root");
            let complaint_payload = serde_json::json!({
                "objectType": "VssShareComplaint",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "sourceTrusteeIdentity": accepted_pair["sourceTrusteeIdentity"],
                "sourceTrusteeRosterPosition": accepted_pair["sourceTrusteeRosterPosition"],
                "recipientIdentity": accepted_pair["recipientIdentity"],
                "recipientRosterPosition": accepted_pair["recipientRosterPosition"],
                "sourceTrusteeCommitmentRoot": accepted_pair["sourceTrusteeCommitmentRoot"],
                "privateVssEnvelopeCommitmentRoot": package["privateVssEnvelopeCommitmentRoot"],
                "privateEnvelopeHash": accepted_pair["privateEnvelopeHash"],
                "complaintEvidenceRoot": complaint_evidence_root,
                "complaintReasonCode": "shareOpeningMismatch",
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "signingPublicKeyHash": accepted_pair["signingPublicKeyHash"],
            });
            let complaint_root =
                derive_canonical_object_hash(&complaint_payload).expect("VSS complaint root");
            let complaint_byte_length = u64::try_from(
                canonical_json(&complaint_payload)
                    .expect("canonical VSS complaint payload")
                    .len(),
            )
            .expect("VSS complaint payload length");
            let complaint_context_hash = derive_canonical_object_hash(&serde_json::json!({
                "objectType": "VssShareComplaintSignatureContext",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "sourceTrusteeIdentity": accepted_pair["sourceTrusteeIdentity"],
                "sourceTrusteeRosterPosition": accepted_pair["sourceTrusteeRosterPosition"],
                "recipientIdentity": accepted_pair["recipientIdentity"],
                "recipientRosterPosition": accepted_pair["recipientRosterPosition"],
                "sourceTrusteeCommitmentRoot": accepted_pair["sourceTrusteeCommitmentRoot"],
                "privateVssEnvelopeCommitmentRoot": package["privateVssEnvelopeCommitmentRoot"],
                "privateEnvelopeHash": accepted_pair["privateEnvelopeHash"],
                "complaintEvidenceRoot": complaint_evidence_root,
                "complaintReasonCode": "shareOpeningMismatch",
                "complaintRoot": complaint_root,
            }))
            .expect("VSS complaint signature context hash");
            let signature_fixture = create_protocol_signature_fixture(
                "trustee-0-setup-signing",
                serde_json::json!({
                    "objectType": "VssShareComplaint",
                    "ceremonyId": setup_context["ceremonyId"],
                    "manifestHash": setup_context["manifestHash"],
                    "boardHeadHash": null,
                    "objectRoot": complaint_root,
                    "chunkMerkleRoot": null,
                    "byteLength": complaint_byte_length,
                    "signerRole": "Trustee",
                    "signerIdentity": accepted_pair["recipientIdentity"],
                    "recoveryEpoch": 0,
                    "deviceEpoch": 0,
                    "contextHash": complaint_context_hash,
                }),
            )
            .expect("VSS complaint signature fixture");
            assert_eq!(
                signature_fixture.public_key_hash,
                accepted_pair["signingPublicKeyHash"]
            );

            let mut complaint_record = complaint_payload;
            complaint_record["complaintRoot"] = serde_json::json!(complaint_root);
            complaint_record["complaintByteLength"] = serde_json::json!(complaint_byte_length);
            complaint_record["complaintContextHash"] = serde_json::json!(complaint_context_hash);
            complaint_record["signatureEnvelopeHash"] =
                signature_fixture.envelope["signatureHash"].clone();
            complaint_record["signatureEnvelope"] = signature_fixture.envelope;
            let mut complaint_set = serde_json::json!({
                "objectType": "VssComplaintSet",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "privateVssEnvelopeCommitmentRoot": package["privateVssEnvelopeCommitmentRoot"],
                "complaintRecords": [complaint_record],
            });
            complaint_set["vssComplaintRoot"] = serde_json::json!(
                derive_canonical_object_hash(&complaint_set).expect("VSS complaint set root")
            );
            package["vssComplaints"] = complaint_set;
        },
        "vssComplaintAcceptedAbort",
    );
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

    assert_minimal_collective_setup_package_refused(
        "drifted private VSS envelope local verification root",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["localVerificationRoot"] =
                serde_json::json!(valid_hash('9'));
            rebind_first_private_vss_envelope_commitment_record_root(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "vssShareAcceptancePrivateEnvelopeRootMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong VSS share acceptance local verification root",
        |package| {
            package["vssShareAcceptances"]["acceptanceRecords"][0]["localVerificationRoot"] =
                serde_json::json!(valid_hash('4'));
            rebind_collective_vss_acceptance_root(package);
        },
        "vssShareAcceptanceLocalVerificationRootMismatch",
    );

    assert_minimal_collective_setup_package_refused(
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
    let proof_binding_session = crate::bgv::setup::AcceptedSetupProofBindingSession::begin_fresh()?;
    for proof_record in
        fixture["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"]
            .as_array()
            .expect("compact aggregate threshold proof records")
    {
        let proof_material_root = proof_record["proofMaterialRoot"]
            .as_str()
            .expect("compact aggregate threshold proof material root");
        let proof_binding_lease =
            crate::bgv::setup::accepted_setup_fixture_proof_binding_lease(proof_material_root)?
                .expect("compact aggregate threshold proof binding lease");
        crate::bgv::setup::restore_accepted_setup_proof_binding_lease(
            proof_binding_session.session_handle,
            &proof_binding_session.capability,
            &proof_binding_lease,
        )?;
    }
    let verification = crate::bgv::setup::verify_vss_public_aggregate_threshold_proofs(
        Some(&proof_binding_session),
        fixture,
        &fixture["vssPublicCoefficientCommitmentSet"],
        &fixture["vssPublicRecipientShareCommitmentSet"],
        aggregate_threshold_commitment_set,
        &compact_aggregate_threshold_proof_context(fixture),
    );
    match verification {
        Ok(()) => crate::bgv::setup::finish_accepted_setup_proof_binding_session(
            proof_binding_session.session_handle,
            &proof_binding_session.capability,
        ),
        Err(error) => {
            crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
                proof_binding_session.session_handle,
                &proof_binding_session.capability,
            )?;
            Err(error)
        }
    }
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
    let _proof_material_eviction_guard =
        crate::bgv::setup::setup_proof::VerifiedSetupProofMaterialEvictionGuard::for_request(
            &fixture,
        );
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
        "tampered aggregate threshold proof bytes hash",
        |aggregate_threshold_commitment_set| {
            aggregate_threshold_commitment_set["aggregateThresholdProofs"][0]["proofBytesHash"] =
                serde_json::json!(valid_hash('a'));
        },
        CanonicalErrorCode::ComponentMismatch,
        Some("proof material root"),
    );
}
