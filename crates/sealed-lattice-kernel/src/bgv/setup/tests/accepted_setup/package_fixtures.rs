use super::*;

static MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<serde_json::Value> = OnceLock::new();
static TERMINAL_PROFILE_RING_MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    TerminalProfileRingSetupPackageFixture,
> = OnceLock::new();
static SAME_SECRET_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<serde_json::Value> =
    OnceLock::new();
static PUBLIC_KEY_SHARE_SUCCINCT_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    serde_json::Value,
> = OnceLock::new();
static COLLECTIVE_PUBLIC_KEY_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<serde_json::Value> =
    OnceLock::new();
static EVALUATION_KEY_PROOF_CONTAINER_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    serde_json::Value,
> = OnceLock::new();

#[derive(Clone)]
pub(super) struct TerminalProfileRingSetupPackageFixture {
    pub(super) package: serde_json::Value,
    pub(super) transported_vss_coefficient_commitment_material: serde_json::Value,
    pub(super) verified_vss_coefficient_commitment_material: serde_json::Value,
}

struct VssMaterialPackageComponents {
    vss_coefficient_commitments: serde_json::Value,
    vss_coefficient_commitment_material: serde_json::Value,
    threshold_share_commitments: serde_json::Value,
    transported_vss_coefficient_commitment_material: Option<serde_json::Value>,
    verified_vss_coefficient_commitment_material: Option<serde_json::Value>,
}

struct CollectiveSetupPackageFixture {
    package: serde_json::Value,
    transported_vss_coefficient_commitment_material: Option<serde_json::Value>,
    verified_vss_coefficient_commitment_material: Option<serde_json::Value>,
}

fn private_vss_mailbox_public_key_hash(roster_position: u64) -> String {
    derive_protocol_hash(
        "PublicKeyHash",
        &serde_json::json!({
            "algorithm": "ML-KEM-768",
            "keyPurpose": "private-vss-mailbox",
            "recipientRosterPosition": roster_position,
        }),
    )
    .expect("recipient mailbox public key hash")
}

fn private_vss_mailbox_public_key_bytes_hash(roster_position: u64) -> String {
    derive_protocol_hash(
        "PublicKeyHash",
        &serde_json::json!({
            "fixture": "recipient-mailbox-public-key-bytes",
            "recipientRosterPosition": roster_position,
        }),
    )
    .expect("recipient mailbox public key bytes hash")
}

pub(super) fn minimal_collective_setup_package() -> serde_json::Value {
    // The reduced development ring must stay provable by the trustee
    // evaluation-key argument: the trace splits each vector in two and the
    // smallest supported trace is sixty-four, so the development ring is one
    // hundred twenty-eight.
    MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(|| build_collective_setup_package_fixture(128, "development-reduced-ring"))
        .clone()
}

pub(super) fn terminal_profile_ring_minimal_collective_setup_package_fixture()
-> TerminalProfileRingSetupPackageFixture {
    TERMINAL_PROFILE_RING_MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(|| {
            let package_fixture =
                build_collective_setup_package_fixture_parts(POLYNOMIAL_DEGREE, "profile-ring");
            TerminalProfileRingSetupPackageFixture {
                package: package_fixture.package,
                transported_vss_coefficient_commitment_material: package_fixture
                    .transported_vss_coefficient_commitment_material
                    .expect("profile-ring VSS transport reference"),
                verified_vss_coefficient_commitment_material: package_fixture
                    .verified_vss_coefficient_commitment_material
                    .expect("profile-ring verified VSS material reference"),
            }
        })
        .clone()
}

fn build_collective_setup_package_fixture(
    vss_material_ring_degree: usize,
    vss_material_ring_degree_status: &str,
) -> serde_json::Value {
    build_collective_setup_package_fixture_parts(
        vss_material_ring_degree,
        vss_material_ring_degree_status,
    )
    .package
}

fn build_collective_setup_package_fixture_parts(
    vss_material_ring_degree: usize,
    vss_material_ring_degree_status: &str,
) -> CollectiveSetupPackageFixture {
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let ceremony_id = "ceremony-main";
    let manifest_hash = derive_protocol_hash(
        "ElectionManifestHash",
        &serde_json::json!({ "manifest": "collective-bgv-setup-test" }),
    )
    .expect("manifest hash");
    let roster_hash = derive_protocol_hash(
        "RosterHash",
        &serde_json::json!({ "roster": "collective-bgv-setup-test" }),
    )
    .expect("roster hash");
    let setup_profile_hash = profile["setupProfileHash"]
        .as_str()
        .expect("setup profile hash");
    let q_share_hash = profile["qShareHash"].as_str().expect("Q_share hash");
    let carry_aware_vss_relation_profile_hash = profile["carryAwareVssShareRelationProfileHash"]
        .as_str()
        .expect("carry-aware VSS relation profile hash");
    let commitment_profile_hash = profile["commitmentProfileHash"]
        .as_str()
        .expect("commitment profile hash");
    let setup_epoch = "setup-epoch-1";
    let setup_context = serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "participantCount": 10,
        "qSetupComplete": 10,
        "qBallotRelease": 10,
        "qFinal": 10,
        "qDec": 4,
    });
    let mut previous_phase_root = serde_json::Value::Null;
    let phase_transcript = profile["phaseOrder"]
        .as_array()
        .expect("phase order")
        .iter()
        .map(|phase| {
            let phase_identifier = phase["phaseId"].as_str().expect("phase id");
            let phase_number = phase["phaseNumber"].as_u64().expect("phase number");
            let participant_phase_objects = (0..10)
                .map(|roster_position| {
                    let trustee_identity = format!("trustee-{roster_position}");
                    let signature_seed_label = format!("{trustee_identity}-{phase_identifier}");
                    let signing_public_key_hash =
                        create_ml_dsa_public_key_hash_fixture(&signature_seed_label)
                            .expect("signature key fixture");
                    let mut phase_payload = serde_json::json!({
                        "objectType": "SetupPhaseParticipantObject",
                        "objectVersion": 1,
                        "phaseId": phase_identifier,
                        "phaseNumber": phase_number,
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "rosterHash": roster_hash,
                        "setupProfileHash": setup_profile_hash,
                        "commitmentProfileHash": commitment_profile_hash,
                        "setupEpoch": setup_epoch,
                        "signerRole": "Trustee",
                        "trusteeIdentity": trustee_identity,
                        "rosterPosition": roster_position,
                        "recoveryEpoch": 0,
                        "deviceEpoch": 0,
                        "signingPublicKeyHash": signing_public_key_hash,
                    });
                    if phase_identifier == "setupIntent" {
                        phase_payload["privateVssMailboxPublicKeyHash"] =
                            serde_json::json!(private_vss_mailbox_public_key_hash(roster_position));
                        phase_payload["privateVssMailboxPublicKeyBytesHash"] = serde_json::json!(
                            private_vss_mailbox_public_key_bytes_hash(roster_position)
                        );
                    }
                    let phase_object_root = derive_protocol_hash(
                        "SetupPhaseObjectHash",
                        &phase_payload,
                    )
                    .expect("phase object root");
                    let phase_object_byte_length =
                        u64::try_from(canonical_json(&phase_payload).expect("phase payload").len())
                            .expect("phase payload length");
                    let phase_signature_context_hash = derive_protocol_hash(
                        "SetupPhaseObjectHash",
                        &serde_json::json!({
                            "purpose": "setup-phase-signature-context",
                            "phaseId": phase_identifier,
                            "phaseNumber": phase_number,
                            "ceremonyId": ceremony_id,
                            "manifestHash": manifest_hash,
                            "rosterHash": roster_hash,
                            "setupProfileHash": setup_profile_hash,
                            "qShareHash": q_share_hash,
                            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                            "commitmentProfileHash": commitment_profile_hash,
                            "setupEpoch": setup_epoch,
                            "trusteeIdentity": trustee_identity,
                            "rosterPosition": roster_position,
                            "phaseObjectRoot": phase_object_root,
                        }),
                    )
                    .expect("phase signature context hash");
                    let signature_fixture = create_protocol_signature_fixture(
                        &signature_seed_label,
                        serde_json::json!({
                            "objectType": "SetupPhaseParticipantObject",
                            "objectVersion": 1,
                            "ceremonyId": ceremony_id,
                            "manifestHash": manifest_hash,
                            "boardHeadHash": null,
                            "objectRoot": phase_object_root,
                            "chunkMerkleRoot": null,
                            "byteLength": phase_object_byte_length,
                            "signerRole": "Trustee",
                            "signerIdentity": trustee_identity,
                            "recoveryEpoch": 0,
                            "deviceEpoch": 0,
                            "contextHash": phase_signature_context_hash,
                        }),
                    )
                    .expect("phase signature fixture");
                    let signature_envelope = signature_fixture.envelope;
                    let signature_envelope_hash = signature_envelope["signatureHash"].clone();
                    let mut participant_phase_object = serde_json::json!({
                        "objectType": "SetupPhaseParticipantObject",
                        "objectVersion": 1,
                        "phaseId": phase_identifier,
                        "phaseNumber": phase_number,
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "rosterHash": roster_hash,
                        "setupProfileHash": setup_profile_hash,
                        "setupEpoch": setup_epoch,
                        "signerRole": "Trustee",
                        "trusteeIdentity": trustee_identity,
                        "rosterPosition": roster_position,
                        "recoveryEpoch": 0,
                        "deviceEpoch": 0,
                        "signingPublicKeyHash": signing_public_key_hash,
                        "phaseObjectRoot": phase_object_root,
                        "phaseObjectByteLength": phase_object_byte_length,
                        "phaseSignatureContextHash": phase_signature_context_hash,
                        "signatureEnvelopeHash": signature_envelope_hash,
                        "signatureEnvelope": signature_envelope,
                    });
                    if phase_identifier == "setupIntent" {
                        participant_phase_object["privateVssMailboxPublicKeyHash"] =
                            serde_json::json!(private_vss_mailbox_public_key_hash(roster_position));
                        participant_phase_object["privateVssMailboxPublicKeyBytesHash"] =
                            serde_json::json!(private_vss_mailbox_public_key_bytes_hash(
                                roster_position
                            ));
                    }

                    participant_phase_object
                })
                .collect::<Vec<_>>();
            let mut phase_record = serde_json::json!({
                "phaseId": phase_identifier,
                "phaseNumber": phase_number,
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "rosterHash": roster_hash,
                "setupProfileHash": setup_profile_hash,
                "qShareHash": q_share_hash,
                "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                "commitmentProfileHash": commitment_profile_hash,
                "setupEpoch": setup_epoch,
                "previousPhaseRoot": previous_phase_root.clone(),
                "participantPhaseObjects": participant_phase_objects,
            });
            let phase_root =
                derive_protocol_hash("SetupPhaseRoot", &phase_record).expect("phase root");
            phase_record["phaseRoot"] = serde_json::json!(phase_root.clone());
            previous_phase_root = serde_json::json!(phase_root);

            phase_record
        })
        .collect::<Vec<_>>();
    let common_randomness = common_randomness_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_profile_hash,
        setup_epoch,
    );
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let vss_components = if vss_material_ring_degree == POLYNOMIAL_DEGREE
        && vss_material_ring_degree_status == "profile-ring"
    {
        streamed_vss_coefficient_commitments_object(
            ceremony_id,
            &manifest_hash,
            &roster_hash,
            setup_profile_hash,
            q_share_hash,
            carry_aware_vss_relation_profile_hash,
            commitment_profile_hash,
            setup_epoch,
            public_matrix_seed_hash,
            vss_material_ring_degree,
            "terminal-profile-ring-vss-material-stream",
        )
    } else {
        let (vss_coefficient_commitments, vss_coefficient_commitment_material) =
            vss_coefficient_commitments_object(
                ceremony_id,
                &manifest_hash,
                &roster_hash,
                setup_profile_hash,
                q_share_hash,
                carry_aware_vss_relation_profile_hash,
                commitment_profile_hash,
                setup_epoch,
                public_matrix_seed_hash,
                vss_material_ring_degree,
                vss_material_ring_degree_status,
            );
        let threshold_share_commitments =
            derive_threshold_share_commitments_from_request(&serde_json::json!({
                "setupContext": setup_context.clone(),
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "sourceTrusteeCoefficientCommitmentRecords": vss_coefficient_commitments["sourceTrusteeRecords"].clone(),
                "coefficientCommitments": vss_coefficient_commitment_material["coefficientCommitments"].clone(),
            }))
            .expect("threshold-share commitments")["thresholdShareCommitments"]
                .clone();
        VssMaterialPackageComponents {
            vss_coefficient_commitments,
            vss_coefficient_commitment_material,
            threshold_share_commitments,
            transported_vss_coefficient_commitment_material: None,
            verified_vss_coefficient_commitment_material: None,
        }
    };
    let vss_coefficient_commitments = vss_components.vss_coefficient_commitments.clone();
    let vss_coefficient_commitment_material =
        vss_components.vss_coefficient_commitment_material.clone();
    let threshold_share_commitments = vss_components.threshold_share_commitments.clone();
    let private_vss_envelope_commitments = private_vss_envelope_commitments_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_profile_hash,
        q_share_hash,
        carry_aware_vss_relation_profile_hash,
        commitment_profile_hash,
        setup_epoch,
        &common_randomness,
        &vss_coefficient_commitments,
    );
    let private_vss_envelope_commitment_root =
        private_vss_envelope_commitments["privateVssEnvelopeCommitmentRoot"]
            .as_str()
            .expect("private VSS envelope commitment root")
            .to_string();
    let vss_share_acceptances = vss_share_acceptances_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_profile_hash,
        q_share_hash,
        carry_aware_vss_relation_profile_hash,
        commitment_profile_hash,
        setup_epoch,
        &private_vss_envelope_commitments,
        &vss_coefficient_commitments,
    );
    let same_secret_consistency = same_secret_consistency_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_profile_hash,
        q_share_hash,
        carry_aware_vss_relation_profile_hash,
        commitment_profile_hash,
        setup_epoch,
        &vss_coefficient_commitments,
    );
    let public_key_shares = public_key_shares_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_profile_hash,
        q_share_hash,
        carry_aware_vss_relation_profile_hash,
        commitment_profile_hash,
        setup_epoch,
        &common_randomness,
        &same_secret_consistency,
    );
    let public_key_share_proofs = public_key_share_proofs_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_profile_hash,
        q_share_hash,
        carry_aware_vss_relation_profile_hash,
        commitment_profile_hash,
        setup_epoch,
        &common_randomness,
        &same_secret_consistency,
        &public_key_shares,
    );
    let evaluator_key_schedule = evaluator_key_schedule_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_profile_hash,
        q_share_hash,
        carry_aware_vss_relation_profile_hash,
        commitment_profile_hash,
        setup_epoch,
        &profile,
        &common_randomness,
        &same_secret_consistency,
        &public_key_shares,
        &public_key_share_proofs,
    );
    let setup_commitment_security_certificate =
        setup_commitment_security_certificate_fixture(&profile);
    let setup_commitment_security_certificate_hash = setup_commitment_security_certificate
        .get("setupCommitmentSecurityCertificateHash")
        .and_then(serde_json::Value::as_str)
        .expect("setup commitment security certificate hash")
        .to_string();
    let setup_transport_certificate = match &vss_components
        .transported_vss_coefficient_commitment_material
    {
        Some(transported_vss_coefficient_commitment_material) => {
            setup_transport_certificate_for_transported_vss_material(
                &profile,
                &vss_coefficient_commitment_material,
                transported_vss_coefficient_commitment_material,
            )
        }
        None => setup_transport_certificate_fixture(&profile, &vss_coefficient_commitment_material),
    };
    let setup_transport_certificate_hash = setup_transport_certificate
        .get("setupTransportCertificateHash")
        .and_then(serde_json::Value::as_str)
        .expect("setup transport certificate hash")
        .to_string();
    let setup_proof_accounting_certificate_hash_value =
        setup_proof_accounting_certificate_hash().expect("setup proof accounting certificate hash");
    let mut setup_proof_accounting_certificate =
        setup_proof_accounting_certificate_value().expect("setup proof accounting certificate");
    setup_proof_accounting_certificate["setupProofAccountingCertificateHash"] =
        serde_json::json!(setup_proof_accounting_certificate_hash_value.clone());
    let he_security_certificate_hash =
        accepted_he_security_certificate_hash().expect("HE security certificate hash");
    let mut he_security_certificate =
        accepted_he_security_certificate_value().expect("HE security certificate");
    he_security_certificate["heSecurityCertificateHash"] =
        serde_json::json!(he_security_certificate_hash.clone());
    let mut package = serde_json::json!({
        "objectType": "SetupPackage",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupContext": setup_context,
        "qShare": profile["qShare"].clone(),
        "phaseTranscript": phase_transcript,
        "commonRandomness": common_randomness,
        "vssCoefficientCommitments": vss_coefficient_commitments,
        "vssCoefficientCommitmentMaterial": vss_coefficient_commitment_material,
        "privateVssEnvelopeCommitments": private_vss_envelope_commitments,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "vssShareAcceptances": vss_share_acceptances,
        "thresholdShareCommitments": threshold_share_commitments,
        "sameSecretConsistency": same_secret_consistency,
        "publicKeyShares": public_key_shares,
        "publicKeyShareProofs": public_key_share_proofs,
        "evaluatorKeySchedule": evaluator_key_schedule,
        "relinearizationKeyShareRounds": {},
        "galoisKeyShareBatches": [],
        "trusteeEvaluationKeyProofs": {},
        "evaluationKeys": {},
        "setupCommitmentSecurityCertificate": setup_commitment_security_certificate,
        "setupCommitmentSecurityCertificateHash": setup_commitment_security_certificate_hash,
        "setupTransportCertificate": setup_transport_certificate,
        "setupTransportCertificateHash": setup_transport_certificate_hash,
        "setupProofAccountingCertificate": setup_proof_accounting_certificate,
        "setupProofAccountingCertificateHash": setup_proof_accounting_certificate_hash_value,
        "heSecurityCertificate": he_security_certificate,
        "heSecurityCertificateHash": he_security_certificate_hash,
    });
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    CollectiveSetupPackageFixture {
        package,
        transported_vss_coefficient_commitment_material: vss_components
            .transported_vss_coefficient_commitment_material,
        verified_vss_coefficient_commitment_material: vss_components
            .verified_vss_coefficient_commitment_material,
    }
}

fn setup_commitment_security_certificate_fixture(profile: &serde_json::Value) -> serde_json::Value {
    let max_source_message_modulus = DATA_PRIMES.iter().copied().max().expect("Q_share primes");
    let recipient_scalar_sum = scalar_power_sum_fixture(4, 10);
    let threshold_scalar_sum = recipient_scalar_sum * 10;
    let recipient_scalar_sum_u64 = u64::try_from(recipient_scalar_sum).expect("recipient bound");
    let threshold_scalar_sum_u64 = u64::try_from(threshold_scalar_sum).expect("threshold bound");
    let commitment_modulus_product =
        profile["commitmentProfile"]["messageEncoding"]["commitmentModulusLimbs"]
            .as_array()
            .expect("commitment modulus limbs")
            .iter()
            .map(|limb| BigUint::from(limb["modulus"].as_u64().expect("commitment modulus limb")))
            .product::<BigUint>();
    let max_recipient_lifted_coefficient =
        u128::from(max_source_message_modulus - 1) * recipient_scalar_sum;
    let max_threshold_lifted_coefficient =
        u128::from(max_source_message_modulus - 1) * threshold_scalar_sum;
    let commitment_modulus_product_bits = ceil_log2_fixture(&commitment_modulus_product);
    let fresh_message_no_wrap =
        BigUint::from(max_source_message_modulus - 1) < commitment_modulus_product.clone();
    let certificate = serde_json::json!({
        "objectType": "SetupCommitmentSecurityCertificate",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProfileHash": profile["setupProfileHash"],
        "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
        "commitmentProfileHash": profile["commitmentProfileHash"],
        "qShareHash": profile["qShareHash"],
        "carryAwareVssShareRelationProfileHash": profile["carryAwareVssShareRelationProfileHash"],
        "certificateScope": "first-profile-BDLOP-LNP-commitment-parameters-and-opening-bounds",
        "acceptedUse": [
            "VSS coefficient commitment records",
            "recipient-local private VSS proof witness checks",
            "verifier-derived threshold-share commitment roots",
            "same-secret trustee commitment roots",
        ],
        "nonClosure": [
            "public evaluation-key assembly and setup-package terminal acceptance remain separate from this commitment parameter certificate",
            "profile-scale binary streaming evidence remains separate from this commitment parameter certificate",
            "future target-decryption readiness remains outside this commitment parameter certificate",
        ],
        "ringAndMatrixParameters": {
            "coefficientRing": "Z_q[X]/(X^N+1)",
            "ringDegree": POLYNOMIAL_DEGREE,
            "sourceRnsLimbCount": DATA_PRIMES.len(),
            "sourceRnsPrimes": DATA_PRIMES,
            "commitmentModulusLimbs": profile["commitmentProfile"]["messageEncoding"]["commitmentModulusLimbs"],
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "commitmentModulusProductCeilBits": commitment_modulus_product_bits,
            "moduleRank": 2,
            "randomnessWidth": 5,
            "commitmentRowCount": 3,
            "publicMatrixSource": "full-roster-common-randomness-XOF-unbiased-residue-stream",
            "matrixHashBound": true,
        },
        "freshOpeningDistribution": {
            "distribution": "coefficientwise-centered-ternary",
            "coefficientSet": [-1, 0, 1],
            "infinityNormBound": 1,
            "randomnessWidth": 5,
            "rawOpeningExported": false,
            "perCoefficientOpeningExported": false,
        },
        "fullWidthMessageBound": {
            "messageSource": "per-RNS-prime-Shamir-coefficient-ring-element",
            "maxSourceMessageModulus": max_source_message_modulus,
            "maxFreshMessageCoefficientDecimal": (max_source_message_modulus - 1).to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "freshMessageNoWrap": fresh_message_no_wrap,
            "status": "claim-accounting-full-width-per-rns-message-bound-recorded",
        },
        "aggregateOpeningBounds": {
            "shamirCoefficientCount": 4,
            "maximumTrusteePoint": 10,
            "recipientScalarPowerSumDecimal": recipient_scalar_sum.to_string(),
            "recipientAggregateOpeningInfinityBound": recipient_scalar_sum_u64,
            "maxRecipientLiftedCoefficientDecimal": max_recipient_lifted_coefficient.to_string(),
            "sourceTrusteeCountForThresholdAggregation": 10,
            "thresholdScalarPowerSumDecimal": threshold_scalar_sum.to_string(),
            "thresholdShareOpeningInfinityBound": threshold_scalar_sum_u64,
            "maxThresholdLiftedCoefficientDecimal": max_threshold_lifted_coefficient.to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "recipientAndThresholdNoWrap": true,
            "boundStatus": "claim-accounting-first-profile-homomorphic-opening-bounds-recorded",
        },
        "multiOpeningLeakage": {
            "recipientAggregateOpeningsArePublic": false,
            "recipientAggregateOpeningsAreMailboxPlaintext": false,
            "maxCorruptRecipientsBeforeThreshold": 3,
            "shamirPolynomialDegree": 3,
            "rawCoefficientOpeningsExported": false,
            "perCoefficientRandomnessExported": false,
            "thresholdBoundary": "recipient-aggregate-openings-and-carry-witnesses-are-private-proof-witnesses",
            "status": "claim-accounting-active-static-threshold-leakage-bound-recorded",
        },
        "bindingAssumption": {
            "assumption": "Module-SIS",
            "boundTarget": "two-valid-openings-to-one-commitment-yield-short-module-SIS-solution",
            "moduleRank": 2,
            "randomnessWidth": 5,
            "commitmentModulusProductCeilBits": commitment_modulus_product_bits,
            "extractedOpeningInfinityBound": threshold_scalar_sum_u64,
            "referenceRows": [
                {
                    "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                    "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                    "sections": [
                        "Commitment schemes",
                        "Module-SIS and Module-LWE problems",
                        "ABDLOP commitment scheme and proofs of linear relations"
                    ]
                },
                {
                    "document": "FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting",
                    "localReferencePath": "reference-documents/FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting.txt",
                    "sections": [
                        "BDLOP commitment background",
                        "Module-LWE and Module-SIS definitions"
                    ]
                }
            ],
            "estimatorStatus": "repo-owned-module-sis-parameter-accounting-accepted",
        },
        "hidingAssumption": {
            "assumption": "Module-LWE with recipient-hidden proof-witness opening leakage boundary",
            "openingDistribution": "coefficientwise-centered-ternary",
            "publicMatrixDistribution": "hash-derived-uniform-residue-stream",
            "lowEntropySecretHiding": true,
            "statisticalLeakageStatus": "repo-owned-recipient-hidden-aggregate-opening-proof-witness-accounting-accepted",
            "estimatorStatus": "repo-owned-module-lwe-parameter-accounting-accepted",
        },
        "estimatorRows": [
            {
                "rowId": "first-profile-module-sis-binding-row",
                "problem": "Module-SIS",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": 2,
                "modulusCeilBits": commitment_modulus_product_bits,
                "shortVectorInfinityBoundDecimal": threshold_scalar_sum.to_string(),
                "status": "claim-accounting-accepted",
                "accountingBasis": "accepted Module-SIS binding row under LNP22/FPS25 commitment references and no-wrap threshold-opening bounds"
            },
            {
                "rowId": "first-profile-module-lwe-hiding-row",
                "problem": "Module-LWE",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": 2,
                "secretDistribution": "centered-ternary-opening",
                "modulusCeilBits": commitment_modulus_product_bits,
                "status": "claim-accounting-accepted",
                "accountingBasis": "accepted Module-LWE hiding row under LNP22/FPS25/ACC18 references and recipient-hidden opening leakage boundary"
            }
        ],
        "certificateStatus": "claim-bearing-setup-commitment-parameter-accounting-accepted",
    });

    let certificate_hash =
        derive_protocol_hash("SetupCommitmentSecurityCertificateHash", &certificate)
            .expect("commitment security certificate hash");
    let mut certificate_with_hash = certificate;
    certificate_with_hash["setupCommitmentSecurityCertificateHash"] =
        serde_json::json!(certificate_hash);

    certificate_with_hash
}

fn scalar_power_sum_fixture(coefficient_count: u64, trustee_point: u64) -> u128 {
    let mut scalar_sum = 0_u128;
    let mut trustee_power = 1_u128;
    for coefficient_index in 0..coefficient_count {
        scalar_sum += trustee_power;
        if coefficient_index + 1 < coefficient_count {
            trustee_power *= u128::from(trustee_point);
        }
    }

    scalar_sum
}

fn ceil_log2_fixture(value: &BigUint) -> u32 {
    if value <= &BigUint::from(1_u8) {
        0
    } else {
        let previous = value - BigUint::from(1_u8);
        u32::try_from(previous.bits()).expect("fixture bit length")
    }
}

pub(super) fn setup_transport_chunk_manifest_root_fixture(
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> String {
    derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "objectType": "SetupTransportChunkManifest",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "chunkSizeBytes": 1_048_576_u64,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )
    .expect("setup transport chunk manifest root")
}

pub(super) fn setup_transport_certificate_fixture(
    profile: &serde_json::Value,
    vss_coefficient_commitment_material: &serde_json::Value,
) -> serde_json::Value {
    let chunk_size_bytes = 1_048_576_u64;
    let total_byte_length = vss_material_binary_total_byte_length(POLYNOMIAL_DEGREE);
    let chunk_count = total_byte_length.div_ceil(chunk_size_bytes);
    let vss_full_object_hash = derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "fixture": "setup-transport-full-object-hash",
            "totalByteLength": total_byte_length,
        }),
    )
    .expect("transport full object hash");
    let chunk_hashes = (0..chunk_count)
        .map(|chunk_index| {
            derive_protocol_hash(
                "SetupTransportChunkManifestRoot",
                &serde_json::json!({
                    "fixture": "setup-transport-chunk-hash",
                    "chunkIndex": chunk_index,
                }),
            )
            .expect("transport chunk hash")
        })
        .collect::<Vec<_>>();
    let vss_chunk_root = derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "objectType": "SetupTransportChunkManifest",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": vss_full_object_hash,
        }),
    )
    .expect("setup transport chunk root");
    let transported_objects = serde_json::json!([
        {
            "objectType": "SetupTransportedObject",
            "objectVersion": 1,
            "objectName": "vssCoefficientCommitmentMaterial",
            "objectRole": "public-vss-coefficient-commitment-material",
            "objectRoot": vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"],
            "byteLength": total_byte_length,
            "chunkStartIndex": 0_u64,
            "chunkCount": chunk_count,
            "chunkRoot": vss_chunk_root,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": vss_full_object_hash,
            "encoding": "binary",
            "loadingPolicy": "stream-verified-before-object-use",
        }
    ]);
    let aggregate_full_object_hash = derive_protocol_hash(
        "SetupTransportFullObjectSetHash",
        &serde_json::json!({
            "objectType": "SetupTransportFullObjectSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "transportedObjects": [{
                "objectName": "vssCoefficientCommitmentMaterial",
                "objectRole": "public-vss-coefficient-commitment-material",
                "objectRoot": vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"],
                "byteLength": total_byte_length,
                "chunkStartIndex": 0_u64,
                "chunkCount": chunk_count,
                "chunkRoot": vss_chunk_root,
                "fullObjectHash": vss_full_object_hash,
            }],
            "totalByteLength": total_byte_length,
            "chunkCount": chunk_count,
            "chunkHashes": chunk_hashes,
        }),
    )
    .expect("setup transport full object set hash");
    let chunk_root = derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "objectType": "SetupTransportChunkManifest",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": aggregate_full_object_hash,
        }),
    )
    .expect("setup transport aggregate chunk root");
    let mut certificate = serde_json::json!({
        "objectType": "SetupTransportCertificate",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
        "setupTransportProfileHash": profile["setupTransportProfileHash"],
        "largeObjectEncoding": "binary",
        "chunking": "required",
        "chunkSizeBytes": chunk_size_bytes,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "storageQuotaBytes": 2_147_483_648_u64,
        "largestSingleBufferBytes": 1_572_864_u64,
        "copyCountLimit": 2_u64,
        "streamVerificationOrder": "ascending-chunk-index",
        "resumePolicy": "chunk-index-checkpointed-by-hash",
        "lazyLoadingPolicy": "root-addressed-large-object-loading",
        "transportedObjects": transported_objects,
        "chunkHashes": chunk_hashes,
        "chunkRoot": chunk_root,
        "fullObjectHash": aggregate_full_object_hash,
    });
    let certificate_hash = derive_protocol_hash("SetupTransportCertificateHash", &certificate)
        .expect("setup transport certificate hash");
    certificate["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);

    certificate
}

pub(super) fn setup_transport_certificate_for_transported_vss_material(
    profile: &serde_json::Value,
    vss_coefficient_commitment_material: &serde_json::Value,
    transported_vss_material: &serde_json::Value,
) -> serde_json::Value {
    let mut certificate =
        setup_transport_certificate_fixture(profile, vss_coefficient_commitment_material);
    let vss_transport_object = certificate["transportedObjects"][0]
        .as_object_mut()
        .expect("VSS transport certificate object");
    vss_transport_object.insert(
        "objectRoot".to_string(),
        vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"].clone(),
    );
    vss_transport_object.insert(
        "byteLength".to_string(),
        transported_vss_material["totalByteLength"].clone(),
    );
    vss_transport_object.insert(
        "chunkCount".to_string(),
        transported_vss_material["chunkCount"].clone(),
    );
    vss_transport_object.insert(
        "chunkRoot".to_string(),
        transported_vss_material["chunkRoot"].clone(),
    );
    vss_transport_object.insert(
        "chunkHashes".to_string(),
        transported_vss_material["chunkHashes"].clone(),
    );
    vss_transport_object.insert(
        "fullObjectHash".to_string(),
        transported_vss_material["fullObjectHash"].clone(),
    );
    rebind_setup_transport_certificate(&mut certificate);

    certificate
}

#[allow(clippy::too_many_arguments)]
fn vss_coefficient_commitments_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    ring_degree_status: &str,
) -> (serde_json::Value, serde_json::Value) {
    let mut source_trustee_records = Vec::new();
    let mut coefficient_commitment_material = Vec::new();

    for source_trustee_roster_position in 0..10_u64 {
        let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
        let mut coefficient_commitments = Vec::new();
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..4_u64 {
                let coefficient_message = accepted_vss_coefficient_message_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    rns_prime,
                    ring_degree,
                );
                let coefficient_message_wide = coefficient_message
                    .iter()
                    .map(|coefficient| u128::from(*coefficient))
                    .collect::<Vec<_>>();
                let randomness_by_column = accepted_vss_randomness_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    ring_degree,
                );
                let commitment = compute_setup_commitment_for_tests(
                    public_matrix_seed_hash,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    &coefficient_message_wide,
                    &randomness_by_column,
                    ring_degree,
                )
                .expect("setup commitment");
                let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
                let commitment_chunk_root = derive_protocol_hash(
                    "VssCoefficientCommitmentRoot",
                    &serde_json::json!({
                        "fixture": "vss-coefficient-commitment-chunk-root",
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "rnsLimbIndex": rns_limb_index,
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                )
                .expect("commitment chunk root");
                let coefficient_vector_hash512 = derive_protocol_hash(
                    "VssCoefficientCommitmentRoot",
                    &serde_json::json!({
                        "fixture": "vss-coefficient-vector-hash",
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "rnsLimbIndex": rns_limb_index,
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                )
                .expect("coefficient vector hash");
                coefficient_commitments.push(serde_json::json!({
                    "objectType": "VssCoefficientCommitment",
                    "objectVersion": 1,
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "commitmentRoot": commitment_root,
                    "commitmentChunkRoot": commitment_chunk_root,
                    "coefficientVectorHash512": coefficient_vector_hash512,
                    "openingVerificationStatus": "pending-private-envelope-opening",
                }));
                coefficient_commitment_material.push(serde_json::json!({
                    "objectType": "VssCoefficientCommitmentMaterial",
                    "objectVersion": 1,
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "commitmentRoot": commitment_root,
                    "commitment": setup_commitment_full_value(&commitment),
                }));
            }
        }

        let mut source_trustee_record = serde_json::json!({
            "objectType": "VssSourceTrusteeCoefficientCommitments",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "sourceTrusteeIdentity": source_trustee_identity,
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "coefficientCommitments": coefficient_commitments,
        });
        source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
            derive_protocol_hash("VssCoefficientCommitmentRoot", &source_trustee_record)
                .expect("source trustee commitment root")
        );
        source_trustee_records.push(source_trustee_record);
    }

    let mut commitment_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRecords": source_trustee_records,
    });
    commitment_set["vssCoefficientCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("VssCoefficientCommitmentRoot", &commitment_set)
            .expect("VSS commitment set root")
    );

    let mut material_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentMaterialSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": commitment_set["vssCoefficientCommitmentRoot"].clone(),
        "materialEncoding": "full-public-setup-commitment-values",
        "participantCount": 10,
        "thresholdDegree": 4,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "materialRecordCount": coefficient_commitment_material.len(),
        "coefficientCommitments": coefficient_commitment_material,
    });
    material_set["vssCoefficientCommitmentMaterialRoot"] = serde_json::json!(
        derive_protocol_hash("VssCoefficientCommitmentMaterialRoot", &material_set)
            .expect("VSS coefficient commitment material root")
    );

    (commitment_set, material_set)
}

#[allow(clippy::too_many_arguments)]
fn streamed_vss_coefficient_commitments_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    derivation_id: &str,
) -> VssMaterialPackageComponents {
    let total_byte_length = vss_material_binary_total_byte_length(ring_degree);
    let chunk_count = total_byte_length.div_ceil(SETUP_TRANSPORT_CHUNK_SIZE_BYTES_FOR_TESTS);
    let transported_material_template = serde_json::json!({
        "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
        "objectVersion": 1,
        "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
        "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES_FOR_TESTS,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
    });
    let setup_context = serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "participantCount": 10,
        "qSetupComplete": 10,
        "qBallotRelease": 10,
        "qFinal": 10,
        "qDec": 4,
    });
    begin_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
        "derivationId": derivation_id,
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "transportedVssCoefficientCommitmentMaterial": transported_material_template,
    }))
    .expect("begin streamed profile-ring VSS material");
    let mut writer =
        StreamingVssMaterialFixtureWriter::new(derivation_id.to_string(), total_byte_length);
    let mut header = Vec::new();
    append_vss_material_binary_header(&mut header, ring_degree);
    writer
        .write_bytes(&header)
        .expect("write streamed VSS material header");

    let mut source_trustee_records = Vec::new();
    for source_trustee_roster_position in 0..10_u64 {
        terminal_phase(&format!(
            "streaming VSS source trustee {source_trustee_roster_position}"
        ));
        let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
        let mut coefficient_commitments = Vec::new();
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..4_u64 {
                let coefficient_message = accepted_vss_coefficient_message_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    rns_prime,
                    ring_degree,
                );
                let coefficient_message_wide = coefficient_message
                    .iter()
                    .map(|coefficient| u128::from(*coefficient))
                    .collect::<Vec<_>>();
                let randomness_by_column = accepted_vss_randomness_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    ring_degree,
                );
                let commitment = compute_setup_commitment_for_tests(
                    public_matrix_seed_hash,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    &coefficient_message_wide,
                    &randomness_by_column,
                    ring_degree,
                )
                .expect("setup commitment");
                let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
                let commitment_chunk_root = derive_protocol_hash(
                    "VssCoefficientCommitmentRoot",
                    &serde_json::json!({
                        "fixture": "vss-coefficient-commitment-chunk-root",
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "rnsLimbIndex": rns_limb_index,
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                )
                .expect("commitment chunk root");
                let coefficient_vector_hash512 = derive_protocol_hash(
                    "VssCoefficientCommitmentRoot",
                    &serde_json::json!({
                        "fixture": "vss-coefficient-vector-hash",
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "rnsLimbIndex": rns_limb_index,
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                )
                .expect("coefficient vector hash");
                coefficient_commitments.push(serde_json::json!({
                    "objectType": "VssCoefficientCommitment",
                    "objectVersion": 1,
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "commitmentRoot": commitment_root,
                    "commitmentChunkRoot": commitment_chunk_root,
                    "coefficientVectorHash512": coefficient_vector_hash512,
                    "openingVerificationStatus": "pending-private-envelope-opening",
                }));
                let mut record_bytes = Vec::new();
                append_vss_material_binary_record(
                    &mut record_bytes,
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    &commitment,
                );
                writer
                    .write_bytes(&record_bytes)
                    .expect("write streamed VSS material record");
            }
        }

        let mut source_trustee_record = serde_json::json!({
            "objectType": "VssSourceTrusteeCoefficientCommitments",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "sourceTrusteeIdentity": source_trustee_identity,
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "coefficientCommitments": coefficient_commitments,
        });
        source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
            derive_protocol_hash("VssCoefficientCommitmentRoot", &source_trustee_record)
                .expect("source trustee commitment root")
        );
        source_trustee_records.push(source_trustee_record);
    }

    let mut commitment_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRecords": source_trustee_records,
    });
    commitment_set["vssCoefficientCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("VssCoefficientCommitmentRoot", &commitment_set)
            .expect("VSS commitment set root")
    );
    let stream_derivation = writer
        .finish(
            &commitment_set["vssCoefficientCommitmentRoot"],
            &commitment_set["sourceTrusteeRecords"],
        )
        .expect("finish streamed profile-ring VSS material");
    let transport = stream_derivation["transport"].clone();
    let transported_vss_coefficient_commitment_material = serde_json::json!({
        "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
        "objectVersion": 1,
        "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
        "chunkSizeBytes": transport["chunkSizeBytes"].clone(),
        "chunkCount": transport["chunkCount"].clone(),
        "totalByteLength": transport["totalByteLength"].clone(),
        "fullObjectHash": transport["fullObjectHash"].clone(),
        "chunkRoot": transport["chunkRoot"].clone(),
        "chunkHashes": transport["chunkHashes"].clone(),
    });

    VssMaterialPackageComponents {
        vss_coefficient_commitments: commitment_set,
        vss_coefficient_commitment_material: stream_derivation["vssCoefficientCommitmentMaterial"]
            .clone(),
        threshold_share_commitments: stream_derivation["thresholdShareCommitments"].clone(),
        transported_vss_coefficient_commitment_material: Some(
            transported_vss_coefficient_commitment_material,
        ),
        verified_vss_coefficient_commitment_material: Some(
            stream_derivation["verifiedVssCoefficientCommitmentMaterial"].clone(),
        ),
    }
}

pub(super) fn accepted_vss_coefficient_message_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    rns_prime: u64,
    ring_degree: usize,
) -> Vec<u64> {
    if shamir_coefficient_index == 0 {
        return (0..ring_degree)
            .map(|coefficient_position| {
                match accepted_vss_secret_coefficient_fixture(
                    source_trustee_roster_position,
                    coefficient_position,
                ) {
                    -1 => rns_prime - 1,
                    0 => 0,
                    1 => 1,
                    _ => unreachable!("secret fixture is centered ternary"),
                }
            })
            .collect();
    }

    (0..ring_degree)
        .map(|coefficient_position| {
            let value = ((source_trustee_roster_position + 1) * 17)
                + ((rns_limb_index as u64 + 1) * 5)
                + ((shamir_coefficient_index + 1) * 3)
                + (coefficient_position as u64 % 11);
            value % rns_prime
        })
        .collect()
}

pub(super) fn accepted_vss_secret_coefficient_fixture(
    source_trustee_roster_position: u64,
    coefficient_position: usize,
) -> i64 {
    match (source_trustee_roster_position as usize + coefficient_position) % 3 {
        0 => -1,
        1 => 0,
        _ => 1,
    }
}

pub(super) fn accepted_vss_randomness_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i128>> {
    (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .map(|randomness_column_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    match (source_trustee_roster_position as usize
                        + rns_limb_index
                        + shamir_coefficient_index as usize
                        + randomness_column_index
                        + coefficient_position)
                        % 3
                    {
                        0 => -1,
                        1 => 0,
                        _ => 1,
                    }
                })
                .collect()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn same_secret_consistency_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    vss_coefficient_commitments: &serde_json::Value,
) -> serde_json::Value {
    let mut statement_records = Vec::new();
    let mut trustee_secret_commitment_roots = Vec::new();
    let same_secret_proof_family_binding_root = derive_protocol_hash(
        "SameSecretProofFamilyBindingRoot",
        &serde_json::json!({
            "objectType": "SameSecretProofFamilyBinding",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "anchorArgument": "one keyless succinct linkage proof per trustee; secret-dependent families bind the anchor root and open the same commitment values",
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share",
            ],
            "genericKeySwitchBindingPolicy": "absent-unless-frozen-schedule-requires-proof-family",
            "targetDecryptionBindingPolicy": "later-target-share-must-bind-threshold-share-commitment",
        }),
    )
    .expect("same-secret proof family binding root");
    for trustee_roster_position in 0..10_u64 {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let source_trustee_record =
            &vss_coefficient_commitments["sourceTrusteeRecords"][trustee_roster_position as usize];
        let vss_source_trustee_commitment_root =
            source_trustee_record["sourceTrusteeCommitmentRoot"]
                .as_str()
                .expect("source trustee commitment root");
        let constant_coefficient_commitment_roots = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(rns_limb_index, rns_prime)| {
                let commitment_root = source_trustee_record["coefficientCommitments"]
                    .as_array()
                    .expect("coefficient commitments")
                    .iter()
                    .find(|coefficient_record| {
                        coefficient_record["rnsLimbIndex"].as_u64() == Some(rns_limb_index as u64)
                            && coefficient_record["shamirCoefficientIndex"].as_u64() == Some(0)
                    })
                    .and_then(|coefficient_record| coefficient_record["commitmentRoot"].as_str())
                    .expect("constant commitment root");
                serde_json::json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": 0,
                    "commitmentRoot": commitment_root,
                })
            })
            .collect::<Vec<_>>();
        let trustee_secret_commitment_payload = serde_json::json!({
            "objectType": "TrusteeSecretCommitment",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "vssSourceTrusteeCommitmentRoot": vss_source_trustee_commitment_root,
            "secretCommitmentSource": "vss-constant-coefficient-commitments",
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "constantCoefficientCommitmentRoots": constant_coefficient_commitment_roots,
        });
        let trustee_secret_commitment_root = derive_protocol_hash(
            "TrusteeSecretCommitmentRoot",
            &trustee_secret_commitment_payload,
        )
        .expect("trustee secret commitment root");
        let mut statement_record = serde_json::json!({
            "objectType": "SameSecretConsistencyStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "proofVerificationStatus": "anchor-proof-verification-pending",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "vssSourceTrusteeCommitmentRoot": vss_source_trustee_commitment_root,
            "constantCoefficientCommitmentRoots": trustee_secret_commitment_payload["constantCoefficientCommitmentRoots"].clone(),
            "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share",
            ],
            "genericKeySwitchBindingPolicy": "absent-unless-frozen-schedule-requires-proof-family",
            "targetDecryptionBindingPolicy": "later-target-share-must-bind-threshold-share-commitment",
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        });
        statement_record["sameSecretStatementRoot"] = serde_json::json!(
            derive_protocol_hash("SameSecretConsistencyRoot", &statement_record)
                .expect("same-secret statement root")
        );
        trustee_secret_commitment_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        }));
        statement_records.push(statement_record);
    }
    let mut same_secret_consistency = serde_json::json!({
        "objectType": "SameSecretConsistencyStatementSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "same-secret-linkage-anchor",
        "proofVerificationStatus": "anchor-proof-verification-pending",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": 4,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitments["vssCoefficientCommitmentRoot"],
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "trusteeSecretCommitmentRoots": trustee_secret_commitment_roots,
        "statementRecords": statement_records,
    });
    same_secret_consistency["sameSecretConsistencyRoot"] = serde_json::json!(
        derive_protocol_hash("SameSecretConsistencyRoot", &same_secret_consistency)
            .expect("same-secret consistency root")
    );

    same_secret_consistency
}

pub(super) fn same_secret_proof_bearing_collective_setup_package() -> serde_json::Value {
    SAME_SECRET_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_same_secret_proof_bearing_collective_setup_package)
        .clone()
}

fn build_same_secret_proof_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = minimal_collective_setup_package();
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

pub(super) fn public_key_share_succinct_proof_bearing_collective_setup_package() -> serde_json::Value {
    PUBLIC_KEY_SHARE_SUCCINCT_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_public_key_share_succinct_proof_bearing_collective_setup_package)
        .clone()
}

fn build_public_key_share_succinct_proof_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = same_secret_proof_bearing_collective_setup_package();
    replace_public_key_share_hashes_with_material_hashes(&mut package);
    package["publicKeyShareMaterial"] = public_key_share_material_object(&package);
    package["publicKeyShareSuccinctProofs"] = public_key_share_succinct_proofs_object(&package);
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

pub(super) fn collective_public_key_bearing_collective_setup_package() -> serde_json::Value {
    COLLECTIVE_PUBLIC_KEY_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_collective_public_key_bearing_collective_setup_package)
        .clone()
}

fn build_collective_public_key_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["collectivePublicKey"] = collective_public_key_object(&package);
    package["collectivePublicKeyRoot"] =
        package["collectivePublicKey"]["collectivePublicKeyRoot"].clone();
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

pub(super) fn evaluation_key_proof_container_bearing_collective_setup_package() -> serde_json::Value
{
    evaluation_key_proof_container_bearing_collective_setup_package_ref().clone()
}

pub(super) fn evaluation_key_proof_container_bearing_collective_setup_package_ref()
-> &'static serde_json::Value {
    EVALUATION_KEY_PROOF_CONTAINER_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_evaluation_key_proof_container_bearing_collective_setup_package)
}

fn build_evaluation_key_proof_container_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = collective_public_key_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"] = relinearization_key_share_rounds_object(&package);
    package["galoisKeyShareBatches"] = galois_key_share_batches_object(&package);
    package["trusteeEvaluationKeyProofs"] = trustee_evaluation_key_proofs_object(&package);
    package["evaluationKeys"] = public_evaluation_key_set_object(&package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

#[allow(clippy::too_many_arguments)]
fn public_key_shares_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    common_randomness: &serde_json::Value,
    same_secret_consistency: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let public_key_crp_root =
        common_randomness["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"]
            .as_str()
            .expect("public-key CRP root");
    let public_a_polynomial_root =
        common_randomness["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"]
            .as_str()
            .expect("public a root");
    let statement_records = same_secret_consistency["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let mut share_records = Vec::new();
    let mut public_key_share_roots = Vec::new();
    for trustee_roster_position in 0..10_u64 {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let same_secret_statement = &statement_records[trustee_roster_position as usize];
        let share_coefficient_hashes = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(rns_limb_index, rns_prime)| {
                serde_json::json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "component": "b_i",
                    "coefficientVectorHash512": derive_protocol_hash(
                        "PublicKeyShareRoot",
                        &serde_json::json!({
                            "fixture": "public-key-share-coefficient-vector",
                            "trusteeRosterPosition": trustee_roster_position,
                            "rnsLimbIndex": rns_limb_index,
                        }),
                    )
                    .expect("public-key share coefficient hash"),
                })
            })
            .collect::<Vec<_>>();
        let mut share_record = serde_json::json!({
            "objectType": "PublicKeyShare",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicKeyCrpRoot": public_key_crp_root,
            "publicAPolynomialRoot": public_a_polynomial_root,
            "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
            "shareComponent": "component-zero-b_i",
            "rnsLimbCount": DATA_PRIMES.len(),
            "shareCoefficientVectorHash512ByLimb": share_coefficient_hashes,
            "proofBindingStatus": "public-key-share-proof-required",
        });
        share_record["publicKeyShareRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareRoot", &share_record)
                .expect("public-key share root")
        );
        public_key_share_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
        }));
        share_records.push(share_record);
    }
    let mut share_set = serde_json::json!({
        "objectType": "PublicKeyShareSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofBindingStatus": "public-key-share-proof-required",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_key_crp_root,
        "publicAPolynomialRoot": public_a_polynomial_root,
        "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
        "publicKeyShareRoots": public_key_share_roots,
        "shareRecords": share_records,
    });
    share_set["publicKeyShareSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareRoot", &share_set).expect("public-key share set root")
    );

    share_set
}

#[allow(clippy::too_many_arguments)]
fn public_key_share_proofs_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    common_randomness: &serde_json::Value,
    same_secret_consistency: &serde_json::Value,
    public_key_shares: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let public_key_crp_root =
        common_randomness["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"]
            .as_str()
            .expect("public-key CRP root");
    let public_a_polynomial_root =
        common_randomness["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"]
            .as_str()
            .expect("public a root");
    let statement_records = same_secret_consistency["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let share_records = public_key_shares["shareRecords"]
        .as_array()
        .expect("public-key share records");
    let mut proof_records = Vec::new();
    let mut public_key_share_proof_roots = Vec::new();
    for trustee_roster_position in 0..10_u64 {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let same_secret_statement = &statement_records[trustee_roster_position as usize];
        let share_record = &share_records[trustee_roster_position as usize];
        let mut proof_record = serde_json::json!({
            "objectType": "PublicKeyShareProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "public-key-share",
            "proofVerificationStatus": "lnp-proof-verification-pending",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicKeyCrpRoot": public_key_crp_root,
            "publicAPolynomialRoot": public_a_polynomial_root,
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
            "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
            "rnsLimbCount": DATA_PRIMES.len(),
            "noWrapRelation": "PKShare_i,l - p*e_i,l + a_l*s_i + q_l*v_i,l = 0 over lifted integers",
            "errorSupport": "checked-by-public-key-share-lnp-proof-set",
            "carryWitnessStatus": "checked-by-public-key-share-lnp-proof-set",
            "proofBytesStatus": "supplied-by-public-key-share-lnp-proof-set",
        });
        proof_record["publicKeyShareProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", &proof_record)
                .expect("public-key share proof root")
        );
        public_key_share_proof_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareProofRoot": proof_record["publicKeyShareProofRoot"],
        }));
        proof_records.push(proof_record);
    }
    let mut proof_set = serde_json::json!({
        "objectType": "PublicKeyShareProofSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofVerificationStatus": "lnp-proof-verification-pending",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_key_crp_root,
        "publicAPolynomialRoot": public_a_polynomial_root,
        "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
        "publicKeyShareSetRoot": public_key_shares["publicKeyShareSetRoot"],
        "publicKeyShareProofRoots": public_key_share_proof_roots,
        "proofRecords": proof_records,
    });
    proof_set["publicKeyShareProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareProofRoot", &proof_set)
            .expect("public-key share proof set root")
    );

    proof_set
}

#[allow(clippy::too_many_arguments)]
fn evaluator_key_schedule_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    profile: &serde_json::Value,
    common_randomness: &serde_json::Value,
    same_secret_consistency: &serde_json::Value,
    public_key_shares: &serde_json::Value,
    public_key_share_proofs: &serde_json::Value,
) -> serde_json::Value {
    let public_derivations = &common_randomness["publicDerivations"];
    let crp_roots = &public_derivations["crpRoots"];
    let schedule_profile = &profile["evaluatorKeyScheduleProfile"];
    let mut schedule = serde_json::json!({
        "objectType": "EvaluatorKeySchedule",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "publicMatrixSeedHash": common_randomness["publicMatrixSeedHash"],
        "relinearizationCrpRoot": crp_roots["relinearizationCrpRoot"],
        "galoisKeyCrpRoot": crp_roots["galoisKeyCrpRoot"],
        "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
        "publicKeyShareSetRoot": public_key_shares["publicKeyShareSetRoot"],
        "publicKeyShareProofSetRoot": public_key_share_proofs["publicKeyShareProofSetRoot"],
        "relinearizationLevelSchedule": schedule_profile["relinearizationLevelSchedule"],
        "requiredGaloisKeySchedule": schedule_profile["requiredGaloisKeySchedule"],
        "requiredGaloisSetHash": schedule_profile["requiredGaloisSetHash"],
        "genericKeySwitchPolicy": "refused-unless-explicitly-required",
        "genericKeySwitchProofStatus": "not-required-for-first-profile",
        "scheduleBindingStatus": "relinearization-and-galois-proof-verifiers-bound-by-accepted-setup-proof-accounting",
    });
    schedule["evaluatorKeyScheduleRoot"] = serde_json::json!(
        derive_protocol_hash("EvaluatorKeyScheduleRoot", &schedule)
            .expect("evaluator-key schedule root")
    );

    schedule
}

#[allow(clippy::too_many_arguments)]
fn private_vss_envelope_commitments_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    common_randomness: &serde_json::Value,
    vss_coefficient_commitments: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let vss_coefficient_commitment_root =
        vss_coefficient_commitments["vssCoefficientCommitmentRoot"]
            .as_str()
            .expect("VSS coefficient commitment root");
    let phase_order_hash = derive_protocol_hash(
        "CollectiveBgvSetupPhaseOrderHash",
        &serde_json::json!([
            {"phaseId": "rosterFreeze", "phaseNumber": 1},
            {"phaseId": "setupIntent", "phaseNumber": 2},
            {"phaseId": "commonRandomnessCommit", "phaseNumber": 3},
            {"phaseId": "commonRandomnessReveal", "phaseNumber": 4},
            {"phaseId": "vssCoefficientCommitments", "phaseNumber": 5},
            {"phaseId": "privateVssEnvelopeDelivery", "phaseNumber": 6},
            {"phaseId": "recipientVssVerification", "phaseNumber": 7},
            {"phaseId": "vssAcceptanceOrComplaint", "phaseNumber": 8},
            {"phaseId": "publicKeyShareProofs", "phaseNumber": 9},
            {"phaseId": "relinearizationRoundOne", "phaseNumber": 10},
            {"phaseId": "relinearizationRoundTwo", "phaseNumber": 11},
            {"phaseId": "galoisKeyShareBatches", "phaseNumber": 12},
            {"phaseId": "trusteeEvaluationKeyProofs", "phaseNumber": 13},
            {"phaseId": "setupPackageAssembly", "phaseNumber": 14},
            {"phaseId": "setupPackageVerification", "phaseNumber": 15},
        ]),
    )
    .expect("phase order hash");
    let envelope_references = (0..10_u64)
        .flat_map(|source_trustee_roster_position| {
            let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
            let source_trustee_commitment_root = vss_coefficient_commitments["sourceTrusteeRecords"]
                [source_trustee_roster_position as usize]["sourceTrusteeCommitmentRoot"]
                .as_str()
                .expect("source trustee commitment root")
                .to_string();
            let phase_order_hash = phase_order_hash.clone();
            (0..10_u64).map(move |recipient_roster_position| {
                let recipient_identity = format!("trustee-{recipient_roster_position}");
                let envelope_sequence_number = source_trustee_roster_position * 10 + recipient_roster_position;
                let private_envelope_hash = derive_protocol_hash(
                    "PrivateVssShareEnvelopeHash",
                    &serde_json::json!({
                        "fixture": "private-vss-share-envelope",
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "recipientRosterPosition": recipient_roster_position,
                    }),
                )
                .expect("private envelope hash");
                let local_verification_root = derive_protocol_hash(
                    "PrivateVssLocalVerificationRoot",
                    &serde_json::json!({
                        "fixture": "recipient-vss-local-verification",
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "recipientRosterPosition": recipient_roster_position,
                        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                        "privateEnvelopeHash": private_envelope_hash.as_str(),
                    }),
                )
                .expect("local verification root");
                let private_envelope_aad = serde_json::json!({
                    "objectType": "PrivateVssEnvelopeAad",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "mailboxEncryptionProfileId": "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1",
                    "privateEnvelopeObjectType": "PrivateVssShareEnvelope",
                    "ciphertextContentType": "private-vss-share-envelope",
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "phaseOrderHash": phase_order_hash.as_str(),
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity.as_str(),
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "envelopeSequenceNumber": envelope_sequence_number,
                    "deliveryPhaseNumber": 6,
                    "verificationPhaseNumber": 7,
                    "recipientVerificationRequirement": "recipient-verifies-private-vss-opening-before-acceptance",
                });
                let private_envelope_aad_hash = derive_protocol_hash(
                    "PrivateVssEnvelopeAadHash",
                    &private_envelope_aad,
                )
                .expect("private envelope AAD hash");
                let recipient_mailbox_public_key_hash =
                    private_vss_mailbox_public_key_hash(recipient_roster_position);
                let recipient_mailbox_public_key_bytes_hash =
                    private_vss_mailbox_public_key_bytes_hash(recipient_roster_position);
                let kem_ciphertext_bytes = vec![0xa5_u8; 1088];
                let kem_ciphertext_hash = hash512_hex(
                    "sealed-lattice-private-vss-mailbox/ml-kem-768-ciphertext-v1",
                    &[&kem_ciphertext_bytes],
                );
                let ciphertext_bytes = vec![0xc3_u8; 96];
                let ciphertext_bytes_hash = hash512_hex(
                    "sealed-lattice-private-vss-mailbox/aes-256-gcm-ciphertext-v1",
                    &[&ciphertext_bytes],
                );
                let mut encrypted_envelope = serde_json::json!({
                    "objectType": "EncryptedPrivateVssShareEnvelope",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "mailboxEncryptionProfileId": "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1",
                    "ciphertextContentType": "private-vss-share-envelope",
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity.as_str(),
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "envelopeSequenceNumber": envelope_sequence_number,
                    "deliveryPhaseNumber": 6,
                    "verificationPhaseNumber": 7,
                    "privateEnvelopeHash": private_envelope_hash.as_str(),
                    "privateEnvelopeAad": private_envelope_aad.clone(),
                    "privateEnvelopeAadHash": private_envelope_aad_hash.as_str(),
                    "recipientMailboxPublicKeyHash": recipient_mailbox_public_key_hash.as_str(),
                    "recipientMailboxPublicKeyBytesHash": recipient_mailbox_public_key_bytes_hash.as_str(),
                    "kemCiphertextBytesHex": "a5".repeat(1088),
                    "kemCiphertextHash": kem_ciphertext_hash.as_str(),
                    "aeadNonceHex": "5a".repeat(12),
                    "ciphertextBytesHex": "c3".repeat(96),
                    "ciphertextBytesHash": ciphertext_bytes_hash.as_str(),
                    "ciphertextByteLength": 96,
                    "plaintextByteLength": 512,
                    "aeadTagLength": 128,
                });
                encrypted_envelope["encryptedEnvelopeHash"] = serde_json::json!(
                    derive_protocol_hash("PrivateVssEncryptedEnvelopeHash", &encrypted_envelope)
                        .expect("encrypted envelope hash")
                );
                let encrypted_envelope_hash = encrypted_envelope["encryptedEnvelopeHash"].clone();
                let mut envelope_reference = serde_json::json!({
                    "objectType": "PrivateVssEnvelopeCommitment",
                    "objectVersion": 1,
                    "mailboxEncryptionProfileId": "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1",
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity.as_str(),
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "envelopeSequenceNumber": envelope_sequence_number,
                    "deliveryPhaseNumber": 6,
                    "verificationPhaseNumber": 7,
                    "privateEnvelopeHash": private_envelope_hash,
                    "encryptedEnvelopeHash": encrypted_envelope_hash,
                    "privateEnvelopeAad": private_envelope_aad,
                    "privateEnvelopeAadHash": private_envelope_aad_hash,
                    "encryptedEnvelope": encrypted_envelope,
                    "recipientMailboxPublicKeyHash": recipient_mailbox_public_key_hash,
                    "localVerificationRoot": local_verification_root,
                    "openingVerificationStatus": "accepted-local-private-vss-opening",
                });
                envelope_reference["privateEnvelopeCommitmentRoot"] = serde_json::json!(
                    derive_protocol_hash(
                        "PrivateVssEnvelopeCommitmentRoot",
                        &private_vss_envelope_commitment_record_root_input(&envelope_reference)
                    )
                    .expect("private envelope commitment record root")
                );

                envelope_reference
            })
        })
        .collect::<Vec<_>>();
    let mut commitment_set = serde_json::json!({
        "objectType": "PrivateVssEnvelopeCommitmentSet",
        "objectVersion": 1,
        "mailboxEncryptionProfileId": "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "participantCount": 10,
        "envelopeCount": 100,
        "deliveryPhaseNumber": 6,
        "verificationPhaseNumber": 7,
        "envelopeReferences": envelope_references,
    });
    commitment_set["privateVssEnvelopeCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash(
            "PrivateVssEnvelopeCommitmentRoot",
            &private_vss_envelope_commitment_set_root_input(&commitment_set)
        )
        .expect("private VSS envelope commitment root")
    );

    commitment_set
}

#[allow(clippy::too_many_arguments)]
fn vss_share_acceptances_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    private_vss_envelope_commitments: &serde_json::Value,
    vss_coefficient_commitments: &serde_json::Value,
) -> serde_json::Value {
    let private_vss_envelope_commitment_root =
        private_vss_envelope_commitments["privateVssEnvelopeCommitmentRoot"]
            .as_str()
            .expect("private VSS envelope commitment root");
    let envelope_references = private_vss_envelope_commitments["envelopeReferences"]
        .as_array()
        .expect("private VSS envelope references");
    let acceptance_records = (0..10_u64)
        .flat_map(|source_trustee_roster_position| {
            let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
            let source_trustee_commitment_root = vss_coefficient_commitments["sourceTrusteeRecords"]
                [source_trustee_roster_position as usize]["sourceTrusteeCommitmentRoot"]
                .as_str()
                .expect("source trustee commitment root")
                .to_string();
            (0..10_u64).map(move |recipient_roster_position| {
                let recipient_identity = format!("trustee-{recipient_roster_position}");
                let signature_seed_label = format!("{recipient_identity}-accepts-{source_trustee_identity}");
                let signing_public_key_hash =
                    create_ml_dsa_public_key_hash_fixture(&signature_seed_label)
                        .expect("signature key fixture");
                let envelope_sequence_number =
                    (source_trustee_roster_position * 10 + recipient_roster_position) as usize;
                let envelope_reference = &envelope_references[envelope_sequence_number];
                let private_envelope_hash = envelope_reference["privateEnvelopeHash"]
                    .as_str()
                    .expect("private envelope hash");
                let local_verification_root = envelope_reference["localVerificationRoot"]
                    .as_str()
                    .expect("local verification root");
                let acceptance_payload = serde_json::json!({
                    "objectType": "VssShareAcceptance",
                    "objectVersion": 1,
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "sourceTrusteeIdentity": source_trustee_identity,
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity,
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
                    "privateEnvelopeHash": private_envelope_hash,
                    "localVerificationRoot": local_verification_root,
                    "verificationStatus": "accepted",
                    "recoveryEpoch": 0,
                    "deviceEpoch": 0,
                    "signingPublicKeyHash": signing_public_key_hash,
                });
                let acceptance_root =
                    derive_protocol_hash("VssShareAcceptanceRoot", &acceptance_payload)
                        .expect("acceptance root");
                let acceptance_byte_length =
                    u64::try_from(canonical_json(&acceptance_payload).expect("acceptance payload").len())
                        .expect("acceptance payload length");
                let acceptance_context_hash = derive_protocol_hash(
                    "VssShareAcceptanceRoot",
                    &serde_json::json!({
                        "purpose": "vss-share-acceptance-signature-context",
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "rosterHash": roster_hash,
                        "setupProfileHash": setup_profile_hash,
                        "qShareHash": q_share_hash,
                        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                        "commitmentProfileHash": commitment_profile_hash,
                        "setupEpoch": setup_epoch,
                        "sourceTrusteeIdentity": source_trustee_identity,
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "recipientIdentity": recipient_identity,
                        "recipientRosterPosition": recipient_roster_position,
                        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
                        "privateEnvelopeHash": private_envelope_hash,
                        "localVerificationRoot": local_verification_root,
                        "acceptanceRoot": acceptance_root,
                    }),
                )
                .expect("acceptance context hash");
                let signature_fixture = create_protocol_signature_fixture(
                    &signature_seed_label,
                    serde_json::json!({
                        "objectType": "VssShareAcceptance",
                        "objectVersion": 1,
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "boardHeadHash": null,
                        "objectRoot": acceptance_root,
                        "chunkMerkleRoot": null,
                        "byteLength": acceptance_byte_length,
                        "signerRole": "Trustee",
                        "signerIdentity": recipient_identity,
                        "recoveryEpoch": 0,
                        "deviceEpoch": 0,
                        "contextHash": acceptance_context_hash,
                    }),
                )
                .expect("acceptance signature fixture");
                let signature_envelope = signature_fixture.envelope;
                let signature_envelope_hash = signature_envelope["signatureHash"].clone();
                let mut acceptance_record = acceptance_payload;
                acceptance_record["acceptanceRoot"] = serde_json::json!(acceptance_root);
                acceptance_record["acceptanceByteLength"] =
                    serde_json::json!(acceptance_byte_length);
                acceptance_record["acceptanceContextHash"] =
                    serde_json::json!(acceptance_context_hash);
                acceptance_record["signatureEnvelopeHash"] = signature_envelope_hash;
                acceptance_record["signatureEnvelope"] = signature_envelope;

                acceptance_record
            })
        })
        .collect::<Vec<_>>();
    let mut acceptance_set = serde_json::json!({
        "objectType": "VssShareAcceptanceSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "acceptanceRecords": acceptance_records,
    });
    acceptance_set["vssShareAcceptanceRoot"] = serde_json::json!(
        derive_protocol_hash("VssShareAcceptanceRoot", &acceptance_set)
            .expect("VSS share acceptance set root")
    );

    acceptance_set
}

pub(super) fn vss_complaints_object(
    setup_context: &serde_json::Value,
    private_vss_envelope_commitments: &serde_json::Value,
    vss_coefficient_commitments: &serde_json::Value,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
) -> serde_json::Value {
    let private_vss_envelope_commitment_root =
        private_vss_envelope_commitments["privateVssEnvelopeCommitmentRoot"]
            .as_str()
            .expect("private VSS envelope commitment root");
    let ceremony_id = setup_context["ceremonyId"].as_str().expect("ceremony id");
    let manifest_hash = setup_context["manifestHash"]
        .as_str()
        .expect("manifest hash");
    let roster_hash = setup_context["rosterHash"].as_str().expect("roster hash");
    let setup_profile_hash = setup_context["setupProfileHash"]
        .as_str()
        .expect("setup profile hash");
    let q_share_hash = setup_context["qShareHash"].as_str().expect("Q_share hash");
    let carry_aware_vss_relation_profile_hash =
        setup_context["carryAwareVssShareRelationProfileHash"]
            .as_str()
            .expect("carry-aware VSS relation profile hash");
    let commitment_profile_hash = setup_context["commitmentProfileHash"]
        .as_str()
        .expect("commitment profile hash");
    let setup_epoch = setup_context["setupEpoch"].as_str().expect("setup epoch");
    let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
    let recipient_identity = format!("trustee-{recipient_roster_position}");
    let source_trustee_commitment_root = vss_coefficient_commitments["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]["sourceTrusteeCommitmentRoot"]
        .as_str()
        .expect("source trustee commitment root");
    let envelope_sequence_number =
        (source_trustee_roster_position * 10 + recipient_roster_position) as usize;
    let private_envelope_hash = private_vss_envelope_commitments["envelopeReferences"]
        [envelope_sequence_number]["privateEnvelopeHash"]
        .as_str()
        .expect("private envelope hash");
    let complaint_reason_code = "privateVssEnvelopeInvalidOpening";
    let complaint_evidence_root = derive_protocol_hash(
        "PrivateVssLocalVerificationRoot",
        &serde_json::json!({
            "fixture": "recipient-vss-complaint-evidence",
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "recipientRosterPosition": recipient_roster_position,
            "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
            "privateEnvelopeHash": private_envelope_hash,
            "complaintReasonCode": complaint_reason_code,
        }),
    )
    .expect("complaint evidence root");
    let signature_seed_label =
        format!("{recipient_identity}-complains-about-{source_trustee_identity}");
    let signing_public_key_hash = create_ml_dsa_public_key_hash_fixture(&signature_seed_label)
        .expect("signature key fixture");
    let complaint_payload = serde_json::json!({
        "objectType": "VssShareComplaint",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "sourceTrusteeIdentity": source_trustee_identity.as_str(),
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity.as_str(),
        "recipientRosterPosition": recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "privateEnvelopeHash": private_envelope_hash,
        "complaintEvidenceRoot": complaint_evidence_root.as_str(),
        "complaintReasonCode": complaint_reason_code,
        "complaintStatus": "valid-complaint-aborts-setup",
        "recoveryEpoch": 0,
        "deviceEpoch": 0,
        "signingPublicKeyHash": signing_public_key_hash,
    });
    let complaint_root =
        derive_protocol_hash("VssComplaintRoot", &complaint_payload).expect("complaint root");
    let complaint_byte_length = u64::try_from(
        canonical_json(&complaint_payload)
            .expect("complaint payload")
            .len(),
    )
    .expect("complaint payload length");
    let complaint_context_hash = derive_protocol_hash(
        "VssComplaintRoot",
        &serde_json::json!({
            "purpose": "vss-share-complaint-signature-context",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "sourceTrusteeIdentity": source_trustee_identity.as_str(),
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "recipientIdentity": recipient_identity.as_str(),
            "recipientRosterPosition": recipient_roster_position,
            "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
            "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
            "privateEnvelopeHash": private_envelope_hash,
            "complaintEvidenceRoot": complaint_evidence_root.as_str(),
            "complaintReasonCode": complaint_reason_code,
            "complaintRoot": complaint_root.as_str(),
        }),
    )
    .expect("complaint context hash");
    let signature_fixture = create_protocol_signature_fixture(
        &signature_seed_label,
        serde_json::json!({
            "objectType": "VssShareComplaint",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "boardHeadHash": null,
            "objectRoot": complaint_root.as_str(),
            "chunkMerkleRoot": null,
            "byteLength": complaint_byte_length,
            "signerRole": "Trustee",
            "signerIdentity": recipient_identity.as_str(),
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "contextHash": complaint_context_hash,
        }),
    )
    .expect("complaint signature fixture");
    let signature_envelope = signature_fixture.envelope;
    let signature_envelope_hash = signature_envelope["signatureHash"].clone();
    let mut complaint_record = complaint_payload;
    complaint_record["complaintRoot"] = serde_json::json!(complaint_root);
    complaint_record["complaintByteLength"] = serde_json::json!(complaint_byte_length);
    complaint_record["complaintContextHash"] = serde_json::json!(complaint_context_hash);
    complaint_record["signatureEnvelopeHash"] = signature_envelope_hash;
    complaint_record["signatureEnvelope"] = signature_envelope;

    let mut complaint_set = serde_json::json!({
        "objectType": "VssComplaintSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "complaintRecords": [complaint_record],
    });
    complaint_set["vssComplaintRoot"] = serde_json::json!(
        derive_protocol_hash("VssComplaintRoot", &complaint_set).expect("VSS complaint set root")
    );

    complaint_set
}

fn common_randomness_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    setup_epoch: &str,
) -> serde_json::Value {
    let mut commit_records = Vec::new();
    let mut reveal_records = Vec::new();
    let mut ordered_reveal_hashes = Vec::new();
    for roster_position in 0..10 {
        let trustee_identity = format!("trustee-{roster_position}");
        let reveal_source_hash = derive_protocol_hash(
            "CommonRandomnessRevealHash",
            &serde_json::json!({
                "fixture": "common-randomness-reveal",
                "rosterPosition": roster_position,
            }),
        )
        .expect("reveal source hash");
        let reveal_hex = reveal_source_hash[..64].to_string();
        let signature_envelope_hash = derive_protocol_hash(
            "ProtocolSignatureEnvelopeHash",
            &serde_json::json!({
                "fixture": "common-randomness-signature",
                "rosterPosition": roster_position,
            }),
        )
        .expect("signature envelope hash");
        let mut reveal_record = serde_json::json!({
            "objectType": "CommonRandomnessReveal",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "setupEpoch": setup_epoch,
            "signerRole": "Trustee",
            "trusteeIdentity": trustee_identity.clone(),
            "rosterPosition": roster_position,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "revealHex": reveal_hex,
            "signatureEnvelopeHash": signature_envelope_hash.clone(),
        });
        let reveal_hash = derive_protocol_hash("CommonRandomnessRevealHash", &reveal_record)
            .expect("reveal hash");
        reveal_record["revealHash"] = serde_json::json!(reveal_hash.clone());
        ordered_reveal_hashes.push(reveal_hash.clone());
        reveal_records.push(reveal_record);

        let mut commit_record = serde_json::json!({
            "objectType": "CommonRandomnessCommit",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "setupEpoch": setup_epoch,
            "signerRole": "Trustee",
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "revealHash": reveal_hash,
            "signatureEnvelopeHash": signature_envelope_hash,
        });
        let commit_hash = derive_protocol_hash("CommonRandomnessCommitHash", &commit_record)
            .expect("commit hash");
        commit_record["commitHash"] = serde_json::json!(commit_hash);
        commit_records.push(commit_record);
    }

    let public_matrix_seed_hash = derive_protocol_hash(
        "SetupPublicMatrixSeedHash",
        &serde_json::json!({
            "setupProfileId": "CollectiveBgvSetup-v1",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "setupEpoch": setup_epoch,
            "orderedRevealHashes": ordered_reveal_hashes,
        }),
    )
    .expect("public matrix seed hash");
    let public_derivations =
        derive_collective_bgv_setup_public_derivations_from_request(&serde_json::json!({
            "publicMatrixSeedHash": public_matrix_seed_hash,
        }))
        .expect("public derivations");
    assert_eq!(
        public_derivations["publicMatrices"]["commitmentMatrix"]["matrixKind"],
        "commitment"
    );
    assert_eq!(
        public_derivations["publicMatrices"]["setupProofMatrix"]["matrixKind"],
        "setupProof"
    );
    assert_eq!(
        public_derivations["publicMatrices"]["setupProofMatrix"]["profileStatus"],
        "setup-proof-profile-bound"
    );
    assert!(
        public_derivations["publicMatrices"]["setupProofMatrix"]["setupProofProfileHash"]
            .as_str()
            .is_some()
    );
    assert!(
        public_derivations["publicMatrices"]["setupProofMatrix"]["challengeDomainHash"]
            .as_str()
            .is_some()
    );
    assert!(
        public_derivations["publicMatrices"]["commitmentMatrix"]["sampledEntries"]
            .as_array()
            .expect("commitment matrix sampled entries")
            .len()
            > 1
    );
    assert!(
        public_derivations["publicMatrices"]["commitmentMatrix"]["sampledEntries"][0]
            ["coefficientValue"]
            .as_u64()
            .is_some()
    );
    assert!(
        public_derivations["publicMatrices"]["setupProofMatrix"]["sampledEntries"][0]
            ["coefficientValue"]
            .as_u64()
            .is_some()
    );
    let mut common_randomness = serde_json::json!({
        "objectType": "SetupCommonRandomness",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "setupEpoch": setup_epoch,
        "commitRecords": commit_records,
        "revealRecords": reveal_records,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicDerivations": public_derivations,
    });
    let common_randomness_root =
        derive_protocol_hash("SetupCommonRandomnessRoot", &common_randomness)
            .expect("common randomness root");
    common_randomness["commonRandomnessRoot"] = serde_json::json!(common_randomness_root);

    common_randomness
}
