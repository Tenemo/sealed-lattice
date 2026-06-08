use super::super::accepted_setup::{
    PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE,
    PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
    PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING, accepted_hashes_from_package,
    accepted_he_security_certificate_hash, accepted_he_security_certificate_value,
    accepted_setup_collective_public_key_from_package,
    accepted_setup_public_galois_keys_from_transport,
    accepted_setup_public_relinearization_keys_from_transport,
    active_static_setup_theorem_certificate_hash, active_static_setup_theorem_certificate_value,
    encode_public_evaluation_key_material_manifest, public_evaluation_key_material_manifest,
    public_evaluation_key_material_reference_root, public_evaluation_key_material_transport_hashes,
    setup_key_correctness_certificate_hash, setup_key_correctness_certificate_value,
    setup_proof_accounting_certificate_hash, setup_proof_accounting_certificate_value,
    verify_profile_ring_material,
};
use super::super::evaluation_key_share_proof::{
    EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE,
    EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
    EvaluationKeyShareLnpProofGenerationInput, EvaluationKeyShareLnpProofVerificationInput,
    EvaluationKeyShareLnpProofWitness, EvaluationKeyShareProofFamily,
    GALOIS_KEY_SHARE_LNP_PROOF_MODEL_STATUS, GALOIS_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
    KeySwitchComponentBFixtureInput, RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
    RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
    automorphism_i128_for_evaluation_key_fixture, encode_evaluation_key_share_component_vectors,
    evaluation_key_share_component_material_reference_root,
    evaluation_key_share_component_material_transport_hashes,
    evaluation_key_share_component_vector_hash, evaluation_key_share_component_vector_root,
    evaluation_key_share_lnp_relation_proof_bytes_hash,
    generate_evaluation_key_share_lnp_proof_from_request,
    generate_evaluation_key_share_lnp_relation_proof,
    key_switch_component_b_for_evaluation_key_fixture,
    negacyclic_i128_product_for_evaluation_key_fixture,
    verify_evaluation_key_share_lnp_relation_proof,
};
use super::super::public_key_share_proof::{
    PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS, PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
    PublicKeyShareLnpProofGenerationInput, PublicKeyShareLnpProofVerificationInput,
    PublicKeyShareLnpProofWitness, generate_public_key_share_lnp_relation_proof,
    public_key_share_coefficient_vector_hash, public_key_share_lnp_relation_proof_bytes_hash,
    verify_public_key_share_lnp_relation_proof,
};
use super::super::same_secret_proof::{
    SAME_SECRET_LNP_PROOF_MODEL_STATUS, SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
    SameSecretLnpProofWitness, generate_same_secret_lnp_relation_proof,
    same_secret_lnp_relation_proof_bytes_hash, verify_same_secret_lnp_relation_proof,
};
use super::super::sampling::dense_public_residues;
use super::super::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    SetupProofMaterialReferenceInput, setup_proof_material_reference_root,
    setup_proof_material_transport_hashes, setup_proof_record_binding_value,
};
use super::*;
use crate::bgv::coefficient_codec::{coefficient_vector_from_le_hex, coefficient_vector_le_hex};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::canonical_json;
use crate::hashing::{hash512_hex, to_hex};
use crate::protocol_signatures::{
    create_ml_dsa_public_key_hash_fixture, create_protocol_signature_fixture,
};
use crate::transcript_core::decode_hex;
use num_bigint::BigUint;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Instant;

static MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<serde_json::Value> = OnceLock::new();
static SAME_SECRET_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<serde_json::Value> =
    OnceLock::new();
static PUBLIC_KEY_SHARE_LNP_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    serde_json::Value,
> = OnceLock::new();
static COLLECTIVE_PUBLIC_KEY_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<serde_json::Value> =
    OnceLock::new();
static EVALUATION_KEY_PROOF_CONTAINER_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    serde_json::Value,
> = OnceLock::new();

struct AcceptedSetupTestTiming {
    started_at: Instant,
    test_name: &'static str,
}

impl Drop for AcceptedSetupTestTiming {
    fn drop(&mut self) {
        let duration = self.started_at.elapsed();
        println!(
            concat!(
                "sealed-lattice-rust-test-timing ",
                "{{\"suite\":\"bgv::setup::tests::accepted_setup\",",
                "\"test\":\"{}\",",
                "\"durationMilliseconds\":{},",
                "\"durationMicroseconds\":{}}}"
            ),
            self.test_name,
            duration.as_millis(),
            duration.as_micros()
        );
    }
}

fn accepted_setup_test_timing(test_name: &'static str) -> AcceptedSetupTestTiming {
    AcceptedSetupTestTiming {
        started_at: Instant::now(),
        test_name,
    }
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

#[test]
fn collective_setup_profile_exposes_first_profile_state_machine() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_profile_exposes_first_profile_state_machine");
    let profile = describe_collective_bgv_setup_profile().expect("profile");

    assert_eq!(profile["setupProfileId"], "CollectiveBgvSetup-v1");
    assert_eq!(profile["objectType"], "SetupPackage");
    assert_eq!(profile["participantCount"], 10);
    assert_eq!(profile["qSetupComplete"], 10);
    assert_eq!(profile["qBallotRelease"], 10);
    assert_eq!(profile["qFinal"], 10);
    assert_eq!(profile["qDec"], 4);
    assert_eq!(profile["qShare"]["objectType"], "QSharePrimeList");
    assert_eq!(
        profile["qShare"]["primes"]
            .as_array()
            .expect("Q_share primes")
            .len(),
        DATA_PRIMES.len()
    );
    assert!(profile["qShareHash"].as_str().is_some());
    assert_eq!(
        profile["carryAwareVssShareRelationProfile"]["objectType"],
        "CarryAwareVssShareRelationProfile"
    );
    assert!(
        profile["carryAwareVssShareRelationProfileHash"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        profile["commitmentProfile"]["objectType"],
        "BdlopLnpCommitmentProfile"
    );
    assert_eq!(
        profile["commitmentProfile"]["assumptions"]["parameterAcceptanceStatus"],
        "claim-bearing-setup-commitment-parameter-accounting-accepted"
    );
    assert!(profile["commitmentProfileHash"].as_str().is_some());
    assert_eq!(
        profile["publicVssCommitmentMaterialSizeProfile"]["objectType"],
        "PublicVssCommitmentMaterialSizeProfile"
    );
    assert_eq!(
        profile["publicVssCommitmentMaterialSizeProfile"]["ringDegree"],
        POLYNOMIAL_DEGREE
    );
    assert_eq!(
        profile["publicVssCommitmentMaterialSizeProfile"]["fullMaterialCoefficientBytes"],
        serde_json::json!(1_604_321_280_u64)
    );
    assert_eq!(
        profile["publicVssCommitmentMaterialSizeProfile"]["fullMaterialCoefficientMebibytes"],
        1_530
    );
    assert!(
        profile["publicVssCommitmentMaterialSizeProfileHash"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        profile["setupProofProfile"]["objectType"],
        "SetupProofProfile"
    );
    assert_eq!(
        profile["setupProofProfile"]["profileId"],
        "SealedLattice-LNP-SetupProof-v1"
    );
    assert_eq!(
        profile["setupProofProfile"]["challengeBinding"]["challengeBits"],
        128
    );
    assert!(profile["setupProofProfileHash"].as_str().is_some());
    assert_eq!(
        profile["setupTransportProfile"]["objectType"],
        "SetupTransportProfile"
    );
    assert_eq!(
        profile["setupTransportProfile"]["chunkSizeBytes"],
        1_048_576
    );
    assert_eq!(
        profile["setupTransportProfile"]["storageQuotaBytes"],
        2_147_483_648_u64
    );
    assert_eq!(
        profile["setupTransportProfile"]["streamVerificationOrder"],
        "ascending-chunk-index"
    );
    assert_eq!(
        profile["setupTransportProfile"]["lazyLoadingPolicy"],
        "root-addressed-large-object-loading"
    );
    assert!(profile["setupTransportProfileHash"].as_str().is_some());
    assert_eq!(
        profile["evaluatorKeyScheduleProfile"]["objectType"],
        "EvaluatorKeyScheduleProfile"
    );
    assert_eq!(
        profile["evaluatorKeyScheduleProfile"]["genericKeySwitchPolicy"],
        "refused-unless-explicitly-required"
    );
    assert!(
        !profile["evaluatorKeyScheduleProfile"]["relinearizationLevelSchedule"]
            .as_array()
            .expect("relinearization schedule")
            .is_empty()
    );
    assert!(
        !profile["evaluatorKeyScheduleProfile"]["requiredGaloisKeySchedule"]
            .as_array()
            .expect("required Galois schedule")
            .is_empty()
    );
    assert!(
        profile["evaluatorKeyScheduleProfile"]["requiredGaloisSetHash"]
            .as_str()
            .is_some()
    );
    assert!(
        profile["evaluatorKeyScheduleProfileHash"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        profile["verifierStatuses"],
        serde_json::json!([
            "accepted",
            "pending",
            "refused",
            "aborted",
            "forkDetected",
            "outsideProfile"
        ])
    );
    assert_eq!(
        profile["phaseOrder"].as_array().expect("phase order").len(),
        14
    );
    assert!(profile["setupProfileHash"].as_str().is_some());
    assert!(profile["phaseOrderHash"].as_str().is_some());
}

#[test]
fn collective_setup_verifier_refuses_passive_setup_packages() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_passive_setup_packages");
    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": setup_package(),
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "outsideCollectiveBgvSetupProfile"
    );
}

#[test]
fn collective_setup_verifier_reports_missing_phase_as_pending() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_reports_missing_phase_as_pending");
    let mut package = minimal_collective_setup_package();
    package
        .as_object_mut()
        .expect("package object")
        .remove("phaseTranscript");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(result["currentPhase"], "rosterFreeze");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!(["phaseTranscript"])
    );
}

#[test]
fn collective_setup_verifier_detects_phase_forks_and_wrong_order() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_detects_phase_forks_and_wrong_order");
    let mut forked_package = minimal_collective_setup_package();
    let first_phase = forked_package["phaseTranscript"][0].clone();
    let mut forked_phase = first_phase.clone();
    forked_phase["participantPhaseObjects"][0]["signatureEnvelopeHash"] =
        serde_json::json!(valid_hash('2'));
    forked_package["phaseTranscript"] = serde_json::json!([first_phase, forked_phase]);
    rebind_collective_setup_package_hash(&mut forked_package);
    let forked_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": forked_package,
    }))
    .expect("verification response");

    assert_eq!(forked_result["verifierStatus"], "forkDetected");
    assert_eq!(
        forked_result["refusedObjects"][0]["reasonCode"],
        "phaseForkDetected"
    );

    let mut wrong_order_package = minimal_collective_setup_package();
    wrong_order_package["phaseTranscript"] = serde_json::json!([
        { "phaseId": "setupIntent", "phaseNumber": 2, "phaseRoot": valid_hash('3') }
    ]);
    rebind_collective_setup_package_hash(&mut wrong_order_package);
    let wrong_order_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_order_package,
    }))
    .expect("verification response");

    assert_eq!(wrong_order_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_order_result["refusedObjects"][0]["reasonCode"],
        "phaseOrderMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_stale_phase_epoch_and_bad_phase_roots() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_stale_phase_epoch_and_bad_phase_roots",
    );
    let mut stale_epoch_package = minimal_collective_setup_package();
    stale_epoch_package["phaseTranscript"][1]["setupEpoch"] = serde_json::json!("old-epoch");
    rebind_collective_setup_package_hash(&mut stale_epoch_package);

    let stale_epoch_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": stale_epoch_package,
    }))
    .expect("verification response");

    assert_eq!(stale_epoch_result["verifierStatus"], "refused");
    assert_eq!(
        stale_epoch_result["refusedObjects"][0]["reasonCode"],
        "phaseContextMismatch"
    );

    let mut bad_root_package = minimal_collective_setup_package();
    bad_root_package["phaseTranscript"][1]["phaseRoot"] = serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut bad_root_package);

    let bad_root_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": bad_root_package,
    }))
    .expect("verification response");

    assert_eq!(bad_root_result["verifierStatus"], "refused");
    assert_eq!(
        bad_root_result["refusedObjects"][0]["reasonCode"],
        "phaseRootMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_tampered_phase_signature_after_rebinding() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_tampered_phase_signature_after_rebinding",
    );
    let mut package = minimal_collective_setup_package();
    let participant = &mut package["phaseTranscript"][0]["participantPhaseObjects"][0];
    let signature_envelope = participant
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
    signature_envelope["signatureBytesHex"] = serde_json::json!(tampered_signature_bytes_hex);
    let signature_envelope_hash = derive_protocol_hash(
        "ProtocolSignatureEnvelopeHash",
        &serde_json::json!({
            "profile": signature_envelope["profile"],
            "publicKeyBytesHex": signature_envelope["publicKeyBytesHex"],
            "publicKeyHash": signature_envelope["publicKeyHash"],
            "signatureBytesHex": signature_envelope["signatureBytesHex"],
            "signedRoot": signature_envelope["signedRoot"],
        }),
    )
    .expect("signature envelope hash");
    signature_envelope["signatureHash"] = serde_json::json!(signature_envelope_hash.clone());
    participant["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
    rebind_collective_phase_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "InvalidSignature"
    );
}

#[test]
fn collective_setup_verifier_refuses_bad_common_randomness() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_bad_common_randomness");
    let mut missing_reveal_package = minimal_collective_setup_package();
    missing_reveal_package["commonRandomness"]["revealRecords"]
        .as_array_mut()
        .expect("reveal records")
        .pop();
    rebind_collective_setup_package_hash(&mut missing_reveal_package);

    let missing_reveal_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": missing_reveal_package,
        }))
        .expect("verification response");

    assert_eq!(missing_reveal_result["verifierStatus"], "refused");
    assert_eq!(
        missing_reveal_result["refusedObjects"][0]["reasonCode"],
        "commonRandomnessRevealCountMismatch"
    );

    let mut wrong_seed_package = minimal_collective_setup_package();
    wrong_seed_package["commonRandomness"]["publicMatrixSeedHash"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut wrong_seed_package);

    let wrong_seed_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_seed_package,
    }))
    .expect("verification response");

    assert_eq!(wrong_seed_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_seed_result["refusedObjects"][0]["reasonCode"],
        "commonRandomnessPublicMatrixSeedMismatch"
    );

    let mut wrong_derivation_package = minimal_collective_setup_package();
    wrong_derivation_package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"] =
        serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut wrong_derivation_package);

    let wrong_derivation_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_derivation_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_derivation_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_derivation_result["refusedObjects"][0]["reasonCode"],
        "setupPublicDerivationsMismatch"
    );

    let mut wrong_matrix_package = minimal_collective_setup_package();
    wrong_matrix_package["commonRandomness"]["publicDerivations"]["publicMatrices"]["commitmentMatrix"]
        ["sampledEntries"][0]["entryDerivationHash"] = serde_json::json!(valid_hash('3'));
    rebind_collective_setup_package_hash(&mut wrong_matrix_package);

    let wrong_matrix_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_matrix_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_matrix_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_matrix_result["refusedObjects"][0]["reasonCode"],
        "setupPublicDerivationsMismatch"
    );

    let mut wrong_setup_proof_profile_package = minimal_collective_setup_package();
    wrong_setup_proof_profile_package["commonRandomness"]["publicDerivations"]["publicMatrices"]
        ["setupProofMatrix"]["setupProofProfileHash"] = serde_json::json!(valid_hash('4'));
    rebind_collective_setup_package_hash(&mut wrong_setup_proof_profile_package);

    let wrong_setup_proof_profile_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_setup_proof_profile_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_setup_proof_profile_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_setup_proof_profile_result["refusedObjects"][0]["reasonCode"],
        "setupPublicDerivationsMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_commitment_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_commitment_records",
    );
    let mut array_package = minimal_collective_setup_package();
    array_package["vssCoefficientCommitments"] = serde_json::json!([]);
    rebind_collective_setup_package_hash(&mut array_package);

    let array_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": array_package,
    }))
    .expect("verification response");

    assert_eq!(array_result["verifierStatus"], "refused");
    assert_eq!(
        array_result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentsNotObject"
    );

    let mut wrong_limb_package = minimal_collective_setup_package();
    wrong_limb_package["vssCoefficientCommitments"]["sourceTrusteeRecords"][0]["coefficientCommitments"]
        [0]["rnsPrime"] = serde_json::json!(65_537);
    rebind_collective_vss_commitment_roots(&mut wrong_limb_package);
    rebind_collective_setup_package_hash(&mut wrong_limb_package);

    let wrong_limb_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_limb_package,
    }))
    .expect("verification response");

    assert_eq!(wrong_limb_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_limb_result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentRnsPrimeMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_threshold_commitment_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_threshold_commitment_material",
    );
    let mut array_package = minimal_collective_setup_package();
    array_package["vssCoefficientCommitmentMaterial"] = serde_json::json!([]);
    rebind_collective_setup_package_hash(&mut array_package);

    let array_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": array_package,
    }))
    .expect("verification response");

    assert_eq!(array_result["verifierStatus"], "refused");
    assert_eq!(
        array_result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialNotObject"
    );

    let mut tampered_material_package = minimal_collective_setup_package();
    tampered_material_package["vssCoefficientCommitmentMaterial"]["coefficientCommitments"][0]["commitment"]
        ["commitmentLimbs"][0]["rows"][0][0] = serde_json::json!(42);
    rebind_collective_vss_coefficient_commitment_material_root(&mut tampered_material_package);
    rebind_collective_setup_package_hash(&mut tampered_material_package);

    let tampered_material_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": tampered_material_package,
        }))
        .expect("verification response");

    assert_eq!(tampered_material_result["verifierStatus"], "refused");
    assert_eq!(
        tampered_material_result["refusedObjects"][0]["reasonCode"],
        "thresholdShareCommitmentDerivationMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_tampered_threshold_share_commitments() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_tampered_threshold_share_commitments",
    );
    let mut tampered_threshold_package = minimal_collective_setup_package();
    tampered_threshold_package["thresholdShareCommitments"]["recipientRecords"][0]["limbCommitments"]
        [0]["ringDegreeStatus"] = serde_json::json!("profile-ring");
    rebind_collective_threshold_share_commitment_root(&mut tampered_threshold_package);
    rebind_collective_setup_package_hash(&mut tampered_threshold_package);

    let tampered_threshold_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": tampered_threshold_package,
        }))
        .expect("verification response");

    assert_eq!(tampered_threshold_result["verifierStatus"], "refused");
    assert_eq!(
        tampered_threshold_result["refusedObjects"][0]["reasonCode"],
        "thresholdShareCommitmentSetMismatch"
    );
}

#[test]
fn collective_setup_verifier_consumes_transported_threshold_material_when_supplied() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_consumes_transported_threshold_material_when_supplied",
    );
    let mut package = minimal_collective_setup_package();
    let material_bytes = encode_transport_material_from_package(&package);
    let transported_material = transported_material_value(&material_bytes);
    let transport_derivation =
        derive_threshold_share_commitments_from_transport_request(&serde_json::json!({
            "setupContext": package["setupContext"],
            "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
            "vssCoefficientCommitmentRoot": package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"],
            "sourceTrusteeCoefficientCommitmentRecords": package["vssCoefficientCommitments"]["sourceTrusteeRecords"],
            "transportedVssCoefficientCommitmentMaterial": transported_material,
        }))
        .expect("transported threshold derivation");
    package["vssCoefficientCommitmentMaterial"] =
        transport_derivation["vssCoefficientCommitmentMaterial"].clone();
    package["thresholdShareCommitments"] =
        transport_derivation["thresholdShareCommitments"].clone();
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let setup_transport_certificate =
        setup_transport_certificate_fixture(&profile, &package["vssCoefficientCommitmentMaterial"]);
    package["setupTransportCertificate"] = setup_transport_certificate.clone();
    package["setupTransportCertificateHash"] =
        setup_transport_certificate["setupTransportCertificateHash"].clone();
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let missing_transport_result = verify_collective_bgv_setup_package_from_request(
        &serde_json::json!({ "setupPackage": package.clone() }),
    )
    .expect("missing transported material result");
    assert_eq!(missing_transport_result["verifierStatus"], "pending");
    assert_eq!(
        missing_transport_result["currentPhase"],
        "thresholdShareCommitments"
    );
    assert_eq!(
        missing_transport_result["missingObjects"][0],
        "transportedVssCoefficientCommitmentMaterial"
    );

    let transported_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    }))
    .expect("transported material result");
    assert_eq!(transported_result["verifierStatus"], "pending");
    assert_eq!(
        transported_result["currentPhase"],
        "setupPackageVerification"
    );
    assert_eq!(
        transported_result["missingObjects"][0],
        serde_json::json!("sameSecretProofs")
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_private_vss_envelope_commitments() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_private_vss_envelope_commitments",
    );
    let mut array_package = minimal_collective_setup_package();
    array_package["privateVssEnvelopeCommitments"] = serde_json::json!([]);
    rebind_collective_setup_package_hash(&mut array_package);

    let array_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": array_package,
    }))
    .expect("verification response");

    assert_eq!(array_result["verifierStatus"], "refused");
    assert_eq!(
        array_result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeCommitmentsNotObject"
    );

    let mut wrong_aad_package = minimal_collective_setup_package();
    wrong_aad_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["privateEnvelopeAadHash"] =
        serde_json::json!(valid_hash('4'));
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_aad_package);
    rebind_collective_setup_package_hash(&mut wrong_aad_package);

    let wrong_aad_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_aad_package,
    }))
    .expect("verification response");

    assert_eq!(wrong_aad_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_aad_result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeAadHashMismatch"
    );

    let mut wrong_encrypted_hash_package = minimal_collective_setup_package();
    wrong_encrypted_hash_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelopeHash"] =
        serde_json::json!(valid_hash('6'));
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_encrypted_hash_package);
    rebind_collective_setup_package_hash(&mut wrong_encrypted_hash_package);

    let wrong_encrypted_hash_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_encrypted_hash_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_encrypted_hash_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_encrypted_hash_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeHashMismatch"
    );

    let mut wrong_encrypted_binding_package = minimal_collective_setup_package();
    wrong_encrypted_binding_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
        ["ciphertextContentType"] = serde_json::json!("wrong-private-vss-envelope");
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_encrypted_binding_package);
    rebind_collective_setup_package_hash(&mut wrong_encrypted_binding_package);

    let wrong_encrypted_binding_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_encrypted_binding_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_encrypted_binding_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_encrypted_binding_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeBindingMismatch"
    );

    let mut wrong_kem_ciphertext_hash_package = minimal_collective_setup_package();
    wrong_kem_ciphertext_hash_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
        ["kemCiphertextHash"] = serde_json::json!(valid_hash('9'));
    rebind_first_private_vss_encrypted_envelope_hash(&mut wrong_kem_ciphertext_hash_package);
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_kem_ciphertext_hash_package);
    rebind_collective_setup_package_hash(&mut wrong_kem_ciphertext_hash_package);

    let wrong_kem_ciphertext_hash_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_kem_ciphertext_hash_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_kem_ciphertext_hash_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_kem_ciphertext_hash_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeKemCiphertextHashMismatch"
    );

    let mut wrong_ciphertext_bytes_hash_package = minimal_collective_setup_package();
    wrong_ciphertext_bytes_hash_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]
        ["encryptedEnvelope"]["ciphertextBytesHash"] = serde_json::json!(valid_hash('8'));
    rebind_first_private_vss_encrypted_envelope_hash(&mut wrong_ciphertext_bytes_hash_package);
    rebind_collective_private_vss_envelope_commitment_root(
        &mut wrong_ciphertext_bytes_hash_package,
    );
    rebind_collective_setup_package_hash(&mut wrong_ciphertext_bytes_hash_package);

    let wrong_ciphertext_bytes_hash_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_ciphertext_bytes_hash_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_ciphertext_bytes_hash_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_ciphertext_bytes_hash_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeCiphertextBytesHashMismatch"
    );

    let mut wrong_mailbox_key_package = minimal_collective_setup_package();
    wrong_mailbox_key_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["recipientMailboxPublicKeyHash"] =
        serde_json::json!(valid_hash('7'));
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_mailbox_key_package);
    rebind_collective_setup_package_hash(&mut wrong_mailbox_key_package);

    let wrong_mailbox_key_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_mailbox_key_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_mailbox_key_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_mailbox_key_result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeMailboxPublicKeyMismatch"
    );

    let mut wrong_mailbox_key_bytes_package = minimal_collective_setup_package();
    wrong_mailbox_key_bytes_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
        ["recipientMailboxPublicKeyBytesHash"] = serde_json::json!(valid_hash('3'));
    rebind_first_private_vss_encrypted_envelope_hash(&mut wrong_mailbox_key_bytes_package);
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_mailbox_key_bytes_package);
    rebind_collective_setup_package_hash(&mut wrong_mailbox_key_bytes_package);

    let wrong_mailbox_key_bytes_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_mailbox_key_bytes_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_mailbox_key_bytes_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_mailbox_key_bytes_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeMailboxPublicKeyBytesHashMismatch"
    );

    let mut wrong_root_package = minimal_collective_setup_package();
    wrong_root_package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"] =
        serde_json::json!(valid_hash('5'));
    rebind_collective_setup_package_hash(&mut wrong_root_package);

    let wrong_root_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_root_package,
    }))
    .expect("verification response");

    assert_eq!(wrong_root_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_root_result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeCommitmentRootMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_share_acceptance_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_share_acceptance_records",
    );
    let mut array_package = minimal_collective_setup_package();
    array_package["vssShareAcceptances"] = serde_json::json!([]);
    rebind_collective_setup_package_hash(&mut array_package);

    let array_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": array_package,
    }))
    .expect("verification response");

    assert_eq!(array_result["verifierStatus"], "refused");
    assert_eq!(
        array_result["refusedObjects"][0]["reasonCode"],
        "vssShareAcceptancesNotObject"
    );

    let mut wrong_source_trustee_root_package = minimal_collective_setup_package();
    wrong_source_trustee_root_package["vssShareAcceptances"]["acceptanceRecords"][0]["sourceTrusteeCommitmentRoot"] =
        serde_json::json!(valid_hash('3'));
    rebind_collective_vss_acceptance_root(&mut wrong_source_trustee_root_package);
    rebind_collective_setup_package_hash(&mut wrong_source_trustee_root_package);

    let wrong_source_trustee_root_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_source_trustee_root_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_source_trustee_root_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_source_trustee_root_result["refusedObjects"][0]["reasonCode"],
        "vssShareAcceptanceSourceTrusteeCommitmentRootMismatch"
    );

    let mut wrong_local_verification_package = minimal_collective_setup_package();
    wrong_local_verification_package["vssShareAcceptances"]["acceptanceRecords"][0]["localVerificationRoot"] =
        serde_json::json!(valid_hash('4'));
    rebind_collective_vss_acceptance_root(&mut wrong_local_verification_package);
    rebind_collective_setup_package_hash(&mut wrong_local_verification_package);

    let wrong_local_verification_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_local_verification_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_local_verification_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_local_verification_result["refusedObjects"][0]["reasonCode"],
        "vssShareAcceptanceLocalVerificationRootMismatch"
    );

    let mut tampered_signature_package = minimal_collective_setup_package();
    let acceptance_record =
        &mut tampered_signature_package["vssShareAcceptances"]["acceptanceRecords"][0];
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
    signature_envelope["signatureBytesHex"] = serde_json::json!(tampered_signature_bytes_hex);
    let signature_envelope_hash = derive_protocol_hash(
        "ProtocolSignatureEnvelopeHash",
        &serde_json::json!({
            "profile": signature_envelope["profile"],
            "publicKeyBytesHex": signature_envelope["publicKeyBytesHex"],
            "publicKeyHash": signature_envelope["publicKeyHash"],
            "signatureBytesHex": signature_envelope["signatureBytesHex"],
            "signedRoot": signature_envelope["signedRoot"],
        }),
    )
    .expect("signature envelope hash");
    signature_envelope["signatureHash"] = serde_json::json!(signature_envelope_hash.clone());
    acceptance_record["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
    rebind_collective_vss_acceptance_root(&mut tampered_signature_package);
    rebind_collective_setup_package_hash(&mut tampered_signature_package);

    let tampered_signature_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": tampered_signature_package,
        }))
        .expect("verification response");

    assert_eq!(tampered_signature_result["verifierStatus"], "refused");
    assert_eq!(
        tampered_signature_result["refusedObjects"][0]["reasonCode"],
        "InvalidSignature"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_same_secret_statements() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_same_secret_statements",
    );
    let mut wrong_constant_package = minimal_collective_setup_package();
    wrong_constant_package["sameSecretConsistency"]["statementRecords"][0]["constantCoefficientCommitmentRoots"]
        [0]["commitmentRoot"] = serde_json::json!(valid_hash('4'));
    rebind_collective_same_secret_statement_roots(&mut wrong_constant_package);
    rebind_collective_setup_package_hash(&mut wrong_constant_package);

    let wrong_constant_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_constant_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_constant_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_constant_result["refusedObjects"][0]["reasonCode"],
        "sameSecretConstantCommitmentRootMismatch"
    );

    let mut wrong_statement_root_package = minimal_collective_setup_package();
    wrong_statement_root_package["sameSecretConsistency"]["statementRecords"][0]["sameSecretStatementRoot"] =
        serde_json::json!(valid_hash('5'));
    rebind_collective_same_secret_consistency_root(&mut wrong_statement_root_package);
    rebind_collective_setup_package_hash(&mut wrong_statement_root_package);

    let wrong_statement_root_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_statement_root_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_statement_root_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_statement_root_result["refusedObjects"][0]["reasonCode"],
        "sameSecretStatementRootMismatch"
    );

    let mut wrong_family_binding_package = minimal_collective_setup_package();
    wrong_family_binding_package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('6'));
    rebind_collective_same_secret_consistency_root(&mut wrong_family_binding_package);
    rebind_collective_setup_package_hash(&mut wrong_family_binding_package);

    let wrong_family_binding_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_family_binding_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_family_binding_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_family_binding_result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofFamilyBindingRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_before_public_key_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_before_public_key_material",
    );
    let package = same_secret_proof_bearing_collective_setup_package();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!([
            "publicKeyShareMaterial",
            "publicKeyShareLnpProofs",
            "collectivePublicKey",
            "collectivePublicKeyRoot"
        ])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_same_secret_lnp_proofs_before_missing_terminal_objects()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_same_secret_lnp_proofs_before_missing_terminal_objects",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofModelStatus"] =
        serde_json::json!("weakened-same-secret-proof-model");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofSetProfileMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_from_transported_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_from_transported_material",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    let material_bytes = encode_transport_material_from_package(&package);
    let transported_material = transported_material_value(&material_bytes);
    let transport_derivation =
        derive_threshold_share_commitments_from_transport_request(&serde_json::json!({
            "setupContext": package["setupContext"],
            "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
            "vssCoefficientCommitmentRoot": package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"],
            "sourceTrusteeCoefficientCommitmentRecords": package["vssCoefficientCommitments"]["sourceTrusteeRecords"],
            "transportedVssCoefficientCommitmentMaterial": transported_material,
        }))
        .expect("transported threshold derivation");
    package["vssCoefficientCommitmentMaterial"] =
        transport_derivation["vssCoefficientCommitmentMaterial"].clone();
    package["thresholdShareCommitments"] =
        transport_derivation["thresholdShareCommitments"].clone();
    package["sameSecretProofs"]["vssCoefficientCommitmentMaterialRoot"] =
        package["vssCoefficientCommitmentMaterial"]["vssCoefficientCommitmentMaterialRoot"].clone();
    rebind_collective_same_secret_proof_set_root(&mut package);
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let setup_transport_certificate =
        setup_transport_certificate_fixture(&profile, &package["vssCoefficientCommitmentMaterial"]);
    package["setupTransportCertificate"] = setup_transport_certificate.clone();
    package["setupTransportCertificateHash"] =
        setup_transport_certificate["setupTransportCertificateHash"].clone();
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!([
            "publicKeyShareMaterial",
            "publicKeyShareLnpProofs",
            "collectivePublicKey",
            "collectivePublicKeyRoot"
        ])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_from_transported_proof_material",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    let transported_proof_material = move_same_secret_proof_bytes_to_transport(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedSameSecretProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!([
            "publicKeyShareMaterial",
            "publicKeyShareLnpProofs",
            "collectivePublicKey",
            "collectivePublicKeyRoot"
        ])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_same_secret_proof_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_same_secret_proof_chunk",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    let mut transported_proof_material = move_same_secret_proof_bytes_to_transport(&mut package);
    transported_proof_material["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedSameSecretProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_lnp_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_lnp_proofs",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["proofBytesHash"] =
        serde_json::json!(valid_hash('6'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_row_metadata() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_row_metadata",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["z34ChallengeZ3RowSetHash"] =
        serde_json::json!(valid_hash('7'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_tail_metadata() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_tail_metadata",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["z34ChallengeTailHash"] =
        serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_tbox_lower_challenge_metadata()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_tbox_lower_challenge_metadata",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["tboxLowerProtocolChallengeHash"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_check_window_metadata()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_check_window_metadata",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["z34Z3CheckWindowHash"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
fn same_secret_lnp_verifier_refuses_unbound_tbox_prefix() {
    let package = minimal_collective_setup_package();
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let statement_record = &package["sameSecretConsistency"]["statementRecords"][0];
    let constant_commitments = same_secret_constant_commitments_from_fixture_package(&package, 0);
    let ring_degree = constant_commitments
        .first()
        .expect("constant commitment")
        .ring_degree;
    let witness = SameSecretLnpProofWitness {
        secret_coefficients: (0..ring_degree)
            .map(|coefficient_position| {
                accepted_vss_secret_coefficient_fixture(0, coefficient_position)
            })
            .collect(),
        opening_randomness_by_limb: (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(0, rns_limb_index, 0, ring_degree)
            })
            .collect(),
    };
    let proof_randomness_seed_hex = derive_protocol_hash(
        "SameSecretProofRoot",
        &serde_json::json!({
            "fixture": "same-secret-unbound-prefix-test",
            "trusteeRosterPosition": 0_u64,
        }),
    )
    .expect("same-secret proof randomness seed");
    let mut proof_bytes = generate_same_secret_lnp_relation_proof(
        public_matrix_seed_hash,
        statement_record,
        &constant_commitments,
        &setup_proof_binding_for_test_package(&package),
        &witness,
        &proof_randomness_seed_hex,
    )
    .expect("same-secret proof bytes");
    let tbox_prefix_offset = 8 + 64 + 64 + 8 + 8;
    proof_bytes[tbox_prefix_offset] ^= 1;

    let error = verify_same_secret_lnp_relation_proof(
        public_matrix_seed_hash,
        statement_record,
        &constant_commitments,
        &setup_proof_binding_for_test_package(&package),
        &proof_bytes,
    )
    .expect_err("unbound tbox prefix must be refused");

    assert!(
        error
            .message
            .contains("tbox commitment prefix is not bound")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_root_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_root_drift",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('7'));
    rebind_collective_same_secret_proof_set_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofConsistencyRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_record_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_record_drift",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_same_secret_proof_set_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_setup_proof_challenge_domain_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_setup_proof_challenge_domain_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["setupProofBinding"]["challengeDomainHash"] =
        serde_json::json!(valid_hash('7'));
    rebind_collective_same_secret_proof_set_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_public_key_share_statements() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_public_key_share_statements",
    );
    let mut wrong_public_a_package = minimal_collective_setup_package();
    wrong_public_a_package["publicKeyShares"]["shareRecords"][0]["publicAPolynomialRoot"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_public_key_share_roots(&mut wrong_public_a_package);
    rebind_collective_setup_package_hash(&mut wrong_public_a_package);

    let wrong_public_a_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_public_a_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_public_a_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_public_a_result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareCommonBindingMismatch"
    );

    let mut wrong_proof_binding_package = minimal_collective_setup_package();
    wrong_proof_binding_package["publicKeyShareProofs"]["proofRecords"][0]["sameSecretStatementRoot"] =
        serde_json::json!(valid_hash('9'));
    rebind_collective_public_key_share_proof_roots(&mut wrong_proof_binding_package);
    rebind_collective_setup_package_hash(&mut wrong_proof_binding_package);

    let wrong_proof_binding_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_proof_binding_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_proof_binding_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_proof_binding_result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareProofBindingMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_lnp_proofs_before_collective_key_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_lnp_proofs_before_collective_key_material",
    );
    let package = public_key_share_lnp_proof_bearing_collective_setup_package();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!(["collectivePublicKey", "collectivePublicKeyRoot"])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_public_key_lnp_proofs_before_missing_terminal_objects()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_public_key_lnp_proofs_before_missing_terminal_objects",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package["publicKeyShareLnpProofs"]["proofModelStatus"] =
        serde_json::json!("weakened-public-key-share-proof-model");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofSetProfileMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_lnp_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_lnp_proofs_from_transported_proof_material",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    let transported_proof_material =
        move_public_key_share_lnp_proof_bytes_to_transport(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicKeyShareProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!(["collectivePublicKey", "collectivePublicKeyRoot"])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_public_key_share_lnp_proof_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_public_key_share_lnp_proof_chunk",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    let mut transported_proof_material =
        move_public_key_share_lnp_proof_bytes_to_transport(&mut package);
    transported_proof_material["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicKeyShareProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_lnp_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_lnp_material",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    let coefficients_hex = package["publicKeyShareMaterial"]["shareMaterialRecords"][0]
        ["shareCoefficientVectorsByLimb"][0]["coefficientsLeHex"]
        .as_str()
        .expect("coefficient hex");
    let replacement_prefix = if coefficients_hex.starts_with("00") {
        "01"
    } else {
        "00"
    };
    let tampered_hex = format!("{replacement_prefix}{}", &coefficients_hex[2..]);
    package["publicKeyShareMaterial"]["shareMaterialRecords"][0]["shareCoefficientVectorsByLimb"]
        [0]["coefficientsLeHex"] = serde_json::json!(tampered_hex);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_lnp_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_lnp_proofs",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package["publicKeyShareLnpProofs"]["proofRecords"][0]["proofBytesHash"] =
        serde_json::json!(valid_hash('a'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_lnp_z34_metadata()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_lnp_z34_metadata",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package["publicKeyShareLnpProofs"]["proofRecords"][0]["z34Z4CheckWindowHash"] =
        serde_json::json!(valid_hash('f'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("z34Z4CheckWindowHash")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_requires_same_secret_proofs_before_public_key_lnp_proofs()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_requires_same_secret_proofs_before_public_key_lnp_proofs",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package")
        .remove("sameSecretProofs");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(result["currentPhase"], "proofVerification");
    assert_eq!(
        result["missingObjects"][0],
        serde_json::json!("sameSecretProofs")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_lnp_same_secret_proof_set_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_lnp_same_secret_proof_set_drift",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package["publicKeyShareLnpProofs"]["sameSecretProofSetRoot"] =
        serde_json::json!(valid_hash('b'));
    rebind_collective_public_key_lnp_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofSetBindingMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_lnp_same_secret_family_root_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_lnp_same_secret_family_root_drift",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package["publicKeyShareLnpProofs"]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('d'));
    rebind_collective_public_key_lnp_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofSetBindingMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_lnp_same_secret_proof_root_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_lnp_same_secret_proof_root_drift",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package["publicKeyShareLnpProofs"]["proofRecords"][0]["sameSecretProofRoot"] =
        serde_json::json!(valid_hash('c'));
    rebind_collective_public_key_lnp_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_lnp_same_secret_family_record_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_lnp_same_secret_family_record_drift",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package["publicKeyShareLnpProofs"]["proofRecords"][0]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('e'));
    rebind_collective_public_key_lnp_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_lnp_carry_response()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_lnp_carry_response",
    );
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    let proof_bytes_hex = package["publicKeyShareLnpProofs"]["proofRecords"][0]["proofBytesHex"]
        .as_str()
        .expect("public-key proof bytes hex");
    let mut proof_bytes = decode_hex(proof_bytes_hex).expect("proof bytes");
    let last_byte = proof_bytes.last_mut().expect("proof bytes are non-empty");
    *last_byte ^= 1;
    package["publicKeyShareLnpProofs"]["proofRecords"][0]["proofBytesHex"] =
        serde_json::json!(to_hex(&proof_bytes));
    package["publicKeyShareLnpProofs"]["proofRecords"][0]["proofBytesHash"] =
        serde_json::json!(public_key_share_lnp_relation_proof_bytes_hash(&proof_bytes));
    package["publicKeyShareLnpProofs"]["proofRecords"][0]["proofSizeBytes"] =
        serde_json::json!(proof_bytes.len());
    rebind_collective_public_key_lnp_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareLnpProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_collective_public_key_from_lnp_proof_bearing_shares()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_collective_public_key_from_lnp_proof_bearing_shares",
    );
    let package = collective_public_key_bearing_collective_setup_package();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_collective_public_key_aggregate()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_collective_public_key_aggregate",
    );
    let mut package = collective_public_key_bearing_collective_setup_package();
    let coefficients_hex =
        package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"][0]["coefficientsLeHex"]
            .as_str()
            .expect("aggregate coefficients");
    let mut coefficients = coefficient_vector_from_le_hex(
        coefficients_hex,
        same_secret_constant_commitments_from_fixture_package(&package, 0)[0].ring_degree,
        "aggregate coefficient width",
    )
    .expect("aggregate coefficients decode");
    coefficients[0] = add_mod(coefficients[0], 1, DATA_PRIMES[0]).expect("tamper coefficient");
    package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"][0]["coefficientsLeHex"] =
        serde_json::json!(coefficient_vector_le_hex(&coefficients));
    package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"][0]["coefficientVectorHash512"] =
        serde_json::json!(public_key_share_coefficient_vector_hash(&coefficients));
    rebind_collective_public_key_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "collectivePublicKeyVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_public_key_loader_refuses_reduced_ring_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_public_key_loader_refuses_reduced_ring_material",
    );
    let package = collective_public_key_bearing_collective_setup_package();

    let error = match accepted_setup_collective_public_key_from_package(&package) {
        Ok(_) => panic!("reduced-ring material must not become a runtime public key"),
        Err(error) => error,
    };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires profile-ring aggregate coefficients")
    );
}

#[test]
fn collective_setup_verifier_refuses_public_key_material_before_proof_verification() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_public_key_material_before_proof_verification",
    );
    let mut package = minimal_collective_setup_package();
    package["collectivePublicKeyRoot"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyMaterialBeforeProofVerification"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_requires_collective_public_key_and_package_root()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_requires_collective_public_key_and_package_root",
    );
    let base_package = collective_public_key_bearing_collective_setup_package();

    let mut missing_object_package = base_package.clone();
    missing_object_package
        .as_object_mut()
        .expect("setup package")
        .remove("collectivePublicKey");
    rebind_collective_setup_package_hash(&mut missing_object_package);

    let missing_object_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": missing_object_package,
        }))
        .expect("verification response");

    assert_eq!(missing_object_result["verifierStatus"], "refused");
    assert_eq!(
        missing_object_result["refusedObjects"][0]["reasonCode"],
        "publicKeyMaterialBeforeProofVerification"
    );
    assert_eq!(
        missing_object_result["refusedObjects"][0]["objectPath"],
        "setupPackage.collectivePublicKey"
    );

    let mut missing_root_package = base_package;
    missing_root_package
        .as_object_mut()
        .expect("setup package")
        .remove("collectivePublicKeyRoot");
    rebind_collective_setup_package_hash(&mut missing_root_package);

    let missing_root_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": missing_root_package,
        }))
        .expect("verification response");

    assert_eq!(missing_root_result["verifierStatus"], "refused");
    assert_eq!(
        missing_root_result["refusedObjects"][0]["reasonCode"],
        "publicKeyMaterialBeforeProofVerification"
    );
    assert_eq!(
        missing_root_result["refusedObjects"][0]["objectPath"],
        "setupPackage.collectivePublicKeyRoot"
    );
}

#[test]
fn collective_setup_verifier_aborts_on_valid_vss_complaint() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_aborts_on_valid_vss_complaint");
    let mut package = minimal_collective_setup_package();
    package["vssComplaints"] = vss_complaints_object(
        &package["setupContext"],
        &package["privateVssEnvelopeCommitments"],
        &package["vssCoefficientCommitments"],
        0,
        1,
    );
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "aborted");
    assert_eq!(result["currentPhase"], "vssAcceptanceOrComplaint");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssComplaintAcceptedAbort"
    );
    assert!(
        result["acceptedHashes"]
            .as_array()
            .expect("accepted hashes")[0]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_complaint_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_complaint_records",
    );
    let mut wrong_source_trustee_root_package = minimal_collective_setup_package();
    wrong_source_trustee_root_package["vssComplaints"] = vss_complaints_object(
        &wrong_source_trustee_root_package["setupContext"],
        &wrong_source_trustee_root_package["privateVssEnvelopeCommitments"],
        &wrong_source_trustee_root_package["vssCoefficientCommitments"],
        0,
        1,
    );
    wrong_source_trustee_root_package["vssComplaints"]["complaintRecords"][0]["sourceTrusteeCommitmentRoot"] =
        serde_json::json!(valid_hash('3'));
    rebind_collective_vss_complaint_root(&mut wrong_source_trustee_root_package);
    rebind_collective_setup_package_hash(&mut wrong_source_trustee_root_package);

    let wrong_source_trustee_root_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_source_trustee_root_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_source_trustee_root_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_source_trustee_root_result["refusedObjects"][0]["reasonCode"],
        "vssComplaintSourceTrusteeCommitmentRootMismatch"
    );

    let mut tampered_signature_package = minimal_collective_setup_package();
    tampered_signature_package["vssComplaints"] = vss_complaints_object(
        &tampered_signature_package["setupContext"],
        &tampered_signature_package["privateVssEnvelopeCommitments"],
        &tampered_signature_package["vssCoefficientCommitments"],
        0,
        1,
    );
    let complaint_record = &mut tampered_signature_package["vssComplaints"]["complaintRecords"][0];
    let signature_envelope = complaint_record
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
    signature_envelope["signatureBytesHex"] = serde_json::json!(tampered_signature_bytes_hex);
    let signature_envelope_hash = derive_protocol_hash(
        "ProtocolSignatureEnvelopeHash",
        &serde_json::json!({
            "profile": signature_envelope["profile"],
            "publicKeyBytesHex": signature_envelope["publicKeyBytesHex"],
            "publicKeyHash": signature_envelope["publicKeyHash"],
            "signatureBytesHex": signature_envelope["signatureBytesHex"],
            "signedRoot": signature_envelope["signedRoot"],
        }),
    )
    .expect("signature envelope hash");
    signature_envelope["signatureHash"] = serde_json::json!(signature_envelope_hash.clone());
    complaint_record["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
    rebind_collective_vss_complaint_root(&mut tampered_signature_package);
    rebind_collective_setup_package_hash(&mut tampered_signature_package);

    let tampered_signature_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": tampered_signature_package,
        }))
        .expect("verification response");

    assert_eq!(tampered_signature_result["verifierStatus"], "refused");
    assert_eq!(
        tampered_signature_result["refusedObjects"][0]["reasonCode"],
        "InvalidSignature"
    );
}

#[test]
fn collective_setup_verifier_refuses_forbidden_accepted_path_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_forbidden_accepted_path_material",
    );
    let mut seeded_package = minimal_collective_setup_package();
    seeded_package["setupSeed"] = serde_json::json!("externally-supplied-seed");
    rebind_collective_setup_package_hash(&mut seeded_package);

    let seeded_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": seeded_package,
    }))
    .expect("verification response");

    assert_eq!(seeded_result["verifierStatus"], "refused");
    assert_eq!(
        seeded_result["refusedObjects"][0]["reasonCode"],
        "acceptedPathForbiddenField"
    );

    let mut externally_supplied_threshold_package = minimal_collective_setup_package();
    externally_supplied_threshold_package["externallySuppliedThresholdShareCommitmentMaterial"] =
        serde_json::json!({ "root": valid_hash('5') });
    rebind_collective_setup_package_hash(&mut externally_supplied_threshold_package);

    let externally_supplied_threshold_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": externally_supplied_threshold_package,
        }))
        .expect("verification response");

    assert_eq!(
        externally_supplied_threshold_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        externally_supplied_threshold_result["refusedObjects"][0]["reasonCode"],
        "acceptedPathForbiddenField"
    );

    let legacy_external_setup_role_field = [
        "central",
        "Trusted",
        "Setup",
        "Authority",
        "ThresholdShareCommitments",
    ]
    .join("");
    let mut legacy_external_setup_role_package = minimal_collective_setup_package();
    legacy_external_setup_role_package[legacy_external_setup_role_field.as_str()] =
        serde_json::json!({ "root": valid_hash('6') });
    rebind_collective_setup_package_hash(&mut legacy_external_setup_role_package);

    let legacy_external_setup_role_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": legacy_external_setup_role_package,
        }))
        .expect("verification response");

    assert_eq!(
        legacy_external_setup_role_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        legacy_external_setup_role_result["refusedObjects"][0]["reasonCode"],
        "secretMaterialPresent"
    );
}

#[test]
fn collective_setup_verifier_refuses_generic_key_switch_material_by_default() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_generic_key_switch_material_by_default",
    );
    let mut package = minimal_collective_setup_package();
    package["genericKeySwitchKeys"] = serde_json::json!({ "keyRoot": valid_hash('4') });
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "genericKeySwitchOutsideProfile"
    );
}

#[test]
fn collective_setup_verifier_refuses_evaluator_schedule_drift() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_evaluator_schedule_drift");
    let mut package = minimal_collective_setup_package();
    package["evaluatorKeySchedule"]["requiredGaloisSetHash"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "requiredGaloisSetHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_evaluation_key_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_evaluation_key_material",
    );
    let mut relin_package = minimal_collective_setup_package();
    let evaluator_key_schedule_root =
        relin_package["evaluatorKeySchedule"]["evaluatorKeyScheduleRoot"].clone();
    relin_package["relinearizationKeyShareRounds"] = serde_json::json!({
        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
    });
    rebind_collective_setup_package_hash(&mut relin_package);

    let relin_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": relin_package,
    }))
    .expect("verification response");

    assert_eq!(relin_result["verifierStatus"], "refused");
    assert_eq!(
        relin_result["refusedObjects"][0]["reasonCode"],
        "relinearizationKeyShareRoundsTypeMismatch"
    );

    let mut evaluation_key_package = minimal_collective_setup_package();
    evaluation_key_package["evaluationKeys"] = serde_json::json!({
        "evaluationKeyRoot": valid_hash('9'),
    });
    rebind_collective_setup_package_hash(&mut evaluation_key_package);

    let evaluation_key_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": evaluation_key_package,
        }))
        .expect("verification response");

    assert_eq!(evaluation_key_result["verifierStatus"], "refused");
    assert_eq!(
        evaluation_key_result["refusedObjects"][0]["reasonCode"],
        "evaluationKeysUnexpectedField"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_evaluation_key_proof_container_roots() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_evaluation_key_proof_container_roots",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let relinearization_root =
        package["relinearizationKeyShareRounds"]["relinearizationKeyShareRoundsRoot"].clone();
    let first_galois_batch_root =
        package["galoisKeyShareBatches"][0]["galoisKeyShareBatchRoot"].clone();
    let evaluation_key_set_hash = package["evaluationKeys"]["evaluationKeySetHash"].clone();
    let accepted_hashes = accepted_hashes_from_package(package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    let relinearization_root = relinearization_root.as_str().expect("relinearization root");
    let first_galois_batch_root = first_galois_batch_root.as_str().expect("Galois batch root");
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == relinearization_root)
    );
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == first_galois_batch_root)
    );
    let evaluation_key_set_hash = evaluation_key_set_hash
        .as_str()
        .expect("evaluation key set hash");
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == evaluation_key_set_hash)
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_transported_public_evaluation_key_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_transported_public_evaluation_key_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    let evaluation_key_set_hash = package["evaluationKeys"]["evaluationKeySetHash"]
        .as_str()
        .expect("evaluation-key set hash")
        .to_string();
    let public_material_root = package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"]
        .as_str()
        .expect("public evaluation-key material root")
        .to_string();
    let accepted_hashes = accepted_hashes_from_package(&package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == &evaluation_key_set_hash)
    );
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == &public_material_root)
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_material_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_material_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    let expected_manifest =
        public_evaluation_key_material_manifest(&package, &package["evaluationKeys"])
            .expect("public evaluation-key material manifest");
    let mut tampered_manifest = expected_manifest;
    tampered_manifest["materialSource"] =
        serde_json::json!("tampered-public-evaluation-key-material");
    let tampered_material_bytes =
        encode_public_evaluation_key_material_manifest(&tampered_manifest)
            .expect("tampered public evaluation-key material bytes");
    rebind_public_evaluation_key_material_transport(
        &mut package,
        &mut transported_public_evaluation_key_material,
        tampered_material_bytes,
    );

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicEvaluationKeyMaterialManifestMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_uses_public_evaluation_key_material_component_chunks()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_uses_public_evaluation_key_material_component_chunks",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let component_material_set =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);
    let mut transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    add_component_materials_to_public_evaluation_key_material_transport(
        &mut transported_public_evaluation_key_material,
        &[component_material_set],
    );

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_public_galois_key_loader_refuses_reduced_ring_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_public_galois_key_loader_refuses_reduced_ring_material",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();

    let error =
        match accepted_setup_public_galois_keys_from_transport(package, &serde_json::json!({})) {
            Ok(_) => panic!("reduced-ring material must not become runtime Galois keys"),
            Err(error) => error,
        };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires profile-ring component vectors")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_public_relinearization_key_loader_refuses_reduced_ring_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_public_relinearization_key_loader_refuses_reduced_ring_material",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();

    let error = match accepted_setup_public_relinearization_keys_from_transport(
        package,
        &serde_json::json!({}),
    ) {
        Ok(_) => panic!("reduced-ring material must not become runtime relinearization keys"),
        Err(error) => error,
    };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires profile-ring component vectors")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_relinearization_round_one_generation_refuses_independent_source_square() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_relinearization_round_one_generation_refuses_independent_source_square",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let proof_record_snapshot =
        package["relinearizationKeyShareRounds"]["roundOneRecords"][0].clone();
    let trustee_roster_position = proof_record_snapshot["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let level = proof_record_snapshot["level"].as_u64().expect("level");
    let ring_degree = proof_record_snapshot["ringDegree"]
        .as_u64()
        .expect("ring degree") as usize;
    let key_switch_seed_hex = proof_record_snapshot["keySwitchSeedHex"]
        .as_str()
        .expect("key-switch seed");
    let legacy_source = legacy_relinearization_source_square_coefficients_for_fixture(
        trustee_roster_position,
        ring_degree,
    );
    let fixture_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Relinearization,
        trustee_roster_position,
        level,
        None,
        ring_degree,
        key_switch_seed_hex,
        Some(&legacy_source),
    );
    let mut proof_record = proof_record_snapshot.clone();
    proof_record["keySwitchComponentVectorRoot"] =
        serde_json::json!(fixture_material.component_vector_root.clone());
    proof_record["keySwitchComponentVectors"] =
        serde_json::json!(fixture_material.component_vector_entries.clone());
    let statement_record =
        &package["sameSecretConsistency"]["statementRecords"][trustee_roster_position as usize];
    let constant_commitments =
        same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let proof_randomness_seed_hex = derive_protocol_hash(
        "RelinearizationRoundOneProofRandomness",
        &serde_json::json!({
            "trusteeRosterPosition": trustee_roster_position,
            "level": level,
            "rotation": serde_json::Value::Null,
        }),
    )
    .expect("proof randomness seed");
    let witness = EvaluationKeyShareLnpProofWitness {
        secret_coefficients: evaluation_key_secret_coefficients_for_fixture(
            trustee_roster_position,
            ring_degree,
        ),
        opening_randomness_by_limb: (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    0,
                    ring_degree,
                )
            })
            .collect(),
        error_coefficients_by_digit: fixture_material.error_coefficients_by_digit.clone(),
        relinearization_source_coefficients_by_digit: fixture_material
            .relinearization_source_coefficients_by_digit
            .clone(),
        round_one_aggregate_source_coefficients_by_digit: Vec::new(),
    };
    let error = match generate_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofGenerationInput {
            proof_family: EvaluationKeyShareProofFamily::Relinearization,
            public_matrix_seed_hash,
            proof_record: &proof_record,
            same_secret_statement_record: statement_record,
            constant_commitments: &constant_commitments,
            component_b_by_digit: &fixture_material.component_b_by_digit,
            setup_proof_binding: &setup_proof_binding,
            transported_key_switch_component_material: None,
            witness: &witness,
            proof_randomness_seed_hex: &proof_randomness_seed_hex,
        },
    ) {
        Ok(_) => panic!("round-one source-square shortcut must reject"),
        Err(error) => error,
    };

    assert!(
        error.message.contains(
            "round-one relinearization source witness must equal the same-secret witness"
        ),
        "{}",
        error.message
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_relinearization_round_two_generation_refuses_aggregate_source_product_mismatch()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_relinearization_round_two_generation_refuses_aggregate_source_product_mismatch",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let proof_record = package["relinearizationKeyShareRounds"]["roundTwoRecords"][0].clone();
    let trustee_roster_position = proof_record["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let level = proof_record["level"].as_u64().expect("level");
    let ring_degree = proof_record["ringDegree"].as_u64().expect("ring degree") as usize;
    let key_switch_seed_hex = proof_record["keySwitchSeedHex"]
        .as_str()
        .expect("key-switch seed");
    let round_two_source = relinearization_round_two_source_coefficients_for_fixture(
        trustee_roster_position,
        ring_degree,
    );
    let fixture_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Relinearization,
        trustee_roster_position,
        level,
        None,
        ring_degree,
        key_switch_seed_hex,
        Some(&round_two_source),
    );
    let statement_record =
        &package["sameSecretConsistency"]["statementRecords"][trustee_roster_position as usize];
    let constant_commitments =
        same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
    let constant_commitment_values = constant_commitments
        .iter()
        .map(super::super::commitment::setup_commitment_full_value)
        .collect::<Vec<_>>();
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let proof_randomness_seed_hex = derive_protocol_hash(
        "RelinearizationRoundTwoProofRandomness",
        &serde_json::json!({
            "trusteeRosterPosition": trustee_roster_position,
            "level": level,
            "rotation": serde_json::Value::Null,
        }),
    )
    .expect("proof randomness seed");
    let request = serde_json::json!({
        "proofFamily": "relinearization-key-share",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "proofRecord": proof_record,
        "sameSecretStatementRecord": statement_record,
        "constantCommitments": constant_commitment_values,
        "setupProofBinding": setup_proof_binding,
        "secretCoefficients": evaluation_key_secret_coefficients_for_fixture(
            trustee_roster_position,
            ring_degree,
        ),
        "openingRandomnessByLimb": (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    0,
                    ring_degree,
                )
            })
            .collect::<Vec<_>>(),
        "errorCoefficientsByDigit": fixture_material.error_coefficients_by_digit,
        "relinearizationSourceCoefficientsByDigit": fixture_material
            .relinearization_source_coefficients_by_digit,
        "roundOneAggregateSourceCoefficientsByDigit": vec![
            vec![0_i128; ring_degree];
            fixture_material.component_b_by_digit.len()
        ],
        "proofRandomnessSource": "development-deterministic-fixture",
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
    });

    let error = match generate_evaluation_key_share_lnp_proof_from_request(&request) {
        Ok(_) => panic!("round-two source product mismatch must reject"),
        Err(error) => error,
    };

    assert!(
        error.message.contains(
            "round-two relinearization source witness must equal the trustee secret times the accepted round-one aggregate source"
        ),
        "{}",
        error.message
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_generate_evaluation_key_share_lnp_proof_command_self_verifies_galois_proof()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_generate_evaluation_key_share_lnp_proof_command_self_verifies_galois_proof",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let proof_record = package["galoisKeyShareBatches"][0]["galoisKeyShareProofs"][0].clone();
    let trustee_roster_position = proof_record["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let rotation = proof_record["rotation"].as_u64().expect("rotation");
    let level = proof_record["level"].as_u64().expect("level");
    let ring_degree = proof_record["ringDegree"].as_u64().expect("ring degree") as usize;
    let key_switch_seed_hex = proof_record["keySwitchSeedHex"]
        .as_str()
        .expect("key-switch seed");
    let fixture_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Galois,
        trustee_roster_position,
        level,
        Some(rotation),
        ring_degree,
        key_switch_seed_hex,
        None,
    );
    let statement_record =
        &package["sameSecretConsistency"]["statementRecords"][trustee_roster_position as usize];
    let constant_commitments =
        same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
    let constant_commitment_values = constant_commitments
        .iter()
        .map(super::super::commitment::setup_commitment_full_value)
        .collect::<Vec<_>>();
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let proof_randomness_seed_hex = derive_protocol_hash(
        "GaloisKeyShareProofRandomness",
        &serde_json::json!({
            "trusteeRosterPosition": trustee_roster_position,
            "level": level,
            "rotation": rotation,
        }),
    )
    .expect("proof randomness seed");
    let request = serde_json::json!({
        "proofFamily": "galois-key-share",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "proofRecord": proof_record,
        "sameSecretStatementRecord": statement_record,
        "constantCommitments": constant_commitment_values,
        "setupProofBinding": setup_proof_binding,
        "secretCoefficients": evaluation_key_secret_coefficients_for_fixture(
            trustee_roster_position,
            ring_degree,
        ),
        "openingRandomnessByLimb": (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    0,
                    ring_degree,
                )
            })
            .collect::<Vec<_>>(),
        "errorCoefficientsByDigit": fixture_material.error_coefficients_by_digit,
        "proofRandomnessSource": "development-deterministic-fixture",
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
    });

    let result = generate_evaluation_key_share_lnp_proof_from_request(&request)
        .expect("generated evaluation-key proof");

    assert_eq!(
        result["ok"],
        true,
        "terminal setup verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(result["operation"], "generateEvaluationKeyShareLnpProof");
    assert_eq!(result["proofFamily"], "galois-key-share");
    assert!(
        result["galoisKeyShareTboxParameterProfileHash"]
            .as_str()
            .is_some()
    );
    let proof_bytes = decode_hex(result["proofBytesHex"].as_str().expect("proof bytes hex"))
        .expect("proof bytes");
    assert_eq!(
        result["proofSizeBytes"].as_u64(),
        Some(u64::try_from(proof_bytes.len()).expect("proof size fits u64"))
    );
    assert_eq!(
        result["proofBytesHash"].as_str().expect("proof bytes hash"),
        evaluation_key_share_lnp_relation_proof_bytes_hash(
            EvaluationKeyShareProofFamily::Galois,
            &proof_bytes,
        ),
    );
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family: EvaluationKeyShareProofFamily::Galois,
            public_matrix_seed_hash,
            proof_record: &request["proofRecord"],
            same_secret_statement_record: statement_record,
            constant_commitments: &constant_commitments,
            setup_proof_binding: &setup_proof_binding,
            transported_key_switch_component_material: None,
            proof_bytes: &proof_bytes,
        },
    )
    .expect("returned proof verifies");
    assert_eq!(
        result["statementHash"].as_str().expect("statement hash"),
        verification.statement_hash_hex
    );
    assert_eq!(
        result["relationCommitmentHash"]
            .as_str()
            .expect("relation commitment hash"),
        verification.relation_commitment_hash_hex
    );
    assert_eq!(
        result["tboxCommitmentPrefixHash"]
            .as_str()
            .expect("tbox commitment prefix hash"),
        verification.tbox_commitment_prefix_hash
    );

    let mut rejected_request = request;
    rejected_request["relinearizationSourceCoefficientsByDigit"] =
        serde_json::json!([vec![0_i64; ring_degree]]);
    let error = match generate_evaluation_key_share_lnp_proof_from_request(&rejected_request) {
        Ok(_) => panic!("Galois command must reject relinearization-only source witness material"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("must not be provided for Galois proof generation"),
        "{}",
        error.message
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_component_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_component_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let component_material_set =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);
    let mut transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    add_component_materials_to_public_evaluation_key_material_transport(
        &mut transported_public_evaluation_key_material,
        &[component_material_set],
    );
    transported_public_evaluation_key_material["componentMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_galois_lnp_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_galois_lnp_proofs_from_transported_proof_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let transported_proof_material =
        move_first_galois_key_share_lnp_proof_bytes_to_transport(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_galois_lnp_proof_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_galois_lnp_proof_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut transported_proof_material =
        move_first_galois_key_share_lnp_proof_bytes_to_transport(&mut package);
    transported_proof_material["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("transported evaluation-key proof material hashes do not match chunks")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_galois_lnp_proofs_from_transported_component_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_galois_lnp_proofs_from_transported_component_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let transported_component_material =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareComponentMaterial": transported_component_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_galois_component_material_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_galois_component_material_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut transported_component_material =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);
    transported_component_material["componentMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareComponentMaterial": transported_component_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("transported evaluation-key component material hash metadata does not match supplied chunks")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundTwoAggregateRoots"][0]["roundTwoAggregateRoot"] =
        serde_json::json!(valid_hash('b'));
    rebind_relinearization_key_share_rounds_root(&mut package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationRoundTwoAggregateRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_source_square_binding_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_source_square_binding_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["sourceSquareBindingRoot"] =
        serde_json::json!(valid_hash('d'));
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]
        .as_object_mut()
        .expect("relinearization round-one record")
        .remove("roundOneProofRoot");
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]
        .as_object_mut()
        .expect("relinearization round-one record")
        .remove("roundOneRecordRoot");
    let round_one_proof_root = derive_protocol_hash(
        "RelinearizationKeyShareProofRoot",
        &package["relinearizationKeyShareRounds"]["roundOneRecords"][0],
    )
    .expect("relinearization round-one proof root");
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["roundOneProofRoot"] =
        serde_json::json!(round_one_proof_root);
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["roundOneRecordRoot"] =
        serde_json::json!(valid_hash('c'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert_eq!(
        result["refusedObjects"][0]["message"],
        "sourceSquareBindingRoot does not match the canonical relinearization source-square binding"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["keySwitchSeedHex"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("shared by scheduled level and round")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_one_source_square_aggregate_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_one_source_square_aggregate_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneAggregateRoots"][0]["roundOneSourceSquareAggregateRoot"] =
        serde_json::json!(valid_hash('e'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationRoundOneSourceSquareAggregateRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_source_square_linkage_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_source_square_linkage_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundTwoRecords"][0]["roundOneSourceSquareBindingRoot"] =
        serde_json::json!(valid_hash('f'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert_eq!(
        result["refusedObjects"][0]["message"],
        "relinearization round-two record must bind the accepted round-one record, share, aggregate, and source-square roots"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_source_square_aggregate_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_source_square_aggregate_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundTwoAggregateRoots"][0]["roundTwoSourceSquareAggregateRoot"] =
        serde_json::json!(valid_hash('a'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationRoundTwoSourceSquareAggregateRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_same_secret_family_root_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_same_secret_family_root_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('e'));
    rebind_relinearization_key_share_rounds_root(&mut package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_galois_trustee_specific_key_switch_seed()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_galois_trustee_specific_key_switch_seed",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["galoisKeyShareBatches"][0]["galoisKeyShareProofs"][0]["keySwitchSeedHex"] =
        serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("shared by scheduled rotation and level")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_galois_batch_schedule_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_galois_batch_schedule_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["galoisKeyShareBatches"][0]["requiredGaloisKeySchedule"][0]["rotation"] =
        serde_json::json!(999_u64);
    rebind_galois_key_share_batch_root(&mut package, 0);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_assembly_root_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_assembly_root_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["evaluationKeys"]["relinearizationKeyRoots"][0]["relinearizationKeyRoot"] =
        serde_json::json!(valid_hash('c'));
    rebind_public_evaluation_key_set_hash(&mut package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyRelinearizationKeyRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_missing_and_extra_evaluation_keys() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_missing_and_extra_evaluation_keys",
    );
    let mut missing_galois_key = evaluation_key_proof_container_bearing_collective_setup_package();
    missing_galois_key["evaluationKeys"]["galoisKeyRoots"]
        .as_array_mut()
        .expect("Galois key roots")
        .pop();
    rebind_public_evaluation_key_set_hash(&mut missing_galois_key);
    rebind_collective_setup_package_hash(&mut missing_galois_key);

    let missing_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": missing_galois_key,
    }))
    .expect("verification response");

    assert_eq!(missing_result["verifierStatus"], "refused");
    assert_eq!(
        missing_result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyGaloisKeyCountMismatch"
    );

    let mut extra_generic_key = evaluation_key_proof_container_bearing_collective_setup_package();
    extra_generic_key["evaluationKeys"]["genericKeySwitchKeyRoots"] =
        serde_json::json!([valid_hash('d')]);
    rebind_public_evaluation_key_set_hash(&mut extra_generic_key);
    rebind_collective_setup_package_hash(&mut extra_generic_key);

    let extra_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": extra_generic_key,
    }))
    .expect("verification response");

    assert_eq!(extra_result["verifierStatus"], "refused");
    assert_eq!(
        extra_result["refusedObjects"][0]["reasonCode"],
        "evaluationKeysGenericKeySwitchOutsideProfile"
    );
}

#[test]
fn collective_setup_verifier_refuses_wrong_q_share_prime_list() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_wrong_q_share_prime_list");
    let mut package = minimal_collective_setup_package();
    package["qShare"]["primes"][0] = serde_json::json!(65_537);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(result["refusedObjects"][0]["reasonCode"], "qShareMismatch");
}

#[test]
fn collective_setup_verifier_refuses_malformed_commitment_security_certificate() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_commitment_security_certificate",
    );
    let mut package = minimal_collective_setup_package();
    package["setupCommitmentSecurityCertificate"]["aggregateOpeningBounds"]["thresholdShareOpeningInfinityBound"] =
        serde_json::json!(11_109_u64);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "commitmentSecurityCertificatePayloadMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_commitment_security_certificate_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_commitment_security_certificate_hash_drift",
    );
    let mut package = minimal_collective_setup_package();
    package["setupCommitmentSecurityCertificateHash"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "commitmentSecurityPackageCertificateHashMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_setup_proof_accounting_certificate() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_setup_proof_accounting_certificate",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupProofAccountingCertificate"]["challengeAccounting"]["qromStatus"] =
        serde_json::json!("externally-reviewed");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupProofAccountingCertificatePayloadMismatch"
    );
}

#[test]
fn setup_proof_accounting_certificate_accepts_claim_theorem_accounting() {
    let certificate =
        setup_proof_accounting_certificate_value().expect("setup proof accounting certificate");
    let proof_family_accounting = certificate["proofFamilyAccounting"]
        .as_array()
        .expect("proof family accounting");

    assert_eq!(proof_family_accounting.len(), 5);
    assert_eq!(
        proof_family_accounting[0]["proofFamily"],
        "vss-opening-carry"
    );
    assert_eq!(
        proof_family_accounting[0]["verifierClosedStatus"],
        "relation-transcript-and-bound-checks-verifier-closed"
    );
    assert_eq!(
        proof_family_accounting[0]["accountingStatus"],
        "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted"
    );
    assert!(
        proof_family_accounting[2]["verifierClosedChecks"]
            .as_array()
            .expect("public-key verifier-closed checks")
            .iter()
            .any(|check| check
                .as_str()
                .is_some_and(|text| text.contains("lifted public-key equality")))
    );
    assert!(proof_family_accounting.iter().all(|family| {
        family["claimAccounting"]["qrom"]
            .as_str()
            .is_some_and(|text| text.contains("Fiat-Shamir reduction accounting is accepted"))
    }));

    let tbox_accounting = certificate["tboxAccounting"]
        .as_object()
        .expect("tbox accounting");
    assert_eq!(
        tbox_accounting["accountingStatus"],
        "generated-lower-protocol-tbox-profile-verifier-and-prover-closed"
    );
    assert_eq!(
        tbox_accounting["closedProofFamilies"]
            .as_array()
            .expect("closed tbox proof families")
            .len(),
        5
    );
    assert!(
        tbox_accounting["closedVerifierChecks"]
            .as_array()
            .expect("closed tbox verifier checks")
            .iter()
            .any(|check| check
                .as_str()
                .is_some_and(|text| text.contains("generated lower-protocol tbox suffix")))
    );

    let fiat_shamir_accounting = certificate["fiatShamirTranscriptAccounting"]
        .as_object()
        .expect("Fiat-Shamir transcript accounting");
    assert_eq!(
        fiat_shamir_accounting["accountingStatus"],
        "fiat-shamir-transcript-domain-and-challenge-input-accounting-closed"
    );
    assert_eq!(
        fiat_shamir_accounting["qromReductionStatus"],
        "repo-owned-qrom-reduction-theorem-accepted-for-setup-proof-claim"
    );
    assert!(
        fiat_shamir_accounting["challengeStages"]
            .as_array()
            .expect("Fiat-Shamir challenge stages")
            .iter()
            .any(|stage| stage["stageId"] == "scalar-relation-challenge")
    );
    assert!(
        fiat_shamir_accounting["referenceRows"]
            .as_array()
            .expect("Fiat-Shamir reference rows")
            .iter()
            .any(|reference| reference["document"]
                .as_str()
                .is_some_and(|text| text.starts_with("DFM20_")))
    );

    let response_masking_accounting = certificate["responseMaskingAccounting"]
        .as_object()
        .expect("response masking accounting");
    assert_eq!(
        response_masking_accounting["accountingStatus"],
        "response-mask-bounds-strengthened-verifier-bound-and-zk-accounting-accepted"
    );
    assert_eq!(
        response_masking_accounting["encodingConstraints"]["relationCommitmentEncoding"],
        "public-key and evaluation-key lifted relation commitments use fixed-width signed 32-byte little-endian big-integer coefficients; response vectors remain signed i128"
    );
    let response_families = response_masking_accounting["families"]
        .as_array()
        .expect("response masking families");
    assert_eq!(response_families.len(), 5);
    assert_eq!(
        response_families[0]["fullWidthCoefficientMaskingStatus"],
        "centered-signed-private-vss-message-response-masking-verifier-bound-and-simulator-accounting-accepted"
    );
    assert_eq!(
        response_families[0]["commitmentNoWrapStatus"],
        "three-limb-big-int-no-wrap-bound-recorded"
    );
    assert_eq!(
        response_families[0]["responseProfiles"][0]["maskRandomBits"],
        112
    );
    assert!(
        response_families[0]["responseProfiles"][0]["maskingSlackBits"]
            .as_i64()
            .expect("private VSS coefficient masking slack")
            > 0
    );
    assert_eq!(
        response_families[1]["responseProfiles"][0]["maskRandomBits"],
        80
    );
    assert!(
        response_families[1]["responseProfiles"][0]["maskingSlackBits"]
            .as_i64()
            .expect("same-secret secret masking slack")
            > 0
    );
    assert_eq!(
        response_families[2]["responseProfiles"][0]["maskRandomBits"],
        80
    );
    assert!(
        response_families[2]["responseProfiles"][0]["maskingSlackBits"]
            .as_i64()
            .expect("public-key secret masking slack")
            > 0
    );
    assert_eq!(
        response_families[3]["responseProfiles"][0]["maskRandomBits"],
        80
    );
    assert!(
        response_families[3]["responseProfiles"][0]["maskingSlackBits"]
            .as_i64()
            .expect("relinearization secret masking slack")
            > 0
    );
    assert_eq!(
        response_families[3]["responseProfiles"][2]["responseKind"],
        "round-two-source"
    );
    assert_eq!(
        response_families[3]["responseProfiles"][2]["maskRandomBits"],
        80
    );

    let proof_theorem_accounting = certificate["proofTheoremAccounting"]
        .as_object()
        .expect("proof theorem accounting");
    assert_eq!(
        proof_theorem_accounting["accountingStatus"],
        "repo-owned-setup-proof-soundness-zero-knowledge-and-qrom-accounting-accepted"
    );
    assert_eq!(
        proof_theorem_accounting["qromReductionAccounting"]["compositionStatus"],
        "accepted-for-fixed-five-family-two-stage-setup-profile"
    );
    assert!(
        proof_theorem_accounting["referenceRows"]
            .as_array()
            .expect("proof theorem reference rows")
            .iter()
            .any(|reference| reference["document"]
                .as_str()
                .is_some_and(|text| text.starts_with("LNP22_")))
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_challenge_audit_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_challenge_audit_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupProofAccountingCertificate"]["challengeAccounting"]["challengeSpaceAuditHash"] =
        serde_json::json!(valid_hash('5'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupProofAccountingCertificatePayloadMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_accounting_certificate_hash_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_accounting_certificate_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupProofAccountingCertificateHash"] = serde_json::json!(valid_hash('6'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupProofAccountingPackageCertificateHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_checks_he_security_certificate() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_checks_he_security_certificate");
    let mut package = minimal_collective_setup_package();
    package["heSecurityCertificate"]["assessedRing"]["largestExposedBasisClass"] =
        serde_json::json!("Q_extended");
    rebind_collective_he_security_certificate_hash(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "heSecurityCertificateMismatch"
    );
}

#[test]
fn he_security_certificate_accepts_direct_setup_evaluator_parameter_boundary() {
    let certificate = accepted_he_security_certificate_value().expect("HE security certificate");

    assert_eq!(
        certificate["parameterBoundary"]["certificateStatus"],
        "accepted-for-direct-setup-and-evaluator-HE-parameter-boundary"
    );
    assert_eq!(certificate["acceptedForDirectEvaluatorReplay"], true);
    assert_eq!(certificate["acceptedForTargetDecryption"], false);
    assert_eq!(
        certificate["targetDecryptionStatus"]["targetDecryptionReadiness"],
        "refused-until-q-target-certificate-closes"
    );
    assert_eq!(
        certificate["errorDistribution"]["certificateStatus"],
        "accepted-for-direct-evaluator-replay-HE-parameter-boundary"
    );
    assert!(
        certificate["statusLabels"]
            .as_array()
            .expect("HE certificate status labels")
            .iter()
            .any(|label| label
                .as_str()
                .is_some_and(|text| text == "DirectSetupEvaluatorHeParameterBoundaryAccepted"))
    );
}

#[test]
fn collective_setup_verifier_refuses_he_security_certificate_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_he_security_certificate_hash_drift",
    );
    let mut package = minimal_collective_setup_package();
    package["heSecurityCertificateHash"] = serde_json::json!(valid_hash('7'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "packageHeSecurityCertificateHashMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_requires_setup_key_correctness_certificate_for_evaluation_keys()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_requires_setup_key_correctness_certificate_for_evaluation_keys",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package")
        .remove("setupKeyCorrectnessCertificate");
    package
        .as_object_mut()
        .expect("setup package")
        .remove("setupKeyCorrectnessCertificateHash");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "pending");
    assert!(
        result["missingObjects"]
            .as_array()
            .expect("pending objects")
            .iter()
            .any(|object| object == "setupKeyCorrectnessCertificate")
    );
}

#[test]
fn terminal_profile_ring_gate_refuses_reduced_public_key_material() {
    let package = serde_json::json!({
        "vssCoefficientCommitmentMaterial": {
            "ringDegree": POLYNOMIAL_DEGREE,
            "ringDegreeStatus": "profile-ring",
        },
        "sameSecretProofs": {
            "proofRecords": [
                { "ringDegree": POLYNOMIAL_DEGREE }
            ],
        },
        "publicKeyShareMaterial": {
            "ringDegree": 8,
        },
    });

    let response = verify_profile_ring_material(&package)
        .expect("profile-ring verification")
        .expect("reduced public-key material refusal");

    assert_eq!(response["verifierStatus"], "outsideProfile");
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    assert_eq!(
        response["refusedObjects"][0]["objectPath"],
        "setupPackage.publicKeyShareMaterial.ringDegree"
    );
}

#[test]
fn terminal_profile_ring_gate_refuses_reduced_evaluation_key_records() {
    let package = serde_json::json!({
        "vssCoefficientCommitmentMaterial": {
            "ringDegree": POLYNOMIAL_DEGREE,
            "ringDegreeStatus": "profile-ring",
        },
        "sameSecretProofs": {
            "proofRecords": [
                { "ringDegree": POLYNOMIAL_DEGREE }
            ],
        },
        "publicKeyShareMaterial": {
            "ringDegree": POLYNOMIAL_DEGREE,
        },
        "publicKeyShareLnpProofs": {
            "proofRecords": [
                { "ringDegree": POLYNOMIAL_DEGREE }
            ],
        },
        "collectivePublicKey": {
            "ringDegree": POLYNOMIAL_DEGREE,
        },
        "relinearizationKeyShareRounds": {
            "roundOneRecords": [
                { "ringDegree": POLYNOMIAL_DEGREE }
            ],
            "roundTwoRecords": [
                { "ringDegree": 8 }
            ],
        },
        "galoisKeyShareBatches": [
            {
                "galoisKeyShareProofs": [
                    { "ringDegree": POLYNOMIAL_DEGREE }
                ]
            }
        ],
    });

    let response = verify_profile_ring_material(&package)
        .expect("profile-ring verification")
        .expect("reduced evaluation-key proof refusal");

    assert_eq!(response["verifierStatus"], "outsideProfile");
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    assert_eq!(
        response["refusedObjects"][0]["objectPath"],
        "setupPackage.relinearizationKeyShareRounds.roundTwoRecords.ringDegree"
    );
}

#[test]
fn setup_key_correctness_certificate_binds_accepted_theorem_statement() {
    let package = serde_json::json!({
        "setupContext": {
            "ceremonyId": "ceremony-main",
            "manifestHash": valid_hash('1'),
            "rosterHash": valid_hash('2'),
            "setupProfileHash": valid_hash('3'),
            "qShareHash": valid_hash('4'),
            "carryAwareVssShareRelationProfileHash": valid_hash('5'),
            "commitmentProfileHash": valid_hash('6'),
            "setupEpoch": "setup-epoch-1",
        },
        "collectivePublicKey": {
            "collectivePublicKeyRoot": valid_hash('7'),
        },
        "publicKeyShares": {
            "publicKeyShareSetRoot": valid_hash('8'),
        },
        "publicKeyShareProofs": {
            "publicKeyShareProofSetRoot": valid_hash('9'),
        },
        "publicKeyShareMaterial": {
            "publicKeyShareMaterialSetRoot": valid_hash('a'),
        },
        "publicKeyShareLnpProofs": {
            "publicKeyShareLnpProofSetRoot": valid_hash('b'),
        },
        "evaluationKeys": {
            "evaluationKeySetHash": valid_hash('c'),
        },
        "evaluatorKeySchedule": {
            "evaluatorKeyScheduleRoot": valid_hash('d'),
            "requiredGaloisSetHash": valid_hash('e'),
        },
        "relinearizationKeyShareRounds": {
            "relinearizationKeyShareRoundsRoot": valid_hash('f'),
        },
        "galoisKeyShareBatches": [
            {
                "trusteeIdentity": "trustee-0",
                "trusteeRosterPosition": 0,
                "galoisKeyShareBatchRoot": valid_hash('0'),
            }
        ],
        "setupProofAccountingCertificateHash": valid_hash('1'),
        "heSecurityCertificateHash": valid_hash('2'),
    });

    let certificate = setup_key_correctness_certificate_value(&package)
        .expect("setup key correctness certificate");

    assert_eq!(
        certificate["keyCorrectnessTheorem"]["theoremStatus"],
        "repo-owned-key-correctness-theorem-accepted-for-verifier-recomputed-roots"
    );
    assert_eq!(
        certificate["collectivePublicKey"]["status"],
        "collective-public-key-coefficients-recomputed-from-public-key-share-material-and-LNP-proof-roots"
    );
    assert_eq!(
        certificate["publicEvaluationKeys"]["status"],
        "public-evaluation-key-roots-recomputed-from-frozen-schedule-and-proof-bearing-relinearization-and-galois-records"
    );
    assert!(
        certificate["keyCorrectnessTheorem"]["checkedByVerifier"]
            .as_array()
            .expect("checked theorem clauses")
            .iter()
            .any(|clause| {
                clause
                    == "transported public evaluation-key runtime material is verified against evaluationKeys when supplied"
            })
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_setup_key_correctness_certificate() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_setup_key_correctness_certificate",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupKeyCorrectnessCertificate"]["claimBoundary"] =
        serde_json::json!("weakened-key-correctness-claim");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupKeyCorrectnessCertificatePayloadMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_certificate_hash_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_certificate_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupKeyCorrectnessCertificate"]["setupKeyCorrectnessCertificateHash"] =
        serde_json::json!(valid_hash('8'));
    package["setupKeyCorrectnessCertificateHash"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupKeyCorrectnessCertificateHashMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_package_hash_drift()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_package_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupKeyCorrectnessCertificateHash"] = serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupKeyCorrectnessPackageCertificateHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_requires_active_static_setup_theorem_certificate() {
    let mut package = minimal_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package")
        .remove("activeStaticSetupTheoremCertificate");
    package
        .as_object_mut()
        .expect("setup package")
        .remove("activeStaticSetupTheoremCertificateHash");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "pending");
    assert!(
        result["missingObjects"]
            .as_array()
            .expect("pending objects")
            .iter()
            .any(|object| object == "activeStaticSetupTheoremCertificate")
    );
}

#[test]
fn active_static_setup_theorem_certificate_records_accepted_claim_boundary() {
    let mut package = minimal_collective_setup_package();
    package["setupKeyCorrectnessCertificateHash"] = serde_json::json!(valid_hash('c'));
    let certificate = active_static_setup_theorem_certificate_value(&package)
        .expect("active-static setup theorem certificate");

    assert_eq!(
        certificate["objectType"],
        "ActiveStaticSetupTheoremCertificate"
    );
    assert_eq!(
        certificate["adversaryModel"]["corruptionTiming"],
        "active-static"
    );
    assert_eq!(certificate["livenessModel"]["model"], "secure-with-abort");
    assert_eq!(
        certificate["dependencyHashes"]["setupKeyCorrectnessCertificateHash"],
        package["setupKeyCorrectnessCertificateHash"]
    );
    assert_eq!(
        certificate["claimBoundary"]["certificateStatus"],
        "active-static-secure-with-abort-theorem-accepted"
    );
    let remaining_dependencies = certificate["claimBoundary"]["remainingDependencies"]
        .as_array()
        .expect("remaining theorem dependencies");
    assert!(remaining_dependencies.is_empty());
    assert!(remaining_dependencies.iter().all(|dependency| {
        dependency
            .as_str()
            .is_some_and(|text| !text.contains("AB-DLOP/LNP soundness"))
    }));
    assert!(remaining_dependencies.iter().all(|dependency| {
        dependency
            .as_str()
            .is_some_and(|text| !text.contains("Fiat-Shamir/QROM"))
    }));
    assert!(remaining_dependencies.iter().all(|dependency| {
        dependency
            .as_str()
            .is_some_and(|text| !text.contains("tbox"))
    }));
    assert_eq!(
        certificate["claimBoundary"]["completionBoundary"],
        "external validation, independent audit, and third-party proof review are not setup completion prerequisites"
    );
}

#[test]
fn collective_setup_verifier_checks_active_static_setup_theorem_certificate() {
    let mut package = minimal_collective_setup_package();
    package["activeStaticSetupTheoremCertificate"]["claimBoundary"]["completionBoundary"] =
        serde_json::json!("external-review-required");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "activeStaticSetupTheoremCertificatePayloadMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_active_static_setup_theorem_certificate_hash_drift() {
    let mut package = minimal_collective_setup_package();
    package["activeStaticSetupTheoremCertificate"]["activeStaticSetupTheoremCertificateHash"] =
        serde_json::json!(valid_hash('a'));
    package["activeStaticSetupTheoremCertificateHash"] = serde_json::json!(valid_hash('a'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "activeStaticSetupTheoremCertificateHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_active_static_setup_theorem_package_hash_drift() {
    let mut package = minimal_collective_setup_package();
    package["activeStaticSetupTheoremCertificateHash"] = serde_json::json!(valid_hash('b'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "activeStaticSetupTheoremPackageCertificateHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_non_binary_setup_transport() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_non_binary_setup_transport");
    let mut package = minimal_collective_setup_package();
    package["setupTransportCertificate"]["largeObjectEncoding"] = serde_json::json!("json");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "transportEncodingMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_setup_transport_manifest() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_setup_transport_manifest",
    );
    let mut missing_chunk_package = minimal_collective_setup_package();
    missing_chunk_package["setupTransportCertificate"]["chunkHashes"]
        .as_array_mut()
        .expect("chunk hashes")
        .pop();
    rebind_collective_setup_package_hash(&mut missing_chunk_package);

    let missing_chunk_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": missing_chunk_package,
        }))
        .expect("verification response");
    assert_eq!(missing_chunk_result["verifierStatus"], "refused");
    assert_eq!(
        missing_chunk_result["refusedObjects"][0]["reasonCode"],
        "transportChunkHashCountMismatch"
    );

    let mut wrong_root_package = minimal_collective_setup_package();
    wrong_root_package["setupTransportCertificate"]["chunkRoot"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut wrong_root_package);

    let wrong_root_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_root_package,
    }))
    .expect("verification response");
    assert_eq!(wrong_root_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_root_result["refusedObjects"][0]["reasonCode"],
        "transportChunkRootMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_setup_transport_certificate_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_setup_transport_certificate_hash_drift",
    );
    let mut package = minimal_collective_setup_package();
    package["setupTransportCertificateHash"] = serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "transportPackageCertificateHashMismatch"
    );
}

#[test]
fn terminal_profile_ring_gate_refuses_reduced_vss_material() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("terminal_profile_ring_gate_refuses_reduced_vss_material");
    let package = serde_json::json!({
        "vssCoefficientCommitmentMaterial": {
            "ringDegree": 8,
            "ringDegreeStatus": "development-reduced-ring",
        },
    });

    let response = verify_profile_ring_material(&package)
        .expect("profile-ring verification")
        .expect("reduced VSS material refusal");

    assert_eq!(response["ok"], false);
    assert_eq!(response["verifierStatus"], "outsideProfile");
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

fn minimal_collective_setup_package() -> serde_json::Value {
    MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_minimal_collective_setup_package)
        .clone()
}

fn build_minimal_collective_setup_package() -> serde_json::Value {
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
    let setup_transport_certificate =
        setup_transport_certificate_fixture(&profile, &vss_coefficient_commitment_material);
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

    package
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

fn setup_transport_certificate_fixture(
    profile: &serde_json::Value,
    vss_coefficient_commitment_material: &serde_json::Value,
) -> serde_json::Value {
    let chunk_size_bytes = 1_048_576_u64;
    let total_byte_length =
        profile["publicVssCommitmentMaterialSizeProfile"]["fullMaterialCoefficientBytes"]
            .as_u64()
            .expect("public VSS material byte length");
    let chunk_count = total_byte_length.div_ceil(chunk_size_bytes);
    let full_object_hash = derive_protocol_hash(
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
            "fullObjectHash": full_object_hash,
        }),
    )
    .expect("setup transport chunk root");
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
        "transportedObjects": [
            {
                "objectType": "SetupTransportedObject",
                "objectVersion": 1,
                "objectName": "vssCoefficientCommitmentMaterial",
                "objectRole": "public-vss-coefficient-commitment-material",
                "objectRoot": vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"],
                "byteLength": total_byte_length,
                "chunkStartIndex": 0_u64,
                "chunkCount": chunk_count,
                "chunkRoot": chunk_root,
                "fullObjectHash": full_object_hash,
                "encoding": "binary",
                "loadingPolicy": "stream-verified-before-object-use",
            }
        ],
        "chunkHashes": chunk_hashes,
        "chunkRoot": chunk_root,
        "fullObjectHash": full_object_hash,
    });
    let certificate_hash = derive_protocol_hash("SetupTransportCertificateHash", &certificate)
        .expect("setup transport certificate hash");
    certificate["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);

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
) -> (serde_json::Value, serde_json::Value) {
    let development_ring_degree = 8_usize;
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
                    development_ring_degree,
                );
                let coefficient_message_wide = coefficient_message
                    .iter()
                    .map(|coefficient| u128::from(*coefficient))
                    .collect::<Vec<_>>();
                let randomness_by_column = accepted_vss_randomness_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    development_ring_degree,
                );
                let commitment = compute_setup_commitment_for_tests(
                    public_matrix_seed_hash,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    &coefficient_message_wide,
                    &randomness_by_column,
                    development_ring_degree,
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
        "ringDegree": development_ring_degree,
        "ringDegreeStatus": "development-reduced-ring",
        "materialRecordCount": coefficient_commitment_material.len(),
        "coefficientCommitments": coefficient_commitment_material,
    });
    material_set["vssCoefficientCommitmentMaterialRoot"] = serde_json::json!(
        derive_protocol_hash("VssCoefficientCommitmentMaterialRoot", &material_set)
            .expect("VSS coefficient commitment material root")
    );

    (commitment_set, material_set)
}

fn accepted_vss_coefficient_message_fixture(
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

fn accepted_vss_secret_coefficient_fixture(
    source_trustee_roster_position: u64,
    coefficient_position: usize,
) -> i64 {
    match (source_trustee_roster_position as usize + coefficient_position) % 3 {
        0 => -1,
        1 => 0,
        _ => 1,
    }
}

fn accepted_vss_randomness_fixture(
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
            "proofFamily": "same-secret-consistency",
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
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
            "proofFamily": "same-secret-consistency",
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
        "proofFamily": "same-secret-consistency",
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

fn same_secret_proof_bearing_collective_setup_package() -> serde_json::Value {
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

fn same_secret_proofs_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let mut proof_records = Vec::new();
    let mut same_secret_proof_roots = Vec::new();
    for trustee_roster_position in 0..10_u64 {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let statement_record = &statement_records[trustee_roster_position as usize];
        let constant_commitments =
            same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
        let ring_degree = constant_commitments
            .first()
            .expect("constant commitment")
            .ring_degree;
        let witness = SameSecretLnpProofWitness {
            secret_coefficients: (0..ring_degree)
                .map(|coefficient_position| {
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    )
                })
                .collect(),
            opening_randomness_by_limb: (0..DATA_PRIMES.len())
                .map(|rns_limb_index| {
                    accepted_vss_randomness_fixture(
                        trustee_roster_position,
                        rns_limb_index,
                        0,
                        ring_degree,
                    )
                })
                .collect(),
        };
        let proof_randomness_seed_hex = derive_protocol_hash(
            "SameSecretProofRoot",
            &serde_json::json!({
                "fixture": "same-secret-internal-proof-randomness",
                "trusteeRosterPosition": trustee_roster_position,
            }),
        )
        .expect("same-secret proof randomness seed");
        let proof_bytes = generate_same_secret_lnp_relation_proof(
            public_matrix_seed_hash,
            statement_record,
            &constant_commitments,
            &setup_proof_binding_for_test_package(package),
            &witness,
            &proof_randomness_seed_hex,
        )
        .expect("same-secret proof bytes");
        let verification = verify_same_secret_lnp_relation_proof(
            public_matrix_seed_hash,
            statement_record,
            &constant_commitments,
            &setup_proof_binding_for_test_package(package),
            &proof_bytes,
        )
        .expect("same-secret proof verification");
        let proof_size_bytes = u64::try_from(proof_bytes.len()).expect("proof size bytes");
        let proof_bytes_hash = same_secret_lnp_relation_proof_bytes_hash(&proof_bytes);
        let same_secret_tbox_parameter_profile_hash =
            super::super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()
                .expect("same-secret tbox parameter profile hash");
        let mut proof_record = serde_json::json!({
            "objectType": "SameSecretProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "same-secret-consistency",
            "proofVerificationStatus": SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
            "proofModelStatus": SAME_SECRET_LNP_PROOF_MODEL_STATUS,
            "sameSecretTboxParameterProfileHash": same_secret_tbox_parameter_profile_hash,
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "qShareHash": setup_context["qShareHash"],
            "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": setup_context["commitmentProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": statement_record["sameSecretProofFamilyBindingRoot"],
            "setupProofBinding": setup_proof_binding_for_test_package(package),
            "statementHash": verification.statement_hash_hex,
            "relationCommitmentHash": verification.relation_commitment_hash_hex,
            "tboxCommitmentPrefixHash": verification.tbox_commitment_prefix_hash,
            "z34SeedMaterialHash": verification.z34_seed_material_hash,
            "z34ChallengeSeedHash": verification.z34_challenge_seed_hash,
            "z34ChallengeTailHash": verification.z34_challenge_tail_hash,
            "z34ChallengeRowDomainHash": verification.z34_challenge_row_domain_hash,
            "z34ChallengeZ3RowSetHash": verification.z34_challenge_z3_row_set_hash,
            "z34ChallengeZ4RowSetHash": verification.z34_challenge_z4_row_set_hash,
            "tboxLowerProtocolChallengeHash": verification.tbox_lower_protocol_challenge_hash,
            "z34Z3CheckWindowHash": verification.z34_z3_check_window_hash,
            "z34Z4CheckWindowHash": verification.z34_z4_check_window_hash,
            "z34Z3L2SquaredDecimal": verification.z34_z3_l2_squared_decimal,
            "z34Z4InfinityNormDecimal": verification.z34_z4_infinity_norm_decimal,
            "challenge": verification.challenge.to_string(),
            "proofSizeBytes": proof_size_bytes,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesHex": to_hex(&proof_bytes),
        });
        proof_record["sameSecretProofRoot"] = serde_json::json!(
            derive_protocol_hash("SameSecretProofRoot", &proof_record)
                .expect("same-secret proof root")
        );
        same_secret_proof_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
        }));
        proof_records.push(proof_record);
    }
    let mut proof_set = serde_json::json!({
        "objectType": "SameSecretProofSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "commitmentProfileId": "SealedLattice-BDLOP-LNP-Commitment-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "same-secret-consistency",
        "proofVerificationStatus": SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": SAME_SECRET_LNP_PROOF_MODEL_STATUS,
        "sameSecretTboxParameterProfileHash": super::super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()
            .expect("same-secret tbox parameter profile hash"),
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "vssCoefficientCommitmentMaterialRoot": package["vssCoefficientCommitmentMaterial"]["vssCoefficientCommitmentMaterialRoot"],
        "setupProofBinding": setup_proof_binding_for_test_package(package),
        "sameSecretProofRoots": same_secret_proof_roots,
        "proofRecords": proof_records,
    });
    proof_set["sameSecretProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("SameSecretProofRoot", &proof_set)
            .expect("same-secret proof set root")
    );

    proof_set
}

fn move_same_secret_proof_bytes_to_transport(package: &mut serde_json::Value) -> serde_json::Value {
    let proof_records = package["sameSecretProofs"]["proofRecords"]
        .as_array_mut()
        .expect("same-secret proof records");
    let mut proof_materials = Vec::new();
    let mut proof_roots = Vec::new();
    for proof_record in proof_records {
        let proof_bytes_hex = proof_record["proofBytesHex"]
            .as_str()
            .expect("embedded proof bytes")
            .to_string();
        let proof_bytes = decode_hex(&proof_bytes_hex).expect("proof bytes");
        let chunks = proof_bytes_transport_chunks(proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            "same-secret-consistency",
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("same-secret proof transport hashes");
        let proof_size_bytes = proof_record["proofSizeBytes"]
            .as_u64()
            .expect("proof size bytes");
        let proof_bytes_hash = proof_record["proofBytesHash"]
            .as_str()
            .expect("proof bytes hash")
            .to_string();
        let statement_hash = proof_record["statementHash"]
            .as_str()
            .expect("statement hash")
            .to_string();
        let relation_commitment_hash = proof_record["relationCommitmentHash"]
            .as_str()
            .expect("relation commitment hash")
            .to_string();
        let tbox_commitment_prefix_hash = proof_record["tboxCommitmentPrefixHash"]
            .as_str()
            .expect("tbox commitment prefix hash")
            .to_string();
        let trustee_identity = proof_record["trusteeIdentity"]
            .as_str()
            .expect("trustee identity")
            .to_string();
        let trustee_roster_position = proof_record["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position");
        let proof_material_root =
            setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
                setup_profile_id: "CollectiveBgvSetup-v1",
                proof_family: "same-secret-consistency",
                trustee_identity: &trustee_identity,
                trustee_roster_position,
                statement_hash_hex: &statement_hash,
                relation_commitment_hash_hex: &relation_commitment_hash,
                tbox_commitment_prefix_hash: &tbox_commitment_prefix_hash,
                proof_size_bytes,
                proof_bytes_hash: &proof_bytes_hash,
                transport_hashes: &transport_hashes,
            })
            .expect("same-secret proof material root");
        let proof_record_object = proof_record
            .as_object_mut()
            .expect("same-secret proof record object");
        proof_record_object.remove("proofBytesHex");
        proof_record_object.remove("sameSecretProofRoot");
        proof_record["proofBytesEncoding"] = serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING);
        proof_record["proofMaterialRoot"] = serde_json::json!(proof_material_root);
        proof_record["proofChunkSizeBytes"] =
            serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
        proof_record["proofChunkCount"] = serde_json::json!(transport_hashes.chunk_hashes.len());
        proof_record["proofTotalByteLength"] =
            serde_json::json!(transport_hashes.total_byte_length);
        proof_record["proofFullObjectHash"] = serde_json::json!(transport_hashes.full_object_hash);
        proof_record["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
        proof_record["proofChunkHashes"] = serde_json::json!(transport_hashes.chunk_hashes.clone());
        proof_record["sameSecretProofRoot"] = serde_json::json!(
            derive_protocol_hash("SameSecretProofRoot", proof_record)
                .expect("same-secret proof root")
        );
        proof_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
        }));
        proof_materials.push(serde_json::json!({
            "objectType": "SetupTransportedSameSecretProofMaterial",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "same-secret-consistency",
            "proofMaterialRoot": proof_record["proofMaterialRoot"],
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": proof_record["proofFullObjectHash"],
            "chunkHashes": proof_record["proofChunkHashes"],
            "chunkRoot": proof_record["proofChunkRoot"],
            "chunks": chunks
                .into_iter()
                .enumerate()
                .map(|(chunk_index, chunk)| serde_json::json!({
                    "chunkIndex": chunk_index,
                    "bytesHex": to_hex(&chunk),
                }))
                .collect::<Vec<_>>(),
        }));
    }
    package["sameSecretProofs"]["sameSecretProofRoots"] = serde_json::json!(proof_roots);
    rebind_collective_same_secret_proof_set_root(package);

    serde_json::json!({
        "objectType": "SetupTransportedSameSecretProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "same-secret-consistency",
        "proofMaterials": proof_materials,
    })
}

fn move_public_key_share_lnp_proof_bytes_to_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_records = package["publicKeyShareLnpProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key LNP proof records");
    let mut proof_materials = Vec::new();
    let mut proof_roots = Vec::new();
    for proof_record in proof_records {
        let proof_bytes_hex = proof_record["proofBytesHex"]
            .as_str()
            .expect("embedded public-key proof bytes")
            .to_string();
        let proof_bytes = decode_hex(&proof_bytes_hex).expect("public-key proof bytes");
        let chunks = proof_bytes_transport_chunks(proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            "public-key-share",
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("public-key proof transport hashes");
        let proof_size_bytes = proof_record["proofSizeBytes"]
            .as_u64()
            .expect("proof size bytes");
        let proof_bytes_hash = proof_record["proofBytesHash"]
            .as_str()
            .expect("proof bytes hash")
            .to_string();
        let statement_hash = proof_record["statementHash"]
            .as_str()
            .expect("statement hash")
            .to_string();
        let relation_commitment_hash = proof_record["relationCommitmentHash"]
            .as_str()
            .expect("relation commitment hash")
            .to_string();
        let tbox_commitment_prefix_hash = proof_record["tboxCommitmentPrefixHash"]
            .as_str()
            .expect("tbox commitment prefix hash")
            .to_string();
        let trustee_identity = proof_record["trusteeIdentity"]
            .as_str()
            .expect("trustee identity")
            .to_string();
        let trustee_roster_position = proof_record["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position");
        let proof_material_root =
            setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
                setup_profile_id: "CollectiveBgvSetup-v1",
                proof_family: "public-key-share",
                trustee_identity: &trustee_identity,
                trustee_roster_position,
                statement_hash_hex: &statement_hash,
                relation_commitment_hash_hex: &relation_commitment_hash,
                tbox_commitment_prefix_hash: &tbox_commitment_prefix_hash,
                proof_size_bytes,
                proof_bytes_hash: &proof_bytes_hash,
                transport_hashes: &transport_hashes,
            })
            .expect("public-key proof material root");
        let proof_record_object = proof_record
            .as_object_mut()
            .expect("public-key LNP proof record object");
        proof_record_object.remove("proofBytesHex");
        proof_record_object.remove("publicKeyShareLnpProofRoot");
        proof_record["proofBytesEncoding"] = serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING);
        proof_record["proofMaterialRoot"] = serde_json::json!(proof_material_root);
        proof_record["proofChunkSizeBytes"] =
            serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
        proof_record["proofChunkCount"] = serde_json::json!(transport_hashes.chunk_hashes.len());
        proof_record["proofTotalByteLength"] =
            serde_json::json!(transport_hashes.total_byte_length);
        proof_record["proofFullObjectHash"] = serde_json::json!(transport_hashes.full_object_hash);
        proof_record["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
        proof_record["proofChunkHashes"] = serde_json::json!(transport_hashes.chunk_hashes.clone());
        proof_record["publicKeyShareLnpProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", proof_record)
                .expect("public-key LNP proof root")
        );
        proof_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareLnpProofRoot": proof_record["publicKeyShareLnpProofRoot"],
        }));
        proof_materials.push(serde_json::json!({
            "objectType": "SetupTransportedPublicKeyShareProofMaterial",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "public-key-share",
            "proofMaterialRoot": proof_record["proofMaterialRoot"],
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": proof_record["proofFullObjectHash"],
            "chunkHashes": proof_record["proofChunkHashes"],
            "chunkRoot": proof_record["proofChunkRoot"],
            "chunks": chunks
                .into_iter()
                .enumerate()
                .map(|(chunk_index, chunk)| serde_json::json!({
                    "chunkIndex": chunk_index,
                    "bytesHex": to_hex(&chunk),
                }))
                .collect::<Vec<_>>(),
        }));
    }
    package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofRoots"] =
        serde_json::json!(proof_roots);
    rebind_collective_public_key_lnp_proof_roots(package);

    serde_json::json!({
        "objectType": "SetupTransportedPublicKeyShareProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofMaterials": proof_materials,
    })
}

fn proof_bytes_transport_chunks(proof_bytes: Vec<u8>) -> Vec<Vec<u8>> {
    let chunk_size = usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES)
        .expect("proof transport chunk size");
    proof_bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect()
}

fn setup_proof_binding_for_test_package(package: &serde_json::Value) -> serde_json::Value {
    let profile = describe_collective_bgv_setup_profile().expect("setup profile");
    assert_eq!(
        package["setupContext"]["setupProfileHash"],
        profile["setupProfileHash"]
    );
    setup_proof_record_binding_value(
        "CollectiveBgvSetup-v1",
        profile["setupProofProfileHash"]
            .as_str()
            .expect("setup proof profile hash"),
    )
    .expect("setup proof record binding")
}

fn public_key_share_lnp_proof_bearing_collective_setup_package() -> serde_json::Value {
    PUBLIC_KEY_SHARE_LNP_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_public_key_share_lnp_proof_bearing_collective_setup_package)
        .clone()
}

fn build_public_key_share_lnp_proof_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = same_secret_proof_bearing_collective_setup_package();
    replace_public_key_share_hashes_with_material_hashes(&mut package);
    package["publicKeyShareMaterial"] = public_key_share_material_object(&package);
    package["publicKeyShareLnpProofs"] = public_key_share_lnp_proofs_object(&package);
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

fn collective_public_key_bearing_collective_setup_package() -> serde_json::Value {
    COLLECTIVE_PUBLIC_KEY_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_collective_public_key_bearing_collective_setup_package)
        .clone()
}

fn build_collective_public_key_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = public_key_share_lnp_proof_bearing_collective_setup_package();
    package["collectivePublicKey"] = collective_public_key_object(&package);
    package["collectivePublicKeyRoot"] =
        package["collectivePublicKey"]["collectivePublicKeyRoot"].clone();
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

fn evaluation_key_proof_container_bearing_collective_setup_package() -> serde_json::Value {
    evaluation_key_proof_container_bearing_collective_setup_package_ref().clone()
}

fn evaluation_key_proof_container_bearing_collective_setup_package_ref()
-> &'static serde_json::Value {
    EVALUATION_KEY_PROOF_CONTAINER_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_evaluation_key_proof_container_bearing_collective_setup_package)
}

fn build_evaluation_key_proof_container_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = collective_public_key_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"] = relinearization_key_share_rounds_object(&package);
    package["galoisKeyShareBatches"] = galois_key_share_batches_object(&package);
    package["evaluationKeys"] = public_evaluation_key_set_object(&package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

struct EvaluationKeyShareFixtureMaterial {
    component_b_by_digit: Vec<Vec<Vec<u64>>>,
    component_vector_entries: Vec<serde_json::Value>,
    component_vector_root: String,
    error_coefficients_by_digit: Vec<Vec<i64>>,
    relinearization_source_coefficients_by_digit: Vec<Vec<i128>>,
}

fn evaluation_key_share_fixture_material(
    proof_family: EvaluationKeyShareProofFamily,
    trustee_roster_position: u64,
    level: u64,
    rotation: Option<u64>,
    ring_degree: usize,
    key_switch_seed_hex: &str,
    relinearization_source_coefficients: Option<&[i128]>,
) -> EvaluationKeyShareFixtureMaterial {
    let level = usize::try_from(level).expect("level fits usize");
    let secret_coefficients =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
    let secret_i128 = secret_coefficients
        .iter()
        .map(|coefficient| i128::from(*coefficient))
        .collect::<Vec<_>>();
    let key_switch_domain = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => "relinearization".to_string(),
        EvaluationKeyShareProofFamily::Galois => {
            format!("galois-{}", rotation.expect("Galois rotation"))
        }
    };
    let base_source = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => relinearization_source_coefficients
            .expect("relinearization source coefficients")
            .to_vec(),
        EvaluationKeyShareProofFamily::Galois => automorphism_i128_for_evaluation_key_fixture(
            &secret_i128,
            usize::try_from(rotation.expect("Galois rotation")).expect("rotation fits usize"),
        )
        .expect("Galois source"),
    };
    let mut component_b_by_digit = Vec::new();
    let mut error_coefficients_by_digit = Vec::new();
    let mut relinearization_source_coefficients_by_digit = Vec::new();
    for digit_index in 0..=level {
        let error_coefficients = evaluation_key_error_coefficients_for_fixture(
            proof_family,
            trustee_roster_position,
            level,
            rotation,
            digit_index,
            ring_degree,
        );
        let component_b_by_limb = (0..=level)
            .map(|rns_limb_index| {
                let source_for_limb = if rns_limb_index == digit_index {
                    base_source.clone()
                } else {
                    vec![0_i128; ring_degree]
                };
                key_switch_component_b_for_evaluation_key_fixture(KeySwitchComponentBFixtureInput {
                    key_switch_domain: &key_switch_domain,
                    key_switch_seed_hex,
                    digit_index,
                    source_coefficients: &source_for_limb,
                    secret_coefficients: &secret_coefficients,
                    error_coefficients: &error_coefficients,
                    modulus: DATA_PRIMES[rns_limb_index],
                    ring_degree,
                })
                .expect("evaluation-key component b")
            })
            .collect::<Vec<_>>();
        component_b_by_digit.push(component_b_by_limb);
        error_coefficients_by_digit.push(error_coefficients);
        if proof_family == EvaluationKeyShareProofFamily::Relinearization {
            relinearization_source_coefficients_by_digit.push(base_source.clone());
        }
    }
    let (component_vector_entries, component_vector_root) = evaluation_key_component_vector_entries(
        proof_family,
        &key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &component_b_by_digit,
    );

    EvaluationKeyShareFixtureMaterial {
        component_b_by_digit,
        component_vector_entries,
        component_vector_root,
        error_coefficients_by_digit,
        relinearization_source_coefficients_by_digit,
    }
}

fn evaluation_key_secret_coefficients_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
) -> Vec<i64> {
    (0..ring_degree)
        .map(|coefficient_position| {
            accepted_vss_secret_coefficient_fixture(trustee_roster_position, coefficient_position)
        })
        .collect()
}

fn evaluation_key_secret_coefficients_i128_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
) -> Vec<i128> {
    evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree)
        .into_iter()
        .map(i128::from)
        .collect()
}

fn aggregate_evaluation_key_secret_coefficients_for_fixture(ring_degree: usize) -> Vec<i128> {
    let mut aggregate = vec![0_i128; ring_degree];
    for trustee_roster_position in 0..10_u64 {
        let secret = evaluation_key_secret_coefficients_i128_for_fixture(
            trustee_roster_position,
            ring_degree,
        );
        for (aggregate_coefficient, secret_coefficient) in aggregate.iter_mut().zip(secret.iter()) {
            *aggregate_coefficient += *secret_coefficient;
        }
    }

    aggregate
}

fn round_one_aggregate_source_coefficients_for_generation(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &serde_json::Value,
    ring_degree: usize,
    digit_count: usize,
) -> Vec<Vec<i128>> {
    if proof_family != EvaluationKeyShareProofFamily::Relinearization
        || proof_record["objectType"].as_str() != Some("RelinearizationKeyShareRoundTwo")
    {
        return Vec::new();
    }

    vec![aggregate_evaluation_key_secret_coefficients_for_fixture(ring_degree); digit_count]
}

fn relinearization_round_one_source_coefficients_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
) -> Vec<i128> {
    evaluation_key_secret_coefficients_i128_for_fixture(trustee_roster_position, ring_degree)
}

fn relinearization_round_two_source_coefficients_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
) -> Vec<i128> {
    let trustee_secret =
        evaluation_key_secret_coefficients_i128_for_fixture(trustee_roster_position, ring_degree);
    let aggregate_secret = aggregate_evaluation_key_secret_coefficients_for_fixture(ring_degree);

    negacyclic_i128_product_for_evaluation_key_fixture(&trustee_secret, &aggregate_secret)
        .expect("round-two aggregate relinearization source")
}

fn legacy_relinearization_source_square_coefficients_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
) -> Vec<i128> {
    let trustee_secret =
        evaluation_key_secret_coefficients_i128_for_fixture(trustee_roster_position, ring_degree);

    negacyclic_i128_product_for_evaluation_key_fixture(&trustee_secret, &trustee_secret)
        .expect("legacy relinearization source")
}

fn evaluation_key_error_coefficients_for_fixture(
    proof_family: EvaluationKeyShareProofFamily,
    trustee_roster_position: u64,
    level: usize,
    rotation: Option<u64>,
    digit_index: usize,
    ring_degree: usize,
) -> Vec<i64> {
    let family_offset = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => 13_usize,
        EvaluationKeyShareProofFamily::Galois => {
            usize::try_from(rotation.expect("Galois rotation")).expect("rotation fits usize") % 17
        }
    };
    (0..ring_degree)
        .map(|coefficient_position| {
            match (trustee_roster_position as usize * 41
                + level * 19
                + digit_index * 7
                + coefficient_position * 5
                + family_offset)
                % 5
            {
                0 => -2,
                1 => -1,
                2 => 0,
                3 => 1,
                _ => 2,
            }
        })
        .collect()
}

fn evaluation_key_component_vector_entries(
    proof_family: EvaluationKeyShareProofFamily,
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> (Vec<serde_json::Value>, String) {
    let entries = component_b_by_digit
        .iter()
        .enumerate()
        .flat_map(|(digit_index, component_b_by_limb)| {
            component_b_by_limb
                .iter()
                .enumerate()
                .map(move |(rns_limb_index, coefficients)| {
                    serde_json::json!({
                        "digitIndex": digit_index,
                        "rnsLimbIndex": rns_limb_index,
                        "rnsPrime": DATA_PRIMES[rns_limb_index],
                        "component": "b",
                        "coefficientByteLength": ring_degree * 8,
                        "coefficientVectorHash512": evaluation_key_share_component_vector_hash(coefficients),
                        "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
                    })
                })
        })
        .collect::<Vec<_>>();
    let root = evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &entries,
    )
    .expect("evaluation-key component vector root");

    (entries, root)
}

#[allow(clippy::too_many_arguments)]
fn populate_evaluation_key_share_lnp_proof_fields(
    proof_record: &mut serde_json::Value,
    proof_family: EvaluationKeyShareProofFamily,
    public_matrix_seed_hash: &str,
    statement_record: &serde_json::Value,
    constant_commitments: &[super::super::commitment::SetupCommitmentValue],
    setup_proof_binding: &serde_json::Value,
    fixture_material: &EvaluationKeyShareFixtureMaterial,
    trustee_roster_position: u64,
    transported_key_switch_component_material: Option<&serde_json::Value>,
    proof_randomness_label: &str,
) {
    let proof_randomness_seed_hex = derive_protocol_hash(
        proof_randomness_label,
        &serde_json::json!({
            "trusteeRosterPosition": trustee_roster_position,
            "level": proof_record["level"],
            "rotation": proof_record.get("rotation").cloned().unwrap_or(serde_json::Value::Null),
        }),
    )
    .expect("evaluation-key proof randomness seed");
    let witness = EvaluationKeyShareLnpProofWitness {
        secret_coefficients: evaluation_key_secret_coefficients_for_fixture(
            trustee_roster_position,
            constant_commitments
                .first()
                .expect("constant commitment")
                .ring_degree,
        ),
        opening_randomness_by_limb: (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    0,
                    constant_commitments
                        .first()
                        .expect("constant commitment")
                        .ring_degree,
                )
            })
            .collect(),
        error_coefficients_by_digit: fixture_material.error_coefficients_by_digit.clone(),
        relinearization_source_coefficients_by_digit: fixture_material
            .relinearization_source_coefficients_by_digit
            .clone(),
        round_one_aggregate_source_coefficients_by_digit:
            round_one_aggregate_source_coefficients_for_generation(
                proof_family,
                proof_record,
                constant_commitments
                    .first()
                    .expect("constant commitment")
                    .ring_degree,
                fixture_material.component_b_by_digit.len(),
            ),
    };
    let proof_bytes = generate_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofGenerationInput {
            proof_family,
            public_matrix_seed_hash,
            proof_record,
            same_secret_statement_record: statement_record,
            constant_commitments,
            component_b_by_digit: &fixture_material.component_b_by_digit,
            setup_proof_binding,
            transported_key_switch_component_material,
            witness: &witness,
            proof_randomness_seed_hex: &proof_randomness_seed_hex,
        },
    )
    .expect("evaluation-key proof bytes");
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family,
            public_matrix_seed_hash,
            proof_record,
            same_secret_statement_record: statement_record,
            constant_commitments,
            setup_proof_binding,
            transported_key_switch_component_material,
            proof_bytes: &proof_bytes,
        },
    )
    .expect("evaluation-key proof verification");
    proof_record["statementHash"] = serde_json::json!(verification.statement_hash_hex);
    proof_record["relationCommitmentHash"] =
        serde_json::json!(verification.relation_commitment_hash_hex);
    proof_record["tboxCommitmentPrefixHash"] =
        serde_json::json!(verification.tbox_commitment_prefix_hash);
    proof_record["z34SeedMaterialHash"] = serde_json::json!(verification.z34_seed_material_hash);
    proof_record["z34ChallengeSeedHash"] = serde_json::json!(verification.z34_challenge_seed_hash);
    proof_record["z34ChallengeTailHash"] = serde_json::json!(verification.z34_challenge_tail_hash);
    proof_record["z34ChallengeRowDomainHash"] =
        serde_json::json!(verification.z34_challenge_row_domain_hash);
    proof_record["z34ChallengeZ3RowSetHash"] =
        serde_json::json!(verification.z34_challenge_z3_row_set_hash);
    proof_record["z34ChallengeZ4RowSetHash"] =
        serde_json::json!(verification.z34_challenge_z4_row_set_hash);
    proof_record["tboxLowerProtocolChallengeHash"] =
        serde_json::json!(verification.tbox_lower_protocol_challenge_hash);
    proof_record["z34Z3CheckWindowHash"] = serde_json::json!(verification.z34_z3_check_window_hash);
    proof_record["z34Z4CheckWindowHash"] = serde_json::json!(verification.z34_z4_check_window_hash);
    proof_record["z34Z3L2SquaredDecimal"] =
        serde_json::json!(verification.z34_z3_l2_squared_decimal);
    proof_record["z34Z4InfinityNormDecimal"] =
        serde_json::json!(verification.z34_z4_infinity_norm_decimal);
    proof_record["challenge"] = serde_json::json!(verification.challenge.to_string());
    proof_record["proofSizeBytes"] = serde_json::json!(proof_bytes.len());
    proof_record["proofBytesHash"] = serde_json::json!(
        evaluation_key_share_lnp_relation_proof_bytes_hash(proof_family, &proof_bytes)
    );
    proof_record["proofBytesHex"] = serde_json::json!(to_hex(&proof_bytes));
}

fn relinearization_source_square_binding_root_for_test(
    record: &serde_json::Value,
    round: &str,
    share_root: &str,
) -> String {
    let (source_relation, source_relation_status) =
        relinearization_source_relation_for_round_for_test(round);
    derive_protocol_hash(
        "RelinearizationSourceSquareBindingRoot",
        &serde_json::json!({
            "objectType": "RelinearizationSourceSquareBinding",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "relinearization-key-share",
            "sourceRelation": source_relation,
            "sourceRelationStatus": source_relation_status,
            "round": round,
            "evaluatorKeyScheduleRoot": record["evaluatorKeyScheduleRoot"],
            "sameSecretProofSetRoot": record["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": record["sameSecretProofFamilyBindingRoot"],
            "publicKeyShareLnpProofSetRoot": record["publicKeyShareLnpProofSetRoot"],
            "relinearizationCrpRoot": record["relinearizationCrpRoot"],
            "trusteeIdentity": record["trusteeIdentity"],
            "trusteeRosterPosition": record["trusteeRosterPosition"],
            "level": record["level"],
            "sameSecretStatementRoot": record["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": record["trusteeSecretCommitmentRoot"],
            "sameSecretProofRoot": record["sameSecretProofRoot"],
            "shareRoot": share_root,
            "keySwitchComponentVectorRoot": record["keySwitchComponentVectorRoot"],
            "statementHash": record["statementHash"],
            "relationCommitmentHash": record["relationCommitmentHash"],
            "proofBytesHash": record["proofBytesHash"],
        }),
    )
    .expect("relinearization source-square binding root")
}

fn relinearization_source_square_aggregate_root_for_test(
    round: &str,
    evaluator_key_schedule_root: &serde_json::Value,
    level: u64,
    source_square_binding_roots: &[serde_json::Value],
    round_one_source_square_aggregate_root: Option<&str>,
) -> String {
    let (source_relation, source_relation_status) =
        relinearization_source_relation_for_round_for_test(round);
    let mut aggregate = serde_json::json!({
        "objectType": "RelinearizationSourceSquareAggregate",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "relinearization-key-share",
        "sourceRelation": source_relation,
        "sourceRelationStatus": source_relation_status,
        "round": round,
        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
        "level": level,
        "sourceSquareBindingRoots": source_square_binding_roots,
    });
    if let Some(round_one_source_square_aggregate_root) = round_one_source_square_aggregate_root {
        aggregate["roundOneSourceSquareAggregateRoot"] =
            serde_json::json!(round_one_source_square_aggregate_root);
    }

    derive_protocol_hash("RelinearizationSourceSquareAggregateRoot", &aggregate)
        .expect("relinearization source-square aggregate root")
}

fn relinearization_source_relation_for_round_for_test(round: &str) -> (&'static str, &'static str) {
    match round {
        "round-one" => (
            "same-secret-for-relinearization-round-one-source",
            "verified-by-round-one-same-secret-source-response",
        ),
        "round-two" => (
            "same-secret-times-round-one-aggregate-for-relinearization-source",
            "verifier-checked-round-two-source-square-aggregate-binding",
        ),
        _ => panic!("unsupported relinearization round"),
    }
}

fn relinearization_key_switch_seed_for_test(
    schedule: &serde_json::Value,
    round: &str,
    level: u64,
) -> String {
    derive_protocol_hash(
        "RelinearizationKeyShareSeed",
        &serde_json::json!({
            "objectType": "RelinearizationKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "relinearization-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-level-and-round",
            "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
            "relinearizationCrpRoot": schedule["relinearizationCrpRoot"],
            "round": round,
            "level": level,
        }),
    )
    .expect("relinearization key-switch seed")
}

fn galois_key_switch_seed_for_test(
    schedule: &serde_json::Value,
    rotation: u64,
    level: u64,
) -> String {
    derive_protocol_hash(
        "GaloisKeyShareSeed",
        &serde_json::json!({
            "objectType": "GaloisKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "galois-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-rotation-and-level",
            "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
            "galoisKeyCrpRoot": schedule["galoisKeyCrpRoot"],
            "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
            "rotation": rotation,
            "level": level,
        }),
    )
    .expect("Galois key-switch seed")
}

fn relinearization_key_share_rounds_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let relinearization_tbox_parameter_profile_hash =
        super::super::setup_proof::relinearization_key_share_lnp_tbox_parameter_profile_hash()
            .expect("relinearization tbox parameter profile hash");
    let schedule = &package["evaluatorKeySchedule"];
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let mut round_one_records = Vec::new();
    let mut round_one_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    let mut round_one_source_square_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    let mut round_one_share_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_record_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_source_square_binding_roots = BTreeMap::<(u64, u64), String>::new();
    let level_schedule = schedule["relinearizationLevelSchedule"]
        .as_array()
        .expect("relinearization level schedule");
    for level_entry in level_schedule {
        let level = level_entry["level"].as_u64().expect("level");
        for proof_record in same_secret_proofs {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let statement_record = &statement_records[trustee_roster_position as usize];
            let constant_commitments = same_secret_constant_commitments_from_fixture_package(
                package,
                trustee_roster_position,
            );
            let ring_degree = constant_commitments
                .first()
                .expect("constant commitment")
                .ring_degree;
            let key_switch_seed_hex =
                relinearization_key_switch_seed_for_test(schedule, "round-one", level);
            let relinearization_source = relinearization_round_one_source_coefficients_for_fixture(
                trustee_roster_position,
                ring_degree,
            );
            let fixture_material = evaluation_key_share_fixture_material(
                EvaluationKeyShareProofFamily::Relinearization,
                trustee_roster_position,
                level,
                None,
                ring_degree,
                &key_switch_seed_hex,
                Some(&relinearization_source),
            );
            let round_one_share_root = fixture_material.component_vector_root.clone();
            let mut record = serde_json::json!({
                "objectType": "RelinearizationKeyShareRoundOne",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "proofFamily": "relinearization-key-share",
                "proofVerificationStatus": RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
                "proofModelStatus": RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
                "proofProfileId": "sealed-lattice-relinearization-key-share-proof-lnp-v1",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "level": level,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
                "roundOneShareRoot": round_one_share_root,
                "setupProofBinding": setup_proof_binding.clone(),
                "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                "keySwitchDomain": "relinearization",
                "keySwitchSeedHex": key_switch_seed_hex,
                "ringDegree": ring_degree,
                "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                "keySwitchComponentVectors": fixture_material.component_vector_entries,
                "relinearizationKeyShareTboxParameterProfileHash": relinearization_tbox_parameter_profile_hash.clone(),
            });
            populate_evaluation_key_share_lnp_proof_fields(
                &mut record,
                EvaluationKeyShareProofFamily::Relinearization,
                public_matrix_seed_hash,
                statement_record,
                &constant_commitments,
                &setup_proof_binding,
                &fixture_material,
                trustee_roster_position,
                None,
                "RelinearizationRoundOneProofRandomness",
            );
            let source_square_binding_root = relinearization_source_square_binding_root_for_test(
                &record,
                "round-one",
                &round_one_share_root,
            );
            record["sourceSquareBindingRoot"] =
                serde_json::json!(source_square_binding_root.clone());
            let mut proof_root_input = record.clone();
            proof_root_input
                .as_object_mut()
                .expect("round-one proof root input")
                .remove("roundOneProofRoot");
            let round_one_proof_root =
                derive_protocol_hash("RelinearizationKeyShareProofRoot", &proof_root_input)
                    .expect("round-one proof root");
            record["roundOneProofRoot"] = serde_json::json!(round_one_proof_root);
            record["roundOneRecordRoot"] = serde_json::json!(
                derive_protocol_hash("RelinearizationRoundOneRecordRoot", &record)
                    .expect("round-one record root")
            );
            let record_root = record["roundOneRecordRoot"]
                .as_str()
                .expect("round-one record root")
                .to_string();
            round_one_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "roundOneRecordRoot": record_root,
                }));
            round_one_share_roots.insert((level, trustee_roster_position), round_one_share_root);
            round_one_record_roots.insert((level, trustee_roster_position), record_root);
            round_one_source_square_binding_roots.insert(
                (level, trustee_roster_position),
                source_square_binding_root.clone(),
            );
            round_one_source_square_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "sourceSquareBindingRoot": source_square_binding_root,
                }));
            round_one_records.push(record);
        }
    }
    let mut round_one_aggregate_roots = Vec::new();
    let mut round_one_aggregate_root_by_level = BTreeMap::new();
    let mut round_one_source_square_aggregate_root_by_level = BTreeMap::new();
    for level_entry in level_schedule {
        let level = level_entry["level"].as_u64().expect("level");
        let round_one_source_square_aggregate_root =
            relinearization_source_square_aggregate_root_for_test(
                "round-one",
                &schedule["evaluatorKeyScheduleRoot"],
                level,
                round_one_source_square_roots_by_level
                    .get(&level)
                    .expect("round-one source-square roots by level"),
                None,
            );
        let aggregate_root = derive_protocol_hash(
            "RelinearizationRoundOneAggregateRoot",
            &serde_json::json!({
                "objectType": "RelinearizationRoundOneAggregate",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "level": level,
                "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
                "roundOneRecordRoots": round_one_roots_by_level
                    .get(&level)
                    .expect("round-one roots by level"),
            }),
        )
        .expect("round-one aggregate root");
        round_one_aggregate_roots.push(serde_json::json!({
            "level": level,
            "roundOneAggregateRoot": aggregate_root,
            "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
        }));
        round_one_aggregate_root_by_level.insert(level, aggregate_root);
        round_one_source_square_aggregate_root_by_level
            .insert(level, round_one_source_square_aggregate_root);
    }

    let mut round_two_records = Vec::new();
    let mut round_two_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    let mut round_two_source_square_roots_by_level = BTreeMap::<u64, Vec<serde_json::Value>>::new();
    for level_entry in level_schedule {
        let level = level_entry["level"].as_u64().expect("level");
        for proof_record in same_secret_proofs {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let statement_record = &statement_records[trustee_roster_position as usize];
            let constant_commitments = same_secret_constant_commitments_from_fixture_package(
                package,
                trustee_roster_position,
            );
            let ring_degree = constant_commitments
                .first()
                .expect("constant commitment")
                .ring_degree;
            let key_switch_seed_hex =
                relinearization_key_switch_seed_for_test(schedule, "round-two", level);
            let relinearization_source = relinearization_round_two_source_coefficients_for_fixture(
                trustee_roster_position,
                ring_degree,
            );
            let fixture_material = evaluation_key_share_fixture_material(
                EvaluationKeyShareProofFamily::Relinearization,
                trustee_roster_position,
                level,
                None,
                ring_degree,
                &key_switch_seed_hex,
                Some(&relinearization_source),
            );
            let round_two_share_root = fixture_material.component_vector_root.clone();
            let mut record = serde_json::json!({
                "objectType": "RelinearizationKeyShareRoundTwo",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "proofFamily": "relinearization-key-share",
                "proofVerificationStatus": RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
                "proofModelStatus": RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
                "proofProfileId": "sealed-lattice-relinearization-key-share-proof-lnp-v1",
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "level": level,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
                "roundOneShareRoot": round_one_share_roots
                    .get(&(level, trustee_roster_position))
                    .expect("round-one share root"),
                "roundOneRecordRoot": round_one_record_roots
                    .get(&(level, trustee_roster_position))
                    .expect("round-one record root"),
                "roundOneAggregateRoot": round_one_aggregate_root_by_level
                    .get(&level)
                    .expect("round-one aggregate root"),
                "roundOneSourceSquareBindingRoot": round_one_source_square_binding_roots
                    .get(&(level, trustee_roster_position))
                    .expect("round-one source-square binding root"),
                "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root_by_level
                    .get(&level)
                    .expect("round-one source-square aggregate root"),
                "roundTwoShareRoot": round_two_share_root,
                "setupProofBinding": setup_proof_binding.clone(),
                "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                "keySwitchDomain": "relinearization",
                "keySwitchSeedHex": key_switch_seed_hex,
                "ringDegree": ring_degree,
                "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                "keySwitchComponentVectors": fixture_material.component_vector_entries,
                "relinearizationKeyShareTboxParameterProfileHash": relinearization_tbox_parameter_profile_hash.clone(),
            });
            populate_evaluation_key_share_lnp_proof_fields(
                &mut record,
                EvaluationKeyShareProofFamily::Relinearization,
                public_matrix_seed_hash,
                statement_record,
                &constant_commitments,
                &setup_proof_binding,
                &fixture_material,
                trustee_roster_position,
                None,
                "RelinearizationRoundTwoProofRandomness",
            );
            let source_square_binding_root = relinearization_source_square_binding_root_for_test(
                &record,
                "round-two",
                &round_two_share_root,
            );
            record["sourceSquareBindingRoot"] =
                serde_json::json!(source_square_binding_root.clone());
            let mut proof_root_input = record.clone();
            proof_root_input
                .as_object_mut()
                .expect("round-two proof root input")
                .remove("roundTwoProofRoot");
            let round_two_proof_root =
                derive_protocol_hash("RelinearizationKeyShareProofRoot", &proof_root_input)
                    .expect("round-two proof root");
            record["roundTwoProofRoot"] = serde_json::json!(round_two_proof_root);
            record["roundTwoRecordRoot"] = serde_json::json!(
                derive_protocol_hash("RelinearizationRoundTwoRecordRoot", &record)
                    .expect("round-two record root")
            );
            let record_root = record["roundTwoRecordRoot"]
                .as_str()
                .expect("round-two record root")
                .to_string();
            round_two_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "roundTwoRecordRoot": record_root,
                }));
            round_two_source_square_roots_by_level
                .entry(level)
                .or_default()
                .push(serde_json::json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "sourceSquareBindingRoot": source_square_binding_root,
                }));
            round_two_records.push(record);
        }
    }
    let round_two_aggregate_roots = level_schedule
        .iter()
        .map(|level_entry| {
            let level = level_entry["level"].as_u64().expect("level");
            let round_one_source_square_aggregate_root =
                round_one_source_square_aggregate_root_by_level
                    .get(&level)
                    .expect("round-one source-square aggregate root");
            let round_two_source_square_aggregate_root =
                relinearization_source_square_aggregate_root_for_test(
                    "round-two",
                    &schedule["evaluatorKeyScheduleRoot"],
                    level,
                    round_two_source_square_roots_by_level
                        .get(&level)
                        .expect("round-two source-square roots by level"),
                    Some(round_one_source_square_aggregate_root),
                );
            let aggregate_root = derive_protocol_hash(
                "RelinearizationRoundTwoAggregateRoot",
                &serde_json::json!({
                    "objectType": "RelinearizationRoundTwoAggregate",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "level": level,
                    "roundOneAggregateRoot": round_one_aggregate_root_by_level
                        .get(&level)
                        .expect("round-one aggregate root"),
                    "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
                    "roundTwoSourceSquareAggregateRoot": round_two_source_square_aggregate_root,
                    "roundTwoRecordRoots": round_two_roots_by_level
                        .get(&level)
                        .expect("round-two roots by level"),
                }),
            )
            .expect("round-two aggregate root");
            serde_json::json!({
                "level": level,
                "roundTwoAggregateRoot": aggregate_root,
                "roundTwoSourceSquareAggregateRoot": round_two_source_square_aggregate_root,
            })
        })
        .collect::<Vec<_>>();

    let mut rounds = serde_json::json!({
        "objectType": "RelinearizationKeyShareRounds",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "relinearization-key-share",
        "proofVerificationStatus": RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
        "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
        "relinearizationLevelSchedule": schedule["relinearizationLevelSchedule"],
        "roundOneAggregateRoots": round_one_aggregate_roots,
        "roundOneRecords": round_one_records,
        "roundTwoAggregateRoots": round_two_aggregate_roots,
        "roundTwoRecords": round_two_records,
    });
    rounds["relinearizationKeyShareRoundsRoot"] = serde_json::json!(
        derive_protocol_hash("RelinearizationKeyShareRoundsRoot", &rounds)
            .expect("relinearization rounds root")
    );

    rounds
}

fn galois_key_share_batches_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let galois_tbox_parameter_profile_hash =
        super::super::setup_proof::galois_key_share_lnp_tbox_parameter_profile_hash()
            .expect("Galois tbox parameter profile hash");
    let schedule = &package["evaluatorKeySchedule"];
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let required_schedule = schedule["requiredGaloisKeySchedule"]
        .as_array()
        .expect("Galois key schedule");
    let batches = same_secret_proofs
        .iter()
        .map(|proof_record| {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
            let mut galois_key_share_proofs = Vec::new();
            let galois_key_share_roots = required_schedule
                .iter()
                .map(|schedule_entry| {
                    let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
                    let level = schedule_entry["level"].as_u64().expect("level");
                    let statement_record = &statement_records[trustee_roster_position as usize];
                    let constant_commitments =
                        same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
                    let ring_degree = constant_commitments
                        .first()
                        .expect("constant commitment")
                        .ring_degree;
                    let key_switch_seed_hex =
                        galois_key_switch_seed_for_test(schedule, rotation, level);
                    let fixture_material = evaluation_key_share_fixture_material(
                        EvaluationKeyShareProofFamily::Galois,
                        trustee_roster_position,
                        level,
                        Some(rotation),
                        ring_degree,
                        &key_switch_seed_hex,
                        None,
                    );
                    let root = fixture_material.component_vector_root.clone();
                    let mut galois_proof = serde_json::json!({
                        "objectType": "GaloisKeyShareProof",
                        "objectVersion": 1,
                        "setupProfileId": "CollectiveBgvSetup-v1",
                        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                        "proofFamily": "galois-key-share",
                        "proofVerificationStatus": GALOIS_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
                        "proofModelStatus": GALOIS_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
                        "proofProfileId": "sealed-lattice-galois-key-share-proof-lnp-v1",
                        "ceremonyId": setup_context["ceremonyId"],
                        "manifestHash": setup_context["manifestHash"],
                        "rosterHash": setup_context["rosterHash"],
                        "setupProfileHash": setup_context["setupProfileHash"],
                        "qShareHash": setup_context["qShareHash"],
                        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                        "commitmentProfileHash": setup_context["commitmentProfileHash"],
                        "setupEpoch": setup_context["setupEpoch"],
                        "trusteeIdentity": trustee_identity,
                        "trusteeRosterPosition": trustee_roster_position,
                        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                        "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                        "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                        "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                        "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                        "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                        "rotation": rotation,
                        "level": level,
                        "galoisKeyShareRoot": root.clone(),
                        "setupProofBinding": setup_proof_binding.clone(),
                        "keySwitchMaterialEncoding": "embedded-full-key-switch-component-vectors",
                        "keySwitchDomain": format!("galois-{rotation}"),
                        "keySwitchSeedHex": key_switch_seed_hex,
                        "ringDegree": ring_degree,
                        "keySwitchComponentVectorRoot": fixture_material.component_vector_root,
                        "keySwitchComponentVectors": fixture_material.component_vector_entries,
                        "galoisKeyShareTboxParameterProfileHash": galois_tbox_parameter_profile_hash.clone(),
                    });
                    populate_evaluation_key_share_lnp_proof_fields(
                        &mut galois_proof,
                        EvaluationKeyShareProofFamily::Galois,
                        public_matrix_seed_hash,
                        statement_record,
                        &constant_commitments,
                    &setup_proof_binding,
                    &fixture_material,
                    trustee_roster_position,
                    None,
                    "GaloisKeyShareProofRandomness",
                );
                    let mut proof_root_input = galois_proof.clone();
                    proof_root_input
                        .as_object_mut()
                        .expect("Galois proof root input")
                        .remove("galoisKeyShareProofRoot");
                    let galois_proof_root =
                        derive_protocol_hash("GaloisKeyShareProofRoot", &proof_root_input)
                            .expect("Galois proof root");
                    galois_proof["galoisKeyShareProofRoot"] =
                        serde_json::json!(galois_proof_root);
                    galois_key_share_proofs.push(galois_proof);
                    serde_json::json!({
                        "rotation": schedule_entry["rotation"],
                        "level": schedule_entry["level"],
                        "galoisKeyShareRoot": root,
                    })
                })
                .collect::<Vec<_>>();
            let proof_roots = galois_key_share_proofs
                .iter()
                .map(|proof| {
                    serde_json::json!({
                        "rotation": proof["rotation"],
                        "level": proof["level"],
                        "galoisKeyShareProofRoot": proof["galoisKeyShareProofRoot"],
                    })
                })
                .collect::<Vec<_>>();
            let proof_root = derive_protocol_hash(
                "GaloisKeyBatchProofRoot",
                &serde_json::json!({
                    "objectType": "GaloisKeyBatchProofAggregate",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                    "proofFamily": "galois-key-share",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "trusteeRosterPosition": trustee_roster_position,
                    "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                    "proofRoots": proof_roots,
                }),
            )
            .expect("Galois proof root");
            let mut batch = serde_json::json!({
                "objectType": "GaloisKeyShareBatch",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "proofFamily": "galois-key-share",
                "proofVerificationStatus": GALOIS_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
                "proofModelStatus": GALOIS_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupProfileHash": setup_context["setupProfileHash"],
                "qShareHash": setup_context["qShareHash"],
                "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
                "commitmentProfileHash": setup_context["commitmentProfileHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
                "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
                "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                "requiredGaloisKeySchedule": schedule["requiredGaloisKeySchedule"],
                "galoisKeyShareRoots": galois_key_share_roots,
                "galoisKeyShareProofs": galois_key_share_proofs,
                "galoisKeyBatchProofRoot": proof_root,
            });
            batch["galoisKeyShareBatchRoot"] = serde_json::json!(
                derive_protocol_hash("GaloisKeyShareBatchRoot", &batch)
                    .expect("Galois key share batch root")
            );
            batch
        })
        .collect::<Vec<_>>();

    serde_json::Value::Array(batches)
}

fn public_evaluation_key_set_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let relinearization_rounds = &package["relinearizationKeyShareRounds"];
    let relinearization_rounds_root = relinearization_rounds["relinearizationKeyShareRoundsRoot"]
        .as_str()
        .expect("relinearization rounds root");
    let relinearization_key_roots = schedule["relinearizationLevelSchedule"]
        .as_array()
        .expect("relinearization schedule")
        .iter()
        .map(|level_entry| {
            let level = level_entry["level"].as_u64().expect("relinearization level");
            let decomposition_digit_count = level + 1;
            let round_one_aggregate_root = relinearization_rounds["roundOneAggregateRoots"]
                .as_array()
                .expect("round-one aggregate roots")
                .iter()
                .find(|entry| entry["level"].as_u64() == Some(level))
                .and_then(|entry| entry["roundOneAggregateRoot"].as_str())
                .expect("round-one aggregate root");
            let round_one_source_square_aggregate_root =
                relinearization_rounds["roundOneAggregateRoots"]
                    .as_array()
                    .expect("round-one aggregate roots")
                    .iter()
                    .find(|entry| entry["level"].as_u64() == Some(level))
                    .and_then(|entry| entry["roundOneSourceSquareAggregateRoot"].as_str())
                    .expect("round-one source-square aggregate root");
            let round_two_aggregate_root = relinearization_rounds["roundTwoAggregateRoots"]
                .as_array()
                .expect("round-two aggregate roots")
                .iter()
                .find(|entry| entry["level"].as_u64() == Some(level))
                .and_then(|entry| entry["roundTwoAggregateRoot"].as_str())
                .expect("round-two aggregate root");
            let round_two_source_square_aggregate_root =
                relinearization_rounds["roundTwoAggregateRoots"]
                    .as_array()
                    .expect("round-two aggregate roots")
                    .iter()
                    .find(|entry| entry["level"].as_u64() == Some(level))
                    .and_then(|entry| entry["roundTwoSourceSquareAggregateRoot"].as_str())
                    .expect("round-two source-square aggregate root");
            let relinearization_key_root = derive_protocol_hash(
                "RelinearizationKeyRoot",
                &serde_json::json!({
                    "objectType": "RelinearizationKeyAggregate",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                    "assemblyStatus": "assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate",
                    "materialEncoding": "root-bound-public-key-switch-component-roots",
                    "materialSource": "verified-relinearization-and-galois-proof-records",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                    "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                    "relinearizationKeyShareRoundsRoot": relinearization_rounds_root,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "roundOneAggregateRoot": round_one_aggregate_root,
                    "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
                    "roundTwoAggregateRoot": round_two_aggregate_root,
                    "roundTwoSourceSquareAggregateRoot": round_two_source_square_aggregate_root,
                }),
            )
            .expect("relinearization key root");
            serde_json::json!({
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "roundOneAggregateRoot": round_one_aggregate_root,
                "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
                "roundTwoAggregateRoot": round_two_aggregate_root,
                "roundTwoSourceSquareAggregateRoot": round_two_source_square_aggregate_root,
                "relinearizationKeyRoot": relinearization_key_root,
            })
        })
        .collect::<Vec<_>>();

    let mut galois_batches = package["galoisKeyShareBatches"]
        .as_array()
        .expect("Galois key share batches")
        .iter()
        .collect::<Vec<_>>();
    galois_batches.sort_by_key(|batch| {
        batch["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position")
    });
    let galois_key_share_batch_roots = galois_batches
        .iter()
        .map(|batch| {
            serde_json::json!({
                "trusteeIdentity": batch["trusteeIdentity"],
                "trusteeRosterPosition": batch["trusteeRosterPosition"],
                "galoisKeyShareBatchRoot": batch["galoisKeyShareBatchRoot"],
            })
        })
        .collect::<Vec<_>>();
    let galois_key_roots = schedule["requiredGaloisKeySchedule"]
        .as_array()
        .expect("required Galois key schedule")
        .iter()
        .map(|schedule_entry| {
            let rotation = schedule_entry["rotation"].as_u64().expect("rotation");
            let level = schedule_entry["level"].as_u64().expect("level");
            let decomposition_digit_count = level + 1;
            let contributing_share_roots = galois_batches
                .iter()
                .map(|batch| {
                    let proof = batch["galoisKeyShareProofs"]
                        .as_array()
                        .expect("Galois key share proofs")
                        .iter()
                        .find(|proof| {
                            proof["rotation"].as_u64() == Some(rotation)
                                && proof["level"].as_u64() == Some(level)
                        })
                        .expect("scheduled Galois proof");
                    serde_json::json!({
                        "trusteeIdentity": batch["trusteeIdentity"],
                        "trusteeRosterPosition": batch["trusteeRosterPosition"],
                        "galoisKeyShareRoot": proof["galoisKeyShareRoot"],
                        "galoisKeyShareProofRoot": proof["galoisKeyShareProofRoot"],
                    })
                })
                .collect::<Vec<_>>();
            let galois_key_root = derive_protocol_hash(
                "RotationKeyRoot",
                &serde_json::json!({
                    "objectType": "GaloisKeyAggregate",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                    "assemblyStatus": "assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate",
                    "materialEncoding": "root-bound-public-key-switch-component-roots",
                    "materialSource": "verified-relinearization-and-galois-proof-records",
                    "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
                    "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
                    "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
                    "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
                    "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
                    "rotation": rotation,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "contributingShareRoots": contributing_share_roots,
                }),
            )
            .expect("Galois key root");
            serde_json::json!({
                "rotation": rotation,
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "galoisKeyRoot": galois_key_root,
                "contributingShareRoots": contributing_share_roots,
            })
        })
        .collect::<Vec<_>>();

    let mut evaluation_keys = serde_json::json!({
        "objectType": "PublicEvaluationKeySet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "assemblyStatus": "assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate",
        "materialEncoding": "root-bound-public-key-switch-component-roots",
        "materialSource": "verified-relinearization-and-galois-proof-records",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
        "relinearizationKeyShareRoundsRoot": relinearization_rounds_root,
        "relinearizationLevelSchedule": schedule["relinearizationLevelSchedule"],
        "relinearizationKeyRoots": relinearization_key_roots,
        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
        "requiredGaloisKeySchedule": schedule["requiredGaloisKeySchedule"],
        "galoisKeyShareBatchRoots": galois_key_share_batch_roots,
        "galoisKeyRoots": galois_key_roots,
        "genericKeySwitchKeyRoots": [],
        "rawKeyBytesEmbedded": false,
        "verifierGeneratedKeyMaterial": false,
    });
    evaluation_keys["evaluationKeySetHash"] = serde_json::json!(
        derive_protocol_hash("EvaluationKeySetHash", &evaluation_keys)
            .expect("evaluation key set hash")
    );

    evaluation_keys
}

fn add_public_evaluation_key_material_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let manifest = public_evaluation_key_material_manifest(package, &package["evaluationKeys"])
        .expect("public evaluation-key material manifest");
    let material_bytes = encode_public_evaluation_key_material_manifest(&manifest)
        .expect("public evaluation-key material bytes");
    let chunks = proof_bytes_transport_chunks(material_bytes);
    let transport_hashes = public_evaluation_key_material_transport_hashes(&chunks)
        .expect("public evaluation-key material transport hashes");
    let material_root = public_evaluation_key_material_reference_root(
        &package["evaluationKeys"],
        &manifest,
        &transport_hashes,
    )
    .expect("public evaluation-key material root");
    package["evaluationKeys"]["publicEvaluationKeyMaterialEncoding"] =
        serde_json::json!(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING);
    package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"] = serde_json::json!(material_root);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkSizeBytes"] =
        serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkCount"] =
        serde_json::json!(transport_hashes.chunk_hashes.len());
    package["evaluationKeys"]["publicEvaluationKeyMaterialTotalByteLength"] =
        serde_json::json!(transport_hashes.total_byte_length);
    package["evaluationKeys"]["publicEvaluationKeyMaterialFullObjectHash"] =
        serde_json::json!(transport_hashes.full_object_hash);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkRoot"] =
        serde_json::json!(transport_hashes.chunk_root);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkHashes"] =
        serde_json::json!(transport_hashes.chunk_hashes);
    package["evaluationKeys"]
        .as_object_mut()
        .expect("evaluation key set")
        .remove("evaluationKeySetHash");
    package["evaluationKeys"]["evaluationKeySetHash"] = serde_json::json!(
        derive_protocol_hash("EvaluationKeySetHash", &package["evaluationKeys"])
            .expect("evaluation key set hash")
    );
    rebind_setup_key_correctness_certificate(package);
    rebind_collective_setup_package_hash(package);

    serde_json::json!({
        "objectType": PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
        "publicEvaluationKeyMaterials": [{
            "objectType": PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
            "ceremonyId": package["evaluationKeys"]["ceremonyId"],
            "manifestHash": package["evaluationKeys"]["manifestHash"],
            "rosterHash": package["evaluationKeys"]["rosterHash"],
            "setupProfileHash": package["evaluationKeys"]["setupProfileHash"],
            "qShareHash": package["evaluationKeys"]["qShareHash"],
            "carryAwareVssShareRelationProfileHash": package["evaluationKeys"]["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": package["evaluationKeys"]["commitmentProfileHash"],
            "setupEpoch": package["evaluationKeys"]["setupEpoch"],
            "evaluationKeySetHash": package["evaluationKeys"]["evaluationKeySetHash"],
            "publicEvaluationKeyMaterialRoot": package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"],
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": package["evaluationKeys"]["publicEvaluationKeyMaterialChunkCount"],
            "totalByteLength": package["evaluationKeys"]["publicEvaluationKeyMaterialTotalByteLength"],
            "fullObjectHash": package["evaluationKeys"]["publicEvaluationKeyMaterialFullObjectHash"],
            "chunkRoot": package["evaluationKeys"]["publicEvaluationKeyMaterialChunkRoot"],
            "chunkHashes": package["evaluationKeys"]["publicEvaluationKeyMaterialChunkHashes"],
            "chunks": chunks
                .into_iter()
                .enumerate()
                .map(|(chunk_index, chunk)| serde_json::json!({
                    "chunkIndex": chunk_index,
                    "bytesHex": to_hex(&chunk),
                }))
                .collect::<Vec<_>>(),
        }],
    })
}

fn add_component_materials_to_public_evaluation_key_material_transport(
    transported_public_evaluation_key_material: &mut serde_json::Value,
    component_material_sets: &[serde_json::Value],
) {
    let mut component_materials = Vec::new();
    for component_material_set in component_material_sets {
        component_materials.extend(
            component_material_set["componentMaterials"]
                .as_array()
                .expect("component materials")
                .iter()
                .cloned(),
        );
    }
    transported_public_evaluation_key_material["componentMaterials"] =
        serde_json::json!(component_materials);
}

fn rebind_public_evaluation_key_material_transport(
    package: &mut serde_json::Value,
    transported_public_evaluation_key_material: &mut serde_json::Value,
    material_bytes: Vec<u8>,
) {
    let chunks = proof_bytes_transport_chunks(material_bytes);
    let transport_hashes = public_evaluation_key_material_transport_hashes(&chunks)
        .expect("public evaluation-key material transport hashes");
    let expected_manifest =
        public_evaluation_key_material_manifest(package, &package["evaluationKeys"])
            .expect("public evaluation-key material manifest");
    let material_root = public_evaluation_key_material_reference_root(
        &package["evaluationKeys"],
        &expected_manifest,
        &transport_hashes,
    )
    .expect("public evaluation-key material root");

    package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"] = serde_json::json!(material_root);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkCount"] =
        serde_json::json!(transport_hashes.chunk_hashes.len());
    package["evaluationKeys"]["publicEvaluationKeyMaterialTotalByteLength"] =
        serde_json::json!(transport_hashes.total_byte_length);
    package["evaluationKeys"]["publicEvaluationKeyMaterialFullObjectHash"] =
        serde_json::json!(transport_hashes.full_object_hash);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkRoot"] =
        serde_json::json!(transport_hashes.chunk_root);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkHashes"] =
        serde_json::json!(transport_hashes.chunk_hashes);
    package["evaluationKeys"]
        .as_object_mut()
        .expect("evaluation key set")
        .remove("evaluationKeySetHash");
    package["evaluationKeys"]["evaluationKeySetHash"] = serde_json::json!(
        derive_protocol_hash("EvaluationKeySetHash", &package["evaluationKeys"])
            .expect("evaluation key set hash")
    );
    rebind_setup_key_correctness_certificate(package);
    rebind_collective_setup_package_hash(package);

    let material_entry =
        &mut transported_public_evaluation_key_material["publicEvaluationKeyMaterials"][0];
    material_entry["evaluationKeySetHash"] =
        package["evaluationKeys"]["evaluationKeySetHash"].clone();
    material_entry["publicEvaluationKeyMaterialRoot"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"].clone();
    material_entry["chunkCount"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialChunkCount"].clone();
    material_entry["totalByteLength"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialTotalByteLength"].clone();
    material_entry["fullObjectHash"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialFullObjectHash"].clone();
    material_entry["chunkRoot"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialChunkRoot"].clone();
    material_entry["chunkHashes"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialChunkHashes"].clone();
    material_entry["chunks"] = serde_json::Value::Array(
        chunks
            .into_iter()
            .enumerate()
            .map(|(chunk_index, chunk)| {
                serde_json::json!({
                    "chunkIndex": chunk_index,
                    "bytesHex": to_hex(&chunk),
                })
            })
            .collect::<Vec<_>>(),
    );
}

fn move_first_galois_key_share_lnp_proof_bytes_to_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_material = {
        let proof_record = &mut package["galoisKeyShareBatches"][0]["galoisKeyShareProofs"][0];
        move_evaluation_key_share_lnp_proof_record_bytes_to_transport(
            proof_record,
            "galois-key-share",
            "galoisKeyShareProofRoot",
            "GaloisKeyShareProofRoot",
        )
    };
    rebind_galois_key_batch_proof_root(package, 0);
    rebind_galois_key_share_batch_root(package, 0);
    package["evaluationKeys"] = public_evaluation_key_set_object(package);
    rebind_setup_key_correctness_certificate(package);
    rebind_collective_setup_package_hash(package);

    serde_json::json!({
        "objectType": "SetupTransportedEvaluationKeyShareProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "galois-key-share",
        "proofMaterials": [proof_material],
    })
}

fn move_first_galois_key_share_component_vectors_to_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_record_snapshot =
        package["galoisKeyShareBatches"][0]["galoisKeyShareProofs"][0].clone();
    let trustee_roster_position = proof_record_snapshot["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let rotation = proof_record_snapshot["rotation"]
        .as_u64()
        .expect("Galois rotation");
    let level = proof_record_snapshot["level"].as_u64().expect("level");
    let ring_degree = proof_record_snapshot["ringDegree"]
        .as_u64()
        .expect("ring degree") as usize;
    let key_switch_seed_hex = proof_record_snapshot["keySwitchSeedHex"]
        .as_str()
        .expect("key-switch seed")
        .to_string();
    let statement_record = package["sameSecretConsistency"]["statementRecords"]
        [trustee_roster_position as usize]
        .clone();
    let constant_commitments =
        same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash")
        .to_string();
    let fixture_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Galois,
        trustee_roster_position,
        level,
        Some(rotation),
        ring_degree,
        &key_switch_seed_hex,
        None,
    );
    let transported_component_material_set = {
        let proof_record = &mut package["galoisKeyShareBatches"][0]["galoisKeyShareProofs"][0];
        move_evaluation_key_share_component_vectors_to_transport(
            proof_record,
            EvaluationKeyShareProofFamily::Galois,
            &fixture_material,
        )
    };
    {
        let proof_record = &mut package["galoisKeyShareBatches"][0]["galoisKeyShareProofs"][0];
        proof_record
            .as_object_mut()
            .expect("Galois proof record object")
            .remove("galoisKeyShareProofRoot");
        populate_evaluation_key_share_lnp_proof_fields(
            proof_record,
            EvaluationKeyShareProofFamily::Galois,
            &public_matrix_seed_hash,
            &statement_record,
            &constant_commitments,
            &setup_proof_binding,
            &fixture_material,
            trustee_roster_position,
            Some(&transported_component_material_set),
            "GaloisKeyShareProofRandomness",
        );
        proof_record["galoisKeyShareProofRoot"] = serde_json::json!(
            derive_protocol_hash("GaloisKeyShareProofRoot", proof_record)
                .expect("transported Galois proof root")
        );
    }
    rebind_galois_key_batch_proof_root(package, 0);
    rebind_galois_key_share_batch_root(package, 0);
    package["evaluationKeys"] = public_evaluation_key_set_object(package);
    rebind_setup_key_correctness_certificate(package);
    rebind_collective_setup_package_hash(package);

    transported_component_material_set
}

fn move_evaluation_key_share_component_vectors_to_transport(
    proof_record: &mut serde_json::Value,
    proof_family: EvaluationKeyShareProofFamily,
    fixture_material: &EvaluationKeyShareFixtureMaterial,
) -> serde_json::Value {
    let level = proof_record["level"].as_u64().expect("level") as usize;
    let ring_degree = proof_record["ringDegree"].as_u64().expect("ring degree") as usize;
    let material_bytes = encode_evaluation_key_share_component_vectors(
        level,
        ring_degree,
        &fixture_material.component_b_by_digit,
    )
    .expect("evaluation-key component material bytes");
    let chunks = proof_bytes_transport_chunks(material_bytes);
    let transport_hashes = evaluation_key_share_component_material_transport_hashes(
        proof_family,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("evaluation-key component material transport hashes");
    {
        let proof_record_object = proof_record
            .as_object_mut()
            .expect("evaluation-key proof record object");
        proof_record_object.remove("keySwitchComponentVectors");
        proof_record_object.remove("statementHash");
        proof_record_object.remove("relationCommitmentHash");
        proof_record_object.remove("tboxCommitmentPrefixHash");
        proof_record_object.remove("challenge");
        proof_record_object.remove("proofSizeBytes");
        proof_record_object.remove("proofBytesHash");
        proof_record_object.remove("proofBytesHex");
    }
    proof_record["keySwitchMaterialEncoding"] =
        serde_json::json!(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING);
    let material_root = evaluation_key_share_component_material_reference_root(
        proof_family,
        proof_record,
        &transport_hashes,
    )
    .expect("evaluation-key component material root");
    proof_record["keySwitchComponentMaterialRoot"] = serde_json::json!(material_root);
    proof_record["keySwitchComponentChunkSizeBytes"] =
        serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
    proof_record["keySwitchComponentChunkCount"] =
        serde_json::json!(transport_hashes.chunk_hashes.len());
    proof_record["keySwitchComponentTotalByteLength"] =
        serde_json::json!(transport_hashes.total_byte_length);
    proof_record["keySwitchComponentFullObjectHash"] =
        serde_json::json!(transport_hashes.full_object_hash);
    proof_record["keySwitchComponentChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
    proof_record["keySwitchComponentChunkHashes"] =
        serde_json::json!(transport_hashes.chunk_hashes.clone());

    serde_json::json!({
        "objectType": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "componentMaterials": [{
            "objectType": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": proof_family.proof_family(),
            "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
            "trusteeIdentity": proof_record["trusteeIdentity"],
            "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
            "keySwitchDomain": proof_record["keySwitchDomain"],
            "keySwitchSeedHex": proof_record["keySwitchSeedHex"],
            "level": proof_record["level"],
            "ringDegree": proof_record["ringDegree"],
            "digitCount": level + 1,
            "rnsLimbCount": level + 1,
            "keySwitchComponentVectorRoot": proof_record["keySwitchComponentVectorRoot"],
            "keySwitchComponentMaterialRoot": proof_record["keySwitchComponentMaterialRoot"],
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": proof_record["keySwitchComponentFullObjectHash"],
            "chunkRoot": proof_record["keySwitchComponentChunkRoot"],
            "chunkHashes": proof_record["keySwitchComponentChunkHashes"],
            "chunks": chunks
                .into_iter()
                .enumerate()
                .map(|(chunk_index, chunk)| serde_json::json!({
                    "chunkIndex": chunk_index,
                    "bytesHex": to_hex(&chunk),
                }))
                .collect::<Vec<_>>(),
        }],
    })
}

fn move_evaluation_key_share_lnp_proof_record_bytes_to_transport(
    proof_record: &mut serde_json::Value,
    proof_family: &str,
    proof_root_field_name: &str,
    proof_root_namespace: &str,
) -> serde_json::Value {
    let proof_bytes_hex = proof_record["proofBytesHex"]
        .as_str()
        .expect("embedded evaluation-key proof bytes")
        .to_string();
    let proof_bytes = decode_hex(&proof_bytes_hex).expect("evaluation-key proof bytes");
    let chunks = proof_bytes_transport_chunks(proof_bytes);
    let transport_hashes = setup_proof_material_transport_hashes(
        proof_family,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("evaluation-key proof transport hashes");
    let proof_size_bytes = proof_record["proofSizeBytes"]
        .as_u64()
        .expect("proof size bytes");
    let proof_bytes_hash = proof_record["proofBytesHash"]
        .as_str()
        .expect("proof bytes hash")
        .to_string();
    let statement_hash = proof_record["statementHash"]
        .as_str()
        .expect("statement hash")
        .to_string();
    let relation_commitment_hash = proof_record["relationCommitmentHash"]
        .as_str()
        .expect("relation commitment hash")
        .to_string();
    let tbox_commitment_prefix_hash = proof_record["tboxCommitmentPrefixHash"]
        .as_str()
        .expect("tbox commitment prefix hash")
        .to_string();
    let trustee_identity = proof_record["trusteeIdentity"]
        .as_str()
        .expect("trustee identity")
        .to_string();
    let trustee_roster_position = proof_record["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let proof_material_root =
        setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
            setup_profile_id: "CollectiveBgvSetup-v1",
            proof_family,
            trustee_identity: &trustee_identity,
            trustee_roster_position,
            statement_hash_hex: &statement_hash,
            relation_commitment_hash_hex: &relation_commitment_hash,
            tbox_commitment_prefix_hash: &tbox_commitment_prefix_hash,
            proof_size_bytes,
            proof_bytes_hash: &proof_bytes_hash,
            transport_hashes: &transport_hashes,
        })
        .expect("evaluation-key proof material root");
    {
        let proof_record_object = proof_record
            .as_object_mut()
            .expect("evaluation-key proof record object");
        proof_record_object.remove("proofBytesHex");
        proof_record_object.remove(proof_root_field_name);
    }
    proof_record["proofBytesEncoding"] = serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING);
    proof_record["proofMaterialRoot"] = serde_json::json!(proof_material_root);
    proof_record["proofChunkSizeBytes"] = serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
    proof_record["proofChunkCount"] = serde_json::json!(transport_hashes.chunk_hashes.len());
    proof_record["proofTotalByteLength"] = serde_json::json!(transport_hashes.total_byte_length);
    proof_record["proofFullObjectHash"] = serde_json::json!(transport_hashes.full_object_hash);
    proof_record["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
    proof_record["proofChunkHashes"] = serde_json::json!(transport_hashes.chunk_hashes.clone());
    proof_record[proof_root_field_name] = serde_json::json!(
        derive_protocol_hash(proof_root_namespace, proof_record)
            .expect("transported evaluation-key proof root")
    );

    serde_json::json!({
        "objectType": "SetupTransportedEvaluationKeyShareProofMaterial",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": proof_family,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": proof_record["proofMaterialRoot"],
        "proofChunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "proofChunkCount": transport_hashes.chunk_hashes.len(),
        "proofTotalByteLength": transport_hashes.total_byte_length,
        "proofFullObjectHash": proof_record["proofFullObjectHash"],
        "proofChunkRoot": proof_record["proofChunkRoot"],
        "proofChunkHashes": proof_record["proofChunkHashes"],
        "chunks": chunks
            .into_iter()
            .enumerate()
            .map(|(chunk_index, chunk)| serde_json::json!({
                "chunkIndex": chunk_index,
                "bytesHex": to_hex(&chunk),
            }))
            .collect::<Vec<_>>(),
    })
}

fn collective_public_key_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let material_records = package["publicKeyShareMaterial"]["shareMaterialRecords"]
        .as_array()
        .expect("public-key material records");
    let ring_degree = package["publicKeyShareMaterial"]["ringDegree"]
        .as_u64()
        .expect("ring degree") as usize;
    let mut source_roots = Vec::new();
    let mut aggregate_coefficients_by_limb = (0..DATA_PRIMES.len())
        .map(|_| vec![0_u64; ring_degree])
        .collect::<Vec<_>>();
    for material_record in material_records {
        source_roots.push(serde_json::json!({
            "trusteeIdentity": material_record["trusteeIdentity"],
            "trusteeRosterPosition": material_record["trusteeRosterPosition"],
            "publicKeyShareRoot": material_record["publicKeyShareRoot"],
            "publicKeyShareMaterialRoot": material_record["publicKeyShareMaterialRoot"],
        }));
        for (rns_limb_index, limb) in material_record["shareCoefficientVectorsByLimb"]
            .as_array()
            .expect("share limbs")
            .iter()
            .enumerate()
        {
            let coefficients = coefficient_vector_from_le_hex(
                limb["coefficientsLeHex"].as_str().expect("coefficient hex"),
                ring_degree,
                "public-key share coefficient width",
            )
            .expect("public-key share coefficients");
            for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
                aggregate_coefficients_by_limb[rns_limb_index][coefficient_index] = add_mod(
                    aggregate_coefficients_by_limb[rns_limb_index][coefficient_index],
                    *coefficient,
                    DATA_PRIMES[rns_limb_index],
                )
                .expect("aggregate public-key coefficient");
            }
        }
    }
    let aggregate_limbs = aggregate_coefficients_by_limb
        .iter()
        .enumerate()
        .map(|(rns_limb_index, coefficients)| {
            serde_json::json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "component": "b",
                "coefficientByteLength": ring_degree * 8,
                "coefficientVectorHash512": public_key_share_coefficient_vector_hash(coefficients),
                "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
            })
        })
        .collect::<Vec<_>>();
    let mut collective_public_key = serde_json::json!({
        "objectType": "CollectivePublicKey",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofVerificationStatus": PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "aggregationStatus": "lnp-proof-aggregated-with-accepted-setup-proof-accounting",
        "materialEncoding": "embedded-full-collective-public-key-coefficients",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "publicKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"],
        "publicAPolynomialRoot": package["commonRandomness"]["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"],
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareProofSetRoot": package["publicKeyShareProofs"]["publicKeyShareProofSetRoot"],
        "publicKeyShareMaterialSetRoot": package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"],
        "publicKeyShareLnpProofSetRoot": package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"],
        "sourceShareMaterialRoots": source_roots,
        "aggregateCoefficientVectorsByLimb": aggregate_limbs,
    });
    collective_public_key["collectivePublicKeyRoot"] = serde_json::json!(
        derive_protocol_hash("CollectivePublicKeyRoot", &collective_public_key)
            .expect("collective public-key root")
    );

    collective_public_key
}

fn replace_public_key_share_hashes_with_material_hashes(package: &mut serde_json::Value) {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash")
        .to_string();
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    for trustee_roster_position in 0..10_u64 {
        let (coefficients_by_limb, _) = public_key_share_coefficients_and_errors_for_fixture(
            &public_matrix_seed_hash,
            trustee_roster_position,
            ring_degree,
        );
        let share_hashes = coefficients_by_limb
            .iter()
            .enumerate()
            .map(|(rns_limb_index, coefficients)| {
                serde_json::json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": DATA_PRIMES[rns_limb_index],
                    "component": "b_i",
                    "coefficientVectorHash512": public_key_share_coefficient_vector_hash(coefficients),
                })
            })
            .collect::<Vec<_>>();
        package["publicKeyShares"]["shareRecords"][trustee_roster_position as usize]["shareCoefficientVectorHash512ByLimb"] =
            serde_json::json!(share_hashes);
    }
    rebind_collective_public_key_share_roots(package);
    for trustee_roster_position in 0..10_usize {
        package["publicKeyShareProofs"]["proofRecords"][trustee_roster_position]
            ["publicKeyShareRoot"] =
            package["publicKeyShares"]["shareRecords"][trustee_roster_position]
                ["publicKeyShareRoot"]
                .clone();
    }
    package["publicKeyShareProofs"]["publicKeyShareSetRoot"] =
        package["publicKeyShares"]["publicKeyShareSetRoot"].clone();
    rebind_collective_public_key_share_proof_roots(package);
    package["evaluatorKeySchedule"]["publicKeyShareSetRoot"] =
        package["publicKeyShares"]["publicKeyShareSetRoot"].clone();
    package["evaluatorKeySchedule"]["publicKeyShareProofSetRoot"] =
        package["publicKeyShareProofs"]["publicKeyShareProofSetRoot"].clone();
    rebind_collective_evaluator_key_schedule_root(package);
}

fn public_key_share_material_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let public_key_crp_root =
        package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"]
            .as_str()
            .expect("public-key CRP root");
    let public_a_polynomial_root =
        package["commonRandomness"]["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"]
            .as_str()
            .expect("public a root");
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    let mut material_records = Vec::new();
    let mut material_roots = Vec::new();
    for trustee_roster_position in 0..10_u64 {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let (coefficients_by_limb, _) = public_key_share_coefficients_and_errors_for_fixture(
            public_matrix_seed_hash,
            trustee_roster_position,
            ring_degree,
        );
        let limbs = coefficients_by_limb
            .iter()
            .enumerate()
            .map(|(rns_limb_index, coefficients)| {
                serde_json::json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": DATA_PRIMES[rns_limb_index],
                    "component": "b_i",
                    "coefficientByteLength": ring_degree * 8,
                    "coefficientVectorHash512": public_key_share_coefficient_vector_hash(coefficients),
                    "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
                })
            })
            .collect::<Vec<_>>();
        let mut material_record = serde_json::json!({
            "objectType": "PublicKeyShareMaterial",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "public-key-share",
            "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
            "materialEncoding": "embedded-full-public-key-share-coefficients",
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "qShareHash": setup_context["qShareHash"],
            "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": setup_context["commitmentProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "rnsLimbCount": DATA_PRIMES.len(),
            "ringDegree": ring_degree,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicKeyCrpRoot": public_key_crp_root,
            "publicAPolynomialRoot": public_a_polynomial_root,
            "publicKeyShareRoot": package["publicKeyShares"]["shareRecords"][trustee_roster_position as usize]["publicKeyShareRoot"],
            "shareCoefficientVectorsByLimb": limbs,
        });
        material_record["publicKeyShareMaterialRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareRoot", &material_record)
                .expect("public-key share material root")
        );
        material_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareMaterialRoot": material_record["publicKeyShareMaterialRoot"],
        }));
        material_records.push(material_record);
    }
    let mut material_set = serde_json::json!({
        "objectType": "PublicKeyShareMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "materialEncoding": "embedded-full-public-key-share-coefficients",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_key_crp_root,
        "publicAPolynomialRoot": public_a_polynomial_root,
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareMaterialRoots": material_roots,
        "shareMaterialRecords": material_records,
    });
    material_set["publicKeyShareMaterialSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareRoot", &material_set)
            .expect("public-key share material set root")
    );

    material_set
}

fn public_key_share_lnp_proofs_object(package: &serde_json::Value) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_key_share_tbox_parameter_profile_hash =
        super::super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()
            .expect("public-key share tbox parameter profile hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let public_key_crp_root =
        package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"]
            .as_str()
            .expect("public-key CRP root");
    let public_a_polynomial_root =
        package["commonRandomness"]["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"]
            .as_str()
            .expect("public a root");
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let same_secret_proof_records = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    let share_records = package["publicKeyShares"]["shareRecords"]
        .as_array()
        .expect("public-key share records");
    let proof_statement_records = package["publicKeyShareProofs"]["proofRecords"]
        .as_array()
        .expect("public-key proof statement records");
    let material_records = package["publicKeyShareMaterial"]["shareMaterialRecords"]
        .as_array()
        .expect("public-key material records");
    let mut proof_records = Vec::new();
    let mut proof_roots = Vec::new();
    for trustee_roster_position in 0..10_u64 {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let statement_record = &statement_records[trustee_roster_position as usize];
        let same_secret_proof_record = &same_secret_proof_records[trustee_roster_position as usize];
        let share_record = &share_records[trustee_roster_position as usize];
        let proof_statement_record = &proof_statement_records[trustee_roster_position as usize];
        let material_record = &material_records[trustee_roster_position as usize];
        let constant_commitments =
            same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
        let ring_degree = constant_commitments
            .first()
            .expect("constant commitment")
            .ring_degree;
        let (coefficients_by_limb, error_coefficients_by_limb) =
            public_key_share_coefficients_and_errors_for_fixture(
                public_matrix_seed_hash,
                trustee_roster_position,
                ring_degree,
            );
        let witness = PublicKeyShareLnpProofWitness {
            secret_coefficients: (0..ring_degree)
                .map(|coefficient_position| {
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    )
                })
                .collect(),
            opening_randomness_by_limb: (0..DATA_PRIMES.len())
                .map(|rns_limb_index| {
                    accepted_vss_randomness_fixture(
                        trustee_roster_position,
                        rns_limb_index,
                        0,
                        ring_degree,
                    )
                })
                .collect(),
            error_coefficients_by_limb,
        };
        let proof_randomness_seed_hex = derive_protocol_hash(
            "PublicKeyShareProofRoot",
            &serde_json::json!({
                "fixture": "public-key-share-lnp-proof-randomness",
                "trusteeRosterPosition": trustee_roster_position,
            }),
        )
        .expect("public-key proof randomness seed");
        let proof_bytes =
            generate_public_key_share_lnp_relation_proof(PublicKeyShareLnpProofGenerationInput {
                public_matrix_seed_hash,
                public_key_share_record: share_record,
                public_key_share_proof_record: proof_statement_record,
                same_secret_statement_record: statement_record,
                constant_commitments: &constant_commitments,
                public_share_coefficients_by_limb: &coefficients_by_limb,
                setup_proof_binding: &setup_proof_binding,
                witness: &witness,
                proof_randomness_seed_hex: &proof_randomness_seed_hex,
            })
            .expect("public-key proof bytes");
        let verification =
            verify_public_key_share_lnp_relation_proof(PublicKeyShareLnpProofVerificationInput {
                public_matrix_seed_hash,
                public_key_share_record: share_record,
                public_key_share_proof_record: proof_statement_record,
                same_secret_statement_record: statement_record,
                constant_commitments: &constant_commitments,
                public_share_coefficients_by_limb: &coefficients_by_limb,
                setup_proof_binding: &setup_proof_binding,
                proof_bytes: &proof_bytes,
            })
            .expect("public-key proof verification");
        let proof_size_bytes = u64::try_from(proof_bytes.len()).expect("proof size bytes");
        let proof_bytes_hash = public_key_share_lnp_relation_proof_bytes_hash(&proof_bytes);
        let mut proof_record = serde_json::json!({
            "objectType": "PublicKeyShareLnpProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
            "proofFamily": "public-key-share",
            "proofVerificationStatus": PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
            "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
            "setupProofBinding": setup_proof_binding.clone(),
            "publicKeyShareTboxParameterProfileHash": public_key_share_tbox_parameter_profile_hash.clone(),
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "qShareHash": setup_context["qShareHash"],
            "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": setup_context["commitmentProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
            "publicKeyShareProofRoot": proof_statement_record["publicKeyShareProofRoot"],
            "publicKeyShareMaterialRoot": material_record["publicKeyShareMaterialRoot"],
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": same_secret_proof_record["sameSecretProofFamilyBindingRoot"],
            "sameSecretProofRoot": same_secret_proof_record["sameSecretProofRoot"],
            "statementHash": verification.statement_hash_hex,
            "relationCommitmentHash": verification.relation_commitment_hash_hex,
            "tboxCommitmentPrefixHash": verification.tbox_commitment_prefix_hash,
            "z34SeedMaterialHash": verification.z34_seed_material_hash,
            "z34ChallengeSeedHash": verification.z34_challenge_seed_hash,
            "z34ChallengeTailHash": verification.z34_challenge_tail_hash,
            "z34ChallengeRowDomainHash": verification.z34_challenge_row_domain_hash,
            "z34ChallengeZ3RowSetHash": verification.z34_challenge_z3_row_set_hash,
            "z34ChallengeZ4RowSetHash": verification.z34_challenge_z4_row_set_hash,
            "tboxLowerProtocolChallengeHash": verification.tbox_lower_protocol_challenge_hash,
            "z34Z3CheckWindowHash": verification.z34_z3_check_window_hash,
            "z34Z4CheckWindowHash": verification.z34_z4_check_window_hash,
            "z34Z3L2SquaredDecimal": verification.z34_z3_l2_squared_decimal,
            "z34Z4InfinityNormDecimal": verification.z34_z4_infinity_norm_decimal,
            "challenge": verification.challenge.to_string(),
            "proofSizeBytes": proof_size_bytes,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesHex": to_hex(&proof_bytes),
        });
        proof_record["publicKeyShareLnpProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", &proof_record)
                .expect("public-key LNP proof root")
        );
        proof_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareLnpProofRoot": proof_record["publicKeyShareLnpProofRoot"],
        }));
        proof_records.push(proof_record);
    }
    let mut proof_set = serde_json::json!({
        "objectType": "PublicKeyShareLnpProofSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofVerificationStatus": PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        "setupProofBinding": setup_proof_binding,
        "publicKeyShareTboxParameterProfileHash": public_key_share_tbox_parameter_profile_hash,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_key_crp_root,
        "publicAPolynomialRoot": public_a_polynomial_root,
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareProofSetRoot": package["publicKeyShareProofs"]["publicKeyShareProofSetRoot"],
        "publicKeyShareMaterialSetRoot": package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"],
        "publicKeyShareLnpProofRoots": proof_roots,
        "proofRecords": proof_records,
    });
    proof_set["publicKeyShareLnpProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareProofRoot", &proof_set)
            .expect("public-key LNP proof set root")
    );

    proof_set
}

fn public_key_share_coefficients_and_errors_for_fixture(
    public_matrix_seed_hash: &str,
    trustee_roster_position: u64,
    ring_degree: usize,
) -> (Vec<Vec<u64>>, Vec<Vec<i64>>) {
    let mut coefficients_by_limb = Vec::new();
    let mut error_coefficients_by_limb = Vec::new();
    for (rns_limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let secret_residues = (0..ring_degree)
            .map(|coefficient_position| {
                signed_i64_residue_for_fixture(
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    ),
                    modulus,
                )
            })
            .collect::<Vec<_>>();
        let public_a =
            dense_public_residues(public_matrix_seed_hash, "accepted-bgv-public-a", modulus)
                .into_iter()
                .take(ring_degree)
                .collect::<Vec<_>>();
        let product = negacyclic_product_mod_for_fixture(&public_a, &secret_residues, modulus)
            .expect("public-key product");
        let errors = (0..ring_degree)
            .map(|coefficient_position| {
                accepted_public_key_error_coefficient_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    coefficient_position,
                )
            })
            .collect::<Vec<_>>();
        let coefficients = errors
            .iter()
            .zip(product.iter())
            .map(|(error, product_coefficient)| {
                let scaled_error = mul_mod(
                    PLAINTEXT_MODULUS % modulus,
                    signed_i64_residue_for_fixture(*error, modulus),
                    modulus,
                )
                .expect("scaled error");
                sub_mod(scaled_error, *product_coefficient, modulus).expect("public-key share")
            })
            .collect::<Vec<_>>();
        coefficients_by_limb.push(coefficients);
        error_coefficients_by_limb.push(errors);
    }

    (coefficients_by_limb, error_coefficients_by_limb)
}

fn accepted_public_key_error_coefficient_fixture(
    trustee_roster_position: u64,
    rns_limb_index: usize,
    coefficient_position: usize,
) -> i64 {
    match (trustee_roster_position as usize * 37 + rns_limb_index * 11 + coefficient_position * 5)
        % 5
    {
        0 => -2,
        1 => -1,
        2 => 0,
        3 => 1,
        _ => 2,
    }
}

fn signed_i64_residue_for_fixture(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        u64::try_from(value).expect("non-negative value") % modulus
    } else {
        let magnitude = value.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}

fn negacyclic_product_mod_for_fixture(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let ring_degree = left.len();
    if ring_degree != right.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "fixture product inputs must have equal width",
        ));
    }
    let mut output = vec![0_u64; ring_degree];
    for (left_index, left_value) in left.iter().enumerate() {
        for (right_index, right_value) in right.iter().enumerate() {
            let product = mul_mod(*left_value, *right_value, modulus)?;
            let raw_index = left_index + right_index;
            if raw_index < ring_degree {
                output[raw_index] = add_mod(output[raw_index], product, modulus)?;
            } else {
                output[raw_index - ring_degree] =
                    sub_mod(output[raw_index - ring_degree], product, modulus)?;
            }
        }
    }

    Ok(output)
}

fn same_secret_constant_commitments_from_fixture_package(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> Vec<super::super::commitment::SetupCommitmentValue> {
    let material_records = package["vssCoefficientCommitmentMaterial"]["coefficientCommitments"]
        .as_array()
        .expect("coefficient material records");
    let mut commitments_by_limb = BTreeMap::new();
    for material_record in material_records {
        if material_record["sourceTrusteeRosterPosition"].as_u64() != Some(trustee_roster_position)
            || material_record["shamirCoefficientIndex"].as_u64() != Some(0)
        {
            continue;
        }
        let rns_limb_index = material_record["rnsLimbIndex"]
            .as_u64()
            .expect("RNS limb index");
        let commitment = super::super::commitment::parse_setup_commitment_full_value(
            &material_record["commitment"],
        )
        .expect("constant commitment value");
        assert!(
            commitments_by_limb
                .insert(rns_limb_index, commitment)
                .is_none(),
            "duplicate constant commitment limb"
        );
    }
    (0..DATA_PRIMES.len() as u64)
        .map(|rns_limb_index| {
            commitments_by_limb
                .remove(&rns_limb_index)
                .expect("constant commitment limb")
        })
        .collect()
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
            {"phaseId": "galoisKeyBatchProofs", "phaseNumber": 12},
            {"phaseId": "setupPackageAssembly", "phaseNumber": 13},
            {"phaseId": "setupPackageVerification", "phaseNumber": 14},
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

fn vss_complaints_object(
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

fn rebind_collective_setup_package_hash(package: &mut serde_json::Value) {
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("setupPackageHash");
    package["setupPackageHash"] = serde_json::json!(
        derive_protocol_hash(
            "SetupPackageHash",
            &setup_package_hash_input_for_test(package)
        )
        .expect("setup package hash")
    );
}

fn setup_package_hash_input_for_test(package: &serde_json::Value) -> serde_json::Value {
    let mut hash_input = package.clone();
    hash_input
        .as_object_mut()
        .expect("setup package object")
        .remove("setupPackageHash");
    if let Some(private_vss_envelope_commitments) = hash_input
        .get_mut("privateVssEnvelopeCommitments")
        .and_then(serde_json::Value::as_object_mut)
        && let Some(envelope_references) = private_vss_envelope_commitments
            .get_mut("envelopeReferences")
            .and_then(serde_json::Value::as_array_mut)
    {
        for envelope_reference in envelope_references {
            if let Some(envelope_reference_object) = envelope_reference.as_object_mut() {
                envelope_reference_object.remove("encryptedEnvelope");
            }
        }
    }
    hash_input
}

fn rebind_collective_phase_roots(package: &mut serde_json::Value) {
    let phases = package["phaseTranscript"]
        .as_array_mut()
        .expect("phase transcript");
    let mut previous_phase_root = serde_json::Value::Null;
    for phase in phases {
        phase["previousPhaseRoot"] = previous_phase_root.clone();
        phase
            .as_object_mut()
            .expect("phase record")
            .remove("phaseRoot");
        let phase_root = derive_protocol_hash("SetupPhaseRoot", phase).expect("phase root");
        phase["phaseRoot"] = serde_json::json!(phase_root.clone());
        previous_phase_root = serde_json::json!(phase_root);
    }
}

fn rebind_collective_vss_commitment_roots(package: &mut serde_json::Value) {
    let source_trustee_records = package["vssCoefficientCommitments"]["sourceTrusteeRecords"]
        .as_array_mut()
        .expect("source trustee records");
    for source_trustee_record in source_trustee_records {
        source_trustee_record
            .as_object_mut()
            .expect("source trustee record")
            .remove("sourceTrusteeCommitmentRoot");
        source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
            derive_protocol_hash("VssCoefficientCommitmentRoot", source_trustee_record)
                .expect("source trustee commitment root")
        );
    }
    package["vssCoefficientCommitments"]
        .as_object_mut()
        .expect("VSS commitment set")
        .remove("vssCoefficientCommitmentRoot");
    package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash(
            "VssCoefficientCommitmentRoot",
            &package["vssCoefficientCommitments"]
        )
        .expect("VSS commitment set root")
    );
}

fn rebind_collective_vss_coefficient_commitment_material_root(package: &mut serde_json::Value) {
    package["vssCoefficientCommitmentMaterial"]
        .as_object_mut()
        .expect("VSS coefficient commitment material set")
        .remove("vssCoefficientCommitmentMaterialRoot");
    package["vssCoefficientCommitmentMaterial"]["vssCoefficientCommitmentMaterialRoot"] = serde_json::json!(
        derive_protocol_hash(
            "VssCoefficientCommitmentMaterialRoot",
            &package["vssCoefficientCommitmentMaterial"]
        )
        .expect("VSS coefficient commitment material root")
    );
}

fn rebind_collective_threshold_share_commitment_root(package: &mut serde_json::Value) {
    package["thresholdShareCommitments"]
        .as_object_mut()
        .expect("threshold-share commitment set")
        .remove("thresholdShareCommitmentRoot");
    package["thresholdShareCommitments"]["thresholdShareCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash(
            "ThresholdShareCommitmentRoot",
            &package["thresholdShareCommitments"]
        )
        .expect("threshold-share commitment root")
    );
}

fn rebind_collective_private_vss_envelope_commitment_root(package: &mut serde_json::Value) {
    package["privateVssEnvelopeCommitments"]
        .as_object_mut()
        .expect("private VSS envelope commitment set")
        .remove("privateVssEnvelopeCommitmentRoot");
    let private_vss_envelope_commitment_root = derive_protocol_hash(
        "PrivateVssEnvelopeCommitmentRoot",
        &private_vss_envelope_commitment_set_root_input(&package["privateVssEnvelopeCommitments"]),
    )
    .expect("private VSS envelope commitment root");
    package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"] =
        serde_json::json!(private_vss_envelope_commitment_root.clone());
    package["privateVssEnvelopeCommitmentRoot"] =
        serde_json::json!(private_vss_envelope_commitment_root);
}

fn private_vss_envelope_commitment_record_root_input(
    envelope_reference: &serde_json::Value,
) -> serde_json::Value {
    let mut root_input = envelope_reference.clone();
    root_input
        .as_object_mut()
        .expect("private VSS envelope commitment reference")
        .remove("encryptedEnvelope");
    root_input
}

fn private_vss_envelope_commitment_set_root_input(
    commitment_set: &serde_json::Value,
) -> serde_json::Value {
    let mut root_input = commitment_set.clone();
    if let Some(envelope_references) = root_input
        .get_mut("envelopeReferences")
        .and_then(serde_json::Value::as_array_mut)
    {
        for envelope_reference in envelope_references {
            if let Some(envelope_reference_object) = envelope_reference.as_object_mut() {
                envelope_reference_object.remove("encryptedEnvelope");
            }
        }
    }
    root_input
}

fn rebind_first_private_vss_encrypted_envelope_hash(package: &mut serde_json::Value) {
    let encrypted_envelope =
        &mut package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"];
    encrypted_envelope
        .as_object_mut()
        .expect("encrypted envelope")
        .remove("encryptedEnvelopeHash");
    let encrypted_envelope_hash =
        derive_protocol_hash("PrivateVssEncryptedEnvelopeHash", encrypted_envelope)
            .expect("encrypted envelope hash");
    encrypted_envelope["encryptedEnvelopeHash"] =
        serde_json::json!(encrypted_envelope_hash.clone());
    package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelopeHash"] =
        serde_json::json!(encrypted_envelope_hash);
}

fn rebind_collective_vss_acceptance_root(package: &mut serde_json::Value) {
    package["vssShareAcceptances"]
        .as_object_mut()
        .expect("VSS share acceptance set")
        .remove("vssShareAcceptanceRoot");
    package["vssShareAcceptances"]["vssShareAcceptanceRoot"] = serde_json::json!(
        derive_protocol_hash("VssShareAcceptanceRoot", &package["vssShareAcceptances"])
            .expect("VSS share acceptance set root")
    );
}

fn rebind_collective_vss_complaint_root(package: &mut serde_json::Value) {
    package["vssComplaints"]
        .as_object_mut()
        .expect("VSS complaint set")
        .remove("vssComplaintRoot");
    package["vssComplaints"]["vssComplaintRoot"] = serde_json::json!(
        derive_protocol_hash("VssComplaintRoot", &package["vssComplaints"])
            .expect("VSS complaint set root")
    );
}

fn rebind_collective_same_secret_statement_roots(package: &mut serde_json::Value) {
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array_mut()
        .expect("same-secret statement records");
    for statement_record in statement_records {
        statement_record
            .as_object_mut()
            .expect("same-secret statement record")
            .remove("sameSecretStatementRoot");
        statement_record["sameSecretStatementRoot"] = serde_json::json!(
            derive_protocol_hash("SameSecretConsistencyRoot", statement_record)
                .expect("same-secret statement root")
        );
    }
    rebind_collective_same_secret_consistency_root(package);
}

fn rebind_collective_same_secret_consistency_root(package: &mut serde_json::Value) {
    package["sameSecretConsistency"]
        .as_object_mut()
        .expect("same-secret statement set")
        .remove("sameSecretConsistencyRoot");
    package["sameSecretConsistency"]["sameSecretConsistencyRoot"] = serde_json::json!(
        derive_protocol_hash(
            "SameSecretConsistencyRoot",
            &package["sameSecretConsistency"]
        )
        .expect("same-secret consistency root")
    );
}

fn rebind_collective_same_secret_proof_set_root(package: &mut serde_json::Value) {
    package["sameSecretProofs"]
        .as_object_mut()
        .expect("same-secret proof set")
        .remove("sameSecretProofSetRoot");
    package["sameSecretProofs"]["sameSecretProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("SameSecretProofRoot", &package["sameSecretProofs"])
            .expect("same-secret proof set root")
    );
    rebind_active_static_setup_theorem_certificate(package);
}

fn rebind_collective_public_key_lnp_proof_roots(package: &mut serde_json::Value) {
    let proof_records = package["publicKeyShareLnpProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key LNP proof records");
    let mut proof_roots = Vec::new();
    for proof_record in proof_records {
        proof_record
            .as_object_mut()
            .expect("public-key LNP proof record")
            .remove("publicKeyShareLnpProofRoot");
        proof_record["publicKeyShareLnpProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", proof_record)
                .expect("public-key LNP proof root")
        );
        proof_roots.push(serde_json::json!({
            "trusteeIdentity": proof_record["trusteeIdentity"],
            "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
            "publicKeyShareLnpProofRoot": proof_record["publicKeyShareLnpProofRoot"],
        }));
    }
    package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofRoots"] =
        serde_json::json!(proof_roots);
    package["publicKeyShareLnpProofs"]
        .as_object_mut()
        .expect("public-key LNP proof set")
        .remove("publicKeyShareLnpProofSetRoot");
    package["publicKeyShareLnpProofs"]["publicKeyShareLnpProofSetRoot"] = serde_json::json!(
        derive_protocol_hash(
            "PublicKeyShareProofRoot",
            &package["publicKeyShareLnpProofs"]
        )
        .expect("public-key LNP proof set root")
    );
    rebind_active_static_setup_theorem_certificate(package);
}

fn rebind_collective_public_key_root(package: &mut serde_json::Value) {
    package["collectivePublicKey"]
        .as_object_mut()
        .expect("collective public key")
        .remove("collectivePublicKeyRoot");
    package["collectivePublicKey"]["collectivePublicKeyRoot"] = serde_json::json!(
        derive_protocol_hash("CollectivePublicKeyRoot", &package["collectivePublicKey"])
            .expect("collective public-key root")
    );
    package["collectivePublicKeyRoot"] =
        package["collectivePublicKey"]["collectivePublicKeyRoot"].clone();
    rebind_active_static_setup_theorem_certificate(package);
}

fn rebind_collective_public_key_share_roots(package: &mut serde_json::Value) {
    let share_records = package["publicKeyShares"]["shareRecords"]
        .as_array_mut()
        .expect("public-key share records");
    let mut public_key_share_roots = Vec::new();
    for share_record in share_records {
        share_record
            .as_object_mut()
            .expect("public-key share record")
            .remove("publicKeyShareRoot");
        share_record["publicKeyShareRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareRoot", share_record)
                .expect("public-key share root")
        );
        public_key_share_roots.push(serde_json::json!({
            "trusteeIdentity": share_record["trusteeIdentity"],
            "trusteeRosterPosition": share_record["trusteeRosterPosition"],
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
        }));
    }
    package["publicKeyShares"]["publicKeyShareRoots"] = serde_json::json!(public_key_share_roots);
    package["publicKeyShares"]
        .as_object_mut()
        .expect("public-key share set")
        .remove("publicKeyShareSetRoot");
    package["publicKeyShares"]["publicKeyShareSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareRoot", &package["publicKeyShares"])
            .expect("public-key share set root")
    );
}

fn rebind_collective_public_key_share_proof_roots(package: &mut serde_json::Value) {
    let proof_records = package["publicKeyShareProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key share proof records");
    let mut public_key_share_proof_roots = Vec::new();
    for proof_record in proof_records {
        proof_record
            .as_object_mut()
            .expect("public-key share proof record")
            .remove("publicKeyShareProofRoot");
        proof_record["publicKeyShareProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", proof_record)
                .expect("public-key share proof root")
        );
        public_key_share_proof_roots.push(serde_json::json!({
            "trusteeIdentity": proof_record["trusteeIdentity"],
            "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
            "publicKeyShareProofRoot": proof_record["publicKeyShareProofRoot"],
        }));
    }
    package["publicKeyShareProofs"]["publicKeyShareProofRoots"] =
        serde_json::json!(public_key_share_proof_roots);
    package["publicKeyShareProofs"]
        .as_object_mut()
        .expect("public-key share proof set")
        .remove("publicKeyShareProofSetRoot");
    package["publicKeyShareProofs"]["publicKeyShareProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareProofRoot", &package["publicKeyShareProofs"])
            .expect("public-key share proof set root")
    );
}

fn rebind_collective_evaluator_key_schedule_root(package: &mut serde_json::Value) {
    package["evaluatorKeySchedule"]
        .as_object_mut()
        .expect("evaluator key schedule")
        .remove("evaluatorKeyScheduleRoot");
    package["evaluatorKeySchedule"]["evaluatorKeyScheduleRoot"] = serde_json::json!(
        derive_protocol_hash("EvaluatorKeyScheduleRoot", &package["evaluatorKeySchedule"])
            .expect("evaluator key schedule root")
    );
}

fn rebind_relinearization_key_share_rounds_root(package: &mut serde_json::Value) {
    package["relinearizationKeyShareRounds"]
        .as_object_mut()
        .expect("relinearization key share rounds")
        .remove("relinearizationKeyShareRoundsRoot");
    package["relinearizationKeyShareRounds"]["relinearizationKeyShareRoundsRoot"] = serde_json::json!(
        derive_protocol_hash(
            "RelinearizationKeyShareRoundsRoot",
            &package["relinearizationKeyShareRounds"]
        )
        .expect("relinearization key share rounds root")
    );
}

fn rebind_galois_key_batch_proof_root(package: &mut serde_json::Value, batch_index: usize) {
    let batch = &mut package["galoisKeyShareBatches"][batch_index];
    let proof_roots = batch["galoisKeyShareProofs"]
        .as_array()
        .expect("Galois key share proofs")
        .iter()
        .map(|proof| {
            serde_json::json!({
                "rotation": proof["rotation"],
                "level": proof["level"],
                "galoisKeyShareProofRoot": proof["galoisKeyShareProofRoot"],
            })
        })
        .collect::<Vec<_>>();
    batch["galoisKeyBatchProofRoot"] = serde_json::json!(
        derive_protocol_hash(
            "GaloisKeyBatchProofRoot",
            &serde_json::json!({
                "objectType": "GaloisKeyBatchProofAggregate",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-LNP-SetupProof-v1",
                "proofFamily": "galois-key-share",
                "evaluatorKeyScheduleRoot": batch["evaluatorKeyScheduleRoot"],
                "trusteeRosterPosition": batch["trusteeRosterPosition"],
                "requiredGaloisSetHash": batch["requiredGaloisSetHash"],
                "proofRoots": proof_roots,
            })
        )
        .expect("Galois proof root")
    );
}

fn rebind_galois_key_share_batch_root(package: &mut serde_json::Value, batch_index: usize) {
    package["galoisKeyShareBatches"][batch_index]
        .as_object_mut()
        .expect("Galois key share batch")
        .remove("galoisKeyShareBatchRoot");
    package["galoisKeyShareBatches"][batch_index]["galoisKeyShareBatchRoot"] = serde_json::json!(
        derive_protocol_hash(
            "GaloisKeyShareBatchRoot",
            &package["galoisKeyShareBatches"][batch_index]
        )
        .expect("Galois key share batch root")
    );
}

fn rebind_public_evaluation_key_set_hash(package: &mut serde_json::Value) {
    package["evaluationKeys"]
        .as_object_mut()
        .expect("public evaluation-key set")
        .remove("evaluationKeySetHash");
    package["evaluationKeys"]["evaluationKeySetHash"] = serde_json::json!(
        derive_protocol_hash("EvaluationKeySetHash", &package["evaluationKeys"])
            .expect("evaluation key set hash")
    );
}

fn rebind_collective_he_security_certificate_hash(package: &mut serde_json::Value) {
    package["heSecurityCertificate"]
        .as_object_mut()
        .expect("HE security certificate")
        .remove("heSecurityCertificateHash");
    let he_security_certificate_hash = derive_protocol_hash(
        "BGVHeSecurityCertificateHash",
        &package["heSecurityCertificate"],
    )
    .expect("HE security certificate hash");
    package["heSecurityCertificate"]["heSecurityCertificateHash"] =
        serde_json::json!(he_security_certificate_hash.clone());
    package["heSecurityCertificateHash"] = serde_json::json!(he_security_certificate_hash);
}

fn rebind_setup_key_correctness_certificate(package: &mut serde_json::Value) {
    let mut certificate = setup_key_correctness_certificate_value(package)
        .expect("setup key correctness certificate");
    let certificate_hash = setup_key_correctness_certificate_hash(package)
        .expect("setup key correctness certificate hash");
    certificate["setupKeyCorrectnessCertificateHash"] = serde_json::json!(certificate_hash.clone());
    package["setupKeyCorrectnessCertificate"] = certificate;
    package["setupKeyCorrectnessCertificateHash"] = serde_json::json!(certificate_hash);
    rebind_active_static_setup_theorem_certificate(package);
}

fn rebind_active_static_setup_theorem_certificate(package: &mut serde_json::Value) {
    let mut certificate = active_static_setup_theorem_certificate_value(package)
        .expect("active-static setup theorem certificate");
    let certificate_hash = active_static_setup_theorem_certificate_hash(package)
        .expect("active-static setup theorem certificate hash");
    certificate["activeStaticSetupTheoremCertificateHash"] =
        serde_json::json!(certificate_hash.clone());
    package["activeStaticSetupTheoremCertificate"] = certificate;
    package["activeStaticSetupTheoremCertificateHash"] = serde_json::json!(certificate_hash);
}

fn encode_transport_material_from_package(package: &serde_json::Value) -> Vec<u8> {
    let material_records = package["vssCoefficientCommitmentMaterial"]["coefficientCommitments"]
        .as_array()
        .expect("coefficient material records");
    let ring_degree = package["vssCoefficientCommitmentMaterial"]["ringDegree"]
        .as_u64()
        .expect("ring degree");
    let mut output = Vec::new();
    output.extend(b"SLVSSMAT");
    crate::encoding::append_varuint(&mut output, 1);
    crate::encoding::append_varuint(&mut output, 10);
    crate::encoding::append_varuint(&mut output, 4);
    crate::encoding::append_varuint(&mut output, DATA_PRIMES.len() as u64);
    crate::encoding::append_varuint(&mut output, ring_degree);
    crate::encoding::append_varuint(
        &mut output,
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64,
    );
    crate::encoding::append_varuint(&mut output, SETUP_COMMITMENT_ROW_COUNT as u64);

    for source_trustee_roster_position in 0..10_u64 {
        for rns_limb_index in 0..DATA_PRIMES.len() {
            for shamir_coefficient_index in 0..4_u64 {
                let record_index = (((source_trustee_roster_position as usize)
                    * DATA_PRIMES.len()
                    + rns_limb_index)
                    * 4)
                    + shamir_coefficient_index as usize;
                let commitment = &material_records[record_index]["commitment"];
                crate::encoding::append_varuint(&mut output, source_trustee_roster_position);
                crate::encoding::append_varuint(&mut output, rns_limb_index as u64);
                crate::encoding::append_varuint(&mut output, shamir_coefficient_index);
                for limb in commitment["commitmentLimbs"]
                    .as_array()
                    .expect("commitment limbs")
                {
                    crate::encoding::append_varuint(
                        &mut output,
                        limb["commitmentModulusIndex"]
                            .as_u64()
                            .expect("commitment modulus index"),
                    );
                    output.extend(
                        limb["modulus"]
                            .as_u64()
                            .expect("commitment modulus")
                            .to_le_bytes(),
                    );
                    for row in limb["rows"].as_array().expect("commitment rows") {
                        for coefficient in row.as_array().expect("commitment row coefficients") {
                            output.extend(
                                coefficient
                                    .as_u64()
                                    .expect("commitment coefficient")
                                    .to_le_bytes(),
                            );
                        }
                    }
                }
            }
        }
    }

    output
}

fn transported_material_value(material_bytes: &[u8]) -> serde_json::Value {
    let chunks = material_bytes
        .chunks(1_048_576)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let transport_hashes =
        crate::bgv::setup::threshold_share_commitments::setup_vss_material_transport_hashes(
            &chunks, 1_048_576,
        )
        .expect("transport hashes");

    serde_json::json!({
        "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
        "objectVersion": 1,
        "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
        "chunkSizeBytes": 1_048_576,
        "chunkCount": chunks.len(),
        "totalByteLength": material_bytes.len(),
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkHashes": transport_hashes.chunk_hashes,
        "chunkRoot": transport_hashes.chunk_root,
        "chunks": chunks.iter().enumerate().map(|(chunk_index, chunk)| {
            serde_json::json!({
                "chunkIndex": chunk_index,
                "bytesHex": crate::hashing::to_hex(chunk),
            })
        }).collect::<Vec<_>>(),
    })
}
