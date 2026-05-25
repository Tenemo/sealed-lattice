use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::{
    bgv::{
        encoding::encode_batch_plaintext_slots,
        profile::{
            BACKEND_PROFILE_ID, BATCH_ENCODER_ID, BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS,
            POLYNOMIAL_DEGREE, PROFILE_ID, aggregate_input_encoding_profile_digest,
            allowed_operation_registry_digest, backend_profile_digest,
            ballot_score_encoding_profile_digest, ballot_share_layout_profile_digest,
            batch_encoder_digest, batch_layout_binding_digest,
            canonical_ciphertext_convention_digest, encoded_aggregate_layout_digest, layout_digest,
            profile_digest, security_estimator_input_digest, top_k_evaluator_input_layout_digest,
        },
        serialization::{
            BgvObjectKind, canonical_bytes_hash, ciphertext_root, serialize_bgv_object,
        },
        validation::reject_if_oracle_boundary_fields_present,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{derive_protocol_digest, hash512, hash512_hex},
};

pub(crate) const PASSIVE_SETUP_PROFILE_ID: &str =
    "sealed-lattice-bgv-rns-passive-full-roster-setup-v1";
pub(crate) const THRESHOLD_DECRYPTION_PROFILE_ID: &str = "BGV-RNS-KLLPS26-AsyncLagrangeTarget-v1";
pub(crate) const KEY_SWITCH_DECOMPOSITION_PROFILE_ID: &str =
    "sealed-lattice-bgv-rns-key-switch-decomposition-v1";
pub(crate) const PROVISIONAL_ROT_SET_ID: &str =
    "sealed-lattice-provisional-m10-top-k-rotation-set-v1";
const MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 50;
const MINIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 3;
const DEVELOPMENT_ENCRYPTION_FIXTURE_ID: &str =
    "sealed-lattice-m8-development-encryption-fixture-v1";

#[derive(Clone)]
struct SetupParticipant {
    trustee_identity: String,
    roster_position: usize,
    board_position: usize,
    recovery_epoch: u64,
    device_epoch: u64,
}

#[derive(Clone)]
struct PassiveSetupInput {
    ceremony_id: String,
    manifest_digest: String,
    roster_digest: String,
    threshold_profile_digest: String,
    setup_seed_digest: String,
    participants: Vec<SetupParticipant>,
}

struct ParticipantSetupMaterial {
    participant_record: Value,
    public_key_share_root: String,
    participant_setup_record_digest: String,
    trustee_threshold_verification_key_digest: String,
}

struct VerifiedParticipantSetupBinding {
    trustee_identity: String,
    roster_position: usize,
    recovery_epoch: u64,
    device_epoch: u64,
    public_key_share_root: String,
    participant_setup_record_digest: String,
    trustee_threshold_verification_key_digest: String,
}

pub(crate) fn describe_passive_setup_object_model() -> CanonicalResult<Value> {
    Ok(json!({
        "objectModelId": "sealed-lattice-m8-passive-setup-object-model-v1",
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "keySwitchDecompositionProfileId": KEY_SWITCH_DECOMPOSITION_PROFILE_ID,
        "provisionalRotSetId": PROVISIONAL_ROT_SET_ID,
        "canonicalObjects": [
            "BgvPassiveSetupPackage",
            "ParticipantBgvSetupRecord",
            "BgvPublicKeyShare",
            "BgvCollectivePublicKey",
            "ThresholdShareVerificationKeySet",
            "TrusteeThresholdVerificationKey",
            "BgvRelinearizationKey",
            "BgvRotationKey",
            "BgvKeySwitchKey",
            "BgvEvaluationKeySet",
            "BgvSetupParameterCertificate",
            "CollectiveSecretDistributionCertificate",
            "ErrorDistributionCertificate",
            "EvaluationKeySizeCertificate",
            "BgvDevelopmentEncryptionFixture"
        ],
        "reservedRootsAndDigests": [
            "BGVPassiveSetupPackageDigest",
            "ParticipantBgvSetupRecordDigest",
            "PublicKeyShareRoot",
            "BGVPublicKeyRoot",
            "CollectivePublicKeyRoot",
            "ThresholdShareVerificationKeyRoot",
            "ThresholdShareVerificationKeyDigest",
            "TrusteeThresholdVerificationKeyDigest",
            "RelinearizationKeyRoot",
            "RotationKeyRoot",
            "KeySwitchKeyRoot",
            "KeySwitchDecompositionDigest",
            "EvalKeyRoot",
            "EvaluationKeySizeProfileDigest",
            "CollectiveSecretDistributionCertificateDigest",
            "ErrorDistributionCertificateDigest",
            "BGVSetupParameterCertificateDigest",
            "BGVDevelopmentEncryptionFixtureDigest",
            "RotSetDigest"
        ],
        "trustedDealerBoundary": {
            "transcriptValidCentralizedSecretReconstruction": false,
            "centralizedSecretFixtureMayProduceAcceptedRoots": false,
            "rawSecretSharesExported": false
        },
        "statusLabels": [
            "M8CanonicalObjectModelFrozen",
            "PassiveSetupOnly",
            "KllpsCompatibleSetupMaterialOnly"
        ],
    }))
}

pub(crate) fn generate_passive_setup_package_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_if_oracle_boundary_fields_present(request)?;
    reject_forbidden_setup_fields(request)?;
    let input = read_passive_setup_input(request)?;

    build_passive_setup_package(&input)
}

pub(crate) fn verify_passive_setup_package_from_request(request: &Value) -> CanonicalResult<Value> {
    reject_if_oracle_boundary_fields_present(request)?;
    reject_forbidden_setup_fields(request)?;
    let setup_package = request.get("setupPackage").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is required",
        )
    })?;
    let setup_package_digest = setup_package
        .get("setupPackageDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupPackageDigest must be present",
            )
        })?;
    let mut digest_input = setup_package.clone();
    let digest_object = digest_input.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage must be an object",
        )
    })?;
    digest_object.remove("setupPackageDigest");
    let expected_digest = derive_protocol_digest("BGVPassiveSetupPackageDigest", &digest_input)?;
    if setup_package_digest != expected_digest {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "BGV passive setup package digest does not match its canonical payload",
        ));
    }

    compare_expected_string(
        request,
        "expectedSetupPackageDigest",
        setup_package_digest,
        "setup package digest",
    )?;
    compare_expected_string(
        request,
        "expectedManifestDigest",
        string_at_path(setup_package, &["setupInputs", "manifestDigest"])?,
        "manifest digest",
    )?;
    compare_expected_string(
        request,
        "expectedRosterDigest",
        string_at_path(setup_package, &["setupInputs", "rosterDigest"])?,
        "roster digest",
    )?;
    compare_expected_string(
        request,
        "expectedCollectivePublicKeyRoot",
        string_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?,
        "collective public key root",
    )?;
    compare_expected_string(
        request,
        "expectedRotSetDigest",
        string_at_path(setup_package, &["evaluationKeys", "rotSetDigest"])?,
        "rotation set digest",
    )?;
    compare_expected_string(
        request,
        "expectedEvaluationKeyRoot",
        string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
        "evaluation key root",
    )?;

    validate_setup_package_shape(setup_package)?;
    validate_setup_package_internal_bindings(setup_package)?;

    Ok(json!({
        "ok": true,
        "operation": "verifyBgvPassiveSetupPackage",
        "acceptedDigests": [
            setup_package_digest,
            string_at_path(setup_package, &["collectivePublicKey", "collectivePublicKeyRoot"])?,
            string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
            string_at_path(setup_package, &["thresholdVerificationMaterial", "thresholdShareVerificationKeyRoot"])?,
            string_at_path(setup_package, &["thresholdVerificationMaterial", "thresholdShareVerificationKeyDigest"])?,
            string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
            string_at_path(setup_package, &["evaluationKeys", "rotSetDigest"])?,
        ],
        "refusedObjects": [],
        "unresolvedReason": null,
        "statusLabels": [
            "M8PassiveSetupPackageVerified",
            "CollectivePublicKeyRootBound",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "AppendixBSetupInputReady",
            "FinalAppendixBPendingQTarget"
        ],
    }))
}

fn build_passive_setup_package(input: &PassiveSetupInput) -> CanonicalResult<Value> {
    let profile_digest = profile_digest()?;
    let backend_profile_digest = backend_profile_digest()?;
    let collective_secret_distribution_certificate =
        collective_secret_distribution_certificate(input.participants.len())?;
    let collective_secret_distribution_certificate_digest = derive_protocol_digest(
        "CollectiveSecretDistributionCertificateDigest",
        &collective_secret_distribution_certificate,
    )?;
    let error_distribution_certificate = error_distribution_certificate()?;
    let error_distribution_certificate_digest = derive_protocol_digest(
        "ErrorDistributionCertificateDigest",
        &error_distribution_certificate,
    )?;
    let key_switch_decomposition = key_switch_decomposition_profile()?;
    let key_switch_decomposition_digest =
        derive_protocol_digest("KeySwitchDecompositionDigest", &key_switch_decomposition)?;
    let threshold_decryption_profile = threshold_decryption_profile(&profile_digest)?;
    let threshold_decryption_profile_digest = derive_protocol_digest(
        "ThresholdDecryptionProfileDigest",
        &threshold_decryption_profile,
    )?;
    let kllps_target_decryption_profile_digest = derive_protocol_digest(
        "KllpsTargetDecryptionProfileDigest",
        &json!({
            "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "profileStatus": "future-target-decryption-profile-binding",
        }),
    )?;
    let public_common_random_polynomial_root = public_common_random_polynomial_root(input)?;
    let participant_material = input
        .participants
        .iter()
        .map(|participant| {
            participant_setup_material(
                input,
                participant,
                &profile_digest,
                &backend_profile_digest,
                &public_common_random_polynomial_root,
                &threshold_decryption_profile_digest,
                &kllps_target_decryption_profile_digest,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let participant_records = participant_material
        .iter()
        .map(|material| material.participant_record.clone())
        .collect::<Vec<_>>();
    let public_key_share_roots = participant_material
        .iter()
        .map(|material| material.public_key_share_root.clone())
        .collect::<Vec<_>>();
    let participant_setup_record_digests = participant_material
        .iter()
        .map(|material| material.participant_setup_record_digest.clone())
        .collect::<Vec<_>>();
    let trustee_threshold_verification_key_digests = participant_material
        .iter()
        .map(|material| material.trustee_threshold_verification_key_digest.clone())
        .collect::<Vec<_>>();
    let collective_public_key = collective_public_key(
        input,
        &profile_digest,
        &backend_profile_digest,
        &public_common_random_polynomial_root,
        &public_key_share_roots,
    )?;
    let threshold_verification_material = threshold_verification_material(
        input,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
        &participant_setup_record_digests,
        &trustee_threshold_verification_key_digests,
    )?;
    let evaluation_keys = evaluation_keys(
        input,
        &collective_public_key,
        &key_switch_decomposition_digest,
    )?;
    let development_encryption_fixture =
        development_encryption_fixture(input, &collective_public_key)?;
    let certificates = setup_certificates(
        input,
        &collective_secret_distribution_certificate,
        &collective_secret_distribution_certificate_digest,
        &error_distribution_certificate,
        &error_distribution_certificate_digest,
        &key_switch_decomposition,
        &key_switch_decomposition_digest,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
        &evaluation_keys,
        &development_encryption_fixture,
    )?;

    let mut package = json!({
        "objectType": "BgvPassiveSetupPackage",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "setupMode": "passive-full-roster-development",
        "setupInputs": {
            "ceremonyId": input.ceremony_id,
            "manifestDigest": input.manifest_digest,
            "rosterDigest": input.roster_digest,
            "thresholdProfileDigest": input.threshold_profile_digest,
            "participantCount": input.participants.len(),
            "participantIdentities": input.participants.iter().map(|participant| participant.trustee_identity.clone()).collect::<Vec<_>>(),
            "setupSeedDigest": input.setup_seed_digest,
        },
        "profileBindings": {
            "profileId": PROFILE_ID,
            "backendProfileId": BACKEND_PROFILE_ID,
            "profileDigest": profile_digest,
            "backendProfileDigest": backend_profile_digest,
            "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest()?,
            "batchEncoderId": BATCH_ENCODER_ID,
            "batchEncoderDigest": batch_encoder_digest()?,
            "batchLayoutBindingDigest": batch_layout_binding_digest()?,
            "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
            "encryptedAggregateInputLayoutDigest": layout_digest()?,
            "ballotScoreEncodingProfileDigest": ballot_score_encoding_profile_digest()?,
            "ballotShareLayoutProfileDigest": ballot_share_layout_profile_digest()?,
            "aggregateInputEncodingProfileDigest": aggregate_input_encoding_profile_digest()?,
            "encodedAggregateLayoutDigest": encoded_aggregate_layout_digest()?,
            "topKEvaluatorInputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        },
        "participants": participant_records,
        "collectivePublicKey": collective_public_key,
        "thresholdVerificationMaterial": threshold_verification_material,
        "evaluationKeys": evaluation_keys,
        "developmentEncryptionFixture": development_encryption_fixture,
        "certificates": certificates,
        "trustedDealerBoundary": {
            "transcriptValidCentralizedSecretReconstruction": false,
            "centralizedSecretFixtureMayProduceAcceptedRoots": false,
            "rawSecretSharesExported": false,
            "forbiddenRequestFields": forbidden_setup_field_names(),
        },
        "kllpsCompatibility": {
            "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
            "setupMaterialCompatibleWithKLLPS": true,
            "KLLPSPartDecImplemented": false,
            "KLLPSC1C4Certified": false,
        },
        "statusLabels": [
            "M8PassiveSetupGenerated",
            "FullRosterSetupMaterialGenerated",
            "CollectivePublicKeyRootBound",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "KllpsCompatibleSetupMaterial",
            "AppendixBSetupInputReady",
            "FinalAppendixBPendingQTarget"
        ],
        "nonClaims": [
            "ActiveMaliciousSetupProofMissing",
            "MaliciousEvaluationKeyProofMissing",
            "KLLPSPartDecNotImplemented",
            "KLLPSC1C4NotCertified",
            "FinalAppendixBPendingQTarget",
            "FinalEvaluatorNoisePendingM10AppendixD",
            "StageXNotClosed",
            "StageCNotClosed",
            "StageANotClosed"
        ],
    });
    let setup_package_digest = derive_protocol_digest("BGVPassiveSetupPackageDigest", &package)?;
    package["setupPackageDigest"] = Value::String(setup_package_digest);

    Ok(package)
}

fn read_passive_setup_input(request: &Value) -> CanonicalResult<PassiveSetupInput> {
    let ceremony_id = read_non_empty_string(request, "ceremonyId")?.to_string();
    let manifest_digest = read_digest_field(request, "manifestDigest")?.to_string();
    let roster_digest = read_digest_field(request, "rosterDigest")?.to_string();
    let threshold_profile_digest =
        read_digest_field(request, "thresholdProfileDigest")?.to_string();
    let setup_seed = request
        .get("setupSeed")
        .and_then(Value::as_str)
        .unwrap_or("sealed-lattice-m8-passive-development-seed-v1");
    if setup_seed.trim().is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupSeed must not be empty when supplied",
        ));
    }
    let setup_seed_digest = hash512_hex(
        "sealed-lattice-bgv-rns/passive-setup-seed-digest-v1",
        &[
            ceremony_id.as_bytes(),
            manifest_digest.as_bytes(),
            roster_digest.as_bytes(),
            threshold_profile_digest.as_bytes(),
            setup_seed.as_bytes(),
        ],
    );
    let participants = read_setup_participants(request)?;
    if participants.len() < MINIMUM_PASSIVE_SETUP_ROSTER_SIZE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M8 passive setup requires at least three frozen roster participants",
        ));
    }
    if participants.len() > MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M8 passive setup supports at most fifty frozen roster participants",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    for participant in &participants {
        if !identities.insert(participant.trustee_identity.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M8 passive setup participant identities must be unique",
            ));
        }
        if participant.roster_position >= participants.len()
            || !roster_positions.insert(participant.roster_position)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M8 passive setup roster positions must be unique and cover the frozen roster",
            ));
        }
    }

    Ok(PassiveSetupInput {
        ceremony_id,
        manifest_digest,
        roster_digest,
        threshold_profile_digest,
        setup_seed_digest,
        participants,
    })
}

fn read_setup_participants(request: &Value) -> CanonicalResult<Vec<SetupParticipant>> {
    let participants = request
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participants must be an array",
            )
        })?;
    participants
        .iter()
        .enumerate()
        .map(|(index, value)| match value {
            Value::String(identity) => {
                if identity.trim().is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "participant identity must not be empty",
                    ));
                }
                Ok(SetupParticipant {
                    trustee_identity: identity.clone(),
                    roster_position: index,
                    board_position: index,
                    recovery_epoch: 0,
                    device_epoch: 0,
                })
            }
            Value::Object(_) => {
                reject_forbidden_setup_fields(value)?;
                let trustee_identity = read_non_empty_string(value, "trusteeIdentity")?.to_string();
                Ok(SetupParticipant {
                    trustee_identity,
                    roster_position: read_optional_usize(value, "rosterPosition")?.unwrap_or(index),
                    board_position: read_optional_usize(value, "boardPosition")?.unwrap_or(index),
                    recovery_epoch: read_optional_u64(value, "recoveryEpoch")?.unwrap_or(0),
                    device_epoch: read_optional_u64(value, "deviceEpoch")?.unwrap_or(0),
                })
            }
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participants entries must be trustee identity strings or participant objects",
            )),
        })
        .collect()
}

fn participant_setup_material(
    input: &PassiveSetupInput,
    participant: &SetupParticipant,
    profile_digest: &str,
    backend_profile_digest: &str,
    public_common_random_polynomial_root: &str,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<ParticipantSetupMaterial> {
    let local_secret_share_commitment_digest = hash512_hex(
        "sealed-lattice-bgv-rns/local-secret-share-commitment-v1",
        &[
            input.setup_seed_digest.as_bytes(),
            participant.trustee_identity.as_bytes(),
            participant.roster_position.to_string().as_bytes(),
            profile_digest.as_bytes(),
        ],
    );
    let local_error_commitment_digest = hash512_hex(
        "sealed-lattice-bgv-rns/local-error-commitment-v1",
        &[
            input.setup_seed_digest.as_bytes(),
            participant.trustee_identity.as_bytes(),
            participant.roster_position.to_string().as_bytes(),
            public_common_random_polynomial_root.as_bytes(),
        ],
    );
    let public_key_share_record = json!({
        "objectType": "BgvPublicKeyShare",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "localSecretShareCommitmentDigest": local_secret_share_commitment_digest,
        "localErrorCommitmentDigest": local_error_commitment_digest,
        "publicShareConstruction": "b_i=-a*s_i+e_i-over-selected-BGV-RNS-profile",
        "rawSecretShareExported": false,
        "centralizedSecretReconstruction": false,
        "sampledLocalSecretCoefficients": sample_small_distribution(
            &input.setup_seed_digest,
            &participant.trustee_identity,
            "local-secret-share",
            -1,
            1,
        ),
        "sampledLocalErrorCoefficients": sample_centered_binomial_eta2(
            &input.setup_seed_digest,
            &participant.trustee_identity,
            "local-error",
        ),
    });
    let public_key_share_root =
        derive_protocol_digest("PublicKeyShareRoot", &public_key_share_record)?;
    let trustee_threshold_verification_key = json!({
        "objectType": "TrusteeThresholdVerificationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
        "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "publicKeyShareRoot": public_key_share_root,
        "verificationStatement": "passive-transcript-identity-profile-and-share-domain-binding",
        "maliciousDkgProofIncluded": false,
    });
    let trustee_threshold_verification_key_digest = derive_protocol_digest(
        "TrusteeThresholdVerificationKeyDigest",
        &trustee_threshold_verification_key,
    )?;
    let participant_record_without_digest = json!({
        "objectType": "ParticipantBgvSetupRecord",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "thresholdProfileDigest": input.threshold_profile_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "boardPosition": participant.board_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicKeyShareRoot": public_key_share_root,
        "trusteeThresholdVerificationKeyDigest": trustee_threshold_verification_key_digest,
        "localSecretShareCommitmentDigest": local_secret_share_commitment_digest,
        "localErrorCommitmentDigest": local_error_commitment_digest,
        "rawSecretShareExported": false,
        "centralizedSecretReconstruction": false,
        "setupProofProfileForM19": "passive-record-only-active-proof-pending-M19",
    });
    let participant_setup_record_digest = derive_protocol_digest(
        "ParticipantBgvSetupRecordDigest",
        &participant_record_without_digest,
    )?;
    let mut participant_record = participant_record_without_digest;
    participant_record["participantSetupRecordDigest"] =
        Value::String(participant_setup_record_digest.clone());

    Ok(ParticipantSetupMaterial {
        participant_record,
        public_key_share_root,
        participant_setup_record_digest,
        trustee_threshold_verification_key_digest,
    })
}

fn collective_public_key(
    input: &PassiveSetupInput,
    profile_digest: &str,
    backend_profile_digest: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
) -> CanonicalResult<Value> {
    let record_without_roots = json!({
        "objectType": "BgvCollectivePublicKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "publicKeyShareRoots": public_key_share_roots,
        "aggregationRule": "coefficient-wise-public-key-share-sum-with-shared-crp",
        "participantCount": public_key_share_roots.len(),
        "centralizedSecretReconstruction": false,
        "rawSecretShareExported": false,
    });
    let collective_public_key_root =
        derive_protocol_digest("CollectivePublicKeyRoot", &record_without_roots)?;
    let bgv_public_key_root = derive_protocol_digest(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "profileDigest": profile_digest,
            "backendProfileDigest": backend_profile_digest,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;

    Ok(json!({
        "record": record_without_roots,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "statusLabels": [
            "CollectivePublicKeyShareAggregationBound",
            "NoTrustedDealerSecretReconstruction"
        ],
    }))
}

fn threshold_verification_material(
    input: &PassiveSetupInput,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
    participant_setup_record_digests: &[String],
    trustee_threshold_verification_key_digests: &[String],
) -> CanonicalResult<Value> {
    let participant_points = input
        .participants
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity.clone(),
                "rosterPosition": participant.roster_position,
                "interpolationPoint": participant.roster_position + 1,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    let verification_key_set = json!({
        "objectType": "ThresholdShareVerificationKeySet",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
        "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "participantSetupRecordDigests": participant_setup_record_digests,
        "trusteeThresholdVerificationKeyDigests": trustee_threshold_verification_key_digests,
        "participantInterpolationUniverse": participant_points,
        "secretShareDomain": "BGV-RNS-secret-share-polynomial-over-selected-Q-data",
        "passiveSetupVerificationScope": [
            "transcript-binding",
            "identity-binding",
            "roster-binding",
            "profile-binding",
            "recovery-device-epoch-binding"
        ],
        "maliciousDkgProofIncluded": false,
    });
    let threshold_share_verification_key_root =
        derive_protocol_digest("ThresholdShareVerificationKeyRoot", &verification_key_set)?;
    let threshold_share_verification_key_digest = derive_protocol_digest(
        "ThresholdShareVerificationKeyDigest",
        &json!({
            "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        }),
    )?;

    Ok(json!({
        "verificationKeySet": verification_key_set,
        "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
        "thresholdShareVerificationKeyDigest": threshold_share_verification_key_digest,
        "trusteeThresholdVerificationKeyDigests": trustee_threshold_verification_key_digests,
        "statusLabels": [
            "ThresholdVerificationMaterialBound",
            "PassiveSetupVerificationScopeOnly",
            "KllpsCompatibleVerificationRootsBound"
        ],
    }))
}

fn evaluation_keys(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
    key_switch_decomposition_digest: &str,
) -> CanonicalResult<Value> {
    let rot_set = provisional_rotation_set()?;
    let rot_set_digest = derive_protocol_digest("RotSetDigest", &rot_set)?;
    let collective_public_key_root =
        string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?;
    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 2,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let relinearization_key_root =
        derive_protocol_digest("RelinearizationKeyRoot", &relinearization_key_record)?;
    let rotation_key_records = rot_set["rotations"]
        .as_array()
        .expect("rotation set uses array")
        .iter()
        .map(|rotation| {
            let record = json!({
                "objectType": "BgvRotationKey",
                "objectVersion": 1,
                "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
                "ceremonyId": input.ceremony_id,
                "rosterDigest": input.roster_digest,
                "collectivePublicKeyRoot": collective_public_key_root,
                "rotSetDigest": rot_set_digest,
                "rotation": rotation,
                "keySwitchDecompositionDigest": key_switch_decomposition_digest,
                "publicBasisId": BgvBasisKind::Extended.basis_id(),
                "publicRlweSampleCount": 1,
                "maliciousEvaluationKeyProofIncluded": false,
            });
            let root = derive_protocol_digest("RotationKeyRoot", &record)?;
            Ok(json!({
                "rotation": rotation,
                "rotationKeyRoot": root,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 1,
        "genericKeySwitchApiExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let key_switch_key_root = derive_protocol_digest("KeySwitchKeyRoot", &key_switch_key_record)?;
    let evaluation_key_record = json!({
        "objectType": "BgvEvaluationKeySet",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "rotSetDigest": rot_set_digest,
        "relinearizationKeyRoot": relinearization_key_root,
        "rotationKeyRoots": rotation_key_records,
        "keySwitchKeyRoot": key_switch_key_root,
        "generatedFor": "provisionalRotSet",
        "finalRotSetClosure": "M10-AppendixD",
        "regenerateIfRotSetChanges": true,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let evaluation_key_root = derive_protocol_digest("EvalKeyRoot", &evaluation_key_record)?;

    Ok(json!({
        "record": evaluation_key_record,
        "rotSet": rot_set,
        "rotSetDigest": rot_set_digest,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "relinearizationKeyRoot": relinearization_key_root,
        "keySwitchKeyRoot": key_switch_key_root,
        "rotationKeyRoots": rotation_key_records,
        "evaluationKeyRoot": evaluation_key_root,
        "statusLabels": [
            "RelinearizationKeyMaterialBound",
            "RotationKeyMaterialBound",
            "KeySwitchMaterialBound",
            "ProvisionalRotSetBound"
        ],
    }))
}

fn development_encryption_fixture(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
) -> CanonicalResult<Value> {
    let message_slots = vec![1_u64, 2, 3, 5, 8, 13, 21, 34];
    let randomizer_slots = vec![55_u64, 89, 144, 233, 377, 610, 987, 1597];
    let message = encode_batch_plaintext_slots(&message_slots, 0)?;
    let randomizer = encode_batch_plaintext_slots(&randomizer_slots, 0)?;
    let canonical_bytes = serialize_bgv_object(
        BgvObjectKind::Ciphertext,
        &[message.polynomial, randomizer.polynomial],
    )?;
    let fixture_record = json!({
        "objectType": "BgvDevelopmentEncryptionFixture",
        "objectVersion": 1,
        "fixtureId": DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?,
        "bgvPublicKeyRoot": string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?,
        "ciphertextRoot": ciphertext_root(&canonical_bytes),
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
        "messageSlotSample": message_slots,
        "fixtureScope": "development-encryption-shape-and-root-binding",
        "m9BridgeEncryptionClaim": false,
        "m10EvaluatorClaim": false,
    });
    let fixture_digest =
        derive_protocol_digest("BGVDevelopmentEncryptionFixtureDigest", &fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureDigest": fixture_digest,
        "statusLabels": [
            "DevelopmentEncryptionFixtureBound",
            "CollectivePublicKeyRootBound",
            "NotBridgeProofEvidence",
            "NotEvaluatorClosureEvidence"
        ],
    }))
}

#[allow(clippy::too_many_arguments)]
fn setup_certificates(
    input: &PassiveSetupInput,
    collective_secret_distribution_certificate: &Value,
    collective_secret_distribution_certificate_digest: &str,
    error_distribution_certificate: &Value,
    error_distribution_certificate_digest: &str,
    key_switch_decomposition: &Value,
    key_switch_decomposition_digest: &str,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
    evaluation_keys: &Value,
    development_encryption_fixture: &Value,
) -> CanonicalResult<Value> {
    let q_data_bits = DATA_PRIMES.len() * 47;
    let qp_public_bits = (DATA_PRIMES.len() + 1) * 47;
    let rotation_key_count = evaluation_keys["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots use array")
        .len();
    let public_samples = public_rlwe_samples_by_basis(input.participants.len(), rotation_key_count);
    let evaluation_key_size_certificate = evaluation_key_size_certificate(rotation_key_count);
    let evaluation_key_size_profile_digest = derive_protocol_digest(
        "EvaluationKeySizeProfileDigest",
        &evaluation_key_size_certificate,
    )?;
    let setup_parameter_certificate = json!({
        "objectType": "BgvSetupParameterCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "profileDigest": profile_digest()?,
        "backendProfileDigest": backend_profile_digest()?,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "qDataBits": q_data_bits,
        "qpPublicBits": qp_public_bits,
        "qTargetBits": null,
        "publicEvaluationKeyBasis": BgvBasisKind::Extended.basis_id(),
        "largestExposedModulusBitsWithoutQTarget": qp_public_bits,
        "largestExposedBasisClassWithoutQTarget": "QP_public",
        "largestExposedModulusBits": null,
        "finalSecurityStatus": "pendingQTarget",
        "collectiveSecretDistributionCertificateDigest": collective_secret_distribution_certificate_digest,
        "errorDistributionCertificateDigest": error_distribution_certificate_digest,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "evaluationKeySizeProfileDigest": evaluation_key_size_profile_digest,
        "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
        "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        "securityEstimatorInputDigest": security_estimator_input_digest()?,
        "HEStdPostQuantumRow": {
            "status": "setup-input-recorded-final-row-pending-Q-target",
            "largestKnownExposedModulusBits": qp_public_bits
        },
        "CurrentEstimatorRow": {
            "status": "setup-input-recorded-run-pending-final-estimator-policy",
            "largestKnownExposedModulusBits": qp_public_bits,
            "secretModel": collective_secret_distribution_certificate["resultingGlobalSecretDistribution"]["distributionKind"],
            "errorModel": error_distribution_certificate["errorDistribution"]["distributionKind"]
        }
    });
    let setup_parameter_certificate_digest = derive_protocol_digest(
        "BGVSetupParameterCertificateDigest",
        &setup_parameter_certificate,
    )?;

    Ok(json!({
        "collectiveSecretDistributionCertificate": collective_secret_distribution_certificate,
        "collectiveSecretDistributionCertificateDigest": collective_secret_distribution_certificate_digest,
        "errorDistributionCertificate": error_distribution_certificate,
        "errorDistributionCertificateDigest": error_distribution_certificate_digest,
        "keySwitchDecomposition": key_switch_decomposition,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicRlweSamplesByBasis": public_samples,
        "setupParameterCertificate": setup_parameter_certificate,
        "setupParameterCertificateDigest": setup_parameter_certificate_digest,
        "evaluationKeySizeCertificate": evaluation_key_size_certificate,
        "evaluationKeySizeProfileDigest": evaluation_key_size_profile_digest,
        "developmentEncryptionFixtureDigest": development_encryption_fixture["fixtureDigest"],
        "statusLabels": [
            "ActualSecretDistributionRecorded",
            "ActualErrorDistributionRecorded",
            "PublicRlweSampleCountsRecorded",
            "LargestExposedModulusWithoutQTargetRecorded",
            "EvaluationKeySizeCertificateRecorded",
            "FinalSecurityPendingQTarget"
        ],
    }))
}

fn collective_secret_distribution_certificate(participant_count: usize) -> CanonicalResult<Value> {
    let mut weights = vec![1_u128];
    for _ in 0..participant_count {
        let mut next = vec![0_u128; weights.len() + 2];
        for (index, weight) in weights.iter().enumerate() {
            next[index] += weight;
            next[index + 1] += weight;
            next[index + 2] += weight;
        }
        weights = next;
    }
    let support_offset = i64::try_from(participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "participant count does not fit signed distribution support",
        )
    })?;
    let support = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| {
            json!({
                "secretCoefficientSum": i64::try_from(index).expect("support index fits i64") - support_offset,
                "weight": weight.to_string(),
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "objectType": "CollectiveSecretDistributionCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "localShareSampler": {
            "samplerId": "hash-derived-balanced-ternary-local-share-v1",
            "support": [-1, 0, 1],
            "probabilityNumeratorBySupport": [1, 1, 1],
            "probabilityDenominator": 3,
            "rawShareExported": false
        },
        "localShareDistribution": "balanced-ternary-local-share",
        "aggregationRule": "coefficient-wise-sum-of-all-full-roster-local-shares",
        "participantCount": participant_count,
        "resultingGlobalSecretDistribution": {
            "distributionKind": "sum-of-full-roster-balanced-ternary-local-shares",
            "support": support,
            "totalWeightExpression": format!("3^{participant_count}"),
            "isPlainDenseTernary": participant_count == 1,
        },
        "estimatorSecretModel": "full-roster-balanced-ternary-share-sum-convolution",
        "noiseModelSecretModel": "full-roster-balanced-ternary-share-sum-convolution",
        "sparseSecretFlag": false,
        "fixedHammingSecretFlag": false,
        "rejectionReasonIfUncertified": null,
    }))
}

fn error_distribution_certificate() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "ErrorDistributionCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "errorSampler": {
            "samplerId": "centered-binomial-eta2-development-v1",
            "support": [-2, -1, 0, 1, 2],
            "weights": ["1", "4", "6", "4", "1"],
            "totalWeight": "16"
        },
        "errorDistribution": {
            "distributionKind": "centered-binomial-eta2",
            "support": [-2, -1, 0, 1, 2]
        },
        "encryptionRandomnessDistribution": {
            "distributionKind": "balanced-ternary-local-randomness",
            "support": [-1, 0, 1]
        },
        "keySwitchNoiseDistribution": {
            "distributionKind": "centered-binomial-eta2",
            "support": [-2, -1, 0, 1, 2]
        },
        "crpPublicSampleDistribution": {
            "distributionKind": "hash-to-modulus-uniform-public-sample",
            "basisId": BgvBasisKind::Data.basis_id()
        },
        "rejectionSamplingRules": [],
        "uncertifiedSmallSecretRejected": true,
    }))
}

fn key_switch_decomposition_profile() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvKeySwitchDecompositionProfile",
        "objectVersion": 1,
        "profileId": KEY_SWITCH_DECOMPOSITION_PROFILE_ID,
        "basisId": BgvBasisKind::Extended.basis_id(),
        "digitBaseBits": 23,
        "digitCountPerPrime": 3,
        "decompositionStatus": "provisional-M8-for-M10-schedule",
        "genericKeySwitchApiExported": false,
    }))
}

fn threshold_decryption_profile(profile_digest: &str) -> CanonicalResult<Value> {
    Ok(json!({
        "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "bgvProfileDigest": profile_digest,
        "secretShareDomain": "BGV-RNS-secret-share-polynomial-over-selected-Q-data",
        "asyncLagrangeTargetDirection": true,
        "partDecImplemented": false,
        "finDecImplemented": false,
        "c1ThroughC4Certified": false,
        "qTargetKnown": false,
    }))
}

fn provisional_rotation_set() -> CanonicalResult<Value> {
    Ok(json!({
        "rotSetId": PROVISIONAL_ROT_SET_ID,
        "sourceRdr": "RDR-M10-Top-K-Circuit-And-Sparse-Target",
        "generatedFor": "provisionalRotSet",
        "finalizedBy": "M10-AppendixD",
        "regenerateM8KeysIfChanged": true,
        "rotations": [
            1, 2, 4, 8, 16, 32, 64, 128,
            256, 512, 1024, 2048, 4096, 8192,
            -1, -2, -4, -8, -16, -32, -64, -128,
            -256, -512, -1024, -2048, -4096, -8192
        ],
        "dependencies": [
            "encrypted-aggregate-reconstruction",
            "score-bit-or-comparison-input-derivation",
            "bit-sliced-GT-EQ",
            "rank-accumulation",
            "encrypted-sparse-target-projection",
            "target-decryption-interface-checks"
        ],
    }))
}

fn public_common_random_polynomial_root(input: &PassiveSetupInput) -> CanonicalResult<String> {
    derive_protocol_digest(
        "PublicKeyShareRoot",
        &json!({
            "objectType": "BgvPublicCommonRandomPolynomial",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "ceremonyId": input.ceremony_id,
            "rosterDigest": input.roster_digest,
            "setupSeedDigest": input.setup_seed_digest,
            "basisId": BgvBasisKind::Data.basis_id(),
            "level": DATA_PRIMES.len() - 1,
            "coefficientCount": POLYNOMIAL_DEGREE,
            "sampledResidues": sample_public_residues(
                &input.setup_seed_digest,
                "public-common-random-polynomial",
                DATA_PRIMES[0],
            ),
        }),
    )
}

fn public_rlwe_samples_by_basis(participant_count: usize, rotation_key_count: usize) -> Value {
    json!({
        "QData": {
            "basisId": BgvBasisKind::Data.basis_id(),
            "modulusBits": DATA_PRIMES.len() * 47,
            "publicKeyShares": participant_count,
            "collectivePublicKey": 1,
            "developmentEncryptionFixtures": 1,
        },
        "QPPublic": {
            "basisId": BgvBasisKind::Extended.basis_id(),
            "modulusBits": (DATA_PRIMES.len() + 1) * 47,
            "relinearizationKeys": 2,
            "rotationKeys": rotation_key_count,
            "keySwitchKeys": 1,
        },
        "QTarget": {
            "modulusBits": null,
            "sampleCountStatus": "pendingUntilAppendixC"
        },
    })
}

fn evaluation_key_size_certificate(rotation_key_count: usize) -> Value {
    let residue_byte_count = 8_usize;
    let polynomial_byte_estimate_data = POLYNOMIAL_DEGREE * DATA_PRIMES.len() * residue_byte_count;
    let polynomial_byte_estimate_extended =
        POLYNOMIAL_DEGREE * (DATA_PRIMES.len() + 1) * residue_byte_count;
    let relinearization_key_bytes = 2 * 2 * polynomial_byte_estimate_extended;
    let rotation_key_bytes = rotation_key_count * 2 * polynomial_byte_estimate_extended;
    let key_switch_key_bytes = 2 * polynomial_byte_estimate_extended;
    let total_evaluation_key_bytes =
        relinearization_key_bytes + rotation_key_bytes + key_switch_key_bytes;

    json!({
        "objectType": "EvaluationKeySizeCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "dataBasisPolynomialByteEstimate": polynomial_byte_estimate_data,
        "extendedBasisPolynomialByteEstimate": polynomial_byte_estimate_extended,
        "relinearizationKeyByteEstimate": relinearization_key_bytes,
        "rotationKeyCount": rotation_key_count,
        "rotationKeyByteEstimate": rotation_key_bytes,
        "keySwitchKeyByteEstimate": key_switch_key_bytes,
        "totalEvaluationKeyByteEstimate": total_evaluation_key_bytes,
        "chunkingStrategy": {
            "chunkSizeBytes": 262144,
            "chunkRootRequired": true,
            "streamingVerificationRequired": true
        },
        "storagePressure": {
            "status": "large-public-evaluation-key-material",
            "mobileDownloadRequiresM16Measurement": true
        },
    })
}

fn sample_public_residues(seed_digest: &str, label: &str, modulus: u64) -> Vec<Value> {
    sample_positions()
        .into_iter()
        .map(|position| {
            json!({
                "position": position,
                "modulus": modulus,
                "value": sample_residue(seed_digest, label, position, modulus),
            })
        })
        .collect()
}

fn sample_small_distribution(
    seed_digest: &str,
    identity: &str,
    label: &str,
    minimum: i64,
    maximum: i64,
) -> Vec<Value> {
    let width = u8::try_from(maximum - minimum + 1).expect("small distribution width fits u8");
    sample_positions()
        .into_iter()
        .map(|position| {
            let position_text = position.to_string();
            let output = hash512(
                "sealed-lattice-bgv-rns/sample-small-distribution-v1",
                &[
                    seed_digest.as_bytes(),
                    identity.as_bytes(),
                    label.as_bytes(),
                    position_text.as_bytes(),
                ],
            );
            let value = minimum + i64::from(output[0] % width);
            json!({
                "position": position,
                "value": value,
            })
        })
        .collect()
}

fn sample_centered_binomial_eta2(seed_digest: &str, identity: &str, label: &str) -> Vec<Value> {
    sample_positions()
        .into_iter()
        .map(|position| {
            let position_text = position.to_string();
            let output = hash512(
                "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-v1",
                &[
                    seed_digest.as_bytes(),
                    identity.as_bytes(),
                    label.as_bytes(),
                    position_text.as_bytes(),
                ],
            );
            let low_weight = i64::from(output[0] & 1) + i64::from((output[0] >> 1) & 1);
            let high_weight = i64::from((output[0] >> 2) & 1) + i64::from((output[0] >> 3) & 1);
            json!({
                "position": position,
                "value": low_weight - high_weight,
            })
        })
        .collect()
}

fn sample_residue(seed_digest: &str, label: &str, position: usize, modulus: u64) -> u64 {
    let position_text = position.to_string();
    let modulus_text = modulus.to_string();
    let output = hash512(
        "sealed-lattice-bgv-rns/sample-residue-v1",
        &[
            seed_digest.as_bytes(),
            label.as_bytes(),
            position_text.as_bytes(),
            modulus_text.as_bytes(),
        ],
    );
    let mut word = [0_u8; 8];
    word.copy_from_slice(&output[..8]);

    u64::from_le_bytes(word) % modulus
}

fn sample_positions() -> Vec<usize> {
    let mut positions = vec![
        0_usize,
        1,
        2,
        17,
        POLYNOMIAL_DEGREE / 2,
        POLYNOMIAL_DEGREE - 1,
    ];
    positions.sort_unstable();
    positions.dedup();

    positions
}

fn reject_forbidden_setup_fields(request: &Value) -> CanonicalResult<()> {
    for field_name in forbidden_setup_field_names() {
        if request.get(field_name).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{field_name} would centralize BGV secret material and cannot be accepted by M8 setup"
                ),
            ));
        }
    }

    Ok(())
}

fn forbidden_setup_field_names() -> Vec<&'static str> {
    vec![
        "secretShares",
        "rawSecretShares",
        "globalSecret",
        "globalSecretPolynomial",
        "fullSecretPolynomial",
        "trustedDealerSecret",
        "trustedDealerSecretHex",
        "centralizedSecret",
        "centralizedSecretReconstruction",
        "rawKeySwitchSecret",
        "rawDecryptionSecret",
    ]
}

fn read_non_empty_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    let field = value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })?;
    if field.trim().is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must not be empty"),
        ));
    }

    Ok(field)
}

fn read_digest_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    let digest = read_non_empty_string(value, field_name)?;
    validate_digest_string(digest, field_name)?;

    Ok(digest)
}

fn validate_digest_string(digest: &str, field_name: &str) -> CanonicalResult<()> {
    if digest.len() != 128
        || !digest
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be a 128-character lowercase hexadecimal protocol digest"),
        ));
    }

    Ok(())
}

fn read_optional_u64(value: &Value, field_name: &str) -> CanonicalResult<Option<u64>> {
    value
        .get(field_name)
        .map(|field| {
            field.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name} must be a non-negative integer"),
                )
            })
        })
        .transpose()
}

fn read_optional_usize(value: &Value, field_name: &str) -> CanonicalResult<Option<usize>> {
    read_optional_u64(value, field_name)?
        .map(|field| {
            usize::try_from(field).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name} does not fit usize"),
                )
            })
        })
        .transpose()
}

fn compare_expected_string(
    request: &Value,
    expected_field_name: &str,
    actual: &str,
    description: &str,
) -> CanonicalResult<()> {
    if let Some(expected) = request.get(expected_field_name).and_then(Value::as_str) {
        validate_digest_string(expected, expected_field_name)?;
        if expected != actual {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("BGV passive setup {description} does not match {expected_field_name}"),
            ));
        }
    }

    Ok(())
}

fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a str> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing setup package field {}", path.join(".")),
            )
        })?;
    }
    current.as_str().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("setup package field {} must be a string", path.join(".")),
        )
    })
}

fn bool_at_path(value: &Value, path: &[&str]) -> CanonicalResult<bool> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing setup package field {}", path.join(".")),
            )
        })?;
    }
    current.as_bool().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("setup package field {} must be a boolean", path.join(".")),
        )
    })
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a Value> {
    let mut current = value;
    for field_name in path {
        current = current.get(*field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("missing setup package field {}", path.join(".")),
            )
        })?;
    }

    Ok(current)
}

fn array_at_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a Vec<Value>> {
    value_at_path(value, path)?.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("setup package field {} must be an array", path.join(".")),
        )
    })
}

fn unsigned_at_path(value: &Value, path: &[&str]) -> CanonicalResult<u64> {
    value_at_path(value, path)?.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "setup package field {} must be a non-negative integer",
                path.join(".")
            ),
        )
    })
}

fn usize_at_path(value: &Value, path: &[&str]) -> CanonicalResult<usize> {
    let value = unsigned_at_path(value, path)?;
    usize::try_from(value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("setup package field {} does not fit usize", path.join(".")),
        )
    })
}

fn digest_at_path<'a>(value: &'a Value, path: &[&str]) -> CanonicalResult<&'a str> {
    let digest = string_at_path(value, path)?;
    validate_digest_string(digest, &path.join("."))?;

    Ok(digest)
}

fn compare_required_string(actual: &str, expected: &str, description: &str) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M8 setup package {description} does not match its canonical binding"),
        ));
    }

    Ok(())
}

fn compare_string_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    compare_required_string(string_at_path(value, path)?, expected, description)
}

fn compare_digest_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    compare_required_string(digest_at_path(value, path)?, expected, description)
}

fn compare_derived_digest(
    namespace: &str,
    value: &Value,
    actual_digest: &str,
    description: &str,
) -> CanonicalResult<()> {
    let expected_digest = derive_protocol_digest(namespace, value)?;
    if actual_digest != expected_digest {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M8 setup package {description} does not match its canonical payload"),
        ));
    }

    Ok(())
}

fn is_forbidden_setup_package_secret_field(field_name: &str) -> bool {
    matches!(
        field_name,
        "secretShares"
            | "rawSecretShares"
            | "globalSecret"
            | "globalSecretPolynomial"
            | "fullSecretPolynomial"
            | "trustedDealerSecret"
            | "trustedDealerSecretHex"
            | "centralizedSecret"
            | "rawKeySwitchSecret"
            | "rawDecryptionSecret"
    )
}

fn reject_forbidden_setup_package_secret_fields(value: &Value) -> CanonicalResult<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                reject_forbidden_setup_package_secret_fields(item)?;
            }
        }
        Value::Object(fields) => {
            for (field_name, field_value) in fields {
                if is_forbidden_setup_package_secret_field(field_name) {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!(
                            "{field_name} would expose BGV secret material and cannot be accepted by M8 setup verification"
                        ),
                    ));
                }
                if (field_name == "centralizedSecretReconstruction"
                    || field_name == "rawSecretShareExported")
                    && field_value.as_bool() != Some(false)
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        format!("M8 setup package field {field_name} must remain false"),
                    ));
                }
                reject_forbidden_setup_package_secret_fields(field_value)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_setup_package_internal_bindings(setup_package: &Value) -> CanonicalResult<()> {
    reject_forbidden_setup_package_secret_fields(setup_package)?;
    let profile_digest = profile_digest()?;
    let backend_profile_digest = backend_profile_digest()?;
    compare_string_at_path(
        setup_package,
        &["profileBindings", "profileId"],
        PROFILE_ID,
        "profile id",
    )?;
    compare_string_at_path(
        setup_package,
        &["profileBindings", "backendProfileId"],
        BACKEND_PROFILE_ID,
        "backend profile id",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "profileDigest"],
        &profile_digest,
        "profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "backendProfileDigest"],
        &backend_profile_digest,
        "backend profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "canonicalCiphertextConventionDigest"],
        &canonical_ciphertext_convention_digest()?,
        "canonical ciphertext convention digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "batchEncoderDigest"],
        &batch_encoder_digest()?,
        "batch encoder digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "batchLayoutBindingDigest"],
        &batch_layout_binding_digest()?,
        "batch layout binding digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "allowedEvaluatorOpsDigest"],
        &allowed_operation_registry_digest()?,
        "allowed evaluator operation digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateInputLayoutDigest"],
        &layout_digest()?,
        "encrypted aggregate input layout digest",
    )?;

    let threshold_decryption_profile_digest = derive_protocol_digest(
        "ThresholdDecryptionProfileDigest",
        &threshold_decryption_profile(&profile_digest)?,
    )?;
    let kllps_target_decryption_profile_digest = derive_protocol_digest(
        "KllpsTargetDecryptionProfileDigest",
        &json!({
            "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "profileStatus": "future-target-decryption-profile-binding",
        }),
    )?;
    compare_string_at_path(
        setup_package,
        &["kllpsCompatibility", "thresholdDecryptionProfileId"],
        THRESHOLD_DECRYPTION_PROFILE_ID,
        "threshold decryption profile id",
    )?;
    compare_digest_at_path(
        setup_package,
        &["kllpsCompatibility", "thresholdDecryptionProfileDigest"],
        &threshold_decryption_profile_digest,
        "threshold decryption profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["kllpsCompatibility", "kllpsTargetDecryptionProfileDigest"],
        &kllps_target_decryption_profile_digest,
        "KLLPS target decryption profile digest",
    )?;

    let participant_bindings = validate_participant_setup_records(
        setup_package,
        &profile_digest,
        &backend_profile_digest,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
    )?;
    validate_collective_public_key(
        setup_package,
        &participant_bindings,
        &profile_digest,
        &backend_profile_digest,
    )?;
    validate_threshold_verification_material(
        setup_package,
        &participant_bindings,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
    )?;
    validate_evaluation_keys(setup_package)?;
    validate_setup_certificates(setup_package)?;

    Ok(())
}

fn validate_participant_setup_records(
    setup_package: &Value,
    profile_digest: &str,
    backend_profile_digest: &str,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<Vec<VerifiedParticipantSetupBinding>> {
    let ceremony_id = string_at_path(setup_package, &["setupInputs", "ceremonyId"])?;
    let manifest_digest = digest_at_path(setup_package, &["setupInputs", "manifestDigest"])?;
    let roster_digest = digest_at_path(setup_package, &["setupInputs", "rosterDigest"])?;
    let threshold_profile_digest =
        digest_at_path(setup_package, &["setupInputs", "thresholdProfileDigest"])?;
    let participants = array_at_path(setup_package, &["participants"])?;
    let participant_identities =
        array_at_path(setup_package, &["setupInputs", "participantIdentities"])?;
    if participant_identities.len() != participants.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setupPackage participant identities do not match participant records",
        ));
    }

    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    let mut verified_participants = Vec::with_capacity(participants.len());
    for (participant_index, participant_record) in participants.iter().enumerate() {
        compare_string_at_path(
            participant_record,
            &["objectType"],
            "ParticipantBgvSetupRecord",
            "participant record object type",
        )?;
        if unsigned_at_path(participant_record, &["objectVersion"])? != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participant setup record object version must be 1",
            ));
        }
        compare_string_at_path(
            participant_record,
            &["setupProfileId"],
            PASSIVE_SETUP_PROFILE_ID,
            "participant setup profile id",
        )?;
        compare_string_at_path(
            participant_record,
            &["ceremonyId"],
            ceremony_id,
            "participant ceremony id",
        )?;
        compare_digest_at_path(
            participant_record,
            &["manifestDigest"],
            manifest_digest,
            "participant manifest digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["rosterDigest"],
            roster_digest,
            "participant roster digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["thresholdProfileDigest"],
            threshold_profile_digest,
            "participant threshold profile digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["profileDigest"],
            profile_digest,
            "participant profile digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["backendProfileDigest"],
            backend_profile_digest,
            "participant backend profile digest",
        )?;
        let trustee_identity = string_at_path(participant_record, &["trusteeIdentity"])?;
        let listed_identity = participant_identities[participant_index]
            .as_str()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupPackage participant identities must be strings",
                )
            })?;
        if listed_identity != trustee_identity {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setupPackage participant identity order does not match participant records",
            ));
        }
        let roster_position = usize_at_path(participant_record, &["rosterPosition"])?;
        if roster_position >= participants.len() || !roster_positions.insert(roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage participant roster positions must be unique and cover the frozen roster",
            ));
        }
        if !identities.insert(trustee_identity.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage participant identities must be unique",
            ));
        }
        let recovery_epoch = unsigned_at_path(participant_record, &["recoveryEpoch"])?;
        let device_epoch = unsigned_at_path(participant_record, &["deviceEpoch"])?;
        let public_key_share_root = digest_at_path(participant_record, &["publicKeyShareRoot"])?;
        let participant_setup_record_digest =
            digest_at_path(participant_record, &["participantSetupRecordDigest"])?;
        let trustee_threshold_verification_key_digest = digest_at_path(
            participant_record,
            &["trusteeThresholdVerificationKeyDigest"],
        )?;
        digest_at_path(participant_record, &["localSecretShareCommitmentDigest"])?;
        digest_at_path(participant_record, &["localErrorCommitmentDigest"])?;

        let mut participant_record_without_digest = participant_record.clone();
        participant_record_without_digest
            .as_object_mut()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "participant setup record must be an object",
                )
            })?
            .remove("participantSetupRecordDigest");
        compare_derived_digest(
            "ParticipantBgvSetupRecordDigest",
            &participant_record_without_digest,
            participant_setup_record_digest,
            "participant setup record digest",
        )?;

        let trustee_threshold_verification_key = json!({
            "objectType": "TrusteeThresholdVerificationKey",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
            "ceremonyId": ceremony_id,
            "rosterDigest": roster_digest,
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "recoveryEpoch": recovery_epoch,
            "deviceEpoch": device_epoch,
            "publicKeyShareRoot": public_key_share_root,
            "verificationStatement": "passive-transcript-identity-profile-and-share-domain-binding",
            "maliciousDkgProofIncluded": false,
        });
        compare_derived_digest(
            "TrusteeThresholdVerificationKeyDigest",
            &trustee_threshold_verification_key,
            trustee_threshold_verification_key_digest,
            "trustee threshold verification key digest",
        )?;

        verified_participants.push(VerifiedParticipantSetupBinding {
            trustee_identity: trustee_identity.to_string(),
            roster_position,
            recovery_epoch,
            device_epoch,
            public_key_share_root: public_key_share_root.to_string(),
            participant_setup_record_digest: participant_setup_record_digest.to_string(),
            trustee_threshold_verification_key_digest: trustee_threshold_verification_key_digest
                .to_string(),
        });
    }

    Ok(verified_participants)
}

fn validate_collective_public_key(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    profile_digest: &str,
    backend_profile_digest: &str,
) -> CanonicalResult<()> {
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let collective_public_key_record = value_at_path(collective_public_key, &["record"])?;
    compare_string_at_path(
        collective_public_key_record,
        &["objectType"],
        "BgvCollectivePublicKey",
        "collective public key object type",
    )?;
    compare_digest_at_path(
        collective_public_key_record,
        &["profileDigest"],
        profile_digest,
        "collective public key profile digest",
    )?;
    compare_digest_at_path(
        collective_public_key_record,
        &["backendProfileDigest"],
        backend_profile_digest,
        "collective public key backend profile digest",
    )?;
    if usize_at_path(collective_public_key_record, &["participantCount"])?
        != participant_bindings.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key participant count does not match participant records",
        ));
    }
    let expected_public_key_share_roots = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.public_key_share_root.clone()))
        .collect::<Vec<_>>();
    if array_at_path(collective_public_key_record, &["publicKeyShareRoots"])?
        != &expected_public_key_share_roots
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key share roots do not match participant records",
        ));
    }

    let collective_public_key_root =
        digest_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    compare_derived_digest(
        "CollectivePublicKeyRoot",
        collective_public_key_record,
        collective_public_key_root,
        "collective public key root",
    )?;
    let expected_bgv_public_key_root = derive_protocol_digest(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "profileDigest": profile_digest,
            "backendProfileDigest": backend_profile_digest,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;
    compare_digest_at_path(
        collective_public_key,
        &["bgvPublicKeyRoot"],
        &expected_bgv_public_key_root,
        "BGV public key root",
    )
}

fn validate_threshold_verification_material(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<()> {
    let threshold_material = value_at_path(setup_package, &["thresholdVerificationMaterial"])?;
    let verification_key_set = value_at_path(threshold_material, &["verificationKeySet"])?;
    let expected_participant_setup_record_digests = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.participant_setup_record_digest.clone()))
        .collect::<Vec<_>>();
    let expected_trustee_threshold_verification_key_digests = participant_bindings
        .iter()
        .map(|participant| {
            Value::String(
                participant
                    .trustee_threshold_verification_key_digest
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    if array_at_path(verification_key_set, &["participantSetupRecordDigests"])?
        != &expected_participant_setup_record_digests
        || array_at_path(
            verification_key_set,
            &["trusteeThresholdVerificationKeyDigests"],
        )? != &expected_trustee_threshold_verification_key_digests
        || array_at_path(
            threshold_material,
            &["trusteeThresholdVerificationKeyDigests"],
        )? != &expected_trustee_threshold_verification_key_digests
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "threshold verification material does not match participant setup records",
        ));
    }

    let expected_interpolation_universe = participant_bindings
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity,
                "rosterPosition": participant.roster_position,
                "interpolationPoint": participant.roster_position + 1,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    if array_at_path(verification_key_set, &["participantInterpolationUniverse"])?
        != &expected_interpolation_universe
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "threshold interpolation universe does not match participant setup records",
        ));
    }

    let threshold_share_verification_key_root =
        digest_at_path(threshold_material, &["thresholdShareVerificationKeyRoot"])?;
    compare_derived_digest(
        "ThresholdShareVerificationKeyRoot",
        verification_key_set,
        threshold_share_verification_key_root,
        "threshold share verification key root",
    )?;
    let expected_threshold_share_verification_key_digest = derive_protocol_digest(
        "ThresholdShareVerificationKeyDigest",
        &json!({
            "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        }),
    )?;
    compare_digest_at_path(
        threshold_material,
        &["thresholdShareVerificationKeyDigest"],
        &expected_threshold_share_verification_key_digest,
        "threshold share verification key digest",
    )
}

fn validate_evaluation_keys(setup_package: &Value) -> CanonicalResult<()> {
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let evaluation_key_record = value_at_path(evaluation_keys, &["record"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_digest = digest_at_path(evaluation_keys, &["rotSetDigest"])?;
    compare_derived_digest(
        "RotSetDigest",
        rot_set,
        rot_set_digest,
        "rotation set digest",
    )?;
    let key_switch_decomposition_digest =
        digest_at_path(evaluation_keys, &["keySwitchDecompositionDigest"])?;
    compare_digest_at_path(
        evaluation_key_record,
        &["keySwitchDecompositionDigest"],
        key_switch_decomposition_digest,
        "evaluation key decomposition digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["certificates", "keySwitchDecompositionDigest"],
        key_switch_decomposition_digest,
        "certificate key-switch decomposition digest",
    )?;
    let collective_public_key_root =
        digest_at_path(evaluation_key_record, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = digest_at_path(evaluation_key_record, &["bgvPublicKeyRoot"])?;
    compare_digest_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
        collective_public_key_root,
        "evaluation key collective public key root",
    )?;
    compare_digest_at_path(
        setup_package,
        &["collectivePublicKey", "bgvPublicKeyRoot"],
        bgv_public_key_root,
        "evaluation key BGV public key root",
    )?;
    compare_digest_at_path(
        evaluation_key_record,
        &["rotSetDigest"],
        rot_set_digest,
        "evaluation key rotation set digest",
    )?;

    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
        "rosterDigest": digest_at_path(evaluation_key_record, &["rosterDigest"])?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 2,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let relinearization_key_root = digest_at_path(evaluation_keys, &["relinearizationKeyRoot"])?;
    compare_derived_digest(
        "RelinearizationKeyRoot",
        &relinearization_key_record,
        relinearization_key_root,
        "relinearization key root",
    )?;
    compare_digest_at_path(
        evaluation_key_record,
        &["relinearizationKeyRoot"],
        relinearization_key_root,
        "evaluation key relinearization root",
    )?;

    let rotation_key_roots = array_at_path(evaluation_keys, &["rotationKeyRoots"])?;
    let rotations = array_at_path(rot_set, &["rotations"])?;
    if rotation_key_roots.len() != rotations.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rotation key root count does not match the provisional rotation set",
        ));
    }
    for (rotation_index, rotation_key_root_record) in rotation_key_roots.iter().enumerate() {
        if value_at_path(rotation_key_root_record, &["rotation"])? != &rotations[rotation_index] {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rotation key root order does not match the provisional rotation set",
            ));
        }
        let rotation_key_record = json!({
            "objectType": "BgvRotationKey",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
            "rosterDigest": digest_at_path(evaluation_key_record, &["rosterDigest"])?,
            "collectivePublicKeyRoot": collective_public_key_root,
            "rotSetDigest": rot_set_digest,
            "rotation": rotations[rotation_index].clone(),
            "keySwitchDecompositionDigest": key_switch_decomposition_digest,
            "publicBasisId": BgvBasisKind::Extended.basis_id(),
            "publicRlweSampleCount": 1,
            "maliciousEvaluationKeyProofIncluded": false,
        });
        compare_derived_digest(
            "RotationKeyRoot",
            &rotation_key_record,
            digest_at_path(rotation_key_root_record, &["rotationKeyRoot"])?,
            "rotation key root",
        )?;
    }
    if array_at_path(evaluation_key_record, &["rotationKeyRoots"])? != rotation_key_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation key record rotation roots do not match exported rotation roots",
        ));
    }

    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
        "rosterDigest": digest_at_path(evaluation_key_record, &["rosterDigest"])?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 1,
        "genericKeySwitchApiExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let key_switch_key_root = digest_at_path(evaluation_keys, &["keySwitchKeyRoot"])?;
    compare_derived_digest(
        "KeySwitchKeyRoot",
        &key_switch_key_record,
        key_switch_key_root,
        "key-switch key root",
    )?;
    compare_digest_at_path(
        evaluation_key_record,
        &["keySwitchKeyRoot"],
        key_switch_key_root,
        "evaluation key key-switch root",
    )?;

    let evaluation_key_root = digest_at_path(evaluation_keys, &["evaluationKeyRoot"])?;
    compare_derived_digest(
        "EvalKeyRoot",
        evaluation_key_record,
        evaluation_key_root,
        "evaluation key root",
    )
}

fn validate_setup_certificates(setup_package: &Value) -> CanonicalResult<()> {
    let certificates = value_at_path(setup_package, &["certificates"])?;
    compare_derived_digest(
        "CollectiveSecretDistributionCertificateDigest",
        value_at_path(certificates, &["collectiveSecretDistributionCertificate"])?,
        digest_at_path(
            certificates,
            &["collectiveSecretDistributionCertificateDigest"],
        )?,
        "collective secret distribution certificate digest",
    )?;
    compare_derived_digest(
        "ErrorDistributionCertificateDigest",
        value_at_path(certificates, &["errorDistributionCertificate"])?,
        digest_at_path(certificates, &["errorDistributionCertificateDigest"])?,
        "error distribution certificate digest",
    )?;
    compare_derived_digest(
        "KeySwitchDecompositionDigest",
        value_at_path(certificates, &["keySwitchDecomposition"])?,
        digest_at_path(certificates, &["keySwitchDecompositionDigest"])?,
        "key-switch decomposition digest",
    )?;
    compare_derived_digest(
        "EvaluationKeySizeProfileDigest",
        value_at_path(certificates, &["evaluationKeySizeCertificate"])?,
        digest_at_path(certificates, &["evaluationKeySizeProfileDigest"])?,
        "evaluation key size profile digest",
    )?;
    compare_derived_digest(
        "BGVSetupParameterCertificateDigest",
        value_at_path(certificates, &["setupParameterCertificate"])?,
        digest_at_path(certificates, &["setupParameterCertificateDigest"])?,
        "setup parameter certificate digest",
    )?;
    compare_derived_digest(
        "BGVDevelopmentEncryptionFixtureDigest",
        value_at_path(setup_package, &["developmentEncryptionFixture", "fixture"])?,
        digest_at_path(
            setup_package,
            &["developmentEncryptionFixture", "fixtureDigest"],
        )?,
        "development encryption fixture digest",
    )?;
    compare_digest_at_path(
        certificates,
        &["developmentEncryptionFixtureDigest"],
        digest_at_path(
            setup_package,
            &["developmentEncryptionFixture", "fixtureDigest"],
        )?,
        "certificate development encryption fixture digest",
    )
}

fn validate_setup_package_shape(setup_package: &Value) -> CanonicalResult<()> {
    if setup_package.get("objectType").and_then(Value::as_str) != Some("BgvPassiveSetupPackage")
        || setup_package.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || setup_package.get("setupProfileId").and_then(Value::as_str)
            != Some(PASSIVE_SETUP_PROFILE_ID)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is not an M8 passive BGV setup package",
        ));
    }
    if !bool_at_path(
        setup_package,
        &["kllpsCompatibility", "setupMaterialCompatibleWithKLLPS"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must be marked KLLPS-compatible",
        ));
    }
    if bool_at_path(
        setup_package,
        &["kllpsCompatibility", "KLLPSPartDecImplemented"],
    )? || bool_at_path(setup_package, &["kllpsCompatibility", "KLLPSC1C4Certified"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must not claim KLLPS PartDec or C1-C4 certification",
        ));
    }
    if bool_at_path(
        setup_package,
        &[
            "trustedDealerBoundary",
            "transcriptValidCentralizedSecretReconstruction",
        ],
    )? || bool_at_path(
        setup_package,
        &["trustedDealerBoundary", "rawSecretSharesExported"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must not claim centralized secret reconstruction or raw share export",
        ));
    }
    if string_at_path(
        setup_package,
        &[
            "certificates",
            "setupParameterCertificate",
            "finalSecurityStatus",
        ],
    )? != "pendingQTarget"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must keep final Appendix B security pending Q_target",
        ));
    }
    let participants = setup_package
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.participants must be an array",
            )
        })?;
    let participant_count = setup_package
        .get("setupInputs")
        .and_then(|inputs| inputs.get("participantCount"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupInputs.participantCount must be present",
            )
        })?;
    if participant_count as usize != participants.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setupPackage participant count does not match participant records",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        generate_passive_setup_package_from_request, sample_centered_binomial_eta2,
        verify_passive_setup_package_from_request,
    };
    use crate::hashing::{derive_protocol_digest, hash512};

    fn request() -> serde_json::Value {
        serde_json::json!({
            "ceremonyId": "ceremony-main",
            "manifestDigest": derive_protocol_digest(
                "ElectionManifestDigest",
                &serde_json::json!({ "manifest": "m8-test" }),
            ).expect("manifest digest"),
            "rosterDigest": derive_protocol_digest(
                "RosterDigest",
                &serde_json::json!({ "roster": "m8-test" }),
            ).expect("roster digest"),
            "thresholdProfileDigest": derive_protocol_digest(
                "ThresholdProfileDigest",
                &serde_json::json!({ "threshold": "m8-test" }),
            ).expect("threshold digest"),
            "participants": [
                { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
                { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 4 },
                { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 5 }
            ],
            "setupSeed": "m8-test-seed",
        })
    }

    fn rebind_setup_package_digest(package: &mut serde_json::Value) {
        let mut digest_input = package.clone();
        digest_input
            .as_object_mut()
            .expect("setup package must be an object")
            .remove("setupPackageDigest");
        package["setupPackageDigest"] = serde_json::json!(
            derive_protocol_digest("BGVPassiveSetupPackageDigest", &digest_input)
                .expect("setup package digest")
        );
    }

    #[test]
    fn passive_setup_generation_is_deterministic_and_verifiable() {
        let first = generate_passive_setup_package_from_request(&request()).expect("first setup");
        let second = generate_passive_setup_package_from_request(&request()).expect("second setup");

        assert_eq!(first["setupPackageDigest"], second["setupPackageDigest"]);
        assert_eq!(
            first["kllpsCompatibility"]["setupMaterialCompatibleWithKLLPS"],
            true
        );
        assert_eq!(
            first["kllpsCompatibility"]["KLLPSPartDecImplemented"],
            false
        );
        assert_eq!(
            first["certificates"]["setupParameterCertificate"]["finalSecurityStatus"],
            "pendingQTarget"
        );

        let verification = verify_passive_setup_package_from_request(&serde_json::json!({
            "setupPackage": first,
            "expectedRosterDigest": request()["rosterDigest"],
        }))
        .expect("verify setup package");
        assert_eq!(verification["ok"], true);
    }

    #[test]
    fn passive_setup_rejects_trusted_dealer_secret_fields() {
        let mut request = request();
        request["globalSecretPolynomial"] = serde_json::json!("forbidden");

        assert!(generate_passive_setup_package_from_request(&request).is_err());
    }

    #[test]
    fn passive_setup_rejects_non_canonical_roster_positions_and_digests() {
        let mut duplicate_position_request = request();
        duplicate_position_request["participants"][1]["rosterPosition"] = serde_json::json!(0);
        assert!(generate_passive_setup_package_from_request(&duplicate_position_request).is_err());

        let mut out_of_range_position_request = request();
        out_of_range_position_request["participants"][2]["rosterPosition"] = serde_json::json!(3);
        assert!(
            generate_passive_setup_package_from_request(&out_of_range_position_request).is_err()
        );

        let mut uppercase_digest_request = request();
        let uppercase_manifest_digest = uppercase_digest_request["manifestDigest"]
            .as_str()
            .expect("manifest digest")
            .to_ascii_uppercase();
        uppercase_digest_request["manifestDigest"] = serde_json::json!(uppercase_manifest_digest);
        assert!(generate_passive_setup_package_from_request(&uppercase_digest_request).is_err());
    }

    #[test]
    fn passive_setup_verification_rejects_mutated_roots() {
        let mut package = generate_passive_setup_package_from_request(&request()).expect("setup");
        package["collectivePublicKey"]["collectivePublicKeyRoot"] =
            serde_json::json!("0".repeat(128));

        assert!(
            verify_passive_setup_package_from_request(&serde_json::json!({
                "setupPackage": package,
            }))
            .is_err()
        );
    }

    #[test]
    fn passive_setup_verification_rejects_rebound_internal_inconsistency() {
        let mut package = generate_passive_setup_package_from_request(&request()).expect("setup");
        package["collectivePublicKey"]["record"]["publicKeyShareRoots"][0] =
            serde_json::json!("f".repeat(128));
        rebind_setup_package_digest(&mut package);

        assert!(
            verify_passive_setup_package_from_request(&serde_json::json!({
                "setupPackage": package,
            }))
            .is_err()
        );
    }

    #[test]
    fn passive_setup_verification_rejects_nested_secret_material() {
        let mut package = generate_passive_setup_package_from_request(&request()).expect("setup");
        package["participants"][0]["globalSecretPolynomial"] = serde_json::json!("forbidden");
        rebind_setup_package_digest(&mut package);

        assert!(
            verify_passive_setup_package_from_request(&serde_json::json!({
                "setupPackage": package,
            }))
            .is_err()
        );
    }

    #[test]
    fn centered_binomial_eta2_samples_match_certified_sampler() {
        let seed_digest = "1".repeat(128);
        let samples = sample_centered_binomial_eta2(&seed_digest, "trustee-1", "local-error");
        for sample in samples {
            let position = sample["position"].as_u64().expect("position") as usize;
            let position_text = position.to_string();
            let output = hash512(
                "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-v1",
                &[
                    seed_digest.as_bytes(),
                    b"trustee-1",
                    b"local-error",
                    position_text.as_bytes(),
                ],
            );
            let expected_value = i64::from(output[0] & 1) + i64::from((output[0] >> 1) & 1)
                - i64::from((output[0] >> 2) & 1)
                - i64::from((output[0] >> 3) & 1);

            assert_eq!(sample["value"], expected_value);
            assert!((-2..=2).contains(&expected_value));
        }
    }
}
