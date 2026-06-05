use super::*;
use super::{
    certificates::{
        collective_secret_distribution_certificate, error_distribution_certificate,
        key_switch_decomposition_profile, passive_setup_evaluator_context_bindings,
        public_common_random_polynomial_root, setup_certificates, target_decryption_profile,
    },
    development_fixtures::development_encryption_fixture,
    key_material::{collective_public_key, evaluation_keys, threshold_verification_material},
    participant_material::participant_setup_material,
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

pub(super) fn build_passive_setup_package(input: &PassiveSetupInput) -> CanonicalResult<Value> {
    let profile_hash = profile_hash()?;
    let backend_profile_hash = backend_profile_hash()?;
    let collective_secret_distribution_certificate =
        collective_secret_distribution_certificate(input.participants.len())?;
    let collective_secret_distribution_certificate_hash = derive_protocol_hash(
        "CollectiveSecretDistributionCertificateHash",
        &collective_secret_distribution_certificate,
    )?;
    let error_distribution_certificate = error_distribution_certificate()?;
    let error_distribution_certificate_hash = derive_protocol_hash(
        "ErrorDistributionCertificateHash",
        &error_distribution_certificate,
    )?;
    let key_switch_decomposition = key_switch_decomposition_profile()?;
    let key_switch_decomposition_hash =
        derive_protocol_hash("KeySwitchDecompositionHash", &key_switch_decomposition)?;
    let target_decryption_profile = target_decryption_profile(&profile_hash)?;
    let target_decryption_profile_hash =
        derive_protocol_hash("TargetDecryptionProfileHash", &target_decryption_profile)?;
    let target_decryption_profile_binding_hash = derive_protocol_hash(
        "TargetDecryptionProfileBindingHash",
        &json!({
            "profileId": TARGET_DECRYPTION_PROFILE_ID,
            "targetDecryptionProfileHash": target_decryption_profile_hash,
            "profileStatus": "target-decryption-profile-binding",
        }),
    )?;
    let public_common_random_polynomial_root = public_common_random_polynomial_root(input)?;
    #[cfg(not(target_arch = "wasm32"))]
    let participant_material = input
        .participants
        .par_iter()
        .map(|participant| {
            participant_setup_material(
                input,
                participant,
                &profile_hash,
                &backend_profile_hash,
                &public_common_random_polynomial_root,
                &target_decryption_profile_hash,
                &target_decryption_profile_binding_hash,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let participant_material = input
        .participants
        .iter()
        .map(|participant| {
            participant_setup_material(
                input,
                participant,
                &profile_hash,
                &backend_profile_hash,
                &public_common_random_polynomial_root,
                &target_decryption_profile_hash,
                &target_decryption_profile_binding_hash,
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
    let participant_setup_record_hashes = participant_material
        .iter()
        .map(|material| material.participant_setup_record_hash.clone())
        .collect::<Vec<_>>();
    let trustee_threshold_verification_key_hashes = participant_material
        .iter()
        .map(|material| material.trustee_threshold_verification_key_hash.clone())
        .collect::<Vec<_>>();
    let collective_public_key = collective_public_key(
        input,
        &profile_hash,
        &backend_profile_hash,
        &public_common_random_polynomial_root,
        &public_key_share_roots,
    )?;
    let threshold_verification_material = threshold_verification_material(
        input,
        &target_decryption_profile_hash,
        &target_decryption_profile_binding_hash,
        &participant_setup_record_hashes,
        &trustee_threshold_verification_key_hashes,
    )?;
    let evaluation_keys = evaluation_keys(
        input,
        &collective_public_key,
        &key_switch_decomposition_hash,
    )?;
    let development_encryption_fixture =
        development_encryption_fixture(input, &collective_public_key)?;
    let setup_inputs = json!({
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "thresholdProfileHash": input.threshold_profile_hash,
        "participantCount": input.participants.len(),
        "participantIdentities": input.participants.iter().map(|participant| participant.trustee_identity.clone()).collect::<Vec<_>>(),
        "defaultSetupSeedUsed": !input.setup_seed_provided,
        "setupSeedHash": input.setup_seed_hash,
    });
    let certificates = setup_certificates(
        input,
        &setup_inputs,
        &collective_public_key,
        &threshold_verification_material,
        &collective_secret_distribution_certificate,
        &collective_secret_distribution_certificate_hash,
        &error_distribution_certificate,
        &error_distribution_certificate_hash,
        &key_switch_decomposition,
        &key_switch_decomposition_hash,
        &target_decryption_profile_hash,
        &target_decryption_profile_binding_hash,
        &evaluation_keys,
        &development_encryption_fixture,
    )?;
    let evaluator_context_bindings = passive_setup_evaluator_context_bindings(&setup_inputs)?;

    let mut package = json!({
        "objectType": "BgvPassiveSetupPackage",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "setupMode": "passive-full-roster-development",
        "setupInputs": setup_inputs,
        "profileBindings": {
            "profileId": PROFILE_ID,
            "backendProfileId": BACKEND_PROFILE_ID,
            "profileHash": profile_hash,
            "backendProfileHash": backend_profile_hash,
            "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
            "batchEncoderId": BATCH_ENCODER_ID,
            "batchEncoderHash": batch_encoder_hash()?,
            "batchLayoutBindingHash": batch_layout_binding_hash()?,
            "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
            "encryptedBallotAggregateLayoutHash": encrypted_ballot_aggregate_layout_hash()?,
            "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
            "encryptedBallotLayoutHash": encrypted_ballot_layout_hash()?,
            "encryptedBallotAggregateProfileHash": encrypted_ballot_aggregate_profile_hash()?,
            "directAggregateLayoutHash": direct_aggregate_layout_hash()?,
            "directComparisonProfileHash": direct_comparison_profile_hash()?,
            "evaluatorBindingContextHash": evaluator_context_bindings["evaluatorBindingContextHash"],
            "encryptedBallotAggregateLayoutHash": evaluator_context_bindings["encryptedBallotAggregateLayoutHash"],
            "directAggregateLayoutHash": evaluator_context_bindings["directAggregateLayoutHash"],
            "comparisonInputDerivationCircuitHash": evaluator_context_bindings["comparisonInputDerivationCircuitHash"],
            "encryptedComparisonInputHash": evaluator_context_bindings["encryptedComparisonInputHash"],
            "encryptedSparseTargetProjectionHash": evaluator_context_bindings["encryptedSparseTargetProjectionHash"],
            "targetLayoutHash": evaluator_context_bindings["targetLayoutHash"],
            "passiveSetupEvaluatorContextBindingHash": evaluator_context_bindings["passiveSetupEvaluatorContextBindingHash"],
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
        "targetDecryptionStatus": {
            "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
            "targetDecryptionProfileHash": target_decryption_profile_hash,
            "targetDecryptionProfileBindingHash": target_decryption_profile_binding_hash,
            "setupMaterialMatchesTargetDecryption": true,
            "targetPartDecImplemented": true,
            "targetC1C4StatusAccepted": false,
        },
        "statusLabels": [
            "PassiveBgvSetupGenerated",
            "PassiveSetupDevelopmentFixtureOnly",
            "FullRosterSetupMaterialGenerated",
            "CollectivePublicKeyRootBound",
            "BgvPublicKeyCoefficientMaterialBound",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "TargetDecryptionSetupMaterialMatched",
            "TargetPartDecAndRecombinationImplemented",
            "PassiveSetupInputReady",
            "DirectEvaluatorReplayHeSecurityAccepted",
            "FinalTargetSecurityPendingTargetModulus"
        ],
        "nonClaims": [
            "ActiveMaliciousSetupProofMissing",
            "BgvAlgebraicPublicKeyProofMissing",
            "MaliciousEvaluationKeyProofMissing",
            "TargetShareProofNotCertified",
            "TargetC1C4NotCertified",
            "FinalTargetSecurityPendingTargetModulus",
            "DirectEvaluatorReplayNoiseClosurePending",
            "EvaluatorReplayNotClosed",
            "TargetDecryptionNotClosed",
            "ActiveMaliciousSetupNotClosed"
        ],
    });
    let setup_package_hash = derive_protocol_hash("BGVPassiveSetupPackageHash", &package)?;
    package["setupPackageHash"] = Value::String(setup_package_hash);

    Ok(package)
}
