use super::*;
use super::{
    certificates::{
        collective_secret_distribution_certificate, error_distribution_certificate,
        key_switch_decomposition_profile, passive_setup_evaluator_context_bindings,
        public_common_random_polynomial_root, setup_certificates, threshold_decryption_profile,
    },
    development_fixtures::development_encryption_fixture,
    key_material::{collective_public_key, evaluation_keys, threshold_verification_material},
    participant_material::participant_setup_material,
};

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
    let threshold_decryption_profile = threshold_decryption_profile(&profile_hash)?;
    let threshold_decryption_profile_hash = derive_protocol_hash(
        "ThresholdDecryptionProfileHash",
        &threshold_decryption_profile,
    )?;
    let kllps_target_decryption_profile_hash = derive_protocol_hash(
        "KllpsTargetDecryptionProfileHash",
        &json!({
            "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
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
                &profile_hash,
                &backend_profile_hash,
                &public_common_random_polynomial_root,
                &threshold_decryption_profile_hash,
                &kllps_target_decryption_profile_hash,
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
        &threshold_decryption_profile_hash,
        &kllps_target_decryption_profile_hash,
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
        &threshold_decryption_profile_hash,
        &kllps_target_decryption_profile_hash,
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
            "encryptedAggregateInputLayoutHash": layout_hash()?,
            "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
            "ballotShareLayoutProfileHash": ballot_share_layout_profile_hash()?,
            "aggregateInputEncodingProfileHash": aggregate_input_encoding_profile_hash()?,
            "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
            "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
            "evaluatorBindingContextHash": evaluator_context_bindings["evaluatorBindingContextHash"],
            "encryptedAggregateBridgeHash": evaluator_context_bindings["encryptedAggregateBridgeHash"],
            "encryptedAggregateTargetBasisRoot": evaluator_context_bindings["encryptedAggregateTargetBasisRoot"],
            "encryptedAggregateReconstructionHash": evaluator_context_bindings["encryptedAggregateReconstructionHash"],
            "scoreBitDerivationCircuitHash": evaluator_context_bindings["scoreBitDerivationCircuitHash"],
            "comparisonInputDerivationCircuitHash": evaluator_context_bindings["comparisonInputDerivationCircuitHash"],
            "encryptedScoreBitInputHash": evaluator_context_bindings["encryptedScoreBitInputHash"],
            "encryptedComparisonInputHash": evaluator_context_bindings["encryptedComparisonInputHash"],
            "bitSlicedComparatorHash": evaluator_context_bindings["bitSlicedComparatorHash"],
            "encryptedSparseTargetProjectionHash": evaluator_context_bindings["encryptedSparseTargetProjectionHash"],
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
        "kllpsStatus": {
            "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
            "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
            "setupMaterialMatchesKLLPS": true,
            "KLLPSPartDecStatusImplemented": false,
            "KLLPSC1C4StatusAccepted": false,
        },
        "statusLabels": [
            "PassiveBgvSetupGenerated",
            "PassiveSetupDevelopmentFixtureOnly",
            "FullRosterSetupMaterialGenerated",
            "CollectivePublicKeyRootBound",
            "BgvPublicKeyCoefficientMaterialBound",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "KllpsSetupMaterialMatched",
            "PassiveSetupInputReady",
            "FinalSetupSecurityPendingTargetModulus"
        ],
        "nonClaims": [
            "ActiveMaliciousSetupProofMissing",
            "BgvAlgebraicPublicKeyProofMissing",
            "MaliciousEvaluationKeyProofMissing",
            "KLLPSPartDecNotImplemented",
            "KLLPSC1C4NotCertified",
            "FinalSetupSecurityPendingTargetModulus",
            "FinalEvaluatorNoisePendingEncryptedAggregateEvaluatorClosure",
            "EvaluationProofNotClosed",
            "TargetDecryptionNotClosed",
            "ActiveMaliciousSetupNotClosed"
        ],
    });
    let setup_package_hash = derive_protocol_hash("BGVPassiveSetupPackageHash", &package)?;
    package["setupPackageHash"] = Value::String(setup_package_hash);

    Ok(package)
}
