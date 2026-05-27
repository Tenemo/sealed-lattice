use super::*;
use super::{
    certificates::{
        collective_secret_distribution_certificate, error_distribution_certificate,
        key_switch_decomposition_profile, m8_evaluator_context_bindings,
        public_common_random_polynomial_root, setup_certificates, threshold_decryption_profile,
    },
    development_fixtures::development_encryption_fixture,
    key_material::{collective_public_key, evaluation_keys, threshold_verification_material},
    participant_material::participant_setup_material,
};

pub(super) fn build_passive_setup_package(input: &PassiveSetupInput) -> CanonicalResult<Value> {
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
    let setup_inputs = json!({
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "thresholdProfileDigest": input.threshold_profile_digest,
        "participantCount": input.participants.len(),
        "participantIdentities": input.participants.iter().map(|participant| participant.trustee_identity.clone()).collect::<Vec<_>>(),
        "defaultSetupSeedUsed": !input.setup_seed_provided,
        "setupSeedDigest": input.setup_seed_digest,
    });
    let evaluator_context_bindings = m8_evaluator_context_bindings(&setup_inputs)?;

    let mut package = json!({
        "objectType": "BgvPassiveSetupPackage",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "setupMode": "passive-full-roster-development",
        "setupInputs": setup_inputs,
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
            "evaluatorBindingContextDigest": evaluator_context_bindings["evaluatorBindingContextDigest"],
            "encryptedAggregateBridgeDigest": evaluator_context_bindings["encryptedAggregateBridgeDigest"],
            "encryptedAggregateTargetBasisDataRoot": evaluator_context_bindings["encryptedAggregateTargetBasisDataRoot"],
            "encryptedAggregateReconstructionDigest": evaluator_context_bindings["encryptedAggregateReconstructionDigest"],
            "scoreBitDerivationCircuitDigest": evaluator_context_bindings["scoreBitDerivationCircuitDigest"],
            "comparisonInputDerivationCircuitDigest": evaluator_context_bindings["comparisonInputDerivationCircuitDigest"],
            "encryptedScoreBitInputDigest": evaluator_context_bindings["encryptedScoreBitInputDigest"],
            "encryptedComparisonInputDigest": evaluator_context_bindings["encryptedComparisonInputDigest"],
            "bitSlicedComparatorDigest": evaluator_context_bindings["bitSlicedComparatorDigest"],
            "encryptedSparseTargetProjectionDigest": evaluator_context_bindings["encryptedSparseTargetProjectionDigest"],
            "m8EvaluatorContextBindingDigest": evaluator_context_bindings["m8EvaluatorContextBindingDigest"],
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
            "PassiveSetupDevelopmentFixtureOnly",
            "FullRosterSetupMaterialGenerated",
            "CollectivePublicKeyRootBound",
            "BgvPublicKeyRootDigestOnly",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "KllpsCompatibleSetupMaterial",
            "AppendixBSetupInputReady",
            "FinalAppendixBPendingQTarget"
        ],
        "nonClaims": [
            "ActiveMaliciousSetupProofMissing",
            "BgvAlgebraicPublicKeyProofMissing",
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
