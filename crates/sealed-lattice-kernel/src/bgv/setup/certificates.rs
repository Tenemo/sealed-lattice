use super::*;
use crate::bgv::evaluator::records::target_layout_hash;
use crate::bgv::profile::SPECIAL_PRIME;
use num_bigint::BigUint;

#[allow(clippy::too_many_arguments)]
pub(super) fn setup_certificates(
    input: &PassiveSetupInput,
    setup_inputs: &Value,
    collective_public_key: &Value,
    threshold_verification_material: &Value,
    collective_secret_distribution_certificate: &Value,
    collective_secret_distribution_certificate_hash: &str,
    error_distribution_certificate: &Value,
    error_distribution_certificate_hash: &str,
    key_switch_decomposition: &Value,
    key_switch_decomposition_hash: &str,
    threshold_decryption_profile_hash: &str,
    kllps_target_decryption_profile_hash: &str,
    evaluation_keys: &Value,
    development_encryption_fixture: &Value,
) -> CanonicalResult<Value> {
    let q_data_bits = data_basis_modulus_bits();
    let q_extended_utility_bits = extended_basis_modulus_bits();
    let rotation_key_roots = evaluation_keys["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots use array");
    let rotation_key_count = rotation_key_roots.len();
    let public_samples = public_rlwe_samples_by_basis(input.participants.len(), rotation_key_count);
    let evaluation_key_size_certificate = evaluation_key_size_certificate(evaluation_keys)?;
    let evaluation_key_size_profile_hash = derive_protocol_hash(
        "EvaluationKeySizeProfileHash",
        &evaluation_key_size_certificate,
    )?;
    let evaluation_key_streaming_commitment =
        evaluation_key_streaming_commitment(evaluation_keys, &evaluation_key_size_certificate)?;
    let target_threshold_decryptability_certificate =
        target_threshold_decryptability_certificate_for_setup_parts(
            setup_inputs,
            collective_public_key,
            threshold_verification_material,
            threshold_decryption_profile_hash,
            kllps_target_decryption_profile_hash,
        )?;
    let target_threshold_decryptability_certificate_hash = derive_protocol_hash(
        "TargetThresholdDecryptabilityCertificateHash",
        &target_threshold_decryptability_certificate,
    )?;
    let he_security_certificate = he_security_certificate_for_setup_profile(
        collective_secret_distribution_certificate,
        error_distribution_certificate,
        &public_samples,
    )?;
    let he_security_certificate_hash =
        derive_protocol_hash("BGVHeSecurityCertificateHash", &he_security_certificate)?;
    let setup_parameter_certificate = json!({
        "objectType": "BgvSetupParameterCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "profileHash": profile_hash()?,
        "backendProfileHash": backend_profile_hash()?,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "qDataBits": q_data_bits,
        "qDataProductDecimal": modulus_product_decimal(DATA_PRIMES.iter().copied()),
        "qSpecialPrime": SPECIAL_PRIME,
        "qExtendedUtilityBits": q_extended_utility_bits,
        "qExtendedUtilityProductDecimal": modulus_product_decimal(
            DATA_PRIMES.iter().copied().chain([SPECIAL_PRIME]),
        ),
        "qpPublicBits": null,
        "qTargetBits": null,
        "publicEvaluationKeyBasis": BgvBasisKind::Data.basis_id(),
        "largestExposedModulusBitsWithoutQTarget": q_data_bits,
        "largestExposedBasisClassWithoutQTarget": "Q_data",
        "largestExposedModulusBits": q_data_bits,
        "finalSecurityStatus": "acceptedForSetupBridgeEvaluatorTargetPending",
        "specialPrimeExposureStatus": "not-exposed-by-current-setup-bridge-evaluator-public-material",
        "collectiveSecretDistributionCertificateHash": collective_secret_distribution_certificate_hash,
        "errorDistributionCertificateHash": error_distribution_certificate_hash,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "evaluationKeySizeProfileHash": evaluation_key_size_profile_hash,
        "evaluationKeyStreamingCommitmentHash": evaluation_key_streaming_commitment["commitmentHash"],
        "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
        "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
        "targetThresholdDecryptabilityCertificateHash": target_threshold_decryptability_certificate_hash,
        "heSecurityCertificateHash": he_security_certificate_hash,
        "securityEstimatorInputHash": security_estimator_input_hash()?,
        "HEStdPostQuantumRow": he_security_certificate["standardRows"]["postQuantumTernary128"],
        "HEStdClassicalRow": he_security_certificate["standardRows"]["classicalTernary128"],
        "CurrentEstimatorRow": he_security_certificate["estimatorBinding"],
    });
    let setup_parameter_certificate_hash = derive_protocol_hash(
        "BGVSetupParameterCertificateHash",
        &setup_parameter_certificate,
    )?;

    Ok(json!({
        "collectiveSecretDistributionCertificate": collective_secret_distribution_certificate,
        "collectiveSecretDistributionCertificateHash": collective_secret_distribution_certificate_hash,
        "errorDistributionCertificate": error_distribution_certificate,
        "errorDistributionCertificateHash": error_distribution_certificate_hash,
        "keySwitchDecomposition": key_switch_decomposition,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "publicRlweSamplesByBasis": public_samples,
        "heSecurityCertificate": he_security_certificate,
        "heSecurityCertificateHash": he_security_certificate_hash,
        "setupParameterCertificate": setup_parameter_certificate,
        "setupParameterCertificateHash": setup_parameter_certificate_hash,
        "targetThresholdDecryptabilityCertificate": target_threshold_decryptability_certificate,
        "targetThresholdDecryptabilityCertificateHash": target_threshold_decryptability_certificate_hash,
        "evaluationKeySizeCertificate": evaluation_key_size_certificate,
        "evaluationKeySizeProfileHash": evaluation_key_size_profile_hash,
        "evaluationKeyStreamingCommitment": evaluation_key_streaming_commitment,
        "developmentEncryptionFixtureHash": development_encryption_fixture["fixtureHash"],
        "statusLabels": [
            "ActualSecretDistributionRecorded",
            "ActualErrorDistributionRecorded",
            "PublicRlweSampleCountsRecorded",
            "LargestExposedModulusAcceptedForSetupBridgeEvaluator",
            "SetupBridgeEvaluatorHeSecurityAccepted",
            "TargetThresholdDecryptabilityCompatibilityRecorded",
            "EvaluationKeySizeCertificateRecorded",
            "FinalTargetSecurityPendingQTarget"
        ],
    }))
}

fn modulus_product_decimal(moduli: impl IntoIterator<Item = u64>) -> String {
    let mut product = BigUint::from(1_u8);
    for modulus in moduli {
        product *= BigUint::from(modulus);
    }

    product.to_str_radix(10)
}

fn he_security_certificate_for_setup_profile(
    collective_secret_distribution_certificate: &Value,
    error_distribution_certificate: &Value,
    public_samples: &Value,
) -> CanonicalResult<Value> {
    let largest_exposed_modulus_bits = data_basis_modulus_bits();
    let post_quantum_max_logq = 827_usize;
    let classical_max_logq = 881_usize;
    let post_quantum_accepted = largest_exposed_modulus_bits <= post_quantum_max_logq;
    let classical_accepted = largest_exposed_modulus_bits <= classical_max_logq;
    let global_secret_distribution = value_at_path(
        collective_secret_distribution_certificate,
        &["resultingGlobalSecretDistribution"],
    )?;
    compare_string_at_path(
        global_secret_distribution,
        &["distributionKind"],
        "standard-ternary-collective-secret",
        "HE security collective secret distribution",
    )?;
    if !bool_at_path(global_secret_distribution, &["isPlainDenseTernary"])? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "HE security certificate requires the setup global secret to match the HE-standard ternary row",
        ));
    }

    Ok(json!({
        "objectType": "BgvHeSecurityCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "reference": {
            "document": "ACC18 Homomorphic Encryption Standard",
            "localReferencePath": "reference-documents/ACC18_Homomorphic Encryption Standard.txt",
            "sections": [
                "Section 2.1.3 secret key distribution",
                "Table 1 BKZ.sieve ternary n=32768 row",
                "Table 2 BKZ.qsieve ternary n=32768 row"
            ],
            "tableScope": "power-of-two cyclotomic RLWE parameter table"
        },
        "assessedRing": {
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "dataBasisId": BgvBasisKind::Data.basis_id(),
            "dataPrimeCount": DATA_PRIMES.len(),
            "dataPrimeProductDecimal": modulus_product_decimal(DATA_PRIMES.iter().copied()),
            "dataPrimeCeilLog2Product": data_basis_modulus_bits(),
            "specialPrime": SPECIAL_PRIME,
            "extendedUtilityCeilLog2Product": extended_basis_modulus_bits(),
            "extendedUtilityExposureStatus": "not-exposed-by-current-setup-bridge-evaluator-public-material",
            "largestExposedBasisClass": "Q_data",
            "largestExposedModulusBits": largest_exposed_modulus_bits
        },
        "secretDistribution": {
            "certificate": global_secret_distribution,
            "estimatorModel": collective_secret_distribution_certificate["estimatorSecretModel"],
            "HEStandardRow": "ternary",
        },
        "errorDistribution": {
            "certificate": error_distribution_certificate["errorDistribution"],
            "sampler": error_distribution_certificate["errorSampler"],
            "estimatorNote": "the HE-standard table is the accepted published parameter row for the ring and secret distribution; the implemented centered-binomial eta2 sampler remains separately recorded for noise/correctness analysis"
        },
        "publicSampleAccounting": public_samples,
        "standardRows": {
            "postQuantumTernary128": {
                "status": if post_quantum_accepted {
                    "accepted"
                } else {
                    "rejected-largest-exposed-modulus-exceeds-row"
                },
                "costModel": "BKZ.qsieve",
                "secretDistribution": "ternary",
                "polynomialDegree": 32768,
                "securityLevelBits": 128,
                "maximumLogQ": post_quantum_max_logq,
                "largestExposedModulusBits": largest_exposed_modulus_bits,
                "marginBits": post_quantum_max_logq.saturating_sub(largest_exposed_modulus_bits),
                "uSVPBits": "128.1",
                "decodingBits": "128.7",
                "dualBits": "128.4"
            },
            "classicalTernary128": {
                "status": if classical_accepted {
                    "accepted"
                } else {
                    "rejected-largest-exposed-modulus-exceeds-row"
                },
                "costModel": "BKZ.sieve",
                "secretDistribution": "ternary",
                "polynomialDegree": 32768,
                "securityLevelBits": 128,
                "maximumLogQ": classical_max_logq,
                "largestExposedModulusBits": largest_exposed_modulus_bits,
                "marginBits": classical_max_logq.saturating_sub(largest_exposed_modulus_bits),
                "uSVPBits": "128.5",
                "decodingBits": "129.1",
                "dualBits": "128.5"
            }
        },
        "estimatorBinding": {
            "status": if post_quantum_accepted && classical_accepted {
                "accepted-by-local-HE-standard-table-row"
            } else {
                "rejected-by-local-HE-standard-table-row"
            },
            "tool": "HE-standard published parameter table",
            "toolVersion": "ACC18 local text reference",
            "securityEstimatorInputHash": security_estimator_input_hash()?,
            "secretModel": "standard-ternary",
            "errorModel": error_distribution_certificate["errorDistribution"]["distributionKind"],
            "largestExposedModulusBits": largest_exposed_modulus_bits,
            "publicSamplesBound": true,
        },
        "targetModulusStatus": "target-decryption-Q-target-not-part-of-setup-bridge-evaluator-closure",
        "acceptedForSetupBridgeEvaluator": post_quantum_accepted && classical_accepted,
        "statusLabels": if post_quantum_accepted && classical_accepted {
            vec![
                "HEStandardPostQuantum128Accepted",
                "HEStandardClassical128Accepted",
                "DataBasisLargestExposedModulusAccepted",
                "SpecialPrimeNotPubliclyExposedOnAcceptedPath",
            ]
        } else {
            vec![
                "HEStandardSecurityRejected",
                "DataBasisLargestExposedModulusRejected",
            ]
        },
    }))
}

pub(super) fn collective_secret_distribution_certificate(
    participant_count: usize,
) -> CanonicalResult<Value> {
    if participant_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective secret distribution requires at least one participant",
        ));
    }
    let participant_count_u64 = u64::try_from(participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "participant count does not fit collective secret owner schedule",
        )
    })?;

    Ok(json!({
        "objectType": "CollectiveSecretDistributionCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "localShareSampler": {
            "samplerId": "hash-derived-owner-routed-standard-ternary-collective-share-v1",
            "support": [-1, 0, 1],
            "probabilityNumeratorBySupport": [1, 1, 1],
            "probabilityDenominator": 3,
            "candidateBits": 64,
            "rejectionRule": "reject-candidates-outside-largest-multiple-of-support-width",
            "ownerSelectionRule": "one-deterministic-participant-owner-per-coefficient; owner samples one standard ternary coefficient; non-owner local shares are zero",
            "ownerSelectionParticipantCount": participant_count_u64,
            "rawShareExported": false
        },
        "localShareDistribution": "owner-routed-standard-ternary-local-share",
        "aggregationRule": "coefficient-wise-owner-routed-share-sum",
        "participantCount": participant_count,
        "resultingGlobalSecretDistribution": {
            "distributionKind": "standard-ternary-collective-secret",
            "support": [
                { "secretCoefficientSum": -1, "weight": "1" },
                { "secretCoefficientSum": 0, "weight": "1" },
                { "secretCoefficientSum": 1, "weight": "1" }
            ],
            "totalWeightExpression": "3",
            "isPlainDenseTernary": true,
        },
        "estimatorSecretModel": "HE-standard-ternary",
        "noiseModelSecretModel": "standard-ternary",
        "sparseSecretFlag": false,
        "fixedHammingSecretFlag": false,
        "rejectionReasonIfUncertified": null,
    }))
}

pub(super) fn error_distribution_certificate() -> CanonicalResult<Value> {
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
        "collectiveKeyErrorShareDistribution": {
            "distributionKind": "owner-routed-centered-binomial-eta2-collective-error",
            "nonOwnerShare": 0,
            "ownerSupport": [-2, -1, 0, 1, 2]
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
            "distributionKind": "hash-to-modulus-rejection-sampled-uniform-public-sample",
            "samplerId": "hash-derived-rejection-sampled-public-residue-v2",
            "candidateBits": 64,
            "basisId": BgvBasisKind::Data.basis_id()
        },
        "rejectionSamplingRules": [
            "small-distribution-candidates-outside-largest-multiple-of-support-width-are-rehashed",
            "public-residue-candidates-outside-largest-multiple-of-modulus-are-rehashed"
        ],
        "uncertifiedSmallSecretRejected": true,
    }))
}

pub(super) fn key_switch_decomposition_profile() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvKeySwitchDecompositionProfile",
        "objectVersion": 1,
        "profileId": KEY_SWITCH_DECOMPOSITION_PROFILE_ID,
        "basisId": BgvBasisKind::Data.basis_id(),
        "digitBaseBits": 23,
        "digitCountPerPrime": 3,
        "decompositionStatus": "setup-bridge-evaluator-data-basis-key-switch-material",
        "genericKeySwitchApiExported": false,
    }))
}

pub(super) fn threshold_decryption_profile(profile_hash: &str) -> CanonicalResult<Value> {
    Ok(json!({
        "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "bgvProfileHash": profile_hash,
        "secretShareDomain": "BGV-RNS-secret-share-polynomial-over-selected-Q-data",
        "asyncLagrangeTargetDirection": true,
        "partDecImplemented": false,
        "finDecImplemented": false,
        "c1ThroughC4Certified": false,
        "qTargetKnown": false,
    }))
}

pub(super) fn target_threshold_decryptability_certificate_from_setup_package(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    target_threshold_decryptability_certificate_for_setup_parts(
        value_at_path(setup_package, &["setupInputs"])?,
        value_at_path(setup_package, &["collectivePublicKey"])?,
        value_at_path(setup_package, &["thresholdVerificationMaterial"])?,
        string_at_path(
            setup_package,
            &["kllpsStatus", "thresholdDecryptionProfileHash"],
        )?,
        string_at_path(
            setup_package,
            &["kllpsStatus", "kllpsTargetDecryptionProfileHash"],
        )?,
    )
}

pub(super) fn target_threshold_decryptability_certificate_for_setup_parts(
    setup_inputs: &Value,
    collective_public_key: &Value,
    threshold_verification_material: &Value,
    threshold_decryption_profile_hash: &str,
    kllps_target_decryption_profile_hash: &str,
) -> CanonicalResult<Value> {
    let setup_binding = json!({
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "bgvProfileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "bgvProfileHash": profile_hash()?,
        "rustBgvBackendProfileHash": backend_profile_hash()?,
        "ceremonyId": string_at_path(setup_inputs, &["ceremonyId"])?,
        "manifestHash": string_at_path(setup_inputs, &["manifestHash"])?,
        "rosterHash": string_at_path(setup_inputs, &["rosterHash"])?,
        "thresholdProfileHash": string_at_path(setup_inputs, &["thresholdProfileHash"])?,
        "participantCount": unsigned_at_path(setup_inputs, &["participantCount"])?,
    });
    let key_binding = json!({
        "collectivePublicKeyRoot": string_at_path(
            collective_public_key,
            &["collectivePublicKeyRoot"],
        )?,
        "collectivePublicKeyCoefficientRoot": string_at_path(
            collective_public_key,
            &["collectivePublicKeyCoefficientRoot"],
        )?,
        "bgvPublicKeyRoot": string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?,
        "publicKeyConvention": "b = p * e - a * s",
        "decryptableCiphertextEquation": "c0 + c1 * s = m + p * noise",
    });
    let ciphertext_profile = json!({
        "plaintextModulus": PLAINTEXT_MODULUS,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "basisId": BgvBasisKind::Data.basis_id(),
        "level": DATA_PRIMES.len() - 1,
        "dataPrimeCount": DATA_PRIMES.len(),
        "ciphertextComponentCount": 2,
        "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "batchEncoderHash": batch_encoder_hash()?,
        "encryptedAggregateInputLayoutHash": layout_hash()?,
        "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
    });
    let threshold_binding = json!({
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
        "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
        "thresholdShareVerificationKeyRoot": string_at_path(
            threshold_verification_material,
            &["thresholdShareVerificationKeyRoot"],
        )?,
        "thresholdShareVerificationKeyHash": string_at_path(
            threshold_verification_material,
            &["thresholdShareVerificationKeyHash"],
        )?,
        "trusteeThresholdVerificationKeyHashes": value_at_path(
            threshold_verification_material,
            &["trusteeThresholdVerificationKeyHashes"],
        )?,
        "participantInterpolationUniverse": value_at_path(
            threshold_verification_material,
            &["verificationKeySet", "participantInterpolationUniverse"],
        )?,
    });

    Ok(json!({
        "objectType": "TargetThresholdDecryptabilityCertificate",
        "objectVersion": 1,
        "certificateScope": "setup-key-and-ciphertext-profile-compatibility-only",
        "setupBinding": setup_binding,
        "keyBinding": key_binding,
        "ciphertextProfile": ciphertext_profile,
        "thresholdBinding": threshold_binding,
        "ciphertextCompatibilityStatus": "TargetThresholdDecryptabilityCompatibilityCertified",
        "semanticDecryptionPolicy": "only-an-accepted-target-ciphertext-after-target-finality-and-evaluation-proof-may-request-threshold-decryption",
        "bridgeCiphertextPolicy": "encrypted-aggregate-input-ciphertexts-are-threshold-key-compatible-but-never-authorized-semantic-decryption-targets",
        "downstreamProtocolStatus": "TargetDecryptionShareProtocolStillDownstream",
        "statusLabels": [
            "TargetThresholdDecryptabilityCompatibilityCertified",
            "CollectivePublicKeyRootBound",
            "ThresholdVerificationMaterialBound",
            "DecryptableBgvCiphertextConvention",
            "TargetDecryptionShareProtocolStillDownstream"
        ],
    }))
}

pub(super) fn passive_setup_evaluator_context_bindings(
    setup_inputs: &Value,
) -> CanonicalResult<Value> {
    let evaluator_binding_context = json!({
        "objectType": "PassiveSetupEvaluatorBindingContext",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": string_at_path(setup_inputs, &["ceremonyId"])?,
        "manifestHash": string_at_path(setup_inputs, &["manifestHash"])?,
        "rosterHash": string_at_path(setup_inputs, &["rosterHash"])?,
        "thresholdProfileHash": string_at_path(setup_inputs, &["thresholdProfileHash"])?,
        "participantCount": unsigned_at_path(setup_inputs, &["participantCount"])?,
        "setupSeedHash": string_at_path(setup_inputs, &["setupSeedHash"])?,
    });
    let evaluator_binding_context_hash = derive_protocol_hash(
        "PassiveSetupEvaluatorBindingContextHash",
        &evaluator_binding_context,
    )?;
    let bridge_record = json!({
        "profileId": "EncryptedAggregateBridge-v1",
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "bgvProfileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "inputLayoutHash": layout_hash()?,
        "aggregateInputEncodingProfileHash": aggregate_input_encoding_profile_hash()?,
        "bridgeEvidenceRequiredBeforeClaimUse": true,
        "passiveSetupProvidesBindingOnly": true,
    });
    let target_basis_record = json!({
        "objectType": "EncryptedAggregateTargetBasis",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "sourceBridgeProfileId": "EncryptedAggregateBridge-v1",
        "basisId": BgvBasisKind::Data.basis_id(),
        "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "layoutHash": layout_hash()?,
        "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
        "finalizedBy": "bridge-and-evaluator-closure",
    });
    let reconstruction_record = json!({
        "objectType": "EncryptedAggregateReconstructionBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "bridgeHash": derive_protocol_hash("EncryptedAggregateBridgeHash", &bridge_record)?,
        "TargetBasisRoot": derive_protocol_hash(
            "EncryptedAggregateTargetBasisRoot",
            &target_basis_record,
        )?,
        "layoutHash": layout_hash()?,
        "reconstructionClaimPendingEncryptedAggregateBridge": true,
    });
    let score_bit_derivation_record = json!({
        "objectType": "ScoreBitDerivationCircuitBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "encrypted-score-bit-sliced-comparison-v1",
        "inputLayoutHash": top_k_evaluator_input_layout_hash()?,
        "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "circuitClosurePendingEncryptedAggregateEvaluator": false,
        "developmentEvidenceOnly": true,
    });
    let comparison_input_derivation_record = json!({
        "objectType": "ComparisonInputDerivationCircuitBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "direct-encrypted-score-comparison-v1",
        "inputLayoutHash": top_k_evaluator_input_layout_hash()?,
        "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "circuitClosurePendingEncryptedAggregateEvaluator": true,
        "noiseCertificateAcceptancePending": true,
    });
    let encrypted_score_bit_input_record = json!({
        "objectType": "EncryptedScoreBitInputBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "encrypted-score-bit-sliced-comparison-v1",
        "scoreBitDerivationCircuitHash": derive_protocol_hash(
            "ScoreBitDerivationCircuitHash",
            &score_bit_derivation_record,
        )?,
        "ciphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "packingLayoutHash": top_k_evaluator_input_layout_hash()?,
        "claimUsePendingEncryptedAggregateEvaluator": false,
        "developmentEvidenceOnly": true,
    });
    let encrypted_comparison_input_record = json!({
        "objectType": "EncryptedComparisonInputBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "direct-encrypted-score-comparison-v1",
        "comparisonInputDerivationCircuitHash": derive_protocol_hash(
            "ComparisonInputDerivationCircuitHash",
            &comparison_input_derivation_record,
        )?,
        "ciphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "packingLayoutHash": top_k_evaluator_input_layout_hash()?,
        "claimUsePendingEncryptedAggregateEvaluator": true,
        "noiseCertificateAcceptancePending": true,
    });
    let comparator_record = json!({
        "objectType": "BitSlicedComparatorBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "forbiddenScalarComparatorOperations": [
            "scalar-polynomial-degree-360-comparator",
            "uncertified-polynomial-comparator"
        ],
        "evaluatorProfilePending": true,
    });
    let sparse_target_projection_record = json!({
        "objectType": "EncryptedSparseTargetProjectionBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "targetLayoutHash": target_layout_hash(MAXIMUM_OPTION_COUNT)?,
        "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
        "claimUsePendingEncryptedAggregateEvaluator": true,
    });

    let encrypted_aggregate_bridge_hash =
        derive_protocol_hash("EncryptedAggregateBridgeHash", &bridge_record)?;
    let encrypted_aggregate_target_basis_root =
        derive_protocol_hash("EncryptedAggregateTargetBasisRoot", &target_basis_record)?;
    let encrypted_aggregate_reconstruction_hash = derive_protocol_hash(
        "EncryptedAggregateReconstructionHash",
        &reconstruction_record,
    )?;
    let score_bit_derivation_circuit_hash = derive_protocol_hash(
        "ScoreBitDerivationCircuitHash",
        &score_bit_derivation_record,
    )?;
    let comparison_input_derivation_circuit_hash = derive_protocol_hash(
        "ComparisonInputDerivationCircuitHash",
        &comparison_input_derivation_record,
    )?;
    let encrypted_score_bit_input_hash = derive_protocol_hash(
        "EncryptedScoreBitInputHash",
        &encrypted_score_bit_input_record,
    )?;
    let encrypted_comparison_input_hash = derive_protocol_hash(
        "EncryptedComparisonInputHash",
        &encrypted_comparison_input_record,
    )?;
    let bit_sliced_comparator_hash =
        derive_protocol_hash("BitSlicedComparatorHash", &comparator_record)?;
    let encrypted_sparse_target_projection_hash = derive_protocol_hash(
        "EncryptedSparseTargetProjectionHash",
        &sparse_target_projection_record,
    )?;
    let binding_record = json!({
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "encryptedAggregateBridgeHash": encrypted_aggregate_bridge_hash,
        "encryptedAggregateTargetBasisRoot": encrypted_aggregate_target_basis_root,
        "encryptedAggregateReconstructionHash": encrypted_aggregate_reconstruction_hash,
        "scoreBitDerivationCircuitHash": score_bit_derivation_circuit_hash,
        "comparisonInputDerivationCircuitHash": comparison_input_derivation_circuit_hash,
        "encryptedScoreBitInputHash": encrypted_score_bit_input_hash,
        "encryptedComparisonInputHash": encrypted_comparison_input_hash,
        "bitSlicedComparatorHash": bit_sliced_comparator_hash,
        "encryptedSparseTargetProjectionHash": encrypted_sparse_target_projection_hash,
        "targetLayoutHash": sparse_target_projection_record["targetLayoutHash"],
        "selectedEvaluatorPath": "direct-encrypted-score-comparison-v1",
        "directComparisonInputDerivationStatus": "active-profile-candidate",
        "scoreBitSlicedStatus": "development-evidence-rejected-at-full-depth",
        "claimUse": "binding-only-until-bridge-and-evaluator-closure",
    });

    Ok(json!({
        "evaluatorBindingContextHash": binding_record["evaluatorBindingContextHash"],
        "encryptedAggregateBridgeHash": binding_record["encryptedAggregateBridgeHash"],
        "encryptedAggregateTargetBasisRoot": binding_record["encryptedAggregateTargetBasisRoot"],
        "encryptedAggregateReconstructionHash": binding_record["encryptedAggregateReconstructionHash"],
        "scoreBitDerivationCircuitHash": binding_record["scoreBitDerivationCircuitHash"],
        "comparisonInputDerivationCircuitHash": binding_record["comparisonInputDerivationCircuitHash"],
        "encryptedScoreBitInputHash": binding_record["encryptedScoreBitInputHash"],
        "encryptedComparisonInputHash": binding_record["encryptedComparisonInputHash"],
        "bitSlicedComparatorHash": binding_record["bitSlicedComparatorHash"],
        "encryptedSparseTargetProjectionHash": binding_record["encryptedSparseTargetProjectionHash"],
        "targetLayoutHash": binding_record["targetLayoutHash"],
        "passiveSetupEvaluatorContextBindingHash": derive_protocol_hash(
            "EvaluationContextHash",
            &binding_record,
        )?,
    }))
}

pub(super) fn public_common_random_polynomial_root(
    input: &PassiveSetupInput,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BGVPublicCommonRandomPolynomialRoot",
        &json!({
            "objectType": "BgvPublicCommonRandomPolynomial",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "ceremonyId": input.ceremony_id,
            "rosterHash": input.roster_hash,
            "setupSeedHash": input.setup_seed_hash,
            "basisId": BgvBasisKind::Data.basis_id(),
            "level": DATA_PRIMES.len() - 1,
            "coefficientCount": POLYNOMIAL_DEGREE,
            "sampledResidues": sample_public_residues(
                &input.setup_seed_hash,
                "public-common-random-polynomial",
                DATA_PRIMES[0],
            ),
        }),
    )
}

fn public_rlwe_samples_by_basis(participant_count: usize, rotation_key_count: usize) -> Value {
    let q_data_bits = data_basis_modulus_bits();
    let q_extended_utility_bits = extended_basis_modulus_bits();

    json!({
        "QData": {
            "basisId": BgvBasisKind::Data.basis_id(),
            "modulusBits": q_data_bits,
            "publicKeyShares": participant_count,
            "collectivePublicKey": 1,
            "developmentEncryptionFixtures": 1,
            "relinearizationKeys": DATA_PRIMES.len() - 1,
            "rotationKeys": rotation_key_count,
            "keySwitchKeys": 1,
        },
        "QPPublic": {
            "basisId": BgvBasisKind::Extended.basis_id(),
            "modulusBits": q_extended_utility_bits,
            "exposedOnAcceptedSetupBridgeEvaluatorPath": false,
            "relinearizationKeys": 0,
            "rotationKeys": 0,
            "keySwitchKeys": 0,
            "exposurePolicy": "special-prime utility basis is not public key-switch material in the current accepted setup-bridge-evaluator path",
        },
        "QTarget": {
            "modulusBits": null,
            "sampleCountStatus": "pendingUntilFinalNoiseAnalysis"
        },
    })
}

fn evaluation_key_size_certificate(evaluation_keys: &Value) -> CanonicalResult<Value> {
    let residue_byte_count = 8_usize;
    let polynomial_byte_estimate_data = POLYNOMIAL_DEGREE * DATA_PRIMES.len() * residue_byte_count;
    let polynomial_byte_estimate_extended =
        POLYNOMIAL_DEGREE * (DATA_PRIMES.len() + 1) * residue_byte_count;
    let relinearization_key_record = value_at_path(
        evaluation_keys,
        &[
            "evaluationKeyMaterialCommitment",
            "relinearizationKeyRecord",
        ],
    )?;
    let relinearization_key_bytes = array_at_path(relinearization_key_record, &["levelSchedule"])?
        .iter()
        .map(|level| {
            level
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .map(evaluation_key_stream_bytes_at_level)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "relinearization key level schedule entries must be non-negative integers",
                    )
                })
        })
        .sum::<CanonicalResult<usize>>()?;
    let rotation_key_roots = array_at_path(evaluation_keys, &["rotationKeyRoots"])?;
    let rotation_key_bytes = rotation_key_roots
        .iter()
        .map(|rotation_key| {
            usize_at_path(rotation_key, &["level"]).map(evaluation_key_stream_bytes_at_level)
        })
        .sum::<CanonicalResult<usize>>()?;
    let key_switch_key_bytes = relinearization_key_bytes + rotation_key_bytes;
    let total_evaluation_key_bytes = key_switch_key_bytes;

    Ok(json!({
        "objectType": "EvaluationKeySizeCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "dataBasisPolynomialByteEstimate": polynomial_byte_estimate_data,
        "extendedBasisPolynomialByteEstimate": polynomial_byte_estimate_extended,
        "relinearizationKeyByteEstimate": relinearization_key_bytes,
        "relinearizationKeyLevelCount": array_at_path(relinearization_key_record, &["levelSchedule"])?.len(),
        "rotationKeyCount": rotation_key_roots.len(),
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
            "mobileDownloadRequiresPerformanceMeasurement": true
        },
    }))
}

fn evaluation_key_streaming_commitment(
    evaluation_keys: &Value,
    evaluation_key_size_certificate: &Value,
) -> CanonicalResult<Value> {
    let stream_record = json!({
        "objectType": "BgvEvaluationKeyMaterialCommitmentStream",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluationKeyRoot": evaluation_keys["evaluationKeyRoot"],
        "rotSetHash": evaluation_keys["rotSetHash"],
        "relinearizationKeyRoot": evaluation_keys["relinearizationKeyRoot"],
        "keySwitchKeyRoot": evaluation_keys["keySwitchKeyRoot"],
        "rotationKeyRoots": evaluation_keys["rotationKeyRoots"],
        "evaluationKeyMaterialCommitmentHash": evaluation_keys["evaluationKeyMaterialCommitmentHash"],
        "evaluationKeyMaterialCommitment": evaluation_keys["evaluationKeyMaterialCommitment"],
        "serializationPolicy": "sealed-lattice-canonical-json-evaluation-key-material-commitment-stream",
        "streamCommitmentEvidence": true,
        "fullCoefficientStreamMaterializedInSetupPackage": false,
    });
    let stream_bytes = canonical_json(&stream_record)?.into_bytes();
    let chunk_root_value = chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?;
    let total_evaluation_key_byte_estimate = usize_at_path(
        evaluation_key_size_certificate,
        &["totalEvaluationKeyByteEstimate"],
    )?;
    let storage_quota_refused =
        total_evaluation_key_byte_estimate > DEVELOPMENT_MOBILE_STORAGE_QUOTA_BYTES;
    let commitment_record = json!({
        "objectType": "BgvEvaluationKeyStreamingCommitment",
        "objectVersion": 1,
        "commitmentId": EVALUATION_KEY_STREAMING_COMMITMENT_ID,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "streamRecord": stream_record,
        "canonicalStreamByteLength": stream_bytes.len(),
        "chunkSizeBytes": EVALUATION_KEY_CHUNK_SIZE_BYTES,
        "chunkRoot": chunk_root_value,
        "chunkCount": stream_bytes.len().div_ceil(EVALUATION_KEY_CHUNK_SIZE_BYTES),
        "storageQuotaDecision": {
            "quotaBytes": DEVELOPMENT_MOBILE_STORAGE_QUOTA_BYTES,
            "totalEvaluationKeyByteEstimate": total_evaluation_key_byte_estimate,
            "accepted": !storage_quota_refused,
            "refusalReason": if storage_quota_refused {
                "evaluation-key-estimate-exceeds-development-mobile-storage-quota"
            } else {
                "within-development-mobile-storage-quota"
            }
        },
        "streamCommitmentEvidence": true,
        "fullCoefficientStreamMaterializedInSetupPackage": false,
    });
    let commitment_hash = derive_protocol_hash("EvaluationKeySetDigest", &commitment_record)?;

    Ok(json!({
        "commitment": commitment_record,
        "commitmentHash": commitment_hash,
    }))
}

fn evaluation_key_stream_bytes_at_level(level: usize) -> usize {
    let active_limb_count = level + 1;
    let component_count = 2;
    let digit_count = active_limb_count;

    digit_count * component_count * active_limb_count * POLYNOMIAL_DEGREE * 8
}
