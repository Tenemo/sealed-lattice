use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn setup_certificates(
    input: &PassiveSetupInput,
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
    let qp_public_bits = extended_basis_modulus_bits();
    let rotation_key_count = evaluation_keys["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots use array")
        .len();
    let public_samples = public_rlwe_samples_by_basis(input.participants.len(), rotation_key_count);
    let evaluation_key_size_certificate = evaluation_key_size_certificate(rotation_key_count);
    let evaluation_key_size_profile_hash = derive_protocol_hash(
        "EvaluationKeySizeProfileHash",
        &evaluation_key_size_certificate,
    )?;
    let evaluation_key_streaming_fixture =
        evaluation_key_streaming_fixture(evaluation_keys, &evaluation_key_size_certificate)?;
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
        "qpPublicBits": qp_public_bits,
        "qTargetBits": null,
        "publicEvaluationKeyBasis": BgvBasisKind::Extended.basis_id(),
        "largestExposedModulusBitsWithoutQTarget": qp_public_bits,
        "largestExposedBasisClassWithoutQTarget": "QP_public",
        "largestExposedModulusBits": null,
        "finalSecurityStatus": "pendingQTarget",
        "collectiveSecretDistributionCertificateHash": collective_secret_distribution_certificate_hash,
        "errorDistributionCertificateHash": error_distribution_certificate_hash,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "evaluationKeySizeProfileHash": evaluation_key_size_profile_hash,
        "evaluationKeyStreamingFixtureHash": evaluation_key_streaming_fixture["fixtureHash"],
        "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
        "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
        "securityEstimatorInputHash": security_estimator_input_hash()?,
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
        "setupParameterCertificate": setup_parameter_certificate,
        "setupParameterCertificateHash": setup_parameter_certificate_hash,
        "evaluationKeySizeCertificate": evaluation_key_size_certificate,
        "evaluationKeySizeProfileHash": evaluation_key_size_profile_hash,
        "evaluationKeyStreamingFixture": evaluation_key_streaming_fixture,
        "developmentEncryptionFixtureHash": development_encryption_fixture["fixtureHash"],
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

pub(super) fn collective_secret_distribution_certificate(
    participant_count: usize,
) -> CanonicalResult<Value> {
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
            "samplerId": "hash-derived-rejection-sampled-balanced-ternary-local-share-v2",
            "support": [-1, 0, 1],
            "probabilityNumeratorBySupport": [1, 1, 1],
            "probabilityDenominator": 3,
            "candidateBits": 64,
            "rejectionRule": "reject-candidates-outside-largest-multiple-of-support-width",
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
        "basisId": BgvBasisKind::Extended.basis_id(),
        "digitBaseBits": 23,
        "digitCountPerPrime": 3,
        "decompositionStatus": "provisional-passive-setup-for-encrypted-evaluator",
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
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "inputLayoutHash": top_k_evaluator_input_layout_hash()?,
        "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "circuitClosurePendingEncryptedAggregateEvaluator": true,
    });
    let comparison_input_derivation_record = json!({
        "objectType": "ComparisonInputDerivationCircuitBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "inactive-future-direct-comparison-input-profile",
        "inputLayoutHash": top_k_evaluator_input_layout_hash()?,
        "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "circuitClosurePendingEncryptedAggregateEvaluator": false,
        "futureDesignNoteRequired": true,
    });
    let encrypted_score_bit_input_record = json!({
        "objectType": "EncryptedScoreBitInputBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "scoreBitDerivationCircuitHash": derive_protocol_hash(
            "ScoreBitDerivationCircuitHash",
            &score_bit_derivation_record,
        )?,
        "ciphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "packingLayoutHash": top_k_evaluator_input_layout_hash()?,
        "claimUsePendingEncryptedAggregateEvaluator": true,
    });
    let encrypted_comparison_input_record = json!({
        "objectType": "EncryptedComparisonInputBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "inactive-future-direct-comparison-input-profile",
        "comparisonInputDerivationCircuitHash": derive_protocol_hash(
            "ComparisonInputDerivationCircuitHash",
            &comparison_input_derivation_record,
        )?,
        "ciphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "packingLayoutHash": top_k_evaluator_input_layout_hash()?,
        "claimUsePendingEncryptedAggregateEvaluator": false,
        "futureDesignNoteRequired": true,
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
        "targetLayoutHash": derive_protocol_hash(
            "TargetLayoutHash",
            &json!({
                "profileId": PROFILE_ID,
                "targetLayout": "sparse-top-k-target-over-bgv-rns-canonical-ciphertext-convention",
                "finalizedBy": "evaluator-and-decryption-closure",
            }),
        )?,
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
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "directComparisonInputDerivationStatus": "inactive-future-profile",
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
    let qp_public_bits = extended_basis_modulus_bits();

    json!({
        "QData": {
            "basisId": BgvBasisKind::Data.basis_id(),
            "modulusBits": q_data_bits,
            "publicKeyShares": participant_count,
            "collectivePublicKey": 1,
            "developmentEncryptionFixtures": 1,
        },
        "QPPublic": {
            "basisId": BgvBasisKind::Extended.basis_id(),
            "modulusBits": qp_public_bits,
            "relinearizationKeys": 2,
            "rotationKeys": rotation_key_count,
            "keySwitchKeys": 1,
        },
        "QTarget": {
            "modulusBits": null,
            "sampleCountStatus": "pendingUntilFinalNoiseAnalysis"
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
            "mobileDownloadRequiresPerformanceMeasurement": true
        },
    })
}

fn evaluation_key_streaming_fixture(
    evaluation_keys: &Value,
    evaluation_key_size_certificate: &Value,
) -> CanonicalResult<Value> {
    let stream_record = json!({
        "objectType": "BgvEvaluationKeyCanonicalByteStream",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluationKeyRoot": evaluation_keys["evaluationKeyRoot"],
        "rotSetHash": evaluation_keys["rotSetHash"],
        "relinearizationKeyRoot": evaluation_keys["relinearizationKeyRoot"],
        "keySwitchKeyRoot": evaluation_keys["keySwitchKeyRoot"],
        "rotationKeyRoots": evaluation_keys["rotationKeyRoots"],
        "relinearizationArithmeticFixtureHash": evaluation_keys["relinearizationArithmeticFixture"]["fixtureHash"],
        "keySwitchArithmeticFixtureHash": evaluation_keys["keySwitchArithmeticFixture"]["fixtureHash"],
        "serializationPolicy": "sealed-lattice-canonical-json-evaluation-key-record-stream",
        "protocolEvidence": false,
    });
    let stream_bytes = canonical_json(&stream_record)?.into_bytes();
    let chunk_root_value = chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?;
    let total_evaluation_key_byte_estimate = usize_at_path(
        evaluation_key_size_certificate,
        &["totalEvaluationKeyByteEstimate"],
    )?;
    let storage_quota_refused =
        total_evaluation_key_byte_estimate > DEVELOPMENT_MOBILE_STORAGE_QUOTA_BYTES;
    let fixture_record = json!({
        "objectType": "BgvEvaluationKeyStreamingFixture",
        "objectVersion": 1,
        "fixtureId": EVALUATION_KEY_STREAMING_FIXTURE_ID,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "streamRecord": stream_record,
        "canonicalStreamByteLength": stream_bytes.len(),
        "chunkSizeBytes": EVALUATION_KEY_CHUNK_SIZE_BYTES,
        "chunkRoot": chunk_root_value,
        "chunkCount": stream_bytes.len().div_ceil(EVALUATION_KEY_CHUNK_SIZE_BYTES),
        "storageQuotaFixture": {
            "quotaBytes": DEVELOPMENT_MOBILE_STORAGE_QUOTA_BYTES,
            "totalEvaluationKeyByteEstimate": total_evaluation_key_byte_estimate,
            "accepted": !storage_quota_refused,
            "refusalReason": if storage_quota_refused {
                "evaluation-key-estimate-exceeds-development-mobile-storage-quota"
            } else {
                "within-development-mobile-storage-quota"
            }
        },
        "protocolEvidence": false,
    });
    let fixture_hash = development_fixture_hash(&fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureHash": fixture_hash,
    }))
}
