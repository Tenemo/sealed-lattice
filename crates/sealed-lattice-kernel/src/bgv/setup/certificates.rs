use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn setup_certificates(
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
    let q_data_bits = data_basis_modulus_bits();
    let qp_public_bits = extended_basis_modulus_bits();
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
    let evaluation_key_streaming_fixture =
        evaluation_key_streaming_fixture(evaluation_keys, &evaluation_key_size_certificate)?;
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
        "evaluationKeyStreamingFixtureDigest": evaluation_key_streaming_fixture["fixtureDigest"],
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
        "evaluationKeyStreamingFixture": evaluation_key_streaming_fixture,
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
        "decompositionStatus": "provisional-M8-for-M10-schedule",
        "genericKeySwitchApiExported": false,
    }))
}

pub(super) fn threshold_decryption_profile(profile_digest: &str) -> CanonicalResult<Value> {
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

pub(super) fn m8_evaluator_context_bindings(setup_inputs: &Value) -> CanonicalResult<Value> {
    let evaluator_binding_context = json!({
        "objectType": "M8EvaluatorBindingContext",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": string_at_path(setup_inputs, &["ceremonyId"])?,
        "manifestDigest": string_at_path(setup_inputs, &["manifestDigest"])?,
        "rosterDigest": string_at_path(setup_inputs, &["rosterDigest"])?,
        "thresholdProfileDigest": string_at_path(setup_inputs, &["thresholdProfileDigest"])?,
        "participantCount": unsigned_at_path(setup_inputs, &["participantCount"])?,
        "setupSeedDigest": string_at_path(setup_inputs, &["setupSeedDigest"])?,
    });
    let evaluator_binding_context_digest = derive_protocol_digest(
        "M8EvaluatorBindingContextDigest",
        &evaluator_binding_context,
    )?;
    let bridge_record = json!({
        "profileId": "EncryptedAggregateBridge-v1",
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "bgvProfileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "inputLayoutDigest": layout_digest()?,
        "aggregateInputEncodingProfileDigest": aggregate_input_encoding_profile_digest()?,
        "bridgeEvidenceRequiredBeforeClaimUse": true,
        "m8ProvidesSetupBindingOnly": true,
    });
    let target_basis_record = json!({
        "objectType": "EncryptedAggregateTargetBasisData",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "sourceBridgeProfileId": "EncryptedAggregateBridge-v1",
        "basisId": BgvBasisKind::Data.basis_id(),
        "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest()?,
        "layoutDigest": layout_digest()?,
        "topKEvaluatorInputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "finalizedBy": "M9-M10",
    });
    let reconstruction_record = json!({
        "objectType": "EncryptedAggregateReconstructionBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "bridgeDigest": derive_protocol_digest("EncryptedAggregateBridgeDigest", &bridge_record)?,
        "targetBasisDataRoot": derive_protocol_digest(
            "EncryptedAggregateTargetBasisDataRoot",
            &target_basis_record,
        )?,
        "layoutDigest": layout_digest()?,
        "reconstructionClaimPendingM9": true,
    });
    let score_bit_derivation_record = json!({
        "objectType": "ScoreBitDerivationCircuitBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "inputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "encodedAggregateLayoutDigest": encoded_aggregate_layout_digest()?,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
        "circuitClosurePendingM10": true,
    });
    let comparison_input_derivation_record = json!({
        "objectType": "ComparisonInputDerivationCircuitBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "selectedEvaluatorPath": "inactive-future-direct-comparison-input-profile",
        "inputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "encodedAggregateLayoutDigest": encoded_aggregate_layout_digest()?,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
        "circuitClosurePendingM10": false,
        "futureRdrRequired": true,
    });
    let encrypted_score_bit_input_record = json!({
        "objectType": "EncryptedScoreBitInputBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "scoreBitDerivationCircuitDigest": derive_protocol_digest(
            "ScoreBitDerivationCircuitDigest",
            &score_bit_derivation_record,
        )?,
        "ciphertextConventionDigest": canonical_ciphertext_convention_digest()?,
        "packingLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "claimUsePendingM10": true,
    });
    let encrypted_comparison_input_record = json!({
        "objectType": "EncryptedComparisonInputBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "selectedEvaluatorPath": "inactive-future-direct-comparison-input-profile",
        "comparisonInputDerivationCircuitDigest": derive_protocol_digest(
            "ComparisonInputDerivationCircuitDigest",
            &comparison_input_derivation_record,
        )?,
        "ciphertextConventionDigest": canonical_ciphertext_convention_digest()?,
        "packingLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "claimUsePendingM10": false,
        "futureRdrRequired": true,
    });
    let comparator_record = json!({
        "objectType": "BitSlicedComparatorBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
        "forbiddenScalarComparatorOperations": [
            "scalar-polynomial-degree-360-comparator",
            "uncertified-polynomial-comparator"
        ],
        "appendixDProfilePending": true,
    });
    let sparse_target_projection_record = json!({
        "objectType": "EncryptedSparseTargetProjectionBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "targetLayoutDigest": derive_protocol_digest(
            "TargetLayoutDigest",
            &json!({
                "profileId": PROFILE_ID,
                "targetLayout": "M3-sparse-top-k-target-over-M7-canonical-ciphertext-convention",
                "finalizedBy": "M10-M13",
            }),
        )?,
        "topKEvaluatorInputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "claimUsePendingM10": true,
    });

    let encrypted_aggregate_bridge_digest =
        derive_protocol_digest("EncryptedAggregateBridgeDigest", &bridge_record)?;
    let encrypted_aggregate_target_basis_data_root = derive_protocol_digest(
        "EncryptedAggregateTargetBasisDataRoot",
        &target_basis_record,
    )?;
    let encrypted_aggregate_reconstruction_digest = derive_protocol_digest(
        "EncryptedAggregateReconstructionDigest",
        &reconstruction_record,
    )?;
    let score_bit_derivation_circuit_digest = derive_protocol_digest(
        "ScoreBitDerivationCircuitDigest",
        &score_bit_derivation_record,
    )?;
    let comparison_input_derivation_circuit_digest = derive_protocol_digest(
        "ComparisonInputDerivationCircuitDigest",
        &comparison_input_derivation_record,
    )?;
    let encrypted_score_bit_input_digest = derive_protocol_digest(
        "EncryptedScoreBitInputDigest",
        &encrypted_score_bit_input_record,
    )?;
    let encrypted_comparison_input_digest = derive_protocol_digest(
        "EncryptedComparisonInputDigest",
        &encrypted_comparison_input_record,
    )?;
    let bit_sliced_comparator_digest =
        derive_protocol_digest("BitSlicedComparatorDigest", &comparator_record)?;
    let encrypted_sparse_target_projection_digest = derive_protocol_digest(
        "EncryptedSparseTargetProjectionDigest",
        &sparse_target_projection_record,
    )?;
    let binding_record = json!({
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluatorBindingContextDigest": &evaluator_binding_context_digest,
        "encryptedAggregateBridgeDigest": encrypted_aggregate_bridge_digest,
        "encryptedAggregateTargetBasisDataRoot": encrypted_aggregate_target_basis_data_root,
        "encryptedAggregateReconstructionDigest": encrypted_aggregate_reconstruction_digest,
        "scoreBitDerivationCircuitDigest": score_bit_derivation_circuit_digest,
        "comparisonInputDerivationCircuitDigest": comparison_input_derivation_circuit_digest,
        "encryptedScoreBitInputDigest": encrypted_score_bit_input_digest,
        "encryptedComparisonInputDigest": encrypted_comparison_input_digest,
        "bitSlicedComparatorDigest": bit_sliced_comparator_digest,
        "encryptedSparseTargetProjectionDigest": encrypted_sparse_target_projection_digest,
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "directComparisonInputDerivationStatus": "inactive-future-profile",
        "claimUse": "binding-only-until-M9-M10-closure",
    });

    Ok(json!({
        "evaluatorBindingContextDigest": binding_record["evaluatorBindingContextDigest"],
        "encryptedAggregateBridgeDigest": binding_record["encryptedAggregateBridgeDigest"],
        "encryptedAggregateTargetBasisDataRoot": binding_record["encryptedAggregateTargetBasisDataRoot"],
        "encryptedAggregateReconstructionDigest": binding_record["encryptedAggregateReconstructionDigest"],
        "scoreBitDerivationCircuitDigest": binding_record["scoreBitDerivationCircuitDigest"],
        "comparisonInputDerivationCircuitDigest": binding_record["comparisonInputDerivationCircuitDigest"],
        "encryptedScoreBitInputDigest": binding_record["encryptedScoreBitInputDigest"],
        "encryptedComparisonInputDigest": binding_record["encryptedComparisonInputDigest"],
        "bitSlicedComparatorDigest": binding_record["bitSlicedComparatorDigest"],
        "encryptedSparseTargetProjectionDigest": binding_record["encryptedSparseTargetProjectionDigest"],
        "m8EvaluatorContextBindingDigest": derive_protocol_digest(
            "EvaluationContextDigest",
            &binding_record,
        )?,
    }))
}

pub(super) fn public_common_random_polynomial_root(
    input: &PassiveSetupInput,
) -> CanonicalResult<String> {
    derive_protocol_digest(
        "BGVPublicCommonRandomPolynomialRoot",
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

fn evaluation_key_streaming_fixture(
    evaluation_keys: &Value,
    evaluation_key_size_certificate: &Value,
) -> CanonicalResult<Value> {
    let stream_record = json!({
        "objectType": "BgvEvaluationKeyCanonicalByteStream",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluationKeyRoot": evaluation_keys["evaluationKeyRoot"],
        "rotSetDigest": evaluation_keys["rotSetDigest"],
        "relinearizationKeyRoot": evaluation_keys["relinearizationKeyRoot"],
        "keySwitchKeyRoot": evaluation_keys["keySwitchKeyRoot"],
        "rotationKeyRoots": evaluation_keys["rotationKeyRoots"],
        "relinearizationArithmeticFixtureDigest": evaluation_keys["relinearizationArithmeticFixture"]["fixtureDigest"],
        "keySwitchArithmeticFixtureDigest": evaluation_keys["keySwitchArithmeticFixture"]["fixtureDigest"],
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
    let fixture_digest = development_fixture_digest(&fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureDigest": fixture_digest,
    }))
}
