mod evaluation_keys;

use self::evaluation_keys::{
    evaluation_key_size_certificate, evaluation_key_streaming_commitment,
    public_rlwe_samples_by_basis,
};
use super::*;
use crate::bgv::evaluator::records::target_layout_hash;
use crate::bgv::parameters::SPECIAL_PRIME;
use crate::hashing::derive_canonical_object_hash;
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
    target_decryption_parameters_hash: &str,
    target_decryption_parameters_binding_hash: &str,
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
    let evaluation_key_size_parameters_hash =
        derive_canonical_object_hash(&evaluation_key_size_certificate)?;
    let evaluation_key_streaming_commitment = evaluation_key_streaming_commitment(evaluation_keys)?;
    let target_threshold_decryptability_certificate =
        target_threshold_decryptability_certificate_for_setup_parts(
            setup_inputs,
            collective_public_key,
            threshold_verification_material,
            target_decryption_parameters_hash,
            target_decryption_parameters_binding_hash,
        )?;
    let target_threshold_decryptability_certificate_hash =
        derive_canonical_object_hash(&target_threshold_decryptability_certificate)?;
    let setup_parameter_certificate = json!({
        "objectType": "BgvSetupParameterCertificate",
        "objectVersion": 1,
        "bgvParametersHash": bgv_parameters_hash()?,
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
        "collectiveSecretDistributionCertificateHash": collective_secret_distribution_certificate_hash,
        "errorDistributionCertificateHash": error_distribution_certificate_hash,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "evaluationKeySizeParametersHash": evaluation_key_size_parameters_hash,
        "evaluationKeyStreamingCommitmentHash": evaluation_key_streaming_commitment["commitmentHash"],
        "targetDecryptionParametersHash": target_decryption_parameters_hash,
        "targetDecryptionParametersBindingHash": target_decryption_parameters_binding_hash,
        "targetThresholdDecryptabilityCertificateHash": target_threshold_decryptability_certificate_hash,
    });
    let setup_parameter_certificate_hash =
        derive_canonical_object_hash(&setup_parameter_certificate)?;

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
        "targetThresholdDecryptabilityCertificate": target_threshold_decryptability_certificate,
        "targetThresholdDecryptabilityCertificateHash": target_threshold_decryptability_certificate_hash,
        "evaluationKeySizeCertificate": evaluation_key_size_certificate,
        "evaluationKeySizeParametersHash": evaluation_key_size_parameters_hash,
        "evaluationKeyStreamingCommitment": evaluation_key_streaming_commitment,
        "developmentEncryptionFixtureHash": development_encryption_fixture["fixtureHash"],
    }))
}

fn modulus_product_decimal(moduli: impl IntoIterator<Item = u64>) -> String {
    let mut product = BigUint::from(1_u8);
    for modulus in moduli {
        product *= BigUint::from(modulus);
    }

    product.to_str_radix(10)
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
        "localShareSampler": {
            "support": [-1, 0, 1],
            "probabilityNumeratorBySupport": [1, 1, 1],
            "probabilityDenominator": 3,
            "candidateBits": 64,
            "rejectionRule": "reject-candidates-outside-largest-multiple-of-support-width",
            "ownerSelectionRule": "one-deterministic-participant-owner-per-coefficient; owner samples one standard ternary coefficient; non-owner local shares are zero",
            "ownerSelectionParticipantCount": participant_count_u64,
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
        },
        "estimatorSecretModel": "HE-standard-ternary",
        "noiseModelSecretModel": "standard-ternary",
    }))
}

pub(super) fn error_distribution_certificate() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "ErrorDistributionCertificate",
        "objectVersion": 1,
        "errorSampler": {
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
            "candidateBits": 64,
        },
        "rejectionSamplingRules": [
            "small-distribution-candidates-outside-largest-multiple-of-support-width-are-rehashed",
            "public-residue-candidates-outside-largest-multiple-of-modulus-are-rehashed"
        ],
    }))
}

pub(super) fn key_switch_decomposition_parameters() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvKeySwitchDecompositionParameters",
        "objectVersion": 1,
        "digitBaseBits": 23,
        "digitCountPerPrime": 3,
    }))
}

// Identity of the target-decryption parameters: the bound BGV parameters
// hash, the secret-share domain, and the async-Lagrange target direction. Implementation
// and certification state (partial/final decryption maturity, C1-C4 certification, whether
// Q_target is known) is not asserted as bound flags here; that scope lives in the README
// safety boundaries and the target-decryption implementation notes.
pub(super) fn target_decryption_parameters(bgv_parameters_hash: &str) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "TargetDecryptionParameters",
        "objectVersion": 1,
        "bgvParametersHash": bgv_parameters_hash,
        "secretShareDomain": "BGV-RNS-secret-share-polynomial-over-selected-Q-data",
        "asyncLagrangeTargetDirection": true,
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
            &["targetDecryptionStatus", "targetDecryptionParametersHash"],
        )?,
        string_at_path(
            setup_package,
            &[
                "targetDecryptionStatus",
                "targetDecryptionParametersBindingHash",
            ],
        )?,
    )
}

pub(super) fn target_threshold_decryptability_certificate_for_setup_parts(
    setup_inputs: &Value,
    collective_public_key: &Value,
    threshold_verification_material: &Value,
    target_decryption_parameters_hash: &str,
    target_decryption_parameters_binding_hash: &str,
) -> CanonicalResult<Value> {
    let setup_binding = json!({
        "bgvParametersHash": bgv_parameters_hash()?,
        "ceremonyId": string_at_path(setup_inputs, &["ceremonyId"])?,
        "manifestHash": string_at_path(setup_inputs, &["manifestHash"])?,
        "rosterHash": string_at_path(setup_inputs, &["rosterHash"])?,
        "thresholdParametersHash": string_at_path(setup_inputs, &["thresholdParametersHash"])?,
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
    let ciphertext_parameters = json!({
        "plaintextModulus": PLAINTEXT_MODULUS,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "level": DATA_PRIMES.len() - 1,
        "dataPrimeCount": DATA_PRIMES.len(),
        "ciphertextComponentCount": 2,
        "bgvParametersHash": bgv_parameters_hash()?,
    });
    let threshold_binding = json!({
        "targetDecryptionParametersHash": target_decryption_parameters_hash,
        "targetDecryptionParametersBindingHash": target_decryption_parameters_binding_hash,
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
        "setupBinding": setup_binding,
        "keyBinding": key_binding,
        "ciphertextParameters": ciphertext_parameters,
        "thresholdBinding": threshold_binding,
    }))
}

pub(super) fn passive_setup_evaluator_context_bindings(
    setup_inputs: &Value,
) -> CanonicalResult<Value> {
    let evaluator_binding_context = json!({
        "objectType": "PassiveSetupEvaluatorBindingContext",
        "objectVersion": 1,
        "ceremonyId": string_at_path(setup_inputs, &["ceremonyId"])?,
        "manifestHash": string_at_path(setup_inputs, &["manifestHash"])?,
        "rosterHash": string_at_path(setup_inputs, &["rosterHash"])?,
        "thresholdParametersHash": string_at_path(setup_inputs, &["thresholdParametersHash"])?,
        "participantCount": unsigned_at_path(setup_inputs, &["participantCount"])?,
        "setupSeedHash": string_at_path(setup_inputs, &["setupSeedHash"])?,
    });
    let evaluator_binding_context_hash = derive_canonical_object_hash(&evaluator_binding_context)?;
    let bgv_parameters_hash = bgv_parameters_hash()?;
    let comparison_input_derivation_record = json!({
        "objectType": "ComparisonInputDerivationCircuitBinding",
        "objectVersion": 1,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "direct-encrypted-score-comparison-v1",
        "bgvParametersHash": &bgv_parameters_hash,
    });
    let encrypted_comparison_input_record = json!({
        "objectType": "EncryptedComparisonInputBinding",
        "objectVersion": 1,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "direct-encrypted-score-comparison-v1",
        "comparisonInputDerivationCircuitHash": derive_canonical_object_hash(
            &comparison_input_derivation_record,
        )?,
        "bgvParametersHash": &bgv_parameters_hash,
    });
    let sparse_target_projection_record = json!({
        "objectType": "EncryptedSparseTargetProjectionBinding",
        "objectVersion": 1,
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "targetLayoutHash": target_layout_hash(MAXIMUM_OPTION_COUNT)?,
        "bgvParametersHash": &bgv_parameters_hash,
    });

    let comparison_input_derivation_circuit_hash =
        derive_canonical_object_hash(&comparison_input_derivation_record)?;
    let encrypted_comparison_input_hash =
        derive_canonical_object_hash(&encrypted_comparison_input_record)?;
    let encrypted_sparse_target_projection_hash =
        derive_canonical_object_hash(&sparse_target_projection_record)?;
    let binding_record = json!({
        "objectType": "PassiveSetupEvaluatorContextBinding",
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "bgvParametersHash": &bgv_parameters_hash,
        "comparisonInputDerivationCircuitHash": comparison_input_derivation_circuit_hash,
        "encryptedComparisonInputHash": encrypted_comparison_input_hash,
        "encryptedSparseTargetProjectionHash": encrypted_sparse_target_projection_hash,
        "targetLayoutHash": sparse_target_projection_record["targetLayoutHash"],
        "selectedEvaluatorPath": "direct-encrypted-score-comparison-v1",
    });

    Ok(json!({
        "evaluatorBindingContextHash": binding_record["evaluatorBindingContextHash"],
        "bgvParametersHash": binding_record["bgvParametersHash"],
        "comparisonInputDerivationCircuitHash": binding_record["comparisonInputDerivationCircuitHash"],
        "encryptedComparisonInputHash": binding_record["encryptedComparisonInputHash"],
        "encryptedSparseTargetProjectionHash": binding_record["encryptedSparseTargetProjectionHash"],
        "targetLayoutHash": binding_record["targetLayoutHash"],
        "passiveSetupEvaluatorContextBindingHash": derive_canonical_object_hash(
            &binding_record,
        )?,
    }))
}

pub(super) fn public_common_random_polynomial_root(
    input: &PassiveSetupInput,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "BgvPublicCommonRandomPolynomial",
        "objectVersion": 1,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "setupSeedHash": input.setup_seed_hash,
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "sampledResidues": sample_public_residues(
            &input.setup_seed_hash,
            "public-common-random-polynomial",
            DATA_PRIMES[0],
        ),
    }))
}
