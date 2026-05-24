use serde_json::{Value, json};

use crate::{
    bgv::{
        modular_arithmetic::centered_representative,
        profile::{
            BACKEND_PROFILE_ID, BATCH_ENCODER_ID, BgvBasisKind, CANONICAL_CIPHERTEXT_CONVENTION_ID,
            DATA_PRIMES, OPERATION_REGISTRY_ID, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, PROFILE_ID,
            SPECIAL_PRIME, aggregate_input_encoding_profile_digest,
            allowed_operation_registry_digest, allowed_operation_registry_value,
            backend_profile_digest, ballot_score_encoding_profile_digest,
            ballot_share_layout_profile_digest, batch_encoder_digest, batch_layout_binding_digest,
            batch_layout_binding_value, canonical_ciphertext_convention_digest,
            encoded_aggregate_layout_digest, layout_digest, profile_digest,
            security_estimator_input_digest, selected_profile_value,
            top_k_evaluator_input_layout_digest,
        },
    },
    encoding::CanonicalResult,
    hashing::derive_protocol_digest,
};

pub(crate) fn describe_profile_report() -> CanonicalResult<Value> {
    let profile_digest = profile_digest()?;
    let backend_profile_digest = backend_profile_digest()?;
    let batch_encoder_digest = batch_encoder_digest()?;
    let batch_layout_binding = batch_layout_binding_value()?;
    let batch_layout_binding_digest = batch_layout_binding_digest()?;
    let layout_digest = layout_digest()?;
    let canonical_ciphertext_convention_digest = canonical_ciphertext_convention_digest()?;
    let allowed_operation_registry_digest = allowed_operation_registry_digest()?;
    let estimator_input_digest = security_estimator_input_digest()?;

    Ok(json!({
        "profile": selected_profile_value(),
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "batchEncoderDigest": batch_encoder_digest,
        "batchLayoutBinding": batch_layout_binding,
        "batchLayoutBindingDigest": batch_layout_binding_digest,
        "encryptedAggregateInputLayoutDigest": layout_digest,
        "ballotScoreEncodingProfileDigest": ballot_score_encoding_profile_digest()?,
        "ballotShareLayoutProfileDigest": ballot_share_layout_profile_digest()?,
        "aggregateInputEncodingProfileDigest": aggregate_input_encoding_profile_digest()?,
        "encodedAggregateLayoutDigest": encoded_aggregate_layout_digest()?,
        "topKEvaluatorInputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest,
        "securityEstimatorInputDigest": estimator_input_digest,
        "basisReports": [
            basis_report(BgvBasisKind::Data)?,
            basis_report(BgvBasisKind::Extended)?,
            basis_report(BgvBasisKind::Special)?
        ],
        "statusLabels": [
            "M7ImplementationEvidence",
            "SealedLatticeRustWasmOwned",
            "ReferenceOracleDevelopmentOnly"
        ],
        "nonClaims": [
            "M8SetupNotImplemented",
            "M9BridgeProofNotImplemented",
            "M10EvaluatorNotImplemented",
            "StageXNotClosed",
            "CPADNotImplemented",
            "RuntimeBenchmarkReportMissing"
        ],
    }))
}

pub(crate) fn operation_registry_report() -> CanonicalResult<Value> {
    Ok(json!({
        "registry": allowed_operation_registry_value()?,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
        "statusLabels": [
            "AllowedOperationsFrozen",
            "GenericFheApiNotExported"
        ],
    }))
}

pub(crate) fn backend_parameter_certificate_report() -> CanonicalResult<Value> {
    let profile_digest = profile_digest()?;
    let q_data_bits = DATA_PRIMES.len() * 47;
    let qp_public_bits = (DATA_PRIMES.len() + 1) * 47;
    let parameter_certificate_value = json!({
        "parameterCertificateId": "m7-bgv-rns-backend-parameter-certificate-v1",
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "profileDigest": profile_digest,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "dataPrimeCount": DATA_PRIMES.len(),
        "dataPrimeBitLength": 47,
        "specialPrimeCount": 1,
        "totalModulusBitsAtFullDataLevel": q_data_bits,
        "totalModulusBitsAtExtendedLevel": qp_public_bits,
        "qDataBits": q_data_bits,
        "qTargetBits": null,
        "qpPublicBits": qp_public_bits,
        "largestExposedModulusBits": null,
        "largestKnownExposedModulusBits": qp_public_bits,
        "exposedBasisClass": "data-plus-special-public-estimator-input-target-pending",
        "publicRlweSamplesByBasis": {
            "data": {
                "modulusBits": q_data_bits,
                "sampleCountStatus": "pending-M8-key-material"
            },
            "qpPublic": {
                "modulusBits": qp_public_bits,
                "sampleCountStatus": "pending-M8-evaluation-key-material"
            },
            "target": {
                "modulusBits": null,
                "sampleCountStatus": "pending-Appendix-C-Q-target"
            }
        },
        "secretDistributionCertificate": {
            "status": "pending-M8-collective-secret-distribution",
            "sparseOrFixedHammingSecretsRequireSeparateCertification": true
        },
        "errorDistributionCertificate": {
            "status": "pending-M8-error-distribution"
        },
        "estimatorRows": [
            {
                "basis": "data",
                "modulusBits": q_data_bits,
                "status": "preliminary-M7-input"
            },
            {
                "basis": "qpPublic",
                "modulusBits": qp_public_bits,
                "status": "preliminary-M7-input"
            },
            {
                "basis": "target",
                "modulusBits": null,
                "status": "pending-Appendix-C-Q-target"
            }
        ],
        "securityEstimatorInputDigest": security_estimator_input_digest()?,
        "noiseBudgetHook": {
            "status": "hook-only-for-M8-through-M10",
            "owner": "sealed-lattice-rust-wasm",
            "mustBindProfileDigest": true
        },
        "referenceOracleBoundary": {
            "lattigoRuntimeDependency": false,
            "dockerOracleEvidenceAcceptedAsTranscriptObject": false,
            "oracleVectorsAcceptedAsProtocolEvidence": false
        },
        "m6ToM7InputContract": {
            "sourceMilestone": "M6",
            "bridgePath": "EncryptedAggregateBridge-v1",
            "inputWitnessCustody": "each contributor keeps aggregate witness private",
            "encryptedAggregateInputLayoutId": "encrypted-aggregate-input-layout-v1",
            "encryptedAggregateInputLayoutDigest": layout_digest()?,
            "batchLayoutBinding": batch_layout_binding_value()?,
            "batchLayoutBindingDigest": batch_layout_binding_digest()?,
            "batchEncoderId": BATCH_ENCODER_ID,
            "batchEncoderDigest": batch_encoder_digest()?,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "slotCount": POLYNOMIAL_DEGREE,
            "forbiddenCentralization": [
                "aggregate histograms",
                "exact aggregate scores",
                "aggregate score bits",
                "plaintext comparison inputs",
                "t_pvss aggregate witnesses"
            ]
        },
        "canonicalObjectBoundary": {
            "plaintextRootNamespace": "PlaintextRoot",
            "ciphertextRootNamespace": "CiphertextRoot",
            "canonicalCiphertextConventionId": CANONICAL_CIPHERTEXT_CONVENTION_ID,
            "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest()?,
            "canonicalBytesHashDomain": "sealed-lattice-bgv-rns/canonical-bytes-v1"
        },
        "allowedOperationRegistryId": OPERATION_REGISTRY_ID,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
        "centeredRepresentativeExamples": [
            {
                "modulus": DATA_PRIMES[0],
                "residue": 0,
                "centered": centered_representative(0, DATA_PRIMES[0])?
            },
            {
                "modulus": DATA_PRIMES[0],
                "residue": DATA_PRIMES[0] - 1,
                "centered": centered_representative(DATA_PRIMES[0] - 1, DATA_PRIMES[0])?
            }
        ],
    });

    Ok(json!({
        "parameterCertificate": parameter_certificate_value,
        "parameterCertificateDigest": derive_protocol_digest("HEParamDigest", &parameter_certificate_value)?,
        "statusLabels": [
            "ParameterCertificateReportEmitted",
            "SecurityEstimatorInputRecorded",
            "NoiseBudgetHookRecorded"
        ],
    }))
}

fn basis_report(basis_kind: BgvBasisKind) -> CanonicalResult<Value> {
    let all_moduli = basis_kind.all_moduli();
    let full_level = match basis_kind {
        BgvBasisKind::Special => 0,
        BgvBasisKind::Data => DATA_PRIMES.len() - 1,
        BgvBasisKind::Extended => DATA_PRIMES.len(),
    };

    Ok(json!({
        "basisId": basis_kind.basis_id(),
        "fullLevel": full_level,
        "modulusCount": all_moduli.len(),
        "moduli": all_moduli,
        "specialPrime": if basis_kind == BgvBasisKind::Special { Some(SPECIAL_PRIME) } else { None },
    }))
}
