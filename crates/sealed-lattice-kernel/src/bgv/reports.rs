use serde_json::{Value, json};

use crate::{
    bgv::{
        modular_arithmetic::centered_representative,
        profile::{
            BACKEND_PROFILE_ID, BATCH_ENCODER_ID, BgvBasisKind, CANONICAL_CIPHERTEXT_CONVENTION_ID,
            DATA_PRIMES, OPERATION_REGISTRY_ID, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, PROFILE_ID,
            SPECIAL_PRIME, allowed_operation_registry_digest, allowed_operation_registry_value,
            backend_profile_digest, batch_encoder_digest, canonical_ciphertext_convention_digest,
            data_basis_modulus_bits, data_prime_bit_length, extended_basis_modulus_bits,
            layout_digest, profile_digest, security_estimator_input_digest, selected_profile_value,
        },
        serialization::canonical_bytes_hash,
    },
    encoding::CanonicalResult,
    hashing::derive_protocol_digest,
};

pub(crate) fn describe_profile_report() -> CanonicalResult<Value> {
    let profile_digest = profile_digest()?;
    let backend_profile_digest = backend_profile_digest()?;
    let batch_encoder_digest = batch_encoder_digest()?;
    let layout_digest = layout_digest()?;
    let canonical_ciphertext_convention_digest = canonical_ciphertext_convention_digest()?;
    let allowed_operation_registry_digest = allowed_operation_registry_digest()?;
    let estimator_input_digest = security_estimator_input_digest()?;

    Ok(json!({
        "profile": selected_profile_value(),
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "batchEncoderDigest": batch_encoder_digest,
        "targetBasisDataLayoutDigest": layout_digest,
        "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest,
        "securityEstimatorInputDigest": estimator_input_digest,
        "basisReports": [
            basis_report(BgvBasisKind::Data)?,
            basis_report(BgvBasisKind::Extended)?,
            basis_report(BgvBasisKind::Special)?
        ],
        "statusLabels": [
            "BgvRnsBackendImplementationEvidence",
            "SealedLatticeRustWasmOwned",
            "ReferenceOracleDevelopmentOnly"
        ],
        "nonClaims": [
            "PassiveSetupNotImplemented",
            "EncryptedAggregateBridgeProofNotImplemented",
            "EncryptedTopKEvaluatorNotImplemented",
            "EvaluationProofNotClosed",
            "CPADNotImplemented",
            "SupportedPhoneNotCertified"
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

pub(crate) fn backend_workbook_report() -> CanonicalResult<Value> {
    let profile_digest = profile_digest()?;
    let workbook_value = json!({
        "workbookId": "bgv-rns-backend-workbook-v1",
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "profileDigest": profile_digest,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "dataPrimeCount": DATA_PRIMES.len(),
        "dataPrimeBitLength": data_prime_bit_length(),
        "specialPrimeCount": 1,
        "totalModulusBitsAtFullDataLevel": data_basis_modulus_bits(),
        "totalModulusBitsAtExtendedLevel": extended_basis_modulus_bits(),
        "securityEstimatorInputDigest": security_estimator_input_digest()?,
        "noiseBudgetHook": {
            "status": "hook-only-for-setup-bridge-evaluator",
            "owner": "sealed-lattice-rust-wasm",
            "mustBindProfileDigest": true
        },
        "referenceOracleBoundary": {
            "lattigoRuntimeDependency": false,
            "dockerOracleEvidenceAcceptedAsTranscriptObject": false,
            "oracleVectorsAcceptedAsProtocolEvidence": false
        },
        "aggregateDerivationToBgvInputContract": {
            "sourceProtocolComponent": "aggregate-derivation-component",
            "bridgePath": "EncryptedAggregateBridge-v1",
            "inputWitnessCustody": "each contributor keeps aggregate witness private",
            "targetBasisDataLayoutId": "encrypted-aggregate-target-basis-data-layout-v1",
            "targetBasisDataLayoutDigest": layout_digest()?,
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
        "workbook": workbook_value,
        "workbookDigest": derive_protocol_digest("HEParamDigest", &workbook_value)?,
        "workbookCanonicalBytesHash512": canonical_bytes_hash(
            serde_json::to_string(&workbook_value)
                .expect("workbook report should serialize")
                .as_bytes()
        ),
        "statusLabels": [
            "WorkbookReportEmitted",
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
