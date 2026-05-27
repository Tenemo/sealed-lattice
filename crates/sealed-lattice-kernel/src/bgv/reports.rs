use serde_json::{Value, json};

use crate::{
    bgv::{
        modular_arithmetic::{add_mod, centered_representative, mul_mod, sub_mod},
        profile::{
            BACKEND_PROFILE_ID, BATCH_ENCODER_ID, BgvBasisKind, CANONICAL_CIPHERTEXT_CONVENTION_ID,
            DATA_PRIMES, OPERATION_REGISTRY_ID, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, PROFILE_ID,
            SPECIAL_PRIME, aggregate_input_encoding_profile_digest,
            allowed_operation_registry_digest, allowed_operation_registry_value,
            backend_profile_digest, ballot_score_encoding_profile_digest,
            ballot_share_layout_profile_digest, batch_encoder_digest, batch_layout_binding_digest,
            batch_layout_binding_value, canonical_ciphertext_convention_digest,
            data_basis_modulus_bits, data_prime_bit_length, encoded_aggregate_layout_digest,
            extended_basis_modulus_bits, layout_digest, profile_digest,
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
    let big_integer_reference_vectors = big_integer_reference_vectors()?;
    let big_integer_reference_vector_root =
        derive_protocol_digest("ReferenceOracleVectorRoot", &big_integer_reference_vectors)?;

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
        "bigIntegerReferenceVectors": big_integer_reference_vectors,
        "bigIntegerReferenceVectorRoot": big_integer_reference_vector_root,
        "basisReports": [
            basis_report(BgvBasisKind::Data)?,
            basis_report(BgvBasisKind::Extended)?,
            basis_report(BgvBasisKind::Special)?
        ],
        "statusLabels": [
            "M7ImplementationEvidence",
            "M8PassiveSetupCommandAvailable",
            "SealedLatticeRustWasmOwned",
            "ReferenceOracleDevelopmentOnly"
        ],
        "nonClaims": [
            "ActiveMaliciousSetupNotImplemented",
            "FinalAppendixBPendingQTarget",
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
        "forbiddenOperationRejectionFixtures": [
            bgv_profile_rejection_fixture(
                "validateBgvEvaluatorOperation",
                "ForbiddenEvaluatorOperation",
                "scalarDegree360Comparator is excluded from the selected M7 operation registry"
            ),
            bgv_profile_rejection_fixture(
                "validateBgvEvaluatorOperation",
                "ForbiddenEvaluatorOperation",
                "uncertifiedScoreBitDerivationOperation is excluded until a certified evaluator subprofile exists"
            ),
            bgv_profile_rejection_fixture(
                "validateBgvEvaluatorOperation",
                "UncertifiedEvaluatorOperation",
                "unlisted evaluator operations are refused by default"
            )
        ],
        "statusLabels": [
            "AllowedOperationsFrozen",
            "GenericFheApiNotExported"
        ],
    }))
}

pub(crate) fn backend_parameter_certificate_report() -> CanonicalResult<Value> {
    let profile_digest = profile_digest()?;
    let data_prime_bits = usize::try_from(data_prime_bit_length()).unwrap_or(0);
    let q_data_bits = data_basis_modulus_bits();
    let qp_public_bits = extended_basis_modulus_bits();
    let parameter_certificate_value = json!({
        "parameterCertificateId": "m7-bgv-rns-backend-parameter-certificate-v1",
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "profileDigest": profile_digest,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "dataPrimeCount": DATA_PRIMES.len(),
        "dataPrimeBitLength": data_prime_bits,
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
                "sampleCountStatus": "available-via-GenerateBgvPassiveSetup"
            },
            "qpPublic": {
                "modulusBits": qp_public_bits,
                "sampleCountStatus": "available-via-GenerateBgvPassiveSetup"
            },
            "target": {
                "modulusBits": null,
                "sampleCountStatus": "pending-Appendix-C-Q-target"
            }
        },
        "secretDistributionCertificate": {
            "status": "available-in-M8-passive-setup-package",
            "sparseOrFixedHammingSecretsRequireSeparateCertification": true
        },
        "errorDistributionCertificate": {
            "status": "available-in-M8-passive-setup-package"
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
        "parameterCertificateDigest": derive_protocol_digest(
            "BGVSetupParameterCertificateDigest",
            &parameter_certificate_value,
        )?,
        "bgvProfileRejectionFixtures": bgv_profile_rejection_fixtures(),
        "conventionDifferenceRegistry": convention_difference_registry(),
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

fn bgv_profile_rejection_fixture(operation: &str, reason_code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "operation": operation,
        "acceptedDigests": [],
        "refusedObjects": [
            {
                "code": "BGVProfileRejected",
                "reasonCode": reason_code,
                "message": message
            }
        ],
        "unresolvedReason": "BGVProfileRejected",
        "statusLabels": [
            "BGVProfileRejected"
        ]
    })
}

fn bgv_profile_rejection_fixtures() -> Vec<Value> {
    vec![
        bgv_profile_rejection_fixture(
            "describeBgvRnsProfile",
            "InvalidParameters",
            "invalid BGV parameter sets are rejected before profile acceptance",
        ),
        bgv_profile_rejection_fixture(
            "generateBgvBackendReport",
            "MissingEstimatorRow",
            "the M7 parameter certificate must contain data, qpPublic, and target estimator rows",
        ),
        bgv_profile_rejection_fixture(
            "validateBgvPlaintextObject",
            "UnsupportedRingDimension",
            "canonical BGV objects must use the selected N = 32768 ring dimension",
        ),
        bgv_profile_rejection_fixture(
            "validateBgvPlaintextObject",
            "InvalidRnsBasis",
            "canonical BGV objects must bind one selected RNS basis and level",
        ),
        bgv_profile_rejection_fixture(
            "validateBgvPlaintextObject",
            "ProfileMismatch",
            "canonical BGV objects must bind the selected profile and encrypted aggregate layout",
        ),
        bgv_profile_rejection_fixture(
            "validateBgvPlaintextObject",
            "InvalidCanonicalEncoding",
            "canonical BGV bytes must parse, reserialize byte-identically, and remain coefficient-domain only",
        ),
    ]
}

fn convention_difference_registry() -> Vec<Value> {
    [
        (
            "coefficientOrdering",
            "coefficient-index-ascending-within-each-rns-limb",
        ),
        ("nttRootDirection", "sealed-lattice-negacyclic-forward-root"),
        (
            "automorphismDirection",
            "sealed-lattice-positive-slot-rotation",
        ),
        ("slotOrdering", "BGVBatchEncode_65537-slot-index-ascending"),
        (
            "plaintextEncodingConvention",
            "inverse-negacyclic-ntt-then-plaintext-lift",
        ),
        (
            "keySwitchDecomposition",
            "not-accepted-in-M7-canonical-objects",
        ),
        (
            "ciphertextComponentOrder",
            "coefficient-domain-c0-then-c1-then-optional-c2",
        ),
    ]
    .into_iter()
    .map(|(dimension, expected_convention)| {
        json!({
            "dimension": dimension,
            "expectedConvention": expected_convention,
            "swappedConventionRejection": bgv_profile_rejection_fixture(
                "validateBgvConventionDifference",
                "ProfileMismatch",
                "convention differences cannot define sealed-lattice transcript roots"
            )
        })
    })
    .collect()
}

fn big_integer_reference_vectors() -> CanonicalResult<Value> {
    let positions = [
        0_usize,
        1,
        2,
        17,
        POLYNOMIAL_DEGREE / 2,
        POLYNOMIAL_DEGREE - 1,
    ];
    let mut vectors = Vec::new();
    for modulus in DATA_PRIMES.into_iter().chain([SPECIAL_PRIME]) {
        let mut samples = Vec::new();
        for position in positions {
            let left = reference_residue(position, 0, modulus);
            let right = reference_residue(position, 17, modulus);
            let expected_addition =
                ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64;
            let expected_subtraction = ((u128::from(left) + u128::from(modulus)
                - u128::from(right))
                % u128::from(modulus)) as u64;
            let expected_multiplication =
                ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64;

            if add_mod(left, right, modulus)? != expected_addition
                || sub_mod(left, right, modulus)? != expected_subtraction
                || mul_mod(left, right, modulus)? != expected_multiplication
            {
                return Err(crate::encoding::CanonicalError::new(
                    crate::encoding::CanonicalErrorCode::FixtureMismatch,
                    "M7 big-integer reference vector disagrees with modular arithmetic",
                ));
            }

            samples.push(json!({
                "position": position,
                "left": left,
                "right": right,
                "addition": expected_addition,
                "subtraction": expected_subtraction,
                "multiplication": expected_multiplication,
            }));
        }
        vectors.push(json!({
            "modulus": modulus,
            "samples": samples,
        }));
    }

    Ok(json!({
        "fixtureId": "m7-rns-big-integer-reference-v1",
        "coefficientSource": "sealed-lattice-canonical-rns-coefficient-material",
        "moduli": DATA_PRIMES.into_iter().chain([SPECIAL_PRIME]).collect::<Vec<_>>(),
        "samplePositions": positions,
        "vectors": vectors,
    }))
}

fn reference_residue(position: usize, offset: usize, modulus: u64) -> u64 {
    let shifted_position = position + offset;
    ((shifted_position * shifted_position + 31 * shifted_position + 7) as u64) % modulus
}

#[cfg(test)]
mod tests {
    use super::{
        backend_parameter_certificate_report, big_integer_reference_vectors,
        describe_profile_report, operation_registry_report,
    };

    #[test]
    fn reports_emit_m7_rejection_and_big_integer_reference_vectors() {
        let profile = describe_profile_report().expect("profile report");
        let vectors = big_integer_reference_vectors().expect("reference vectors");
        assert_eq!(profile["bigIntegerReferenceVectors"], vectors);
        assert_eq!(
            profile["bigIntegerReferenceVectorRoot"],
            "83cb67a77a5c84bf3c3bd98ded3fdb93eef9ee9878df6434c680762d70aceaae6ea94874e3790fcd3caa2d4b1dd124d040b91cadaebf32b8376ef357969d40e6"
        );
        assert_eq!(
            profile["bigIntegerReferenceVectors"]["vectors"]
                .as_array()
                .expect("vectors")
                .len(),
            17
        );
        assert_eq!(
            operation_registry_report().expect("operation registry")["forbiddenOperationRejectionFixtures"]
                [0]["unresolvedReason"],
            "BGVProfileRejected"
        );
        assert!(
            backend_parameter_certificate_report()
                .expect("backend report")["bgvProfileRejectionFixtures"]
                .as_array()
                .expect("rejection fixtures")
                .iter()
                .any(|fixture| fixture["refusedObjects"][0]["reasonCode"] == "MissingEstimatorRow")
        );
        assert_eq!(
            backend_parameter_certificate_report().expect("backend report")["parameterCertificateDigest"],
            "1af357fdb1330b3d0c1c41a8eb97ecc150e847f9ce14eedf039e22b74a4b773d8f1d13d87fab48790289baa3bb0f6a7f2e52bfcec8d0a6849aab7d89e98d2ecd"
        );
    }
}
