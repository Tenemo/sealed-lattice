use super::*;

fn expected_relinearization_key_switch_component_polynomial_count() -> CanonicalResult<u64> {
    scheduled_relinearization_levels()?
        .into_iter()
        .try_fold(0_u64, |total, level| {
            let digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "relinearization level overflowed while deriving HE certificate accounting",
                )
            })?;
            let component_polynomial_count =
                digit_count.checked_mul(digit_count).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "relinearization component polynomial count overflowed",
                    )
                })?;
            total
                .checked_add(component_polynomial_count)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "relinearization key polynomial count overflowed",
                    )
                })
        })
}

fn expected_galois_key_switch_component_polynomial_count() -> CanonicalResult<u64> {
    expected_required_galois_key_schedule()?
        .as_array()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "required Galois key schedule must be an array",
            )
        })?
        .iter()
        .try_fold(0_u64, |total, schedule_entry| {
            let level = value_u64(schedule_entry, "level")?;
            let digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "Galois key level overflowed while deriving HE certificate accounting",
                )
            })?;
            let component_polynomial_count =
                digit_count.checked_mul(digit_count).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "Galois component polynomial count overflowed",
                    )
                })?;
            total
                .checked_add(component_polynomial_count)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "Galois key polynomial count overflowed",
                    )
                })
        })
}

pub(super) fn verify_commitment_security_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(commitment_certificate) = setup_package.get("setupCommitmentSecurityCertificate")
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupCommitmentSecurityCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !commitment_certificate.is_object() {
        return Ok(Some(setup_commitment_certificate_refusal(
            "commitmentSecurityCertificateNotObject",
            "setupCommitmentSecurityCertificate must be a root-bound object",
            "setupPackage.setupCommitmentSecurityCertificate",
        )?));
    }

    let certificate_hash = commitment_certificate
        .get("setupCommitmentSecurityCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash",
    )?;

    let mut certificate_body = commitment_certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("commitment certificate object was checked")
        .remove("setupCommitmentSecurityCertificateHash");
    let expected_body = setup_commitment_security_certificate_value()?;
    if certificate_body != expected_body {
        return Ok(Some(setup_commitment_certificate_refusal(
            "commitmentSecurityCertificatePayloadMismatch",
            "setupCommitmentSecurityCertificate does not match the accepted commitment profile certificate",
            "setupPackage.setupCommitmentSecurityCertificate",
        )?));
    }

    let expected_certificate_hash = setup_commitment_security_certificate_hash()?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(setup_commitment_certificate_refusal(
            "commitmentSecurityCertificateHashMismatch",
            "setupCommitmentSecurityCertificateHash does not match the canonical commitment security certificate",
            "setupPackage.setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash",
        )?));
    }

    Ok(None)
}

fn setup_commitment_security_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupCommitmentSecurityCertificateHash",
        &setup_commitment_security_certificate_value()?,
    )
}

pub(super) fn setup_commitment_security_certificate_with_hash_value() -> CanonicalResult<Value> {
    let mut certificate = setup_commitment_security_certificate_value()?;
    certificate
        .as_object_mut()
        .expect("setup commitment security certificate is an object")
        .insert(
            "setupCommitmentSecurityCertificateHash".to_string(),
            json!(setup_commitment_security_certificate_hash()?),
        );

    Ok(certificate)
}

fn setup_commitment_security_certificate_value() -> CanonicalResult<Value> {
    let max_source_message_modulus = DATA_PRIMES.iter().copied().max().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted Q_share prime list must not be empty",
        )
    })?;
    let recipient_scalar_sum = scalar_power_sum(
        FIRST_PROFILE_DECRYPTION_THRESHOLD,
        FIRST_PROFILE_PARTICIPANT_COUNT,
    )?;
    let threshold_scalar_sum = recipient_scalar_sum
        .checked_mul(u128::from(FIRST_PROFILE_PARTICIPANT_COUNT))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment certificate threshold scalar sum overflow",
            )
        })?;
    let recipient_scalar_sum_u64 = u64::try_from(recipient_scalar_sum).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment certificate recipient scalar sum does not fit u64",
        )
    })?;
    let threshold_scalar_sum_u64 = u64::try_from(threshold_scalar_sum).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment certificate threshold scalar sum does not fit u64",
        )
    })?;
    let max_recipient_lifted_coefficient = u128::from(max_source_message_modulus - 1)
        .checked_mul(recipient_scalar_sum)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment certificate recipient lifted coefficient bound overflow",
            )
        })?;
    let max_threshold_lifted_coefficient = u128::from(max_source_message_modulus - 1)
        .checked_mul(threshold_scalar_sum)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment certificate threshold lifted coefficient bound overflow",
            )
        })?;
    let commitment_modulus_product = setup_commitment_modulus_product();
    if BigUint::from(max_threshold_lifted_coefficient) >= commitment_modulus_product {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "commitment modulus product does not cover threshold-share aggregate no-wrap bound",
        ));
    }
    let commitment_modulus_product_bits = setup_commitment_modulus_product_ceil_bits();

    Ok(json!({
        "objectType": SETUP_COMMITMENT_SECURITY_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProfileHash": setup_profile_hash()?,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "qShareHash": q_share_hash()?,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash()?,
        "ringAndMatrixParameters": {
            "coefficientRing": "Z_q[X]/(X^N+1)",
            "ringDegree": POLYNOMIAL_DEGREE,
            "sourceRnsLimbCount": DATA_PRIMES.len(),
            "sourceRnsPrimes": DATA_PRIMES,
            "commitmentModulusLimbs": setup_commitment_modulus_limb_values(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "commitmentModulusProductCeilBits": commitment_modulus_product_bits,
            "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
            "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
            "publicMatrixSource": "full-roster-common-randomness-XOF-unbiased-residue-stream",
            "matrixHashBound": true,
        },
        "freshOpeningDistribution": {
            "distribution": "coefficientwise-centered-ternary",
            "coefficientSet": [-1, 0, 1],
            "infinityNormBound": SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
            "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "rawOpeningExported": false,
            "perCoefficientOpeningExported": false,
        },
        "fullWidthMessageBound": {
            "messageSource": "per-RNS-prime-Shamir-coefficient-ring-element",
            "maxSourceMessageModulus": max_source_message_modulus,
            "maxFreshMessageCoefficientDecimal": (max_source_message_modulus - 1).to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "freshMessageNoWrap": BigUint::from(max_source_message_modulus - 1)
                < commitment_modulus_product,
            "status": "claim-accounting-full-width-per-rns-message-bound-recorded",
        },
        "aggregateOpeningBounds": {
            "shamirCoefficientCount": FIRST_PROFILE_DECRYPTION_THRESHOLD,
            "maximumTrusteePoint": FIRST_PROFILE_PARTICIPANT_COUNT,
            "recipientScalarPowerSumDecimal": recipient_scalar_sum.to_string(),
            "recipientAggregateOpeningInfinityBound": recipient_scalar_sum_u64,
            "maxRecipientLiftedCoefficientDecimal": max_recipient_lifted_coefficient.to_string(),
            "sourceTrusteeCountForThresholdAggregation": FIRST_PROFILE_PARTICIPANT_COUNT,
            "thresholdScalarPowerSumDecimal": threshold_scalar_sum.to_string(),
            "thresholdShareOpeningInfinityBound": threshold_scalar_sum_u64,
            "maxThresholdLiftedCoefficientDecimal": max_threshold_lifted_coefficient.to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "recipientAndThresholdNoWrap": true,
            "boundStatus": "claim-accounting-first-profile-homomorphic-opening-bounds-recorded",
        },
        "multiOpeningLeakage": {
            "recipientAggregateOpeningsArePublic": false,
            "recipientAggregateOpeningsAreMailboxPlaintext": false,
            "maxCorruptRecipientsBeforeThreshold": FIRST_PROFILE_DECRYPTION_THRESHOLD - 1,
            "shamirPolynomialDegree": FIRST_PROFILE_DECRYPTION_THRESHOLD - 1,
            "rawCoefficientOpeningsExported": false,
            "perCoefficientRandomnessExported": false,
            "thresholdBoundary": "recipient-aggregate-openings-and-carry-witnesses-are-private-proof-witnesses",
            "status": "claim-accounting-active-static-threshold-leakage-bound-recorded",
        },
        "bindingAssumption": {
            "assumption": "Module-SIS",
            "boundTarget": "two-valid-openings-to-one-commitment-yield-short-module-SIS-solution",
            "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
            "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "commitmentModulusProductCeilBits": commitment_modulus_product_bits,
            "extractedOpeningInfinityBound": threshold_scalar_sum_u64,
            "estimatorStatus": "repo-owned-module-sis-parameter-accounting-accepted",
        },
        "hidingAssumption": {
            "assumption": "Module-LWE with recipient-hidden proof-witness opening leakage boundary",
            "openingDistribution": "coefficientwise-centered-ternary",
            "publicMatrixDistribution": "hash-derived-uniform-residue-stream",
            "lowEntropySecretHiding": true,
            "statisticalLeakageStatus": "repo-owned-recipient-hidden-aggregate-opening-proof-witness-accounting-accepted",
            "estimatorStatus": "repo-owned-module-lwe-parameter-accounting-accepted",
        },
        "estimatorRows": [
            {
                "rowId": "first-profile-module-sis-binding-row",
                "problem": "Module-SIS",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
                "modulusCeilBits": commitment_modulus_product_bits,
                "shortVectorInfinityBoundDecimal": threshold_scalar_sum.to_string(),
                "status": "claim-accounting-accepted",
                "accountingBasis": "accepted Module-SIS binding row under FPS25 commitment references and no-wrap threshold-opening bounds"
            },
            {
                "rowId": "first-profile-module-lwe-hiding-row",
                "problem": "Module-LWE",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
                "secretDistribution": "centered-ternary-opening",
                "modulusCeilBits": commitment_modulus_product_bits,
                "status": "claim-accounting-accepted",
                "accountingBasis": "accepted Module-LWE hiding row under FPS25/ACC18 references and recipient-hidden opening leakage boundary"
            }
        ],
    }))
}

fn scalar_power_sum(coefficient_count: u64, trustee_point: u64) -> CanonicalResult<u128> {
    let mut scalar_sum = 0_u128;
    let mut trustee_power = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for coefficient_index in 0..coefficient_count {
        scalar_sum = scalar_sum.checked_add(trustee_power).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment certificate scalar sum overflow",
            )
        })?;
        if coefficient_index + 1 < coefficient_count {
            trustee_power = trustee_power
                .checked_mul(trustee_point_wide)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "commitment certificate trustee power overflow",
                    )
                })?;
        }
    }

    Ok(scalar_sum)
}

fn setup_commitment_certificate_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn verify_setup_proof_accounting_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(certificate) = setup_package.get("setupProofAccountingCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupProofAccountingCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(setup_proof_accounting_certificate_refusal(
            "setupProofAccountingCertificateNotObject",
            "setupProofAccountingCertificate must be a root-bound object",
            "setupPackage.setupProofAccountingCertificate",
        )?));
    }

    let certificate_hash = certificate
        .get("setupProofAccountingCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupProofAccountingCertificate.setupProofAccountingCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "setupProofAccountingCertificate.setupProofAccountingCertificateHash",
    )?;

    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("setup proof accounting certificate object was checked")
        .remove("setupProofAccountingCertificateHash");
    let expected_body = setup_proof_accounting_certificate_value()?;
    if certificate_body != expected_body {
        return Ok(Some(setup_proof_accounting_certificate_refusal(
            "setupProofAccountingCertificatePayloadMismatch",
            "setupProofAccountingCertificate does not match the accepted setup proof accounting certificate",
            "setupPackage.setupProofAccountingCertificate",
        )?));
    }

    let expected_certificate_hash = setup_proof_accounting_certificate_hash()?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(setup_proof_accounting_certificate_refusal(
            "setupProofAccountingCertificateHashMismatch",
            "setupProofAccountingCertificateHash does not match the canonical setup proof accounting certificate",
            "setupPackage.setupProofAccountingCertificate.setupProofAccountingCertificateHash",
        )?));
    }

    Ok(None)
}

pub(in crate::bgv::setup) fn setup_proof_accounting_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        SETUP_PROOF_ACCOUNTING_CERTIFICATE_HASH_NAMESPACE,
        &setup_proof_accounting_certificate_value()?,
    )
}

pub(super) fn setup_proof_accounting_certificate_with_hash_value() -> CanonicalResult<Value> {
    let mut certificate = setup_proof_accounting_certificate_value()?;
    certificate
        .as_object_mut()
        .expect("setup proof accounting certificate is an object")
        .insert(
            "setupProofAccountingCertificateHash".to_string(),
            json!(setup_proof_accounting_certificate_hash()?),
        );

    Ok(certificate)
}

fn setup_proof_family_accounting_value() -> CanonicalResult<Value> {
    use crate::bgv::setup::trustee_evaluation_key_proof::{
        succinct_evaluation_key_proof_accounting_hash, succinct_private_vss_share_accounting_hash,
        succinct_public_key_share_accounting_hash,
        succinct_same_secret_linkage_anchor_accounting_hash,
    };

    Ok(json!([
        {
            "proofFamily": "vss-opening-carry",
            "claimAccounting": {
                "accountingHash": succinct_private_vss_share_accounting_hash()?,
            },
        },
        {
            "proofFamily": "same-secret-linkage-anchor",
            "claimAccounting": {
                "accountingHash": succinct_same_secret_linkage_anchor_accounting_hash()?,
            },
        },
        {
            "proofFamily": "public-key-share",
            "claimAccounting": {
                "accountingHash": succinct_public_key_share_accounting_hash()?,
            },
        },
        {
            "proofFamily": "trustee-evaluation-key",
            "claimAccounting": {
                "accountingHash": succinct_evaluation_key_proof_accounting_hash()?,
            },
        },
    ]))
}

fn setup_proof_succinct_transport_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofSuccinctTransportAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
    }))
}
fn setup_proof_fiat_shamir_transcript_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofFiatShamirTranscriptAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "familyAccountingHashes": {
            "sameSecretLinkageAnchor": crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_hash()?,
            "publicKeyShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
            "privateVssShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
            "trusteeEvaluationKey": crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
        },
        "challengeBinding": "each succinct proof statement hash, proof family label, binding roots, Merkle transcript, low-degree transcript, and challenge-extension sampling rule is recorded inside the bound family accounting object",
    }))
}
fn setup_proof_theorem_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofTheoremAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamilies": [
            "same-secret-linkage-anchor",
            "public-key-share",
            "vss-opening-carry",
            "trustee-evaluation-key"
        ],
        "familyAccounting": {
            "sameSecretLinkageAnchor": crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_value()?,
            "publicKeyShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_public_key_share_accounting_value()?,
            "privateVssShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_value()?,
            "trusteeEvaluationKey": crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_value()?,
        },
    }))
}
fn setup_proof_succinct_leakage_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofSuccinctLeakageAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "familyAccountingHashes": {
            "sameSecretLinkageAnchor": crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_hash()?,
            "publicKeyShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
            "privateVssShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
            "trusteeEvaluationKey": crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
        },
    }))
}
pub(in crate::bgv::setup) fn setup_proof_accounting_certificate_value() -> CanonicalResult<Value> {
    let setup_proof_record_binding = setup_proof_record_binding_value()?;

    Ok(json!({
        "objectType": SETUP_PROOF_ACCOUNTING_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProfileHash": setup_profile_hash()?,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "setupProofRecordBinding": setup_proof_record_binding,
        "setupProofRecordBindingHash": setup_proof_record_binding_hash()?,
        "proofFamilies": ACCEPTED_SETUP_SUCCINCT_PROOF_FAMILIES,
        "proofFamilyAccounting": setup_proof_family_accounting_value()?,
        "sameSecretLinkageAnchorProofAccounting":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_value()?,
        "sameSecretLinkageAnchorProofAccountingHash":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_hash()?,
        "trusteeEvaluationKeyProofAccounting":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_value()?,
        "trusteeEvaluationKeyProofAccountingHash":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
        "publicKeyShareProofAccounting":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_public_key_share_accounting_value()?,
        "publicKeyShareProofAccountingHash":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
        "succinctTransportAccounting": setup_proof_succinct_transport_accounting_value()?,
        "succinctLeakageAccounting": setup_proof_succinct_leakage_accounting_value()?,
        "fiatShamirTranscriptAccounting": setup_proof_fiat_shamir_transcript_accounting_value()?,
        "proofTheoremAccounting": setup_proof_theorem_accounting_value()?,
    }))
}

fn setup_proof_record_binding_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        SETUP_PROOF_RECORD_BINDING_HASH_NAMESPACE,
        &setup_proof_record_binding_value()?,
    )
}

fn setup_proof_accounting_certificate_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn verify_setup_key_correctness_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    if !setup_package_requires_setup_key_correctness_certificate(setup_package) {
        return Ok(None);
    }

    let Some(certificate) = setup_package.get("setupKeyCorrectnessCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupKeyCorrectnessCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(setup_key_correctness_certificate_refusal(
            "setupKeyCorrectnessCertificateNotObject",
            "setupKeyCorrectnessCertificate must be a root-bound object",
            "setupPackage.setupKeyCorrectnessCertificate",
        )?));
    }

    let certificate_hash = certificate
        .get("setupKeyCorrectnessCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash",
    )?;

    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("setup key correctness certificate object was checked")
        .remove("setupKeyCorrectnessCertificateHash");
    let expected_body = setup_key_correctness_certificate_value(setup_package)?;
    if certificate_body != expected_body {
        return Ok(Some(setup_key_correctness_certificate_refusal(
            "setupKeyCorrectnessCertificatePayloadMismatch",
            "setupKeyCorrectnessCertificate does not match the accepted setup key correctness certificate",
            "setupPackage.setupKeyCorrectnessCertificate",
        )?));
    }

    let expected_certificate_hash = setup_key_correctness_certificate_hash(setup_package)?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(setup_key_correctness_certificate_refusal(
            "setupKeyCorrectnessCertificateHashMismatch",
            "setupKeyCorrectnessCertificateHash does not match the canonical setup key correctness certificate",
            "setupPackage.setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash",
        )?));
    }

    Ok(None)
}

pub(super) fn setup_package_requires_setup_key_correctness_certificate(
    setup_package: &Value,
) -> bool {
    setup_package
        .get("evaluationKeys")
        .and_then(Value::as_object)
        .is_some_and(|evaluation_keys| !evaluation_keys.is_empty())
}

pub(in crate::bgv::setup) fn setup_key_correctness_certificate_hash(
    setup_package: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        SETUP_KEY_CORRECTNESS_CERTIFICATE_HASH_NAMESPACE,
        &setup_key_correctness_certificate_value(setup_package)?,
    )
}

pub(in crate::bgv::setup) fn setup_key_correctness_certificate_value(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before setup key correctness certificate verification",
        )
    })?;
    let collective_public_key_root = package_nested_hash(
        setup_package,
        "collectivePublicKey",
        "collectivePublicKeyRoot",
    )?;
    let public_key_share_material_set_root = package_nested_hash(
        setup_package,
        "publicKeyShareMaterial",
        "publicKeyShareMaterialSetRoot",
    )?;
    let public_key_share_succinct_proof_set_root = package_nested_hash(
        setup_package,
        "publicKeyShareSuccinctProofs",
        "publicKeyShareSuccinctProofSetRoot",
    )?;

    Ok(json!({
        "objectType": SETUP_KEY_CORRECTNESS_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(setup_context, "carryAwareVssShareRelationProfileHash")?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "setupProofProfileBinding": "fixed-setup-proof-profile-bound-by-setup-proof-accounting-certificate",
        "keyCorrectnessScope": "collective-public-key-and-public-evaluation-key-roots-derived-from-proof-bearing-setup-records",
        "keyCorrectnessTheorem": {
            "activeMaliciousPrototypeBoundary": "malformed roots, reordered trustee records, stale schedules, missing proof material, inconsistent collective public-key material, and unscheduled evaluation keys are refused before accepted runtime loading",
        },
        "collectivePublicKey": {
            "status": "collective-public-key-coefficients-recomputed-from-public-key-share-material-and-succinct-proof-roots",
            "collectivePublicKeyRoot": collective_public_key_root,
            "sourceRoots": {
                "publicKeyShareSetRoot": package_nested_hash(setup_package, "publicKeyShares", "publicKeyShareSetRoot")?,
                "publicKeyShareProofSetRoot": package_nested_hash(setup_package, "publicKeyShareProofs", "publicKeyShareProofSetRoot")?,
                "publicKeyShareMaterialSetRoot": public_key_share_material_set_root,
                "publicKeyShareSuccinctProofSetRoot": public_key_share_succinct_proof_set_root,
            }
        },
        "publicEvaluationKeys": {
            "status": "public-evaluation-key-roots-recomputed-from-frozen-schedule-and-proof-bearing-relinearization-and-galois-records",
            "evaluationKeySetHash": package_nested_hash(setup_package, "evaluationKeys", "evaluationKeySetHash")?,
            "evaluatorKeyScheduleRoot": package_nested_hash(setup_package, "evaluatorKeySchedule", "evaluatorKeyScheduleRoot")?,
            "relinearizationKeyShareRoundsRoot": package_nested_hash(setup_package, "relinearizationKeyShareRounds", "relinearizationKeyShareRoundsRoot")?,
            "galoisKeyShareBatchRoots": setup_key_correctness_galois_batch_roots(setup_package)?,
            "requiredGaloisSetHash": package_nested_hash(setup_package, "evaluatorKeySchedule", "requiredGaloisSetHash")?,
        },
        "certificateDependencies": {
            "setupProofAccountingCertificateHash": value_string(setup_package, "setupProofAccountingCertificateHash")?,
            "heSecurityCertificateHash": value_string(setup_package, "heSecurityCertificateHash")?,
        },
    }))
}

pub(super) fn verify_active_static_setup_theorem_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(certificate) = setup_package.get("activeStaticSetupTheoremCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["activeStaticSetupTheoremCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(active_static_setup_theorem_certificate_refusal(
            "activeStaticSetupTheoremCertificateNotObject",
            "activeStaticSetupTheoremCertificate must be a root-bound object",
            "setupPackage.activeStaticSetupTheoremCertificate",
        )?));
    }

    let certificate_hash = certificate
        .get("activeStaticSetupTheoremCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash",
    )?;

    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("active-static setup theorem certificate object was checked")
        .remove("activeStaticSetupTheoremCertificateHash");
    let expected_body = active_static_setup_theorem_certificate_value(setup_package)?;
    if certificate_body != expected_body {
        return Ok(Some(active_static_setup_theorem_certificate_refusal(
            "activeStaticSetupTheoremCertificatePayloadMismatch",
            "activeStaticSetupTheoremCertificate does not match the accepted active-static setup theorem certificate",
            "setupPackage.activeStaticSetupTheoremCertificate",
        )?));
    }

    let expected_certificate_hash = active_static_setup_theorem_certificate_hash(setup_package)?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(active_static_setup_theorem_certificate_refusal(
            "activeStaticSetupTheoremCertificateHashMismatch",
            "activeStaticSetupTheoremCertificateHash does not match the canonical active-static setup theorem certificate",
            "setupPackage.activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash",
        )?));
    }

    Ok(None)
}

pub(in crate::bgv::setup) fn active_static_setup_theorem_certificate_hash(
    setup_package: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_HASH_NAMESPACE,
        &active_static_setup_theorem_certificate_value(setup_package)?,
    )
}

pub(in crate::bgv::setup) fn active_static_setup_theorem_certificate_value(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before active-static setup theorem certificate verification",
        )
    })?;
    let roster = super::accepted_roster_from_setup_context(setup_context);

    Ok(json!({
        "objectType": ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(setup_context, "carryAwareVssShareRelationProfileHash")?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "adversaryModel": {
            "secretConfidentialityCorruptTrusteeBound": roster.decryption_threshold - 1,
            "fullRosterSetupCompletionRequired": true,
        },
        "livenessModel": {
            "model": "secure-with-abort",
            "setupCompletionQuorum": roster.setup_completion_quorum,
            "participantCount": roster.participant_count,
        },
        "dependencyHashes": {
            "setupCommitmentSecurityCertificateHash": required_top_level_hash_value(
                setup_package,
                "setupCommitmentSecurityCertificateHash",
            )?,
            "setupTransportCertificateHash": required_top_level_hash_value(
                setup_package,
                "setupTransportCertificateHash",
            )?,
            "setupProofAccountingCertificateHash": required_top_level_hash_value(
                setup_package,
                "setupProofAccountingCertificateHash",
            )?,
            "heSecurityCertificateHash": required_top_level_hash_value(
                setup_package,
                "heSecurityCertificateHash",
            )?,
            "setupKeyCorrectnessCertificateHash": optional_top_level_hash_value(
                setup_package,
                "setupKeyCorrectnessCertificateHash",
            )?,
        },
        "terminalRoots": {
            "thresholdShareCommitmentRoot": optional_top_level_hash_value(
                setup_package,
                "thresholdShareCommitmentRoot",
            )?,
            "sameSecretProofSetRoot": optional_nested_hash_value(
                setup_package,
                "sameSecretProofs",
                "sameSecretProofSetRoot",
            )?,
            "publicKeyShareMaterialSetRoot": optional_nested_hash_value(
                setup_package,
                "publicKeyShareMaterial",
                "publicKeyShareMaterialSetRoot",
            )?,
            "publicKeyShareSuccinctProofSetRoot": optional_nested_hash_value(
                setup_package,
                "publicKeyShareSuccinctProofs",
                "publicKeyShareSuccinctProofSetRoot",
            )?,
            "collectivePublicKeyRoot": optional_nested_hash_value(
                setup_package,
                "collectivePublicKey",
                "collectivePublicKeyRoot",
            )?,
            "evaluatorKeyScheduleRoot": optional_nested_hash_value(
                setup_package,
                "evaluatorKeySchedule",
                "evaluatorKeyScheduleRoot",
            )?,
            "evaluationKeySetHash": optional_nested_hash_value(
                setup_package,
                "evaluationKeys",
                "evaluationKeySetHash",
            )?,
            "publicEvaluationKeyMaterialRoot": optional_nested_hash_value(
                setup_package,
                "evaluationKeys",
                "publicEvaluationKeyMaterialRoot",
            )?,
        },
        "claimBoundary": {
            "remainingDependencies": [],
            "integrationDependencies": [],
        },
    }))
}

fn required_top_level_hash_value(
    setup_package: &Value,
    field_name: &str,
) -> CanonicalResult<Value> {
    let hash_value = value_string(setup_package, field_name)?;
    validate_hash_string(hash_value, field_name)?;

    Ok(json!(hash_value))
}

fn optional_top_level_hash_value(
    setup_package: &Value,
    field_name: &str,
) -> CanonicalResult<Value> {
    optional_hash_value(setup_package.get(field_name), field_name)
}

pub(super) fn optional_nested_hash_value(
    setup_package: &Value,
    object_field_name: &str,
    hash_field_name: &str,
) -> CanonicalResult<Value> {
    let Some(object_value) = setup_package.get(object_field_name) else {
        return Ok(Value::Null);
    };
    optional_hash_value(
        object_value.get(hash_field_name),
        &format!("setupPackage.{object_field_name}.{hash_field_name}"),
    )
}

fn optional_hash_value(value: Option<&Value>, field_path: &str) -> CanonicalResult<Value> {
    let Some(value) = value else {
        return Ok(Value::Null);
    };
    let Some(hash_value) = value.as_str() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_path} must be a string when present"),
        ));
    };
    validate_hash_string(hash_value, field_path)?;

    Ok(json!(hash_value))
}

fn active_static_setup_theorem_certificate_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn package_nested_hash(
    setup_package: &Value,
    object_field_name: &str,
    hash_field_name: &str,
) -> CanonicalResult<String> {
    setup_package
        .get(object_field_name)
        .and_then(|object| object.get(hash_field_name))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("setupPackage.{object_field_name}.{hash_field_name} is required"),
            )
        })
}

fn setup_key_correctness_galois_batch_roots(setup_package: &Value) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches were required before setup key correctness certificate verification",
            )
        })?;
    batches
        .iter()
        .map(|batch| {
            Ok(json!({
                "trusteeIdentity": value_string(batch, "trusteeIdentity")?,
                "trusteeRosterPosition": value_u64(batch, "trusteeRosterPosition")?,
                "galoisKeyShareBatchRoot": value_string(batch, "galoisKeyShareBatchRoot")?,
            }))
        })
        .collect()
}

fn setup_key_correctness_certificate_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn verify_he_security_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(certificate) = setup_package.get("heSecurityCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["heSecurityCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(he_security_certificate_refusal(
            "heSecurityCertificateNotObject",
            "heSecurityCertificate must be a root-bound object",
            "setupPackage.heSecurityCertificate",
        )?));
    }
    let certificate_hash = certificate
        .get("heSecurityCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "heSecurityCertificate.heSecurityCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "heSecurityCertificate.heSecurityCertificateHash",
    )?;
    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("HE security certificate object was checked")
        .remove("heSecurityCertificateHash");
    let expected_body = accepted_he_security_certificate_value()?;
    if certificate_body != expected_body {
        return Ok(Some(he_security_certificate_refusal(
            "heSecurityCertificateMismatch",
            "heSecurityCertificate does not match the accepted direct evaluator replay security certificate",
            "setupPackage.heSecurityCertificate",
        )?));
    }
    let expected_hash = accepted_he_security_certificate_hash()?;
    if certificate_hash != expected_hash {
        return Ok(Some(he_security_certificate_refusal(
            "heSecurityCertificateHashMismatch",
            "heSecurityCertificateHash does not match the canonical HE security certificate",
            "setupPackage.heSecurityCertificate.heSecurityCertificateHash",
        )?));
    }

    Ok(None)
}

pub(in crate::bgv::setup) fn accepted_he_security_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BGVHeSecurityCertificateHash",
        &accepted_he_security_certificate_value()?,
    )
}

pub(super) fn accepted_he_security_certificate_with_hash_value() -> CanonicalResult<Value> {
    let mut certificate = accepted_he_security_certificate_value()?;
    certificate
        .as_object_mut()
        .expect("HE security certificate is an object")
        .insert(
            "heSecurityCertificateHash".to_string(),
            json!(accepted_he_security_certificate_hash()?),
        );

    Ok(certificate)
}

pub(in crate::bgv::setup) fn accepted_he_security_certificate_value() -> CanonicalResult<Value> {
    let largest_exposed_modulus_bits = data_basis_modulus_bits();
    let extended_basis_bits = extended_basis_modulus_bits();
    let post_quantum_max_logq = 827_usize;
    let classical_max_logq = 881_usize;
    let required_galois_key_count = expected_required_galois_key_schedule()?
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    let scheduled_relinearization_level_count = expected_relinearization_level_schedule()
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    let accepted_relinearization_key_polynomials =
        expected_relinearization_key_switch_component_polynomial_count()?;
    let accepted_galois_key_polynomials = expected_galois_key_switch_component_polynomial_count()?;

    Ok(json!({
        "objectType": HE_SECURITY_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "setupProfileHash": setup_profile_hash()?,
        "qShareHash": q_share_hash()?,
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "evaluatorKeyScheduleProfileHash": evaluator_key_schedule_profile_hash()?,
        "assessedRing": {
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "dataBasisId": BgvBasisKind::Data.basis_id(),
            "dataPrimeCount": DATA_PRIMES.len(),
            "dataPrimeProductDecimal": modulus_product_decimal(DATA_PRIMES.iter().copied()),
            "dataPrimeCeilLog2Product": largest_exposed_modulus_bits,
            "qSharePrimeCount": DATA_PRIMES.len(),
            "qSharePrimeProductDecimal": modulus_product_decimal(DATA_PRIMES.iter().copied()),
            "qShareCeilLog2Product": largest_exposed_modulus_bits,
            "specialPrime": SPECIAL_PRIME,
            "extendedUtilityCeilLog2Product": extended_basis_bits,
            "largestExposedBasisClass": "Q_data",
            "largestExposedModulusBits": largest_exposed_modulus_bits
        },
        "secretDistribution": {
            "distributionKind": "standard-ternary-collective-secret",
            "support": [-1, 0, 1],
            "isPlainDenseTernary": true,
            "estimatorModel": "HE-standard-ternary",
            "source": "recipient-verified-VSS same-secret commitments"
        },
        "errorDistribution": {
            "distributionKind": "centered-binomial-eta2",
            "support": [-2, -1, 0, 1, 2],
            "keySwitchNoiseDistribution": "centered-binomial-eta2"
        },
        "publicSampleAccounting": {
            "publicKeyCrpPolynomials": 1,
            "publicKeyShareCount": FIRST_PROFILE_PARTICIPANT_COUNT,
            "acceptedRelinearizationKeyPolynomials": accepted_relinearization_key_polynomials,
            "acceptedGaloisKeyPolynomials": accepted_galois_key_polynomials,
            "scheduledRelinearizationLevelCount": scheduled_relinearization_level_count,
            "scheduledGaloisKeyCount": required_galois_key_count
        },
        "standardRows": {
            "postQuantumTernary128": {
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
            "tool": "HE-standard published parameter table",
            "toolVersion": "ACC18 local text reference",
            "securityEstimatorInputHash": security_estimator_input_hash()?,
            "secretModel": "standard-ternary",
            "errorModel": "centered-binomial-eta2",
            "largestExposedModulusBits": largest_exposed_modulus_bits,
            "publicSamplesBound": true
        },
        "targetDecryptionStatus": {
            "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID
        }
    }))
}

fn modulus_product_decimal(moduli: impl IntoIterator<Item = u64>) -> String {
    let mut product = BigUint::from(1_u8);
    for modulus in moduli {
        product *= BigUint::from(modulus);
    }

    product.to_str_radix(10)
}

fn he_security_certificate_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
