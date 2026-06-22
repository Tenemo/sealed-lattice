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
    let package_certificate_hash = setup_package
        .get("setupCommitmentSecurityCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupCommitmentSecurityCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.setupCommitmentSecurityCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(setup_commitment_certificate_refusal(
            "commitmentSecurityPackageCertificateHashMismatch",
            "setupPackage.setupCommitmentSecurityCertificateHash must match setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash",
            "setupPackage.setupCommitmentSecurityCertificateHash",
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
        "certificateScope": "first-profile-BDLOP-commitment-parameters-and-opening-bounds",
        "acceptedUse": [
            "VSS coefficient commitment records",
            "recipient-local private VSS proof witness checks",
            "verifier-derived threshold-share commitment roots",
            "same-secret trustee commitment roots",
        ],
        "nonClosure": [
            "public evaluation-key assembly and setup-package terminal acceptance remain separate from this commitment parameter certificate",
            "profile-scale binary streaming evidence remains separate from this commitment parameter certificate",
            "future target-decryption readiness remains outside this commitment parameter certificate",
        ],
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
            "referenceRows": [
                {
                    "document": "FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting",
                    "localReferencePath": "reference-documents/FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting.txt",
                    "sections": [
                        "BDLOP commitment background",
                        "Module-LWE and Module-SIS definitions"
                    ]
                }
            ],
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
        "certificateStatus": "claim-bearing-setup-commitment-parameter-accounting-accepted",
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
    let package_certificate_hash = setup_package
        .get("setupProofAccountingCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupProofAccountingCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.setupProofAccountingCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(setup_proof_accounting_certificate_refusal(
            "setupProofAccountingPackageCertificateHashMismatch",
            "setupPackage.setupProofAccountingCertificateHash must match setupProofAccountingCertificate.setupProofAccountingCertificateHash",
            "setupPackage.setupProofAccountingCertificateHash",
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
            "claimScope": "recipient-local private VSS share proof relation over accepted Q_share limbs",
            "verifierClosedStatus": "statement-rebuild-and-succinct-argument-checks-verifier-closed",
            "verifierClosedChecks": [
                "every private VSS statement is rebuilt by the recipient verifier from the encrypted envelope AAD hash, accepted VSS coefficient commitments, share values, setup context, and source and recipient identities",
                "canonical proof bytes are hashed, decoded, checked for canonical field elements, and rebound to the statement hash, proof statement root, proof material root, and accepted accounting hash before acceptance",
                "one succinct argument checks all four hidden Shamir coefficient commitment openings and the hidden lifted carry vector over the commitment-modulus fields",
                "the recipient-point lifted share relation sum_k alpha_j^k F_k - q_l * carry = sigma is enforced coefficientwise inside the batched sumcheck",
                "coefficient messages, opening randomness, carry witnesses, and source trustee secret constants remain outside public transcript artifacts",
            ],
            "accountingStatus": "succinct-private-vss-share-theorem-accounting-accepted",
            "claimAccounting": {
                "accountingObject": "SuccinctPrivateVssShareAccounting",
                "accountingHash": succinct_private_vss_share_accounting_hash()?,
                "closedItems": "the relation shape, canonical statement binding, proof-byte decoding, batched low-degree checks, cross-field integer consistency bound, classical Fiat-Shamir transcript rows, achieved-level CMS19 QROM metadata, and family-specific bounded-leakage scope are recorded inside the bound accounting object",
                "claimBoundary": "recipient-local private VSS accounting is accepted only for the succinct family under the named FRI conjecture with achieved-level QROM metadata recorded; QROM strength and 128-bit zero-knowledge are not accepted rows",
            },
        },
        {
            "proofFamily": "same-secret-linkage-anchor",
            "claimScope": "one short trustee secret behind every accepted VSS constant commitment, proven once per trustee by a keyless succinct linkage argument over the commitment-modulus fields",
            "verifierClosedStatus": "statement-rebuild-and-argument-checks-verifier-closed",
            "verifierClosedChecks": [
                "every anchor statement is rebuilt by the verifier from the accepted VSS constant commitments, the accepted public VSS material root, and the ceremony context; no prover-supplied statement field is trusted",
                "the linkage opens the accepted BDLOP constant commitments natively over the commitment-modulus fields against one committed ternary secret with Boolean negative-indicator support",
                "per-limb trace commitments, masked column openings, batched row checks, the batched linear sumcheck, DEEP out-of-domain bindings, and the batched low-degree proof are verified for every commitment-modulus field",
                "cross-limb consistency claims are checked as residues of one shared masked integer per claim, lifted from two limb fields and matched in every other limb",
                "canonical proof bytes are decoded with trailing-byte refusal and rebound to the statement hash recorded in the package",
            ],
            "accountingStatus": "succinct-same-secret-linkage-anchor-theorem-accounting-accepted",
            "claimAccounting": {
                "accountingObject": "SuccinctSameSecretLinkageAnchorAccounting",
                "accountingHash": succinct_same_secret_linkage_anchor_accounting_hash()?,
                "closedItems": "the named-conjecture low-degree bound, the two-prime cross-limb consistency lemma, the simulator argument with its opening-budget margin, the scoped smudging leakage budget, classical round-by-round Fiat-Shamir accounting, and achieved-level CMS19 QROM metadata are recorded inside the bound accounting object; QROM strength and 128-bit zero-knowledge are not accepted rows",
                "claimBoundary": "active-malicious same-secret linkage accounting is accepted only for classical succinct-family soundness under the named FRI conjecture; secret-dependent setup families reference this anchor through the accepted family binding root",
            },
        },
        {
            "proofFamily": "public-key-share",
            "claimScope": "the public-key share of one trustee over every accepted Q_share limb, proven by one succinct argument against the committed trustee secret, one shared centered-binomial error, and the accepted common reference polynomial",
            "verifierClosedStatus": "statement-rebuild-and-argument-checks-verifier-closed",
            "verifierClosedChecks": [
                "every statement is rebuilt by the verifier from the accepted public-key share records, the seed-derived common reference polynomial, the selected accepted limb-zero same-secret constant commitment, the accepted same-secret anchor roots, and the ceremony context; no prover-supplied statement field is trusted",
                "per-limb trace commitments, masked column openings, batched row checks, the batched linear sumcheck, DEEP out-of-domain bindings, and the batched low-degree proof are verified for every Q_share limb field",
                "the share-correctness relation b_l + a_l*s - p*e = 0 is enforced inside the argument over every Q_share limb against one committed ternary secret and one shared centered-binomial error column",
                "one limb-zero constant-commitment linkage opening rebinds the share secret to the accepted same-secret anchor over the commitment-modulus fields; this is sufficient only because the same-secret anchor already proves all accepted Q_share constant commitments open to the same ternary trustee secret",
                "cross-limb consistency claims are checked as residues of one shared masked integer per claim, lifted from two limb fields and matched in every other limb",
                "canonical proof bytes are decoded with trailing-byte refusal and rebound to the statement hash recorded in the package",
            ],
            "accountingStatus": "succinct-public-key-share-theorem-accounting-accepted",
            "claimAccounting": {
                "accountingObject": "SuccinctPublicKeyShareAccounting",
                "accountingHash": succinct_public_key_share_accounting_hash()?,
                "closedItems": "the named-conjecture low-degree bound, the two-prime cross-limb consistency lemma, the simulator argument with its opening-budget margin, the scoped smudging leakage budget, classical round-by-round Fiat-Shamir accounting, and achieved-level CMS19 QROM metadata are recorded inside the bound accounting object; QROM strength and 128-bit zero-knowledge are not accepted rows",
                "claimBoundary": "active-malicious public-key share accounting is accepted only for classical succinct-family soundness under the named FRI conjecture; the share secret is rebound to the same-secret linkage anchor through the accepted family binding root and the limb-zero commitment opening theorem dependency",
            },
        },
        {
            "proofFamily": "trustee-evaluation-key",
            "claimScope": "every scheduled relinearization and Galois key share of one trustee, proven by one batched succinct argument against the committed trustee secret and the recomputed round-one public aggregates",
            "verifierClosedStatus": "statement-rebuild-and-argument-checks-verifier-closed",
            "verifierClosedChecks": [
                "every statement is rebuilt by the verifier from the transported share records, the recomputed round-one public aggregate diagonals, the accepted same-secret constant commitments, and the ceremony context; no prover-supplied statement field is trusted",
                "key-switch component material is decoded against record-bound component vector roots and deterministic public sampler seeds shared by schedule entry",
                "per-limb trace commitments, masked column openings, batched row checks, the digit-and-key-batched linear sumcheck, DEEP out-of-domain bindings, and the batched low-degree proof are verified for every limb field",
                // A Galois/rotation key switches s(X^k) back to s, so its proven source is the automorphism image of the secret, and the rotation amount is the Galois exponent k.
                "arithmetic source relations are enforced inside the argument: round-one sources equal the committed secret, round-two sources equal the secret times the recomputed public aggregate, and Galois sources equal the automorphism image",
                "the same-secret linkage opens the accepted BDLOP constant commitments natively over the commitment-modulus fields against the shared key-relation secret",
                "cross-limb consistency claims are checked as residues of one shared masked integer per claim, lifted from two limb fields and matched in every other limb",
                "canonical proof bytes are decoded with trailing-byte refusal and rebound to the statement hash recorded in the package",
            ],
            "accountingStatus": "succinct-trustee-evaluation-key-theorem-accounting-accepted",
            "claimAccounting": {
                "accountingObject": "SuccinctEvaluationKeyProofAccounting",
                "accountingHash": succinct_evaluation_key_proof_accounting_hash()?,
                "closedItems": "the named-conjecture low-degree bound, the two-prime cross-limb consistency lemma, the simulator argument with its opening-budget margin, the scoped smudging leakage budget, classical round-by-round Fiat-Shamir accounting, and achieved-level CMS19 QROM metadata are recorded inside the bound accounting object; QROM strength and 128-bit zero-knowledge are not accepted rows",
                "claimBoundary": "active-malicious evaluation-key proof accounting is accepted only for classical succinct-family soundness under the named FRI conjecture; ceremony transport, roster binding, and target decryption keep their own gates",
            },
        },
    ]))
}

fn setup_proof_succinct_transport_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofSuccinctTransportAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "succinct-proof-material-roots-and-transport-binding-accepted",
        "closedProofFamilies": [
            "same-secret-linkage-anchor",
            "public-key-share",
            "vss-opening-carry",
            "trustee-evaluation-key"
        ],
        "closedVerifierChecks": [
            "embedded proof bytes bind statement hash, proof size, proof bytes hash, and proof material root",
            "transported proof bytes bind chunk size, chunk count, total byte length, full object hash, chunk root, and chunk hashes",
            "private VSS transported proof material uses the succinct proof material root and carries no relation-commitment or tbox metadata",
            "canonical proof decoding and verifier arithmetic reject malformed proof bytes before accepted setup handoff"
        ],
        "claimBoundary": "proof material transport accounting covers root binding and canonical byte delivery only; each proof family's soundness, leakage, and Fiat-Shamir rows live in its bound succinct accounting object"
    }))
}
fn setup_proof_fiat_shamir_transcript_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofFiatShamirTranscriptAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "succinct-family-fiat-shamir-accounting-bound-with-achieved-qrom-recorded",
        "qromReductionStatus": "computed-cms19-state-restoration-achieved-level-recorded-per-family",
        "qromReductionLossComputed": true,
        "qromAccepted": false,
        "meetsConventional128BitQuantumBar": false,
        "achievedQuantumSoundnessAfterInstanceUnionBitsApproximate": 70,
        "familyAccountingHashes": {
            "sameSecretLinkageAnchor": crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_hash()?,
            "publicKeyShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
            "privateVssShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
            "trusteeEvaluationKey": crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
        },
        "challengeBinding": "each succinct proof statement hash, proof family label, binding roots, Merkle transcript, low-degree transcript, and challenge-extension sampling rule is recorded inside the bound family accounting object",
        "claimBoundary": "the setup accounting certificate binds classical Fiat-Shamir rows and achieved-level CMS19 QROM metadata through the succinct family accounting objects; QROM strength and conventional 128-bit quantum QROM claims remain deferred"
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
        "accountingStatus": "succinct-setup-proof-family-accounting-accepted-achieved-qrom-recorded",
        "familyAccounting": {
            "sameSecretLinkageAnchor": crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_value()?,
            "publicKeyShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_public_key_share_accounting_value()?,
            "privateVssShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_value()?,
            "trusteeEvaluationKey": crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_value()?,
        },
        "acceptedClaimScope": [
            "same-secret linkage anchor relation",
            "public-key share correctness relation",
            "recipient-local private VSS opening and carry relation",
            "trustee evaluation-key schedule relation"
        ],
        "claimBoundary": "accepted only for the listed succinct setup proof families under their bound family accounting objects; achieved-level CMS19 QROM metadata is recorded, but QROM strength and 128-bit zero-knowledge are not accepted rows, and this does not close ballot proofs, evaluator replay, target decryption, supported-phone evidence, production audit readiness, or future proof-system families"
    }))
}
fn setup_proof_succinct_leakage_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofSuccinctLeakageAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "succinct-family-leakage-scope-bound-per-family",
        "familyAccountingHashes": {
            "sameSecretLinkageAnchor": crate::bgv::setup::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_hash()?,
            "publicKeyShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
            "privateVssShare": crate::bgv::setup::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
            "trusteeEvaluationKey": crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
        },
        "zeroKnowledgeScope": "bounded-leakage succinct-family accounting only; the setup certificate does not claim 128-bit zero-knowledge for these families",
        "claimBoundary": "legacy response-mask accounting for non-succinct private VSS records is not terminal setup evidence after the private VSS succinct migration"
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
        "privateVssShareProofAccounting":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_value()?,
        "privateVssShareProofAccountingHash":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
        "succinctTransportAccounting": setup_proof_succinct_transport_accounting_value()?,
        "succinctLeakageAccounting": setup_proof_succinct_leakage_accounting_value()?,
        "fiatShamirTranscriptAccounting": setup_proof_fiat_shamir_transcript_accounting_value()?,
        "proofTheoremAccounting": setup_proof_theorem_accounting_value()?,
        "completionBoundary": "claim-bearing accepted setup is a repo-owned library claim and does not require external validation or a third-party review gate",
        "certificateStatus": "succinct-setup-proof-family-accounting-accepted-achieved-qrom-recorded",
        "claimBoundary": "every bound setup proof family carries accepted classical accounting and achieved-level CMS19 QROM metadata through its succinct-family accounting object under the named FRI conjecture where applicable; QROM strength and 128-bit zero-knowledge are not accepted by this certificate",
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
    let package_certificate_hash = setup_package
        .get("setupKeyCorrectnessCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupKeyCorrectnessCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.setupKeyCorrectnessCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(setup_key_correctness_certificate_refusal(
            "setupKeyCorrectnessPackageCertificateHashMismatch",
            "setupPackage.setupKeyCorrectnessCertificateHash must match setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash",
            "setupPackage.setupKeyCorrectnessCertificateHash",
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
            "theoremStatus": "repo-owned-key-correctness-theorem-accepted-for-verifier-recomputed-roots",
            "claimDependency": "terminal accepted setup verifies these roots before returning the accepted setup handoff",
            "checkedByVerifier": [
                "collective public-key coefficients are recomputed from publicKeyShareMaterial records and verified source roots",
                "collectivePublicKeyRoot is canonical and matches the top-level setup package root",
                "evaluationKeySetHash is canonical and binds the frozen evaluator schedule, relinearization rounds, and Galois batch records",
                "transported public evaluation-key runtime material is verified against evaluationKeys when supplied",
                "generic key-switch material and unscheduled Galois keys are refused for the first profile",
            ],
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
        "claimBoundary": "key-correctness theorem is accepted for verified roots, loaded runtime material, and terminal accepted setup handoff construction",
    }))
}

pub(super) fn verify_setup_assembly_provenance_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(certificate) = setup_package.get("setupAssemblyProvenanceCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupAssemblyProvenanceCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(setup_assembly_provenance_certificate_refusal(
            "setupAssemblyProvenanceCertificateNotObject",
            "setupAssemblyProvenanceCertificate must be a root-bound object",
            "setupPackage.setupAssemblyProvenanceCertificate",
        )?));
    }

    let certificate_hash = certificate
        .get("setupAssemblyProvenanceCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupAssemblyProvenanceCertificate.setupAssemblyProvenanceCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "setupAssemblyProvenanceCertificate.setupAssemblyProvenanceCertificateHash",
    )?;

    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("setup assembly provenance certificate object was checked")
        .remove("setupAssemblyProvenanceCertificateHash");
    let expected_body = setup_assembly_provenance_certificate_value(setup_package)?;
    if certificate_body != expected_body {
        return Ok(Some(setup_assembly_provenance_certificate_refusal(
            "setupAssemblyProvenanceCertificatePayloadMismatch",
            "setupAssemblyProvenanceCertificate does not match the verifier-recomputed setup assembly provenance certificate",
            "setupPackage.setupAssemblyProvenanceCertificate",
        )?));
    }

    let expected_certificate_hash = setup_assembly_provenance_certificate_hash(setup_package)?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(setup_assembly_provenance_certificate_refusal(
            "setupAssemblyProvenanceCertificateHashMismatch",
            "setupAssemblyProvenanceCertificateHash does not match the canonical setup assembly provenance certificate",
            "setupPackage.setupAssemblyProvenanceCertificate.setupAssemblyProvenanceCertificateHash",
        )?));
    }
    let package_certificate_hash = setup_package
        .get("setupAssemblyProvenanceCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupAssemblyProvenanceCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.setupAssemblyProvenanceCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(setup_assembly_provenance_certificate_refusal(
            "setupAssemblyProvenancePackageCertificateHashMismatch",
            "setupPackage.setupAssemblyProvenanceCertificateHash must match setupAssemblyProvenanceCertificate.setupAssemblyProvenanceCertificateHash",
            "setupPackage.setupAssemblyProvenanceCertificateHash",
        )?));
    }

    Ok(None)
}

pub(in crate::bgv::setup) fn setup_assembly_provenance_certificate_hash(
    setup_package: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        SETUP_ASSEMBLY_PROVENANCE_CERTIFICATE_HASH_NAMESPACE,
        &setup_assembly_provenance_certificate_value(setup_package)?,
    )
}

pub(in crate::bgv::setup) fn setup_assembly_provenance_certificate_value(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before setup assembly provenance certificate verification",
        )
    })?;
    let phase_transcript = setup_package.get("phaseTranscript").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "phaseTranscript was required before setup assembly provenance certificate verification",
        )
    })?;
    let phase_transcript_root = derive_protocol_hash("SetupPhaseTranscriptRoot", phase_transcript)?;

    Ok(json!({
        "objectType": SETUP_ASSEMBLY_PROVENANCE_CERTIFICATE_OBJECT_TYPE,
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
        "assemblySource": "integrated-full-roster-setup-package-assembly",
        "assemblySourceStatus": "claim-bearing-setup-source-bound-to-verifier-recomputed-final-record-roots",
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "setupCompletionQuorum": FIRST_PROFILE_SETUP_COMPLETION_QUORUM,
        "sourceBoundary": {
            "acceptedHandoffSource": "accepted-setup-verifier-after-package-hash-certificate-and-final-object-gates",
            "developmentAssemblyAcceptedAsClaimSource": false,
            "helperAssemblyAcceptedAsClaimSource": false,
        },
        "rootBindings": {
            "phaseTranscriptRoot": phase_transcript_root,
            "commonRandomnessRoot": optional_nested_hash_value(
                setup_package,
                "commonRandomness",
                "commonRandomnessRoot",
            )?,
            "vssCoefficientCommitmentRoot": optional_nested_hash_value(
                setup_package,
                "vssCoefficientCommitments",
                "vssCoefficientCommitmentRoot",
            )?,
            "privateVssEnvelopeCommitmentRoot": optional_top_level_hash_value(
                setup_package,
                "privateVssEnvelopeCommitmentRoot",
            )?,
            "vssShareAcceptanceRoot": optional_nested_hash_value(
                setup_package,
                "vssShareAcceptances",
                "vssShareAcceptanceRoot",
            )?,
            "thresholdShareCommitmentRoot": optional_nested_hash_value(
                setup_package,
                "thresholdShareCommitments",
                "thresholdShareCommitmentRoot",
            )?,
            "sameSecretConsistencyRoot": optional_nested_hash_value(
                setup_package,
                "sameSecretConsistency",
                "sameSecretConsistencyRoot",
            )?,
            "publicKeyShareSetRoot": optional_nested_hash_value(
                setup_package,
                "publicKeyShares",
                "publicKeyShareSetRoot",
            )?,
            "publicKeyShareProofSetRoot": optional_nested_hash_value(
                setup_package,
                "publicKeyShareProofs",
                "publicKeyShareProofSetRoot",
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
            "relinearizationKeyShareRoundsRoot": optional_nested_hash_value(
                setup_package,
                "relinearizationKeyShareRounds",
                "relinearizationKeyShareRoundsRoot",
            )?,
            "trusteeEvaluationKeyProofSetRoot": optional_nested_hash_value(
                setup_package,
                "trusteeEvaluationKeyProofs",
                "trusteeEvaluationKeyProofSetRoot",
            )?,
            "evaluationKeySetHash": optional_nested_hash_value(
                setup_package,
                "evaluationKeys",
                "evaluationKeySetHash",
            )?,
        },
        "claimBoundary": "accepted setup handoff construction is sourced from this verifier-recomputed package provenance certificate, not from development assembly or helper paths",
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
    let package_certificate_hash = setup_package
        .get("activeStaticSetupTheoremCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.activeStaticSetupTheoremCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.activeStaticSetupTheoremCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(active_static_setup_theorem_certificate_refusal(
            "activeStaticSetupTheoremPackageCertificateHashMismatch",
            "setupPackage.activeStaticSetupTheoremCertificateHash must match activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash",
            "setupPackage.activeStaticSetupTheoremCertificateHash",
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
    let evaluation_keys_declared = setup_package_declares_public_runtime_material(setup_package);

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
            "corruptionTiming": "active-static",
            "maliciousBehavior": "arbitrary-invalid-public-setup-artifacts-and-abort",
            "secretConfidentialityCorruptTrusteeBound": FIRST_PROFILE_DECRYPTION_THRESHOLD - 1,
            "fullRosterSetupCompletionRequired": true,
        },
        "livenessModel": {
            "model": "secure-with-abort",
            "setupCompletionQuorum": FIRST_PROFILE_SETUP_COMPLETION_QUORUM,
            "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
            "acceptedAbortEvents": [
                "missing required setup phase object",
                "malformed public setup object",
                "invalid private VSS acceptance state",
                "invalid setup proof or proof material root",
                "invalid collective public-key or evaluation-key root",
                "unsupported target-decryption readiness claim",
            ],
            "notClaimed": [
                "guaranteed output delivery",
                "identifiable abort",
                "post-setup target decryption",
                "production audit readiness",
            ],
        },
        "verifiedSetupGates": [
            "setup context and package hash bind the ceremony, roster, manifest, profile, Q_share, commitment profile, and setup epoch",
            "full-roster common randomness commit/reveal records derive public setup matrices before proof and key verification",
            "public VSS coefficient commitments and recipient-local signed acceptances are checked before threshold-share commitment derivation",
            "threshold-share commitment roots are verifier-derived from public VSS commitments, not source-trustee supplied",
            "same-secret, public-key share, relinearization, and Galois proof records are verified before key roots are accepted",
            "collective public-key coefficients and public evaluation-key roots are verifier-recomputed from proof-bearing setup records",
            "setup commitment, proof-accounting, transport, assembly provenance, HE, and key-correctness certificates are root-bound package objects",
            "generic key-switch material, unscheduled Galois keys, raw setup witnesses, raw shares, external aggregate public-key material, and premature target-decryption readiness are refused",
        ],
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
            "setupAssemblyProvenanceCertificateHash": required_top_level_hash_value(
                setup_package,
                "setupAssemblyProvenanceCertificateHash",
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
        "referenceRows": [
            {
                "document": "BCD25_Threshold (Fully) Homomorphic Encryption",
                "localReferencePath": "reference-documents/BCD25_Threshold (Fully) Homomorphic Encryption.txt",
                "sections": [
                    "active-with-abort security model",
                    "static malicious adversaries",
                    "threshold FHE setup and abort boundaries"
                ]
            },
            {
                "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                "sections": [
                    "Fiat-Shamir with aborts",
                    "commit-and-prove simulatability",
                    "knowledge soundness"
                ]
            },
            {
                "document": "BFM25_Threshold FHE with Efficient Asynchronous Decryption",
                "localReferencePath": "reference-documents/BFM25_Threshold FHE with Efficient Asynchronous Decryption.txt",
                "sections": [
                    "malicious participant detection",
                    "setup preprocessing",
                    "abort behavior"
                ]
            }
        ],
        "claimBoundary": {
            "certificateStatus": "active-static-secure-with-abort-theorem-accepted",
            "evaluationKeyCorrectnessStatus": if evaluation_keys_declared {
                "requires-setup-key-correctness-certificate"
            } else {
                "no-public-evaluation-key-runtime-material-declared"
            },
            "remainingDependencies": [],
            "integrationDependencies": [],
            "completionBoundary": "external validation, independent audit, and third-party proof review are not setup completion prerequisites",
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

fn setup_assembly_provenance_certificate_refusal(
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
    let package_certificate_hash = setup_package
        .get("heSecurityCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.heSecurityCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.heSecurityCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(he_security_certificate_refusal(
            "packageHeSecurityCertificateHashMismatch",
            "setupPackage.heSecurityCertificateHash must match heSecurityCertificate.heSecurityCertificateHash",
            "setupPackage.heSecurityCertificateHash",
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
    let post_quantum_accepted = largest_exposed_modulus_bits <= post_quantum_max_logq;
    let classical_accepted = largest_exposed_modulus_bits <= classical_max_logq;
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
        "certificateScope": "first-profile-accepted-setup-direct-evaluator-replay-Q-data-boundary",
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
            "dataPrimeCeilLog2Product": largest_exposed_modulus_bits,
            "qSharePrimeCount": DATA_PRIMES.len(),
            "qSharePrimeProductDecimal": modulus_product_decimal(DATA_PRIMES.iter().copied()),
            "qShareCeilLog2Product": largest_exposed_modulus_bits,
            "specialPrime": SPECIAL_PRIME,
            "extendedUtilityCeilLog2Product": extended_basis_bits,
            "extendedUtilityExposureStatus": "not-exposed-by-current-accepted-direct-evaluator-replay-material",
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
            "keySwitchNoiseDistribution": "centered-binomial-eta2",
            "certificateStatus": "accepted-for-direct-evaluator-replay-HE-parameter-boundary"
        },
        "publicSampleAccounting": {
            "publicKeyCrpPolynomials": 1,
            "publicKeyShareCount": FIRST_PROFILE_PARTICIPANT_COUNT,
            "acceptedRelinearizationKeyPolynomials": accepted_relinearization_key_polynomials,
            "acceptedGaloisKeyPolynomials": accepted_galois_key_polynomials,
            "scheduledRelinearizationLevelCount": scheduled_relinearization_level_count,
            "scheduledGaloisKeyCount": required_galois_key_count,
            "evaluationKeyExposureStatus": "root-bound-relinearization-and-galois-key-material-counted-for-direct-evaluator-replay-HE-boundary",
            "commitmentAndSetupProofPublicMatrices": "covered-by-setup-commitment-and-setup-proof profiles, not counted as HE RLWE public-key samples"
        },
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
            "errorModel": "centered-binomial-eta2",
            "largestExposedModulusBits": largest_exposed_modulus_bits,
            "publicSamplesBound": true
        },
        "targetDecryptionStatus": {
            "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
            "qTargetKnown": false,
            "qTargetCoveredByCertificate": false,
            "targetC1ThroughC4Covered": false,
            "targetDecryptionReadiness": "refused-until-q-target-certificate-closes"
        },
        "parameterBoundary": {
            "certificateStatus": if post_quantum_accepted && classical_accepted {
                "accepted-for-direct-setup-and-evaluator-HE-parameter-boundary"
            } else {
                "rejected-by-local-HE-standard-table-row"
            },
            "acceptedScope": "current Q_data/Q_share direct evaluator replay and accepted setup public key/evaluation-key exposure",
            "excludedScope": "Q_target, target decryption, smudging, C1-C4, and downstream decryption-share proof material",
            "proofDependency": "proof soundness and zero-knowledge certificates remain separate from this HE parameter certificate",
        },
        "acceptedForDirectEvaluatorReplay": post_quantum_accepted && classical_accepted,
        "acceptedForTargetDecryption": false,
        "statusLabels": if post_quantum_accepted && classical_accepted {
            vec![
                "HEStandardPostQuantum128Accepted",
                "HEStandardClassical128Accepted",
                "DataBasisLargestExposedModulusAccepted",
                "DirectSetupEvaluatorHeParameterBoundaryAccepted",
                "SpecialPrimeNotPubliclyExposedOnAcceptedPath",
                "TargetDecryptionReadinessRefusedUntilQTargetCertificate",
            ]
        } else {
            vec![
                "HEStandardSecurityRejected",
                "DataBasisLargestExposedModulusRejected",
            ]
        },
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
