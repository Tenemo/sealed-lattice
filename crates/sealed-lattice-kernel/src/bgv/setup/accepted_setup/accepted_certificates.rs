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
        "certificateScope": "first-profile-BDLOP-LNP-commitment-parameters-and-opening-bounds",
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
                    "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                    "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                    "sections": [
                        "Commitment schemes",
                        "Module-SIS and Module-LWE problems",
                        "ABDLOP commitment scheme and proofs of linear relations"
                    ]
                },
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
                "accountingBasis": "accepted Module-SIS binding row under LNP22/FPS25 commitment references and no-wrap threshold-opening bounds"
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
                "accountingBasis": "accepted Module-LWE hiding row under LNP22/FPS25/ACC18 references and recipient-hidden opening leakage boundary"
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

fn ceil_log2_u128(value: u128) -> u32 {
    if value <= 1 {
        0
    } else {
        u128::BITS - (value - 1).leading_zeros()
    }
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
    use crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash;

    Ok(json!([
        {
            "proofFamily": "vss-opening-carry",
            "claimScope": "recipient-local private VSS share proof relation over accepted Q_share limbs",
            "verifierClosedStatus": "relation-transcript-and-bound-checks-verifier-closed",
            "verifierClosedChecks": [
                "proof bytes hash, size, statement root, material root, statement-and-relation-bound tbox prefix, and scalar challenge are recomputed from canonical proof material",
                "accepted private VSS tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript",
                "four first-profile Shamir coefficient opening responses are checked against accepted coefficient commitments",
                "recipient-point lifted share equality and explicit carry responses are checked coefficientwise before acceptance",
                "message, randomness, and carry responses are checked against fixed first-profile bounds",
            ],
            "accountingStatus": "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted",
            "claimAccounting": {
                "soundness": "LNP22 commit-and-prove extractor accounting is accepted for the recipient-local carry-aware VSS relation because statement binding, first-message commitments, generated tbox bytes, coefficient openings, carry relations, and response bounds are verified before acceptance",
                "zeroKnowledge": "LNP22 simulator accounting is accepted for centered 112-bit coefficient masks, opening-randomness masks, carry masks, verifier-bound no-wrap bounds, and transcript-bound tbox bytes; private coefficients, openings, and carries are not exposed in accepted public artifacts",
                "qrom": "DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object",
            },
        },
        {
            "proofFamily": "same-secret-consistency",
            "claimScope": "same trustee secret across accepted VSS constant commitments",
            "verifierClosedStatus": "relation-transcript-and-bound-checks-verifier-closed",
            "verifierClosedChecks": [
                "statement hash binds setup proof record binding, trustee statement roots, accepted constant commitment roots, and tbox profile hash",
                "relation commitment hash and scalar challenge are recomputed from proof commitments and canonical transcript fields",
                "accepted same-secret tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript",
                "ternary secret support is checked through Boolean negative-indicator and shifted-secret support equations",
                "all accepted Q_share constant commitments are checked against one shared secret response and opening randomness response",
                "secret, negative-indicator, and randomness responses are checked against fixed first-profile bounds",
            ],
            "accountingStatus": "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted",
            "claimAccounting": {
                "soundness": "LNP22 commit-and-prove extractor accounting is accepted for the same-secret relation because the verifier binds one shared secret response to every accepted constant commitment and support equation",
                "zeroKnowledge": "LNP22 simulator accounting is accepted for centered 80-bit same-secret and support-response masks with witness-dependent support commitments treated as simulated first messages under the fixed relation and no-wrap response accounting",
                "qrom": "DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object",
            },
        },
        {
            "proofFamily": "public-key-share",
            "claimScope": "public-key share relation bound to the accepted same-secret proof and public-key material roots",
            "verifierClosedStatus": "relation-transcript-and-bound-checks-verifier-closed",
            "verifierClosedChecks": [
                "statement hash binds public-key share roots, same-secret statement roots, public matrix roots, coefficient vector hashes, and setup proof record binding",
                "relation commitment hash and scalar challenge are recomputed from public-key, support, and commitment-response commitments",
                "accepted public-key-share tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript",
                "same-secret opening response and ternary secret support are checked against accepted VSS constant commitments",
                "centered-binomial error support is checked for every accepted Q_share limb and coefficient",
                "lifted public-key equality PKShare_i,l - p*e_i,l + a_l*s_i + q_l*v_i,l = 0 is checked with explicit carry responses",
                "secret, negative-indicator, opening-randomness, and error responses are checked against fixed first-profile bounds",
            ],
            "accountingStatus": "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted",
            "claimAccounting": {
                "soundness": "LNP22 commit-and-prove extractor accounting is accepted for the public-key share relation because same-secret openings, ternary support, centered-binomial error support, lifted no-wrap public-key equality, and fixed response bounds are verifier-bound",
                "zeroKnowledge": "LNP22 simulator accounting is accepted for centered 80-bit committed-secret masks, support commitments, error masks, opening masks, and carry masks with fixed-width signed relation commitments and no-wrap accounting",
                "qrom": "DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object",
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
                "arithmetic source relations are enforced inside the argument: round-one sources equal the committed secret, round-two sources equal the secret times the recomputed public aggregate, and Galois sources equal the automorphism image",
                "the same-secret linkage opens the accepted BDLOP constant commitments natively over the commitment-modulus fields against the shared key-relation secret",
                "cross-limb consistency claims are checked as residues of one shared masked integer per claim, lifted from two limb fields and matched in every other limb",
                "canonical proof bytes are decoded with trailing-byte refusal and rebound to the statement hash recorded in the package",
            ],
            "accountingStatus": "succinct-trustee-evaluation-key-theorem-accounting-accepted",
            "claimAccounting": {
                "accountingObject": "SuccinctEvaluationKeyProofAccounting",
                "accountingHash": succinct_evaluation_key_proof_accounting_hash()?,
                "closedItems": "the explicitly conjectured low-degree bound with its proven fallback, the two-prime cross-limb consistency lemma, the simulator argument with its opening-budget margin, the certified smudging leakage budget, and the round-by-round Fiat-Shamir accounting with referenced QROM reductions are accepted rows inside the bound accounting object",
                "claimBoundary": "active-malicious evaluation-key proof accounting is accepted under the named FRI conjecture; ceremony transport, roster binding, and target decryption keep their own gates",
            },
        },
    ]))
}

fn setup_proof_tbox_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofLnpTboxAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "generated-lower-protocol-tbox-profile-verifier-and-prover-closed",
        "closedProofFamilies": SETUP_PROOF_FAMILIES,
        "proofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "challengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "challengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
        "challengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "profileHashes": {
            "privateVssShareTboxParameterProfileHash": super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?,
            "sameSecretTboxParameterProfileHash": super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?,
            "publicKeyShareTboxParameterProfileHash": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?,
        },
        "challengeAuditHash": super::setup_proof::setup_proof_challenge_space_audit_hash(
            SETUP_PROOF_CHALLENGE_SPACE_AUDIT_HASH_NAMESPACE,
            SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        )?,
        "commitmentPrefixGeneration": "setup proof generators encode full declared-width tB, h, and compressed tA1 residue bytes from a deterministic statement-and-relation binding seed with rejection sampling for proof-modulus residues and forced zero h coefficients at positions 0 and d/2",
        "commitmentPrefixVerifierBinding": "setup proof verifiers recompute the deterministic tbox prefix from statement hash, tbox profile hash, and encoded relation commitments, decode canonical fixed-width prefix residues, enforce h coefficients at positions 0 and d/2 as zero, and bind tboxCommitmentPrefixHash into the relation transcript",
        "z34SeedMaterialBinding": "setup proof verifiers extract LaZer check_z34 ty3, ty4, and tbeta seed material from tB after the fixed message-polynomial prefix, hash the canonical urandom3 encoding for later z3/z4 challenge binding, and require accepted proof records to carry the matching seed-material hash",
        "z34ChallengeSeedBinding": "setup proof verifiers derive the 32-byte check_z34 challenge seed from the statement hash, relation commitment hash, proof family, tbox profile, and canonical seed material, hash the current tB challenge-tail residues after tbeta, expand LaZer brandom k=1 ternary R/Rprime rows over the declared z3/z4 row widths with R domains 0..255 and Rprime domains 256..511, sample the proof-byte challenge polynomial from the lower-protocol challenge hash, then require accepted proof records to carry matching challenge-seed, challenge-tail, lower-protocol challenge, row-domain, z3 row-set, and z4 row-set hashes",
        "suffixVerifierBinding": "setup proof verifiers decode LaZer signed hint and Gaussian suffix values, hash the signed z3/z4 check-window values, compute z3 L2 squared and z4 infinity norm over the 256-coefficient check_z34 window, reject values above the generated LaZer Bz3sqr/Bz4 bounds, check z1/z21 Gaussian L2 bounds and generated hint ranges, and enforce the generated lower-protocol tbox suffix profile against the statement-and-relation-bound prefix",
        "closedVerifierChecks": [
            "deterministic statement-and-relation-bound full-width tbox commitment-prefix generation and verifier recomputation",
            "proof-record-bound LaZer check_z34 seed material, challenge seed, challenge tail, lower-protocol challenge hash, row domains, R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms",
            "generated LaZer check_z34 256-coefficient z3/z4 norm-bound enforcement",
            "signed LaZer hint and Gaussian suffix decoding",
            "generated z1/z21 Gaussian L2 bound enforcement",
            "generated hint range enforcement",
            "h zero-position enforcement",
            "z34-bound lower-protocol challenge sampling",
            "generated lower-protocol tbox suffix byte-for-byte enforcement",
        ],
        "claimBoundary": "tbox proof-byte generation and verification are closed for the fixed setup proof profiles and feed the accepted setup proof soundness, zero-knowledge, and QROM accounting object",
    }))
}

fn setup_proof_scalar_relation_challenge_bits() -> CanonicalResult<usize> {
    let challenge_bits = [
        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
        SAME_SECRET_SCALAR_CHALLENGE_BITS,
        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
    ];
    let first_challenge_bits = challenge_bits[0];
    if challenge_bits
        .iter()
        .any(|candidate_bits| *candidate_bits != first_challenge_bits)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof scalar relation challenge bit counts must match across proof families",
        ));
    }

    Ok(first_challenge_bits)
}

fn setup_proof_fiat_shamir_transcript_accounting_value() -> CanonicalResult<Value> {
    let scalar_relation_challenge_bits = setup_proof_scalar_relation_challenge_bits()?;

    Ok(json!({
        "objectType": "SetupProofFiatShamirTranscriptAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "fiat-shamir-transcript-domain-and-challenge-input-accounting-closed",
        "qromReductionStatus": "repo-owned-qrom-reduction-theorem-accepted-for-setup-proof-claim",
        "challengeDomainHash": setup_proof_challenge_domain_hash()?,
        "challengeSpaceAuditHash": super::setup_proof::setup_proof_challenge_space_audit_hash(
            SETUP_PROOF_CHALLENGE_SPACE_AUDIT_HASH_NAMESPACE,
            SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        )?,
        "challengeStages": [
            {
                "stageId": "lnp-polynomial-challenge",
                "domain": SETUP_PROOF_CHALLENGE_DOMAIN,
                "seedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
                "streamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
                "inputBinding": [
                    "proofFamily",
                    "statementHash",
                    "relationCommitmentHash"
                ],
                "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
                "challengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
                "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
            },
            {
                "stageId": "scalar-relation-challenge",
                "challengeBits": scalar_relation_challenge_bits,
                "nonzeroChallengeRequired": true,
                "inputBinding": [
                    "family-specific scalar challenge domain",
                    "statementHash",
                    "relationCommitmentHash",
                    "encoded LNP polynomial challenge coefficients",
                    "rejection block index"
                ],
                "familyDomains": [
                    {
                        "proofFamily": "vss-opening-carry",
                        "domain": PRIVATE_VSS_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
                    },
                    {
                        "proofFamily": "same-secret-consistency",
                        "domain": SAME_SECRET_LNP_SCALAR_CHALLENGE_DOMAIN,
                    },
                    {
                        "proofFamily": "public-key-share",
                        "domain": PUBLIC_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
                    },
                ],
            },
        ],
        "duplicateFreeInputAccounting": {
            "familyDomainSeparation": "scalar relation challenges use one fixed domain string per setup proof family",
            "stageSeparation": "polynomial challenge sampling and scalar relation challenge sampling use distinct domains and distinct encoded inputs",
            "statementBinding": "statement hashes include setup profile, trustee or schedule roots, accepted public material roots, and setup proof record binding before any challenge is derived",
            "firstMessageBinding": "relation commitment hashes bind the prover first-message commitments before the scalar relation challenge is derived",
            "tboxBinding": "tbox lower-protocol challenge hashes and z34 challenge metadata are bound to statement, relation commitment, proof family, tbox profile, and canonical seed material before accepted proof records are accepted",
        },
        "referenceRows": [
            {
                "document": "DFM20_The Measure-and-Reprogram Technique 2.0 Multi-Round Fiat-Shamir and More",
                "localReferencePath": "reference-documents/DFM20_The Measure-and-Reprogram Technique 2.0 Multi-Round Fiat-Shamir and More.txt",
                "sections": [
                    "Definition 11 Fiat-Shamir transformation for public-coin protocols",
                    "Remark 12 duplicate-free hash inputs through round indices or transcript/domain separation",
                    "Corollary 13 multi-round Fiat-Shamir in the QROM"
                ]
            },
            {
                "document": "DFMS22_Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM",
                "localReferencePath": "reference-documents/DFMS22_Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM.txt",
                "sections": [
                    "Section 3.4 Fiat-Shamir transformation of commit-and-open Sigma protocols",
                    "Remark 3.7 domain separation of random-oracle inputs",
                    "Theorem 4.2 online extractability of the Fiat-Shamir transformation"
                ]
            },
            {
                "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                "sections": [
                    "Section 2.7 Challenge Space",
                    "Section 3 ABDLOP commitment scheme and proofs of linear relations",
                    "Appendix A knowledge soundness"
                ]
            }
        ],
        "claimBoundary": "Fiat-Shamir transcript domain separation, challenge input binding, challenge-space accounting, QROM reduction, and fixed-profile composition loss are accepted for setup proof-family claim accounting",
    }))
}

fn setup_proof_theorem_accounting_value() -> CanonicalResult<Value> {
    let scalar_relation_challenge_bits = setup_proof_scalar_relation_challenge_bits()?;

    Ok(json!({
        "objectType": "SetupProofTheoremAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "accountingStatus": "repo-owned-setup-proof-soundness-zero-knowledge-and-qrom-accounting-accepted",
        "acceptedClaimScope": [
            "private VSS share opening and carry proof relation",
            "same-secret consistency proof relation",
            "public-key share proof relation",
        ],
        "claimScopeBoundary": "the trustee evaluation-key argument is accounted by the bound SuccinctEvaluationKeyProofAccounting object and is outside this accepted LNP theorem scope until its open rows close",
        "soundnessAccounting": {
            "baseProtocol": "LNP22 AB-DLOP/LNP commit-and-prove linear-relation proof profile",
            "extractorModel": "repo-owned extractor mapping over verifier-closed statement roots, relation commitments, generated tbox bytes, response bounds, no-wrap lifted relations, and support equations",
            "knowledgeFailureEvents": [
                "noncanonical proof bytes",
                "statement or material root drift",
                "relation commitment drift",
                "generated tbox suffix drift",
                "challenge-domain replay across proof families",
                "response bound overflow",
                "lifted no-wrap violation",
                "support equation violation",
            ],
            "acceptedFailureLabel": "refused-before-claim-bearing-setup-acceptance",
        },
        "zeroKnowledgeAccounting": {
            "simulatorModel": "LNP22 commit-and-prove simulator for non-aborting transcripts with setup-family statements treated as public inputs",
            "responseMasking": "centered signed response masks are verifier-bound, no-wrap checked, and have positive masking slack for each committed-secret, error, opening, source, and carry response class",
            "supportCommitments": "witness-dependent support commitments are accounted as simulated first-message commitments bound to the accepted relation and response distributions",
            "witnessExportBoundary": "accepted proof records expose statement roots, commitments, proof bytes, roots, and public key material only; raw shares, trustee secrets, openings, errors, carries, and key-switch witnesses remain outside accepted public artifacts",
        },
        "qromReductionAccounting": {
            "model": "quantum-random-oracle-model",
            "transform": "Fiat-Shamir",
            "fixedProofFamilyCount": SETUP_PROOF_FAMILIES.len(),
            "challengeStageCount": 2,
            "lnpPolynomialChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
            "scalarRelationChallengeBits": scalar_relation_challenge_bits,
            "compositionStatus": "accepted-for-fixed-three-family-two-stage-setup-profile",
            "duplicateFreeInputStatus": "accepted-by-family-specific-domain-separation-and-stage-specific-transcript-inputs",
            "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
        },
        "referenceRows": [
            {
                "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                "sections": [
                    "commit-and-prove simulatability",
                    "Lemma 4.3 knowledge soundness",
                    "Fiat-Shamir transformed knowledge soundness"
                ]
            },
            {
                "document": "DFM20_The Measure-and-Reprogram Technique 2.0 Multi-Round Fiat-Shamir and More",
                "localReferencePath": "reference-documents/DFM20_The Measure-and-Reprogram Technique 2.0 Multi-Round Fiat-Shamir and More.txt",
                "sections": [
                    "Theorem 7 measure-and-reprogram with enforced extraction order",
                    "Corollary 13 multi-round Fiat-Shamir in the QROM",
                    "Corollary 15 preservation of soundness and proof of knowledge"
                ]
            },
            {
                "document": "DFMS22_Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM",
                "localReferencePath": "reference-documents/DFMS22_Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM.txt",
                "sections": [
                    "Section 3.4 Fiat-Shamir transformation of commit-and-open Sigma protocols",
                    "Theorem 4.2 online extractability of the Fiat-Shamir transformation",
                    "Corollary 5.3 Fiat-Shamir soundness after parallel repetition"
                ]
            }
        ],
        "claimBoundary": "accepted only for setup proof families under CollectiveBgvSetup-v1; this does not close ballot proof soundness, evaluator replay, target decryption, supported-phone evidence, production audit readiness, or future proof-system families",
    }))
}

fn scalar_challenge_maximum_for_bits(bit_count: usize) -> CanonicalResult<u128> {
    let bit_count = u32::try_from(bit_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting challenge bit count overflowed",
        )
    })?;
    1_u128
        .checked_shl(bit_count)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting challenge maximum overflowed",
            )
        })
}

fn response_mask_random_bound(mask_bits: usize) -> CanonicalResult<u128> {
    let mask_bits = u32::try_from(mask_bits).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting mask bit count overflowed",
        )
    })?;
    1_u128
        .checked_shl(mask_bits)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting mask bound overflowed",
            )
        })
}

fn response_mask_profile_value(
    response_kind: &str,
    mask_bits: usize,
    challenge_bits: usize,
    witness_infinity_bound: u128,
    mask_offset: u128,
    encoding_role: &str,
) -> CanonicalResult<Value> {
    let scalar_challenge_maximum = scalar_challenge_maximum_for_bits(challenge_bits)?;
    let random_mask_bound = response_mask_random_bound(mask_bits)?;
    let effective_mask_bound = random_mask_bound.checked_add(mask_offset).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting effective mask bound overflowed",
        )
    })?;
    let challenge_witness_term_bound = scalar_challenge_maximum
        .checked_mul(witness_infinity_bound)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting challenge witness term overflowed",
            )
        })?;
    let response_bound = effective_mask_bound
        .checked_add(challenge_witness_term_bound)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting response bound overflowed",
            )
        })?;
    let challenge_witness_term_bits =
        ceil_log2_u128(challenge_witness_term_bound.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting challenge term bit length overflowed",
            )
        })?);
    let masking_slack_bits = i64::try_from(mask_bits).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting mask bits do not fit i64",
        )
    })? - i64::from(challenge_witness_term_bits);

    Ok(json!({
        "responseKind": response_kind,
        "encodingRole": encoding_role,
        "maskRandomBits": mask_bits,
        "maskOffsetDecimal": mask_offset.to_string(),
        "effectiveMaskBoundDecimal": effective_mask_bound.to_string(),
        "scalarChallengeBits": challenge_bits,
        "scalarChallengeMaximumDecimal": scalar_challenge_maximum.to_string(),
        "witnessInfinityBoundDecimal": witness_infinity_bound.to_string(),
        "challengeWitnessTermBoundDecimal": challenge_witness_term_bound.to_string(),
        "challengeWitnessTermCeilBits": challenge_witness_term_bits,
        "responseBoundDecimal": response_bound.to_string(),
        "responseBoundCeilBits": ceil_log2_u128(response_bound),
        "maskingSlackBits": masking_slack_bits,
    }))
}

fn response_profile_bound(
    mask_bits: usize,
    challenge_bits: usize,
    witness_infinity_bound: u128,
    mask_offset: u128,
) -> CanonicalResult<u128> {
    let scalar_challenge_maximum = scalar_challenge_maximum_for_bits(challenge_bits)?;
    response_mask_random_bound(mask_bits)?
        .checked_add(mask_offset)
        .and_then(|mask_bound| {
            scalar_challenge_maximum
                .checked_mul(witness_infinity_bound)
                .and_then(|challenge_term| mask_bound.checked_add(challenge_term))
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting response bound overflowed",
            )
        })
}

fn lifted_message_no_wrap_value(
    relation_name: &str,
    secret_response_bound: u128,
    negative_indicator_response_bound: u128,
    max_source_message_modulus: u64,
    commitment_modulus_product: &BigUint,
) -> CanonicalResult<Value> {
    let lifted_bound = u128::from(max_source_message_modulus)
        .checked_mul(negative_indicator_response_bound)
        .and_then(|value| value.checked_add(secret_response_bound))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting lifted message bound overflowed",
            )
        })?;
    let lifted_bound_big = BigUint::from(lifted_bound);
    let no_wrap_satisfied = &lifted_bound_big < commitment_modulus_product;

    Ok(json!({
        "relationName": relation_name,
        "maxSourceMessageModulus": max_source_message_modulus,
        "secretResponseBoundDecimal": secret_response_bound.to_string(),
        "negativeIndicatorResponseBoundDecimal": negative_indicator_response_bound.to_string(),
        "liftedMessageResponseBoundDecimal": lifted_bound.to_string(),
        "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
        "noWrapSatisfied": no_wrap_satisfied,
    }))
}

fn setup_proof_response_masking_accounting_value() -> CanonicalResult<Value> {
    let max_source_message_modulus = DATA_PRIMES.iter().copied().max().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted Q_share prime list must not be empty",
        )
    })?;
    let commitment_modulus_product = setup_commitment_modulus_product();
    let profile_ring_degree = u128::try_from(POLYNOMIAL_DEGREE).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting ring degree does not fit u128",
        )
    })?;
    let private_vss_carry_witness_bound = scalar_power_sum(
        FIRST_PROFILE_DECRYPTION_THRESHOLD,
        FIRST_PROFILE_PARTICIPANT_COUNT,
    )?;
    let public_key_carry_witness_bound = profile_ring_degree.checked_add(3).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting public-key carry bound overflowed",
        )
    })?;
    let same_secret_response_bound = response_profile_bound(
        SAME_SECRET_MESSAGE_MASK_BITS,
        SAME_SECRET_SCALAR_CHALLENGE_BITS,
        SAME_SECRET_TERNARY_INFINITY_BOUND as u128,
        0,
    )?;
    let same_secret_negative_response_bound = response_profile_bound(
        SAME_SECRET_MESSAGE_MASK_BITS,
        SAME_SECRET_SCALAR_CHALLENGE_BITS,
        SAME_SECRET_NEGATIVE_INDICATOR_INFINITY_BOUND as u128,
        0,
    )?;
    let public_key_secret_response_bound = response_profile_bound(
        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
        PUBLIC_KEY_SHARE_SECRET_INFINITY_BOUND as u128,
        0,
    )?;
    let public_key_negative_response_bound = response_profile_bound(
        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
        PUBLIC_KEY_SHARE_NEGATIVE_INDICATOR_INFINITY_BOUND as u128,
        0,
    )?;
    Ok(json!({
        "objectType": "SetupProofResponseMaskingAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "response-mask-bounds-strengthened-verifier-bound-and-zk-accounting-accepted",
        "encodingConstraints": {
            "responseEncoding": "signed-i128-little-endian",
            "committedMessageEncoding": "u128-source-coefficients-and-centered-signed-response-coefficients-with-big-int-no-wrap-before-commitment-modulus-reduction",
            "relationCommitmentEncoding": "public-key lifted relation commitments use fixed-width signed 32-byte little-endian big-integer coefficients; response vectors remain signed i128",
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "commitmentModulusProductCeilBits": setup_commitment_modulus_product_ceil_bits(),
            "maxSourceMessageModulus": max_source_message_modulus,
            "carryMaskWideningStatus": "carry masks remain 64 bits and scalar relation challenges are capped at 63 bits because carry responses and response vectors remain signed i128",
        },
        "families": [
            {
                "proofFamily": "vss-opening-carry",
                "responseProfiles": [
                    response_mask_profile_value(
                        "coefficient-message",
                        PRIVATE_VSS_SHARE_MESSAGE_MASK_BITS,
                        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
                        u128::from(max_source_message_modulus - 1),
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "opening-randomness",
                        PRIVATE_VSS_SHARE_RANDOMNESS_MASK_BITS,
                        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
                        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND as u128,
                        0,
                        "signed-opening-response",
                    )?,
                    response_mask_profile_value(
                        "lifted-carry",
                        PRIVATE_VSS_SHARE_CARRY_MASK_BITS,
                        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
                        private_vss_carry_witness_bound,
                        0,
                        "signed-carry-response",
                    )?,
                ],
                "fullWidthCoefficientMaskingStatus": "centered-signed-private-vss-message-response-masking-verifier-bound-and-simulator-accounting-accepted",
                "commitmentNoWrapStatus": "three-limb-big-int-no-wrap-bound-recorded",
            },
            {
                "proofFamily": "same-secret-consistency",
                "responseProfiles": [
                    response_mask_profile_value(
                        "secret",
                        SAME_SECRET_MESSAGE_MASK_BITS,
                        SAME_SECRET_SCALAR_CHALLENGE_BITS,
                        SAME_SECRET_TERNARY_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "negative-indicator",
                        SAME_SECRET_MESSAGE_MASK_BITS,
                        SAME_SECRET_SCALAR_CHALLENGE_BITS,
                        SAME_SECRET_NEGATIVE_INDICATOR_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "opening-randomness",
                        SAME_SECRET_RANDOMNESS_MASK_BITS,
                        SAME_SECRET_SCALAR_CHALLENGE_BITS,
                        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND as u128,
                        0,
                        "signed-opening-response",
                    )?,
                ],
                "liftedMessageNoWrap": lifted_message_no_wrap_value(
                    "secret-plus-rns-prime-times-negative-indicator",
                    same_secret_response_bound,
                    same_secret_negative_response_bound,
                    max_source_message_modulus,
                    &commitment_modulus_product,
                )?,
            },
            {
                "proofFamily": "public-key-share",
                "responseProfiles": [
                    response_mask_profile_value(
                        "secret",
                        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        PUBLIC_KEY_SHARE_SECRET_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "negative-indicator",
                        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        PUBLIC_KEY_SHARE_NEGATIVE_INDICATOR_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "error",
                        PUBLIC_KEY_SHARE_ERROR_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        PUBLIC_KEY_SHARE_ERROR_INFINITY_BOUND as u128,
                        0,
                        "signed-error-response",
                    )?,
                    response_mask_profile_value(
                        "opening-randomness",
                        PUBLIC_KEY_SHARE_RANDOMNESS_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND as u128,
                        0,
                        "signed-opening-response",
                    )?,
                    response_mask_profile_value(
                        "lifted-carry",
                        PUBLIC_KEY_SHARE_CARRY_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        public_key_carry_witness_bound,
                        0,
                        "signed-carry-response",
                    )?,
                ],
                "liftedMessageNoWrap": lifted_message_no_wrap_value(
                    "secret-plus-rns-prime-times-negative-indicator",
                    public_key_secret_response_bound,
                    public_key_negative_response_bound,
                    max_source_message_modulus,
                    &commitment_modulus_product,
                )?,
            },
        ],
        "zeroKnowledgeAccountingStatus": "response masking, witness-dependent support commitments, committed-secret response distributions, fixed-width signed relation commitments, and no-wrap response bounds are accepted by the setup proof theorem accounting object",
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
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "proofFamilyAccounting": setup_proof_family_accounting_value()?,
        "trusteeEvaluationKeyProofAccounting":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_value()?,
        "trusteeEvaluationKeyProofAccountingHash":
            crate::bgv::setup::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
        "tboxAccounting": setup_proof_tbox_accounting_value()?,
        "responseMaskingAccounting": setup_proof_response_masking_accounting_value()?,
        "fiatShamirTranscriptAccounting": setup_proof_fiat_shamir_transcript_accounting_value()?,
        "proofTheoremAccounting": setup_proof_theorem_accounting_value()?,
        "challengeAccounting": {
            "transform": "Fiat-Shamir",
            "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
            "challengeDomainHash": setup_proof_challenge_domain_hash()?,
            "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
            "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
            "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
            "challengeDifferenceInvertibilityAccounting": super::setup_proof::challenge_difference_invertibility_accounting_value()?,
            "challengeSpaceAudit": super::setup_proof::setup_proof_challenge_space_audit_value(SETUP_PROOF_LNP_PROOF_RING_DEGREE)?,
            "challengeSpaceAuditHash": super::setup_proof::setup_proof_challenge_space_audit_hash(
                SETUP_PROOF_CHALLENGE_SPACE_AUDIT_HASH_NAMESPACE,
                SETUP_PROOF_LNP_PROOF_RING_DEGREE,
            )?,
            "scalarRelationChallengePolicy": "per-family scalar relation challenges use 63 bits, capped by signed i128 carried relation arithmetic after the setup commitment no-wrap product moved to three selected limbs with big-integer accounting",
            "randomOracleModel": "Fiat-Shamir transcript accounting and repo-owned QROM reduction theorem are accepted for setup proof-family claim accounting",
            "qromStatus": "qrom-reduction-theorem-accepted-for-setup-proof-claim",
            "transcriptBinding": [
                "setupProfileHash",
                "manifestHash",
                "rosterHash",
                "setupEpoch",
                "publicMatrixSeedHash",
                "proofFamily",
                "statementRoot",
                "proofChunkRoot"
            ],
        },
        "completionBoundary": "claim-bearing accepted setup is a repo-owned library claim and does not require external validation or a third-party review gate",
        "certificateStatus": "lnp-and-trustee-evaluation-key-family-accounting-accepted",
        "claimBoundary": "every bound setup proof family carries accepted accounting: the LNP families under their closed tbox and challenge accounting, and the trustee evaluation-key family under the named FRI conjecture with referenced QROM reductions",
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
    let public_key_share_lnp_proof_set_root = package_nested_hash(
        setup_package,
        "publicKeyShareLnpProofs",
        "publicKeyShareLnpProofSetRoot",
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
            "status": "collective-public-key-coefficients-recomputed-from-public-key-share-material-and-LNP-proof-roots",
            "collectivePublicKeyRoot": collective_public_key_root,
            "sourceRoots": {
                "publicKeyShareSetRoot": package_nested_hash(setup_package, "publicKeyShares", "publicKeyShareSetRoot")?,
                "publicKeyShareProofSetRoot": package_nested_hash(setup_package, "publicKeyShareProofs", "publicKeyShareProofSetRoot")?,
                "publicKeyShareMaterialSetRoot": public_key_share_material_set_root,
                "publicKeyShareLnpProofSetRoot": public_key_share_lnp_proof_set_root,
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
            "setup commitment, proof-accounting, transport, HE, and key-correctness certificates are root-bound package objects",
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
            "publicKeyShareLnpProofSetRoot": optional_nested_hash_value(
                setup_package,
                "publicKeyShareLnpProofs",
                "publicKeyShareLnpProofSetRoot",
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
