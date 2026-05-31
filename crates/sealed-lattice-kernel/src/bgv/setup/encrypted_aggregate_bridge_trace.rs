use super::validation;
use super::*;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

const INTEGER_LIFTED_BATCH_ENCODING_RELATION: &str =
    "BGVBatchEncode65537IntegerLiftedInverseNegacyclicNtt";
const INTEGER_LIFTED_BATCH_PROOF_MODULI: [u64; 2] = [DATA_PRIMES[0], DATA_PRIMES[1]];
const INTEGER_LIFTED_BATCH_PROOF_MODULUS_PRODUCT: u128 =
    (DATA_PRIMES[0] as u128) * (DATA_PRIMES[1] as u128);

#[derive(Clone, Debug)]
pub(crate) struct EncryptedAggregateBridgeCiphertextRelationTrace {
    pub(crate) public_artifact: Value,
    pub(crate) supplied_plaintext_slots: Vec<u64>,
    pub(crate) padded_plaintext_slots: Vec<u64>,
    pub(crate) plaintext_coefficients_mod_plaintext: Vec<u64>,
    pub(crate) plaintext_encoding_quotients: Vec<u64>,
    pub(crate) encryption_randomness_coefficients: Vec<i64>,
    pub(crate) encryption_error_zero_coefficients: Vec<i64>,
    pub(crate) encryption_error_one_coefficients: Vec<i64>,
}

impl EncryptedAggregateBridgeCiphertextRelationTrace {
    fn validate_shape(&self, supplied_slot_count: usize) -> CanonicalResult<()> {
        if self.supplied_plaintext_slots.len() != supplied_slot_count
            || self.padded_plaintext_slots.len() != POLYNOMIAL_DEGREE
            || self.plaintext_coefficients_mod_plaintext.len() != POLYNOMIAL_DEGREE
            || self.plaintext_encoding_quotients.len() != POLYNOMIAL_DEGREE
            || self.encryption_randomness_coefficients.len() != POLYNOMIAL_DEGREE
            || self.encryption_error_zero_coefficients.len() != POLYNOMIAL_DEGREE
            || self.encryption_error_one_coefficients.len() != POLYNOMIAL_DEGREE
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge ciphertext relation trace has inconsistent witness dimensions",
            ));
        }
        if self
            .supplied_plaintext_slots
            .iter()
            .chain(self.padded_plaintext_slots.iter())
            .chain(self.plaintext_coefficients_mod_plaintext.iter())
            .any(|coefficient| *coefficient >= PLAINTEXT_MODULUS)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "encrypted aggregate bridge ciphertext relation trace contains a non-canonical plaintext coefficient",
            ));
        }
        let quotient_bound = batch_encoding_quotient_bound(supplied_slot_count)?;
        if self
            .plaintext_encoding_quotients
            .iter()
            .any(|coefficient| *coefficient > quotient_bound)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "encrypted aggregate bridge ciphertext relation trace contains a batch quotient outside the declared bound",
            ));
        }
        if self
            .encryption_randomness_coefficients
            .iter()
            .any(|coefficient| !(-1..=1).contains(coefficient))
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "encrypted aggregate bridge ciphertext relation trace randomizer is outside the declared support",
            ));
        }
        if self
            .encryption_error_zero_coefficients
            .iter()
            .chain(self.encryption_error_one_coefficients.iter())
            .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "encrypted aggregate bridge ciphertext relation trace error coefficient is outside the declared support",
            ));
        }

        Ok(())
    }

    fn validate_private_preflight(&self) -> CanonicalResult<()> {
        self.validate_shape(self.supplied_plaintext_slots.len())?;
        let encoded =
            encode_batch_plaintext_slots(&self.supplied_plaintext_slots, DATA_PRIMES.len() - 1)?;
        if self.padded_plaintext_slots[..self.supplied_plaintext_slots.len()]
            != self.supplied_plaintext_slots
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate bridge private preflight detected a padded slot prefix that does not match the active slot map",
            ));
        }
        if self.padded_plaintext_slots[self.supplied_plaintext_slots.len()..]
            .iter()
            .any(|slot| *slot != 0)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate bridge private preflight detected a nonzero reserved plaintext slot",
            ));
        }
        if self.padded_plaintext_slots != encoded.slots {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate bridge private preflight detected a padded plaintext layout mismatch",
            ));
        }
        if self.plaintext_coefficients_mod_plaintext != encoded.coefficients_mod_plaintext {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate bridge private preflight detected plaintext coefficients that do not match the deterministic batch encoder",
            ));
        }
        let expected_quotients = derive_plaintext_encoding_quotients(
            &self.supplied_plaintext_slots,
            &self.plaintext_coefficients_mod_plaintext,
        )?;
        if self.plaintext_encoding_quotients != expected_quotients {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate bridge private preflight detected batch quotients that do not match the exact integer lift",
            ));
        }
        encrypted_aggregate_bridge_batch_lift_bound_certificate_value(
            self.supplied_plaintext_slots.len(),
        )?;
        let basis_sums = batch_basis_integer_sums(&self.supplied_plaintext_slots)?;
        for ((basis_sum, plaintext_coefficient), batch_quotient) in basis_sums
            .iter()
            .zip(self.plaintext_coefficients_mod_plaintext.iter())
            .zip(self.plaintext_encoding_quotients.iter())
        {
            if *basis_sum >= INTEGER_LIFTED_BATCH_PROOF_MODULUS_PRODUCT {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "encrypted aggregate bridge private preflight detected an integer-lifted batch expression that can wrap the proof modulus product",
                ));
            }
            let reconstructed_sum = u128::from(*plaintext_coefficient)
                + u128::from(PLAINTEXT_MODULUS) * u128::from(*batch_quotient);
            if *basis_sum != reconstructed_sum {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "encrypted aggregate bridge private preflight detected a non-exact batch quotient equation",
                ));
            }
        }

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_encrypted_aggregate_bridge_ciphertext_relation_trace_from_slots(
    setup_package: &Value,
    contributor_identity: &str,
    aggregate_derivation_component_hash: &str,
    aggregate_derivation_statement_hash: &str,
    post_voting_closed_context_hash: &str,
    reduced_aggregate_slots: &[u64],
    encryption_randomness_seed_hex: &str,
    include_canonical_bytes_hex: bool,
) -> CanonicalResult<EncryptedAggregateBridgeCiphertextRelationTrace> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;

    let setup_seed_hash = string_at_path(setup_package, &["setupInputs", "setupSeedHash"])?;
    let collective_public_key_root = string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
    )?;
    let collective_public_key_coefficient_root = string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyCoefficientRoot"],
    )?;
    let bgv_public_key_root =
        string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?;
    let manifest_hash = string_at_path(setup_package, &["setupInputs", "manifestHash"])?;
    let roster_hash = string_at_path(setup_package, &["setupInputs", "rosterHash"])?;
    let threshold_profile_hash =
        string_at_path(setup_package, &["setupInputs", "thresholdProfileHash"])?;
    let target_threshold_decryptability_certificate_hash = string_at_path(
        setup_package,
        &[
            "certificates",
            "targetThresholdDecryptabilityCertificateHash",
        ],
    )?;
    let encoded = encode_batch_plaintext_slots(reduced_aggregate_slots, DATA_PRIMES.len() - 1)?;
    let plaintext_encoding_quotients = derive_plaintext_encoding_quotients(
        reduced_aggregate_slots,
        &encoded.coefficients_mod_plaintext,
    )?;
    let batch_encoding_bound_certificate =
        encrypted_aggregate_bridge_batch_lift_bound_certificate_value(
            reduced_aggregate_slots.len(),
        )?;
    let batch_encoding_bound_certificate_hash =
        encrypted_aggregate_bridge_batch_lift_bound_certificate_hash(
            &batch_encoding_bound_certificate,
        )?;
    let plaintext_bytes = serialize_bgv_object(
        BgvObjectKind::Plaintext,
        std::slice::from_ref(&encoded.polynomial),
    )?;
    let plaintext_root = plaintext_root(&plaintext_bytes);
    let encryption_seed_hash = hash512_hex(
        "sealed-lattice-bgv-rns/aggregate-bridge-encryption-seed-v1",
        &[
            setup_seed_hash.as_bytes(),
            contributor_identity.as_bytes(),
            aggregate_derivation_component_hash.as_bytes(),
            aggregate_derivation_statement_hash.as_bytes(),
            post_voting_closed_context_hash.as_bytes(),
            encryption_randomness_seed_hex.as_bytes(),
        ],
    );
    let encryption_randomness_coefficients = dense_small_coefficients(
        &encryption_seed_hash,
        "aggregate-bridge-encryption",
        "encryption-randomness",
        -1,
        1,
    );
    let encryption_error_zero_coefficients = dense_centered_binomial_coefficients(
        &encryption_seed_hash,
        "aggregate-bridge-encryption",
        "encryption-error-zero",
    );
    let encryption_error_one_coefficients = dense_centered_binomial_coefficients(
        &encryption_seed_hash,
        "aggregate-bridge-encryption",
        "encryption-error-one",
    );
    let mut component_zero_residues_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
    let mut component_one_residues_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
    let mut sampled_relation_checks = Vec::new();
    let collective_key_coefficients_by_modulus =
        super::key_material::collective_public_key_coefficients_by_modulus_from_setup_package(
            setup_package,
        )?;

    for (modulus_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let collective_key_coefficients = collective_key_coefficients_by_modulus
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "encrypted aggregate bridge collective public key coefficient table is missing a data limb",
                )
            })?;
        let public_key_coefficients = &collective_key_coefficients.component_zero_coefficients;
        let public_sample_coefficients = &collective_key_coefficients.component_one_coefficients;
        let randomness_residues = encryption_randomness_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let scaled_error_zero_residues = encryption_error_zero_coefficients
            .iter()
            .map(|coefficient| signed_to_plaintext_scaled_residue(*coefficient, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;
        let scaled_error_one_residues = encryption_error_one_coefficients
            .iter()
            .map(|coefficient| signed_to_plaintext_scaled_residue(*coefficient, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;
        let public_key_product =
            negacyclic_product_mod(public_key_coefficients, &randomness_residues, modulus)?;
        let public_sample_product =
            negacyclic_product_mod(public_sample_coefficients, &randomness_residues, modulus)?;
        let message_residues = encoded
            .polynomial
            .residues_by_modulus
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "encrypted aggregate bridge plaintext is missing a selected data-basis residue limb",
                )
            })?;
        // Inline BGV encryption under the collective public key (pk, a) with
        // randomizer u and errors e0, e1: c0 = pk*u + p*e0 + m,
        // c1 = a*u + p*e1.
        let ciphertext_component_zero = public_key_product
            .iter()
            .zip(scaled_error_zero_residues.iter())
            .zip(message_residues.iter())
            .map(|((product, scaled_error), message_coefficient)| {
                add_mod(
                    add_mod(*product, *scaled_error, modulus)?,
                    *message_coefficient,
                    modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let ciphertext_component_one = public_sample_product
            .iter()
            .zip(scaled_error_one_residues.iter())
            .map(|(product, scaled_error)| add_mod(*product, *scaled_error, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;

        if modulus_index == 0 {
            sampled_relation_checks = sample_encryption_relation_checks(
                message_residues,
                &public_key_product,
                &public_sample_product,
                &scaled_error_zero_residues,
                &scaled_error_one_residues,
            )?;
        }
        component_zero_residues_by_modulus.push(ciphertext_component_zero);
        component_one_residues_by_modulus.push(ciphertext_component_one);
    }

    let layout_hash = layout_hash()?;
    let component_zero = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        DATA_PRIMES.len() - 1,
        layout_hash.clone(),
        component_zero_residues_by_modulus,
    )?;
    let component_one = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        DATA_PRIMES.len() - 1,
        layout_hash,
        component_one_residues_by_modulus,
    )?;
    let canonical_bytes =
        serialize_bgv_object(BgvObjectKind::Ciphertext, &[component_zero, component_one])?;
    let ciphertext_root = ciphertext_root(&canonical_bytes);
    let encrypted_aggregate_share_ciphertext_root = derive_protocol_hash(
        "EncryptedAggregateShareCiphertextRoot",
        &json!({
            "purpose": "sealed-lattice-encrypted-aggregate-share-ciphertext-root-v1",
            "aggregateDerivationComponentHash": aggregate_derivation_component_hash,
            "aggregateDerivationStatementHash": aggregate_derivation_statement_hash,
            "postVotingClosedContextHash": post_voting_closed_context_hash,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "thresholdProfileHash": threshold_profile_hash,
            "targetThresholdDecryptabilityCertificateHash": target_threshold_decryptability_certificate_hash,
            "collectivePublicKeyRoot": collective_public_key_root,
            "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
            "bgvPublicKeyRoot": bgv_public_key_root,
            "plaintextRoot": plaintext_root,
            "ciphertextRoot": ciphertext_root,
            "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
            "bgvProfileHash": profile_hash()?,
            "rustBgvBackendProfileHash": backend_profile_hash()?,
        }),
    )?;

    let sampled_relation_check_count = sampled_relation_checks.len();
    let mut result = json!({
        "ok": true,
        "operation": "generateAggregateBridgeEncryption",
        "profileHash": profile_hash()?,
        "rustBgvBackendProfileHash": backend_profile_hash()?,
        "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "plaintextRoot": plaintext_root,
        "ciphertextRoot": ciphertext_root,
        "encryptedAggregateShareCiphertextRoot": encrypted_aggregate_share_ciphertext_root,
        "targetThresholdDecryptabilityCertificateHash": target_threshold_decryptability_certificate_hash,
        "targetDecryptabilityStatus": "TargetThresholdDecryptabilityCompatibilityCertified",
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
        "basisId": BgvBasisKind::Data.basis_id(),
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "suppliedSlotCount": reduced_aggregate_slots.len(),
        "slotCount": POLYNOMIAL_DEGREE,
        "batchEncodingRelation": INTEGER_LIFTED_BATCH_ENCODING_RELATION,
        "batchEncodingBoundCertificate": batch_encoding_bound_certificate,
        "batchEncodingBoundCertificateHash": batch_encoding_bound_certificate_hash,
        "sampledPublicRelationChecks": sampled_relation_checks,
        "sampledPublicRelationCheckPolicy": {
            "objectType": "AggregateBridgeSampledRelationCheckPolicy",
            "objectVersion": 1,
            "diagnosticOnly": true,
            "acceptedForBridgeProofVerification": false,
            "fullBridgeProofRequired": true,
            "sampledOnlyBridgeVerificationAccepted": false,
            "relationCheckSource": "first-data-prime-diagnostic",
            "sampledRelationCheckCount": sampled_relation_check_count
        },
        "privateMaterialDisclosure": {
            "aggregateOpeningMaterialExported": false,
            "aggregateShareMaterialExported": false,
            "layoutMessageMaterialExported": false,
            "encodedMessageMaterialExported": false,
            "encryptionRandomizerMaterialExported": false,
            "noiseMaterialExported": false
        },
        "statusLabels": [
            "AggregateBridgePlaintextAssembled",
            "AggregateBridgeCiphertextGenerated",
            "CollectivePublicKeyRootBound",
            "BgvPublicKeyCoefficientMaterialBound",
            "DecryptableBgvCiphertextConvention",
            "TargetThresholdDecryptabilityCompatibilityCertified",
            "PassiveCollectiveBgvCiphertextEquationRelation",
            "BgvRandomnessBoundProofMissing",
            "CoefficientDomainCanonical",
            "BridgeProofBackendStillRequired"
        ],
    });
    if include_canonical_bytes_hex {
        result["canonicalBytesHex"] = Value::String(canonical_bytes_hex(&canonical_bytes));
    }

    let trace = EncryptedAggregateBridgeCiphertextRelationTrace {
        public_artifact: result,
        supplied_plaintext_slots: reduced_aggregate_slots.to_vec(),
        padded_plaintext_slots: encoded.slots,
        plaintext_coefficients_mod_plaintext: encoded.coefficients_mod_plaintext,
        plaintext_encoding_quotients,
        encryption_randomness_coefficients,
        encryption_error_zero_coefficients,
        encryption_error_one_coefficients,
    };
    trace.validate_private_preflight()?;

    Ok(trace)
}

pub(crate) fn encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses(
    reduced_slot_response: &[BigInt],
    plaintext_coefficient_response: &[BigInt],
    plaintext_encoding_quotient_response: &[BigInt],
) -> CanonicalResult<String> {
    if reduced_slot_response.len() > POLYNOMIAL_DEGREE
        || plaintext_coefficient_response.len() != POLYNOMIAL_DEGREE
        || plaintext_encoding_quotient_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge batch encoding proof response dimensions are invalid",
        ));
    }
    let commitment_coefficients_by_modulus = INTEGER_LIFTED_BATCH_PROOF_MODULI
        .iter()
        .map(|proof_modulus| {
            batch_encoding_commitment_coefficients_from_responses_modulus(
                reduced_slot_response,
                plaintext_coefficient_response,
                plaintext_encoding_quotient_response,
                *proof_modulus,
            )
            .map(|commitment_coefficients| {
                json!({
                    "proofModulus": proof_modulus,
                    "commitmentCoefficients": commitment_coefficients
                        .iter()
                        .map(|coefficient| coefficient.to_string())
                        .collect::<Vec<_>>(),
                })
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-integer-lifted-batch-encoding-commitment-v1",
            "batchEncodingRelation": INTEGER_LIFTED_BATCH_ENCODING_RELATION,
            "proofModuli": INTEGER_LIFTED_BATCH_PROOF_MODULI,
            "proofModulusProduct": integer_lifted_batch_proof_modulus_product_decimal(),
            "plaintextModulus": PLAINTEXT_MODULUS,
            "activeSlotCount": reduced_slot_response.len(),
            "commitmentCoefficientsByModulus": commitment_coefficients_by_modulus,
        }),
    )
}

fn batch_encoding_commitment_coefficients_from_responses_modulus(
    reduced_slot_response: &[BigInt],
    plaintext_coefficient_response: &[BigInt],
    plaintext_encoding_quotient_response: &[BigInt],
    proof_modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let proof_modulus_bigint = BigInt::from(proof_modulus);
    let mut commitment_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    accumulate_batch_basis_responses_mod_proof_modulus(
        reduced_slot_response,
        proof_modulus,
        &proof_modulus_bigint,
        &mut commitment_coefficients,
    )?;
    let plaintext_modulus_residue = PLAINTEXT_MODULUS % proof_modulus;
    for ((commitment_coefficient, plaintext_response), quotient_response) in commitment_coefficients
        .iter_mut()
        .zip(plaintext_coefficient_response.iter())
        .zip(plaintext_encoding_quotient_response.iter())
    {
        let plaintext_response_residue =
            signed_bigint_to_modulus_residue(plaintext_response, &proof_modulus_bigint);
        let quotient_response_residue =
            signed_bigint_to_modulus_residue(quotient_response, &proof_modulus_bigint);
        let scaled_quotient_response = mul_mod(
            plaintext_modulus_residue,
            quotient_response_residue,
            proof_modulus,
        )?;
        *commitment_coefficient = sub_mod(
            *commitment_coefficient,
            plaintext_response_residue,
            proof_modulus,
        )?;
        *commitment_coefficient = sub_mod(
            *commitment_coefficient,
            scaled_quotient_response,
            proof_modulus,
        )?;
    }

    Ok(commitment_coefficients)
}

pub(crate) fn encrypted_aggregate_bridge_batch_lift_bound_certificate_value(
    active_slot_count: usize,
) -> CanonicalResult<Value> {
    if active_slot_count > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge active slot count exceeds the selected polynomial degree",
        ));
    }
    let maximum_basis_coefficient = PLAINTEXT_MODULUS - 1;
    let maximum_reduced_coordinate = PLAINTEXT_MODULUS - 1;
    let maximum_plaintext_coefficient = PLAINTEXT_MODULUS - 1;
    let maximum_batch_sum = u128::try_from(active_slot_count)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge active slot count does not fit u128",
            )
        })?
        .checked_mul(u128::from(maximum_reduced_coordinate))
        .and_then(|value| value.checked_mul(u128::from(maximum_basis_coefficient)))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge batch sum bound overflowed",
            )
        })?;
    let batch_quotient_bound = batch_encoding_quotient_bound(active_slot_count)?;
    if maximum_batch_sum >= INTEGER_LIFTED_BATCH_PROOF_MODULUS_PRODUCT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge integer-lifted batch relation can wrap the selected proof modulus product",
        ));
    }
    let safe_no_wrap_margin = INTEGER_LIFTED_BATCH_PROOF_MODULUS_PRODUCT - maximum_batch_sum;

    Ok(json!({
        "objectType": "AggregateBridgeIntegerLiftedBatchBoundCertificate",
        "objectVersion": 1,
        "batchEncodingRelation": INTEGER_LIFTED_BATCH_ENCODING_RELATION,
        "activeSlotCount": active_slot_count,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "maxBasisCoefficient": maximum_basis_coefficient,
        "maxReducedCoordinate": maximum_reduced_coordinate,
        "maxPlaintextCoefficient": maximum_plaintext_coefficient,
        "maxBatchSum": maximum_batch_sum.to_string(),
        "batchQuotientBound": batch_quotient_bound,
        "proofModuli": INTEGER_LIFTED_BATCH_PROOF_MODULI,
        "proofModulusProduct": integer_lifted_batch_proof_modulus_product_decimal(),
        "safeNoWrapMargin": safe_no_wrap_margin.to_string(),
        "verifierChecked": true,
        "claimBearingBridgeClosureAccepted": false,
    }))
}

fn integer_lifted_batch_proof_modulus_product_decimal() -> String {
    INTEGER_LIFTED_BATCH_PROOF_MODULUS_PRODUCT.to_string()
}

pub(crate) fn encrypted_aggregate_bridge_batch_lift_bound_certificate_hash(
    certificate: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-integer-lifted-batch-bound-certificate-v1",
            "certificate": certificate,
        }),
    )
}

fn derive_plaintext_encoding_quotients(
    supplied_slots: &[u64],
    plaintext_coefficients: &[u64],
) -> CanonicalResult<Vec<u64>> {
    if plaintext_coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge plaintext coefficient count does not match the selected polynomial degree",
        ));
    }
    let basis_sums = batch_basis_integer_sums(supplied_slots)?;
    let quotient_bound = batch_encoding_quotient_bound(supplied_slots.len())?;
    basis_sums
        .iter()
        .zip(plaintext_coefficients.iter())
        .map(|(basis_sum, plaintext_coefficient)| {
            let plaintext_coefficient = u128::from(*plaintext_coefficient);
            if *basis_sum < plaintext_coefficient {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "encrypted aggregate bridge integer-lifted batch relation has a negative quotient",
                ));
            }
            let numerator = basis_sum - plaintext_coefficient;
            let plaintext_modulus = u128::from(PLAINTEXT_MODULUS);
            if numerator % plaintext_modulus != 0 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "encrypted aggregate bridge integer-lifted batch relation is not divisible by the plaintext modulus",
                ));
            }
            let quotient = numerator / plaintext_modulus;
            let quotient = u64::try_from(quotient).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "encrypted aggregate bridge batch quotient does not fit u64",
                )
            })?;
            if quotient > quotient_bound {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "encrypted aggregate bridge batch quotient exceeds its verifier-bound certificate",
                ));
            }

            Ok(quotient)
        })
        .collect()
}

fn batch_basis_integer_sums(supplied_slots: &[u64]) -> CanonicalResult<Vec<u128>> {
    if supplied_slots.len() > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge batch basis received too many active slots",
        ));
    }
    let mut sums = vec![0_u128; POLYNOMIAL_DEGREE];
    for (slot_index, slot_value) in supplied_slots.iter().enumerate() {
        if *slot_value == 0 {
            continue;
        }
        let mut basis_coefficient = batch_basis_initial_coefficient()?;
        let basis_ratio = batch_basis_ratio_for_slot(slot_index)?;
        for sum in &mut sums {
            *sum = sum
                .checked_add(u128::from(*slot_value) * u128::from(basis_coefficient))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "encrypted aggregate bridge batch basis sum overflowed",
                    )
                })?;
            basis_coefficient = mul_mod(basis_coefficient, basis_ratio, PLAINTEXT_MODULUS)?;
        }
    }

    Ok(sums)
}

fn accumulate_batch_basis_responses_mod_proof_modulus(
    supplied_slot_responses: &[BigInt],
    proof_modulus: u64,
    proof_modulus_bigint: &BigInt,
    commitment_coefficients: &mut [u64],
) -> CanonicalResult<()> {
    if commitment_coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge commitment coefficient count does not match the selected polynomial degree",
        ));
    }
    for (slot_index, slot_response) in supplied_slot_responses.iter().enumerate() {
        let slot_response_residue =
            signed_bigint_to_modulus_residue(slot_response, proof_modulus_bigint);
        if slot_response_residue == 0 {
            continue;
        }
        let mut basis_coefficient = batch_basis_initial_coefficient()?;
        let basis_ratio = batch_basis_ratio_for_slot(slot_index)?;
        for commitment_coefficient in commitment_coefficients.iter_mut() {
            let scaled_basis = mul_mod(slot_response_residue, basis_coefficient, proof_modulus)?;
            *commitment_coefficient =
                add_mod(*commitment_coefficient, scaled_basis, proof_modulus)?;
            basis_coefficient = mul_mod(basis_coefficient, basis_ratio, PLAINTEXT_MODULUS)?;
        }
    }

    Ok(())
}

fn batch_basis_initial_coefficient() -> CanonicalResult<u64> {
    let root_parameters = crate::bgv::profile::root_parameters_for_modulus(PLAINTEXT_MODULUS)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "plaintext modulus is missing BGV batch encoder root parameters",
            )
        })?;

    Ok(root_parameters.inverse_polynomial_degree)
}

fn batch_basis_ratio_for_slot(slot_index: usize) -> CanonicalResult<u64> {
    let root_parameters = crate::bgv::profile::root_parameters_for_modulus(PLAINTEXT_MODULUS)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "plaintext modulus is missing BGV batch encoder root parameters",
            )
        })?;
    let inverse_slot_cyclic_root = crate::bgv::modular_arithmetic::pow_mod(
        root_parameters.inverse_cyclic_root,
        u64::try_from(slot_index).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge slot index does not fit u64",
            )
        })?,
        PLAINTEXT_MODULUS,
    )?;

    mul_mod(
        root_parameters.inverse_negacyclic_root,
        inverse_slot_cyclic_root,
        PLAINTEXT_MODULUS,
    )
}

fn batch_encoding_quotient_bound(active_slot_count: usize) -> CanonicalResult<u64> {
    u64::try_from(active_slot_count)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge active slot count does not fit u64",
            )
        })?
        .checked_mul(PLAINTEXT_MODULUS - 1)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge batch quotient bound overflowed",
            )
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypted_aggregate_bridge_ciphertext_commitment_hash_from_responses(
    setup_package: &Value,
    _contributor_identity: &str,
    _aggregate_derivation_statement_hash: &str,
    bridge_encryption: &Value,
    challenge_scalar: u64,
    plaintext_coefficient_response: &[BigInt],
    randomizer_response: &[BigInt],
    perturbation_zero_response: &[BigInt],
    perturbation_one_response: &[BigInt],
) -> CanonicalResult<String> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    if plaintext_coefficient_response.len() != POLYNOMIAL_DEGREE
        || randomizer_response.len() != POLYNOMIAL_DEGREE
        || perturbation_zero_response.len() != POLYNOMIAL_DEGREE
        || perturbation_one_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge ciphertext proof response dimensions are invalid",
        ));
    }
    let canonical_bytes_hex = string_at_path(bridge_encryption, &["canonicalBytesHex"])?;
    let ciphertext = parse_bgv_object_hex(canonical_bytes_hex)?;
    if ciphertext.object_kind != BgvObjectKind::Ciphertext || ciphertext.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate bridge proof response verifier requires a two-component ciphertext",
        ));
    }
    for component in &ciphertext.components {
        component.validate()?;
        if component.basis_id != BgvBasisKind::Data.basis_id()
            || component.level != DATA_PRIMES.len() - 1
            || component.moduli != DATA_PRIMES
            || component.residues_by_modulus.len() != DATA_PRIMES.len()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate bridge proof ciphertext must cover the full data basis",
            ));
        }
    }

    let mut component_zero_residues_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
    let mut component_one_residues_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
    let collective_key_coefficients_by_modulus =
        super::key_material::collective_public_key_coefficients_by_modulus_from_setup_package(
            setup_package,
        )?;

    for (modulus_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let modulus_bigint = BigInt::from(modulus);
        let collective_key_coefficients = collective_key_coefficients_by_modulus
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "encrypted aggregate bridge proof collective public key coefficient table is missing a data limb",
                )
            })?;
        let public_key_coefficients = &collective_key_coefficients.component_zero_coefficients;
        let public_sample_coefficients = &collective_key_coefficients.component_one_coefficients;
        let randomizer_residues = randomizer_response
            .iter()
            .map(|coefficient| signed_bigint_to_modulus_residue(coefficient, &modulus_bigint))
            .collect::<Vec<_>>();
        let scaled_perturbation_zero_residues = perturbation_zero_response
            .iter()
            .map(|coefficient| {
                signed_bigint_to_plaintext_scaled_residue(coefficient, &modulus_bigint, modulus)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let scaled_perturbation_one_residues = perturbation_one_response
            .iter()
            .map(|coefficient| {
                signed_bigint_to_plaintext_scaled_residue(coefficient, &modulus_bigint, modulus)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let plaintext_response_residues = plaintext_coefficient_response
            .iter()
            .map(|coefficient| signed_bigint_to_modulus_residue(coefficient, &modulus_bigint))
            .collect::<Vec<_>>();
        let public_key_product =
            negacyclic_product_mod(public_key_coefficients, &randomizer_residues, modulus)?;
        let public_sample_product =
            negacyclic_product_mod(public_sample_coefficients, &randomizer_residues, modulus)?;
        let challenge_residue = challenge_scalar % modulus;
        let ciphertext_component_zero = ciphertext.components[0]
            .residues_by_modulus
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "encrypted aggregate bridge proof ciphertext component zero is missing a data limb",
                )
            })?;
        let ciphertext_component_one = ciphertext.components[1]
            .residues_by_modulus
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "encrypted aggregate bridge proof ciphertext component one is missing a data limb",
                )
            })?;

        // Sigma-protocol verification: recompute the commitment from the
        // responses as A = response*base - challenge*statement. Per limb that is
        // A = (pk*z_r + z_pert + z_m) - c*ct (z_r randomizer, z_m plaintext
        // response, z_pert noise perturbation, c challenge, ct the ciphertext).
        let commitment_zero = public_key_product
            .iter()
            .zip(scaled_perturbation_zero_residues.iter())
            .zip(plaintext_response_residues.iter())
            .zip(ciphertext_component_zero.iter())
            .map(
                |(((product, scaled_perturbation), plaintext_response), ciphertext_coefficient)| {
                    let response_sum = add_mod(
                        add_mod(*product, *scaled_perturbation, modulus)?,
                        *plaintext_response,
                        modulus,
                    )?;
                    let scaled_ciphertext =
                        mul_mod(challenge_residue, *ciphertext_coefficient, modulus)?;
                    sub_mod(response_sum, scaled_ciphertext, modulus)
                },
            )
            .collect::<CanonicalResult<Vec<_>>>()?;
        let commitment_one = public_sample_product
            .iter()
            .zip(scaled_perturbation_one_residues.iter())
            .zip(ciphertext_component_one.iter())
            .map(|((product, scaled_perturbation), ciphertext_coefficient)| {
                let response_sum = add_mod(*product, *scaled_perturbation, modulus)?;
                let scaled_ciphertext =
                    mul_mod(challenge_residue, *ciphertext_coefficient, modulus)?;
                sub_mod(response_sum, scaled_ciphertext, modulus)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;

        component_zero_residues_by_modulus.push(commitment_zero);
        component_one_residues_by_modulus.push(commitment_one);
    }

    let layout_hash = layout_hash()?;
    let component_zero = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        DATA_PRIMES.len() - 1,
        layout_hash.clone(),
        component_zero_residues_by_modulus,
    )?;
    let component_one = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        DATA_PRIMES.len() - 1,
        layout_hash,
        component_one_residues_by_modulus,
    )?;
    let commitment_bytes =
        serialize_bgv_object(BgvObjectKind::Ciphertext, &[component_zero, component_one])?;

    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-bgv-ciphertext-commitment-v1",
            "commitmentRoot": ciphertext_root(&commitment_bytes),
            "commitmentCanonicalBytesHash512": canonical_bytes_hash(&commitment_bytes),
        }),
    )
}

fn signed_bigint_to_modulus_residue(value: &BigInt, modulus_bigint: &BigInt) -> u64 {
    let residue = ((value % modulus_bigint) + modulus_bigint) % modulus_bigint;

    residue
        .to_u64()
        .expect("non-negative BigInt residue below a u64 modulus fits u64")
}

fn signed_bigint_to_plaintext_scaled_residue(
    value: &BigInt,
    modulus_bigint: &BigInt,
    modulus: u64,
) -> CanonicalResult<u64> {
    mul_mod(
        PLAINTEXT_MODULUS % modulus,
        signed_bigint_to_modulus_residue(value, modulus_bigint),
        modulus,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_encrypted_aggregate_bridge_ciphertext_public_bindings(
    setup_package: &Value,
    aggregate_derivation_component_hash: &str,
    aggregate_derivation_statement_hash: &str,
    post_voting_closed_context_hash: &str,
    bridge_encryption: &Value,
) -> CanonicalResult<()> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;

    let collective_public_key_root = string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
    )?;
    let collective_public_key_coefficient_root = string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyCoefficientRoot"],
    )?;
    let bgv_public_key_root =
        string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?;
    let manifest_hash = string_at_path(setup_package, &["setupInputs", "manifestHash"])?;
    let roster_hash = string_at_path(setup_package, &["setupInputs", "rosterHash"])?;
    let threshold_profile_hash =
        string_at_path(setup_package, &["setupInputs", "thresholdProfileHash"])?;
    let target_threshold_decryptability_certificate_hash = string_at_path(
        setup_package,
        &[
            "certificates",
            "targetThresholdDecryptabilityCertificateHash",
        ],
    )?;
    let plaintext_root = string_at_path(bridge_encryption, &["plaintextRoot"])?;
    let ciphertext_root = string_at_path(bridge_encryption, &["ciphertextRoot"])?;
    let expected_encrypted_aggregate_share_ciphertext_root = derive_protocol_hash(
        "EncryptedAggregateShareCiphertextRoot",
        &json!({
            "purpose": "sealed-lattice-encrypted-aggregate-share-ciphertext-root-v1",
            "aggregateDerivationComponentHash": aggregate_derivation_component_hash,
            "aggregateDerivationStatementHash": aggregate_derivation_statement_hash,
            "postVotingClosedContextHash": post_voting_closed_context_hash,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "thresholdProfileHash": threshold_profile_hash,
            "targetThresholdDecryptabilityCertificateHash": target_threshold_decryptability_certificate_hash,
            "collectivePublicKeyRoot": collective_public_key_root,
            "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
            "bgvPublicKeyRoot": bgv_public_key_root,
            "plaintextRoot": plaintext_root,
            "ciphertextRoot": ciphertext_root,
            "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
            "bgvProfileHash": profile_hash()?,
            "rustBgvBackendProfileHash": backend_profile_hash()?,
        }),
    )?;

    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["profileHash"],
        &profile_hash()?,
        "BGV profile hash",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["rustBgvBackendProfileHash"],
        &backend_profile_hash()?,
        "Rust BGV backend profile hash",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["canonicalCiphertextConventionHash"],
        &canonical_ciphertext_convention_hash()?,
        "canonical ciphertext convention hash",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["collectivePublicKeyRoot"],
        collective_public_key_root,
        "collective public key root",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["collectivePublicKeyCoefficientRoot"],
        collective_public_key_coefficient_root,
        "collective public key coefficient root",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["bgvPublicKeyRoot"],
        bgv_public_key_root,
        "BGV public key root",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["targetThresholdDecryptabilityCertificateHash"],
        target_threshold_decryptability_certificate_hash,
        "target-threshold decryptability certificate hash",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["targetDecryptabilityStatus"],
        "TargetThresholdDecryptabilityCompatibilityCertified",
        "target-threshold decryptability status",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["basisId"],
        BgvBasisKind::Data.basis_id(),
        "ciphertext basis",
    )?;
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["batchEncodingRelation"],
        INTEGER_LIFTED_BATCH_ENCODING_RELATION,
        "batch encoding relation",
    )?;
    let supplied_slot_count = usize_at_path(bridge_encryption, &["suppliedSlotCount"])?;
    let expected_batch_encoding_bound_certificate =
        encrypted_aggregate_bridge_batch_lift_bound_certificate_value(supplied_slot_count)?;
    let batch_encoding_bound_certificate =
        value_at_path(bridge_encryption, &["batchEncodingBoundCertificate"])?;
    if batch_encoding_bound_certificate != &expected_batch_encoding_bound_certificate {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge batch encoding bound certificate does not match its active slot count",
        ));
    }
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["batchEncodingBoundCertificateHash"],
        &encrypted_aggregate_bridge_batch_lift_bound_certificate_hash(
            &expected_batch_encoding_bound_certificate,
        )?,
        "batch encoding bound certificate hash",
    )?;
    if usize_at_path(bridge_encryption, &["level"])? != DATA_PRIMES.len() - 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge ciphertext level does not match the full data basis",
        ));
    }
    if usize_at_path(bridge_encryption, &["suppliedSlotCount"])? > POLYNOMIAL_DEGREE
        || usize_at_path(bridge_encryption, &["coefficientCount"])? != POLYNOMIAL_DEGREE
        || usize_at_path(bridge_encryption, &["slotCount"])? != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge ciphertext dimensions do not match the selected BGV profile",
        ));
    }
    compare_encrypted_aggregate_bridge_string_at_path(
        bridge_encryption,
        &["encryptedAggregateShareCiphertextRoot"],
        &expected_encrypted_aggregate_share_ciphertext_root,
        "encrypted aggregate-share ciphertext root",
    )?;

    Ok(())
}

fn compare_encrypted_aggregate_bridge_string_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    let actual = string_at_path(value, path)?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "encrypted aggregate bridge {description} does not match its canonical binding"
            ),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    struct FirstDataLimbBridgeCiphertext {
        plaintext_coefficients: Vec<u64>,
        component_zero_coefficients: Vec<u64>,
        component_one_coefficients: Vec<u64>,
        raw_error_component_zero_coefficients: Vec<u64>,
        raw_error_component_one_coefficients: Vec<u64>,
        collective_secret_coefficients: Vec<i64>,
    }

    fn bridge_setup_request() -> Value {
        json!({
            "ceremonyId": "bridge-decryptability-ceremony",
            "manifestHash": derive_protocol_hash(
                "ElectionManifestHash",
                &json!({ "manifest": "bridge decryptability test" }),
            )
            .expect("manifest hash"),
            "rosterHash": derive_protocol_hash(
                "RosterHash",
                &json!({ "roster": "bridge decryptability test" }),
            )
            .expect("roster hash"),
            "thresholdProfileHash": derive_protocol_hash(
                "ThresholdProfileHash",
                &json!({ "threshold": "bridge decryptability test" }),
            )
            .expect("threshold hash"),
            "participants": [
                { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
                { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 4 },
                { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 5 }
            ],
            "setupSeed": "bridge-decryptability-test-seed",
        })
    }

    fn bridge_ciphertext_relation_trace(
        setup_package: &Value,
    ) -> EncryptedAggregateBridgeCiphertextRelationTrace {
        generate_encrypted_aggregate_bridge_ciphertext_relation_trace_from_slots(
            setup_package,
            "trustee-1",
            &"a".repeat(128),
            &"b".repeat(128),
            &"c".repeat(128),
            &[0, 1, 2, 65_536, 19, 200, 34, 55],
            "0123456789abcdeffedcba9876543210",
            true,
        )
        .expect("bridge ciphertext relation trace")
    }

    fn collective_secret_coefficients(setup_package: &Value) -> Vec<i64> {
        let setup_seed_hash = string_at_path(setup_package, &["setupInputs", "setupSeedHash"])
            .expect("setup seed hash");
        let participants = array_at_path(setup_package, &["participants"]).expect("participants");
        let mut collective_secret_coefficients = vec![0_i64; POLYNOMIAL_DEGREE];
        for participant in participants {
            let trustee_identity =
                string_at_path(participant, &["trusteeIdentity"]).expect("trustee identity");
            let local_secret_coefficients = dense_small_coefficients(
                setup_seed_hash,
                trustee_identity,
                "local-secret-share",
                -1,
                1,
            );
            for (collective_coefficient, local_coefficient) in collective_secret_coefficients
                .iter_mut()
                .zip(local_secret_coefficients.iter())
            {
                *collective_coefficient += *local_coefficient;
            }
        }

        collective_secret_coefficients
    }

    fn participant_identities(setup_package: &Value) -> Vec<String> {
        let participants = array_at_path(setup_package, &["participants"]).expect("participants");
        participants
            .iter()
            .map(|participant| {
                string_at_path(participant, &["trusteeIdentity"])
                    .expect("trustee identity")
                    .to_string()
            })
            .collect()
    }

    fn first_data_limb_bridge_ciphertext(setup_package: &Value) -> FirstDataLimbBridgeCiphertext {
        let data_modulus = DATA_PRIMES[0];
        let setup_seed_hash = string_at_path(setup_package, &["setupInputs", "setupSeedHash"])
            .expect("setup seed hash");
        let identities = participant_identities(setup_package);
        let (collective_secret_coefficients, collective_error_coefficients) =
            super::super::key_material::collective_signed_secret_and_error_coefficients(
                setup_seed_hash,
                &identities,
            );
        let collective_key_coefficients =
            super::super::key_material::collective_public_key_coefficients_from_signed(
                setup_seed_hash,
                &collective_secret_coefficients,
                &collective_error_coefficients,
                data_modulus,
            )
            .expect("collective public key coefficients");
        let encoded = encode_batch_plaintext_slots(&[0, 1, 2, 65_536, 19, 200, 34, 55], 0)
            .expect("batch plaintext");
        let plaintext_coefficients = encoded
            .polynomial
            .residues_by_modulus
            .first()
            .expect("first data limb plaintext")
            .clone();
        let encryption_seed_hash = hash512_hex(
            "sealed-lattice-bgv-rns/aggregate-bridge-encryption-seed-v1",
            &[
                setup_seed_hash.as_bytes(),
                b"trustee-1",
                b"a",
                b"b",
                b"c",
                b"0123456789abcdeffedcba9876543210",
            ],
        );
        let randomizer_coefficients = dense_small_coefficients(
            &encryption_seed_hash,
            "aggregate-bridge-encryption",
            "encryption-randomness",
            -1,
            1,
        );
        let error_zero_coefficients = dense_centered_binomial_coefficients(
            &encryption_seed_hash,
            "aggregate-bridge-encryption",
            "encryption-error-zero",
        );
        let error_one_coefficients = dense_centered_binomial_coefficients(
            &encryption_seed_hash,
            "aggregate-bridge-encryption",
            "encryption-error-one",
        );
        let randomizer_residues = randomizer_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, data_modulus))
            .collect::<Vec<_>>();
        let scaled_error_zero_residues = error_zero_coefficients
            .iter()
            .map(|coefficient| signed_to_plaintext_scaled_residue(*coefficient, data_modulus))
            .collect::<CanonicalResult<Vec<_>>>()
            .expect("scaled error zero");
        let scaled_error_one_residues = error_one_coefficients
            .iter()
            .map(|coefficient| signed_to_plaintext_scaled_residue(*coefficient, data_modulus))
            .collect::<CanonicalResult<Vec<_>>>()
            .expect("scaled error one");
        let raw_error_zero_residues = error_zero_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, data_modulus))
            .collect::<Vec<_>>();
        let raw_error_one_residues = error_one_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, data_modulus))
            .collect::<Vec<_>>();
        let public_key_product = negacyclic_product_mod(
            &collective_key_coefficients.component_zero_coefficients,
            &randomizer_residues,
            data_modulus,
        )
        .expect("public key product");
        let public_sample_product = negacyclic_product_mod(
            &collective_key_coefficients.component_one_coefficients,
            &randomizer_residues,
            data_modulus,
        )
        .expect("public sample product");
        let component_zero_coefficients = public_key_product
            .iter()
            .zip(scaled_error_zero_residues.iter())
            .zip(plaintext_coefficients.iter())
            .map(|((product, scaled_error), plaintext_coefficient)| {
                add_mod(
                    add_mod(*product, *scaled_error, data_modulus).expect("add scaled error"),
                    *plaintext_coefficient,
                    data_modulus,
                )
                .expect("add plaintext")
            })
            .collect::<Vec<_>>();
        let component_one_coefficients = public_sample_product
            .iter()
            .zip(scaled_error_one_residues.iter())
            .map(|(product, scaled_error)| {
                add_mod(*product, *scaled_error, data_modulus).expect("add scaled error")
            })
            .collect::<Vec<_>>();
        let raw_error_component_zero_coefficients = public_key_product
            .iter()
            .zip(raw_error_zero_residues.iter())
            .zip(plaintext_coefficients.iter())
            .map(|((product, raw_error), plaintext_coefficient)| {
                add_mod(
                    add_mod(*product, *raw_error, data_modulus).expect("add raw error"),
                    *plaintext_coefficient,
                    data_modulus,
                )
                .expect("add plaintext")
            })
            .collect::<Vec<_>>();
        let raw_error_component_one_coefficients = public_sample_product
            .iter()
            .zip(raw_error_one_residues.iter())
            .map(|(product, raw_error)| {
                add_mod(*product, *raw_error, data_modulus).expect("add raw error")
            })
            .collect::<Vec<_>>();

        FirstDataLimbBridgeCiphertext {
            plaintext_coefficients,
            component_zero_coefficients,
            component_one_coefficients,
            raw_error_component_zero_coefficients,
            raw_error_component_one_coefficients,
            collective_secret_coefficients,
        }
    }

    fn shared_first_data_limb_bridge_ciphertext() -> &'static FirstDataLimbBridgeCiphertext {
        static FIRST_DATA_LIMB_CIPHERTEXT: OnceLock<FirstDataLimbBridgeCiphertext> =
            OnceLock::new();
        FIRST_DATA_LIMB_CIPHERTEXT.get_or_init(|| {
            let setup_package =
                generate_passive_setup_package_from_request(&bridge_setup_request())
                    .expect("setup");

            first_data_limb_bridge_ciphertext(&setup_package)
        })
    }

    fn decrypt_first_data_limb_coefficients(
        component_zero_coefficients: &[u64],
        component_one_coefficients: &[u64],
        collective_secret_coefficients: &[i64],
    ) -> Vec<u64> {
        let data_modulus = DATA_PRIMES[0];
        let collective_secret_residues = collective_secret_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, data_modulus))
            .collect::<Vec<_>>();
        let secret_product = negacyclic_product_mod(
            component_one_coefficients,
            &collective_secret_residues,
            data_modulus,
        )
        .expect("secret product");

        component_zero_coefficients
            .iter()
            .zip(secret_product.iter())
            .map(|(component_zero, product)| {
                let decrypted_residue =
                    add_mod(*component_zero, *product, data_modulus).expect("add decrypt term");
                centered_data_residue_to_plaintext(decrypted_residue, data_modulus)
            })
            .collect()
    }

    fn decrypt_trace_first_data_limb_coefficients(
        trace: &EncryptedAggregateBridgeCiphertextRelationTrace,
        collective_secret_coefficients: &[i64],
    ) -> Vec<u64> {
        let canonical_bytes_hex = string_at_path(&trace.public_artifact, &["canonicalBytesHex"])
            .expect("canonical bytes");
        let ciphertext = parse_bgv_object_hex(canonical_bytes_hex).expect("parse ciphertext");
        assert_eq!(ciphertext.object_kind, BgvObjectKind::Ciphertext);
        assert_eq!(ciphertext.components.len(), 2);
        let component_zero_coefficients = &ciphertext.components[0].residues_by_modulus[0];
        let component_one_coefficients = &ciphertext.components[1].residues_by_modulus[0];

        decrypt_first_data_limb_coefficients(
            component_zero_coefficients,
            component_one_coefficients,
            collective_secret_coefficients,
        )
    }

    fn centered_data_residue_to_plaintext(residue: u64, data_modulus: u64) -> u64 {
        let centered_residue = if residue > data_modulus / 2 {
            i128::from(residue) - i128::from(data_modulus)
        } else {
            i128::from(residue)
        };
        let plaintext_modulus = i128::from(PLAINTEXT_MODULUS);
        let reduced =
            ((centered_residue % plaintext_modulus) + plaintext_modulus) % plaintext_modulus;

        u64::try_from(reduced).expect("plaintext residue fits u64")
    }

    #[test]
    fn bridge_first_data_limb_decrypts_to_encoded_plaintext_under_setup_secret() {
        let first_data_limb_ciphertext = shared_first_data_limb_bridge_ciphertext();

        let decrypted_coefficients = decrypt_first_data_limb_coefficients(
            &first_data_limb_ciphertext.component_zero_coefficients,
            &first_data_limb_ciphertext.component_one_coefficients,
            &first_data_limb_ciphertext.collective_secret_coefficients,
        );

        assert_eq!(
            decrypted_coefficients,
            first_data_limb_ciphertext.plaintext_coefficients
        );
    }

    #[test]
    #[ignore = "full bridge ciphertext generation covers all data primes and is a manual closure check"]
    fn full_bridge_ciphertext_decrypts_to_encoded_plaintext_under_setup_secret() {
        let setup_package =
            generate_passive_setup_package_from_request(&bridge_setup_request()).expect("setup");
        let trace = bridge_ciphertext_relation_trace(&setup_package);
        let secret_coefficients = collective_secret_coefficients(&setup_package);

        let decrypted_coefficients =
            decrypt_trace_first_data_limb_coefficients(&trace, &secret_coefficients);

        assert_eq!(
            decrypted_coefficients,
            trace.plaintext_coefficients_mod_plaintext
        );
    }

    #[test]
    fn raw_error_bridge_ciphertext_formula_fails_decryptability_contract() {
        let first_data_limb_ciphertext = shared_first_data_limb_bridge_ciphertext();

        let decrypted_coefficients = decrypt_first_data_limb_coefficients(
            &first_data_limb_ciphertext.raw_error_component_zero_coefficients,
            &first_data_limb_ciphertext.raw_error_component_one_coefficients,
            &first_data_limb_ciphertext.collective_secret_coefficients,
        );

        assert!(
            decrypted_coefficients
                .iter()
                .zip(first_data_limb_ciphertext.plaintext_coefficients.iter())
                .any(|(decrypted_coefficient, plaintext_coefficient)| {
                    decrypted_coefficient != plaintext_coefficient
                }),
            "raw-error bridge encryption must not satisfy the decryptable BGV contract"
        );
    }

    #[test]
    fn integer_lifted_batch_commitment_rejects_coherent_plaintext_from_different_aggregate_slots() {
        let aggregate_slots = vec![5_u64, 7, 11, 13];
        let different_plaintext_slots = vec![6_u64, 7, 11, 13];
        let aggregate_encoding =
            encode_batch_plaintext_slots(&aggregate_slots, DATA_PRIMES.len() - 1)
                .expect("aggregate encoding");
        let different_encoding =
            encode_batch_plaintext_slots(&different_plaintext_slots, DATA_PRIMES.len() - 1)
                .expect("different encoding");
        let aggregate_quotients = derive_plaintext_encoding_quotients(
            &aggregate_slots,
            &aggregate_encoding.coefficients_mod_plaintext,
        )
        .expect("aggregate quotients");
        let different_quotients = derive_plaintext_encoding_quotients(
            &different_plaintext_slots,
            &different_encoding.coefficients_mod_plaintext,
        )
        .expect("different quotients");
        let zero_slot_response = vec![BigInt::from(0_u8); aggregate_slots.len()];
        let plaintext_coefficient_mask_response = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let plaintext_encoding_quotient_mask_response = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let honest_mask_commitment =
            encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses(
                &zero_slot_response,
                &plaintext_coefficient_mask_response,
                &plaintext_encoding_quotient_mask_response,
            )
            .expect("zero mask commitment should hash");
        let weak_challenge = BigInt::from(PLAINTEXT_MODULUS);
        let matching_aggregate_response = aggregate_slots
            .iter()
            .map(|slot| &weak_challenge * BigInt::from(*slot))
            .collect::<Vec<_>>();
        let matching_plaintext_response = aggregate_encoding
            .coefficients_mod_plaintext
            .iter()
            .map(|coefficient| &weak_challenge * BigInt::from(*coefficient))
            .collect::<Vec<_>>();
        let matching_quotient_response = aggregate_quotients
            .iter()
            .map(|quotient| &weak_challenge * BigInt::from(*quotient))
            .collect::<Vec<_>>();
        let matching_commitment =
            encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses(
                &matching_aggregate_response,
                &matching_plaintext_response,
                &matching_quotient_response,
            )
            .expect("matching weak challenge response should hash");
        let mismatched_plaintext_response = different_encoding
            .coefficients_mod_plaintext
            .iter()
            .map(|coefficient| &weak_challenge * BigInt::from(*coefficient))
            .collect::<Vec<_>>();
        let mismatched_quotient_response = different_quotients
            .iter()
            .map(|quotient| &weak_challenge * BigInt::from(*quotient))
            .collect::<Vec<_>>();
        let mismatched_commitment =
            encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses(
                &matching_aggregate_response,
                &mismatched_plaintext_response,
                &mismatched_quotient_response,
            )
            .expect("mismatched weak challenge response should hash");

        assert_eq!(matching_commitment, honest_mask_commitment);
        assert_ne!(mismatched_commitment, honest_mask_commitment);
    }
}
