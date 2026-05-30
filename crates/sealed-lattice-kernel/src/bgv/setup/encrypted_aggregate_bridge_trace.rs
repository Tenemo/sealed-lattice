use super::validation;
use super::*;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

#[derive(Clone, Debug)]
pub(crate) struct EncryptedAggregateBridgeCiphertextRelationTrace {
    pub(crate) public_artifact: Value,
    pub(crate) supplied_plaintext_slots: Vec<u64>,
    pub(crate) padded_plaintext_slots: Vec<u64>,
    pub(crate) plaintext_coefficients_mod_plaintext: Vec<u64>,
    pub(crate) encryption_randomness_coefficients: Vec<i64>,
    pub(crate) encryption_error_zero_coefficients: Vec<i64>,
    pub(crate) encryption_error_one_coefficients: Vec<i64>,
}

impl EncryptedAggregateBridgeCiphertextRelationTrace {
    fn validate_shape(&self, supplied_slot_count: usize) -> CanonicalResult<()> {
        if self.supplied_plaintext_slots.len() != supplied_slot_count
            || self.padded_plaintext_slots.len() != POLYNOMIAL_DEGREE
            || self.plaintext_coefficients_mod_plaintext.len() != POLYNOMIAL_DEGREE
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
    let encoded = encode_batch_plaintext_slots(reduced_aggregate_slots, DATA_PRIMES.len() - 1)?;
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
        let error_zero_residues = encryption_error_zero_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let error_one_residues = encryption_error_one_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
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
        // Inline RLWE encryption under the collective public key (pk, a) with
        // randomizer u and errors e0, e1: c0 = pk*u + e0 + m, c1 = a*u + e1.
        let ciphertext_component_zero = public_key_product
            .iter()
            .zip(error_zero_residues.iter())
            .zip(message_residues.iter())
            .map(|((product, error), message_coefficient)| {
                add_mod(
                    add_mod(*product, *error, modulus)?,
                    *message_coefficient,
                    modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let ciphertext_component_one = public_sample_product
            .iter()
            .zip(error_one_residues.iter())
            .map(|(product, error)| add_mod(*product, *error, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;

        if modulus_index == 0 {
            sampled_relation_checks = sample_encryption_relation_checks(
                message_residues,
                &public_key_product,
                &public_sample_product,
                &error_zero_residues,
                &error_one_residues,
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
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
        "basisId": BgvBasisKind::Data.basis_id(),
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "suppliedSlotCount": reduced_aggregate_slots.len(),
        "slotCount": POLYNOMIAL_DEGREE,
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
            "NotThresholdDecryptableBridgeCiphertext",
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
        encryption_randomness_coefficients,
        encryption_error_zero_coefficients,
        encryption_error_one_coefficients,
    };
    trace.validate_shape(reduced_aggregate_slots.len())?;

    Ok(trace)
}

pub(crate) fn encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses(
    reduced_slot_response: &[BigInt],
    plaintext_coefficient_response: &[BigInt],
) -> CanonicalResult<String> {
    if reduced_slot_response.len() > POLYNOMIAL_DEGREE
        || plaintext_coefficient_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge batch encoding proof response dimensions are invalid",
        ));
    }
    let plaintext_modulus_bigint = BigInt::from(PLAINTEXT_MODULUS);
    let mut padded_slot_response = vec![0_u64; POLYNOMIAL_DEGREE];
    for (slot_index, response) in reduced_slot_response.iter().enumerate() {
        padded_slot_response[slot_index] =
            signed_bigint_to_modulus_residue(response, &plaintext_modulus_bigint);
    }
    let encoded_response_coefficients =
        inverse_negacyclic_ntt(&padded_slot_response, PLAINTEXT_MODULUS)?;
    let commitment_coefficients = encoded_response_coefficients
        .iter()
        .zip(plaintext_coefficient_response.iter())
        .map(|(encoded_response_coefficient, plaintext_response)| {
            let plaintext_response_residue =
                signed_bigint_to_modulus_residue(plaintext_response, &plaintext_modulus_bigint);
            sub_mod(
                *encoded_response_coefficient,
                plaintext_response_residue,
                PLAINTEXT_MODULUS,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-batch-encoding-commitment-v1",
            "commitmentCoefficients": commitment_coefficients
                .iter()
                .map(|coefficient| coefficient.to_string())
                .collect::<Vec<_>>(),
        }),
    )
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
        let perturbation_zero_residues = perturbation_zero_response
            .iter()
            .map(|coefficient| signed_bigint_to_modulus_residue(coefficient, &modulus_bigint))
            .collect::<Vec<_>>();
        let perturbation_one_residues = perturbation_one_response
            .iter()
            .map(|coefficient| signed_bigint_to_modulus_residue(coefficient, &modulus_bigint))
            .collect::<Vec<_>>();
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
            .zip(perturbation_zero_residues.iter())
            .zip(plaintext_response_residues.iter())
            .zip(ciphertext_component_zero.iter())
            .map(
                |(((product, perturbation), plaintext_response), ciphertext_coefficient)| {
                    let response_sum = add_mod(
                        add_mod(*product, *perturbation, modulus)?,
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
            .zip(perturbation_one_residues.iter())
            .zip(ciphertext_component_one.iter())
            .map(|((product, perturbation), ciphertext_coefficient)| {
                let response_sum = add_mod(*product, *perturbation, modulus)?;
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
        &["basisId"],
        BgvBasisKind::Data.basis_id(),
        "ciphertext basis",
    )?;
    if usize_at_path(bridge_encryption, &["level"])? != DATA_PRIMES.len() - 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge ciphertext level does not match the full data basis",
        ));
    }
    if usize_at_path(bridge_encryption, &["coefficientCount"])? != POLYNOMIAL_DEGREE
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

    #[test]
    fn batch_encoding_commitment_accepts_false_plaintext_when_challenge_is_zero_mod_plaintext_modulus()
     {
        let aggregate_slot_mask_response = vec![BigInt::from(0_u8)];
        let plaintext_coefficient_mask_response = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let honest_mask_commitment =
            encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses(
                &aggregate_slot_mask_response,
                &plaintext_coefficient_mask_response,
            )
            .expect("zero mask commitment should hash");

        let false_plaintext_witness = BigInt::from(1_u8);
        let weak_challenge = BigInt::from(PLAINTEXT_MODULUS);
        let weak_aggregate_slot_response = vec![BigInt::from(0_u8)];
        let mut weak_plaintext_coefficient_response = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        weak_plaintext_coefficient_response[0] = &weak_challenge * &false_plaintext_witness;
        let weak_commitment =
            encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses(
                &weak_aggregate_slot_response,
                &weak_plaintext_coefficient_response,
            )
            .expect("weak challenge response should hash");

        let ordinary_challenge = BigInt::from(1_u8);
        let ordinary_aggregate_slot_response = vec![BigInt::from(0_u8)];
        let mut ordinary_plaintext_coefficient_response =
            vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        ordinary_plaintext_coefficient_response[0] = &ordinary_challenge * &false_plaintext_witness;
        let ordinary_commitment =
            encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses(
                &ordinary_aggregate_slot_response,
                &ordinary_plaintext_coefficient_response,
            )
            .expect("ordinary challenge response should hash");

        assert_eq!(weak_commitment, honest_mask_commitment);
        assert_ne!(ordinary_commitment, honest_mask_commitment);
    }
}
