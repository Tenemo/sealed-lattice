use super::*;

pub(super) fn development_key_arithmetic_fixture(
    input: &PassiveSetupInput,
    fixture_id: &str,
    fixture_scope: &str,
    key_switch_decomposition_hash: &str,
) -> CanonicalResult<Value> {
    let modulus = DATA_PRIMES[0];
    let digit_base = 1_u64 << 23;
    let samples = sample_positions()
        .into_iter()
        .map(|position| {
            let source_coefficient =
                sample_residue(&input.setup_seed_hash, fixture_scope, position, modulus);
            let first_digit = source_coefficient % digit_base;
            let second_digit = (source_coefficient / digit_base) % digit_base;
            let third_digit = (source_coefficient / digit_base / digit_base) % digit_base;
            let recomposed =
                (first_digit + digit_base * second_digit + digit_base * digit_base * third_digit)
                    % modulus;
            let multiplier = sample_residue(
                &input.setup_seed_hash,
                &format!("{fixture_scope}-bgv-rns-multiplier"),
                position,
                modulus,
            );
            Ok(json!({
                "position": position,
                "modulus": modulus,
                "sourceCoefficient": source_coefficient,
                "decompositionDigits": [first_digit, second_digit, third_digit],
                "recomposedCoefficient": recomposed,
                "recompositionMatches": recomposed == source_coefficient,
                "rnsMulCheck": mul_mod(source_coefficient, multiplier, modulus)?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let fixture_record = json!({
        "objectType": "BgvDevelopmentKeyArithmeticFixture",
        "objectVersion": 1,
        "fixtureId": fixture_id,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "basisId": BgvBasisKind::Extended.basis_id(),
        "digitBaseBits": 23,
        "digitCountPerPrime": 3,
        "sampleModulus": modulus,
        "sampledCoefficientChecks": samples,
        "rnsArithmeticStatus": "sampled-decompose-recompose-and-modmul-passed",
        "protocolEvidence": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let fixture_hash = development_fixture_hash(&fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureHash": fixture_hash,
    }))
}

pub(super) fn development_encryption_fixture(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
) -> CanonicalResult<Value> {
    let message_slots = vec![1_u64, 2, 3, 5, 8, 13, 21, 34];
    let message = encode_batch_plaintext_slots(&message_slots, 0)?;
    let modulus = DATA_PRIMES[0];
    let public_key_coefficients = dense_public_residues(
        &input.setup_seed_hash,
        "development-collective-public-key-coefficients",
        modulus,
    );
    let public_sample_coefficients = dense_public_residues(
        &input.setup_seed_hash,
        "development-encryption-public-sample",
        modulus,
    );
    let encryption_randomness_coefficients = dense_small_coefficients(
        &input.setup_seed_hash,
        DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "encryption-randomness",
        -1,
        1,
    );
    let encryption_error_zero_coefficients = dense_centered_binomial_coefficients(
        &input.setup_seed_hash,
        DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "encryption-error-zero",
    );
    let encryption_error_one_coefficients = dense_centered_binomial_coefficients(
        &input.setup_seed_hash,
        DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "encryption-error-one",
    );
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
        negacyclic_product_mod(&public_key_coefficients, &randomness_residues, modulus)?;
    let public_sample_product =
        negacyclic_product_mod(&public_sample_coefficients, &randomness_residues, modulus)?;
    let message_residues = message
        .polynomial
        .residues_by_modulus
        .first()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "development encryption message has no data-basis residues",
            )
        })?;
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
    let layout_hash = layout_hash()?;
    let component_zero = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        0,
        layout_hash.clone(),
        vec![ciphertext_component_zero],
    )?;
    let component_one = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        0,
        layout_hash,
        vec![ciphertext_component_one],
    )?;
    let canonical_bytes =
        serialize_bgv_object(BgvObjectKind::Ciphertext, &[component_zero, component_one])?;
    let plaintext_bytes = serialize_bgv_object(
        BgvObjectKind::Plaintext,
        std::slice::from_ref(&message.polynomial),
    )?;
    let public_key_material_root = derive_protocol_hash(
        "BGVPublicKeyRoot",
        &json!({
            "fixtureId": DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
            "collectivePublicKeyRoot": string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?,
            "bgvPublicKeyRoot": string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?,
            "sampleModulus": modulus,
            "sampledPublicKeyCoefficients": sample_values(&public_key_coefficients),
            "sampledPublicEncryptionCoefficients": sample_values(&public_sample_coefficients),
        }),
    )?;
    let randomness_root = hash512_hex(
        "sealed-lattice-bgv-rns/development-encryption-randomness-root-v1",
        &[canonical_json(&json!({
            "fixtureId": DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
            "sampledRandomnessCoefficients": sample_signed_values(&encryption_randomness_coefficients),
            "sampledErrorZeroCoefficients": sample_signed_values(&encryption_error_zero_coefficients),
            "sampledErrorOneCoefficients": sample_signed_values(&encryption_error_one_coefficients),
        }))?.as_bytes()],
    );
    let fixture_record = json!({
        "objectType": "BgvDevelopmentEncryptionFixture",
        "objectVersion": 1,
        "fixtureId": DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?,
        "bgvPublicKeyRoot": string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?,
        "publicKeyMaterialRoot": public_key_material_root,
        "randomnessRoot": randomness_root,
        "plaintextRoot": plaintext_root(&plaintext_bytes),
        "ciphertextRoot": ciphertext_root(&canonical_bytes),
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
        "messageSlotSample": message_slots,
        "sampleModulus": modulus,
        "encryptionFormula": "c0=pk*u+e0+m,c1=a*u+e1-over-selected-level-zero-Q-data",
        "sampledPublicRelationChecks": sample_encryption_relation_checks(
            message_residues,
            &public_key_product,
            &public_sample_product,
            &error_zero_residues,
            &error_one_residues,
        )?,
        "fixtureScope": "development-collective-public-key-encryption-fixture",
        "bridgeEncryptionClaim": false,
        "encryptedAggregateEvaluatorClaim": false,
    });
    let fixture_hash =
        derive_protocol_hash("BGVDevelopmentEncryptionFixtureHash", &fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureHash": fixture_hash,
        "statusLabels": [
            "DevelopmentEncryptionFixtureBound",
            "CollectivePublicKeyRootBound",
            "NotBridgeProofEvidence",
            "NotEvaluatorClosureEvidence"
        ],
    }))
}
