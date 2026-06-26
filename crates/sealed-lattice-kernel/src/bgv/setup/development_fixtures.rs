use super::*;

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
    let scaled_error_zero_residues = encryption_error_zero_coefficients
        .iter()
        .map(|coefficient| signed_to_plaintext_scaled_residue(*coefficient, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let scaled_error_one_residues = encryption_error_one_coefficients
        .iter()
        .map(|coefficient| signed_to_plaintext_scaled_residue(*coefficient, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
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
    let encrypted_ballot_aggregate_layout_hash = encrypted_ballot_aggregate_layout_hash()?;
    let component_zero = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        0,
        encrypted_ballot_aggregate_layout_hash.clone(),
        vec![ciphertext_component_zero],
    )?;
    let component_one = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        0,
        encrypted_ballot_aggregate_layout_hash,
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
    });
    let fixture_hash =
        derive_protocol_hash("BGVDevelopmentEncryptionFixtureHash", &fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureHash": fixture_hash,
    }))
}
