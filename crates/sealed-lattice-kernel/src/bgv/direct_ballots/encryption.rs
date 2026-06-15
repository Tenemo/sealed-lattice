use super::*;

pub(super) fn encrypt_direct_ballot(
    setup_package: &Value,
    public_key: &BgvPublicKey,
    ballot: DirectBallotInput,
) -> CanonicalResult<DirectEncryptedBallot> {
    validate_direct_ballot_input(&ballot)?;
    let slots = direct_ballot_slots(&ballot.scores);
    let plaintext_coefficients = encode_slots_to_coefficients(&slots)?;
    let (ciphertext, encryption_witness) = public_key
        .encrypt_coefficients_with_witness(&plaintext_coefficients, &ballot.encryption_seed_hex)?;
    let ciphertext_root = ciphertext_object_root(&ciphertext)?;
    let ciphertext_canonical_bytes_hex = ciphertext_canonical_bytes_hex(&ciphertext)?;
    let encrypted_ballot_hash = direct_encrypted_ballot_hash(
        setup_package,
        &ballot,
        &ciphertext_root,
        ciphertext_canonical_bytes_hex.len() / 2,
    )?;

    Ok(DirectEncryptedBallot {
        input: ballot,
        slots,
        plaintext_coefficients,
        ciphertext,
        encryption_witness,
        encrypted_ballot_hash,
        ciphertext_root,
        ciphertext_canonical_byte_length: ciphertext_canonical_bytes_hex.len() / 2,
    })
}

pub(super) fn validate_direct_ballot_input(ballot: &DirectBallotInput) -> CanonicalResult<()> {
    if ballot.scores.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot requires exactly twenty scores",
        ));
    }
    for (option_index, score) in ballot.scores.iter().enumerate() {
        if !(DIRECT_BALLOT_MINIMUM_SCORE..=DIRECT_BALLOT_MAXIMUM_SCORE).contains(score) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "direct encrypted ballot score at option {option_index} must be between 1 and 10"
                ),
            ));
        }
    }
    if let Some(one_hot_witnesses) = &ballot.one_hot_witnesses {
        validate_one_hot_witnesses(&ballot.scores, one_hot_witnesses)?;
    }

    Ok(())
}

pub(super) fn validate_one_hot_witnesses(
    scores: &[u64],
    one_hot_witnesses: &[Vec<u64>],
) -> CanonicalResult<()> {
    if one_hot_witnesses.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot one-hot witness must have one row per option",
        ));
    }
    for (option_index, one_hot_row) in one_hot_witnesses.iter().enumerate() {
        if one_hot_row.len() != DIRECT_BALLOT_SCORE_BUCKET_COUNT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot one-hot witness rows must have ten entries",
            ));
        }
        if one_hot_row.iter().any(|entry| *entry > 1) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness entries must be zero or one",
            ));
        }
        let one_hot_sum = one_hot_row.iter().sum::<u64>();
        if one_hot_sum != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness must select exactly one score",
            ));
        }
        // Bucket j (0-based) encodes score j+1 because the score domain is 1..=10; this maps the one-hot witness back to its scalar score.
        let derived_score = one_hot_row
            .iter()
            .enumerate()
            .map(|(score_index, indicator)| {
                u64::try_from(score_index + 1).expect("score index fits u64") * indicator
            })
            .sum::<u64>();
        if derived_score != scores[option_index] {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot one-hot witness does not match its scalar score",
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_direct_ballot_public_preflight(
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    if ballot.slots.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot slot vector must match the polynomial degree",
        ));
    }
    if ballot.slots[DIRECT_BALLOT_OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot reserved slots must be zero",
        ));
    }
    validate_encryption_witness_support(&ballot.encryption_witness)?;
    validate_all_limb_encryption_relation(public_key, ballot)
}

pub(super) fn validate_direct_ballot_development_preflight(
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    let decrypted_slots = evaluator_key.decrypt_to_slots(&ballot.ciphertext)?;
    if decrypted_slots[..DIRECT_BALLOT_OPTION_COUNT] != ballot.input.scores[..] {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot does not decrypt to the submitted score slots",
        ));
    }
    if decrypted_slots[DIRECT_BALLOT_OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot decrypts to a non-zero reserved slot",
        ));
    }

    Ok(())
}

// Support bounds: the randomizer is ternary {-1,0,1} and both errors are centered-binomial eta = 2 in [-2,2]; these are the bounds the relation proof certifies and they bound the decryption noise.
pub(super) fn validate_encryption_witness_support(
    witness: &EncryptionWitness,
) -> CanonicalResult<()> {
    validate_signed_support(
        &witness.randomizer_coefficients,
        1,
        "direct encrypted ballot randomizer",
    )?;
    validate_signed_support(
        &witness.error_zero_coefficients,
        2,
        "direct encrypted ballot first error polynomial",
    )?;
    validate_signed_support(
        &witness.error_one_coefficients,
        2,
        "direct encrypted ballot second error polynomial",
    )
}

pub(super) fn validate_signed_support(
    coefficients: &[i64],
    maximum_abs: i64,
    label: &str,
) -> CanonicalResult<()> {
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} must match the polynomial degree"),
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| coefficient.abs() > maximum_abs)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{label} has a coefficient outside the expected support"),
        ));
    }

    Ok(())
}

pub(super) fn validate_all_limb_encryption_relation(
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<()> {
    let (public_component_zero, public_component_one) = public_key.public_key_components();
    if ballot.ciphertext.components.len() != 2
        || ballot.ciphertext.components[0].len() != DATA_PRIMES.len()
        || ballot.ciphertext.components[1].len() != DATA_PRIMES.len()
        || public_component_zero.len() != DATA_PRIMES.len()
        || public_component_one.len() != DATA_PRIMES.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot RNS limb relation requires two full data-prime ciphertext components and a full public key",
        ));
    }
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        validate_limb_encryption_relation(
            ballot,
            public_component_zero,
            public_component_one,
            limb_index,
            modulus,
        )?;
    }

    Ok(())
}

pub(super) fn validate_limb_encryption_relation(
    ballot: &DirectEncryptedBallot,
    public_component_zero: &[Vec<u64>],
    public_component_one: &[Vec<u64>],
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<()> {
    let randomizer_residues = ballot
        .encryption_witness
        .randomizer_coefficients
        .iter()
        .map(|coefficient| signed_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let public_key_product = negacyclic_mul(
        &public_component_zero[limb_index],
        &randomizer_residues,
        modulus,
    )?;
    let public_sample_product = negacyclic_mul(
        &public_component_one[limb_index],
        &randomizer_residues,
        modulus,
    )?;
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        // BGV LSB encoding: the error is scaled by the plaintext modulus p while the message m is added raw, so c0 + c1*s = m + p*(...); decryption recovers m by centered reduction mod p.
        let expected_component_zero = add_mod(
            add_mod(
                public_key_product[coefficient_index],
                signed_residue(
                    ballot.encryption_witness.error_zero_coefficients[coefficient_index]
                        * i64::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits i64"),
                    modulus,
                ),
                modulus,
            )?,
            ballot.plaintext_coefficients[coefficient_index],
            modulus,
        )?;
        if expected_component_zero != ballot.ciphertext.components[0][limb_index][coefficient_index]
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("direct encrypted ballot RNS limb {limb_index} c0 relation failed"),
            ));
        }
        let expected_component_one = add_mod(
            public_sample_product[coefficient_index],
            signed_residue(
                ballot.encryption_witness.error_one_coefficients[coefficient_index]
                    * i64::try_from(PLAINTEXT_MODULUS).expect("plaintext modulus fits i64"),
                modulus,
            ),
            modulus,
        )?;
        if expected_component_one != ballot.ciphertext.components[1][limb_index][coefficient_index]
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("direct encrypted ballot RNS limb {limb_index} c1 relation failed"),
            ));
        }
    }

    Ok(())
}
