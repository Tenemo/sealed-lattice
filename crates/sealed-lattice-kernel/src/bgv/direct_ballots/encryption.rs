use super::*;

pub(super) fn encrypt_direct_ballot(
    evaluator_key: &DevelopmentBgvKey,
    ballot: DirectBallotInput,
) -> CanonicalResult<DirectEncryptedBallot> {
    validate_direct_ballot_input(&ballot)?;
    let slots = direct_ballot_slots(&ballot.scores);
    let plaintext_coefficients = encode_slots_to_coefficients(&slots)?;
    let (ciphertext, _) = evaluator_key
        .encrypt_coefficients_with_witness(&plaintext_coefficients, &ballot.encryption_seed_hex)?;
    Ok(DirectEncryptedBallot { ciphertext })
}

pub(super) fn validate_direct_ballot_input(ballot: &DirectBallotInput) -> CanonicalResult<()> {
    if ballot.scores.len() != OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot requires exactly twenty scores",
        ));
    }
    for (option_index, score) in ballot.scores.iter().enumerate() {
        if !(MINIMUM_SCORE..=MAXIMUM_SCORE).contains(score) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
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
    if scores.len() != OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot one-hot witness requires one score per option",
        ));
    }
    if one_hot_witnesses.len() != OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot one-hot witness must have one row per option",
        ));
    }
    for (option_index, one_hot_row) in one_hot_witnesses.iter().enumerate() {
        if one_hot_row.len() != SCORE_BUCKET_COUNT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot one-hot witness rows must have ten entries",
            ));
        }
        if one_hot_row.iter().any(|entry| *entry > 1) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "direct encrypted ballot one-hot witness entries must be zero or one",
            ));
        }
        let one_hot_sum = one_hot_row.iter().sum::<u64>();
        if one_hot_sum != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
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
                CanonicalErrorCode::InvalidProtocolObject,
                "direct encrypted ballot one-hot witness does not match its scalar score",
            ));
        }
    }

    Ok(())
}
