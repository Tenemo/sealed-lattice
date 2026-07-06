use super::*;

pub(super) fn verify_direct_ballot_aggregation(
    evaluator_key: &DevelopmentBgvKey,
    encrypted_ballots: &[DirectEncryptedBallot],
) -> CanonicalResult<DirectBallotAggregationResult> {
    let mut aggregate_ciphertext = encrypted_ballots
        .first()
        .map(|ballot| ballot.ciphertext.clone())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot aggregation requires at least one ballot",
            )
        })?;
    for encrypted_ballot in encrypted_ballots.iter().skip(1) {
        aggregate_ciphertext = ciphertext_add(&aggregate_ciphertext, &encrypted_ballot.ciphertext)?;
    }

    let aggregate_slots = evaluator_key.decrypt_to_slots(&aggregate_ciphertext)?;
    let aggregate_scores = aggregate_slots[..OPTION_COUNT].to_vec();
    let expected_scores = direct_ballot_plaintext_aggregate_scores(encrypted_ballots)?;
    if aggregate_scores != expected_scores {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot aggregate scores do not match the plaintext oracle",
        ));
    }
    if aggregate_slots[OPTION_COUNT..]
        .iter()
        .any(|slot| *slot != 0)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct encrypted ballot aggregate has a non-zero reserved slot",
        ));
    }
    let aggregate_ciphertext_root = ciphertext_object_root(&aggregate_ciphertext)?;
    let aggregate_ciphertext_canonical_bytes_hex =
        ciphertext_canonical_bytes_hex(&aggregate_ciphertext)?;

    let report = json!({
        "ballotCount": encrypted_ballots.len(),
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "aggregateCiphertextCanonicalByteLength": aggregate_ciphertext_canonical_bytes_hex.len() / 2
    });

    Ok(DirectBallotAggregationResult {
        report,
        aggregate_ciphertext,
        aggregate_scores,
    })
}

pub(super) fn direct_ballot_plaintext_aggregate_scores(
    encrypted_ballots: &[DirectEncryptedBallot],
) -> CanonicalResult<Vec<u64>> {
    let mut aggregate_scores = vec![0_u64; OPTION_COUNT];
    for encrypted_ballot in encrypted_ballots {
        if encrypted_ballot.input.scores.len() != OPTION_COUNT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot aggregate oracle requires each ballot to have twenty scores",
            ));
        }
        for (aggregate_score, score) in aggregate_scores
            .iter_mut()
            .zip(encrypted_ballot.input.scores.iter())
        {
            *aggregate_score = add_mod(*aggregate_score, *score, PLAINTEXT_MODULUS)?;
        }
    }

    Ok(aggregate_scores)
}
