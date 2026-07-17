use super::*;

pub(super) fn aggregate_direct_encrypted_ballots(
    encrypted_ballots: &[DirectEncryptedBallot],
) -> CanonicalResult<Ciphertext> {
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

    Ok(aggregate_ciphertext)
}
