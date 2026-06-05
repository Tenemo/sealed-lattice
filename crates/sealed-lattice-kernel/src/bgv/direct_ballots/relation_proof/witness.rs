use std::sync::OnceLock;

use super::*;

static DIRECT_BALLOT_SCORE_ENCODING_BASIS: OnceLock<Vec<Vec<u64>>> = OnceLock::new();

pub(super) fn direct_ballot_witness_vector(
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<DirectBallotWitnessVector> {
    Ok(DirectBallotWitnessVector {
        randomizer_coefficients: ballot
            .encryption_witness
            .randomizer_coefficients
            .iter()
            .map(|coefficient| BigInt::from(*coefficient))
            .collect(),
        error_zero_coefficients: ballot
            .encryption_witness
            .error_zero_coefficients
            .iter()
            .map(|coefficient| BigInt::from(*coefficient))
            .collect(),
        error_one_coefficients: ballot
            .encryption_witness
            .error_one_coefficients
            .iter()
            .map(|coefficient| BigInt::from(*coefficient))
            .collect(),
        encoding_carry_coefficients: direct_ballot_encoding_carry_coefficients(ballot)?,
        score_coefficients: ballot
            .input
            .scores
            .iter()
            .map(|coefficient| BigInt::from(*coefficient))
            .collect(),
        one_hot_coefficients: direct_ballot_one_hot_coefficients(ballot)?,
    })
}

pub(super) fn direct_ballot_encoding_carry_coefficients(
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<Vec<BigInt>> {
    let score_encoding_basis = direct_ballot_score_encoding_basis()?;
    let mut carry_coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let mut raw_coefficient = 0_i128;
        for (score, basis_polynomial) in ballot.input.scores.iter().zip(score_encoding_basis.iter())
        {
            raw_coefficient += i128::from(*score) * i128::from(basis_polynomial[coefficient_index]);
        }
        let plaintext_coefficient = i128::from(ballot.plaintext_coefficients[coefficient_index]);
        let difference = raw_coefficient - plaintext_coefficient;
        let plaintext_modulus = i128::from(PLAINTEXT_MODULUS);
        if difference % plaintext_modulus != 0 {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot encoding carry does not match the batch-encoded score polynomial",
            ));
        }
        carry_coefficients.push(BigInt::from(difference / plaintext_modulus));
    }

    Ok(carry_coefficients)
}

pub(super) fn direct_ballot_one_hot_coefficients(
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<Vec<Vec<BigInt>>> {
    match &ballot.input.one_hot_witnesses {
        Some(rows) => Ok(rows
            .iter()
            .map(|row| row.iter().map(|entry| BigInt::from(*entry)).collect())
            .collect()),
        None => ballot
            .input
            .scores
            .iter()
            .map(|score| {
                let selected_bucket = usize::try_from(score - 1).map_err(|_| {
                    invalid_direct_ballot_relation_proof(
                        "direct ballot score does not fit in a one-hot bucket index",
                    )
                })?;
                let mut row = vec![BigInt::zero(); DIRECT_BALLOT_SCORE_BUCKET_COUNT];
                if selected_bucket >= row.len() {
                    return Err(invalid_direct_ballot_relation_proof(
                        "direct ballot score is outside the one-hot bucket range",
                    ));
                }
                row[selected_bucket] = BigInt::from(1_u8);
                Ok(row)
            })
            .collect(),
    }
}

pub(super) fn direct_ballot_score_encoding_basis() -> CanonicalResult<&'static [Vec<u64>]> {
    if let Some(score_encoding_basis) = DIRECT_BALLOT_SCORE_ENCODING_BASIS.get() {
        return Ok(score_encoding_basis.as_slice());
    }

    let score_encoding_basis = (0..DIRECT_BALLOT_OPTION_COUNT)
        .map(|option_index| {
            let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
            slots[option_index] = 1;
            encode_slots_to_coefficients(&slots)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let _ = DIRECT_BALLOT_SCORE_ENCODING_BASIS.set(score_encoding_basis);

    Ok(DIRECT_BALLOT_SCORE_ENCODING_BASIS
        .get()
        .expect("direct ballot score encoding basis is initialized")
        .as_slice())
}

pub(super) fn validate_direct_ballot_witness_vector_shape(
    witness_vector: &DirectBallotWitnessVector,
) -> CanonicalResult<()> {
    for (label, polynomial) in [
        (
            "direct ballot relation randomizer",
            witness_vector.randomizer_coefficients.as_slice(),
        ),
        (
            "direct ballot relation first error polynomial",
            witness_vector.error_zero_coefficients.as_slice(),
        ),
        (
            "direct ballot relation second error polynomial",
            witness_vector.error_one_coefficients.as_slice(),
        ),
        (
            "direct ballot relation encoding carry polynomial",
            witness_vector.encoding_carry_coefficients.as_slice(),
        ),
    ] {
        if polynomial.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "{label} must match the polynomial degree"
            )));
        }
    }
    if witness_vector.score_coefficients.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation score response must have one scalar per option",
        ));
    }
    if witness_vector.one_hot_coefficients.len() != DIRECT_BALLOT_OPTION_COUNT {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation one-hot response must have one row per option",
        ));
    }
    for (option_index, row) in witness_vector.one_hot_coefficients.iter().enumerate() {
        if row.len() != DIRECT_BALLOT_SCORE_BUCKET_COUNT {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot relation one-hot response row {option_index} must have one scalar per score bucket"
            )));
        }
    }

    Ok(())
}

pub(super) fn direct_ballot_witness_polynomials(
    witness_vector: &DirectBallotWitnessVector,
) -> [&[BigInt]; DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS] {
    [
        witness_vector.randomizer_coefficients.as_slice(),
        witness_vector.error_zero_coefficients.as_slice(),
        witness_vector.error_one_coefficients.as_slice(),
        witness_vector.encoding_carry_coefficients.as_slice(),
    ]
}
