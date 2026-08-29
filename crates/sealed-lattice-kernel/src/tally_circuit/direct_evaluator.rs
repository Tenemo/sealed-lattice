use super::{
    TallyCircuitError, TallyCircuitProfile, TallyEvaluationInput, TallyEvaluationOutcome,
    bit_width_for_maximum_value, foundation_score_bounds,
};

pub(crate) fn evaluate_tally_directly(
    profile: TallyCircuitProfile,
    input: &TallyEvaluationInput,
) -> Result<TallyEvaluationOutcome, TallyCircuitError> {
    let (minimum_score, maximum_score) = foundation_score_bounds()?;
    let participant_count = usize::from(profile.participant_count());
    let option_count = usize::from(profile.option_count());
    let top_count = usize::from(profile.top_count());
    let participant_ballots = input.participant_ballots();

    if participant_ballots.len() != participant_count {
        return Err(TallyCircuitError::InputParticipantCountMismatch {
            expected: participant_count,
            actual: participant_ballots.len(),
        });
    }

    let score_bit_width = bit_width_for_maximum_value(usize::from(maximum_score));
    let maximum_score_encoding = (1_usize << score_bit_width) - 1;
    let mut aggregate_scores = vec![0_u32; option_count];
    let mut has_selected_ballot = false;

    for (participant_position, ballot) in participant_ballots.iter().enumerate() {
        if ballot.score_encodings().len() != option_count {
            return Err(TallyCircuitError::InputOptionCountMismatch {
                participant_position,
                expected: option_count,
                actual: ballot.score_encodings().len(),
            });
        }
        for (option_position, score_encoding) in
            ballot.score_encodings().iter().copied().enumerate()
        {
            if usize::from(score_encoding) > maximum_score_encoding {
                return Err(TallyCircuitError::ScoreEncodingOutOfRange {
                    participant_position,
                    option_position,
                    score_encoding,
                });
            }
        }

        let is_selected = ballot.is_present()
            && ballot
                .score_encodings()
                .iter()
                .copied()
                .all(|score_encoding| {
                    (minimum_score..=maximum_score).contains(&u16::from(score_encoding))
                });
        if is_selected {
            has_selected_ballot = true;
            for (aggregate_score, score_encoding) in aggregate_scores
                .iter_mut()
                .zip(ballot.score_encodings().iter().copied())
            {
                *aggregate_score = aggregate_score
                    .checked_add(u32::from(score_encoding))
                    .ok_or(TallyCircuitError::ArithmeticOverflow)?;
            }
        }
    }

    let mut ordered_option_positions = (0..option_count).collect::<Vec<_>>();
    ordered_option_positions.sort_by(|left_position, right_position| {
        aggregate_scores[*right_position]
            .cmp(&aggregate_scores[*left_position])
            .then_with(|| left_position.cmp(right_position))
    });
    let ordered_option_positions = ordered_option_positions
        .into_iter()
        .take(top_count)
        .map(|option_position| {
            u16::try_from(option_position).map_err(|_| TallyCircuitError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(TallyEvaluationOutcome {
        ordered_option_positions,
        has_selected_ballot,
    })
}
