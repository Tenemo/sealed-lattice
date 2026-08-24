use super::{
    TallyCircuitError, TallyCircuitProfile, TallyEvaluationInput, TallyEvaluationOutcome,
    bit_width_for_maximum_value, foundation_score_bounds,
};

/// Evaluates tally semantics without compiling or interpreting a circuit.
pub(crate) fn evaluate_tally_directly(
    profile: TallyCircuitProfile,
    input: &TallyEvaluationInput,
) -> Result<TallyEvaluationOutcome, TallyCircuitError> {
    let (minimum_score, maximum_score) = foundation_score_bounds()?;
    let participant_count = usize::from(profile.participant_count());
    let option_count = usize::from(profile.option_count());
    let top_count = usize::from(profile.top_count());

    if input.participant_presence().len() != participant_count {
        return Err(TallyCircuitError::InputParticipantCountMismatch {
            expected: participant_count,
            actual: input.participant_presence().len(),
        });
    }
    if input.participant_scores().len() != participant_count {
        return Err(TallyCircuitError::InputParticipantCountMismatch {
            expected: participant_count,
            actual: input.participant_scores().len(),
        });
    }

    let score_bit_width = bit_width_for_maximum_value(usize::from(maximum_score));
    let maximum_score_encoding = (1_usize << score_bit_width) - 1;
    let mut participant_validity = Vec::with_capacity(participant_count);
    let mut aggregate_scores = vec![0_u32; option_count];

    for participant_position in 0..participant_count {
        let participant_scores = &input.participant_scores()[participant_position];
        if participant_scores.len() != option_count {
            return Err(TallyCircuitError::InputOptionCountMismatch {
                participant_position,
                expected: option_count,
                actual: participant_scores.len(),
            });
        }

        for (option_position, score_encoding) in participant_scores.iter().copied().enumerate() {
            if usize::from(score_encoding) > maximum_score_encoding {
                return Err(TallyCircuitError::ScoreEncodingOutOfRange {
                    participant_position,
                    option_position,
                    score_encoding,
                });
            }
        }

        let is_present = input.participant_presence()[participant_position];
        let is_valid = if is_present {
            participant_scores
                .iter()
                .copied()
                .all(|score| (minimum_score..=maximum_score).contains(&u16::from(score)))
        } else {
            participant_scores.iter().all(|score| *score == 0)
        };
        participant_validity.push(is_valid);

        if is_present {
            for (aggregate_score, score_encoding) in aggregate_scores
                .iter_mut()
                .zip(participant_scores.iter().copied())
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
        participant_validity,
        ordered_option_positions,
        has_selected_ballot: input
            .participant_presence()
            .iter()
            .any(|is_present| *is_present),
    })
}
