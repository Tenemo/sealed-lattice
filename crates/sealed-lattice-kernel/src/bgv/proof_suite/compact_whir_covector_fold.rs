//! Bounded allocation-reusing folds for compact WHIR relation covectors.

use p3_field::PrimeCharacteristicRing;

use super::compact_cfw::CompactChallengeField;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirCovectorFoldError {
    ArithmeticOverflow,
    InvalidGeometry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirInPlaceCovectorFold {
    active_column_count: usize,
    challenge_ordinal: usize,
    challenges: Vec<CompactChallengeField>,
    column_length: usize,
    next_destination_element_ordinal: usize,
    values: Option<Vec<CompactChallengeField>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirInPlaceCovectorFoldPoll {
    WorkCompleted {
        completed_work_unit_count: u64,
    },
    Complete {
        completed_work_unit_count: u64,
        values: Vec<CompactChallengeField>,
    },
}

impl CompactWhirInPlaceCovectorFold {
    pub(crate) fn new(
        flattened: Vec<CompactChallengeField>,
        folding_factor: usize,
        challenges: &[CompactChallengeField],
    ) -> Result<Self, CompactWhirCovectorFoldError> {
        let width = 1_usize
            .checked_shl(
                u32::try_from(folding_factor)
                    .map_err(|_| CompactWhirCovectorFoldError::ArithmeticOverflow)?,
            )
            .ok_or(CompactWhirCovectorFoldError::ArithmeticOverflow)?;
        if challenges.len() != folding_factor
            || width == 0
            || flattened.is_empty()
            || !flattened.len().is_multiple_of(width)
        {
            return Err(CompactWhirCovectorFoldError::InvalidGeometry);
        }
        Ok(Self {
            active_column_count: width,
            challenge_ordinal: 0,
            challenges: challenges.to_vec(),
            column_length: flattened.len() / width,
            next_destination_element_ordinal: 0,
            values: Some(flattened),
        })
    }

    pub(crate) fn advance(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactWhirInPlaceCovectorFoldPoll, CompactWhirCovectorFoldError> {
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirCovectorFoldError::InvalidGeometry);
        }
        let mut completed_work_unit_count = 0_u64;
        loop {
            if self.challenge_ordinal == self.challenges.len() {
                return Ok(CompactWhirInPlaceCovectorFoldPoll::Complete {
                    completed_work_unit_count,
                    values: self
                        .values
                        .take()
                        .ok_or(CompactWhirCovectorFoldError::InvalidGeometry)?,
                });
            }
            if self.active_column_count < 2 || !self.active_column_count.is_multiple_of(2) {
                return Err(CompactWhirCovectorFoldError::InvalidGeometry);
            }
            let output_column_count = self.active_column_count / 2;
            let output_element_count = output_column_count
                .checked_mul(self.column_length)
                .ok_or(CompactWhirCovectorFoldError::ArithmeticOverflow)?;
            let remaining_budget = maximum_work_unit_count
                .checked_sub(completed_work_unit_count)
                .ok_or(CompactWhirCovectorFoldError::ArithmeticOverflow)?;
            if remaining_budget == 0 {
                return Ok(CompactWhirInPlaceCovectorFoldPoll::WorkCompleted {
                    completed_work_unit_count,
                });
            }
            let remaining_output_element_count = output_element_count
                .checked_sub(self.next_destination_element_ordinal)
                .ok_or(CompactWhirCovectorFoldError::InvalidGeometry)?;
            let step_element_count = usize::try_from(
                remaining_budget.min(
                    u64::try_from(remaining_output_element_count)
                        .map_err(|_| CompactWhirCovectorFoldError::ArithmeticOverflow)?,
                ),
            )
            .map_err(|_| CompactWhirCovectorFoldError::ArithmeticOverflow)?;
            let step_end = self
                .next_destination_element_ordinal
                .checked_add(step_element_count)
                .ok_or(CompactWhirCovectorFoldError::ArithmeticOverflow)?;
            let challenge = self.challenges[self.challenge_ordinal];
            let one_minus_challenge = CompactChallengeField::ONE - challenge;
            let values = self
                .values
                .as_mut()
                .ok_or(CompactWhirCovectorFoldError::InvalidGeometry)?;
            for destination_element_ordinal in self.next_destination_element_ordinal..step_end {
                let destination_column_ordinal = destination_element_ordinal / self.column_length;
                let row_ordinal = destination_element_ordinal % self.column_length;
                let source_one_element_ordinal = output_column_count
                    .checked_add(destination_column_ordinal)
                    .and_then(|column_ordinal| column_ordinal.checked_mul(self.column_length))
                    .and_then(|column_start| column_start.checked_add(row_ordinal))
                    .ok_or(CompactWhirCovectorFoldError::ArithmeticOverflow)?;
                let zero = values[destination_element_ordinal];
                let one = values[source_one_element_ordinal];
                values[destination_element_ordinal] = one_minus_challenge * zero + challenge * one;
            }
            self.next_destination_element_ordinal = step_end;
            completed_work_unit_count = completed_work_unit_count
                .checked_add(
                    u64::try_from(step_element_count)
                        .map_err(|_| CompactWhirCovectorFoldError::ArithmeticOverflow)?,
                )
                .ok_or(CompactWhirCovectorFoldError::ArithmeticOverflow)?;
            if self.next_destination_element_ordinal == output_element_count {
                values.truncate(output_element_count);
                self.active_column_count = output_column_count;
                self.challenge_ordinal = self
                    .challenge_ordinal
                    .checked_add(1)
                    .ok_or(CompactWhirCovectorFoldError::ArithmeticOverflow)?;
                self.next_destination_element_ordinal = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(canonical: u64) -> CompactChallengeField {
        CompactChallengeField::from_u64(canonical)
    }

    fn reference_fold_flattened_covector(
        flattened: &[CompactChallengeField],
        folding_factor: usize,
        challenges: &[CompactChallengeField],
    ) -> Vec<CompactChallengeField> {
        let width = 1_usize << folding_factor;
        let column_length = flattened.len() / width;
        let mut columns = flattened
            .chunks_exact(column_length)
            .map(<[CompactChallengeField]>::to_vec)
            .collect::<Vec<_>>();
        for &challenge in challenges {
            let half = columns.len() / 2;
            let one_minus_challenge = CompactChallengeField::ONE - challenge;
            columns = (0..half)
                .map(|column_ordinal| {
                    columns[column_ordinal]
                        .iter()
                        .zip(&columns[half + column_ordinal])
                        .map(|(&zero, &one)| one_minus_challenge * zero + challenge * one)
                        .collect()
                })
                .collect();
        }
        columns.into_iter().flatten().collect()
    }

    #[test]
    fn bounded_in_place_fold_matches_reference_without_reallocating() {
        for folding_factor in 1_usize..=4 {
            let width = 1_usize << folding_factor;
            let challenges = (0..folding_factor)
                .map(|challenge_ordinal| value(7 + u64::try_from(challenge_ordinal).unwrap()))
                .collect::<Vec<_>>();
            for column_length in [1_usize, 3, 17] {
                let element_count = width * column_length;
                let mut flattened = (0..element_count)
                    .map(|element_ordinal| value(101 + u64::try_from(element_ordinal).unwrap()))
                    .collect::<Vec<_>>();
                flattened.shrink_to_fit();
                assert_eq!(flattened.capacity(), flattened.len());
                let expected =
                    reference_fold_flattened_covector(&flattened, folding_factor, &challenges);
                let initial_pointer = flattened.as_ptr();
                let initial_capacity = flattened.capacity();
                let mut fold =
                    CompactWhirInPlaceCovectorFold::new(flattened, folding_factor, &challenges)
                        .unwrap();
                let work_budgets = [1_u64, 5, 2, 11];
                let mut poll_ordinal = 0_usize;
                let completed = loop {
                    let work_budget = work_budgets[poll_ordinal % work_budgets.len()];
                    poll_ordinal += 1;
                    match fold.advance(work_budget).unwrap() {
                        CompactWhirInPlaceCovectorFoldPoll::WorkCompleted {
                            completed_work_unit_count,
                        } => {
                            assert!((1..=work_budget).contains(&completed_work_unit_count));
                        }
                        CompactWhirInPlaceCovectorFoldPoll::Complete { values, .. } => {
                            break values;
                        }
                    }
                };
                assert_eq!(completed, expected);
                assert_eq!(completed.len(), column_length);
                assert_eq!(completed.capacity(), initial_capacity);
                assert_eq!(completed.as_ptr(), initial_pointer);
            }
        }
    }

    #[test]
    fn bounded_in_place_fold_refuses_invalid_geometry_budget_and_reuse() {
        assert_eq!(
            CompactWhirInPlaceCovectorFold::new(Vec::new(), 1, &[value(2)]),
            Err(CompactWhirCovectorFoldError::InvalidGeometry),
        );
        assert_eq!(
            CompactWhirInPlaceCovectorFold::new(vec![value(2), value(3)], 1, &[]),
            Err(CompactWhirCovectorFoldError::InvalidGeometry),
        );
        assert_eq!(
            CompactWhirInPlaceCovectorFold::new(vec![value(2), value(3), value(5)], 1, &[value(7)],),
            Err(CompactWhirCovectorFoldError::InvalidGeometry),
        );

        let mut fold =
            CompactWhirInPlaceCovectorFold::new(vec![value(2), value(3)], 1, &[value(5)]).unwrap();
        assert_eq!(
            fold.advance(0),
            Err(CompactWhirCovectorFoldError::InvalidGeometry),
        );
        assert!(matches!(
            fold.advance(1).unwrap(),
            CompactWhirInPlaceCovectorFoldPoll::Complete {
                completed_work_unit_count: 1,
                ..
            }
        ));
        assert_eq!(
            fold.advance(1),
            Err(CompactWhirCovectorFoldError::InvalidGeometry),
        );
    }
}
