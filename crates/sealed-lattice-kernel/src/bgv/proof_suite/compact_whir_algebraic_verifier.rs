//! Verifier-side algebra for the compact WHIR epochs.
//!
//! The transport owner authenticates commitments and opened rows. This module
//! independently replays the sumcheck and code-switch equations over those
//! authenticated values. It never receives a witness or producer-computed
//! covector.

use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;

use super::compact_cfw::{CompactCfwPublicMainCovectors, CompactChallengeField};
use super::compact_proof_contract::{
    CompactWhirEpochContract, CompactWhirFoldContract, CompactWhirMaskGroupContract,
};
use super::compact_whir_covector_fold::{
    CompactWhirCovectorFoldError, CompactWhirInPlaceCovectorFold,
    CompactWhirInPlaceCovectorFoldPoll,
};

const COMPACT_WHIR_BATCH_COUNT: usize = 4;
const COMPACT_WHIR_SUMCHECK_MESSAGE_LENGTH: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirAlgebraicVerifierError {
    ArithmeticOverflow,
    InvalidContract,
    InvalidRelation,
    InvalidSumcheck,
    InvalidCodeSwitch,
    InvalidBaseCase,
}

const fn compact_whir_covector_fold_error(
    error: CompactWhirCovectorFoldError,
) -> CompactWhirAlgebraicVerifierError {
    match error {
        CompactWhirCovectorFoldError::ArithmeticOverflow => {
            CompactWhirAlgebraicVerifierError::ArithmeticOverflow
        }
        CompactWhirCovectorFoldError::InvalidGeometry => {
            CompactWhirAlgebraicVerifierError::InvalidRelation
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirAlgebraicRelation {
    source_covector: Vec<CompactChallengeField>,
    mask_group_covectors: Vec<Vec<CompactChallengeField>>,
    target: CompactChallengeField,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirSumcheckTranscript<'transcript> {
    pub(crate) auxiliary_target: CompactChallengeField,
    pub(crate) combination_challenge: CompactChallengeField,
    pub(crate) round_wires: &'transcript [[CompactChallengeField; 2]],
    pub(crate) round_challenges: &'transcript [CompactChallengeField],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirSumcheckVerification {
    preparation: Option<CompactWhirSumcheckPreparation>,
    source_fold: Option<CompactWhirInPlaceCovectorFold>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirSumcheckVerificationPoll {
    WorkCompleted { completed_work_unit_count: u64 },
    Complete { completed_work_unit_count: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactWhirSumcheckPreparation {
    batch_ordinal: usize,
    combination_challenge: CompactChallengeField,
    expected_output_length: usize,
    folding_factor: usize,
    residual_target: CompactChallengeField,
    round_challenges: Vec<CompactChallengeField>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirCodeSwitchTranscript<'transcript> {
    pub(crate) combination_challenge: CompactChallengeField,
    pub(crate) query_positions: &'transcript [u64],
    pub(crate) folded_source_openings: &'transcript [CompactChallengeField],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirBlindedMaskReveal {
    pub(crate) messages: Vec<Vec<CompactChallengeField>>,
    pub(crate) randomness: Vec<Vec<CompactChallengeField>>,
}

impl CompactWhirSumcheckVerification {
    pub(crate) fn advance(
        &mut self,
        relation: &mut CompactWhirAlgebraicRelation,
        epoch: &CompactWhirEpochContract,
        maximum_work_unit_count: u64,
    ) -> Result<CompactWhirSumcheckVerificationPoll, CompactWhirAlgebraicVerifierError> {
        if maximum_work_unit_count == 0 {
            return Err(CompactWhirAlgebraicVerifierError::InvalidRelation);
        }
        let completed_work_unit_count = if let Some(source_fold) = &mut self.source_fold {
            match source_fold
                .advance(maximum_work_unit_count)
                .map_err(compact_whir_covector_fold_error)?
            {
                CompactWhirInPlaceCovectorFoldPoll::WorkCompleted {
                    completed_work_unit_count,
                } => {
                    return Ok(CompactWhirSumcheckVerificationPoll::WorkCompleted {
                        completed_work_unit_count,
                    });
                }
                CompactWhirInPlaceCovectorFoldPoll::Complete {
                    completed_work_unit_count,
                    values,
                } => {
                    relation.source_covector = values;
                    completed_work_unit_count
                }
            }
        } else {
            0
        };
        self.source_fold = None;
        let preparation = self
            .preparation
            .take()
            .ok_or(CompactWhirAlgebraicVerifierError::InvalidRelation)?;
        relation.finish_sumcheck_batch(epoch, preparation)?;
        Ok(CompactWhirSumcheckVerificationPoll::Complete {
            completed_work_unit_count,
        })
    }
}

impl CompactWhirAlgebraicRelation {
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        source_covector: Vec<CompactChallengeField>,
        mask_group_covectors: Vec<Vec<CompactChallengeField>>,
        target: CompactChallengeField,
    ) -> Self {
        Self {
            source_covector,
            mask_group_covectors,
            target,
        }
    }

    pub(crate) fn pre_challenge(
        epoch: &CompactWhirEpochContract,
        cross_epoch_point: &[CompactChallengeField],
        masked_pre_challenge_target: CompactChallengeField,
    ) -> Result<Self, CompactWhirAlgebraicVerifierError> {
        let source_length = 1_usize
            .checked_shl(epoch.polynomial_variable_count)
            .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        let source_covector = multilinear_equality_covector(cross_epoch_point, source_length)?;
        let relation = Self {
            source_covector,
            mask_group_covectors: vec![vec![
                CompactChallengeField::ONE,
                CompactChallengeField::ZERO,
            ]],
            target: masked_pre_challenge_target,
        };
        relation.validate_external_groups(epoch)?;
        Ok(relation)
    }

    pub(crate) fn main(
        epoch: &CompactWhirEpochContract,
        public_covectors: CompactCfwPublicMainCovectors,
        target: CompactChallengeField,
    ) -> Result<Self, CompactWhirAlgebraicVerifierError> {
        let (source, inner_masks, outer_masks, cross_epoch_masks) = public_covectors.into_parts();
        let relation = Self {
            source_covector: source,
            mask_group_covectors: vec![
                inner_masks.into_iter().flatten().collect(),
                outer_masks.into_iter().flatten().collect(),
                cross_epoch_masks.into_iter().flatten().collect(),
            ],
            target,
        };
        relation.validate_external_groups(epoch)?;
        Ok(relation)
    }

    pub(crate) fn begin_sumcheck_batch(
        &mut self,
        epoch: &CompactWhirEpochContract,
        fold: CompactWhirFoldContract,
        batch_ordinal: usize,
        source_was_already_folded: bool,
        transcript: CompactWhirSumcheckTranscript<'_>,
    ) -> Result<CompactWhirSumcheckVerification, CompactWhirAlgebraicVerifierError> {
        if batch_ordinal >= COMPACT_WHIR_BATCH_COUNT
            || usize::from(fold.epoch) != usize::from(epoch.epoch)
            || usize::from(fold.batch_ordinal) != batch_ordinal
        {
            return Err(CompactWhirAlgebraicVerifierError::InvalidContract);
        }
        let folding_factor = usize::try_from(epoch.folding_schedule[batch_ordinal])
            .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        if transcript.round_wires.len() != folding_factor
            || transcript.round_challenges.len() != folding_factor
        {
            return Err(CompactWhirAlgebraicVerifierError::InvalidSumcheck);
        }
        let expected_input_length = usize::try_from(fold.message_length)
            .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?
            .checked_shl(
                u32::try_from(folding_factor)
                    .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?,
            )
            .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        let expected_output_length = usize::try_from(fold.message_length)
            .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        let observed_source_length = if source_was_already_folded {
            expected_output_length
        } else {
            expected_input_length
        };
        if self.source_covector.len() != observed_source_length {
            return Err(CompactWhirAlgebraicVerifierError::InvalidRelation);
        }

        let mut residual_target =
            transcript.auxiliary_target + transcript.combination_challenge * self.target;
        for (wire, challenge) in transcript
            .round_wires
            .iter()
            .zip(transcript.round_challenges)
        {
            let constant = wire[0];
            let leading = wire[1];
            let linear = residual_target - CompactChallengeField::TWO * constant - leading;
            residual_target = constant + *challenge * linear + *challenge * *challenge * leading;
        }

        let source_fold = if source_was_already_folded {
            None
        } else {
            Some(
                CompactWhirInPlaceCovectorFold::new(
                    core::mem::take(&mut self.source_covector),
                    folding_factor,
                    transcript.round_challenges,
                )
                .map_err(compact_whir_covector_fold_error)?,
            )
        };
        Ok(CompactWhirSumcheckVerification {
            preparation: Some(CompactWhirSumcheckPreparation {
                batch_ordinal,
                combination_challenge: transcript.combination_challenge,
                expected_output_length,
                folding_factor,
                residual_target,
                round_challenges: transcript.round_challenges.to_vec(),
            }),
            source_fold,
        })
    }

    fn finish_sumcheck_batch(
        &mut self,
        epoch: &CompactWhirEpochContract,
        preparation: CompactWhirSumcheckPreparation,
    ) -> Result<(), CompactWhirAlgebraicVerifierError> {
        if self.source_covector.len() != preparation.expected_output_length {
            return Err(CompactWhirAlgebraicVerifierError::InvalidRelation);
        }
        scale_in_place(&mut self.source_covector, preparation.combination_challenge);
        let carried_mask_scale =
            preparation.combination_challenge * power_of_two(preparation.folding_factor).inverse();
        for covector in &mut self.mask_group_covectors {
            scale_in_place(covector, carried_mask_scale);
        }
        let mut sumcheck_mask_covectors = Vec::new();
        sumcheck_mask_covectors
            .try_reserve_exact(
                preparation
                    .folding_factor
                    .checked_mul(COMPACT_WHIR_SUMCHECK_MESSAGE_LENGTH)
                    .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?,
            )
            .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        for challenge in preparation.round_challenges {
            sumcheck_mask_covectors.extend([
                CompactChallengeField::ONE,
                challenge,
                challenge * challenge,
            ]);
        }
        self.mask_group_covectors.push(sumcheck_mask_covectors);
        self.target = preparation.residual_target;
        self.validate_internal_prefix(epoch, preparation.batch_ordinal, false)
    }

    pub(crate) fn verify_code_switch(
        &mut self,
        epoch: &CompactWhirEpochContract,
        input_fold: CompactWhirFoldContract,
        output_fold: CompactWhirFoldContract,
        round_ordinal: usize,
        transcript: CompactWhirCodeSwitchTranscript<'_>,
    ) -> Result<(), CompactWhirAlgebraicVerifierError> {
        if round_ordinal + 1 >= COMPACT_WHIR_BATCH_COUNT
            || usize::from(input_fold.epoch) != usize::from(epoch.epoch)
            || usize::from(output_fold.epoch) != usize::from(epoch.epoch)
            || usize::from(input_fold.batch_ordinal) != round_ordinal
            || usize::from(output_fold.batch_ordinal) != round_ordinal + 1
            || transcript.query_positions.is_empty()
            || transcript.query_positions.len() != transcript.folded_source_openings.len()
            || u64::try_from(transcript.query_positions.len()).ok() != Some(input_fold.query_count)
            || transcript
                .query_positions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || transcript
                .query_positions
                .last()
                .is_none_or(|position| *position >= input_fold.block_length)
            || u64::try_from(self.source_covector.len()).ok() != Some(input_fold.message_length)
            || output_fold
                .message_length
                .checked_mul(output_fold.oracle_width)
                != Some(input_fold.message_length)
        {
            return Err(CompactWhirAlgebraicVerifierError::InvalidCodeSwitch);
        }
        let switch_message_length = usize::try_from(input_fold.hiding_randomness_length)
            .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        let mut switch_mask_covector = allocate_zero_values(switch_message_length)?;
        let domain_generator = two_adic_domain_generator(input_fold.block_length)?;
        let mut combination_coefficient = transcript.combination_challenge;
        for (&position, &folded_source_opening) in transcript
            .query_positions
            .iter()
            .zip(transcript.folded_source_openings)
        {
            let point = domain_generator.exp_u64(position);
            let mut power = CompactChallengeField::ONE;
            for coefficient in &mut self.source_covector {
                *coefficient += combination_coefficient * power;
                power *= point;
            }
            for coefficient in &mut switch_mask_covector {
                *coefficient += combination_coefficient * power;
                power *= point;
            }
            self.target += combination_coefficient * folded_source_opening;
            combination_coefficient *= transcript.combination_challenge;
        }
        self.mask_group_covectors.push(switch_mask_covector);
        self.validate_internal_prefix(epoch, round_ordinal, true)
    }

    pub(crate) fn verify_blinded_target(
        &self,
        epoch: &CompactWhirEpochContract,
        fresh_claim: CompactChallengeField,
        combination_challenge: CompactChallengeField,
        blinded_source_message: &[CompactChallengeField],
        blinded_masks: &[CompactWhirBlindedMaskReveal],
    ) -> Result<(), CompactWhirAlgebraicVerifierError> {
        self.validate_complete(epoch)?;
        if blinded_source_message.len() != self.source_covector.len()
            || blinded_masks.len() != self.mask_group_covectors.len()
        {
            return Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase);
        }
        let mut combined = dot_product(blinded_source_message, &self.source_covector)?;
        for ((reveal, covector), contract) in
            blinded_masks.iter().zip(&self.mask_group_covectors).zip(
                epoch
                    .external_mask_groups
                    .iter()
                    .chain(&epoch.internal_mask_groups),
            )
        {
            validate_blinded_mask_reveal(reveal, *contract)?;
            let flattened_messages = reveal.messages.iter().flatten().copied();
            combined += flattened_messages
                .zip(covector)
                .map(|(value, coefficient)| value * *coefficient)
                .sum::<CompactChallengeField>();
        }
        if combined != fresh_claim + combination_challenge * self.target {
            return Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn source_covector(&self) -> &[CompactChallengeField] {
        &self.source_covector
    }

    #[cfg(test)]
    pub(crate) fn mask_group_covectors(&self) -> &[Vec<CompactChallengeField>] {
        &self.mask_group_covectors
    }

    #[cfg(test)]
    pub(crate) const fn target(&self) -> CompactChallengeField {
        self.target
    }

    fn validate_external_groups(
        &self,
        epoch: &CompactWhirEpochContract,
    ) -> Result<(), CompactWhirAlgebraicVerifierError> {
        if self.source_covector.is_empty()
            || self.mask_group_covectors.len() != epoch.external_mask_groups.len()
            || self
                .mask_group_covectors
                .iter()
                .zip(&epoch.external_mask_groups)
                .any(|(covector, contract)| {
                    u64::try_from(covector.len()).ok()
                        != contract.width.checked_mul(contract.message_length)
                })
        {
            return Err(CompactWhirAlgebraicVerifierError::InvalidRelation);
        }
        Ok(())
    }

    fn validate_internal_prefix(
        &self,
        epoch: &CompactWhirEpochContract,
        ordinal: usize,
        includes_code_switch: bool,
    ) -> Result<(), CompactWhirAlgebraicVerifierError> {
        let internal_group_count = ordinal
            .checked_mul(2)
            .and_then(|count| count.checked_add(1 + usize::from(includes_code_switch)))
            .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        let expected_group_count = epoch
            .external_mask_groups
            .len()
            .checked_add(internal_group_count)
            .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        if self.mask_group_covectors.len() != expected_group_count {
            return Err(CompactWhirAlgebraicVerifierError::InvalidRelation);
        }
        for (covector, contract) in self.mask_group_covectors.iter().zip(
            epoch
                .external_mask_groups
                .iter()
                .chain(&epoch.internal_mask_groups),
        ) {
            if u64::try_from(covector.len()).ok()
                != contract.width.checked_mul(contract.message_length)
            {
                return Err(CompactWhirAlgebraicVerifierError::InvalidRelation);
            }
        }
        Ok(())
    }

    fn validate_complete(
        &self,
        epoch: &CompactWhirEpochContract,
    ) -> Result<(), CompactWhirAlgebraicVerifierError> {
        let expected_source_length = 1_usize
            .checked_shl(epoch.final_variable_count)
            .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        let expected_group_count = epoch
            .external_mask_groups
            .len()
            .checked_add(epoch.internal_mask_groups.len())
            .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        if self.source_covector.len() != expected_source_length
            || self.mask_group_covectors.len() != expected_group_count
        {
            return Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase);
        }
        self.validate_internal_prefix(epoch, COMPACT_WHIR_BATCH_COUNT - 1, false)
    }
}

pub(crate) struct CompactWhirSourceSpotCheck<'input> {
    pub(crate) final_fold: CompactWhirFoldContract,
    pub(crate) final_folding_challenges: &'input [CompactChallengeField],
    pub(crate) query_positions: &'input [u64],
    pub(crate) carried_source_rows: &'input [Vec<CompactChallengeField>],
    pub(crate) fresh_source_rows: &'input [Vec<CompactChallengeField>],
    pub(crate) blinded_message: &'input [CompactChallengeField],
    pub(crate) blinded_randomness: &'input [CompactChallengeField],
    pub(crate) combination_challenge: CompactChallengeField,
}

pub(crate) fn verify_compact_whir_source_spot_checks(
    input: CompactWhirSourceSpotCheck<'_>,
) -> Result<(), CompactWhirAlgebraicVerifierError> {
    let CompactWhirSourceSpotCheck {
        final_fold,
        final_folding_challenges,
        query_positions,
        carried_source_rows,
        fresh_source_rows,
        blinded_message,
        blinded_randomness,
        combination_challenge,
    } = input;
    let expected_width = 1_usize
        .checked_shl(
            u32::try_from(final_folding_challenges.len())
                .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?,
        )
        .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
    if u64::try_from(expected_width).ok() != Some(final_fold.oracle_width)
        || u64::try_from(query_positions.len()).ok() != Some(final_fold.query_count)
        || query_positions.len() != carried_source_rows.len()
        || query_positions.len() != fresh_source_rows.len()
        || query_positions.windows(2).any(|pair| pair[0] >= pair[1])
        || query_positions
            .last()
            .is_none_or(|position| *position >= final_fold.block_length)
        || carried_source_rows
            .iter()
            .any(|row| row.len() != expected_width)
        || fresh_source_rows.iter().any(|row| row.len() != 1)
        || u64::try_from(blinded_message.len()).ok() != Some(final_fold.message_length)
        || u64::try_from(blinded_randomness.len()).ok() != Some(final_fold.hiding_randomness_length)
    {
        return Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase);
    }
    let folding_weights = multilinear_equality_covector(final_folding_challenges, expected_width)?;
    let domain_generator = two_adic_domain_generator(final_fold.block_length)?;
    for ((&position, carried_row), fresh_row) in query_positions
        .iter()
        .zip(carried_source_rows)
        .zip(fresh_source_rows)
    {
        let carried_value = dot_product(carried_row, &folding_weights)?;
        let blinded_value = evaluate_padded_polynomial(
            domain_generator.exp_u64(position),
            blinded_message,
            blinded_randomness,
        );
        if blinded_value != fresh_row[0] + combination_challenge * carried_value {
            return Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase);
        }
    }
    Ok(())
}

pub(crate) fn verify_compact_whir_mask_spot_checks(
    contract: CompactWhirMaskGroupContract,
    query_positions: &[u64],
    carried_rows: &[Vec<CompactChallengeField>],
    fresh_rows: &[Vec<CompactChallengeField>],
    blinded: &CompactWhirBlindedMaskReveal,
    combination_challenge: CompactChallengeField,
) -> Result<(), CompactWhirAlgebraicVerifierError> {
    validate_blinded_mask_reveal(blinded, contract)?;
    let width = usize::try_from(contract.width)
        .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
    if query_positions.is_empty()
        || query_positions.len() != carried_rows.len()
        || query_positions.len() != fresh_rows.len()
        || query_positions.windows(2).any(|pair| pair[0] >= pair[1])
        || query_positions
            .last()
            .is_none_or(|position| *position >= contract.domain_size)
        || carried_rows.iter().any(|row| row.len() != width)
        || fresh_rows.iter().any(|row| row.len() != width)
    {
        return Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase);
    }
    let domain_generator = two_adic_domain_generator(contract.domain_size)?;
    for ((&position, carried_row), fresh_row) in
        query_positions.iter().zip(carried_rows).zip(fresh_rows)
    {
        let point = domain_generator.exp_u64(position);
        for lane_ordinal in 0..width {
            let blinded_value = evaluate_padded_polynomial(
                point,
                &blinded.messages[lane_ordinal],
                &blinded.randomness[lane_ordinal],
            );
            if blinded_value
                != fresh_row[lane_ordinal] + combination_challenge * carried_row[lane_ordinal]
            {
                return Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase);
            }
        }
    }
    Ok(())
}

fn validate_blinded_mask_reveal(
    reveal: &CompactWhirBlindedMaskReveal,
    contract: CompactWhirMaskGroupContract,
) -> Result<(), CompactWhirAlgebraicVerifierError> {
    let width = usize::try_from(contract.width)
        .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
    let message_length = usize::try_from(contract.message_length)
        .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
    let randomness_length = usize::try_from(contract.randomness_length)
        .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
    if reveal.messages.len() != width
        || reveal.randomness.len() != width
        || reveal
            .messages
            .iter()
            .any(|message| message.len() != message_length)
        || reveal
            .randomness
            .iter()
            .any(|randomness| randomness.len() != randomness_length)
    {
        return Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase);
    }
    Ok(())
}

fn multilinear_equality_covector(
    point: &[CompactChallengeField],
    expected_length: usize,
) -> Result<Vec<CompactChallengeField>, CompactWhirAlgebraicVerifierError> {
    let mut weights = vec![CompactChallengeField::ONE];
    for coordinate in point {
        let mut next = Vec::new();
        next.try_reserve_exact(
            weights
                .len()
                .checked_mul(2)
                .ok_or(CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?,
        )
        .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
        for weight in weights {
            next.push(weight * (CompactChallengeField::ONE - *coordinate));
            next.push(weight * *coordinate);
        }
        weights = next;
    }
    if weights.len() != expected_length {
        return Err(CompactWhirAlgebraicVerifierError::InvalidRelation);
    }
    Ok(weights)
}

fn evaluate_padded_polynomial(
    point: CompactChallengeField,
    message: &[CompactChallengeField],
    randomness: &[CompactChallengeField],
) -> CompactChallengeField {
    message
        .iter()
        .chain(randomness)
        .rev()
        .fold(CompactChallengeField::ZERO, |value, coefficient| {
            value * point + *coefficient
        })
}

fn two_adic_domain_generator(
    domain_size: u64,
) -> Result<CompactChallengeField, CompactWhirAlgebraicVerifierError> {
    let domain_size = usize::try_from(domain_size)
        .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
    if !domain_size.is_power_of_two() {
        return Err(CompactWhirAlgebraicVerifierError::InvalidContract);
    }
    Ok(CompactChallengeField::from(Goldilocks::two_adic_generator(
        usize::try_from(domain_size.ilog2())
            .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?,
    )))
}

fn dot_product(
    left: &[CompactChallengeField],
    right: &[CompactChallengeField],
) -> Result<CompactChallengeField, CompactWhirAlgebraicVerifierError> {
    if left.len() != right.len() {
        return Err(CompactWhirAlgebraicVerifierError::InvalidRelation);
    }
    Ok(left
        .iter()
        .zip(right)
        .map(|(left, right)| *left * *right)
        .sum())
}

fn allocate_zero_values(
    count: usize,
) -> Result<Vec<CompactChallengeField>, CompactWhirAlgebraicVerifierError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| CompactWhirAlgebraicVerifierError::ArithmeticOverflow)?;
    values.resize(count, CompactChallengeField::ZERO);
    Ok(values)
}

fn power_of_two(exponent: usize) -> CompactChallengeField {
    (0..exponent).fold(CompactChallengeField::ONE, |value, _| value + value)
}

fn scale_in_place(values: &mut [CompactChallengeField], scale: CompactChallengeField) {
    for value in values {
        *value *= scale;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(canonical: u64) -> CompactChallengeField {
        CompactChallengeField::from_u64(canonical)
    }

    fn mask_contract(
        role_tag: u8,
        coordinate: u8,
        width: u64,
        message_length: u64,
        randomness_length: u64,
    ) -> CompactWhirMaskGroupContract {
        CompactWhirMaskGroupContract {
            role_tag,
            coordinate,
            width,
            message_length,
            randomness_length,
            domain_size: (message_length + randomness_length).next_power_of_two() << 2,
            committed_encoding_source: 1,
        }
    }

    #[test]
    fn terminal_relation_accepts_exact_blinding_and_rejects_equation_mutation() {
        let external_contract = mask_contract(1, 0, 1, 2, 1);
        let internal_contracts = vec![
            mask_contract(4, 0, 1, 2, 1),
            mask_contract(5, 0, 1, 2, 1),
            mask_contract(4, 1, 1, 2, 1),
            mask_contract(5, 1, 1, 2, 1),
            mask_contract(4, 2, 1, 2, 1),
            mask_contract(5, 2, 1, 2, 1),
            mask_contract(4, 3, 1, 2, 1),
        ];
        let epoch = CompactWhirEpochContract {
            epoch: 1,
            polynomial_variable_count: 6,
            folding_schedule: [1, 1, 1, 1],
            final_variable_count: 2,
            round_log_inverse_rates: [2, 2, 2],
            mask_query_count: 1,
            internal_mask_groups: internal_contracts.clone(),
            external_mask_groups: vec![external_contract],
        };
        let contracts = core::iter::once(external_contract)
            .chain(internal_contracts)
            .collect::<Vec<_>>();
        let source_covector = vec![value(2), value(3), value(5), value(7)];
        let carried_source = vec![value(11), value(13), value(17), value(19)];
        let fresh_source = vec![value(23), value(29), value(31), value(37)];
        let combination_challenge = value(41);
        let mut target = dot_product(&carried_source, &source_covector).unwrap();
        let mut fresh_claim = dot_product(&fresh_source, &source_covector).unwrap();
        let mut mask_covectors = Vec::new();
        let mut blinded_masks = Vec::new();
        for (group_ordinal, contract) in contracts.iter().copied().enumerate() {
            let offset = u64::try_from(group_ordinal).unwrap() * 10;
            let covector = vec![value(43 + offset), value(47 + offset)];
            let carried_message = vec![value(53 + offset), value(59 + offset)];
            let fresh_message = vec![value(61 + offset), value(67 + offset)];
            target += dot_product(&carried_message, &covector).unwrap();
            fresh_claim += dot_product(&fresh_message, &covector).unwrap();
            mask_covectors.push(covector);
            blinded_masks.push(CompactWhirBlindedMaskReveal {
                messages: vec![
                    fresh_message
                        .iter()
                        .zip(&carried_message)
                        .map(|(fresh, carried)| *fresh + combination_challenge * *carried)
                        .collect(),
                ],
                randomness: vec![vec![value(71 + offset)]],
            });
            assert_eq!(contract.width, 1);
        }
        let relation = CompactWhirAlgebraicRelation::from_parts_for_test(
            source_covector,
            mask_covectors,
            target,
        );
        let blinded_source = fresh_source
            .iter()
            .zip(&carried_source)
            .map(|(fresh, carried)| *fresh + combination_challenge * *carried)
            .collect::<Vec<_>>();
        relation
            .verify_blinded_target(
                &epoch,
                fresh_claim,
                combination_challenge,
                &blinded_source,
                &blinded_masks,
            )
            .unwrap();

        let mut hostile_masks = blinded_masks;
        hostile_masks[6].messages[0][1] += CompactChallengeField::ONE;
        assert_eq!(
            relation.verify_blinded_target(
                &epoch,
                fresh_claim,
                combination_challenge,
                &blinded_source,
                &hostile_masks,
            ),
            Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase)
        );
    }

    #[test]
    fn terminal_spot_checks_bind_source_masks_positions_and_randomness() {
        let final_fold = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 3,
            message_length: 4,
            hiding_randomness_length: 2,
            block_length: 8,
            oracle_width: 2,
            query_count: 2,
            unique_decoding_radius: 0,
        };
        let folding_challenges = [value(7)];
        let query_positions = [1_u64, 6];
        let carried_message = vec![value(2), value(3), value(5), value(11)];
        let carried_randomness = vec![value(13), value(17)];
        let fresh_message = vec![value(19), value(23), value(29), value(31)];
        let fresh_randomness = vec![value(37), value(41)];
        let combination_challenge = value(43);
        let blinded_message = fresh_message
            .iter()
            .zip(&carried_message)
            .map(|(fresh, carried)| *fresh + combination_challenge * *carried)
            .collect::<Vec<_>>();
        let blinded_randomness = fresh_randomness
            .iter()
            .zip(&carried_randomness)
            .map(|(fresh, carried)| *fresh + combination_challenge * *carried)
            .collect::<Vec<_>>();
        let domain_generator = two_adic_domain_generator(final_fold.block_length).unwrap();
        let carried_source_rows = query_positions
            .iter()
            .map(|position| {
                let evaluation = evaluate_padded_polynomial(
                    domain_generator.exp_u64(*position),
                    &carried_message,
                    &carried_randomness,
                );
                vec![evaluation, evaluation]
            })
            .collect::<Vec<_>>();
        let fresh_source_rows = query_positions
            .iter()
            .map(|position| {
                vec![evaluate_padded_polynomial(
                    domain_generator.exp_u64(*position),
                    &fresh_message,
                    &fresh_randomness,
                )]
            })
            .collect::<Vec<_>>();
        verify_compact_whir_source_spot_checks(CompactWhirSourceSpotCheck {
            final_fold,
            final_folding_challenges: &folding_challenges,
            query_positions: &query_positions,
            carried_source_rows: &carried_source_rows,
            fresh_source_rows: &fresh_source_rows,
            blinded_message: &blinded_message,
            blinded_randomness: &blinded_randomness,
            combination_challenge,
        })
        .unwrap();
        let mut hostile_source_rows = fresh_source_rows;
        hostile_source_rows[1][0] += CompactChallengeField::ONE;
        assert_eq!(
            verify_compact_whir_source_spot_checks(CompactWhirSourceSpotCheck {
                final_fold,
                final_folding_challenges: &folding_challenges,
                query_positions: &query_positions,
                carried_source_rows: &carried_source_rows,
                fresh_source_rows: &hostile_source_rows,
                blinded_message: &blinded_message,
                blinded_randomness: &blinded_randomness,
                combination_challenge,
            }),
            Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase)
        );

        let mask_contract = mask_contract(2, 0, 2, 2, 1);
        let carried_mask = CompactWhirBlindedMaskReveal {
            messages: vec![vec![value(47), value(53)], vec![value(59), value(61)]],
            randomness: vec![vec![value(67)], vec![value(71)]],
        };
        let fresh_mask = CompactWhirBlindedMaskReveal {
            messages: vec![vec![value(73), value(79)], vec![value(83), value(89)]],
            randomness: vec![vec![value(97)], vec![value(101)]],
        };
        let blinded_mask = CompactWhirBlindedMaskReveal {
            messages: fresh_mask
                .messages
                .iter()
                .zip(&carried_mask.messages)
                .map(|(fresh, carried)| {
                    fresh
                        .iter()
                        .zip(carried)
                        .map(|(fresh, carried)| *fresh + combination_challenge * *carried)
                        .collect()
                })
                .collect(),
            randomness: fresh_mask
                .randomness
                .iter()
                .zip(&carried_mask.randomness)
                .map(|(fresh, carried)| {
                    fresh
                        .iter()
                        .zip(carried)
                        .map(|(fresh, carried)| *fresh + combination_challenge * *carried)
                        .collect()
                })
                .collect(),
        };
        let mask_domain_generator = two_adic_domain_generator(mask_contract.domain_size).unwrap();
        let carried_mask_rows = query_positions
            .iter()
            .map(|position| {
                (0..2)
                    .map(|lane_ordinal| {
                        evaluate_padded_polynomial(
                            mask_domain_generator.exp_u64(*position),
                            &carried_mask.messages[lane_ordinal],
                            &carried_mask.randomness[lane_ordinal],
                        )
                    })
                    .collect()
            })
            .collect::<Vec<_>>();
        let fresh_mask_rows = query_positions
            .iter()
            .map(|position| {
                (0..2)
                    .map(|lane_ordinal| {
                        evaluate_padded_polynomial(
                            mask_domain_generator.exp_u64(*position),
                            &fresh_mask.messages[lane_ordinal],
                            &fresh_mask.randomness[lane_ordinal],
                        )
                    })
                    .collect()
            })
            .collect::<Vec<_>>();
        verify_compact_whir_mask_spot_checks(
            mask_contract,
            &query_positions,
            &carried_mask_rows,
            &fresh_mask_rows,
            &blinded_mask,
            combination_challenge,
        )
        .unwrap();
        let reordered_positions = [6_u64, 1];
        assert_eq!(
            verify_compact_whir_mask_spot_checks(
                mask_contract,
                &reordered_positions,
                &carried_mask_rows,
                &fresh_mask_rows,
                &blinded_mask,
                combination_challenge,
            ),
            Err(CompactWhirAlgebraicVerifierError::InvalidBaseCase)
        );
    }
}
