//! Exact symbolic error recurrence for the selected direct-pair-character evaluator.
//!
//! The recurrence follows the production instruction stream and its fixed
//! Q/P key topology. It is evidence only: no transported bound or verdict can
//! influence evaluator or target-release acceptance.

use std::collections::BTreeMap;

use num_bigint::{BigInt, BigUint};
#[cfg(test)]
use num_traits::Signed;
use num_traits::{One, Zero};

use crate::{
    bgv::{
        evaluator::{
            pair_character_product::canonical_pair_character_product_schedule,
            program::{EvaluatorInstruction, EvaluatorOpcode, selected_evaluator_program_set},
            top_k::{
                CANONICAL_TARGET_CIPHERTEXT_LEVEL, CHARACTER_OUTPUT_LEVEL,
                SELECTED_EVALUATOR_WORKING_LEVEL,
            },
        },
        key_switch_topology::{
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK, key_switch_special_basis_modulus_product,
        },
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{FOUNDATION_PROFILE, Hash512},
};

const CENTERED_PLAINTEXT_BOUND: u64 = PLAINTEXT_MODULUS / 2;
const FRESH_ERROR_COEFFICIENT_BOUND: u64 = 2;
const FRESH_RANDOMIZER_COEFFICIENT_BOUND: u64 = 1;
const CANONICAL_PLAINTEXT_LIFT_OFFSET_BOUND: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymbolicCiphertextBound {
    pub(crate) level: usize,
    pub(crate) decrypt_scaling: u64,
    pub(crate) message_coefficient_bound: BigUint,
    pub(crate) error_coefficient_bound: BigUint,
    pub(crate) component_count: usize,
    pub(crate) collective_secret_coefficient_bound: u64,
    pub(crate) minimum_decryption_margin: BigInt,
}

impl SymbolicCiphertextBound {
    fn from_state(state: &SymbolicState, collective_secret_coefficient_bound: u64) -> Self {
        Self {
            level: state.level,
            decrypt_scaling: 1,
            message_coefficient_bound: state.message_bound.clone(),
            error_coefficient_bound: state.error_bound.clone(),
            component_count: 2,
            collective_secret_coefficient_bound,
            minimum_decryption_margin: state.minimum_margin.clone(),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorStreamNoiseTrace {
    top_count: u16,
    pair_character_input_bounds: [SymbolicCiphertextBound; 2],
    register_bounds: Vec<SymbolicCiphertextBound>,
}

#[cfg(test)]
impl SelectedEvaluatorStreamNoiseTrace {
    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) fn pair_character_input_bounds(&self) -> &[SymbolicCiphertextBound; 2] {
        &self.pair_character_input_bounds
    }

    pub(crate) fn register_bound(&self, register_ordinal: u32) -> Option<&SymbolicCiphertextBound> {
        self.register_bounds
            .get(usize::try_from(register_ordinal).ok()?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectBallotTargetNoiseBound {
    pub(crate) top_count: usize,
    pub(crate) target_identifier: SymbolicCiphertextBound,
    pub(crate) target_order: SymbolicCiphertextBound,
}

impl DirectBallotTargetNoiseBound {
    pub(crate) fn maximum_error_coefficient_bound(&self) -> &BigUint {
        if self.target_identifier.error_coefficient_bound
            >= self.target_order.error_coefficient_bound
        {
            &self.target_identifier.error_coefficient_bound
        } else {
            &self.target_order.error_coefficient_bound
        }
    }

    #[cfg(test)]
    pub(crate) fn every_decryption_margin_is_positive(&self) -> bool {
        self.target_identifier
            .minimum_decryption_margin
            .is_positive()
            && self.target_order.minimum_decryption_margin.is_positive()
    }
}

/// Ordered release stages that extend the evaluator recurrence through the
/// selected threshold-four target decoder. Bounds use four times the centered
/// reconstruction error so the `p / 4` conversion-rounding term stays exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetReleaseNoiseStage {
    PositiveMessageConversion,
    PartialShare,
    Flooding,
    AuthorizedInterpolation,
    Reconstruction,
    Decode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetReleaseNoiseStageBound {
    pub(crate) stage: TargetReleaseNoiseStage,
    pub(crate) four_times_reconstruction_error_bound: BigUint,
    pub(crate) scaled_no_wrap_margin: BigInt,
}

pub(crate) struct DirectBallotTargetReleaseNoiseInput<'a> {
    pub(crate) participant_count: u64,
    pub(crate) ballot_count: usize,
    pub(crate) option_count: usize,
    pub(crate) minimum_score: u64,
    pub(crate) maximum_score: u64,
    pub(crate) denominator_clearing_factor: u64,
    pub(crate) reconstruction_threshold: usize,
    pub(crate) maximum_authorized_coefficient_norm: u64,
    pub(crate) flooding_coefficient_bound: &'a BigUint,
}

/// Continues the exact evaluator target bound through positive BGV-to-BFV
/// conversion, one partial share, flooding, authorized interpolation, full
/// reconstruction, and plaintext decode. The final margin is exactly
/// `2q - p * (4 * E)`, so positivity is equivalent to the strict C2 bound.
pub(crate) fn direct_ballot_target_release_noise_trace(
    input: DirectBallotTargetReleaseNoiseInput<'_>,
) -> CanonicalResult<Vec<TargetReleaseNoiseStageBound>> {
    let DirectBallotTargetReleaseNoiseInput {
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
        denominator_clearing_factor,
        reconstruction_threshold,
        maximum_authorized_coefficient_norm,
        flooding_coefficient_bound,
    } = input;
    if denominator_clearing_factor == 0
        || reconstruction_threshold == 0
        || maximum_authorized_coefficient_norm == 0
        || flooding_coefficient_bound.is_zero()
    {
        return Err(invalid_recurrence(
            "target release recurrence requires positive selected parameters",
        ));
    }
    let target_bounds = direct_ballot_target_noise_bounds(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
    )?;
    let evaluation_error_bound = target_bounds
        .iter()
        .map(DirectBallotTargetNoiseBound::maximum_error_coefficient_bound)
        .max()
        .cloned()
        .ok_or_else(|| invalid_recurrence("target release recurrence has no evaluator target"))?;
    let target_level = target_bounds
        .first()
        .map(|bound| bound.target_identifier.level)
        .ok_or_else(|| invalid_recurrence("target release recurrence has no target level"))?;
    if target_bounds.iter().any(|bound| {
        bound.target_identifier.level != target_level || bound.target_order.level != target_level
    }) {
        return Err(invalid_recurrence(
            "target release recurrence targets do not share one basis",
        ));
    }
    let target_modulus = DATA_PRIMES[..=target_level]
        .iter()
        .map(|prime| BigUint::from(*prime))
        .product::<BigUint>();
    let clearing_factor = BigUint::from(denominator_clearing_factor);
    let four = BigUint::from(4_u8);
    let plaintext_modulus = BigUint::from(PLAINTEXT_MODULUS);
    let converted_error = &four * &clearing_factor * evaluation_error_bound;
    let one_share_flooding_error = &four * flooding_coefficient_bound;
    let interpolated_flooding_error = &one_share_flooding_error
        * BigUint::from(reconstruction_threshold)
        * BigUint::from(maximum_authorized_coefficient_norm);
    let conversion_rounding_error = &plaintext_modulus * (&clearing_factor + BigUint::one());

    let stage_bounds = [
        (
            TargetReleaseNoiseStage::PositiveMessageConversion,
            converted_error.clone(),
        ),
        (
            TargetReleaseNoiseStage::PartialShare,
            converted_error.clone(),
        ),
        (
            TargetReleaseNoiseStage::Flooding,
            &converted_error + &one_share_flooding_error,
        ),
        (
            TargetReleaseNoiseStage::AuthorizedInterpolation,
            &converted_error + &interpolated_flooding_error,
        ),
        (
            TargetReleaseNoiseStage::Reconstruction,
            &converted_error + &interpolated_flooding_error + &conversion_rounding_error,
        ),
        (
            TargetReleaseNoiseStage::Decode,
            &converted_error + &interpolated_flooding_error + &conversion_rounding_error,
        ),
    ];
    Ok(stage_bounds
        .into_iter()
        .map(|(stage, four_times_reconstruction_error_bound)| {
            let scaled_no_wrap_margin = BigInt::from(&target_modulus << 1_usize)
                - BigInt::from(&plaintext_modulus * &four_times_reconstruction_error_bound);
            TargetReleaseNoiseStageBound {
                stage,
                four_times_reconstruction_error_bound,
                scaled_no_wrap_margin,
            }
        })
        .collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolicState {
    level: usize,
    message_bound: BigUint,
    error_bound: BigUint,
    minimum_margin: BigInt,
}

impl SymbolicState {
    fn new(level: usize, message_bound: BigUint, error_bound: BigUint) -> Self {
        let minimum_margin = decryption_margin(level, &message_bound, &error_bound);
        Self {
            level,
            message_bound,
            error_bound,
            minimum_margin,
        }
    }

    fn derived(
        &self,
        level: usize,
        message_bound: BigUint,
        error_bound: BigUint,
        other_minimum_margin: Option<&BigInt>,
    ) -> Self {
        let current_margin = decryption_margin(level, &message_bound, &error_bound);
        let minimum_margin = other_minimum_margin.map_or_else(
            || self.minimum_margin.clone(),
            |other| self.minimum_margin.clone().min(other.clone()),
        );
        Self {
            level,
            message_bound,
            error_bound,
            minimum_margin: minimum_margin.min(current_margin),
        }
    }

    fn add(&self, other: &Self) -> CanonicalResult<Self> {
        require_same_level(self, other, "addition")?;
        let unreduced_message_bound = &self.message_bound + &other.message_bound;
        let error_bound = &self.error_bound
            + &other.error_bound
            + centered_reduction_carry_bound(&unreduced_message_bound);
        Ok(self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            Some(&other.minimum_margin),
        ))
    }

    fn plaintext_add(&self, coefficients: &[u32]) -> Self {
        let (infinity_norm, _, lift_offset) = plaintext_norms(coefficients);
        let unreduced_message_bound = &self.message_bound + &infinity_norm;
        let error_bound = &self.error_bound
            + centered_reduction_carry_bound(&unreduced_message_bound)
            + lift_offset;
        self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            None,
        )
    }

    fn plaintext_multiply<Coefficient>(&self, coefficients: &[Coefficient]) -> Self
    where
        Coefficient: Copy + Into<u64>,
    {
        let (_, l1_norm, _) = plaintext_norms(coefficients);
        let unreduced_message_bound = &self.message_bound * &l1_norm;
        let error_bound = (&self.error_bound * l1_norm)
            + centered_reduction_carry_bound(&unreduced_message_bound);
        self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            None,
        )
    }

    fn rotate(&self, participant_count: u64) -> CanonicalResult<Self> {
        let error_bound = &self.error_bound
            + hybrid_key_switch_error_bound(self.level, participant_count, false)?;
        Ok(self.derived(self.level, self.message_bound.clone(), error_bound, None))
    }

    fn fixed_subring_multiply(
        &self,
        other: &Self,
        participant_count: u64,
    ) -> CanonicalResult<Self> {
        require_same_level(self, other, "fixed-subring multiplication")?;
        let centered_bound = BigUint::from(CENTERED_PLAINTEXT_BOUND);
        let unreduced_message_bound = &centered_bound * &self.message_bound * &other.message_bound;
        let error_bound = &centered_bound * &self.message_bound * &other.error_bound
            + &centered_bound * &other.message_bound * &self.error_bound
            + BigUint::from(PLAINTEXT_MODULUS)
                * BigUint::from(POLYNOMIAL_DEGREE)
                * &self.error_bound
                * &other.error_bound
            + centered_reduction_carry_bound(&unreduced_message_bound)
            + hybrid_key_switch_error_bound(self.level, participant_count, true)?;
        Ok(self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            Some(&other.minimum_margin),
        ))
    }

    fn character_multiply(
        &self,
        other: &Self,
        left_width: usize,
        right_width: usize,
        participant_count: u64,
    ) -> CanonicalResult<Self> {
        require_same_level(self, other, "pair-character multiplication")?;
        let centered_bound = BigUint::from(CENTERED_PLAINTEXT_BOUND);
        let left_structure_norm = &centered_bound * BigUint::from(left_width);
        let right_structure_norm = &centered_bound * BigUint::from(right_width);
        let product_structure_norm = &centered_bound * BigUint::from(left_width.min(right_width));
        let unreduced_message_bound =
            &product_structure_norm * &self.message_bound * &other.message_bound;
        let error_bound = left_structure_norm * &self.message_bound * &other.error_bound
            + right_structure_norm * &other.message_bound * &self.error_bound
            + BigUint::from(PLAINTEXT_MODULUS)
                * BigUint::from(POLYNOMIAL_DEGREE)
                * &self.error_bound
                * &other.error_bound
            + centered_reduction_carry_bound(&unreduced_message_bound)
            + hybrid_key_switch_error_bound(self.level, participant_count, true)?;
        Ok(self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            Some(&other.minimum_margin),
        ))
    }

    fn modulus_switch_to(
        &self,
        target_level: usize,
        participant_count: u64,
    ) -> CanonicalResult<Self> {
        if target_level > self.level {
            return Err(invalid_recurrence(
                "symbolic modulus switch cannot raise the ciphertext level",
            ));
        }
        let mut state = self.clone();
        while state.level > target_level {
            state = state.modulus_switch_once(participant_count)?;
        }
        Ok(state)
    }

    fn modulus_switch_once(&self, participant_count: u64) -> CanonicalResult<Self> {
        if self.level == 0 {
            return Err(invalid_recurrence(
                "symbolic modulus switch cannot drop level zero",
            ));
        }
        let dropped_modulus = DATA_PRIMES[self.level];
        if dropped_modulus % PLAINTEXT_MODULUS != 1 {
            return Err(invalid_recurrence(
                "selected data modulus is not one modulo the plaintext modulus",
            ));
        }
        let correction_bound = BigUint::from(dropped_modulus / 2)
            * (BigUint::one()
                + BigUint::from(POLYNOMIAL_DEGREE) * BigUint::from(participant_count));
        let scaling_transition_bound =
            BigUint::from((dropped_modulus - 1) / PLAINTEXT_MODULUS) * &self.message_bound;
        let numerator = &self.error_bound + correction_bound + scaling_transition_bound;
        let error_bound = divide_with_ceiling(&numerator, &BigUint::from(dropped_modulus));
        Ok(self.derived(
            self.level - 1,
            self.message_bound.clone(),
            error_bound,
            None,
        ))
    }
}

/// Runs the exact production recurrence for all twenty selected target counts.
/// Other roster sizes and score domains are intentionally unsupported by the
/// current cryptographic prototype.
pub(crate) fn direct_ballot_target_noise_bounds(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    Ok(derive_direct_ballot_noise_bounds(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
    )?
    .target_bounds)
}

#[cfg(test)]
pub(crate) fn direct_ballot_evaluator_noise_traces(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
) -> CanonicalResult<Vec<SelectedEvaluatorStreamNoiseTrace>> {
    Ok(derive_direct_ballot_noise_bounds(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
    )?
    .stream_traces)
}

struct DerivedDirectBallotNoiseBounds {
    target_bounds: Vec<DirectBallotTargetNoiseBound>,
    #[cfg(test)]
    stream_traces: Vec<SelectedEvaluatorStreamNoiseTrace>,
}

fn derive_direct_ballot_noise_bounds(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
) -> CanonicalResult<DerivedDirectBallotNoiseBounds> {
    if participant_count != u64::from(FOUNDATION_PROFILE.participant_count)
        || ballot_count == 0
        || ballot_count > usize::from(FOUNDATION_PROFILE.participant_count)
        || option_count != usize::from(FOUNDATION_PROFILE.option_count)
        || minimum_score != u64::from(FOUNDATION_PROFILE.minimum_score)
        || maximum_score != u64::from(FOUNDATION_PROFILE.maximum_score)
        || PLAINTEXT_MODULUS != 257
        || POLYNOMIAL_DEGREE != 32_768
        || DATA_PRIMES.len() != SELECTED_EVALUATOR_WORKING_LEVEL + 1
        || CANONICAL_TARGET_CIPHERTEXT_LEVEL != 7
    {
        return Err(invalid_recurrence(
            "noise recurrence is defined only for the exact selected direct-ballot suite",
        ));
    }

    let first_aggregate_character_bound =
        selected_pair_character_product_bound(participant_count, ballot_count)?;
    let second_aggregate_character_bound = first_aggregate_character_bound.clone();
    let aggregate_character_bounds = [
        first_aggregate_character_bound,
        second_aggregate_character_bound,
    ];
    if aggregate_character_bounds
        .iter()
        .any(|bound| bound.level != CHARACTER_OUTPUT_LEVEL)
    {
        return Err(invalid_recurrence(
            "pair-character product reached the wrong selected level",
        ));
    }
    let program = selected_evaluator_program_set()?;
    let constants_by_hash = program
        .constants()
        .iter()
        .map(|constant| Ok((*constant.constant_hash()?.as_bytes(), constant.values())))
        .collect::<CanonicalResult<BTreeMap<_, _>>>()?;

    let mut target_bounds = Vec::with_capacity(program.streams().len());
    #[cfg(test)]
    let mut stream_traces = Vec::with_capacity(program.streams().len());
    for stream in program.streams() {
        let evaluated_stream = evaluate_selected_stream(
            stream.instructions(),
            &constants_by_hash,
            &aggregate_character_bounds,
            participant_count,
        )?;
        target_bounds.push(DirectBallotTargetNoiseBound {
            top_count: usize::from(stream.top_count()),
            target_identifier: SymbolicCiphertextBound::from_state(
                &evaluated_stream.target_identifier,
                participant_count,
            ),
            target_order: SymbolicCiphertextBound::from_state(
                &evaluated_stream.target_order,
                participant_count,
            ),
        });
        #[cfg(test)]
        stream_traces.push(SelectedEvaluatorStreamNoiseTrace {
            top_count: stream.top_count(),
            pair_character_input_bounds: aggregate_character_bounds
                .clone()
                .map(|state| SymbolicCiphertextBound::from_state(&state, participant_count)),
            register_bounds: evaluated_stream
                .register_bounds
                .iter()
                .map(|state| SymbolicCiphertextBound::from_state(state, participant_count))
                .collect(),
        });
    }
    Ok(DerivedDirectBallotNoiseBounds {
        target_bounds,
        #[cfg(test)]
        stream_traces,
    })
}

fn selected_pair_character_product_bound(
    participant_count: u64,
    ballot_count: usize,
) -> CanonicalResult<SymbolicState> {
    let fresh_error = BigUint::from(2_u8)
        * BigUint::from(POLYNOMIAL_DEGREE)
        * BigUint::from(FRESH_ERROR_COEFFICIENT_BOUND)
        * BigUint::from(FRESH_RANDOMIZER_COEFFICIENT_BOUND)
        * BigUint::from(participant_count)
        + BigUint::from(FRESH_ERROR_COEFFICIENT_BOUND)
        + BigUint::from(CANONICAL_PLAINTEXT_LIFT_OFFSET_BOUND);
    let fresh_state = SymbolicState::new(
        SELECTED_EVALUATOR_WORKING_LEVEL,
        BigUint::from(CENTERED_PLAINTEXT_BOUND),
        fresh_error,
    );
    let schedule = canonical_pair_character_product_schedule(ballot_count)?;
    let root = schedule.nodes[schedule.root_node_ordinal];
    let executed_modulus_switch_count = schedule
        .merges
        .iter()
        .map(|merge| {
            usize::from(merge.left_alignment_drop_count > 0)
                + usize::from(merge.right_alignment_drop_count > 0)
                + usize::from(merge.depth_drop_count > 0)
        })
        .sum::<usize>()
        + usize::from(root.level > schedule.terminal_output_level);
    let executed_modulus_drop_count = schedule
        .merges
        .iter()
        .map(|merge| {
            merge.left_alignment_drop_count
                + merge.right_alignment_drop_count
                + merge.depth_drop_count
        })
        .sum::<usize>()
        + root.level.saturating_sub(schedule.terminal_output_level);
    if schedule.accounting.ciphertext_multiplication_count != schedule.merges.len()
        || schedule.accounting.relinearization_count != schedule.merges.len()
        || schedule
            .accounting
            .normalization_plaintext_multiplication_count
            != usize::from(schedule.normalization.requires_plaintext_multiplication())
        || schedule.accounting.modulus_switch_count() != executed_modulus_switch_count
        || schedule.accounting.modulus_drop_count() != executed_modulus_drop_count
    {
        return Err(invalid_recurrence(
            "pair-character schedule accounting does not match its operations",
        ));
    }

    let mut states = vec![None; schedule.nodes.len()];
    for node in schedule
        .nodes
        .iter()
        .filter(|node| node.multiplication_depth == 0)
    {
        states[node.node_ordinal] = Some(fresh_state.clone());
    }
    for merge in &schedule.merges {
        let left_node = schedule.nodes[merge.left_node_ordinal];
        let right_node = schedule.nodes[merge.right_node_ordinal];
        let output_node = schedule.nodes[merge.output_node_ordinal];
        let left = states[merge.left_node_ordinal]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("pair-character left product state is absent"))?
            .modulus_switch_to(merge.alignment_level, participant_count)?;
        let right = states[merge.right_node_ordinal]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("pair-character right product state is absent"))?
            .modulus_switch_to(merge.alignment_level, participant_count)?;
        let product = left
            .character_multiply(
                &right,
                left_node.message_width,
                right_node.message_width,
                participant_count,
            )?
            .modulus_switch_to(output_node.level, participant_count)?;
        states[merge.output_node_ordinal] = Some(product);
    }

    let mut product = states[schedule.root_node_ordinal]
        .take()
        .ok_or_else(|| invalid_recurrence("pair-character root product state is absent"))?;
    if schedule.normalization.requires_plaintext_multiplication() {
        let normalization_coefficients = schedule.normalization.plaintext_coefficients();
        let (_, centered_l1_norm, _) = plaintext_norms(&normalization_coefficients);
        if centered_l1_norm != BigUint::from(schedule.normalization.centered_coefficient_l1_norm)
            || schedule.normalization.centered_coefficient_l1_norm
                != schedule.normalization.convolution_infinity_operator_norm
        {
            return Err(invalid_recurrence(
                "pair-character normalization does not have its selected unit norms",
            ));
        }
        product = product.plaintext_multiply(&normalization_coefficients);
    }
    product.modulus_switch_to(schedule.terminal_output_level, participant_count)
}

fn evaluate_selected_stream(
    instructions: &[EvaluatorInstruction],
    constants_by_hash: &BTreeMap<[u8; Hash512::BYTE_LENGTH], &[u32]>,
    aggregate_character_bounds: &[SymbolicState; 2],
    participant_count: u64,
) -> CanonicalResult<EvaluatedSelectedStream> {
    let mut registers = aggregate_character_bounds
        .iter()
        .cloned()
        .map(Some)
        .collect::<Vec<_>>();
    #[cfg(test)]
    let mut register_bounds = aggregate_character_bounds.to_vec();
    let mut target_identifier = None;
    let mut target_order = None;
    for instruction in instructions {
        let inputs = instruction
            .input_registers()
            .iter()
            .map(|register| read_symbolic_register(&registers, *register))
            .collect::<CanonicalResult<Vec<_>>>()?;
        let output = match instruction.opcode() {
            EvaluatorOpcode::ModulusSwitchToLevel => Some(inputs[0].modulus_switch_to(
                usize::try_from(instruction.immediate0()).map_err(|_| {
                    invalid_recurrence("symbolic target level does not fit the host index")
                })?,
                participant_count,
            )?),
            EvaluatorOpcode::NormalizeDecryptionMultiplier => Some(inputs[0].clone()),
            EvaluatorOpcode::CiphertextAdd => Some(inputs[0].add(inputs[1])?),
            EvaluatorOpcode::PlaintextAdd => {
                Some(inputs[0].plaintext_add(instruction_constant(instruction, constants_by_hash)?))
            }
            EvaluatorOpcode::PlaintextMultiply => Some(
                inputs[0].plaintext_multiply(instruction_constant(instruction, constants_by_hash)?),
            ),
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop => Some(
                inputs[0]
                    .fixed_subring_multiply(inputs[1], participant_count)?
                    .modulus_switch_to(inputs[0].level - 1, participant_count)?,
            ),
            EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                Some(inputs[0].fixed_subring_multiply(inputs[1], participant_count)?)
            }
            EvaluatorOpcode::GaloisRotate => Some(inputs[0].rotate(participant_count)?),
            EvaluatorOpcode::DropRegister => {
                let register = usize::try_from(instruction.input_registers()[0]).map_err(|_| {
                    invalid_recurrence("symbolic drop register does not fit the host index")
                })?;
                registers
                    .get_mut(register)
                    .ok_or_else(|| invalid_recurrence("symbolic drop register is undefined"))?
                    .take()
                    .ok_or_else(|| invalid_recurrence("symbolic register was already dropped"))?;
                None
            }
            EvaluatorOpcode::DeclareOutput => {
                let target = inputs[0].clone();
                match instruction.immediate0() {
                    1 => target_identifier = Some(target),
                    2 => target_order = Some(target),
                    _ => {
                        return Err(invalid_recurrence(
                            "symbolic evaluator output role is unassigned",
                        ));
                    }
                }
                None
            }
        };
        if let Some(output) = output {
            let output_register = usize::try_from(
                instruction
                    .output_register()
                    .ok_or_else(|| invalid_recurrence("symbolic output register is absent"))?,
            )
            .map_err(|_| invalid_recurrence("symbolic output register does not fit usize"))?;
            if output_register != registers.len() {
                return Err(invalid_recurrence(
                    "symbolic evaluator registers are not consecutive",
                ));
            }
            #[cfg(test)]
            register_bounds.push(output.clone());
            registers.push(Some(output));
        }
    }
    let target_identifier = target_identifier
        .ok_or_else(|| invalid_recurrence("symbolic target identifier was not declared"))?;
    let target_order =
        target_order.ok_or_else(|| invalid_recurrence("symbolic target order was not declared"))?;
    if target_identifier.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
        || target_order.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
    {
        return Err(invalid_recurrence(
            "symbolic evaluator targets reached the wrong selected level",
        ));
    }
    Ok(EvaluatedSelectedStream {
        target_identifier,
        target_order,
        #[cfg(test)]
        register_bounds,
    })
}

struct EvaluatedSelectedStream {
    target_identifier: SymbolicState,
    target_order: SymbolicState,
    #[cfg(test)]
    register_bounds: Vec<SymbolicState>,
}

fn instruction_constant<'a>(
    instruction: &EvaluatorInstruction,
    constants_by_hash: &'a BTreeMap<[u8; Hash512::BYTE_LENGTH], &[u32]>,
) -> CanonicalResult<&'a [u32]> {
    let hash = instruction
        .constant_hash()
        .ok_or_else(|| invalid_recurrence("symbolic plaintext instruction has no constant"))?;
    constants_by_hash
        .get(hash.as_bytes())
        .copied()
        .ok_or_else(|| invalid_recurrence("symbolic plaintext constant is not in the program"))
}

fn read_symbolic_register(
    registers: &[Option<SymbolicState>],
    register: u32,
) -> CanonicalResult<&SymbolicState> {
    registers
        .get(
            usize::try_from(register)
                .map_err(|_| invalid_recurrence("symbolic register does not fit usize"))?,
        )
        .and_then(Option::as_ref)
        .ok_or_else(|| invalid_recurrence("symbolic evaluator used an unavailable register"))
}

fn hybrid_key_switch_error_bound(
    level: usize,
    participant_count: u64,
    relinearization: bool,
) -> CanonicalResult<BigUint> {
    if level >= DATA_PRIMES.len() {
        return Err(invalid_recurrence(
            "symbolic key-switch level is outside the selected data basis",
        ));
    }
    let active_block_count = (level + 1).div_ceil(KEY_SWITCH_DATA_PRIMES_PER_BLOCK);
    let maximum_block_modulus = DATA_PRIMES[..=level]
        .chunks(KEY_SWITCH_DATA_PRIMES_PER_BLOCK)
        .map(|block| {
            block
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product::<BigUint>()
        })
        .max()
        .ok_or_else(|| invalid_recurrence("symbolic key-switch basis is empty"))?;
    let twice_participant_count = BigUint::from(2_u8) * BigUint::from(participant_count);
    let evaluation_key_error = if relinearization {
        BigUint::from(2_u8)
            * BigUint::from(POLYNOMIAL_DEGREE)
            * BigUint::from(participant_count)
            * &twice_participant_count
            + &twice_participant_count
    } else {
        twice_participant_count
    };
    let decomposed_numerator = BigUint::from(active_block_count)
        * BigUint::from(POLYNOMIAL_DEGREE)
        * maximum_block_modulus
        * evaluation_key_error;
    let decomposed_error = divide_with_ceiling(
        &decomposed_numerator,
        &(BigUint::from(2_u8) * key_switch_special_basis_modulus_product()),
    );
    Ok(decomposed_error
        + BigUint::one()
        + divide_with_ceiling(
            &(BigUint::from(POLYNOMIAL_DEGREE) * BigUint::from(participant_count)),
            &BigUint::from(2_u8),
        ))
}

fn plaintext_norms<Coefficient>(coefficients: &[Coefficient]) -> (BigUint, BigUint, BigUint)
where
    Coefficient: Copy + Into<u64>,
{
    let mut infinity_norm = BigUint::zero();
    let mut l1_norm = BigUint::zero();
    let mut lift_offset = BigUint::zero();
    for coefficient in coefficients {
        let residue = (*coefficient).into();
        let centered_absolute = residue.min(PLAINTEXT_MODULUS - residue);
        infinity_norm = infinity_norm.max(BigUint::from(centered_absolute));
        l1_norm += BigUint::from(centered_absolute);
        if residue > CENTERED_PLAINTEXT_BOUND {
            lift_offset = BigUint::one();
        }
    }
    (infinity_norm, l1_norm, lift_offset)
}

fn require_same_level(
    left: &SymbolicState,
    right: &SymbolicState,
    operation: &str,
) -> CanonicalResult<()> {
    if left.level != right.level {
        return Err(invalid_recurrence(format!(
            "symbolic {operation} requires equal ciphertext levels",
        )));
    }
    Ok(())
}

fn decryption_margin(level: usize, message_bound: &BigUint, error_bound: &BigUint) -> BigInt {
    let active_modulus = DATA_PRIMES[..=level]
        .iter()
        .map(|prime| BigUint::from(*prime))
        .product::<BigUint>();
    let raw_decryption_bound = message_bound + BigUint::from(PLAINTEXT_MODULUS) * error_bound;
    BigInt::from(active_modulus) - BigInt::from(BigUint::from(2_u8) * raw_decryption_bound)
}

fn centered_reduction_carry_bound(unreduced_bound: &BigUint) -> BigUint {
    (unreduced_bound + BigUint::from(CENTERED_PLAINTEXT_BOUND)) / BigUint::from(PLAINTEXT_MODULUS)
}

fn canonical_message_bound(unreduced_bound: BigUint) -> BigUint {
    unreduced_bound.min(BigUint::from(CENTERED_PLAINTEXT_BOUND))
}

fn divide_with_ceiling(numerator: &BigUint, denominator: &BigUint) -> BigUint {
    let quotient = numerator / denominator;
    if numerator % denominator == BigUint::zero() {
        quotient
    } else {
        quotient + BigUint::one()
    }
}

fn invalid_recurrence(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::bgv::evaluator::program::selected_evaluator_program_set_with_stage_registers;

    #[test]
    fn selected_recurrence_pins_the_exact_worst_target_error() {
        let bounds =
            direct_ballot_target_noise_bounds(10, 10, 20, 1, 10).expect("selected recurrence");
        assert_eq!(bounds.len(), 20);
        let worst = bounds
            .iter()
            .max_by_key(|bound| bound.maximum_error_coefficient_bound())
            .expect("selected target bounds");
        assert_eq!(worst.top_count, 8);
        assert_eq!(
            worst.maximum_error_coefficient_bound().to_str_radix(10),
            "16873484365703521901782467690810",
        );
        assert!(
            bounds
                .iter()
                .all(DirectBallotTargetNoiseBound::every_decryption_margin_is_positive)
        );
    }

    #[test]
    fn selected_recurrence_is_monotone_and_positive_for_every_accepted_ballot_count() {
        let mut previous_product_error = None;
        let mut previous_target_bounds: Option<Vec<DirectBallotTargetNoiseBound>> = None;
        for ballot_count in 1..=10 {
            let product = selected_pair_character_product_bound(10, ballot_count)
                .expect("selected pair-character recurrence");
            assert_eq!(product.level, CHARACTER_OUTPUT_LEVEL);
            assert!(product.minimum_margin.is_positive());
            if let Some(previous_error) = previous_product_error.as_ref() {
                if ballot_count == 2 {
                    // Both paths finish with the same selected level-20 modulus
                    // switch. Its exact correction and scaling terms dominate
                    // the incoming error and round both bounds to this value.
                    assert_eq!(product.error_bound, *previous_error);
                    assert_eq!(product.error_bound, BigUint::from(163_841_u64));
                } else {
                    assert!(
                        product.error_bound > *previous_error,
                        "pair-character error did not grow from {} to {ballot_count} ballots: previous={previous_error}, current={}",
                        ballot_count - 1,
                        product.error_bound,
                    );
                }
            }
            previous_product_error = Some(product.error_bound);

            let target_bounds = direct_ballot_target_noise_bounds(10, ballot_count, 20, 1, 10)
                .expect("selected target recurrence");
            assert_eq!(target_bounds.len(), 20);
            assert!(
                target_bounds
                    .iter()
                    .all(DirectBallotTargetNoiseBound::every_decryption_margin_is_positive)
            );
            if let Some(previous_bounds) = previous_target_bounds.as_ref() {
                for (previous, current) in previous_bounds.iter().zip(&target_bounds) {
                    assert_eq!(current.top_count, previous.top_count);
                    assert!(
                        current.target_identifier.error_coefficient_bound
                            >= previous.target_identifier.error_coefficient_bound,
                        "target-identifier error decreased for top count {} at {ballot_count} ballots",
                        current.top_count
                    );
                    assert!(
                        current.target_order.error_coefficient_bound
                            >= previous.target_order.error_coefficient_bound,
                        "target-order error decreased for top count {} at {ballot_count} ballots",
                        current.top_count
                    );
                }
            }
            previous_target_bounds = Some(target_bounds);
        }
    }

    #[test]
    fn selected_recurrence_covers_both_inputs_and_every_compiler_stage() {
        let (program, compiler_streams) = selected_evaluator_program_set_with_stage_registers()
            .expect("selected compiler stage catalog");
        assert_eq!(program.streams().len(), 20);
        assert_eq!(compiler_streams.len(), program.streams().len());

        let expected_stages = compiler_streams
            .iter()
            .flat_map(|stream| stream.stage_registers())
            .map(|entry| entry.stage())
            .collect::<BTreeSet<_>>();
        assert!(!expected_stages.is_empty());

        for ballot_count in 1..=10 {
            let traces = direct_ballot_evaluator_noise_traces(10, ballot_count, 20, 1, 10)
                .expect("selected evaluator noise traces");
            assert_eq!(traces.len(), program.streams().len());
            let mut observed_stages = BTreeSet::new();

            for ((trace, stream), compiler_stream) in
                traces.iter().zip(program.streams()).zip(&compiler_streams)
            {
                assert_eq!(trace.top_count(), stream.top_count());
                assert_eq!(trace.top_count(), compiler_stream.top_count());
                for input_bound in trace.pair_character_input_bounds() {
                    assert_eq!(input_bound.level, CHARACTER_OUTPUT_LEVEL);
                    assert_eq!(input_bound.decrypt_scaling, 1);
                    assert_eq!(input_bound.component_count, 2);
                    assert_eq!(input_bound.collective_secret_coefficient_bound, 10);
                    assert!(input_bound.minimum_decryption_margin.is_positive());
                }
                assert_eq!(
                    trace.pair_character_input_bounds()[0],
                    trace.pair_character_input_bounds()[1],
                    "both production ballot streams must enter the evaluator under the same checked schedule",
                );

                for instruction in stream.instructions() {
                    if let Some(output_register) = instruction.output_register() {
                        let bound = trace.register_bound(output_register).unwrap_or_else(|| {
                            panic!(
                                "missing symbolic bound for top count {} register {output_register}",
                                trace.top_count(),
                            )
                        });
                        assert!(bound.minimum_decryption_margin.is_positive());
                    }
                }
                for stage_register in compiler_stream.stage_registers() {
                    let stage_bound = trace
                        .register_bound(stage_register.register_ordinal())
                        .unwrap_or_else(|| {
                            panic!(
                                "missing symbolic stage bound for top count {} and stage {:?}",
                                trace.top_count(),
                                stage_register.stage(),
                            )
                        });
                    assert!(stage_bound.minimum_decryption_margin.is_positive());
                    observed_stages.insert(stage_register.stage());
                }
            }
            assert_eq!(observed_stages, expected_stages);
        }
    }

    #[test]
    fn hostile_centered_carries_and_negacyclic_products_fit_the_symbolic_bounds() {
        for message_residue in 0..PLAINTEXT_MODULUS {
            let centered_message = independent_centered_lift(BigInt::from(message_residue));
            for added_residue in 0..PLAINTEXT_MODULUS {
                let centered_addend = independent_centered_lift(BigInt::from(added_residue));
                let unreduced = &centered_message + centered_addend;
                let centered_output = independent_centered_lift(unreduced.clone());
                let exact_carry = (&unreduced - &centered_output) / BigInt::from(PLAINTEXT_MODULUS);
                let state =
                    SymbolicState::new(0, centered_message.magnitude().clone(), BigUint::zero())
                        .plaintext_add(&[
                            u32::try_from(added_residue).expect("field residue fits u32")
                        ]);
                assert!(centered_output.magnitude() <= &state.message_bound);
                assert!(exact_carry.magnitude() <= &state.error_bound);
            }
        }

        let message = [128_i64, -128, 127, -127, 1, -1, 64, -64].map(BigInt::from);
        let error = [2_i64, -2, -2, 2, 1, -1, 0, 2].map(BigInt::from);
        let constant_residues = [128_u32, 129, 256, 1, 0, 127, 130, 2];
        let centered_constant =
            constant_residues.map(|residue| independent_centered_lift(BigInt::from(residue)));
        let unreduced_message = independent_negacyclic_product(&message, &centered_constant);
        let centered_message = unreduced_message
            .iter()
            .cloned()
            .map(independent_centered_lift)
            .collect::<Vec<_>>();
        let carries = unreduced_message
            .iter()
            .zip(&centered_message)
            .map(|(unreduced, centered)| (unreduced - centered) / BigInt::from(PLAINTEXT_MODULUS))
            .collect::<Vec<_>>();
        let exact_error = independent_negacyclic_product(&error, &centered_constant)
            .into_iter()
            .zip(carries)
            .map(|(product, carry)| product + carry)
            .collect::<Vec<_>>();
        let symbolic = SymbolicState::new(
            7,
            independent_infinity_norm(&message),
            independent_infinity_norm(&error),
        )
        .plaintext_multiply(&constant_residues);
        assert!(independent_infinity_norm(&centered_message) <= symbolic.message_bound);
        assert!(independent_infinity_norm(&exact_error) <= symbolic.error_bound);
        assert!(symbolic.minimum_margin.is_positive());
    }

    #[test]
    fn selected_recurrence_rejects_each_nonselected_dimension() {
        for arguments in [
            (9, 10, 20, 1, 10),
            (10, 0, 20, 1, 10),
            (10, 11, 20, 1, 10),
            (10, 10, 19, 1, 10),
            (10, 10, 21, 1, 10),
            (10, 10, 20, 0, 10),
            (10, 10, 20, 1, 11),
        ] {
            assert!(
                direct_ballot_target_noise_bounds(
                    arguments.0,
                    arguments.1,
                    arguments.2,
                    arguments.3,
                    arguments.4,
                )
                .is_err()
            );
        }
    }

    fn independent_centered_lift(value: BigInt) -> BigInt {
        let plaintext_modulus = BigInt::from(PLAINTEXT_MODULUS);
        let mut residue = value % &plaintext_modulus;
        if residue.is_negative() {
            residue += &plaintext_modulus;
        }
        if residue > BigInt::from(CENTERED_PLAINTEXT_BOUND) {
            residue -= plaintext_modulus;
        }
        residue
    }

    fn independent_negacyclic_product<const RING_DEGREE: usize>(
        left: &[BigInt; RING_DEGREE],
        right: &[BigInt; RING_DEGREE],
    ) -> Vec<BigInt> {
        let mut product = vec![BigInt::zero(); RING_DEGREE];
        for (left_ordinal, left_coefficient) in left.iter().enumerate() {
            for (right_ordinal, right_coefficient) in right.iter().enumerate() {
                let unreduced_ordinal = left_ordinal + right_ordinal;
                let term = left_coefficient * right_coefficient;
                if unreduced_ordinal < RING_DEGREE {
                    product[unreduced_ordinal] += term;
                } else {
                    product[unreduced_ordinal - RING_DEGREE] -= term;
                }
            }
        }
        product
    }

    fn independent_infinity_norm(coefficients: &[BigInt]) -> BigUint {
        coefficients
            .iter()
            .map(|coefficient| coefficient.magnitude())
            .max()
            .cloned()
            .unwrap_or_else(BigUint::zero)
    }
}
