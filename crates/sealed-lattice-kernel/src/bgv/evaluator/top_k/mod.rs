#[cfg(test)]
pub(crate) mod character_comparison;
mod comparison;
mod interpolation;
#[cfg(test)]
pub(crate) mod pairwise_topology;
mod rotations;
mod score_packing;
pub(crate) use comparison::*;
pub(crate) use interpolation::*;
pub(crate) use rotations::*;
pub(crate) use score_packing::*;

use crate::bgv::{
    evaluator::engine::encode_slots_to_coefficients,
    modular_arithmetic::{add_mod, integer_square_root_ceil, inverse_mod, mul_mod, sub_mod},
};
use crate::{
    bgv::parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

// The frozen evaluator working level for the selected multi-ballot parameters:
// the pair-difference aggregate enters at this level and every multiplication
// happens at or below it. The directed Galois keys are generated separately at
// the exact comparison-output level where their first opcode consumes them.
pub(crate) const SELECTED_EVALUATOR_WORKING_LEVEL: usize = 25;
pub(crate) const COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT: usize = 8;
pub(crate) const RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorModulusSchedule {
    pub(crate) pre_comparison_drop_count: usize,
    pub(crate) comparison_depth_drop_counts:
        [usize; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
    pub(crate) rank_depth_drop_counts: [usize; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
}

impl EvaluatorModulusSchedule {
    pub(crate) const fn total_drop_count(&self) -> usize {
        let mut total = self.pre_comparison_drop_count;
        let mut comparison_depth = 0;
        while comparison_depth < self.comparison_depth_drop_counts.len() {
            total += self.comparison_depth_drop_counts[comparison_depth];
            comparison_depth += 1;
        }
        let mut rank_depth = 0;
        while rank_depth < self.rank_depth_drop_counts.len() {
            total += self.rank_depth_drop_counts[rank_depth];
            rank_depth += 1;
        }
        total
    }

    pub(crate) const fn comparison_drop_count(&self) -> usize {
        let mut total = 0;
        let mut depth = 0;
        while depth < self.comparison_depth_drop_counts.len() {
            total += self.comparison_depth_drop_counts[depth];
            depth += 1;
        }
        total
    }
}

// This schedule is replaced only by the exact joint search. Its entries are
// indexed by switched multiplication depth, not by multiplication occurrence;
// every power at one depth therefore reaches the same data-basis prefix.
pub(crate) const SELECTED_EVALUATOR_MODULUS_SCHEDULE: EvaluatorModulusSchedule =
    EvaluatorModulusSchedule {
        pre_comparison_drop_count: 2,
        comparison_depth_drop_counts: [1; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
        rank_depth_drop_counts: [2; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
    };
// The first product determines the one suite-fixed relinearization-key level;
// every later product uses the same key through CRT-prefix truncation.
pub(crate) const SELECTED_RELINEARIZATION_KEY_LEVEL: usize = SELECTED_EVALUATOR_WORKING_LEVEL
    - SELECTED_EVALUATOR_MODULUS_SCHEDULE.pre_comparison_drop_count;
pub(crate) const DIRECT_COMPARISON_OUTPUT_LEVEL: usize = SELECTED_RELINEARIZATION_KEY_LEVEL
    - SELECTED_EVALUATOR_MODULUS_SCHEDULE.comparison_drop_count();
// Every target stream is normalized to the six-prime terminal basis selected
// by the exact evaluator and factor-four release bounds.
pub(crate) const CANONICAL_TARGET_CIPHERTEXT_LEVEL: usize = 5;
// Five is near the square root of the degree-19 rank lookup.
pub(crate) const RANK_LOOKUP_BABY_STEP_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScheduledPowerTableProduct {
    pub(crate) output_power: usize,
    pub(crate) lower_power: usize,
    pub(crate) upper_power: usize,
    pub(crate) multiplication_depth: usize,
}

pub(crate) fn scheduled_power_table_products(
    highest_power: usize,
    base_multiplication_depth: usize,
) -> CanonicalResult<Vec<ScheduledPowerTableProduct>> {
    let mut multiplication_depths = vec![None; highest_power + 1];
    if highest_power >= 1 {
        multiplication_depths[1] = Some(base_multiplication_depth);
    }
    let mut products = Vec::with_capacity(highest_power.saturating_sub(1));
    for output_power in 2..=highest_power {
        let lower_power = output_power / 2;
        let upper_power = output_power - lower_power;
        let lower_depth = multiplication_depths[lower_power].ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "scheduled lower power is missing",
            )
        })?;
        let upper_depth = multiplication_depths[upper_power].ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "scheduled upper power is missing",
            )
        })?;
        let multiplication_depth =
            lower_depth.max(upper_depth).checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "scheduled multiplication depth overflowed",
                )
            })?;
        multiplication_depths[output_power] = Some(multiplication_depth);
        products.push(ScheduledPowerTableProduct {
            output_power,
            lower_power,
            upper_power,
            multiplication_depth,
        });
    }
    Ok(products)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScheduledMultiplicationLevelTrace {
    pub(crate) multiplication_depth: usize,
    pub(crate) left_input_level: usize,
    pub(crate) right_input_level: usize,
    pub(crate) modulus_drop_count: usize,
    pub(crate) output_level: usize,
}

pub(crate) fn prepared_polynomial_power_level_trace(
    input_level: usize,
    coefficient_count: usize,
    baby_step_count: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<Vec<ScheduledMultiplicationLevelTrace>> {
    if coefficient_count <= baby_step_count || baby_step_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "power-level trace requires nontrivial Paterson-Stockmeyer geometry",
        ));
    }
    let mut trace = Vec::new();
    let baby_power_levels = append_power_table_level_trace(
        input_level,
        0,
        baby_step_count,
        depth_drop_counts,
        &mut trace,
    )?;
    let giant_base_level = baby_power_levels[baby_step_count].ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "power-level trace omitted the giant-step base",
        )
    })?;
    let giant_base_depth = scheduled_power_table_products(baby_step_count, 0)?
        .last()
        .map_or(0, |product| product.multiplication_depth);
    append_power_table_level_trace(
        giant_base_level,
        giant_base_depth,
        coefficient_count
            .div_ceil(baby_step_count)
            .saturating_sub(1),
        depth_drop_counts,
        &mut trace,
    )?;
    Ok(trace)
}

fn append_power_table_level_trace(
    base_level: usize,
    base_multiplication_depth: usize,
    highest_power: usize,
    depth_drop_counts: &[usize],
    trace: &mut Vec<ScheduledMultiplicationLevelTrace>,
) -> CanonicalResult<Vec<Option<usize>>> {
    let mut levels = vec![None; highest_power + 1];
    if highest_power >= 1 {
        levels[1] = Some(base_level);
    }
    for product in scheduled_power_table_products(highest_power, base_multiplication_depth)? {
        let left_input_level = levels[product.lower_power].ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "power-level trace is missing its lower input",
            )
        })?;
        let right_input_level = levels[product.upper_power].ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "power-level trace is missing its upper input",
            )
        })?;
        let modulus_drop_count = *depth_drop_counts
            .get(product.multiplication_depth - 1)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "power-level trace exceeded its depth schedule",
                )
            })?;
        let product_level = left_input_level.min(right_input_level);
        let output_level = product_level
            .checked_sub(modulus_drop_count)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "power-level trace drop exceeds its active level",
                )
            })?;
        levels[product.output_power] = Some(output_level);
        trace.push(ScheduledMultiplicationLevelTrace {
            multiplication_depth: product.multiplication_depth,
            left_input_level,
            right_input_level,
            modulus_drop_count,
            output_level,
        });
    }
    Ok(levels)
}

const GENERATOR_SUBGROUP_ORDER: usize = POLYNOMIAL_DEGREE / 2;

#[cfg(test)]
mod tests;
