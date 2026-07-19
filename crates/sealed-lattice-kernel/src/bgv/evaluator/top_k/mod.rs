mod interpolation;
mod rotations;
pub(crate) use interpolation::*;
pub(crate) use rotations::*;

use crate::bgv::modular_arithmetic::{add_mod, inverse_mod, mul_mod, sub_mod};
use crate::{
    bgv::parameters::PLAINTEXT_MODULUS,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

// Each of the two pair-character product trees begins at the complete data
// basis. The schedule fixes every switch point through character products,
// extension trace, scatter, and the paired rank selector.
pub(crate) const SELECTED_EVALUATOR_WORKING_LEVEL: usize = 22;
pub(crate) const CHARACTER_SWITCHED_MULTIPLICATION_DEPTH_COUNT: usize = 4;
pub(crate) const RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorModulusSchedule {
    pub(crate) character_depth_drop_counts: [usize; CHARACTER_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
    pub(crate) pre_trace_drop_count: usize,
    pub(crate) post_trace_drop_count: usize,
    pub(crate) post_scatter_drop_count: usize,
    pub(crate) rank_depth_drop_counts: [usize; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
}

pub(crate) const SELECTED_EVALUATOR_MODULUS_SCHEDULE: EvaluatorModulusSchedule =
    EvaluatorModulusSchedule {
        character_depth_drop_counts: [1, 2, 0, 0],
        pre_trace_drop_count: 1,
        post_trace_drop_count: 4,
        post_scatter_drop_count: 1,
        rank_depth_drop_counts: [0, 2, 2, 1, 1],
    };
pub(crate) const SELECTED_RELINEARIZATION_KEY_LEVEL: usize = 22;
pub(crate) const CHARACTER_OUTPUT_LEVEL: usize = 19;
pub(crate) const TRACE_KEY_LEVEL: usize = 18;
pub(crate) const SCATTER_KEY_LEVEL: usize = 14;
pub(crate) const RANK_INPUT_LEVEL: usize = 13;
pub(crate) const CANONICAL_TARGET_CIPHERTEXT_LEVEL: usize = 7;
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

#[cfg(test)]
mod tests;
