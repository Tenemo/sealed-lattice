use super::{
    DIRECT_COMPARISON_OUTPUT_LEVEL, GENERATOR_SUBGROUP_ORDER, NEGATIVE_ONE_GALOIS_ELEMENT,
    NEGATIVE_SEVEN_GALOIS_ELEMENT, POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT,
    forward_pair_window_rotation_path, galois_power, generator_exponent_or_conjugated,
    interpolate_coefficients, inverse_galois_element, inverse_pair_shift_rotation_path,
    logical_slot_galois_element, selected_evaluator_rotation_key_schedule,
};
use crate::bgv::modular_arithmetic::{add_mod, mul_mod, pow_mod};
use crate::bgv::parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE};
use crate::foundation::FOUNDATION_PROFILE;

mod interpolation;
mod rotation_schedule;

fn evaluate_plaintext(coefficients: &[u64], point: u64) -> u64 {
    let mut accumulator = 0_u64;
    for (degree, coefficient) in coefficients.iter().enumerate() {
        let power = pow_mod(point, degree as u64, PLAINTEXT_MODULUS).expect("power");
        accumulator = add_mod(
            accumulator,
            mul_mod(*coefficient, power, PLAINTEXT_MODULUS).expect("mul"),
            PLAINTEXT_MODULUS,
        )
        .expect("add");
    }
    accumulator
}
