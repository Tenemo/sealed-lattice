use super::{
    GENERATOR_SUBGROUP_ORDER, SELECTED_EVALUATOR_WORKING_LEVEL,
    direct_score_packing_basis_galois_elements, direct_score_packing_galois_elements,
    galois_element_moving_slot_to_target, generator_inverse_power_basis_for_exponent,
    generator_power_basis_for_exponent, interpolate_coefficients, logical_slot_galois_element,
    packed_rank_forward_basis_galois_elements, packed_rank_return_basis_galois_elements,
    selected_evaluator_rotation_key_schedule,
};
use crate::bgv::modular_arithmetic::{add_mod, mul_mod, pow_mod};
use crate::bgv::parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE};

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
