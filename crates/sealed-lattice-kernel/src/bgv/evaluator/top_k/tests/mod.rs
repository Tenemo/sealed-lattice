use super::{
    SELECTED_EVALUATOR_WORKING_LEVEL, bit_extraction_polynomials,
    direct_score_packing_basis_galois_elements, direct_score_packing_galois_elements,
    galois_element_moving_slot_to_target, generator_exponent_or_conjugated,
    generator_power_basis_for_exponent, interpolate_coefficients, inverse_galois_element,
    packed_rank_forward_basis_galois_elements, packed_rank_galois_elements,
    packed_rank_return_basis_galois_elements, packed_score_slot, score_bit_count,
    selected_evaluator_rotation_key_schedule, top_k_order_value,
};
use crate::bgv::evaluator::circuit::EvaluatorContext;
use crate::bgv::modular_arithmetic::{add_mod, mul_mod, pow_mod};
use crate::bgv::parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE};

mod interpolation;
mod packing_and_rotations;
mod rank_evaluation;

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
