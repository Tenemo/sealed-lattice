use super::{
    DIRECT_COMPARISON_OUTPUT_LEVEL, accumulate_rank, ahead_indicator, bit_extraction_polynomials,
    bit_sliced_greater_than_and_equal, broadcast_constant, comparison_polynomials,
    derive_score_bits, direct_score_packing_basis_galois_elements,
    direct_score_packing_galois_elements, evaluate_direct_comparison_polynomial,
    evaluate_packed_rank_evaluation_from_packed_scores,
    evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs,
    evaluate_packed_ranks_via_difference, evaluate_top_k_via_difference,
    exact_rank_indicators_for_option, galois_element_moving_slot_to_target, galois_power,
    generator_exponent_or_conjugated, generator_power_basis_for_exponent, interpolate_coefficients,
    inverse_galois_element, pack_broadcast_scores, packed_rank_forward_basis_galois_elements,
    packed_rank_galois_elements, packed_rank_return_basis_galois_elements, packed_score_slot,
    project_packed_sparse_target_from_rank_evaluation, project_sparse_target, score_bit_count,
    selected_evaluator_rotation_key_schedule, top_k_indicator, top_k_order_value,
};
use crate::bgv::evaluator::{
    circuit::{EvaluatorContext, modulus_switch_to, normalize_scaling},
    engine::{Ciphertext, add_plaintext_coefficients, ciphertext_sub},
};
use crate::bgv::modular_arithmetic::{add_mod, mul_mod, pow_mod};
use crate::bgv::profile::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE};

mod interpolation;
mod packing_and_rotations;
mod rank_evaluation;
mod sparse_target;

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

// Encrypt a value broadcast into every slot (the constant polynomial).
fn encrypt_broadcast(context: &EvaluatorContext, value: u64, seed: &str) -> Ciphertext {
    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    coefficients[0] = value;
    context
        .key()
        .encrypt_coefficients(&coefficients, seed)
        .expect("encrypt broadcast")
}
