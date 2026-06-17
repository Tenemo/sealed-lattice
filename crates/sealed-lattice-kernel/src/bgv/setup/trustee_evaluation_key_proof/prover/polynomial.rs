use super::super::evaluation_domain::{EvaluationDomainPlan, negacyclic_transpose_product};
use super::super::extension_field::{
    CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
};
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::*;
use crate::bgv::modular_arithmetic::{inverse_mod, pow_mod};

pub(super) fn trim_trailing_zeros(mut coefficients: Vec<u64>) -> Vec<u64> {
    while coefficients.last() == Some(&0) {
        coefficients.pop();
    }

    coefficients
}

// Synthetic division by Z_H = X^T - 1: returns (quotient, remainder) with the
// remainder of length T.
pub(in super::super) fn divide_by_trace_vanishing(
    coefficients: &[u64],
    trace_size: usize,
    modulus: u64,
) -> (Vec<u64>, Vec<u64>) {
    if coefficients.len() <= trace_size {
        let mut remainder = coefficients.to_vec();
        remainder.resize(trace_size, 0);
        return (Vec::new(), remainder);
    }
    let quotient_length = coefficients.len() - trace_size;
    let mut quotient = vec![0_u64; quotient_length];
    for index in (0..quotient_length).rev() {
        let mut value = coefficients[index + trace_size];
        if index + trace_size < quotient_length {
            value = add_mod_fast(value, quotient[index + trace_size], modulus);
        }
        quotient[index] = value;
    }
    let mut remainder = Vec::with_capacity(trace_size);
    for index in 0..trace_size {
        let mut value = coefficients[index];
        if index < quotient_length {
            value = add_mod_fast(value, quotient[index], modulus);
        }
        remainder.push(value);
    }

    (quotient, remainder)
}

// Shared per-point trace interpolation weights at one out-of-domain
// extension point.
pub(in super::super) fn barycentric_weights(
    plan: &EvaluationDomainPlan,
    tower: &ChallengeExtensionTower,
    point: &ChallengeExtensionElement,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let modulus = plan.modulus;
    // Barycentric interpolation over H = {omega^i}; valid only for a point
    // outside H (else a difference is zero and inversion fails), which
    // sample_deep_points guarantees by rejecting H.
    let mut differences = Vec::with_capacity(plan.trace_size);
    let mut subgroup_power = 1_u64;
    for _ in 0..plan.trace_size {
        differences.push(tower.sub(point, &tower.embed_base(subgroup_power)));
        subgroup_power = mul_mod_fast(subgroup_power, plan.trace_root, modulus);
    }
    let inverted = tower.batch_inverse(&differences)?;
    let vanishing = trace_vanishing_at_extension(plan, tower, point);
    let scale = tower.scale_base(&vanishing, inverse_mod(plan.trace_size as u64, modulus)?);
    let mut weights = Vec::with_capacity(plan.trace_size);
    let mut subgroup_power = 1_u64;
    for inverted_difference in inverted {
        weights.push(tower.mul(
            &tower.scale_base(&scale, subgroup_power),
            &inverted_difference,
        ));
        subgroup_power = mul_mod_fast(subgroup_power, plan.trace_root, modulus);
    }

    Ok(weights)
}

// Z_H(z) = z^T - 1 at an extension point.
pub(in super::super) fn trace_vanishing_at_extension(
    plan: &EvaluationDomainPlan,
    tower: &ChallengeExtensionTower,
    point: &ChallengeExtensionElement,
) -> ChallengeExtensionElement {
    tower.sub(
        &tower.pow(point, plan.trace_size as u64),
        &ChallengeExtensionTower::one(),
    )
}

// Deterministic rejection sampling of out-of-domain points shared by prover
// and verifier: extension points avoiding zero, the base trace subgroup, and
// the base extension coset.
pub(in super::super) fn sample_deep_points(
    transcript: &mut FiatShamirTranscript,
    plan: &EvaluationDomainPlan,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let modulus = plan.modulus;
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let coset_marker = tower.embed_base(pow_mod(
        plan.coset_offset,
        plan.extension_size as u64,
        modulus,
    )?);
    let mut points = Vec::with_capacity(DEEP_POINT_COUNT);
    while points.len() < DEEP_POINT_COUNT {
        let candidate = transcript.challenge_extension_elements("deep-point", modulus, 1)[0];
        if ChallengeExtensionTower::is_zero(&candidate) {
            continue;
        }
        if tower.pow(&candidate, plan.trace_size as u64) == ChallengeExtensionTower::one() {
            continue;
        }
        // Every element of the coset raises to g^extension_size, so this single
        // equality rejects the whole coset at once; likewise
        // candidate^trace_size == 1 rejects all of H.
        if tower.pow(&candidate, plan.extension_size as u64) == coset_marker {
            continue;
        }
        points.push(candidate);
    }

    Ok(points)
}

pub(super) fn extension_powers(
    tower: &ChallengeExtensionTower,
    base: &ChallengeExtensionElement,
    count: usize,
) -> Vec<ChallengeExtensionElement> {
    let mut powers = Vec::with_capacity(count);
    let mut power = ChallengeExtensionTower::one();
    for _ in 0..count {
        powers.push(power);
        power = tower.mul(&power, base);
    }

    powers
}

// Transpose action of the negacyclic matrix of an extension polynomial on an
// extension vector: expand both operands over the basis pairs, run the base
// transpose action per pair, and recombine through the tower basis products.
pub(super) fn negacyclic_transpose_product_extension_matrix(
    tower: &ChallengeExtensionTower,
    matrix_polynomial: &[ChallengeExtensionElement],
    vector: &[ChallengeExtensionElement],
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let length = vector.len();
    let mut result = vec![ChallengeExtensionTower::zero(); length];
    let mut matrix_coordinate = vec![0_u64; matrix_polynomial.len()];
    let mut vector_coordinate = vec![0_u64; length];
    for matrix_basis in 0..CHALLENGE_EXTENSION_DEGREE {
        for (slot, element) in matrix_coordinate.iter_mut().zip(matrix_polynomial.iter()) {
            *slot = element[matrix_basis];
        }
        let mut matrix_basis_element = ChallengeExtensionTower::zero();
        matrix_basis_element[matrix_basis] = 1;
        for vector_basis in 0..CHALLENGE_EXTENSION_DEGREE {
            for (slot, element) in vector_coordinate.iter_mut().zip(vector.iter()) {
                *slot = element[vector_basis];
            }
            let transposed =
                negacyclic_transpose_product(&matrix_coordinate, &vector_coordinate, modulus)?;
            let mut vector_basis_element = ChallengeExtensionTower::zero();
            vector_basis_element[vector_basis] = 1;
            let basis_product = tower.mul(&matrix_basis_element, &vector_basis_element);
            for (target, value) in result.iter_mut().zip(transposed.iter()) {
                *target = tower.add(target, &tower.scale_base(&basis_product, *value));
            }
        }
    }

    Ok(result)
}

// Split a logical length-N public vector into trace halves and extend each.
pub(super) fn extend_logical_vector(plan: &EvaluationDomainPlan, vector: &[u64]) -> [Vec<u64>; 2] {
    let trace_size = plan.trace_size;
    [
        plan.extension_evaluations_from_coefficients(
            &plan.coefficients_from_trace_values(&vector[..trace_size]),
        ),
        plan.extension_evaluations_from_coefficients(
            &plan.coefficients_from_trace_values(&vector[trace_size..]),
        ),
    ]
}

// The same split-and-extend for an extension-valued public vector, applied
// per challenge extension coordinate.
pub(super) fn extend_logical_vector_extension(
    plan: &EvaluationDomainPlan,
    vector: &[ChallengeExtensionElement],
) -> [Vec<ChallengeExtensionElement>; 2] {
    let extension_size = plan.extension_size;
    let mut halves = [
        vec![ChallengeExtensionTower::zero(); extension_size],
        vec![ChallengeExtensionTower::zero(); extension_size],
    ];
    let mut coordinate_vector = vec![0_u64; vector.len()];
    for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
        for (slot, element) in coordinate_vector.iter_mut().zip(vector.iter()) {
            *slot = element[coordinate];
        }
        let extended = extend_logical_vector(plan, &coordinate_vector);
        for (half, extended_half) in halves.iter_mut().zip(extended.iter()) {
            for (target, value) in half.iter_mut().zip(extended_half.iter()) {
                target[coordinate] = *value;
            }
        }
    }

    halves
}
