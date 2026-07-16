use super::super::evaluation_domain::EvaluationDomainPlan;
#[cfg(test)]
use super::super::extension_field::CHALLENGE_EXTENSION_DEGREE;
use super::super::extension_field::{ChallengeExtensionElement, ChallengeExtensionTower};
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::*;
use crate::bgv::modular_arithmetic::{inverse_mod, pow_mod};

#[cfg(test)]
pub(super) fn trim_trailing_zeros(mut coefficients: Vec<u64>) -> Vec<u64> {
    while coefficients.last() == Some(&0) {
        coefficients.pop();
    }

    coefficients
}

// Synthetic division by Z_H = X^T - 1: returns (quotient, remainder) with the
// remainder of length T.
#[cfg(test)]
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
        let mut accepted_point = None;
        for _ in 0..transcript.maximum_candidate_draws_per_output() {
            let candidate = transcript.challenge_extension_elements("deep-point", modulus, 1)?[0];
            if ChallengeExtensionTower::is_zero(&candidate)
                || points.contains(&candidate)
                || tower.pow(&candidate, plan.trace_size as u64) == ChallengeExtensionTower::one()
            {
                continue;
            }
            // Every element of the coset raises to g^extension_size, so this
            // single equality rejects the whole coset at once; likewise
            // candidate^trace_size == 1 rejects all of H.
            if tower.pow(&candidate, plan.extension_size as u64) == coset_marker {
                continue;
            }
            accepted_point = Some(candidate);
            break;
        }
        points.push(accepted_point.ok_or_else(|| {
            invalid_succinct_setup_proof(
                "the DEEP-point candidate-draw limit was exhausted before deriving an out-of-domain point",
            )
        })?);
    }

    Ok(points)
}

pub(in super::super) fn sample_deep_identity_points(
    transcript: &mut FiatShamirTranscript,
    plan: &EvaluationDomainPlan,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let mut points = sample_deep_points(transcript, plan)?;
    points.push(ChallengeExtensionTower::zero());

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

// Split a logical length-N public vector into trace halves and extend each.
#[cfg(test)]
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
#[cfg(test)]
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
