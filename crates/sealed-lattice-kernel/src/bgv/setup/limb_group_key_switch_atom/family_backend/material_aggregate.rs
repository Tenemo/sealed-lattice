//! Aggregate binding for the committed key-switch material (S1).
//!
//! The published runtime key is the per-limb sum of the trustee materials. Once
//! the material is committed as an atom column (S0) rather than re-summed from
//! raw bytes, the aggregate is bound by a random linear evaluation instead of by
//! reconstruction: the verifier reconstructs the integer coefficient sum from the
//! per-limb runtime key by CRT plus a public per-coefficient wrap multiple, then
//! checks it against the trustee columns' opened linear evaluations.
//!
//! For one key the coefficient sum is
//!
//! ```text
//! S[digit][c] = sum_i recombined_B_i[digit][c]   (integer, |S| <= n * Q_L / 2)
//!            = R[digit][c] + w[digit][c] * Q_L
//! ```
//!
//! where `R` is the centered CRT recombination of the runtime key over the level
//! primes, `Q_L` is their product, and `w` is the wrap multiple bounded by
//! `ceil(n / 2)` (n = roster size). With `delta` a Fiat-Shamir vector drawn after
//! every trustee commitment and the published aggregate, the batched
//! delta-opening (built separately) yields `z_i = <delta, recombined_B_i>`, and
//! this module checks `sum_i z_i == <delta, S>`. A forged runtime key or wrap
//! multiple moves `S`, so the check fails except with probability about
//! `1 / |F_p|` (Schwartz-Zippel). The trust base is Fiat-Shamir plus Reed-Solomon
//! distance only; there is no homomorphic commitment.

use super::super::proof_field::ProofFieldParameters;

// The largest wrap multiple magnitude a roster of `roster_size` centered mod-Q_L
// summands can produce: each summand is in (-Q_L/2, Q_L/2], so the sum is in
// (-n*Q_L/2, n*Q_L/2], hence |w| <= ceil(n/2).
fn maximum_wrap_multiple_magnitude(roster_size: usize) -> i64 {
    roster_size.div_ceil(2) as i64
}

// Reconstruct the integer coefficient sum `S = R + w * Q_L` as a proof-field
// element, refusing a wrap multiple outside the roster-bounded range. `R` is the
// centered CRT recombination of the runtime key (one proof-field element per
// coefficient); `wrap_multiple` is the public signed wrap; `group_modulus` is
// `Q_L` as a proof-field element.
fn coefficient_sum<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    recombined_coefficient: &[u64; LIMB_COUNT],
    group_modulus: &[u64; LIMB_COUNT],
    wrap_multiple: i64,
    roster_size: usize,
) -> Option<[u64; LIMB_COUNT]> {
    if wrap_multiple.abs() > maximum_wrap_multiple_magnitude(roster_size) {
        return None;
    }
    let wrap = parameters.signed_word_to_element(wrap_multiple);
    let wrap_contribution = parameters.multiply(&wrap, group_modulus);
    Some(parameters.add(recombined_coefficient, &wrap_contribution))
}

// The S1 aggregate identity for one key: `sum_i z_i == <delta, R + w * Q_L>`,
// with every wrap multiple inside the roster-bounded range. `recombined_runtime_
// key[digit][coeff]` is the centered CRT recombination of the published runtime
// key; `wrap_multiples[digit][coeff]` and `delta[digit][coeff]` share that shape;
// `evaluations[i]` is trustee i's opened `<delta, recombined_B_i>`. Returns false
// on any shape mismatch, out-of-range wrap, or identity mismatch (fail-closed).
pub(crate) fn material_aggregate_identity_holds<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    recombined_runtime_key: &[Vec<[u64; LIMB_COUNT]>],
    group_modulus: &[u64; LIMB_COUNT],
    wrap_multiples: &[Vec<i64>],
    roster_size: usize,
    delta: &[Vec<[u64; LIMB_COUNT]>],
    evaluations: &[[u64; LIMB_COUNT]],
) -> bool {
    if roster_size == 0 || evaluations.len() != roster_size {
        return false;
    }
    let digit_count = recombined_runtime_key.len();
    if digit_count == 0
        || wrap_multiples.len() != digit_count
        || delta.len() != digit_count
    {
        return false;
    }

    let mut delta_dot_sum = parameters.zero();
    for digit in 0..digit_count {
        let recombined_digit = &recombined_runtime_key[digit];
        let wrap_digit = &wrap_multiples[digit];
        let delta_digit = &delta[digit];
        let coefficient_count = recombined_digit.len();
        if coefficient_count == 0
            || wrap_digit.len() != coefficient_count
            || delta_digit.len() != coefficient_count
        {
            return false;
        }
        for coefficient in 0..coefficient_count {
            let Some(sum) = coefficient_sum(
                parameters,
                &recombined_digit[coefficient],
                group_modulus,
                wrap_digit[coefficient],
                roster_size,
            ) else {
                return false;
            };
            delta_dot_sum = parameters.add(
                &delta_dot_sum,
                &parameters.multiply(&delta_digit[coefficient], &sum),
            );
        }
    }

    let mut evaluation_sum = parameters.zero();
    for evaluation in evaluations {
        evaluation_sum = parameters.add(&evaluation_sum, evaluation);
    }

    evaluation_sum == delta_dot_sum
}

#[cfg(test)]
mod tests {
    use super::super::super::limb_group_statement::LimbGroupContext;
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;
    use crate::bgv::parameters::DATA_PRIMES;

    // A deterministic proof-field element from a mixing state.
    fn element(parameters: &ProofFieldParameters<13>, state: &mut u64) -> [u64; 13] {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        parameters.unsigned_word_to_element(*state)
    }

    // Build an honest instance: random recombined runtime key R and wrap
    // multiples w within range, delta random, and a single trustee carrying the
    // whole evaluation z_0 = <delta, R + w*Q_L> (others zero), so the identity
    // holds by construction. Returns every input plus the honest evaluations.
    #[allow(clippy::type_complexity)]
    fn honest_instance(
        parameters: &ProofFieldParameters<13>,
        group_modulus: &[u64; 13],
        digit_count: usize,
        coefficient_count: usize,
        roster_size: usize,
    ) -> (
        Vec<Vec<[u64; 13]>>,
        Vec<Vec<i64>>,
        Vec<Vec<[u64; 13]>>,
        Vec<[u64; 13]>,
    ) {
        let mut state = 0x51a1_u64;
        let max_wrap = maximum_wrap_multiple_magnitude(roster_size);
        let mut recombined = Vec::with_capacity(digit_count);
        let mut wraps = Vec::with_capacity(digit_count);
        let mut delta = Vec::with_capacity(digit_count);
        let mut total = parameters.zero();
        for _ in 0..digit_count {
            let mut recombined_digit = Vec::with_capacity(coefficient_count);
            let mut wrap_digit = Vec::with_capacity(coefficient_count);
            let mut delta_digit = Vec::with_capacity(coefficient_count);
            for _ in 0..coefficient_count {
                let recombined_coefficient = element(parameters, &mut state);
                // A wrap in [-max_wrap, max_wrap].
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let wrap = (state % (2 * max_wrap as u64 + 1)) as i64 - max_wrap;
                let delta_coefficient = element(parameters, &mut state);
                let sum = coefficient_sum(
                    parameters,
                    &recombined_coefficient,
                    group_modulus,
                    wrap,
                    roster_size,
                )
                .expect("wrap in range");
                total = parameters.add(
                    &total,
                    &parameters.multiply(&delta_coefficient, &sum),
                );
                recombined_digit.push(recombined_coefficient);
                wrap_digit.push(wrap);
                delta_digit.push(delta_coefficient);
            }
            recombined.push(recombined_digit);
            wraps.push(wrap_digit);
            delta.push(delta_digit);
        }
        let mut evaluations = vec![parameters.zero(); roster_size];
        evaluations[0] = total;
        (recombined, wraps, delta, evaluations)
    }

    #[test]
    fn honest_aggregate_identity_holds_and_forgeries_are_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        // Level-1 group (two primes) is enough to exercise the arithmetic; the
        // check is modulus-size independent.
        let group = LimbGroupContext::new(&parameters, &DATA_PRIMES[..2]).expect("group builds");
        let group_modulus = group.group_modulus_element(&parameters);
        let roster_size = 7;
        let (recombined, wraps, delta, evaluations) =
            honest_instance(&parameters, &group_modulus, 2, 24, roster_size);

        assert!(
            material_aggregate_identity_holds(
                &parameters,
                &recombined,
                &group_modulus,
                &wraps,
                roster_size,
                &delta,
                &evaluations,
            ),
            "the honest aggregate identity must hold"
        );

        // Forge the runtime key in one coefficient: S moves, the check fails.
        let mut forged_recombined = recombined.clone();
        forged_recombined[1][9] = parameters.add(&forged_recombined[1][9], &parameters.one());
        assert!(
            !material_aggregate_identity_holds(
                &parameters,
                &forged_recombined,
                &group_modulus,
                &wraps,
                roster_size,
                &delta,
                &evaluations,
            ),
            "a forged runtime-key coefficient must be rejected"
        );

        // Forge one wrap multiple (still in range): S moves by Q_L, the check fails.
        let mut forged_wraps = wraps.clone();
        forged_wraps[0][3] += 1;
        assert!(
            !material_aggregate_identity_holds(
                &parameters,
                &recombined,
                &group_modulus,
                &forged_wraps,
                roster_size,
                &delta,
                &evaluations,
            ),
            "a forged in-range wrap multiple must be rejected"
        );

        // An out-of-range wrap multiple is refused outright.
        let mut out_of_range_wraps = wraps.clone();
        out_of_range_wraps[0][0] = maximum_wrap_multiple_magnitude(roster_size) + 1;
        assert!(
            !material_aggregate_identity_holds(
                &parameters,
                &recombined,
                &group_modulus,
                &out_of_range_wraps,
                roster_size,
                &delta,
                &evaluations,
            ),
            "a wrap multiple beyond ceil(n/2) must be refused"
        );

        // Dropping a trustee's evaluation (here, tampering the carrying one)
        // breaks the sum.
        let mut forged_evaluations = evaluations.clone();
        forged_evaluations[0] = parameters.add(&forged_evaluations[0], &parameters.one());
        assert!(
            !material_aggregate_identity_holds(
                &parameters,
                &recombined,
                &group_modulus,
                &wraps,
                roster_size,
                &delta,
                &forged_evaluations,
            ),
            "a tampered trustee evaluation must be rejected"
        );
    }

    #[test]
    fn shape_mismatches_are_fail_closed() {
        let parameters = sixteen_limb_group_field_parameters();
        let group = LimbGroupContext::new(&parameters, &DATA_PRIMES[..2]).expect("group builds");
        let group_modulus = group.group_modulus_element(&parameters);
        let roster_size = 5;
        let (recombined, wraps, delta, evaluations) =
            honest_instance(&parameters, &group_modulus, 2, 16, roster_size);

        // Wrong evaluation count.
        assert!(!material_aggregate_identity_holds(
            &parameters,
            &recombined,
            &group_modulus,
            &wraps,
            roster_size,
            &delta,
            &evaluations[..roster_size - 1],
        ));
        // Empty digit set.
        assert!(!material_aggregate_identity_holds(
            &parameters,
            &[],
            &group_modulus,
            &[],
            roster_size,
            &[],
            &evaluations,
        ));
        // Mismatched coefficient counts between delta and the runtime key.
        let mut short_delta = delta.clone();
        short_delta[0].pop();
        assert!(!material_aggregate_identity_holds(
            &parameters,
            &recombined,
            &group_modulus,
            &wraps,
            roster_size,
            &short_delta,
            &evaluations,
        ));
    }
}
