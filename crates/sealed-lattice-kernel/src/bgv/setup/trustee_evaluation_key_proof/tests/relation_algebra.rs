use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::extension_field::ChallengeExtensionTower;
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::low_degree_proof::{
    LowDegreeParameters, commit_low_degree, open_low_degree_at_positions,
};
use super::*;
use crate::bgv::modular_arithmetic::pow_mod;
use crate::bgv::parameters::POLYNOMIAL_DEGREE;

#[test]
fn degree_t_sumcheck_residual_shifts_subgroup_constant() {
    // A sumcheck residual of degree exactly T can hide a false constant by
    // adding a term that vanishes on the trace subgroup: the forged slack is
    // zero at X = 0 but has degree exactly T. This is why the residual column
    // carries its own degree-below-T low-degree proof, which rejects it.
    let modulus = DATA_PRIMES[0];
    let trace_size = 64_usize;
    let trace_root = pow_mod(
        crate::bgv::parameters::root_parameters_for_modulus(modulus)
            .expect("root parameters")
            .negacyclic_root,
        (2 * crate::bgv::parameters::POLYNOMIAL_DEGREE / trace_size) as u64,
        modulus,
    )
    .expect("trace root");
    let false_constant_delta = 17_u64;
    let true_expected_constant = 123_u64;
    let false_expected_constant = (true_expected_constant + false_constant_delta) % modulus;
    let forged_top_coefficient = (modulus - false_constant_delta) % modulus;

    assert_ne!(forged_top_coefficient, 0);
    assert_eq!(
        (false_expected_constant + forged_top_coefficient) % modulus,
        true_expected_constant
    );

    let mut subgroup_point = 1_u64;
    for _position in 0..trace_size {
        assert_eq!(
            pow_mod(subgroup_point, trace_size as u64, modulus).expect("power"),
            1
        );
        let forged_residual_at_trace_point = forged_top_coefficient;
        assert_eq!(
            (false_expected_constant + forged_residual_at_trace_point) % modulus,
            true_expected_constant,
            "the degree-T slack preserves the false sumcheck on the trace subgroup"
        );
        subgroup_point =
            (u128::from(subgroup_point) * u128::from(trace_root) % u128::from(modulus)) as u64;
    }

    let mut forged_residual_coefficients = vec![0_u64; trace_size + 1];
    forged_residual_coefficients[trace_size] = forged_top_coefficient;
    assert_eq!(forged_residual_coefficients[0], 0);
    assert!(
        forged_residual_coefficients.len() > trace_size,
        "the forged residual has degree T and violates the new degree-below-T bound"
    );
}

#[test]
fn full_ring_low_degree_proof_accepts_degree_below_main_bound() {
    let modulus = DATA_PRIMES[0];
    let trace_size = POLYNOMIAL_DEGREE / super::super::TRACE_SPLIT;
    let plan = EvaluationDomainPlan::new(modulus, trace_size).expect("domain plan");
    let degree_bound = super::super::COMMITMENT_BOUND_FACTOR * plan.trace_size;
    let mut initial_layer = vec![ChallengeExtensionTower::zero(); plan.extension_size];
    for coordinate in 0..super::super::extension_field::CHALLENGE_EXTENSION_DEGREE {
        let mut coefficients = vec![0_u64; degree_bound];
        coefficients[coordinate] = 17 + coordinate as u64;
        coefficients[plan.trace_size - 1 + coordinate] = 23 + coordinate as u64;
        coefficients[degree_bound - 1 - coordinate] = 29 + coordinate as u64;
        for (value, coordinate_value) in initial_layer
            .iter_mut()
            .zip(plan.extension_evaluations_from_coefficients(&coefficients))
        {
            value[coordinate] = coordinate_value;
        }
    }
    let parameters = LowDegreeParameters {
        modulus,
        initial_domain_size: plan.extension_size,
        initial_offset: plan.coset_offset,
        initial_root: plan.extension_root,
        initial_degree_bound: degree_bound,
    };
    let mut transcript = FiatShamirTranscript::new(
        "full-ring-low-degree-test",
        super::super::MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    )
    .expect("the fixed Fiat-Shamir candidate-draw limit is positive");
    transcript.absorb(
        "low-degree-purpose",
        super::super::MAIN_LOW_DEGREE_TRANSCRIPT_PURPOSE,
    );

    let state = commit_low_degree(&mut transcript, &parameters, &initial_layer)
        .expect("full-ring degree-below-bound polynomial must commit");
    let query_positions = transcript
        .challenge_positions(
            "shared-query-position",
            plan.extension_size / 2,
            super::super::LOW_DEGREE_QUERY_COUNT,
        )
        .expect("query challenges derive within the fixed candidate-draw limit");
    open_low_degree_at_positions(state, &query_positions)
        .expect("full-ring degree-below-bound polynomial must open");
}
