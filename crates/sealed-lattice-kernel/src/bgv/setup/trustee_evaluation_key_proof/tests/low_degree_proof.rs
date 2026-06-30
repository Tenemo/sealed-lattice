use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::extension_field::ChallengeExtensionTower;
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::low_degree_proof::{LowDegreeParameters, prove_low_degree};
use super::*;
use crate::bgv::parameters::POLYNOMIAL_DEGREE;

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
    let mut transcript = FiatShamirTranscript::new("full-ring-low-degree-test");
    transcript.absorb(
        "low-degree-purpose",
        super::super::MAIN_LOW_DEGREE_TRANSCRIPT_PURPOSE,
    );

    prove_low_degree(&mut transcript, &parameters, &initial_layer)
        .expect("full-ring degree-below-bound polynomial must prove");
}
