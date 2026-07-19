use super::sharing::{
    RnsShamirShare, canonical_trustee_point, evaluate_shamir_polynomial,
    interpolate_shamir_constant_with_threshold,
};
use super::vss::{evaluate_unreduced_shamir_polynomial, verify_carry_aware_vss_share_opening};
use super::{
    commitment::{SETUP_COMMITMENT_RANDOMNESS_WIDTH, compute_setup_commitment_for_degree},
    vss::{CarryAwareVssCommitmentOpeningInput, verify_carry_aware_vss_commitment_opening},
};
use crate::bgv::parameters::DATA_PRIMES;

mod sharing_algebra;
mod vss_share_relation;

const TEST_SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND: i128 = 2;

fn valid_hash(fill: char) -> String {
    fill.to_string().repeat(128)
}
