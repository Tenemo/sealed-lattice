use super::sharing::{
    RnsShamirShare, canonical_trustee_point, evaluate_shamir_polynomial,
    interpolate_shamir_constant_with_threshold,
};
use super::vss::{evaluate_unreduced_shamir_polynomial, verify_carry_aware_vss_share_opening};
use super::{
    DATA_PRIMES, describe_collective_bgv_setup_parameters,
    verify_local_trustee_setup_state_from_request, verify_private_vss_share_envelope_from_request,
};
use super::{
    commitment::{
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, compute_setup_commitment_for_tests,
        parse_setup_commitment_full_value, setup_commitment_full_value, setup_commitment_root,
    },
    private_vss_share_proof::{
        PrivateVssShareSuccinctProofGenerationInput, PrivateVssShareSuccinctProofVerificationInput,
        PrivateVssShareSuccinctProofWitness, private_vss_share_succinct_proof_record,
        verify_private_vss_share_succinct_relation_proof,
    },
    vss::{CarryAwareVssCommitmentOpeningInput, verify_carry_aware_vss_commitment_opening},
};
use crate::bgv::modular_arithmetic::{add_mod, mul_mod, sub_mod};
use crate::bgv::parameters::PLAINTEXT_MODULUS;
use crate::hashing::derive_canonical_object_hash;

mod accepted_setup;
mod local_trustee_state;
mod private_vss;
mod sharing_algebra;
mod vss_share_relation;

const TEST_SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND: i128 = 1;

fn valid_hash(fill: char) -> String {
    fill.to_string().repeat(128)
}

#[test]
fn setup_refusal_reason_maps_lower_camel_outside_codes_to_the_profile_boundary() {
    assert_eq!(
        super::setup_refusal_reason("outsideCollectiveBgvSetupParameters"),
        crate::foundation::RefusalReason::OutsideSupportedProfile,
    );
}
