mod package_fixtures;
mod proof_record_fixtures;
mod record_rebinding;
mod setup_intent;
mod vss_material;

use self::package_fixtures::{
    CollectiveSetupVerificationFixture, accepted_vss_coefficient_message_fixture,
    accepted_vss_randomness_fixture, accepted_vss_secret_coefficient_fixture,
    collective_setup_intent_package, minimal_collective_setup_package_fixture,
    structural_vss_collective_setup_fixture,
    ten_participant_structural_vss_collective_setup_fixture,
};
use self::record_rebinding::{
    private_vss_envelope_commitment_set_root_input, rebind_collective_setup_intent_registration,
    rebind_collective_setup_intent_registration_with_signature_seed,
    rebind_collective_setup_intent_signatures,
};

use super::super::accepted_setup::{
    verify_collective_bgv_setup_intent_for_test, verify_collective_bgv_setup_package,
};
use super::super::decryption_threshold_for_participant_count;
use super::super::sampling::negacyclic_product_mod;
use super::super::setup_proof::authenticate_setup_proof_material_stream_for_test;
use super::*;
use crate::bgv::coefficient_codec::coefficient_vector_le_hex;
use crate::encoding::CanonicalErrorCode;
use crate::protocol_signatures::{
    create_ml_dsa_public_key_hash_fixture, create_protocol_signature_fixture,
};
use std::sync::OnceLock;
use std::time::Instant;

struct AcceptedSetupTestTiming {
    started_at: Instant,
    test_name: &'static str,
}

impl Drop for AcceptedSetupTestTiming {
    fn drop(&mut self) {
        let duration = self.started_at.elapsed();
        println!(
            concat!(
                "sealed-lattice-rust-test-timing ",
                "{{\"suite\":\"bgv::setup::tests::accepted_setup\",",
                "\"test\":\"{}\",",
                "\"durationMicroseconds\":{}}}"
            ),
            self.test_name,
            duration.as_micros()
        );
    }
}

fn accepted_setup_test_timing(test_name: &'static str) -> AcceptedSetupTestTiming {
    AcceptedSetupTestTiming {
        started_at: Instant::now(),
        test_name,
    }
}

// Runs the collective BGV setup verifier over a setup package and its
// authenticated material references. Wraps the infallible-response expectation
// that every accepted-setup rejection test repeats verbatim. The minimal helper
// is for mutations reached during VSS verification.
fn assert_minimal_collective_setup_package_refused(
    case_label: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_refusal_reason: &str,
) {
    let mut fixture = structural_vss_collective_setup_fixture();
    mutate(&mut fixture.package);
    let result = fixture.verify().expect("verification response");
    assert_eq!(
        result["isValid"], false,
        "{case_label}: unexpected verifier result: {result}"
    );
    assert_eq!(
        result["refusalReason"], expected_refusal_reason,
        "{case_label}: unexpected refusal reason: {result}"
    );
}
