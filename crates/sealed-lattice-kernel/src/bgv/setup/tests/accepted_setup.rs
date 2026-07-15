mod evaluation_key_share_proofs;
mod package_fixtures;
mod proof_record_fixtures;
mod public_key_share_proofs;
mod record_rebinding;
mod setup_intent;
mod terminal_evaluation_key_proofs;
mod vss_material;

use self::package_fixtures::{
    CollectiveSetupVerificationFixture, accepted_vss_coefficient_message_fixture,
    accepted_vss_randomness_fixture, accepted_vss_secret_coefficient_fixture,
    collective_public_key_bearing_collective_setup_fixture, collective_setup_intent_package,
    descriptor_backed_vss_collective_setup_fixture, minimal_collective_setup_package_fixture,
    minimal_collective_setup_package_for_participant_count,
    public_key_share_succinct_proof_bearing_collective_setup_fixture,
    ten_participant_descriptor_backed_vss_collective_setup_fixture,
};
use self::proof_record_fixtures::{
    CompactAggregateThresholdProofFixture, collective_public_key_object,
    compact_aggregate_threshold_proof_fixture, galois_key_share_batches_object,
    public_key_share_material_object, public_key_share_succinct_proofs_fixture,
    relinearization_key_share_rounds_fixture, replace_public_key_share_hashes_with_material_hashes,
    trustee_evaluation_key_proofs_object, vss_commitment_ring_degree_from_fixture_package,
};
use self::record_rebinding::{
    private_vss_envelope_commitment_set_root_input, rebind_collective_setup_intent_registration,
    rebind_collective_setup_intent_registration_with_signature_seed,
    rebind_collective_setup_intent_signatures,
};

use super::super::accepted_setup::{
    public_key_share_coefficient_vector_hash, verify_collective_bgv_setup_intent_for_test,
    verify_collective_bgv_setup_package,
};
use super::super::sampling::{dense_public_residues, negacyclic_product_mod};
use super::super::setup_proof::{
    authenticate_setup_proof_material_stream_for_test,
    authenticate_setup_proof_material_stream_in_session_for_test,
};
use super::super::trustee_evaluation_key_proof::{
    EvaluationKeyShareKind, TrusteeEvaluationKeyWitness, encode_trustee_evaluation_key_proof,
    prove_evaluation_key_share,
};
use super::*;
use crate::bgv::coefficient_codec::{coefficient_vector_from_le_hex, coefficient_vector_le_hex};
use crate::encoding::CanonicalErrorCode;
use crate::hashing::to_hex;
use crate::protocol_signatures::{
    create_ml_dsa_public_key_hash_fixture, create_protocol_signature_fixture,
};
use std::collections::BTreeMap;
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
// is for mutations reached during VSS verification; the collective-public-key
// helper carries every prerequisite needed to reach evaluator-key checks.
fn assert_minimal_collective_setup_package_refused(
    case_label: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_refusal_reason: &str,
) {
    let mut fixture = descriptor_backed_vss_collective_setup_fixture();
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

fn assert_collective_public_key_bearing_setup_package_refused(
    case_label: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_refusal_reason: &str,
) {
    let mut fixture = collective_public_key_bearing_collective_setup_fixture();
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

pub(super) fn final_package_phase(message: &str) {
    static FINAL_PACKAGE_PHASE_CLOCK: std::sync::OnceLock<std::time::Instant> =
        std::sync::OnceLock::new();
    let started = FINAL_PACKAGE_PHASE_CLOCK.get_or_init(std::time::Instant::now);
    println!(
        "accepted-setup-final-package-phase [+{}s] {message}",
        started.elapsed().as_secs()
    );
}
