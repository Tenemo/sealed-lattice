mod ceremony_phases;
mod evaluation_key_share_proofs;
mod material_transport_fixtures;
mod package_fixtures;
mod proof_record_fixtures;
mod public_key_share_proofs;
mod record_rebinding;
mod same_secret_proofs;
mod terminal_evaluation_key_proofs;
mod transport_policy;
mod vss_material;

use self::material_transport_fixtures::vss_material_binary_total_byte_length;
use self::package_fixtures::{
    accepted_vss_coefficient_message_fixture, accepted_vss_randomness_fixture,
    accepted_vss_secret_coefficient_fixture,
    collective_public_key_bearing_collective_setup_package, minimal_collective_setup_package,
    minimal_collective_setup_package_for_participant_count,
    public_key_share_succinct_proof_bearing_collective_setup_package,
};
use self::proof_record_fixtures::{
    collective_public_key_object, compactify_collective_setup_package,
    galois_key_share_batches_object, public_evaluation_key_set_object,
    public_key_share_material_object, public_key_share_succinct_proofs_object,
    relinearization_key_share_rounds_fixture, replace_public_key_share_hashes_with_material_hashes,
    same_secret_constant_commitments_from_fixture_package, trustee_evaluation_key_proofs_object,
};
use self::record_rebinding::{
    private_vss_envelope_commitment_record_root_input,
    private_vss_envelope_commitment_set_root_input, rebind_collective_evaluator_key_schedule_root,
    rebind_collective_phase_roots, rebind_collective_private_vss_envelope_commitment_root,
    rebind_collective_public_key_root, rebind_collective_public_key_share_proof_roots,
    rebind_collective_public_key_share_roots, rebind_collective_public_key_succinct_proof_roots,
    rebind_collective_same_secret_consistency_root, rebind_collective_same_secret_statement_roots,
    rebind_collective_setup_package_hash, rebind_collective_vss_acceptance_root,
    rebind_first_private_vss_encrypted_envelope_hash,
    rebind_first_private_vss_envelope_commitment_record_root,
};

use super::super::accepted_setup::{
    PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
    PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
    accepted_setup_collective_public_key_from_package, public_key_share_coefficient_vector_hash,
    verify_collective_bgv_setup_package, verify_full_ring_material,
    verify_terminal_setup_transport_policy,
};
use super::super::evaluation_key_share_material::EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING;
use super::super::sampling::{dense_public_residues, negacyclic_product_mod};
use super::super::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    setup_proof_material_transport_hashes,
};
use super::super::trustee_evaluation_key_proof::{
    EvaluationKeyShareKind, TrusteeEvaluationKeyWitness, encode_trustee_evaluation_key_proof,
    prove_evaluation_key_share,
};
use super::*;
use crate::bgv::coefficient_codec::{coefficient_vector_from_le_hex, coefficient_vector_le_hex};
use crate::encoding::{CanonicalErrorCode, append_varuint};
use crate::hashing::canonical_json;
use crate::hashing::{hash512_hex, to_hex};
use crate::protocol_signatures::{
    create_ml_dsa_public_key_hash_fixture, create_protocol_signature_fixture,
};
use crate::transcript_core::decode_hex;
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
                "\"durationMilliseconds\":{},",
                "\"durationMicroseconds\":{}}}"
            ),
            self.test_name,
            duration.as_millis(),
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

// Mirrors FIELD_RESIDUE_BYTE_WIDTH in the trustee proof codec: every data prime
// is below 2^48, so each committed base-field residue occupies six bytes. The
// fold-count offset self-check below guards against this drifting from the codec.
const PROOF_CODEC_FIELD_RESIDUE_BYTES: usize = 6;

fn set_first_masked_consistency_claim_to_noncanonical_modulus(proof_bytes: &mut [u8]) {
    // Header (magic plus limb count) and the two commitment roots precede the
    // first masked consistency claim, which is a six-byte base-field residue.
    const FIRST_MASKED_CONSISTENCY_CLAIM_OFFSET: usize = 8 + 8 + 64 + 64;
    let end = FIRST_MASKED_CONSISTENCY_CLAIM_OFFSET + PROOF_CODEC_FIELD_RESIDUE_BYTES;
    assert!(
        proof_bytes.len() >= end,
        "proof bytes must include the first masked consistency claim"
    );
    // Limb zero's claims live mod DATA_PRIMES[0]; writing that modulus as the
    // residue is noncanonical, since a residue must be strictly below it.
    proof_bytes[FIRST_MASKED_CONSISTENCY_CLAIM_OFFSET..end].copy_from_slice(
        &crate::bgv::parameters::DATA_PRIMES[0].to_le_bytes()[..PROOF_CODEC_FIELD_RESIDUE_BYTES],
    );
}

// Runs the collective BGV setup verifier over a setup package and returns the
// verification response. Wraps the request envelope and the infallible-response
// expectation that every accepted-setup rejection test repeats verbatim.
fn verify_collective_setup_package(package: &serde_json::Value) -> serde_json::Value {
    verify_collective_bgv_setup_package(package, &serde_json::json!({}))
        .expect("verification response")
}

// Asserts that the verifier refuses a setup package with the expected first
// refused-object reason code. The case label is carried into every assertion
// message so a table-driven caller still pinpoints which mutation failed, and
// the full response is printed on mismatch to keep failures diagnosable.
fn assert_collective_setup_package_refused(
    case_label: &str,
    package: serde_json::Value,
    expected_reason_code: &str,
) {
    let result = verify_collective_setup_package(&package);
    assert_eq!(
        result["isValid"], false,
        "{case_label}: unexpected verifier result: {result}"
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], expected_reason_code,
        "{case_label}: unexpected refusal reason code: {result}"
    );
}

// Like assert_collective_setup_package_refused, but also asserts that the
// refusal carries no accepted setup handoff. Used by the rejection cases that
// must additionally prove a refused package never produces a terminal handoff.
fn assert_collective_setup_package_refused_without_handoff(
    case_label: &str,
    package: serde_json::Value,
    expected_reason_code: &str,
) {
    let result = verify_collective_setup_package(&package);
    assert_eq!(
        result["isValid"], false,
        "{case_label}: unexpected verifier result: {result}"
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], expected_reason_code,
        "{case_label}: unexpected refusal reason code: {result}"
    );
    assert!(
        result["acceptedSetupHandoff"].is_null(),
        "{case_label}: refused package must not return an accepted setup handoff: {result}"
    );
}

// Builds the minimal collective setup package, applies a single labeled
// mutation (which performs any record-level rebinds it needs), rebinds the
// outer package hash, and asserts the verifier refuses with the expected reason
// code. This captures the "mutate one field, expect a specific refusal" shape
// shared by the fast accepted-setup rejection tests while keeping each case a
// distinct, individually labeled mutation closure.
fn assert_minimal_collective_setup_package_refused(
    case_label: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_reason_code: &str,
) {
    let mut package = minimal_collective_setup_package();
    mutate(&mut package);
    rebind_collective_setup_package_hash(&mut package);
    assert_collective_setup_package_refused(case_label, package, expected_reason_code);
}

// Like assert_minimal_collective_setup_package_refused, but also asserts the
// refusal carries no accepted setup handoff, for cases that must prove the
// terminal handoff stays withheld on rejection.
fn assert_minimal_collective_setup_package_refused_without_handoff(
    case_label: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
    expected_reason_code: &str,
) {
    let mut package = minimal_collective_setup_package();
    mutate(&mut package);
    rebind_collective_setup_package_hash(&mut package);
    assert_collective_setup_package_refused_without_handoff(
        case_label,
        package,
        expected_reason_code,
    );
}

// Shared elapsed-clock logger for final-package accepted-setup fixture phases.
pub(super) fn final_package_phase(message: &str) {
    static FINAL_PACKAGE_PHASE_CLOCK: std::sync::OnceLock<std::time::Instant> =
        std::sync::OnceLock::new();
    let started = FINAL_PACKAGE_PHASE_CLOCK.get_or_init(std::time::Instant::now);
    println!(
        "accepted-setup-final-package-phase [+{}s] {message}",
        started.elapsed().as_secs()
    );
}
