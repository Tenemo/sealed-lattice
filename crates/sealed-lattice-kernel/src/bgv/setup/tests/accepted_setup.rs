mod ceremony_phases;
mod evaluation_key_share_proofs;
mod material_transport_fixtures;
mod package_fixtures;
mod proof_record_fixtures;
mod public_key_share_proofs;
mod record_rebinding;
mod same_secret_proofs;
mod setup_certificates;
mod transport_policy;
mod vss_material;

use self::material_transport_fixtures::{
    DIRECT_TRANSPORT_CERTIFICATE_FIELDS, SetupTransportCertificateObjectFixture,
    StreamingVssMaterialFixtureWriter, TerminalEvaluationKeyTransportSinks,
    TransportedPublicSetupCompanions, append_setup_transport_certificate_object,
    append_transport_certificate_entries_from_material_set,
    append_unreferenced_evaluation_key_component_transport_sidecar,
    append_unreferenced_same_secret_transport_sidecar, append_unrequested_setup_transport_object,
    append_vss_material_binary_header, append_vss_material_binary_record,
    encode_transport_material_from_package,
    move_evaluation_key_share_component_vectors_to_compact_transport,
    move_public_key_share_material_to_transport,
    move_public_key_share_succinct_proof_bytes_to_transport,
    move_same_secret_proof_bytes_to_transport,
    move_trustee_evaluation_key_proof_record_bytes_to_compact_transport,
    proof_bytes_transport_chunks, rebind_public_evaluation_key_material_transport,
    rebind_setup_transport_certificate,
    reduced_ring_setup_package_with_transported_public_setup_companions,
    setup_package_with_transported_public_setup_companions,
    stream_verified_vss_material_from_package, transported_material_reference_value,
    transported_material_value, vss_material_binary_total_byte_length,
};
use self::package_fixtures::{
    TerminalProfileRingSetupPackageFixture, accepted_vss_coefficient_message_fixture,
    accepted_vss_randomness_fixture, accepted_vss_secret_coefficient_fixture,
    collective_public_key_bearing_collective_setup_package, minimal_collective_setup_package,
    public_key_share_succinct_proof_bearing_collective_setup_package,
    reduced_ring_streamed_collective_setup_package_fixture,
    same_secret_proof_bearing_collective_setup_package, setup_transport_certificate_fixture,
    setup_transport_certificate_for_transported_vss_material,
    setup_transport_chunk_manifest_root_fixture,
    terminal_profile_ring_minimal_collective_setup_package_fixture, vss_complaints_object,
};
use self::proof_record_fixtures::{
    EvaluationKeyShareFixtureMaterial, RelinearizationKeyShareRoundsFixture,
    add_public_evaluation_key_material_transport, collective_public_key_object,
    evaluation_key_share_fixture_material, galois_key_share_batches_object_with_terminal_transport,
    public_evaluation_key_set_object, public_key_share_material_object,
    public_key_share_succinct_proofs_object,
    relinearization_key_share_rounds_fixture_with_terminal_transport,
    relinearization_key_switch_seed_for_test,
    relinearization_round_two_source_by_digit_for_fixture,
    replace_public_key_share_hashes_with_material_hashes,
    round_one_aggregate_diagonals_from_fixture_package,
    same_secret_constant_commitments_from_fixture_package, same_secret_proofs_object,
    trustee_evaluation_key_proofs_object_with_terminal_transport,
    trustee_evaluation_key_witness_for_fixture,
};
use self::record_rebinding::{
    drift_all_occurrences, drift_hash, private_vss_envelope_commitment_record_root_input,
    private_vss_envelope_commitment_set_root_input, rebind_active_static_setup_theorem_certificate,
    rebind_collective_evaluator_key_schedule_root, rebind_collective_he_security_certificate_hash,
    rebind_collective_phase_roots, rebind_collective_private_vss_envelope_commitment_root,
    rebind_collective_public_key_root, rebind_collective_public_key_share_proof_roots,
    rebind_collective_public_key_share_roots, rebind_collective_public_key_succinct_proof_roots,
    rebind_collective_same_secret_consistency_root, rebind_collective_same_secret_proof_roots,
    rebind_collective_same_secret_proof_set_root, rebind_collective_same_secret_statement_roots,
    rebind_collective_setup_package_hash, rebind_collective_threshold_share_commitment_root,
    rebind_collective_vss_acceptance_root,
    rebind_collective_vss_coefficient_commitment_material_root,
    rebind_collective_vss_commitment_roots, rebind_collective_vss_complaint_root,
    rebind_first_private_vss_encrypted_envelope_hash,
    rebind_first_private_vss_envelope_commitment_record_root, rebind_same_secret_proof_record_root,
    rebind_setup_key_correctness_certificate, rebind_setup_proof_accounting_certificate_hash,
    rebind_trustee_evaluation_key_proof_record_root, rebind_trustee_evaluation_key_proof_set_root,
};

use super::super::accepted_setup::{
    PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE,
    PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
    PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING, PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT,
    PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING, PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE,
    TrusteeEvaluationKeyStatementInputs, accepted_hashes_from_package,
    accepted_he_security_certificate_value, accepted_key_switch_decomposition_hash,
    accepted_setup_collective_public_key_from_package,
    accepted_setup_public_galois_keys_from_transport,
    accepted_setup_public_relinearization_keys_from_transport,
    active_static_setup_theorem_certificate_hash, active_static_setup_theorem_certificate_value,
    encode_public_evaluation_key_material_manifest, public_evaluation_key_material_manifest,
    public_evaluation_key_material_reference_root, public_evaluation_key_material_transport_hashes,
    public_key_share_coefficient_vector_hash, public_key_share_material_transport_hashes,
    public_key_share_succinct_proof_material_root,
    register_verified_trustee_evaluation_key_proof_material_chunks,
    round_one_public_aggregate_diagonals_from_package, same_secret_anchor_proof_material_root,
    setup_key_correctness_certificate_hash, setup_key_correctness_certificate_value,
    setup_proof_accounting_certificate_hash, setup_proof_accounting_certificate_value,
    stored_verified_trustee_evaluation_key_proof_material_chunks_for_test,
    trustee_evaluation_key_proof_material_root, trustee_evaluation_key_statement_from_package,
    verify_collective_bgv_setup_package, verify_profile_ring_material,
    verify_required_public_evaluation_key_set_for_test,
    verify_setup_key_correctness_certificate_for_test, verify_terminal_setup_transport_policy,
};
use super::super::evaluation_key_share_material::{
    EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE,
    EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
    EvaluationKeyShareProofFamily, KeySwitchComponentBFixtureInput,
    automorphism_i128_for_evaluation_key_fixture, encode_evaluation_key_share_component_vectors,
    evaluation_key_share_component_material_reference_root,
    evaluation_key_share_component_material_transport_hashes,
    evaluation_key_share_component_vector_hash, evaluation_key_share_component_vector_root,
    key_switch_component_b_for_evaluation_key_fixture,
    register_verified_evaluation_key_share_component_material_chunks,
};
use super::super::sampling::{dense_public_residues, negacyclic_product_mod};
use super::super::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    setup_proof_material_transport_hashes,
};
use super::super::trustee_evaluation_key_proof::{
    EvaluationKeyShareKind, FIELD_RESIDUE_BIT_WIDTH, TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
    TrusteeEvaluationKeyWitness, encode_trustee_evaluation_key_proof, prove_evaluation_key_share,
    public_key_share_succinct_proof_bytes_hash, succinct_evaluation_key_proof_accounting_hash,
    trustee_evaluation_key_proof_bytes_hash,
};
use super::*;
use crate::bgv::coefficient_codec::{coefficient_vector_from_le_hex, coefficient_vector_le_hex};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_varuint};
use crate::hashing::canonical_json;
use crate::hashing::{hash512_hex, to_hex};
use crate::protocol_signatures::{
    create_ml_dsa_public_key_hash_fixture, create_protocol_signature_fixture,
};
use crate::transcript_core::decode_hex;
use num_bigint::BigUint;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Instant;

const SETUP_TRANSPORT_CHUNK_SIZE_BYTES_FOR_TESTS: u64 = 1_048_576;

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

fn proof_codec_field_residue_slice_byte_count(residue_count: usize) -> usize {
    residue_count
        .checked_mul(FIELD_RESIDUE_BIT_WIDTH)
        .expect("field-residue bit count")
        .div_ceil(8)
}

fn set_first_masked_consistency_claim_to_noncanonical_modulus(proof_bytes: &mut [u8]) {
    // Header (magic plus limb count) and the two commitment roots precede the
    // first masked consistency claim, which starts a packed base-field slice.
    const FIRST_MASKED_CONSISTENCY_CLAIM_OFFSET: usize = 8 + 8 + 64 + 64;
    let first_residue_byte_count = proof_codec_field_residue_slice_byte_count(1);
    let end = FIRST_MASKED_CONSISTENCY_CLAIM_OFFSET + first_residue_byte_count;
    assert!(
        proof_bytes.len() >= end,
        "proof bytes must include the first masked consistency claim"
    );
    // Limb zero's claims live mod DATA_PRIMES[0]; writing that modulus as the
    // residue is noncanonical, since a residue must be strictly below it.
    proof_bytes[FIRST_MASKED_CONSISTENCY_CLAIM_OFFSET..end].copy_from_slice(
        &crate::bgv::profile::DATA_PRIMES[0].to_le_bytes()[..first_residue_byte_count],
    );
}

fn transported_public_setup_verification_request(
    companions: TransportedPublicSetupCompanions,
) -> serde_json::Value {
    serde_json::json!({
        "transportedVssCoefficientCommitmentMaterial": companions.vss_coefficient_commitment_material,
        "verifiedVssCoefficientCommitmentMaterial": companions.verified_vss_coefficient_commitment_material,
        "transportedSameSecretProofMaterial": companions.same_secret_proof_material,
        "transportedPublicKeyShareMaterial": companions.public_key_share_material,
        "transportedPublicKeyShareProofMaterial": companions.public_key_share_proof_material,
        "transportedEvaluationKeyShareComponentMaterial": companions.evaluation_key_share_component_material,
        "transportedEvaluationKeyShareProofMaterial": companions.evaluation_key_share_proof_material,
        "transportedPublicEvaluationKeyMaterial": companions.public_evaluation_key_material,
    })
}

fn transported_public_setup_package_and_request() -> (serde_json::Value, serde_json::Value) {
    let (package, companions) = setup_package_with_transported_public_setup_companions();
    (
        package,
        transported_public_setup_verification_request(companions),
    )
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
        result["verifierStatus"], "refused",
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
        result["verifierStatus"], "refused",
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

// Shared elapsed-clock logger for the terminal accepted-setup fixture phases.
pub(super) fn terminal_phase(message: &str) {
    static TERMINAL_PHASE_CLOCK: std::sync::OnceLock<std::time::Instant> =
        std::sync::OnceLock::new();
    let started = TERMINAL_PHASE_CLOCK.get_or_init(std::time::Instant::now);
    println!(
        "terminal-accepted-setup-phase [+{}s] {message}",
        started.elapsed().as_secs()
    );
}
