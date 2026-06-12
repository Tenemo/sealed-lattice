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
    SetupTransportCertificateObjectFixture, StreamingVssMaterialFixtureWriter,
    TerminalEvaluationKeyTransportSinks, append_setup_transport_certificate_object,
    append_unreferenced_evaluation_key_component_transport_sidecar,
    append_unreferenced_same_secret_transport_sidecar, append_unrequested_setup_transport_object,
    append_vss_material_binary_header, append_vss_material_binary_record,
    encode_transport_material_from_package,
    move_evaluation_key_share_component_vectors_to_compact_transport,
    move_first_galois_key_share_component_vectors_to_transport,
    move_public_key_share_lnp_proof_bytes_to_transport,
    move_trustee_evaluation_key_proof_record_bytes_to_compact_transport,
    move_first_trustee_evaluation_key_proof_bytes_to_transport,
    move_public_key_share_material_to_transport, move_same_secret_proof_bytes_to_transport,
    proof_bytes_transport_chunks, rebind_public_evaluation_key_material_transport,
    rebind_setup_transport_certificate, setup_package_with_transported_public_setup_companions,
    stream_verified_vss_material_from_package, transported_material_reference_value,
    transported_material_value, vss_material_binary_total_byte_length,
};
use self::package_fixtures::{
    accepted_vss_coefficient_message_fixture, accepted_vss_randomness_fixture,
    accepted_vss_secret_coefficient_fixture,
    collective_public_key_bearing_collective_setup_package,
    evaluation_key_proof_container_bearing_collective_setup_package,
    evaluation_key_proof_container_bearing_collective_setup_package_ref,
    minimal_collective_setup_package, public_key_share_lnp_proof_bearing_collective_setup_package,
    same_secret_proof_bearing_collective_setup_package, setup_transport_certificate_fixture,
    setup_transport_certificate_for_transported_vss_material,
    setup_transport_chunk_manifest_root_fixture,
    terminal_profile_ring_minimal_collective_setup_package_fixture, vss_complaints_object,
};
use self::proof_record_fixtures::{
    EvaluationKeyShareFixtureMaterial, add_public_evaluation_key_material_transport,
    collective_public_key_object, evaluation_key_share_fixture_material, galois_key_share_batches_object,
    galois_key_share_batches_object_with_terminal_transport, public_evaluation_key_set_object,
    public_key_share_lnp_proofs_object, public_key_share_material_object,
    relinearization_key_share_rounds_object,
    relinearization_key_share_rounds_object_with_terminal_transport,
    relinearization_key_switch_seed_for_test,
    relinearization_round_two_source_by_digit_for_fixture,
    replace_public_key_share_hashes_with_material_hashes,
    round_one_aggregate_diagonals_from_fixture_package,
    same_secret_constant_commitments_from_fixture_package, same_secret_proofs_object,
    setup_proof_binding_for_test_package, trustee_evaluation_key_proofs_object,
    trustee_evaluation_key_proofs_object_with_terminal_transport,
    trustee_evaluation_key_witness_for_fixture,
};
use self::record_rebinding::{
    private_vss_envelope_commitment_record_root_input,
    private_vss_envelope_commitment_set_root_input, rebind_active_static_setup_theorem_certificate,
    rebind_collective_evaluator_key_schedule_root, rebind_collective_he_security_certificate_hash,
    rebind_collective_phase_roots, rebind_collective_private_vss_envelope_commitment_root,
    rebind_collective_public_key_lnp_proof_roots, rebind_collective_public_key_root,
    rebind_collective_public_key_share_proof_roots, rebind_collective_public_key_share_roots,
    rebind_collective_same_secret_consistency_root, rebind_collective_same_secret_proof_set_root,
    rebind_collective_same_secret_statement_roots, rebind_collective_setup_package_hash,
    rebind_collective_threshold_share_commitment_root, rebind_collective_vss_acceptance_root,
    rebind_collective_vss_coefficient_commitment_material_root,
    rebind_collective_vss_commitment_roots, rebind_collective_vss_complaint_root,
    rebind_first_private_vss_encrypted_envelope_hash, rebind_galois_key_share_batch_root,
    rebind_trustee_evaluation_key_proof_set_bindings,
    rebind_trustee_evaluation_key_proof_set_root,
    rebind_setup_key_correctness_certificate,
};

use super::super::accepted_setup::{
    EVALUATION_KEY_SHARE_RECORD_VERIFICATION_STATUS,
    PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE,
    PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
    PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING, PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT,
    PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING, PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE,
    TrusteeEvaluationKeyStatementInputs, accepted_hashes_from_package,
    accepted_he_security_certificate_hash, accepted_he_security_certificate_value,
    accepted_key_switch_decomposition_hash, accepted_setup_collective_public_key_from_package,
    accepted_setup_public_galois_keys_from_transport,
    accepted_setup_public_relinearization_keys_from_transport,
    active_static_setup_theorem_certificate_hash, active_static_setup_theorem_certificate_value,
    encode_public_evaluation_key_material_manifest, public_evaluation_key_material_manifest,
    public_evaluation_key_material_reference_root, public_evaluation_key_material_transport_hashes,
    public_key_share_material_transport_hashes,
    register_verified_trustee_evaluation_key_proof_material_chunks,
    round_one_public_aggregate_diagonals_from_package, setup_key_correctness_certificate_hash,
    setup_key_correctness_certificate_value, setup_proof_accounting_certificate_hash,
    setup_proof_accounting_certificate_value, trustee_evaluation_key_proof_material_root,
    trustee_evaluation_key_statement_from_package, verify_profile_ring_material,
    verify_terminal_setup_transport_policy,
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
use super::super::trustee_evaluation_key_proof::{
    EvaluationKeyShareKind, TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
    TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS, TRUSTEE_EVALUATION_KEY_PROOF_VERIFICATION_STATUS,
    TrusteeEvaluationKeyWitness, encode_trustee_evaluation_key_proof, prove_evaluation_key_share,
    succinct_evaluation_key_proof_accounting_hash, trustee_evaluation_key_proof_bytes_hash,
};
use super::super::public_key_share_proof::{
    PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS, PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
    PublicKeyShareLnpProofGenerationInput, PublicKeyShareLnpProofVerificationInput,
    PublicKeyShareLnpProofWitness, generate_public_key_share_lnp_relation_proof,
    public_key_share_coefficient_vector_hash, public_key_share_lnp_relation_proof_bytes_hash,
    verify_public_key_share_lnp_relation_proof,
};
use super::super::same_secret_proof::{
    SAME_SECRET_LNP_PROOF_MODEL_STATUS, SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
    SameSecretLnpProofWitness, generate_same_secret_lnp_relation_proof,
    same_secret_lnp_relation_proof_bytes_hash, verify_same_secret_lnp_relation_proof,
};
use super::super::sampling::{dense_public_residues, negacyclic_product_mod};
use super::super::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    SetupProofMaterialReferenceInput, setup_proof_material_reference_root,
    setup_proof_material_transport_hashes, setup_proof_record_binding_value,
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
