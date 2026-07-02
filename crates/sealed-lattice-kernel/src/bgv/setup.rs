use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

mod accepted_setup;
mod certificates;
mod commitment;
// Development gate for the mobile trustee evaluation-key proving path;
// exercised only by its tests and ignored benchmark until the consolidated
// backend consumes it.
#[cfg(test)]
mod consolidated_key_switch_atom;
mod evaluation_key_share_material;
mod input;
mod key_material;
mod local_trustee_state;
mod package_builder;
mod participant_material;
mod private_vss;
mod private_vss_share_proof;
mod public_evaluation_key_material;
mod sampling;
mod setup_proof;
mod sharing;
mod threshold_share_commitments;
mod trustee_evaluation_key_proof;
pub(crate) use trustee_evaluation_key_proof::generate_trustee_evaluation_key_proof_from_request;
mod validation;
mod vss;

pub(super) const SETUP_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;

#[cfg(test)]
mod tests;

pub(crate) use accepted_setup::{
    derive_collective_bgv_setup_public_derivations_from_request,
    describe_collective_bgv_setup_parameters, verify_collective_bgv_setup_package_from_request,
};
pub(crate) use commitment::compute_setup_commitment_from_opening_request;
pub(crate) use local_trustee_state::verify_local_trustee_setup_state_from_request;
pub(crate) use private_vss::{
    generate_private_vss_share_proof_from_request, verify_private_vss_share_envelope_from_request,
};
pub(crate) use public_evaluation_key_material::{
    generate_passive_setup_public_evaluation_key_material_from_request,
    public_evaluation_keys_from_material,
};
#[cfg(test)]
use public_evaluation_key_material::{
    read_public_evaluation_key_rotation_requests, selected_public_evaluation_key_rotation_requests,
};
pub(crate) use setup_proof::{
    absorb_setup_proof_material_transport_stream_chunk_request,
    begin_setup_proof_material_transport_stream_request,
    finish_setup_proof_material_transport_stream_request,
};
pub(crate) use threshold_share_commitments::{
    absorb_threshold_share_commitment_transport_derivation_stream_chunk_request,
    begin_threshold_share_commitment_transport_derivation_stream_request,
    derive_threshold_share_commitments_from_request,
    finish_threshold_share_commitment_transport_derivation_stream_request,
};

#[cfg(test)]
pub(in crate::bgv::setup) const TEST_CHECKPOINT_ROOT_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_TEST_CHECKPOINT_ROOT";

#[cfg(test)]
pub(in crate::bgv::setup) fn accepted_setup_test_checkpoint_root_directory() -> std::path::PathBuf {
    std::env::var_os(TEST_CHECKPOINT_ROOT_ENVIRONMENT_VARIABLE)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("temp").join("test-checkpoints"))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn accepted_setup_final_package_material_store_checkpoint_directory()
-> std::path::PathBuf {
    accepted_setup_test_checkpoint_root_directory()
        .join("accepted-setup-final-package-material-store")
}

use sampling::{
    dense_public_residues, negacyclic_product_mod,
    sample_bounded_collective_error_share_distribution,
    sample_bounded_collective_secret_share_distribution, sample_positions, sample_public_residues,
    signed_to_modulus_residue, signed_to_plaintext_scaled_residue,
};

use crate::bgv::evaluator::key_switch::key_switch_key_from_public_component_b;
use crate::{
    bgv::{
        coefficient_codec::{
            coefficient_vector_from_le_hex, coefficient_vector_hash512, coefficient_vector_le_hex,
        },
        evaluator::{
            engine::{BgvPublicKey, DevelopmentBgvKey},
            key_switch::{KeySwitchKey, generate_galois_key, generate_relinearization_key},
            records::MAXIMUM_OPTION_COUNT,
        },
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        ntt::{forward_negacyclic_ntt_in_place, inverse_negacyclic_ntt_in_place},
        parameters::{
            BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, bgv_parameters_hash,
            data_basis_modulus_bits, extended_basis_modulus_bits,
        },
        setup_helpers::{
            array_at_path, compare_derived_hash, compare_expected_string, compare_hash_at_path,
            compare_string_at_path, hash_at_path, integer_at_path, read_hash_field,
            read_non_empty_string, read_optional_u64, read_optional_usize, string_at_path,
            unsigned_at_path, usize_at_path, validate_hash_string, value_at_path,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, chunk_root, derive_canonical_object_hash, hash512, hash512_hex},
};

const MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 50;
const MINIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 3;
const EVALUATION_KEY_CHUNK_SIZE_BYTES: usize = 262_144;

#[derive(Clone)]
struct SetupParticipant {
    trustee_identity: String,
    roster_position: usize,
    board_position: usize,
    recovery_epoch: u64,
    device_epoch: u64,
}

#[derive(Clone)]
struct PassiveSetupInput {
    ceremony_id: String,
    manifest_hash: String,
    roster_hash: String,
    threshold_parameters_hash: String,
    setup_seed_provided: bool,
    setup_seed_hash: String,
    private_setup_seed_hash: String,
    participants: Vec<SetupParticipant>,
}

struct ParticipantSetupMaterial {
    participant_record: Value,
    public_key_share_root: String,
    participant_setup_record_hash: String,
    trustee_threshold_verification_key_hash: String,
}

struct VerifiedParticipantSetupBinding {
    trustee_identity: String,
    roster_position: usize,
    recovery_epoch: u64,
    device_epoch: u64,
    public_key_share_root: String,
    participant_setup_record_hash: String,
    trustee_threshold_verification_key_hash: String,
}

pub(crate) fn generate_passive_setup_package_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let input = read_passive_setup_input(request)?;

    build_passive_setup_package(&input)
}

pub(crate) fn verify_passive_setup_package_from_request(request: &Value) -> CanonicalResult<Value> {
    let setup_package = request.get("setupPackage").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is required",
        )
    })?;
    let setup_package_hash = setup_package
        .get("setupPackageHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupPackageHash must be present",
            )
        })?;
    let mut hash_input = setup_package.clone();
    let hash_object = hash_input.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage must be an object",
        )
    })?;
    hash_object.remove("setupPackageHash");
    let expected_hash = derive_canonical_object_hash(&hash_input)?;
    if setup_package_hash != expected_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "BGV passive setup package hash does not match its canonical payload",
        ));
    }

    compare_expected_string(
        request,
        "expectedSetupPackageHash",
        setup_package_hash,
        "setup package hash",
    )?;
    compare_expected_string(
        request,
        "expectedManifestHash",
        string_at_path(setup_package, &["setupInputs", "manifestHash"])?,
        "manifest hash",
    )?;
    compare_expected_string(
        request,
        "expectedRosterHash",
        string_at_path(setup_package, &["setupInputs", "rosterHash"])?,
        "roster hash",
    )?;
    compare_expected_string(
        request,
        "expectedCollectivePublicKeyRoot",
        string_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?,
        "collective public key root",
    )?;
    compare_expected_string(
        request,
        "expectedRotSetHash",
        string_at_path(setup_package, &["evaluationKeys", "rotSetHash"])?,
        "rotation set hash",
    )?;
    compare_expected_string(
        request,
        "expectedEvaluationKeyRoot",
        string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
        "evaluation key root",
    )?;

    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;

    Ok(json!({
        "operation": "verifyBgvPassiveSetupPackage",
        "acceptedHashes": [
            setup_package_hash,
            string_at_path(setup_package, &["collectivePublicKey", "collectivePublicKeyRoot"])?,
            string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
            string_at_path(setup_package, &["thresholdVerificationMaterial", "thresholdShareVerificationKeyRoot"])?,
            string_at_path(setup_package, &["thresholdVerificationMaterial", "thresholdShareVerificationKeyHash"])?,
            string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
            string_at_path(setup_package, &["evaluationKeys", "rotSetHash"])?,
        ],
    }))
}

pub(crate) fn validate_passive_setup_package_for_encrypted_evaluation(
    setup_package: &Value,
) -> CanonicalResult<()> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)
}

pub(crate) fn validate_private_setup_seed_from_passive_setup_package(
    setup_package: &Value,
    private_setup_seed: &str,
) -> CanonicalResult<()> {
    input::private_passive_setup_seed_hash_from_package_witness(setup_package, private_setup_seed)?;
    Ok(())
}

pub(crate) fn development_evaluator_key_from_passive_setup_package(
    setup_package: &Value,
    private_setup_seed: &str,
) -> CanonicalResult<DevelopmentBgvKey> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    let private_setup_seed_hash = input::private_passive_setup_seed_hash_from_package_witness(
        setup_package,
        private_setup_seed,
    )?;
    let participants = array_at_path(setup_package, &["participants"])?;
    let participant_identities = participants
        .iter()
        .map(|participant| {
            string_at_path(participant, &["trusteeIdentity"]).map(ToString::to_string)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let (collective_secret_coefficients, _) =
        key_material::collective_signed_secret_and_error_coefficients(
            &private_setup_seed_hash,
            &participant_identities,
        );
    let collective_public_key_coefficients =
        key_material::collective_public_key_coefficients_by_modulus_from_setup_package(
            setup_package,
        )?;
    let public_b = collective_public_key_coefficients
        .iter()
        .map(|coefficients| coefficients.component_zero_coefficients.clone())
        .collect::<Vec<_>>();
    let public_a = collective_public_key_coefficients
        .iter()
        .map(|coefficients| coefficients.component_one_coefficients.clone())
        .collect::<Vec<_>>();

    DevelopmentBgvKey::from_collective_components(
        collective_secret_coefficients,
        public_b,
        public_a,
    )
}

use input::read_passive_setup_input;
use package_builder::build_passive_setup_package;
