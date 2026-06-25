use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

mod accepted_setup;
mod certificates;
mod commitment;
mod compact_same_secret_bridge;
mod compact_vss_commitment;
mod development_fixtures;
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
pub(crate) use trustee_evaluation_key_proof::{
    generate_compact_same_secret_bridge_proof_from_request,
    generate_compact_vss_share_linkage_proof_from_request,
    generate_trustee_evaluation_key_proof_from_request,
    verify_compact_same_secret_bridge_proof_from_request,
    verify_compact_vss_share_linkage_proof_from_request,
    verify_trustee_evaluation_key_proof_from_request,
};
mod validation;
mod vss;

#[cfg(test)]
mod tests;

pub(crate) use accepted_setup::{
    COLLECTIVE_BGV_SETUP_PROFILE_ID, derive_collective_bgv_setup_public_derivations_from_request,
    describe_collective_bgv_setup_profile, verify_collective_bgv_setup_package_from_request,
};
pub(crate) use commitment::compute_setup_commitment_from_opening_request;
pub(crate) use compact_same_secret_bridge::{
    verify_compact_vss_same_secret_bridge_proof_material_set_request,
    verify_compact_vss_same_secret_bridge_statement_set_request,
};
pub(crate) use compact_vss_commitment::{
    CompactVssCommitmentOpeningInput, compute_compact_vss_commitment_from_opening,
    compute_compact_vss_commitment_from_opening_request,
    decode_compact_vss_commitment_body_request, encode_compact_vss_commitment_body_request,
    read_compact_vss_randomness_by_column,
    verify_compact_vss_aggregate_threshold_commitment_set_request,
    verify_compact_vss_coefficient_commitment_set_request,
    verify_compact_vss_commitment_opening_request,
    verify_compact_vss_recipient_share_commitment_set_request,
    verify_compact_vss_share_linkage_proof_material_set_request,
    verify_compact_vss_share_linkage_statement_request,
};
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
    abort_threshold_share_commitment_transport_derivation_stream_request,
    absorb_threshold_share_commitment_transport_derivation_stream_chunk_request,
    begin_threshold_share_commitment_transport_derivation_stream_request,
    derive_threshold_share_commitments_from_request,
    derive_threshold_share_commitments_from_transport_request,
    finish_threshold_share_commitment_transport_derivation_stream_request,
    release_verified_transported_vss_material_request,
};

use sampling::{
    dense_centered_binomial_coefficients, dense_public_residues, dense_small_coefficients,
    negacyclic_product_mod, sample_bounded_collective_error_share_distribution,
    sample_bounded_collective_secret_share_distribution, sample_positions, sample_public_residues,
    sample_signed_values, sample_values, signed_to_modulus_residue,
    signed_to_plaintext_scaled_residue,
};

use crate::bgv::evaluator::key_switch::key_switch_key_from_public_component_b;
use crate::{
    bgv::{
        coefficient_codec::{
            coefficient_vector_from_le_hex, coefficient_vector_hash512, coefficient_vector_le_hex,
        },
        encoding::encode_batch_plaintext_slots,
        evaluator::{
            engine::{BgvPublicKey, DevelopmentBgvKey},
            key_switch::{KeySwitchKey, generate_galois_key, generate_relinearization_key},
            records::MAXIMUM_OPTION_COUNT,
        },
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        ntt::{forward_negacyclic_ntt_in_place, inverse_negacyclic_ntt_in_place},
        profile::{
            BACKEND_PROFILE_ID, BATCH_ENCODER_ID, BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS,
            POLYNOMIAL_DEGREE, PROFILE_ID, allowed_operation_registry_hash, backend_profile_hash,
            ballot_score_encoding_profile_hash, batch_encoder_hash, batch_layout_binding_hash,
            canonical_ciphertext_convention_hash, data_basis_modulus_bits,
            direct_aggregate_layout_hash, direct_comparison_profile_hash,
            encrypted_ballot_aggregate_layout_hash, encrypted_ballot_aggregate_profile_hash,
            encrypted_ballot_layout_hash, extended_basis_modulus_bits, profile_hash,
            security_estimator_input_hash,
        },
        rns::RnsPolynomial,
        serialization::{
            BgvObjectKind, canonical_bytes_hash, ciphertext_root, plaintext_root,
            serialize_bgv_object,
        },
        setup_helpers::{
            array_at_path, compare_derived_hash, compare_expected_string, compare_hash_at_path,
            compare_required_string, compare_string_at_path, hash_at_path, integer_at_path,
            read_hash_field, read_non_empty_string, read_optional_u64, read_optional_usize,
            string_at_path, unsigned_at_path, usize_at_path, validate_hash_string, value_at_path,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, chunk_root, derive_protocol_hash, hash512, hash512_hex},
};

pub(crate) const PASSIVE_SETUP_PROFILE_ID: &str =
    "sealed-lattice-bgv-rns-passive-full-roster-setup-v1";
pub(crate) const TARGET_DECRYPTION_PROFILE_ID: &str = "BGV-RNS-AsyncTargetDecryption-v1";
pub(crate) const KEY_SWITCH_DECOMPOSITION_PROFILE_ID: &str =
    "sealed-lattice-bgv-rns-key-switch-decomposition-v1";
pub(crate) const SELECTED_ROT_SET_ID: &str = "compact-generator-basis-packed-rank-rot-set-v1";
const MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 50;
const MINIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 3;
const DEVELOPMENT_ENCRYPTION_FIXTURE_ID: &str =
    "sealed-lattice-passive-bgv-setup-development-encryption-fixture-v1";
const EVALUATION_KEY_STREAMING_COMMITMENT_ID: &str =
    "sealed-lattice-passive-bgv-setup-evaluation-key-streaming-commitment-v1";
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
    threshold_profile_hash: String,
    setup_seed_provided: bool,
    setup_seed_hash: String,
    private_setup_seed_hash: String,
    participants: Vec<SetupParticipant>,
}

pub(crate) struct CollectiveBgvSetupContextHashes {
    pub(crate) roster_hash: String,
    pub(crate) setup_profile_hash: String,
    pub(crate) q_share_hash: String,
    pub(crate) carry_aware_vss_share_relation_profile_hash: String,
    pub(crate) commitment_profile_hash: String,
}

pub(crate) fn collective_bgv_setup_context_hashes_from_package(
    setup_package: &Value,
) -> CanonicalResult<CollectiveBgvSetupContextHashes> {
    let roster_hash = if let Some(setup_context) = setup_package.get("setupContext") {
        hash_at_path(setup_context, &["rosterHash"])?.to_string()
    } else {
        hash_at_path(setup_package, &["setupInputs", "rosterHash"])?.to_string()
    };
    let roster = accepted_setup::accepted_roster_from_package(setup_package);

    Ok(CollectiveBgvSetupContextHashes {
        roster_hash,
        setup_profile_hash: accepted_setup::setup_profile_hash_for_roster(&roster)?,
        q_share_hash: accepted_setup::accepted_q_share_hash()?,
        carry_aware_vss_share_relation_profile_hash:
            vss::carry_aware_vss_share_relation_profile_hash()?,
        commitment_profile_hash: commitment::setup_commitment_profile_hash()?,
    })
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

pub(crate) fn describe_passive_setup_object_model() -> CanonicalResult<Value> {
    Ok(json!({
        "objectModelId": "sealed-lattice-passive-bgv-setup-object-model-v1",
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "keySwitchDecompositionProfileId": KEY_SWITCH_DECOMPOSITION_PROFILE_ID,
        "selectedRotSetId": SELECTED_ROT_SET_ID,
        "canonicalObjects": [
            "BgvPassiveSetupPackage",
            "ParticipantBgvSetupRecord",
            "BgvPublicKeyShare",
            "BgvCollectivePublicKey",
            "BgvCollectivePublicKeyCoefficientMaterial",
            "ThresholdShareVerificationKeySet",
            "TrusteeThresholdVerificationKey",
            "BgvRelinearizationKey",
            "BgvRotationKey",
            "BgvKeySwitchKey",
            "BgvEvaluationKeySet",
            "BgvEvaluationKeyMaterialCommitment",
            "BgvPublicEvaluationKeyMaterial",
            "BgvEvaluationKeyStreamingCommitment",
            "BgvSetupParameterCertificate",
            "CollectiveSecretDistributionCertificate",
            "ErrorDistributionCertificate",
            "EvaluationKeySizeCertificate",
            "BgvPassiveSetupCommonRandomness",
            "BgvDevelopmentEncryptionFixture"
        ],
        "reservedRootsAndHashes": [
            "BGVPassiveSetupPackageHash",
            "ParticipantBgvSetupRecordHash",
            "PublicKeyShareRoot",
            "BGVPublicCommonRandomPolynomialRoot",
            "BGVPublicKeyRoot",
            "CollectivePublicKeyRoot",
            "ThresholdShareVerificationKeyRoot",
            "ThresholdShareVerificationKeyHash",
            "TrusteeThresholdVerificationKeyHash",
            "RelinearizationKeyRoot",
            "RotationKeyRoot",
            "KeySwitchKeyRoot",
            "KeySwitchDecompositionHash",
            "EvalKeyRoot",
            "EvaluationKeySetHash",
            "EvaluationKeySizeProfileHash",
            "CollectiveSecretDistributionCertificateHash",
            "ErrorDistributionCertificateHash",
            "BGVHeSecurityCertificateHash",
            "BGVSetupParameterCertificateHash",
            "SetupProofRecordBindingHash",
            "SetupProofAccountingCertificateHash",
            "SetupKeyCorrectnessCertificateHash",
            "BGVDevelopmentEncryptionFixtureHash",
            "RotSetHash",
            "ComparisonInputDerivationCircuitHash",
            "EncryptedComparisonInputHash",
            "EncryptedSparseTargetProjectionHash",
            "SetupPublicMatrixSeedHash",
            "SetupCommonRandomnessRoot"
        ],
    }))
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
    let expected_hash = derive_protocol_hash("BGVPassiveSetupPackageHash", &hash_input)?;
    if setup_package_hash != expected_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
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
        "ok": true,
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
        "refusedObjects": [],
        "unresolvedReason": null,
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
