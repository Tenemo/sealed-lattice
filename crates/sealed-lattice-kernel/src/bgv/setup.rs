use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

mod certificates;
mod development_fixtures;
mod encrypted_aggregate_bridge_trace;
mod input;
mod key_material;
mod package_builder;
mod participant_material;
mod sampling;
mod validation;

#[cfg(test)]
mod tests;

use sampling::{
    dense_centered_binomial_coefficients, dense_public_residues, dense_small_coefficients,
    negacyclic_product_mod, sample_centered_binomial_eta2, sample_encryption_relation_checks,
    sample_positions, sample_public_residues, sample_signed_values, sample_small_distribution,
    sample_values, signed_to_modulus_residue, signed_to_plaintext_scaled_residue,
};

use crate::{
    bgv::{
        encoding::encode_batch_plaintext_slots,
        evaluator::engine::DevelopmentBgvKey,
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
        profile::{
            BACKEND_PROFILE_ID, BATCH_ENCODER_ID, BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS,
            POLYNOMIAL_DEGREE, PROFILE_ID, aggregate_input_encoding_profile_hash,
            allowed_operation_registry_hash, backend_profile_hash,
            ballot_score_encoding_profile_hash, ballot_share_layout_profile_hash,
            batch_encoder_hash, batch_layout_binding_hash, canonical_ciphertext_convention_hash,
            data_basis_modulus_bits, encoded_aggregate_layout_hash, extended_basis_modulus_bits,
            layout_hash, profile_hash, security_estimator_input_hash,
            top_k_evaluator_input_layout_hash,
        },
        rns::RnsPolynomial,
        serialization::{
            BgvObjectKind, canonical_bytes_hash, canonical_bytes_hex, ciphertext_root,
            parse_bgv_object_hex, plaintext_root, serialize_bgv_object,
        },
        setup_helpers::{
            array_at_path, bool_at_path, compare_derived_hash, compare_expected_string,
            compare_hash_at_path, compare_string_at_path, forbidden_setup_field_names,
            hash_at_path, integer_at_path, read_hash_field, read_non_empty_string,
            read_optional_u64, read_optional_usize, reject_forbidden_setup_fields,
            reject_forbidden_setup_package_secret_fields, string_at_path, unsigned_at_path,
            usize_at_path, value_at_path,
        },
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, chunk_root, derive_protocol_hash, hash512, hash512_hex},
};

pub(crate) const PASSIVE_SETUP_PROFILE_ID: &str =
    "sealed-lattice-bgv-rns-passive-full-roster-setup-v1";
pub(crate) const THRESHOLD_DECRYPTION_PROFILE_ID: &str = "BGV-RNS-KLLPS26-AsyncLagrangeTarget-v1";
pub(crate) const KEY_SWITCH_DECOMPOSITION_PROFILE_ID: &str =
    "sealed-lattice-bgv-rns-key-switch-decomposition-v1";
pub(crate) const SELECTED_ROT_SET_ID: &str = "generator-ordered-packed-rank-rot-set-v1";
const MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 50;
const MINIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 3;
const DEVELOPMENT_ENCRYPTION_FIXTURE_ID: &str =
    "sealed-lattice-passive-bgv-setup-development-encryption-fixture-v1";
const EVALUATION_KEY_STREAMING_COMMITMENT_ID: &str =
    "sealed-lattice-passive-bgv-setup-evaluation-key-streaming-commitment-v1";
const EVALUATION_KEY_CHUNK_SIZE_BYTES: usize = 262_144;
const DEVELOPMENT_MOBILE_STORAGE_QUOTA_BYTES: usize = 32 * 1024 * 1024;

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

pub(crate) struct PassiveSetupEvaluationKeySeeds {
    pub(crate) relinearization_key_seeds: BTreeMap<usize, String>,
    pub(crate) rotation_key_seeds: BTreeMap<(usize, usize), String>,
}

pub(crate) fn describe_passive_setup_object_model() -> CanonicalResult<Value> {
    Ok(json!({
        "objectModelId": "sealed-lattice-passive-bgv-setup-object-model-v1",
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
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
            "BgvEvaluationKeyStreamingCommitment",
            "BgvSetupParameterCertificate",
            "CollectiveSecretDistributionCertificate",
            "ErrorDistributionCertificate",
            "EvaluationKeySizeCertificate",
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
            "EvaluationKeySetDigest",
            "EvaluationKeySizeProfileHash",
            "CollectiveSecretDistributionCertificateHash",
            "ErrorDistributionCertificateHash",
            "BGVSetupParameterCertificateHash",
            "BGVDevelopmentEncryptionFixtureHash",
            "RotSetHash",
            "EncryptedAggregateBridgeHash",
            "EncryptedAggregateTargetBasisRoot",
            "EncryptedAggregateReconstructionHash",
            "ScoreBitDerivationCircuitHash",
            "ComparisonInputDerivationCircuitHash",
            "EncryptedScoreBitInputHash",
            "EncryptedComparisonInputHash",
            "BitSlicedComparatorHash",
            "EncryptedSparseTargetProjectionHash"
        ],
        "trustedDealerBoundary": {
            "transcriptValidCentralizedSecretReconstruction": false,
            "centralizedSecretFixtureMayProduceAcceptedRoots": false,
            "rawSecretSharesExported": false
        },
        "statusLabels": [
            "PassiveBgvSetupCanonicalObjectModelFrozen",
            "PassiveSetupOnly",
            "KllpsSetupMaterialMatchedOnly"
        ],
    }))
}

pub(crate) fn generate_passive_setup_package_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "ceremonyId",
            "manifestHash",
            "participants",
            "rosterHash",
            "setupSeed",
            "thresholdProfileHash",
        ],
        "generateBgvPassiveSetup",
    )?;
    reject_forbidden_setup_fields(request)?;
    let input = read_passive_setup_input(request)?;

    build_passive_setup_package(&input)
}

pub(crate) fn verify_passive_setup_package_from_request(request: &Value) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "expectedCollectivePublicKeyRoot",
            "expectedEvaluationKeyRoot",
            "expectedManifestHash",
            "expectedRosterHash",
            "expectedRotSetHash",
            "expectedSetupPackageHash",
            "setupPackage",
        ],
        "verifyBgvPassiveSetup",
    )?;
    reject_forbidden_setup_fields(request)?;
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
        "statusLabels": [
            "PassiveBgvSetupPackageVerified",
            "PassiveSetupDevelopmentFixtureOnly",
            "CollectivePublicKeyRootBound",
            "BgvPublicKeyCoefficientMaterialBound",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "PassiveSetupInputReady",
            "BgvAlgebraicPublicKeyProofMissing",
            "FinalSetupSecurityPendingTargetModulus"
        ],
    }))
}

pub(crate) fn development_evaluator_key_from_passive_setup_package(
    setup_package: &Value,
) -> CanonicalResult<DevelopmentBgvKey> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    let setup_seed_hash = string_at_path(setup_package, &["setupInputs", "setupSeedHash"])?;
    let participants = array_at_path(setup_package, &["participants"])?;
    let participant_identities = participants
        .iter()
        .map(|participant| {
            string_at_path(participant, &["trusteeIdentity"]).map(ToString::to_string)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let (collective_secret_coefficients, _) =
        key_material::collective_signed_secret_and_error_coefficients(
            setup_seed_hash,
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

pub(crate) fn evaluation_key_seeds_from_passive_setup_package(
    setup_package: &Value,
    working_level: usize,
) -> CanonicalResult<PassiveSetupEvaluationKeySeeds> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    let setup_seed_hash = string_at_path(setup_package, &["setupInputs", "setupSeedHash"])?;
    if working_level >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setup-bound evaluator working level is outside the selected data basis",
        ));
    }
    let relinearization_key_seeds = (1..=working_level)
        .map(|level| {
            (
                level,
                key_material::evaluation_key_stream_seed(
                    setup_seed_hash,
                    "relinearization",
                    level,
                    None,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut rotation_key_seeds = BTreeMap::new();
    let rotation_roots = array_at_path(
        setup_package,
        &[
            "evaluationKeys",
            "evaluationKeyMaterialCommitment",
            "rotationKeyRoots",
        ],
    )?;
    for rotation_root in rotation_roots {
        let rotation = usize_at_path(rotation_root, &["rotation"])?;
        let level = usize_at_path(rotation_root, &["level"])?;
        rotation_key_seeds.insert(
            (rotation, level),
            key_material::evaluation_key_stream_seed(
                setup_seed_hash,
                "rotation",
                level,
                Some(rotation),
            ),
        );
    }

    Ok(PassiveSetupEvaluationKeySeeds {
        relinearization_key_seeds,
        rotation_key_seeds,
    })
}

pub(crate) use encrypted_aggregate_bridge_trace::{
    EncryptedAggregateBridgeCiphertextRelationTrace,
    encrypted_aggregate_bridge_batch_encoding_commitment_hash_from_responses,
    encrypted_aggregate_bridge_ciphertext_commitment_hash_from_responses,
    generate_encrypted_aggregate_bridge_ciphertext_relation_trace_from_slots,
    verify_encrypted_aggregate_bridge_ciphertext_public_bindings,
};
use input::read_passive_setup_input;
use package_builder::build_passive_setup_package;
