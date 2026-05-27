use std::collections::BTreeSet;

use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

mod certificates;
mod development_fixtures;
mod input;
mod key_material;
mod m9_bridge_trace;
mod package_builder;
mod participant_material;
mod sampling;
mod validation;

#[cfg(test)]
mod tests;

use sampling::{
    dense_centered_binomial_coefficients, dense_public_residues, dense_small_coefficients,
    development_fixture_digest, negacyclic_product_mod, sample_centered_binomial_eta2,
    sample_encryption_relation_checks, sample_positions, sample_public_residues, sample_residue,
    sample_signed_values, sample_small_distribution, sample_values, signed_to_modulus_residue,
};

use crate::{
    bgv::{
        encoding::encode_batch_plaintext_slots,
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
        profile::{
            BACKEND_PROFILE_ID, BATCH_ENCODER_ID, BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS,
            POLYNOMIAL_DEGREE, PROFILE_ID, aggregate_input_encoding_profile_digest,
            allowed_operation_registry_digest, backend_profile_digest,
            ballot_score_encoding_profile_digest, ballot_share_layout_profile_digest,
            batch_encoder_digest, batch_layout_binding_digest,
            canonical_ciphertext_convention_digest, data_basis_modulus_bits,
            encoded_aggregate_layout_digest, extended_basis_modulus_bits, layout_digest,
            profile_digest, security_estimator_input_digest, top_k_evaluator_input_layout_digest,
        },
        rns::RnsPolynomial,
        serialization::{
            BgvObjectKind, canonical_bytes_hash, canonical_bytes_hex, ciphertext_root,
            parse_bgv_object_hex, plaintext_root, serialize_bgv_object,
        },
        setup_helpers::{
            array_at_path, bool_at_path, compare_derived_digest, compare_digest_at_path,
            compare_expected_string, compare_string_at_path, digest_at_path,
            forbidden_setup_field_names, integer_at_path, read_digest_field, read_non_empty_string,
            read_optional_u64, read_optional_usize, reject_forbidden_setup_fields,
            reject_forbidden_setup_package_secret_fields, string_at_path, unsigned_at_path,
            usize_at_path, value_at_path,
        },
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, chunk_root, derive_protocol_digest, hash512, hash512_hex},
};

pub(crate) const PASSIVE_SETUP_PROFILE_ID: &str =
    "sealed-lattice-bgv-rns-passive-full-roster-setup-v1";
pub(crate) const THRESHOLD_DECRYPTION_PROFILE_ID: &str = "BGV-RNS-KLLPS26-AsyncLagrangeTarget-v1";
pub(crate) const KEY_SWITCH_DECOMPOSITION_PROFILE_ID: &str =
    "sealed-lattice-bgv-rns-key-switch-decomposition-v1";
pub(crate) const PROVISIONAL_ROT_SET_ID: &str =
    "sealed-lattice-provisional-m10-top-k-rotation-set-v1";
const MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 50;
const MINIMUM_PASSIVE_SETUP_ROSTER_SIZE: usize = 3;
const DEVELOPMENT_ENCRYPTION_FIXTURE_ID: &str =
    "sealed-lattice-m8-development-encryption-fixture-v1";
const DEVELOPMENT_RELINEARIZATION_ARITHMETIC_FIXTURE_ID: &str =
    "sealed-lattice-m8-development-relinearization-arithmetic-fixture-v1";
const DEVELOPMENT_KEY_SWITCH_ARITHMETIC_FIXTURE_ID: &str =
    "sealed-lattice-m8-development-key-switch-arithmetic-fixture-v1";
const EVALUATION_KEY_STREAMING_FIXTURE_ID: &str =
    "sealed-lattice-m8-evaluation-key-streaming-fixture-v1";
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
    manifest_digest: String,
    roster_digest: String,
    threshold_profile_digest: String,
    setup_seed_provided: bool,
    setup_seed_digest: String,
    participants: Vec<SetupParticipant>,
}

struct ParticipantSetupMaterial {
    participant_record: Value,
    public_key_share_root: String,
    participant_setup_record_digest: String,
    trustee_threshold_verification_key_digest: String,
}

struct VerifiedParticipantSetupBinding {
    trustee_identity: String,
    roster_position: usize,
    recovery_epoch: u64,
    device_epoch: u64,
    public_key_share_root: String,
    participant_setup_record_digest: String,
    trustee_threshold_verification_key_digest: String,
}

pub(crate) fn describe_passive_setup_object_model() -> CanonicalResult<Value> {
    Ok(json!({
        "objectModelId": "sealed-lattice-m8-passive-setup-object-model-v1",
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "keySwitchDecompositionProfileId": KEY_SWITCH_DECOMPOSITION_PROFILE_ID,
        "provisionalRotSetId": PROVISIONAL_ROT_SET_ID,
        "canonicalObjects": [
            "BgvPassiveSetupPackage",
            "ParticipantBgvSetupRecord",
            "BgvPublicKeyShare",
            "BgvCollectivePublicKey",
            "ThresholdShareVerificationKeySet",
            "TrusteeThresholdVerificationKey",
            "BgvRelinearizationKey",
            "BgvRotationKey",
            "BgvKeySwitchKey",
            "BgvEvaluationKeySet",
            "BgvSetupParameterCertificate",
            "CollectiveSecretDistributionCertificate",
            "ErrorDistributionCertificate",
            "EvaluationKeySizeCertificate",
            "BgvDevelopmentEncryptionFixture"
        ],
        "reservedRootsAndDigests": [
            "BGVPassiveSetupPackageDigest",
            "ParticipantBgvSetupRecordDigest",
            "PublicKeyShareRoot",
            "BGVPublicCommonRandomPolynomialRoot",
            "BGVPublicKeyRoot",
            "CollectivePublicKeyRoot",
            "ThresholdShareVerificationKeyRoot",
            "ThresholdShareVerificationKeyDigest",
            "TrusteeThresholdVerificationKeyDigest",
            "RelinearizationKeyRoot",
            "RotationKeyRoot",
            "KeySwitchKeyRoot",
            "KeySwitchDecompositionDigest",
            "EvalKeyRoot",
            "EvaluationKeySizeProfileDigest",
            "CollectiveSecretDistributionCertificateDigest",
            "ErrorDistributionCertificateDigest",
            "BGVSetupParameterCertificateDigest",
            "BGVDevelopmentEncryptionFixtureDigest",
            "RotSetDigest",
            "EncryptedAggregateBridgeDigest",
            "EncryptedAggregateTargetBasisDataRoot",
            "EncryptedAggregateReconstructionDigest",
            "ScoreBitDerivationCircuitDigest",
            "ComparisonInputDerivationCircuitDigest",
            "EncryptedScoreBitInputDigest",
            "EncryptedComparisonInputDigest",
            "BitSlicedComparatorDigest",
            "EncryptedSparseTargetProjectionDigest"
        ],
        "trustedDealerBoundary": {
            "transcriptValidCentralizedSecretReconstruction": false,
            "centralizedSecretFixtureMayProduceAcceptedRoots": false,
            "rawSecretSharesExported": false
        },
        "statusLabels": [
            "M8CanonicalObjectModelFrozen",
            "PassiveSetupOnly",
            "KllpsCompatibleSetupMaterialOnly"
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
            "manifestDigest",
            "participants",
            "rosterDigest",
            "setupSeed",
            "thresholdProfileDigest",
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
            "expectedManifestDigest",
            "expectedRosterDigest",
            "expectedRotSetDigest",
            "expectedSetupPackageDigest",
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
    let setup_package_digest = setup_package
        .get("setupPackageDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupPackageDigest must be present",
            )
        })?;
    let mut digest_input = setup_package.clone();
    let digest_object = digest_input.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage must be an object",
        )
    })?;
    digest_object.remove("setupPackageDigest");
    let expected_digest = derive_protocol_digest("BGVPassiveSetupPackageDigest", &digest_input)?;
    if setup_package_digest != expected_digest {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "BGV passive setup package digest does not match its canonical payload",
        ));
    }

    compare_expected_string(
        request,
        "expectedSetupPackageDigest",
        setup_package_digest,
        "setup package digest",
    )?;
    compare_expected_string(
        request,
        "expectedManifestDigest",
        string_at_path(setup_package, &["setupInputs", "manifestDigest"])?,
        "manifest digest",
    )?;
    compare_expected_string(
        request,
        "expectedRosterDigest",
        string_at_path(setup_package, &["setupInputs", "rosterDigest"])?,
        "roster digest",
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
        "expectedRotSetDigest",
        string_at_path(setup_package, &["evaluationKeys", "rotSetDigest"])?,
        "rotation set digest",
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
        "acceptedDigests": [
            setup_package_digest,
            string_at_path(setup_package, &["collectivePublicKey", "collectivePublicKeyRoot"])?,
            string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
            string_at_path(setup_package, &["thresholdVerificationMaterial", "thresholdShareVerificationKeyRoot"])?,
            string_at_path(setup_package, &["thresholdVerificationMaterial", "thresholdShareVerificationKeyDigest"])?,
            string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
            string_at_path(setup_package, &["evaluationKeys", "rotSetDigest"])?,
        ],
        "refusedObjects": [],
        "unresolvedReason": null,
        "statusLabels": [
            "M8PassiveSetupPackageVerified",
            "PassiveSetupDevelopmentFixtureOnly",
            "CollectivePublicKeyRootBound",
            "BgvPublicKeyRootDigestOnly",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "AppendixBSetupInputReady",
            "BgvAlgebraicPublicKeyProofMissing",
            "FinalAppendixBPendingQTarget"
        ],
    }))
}

use input::read_passive_setup_input;
pub(crate) use m9_bridge_trace::{
    M9BridgeCiphertextRelationTrace, generate_m9_bridge_ciphertext_relation_trace_from_slots,
    m9_bridge_batch_encoding_commitment_digest_from_responses,
    m9_bridge_ciphertext_commitment_digest_from_responses,
    verify_m9_bridge_ciphertext_public_bindings,
};
use package_builder::build_passive_setup_package;
