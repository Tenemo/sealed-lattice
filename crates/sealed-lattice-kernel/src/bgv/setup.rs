use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

mod certificates;
mod development_fixtures;
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
    negacyclic_product_mod, sample_bounded_collective_error_share_distribution,
    sample_bounded_collective_secret_share_distribution, sample_encryption_relation_checks,
    sample_positions, sample_public_residues, sample_signed_values, sample_values,
    signed_to_modulus_residue, signed_to_plaintext_scaled_residue,
};

#[cfg(test)]
use crate::bgv::evaluator::key_switch::key_switch_key_from_public_component_b;
use crate::{
    bgv::{
        encoding::encode_batch_plaintext_slots,
        evaluator::{
            engine::DevelopmentBgvKey,
            key_switch::{KeySwitchKey, generate_galois_key, generate_relinearization_key},
            records::MAXIMUM_OPTION_COUNT,
            top_k::selected_evaluator_rotation_key_schedule,
        },
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
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
const PUBLIC_EVALUATION_KEY_COMPONENT_ENCODING: &str = "component-zero-b-little-endian-u64-coefficient-vectors-with-public-component-one-regenerated-from-stream-seed";
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

pub(crate) struct PassiveSetupEvaluationKeySeeds {
    pub(crate) relinearization_key_seeds: BTreeMap<usize, String>,
    pub(crate) rotation_key_seeds: BTreeMap<(usize, usize), String>,
}

pub(crate) struct PassiveSetupPublicEvaluationKeys {
    pub(crate) relinearization_keys: Vec<Option<KeySwitchKey>>,
    pub(crate) rotation_keys: BTreeMap<(usize, usize), KeySwitchKey>,
}

pub(crate) struct PreparedPassiveSetupPublicEvaluationKeys {
    pub(crate) keys: PassiveSetupPublicEvaluationKeys,
    pub(crate) record: Value,
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
            "BGVDevelopmentEncryptionFixtureHash",
            "RotSetHash",
            "ComparisonInputDerivationCircuitHash",
            "EncryptedComparisonInputHash",
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
            "TargetDecryptionSetupMaterialMatchedOnly"
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
            "DirectEvaluatorReplayHeSecurityAccepted",
            "FinalTargetSecurityPendingTargetModulus"
        ],
    }))
}

pub(crate) fn validate_passive_setup_package_for_encrypted_evaluation(
    setup_package: &Value,
) -> CanonicalResult<()> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)
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

pub(crate) fn generate_passive_setup_public_evaluation_key_material_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let generated = generate_passive_setup_public_evaluation_keys_from_request(
        request,
        "generateBgvEvaluationKeyMaterial",
    )?;
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let seed_material = evaluation_key_seeds_from_passive_setup_package(
        setup_package,
        usize_at_path(&generated.record, &["workingLevel"])?,
    )?;
    let relinearization_keys = generated
        .keys
        .relinearization_keys
        .iter()
        .enumerate()
        .skip(1)
        .map(|(level, key)| {
            let seed = seed_material
                .relinearization_key_seeds
                .get(&level)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "missing setup-bound relinearization key stream seed",
                    )
                })?;
            public_key_switch_material_entry(
                "relinearization",
                "secret-square",
                None,
                level,
                seed,
                key.as_ref().ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "generated public evaluation-key material is missing a relinearization key",
                    )
                })?,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let rotation_keys = generated
        .keys
        .rotation_keys
        .iter()
        .map(|((rotation, level), key)| {
            let seed = seed_material
                .rotation_key_seeds
                .get(&(*rotation, *level))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        "requested public rotation key is not part of the selected setup rotation set",
                    )
                })?;
            public_key_switch_material_entry(
                "rotation",
                "selected-rotation",
                Some(*rotation),
                *level,
                seed,
                key,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let mut material = generated.record;
    material["objectType"] = Value::String("BgvPublicEvaluationKeyMaterial".to_string());
    material["componentEncoding"] =
        Value::String(PUBLIC_EVALUATION_KEY_COMPONENT_ENCODING.to_string());
    material["relinearizationKeys"] = Value::Array(relinearization_keys);
    material["rotationKeys"] = Value::Array(rotation_keys);
    material["statusLabels"] = json!([
        "PublicEvaluationKeyMaterialGenerated",
        "SetupPrivateWitnessNotExported",
        "EvaluationKeyRootBound"
    ]);
    let public_material_hash = derive_protocol_hash("EvaluationKeySetHash", &material)?;
    material["publicEvaluationKeyMaterialHash"] = Value::String(public_material_hash);

    Ok(material)
}

pub(crate) fn generate_passive_setup_public_evaluation_keys_from_request(
    request: &Value,
    command_name: &str,
) -> CanonicalResult<PreparedPassiveSetupPublicEvaluationKeys> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupPackage",
            "setupPrivateWitness",
            "workingLevel",
            "rotationKeys",
        ],
        command_name,
    )?;
    reject_forbidden_setup_fields(request)?;
    let setup_package = value_at_path(request, &["setupPackage"])?;
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    let private_setup_seed = string_at_path(request, &["setupPrivateWitness", "setupSeed"])?;
    let working_level = request
        .get("workingLevel")
        .and_then(Value::as_u64)
        .and_then(|level| usize::try_from(level).ok())
        .unwrap_or(DATA_PRIMES.len() - 1);
    if working_level >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material working level is outside the selected data basis",
        ));
    }
    let rotation_requests = read_public_evaluation_key_rotation_requests(request, working_level)?;

    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, private_setup_seed)?;
    let seed_material =
        evaluation_key_seeds_from_passive_setup_package(setup_package, working_level)?;
    let mut relinearization_keys = Vec::with_capacity(working_level + 1);
    relinearization_keys.push(None);
    for level in 1..=working_level {
        let seed = seed_material
            .relinearization_key_seeds
            .get(&level)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "missing setup-bound relinearization key stream seed",
                )
            })?;
        let mut key = generate_relinearization_key(&evaluator_key, level, seed)?;
        key.drop_component_a_ntt();
        relinearization_keys.push(Some(key));
    }
    let mut rotation_keys = BTreeMap::new();
    for (rotation, level) in rotation_requests {
        let seed = seed_material
            .rotation_key_seeds
            .get(&(rotation, level))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "requested public rotation key is not part of the selected setup rotation set",
                )
            })?;
        let mut key = generate_galois_key(&evaluator_key, rotation, level, seed)?;
        key.drop_component_a_ntt();
        rotation_keys.insert((rotation, level), key);
    }
    let record = json!({
        "objectType": "PreparedBgvPublicEvaluationKeyMaterial",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "setupPackageHash": string_at_path(setup_package, &["setupPackageHash"])?,
        "collectivePublicKeyRoot": string_at_path(setup_package, &["collectivePublicKey", "collectivePublicKeyRoot"])?,
        "bgvPublicKeyRoot": string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
        "evaluationKeyRoot": string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
        "keySwitchDecompositionHash": string_at_path(setup_package, &["evaluationKeys", "keySwitchDecompositionHash"])?,
        "rotSetHash": string_at_path(setup_package, &["evaluationKeys", "rotSetHash"])?,
        "workingLevel": working_level,
        "relinearizationKeyCount": working_level,
        "rotationKeyCount": rotation_keys.len(),
        "rawSecretMaterialExported": false,
        "statusLabels": [
            "PreparedPublicEvaluationKeyMaterialGenerated",
            "SetupPrivateWitnessNotExported",
            "EvaluationKeyRootBound"
        ],
    });

    Ok(PreparedPassiveSetupPublicEvaluationKeys {
        keys: PassiveSetupPublicEvaluationKeys {
            relinearization_keys,
            rotation_keys,
        },
        record,
    })
}

#[cfg(test)]
pub(crate) fn public_evaluation_keys_from_material(
    setup_package: &Value,
    material: &Value,
    working_level: usize,
) -> CanonicalResult<PassiveSetupPublicEvaluationKeys> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    reject_forbidden_public_evaluation_key_material_secret_fields(material)?;
    compare_string_at_path(
        material,
        &["objectType"],
        "BgvPublicEvaluationKeyMaterial",
        "public evaluation-key material object type",
    )?;
    if usize_at_path(material, &["objectVersion"])? != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public evaluation-key material object version is unsupported",
        ));
    }
    compare_string_at_path(
        material,
        &["setupProfileId"],
        PASSIVE_SETUP_PROFILE_ID,
        "public evaluation-key material setup profile",
    )?;
    compare_string_at_path(
        material,
        &["componentEncoding"],
        PUBLIC_EVALUATION_KEY_COMPONENT_ENCODING,
        "public evaluation-key material component encoding",
    )?;
    if bool_at_path(material, &["rawSecretMaterialExported"])? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material must not export raw secret material",
        ));
    }
    compare_hash_at_path(
        material,
        &["setupPackageHash"],
        string_at_path(setup_package, &["setupPackageHash"])?,
        "public evaluation-key material setup package hash",
    )?;
    compare_hash_at_path(
        material,
        &["evaluationKeyRoot"],
        string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?,
        "public evaluation-key material evaluation key root",
    )?;
    compare_hash_at_path(
        material,
        &["collectivePublicKeyRoot"],
        string_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?,
        "public evaluation-key material collective public key root",
    )?;
    compare_hash_at_path(
        material,
        &["bgvPublicKeyRoot"],
        string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
        "public evaluation-key material BGV public key root",
    )?;
    compare_hash_at_path(
        material,
        &["keySwitchDecompositionHash"],
        string_at_path(
            setup_package,
            &["evaluationKeys", "keySwitchDecompositionHash"],
        )?,
        "public evaluation-key material key-switch decomposition hash",
    )?;
    compare_hash_at_path(
        material,
        &["rotSetHash"],
        string_at_path(setup_package, &["evaluationKeys", "rotSetHash"])?,
        "public evaluation-key material rotation set hash",
    )?;
    if usize_at_path(material, &["workingLevel"])? < working_level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public evaluation-key material working level is below the evaluator working level",
        ));
    }
    let mut hash_input = material.clone();
    hash_input
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public evaluation-key material must be an object",
            )
        })?
        .remove("publicEvaluationKeyMaterialHash");
    compare_hash_at_path(
        material,
        &["publicEvaluationKeyMaterialHash"],
        &derive_protocol_hash("EvaluationKeySetHash", &hash_input)?,
        "public evaluation-key material hash",
    )?;

    let seed_material =
        evaluation_key_seeds_from_passive_setup_package(setup_package, working_level)?;
    let mut relinearization_keys = Vec::with_capacity(working_level + 1);
    relinearization_keys.push(None);
    let mut relinearization_by_level = BTreeMap::new();
    for entry in array_at_path(material, &["relinearizationKeys"])? {
        let level = usize_at_path(entry, &["level"])?;
        let seed = string_at_path(entry, &["keyStreamSeed"])?;
        if seed_material
            .relinearization_key_seeds
            .get(&level)
            .map(String::as_str)
            != Some(seed)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public relinearization key seed does not match the setup key stream",
            ));
        }
        let key = public_key_switch_material_entry_to_key(entry, "relinearization", None)?;
        if relinearization_by_level.insert(level, key).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public evaluation-key material repeats a relinearization key level",
            ));
        }
    }
    for level in 1..=working_level {
        relinearization_keys.push(Some(relinearization_by_level.remove(&level).ok_or_else(
            || {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public evaluation-key material is missing a required relinearization key",
                )
            },
        )?));
    }
    if !relinearization_by_level.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public evaluation-key material contains relinearization keys outside the requested level schedule",
        ));
    }

    let mut rotation_keys = BTreeMap::new();
    for entry in array_at_path(material, &["rotationKeys"])? {
        let rotation = usize_at_path(entry, &["rotation"])?;
        let level = usize_at_path(entry, &["level"])?;
        let seed = string_at_path(entry, &["keyStreamSeed"])?;
        if seed_material
            .rotation_key_seeds
            .get(&(rotation, level))
            .map(String::as_str)
            != Some(seed)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public rotation key seed does not match the setup key stream",
            ));
        }
        let key = public_key_switch_material_entry_to_key(entry, "rotation", Some(rotation))?;
        if rotation_keys.insert((rotation, level), key).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public evaluation-key material repeats a rotation key",
            ));
        }
    }

    Ok(PassiveSetupPublicEvaluationKeys {
        relinearization_keys,
        rotation_keys,
    })
}

#[cfg(test)]
fn reject_forbidden_public_evaluation_key_material_secret_fields(
    value: &Value,
) -> CanonicalResult<()> {
    reject_forbidden_setup_package_secret_fields(value)?;
    match value {
        Value::Array(items) => {
            for item in items {
                reject_forbidden_public_evaluation_key_material_secret_fields(item)?;
            }
        }
        Value::Object(fields) => {
            for (field_name, field_value) in fields {
                if field_name == "setupPrivateWitness" || field_name == "privateSetupSeedHash" {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!(
                            "{field_name} must not be present in public evaluation-key material"
                        ),
                    ));
                }
                reject_forbidden_public_evaluation_key_material_secret_fields(field_value)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn read_public_evaluation_key_rotation_requests(
    request: &Value,
    working_level: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    match request.get("rotationKeys") {
        None => selected_public_evaluation_key_rotation_requests(working_level),
        Some(Value::Array(entries)) => {
            let mut seen = BTreeSet::new();
            entries
                .iter()
                .map(|entry| {
                    let rotation = usize_at_path(entry, &["rotation"])?;
                    let level = usize_at_path(entry, &["level"])?;
                    if !seen.insert((rotation, level)) {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::ProfileComponentMismatch,
                            "rotationKeys must not repeat a rotation and level",
                        ));
                    }

                    Ok((rotation, level))
                })
                .collect()
        }
        Some(_) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rotationKeys must be an array when supplied",
        )),
    }
}

fn selected_public_evaluation_key_rotation_requests(
    working_level: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    selected_evaluator_rotation_key_schedule(MAXIMUM_OPTION_COUNT, working_level)
}

fn public_key_switch_material_entry(
    key_kind: &str,
    purpose: &str,
    rotation: Option<usize>,
    level: usize,
    seed: &str,
    key: &KeySwitchKey,
) -> CanonicalResult<Value> {
    if key.level != level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "generated public key-switch material level does not match its request",
        ));
    }
    let digits = key
        .components
        .iter()
        .enumerate()
        .map(|(digit_index, component)| {
            let component_b = component.component_b.as_ref().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public key-switch material serialization requires component-b coefficient limbs",
                )
            })?;
            let limbs = component_b
                .iter()
                .enumerate()
                .map(|(limb_index, coefficients)| {
                    json!({
                        "limbIndex": limb_index,
                        "modulus": DATA_PRIMES[limb_index],
                        "componentZeroBLeHex": coefficient_vector_le_hex(coefficients),
                        "componentZeroBHash512": coefficient_vector_hash512(coefficients),
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({
                "digitIndex": digit_index,
                "limbs": limbs,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "keyKind": key_kind,
        "purpose": purpose,
        "rotation": rotation,
        "level": level,
        "keyStreamSeed": seed,
        "digits": digits,
    }))
}

#[cfg(test)]
fn public_key_switch_material_entry_to_key(
    entry: &Value,
    expected_key_kind: &str,
    expected_rotation: Option<usize>,
) -> CanonicalResult<KeySwitchKey> {
    compare_string_at_path(
        entry,
        &["keyKind"],
        expected_key_kind,
        "public key-switch material kind",
    )?;
    match expected_rotation {
        Some(rotation) => {
            if usize_at_path(entry, &["rotation"])? != rotation {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "public rotation key material has the wrong rotation",
                ));
            }
        }
        None if !entry.get("rotation").is_none_or(Value::is_null) => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public relinearization key material must not carry a rotation",
            ));
        }
        None => {}
    }
    let level = usize_at_path(entry, &["level"])?;
    let seed = string_at_path(entry, &["keyStreamSeed"])?;
    let domain = match expected_rotation {
        Some(rotation) => format!("galois-{rotation}"),
        None => "relinearization".to_string(),
    };
    let mut component_b_by_digit = Vec::new();
    for digit in array_at_path(entry, &["digits"])? {
        let digit_index = usize_at_path(digit, &["digitIndex"])?;
        if digit_index != component_b_by_digit.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public key-switch material digits must be in canonical order",
            ));
        }
        let mut component_b_by_limb = Vec::new();
        for limb in array_at_path(digit, &["limbs"])? {
            let limb_index = usize_at_path(limb, &["limbIndex"])?;
            if limb_index != component_b_by_limb.len() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "public key-switch material limbs must be in canonical order",
                ));
            }
            if unsigned_at_path(limb, &["modulus"])? != DATA_PRIMES[limb_index] {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "public key-switch material limb modulus does not match the selected data basis",
                ));
            }
            let coefficients =
                coefficient_vector_from_le_hex(string_at_path(limb, &["componentZeroBLeHex"])?)?;
            compare_hash_at_path(
                limb,
                &["componentZeroBHash512"],
                &coefficient_vector_hash512(&coefficients),
                "public key-switch material component-zero hash",
            )?;
            component_b_by_limb.push(coefficients);
        }
        component_b_by_digit.push(component_b_by_limb);
    }

    key_switch_key_from_public_component_b(level, &domain, seed, component_b_by_digit)
}

#[cfg(test)]
fn coefficient_vector_from_le_hex(value: &str) -> CanonicalResult<Vec<u64>> {
    let bytes = crate::transcript_core::decode_hex(value)?;
    if bytes.len() != POLYNOMIAL_DEGREE * 8 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public key-switch coefficient vector byte length does not match the selected BGV profile",
        ));
    }
    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut coefficient_bytes = [0_u8; 8];
            coefficient_bytes.copy_from_slice(chunk);
            u64::from_le_bytes(coefficient_bytes)
        })
        .collect())
}

fn coefficient_vector_bytes(coefficients: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for coefficient in coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }
    bytes
}

fn coefficient_vector_le_hex(coefficients: &[u64]) -> String {
    crate::transcript_core::encode_hex(&coefficient_vector_bytes(coefficients))
}

fn coefficient_vector_hash512(coefficients: &[u64]) -> String {
    hash512_hex(
        "sealed-lattice-bgv-rns/public-key-switch-component-vector-v1",
        &[&coefficient_vector_bytes(coefficients)],
    )
}

use input::read_passive_setup_input;
use package_builder::build_passive_setup_package;
