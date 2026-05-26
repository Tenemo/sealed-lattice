use std::collections::BTreeSet;

use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

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
            canonical_ciphertext_convention_digest, encoded_aggregate_layout_digest, layout_digest,
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
            "CollectivePublicKeyRootBound",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "AppendixBSetupInputReady",
            "FinalAppendixBPendingQTarget"
        ],
    }))
}

#[derive(Clone, Debug)]
pub(crate) struct M9BridgeCiphertextRelationTrace {
    pub(crate) public_artifact: Value,
    pub(crate) supplied_plaintext_slots: Vec<u64>,
    pub(crate) padded_plaintext_slots: Vec<u64>,
    pub(crate) plaintext_coefficients_mod_plaintext: Vec<u64>,
    pub(crate) encryption_randomness_coefficients: Vec<i64>,
    pub(crate) encryption_error_zero_coefficients: Vec<i64>,
    pub(crate) encryption_error_one_coefficients: Vec<i64>,
}

impl M9BridgeCiphertextRelationTrace {
    fn validate_shape(&self, supplied_slot_count: usize) -> CanonicalResult<()> {
        if self.supplied_plaintext_slots.len() != supplied_slot_count
            || self.padded_plaintext_slots.len() != POLYNOMIAL_DEGREE
            || self.plaintext_coefficients_mod_plaintext.len() != POLYNOMIAL_DEGREE
            || self.encryption_randomness_coefficients.len() != POLYNOMIAL_DEGREE
            || self.encryption_error_zero_coefficients.len() != POLYNOMIAL_DEGREE
            || self.encryption_error_one_coefficients.len() != POLYNOMIAL_DEGREE
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge ciphertext relation trace has inconsistent witness dimensions",
            ));
        }
        if self
            .supplied_plaintext_slots
            .iter()
            .chain(self.padded_plaintext_slots.iter())
            .chain(self.plaintext_coefficients_mod_plaintext.iter())
            .any(|coefficient| *coefficient >= PLAINTEXT_MODULUS)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M9 bridge ciphertext relation trace contains a non-canonical plaintext coefficient",
            ));
        }
        if self
            .encryption_randomness_coefficients
            .iter()
            .any(|coefficient| !(-1..=1).contains(coefficient))
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M9 bridge ciphertext relation trace randomizer is outside the declared support",
            ));
        }
        if self
            .encryption_error_zero_coefficients
            .iter()
            .chain(self.encryption_error_one_coefficients.iter())
            .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M9 bridge ciphertext relation trace error coefficient is outside the declared support",
            ));
        }

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_m9_bridge_ciphertext_relation_trace_from_slots(
    setup_package: &Value,
    contributor_identity: &str,
    aggregate_derivation_component_digest: &str,
    aggregate_derivation_statement_digest: &str,
    post_voting_closed_context_digest: &str,
    reduced_aggregate_slots: &[u64],
    prover_randomness_hex: &str,
    include_canonical_bytes_hex: bool,
) -> CanonicalResult<M9BridgeCiphertextRelationTrace> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;

    let setup_seed_digest = string_at_path(setup_package, &["setupInputs", "setupSeedDigest"])?;
    let collective_public_key_root = string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
    )?;
    let bgv_public_key_root =
        string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?;
    let manifest_digest = string_at_path(setup_package, &["setupInputs", "manifestDigest"])?;
    let roster_digest = string_at_path(setup_package, &["setupInputs", "rosterDigest"])?;
    let threshold_profile_digest =
        string_at_path(setup_package, &["setupInputs", "thresholdProfileDigest"])?;
    let encoded = encode_batch_plaintext_slots(reduced_aggregate_slots, DATA_PRIMES.len() - 1)?;
    let plaintext_bytes = serialize_bgv_object(
        BgvObjectKind::Plaintext,
        std::slice::from_ref(&encoded.polynomial),
    )?;
    let plaintext_root = plaintext_root(&plaintext_bytes);
    let encryption_seed_digest = hash512_hex(
        "sealed-lattice-bgv-rns/m9-bridge-encryption-seed-v1",
        &[
            setup_seed_digest.as_bytes(),
            contributor_identity.as_bytes(),
            aggregate_derivation_component_digest.as_bytes(),
            aggregate_derivation_statement_digest.as_bytes(),
            post_voting_closed_context_digest.as_bytes(),
            prover_randomness_hex.as_bytes(),
        ],
    );
    let encryption_randomness_coefficients = dense_small_coefficients(
        &encryption_seed_digest,
        "m9-bridge-encryption",
        "encryption-randomness",
        -1,
        1,
    );
    let encryption_error_zero_coefficients = dense_centered_binomial_coefficients(
        &encryption_seed_digest,
        "m9-bridge-encryption",
        "encryption-error-zero",
    );
    let encryption_error_one_coefficients = dense_centered_binomial_coefficients(
        &encryption_seed_digest,
        "m9-bridge-encryption",
        "encryption-error-one",
    );
    let public_sample_label = format!(
        "m9-bridge-encryption-public-sample:{aggregate_derivation_statement_digest}:{contributor_identity}"
    );
    let mut component_zero_residues_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
    let mut component_one_residues_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
    let mut sampled_relation_checks = Vec::new();

    for (modulus_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let public_key_coefficients = dense_public_residues(
            setup_seed_digest,
            "development-collective-public-key-coefficients",
            modulus,
        );
        let public_sample_coefficients =
            dense_public_residues(setup_seed_digest, &public_sample_label, modulus);
        let randomness_residues = encryption_randomness_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let error_zero_residues = encryption_error_zero_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let error_one_residues = encryption_error_one_coefficients
            .iter()
            .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let public_key_product =
            negacyclic_product_mod(&public_key_coefficients, &randomness_residues, modulus)?;
        let public_sample_product =
            negacyclic_product_mod(&public_sample_coefficients, &randomness_residues, modulus)?;
        let message_residues = encoded
            .polynomial
            .residues_by_modulus
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "M9 bridge plaintext is missing a selected data-basis residue limb",
                )
            })?;
        let ciphertext_component_zero = public_key_product
            .iter()
            .zip(error_zero_residues.iter())
            .zip(message_residues.iter())
            .map(|((product, error), message_coefficient)| {
                add_mod(
                    add_mod(*product, *error, modulus)?,
                    *message_coefficient,
                    modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let ciphertext_component_one = public_sample_product
            .iter()
            .zip(error_one_residues.iter())
            .map(|(product, error)| add_mod(*product, *error, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;

        if modulus_index == 0 {
            sampled_relation_checks = sample_encryption_relation_checks(
                message_residues,
                &public_key_product,
                &public_sample_product,
                &error_zero_residues,
                &error_one_residues,
            )?;
        }
        component_zero_residues_by_modulus.push(ciphertext_component_zero);
        component_one_residues_by_modulus.push(ciphertext_component_one);
    }

    let layout_digest = layout_digest()?;
    let component_zero = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        DATA_PRIMES.len() - 1,
        layout_digest.clone(),
        component_zero_residues_by_modulus,
    )?;
    let component_one = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        DATA_PRIMES.len() - 1,
        layout_digest,
        component_one_residues_by_modulus,
    )?;
    let canonical_bytes =
        serialize_bgv_object(BgvObjectKind::Ciphertext, &[component_zero, component_one])?;
    let ciphertext_root = ciphertext_root(&canonical_bytes);
    let encrypted_aggregate_share_ciphertext_root = derive_protocol_digest(
        "EncryptedAggregateShareCiphertextRoot",
        &json!({
            "purpose": "m9-encrypted-aggregate-share-ciphertext-root-v1",
            "aggregateDerivationComponentDigest": aggregate_derivation_component_digest,
            "aggregateDerivationStatementDigest": aggregate_derivation_statement_digest,
            "postVotingClosedContextDigest": post_voting_closed_context_digest,
            "manifestDigest": manifest_digest,
            "rosterDigest": roster_digest,
            "thresholdProfileDigest": threshold_profile_digest,
            "collectivePublicKeyRoot": collective_public_key_root,
            "bgvPublicKeyRoot": bgv_public_key_root,
            "plaintextRoot": plaintext_root,
            "ciphertextRoot": ciphertext_root,
            "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest()?,
            "bgvProfileDigest": profile_digest()?,
            "rustBgvBackendProfileDigest": backend_profile_digest()?,
        }),
    )?;

    let sampled_relation_check_count = sampled_relation_checks.len();
    let mut result = json!({
        "ok": true,
        "operation": "generateAggregateBridgeEncryption",
        "profileDigest": profile_digest()?,
        "rustBgvBackendProfileDigest": backend_profile_digest()?,
        "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest()?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "plaintextRoot": plaintext_root,
        "ciphertextRoot": ciphertext_root,
        "encryptedAggregateShareCiphertextRoot": encrypted_aggregate_share_ciphertext_root,
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
        "basisId": BgvBasisKind::Data.basis_id(),
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "suppliedSlotCount": reduced_aggregate_slots.len(),
        "slotCount": POLYNOMIAL_DEGREE,
        "sampledPublicRelationChecks": sampled_relation_checks,
        "sampledPublicRelationCheckPolicy": {
            "objectType": "M9BridgeSampledRelationCheckPolicy",
            "objectVersion": 1,
            "diagnosticOnly": true,
            "acceptedForBridgeProofVerification": false,
            "fullBridgeProofRequired": true,
            "sampledOnlyBridgeVerificationAccepted": false,
            "relationCheckSource": "first-data-prime-diagnostic",
            "sampledRelationCheckCount": sampled_relation_check_count
        },
        "privateMaterialDisclosure": {
            "aggregateOpeningMaterialExported": false,
            "aggregateShareMaterialExported": false,
            "layoutMessageMaterialExported": false,
            "encodedMessageMaterialExported": false,
            "encryptionRandomizerMaterialExported": false,
            "noiseMaterialExported": false
        },
        "statusLabels": [
            "M9BridgePlaintextAssembled",
            "M9BridgeCiphertextGenerated",
            "CollectivePublicKeyRootBound",
            "CoefficientDomainCanonical",
            "BridgeProofBackendStillRequired"
        ],
    });
    if include_canonical_bytes_hex {
        result["canonicalBytesHex"] = Value::String(canonical_bytes_hex(&canonical_bytes));
    }

    let trace = M9BridgeCiphertextRelationTrace {
        public_artifact: result,
        supplied_plaintext_slots: reduced_aggregate_slots.to_vec(),
        padded_plaintext_slots: encoded.slots,
        plaintext_coefficients_mod_plaintext: encoded.coefficients_mod_plaintext,
        encryption_randomness_coefficients,
        encryption_error_zero_coefficients,
        encryption_error_one_coefficients,
    };
    trace.validate_shape(reduced_aggregate_slots.len())?;

    Ok(trace)
}

pub(crate) fn m9_bridge_batch_encoding_commitment_digest_from_responses(
    reduced_slot_response: &[i128],
    plaintext_coefficient_response: &[i128],
) -> CanonicalResult<String> {
    if reduced_slot_response.len() > POLYNOMIAL_DEGREE
        || plaintext_coefficient_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge batch encoding proof response dimensions are invalid",
        ));
    }
    let mut padded_slot_response = vec![0_u64; POLYNOMIAL_DEGREE];
    for (slot_index, response) in reduced_slot_response.iter().enumerate() {
        padded_slot_response[slot_index] =
            signed_i128_to_modulus_residue(*response, PLAINTEXT_MODULUS);
    }
    let encoded_response_coefficients =
        inverse_negacyclic_ntt(&padded_slot_response, PLAINTEXT_MODULUS)?;
    let commitment_coefficients = encoded_response_coefficients
        .iter()
        .zip(plaintext_coefficient_response.iter())
        .map(|(encoded_response_coefficient, plaintext_response)| {
            let plaintext_response_residue =
                signed_i128_to_modulus_residue(*plaintext_response, PLAINTEXT_MODULUS);
            sub_mod(
                *encoded_response_coefficient,
                plaintext_response_residue,
                PLAINTEXT_MODULUS,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-bridge-batch-encoding-commitment-v1",
            "commitmentCoefficients": commitment_coefficients
                .iter()
                .map(|coefficient| coefficient.to_string())
                .collect::<Vec<_>>(),
        }),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn m9_bridge_ciphertext_commitment_digest_from_responses(
    setup_package: &Value,
    contributor_identity: &str,
    aggregate_derivation_statement_digest: &str,
    bridge_encryption: &Value,
    challenge_scalar: u64,
    plaintext_coefficient_response: &[i128],
    randomizer_response: &[i128],
    perturbation_zero_response: &[i128],
    perturbation_one_response: &[i128],
) -> CanonicalResult<String> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;
    if plaintext_coefficient_response.len() != POLYNOMIAL_DEGREE
        || randomizer_response.len() != POLYNOMIAL_DEGREE
        || perturbation_zero_response.len() != POLYNOMIAL_DEGREE
        || perturbation_one_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge ciphertext proof response dimensions are invalid",
        ));
    }
    let canonical_bytes_hex = string_at_path(bridge_encryption, &["canonicalBytesHex"])?;
    let ciphertext = parse_bgv_object_hex(canonical_bytes_hex)?;
    if ciphertext.object_kind != BgvObjectKind::Ciphertext || ciphertext.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge proof response verifier requires a two-component ciphertext",
        ));
    }
    for component in &ciphertext.components {
        component.validate()?;
        if component.basis_id != BgvBasisKind::Data.basis_id()
            || component.level != DATA_PRIMES.len() - 1
            || component.moduli != DATA_PRIMES
            || component.residues_by_modulus.len() != DATA_PRIMES.len()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge proof ciphertext must cover the full data basis",
            ));
        }
    }

    let setup_seed_digest = string_at_path(setup_package, &["setupInputs", "setupSeedDigest"])?;
    let public_sample_label = format!(
        "m9-bridge-encryption-public-sample:{aggregate_derivation_statement_digest}:{contributor_identity}"
    );
    let challenge_scalar_i128 = i128::from(challenge_scalar);
    let mut component_zero_residues_by_modulus = Vec::with_capacity(DATA_PRIMES.len());
    let mut component_one_residues_by_modulus = Vec::with_capacity(DATA_PRIMES.len());

    for (modulus_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let public_key_coefficients = dense_public_residues(
            setup_seed_digest,
            "development-collective-public-key-coefficients",
            modulus,
        );
        let public_sample_coefficients =
            dense_public_residues(setup_seed_digest, &public_sample_label, modulus);
        let randomizer_residues = randomizer_response
            .iter()
            .map(|coefficient| signed_i128_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let perturbation_zero_residues = perturbation_zero_response
            .iter()
            .map(|coefficient| signed_i128_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let perturbation_one_residues = perturbation_one_response
            .iter()
            .map(|coefficient| signed_i128_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let plaintext_response_residues = plaintext_coefficient_response
            .iter()
            .map(|coefficient| signed_i128_to_modulus_residue(*coefficient, modulus))
            .collect::<Vec<_>>();
        let public_key_product =
            negacyclic_product_mod(&public_key_coefficients, &randomizer_residues, modulus)?;
        let public_sample_product =
            negacyclic_product_mod(&public_sample_coefficients, &randomizer_residues, modulus)?;
        let challenge_residue = signed_i128_to_modulus_residue(challenge_scalar_i128, modulus);
        let ciphertext_component_zero = ciphertext.components[0]
            .residues_by_modulus
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "M9 bridge proof ciphertext component zero is missing a data limb",
                )
            })?;
        let ciphertext_component_one = ciphertext.components[1]
            .residues_by_modulus
            .get(modulus_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "M9 bridge proof ciphertext component one is missing a data limb",
                )
            })?;

        let commitment_zero = public_key_product
            .iter()
            .zip(perturbation_zero_residues.iter())
            .zip(plaintext_response_residues.iter())
            .zip(ciphertext_component_zero.iter())
            .map(
                |(((product, perturbation), plaintext_response), ciphertext_coefficient)| {
                    let response_sum = add_mod(
                        add_mod(*product, *perturbation, modulus)?,
                        *plaintext_response,
                        modulus,
                    )?;
                    let scaled_ciphertext =
                        mul_mod(challenge_residue, *ciphertext_coefficient, modulus)?;
                    sub_mod(response_sum, scaled_ciphertext, modulus)
                },
            )
            .collect::<CanonicalResult<Vec<_>>>()?;
        let commitment_one = public_sample_product
            .iter()
            .zip(perturbation_one_residues.iter())
            .zip(ciphertext_component_one.iter())
            .map(|((product, perturbation), ciphertext_coefficient)| {
                let response_sum = add_mod(*product, *perturbation, modulus)?;
                let scaled_ciphertext =
                    mul_mod(challenge_residue, *ciphertext_coefficient, modulus)?;
                sub_mod(response_sum, scaled_ciphertext, modulus)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;

        component_zero_residues_by_modulus.push(commitment_zero);
        component_one_residues_by_modulus.push(commitment_one);
    }

    let layout_digest = layout_digest()?;
    let component_zero = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        DATA_PRIMES.len() - 1,
        layout_digest.clone(),
        component_zero_residues_by_modulus,
    )?;
    let component_one = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        DATA_PRIMES.len() - 1,
        layout_digest,
        component_one_residues_by_modulus,
    )?;
    let commitment_bytes =
        serialize_bgv_object(BgvObjectKind::Ciphertext, &[component_zero, component_one])?;

    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-bridge-bgv-ciphertext-commitment-v1",
            "commitmentRoot": ciphertext_root(&commitment_bytes),
            "commitmentCanonicalBytesHash512": canonical_bytes_hash(&commitment_bytes),
        }),
    )
}

fn signed_i128_to_modulus_residue(value: i128, modulus: u64) -> u64 {
    let residue = value.rem_euclid(i128::from(modulus));

    u64::try_from(residue).expect("non-negative i128 residue below a u64 modulus fits u64")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_m9_bridge_ciphertext_public_bindings(
    setup_package: &Value,
    aggregate_derivation_component_digest: &str,
    aggregate_derivation_statement_digest: &str,
    post_voting_closed_context_digest: &str,
    bridge_encryption: &Value,
) -> CanonicalResult<()> {
    validation::validate_setup_package_shape(setup_package)?;
    validation::validate_setup_package_internal_bindings(setup_package)?;

    let collective_public_key_root = string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
    )?;
    let bgv_public_key_root =
        string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?;
    let manifest_digest = string_at_path(setup_package, &["setupInputs", "manifestDigest"])?;
    let roster_digest = string_at_path(setup_package, &["setupInputs", "rosterDigest"])?;
    let threshold_profile_digest =
        string_at_path(setup_package, &["setupInputs", "thresholdProfileDigest"])?;
    let plaintext_root = string_at_path(bridge_encryption, &["plaintextRoot"])?;
    let ciphertext_root = string_at_path(bridge_encryption, &["ciphertextRoot"])?;
    let expected_encrypted_aggregate_share_ciphertext_root = derive_protocol_digest(
        "EncryptedAggregateShareCiphertextRoot",
        &json!({
            "purpose": "m9-encrypted-aggregate-share-ciphertext-root-v1",
            "aggregateDerivationComponentDigest": aggregate_derivation_component_digest,
            "aggregateDerivationStatementDigest": aggregate_derivation_statement_digest,
            "postVotingClosedContextDigest": post_voting_closed_context_digest,
            "manifestDigest": manifest_digest,
            "rosterDigest": roster_digest,
            "thresholdProfileDigest": threshold_profile_digest,
            "collectivePublicKeyRoot": collective_public_key_root,
            "bgvPublicKeyRoot": bgv_public_key_root,
            "plaintextRoot": plaintext_root,
            "ciphertextRoot": ciphertext_root,
            "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest()?,
            "bgvProfileDigest": profile_digest()?,
            "rustBgvBackendProfileDigest": backend_profile_digest()?,
        }),
    )?;

    compare_m9_bridge_string_at_path(
        bridge_encryption,
        &["profileDigest"],
        &profile_digest()?,
        "BGV profile digest",
    )?;
    compare_m9_bridge_string_at_path(
        bridge_encryption,
        &["rustBgvBackendProfileDigest"],
        &backend_profile_digest()?,
        "Rust BGV backend profile digest",
    )?;
    compare_m9_bridge_string_at_path(
        bridge_encryption,
        &["canonicalCiphertextConventionDigest"],
        &canonical_ciphertext_convention_digest()?,
        "canonical ciphertext convention digest",
    )?;
    compare_m9_bridge_string_at_path(
        bridge_encryption,
        &["collectivePublicKeyRoot"],
        collective_public_key_root,
        "collective public key root",
    )?;
    compare_m9_bridge_string_at_path(
        bridge_encryption,
        &["bgvPublicKeyRoot"],
        bgv_public_key_root,
        "BGV public key root",
    )?;
    compare_m9_bridge_string_at_path(
        bridge_encryption,
        &["basisId"],
        BgvBasisKind::Data.basis_id(),
        "ciphertext basis",
    )?;
    if usize_at_path(bridge_encryption, &["level"])? != DATA_PRIMES.len() - 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge ciphertext level does not match the full data basis",
        ));
    }
    if usize_at_path(bridge_encryption, &["coefficientCount"])? != POLYNOMIAL_DEGREE
        || usize_at_path(bridge_encryption, &["slotCount"])? != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge ciphertext dimensions do not match the selected BGV profile",
        ));
    }
    compare_m9_bridge_string_at_path(
        bridge_encryption,
        &["encryptedAggregateShareCiphertextRoot"],
        &expected_encrypted_aggregate_share_ciphertext_root,
        "encrypted aggregate-share ciphertext root",
    )?;

    Ok(())
}

fn compare_m9_bridge_string_at_path(
    value: &Value,
    path: &[&str],
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    let actual = string_at_path(value, path)?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M9 bridge {description} does not match its canonical binding"),
        ));
    }

    Ok(())
}

fn build_passive_setup_package(input: &PassiveSetupInput) -> CanonicalResult<Value> {
    let profile_digest = profile_digest()?;
    let backend_profile_digest = backend_profile_digest()?;
    let collective_secret_distribution_certificate =
        collective_secret_distribution_certificate(input.participants.len())?;
    let collective_secret_distribution_certificate_digest = derive_protocol_digest(
        "CollectiveSecretDistributionCertificateDigest",
        &collective_secret_distribution_certificate,
    )?;
    let error_distribution_certificate = error_distribution_certificate()?;
    let error_distribution_certificate_digest = derive_protocol_digest(
        "ErrorDistributionCertificateDigest",
        &error_distribution_certificate,
    )?;
    let key_switch_decomposition = key_switch_decomposition_profile()?;
    let key_switch_decomposition_digest =
        derive_protocol_digest("KeySwitchDecompositionDigest", &key_switch_decomposition)?;
    let threshold_decryption_profile = threshold_decryption_profile(&profile_digest)?;
    let threshold_decryption_profile_digest = derive_protocol_digest(
        "ThresholdDecryptionProfileDigest",
        &threshold_decryption_profile,
    )?;
    let kllps_target_decryption_profile_digest = derive_protocol_digest(
        "KllpsTargetDecryptionProfileDigest",
        &json!({
            "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "profileStatus": "future-target-decryption-profile-binding",
        }),
    )?;
    let public_common_random_polynomial_root = public_common_random_polynomial_root(input)?;
    let participant_material = input
        .participants
        .iter()
        .map(|participant| {
            participant_setup_material(
                input,
                participant,
                &profile_digest,
                &backend_profile_digest,
                &public_common_random_polynomial_root,
                &threshold_decryption_profile_digest,
                &kllps_target_decryption_profile_digest,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let participant_records = participant_material
        .iter()
        .map(|material| material.participant_record.clone())
        .collect::<Vec<_>>();
    let public_key_share_roots = participant_material
        .iter()
        .map(|material| material.public_key_share_root.clone())
        .collect::<Vec<_>>();
    let participant_setup_record_digests = participant_material
        .iter()
        .map(|material| material.participant_setup_record_digest.clone())
        .collect::<Vec<_>>();
    let trustee_threshold_verification_key_digests = participant_material
        .iter()
        .map(|material| material.trustee_threshold_verification_key_digest.clone())
        .collect::<Vec<_>>();
    let collective_public_key = collective_public_key(
        input,
        &profile_digest,
        &backend_profile_digest,
        &public_common_random_polynomial_root,
        &public_key_share_roots,
    )?;
    let threshold_verification_material = threshold_verification_material(
        input,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
        &participant_setup_record_digests,
        &trustee_threshold_verification_key_digests,
    )?;
    let evaluation_keys = evaluation_keys(
        input,
        &collective_public_key,
        &key_switch_decomposition_digest,
    )?;
    let development_encryption_fixture =
        development_encryption_fixture(input, &collective_public_key)?;
    let certificates = setup_certificates(
        input,
        &collective_secret_distribution_certificate,
        &collective_secret_distribution_certificate_digest,
        &error_distribution_certificate,
        &error_distribution_certificate_digest,
        &key_switch_decomposition,
        &key_switch_decomposition_digest,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
        &evaluation_keys,
        &development_encryption_fixture,
    )?;
    let evaluator_context_bindings = m8_evaluator_context_bindings()?;

    let mut package = json!({
        "objectType": "BgvPassiveSetupPackage",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "setupMode": "passive-full-roster-development",
        "setupInputs": {
            "ceremonyId": input.ceremony_id,
            "manifestDigest": input.manifest_digest,
            "rosterDigest": input.roster_digest,
            "thresholdProfileDigest": input.threshold_profile_digest,
            "participantCount": input.participants.len(),
            "participantIdentities": input.participants.iter().map(|participant| participant.trustee_identity.clone()).collect::<Vec<_>>(),
            "defaultSetupSeedUsed": !input.setup_seed_provided,
            "setupSeedDigest": input.setup_seed_digest,
        },
        "profileBindings": {
            "profileId": PROFILE_ID,
            "backendProfileId": BACKEND_PROFILE_ID,
            "profileDigest": profile_digest,
            "backendProfileDigest": backend_profile_digest,
            "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest()?,
            "batchEncoderId": BATCH_ENCODER_ID,
            "batchEncoderDigest": batch_encoder_digest()?,
            "batchLayoutBindingDigest": batch_layout_binding_digest()?,
            "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
            "encryptedAggregateInputLayoutDigest": layout_digest()?,
            "ballotScoreEncodingProfileDigest": ballot_score_encoding_profile_digest()?,
            "ballotShareLayoutProfileDigest": ballot_share_layout_profile_digest()?,
            "aggregateInputEncodingProfileDigest": aggregate_input_encoding_profile_digest()?,
            "encodedAggregateLayoutDigest": encoded_aggregate_layout_digest()?,
            "topKEvaluatorInputLayoutDigest": top_k_evaluator_input_layout_digest()?,
            "encryptedAggregateBridgeDigest": evaluator_context_bindings["encryptedAggregateBridgeDigest"],
            "encryptedAggregateTargetBasisDataRoot": evaluator_context_bindings["encryptedAggregateTargetBasisDataRoot"],
            "encryptedAggregateReconstructionDigest": evaluator_context_bindings["encryptedAggregateReconstructionDigest"],
            "scoreBitDerivationCircuitDigest": evaluator_context_bindings["scoreBitDerivationCircuitDigest"],
            "comparisonInputDerivationCircuitDigest": evaluator_context_bindings["comparisonInputDerivationCircuitDigest"],
            "encryptedScoreBitInputDigest": evaluator_context_bindings["encryptedScoreBitInputDigest"],
            "encryptedComparisonInputDigest": evaluator_context_bindings["encryptedComparisonInputDigest"],
            "bitSlicedComparatorDigest": evaluator_context_bindings["bitSlicedComparatorDigest"],
            "encryptedSparseTargetProjectionDigest": evaluator_context_bindings["encryptedSparseTargetProjectionDigest"],
            "m8EvaluatorContextBindingDigest": evaluator_context_bindings["m8EvaluatorContextBindingDigest"],
        },
        "participants": participant_records,
        "collectivePublicKey": collective_public_key,
        "thresholdVerificationMaterial": threshold_verification_material,
        "evaluationKeys": evaluation_keys,
        "developmentEncryptionFixture": development_encryption_fixture,
        "certificates": certificates,
        "trustedDealerBoundary": {
            "transcriptValidCentralizedSecretReconstruction": false,
            "centralizedSecretFixtureMayProduceAcceptedRoots": false,
            "rawSecretSharesExported": false,
            "forbiddenRequestFields": forbidden_setup_field_names(),
        },
        "kllpsCompatibility": {
            "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
            "setupMaterialCompatibleWithKLLPS": true,
            "KLLPSPartDecImplemented": false,
            "KLLPSC1C4Certified": false,
        },
        "statusLabels": [
            "M8PassiveSetupGenerated",
            "FullRosterSetupMaterialGenerated",
            "CollectivePublicKeyRootBound",
            "ThresholdVerificationMaterialBound",
            "EvaluationKeyRootBound",
            "KllpsCompatibleSetupMaterial",
            "AppendixBSetupInputReady",
            "FinalAppendixBPendingQTarget"
        ],
        "nonClaims": [
            "ActiveMaliciousSetupProofMissing",
            "MaliciousEvaluationKeyProofMissing",
            "KLLPSPartDecNotImplemented",
            "KLLPSC1C4NotCertified",
            "FinalAppendixBPendingQTarget",
            "FinalEvaluatorNoisePendingM10AppendixD",
            "StageXNotClosed",
            "StageCNotClosed",
            "StageANotClosed"
        ],
    });
    let setup_package_digest = derive_protocol_digest("BGVPassiveSetupPackageDigest", &package)?;
    package["setupPackageDigest"] = Value::String(setup_package_digest);

    Ok(package)
}

fn read_passive_setup_input(request: &Value) -> CanonicalResult<PassiveSetupInput> {
    let ceremony_id = read_non_empty_string(request, "ceremonyId")?.to_string();
    let manifest_digest = read_digest_field(request, "manifestDigest")?.to_string();
    let roster_digest = read_digest_field(request, "rosterDigest")?.to_string();
    let threshold_profile_digest =
        read_digest_field(request, "thresholdProfileDigest")?.to_string();
    let setup_seed_provided = request.get("setupSeed").is_some();
    let setup_seed = request
        .get("setupSeed")
        .and_then(Value::as_str)
        .unwrap_or("sealed-lattice-m8-passive-development-seed-v1");
    if setup_seed.trim().is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupSeed must not be empty when supplied",
        ));
    }
    let setup_seed_digest = hash512_hex(
        "sealed-lattice-bgv-rns/passive-setup-seed-digest-v1",
        &[
            ceremony_id.as_bytes(),
            manifest_digest.as_bytes(),
            roster_digest.as_bytes(),
            threshold_profile_digest.as_bytes(),
            setup_seed.as_bytes(),
        ],
    );
    let participants = read_setup_participants(request)?;
    if participants.len() < MINIMUM_PASSIVE_SETUP_ROSTER_SIZE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M8 passive setup requires at least three frozen roster participants",
        ));
    }
    if participants.len() > MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M8 passive setup supports at most fifty frozen roster participants",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    for participant in &participants {
        if !identities.insert(participant.trustee_identity.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M8 passive setup participant identities must be unique",
            ));
        }
        if participant.roster_position >= participants.len()
            || !roster_positions.insert(participant.roster_position)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M8 passive setup roster positions must be unique and cover the frozen roster",
            ));
        }
    }

    Ok(PassiveSetupInput {
        ceremony_id,
        manifest_digest,
        roster_digest,
        threshold_profile_digest,
        setup_seed_provided,
        setup_seed_digest,
        participants,
    })
}

fn is_nfc_normalized(value: &str) -> bool {
    value.nfc().eq(value.chars())
}

fn ensure_nfc_identity(value: &str, field_name: &str) -> CanonicalResult<()> {
    if is_nfc_normalized(value) {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be NFC-normalized"),
        ))
    }
}

fn read_setup_participants(request: &Value) -> CanonicalResult<Vec<SetupParticipant>> {
    let participants = request
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participants must be an array",
            )
        })?;
    participants
        .iter()
        .enumerate()
        .map(|(index, value)| match value {
            Value::String(identity) => {
                if identity.trim().is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "participant identity must not be empty",
                    ));
                }
                ensure_nfc_identity(identity, "participant identity")?;
                Ok(SetupParticipant {
                    trustee_identity: identity.clone(),
                    roster_position: index,
                    board_position: index,
                    recovery_epoch: 0,
                    device_epoch: 0,
                })
            }
            Value::Object(_) => {
                reject_forbidden_setup_fields(value)?;
                let trustee_identity = read_non_empty_string(value, "trusteeIdentity")?.to_string();
                ensure_nfc_identity(&trustee_identity, "participant trusteeIdentity")?;
                Ok(SetupParticipant {
                    trustee_identity,
                    roster_position: read_optional_usize(value, "rosterPosition")?.unwrap_or(index),
                    board_position: read_optional_usize(value, "boardPosition")?.unwrap_or(index),
                    recovery_epoch: read_optional_u64(value, "recoveryEpoch")?.unwrap_or(0),
                    device_epoch: read_optional_u64(value, "deviceEpoch")?.unwrap_or(0),
                })
            }
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participants entries must be trustee identity strings or participant objects",
            )),
        })
        .collect()
}

fn participant_setup_material(
    input: &PassiveSetupInput,
    participant: &SetupParticipant,
    profile_digest: &str,
    backend_profile_digest: &str,
    public_common_random_polynomial_root: &str,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<ParticipantSetupMaterial> {
    let local_secret_share_commitment_digest = hash512_hex(
        "sealed-lattice-bgv-rns/local-secret-share-commitment-v1",
        &[
            input.setup_seed_digest.as_bytes(),
            participant.trustee_identity.as_bytes(),
            participant.roster_position.to_string().as_bytes(),
            profile_digest.as_bytes(),
        ],
    );
    let local_error_commitment_digest = hash512_hex(
        "sealed-lattice-bgv-rns/local-error-commitment-v1",
        &[
            input.setup_seed_digest.as_bytes(),
            participant.trustee_identity.as_bytes(),
            participant.roster_position.to_string().as_bytes(),
            public_common_random_polynomial_root.as_bytes(),
        ],
    );
    let public_key_share_record = json!({
        "objectType": "BgvPublicKeyShare",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "localSecretShareCommitmentDigest": local_secret_share_commitment_digest,
        "localErrorCommitmentDigest": local_error_commitment_digest,
        "publicShareConstruction": "b_i=-a*s_i+e_i-over-selected-BGV-RNS-profile",
        "rawSecretShareExported": false,
        "centralizedSecretReconstruction": false,
        "sampledLocalSecretCoefficients": sample_small_distribution(
            &input.setup_seed_digest,
            &participant.trustee_identity,
            "local-secret-share",
            -1,
            1,
        ),
        "sampledLocalErrorCoefficients": sample_centered_binomial_eta2(
            &input.setup_seed_digest,
            &participant.trustee_identity,
            "local-error",
        ),
    });
    let public_key_share_root =
        derive_protocol_digest("PublicKeyShareRoot", &public_key_share_record)?;
    let trustee_threshold_verification_key = json!({
        "objectType": "TrusteeThresholdVerificationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
        "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "publicKeyShareRoot": public_key_share_root,
        "verificationStatement": "passive-transcript-identity-profile-and-share-domain-binding",
        "maliciousDkgProofIncluded": false,
    });
    let trustee_threshold_verification_key_digest = derive_protocol_digest(
        "TrusteeThresholdVerificationKeyDigest",
        &trustee_threshold_verification_key,
    )?;
    let participant_record_without_digest = json!({
        "objectType": "ParticipantBgvSetupRecord",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "thresholdProfileDigest": input.threshold_profile_digest,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "boardPosition": participant.board_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicKeyShareRoot": public_key_share_root,
        "trusteeThresholdVerificationKeyDigest": trustee_threshold_verification_key_digest,
        "localSecretShareCommitmentDigest": local_secret_share_commitment_digest,
        "localErrorCommitmentDigest": local_error_commitment_digest,
        "rawSecretShareExported": false,
        "centralizedSecretReconstruction": false,
        "sampleDisclosure": "commitment-digests-and-roots-only",
        "sampledLocalSecretCoefficientsIncluded": false,
        "sampledLocalErrorCoefficientsIncluded": false,
        "setupProofProfileForM19": "passive-record-only-active-proof-pending-M19",
    });
    let participant_setup_record_digest = derive_protocol_digest(
        "ParticipantBgvSetupRecordDigest",
        &participant_record_without_digest,
    )?;
    let mut participant_record = participant_record_without_digest;
    participant_record["participantSetupRecordDigest"] =
        Value::String(participant_setup_record_digest.clone());

    Ok(ParticipantSetupMaterial {
        participant_record,
        public_key_share_root,
        participant_setup_record_digest,
        trustee_threshold_verification_key_digest,
    })
}

fn collective_public_key(
    input: &PassiveSetupInput,
    profile_digest: &str,
    backend_profile_digest: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
) -> CanonicalResult<Value> {
    let record_without_roots = json!({
        "objectType": "BgvCollectivePublicKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "publicKeyShareRoots": public_key_share_roots,
        "aggregationRule": "coefficient-wise-public-key-share-sum-with-shared-crp",
        "participantCount": public_key_share_roots.len(),
        "centralizedSecretReconstruction": false,
        "rawSecretShareExported": false,
    });
    let collective_public_key_root =
        derive_protocol_digest("CollectivePublicKeyRoot", &record_without_roots)?;
    let bgv_public_key_root = derive_protocol_digest(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "profileDigest": profile_digest,
            "backendProfileDigest": backend_profile_digest,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;

    Ok(json!({
        "record": record_without_roots,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "statusLabels": [
            "CollectivePublicKeyShareAggregationBound",
            "NoTrustedDealerSecretReconstruction"
        ],
    }))
}

fn threshold_verification_material(
    input: &PassiveSetupInput,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
    participant_setup_record_digests: &[String],
    trustee_threshold_verification_key_digests: &[String],
) -> CanonicalResult<Value> {
    let participant_points = input
        .participants
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity.clone(),
                "rosterPosition": participant.roster_position,
                "interpolationPoint": participant.roster_position + 1,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    let verification_key_set = json!({
        "objectType": "ThresholdShareVerificationKeySet",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
        "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "participantSetupRecordDigests": participant_setup_record_digests,
        "trusteeThresholdVerificationKeyDigests": trustee_threshold_verification_key_digests,
        "participantInterpolationUniverse": participant_points,
        "secretShareDomain": "BGV-RNS-secret-share-polynomial-over-selected-Q-data",
        "passiveSetupVerificationScope": [
            "transcript-binding",
            "identity-binding",
            "roster-binding",
            "profile-binding",
            "recovery-device-epoch-binding"
        ],
        "maliciousDkgProofIncluded": false,
    });
    let threshold_share_verification_key_root =
        derive_protocol_digest("ThresholdShareVerificationKeyRoot", &verification_key_set)?;
    let threshold_share_verification_key_digest = derive_protocol_digest(
        "ThresholdShareVerificationKeyDigest",
        &json!({
            "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        }),
    )?;

    Ok(json!({
        "verificationKeySet": verification_key_set,
        "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
        "thresholdShareVerificationKeyDigest": threshold_share_verification_key_digest,
        "trusteeThresholdVerificationKeyDigests": trustee_threshold_verification_key_digests,
        "statusLabels": [
            "ThresholdVerificationMaterialBound",
            "PassiveSetupVerificationScopeOnly",
            "KllpsCompatibleVerificationRootsBound"
        ],
    }))
}

fn evaluation_keys(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
    key_switch_decomposition_digest: &str,
) -> CanonicalResult<Value> {
    let rot_set = provisional_rotation_set()?;
    let rot_set_digest = derive_protocol_digest("RotSetDigest", &rot_set)?;
    let collective_public_key_root =
        string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?;
    let relinearization_arithmetic_fixture = development_key_arithmetic_fixture(
        input,
        DEVELOPMENT_RELINEARIZATION_ARITHMETIC_FIXTURE_ID,
        "relinearization-key-fixture",
        key_switch_decomposition_digest,
    )?;
    let key_switch_arithmetic_fixture = development_key_arithmetic_fixture(
        input,
        DEVELOPMENT_KEY_SWITCH_ARITHMETIC_FIXTURE_ID,
        "key-switch-fixture",
        key_switch_decomposition_digest,
    )?;
    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 2,
        "arithmeticFixtureDigest": relinearization_arithmetic_fixture["fixtureDigest"],
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let relinearization_key_root =
        derive_protocol_digest("RelinearizationKeyRoot", &relinearization_key_record)?;
    let rotation_key_records = rot_set["rotations"]
        .as_array()
        .expect("rotation set uses array")
        .iter()
        .map(|rotation| {
            let record = json!({
                "objectType": "BgvRotationKey",
                "objectVersion": 1,
                "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
                "ceremonyId": input.ceremony_id,
                "rosterDigest": input.roster_digest,
                "collectivePublicKeyRoot": collective_public_key_root,
                "rotSetDigest": rot_set_digest,
                "rotation": rotation,
                "keySwitchDecompositionDigest": key_switch_decomposition_digest,
                "publicBasisId": BgvBasisKind::Extended.basis_id(),
                "publicRlweSampleCount": 1,
                "maliciousEvaluationKeyProofIncluded": false,
            });
            let root = derive_protocol_digest("RotationKeyRoot", &record)?;
            Ok(json!({
                "rotation": rotation,
                "rotationKeyRoot": root,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 1,
        "arithmeticFixtureDigest": key_switch_arithmetic_fixture["fixtureDigest"],
        "genericKeySwitchApiExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let key_switch_key_root = derive_protocol_digest("KeySwitchKeyRoot", &key_switch_key_record)?;
    let evaluation_key_record = json!({
        "objectType": "BgvEvaluationKeySet",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "rotSetDigest": rot_set_digest,
        "relinearizationKeyRoot": relinearization_key_root,
        "relinearizationArithmeticFixtureDigest": relinearization_arithmetic_fixture["fixtureDigest"],
        "rotationKeyRoots": rotation_key_records,
        "keySwitchKeyRoot": key_switch_key_root,
        "keySwitchArithmeticFixtureDigest": key_switch_arithmetic_fixture["fixtureDigest"],
        "generatedFor": "provisionalRotSet",
        "finalRotSetClosure": "M10-AppendixD",
        "regenerateIfRotSetChanges": true,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let evaluation_key_root = derive_protocol_digest("EvalKeyRoot", &evaluation_key_record)?;

    Ok(json!({
        "record": evaluation_key_record,
        "rotSet": rot_set,
        "rotSetDigest": rot_set_digest,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "relinearizationKeyRoot": relinearization_key_root,
        "keySwitchKeyRoot": key_switch_key_root,
        "relinearizationArithmeticFixture": relinearization_arithmetic_fixture,
        "keySwitchArithmeticFixture": key_switch_arithmetic_fixture,
        "rotationKeyRoots": rotation_key_records,
        "evaluationKeyRoot": evaluation_key_root,
        "statusLabels": [
            "RelinearizationKeyMaterialBound",
            "RotationKeyMaterialBound",
            "KeySwitchMaterialBound",
            "ProvisionalRotSetBound"
        ],
    }))
}

fn development_key_arithmetic_fixture(
    input: &PassiveSetupInput,
    fixture_id: &str,
    fixture_scope: &str,
    key_switch_decomposition_digest: &str,
) -> CanonicalResult<Value> {
    let modulus = DATA_PRIMES[0];
    let digit_base = 1_u64 << 23;
    let samples = sample_positions()
        .into_iter()
        .map(|position| {
            let source_coefficient =
                sample_residue(&input.setup_seed_digest, fixture_scope, position, modulus);
            let first_digit = source_coefficient % digit_base;
            let second_digit = (source_coefficient / digit_base) % digit_base;
            let third_digit = (source_coefficient / digit_base / digit_base) % digit_base;
            let recomposed =
                (first_digit + digit_base * second_digit + digit_base * digit_base * third_digit)
                    % modulus;
            let multiplier = sample_residue(
                &input.setup_seed_digest,
                &format!("{fixture_scope}-m7-multiplier"),
                position,
                modulus,
            );
            Ok(json!({
                "position": position,
                "modulus": modulus,
                "sourceCoefficient": source_coefficient,
                "decompositionDigits": [first_digit, second_digit, third_digit],
                "recomposedCoefficient": recomposed,
                "recompositionMatches": recomposed == source_coefficient,
                "m7MulCheck": mul_mod(source_coefficient, multiplier, modulus)?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let fixture_record = json!({
        "objectType": "BgvDevelopmentKeyArithmeticFixture",
        "objectVersion": 1,
        "fixtureId": fixture_id,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "basisId": BgvBasisKind::Extended.basis_id(),
        "digitBaseBits": 23,
        "digitCountPerPrime": 3,
        "sampleModulus": modulus,
        "sampledCoefficientChecks": samples,
        "m7ArithmeticStatus": "sampled-decompose-recompose-and-modmul-passed",
        "protocolEvidence": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let fixture_digest = development_fixture_digest(&fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureDigest": fixture_digest,
    }))
}

fn development_encryption_fixture(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
) -> CanonicalResult<Value> {
    let message_slots = vec![1_u64, 2, 3, 5, 8, 13, 21, 34];
    let message = encode_batch_plaintext_slots(&message_slots, 0)?;
    let modulus = DATA_PRIMES[0];
    let public_key_coefficients = dense_public_residues(
        &input.setup_seed_digest,
        "development-collective-public-key-coefficients",
        modulus,
    );
    let public_sample_coefficients = dense_public_residues(
        &input.setup_seed_digest,
        "development-encryption-public-sample",
        modulus,
    );
    let encryption_randomness_coefficients = dense_small_coefficients(
        &input.setup_seed_digest,
        DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "encryption-randomness",
        -1,
        1,
    );
    let encryption_error_zero_coefficients = dense_centered_binomial_coefficients(
        &input.setup_seed_digest,
        DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "encryption-error-zero",
    );
    let encryption_error_one_coefficients = dense_centered_binomial_coefficients(
        &input.setup_seed_digest,
        DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "encryption-error-one",
    );
    let randomness_residues = encryption_randomness_coefficients
        .iter()
        .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let error_zero_residues = encryption_error_zero_coefficients
        .iter()
        .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let error_one_residues = encryption_error_one_coefficients
        .iter()
        .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let public_key_product =
        negacyclic_product_mod(&public_key_coefficients, &randomness_residues, modulus)?;
    let public_sample_product =
        negacyclic_product_mod(&public_sample_coefficients, &randomness_residues, modulus)?;
    let message_residues = message
        .polynomial
        .residues_by_modulus
        .first()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "development encryption message has no data-basis residues",
            )
        })?;
    let ciphertext_component_zero = public_key_product
        .iter()
        .zip(error_zero_residues.iter())
        .zip(message_residues.iter())
        .map(|((product, error), message_coefficient)| {
            add_mod(
                add_mod(*product, *error, modulus)?,
                *message_coefficient,
                modulus,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let ciphertext_component_one = public_sample_product
        .iter()
        .zip(error_one_residues.iter())
        .map(|(product, error)| add_mod(*product, *error, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let layout_digest = layout_digest()?;
    let component_zero = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        0,
        layout_digest.clone(),
        vec![ciphertext_component_zero],
    )?;
    let component_one = RnsPolynomial::coefficient_domain(
        BgvBasisKind::Data,
        0,
        layout_digest,
        vec![ciphertext_component_one],
    )?;
    let canonical_bytes =
        serialize_bgv_object(BgvObjectKind::Ciphertext, &[component_zero, component_one])?;
    let plaintext_bytes = serialize_bgv_object(
        BgvObjectKind::Plaintext,
        std::slice::from_ref(&message.polynomial),
    )?;
    let public_key_material_root = derive_protocol_digest(
        "BGVPublicKeyRoot",
        &json!({
            "fixtureId": DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
            "collectivePublicKeyRoot": string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?,
            "bgvPublicKeyRoot": string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?,
            "sampleModulus": modulus,
            "sampledPublicKeyCoefficients": sample_values(&public_key_coefficients),
            "sampledPublicEncryptionCoefficients": sample_values(&public_sample_coefficients),
        }),
    )?;
    let randomness_root = hash512_hex(
        "sealed-lattice-bgv-rns/development-encryption-randomness-root-v1",
        &[canonical_json(&json!({
            "fixtureId": DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
            "sampledRandomnessCoefficients": sample_signed_values(&encryption_randomness_coefficients),
            "sampledErrorZeroCoefficients": sample_signed_values(&encryption_error_zero_coefficients),
            "sampledErrorOneCoefficients": sample_signed_values(&encryption_error_one_coefficients),
        }))?.as_bytes()],
    );
    let fixture_record = json!({
        "objectType": "BgvDevelopmentEncryptionFixture",
        "objectVersion": 1,
        "fixtureId": DEVELOPMENT_ENCRYPTION_FIXTURE_ID,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?,
        "bgvPublicKeyRoot": string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?,
        "publicKeyMaterialRoot": public_key_material_root,
        "randomnessRoot": randomness_root,
        "plaintextRoot": plaintext_root(&plaintext_bytes),
        "ciphertextRoot": ciphertext_root(&canonical_bytes),
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "canonicalByteLength": canonical_bytes.len(),
        "messageSlotSample": message_slots,
        "sampleModulus": modulus,
        "encryptionFormula": "c0=pk*u+e0+m,c1=a*u+e1-over-selected-level-zero-Q-data",
        "sampledPublicRelationChecks": sample_encryption_relation_checks(
            message_residues,
            &public_key_product,
            &public_sample_product,
            &error_zero_residues,
            &error_one_residues,
        )?,
        "fixtureScope": "development-collective-public-key-encryption-fixture",
        "m9BridgeEncryptionClaim": false,
        "m10EvaluatorClaim": false,
    });
    let fixture_digest =
        derive_protocol_digest("BGVDevelopmentEncryptionFixtureDigest", &fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureDigest": fixture_digest,
        "statusLabels": [
            "DevelopmentEncryptionFixtureBound",
            "CollectivePublicKeyRootBound",
            "NotBridgeProofEvidence",
            "NotEvaluatorClosureEvidence"
        ],
    }))
}

#[allow(clippy::too_many_arguments)]
fn setup_certificates(
    input: &PassiveSetupInput,
    collective_secret_distribution_certificate: &Value,
    collective_secret_distribution_certificate_digest: &str,
    error_distribution_certificate: &Value,
    error_distribution_certificate_digest: &str,
    key_switch_decomposition: &Value,
    key_switch_decomposition_digest: &str,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
    evaluation_keys: &Value,
    development_encryption_fixture: &Value,
) -> CanonicalResult<Value> {
    let q_data_bits = DATA_PRIMES.len() * 47;
    let qp_public_bits = (DATA_PRIMES.len() + 1) * 47;
    let rotation_key_count = evaluation_keys["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots use array")
        .len();
    let public_samples = public_rlwe_samples_by_basis(input.participants.len(), rotation_key_count);
    let evaluation_key_size_certificate = evaluation_key_size_certificate(rotation_key_count);
    let evaluation_key_size_profile_digest = derive_protocol_digest(
        "EvaluationKeySizeProfileDigest",
        &evaluation_key_size_certificate,
    )?;
    let evaluation_key_streaming_fixture =
        evaluation_key_streaming_fixture(evaluation_keys, &evaluation_key_size_certificate)?;
    let setup_parameter_certificate = json!({
        "objectType": "BgvSetupParameterCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "profileDigest": profile_digest()?,
        "backendProfileDigest": backend_profile_digest()?,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "qDataBits": q_data_bits,
        "qpPublicBits": qp_public_bits,
        "qTargetBits": null,
        "publicEvaluationKeyBasis": BgvBasisKind::Extended.basis_id(),
        "largestExposedModulusBitsWithoutQTarget": qp_public_bits,
        "largestExposedBasisClassWithoutQTarget": "QP_public",
        "largestExposedModulusBits": null,
        "finalSecurityStatus": "pendingQTarget",
        "collectiveSecretDistributionCertificateDigest": collective_secret_distribution_certificate_digest,
        "errorDistributionCertificateDigest": error_distribution_certificate_digest,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "evaluationKeySizeProfileDigest": evaluation_key_size_profile_digest,
        "evaluationKeyStreamingFixtureDigest": evaluation_key_streaming_fixture["fixtureDigest"],
        "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
        "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        "securityEstimatorInputDigest": security_estimator_input_digest()?,
        "HEStdPostQuantumRow": {
            "status": "setup-input-recorded-final-row-pending-Q-target",
            "largestKnownExposedModulusBits": qp_public_bits
        },
        "CurrentEstimatorRow": {
            "status": "setup-input-recorded-run-pending-final-estimator-policy",
            "largestKnownExposedModulusBits": qp_public_bits,
            "secretModel": collective_secret_distribution_certificate["resultingGlobalSecretDistribution"]["distributionKind"],
            "errorModel": error_distribution_certificate["errorDistribution"]["distributionKind"]
        }
    });
    let setup_parameter_certificate_digest = derive_protocol_digest(
        "BGVSetupParameterCertificateDigest",
        &setup_parameter_certificate,
    )?;

    Ok(json!({
        "collectiveSecretDistributionCertificate": collective_secret_distribution_certificate,
        "collectiveSecretDistributionCertificateDigest": collective_secret_distribution_certificate_digest,
        "errorDistributionCertificate": error_distribution_certificate,
        "errorDistributionCertificateDigest": error_distribution_certificate_digest,
        "keySwitchDecomposition": key_switch_decomposition,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicRlweSamplesByBasis": public_samples,
        "setupParameterCertificate": setup_parameter_certificate,
        "setupParameterCertificateDigest": setup_parameter_certificate_digest,
        "evaluationKeySizeCertificate": evaluation_key_size_certificate,
        "evaluationKeySizeProfileDigest": evaluation_key_size_profile_digest,
        "evaluationKeyStreamingFixture": evaluation_key_streaming_fixture,
        "developmentEncryptionFixtureDigest": development_encryption_fixture["fixtureDigest"],
        "statusLabels": [
            "ActualSecretDistributionRecorded",
            "ActualErrorDistributionRecorded",
            "PublicRlweSampleCountsRecorded",
            "LargestExposedModulusWithoutQTargetRecorded",
            "EvaluationKeySizeCertificateRecorded",
            "FinalSecurityPendingQTarget"
        ],
    }))
}

fn collective_secret_distribution_certificate(participant_count: usize) -> CanonicalResult<Value> {
    let mut weights = vec![1_u128];
    for _ in 0..participant_count {
        let mut next = vec![0_u128; weights.len() + 2];
        for (index, weight) in weights.iter().enumerate() {
            next[index] += weight;
            next[index + 1] += weight;
            next[index + 2] += weight;
        }
        weights = next;
    }
    let support_offset = i64::try_from(participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "participant count does not fit signed distribution support",
        )
    })?;
    let support = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| {
            json!({
                "secretCoefficientSum": i64::try_from(index).expect("support index fits i64") - support_offset,
                "weight": weight.to_string(),
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "objectType": "CollectiveSecretDistributionCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "localShareSampler": {
            "samplerId": "hash-derived-rejection-sampled-balanced-ternary-local-share-v2",
            "support": [-1, 0, 1],
            "probabilityNumeratorBySupport": [1, 1, 1],
            "probabilityDenominator": 3,
            "candidateBits": 64,
            "rejectionRule": "reject-candidates-outside-largest-multiple-of-support-width",
            "rawShareExported": false
        },
        "localShareDistribution": "balanced-ternary-local-share",
        "aggregationRule": "coefficient-wise-sum-of-all-full-roster-local-shares",
        "participantCount": participant_count,
        "resultingGlobalSecretDistribution": {
            "distributionKind": "sum-of-full-roster-balanced-ternary-local-shares",
            "support": support,
            "totalWeightExpression": format!("3^{participant_count}"),
            "isPlainDenseTernary": participant_count == 1,
        },
        "estimatorSecretModel": "full-roster-balanced-ternary-share-sum-convolution",
        "noiseModelSecretModel": "full-roster-balanced-ternary-share-sum-convolution",
        "sparseSecretFlag": false,
        "fixedHammingSecretFlag": false,
        "rejectionReasonIfUncertified": null,
    }))
}

fn error_distribution_certificate() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "ErrorDistributionCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "errorSampler": {
            "samplerId": "centered-binomial-eta2-development-v1",
            "support": [-2, -1, 0, 1, 2],
            "weights": ["1", "4", "6", "4", "1"],
            "totalWeight": "16"
        },
        "errorDistribution": {
            "distributionKind": "centered-binomial-eta2",
            "support": [-2, -1, 0, 1, 2]
        },
        "encryptionRandomnessDistribution": {
            "distributionKind": "balanced-ternary-local-randomness",
            "support": [-1, 0, 1]
        },
        "keySwitchNoiseDistribution": {
            "distributionKind": "centered-binomial-eta2",
            "support": [-2, -1, 0, 1, 2]
        },
        "crpPublicSampleDistribution": {
            "distributionKind": "hash-to-modulus-rejection-sampled-uniform-public-sample",
            "samplerId": "hash-derived-rejection-sampled-public-residue-v2",
            "candidateBits": 64,
            "basisId": BgvBasisKind::Data.basis_id()
        },
        "rejectionSamplingRules": [
            "small-distribution-candidates-outside-largest-multiple-of-support-width-are-rehashed",
            "public-residue-candidates-outside-largest-multiple-of-modulus-are-rehashed"
        ],
        "uncertifiedSmallSecretRejected": true,
    }))
}

fn key_switch_decomposition_profile() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvKeySwitchDecompositionProfile",
        "objectVersion": 1,
        "profileId": KEY_SWITCH_DECOMPOSITION_PROFILE_ID,
        "basisId": BgvBasisKind::Extended.basis_id(),
        "digitBaseBits": 23,
        "digitCountPerPrime": 3,
        "decompositionStatus": "provisional-M8-for-M10-schedule",
        "genericKeySwitchApiExported": false,
    }))
}

fn threshold_decryption_profile(profile_digest: &str) -> CanonicalResult<Value> {
    Ok(json!({
        "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "bgvProfileDigest": profile_digest,
        "secretShareDomain": "BGV-RNS-secret-share-polynomial-over-selected-Q-data",
        "asyncLagrangeTargetDirection": true,
        "partDecImplemented": false,
        "finDecImplemented": false,
        "c1ThroughC4Certified": false,
        "qTargetKnown": false,
    }))
}

fn m8_evaluator_context_bindings() -> CanonicalResult<Value> {
    let bridge_record = json!({
        "profileId": "EncryptedAggregateBridge-v1",
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "bgvProfileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "inputLayoutDigest": layout_digest()?,
        "aggregateInputEncodingProfileDigest": aggregate_input_encoding_profile_digest()?,
        "bridgeEvidenceRequiredBeforeClaimUse": true,
        "m8ProvidesSetupBindingOnly": true,
    });
    let target_basis_record = json!({
        "objectType": "EncryptedAggregateTargetBasisData",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "sourceBridgeProfileId": "EncryptedAggregateBridge-v1",
        "basisId": BgvBasisKind::Data.basis_id(),
        "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest()?,
        "layoutDigest": layout_digest()?,
        "topKEvaluatorInputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "finalizedBy": "M9-M10",
    });
    let reconstruction_record = json!({
        "objectType": "EncryptedAggregateReconstructionBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "bridgeDigest": derive_protocol_digest("EncryptedAggregateBridgeDigest", &bridge_record)?,
        "targetBasisDataRoot": derive_protocol_digest(
            "EncryptedAggregateTargetBasisDataRoot",
            &target_basis_record,
        )?,
        "layoutDigest": layout_digest()?,
        "reconstructionClaimPendingM9": true,
    });
    let score_bit_derivation_record = json!({
        "objectType": "ScoreBitDerivationCircuitBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "inputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "encodedAggregateLayoutDigest": encoded_aggregate_layout_digest()?,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
        "circuitClosurePendingM10": true,
    });
    let comparison_input_derivation_record = json!({
        "objectType": "ComparisonInputDerivationCircuitBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "selectedEvaluatorPath": "inactive-future-direct-comparison-input-profile",
        "inputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "encodedAggregateLayoutDigest": encoded_aggregate_layout_digest()?,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
        "circuitClosurePendingM10": false,
        "futureRdrRequired": true,
    });
    let encrypted_score_bit_input_record = json!({
        "objectType": "EncryptedScoreBitInputBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "scoreBitDerivationCircuitDigest": derive_protocol_digest(
            "ScoreBitDerivationCircuitDigest",
            &score_bit_derivation_record,
        )?,
        "ciphertextConventionDigest": canonical_ciphertext_convention_digest()?,
        "packingLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "claimUsePendingM10": true,
    });
    let encrypted_comparison_input_record = json!({
        "objectType": "EncryptedComparisonInputBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "selectedEvaluatorPath": "inactive-future-direct-comparison-input-profile",
        "comparisonInputDerivationCircuitDigest": derive_protocol_digest(
            "ComparisonInputDerivationCircuitDigest",
            &comparison_input_derivation_record,
        )?,
        "ciphertextConventionDigest": canonical_ciphertext_convention_digest()?,
        "packingLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "claimUsePendingM10": false,
        "futureRdrRequired": true,
    });
    let comparator_record = json!({
        "objectType": "BitSlicedComparatorBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "allowedEvaluatorOpsDigest": allowed_operation_registry_digest()?,
        "forbiddenScalarComparatorOperations": [
            "scalar-polynomial-degree-360-comparator",
            "uncertified-polynomial-comparator"
        ],
        "appendixDProfilePending": true,
    });
    let sparse_target_projection_record = json!({
        "objectType": "EncryptedSparseTargetProjectionBinding",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "targetLayoutDigest": derive_protocol_digest(
            "TargetLayoutDigest",
            &json!({
                "profileId": PROFILE_ID,
                "targetLayout": "M3-sparse-top-k-target-over-M7-canonical-ciphertext-convention",
                "finalizedBy": "M10-M13",
            }),
        )?,
        "topKEvaluatorInputLayoutDigest": top_k_evaluator_input_layout_digest()?,
        "claimUsePendingM10": true,
    });

    let encrypted_aggregate_bridge_digest =
        derive_protocol_digest("EncryptedAggregateBridgeDigest", &bridge_record)?;
    let encrypted_aggregate_target_basis_data_root = derive_protocol_digest(
        "EncryptedAggregateTargetBasisDataRoot",
        &target_basis_record,
    )?;
    let encrypted_aggregate_reconstruction_digest = derive_protocol_digest(
        "EncryptedAggregateReconstructionDigest",
        &reconstruction_record,
    )?;
    let score_bit_derivation_circuit_digest = derive_protocol_digest(
        "ScoreBitDerivationCircuitDigest",
        &score_bit_derivation_record,
    )?;
    let comparison_input_derivation_circuit_digest = derive_protocol_digest(
        "ComparisonInputDerivationCircuitDigest",
        &comparison_input_derivation_record,
    )?;
    let encrypted_score_bit_input_digest = derive_protocol_digest(
        "EncryptedScoreBitInputDigest",
        &encrypted_score_bit_input_record,
    )?;
    let encrypted_comparison_input_digest = derive_protocol_digest(
        "EncryptedComparisonInputDigest",
        &encrypted_comparison_input_record,
    )?;
    let bit_sliced_comparator_digest =
        derive_protocol_digest("BitSlicedComparatorDigest", &comparator_record)?;
    let encrypted_sparse_target_projection_digest = derive_protocol_digest(
        "EncryptedSparseTargetProjectionDigest",
        &sparse_target_projection_record,
    )?;
    let binding_record = json!({
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "encryptedAggregateBridgeDigest": encrypted_aggregate_bridge_digest,
        "encryptedAggregateTargetBasisDataRoot": encrypted_aggregate_target_basis_data_root,
        "encryptedAggregateReconstructionDigest": encrypted_aggregate_reconstruction_digest,
        "scoreBitDerivationCircuitDigest": score_bit_derivation_circuit_digest,
        "comparisonInputDerivationCircuitDigest": comparison_input_derivation_circuit_digest,
        "encryptedScoreBitInputDigest": encrypted_score_bit_input_digest,
        "encryptedComparisonInputDigest": encrypted_comparison_input_digest,
        "bitSlicedComparatorDigest": bit_sliced_comparator_digest,
        "encryptedSparseTargetProjectionDigest": encrypted_sparse_target_projection_digest,
        "selectedEvaluatorPath": "encrypted-aggregate-score-bit-derivation-v1",
        "directComparisonInputDerivationStatus": "inactive-future-profile",
        "claimUse": "binding-only-until-M9-M10-closure",
    });

    Ok(json!({
        "encryptedAggregateBridgeDigest": binding_record["encryptedAggregateBridgeDigest"],
        "encryptedAggregateTargetBasisDataRoot": binding_record["encryptedAggregateTargetBasisDataRoot"],
        "encryptedAggregateReconstructionDigest": binding_record["encryptedAggregateReconstructionDigest"],
        "scoreBitDerivationCircuitDigest": binding_record["scoreBitDerivationCircuitDigest"],
        "comparisonInputDerivationCircuitDigest": binding_record["comparisonInputDerivationCircuitDigest"],
        "encryptedScoreBitInputDigest": binding_record["encryptedScoreBitInputDigest"],
        "encryptedComparisonInputDigest": binding_record["encryptedComparisonInputDigest"],
        "bitSlicedComparatorDigest": binding_record["bitSlicedComparatorDigest"],
        "encryptedSparseTargetProjectionDigest": binding_record["encryptedSparseTargetProjectionDigest"],
        "m8EvaluatorContextBindingDigest": derive_protocol_digest(
            "EvaluationContextDigest",
            &binding_record,
        )?,
    }))
}

fn provisional_rotation_set() -> CanonicalResult<Value> {
    Ok(json!({
        "rotSetId": PROVISIONAL_ROT_SET_ID,
        "sourceRdr": "RDR-M10-Top-K-Circuit-And-Sparse-Target",
        "generatedFor": "provisionalRotSet",
        "finalizedBy": "M10-AppendixD",
        "regenerateM8KeysIfChanged": true,
        "rotations": [
            1, 2, 4, 8, 16, 32, 64, 128,
            256, 512, 1024, 2048, 4096, 8192,
            -1, -2, -4, -8, -16, -32, -64, -128,
            -256, -512, -1024, -2048, -4096, -8192
        ],
        "dependencies": [
            "encrypted-aggregate-reconstruction",
            "encrypted-aggregate-score-bit-derivation",
            "bit-sliced-GT-EQ",
            "rank-accumulation",
            "encrypted-sparse-target-projection",
            "target-decryption-interface-checks"
        ],
        "requiredRotationGroups": [
            {
                "purpose": "bit-sliced-projection",
                "rotations": [1, 2, 4, 8, 16, -1, -2, -4, -8, -16]
            },
            {
                "purpose": "encrypted-aggregate-score-bit-derivation",
                "rotations": [32, 64, 128, -32, -64, -128]
            },
            {
                "purpose": "rank-accumulation",
                "rotations": [256, 512, 1024, 2048, -256, -512, -1024, -2048]
            },
            {
                "purpose": "target-projection",
                "rotations": [4096, 8192, -4096, -8192]
            }
        ],
    }))
}

fn public_common_random_polynomial_root(input: &PassiveSetupInput) -> CanonicalResult<String> {
    derive_protocol_digest(
        "BGVPublicCommonRandomPolynomialRoot",
        &json!({
            "objectType": "BgvPublicCommonRandomPolynomial",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "ceremonyId": input.ceremony_id,
            "rosterDigest": input.roster_digest,
            "setupSeedDigest": input.setup_seed_digest,
            "basisId": BgvBasisKind::Data.basis_id(),
            "level": DATA_PRIMES.len() - 1,
            "coefficientCount": POLYNOMIAL_DEGREE,
            "sampledResidues": sample_public_residues(
                &input.setup_seed_digest,
                "public-common-random-polynomial",
                DATA_PRIMES[0],
            ),
        }),
    )
}

fn public_rlwe_samples_by_basis(participant_count: usize, rotation_key_count: usize) -> Value {
    json!({
        "QData": {
            "basisId": BgvBasisKind::Data.basis_id(),
            "modulusBits": DATA_PRIMES.len() * 47,
            "publicKeyShares": participant_count,
            "collectivePublicKey": 1,
            "developmentEncryptionFixtures": 1,
        },
        "QPPublic": {
            "basisId": BgvBasisKind::Extended.basis_id(),
            "modulusBits": (DATA_PRIMES.len() + 1) * 47,
            "relinearizationKeys": 2,
            "rotationKeys": rotation_key_count,
            "keySwitchKeys": 1,
        },
        "QTarget": {
            "modulusBits": null,
            "sampleCountStatus": "pendingUntilAppendixC"
        },
    })
}

fn evaluation_key_size_certificate(rotation_key_count: usize) -> Value {
    let residue_byte_count = 8_usize;
    let polynomial_byte_estimate_data = POLYNOMIAL_DEGREE * DATA_PRIMES.len() * residue_byte_count;
    let polynomial_byte_estimate_extended =
        POLYNOMIAL_DEGREE * (DATA_PRIMES.len() + 1) * residue_byte_count;
    let relinearization_key_bytes = 2 * 2 * polynomial_byte_estimate_extended;
    let rotation_key_bytes = rotation_key_count * 2 * polynomial_byte_estimate_extended;
    let key_switch_key_bytes = 2 * polynomial_byte_estimate_extended;
    let total_evaluation_key_bytes =
        relinearization_key_bytes + rotation_key_bytes + key_switch_key_bytes;

    json!({
        "objectType": "EvaluationKeySizeCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "dataBasisPolynomialByteEstimate": polynomial_byte_estimate_data,
        "extendedBasisPolynomialByteEstimate": polynomial_byte_estimate_extended,
        "relinearizationKeyByteEstimate": relinearization_key_bytes,
        "rotationKeyCount": rotation_key_count,
        "rotationKeyByteEstimate": rotation_key_bytes,
        "keySwitchKeyByteEstimate": key_switch_key_bytes,
        "totalEvaluationKeyByteEstimate": total_evaluation_key_bytes,
        "chunkingStrategy": {
            "chunkSizeBytes": 262144,
            "chunkRootRequired": true,
            "streamingVerificationRequired": true
        },
        "storagePressure": {
            "status": "large-public-evaluation-key-material",
            "mobileDownloadRequiresM16Measurement": true
        },
    })
}

fn evaluation_key_streaming_fixture(
    evaluation_keys: &Value,
    evaluation_key_size_certificate: &Value,
) -> CanonicalResult<Value> {
    let stream_record = json!({
        "objectType": "BgvEvaluationKeyCanonicalByteStream",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluationKeyRoot": evaluation_keys["evaluationKeyRoot"],
        "rotSetDigest": evaluation_keys["rotSetDigest"],
        "relinearizationKeyRoot": evaluation_keys["relinearizationKeyRoot"],
        "keySwitchKeyRoot": evaluation_keys["keySwitchKeyRoot"],
        "rotationKeyRoots": evaluation_keys["rotationKeyRoots"],
        "relinearizationArithmeticFixtureDigest": evaluation_keys["relinearizationArithmeticFixture"]["fixtureDigest"],
        "keySwitchArithmeticFixtureDigest": evaluation_keys["keySwitchArithmeticFixture"]["fixtureDigest"],
        "serializationPolicy": "sealed-lattice-canonical-json-evaluation-key-record-stream",
        "protocolEvidence": false,
    });
    let stream_bytes = canonical_json(&stream_record)?.into_bytes();
    let chunk_root_value = chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?;
    let total_evaluation_key_byte_estimate = usize_at_path(
        evaluation_key_size_certificate,
        &["totalEvaluationKeyByteEstimate"],
    )?;
    let storage_quota_refused =
        total_evaluation_key_byte_estimate > DEVELOPMENT_MOBILE_STORAGE_QUOTA_BYTES;
    let fixture_record = json!({
        "objectType": "BgvEvaluationKeyStreamingFixture",
        "objectVersion": 1,
        "fixtureId": EVALUATION_KEY_STREAMING_FIXTURE_ID,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "streamRecord": stream_record,
        "canonicalStreamByteLength": stream_bytes.len(),
        "chunkSizeBytes": EVALUATION_KEY_CHUNK_SIZE_BYTES,
        "chunkRoot": chunk_root_value,
        "chunkCount": stream_bytes.len().div_ceil(EVALUATION_KEY_CHUNK_SIZE_BYTES),
        "storageQuotaFixture": {
            "quotaBytes": DEVELOPMENT_MOBILE_STORAGE_QUOTA_BYTES,
            "totalEvaluationKeyByteEstimate": total_evaluation_key_byte_estimate,
            "accepted": !storage_quota_refused,
            "refusalReason": if storage_quota_refused {
                "evaluation-key-estimate-exceeds-development-mobile-storage-quota"
            } else {
                "within-development-mobile-storage-quota"
            }
        },
        "protocolEvidence": false,
    });
    let fixture_digest = development_fixture_digest(&fixture_record)?;

    Ok(json!({
        "fixture": fixture_record,
        "fixtureDigest": fixture_digest,
    }))
}
