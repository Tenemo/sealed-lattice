use super::certificates::{
    passive_setup_evaluator_context_bindings,
    target_threshold_decryptability_certificate_from_setup_package, threshold_decryption_profile,
};
use super::input::ensure_nfc_identity;
use super::*;

mod certificate_checks;
mod evaluation_key_checks;
mod key_material_checks;
mod participant_checks;

use certificate_checks::validate_setup_certificates;
use evaluation_key_checks::validate_evaluation_keys;
use key_material_checks::{
    validate_collective_public_key, validate_threshold_verification_material,
};
use participant_checks::validate_participant_setup_records;

pub(super) fn validate_setup_package_internal_bindings(
    setup_package: &Value,
) -> CanonicalResult<()> {
    reject_forbidden_setup_package_secret_fields(setup_package)?;
    let profile_hash = profile_hash()?;
    let backend_profile_hash = backend_profile_hash()?;
    compare_string_at_path(
        setup_package,
        &["profileBindings", "profileId"],
        PROFILE_ID,
        "profile id",
    )?;
    compare_string_at_path(
        setup_package,
        &["profileBindings", "backendProfileId"],
        BACKEND_PROFILE_ID,
        "backend profile id",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "profileHash"],
        &profile_hash,
        "profile hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "backendProfileHash"],
        &backend_profile_hash,
        "backend profile hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "canonicalCiphertextConventionHash"],
        &canonical_ciphertext_convention_hash()?,
        "canonical ciphertext convention hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "batchEncoderHash"],
        &batch_encoder_hash()?,
        "batch encoder hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "batchLayoutBindingHash"],
        &batch_layout_binding_hash()?,
        "batch layout binding hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "allowedEvaluatorOpsHash"],
        &allowed_operation_registry_hash()?,
        "allowed evaluator operation hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateInputLayoutHash"],
        &layout_hash()?,
        "encrypted aggregate input layout hash",
    )?;
    let expected_evaluator_bindings =
        passive_setup_evaluator_context_bindings(value_at_path(setup_package, &["setupInputs"])?)?;
    for (field_name, description) in [
        (
            "evaluatorBindingContextHash",
            "evaluator binding context hash",
        ),
        (
            "encryptedAggregateBridgeHash",
            "encrypted aggregate bridge hash",
        ),
        (
            "encryptedAggregateTargetBasisRoot",
            "encrypted aggregate target-basis data root",
        ),
        (
            "encryptedAggregateReconstructionHash",
            "encrypted aggregate reconstruction hash",
        ),
        (
            "scoreBitDerivationCircuitHash",
            "score-bit derivation circuit hash",
        ),
        (
            "comparisonInputDerivationCircuitHash",
            "comparison-input derivation circuit hash",
        ),
        (
            "encryptedScoreBitInputHash",
            "encrypted score-bit input hash",
        ),
        (
            "encryptedComparisonInputHash",
            "encrypted comparison input hash",
        ),
        ("bitSlicedComparatorHash", "bit-sliced comparator hash"),
        (
            "encryptedSparseTargetProjectionHash",
            "encrypted sparse target projection hash",
        ),
        (
            "passiveSetupEvaluatorContextBindingHash",
            "passive setup evaluator context binding hash",
        ),
    ] {
        compare_hash_at_path(
            setup_package,
            &["profileBindings", field_name],
            string_at_path(&expected_evaluator_bindings, &[field_name])?,
            description,
        )?;
    }

    let threshold_decryption_profile_hash = derive_protocol_hash(
        "ThresholdDecryptionProfileHash",
        &threshold_decryption_profile(&profile_hash)?,
    )?;
    let kllps_target_decryption_profile_hash = derive_protocol_hash(
        "KllpsTargetDecryptionProfileHash",
        &json!({
            "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
            "profileStatus": "future-target-decryption-profile-binding",
        }),
    )?;
    compare_string_at_path(
        setup_package,
        &["kllpsStatus", "thresholdDecryptionProfileId"],
        THRESHOLD_DECRYPTION_PROFILE_ID,
        "threshold decryption profile id",
    )?;
    compare_hash_at_path(
        setup_package,
        &["kllpsStatus", "thresholdDecryptionProfileHash"],
        &threshold_decryption_profile_hash,
        "threshold decryption profile hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["kllpsStatus", "kllpsTargetDecryptionProfileHash"],
        &kllps_target_decryption_profile_hash,
        "KLLPS target decryption profile hash",
    )?;

    let participant_bindings = validate_participant_setup_records(
        setup_package,
        &profile_hash,
        &backend_profile_hash,
        &threshold_decryption_profile_hash,
        &kllps_target_decryption_profile_hash,
    )?;
    validate_collective_public_key(
        setup_package,
        &participant_bindings,
        &profile_hash,
        &backend_profile_hash,
    )?;
    validate_threshold_verification_material(
        setup_package,
        &participant_bindings,
        &threshold_decryption_profile_hash,
        &kllps_target_decryption_profile_hash,
    )?;
    validate_evaluation_keys(setup_package)?;
    validate_setup_certificates(setup_package)?;

    Ok(())
}

pub(super) fn validate_setup_package_shape(setup_package: &Value) -> CanonicalResult<()> {
    if setup_package.get("objectType").and_then(Value::as_str) != Some("BgvPassiveSetupPackage")
        || setup_package.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || setup_package.get("setupProfileId").and_then(Value::as_str)
            != Some(PASSIVE_SETUP_PROFILE_ID)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is not a passive BGV setup package",
        ));
    }
    if !bool_at_path(setup_package, &["kllpsStatus", "setupMaterialMatchesKLLPS"])? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must mark KLLPS material matching",
        ));
    }
    if bool_at_path(
        setup_package,
        &["kllpsStatus", "KLLPSPartDecStatusImplemented"],
    )? || bool_at_path(setup_package, &["kllpsStatus", "KLLPSC1C4StatusAccepted"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must not claim KLLPS PartDec or C1-C4 certification",
        ));
    }
    if bool_at_path(
        setup_package,
        &[
            "trustedDealerBoundary",
            "transcriptValidCentralizedSecretReconstruction",
        ],
    )? || bool_at_path(
        setup_package,
        &["trustedDealerBoundary", "rawSecretSharesExported"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must not claim centralized secret reconstruction or raw share export",
        ));
    }
    if string_at_path(
        setup_package,
        &[
            "certificates",
            "setupParameterCertificate",
            "finalSecurityStatus",
        ],
    )? != "pendingQTarget"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must keep final final setup security pending target modulus",
        ));
    }
    let participants = setup_package
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.participants must be an array",
            )
        })?;
    let participant_count = usize_at_path(setup_package, &["setupInputs", "participantCount"])?;
    if !(MINIMUM_PASSIVE_SETUP_ROSTER_SIZE..=MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE)
        .contains(&participant_count)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage participant count is outside the passive BGV setup roster bounds",
        ));
    }
    if participant_count != participants.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setupPackage participant count does not match participant records",
        ));
    }

    Ok(())
}
