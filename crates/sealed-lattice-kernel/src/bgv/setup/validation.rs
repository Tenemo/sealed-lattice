use super::certificates::{m8_evaluator_context_bindings, threshold_decryption_profile};
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
    let profile_digest = profile_digest()?;
    let backend_profile_digest = backend_profile_digest()?;
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
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "profileDigest"],
        &profile_digest,
        "profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "backendProfileDigest"],
        &backend_profile_digest,
        "backend profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "canonicalCiphertextConventionDigest"],
        &canonical_ciphertext_convention_digest()?,
        "canonical ciphertext convention digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "batchEncoderDigest"],
        &batch_encoder_digest()?,
        "batch encoder digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "batchLayoutBindingDigest"],
        &batch_layout_binding_digest()?,
        "batch layout binding digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "allowedEvaluatorOpsDigest"],
        &allowed_operation_registry_digest()?,
        "allowed evaluator operation digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateInputLayoutDigest"],
        &layout_digest()?,
        "encrypted aggregate input layout digest",
    )?;
    let expected_evaluator_bindings =
        m8_evaluator_context_bindings(value_at_path(setup_package, &["setupInputs"])?)?;
    for (field_name, description) in [
        (
            "evaluatorBindingContextDigest",
            "evaluator binding context digest",
        ),
        (
            "encryptedAggregateBridgeDigest",
            "encrypted aggregate bridge digest",
        ),
        (
            "encryptedAggregateTargetBasisDataRoot",
            "encrypted aggregate target-basis data root",
        ),
        (
            "encryptedAggregateReconstructionDigest",
            "encrypted aggregate reconstruction digest",
        ),
        (
            "scoreBitDerivationCircuitDigest",
            "score-bit derivation circuit digest",
        ),
        (
            "comparisonInputDerivationCircuitDigest",
            "comparison-input derivation circuit digest",
        ),
        (
            "encryptedScoreBitInputDigest",
            "encrypted score-bit input digest",
        ),
        (
            "encryptedComparisonInputDigest",
            "encrypted comparison input digest",
        ),
        ("bitSlicedComparatorDigest", "bit-sliced comparator digest"),
        (
            "encryptedSparseTargetProjectionDigest",
            "encrypted sparse target projection digest",
        ),
        (
            "m8EvaluatorContextBindingDigest",
            "M8 evaluator context binding digest",
        ),
    ] {
        compare_digest_at_path(
            setup_package,
            &["profileBindings", field_name],
            string_at_path(&expected_evaluator_bindings, &[field_name])?,
            description,
        )?;
    }

    let threshold_decryption_profile_digest = derive_protocol_digest(
        "ThresholdDecryptionProfileDigest",
        &threshold_decryption_profile(&profile_digest)?,
    )?;
    let kllps_target_decryption_profile_digest = derive_protocol_digest(
        "KllpsTargetDecryptionProfileDigest",
        &json!({
            "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "profileStatus": "future-target-decryption-profile-binding",
        }),
    )?;
    compare_string_at_path(
        setup_package,
        &["kllpsCompatibility", "thresholdDecryptionProfileId"],
        THRESHOLD_DECRYPTION_PROFILE_ID,
        "threshold decryption profile id",
    )?;
    compare_digest_at_path(
        setup_package,
        &["kllpsCompatibility", "thresholdDecryptionProfileDigest"],
        &threshold_decryption_profile_digest,
        "threshold decryption profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["kllpsCompatibility", "kllpsTargetDecryptionProfileDigest"],
        &kllps_target_decryption_profile_digest,
        "KLLPS target decryption profile digest",
    )?;

    let participant_bindings = validate_participant_setup_records(
        setup_package,
        &profile_digest,
        &backend_profile_digest,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
    )?;
    validate_collective_public_key(
        setup_package,
        &participant_bindings,
        &profile_digest,
        &backend_profile_digest,
    )?;
    validate_threshold_verification_material(
        setup_package,
        &participant_bindings,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
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
            "setupPackage is not an M8 passive BGV setup package",
        ));
    }
    if !bool_at_path(
        setup_package,
        &["kllpsCompatibility", "setupMaterialCompatibleWithKLLPS"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must be marked KLLPS-compatible",
        ));
    }
    if bool_at_path(
        setup_package,
        &["kllpsCompatibility", "KLLPSPartDecImplemented"],
    )? || bool_at_path(setup_package, &["kllpsCompatibility", "KLLPSC1C4Certified"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must not claim KLLPS PartDec or C1-C4 certification",
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
            "M8 setup package must not claim centralized secret reconstruction or raw share export",
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
            "M8 setup package must keep final Appendix B security pending Q_target",
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
            "setupPackage participant count is outside the M8 passive setup roster bounds",
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
