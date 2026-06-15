use super::certificates::{
    passive_setup_evaluator_context_bindings, target_decryption_profile,
    target_threshold_decryptability_certificate_from_setup_package,
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
        &["profileBindings", "encryptedBallotAggregateLayoutHash"],
        &encrypted_ballot_aggregate_layout_hash()?,
        "encrypted ballot aggregate layout hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "ballotScoreEncodingProfileHash"],
        &ballot_score_encoding_profile_hash()?,
        "ballot score encoding profile hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "encryptedBallotLayoutHash"],
        &encrypted_ballot_layout_hash()?,
        "encrypted ballot layout hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "directBallotReservedSlotRuleHash"],
        &direct_ballot_reserved_slot_rule_hash()?,
        "direct ballot reserved slot rule hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "directBallotEncoderMatrixRoot"],
        &direct_ballot_encoder_matrix_root()?,
        "direct ballot encoder matrix root",
    )?;
    compare_hash_at_path(
        setup_package,
        &["profileBindings", "arithmeticCertificateHash"],
        &direct_ballot_arithmetic_certificate_hash()?,
        "direct ballot arithmetic certificate hash",
    )?;
    let expected_evaluator_bindings =
        passive_setup_evaluator_context_bindings(value_at_path(setup_package, &["setupInputs"])?)?;
    for (field_name, description) in [
        (
            "evaluatorBindingContextHash",
            "evaluator binding context hash",
        ),
        (
            "encryptedBallotAggregateLayoutHash",
            "encrypted ballot aggregate layout binding hash",
        ),
        (
            "directAggregateLayoutHash",
            "direct aggregate layout binding hash",
        ),
        (
            "comparisonInputDerivationCircuitHash",
            "comparison-input derivation circuit hash",
        ),
        (
            "encryptedComparisonInputHash",
            "encrypted comparison input hash",
        ),
        (
            "encryptedSparseTargetProjectionHash",
            "encrypted sparse target projection hash",
        ),
        ("targetLayoutHash", "target layout hash"),
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

    let target_decryption_profile_hash = derive_protocol_hash(
        "TargetDecryptionProfileHash",
        &target_decryption_profile(&profile_hash)?,
    )?;
    let target_decryption_profile_binding_hash = derive_protocol_hash(
        "TargetDecryptionProfileBindingHash",
        &json!({
            "profileId": TARGET_DECRYPTION_PROFILE_ID,
            "targetDecryptionProfileHash": target_decryption_profile_hash,
            "profileStatus": "target-decryption-profile-binding",
        }),
    )?;
    compare_string_at_path(
        setup_package,
        &["targetDecryptionStatus", "targetDecryptionProfileId"],
        TARGET_DECRYPTION_PROFILE_ID,
        "target decryption profile id",
    )?;
    compare_hash_at_path(
        setup_package,
        &["targetDecryptionStatus", "targetDecryptionProfileHash"],
        &target_decryption_profile_hash,
        "target decryption profile hash",
    )?;
    compare_hash_at_path(
        setup_package,
        &[
            "targetDecryptionStatus",
            "targetDecryptionProfileBindingHash",
        ],
        &target_decryption_profile_binding_hash,
        "target decryption profile binding hash",
    )?;

    let participant_bindings = validate_participant_setup_records(
        setup_package,
        &profile_hash,
        &backend_profile_hash,
        &target_decryption_profile_hash,
        &target_decryption_profile_binding_hash,
    )?;
    validate_threshold_verification_material(
        setup_package,
        &participant_bindings,
        &target_decryption_profile_hash,
        &target_decryption_profile_binding_hash,
    )?;
    validate_collective_public_key(
        setup_package,
        &participant_bindings,
        &profile_hash,
        &backend_profile_hash,
    )?;
    validate_setup_certificates(setup_package)?;
    validate_evaluation_keys(setup_package)?;

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
    if !bool_at_path(
        setup_package,
        &[
            "targetDecryptionStatus",
            "setupMaterialMatchesTargetDecryption",
        ],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must mark target decryption material matching",
        ));
    }
    if !bool_at_path(
        setup_package,
        &["targetDecryptionStatus", "targetPartDecImplemented"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must mark target decryption PartDec implemented",
        ));
    }
    if bool_at_path(
        setup_package,
        &["targetDecryptionStatus", "targetC1C4StatusAccepted"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must not claim target decryption C1-C4 certification",
        ));
    }
    if bool_at_path(
        setup_package,
        &[
            "externallySuppliedSetupMaterialBoundary",
            "transcriptAcceptsExternallySuppliedSecretReconstruction",
        ],
    )? || bool_at_path(
        setup_package,
        &[
            "externallySuppliedSetupMaterialBoundary",
            "rawSecretSharesExported",
        ],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must not claim externally supplied secret reconstruction or raw share export",
        ));
    }
    if string_at_path(
        setup_package,
        &[
            "certificates",
            "setupParameterCertificate",
            "finalSecurityStatus",
        ],
    )? != "acceptedForDirectEvaluatorReplayTargetPending"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "passive BGV setup package must accept direct evaluator replay HE security while keeping target modulus downstream",
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
