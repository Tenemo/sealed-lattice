use super::input::ensure_nfc_identity;
use super::parameters::target_decryption_parameters;
use super::*;

use crate::hashing::derive_canonical_object_hash;

mod evaluation_key_checks;
mod key_material_checks;
mod participant_checks;

use evaluation_key_checks::validate_evaluation_keys;
use key_material_checks::{
    validate_collective_public_key, validate_threshold_verification_material,
};
use participant_checks::validate_participant_setup_records;

pub(super) fn validate_setup_package_internal_bindings(
    setup_package: &Value,
) -> CanonicalResult<()> {
    let bgv_parameters_hash = bgv_parameters_hash()?;
    compare_hash_at_path(
        setup_package,
        &["bgvParametersHash"],
        &bgv_parameters_hash,
        "BGV parameters hash",
    )?;
    let target_decryption_parameters_hash =
        derive_canonical_object_hash(&target_decryption_parameters(&bgv_parameters_hash)?)?;
    compare_hash_at_path(
        setup_package,
        &["targetDecryptionParametersHash"],
        &target_decryption_parameters_hash,
        "target decryption parameters hash",
    )?;
    let participant_bindings = validate_participant_setup_records(
        setup_package,
        &bgv_parameters_hash,
        &target_decryption_parameters_hash,
    )?;
    validate_threshold_verification_material(
        setup_package,
        &participant_bindings,
        &target_decryption_parameters_hash,
    )?;
    validate_collective_public_key(setup_package, &participant_bindings, &bgv_parameters_hash)?;
    validate_evaluation_keys(setup_package)?;

    Ok(())
}

pub(super) fn validate_setup_package_shape(setup_package: &Value) -> CanonicalResult<()> {
    if setup_package.get("objectType").and_then(Value::as_str) != Some("BgvPassiveSetupPackage") {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is not a passive BGV setup package",
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
    if !(MINIMUM_PASSIVE_SETUP_ROSTER_SIZE..=MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE)
        .contains(&participants.len())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage participant count is outside the passive BGV setup roster bounds",
        ));
    }
    Ok(())
}
