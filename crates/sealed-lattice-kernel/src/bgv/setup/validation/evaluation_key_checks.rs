use super::*;
use crate::bgv::setup::key_material::expected_evaluation_key_material_binding;

pub(super) fn validate_evaluation_keys(setup_package: &Value) -> CanonicalResult<()> {
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let evaluation_key_record = value_at_path(evaluation_keys, &["record"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_hash = hash_at_path(evaluation_key_record, &["rotSetHash"])?;
    compare_derived_hash(rot_set, rot_set_hash, "rotation set hash")?;
    let collective_public_key_root =
        hash_at_path(evaluation_key_record, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = hash_at_path(evaluation_key_record, &["bgvPublicKeyRoot"])?;
    compare_hash_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
        collective_public_key_root,
        "evaluation key collective public key root",
    )?;
    compare_hash_at_path(
        setup_package,
        &["collectivePublicKey", "bgvPublicKeyRoot"],
        bgv_public_key_root,
        "evaluation key BGV public key root",
    )?;
    let expected_material = expected_evaluation_key_material_binding(setup_package)?;
    let actual_material = value_at_path(evaluation_keys, &["evaluationKeyMaterialCommitment"])?;
    compare_hash_at_path(
        evaluation_key_record,
        &["evaluationKeyMaterialCommitmentHash"],
        string_at_path(&expected_material, &["materialHash"])?,
        "evaluation key material commitment hash",
    )?;
    if actual_material != &expected_material {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "evaluation key material commitment does not match the setup-derived key stream schedule",
        ));
    }

    let evaluation_key_root = hash_at_path(evaluation_keys, &["evaluationKeyRoot"])?;
    compare_derived_hash(
        evaluation_key_record,
        evaluation_key_root,
        "evaluation key root",
    )
}
