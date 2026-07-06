use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn verify_same_secret_context(
    value: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("same-secret {field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

pub(super) fn expected_same_secret_bound_proof_families_value() -> Value {
    Value::Array(
        SAME_SECRET_BOUND_PROOF_FAMILIES
            .iter()
            .map(|family| Value::String((*family).to_string()))
            .collect(),
    )
}

fn same_secret_proof_family_binding_value() -> Value {
    json!({
        "objectType": SAME_SECRET_PROOF_FAMILY_BINDING_OBJECT_TYPE,
        "proofFamily": "same-secret-linkage-anchor",
        "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        "boundSecretDependentProofFamilies": expected_same_secret_bound_proof_families_value(),
    })
}

pub(in super::super) fn same_secret_proof_family_binding_root() -> CanonicalResult<String> {
    derive_canonical_object_hash(&same_secret_proof_family_binding_value())
}
