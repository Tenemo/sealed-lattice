use super::*;

pub(in super::super) fn verify_same_secret_context(
    value: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
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
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": "same-secret-linkage-anchor",
        "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        "anchorArgument": "one keyless succinct linkage proof per trustee; secret-dependent families bind the anchor root and open the same commitment values",
        "boundSecretDependentProofFamilies": expected_same_secret_bound_proof_families_value(),
        "genericKeySwitchBindingPolicy": "absent-unless-frozen-schedule-requires-proof-family",
        "targetDecryptionBindingPolicy": "later-target-share-must-bind-threshold-share-commitment",
    })
}

pub(in super::super) fn same_secret_proof_family_binding_root() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SameSecretProofFamilyBindingRoot",
        &same_secret_proof_family_binding_value(),
    )
}
