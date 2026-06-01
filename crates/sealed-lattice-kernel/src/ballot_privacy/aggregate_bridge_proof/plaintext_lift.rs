use super::validation::{read_u64_object_field, required_string_at_path};
use super::*;

pub(super) fn proof_friendly_plaintext_lift_binding_value(
    setup_package: &Value,
    bridge_encryption: &Value,
) -> CanonicalResult<Value> {
    let coefficient_count =
        read_u64_object_field(bridge_encryption, "coefficientCount", "bridgeEncryption")?;
    let slot_count = read_u64_object_field(bridge_encryption, "slotCount", "bridgeEncryption")?;
    if coefficient_count != POLYNOMIAL_DEGREE as u64 || slot_count != POLYNOMIAL_DEGREE as u64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge proof-friendly plaintext lift dimensions do not match the selected BGV profile",
        ));
    }

    Ok(json!({
        "objectType": "AggregateBridgeProofFriendlyPlaintextLiftBinding",
        "objectVersion": 1,
        "bindingStatus": PROOF_FRIENDLY_PLAINTEXT_LIFT_BINDING_STATUS,
        "coefficientBindingStatus": PROOF_FRIENDLY_PLAINTEXT_BINDING_STATUS,
        "coefficientBindingScheme": PLAINTEXT_COEFFICIENT_BINDING_SCHEME,
        "plaintextCoefficientBindingCommitmentHash": required_string_field(
            bridge_encryption,
            "plaintextCoefficientBindingCommitmentHash",
            "bridgeEncryption",
        )?,
        "batchEncodingRelation": required_string_field(
            bridge_encryption,
            "batchEncodingRelation",
            "bridgeEncryption",
        )?,
        "batchEncodingBoundCertificateHash": required_string_field(
            bridge_encryption,
            "batchEncodingBoundCertificateHash",
            "bridgeEncryption",
        )?,
        "bgvBatchEncoderHash": required_string_at_path(
            setup_package,
            &["profileBindings", "batchEncoderHash"],
            "setupPackage",
        )?,
        "bridgeLayoutHash": required_string_at_path(
            setup_package,
            &["profileBindings", "encryptedAggregateInputLayoutHash"],
            "setupPackage",
        )?,
        "encodedAggregateLayoutHash": required_string_at_path(
            setup_package,
            &["profileBindings", "encodedAggregateLayoutHash"],
            "setupPackage",
        )?,
        "bgvProfileHash": required_string_at_path(
            setup_package,
            &["profileBindings", "profileHash"],
            "setupPackage",
        )?,
        "rustBgvBackendProfileHash": required_string_at_path(
            setup_package,
            &["profileBindings", "backendProfileHash"],
            "setupPackage",
        )?,
        "canonicalCiphertextConventionHash": required_string_at_path(
            setup_package,
            &["profileBindings", "canonicalCiphertextConventionHash"],
            "setupPackage",
        )?,
        "basisId": required_string_field(bridge_encryption, "basisId", "bridgeEncryption")?,
        "level": read_u64_object_field(bridge_encryption, "level", "bridgeEncryption")?,
        "plaintextModulus": BALLOT_PRIVACY_FIELD_MODULUS,
        "coefficientCount": coefficient_count,
        "slotCount": slot_count,
        "coefficientDomainCanonical": true,
        "sameHiddenPlaintextCoefficientVectorRequired": true,
        "conventionalPlaintextRootRole": "bound-public-metadata-not-proof-evidence",
        "currentUse": "internal proof binding only; not result acceptance evidence",
    }))
}

pub(super) fn proof_friendly_plaintext_lift_binding_hash(
    binding: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-proof-friendly-plaintext-lift-binding-v1",
            "proofFriendlyPlaintextLiftBinding": binding,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_package_fixture() -> Value {
        json!({
            "profileBindings": {
                "batchEncoderHash": "1".repeat(128),
                "encryptedAggregateInputLayoutHash": "2".repeat(128),
                "encodedAggregateLayoutHash": "3".repeat(128),
                "profileHash": "4".repeat(128),
                "backendProfileHash": "5".repeat(128),
                "canonicalCiphertextConventionHash": "6".repeat(128),
            }
        })
    }

    fn bridge_encryption_fixture() -> Value {
        json!({
            "plaintextCoefficientBindingCommitmentHash": "7".repeat(128),
            "batchEncodingRelation": PLAINTEXT_ENCODING_RELATION,
            "batchEncodingBoundCertificateHash": "8".repeat(128),
            "basisId": "sealed-lattice-bgv-rns-data-basis-v1",
            "level": 15,
            "coefficientCount": POLYNOMIAL_DEGREE,
            "slotCount": POLYNOMIAL_DEGREE,
        })
    }

    #[test]
    fn plaintext_lift_binding_hash_changes_with_coefficient_commitment() {
        let setup_package = setup_package_fixture();
        let bridge_encryption = bridge_encryption_fixture();
        let binding =
            proof_friendly_plaintext_lift_binding_value(&setup_package, &bridge_encryption)
                .expect("binding should derive");
        let binding_hash =
            proof_friendly_plaintext_lift_binding_hash(&binding).expect("hash should derive");
        let mut changed_bridge_encryption = bridge_encryption;
        changed_bridge_encryption["plaintextCoefficientBindingCommitmentHash"] =
            Value::String("9".repeat(128));
        let changed_binding =
            proof_friendly_plaintext_lift_binding_value(&setup_package, &changed_bridge_encryption)
                .expect("changed binding should derive");
        let changed_binding_hash = proof_friendly_plaintext_lift_binding_hash(&changed_binding)
            .expect("changed hash should derive");

        assert_ne!(binding_hash, changed_binding_hash);
    }

    #[test]
    fn plaintext_lift_binding_rejects_wrong_plaintext_dimensions() {
        let setup_package = setup_package_fixture();
        let mut bridge_encryption = bridge_encryption_fixture();
        bridge_encryption["coefficientCount"] = json!(POLYNOMIAL_DEGREE as u64 - 1);

        let error = proof_friendly_plaintext_lift_binding_value(&setup_package, &bridge_encryption)
            .expect_err("wrong dimensions should reject");

        assert!(error.message.contains("plaintext lift dimensions"));
    }
}
