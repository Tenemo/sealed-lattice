use super::*;

#[test]
fn signing_key_derivation_returns_the_identity_type() {
    let signing_verification_key = [0x5a; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH];
    let identity = derive_participant_identity(&signing_verification_key)
        .expect("fixed signing key derives an identity");
    let expected_hash = hash512(
        "sealed-lattice/foundation/participant-id/v1",
        &[CanonicalItem::fixed_bytes(signing_verification_key)
            .expect("fixed key has canonical bytes")],
    )
    .expect("identity hash");

    assert_eq!(identity.to_lowercase_hex(), expected_hash.to_string());
}
