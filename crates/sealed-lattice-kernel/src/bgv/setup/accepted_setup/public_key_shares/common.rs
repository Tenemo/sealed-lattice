use super::*;

pub(in super::super) struct PublicKeyCommonBinding {
    pub(in super::super) public_matrix_seed_hash: String,
}

pub(in super::super) fn public_key_common_binding(
    setup_package: &Value,
) -> CanonicalResult<PublicKeyCommonBinding> {
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "commonRandomness was required before public-key share verification",
        )
    })?;
    let public_matrix_seed_hash = value_string(common_randomness, "publicMatrixSeedHash")?;
    Ok(PublicKeyCommonBinding {
        public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
    })
}
