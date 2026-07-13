use super::*;

// Target-decryption parameter identity binds the BGV parameter hash and
// secret-share domain.
pub(super) fn target_decryption_parameters(bgv_parameters_hash: &str) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "TargetDecryptionParameters",
        "bgvParametersHash": bgv_parameters_hash,
        "secretShareDomain": SECRET_SHARE_DOMAIN,
    }))
}
