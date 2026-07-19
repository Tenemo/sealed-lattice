use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub(super) fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if !is_lowercase_protocol_hash(hash) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{field_name} must be a 128-character lowercase hexadecimal protocol hash"),
        ));
    }

    Ok(())
}

pub(super) fn is_lowercase_protocol_hash(hash: &str) -> bool {
    hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
