mod codec;
#[cfg(test)]
pub use codec::decode_standard_base64;
pub use codec::{decode_hex, encode_hex};

#[cfg(test)]
mod tests {
    use super::decode_hex;
    use crate::encoding::CanonicalErrorCode;

    #[test]
    fn decode_hex_rejects_uppercase_hex() {
        let error = decode_hex("AB").expect_err("uppercase hex must be non-canonical");

        assert_eq!(error.code, CanonicalErrorCode::InvalidHex);
    }
}
