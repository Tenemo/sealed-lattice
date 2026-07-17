use core::fmt;

use super::{CanonicalCodecError, CanonicalItem, hash_foundation_tuple_512 as hash512};

pub const ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH: usize = 1_952;
const PARTICIPANT_IDENTITY_BYTE_LENGTH: usize = 64;

/// A participant identity derived from exactly one ML-DSA-65 verification key.
///
/// This type is intentionally distinct from [`super::Hash512`]. Equal-width
/// protocol hashes cannot be used where a roster-derived identity is required.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantIdentity([u8; PARTICIPANT_IDENTITY_BYTE_LENGTH]);

impl ParticipantIdentity {
    pub const BYTE_LENGTH: usize = PARTICIPANT_IDENTITY_BYTE_LENGTH;
    const LOWERCASE_HEX_LENGTH: usize = Self::BYTE_LENGTH * 2;

    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }

    pub fn to_lowercase_hex(self) -> String {
        const LOWERCASE_HEXADECIMAL_DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(Self::LOWERCASE_HEX_LENGTH);
        for byte in self.0 {
            output.push(char::from(
                LOWERCASE_HEXADECIMAL_DIGITS[usize::from(byte >> 4)],
            ));
            output.push(char::from(
                LOWERCASE_HEXADECIMAL_DIGITS[usize::from(byte & 0x0f)],
            ));
        }
        output
    }
}

impl fmt::Debug for ParticipantIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ParticipantIdentity")
            .field(&self.to_lowercase_hex())
            .finish()
    }
}

impl fmt::Display for ParticipantIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_lowercase_hex())
    }
}

pub fn derive_participant_identity(
    signing_verification_key: &[u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
) -> Result<ParticipantIdentity, CanonicalCodecError> {
    let participant_identity_hash = hash512(
        "sealed-lattice/foundation/participant-id/v1",
        &[CanonicalItem::fixed_bytes(*signing_verification_key)?],
    )?;

    Ok(ParticipantIdentity::from_bytes(
        participant_identity_hash.into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
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

        assert_eq!(identity.into_bytes(), expected_hash.into_bytes());
    }
}
