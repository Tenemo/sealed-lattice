use core::{fmt, str::FromStr};

use super::{CanonicalCodecError, CanonicalItem, hash_foundation_tuple_512 as hash512};

pub const ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH: usize = 1_952;
const PARTICIPANT_IDENTITY_BYTE_LENGTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantIdentityParseError {
    WrongLength,
    InvalidLowercaseHexadecimal,
}

impl fmt::Display for ParticipantIdentityParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => formatter
                .write_str("participant identity must contain exactly 128 hexadecimal characters"),
            Self::InvalidLowercaseHexadecimal => formatter.write_str(
                "participant identity must contain only lowercase hexadecimal characters",
            ),
        }
    }
}

impl std::error::Error for ParticipantIdentityParseError {}

/// A participant identity derived from exactly one ML-DSA-65 verification key.
///
/// This type is intentionally distinct from [`super::Hash512`]. Equal-width
/// protocol hashes cannot be used where a roster-derived identity is required.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantIdentity([u8; PARTICIPANT_IDENTITY_BYTE_LENGTH]);

impl ParticipantIdentity {
    pub const BYTE_LENGTH: usize = PARTICIPANT_IDENTITY_BYTE_LENGTH;
    pub const LOWERCASE_HEX_LENGTH: usize = Self::BYTE_LENGTH * 2;

    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }

    pub fn try_from_lowercase_hex(value: &str) -> Result<Self, ParticipantIdentityParseError> {
        if value.len() != Self::LOWERCASE_HEX_LENGTH {
            return Err(ParticipantIdentityParseError::WrongLength);
        }

        let mut identity_bytes = [0u8; Self::BYTE_LENGTH];
        for (byte_index, hexadecimal_pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_lowercase_hexadecimal_digit(hexadecimal_pair[0])?;
            let low = decode_lowercase_hexadecimal_digit(hexadecimal_pair[1])?;
            identity_bytes[byte_index] = (high << 4) | low;
        }

        Ok(Self(identity_bytes))
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

impl FromStr for ParticipantIdentity {
    type Err = ParticipantIdentityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from_lowercase_hex(value)
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

fn decode_lowercase_hexadecimal_digit(digit: u8) -> Result<u8, ParticipantIdentityParseError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(ParticipantIdentityParseError::InvalidLowercaseHexadecimal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_identity_round_trips_lowercase_hexadecimal() {
        let mut identity_bytes = [0u8; ParticipantIdentity::BYTE_LENGTH];
        for (byte_index, byte) in identity_bytes.iter_mut().enumerate() {
            *byte = u8::try_from(byte_index).expect("identity byte index fits u8");
        }
        let identity = ParticipantIdentity::from_bytes(identity_bytes);
        let encoded = identity.to_lowercase_hex();

        assert_eq!(encoded.len(), ParticipantIdentity::LOWERCASE_HEX_LENGTH);
        assert_eq!(
            ParticipantIdentity::try_from_lowercase_hex(&encoded)
                .expect("canonical participant identity parses"),
            identity
        );
        assert_eq!(encoded.parse::<ParticipantIdentity>(), Ok(identity));
    }

    #[test]
    fn participant_identity_refuses_noncanonical_string_forms() {
        let canonical = "ab".repeat(ParticipantIdentity::BYTE_LENGTH);
        for wrong_length in [
            String::new(),
            canonical[..canonical.len() - 1].to_owned(),
            format!("{canonical}0"),
            format!(" {canonical}"),
            format!("{canonical}\n"),
        ] {
            assert_eq!(
                ParticipantIdentity::try_from_lowercase_hex(&wrong_length),
                Err(ParticipantIdentityParseError::WrongLength)
            );
        }

        for noncanonical in [
            format!("A{}", &canonical[1..]),
            format!("g{}", &canonical[1..]),
            format!(" {}", &canonical[1..]),
            format!("{}\n", &canonical[..canonical.len() - 1]),
        ] {
            assert_eq!(
                ParticipantIdentity::try_from_lowercase_hex(&noncanonical),
                Err(ParticipantIdentityParseError::InvalidLowercaseHexadecimal)
            );
        }
    }

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
