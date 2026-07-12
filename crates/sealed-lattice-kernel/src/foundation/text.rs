use core::{fmt, str};
use unicode_normalization::{UnicodeNormalization, is_nfc};

use super::RefusalReason;

/// The normalization tables are protocol data, not an ambient runtime choice.
pub const REQUIRED_UNICODE_VERSION: (u8, u8, u8) = (17, 0, 0);

const _: () = assert!(
    unicode_normalization::UNICODE_VERSION.0 == REQUIRED_UNICODE_VERSION.0
        && unicode_normalization::UNICODE_VERSION.1 == REQUIRED_UNICODE_VERSION.1
        && unicode_normalization::UNICODE_VERSION.2 == REQUIRED_UNICODE_VERSION.2
);

/// A strict Unicode ingress or canonical-text validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayTextError {
    InvalidUtf8,
    Noncharacter { code_point: u32 },
    UnassignedCodePoint { code_point: u32 },
    NotStabilizedNfc,
}

impl DisplayTextError {
    pub const fn refusal_reason(self) -> RefusalReason {
        RefusalReason::MalformedEncoding
    }
}

impl fmt::Display for DisplayTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => formatter.write_str("display text is not strict UTF-8"),
            Self::Noncharacter { code_point } => {
                write!(
                    formatter,
                    "display text contains noncharacter U+{code_point:04X}"
                )
            }
            Self::UnassignedCodePoint { code_point } => write!(
                formatter,
                "display text contains Unicode 17 unassigned code point U+{code_point:04X}"
            ),
            Self::NotStabilizedNfc => {
                formatter.write_str("canonical display text is not stabilized NFC")
            }
        }
    }
}

impl std::error::Error for DisplayTextError {}

/// Display text normalized once at ingress under the pinned Unicode version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StabilizedDisplayText(String);

impl StabilizedDisplayText {
    /// Strictly decodes and normalizes external UTF-8 exactly once.
    pub fn from_ingress_utf8(bytes: &[u8]) -> Result<Self, DisplayTextError> {
        let decoded = str::from_utf8(bytes).map_err(|_| DisplayTextError::InvalidUtf8)?;
        validate_assigned_scalar_values(decoded)?;

        let normalized = if is_nfc(decoded) {
            decoded.to_owned()
        } else {
            decoded.nfc().collect()
        };
        validate_assigned_scalar_values(&normalized)?;

        Ok(Self(normalized))
    }

    /// Validates bytes selected from a canonical object without normalizing.
    pub fn from_canonical_utf8(bytes: &[u8]) -> Result<Self, DisplayTextError> {
        let decoded = str::from_utf8(bytes).map_err(|_| DisplayTextError::InvalidUtf8)?;
        validate_assigned_scalar_values(decoded)?;
        if !is_nfc(decoded) {
            return Err(DisplayTextError::NotStabilizedNfc);
        }

        Ok(Self(decoded.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for StabilizedDisplayText {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for StabilizedDisplayText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn validate_assigned_scalar_values(value: &str) -> Result<(), DisplayTextError> {
    for character in value.chars() {
        let code_point = u32::from(character);
        if is_noncharacter(code_point) {
            return Err(DisplayTextError::Noncharacter { code_point });
        }
        if !unicode_normalization::char::is_public_assigned(character)
            && !is_private_use(code_point)
        {
            return Err(DisplayTextError::UnassignedCodePoint { code_point });
        }
    }

    Ok(())
}

const fn is_noncharacter(code_point: u32) -> bool {
    (code_point >= 0xfdd0 && code_point <= 0xfdef) || code_point & 0xffff >= 0xfffe
}

const fn is_private_use(code_point: u32) -> bool {
    (code_point >= 0xe000 && code_point <= 0xf8ff)
        || (code_point >= 0xf0000 && code_point <= 0xffffd)
        || (code_point >= 0x100000 && code_point <= 0x10fffd)
}

#[cfg(test)]
mod tests {
    use super::{DisplayTextError, REQUIRED_UNICODE_VERSION, StabilizedDisplayText};

    #[test]
    fn unicode_version_is_pinned_to_seventeen() {
        assert_eq!(
            unicode_normalization::UNICODE_VERSION,
            REQUIRED_UNICODE_VERSION
        );
    }

    #[test]
    fn ingress_normalizes_once_and_canonical_validation_does_not() {
        let decomposed = "Cafe\u{301}";
        let normalized = StabilizedDisplayText::from_ingress_utf8(decomposed.as_bytes())
            .expect("valid ingress text should normalize");
        assert_eq!(normalized.as_str(), "Caf\u{e9}");

        assert_eq!(
            StabilizedDisplayText::from_canonical_utf8(decomposed.as_bytes()),
            Err(DisplayTextError::NotStabilizedNfc)
        );
        assert_eq!(
            StabilizedDisplayText::from_canonical_utf8(normalized.as_str().as_bytes())
                .expect("normalized bytes should validate"),
            normalized
        );
    }

    #[test]
    fn malformed_surrogate_noncharacter_and_unassigned_inputs_are_rejected() {
        assert_eq!(
            StabilizedDisplayText::from_ingress_utf8(&[0xed, 0xa0, 0x80]),
            Err(DisplayTextError::InvalidUtf8)
        );
        assert_eq!(
            StabilizedDisplayText::from_ingress_utf8("\u{fdd0}".as_bytes()),
            Err(DisplayTextError::Noncharacter { code_point: 0xfdd0 })
        );
        assert_eq!(
            StabilizedDisplayText::from_ingress_utf8("\u{10ffff}".as_bytes()),
            Err(DisplayTextError::Noncharacter {
                code_point: 0x10ffff
            })
        );
        assert_eq!(
            StabilizedDisplayText::from_ingress_utf8("\u{378}".as_bytes()),
            Err(DisplayTextError::UnassignedCodePoint { code_point: 0x378 })
        );
    }

    #[test]
    fn assigned_private_use_code_points_are_not_misclassified_as_unassigned() {
        let display_text = StabilizedDisplayText::from_ingress_utf8("label-\u{e000}".as_bytes())
            .expect("private-use characters are assigned Unicode scalar values");

        assert_eq!(display_text.as_str(), "label-\u{e000}");
    }
}
