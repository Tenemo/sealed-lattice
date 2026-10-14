use core::{fmt, str};
use unicode_normalization::{UnicodeNormalization, is_nfc};

/// The normalization tables are protocol data, not an ambient runtime choice.
pub(crate) const REQUIRED_UNICODE_VERSION: (u8, u8, u8) = (17, 0, 0);

const _: () = assert!(
    unicode_normalization::UNICODE_VERSION.0 == REQUIRED_UNICODE_VERSION.0
        && unicode_normalization::UNICODE_VERSION.1 == REQUIRED_UNICODE_VERSION.1
        && unicode_normalization::UNICODE_VERSION.2 == REQUIRED_UNICODE_VERSION.2
);

/// Text that is not strict UTF-8 of assigned, public, non-noncharacter code
/// points, or canonical text that is not stabilized NFC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayTextRefusal;

/// Display text normalized once at ingress under the pinned Unicode version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StabilizedDisplayText(String);

impl StabilizedDisplayText {
    /// Strictly decodes and normalizes external UTF-8 exactly once.
    pub fn from_ingress_utf8(bytes: &[u8]) -> Result<Self, DisplayTextRefusal> {
        let decoded = str::from_utf8(bytes).map_err(|_| DisplayTextRefusal)?;
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
    pub fn from_canonical_utf8(bytes: &[u8]) -> Result<Self, DisplayTextRefusal> {
        let decoded = str::from_utf8(bytes).map_err(|_| DisplayTextRefusal)?;
        validate_assigned_scalar_values(decoded)?;
        if !is_nfc(decoded) {
            return Err(DisplayTextRefusal);
        }

        Ok(Self(decoded.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

fn validate_assigned_scalar_values(value: &str) -> Result<(), DisplayTextRefusal> {
    for character in value.chars() {
        let code_point = u32::from(character);
        if is_noncharacter(code_point)
            || is_private_use(code_point)
            || !unicode_normalization::char::is_public_assigned(character)
        {
            return Err(DisplayTextRefusal);
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
#[path = "text-tests.rs"]
mod tests;
