use core::fmt;

/// The closed semantic refusal taxonomy shared by every verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RefusalReason {
    MalformedEncoding = 0x0001,
    UnsupportedVersionOrSuite = 0x0002,
    OutsideSupportedProfile = 0x0003,
    WrongContext = 0x0004,
    WrongTypeOrLength = 0x0005,
    WrongHashOrRoot = 0x0006,
    InvalidSignature = 0x0007,
    DuplicateIdentity = 0x0008,
    Equivocation = 0x0009,
    MissingPrerequisite = 0x000a,
    InvalidProof = 0x000b,
    InvalidArithmeticRelation = 0x000c,
    ConsumedState = 0x000d,
}

impl RefusalReason {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 13] = [
        Self::MalformedEncoding,
        Self::UnsupportedVersionOrSuite,
        Self::OutsideSupportedProfile,
        Self::WrongContext,
        Self::WrongTypeOrLength,
        Self::WrongHashOrRoot,
        Self::InvalidSignature,
        Self::DuplicateIdentity,
        Self::Equivocation,
        Self::MissingPrerequisite,
        Self::InvalidProof,
        Self::InvalidArithmeticRelation,
        Self::ConsumedState,
    ];

    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    /// Decodes an assigned canonical reason code.
    ///
    /// Code zero and every unassigned code are malformed input rather than an
    /// encoded `MalformedEncoding` refusal.
    pub const fn try_from_canonical_code(code: u16) -> Result<Self, Self> {
        match code {
            0x0001 => Ok(Self::MalformedEncoding),
            0x0002 => Ok(Self::UnsupportedVersionOrSuite),
            0x0003 => Ok(Self::OutsideSupportedProfile),
            0x0004 => Ok(Self::WrongContext),
            0x0005 => Ok(Self::WrongTypeOrLength),
            0x0006 => Ok(Self::WrongHashOrRoot),
            0x0007 => Ok(Self::InvalidSignature),
            0x0008 => Ok(Self::DuplicateIdentity),
            0x0009 => Ok(Self::Equivocation),
            0x000a => Ok(Self::MissingPrerequisite),
            0x000b => Ok(Self::InvalidProof),
            0x000c => Ok(Self::InvalidArithmeticRelation),
            0x000d => Ok(Self::ConsumedState),
            _ => Err(Self::MalformedEncoding),
        }
    }

    /// The language-neutral name used at JavaScript and evidence boundaries.
    pub const fn name(self) -> &'static str {
        match self {
            Self::MalformedEncoding => "malformedEncoding",
            Self::UnsupportedVersionOrSuite => "unsupportedVersionOrSuite",
            Self::OutsideSupportedProfile => "outsideSupportedProfile",
            Self::WrongContext => "wrongContext",
            Self::WrongTypeOrLength => "wrongTypeOrLength",
            Self::WrongHashOrRoot => "wrongHashOrRoot",
            Self::InvalidSignature => "invalidSignature",
            Self::DuplicateIdentity => "duplicateIdentity",
            Self::Equivocation => "equivocation",
            Self::MissingPrerequisite => "missingPrerequisite",
            Self::InvalidProof => "invalidProof",
            Self::InvalidArithmeticRelation => "invalidArithmeticRelation",
            Self::ConsumedState => "consumedState",
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// The only result form returned by cryptographic and protocol verifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum VerificationResult<VerifiedValue> {
    Valid { value: VerifiedValue },
    Refused { refusal_reason: RefusalReason },
}

impl<VerifiedValue> VerificationResult<VerifiedValue> {
    pub const fn valid(value: VerifiedValue) -> Self {
        Self::Valid { value }
    }

    pub const fn refused(refusal_reason: RefusalReason) -> Self {
        Self::Refused { refusal_reason }
    }

    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    pub fn into_result(self) -> Result<VerifiedValue, RefusalReason> {
        match self {
            Self::Valid { value } => Ok(value),
            Self::Refused { refusal_reason } => Err(refusal_reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RefusalReason;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct RefusalReasonVector {
        code: u16,
        name: String,
    }

    #[test]
    fn refusal_codes_and_names_are_closed_and_stable() {
        let expected: Vec<RefusalReasonVector> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/foundation-refusal-reasons.json"
        )))
        .expect("foundation refusal-reason vectors must parse");
        assert_eq!(expected.len(), RefusalReason::ALL.len());

        for (reason, expected) in RefusalReason::ALL.into_iter().zip(expected) {
            let decoded = RefusalReason::try_from_canonical_code(expected.code)
                .expect("assigned refusal code decodes");
            assert_eq!(decoded, reason);
            assert_eq!(reason.canonical_code(), expected.code);
            assert_eq!(reason.name(), expected.name);
        }
    }

    #[test]
    fn unassigned_refusal_codes_fail_as_malformed_encoding() {
        for code in [0, 0x000e, 0x0100, u16::MAX] {
            assert_eq!(
                RefusalReason::try_from_canonical_code(code),
                Err(RefusalReason::MalformedEncoding)
            );
        }
    }
}
