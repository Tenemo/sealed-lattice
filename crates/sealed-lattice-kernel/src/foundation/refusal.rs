use core::fmt;

/// The closed semantic refusal taxonomy shared by every verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    MalformedEncoding,
    UnsupportedVersionOrSuite,
    OutsideSupportedProfile,
    WrongContext,
    WrongTypeOrLength,
    DuplicateIdentity,
}

impl RefusalReason {
    pub const fn name(self) -> &'static str {
        match self {
            Self::MalformedEncoding => "malformedEncoding",
            Self::UnsupportedVersionOrSuite => "unsupportedVersionOrSuite",
            Self::OutsideSupportedProfile => "outsideSupportedProfile",
            Self::WrongContext => "wrongContext",
            Self::WrongTypeOrLength => "wrongTypeOrLength",
            Self::DuplicateIdentity => "duplicateIdentity",
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}
