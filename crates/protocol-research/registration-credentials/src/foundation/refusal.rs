/// The closed semantic refusal taxonomy shared by every verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    MalformedEncoding,
    UnsupportedVersionOrSuite,
    OutsideSupportedProfile,
    WrongTypeOrLength,
    DuplicateIdentity,
}
