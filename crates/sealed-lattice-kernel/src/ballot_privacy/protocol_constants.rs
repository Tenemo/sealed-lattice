// Semantic ballot privacy profile constants. These values define the supported
// protocol shape; they are not LaZer-generated proof-profile bounds.

pub(crate) const BALLOT_PRIVACY_MINIMUM_OPTION_COUNT: u128 = 2;
pub(crate) const BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT: u128 = 20;
pub(crate) const BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT: usize = 3;
pub(crate) const BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT: usize = 20;
pub(crate) const BALLOT_PRIVACY_MAXIMUM_PARTICIPANT_COUNT: usize = 50;
pub(crate) const BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION: u64 = 11;
pub(crate) const BALLOT_PRIVACY_FIELD_MODULUS: u64 = 65_537;

pub(crate) const SHARE_COMMITMENT_MODULUS: u64 = 18_446_744_069_414_584_321;

pub(crate) const RECEIVER_ENCRYPTION_MODULUS: u64 = 12_289;
pub(crate) const RECEIVER_ENCRYPTION_MODULE_RANK: u64 = 4;
pub(crate) const RECEIVER_ENCRYPTION_MODULE_DEGREE: u64 = 256;
