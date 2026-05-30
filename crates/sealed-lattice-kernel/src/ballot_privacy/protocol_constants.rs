// Semantic ballot privacy profile constants. These values define the supported
// protocol shape; they are not LaZer-generated proof-profile bounds.

pub(crate) const BALLOT_PRIVACY_MINIMUM_OPTION_COUNT: u128 = 2;
pub(crate) const BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT: u128 = 20;
pub(crate) const BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT: usize = 3;
// Claim-bearing threshold: below 10 the anonymity set is too small for the privacy claim.
pub(crate) const BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT: usize = 10;
// Participant count fixed by the mandatory benchmark profile.
pub(crate) const BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT: usize = 20;
// Hard upper bound on participants.
pub(crate) const BALLOT_PRIVACY_MAXIMUM_PARTICIPANT_COUNT: usize = 50;
// Each option encodes to 11 coordinates: 1 scalar score + 10 one-hot score buckets.
pub(crate) const BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION: u64 = 11;
pub(crate) const BALLOT_PRIVACY_FIELD_MODULUS: u64 = 65_537;

// Goldilocks prime 2^64 - 2^32 + 1 (NTT-friendly): the Module-SIS share-commitment ring modulus.
pub(crate) const SHARE_COMMITMENT_MODULUS: u64 = 18_446_744_069_414_584_321;

// Module-LWE / Falcon-style params (12289 prime, ring X^256+1), protocol-frozen.
pub(crate) const RECEIVER_ENCRYPTION_MODULUS: u64 = 12_289;
pub(crate) const RECEIVER_ENCRYPTION_MODULE_RANK: u64 = 4;
pub(crate) const RECEIVER_ENCRYPTION_MODULE_DEGREE: u64 = 256;
