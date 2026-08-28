//! Canonical foundation data shared by the active protocol and candidate code.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unactivated candidate codecs retain bounded helpers beyond the public foundation commands"
    )
)]
mod canonical_tuple;
mod ceremony;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unactivated candidate hashing retains streaming helpers beyond the public foundation commands"
    )
)]
mod hash;
mod participant_identity;
mod refusal;
mod schemas;
mod text;

pub use canonical_tuple::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, IncrementalCanonicalTupleDecoder,
};
pub use ceremony::{
    ACTION_DEFINITION_SCHEMA_IDENTIFIER, ActionContext, ActionDefinition,
    BOARD_POLICY_SCHEMA_IDENTIFIER, BoardPolicy, CeremonyContext, MANIFEST_SCHEMA_IDENTIFIER,
    Manifest, OPTION_DEFINITION_SCHEMA_IDENTIFIER, OptionDefinition,
};
pub use hash::{Hash512, hash_foundation_tuple_512};
pub(crate) use hash::{StreamingFoundationTupleHash512, xof_foundation_tuple};
pub use participant_identity::{
    ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ParticipantIdentity, derive_participant_identity,
};
pub use refusal::{RefusalReason, VerificationResult};
pub use schemas::{
    FOUNDATION_PROFILE, FoundationProfile, FoundationRosterParameters, FoundationSchemaError,
    MAXIMUM_CONFIGURABLE_OPTION_COUNT, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    MINIMUM_CONFIGURABLE_OPTION_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH, ROSTER_ENTRY_SCHEMA_IDENTIFIER,
    ROSTER_SCHEMA_IDENTIFIER, Roster, RosterEntry, STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
    StreamDescriptor, derive_foundation_roster_parameters,
};
pub use text::{DisplayTextError, StabilizedDisplayText};
