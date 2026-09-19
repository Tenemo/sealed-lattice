#[path = "../../../sealed-lattice-kernel/src/foundation/canonical_tuple.rs"]
pub mod canonical_tuple;
#[path = "../../../sealed-lattice-kernel/src/foundation/ceremony.rs"]
pub mod ceremony;
#[path = "../../../sealed-lattice-kernel/src/foundation/hash.rs"]
pub mod hash;
#[path = "../../../sealed-lattice-kernel/src/foundation/participant_identity.rs"]
pub mod participant_identity;
#[path = "../../../sealed-lattice-kernel/src/foundation/refusal.rs"]
pub mod refusal;
#[path = "../../../sealed-lattice-kernel/src/foundation/schemas.rs"]
pub mod schemas;
#[path = "../../../sealed-lattice-kernel/src/foundation/text.rs"]
pub mod text;

pub use canonical_tuple::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple,
};
pub(crate) use hash::StreamingFoundationTupleHash512;
pub use hash::{Hash512, hash_foundation_tuple_512};
pub(crate) use participant_identity::{
    ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, derive_participant_identity,
};
pub use refusal::RefusalReason;
pub(crate) use schemas::{
    FOUNDATION_PROTOCOL_NAME, FOUNDATION_PROTOCOL_VERSION, FoundationSchemaError,
    MAXIMUM_CONFIGURABLE_OPTION_COUNT, MAXIMUM_FOUNDATION_COPIED_BUFFER_BYTE_LENGTH,
    MAXIMUM_FOUNDATION_IDENTIFIER_BYTE_LENGTH, MINIMUM_CONFIGURABLE_OPTION_COUNT, Roster,
};
#[cfg(test)]
pub(crate) use schemas::{PROTOTYPE_OPTION_COUNT, PROTOTYPE_PARTICIPANT_COUNT, RosterEntry};
pub use text::StabilizedDisplayText;

pub const MAXIMUM_USERNAME_BYTES: usize = 128;
pub fn normalize_username(bytes: &[u8]) -> Result<StabilizedDisplayText, crate::Error> {
    if bytes.is_empty() || bytes.len() > 512 {
        return Err(crate::Error::Shape);
    }
    let value = StabilizedDisplayText::from_ingress_utf8(bytes).map_err(|_| crate::Error::Shape)?;
    if value.as_str().is_empty() || value.as_str().len() > MAXIMUM_USERNAME_BYTES {
        return Err(crate::Error::Shape);
    }
    Ok(value)
}

pub struct RegistrationHeader {
    pub username: StabilizedDisplayText,
    pub poll: [u8; 64],
    pub runtime: [u8; 64],
    pub signing_public: [u8; 1952],
    pub mailbox_public: [u8; 1184],
    pub recipient_key_hash: [u8; 64],
    pub proof_length: usize,
}
impl RegistrationHeader {
    pub fn encode(&self) -> Result<Vec<u8>, crate::Error> {
        if self.username.as_str().is_empty()
            || self.username.as_str().len() > MAXIMUM_USERNAME_BYTES
        {
            return Err(crate::Error::Shape);
        }
        CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii("sealed-lattice/registration-header/v2").unwrap(),
                CanonicalItem::hash512(self.poll),
                CanonicalItem::hash512(self.runtime),
                CanonicalItem::fixed_bytes(self.signing_public).unwrap(),
                CanonicalItem::fixed_bytes(self.mailbox_public).unwrap(),
                CanonicalItem::hash512(self.recipient_key_hash),
                CanonicalItem::unsigned64(self.proof_length as u64),
                CanonicalItem::display_text(&self.username).map_err(|_| crate::Error::Shape)?,
            ],
        )
        .encode()
        .map_err(|_| crate::Error::Shape)
    }
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), crate::Error> {
        use canonical_tuple::{CanonicalDecodeBudget, CanonicalDecodeLimits};
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: 4096,
            maximum_item_count: 8,
            maximum_item_byte_length: 1952,
            maximum_nesting_depth: 0,
            maximum_cumulative_work_byte_length: 16384,
            maximum_cumulative_allocation_byte_length: 8192,
        };
        let (tuple, consumed) = CanonicalTuple::decode_prefix(
            bytes,
            &limits,
            &mut CanonicalDecodeBudget::new(&limits),
            0,
        )
        .map_err(|_| crate::Error::Shape)?;
        if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != 8 {
            return Err(crate::Error::Shape);
        }
        let items = &tuple.items;
        if items[0].item_type() != CanonicalItemType::Ascii
            || items[0]
                .variable_value_bytes()
                .map_err(|_| crate::Error::Shape)?
                != b"sealed-lattice/registration-header/v2"
        {
            return Err(crate::Error::Context);
        }
        let field = |index: usize, kind| {
            let item = &items[index];
            if item.item_type() != kind {
                return Err(crate::Error::Shape);
            }
            Ok(item.canonical_bytes())
        };
        let poll = field(1, CanonicalItemType::Hash512)?
            .try_into()
            .map_err(|_| crate::Error::Shape)?;
        let runtime = field(2, CanonicalItemType::Hash512)?
            .try_into()
            .map_err(|_| crate::Error::Shape)?;
        let signing_public = field(3, CanonicalItemType::RawBytes)?
            .try_into()
            .map_err(|_| crate::Error::Shape)?;
        let mailbox_public = field(4, CanonicalItemType::RawBytes)?
            .try_into()
            .map_err(|_| crate::Error::Shape)?;
        let recipient_key_hash = field(5, CanonicalItemType::Hash512)?
            .try_into()
            .map_err(|_| crate::Error::Shape)?;
        let proof_length = usize::try_from(u64::from_le_bytes(
            field(6, CanonicalItemType::Unsigned64)?
                .try_into()
                .map_err(|_| crate::Error::Shape)?,
        ))
        .map_err(|_| crate::Error::Shape)?;
        if items[7].item_type() != CanonicalItemType::DisplayText {
            return Err(crate::Error::Shape);
        }
        let username_bytes = items[7]
            .variable_value_bytes()
            .map_err(|_| crate::Error::Shape)?;
        if username_bytes.is_empty() || username_bytes.len() > MAXIMUM_USERNAME_BYTES {
            return Err(crate::Error::Shape);
        }
        let username = StabilizedDisplayText::from_canonical_utf8(username_bytes)
            .map_err(|_| crate::Error::Shape)?;
        Ok((
            Self {
                username,
                poll,
                runtime,
                signing_public,
                mailbox_public,
                recipient_key_hash,
                proof_length,
            },
            consumed,
        ))
    }
}
