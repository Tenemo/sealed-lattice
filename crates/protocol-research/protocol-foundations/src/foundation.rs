#[path = "foundation/canonical-tuple.rs"]
pub(crate) mod canonical_tuple;
pub mod hash;
pub mod manifest;
#[path = "foundation/participant-identity.rs"]
pub mod participant_identity;
pub(crate) mod schemas;
pub mod text;

use crate::SIGNING_PUBLIC_KEY_BYTES;
pub use canonical_tuple::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecRefusal,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
};
pub use hash::{Hash512, hash_foundation_tuple_512};
pub(crate) use participant_identity::derive_participant_identity;
pub(crate) use schemas::FoundationSchemaRefusal;
pub use text::StabilizedDisplayText;

pub(crate) const MAXIMUM_USERNAME_BYTES: usize = 128;
const REGISTRATION_HEADER_PURPOSE: &str = "sealed-lattice/registration-header/v6";
/// A username arrives as at most this many bytes before normalization.
pub const MAXIMUM_USERNAME_INGRESS_BYTES: usize = 512;
pub fn normalize_username(bytes: &[u8]) -> Result<StabilizedDisplayText, crate::Refusal> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_USERNAME_INGRESS_BYTES {
        return Err(crate::Refusal::Shape);
    }
    let value =
        StabilizedDisplayText::from_ingress_utf8(bytes).map_err(|_| crate::Refusal::Shape)?;
    if value.as_str().is_empty() || value.as_str().len() > MAXIMUM_USERNAME_BYTES {
        return Err(crate::Refusal::Shape);
    }
    Ok(value)
}

pub struct RegistrationHeader {
    pub username: StabilizedDisplayText,
    pub poll: [u8; 64],
    pub signing_public: [u8; SIGNING_PUBLIC_KEY_BYTES],
    pub recipient_key_hash: [u8; 64],

    pub fhe_key_commitments: Vec<[u8; 64]>,
}
impl RegistrationHeader {
    /// The encoded length of a header with the longest username.
    pub fn maximum_bytes() -> usize {
        let username = StabilizedDisplayText::from_ingress_utf8(&[b'a'; MAXIMUM_USERNAME_BYTES])
            .expect("A run of one ASCII letter is a stable username.");
        Self {
            username,
            poll: [0; 64],
            signing_public: [0; SIGNING_PUBLIC_KEY_BYTES],
            recipient_key_hash: [0; 64],

            fhe_key_commitments: vec![
                [0; 64];
                crate::source_binding::maximum_fhe_key_family_count()
            ],
        }
        .encode()
        .expect("The longest username encodes.")
        .len()
    }
    pub fn encode(&self) -> Result<Vec<u8>, crate::Refusal> {
        if self.username.as_str().is_empty()
            || self.username.as_str().len() > MAXIMUM_USERNAME_BYTES
            || self.fhe_key_commitments.is_empty()
            || self.fhe_key_commitments.len()
                > crate::source_binding::maximum_fhe_key_family_count()
        {
            return Err(crate::Refusal::Shape);
        }
        CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii(REGISTRATION_HEADER_PURPOSE).unwrap(),
                CanonicalItem::hash512(self.poll),
                CanonicalItem::fixed_bytes(self.signing_public).unwrap(),
                CanonicalItem::hash512(self.recipient_key_hash),
                CanonicalItem::display_text(&self.username).map_err(|_| crate::Refusal::Shape)?,
                CanonicalItem::hash512_list(&self.fhe_key_commitments)
                    .map_err(|_| crate::Refusal::Shape)?,
            ],
        )
        .encode()
        .map_err(|_| crate::Refusal::Shape)
    }
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), crate::Refusal> {
        use canonical_tuple::{CanonicalDecodeBudget, CanonicalDecodeLimits};
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: 4096,
            maximum_item_count: 6.max(crate::source_binding::maximum_fhe_key_family_count()),
            maximum_item_byte_length: SIGNING_PUBLIC_KEY_BYTES,
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
        .map_err(|_| crate::Refusal::Shape)?;
        if !tuple.has_header(6) {
            return Err(crate::Refusal::Shape);
        }
        let items = &tuple.items;
        if items[0].item_type() != CanonicalItemType::Ascii
            || items[0]
                .variable_value_bytes()
                .map_err(|_| crate::Refusal::Shape)?
                != REGISTRATION_HEADER_PURPOSE.as_bytes()
        {
            return Err(crate::Refusal::Context);
        }
        let field = |index: usize, kind| {
            let item = &items[index];
            if item.item_type() != kind {
                return Err(crate::Refusal::Shape);
            }
            Ok(item.canonical_bytes())
        };
        let poll = field(1, CanonicalItemType::Hash512)?
            .try_into()
            .map_err(|_| crate::Refusal::Shape)?;
        let signing_public = field(2, CanonicalItemType::RawBytes)?
            .try_into()
            .map_err(|_| crate::Refusal::Shape)?;
        let recipient_key_hash = field(3, CanonicalItemType::Hash512)?
            .try_into()
            .map_err(|_| crate::Refusal::Shape)?;
        if items[4].item_type() != CanonicalItemType::DisplayText {
            return Err(crate::Refusal::Shape);
        }
        let username_bytes = items[4]
            .variable_value_bytes()
            .map_err(|_| crate::Refusal::Shape)?;
        if username_bytes.is_empty() || username_bytes.len() > MAXIMUM_USERNAME_BYTES {
            return Err(crate::Refusal::Shape);
        }
        let username = StabilizedDisplayText::from_canonical_utf8(username_bytes)
            .map_err(|_| crate::Refusal::Shape)?;
        let commitments = field(5, CanonicalItemType::HomogeneousList)?;
        if commitments.len() < 6
            || commitments[..2] != CanonicalItemType::Hash512.canonical_code().to_le_bytes()
        {
            return Err(crate::Refusal::Shape);
        }
        let count = u32::from_le_bytes(commitments[2..6].try_into().unwrap()) as usize;
        if count == 0
            || count > crate::source_binding::maximum_fhe_key_family_count()
            || commitments.len() != 6 + count * 64
        {
            return Err(crate::Refusal::Shape);
        }
        let fhe_key_commitments = commitments[6..]
            .chunks_exact(64)
            .map(|digest| digest.try_into().unwrap())
            .collect();
        Ok((
            Self {
                username,
                poll,
                signing_public,
                recipient_key_hash,
                fhe_key_commitments,
            },
            consumed,
        ))
    }
}
