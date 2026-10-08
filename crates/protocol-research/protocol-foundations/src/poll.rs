use crate::{
    Credential, Error, SIGNATURE_BYTES, SIGNING_PUBLIC_KEY_BYTES,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512, manifest::Manifest,
    },
};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use supported_profile::Profile;

/// The poll definition's purpose, which is also its signature context.
const POLL_PURPOSE: &str = "sealed-lattice/poll-definition/v2";
pub const POLL_SIGNATURE_CONTEXT: &[u8] = POLL_PURPOSE.as_bytes();
pub const MAXIMUM_POLL_BYTES: usize = 1_048_576;
pub const POLL_BODY_OVERHEAD: usize =
    8 + 7 * 6 + 4 + POLL_PURPOSE.len() + 64 + 32 + SIGNING_PUBLIC_KEY_BYTES + 4 + 2 + 2;

pub struct PollDraft {
    manifest: Manifest,
    top_count: u16,
    maximum_participants: u16,
}
fn validate_fields(
    manifest: &Manifest,
    top_count: u16,
    maximum_participants: u16,
) -> Result<(), Error> {
    // An option count or participant maximum without a supported profile is
    // refused when the poll is created. The roster size is known only when
    // it is proposed, and a roster above the maximum is refused.
    // The manifest itself owns the nonempty title and distinct labels.
    if !Profile::option_range().contains(&manifest.option_count())
        || top_count == 0
        || usize::from(top_count) > manifest.option_count()
        || !Profile::participant_range().contains(&usize::from(maximum_participants))
    {
        return Err(Error::Shape);
    }
    Ok(())
}
impl PollDraft {
    pub fn new(
        manifest: Manifest,
        top_count: u16,
        maximum_participants: u16,
    ) -> Result<Self, Error> {
        validate_fields(&manifest, top_count, maximum_participants)?;
        let value = Self {
            manifest,
            top_count,
            maximum_participants,
        };
        if value
            .body([0; 64], [0; 32], [0; SIGNING_PUBLIC_KEY_BYTES])?
            .len()
            > MAXIMUM_POLL_BYTES
        {
            return Err(Error::Shape);
        }
        Ok(value)
    }
    fn body(
        &self,
        runtime: [u8; 64],
        nonce: [u8; 32],
        organizer: [u8; SIGNING_PUBLIC_KEY_BYTES],
    ) -> Result<Vec<u8>, Error> {
        let manifest = self.manifest.encode().map_err(|_| Error::Shape)?;
        if manifest.len() > MAXIMUM_POLL_BYTES - POLL_BODY_OVERHEAD {
            return Err(Error::Shape);
        }
        let body = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii(POLL_PURPOSE).map_err(|_| Error::Shape)?,
                CanonicalItem::hash512(runtime),
                CanonicalItem::fixed_bytes(nonce).map_err(|_| Error::Shape)?,
                CanonicalItem::fixed_bytes(organizer).map_err(|_| Error::Shape)?,
                CanonicalItem::variable_bytes(manifest).map_err(|_| Error::Shape)?,
                CanonicalItem::unsigned16(self.top_count),
                CanonicalItem::unsigned16(self.maximum_participants),
            ],
        )
        .encode()
        .map_err(|_| Error::Shape)?;
        if body.len() > MAXIMUM_POLL_BYTES {
            return Err(Error::Shape);
        }
        Ok(body)
    }
}

pub struct SignedPoll {
    pub body: Vec<u8>,
    pub signature: [u8; SIGNATURE_BYTES],
    pub identity: [u8; 64],
}
pub struct VerifiedPoll {
    identity: [u8; 64],
    runtime: [u8; 64],
    organizer: [u8; SIGNING_PUBLIC_KEY_BYTES],
    manifest: Manifest,
    top_count: u16,
    maximum_participants: u16,
}
impl VerifiedPoll {
    pub fn identity(&self) -> [u8; 64] {
        self.identity
    }
    pub fn runtime(&self) -> [u8; 64] {
        self.runtime
    }
    pub fn organizer(&self) -> &[u8; SIGNING_PUBLIC_KEY_BYTES] {
        &self.organizer
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn top_count(&self) -> u16 {
        self.top_count
    }
    /// The largest roster the poll admits.
    pub fn maximum_participants(&self) -> u16 {
        self.maximum_participants
    }
}
fn identity(body: &[u8]) -> Result<[u8; 64], Error> {
    hash_foundation_tuple_512(
        "sealed-lattice/poll-identity/v1",
        &[CanonicalItem::variable_bytes(body).map_err(|_| Error::Shape)?],
    )
    .map(|value| value.into_bytes())
    .map_err(|_| Error::Shape)
}

impl Credential {
    pub fn create_poll(
        &mut self,
        draft: PollDraft,
        runtime: [u8; 64],
        nonce: [u8; 32],
    ) -> Result<SignedPoll, Error> {
        if self.poll_creation_consumed || self.signed {
            return Err(Error::Consumed);
        }
        let body = draft.body(runtime, nonce, self.signing_public)?;
        let identity = identity(&body)?;
        self.poll_creation_consumed = true;
        let signature = self.sign_deterministically(&identity, POLL_SIGNATURE_CONTEXT)?;
        Ok(SignedPoll {
            body,
            signature,
            identity,
        })
    }
}

pub fn verify_poll(
    expected_identity: [u8; 64],
    expected_runtime: [u8; 64],
    body: &[u8],
    signature: &[u8],
) -> Result<VerifiedPoll, Error> {
    if body.len() > MAXIMUM_POLL_BYTES
        || signature.len() != SIGNATURE_BYTES
        || identity(body)? != expected_identity
    {
        return Err(Error::Shape);
    }
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_POLL_BYTES,
        maximum_item_count: 7,
        maximum_item_byte_length: MAXIMUM_POLL_BYTES,
        maximum_nesting_depth: 32,
        maximum_cumulative_work_byte_length: 4 * MAXIMUM_POLL_BYTES,
        maximum_cumulative_allocation_byte_length: 4 * MAXIMUM_POLL_BYTES,
    };
    let tuple = CanonicalTuple::decode(body, &limits).map_err(|_| Error::Shape)?;
    if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != 7 {
        return Err(Error::Shape);
    }
    let items = &tuple.items;
    if items[0].item_type() != CanonicalItemType::Ascii
        || items[0].variable_value_bytes().map_err(|_| Error::Shape)? != POLL_PURPOSE.as_bytes()
        || items[1].item_type() != CanonicalItemType::Hash512
        || items[1].canonical_bytes() != expected_runtime
        || items[2].item_type() != CanonicalItemType::RawBytes
        || items[2].canonical_bytes().len() != 32
        || items[3].item_type() != CanonicalItemType::RawBytes
        || items[4].item_type() != CanonicalItemType::RawBytes
        || items[5].item_type() != CanonicalItemType::Unsigned16
        || items[6].item_type() != CanonicalItemType::Unsigned16
    {
        return Err(Error::Context);
    }
    let organizer: [u8; SIGNING_PUBLIC_KEY_BYTES] = items[3]
        .canonical_bytes()
        .try_into()
        .map_err(|_| Error::Shape)?;
    let public = ml_dsa_65::PublicKey::try_from_bytes(organizer).map_err(|_| Error::Shape)?;
    if !public.verify(
        &expected_identity,
        &signature.try_into().map_err(|_| Error::Shape)?,
        POLL_SIGNATURE_CONTEXT,
    ) {
        return Err(Error::Crypto);
    }
    let manifest = Manifest::decode(
        items[4].variable_value_bytes().map_err(|_| Error::Shape)?,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| Error::Shape)?;
    let unsigned16 = |item: &CanonicalItem| {
        item.canonical_bytes()
            .try_into()
            .map(u16::from_le_bytes)
            .map_err(|_| Error::Shape)
    };
    let top_count = unsigned16(&items[5])?;
    let maximum_participants = unsigned16(&items[6])?;
    validate_fields(&manifest, top_count, maximum_participants)?;
    Ok(VerifiedPoll {
        identity: expected_identity,
        runtime: expected_runtime,
        organizer,
        manifest,
        top_count,
        maximum_participants,
    })
}

#[cfg(test)]
#[path = "poll-tests.rs"]
mod tests;
