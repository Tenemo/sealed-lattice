use crate::{
    Credential, Error,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        ceremony::Manifest, hash_foundation_tuple_512,
    },
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use zeroize::Zeroizing;

pub const POLL_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/poll-definition/v1";
pub const MAXIMUM_POLL_BYTES: usize = 1_048_576;
pub const POLL_BODY_OVERHEAD: usize =
    8 + 6 * 6 + 4 + b"sealed-lattice/poll-definition/v1".len() + 64 + 32 + 1952 + 4 + 2;

pub struct PollDraft {
    manifest: Manifest,
    top_count: u16,
}
fn validate_fields(manifest: &Manifest, top_count: u16) -> Result<(), Error> {
    if top_count == 0
        || usize::from(top_count) > manifest.option_count()
        || manifest.display_title().as_str().is_empty()
    {
        return Err(Error::Shape);
    }
    let mut labels = std::collections::BTreeSet::new();
    for option in manifest.options() {
        if !labels.insert(option.display_label().as_str()) {
            return Err(Error::Shape);
        }
    }
    Ok(())
}
impl PollDraft {
    pub fn new(manifest: Manifest, top_count: u16) -> Result<Self, Error> {
        validate_fields(&manifest, top_count)?;
        let value = Self {
            manifest,
            top_count,
        };
        if value.body([0; 64], [0; 32], [0; 1952])?.len() > MAXIMUM_POLL_BYTES {
            return Err(Error::Shape);
        }
        Ok(value)
    }
    fn body(
        &self,
        runtime: [u8; 64],
        nonce: [u8; 32],
        organizer: [u8; 1952],
    ) -> Result<Vec<u8>, Error> {
        let manifest = self.manifest.encode().map_err(|_| Error::Shape)?;
        if manifest.len() > MAXIMUM_POLL_BYTES - POLL_BODY_OVERHEAD {
            return Err(Error::Shape);
        }
        let body = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii("sealed-lattice/poll-definition/v1")
                    .map_err(|_| Error::Shape)?,
                CanonicalItem::hash512(runtime),
                CanonicalItem::fixed_bytes(nonce).map_err(|_| Error::Shape)?,
                CanonicalItem::fixed_bytes(organizer).map_err(|_| Error::Shape)?,
                CanonicalItem::variable_bytes(manifest).map_err(|_| Error::Shape)?,
                CanonicalItem::unsigned16(self.top_count),
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
    pub signature: [u8; 3309],
    pub identity: [u8; 64],
}
pub struct VerifiedPoll {
    identity: [u8; 64],
    runtime: [u8; 64],
    organizer: [u8; 1952],
    manifest: Manifest,
    top_count: u16,
}
impl VerifiedPoll {
    pub fn identity(&self) -> [u8; 64] {
        self.identity
    }
    pub fn runtime(&self) -> [u8; 64] {
        self.runtime
    }
    pub fn organizer(&self) -> &[u8; 1952] {
        &self.organizer
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn top_count(&self) -> u16 {
        self.top_count
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
        randomness: [u8; 32],
    ) -> Result<SignedPoll, Error> {
        if self.poll_creation_consumed || self.signed {
            return Err(Error::Consumed);
        }
        let body = draft.body(runtime, nonce, self.signing_public)?;
        let identity = identity(&body)?;
        self.poll_creation_consumed = true;
        let coins = Zeroizing::new(randomness);
        let (_, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        let signature = private
            .try_sign_with_seed(&coins, &identity, POLL_SIGNATURE_CONTEXT)
            .map_err(|_| Error::Crypto)?;
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
        || signature.len() != 3309
        || identity(body)? != expected_identity
    {
        return Err(Error::Shape);
    }
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_POLL_BYTES,
        maximum_item_count: 6,
        maximum_item_byte_length: MAXIMUM_POLL_BYTES,
        maximum_nesting_depth: 32,
        maximum_cumulative_work_byte_length: 4 * MAXIMUM_POLL_BYTES,
        maximum_cumulative_allocation_byte_length: 4 * MAXIMUM_POLL_BYTES,
    };
    let tuple = CanonicalTuple::decode(body, &limits).map_err(|_| Error::Shape)?;
    if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != 6 {
        return Err(Error::Shape);
    }
    let items = &tuple.items;
    if items[0].item_type() != CanonicalItemType::Ascii
        || items[0].variable_value_bytes().map_err(|_| Error::Shape)?
            != b"sealed-lattice/poll-definition/v1"
        || items[1].item_type() != CanonicalItemType::Hash512
        || items[1].canonical_bytes() != expected_runtime
        || items[2].item_type() != CanonicalItemType::RawBytes
        || items[2].canonical_bytes().len() != 32
        || items[3].item_type() != CanonicalItemType::RawBytes
        || items[4].item_type() != CanonicalItemType::RawBytes
        || items[5].item_type() != CanonicalItemType::Unsigned16
    {
        return Err(Error::Context);
    }
    let organizer: [u8; 1952] = items[3]
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
    let top_count = u16::from_le_bytes(
        items[5]
            .canonical_bytes()
            .try_into()
            .map_err(|_| Error::Shape)?,
    );
    validate_fields(&manifest, top_count)?;
    Ok(VerifiedPoll {
        identity: expected_identity,
        runtime: expected_runtime,
        organizer,
        manifest,
        top_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{StabilizedDisplayText, ceremony::OptionDefinition};
    fn draft(top_count: u16) -> Result<PollDraft, Error> {
        let name =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        PollDraft::new(
            Manifest::new(
                name("Question"),
                vec![
                    OptionDefinition::new(0, "first".to_owned(), name("First")).unwrap(),
                    OptionDefinition::new(1, "second".to_owned(), name("Second")).unwrap(),
                ],
            )
            .unwrap(),
            top_count,
        )
    }
    #[test]
    fn poll_identity_binds_creator_definition_and_runtime_without_a_future_key() {
        let mut creator = Credential::from_seeds([7; 32], [8; 32], [9; 32]);
        let original = *creator.signing_public();
        let packet = creator
            .create_poll(draft(2).unwrap(), [2; 64], [3; 32], [4; 32])
            .unwrap();
        let verified =
            verify_poll(packet.identity, [2; 64], &packet.body, &packet.signature).unwrap();
        assert_eq!(verified.organizer(), &original);
        assert_eq!(verified.manifest().option_count(), 2);
        assert_eq!(verified.top_count(), 2);
        assert!(
            creator
                .create_poll(draft(1).unwrap(), [2; 64], [4; 32], [5; 32])
                .is_err()
        );
        assert!(verify_poll(packet.identity, [9; 64], &packet.body, &packet.signature).is_err());
        let mut changed = packet.body.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify_poll(packet.identity, [2; 64], &changed, &packet.signature).is_err());
        assert!(draft(0).is_err());
        assert!(draft(3).is_err());
    }

    #[test]
    fn valid_signatures_do_not_authorize_invalid_poll_fields() {
        let mut creator = Credential::from_seeds([7; 32], [8; 32], [9; 32]);
        let packet = creator
            .create_poll(draft(2).unwrap(), [2; 64], [3; 32], [4; 32])
            .unwrap();
        let original =
            CanonicalTuple::decode(&packet.body, &CanonicalDecodeLimits::default()).unwrap();
        let (_, private) = ml_dsa_65::KG::keygen_from_seed(&[7; 32]);
        let signed_refusal = |tuple: CanonicalTuple| {
            let body = tuple.encode().unwrap();
            let digest = identity(&body).unwrap();
            let signature = private
                .try_sign_with_seed(&[5; 32], &digest, POLL_SIGNATURE_CONTEXT)
                .unwrap();
            assert!(verify_poll(digest, [2; 64], &body, &signature).is_err());
        };
        let mut top = original.clone();
        top.items[5] = CanonicalItem::unsigned16(3);
        signed_refusal(top);
        let label =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        let options = |first: &str, second: &str| {
            vec![
                OptionDefinition::new(0, "first".to_owned(), label(first)).unwrap(),
                OptionDefinition::new(1, "second".to_owned(), label(second)).unwrap(),
            ]
        };
        let empty = Manifest::new(label(""), options("First", "Second")).unwrap();
        let mut empty_body = original.clone();
        empty_body.items[4] = CanonicalItem::variable_bytes(empty.encode().unwrap()).unwrap();
        signed_refusal(empty_body);
        let duplicates = Manifest::new(label("Question"), options("\u{e9}", "e\u{301}")).unwrap();
        let mut duplicate_body = original.clone();
        duplicate_body.items[4] =
            CanonicalItem::variable_bytes(duplicates.encode().unwrap()).unwrap();
        signed_refusal(duplicate_body);
        let mut wrong_runtime = original;
        wrong_runtime.items[1] = CanonicalItem::hash512([9; 64]);
        signed_refusal(wrong_runtime);
        assert!(matches!(
            verify_poll(
                packet.identity,
                [2; 64],
                &vec![0; MAXIMUM_POLL_BYTES + 1],
                &packet.signature
            ),
            Err(Error::Shape)
        ));
    }
}
