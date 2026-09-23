use crate::{
    Credential, Error, SigningPurpose,
    ballot_authentication::RetainedBallotOwner,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    roster_authentication::OrganizerSignedRoster,
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum PublicationPurpose {
    Close,
    Empty,
    Witness,
}
impl PublicationPurpose {
    pub fn context(self) -> &'static str {
        match self {
            Self::Close => "sealed-lattice/ballot-close/v1",
            Self::Empty => "sealed-lattice/empty-slot/v1",
            Self::Witness => "sealed-lattice/slot-witness/v1",
        }
    }
}
fn identity(purpose: PublicationPurpose, body: &[u8]) -> Result<[u8; 64], Error> {
    hash_foundation_tuple_512(
        purpose.context(),
        &[CanonicalItem::variable_bytes(body).map_err(|_| Error::Shape)?],
    )
    .map(|value| value.into_bytes())
    .map_err(|_| Error::Shape)
}
fn checked_body(
    owner: &RetainedBallotOwner,
    roster: &OrganizerSignedRoster,
    purpose: PublicationPurpose,
    body: &[u8],
) -> Result<CanonicalTuple, Error> {
    let count = roster.proposal().records().len();
    let record = roster
        .proposal()
        .records()
        .get(owner.position())
        .ok_or(Error::Context)?;
    if !(3..=20).contains(&count) || record.header().poll != *owner.poll() {
        return Err(Error::Context);
    }
    let items = if matches!(purpose, PublicationPurpose::Close) {
        3
    } else {
        5
    };
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: 2048,
        maximum_item_byte_length: 2048,
        maximum_item_count: items,
        maximum_nesting_depth: 0,
        ..CanonicalDecodeLimits::default()
    };
    let tuple = CanonicalTuple::decode(body, &limits).map_err(|_| Error::Shape)?;
    if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != items {
        return Err(Error::Shape);
    }
    if tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0]
            .variable_value_bytes()
            .map_err(|_| Error::Shape)?
            != purpose.context().as_bytes()
        || tuple.items[1].item_type() != CanonicalItemType::Hash512
        || tuple.items[1].canonical_bytes() != owner.poll()
        || tuple.items[2].item_type() != CanonicalItemType::Hash512
        || tuple.items[2].canonical_bytes() != owner.inventory()
    {
        return Err(Error::Context);
    }
    if matches!(purpose, PublicationPurpose::Close) {
        if owner.position() != roster.proposal().organizer_position() {
            return Err(Error::Context);
        }
    } else {
        if tuple.items[3].item_type() != CanonicalItemType::Unsigned16
            || tuple.items[3].canonical_bytes() != (owner.position() as u16).to_le_bytes()
        {
            return Err(Error::Context);
        }
        match purpose {
            PublicationPurpose::Empty => {
                if tuple.items[4].item_type() != CanonicalItemType::Hash512 {
                    return Err(Error::Shape);
                }
                if tuple.items[4].canonical_bytes()
                    != identity(PublicationPurpose::Close, &close_body(owner)?)?
                {
                    return Err(Error::Context);
                }
            }
            PublicationPurpose::Witness => {
                if tuple.items[4].item_type() != CanonicalItemType::RawBytes
                    || tuple.items[4]
                        .variable_value_bytes()
                        .map_err(|_| Error::Shape)?
                        .len()
                        != ((count - 1) / 3) * 64
                {
                    return Err(Error::Shape);
                }
            }
            PublicationPurpose::Close => return Err(Error::Shape),
        }
    }
    Ok(tuple)
}
fn close_body(owner: &RetainedBallotOwner) -> Result<Vec<u8>, Error> {
    CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii(PublicationPurpose::Close.context())
                .map_err(|_| Error::Shape)?,
            CanonicalItem::hash512(*owner.poll()),
            CanonicalItem::hash512(*owner.inventory()),
        ],
    )
    .encode()
    .map_err(|_| Error::Shape)
}
impl Credential {
    /// Volatile signing beneath the authenticated participant root. The owning
    /// publication builder must supply the fully checked source dependencies;
    /// this method never creates a public publication or unspent-state value.
    pub fn sign_publication_message(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        purpose: PublicationPurpose,
        body: &[u8],
        close_signature: Option<&[u8]>,
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        self.check_ballot_owner(owner)?;
        let record = &roster
            .proposal()
            .records()
            .get(owner.position())
            .ok_or(Error::Context)?;
        if record.header().signing_public != self.signing_public
            || self.completed_body != Some(record.body_digest())
        {
            return Err(Error::Context);
        }
        let tuple = checked_body(owner, roster, purpose, body)?;
        match purpose {
            PublicationPurpose::Close => {
                self.check_unlocked(SigningPurpose::Close)?;
                if self.ballot_close_signed {
                    return Err(Error::Consumed);
                }
            }
            PublicationPurpose::Empty => {
                self.check_unlocked(SigningPurpose::Ballot)?;
                if self.ballot_signed || self.ballot_attempted {
                    return Err(Error::Consumed);
                }
                let close = close_body(owner)?;
                let close_identity = identity(PublicationPurpose::Close, &close)?;
                if tuple.items[4].canonical_bytes() != close_identity {
                    return Err(Error::Context);
                }
                let signature = close_signature
                    .ok_or(Error::Context)?
                    .try_into()
                    .map_err(|_| Error::Shape)?;
                let creator = &roster.proposal().records()[roster.proposal().organizer_position()];
                let key = ml_dsa_65::PublicKey::try_from_bytes(creator.header().signing_public)
                    .map_err(|_| Error::Crypto)?;
                if !key.verify(
                    &close_identity,
                    &signature,
                    PublicationPurpose::Close.context().as_bytes(),
                ) {
                    return Err(Error::Crypto);
                }
            }
            PublicationPurpose::Witness => {
                self.check_unlocked(SigningPurpose::Witness)?;
                if self.slot_witness_signed {
                    return Err(Error::Consumed);
                }
            }
        }
        let message = identity(purpose, body)?;
        match purpose {
            PublicationPurpose::Close => self.ballot_close_signed = true,
            PublicationPurpose::Empty => self.ballot_signed = true,
            PublicationPurpose::Witness => self.slot_witness_signed = true,
        }
        let coins = Zeroizing::new(coins);
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        key.try_sign_with_seed(&coins, &message, purpose.context().as_bytes())
            .map_err(|_| Error::Crypto)
    }
    /// Reconstructs consumed signature state only from the original root's
    /// authenticated completed message. It is not a receipt for unused authority.
    pub fn restore_publication_message(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        purpose: PublicationPurpose,
        body: &[u8],
        proof: &[u8],
    ) -> Result<(), Error> {
        self.check_ballot_owner(owner)?;
        let record = roster
            .proposal()
            .records()
            .get(owner.position())
            .ok_or(Error::Context)?;
        if self.completed_body != Some(record.body_digest())
            || record.header().signing_public != self.signing_public
        {
            return Err(Error::Context);
        }
        checked_body(owner, roster, purpose, body)?;
        let consumed = match purpose {
            PublicationPurpose::Close => self.ballot_close_signed,
            PublicationPurpose::Empty => self.ballot_signed || self.ballot_attempted,
            PublicationPurpose::Witness => self.slot_witness_signed,
        };
        if consumed {
            return Err(Error::Consumed);
        }
        let signature = proof.try_into().map_err(|_| Error::Shape)?;
        let key =
            ml_dsa_65::PublicKey::try_from_bytes(self.signing_public).map_err(|_| Error::Crypto)?;
        if !key.verify(
            &identity(purpose, body)?,
            &signature,
            purpose.context().as_bytes(),
        ) {
            return Err(Error::Crypto);
        }
        match purpose {
            PublicationPurpose::Close => self.ballot_close_signed = true,
            PublicationPurpose::Empty => self.ballot_signed = true,
            PublicationPurpose::Witness => self.slot_witness_signed = true,
        };
        Ok(())
    }
}
