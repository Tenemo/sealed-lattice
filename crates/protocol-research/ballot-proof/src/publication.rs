use crate::submission::AuthenticatedBallotBody;
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use registration_credentials::{
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    poll::VerifiedPoll,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

pub const CLOSE_PURPOSE: &str = "sealed-lattice/ballot-close/v1";
pub const EMPTY_PURPOSE: &str = "sealed-lattice/empty-slot/v1";
pub const WITNESS_PURPOSE: &str = "sealed-lattice/slot-witness/v1";
const MAXIMUM_MESSAGE_BYTES: usize = 2_048;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Context,
    Signature,
    Incomplete,
}

fn identity(domain: &str, bytes: &[u8]) -> Result<[u8; 64], Error> {
    hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(bytes).map_err(|_| Error::Shape)?],
    )
    .map(|value| value.into_bytes())
    .map_err(|_| Error::Shape)
}
fn encode(
    purpose: &str,
    poll: [u8; 64],
    inventory: [u8; 64],
    mut rest: Vec<CanonicalItem>,
) -> Result<Vec<u8>, Error> {
    let mut items = vec![
        CanonicalItem::nonempty_ascii(purpose).map_err(|_| Error::Shape)?,
        CanonicalItem::hash512(poll),
        CanonicalItem::hash512(inventory),
    ];
    items.append(&mut rest);
    let bytes = CanonicalTuple::new(1, 1, items)
        .encode()
        .map_err(|_| Error::Shape)?;
    if bytes.len() > MAXIMUM_MESSAGE_BYTES {
        return Err(Error::Shape);
    }
    Ok(bytes)
}
fn decode(
    bytes: &[u8],
    purpose: &str,
    poll: &[u8; 64],
    inventory: &[u8; 64],
    item_count: usize,
) -> Result<CanonicalTuple, Error> {
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_MESSAGE_BYTES,
        maximum_item_count: item_count,
        maximum_item_byte_length: MAXIMUM_MESSAGE_BYTES,
        maximum_nesting_depth: 0,
        ..CanonicalDecodeLimits::default()
    };
    let tuple = CanonicalTuple::decode(bytes, &limits).map_err(|_| Error::Shape)?;
    if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != item_count
    {
        return Err(Error::Shape);
    }
    if tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0]
            .variable_value_bytes()
            .map_err(|_| Error::Shape)?
            != purpose.as_bytes()
        || tuple.items[1].item_type() != CanonicalItemType::Hash512
        || tuple.items[1].canonical_bytes() != poll
        || tuple.items[2].item_type() != CanonicalItemType::Hash512
        || tuple.items[2].canonical_bytes() != inventory
    {
        return Err(Error::Context);
    }
    Ok(tuple)
}
fn position(item: &CanonicalItem, count: usize) -> Result<usize, Error> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(Error::Shape);
    }
    let value = usize::from(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| Error::Shape)?,
    ));
    if value >= count {
        return Err(Error::Context);
    }
    Ok(value)
}
fn hash_item(item: &CanonicalItem) -> Result<[u8; 64], Error> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(Error::Shape);
    }
    item.canonical_bytes().try_into().map_err(|_| Error::Shape)
}
fn signature(
    key: &[u8; 1952],
    body: &[u8],
    bytes: &[u8],
    purpose: &str,
) -> Result<[u8; 3309], Error> {
    let signature: [u8; 3309] = bytes.try_into().map_err(|_| Error::Shape)?;
    let key = ml_dsa_65::PublicKey::try_from_bytes(*key).map_err(|_| Error::Signature)?;
    if !key.verify(&identity(purpose, body)?, &signature, purpose.as_bytes()) {
        return Err(Error::Signature);
    }
    Ok(signature)
}

/// Only the owning public setup verifier can supply this context.
pub struct PublicationContext {
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
}
impl PublicationContext {
    pub fn new(poll: Arc<VerifiedPoll>, setup: Arc<VerifiedSetupAggregate>) -> Result<Self, Error> {
        let proposal = setup.inventory().proposal().proposal();
        if !(3..=20).contains(&proposal.records().len())
            || proposal
                .records()
                .iter()
                .any(|record| record.header().poll != poll.identity())
            || proposal.records()[proposal.organizer_position()]
                .header()
                .signing_public
                != *poll.organizer()
        {
            return Err(Error::Context);
        }
        Ok(Self { poll, setup })
    }
    pub fn participant_count(&self) -> usize {
        self.setup.inventory().confirmations().len()
    }
    pub fn assigned_sources(&self, witness: usize) -> Result<Vec<usize>, Error> {
        assignments(self.participant_count(), witness)
    }
    fn key(&self, signer: usize) -> Result<&[u8; 1952], Error> {
        self.setup
            .inventory()
            .proposal()
            .proposal()
            .records()
            .get(signer)
            .map(|record| &record.header().signing_public)
            .ok_or(Error::Context)
    }
    pub fn close_body(&self) -> Result<Vec<u8>, Error> {
        encode(
            CLOSE_PURPOSE,
            self.poll.identity(),
            self.setup.inventory().identity(),
            vec![],
        )
    }
    pub fn authenticate_close(
        &self,
        body: &[u8],
        proof: &[u8],
    ) -> Result<AuthenticatedClose, Error> {
        decode(
            body,
            CLOSE_PURPOSE,
            &self.poll.identity(),
            &self.setup.inventory().identity(),
            3,
        )?;
        if body != self.close_body()? {
            return Err(Error::Shape);
        }
        let proof = signature(self.poll.organizer(), body, proof, CLOSE_PURPOSE)?;
        Ok(AuthenticatedClose {
            body: body.to_vec(),
            signature: proof,
            identity: identity(CLOSE_PURPOSE, body)?,
        })
    }
    fn check_close(&self, close: &AuthenticatedClose) -> Result<(), Error> {
        if close.body != self.close_body()? {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn empty_body(&self, close: &AuthenticatedClose, author: usize) -> Result<Vec<u8>, Error> {
        self.check_close(close)?;
        self.key(author)?;
        encode(
            EMPTY_PURPOSE,
            self.poll.identity(),
            self.setup.inventory().identity(),
            vec![
                CanonicalItem::unsigned16(author as u16),
                CanonicalItem::hash512(close.identity),
            ],
        )
    }
    pub fn authenticate_empty(
        &self,
        close: &AuthenticatedClose,
        body: &[u8],
        proof: &[u8],
    ) -> Result<AuthenticatedSource, Error> {
        self.check_close(close)?;
        let tuple = decode(
            body,
            EMPTY_PURPOSE,
            &self.poll.identity(),
            &self.setup.inventory().identity(),
            5,
        )?;
        let author = position(&tuple.items[3], self.participant_count())?;
        if hash_item(&tuple.items[4])? != close.identity
            || body != self.empty_body(close, author)?
        {
            return Err(Error::Context);
        }
        let proof = signature(self.key(author)?, body, proof, EMPTY_PURPOSE)?;
        Ok(AuthenticatedSource {
            author,
            identity: source_identity(0, body)?,
            value: SourceValue::Empty {
                body: body.to_vec(),
                signature: proof,
            },
        })
    }
    pub fn ballot_source(
        &self,
        body: AuthenticatedBallotBody,
    ) -> Result<AuthenticatedSource, Error> {
        let envelope = body.authentication().envelope();
        if envelope.poll() != &self.poll.identity()
            || envelope.inventory() != &self.setup.inventory().identity()
        {
            return Err(Error::Context);
        }
        self.key(envelope.position())?;
        Ok(AuthenticatedSource {
            author: envelope.position(),
            identity: source_identity(1, envelope.bytes())?,
            value: SourceValue::Ballot(body),
        })
    }
    pub fn witness_body(
        &self,
        witness: usize,
        sources: &[&AuthenticatedSource],
    ) -> Result<Vec<u8>, Error> {
        let assigned = self.assigned_sources(witness)?;
        if sources.len() != assigned.len()
            || sources
                .iter()
                .zip(assigned)
                .any(|(source, author)| source.author != author)
        {
            return Err(Error::Incomplete);
        }
        let mut identities = Vec::with_capacity(sources.len() * 64);
        for source in sources {
            self.check_source(source)?;
            identities.extend(source.identity);
        }
        encode(
            WITNESS_PURPOSE,
            self.poll.identity(),
            self.setup.inventory().identity(),
            vec![
                CanonicalItem::unsigned16(witness as u16),
                CanonicalItem::variable_bytes(identities).map_err(|_| Error::Shape)?,
            ],
        )
    }
    pub fn authenticate_witness(
        &self,
        body: &[u8],
        proof: &[u8],
    ) -> Result<AuthenticatedWitnessBatch, Error> {
        let tuple = decode(
            body,
            WITNESS_PURPOSE,
            &self.poll.identity(),
            &self.setup.inventory().identity(),
            5,
        )?;
        let signer = position(&tuple.items[3], self.participant_count())?;
        if tuple.items[4].item_type() != CanonicalItemType::RawBytes {
            return Err(Error::Shape);
        }
        let bytes = tuple.items[4]
            .variable_value_bytes()
            .map_err(|_| Error::Shape)?;
        let assigned = self.assigned_sources(signer)?;
        if bytes.len() != assigned.len() * 64 {
            return Err(Error::Shape);
        }
        let identities = bytes
            .chunks_exact(64)
            .map(|value| value.try_into().map_err(|_| Error::Shape))
            .collect::<Result<Vec<[u8; 64]>, Error>>()?;
        let proof = signature(self.key(signer)?, body, proof, WITNESS_PURPOSE)?;
        Ok(AuthenticatedWitnessBatch {
            signer,
            identities,
            body: body.to_vec(),
            signature: proof,
        })
    }
    fn check_source(&self, source: &AuthenticatedSource) -> Result<(), Error> {
        match &source.value {
            SourceValue::Ballot(body) => {
                let envelope = body.authentication().envelope();
                if envelope.poll() != &self.poll.identity()
                    || envelope.inventory() != &self.setup.inventory().identity()
                    || envelope.position() != source.author
                {
                    return Err(Error::Context);
                }
            }
            SourceValue::Empty { body, .. } => {
                decode(
                    body,
                    EMPTY_PURPOSE,
                    &self.poll.identity(),
                    &self.setup.inventory().identity(),
                    5,
                )?;
            }
        }
        Ok(())
    }
    pub fn verify_slot(
        &self,
        source: AuthenticatedSource,
        batches: Vec<AuthenticatedWitnessBatch>,
    ) -> Result<VerifiedSlotEvidence, Error> {
        self.check_source(&source)?;
        let required = witnesses(self.participant_count(), source.author)?;
        if batches.len() != required.len() {
            return Err(Error::Incomplete);
        }
        for (batch, signer) in batches.iter().zip(required) {
            if batch.signer != signer {
                return Err(Error::Context);
            }
            decode(
                &batch.body,
                WITNESS_PURPOSE,
                &self.poll.identity(),
                &self.setup.inventory().identity(),
                5,
            )?;
            let assigned = self.assigned_sources(signer)?;
            let offset = assigned
                .iter()
                .position(|author| *author == source.author)
                .ok_or(Error::Context)?;
            if batch.identities.get(offset) != Some(&source.identity) {
                return Err(Error::Context);
            }
        }
        Ok(VerifiedSlotEvidence { source, batches })
    }
    pub fn verify_closed_slots(
        &self,
        close: AuthenticatedClose,
        slots: Vec<VerifiedSlotEvidence>,
    ) -> Result<VerifiedClosedSlots, Error> {
        self.check_close(&close)?;
        if slots.len() != self.participant_count() {
            return Err(Error::Incomplete);
        }
        let mut identities = Vec::with_capacity(slots.len() * 64);
        for (author, slot) in slots.iter().enumerate() {
            self.check_source(&slot.source)?;
            if slot.source.author != author {
                return Err(Error::Context);
            }
            if let SourceValue::Empty { body, .. } = &slot.source.value
                && body != &self.empty_body(&close, author)?
            {
                return Err(Error::Context);
            }
            identities.extend(slot.source.identity);
        }
        let body = encode(
            "sealed-lattice/closed-slots/v1",
            self.poll.identity(),
            self.setup.inventory().identity(),
            vec![
                CanonicalItem::hash512(close.identity),
                CanonicalItem::variable_bytes(identities).map_err(|_| Error::Shape)?,
            ],
        )?;
        let identity = identity("sealed-lattice/closed-slots-id/v1", &body)?;
        Ok(VerifiedClosedSlots {
            close,
            slots,
            body,
            identity,
        })
    }
}

fn assignments(count: usize, witness: usize) -> Result<Vec<usize>, Error> {
    if !(3..=20).contains(&count) || witness >= count {
        return Err(Error::Context);
    }
    let fault_bound = (count - 1) / 3;
    Ok((0..count)
        .filter(|author| *author != witness && (witness + count - author) % count <= fault_bound)
        .collect())
}
fn witnesses(count: usize, author: usize) -> Result<Vec<usize>, Error> {
    if !(3..=20).contains(&count) || author >= count {
        return Err(Error::Context);
    }
    let mut witnesses: Vec<_> = (1..=(count - 1) / 3)
        .map(|offset| (author + offset) % count)
        .collect();
    witnesses.sort_unstable();
    Ok(witnesses)
}
fn source_identity(kind: u16, body: &[u8]) -> Result<[u8; 64], Error> {
    hash_foundation_tuple_512(
        "sealed-lattice/slot-source/v1",
        &[
            CanonicalItem::unsigned16(kind),
            CanonicalItem::variable_bytes(body).map_err(|_| Error::Shape)?,
        ],
    )
    .map(|value| value.into_bytes())
    .map_err(|_| Error::Shape)
}

#[derive(Clone)]
pub struct AuthenticatedClose {
    body: Vec<u8>,
    signature: [u8; 3309],
    identity: [u8; 64],
}
impl AuthenticatedClose {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
}
#[derive(Clone)]
pub enum SourceValue {
    Ballot(AuthenticatedBallotBody),
    Empty {
        body: Vec<u8>,
        signature: [u8; 3309],
    },
}
#[derive(Clone)]
pub struct AuthenticatedSource {
    author: usize,
    identity: [u8; 64],
    value: SourceValue,
}
impl AuthenticatedSource {
    pub fn author(&self) -> usize {
        self.author
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn value(&self) -> &SourceValue {
        &self.value
    }
}
#[derive(Clone)]
pub struct AuthenticatedWitnessBatch {
    signer: usize,
    identities: Vec<[u8; 64]>,
    body: Vec<u8>,
    signature: [u8; 3309],
}
impl AuthenticatedWitnessBatch {
    pub fn signer(&self) -> usize {
        self.signer
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}
/// Signature/body correspondence only. Durable publication and later inner-proof
/// classification are separate obligations; this is not a release capability.
#[derive(Clone)]
pub struct VerifiedSlotEvidence {
    source: AuthenticatedSource,
    batches: Vec<AuthenticatedWitnessBatch>,
}
impl VerifiedSlotEvidence {
    pub fn source(&self) -> &AuthenticatedSource {
        &self.source
    }
    pub fn batches(&self) -> &[AuthenticatedWitnessBatch] {
        &self.batches
    }
}
pub struct VerifiedClosedSlots {
    close: AuthenticatedClose,
    slots: Vec<VerifiedSlotEvidence>,
    body: Vec<u8>,
    identity: [u8; 64],
}
impl VerifiedClosedSlots {
    pub fn close(&self) -> &AuthenticatedClose {
        &self.close
    }
    pub fn slots(&self) -> &[VerifiedSlotEvidence] {
        &self.slots
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::{KeyGen, Signer};

    #[test]
    fn assignments_are_the_transpose_of_fixed_witness_sets() {
        for count in 3..=20 {
            for author in 0..count {
                let required = witnesses(count, author).unwrap();
                assert_eq!(required.len(), (count - 1) / 3);
                for witness in 0..count {
                    assert_eq!(
                        required.contains(&witness),
                        assignments(count, witness).unwrap().contains(&author)
                    );
                }
            }
            assert!(witnesses(count, count).is_err());
            assert!(assignments(count, count).is_err());
        }
    }

    #[test]
    fn messages_bind_context_types_complete_lengths_and_signature_purposes() {
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&[9; 32]);
        let key = public.into_bytes();
        for purpose in [CLOSE_PURPOSE, EMPTY_PURPOSE, WITNESS_PURPOSE] {
            let rest = match purpose {
                CLOSE_PURPOSE => vec![],
                EMPTY_PURPOSE => vec![
                    CanonicalItem::unsigned16(2),
                    CanonicalItem::hash512([3; 64]),
                ],
                _ => vec![
                    CanonicalItem::unsigned16(2),
                    CanonicalItem::variable_bytes([3; 192]).unwrap(),
                ],
            };
            let body = encode(purpose, [1; 64], [2; 64], rest).unwrap();
            let fields = if purpose == CLOSE_PURPOSE { 3 } else { 5 };
            assert!(decode(&body, purpose, &[1; 64], &[2; 64], fields).is_ok());
            let proof = private
                .try_sign_with_seed(
                    &[10; 32],
                    &identity(purpose, &body).unwrap(),
                    purpose.as_bytes(),
                )
                .unwrap();
            assert!(signature(&key, &body, &proof, purpose).is_ok());
            assert!(decode(&body, purpose, &[4; 64], &[2; 64], fields).is_err());
            assert!(decode(&body, purpose, &[1; 64], &[4; 64], fields).is_err());
            let mut changed = body.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(signature(&key, &changed, &proof, purpose).is_err());
            assert!(signature(&key, &body, &proof, "sealed-lattice/other/v1").is_err());
            let mut extra = body.clone();
            extra.push(0);
            assert!(decode(&extra, purpose, &[1; 64], &[2; 64], fields).is_err());
            assert!(decode(&body[..body.len() - 1], purpose, &[1; 64], &[2; 64], fields).is_err());
        }
        assert!(
            decode(
                &vec![0; MAXIMUM_MESSAGE_BYTES + 1],
                CLOSE_PURPOSE,
                &[1; 64],
                &[2; 64],
                3
            )
            .is_err()
        );
        let maximum = encode(
            "sealed-lattice/closed-slots/v1",
            [1; 64],
            [2; 64],
            vec![
                CanonicalItem::hash512([3; 64]),
                CanonicalItem::variable_bytes([4; 20 * 64]).unwrap(),
            ],
        )
        .unwrap();
        assert!(maximum.len() > 1024 && maximum.len() <= MAXIMUM_MESSAGE_BYTES);
        assert_ne!(
            source_identity(0, b"same bytes").unwrap(),
            source_identity(1, b"same bytes").unwrap()
        );
    }
}
