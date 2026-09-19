use crate::{
    Error,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
        schemas::{Roster, RosterEntry},
    },
    poll::VerifiedPoll,
    registration::VerifiedRegistration,
};
use std::sync::Arc;

/// Parsed context for private continuation after the current local root is authenticated.
/// This is not a verified public proposal and cannot initialize contribution generation.
#[derive(Clone)]
pub struct RetainedContributionContext {
    pub(crate) poll: [u8; 64],
    pub(crate) runtime: [u8; 64],
    pub(crate) proposal: [u8; 64],
    pub(crate) position: usize,
    pub(crate) owner_body: [u8; 64],
    role: Vec<u8>,
}
impl RetainedContributionContext {
    pub fn parse(
        poll: [u8; 64],
        runtime: [u8; 64],
        position: usize,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: 2048,
            maximum_item_count: 4,
            maximum_item_byte_length: 2048,
            maximum_nesting_depth: 1,
            maximum_cumulative_work_byte_length: 8192,
            maximum_cumulative_allocation_byte_length: 8192,
        };
        let tuple = CanonicalTuple::decode(bytes, &limits).map_err(|_| Error::Shape)?;
        if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != 4 {
            return Err(Error::Shape);
        }
        let items = &tuple.items;
        if items[0].item_type() != CanonicalItemType::Ascii
            || items[0].variable_value_bytes().map_err(|_| Error::Shape)?
                != b"sealed-lattice/roster-proposal/v1"
            || items[1].item_type() != CanonicalItemType::Hash512
            || items[1].canonical_bytes() != poll
            || items[2].item_type() != CanonicalItemType::Hash512
            || items[2].canonical_bytes() != runtime
            || items[3].item_type() != CanonicalItemType::RawBytes
        {
            return Err(Error::Context);
        }
        let bodies = items[3].variable_value_bytes().map_err(|_| Error::Shape)?;
        if bodies.len() != 4 + 10 * 64
            || u32::from_le_bytes(bodies[..4].try_into().unwrap()) != 10
            || position >= 10
        {
            return Err(Error::Shape);
        }
        let proposal = hash_foundation_tuple_512(
            "sealed-lattice/roster-proposal-id/v1",
            &[CanonicalItem::variable_bytes(bytes).map_err(|_| Error::Shape)?],
        )
        .map_err(|_| Error::Shape)?
        .into_bytes();
        let role = contribution_role_from_context(poll, runtime, proposal, position)?;
        Ok(Self {
            poll,
            runtime,
            proposal,
            position,
            owner_body: bodies[4 + 64 * position..4 + 64 * (position + 1)]
                .try_into()
                .unwrap(),
            role,
        })
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.proposal
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub(crate) fn role(&self) -> &[u8] {
        &self.role
    }
}

pub struct RosterProposal {
    poll: [u8; 64],
    runtime: [u8; 64],
    identity: [u8; 64],
    body: Vec<u8>,
    records: Vec<Arc<VerifiedRegistration>>,
    canonical_roster: Vec<u8>,
    organizer_position: usize,
}
impl RosterProposal {
    pub fn new(
        poll: &VerifiedPoll,
        records: Vec<Arc<VerifiedRegistration>>,
    ) -> Result<Self, Error> {
        if !(3..=20).contains(&records.len()) {
            return Err(Error::Shape);
        }
        let mut entries = Vec::with_capacity(records.len());
        let mut bodies = Vec::with_capacity(4 + 64 * records.len());
        bodies.extend((records.len() as u32).to_le_bytes());
        let mut organizer_position = None;
        for (position, record) in records.iter().enumerate() {
            let header = record.header();
            if header.poll != poll.identity() || header.runtime != poll.runtime() {
                return Err(Error::Context);
            }
            entries.push(
                RosterEntry::new(
                    position as u16,
                    header.signing_public,
                    header.mailbox_public,
                )
                .map_err(|_| Error::Shape)?,
            );
            bodies.extend(record.body_digest());
            if &header.signing_public == poll.organizer()
                && organizer_position.replace(position).is_some()
            {
                return Err(Error::Shape);
            }
        }
        let organizer_position = organizer_position.ok_or(Error::Context)?;
        let canonical_roster = Roster::new(entries)
            .map_err(|_| Error::Shape)?
            .encode()
            .map_err(|_| Error::Shape)?;
        let body = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii("sealed-lattice/roster-proposal/v1")
                    .map_err(|_| Error::Shape)?,
                CanonicalItem::hash512(poll.identity()),
                CanonicalItem::hash512(poll.runtime()),
                CanonicalItem::variable_bytes(bodies).map_err(|_| Error::Shape)?,
            ],
        )
        .encode()
        .map_err(|_| Error::Shape)?;
        let identity = hash_foundation_tuple_512(
            "sealed-lattice/roster-proposal-id/v1",
            &[CanonicalItem::variable_bytes(&body).map_err(|_| Error::Shape)?],
        )
        .map_err(|_| Error::Shape)?
        .into_bytes();
        Ok(Self {
            poll: poll.identity(),
            runtime: poll.runtime(),
            identity,
            body,
            records,
            canonical_roster,
            organizer_position,
        })
    }
    pub fn identity(&self) -> [u8; 64] {
        self.identity
    }
    pub fn identity_bytes(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn canonical_roster(&self) -> &[u8] {
        &self.canonical_roster
    }
    pub fn records(&self) -> &[Arc<VerifiedRegistration>] {
        &self.records
    }
    pub fn organizer_position(&self) -> usize {
        self.organizer_position
    }
    pub fn contribution_role(&self, position: usize) -> Result<Vec<u8>, Error> {
        if self.records.len() != 10 || position >= self.records.len() {
            return Err(Error::Shape);
        }
        contribution_role_from_context(self.poll, self.runtime, self.identity, position)
    }
}

pub fn contribution_role_from_context(
    poll: [u8; 64],
    runtime: [u8; 64],
    proposal: [u8; 64],
    position: usize,
) -> Result<Vec<u8>, Error> {
    if position >= 10 {
        return Err(Error::Shape);
    }
    let role = CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/setup-contribution/v1")
                .map_err(|_| Error::Shape)?,
            CanonicalItem::hash512(poll),
            CanonicalItem::hash512(runtime),
            CanonicalItem::hash512(proposal),
            CanonicalItem::unsigned16(position as u16),
        ],
    )
    .encode()
    .map_err(|_| Error::Shape)?;
    if role.len() > 1024 {
        return Err(Error::Shape);
    }
    Ok(role)
}
