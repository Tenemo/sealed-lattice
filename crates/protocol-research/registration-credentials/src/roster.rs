use crate::{
    Credential, Error,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
        participant_identity::{ParticipantIdentity, derive_participant_identity},
        schemas::{Roster, RosterEntry},
    },
    poll::VerifiedPoll,
    registration::VerifiedRegistration,
};
use std::sync::Arc;
use supported_profile::Profile;

/// A retained proposal is at most this long; the largest supported roster's
/// proposal fits.
pub const MAXIMUM_PROPOSAL_BYTES: usize = 2048;

/// Parsed context for private continuation after the current local root is authenticated.
/// This is not a verified public proposal and cannot initialize contribution generation.
#[derive(Clone)]
pub struct RetainedContributionContext {
    pub(crate) poll: [u8; 64],
    pub(crate) runtime: [u8; 64],
    pub(crate) proposal: [u8; 64],
    pub(crate) position: usize,
    pub(crate) owner_body: [u8; 64],
    profile: Profile,
    role: Vec<u8>,
}
impl RetainedContributionContext {
    /// The option count comes from the same retained poll whose identity the
    /// proposal names; together with the roster size it fixes the profile.
    /// The original verified registration must be this credential's completed
    /// body and occupy the requested proposal position before a role exists.
    pub fn parse(
        credential: &Credential,
        original: &VerifiedRegistration,
        options: usize,
        position: usize,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        let header = original.header();
        if credential.signing_public() != &header.signing_public
            || credential.completed_body != Some(original.body_digest())
        {
            return Err(Error::Context);
        }
        let (poll, runtime) = (header.poll, header.runtime);
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: MAXIMUM_PROPOSAL_BYTES,
            maximum_item_count: 4,
            maximum_item_byte_length: MAXIMUM_PROPOSAL_BYTES,
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
        let count = bodies
            .get(..4)
            .map(|count| u32::from_le_bytes(count.try_into().unwrap()) as usize)
            .ok_or(Error::Shape)?;
        let profile = Profile::new(count, options).map_err(|_| Error::Shape)?;
        if bodies.len() != 4 + count * 64 || position >= count {
            return Err(Error::Shape);
        }
        let owner_body = original.body_digest();
        if bodies[4 + 64 * position..4 + 64 * (position + 1)] != owner_body {
            return Err(Error::Context);
        }
        let proposal = hash_foundation_tuple_512(
            "sealed-lattice/roster-proposal-id/v1",
            &[CanonicalItem::variable_bytes(bytes).map_err(|_| Error::Shape)?],
        )
        .map_err(|_| Error::Shape)?
        .into_bytes();
        let role = contribution_role(original, proposal, position)?;
        Ok(Self {
            poll,
            runtime,
            proposal,
            position,
            owner_body,
            profile,
            role,
        })
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.proposal
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub(crate) fn role(&self) -> &[u8] {
        &self.role
    }
    /// The checkpoint's routing and profile must match this original owner
    /// before its sealed records are read. Noncontributors retain a context
    /// for ballots, but never import a contribution checkpoint.
    pub fn checkpoint_role(
        &self,
        prefix: &[u8],
        position: usize,
        profile: Profile,
    ) -> Result<&[u8], Error> {
        if prefix.len() != 192
            || prefix[..64] != self.poll
            || prefix[64..128] != self.runtime
            || prefix[128..] != self.proposal
            || position != self.position
            || position >= self.profile.setup_contributors()
            || profile != self.profile
        {
            return Err(Error::Context);
        }
        Ok(&self.role)
    }
}

/// A proposal names its poll and runtime and lists the registration count
/// and each registration's body digest.
fn encode_proposal(poll: [u8; 64], runtime: [u8; 64], bodies: Vec<u8>) -> Result<Vec<u8>, Error> {
    CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/roster-proposal/v1")
                .map_err(|_| Error::Shape)?,
            CanonicalItem::hash512(poll),
            CanonicalItem::hash512(runtime),
            CanonicalItem::variable_bytes(bodies).map_err(|_| Error::Shape)?,
        ],
    )
    .encode()
    .map_err(|_| Error::Shape)
}
/// A proposal of this many registrations has this exact encoded length.
pub fn proposal_bytes(participants: usize) -> usize {
    let mut bodies = Vec::from((participants as u32).to_le_bytes());
    bodies.resize(4 + 64 * participants, 0);
    encode_proposal([0; 64], [0; 64], bodies)
        .expect("A proposal of a supported size encodes.")
        .len()
}

pub struct RosterProposal {
    identity: [u8; 64],
    body: Vec<u8>,
    records: Vec<Arc<VerifiedRegistration>>,
    organizer_position: usize,
    profile: Profile,
}
impl RosterProposal {
    pub fn new(
        poll: &VerifiedPoll,
        records: Vec<Arc<VerifiedRegistration>>,
    ) -> Result<Self, Error> {
        // Every supported roster size has a profile for every option count
        // a poll can have; another size, or one above the poll's maximum, is
        // refused before any preparation.
        let profile = Profile::new(records.len(), poll.manifest().option_count())
            .map_err(|_| Error::Shape)?;
        if records.len() > usize::from(poll.maximum_participants()) {
            return Err(Error::Context);
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
                RosterEntry::new(position as u16, header.signing_public)
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
        // The roster refuses a repeated signing key or identity.
        Roster::new(entries).map_err(|_| Error::Shape)?;
        let body = encode_proposal(poll.identity(), poll.runtime(), bodies)?;
        let identity = hash_foundation_tuple_512(
            "sealed-lattice/roster-proposal-id/v1",
            &[CanonicalItem::variable_bytes(&body).map_err(|_| Error::Shape)?],
        )
        .map_err(|_| Error::Shape)?
        .into_bytes();
        Ok(Self {
            identity,
            body,
            records,
            organizer_position,
            profile,
        })
    }
    pub fn profile(&self) -> Profile {
        self.profile
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
    pub fn records(&self) -> &[Arc<VerifiedRegistration>] {
        &self.records
    }
    pub fn organizer_position(&self) -> usize {
        self.organizer_position
    }
    /// The proof role of a setup contributor's contribution.
    pub fn contribution_role(&self, position: usize) -> Result<Vec<u8>, Error> {
        if position >= self.records.len() {
            return Err(Error::Shape);
        }
        if position >= self.profile.setup_contributors() {
            return Err(Error::Context);
        }
        contribution_role(&self.records[position], self.identity, position)
    }
}

fn contribution_role(
    original: &VerifiedRegistration,
    proposal: [u8; 64],
    position: usize,
) -> Result<Vec<u8>, Error> {
    let header = original.header();
    encode_contribution_role(
        header.poll,
        header.runtime,
        proposal,
        position,
        derive_participant_identity(&header.signing_public).map_err(|_| Error::Shape)?,
    )
}

// Byte encoding alone supplies no original-owner or contribution authority.
pub(crate) fn encode_contribution_role(
    poll: [u8; 64],
    runtime: [u8; 64],
    proposal: [u8; 64],
    position: usize,
    participant_identity: ParticipantIdentity,
) -> Result<Vec<u8>, Error> {
    if position >= *Profile::participant_range().end() {
        return Err(Error::Shape);
    }
    let role = CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/setup-contribution/v2")
                .map_err(|_| Error::Shape)?,
            CanonicalItem::nonempty_ascii(&participant_identity.to_lowercase_hex())
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
