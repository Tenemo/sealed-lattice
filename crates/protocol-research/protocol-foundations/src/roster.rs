use crate::{
    Credential, Refusal,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
        participant_identity::{ParticipantIdentity, derive_participant_identity},
    },
    poll::VerifiedPoll,
    registration::VerifiedRegistration,
};
use std::{collections::BTreeSet, sync::Arc};
use supported_profile::Profile;

/// A retained proposal is at most this long; the largest supported roster's
/// proposal fits.
pub const MAXIMUM_PROPOSAL_BYTES: usize = 2048;
/// The proposal's purpose, which is also the organizer's signature context.
pub(crate) const PROPOSAL_PURPOSE: &str = "sealed-lattice/roster-proposal";
const PROPOSAL_IDENTITY_DOMAIN: &str = "sealed-lattice/roster-proposal-identity";

/// Parsed context for private continuation after the current local root is authenticated.
/// This is not a verified public proposal and cannot initialize contribution generation.
#[derive(Clone)]
pub struct RetainedContributionContext {
    pub(crate) poll: [u8; 64],
    pub(crate) proposal: [u8; 64],
    pub(crate) position: usize,
    pub(crate) owner_body: [u8; 64],
    profile: Profile,
    role: Vec<u8>,
    source_binding: [u8; 64],
}
impl RetainedContributionContext {
    /// The verified poll fixes both the profile's option count and the
    /// original registration's complete source family inventory.
    /// The original verified registration must be this credential's completed
    /// body and occupy the requested proposal position before a role exists.
    pub fn parse(
        credential: &Credential,
        original: &VerifiedRegistration,
        verified_poll: &VerifiedPoll,
        position: usize,
        bytes: &[u8],
    ) -> Result<Self, Refusal> {
        let header = original.header();
        if credential.signing_public() != &header.signing_public
            || credential.completed_body != Some(original.body_digest())
            || header.poll != verified_poll.identity()
            || header.source_bindings.len()
                != crate::source_binding::fhe_key_families(verified_poll).len()
        {
            return Err(Refusal::Context);
        }
        let poll = header.poll;
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: MAXIMUM_PROPOSAL_BYTES,
            maximum_item_count: 3,
            maximum_item_byte_length: MAXIMUM_PROPOSAL_BYTES,
            maximum_nesting_depth: 1,
            maximum_cumulative_work_byte_length: 8192,
            maximum_cumulative_allocation_byte_length: 8192,
        };
        let tuple = CanonicalTuple::decode(bytes, &limits).map_err(|_| Refusal::Shape)?;
        if !tuple.has_header(3) {
            return Err(Refusal::Shape);
        }
        let items = &tuple.items;
        if items[0].item_type() != CanonicalItemType::Ascii
            || items[0]
                .variable_value_bytes()
                .map_err(|_| Refusal::Shape)?
                != PROPOSAL_PURPOSE.as_bytes()
            || items[1].item_type() != CanonicalItemType::Hash512
            || items[1].canonical_bytes() != poll
            || items[2].item_type() != CanonicalItemType::RawBytes
        {
            return Err(Refusal::Context);
        }
        let bodies = items[2]
            .variable_value_bytes()
            .map_err(|_| Refusal::Shape)?;
        let count = bodies
            .get(..4)
            .map(|count| u32::from_le_bytes(count.try_into().unwrap()) as usize)
            .ok_or(Refusal::Shape)?;
        let profile = Profile::new(count, verified_poll.manifest().option_count())
            .map_err(|_| Refusal::Shape)?;
        let family = crate::source_binding::fhe_key_family_index(verified_poll, profile)?;
        let source_binding = *header.source_bindings.get(family).ok_or(Refusal::Context)?;
        if bodies.len() != 4 + count * 64 || position >= count {
            return Err(Refusal::Shape);
        }
        let owner_body = original.body_digest();
        if bodies[4 + 64 * position..4 + 64 * (position + 1)] != owner_body {
            return Err(Refusal::Context);
        }
        let proposal = hash_foundation_tuple_512(
            PROPOSAL_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(bytes).map_err(|_| Refusal::Shape)?],
        )
        .map_err(|_| Refusal::Shape)?
        .into_bytes();
        let role = contribution_role(original, proposal, position)?;
        Ok(Self {
            poll,
            proposal,
            position,
            owner_body,
            profile,
            role,
            source_binding,
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
    pub fn source_binding(&self) -> &[u8; 64] {
        &self.source_binding
    }
    /// The checkpoint's routing, the poll and proposal identities, and its
    /// profile must match this original owner before its sealed records are
    /// read. Noncontributors retain a context for ballots, but never import
    /// a contribution checkpoint.
    pub fn checkpoint_role(
        &self,
        prefix: &[u8],
        position: usize,
        profile: Profile,
    ) -> Result<&[u8], Refusal> {
        if prefix.len() != 128
            || prefix[..64] != self.poll
            || prefix[64..] != self.proposal
            || position != self.position
            || position >= self.profile.setup_eligible_contributors()
            || profile != self.profile
        {
            return Err(Refusal::Context);
        }
        Ok(&self.role)
    }
}

/// A proposal names its poll and lists the registration count and each
/// registration's body digest.
fn encode_proposal(poll: [u8; 64], bodies: Vec<u8>) -> Result<Vec<u8>, Refusal> {
    CanonicalTuple::new(
        1,
        vec![
            CanonicalItem::nonempty_ascii(PROPOSAL_PURPOSE).map_err(|_| Refusal::Shape)?,
            CanonicalItem::hash512(poll),
            CanonicalItem::variable_bytes(bodies).map_err(|_| Refusal::Shape)?,
        ],
    )
    .encode()
    .map_err(|_| Refusal::Shape)
}
/// A proposal of this many registrations has this exact encoded length.
pub fn proposal_bytes(participants: usize) -> usize {
    let mut bodies = Vec::from((participants as u32).to_le_bytes());
    bodies.resize(4 + 64 * participants, 0);
    encode_proposal([0; 64], bodies)
        .expect("A proposal of a supported size encodes.")
        .len()
}

pub struct RosterProposal {
    identity: [u8; 64],
    body: Vec<u8>,
    records: Vec<Arc<VerifiedRegistration>>,
    organizer_position: usize,
    profile: Profile,
    fhe_key_family_index: usize,
}
impl RosterProposal {
    pub fn new(
        poll: &VerifiedPoll,
        records: Vec<Arc<VerifiedRegistration>>,
    ) -> Result<Self, Refusal> {
        // Every supported roster size has a profile for every option count
        // a poll can have; another size, or one above the poll's maximum, is
        // refused before any preparation.
        let profile = Profile::new(records.len(), poll.manifest().option_count())
            .map_err(|_| Refusal::Shape)?;
        if records.len() > usize::from(poll.maximum_participants()) {
            return Err(Refusal::Context);
        }
        let fhe_key_family_index = crate::source_binding::fhe_key_family_index(poll, profile)?;
        let family_count = crate::source_binding::fhe_key_families(poll).len();
        let mut bodies = Vec::with_capacity(4 + 64 * records.len());
        bodies.extend((records.len() as u32).to_le_bytes());
        let mut organizer_position = None;
        for (position, record) in records.iter().enumerate() {
            let header = record.header();
            if header.poll != poll.identity() || header.source_bindings.len() != family_count {
                return Err(Refusal::Context);
            }
            bodies.extend(record.body_digest());
            if &header.signing_public == poll.organizer()
                && organizer_position.replace(position).is_some()
            {
                return Err(Refusal::Shape);
            }
        }
        let organizer_position = organizer_position.ok_or(Refusal::Context)?;
        // The roster refuses a repeated signing key or participant identity.
        // Distinct keys derive distinct identities only outside a collision of
        // the identity hash, so the identities are compared as well.
        let mut signing_keys = BTreeSet::new();
        let mut participant_identities = BTreeSet::new();
        for record in &records {
            let signing_public = &record.header().signing_public;
            let identity =
                derive_participant_identity(signing_public).map_err(|_| Refusal::Shape)?;
            if !signing_keys.insert(signing_public) || !participant_identities.insert(identity) {
                return Err(Refusal::Shape);
            }
        }
        let body = encode_proposal(poll.identity(), bodies)?;
        let identity = hash_foundation_tuple_512(
            PROPOSAL_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(&body).map_err(|_| Refusal::Shape)?],
        )
        .map_err(|_| Refusal::Shape)?
        .into_bytes();
        Ok(Self {
            identity,
            body,
            records,
            organizer_position,
            profile,
            fhe_key_family_index,
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
    /// The original registration commitment for this roster's exact FHE
    /// modulus and common-sampler family.
    pub fn source_binding(&self, position: usize) -> Result<&[u8; 64], Refusal> {
        self.records
            .get(position)
            .and_then(|record| {
                record
                    .header()
                    .source_bindings
                    .get(self.fhe_key_family_index)
            })
            .ok_or(Refusal::Context)
    }
    /// Byte range of this roster's family in each original registration's
    /// canonical ciphertext inventory. This is transport metadata only.
    pub fn source_ciphertext_range(&self) -> std::ops::Range<usize> {
        let bytes = setup_witness::encrypted_source::ciphertext_bytes();
        let start = self.fhe_key_family_index * bytes;
        start..start + bytes
    }
    pub fn organizer_position(&self) -> usize {
        self.organizer_position
    }
    /// The proof role of a setup contributor's contribution.
    pub fn contribution_role(&self, position: usize) -> Result<Vec<u8>, Refusal> {
        if position >= self.records.len() {
            return Err(Refusal::Shape);
        }
        if position >= self.profile.setup_eligible_contributors() {
            return Err(Refusal::Context);
        }
        contribution_role(&self.records[position], self.identity, position)
    }
}

fn contribution_role(
    original: &VerifiedRegistration,
    proposal: [u8; 64],
    position: usize,
) -> Result<Vec<u8>, Refusal> {
    let header = original.header();
    encode_contribution_role(
        header.poll,
        proposal,
        position,
        derive_participant_identity(&header.signing_public).map_err(|_| Refusal::Shape)?,
    )
}

// Byte encoding alone supplies no original-owner or contribution authority.
pub(crate) fn encode_contribution_role(
    poll: [u8; 64],
    proposal: [u8; 64],
    position: usize,
    participant_identity: ParticipantIdentity,
) -> Result<Vec<u8>, Refusal> {
    if position >= *Profile::participant_range().end() {
        return Err(Refusal::Shape);
    }
    let role = CanonicalTuple::new(
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/setup-contribution")
                .map_err(|_| Refusal::Shape)?,
            CanonicalItem::nonempty_ascii(&participant_identity.to_lowercase_hex())
                .map_err(|_| Refusal::Shape)?,
            CanonicalItem::hash512(poll),
            CanonicalItem::hash512(proposal),
            CanonicalItem::unsigned16(position as u16),
        ],
    )
    .encode()
    .map_err(|_| Refusal::Shape)?;
    if role.len() > 1024 {
        return Err(Refusal::Shape);
    }
    Ok(role)
}
