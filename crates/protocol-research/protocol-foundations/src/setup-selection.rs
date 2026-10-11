//! Canonical selection messages and authentication. These types establish
//! signatures only; the setup verifier separately checks every selected body.
use crate::{
    Credential, Error, SIGNATURE_BYTES, SigningPurpose,
    foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple},
    identity::identity,
    poll::VerifiedPoll,
    roster::RosterProposal,
    roster_authentication::AuthenticatedRosterProposal,
};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use std::sync::Arc;
use supported_profile::Profile;

pub const SELECTION_PURPOSE: &str = "sealed-lattice/setup-selection/v1";
pub const SELECTION_IDENTITY_DOMAIN: &str = "sealed-lattice/setup-selection-identity/v1";
pub const PROPOSAL_CONTEXT: &[u8] = b"sealed-lattice/setup-selection-proposal/v1";
pub const ENDORSEMENT_PURPOSE: &str = "sealed-lattice/setup-selection-endorsement/v1";
pub const ENDORSEMENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/setup-selection-endorsement-identity/v1";
pub const ENDORSEMENT_BYTES: usize = 2 + 64 + SIGNATURE_BYTES;
pub const MAXIMUM_SELECTION_BYTES: usize = 2048;
const RETAINED_INPUTS_LABEL: &[u8] = b"sealed-lattice/retained-selection-inputs/v2";
pub fn selection_body_bytes(profile: Profile) -> usize {
    CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii(SELECTION_PURPOSE).expect("Purpose"),
            CanonicalItem::hash512([0; 64]),
            CanonicalItem::variable_bytes(vec![0; 4 + 66 * profile.setup_contributors()])
                .expect("Bounded selected list"),
        ],
    )
    .encode()
    .expect("Canonical selection")
    .len()
}
pub fn endorsement_body_bytes() -> usize {
    endorsement_body([0; 64], 0)
        .expect("Canonical endorsement")
        .len()
}

#[derive(Clone)]
pub struct SelectionProposal {
    body: Vec<u8>,
    identity: [u8; 64],
    roster: [u8; 64],
    selected: Vec<(usize, [u8; 64])>,
}
impl SelectionProposal {
    /// Encoding alone creates no selected-offer or setup capability.
    pub fn new(roster: &RosterProposal, selected: &[(usize, [u8; 64])]) -> Result<Self, Error> {
        let profile = roster.profile();
        if selected.len() != profile.setup_contributors()
            || selected
                .iter()
                .any(|(position, _)| *position >= profile.setup_eligible_contributors())
            || selected.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(Error::Shape);
        }
        let mut entries = Vec::from((selected.len() as u32).to_le_bytes());
        for (position, body) in selected {
            entries.extend((*position as u16).to_le_bytes());
            entries.extend(body);
        }
        let body = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii(SELECTION_PURPOSE).map_err(|_| Error::Shape)?,
                CanonicalItem::hash512(roster.identity()),
                CanonicalItem::variable_bytes(entries).map_err(|_| Error::Shape)?,
            ],
        )
        .encode()
        .map_err(|_| Error::Shape)?;
        let identity = identity(SELECTION_IDENTITY_DOMAIN, &body)?;
        Ok(Self {
            body,
            identity,
            roster: roster.identity(),
            selected: selected.to_vec(),
        })
    }
    pub fn decode(roster: &RosterProposal, bytes: &[u8]) -> Result<Self, Error> {
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: MAXIMUM_SELECTION_BYTES,
            maximum_item_count: 3,
            maximum_item_byte_length: MAXIMUM_SELECTION_BYTES,
            maximum_nesting_depth: 0,
            ..CanonicalDecodeLimits::default()
        };
        let tuple = CanonicalTuple::decode(bytes, &limits).map_err(|_| Error::Shape)?;
        if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != 3 {
            return Err(Error::Shape);
        }
        let items = &tuple.items;
        if items[0].item_type() != CanonicalItemType::Ascii
            || items[1].item_type() != CanonicalItemType::Hash512
            || items[2].item_type() != CanonicalItemType::RawBytes
            || items[0].variable_value_bytes().map_err(|_| Error::Shape)?
                != SELECTION_PURPOSE.as_bytes()
            || items[1].canonical_bytes() != roster.identity()
        {
            return Err(Error::Context);
        }
        let entries = items[2].variable_value_bytes().map_err(|_| Error::Shape)?;
        if entries.len() != 4 + roster.profile().setup_contributors() * 66
            || u32::from_le_bytes(entries[..4].try_into().unwrap()) as usize
                != roster.profile().setup_contributors()
        {
            return Err(Error::Shape);
        }
        let selected: Vec<_> = entries[4..]
            .chunks_exact(66)
            .map(|entry| {
                (
                    u16::from_le_bytes(entry[..2].try_into().unwrap()) as usize,
                    entry[2..].try_into().unwrap(),
                )
            })
            .collect();
        Self::new(roster, &selected)
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn identity(&self) -> [u8; 64] {
        self.identity
    }
    pub fn selected(&self) -> &[(usize, [u8; 64])] {
        &self.selected
    }
    pub fn roster_identity(&self) -> &[u8; 64] {
        &self.roster
    }
}

#[derive(Clone)]
pub struct AuthenticatedSelectionProposal {
    roster: Arc<AuthenticatedRosterProposal>,
    selection: SelectionProposal,
    signature: [u8; SIGNATURE_BYTES],
}
impl AuthenticatedSelectionProposal {
    pub fn roster(&self) -> &Arc<AuthenticatedRosterProposal> {
        &self.roster
    }
    pub fn selection(&self) -> &SelectionProposal {
        &self.selection
    }
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }
}
pub fn authenticate_selection(
    roster: Arc<AuthenticatedRosterProposal>,
    body: &[u8],
    signature: &[u8],
) -> Result<AuthenticatedSelectionProposal, Error> {
    let selection = SelectionProposal::decode(roster.proposal(), body)?;
    let signature = signature.try_into().map_err(|_| Error::Shape)?;
    verify(
        roster.proposal(),
        roster.proposal().organizer_position(),
        &selection.identity(),
        &signature,
        PROPOSAL_CONTEXT,
    )?;
    Ok(AuthenticatedSelectionProposal {
        roster,
        selection,
        signature,
    })
}
fn verify(
    roster: &RosterProposal,
    position: usize,
    digest: &[u8; 64],
    signature: &[u8; SIGNATURE_BYTES],
    purpose: &[u8],
) -> Result<(), Error> {
    let key = roster
        .records()
        .get(position)
        .ok_or(Error::Context)?
        .header()
        .signing_public;
    let key = ml_dsa_65::PublicKey::try_from_bytes(key).map_err(|_| Error::Shape)?;
    if !key.verify(digest, signature, purpose) {
        return Err(Error::Crypto);
    }
    Ok(())
}
pub fn endorsement_body(selection: [u8; 64], position: usize) -> Result<Vec<u8>, Error> {
    CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii(ENDORSEMENT_PURPOSE).map_err(|_| Error::Shape)?,
            CanonicalItem::hash512(selection),
            CanonicalItem::unsigned16(u16::try_from(position).map_err(|_| Error::Shape)?),
        ],
    )
    .encode()
    .map_err(|_| Error::Shape)
}
fn endorsement_identity(selection: [u8; 64], position: usize) -> Result<[u8; 64], Error> {
    identity(
        ENDORSEMENT_IDENTITY_DOMAIN,
        &endorsement_body(selection, position)?,
    )
}
#[derive(Clone)]
pub struct AuthenticatedSelectionEndorsement {
    roster: [u8; 64],
    position: usize,
    selection: [u8; 64],
    signature: [u8; SIGNATURE_BYTES],
}
impl AuthenticatedSelectionEndorsement {
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn selection_identity(&self) -> &[u8; 64] {
        &self.selection
    }
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }
    pub fn packet(&self) -> Vec<u8> {
        endorsement_packet(self.position, self.selection, &self.signature)
    }
}
fn endorsement_packet(
    position: usize,
    selection: [u8; 64],
    signature: &[u8; SIGNATURE_BYTES],
) -> Vec<u8> {
    let mut bytes = Vec::from((position as u16).to_le_bytes());
    bytes.extend(selection);
    bytes.extend(signature);
    bytes
}
pub fn authenticate_endorsement(
    roster: &AuthenticatedRosterProposal,
    selection: &SelectionProposal,
    packet: &[u8],
) -> Result<AuthenticatedSelectionEndorsement, Error> {
    if packet.len() != ENDORSEMENT_BYTES {
        return Err(Error::Shape);
    }
    if selection.roster_identity() != roster.proposal().identity_bytes()
        || packet[2..66] != selection.identity()
    {
        return Err(Error::Context);
    }
    endorsement(
        roster,
        selection,
        u16::from_le_bytes(packet[..2].try_into().unwrap()) as usize,
        packet[66..].try_into().unwrap(),
    )
}
/// A member's endorsement of a selection of the roster's.
fn endorsement(
    roster: &AuthenticatedRosterProposal,
    selection: &SelectionProposal,
    position: usize,
    signature: [u8; SIGNATURE_BYTES],
) -> Result<AuthenticatedSelectionEndorsement, Error> {
    verify(
        roster.proposal(),
        position,
        &endorsement_identity(selection.identity(), position)?,
        &signature,
        ENDORSEMENT_PURPOSE.as_bytes(),
    )?;
    Ok(AuthenticatedSelectionEndorsement {
        roster: roster.proposal().identity(),
        position,
        selection: selection.identity(),
        signature,
    })
}
pub struct AuthenticatedSelectionCertificate {
    proposal: AuthenticatedSelectionProposal,
    endorsements: Vec<AuthenticatedSelectionEndorsement>,
    bytes: Vec<u8>,
}
impl AuthenticatedSelectionCertificate {
    pub fn proposal(&self) -> &AuthenticatedSelectionProposal {
        &self.proposal
    }
    pub fn endorsements(&self) -> &[AuthenticatedSelectionEndorsement] {
        &self.endorsements
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn identity(&self) -> [u8; 64] {
        self.proposal.selection.identity()
    }
}
pub fn certificate_bytes(profile: Profile, proposal_bytes: usize) -> Result<usize, Error> {
    if proposal_bytes > MAXIMUM_SELECTION_BYTES {
        return Err(Error::Shape);
    }
    Ok(4 + 4
        + proposal_bytes
        + SIGNATURE_BYTES
        + profile.inventory_threshold() * (2 + SIGNATURE_BYTES))
}
pub fn encode_certificate(
    proposal: &AuthenticatedSelectionProposal,
    endorsements: &[AuthenticatedSelectionEndorsement],
) -> Result<Vec<u8>, Error> {
    let profile = proposal.roster.proposal().profile();
    if endorsements.len() != profile.inventory_threshold()
        || endorsements.iter().any(|value| {
            value.position >= profile.participants()
                || value.selection != proposal.selection.identity()
                || value.roster != proposal.roster.proposal().identity()
        })
        || endorsements
            .windows(2)
            .any(|pair| pair[0].position >= pair[1].position)
    {
        return Err(Error::Context);
    }
    let body = proposal.selection.body();
    let mut bytes = Vec::from(b"SSC1".as_slice());
    bytes.extend((body.len() as u32).to_le_bytes());
    bytes.extend(body);
    bytes.extend(proposal.signature);
    for endorsement in endorsements {
        bytes.extend((endorsement.position as u16).to_le_bytes());
        bytes.extend(endorsement.signature);
    }
    Ok(bytes)
}
pub fn authenticate_certificate(
    roster: Arc<AuthenticatedRosterProposal>,
    bytes: &[u8],
) -> Result<AuthenticatedSelectionCertificate, Error> {
    if bytes.len() < 8 || &bytes[..4] != b"SSC1" {
        return Err(Error::Shape);
    }
    let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if bytes.len() != certificate_bytes(roster.proposal().profile(), length)? {
        return Err(Error::Shape);
    }
    let proposal = authenticate_selection(
        roster.clone(),
        &bytes[8..8 + length],
        &bytes[8 + length..8 + length + SIGNATURE_BYTES],
    )?;
    let endorsements = bytes[8 + length + SIGNATURE_BYTES..]
        .chunks_exact(2 + SIGNATURE_BYTES)
        .map(|entry| {
            endorsement(
                &roster,
                &proposal.selection,
                u16::from_le_bytes(entry[..2].try_into().unwrap()) as usize,
                entry[2..].try_into().unwrap(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if encode_certificate(&proposal, &endorsements)?.as_slice() != bytes {
        return Err(Error::Shape);
    }
    Ok(AuthenticatedSelectionCertificate {
        proposal,
        endorsements,
        bytes: bytes.to_vec(),
    })
}

impl Credential {
    pub fn sign_selection_proposal(
        &mut self,
        roster: &AuthenticatedRosterProposal,
        selection: &SelectionProposal,
    ) -> Result<[u8; SIGNATURE_BYTES], Error> {
        self.check_unlocked(SigningPurpose::SelectionProposal)?;
        self.check_confirmed_position(roster.proposal(), roster.proposal().organizer_position())?;
        if self.preparation_retired || self.selection_proposal_signed.is_some() {
            return Err(Error::Consumed);
        }
        if selection.roster_identity() != roster.proposal().identity_bytes() {
            return Err(Error::Context);
        }
        self.selection_proposal_signed = Some(selection.identity());
        self.sign_deterministically(&selection.identity(), PROPOSAL_CONTEXT)
    }
    pub fn endorse_selection(
        &mut self,
        roster: &AuthenticatedRosterProposal,
        selection: &SelectionProposal,
        position: usize,
    ) -> Result<Vec<u8>, Error> {
        self.check_unlocked(SigningPurpose::SelectionEndorsement)?;
        self.check_confirmed_position(roster.proposal(), position)?;
        if self.preparation_retired || self.selection_endorsed.is_some() {
            return Err(Error::Consumed);
        }
        if selection.roster_identity() != roster.proposal().identity_bytes() {
            return Err(Error::Context);
        }
        let digest = endorsement_identity(selection.identity(), position)?;
        self.selection_endorsed = Some(selection.identity());
        let signature = self.sign_deterministically(&digest, ENDORSEMENT_PURPOSE.as_bytes())?;
        Ok(endorsement_packet(
            position,
            selection.identity(),
            &signature,
        ))
    }
    pub fn restore_selection_proposal(
        &mut self,
        proposal: &AuthenticatedSelectionProposal,
    ) -> Result<(), Error> {
        self.check_confirmed_position(
            proposal.roster.proposal(),
            proposal.roster.proposal().organizer_position(),
        )?;
        let target = proposal.selection.identity();
        if self
            .selection_proposal_signed
            .is_some_and(|old| old != target)
        {
            return Err(Error::Consumed);
        }
        self.selection_proposal_signed = Some(target);
        self.locked_purposes |= SigningPurpose::SelectionProposal.mask();
        Ok(())
    }
    pub fn restore_selection_endorsement(
        &mut self,
        roster: &AuthenticatedRosterProposal,
        endorsement: &AuthenticatedSelectionEndorsement,
    ) -> Result<(), Error> {
        self.check_confirmed_position(roster.proposal(), endorsement.position)?;
        if endorsement.roster != roster.proposal().identity() {
            return Err(Error::Context);
        }
        if self
            .selection_endorsed
            .is_some_and(|old| old != endorsement.selection)
        {
            return Err(Error::Consumed);
        }
        self.selection_endorsed = Some(endorsement.selection);
        self.locked_purposes |= SigningPurpose::SelectionEndorsement.mask();
        Ok(())
    }
    pub fn retained_selection_inputs_tag(&self, poll: &VerifiedPoll, reference: &[u8]) -> [u8; 64] {
        self.retained_tag(RETAINED_INPUTS_LABEL, poll, reference)
    }
    pub fn check_retained_selection_inputs_tag(
        &self,
        poll: &VerifiedPoll,
        reference: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        self.check_retained_tag(RETAINED_INPUTS_LABEL, poll, reference, tag)
    }
}
