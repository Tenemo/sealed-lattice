use crate::{
    Credential, Error, SigningPurpose,
    contribution_commitment::ComputedContributionCommitment,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    roster::RetainedContributionContext,
    roster_authentication::OrganizerSignedRoster,
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const CONFIRMATION_CONTEXT: &[u8] = b"sealed-lattice/roster-confirmation/v1";
pub const OPENING_CONTEXT: &[u8] = b"sealed-lattice/setup-opening/v1";
const MAXIMUM_MESSAGE_BYTES: usize = 1024;

/// Every roster participant confirms the roster once. A setup contributor's
/// confirmation also commits to its contribution, which it opens once.
pub(crate) struct ConfirmationLock {
    proposal: [u8; 64],
    position: usize,
    contribution: Option<ContributionLock>,
}

struct ContributionLock {
    commitment: [u8; 64],
    salt: Zeroizing<[u8; 64]>,
    opened: bool,
}

pub struct SignedConfirmation {
    body: Vec<u8>,
    signature: [u8; 3309],
}
impl SignedConfirmation {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}
pub struct VerifiedConfirmation {
    proposal: [u8; 64],
    position: usize,
    commitment: Option<[u8; 64]>,
    body: Vec<u8>,
    signature: [u8; 3309],
}
impl VerifiedConfirmation {
    pub fn position(&self) -> usize {
        self.position
    }
    /// A setup contributor's contribution commitment; a confirmation at any
    /// other position carries none.
    pub fn commitment(&self) -> Option<&[u8; 64]> {
        self.commitment.as_ref()
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}

pub(crate) fn identity(domain: &str, body: &[u8]) -> Result<[u8; 64], Error> {
    hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(body).map_err(|_| Error::Shape)?],
    )
    .map(|hash| hash.into_bytes())
    .map_err(|_| Error::Shape)
}
fn body(
    purpose: &str,
    predecessor: [u8; 64],
    position: usize,
    value: CanonicalItem,
) -> Result<Vec<u8>, Error> {
    let position = u16::try_from(position).map_err(|_| Error::Shape)?;
    CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii(purpose).map_err(|_| Error::Shape)?,
            CanonicalItem::hash512(predecessor),
            CanonicalItem::unsigned16(position),
            value,
        ],
    )
    .encode()
    .map_err(|_| Error::Shape)
}
/// A confirmation names the proposal, the signer's position and, for a setup
/// contributor, its contribution commitment; any other participant names its
/// own registration body in its place.
fn confirmation_message(
    proposal: [u8; 64],
    position: usize,
    value: [u8; 64],
) -> Result<Vec<u8>, Error> {
    body(
        "sealed-lattice/roster-confirmation/v1",
        proposal,
        position,
        CanonicalItem::hash512(value),
    )
}
fn opening_message(inventory: [u8; 64], position: usize, salt: [u8; 64]) -> Result<Vec<u8>, Error> {
    body(
        "sealed-lattice/setup-opening/v1",
        inventory,
        position,
        CanonicalItem::fixed_bytes(salt).map_err(|_| Error::Shape)?,
    )
}
/// Every confirmation body has this exact encoded length.
pub fn confirmation_body_bytes() -> usize {
    confirmation_message([0; 64], 0, [0; 64])
        .expect("A confirmation body encodes.")
        .len()
}
/// Every opening body has this exact encoded length.
pub fn opening_body_bytes() -> usize {
    opening_message([0; 64], 0, [0; 64])
        .expect("An opening body encodes.")
        .len()
}
pub(crate) fn decode(
    bytes: &[u8],
    purpose: &[u8],
    predecessor: [u8; 64],
    value_type: CanonicalItemType,
) -> Result<(usize, [u8; 64]), Error> {
    if bytes.len() > MAXIMUM_MESSAGE_BYTES {
        return Err(Error::Shape);
    }
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_MESSAGE_BYTES,
        maximum_item_count: 4,
        maximum_item_byte_length: MAXIMUM_MESSAGE_BYTES,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: 4 * MAXIMUM_MESSAGE_BYTES,
        maximum_cumulative_allocation_byte_length: 4 * MAXIMUM_MESSAGE_BYTES,
    };
    let tuple = CanonicalTuple::decode(bytes, &limits).map_err(|_| Error::Shape)?;
    if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != 4 {
        return Err(Error::Shape);
    }
    let items = &tuple.items;
    if items[0].item_type() != CanonicalItemType::Ascii
        || items[0].variable_value_bytes().map_err(|_| Error::Shape)? != purpose
        || items[1].item_type() != CanonicalItemType::Hash512
        || items[1].canonical_bytes() != predecessor
        || items[2].item_type() != CanonicalItemType::Unsigned16
        || items[3].item_type() != value_type
    {
        return Err(Error::Context);
    }
    let position = u16::from_le_bytes(
        items[2]
            .canonical_bytes()
            .try_into()
            .map_err(|_| Error::Shape)?,
    ) as usize;
    let value = items[3]
        .canonical_bytes()
        .try_into()
        .map_err(|_| Error::Shape)?;
    Ok((position, value))
}
fn verify_signature(
    proposal: &OrganizerSignedRoster,
    position: usize,
    identity: &[u8; 64],
    signature: &[u8],
    context: &[u8],
) -> Result<[u8; 3309], Error> {
    let record = proposal
        .proposal()
        .records()
        .get(position)
        .ok_or(Error::Context)?;
    let signature = signature.try_into().map_err(|_| Error::Shape)?;
    let key = ml_dsa_65::PublicKey::try_from_bytes(record.header().signing_public)
        .map_err(|_| Error::Shape)?;
    if !key.verify(identity, &signature, context) {
        return Err(Error::Crypto);
    }
    Ok(signature)
}

impl Credential {
    pub fn validate_retained_confirmation(
        &self,
        context: &RetainedContributionContext,
    ) -> Result<(), Error> {
        self.check_unlocked(SigningPurpose::Confirmation)?;
        if self.confirmation.is_some() {
            return Err(Error::Consumed);
        }
        if self.completed_body != Some(context.owner_body) {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn retained_confirmation_body(
        &self,
        context: &RetainedContributionContext,
        computed: &ComputedContributionCommitment,
    ) -> Result<Vec<u8>, Error> {
        self.validate_retained_confirmation(context)?;
        if computed.proposal != context.proposal || computed.position != context.position {
            return Err(Error::Context);
        }
        Self::computed_confirmation_body(computed)
    }
    pub fn sign_retained_confirmation(
        &mut self,
        context: &RetainedContributionContext,
        computed: ComputedContributionCommitment,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        let body = self.retained_confirmation_body(context, &computed)?;
        self.sign_computed_confirmation(body, computed, coins)
    }
    /// Checks the signing position before any new commitment work.
    pub fn validate_confirmation_position(
        &self,
        proposal: &OrganizerSignedRoster,
        position: usize,
    ) -> Result<(), Error> {
        self.check_unlocked(SigningPurpose::Confirmation)?;
        self.check_confirmation_position(proposal, position)
    }
    /// Checks the owner of a body before its commitment is hashed, without
    /// requiring an unlocked purpose. Signing still requires it, so a restored
    /// owner rebuilds the commitment of its completed confirmation but signs
    /// nothing new.
    pub fn validate_body_position(
        &self,
        proposal: &OrganizerSignedRoster,
        position: usize,
    ) -> Result<(), Error> {
        self.check_confirmation_position(proposal, position)
    }
    fn check_confirmation_position(
        &self,
        proposal: &OrganizerSignedRoster,
        position: usize,
    ) -> Result<(), Error> {
        if self.confirmation.is_some() {
            return Err(Error::Consumed);
        }
        // Only a setup contributor commits to a contribution.
        if position >= proposal.proposal().profile().setup_contributors() {
            return Err(Error::Context);
        }
        let record = proposal
            .proposal()
            .records()
            .get(position)
            .ok_or(Error::Context)?;
        if self.signing_public != record.header().signing_public
            || self.completed_body != Some(record.body_digest())
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn check_confirmation_owner(
        &self,
        proposal: &OrganizerSignedRoster,
        computed: &ComputedContributionCommitment,
    ) -> Result<(), Error> {
        if computed.proposal != proposal.proposal().identity() {
            return Err(Error::Context);
        }
        self.check_confirmation_position(proposal, computed.position)
    }
    pub fn confirmation_body(
        &self,
        proposal: &OrganizerSignedRoster,
        computed: &ComputedContributionCommitment,
    ) -> Result<Vec<u8>, Error> {
        self.check_confirmation_owner(proposal, computed)?;
        Self::computed_confirmation_body(computed)
    }
    fn computed_confirmation_body(
        computed: &ComputedContributionCommitment,
    ) -> Result<Vec<u8>, Error> {
        confirmation_message(computed.proposal, computed.position, computed.digest)
    }
    pub fn sign_confirmation(
        &mut self,
        proposal: &OrganizerSignedRoster,
        computed: ComputedContributionCommitment,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        let body = self.confirmation_body(proposal, &computed)?;
        self.sign_computed_confirmation(body, computed, coins)
    }
    fn sign_computed_confirmation(
        &mut self,
        body: Vec<u8>,
        computed: ComputedContributionCommitment,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        self.sign_locked_confirmation(
            body,
            ConfirmationLock {
                proposal: computed.proposal,
                position: computed.position,
                contribution: Some(ContributionLock {
                    commitment: computed.digest,
                    salt: computed.salt,
                    opened: false,
                }),
            },
            coins,
        )
    }
    fn sign_locked_confirmation(
        &mut self,
        body: Vec<u8>,
        lock: ConfirmationLock,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        self.check_unlocked(SigningPurpose::Confirmation)?;
        if self.confirmation.is_some() {
            return Err(Error::Consumed);
        }
        let message = identity("sealed-lattice/roster-confirmation-id/v1", &body)?;
        self.confirmation = Some(lock);
        let coins = Zeroizing::new(coins);
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        let signature = key
            .try_sign_with_seed(&coins, &message, CONFIRMATION_CONTEXT)
            .map_err(|_| Error::Crypto)?;
        Ok(SignedConfirmation { body, signature })
    }
    /// The roster confirmation of a participant outside the setup
    /// contributors, which commits to no contribution.
    fn roster_confirmation(
        &self,
        proposal: [u8; 64],
        profile: supported_profile::Profile,
        position: usize,
        owner_body: [u8; 64],
    ) -> Result<Vec<u8>, Error> {
        self.check_unlocked(SigningPurpose::Confirmation)?;
        if self.confirmation.is_some() {
            return Err(Error::Consumed);
        }
        if position < profile.setup_contributors()
            || position >= profile.participants()
            || self.completed_body != Some(owner_body)
        {
            return Err(Error::Context);
        }
        confirmation_message(proposal, position, owner_body)
    }
    pub fn roster_confirmation_body(
        &self,
        proposal: &OrganizerSignedRoster,
        position: usize,
    ) -> Result<Vec<u8>, Error> {
        let proposal = proposal.proposal();
        let record = proposal.records().get(position).ok_or(Error::Context)?;
        if self.signing_public != record.header().signing_public {
            return Err(Error::Context);
        }
        self.roster_confirmation(
            proposal.identity(),
            proposal.profile(),
            position,
            record.body_digest(),
        )
    }
    pub fn sign_roster_confirmation(
        &mut self,
        proposal: &OrganizerSignedRoster,
        position: usize,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        let body = self.roster_confirmation_body(proposal, position)?;
        let lock = ConfirmationLock {
            proposal: proposal.proposal().identity(),
            position,
            contribution: None,
        };
        self.sign_locked_confirmation(body, lock, coins)
    }
    pub fn retained_roster_confirmation_body(
        &self,
        context: &RetainedContributionContext,
    ) -> Result<Vec<u8>, Error> {
        self.roster_confirmation(
            context.proposal,
            context.profile(),
            context.position,
            context.owner_body,
        )
    }
    pub fn sign_retained_roster_confirmation(
        &mut self,
        context: &RetainedContributionContext,
        coins: [u8; 32],
    ) -> Result<SignedConfirmation, Error> {
        let body = self.retained_roster_confirmation_body(context)?;
        let lock = ConfirmationLock {
            proposal: context.proposal,
            position: context.position,
            contribution: None,
        };
        self.sign_locked_confirmation(body, lock, coins)
    }
    pub fn restore_confirmation(
        &mut self,
        proposal: &OrganizerSignedRoster,
        computed: ComputedContributionCommitment,
        confirmation: &VerifiedConfirmation,
    ) -> Result<(), Error> {
        if self.confirmation.is_some() {
            return Err(Error::Consumed);
        }
        self.check_confirmation_owner(proposal, &computed)?;
        if confirmation.proposal != computed.proposal
            || confirmation.position != computed.position
            || confirmation.commitment != Some(computed.digest)
        {
            return Err(Error::Context);
        }
        self.confirmation = Some(ConfirmationLock {
            proposal: computed.proposal,
            position: computed.position,
            contribution: Some(ContributionLock {
                commitment: computed.digest,
                salt: computed.salt,
                opened: false,
            }),
        });
        Ok(())
    }
}

pub fn verify_confirmation(
    proposal: &OrganizerSignedRoster,
    bytes: &[u8],
    signature: &[u8],
) -> Result<VerifiedConfirmation, Error> {
    let (position, value) = decode(
        bytes,
        CONFIRMATION_CONTEXT,
        proposal.proposal().identity(),
        CanonicalItemType::Hash512,
    )?;
    let record = proposal
        .proposal()
        .records()
        .get(position)
        .ok_or(Error::Context)?;
    let commitment = if position < proposal.proposal().profile().setup_contributors() {
        Some(value)
    } else if value == record.body_digest() {
        None
    } else {
        return Err(Error::Context);
    };
    let digest = identity("sealed-lattice/roster-confirmation-id/v1", bytes)?;
    let signature = verify_signature(proposal, position, &digest, signature, CONFIRMATION_CONTEXT)?;
    Ok(VerifiedConfirmation {
        proposal: proposal.proposal().identity(),
        position,
        commitment,
        body: bytes.to_vec(),
        signature,
    })
}

pub struct CommitmentInventory {
    proposal: Arc<OrganizerSignedRoster>,
    confirmations: Vec<VerifiedConfirmation>,
    body: Vec<u8>,
    identity: [u8; 64],
}
impl CommitmentInventory {
    /// Holds one confirmation from every roster position. Its body lists the
    /// setup contributors' commitments, which only their confirmations carry.
    pub fn new(
        proposal: Arc<OrganizerSignedRoster>,
        mut confirmations: Vec<VerifiedConfirmation>,
    ) -> Result<Self, Error> {
        let profile = proposal.proposal().profile();
        if confirmations.len() != profile.participants() {
            return Err(Error::Shape);
        }
        confirmations.sort_by_key(|confirmation| confirmation.position);
        let contributors = profile.setup_contributors();
        let mut commitments = Vec::from((contributors as u32).to_le_bytes());
        for (position, confirmation) in confirmations.iter().enumerate() {
            if confirmation.position != position
                || confirmation.proposal != proposal.proposal().identity()
                || confirmation.commitment.is_some() != (position < contributors)
            {
                return Err(Error::Context);
            }
            commitments.extend(confirmation.commitment.iter().flatten());
        }
        let body = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii("sealed-lattice/commitment-inventory/v1")
                    .map_err(|_| Error::Shape)?,
                CanonicalItem::hash512(proposal.proposal().identity()),
                CanonicalItem::variable_bytes(commitments).map_err(|_| Error::Shape)?,
            ],
        )
        .encode()
        .map_err(|_| Error::Shape)?;
        let identity = identity("sealed-lattice/commitment-inventory-id/v1", &body)?;
        Ok(Self {
            proposal,
            confirmations,
            body,
            identity,
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
    pub fn proposal(&self) -> &OrganizerSignedRoster {
        &self.proposal
    }
    pub fn confirmations(&self) -> &[VerifiedConfirmation] {
        &self.confirmations
    }
}

pub struct SignedOpening {
    body: Vec<u8>,
    signature: [u8; 3309],
}
impl SignedOpening {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}
pub struct AuthenticatedOpening {
    inventory: [u8; 64],
    position: usize,
    salt: [u8; 64],
}
impl AuthenticatedOpening {
    pub fn inventory(&self) -> [u8; 64] {
        self.inventory
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn salt(&self) -> &[u8; 64] {
        &self.salt
    }
}
impl Credential {
    /// Only a setup contributor's confirmation leaves a contribution to open.
    fn contribution_lock(&self) -> Result<(&ConfirmationLock, &ContributionLock), Error> {
        let lock = self.confirmation.as_ref().ok_or(Error::Consumed)?;
        Ok((lock, lock.contribution.as_ref().ok_or(Error::Context)?))
    }
    pub fn opening_body(&self, inventory: &CommitmentInventory) -> Result<Vec<u8>, Error> {
        let (lock, contribution) = self.contribution_lock()?;
        if contribution.opened {
            return Err(Error::Consumed);
        }
        if inventory.proposal.proposal().identity() != lock.proposal
            || inventory
                .confirmations
                .get(lock.position)
                .is_none_or(|entry| entry.commitment != Some(contribution.commitment))
        {
            return Err(Error::Context);
        }
        opening_message(inventory.identity, lock.position, *contribution.salt)
    }
    fn mark_opened(&mut self) -> Result<(), Error> {
        self.confirmation
            .as_mut()
            .ok_or(Error::Consumed)?
            .contribution
            .as_mut()
            .ok_or(Error::Context)?
            .opened = true;
        Ok(())
    }
    pub fn sign_opening(
        &mut self,
        inventory: &CommitmentInventory,
        coins: [u8; 32],
    ) -> Result<SignedOpening, Error> {
        self.check_unlocked(SigningPurpose::Opening)?;
        let body = self.opening_body(inventory)?;
        let message = identity("sealed-lattice/setup-opening-id/v1", &body)?;
        self.mark_opened()?;
        let coins = Zeroizing::new(coins);
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        let signature = key
            .try_sign_with_seed(&coins, &message, OPENING_CONTEXT)
            .map_err(|_| Error::Crypto)?;
        Ok(SignedOpening { body, signature })
    }
    pub fn consume_opening(&mut self) -> Result<(), Error> {
        self.mark_opened()
    }
    pub fn restore_opening(
        &mut self,
        inventory: &CommitmentInventory,
        body: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let opening = verify_opening(inventory, body, signature)?;
        let (lock, contribution) = self.contribution_lock()?;
        if opening.position != lock.position
            || opening.salt != *contribution.salt
            || inventory.proposal.proposal().identity() != lock.proposal
            || inventory.confirmations[lock.position].commitment != Some(contribution.commitment)
        {
            return Err(Error::Context);
        }
        self.consume_opening()
    }
}
pub fn verify_opening(
    inventory: &CommitmentInventory,
    bytes: &[u8],
    signature: &[u8],
) -> Result<AuthenticatedOpening, Error> {
    let (position, salt) = decode(
        bytes,
        OPENING_CONTEXT,
        inventory.identity,
        CanonicalItemType::RawBytes,
    )?;
    if position >= inventory.proposal.proposal().profile().setup_contributors() {
        return Err(Error::Context);
    }
    let digest = identity("sealed-lattice/setup-opening-id/v1", bytes)?;
    verify_signature(
        &inventory.proposal,
        position,
        &digest,
        signature,
        OPENING_CONTEXT,
    )?;
    Ok(AuthenticatedOpening {
        inventory: inventory.identity,
        position,
        salt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        foundation::{
            RegistrationHeader, StabilizedDisplayText,
            ceremony::{Manifest, OptionDefinition},
            normalize_username,
        },
        poll::{PollDraft, verify_poll},
        registration::VerifiedRegistration,
        roster::RosterProposal,
        roster_authentication::verify_roster_proposal,
    };

    // Three credentials whose completed bodies a signed roster lists in
    // order, with the organizer first.
    fn signed_roster() -> (Vec<Credential>, OrganizerSignedRoster) {
        let text =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        let options = (0..2)
            .map(|index| {
                OptionDefinition::new(
                    index,
                    format!("option-{index}"),
                    text(&format!("Option {index}")),
                )
                .unwrap()
            })
            .collect();
        let draft =
            PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 1, 3).unwrap();
        let mut credentials: Vec<_> = (1..4)
            .map(|seed| Credential::from_seeds([seed; 32], [seed + 30; 32], [seed + 60; 32]))
            .collect();
        let packet = credentials[0]
            .create_poll(draft, [4; 64], [5; 32], [6; 32])
            .unwrap();
        let poll = verify_poll(packet.identity, [4; 64], &packet.body, &packet.signature).unwrap();
        let records = credentials
            .iter_mut()
            .zip(1..)
            .map(|(credential, body)| {
                credential.completed_body = Some([body; 64]);
                Arc::new(VerifiedRegistration::for_roster(
                    RegistrationHeader {
                        username: normalize_username(b"Participant").unwrap(),
                        poll: poll.identity(),
                        runtime: poll.runtime(),
                        signing_public: *credential.signing_public(),
                        mailbox_public: *credential.mailbox_public(),
                        recipient_key_hash: [0; 64],
                        proof_length: 0,
                    },
                    [body; 64],
                ))
            })
            .collect();
        let proposal = RosterProposal::new(&poll, records).unwrap();
        let signature = credentials[0]
            .sign_roster_proposal(&proposal, [7; 32])
            .unwrap();
        (
            credentials,
            verify_roster_proposal(proposal, &signature).unwrap(),
        )
    }

    fn commitment(
        roster: &OrganizerSignedRoster,
        position: usize,
        digest: u8,
    ) -> ComputedContributionCommitment {
        ComputedContributionCommitment {
            proposal: roster.proposal().identity(),
            position,
            digest: [digest; 64],
            salt: Zeroizing::new([3; 64]),
        }
    }

    #[test]
    fn a_restored_owner_reinstalls_its_confirmation_but_signs_no_other() {
        let (mut credentials, roster) = signed_roster();
        let verify = |confirmation: SignedConfirmation| {
            verify_confirmation(&roster, confirmation.body(), confirmation.signature()).unwrap()
        };
        let own = verify(
            credentials[1]
                .sign_confirmation(&roster, commitment(&roster, 1, 9), [8; 32])
                .unwrap(),
        );
        let other = verify(
            credentials[0]
                .sign_confirmation(&roster, commitment(&roster, 0, 9), [8; 32])
                .unwrap(),
        );
        // The root shows the proposal and the confirmation used, so the
        // restored owner unlocks every purpose but those two.
        let mut restored = Credential::from_seeds([2; 32], [32; 32], [62; 32]);
        restored.completed_body = Some([2; 64]);
        restored.locked_purposes =
            SigningPurpose::Proposal.mask() | SigningPurpose::Confirmation.mask();
        assert!(matches!(
            restored.validate_confirmation_position(&roster, 1),
            Err(Error::Consumed)
        ));
        restored.validate_body_position(&roster, 1).unwrap();
        for position in [0, 2, 3] {
            assert!(restored.validate_body_position(&roster, position).is_err());
        }
        assert!(matches!(
            restored.sign_confirmation(&roster, commitment(&roster, 1, 9), [8; 32]),
            Err(Error::Consumed)
        ));
        // A different body, another owner's confirmation, or another owner's
        // position installs nothing.
        for (computed, confirmation) in [
            (commitment(&roster, 1, 10), &own),
            (commitment(&roster, 1, 9), &other),
            (commitment(&roster, 0, 9), &other),
        ] {
            assert!(
                restored
                    .restore_confirmation(&roster, computed, confirmation)
                    .is_err()
            );
        }
        restored
            .restore_confirmation(&roster, commitment(&roster, 1, 9), &own)
            .unwrap();
        assert!(matches!(
            restored.restore_confirmation(&roster, commitment(&roster, 1, 9), &own),
            Err(Error::Consumed)
        ));
        assert!(matches!(
            restored.validate_body_position(&roster, 1),
            Err(Error::Consumed)
        ));
    }

    #[test]
    fn every_participant_confirms_and_only_setup_contributors_commit_and_open() {
        let (mut credentials, roster) = signed_roster();
        // Three participants have two setup contributors, so the last
        // position commits to no contribution: it neither signs nor has
        // accepted a confirmation that carries a commitment.
        assert_eq!(roster.proposal().profile().setup_contributors(), 2);
        assert!(matches!(
            credentials[2].validate_confirmation_position(&roster, 2),
            Err(Error::Context)
        ));
        assert!(matches!(
            credentials[2].sign_confirmation(&roster, commitment(&roster, 2, 9), [8; 32]),
            Err(Error::Context)
        ));
        assert!(matches!(
            roster.proposal().contribution_role(2),
            Err(Error::Context)
        ));
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&credentials[2].signing_seed);
        let forged = |value: [u8; 64]| {
            let body = confirmation_message(roster.proposal().identity(), 2, value).unwrap();
            let message = identity("sealed-lattice/roster-confirmation-id/v1", &body).unwrap();
            let signature = key
                .try_sign_with_seed(&[8; 32], &message, CONFIRMATION_CONTEXT)
                .unwrap();
            (body, signature)
        };
        let (body, signature) = forged([9; 64]);
        assert!(matches!(
            verify_confirmation(&roster, &body, &signature),
            Err(Error::Context)
        ));
        // Its confirmation names its own registration body instead. No
        // contributor signs one, nor does anyone at another's position.
        let (body, signature) = forged([3; 64]);
        assert_eq!(
            verify_confirmation(&roster, &body, &signature)
                .unwrap()
                .commitment(),
            None
        );
        for (signer, position) in [(0, 0), (1, 2), (2, 1)] {
            assert!(matches!(
                credentials[signer].sign_roster_confirmation(&roster, position, [8; 32]),
                Err(Error::Context)
            ));
        }
        let own = credentials[2]
            .sign_roster_confirmation(&roster, 2, [8; 32])
            .unwrap();
        assert_eq!(own.body(), body);
        assert!(matches!(
            credentials[2].sign_roster_confirmation(&roster, 2, [8; 32]),
            Err(Error::Consumed)
        ));
        // The inventory holds every position's confirmation and lists only
        // the contributors' commitments.
        let roster = Arc::new(roster);
        let signed: Vec<_> = (0..2)
            .map(|position| {
                credentials[position]
                    .sign_confirmation(
                        &roster,
                        commitment(&roster, position, 9 + position as u8),
                        [8; 32],
                    )
                    .unwrap()
            })
            .collect();
        let verified = |all: bool| {
            signed
                .iter()
                .chain(all.then_some(&own))
                .map(|signed| {
                    verify_confirmation(&roster, signed.body(), signed.signature()).unwrap()
                })
                .collect::<Vec<_>>()
        };
        assert!(matches!(
            CommitmentInventory::new(roster.clone(), verified(false)),
            Err(Error::Shape)
        ));
        let inventory = CommitmentInventory::new(roster.clone(), verified(true)).unwrap();
        assert_eq!(inventory.confirmations().len(), 3);
        let listed: Vec<u8> = [2, 0, 0, 0]
            .into_iter()
            .chain([9; 64])
            .chain([10; 64])
            .collect();
        assert!(inventory.body().ends_with(&listed));
        // An opening is signed and accepted only at a contributor's position
        // of that inventory.
        assert!(matches!(
            credentials[2].sign_opening(&inventory, [8; 32]),
            Err(Error::Context)
        ));
        let opening = credentials[1].sign_opening(&inventory, [8; 32]).unwrap();
        assert_eq!(
            verify_opening(&inventory, opening.body(), opening.signature())
                .unwrap()
                .position(),
            1
        );
        let body = opening_message(inventory.identity(), 2, [3; 64]).unwrap();
        let message = identity("sealed-lattice/setup-opening-id/v1", &body).unwrap();
        let signature = key
            .try_sign_with_seed(&[8; 32], &message, OPENING_CONTEXT)
            .unwrap();
        assert!(matches!(
            verify_opening(&inventory, &body, &signature),
            Err(Error::Context)
        ));
    }

    #[test]
    fn a_retained_roster_confirmation_is_signed_once_at_its_own_position() {
        let (mut credentials, roster) = signed_roster();
        let header = roster.proposal().records()[0].header();
        let context = |position| {
            RetainedContributionContext::parse(
                header.poll,
                header.runtime,
                2,
                position,
                roster.proposal().body(),
            )
            .unwrap()
        };
        // A setup contributor's position and another participant's position
        // are refused.
        for (signer, position) in [(0, 0), (2, 0), (1, 2)] {
            assert!(matches!(
                credentials[signer].retained_roster_confirmation_body(&context(position)),
                Err(Error::Context)
            ));
        }
        let body = credentials[2]
            .retained_roster_confirmation_body(&context(2))
            .unwrap();
        let signed = credentials[2]
            .sign_retained_roster_confirmation(&context(2), [8; 32])
            .unwrap();
        assert_eq!(signed.body(), body);
        let verified = verify_confirmation(&roster, signed.body(), signed.signature()).unwrap();
        assert_eq!((verified.position(), verified.commitment()), (2, None));
        assert!(matches!(
            credentials[2].sign_retained_roster_confirmation(&context(2), [8; 32]),
            Err(Error::Consumed)
        ));
    }
}
