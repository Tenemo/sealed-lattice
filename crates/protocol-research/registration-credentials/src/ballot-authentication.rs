use crate::{
    Credential, Error, RETAINED_TAG_BYTES, SigningPurpose,
    roster_authentication::OrganizerSignedRoster,
};
use crate::{
    foundation::{CanonicalItem, hash_foundation_tuple_512},
    poll::VerifiedPoll,
    roster::RetainedContributionContext,
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use supported_profile::Profile;

pub const BALLOT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/ballot-envelope/v1";
pub const ENVELOPE_BYTES: usize = 4 + 64 + 64 + 2 + 8 + 8 + 64;
pub const ENVELOPE_IDENTITY_DOMAIN: &str = "sealed-lattice/ballot-envelope-id/v1";
const RETAINED_SETUP_TAG_LABEL: &[u8] = b"sealed-lattice/retained-setup-reference/v1";

/// Original credential correspondence beneath the authenticated participant root.
/// This creates no public roster, setup, ballot, or unspent-attempt capability.
pub struct RetainedBallotOwner {
    poll: [u8; 64],
    runtime: [u8; 64],
    inventory: [u8; 64],
    position: usize,
    owner_body: [u8; 64],
    signing_public: [u8; 1952],
}
impl RetainedBallotOwner {
    pub fn participant_identity(
        &self,
    ) -> crate::foundation::participant_identity::ParticipantIdentity {
        crate::foundation::derive_participant_identity(&self.signing_public)
            .expect("Original signing credential identity")
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn runtime(&self) -> &[u8; 64] {
        &self.runtime
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn position(&self) -> usize {
        self.position
    }
}

/// Canonical public envelope bytes; construction supplies no proof or signature authority.
/// The ballot time is the author's clock reading when its honest attempt lock
/// was created, in Unix milliseconds; only its order against a close time matters.
#[derive(Clone)]
pub struct BallotEnvelope {
    bytes: [u8; ENVELOPE_BYTES],
}
impl BallotEnvelope {
    pub fn new(
        profile: Profile,
        poll: [u8; 64],
        inventory: [u8; 64],
        position: usize,
        ballot_time: u64,
        body_length: usize,
        body_identity: [u8; 64],
    ) -> Result<Self, Error> {
        if position >= profile.participants()
            || !crate::ballot_body::body_lengths(profile).contains(&body_length)
        {
            return Err(Error::Shape);
        }
        let mut bytes = [0; ENVELOPE_BYTES];
        bytes[..4].copy_from_slice(b"LBE2");
        bytes[4..68].copy_from_slice(&poll);
        bytes[68..132].copy_from_slice(&inventory);
        bytes[132..134].copy_from_slice(&(position as u16).to_le_bytes());
        bytes[134..142].copy_from_slice(&ballot_time.to_le_bytes());
        bytes[142..150].copy_from_slice(&(body_length as u64).to_le_bytes());
        bytes[150..].copy_from_slice(&body_identity);
        Ok(Self { bytes })
    }
    pub fn decode(profile: Profile, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ENVELOPE_BYTES || &bytes[..4] != b"LBE2" {
            return Err(Error::Shape);
        }
        Self::new(
            profile,
            bytes[4..68].try_into().unwrap(),
            bytes[68..132].try_into().unwrap(),
            u16::from_le_bytes(bytes[132..134].try_into().unwrap()) as usize,
            u64::from_le_bytes(bytes[134..142].try_into().unwrap()),
            usize::try_from(u64::from_le_bytes(bytes[142..150].try_into().unwrap()))
                .map_err(|_| Error::Shape)?,
            bytes[150..].try_into().unwrap(),
        )
    }
    pub fn bytes(&self) -> &[u8; ENVELOPE_BYTES] {
        &self.bytes
    }
    pub fn poll(&self) -> &[u8; 64] {
        self.bytes[4..68].try_into().unwrap()
    }
    pub fn inventory(&self) -> &[u8; 64] {
        self.bytes[68..132].try_into().unwrap()
    }
    pub fn position(&self) -> usize {
        u16::from_le_bytes(self.bytes[132..134].try_into().unwrap()) as usize
    }
    pub fn ballot_time(&self) -> u64 {
        u64::from_le_bytes(self.bytes[134..142].try_into().unwrap())
    }
    pub fn body_length(&self) -> usize {
        u64::from_le_bytes(self.bytes[142..150].try_into().unwrap()) as usize
    }
    pub fn body_identity(&self) -> &[u8; 64] {
        self.bytes[150..].try_into().unwrap()
    }
    /// The submission identity. Signatures are carriers, so two signatures on
    /// the same envelope are one submission.
    pub fn identity(&self) -> [u8; 64] {
        hash_foundation_tuple_512(
            ENVELOPE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.bytes).expect("fixed envelope length")],
        )
        .expect("fixed envelope identity input")
        .into_bytes()
    }
}

impl Credential {
    /// Keys a retained setup reference to this credential's secret seed. Only
    /// the transition that consumes the owning setup verifier requests a tag, so
    /// a later private operation can refuse references it did not produce. The
    /// tag is local custody evidence, not a public setup capability.
    pub fn retained_setup_tag(
        &self,
        poll: &VerifiedPoll,
        reference: &[u8],
    ) -> [u8; RETAINED_TAG_BYTES] {
        self.retained_tag(RETAINED_SETUP_TAG_LABEL, poll, reference)
    }
    pub fn check_retained_setup_tag(
        &self,
        poll: &VerifiedPoll,
        reference: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        self.check_retained_tag(RETAINED_SETUP_TAG_LABEL, poll, reference, tag)
    }
    pub(crate) fn check_ballot_owner(&self, owner: &RetainedBallotOwner) -> Result<(), Error> {
        if self.completed_body != Some(owner.owner_body)
            || self.signing_public != owner.signing_public
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    /// Mirrors an already authenticated local ballot intent. It grants no
    /// public publication and cannot restore unused authority.
    /// No attempt starts after an authenticated close intent.
    pub fn reserve_ballot_attempt(&mut self, owner: &RetainedBallotOwner) -> Result<(), Error> {
        self.check_ballot_owner(owner)?;
        self.check_unlocked(SigningPurpose::Ballot)?;
        if self.signed_ballot.is_some() || self.close_lock.is_some() {
            return Err(Error::Consumed);
        }
        self.ballot_attempted = true;
        Ok(())
    }
    fn check_owner_context(
        &self,
        poll: &VerifiedPoll,
        context: &RetainedContributionContext,
    ) -> Result<(), Error> {
        self.check_confirmed_context(context)?;
        if context.poll != poll.identity()
            || context.runtime != poll.runtime()
            || context.profile().options() != poll.manifest().option_count()
            || self.completed_body != Some(context.owner_body)
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    /// Every original roster member uses its own verified winning setup
    /// reference, whether its own offer or endorsement was selected or absent.
    pub fn retain_setup_ballot_owner(
        &self,
        poll: &VerifiedPoll,
        context: &RetainedContributionContext,
        inventory: [u8; 64],
        reference: &[u8],
        tag: &[u8],
    ) -> Result<RetainedBallotOwner, Error> {
        self.check_owner_context(poll, context)?;
        self.check_retained_setup_tag(poll, reference, tag)?;
        if reference.get(4..68) != Some(inventory.as_slice()) {
            return Err(Error::Context);
        }
        Ok(RetainedBallotOwner {
            poll: poll.identity(),
            runtime: poll.runtime(),
            inventory,
            position: context.position,
            owner_body: context.owner_body,
            signing_public: self.signing_public,
        })
    }
    pub fn sign_retained_ballot_envelope(
        &mut self,
        owner: &RetainedBallotOwner,
        envelope: &BallotEnvelope,
    ) -> Result<[u8; 3309], Error> {
        if self.completed_body != Some(owner.owner_body)
            || self.signing_public != owner.signing_public
            || envelope.poll() != owner.poll()
            || envelope.inventory() != owner.inventory()
            || envelope.position() != owner.position()
        {
            return Err(Error::Context);
        }
        self.sign_ballot_bytes(envelope)
    }
    pub fn restore_retained_ballot_signing(
        &mut self,
        owner: &RetainedBallotOwner,
        envelope: &BallotEnvelope,
        signature: &[u8],
    ) -> Result<(), Error> {
        if self.signed_ballot.is_some() {
            return Err(Error::Consumed);
        }
        if self.completed_body != Some(owner.owner_body)
            || self.signing_public != owner.signing_public
            || envelope.poll() != owner.poll()
            || envelope.inventory() != owner.inventory()
            || envelope.position() != owner.position()
        {
            return Err(Error::Context);
        }
        let signature = signature.try_into().map_err(|_| Error::Shape)?;
        let public =
            ml_dsa_65::PublicKey::try_from_bytes(self.signing_public).map_err(|_| Error::Shape)?;
        if !public.verify(envelope.bytes(), &signature, BALLOT_SIGNATURE_CONTEXT) {
            return Err(Error::Crypto);
        }
        self.signed_ballot = Some((envelope.identity(), envelope.ballot_time()));
        Ok(())
    }
    /// One signature operation beneath the authenticated participant-state boundary.
    /// The caller must derive the envelope from the exact verified body and setup.
    pub fn sign_ballot_envelope(
        &mut self,
        roster: &OrganizerSignedRoster,
        envelope: &BallotEnvelope,
    ) -> Result<[u8; 3309], Error> {
        if self.signed_ballot.is_some() {
            return Err(Error::Consumed);
        }
        let record = roster
            .proposal()
            .records()
            .get(envelope.position())
            .ok_or(Error::Context)?;
        if envelope.poll() != &record.header().poll
            || record.header().signing_public != self.signing_public
            || self.completed_body != Some(record.body_digest())
        {
            return Err(Error::Context);
        }
        self.sign_ballot_bytes(envelope)
    }
    fn sign_ballot_bytes(&mut self, envelope: &BallotEnvelope) -> Result<[u8; 3309], Error> {
        self.check_unlocked(SigningPurpose::Ballot)?;
        // An attempt locked before the close intent completes; a new one never starts.
        if self.signed_ballot.is_some() || (self.close_lock.is_some() && !self.ballot_attempted) {
            return Err(Error::Consumed);
        }
        self.signed_ballot = Some((envelope.identity(), envelope.ballot_time()));
        let (_, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        private
            .try_sign_with_seed(&[0; 32], envelope.bytes(), BALLOT_SIGNATURE_CONTEXT)
            .map_err(|_| Error::Crypto)
    }
}

pub fn verify_ballot_signature(
    roster: &OrganizerSignedRoster,
    expected_inventory: &[u8; 64],
    envelope: &BallotEnvelope,
    signature: &[u8],
) -> bool {
    let Some(record) = roster.proposal().records().get(envelope.position()) else {
        return false;
    };
    if envelope.poll() != &record.header().poll || envelope.inventory() != expected_inventory {
        return false;
    }
    let Ok(signature) = <[u8; 3309]>::try_from(signature) else {
        return false;
    };
    let Ok(public) = ml_dsa_65::PublicKey::try_from_bytes(record.header().signing_public) else {
        return false;
    };
    public.verify(envelope.bytes(), &signature, BALLOT_SIGNATURE_CONTEXT)
}

#[cfg(test)]
#[path = "ballot-authentication-tests.rs"]
mod tests;
