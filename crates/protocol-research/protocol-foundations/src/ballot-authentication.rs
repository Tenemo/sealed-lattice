use crate::{
    Credential, RETAINED_TAG_BYTES, Refusal, SIGNATURE_BYTES, SIGNING_PUBLIC_KEY_BYTES,
    SigningPurpose, roster_authentication::AuthenticatedRosterProposal,
};
use crate::{
    foundation::{CanonicalItem, hash_foundation_tuple_512},
    poll::VerifiedPoll,
    roster::RetainedContributionContext,
};
use supported_profile::Profile;

pub(crate) const BALLOT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/ballot-envelope";
/// The envelope's fields start at these offsets: the poll, the setup
/// identity, the author's position, the ballot time, the body length and the
/// body identity.
pub const ENVELOPE_POLL_OFFSET: usize = 0;
pub const ENVELOPE_SETUP_IDENTITY_OFFSET: usize = 64;
pub const ENVELOPE_POSITION_OFFSET: usize = 128;
pub const ENVELOPE_BALLOT_TIME_OFFSET: usize = 130;
pub const ENVELOPE_BODY_LENGTH_OFFSET: usize = 138;
pub(crate) const ENVELOPE_BODY_IDENTITY_OFFSET: usize = 146;
pub const ENVELOPE_BYTES: usize = ENVELOPE_BODY_IDENTITY_OFFSET + 64;
pub const ENVELOPE_IDENTITY_DOMAIN: &str = "sealed-lattice/ballot-envelope-identity";
const RETAINED_SETUP_TAG_LABEL: &[u8] = b"sealed-lattice/retained-setup-reference";

/// Original credential correspondence beneath the authenticated participant root.
/// This creates no public roster, setup, ballot, or unspent-attempt capability.
pub struct RetainedSetupOwner {
    poll: [u8; 64],
    setup_identity: [u8; 64],
    position: usize,
    owner_body: [u8; 64],
    signing_public: [u8; SIGNING_PUBLIC_KEY_BYTES],
}
impl RetainedSetupOwner {
    pub fn participant_identity(
        &self,
    ) -> crate::foundation::participant_identity::ParticipantIdentity {
        crate::foundation::derive_participant_identity(&self.signing_public)
            .expect("Original signing credential identity")
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn setup_identity(&self) -> &[u8; 64] {
        &self.setup_identity
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
        setup_identity: [u8; 64],
        position: usize,
        ballot_time: u64,
        body_length: usize,
        body_identity: [u8; 64],
    ) -> Result<Self, Refusal> {
        if position >= profile.participants()
            || !crate::ballot_body::body_lengths(profile).contains(&body_length)
        {
            return Err(Refusal::Shape);
        }
        let mut bytes = [0; ENVELOPE_BYTES];
        bytes[ENVELOPE_POLL_OFFSET..ENVELOPE_SETUP_IDENTITY_OFFSET].copy_from_slice(&poll);
        bytes[ENVELOPE_SETUP_IDENTITY_OFFSET..ENVELOPE_POSITION_OFFSET]
            .copy_from_slice(&setup_identity);
        bytes[ENVELOPE_POSITION_OFFSET..ENVELOPE_BALLOT_TIME_OFFSET]
            .copy_from_slice(&(position as u16).to_le_bytes());
        bytes[ENVELOPE_BALLOT_TIME_OFFSET..ENVELOPE_BODY_LENGTH_OFFSET]
            .copy_from_slice(&ballot_time.to_le_bytes());
        bytes[ENVELOPE_BODY_LENGTH_OFFSET..ENVELOPE_BODY_IDENTITY_OFFSET]
            .copy_from_slice(&(body_length as u64).to_le_bytes());
        bytes[ENVELOPE_BODY_IDENTITY_OFFSET..].copy_from_slice(&body_identity);
        Ok(Self { bytes })
    }
    pub fn decode(profile: Profile, bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() != ENVELOPE_BYTES {
            return Err(Refusal::Shape);
        }
        let fields = Self {
            bytes: bytes.try_into().unwrap(),
        };
        let body_length = usize::try_from(u64::from_le_bytes(
            bytes[ENVELOPE_BODY_LENGTH_OFFSET..ENVELOPE_BODY_IDENTITY_OFFSET]
                .try_into()
                .unwrap(),
        ))
        .map_err(|_| Refusal::Shape)?;
        Self::new(
            profile,
            *fields.poll(),
            *fields.setup_identity(),
            fields.position(),
            fields.ballot_time(),
            body_length,
            *fields.body_identity(),
        )
    }
    pub fn bytes(&self) -> &[u8; ENVELOPE_BYTES] {
        &self.bytes
    }
    pub fn poll(&self) -> &[u8; 64] {
        self.bytes[ENVELOPE_POLL_OFFSET..ENVELOPE_SETUP_IDENTITY_OFFSET]
            .try_into()
            .unwrap()
    }
    pub fn setup_identity(&self) -> &[u8; 64] {
        self.bytes[ENVELOPE_SETUP_IDENTITY_OFFSET..ENVELOPE_POSITION_OFFSET]
            .try_into()
            .unwrap()
    }
    pub fn position(&self) -> usize {
        u16::from_le_bytes(
            self.bytes[ENVELOPE_POSITION_OFFSET..ENVELOPE_BALLOT_TIME_OFFSET]
                .try_into()
                .unwrap(),
        ) as usize
    }
    pub fn ballot_time(&self) -> u64 {
        u64::from_le_bytes(
            self.bytes[ENVELOPE_BALLOT_TIME_OFFSET..ENVELOPE_BODY_LENGTH_OFFSET]
                .try_into()
                .unwrap(),
        )
    }
    pub fn body_length(&self) -> usize {
        u64::from_le_bytes(
            self.bytes[ENVELOPE_BODY_LENGTH_OFFSET..ENVELOPE_BODY_IDENTITY_OFFSET]
                .try_into()
                .unwrap(),
        ) as usize
    }
    pub fn body_identity(&self) -> &[u8; 64] {
        self.bytes[ENVELOPE_BODY_IDENTITY_OFFSET..]
            .try_into()
            .unwrap()
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
    ) -> Result<(), Refusal> {
        self.check_retained_tag(RETAINED_SETUP_TAG_LABEL, poll, reference, tag)
    }
    pub(crate) fn check_setup_owner(&self, owner: &RetainedSetupOwner) -> Result<(), Refusal> {
        if self.completed_body != Some(owner.owner_body)
            || self.signing_public != owner.signing_public
        {
            return Err(Refusal::Context);
        }
        Ok(())
    }
    /// Mirrors an already authenticated local ballot intent. It grants no
    /// public publication and cannot restore unused authority.
    /// No attempt starts after an authenticated close intent.
    pub fn reserve_ballot_attempt(&mut self, owner: &RetainedSetupOwner) -> Result<(), Refusal> {
        self.check_setup_owner(owner)?;
        self.check_unlocked(SigningPurpose::Ballot)?;
        if self.signed_ballot.is_some() || self.close_lock.is_some() {
            return Err(Refusal::Consumed);
        }
        self.ballot_attempted = true;
        Ok(())
    }
    fn check_owner_context(
        &self,
        poll: &VerifiedPoll,
        context: &RetainedContributionContext,
    ) -> Result<(), Refusal> {
        self.check_confirmed_context(context)?;
        if context.poll != poll.identity()
            || context.profile().options() != poll.manifest().option_count()
            || self.completed_body != Some(context.owner_body)
        {
            return Err(Refusal::Context);
        }
        Ok(())
    }
    /// Every original roster member uses its own verified winning setup
    /// reference, whether its own offer or endorsement was selected or absent.
    pub fn retain_setup_owner(
        &self,
        poll: &VerifiedPoll,
        context: &RetainedContributionContext,
        setup_identity: [u8; 64],
        reference: &[u8],
        tag: &[u8],
    ) -> Result<RetainedSetupOwner, Refusal> {
        self.check_owner_context(poll, context)?;
        self.check_retained_setup_tag(poll, reference, tag)?;
        if reference.get(..64) != Some(setup_identity.as_slice()) {
            return Err(Refusal::Context);
        }
        Ok(RetainedSetupOwner {
            poll: poll.identity(),
            setup_identity,
            position: context.position,
            owner_body: context.owner_body,
            signing_public: self.signing_public,
        })
    }
    pub fn sign_retained_ballot_envelope(
        &mut self,
        owner: &RetainedSetupOwner,
        envelope: &BallotEnvelope,
    ) -> Result<[u8; SIGNATURE_BYTES], Refusal> {
        if self.completed_body != Some(owner.owner_body)
            || self.signing_public != owner.signing_public
            || envelope.poll() != owner.poll()
            || envelope.setup_identity() != owner.setup_identity()
            || envelope.position() != owner.position()
        {
            return Err(Refusal::Context);
        }
        self.sign_ballot_bytes(envelope)
    }
    pub fn restore_retained_ballot_signing(
        &mut self,
        owner: &RetainedSetupOwner,
        envelope: &BallotEnvelope,
        signature: &[u8],
    ) -> Result<(), Refusal> {
        if self.signed_ballot.is_some() {
            return Err(Refusal::Consumed);
        }
        if self.completed_body != Some(owner.owner_body)
            || self.signing_public != owner.signing_public
            || envelope.poll() != owner.poll()
            || envelope.setup_identity() != owner.setup_identity()
            || envelope.position() != owner.position()
        {
            return Err(Refusal::Context);
        }
        let signature: [u8; SIGNATURE_BYTES] = signature.try_into().map_err(|_| Refusal::Shape)?;
        let public = crate::authentication::PublicKey::from_bytes(self.signing_public);
        if !public.verify(envelope.bytes(), &signature, BALLOT_SIGNATURE_CONTEXT) {
            return Err(Refusal::Crypto);
        }
        self.signed_ballot = Some((envelope.identity(), envelope.ballot_time()));
        Ok(())
    }
    fn sign_ballot_bytes(
        &mut self,
        envelope: &BallotEnvelope,
    ) -> Result<[u8; SIGNATURE_BYTES], Refusal> {
        self.check_unlocked(SigningPurpose::Ballot)?;
        // An attempt locked before the close intent completes; a new one never starts.
        if self.signed_ballot.is_some() || (self.close_lock.is_some() && !self.ballot_attempted) {
            return Err(Refusal::Consumed);
        }
        self.signed_ballot = Some((envelope.identity(), envelope.ballot_time()));
        self.sign_deterministically(envelope.bytes(), BALLOT_SIGNATURE_CONTEXT)
    }
}

pub fn verify_ballot_signature(
    roster: &AuthenticatedRosterProposal,
    expected_setup_identity: &[u8; 64],
    envelope: &BallotEnvelope,
    signature: &[u8],
) -> bool {
    let Some(record) = roster.proposal().records().get(envelope.position()) else {
        return false;
    };
    if envelope.poll() != &record.header().poll
        || envelope.setup_identity() != expected_setup_identity
    {
        return false;
    }
    let Ok(signature) = <[u8; SIGNATURE_BYTES]>::try_from(signature) else {
        return false;
    };
    let public = crate::authentication::PublicKey::from_bytes(record.header().signing_public);
    public.verify(envelope.bytes(), &signature, BALLOT_SIGNATURE_CONTEXT)
}

#[cfg(test)]
#[path = "ballot-authentication-tests.rs"]
mod tests;
