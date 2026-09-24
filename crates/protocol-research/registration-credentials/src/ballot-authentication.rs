use crate::{Credential, Error, SigningPurpose, roster_authentication::OrganizerSignedRoster};
use crate::{poll::VerifiedPoll, roster::RetainedContributionContext};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use stateful_sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

pub const BALLOT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/ballot-envelope/v1";
pub const ENVELOPE_BYTES: usize = 4 + 64 + 64 + 2 + 8 + 64;
pub const RETAINED_SETUP_TAG_BYTES: usize = 64;
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
#[derive(Clone)]
pub struct BallotEnvelope {
    bytes: [u8; ENVELOPE_BYTES],
}
impl BallotEnvelope {
    pub fn new(
        poll: [u8; 64],
        inventory: [u8; 64],
        position: usize,
        body_length: usize,
        body_identity: [u8; 64],
    ) -> Result<Self, Error> {
        use crate::ballot_body::{
            CIPHERTEXT_BYTES, HEADER_BYTES, MAXIMUM_PROOF_BYTES, MINIMUM_PROOF_BYTES,
        };
        if position >= 20
            || !(HEADER_BYTES + CIPHERTEXT_BYTES + MINIMUM_PROOF_BYTES
                ..=HEADER_BYTES + CIPHERTEXT_BYTES + MAXIMUM_PROOF_BYTES)
                .contains(&body_length)
        {
            return Err(Error::Shape);
        }
        let mut bytes = [0; ENVELOPE_BYTES];
        bytes[..4].copy_from_slice(b"LBE1");
        bytes[4..68].copy_from_slice(&poll);
        bytes[68..132].copy_from_slice(&inventory);
        bytes[132..134].copy_from_slice(&(position as u16).to_le_bytes());
        bytes[134..142].copy_from_slice(&(body_length as u64).to_le_bytes());
        bytes[142..].copy_from_slice(&body_identity);
        Ok(Self { bytes })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ENVELOPE_BYTES || &bytes[..4] != b"LBE1" {
            return Err(Error::Shape);
        }
        Self::new(
            bytes[4..68].try_into().unwrap(),
            bytes[68..132].try_into().unwrap(),
            u16::from_le_bytes(bytes[132..134].try_into().unwrap()) as usize,
            usize::try_from(u64::from_le_bytes(bytes[134..142].try_into().unwrap()))
                .map_err(|_| Error::Shape)?,
            bytes[142..].try_into().unwrap(),
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
    pub fn body_length(&self) -> usize {
        u64::from_le_bytes(self.bytes[134..142].try_into().unwrap()) as usize
    }
    pub fn body_identity(&self) -> &[u8; 64] {
        self.bytes[142..].try_into().unwrap()
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
    ) -> [u8; RETAINED_SETUP_TAG_BYTES] {
        let mut hash = Sha3_512::new();
        hash.update((RETAINED_SETUP_TAG_LABEL.len() as u64).to_le_bytes());
        hash.update(RETAINED_SETUP_TAG_LABEL);
        hash.update(self.signing_seed.as_slice());
        hash.update(poll.identity());
        hash.update(poll.runtime());
        hash.update((reference.len() as u64).to_le_bytes());
        hash.update(reference);
        hash.finalize().into()
    }
    pub fn check_retained_setup_tag(
        &self,
        poll: &VerifiedPoll,
        reference: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let expected = self.retained_setup_tag(poll, reference);
        if tag.len() != expected.len()
            || tag
                .iter()
                .zip(expected)
                .fold(0, |difference, (left, right)| difference | (left ^ right))
                != 0
        {
            return Err(Error::Crypto);
        }
        Ok(())
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
    pub fn reserve_ballot_attempt(&mut self, owner: &RetainedBallotOwner) -> Result<(), Error> {
        self.check_ballot_owner(owner)?;
        self.check_unlocked(SigningPurpose::Ballot)?;
        if self.ballot_signed {
            return Err(Error::Consumed);
        }
        self.ballot_attempted = true;
        Ok(())
    }
    pub fn retain_ballot_owner(
        &self,
        poll: &VerifiedPoll,
        context: &RetainedContributionContext,
        inventory: [u8; 64],
        opening_body: &[u8],
        opening_signature: &[u8],
    ) -> Result<RetainedBallotOwner, Error> {
        if context.poll != poll.identity()
            || context.runtime != poll.runtime()
            || self.completed_body != Some(context.owner_body)
        {
            return Err(Error::Context);
        }
        let (position, _) = crate::contribution_authentication::decode(
            opening_body,
            crate::contribution_authentication::OPENING_CONTEXT,
            inventory,
            crate::foundation::CanonicalItemType::RawBytes,
        )?;
        if position != context.position {
            return Err(Error::Context);
        }
        let signature = opening_signature.try_into().map_err(|_| Error::Shape)?;
        let identity = crate::contribution_authentication::identity(
            "sealed-lattice/setup-opening-id/v1",
            opening_body,
        )?;
        let public =
            ml_dsa_65::PublicKey::try_from_bytes(self.signing_public).map_err(|_| Error::Shape)?;
        if !public.verify(
            &identity,
            &signature,
            crate::contribution_authentication::OPENING_CONTEXT,
        ) {
            return Err(Error::Crypto);
        }
        Ok(RetainedBallotOwner {
            poll: poll.identity(),
            runtime: poll.runtime(),
            inventory,
            position,
            owner_body: context.owner_body,
            signing_public: self.signing_public,
        })
    }
    pub fn sign_retained_ballot_envelope(
        &mut self,
        owner: &RetainedBallotOwner,
        envelope: &BallotEnvelope,
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        if self.completed_body != Some(owner.owner_body)
            || self.signing_public != owner.signing_public
            || envelope.poll() != owner.poll()
            || envelope.inventory() != owner.inventory()
            || envelope.position() != owner.position()
        {
            return Err(Error::Context);
        }
        self.sign_ballot_bytes(envelope, coins)
    }
    pub fn restore_retained_ballot_signing(
        &mut self,
        owner: &RetainedBallotOwner,
        envelope: &BallotEnvelope,
        signature: &[u8],
    ) -> Result<(), Error> {
        if self.ballot_signed {
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
        self.ballot_signed = true;
        Ok(())
    }
    /// One signature operation beneath the authenticated participant-state boundary.
    /// The caller must derive the envelope from the exact verified body and setup.
    pub fn sign_ballot_envelope(
        &mut self,
        roster: &OrganizerSignedRoster,
        envelope: &BallotEnvelope,
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        if self.ballot_signed {
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
        self.sign_ballot_bytes(envelope, coins)
    }
    fn sign_ballot_bytes(
        &mut self,
        envelope: &BallotEnvelope,
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        self.check_unlocked(SigningPurpose::Ballot)?;
        if self.ballot_signed {
            return Err(Error::Consumed);
        }
        self.ballot_signed = true;
        let coins = Zeroizing::new(coins);
        let (_, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        private
            .try_sign_with_seed(&coins, envelope.bytes(), BALLOT_SIGNATURE_CONTEXT)
            .map_err(|_| Error::Crypto)
    }
    pub fn restore_ballot_signing(
        &mut self,
        roster: &OrganizerSignedRoster,
        expected_inventory: &[u8; 64],
        envelope: &BallotEnvelope,
        signature: &[u8],
    ) -> Result<(), Error> {
        if self.ballot_signed {
            return Err(Error::Consumed);
        }
        let record = roster
            .proposal()
            .records()
            .get(envelope.position())
            .ok_or(Error::Context)?;
        if record.header().signing_public != self.signing_public
            || self.completed_body != Some(record.body_digest())
        {
            return Err(Error::Context);
        }
        if !verify_ballot_signature(roster, expected_inventory, envelope, signature) {
            return Err(Error::Crypto);
        }
        self.ballot_signed = true;
        Ok(())
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
mod tests {
    use super::*;
    use crate::ballot_body::*;
    use crate::foundation::{
        StabilizedDisplayText,
        ceremony::{Manifest, OptionDefinition},
    };
    use crate::poll::{PollDraft, verify_poll};
    fn verified_poll(runtime: [u8; 64]) -> VerifiedPoll {
        let label =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        let options = (0..10)
            .map(|index| {
                OptionDefinition::new(
                    index,
                    format!("option-{index}"),
                    label(&format!("O{index}")),
                )
                .unwrap()
            })
            .collect();
        let draft = PollDraft::new(Manifest::new(label("Question"), options).unwrap(), 10).unwrap();
        let packet = Credential::from_seeds([20; 32], [21; 32], [22; 32])
            .create_poll(draft, runtime, [3; 32], [4; 32])
            .unwrap();
        verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap()
    }
    #[test]
    fn retained_setup_tags_bind_the_credential_poll_and_exact_reference() {
        let participant = Credential::from_seeds([7; 32], [8; 32], [9; 32]);
        let same_seed = Credential::from_seeds([7; 32], [11; 32], [12; 32]);
        let other = Credential::from_seeds([10; 32], [8; 32], [9; 32]);
        let poll = verified_poll([2; 64]);
        let reference = [b"SAV1".as_slice(), &[5; 64], &[6; 128]].concat();
        let tag = participant.retained_setup_tag(&poll, &reference);
        assert!(
            participant
                .check_retained_setup_tag(&poll, &reference, &tag)
                .is_ok()
        );
        // The key is the signing seed alone, so a restored credential accepts
        // its earlier tag while every other credential refuses it.
        assert!(
            same_seed
                .check_retained_setup_tag(&poll, &reference, &tag)
                .is_ok()
        );
        assert!(
            other
                .check_retained_setup_tag(&poll, &reference, &tag)
                .is_err()
        );
        assert!(
            participant
                .check_retained_setup_tag(&verified_poll([9; 64]), &reference, &tag)
                .is_err()
        );
        let mut changed = reference.clone();
        changed[70] ^= 1;
        let extended = [reference.as_slice(), &[0]].concat();
        for candidate in [&changed[..], &reference[..reference.len() - 1], &extended] {
            assert!(
                participant
                    .check_retained_setup_tag(&poll, candidate, &tag)
                    .is_err()
            );
        }
        let mut forged = tag;
        forged[RETAINED_SETUP_TAG_BYTES - 1] ^= 1;
        let long_tag = [tag.as_slice(), &[0]].concat();
        for candidate in [
            &forged[..],
            &tag[..RETAINED_SETUP_TAG_BYTES - 1],
            &long_tag,
            &[],
        ] {
            assert!(
                participant
                    .check_retained_setup_tag(&poll, &reference, candidate)
                    .is_err()
            );
        }
    }
    #[test]
    fn envelope_lengths_and_positions_are_bounded_before_body_work() {
        let minimum = HEADER_BYTES + CIPHERTEXT_BYTES + MINIMUM_PROOF_BYTES;
        let maximum = HEADER_BYTES + CIPHERTEXT_BYTES + MAXIMUM_PROOF_BYTES;
        for length in [minimum, maximum] {
            let value = BallotEnvelope::new([1; 64], [2; 64], 19, length, [3; 64]).unwrap();
            assert_eq!(
                BallotEnvelope::decode(value.bytes()).unwrap().bytes(),
                value.bytes()
            );
            assert!(BallotEnvelope::decode(&value.bytes()[..ENVELOPE_BYTES - 1]).is_err());
            let mut extended = value.bytes().to_vec();
            extended.push(0);
            assert!(BallotEnvelope::decode(&extended).is_err());
        }
        for length in [minimum - 1, maximum + 1, usize::MAX] {
            assert!(BallotEnvelope::new([1; 64], [2; 64], 0, length, [3; 64]).is_err());
        }
        assert!(BallotEnvelope::new([1; 64], [2; 64], 20, minimum, [3; 64]).is_err());
    }
}
