use crate::{Credential, Error, SIGNING_PUBLIC_KEY_BYTES};
use parallel_work::sealing::{self, Sealed, TAG_BYTES};
use zeroize::Zeroizing;

/// The sealed signing seed: its magic, the seed and the AES-GCM tag.
pub const SEALED_SIGNING_SEED_BYTES: usize = 4 + 32 + TAG_BYTES;

/// Signing purposes that a restored credential withholds until the
/// authenticated participant root unlocks those its records show unused.
/// Each discriminant is the purpose's bit position in the unused-purpose
/// mask, which the worker names the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningPurpose {
    RosterProposal = 0,
    Offer = 1,
    SelectionProposal = 2,
    SelectionEndorsement = 3,
    Ballot = 4,
    CloseIntent = 5,
    CloseResponse = 6,
    CloseProposal = 7,
    Target = 8,
    Release = 9,
}
impl SigningPurpose {
    pub const fn mask(self) -> u16 {
        1 << self as u16
    }
}
const ALL_SIGNING_PURPOSES: u16 = (SigningPurpose::Release.mask() << 1) - 1;

fn associated(body: [u8; 64]) -> Vec<u8> {
    let mut bytes = Vec::from(b"registration-signing-seed/1".as_slice());
    bytes.extend(body);
    bytes
}

impl Credential {
    /// Seals the completed signing seed under a fresh key, once.
    pub fn seal_complete(&mut self) -> Result<Sealed, Error> {
        if self.sealed {
            return Err(Error::Consumed);
        }
        let body = self.completed_body.ok_or(Error::Consumed)?;
        self.sealed = true;
        if !self.check_retained() {
            return Err(Error::Crypto);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(4 + 32));
        bytes.extend(b"RCS1");
        bytes.extend(*self.signing_seed);
        Ok(sealing::seal(&bytes, &associated(body)))
    }
    pub fn open_complete(
        signing_public: [u8; SIGNING_PUBLIC_KEY_BYTES],
        body: [u8; 64],
        key: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Self, Error> {
        if sealed.len() != SEALED_SIGNING_SEED_BYTES {
            return Err(Error::Shape);
        }
        let bytes = sealing::open(key, &associated(body), sealed).ok_or(Error::Crypto)?;
        if bytes.len() != 36 || &bytes[..4] != b"RCS1" {
            return Err(Error::Shape);
        }
        let value = Self {
            signing_seed: Zeroizing::new(bytes[4..].try_into().map_err(|_| Error::Shape)?),
            signing_public,
            signed: true,
            completed_body: Some(body),
            sealed: true,
            poll_creation_consumed: true,
            proposal_signed: false,
            signed_ballot: None,
            ballot_attempted: false,
            close_intent_signed: false,
            close_lock: None,
            close_response: None,
            close_proposal_signed: false,
            target_signed: false,
            target_lock: None,
            release_started: false,
            release_signed: false,
            confirmed_roster: None,
            offer_signed: None,
            selection_proposal_signed: None,
            selection_endorsed: None,
            preparation_retired: false,
            locked_purposes: ALL_SIGNING_PURPOSES,
        };
        if !value.check_retained() {
            return Err(Error::Crypto);
        }
        Ok(value)
    }
    /// Unlocks the purposes that the authenticated participant root has shown
    /// unused. Completed messages are restored from their verified records
    /// instead, so a purpose left locked signs nothing new.
    pub fn unlock_unused_purposes(&mut self, mask: u16) -> Result<(), Error> {
        if mask & !ALL_SIGNING_PURPOSES != 0 {
            return Err(Error::Shape);
        }
        self.locked_purposes &= !mask;
        Ok(())
    }
    pub(crate) fn check_unlocked(&self, purpose: SigningPurpose) -> Result<(), Error> {
        if self.locked_purposes & purpose.mask() != 0 {
            return Err(Error::Consumed);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "custody-tests.rs"]
mod tests;
