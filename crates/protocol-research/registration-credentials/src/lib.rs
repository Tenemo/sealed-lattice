#[path = "ballot-authentication.rs"]
pub mod ballot_authentication;
#[path = "ballot-body.rs"]
pub mod ballot_body;
#[path = "close-signing.rs"]
pub mod close_signing;
#[path = "contribution-body.rs"]
pub mod contribution_body;
#[path = "contribution-offer.rs"]
pub mod contribution_offer;
mod custody;
mod preparation;
#[path = "setup-selection.rs"]
pub mod setup_selection;
pub use custody::{SEALED_SIGNING_SEED_BYTES, SigningPurpose};
pub mod foundation;
pub mod identity;
pub mod poll;
pub mod registration;
#[path = "release-signing.rs"]
pub mod release_signing;
#[path = "retained-roster.rs"]
pub mod retained_roster;
#[cfg(test)]
#[path = "role-ownership-tests.rs"]
mod role_ownership_tests;
pub mod roster;
#[path = "roster-authentication.rs"]
pub mod roster_authentication;
#[path = "roster-input.rs"]
pub mod roster_input;
#[path = "source-binding.rs"]
pub mod source_binding;
#[path = "target-signing.rs"]
pub mod target_signing;

use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use foundation::{CanonicalItem, RegistrationHeader, hash_foundation_tuple_512};
use parallel_work::ProtocolHash;
use poll::VerifiedPoll;

use zeroize::Zeroizing;

pub const SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/registration/v1";
/// Every participant signature is one ML-DSA-65 signature.
pub const SIGNATURE_BYTES: usize = ml_dsa_65::SIG_LEN;
/// A tag that keys retained bytes to a credential is this long.
pub const RETAINED_TAG_BYTES: usize = 64;

/// The jobs this crate defines.
pub static JOBS: [&parallel_work::Job; 1] = [&registration::session::REGISTRATION];

#[derive(Debug)]
pub enum Error {
    Shape,
    Context,
    Consumed,
    Crypto,
}

pub struct Credential {
    signing_seed: Zeroizing<[u8; 32]>,
    signing_public: [u8; 1952],
    signed: bool,
    completed_body: Option<[u8; 64]>,
    sealed: bool,
    poll_creation_consumed: bool,
    proposal_signed: bool,
    // The signed envelope identity and ballot time.
    signed_ballot: Option<([u8; 64], u64)>,
    ballot_attempted: bool,
    close_intent_signed: bool,
    // The first authenticated close intent and its close time.
    close_lock: Option<([u8; 64], u64)>,
    close_response: Option<[u8; 64]>,
    close_proposal_signed: bool,
    target_signed: bool,
    target_lock: Option<[u8; 64]>,
    release_started: bool,
    release_signed: bool,
    confirmed_roster: Option<preparation::ConfirmedRoster>,
    offer_signed: Option<[u8; 64]>,
    selection_proposal_signed: Option<[u8; 64]>,
    selection_endorsed: Option<[u8; 64]>,
    preparation_retired: bool,
    locked_purposes: u16,
}
impl Credential {
    pub fn from_seed(signing: [u8; 32]) -> Self {
        let signing_seed = Zeroizing::new(signing);
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
        drop(private);
        Self {
            signing_seed,
            signing_public: public.into_bytes(),
            signed: false,
            completed_body: None,
            sealed: false,
            poll_creation_consumed: false,
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
            locked_purposes: 0,
        }
    }
    pub fn signing_public(&self) -> &[u8; 1952] {
        &self.signing_public
    }
    pub fn sign_registration(&mut self, body: BodyDigest) -> Result<[u8; 3309], Error> {
        if self.signed {
            return Err(Error::Consumed);
        }
        if body.signing_public != self.signing_public {
            return Err(Error::Context);
        }
        self.signed = true;
        self.poll_creation_consumed = true;
        let (_, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        let signature = private
            .try_sign_with_seed(&[0; 32], &body.digest, SIGNATURE_CONTEXT)
            .map_err(|_| Error::Crypto)?;
        self.completed_body = Some(body.digest);
        Ok(signature)
    }

    pub fn check_retained(&self) -> bool {
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        drop(private);
        public.into_bytes() == self.signing_public
    }

    /// Keys a result that its owning verifier or evaluator produced to this
    /// credential's secret seed, under the label of what the bytes are and
    /// the poll and runtime they belong to. Only the transition that
    /// consumes the owner's result requests a tag, so a later operation of
    /// the same participant refuses bytes it did not retain. The tag is
    /// local custody evidence, not a public capability.
    pub fn retained_tag(
        &self,
        label: &[u8],
        poll: &VerifiedPoll,
        bytes: &[u8],
    ) -> [u8; RETAINED_TAG_BYTES] {
        let mut hash = ProtocolHash::new();
        hash.update((label.len() as u64).to_le_bytes());
        hash.update(label);
        hash.update(self.signing_seed.as_slice());
        hash.update(poll.identity());
        hash.update(poll.runtime());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        hash.finalize()
    }
    pub fn check_retained_tag(
        &self,
        label: &[u8],
        poll: &VerifiedPoll,
        bytes: &[u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let expected = self.retained_tag(label, poll, bytes);
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
}

pub struct BodyDigest {
    digest: [u8; 64],
    signing_public: [u8; 1952],
}
impl BodyDigest {
    pub fn bytes(&self) -> [u8; 64] {
        self.digest
    }
    pub fn new(header: RegistrationHeader) -> Result<Self, Error> {
        check_header(&header)?;
        let encoded = header.encode()?;
        let digest = hash_foundation_tuple_512(
            "sealed-lattice/registration-body/v2",
            &[CanonicalItem::variable_bytes(encoded).map_err(|_| Error::Shape)?],
        )
        .map_err(|_| Error::Shape)?
        .into_bytes();
        Ok(Self {
            digest,
            signing_public: header.signing_public,
        })
    }
    pub fn from_header(
        bytes: &[u8],
        expected_poll: [u8; 64],
        expected_runtime: [u8; 64],
    ) -> Result<Self, Error> {
        let (header, consumed) = RegistrationHeader::decode_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(Error::Shape);
        }
        if header.poll != expected_poll || header.runtime != expected_runtime {
            return Err(Error::Context);
        }
        Self::new(header)
    }
}

fn check_header(header: &RegistrationHeader) -> Result<(), Error> {
    ml_dsa_65::PublicKey::try_from_bytes(header.signing_public).map_err(|_| Error::Shape)?;
    Ok(())
}

/// A complete registration header of the poll and runtime, checked as the
/// registration verifier checks it.
pub(crate) fn checked_header(
    bytes: &[u8],
    poll: &VerifiedPoll,
) -> Result<RegistrationHeader, Error> {
    let (header, consumed) = RegistrationHeader::decode_prefix(bytes)?;
    if consumed != bytes.len() {
        return Err(Error::Shape);
    }
    if header.poll != poll.identity()
        || header.runtime != poll.runtime()
        || header.fhe_key_commitments.len() != source_binding::fhe_key_families(poll).len()
    {
        return Err(Error::Context);
    }
    check_header(&header)?;
    Ok(header)
}

pub fn verify_registration_signature(body: BodyDigest, signature: &[u8]) -> bool {
    let Ok(signature) = signature.try_into() else {
        return false;
    };
    let Ok(public) = ml_dsa_65::PublicKey::try_from_bytes(body.signing_public) else {
        return false;
    };
    public.verify(&body.digest, &signature, SIGNATURE_CONTEXT)
}

#[cfg(test)]
#[path = "lib-tests.rs"]
mod tests;
