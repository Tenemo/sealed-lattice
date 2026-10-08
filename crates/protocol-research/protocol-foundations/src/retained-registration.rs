//! The participant's own registration, which its registration verifier
//! accepted, retained beneath the participant root and keyed to the
//! credential the header names. A later visit of the same participant
//! restores the verifier's result from the header and the key alone: the
//! header must be the one the verifier accepted and the key must hash to the
//! value that header names, so another signature verification is unnecessary.
use super::{RegistrationVerifier, VerifiedRegistration};
use crate::{
    Credential, Error, RETAINED_TAG_BYTES, foundation::RegistrationHeader, poll::VerifiedPoll,
};

const LABEL: &[u8] = b"sealed-lattice/retained-registration/v2";

/// A retained registration: the body digest and the credential tag.
pub const RETAINED_REGISTRATION_BYTES: usize = 64 + RETAINED_TAG_BYTES;

// The bytes the tag covers: the length-prefixed canonical header, then the
// body digest.
fn tagged_bytes(header: &RegistrationHeader, digests: &[u8]) -> Result<Vec<u8>, Error> {
    let header = header.encode()?;
    Ok([
        (header.len() as u32).to_le_bytes().as_slice(),
        &header,
        digests,
    ]
    .concat())
}

// The credential must be the one the header names, for the header's poll.
fn check_owner(
    credential: &Credential,
    poll: &VerifiedPoll,
    header: &RegistrationHeader,
) -> Result<(), Error> {
    if credential.signing_public() != &header.signing_public
        || poll.identity() != header.poll
        || poll.runtime() != header.runtime
        || header.fhe_key_commitments.len() != crate::source_binding::fhe_key_families(poll).len()
    {
        return Err(Error::Context);
    }
    Ok(())
}

impl VerifiedRegistration {
    /// Keys the participant's own registration, as its verifier accepted
    /// it, to the credential the header names.
    pub fn retain(&self, credential: &Credential, poll: &VerifiedPoll) -> Result<Vec<u8>, Error> {
        check_owner(credential, poll, &self.header)?;
        let digests = self.body_digest.to_vec();
        let tag = credential.retained_tag(LABEL, poll, &tagged_bytes(&self.header, &digests)?);
        Ok([digests.as_slice(), &tag].concat())
    }
}

impl RegistrationVerifier {
    /// Restores the participant's own registration from its retained copy
    /// once the complete canonical key its header names has arrived.
    /// Only the credential that retained it restores it.
    pub fn restore(
        self,
        credential: &Credential,
        poll: &VerifiedPoll,
        retained: &[u8],
    ) -> Result<VerifiedRegistration, Error> {
        if self.failed || !self.key_finished {
            return Err(Error::Consumed);
        }
        if retained.len() != RETAINED_REGISTRATION_BYTES {
            return Err(Error::Shape);
        }
        check_owner(credential, poll, &self.header)?;
        let (digests, tag) = retained.split_at(64);
        credential.check_retained_tag(LABEL, poll, &tagged_bytes(&self.header, digests)?, tag)?;
        Ok(VerifiedRegistration {
            header: self.header,
            body_digest: digests.try_into().unwrap(),
            public_key: self.key,
        })
    }
}

#[cfg(test)]
#[path = "retained-registration-tests.rs"]
mod tests;
