use crate::{
    BodyDigest, Error, SIGNATURE_BYTES, foundation::RegistrationHeader, poll::VerifiedPoll,
    verify_registration_signature,
};
use parallel_work::ProtocolHash;

#[path = "registration-session.rs"]
pub mod session;

pub const CHUNK_LIMIT: usize = 1 << 20;
pub const KEY_BYTES: usize = supported_profile::DEGREE * 21;

pub struct VerifiedRegistration {
    header: RegistrationHeader,
    body_digest: [u8; 64],
    public_key: Vec<u8>,
}
impl VerifiedRegistration {
    pub fn header(&self) -> &RegistrationHeader {
        &self.header
    }
    pub fn body_digest(&self) -> [u8; 64] {
        self.body_digest
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    #[cfg(test)]
    pub(crate) fn for_roster(header: RegistrationHeader, body_digest: [u8; 64]) -> Self {
        Self {
            header,
            body_digest,
            public_key: Vec::new(),
        }
    }
}

// Canonical centered coefficients are required independently of any proof.
// Check bytes directly: signs are 0/1, zero is positive, and magnitude is at
// most floor(q/2). No bound on a corrupt recipient's secret is assumed here.
pub(crate) fn canonical_key(bytes: &[u8]) -> bool {
    if bytes.len() != KEY_BYTES {
        return false;
    }
    let mut half = supported_profile::share_modulus().to_vec();
    let mut carry = 0;
    for byte in half.iter_mut().rev() {
        let next = (*byte & 1) << 7;
        *byte = (*byte >> 1) | carry;
        carry = next;
    }
    bytes.chunks_exact(1 + half.len()).all(|coefficient| {
        coefficient[0] <= 1
            && (coefficient[0] == 0 || coefficient[1..].iter().any(|byte| *byte != 0))
            && coefficient[1..].iter().rev().cmp(half.iter().rev()) != std::cmp::Ordering::Greater
    })
}

pub struct RegistrationVerifier {
    header: RegistrationHeader,
    body: BodyDigest,
    signature: [u8; SIGNATURE_BYTES],
    key: Vec<u8>,
    key_finished: bool,
    failed: bool,
}
impl RegistrationVerifier {
    pub fn new(poll: &VerifiedPoll, header_bytes: &[u8], signature: &[u8]) -> Result<Self, Error> {
        crate::checked_header(header_bytes, poll)?;
        Self::open(poll.identity(), poll.runtime(), header_bytes, signature)
    }
    fn open(
        poll: [u8; 64],
        runtime: [u8; 64],
        header_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Self, Error> {
        let (header, consumed) = RegistrationHeader::decode_prefix(header_bytes)?;
        if consumed != header_bytes.len() {
            return Err(Error::Shape);
        }
        let body = BodyDigest::from_header(header_bytes, poll, runtime)?;
        Ok(Self {
            header,
            body,
            signature: signature.try_into().map_err(|_| Error::Shape)?,
            key: Vec::with_capacity(KEY_BYTES),
            key_finished: false,
            failed: false,
        })
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed
            || self.key_finished
            || bytes.len() > CHUNK_LIMIT
            || bytes.len() > KEY_BYTES - self.key.len()
        {
            self.failed = true;
            return Err(Error::Shape);
        }
        self.key.extend(bytes);
        Ok(())
    }
    pub fn finish_key(&mut self) -> Result<(), Error> {
        if self.failed
            || self.key_finished
            || !canonical_key(&self.key)
            || ProtocolHash::digest(&self.key) != self.header.recipient_key_hash
        {
            self.failed = true;
            return Err(Error::Shape);
        }
        self.key_finished = true;
        Ok(())
    }
    pub fn finish(self) -> Result<VerifiedRegistration, Error> {
        if self.failed || !self.key_finished {
            return Err(Error::Consumed);
        }
        let body_digest = self.body.bytes();
        if !verify_registration_signature(self.body, &self.signature) {
            return Err(Error::Crypto);
        }
        Ok(VerifiedRegistration {
            header: self.header,
            body_digest,
            public_key: self.key,
        })
    }
}

#[cfg(test)]
#[path = "registration-tests.rs"]
mod tests;
