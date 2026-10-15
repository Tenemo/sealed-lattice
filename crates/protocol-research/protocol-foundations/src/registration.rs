use crate::{
    BodyDigest, Refusal, SIGNATURE_BYTES, foundation::RegistrationHeader, poll::VerifiedPoll,
    verify_registration_signature,
};
use parallel_work::ProtocolHash;
use setup_witness::encrypted_source::{SourceBodyVerifier, ciphertext_bytes};
use supported_profile::Profile;

#[path = "registration-session.rs"]
pub mod session;

pub use parallel_work::CHUNK_LIMIT;
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
    source_families: Vec<Profile>,
    source_index: usize,
    source_remaining: usize,
    source: Option<SourceBodyVerifier>,
}
impl RegistrationVerifier {
    pub fn new(
        poll: &VerifiedPoll,
        header_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Self, Refusal> {
        crate::checked_header(header_bytes, poll)?;
        Self::open(
            poll.identity(),
            header_bytes,
            signature,
            crate::source_binding::fhe_key_families(poll),
        )
    }
    fn open(
        poll: [u8; 64],
        header_bytes: &[u8],
        signature: &[u8],
        source_families: Vec<Profile>,
    ) -> Result<Self, Refusal> {
        let (header, consumed) = RegistrationHeader::decode_prefix(header_bytes)?;
        if consumed != header_bytes.len()
            || source_families.is_empty()
            || source_families.len() != header.source_bindings.len()
        {
            return Err(Refusal::Shape);
        }
        let body = BodyDigest::from_header(header_bytes, poll)?;
        Ok(Self {
            header,
            body,
            signature: signature.try_into().map_err(|_| Refusal::Shape)?,
            key: Vec::with_capacity(KEY_BYTES),
            key_finished: false,
            failed: false,
            source_families,
            source_index: 0,
            source_remaining: 0,
            source: None,
        })
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed
            || self.key_finished
            || bytes.len() > CHUNK_LIMIT
            || bytes.len() > KEY_BYTES - self.key.len()
        {
            self.failed = true;
            return Err(Refusal::Shape);
        }
        self.key.extend(bytes);
        Ok(())
    }
    pub fn finish_key(&mut self) -> Result<(), Refusal> {
        if self.failed
            || self.key_finished
            || !canonical_key(&self.key)
            || ProtocolHash::digest(&self.key) != self.header.recipient_key_hash
        {
            self.failed = true;
            return Err(Refusal::Shape);
        }
        self.key_finished = true;
        Ok(())
    }
    /// The concatenated source bodies, in the signed poll's family order.
    /// Only one coefficient and one hash state are retained across chunks.
    pub fn push_sources(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let result = self.consume_sources(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn consume_sources(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || !self.key_finished || bytes.is_empty() || bytes.len() > CHUNK_LIMIT {
            return Err(Refusal::Shape);
        }
        while !bytes.is_empty() {
            if self.source.is_none() {
                let profile = *self
                    .source_families
                    .get(self.source_index)
                    .ok_or(Refusal::Shape)?;
                let expected = self.header.source_bindings[self.source_index];
                let owner =
                    crate::foundation::derive_participant_identity(&self.header.signing_public)
                        .map_err(|_| Refusal::Shape)?;
                self.source = Some(SourceBodyVerifier::new(
                    profile,
                    &self.header.poll,
                    owner.as_bytes(),
                    expected,
                ));
                self.source_remaining = ciphertext_bytes();
            }
            let count = bytes.len().min(self.source_remaining);
            self.source
                .as_mut()
                .ok_or(Refusal::Consumed)?
                .push(&bytes[..count])
                .map_err(|_| Refusal::Shape)?;
            self.source_remaining -= count;
            bytes = &bytes[count..];
            if self.source_remaining == 0 {
                self.source
                    .take()
                    .ok_or(Refusal::Consumed)?
                    .finish()
                    .map_err(|_| Refusal::Crypto)?;
                self.source_index += 1;
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<VerifiedRegistration, Refusal> {
        if self.failed
            || !self.key_finished
            || self.source_index != self.source_families.len()
            || self.source.is_some()
        {
            return Err(Refusal::Consumed);
        }
        let body_digest = self.body.bytes();
        if !verify_registration_signature(self.body, &self.signature) {
            return Err(Refusal::Crypto);
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
