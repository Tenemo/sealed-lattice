use crate::{
    BodyHasher, Error, foundation::RegistrationHeader, poll::VerifiedPoll, registration_proof_role,
    verify_registration_signature,
};
use parallel_work::{Digest, ProtocolHash};
use registration_proof::statement;
use registration_proof::{CHUNK_LIMIT, HEADER_LENGTH, Verifier, verifier};

#[path = "retained-registration.rs"]
mod retained;
#[path = "registration-session.rs"]
pub mod session;
pub use retained::RETAINED_REGISTRATION_BYTES;

/// A registration public key: a sign byte and a share-modulus magnitude for
/// each coefficient.
pub const KEY_BYTES: usize = 65536 * 21;
pub struct VerifiedRegistration {
    header: RegistrationHeader,
    body_digest: [u8; 64],
    proof_hash: [u8; 64],
    public_key: Vec<u8>,
}
impl VerifiedRegistration {
    pub fn header(&self) -> &RegistrationHeader {
        &self.header
    }
    pub fn body_digest(&self) -> [u8; 64] {
        self.body_digest
    }
    pub fn proof_hash(&self) -> [u8; 64] {
        self.proof_hash
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    /// The registration verifier's result as a retained roster keeps it:
    /// the accepted header, body digest and proof hash, and the key whose
    /// hash that header names.
    pub(crate) fn restored(
        header: RegistrationHeader,
        body_digest: [u8; 64],
        proof_hash: [u8; 64],
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            header,
            body_digest,
            proof_hash,
            public_key,
        }
    }
    /// A record with only the verified header and body digest that a roster
    /// proposal reads; it carries no key or registration proof.
    #[cfg(test)]
    pub(crate) fn for_roster(header: RegistrationHeader, body_digest: [u8; 64]) -> Self {
        Self {
            header,
            body_digest,
            proof_hash: [0; 64],
            public_key: Vec::new(),
        }
    }
}

pub struct RegistrationVerifier {
    header: RegistrationHeader,
    body: Option<BodyHasher>,
    signature: [u8; 3309],
    key: Vec<u8>,
    proof_prefix: Vec<u8>,
    proof: Option<Verifier>,
    proof_hash: ProtocolHash,
    key_finished: bool,
    failed: bool,
}
impl RegistrationVerifier {
    pub fn new(poll: &VerifiedPoll, header_bytes: &[u8], signature: &[u8]) -> Result<Self, Error> {
        Self::open(poll.identity(), poll.runtime(), header_bytes, signature)
    }
    // A verification against the identity and runtime of the verified poll
    // the registration must name.
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
        let (body, _) = BodyHasher::from_header(header_bytes, poll, runtime)?;
        Ok(Self {
            header,
            body: Some(body),
            signature: signature.try_into().map_err(|_| Error::Shape)?,
            key: Vec::with_capacity(KEY_BYTES),
            proof_prefix: Vec::with_capacity(HEADER_LENGTH),
            proof: None,
            proof_hash: ProtocolHash::new(),
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
            || self.key.len() != KEY_BYTES
            || <[u8; 64]>::from(ProtocolHash::digest(&self.key)) != self.header.recipient_key_hash
        {
            self.failed = true;
            return Err(Error::Shape);
        }
        self.key_finished = true;
        Ok(())
    }
    pub fn push_proof(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Consumed);
        }
        let result = self.push_proof_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn push_proof_inner(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if !self.key_finished || bytes.len() > CHUNK_LIMIT {
            return Err(Error::Shape);
        }
        self.body.as_mut().ok_or(Error::Consumed)?.absorb(bytes)?;
        self.proof_hash.update(bytes);
        if self.proof_prefix.len() < HEADER_LENGTH {
            let count = bytes.len().min(HEADER_LENGTH - self.proof_prefix.len());
            self.proof_prefix.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.proof_prefix.len() == HEADER_LENGTH {
                let common = statement::common_bytes();
                let digest = statement::digest(common, &self.key);
                let role = registration_proof_role(
                    self.header.poll,
                    self.header.runtime,
                    &self.header.signing_public,
                );
                let mut verifier =
                    verifier(&role, digest, &self.proof_prefix).map_err(|_| Error::Crypto)?;
                verifier
                    .push_statement(&statement::header())
                    .map_err(|_| Error::Crypto)?;
                for value in [common, self.key.as_slice()] {
                    for part in value.chunks(CHUNK_LIMIT) {
                        verifier.push_statement(part).map_err(|_| Error::Crypto)?;
                    }
                }
                verifier.finish_statement().map_err(|_| Error::Crypto)?;
                self.proof = Some(verifier);
            }
        }
        if !bytes.is_empty() {
            self.proof
                .as_mut()
                .ok_or(Error::Shape)?
                .push_proof(bytes)
                .map_err(|_| Error::Crypto)?;
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<VerifiedRegistration, Error> {
        if self.failed || !self.key_finished {
            return Err(Error::Consumed);
        }
        let proof = self.proof.take().ok_or(Error::Shape)?;
        if !proof.finish() {
            return Err(Error::Crypto);
        }
        let body = self.body.take().ok_or(Error::Consumed)?.finish()?;
        let body_digest = body.bytes();
        if !verify_registration_signature(body, &self.signature) {
            return Err(Error::Crypto);
        }
        Ok(VerifiedRegistration {
            header: self.header,
            body_digest,
            proof_hash: self.proof_hash.finalize().into(),
            public_key: self.key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Credential,
        foundation::{
            StabilizedDisplayText,
            ceremony::{Manifest, OptionDefinition},
            normalize_username,
        },
        poll::{PollDraft, verify_poll},
        roster::RosterProposal,
    };
    use std::sync::Arc;
    use supported_profile::Profile;

    #[test]
    fn every_supported_roster_size_up_to_the_poll_maximum_can_be_proposed() {
        let text =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        let poll = |maximum: usize| {
            let options = (0..10)
                .map(|index| {
                    OptionDefinition::new(
                        index,
                        format!("option-{index}"),
                        text(&format!("Option {index}")),
                    )
                    .unwrap()
                })
                .collect();
            let draft = PollDraft::new(
                Manifest::new(text("Question"), options).unwrap(),
                1,
                maximum as u16,
            )
            .unwrap();
            let packet = Credential::from_seed([1; 32])
                .create_poll(draft, [4; 64], [5; 32], [6; 32])
                .unwrap();
            verify_poll(packet.identity, [4; 64], &packet.body, &packet.signature).unwrap()
        };
        let organizer = Credential::from_seed([1; 32]);
        let members: Vec<_> = (10..30)
            .map(|seed| Credential::from_seed([seed; 32]))
            .collect();
        let proposal = |poll: &VerifiedPoll, size: usize| {
            let records = std::iter::once(&organizer)
                .chain(&members[..size - 1])
                .map(|credential| {
                    Arc::new(VerifiedRegistration::for_roster(
                        RegistrationHeader {
                            username: normalize_username(b"Participant").unwrap(),
                            poll: poll.identity(),
                            runtime: poll.runtime(),
                            signing_public: *credential.signing_public(),
                            recipient_key_hash: [0; 64],
                            proof_length: 0,
                        },
                        [0; 64],
                    ))
                })
                .collect();
            RosterProposal::new(poll, records)
        };
        let largest = poll(20);
        for size in Profile::participant_range() {
            let profile = proposal(&largest, size).unwrap().profile();
            assert_eq!((profile.participants(), profile.options()), (size, 10));
        }
        for size in [2, 21] {
            assert!(matches!(proposal(&largest, size), Err(Error::Shape)));
        }
        // A roster above the poll's signed maximum is refused.
        for maximum in 3..20 {
            let poll = poll(maximum);
            assert!(proposal(&poll, maximum).is_ok());
            assert!(matches!(proposal(&poll, maximum + 1), Err(Error::Context)));
        }
        assert_eq!(Profile::participant_range(), 3..=20);
    }
}
