use crate::{
    BodyHasher, Error, foundation::RegistrationHeader, poll::VerifiedPoll, registration_proof_role,
    verify_registration_signature,
};
use registration_proof::statement;
use registration_verifier::{CHUNK_LIMIT, HEADER_LENGTH, Verifier};
use sha3::{Digest, Sha3_512};

const KEY_BYTES: usize = 65536 * 21;
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
}

pub struct RegistrationVerifier {
    header: RegistrationHeader,
    body: Option<BodyHasher>,
    signature: [u8; 3309],
    key: Vec<u8>,
    proof_prefix: Vec<u8>,
    proof: Option<Verifier>,
    proof_hash: Sha3_512,
    key_finished: bool,
    failed: bool,
}
impl RegistrationVerifier {
    pub fn new(poll: &VerifiedPoll, header_bytes: &[u8], signature: &[u8]) -> Result<Self, Error> {
        let (header, consumed) = RegistrationHeader::decode_prefix(header_bytes)?;
        if consumed != header_bytes.len() {
            return Err(Error::Shape);
        }
        let (body, _) = BodyHasher::from_header(header_bytes, poll.identity(), poll.runtime())?;
        Ok(Self {
            header,
            body: Some(body),
            signature: signature.try_into().map_err(|_| Error::Shape)?,
            key: Vec::with_capacity(KEY_BYTES),
            proof_prefix: Vec::with_capacity(HEADER_LENGTH),
            proof: None,
            proof_hash: Sha3_512::new(),
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
            || <[u8; 64]>::from(Sha3_512::digest(&self.key)) != self.header.recipient_key_hash
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
                let digest = statement::digest(&common, &self.key);
                let role = registration_proof_role(
                    self.header.poll,
                    self.header.runtime,
                    &self.header.signing_public,
                );
                let mut verifier =
                    Verifier::new(&role, digest, &self.proof_prefix).map_err(|_| Error::Crypto)?;
                verifier
                    .push_statement(&statement::header())
                    .map_err(|_| Error::Crypto)?;
                for value in [&common, &self.key] {
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
