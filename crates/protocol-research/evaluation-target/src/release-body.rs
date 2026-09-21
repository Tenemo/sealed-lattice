use crate::release::{Error, ReleaseContext};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier as SignatureVerifier},
};
use linked_release_proof::{CHUNK_LIMIT, HEADER_LENGTH, Verifier};
use num_bigint::BigInt;
use registration_credentials::release_signing::{
    PARTIAL_BYTES, RELEASE_BODY_HEADER_BYTES, RELEASE_ENVELOPE_BYTES, RELEASE_SIGNATURE_CONTEXT,
    ReleaseBodyHasher, ReleaseEnvelope, proof_length,
};
use std::sync::Arc;

pub struct AuthenticatedReleaseEnvelope {
    envelope: ReleaseEnvelope,
    signature: [u8; 3309],
}
impl AuthenticatedReleaseEnvelope {
    pub fn envelope(&self) -> &ReleaseEnvelope {
        &self.envelope
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}
impl ReleaseContext {
    pub fn authenticate(&self, packet: &[u8]) -> Result<AuthenticatedReleaseEnvelope, Error> {
        if packet.len() != RELEASE_ENVELOPE_BYTES + 3309 {
            return Err(Error::Encoding);
        }
        let envelope = ReleaseEnvelope::decode(&packet[..RELEASE_ENVELOPE_BYTES])
            .map_err(|_| Error::Encoding)?;
        let target = self.certificate().target();
        let inventory = target.inventory();
        if envelope.poll() != &inventory.poll().identity()
            || envelope.inventory() != &inventory.setup().inventory().identity()
            || envelope.target() != target.identity()
            || envelope.position() != self.position()
        {
            return Err(Error::Context);
        }
        let public = inventory
            .setup()
            .inventory()
            .proposal()
            .proposal()
            .records()[self.position()]
        .header()
        .signing_public;
        let key = ml_dsa_65::PublicKey::try_from_bytes(public).map_err(|_| Error::Context)?;
        let signature = packet[RELEASE_ENVELOPE_BYTES..].try_into().unwrap();
        if !key.verify(envelope.bytes(), &signature, RELEASE_SIGNATURE_CONTEXT) {
            return Err(Error::Signature);
        }
        Ok(AuthenticatedReleaseEnvelope {
            envelope,
            signature,
        })
    }
}

pub struct ReleaseBodyVerifier {
    context: Arc<ReleaseContext>,
    hash: ReleaseBodyHasher,
    length: usize,
    remaining: usize,
    partial: Vec<u8>,
    proof_prefix: Vec<u8>,
    verifier: Option<Verifier>,
    failed: bool,
}
impl ReleaseBodyVerifier {
    pub fn new(context: Arc<ReleaseContext>, header: &[u8]) -> Result<Self, Error> {
        let proof_bytes = proof_length(header).map_err(|_| Error::Encoding)?;
        if header[12..] != *context.header() {
            return Err(Error::Context);
        }
        let length = RELEASE_BODY_HEADER_BYTES + PARTIAL_BYTES + proof_bytes;
        let mut hash = ReleaseBodyHasher::new(length).map_err(|_| Error::Encoding)?;
        hash.push(header).map_err(|_| Error::Encoding)?;
        Ok(Self {
            context,
            hash,
            length,
            remaining: length - header.len(),
            partial: Vec::with_capacity(PARTIAL_BYTES),
            proof_prefix: Vec::with_capacity(HEADER_LENGTH),
            verifier: None,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Proof);
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.verifier = None;
        }
        result
    }
    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > CHUNK_LIMIT || bytes.len() > self.remaining {
            return Err(Error::Encoding);
        }
        self.hash.push(bytes).map_err(|_| Error::Encoding)?;
        self.remaining -= bytes.len();
        if self.partial.len() < PARTIAL_BYTES {
            let count = (PARTIAL_BYTES - self.partial.len()).min(bytes.len());
            self.partial.extend(&bytes[..count]);
            bytes = &bytes[count..];
        }
        if self.partial.len() != PARTIAL_BYTES || bytes.is_empty() {
            return Ok(());
        }
        if self.proof_prefix.len() < HEADER_LENGTH {
            let count = (HEADER_LENGTH - self.proof_prefix.len()).min(bytes.len());
            self.proof_prefix.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.proof_prefix.len() == HEADER_LENGTH {
                let statement = self.context.statement(&self.partial)?;
                let mut verifier = Verifier::new(
                    &self.context.proof_role()?,
                    statement.digest(),
                    &self.proof_prefix,
                )
                .map_err(|_| Error::Proof)?;
                for values in std::iter::once(&statement.header).chain(&statement.polynomials) {
                    for chunk in values.chunks(CHUNK_LIMIT) {
                        verifier.push_statement(chunk).map_err(|_| Error::Proof)?;
                    }
                }
                verifier.finish_statement().map_err(|_| Error::Proof)?;
                self.verifier = Some(verifier);
            }
        }
        if !bytes.is_empty() {
            self.verifier
                .as_mut()
                .ok_or(Error::Proof)?
                .push_proof(bytes)
                .map_err(|_| Error::Proof)?;
        }
        Ok(())
    }
    pub fn finish(self) -> Result<VerifiedReleaseBody, Error> {
        if self.failed || self.remaining != 0 || !self.verifier.ok_or(Error::Proof)?.finish() {
            return Err(Error::Proof);
        }
        let identity = self.hash.finish().map_err(|_| Error::Encoding)?;
        let partial = super::release::decode_polynomial(
            &self.partial,
            25,
            &linked_release_proof::statement::release_modulus(),
        )?;
        Ok(VerifiedReleaseBody {
            certificate: self.context.certificate().clone(),
            position: self.context.position(),
            identity,
            length: self.length,
            partial,
        })
    }
}
pub struct VerifiedReleaseBody {
    certificate: Arc<crate::certification::VerifiedTargetCertificate>,
    position: usize,
    identity: [u8; 64],
    length: usize,
    partial: Vec<BigInt>,
}
impl VerifiedReleaseBody {
    pub fn certificate(&self) -> &Arc<crate::certification::VerifiedTargetCertificate> {
        &self.certificate
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn length(&self) -> usize {
        self.length
    }
    pub fn partial(&self) -> &[BigInt] {
        &self.partial
    }
    pub fn envelope(&self) -> ReleaseEnvelope {
        let target = self.certificate.target();
        let inventory = target.inventory();
        ReleaseEnvelope::new(
            inventory.poll().identity(),
            inventory.setup().inventory().identity(),
            *target.identity(),
            self.position,
            self.length,
            self.identity,
        )
        .expect("Verified release body has bounded canonical context")
    }
    pub fn authenticate(
        self,
        authentication: AuthenticatedReleaseEnvelope,
    ) -> Result<VerifiedReleaseShare, Error> {
        if authentication.envelope.bytes() != self.envelope().bytes() {
            return Err(Error::Context);
        }
        Ok(VerifiedReleaseShare {
            body: self,
            authentication,
        })
    }
}
pub struct VerifiedReleaseShare {
    body: VerifiedReleaseBody,
    authentication: AuthenticatedReleaseEnvelope,
}
impl VerifiedReleaseShare {
    pub fn body(&self) -> &VerifiedReleaseBody {
        &self.body
    }
    pub fn authentication(&self) -> &AuthenticatedReleaseEnvelope {
        &self.authentication
    }
}
