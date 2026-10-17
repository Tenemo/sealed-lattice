use crate::release::{Refusal, ReleaseContext};
use linked_release_proof::{CHUNK_LIMIT, HEADER_LENGTH, Verifier, verifier};
use num_bigint::BigInt;
use protocol_foundations::{
    SIGNATURE_BYTES,
    identity::BodyHasher,
    release_signing::{
        RELEASE_BODY_HEADER_BYTES, RELEASE_ENVELOPE_BYTES, RELEASE_SIGNATURE_CONTEXT,
        ReleaseEnvelope, body_hasher, partial_bytes, proof_length,
    },
};
use std::sync::Arc;

pub struct AuthenticatedReleaseEnvelope {
    envelope: ReleaseEnvelope,
}
impl AuthenticatedReleaseEnvelope {
    pub fn envelope(&self) -> &ReleaseEnvelope {
        &self.envelope
    }
}
impl ReleaseContext {
    pub fn authenticate(&self, packet: &[u8]) -> Result<AuthenticatedReleaseEnvelope, Refusal> {
        if packet.len() != RELEASE_ENVELOPE_BYTES + SIGNATURE_BYTES {
            return Err(Refusal::Encoding);
        }
        let envelope = ReleaseEnvelope::decode(self.profile(), &packet[..RELEASE_ENVELOPE_BYTES])
            .map_err(|_| Refusal::Encoding)?;
        let target = self.certificate().target();
        if envelope.poll() != &target.poll().identity()
            || envelope.setup_identity() != &target.setup().identity()
            || envelope.target() != target.identity()
            || envelope.position() != self.position()
        {
            return Err(Refusal::Context);
        }
        let public = target.setup().roster().proposal().records()[self.position()]
            .header()
            .signing_public;
        let signature: [u8; SIGNATURE_BYTES] = packet[RELEASE_ENVELOPE_BYTES..].try_into().unwrap();
        if !protocol_foundations::verify_purpose_signature(
            &public,
            envelope.bytes(),
            &signature,
            RELEASE_SIGNATURE_CONTEXT,
        ) {
            return Err(Refusal::Signature);
        }
        Ok(AuthenticatedReleaseEnvelope { envelope })
    }
}

pub struct ReleaseBodyVerifier {
    context: Arc<ReleaseContext>,
    hash: BodyHasher,
    length: usize,
    remaining: usize,
    partial_bytes: usize,
    partial: Vec<u8>,
    proof_prefix: Vec<u8>,
    verifier: Option<Verifier>,
    failed: bool,
}
impl ReleaseBodyVerifier {
    pub fn new(context: Arc<ReleaseContext>, header: &[u8]) -> Result<Self, Refusal> {
        let profile = context.profile();
        let proof_bytes = proof_length(profile, header).map_err(|_| Refusal::Encoding)?;
        if header[8..] != *context.header() {
            return Err(Refusal::Context);
        }
        let partial_bytes = partial_bytes(profile);
        let length = RELEASE_BODY_HEADER_BYTES + partial_bytes + proof_bytes;
        let mut hash = body_hasher(profile, length).map_err(|_| Refusal::Encoding)?;
        hash.push(header).map_err(|_| Refusal::Encoding)?;
        Ok(Self {
            context,
            hash,
            length,
            remaining: length - header.len(),
            partial_bytes,
            partial: Vec::with_capacity(partial_bytes),
            proof_prefix: Vec::with_capacity(HEADER_LENGTH),
            verifier: None,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Proof);
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.verifier = None;
        }
        result
    }
    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if bytes.is_empty() || bytes.len() > CHUNK_LIMIT || bytes.len() > self.remaining {
            return Err(Refusal::Encoding);
        }
        self.hash.push(bytes).map_err(|_| Refusal::Encoding)?;
        self.remaining -= bytes.len();
        if self.partial.len() < self.partial_bytes {
            let count = (self.partial_bytes - self.partial.len()).min(bytes.len());
            self.partial.extend(&bytes[..count]);
            bytes = &bytes[count..];
        }
        if self.partial.len() != self.partial_bytes || bytes.is_empty() {
            return Ok(());
        }
        if self.proof_prefix.len() < HEADER_LENGTH {
            let count = (HEADER_LENGTH - self.proof_prefix.len()).min(bytes.len());
            self.proof_prefix.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.proof_prefix.len() == HEADER_LENGTH {
                let statement = self.context.statement(&self.partial)?;
                let mut verifier = verifier(
                    self.context.profile(),
                    &self.context.proof_role()?,
                    &self.proof_prefix,
                )
                .map_err(|_| Refusal::Proof)?;
                for values in std::iter::once(&statement.header).chain(&statement.polynomials) {
                    for chunk in values.chunks(CHUNK_LIMIT) {
                        verifier.push_statement(chunk).map_err(|_| Refusal::Proof)?;
                    }
                }
                verifier.finish_statement().map_err(|_| Refusal::Proof)?;
                self.verifier = Some(verifier);
            }
        }
        if !bytes.is_empty() {
            self.verifier
                .as_mut()
                .ok_or(Refusal::Proof)?
                .push_proof(bytes)
                .map_err(|_| Refusal::Proof)?;
        }
        Ok(())
    }
    pub fn finish(self) -> Result<VerifiedReleaseBody, Refusal> {
        if self.failed || self.remaining != 0 || !self.verifier.ok_or(Refusal::Proof)?.finish() {
            return Err(Refusal::Proof);
        }
        let identity = self.hash.finish().map_err(|_| Refusal::Encoding)?;
        let profile = self.context.profile();
        let partial = super::release::decode_polynomial(
            &self.partial,
            &profile.release_modulus().to_bytes(),
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
    certificate: Arc<crate::certification::VerifiedInventoryCertificate>,
    position: usize,
    identity: [u8; 64],
    length: usize,
    partial: Vec<BigInt>,
}
impl VerifiedReleaseBody {
    pub fn certificate(&self) -> &Arc<crate::certification::VerifiedInventoryCertificate> {
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
        ReleaseEnvelope::new(
            target.setup().profile(),
            target.poll().identity(),
            target.setup().identity(),
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
    ) -> Result<VerifiedReleaseShare, Refusal> {
        if authentication.envelope.bytes() != self.envelope().bytes() {
            return Err(Refusal::Context);
        }
        Ok(VerifiedReleaseShare { body: self })
    }
}
pub struct VerifiedReleaseShare {
    body: VerifiedReleaseBody,
}
impl VerifiedReleaseShare {
    pub fn body(&self) -> &VerifiedReleaseBody {
        &self.body
    }
}
