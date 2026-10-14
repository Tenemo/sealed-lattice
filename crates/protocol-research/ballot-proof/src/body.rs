use crate::{
    CHUNK_LIMIT, HEADER_LENGTH, Verifier, context,
    statement::{self, setup_input},
    verifier,
};
use protocol_foundations::{ballot_body, identity::BodyHasher, poll::VerifiedPoll};
use setup_aggregate::{AggregatePolynomialReader, verified::VerifiedSetupAggregate};
use setup_witness::contribution::common_records;

use std::sync::Arc;
use supported_profile::Profile;

#[derive(Debug)]
pub enum Refusal {
    Shape,
    Phase,
    Context,
    Proof,
}

/// Proof-valid linked ciphertexts under this verifier's own setup.
/// Envelope authentication and authoritative publication are separate gates.
pub struct VerifiedBallotRelation {
    poll: [u8; 64],
    setup_identity: [u8; 64],
    position: usize,
}
impl VerifiedBallotRelation {
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn setup_identity(&self) -> &[u8; 64] {
        &self.setup_identity
    }
    pub fn position(&self) -> usize {
        self.position
    }
}

/// Exact body bytes and their linked relation, checked by one stream.
/// This still needs the original participant's signature and publication evidence.
pub struct VerifiedBallotBody {
    identity: [u8; 64],
    length: usize,
    relation: VerifiedBallotRelation,
}
impl VerifiedBallotBody {
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn relation(&self) -> &VerifiedBallotRelation {
        &self.relation
    }
    pub fn length(&self) -> usize {
        self.length
    }
}

/// The statement polynomials that every ballot under one verified setup
/// shares: the common polynomials' canonical records and the encryption keys,
/// in statement order. Only the relation verifier builds them, once the
/// setup's key has matched its certified identity, so every statement takes
/// them as they are.
pub struct BallotInputs {
    setup: Arc<VerifiedSetupAggregate>,
    commons: [Vec<u8>; 2],
    keys: [Vec<u8>; 2],
}
impl BallotInputs {
    /// Whether these are the inputs of this verified setup.
    pub fn serves(&self, setup: &Arc<VerifiedSetupAggregate>) -> bool {
        Arc::ptr_eq(&self.setup, setup)
    }
}

/// Verifies a ballot body's proof over the statement the body implies: the
/// statement header this poll, setup and position expect, the setup's
/// inputs and the body's ciphertexts.
struct BallotBodyRelationVerifier {
    profile: Profile,
    setup: Arc<VerifiedSetupAggregate>,
    role: Vec<u8>,
    // The statement header, which the body header carries after its prefix.
    statement_header: Vec<u8>,
    relation: VerifiedBallotRelation,
    ciphertexts: Vec<Vec<u8>>,
    ordinal: usize,
    proof_prefix: Vec<u8>,
    proof_length: usize,
    proof_bytes: usize,
    verifier: Option<Verifier>,
    // The complete shared inputs, or the FHE aggregate key being read.
    inputs: Option<Arc<BallotInputs>>,
    key: Option<Vec<u8>>,
    key_reader: Option<AggregatePolynomialReader>,
    key_offset: usize,
    failed: bool,
}
impl BallotBodyRelationVerifier {
    /// Inputs of another setup are not used, and the keys are read again.
    pub fn new(
        poll: &VerifiedPoll,
        setup: Arc<VerifiedSetupAggregate>,
        position: usize,
        header: &[u8],
        inputs: Option<Arc<BallotInputs>>,
    ) -> Result<Self, Refusal> {
        let profile = setup.profile();
        let proof_length =
            ballot_body::proof_length(profile, header).map_err(|_| Refusal::Shape)?;
        // The role names a position of the setup's roster for this poll.
        let role = context::proof_role(poll, &setup, position).map_err(|_| Refusal::Context)?;
        let relation = VerifiedBallotRelation {
            poll: poll.identity(),
            setup_identity: setup.identity(),
            position,
        };
        let statement_header = statement::header(
            &relation.poll,
            &relation.setup_identity,
            position,
            profile.options(),
            usize::from(poll.top_count()),
        )
        .map_err(|_| Refusal::Context)?;
        if header[12..] != statement_header {
            return Err(Refusal::Context);
        }
        let inputs = inputs.filter(|value| value.serves(&setup));
        Ok(Self {
            profile,
            setup,
            role,
            statement_header,
            relation,
            ciphertexts: (0..4).map(|_| Vec::new()).collect(),
            ordinal: 0,
            proof_prefix: Vec::new(),
            proof_length,
            proof_bytes: 0,
            verifier: None,
            inputs,
            key: None,
            key_reader: None,
            key_offset: 0,
            failed: false,
        })
    }
    pub fn begin_key(&mut self, index: usize) -> Result<(), Refusal> {
        if self.failed
            || self.inputs.is_some()
            || self.key_reader.is_some()
            || self.key.is_some()
            || index != setup_input(self.profile).2
        {
            self.failed = true;
            return Err(Refusal::Phase);
        }
        self.key_reader = Some(
            self.setup
                .read_polynomial(index)
                .map_err(|_| Refusal::Context)?,
        );
        self.key = Some(Vec::new());
        self.key_offset = 0;
        Ok(())
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Phase);
        }
        let result = (|| {
            self.key_reader
                .as_mut()
                .ok_or(Refusal::Phase)?
                .push(self.key_offset, bytes)
                .map_err(|_| Refusal::Context)?;
            self.key.as_mut().ok_or(Refusal::Phase)?.extend(bytes);
            self.key_offset += bytes.len();
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish_key(&mut self) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Phase);
        }
        let result = self
            .key_reader
            .take()
            .ok_or(Refusal::Phase)
            .and_then(|reader| reader.finish().map(|_| ()).map_err(|_| Refusal::Context))
            .and_then(|()| {
                let commons = [
                    common_records(self.profile, setup_input(self.profile).1)
                        .map_err(|_| Refusal::Context)?,
                    setup_witness::fixed_auxiliary::common_records(),
                ];
                self.inputs = Some(Arc::new(BallotInputs {
                    setup: self.setup.clone(),
                    commons,
                    keys: [
                        self.key.take().ok_or(Refusal::Phase)?,
                        setup_witness::fixed_auxiliary::public_key_records(),
                    ],
                }));
                Ok(())
            });
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Phase);
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.verifier = None;
        }
        result
    }
    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if self.inputs.is_none()
            || self.key_reader.is_some()
            || bytes.is_empty()
            || bytes.len() > CHUNK_LIMIT
        {
            return Err(Refusal::Phase);
        }
        while !bytes.is_empty() && self.ordinal < 4 {
            let (_, length) =
                ballot_body::polynomial(self.profile, self.ordinal).ok_or(Refusal::Shape)?;
            let count = bytes
                .len()
                .min(length - self.ciphertexts[self.ordinal].len());
            self.ciphertexts[self.ordinal].extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.ciphertexts[self.ordinal].len() == length {
                self.ordinal += 1;
            }
        }
        if bytes.is_empty() {
            return Ok(());
        }
        self.proof_bytes += bytes.len();
        if self.proof_bytes > self.proof_length {
            return Err(Refusal::Shape);
        }
        if self.proof_prefix.len() < HEADER_LENGTH {
            let count = bytes.len().min(HEADER_LENGTH - self.proof_prefix.len());
            self.proof_prefix.extend(&bytes[..count]);
            bytes = &bytes[count..];
            if self.proof_prefix.len() == HEADER_LENGTH {
                self.initialize_proof()?;
            }
        }
        if !bytes.is_empty() {
            self.verifier
                .as_mut()
                .ok_or(Refusal::Phase)?
                .push_proof(bytes)
                .map_err(|_| Refusal::Proof)?;
        }
        Ok(())
    }
    fn initialize_proof(&mut self) -> Result<(), Refusal> {
        let inputs = self.inputs.clone().ok_or(Refusal::Phase)?;
        let ciphertexts = std::mem::take(&mut self.ciphertexts);
        // The statement stream recomputes the statement digest the proof
        // declares from the statement below and refuses a mismatch.
        let mut verifier =
            verifier(self.profile, &self.role, &self.proof_prefix).map_err(|_| Refusal::Context)?;
        verifier
            .push_statement(&self.statement_header)
            .map_err(|_| Refusal::Context)?;
        for slot in 0..2 {
            for polynomial in [
                &inputs.commons[slot],
                &inputs.keys[slot],
                &ciphertexts[2 * slot],
                &ciphertexts[2 * slot + 1],
            ] {
                for chunk in polynomial.chunks(CHUNK_LIMIT) {
                    verifier
                        .push_statement(chunk)
                        .map_err(|_| Refusal::Context)?;
                }
            }
        }
        verifier.finish_statement().map_err(|_| Refusal::Proof)?;
        self.verifier = Some(verifier);
        Ok(())
    }
    fn inputs_ready(&self) -> bool {
        !self.failed && self.inputs.is_some() && self.key_reader.is_none()
    }
    pub fn finish(self) -> Result<VerifiedBallotRelation, Refusal> {
        if self.failed || self.proof_bytes != self.proof_length {
            return Err(Refusal::Phase);
        }
        if !self.verifier.ok_or(Refusal::Phase)?.finish() {
            return Err(Refusal::Proof);
        }
        Ok(self.relation)
    }
}

pub struct BallotBodyVerifier {
    relation: BallotBodyRelationVerifier,
    hash: BodyHasher,
    length: usize,
}
impl BallotBodyVerifier {
    pub fn new(
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
        position: usize,
        header: &[u8],
    ) -> Result<Self, Refusal> {
        let profile = setup.profile();
        let relation = BallotBodyRelationVerifier::new(&poll, setup, position, header, None)?;
        let length = ballot_body::HEADER_BYTES
            + ballot_body::ciphertext_bytes(profile)
            + relation.proof_length;
        let hash = ballot_body::header_body_hasher(profile, header).map_err(|_| Refusal::Shape)?;
        Ok(Self {
            relation,
            hash,
            length,
        })
    }
    pub fn begin_key(&mut self, index: usize) -> Result<(), Refusal> {
        self.relation.begin_key(index)
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.relation.push_key(bytes)
    }
    pub fn finish_key(&mut self) -> Result<(), Refusal> {
        self.relation.finish_key()
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.hash.push(bytes).map_err(|_| Refusal::Shape)?;
        self.relation.push(bytes)
    }
    pub fn finish(self) -> Result<VerifiedBallotBody, Refusal> {
        let relation = self.relation.finish()?;
        let identity = self.hash.finish().map_err(|_| Refusal::Shape)?;
        Ok(VerifiedBallotBody {
            identity,
            length: self.length,
            relation,
        })
    }
}

pub struct InvalidBallotBody {
    authentication: crate::submission::AuthenticatedBallotEnvelope,
}
impl InvalidBallotBody {
    pub fn envelope(&self) -> &protocol_foundations::ballot_authentication::BallotEnvelope {
        self.authentication.envelope()
    }
}
pub enum BallotBodyClassification {
    Valid(Box<crate::submission::VerifiedBallotSubmission>),
    Invalid(Box<InvalidBallotBody>),
}

/// Classifies only bytes matching an already authenticated envelope.
/// Corrupt key/cache inputs and wrong-hash delivery never yield `Invalid`.
pub struct BallotBodyClassifier {
    authentication: crate::submission::AuthenticatedBallotEnvelope,
    setup: Arc<VerifiedSetupAggregate>,
    relation: Option<BallotBodyRelationVerifier>,
    hash: BodyHasher,
    failed: bool,
}
impl BallotBodyClassifier {
    /// Inputs kept from an earlier ballot of the same setup spare this one
    /// reading the keys again.
    pub fn new(
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
        authentication: crate::submission::AuthenticatedBallotEnvelope,
        header: &[u8],
        inputs: Option<Arc<BallotInputs>>,
    ) -> Result<Self, Refusal> {
        let envelope = authentication.envelope();
        if header.len() != ballot_body::HEADER_BYTES
            || envelope.poll() != &poll.identity()
            || envelope.setup_identity() != &setup.identity()
        {
            return Err(Refusal::Context);
        }
        let mut hash = ballot_body::body_hasher(setup.profile(), envelope.body_length())
            .map_err(|_| Refusal::Shape)?;
        hash.push(header).map_err(|_| Refusal::Shape)?;
        let relation = BallotBodyRelationVerifier::new(
            &poll,
            setup.clone(),
            envelope.position(),
            header,
            inputs,
        )
        .ok();
        Ok(Self {
            authentication,
            setup,
            relation,
            hash,
            failed: false,
        })
    }
    pub fn requires_key(&self) -> bool {
        self.relation
            .as_ref()
            .is_some_and(|value| !value.inputs_ready())
    }
    /// The shared inputs once this ballot has them, for later ballots of
    /// the same setup.
    pub fn inputs(&self) -> Option<Arc<BallotInputs>> {
        self.relation
            .as_ref()
            .and_then(|value| value.inputs.clone())
    }
    fn key_operation(
        &mut self,
        operation: impl FnOnce(&mut BallotBodyRelationVerifier) -> Result<(), Refusal>,
    ) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Phase);
        }
        let result = self
            .relation
            .as_mut()
            .ok_or(Refusal::Phase)
            .and_then(operation);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn begin_key(&mut self, index: usize) -> Result<(), Refusal> {
        self.key_operation(|value| value.begin_key(index))
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.key_operation(|value| value.push_key(bytes))
    }
    pub fn finish_key(&mut self) -> Result<(), Refusal> {
        self.key_operation(BallotBodyRelationVerifier::finish_key)
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed
            || self
                .relation
                .as_ref()
                .is_some_and(|value| !value.inputs_ready())
        {
            self.failed = true;
            return Err(Refusal::Phase);
        }
        if self.hash.push(bytes).is_err() {
            self.failed = true;
            return Err(Refusal::Shape);
        }
        if self
            .relation
            .as_mut()
            .is_some_and(|value| value.push(bytes).is_err())
        {
            self.relation = None;
        }
        Ok(())
    }
    pub fn finish(self) -> Result<BallotBodyClassification, Refusal> {
        if self.failed {
            return Err(Refusal::Phase);
        }
        let identity = self.hash.finish().map_err(|_| Refusal::Shape)?;
        if &identity != self.authentication.envelope().body_identity() {
            return Err(Refusal::Context);
        }
        if let Some(relation) = self.relation.and_then(|value| value.finish().ok()) {
            let body = VerifiedBallotBody {
                identity,
                length: self.authentication.envelope().body_length(),
                relation,
            };
            let submission =
                crate::submission::verify_submission(body, &self.setup, self.authentication)
                    .map_err(|_| Refusal::Context)?;
            Ok(BallotBodyClassification::Valid(Box::new(submission)))
        } else {
            Ok(BallotBodyClassification::Invalid(Box::new(
                InvalidBallotBody {
                    authentication: self.authentication,
                },
            )))
        }
    }
}
