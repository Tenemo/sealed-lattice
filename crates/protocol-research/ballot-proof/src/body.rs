use crate::{
    CHUNK_LIMIT, HEADER_LENGTH,
    admission::{BallotRelationVerifier, VerifiedBallotRelation},
    statement::encode_polynomial,
};
use registration_credentials::{
    ballot_body::{self, BallotBodyHasher},
    poll::VerifiedPoll,
};
use setup_aggregate::{AggregatePolynomialReader, verified::VerifiedSetupAggregate};
use sha3::{Digest, Sha3_512};
use std::sync::Arc;

#[derive(Debug)]
pub enum Error {
    Shape,
    Stage,
    Context,
    Proof,
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

struct BallotBodyRelationVerifier {
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    position: usize,
    context: Vec<u8>,
    ciphertexts: Vec<Vec<u8>>,
    ordinal: usize,
    proof_prefix: Vec<u8>,
    proof_length: usize,
    proof_bytes: usize,
    verifier: Option<BallotRelationVerifier>,
    keys: Vec<Vec<u8>>,
    key_reader: Option<AggregatePolynomialReader>,
    key_offset: usize,
    failed: bool,
}
impl BallotBodyRelationVerifier {
    pub fn new(
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
        position: usize,
        header: &[u8],
    ) -> Result<Self, Error> {
        let proof_length = ballot_body::proof_length(header).map_err(|_| Error::Shape)?;
        if position >= setup.inventory().confirmations().len() {
            return Err(Error::Context);
        }
        let context = &header[12..];
        if context[4..68] != poll.identity()
            || context[68..132] != setup.inventory().identity()
            || u16::from_le_bytes(context[132..134].try_into().unwrap()) as usize != position
            || context[134] as usize != poll.manifest().option_count()
            || u16::from(context[135]) != poll.top_count()
            || setup.inventory().proposal().proposal().records()[0]
                .header()
                .poll
                != poll.identity()
        {
            return Err(Error::Context);
        }
        Ok(Self {
            poll,
            setup,
            position,
            context: context.to_vec(),
            ciphertexts: (0..4).map(|_| Vec::new()).collect(),
            ordinal: 0,
            proof_prefix: Vec::new(),
            proof_length,
            proof_bytes: 0,
            verifier: None,
            keys: Vec::new(),
            key_reader: None,
            key_offset: 0,
            failed: false,
        })
    }
    pub fn begin_key(&mut self, index: usize) -> Result<(), Error> {
        if self.failed
            || self.key_reader.is_some()
            || self.keys.len() >= 2
            || index != [1, 74][self.keys.len()]
        {
            self.failed = true;
            return Err(Error::Stage);
        }
        self.key_reader = Some(
            self.setup
                .read_polynomial(index)
                .map_err(|_| Error::Context)?,
        );
        self.keys.push(Vec::new());
        self.key_offset = 0;
        Ok(())
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Stage);
        }
        let result = (|| {
            self.key_reader
                .as_mut()
                .ok_or(Error::Stage)?
                .push(self.key_offset, bytes)
                .map_err(|_| Error::Context)?;
            self.keys.last_mut().ok_or(Error::Stage)?.extend(bytes);
            self.key_offset += bytes.len();
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish_key(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Stage);
        }
        let result = self
            .key_reader
            .take()
            .ok_or(Error::Stage)
            .and_then(|reader| reader.finish().map(|_| ()).map_err(|_| Error::Context));
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Stage);
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.verifier = None;
        }
        result
    }
    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if self.keys.len() != 2
            || self.key_reader.is_some()
            || bytes.is_empty()
            || bytes.len() > CHUNK_LIMIT
        {
            return Err(Error::Stage);
        }
        while !bytes.is_empty() && self.ordinal < 4 {
            let (_, length) = ballot_body::polynomial(self.ordinal).ok_or(Error::Shape)?;
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
            return Err(Error::Shape);
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
                .ok_or(Error::Stage)?
                .push_proof(bytes)
                .map_err(|_| Error::Proof)?;
        }
        Ok(())
    }
    fn initialize_proof(&mut self) -> Result<(), Error> {
        let mut polynomials = Vec::with_capacity(8);
        for (family, index) in [0, 73].into_iter().enumerate() {
            let common = setup_witness::contribution::common_polynomial(index)
                .map_err(|_| Error::Context)?;
            polynomials.push(
                encode_polynomial(&common, if family == 0 { 109 } else { 6 })
                    .map_err(|_| Error::Shape)?,
            );
            polynomials.push(std::mem::take(&mut self.keys[family]));
            polynomials.push(std::mem::take(&mut self.ciphertexts[2 * family]));
            polynomials.push(std::mem::take(&mut self.ciphertexts[2 * family + 1]));
        }
        let mut hash = Sha3_512::new();
        hash.update(&self.context);
        for polynomial in &polynomials {
            hash.update(polynomial);
        }
        let mut verifier = BallotRelationVerifier::new(
            &self.poll,
            &self.setup,
            self.position,
            hash.finalize().into(),
            &self.proof_prefix,
        )
        .map_err(|_| Error::Context)?;
        verifier
            .push_statement(&self.context)
            .map_err(|_| Error::Context)?;
        for polynomial in polynomials {
            for chunk in polynomial.chunks(CHUNK_LIMIT) {
                verifier.push_statement(chunk).map_err(|_| Error::Context)?;
            }
        }
        verifier.finish_statement().map_err(|_| Error::Proof)?;
        self.verifier = Some(verifier);
        Ok(())
    }
    fn inputs_ready(&self) -> bool {
        !self.failed && self.keys.len() == 2 && self.key_reader.is_none()
    }
    pub fn finish(mut self) -> Result<VerifiedBallotRelation, Error> {
        if self.failed || self.proof_bytes != self.proof_length {
            return Err(Error::Stage);
        }
        self.verifier
            .take()
            .ok_or(Error::Stage)?
            .finish()
            .map_err(|_| Error::Proof)
    }
}

pub struct BallotBodyVerifier {
    relation: BallotBodyRelationVerifier,
    hash: BallotBodyHasher,
    length: usize,
}
impl BallotBodyVerifier {
    pub fn new(
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
        position: usize,
        header: &[u8],
    ) -> Result<Self, Error> {
        let relation = BallotBodyRelationVerifier::new(poll, setup, position, header)?;
        let length =
            ballot_body::HEADER_BYTES + ballot_body::CIPHERTEXT_BYTES + relation.proof_length;
        let hash = BallotBodyHasher::new(header).map_err(|_| Error::Shape)?;
        Ok(Self {
            relation,
            hash,
            length,
        })
    }
    pub fn begin_key(&mut self, index: usize) -> Result<(), Error> {
        self.relation.begin_key(index)
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.relation.push_key(bytes)
    }
    pub fn finish_key(&mut self) -> Result<(), Error> {
        self.relation.finish_key()
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.hash.push(bytes).map_err(|_| Error::Shape)?;
        self.relation.push(bytes)
    }
    pub fn finish(self) -> Result<VerifiedBallotBody, Error> {
        let relation = self.relation.finish()?;
        let identity = self.hash.finish().map_err(|_| Error::Shape)?;
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
    pub fn envelope(&self) -> &registration_credentials::ballot_authentication::BallotEnvelope {
        self.authentication.envelope()
    }
}
pub enum BallotBodyClassification {
    Valid(Box<crate::submission::VerifiedBallotSubmission>),
    Invalid(Box<InvalidBallotBody>),
}

/// Classifies only bytes matching an already authenticated envelope.
/// Corrupt key/cache inputs and wrong-hash delivery never yield `Invalid`.
pub struct SignedBallotVerifier {
    authentication: crate::submission::AuthenticatedBallotEnvelope,
    setup: Arc<VerifiedSetupAggregate>,
    relation: Option<BallotBodyRelationVerifier>,
    hash: BallotBodyHasher,
    failed: bool,
}
impl SignedBallotVerifier {
    pub fn new(
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
        authentication: crate::submission::AuthenticatedBallotEnvelope,
        header: &[u8],
    ) -> Result<Self, Error> {
        let envelope = authentication.envelope();
        if header.len() != ballot_body::HEADER_BYTES
            || envelope.poll() != &poll.identity()
            || envelope.inventory() != &setup.inventory().identity()
        {
            return Err(Error::Context);
        }
        let mut hash =
            BallotBodyHasher::for_body_length(envelope.body_length()).map_err(|_| Error::Shape)?;
        hash.push(header).map_err(|_| Error::Shape)?;
        let relation =
            BallotBodyRelationVerifier::new(poll, setup.clone(), envelope.position(), header).ok();
        Ok(Self {
            authentication,
            setup,
            relation,
            hash,
            failed: false,
        })
    }
    pub fn requires_keys(&self) -> bool {
        self.relation
            .as_ref()
            .is_some_and(|value| !value.inputs_ready())
    }
    fn key_operation(
        &mut self,
        operation: impl FnOnce(&mut BallotBodyRelationVerifier) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Stage);
        }
        let result = self
            .relation
            .as_mut()
            .ok_or(Error::Stage)
            .and_then(operation);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn begin_key(&mut self, index: usize) -> Result<(), Error> {
        self.key_operation(|value| value.begin_key(index))
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.key_operation(|value| value.push_key(bytes))
    }
    pub fn finish_key(&mut self) -> Result<(), Error> {
        self.key_operation(BallotBodyRelationVerifier::finish_key)
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed
            || self
                .relation
                .as_ref()
                .is_some_and(|value| !value.inputs_ready())
        {
            self.failed = true;
            return Err(Error::Stage);
        }
        if self.hash.push(bytes).is_err() {
            self.failed = true;
            return Err(Error::Shape);
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
    pub fn finish(self) -> Result<BallotBodyClassification, Error> {
        if self.failed {
            return Err(Error::Stage);
        }
        let identity = self.hash.finish().map_err(|_| Error::Shape)?;
        if &identity != self.authentication.envelope().body_identity() {
            return Err(Error::Context);
        }
        if let Some(relation) = self.relation.and_then(|value| value.finish().ok()) {
            let body = VerifiedBallotBody {
                identity,
                length: self.authentication.envelope().body_length(),
                relation,
            };
            let submission =
                crate::submission::verify_submission(body, &self.setup, self.authentication)
                    .map_err(|_| Error::Context)?;
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
