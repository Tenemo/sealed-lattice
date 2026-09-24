use crate::{
    CHUNK_LIMIT, Refusal, Verifier,
    parameters::BALLOT_HEADER_BYTES,
    statement::{self, coefficient_bytes, encode_polynomial, polynomial_bytes, setup_inputs},
};
use registration_credentials::poll::VerifiedPoll;
use setup_aggregate::verified::VerifiedSetupAggregate;
use sha2::{Digest, Sha512};
use supported_profile::Profile;

/// Proof-valid linked ciphertexts under this verifier's own setup.
/// Envelope authentication and authoritative publication are separate gates.
pub struct VerifiedBallotRelation {
    statement: [u8; 64],
    poll: [u8; 64],
    inventory: [u8; 64],
    position: usize,
}
impl VerifiedBallotRelation {
    pub fn statement(&self) -> &[u8; 64] {
        &self.statement
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn position(&self) -> usize {
        self.position
    }
}
pub struct BallotRelationVerifier {
    profile: Profile,
    verifier: Option<Verifier>,
    expected_header: Vec<u8>,
    expected_inputs: [[u8; 64]; 4],
    header_offset: usize,
    polynomial: usize,
    polynomial_bytes: usize,
    hash: Sha512,
    statement_done: bool,
    statement: [u8; 64],
}
impl BallotRelationVerifier {
    pub fn new(
        poll: &VerifiedPoll,
        setup: &VerifiedSetupAggregate,
        position: usize,
        statement: [u8; 64],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        let inventory = setup.inventory();
        let profile = setup.profile();
        let role =
            crate::context::proof_role(poll, setup, position).map_err(|_| Refusal::Context)?;
        if position >= profile.participants()
            || profile.options() != poll.manifest().option_count()
            || inventory.proposal().proposal().records()[0].header().poll != poll.identity()
        {
            return Err(Refusal::Context);
        }
        let expected_header = statement::header(
            &poll.identity(),
            &inventory.identity(),
            position,
            profile.options(),
            usize::from(poll.top_count()),
        )
        .map_err(|_| Refusal::Context)?;
        let mut expected_inputs = [[0; 64]; 4];
        for (slot, (family, common, key)) in setup_inputs(profile).into_iter().enumerate() {
            let common = setup_witness::contribution::common_polynomial(profile, common)
                .map_err(|_| Refusal::Context)?;
            let bytes = encode_polynomial(&common, coefficient_bytes(profile, family))
                .map_err(|_| Refusal::Context)?;
            expected_inputs[2 * slot] = Sha512::digest(bytes).into();
            let key = setup
                .polynomials()
                .iter()
                .find(|polynomial| polynomial.index() == key)
                .ok_or(Refusal::Context)?;
            expected_inputs[2 * slot + 1] = *key.digest();
        }
        Ok(Self {
            profile,
            verifier: Some(Verifier::new(profile, &role, statement, proof_header)?),
            expected_header,
            expected_inputs,
            header_offset: 0,
            polynomial: 0,
            polynomial_bytes: 0,
            hash: Sha512::new(),
            statement_done: false,
            statement,
        })
    }
    pub fn push_statement(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let result = self.push_statement_inner(bytes);
        if result.is_err() {
            self.verifier = None;
        }
        result
    }
    fn push_statement_inner(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if self.statement_done || bytes.len() > CHUNK_LIMIT {
            return Err(Refusal::Stage);
        }
        self.verifier
            .as_mut()
            .ok_or(Refusal::Stage)?
            .push_statement(bytes)?;
        if self.header_offset < BALLOT_HEADER_BYTES {
            let count = bytes.len().min(BALLOT_HEADER_BYTES - self.header_offset);
            if bytes[..count]
                != self.expected_header[self.header_offset..self.header_offset + count]
            {
                return Err(Refusal::Context);
            }
            bytes = &bytes[count..];
            self.header_offset += count;
        }
        while !bytes.is_empty() {
            if self.polynomial >= 8 {
                return Err(Refusal::Length);
            }
            let length = polynomial_bytes(self.profile, self.polynomial);
            let count = bytes.len().min(length - self.polynomial_bytes);
            if self.polynomial % 4 < 2 {
                self.hash.update(&bytes[..count]);
            }
            bytes = &bytes[count..];
            self.polynomial_bytes += count;
            if self.polynomial_bytes == length {
                if self.polynomial % 4 < 2 {
                    let expected =
                        self.expected_inputs[self.polynomial / 4 * 2 + self.polynomial % 4];
                    if <[u8; 64]>::from(std::mem::take(&mut self.hash).finalize()) != expected {
                        return Err(Refusal::Context);
                    }
                }
                self.polynomial += 1;
                self.polynomial_bytes = 0;
            }
        }
        Ok(())
    }
    pub fn finish_statement(&mut self) -> Result<(), Refusal> {
        let result = (|| {
            if self.statement_done || self.polynomial != 8 || self.polynomial_bytes != 0 {
                return Err(Refusal::Stage);
            }
            self.verifier
                .as_mut()
                .ok_or(Refusal::Stage)?
                .finish_statement()?;
            self.statement_done = true;
            Ok(())
        })();
        if result.is_err() {
            self.verifier = None;
        }
        result
    }
    pub fn push_proof(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let result = self
            .verifier
            .as_mut()
            .ok_or(Refusal::Stage)
            .and_then(|verifier| verifier.push_proof(bytes));
        if result.is_err() {
            self.verifier = None;
        }
        result
    }
    pub fn finish(self) -> Result<VerifiedBallotRelation, Refusal> {
        if !self.statement_done || !self.verifier.is_some_and(Verifier::finish) {
            return Err(Refusal::Relation);
        }
        Ok(VerifiedBallotRelation {
            statement: self.statement,
            poll: self.expected_header[4..68].try_into().unwrap(),
            inventory: self.expected_header[68..132].try_into().unwrap(),
            position: u16::from_le_bytes(self.expected_header[132..134].try_into().unwrap())
                as usize,
        })
    }
}
