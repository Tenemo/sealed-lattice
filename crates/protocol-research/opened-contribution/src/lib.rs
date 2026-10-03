use parallel_work::Ticket;
use registration_credentials::{
    contribution_authentication::{CommitmentInventory, verify_opening},
    contribution_commitment::ContributionCommitmentHasher,
};
use setup_witness::{Profile, contribution::common_records_job};
use std::{collections::VecDeque, sync::Arc};
use word_verifier::{CHUNK_LIMIT, HEADER_LENGTH, Verifier, verifier};

/// The most common polynomials whose records helpers compute ahead of
/// their use; the host holds each one's records until the verifier takes
/// them.
const COMMON_AHEAD: usize = 4;

#[derive(Debug)]
pub enum Refusal {
    Shape,
    Context,
    Statement,
    Commitment,
    Proof,
    Consumed,
}

pub struct VerifiedOpenedContribution {
    inventory: [u8; 64],
    position: usize,
    commitment: [u8; 64],
}
impl VerifiedOpenedContribution {
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn commitment(&self) -> &[u8; 64] {
        &self.commitment
    }
}

/// Consumes the body once. A bounded proof-header lookahead is compared again
/// against the same full proof bytes included in the contribution commitment.
pub struct OpenedContributionVerifier {
    inventory: Arc<CommitmentInventory>,
    profile: Profile,
    position: usize,
    commitment: ContributionCommitmentHasher,
    verifier: Verifier,
    proof_header: Vec<u8>,
    statement_index: usize,
    // The common polynomials the statement supplies, in its order: those
    // whose records are being computed, then those not yet started.
    computing: VecDeque<(usize, Ticket)>,
    common: VecDeque<usize>,
    statement_done: bool,
    failed: bool,
}
impl OpenedContributionVerifier {
    pub fn new(
        inventory: Arc<CommitmentInventory>,
        opening_body: &[u8],
        opening_signature: &[u8],
        body_header: &[u8],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        if proof_header.len() != HEADER_LENGTH {
            return Err(Refusal::Shape);
        }
        let opening = verify_opening(&inventory, opening_body, opening_signature)
            .map_err(|_| Refusal::Context)?;
        let proposal = inventory.proposal().proposal();
        let profile = proposal.profile();
        let role = proposal
            .contribution_role(opening.position())
            .map_err(|_| Refusal::Context)?;
        let commitment = ContributionCommitmentHasher::new(
            proposal,
            opening.position(),
            opening.salt(),
            body_header,
        )
        .map_err(|_| Refusal::Shape)?;
        // This declared value is not trusted: the underlying statement stream
        // recomputes it from fixed predecessors and every supplied polynomial.
        let declared_statement = proof_header[4..68].try_into().map_err(|_| Refusal::Shape)?;
        let mut verifier = verifier(profile, &role, declared_statement, proof_header)
            .map_err(|_| Refusal::Proof)?;
        verifier
            .push_statement(&profile.setup_statement_header())
            .map_err(|_| Refusal::Statement)?;
        // Every polynomial that is neither the body's nor a recipient's
        // registered key is common.
        let body = profile.contribution_body_polynomials();
        let common = (0..profile.setup_polynomials())
            .filter(|index| {
                !body.contains(index)
                    && (0..profile.participants())
                        .all(|recipient| profile.recipient_key_polynomial(recipient) != *index)
            })
            .collect();
        let mut result = Self {
            inventory,
            profile,
            position: opening.position(),
            commitment,
            verifier,
            proof_header: proof_header.to_vec(),
            statement_index: 0,
            computing: VecDeque::new(),
            common,
            statement_done: false,
            failed: false,
        };
        result.compute_common()?;
        result.fixed_inputs()?;
        Ok(result)
    }

    // Starts the records of the next common polynomials, as many as the
    // helpers can compute ahead; without helpers each is computed when it
    // is started.
    fn compute_common(&mut self) -> Result<(), Refusal> {
        while self.computing.len() < parallel_work::window().min(COMMON_AHEAD) {
            let Some(index) = self.common.pop_front() else {
                break;
            };
            let ticket = common_records_job(self.profile, index).map_err(|_| Refusal::Statement)?;
            self.computing.push_back((index, ticket));
        }
        Ok(())
    }

    /// Supplies every statement polynomial before the next one the body
    /// owns: the recipients' registered keys and the public common
    /// polynomials.
    fn fixed_inputs(&mut self) -> Result<(), Refusal> {
        let profile = self.profile;
        let next_owned = self
            .commitment
            .next_polynomial()
            .map_or(profile.setup_polynomials(), |(index, _)| index);
        while self.statement_index < next_owned {
            let index = self.statement_index;
            if let Some(recipient) = (0..profile.participants())
                .find(|recipient| profile.recipient_key_polynomial(*recipient) == index)
            {
                let bytes = self.inventory.proposal().proposal().records()[recipient].public_key();
                for chunk in bytes.chunks(CHUNK_LIMIT) {
                    self.verifier
                        .push_statement(chunk)
                        .map_err(|_| Refusal::Statement)?;
                }
            } else {
                let (expected, ticket) = self.computing.pop_front().ok_or(Refusal::Statement)?;
                if expected != index {
                    return Err(Refusal::Statement);
                }
                for chunk in ticket.wait().chunks(CHUNK_LIMIT) {
                    self.verifier
                        .push_statement(chunk)
                        .map_err(|_| Refusal::Statement)?;
                }
                self.compute_common()?;
            }
            self.statement_index += 1;
        }
        if next_owned == profile.setup_polynomials() {
            self.verifier
                .finish_statement()
                .map_err(|_| Refusal::Statement)?;
            self.statement_done = true;
        }
        Ok(())
    }

    pub fn polynomial(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || self.statement_done {
            return Err(Refusal::Consumed);
        }
        let result = (|| {
            if index != self.statement_index {
                return Err(Refusal::Shape);
            }
            self.commitment
                .push_polynomial(index, offset, bytes)
                .map_err(|_| Refusal::Shape)?;
            self.verifier
                .push_statement(bytes)
                .map_err(|_| Refusal::Statement)?;
            if self
                .commitment
                .next_polynomial()
                .is_none_or(|(next, _)| next != index)
            {
                self.statement_index = index + 1;
                self.fixed_inputs()?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub fn proof(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || !self.statement_done {
            return Err(Refusal::Consumed);
        }
        let result = (|| {
            self.commitment
                .push_proof(offset, bytes)
                .map_err(|_| Refusal::Shape)?;
            let prefix = HEADER_LENGTH.saturating_sub(offset).min(bytes.len());
            if prefix > 0 && bytes[..prefix] != self.proof_header[offset..offset + prefix] {
                return Err(Refusal::Context);
            }
            if prefix < bytes.len() {
                self.verifier
                    .push_proof(&bytes[prefix..])
                    .map_err(|_| Refusal::Proof)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub fn finish(mut self) -> Result<VerifiedOpenedContribution, Refusal> {
        if self.failed || !self.statement_done {
            return Err(Refusal::Consumed);
        }
        let commitment = *self
            .commitment
            .finish()
            .map_err(|_| Refusal::Shape)?
            .digest();
        if self.inventory.confirmations()[self.position].commitment() != Some(&commitment) {
            return Err(Refusal::Commitment);
        }
        if !self.verifier.finish() {
            return Err(Refusal::Proof);
        }
        Ok(VerifiedOpenedContribution {
            inventory: self.inventory.identity(),
            position: self.position,
            commitment,
        })
    }
}
