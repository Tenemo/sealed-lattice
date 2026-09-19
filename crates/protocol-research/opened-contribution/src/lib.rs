use num_bigint::Sign;
use registration_credentials::{
    contribution_authentication::{CommitmentInventory, verify_opening},
    contribution_commitment::ContributionCommitmentHasher,
};
use setup_witness::contribution::{common_polynomial, statement_header};
use std::sync::Arc;
use word_verifier::{CHUNK_LIMIT, HEADER_LENGTH, Verifier};

#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
mod browser;

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
    position: usize,
    commitment: ContributionCommitmentHasher,
    verifier: Verifier,
    proof_header: Vec<u8>,
    statement_index: usize,
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
        let mut verifier =
            Verifier::new(&role, declared_statement, proof_header).map_err(|_| Refusal::Proof)?;
        verifier
            .push_statement(&statement_header())
            .map_err(|_| Refusal::Statement)?;
        let mut result = Self {
            inventory,
            position: opening.position(),
            commitment,
            verifier,
            proof_header: proof_header.to_vec(),
            statement_index: 0,
            statement_done: false,
            failed: false,
        };
        result.fixed_inputs()?;
        Ok(result)
    }

    fn fixed_inputs(&mut self) -> Result<(), Refusal> {
        let next_owned = self
            .commitment
            .next_polynomial()
            .map_or(75, |(index, _)| index);
        while self.statement_index < next_owned {
            let index = self.statement_index;
            if (43..=70).contains(&index) && (index - 43).is_multiple_of(3) {
                let recipient = (index - 43) / 3;
                let bytes = self.inventory.proposal().proposal().records()[recipient].public_key();
                for chunk in bytes.chunks(CHUNK_LIMIT) {
                    self.verifier
                        .push_statement(chunk)
                        .map_err(|_| Refusal::Statement)?;
                }
            } else {
                let values = common_polynomial(index).map_err(|_| Refusal::Statement)?;
                let width = if index < 42 {
                    108
                } else if index == 42 {
                    20
                } else if index == 73 {
                    5
                } else {
                    return Err(Refusal::Statement);
                };
                let mut buffer = Vec::with_capacity(CHUNK_LIMIT);
                for value in values {
                    let (sign, magnitude) = value.to_bytes_le();
                    if magnitude.len() > width {
                        return Err(Refusal::Statement);
                    }
                    let mut encoded = [0u8; 109];
                    encoded[0] = u8::from(sign == Sign::Minus);
                    encoded[1..1 + magnitude.len()].copy_from_slice(&magnitude);
                    for byte in &encoded[..width + 1] {
                        buffer.push(*byte);
                        if buffer.len() == CHUNK_LIMIT {
                            self.verifier
                                .push_statement(&buffer)
                                .map_err(|_| Refusal::Statement)?;
                            buffer.clear();
                        }
                    }
                }
                if !buffer.is_empty() {
                    self.verifier
                        .push_statement(&buffer)
                        .map_err(|_| Refusal::Statement)?;
                }
            }
            self.statement_index += 1;
        }
        if next_owned == 75 {
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
        if &commitment != self.inventory.confirmations()[self.position].commitment() {
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
