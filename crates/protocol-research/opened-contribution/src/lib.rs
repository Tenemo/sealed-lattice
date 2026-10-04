use parallel_work::Ticket;
use registration_credentials::{
    contribution_body::{ContributionBodyHasher, ContributionBodyHeader, body_length},
    contribution_offer::{AuthenticatedContributionOffer, OfferEnvelope},
    identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN},
    roster_authentication::OrganizerSignedRoster,
    source_binding::FheKeyCommitmentHasher,
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
    Body,
    Proof,
    Consumed,
}

pub struct OfferPolynomial {
    index: usize,
    bytes: usize,
    digest: [u8; 64],
}
impl OfferPolynomial {
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
}

/// Complete authenticated body bytes whose original source and contribution
/// relation this verifier accepted. It supplies no selected-set authority.
pub struct VerifiedContributionOffer {
    offer: Arc<AuthenticatedContributionOffer>,
    polynomials: Vec<OfferPolynomial>,
}
impl VerifiedContributionOffer {
    pub fn roster(&self) -> &Arc<OrganizerSignedRoster> {
        self.offer.roster()
    }
    pub fn envelope(&self) -> &OfferEnvelope {
        self.offer.envelope()
    }
    pub fn polynomials(&self) -> &[OfferPolynomial] {
        &self.polynomials
    }
}

/// Consumes the body once. A bounded proof-header lookahead is compared again
/// against the same full proof bytes included in the ordinary body identity.
pub struct ContributionOfferVerifier {
    offer: Arc<AuthenticatedContributionOffer>,
    profile: Profile,
    position: usize,
    body: ContributionBodyHasher,
    source_binding: Option<FheKeyCommitmentHasher>,
    polynomial_hash: Option<IdentityHasher>,
    polynomials: Vec<OfferPolynomial>,
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
impl ContributionOfferVerifier {
    pub fn new(
        offer: Arc<AuthenticatedContributionOffer>,
        body_header: &[u8],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        if proof_header.len() != HEADER_LENGTH {
            return Err(Refusal::Shape);
        }
        let proposal = offer.roster().proposal();
        let profile = proposal.profile();
        let decoded =
            ContributionBodyHeader::decode(profile, body_header).map_err(|_| Refusal::Shape)?;
        if body_length(profile, decoded.proof_length).map_err(|_| Refusal::Shape)?
            != offer.envelope().body_length()
        {
            return Err(Refusal::Shape);
        }
        let source_binding = FheKeyCommitmentHasher::for_contribution(
            proposal,
            offer.envelope().position(),
            &decoded.source_salt,
        )
        .map_err(|_| Refusal::Context)?;
        let role = proposal
            .contribution_role(offer.envelope().position())
            .map_err(|_| Refusal::Context)?;
        let body = ContributionBodyHasher::new(profile, body_header).map_err(|_| Refusal::Shape)?;
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
        let body_polynomials = profile.contribution_body_polynomials();
        let common = (0..profile.setup_polynomials())
            .filter(|index| {
                !body_polynomials.contains(index)
                    && (0..profile.participants())
                        .all(|recipient| profile.recipient_key_polynomial(recipient) != *index)
            })
            .collect();
        let mut result = Self {
            position: offer.envelope().position(),
            offer,
            profile,
            body,
            source_binding: Some(source_binding),
            polynomial_hash: None,
            polynomials: Vec::new(),
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
            .body
            .next_polynomial()
            .map_or(profile.setup_polynomials(), |(index, _)| index);
        while self.statement_index < next_owned {
            let index = self.statement_index;
            if let Some(recipient) = (0..profile.participants())
                .find(|recipient| profile.recipient_key_polynomial(*recipient) == index)
            {
                let bytes = self.offer.roster().proposal().records()[recipient].public_key();
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
            self.body
                .push_polynomial(index, offset, bytes)
                .map_err(|_| Refusal::Shape)?;
            let polynomial_bytes = self
                .profile
                .setup_polynomial_bytes(index)
                .ok_or(Refusal::Shape)?;
            if offset == 0 {
                self.polynomial_hash = Some(
                    IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], polynomial_bytes)
                        .map_err(|_| Refusal::Shape)?,
                );
            }
            self.polynomial_hash
                .as_mut()
                .ok_or(Refusal::Consumed)?
                .absorb(bytes)
                .map_err(|_| Refusal::Shape)?;
            if index == self.profile.fhe_polynomial(0, 1) {
                self.source_binding
                    .as_mut()
                    .ok_or(Refusal::Consumed)?
                    .push(offset, bytes)
                    .map_err(|_| Refusal::Statement)?;
                if self
                    .body
                    .next_polynomial()
                    .is_none_or(|(next, _)| next != index)
                {
                    let digest = self
                        .source_binding
                        .take()
                        .ok_or(Refusal::Consumed)?
                        .finish()
                        .map_err(|_| Refusal::Statement)?;
                    let expected = self
                        .offer
                        .roster()
                        .proposal()
                        .fhe_key_commitment(self.position)
                        .map_err(|_| Refusal::Context)?;
                    if &digest != expected {
                        return Err(Refusal::Commitment);
                    }
                }
            }
            self.verifier
                .push_statement(bytes)
                .map_err(|_| Refusal::Statement)?;
            if self
                .body
                .next_polynomial()
                .is_none_or(|(next, _)| next != index)
            {
                self.polynomials.push(OfferPolynomial {
                    index,
                    bytes: polynomial_bytes,
                    digest: self
                        .polynomial_hash
                        .take()
                        .ok_or(Refusal::Consumed)?
                        .finish()
                        .map_err(|_| Refusal::Shape)?,
                });
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
        if self.failed || !self.statement_done || self.source_binding.is_some() {
            return Err(Refusal::Consumed);
        }
        let result = (|| {
            self.body
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

    pub fn finish(self) -> Result<VerifiedContributionOffer, Refusal> {
        if self.failed
            || !self.statement_done
            || self.source_binding.is_some()
            || self.polynomial_hash.is_some()
        {
            return Err(Refusal::Consumed);
        }
        let body = self.body.finish().map_err(|_| Refusal::Shape)?;
        if body.identity() != self.offer.envelope().body_identity()
            || body.length() != self.offer.envelope().body_length()
        {
            return Err(Refusal::Body);
        }
        if !self.verifier.finish() {
            return Err(Refusal::Proof);
        }
        Ok(VerifiedContributionOffer {
            offer: self.offer,
            polynomials: self.polynomials,
        })
    }
}
