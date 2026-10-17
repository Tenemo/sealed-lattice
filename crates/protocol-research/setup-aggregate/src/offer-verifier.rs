use encrypted_source_operator::LinkedStatementStream;
use parallel_work::Ticket;
use protocol_foundations::{
    Credential, RETAINED_TAG_BYTES, SIGNATURE_BYTES,
    contribution_body::{ContributionBodyHasher, ContributionBodyHeader, body_length},
    contribution_offer::{
        AuthenticatedContributionOffer, OfferEnvelope, authenticate_offer, offer_envelope_bytes,
    },
    foundation::participant_identity::derive_participant_identity,
    identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN},
    poll::VerifiedPoll,
    roster_authentication::AuthenticatedRosterProposal,
};
use setup_witness::encrypted_source::{SourceCiphertextVerifier, ciphertext_bytes};
use setup_witness::{Profile, contribution::common_records_job};
use statement_stream::committed_polynomial::CommittedPolynomial;
use std::{collections::VecDeque, sync::Arc};
use supported_profile::source_linked::relation as setup_relation;
use word_proof::public_oracle::PublicOracleBuilder;
use word_verifier::{CHUNK_LIMIT, HEADER_LENGTH, engine::Verifier};

#[cfg(test)]
#[path = "published-aggregate-tests.rs"]
mod aggregate_tests;

/// The most common polynomials whose records helpers compute ahead of
/// their use; the host holds each one's records until the verifier takes
/// them.
const COMMON_AHEAD: usize = 4;
pub(crate) const COLLECTION_LABEL: &[u8] = b"sealed-lattice/collected-offers";

pub(crate) fn collected_offer_bytes(profile: Profile) -> usize {
    offer_envelope_bytes()
        + SIGNATURE_BYTES
        + 64
        + 64 * profile.contribution_body_polynomials().len()
}
pub(crate) struct RestoredCollection {
    pub offers: Vec<Arc<VerifiedContributionOffer>>,
    pub sum_digests: Vec<[u8; 64]>,
}

/// Restores this participant's collection only after its credential tag
/// authenticates the complete offer results and aggregate digests together.
pub(crate) fn restore_collection(
    credential: &Credential,
    poll: &VerifiedPoll,
    roster: Arc<AuthenticatedRosterProposal>,
    bytes: &[u8],
) -> Result<RestoredCollection, Refusal> {
    let profile = roster.proposal().profile();
    if bytes.len() < 2 + RETAINED_TAG_BYTES
        || roster.proposal().records()[0].header().poll != poll.identity()
    {
        return Err(Refusal::Context);
    }
    let count = usize::from(u16::from_le_bytes(bytes[..2].try_into().unwrap()));
    let indices = profile.contribution_body_polynomials();
    if count == 0
        || count > profile.setup_contributors()
        || bytes.len()
            != 2 + count * collected_offer_bytes(profile) + 64 * indices.len() + RETAINED_TAG_BYTES
    {
        return Err(Refusal::Shape);
    }
    let end = bytes.len() - RETAINED_TAG_BYTES;
    credential
        .check_retained_tag(COLLECTION_LABEL, poll, &bytes[..end], &bytes[end..])
        .map_err(|_| Refusal::Context)?;
    let mut offset = 2;
    let mut offers = Vec::new();
    for _ in 0..count {
        let envelope = &bytes[offset..offset + offer_envelope_bytes()];
        offset += envelope.len();
        let signature = &bytes[offset..offset + SIGNATURE_BYTES];
        offset += signature.len();
        let offer = Arc::new(
            authenticate_offer(roster.clone(), envelope, signature)
                .map_err(|_| Refusal::Context)?,
        );
        let public_root = bytes[offset..offset + 64].try_into().unwrap();
        offset += 64;
        let polynomials = indices
            .iter()
            .map(|index| {
                let digest = bytes[offset..offset + 64].try_into().unwrap();
                offset += 64;
                OfferPolynomial {
                    index: *index,
                    bytes: profile.setup_polynomial_bytes(*index).unwrap(),
                    digest,
                }
            })
            .collect();
        offers.push(Arc::new(VerifiedContributionOffer {
            offer,
            polynomials,
            public_root,
        }));
    }
    let sums = bytes[offset..end]
        .chunks_exact(64)
        .map(|bytes| bytes.try_into().unwrap())
        .collect();
    Ok(RestoredCollection {
        offers,
        sum_digests: sums,
    })
}

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

#[derive(Clone)]
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
pub struct VerifiedOffer<const EXACT: bool> {
    offer: Arc<AuthenticatedContributionOffer>,
    polynomials: Vec<OfferPolynomial>,
    public_root: [u8; 64],
}
pub type VerifiedContributionOffer = VerifiedOffer<true>;
pub type VerifiedCommittedOffer = VerifiedOffer<false>;
impl<const EXACT: bool> VerifiedOffer<EXACT> {
    pub fn roster(&self) -> &Arc<AuthenticatedRosterProposal> {
        self.offer.roster()
    }
    pub fn envelope(&self) -> &OfferEnvelope {
        self.offer.envelope()
    }
    pub fn polynomials(&self) -> &[OfferPolynomial] {
        &self.polynomials
    }
    pub fn public_root(&self) -> &[u8; 64] {
        &self.public_root
    }
    pub fn authenticated(&self) -> &Arc<AuthenticatedContributionOffer> {
        &self.offer
    }
}
impl VerifiedContributionOffer {
    pub fn committed(&self) -> VerifiedCommittedOffer {
        let streamed = self
            .roster()
            .proposal()
            .profile()
            .streamed_contribution_polynomials();
        VerifiedCommittedOffer {
            offer: self.offer.clone(),
            polynomials: self
                .polynomials
                .iter()
                .filter(|polynomial| streamed.contains(&polynomial.index))
                .cloned()
                .collect(),
            public_root: self.public_root,
        }
    }
}

/// Consumes the body once. A bounded proof-header lookahead is compared again
/// against the same full proof bytes included in the ordinary body identity.
pub struct OfferVerifier<const EXACT: bool> {
    offer: Arc<AuthenticatedContributionOffer>,
    profile: Profile,
    position: usize,
    body: ContributionBodyHasher,
    source: Option<SourceCiphertextVerifier>,
    source_remaining: usize,
    source_records: Vec<Vec<u8>>,
    polynomial_hash: Option<IdentityHasher>,
    polynomials: Vec<OfferPolynomial>,
    verifier: Option<Verifier<LinkedStatementStream>>,
    proof_header: Vec<u8>,
    statement_index: usize,
    // The common polynomials the statement supplies, in its order: those
    // whose records are being computed, then those not yet started.
    computing: VecDeque<(usize, Ticket)>,
    common: VecDeque<usize>,
    statement_done: bool,
    failed: bool,
    public_builder: Option<PublicOracleBuilder>,
    public_polynomial: Option<CommittedPolynomial>,
    public_root: [u8; 64],
    owned: Vec<usize>,
    ordinal: usize,
    polynomial_offset: usize,
}
pub type ContributionOfferVerifier = OfferVerifier<true>;
pub type CommittedOfferVerifier = OfferVerifier<false>;
impl<const EXACT: bool> OfferVerifier<EXACT> {
    pub fn new(
        offer: Arc<AuthenticatedContributionOffer>,
        body_header: &[u8],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        let proposal = offer.roster().proposal();
        let profile = proposal.profile();
        if proof_header.len() != setup_relation(profile).proof_header_bytes() {
            return Err(Refusal::Shape);
        }
        let public_root = proof_header[HEADER_LENGTH..HEADER_LENGTH + 64]
            .try_into()
            .unwrap();
        let decoded =
            ContributionBodyHeader::decode(profile, body_header).map_err(|_| Refusal::Shape)?;
        if body_length(profile, decoded.proof_length).map_err(|_| Refusal::Shape)?
            != offer.envelope().body_length()
        {
            return Err(Refusal::Shape);
        }
        let registration = proposal
            .records()
            .get(offer.envelope().position())
            .ok_or(Refusal::Context)?;
        let owner = derive_participant_identity(&registration.header().signing_public)
            .map_err(|_| Refusal::Context)?;
        let source = SourceCiphertextVerifier::new(
            profile,
            &registration.header().poll,
            owner.as_bytes(),
            *proposal
                .source_binding(offer.envelope().position())
                .map_err(|_| Refusal::Context)?,
        );
        let role = proposal
            .contribution_role(offer.envelope().position())
            .map_err(|_| Refusal::Context)?;
        let body = ContributionBodyHasher::new(profile, body_header).map_err(|_| Refusal::Shape)?;
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
        let result = Self {
            position: offer.envelope().position(),
            offer,
            profile,
            body,
            source: Some(source),
            source_remaining: ciphertext_bytes(),
            source_records: Vec::new(),
            polynomial_hash: None,
            polynomials: Vec::new(),
            verifier: None,
            proof_header: proof_header.to_vec(),
            statement_index: 0,
            computing: VecDeque::new(),
            common,
            statement_done: false,
            failed: false,
            public_builder: if EXACT {
                Some(
                    PublicOracleBuilder::new(&role, profile.committed_columns())
                        .map_err(|_| Refusal::Shape)?,
                )
            } else {
                None
            },
            public_polynomial: None,
            public_root,
            owned: if EXACT {
                profile.contribution_body_polynomials()
            } else {
                profile.streamed_contribution_polynomials()
            },
            ordinal: 0,
            polynomial_offset: 0,
        };
        Ok(result)
    }

    /// Reopens the exact source family authenticated by the registration.
    pub fn source(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Consumed);
        }
        let result = (|| {
            if bytes.len() > self.source_remaining {
                return Err(Refusal::Shape);
            }
            self.source
                .as_mut()
                .ok_or(Refusal::Consumed)?
                .push(bytes)
                .map_err(|_| Refusal::Commitment)?;
            self.source_remaining -= bytes.len();
            if self.source_remaining == 0 {
                let registered = self
                    .source
                    .take()
                    .ok_or(Refusal::Consumed)?
                    .finish()
                    .map_err(|_| Refusal::Commitment)?;
                self.source_records = registered
                    .public()
                    .records()
                    .map_err(|_| Refusal::Statement)?;
                let role = self
                    .offer
                    .roster()
                    .proposal()
                    .contribution_role(self.position)
                    .map_err(|_| Refusal::Context)?;
                let mut verifier = Verifier::open_with_public(
                    setup_relation(self.profile),
                    &role,
                    &self.proof_header,
                    |digest, alpha, queries, root, evaluations| {
                        LinkedStatementStream::committed(
                            self.profile,
                            digest,
                            registered,
                            alpha,
                            queries,
                            root?,
                            evaluations,
                        )
                        .ok()
                    },
                )
                .map_err(|_| Refusal::Proof)?;
                verifier
                    .push_statement(&self.profile.setup_statement_header())
                    .map_err(|_| Refusal::Statement)?;
                self.verifier = Some(verifier);
                self.compute_common()?;
                self.fixed_inputs()?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
            self.verifier = None;
        }
        result
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
            .owned
            .get(self.ordinal)
            .copied()
            .unwrap_or(profile.setup_polynomials());
        while self.statement_index < next_owned {
            let index = self.statement_index;
            if profile.committed_polynomials().contains(&index) {
                self.statement_index += 1;
                continue;
            }
            if let Some(recipient) = (0..profile.participants())
                .find(|recipient| profile.recipient_key_polynomial(*recipient) == index)
            {
                let bytes = self.offer.roster().proposal().records()[recipient].public_key();
                for chunk in bytes.chunks(CHUNK_LIMIT) {
                    self.verifier
                        .as_mut()
                        .ok_or(Refusal::Consumed)?
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
                        .as_mut()
                        .ok_or(Refusal::Consumed)?
                        .push_statement(chunk)
                        .map_err(|_| Refusal::Statement)?;
                }
                self.compute_common()?;
            }
            self.statement_index += 1;
        }
        if next_owned == profile.setup_polynomials() {
            for record in &self.source_records {
                for chunk in record.chunks(CHUNK_LIMIT) {
                    self.verifier
                        .as_mut()
                        .ok_or(Refusal::Consumed)?
                        .push_statement(chunk)
                        .map_err(|_| Refusal::Statement)?;
                }
            }
            self.verifier
                .as_mut()
                .ok_or(Refusal::Consumed)?
                .finish_statement()
                .map_err(|_| Refusal::Statement)?;
            self.statement_done = true;
        }
        Ok(())
    }

    pub fn polynomial(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || self.statement_done || self.verifier.is_none() {
            return Err(Refusal::Consumed);
        }
        let result = (|| {
            if index != self.statement_index
                || self.owned.get(self.ordinal) != Some(&index)
                || offset != self.polynomial_offset
                || bytes.is_empty()
                || bytes.len() > CHUNK_LIMIT
            {
                return Err(Refusal::Shape);
            }
            let polynomial_bytes = self
                .profile
                .setup_polynomial_bytes(index)
                .ok_or(Refusal::Shape)?;
            if bytes.len() > polynomial_bytes.saturating_sub(offset) {
                return Err(Refusal::Shape);
            }
            self.polynomial_offset += bytes.len();
            if !self.profile.committed_polynomials().contains(&index) {
                self.body
                    .push_polynomial(index, offset, bytes)
                    .map_err(|_| Refusal::Shape)?;
            }
            if offset == 0 {
                if self.profile.committed_polynomials().contains(&index) {
                    self.public_polynomial = Some(CommittedPolynomial::new(self.profile));
                }
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
            if let Some(public) = &mut self.public_polynomial {
                public.push(bytes).map_err(|_| Refusal::Statement)?;
            } else {
                self.verifier
                    .as_mut()
                    .ok_or(Refusal::Consumed)?
                    .push_statement(bytes)
                    .map_err(|_| Refusal::Statement)?;
            }
            if self.polynomial_offset == polynomial_bytes {
                if let Some(public) = self.public_polynomial.take() {
                    for column in public.finish().map_err(|_| Refusal::Statement)? {
                        self.public_builder
                            .as_mut()
                            .ok_or(Refusal::Consumed)?
                            .column(&column)
                            .map_err(|_| Refusal::Statement)?;
                    }
                }
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
                self.ordinal += 1;
                self.polynomial_offset = 0;
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
        if self.failed || !self.statement_done || self.source.is_some() {
            return Err(Refusal::Consumed);
        }
        let result = (|| {
            self.body
                .push_proof(offset, bytes)
                .map_err(|_| Refusal::Shape)?;
            let prefix = self
                .proof_header
                .len()
                .saturating_sub(offset)
                .min(bytes.len());
            if prefix > 0 && bytes[..prefix] != self.proof_header[offset..offset + prefix] {
                return Err(Refusal::Context);
            }
            if prefix < bytes.len() {
                self.verifier
                    .as_mut()
                    .ok_or(Refusal::Consumed)?
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

    pub fn finish(mut self) -> Result<VerifiedOffer<EXACT>, Refusal> {
        if self.failed
            || !self.statement_done
            || self.source.is_some()
            || self.polynomial_hash.is_some()
        {
            return Err(Refusal::Consumed);
        }
        if EXACT
            && self
                .public_builder
                .take()
                .ok_or(Refusal::Consumed)?
                .finish()
                .map_err(|_| Refusal::Statement)?
                .root()
                != self.public_root
        {
            return Err(Refusal::Commitment);
        }
        let body = self.body.finish().map_err(|_| Refusal::Shape)?;
        if body.identity() != self.offer.envelope().body_identity()
            || body.length() != self.offer.envelope().body_length()
        {
            return Err(Refusal::Body);
        }
        if !self.verifier.take().ok_or(Refusal::Consumed)?.finish() {
            return Err(Refusal::Proof);
        }
        Ok(VerifiedOffer {
            offer: self.offer,
            polynomials: self.polynomials,
            public_root: self.public_root,
        })
    }
}
