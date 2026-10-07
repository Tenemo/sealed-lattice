use crate::{CHUNK_BYTES, PolynomialAdder, RetainedSetupInputs};
use opened_contribution::{ContributionOfferVerifier, VerifiedContributionOffer};
use parallel_work::PendingDigest;
use registration_credentials::{
    Credential, RETAINED_TAG_BYTES,
    contribution_offer::AuthenticatedContributionOffer,
    identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN},
    poll::VerifiedPoll,
    roster_authentication::OrganizerSignedRoster,
    setup_selection::{
        AuthenticatedSelectionCertificate, AuthenticatedSelectionProposal, SelectionProposal,
    },
};
use std::{collections::VecDeque, sync::Arc};
use supported_profile::Profile;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregatePolynomial {
    pub(crate) index: usize,
    pub(crate) bytes: usize,
    pub(crate) digest: [u8; 64],
}
impl AggregatePolynomial {
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

pub struct VerifiedSelectionInputs {
    selection: Arc<AuthenticatedSelectionProposal>,
    polynomials: Vec<AggregatePolynomial>,
}
pub struct VerifiedSetupAggregate {
    inputs: Arc<VerifiedSelectionInputs>,
}
impl VerifiedSetupAggregate {
    pub fn identity(&self) -> [u8; 64] {
        self.inputs.identity()
    }
    pub fn roster(&self) -> &Arc<OrganizerSignedRoster> {
        self.inputs.roster()
    }
    pub fn profile(&self) -> Profile {
        self.inputs.profile()
    }
    pub fn polynomials(&self) -> &[AggregatePolynomial] {
        &self.inputs.polynomials
    }
    pub fn read_polynomial(
        &self,
        index: usize,
    ) -> Result<crate::AggregatePolynomialReader, Refusal> {
        let polynomial = self
            .inputs
            .polynomials
            .iter()
            .find(|polynomial| polynomial.index == index)
            .ok_or(Refusal::Order)?;
        crate::AggregatePolynomialReader::new(self.profile(), self.identity(), polynomial.clone())
    }
}

fn check_poll(roster: &OrganizerSignedRoster, poll: &VerifiedPoll) -> Result<(), Refusal> {
    if roster.proposal().records()[0].header().poll != poll.identity()
        || roster.proposal().records()[0].header().runtime != poll.runtime()
    {
        return Err(Refusal::Context);
    }
    Ok(())
}

impl VerifiedSelectionInputs {
    pub fn identity(&self) -> [u8; 64] {
        self.selection.selection().identity()
    }
    pub fn roster(&self) -> &Arc<OrganizerSignedRoster> {
        self.selection.roster()
    }
    pub fn profile(&self) -> Profile {
        self.roster().proposal().profile()
    }
    pub fn selection(&self) -> &AuthenticatedSelectionProposal {
        &self.selection
    }
    pub fn polynomials(&self) -> &[AggregatePolynomial] {
        &self.polynomials
    }
    pub fn certify(
        self: &Arc<Self>,
        certificate: &AuthenticatedSelectionCertificate,
    ) -> Result<VerifiedSetupAggregate, Refusal> {
        if certificate.proposal().roster().proposal().identity()
            != self.roster().proposal().identity()
            || certificate.proposal().selection().body() != self.selection.selection().body()
        {
            return Err(Refusal::Context);
        }
        Ok(VerifiedSetupAggregate {
            inputs: self.clone(),
        })
    }
    pub fn retain(&self, credential: &Credential, poll: &VerifiedPoll) -> Result<Vec<u8>, Refusal> {
        check_poll(self.roster(), poll)?;
        let mut reference = crate::retained::encode_reference(
            b"SPI1",
            self.profile(),
            self.identity(),
            &self.polynomials,
        )?;
        let tag = credential.retained_selection_inputs_tag(poll, &reference);
        reference.extend(tag);
        Ok(reference)
    }
    pub fn restore(
        credential: &Credential,
        poll: &VerifiedPoll,
        selection: Arc<AuthenticatedSelectionProposal>,
        retained: &[u8],
    ) -> Result<Self, Refusal> {
        check_poll(selection.roster(), poll)?;
        let split = retained
            .len()
            .checked_sub(RETAINED_TAG_BYTES)
            .ok_or(Refusal::Context)?;
        let (reference, tag) = retained.split_at(split);
        credential
            .check_retained_selection_inputs_tag(poll, reference, tag)
            .map_err(|_| Refusal::Context)?;
        let profile = selection.roster().proposal().profile();
        let inputs = RetainedSetupInputs::parse_with_magic(
            b"SPI1",
            profile,
            reference,
            selection.selection().identity(),
        )?;
        Ok(Self {
            selection,
            polynomials: inputs.into_polynomials(),
        })
    }
}

impl VerifiedSetupAggregate {
    pub fn restore(
        credential: &Credential,
        poll: &VerifiedPoll,
        certificate: &AuthenticatedSelectionCertificate,
        retained: &[u8],
    ) -> Result<Self, Refusal> {
        let selection = Arc::new(certificate.proposal().clone());
        check_poll(selection.roster(), poll)?;
        let split = retained
            .len()
            .checked_sub(RETAINED_TAG_BYTES)
            .ok_or(Refusal::Context)?;
        let (reference, tag) = retained.split_at(split);
        credential
            .check_retained_setup_tag(poll, reference, tag)
            .map_err(|_| Refusal::Context)?;
        let profile = selection.roster().proposal().profile();
        let inputs = RetainedSetupInputs::parse(profile, reference, certificate.identity())?;
        Ok(Self {
            inputs: Arc::new(VerifiedSelectionInputs {
                selection,
                polynomials: inputs.into_polynomials(),
            }),
        })
    }
}

/// The organizer can propose only a complete set of this verifier's offers.
pub fn build_selection(
    roster: &Arc<OrganizerSignedRoster>,
    offers: &[Arc<VerifiedContributionOffer>],
) -> Result<SelectionProposal, Refusal> {
    if offers
        .iter()
        .any(|offer| offer.roster().proposal().identity() != roster.proposal().identity())
    {
        return Err(Refusal::Context);
    }
    let selected: Vec<_> = offers
        .iter()
        .map(|offer| {
            (
                offer.envelope().position(),
                *offer.envelope().body_identity(),
            )
        })
        .collect();
    SelectionProposal::new(roster.proposal(), &selected).map_err(|_| Refusal::Context)
}

#[derive(Debug)]
pub enum Refusal {
    Context,
    Order,
    Body,
    PreviousAggregate,
    Incomplete,
}

struct Pending {
    incoming: IncomingOffer,
    incoming_hash: Option<IdentityHasher>,
    ordinal: usize,
    offset: usize,
    // The identities of the polynomial in progress: the previous aggregate
    // read back from the host, and the new aggregate.
    previous_hash: Option<IdentityHasher>,
    output_hash: Option<IdentityHasher>,
    // The completed polynomials whose identities helpers may still be
    // finishing, oldest first.
    finishing: VecDeque<FinishingPolynomial>,
    outputs: Vec<AggregatePolynomial>,
}

enum IncomingOffer {
    Verified(Arc<VerifiedContributionOffer>),
    Verifying(Box<ContributionOfferVerifier>),
}

struct FinishingPolynomial {
    index: usize,
    bytes: usize,
    // The previous aggregate's identity and the digest it must equal.
    previous: Option<(PendingDigest, [u8; 64])>,
    output: PendingDigest,
}

// Checks the oldest completed polynomials' identities and adds each one's
// output until at most the kept number remain unchecked.
fn settle(
    finishing: &mut VecDeque<FinishingPolynomial>,
    kept: usize,
    outputs: &mut Vec<AggregatePolynomial>,
) -> Result<(), Refusal> {
    while finishing.len() > kept {
        let polynomial = finishing.pop_front().unwrap();
        if let Some((identity, expected)) = polynomial.previous
            && identity.wait() != expected
        {
            return Err(Refusal::PreviousAggregate);
        }
        outputs.push(AggregatePolynomial {
            index: polynomial.index,
            bytes: polynomial.bytes,
            digest: polynomial.output.wait(),
        });
    }
    Ok(())
}

/// Only complete bytes matching a positively verified offer advance the prefix.
/// Output chunks are provisional until `finish_contribution` succeeds. A
/// polynomial's identities are checked while later polynomials stream, and
/// `finish_contribution` checks the last ones.
pub struct SetupAggregator {
    selection: Arc<AuthenticatedSelectionProposal>,
    offers: Vec<Arc<VerifiedContributionOffer>>,
    profile: Profile,
    accepted: usize,
    indices: Vec<usize>,
    previous: Vec<AggregatePolynomial>,
    pending: Option<Pending>,
    failed: bool,
}
impl SetupAggregator {
    pub fn new(
        selection: Arc<AuthenticatedSelectionProposal>,
        offers: Vec<Arc<VerifiedContributionOffer>>,
    ) -> Result<Self, Refusal> {
        let profile = selection.roster().proposal().profile();
        for (index, offer) in offers.iter().enumerate() {
            if offer.roster().proposal().identity() != selection.roster().proposal().identity()
                || !selection.selection().selected().contains(&(
                    offer.envelope().position(),
                    *offer.envelope().body_identity(),
                ))
                || offers[..index]
                    .iter()
                    .any(|previous| previous.envelope().position() == offer.envelope().position())
            {
                return Err(Refusal::Context);
            }
        }
        Ok(Self {
            selection,
            offers,
            profile,
            accepted: 0,
            indices: profile.contribution_body_polynomials(),
            previous: Vec::new(),
            pending: None,
            failed: false,
        })
    }
    pub fn accepted(&self) -> usize {
        self.accepted
    }
    /// Drops only disposable public aggregation progress. The caller clears
    /// its mixed cache and replays from the first selected offer; positive
    /// offer holders and the authenticated selection remain unchanged.
    pub fn discard_progress(&mut self) {
        self.pending = None;
        self.previous.clear();
        self.accepted = 0;
        self.failed = false;
    }
    /// Every selected contribution is aggregated and none is pending.
    pub fn complete(&self) -> bool {
        !self.failed && self.pending.is_none() && self.accepted == self.profile.setup_contributors()
    }
    pub fn polynomials(&self) -> &[AggregatePolynomial] {
        &self.previous
    }
    pub fn begin(&mut self, position: usize) -> Result<(), Refusal> {
        let expected = self.next_offer()?;
        if expected.0 != position {
            return Err(Refusal::Context);
        }
        let offer = self
            .offers
            .iter()
            .find(|offer| {
                offer.envelope().position() == expected.0
                    && offer.envelope().body_identity() == &expected.1
            })
            .ok_or(Refusal::Order)?
            .clone();
        self.begin_incoming(IncomingOffer::Verified(offer));
        Ok(())
    }
    fn next_offer(&self) -> Result<(usize, [u8; 64]), Refusal> {
        if self.failed || self.pending.is_some() {
            return Err(Refusal::Order);
        }
        self.selection
            .selection()
            .selected()
            .get(self.accepted)
            .copied()
            .ok_or(Refusal::Order)
    }
    /// The offer's original context and exact selected identity are checked
    /// before starting the body verifier or emitting any provisional sum.
    pub fn begin_verification(
        &mut self,
        offer: Arc<AuthenticatedContributionOffer>,
        body_header: &[u8],
        proof_header: &[u8],
    ) -> Result<(), Refusal> {
        let expected = self.next_offer()?;
        if offer.roster().proposal().identity() != self.selection.roster().proposal().identity()
            || offer.envelope().position() != expected.0
            || offer.envelope().body_identity() != &expected.1
        {
            return Err(Refusal::Context);
        }
        let verifier = ContributionOfferVerifier::new(offer, body_header, proof_header)
            .map_err(|_| Refusal::Body)?;
        self.begin_incoming(IncomingOffer::Verifying(Box::new(verifier)));
        Ok(())
    }
    fn begin_incoming(&mut self, incoming: IncomingOffer) {
        self.pending = Some(Pending {
            incoming,
            incoming_hash: None,
            ordinal: 0,
            offset: 0,
            previous_hash: None,
            output_hash: None,
            finishing: VecDeque::new(),
            outputs: Vec::new(),
        });
    }
    pub fn polynomial(
        &mut self,
        index: usize,
        offset: usize,
        incoming: &[u8],
        previous_and_output: &mut [u8],
    ) -> Result<(), Refusal> {
        let pending = self.pending.as_mut().ok_or(Refusal::Order)?;
        if self.failed {
            return Err(Refusal::Order);
        }
        let result = (|| {
            if incoming.is_empty()
                || incoming.len() > CHUNK_BYTES
                || incoming.len() != previous_and_output.len()
            {
                return Err(Refusal::Body);
            }
            if self.indices.get(pending.ordinal) != Some(&index) || pending.offset != offset {
                return Err(Refusal::Order);
            }
            let family = self.profile.setup_family(index).ok_or(Refusal::Order)?;
            let bytes = self
                .profile
                .setup_polynomial_bytes(index)
                .ok_or(Refusal::Order)?;
            if incoming.len() > bytes.saturating_sub(offset) {
                return Err(Refusal::Order);
            }
            if let IncomingOffer::Verifying(verifier) = &mut pending.incoming {
                verifier
                    .polynomial(index, offset, incoming)
                    .map_err(|_| Refusal::Body)?;
            }
            let identity = || {
                IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], bytes).map_err(|_| Refusal::Body)
            };
            if offset == 0 {
                pending.incoming_hash = match pending.incoming {
                    IncomingOffer::Verified(_) => Some(identity()?),
                    IncomingOffer::Verifying(_) => None,
                };
                pending.previous_hash = (self.accepted > 0).then(identity).transpose()?;
                pending.output_hash = Some(identity()?);
            }
            if let Some(hash) = pending.incoming_hash.as_mut() {
                hash.absorb(incoming).map_err(|_| Refusal::Body)?;
            }
            match pending.previous_hash.as_mut() {
                None => previous_and_output.fill(0),
                Some(hash) => hash
                    .absorb(previous_and_output)
                    .map_err(|_| Refusal::PreviousAggregate)?,
            }
            PolynomialAdder::new(self.profile, family)
                .add_into(incoming, previous_and_output)
                .map_err(|_| Refusal::Body)?;
            pending
                .output_hash
                .as_mut()
                .ok_or(Refusal::Order)?
                .absorb(previous_and_output)
                .map_err(|_| Refusal::Body)?;
            pending.offset += incoming.len();
            if pending.offset == bytes {
                if let IncomingOffer::Verified(offer) = &pending.incoming {
                    let original = offer
                        .polynomials()
                        .get(pending.ordinal)
                        .ok_or(Refusal::Body)?;
                    let digest = pending
                        .incoming_hash
                        .take()
                        .ok_or(Refusal::Order)?
                        .finish()
                        .map_err(|_| Refusal::Body)?;
                    if original.index() != index
                        || original.bytes() != bytes
                        || original.digest() != &digest
                    {
                        return Err(Refusal::Body);
                    }
                }
                let previous = match pending.previous_hash.take() {
                    None => None,
                    Some(hash) => {
                        let expected = &self.previous[pending.ordinal];
                        if expected.index != index || expected.bytes != bytes {
                            return Err(Refusal::PreviousAggregate);
                        }
                        let identity = hash
                            .finish_later()
                            .map_err(|_| Refusal::PreviousAggregate)?;
                        Some((identity, expected.digest))
                    }
                };
                let output = pending
                    .output_hash
                    .take()
                    .ok_or(Refusal::Order)?
                    .finish_later()
                    .map_err(|_| Refusal::Body)?;
                pending.finishing.push_back(FinishingPolynomial {
                    index,
                    bytes,
                    previous,
                    output,
                });
                pending.ordinal += 1;
                pending.offset = 0;
                // The next polynomials stream while helpers finish these
                // identities, as many as the jobs kept ahead.
                settle(
                    &mut pending.finishing,
                    parallel_work::window(),
                    &mut pending.outputs,
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn proof(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Order);
        }
        let pending = self.pending.as_mut().ok_or(Refusal::Order)?;
        let result = match &mut pending.incoming {
            IncomingOffer::Verifying(verifier)
                if pending.ordinal == self.indices.len() && pending.offset == 0 =>
            {
                verifier.proof(offset, bytes).map_err(|_| Refusal::Body)
            }
            _ => Err(Refusal::Order),
        };
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish_contribution(&mut self) -> Result<Arc<VerifiedContributionOffer>, Refusal> {
        if self.failed {
            return Err(Refusal::Incomplete);
        }
        let result = (|| {
            let mut pending = self.pending.take().ok_or(Refusal::Order)?;
            if pending.ordinal != self.indices.len() || pending.offset != 0 {
                return Err(Refusal::Incomplete);
            }
            settle(&mut pending.finishing, 0, &mut pending.outputs)?;
            let offer = match pending.incoming {
                IncomingOffer::Verified(offer) => offer,
                IncomingOffer::Verifying(verifier) => {
                    Arc::new(verifier.finish().map_err(|_| Refusal::Body)?)
                }
            };
            self.previous = pending.outputs;
            self.accepted += 1;
            if !self.offers.iter().any(|held| {
                held.envelope().position() == offer.envelope().position()
                    && held.envelope().body_identity() == offer.envelope().body_identity()
            }) {
                self.offers.push(offer.clone());
            }
            Ok(offer)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish(self) -> Result<VerifiedSelectionInputs, Refusal> {
        if !self.complete() {
            return Err(Refusal::Incomplete);
        }
        Ok(VerifiedSelectionInputs {
            selection: self.selection,
            polynomials: self.previous,
        })
    }
}

#[cfg(test)]
#[path = "verified-finishing-tests.rs"]
mod finishing_tests;
#[cfg(test)]
#[path = "verified-retained-tests.rs"]
mod retained_tests;
