//! The public setup verification: the roster, the contribution offers, the
//! selection and its aggregate, and the certificate that verifies the setup.
use crate::offer_verifier::{
    ContributionOfferVerifier, VerifiedCommittedOffer, VerifiedContributionOffer, VerifiedOffer,
};
use crate::{
    CHUNK_BYTES,
    verified::{
        StreamedOfferAggregator, VerifiedSelectionInputs, VerifiedSetupAggregate, build_selection,
    },
};
use protocol_foundations::{
    Credential,
    contribution_body::BODY_HEADER_BYTES,
    contribution_offer::{AuthenticatedContributionOffer, MAXIMUM_OFFER_BYTES, authenticate_offer},
    poll::VerifiedPoll,
    roster::MAXIMUM_PROPOSAL_BYTES,
    roster_authentication::{AuthenticatedRosterProposal, authenticate_roster_proposal},
    roster_input::{RecordStep, RosterInputVerifier},
    setup_selection::{
        AuthenticatedSelectionCertificate, AuthenticatedSelectionEndorsement,
        AuthenticatedSelectionProposal, MAXIMUM_SELECTION_BYTES, SelectionProposal,
        authenticate_certificate, authenticate_endorsement, authenticate_selection,
        encode_certificate,
    },
    signed_packet,
};
use std::sync::Arc;
use supported_profile::relation::setup_relation;
#[path = "public-work.rs"]
mod public_work;
pub use public_work::PublicOperation;
use public_work::PublicWork;

pub const SETUP_INPUT_BYTES: usize = 1_572_864;
/// The refusal of a setup verification step.
#[derive(Debug)]
pub struct Refusal;
fn refused(failed: bool) -> Result<(), Refusal> {
    if failed { Err(Refusal) } else { Ok(()) }
}

struct OfferInput<'a> {
    offer: Arc<AuthenticatedContributionOffer>,
    body_header: &'a [u8],
    proof_header: &'a [u8],
}
fn offer_input(
    roster: Arc<AuthenticatedRosterProposal>,
    bytes: &[u8],
) -> Result<OfferInput<'_>, ()> {
    let (envelope, signature, headers) =
        signed_packet::leading(bytes, MAXIMUM_OFFER_BYTES).ok_or(())?;
    if headers.len()
        != BODY_HEADER_BYTES + setup_relation(roster.proposal().profile()).proof_header_bytes()
    {
        return Err(());
    }
    let offer = authenticate_offer(roster, envelope, signature).map_err(|_| ())?;
    let (body_header, proof_header) = headers.split_at(BODY_HEADER_BYTES);
    Ok(OfferInput {
        offer: Arc::new(offer),
        body_header,
        proof_header,
    })
}
fn keep_offer<const EXACT: bool>(
    offers: &mut Vec<Arc<VerifiedOffer<EXACT>>>,
    offer: Arc<VerifiedOffer<EXACT>>,
) {
    if let Some(slot) = offers
        .iter_mut()
        .find(|old| old.envelope().position() == offer.envelope().position())
    {
        *slot = offer;
    } else {
        offers.push(offer);
    }
}
/// One visit's public setup verification, from its roster to the verified
/// setup that its certificate certifies.
pub struct SetupSession {
    input: Vec<u8>,
    output: Vec<u8>,
    roster: Option<RosterInputVerifier>,
    proposal: Option<Arc<AuthenticatedRosterProposal>>,
    poll: Option<Arc<VerifiedPoll>>,
    offer: Option<ContributionOfferVerifier>,
    offers: Vec<Arc<VerifiedContributionOffer>>,
    committed_offers: Vec<Arc<VerifiedCommittedOffer>>,
    unsigned: Option<SelectionProposal>,
    selected: Option<Arc<AuthenticatedSelectionProposal>>,
    inputs: Option<Arc<VerifiedSelectionInputs>>,
    endorsements: Vec<AuthenticatedSelectionEndorsement>,
    certificate: Option<AuthenticatedSelectionCertificate>,
    aggregator: Option<StreamedOfferAggregator>,
    public_work: PublicWork,
    verified: Option<Arc<VerifiedSetupAggregate>>,
}
impl SetupSession {
    pub fn new() -> Self {
        Self {
            input: vec![0; SETUP_INPUT_BYTES],
            output: Vec::new(),
            roster: None,
            proposal: None,
            poll: None,
            offer: None,
            offers: Vec::new(),
            committed_offers: Vec::new(),
            unsigned: None,
            selected: None,
            inputs: None,
            endorsements: Vec::new(),
            certificate: None,
            aggregator: None,
            public_work: PublicWork::default(),
            verified: None,
        }
    }
    pub fn input(&mut self) -> &mut [u8] {
        &mut self.input
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn verified_setup(&self) -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)> {
        Some((self.poll.clone()?, self.verified.clone()?))
    }
    /// Starts a setup verification with the roster verifier that reads its
    /// registrations, discarding any earlier one.
    fn begin_roster(&mut self, roster: RosterInputVerifier) {
        self.roster = Some(roster);
        self.proposal = None;
        self.poll = None;
        self.output.clear();
        self.offer = None;
        self.offers.clear();
        self.committed_offers.clear();
        self.public_work = PublicWork::default();
        self.unsigned = None;
        self.selected = None;
        self.inputs = None;
        self.endorsements.clear();
        self.certificate = None;
        self.aggregator = None;
        self.verified = None;
    }
    /// Starts a setup verification with the roster that the input's first
    /// `length` bytes begin.
    pub fn begin_roster_input(&mut self, length: usize) -> Result<(), Refusal> {
        let roster = RosterInputVerifier::new(self.input.get(..length).ok_or(Refusal)?)
            .map_err(|_| Refusal)?;
        self.begin_roster(roster);
        Ok(())
    }
    /// Restores this participant's earlier setup result only after the complete
    /// public certificate has authenticated against this visit's verified roster.
    pub fn restore_setup(&mut self, credential: &Credential, retained: &[u8]) -> bool {
        let (Some(poll), Some(certificate)) = (self.poll.clone(), self.certificate.as_ref()) else {
            return false;
        };
        let Ok(verified) =
            VerifiedSetupAggregate::restore(credential, &poll, certificate, retained)
        else {
            return false;
        };
        self.verified = Some(Arc::new(verified));
        true
    }
    pub fn roster_record(
        &mut self,
        step: RecordStep,
        position: usize,
        length: usize,
    ) -> Result<(), Refusal> {
        let Self {
            input,
            roster,
            proposal,
            ..
        } = self;
        if proposal.is_some() {
            return Err(Refusal);
        }
        let Some(bytes) = input.get(..length) else {
            return Err(Refusal);
        };
        let Some(roster) = roster.as_mut() else {
            return Err(Refusal);
        };
        refused(roster.record_step(step, position, bytes).is_err())
    }
    pub fn finish_roster(&mut self, length: usize) -> Result<(), Refusal> {
        if self.proposal.is_some() {
            return Err(Refusal);
        }
        let Self { input, roster, .. } = self;
        let Some((body, signature)) = input
            .get(..length)
            .and_then(|bytes| signed_packet::split(bytes, MAXIMUM_PROPOSAL_BYTES))
        else {
            return Err(Refusal);
        };
        let Some(roster) = roster.as_mut() else {
            return Err(Refusal);
        };
        let Ok(proposal) = roster.finish() else {
            return Err(Refusal);
        };
        if proposal.body() != body {
            return Err(Refusal);
        }
        let Ok(proposal) = authenticate_roster_proposal(proposal, signature) else {
            return Err(Refusal);
        };
        self.proposal = Some(Arc::new(proposal));
        self.poll = Some(Arc::new(self.roster.take().unwrap().into_poll()));
        Ok(())
    }
    /// The option count of the poll whose roster this verification verified, or
    /// zero before the roster verifies.
    pub fn option_count(&self) -> usize {
        self.proposal
            .as_ref()
            .map_or(0, |proposal| proposal.proposal().profile().options())
    }
    pub fn roster_context(&self) -> Option<(Arc<VerifiedPoll>, Arc<AuthenticatedRosterProposal>)> {
        Some((self.poll.clone()?, self.proposal.clone()?))
    }
    pub fn unsigned_selection(&self) -> Option<SelectionProposal> {
        self.unsigned.clone()
    }
    pub fn selection_inputs(&self) -> Option<Arc<VerifiedSelectionInputs>> {
        self.inputs.clone()
    }
    pub fn restore_inputs(&mut self, credential: &Credential, retained: &[u8]) -> bool {
        if self.verified.is_some() {
            return false;
        }
        let (Some(poll), Some(selection)) = (self.poll.clone(), self.selected.clone()) else {
            return false;
        };
        let Ok(inputs) = VerifiedSelectionInputs::restore(credential, &poll, selection, retained)
        else {
            return false;
        };
        self.inputs = Some(Arc::new(inputs));
        self.aggregator = None;
        true
    }
    /// Authenticated envelope and bounded body/proof-header lookahead. No pending
    /// offer replaces an already verified offer until its entire proof succeeds.
    pub fn begin_offer(&mut self, length: usize) -> Result<(), Refusal> {
        let result = (|| {
            let roster = self.proposal.clone().ok_or(())?;
            let bytes = self.input.get(..length).ok_or(())?;
            let OfferInput {
                offer,
                body_header,
                proof_header,
            } = offer_input(roster, bytes)?;
            ContributionOfferVerifier::new(offer, body_header, proof_header).map_err(|_| ())
        })();
        match result {
            Ok(verifier) => {
                self.offer = Some(verifier);
                Ok(())
            }
            Err(()) => {
                self.offer = None;
                Err(Refusal)
            }
        }
    }
    pub fn offer_polynomial(
        &mut self,
        index: usize,
        offset: usize,
        length: usize,
    ) -> Result<(), Refusal> {
        let Self { input, offer, .. } = self;
        let Some(bytes) = input.get(..length) else {
            return Err(Refusal);
        };
        refused(
            offer
                .as_mut()
                .is_none_or(|offer| offer.polynomial(index, offset, bytes).is_err()),
        )
    }
    pub fn offer_proof(&mut self, offset: usize, length: usize) -> Result<(), Refusal> {
        let Self { input, offer, .. } = self;
        let Some(bytes) = input.get(..length) else {
            return Err(Refusal);
        };
        refused(
            offer
                .as_mut()
                .is_none_or(|offer| offer.proof(offset, bytes).is_err()),
        )
    }
    pub fn finish_offer(&mut self) -> Result<(), Refusal> {
        let Some(offer) = self.offer.take() else {
            return Err(Refusal);
        };
        let Ok(offer) = offer.finish() else {
            return Err(Refusal);
        };
        keep_offer(&mut self.offers, Arc::new(offer));
        Ok(())
    }
    /// Whether a verified offer of the position carries the body identity
    /// that the input's first 64 bytes hold.
    pub fn offer_available(&self, position: usize, length: usize) -> bool {
        length == 64
            && self.offers.iter().any(|offer| {
                offer.envelope().position() == position
                    && offer.envelope().body_identity().as_slice() == &self.input[..64]
            })
    }
    /// Requested original positions only; every body identity comes from this
    /// verifier's completed offer results.
    pub fn propose_selection(&mut self, length: usize) -> Result<(), Refusal> {
        self.output.clear();
        if self.verified.is_some() {
            return Err(Refusal);
        }
        let result = (|| {
            let roster = self.proposal.as_ref().ok_or(())?;
            if length != 2 * roster.proposal().profile().setup_contributors() {
                return Err(());
            }
            let offers: Result<Vec<_>, _> = self.input[..length]
                .chunks_exact(2)
                .map(|position| {
                    let position = u16::from_le_bytes(position.try_into().unwrap()) as usize;
                    self.offers
                        .iter()
                        .find(|offer| offer.envelope().position() == position)
                        .cloned()
                        .ok_or(())
                })
                .collect();
            build_selection(roster, &offers?).map_err(|_| ())
        })();
        match result {
            Ok(selection) => {
                self.output = selection.body().to_vec();
                self.unsigned = Some(selection);
                Ok(())
            }
            Err(()) => Err(Refusal),
        }
    }
    fn install_selection(&mut self, selected: Arc<AuthenticatedSelectionProposal>) {
        if self
            .selected
            .as_ref()
            .is_none_or(|old| old.selection().body() != selected.selection().body())
        {
            self.aggregator = None;
            self.inputs = None;
            self.public_work.reset_selection();
            self.endorsements.clear();
        }
        self.selected = Some(selected);
    }
    pub fn begin_selection(&mut self, length: usize) -> Result<(), Refusal> {
        if self.verified.is_some() {
            return Err(Refusal);
        }
        let result = (|| {
            let roster = self.proposal.clone().ok_or(())?;
            let (body, signature) =
                signed_packet::split(self.input.get(..length).ok_or(())?, MAXIMUM_SELECTION_BYTES)
                    .ok_or(())?;
            authenticate_selection(roster, body, signature).map_err(|_| ())
        })();
        match result {
            Ok(selected) => {
                self.install_selection(Arc::new(selected));
                Ok(())
            }
            Err(()) => Err(Refusal),
        }
    }
    /// Writes the authenticated selection to the output: its identity, then
    /// each selected offer's position as four bytes and its body identity.
    pub fn output_selection(&mut self) -> Result<(), Refusal> {
        let selection = self.selected.as_ref().ok_or(Refusal)?.selection();
        let mut output = selection.identity().to_vec();
        for (position, identity) in selection.selected() {
            output.extend((*position as u32).to_le_bytes());
            output.extend(identity);
        }
        self.output = output;
        Ok(())
    }
    /// Begins the selected aggregation, discarding any earlier unfinished
    /// progress, which is disposable.
    pub fn aggregate_selection(&mut self) -> Result<(), Refusal> {
        self.aggregator = None;
        let result = (|| {
            let selected = self.selected.clone().ok_or(())?;
            let offers: Vec<_> = selected
                .selection()
                .selected()
                .iter()
                .filter_map(|(position, identity)| {
                    self.offers
                        .iter()
                        .find(|offer| {
                            offer.envelope().position() == *position
                                && offer.envelope().body_identity() == identity
                        })
                        .cloned()
                })
                .collect();
            let mut committed: Vec<_> = offers
                .iter()
                .map(|offer| Arc::new(offer.committed()))
                .collect();
            for offer in &self.committed_offers {
                if selected.selection().selected().contains(&(
                    offer.envelope().position(),
                    *offer.envelope().body_identity(),
                )) {
                    keep_offer(&mut committed, offer.clone());
                }
            }
            StreamedOfferAggregator::new(selected, committed).map_err(|_| ())
        })();
        match result {
            Ok(aggregate) => {
                self.aggregator = Some(aggregate);
                Ok(())
            }
            Err(()) => Err(Refusal),
        }
    }
    /// Discards only disposable aggregate progress. Positive offer holders,
    /// selected inputs and certificate authority remain in their owning state.
    pub fn discard_aggregation(&mut self) {
        self.aggregator = None;
    }
    pub fn begin_selected_offer_verification(&mut self, length: usize) -> Result<(), Refusal> {
        let result = (|| {
            let roster = self.proposal.clone().ok_or(())?;
            let OfferInput {
                offer,
                body_header,
                proof_header,
            } = offer_input(roster, self.input.get(..length).ok_or(())?)?;
            self.aggregator
                .as_mut()
                .ok_or(())?
                .begin_verification(offer, body_header, proof_header)
                .map_err(|_| ())
        })();
        refused(result.is_err())
    }
    pub fn selected_offer_proof(&mut self, offset: usize, length: usize) -> Result<(), Refusal> {
        let Self {
            input, aggregator, ..
        } = self;
        let Some(bytes) = input.get(..length) else {
            return Err(Refusal);
        };
        refused(
            aggregator
                .as_mut()
                .is_none_or(|aggregate| aggregate.proof(offset, bytes).is_err()),
        )
    }
    pub fn begin_selected_offer(&mut self, position: usize) -> Result<(), Refusal> {
        refused(
            self.aggregator
                .as_mut()
                .is_none_or(|aggregate| aggregate.begin(position).is_err()),
        )
    }
    pub fn aggregate_polynomial(
        &mut self,
        index: usize,
        offset: usize,
        length: usize,
    ) -> Result<(), Refusal> {
        let Self {
            input, aggregator, ..
        } = self;
        if length > CHUNK_BYTES {
            return Err(Refusal);
        }
        let (incoming, previous) = input.split_at_mut(CHUNK_BYTES);
        refused(aggregator.as_mut().is_none_or(|aggregate| {
            aggregate
                .polynomial(index, offset, &incoming[..length], &mut previous[..length])
                .is_err()
        }))
    }
    pub fn finish_selected_offer(&mut self) -> Result<(), Refusal> {
        let Some(Ok(offer)) = self
            .aggregator
            .as_mut()
            .map(StreamedOfferAggregator::finish_contribution)
        else {
            return Err(Refusal);
        };
        keep_offer(&mut self.committed_offers, offer);
        Ok(())
    }
    pub fn accepted(&self) -> usize {
        self.aggregator
            .as_ref()
            .map_or(0, StreamedOfferAggregator::accepted)
    }
    pub fn finish_selection(&mut self) -> Result<(), Refusal> {
        if self
            .aggregator
            .as_ref()
            .is_none_or(|aggregate| !aggregate.complete())
        {
            return Err(Refusal);
        }
        let Ok(inputs) = self.aggregator.take().unwrap().finish() else {
            return Err(Refusal);
        };
        self.public_work.streamed = Some(inputs);
        Ok(())
    }
    pub fn add_endorsement(&mut self, length: usize) -> Result<(), Refusal> {
        let result = (|| {
            let selected = self.selected.as_ref().ok_or(())?;
            authenticate_endorsement(
                selected.roster(),
                selected.selection(),
                self.input.get(..length).ok_or(())?,
            )
            .map_err(|_| ())
        })();
        let Ok(endorsement) = result else {
            return Err(Refusal);
        };
        if let Some(old) = self
            .endorsements
            .iter()
            .find(|old| old.position() == endorsement.position())
        {
            return refused(old.selection_identity() != endorsement.selection_identity());
        }
        self.endorsements.push(endorsement);
        self.endorsements
            .sort_by_key(AuthenticatedSelectionEndorsement::position);
        Ok(())
    }
    pub fn build_certificate(&mut self) -> Result<(), Refusal> {
        self.output.clear();
        let result = (|| {
            let selected = self.selected.as_ref().ok_or(())?;
            let quorum = selected.roster().proposal().profile().inventory_threshold();
            encode_certificate(selected, self.endorsements.get(..quorum).ok_or(())?).map_err(|_| ())
        })();
        match result {
            Ok(bytes) => {
                self.output = bytes;
                Ok(())
            }
            Err(()) => Err(Refusal),
        }
    }
    pub fn begin_certificate(&mut self, length: usize) -> Result<(), Refusal> {
        let result = (|| {
            let roster = self.proposal.clone().ok_or(())?;
            authenticate_certificate(roster, self.input.get(..length).ok_or(())?).map_err(|_| ())
        })();
        let Ok(certificate) = result else {
            return Err(Refusal);
        };
        if self
            .verified
            .as_ref()
            .is_some_and(|verified| verified.identity() != certificate.identity())
        {
            return Err(Refusal);
        }
        self.install_selection(Arc::new(certificate.proposal().clone()));
        self.certificate = Some(certificate);
        Ok(())
    }
    pub fn finish_certificate(&mut self) -> Result<(), Refusal> {
        let (Some(inputs), Some(certificate)) = (self.inputs.as_ref(), self.certificate.as_ref())
        else {
            return Err(Refusal);
        };
        let Ok(verified) = inputs.certify(certificate) else {
            return Err(Refusal);
        };
        self.verified = Some(Arc::new(verified));
        Ok(())
    }
}
impl Default for SetupSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "setup-session-tests.rs"]
mod tests;
