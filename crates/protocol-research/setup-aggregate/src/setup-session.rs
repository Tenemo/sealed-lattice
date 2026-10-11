//! The public setup verification: the roster, the contribution offers, the
//! selection and its aggregate, and the certificate that verifies the setup.
use crate::offer_verifier::{ContributionOfferVerifier, VerifiedContributionOffer};
use crate::{
    CHUNK_BYTES,
    verified::{SetupAggregator, VerifiedSelectionInputs, VerifiedSetupAggregate, build_selection},
};
use protocol_foundations::{
    Credential, SIGNATURE_BYTES,
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
};
use std::sync::Arc;
use supported_profile::relation::PROOF_HEADER_BYTES;

pub const SETUP_INPUT_BYTES: usize = 1_572_864;
/// A refused setup verification step.
#[derive(Debug)]
pub struct Refused;
fn refused(failed: bool) -> Result<(), Refused> {
    if failed { Err(Refused) } else { Ok(()) }
}
fn packet(bytes: &[u8], maximum: usize) -> Option<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if length > maximum || bytes.len() != 4 + length + SIGNATURE_BYTES {
        return None;
    }
    Some((&bytes[4..4 + length], &bytes[4 + length..]))
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
    let envelope_length =
        u32::from_le_bytes(bytes.get(..4).ok_or(())?.try_into().unwrap()) as usize;
    if envelope_length > MAXIMUM_OFFER_BYTES
        || bytes.len()
            != 4 + envelope_length + SIGNATURE_BYTES + BODY_HEADER_BYTES + PROOF_HEADER_BYTES
    {
        return Err(());
    }
    let end = 4 + envelope_length;
    let offer = authenticate_offer(roster, &bytes[4..end], &bytes[end..end + SIGNATURE_BYTES])
        .map_err(|_| ())?;
    let header = end + SIGNATURE_BYTES;
    Ok(OfferInput {
        offer: Arc::new(offer),
        body_header: &bytes[header..header + BODY_HEADER_BYTES],
        proof_header: &bytes[header + BODY_HEADER_BYTES..],
    })
}
fn keep_offer(
    offers: &mut Vec<Arc<VerifiedContributionOffer>>,
    offer: Arc<VerifiedContributionOffer>,
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
    unsigned: Option<SelectionProposal>,
    selected: Option<Arc<AuthenticatedSelectionProposal>>,
    inputs: Option<Arc<VerifiedSelectionInputs>>,
    endorsements: Vec<AuthenticatedSelectionEndorsement>,
    certificate: Option<AuthenticatedSelectionCertificate>,
    aggregator: Option<SetupAggregator>,
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
            unsigned: None,
            selected: None,
            inputs: None,
            endorsements: Vec::new(),
            certificate: None,
            aggregator: None,
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
    pub fn begin_roster_input(&mut self, length: usize) -> Result<(), Refused> {
        let roster = RosterInputVerifier::new(self.input.get(..length).ok_or(Refused)?)
            .map_err(|_| Refused)?;
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
    ) -> Result<(), Refused> {
        let Self {
            input,
            roster,
            proposal,
            ..
        } = self;
        if proposal.is_some() {
            return Err(Refused);
        }
        let Some(bytes) = input.get(..length) else {
            return Err(Refused);
        };
        let Some(roster) = roster.as_mut() else {
            return Err(Refused);
        };
        refused(roster.record_step(step, position, bytes).is_err())
    }
    pub fn finish_roster(&mut self, length: usize) -> Result<(), Refused> {
        if self.proposal.is_some() {
            return Err(Refused);
        }
        let Self { input, roster, .. } = self;
        let Some((body, signature)) = input
            .get(..length)
            .and_then(|bytes| packet(bytes, MAXIMUM_PROPOSAL_BYTES))
        else {
            return Err(Refused);
        };
        let Some(roster) = roster.as_mut() else {
            return Err(Refused);
        };
        let Ok(proposal) = roster.finish() else {
            return Err(Refused);
        };
        if proposal.body() != body {
            return Err(Refused);
        }
        let Ok(proposal) = authenticate_roster_proposal(proposal, signature) else {
            return Err(Refused);
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
    pub fn begin_offer(&mut self, length: usize) -> Result<(), Refused> {
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
                Err(Refused)
            }
        }
    }
    pub fn offer_polynomial(
        &mut self,
        index: usize,
        offset: usize,
        length: usize,
    ) -> Result<(), Refused> {
        let Self { input, offer, .. } = self;
        let Some(bytes) = input.get(..length) else {
            return Err(Refused);
        };
        refused(
            offer
                .as_mut()
                .is_none_or(|offer| offer.polynomial(index, offset, bytes).is_err()),
        )
    }
    pub fn offer_proof(&mut self, offset: usize, length: usize) -> Result<(), Refused> {
        let Self { input, offer, .. } = self;
        let Some(bytes) = input.get(..length) else {
            return Err(Refused);
        };
        refused(
            offer
                .as_mut()
                .is_none_or(|offer| offer.proof(offset, bytes).is_err()),
        )
    }
    pub fn finish_offer(&mut self) -> Result<(), Refused> {
        let Some(offer) = self.offer.take() else {
            return Err(Refused);
        };
        let Ok(offer) = offer.finish() else {
            return Err(Refused);
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
    pub fn propose_selection(&mut self, length: usize) -> Result<(), Refused> {
        self.output.clear();
        if self.verified.is_some() {
            return Err(Refused);
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
            Err(()) => Err(Refused),
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
            self.endorsements.clear();
        }
        self.selected = Some(selected);
    }
    pub fn begin_selection(&mut self, length: usize) -> Result<(), Refused> {
        if self.verified.is_some() {
            return Err(Refused);
        }
        let result = (|| {
            let roster = self.proposal.clone().ok_or(())?;
            let (body, signature) =
                packet(self.input.get(..length).ok_or(())?, MAXIMUM_SELECTION_BYTES).ok_or(())?;
            authenticate_selection(roster, body, signature).map_err(|_| ())
        })();
        match result {
            Ok(selected) => {
                self.install_selection(Arc::new(selected));
                Ok(())
            }
            Err(()) => Err(Refused),
        }
    }
    pub fn selection_count(&self) -> usize {
        self.selected
            .as_ref()
            .map_or(0, |selection| selection.selection().selected().len())
    }
    pub fn selection_position(&self, ordinal: usize) -> Option<usize> {
        self.selected.as_ref().and_then(|selection| {
            selection
                .selection()
                .selected()
                .get(ordinal)
                .map(|entry| entry.0)
        })
    }
    pub fn selection_body_identity(&self, ordinal: usize) -> Option<&[u8; 64]> {
        self.selected.as_ref().and_then(|selection| {
            selection
                .selection()
                .selected()
                .get(ordinal)
                .map(|entry| &entry.1)
        })
    }
    /// Writes the selection's identity to the output, when there is a
    /// selection.
    pub fn output_selection_identity(&mut self) -> bool {
        let Some(identity) = self
            .selected
            .as_ref()
            .map(|selection| selection.selection().identity())
        else {
            return false;
        };
        self.output = identity.to_vec();
        true
    }
    pub fn aggregate_selection(&mut self) -> Result<(), Refused> {
        if self.aggregator.is_some() {
            return Err(Refused);
        }
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
            SetupAggregator::new(selected, offers).map_err(|_| ())
        })();
        match result {
            Ok(aggregate) => {
                self.aggregator = Some(aggregate);
                Ok(())
            }
            Err(()) => Err(Refused),
        }
    }
    /// Discards only disposable aggregate progress. Positive offer holders,
    /// selected inputs and certificate authority remain in their owning state.
    pub fn discard_aggregation(&mut self) {
        self.aggregator = None;
    }
    pub fn begin_selected_offer_verification(&mut self, length: usize) -> Result<(), Refused> {
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
    pub fn selected_offer_proof(&mut self, offset: usize, length: usize) -> Result<(), Refused> {
        let Self {
            input, aggregator, ..
        } = self;
        let Some(bytes) = input.get(..length) else {
            return Err(Refused);
        };
        refused(
            aggregator
                .as_mut()
                .is_none_or(|aggregate| aggregate.proof(offset, bytes).is_err()),
        )
    }
    pub fn begin_selected_offer(&mut self, position: usize) -> Result<(), Refused> {
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
    ) -> Result<(), Refused> {
        let Self {
            input, aggregator, ..
        } = self;
        if length > CHUNK_BYTES {
            return Err(Refused);
        }
        let (incoming, previous) = input.split_at_mut(CHUNK_BYTES);
        refused(aggregator.as_mut().is_none_or(|aggregate| {
            aggregate
                .polynomial(index, offset, &incoming[..length], &mut previous[..length])
                .is_err()
        }))
    }
    pub fn finish_selected_offer(&mut self) -> Result<(), Refused> {
        let Some(Ok(offer)) = self
            .aggregator
            .as_mut()
            .map(SetupAggregator::finish_contribution)
        else {
            return Err(Refused);
        };
        keep_offer(&mut self.offers, offer);
        Ok(())
    }
    pub fn accepted(&self) -> usize {
        self.aggregator
            .as_ref()
            .map_or(0, SetupAggregator::accepted)
    }
    pub fn finish_selection(&mut self) -> Result<(), Refused> {
        if self
            .aggregator
            .as_ref()
            .is_none_or(|aggregate| !aggregate.complete())
        {
            return Err(Refused);
        }
        let Ok(inputs) = self.aggregator.take().unwrap().finish() else {
            return Err(Refused);
        };
        if self.inputs.as_ref().is_some_and(|known| {
            known.identity() != inputs.identity() || known.polynomials() != inputs.polynomials()
        }) || self.verified.as_ref().is_some_and(|known| {
            known.identity() != inputs.identity() || known.polynomials() != inputs.polynomials()
        }) {
            return Err(Refused);
        }
        self.inputs = Some(Arc::new(inputs));
        Ok(())
    }
    pub fn add_endorsement(&mut self, length: usize) -> Result<(), Refused> {
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
            return Err(Refused);
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
    pub fn build_certificate(&mut self) -> Result<(), Refused> {
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
            Err(()) => Err(Refused),
        }
    }
    pub fn begin_certificate(&mut self, length: usize) -> Result<(), Refused> {
        let result = (|| {
            let roster = self.proposal.clone().ok_or(())?;
            authenticate_certificate(roster, self.input.get(..length).ok_or(())?).map_err(|_| ())
        })();
        let Ok(certificate) = result else {
            return Err(Refused);
        };
        if self
            .verified
            .as_ref()
            .is_some_and(|verified| verified.identity() != certificate.identity())
        {
            return Err(Refused);
        }
        self.install_selection(Arc::new(certificate.proposal().clone()));
        self.certificate = Some(certificate);
        Ok(())
    }
    pub fn finish_certificate(&mut self) -> Result<(), Refused> {
        let (Some(inputs), Some(certificate)) = (self.inputs.as_ref(), self.certificate.as_ref())
        else {
            return Err(Refused);
        };
        let Ok(verified) = inputs.certify(certificate) else {
            return Err(Refused);
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
