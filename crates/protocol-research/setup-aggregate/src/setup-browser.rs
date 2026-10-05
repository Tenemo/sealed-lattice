use crate::{
    CHUNK_BYTES,
    verified::{SetupAggregator, VerifiedSelectionInputs, VerifiedSetupAggregate, build_selection},
};
use opened_contribution::{ContributionOfferVerifier, VerifiedContributionOffer};
use registration_credentials::{
    Credential, SIGNATURE_BYTES,
    contribution_body::BODY_HEADER_BYTES,
    contribution_offer::{AuthenticatedContributionOffer, MAXIMUM_OFFER_BYTES, authenticate_offer},
    poll::VerifiedPoll,
    roster::MAXIMUM_PROPOSAL_BYTES,
    roster_authentication::{OrganizerSignedRoster, verify_roster_proposal},
    roster_input::RosterInputVerifier,
    setup_selection::{
        AuthenticatedSelectionCertificate, AuthenticatedSelectionEndorsement,
        AuthenticatedSelectionProposal, MAXIMUM_SELECTION_BYTES, SelectionProposal,
        authenticate_certificate, authenticate_endorsement, authenticate_selection,
        encode_certificate,
    },
};
use std::{cell::RefCell, sync::Arc};
use supported_profile::relation::PROOF_HEADER_BYTES;

const INPUT_BYTES: usize = 1_572_864;
struct Session {
    input: Vec<u8>,
    output: Vec<u8>,
    roster: Option<RosterInputVerifier>,
    proposal: Option<Arc<OrganizerSignedRoster>>,
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
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session {
    input: vec![0; INPUT_BYTES], output: Vec::new(), roster: None, proposal: None, poll: None, offer: None, offers: Vec::new(), unsigned: None, selected: None, inputs: None, endorsements: Vec::new(), certificate: None, aggregator: None, verified: None,
}); }

pub fn context() -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)> {
    SESSION.with(|value| {
        let value = value.borrow();
        Some((value.poll.clone()?, value.verified.clone()?))
    })
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
fn offer_input(roster: Arc<OrganizerSignedRoster>, bytes: &[u8]) -> Result<OfferInput<'_>, ()> {
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
#[unsafe(no_mangle)]
pub extern "C" fn setup_input_pointer() -> usize {
    SESSION.with(|value| value.borrow_mut().input.as_mut_ptr() as usize)
}
/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn setup_input_capacity() -> usize {
    INPUT_BYTES
}
/// The largest aggregated chunk. Its incoming bytes start the input buffer
/// and the previous aggregate follows at this offset.
#[unsafe(no_mangle)]
pub extern "C" fn setup_chunk_capacity() -> usize {
    CHUNK_BYTES
}
/// Starts a setup verification with the roster verifier that reads its
/// registrations, discarding any earlier one.
pub fn begin_roster(roster: RosterInputVerifier) {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        value.roster = Some(roster);
        value.proposal = None;
        value.poll = None;
        value.output.clear();
        value.offer = None;
        value.offers.clear();
        value.unsigned = None;
        value.selected = None;
        value.inputs = None;
        value.endorsements.clear();
        value.certificate = None;
        value.aggregator = None;
        value.verified = None;
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_begin(length: usize) -> u32 {
    let Some(roster) = SESSION.with(|value| {
        let value = value.borrow();
        RosterInputVerifier::new(value.input.get(..length)?).ok()
    }) else {
        return 1;
    };
    begin_roster(roster);
    0
}
/// Restores this participant's earlier setup result only after the complete
/// public certificate has authenticated against this visit's verified roster.
pub fn restore(credential: &Credential, retained: &[u8]) -> bool {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let (Some(poll), Some(certificate)) = (value.poll.clone(), value.certificate.as_ref())
        else {
            return false;
        };
        let Ok(verified) =
            VerifiedSetupAggregate::restore(credential, &poll, certificate, retained)
        else {
            return false;
        };
        value.verified = Some(Arc::new(verified));
        true
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_record(operation: u32, position: usize, length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        let Session {
            input,
            roster,
            proposal,
            ..
        } = &mut *value;
        if proposal.is_some() {
            return 1;
        }
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        let Some(roster) = roster.as_mut() else {
            return 1;
        };
        let result = match operation {
            0 => roster.begin_record(bytes),
            1 => roster.push_key(position, bytes),
            2 if length == 0 => roster.finish_key(position),
            4 if length == 0 => roster.finish_record(position),
            5 if length == 0 => roster.discard_record(position),
            _ => return 1,
        };
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_roster_finish(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        if value.proposal.is_some() {
            return 0;
        }
        let Session { input, roster, .. } = &mut *value;
        let Some((body, signature)) = input
            .get(..length)
            .and_then(|bytes| packet(bytes, MAXIMUM_PROPOSAL_BYTES))
        else {
            return 0;
        };
        let Some(roster) = roster.as_mut() else {
            return 0;
        };
        let Ok(proposal) = roster.finish() else {
            return 0;
        };
        if proposal.body() != body {
            return 0;
        }
        let Ok(proposal) = verify_roster_proposal(proposal, signature) else {
            return 0;
        };
        value.proposal = Some(Arc::new(proposal));
        value.poll = Some(Arc::new(value.roster.take().unwrap().into_poll()));
        1
    })
}
/// The option count of the poll whose roster this verification verified, or
/// zero before the roster verifies.
#[unsafe(no_mangle)]
pub extern "C" fn setup_option_count() -> usize {
    SESSION.with(|value| {
        value
            .borrow()
            .proposal
            .as_ref()
            .map_or(0, |proposal| proposal.proposal().profile().options())
    })
}

pub fn roster_context() -> Option<(Arc<VerifiedPoll>, Arc<OrganizerSignedRoster>)> {
    SESSION.with(|state| {
        let state = state.borrow();
        Some((state.poll.clone()?, state.proposal.clone()?))
    })
}
pub fn verified_offers() -> Vec<Arc<VerifiedContributionOffer>> {
    SESSION.with(|state| state.borrow().offers.clone())
}
pub fn unsigned_selection() -> Option<SelectionProposal> {
    SESSION.with(|state| state.borrow().unsigned.clone())
}
pub fn authenticated_selection() -> Option<Arc<AuthenticatedSelectionProposal>> {
    SESSION.with(|state| state.borrow().selected.clone())
}
pub fn selection_inputs() -> Option<Arc<VerifiedSelectionInputs>> {
    SESSION.with(|state| state.borrow().inputs.clone())
}
pub fn restore_inputs(credential: &Credential, retained: &[u8]) -> bool {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.verified.is_some() {
            return false;
        }
        let (Some(poll), Some(selection)) = (state.poll.clone(), state.selected.clone()) else {
            return false;
        };
        let Ok(inputs) = VerifiedSelectionInputs::restore(credential, &poll, selection, retained)
        else {
            return false;
        };
        state.inputs = Some(Arc::new(inputs));
        state.aggregator = None;
        true
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn setup_output_pointer() -> usize {
    SESSION.with(|state| state.borrow().output.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_output_length() -> usize {
    SESSION.with(|state| state.borrow().output.len())
}

/// Authenticated envelope and bounded body/proof-header lookahead. No pending
/// offer replaces an already verified offer until its entire proof succeeds.
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let result = (|| {
            let roster = state.proposal.clone().ok_or(())?;
            let bytes = state.input.get(..length).ok_or(())?;
            let OfferInput {
                offer,
                body_header,
                proof_header,
            } = offer_input(roster, bytes)?;
            ContributionOfferVerifier::new(offer, body_header, proof_header).map_err(|_| ())
        })();
        match result {
            Ok(verifier) => {
                state.offer = Some(verifier);
                0
            }
            Err(()) => {
                state.offer = None;
                1
            }
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_polynomial(index: usize, offset: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, offer, .. } = &mut *state;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        u32::from(
            offer
                .as_mut()
                .is_none_or(|offer| offer.polynomial(index, offset, bytes).is_err()),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_proof(offset: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session { input, offer, .. } = &mut *state;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        u32::from(
            offer
                .as_mut()
                .is_none_or(|offer| offer.proof(offset, bytes).is_err()),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(offer) = state.offer.take() else {
            return 0;
        };
        let Ok(offer) = offer.finish() else {
            return 0;
        };
        keep_offer(&mut state.offers, Arc::new(offer));
        1
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_offer_available(position: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let state = state.borrow();
        u32::from(
            length == 64
                && state.offers.iter().any(|offer| {
                    offer.envelope().position() == position
                        && offer.envelope().body_identity().as_slice() == &state.input[..64]
                }),
        )
    })
}

/// Requested original positions only; every body identity comes from this
/// verifier's completed offer results.
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_build(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.output.clear();
        if state.verified.is_some() {
            return 1;
        }
        let result = (|| {
            let roster = state.proposal.as_ref().ok_or(())?;
            if length != 2 * roster.proposal().profile().setup_contributors() {
                return Err(());
            }
            let offers: Result<Vec<_>, _> = state.input[..length]
                .chunks_exact(2)
                .map(|position| {
                    let position = u16::from_le_bytes(position.try_into().unwrap()) as usize;
                    state
                        .offers
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
                state.output = selection.body().to_vec();
                state.unsigned = Some(selection);
                0
            }
            Err(()) => 1,
        }
    })
}

fn install_selection(state: &mut Session, selected: Arc<AuthenticatedSelectionProposal>) {
    if state
        .selected
        .as_ref()
        .is_none_or(|old| old.selection().body() != selected.selection().body())
    {
        state.aggregator = None;
        state.inputs = None;
        state.endorsements.clear();
    }
    state.selected = Some(selected);
}

#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_begin(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.verified.is_some() {
            return 1;
        }
        let result = (|| {
            let roster = state.proposal.clone().ok_or(())?;
            let (body, signature) = packet(
                state.input.get(..length).ok_or(())?,
                MAXIMUM_SELECTION_BYTES,
            )
            .ok_or(())?;
            authenticate_selection(roster, body, signature).map_err(|_| ())
        })();
        match result {
            Ok(selected) => {
                install_selection(&mut state, Arc::new(selected));
                0
            }
            Err(()) => 1,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_count() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .selected
            .as_ref()
            .map_or(0, |selection| selection.selection().selected().len())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_position(ordinal: usize) -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .selected
            .as_ref()
            .and_then(|selection| {
                selection
                    .selection()
                    .selected()
                    .get(ordinal)
                    .map(|entry| entry.0)
            })
            .unwrap_or(usize::MAX)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_body_identity_pointer(ordinal: usize) -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .selected
            .as_ref()
            .and_then(|selection| {
                selection
                    .selection()
                    .selected()
                    .get(ordinal)
                    .map(|entry| entry.1.as_ptr() as usize)
            })
            .unwrap_or(0)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_identity_pointer() -> usize {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(identity) = state
            .selected
            .as_ref()
            .map(|selection| selection.selection().identity())
        else {
            return 0;
        };
        state.output = identity.to_vec();
        state.output.as_ptr() as usize
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_aggregate() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state.aggregator.is_some() {
            return 0;
        }
        let result = (|| {
            let selected = state.selected.clone().ok_or(())?;
            let offers: Vec<_> = selected
                .selection()
                .selected()
                .iter()
                .filter_map(|(position, identity)| {
                    state
                        .offers
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
                state.aggregator = Some(aggregate);
                1
            }
            Err(()) => 0,
        }
    })
}
/// Discards only disposable aggregate progress. Positive offer holders,
/// selected inputs and certificate authority remain in their owning state.
#[unsafe(no_mangle)]
pub extern "C" fn setup_discard_aggregation() -> u32 {
    SESSION.with(|state| {
        state.borrow_mut().aggregator = None;
    });
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_begin_selected_offer_verification(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let result = (|| {
            let roster = state.proposal.clone().ok_or(())?;
            let Session {
                input, aggregator, ..
            } = &mut *state;
            let OfferInput {
                offer,
                body_header,
                proof_header,
            } = offer_input(roster, input.get(..length).ok_or(())?)?;
            aggregator
                .as_mut()
                .ok_or(())?
                .begin_verification(offer, body_header, proof_header)
                .map_err(|_| ())
        })();
        u32::from(result.is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selected_offer_proof(offset: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session {
            input, aggregator, ..
        } = &mut *state;
        let Some(bytes) = input.get(..length) else {
            return 1;
        };
        u32::from(
            aggregator
                .as_mut()
                .is_none_or(|aggregate| aggregate.proof(offset, bytes).is_err()),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_begin_selected_offer(position: usize) -> u32 {
    SESSION.with(|state| {
        u32::from(
            state
                .borrow_mut()
                .aggregator
                .as_mut()
                .is_none_or(|aggregate| aggregate.begin(position).is_err()),
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_polynomial(index: usize, offset: usize, length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Session {
            input, aggregator, ..
        } = &mut *state;
        if length > CHUNK_BYTES {
            return 1;
        }
        let (incoming, previous) = input.split_at_mut(CHUNK_BYTES);
        u32::from(aggregator.as_mut().is_none_or(|aggregate| {
            aggregate
                .polynomial(index, offset, &incoming[..length], &mut previous[..length])
                .is_err()
        }))
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_finish_selected_offer() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(Ok(offer)) = state
            .aggregator
            .as_mut()
            .map(SetupAggregator::finish_contribution)
        else {
            return 0;
        };
        keep_offer(&mut state.offers, offer);
        1
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_accepted() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .aggregator
            .as_ref()
            .map_or(0, SetupAggregator::accepted)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_selection_finish() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if state
            .aggregator
            .as_ref()
            .is_none_or(|aggregate| !aggregate.complete())
        {
            return 0;
        }
        let Ok(inputs) = state.aggregator.take().unwrap().finish() else {
            return 0;
        };
        if state.inputs.as_ref().is_some_and(|known| {
            known.identity() != inputs.identity() || known.polynomials() != inputs.polynomials()
        }) || state.verified.as_ref().is_some_and(|known| {
            known.identity() != inputs.identity() || known.polynomials() != inputs.polynomials()
        }) {
            return 0;
        }
        state.inputs = Some(Arc::new(inputs));
        1
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn setup_endorsement(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let result = (|| {
            let selected = state.selected.as_ref().ok_or(())?;
            authenticate_endorsement(
                selected.roster(),
                selected.selection(),
                state.input.get(..length).ok_or(())?,
            )
            .map_err(|_| ())
        })();
        let Ok(endorsement) = result else {
            return 1;
        };
        if let Some(old) = state
            .endorsements
            .iter()
            .find(|old| old.position() == endorsement.position())
        {
            return u32::from(old.selection_identity() != endorsement.selection_identity());
        }
        state.endorsements.push(endorsement);
        state
            .endorsements
            .sort_by_key(AuthenticatedSelectionEndorsement::position);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_certificate_build() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        state.output.clear();
        let result = (|| {
            let selected = state.selected.as_ref().ok_or(())?;
            let quorum = selected.roster().proposal().profile().inventory_threshold();
            encode_certificate(selected, state.endorsements.get(..quorum).ok_or(())?)
                .map_err(|_| ())
        })();
        match result {
            Ok(bytes) => {
                state.output = bytes;
                0
            }
            Err(()) => 1,
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_certificate(length: usize) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let result = (|| {
            let roster = state.proposal.clone().ok_or(())?;
            authenticate_certificate(roster, state.input.get(..length).ok_or(())?).map_err(|_| ())
        })();
        let Ok(certificate) = result else {
            return 1;
        };
        if state
            .verified
            .as_ref()
            .is_some_and(|verified| verified.identity() != certificate.identity())
        {
            return 1;
        }
        install_selection(&mut state, Arc::new(certificate.proposal().clone()));
        state.certificate = Some(certificate);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn setup_finish_certificate() -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        let (Some(inputs), Some(certificate)) = (state.inputs.as_ref(), state.certificate.as_ref())
        else {
            return 0;
        };
        let Ok(verified) = inputs.certify(certificate) else {
            return 0;
        };
        state.verified = Some(Arc::new(verified));
        1
    })
}
