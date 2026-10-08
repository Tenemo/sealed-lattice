//! The participant crate's WebAssembly exports, one file per stage, and the
//! participant session they share.
use crate::{Enrollment, offer_signing::OfferSigning};
use protocol_foundations::foundation::{MAXIMUM_USERNAME_INGRESS_BYTES, RegistrationHeader};
use protocol_foundations::{
    SIGNATURE_BYTES,
    roster::{RetainedContributionContext, RosterProposal},
    roster_authentication::AuthenticatedRosterProposal,
    roster_input::RosterInputVerifier,
};
use std::{cell::RefCell, sync::Arc};

mod ballot;
mod close;
mod contribution;
#[path = "abi/custody-identity.rs"]
mod custody_identity;
mod enrollment;
mod evaluation;
mod finality;
#[path = "abi/operation-random.rs"]
mod operation_random;
#[path = "abi/own-verification.rs"]
mod own_verification;
mod parallel;
#[path = "abi/participant-bounds.rs"]
mod participant_bounds;
mod release;
mod roster;
mod setup;

fn input_bytes() -> usize {
    let retained_setup = supported_profile::Profile::all()
        .map(|profile| {
            4 + 64
                + 64 * profile.contribution_body_polynomials().len()
                + protocol_foundations::RETAINED_TAG_BYTES
        })
        .max()
        .unwrap();
    let restore = 128
        + 4
        + RegistrationHeader::maximum_bytes()
        + 128
        + protocol_foundations::registration::KEY_BYTES
        + setup_witness::registration::SEALED_KEY_BYTES
        + protocol_foundations::SEALED_SIGNING_SEED_BYTES
        + 2
        + (96 + crate::fhe_sources::maximum_capsule_bytes()).max(64 + 4 + retained_setup);
    let enrollment = 128
        + 4
        + protocol_foundations::poll::MAXIMUM_POLL_BYTES
        + protocol_foundations::SIGNATURE_BYTES
        + 4
        + MAXIMUM_USERNAME_INGRESS_BYTES
        + 96;
    restore.max(enrollment)
}
struct Session {
    input: Vec<u8>,
    started: bool,
    restored: bool,
    enrollment: Option<Enrollment>,
    poll_identity: [u8; 64],
    roster: Option<RosterInputVerifier>,
    proposal: Option<RosterProposal>,
    proposal_signature: Option<[u8; SIGNATURE_BYTES]>,
    signed_proposal: Option<Arc<AuthenticatedRosterProposal>>,
    offer: OfferSigning,
    contribution_output: Vec<u8>,
    unsigned_selection: Option<protocol_foundations::setup_selection::SelectionProposal>,
    retained_context: Option<RetainedContributionContext>,
    ballot: Option<crate::ballot::BallotWork>,
    close: Option<crate::close_work::CloseWork>,
    finality: Option<crate::finality_work::FinalityWork>,
    release: Option<release::ReleaseState>,
    // A retained evaluated target the host streams in, and its length.
    evaluation: Option<(usize, Vec<u8>)>,
}
thread_local! {
    static SESSION: RefCell<Session> = RefCell::new(Session {
        input: vec![0; input_bytes()],
        started: false,
        restored: false,
        enrollment: None,
        poll_identity: [0; 64],
        roster: None,
        proposal: None,
        proposal_signature: None,
        signed_proposal: None,
        offer: OfferSigning::default(),
        contribution_output: Vec::new(),
        unsigned_selection: None,
        retained_context: None,
        ballot: None,
        close: None,
        finality: None,
        release: None,
        evaluation: None,
    });
}
#[unsafe(no_mangle)]
pub extern "C" fn input_pointer() -> usize {
    SESSION.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}

/// The input buffer's length; the host never writes more.
#[unsafe(no_mangle)]
pub extern "C" fn input_capacity() -> usize {
    SESSION.with(|state| state.borrow().input.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn poll_identity_pointer() -> usize {
    SESSION.with(|state| state.borrow().poll_identity.as_ptr() as usize)
}

fn signed_packet(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if length > protocol_foundations::setup_selection::MAXIMUM_SELECTION_BYTES
        || bytes.len() != 4 + length + SIGNATURE_BYTES
    {
        return None;
    }
    Some((&bytes[4..4 + length], &bytes[4 + length..]))
}

fn emitted_packet(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut output = Vec::from((body.len() as u32).to_le_bytes());
    output.extend(body);
    output.extend(signature);
    output
}

fn original_context(
    state: &Session,
) -> Result<RetainedContributionContext, protocol_foundations::Error> {
    use protocol_foundations::Error;
    if let Some(context) = &state.retained_context {
        return Ok(context.clone());
    }
    let enrollment = state.enrollment.as_ref().ok_or(Error::Context)?;
    let original = own_verification::verified().ok_or(Error::Context)?;
    let proposal = state
        .signed_proposal
        .as_ref()
        .ok_or(Error::Context)?
        .proposal();
    let position = proposal
        .records()
        .iter()
        .position(|record| {
            record.body_digest() == original.body_digest()
                && record.header().signing_public == *enrollment.credential.signing_public()
        })
        .ok_or(Error::Context)?;
    own_verification::with_poll(|poll| {
        RetainedContributionContext::parse(
            &enrollment.credential,
            &original,
            poll,
            position,
            proposal.body(),
        )
    })
    .ok_or(Error::Context)?
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_output_pointer() -> usize {
    SESSION.with(|state| state.borrow().contribution_output.as_ptr() as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn contribution_output_length() -> usize {
    SESSION.with(|state| state.borrow().contribution_output.len())
}
