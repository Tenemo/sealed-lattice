use crate::{
    close::{
        AuthenticatedCloseIntent, AuthenticatedCloseResponse, CloseContext, VerifiedCloseBarrier,
    },
    submission::{
        AuthenticatedBallotBody, AuthenticatedBallotEnvelope, BallotBodyAuthentication,
        authenticate_envelope,
    },
};
use registration_credentials::{
    ballot_authentication::ENVELOPE_BYTES,
    close_signing::{
        CloseProposalMessage, ClosePurpose, MAXIMUM_LISTED_ENVELOPES_PER_SLOT,
        maximum_close_message_bytes,
    },
};
use std::cell::RefCell;

/// Public close verification for one browser instance. Every listed envelope
/// passes the owning envelope authentication before a response that lists it
/// is authenticated; only the bodies of the proposal's usable slots stream
/// through body authentication.
struct Session {
    input: Vec<u8>,
    context: Option<CloseContext>,
    intent: Option<AuthenticatedCloseIntent>,
    envelopes: Vec<AuthenticatedBallotEnvelope>,
    pending_body: Option<BallotBodyAuthentication>,
    bodies: Vec<AuthenticatedBallotBody>,
    responses: Vec<AuthenticatedCloseResponse>,
    missing: Vec<u8>,
    barrier: Option<VerifiedCloseBarrier>,
}
impl Session {
    fn new() -> Self {
        Self {
            input: vec![0; 1 << 20],
            context: None,
            intent: None,
            envelopes: Vec::new(),
            pending_body: None,
            bodies: Vec::new(),
            responses: Vec::new(),
            missing: Vec::new(),
            barrier: None,
        }
    }
    fn command(&mut self, operation: u32, length: usize) -> Result<(), ()> {
        if operation == 1 {
            if length != 0 {
                return Err(());
            }
            let (poll, setup) = setup_aggregate::setup_browser::context().ok_or(())?;
            *self = Self {
                input: std::mem::take(&mut self.input),
                context: Some(CloseContext::new(poll, setup).map_err(|_| ())?),
                ..Self::new()
            };
            return Ok(());
        }
        if self.barrier.is_some() {
            return Err(());
        }
        let context = self.context.as_ref().ok_or(())?;
        let count = context.participant_count();
        let bytes = self.input.get(..length).ok_or(())?;
        match operation {
            2 => {
                if self.intent.is_some() {
                    return Err(());
                }
                let (body, signature) = packet(
                    bytes,
                    maximum_close_message_bytes(ClosePurpose::Intent, count),
                )?;
                self.intent = Some(
                    context
                        .authenticate_intent(body, signature)
                        .map_err(|_| ())?,
                );
            }
            // A listed envelope and its signature. The stored responses list
            // at most two envelopes for each slot.
            3 => {
                if self.envelopes.len() >= MAXIMUM_LISTED_ENVELOPES_PER_SLOT * count * count
                    || bytes.len() != ENVELOPE_BYTES + 3309
                {
                    return Err(());
                }
                let authentication = authenticate_envelope(
                    context.setup(),
                    &bytes[..ENVELOPE_BYTES],
                    &bytes[ENVELOPE_BYTES..],
                )
                .map_err(|_| ())?;
                let identity = authentication.envelope().identity();
                if !self
                    .envelopes
                    .iter()
                    .any(|value| value.envelope().identity() == identity)
                {
                    self.envelopes.push(authentication);
                }
            }
            // Begins the complete body of an authenticated envelope, named by
            // its identity.
            4 => {
                if self.pending_body.is_some() || self.bodies.len() >= count {
                    return Err(());
                }
                let authentication = self
                    .envelopes
                    .iter()
                    .find(|value| value.envelope().identity().as_slice() == bytes)
                    .ok_or(())?;
                self.pending_body =
                    Some(BallotBodyAuthentication::new(authentication.clone()).map_err(|_| ())?);
            }
            5 => {
                if self.pending_body.as_mut().ok_or(())?.push(bytes).is_err() {
                    self.pending_body = None;
                    return Err(());
                }
            }
            6 => {
                if !bytes.is_empty() {
                    return Err(());
                }
                let body = self
                    .pending_body
                    .take()
                    .ok_or(())?
                    .finish()
                    .map_err(|_| ())?;
                let identity = body.authentication().envelope().identity();
                if !self
                    .bodies
                    .iter()
                    .any(|value| value.authentication().envelope().identity() == identity)
                {
                    self.bodies.push(body);
                }
            }
            7 => {
                if self.responses.len() >= count {
                    return Err(());
                }
                let (body, signature) = packet(
                    bytes,
                    maximum_close_message_bytes(ClosePurpose::Response, count),
                )?;
                let response = context
                    .authenticate_response(
                        self.intent.as_ref().ok_or(())?,
                        body,
                        signature,
                        &self.envelopes,
                    )
                    .map_err(|_| ())?;
                // One response per signer; a duplicate never replaces the first.
                if self
                    .responses
                    .iter()
                    .any(|value| value.message().responder() == response.message().responder())
                {
                    return Err(());
                }
                self.responses.push(response);
            }
            // The usable-slot bodies a proposal still needs, before its
            // signature is checked. This creates no barrier.
            8 => {
                let (body, _) = packet(
                    bytes,
                    maximum_close_message_bytes(ClosePurpose::Proposal, count),
                )?;
                let proposal = CloseProposalMessage::parse(body, count, context.organizer())
                    .map_err(|_| ())?;
                let required = context
                    .required_bodies(self.intent.as_ref().ok_or(())?, &proposal, &self.responses)
                    .map_err(|_| ())?;
                self.missing = required
                    .into_iter()
                    .filter(|(_, identity)| {
                        !self
                            .bodies
                            .iter()
                            .any(|value| value.authentication().envelope().identity() == *identity)
                    })
                    .flat_map(|(_, identity)| identity)
                    .collect();
            }
            9 => {
                let (body, signature) = packet(
                    bytes,
                    maximum_close_message_bytes(ClosePurpose::Proposal, count),
                )?;
                self.barrier = Some(
                    context
                        .verify_proposal(
                            self.intent.clone().ok_or(())?,
                            body,
                            signature,
                            &self.responses,
                            &self.bodies,
                        )
                        .map_err(|_| ())?,
                );
            }
            10 => {
                if !bytes.is_empty() {
                    return Err(());
                }
                self.pending_body = None;
            }
            _ => return Err(()),
        }
        Ok(())
    }
}
fn packet(bytes: &[u8], maximum: usize) -> Result<(&[u8], &[u8]), ()> {
    let length = u32::from_le_bytes(bytes.get(..4).ok_or(())?.try_into().map_err(|_| ())?) as usize;
    if length > maximum || bytes.len() != 4 + length + 3309 {
        return Err(());
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session::new()); }
#[unsafe(no_mangle)]
pub extern "C" fn close_input_pointer() -> usize {
    SESSION.with(|session| session.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn close_command(operation: u32, length: usize) -> u32 {
    SESSION.with(|session| u32::from(session.borrow_mut().command(operation, length).is_err()))
}
#[unsafe(no_mangle)]
pub extern "C" fn close_envelope_count() -> usize {
    SESSION.with(|session| session.borrow().envelopes.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn close_body_count() -> usize {
    SESSION.with(|session| session.borrow().bodies.len())
}
/// Consecutive 64-byte envelope identities of the missing usable-slot bodies.
#[unsafe(no_mangle)]
pub extern "C" fn close_missing_pointer() -> usize {
    SESSION.with(|session| session.borrow().missing.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn close_missing_count() -> usize {
    SESSION.with(|session| session.borrow().missing.len() / 64)
}
#[unsafe(no_mangle)]
pub extern "C" fn close_response_count() -> usize {
    SESSION.with(|session| session.borrow().responses.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn close_proposal_identity_pointer() -> usize {
    SESSION.with(|session| {
        session
            .borrow()
            .barrier
            .as_ref()
            .map_or(0, |barrier| barrier.proposal().identity().as_ptr() as usize)
    })
}

pub(super) fn take_barrier() -> Option<VerifiedCloseBarrier> {
    SESSION.with(|session| session.borrow_mut().barrier.take())
}
