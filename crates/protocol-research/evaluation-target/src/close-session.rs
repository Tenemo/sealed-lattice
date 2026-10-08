use crate::close::{
    AuthenticatedCloseIntent, AuthenticatedCloseResponse, CloseContext, VerifiedCloseBarrier,
};
use ballot_proof::submission::{
    AuthenticatedBallotBody, AuthenticatedBallotEnvelope, BallotBodyAuthentication,
    authenticate_envelope,
};
use protocol_foundations::poll::VerifiedPoll;
use protocol_foundations::{
    SIGNATURE_BYTES,
    ballot_authentication::ENVELOPE_BYTES,
    close_signing::{
        CloseProposalMessage, ClosePurpose, MAXIMUM_LISTED_ENVELOPES_PER_SLOT,
        maximum_close_message_bytes,
    },
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

/// The input buffer's length; the host never writes more.
pub const CLOSE_INPUT_BYTES: usize = 1 << 20;
/// A refused close operation.
#[derive(Debug)]
pub struct Refused;
/// Public close verification for one instance. Every listed envelope
/// passes the owning envelope authentication before a response that lists it
/// is authenticated; only the bodies of the proposal's usable slots stream
/// through body authentication.
pub struct CloseSession {
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
impl CloseSession {
    pub fn new() -> Self {
        Self::with_input(vec![0; CLOSE_INPUT_BYTES])
    }
    pub fn input(&mut self) -> &mut [u8] {
        &mut self.input
    }
    /// Consecutive 64-byte envelope identities of the missing usable-slot
    /// bodies.
    pub fn missing(&self) -> &[u8] {
        &self.missing
    }
    pub fn take_barrier(&mut self) -> Option<VerifiedCloseBarrier> {
        self.barrier.take()
    }
    // A session that keeps the host's input buffer.
    fn with_input(input: Vec<u8>) -> Self {
        Self {
            input,
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
    /// Runs a close operation. The first one takes the instance's verified
    /// setup, which `setup` reads.
    pub fn command(
        &mut self,
        setup: impl FnOnce() -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)>,
        operation: u32,
        length: usize,
    ) -> Result<(), Refused> {
        if operation == 1 {
            if length != 0 {
                return Err(Refused);
            }
            let (poll, setup) = setup().ok_or(Refused)?;
            let context = CloseContext::new(poll, setup).map_err(|_| Refused)?;
            *self = Self {
                context: Some(context),
                ..Self::with_input(std::mem::take(&mut self.input))
            };
            return Ok(());
        }
        if self.barrier.is_some() {
            return Err(Refused);
        }
        let context = self.context.as_ref().ok_or(Refused)?;
        let count = context.participant_count();
        let bytes = self.input.get(..length).ok_or(Refused)?;
        match operation {
            2 => {
                if self.intent.is_some() {
                    return Err(Refused);
                }
                let (body, signature) = packet(
                    bytes,
                    maximum_close_message_bytes(ClosePurpose::Intent, count),
                )?;
                self.intent = Some(
                    context
                        .authenticate_intent(body, signature)
                        .map_err(|_| Refused)?,
                );
            }
            // A listed envelope and its signature. The stored responses list
            // at most two envelopes for each slot.
            3 => {
                if self.envelopes.len() >= MAXIMUM_LISTED_ENVELOPES_PER_SLOT * count * count
                    || bytes.len() != ENVELOPE_BYTES + SIGNATURE_BYTES
                {
                    return Err(Refused);
                }
                let authentication = authenticate_envelope(
                    context.setup(),
                    &bytes[..ENVELOPE_BYTES],
                    &bytes[ENVELOPE_BYTES..],
                )
                .map_err(|_| Refused)?;
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
                    return Err(Refused);
                }
                let authentication = self
                    .envelopes
                    .iter()
                    .find(|value| value.envelope().identity().as_slice() == bytes)
                    .ok_or(Refused)?;
                self.pending_body = Some(
                    BallotBodyAuthentication::new(authentication.clone()).map_err(|_| Refused)?,
                );
            }
            5 => {
                if self
                    .pending_body
                    .as_mut()
                    .ok_or(Refused)?
                    .push(bytes)
                    .is_err()
                {
                    self.pending_body = None;
                    return Err(Refused);
                }
            }
            6 => {
                if !bytes.is_empty() {
                    return Err(Refused);
                }
                let body = self
                    .pending_body
                    .take()
                    .ok_or(Refused)?
                    .finish()
                    .map_err(|_| Refused)?;
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
                    return Err(Refused);
                }
                let (body, signature) = packet(
                    bytes,
                    maximum_close_message_bytes(ClosePurpose::Response, count),
                )?;
                let response = context
                    .authenticate_response(
                        self.intent.as_ref().ok_or(Refused)?,
                        body,
                        signature,
                        &self.envelopes,
                    )
                    .map_err(|_| Refused)?;
                // One response per signer; a duplicate never replaces the first.
                if self
                    .responses
                    .iter()
                    .any(|value| value.message().responder() == response.message().responder())
                {
                    return Err(Refused);
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
                    .map_err(|_| Refused)?;
                let required = context
                    .required_bodies(
                        self.intent.as_ref().ok_or(Refused)?,
                        &proposal,
                        &self.responses,
                    )
                    .map_err(|_| Refused)?;
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
                            self.intent.clone().ok_or(Refused)?,
                            body,
                            signature,
                            &self.responses,
                            &self.bodies,
                        )
                        .map_err(|_| Refused)?,
                );
            }
            10 => {
                if !bytes.is_empty() {
                    return Err(Refused);
                }
                self.pending_body = None;
            }
            _ => return Err(Refused),
        }
        Ok(())
    }
}
fn packet(bytes: &[u8], maximum: usize) -> Result<(&[u8], &[u8]), Refused> {
    let length = u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or(Refused)?
            .try_into()
            .map_err(|_| Refused)?,
    ) as usize;
    if length > maximum || bytes.len() != 4 + length + SIGNATURE_BYTES {
        return Err(Refused);
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}
impl Default for CloseSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "close-session-tests.rs"]
mod tests;
