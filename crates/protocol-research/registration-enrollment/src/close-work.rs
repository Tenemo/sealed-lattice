use ballot_proof::{
    close::{AuthenticatedCloseIntent, AuthenticatedCloseResponse, CloseContext, usable_entries},
    submission::{
        AuthenticatedBallotBody, AuthenticatedBallotEnvelope, BallotBodyAuthentication,
        authenticate_envelope,
    },
};
use registration_credentials::{
    Credential, Error,
    ballot_authentication::{BallotEnvelope, ENVELOPE_BYTES, RetainedBallotOwner},
    close_signing::{
        CloseIntentMessage, CloseMessage, CloseProposalMessage, ClosePurpose, CloseResponseMessage,
        MAXIMUM_LISTED_ENVELOPES_PER_SLOT, close_quorum, maximum_close_message_bytes,
    },
    poll::VerifiedPoll,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

enum Prepared {
    Intent(CloseIntentMessage),
    Response(CloseResponseMessage),
    Proposal(CloseProposalMessage),
}
impl Prepared {
    fn body(&self) -> &[u8] {
        match self {
            Self::Intent(message) => message.body(),
            Self::Response(message) => message.body(),
            Self::Proposal(message) => message.body(),
        }
    }
}

/// Original-key close signing beneath the authenticated browser root. Public
/// inputs pass the owning intent, envelope, body, and response verifiers first;
/// the root persists each lock and prepared body before signing. `held` are the
/// complete bodies this participant may list, at most two for one slot;
/// `envelopes` also include known envelopes whose bodies it does not hold.
/// The organizer signs its own response only when it can propose, so its
/// listing makes every slot with two known envelopes conflicting.
pub struct CloseWork {
    owner: Arc<RetainedBallotOwner>,
    context: CloseContext,
    intent: Option<AuthenticatedCloseIntent>,
    pending: Option<BallotBodyAuthentication>,
    held: Vec<AuthenticatedBallotBody>,
    envelopes: Vec<AuthenticatedBallotEnvelope>,
    responses: Vec<AuthenticatedCloseResponse>,
    prepared: Option<Prepared>,
}

fn packet(bytes: &[u8], maximum: usize) -> Result<(&[u8], &[u8]), Error> {
    let length =
        u32::from_le_bytes(bytes.get(..4).ok_or(Error::Shape)?.try_into().unwrap()) as usize;
    if length > maximum || bytes.len() != 4 + length + 3309 {
        return Err(Error::Shape);
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}
impl CloseWork {
    pub fn new(
        owner: RetainedBallotOwner,
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
    ) -> Result<Self, Error> {
        let proposal = setup.inventory().proposal().proposal();
        if owner.poll() != &poll.identity()
            || owner.runtime() != &poll.runtime()
            || owner.inventory() != &setup.inventory().identity()
            || owner.position() >= proposal.records().len()
        {
            return Err(Error::Context);
        }
        Ok(Self {
            owner: Arc::new(owner),
            context: CloseContext::new(poll, setup).map_err(|_| Error::Context)?,
            intent: None,
            pending: None,
            held: Vec::new(),
            envelopes: Vec::new(),
            responses: Vec::new(),
            prepared: None,
        })
    }
    pub fn owner(&self) -> Arc<RetainedBallotOwner> {
        self.owner.clone()
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn setup(&self) -> &Arc<VerifiedSetupAggregate> {
        self.context.setup()
    }
    pub fn restore_target(
        &self,
        credential: &mut Credential,
        body: &[u8],
        packet: &[u8],
    ) -> Result<(), Error> {
        let message = registration_credentials::target_signing::TargetMessage::parse(
            body,
            self.context.participant_count(),
        )?;
        credential.restore_target(
            &self.owner,
            self.context.setup().inventory().proposal(),
            &message,
            packet,
        )
    }
    fn count(&self) -> usize {
        self.context.participant_count()
    }
    fn roster(&self) -> &registration_credentials::roster_authentication::OrganizerSignedRoster {
        self.context.setup().inventory().proposal()
    }
    fn remember(&mut self, authentication: &AuthenticatedBallotEnvelope) -> Result<(), Error> {
        let identity = authentication.envelope().identity();
        if self
            .envelopes
            .iter()
            .any(|value| value.envelope().identity() == identity)
        {
            return Ok(());
        }
        // Retained responses list at most two envelopes for each slot.
        if self.envelopes.len() >= MAXIMUM_LISTED_ENVELOPES_PER_SLOT * self.count() * self.count() {
            return Err(Error::Shape);
        }
        self.envelopes.push(authentication.clone());
        Ok(())
    }
    fn is_organizer(&self) -> bool {
        self.owner.position() == self.context.organizer()
    }
    pub fn command(
        &mut self,
        credential: &mut Credential,
        operation: u32,
        argument: usize,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if input.len() > 1 << 20 || (operation != 10 && argument != 0) {
            return Err(Error::Shape);
        }
        let ready = self.prepared.is_none() && self.pending.is_none();
        match operation {
            // The organizer's close intent. Input is the close time.
            1 => {
                if !ready || self.intent.is_some() {
                    return Err(Error::Consumed);
                }
                let time = u64::from_le_bytes(input.try_into().map_err(|_| Error::Shape)?);
                let message = self.context.intent(time).map_err(|_| Error::Context)?;
                let body = message.body().to_vec();
                self.prepared = Some(Prepared::Intent(message));
                Ok(body)
            }
            // Authenticates and locks the first close intent. The root persists
            // that lock before any response is prepared. Held bodies timed
            // after the close time can never be listed or needed, so the lock
            // discards them and frees their slots.
            2 => {
                if !ready || self.intent.is_some() {
                    return Err(Error::Consumed);
                }
                let (body, signature) = packet(
                    input,
                    maximum_close_message_bytes(ClosePurpose::Intent, self.count()),
                )?;
                let intent = self
                    .context
                    .authenticate_intent(body, signature)
                    .map_err(|_| Error::Crypto)?;
                credential.lock_close_intent(
                    &self.owner,
                    self.roster(),
                    intent.message(),
                    signature,
                )?;
                let close_time = intent.message().close_time();
                self.held
                    .retain(|body| body.authentication().envelope().ballot_time() <= close_time);
                self.intent = Some(intent);
                Ok(Vec::new())
            }
            // A held envelope and its complete body, including this
            // participant's own ballot. A response lists at most two envelopes
            // for one slot, so a third body for a slot, which only a corrupt
            // author can sign, is refused before it is transferred, as is a
            // body timed after a locked close time.
            3 => {
                if !ready || input.len() != ENVELOPE_BYTES + 3309 {
                    return Err(Error::Shape);
                }
                let authentication = authenticate_envelope(
                    self.context.setup(),
                    &input[..ENVELOPE_BYTES],
                    &input[ENVELOPE_BYTES..],
                )
                .map_err(|_| Error::Crypto)?;
                let envelope = authentication.envelope();
                if self
                    .intent
                    .as_ref()
                    .is_some_and(|intent| envelope.ballot_time() > intent.message().close_time())
                {
                    return Err(Error::Context);
                }
                let slot = self.held.iter().filter(|value| {
                    value.authentication().envelope().position() == envelope.position()
                });
                if slot.clone().count() >= MAXIMUM_LISTED_ENVELOPES_PER_SLOT
                    || slot.into_iter().any(|value| {
                        value.authentication().envelope().identity() == envelope.identity()
                    })
                {
                    return Err(Error::Consumed);
                }
                self.pending =
                    Some(BallotBodyAuthentication::new(authentication).map_err(|_| Error::Shape)?);
                Ok(Vec::new())
            }
            4 => {
                if self
                    .pending
                    .as_mut()
                    .ok_or(Error::Context)?
                    .push(input)
                    .is_err()
                {
                    self.pending = None;
                    return Err(Error::Crypto);
                }
                Ok(Vec::new())
            }
            5 => {
                if !input.is_empty() {
                    return Err(Error::Shape);
                }
                let body = self
                    .pending
                    .take()
                    .ok_or(Error::Context)?
                    .finish()
                    .map_err(|_| Error::Crypto)?;
                self.remember(body.authentication())?;
                self.held.push(body);
                Ok(Vec::new())
            }
            // This participant's response under the honest listing rule. Any
            // other participant responds without waiting; the organizer only
            // once `q-1` other responses are ready, so every response it has
            // not yet authenticated is unnecessary to its proposal.
            6 => {
                if !ready || !input.is_empty() {
                    return Err(Error::Consumed);
                }
                let intent = self.intent.as_ref().ok_or(Error::Context)?;
                if self.is_organizer()
                    && self
                        .responses
                        .iter()
                        .filter(|response| {
                            response.message().responder() != self.owner.position()
                                && self.context.organizer_ready(
                                    intent,
                                    &self.envelopes,
                                    &self.held,
                                    response,
                                )
                        })
                        .count()
                        < close_quorum(self.count()) - 1
                {
                    return Err(Error::Context);
                }
                let message = self
                    .context
                    .response(intent, self.owner.position(), &self.envelopes, &self.held)
                    .map_err(|_| Error::Context)?;
                let body = message.body().to_vec();
                self.prepared = Some(Prepared::Response(message));
                Ok(body)
            }
            // A response to the locked intent, for the organizer's proposal.
            7 => {
                if !ready {
                    return Err(Error::Consumed);
                }
                let (body, signature) = packet(
                    input,
                    maximum_close_message_bytes(ClosePurpose::Response, self.count()),
                )?;
                let response = self
                    .context
                    .authenticate_response(
                        self.intent.as_ref().ok_or(Error::Context)?,
                        body,
                        signature,
                        &self.envelopes,
                    )
                    .map_err(|_| Error::Crypto)?;
                if !self
                    .responses
                    .iter()
                    .any(|value| value.message().responder() == response.message().responder())
                {
                    self.responses.push(response);
                }
                Ok(Vec::new())
            }
            // Signing is reachable only after the root commits this body and
            // its exact coins. One request consumes the prepared body; the
            // credential consumes its purpose before signing.
            8 => {
                if input.len() < 32 {
                    return Err(Error::Shape);
                }
                if input[..input.len() - 32]
                    != *self.prepared.as_ref().ok_or(Error::Context)?.body()
                {
                    return Err(Error::Context);
                }
                let prepared = self.prepared.take().ok_or(Error::Context)?;
                let coins = input[input.len() - 32..].try_into().unwrap();
                let roster = self.context.setup().inventory().proposal();
                let signature = match &prepared {
                    Prepared::Intent(message) => {
                        credential.sign_close_intent(&self.owner, roster, message, coins)?
                    }
                    Prepared::Response(message) => {
                        credential.sign_close_response(&self.owner, roster, message, coins)?
                    }
                    Prepared::Proposal(message) => {
                        credential.sign_close_proposal(&self.owner, roster, message, coins)?
                    }
                };
                Ok(signature.to_vec())
            }
            // The organizer's proposal: its own response and the first `q-1`
            // other authenticated responses to its intent, in arrival order,
            // that keep every usable slot's body held.
            9 => {
                if !ready || !input.is_empty() {
                    return Err(Error::Consumed);
                }
                let organizer = self.owner.position();
                let own = self
                    .responses
                    .iter()
                    .find(|response| response.message().responder() == organizer)
                    .ok_or(Error::Context)?;
                // A response joins only while every usable slot of the
                // selection has a held body, so a response listing a body no
                // one supplies cannot stall the proposal.
                let holds = |selection: &[&AuthenticatedCloseResponse]| {
                    usable_entries(self.count(), selection)
                        .iter()
                        .all(|(_, identity)| {
                            self.held.iter().any(|value| {
                                value.authentication().envelope().identity() == *identity
                            })
                        })
                };
                let mut selected = vec![own];
                if !holds(&selected) {
                    return Err(Error::Context);
                }
                for response in &self.responses {
                    if selected.len() == close_quorum(self.count()) {
                        break;
                    }
                    if response.message().responder() == organizer {
                        continue;
                    }
                    selected.push(response);
                    if !holds(&selected) {
                        selected.pop();
                    }
                }
                let selected: Vec<_> = selected.into_iter().cloned().collect();
                let intent = self.intent.as_ref().ok_or(Error::Context)?;
                let message = self
                    .context
                    .proposal(intent, &selected)
                    .map_err(|_| Error::Context)?;
                let body = message.body().to_vec();
                self.prepared = Some(Prepared::Proposal(message));
                Ok(body)
            }
            // Restores a completed close message: 0 intent, 1 response,
            // 2 proposal. A response requires its intent to be locked first.
            10 => {
                if !ready {
                    return Err(Error::Consumed);
                }
                let count = self.count();
                let organizer = self.context.organizer();
                let roster = self.context.setup().inventory().proposal();
                match argument {
                    0 => {
                        let (body, signature) = packet(
                            input,
                            maximum_close_message_bytes(ClosePurpose::Intent, count),
                        )?;
                        let message = CloseIntentMessage::parse(body)?;
                        credential.restore_close_message(
                            &self.owner,
                            roster,
                            CloseMessage::Intent(&message),
                            signature,
                        )
                    }
                    1 => {
                        let (body, signature) = packet(
                            input,
                            maximum_close_message_bytes(ClosePurpose::Response, count),
                        )?;
                        let message = CloseResponseMessage::parse(body, count)?;
                        credential.restore_close_message(
                            &self.owner,
                            roster,
                            CloseMessage::Response(&message),
                            signature,
                        )
                    }
                    2 => {
                        let (body, signature) = packet(
                            input,
                            maximum_close_message_bytes(ClosePurpose::Proposal, count),
                        )?;
                        let message = CloseProposalMessage::parse(body, count, organizer)?;
                        credential.restore_close_message(
                            &self.owner,
                            roster,
                            CloseMessage::Proposal(&message),
                            signature,
                        )
                    }
                    _ => Err(Error::Shape),
                }?;
                Ok(Vec::new())
            }
            // Restores the spent ballot purpose before close work. This
            // requires the original completed local envelope and signature.
            11 => {
                if input.len() != ENVELOPE_BYTES + 3309 {
                    return Err(Error::Shape);
                }
                let envelope = BallotEnvelope::decode(&input[..ENVELOPE_BYTES])?;
                credential.restore_retained_ballot_signing(
                    &self.owner,
                    &envelope,
                    &input[ENVELOPE_BYTES..],
                )?;
                Ok(Vec::new())
            }
            // A known envelope whose body this participant does not hold. It
            // authenticates another participant's response, and a second known
            // on-time envelope for a slot lets the honest listing name both.
            12 => {
                if !ready || input.len() != ENVELOPE_BYTES + 3309 {
                    return Err(Error::Shape);
                }
                let authentication = authenticate_envelope(
                    self.context.setup(),
                    &input[..ENVELOPE_BYTES],
                    &input[ENVELOPE_BYTES..],
                )
                .map_err(|_| Error::Crypto)?;
                self.remember(&authentication)?;
                Ok(Vec::new())
            }
            // The bodies the organizer still needs, as consecutive two-byte
            // author positions and envelope identities: at most one per slot,
            // each listed by an authenticated response.
            13 => {
                if !input.is_empty() || !self.is_organizer() {
                    return Err(Error::Shape);
                }
                let intent = self.intent.as_ref().ok_or(Error::Context)?;
                Ok(self
                    .context
                    .organizer_wanted(intent, &self.envelopes, &self.held, &self.responses)
                    .into_iter()
                    .flat_map(|(author, identity)| {
                        (author as u16).to_le_bytes().into_iter().chain(identity)
                    })
                    .collect())
            }
            _ => Err(Error::Shape),
        }
    }
}
