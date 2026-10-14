use ballot_proof::submission::{
    AuthenticatedBallotBody, AuthenticatedBallotEnvelope, BallotBodyAuthentication,
    authenticate_envelope,
};
use evaluation_target::close::{
    AuthenticatedCloseIntent, AuthenticatedCloseResponse, CloseContext, usable_entries,
};
use protocol_foundations::{
    Credential, Refusal, SIGNATURE_BYTES,
    ballot_authentication::{BallotEnvelope, ENVELOPE_BYTES, RetainedSetupOwner},
    close_signing::{
        CloseIntentMessage, CloseMessage, CloseProposalMessage, ClosePurpose, CloseResponseMessage,
        MAXIMUM_LISTED_ENVELOPES_PER_SLOT, maximum_close_message_bytes,
    },
    poll::VerifiedPoll,
    signed_packet,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;
use supported_profile::inventory_threshold;

protocol_foundations::operation_codes! {
    /// The close commands; the participant session begins the close work,
    /// and the work runs every other command.
    pub enum CloseOperation {
        Begin = 0,
        PrepareIntent = 1,
        LockIntent = 2,
        BeginHeldBody = 3,
        PushHeldBody = 4,
        FinishHeldBody = 5,
        PrepareResponse = 6,
        AdmitResponse = 7,
        Sign = 8,
        PrepareProposal = 9,
        RestoreMessage = 10,
        RestoreBallotSigning = 11,
        DiscardHeldBody = 12,
        WantedBodies = 13,
        EnvelopeIdentity = 14,
    }
}
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
///
/// Delivery adds a new envelope to a slot only while fewer than two are
/// known, since a response lists at most two. The organizer also learns the
/// envelopes listed by the first authenticated response of each responder,
/// and no other participant takes responses. A relay therefore cannot grow
/// the retained set beyond two envelopes per slot and per retained response,
/// and the intent lock discards late envelopes.
///
/// Every accepted delivery changes the state: an already held body, an already
/// known envelope supplied with a response and a later response of a
/// responder are refused. A persistent log of accepted inputs therefore stays
/// within these bounds.
pub struct CloseWork {
    owner: Arc<RetainedSetupOwner>,
    context: CloseContext,
    intent: Option<AuthenticatedCloseIntent>,
    pending: Option<BallotBodyAuthentication>,
    held: Vec<AuthenticatedBallotBody>,
    envelopes: Vec<AuthenticatedBallotEnvelope>,
    responses: Vec<AuthenticatedCloseResponse>,
    prepared: Option<Prepared>,
}

/// A signed packet filling the bytes.
fn packet(bytes: &[u8], maximum: usize) -> Result<(&[u8], &[u8]), Refusal> {
    signed_packet::split(bytes, maximum).ok_or(Refusal::Shape)
}
impl CloseWork {
    pub fn new(
        owner: RetainedSetupOwner,
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
    ) -> Result<Self, Refusal> {
        let proposal = setup.roster().proposal();
        if owner.poll() != &poll.identity()
            || owner.setup_identity() != &setup.identity()
            || owner.position() >= proposal.records().len()
        {
            return Err(Refusal::Context);
        }
        Ok(Self {
            owner: Arc::new(owner),
            context: CloseContext::new(poll, setup).map_err(|_| Refusal::Context)?,
            intent: None,
            pending: None,
            held: Vec::new(),
            envelopes: Vec::new(),
            responses: Vec::new(),
            prepared: None,
        })
    }
    pub fn owner(&self) -> Arc<RetainedSetupOwner> {
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
    ) -> Result<(), Refusal> {
        let message = protocol_foundations::target_signing::TargetMessage::parse(
            body,
            self.context.participant_count(),
        )?;
        credential.restore_target(&self.owner, self.context.setup().roster(), &message, packet)
    }
    /// The own ballot's status in a certified target that this participant
    /// did not sign, from the target's classification of its slot and the
    /// locked close time.
    pub fn released_ballot_inclusion(
        &self,
        credential: &Credential,
        body: &[u8],
    ) -> Result<crate::finality_work::OwnBallotInclusion, Refusal> {
        let message =
            protocol_foundations::target_signing::TargetMessage::parse(body, self.count())?;
        let intent = self.intent.as_ref().ok_or(Refusal::Context)?;
        if message.poll() != self.owner.poll()
            || message.setup_identity() != self.owner.setup_identity()
        {
            return Err(Refusal::Context);
        }
        Ok(crate::finality_work::classified_ballot_inclusion(
            credential.signed_ballot().map(|(_, time)| *time),
            intent.message().close_time(),
            message.classification(self.owner.position()),
        ))
    }
    fn count(&self) -> usize {
        self.context.participant_count()
    }
    fn roster(&self) -> &protocol_foundations::roster_authentication::AuthenticatedRosterProposal {
        self.context.setup().roster()
    }
    fn known(&self, identity: &[u8; 64]) -> bool {
        self.envelopes
            .iter()
            .any(|value| value.envelope().identity() == *identity)
    }
    /// Refuses a delivered envelope that no response could need: a late one
    /// once the intent is locked, or a new one for a slot that already has two
    /// known envelopes.
    fn admit(&self, authentication: &AuthenticatedBallotEnvelope) -> Result<(), Refusal> {
        let envelope = authentication.envelope();
        if self
            .intent
            .as_ref()
            .is_some_and(|intent| envelope.ballot_time() > intent.message().close_time())
        {
            return Err(Refusal::Context);
        }
        if !self.known(&envelope.identity())
            && self
                .envelopes
                .iter()
                .filter(|value| value.envelope().position() == envelope.position())
                .count()
                >= MAXIMUM_LISTED_ENVELOPES_PER_SLOT
        {
            return Err(Refusal::Consumed);
        }
        Ok(())
    }
    fn remember(&mut self, authentication: &AuthenticatedBallotEnvelope) {
        if !self.known(&authentication.envelope().identity()) {
            self.envelopes.push(authentication.clone());
        }
    }
    fn is_organizer(&self) -> bool {
        self.owner.position() == self.context.organizer()
    }
    pub fn command(
        &mut self,
        credential: &mut Credential,
        operation: CloseOperation,
        argument: usize,
        input: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        if input.len() > 1 << 20 || (operation != CloseOperation::RestoreMessage && argument != 0) {
            return Err(Refusal::Shape);
        }
        match operation {
            CloseOperation::Begin => Err(Refusal::Shape),
            CloseOperation::PrepareIntent => self.prepare_intent(input),
            CloseOperation::LockIntent => self.lock_intent(credential, input),
            CloseOperation::BeginHeldBody => self.begin_held_body(input),
            CloseOperation::PushHeldBody => self.push_held_body(input),
            CloseOperation::FinishHeldBody => self.finish_held_body(input),
            CloseOperation::PrepareResponse => self.prepare_response(input),
            CloseOperation::AdmitResponse => self.admit_response(input),
            CloseOperation::Sign => self.sign(credential, input),
            CloseOperation::PrepareProposal => self.prepare_proposal(input),
            CloseOperation::RestoreMessage => self.restore_message(credential, argument, input),
            CloseOperation::RestoreBallotSigning => self.restore_ballot_signing(credential, input),
            CloseOperation::DiscardHeldBody => self.discard_held_body(input),
            CloseOperation::WantedBodies => self.wanted_bodies(input),
            CloseOperation::EnvelopeIdentity => self.envelope_identity(input),
        }
    }
    // Whether no prepared message or tentative body is outstanding.
    fn ready(&self) -> bool {
        self.prepared.is_none() && self.pending.is_none()
    }
    /// The organizer's close intent. Input is the close time.
    fn prepare_intent(&mut self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !self.ready() || self.intent.is_some() {
            return Err(Refusal::Consumed);
        }
        let time = u64::from_le_bytes(input.try_into().map_err(|_| Refusal::Shape)?);
        let message = self.context.intent(time).map_err(|_| Refusal::Context)?;
        let body = message.body().to_vec();
        self.prepared = Some(Prepared::Intent(message));
        Ok(body)
    }
    /// Authenticates and locks the first close intent. The root persists
    /// that lock before any response is prepared. Held bodies and known
    /// envelopes timed after the close time can never be listed or
    /// needed, so the lock discards them and frees their slots.
    fn lock_intent(
        &mut self,
        credential: &mut Credential,
        input: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        if !self.ready() || self.intent.is_some() {
            return Err(Refusal::Consumed);
        }
        let (body, signature) = packet(
            input,
            maximum_close_message_bytes(ClosePurpose::Intent, self.count()),
        )?;
        let intent = self
            .context
            .authenticate_intent(body, signature)
            .map_err(|_| Refusal::Crypto)?;
        credential.lock_close_intent(&self.owner, self.roster(), intent.message(), signature)?;
        let close_time = intent.message().close_time();
        self.held
            .retain(|body| body.authentication().envelope().ballot_time() <= close_time);
        self.envelopes
            .retain(|value| value.envelope().ballot_time() <= close_time);
        self.intent = Some(intent);
        Ok(Vec::new())
    }
    /// A held envelope and its complete body, including this
    /// participant's own ballot. A response lists at most two envelopes
    /// for one slot, so a third body for a slot, which only a corrupt
    /// author can sign, is refused before it is transferred, as is a
    /// body timed after a locked close time or a new envelope for a
    /// slot with two known ones.
    fn begin_held_body(&mut self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !self.ready() || input.len() != ENVELOPE_BYTES + SIGNATURE_BYTES {
            return Err(Refusal::Shape);
        }
        let authentication = authenticate_envelope(
            self.context.setup(),
            &input[..ENVELOPE_BYTES],
            &input[ENVELOPE_BYTES..],
        )
        .map_err(|_| Refusal::Crypto)?;
        self.admit(&authentication)?;
        let envelope = authentication.envelope();
        let slot = self
            .held
            .iter()
            .filter(|value| value.authentication().envelope().position() == envelope.position());
        if slot.clone().count() >= MAXIMUM_LISTED_ENVELOPES_PER_SLOT
            || slot
                .into_iter()
                .any(|value| value.authentication().envelope().identity() == envelope.identity())
        {
            return Err(Refusal::Consumed);
        }
        self.pending =
            Some(BallotBodyAuthentication::new(authentication).map_err(|_| Refusal::Shape)?);
        Ok(Vec::new())
    }
    fn push_held_body(&mut self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if self
            .pending
            .as_mut()
            .ok_or(Refusal::Context)?
            .push(input)
            .is_err()
        {
            self.pending = None;
            return Err(Refusal::Crypto);
        }
        Ok(Vec::new())
    }
    fn finish_held_body(&mut self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !input.is_empty() {
            return Err(Refusal::Shape);
        }
        let body = self
            .pending
            .take()
            .ok_or(Refusal::Context)?
            .finish()
            .map_err(|_| Refusal::Crypto)?;
        self.remember(body.authentication());
        self.held.push(body);
        Ok(Vec::new())
    }
    /// This participant's response under the honest listing rule. Any
    /// other participant responds without waiting; the organizer only
    /// once `q-1` other responses are ready, so every response it has
    /// not yet authenticated is unnecessary to its proposal.
    fn prepare_response(&mut self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !self.ready() || !input.is_empty() {
            return Err(Refusal::Consumed);
        }
        let intent = self.intent.as_ref().ok_or(Refusal::Context)?;
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
                < inventory_threshold(self.count()) - 1
        {
            return Err(Refusal::Context);
        }
        let message = self
            .context
            .response(intent, self.owner.position(), &self.envelopes, &self.held)
            .map_err(|_| Refusal::Context)?;
        let body = message.body().to_vec();
        self.prepared = Some(Prepared::Response(message));
        Ok(body)
    }
    /// A response to the locked intent, for the organizer's proposal,
    /// followed by each envelope it lists that the organizer does not
    /// know, with its signature. Only the first response of a responder
    /// is retained, and its envelopes join the known set only once it
    /// authenticates; a later one is refused.
    fn admit_response(&mut self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !self.ready() {
            return Err(Refusal::Consumed);
        }
        if !self.is_organizer() {
            return Err(Refusal::Context);
        }
        let intent = self.intent.as_ref().ok_or(Refusal::Context)?;
        let maximum = maximum_close_message_bytes(ClosePurpose::Response, self.count());
        let (body, signature, rest) =
            signed_packet::leading(input, maximum).ok_or(Refusal::Shape)?;
        let submission = ENVELOPE_BYTES + SIGNATURE_BYTES;
        if !rest.len().is_multiple_of(submission) {
            return Err(Refusal::Shape);
        }
        let message = CloseResponseMessage::parse(body, self.count())?;
        if self
            .responses
            .iter()
            .any(|value| value.message().responder() == message.responder())
        {
            return Err(Refusal::Consumed);
        }
        let mut supplied: Vec<AuthenticatedBallotEnvelope> = Vec::new();
        for bytes in rest.chunks_exact(submission) {
            let authentication = authenticate_envelope(
                self.context.setup(),
                &bytes[..ENVELOPE_BYTES],
                &bytes[ENVELOPE_BYTES..],
            )
            .map_err(|_| Refusal::Crypto)?;
            let identity = authentication.envelope().identity();
            if self.known(&identity)
                || supplied
                    .iter()
                    .any(|value| value.envelope().identity() == identity)
                || !message
                    .listed()
                    .iter()
                    .any(|(_, listed)| *listed == identity)
            {
                return Err(Refusal::Context);
            }
            supplied.push(authentication);
        }
        let available: Vec<_> = self.envelopes.iter().chain(&supplied).cloned().collect();
        let response = self
            .context
            .authenticate_response(intent, body, signature, &available)
            .map_err(|_| Refusal::Crypto)?;
        for authentication in &supplied {
            self.remember(authentication);
        }
        self.responses.push(response);
        Ok(Vec::new())
    }
    /// Signing is reachable only after the root commits this exact
    /// body. One request consumes the prepared body; the
    /// credential consumes its purpose before signing.
    fn sign(&mut self, credential: &mut Credential, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if input != self.prepared.as_ref().ok_or(Refusal::Context)?.body() {
            return Err(Refusal::Context);
        }
        let prepared = self.prepared.take().ok_or(Refusal::Context)?;
        let roster = self.context.setup().roster();
        let signature = match &prepared {
            Prepared::Intent(message) => {
                credential.sign_close_intent(&self.owner, roster, message)?
            }
            Prepared::Response(message) => {
                credential.sign_close_response(&self.owner, roster, message)?
            }
            Prepared::Proposal(message) => {
                credential.sign_close_proposal(&self.owner, roster, message)?
            }
        };
        Ok(signature.to_vec())
    }
    /// The organizer's proposal: its own response and the first `q-1`
    /// other authenticated responses to its intent, in arrival order,
    /// that keep every usable slot's body held.
    fn prepare_proposal(&mut self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !self.ready() || !input.is_empty() {
            return Err(Refusal::Consumed);
        }
        let organizer = self.owner.position();
        let own = self
            .responses
            .iter()
            .find(|response| response.message().responder() == organizer)
            .ok_or(Refusal::Context)?;
        // A response joins only while every usable slot of the
        // selection has a held body, so a response listing a body no
        // one supplies cannot stall the proposal.
        let holds = |selection: &[&AuthenticatedCloseResponse]| {
            usable_entries(self.count(), selection)
                .iter()
                .all(|(_, identity)| {
                    self.held
                        .iter()
                        .any(|value| value.authentication().envelope().identity() == *identity)
                })
        };
        let mut selected = vec![own];
        if !holds(&selected) {
            return Err(Refusal::Context);
        }
        for response in &self.responses {
            if selected.len() == inventory_threshold(self.count()) {
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
        let intent = self.intent.as_ref().ok_or(Refusal::Context)?;
        let message = self
            .context
            .proposal(intent, &selected)
            .map_err(|_| Refusal::Context)?;
        let body = message.body().to_vec();
        self.prepared = Some(Prepared::Proposal(message));
        Ok(body)
    }
    /// Restores a completed close message: 0 intent, 1 response,
    /// 2 proposal. A response requires its intent to be locked first.
    fn restore_message(
        &mut self,
        credential: &mut Credential,
        argument: usize,
        input: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        if !self.ready() {
            return Err(Refusal::Consumed);
        }
        let count = self.count();
        let organizer = self.context.organizer();
        let roster = self.context.setup().roster();
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
            _ => Err(Refusal::Shape),
        }?;
        Ok(Vec::new())
    }
    /// Restores the spent ballot purpose before close work. This
    /// requires the original completed local envelope and signature.
    fn restore_ballot_signing(
        &mut self,
        credential: &mut Credential,
        input: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        if input.len() != ENVELOPE_BYTES + SIGNATURE_BYTES {
            return Err(Refusal::Shape);
        }
        let envelope =
            BallotEnvelope::decode(self.context.setup().profile(), &input[..ENVELOPE_BYTES])?;
        credential.restore_retained_ballot_signing(
            &self.owner,
            &envelope,
            &input[ENVELOPE_BYTES..],
        )?;
        Ok(Vec::new())
    }
    /// A failed transport discards its tentative body without
    /// accepting even a complete prefix or changing held records.
    fn discard_held_body(&mut self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !input.is_empty() {
            return Err(Refusal::Shape);
        }
        self.pending = None;
        Ok(Vec::new())
    }
    /// The bodies the organizer still needs, as consecutive two-byte
    /// author positions and envelope identities: at most one per slot,
    /// each listed by an authenticated response.
    fn wanted_bodies(&self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !input.is_empty() || !self.is_organizer() {
            return Err(Refusal::Shape);
        }
        let intent = self.intent.as_ref().ok_or(Refusal::Context)?;
        Ok(self
            .context
            .organizer_wanted(intent, &self.envelopes, &self.held, &self.responses)
            .into_iter()
            .flat_map(|(author, identity)| {
                (author as u16).to_le_bytes().into_iter().chain(identity)
            })
            .collect())
    }
    /// The submission identity of an envelope of this poll's profile,
    /// which listings and wanted bodies name. It changes no state.
    fn envelope_identity(&self, input: &[u8]) -> Result<Vec<u8>, Refusal> {
        Ok(
            BallotEnvelope::decode(self.context.setup().profile(), input)?
                .identity()
                .to_vec(),
        )
    }
}
