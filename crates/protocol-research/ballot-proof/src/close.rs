use crate::submission::{AuthenticatedBallotBody, AuthenticatedBallotEnvelope};
use registration_credentials::{
    close_signing::{
        CloseIntentMessage, CloseProposalMessage, ClosePurpose, CloseResponseMessage,
        MAXIMUM_LISTED_ENVELOPES_PER_SLOT, verify_close_signature,
    },
    poll::VerifiedPoll,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Context,
    Signature,
    Incomplete,
}

/// Only the owning public setup verifier can supply this context.
pub struct CloseContext {
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
}

/// The organizer's authenticated close intent.
#[derive(Clone)]
pub struct AuthenticatedCloseIntent {
    message: CloseIntentMessage,
    signature: [u8; 3309],
}
impl AuthenticatedCloseIntent {
    pub fn message(&self) -> &CloseIntentMessage {
        &self.message
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}

/// An authenticated close response together with the exact authenticated
/// envelope of every entry it lists. It creates no inventory.
#[derive(Clone)]
pub struct AuthenticatedCloseResponse {
    message: CloseResponseMessage,
    signature: [u8; 3309],
    listed: Vec<AuthenticatedBallotEnvelope>,
}
impl AuthenticatedCloseResponse {
    pub fn message(&self) -> &CloseResponseMessage {
        &self.message
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
    /// The listed envelopes in listing order.
    pub fn listed(&self) -> &[AuthenticatedBallotEnvelope] {
        &self.listed
    }
}

/// One roster slot of the union of a proposal's responses.
#[derive(Clone)]
pub enum ClosedSlot {
    Absent,
    Usable(Box<AuthenticatedBallotBody>),
    /// The distinct listed envelope identities in ascending order.
    Conflicting(Vec<[u8; 64]>),
}

/// Created only by the close-proposal verifier from the authenticated close
/// intent, `n-f` authenticated close responses, and the complete body of every
/// usable slot. It fixes the union but not inner-proof validity, the target,
/// or its certificate.
pub struct VerifiedCloseBarrier {
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    intent: AuthenticatedCloseIntent,
    proposal: CloseProposalMessage,
    signature: [u8; 3309],
    responses: Vec<AuthenticatedCloseResponse>,
    slots: Vec<ClosedSlot>,
}
impl VerifiedCloseBarrier {
    pub fn poll(&self) -> &Arc<VerifiedPoll> {
        &self.poll
    }
    pub fn setup(&self) -> &Arc<VerifiedSetupAggregate> {
        &self.setup
    }
    pub fn intent(&self) -> &AuthenticatedCloseIntent {
        &self.intent
    }
    pub fn proposal(&self) -> &CloseProposalMessage {
        &self.proposal
    }
    pub fn proposal_signature(&self) -> &[u8; 3309] {
        &self.signature
    }
    /// The used responses in ascending responder order.
    pub fn responses(&self) -> &[AuthenticatedCloseResponse] {
        &self.responses
    }
    pub fn slots(&self) -> &[ClosedSlot] {
        &self.slots
    }
}

impl CloseContext {
    pub fn new(poll: Arc<VerifiedPoll>, setup: Arc<VerifiedSetupAggregate>) -> Result<Self, Error> {
        let proposal = setup.inventory().proposal().proposal();
        if !(3..=20).contains(&proposal.records().len())
            || proposal
                .records()
                .iter()
                .any(|record| record.header().poll != poll.identity())
            || proposal.records()[proposal.organizer_position()]
                .header()
                .signing_public
                != *poll.organizer()
        {
            return Err(Error::Context);
        }
        Ok(Self { poll, setup })
    }
    pub fn poll(&self) -> &Arc<VerifiedPoll> {
        &self.poll
    }
    pub fn setup(&self) -> &Arc<VerifiedSetupAggregate> {
        &self.setup
    }
    pub fn participant_count(&self) -> usize {
        self.setup.inventory().proposal().proposal().records().len()
    }
    pub fn organizer(&self) -> usize {
        self.setup
            .inventory()
            .proposal()
            .proposal()
            .organizer_position()
    }
    fn key(&self, position: usize) -> Result<&[u8; 1952], Error> {
        Ok(&self
            .setup
            .inventory()
            .proposal()
            .proposal()
            .records()
            .get(position)
            .ok_or(Error::Context)?
            .header()
            .signing_public)
    }
    fn inventory(&self) -> [u8; 64] {
        self.setup.inventory().identity()
    }
    pub fn intent(&self, close_time: u64) -> Result<CloseIntentMessage, Error> {
        CloseIntentMessage::new(self.poll.identity(), self.inventory(), close_time)
            .map_err(|_| Error::Shape)
    }
    pub fn authenticate_intent(
        &self,
        body: &[u8],
        signature: &[u8],
    ) -> Result<AuthenticatedCloseIntent, Error> {
        let message = CloseIntentMessage::parse(body).map_err(|_| Error::Shape)?;
        if *message.poll() != self.poll.identity() || *message.inventory() != self.inventory() {
            return Err(Error::Context);
        }
        if !verify_close_signature(
            self.key(self.organizer())?,
            ClosePurpose::Intent,
            message.identity(),
            signature,
        ) {
            return Err(Error::Signature);
        }
        Ok(AuthenticatedCloseIntent {
            message,
            signature: signature.try_into().map_err(|_| Error::Shape)?,
        })
    }
    /// The on-time envelope identities known for each slot, from the known
    /// envelopes and the envelopes of the held bodies.
    fn known_slots(
        &self,
        intent: &AuthenticatedCloseIntent,
        known: &[AuthenticatedBallotEnvelope],
        held: &[AuthenticatedBallotBody],
    ) -> Vec<Vec<[u8; 64]>> {
        known_on_time(
            self.participant_count(),
            known
                .iter()
                .chain(held.iter().map(AuthenticatedBallotBody::authentication))
                .map(|authentication| {
                    let envelope = authentication.envelope();
                    (
                        envelope.position(),
                        envelope.identity(),
                        envelope.ballot_time(),
                    )
                }),
            intent.message.close_time(),
        )
    }
    /// The honest listing, in ascending author and identity order. A slot
    /// with at least two known on-time envelopes lists the two smallest
    /// identities, which make it conflicting without any body; a slot with
    /// one lists it only when its complete body is held.
    pub fn response(
        &self,
        intent: &AuthenticatedCloseIntent,
        responder: usize,
        known: &[AuthenticatedBallotEnvelope],
        held: &[AuthenticatedBallotBody],
    ) -> Result<CloseResponseMessage, Error> {
        let listed = honest_listing(
            &self.known_slots(intent, known, held),
            &held_identities(held),
        );
        CloseResponseMessage::new(
            self.poll.identity(),
            self.inventory(),
            *intent.message.identity(),
            responder,
            self.participant_count(),
            &listed,
        )
        .map_err(|_| Error::Context)
    }
    /// A response is usable only with the exact authenticated envelope of
    /// every listed entry. A missing envelope leaves it pending; a late or
    /// wrong-author entry makes it invalid. Listed bodies are not needed here:
    /// only the barrier's usable slots require theirs.
    pub fn authenticate_response(
        &self,
        intent: &AuthenticatedCloseIntent,
        body: &[u8],
        signature: &[u8],
        available: &[AuthenticatedBallotEnvelope],
    ) -> Result<AuthenticatedCloseResponse, Error> {
        let message = CloseResponseMessage::parse(body, self.participant_count())
            .map_err(|_| Error::Shape)?;
        if *message.poll() != self.poll.identity()
            || *message.inventory() != self.inventory()
            || message.intent() != intent.message.identity()
        {
            return Err(Error::Context);
        }
        if !verify_close_signature(
            self.key(message.responder())?,
            ClosePurpose::Response,
            message.identity(),
            signature,
        ) {
            return Err(Error::Signature);
        }
        let mut listed = Vec::with_capacity(message.listed().len());
        for (author, identity) in message.listed() {
            let authentication = available
                .iter()
                .find(|value| value.envelope().identity() == *identity)
                .ok_or(Error::Incomplete)?;
            let envelope = authentication.envelope();
            if envelope.position() != *author
                || envelope.ballot_time() > intent.message.close_time()
            {
                return Err(Error::Context);
            }
            listed.push(authentication.clone());
        }
        Ok(AuthenticatedCloseResponse {
            message,
            signature: signature.try_into().map_err(|_| Error::Shape)?,
            listed,
        })
    }
    /// Whether an organizer with these known envelopes and held bodies can
    /// include this response: every slot it lists where only one on-time
    /// envelope is known has that body held. A slot with two known envelopes
    /// is conflicting through the organizer's own listing and needs none.
    pub fn organizer_ready(
        &self,
        intent: &AuthenticatedCloseIntent,
        known: &[AuthenticatedBallotEnvelope],
        held: &[AuthenticatedBallotBody],
        response: &AuthenticatedCloseResponse,
    ) -> bool {
        ready_listing(
            &self.known_slots(intent, known, held),
            &held_identities(held),
            response.message.listed(),
        )
    }
    /// The bodies an organizer still needs: the one known on-time envelope of
    /// each slot that these responses list, when its body is not held. It
    /// names at most one body per slot, and none once two are known.
    pub fn organizer_wanted(
        &self,
        intent: &AuthenticatedCloseIntent,
        known: &[AuthenticatedBallotEnvelope],
        held: &[AuthenticatedBallotBody],
        responses: &[AuthenticatedCloseResponse],
    ) -> Vec<(usize, [u8; 64])> {
        wanted_listing(
            &self.known_slots(intent, known, held),
            &held_identities(held),
            responses.iter().map(|response| response.message.listed()),
        )
    }
    /// The organizer's proposal from exactly `q` authenticated responses to
    /// its intent, including its own.
    pub fn proposal(
        &self,
        intent: &AuthenticatedCloseIntent,
        responses: &[AuthenticatedCloseResponse],
    ) -> Result<CloseProposalMessage, Error> {
        if responses
            .iter()
            .any(|response| response.message.intent() != intent.message.identity())
        {
            return Err(Error::Context);
        }
        let mut entries: Vec<(usize, [u8; 64])> = responses
            .iter()
            .map(|response| (response.message.responder(), *response.message.identity()))
            .collect();
        entries.sort_unstable();
        CloseProposalMessage::new(
            self.poll.identity(),
            self.inventory(),
            *intent.message.identity(),
            self.participant_count(),
            self.organizer(),
            &entries,
        )
        .map_err(|_| Error::Context)
    }
    fn select(
        &self,
        intent: &AuthenticatedCloseIntent,
        proposal: &CloseProposalMessage,
        responses: &[AuthenticatedCloseResponse],
    ) -> Result<Selection, Error> {
        if *proposal.poll() != self.poll.identity()
            || *proposal.inventory() != self.inventory()
            || proposal.intent() != intent.message.identity()
        {
            return Err(Error::Context);
        }
        let mut used = Vec::with_capacity(proposal.responses().len());
        for (responder, identity) in proposal.responses() {
            let response = responses
                .iter()
                .find(|response| response.message.identity() == identity)
                .ok_or(Error::Incomplete)?;
            if response.message.responder() != *responder
                || response.message.intent() != intent.message.identity()
            {
                return Err(Error::Context);
            }
            used.push(response.clone());
        }
        let slots = union(
            self.participant_count(),
            used.iter().map(|response| response.message.listed()),
        );
        Ok(Selection { used, slots })
    }
    /// The author and envelope identity of every usable slot of a proposal's
    /// union: the only bodies its barrier requires. Conflicting slots need
    /// none. This creates no capability.
    pub fn required_bodies(
        &self,
        intent: &AuthenticatedCloseIntent,
        proposal: &CloseProposalMessage,
        responses: &[AuthenticatedCloseResponse],
    ) -> Result<Vec<(usize, [u8; 64])>, Error> {
        Ok(singletons(&self.select(intent, proposal, responses)?.slots))
    }
    /// The only producer of `VerifiedCloseBarrier`. It authenticates the
    /// organizer's proposal, selects exactly its named responses, and derives
    /// the union: one listed envelope makes a slot usable and two or more make
    /// it conflicting. Each usable slot needs its complete authenticated body.
    pub fn verify_proposal(
        &self,
        intent: AuthenticatedCloseIntent,
        body: &[u8],
        signature: &[u8],
        responses: &[AuthenticatedCloseResponse],
        bodies: &[AuthenticatedBallotBody],
    ) -> Result<VerifiedCloseBarrier, Error> {
        let proposal =
            CloseProposalMessage::parse(body, self.participant_count(), self.organizer())
                .map_err(|_| Error::Shape)?;
        let Selection { used, slots } = self.select(&intent, &proposal, responses)?;
        if !verify_close_signature(
            self.key(self.organizer())?,
            ClosePurpose::Proposal,
            proposal.identity(),
            signature,
        ) {
            return Err(Error::Signature);
        }
        let slots = slots
            .into_iter()
            .map(|identities| match identities.as_slice() {
                [] => Ok(ClosedSlot::Absent),
                [identity] => bodies
                    .iter()
                    .find(|body| body.authentication().envelope().identity() == *identity)
                    .map(|body| ClosedSlot::Usable(Box::new(body.clone())))
                    .ok_or(Error::Incomplete),
                _ => Ok(ClosedSlot::Conflicting(identities)),
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(VerifiedCloseBarrier {
            poll: self.poll.clone(),
            setup: self.setup.clone(),
            intent,
            proposal,
            signature: signature.try_into().map_err(|_| Error::Shape)?,
            responses: used,
            slots,
        })
    }
}

/// The named responses of a proposal and the distinct listed identities of
/// each slot in their union.
struct Selection {
    used: Vec<AuthenticatedCloseResponse>,
    slots: Vec<Vec<[u8; 64]>>,
}

fn held_identities(held: &[AuthenticatedBallotBody]) -> Vec<[u8; 64]> {
    held.iter()
        .map(|body| body.authentication().envelope().identity())
        .collect()
}

/// The distinct identities of the known (author, envelope identity, ballot
/// time) values timed no later than the close time, for each slot in
/// ascending order.
fn known_on_time(
    count: usize,
    known: impl IntoIterator<Item = (usize, [u8; 64], u64)>,
    close_time: u64,
) -> Vec<Vec<[u8; 64]>> {
    let mut slots = vec![Vec::new(); count];
    for (author, identity, time) in known {
        if time <= close_time
            && let Some(slot) = slots.get_mut(author)
        {
            slot.push(identity);
        }
    }
    for identities in &mut slots {
        identities.sort_unstable();
        identities.dedup();
    }
    slots
}

/// The honest listing rule. Two known envelopes already make a slot
/// conflicting, so it lists the two smallest identities and needs no body; a
/// slot's only known envelope is listed only with its complete body held.
fn honest_listing(known: &[Vec<[u8; 64]>], held: &[[u8; 64]]) -> Vec<(usize, [u8; 64])> {
    let mut listed = Vec::new();
    for (author, identities) in known.iter().enumerate() {
        match identities.as_slice() {
            [] => {}
            [identity] => {
                if held.contains(identity) {
                    listed.push((author, *identity));
                }
            }
            _ => listed.extend(
                identities[..MAXIMUM_LISTED_ENVELOPES_PER_SLOT]
                    .iter()
                    .map(|identity| (author, *identity)),
            ),
        }
    }
    listed
}

/// Whether every listed entry whose slot has one known envelope has its body
/// held. A listed entry that is not known leaves the listing unready.
fn ready_listing(known: &[Vec<[u8; 64]>], held: &[[u8; 64]], listed: &[(usize, [u8; 64])]) -> bool {
    listed.iter().all(|(author, identity)| {
        known.get(*author).is_some_and(|identities| {
            identities.contains(identity) && (identities.len() > 1 || held.contains(identity))
        })
    })
}

/// The distinct unheld entries of these listings whose slot has one known
/// envelope, in ascending order.
fn wanted_listing<'a>(
    known: &[Vec<[u8; 64]>],
    held: &[[u8; 64]],
    listings: impl IntoIterator<Item = &'a [(usize, [u8; 64])]>,
) -> Vec<(usize, [u8; 64])> {
    let mut wanted: Vec<(usize, [u8; 64])> = listings
        .into_iter()
        .flatten()
        .filter(|(author, identity)| {
            known.get(*author).is_some_and(|identities| {
                identities.as_slice() == [*identity] && !held.contains(identity)
            })
        })
        .copied()
        .collect();
    wanted.sort_unstable();
    wanted.dedup();
    wanted
}

/// The author and identity of every slot that exactly one listed envelope
/// occupies in the union of these responses: the slots whose bodies a barrier
/// over them requires. An organizer uses it to build a proposal it can verify.
pub fn usable_entries(
    count: usize,
    responses: &[&AuthenticatedCloseResponse],
) -> Vec<(usize, [u8; 64])> {
    singletons(&union(
        count,
        responses.iter().map(|response| response.message.listed()),
    ))
}
fn singletons(slots: &[Vec<[u8; 64]>]) -> Vec<(usize, [u8; 64])> {
    slots
        .iter()
        .enumerate()
        .filter_map(|(author, identities)| match identities.as_slice() {
            [identity] => Some((author, *identity)),
            _ => None,
        })
        .collect()
}

/// The distinct envelope identities listed for each slot across the used
/// responses, in ascending order.
fn union<'a>(
    count: usize,
    listings: impl IntoIterator<Item = &'a [(usize, [u8; 64])]>,
) -> Vec<Vec<[u8; 64]>> {
    let mut slots = vec![Vec::new(); count];
    for (author, identity) in listings.into_iter().flatten() {
        slots[*author].push(*identity);
    }
    for identities in &mut slots {
        identities.sort_unstable();
        identities.dedup();
    }
    slots
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(value: u8) -> [u8; 64] {
        [value; 64]
    }
    const KNOWN: [(usize, [u8; 64], u64); 8] = [
        (3, [9; 64], 10),
        (0, [5; 64], 11),
        (3, [1; 64], 3),
        (3, [4; 64], 7),
        (1, [2; 64], 12),
        (0, [5; 64], 11),
        (2, [8; 64], 10),
        (4, [6; 64], 9),
    ];
    #[test]
    fn honest_listings_keep_on_time_envelopes_and_two_per_slot() {
        let every = [
            identity(9),
            identity(5),
            identity(1),
            identity(4),
            identity(2),
            identity(8),
            identity(6),
        ];
        assert_eq!(
            honest_listing(&known_on_time(5, KNOWN, 10), &every),
            vec![
                (2, identity(8)),
                (3, identity(1)),
                (3, identity(4)),
                (4, identity(6))
            ]
        );
        assert_eq!(
            honest_listing(&known_on_time(5, KNOWN, 12), &every),
            vec![
                (0, identity(5)),
                (1, identity(2)),
                (2, identity(8)),
                (3, identity(1)),
                (3, identity(4)),
                (4, identity(6)),
            ]
        );
        assert!(honest_listing(&known_on_time(5, KNOWN, 2), &every).is_empty());
        assert!(honest_listing(&known_on_time(5, [], u64::MAX), &every).is_empty());
        // Out-of-roster authors are never known.
        assert!(
            known_on_time(2, KNOWN, u64::MAX)
                .iter()
                .all(|slot| slot.len() == 1)
        );
    }
    #[test]
    fn two_known_envelopes_are_listed_without_bodies() {
        // Only slot 2's body is held. Slot 3 knows three on-time envelopes
        // and lists the two smallest; slots 0, 1 and 4 know one unheld
        // envelope each and list nothing.
        let known = known_on_time(5, KNOWN, 12);
        assert_eq!(
            honest_listing(&known, &[identity(8)]),
            vec![(2, identity(8)), (3, identity(1)), (3, identity(4))]
        );
        assert!(
            honest_listing(&known, &[])
                .iter()
                .all(|(author, _)| *author == 3)
        );
        // Both envelopes are on time at close time 7. At 6 the second is
        // late and does not make the slot conflicting.
        assert_eq!(
            honest_listing(&known_on_time(5, KNOWN, 7), &[identity(1)]),
            vec![(3, identity(1)), (3, identity(4))]
        );
        assert_eq!(
            honest_listing(&known_on_time(5, KNOWN, 6), &[identity(1)]),
            vec![(3, identity(1))]
        );
    }
    #[test]
    fn the_organizer_needs_only_single_known_bodies() {
        let known = known_on_time(5, KNOWN, 12);
        let held = [identity(5)];
        // Slot 3 needs no body; slot 0's body is held; slots 1 and 2 are not.
        assert!(ready_listing(
            &known,
            &held,
            &[(0, identity(5)), (3, identity(9))]
        ));
        assert!(ready_listing(
            &known,
            &held,
            &[(3, identity(1)), (3, identity(4))]
        ));
        assert!(!ready_listing(
            &known,
            &held,
            &[(0, identity(5)), (2, identity(8))]
        ));
        assert!(ready_listing(&known, &held, &[]));
        // An entry the organizer does not know, or a late one, is never ready.
        assert!(!ready_listing(&known, &held, &[(0, identity(7))]));
        assert!(!ready_listing(
            &known_on_time(5, KNOWN, 10),
            &held,
            &[(0, identity(5))]
        ));
        assert!(!ready_listing(&known, &held, &[(9, identity(5))]));
        let first = [(0, identity(5)), (1, identity(2)), (3, identity(1))];
        let second = [(1, identity(2)), (2, identity(8)), (3, identity(4))];
        assert_eq!(
            wanted_listing(&known, &held, [&first[..], &second[..]]),
            vec![(1, identity(2)), (2, identity(8))]
        );
        assert!(
            wanted_listing(
                &known,
                &[identity(2), identity(8), identity(5)],
                [&first[..], &second[..]]
            )
            .is_empty()
        );
        // Once a second envelope is known, the first is no longer wanted.
        let later = known_on_time(5, KNOWN.into_iter().chain([(2, identity(7), 1)]), 12);
        assert_eq!(
            wanted_listing(&later, &held, [&first[..], &second[..]]),
            vec![(1, identity(2))]
        );
    }
    #[test]
    fn the_union_separates_absent_usable_and_conflicting_slots() {
        let first = [(0, identity(1)), (2, identity(3)), (2, identity(4))];
        let second = [(0, identity(1)), (1, identity(2))];
        let third = [(2, identity(5))];
        let slots = union(4, [&first[..], &second[..], &third[..]]);
        assert_eq!(slots[0], vec![identity(1)]);
        assert_eq!(slots[1], vec![identity(2)]);
        assert_eq!(slots[2], vec![identity(3), identity(4), identity(5)]);
        assert!(slots[3].is_empty());
        // Only the usable slots need bodies.
        assert_eq!(singletons(&slots), vec![(0, identity(1)), (1, identity(2))]);
        assert!(
            singletons(&union(3, [&first[..]]))
                .iter()
                .all(|(author, _)| *author == 0)
        );
        // One response alone may already make a slot conflicting.
        assert_eq!(union(3, [&first[..]])[2].len(), 2);
        assert!(union(3, []).iter().all(Vec::is_empty));
    }
}
