use crate::{
    Credential, Error, SigningPurpose,
    ballot_authentication::RetainedBallotOwner,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    roster_authentication::OrganizerSignedRoster,
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use zeroize::Zeroizing;

/// Two different envelopes already make a slot conflicting, so a response
/// lists no more; a corrupt author cannot inflate honest responses.
pub const MAXIMUM_LISTED_ENVELOPES_PER_SLOT: usize = 2;
/// One listing entry: an author position and an envelope or response identity.
pub const LISTED_ENTRY_BYTES: usize = 2 + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosePurpose {
    Intent,
    Response,
    Proposal,
}
impl ClosePurpose {
    pub const fn context(self) -> &'static str {
        match self {
            Self::Intent => "sealed-lattice/close-intent/v1",
            Self::Response => "sealed-lattice/close-response/v1",
            Self::Proposal => "sealed-lattice/close-proposal/v1",
        }
    }
    const fn item_count(self) -> usize {
        match self {
            Self::Intent => 4,
            Self::Response => 6,
            Self::Proposal => 5,
        }
    }
}

/// The close quorum `q = n - f`, where `f = floor((n-1)/3)`.
pub fn close_quorum(participants: usize) -> usize {
    participants - (participants - 1) / 3
}

/// The exact encoded length of the largest message of a purpose, from the
/// canonical tuple layout: an eight-byte header and, per item, a two-byte type
/// and four-byte length, with a four-byte length inside variable values.
pub fn maximum_close_message_bytes(purpose: ClosePurpose, participants: usize) -> usize {
    let prefix = 8 + (6 + 4 + purpose.context().len()) + 2 * (6 + 64);
    match purpose {
        ClosePurpose::Intent => prefix + 6 + 8,
        ClosePurpose::Response => {
            prefix
                + (6 + 64)
                + (6 + 2)
                + (6 + 4 + MAXIMUM_LISTED_ENVELOPES_PER_SLOT * participants * LISTED_ENTRY_BYTES)
        }
        ClosePurpose::Proposal => {
            prefix + (6 + 64) + (6 + 4 + close_quorum(participants) * LISTED_ENTRY_BYTES)
        }
    }
}

/// The signed message identity: the foundation hash of the complete body as
/// one variable-byte item under the purpose, which is also the signature context.
pub fn close_message_identity(purpose: ClosePurpose, body: &[u8]) -> Result<[u8; 64], Error> {
    hash_foundation_tuple_512(
        purpose.context(),
        &[CanonicalItem::variable_bytes(body).map_err(|_| Error::Shape)?],
    )
    .map(|value| value.into_bytes())
    .map_err(|_| Error::Shape)
}

/// Checks one signature by the supplied roster key. The caller selects that
/// key from a positively verified roster position.
pub fn verify_close_signature(
    public: &[u8; 1952],
    purpose: ClosePurpose,
    identity: &[u8; 64],
    signature: &[u8],
) -> bool {
    let Ok(signature) = <[u8; 3309]>::try_from(signature) else {
        return false;
    };
    let Ok(public) = ml_dsa_65::PublicKey::try_from_bytes(*public) else {
        return false;
    };
    public.verify(identity, &signature, purpose.context().as_bytes())
}

fn check_participants(participants: usize) -> Result<(), Error> {
    if !(3..=20).contains(&participants) {
        return Err(Error::Context);
    }
    Ok(())
}
fn encode(
    purpose: ClosePurpose,
    poll: [u8; 64],
    inventory: [u8; 64],
    rest: Vec<CanonicalItem>,
) -> Result<Vec<u8>, Error> {
    let mut items = vec![
        CanonicalItem::nonempty_ascii(purpose.context()).map_err(|_| Error::Shape)?,
        CanonicalItem::hash512(poll),
        CanonicalItem::hash512(inventory),
    ];
    items.extend(rest);
    CanonicalTuple::new(1, 1, items)
        .encode()
        .map_err(|_| Error::Shape)
}
fn decode(
    body: &[u8],
    purpose: ClosePurpose,
    participants: usize,
) -> Result<Vec<CanonicalItem>, Error> {
    let maximum = maximum_close_message_bytes(purpose, participants);
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: maximum,
        maximum_item_count: purpose.item_count(),
        maximum_item_byte_length: maximum,
        maximum_nesting_depth: 0,
        ..CanonicalDecodeLimits::default()
    };
    let tuple = CanonicalTuple::decode(body, &limits).map_err(|_| Error::Shape)?;
    if tuple.schema_identifier != 1
        || tuple.schema_version != 1
        || tuple.items.len() != purpose.item_count()
    {
        return Err(Error::Shape);
    }
    let items = tuple.items;
    if items[0].item_type() != CanonicalItemType::Ascii
        || items[0].variable_value_bytes().map_err(|_| Error::Shape)?
            != purpose.context().as_bytes()
    {
        return Err(Error::Context);
    }
    Ok(items)
}
fn hash(item: &CanonicalItem) -> Result<[u8; 64], Error> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(Error::Shape);
    }
    item.canonical_bytes().try_into().map_err(|_| Error::Shape)
}
fn position(item: &CanonicalItem, participants: usize) -> Result<usize, Error> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(Error::Shape);
    }
    let value = usize::from(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| Error::Shape)?,
    ));
    if value >= participants {
        return Err(Error::Context);
    }
    Ok(value)
}
/// Entries strictly ascend by author and then identity bytes, with at most
/// `per_author` entries for one author.
fn entries(
    item: &CanonicalItem,
    participants: usize,
    per_author: usize,
) -> Result<Vec<(usize, [u8; 64])>, Error> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(Error::Shape);
    }
    let bytes = item.variable_value_bytes().map_err(|_| Error::Shape)?;
    if bytes.len() % LISTED_ENTRY_BYTES != 0 {
        return Err(Error::Shape);
    }
    let values: Vec<(usize, [u8; 64])> = bytes
        .chunks_exact(LISTED_ENTRY_BYTES)
        .map(|entry| {
            (
                usize::from(u16::from_le_bytes([entry[0], entry[1]])),
                entry[2..].try_into().unwrap(),
            )
        })
        .collect();
    let mut run = 0;
    for (index, (author, _)) in values.iter().enumerate() {
        if *author >= participants {
            return Err(Error::Context);
        }
        if index > 0 && values[index - 1] >= values[index] {
            return Err(Error::Shape);
        }
        run = if index > 0 && values[index - 1].0 == *author {
            run + 1
        } else {
            1
        };
        if run > per_author {
            return Err(Error::Shape);
        }
    }
    Ok(values)
}
fn encode_entries(values: &[(usize, [u8; 64])]) -> Result<CanonicalItem, Error> {
    let mut bytes = Vec::with_capacity(values.len() * LISTED_ENTRY_BYTES);
    for (author, identity) in values {
        bytes.extend(
            u16::try_from(*author)
                .map_err(|_| Error::Shape)?
                .to_le_bytes(),
        );
        bytes.extend(identity);
    }
    CanonicalItem::variable_bytes(bytes).map_err(|_| Error::Shape)
}

/// Canonical close-intent signing data. Parsing verifies no signature.
#[derive(Clone)]
pub struct CloseIntentMessage {
    body: Vec<u8>,
    identity: [u8; 64],
    poll: [u8; 64],
    inventory: [u8; 64],
    close_time: u64,
}
impl CloseIntentMessage {
    pub fn new(poll: [u8; 64], inventory: [u8; 64], close_time: u64) -> Result<Self, Error> {
        Self::parse(&encode(
            ClosePurpose::Intent,
            poll,
            inventory,
            vec![CanonicalItem::unsigned64(close_time)],
        )?)
    }
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let items = decode(body, ClosePurpose::Intent, 3)?;
        if items[3].item_type() != CanonicalItemType::Unsigned64 {
            return Err(Error::Shape);
        }
        Ok(Self {
            body: body.to_vec(),
            identity: close_message_identity(ClosePurpose::Intent, body)?,
            poll: hash(&items[1])?,
            inventory: hash(&items[2])?,
            close_time: u64::from_le_bytes(
                items[3]
                    .canonical_bytes()
                    .try_into()
                    .map_err(|_| Error::Shape)?,
            ),
        })
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn close_time(&self) -> u64 {
        self.close_time
    }
}

/// Canonical close-response signing data: the responder and the listed
/// envelope identities. Parsing authenticates no listed envelope or body.
#[derive(Clone)]
pub struct CloseResponseMessage {
    body: Vec<u8>,
    identity: [u8; 64],
    poll: [u8; 64],
    inventory: [u8; 64],
    intent: [u8; 64],
    responder: usize,
    listed: Vec<(usize, [u8; 64])>,
}
impl CloseResponseMessage {
    pub fn new(
        poll: [u8; 64],
        inventory: [u8; 64],
        intent: [u8; 64],
        responder: usize,
        participants: usize,
        listed: &[(usize, [u8; 64])],
    ) -> Result<Self, Error> {
        check_participants(participants)?;
        let body = encode(
            ClosePurpose::Response,
            poll,
            inventory,
            vec![
                CanonicalItem::hash512(intent),
                CanonicalItem::unsigned16(u16::try_from(responder).map_err(|_| Error::Shape)?),
                encode_entries(listed)?,
            ],
        )?;
        Self::parse(&body, participants)
    }
    pub fn parse(body: &[u8], participants: usize) -> Result<Self, Error> {
        check_participants(participants)?;
        let items = decode(body, ClosePurpose::Response, participants)?;
        Ok(Self {
            body: body.to_vec(),
            identity: close_message_identity(ClosePurpose::Response, body)?,
            poll: hash(&items[1])?,
            inventory: hash(&items[2])?,
            intent: hash(&items[3])?,
            responder: position(&items[4], participants)?,
            listed: entries(&items[5], participants, MAXIMUM_LISTED_ENVELOPES_PER_SLOT)?,
        })
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn intent(&self) -> &[u8; 64] {
        &self.intent
    }
    pub fn responder(&self) -> usize {
        self.responder
    }
    pub fn listed(&self) -> &[(usize, [u8; 64])] {
        &self.listed
    }
}

/// Canonical organizer close-proposal signing data: exactly `q` response
/// identities from distinct responders in ascending order, including the
/// organizer. Parsing authenticates no response.
#[derive(Clone)]
pub struct CloseProposalMessage {
    body: Vec<u8>,
    identity: [u8; 64],
    poll: [u8; 64],
    inventory: [u8; 64],
    intent: [u8; 64],
    responses: Vec<(usize, [u8; 64])>,
}
impl CloseProposalMessage {
    pub fn new(
        poll: [u8; 64],
        inventory: [u8; 64],
        intent: [u8; 64],
        participants: usize,
        organizer: usize,
        responses: &[(usize, [u8; 64])],
    ) -> Result<Self, Error> {
        check_participants(participants)?;
        let body = encode(
            ClosePurpose::Proposal,
            poll,
            inventory,
            vec![CanonicalItem::hash512(intent), encode_entries(responses)?],
        )?;
        Self::parse(&body, participants, organizer)
    }
    pub fn parse(body: &[u8], participants: usize, organizer: usize) -> Result<Self, Error> {
        check_participants(participants)?;
        let items = decode(body, ClosePurpose::Proposal, participants)?;
        let responses = entries(&items[4], participants, 1)?;
        if responses.len() != close_quorum(participants) {
            return Err(Error::Shape);
        }
        if !responses
            .iter()
            .any(|(responder, _)| *responder == organizer)
        {
            return Err(Error::Context);
        }
        Ok(Self {
            body: body.to_vec(),
            identity: close_message_identity(ClosePurpose::Proposal, body)?,
            poll: hash(&items[1])?,
            inventory: hash(&items[2])?,
            intent: hash(&items[3])?,
            responses,
        })
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn intent(&self) -> &[u8; 64] {
        &self.intent
    }
    pub fn responses(&self) -> &[(usize, [u8; 64])] {
        &self.responses
    }
}

/// A completed close message for restoration. Each variant carries its exact
/// canonical signing data.
pub enum CloseMessage<'a> {
    Intent(&'a CloseIntentMessage),
    Response(&'a CloseResponseMessage),
    Proposal(&'a CloseProposalMessage),
}

impl Credential {
    fn check_close_owner(
        &self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        poll: &[u8; 64],
        inventory: &[u8; 64],
    ) -> Result<(), Error> {
        self.check_ballot_owner(owner)?;
        let records = roster.proposal().records();
        let record = records.get(owner.position()).ok_or(Error::Context)?;
        if !(3..=20).contains(&records.len())
            || record.header().poll != *owner.poll()
            || record.header().signing_public != self.signing_public
            || self.completed_body != Some(record.body_digest())
            || poll != owner.poll()
            || inventory != owner.inventory()
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn check_organizer(
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
    ) -> Result<(), Error> {
        if owner.position() != roster.proposal().organizer_position() {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn sign_close(
        &self,
        purpose: ClosePurpose,
        identity: &[u8; 64],
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        let coins = Zeroizing::new(coins);
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        key.try_sign_with_seed(&coins, identity, purpose.context().as_bytes())
            .map_err(|_| Error::Crypto)
    }
    fn check_own_signature(
        &self,
        purpose: ClosePurpose,
        identity: &[u8; 64],
        signature: &[u8],
    ) -> Result<(), Error> {
        if !verify_close_signature(&self.signing_public, purpose, identity, signature) {
            return Err(Error::Crypto);
        }
        Ok(())
    }
    /// Locks the first close intent this participant authenticates. It freezes
    /// new ballot attempts and fixes the only intent its response may name.
    fn lock_intent(&mut self, message: &CloseIntentMessage) -> Result<(), Error> {
        match self.close_lock {
            Some((identity, _)) if identity != *message.identity() => Err(Error::Consumed),
            _ => {
                self.close_lock = Some((*message.identity(), message.close_time()));
                Ok(())
            }
        }
    }
    /// The organizer's one close intent. Signing it also authenticates it.
    pub fn sign_close_intent(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &CloseIntentMessage,
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        self.check_close_owner(owner, roster, message.poll(), message.inventory())?;
        Self::check_organizer(owner, roster)?;
        self.check_unlocked(SigningPurpose::CloseIntent)?;
        if self.close_intent_signed
            || self
                .close_lock
                .is_some_and(|(identity, _)| identity != *message.identity())
        {
            return Err(Error::Consumed);
        }
        self.close_intent_signed = true;
        self.lock_intent(message)?;
        self.sign_close(ClosePurpose::Intent, message.identity(), coins)
    }
    /// Authenticates the organizer's close intent and locks it. A second,
    /// different intent is refused, so an equivocating organizer obtains at
    /// most one response from this participant.
    pub fn lock_close_intent(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &CloseIntentMessage,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.check_close_owner(owner, roster, message.poll(), message.inventory())?;
        let organizer = &roster.proposal().records()[roster.proposal().organizer_position()];
        if !verify_close_signature(
            &organizer.header().signing_public,
            ClosePurpose::Intent,
            message.identity(),
            signature,
        ) {
            return Err(Error::Crypto);
        }
        self.lock_intent(message)
    }
    /// One response to the locked intent. A locked ballot attempt must first
    /// complete, and the participant's own on-time ballot must be listed.
    pub fn sign_close_response(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &CloseResponseMessage,
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        self.check_close_owner(owner, roster, message.poll(), message.inventory())?;
        self.check_unlocked(SigningPurpose::CloseResponse)?;
        if self.close_response.is_some() {
            return Err(Error::Consumed);
        }
        let (intent, close_time) = self.close_lock.ok_or(Error::Context)?;
        if message.responder() != owner.position()
            || *message.intent() != intent
            || (self.ballot_attempted && self.signed_ballot.is_none())
            || self.signed_ballot.is_some_and(|(identity, time)| {
                time <= close_time && !message.listed().contains(&(owner.position(), identity))
            })
        {
            return Err(Error::Context);
        }
        self.close_response = Some(*message.identity());
        self.sign_close(ClosePurpose::Response, message.identity(), coins)
    }
    /// The organizer's one proposal, which must name its locked intent and
    /// include its own response.
    pub fn sign_close_proposal(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &CloseProposalMessage,
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        self.check_close_owner(owner, roster, message.poll(), message.inventory())?;
        Self::check_organizer(owner, roster)?;
        self.check_unlocked(SigningPurpose::CloseProposal)?;
        if self.close_proposal_signed {
            return Err(Error::Consumed);
        }
        let own = self.close_response.ok_or(Error::Context)?;
        if !self.close_intent_signed
            || self.close_lock.map(|(identity, _)| identity) != Some(*message.intent())
            || !message.responses().contains(&(owner.position(), own))
        {
            return Err(Error::Context);
        }
        self.close_proposal_signed = true;
        self.sign_close(ClosePurpose::Proposal, message.identity(), coins)
    }
    /// Reconstructs consumed close state only from the original root's
    /// authenticated completed message and its signature. It is not a receipt
    /// for unused authority. A response requires its intent to be locked first.
    pub fn restore_close_message(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: CloseMessage<'_>,
        signature: &[u8],
    ) -> Result<(), Error> {
        match message {
            CloseMessage::Intent(message) => {
                self.check_close_owner(owner, roster, message.poll(), message.inventory())?;
                Self::check_organizer(owner, roster)?;
                if self.close_intent_signed {
                    return Err(Error::Consumed);
                }
                self.check_own_signature(ClosePurpose::Intent, message.identity(), signature)?;
                self.lock_intent(message)?;
                self.close_intent_signed = true;
            }
            CloseMessage::Response(message) => {
                self.check_close_owner(owner, roster, message.poll(), message.inventory())?;
                if self.close_response.is_some() {
                    return Err(Error::Consumed);
                }
                if message.responder() != owner.position()
                    || self.close_lock.map(|(identity, _)| identity) != Some(*message.intent())
                {
                    return Err(Error::Context);
                }
                self.check_own_signature(ClosePurpose::Response, message.identity(), signature)?;
                self.close_response = Some(*message.identity());
            }
            CloseMessage::Proposal(message) => {
                self.check_close_owner(owner, roster, message.poll(), message.inventory())?;
                Self::check_organizer(owner, roster)?;
                if self.close_proposal_signed {
                    return Err(Error::Consumed);
                }
                if self.close_lock.map(|(identity, _)| identity) != Some(*message.intent()) {
                    return Err(Error::Context);
                }
                self.check_own_signature(ClosePurpose::Proposal, message.identity(), signature)?;
                self.close_proposal_signed = true;
            }
        }
        Ok(())
    }
    /// The identity of this participant's signed close response, if any.
    pub fn close_response_identity(&self) -> Option<&[u8; 64]> {
        self.close_response.as_ref()
    }
    /// The identity and ballot time of this participant's signed ballot, if any.
    pub fn signed_ballot(&self) -> Option<&([u8; 64], u64)> {
        self.signed_ballot.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(value: u8) -> [u8; 64] {
        [value; 64]
    }
    #[test]
    fn quorum_and_maximum_lengths_follow_the_roster() {
        for (participants, quorum) in [(3, 3), (4, 3), (6, 5), (7, 5), (10, 7), (13, 9), (20, 14)] {
            assert_eq!(close_quorum(participants), quorum);
        }
        for participants in 3..=20 {
            let listed: Vec<_> = (0..participants)
                .flat_map(|author| [(author, identity(1)), (author, identity(2))])
                .collect();
            let response = CloseResponseMessage::new(
                identity(7),
                identity(8),
                identity(9),
                0,
                participants,
                &listed,
            )
            .unwrap();
            assert_eq!(
                response.body().len(),
                maximum_close_message_bytes(ClosePurpose::Response, participants)
            );
            let responses: Vec<_> = (0..close_quorum(participants))
                .map(|responder| (responder, identity(3)))
                .collect();
            let proposal = CloseProposalMessage::new(
                identity(7),
                identity(8),
                identity(9),
                participants,
                0,
                &responses,
            )
            .unwrap();
            assert_eq!(
                proposal.body().len(),
                maximum_close_message_bytes(ClosePurpose::Proposal, participants)
            );
        }
        let intent = CloseIntentMessage::new(identity(7), identity(8), u64::MAX).unwrap();
        assert_eq!(
            intent.body().len(),
            maximum_close_message_bytes(ClosePurpose::Intent, 3)
        );
        assert_eq!(intent.close_time(), u64::MAX);
        assert_eq!(
            CloseIntentMessage::parse(intent.body()).unwrap().identity(),
            intent.identity()
        );
    }
    #[test]
    fn response_listings_are_canonical_and_capped_per_slot() {
        let make = |listed: &[(usize, [u8; 64])]| {
            CloseResponseMessage::new(identity(7), identity(8), identity(9), 1, 4, listed)
        };
        let valid = make(&[(0, identity(1)), (0, identity(2)), (3, identity(1))]).unwrap();
        assert_eq!(valid.responder(), 1);
        assert_eq!(valid.listed().len(), 3);
        assert!(make(&[]).unwrap().listed().is_empty());
        for refused in [
            vec![(0, identity(2)), (0, identity(1))],
            vec![(3, identity(1)), (0, identity(1))],
            vec![(0, identity(1)), (0, identity(1))],
            vec![(0, identity(1)), (0, identity(2)), (0, identity(3))],
            vec![(4, identity(1))],
        ] {
            assert!(make(&refused).is_err(), "{refused:?}");
        }
        assert!(
            CloseResponseMessage::new(identity(7), identity(8), identity(9), 4, 4, &[]).is_err()
        );
        let mut truncated = valid.body().to_vec();
        truncated.pop();
        assert!(CloseResponseMessage::parse(&truncated, 4).is_err());
        let mut extended = valid.body().to_vec();
        extended.push(0);
        assert!(CloseResponseMessage::parse(&extended, 4).is_err());
        assert!(CloseResponseMessage::parse(valid.body(), 3).is_err());
        assert!(CloseIntentMessage::parse(valid.body()).is_err());
        assert!(CloseProposalMessage::parse(valid.body(), 4, 0).is_err());
    }
    #[test]
    fn proposals_carry_exactly_the_quorum_including_the_organizer() {
        let make = |responses: &[(usize, [u8; 64])], organizer| {
            CloseProposalMessage::new(
                identity(7),
                identity(8),
                identity(9),
                10,
                organizer,
                responses,
            )
        };
        let quorum: Vec<_> = (0..7).map(|responder| (responder, identity(3))).collect();
        assert!(make(&quorum, 0).is_ok());
        assert!(make(&quorum, 6).is_ok());
        assert!(make(&quorum, 7).is_err());
        assert!(make(&quorum[..6], 0).is_err());
        let mut extra = quorum.clone();
        extra.push((7, identity(3)));
        assert!(make(&extra, 0).is_err());
        let mut repeated = quorum.clone();
        repeated[1] = (0, identity(4));
        assert!(make(&repeated, 0).is_err());
        let mut unordered = quorum;
        unordered.swap(1, 2);
        assert!(make(&unordered, 0).is_err());
    }
    #[test]
    fn signatures_bind_the_purpose_context() {
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&[9; 32]);
        let public = public.into_bytes();
        let intent = CloseIntentMessage::new(identity(7), identity(8), 5).unwrap();
        let signature = private
            .try_sign_with_seed(
                &[10; 32],
                intent.identity(),
                ClosePurpose::Intent.context().as_bytes(),
            )
            .unwrap();
        assert!(verify_close_signature(
            &public,
            ClosePurpose::Intent,
            intent.identity(),
            &signature
        ));
        assert!(!verify_close_signature(
            &public,
            ClosePurpose::Response,
            intent.identity(),
            &signature
        ));
        assert!(!verify_close_signature(
            &public,
            ClosePurpose::Intent,
            &identity(1),
            &signature
        ));
        assert!(!verify_close_signature(
            &public,
            ClosePurpose::Intent,
            intent.identity(),
            &signature[1..]
        ));
        let later = CloseIntentMessage::new(identity(7), identity(8), 6).unwrap();
        assert_ne!(later.identity(), intent.identity());
    }
}
