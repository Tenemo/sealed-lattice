use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, Hash512, RefusalReason,
};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{read_hash, read_u16, read_u64, require_tuple},
    field::PARTICIPANT_COUNT,
    mailbox::{MailboxStreamKind, VerifiedMailboxEnvelope},
    protocol_oracle::protocol_oracle_512,
};

const LOCAL_STATE_SCHEMA_IDENTIFIER: u16 = 0x0230;
const LOCAL_STATE_SCHEMA_VERSION: u16 = 1;
const PUBLICATION_KIND_COUNT: usize = 8;
const OBSERVATION_KIND_COUNT: usize = 9;
const MAILBOX_KIND_COUNT: usize = 2;
const BASE_ITEM_COUNT: usize = 12;
const LOCAL_STATE_ITEM_COUNT: usize = BASE_ITEM_COUNT
    + PUBLICATION_KIND_COUNT * 2
    + OBSERVATION_KIND_COUNT * 2
    + MAILBOX_KIND_COUNT * PARTICIPANT_COUNT * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum PublicationKind {
    PreparationContribution = 0,
    PreparationChallengeOpening = 1,
    PreparationResponse = 2,
    SourceContribution = 3,
    SourceChallengeOpening = 4,
    SourceResponse = 5,
    FinalitySignature = 6,
    Activation = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum ObservationKind {
    PreparationCandidateInventory = 0,
    PreparationChallengeInventory = 1,
    PreparationTerminal = 2,
    SourceCandidateInventory = 3,
    SourceChallengeInventory = 4,
    SourceTerminal = 5,
    FinalityCertificate = 6,
    ActivationInventory = 7,
    ResultTerminal = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StateTransition {
    Fresh,
    SemanticReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalStateContext {
    pub(crate) suite_identity: Hash512,
    pub(crate) build_identity: Hash512,
    pub(crate) action_identity: Hash512,
    pub(crate) roster_identity: Hash512,
    pub(crate) circuit_identity: Hash512,
    pub(crate) action_predecessor_identity: Hash512,
    pub(crate) attempt_ordinal: u64,
    pub(crate) output_ordinal: u64,
    pub(crate) participant_position: u16,
}

pub(crate) struct ActionLocalState {
    context: LocalStateContext,
    generation: u64,
    previous_checkpoint_identity: Option<Hash512>,
    publication_locks: [Option<Hash512>; PUBLICATION_KIND_COUNT],
    observations: [Option<Hash512>; OBSERVATION_KIND_COUNT],
    mailbox_locks: [[Option<Hash512>; PARTICIPANT_COUNT]; MAILBOX_KIND_COUNT],
}

impl core::fmt::Debug for ActionLocalState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ActionLocalState")
            .field("context", &self.context)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl ActionLocalState {
    pub(crate) fn new(context: LocalStateContext) -> ProtocolResult<Self> {
        if usize::from(context.participant_position) >= PARTICIPANT_COUNT {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "local-state participant position is outside the roster",
            ));
        }
        Ok(Self {
            context,
            generation: 0,
            previous_checkpoint_identity: None,
            publication_locks: [None; PUBLICATION_KIND_COUNT],
            observations: [None; OBSERVATION_KIND_COUNT],
            mailbox_locks: [[None; PARTICIPANT_COUNT]; MAILBOX_KIND_COUNT],
        })
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn lock_publication(
        &mut self,
        kind: PublicationKind,
        semantic_identity: Hash512,
    ) -> ProtocolResult<StateTransition> {
        self.require_publication_predecessor(kind)?;
        let index = kind as usize;
        match self.publication_locks[index] {
            Some(identity) if identity == semantic_identity => Ok(StateTransition::SemanticReplay),
            Some(_) => Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "one-shot publication is already locked to another semantic value",
            )),
            None => {
                self.advance_checkpoint_chain()?;
                self.publication_locks[index] = Some(semantic_identity);
                Ok(StateTransition::Fresh)
            }
        }
    }

    pub(crate) fn observe(
        &mut self,
        kind: ObservationKind,
        semantic_identity: Hash512,
    ) -> ProtocolResult<StateTransition> {
        self.require_observation_predecessor(kind)?;
        let index = kind as usize;
        match self.observations[index] {
            Some(identity) if identity == semantic_identity => Ok(StateTransition::SemanticReplay),
            Some(_) => Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "verified transcript observation is already locked to another value",
            )),
            None => {
                self.advance_checkpoint_chain()?;
                self.observations[index] = Some(semantic_identity);
                Ok(StateTransition::Fresh)
            }
        }
    }

    pub(crate) fn lock_verified_mailbox(
        &mut self,
        verified: &VerifiedMailboxEnvelope,
    ) -> ProtocolResult<StateTransition> {
        let mailbox_context = verified.context();
        let expected_phase_predecessor_identity = match mailbox_context.stream_kind {
            MailboxStreamKind::Preparation => self.context.action_predecessor_identity,
            MailboxStreamKind::Source => self.observations
                [ObservationKind::PreparationTerminal as usize]
                .ok_or_else(|| {
                    ProtocolRefusal::new(
                        RefusalReason::WrongContext,
                        "source mailbox arrived before the preparation terminal",
                    )
                })?,
        };
        if mailbox_context.suite_identity != self.context.suite_identity
            || mailbox_context.build_identity != self.context.build_identity
            || mailbox_context.action_identity != self.context.action_identity
            || mailbox_context.roster_identity != self.context.roster_identity
            || mailbox_context.circuit_identity != self.context.circuit_identity
            || mailbox_context.action_predecessor_identity
                != self.context.action_predecessor_identity
            || mailbox_context.phase_predecessor_identity != expected_phase_predecessor_identity
            || mailbox_context.attempt_ordinal != self.context.attempt_ordinal
            || mailbox_context.output_ordinal != self.context.output_ordinal
            || mailbox_context.recipient_position != self.context.participant_position
            || usize::from(mailbox_context.sender_position) >= PARTICIPANT_COUNT
            || mailbox_context.stream_ordinal != 0
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "verified mailbox does not match the local action slot",
            ));
        }
        let mailbox_kind = match mailbox_context.stream_kind {
            MailboxStreamKind::Preparation => 0,
            MailboxStreamKind::Source => 1,
        };
        self.require_mailbox_window(mailbox_context.stream_kind)?;
        let sender_position = usize::from(mailbox_context.sender_position);
        let body_identity = verified.body_identity();
        match self.mailbox_locks[mailbox_kind][sender_position] {
            Some(identity) if identity == body_identity => Ok(StateTransition::SemanticReplay),
            Some(_) => Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "mailbox slot is already consumed by another authenticated carrier",
            )),
            None => {
                self.advance_checkpoint_chain()?;
                self.mailbox_locks[mailbox_kind][sender_position] = Some(body_identity);
                Ok(StateTransition::Fresh)
            }
        }
    }

    pub(crate) fn encode_checkpoint(&self) -> ProtocolResult<Vec<u8>> {
        let mut items = Vec::with_capacity(LOCAL_STATE_ITEM_COUNT);
        items.extend([
            hash_item(self.context.suite_identity),
            hash_item(self.context.build_identity),
            hash_item(self.context.action_identity),
            hash_item(self.context.roster_identity),
            hash_item(self.context.circuit_identity),
            hash_item(self.context.action_predecessor_identity),
            CanonicalItem::unsigned64(self.context.attempt_ordinal),
            CanonicalItem::unsigned64(self.context.output_ordinal),
            CanonicalItem::unsigned16(self.context.participant_position),
            CanonicalItem::unsigned64(self.generation),
        ]);
        push_optional_hash(&mut items, self.previous_checkpoint_identity);
        for lock in self.publication_locks {
            push_optional_hash(&mut items, lock);
        }
        for observation in self.observations {
            push_optional_hash(&mut items, observation);
        }
        for mailbox_kind in self.mailbox_locks {
            for lock in mailbox_kind {
                push_optional_hash(&mut items, lock);
            }
        }
        debug_assert_eq!(items.len(), LOCAL_STATE_ITEM_COUNT);
        Ok(CanonicalTuple::new(
            LOCAL_STATE_SCHEMA_IDENTIFIER,
            LOCAL_STATE_SCHEMA_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn checkpoint_identity(&self) -> ProtocolResult<Hash512> {
        checkpoint_identity(&self.encode_checkpoint()?)
    }

    pub(crate) fn restore(
        checkpoint_bytes: &[u8],
        expected_context: LocalStateContext,
        minimum_generation: u64,
        expected_checkpoint_identity: Option<Hash512>,
    ) -> ProtocolResult<Self> {
        if let Some(expected_identity) = expected_checkpoint_identity
            && checkpoint_identity(checkpoint_bytes)? != expected_identity
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "local checkpoint identity does not match the durable anchor",
            ));
        }
        let tuple = CanonicalTuple::decode(checkpoint_bytes, &CanonicalDecodeLimits::default())?;
        require_tuple(
            &tuple,
            LOCAL_STATE_SCHEMA_IDENTIFIER,
            LOCAL_STATE_SCHEMA_VERSION,
            LOCAL_STATE_ITEM_COUNT,
        )?;
        let context = LocalStateContext {
            suite_identity: read_hash(&tuple.items[0])?,
            build_identity: read_hash(&tuple.items[1])?,
            action_identity: read_hash(&tuple.items[2])?,
            roster_identity: read_hash(&tuple.items[3])?,
            circuit_identity: read_hash(&tuple.items[4])?,
            action_predecessor_identity: read_hash(&tuple.items[5])?,
            attempt_ordinal: read_u64(&tuple.items[6])?,
            output_ordinal: read_u64(&tuple.items[7])?,
            participant_position: read_u16(&tuple.items[8])?,
        };
        if context != expected_context
            || usize::from(context.participant_position) >= PARTICIPANT_COUNT
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "local checkpoint does not match the expected participant context",
            ));
        }
        let generation = read_u64(&tuple.items[9])?;
        if generation < minimum_generation {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "local checkpoint is older than the durable generation anchor",
            ));
        }
        let mut cursor = 10;
        let previous_checkpoint_identity = read_optional_hash(&tuple.items, &mut cursor)?;
        let publication_locks = read_optional_hash_array(&tuple.items, &mut cursor)?;
        let observations = read_optional_hash_array(&tuple.items, &mut cursor)?;
        let mailbox_locks = (0..MAILBOX_KIND_COUNT)
            .map(|_| read_optional_hash_array(&tuple.items, &mut cursor))
            .collect::<ProtocolResult<Vec<_>>>()?
            .try_into()
            .map_err(|_| malformed_checkpoint())?;
        if cursor != tuple.items.len() {
            return Err(ProtocolRefusal::new(
                RefusalReason::MalformedEncoding,
                "local checkpoint contains trailing state fields",
            ));
        }
        let state = Self {
            context,
            generation,
            previous_checkpoint_identity,
            publication_locks,
            observations,
            mailbox_locks,
        };
        state.verify_internal_consistency()?;
        Ok(state)
    }

    fn require_publication_predecessor(&self, kind: PublicationKind) -> ProtocolResult<()> {
        let ready = match kind {
            PublicationKind::PreparationContribution => true,
            PublicationKind::PreparationChallengeOpening => {
                self.publication_locks[PublicationKind::PreparationContribution as usize].is_some()
                    && self.observations[ObservationKind::PreparationCandidateInventory as usize]
                        .is_some()
            }
            PublicationKind::PreparationResponse => {
                self.publication_locks[PublicationKind::PreparationChallengeOpening as usize]
                    .is_some()
                    && self.observations[ObservationKind::PreparationChallengeInventory as usize]
                        .is_some()
            }
            PublicationKind::SourceContribution => {
                self.observations[ObservationKind::PreparationTerminal as usize].is_some()
            }
            PublicationKind::SourceChallengeOpening => {
                self.publication_locks[PublicationKind::SourceContribution as usize].is_some()
                    && self.observations[ObservationKind::SourceCandidateInventory as usize]
                        .is_some()
            }
            PublicationKind::SourceResponse => {
                self.publication_locks[PublicationKind::SourceChallengeOpening as usize].is_some()
                    && self.observations[ObservationKind::SourceChallengeInventory as usize]
                        .is_some()
            }
            PublicationKind::FinalitySignature => {
                self.observations[ObservationKind::SourceTerminal as usize].is_some()
            }
            PublicationKind::Activation => {
                self.observations[ObservationKind::FinalityCertificate as usize].is_some()
            }
        };
        if !ready {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "publication predecessor has not been positively verified",
            ));
        }
        Ok(())
    }

    fn require_observation_predecessor(&self, kind: ObservationKind) -> ProtocolResult<()> {
        let ready = match kind {
            ObservationKind::PreparationCandidateInventory => {
                self.publication_locks[PublicationKind::PreparationContribution as usize].is_some()
            }
            ObservationKind::PreparationChallengeInventory => self.publication_locks
                [PublicationKind::PreparationChallengeOpening as usize]
                .is_some(),
            ObservationKind::PreparationTerminal => {
                self.publication_locks[PublicationKind::PreparationResponse as usize].is_some()
            }
            ObservationKind::SourceCandidateInventory => {
                self.publication_locks[PublicationKind::SourceContribution as usize].is_some()
            }
            ObservationKind::SourceChallengeInventory => {
                self.publication_locks[PublicationKind::SourceChallengeOpening as usize].is_some()
            }
            ObservationKind::SourceTerminal => {
                self.publication_locks[PublicationKind::SourceResponse as usize].is_some()
            }
            ObservationKind::FinalityCertificate => {
                self.observations[ObservationKind::SourceTerminal as usize].is_some()
            }
            ObservationKind::ActivationInventory => {
                self.publication_locks[PublicationKind::Activation as usize].is_some()
            }
            ObservationKind::ResultTerminal => {
                self.observations[ObservationKind::ActivationInventory as usize].is_some()
            }
        };
        if !ready {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "transcript observation predecessor has not been completed",
            ));
        }
        Ok(())
    }

    fn require_mailbox_window(&self, kind: MailboxStreamKind) -> ProtocolResult<()> {
        let open = match kind {
            MailboxStreamKind::Preparation => self.publication_locks
                [PublicationKind::PreparationChallengeOpening as usize]
                .is_none(),
            MailboxStreamKind::Source => {
                self.observations[ObservationKind::PreparationTerminal as usize].is_some()
                    && self.publication_locks[PublicationKind::SourceChallengeOpening as usize]
                        .is_none()
            }
        };
        if !open {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "mailbox stream arrived outside its one-shot verification window",
            ));
        }
        Ok(())
    }

    fn advance_checkpoint_chain(&mut self) -> ProtocolResult<()> {
        self.previous_checkpoint_identity = Some(self.checkpoint_identity()?);
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "local checkpoint generation overflows",
            )
        })?;
        Ok(())
    }

    fn verify_internal_consistency(&self) -> ProtocolResult<()> {
        let present_count = self
            .publication_locks
            .iter()
            .chain(self.observations.iter())
            .chain(self.mailbox_locks.iter().flatten())
            .filter(|value| value.is_some())
            .count();
        if self.generation != present_count as u64
            || (self.generation == 0) != self.previous_checkpoint_identity.is_none()
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::MalformedEncoding,
                "local checkpoint generation does not match its one-shot state",
            ));
        }
        for publication in [
            PublicationKind::PreparationChallengeOpening,
            PublicationKind::PreparationResponse,
            PublicationKind::SourceContribution,
            PublicationKind::SourceChallengeOpening,
            PublicationKind::SourceResponse,
            PublicationKind::FinalitySignature,
            PublicationKind::Activation,
        ] {
            if self.publication_locks[publication as usize].is_some() {
                self.require_publication_predecessor(publication)?;
            }
        }
        for observation in [
            ObservationKind::PreparationCandidateInventory,
            ObservationKind::PreparationChallengeInventory,
            ObservationKind::PreparationTerminal,
            ObservationKind::SourceCandidateInventory,
            ObservationKind::SourceChallengeInventory,
            ObservationKind::SourceTerminal,
            ObservationKind::FinalityCertificate,
            ObservationKind::ActivationInventory,
            ObservationKind::ResultTerminal,
        ] {
            if self.observations[observation as usize].is_some() {
                self.require_observation_predecessor(observation)?;
            }
        }
        Ok(())
    }
}

fn checkpoint_identity(bytes: &[u8]) -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/local-checkpoint/v1",
        &[CanonicalItem::variable_bytes(bytes)?],
    )
}

fn push_optional_hash(items: &mut Vec<CanonicalItem>, value: Option<Hash512>) {
    items.push(CanonicalItem::unsigned16(u16::from(value.is_some())));
    items.push(hash_item(
        value.unwrap_or_else(|| Hash512::from_bytes([0; 64])),
    ));
}

fn read_optional_hash(
    items: &[CanonicalItem],
    cursor: &mut usize,
) -> ProtocolResult<Option<Hash512>> {
    let present = read_u16(items.get(*cursor).ok_or_else(malformed_checkpoint)?)?;
    let hash = read_hash(items.get(*cursor + 1).ok_or_else(malformed_checkpoint)?)?;
    *cursor += 2;
    match present {
        0 if hash == Hash512::from_bytes([0; 64]) => Ok(None),
        1 => Ok(Some(hash)),
        _ => Err(malformed_checkpoint()),
    }
}

fn read_optional_hash_array<const COUNT: usize>(
    items: &[CanonicalItem],
    cursor: &mut usize,
) -> ProtocolResult<[Option<Hash512>; COUNT]> {
    let mut values = [None; COUNT];
    for value in &mut values {
        *value = read_optional_hash(items, cursor)?;
    }
    Ok(values)
}

fn malformed_checkpoint() -> ProtocolRefusal {
    ProtocolRefusal::new(
        RefusalReason::MalformedEncoding,
        "local checkpoint optional field is not canonical",
    )
}

fn hash_item(hash: Hash512) -> CanonicalItem {
    CanonicalItem::hash512(hash.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::{
        mailbox::{
            MailboxStreamContext, open_verified_mailbox_envelope, seal_mailbox_stream,
            verify_mailbox_envelope,
        },
        roster_signature::{
            ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH, ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH,
            generate_roster_signature_keypair,
        },
    };
    use fips203::{
        ml_kem_768,
        traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
    };

    fn hash(marker: u8) -> Hash512 {
        Hash512::from_bytes([marker; 64])
    }

    fn context() -> LocalStateContext {
        LocalStateContext {
            suite_identity: hash(1),
            build_identity: hash(2),
            action_identity: hash(3),
            roster_identity: hash(4),
            circuit_identity: hash(5),
            action_predecessor_identity: hash(6),
            attempt_ordinal: 3,
            output_ordinal: 0,
            participant_position: 7,
        }
    }

    fn complete_prefinality(state: &mut ActionLocalState) {
        state
            .lock_publication(PublicationKind::PreparationContribution, hash(10))
            .unwrap();
        state
            .observe(ObservationKind::PreparationCandidateInventory, hash(11))
            .unwrap();
        state
            .lock_publication(PublicationKind::PreparationChallengeOpening, hash(12))
            .unwrap();
        state
            .observe(ObservationKind::PreparationChallengeInventory, hash(13))
            .unwrap();
        state
            .lock_publication(PublicationKind::PreparationResponse, hash(14))
            .unwrap();
        state
            .observe(ObservationKind::PreparationTerminal, hash(15))
            .unwrap();
        state
            .lock_publication(PublicationKind::SourceContribution, hash(16))
            .unwrap();
        state
            .observe(ObservationKind::SourceCandidateInventory, hash(17))
            .unwrap();
        state
            .lock_publication(PublicationKind::SourceChallengeOpening, hash(18))
            .unwrap();
        state
            .observe(ObservationKind::SourceChallengeInventory, hash(19))
            .unwrap();
        state
            .lock_publication(PublicationKind::SourceResponse, hash(20))
            .unwrap();
        state
            .observe(ObservationKind::SourceTerminal, hash(21))
            .unwrap();
    }

    #[test]
    fn ordered_locks_checkpoint_and_restore_through_result_terminal() {
        let mut state = ActionLocalState::new(context()).unwrap();
        complete_prefinality(&mut state);
        state
            .lock_publication(PublicationKind::FinalitySignature, hash(22))
            .unwrap();
        state
            .observe(ObservationKind::FinalityCertificate, hash(23))
            .unwrap();
        state
            .lock_publication(PublicationKind::Activation, hash(24))
            .unwrap();
        state
            .observe(ObservationKind::ActivationInventory, hash(25))
            .unwrap();
        state
            .observe(ObservationKind::ResultTerminal, hash(26))
            .unwrap();
        let bytes = state.encode_checkpoint().unwrap();
        let identity = state.checkpoint_identity().unwrap();
        let restored =
            ActionLocalState::restore(&bytes, context(), state.generation(), Some(identity))
                .expect("current checkpoint cold-restores");
        assert_eq!(restored.generation(), state.generation());
        assert_eq!(restored.encode_checkpoint().unwrap(), bytes);
    }

    #[test]
    fn byte_identical_replay_is_idempotent_and_conflict_or_early_release_refuses() {
        let mut state = ActionLocalState::new(context()).unwrap();
        assert!(
            state
                .lock_publication(PublicationKind::Activation, hash(30))
                .is_err()
        );
        assert_eq!(
            state
                .lock_publication(PublicationKind::PreparationContribution, hash(31))
                .unwrap(),
            StateTransition::Fresh
        );
        let generation = state.generation();
        assert_eq!(
            state
                .lock_publication(PublicationKind::PreparationContribution, hash(31))
                .unwrap(),
            StateTransition::SemanticReplay
        );
        assert_eq!(state.generation(), generation);
        assert!(
            state
                .lock_publication(PublicationKind::PreparationContribution, hash(32))
                .is_err()
        );
    }

    #[test]
    fn authenticated_mailbox_slot_is_persisted_before_decapsulation_and_never_retried() {
        let (encapsulation_key, decapsulation_key) =
            ml_kem_768::KG::keygen_from_seed([0x21; 32], [0x72; 32]);
        let (verification_key, signing_key) =
            generate_roster_signature_keypair([0x43; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        let encapsulation_key = encapsulation_key.into_bytes();
        let decapsulation_key = decapsulation_key.into_bytes();
        let mailbox_context = MailboxStreamContext {
            suite_identity: context().suite_identity,
            build_identity: context().build_identity,
            action_identity: context().action_identity,
            roster_identity: context().roster_identity,
            circuit_identity: context().circuit_identity,
            action_predecessor_identity: context().action_predecessor_identity,
            phase_predecessor_identity: context().action_predecessor_identity,
            attempt_ordinal: context().attempt_ordinal,
            sender_position: 2,
            recipient_position: context().participant_position,
            stream_kind: MailboxStreamKind::Preparation,
            stream_ordinal: 0,
            output_ordinal: context().output_ordinal,
        };
        let carrier = seal_mailbox_stream(
            mailbox_context,
            &encapsulation_key,
            &signing_key,
            &verification_key,
            [0x55; 32],
            [0x66; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            b"private coordinates",
        )
        .unwrap();
        let verified = verify_mailbox_envelope(
            mailbox_context,
            &encapsulation_key,
            &verification_key,
            &carrier,
        )
        .unwrap();
        let mut state = ActionLocalState::new(context()).unwrap();
        assert_eq!(
            state.lock_verified_mailbox(&verified).unwrap(),
            StateTransition::Fresh
        );
        let checkpoint = state.encode_checkpoint().unwrap();
        let checkpoint_identity = state.checkpoint_identity().unwrap();
        let opened = open_verified_mailbox_envelope(verified, &decapsulation_key)
            .expect("persisted verified envelope opens");
        assert_eq!(opened.as_bytes(), b"private coordinates");

        let mut restored = ActionLocalState::restore(
            &checkpoint,
            context(),
            state.generation(),
            Some(checkpoint_identity),
        )
        .unwrap();
        let alternate_signature_carrier = seal_mailbox_stream(
            mailbox_context,
            &encapsulation_key,
            &signing_key,
            &verification_key,
            [0x55; 32],
            [0x67; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            b"private coordinates",
        )
        .unwrap();
        let replay = verify_mailbox_envelope(
            mailbox_context,
            &encapsulation_key,
            &verification_key,
            &alternate_signature_carrier,
        )
        .unwrap();
        assert_eq!(
            restored.lock_verified_mailbox(&replay).unwrap(),
            StateTransition::SemanticReplay
        );

        let conflicting_carrier = seal_mailbox_stream(
            mailbox_context,
            &encapsulation_key,
            &signing_key,
            &verification_key,
            [0x75; 32],
            [0x86; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            b"different private coordinates",
        )
        .unwrap();
        let conflicting = verify_mailbox_envelope(
            mailbox_context,
            &encapsulation_key,
            &verification_key,
            &conflicting_carrier,
        )
        .unwrap();
        assert!(restored.lock_verified_mailbox(&conflicting).is_err());
    }

    #[test]
    fn stale_mutated_and_wrong_context_checkpoints_refuse() {
        let mut state = ActionLocalState::new(context()).unwrap();
        let initial = state.encode_checkpoint().unwrap();
        state
            .lock_publication(PublicationKind::PreparationContribution, hash(40))
            .unwrap();
        let current = state.encode_checkpoint().unwrap();
        assert!(ActionLocalState::restore(&initial, context(), 1, None).is_err());

        let mut mutated = current.clone();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        assert!(ActionLocalState::restore(&mutated, context(), 0, None).is_err());

        let wrong_context = LocalStateContext {
            action_identity: hash(99),
            ..context()
        };
        assert!(ActionLocalState::restore(&current, wrong_context, 0, None).is_err());
    }
}
