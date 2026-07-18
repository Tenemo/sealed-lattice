use core::fmt;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[cfg(test)]
use super::schemas::AGGREGATE_PAYLOAD_SCHEMA_IDENTIFIER;
use super::schemas::{AggregatePayload, EvaluatorReplayPayload};
use super::{
    CanonicalCodecError, CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem,
    CanonicalItemType, CanonicalTuple, FINALITY_SIGNATURE_PAYLOAD_SCHEMA_IDENTIFIER,
    FOUNDATION_PROFILE, FoundationObjectType, FoundationSchemaError, Hash512, ObjectEnvelope,
    ParticipantIdentity, RefusalReason, Roster, SignedCarrier, StateCapabilityKind, StateError,
    StateOutputIntentPayload, StateReservationIntentPayload, StateWitnessVoteKind,
    StateWitnessVotePayload, StorageRootCommitmentPayload, StreamDescriptor, VerificationResult,
    derive_state_key, derive_state_witness_vote_sequence,
};

pub(crate) const FOUNDATION_SCHEMA_VERSION: u16 = 1;
pub(crate) const SETUP_INTENT_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1200;
pub(crate) const PUBLIC_RANDOMNESS_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1201;
pub(crate) const PUBLIC_RANDOMNESS_REVEAL_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1202;
pub(crate) const PRIVATE_SHARE_ACCEPTANCE_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1203;
const COMPLAINT_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1204;
pub(crate) const DEALER_PUBLIC_RECORD_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x2100;
pub(super) const BALLOT_PACKAGE_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1301;
const TARGET_DECRYPTION_SHARE_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1620;
pub(crate) const MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT: u32 = 4_096;

/// Suite-owned multiplicity limits and independent runtime safety bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalBoardLimits {
    pub maximum_ballot_attempts_per_participant: u64,
    pub maximum_retained_canonical_carrier_byte_length: u64,
    pub maximum_unordered_carriers_per_batch: u32,
    pub maximum_retained_transcript_objects: u32,
}

impl CanonicalBoardLimits {
    fn validate(self) -> BoardResult<()> {
        if self.maximum_ballot_attempts_per_participant == 0
            || self.maximum_retained_canonical_carrier_byte_length == 0
            || self.maximum_unordered_carriers_per_batch == 0
            || self.maximum_retained_transcript_objects == 0
        {
            return Err(CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "canonical-board limits must be positive",
            ));
        }
        if self.maximum_unordered_carriers_per_batch > self.maximum_retained_transcript_objects {
            return Err(CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "canonical-board batch capacity exceeds retained-object capacity",
            ));
        }
        if self.maximum_unordered_carriers_per_batch > MAXIMUM_CANONICAL_BOARD_BATCH_CARRIER_COUNT {
            return Err(CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "canonical-board batch capacity exceeds the runtime maximum",
            ));
        }
        if self.maximum_ballot_attempts_per_participant > u64::from(u16::MAX) {
            return Err(CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "canonical-board suite limits exceed the version-one field widths",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBoardError {
    pub refusal_reason: RefusalReason,
    pub message: &'static str,
}

impl CanonicalBoardError {
    const fn new(refusal_reason: RefusalReason, message: &'static str) -> Self {
        Self {
            refusal_reason,
            message,
        }
    }

    fn missing_prerequisite() -> Self {
        Self::new(
            RefusalReason::MissingPrerequisite,
            "canonical-board verification lacks a typed prerequisite",
        )
    }
}

impl fmt::Display for CanonicalBoardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for CanonicalBoardError {}

impl From<CanonicalCodecError> for CanonicalBoardError {
    fn from(error: CanonicalCodecError) -> Self {
        let refusal_reason = if error.kind == CanonicalCodecErrorKind::LimitExceeded {
            RefusalReason::OutsideSupportedProfile
        } else {
            RefusalReason::MalformedEncoding
        };
        Self::new(refusal_reason, "canonical-board bytes are not canonical")
    }
}

impl From<FoundationSchemaError> for CanonicalBoardError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::new(error.refusal_reason, error.message)
    }
}

impl From<StateError> for CanonicalBoardError {
    fn from(error: StateError) -> Self {
        Self::new(error.refusal_reason, error.message)
    }
}

type BoardResult<Value> = Result<Value, CanonicalBoardError>;

/// A non-serializable foundation-object capability minted after canonical parsing,
/// context binding, typed dependency resolution, and roster-signature authentication
/// for every signed family.
///
/// This capability does not imply verification of an owning setup, ballot, proof,
/// evaluator, finality, or decryption relation.
#[derive(Clone)]
pub struct VerifiedTranscriptObject {
    inner: Arc<VerifiedTranscriptObjectData>,
}

impl VerifiedTranscriptObject {
    pub fn object_hash(&self) -> Hash512 {
        self.inner.object_hash
    }

    pub fn object_type(&self) -> FoundationObjectType {
        self.inner.envelope.object_type
    }

    pub fn producer_participant_id(&self) -> Option<ParticipantIdentity> {
        self.inner.envelope.producer_participant_id
    }

    pub fn producer_sequence(&self) -> u64 {
        self.inner.envelope.producer_sequence
    }

    /// Returns the first authenticated carrier retained for byte-identical replay.
    pub fn canonical_carrier_bytes(&self) -> &[u8] {
        &self.inner.canonical_carrier_bytes
    }

    pub(crate) fn envelope(&self) -> &ObjectEnvelope {
        &self.inner.envelope
    }
}

impl fmt::Debug for VerifiedTranscriptObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTranscriptObject")
            .field("object_hash", &self.object_hash())
            .field("object_type", &self.object_type())
            .field("producer_participant_id", &self.producer_participant_id())
            .field("producer_sequence", &self.producer_sequence())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedTranscriptBatch {
    objects: Vec<VerifiedTranscriptObject>,
}

impl VerifiedTranscriptBatch {
    pub fn objects(&self) -> &[VerifiedTranscriptObject] {
        &self.objects
    }
}

#[derive(Clone)]
struct VerifiedTranscriptObjectData {
    object_hash: Hash512,
    canonical_carrier_bytes: Arc<[u8]>,
    envelope: ObjectEnvelope,
    state_intent: Option<StateIntentCoordinate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ProducerSlot {
    Participant {
        object_type: FoundationObjectType,
        producer_participant_id: ParticipantIdentity,
        producer_sequence: u64,
    },
    StatefulSubject {
        object_type: FoundationObjectType,
        state_key: Hash512,
        producer_sequence: u64,
    },
    StateWitness {
        state_key: Hash512,
        subject_participant_id: ParticipantIdentity,
        witness_participant_id: ParticipantIdentity,
        producer_sequence: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StateIntentCoordinate {
    capability_kind: StateCapabilityKind,
    state_key: Hash512,
    subject_participant_id: ParticipantIdentity,
    vote_kind: StateWitnessVoteKind,
}

struct ResolvedSemantics {
    producer_slot: Option<ProducerSlot>,
    state_intent: Option<StateIntentCoordinate>,
}

#[derive(Debug, Clone)]
enum TypedPayload {
    SetupIntent,
    PublicRandomnessCommitment,
    PublicRandomnessReveal {
        contribution_commitment_object_hash: Hash512,
    },
    PrivateShareAcceptance,
    Complaint {
        accused_participant_id: ParticipantIdentity,
    },
    DealerPublicRecord {
        dealer_roster_position: u16,
    },
    BallotPackage,
    Aggregate {
        selected_ballot_object_hashes: Vec<Hash512>,
    },
    EvaluatorReplay {
        verified_aggregate_source_hash: Hash512,
    },
    Finality,
    StateReservation {
        capability_kind: StateCapabilityKind,
    },
    StateOutputIntent {
        reservation_intent_object_hash: Hash512,
    },
    StateWitnessVote {
        intent_object_hash: Hash512,
    },
    TargetDecryptionShare {
        reservation_intent_object_hash: Hash512,
    },
    StorageRootCommitment,
}

struct ParsedBoardObject {
    object_hash: Hash512,
    canonical_carrier_bytes: Arc<[u8]>,
    envelope: ObjectEnvelope,
    payload: TypedPayload,
}

/// Verifies foundation rules for unordered adversarial board carriers under one
/// frozen action context. Owning operation verifiers must separately verify their
/// cryptographic relations before minting operation-specific capabilities.
pub struct CanonicalBoardVerifier {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
    roster_hash: Hash512,
    roster_positions: HashMap<ParticipantIdentity, u16>,
    limits: CanonicalBoardLimits,
    canonical_decode_limits: CanonicalDecodeLimits,
    objects_by_hash: HashMap<Hash512, Arc<VerifiedTranscriptObjectData>>,
    object_hashes_by_producer_slot: HashMap<ProducerSlot, Hash512>,
    retained_canonical_carrier_byte_length: u64,
}

impl CanonicalBoardVerifier {
    pub fn new(
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        roster: &Roster,
        limits: CanonicalBoardLimits,
        canonical_decode_limits: CanonicalDecodeLimits,
    ) -> Result<Self, CanonicalBoardError> {
        limits.validate()?;
        roster.validate()?;
        let canonical_roster = roster.clone();
        canonical_roster.require_selected_profile_size()?;
        let roster_hash = canonical_roster.roster_hash()?;
        let mut roster_positions = HashMap::with_capacity(canonical_roster.entries.len());
        for (roster_position, entry) in canonical_roster.entries.iter().enumerate() {
            let roster_position = u16::try_from(roster_position).map_err(|_| {
                CanonicalBoardError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "roster position does not fit the canonical field width",
                )
            })?;
            roster_positions.insert(entry.participant_identity()?, roster_position);
        }
        Ok(Self {
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            roster: canonical_roster,
            roster_hash,
            roster_positions,
            limits,
            canonical_decode_limits,
            objects_by_hash: HashMap::new(),
            object_hashes_by_producer_slot: HashMap::new(),
            retained_canonical_carrier_byte_length: 0,
        })
    }

    pub(crate) const fn suite_id(&self) -> Hash512 {
        self.suite_id
    }

    pub(crate) const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> Hash512 {
        self.roster_hash
    }

    pub fn verify_unordered_carriers<Carrier: AsRef<[u8]>>(
        &mut self,
        canonical_carriers: &[Carrier],
    ) -> VerificationResult<VerifiedTranscriptBatch> {
        match self.verify_unordered_carriers_inner(canonical_carriers) {
            Ok(batch) => VerificationResult::valid(batch),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    fn verify_unordered_carriers_inner<Carrier: AsRef<[u8]>>(
        &mut self,
        canonical_carriers: &[Carrier],
    ) -> BoardResult<VerifiedTranscriptBatch> {
        if canonical_carriers.is_empty()
            || canonical_carriers.len()
                > usize::try_from(self.limits.maximum_unordered_carriers_per_batch).map_err(
                    |_| {
                        CanonicalBoardError::new(
                            RefusalReason::OutsideSupportedProfile,
                            "canonical-board batch limit does not fit this runtime",
                        )
                    },
                )?
        {
            return Err(CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "canonical-board carrier count is outside the supported profile",
            ));
        }
        let framed_byte_length =
            canonical_carriers
                .iter()
                .try_fold(4_usize, |accumulated_byte_length, carrier| {
                    accumulated_byte_length
                        .checked_add(4)
                        .and_then(|value| value.checked_add(carrier.as_ref().len()))
                        .ok_or_else(|| {
                            CanonicalBoardError::new(
                                RefusalReason::OutsideSupportedProfile,
                                "canonical-board carrier byte length overflows",
                            )
                        })
                })?;
        if framed_byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
            return Err(CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "canonical-board carrier bytes exceed the copied-buffer safety bound",
            ));
        }

        let mut requested_object_hashes = Vec::with_capacity(canonical_carriers.len());
        let mut requested_hash_set = HashSet::with_capacity(canonical_carriers.len());
        let mut pending_objects = HashMap::with_capacity(canonical_carriers.len());
        let mut unique_canonical_carriers = HashSet::with_capacity(canonical_carriers.len());
        for canonical_carrier in canonical_carriers {
            let canonical_carrier = canonical_carrier.as_ref();
            if !unique_canonical_carriers.insert(canonical_carrier) {
                continue;
            }
            let parsed = self.parse_and_authenticate_carrier(canonical_carrier)?;
            if requested_hash_set.insert(parsed.object_hash) {
                requested_object_hashes.push(parsed.object_hash);
            }
            if let Some(existing) = self.objects_by_hash.get(&parsed.object_hash) {
                require_same_envelope(existing, &parsed)?;
                continue;
            }
            if let Some(previous) = pending_objects.get(&parsed.object_hash) {
                require_same_parsed_envelope(previous, &parsed)?;
                continue;
            }
            pending_objects.insert(parsed.object_hash, parsed);
        }

        let retained_count = self
            .objects_by_hash
            .len()
            .checked_add(pending_objects.len())
            .ok_or_else(|| {
                CanonicalBoardError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "canonical-board retained-object count overflows",
                )
            })?;
        if retained_count
            > usize::try_from(self.limits.maximum_retained_transcript_objects).map_err(|_| {
                CanonicalBoardError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "canonical-board retained-object limit does not fit this runtime",
                )
            })?
        {
            return Err(CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "canonical-board retained-object limit is exceeded",
            ));
        }
        let pending_carrier_byte_length =
            pending_objects
                .values()
                .try_fold(0_u64, |accumulated_byte_length, object| {
                    let object_byte_length = u64::try_from(object.canonical_carrier_bytes.len())
                        .map_err(|_| {
                            CanonicalBoardError::new(
                                RefusalReason::OutsideSupportedProfile,
                                "canonical-board carrier length does not fit u64",
                            )
                        })?;
                    accumulated_byte_length
                        .checked_add(object_byte_length)
                        .ok_or_else(|| {
                            CanonicalBoardError::new(
                                RefusalReason::OutsideSupportedProfile,
                                "canonical-board retained carrier bytes overflow",
                            )
                        })
                })?;
        let retained_carrier_byte_length = self
            .retained_canonical_carrier_byte_length
            .checked_add(pending_carrier_byte_length)
            .ok_or_else(|| {
                CanonicalBoardError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "canonical-board retained carrier bytes overflow",
                )
            })?;
        if retained_carrier_byte_length > self.limits.maximum_retained_canonical_carrier_byte_length
        {
            return Err(CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "canonical-board retained carrier bytes exceed the runtime safety bound",
            ));
        }

        let mut available_objects = self.objects_by_hash.clone();
        let mut staged_objects = HashMap::with_capacity(pending_objects.len());
        let mut staged_slots = self.object_hashes_by_producer_slot.clone();
        while !pending_objects.is_empty() {
            let mut pending_hashes = pending_objects.keys().copied().collect::<Vec<_>>();
            pending_hashes.sort_unstable_by(|left, right| {
                left.as_bytes().as_slice().cmp(right.as_bytes().as_slice())
            });
            let mut made_progress = false;
            for object_hash in pending_hashes {
                let Some(parsed) = pending_objects.get(&object_hash) else {
                    continue;
                };
                let resolved = match self.resolve_object(parsed, &available_objects) {
                    Ok(resolved) => resolved,
                    Err(ResolveError::Deferred) => continue,
                    Err(ResolveError::Refused(error)) => return Err(error),
                };
                let (resolved, producer_slot) = resolved;
                if let Some(producer_slot) = producer_slot {
                    if let Some(previous_hash) = staged_slots.get(&producer_slot) {
                        if *previous_hash != object_hash {
                            return Err(CanonicalBoardError::new(
                                RefusalReason::Equivocation,
                                "an authenticated producer slot contains conflicting objects",
                            ));
                        }
                    } else {
                        staged_slots.insert(producer_slot, object_hash);
                    }
                }
                let resolved = Arc::new(resolved);
                available_objects.insert(object_hash, Arc::clone(&resolved));
                staged_objects.insert(object_hash, resolved);
                pending_objects.remove(&object_hash);
                made_progress = true;
            }
            if !made_progress {
                return Err(CanonicalBoardError::missing_prerequisite());
            }
        }

        self.object_hashes_by_producer_slot = staged_slots;
        self.objects_by_hash.extend(staged_objects);
        self.retained_canonical_carrier_byte_length = retained_carrier_byte_length;

        requested_object_hashes.sort_unstable_by(|left, right| {
            left.as_bytes().as_slice().cmp(right.as_bytes().as_slice())
        });
        let objects = requested_object_hashes
            .into_iter()
            .map(|object_hash| {
                self.objects_by_hash
                    .get(&object_hash)
                    .cloned()
                    .map(|inner| VerifiedTranscriptObject { inner })
                    .ok_or_else(CanonicalBoardError::missing_prerequisite)
            })
            .collect::<BoardResult<Vec<_>>>()?;
        Ok(VerifiedTranscriptBatch { objects })
    }

    fn parse_and_authenticate_carrier(
        &self,
        canonical_carrier_bytes: &[u8],
    ) -> BoardResult<ParsedBoardObject> {
        let decoded = decode_board_carrier(canonical_carrier_bytes, &self.canonical_decode_limits)?;
        let envelope = match &decoded {
            DecodedBoardCarrier::Signed(carrier) => {
                if matches!(
                    carrier.envelope.object_type,
                    FoundationObjectType::Aggregate | FoundationObjectType::EvaluatorReplay
                ) {
                    return Err(CanonicalBoardError::new(
                        RefusalReason::WrongTypeOrLength,
                        "a deterministic transcript object must be unsigned",
                    ));
                }
                &carrier.envelope
            }
            DecodedBoardCarrier::Unsigned(envelope) => {
                if !matches!(
                    envelope.object_type,
                    FoundationObjectType::Aggregate | FoundationObjectType::EvaluatorReplay
                ) {
                    return Err(CanonicalBoardError::new(
                        RefusalReason::WrongTypeOrLength,
                        "a signed transcript family was supplied as an unsigned envelope",
                    ));
                }
                envelope
            }
        };
        if envelope.suite_id != self.suite_id
            || envelope.ceremony_context_hash != self.ceremony_context_hash
            || envelope.action_context_hash != self.action_context_hash
        {
            return Err(CanonicalBoardError::new(
                RefusalReason::WrongContext,
                "canonical-board carrier belongs to another action context",
            ));
        }
        let payload = decode_typed_payload(
            envelope.object_type,
            &envelope.payload_bytes,
            &self.canonical_decode_limits,
        )?;
        if let DecodedBoardCarrier::Signed(carrier) = &decoded {
            carrier
                .verify_signature(&self.roster)
                .into_result()
                .map_err(|reason| {
                    CanonicalBoardError::new(
                        reason,
                        "canonical-board carrier signature does not verify",
                    )
                })?;
        }
        let envelope = match decoded {
            DecodedBoardCarrier::Signed(carrier) => carrier.envelope,
            DecodedBoardCarrier::Unsigned(envelope) => *envelope,
        };
        Ok(ParsedBoardObject {
            object_hash: envelope.object_hash()?,
            canonical_carrier_bytes: Arc::from(canonical_carrier_bytes),
            envelope,
            payload,
        })
    }

    fn resolve_object(
        &self,
        parsed: &ParsedBoardObject,
        available: &HashMap<Hash512, Arc<VerifiedTranscriptObjectData>>,
    ) -> Result<(VerifiedTranscriptObjectData, Option<ProducerSlot>), ResolveError> {
        let semantics = self.derive_and_validate_semantics(parsed, available)?;
        Ok((
            VerifiedTranscriptObjectData {
                object_hash: parsed.object_hash,
                canonical_carrier_bytes: Arc::clone(&parsed.canonical_carrier_bytes),
                envelope: parsed.envelope.clone(),
                state_intent: semantics.state_intent,
            },
            semantics.producer_slot,
        ))
    }

    fn derive_and_validate_semantics(
        &self,
        parsed: &ParsedBoardObject,
        available: &HashMap<Hash512, Arc<VerifiedTranscriptObjectData>>,
    ) -> Result<ResolvedSemantics, ResolveError> {
        let envelope = &parsed.envelope;
        let participant_slot = |producer_participant_id| ResolvedSemantics {
            producer_slot: Some(ProducerSlot::Participant {
                object_type: envelope.object_type,
                producer_participant_id,
                producer_sequence: envelope.producer_sequence,
            }),
            state_intent: None,
        };

        match &parsed.payload {
            TypedPayload::SetupIntent => {
                let producer = self.require_signed_envelope(envelope, 0)?;
                require_sequence(envelope, 0)?;
                Ok(participant_slot(producer))
            }
            TypedPayload::PublicRandomnessCommitment => {
                let producer = self.require_signed_envelope(envelope, self.roster.entries.len())?;
                require_sequence(envelope, 0)?;
                for (roster_position, prerequisite_hash) in
                    envelope.ordered_prerequisite_hashes.iter().enumerate()
                {
                    let prerequisite = require_available(available, *prerequisite_hash)?;
                    require_object_type(prerequisite, FoundationObjectType::SetupIntent)?;
                    self.require_producer_at_position(prerequisite, roster_position)?;
                }
                Ok(participant_slot(producer))
            }
            TypedPayload::PublicRandomnessReveal {
                contribution_commitment_object_hash,
            } => {
                let producer = self.require_signed_envelope(envelope, 0)?;
                require_sequence(envelope, 0)?;
                let commitment =
                    require_available(available, *contribution_commitment_object_hash)?;
                require_object_type(commitment, FoundationObjectType::PublicRandomnessCommitment)?;
                require_producer(commitment, producer)?;
                Ok(participant_slot(producer))
            }
            TypedPayload::PrivateShareAcceptance => {
                let producer = self.require_signed_envelope(envelope, 0)?;
                require_sequence(envelope, 0)?;
                Ok(participant_slot(producer))
            }
            TypedPayload::Complaint {
                accused_participant_id,
            } => {
                let producer = self.require_signed_envelope(envelope, 0)?;
                require_sequence(envelope, 0)?;
                self.roster_position(*accused_participant_id)?;
                Ok(participant_slot(producer))
            }
            TypedPayload::DealerPublicRecord {
                dealer_roster_position,
            } => {
                let producer = self.require_signed_envelope(envelope, 1)?;
                require_sequence(envelope, 0)?;
                let producer_position = self.roster_position(producer)?;
                if producer_position != *dealer_roster_position {
                    return Err(CanonicalBoardError::new(
                        RefusalReason::WrongContext,
                        "dealer record producer does not match its roster position",
                    )
                    .into());
                }
                Ok(participant_slot(producer))
            }
            TypedPayload::BallotPackage => {
                let producer = self.require_signed_envelope(envelope, 1)?;
                if envelope.producer_sequence >= self.limits.maximum_ballot_attempts_per_participant
                {
                    return Err(CanonicalBoardError::new(
                        RefusalReason::OutsideSupportedProfile,
                        "ballot producer sequence exceeds the suite candidate bound",
                    )
                    .into());
                }
                Ok(participant_slot(producer))
            }
            TypedPayload::Aggregate {
                selected_ballot_object_hashes,
            } => {
                self.require_deterministic_unsigned_envelope(envelope, 0)?;
                let mut previous_roster_position = None;
                for ballot_hash in selected_ballot_object_hashes {
                    let ballot = require_available(available, *ballot_hash)?;
                    require_object_type(ballot, FoundationObjectType::BallotPackage)?;
                    let producer = ballot.envelope.producer_participant_id.ok_or_else(|| {
                        ResolveError::Refused(CanonicalBoardError::new(
                            RefusalReason::WrongTypeOrLength,
                            "selected ballot does not name a producer",
                        ))
                    })?;
                    let roster_position = self.roster_position(producer)?;
                    if previous_roster_position.is_some_and(|previous| roster_position <= previous)
                    {
                        return Err(CanonicalBoardError::new(
                            RefusalReason::WrongContext,
                            "selected ballots are not unique and in frozen-roster order",
                        )
                        .into());
                    }
                    previous_roster_position = Some(roster_position);
                }
                Ok(ResolvedSemantics {
                    producer_slot: None,
                    state_intent: None,
                })
            }
            TypedPayload::EvaluatorReplay {
                verified_aggregate_source_hash,
            } => {
                self.require_deterministic_unsigned_envelope(envelope, 0)?;
                let aggregate = require_available(available, *verified_aggregate_source_hash)?;
                require_object_type(aggregate, FoundationObjectType::Aggregate)?;
                Ok(ResolvedSemantics {
                    producer_slot: None,
                    state_intent: None,
                })
            }
            TypedPayload::Finality => {
                let producer = self.require_signed_envelope(envelope, 1)?;
                require_sequence(envelope, 0)?;
                let replay = require_available(available, envelope.ordered_prerequisite_hashes[0])?;
                require_object_type(replay, FoundationObjectType::EvaluatorReplay)?;
                self.stateful_output_semantics(
                    envelope,
                    producer,
                    StateCapabilityKind::FinalitySignature,
                )
            }
            TypedPayload::StateReservation { capability_kind } => {
                let subject = self.require_signed_envelope(envelope, 0)?;
                require_sequence(envelope, 0)?;
                let state_key = derive_state_key(
                    self.suite_id,
                    self.ceremony_context_hash,
                    self.action_context_hash,
                    subject,
                    *capability_kind,
                )?;
                Ok(ResolvedSemantics {
                    producer_slot: Some(ProducerSlot::StatefulSubject {
                        object_type: envelope.object_type,
                        state_key,
                        producer_sequence: envelope.producer_sequence,
                    }),
                    state_intent: Some(StateIntentCoordinate {
                        capability_kind: *capability_kind,
                        state_key,
                        subject_participant_id: subject,
                        vote_kind: StateWitnessVoteKind::Reservation,
                    }),
                })
            }
            TypedPayload::StateOutputIntent {
                reservation_intent_object_hash,
            } => {
                let subject = self.require_signed_envelope(envelope, 0)?;
                require_sequence(envelope, 0)?;
                let reservation = require_available(available, *reservation_intent_object_hash)?;
                require_object_type(reservation, FoundationObjectType::StateReservation)?;
                let reservation_coordinate = reservation.state_intent.ok_or_else(|| {
                    ResolveError::Refused(CanonicalBoardError::new(
                        RefusalReason::WrongTypeOrLength,
                        "state output does not reference a resolved reservation intent",
                    ))
                })?;
                if reservation_coordinate.vote_kind != StateWitnessVoteKind::Reservation
                    || !reservation_coordinate
                        .capability_kind
                        .supports_exact_output()
                    || reservation_coordinate.subject_participant_id != subject
                {
                    return Err(CanonicalBoardError::new(
                        RefusalReason::WrongContext,
                        "state output does not match its reservation subject slot",
                    )
                    .into());
                }
                let state_key = derive_state_key(
                    self.suite_id,
                    self.ceremony_context_hash,
                    self.action_context_hash,
                    subject,
                    reservation_coordinate.capability_kind,
                )?;
                if state_key != reservation_coordinate.state_key {
                    return Err(CanonicalBoardError::new(
                        RefusalReason::WrongContext,
                        "state output derives a different stable state key",
                    )
                    .into());
                }
                Ok(ResolvedSemantics {
                    producer_slot: Some(ProducerSlot::StatefulSubject {
                        object_type: envelope.object_type,
                        state_key: reservation_coordinate.state_key,
                        producer_sequence: envelope.producer_sequence,
                    }),
                    state_intent: Some(StateIntentCoordinate {
                        capability_kind: reservation_coordinate.capability_kind,
                        state_key: reservation_coordinate.state_key,
                        subject_participant_id: subject,
                        vote_kind: StateWitnessVoteKind::Output,
                    }),
                })
            }
            TypedPayload::StateWitnessVote { intent_object_hash } => {
                let witness = self.require_signed_envelope(envelope, 0)?;
                let intent = require_available(available, *intent_object_hash)?;
                let intent_coordinate = intent.state_intent.ok_or_else(|| {
                    ResolveError::Refused(CanonicalBoardError::new(
                        RefusalReason::WrongTypeOrLength,
                        "state witness vote does not reference a state intent",
                    ))
                })?;
                if witness == intent_coordinate.subject_participant_id {
                    return Err(CanonicalBoardError::new(
                        RefusalReason::WrongContext,
                        "a state subject cannot witness its own intent",
                    )
                    .into());
                }
                let expected_sequence =
                    derive_state_witness_vote_sequence(intent_coordinate.vote_kind);
                require_sequence(envelope, expected_sequence)?;
                Ok(ResolvedSemantics {
                    producer_slot: Some(ProducerSlot::StateWitness {
                        state_key: intent_coordinate.state_key,
                        subject_participant_id: intent_coordinate.subject_participant_id,
                        witness_participant_id: witness,
                        producer_sequence: envelope.producer_sequence,
                    }),
                    state_intent: None,
                })
            }
            TypedPayload::TargetDecryptionShare {
                reservation_intent_object_hash,
            } => {
                let subject = self.require_signed_envelope(envelope, 0)?;
                require_sequence(envelope, 0)?;
                let reservation = require_available(available, *reservation_intent_object_hash)?;
                let coordinate = reservation.state_intent.ok_or_else(|| {
                    ResolveError::Refused(CanonicalBoardError::new(
                        RefusalReason::WrongTypeOrLength,
                        "target share does not reference a state reservation",
                    ))
                })?;
                if reservation.envelope.object_type != FoundationObjectType::StateReservation
                    || coordinate.vote_kind != StateWitnessVoteKind::Reservation
                    || coordinate.capability_kind != StateCapabilityKind::TargetRelease
                    || coordinate.subject_participant_id != subject
                {
                    return Err(CanonicalBoardError::new(
                        RefusalReason::WrongContext,
                        "target share does not match its release reservation",
                    )
                    .into());
                }
                self.stateful_output_semantics(
                    envelope,
                    subject,
                    StateCapabilityKind::TargetRelease,
                )
            }
            TypedPayload::StorageRootCommitment => {
                let producer = self.require_signed_envelope(envelope, 0)?;
                require_sequence(envelope, 0)?;
                Ok(participant_slot(producer))
            }
        }
    }

    fn stateful_output_semantics(
        &self,
        envelope: &ObjectEnvelope,
        subject_participant_id: ParticipantIdentity,
        capability_kind: StateCapabilityKind,
    ) -> Result<ResolvedSemantics, ResolveError> {
        let state_key = derive_state_key(
            self.suite_id,
            self.ceremony_context_hash,
            self.action_context_hash,
            subject_participant_id,
            capability_kind,
        )?;
        Ok(ResolvedSemantics {
            producer_slot: Some(ProducerSlot::StatefulSubject {
                object_type: envelope.object_type,
                state_key,
                producer_sequence: envelope.producer_sequence,
            }),
            state_intent: None,
        })
    }

    fn require_signed_envelope(
        &self,
        envelope: &ObjectEnvelope,
        prerequisite_count: usize,
    ) -> BoardResult<ParticipantIdentity> {
        if envelope.ordered_prerequisite_hashes.len() != prerequisite_count {
            return Err(CanonicalBoardError::new(
                RefusalReason::WrongTypeOrLength,
                "transcript object has the wrong prerequisite-list shape",
            ));
        }
        let producer = envelope.producer_participant_id.ok_or_else(|| {
            CanonicalBoardError::new(
                RefusalReason::WrongTypeOrLength,
                "signed transcript object does not name a producer",
            )
        })?;
        self.roster_position(producer)?;
        Ok(producer)
    }

    fn require_deterministic_unsigned_envelope(
        &self,
        envelope: &ObjectEnvelope,
        prerequisite_count: usize,
    ) -> BoardResult<()> {
        if envelope.producer_participant_id.is_some()
            || envelope.producer_sequence != 0
            || envelope.ordered_prerequisite_hashes.len() != prerequisite_count
        {
            return Err(CanonicalBoardError::new(
                RefusalReason::WrongContext,
                "deterministic transcript object carries producer coordinates",
            ));
        }
        Ok(())
    }

    pub(crate) fn roster_position(&self, participant_id: ParticipantIdentity) -> BoardResult<u16> {
        self.roster_positions
            .get(&participant_id)
            .copied()
            .ok_or_else(|| {
                CanonicalBoardError::new(
                    RefusalReason::WrongContext,
                    "transcript participant is not in the frozen roster",
                )
            })
    }

    fn require_producer_at_position(
        &self,
        object: &VerifiedTranscriptObjectData,
        expected_roster_position: usize,
    ) -> Result<(), ResolveError> {
        let producer = object.envelope.producer_participant_id.ok_or_else(|| {
            ResolveError::Refused(CanonicalBoardError::new(
                RefusalReason::WrongTypeOrLength,
                "typed prerequisite does not name a producer",
            ))
        })?;
        if usize::from(self.roster_position(producer)?) != expected_roster_position {
            return Err(CanonicalBoardError::new(
                RefusalReason::WrongContext,
                "typed prerequisite resolves outside frozen-roster order",
            )
            .into());
        }
        Ok(())
    }
}

enum DecodedBoardCarrier {
    Signed(Box<SignedCarrier>),
    Unsigned(Box<ObjectEnvelope>),
}

enum ResolveError {
    Deferred,
    Refused(CanonicalBoardError),
}

impl From<CanonicalBoardError> for ResolveError {
    fn from(error: CanonicalBoardError) -> Self {
        Self::Refused(error)
    }
}

impl From<StateError> for ResolveError {
    fn from(error: StateError) -> Self {
        Self::Refused(error.into())
    }
}

fn decode_board_carrier(
    canonical_carrier_bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> BoardResult<DecodedBoardCarrier> {
    let carrier_tuple = CanonicalTuple::decode(canonical_carrier_bytes, limits)?;
    if carrier_tuple.schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(CanonicalBoardError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "canonical-board carrier schema version is unsupported",
        ));
    }
    match carrier_tuple.schema_identifier {
        super::SIGNED_CARRIER_SCHEMA_IDENTIFIER => {
            if carrier_tuple.items.len() != 2 {
                return Err(CanonicalBoardError::new(
                    RefusalReason::WrongTypeOrLength,
                    "signed carrier has the wrong item count",
                ));
            }
            let envelope_bytes = carrier_tuple.items[0].variable_value_bytes()?;
            preflight_envelope_family(envelope_bytes, limits)?;
            Ok(DecodedBoardCarrier::Signed(Box::new(
                SignedCarrier::decode(canonical_carrier_bytes, limits)?,
            )))
        }
        super::OBJECT_ENVELOPE_SCHEMA_IDENTIFIER => {
            preflight_envelope_family(canonical_carrier_bytes, limits)?;
            Ok(DecodedBoardCarrier::Unsigned(Box::new(
                ObjectEnvelope::decode(canonical_carrier_bytes, limits)?,
            )))
        }
        _ => Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            "canonical-board input is neither a signed carrier nor an unsigned deterministic envelope",
        )),
    }
}

fn preflight_envelope_family(
    canonical_envelope_bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> BoardResult<FoundationObjectType> {
    let envelope_tuple = CanonicalTuple::decode(canonical_envelope_bytes, limits)?;
    if envelope_tuple.schema_identifier != super::OBJECT_ENVELOPE_SCHEMA_IDENTIFIER
        || envelope_tuple.items.len() != 10
    {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            "canonical-board envelope has the wrong schema shape",
        ));
    }
    if envelope_tuple.schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(CanonicalBoardError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "canonical-board envelope schema version is unsupported",
        ));
    }
    let object_type_code = read_u16(&envelope_tuple.items[3])?;
    FoundationObjectType::from_canonical_code(object_type_code).ok_or_else(|| {
        CanonicalBoardError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "canonical-board object family is unsupported",
        )
    })
}

fn decode_typed_payload(
    object_type: FoundationObjectType,
    payload_bytes: &[u8],
    limits: &CanonicalDecodeLimits,
) -> BoardResult<TypedPayload> {
    let tuple = CanonicalTuple::decode(payload_bytes, limits)?;
    if tuple.schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(CanonicalBoardError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "transcript payload schema version is unsupported",
        ));
    }
    match object_type {
        FoundationObjectType::SetupIntent => {
            require_payload_header(&tuple, SETUP_INTENT_PAYLOAD_SCHEMA_IDENTIFIER, 1)?;
            read_hash(&tuple.items[0])?;
            Ok(TypedPayload::SetupIntent)
        }
        FoundationObjectType::PublicRandomnessCommitment => {
            require_payload_header(
                &tuple,
                PUBLIC_RANDOMNESS_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
                1,
            )?;
            read_hash(&tuple.items[0])?;
            Ok(TypedPayload::PublicRandomnessCommitment)
        }
        FoundationObjectType::PublicRandomnessReveal => {
            require_payload_header(
                &tuple,
                PUBLIC_RANDOMNESS_REVEAL_PAYLOAD_SCHEMA_IDENTIFIER,
                2,
            )?;
            let contribution_commitment_object_hash = read_hash(&tuple.items[0])?;
            require_fixed_raw_byte_length(&tuple.items[1], Hash512::BYTE_LENGTH)?;
            Ok(TypedPayload::PublicRandomnessReveal {
                contribution_commitment_object_hash,
            })
        }
        FoundationObjectType::PrivateShareAcceptance => {
            require_payload_header(
                &tuple,
                PRIVATE_SHARE_ACCEPTANCE_PAYLOAD_SCHEMA_IDENTIFIER,
                3,
            )?;
            read_hash(&tuple.items[0])?;
            require_nonempty_hash_list(
                &tuple.items[1],
                "private-share acceptance has no aggregate material roots",
            )?;
            read_stream_descriptor(&tuple.items[2], limits)?;
            Ok(TypedPayload::PrivateShareAcceptance)
        }
        FoundationObjectType::Complaint => {
            require_payload_header(&tuple, COMPLAINT_PAYLOAD_SCHEMA_IDENTIFIER, 3)?;
            let accused_participant_id = read_participant_identity(&tuple.items[0])?;
            read_hash(&tuple.items[1])?;
            let refusal_reason = RefusalReason::try_from_canonical_code(read_u16(&tuple.items[2])?)
                .map_err(|reason| {
                    CanonicalBoardError::new(reason, "complaint refusal code is unassigned")
                })?;
            if !matches!(
                refusal_reason,
                RefusalReason::MalformedEncoding
                    | RefusalReason::InvalidSignature
                    | RefusalReason::WrongContext
                    | RefusalReason::WrongHashOrRoot
                    | RefusalReason::InvalidProof
                    | RefusalReason::InvalidArithmeticRelation
            ) {
                return Err(CanonicalBoardError::new(
                    RefusalReason::WrongTypeOrLength,
                    "complaint refusal reason is not permitted by the setup schema",
                ));
            }
            Ok(TypedPayload::Complaint {
                accused_participant_id,
            })
        }
        FoundationObjectType::PublicSetupRecord => {
            require_payload_header(&tuple, DEALER_PUBLIC_RECORD_PAYLOAD_SCHEMA_IDENTIFIER, 5)?;
            let dealer_roster_position = read_u16(&tuple.items[0])?;
            require_nonempty_hash_list(
                &tuple.items[1],
                "dealer public record has an empty coefficient-root catalog",
            )?;
            require_nonempty_hash_list(
                &tuple.items[2],
                "dealer public record has an empty share-root catalog",
            )?;
            require_hash_list_count(
                &tuple.items[3],
                usize::from(FOUNDATION_PROFILE.participant_count),
                "dealer public record has the wrong recipient-envelope count",
            )?;
            read_stream_descriptor(&tuple.items[4], limits)?;
            Ok(TypedPayload::DealerPublicRecord {
                dealer_roster_position,
            })
        }
        FoundationObjectType::BallotPackage => {
            require_payload_header(&tuple, BALLOT_PACKAGE_PAYLOAD_SCHEMA_IDENTIFIER, 2)?;
            read_stream_descriptor(&tuple.items[0], limits)?;
            read_stream_descriptor(&tuple.items[1], limits)?;
            Ok(TypedPayload::BallotPackage)
        }
        FoundationObjectType::Aggregate => {
            let aggregate_payload = AggregatePayload::from_tuple(&tuple, limits)?;
            Ok(TypedPayload::Aggregate {
                selected_ballot_object_hashes: aggregate_payload
                    .selected_ballot_object_hashes()
                    .to_vec(),
            })
        }
        FoundationObjectType::EvaluatorReplay => {
            let replay_payload = EvaluatorReplayPayload::from_tuple(&tuple, limits)?;
            Ok(TypedPayload::EvaluatorReplay {
                verified_aggregate_source_hash: replay_payload.verified_aggregate_source_hash(),
            })
        }
        FoundationObjectType::FinalitySignature => {
            require_payload_header(&tuple, FINALITY_SIGNATURE_PAYLOAD_SCHEMA_IDENTIFIER, 1)?;
            read_hash(&tuple.items[0])?;
            Ok(TypedPayload::Finality)
        }
        FoundationObjectType::StateReservation => {
            require_payload_header(&tuple, super::STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER, 2)?;
            let payload = StateReservationIntentPayload::decode(payload_bytes, limits)?;
            Ok(TypedPayload::StateReservation {
                capability_kind: payload.capability_kind,
            })
        }
        FoundationObjectType::StateOutputIntent => {
            require_payload_header(&tuple, super::STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER, 2)?;
            let payload = StateOutputIntentPayload::decode(payload_bytes, limits)?;
            Ok(TypedPayload::StateOutputIntent {
                reservation_intent_object_hash: payload.reservation_intent_object_hash,
            })
        }
        FoundationObjectType::StateWitnessVote => {
            require_payload_header(&tuple, super::STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER, 1)?;
            let payload = StateWitnessVotePayload::decode(payload_bytes, limits)?;
            Ok(TypedPayload::StateWitnessVote {
                intent_object_hash: payload.intent_object_hash,
            })
        }
        FoundationObjectType::TargetDecryptionShare => {
            require_payload_header(&tuple, TARGET_DECRYPTION_SHARE_PAYLOAD_SCHEMA_IDENTIFIER, 5)?;
            read_hash(&tuple.items[0])?;
            let reservation_intent_object_hash = read_hash(&tuple.items[1])?;
            read_stream_descriptor(&tuple.items[2], limits)?;
            read_stream_descriptor(&tuple.items[3], limits)?;
            read_stream_descriptor(&tuple.items[4], limits)?;
            Ok(TypedPayload::TargetDecryptionShare {
                reservation_intent_object_hash,
            })
        }
        FoundationObjectType::StorageRootCommitment => {
            require_payload_header(
                &tuple,
                super::STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
                1,
            )?;
            StorageRootCommitmentPayload::decode(payload_bytes, limits)?;
            Ok(TypedPayload::StorageRootCommitment)
        }
    }
}

fn require_payload_header(
    tuple: &CanonicalTuple,
    expected_schema_identifier: u16,
    expected_item_count: usize,
) -> BoardResult<()> {
    if tuple.schema_identifier != expected_schema_identifier
        || tuple.items.len() != expected_item_count
    {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            "transcript payload does not match its object family",
        ));
    }
    if tuple.schema_version != FOUNDATION_SCHEMA_VERSION {
        return Err(CanonicalBoardError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "transcript payload schema version is unsupported",
        ));
    }
    Ok(())
}

fn read_u16(item: &CanonicalItem) -> BoardResult<u16> {
    require_item(item, CanonicalItemType::Unsigned16, 2)?;
    let mut bytes = [0_u8; 2];
    bytes.copy_from_slice(item.canonical_bytes());
    Ok(u16::from_le_bytes(bytes))
}

fn read_hash(item: &CanonicalItem) -> BoardResult<Hash512> {
    require_item(item, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
    let mut bytes = [0_u8; Hash512::BYTE_LENGTH];
    bytes.copy_from_slice(item.canonical_bytes());
    Ok(Hash512::from_bytes(bytes))
}

fn read_participant_identity(item: &CanonicalItem) -> BoardResult<ParticipantIdentity> {
    require_item(
        item,
        CanonicalItemType::ParticipantIdentity,
        ParticipantIdentity::BYTE_LENGTH,
    )?;
    let mut bytes = [0_u8; ParticipantIdentity::BYTE_LENGTH];
    bytes.copy_from_slice(item.canonical_bytes());
    Ok(ParticipantIdentity::from_bytes(bytes))
}

fn require_fixed_raw_byte_length(item: &CanonicalItem, expected: usize) -> BoardResult<()> {
    require_item(item, CanonicalItemType::RawBytes, expected)
}

fn require_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
    expected_byte_length: usize,
) -> BoardResult<()> {
    if item.item_type() != expected_type || item.canonical_bytes().len() != expected_byte_length {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            "transcript payload item has the wrong type or length",
        ));
    }
    Ok(())
}

fn hash_list_layout(item: &CanonicalItem) -> BoardResult<(&[u8], usize)> {
    if item.item_type() != CanonicalItemType::HomogeneousList {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            "transcript payload item is not a homogeneous list",
        ));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 6 {
        return Err(CanonicalBoardError::new(
            RefusalReason::MalformedEncoding,
            "transcript hash list is truncated",
        ));
    }
    if u16::from_le_bytes([bytes[0], bytes[1]]) != CanonicalItemType::Hash512.canonical_code() {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            "transcript list has the wrong element type",
        ));
    }
    let count = usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
        .map_err(|_| {
            CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "transcript hash-list count does not fit this runtime",
            )
        })?;
    let expected_length = count
        .checked_mul(Hash512::BYTE_LENGTH)
        .and_then(|value| value.checked_add(6))
        .ok_or_else(|| {
            CanonicalBoardError::new(
                RefusalReason::OutsideSupportedProfile,
                "transcript hash-list length overflows",
            )
        })?;
    if bytes.len() != expected_length {
        return Err(CanonicalBoardError::new(
            RefusalReason::MalformedEncoding,
            "transcript hash-list length is inconsistent",
        ));
    }
    Ok((bytes, count))
}

fn require_hash_list_count(
    item: &CanonicalItem,
    expected_count: usize,
    mismatch_message: &'static str,
) -> BoardResult<()> {
    let (_, count) = hash_list_layout(item)?;
    if count != expected_count {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            mismatch_message,
        ));
    }
    Ok(())
}

fn require_nonempty_hash_list(
    item: &CanonicalItem,
    empty_message: &'static str,
) -> BoardResult<()> {
    let (_, count) = hash_list_layout(item)?;
    if count == 0 {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            empty_message,
        ));
    }
    Ok(())
}

fn read_stream_descriptor(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> BoardResult<StreamDescriptor> {
    if item.item_type() != CanonicalItemType::NestedTuple {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            "transcript stream descriptor is not a nested tuple",
        ));
    }
    Ok(StreamDescriptor::decode(item.canonical_bytes(), limits)?)
}

fn require_available(
    available: &HashMap<Hash512, Arc<VerifiedTranscriptObjectData>>,
    object_hash: Hash512,
) -> Result<&VerifiedTranscriptObjectData, ResolveError> {
    available
        .get(&object_hash)
        .map(Arc::as_ref)
        .ok_or(ResolveError::Deferred)
}

fn require_object_type(
    object: &VerifiedTranscriptObjectData,
    expected_object_type: FoundationObjectType,
) -> Result<(), ResolveError> {
    if object.envelope.object_type != expected_object_type {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongTypeOrLength,
            "typed prerequisite resolves to the wrong object family",
        )
        .into());
    }
    Ok(())
}

fn require_producer(
    object: &VerifiedTranscriptObjectData,
    expected_producer: ParticipantIdentity,
) -> Result<(), ResolveError> {
    if object.envelope.producer_participant_id != Some(expected_producer) {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongContext,
            "typed prerequisite resolves to the wrong producer",
        )
        .into());
    }
    Ok(())
}

fn require_sequence(envelope: &ObjectEnvelope, expected_sequence: u64) -> BoardResult<()> {
    if envelope.producer_sequence != expected_sequence {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongContext,
            "transcript object has the wrong producer sequence",
        ));
    }
    Ok(())
}

fn require_same_envelope(
    existing: &VerifiedTranscriptObjectData,
    parsed: &ParsedBoardObject,
) -> BoardResult<()> {
    if existing.envelope != parsed.envelope {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongHashOrRoot,
            "distinct transcript envelopes recompute to one object hash",
        ));
    }
    Ok(())
}

fn require_same_parsed_envelope(
    previous: &ParsedBoardObject,
    current: &ParsedBoardObject,
) -> BoardResult<()> {
    if previous.envelope != current.envelope {
        return Err(CanonicalBoardError::new(
            RefusalReason::WrongHashOrRoot,
            "distinct transcript envelopes recompute to one object hash",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
