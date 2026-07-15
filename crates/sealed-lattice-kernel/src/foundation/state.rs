use core::fmt;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::canonical_stream::VerifiedCanonicalStreamSummary;
use super::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, FOUNDATION_PROFILE, FoundationObjectType, FoundationSchemaError, Hash512,
    ObjectEnvelope, ParticipantIdentity, RefusalReason, Roster, SignedCarrier, VerificationResult,
    hash_foundation_tuple_512 as hash512,
};

pub const STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER: u16 = 0x1610;
pub const STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER: u16 = 0x1611;
pub const STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER: u16 = 0x1612;
pub const STATE_CERTIFICATE_SCHEMA_IDENTIFIER: u16 = 0x1613;

const STATE_SCHEMA_VERSION: u16 = 1;
const STATE_EXACT_OUTPUT_HASH_DOMAIN: &str = "sealed-lattice/state/exact-output/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StateCapabilityKind {
    FinalitySignature = 2,
    TargetRelease = 3,
    SetupActionRandomnessRoot = 4,
    SetupTerminalPackage = 8,
}

impl StateCapabilityKind {
    pub const fn canonical_code(self) -> u16 {
        self as u16
    }

    pub const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            2 => Some(Self::FinalitySignature),
            3 => Some(Self::TargetRelease),
            4 => Some(Self::SetupActionRandomnessRoot),
            8 => Some(Self::SetupTerminalPackage),
            _ => None,
        }
    }

    pub const fn supports_exact_output(self) -> bool {
        matches!(self, Self::FinalitySignature | Self::TargetRelease)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError {
    pub refusal_reason: RefusalReason,
    pub message: &'static str,
}

impl StateError {
    const fn new(refusal_reason: RefusalReason, message: &'static str) -> Self {
        Self {
            refusal_reason,
            message,
        }
    }

    fn from_schema(error: FoundationSchemaError) -> Self {
        Self::new(error.refusal_reason, error.message)
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for StateError {}

impl From<CanonicalCodecError> for StateError {
    fn from(error: CanonicalCodecError) -> Self {
        let refusal_reason = if error.kind == CanonicalCodecErrorKind::LimitExceeded {
            RefusalReason::OutsideSupportedProfile
        } else {
            RefusalReason::MalformedEncoding
        };
        Self::new(refusal_reason, "state value is not canonical")
    }
}

type StateResult<Value> = Result<Value, StateError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateReservationIntentPayload {
    pub capability_kind: StateCapabilityKind,
    pub authorization_hash: Hash512,
}

impl StateReservationIntentPayload {
    pub fn encode(self) -> StateResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER,
            STATE_SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.capability_kind.canonical_code()),
                CanonicalItem::hash512(self.authorization_hash.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> StateResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_state_tuple_header(&tuple, STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER, 2)?;
        let capability_kind = read_capability_kind(&tuple.items[0])?;
        let authorization_hash = read_hash512(&tuple.items[1])?;
        Ok(Self {
            capability_kind,
            authorization_hash,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateOutputIntentPayload {
    pub reservation_intent_object_hash: Hash512,
    pub exact_output_hash: Hash512,
}

impl StateOutputIntentPayload {
    pub fn encode(self) -> StateResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
            STATE_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(self.reservation_intent_object_hash.into_bytes()),
                CanonicalItem::hash512(self.exact_output_hash.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> StateResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_state_tuple_header(&tuple, STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER, 2)?;
        Ok(Self {
            reservation_intent_object_hash: read_hash512(&tuple.items[0])?,
            exact_output_hash: read_hash512(&tuple.items[1])?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateWitnessVotePayload {
    pub intent_object_hash: Hash512,
}

impl StateWitnessVotePayload {
    pub fn encode(self) -> StateResult<Vec<u8>> {
        Ok(CanonicalTuple::new(
            STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER,
            STATE_SCHEMA_VERSION,
            vec![CanonicalItem::hash512(self.intent_object_hash.into_bytes())],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> StateResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_state_tuple_header(&tuple, STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER, 1)?;
        Ok(Self {
            intent_object_hash: read_hash512(&tuple.items[0])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateCertificate {
    canonical_signed_state_witness_vote_carriers: Vec<Vec<u8>>,
}

impl StateCertificate {
    pub fn new(canonical_signed_state_witness_vote_carriers: Vec<Vec<u8>>) -> StateResult<Self> {
        validate_state_certificate_count(canonical_signed_state_witness_vote_carriers.len())?;
        Ok(Self {
            canonical_signed_state_witness_vote_carriers,
        })
    }

    pub fn canonical_signed_state_witness_vote_carriers(&self) -> &[Vec<u8>] {
        &self.canonical_signed_state_witness_vote_carriers
    }

    pub fn encode(&self) -> StateResult<Vec<u8>> {
        validate_state_certificate_count(self.canonical_signed_state_witness_vote_carriers.len())?;
        let carriers = self
            .canonical_signed_state_witness_vote_carriers
            .iter()
            .map(CanonicalItem::variable_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CanonicalTuple::new(
            STATE_CERTIFICATE_SCHEMA_IDENTIFIER,
            STATE_SCHEMA_VERSION,
            vec![CanonicalItem::homogeneous_list(
                CanonicalItemType::RawBytes,
                &carriers,
            )?],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> StateResult<Self> {
        preflight_state_certificate(bytes)?;
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_state_tuple_header(&tuple, STATE_CERTIFICATE_SCHEMA_IDENTIFIER, 1)?;
        let carriers = read_variable_byte_list(&tuple.items[0])?;
        Self::new(carriers)
    }
}

fn validate_state_certificate_count(count: usize) -> StateResult<()> {
    let minimum = usize::from(FOUNDATION_PROFILE.state_witness_quorum);
    let maximum = usize::from(FOUNDATION_PROFILE.participant_count - 1);
    if !(minimum..=maximum).contains(&count) {
        return Err(StateError::new(
            RefusalReason::OutsideSupportedProfile,
            "state certificate witness count is outside the supported profile",
        ));
    }
    Ok(())
}

fn preflight_state_certificate(bytes: &[u8]) -> StateResult<()> {
    const TUPLE_HEADER_BYTE_LENGTH: usize = 8;
    const ITEM_HEADER_BYTE_LENGTH: usize = 6;
    const LIST_HEADER_BYTE_LENGTH: usize = 6;
    const LIST_HEADER_OFFSET: usize = TUPLE_HEADER_BYTE_LENGTH + ITEM_HEADER_BYTE_LENGTH;

    if bytes.len() < LIST_HEADER_OFFSET + LIST_HEADER_BYTE_LENGTH {
        return Err(StateError::new(
            RefusalReason::MalformedEncoding,
            "state certificate header is truncated",
        ));
    }
    let schema_identifier = u16::from_le_bytes([bytes[0], bytes[1]]);
    let schema_version = u16::from_le_bytes([bytes[2], bytes[3]]);
    let tuple_item_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let outer_item_type = u16::from_le_bytes([bytes[8], bytes[9]]);
    let list_element_type =
        u16::from_le_bytes([bytes[LIST_HEADER_OFFSET], bytes[LIST_HEADER_OFFSET + 1]]);
    let list_count = u32::from_le_bytes([
        bytes[LIST_HEADER_OFFSET + 2],
        bytes[LIST_HEADER_OFFSET + 3],
        bytes[LIST_HEADER_OFFSET + 4],
        bytes[LIST_HEADER_OFFSET + 5],
    ]);
    if schema_identifier != STATE_CERTIFICATE_SCHEMA_IDENTIFIER || tuple_item_count != 1 {
        return Err(StateError::new(
            RefusalReason::WrongTypeOrLength,
            "state certificate has the wrong schema or item count",
        ));
    }
    if schema_version != STATE_SCHEMA_VERSION {
        return Err(StateError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "state certificate version is unsupported",
        ));
    }
    if outer_item_type != CanonicalItemType::HomogeneousList.canonical_code()
        || list_element_type != CanonicalItemType::RawBytes.canonical_code()
    {
        return Err(StateError::new(
            RefusalReason::WrongTypeOrLength,
            "state certificate carrier list has the wrong item type",
        ));
    }
    validate_state_certificate_count(usize::try_from(list_count).map_err(|_| {
        StateError::new(
            RefusalReason::OutsideSupportedProfile,
            "state certificate witness count does not fit the platform",
        )
    })?)
}

fn require_state_tuple_header(
    tuple: &CanonicalTuple,
    expected_schema_identifier: u16,
    expected_item_count: usize,
) -> StateResult<()> {
    if tuple.schema_identifier != expected_schema_identifier
        || tuple.items.len() != expected_item_count
    {
        return Err(StateError::new(
            RefusalReason::WrongTypeOrLength,
            "state tuple has the wrong schema or item count",
        ));
    }
    if tuple.schema_version != STATE_SCHEMA_VERSION {
        return Err(StateError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "state tuple version is unsupported",
        ));
    }
    Ok(())
}

fn require_item_type(item: &CanonicalItem, expected_type: CanonicalItemType) -> StateResult<&[u8]> {
    if item.item_type() != expected_type {
        return Err(StateError::new(
            RefusalReason::WrongTypeOrLength,
            "state tuple item has the wrong type",
        ));
    }
    Ok(item.canonical_bytes())
}

fn read_capability_kind(item: &CanonicalItem) -> StateResult<StateCapabilityKind> {
    let bytes: [u8; 2] = require_item_type(item, CanonicalItemType::Unsigned16)?
        .try_into()
        .map_err(|_| {
            StateError::new(
                RefusalReason::MalformedEncoding,
                "state capability kind has the wrong length",
            )
        })?;
    StateCapabilityKind::from_canonical_code(u16::from_le_bytes(bytes)).ok_or_else(|| {
        StateError::new(
            RefusalReason::WrongTypeOrLength,
            "state capability kind is unassigned",
        )
    })
}

fn read_hash512(item: &CanonicalItem) -> StateResult<Hash512> {
    let bytes: [u8; 64] = require_item_type(item, CanonicalItemType::Hash512)?
        .try_into()
        .map_err(|_| {
            StateError::new(
                RefusalReason::MalformedEncoding,
                "state hash has the wrong length",
            )
        })?;
    Ok(Hash512::from_bytes(bytes))
}

fn read_variable_byte_list(item: &CanonicalItem) -> StateResult<Vec<Vec<u8>>> {
    let bytes = require_item_type(item, CanonicalItemType::HomogeneousList)?;
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != CanonicalItemType::RawBytes.canonical_code()
    {
        return Err(StateError::new(
            RefusalReason::WrongTypeOrLength,
            "state carrier list has the wrong element type",
        ));
    }
    let count = usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
        .map_err(|_| {
            StateError::new(
                RefusalReason::OutsideSupportedProfile,
                "state carrier count does not fit the platform",
            )
        })?;
    validate_state_certificate_count(count)?;
    let mut offset = 6usize;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = offset.checked_add(4).ok_or_else(|| {
            StateError::new(
                RefusalReason::MalformedEncoding,
                "state carrier length offset overflows",
            )
        })?;
        if length_end > bytes.len() {
            return Err(StateError::new(
                RefusalReason::MalformedEncoding,
                "state carrier length is truncated",
            ));
        }
        let value_length = usize::try_from(u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]))
        .map_err(|_| {
            StateError::new(
                RefusalReason::OutsideSupportedProfile,
                "state carrier length does not fit the platform",
            )
        })?;
        let value_end = length_end.checked_add(value_length).ok_or_else(|| {
            StateError::new(
                RefusalReason::MalformedEncoding,
                "state carrier end offset overflows",
            )
        })?;
        if value_end > bytes.len() {
            return Err(StateError::new(
                RefusalReason::MalformedEncoding,
                "state carrier is truncated",
            ));
        }
        values.push(bytes[length_end..value_end].to_vec());
        offset = value_end;
    }
    if offset != bytes.len() {
        return Err(StateError::new(
            RefusalReason::MalformedEncoding,
            "state carrier list contains trailing bytes",
        ));
    }
    Ok(values)
}

pub fn derive_state_key(
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_id: ParticipantIdentity,
    capability_kind: StateCapabilityKind,
) -> StateResult<Hash512> {
    Ok(hash512(
        "sealed-lattice/state/key/v1",
        &[
            CanonicalItem::hash512(suite_id.into_bytes()),
            CanonicalItem::hash512(ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(action_context_hash.into_bytes()),
            CanonicalItem::participant_identity(participant_id.into_bytes()),
            CanonicalItem::unsigned16(capability_kind.canonical_code()),
        ],
    )?)
}

pub fn derive_state_exact_output_hash(
    capability_kind: StateCapabilityKind,
    exact_output_bytes: &[u8],
) -> StateResult<Hash512> {
    let byte_length = u64::try_from(exact_output_bytes.len()).map_err(|_| {
        StateError::new(
            RefusalReason::OutsideSupportedProfile,
            "exact state output length does not fit u64",
        )
    })?;
    let mut hasher = StateExactOutputHasher::new(capability_kind, byte_length)?;
    hasher.absorb(exact_output_bytes)?;
    hasher.finish()
}

/// Incremental form of the exact-output relation used by the canonical stream verifier.
///
/// Construction and completion stay crate-private so a `VerifiedCanonicalStreamSummary`
/// can only carry this digest after the generic stream verifier has consumed every
/// descriptor-bound byte.
pub(crate) struct StateExactOutputHasher {
    hasher: Shake256,
    total_byte_length: u64,
    observed_byte_length: u64,
}

impl StateExactOutputHasher {
    pub(crate) fn new(
        capability_kind: StateCapabilityKind,
        total_byte_length: u64,
    ) -> StateResult<Self> {
        if !capability_kind.supports_exact_output() {
            return Err(StateError::new(
                RefusalReason::WrongTypeOrLength,
                "reservation-only state capability has no exact output",
            ));
        }
        let raw_payload_byte_length = u32::try_from(total_byte_length).map_err(|_| {
            StateError::new(
                RefusalReason::OutsideSupportedProfile,
                "exact state output exceeds canonical raw-byte framing",
            )
        })?;
        let raw_item_byte_length = raw_payload_byte_length.checked_add(4).ok_or_else(|| {
            StateError::new(
                RefusalReason::OutsideSupportedProfile,
                "exact state output item length overflows",
            )
        })?;
        let domain_byte_length =
            u32::try_from(STATE_EXACT_OUTPUT_HASH_DOMAIN.len()).map_err(|_| {
                StateError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "exact state output domain length does not fit u32",
                )
            })?;
        let domain_item_byte_length = domain_byte_length.checked_add(4).ok_or_else(|| {
            StateError::new(
                RefusalReason::OutsideSupportedProfile,
                "exact state output domain item length overflows",
            )
        })?;

        let mut hasher = Shake256::default();
        hasher.update(&CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
        hasher.update(&CANONICAL_TUPLE_VERSION.to_le_bytes());
        hasher.update(&4_u32.to_le_bytes());
        hasher.update(&CanonicalItemType::Ascii.canonical_code().to_le_bytes());
        hasher.update(&domain_item_byte_length.to_le_bytes());
        hasher.update(&domain_byte_length.to_le_bytes());
        hasher.update(STATE_EXACT_OUTPUT_HASH_DOMAIN.as_bytes());
        hasher.update(&CanonicalItemType::Unsigned16.canonical_code().to_le_bytes());
        hasher.update(&2_u32.to_le_bytes());
        hasher.update(&capability_kind.canonical_code().to_le_bytes());
        hasher.update(&CanonicalItemType::Unsigned64.canonical_code().to_le_bytes());
        hasher.update(&8_u32.to_le_bytes());
        hasher.update(&total_byte_length.to_le_bytes());
        hasher.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
        hasher.update(&raw_item_byte_length.to_le_bytes());
        hasher.update(&raw_payload_byte_length.to_le_bytes());

        Ok(Self {
            hasher,
            total_byte_length,
            observed_byte_length: 0,
        })
    }

    pub(crate) fn absorb(&mut self, bytes: &[u8]) -> StateResult<()> {
        let byte_length = u64::try_from(bytes.len()).map_err(|_| {
            StateError::new(
                RefusalReason::OutsideSupportedProfile,
                "exact state output chunk length does not fit u64",
            )
        })?;
        let observed_byte_length = self
            .observed_byte_length
            .checked_add(byte_length)
            .ok_or_else(|| {
                StateError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "exact state output observed length overflows",
                )
            })?;
        if observed_byte_length > self.total_byte_length {
            return Err(StateError::new(
                RefusalReason::WrongTypeOrLength,
                "exact state output exceeds its declared byte length",
            ));
        }
        self.hasher.update(bytes);
        self.observed_byte_length = observed_byte_length;
        Ok(())
    }

    pub(crate) fn finish(self) -> StateResult<Hash512> {
        if self.observed_byte_length != self.total_byte_length {
            return Err(StateError::new(
                RefusalReason::WrongTypeOrLength,
                "exact state output is incomplete",
            ));
        }
        let mut reader = self.hasher.finalize_xof();
        let mut digest = [0_u8; Hash512::BYTE_LENGTH];
        reader.read(&mut digest);
        Ok(Hash512::from_bytes(digest))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StateWitnessVoteKind {
    Reservation,
    Output,
}

impl StateWitnessVoteKind {
    pub const fn canonical_code(self) -> u16 {
        match self {
            Self::Reservation => 1,
            Self::Output => 2,
        }
    }
}

pub const fn derive_state_witness_vote_sequence(vote_kind: StateWitnessVoteKind) -> u64 {
    match vote_kind {
        StateWitnessVoteKind::Reservation => 1,
        StateWitnessVoteKind::Output => 2,
    }
}

#[derive(Clone, Copy)]
struct StateReservationBinding {
    intent_object_hash: Hash512,
    subject_participant_id: ParticipantIdentity,
    capability_kind: StateCapabilityKind,
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    state_key: Hash512,
    authorization_hash: Hash512,
}

#[derive(Clone, Copy)]
struct StateOutputBinding {
    reservation_binding: StateReservationBinding,
    output_intent_object_hash: Hash512,
    exact_output_hash: Hash512,
    exact_output_byte_length: u64,
}

/// Verifier-derived durable lock metadata. This value is never decoded from a
/// producer artifact; it is projected only from a successfully verified state
/// intent or certified state capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDurableBinding {
    vote_kind: StateWitnessVoteKind,
    capability_kind: StateCapabilityKind,
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    subject_participant_id: ParticipantIdentity,
    state_key: Hash512,
    intent_object_hash: Hash512,
    reservation_intent_object_hash: Option<Hash512>,
    output_intent_object_hash: Option<Hash512>,
    exact_output_hash: Option<Hash512>,
    exact_output_byte_length: Option<u64>,
}

impl StateDurableBinding {
    pub const fn vote_kind(self) -> StateWitnessVoteKind {
        self.vote_kind
    }

    pub const fn capability_kind(self) -> StateCapabilityKind {
        self.capability_kind
    }

    pub const fn suite_id(self) -> Hash512 {
        self.suite_id
    }

    pub const fn ceremony_context_hash(self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub const fn subject_participant_id(self) -> ParticipantIdentity {
        self.subject_participant_id
    }

    pub const fn state_key(self) -> Hash512 {
        self.state_key
    }

    pub const fn intent_object_hash(self) -> Hash512 {
        self.intent_object_hash
    }

    pub const fn reservation_intent_object_hash(self) -> Option<Hash512> {
        self.reservation_intent_object_hash
    }

    pub const fn output_intent_object_hash(self) -> Option<Hash512> {
        self.output_intent_object_hash
    }

    pub const fn exact_output_hash(self) -> Option<Hash512> {
        self.exact_output_hash
    }

    pub const fn exact_output_byte_length(self) -> Option<u64> {
        self.exact_output_byte_length
    }

    pub const fn witness_vote_sequence(self) -> u64 {
        derive_state_witness_vote_sequence(self.vote_kind)
    }
}

pub struct VerifiedStateReservationIntent {
    binding: StateReservationBinding,
}

impl VerifiedStateReservationIntent {
    pub const fn durable_binding(&self) -> StateDurableBinding {
        durable_reservation_binding(self.binding)
    }
}

pub struct VerifiedStateReservation {
    binding: StateReservationBinding,
}

impl VerifiedStateReservation {
    pub const fn intent_object_hash(&self) -> Hash512 {
        self.binding.intent_object_hash
    }

    pub const fn subject_participant_id(&self) -> ParticipantIdentity {
        self.binding.subject_participant_id
    }

    pub const fn capability_kind(&self) -> StateCapabilityKind {
        self.binding.capability_kind
    }

    pub const fn suite_id(&self) -> Hash512 {
        self.binding.suite_id
    }

    pub const fn ceremony_context_hash(&self) -> Hash512 {
        self.binding.ceremony_context_hash
    }

    pub const fn action_context_hash(&self) -> Hash512 {
        self.binding.action_context_hash
    }

    pub const fn state_key(&self) -> Hash512 {
        self.binding.state_key
    }

    pub const fn authorization_hash(&self) -> Hash512 {
        self.binding.authorization_hash
    }

    pub const fn durable_binding(&self) -> StateDurableBinding {
        durable_reservation_binding(self.binding)
    }
}

pub struct VerifiedStateOutputIntent {
    binding: StateOutputBinding,
}

impl VerifiedStateOutputIntent {
    pub const fn durable_binding(&self) -> StateDurableBinding {
        durable_output_binding(self.binding)
    }
}

pub struct VerifiedStateOutput {
    binding: StateOutputBinding,
}

impl VerifiedStateOutput {
    pub const fn reservation_intent_object_hash(&self) -> Hash512 {
        self.binding.reservation_binding.intent_object_hash
    }

    pub const fn output_intent_object_hash(&self) -> Hash512 {
        self.binding.output_intent_object_hash
    }

    pub const fn subject_participant_id(&self) -> ParticipantIdentity {
        self.binding.reservation_binding.subject_participant_id
    }

    pub const fn capability_kind(&self) -> StateCapabilityKind {
        self.binding.reservation_binding.capability_kind
    }

    pub const fn suite_id(&self) -> Hash512 {
        self.binding.reservation_binding.suite_id
    }

    pub const fn ceremony_context_hash(&self) -> Hash512 {
        self.binding.reservation_binding.ceremony_context_hash
    }

    pub const fn action_context_hash(&self) -> Hash512 {
        self.binding.reservation_binding.action_context_hash
    }

    pub const fn state_key(&self) -> Hash512 {
        self.binding.reservation_binding.state_key
    }

    pub const fn authorization_hash(&self) -> Hash512 {
        self.binding.reservation_binding.authorization_hash
    }

    pub const fn exact_output_hash(&self) -> Hash512 {
        self.binding.exact_output_hash
    }

    pub const fn exact_output_byte_length(&self) -> u64 {
        self.binding.exact_output_byte_length
    }

    pub const fn durable_binding(&self) -> StateDurableBinding {
        durable_output_binding(self.binding)
    }
}

const fn durable_reservation_binding(binding: StateReservationBinding) -> StateDurableBinding {
    StateDurableBinding {
        vote_kind: StateWitnessVoteKind::Reservation,
        capability_kind: binding.capability_kind,
        suite_id: binding.suite_id,
        ceremony_context_hash: binding.ceremony_context_hash,
        action_context_hash: binding.action_context_hash,
        subject_participant_id: binding.subject_participant_id,
        state_key: binding.state_key,
        intent_object_hash: binding.intent_object_hash,
        reservation_intent_object_hash: Some(binding.intent_object_hash),
        output_intent_object_hash: None,
        exact_output_hash: None,
        exact_output_byte_length: None,
    }
}

const fn durable_output_binding(binding: StateOutputBinding) -> StateDurableBinding {
    StateDurableBinding {
        vote_kind: StateWitnessVoteKind::Output,
        capability_kind: binding.reservation_binding.capability_kind,
        suite_id: binding.reservation_binding.suite_id,
        ceremony_context_hash: binding.reservation_binding.ceremony_context_hash,
        action_context_hash: binding.reservation_binding.action_context_hash,
        subject_participant_id: binding.reservation_binding.subject_participant_id,
        state_key: binding.reservation_binding.state_key,
        intent_object_hash: binding.output_intent_object_hash,
        reservation_intent_object_hash: Some(binding.reservation_binding.intent_object_hash),
        output_intent_object_hash: Some(binding.output_intent_object_hash),
        exact_output_hash: Some(binding.exact_output_hash),
        exact_output_byte_length: Some(binding.exact_output_byte_length),
    }
}

pub struct StateReservationVerificationInput<'input> {
    pub subject_participant_id: ParticipantIdentity,
    pub capability_kind: StateCapabilityKind,
    pub expected_authorization_hash: Hash512,
    pub canonical_reservation_intent_carrier: &'input [u8],
    pub canonical_state_certificate: &'input [u8],
}

pub struct StateReservationIntentVerificationInput<'input> {
    pub subject_participant_id: ParticipantIdentity,
    pub capability_kind: StateCapabilityKind,
    pub expected_authorization_hash: Hash512,
    pub canonical_reservation_intent_carrier: &'input [u8],
}

pub struct StateVerifier {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
    canonical_decode_limits: CanonicalDecodeLimits,
}

impl StateVerifier {
    /// Constructs one suite-bound state verifier context.
    pub fn new(
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        roster: &Roster,
        canonical_decode_limits: CanonicalDecodeLimits,
    ) -> StateResult<Self> {
        Roster::new(roster.entries.clone()).map_err(StateError::from_schema)?;
        Ok(Self {
            suite_id,
            ceremony_context_hash,
            action_context_hash,
            roster: roster.clone(),
            canonical_decode_limits,
        })
    }

    pub fn verify_reservation(
        &self,
        input: StateReservationVerificationInput<'_>,
    ) -> VerificationResult<VerifiedStateReservation> {
        match self.verify_reservation_inner(input) {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    fn verify_reservation_inner(
        &self,
        input: StateReservationVerificationInput<'_>,
    ) -> StateResult<VerifiedStateReservation> {
        let verified_intent =
            self.verify_reservation_intent_inner(StateReservationIntentVerificationInput {
                subject_participant_id: input.subject_participant_id,
                capability_kind: input.capability_kind,
                expected_authorization_hash: input.expected_authorization_hash,
                canonical_reservation_intent_carrier: input.canonical_reservation_intent_carrier,
            })?;
        self.certify_reservation_inner(&verified_intent, input.canonical_state_certificate)
    }

    pub fn verify_reservation_intent(
        &self,
        input: StateReservationIntentVerificationInput<'_>,
    ) -> VerificationResult<VerifiedStateReservationIntent> {
        match self.verify_reservation_intent_inner(input) {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    fn verify_reservation_intent_inner(
        &self,
        input: StateReservationIntentVerificationInput<'_>,
    ) -> StateResult<VerifiedStateReservationIntent> {
        let carrier = self.decode_and_verify_subject_carrier(
            input.canonical_reservation_intent_carrier,
            FoundationObjectType::StateReservation,
            input.subject_participant_id,
            0,
        )?;
        let payload = StateReservationIntentPayload::decode(
            &carrier.envelope.payload_bytes,
            &self.canonical_decode_limits,
        )?;
        if payload.capability_kind != input.capability_kind {
            return Err(StateError::new(
                RefusalReason::WrongTypeOrLength,
                "reservation capability kind does not match the expected operation",
            ));
        }
        if payload.authorization_hash != input.expected_authorization_hash {
            return Err(StateError::new(
                RefusalReason::WrongHashOrRoot,
                "reservation authorization hash does not match the expected operation",
            ));
        }
        let state_key = derive_state_key(
            self.suite_id,
            self.ceremony_context_hash,
            self.action_context_hash,
            input.subject_participant_id,
            input.capability_kind,
        )?;
        let intent_object_hash = carrier
            .envelope
            .object_hash()
            .map_err(StateError::from_schema)?;
        Ok(VerifiedStateReservationIntent {
            binding: StateReservationBinding {
                intent_object_hash,
                subject_participant_id: input.subject_participant_id,
                capability_kind: input.capability_kind,
                suite_id: self.suite_id,
                ceremony_context_hash: self.ceremony_context_hash,
                action_context_hash: self.action_context_hash,
                state_key,
                authorization_hash: payload.authorization_hash,
            },
        })
    }

    pub fn certify_reservation_intent(
        &self,
        verified_intent: &VerifiedStateReservationIntent,
        canonical_state_certificate: &[u8],
    ) -> VerificationResult<VerifiedStateReservation> {
        match self.certify_reservation_inner(verified_intent, canonical_state_certificate) {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    pub fn certify_reservation_intent_from_unordered_vote_carriers(
        &self,
        verified_intent: &VerifiedStateReservationIntent,
        canonical_vote_carriers: &[Vec<u8>],
    ) -> VerificationResult<VerifiedStateReservation> {
        let binding = verified_intent.binding;
        let result = self
            .require_reservation_binding_context(binding)
            .and_then(|()| {
                self.verify_unordered_vote_carriers(
                    canonical_vote_carriers,
                    &ResolvedStateIntent {
                        intent_object_hash: binding.intent_object_hash,
                        subject_participant_id: binding.subject_participant_id,
                        vote_kind: StateWitnessVoteKind::Reservation,
                    },
                )
            })
            .map(|()| VerifiedStateReservation { binding });
        match result {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    fn certify_reservation_inner(
        &self,
        verified_intent: &VerifiedStateReservationIntent,
        canonical_state_certificate: &[u8],
    ) -> StateResult<VerifiedStateReservation> {
        let binding = verified_intent.binding;
        self.require_reservation_binding_context(binding)?;
        self.verify_certificate(
            canonical_state_certificate,
            &ResolvedStateIntent {
                intent_object_hash: binding.intent_object_hash,
                subject_participant_id: binding.subject_participant_id,
                vote_kind: StateWitnessVoteKind::Reservation,
            },
        )?;
        Ok(VerifiedStateReservation { binding })
    }

    pub(crate) fn verify_output_from_verified_stream(
        &self,
        verified_reservation: &VerifiedStateReservation,
        canonical_output_intent_carrier: &[u8],
        canonical_state_certificate: &[u8],
        verified_stream: VerifiedCanonicalStreamSummary,
    ) -> VerificationResult<VerifiedStateOutput> {
        let binding = verified_reservation.binding;
        if !binding.capability_kind.supports_exact_output() {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        }
        if verified_stream
            .stream_domain()
            .state_exact_output_capability_kind()
            != Some(binding.capability_kind)
        {
            return VerificationResult::refused(RefusalReason::WrongContext);
        }
        let Some(exact_output_hash) = verified_stream.state_exact_output_hash() else {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        };
        let verified_intent = match self.verify_output_intent_binding(
            verified_reservation,
            canonical_output_intent_carrier,
            exact_output_hash,
            verified_stream.total_byte_length(),
        ) {
            Ok(value) => value,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        match self.certify_output_inner(&verified_intent, canonical_state_certificate) {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    pub(crate) fn verify_output_intent_from_verified_stream(
        &self,
        verified_reservation: &VerifiedStateReservation,
        canonical_output_intent_carrier: &[u8],
        verified_stream: VerifiedCanonicalStreamSummary,
    ) -> VerificationResult<VerifiedStateOutputIntent> {
        let binding = verified_reservation.binding;
        if !binding.capability_kind.supports_exact_output() {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        }
        if verified_stream
            .stream_domain()
            .state_exact_output_capability_kind()
            != Some(binding.capability_kind)
        {
            return VerificationResult::refused(RefusalReason::WrongContext);
        }
        let Some(exact_output_hash) = verified_stream.state_exact_output_hash() else {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        };
        match self.verify_output_intent_binding(
            verified_reservation,
            canonical_output_intent_carrier,
            exact_output_hash,
            verified_stream.total_byte_length(),
        ) {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    fn verify_output_intent_binding(
        &self,
        verified_reservation: &VerifiedStateReservation,
        canonical_output_intent_carrier: &[u8],
        exact_output_hash: Hash512,
        exact_output_byte_length: u64,
    ) -> StateResult<VerifiedStateOutputIntent> {
        self.require_reservation_context(verified_reservation)?;
        let binding = verified_reservation.binding;
        let carrier = self.decode_and_verify_subject_carrier(
            canonical_output_intent_carrier,
            FoundationObjectType::StateOutputIntent,
            binding.subject_participant_id,
            0,
        )?;
        let payload = StateOutputIntentPayload::decode(
            &carrier.envelope.payload_bytes,
            &self.canonical_decode_limits,
        )?;
        if payload.reservation_intent_object_hash != binding.intent_object_hash {
            return Err(StateError::new(
                RefusalReason::MissingPrerequisite,
                "output intent does not reference its verified reservation",
            ));
        }
        if payload.exact_output_hash != exact_output_hash {
            return Err(StateError::new(
                RefusalReason::WrongHashOrRoot,
                "output intent does not bind the complete exact output",
            ));
        }
        let output_intent_object_hash = carrier
            .envelope
            .object_hash()
            .map_err(StateError::from_schema)?;
        Ok(VerifiedStateOutputIntent {
            binding: StateOutputBinding {
                reservation_binding: binding,
                output_intent_object_hash,
                exact_output_hash,
                exact_output_byte_length,
            },
        })
    }

    pub fn certify_output_intent(
        &self,
        verified_intent: &VerifiedStateOutputIntent,
        canonical_state_certificate: &[u8],
    ) -> VerificationResult<VerifiedStateOutput> {
        match self.certify_output_inner(verified_intent, canonical_state_certificate) {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    pub fn certify_output_intent_from_unordered_vote_carriers(
        &self,
        verified_intent: &VerifiedStateOutputIntent,
        canonical_vote_carriers: &[Vec<u8>],
    ) -> VerificationResult<VerifiedStateOutput> {
        let binding = verified_intent.binding;
        let result = self
            .require_reservation_binding_context(binding.reservation_binding)
            .and_then(|()| {
                self.verify_unordered_vote_carriers(
                    canonical_vote_carriers,
                    &ResolvedStateIntent {
                        intent_object_hash: binding.output_intent_object_hash,
                        subject_participant_id: binding.reservation_binding.subject_participant_id,
                        vote_kind: StateWitnessVoteKind::Output,
                    },
                )
            })
            .map(|()| VerifiedStateOutput { binding });
        match result {
            Ok(value) => VerificationResult::valid(value),
            Err(error) => VerificationResult::refused(error.refusal_reason),
        }
    }

    fn certify_output_inner(
        &self,
        verified_intent: &VerifiedStateOutputIntent,
        canonical_state_certificate: &[u8],
    ) -> StateResult<VerifiedStateOutput> {
        let binding = verified_intent.binding;
        self.require_reservation_binding_context(binding.reservation_binding)?;
        self.verify_certificate(
            canonical_state_certificate,
            &ResolvedStateIntent {
                intent_object_hash: binding.output_intent_object_hash,
                subject_participant_id: binding.reservation_binding.subject_participant_id,
                vote_kind: StateWitnessVoteKind::Output,
            },
        )?;
        Ok(VerifiedStateOutput { binding })
    }

    fn require_reservation_context(
        &self,
        reservation: &VerifiedStateReservation,
    ) -> StateResult<()> {
        self.require_reservation_binding_context(reservation.binding)
    }

    fn require_reservation_binding_context(
        &self,
        binding: StateReservationBinding,
    ) -> StateResult<()> {
        if binding.suite_id != self.suite_id
            || binding.ceremony_context_hash != self.ceremony_context_hash
            || binding.action_context_hash != self.action_context_hash
        {
            return Err(StateError::new(
                RefusalReason::WrongContext,
                "verified reservation belongs to another state verifier context",
            ));
        }
        Ok(())
    }

    fn decode_and_verify_subject_carrier(
        &self,
        canonical_carrier: &[u8],
        expected_object_type: FoundationObjectType,
        expected_subject_participant_id: ParticipantIdentity,
        expected_producer_sequence: u64,
    ) -> StateResult<SignedCarrier> {
        let carrier = SignedCarrier::decode(canonical_carrier, &self.canonical_decode_limits)
            .map_err(StateError::from_schema)?;
        self.require_envelope_context(&carrier.envelope)?;
        if carrier.envelope.object_type != expected_object_type
            || carrier.envelope.producer_participant_id != Some(expected_subject_participant_id)
            || carrier.envelope.producer_sequence != expected_producer_sequence
            || !carrier.envelope.ordered_prerequisite_hashes.is_empty()
        {
            return Err(StateError::new(
                RefusalReason::WrongContext,
                "state intent envelope does not match the expected subject slot",
            ));
        }
        carrier
            .verify_signature(&self.roster)
            .into_result()
            .map_err(|refusal_reason| {
                StateError::new(refusal_reason, "state intent signature does not verify")
            })?;
        Ok(carrier)
    }

    fn require_envelope_context(&self, envelope: &ObjectEnvelope) -> StateResult<()> {
        if envelope.suite_id != self.suite_id
            || envelope.ceremony_context_hash != self.ceremony_context_hash
            || envelope.action_context_hash != self.action_context_hash
        {
            return Err(StateError::new(
                RefusalReason::WrongContext,
                "state envelope belongs to another suite or context",
            ));
        }
        Ok(())
    }

    fn verify_certificate(
        &self,
        canonical_state_certificate: &[u8],
        expected_intent: &ResolvedStateIntent,
    ) -> StateResult<()> {
        let certificate =
            StateCertificate::decode(canonical_state_certificate, &self.canonical_decode_limits)?;
        self.verify_ordered_vote_carriers(
            certificate.canonical_signed_state_witness_vote_carriers(),
            expected_intent,
        )
    }

    fn verify_ordered_vote_carriers(
        &self,
        canonical_vote_carriers: &[Vec<u8>],
        expected_intent: &ResolvedStateIntent,
    ) -> StateResult<()> {
        let expected_sequence = derive_state_witness_vote_sequence(expected_intent.vote_kind);
        let mut previous_roster_position = None;
        for canonical_vote_carrier in canonical_vote_carriers {
            let verified_vote = self.verify_vote_carrier(
                canonical_vote_carrier,
                expected_intent,
                expected_sequence,
            )?;
            if verified_vote.intent_object_hash != expected_intent.intent_object_hash {
                return Err(StateError::new(
                    RefusalReason::WrongHashOrRoot,
                    "state witness vote does not resolve to the exact expected intent",
                ));
            }
            let roster_position = verified_vote.roster_position;
            if let Some(previous_position) = previous_roster_position {
                if roster_position == previous_position {
                    return Err(StateError::new(
                        RefusalReason::DuplicateIdentity,
                        "state certificate contains a duplicate witness",
                    ));
                }
                if roster_position < previous_position {
                    return Err(StateError::new(
                        RefusalReason::WrongTypeOrLength,
                        "state certificate witnesses are not in participant roster order",
                    ));
                }
            }
            previous_roster_position = Some(roster_position);
        }
        Ok(())
    }

    fn verify_unordered_vote_carriers(
        &self,
        canonical_vote_carriers: &[Vec<u8>],
        expected_intent: &ResolvedStateIntent,
    ) -> StateResult<()> {
        const MAXIMUM_UNTRUSTED_STATE_VOTE_CARRIER_COUNT: usize =
            FOUNDATION_PROFILE.participant_count as usize * 2;
        if canonical_vote_carriers.is_empty()
            || canonical_vote_carriers.len() > MAXIMUM_UNTRUSTED_STATE_VOTE_CARRIER_COUNT
        {
            return Err(StateError::new(
                RefusalReason::OutsideSupportedProfile,
                "untrusted state vote carrier count is outside the supported profile",
            ));
        }
        let expected_sequence = derive_state_witness_vote_sequence(expected_intent.vote_kind);
        let mut unique_votes: Vec<VerifiedStateWitnessVote> = Vec::new();
        for canonical_vote_carrier in canonical_vote_carriers {
            let verified_vote = self.verify_vote_carrier(
                canonical_vote_carrier,
                expected_intent,
                expected_sequence,
            )?;
            if let Some(previous_vote) = unique_votes
                .iter()
                .find(|previous| previous.roster_position == verified_vote.roster_position)
            {
                if previous_vote.intent_object_hash != verified_vote.intent_object_hash {
                    return Err(StateError::new(
                        RefusalReason::Equivocation,
                        "one authenticated witness slot contains conflicting state votes",
                    ));
                }
                continue;
            }
            unique_votes.push(verified_vote);
        }
        unique_votes.sort_unstable_by_key(|vote| vote.roster_position);
        validate_state_certificate_count(unique_votes.len())?;
        if unique_votes
            .iter()
            .any(|vote| vote.intent_object_hash != expected_intent.intent_object_hash)
        {
            return Err(StateError::new(
                RefusalReason::WrongHashOrRoot,
                "state witness vote does not resolve to the exact expected intent",
            ));
        }
        Ok(())
    }

    fn verify_vote_carrier(
        &self,
        canonical_vote_carrier: &[u8],
        expected_intent: &ResolvedStateIntent,
        expected_sequence: u64,
    ) -> StateResult<VerifiedStateWitnessVote> {
        let vote_carrier =
            SignedCarrier::decode(canonical_vote_carrier, &self.canonical_decode_limits)
                .map_err(StateError::from_schema)?;
        self.require_envelope_context(&vote_carrier.envelope)?;
        let envelope = &vote_carrier.envelope;
        if envelope.object_type != FoundationObjectType::StateWitnessVote
            || envelope.producer_sequence != expected_sequence
            || !envelope.ordered_prerequisite_hashes.is_empty()
        {
            return Err(StateError::new(
                RefusalReason::WrongContext,
                "state witness vote does not match the derived producer slot",
            ));
        }
        let witness_participant_id = envelope.producer_participant_id.ok_or_else(|| {
            StateError::new(
                RefusalReason::WrongTypeOrLength,
                "state witness vote does not name its producer",
            )
        })?;
        if witness_participant_id == expected_intent.subject_participant_id {
            return Err(StateError::new(
                RefusalReason::WrongContext,
                "the state subject cannot witness its own intent",
            ));
        }
        let roster_position = self.roster_position(witness_participant_id)?;
        vote_carrier
            .verify_signature(&self.roster)
            .into_result()
            .map_err(|refusal_reason| {
                StateError::new(
                    refusal_reason,
                    "state witness vote signature does not verify",
                )
            })?;
        let payload = StateWitnessVotePayload::decode(
            &envelope.payload_bytes,
            &self.canonical_decode_limits,
        )?;
        Ok(VerifiedStateWitnessVote {
            intent_object_hash: payload.intent_object_hash,
            roster_position,
        })
    }

    fn roster_position(&self, participant_id: ParticipantIdentity) -> StateResult<u16> {
        for (roster_position, roster_entry) in self.roster.entries.iter().enumerate() {
            let roster_participant_id = roster_entry
                .participant_identity()
                .map_err(StateError::from_schema)?;
            if roster_participant_id == participant_id {
                return u16::try_from(roster_position).map_err(|_| {
                    StateError::new(
                        RefusalReason::OutsideSupportedProfile,
                        "roster position does not fit the canonical field width",
                    )
                });
            }
        }
        Err(StateError::new(
            RefusalReason::WrongContext,
            "state witness is not present in the participant roster",
        ))
    }
}

struct ResolvedStateIntent {
    intent_object_hash: Hash512,
    subject_participant_id: ParticipantIdentity,
    vote_kind: StateWitnessVoteKind,
}

#[derive(Clone, Copy)]
struct VerifiedStateWitnessVote {
    intent_object_hash: Hash512,
    roster_position: u16,
}

#[cfg(test)]
mod tests;
