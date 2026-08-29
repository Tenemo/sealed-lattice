use core::{cell::RefCell, fmt, str};

use zeroize::Zeroizing;

use crate::{
    foundation::{
        ActionContext, ActionDefinition, BoardPolicy, CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
        CanonicalTuple, CeremonyContext, FOUNDATION_PROFILE, Hash512, Manifest, Roster,
    },
    tally_preparation::{
        VerifiedDirectMpcOneAndPreprocessingSource,
        VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
        VerifiedPseudorandomZeroSharingSeedRecipientSelection320,
        verify_direct_mpc_one_and_preprocessing_source_from_joined_custody,
        verify_pseudorandom_zero_sharing_seed_recipient_authenticated_inconsistency_320,
        verify_pseudorandom_zero_sharing_seed_recipient_authenticated_inconsistency_disclosure_320,
        verify_pseudorandom_zero_sharing_seed_recipient_selection_320,
    },
};

use super::direct_mpc_preprocessing_source_terminal::{
    DirectMpcPreprocessingSourceOutcomeCandidate, DirectMpcPreprocessingSourceTerminalError,
    DirectMpcPreprocessingSourceTerminalVerification, PreparedDirectMpcPreprocessingSourceTerminal,
    direct_mpc_preprocessing_source_endorsement_carrier_bytes,
    direct_mpc_preprocessing_source_terminal_bytes,
    prepare_direct_mpc_preprocessing_source_terminal,
    verify_direct_mpc_preprocessing_source_terminal,
};
use super::{
    STATE_OUTPUT_CERTIFICATE_DOMAIN, STATE_SUBJECT_SIGNATURE_CONTEXT,
    STATE_WITNESS_ENVELOPE_DOMAIN, STATE_WITNESS_SIGNATURE_CONTEXT, StateSubjectAuthorizationBody,
    StateWitnessAuthorizationBody, encode_domain_tuple, state_witness_certificate_identity,
    verify_state_output_certificate, verify_witness_envelopes,
};

const REQUEST_MAGIC: &[u8; 4] = b"SLPS";
const RESPONSE_MAGIC: &[u8; 4] = b"SLPT";
const CODEC_VERSION: u16 = 1;

const OPEN_OUTCOME_OPERATION: u8 = 1;
const PREPARE_WITNESS_OPERATION: u8 = 2;
const COMPLETE_WITNESS_OPERATION: u8 = 3;
const PREPARE_SUBJECT_OPERATION: u8 = 4;
const COMPLETE_SUBJECT_OPERATION: u8 = 5;
const CREATE_TERMINAL_OPERATION: u8 = 6;
const VALIDATE_TERMINAL_OPERATION: u8 = 7;
const CLOSE_OUTCOME_OPERATION: u8 = 8;

const FAILURE_STATUS: u8 = 0;
const OPEN_OUTCOME_STATUS: u8 = 1;
const PREPARED_WITNESS_STATUS: u8 = 2;
const COMPLETED_WITNESS_STATUS: u8 = 3;
const PREPARED_SUBJECT_STATUS: u8 = 4;
const COMPLETED_SUBJECT_STATUS: u8 = 5;
const TERMINAL_STATUS: u8 = 6;
const CLOSED_OUTCOME_STATUS: u8 = 7;
const PENDING_OUTCOME_STATUS: u8 = 8;

const SUCCESS_OUTCOME: u8 = 1;
const BURN_OUTCOME: u8 = 2;

const AUTHENTICATION_RECORD_MAGIC: &[u8; 4] = b"SLRA";
const AUTHENTICATION_RECORD_VERSION: u16 = 2;
const SELECTED_AUTHENTICATION_RECORD: u8 = 1;
const BURNED_AUTHENTICATION_RECORD: u8 = 2;
const JOINED_AUTHENTICATION_RECORD: u8 = 3;
const AUTHENTICATED_DELIVERY_INCONSISTENCY_REASON: u8 = 1;

const PUBLIC_INCONSISTENCY_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-inconsistency-carrier";
const PUBLIC_INCONSISTENCY_CARRIER_ITEM_COUNT: usize = 5;

const MAXIMUM_COPIED_BUFFER_BYTE_LENGTH: usize = 8 * 1024 * 1024;
const MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH: usize = 2 * 1024 * 1024;
const MAXIMUM_FOUNDATION_OBJECT_BYTE_LENGTH: usize = 2 * 1024 * 1024;
const MAXIMUM_EXTERNAL_IDENTIFIER_BYTE_LENGTH: usize = 4096;
const MAXIMUM_STATE_CARRIER_COUNT: usize = 32;
const ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = 3_309;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcPreprocessingSourceStateKernelError {
    MalformedRequest(&'static str),
    ResourceLimit(&'static str),
    WrongFoundation,
    WrongPredecessor,
    WrongContext,
    MissingPrerequisite,
    StateVerification,
    ContextUnavailable,
    ConsumedState,
}

impl DirectMpcPreprocessingSourceStateKernelError {
    const fn response_code(&self) -> u16 {
        match self {
            Self::MalformedRequest(_) => 1,
            Self::ResourceLimit(_) => 2,
            Self::WrongFoundation => 3,
            Self::WrongPredecessor => 4,
            Self::WrongContext => 5,
            Self::MissingPrerequisite => 6,
            Self::StateVerification => 7,
            Self::ContextUnavailable => 8,
            Self::ConsumedState => 9,
        }
    }
}

impl fmt::Display for DirectMpcPreprocessingSourceStateKernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRequest(field) => {
                write!(
                    formatter,
                    "preprocessing-source state request is malformed: {field}"
                )
            }
            Self::ResourceLimit(field) => {
                write!(
                    formatter,
                    "preprocessing-source state resource limit: {field}"
                )
            }
            Self::WrongFoundation => {
                formatter.write_str("preprocessing-source state foundation evidence is invalid")
            }
            Self::WrongPredecessor => {
                formatter.write_str("preprocessing-source state predecessor evidence is invalid")
            }
            Self::WrongContext => {
                formatter.write_str("preprocessing-source state context does not match")
            }
            Self::MissingPrerequisite => formatter
                .write_str("preprocessing-source state is pending authenticated predecessor bytes"),
            Self::StateVerification => {
                formatter.write_str("preprocessing-source state authorization is invalid")
            }
            Self::ContextUnavailable => {
                formatter.write_str("preprocessing-source state context is unavailable")
            }
            Self::ConsumedState => formatter
                .write_str("preprocessing-source state terminal has already consumed its state"),
        }
    }
}

impl std::error::Error for DirectMpcPreprocessingSourceStateKernelError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthenticationScope {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    root_terminal_identity: Hash512,
    preparation_attempt_ordinal: u16,
    participant_count: u16,
    recipient_position: u16,
}

enum AuthenticationRecord<'a> {
    Selected {
        scope: AuthenticationScope,
        canonical_open_request_bytes: &'a [u8],
    },
    Burned {
        scope: AuthenticationScope,
        canonical_open_request_bytes: &'a [u8],
        sender_position: u16,
        recipient_position: u16,
        disclosed_authenticated_encryption_key: [u8; 32],
        evidence_identity: Hash512,
    },
    Joined {
        scope: AuthenticationScope,
        receipt_terminal_identity: Hash512,
    },
}

impl AuthenticationRecord<'_> {
    const fn scope(&self) -> AuthenticationScope {
        match self {
            Self::Selected { scope, .. }
            | Self::Burned { scope, .. }
            | Self::Joined { scope, .. } => *scope,
        }
    }
}

#[derive(Debug, Clone)]
enum OwnedSourceOutcome {
    Success(VerifiedDirectMpcOneAndPreprocessingSource),
    Burn(VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320),
}

impl OwnedSourceOutcome {
    fn candidate(&self) -> DirectMpcPreprocessingSourceOutcomeCandidate<'_> {
        match self {
            Self::Success(source) => DirectMpcPreprocessingSourceOutcomeCandidate::Success(source),
            Self::Burn(evidence) => DirectMpcPreprocessingSourceOutcomeCandidate::Burn(evidence),
        }
    }

    const fn status(&self) -> u8 {
        match self {
            Self::Success(_) => SUCCESS_OUTCOME,
            Self::Burn(_) => BURN_OUTCOME,
        }
    }
}

struct VerifiedStateContext {
    action_context: ActionContext,
    roster: Roster,
    outcome: OwnedSourceOutcome,
    prepared: PreparedDirectMpcPreprocessingSourceTerminal,
    local_participant_position: u16,
    public_inconsistency_carrier_bytes: Option<Vec<u8>>,
}

struct VerifiedStateContextRegistry {
    next_handle: u32,
    retained: Option<(u32, VerifiedStateContext)>,
}

impl Default for VerifiedStateContextRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            retained: None,
        }
    }
}

thread_local! {
    static VERIFIED_STATE_CONTEXTS: RefCell<VerifiedStateContextRegistry> =
        RefCell::new(VerifiedStateContextRegistry::default());
}

struct BoundedCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BoundedCursor<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, DirectMpcPreprocessingSourceStateKernelError> {
        if bytes.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
            return Err(DirectMpcPreprocessingSourceStateKernelError::ResourceLimit(
                "input byte length",
            ));
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn read_exact(
        &mut self,
        byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], DirectMpcPreprocessingSourceStateKernelError> {
        let end = self.offset.checked_add(byte_length).ok_or(
            DirectMpcPreprocessingSourceStateKernelError::ResourceLimit(field),
        )?;
        if end > self.bytes.len() {
            return Err(DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(field));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_unsigned8(
        &mut self,
        field: &'static str,
    ) -> Result<u8, DirectMpcPreprocessingSourceStateKernelError> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_unsigned16(
        &mut self,
        field: &'static str,
    ) -> Result<u16, DirectMpcPreprocessingSourceStateKernelError> {
        Ok(u16::from_le_bytes(
            self.read_exact(size_of::<u16>(), field)?
                .try_into()
                .map_err(|_| {
                    DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(field)
                })?,
        ))
    }

    fn read_unsigned32(
        &mut self,
        field: &'static str,
    ) -> Result<usize, DirectMpcPreprocessingSourceStateKernelError> {
        usize::try_from(u32::from_le_bytes(
            self.read_exact(size_of::<u32>(), field)?
                .try_into()
                .map_err(|_| {
                    DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(field)
                })?,
        ))
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::ResourceLimit(field))
    }

    fn read_hash512(
        &mut self,
        field: &'static str,
    ) -> Result<Hash512, DirectMpcPreprocessingSourceStateKernelError> {
        Ok(Hash512::from_bytes(
            self.read_exact(Hash512::BYTE_LENGTH, field)?
                .try_into()
                .map_err(|_| {
                    DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(field)
                })?,
        ))
    }

    fn read_bounded_bytes(
        &mut self,
        maximum_byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], DirectMpcPreprocessingSourceStateKernelError> {
        let byte_length = self.read_unsigned32(field)?;
        if byte_length == 0 || byte_length > maximum_byte_length {
            return Err(DirectMpcPreprocessingSourceStateKernelError::ResourceLimit(
                field,
            ));
        }
        self.read_exact(byte_length, field)
    }

    fn read_optional_bounded_bytes(
        &mut self,
        maximum_byte_length: usize,
        field: &'static str,
    ) -> Result<Option<&'a [u8]>, DirectMpcPreprocessingSourceStateKernelError> {
        match self.read_unsigned8(field)? {
            0 => Ok(None),
            1 => Ok(Some(self.read_bounded_bytes(maximum_byte_length, field)?)),
            _ => Err(DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(field)),
        }
    }

    fn require_magic(
        &mut self,
        expected: &[u8; 4],
        field: &'static str,
    ) -> Result<(), DirectMpcPreprocessingSourceStateKernelError> {
        if self.read_exact(expected.len(), field)? != expected {
            return Err(DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(field));
        }
        Ok(())
    }

    fn require_complete(
        &self,
        field: &'static str,
    ) -> Result<(), DirectMpcPreprocessingSourceStateKernelError> {
        if self.offset != self.bytes.len() {
            return Err(DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(field));
        }
        Ok(())
    }
}

fn parse_authentication_record(
    bytes: &[u8],
) -> Result<AuthenticationRecord<'_>, DirectMpcPreprocessingSourceStateKernelError> {
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(AUTHENTICATION_RECORD_MAGIC, "authentication-record magic")?;
    if cursor.read_unsigned16("authentication-record version")? != AUTHENTICATION_RECORD_VERSION {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor);
    }
    let record_kind = cursor.read_unsigned8("authentication-record kind")?;
    let scope = AuthenticationScope {
        parameter_identity: cursor.read_hash512("authentication parameter identity")?,
        preparation_context_identity: cursor
            .read_hash512("authentication preparation-context identity")?,
        root_terminal_identity: cursor.read_hash512("authentication root-terminal identity")?,
        preparation_attempt_ordinal: cursor
            .read_unsigned16("authentication preparation-attempt ordinal")?,
        participant_count: cursor.read_unsigned16("authentication participant count")?,
        recipient_position: cursor.read_unsigned16("authentication recipient position")?,
    };
    if scope.preparation_attempt_ordinal != 0
        || scope.participant_count != FOUNDATION_PROFILE.participant_count
        || scope.recipient_position >= scope.participant_count
    {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
    }
    let record = match record_kind {
        SELECTED_AUTHENTICATION_RECORD => {
            let canonical_open_request_bytes = cursor.read_bounded_bytes(
                MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
                "selected canonical open request",
            )?;
            AuthenticationRecord::Selected {
                scope,
                canonical_open_request_bytes,
            }
        }
        BURNED_AUTHENTICATION_RECORD => {
            let canonical_open_request_bytes = cursor.read_bounded_bytes(
                MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
                "burned canonical open request",
            )?;
            if cursor.read_unsigned8("authentication burn reason")?
                != AUTHENTICATED_DELIVERY_INCONSISTENCY_REASON
            {
                return Err(DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor);
            }
            let sender_position = cursor.read_unsigned16("inconsistency sender position")?;
            let recipient_position = cursor.read_unsigned16("inconsistency recipient position")?;
            let disclosed_authenticated_encryption_key = cursor
                .read_exact(32, "disclosed authenticated-encryption key")?
                .try_into()
                .map_err(|_| {
                    DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(
                        "disclosed authenticated-encryption key",
                    )
                })?;
            let evidence_identity = cursor.read_hash512("authenticated-inconsistency identity")?;
            if recipient_position != scope.recipient_position
                || sender_position >= scope.participant_count
                || sender_position == recipient_position
            {
                return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
            }
            AuthenticationRecord::Burned {
                scope,
                canonical_open_request_bytes,
                sender_position,
                recipient_position,
                disclosed_authenticated_encryption_key,
                evidence_identity,
            }
        }
        JOINED_AUTHENTICATION_RECORD => AuthenticationRecord::Joined {
            scope,
            receipt_terminal_identity: cursor
                .read_hash512("authentication receipt-terminal identity")?,
        },
        _ => return Err(DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor),
    };
    cursor.require_complete("authentication-record trailing bytes")?;
    Ok(record)
}

fn foundation_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_FOUNDATION_OBJECT_BYTE_LENGTH,
        maximum_item_count: 128,
        maximum_item_byte_length: MAXIMUM_FOUNDATION_OBJECT_BYTE_LENGTH,
        maximum_nesting_depth: 4,
        maximum_cumulative_work_byte_length: MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length: MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
    }
}

fn parse_foundation(
    cursor: &mut BoundedCursor<'_>,
) -> Result<(ActionContext, Roster), DirectMpcPreprocessingSourceStateKernelError> {
    let suite_identity = cursor.read_hash512("suite identity")?;
    let manifest_bytes =
        cursor.read_bounded_bytes(MAXIMUM_FOUNDATION_OBJECT_BYTE_LENGTH, "canonical manifest")?;
    let roster_bytes =
        cursor.read_bounded_bytes(MAXIMUM_FOUNDATION_OBJECT_BYTE_LENGTH, "canonical roster")?;
    let ceremony_identifier_bytes = cursor.read_bounded_bytes(
        MAXIMUM_EXTERNAL_IDENTIFIER_BYTE_LENGTH,
        "ceremony identifier",
    )?;
    let action_identifier_bytes =
        cursor.read_bounded_bytes(MAXIMUM_EXTERNAL_IDENTIFIER_BYTE_LENGTH, "action identifier")?;
    let action_definition_bytes = cursor.read_bounded_bytes(
        MAXIMUM_FOUNDATION_OBJECT_BYTE_LENGTH,
        "canonical action definition",
    )?;
    let board_policy_bytes = cursor.read_bounded_bytes(
        MAXIMUM_FOUNDATION_OBJECT_BYTE_LENGTH,
        "canonical board policy",
    )?;
    let limits = foundation_decode_limits();
    let manifest = Manifest::decode(manifest_bytes, &limits)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?;
    let roster = Roster::decode(roster_bytes, &limits)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?;
    let action_definition = ActionDefinition::decode(action_definition_bytes, &limits)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?;
    let board_policy = BoardPolicy::decode(board_policy_bytes, &limits)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?;
    if manifest
        .encode()
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?
        != manifest_bytes
        || roster
            .encode()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?
            != roster_bytes
        || action_definition
            .encode()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?
            != action_definition_bytes
        || board_policy
            .encode()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?
            != board_policy_bytes
    {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongFoundation);
    }
    let ceremony_identifier = str::from_utf8(ceremony_identifier_bytes)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?
        .to_owned();
    let action_identifier = str::from_utf8(action_identifier_bytes)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?
        .to_owned();
    let ceremony_context =
        CeremonyContext::new(suite_identity, &manifest, &roster, ceremony_identifier)
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?;
    let action_context = ActionContext::new(
        &ceremony_context,
        action_identifier,
        action_definition,
        &board_policy,
    )
    .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?;
    Ok((action_context, roster))
}

fn require_authentication_scope_matches_selection(
    scope: AuthenticationScope,
    selection: VerifiedPseudorandomZeroSharingSeedRecipientSelection320,
    action_context: &ActionContext,
    roster: &Roster,
) -> Result<(), DirectMpcPreprocessingSourceStateKernelError> {
    let roster_identity = roster
        .roster_hash()
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongFoundation)?;
    let preparation_context = selection.preparation_context();
    if selection.parameter_identity() != scope.parameter_identity
        || preparation_context.identity() != scope.preparation_context_identity
        || selection.root_terminal_identity() != scope.root_terminal_identity
        || selection.participant_count() != scope.participant_count
        || selection.recipient_position() != scope.recipient_position
        || preparation_context.action_context_hash() != action_context.context_hash()
        || preparation_context.roster_hash() != roster_identity
    {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
    }
    Ok(())
}

fn require_authentication_scope_matches_source(
    scope: AuthenticationScope,
    receipt_terminal_identity: Hash512,
    source: &VerifiedDirectMpcOneAndPreprocessingSource,
    participant_position: u16,
) -> Result<(), DirectMpcPreprocessingSourceStateKernelError> {
    if source.parameter_identity() != scope.parameter_identity
        || source.preparation_context().identity() != scope.preparation_context_identity
        || source.root_terminal_identity() != scope.root_terminal_identity
        || source.preparation_context().participant_count() != scope.participant_count
        || participant_position != scope.recipient_position
        || source.receipt_terminal_identity() != receipt_terminal_identity
    {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
    }
    Ok(())
}

fn require_authentication_scope_matches_evidence(
    scope: AuthenticationScope,
    evidence: VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
) -> Result<(), DirectMpcPreprocessingSourceStateKernelError> {
    if evidence.parameter_identity() != scope.parameter_identity
        || evidence.preparation_context().identity() != scope.preparation_context_identity
        || evidence.root_terminal_identity() != scope.root_terminal_identity
        || evidence.preparation_context().participant_count() != scope.participant_count
    {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
    }
    Ok(())
}

fn encode_public_inconsistency_carrier(
    canonical_open_request_bytes: &[u8],
    sender_position: u16,
    recipient_position: u16,
    disclosed_authenticated_encryption_key: [u8; 32],
) -> Result<Vec<u8>, DirectMpcPreprocessingSourceStateKernelError> {
    let bytes = encode_domain_tuple(
        PUBLIC_INCONSISTENCY_CARRIER_DOMAIN,
        vec![
            CanonicalItem::variable_bytes(canonical_open_request_bytes)
                .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?,
            CanonicalItem::unsigned16(sender_position),
            CanonicalItem::unsigned16(recipient_position),
            CanonicalItem::fixed_bytes(disclosed_authenticated_encryption_key)
                .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?,
        ],
    )
    .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?;
    if bytes.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
        return Err(DirectMpcPreprocessingSourceStateKernelError::ResourceLimit(
            "public inconsistency carrier",
        ));
    }
    Ok(bytes)
}

fn decode_public_inconsistency_carrier(
    carrier_bytes: &[u8],
) -> Result<
    (
        VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
        Vec<u8>,
    ),
    DirectMpcPreprocessingSourceStateKernelError,
> {
    let tuple = CanonicalTuple::decode(carrier_bytes, &public_carrier_decode_limits())
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?;
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || tuple.items.len() != PUBLIC_INCONSISTENCY_CARRIER_ITEM_COUNT
        || tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0]
            .variable_value_bytes()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?
            != PUBLIC_INCONSISTENCY_CARRIER_DOMAIN.as_bytes()
        || tuple.items[1].item_type() != CanonicalItemType::RawBytes
        || tuple.items[2].item_type() != CanonicalItemType::Unsigned16
        || tuple.items[3].item_type() != CanonicalItemType::Unsigned16
        || tuple.items[4].item_type() != CanonicalItemType::RawBytes
    {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor);
    }
    let canonical_open_request_bytes = tuple.items[1]
        .variable_value_bytes()
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?;
    let sender_position = u16::from_le_bytes(
        tuple.items[2]
            .canonical_bytes()
            .try_into()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?,
    );
    let recipient_position = u16::from_le_bytes(
        tuple.items[3]
            .canonical_bytes()
            .try_into()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?,
    );
    let disclosed_authenticated_encryption_key: [u8; 32] = tuple.items[4]
        .canonical_bytes()
        .try_into()
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?;
    let evidence =
        verify_pseudorandom_zero_sharing_seed_recipient_authenticated_inconsistency_disclosure_320(
            canonical_open_request_bytes,
            sender_position,
            recipient_position,
            disclosed_authenticated_encryption_key,
        )
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?;
    let canonical = encode_public_inconsistency_carrier(
        canonical_open_request_bytes,
        sender_position,
        recipient_position,
        disclosed_authenticated_encryption_key,
    )?;
    if canonical != carrier_bytes {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor);
    }
    Ok((evidence, canonical))
}

fn public_carrier_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
        maximum_item_count: PUBLIC_INCONSISTENCY_CARRIER_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length: MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
    }
}

fn verify_open_outcome(
    cursor: &mut BoundedCursor<'_>,
) -> Result<Option<VerifiedStateContext>, DirectMpcPreprocessingSourceStateKernelError> {
    let (action_context, roster) = parse_foundation(cursor)?;
    let authentication_record_bytes =
        cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "authentication record")?;
    let joined_custody_record_bytes = cursor
        .read_optional_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "joined-custody record")?;
    let supplied_public_inconsistency_carrier_bytes = cursor.read_optional_bounded_bytes(
        MAXIMUM_COPIED_BUFFER_BYTE_LENGTH,
        "public inconsistency carrier",
    )?;
    cursor.require_complete("open-outcome trailing bytes")?;

    let authentication_record = parse_authentication_record(authentication_record_bytes)?;
    let scope = authentication_record.scope();
    let local_participant_position = scope.recipient_position;
    let mut local_success = None;
    let mut local_burn = None;
    let mut locally_encoded_public_inconsistency_carrier = None;
    match authentication_record {
        AuthenticationRecord::Selected {
            canonical_open_request_bytes,
            ..
        } => {
            let selection = verify_pseudorandom_zero_sharing_seed_recipient_selection_320(
                canonical_open_request_bytes,
            )
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?;
            require_authentication_scope_matches_selection(
                scope,
                selection,
                &action_context,
                &roster,
            )?;
            if joined_custody_record_bytes.is_some() {
                return Err(DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor);
            }
        }
        AuthenticationRecord::Burned {
            canonical_open_request_bytes,
            sender_position,
            recipient_position,
            disclosed_authenticated_encryption_key,
            evidence_identity,
            ..
        } => {
            if joined_custody_record_bytes.is_some() {
                return Err(DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor);
            }
            let evidence =
                verify_pseudorandom_zero_sharing_seed_recipient_authenticated_inconsistency_320(
                    canonical_open_request_bytes,
                    sender_position,
                    recipient_position,
                    disclosed_authenticated_encryption_key,
                    evidence_identity,
                )
                .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?;
            require_authentication_scope_matches_evidence(scope, evidence)?;
            locally_encoded_public_inconsistency_carrier =
                Some(encode_public_inconsistency_carrier(
                    canonical_open_request_bytes,
                    sender_position,
                    recipient_position,
                    disclosed_authenticated_encryption_key,
                )?);
            local_burn = Some(evidence);
        }
        AuthenticationRecord::Joined {
            receipt_terminal_identity,
            ..
        } => {
            let joined_custody_record_bytes = joined_custody_record_bytes
                .ok_or(DirectMpcPreprocessingSourceStateKernelError::MissingPrerequisite)?;
            let (source, participant_position) =
                verify_direct_mpc_one_and_preprocessing_source_from_joined_custody(
                    &action_context,
                    &roster,
                    joined_custody_record_bytes,
                )
                .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongPredecessor)?;
            require_authentication_scope_matches_source(
                scope,
                receipt_terminal_identity,
                &source,
                participant_position,
            )?;
            local_success = Some(source);
        }
    }

    let (outcome, public_inconsistency_carrier_bytes) =
        if let Some(supplied_carrier_bytes) = supplied_public_inconsistency_carrier_bytes {
            let (evidence, canonical_carrier_bytes) =
                decode_public_inconsistency_carrier(supplied_carrier_bytes)?;
            require_authentication_scope_matches_evidence(scope, evidence)?;
            (
                OwnedSourceOutcome::Burn(evidence),
                Some(canonical_carrier_bytes),
            )
        } else if let Some(evidence) = local_burn {
            (
                OwnedSourceOutcome::Burn(evidence),
                locally_encoded_public_inconsistency_carrier,
            )
        } else if let Some(source) = local_success {
            (OwnedSourceOutcome::Success(source), None)
        } else {
            return Ok(None);
        };
    let prepared = prepare_direct_mpc_preprocessing_source_terminal(
        &action_context,
        &roster,
        outcome.candidate(),
    )
    .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::WrongContext)?;
    Ok(Some(VerifiedStateContext {
        action_context,
        roster,
        outcome,
        prepared,
        local_participant_position,
        public_inconsistency_carrier_bytes,
    }))
}

fn retain_verified_context(
    context: VerifiedStateContext,
) -> Result<u32, DirectMpcPreprocessingSourceStateKernelError> {
    VERIFIED_STATE_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        if registry.retained.is_some() {
            return Err(DirectMpcPreprocessingSourceStateKernelError::ContextUnavailable);
        }
        let handle = registry.next_handle;
        registry.next_handle = registry
            .next_handle
            .checked_add(1)
            .filter(|value| *value != 0)
            .unwrap_or(1);
        registry.retained = Some((handle, context));
        Ok(handle)
    })
}

fn with_verified_context<ResultValue>(
    handle: u32,
    operation: impl FnOnce(
        &VerifiedStateContext,
    ) -> Result<ResultValue, DirectMpcPreprocessingSourceStateKernelError>,
) -> Result<ResultValue, DirectMpcPreprocessingSourceStateKernelError> {
    VERIFIED_STATE_CONTEXTS.with(|registry| {
        let registry = registry.borrow();
        let Some((retained_handle, context)) = registry.retained.as_ref() else {
            return Err(DirectMpcPreprocessingSourceStateKernelError::ContextUnavailable);
        };
        if *retained_handle != handle {
            return Err(DirectMpcPreprocessingSourceStateKernelError::ContextUnavailable);
        }
        operation(context)
    })
}

fn close_verified_context(handle: u32) -> Result<(), DirectMpcPreprocessingSourceStateKernelError> {
    VERIFIED_STATE_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        if registry.retained.as_ref().map(|(retained, _)| *retained) != Some(handle) {
            return Err(DirectMpcPreprocessingSourceStateKernelError::ContextUnavailable);
        }
        registry.retained = None;
        Ok(())
    })
}

fn parse_handle(
    cursor: &mut BoundedCursor<'_>,
) -> Result<u32, DirectMpcPreprocessingSourceStateKernelError> {
    u32::try_from(cursor.read_unsigned32("state context handle")?).map_err(|_| {
        DirectMpcPreprocessingSourceStateKernelError::MalformedRequest("state context handle")
    })
}

fn response_header(status: u8) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(64));
    bytes.extend_from_slice(RESPONSE_MAGIC);
    bytes.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    bytes.push(status);
    bytes
}

fn append_unsigned16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_unsigned32(
    bytes: &mut Vec<u8>,
    value: usize,
) -> Result<(), DirectMpcPreprocessingSourceStateKernelError> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| {
                DirectMpcPreprocessingSourceStateKernelError::ResourceLimit("encoded byte length")
            })?
            .to_le_bytes(),
    );
    Ok(())
}

fn append_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), DirectMpcPreprocessingSourceStateKernelError> {
    append_unsigned32(output, value.len())?;
    output.extend_from_slice(value);
    if output.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
        return Err(DirectMpcPreprocessingSourceStateKernelError::ResourceLimit(
            "response byte length",
        ));
    }
    Ok(())
}

fn encode_failure_response(
    error: &DirectMpcPreprocessingSourceStateKernelError,
) -> Zeroizing<Vec<u8>> {
    let mut bytes = response_header(FAILURE_STATUS);
    append_unsigned16(&mut bytes, error.response_code());
    bytes
}

fn encode_pending_response() -> Zeroizing<Vec<u8>> {
    response_header(PENDING_OUTCOME_STATUS)
}

fn encode_open_response(
    handle: u32,
    context: &VerifiedStateContext,
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let mut bytes = response_header(OPEN_OUTCOME_STATUS);
    bytes.extend_from_slice(&handle.to_le_bytes());
    bytes.push(context.outcome.status());
    append_unsigned16(&mut bytes, context.local_participant_position);
    bytes.extend_from_slice(context.prepared.state_namespace_identity().as_bytes());
    append_bytes(
        &mut bytes,
        &context
            .prepared
            .source_outcome_body_bytes()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
    )?;
    append_bytes(
        &mut bytes,
        context
            .public_inconsistency_carrier_bytes
            .as_deref()
            .unwrap_or_default(),
    )?;
    Ok(bytes)
}

fn encode_prepared_authorization_response(
    status: u8,
    state_key_identity: Hash512,
    intent_bytes: &[u8],
    authorization_body_bytes: &[u8],
    verification_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let mut bytes = response_header(status);
    bytes.extend_from_slice(state_key_identity.as_bytes());
    append_bytes(&mut bytes, intent_bytes)?;
    append_bytes(&mut bytes, authorization_body_bytes)?;
    append_bytes(&mut bytes, verification_key)?;
    Ok(bytes)
}

fn prepare_witness_response(
    context: &VerifiedStateContext,
    subject_position: u16,
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let intent = context
        .prepared
        .state_output_intent(subject_position)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let witness_body =
        StateWitnessAuthorizationBody::new(intent, context.local_participant_position)
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let roster_entry = context
        .roster
        .entries
        .get(usize::from(context.local_participant_position))
        .ok_or(DirectMpcPreprocessingSourceStateKernelError::WrongContext)?;
    encode_prepared_authorization_response(
        PREPARED_WITNESS_STATUS,
        intent.state_key_identity(),
        &intent
            .canonical_bytes()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
        &witness_body
            .canonical_bytes()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
        &roster_entry.signing_verification_key,
    )
}

fn complete_witness_response(
    context: &VerifiedStateContext,
    subject_position: u16,
    expected_authorization_body_bytes: &[u8],
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let intent = context
        .prepared
        .state_output_intent(subject_position)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let expected_body =
        StateWitnessAuthorizationBody::new(intent, context.local_participant_position)
            .and_then(StateWitnessAuthorizationBody::canonical_bytes)
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    if expected_authorization_body_bytes != expected_body {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
    }
    let envelope = encode_domain_tuple(
        STATE_WITNESS_ENVELOPE_DOMAIN,
        vec![
            CanonicalItem::variable_bytes(expected_authorization_body_bytes)
                .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
            CanonicalItem::fixed_bytes(signature)
                .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
        ],
    )
    .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    verify_witness_envelopes(intent, &context.roster, &[envelope.as_slice()])
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let mut bytes = response_header(COMPLETED_WITNESS_STATUS);
    bytes.extend_from_slice(intent.state_key_identity().as_bytes());
    append_bytes(&mut bytes, &envelope)?;
    Ok(bytes)
}

fn parse_witness_envelopes<'a>(
    cursor: &mut BoundedCursor<'a>,
) -> Result<Vec<&'a [u8]>, DirectMpcPreprocessingSourceStateKernelError> {
    let count = usize::from(cursor.read_unsigned16("witness-envelope count")?);
    if count != usize::from(FOUNDATION_PROFILE.state_witness_quorum)
        || count > MAXIMUM_STATE_CARRIER_COUNT
    {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
    }
    (0..count)
        .map(|_| cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "witness envelope"))
        .collect()
}

fn subject_components(
    context: &VerifiedStateContext,
    witness_envelopes: &[&[u8]],
) -> Result<
    (
        super::StateOutputIntent,
        Vec<u8>,
        StateSubjectAuthorizationBody,
    ),
    DirectMpcPreprocessingSourceStateKernelError,
> {
    let intent = context
        .prepared
        .state_output_intent(context.local_participant_position)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    verify_witness_envelopes(intent, &context.roster, witness_envelopes)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let witness_certificate_identity =
        state_witness_certificate_identity(intent, witness_envelopes)
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let subject_body = StateSubjectAuthorizationBody::new(intent, witness_certificate_identity)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let intent_bytes = intent
        .canonical_bytes()
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    Ok((intent, intent_bytes, subject_body))
}

fn prepare_subject_response(
    context: &VerifiedStateContext,
    witness_envelopes: &[&[u8]],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let (intent, intent_bytes, subject_body) = subject_components(context, witness_envelopes)?;
    let roster_entry = context
        .roster
        .entries
        .get(usize::from(context.local_participant_position))
        .ok_or(DirectMpcPreprocessingSourceStateKernelError::WrongContext)?;
    encode_prepared_authorization_response(
        PREPARED_SUBJECT_STATUS,
        intent.state_key_identity(),
        &intent_bytes,
        &subject_body
            .canonical_bytes()
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
        &roster_entry.signing_verification_key,
    )
}

fn complete_subject_response(
    context: &VerifiedStateContext,
    witness_envelopes: &[&[u8]],
    expected_authorization_body_bytes: &[u8],
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let (intent, intent_bytes, subject_body) = subject_components(context, witness_envelopes)?;
    let expected_body_bytes = subject_body
        .canonical_bytes()
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    if expected_authorization_body_bytes != expected_body_bytes {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
    }
    let mut certificate_items = Vec::with_capacity(witness_envelopes.len() + 3);
    certificate_items.push(
        CanonicalItem::variable_bytes(intent_bytes)
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
    );
    for witness_envelope in witness_envelopes {
        certificate_items.push(
            CanonicalItem::variable_bytes(*witness_envelope)
                .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
        );
    }
    certificate_items.push(
        CanonicalItem::variable_bytes(expected_authorization_body_bytes)
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
    );
    certificate_items.push(
        CanonicalItem::fixed_bytes(signature)
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?,
    );
    let certificate_bytes = encode_domain_tuple(STATE_OUTPUT_CERTIFICATE_DOMAIN, certificate_items)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    verify_state_output_certificate(intent, &context.roster, &certificate_bytes)
        .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let carrier_bytes = direct_mpc_preprocessing_source_endorsement_carrier_bytes(
        context.local_participant_position,
        &certificate_bytes,
    )
    .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    let mut bytes = response_header(COMPLETED_SUBJECT_STATUS);
    bytes.extend_from_slice(intent.state_key_identity().as_bytes());
    append_bytes(&mut bytes, &carrier_bytes)?;
    Ok(bytes)
}

fn parse_endorsement_carriers<'a>(
    cursor: &mut BoundedCursor<'a>,
) -> Result<Vec<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let count = usize::from(cursor.read_unsigned16("endorsement-carrier count")?);
    if count != usize::from(FOUNDATION_PROFILE.finality_quorum)
        || count > MAXIMUM_STATE_CARRIER_COUNT
    {
        return Err(DirectMpcPreprocessingSourceStateKernelError::WrongContext);
    }
    (0..count)
        .map(|_| {
            cursor
                .read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "endorsement carrier")
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn terminal_response(
    context: &VerifiedStateContext,
    terminal_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let verification = verify_direct_mpc_preprocessing_source_terminal(
        &context.action_context,
        &context.roster,
        Some(context.outcome.candidate()),
        Some(terminal_bytes),
    )
    .map_err(|error| match error {
        DirectMpcPreprocessingSourceTerminalError::ConsumedState => {
            DirectMpcPreprocessingSourceStateKernelError::ConsumedState
        }
        _ => DirectMpcPreprocessingSourceStateKernelError::StateVerification,
    })?;
    let terminal_identity = match verification {
        DirectMpcPreprocessingSourceTerminalVerification::Success(source) => source.identity(),
        DirectMpcPreprocessingSourceTerminalVerification::Burn(burn) => burn.identity(),
        DirectMpcPreprocessingSourceTerminalVerification::Pending => {
            return Err(DirectMpcPreprocessingSourceStateKernelError::MissingPrerequisite);
        }
    };
    let mut bytes = response_header(TERMINAL_STATUS);
    bytes.push(context.outcome.status());
    bytes.extend_from_slice(context.prepared.state_namespace_identity().as_bytes());
    bytes.extend_from_slice(terminal_identity.as_bytes());
    append_bytes(&mut bytes, terminal_bytes)?;
    Ok(bytes)
}

fn create_terminal_response(
    context: &VerifiedStateContext,
    endorsement_carriers: &[Vec<u8>],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let terminal_bytes =
        direct_mpc_preprocessing_source_terminal_bytes(context.prepared, endorsement_carriers)
            .map_err(|_| DirectMpcPreprocessingSourceStateKernelError::StateVerification)?;
    terminal_response(context, &terminal_bytes)
}

fn parse_request(
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcPreprocessingSourceStateKernelError> {
    let mut cursor = BoundedCursor::new(input)?;
    cursor.require_magic(REQUEST_MAGIC, "request magic")?;
    if cursor.read_unsigned16("request version")? != CODEC_VERSION {
        return Err(
            DirectMpcPreprocessingSourceStateKernelError::MalformedRequest("request version"),
        );
    }
    match cursor.read_unsigned8("operation")? {
        OPEN_OUTCOME_OPERATION => match verify_open_outcome(&mut cursor)? {
            Some(context) => {
                let handle = retain_verified_context(context)?;
                with_verified_context(handle, |context| encode_open_response(handle, context))
            }
            None => Ok(encode_pending_response()),
        },
        PREPARE_WITNESS_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            let subject_position = cursor.read_unsigned16("witness subject position")?;
            cursor.require_complete("prepare-witness trailing bytes")?;
            with_verified_context(handle, |context| {
                prepare_witness_response(context, subject_position)
            })
        }
        COMPLETE_WITNESS_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            let subject_position = cursor.read_unsigned16("witness subject position")?;
            let authorization_body_bytes = cursor.read_bounded_bytes(
                MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                "witness authorization body",
            )?;
            let signature = cursor
                .read_exact(ML_DSA_65_SIGNATURE_BYTE_LENGTH, "witness signature")?
                .try_into()
                .map_err(|_| {
                    DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(
                        "witness signature",
                    )
                })?;
            cursor.require_complete("complete-witness trailing bytes")?;
            with_verified_context(handle, |context| {
                complete_witness_response(
                    context,
                    subject_position,
                    authorization_body_bytes,
                    signature,
                )
            })
        }
        PREPARE_SUBJECT_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            let witness_envelopes = parse_witness_envelopes(&mut cursor)?;
            cursor.require_complete("prepare-subject trailing bytes")?;
            with_verified_context(handle, |context| {
                prepare_subject_response(context, &witness_envelopes)
            })
        }
        COMPLETE_SUBJECT_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            let witness_envelopes = parse_witness_envelopes(&mut cursor)?;
            let authorization_body_bytes = cursor.read_bounded_bytes(
                MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                "subject authorization body",
            )?;
            let signature = cursor
                .read_exact(ML_DSA_65_SIGNATURE_BYTE_LENGTH, "subject signature")?
                .try_into()
                .map_err(|_| {
                    DirectMpcPreprocessingSourceStateKernelError::MalformedRequest(
                        "subject signature",
                    )
                })?;
            cursor.require_complete("complete-subject trailing bytes")?;
            with_verified_context(handle, |context| {
                complete_subject_response(
                    context,
                    &witness_envelopes,
                    authorization_body_bytes,
                    signature,
                )
            })
        }
        CREATE_TERMINAL_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            let endorsement_carriers = parse_endorsement_carriers(&mut cursor)?;
            cursor.require_complete("create-terminal trailing bytes")?;
            with_verified_context(handle, |context| {
                create_terminal_response(context, &endorsement_carriers)
            })
        }
        VALIDATE_TERMINAL_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            let terminal_bytes =
                cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "source terminal")?;
            cursor.require_complete("validate-terminal trailing bytes")?;
            with_verified_context(handle, |context| terminal_response(context, terminal_bytes))
        }
        CLOSE_OUTCOME_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            cursor.require_complete("close-outcome trailing bytes")?;
            close_verified_context(handle)?;
            Ok(response_header(CLOSED_OUTCOME_STATUS))
        }
        _ => Err(DirectMpcPreprocessingSourceStateKernelError::MalformedRequest("operation")),
    }
}

pub(crate) fn run_direct_mpc_preprocessing_source_state_kernel(input: &[u8]) -> Zeroizing<Vec<u8>> {
    match parse_request(input) {
        Ok(response) => response,
        Err(error) => encode_failure_response(&error),
    }
}

#[cfg(test)]
pub(crate) fn clear_direct_mpc_preprocessing_source_state_context_for_test() {
    VERIFIED_STATE_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.retained = None;
        registry.next_handle = 1;
    });
}

const _: () = assert!(ML_DSA_65_SIGNATURE_BYTE_LENGTH == 3_309);
const _: () = assert!(STATE_WITNESS_SIGNATURE_CONTEXT.len() <= u8::MAX as usize);
const _: () = assert!(STATE_SUBJECT_SIGNATURE_CONTEXT.len() <= u8::MAX as usize);

#[cfg(test)]
mod tests;
