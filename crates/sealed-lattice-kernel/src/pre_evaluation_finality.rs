//! Unactivated positive verifier for the minimum pre-evaluation-finality
//! chronology.
//!
//! This module fixes one protected input, one public `true` input, one AND
//! gate, and one clear output. It verifies chronology and nonforking state; it
//! is not a ballot-custody construction, a BMR realization, a suite, or a
//! production capability.

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

use crate::foundation::{
    ActionContext, CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    Hash512, RefusalReason, Roster, derive_foundation_roster_parameters, hash_foundation_tuple_512,
};

const ONE_AND_CIRCUIT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/one-and-circuit-identity";
const PREPARATION_TERMINAL_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/preparation-terminal-identity";
const INPUT_SOURCE_ROOT_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/input-source-root";
const COMPUTATION_TARGET_BODY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/computation-target-body";
const COMPUTATION_TARGET_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/computation-target-identity";
const NO_RESULT_TERMINAL_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/no-result-terminal";
const TARGET_FINALITY_ENDORSEMENT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/target-finality-endorsement-body";
const TARGET_FINALITY_ENDORSEMENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/target-finality-endorsement-identity";
const TARGET_FINALITY_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/target-finality-carrier";
const TARGET_FINALITY_TERMINAL_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/target-finality-terminal";
const TARGET_FINALITY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/target-finality-identity";
const INPUT_ACTIVATION_BODY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/input-activation-body";
const INPUT_ACTIVATION_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/input-activation-carrier";
const INPUT_ACTIVATION_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/input-activation-identity";
const GARBLING_RELEASE_BODY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/garbling-release-body";
const GARBLING_RELEASE_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/garbling-release-carrier";
const GARBLING_RELEASE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/garbling-release-identity";
const GARBLING_RELEASE_PREDECESSOR_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/garbling-release-predecessor-identity";
const STATE_KEY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/state-key-identity";
const STATE_OUTPUT_INTENT_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/state-output-intent";
const STATE_OUTPUT_INTENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/state-output-intent-identity";
const STATE_WITNESS_AUTHORIZATION_BODY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/state-witness-authorization-body";
const STATE_WITNESS_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/state-witness-envelope";
const STATE_WITNESS_CERTIFICATE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/state-witness-certificate-identity";
const STATE_SUBJECT_AUTHORIZATION_BODY_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/state-subject-authorization-body";
const STATE_OUTPUT_CERTIFICATE_DOMAIN: &str =
    "sealed-lattice/v1/pre-evaluation-finality/state-output-certificate";
const STATE_WITNESS_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/pre-evaluation-finality/state-witness";
const STATE_SUBJECT_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/pre-evaluation-finality/state-subject";

const TARGET_FINALITY_OPERATION_KIND: &str = "target-finality-endorsement";
const INPUT_ACTIVATION_OPERATION_KIND: &str = "ballot-input-release";
const GARBLING_RELEASE_OPERATION_KIND: &str = "active-garbling-release";

const OPENING_NONCE_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
const STATE_WITNESS_ENVELOPE_ITEM_COUNT: usize = 3;
const STATE_OUTPUT_CERTIFICATE_FIXED_ITEM_COUNT: usize = 4;
const TARGET_FINALITY_CARRIER_ITEM_COUNT: usize = 3;
const INPUT_ACTIVATION_CARRIER_ITEM_COUNT: usize = 3;
const GARBLING_RELEASE_CARRIER_ITEM_COUNT: usize = 3;
const MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH: usize = 2 * 1024 * 1024;
const MAXIMUM_CONTROL_OBJECT_ITEM_COUNT: usize = 128;
const MAXIMUM_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionState {
    AllAbstained,
    Nonempty {
        input_source_root: Hash512,
        activation_holder_position: u16,
        garbling_contributor_position: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PreEvaluationFinalityScope {
    suite_identity: Hash512,
    action_context_identity: Hash512,
    roster_identity: Hash512,
    participant_count: u16,
    circuit_identity: Hash512,
    preparation_terminal_identity: Hash512,
    selected_set_root: Hash512,
    selection_state: SelectionState,
}

impl PreEvaluationFinalityScope {
    fn all_abstained(
        action_context: &ActionContext,
        roster: &Roster,
        preparation_terminal_identity: Hash512,
        selected_set_root: Hash512,
    ) -> Result<Self, FragmentError> {
        Self::new(
            action_context,
            roster,
            preparation_terminal_identity,
            selected_set_root,
            SelectionState::AllAbstained,
        )
    }

    fn nonempty(
        action_context: &ActionContext,
        roster: &Roster,
        preparation_terminal_identity: Hash512,
        selected_set_root: Hash512,
        input_source_root: Hash512,
        activation_holder_position: u16,
        garbling_contributor_position: u16,
    ) -> Result<Self, FragmentError> {
        Self::new(
            action_context,
            roster,
            preparation_terminal_identity,
            selected_set_root,
            SelectionState::Nonempty {
                input_source_root,
                activation_holder_position,
                garbling_contributor_position,
            },
        )
    }

    fn new(
        action_context: &ActionContext,
        roster: &Roster,
        preparation_terminal_identity: Hash512,
        selected_set_root: Hash512,
        selection_state: SelectionState,
    ) -> Result<Self, FragmentError> {
        Self::new_from_identities(
            action_context.suite_id(),
            action_context.context_hash(),
            action_context.roster_hash(),
            roster,
            preparation_terminal_identity,
            selected_set_root,
            selection_state,
        )
    }

    fn new_from_identities(
        suite_identity: Hash512,
        action_context_identity: Hash512,
        expected_roster_identity: Hash512,
        roster: &Roster,
        preparation_terminal_identity: Hash512,
        selected_set_root: Hash512,
        selection_state: SelectionState,
    ) -> Result<Self, FragmentError> {
        roster.validate().map_err(|_| FragmentError::WrongRoster)?;
        let roster_identity = roster
            .roster_hash()
            .map_err(|_| FragmentError::WrongRoster)?;
        if roster_identity != expected_roster_identity {
            return Err(FragmentError::WrongRoster);
        }
        let participant_count =
            u16::try_from(roster.entries.len()).map_err(|_| FragmentError::UnsupportedProfile)?;
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(FragmentError::UnsupportedProfile)?;
        if roster_parameters.active_fault_bound != FOUNDATION_PROFILE.active_fault_bound
            || roster_parameters.reconstruction_threshold
                != FOUNDATION_PROFILE.reconstruction_threshold
            || roster_parameters.finality_quorum != FOUNDATION_PROFILE.finality_quorum
            || roster_parameters.state_witness_quorum != FOUNDATION_PROFILE.state_witness_quorum
        {
            return Err(FragmentError::UnsupportedProfile);
        }
        if let SelectionState::Nonempty {
            activation_holder_position,
            garbling_contributor_position,
            ..
        } = selection_state
        {
            validate_roster_position(activation_holder_position, participant_count)?;
            validate_roster_position(garbling_contributor_position, participant_count)?;
        }
        Ok(Self {
            suite_identity,
            action_context_identity,
            roster_identity,
            participant_count,
            circuit_identity: one_and_circuit_identity()?,
            preparation_terminal_identity,
            selected_set_root,
            selection_state,
        })
    }

    fn nonempty_selection(self) -> Result<(Hash512, u16, u16), FragmentError> {
        match self.selection_state {
            SelectionState::AllAbstained => Err(FragmentError::MissingPrerequisite),
            SelectionState::Nonempty {
                input_source_root,
                activation_holder_position,
                garbling_contributor_position,
            } => Ok((
                input_source_root,
                activation_holder_position,
                garbling_contributor_position,
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequiredEvent {
    NoResultTerminal,
    ComputationTarget,
    TargetFinality,
    InputActivation,
    GarblingRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatedAbortReason {
    InputSourceOpeningMismatch,
    GarblingOpeningMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifiedFragmentTerminal {
    NoResult {
        selected_set_root: Hash512,
    },
    ClearResult {
        target_identity: Hash512,
        result: bool,
    },
    Abort {
        target_identity: Hash512,
        reason: AuthenticatedAbortReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentVerification {
    Pending { next_required: RequiredEvent },
    Complete { terminal: VerifiedFragmentTerminal },
    Refused { refusal_reason: RefusalReason },
}

impl FragmentVerification {
    const fn pending(next_required: RequiredEvent) -> Self {
        Self::Pending { next_required }
    }

    const fn complete(terminal: VerifiedFragmentTerminal) -> Self {
        Self::Complete { terminal }
    }

    const fn refused(error: FragmentError) -> Self {
        Self::Refused {
            refusal_reason: error.refusal_reason(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FragmentError {
    Canonical(CanonicalCodecError),
    UnsupportedProfile,
    WrongRoster,
    WrongContext,
    WrongObject,
    WrongHashOrRoot,
    WrongEventOrder,
    WrongCount,
    WrongOrder,
    DuplicateIdentity,
    InvalidSignature,
    MissingPrerequisite,
    ConsumedState,
}

impl From<CanonicalCodecError> for FragmentError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl FragmentError {
    const fn refusal_reason(&self) -> RefusalReason {
        match self {
            Self::Canonical(_) => RefusalReason::MalformedEncoding,
            Self::UnsupportedProfile => RefusalReason::OutsideSupportedProfile,
            Self::WrongRoster | Self::WrongContext => RefusalReason::WrongContext,
            Self::WrongObject | Self::WrongCount | Self::WrongOrder => {
                RefusalReason::WrongTypeOrLength
            }
            Self::WrongHashOrRoot => RefusalReason::WrongHashOrRoot,
            Self::WrongEventOrder | Self::MissingPrerequisite => RefusalReason::MissingPrerequisite,
            Self::DuplicateIdentity => RefusalReason::DuplicateIdentity,
            Self::InvalidSignature => RefusalReason::InvalidSignature,
            Self::ConsumedState => RefusalReason::ConsumedState,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ComputationTargetBody {
    suite_identity: Hash512,
    action_context_identity: Hash512,
    roster_identity: Hash512,
    circuit_identity: Hash512,
    preparation_terminal_identity: Hash512,
    selected_set_root: Hash512,
    input_source_root: Hash512,
}

impl ComputationTargetBody {
    fn new(scope: PreEvaluationFinalityScope) -> Result<Self, FragmentError> {
        let (input_source_root, _, _) = scope.nonempty_selection()?;
        Ok(Self {
            suite_identity: scope.suite_identity,
            action_context_identity: scope.action_context_identity,
            roster_identity: scope.roster_identity,
            circuit_identity: scope.circuit_identity,
            preparation_terminal_identity: scope.preparation_terminal_identity,
            selected_set_root: scope.selected_set_root,
            input_source_root,
        })
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, FragmentError> {
        encode_domain_tuple(
            COMPUTATION_TARGET_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.suite_identity.into_bytes()),
                CanonicalItem::hash512(self.action_context_identity.into_bytes()),
                CanonicalItem::hash512(self.roster_identity.into_bytes()),
                CanonicalItem::hash512(self.circuit_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_terminal_identity.into_bytes()),
                CanonicalItem::hash512(self.selected_set_root.into_bytes()),
                CanonicalItem::hash512(self.input_source_root.into_bytes()),
            ],
        )
    }

    fn identity(self) -> Result<Hash512, FragmentError> {
        hash_encoded_object(COMPUTATION_TARGET_IDENTITY_DOMAIN, &self.canonical_bytes()?)
    }

    fn verify_bytes(
        scope: PreEvaluationFinalityScope,
        bytes: &[u8],
    ) -> Result<Self, FragmentError> {
        let expected = Self::new(scope)?;
        require_exact_bytes(bytes, &expected.canonical_bytes()?)?;
        Ok(expected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TargetFinalityEndorsementBody {
    target_identity: Hash512,
    subject_position: u16,
}

impl TargetFinalityEndorsementBody {
    const fn new(target_identity: Hash512, subject_position: u16) -> Self {
        Self {
            target_identity,
            subject_position,
        }
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, FragmentError> {
        encode_domain_tuple(
            TARGET_FINALITY_ENDORSEMENT_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.target_identity.into_bytes()),
                CanonicalItem::unsigned16(self.subject_position),
            ],
        )
    }

    fn identity(self) -> Result<Hash512, FragmentError> {
        hash_encoded_object(
            TARGET_FINALITY_ENDORSEMENT_IDENTITY_DOMAIN,
            &self.canonical_bytes()?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StateOutputIntent {
    participant_count: u16,
    operation_kind: &'static str,
    subject_position: u16,
    state_key_identity: Hash512,
    predecessor_identity: Hash512,
    semantic_body_identity: Hash512,
}

impl StateOutputIntent {
    fn new(
        scope: PreEvaluationFinalityScope,
        operation_kind: &'static str,
        subject_position: u16,
        predecessor_identity: Hash512,
        semantic_body_identity: Hash512,
    ) -> Result<Self, FragmentError> {
        Self::new_with_namespace(
            scope.suite_identity,
            scope.action_context_identity,
            scope.preparation_terminal_identity,
            scope.participant_count,
            operation_kind,
            subject_position,
            predecessor_identity,
            semantic_body_identity,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_namespace(
        suite_identity: Hash512,
        action_context_identity: Hash512,
        state_namespace_identity: Hash512,
        participant_count: u16,
        operation_kind: &'static str,
        subject_position: u16,
        predecessor_identity: Hash512,
        semantic_body_identity: Hash512,
    ) -> Result<Self, FragmentError> {
        validate_roster_position(subject_position, participant_count)?;
        let state_key_identity = hash_foundation_tuple_512(
            STATE_KEY_IDENTITY_DOMAIN,
            &[
                CanonicalItem::hash512(suite_identity.into_bytes()),
                CanonicalItem::hash512(action_context_identity.into_bytes()),
                CanonicalItem::hash512(state_namespace_identity.into_bytes()),
                CanonicalItem::nonempty_ascii(operation_kind)?,
                CanonicalItem::unsigned16(subject_position),
            ],
        )?;
        Ok(Self {
            participant_count,
            operation_kind,
            subject_position,
            state_key_identity,
            predecessor_identity,
            semantic_body_identity,
        })
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, FragmentError> {
        encode_domain_tuple(
            STATE_OUTPUT_INTENT_DOMAIN,
            vec![
                CanonicalItem::nonempty_ascii(self.operation_kind)?,
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.subject_position),
                CanonicalItem::hash512(self.state_key_identity.into_bytes()),
                CanonicalItem::hash512(self.predecessor_identity.into_bytes()),
                CanonicalItem::hash512(self.semantic_body_identity.into_bytes()),
            ],
        )
    }

    fn identity(self) -> Result<Hash512, FragmentError> {
        hash_encoded_object(
            STATE_OUTPUT_INTENT_IDENTITY_DOMAIN,
            &self.canonical_bytes()?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StateWitnessAuthorizationBody {
    intent_identity: Hash512,
    witness_position: u16,
}

impl StateWitnessAuthorizationBody {
    fn new(intent: StateOutputIntent, witness_position: u16) -> Result<Self, FragmentError> {
        validate_witness_position(intent, witness_position)?;
        Ok(Self {
            intent_identity: intent.identity()?,
            witness_position,
        })
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, FragmentError> {
        encode_domain_tuple(
            STATE_WITNESS_AUTHORIZATION_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.intent_identity.into_bytes()),
                CanonicalItem::unsigned16(self.witness_position),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StateSubjectAuthorizationBody {
    intent_identity: Hash512,
    witness_certificate_identity: Hash512,
    subject_position: u16,
}

impl StateSubjectAuthorizationBody {
    fn new(
        intent: StateOutputIntent,
        witness_certificate_identity: Hash512,
    ) -> Result<Self, FragmentError> {
        Ok(Self {
            intent_identity: intent.identity()?,
            witness_certificate_identity,
            subject_position: intent.subject_position,
        })
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, FragmentError> {
        encode_domain_tuple(
            STATE_SUBJECT_AUTHORIZATION_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.intent_identity.into_bytes()),
                CanonicalItem::hash512(self.witness_certificate_identity.into_bytes()),
                CanonicalItem::unsigned16(self.subject_position),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedStateOutput {
    semantic_body_identity: Hash512,
}

fn verify_state_output_certificate(
    expected_intent: StateOutputIntent,
    roster: &Roster,
    certificate_bytes: &[u8],
) -> Result<VerifiedStateOutput, FragmentError> {
    let tuple = decode_domain_tuple(certificate_bytes, STATE_OUTPUT_CERTIFICATE_DOMAIN)?;
    let roster_parameters = derive_foundation_roster_parameters(expected_intent.participant_count)
        .ok_or(FragmentError::UnsupportedProfile)?;
    let expected_witness_count = usize::from(roster_parameters.state_witness_quorum);
    let expected_item_count = STATE_OUTPUT_CERTIFICATE_FIXED_ITEM_COUNT
        .checked_add(expected_witness_count)
        .ok_or(FragmentError::WrongCount)?;
    if tuple.items.len() != expected_item_count {
        return Err(FragmentError::WrongCount);
    }
    let intent_bytes = read_variable_bytes(&tuple.items[1])?;
    require_exact_bytes(intent_bytes, &expected_intent.canonical_bytes()?)?;
    let witness_items_end = 2 + expected_witness_count;
    let witness_envelope_bytes = tuple.items[2..witness_items_end]
        .iter()
        .map(read_variable_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    verify_witness_envelopes(expected_intent, roster, &witness_envelope_bytes)?;
    let witness_certificate_identity =
        state_witness_certificate_identity(expected_intent, &witness_envelope_bytes)?;
    let expected_subject_body =
        StateSubjectAuthorizationBody::new(expected_intent, witness_certificate_identity)?;
    let subject_body_bytes = read_variable_bytes(&tuple.items[witness_items_end])?;
    require_exact_bytes(
        subject_body_bytes,
        &expected_subject_body.canonical_bytes()?,
    )?;
    let subject_signature = read_signature(&tuple.items[witness_items_end + 1])?;
    verify_signature(
        roster,
        expected_intent.subject_position,
        subject_body_bytes,
        &subject_signature,
        STATE_SUBJECT_SIGNATURE_CONTEXT,
    )?;
    Ok(VerifiedStateOutput {
        semantic_body_identity: expected_intent.semantic_body_identity,
    })
}

fn verify_witness_envelopes(
    intent: StateOutputIntent,
    roster: &Roster,
    witness_envelope_bytes: &[&[u8]],
) -> Result<(), FragmentError> {
    let mut preceding_witness_position = None;
    for envelope_bytes in witness_envelope_bytes {
        let tuple = decode_domain_tuple(envelope_bytes, STATE_WITNESS_ENVELOPE_DOMAIN)?;
        if tuple.items.len() != STATE_WITNESS_ENVELOPE_ITEM_COUNT {
            return Err(FragmentError::WrongCount);
        }
        let authorization_body_bytes = read_variable_bytes(&tuple.items[1])?;
        let authorization_tuple = decode_domain_tuple(
            authorization_body_bytes,
            STATE_WITNESS_AUTHORIZATION_BODY_DOMAIN,
        )?;
        if authorization_tuple.items.len() != 3 {
            return Err(FragmentError::WrongCount);
        }
        let witness_position = read_u16(&authorization_tuple.items[2])?;
        let expected_authorization_body =
            StateWitnessAuthorizationBody::new(intent, witness_position)?;
        require_exact_bytes(
            authorization_body_bytes,
            &expected_authorization_body.canonical_bytes()?,
        )?;
        if preceding_witness_position.is_some_and(|preceding| preceding >= witness_position) {
            return Err(if preceding_witness_position == Some(witness_position) {
                FragmentError::DuplicateIdentity
            } else {
                FragmentError::WrongOrder
            });
        }
        preceding_witness_position = Some(witness_position);
        let signature = read_signature(&tuple.items[2])?;
        verify_signature(
            roster,
            witness_position,
            authorization_body_bytes,
            &signature,
            STATE_WITNESS_SIGNATURE_CONTEXT,
        )?;
    }
    Ok(())
}

fn state_witness_certificate_identity(
    intent: StateOutputIntent,
    witness_envelope_bytes: &[&[u8]],
) -> Result<Hash512, FragmentError> {
    let mut items = Vec::with_capacity(witness_envelope_bytes.len() + 1);
    items.push(CanonicalItem::variable_bytes(intent.canonical_bytes()?)?);
    for envelope_bytes in witness_envelope_bytes {
        items.push(CanonicalItem::variable_bytes(*envelope_bytes)?);
    }
    let certificate_bytes = encode_domain_tuple(STATE_OUTPUT_CERTIFICATE_DOMAIN, items)?;
    hash_encoded_object(
        STATE_WITNESS_CERTIFICATE_IDENTITY_DOMAIN,
        &certificate_bytes,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedTargetFinality {
    target_identity: Hash512,
    finality_identity: Hash512,
}

fn verify_target_finality_terminal(
    scope: PreEvaluationFinalityScope,
    target: ComputationTargetBody,
    roster: &Roster,
    terminal_bytes: &[u8],
) -> Result<VerifiedTargetFinality, FragmentError> {
    let tuple = decode_domain_tuple(terminal_bytes, TARGET_FINALITY_TERMINAL_DOMAIN)?;
    let roster_parameters = derive_foundation_roster_parameters(scope.participant_count)
        .ok_or(FragmentError::UnsupportedProfile)?;
    let expected_endorsement_count = usize::from(roster_parameters.finality_quorum);
    if tuple.items.len() != expected_endorsement_count + 2 {
        return Err(FragmentError::WrongCount);
    }
    let target_identity = target.identity()?;
    require_hash(&tuple.items[1], target_identity)?;
    let mut preceding_subject_position = None;
    for carrier_item in &tuple.items[2..] {
        let carrier_bytes = read_variable_bytes(carrier_item)?;
        let carrier_tuple = decode_domain_tuple(carrier_bytes, TARGET_FINALITY_CARRIER_DOMAIN)?;
        if carrier_tuple.items.len() != TARGET_FINALITY_CARRIER_ITEM_COUNT {
            return Err(FragmentError::WrongCount);
        }
        let subject_position = read_u16(&carrier_tuple.items[1])?;
        validate_roster_position(subject_position, scope.participant_count)?;
        if preceding_subject_position.is_some_and(|preceding| preceding >= subject_position) {
            return Err(if preceding_subject_position == Some(subject_position) {
                FragmentError::DuplicateIdentity
            } else {
                FragmentError::WrongOrder
            });
        }
        preceding_subject_position = Some(subject_position);
        let endorsement_body =
            TargetFinalityEndorsementBody::new(target_identity, subject_position);
        let intent = StateOutputIntent::new(
            scope,
            TARGET_FINALITY_OPERATION_KIND,
            subject_position,
            target_identity,
            endorsement_body.identity()?,
        )?;
        let verified_state_output = verify_state_output_certificate(
            intent,
            roster,
            read_variable_bytes(&carrier_tuple.items[2])?,
        )?;
        if verified_state_output.semantic_body_identity != endorsement_body.identity()? {
            return Err(FragmentError::WrongHashOrRoot);
        }
    }
    let finality_identity = hash_foundation_tuple_512(
        TARGET_FINALITY_IDENTITY_DOMAIN,
        &[CanonicalItem::hash512(target_identity.into_bytes())],
    )?;
    Ok(VerifiedTargetFinality {
        target_identity,
        finality_identity,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InputActivationBody {
    action_context_identity: Hash512,
    preparation_terminal_identity: Hash512,
    selected_set_root: Hash512,
    input_source_root: Hash512,
    holder_position: u16,
    protected_input: bool,
    source_opening_nonce: [u8; OPENING_NONCE_BYTE_LENGTH],
}

impl InputActivationBody {
    fn canonical_bytes(self) -> Result<Vec<u8>, FragmentError> {
        encode_domain_tuple(
            INPUT_ACTIVATION_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.action_context_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_terminal_identity.into_bytes()),
                CanonicalItem::hash512(self.selected_set_root.into_bytes()),
                CanonicalItem::hash512(self.input_source_root.into_bytes()),
                CanonicalItem::unsigned16(self.holder_position),
                CanonicalItem::boolean(self.protected_input),
                CanonicalItem::fixed_bytes(self.source_opening_nonce)?,
            ],
        )
    }

    fn identity(self) -> Result<Hash512, FragmentError> {
        hash_encoded_object(INPUT_ACTIVATION_IDENTITY_DOMAIN, &self.canonical_bytes()?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, FragmentError> {
        let tuple = decode_domain_tuple(bytes, INPUT_ACTIVATION_BODY_DOMAIN)?;
        if tuple.items.len() != 8 {
            return Err(FragmentError::WrongCount);
        }
        Ok(Self {
            action_context_identity: read_hash(&tuple.items[1])?,
            preparation_terminal_identity: read_hash(&tuple.items[2])?,
            selected_set_root: read_hash(&tuple.items[3])?,
            input_source_root: read_hash(&tuple.items[4])?,
            holder_position: read_u16(&tuple.items[5])?,
            protected_input: read_bool(&tuple.items[6])?,
            source_opening_nonce: read_fixed_bytes(&tuple.items[7])?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedInputActivation {
    identity: Hash512,
    protected_input: bool,
}

enum InputActivationVerification {
    Verified(VerifiedInputActivation),
    AuthenticatedAbort,
}

fn verify_input_activation(
    scope: PreEvaluationFinalityScope,
    finality: VerifiedTargetFinality,
    roster: &Roster,
    carrier_bytes: &[u8],
) -> Result<InputActivationVerification, FragmentError> {
    let (input_source_root, expected_holder_position, _) = scope.nonempty_selection()?;
    let tuple = decode_domain_tuple(carrier_bytes, INPUT_ACTIVATION_CARRIER_DOMAIN)?;
    if tuple.items.len() != INPUT_ACTIVATION_CARRIER_ITEM_COUNT {
        return Err(FragmentError::WrongCount);
    }
    let body = InputActivationBody::decode(read_variable_bytes(&tuple.items[1])?)?;
    if body.action_context_identity != scope.action_context_identity
        || body.preparation_terminal_identity != scope.preparation_terminal_identity
        || body.selected_set_root != scope.selected_set_root
        || body.holder_position != expected_holder_position
    {
        return Err(FragmentError::WrongContext);
    }
    if body.input_source_root != input_source_root {
        return Err(FragmentError::WrongHashOrRoot);
    }
    let intent = StateOutputIntent::new(
        scope,
        INPUT_ACTIVATION_OPERATION_KIND,
        expected_holder_position,
        finality.finality_identity,
        body.identity()?,
    )?;
    verify_state_output_certificate(intent, roster, read_variable_bytes(&tuple.items[2])?)?;
    let reconstructed_root = derive_input_source_root(
        scope.action_context_identity,
        scope.preparation_terminal_identity,
        scope.selected_set_root,
        expected_holder_position,
        body.protected_input,
        body.source_opening_nonce,
    )?;
    if reconstructed_root != input_source_root {
        return Ok(InputActivationVerification::AuthenticatedAbort);
    }
    Ok(InputActivationVerification::Verified(
        VerifiedInputActivation {
            identity: body.identity()?,
            protected_input: body.protected_input,
        },
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GarblingReleaseBody {
    action_context_identity: Hash512,
    circuit_identity: Hash512,
    preparation_terminal_identity: Hash512,
    input_activation_identity: Hash512,
    contributor_position: u16,
    public_input: bool,
    preparation_opening_nonce: [u8; OPENING_NONCE_BYTE_LENGTH],
}

impl GarblingReleaseBody {
    fn canonical_bytes(self) -> Result<Vec<u8>, FragmentError> {
        encode_domain_tuple(
            GARBLING_RELEASE_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.action_context_identity.into_bytes()),
                CanonicalItem::hash512(self.circuit_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_terminal_identity.into_bytes()),
                CanonicalItem::hash512(self.input_activation_identity.into_bytes()),
                CanonicalItem::unsigned16(self.contributor_position),
                CanonicalItem::boolean(self.public_input),
                CanonicalItem::fixed_bytes(self.preparation_opening_nonce)?,
            ],
        )
    }

    fn identity(self) -> Result<Hash512, FragmentError> {
        hash_encoded_object(GARBLING_RELEASE_IDENTITY_DOMAIN, &self.canonical_bytes()?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, FragmentError> {
        let tuple = decode_domain_tuple(bytes, GARBLING_RELEASE_BODY_DOMAIN)?;
        if tuple.items.len() != 8 {
            return Err(FragmentError::WrongCount);
        }
        Ok(Self {
            action_context_identity: read_hash(&tuple.items[1])?,
            circuit_identity: read_hash(&tuple.items[2])?,
            preparation_terminal_identity: read_hash(&tuple.items[3])?,
            input_activation_identity: read_hash(&tuple.items[4])?,
            contributor_position: read_u16(&tuple.items[5])?,
            public_input: read_bool(&tuple.items[6])?,
            preparation_opening_nonce: read_fixed_bytes(&tuple.items[7])?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedGarblingRelease {
    public_input: bool,
}

enum GarblingReleaseVerification {
    Verified(VerifiedGarblingRelease),
    AuthenticatedAbort,
}

fn verify_garbling_release(
    scope: PreEvaluationFinalityScope,
    finality: VerifiedTargetFinality,
    activation: VerifiedInputActivation,
    roster: &Roster,
    carrier_bytes: &[u8],
) -> Result<GarblingReleaseVerification, FragmentError> {
    let (_, _, expected_contributor_position) = scope.nonempty_selection()?;
    let tuple = decode_domain_tuple(carrier_bytes, GARBLING_RELEASE_CARRIER_DOMAIN)?;
    if tuple.items.len() != GARBLING_RELEASE_CARRIER_ITEM_COUNT {
        return Err(FragmentError::WrongCount);
    }
    let body = GarblingReleaseBody::decode(read_variable_bytes(&tuple.items[1])?)?;
    if body.action_context_identity != scope.action_context_identity
        || body.circuit_identity != scope.circuit_identity
        || body.preparation_terminal_identity != scope.preparation_terminal_identity
        || body.input_activation_identity != activation.identity
        || body.contributor_position != expected_contributor_position
    {
        return Err(FragmentError::WrongContext);
    }
    let predecessor_identity = hash_foundation_tuple_512(
        GARBLING_RELEASE_PREDECESSOR_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(finality.finality_identity.into_bytes()),
            CanonicalItem::hash512(activation.identity.into_bytes()),
        ],
    )?;
    let intent = StateOutputIntent::new(
        scope,
        GARBLING_RELEASE_OPERATION_KIND,
        expected_contributor_position,
        predecessor_identity,
        body.identity()?,
    )?;
    verify_state_output_certificate(intent, roster, read_variable_bytes(&tuple.items[2])?)?;
    let reconstructed_terminal_identity = derive_preparation_terminal_identity(
        scope.action_context_identity,
        scope.circuit_identity,
        expected_contributor_position,
        body.public_input,
        body.preparation_opening_nonce,
    )?;
    if !body.public_input || reconstructed_terminal_identity != scope.preparation_terminal_identity
    {
        return Ok(GarblingReleaseVerification::AuthenticatedAbort);
    }
    Ok(GarblingReleaseVerification::Verified(
        VerifiedGarblingRelease {
            public_input: body.public_input,
        },
    ))
}

fn verify_pre_evaluation_finality_fragment(
    scope: PreEvaluationFinalityScope,
    roster: &Roster,
    event_bytes: &[Vec<u8>],
) -> FragmentVerification {
    match verify_pre_evaluation_finality_fragment_inner(scope, roster, event_bytes) {
        Ok(verification) => verification,
        Err(error) => FragmentVerification::refused(error),
    }
}

fn verify_pre_evaluation_finality_fragment_inner(
    scope: PreEvaluationFinalityScope,
    roster: &Roster,
    event_bytes: &[Vec<u8>],
) -> Result<FragmentVerification, FragmentError> {
    match scope.selection_state {
        SelectionState::AllAbstained => verify_no_result(scope, event_bytes),
        SelectionState::Nonempty { .. } => verify_nonempty(scope, roster, event_bytes),
    }
}

fn verify_no_result(
    scope: PreEvaluationFinalityScope,
    event_bytes: &[Vec<u8>],
) -> Result<FragmentVerification, FragmentError> {
    if event_bytes.is_empty() {
        return Ok(FragmentVerification::pending(
            RequiredEvent::NoResultTerminal,
        ));
    }
    if event_bytes.len() > 1 {
        return Err(FragmentError::ConsumedState);
    }
    let expected = encode_domain_tuple(
        NO_RESULT_TERMINAL_DOMAIN,
        vec![
            CanonicalItem::hash512(scope.action_context_identity.into_bytes()),
            CanonicalItem::hash512(scope.preparation_terminal_identity.into_bytes()),
            CanonicalItem::hash512(scope.selected_set_root.into_bytes()),
        ],
    )?;
    require_expected_event(&event_bytes[0], NO_RESULT_TERMINAL_DOMAIN, &expected, true)?;
    Ok(FragmentVerification::complete(
        VerifiedFragmentTerminal::NoResult {
            selected_set_root: scope.selected_set_root,
        },
    ))
}

fn verify_nonempty(
    scope: PreEvaluationFinalityScope,
    roster: &Roster,
    event_bytes: &[Vec<u8>],
) -> Result<FragmentVerification, FragmentError> {
    let Some(target_bytes) = event_bytes.first() else {
        return Ok(FragmentVerification::pending(
            RequiredEvent::ComputationTarget,
        ));
    };
    require_event_domain(target_bytes, COMPUTATION_TARGET_BODY_DOMAIN, false)?;
    let target = ComputationTargetBody::verify_bytes(scope, target_bytes)?;
    let Some(finality_bytes) = event_bytes.get(1) else {
        return Ok(FragmentVerification::pending(RequiredEvent::TargetFinality));
    };
    require_event_domain(finality_bytes, TARGET_FINALITY_TERMINAL_DOMAIN, false)?;
    let finality = verify_target_finality_terminal(scope, target, roster, finality_bytes)?;
    let Some(activation_bytes) = event_bytes.get(2) else {
        return Ok(FragmentVerification::pending(
            RequiredEvent::InputActivation,
        ));
    };
    require_event_domain(activation_bytes, INPUT_ACTIVATION_CARRIER_DOMAIN, false)?;
    let activation = match verify_input_activation(scope, finality, roster, activation_bytes)? {
        InputActivationVerification::Verified(activation) => activation,
        InputActivationVerification::AuthenticatedAbort => {
            return Ok(FragmentVerification::complete(
                VerifiedFragmentTerminal::Abort {
                    target_identity: finality.target_identity,
                    reason: AuthenticatedAbortReason::InputSourceOpeningMismatch,
                },
            ));
        }
    };
    let Some(garbling_bytes) = event_bytes.get(3) else {
        return Ok(FragmentVerification::pending(
            RequiredEvent::GarblingRelease,
        ));
    };
    require_event_domain(garbling_bytes, GARBLING_RELEASE_CARRIER_DOMAIN, false)?;
    let garbling =
        match verify_garbling_release(scope, finality, activation, roster, garbling_bytes)? {
            GarblingReleaseVerification::Verified(garbling) => garbling,
            GarblingReleaseVerification::AuthenticatedAbort => {
                return Ok(FragmentVerification::complete(
                    VerifiedFragmentTerminal::Abort {
                        target_identity: finality.target_identity,
                        reason: AuthenticatedAbortReason::GarblingOpeningMismatch,
                    },
                ));
            }
        };
    if event_bytes.len() > 4 {
        return Err(FragmentError::ConsumedState);
    }
    let result = activation.protected_input & garbling.public_input;
    Ok(FragmentVerification::complete(
        VerifiedFragmentTerminal::ClearResult {
            target_identity: finality.target_identity,
            result,
        },
    ))
}

fn derive_input_source_root(
    action_context_identity: Hash512,
    preparation_terminal_identity: Hash512,
    selected_set_root: Hash512,
    holder_position: u16,
    protected_input: bool,
    source_opening_nonce: [u8; OPENING_NONCE_BYTE_LENGTH],
) -> Result<Hash512, FragmentError> {
    Ok(hash_foundation_tuple_512(
        INPUT_SOURCE_ROOT_DOMAIN,
        &[
            CanonicalItem::hash512(action_context_identity.into_bytes()),
            CanonicalItem::hash512(preparation_terminal_identity.into_bytes()),
            CanonicalItem::hash512(selected_set_root.into_bytes()),
            CanonicalItem::unsigned16(holder_position),
            CanonicalItem::boolean(protected_input),
            CanonicalItem::fixed_bytes(source_opening_nonce)?,
        ],
    )?)
}

fn derive_preparation_terminal_identity(
    action_context_identity: Hash512,
    circuit_identity: Hash512,
    contributor_position: u16,
    public_input: bool,
    preparation_opening_nonce: [u8; OPENING_NONCE_BYTE_LENGTH],
) -> Result<Hash512, FragmentError> {
    Ok(hash_foundation_tuple_512(
        PREPARATION_TERMINAL_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(action_context_identity.into_bytes()),
            CanonicalItem::hash512(circuit_identity.into_bytes()),
            CanonicalItem::unsigned16(contributor_position),
            CanonicalItem::boolean(public_input),
            CanonicalItem::fixed_bytes(preparation_opening_nonce)?,
        ],
    )?)
}

fn one_and_circuit_identity() -> Result<Hash512, FragmentError> {
    Ok(hash_foundation_tuple_512(
        ONE_AND_CIRCUIT_IDENTITY_DOMAIN,
        &[
            CanonicalItem::nonempty_ascii("protected-input")?,
            CanonicalItem::nonempty_ascii("public-true-input")?,
            CanonicalItem::nonempty_ascii("conjunction")?,
            CanonicalItem::nonempty_ascii("clear-output")?,
        ],
    )?)
}

fn verify_signature(
    roster: &Roster,
    signer_position: u16,
    message: &[u8],
    signature: &[u8; ml_dsa_65::SIG_LEN],
    context: &[u8],
) -> Result<(), FragmentError> {
    let roster_entry = roster
        .entries
        .get(usize::from(signer_position))
        .ok_or(FragmentError::WrongRoster)?;
    if roster_entry.roster_position != signer_position {
        return Err(FragmentError::WrongRoster);
    }
    let verification_key =
        ml_dsa_65::PublicKey::try_from_bytes(roster_entry.signing_verification_key)
            .map_err(|_| FragmentError::WrongRoster)?;
    if !verification_key.verify(message, signature, context) {
        return Err(FragmentError::InvalidSignature);
    }
    Ok(())
}

fn validate_witness_position(
    intent: StateOutputIntent,
    witness_position: u16,
) -> Result<(), FragmentError> {
    validate_roster_position(witness_position, intent.participant_count)?;
    if witness_position == intent.subject_position {
        return Err(FragmentError::DuplicateIdentity);
    }
    Ok(())
}

fn validate_roster_position(
    roster_position: u16,
    participant_count: u16,
) -> Result<(), FragmentError> {
    if roster_position >= participant_count {
        return Err(FragmentError::WrongRoster);
    }
    Ok(())
}

fn encode_domain_tuple(
    domain: &str,
    mut items: Vec<CanonicalItem>,
) -> Result<Vec<u8>, FragmentError> {
    let mut framed_items = Vec::with_capacity(items.len() + 1);
    framed_items.push(CanonicalItem::nonempty_ascii(domain)?);
    framed_items.append(&mut items);
    Ok(CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        framed_items,
    )
    .encode()?)
}

fn decode_domain_tuple(
    bytes: &[u8],
    expected_domain: &str,
) -> Result<CanonicalTuple, FragmentError> {
    let tuple = CanonicalTuple::decode(bytes, &control_object_decode_limits())?;
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || tuple.items.is_empty()
    {
        return Err(FragmentError::WrongObject);
    }
    require_ascii(&tuple.items[0], expected_domain)?;
    Ok(tuple)
}

fn event_domain(bytes: &[u8]) -> Result<String, FragmentError> {
    let tuple = CanonicalTuple::decode(bytes, &control_object_decode_limits())?;
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || tuple.items.is_empty()
    {
        return Err(FragmentError::WrongObject);
    }
    let domain_item = &tuple.items[0];
    if domain_item.item_type() != CanonicalItemType::Ascii {
        return Err(FragmentError::WrongObject);
    }
    String::from_utf8(domain_item.variable_value_bytes()?.to_vec())
        .map_err(|_| FragmentError::WrongObject)
}

fn require_event_domain(
    bytes: &[u8],
    expected_domain: &str,
    no_result_path: bool,
) -> Result<(), FragmentError> {
    let actual_domain = event_domain(bytes)?;
    if actual_domain == expected_domain {
        return Ok(());
    }
    let is_release = matches!(
        actual_domain.as_str(),
        INPUT_ACTIVATION_CARRIER_DOMAIN | GARBLING_RELEASE_CARRIER_DOMAIN
    );
    if is_release || (no_result_path && actual_domain == COMPUTATION_TARGET_BODY_DOMAIN) {
        return Err(FragmentError::WrongEventOrder);
    }
    Err(FragmentError::WrongObject)
}

fn require_expected_event(
    bytes: &[u8],
    expected_domain: &str,
    expected_bytes: &[u8],
    no_result_path: bool,
) -> Result<(), FragmentError> {
    require_event_domain(bytes, expected_domain, no_result_path)?;
    require_exact_bytes(bytes, expected_bytes)
}

fn require_exact_bytes(actual: &[u8], expected: &[u8]) -> Result<(), FragmentError> {
    if actual != expected {
        return Err(FragmentError::WrongHashOrRoot);
    }
    Ok(())
}

fn hash_encoded_object(domain: &str, bytes: &[u8]) -> Result<Hash512, FragmentError> {
    Ok(hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(bytes)?],
    )?)
}

fn require_ascii(item: &CanonicalItem, expected: &str) -> Result<(), FragmentError> {
    if item.item_type() != CanonicalItemType::Ascii
        || item.variable_value_bytes()? != expected.as_bytes()
    {
        return Err(FragmentError::WrongObject);
    }
    Ok(())
}

fn require_hash(item: &CanonicalItem, expected: Hash512) -> Result<(), FragmentError> {
    if read_hash(item)? != expected {
        return Err(FragmentError::WrongHashOrRoot);
    }
    Ok(())
}

fn read_hash(item: &CanonicalItem) -> Result<Hash512, FragmentError> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(FragmentError::WrongObject);
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| FragmentError::WrongObject)?;
    Ok(Hash512::from_bytes(bytes))
}

fn read_u16(item: &CanonicalItem) -> Result<u16, FragmentError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(FragmentError::WrongObject);
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| FragmentError::WrongObject)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_bool(item: &CanonicalItem) -> Result<bool, FragmentError> {
    if item.item_type() != CanonicalItemType::Boolean {
        return Err(FragmentError::WrongObject);
    }
    match item.canonical_bytes() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(FragmentError::WrongObject),
    }
}

fn read_variable_bytes(item: &CanonicalItem) -> Result<&[u8], FragmentError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(FragmentError::WrongObject);
    }
    Ok(item.variable_value_bytes()?)
}

fn read_fixed_bytes<const BYTE_LENGTH: usize>(
    item: &CanonicalItem,
) -> Result<[u8; BYTE_LENGTH], FragmentError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(FragmentError::WrongObject);
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| FragmentError::WrongObject)
}

fn read_signature(item: &CanonicalItem) -> Result<[u8; ml_dsa_65::SIG_LEN], FragmentError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(FragmentError::WrongObject);
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| FragmentError::WrongObject)
}

const fn control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length: MAXIMUM_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

mod direct_mpc_one_and;

#[cfg(feature = "direct-mpc-one-and-verifier")]
pub(crate) use direct_mpc_one_and::run_direct_mpc_one_and_verification_bundle;

#[cfg(test)]
mod tests;
