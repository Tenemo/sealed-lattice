use core::fmt;

use crate::{
    foundation::{
        ActionContext, CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION,
        CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
        CanonicalTuple, FOUNDATION_PROFILE, Hash512, Roster, derive_foundation_roster_parameters,
        hash_foundation_tuple_512,
    },
    tally_preparation::{
        DirectMpcOneAndPreprocessingSourceError, TallyPreparationContext,
        VerifiedDirectMpcOneAndPreprocessingSource,
        VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
        direct_mpc_one_and_preprocessing_source_parameter_identity,
    },
};

use super::{FragmentError, StateOutputIntent, verify_state_output_certificate};

const SOURCE_STATE_NAMESPACE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-state-namespace-identity";
const SOURCE_SUCCESS_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-success-body";
const SOURCE_BURN_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-burn-body";
const SOURCE_BODY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-outcome-identity";
const SOURCE_ENDORSEMENT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-endorsement-body";
const SOURCE_ENDORSEMENT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-endorsement-identity";
const SOURCE_ENDORSEMENT_CARRIER_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-endorsement-carrier";
const SOURCE_TERMINAL_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-terminal";
const SOURCE_TERMINAL_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-state-terminal-identity";
const SOURCE_TERMINAL_OPERATION_KIND: &str = "direct-mpc-preprocessing-source-terminal";

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const SOURCE_ENDORSEMENT_CARRIER_ITEM_COUNT: usize = 3;
const SOURCE_TERMINAL_FIXED_ITEM_COUNT: usize = 2;
const MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH: usize = 2 * 1024 * 1024;
const MAXIMUM_CONTROL_OBJECT_ITEM_COUNT: usize = 128;
const MAXIMUM_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcPreprocessingSourceTerminalError {
    Canonical(CanonicalCodecError),
    Source(DirectMpcOneAndPreprocessingSourceError),
    State(FragmentError),
    WrongContext,
    WrongObject,
    WrongCount,
    WrongOrder,
    DuplicateIdentity,
    ConsumedState,
    ArithmeticOverflow,
}

impl From<CanonicalCodecError> for DirectMpcPreprocessingSourceTerminalError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<DirectMpcOneAndPreprocessingSourceError> for DirectMpcPreprocessingSourceTerminalError {
    fn from(error: DirectMpcOneAndPreprocessingSourceError) -> Self {
        Self::Source(error)
    }
}

impl From<FragmentError> for DirectMpcPreprocessingSourceTerminalError {
    fn from(error: FragmentError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for DirectMpcPreprocessingSourceTerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DirectMpcPreprocessingSourceTerminalError {}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DirectMpcPreprocessingSourceOutcomeCandidate<'a> {
    Success(&'a VerifiedDirectMpcOneAndPreprocessingSource),
    Burn(&'a VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcPreprocessingSourceStateContext {
    suite_identity: Hash512,
    action_context_identity: Hash512,
    roster_identity: Hash512,
    participant_count: u16,
    preparation_context_identity: Hash512,
    parameter_identity: Hash512,
    root_terminal_identity: Hash512,
    state_namespace_identity: Hash512,
}

impl DirectMpcPreprocessingSourceStateContext {
    fn new(
        action_context: &ActionContext,
        roster: &Roster,
        preparation_context: TallyPreparationContext,
        parameter_identity: Hash512,
        root_terminal_identity: Hash512,
    ) -> Result<Self, DirectMpcPreprocessingSourceTerminalError> {
        roster
            .validate()
            .map_err(|_| DirectMpcPreprocessingSourceTerminalError::WrongContext)?;
        let roster_identity = roster
            .roster_hash()
            .map_err(|_| DirectMpcPreprocessingSourceTerminalError::WrongContext)?;
        let participant_count = u16::try_from(roster.entries.len())
            .map_err(|_| DirectMpcPreprocessingSourceTerminalError::ArithmeticOverflow)?;
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(DirectMpcPreprocessingSourceTerminalError::WrongContext)?;
        if participant_count != FOUNDATION_PROFILE.participant_count
            || roster_parameters.active_fault_bound != FOUNDATION_PROFILE.active_fault_bound
            || roster_parameters.state_witness_quorum != FOUNDATION_PROFILE.state_witness_quorum
            || roster_parameters.finality_quorum != FOUNDATION_PROFILE.finality_quorum
            || action_context.roster_hash() != roster_identity
            || preparation_context.action_context_hash() != action_context.context_hash()
            || preparation_context.roster_hash() != roster_identity
            || preparation_context.participant_count() != participant_count
            || parameter_identity != direct_mpc_one_and_preprocessing_source_parameter_identity()?
        {
            return Err(DirectMpcPreprocessingSourceTerminalError::WrongContext);
        }
        let suite_identity = action_context.suite_id();
        let action_context_identity = action_context.context_hash();
        let preparation_context_identity = preparation_context.identity();
        let state_namespace_identity = hash_foundation_tuple_512(
            SOURCE_STATE_NAMESPACE_IDENTITY_DOMAIN,
            &[
                CanonicalItem::hash512(suite_identity.into_bytes()),
                CanonicalItem::hash512(action_context_identity.into_bytes()),
                CanonicalItem::hash512(roster_identity.into_bytes()),
                CanonicalItem::hash512(preparation_context_identity.into_bytes()),
                CanonicalItem::hash512(parameter_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
            ],
        )?;
        Ok(Self {
            suite_identity,
            action_context_identity,
            roster_identity,
            participant_count,
            preparation_context_identity,
            parameter_identity,
            root_terminal_identity,
            state_namespace_identity,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectMpcPreprocessingSourceTerminalBody {
    Success {
        preparation_context_identity: Hash512,
        parameter_identity: Hash512,
        root_terminal_identity: Hash512,
        receipt_terminal_identity: Hash512,
        receipt_terminal_certificate_identity: Hash512,
        source_identity: Hash512,
    },
    Burn {
        preparation_context_identity: Hash512,
        parameter_identity: Hash512,
        root_terminal_identity: Hash512,
        sender_position: u16,
        recipient_position: u16,
        header_identity: Hash512,
        manifest_identity: Hash512,
        evidence_identity: Hash512,
    },
}

impl DirectMpcPreprocessingSourceTerminalBody {
    fn from_candidate(candidate: DirectMpcPreprocessingSourceOutcomeCandidate<'_>) -> Self {
        match candidate {
            DirectMpcPreprocessingSourceOutcomeCandidate::Success(source) => Self::Success {
                preparation_context_identity: source.preparation_context().identity(),
                parameter_identity: source.parameter_identity(),
                root_terminal_identity: source.root_terminal_identity(),
                receipt_terminal_identity: source.receipt_terminal_identity(),
                receipt_terminal_certificate_identity: source
                    .receipt_terminal_certificate_identity(),
                source_identity: source.identity(),
            },
            DirectMpcPreprocessingSourceOutcomeCandidate::Burn(evidence) => Self::Burn {
                preparation_context_identity: evidence.preparation_context().identity(),
                parameter_identity: evidence.parameter_identity(),
                root_terminal_identity: evidence.root_terminal_identity(),
                sender_position: evidence.sender_position(),
                recipient_position: evidence.recipient_position(),
                header_identity: evidence.header_identity(),
                manifest_identity: evidence.manifest_identity(),
                evidence_identity: evidence.identity(),
            },
        }
    }

    fn canonical_bytes(self) -> Result<Vec<u8>, DirectMpcPreprocessingSourceTerminalError> {
        let (domain, items) = match self {
            Self::Success {
                preparation_context_identity,
                parameter_identity,
                root_terminal_identity,
                receipt_terminal_identity,
                receipt_terminal_certificate_identity,
                source_identity,
            } => (
                SOURCE_SUCCESS_BODY_DOMAIN,
                vec![
                    CanonicalItem::hash512(preparation_context_identity.into_bytes()),
                    CanonicalItem::hash512(parameter_identity.into_bytes()),
                    CanonicalItem::hash512(root_terminal_identity.into_bytes()),
                    CanonicalItem::hash512(receipt_terminal_identity.into_bytes()),
                    CanonicalItem::hash512(receipt_terminal_certificate_identity.into_bytes()),
                    CanonicalItem::hash512(source_identity.into_bytes()),
                ],
            ),
            Self::Burn {
                preparation_context_identity,
                parameter_identity,
                root_terminal_identity,
                sender_position,
                recipient_position,
                header_identity,
                manifest_identity,
                evidence_identity,
            } => (
                SOURCE_BURN_BODY_DOMAIN,
                vec![
                    CanonicalItem::hash512(preparation_context_identity.into_bytes()),
                    CanonicalItem::hash512(parameter_identity.into_bytes()),
                    CanonicalItem::hash512(root_terminal_identity.into_bytes()),
                    CanonicalItem::unsigned16(sender_position),
                    CanonicalItem::unsigned16(recipient_position),
                    CanonicalItem::hash512(header_identity.into_bytes()),
                    CanonicalItem::hash512(manifest_identity.into_bytes()),
                    CanonicalItem::hash512(evidence_identity.into_bytes()),
                ],
            ),
        };
        encode_domain_tuple(domain, items)
    }

    fn identity(self) -> Result<Hash512, DirectMpcPreprocessingSourceTerminalError> {
        hash_encoded_object(SOURCE_BODY_IDENTITY_DOMAIN, &self.canonical_bytes()?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedDirectMpcPreprocessingSourceTerminal {
    context: DirectMpcPreprocessingSourceStateContext,
    body: DirectMpcPreprocessingSourceTerminalBody,
}

impl PreparedDirectMpcPreprocessingSourceTerminal {
    pub(crate) fn source_outcome_body_bytes(
        self,
    ) -> Result<Vec<u8>, DirectMpcPreprocessingSourceTerminalError> {
        self.body.canonical_bytes()
    }

    pub(crate) fn endorsement_body(
        self,
        subject_position: u16,
    ) -> Result<
        DirectMpcPreprocessingSourceEndorsementBody,
        DirectMpcPreprocessingSourceTerminalError,
    > {
        DirectMpcPreprocessingSourceEndorsementBody::new(self, subject_position)
    }

    pub(crate) fn state_output_intent(
        self,
        subject_position: u16,
    ) -> Result<StateOutputIntent, DirectMpcPreprocessingSourceTerminalError> {
        let endorsement = self.endorsement_body(subject_position)?;
        Ok(StateOutputIntent::new_with_namespace(
            self.context.suite_identity,
            self.context.action_context_identity,
            self.context.state_namespace_identity,
            self.context.participant_count,
            SOURCE_TERMINAL_OPERATION_KIND,
            subject_position,
            self.context.root_terminal_identity,
            endorsement.identity()?,
        )?)
    }

    pub(crate) const fn state_namespace_identity(self) -> Hash512 {
        self.context.state_namespace_identity
    }
}

pub(crate) fn prepare_direct_mpc_preprocessing_source_terminal(
    action_context: &ActionContext,
    roster: &Roster,
    candidate: DirectMpcPreprocessingSourceOutcomeCandidate<'_>,
) -> Result<PreparedDirectMpcPreprocessingSourceTerminal, DirectMpcPreprocessingSourceTerminalError>
{
    let (preparation_context, parameter_identity, root_terminal_identity) = match candidate {
        DirectMpcPreprocessingSourceOutcomeCandidate::Success(source) => {
            source.verify_action_and_roster(action_context, roster)?;
            (
                source.preparation_context(),
                source.parameter_identity(),
                source.root_terminal_identity(),
            )
        }
        DirectMpcPreprocessingSourceOutcomeCandidate::Burn(evidence) => (
            evidence.preparation_context(),
            evidence.parameter_identity(),
            evidence.root_terminal_identity(),
        ),
    };
    let context = DirectMpcPreprocessingSourceStateContext::new(
        action_context,
        roster,
        preparation_context,
        parameter_identity,
        root_terminal_identity,
    )?;
    if let DirectMpcPreprocessingSourceOutcomeCandidate::Burn(evidence) = candidate
        && (evidence.sender_position() >= context.participant_count
            || evidence.recipient_position() >= context.participant_count
            || evidence.sender_position() == evidence.recipient_position())
    {
        return Err(DirectMpcPreprocessingSourceTerminalError::WrongContext);
    }
    Ok(PreparedDirectMpcPreprocessingSourceTerminal {
        context,
        body: DirectMpcPreprocessingSourceTerminalBody::from_candidate(candidate),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcPreprocessingSourceEndorsementBody {
    state_namespace_identity: Hash512,
    root_terminal_identity: Hash512,
    source_outcome_identity: Hash512,
    subject_position: u16,
}

impl DirectMpcPreprocessingSourceEndorsementBody {
    fn new(
        prepared: PreparedDirectMpcPreprocessingSourceTerminal,
        subject_position: u16,
    ) -> Result<Self, DirectMpcPreprocessingSourceTerminalError> {
        if subject_position >= prepared.context.participant_count {
            return Err(DirectMpcPreprocessingSourceTerminalError::WrongContext);
        }
        Ok(Self {
            state_namespace_identity: prepared.context.state_namespace_identity,
            root_terminal_identity: prepared.context.root_terminal_identity,
            source_outcome_identity: prepared.body.identity()?,
            subject_position,
        })
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, DirectMpcPreprocessingSourceTerminalError> {
        encode_domain_tuple(
            SOURCE_ENDORSEMENT_BODY_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state_namespace_identity.into_bytes()),
                CanonicalItem::hash512(self.root_terminal_identity.into_bytes()),
                CanonicalItem::hash512(self.source_outcome_identity.into_bytes()),
                CanonicalItem::unsigned16(self.subject_position),
            ],
        )
    }

    fn identity(self) -> Result<Hash512, DirectMpcPreprocessingSourceTerminalError> {
        hash_encoded_object(SOURCE_ENDORSEMENT_IDENTITY_DOMAIN, &self.canonical_bytes()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateAuthorizedDirectMpcOneAndPreprocessingSource {
    source: VerifiedDirectMpcOneAndPreprocessingSource,
    state_namespace_identity: Hash512,
    terminal_identity: Hash512,
}

impl StateAuthorizedDirectMpcOneAndPreprocessingSource {
    pub(crate) const fn source(&self) -> &VerifiedDirectMpcOneAndPreprocessingSource {
        &self.source
    }

    pub(crate) const fn identity(&self) -> Hash512 {
        self.terminal_identity
    }

    pub(crate) const fn state_namespace_identity(&self) -> Hash512 {
        self.state_namespace_identity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedDirectMpcPreprocessingSourceBurn {
    evidence: VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
    state_namespace_identity: Hash512,
    terminal_identity: Hash512,
}

impl VerifiedDirectMpcPreprocessingSourceBurn {
    pub(crate) const fn evidence(
        self,
    ) -> VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320 {
        self.evidence
    }

    pub(crate) const fn identity(self) -> Hash512 {
        self.terminal_identity
    }

    pub(crate) const fn state_namespace_identity(self) -> Hash512 {
        self.state_namespace_identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcPreprocessingSourceTerminalVerification {
    Pending,
    Success(StateAuthorizedDirectMpcOneAndPreprocessingSource),
    Burn(VerifiedDirectMpcPreprocessingSourceBurn),
}

pub(crate) fn verify_direct_mpc_preprocessing_source_terminal(
    action_context: &ActionContext,
    roster: &Roster,
    candidate: Option<DirectMpcPreprocessingSourceOutcomeCandidate<'_>>,
    terminal_bytes: Option<&[u8]>,
) -> Result<
    DirectMpcPreprocessingSourceTerminalVerification,
    DirectMpcPreprocessingSourceTerminalError,
> {
    let (Some(candidate), Some(terminal_bytes)) = (candidate, terminal_bytes) else {
        return Ok(DirectMpcPreprocessingSourceTerminalVerification::Pending);
    };
    let prepared =
        prepare_direct_mpc_preprocessing_source_terminal(action_context, roster, candidate)?;
    let tuple = decode_domain_tuple(terminal_bytes, SOURCE_TERMINAL_DOMAIN)?;
    let roster_parameters = derive_foundation_roster_parameters(prepared.context.participant_count)
        .ok_or(DirectMpcPreprocessingSourceTerminalError::WrongContext)?;
    let expected_endorsement_count = usize::from(roster_parameters.finality_quorum);
    let expected_item_count = SOURCE_TERMINAL_FIXED_ITEM_COUNT
        .checked_add(expected_endorsement_count)
        .ok_or(DirectMpcPreprocessingSourceTerminalError::ArithmeticOverflow)?;
    if tuple.items.len() > expected_item_count {
        return Err(DirectMpcPreprocessingSourceTerminalError::ConsumedState);
    }
    if tuple.items.len() != expected_item_count {
        return Err(DirectMpcPreprocessingSourceTerminalError::WrongCount);
    }
    require_exact_bytes(
        read_variable_bytes(&tuple.items[1])?,
        &prepared.body.canonical_bytes()?,
    )?;
    let mut preceding_subject_position = None;
    for carrier_item in &tuple.items[SOURCE_TERMINAL_FIXED_ITEM_COUNT..] {
        let carrier = decode_domain_tuple(
            read_variable_bytes(carrier_item)?,
            SOURCE_ENDORSEMENT_CARRIER_DOMAIN,
        )?;
        if carrier.items.len() != SOURCE_ENDORSEMENT_CARRIER_ITEM_COUNT {
            return Err(DirectMpcPreprocessingSourceTerminalError::WrongCount);
        }
        let subject_position = read_u16(&carrier.items[1])?;
        if subject_position >= prepared.context.participant_count {
            return Err(DirectMpcPreprocessingSourceTerminalError::WrongContext);
        }
        if preceding_subject_position.is_some_and(|preceding| preceding >= subject_position) {
            return Err(if preceding_subject_position == Some(subject_position) {
                DirectMpcPreprocessingSourceTerminalError::DuplicateIdentity
            } else {
                DirectMpcPreprocessingSourceTerminalError::WrongOrder
            });
        }
        preceding_subject_position = Some(subject_position);
        let intent = prepared.state_output_intent(subject_position)?;
        verify_state_output_certificate(intent, roster, read_variable_bytes(&carrier.items[2])?)?;
    }
    let terminal_identity = hash_foundation_tuple_512(
        SOURCE_TERMINAL_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(prepared.context.state_namespace_identity.into_bytes()),
            CanonicalItem::hash512(prepared.body.identity()?.into_bytes()),
        ],
    )?;
    Ok(match candidate {
        DirectMpcPreprocessingSourceOutcomeCandidate::Success(source) => {
            DirectMpcPreprocessingSourceTerminalVerification::Success(
                StateAuthorizedDirectMpcOneAndPreprocessingSource {
                    source: source.clone(),
                    state_namespace_identity: prepared.context.state_namespace_identity,
                    terminal_identity,
                },
            )
        }
        DirectMpcPreprocessingSourceOutcomeCandidate::Burn(evidence) => {
            DirectMpcPreprocessingSourceTerminalVerification::Burn(
                VerifiedDirectMpcPreprocessingSourceBurn {
                    evidence: *evidence,
                    state_namespace_identity: prepared.context.state_namespace_identity,
                    terminal_identity,
                },
            )
        }
    })
}

pub(crate) fn direct_mpc_preprocessing_source_endorsement_carrier_bytes(
    subject_position: u16,
    state_output_certificate_bytes: &[u8],
) -> Result<Vec<u8>, DirectMpcPreprocessingSourceTerminalError> {
    encode_domain_tuple(
        SOURCE_ENDORSEMENT_CARRIER_DOMAIN,
        vec![
            CanonicalItem::unsigned16(subject_position),
            CanonicalItem::variable_bytes(state_output_certificate_bytes)?,
        ],
    )
}

pub(crate) fn direct_mpc_preprocessing_source_terminal_bytes(
    prepared: PreparedDirectMpcPreprocessingSourceTerminal,
    endorsement_carrier_bytes: &[Vec<u8>],
) -> Result<Vec<u8>, DirectMpcPreprocessingSourceTerminalError> {
    let mut items = Vec::with_capacity(endorsement_carrier_bytes.len() + 1);
    items.push(CanonicalItem::variable_bytes(
        prepared.body.canonical_bytes()?,
    )?);
    for carrier_bytes in endorsement_carrier_bytes {
        items.push(CanonicalItem::variable_bytes(carrier_bytes)?);
    }
    encode_domain_tuple(SOURCE_TERMINAL_DOMAIN, items)
}

fn encode_domain_tuple(
    domain: &str,
    mut items: Vec<CanonicalItem>,
) -> Result<Vec<u8>, DirectMpcPreprocessingSourceTerminalError> {
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
) -> Result<CanonicalTuple, DirectMpcPreprocessingSourceTerminalError> {
    let tuple = CanonicalTuple::decode(bytes, &control_object_decode_limits())?;
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || tuple.items.is_empty()
        || tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0].variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(DirectMpcPreprocessingSourceTerminalError::WrongObject);
    }
    Ok(tuple)
}

fn hash_encoded_object(
    domain: &str,
    bytes: &[u8],
) -> Result<Hash512, DirectMpcPreprocessingSourceTerminalError> {
    Ok(hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(bytes)?],
    )?)
}

fn require_exact_bytes(
    actual: &[u8],
    expected: &[u8],
) -> Result<(), DirectMpcPreprocessingSourceTerminalError> {
    if actual != expected {
        return Err(DirectMpcPreprocessingSourceTerminalError::WrongContext);
    }
    Ok(())
}

fn read_variable_bytes(
    item: &CanonicalItem,
) -> Result<&[u8], DirectMpcPreprocessingSourceTerminalError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(DirectMpcPreprocessingSourceTerminalError::WrongObject);
    }
    Ok(item.variable_value_bytes()?)
}

fn read_u16(item: &CanonicalItem) -> Result<u16, DirectMpcPreprocessingSourceTerminalError> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(DirectMpcPreprocessingSourceTerminalError::WrongObject);
    }
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| DirectMpcPreprocessingSourceTerminalError::WrongObject)?,
    ))
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

#[cfg(test)]
mod tests {
    use fips204::{ml_dsa_65, traits::Signer};

    use super::*;
    use crate::{
        foundation::{CanonicalItem, FOUNDATION_PROFILE},
        tally_preparation::{
            SeedMailboxTestFixture320, seal_mailbox_stream,
            verified_one_and_source_and_joined_custody,
            verify_direct_mpc_one_and_preprocessing_source,
            verify_pseudorandom_zero_sharing_seed_mailbox_authenticated_inconsistency_320,
        },
    };

    use super::super::{
        STATE_OUTPUT_CERTIFICATE_DOMAIN, STATE_SUBJECT_SIGNATURE_CONTEXT,
        STATE_WITNESS_ENVELOPE_DOMAIN, STATE_WITNESS_SIGNATURE_CONTEXT,
        StateSubjectAuthorizationBody, StateWitnessAuthorizationBody,
        state_witness_certificate_identity,
    };

    const TEST_SIGNATURE_RANDOMNESS_DOMAIN: &str =
        "sealed-lattice/test/direct-mpc-preprocessing-source-terminal-signature-randomness";

    #[test]
    fn actual_success_and_authenticated_inconsistency_mint_distinct_one_shot_terminals() {
        let (fixture, source, evidence) = source_and_evidence();
        let success_candidate = DirectMpcPreprocessingSourceOutcomeCandidate::Success(&source);
        let burn_candidate = DirectMpcPreprocessingSourceOutcomeCandidate::Burn(&evidence);
        let prepared_success = prepare_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            success_candidate,
        )
        .unwrap();
        let prepared_burn = prepare_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            burn_candidate,
        )
        .unwrap();
        assert_eq!(
            prepared_success.state_namespace_identity(),
            prepared_burn.state_namespace_identity()
        );
        for subject_position in 0..FOUNDATION_PROFILE.participant_count {
            assert_eq!(
                prepared_success
                    .state_output_intent(subject_position)
                    .unwrap()
                    .state_key_identity(),
                prepared_burn
                    .state_output_intent(subject_position)
                    .unwrap()
                    .state_key_identity()
            );
        }

        let success_terminal = terminal_bytes(
            prepared_success,
            &fixture,
            &(0..FOUNDATION_PROFILE.finality_quorum).collect::<Vec<_>>(),
            0x31,
        );
        let burn_subjects = (FOUNDATION_PROFILE.participant_count
            - FOUNDATION_PROFILE.finality_quorum
            ..FOUNDATION_PROFILE.participant_count)
            .collect::<Vec<_>>();
        let burn_terminal = terminal_bytes(prepared_burn, &fixture, &burn_subjects, 0x71);
        let measurement_certificate = signed_state_output_certificate(
            prepared_success.state_output_intent(0).unwrap(),
            &fixture,
            0x31,
        );
        let measurement_carrier =
            direct_mpc_preprocessing_source_endorsement_carrier_bytes(0, &measurement_certificate)
                .unwrap();
        assert_eq!(prepared_success.body.canonical_bytes().unwrap().len(), 508);
        assert_eq!(prepared_burn.body.canonical_bytes().unwrap().len(), 521);
        assert_eq!(
            prepared_success
                .endorsement_body(0)
                .unwrap()
                .canonical_bytes()
                .unwrap()
                .len(),
            310
        );
        assert_eq!(measurement_certificate.len(), 29_123);
        assert_eq!(measurement_carrier.len(), 29_236);
        assert_eq!(success_terminal.len(), 205_324);
        assert_eq!(burn_terminal.len(), 205_337);

        let success = verify_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            Some(success_candidate),
            Some(&success_terminal),
        )
        .unwrap();
        let burn = verify_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            Some(burn_candidate),
            Some(&burn_terminal),
        )
        .unwrap();
        let DirectMpcPreprocessingSourceTerminalVerification::Success(success) = success else {
            panic!("success terminal did not authorize the source");
        };
        let DirectMpcPreprocessingSourceTerminalVerification::Burn(burn) = burn else {
            panic!("burn terminal did not authorize the inconsistency");
        };
        assert_eq!(success.source(), &source);
        assert_eq!(burn.evidence(), evidence);
        assert_eq!(
            success.state_namespace_identity(),
            burn.state_namespace_identity()
        );
        assert_ne!(success.identity(), burn.identity());

        let replay = verify_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            Some(success_candidate),
            Some(&success_terminal),
        )
        .unwrap();
        assert_eq!(
            replay,
            DirectMpcPreprocessingSourceTerminalVerification::Success(success)
        );
    }

    #[test]
    fn missing_material_stays_pending_and_cross_outcome_terminals_refuse() {
        let (fixture, source, evidence) = source_and_evidence();
        let success_candidate = DirectMpcPreprocessingSourceOutcomeCandidate::Success(&source);
        let burn_candidate = DirectMpcPreprocessingSourceOutcomeCandidate::Burn(&evidence);
        let prepared_success = prepare_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            success_candidate,
        )
        .unwrap();
        let success_terminal = terminal_bytes(
            prepared_success,
            &fixture,
            &(0..FOUNDATION_PROFILE.finality_quorum).collect::<Vec<_>>(),
            0x41,
        );
        assert_eq!(
            verify_direct_mpc_preprocessing_source_terminal(
                &fixture.action_context,
                &fixture.roster,
                None,
                Some(&success_terminal),
            )
            .unwrap(),
            DirectMpcPreprocessingSourceTerminalVerification::Pending
        );
        assert_eq!(
            verify_direct_mpc_preprocessing_source_terminal(
                &fixture.action_context,
                &fixture.roster,
                Some(success_candidate),
                None,
            )
            .unwrap(),
            DirectMpcPreprocessingSourceTerminalVerification::Pending
        );
        assert_eq!(
            verify_direct_mpc_preprocessing_source_terminal(
                &fixture.action_context,
                &fixture.roster,
                Some(burn_candidate),
                Some(&success_terminal),
            ),
            Err(DirectMpcPreprocessingSourceTerminalError::WrongContext)
        );
    }

    #[test]
    fn terminal_refuses_bad_subject_inventories_wrong_state_and_appended_events() {
        let (fixture, source, evidence) = source_and_evidence();
        let success_candidate = DirectMpcPreprocessingSourceOutcomeCandidate::Success(&source);
        let burn_candidate = DirectMpcPreprocessingSourceOutcomeCandidate::Burn(&evidence);
        let prepared_success = prepare_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            success_candidate,
        )
        .unwrap();
        for (subjects, expected_error) in [
            (
                vec![0, 1, 1, 2, 3, 4, 5],
                DirectMpcPreprocessingSourceTerminalError::DuplicateIdentity,
            ),
            (
                vec![0, 2, 1, 3, 4, 5, 6],
                DirectMpcPreprocessingSourceTerminalError::WrongOrder,
            ),
            (
                vec![0, 1, 2, 3, 4, 5],
                DirectMpcPreprocessingSourceTerminalError::WrongCount,
            ),
            (
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                DirectMpcPreprocessingSourceTerminalError::ConsumedState,
            ),
        ] {
            let hostile_terminal = terminal_bytes(prepared_success, &fixture, &subjects, 0x51);
            assert_eq!(
                verify_direct_mpc_preprocessing_source_terminal(
                    &fixture.action_context,
                    &fixture.roster,
                    Some(success_candidate),
                    Some(&hostile_terminal),
                ),
                Err(expected_error)
            );
        }

        let prepared_burn = prepare_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            burn_candidate,
        )
        .unwrap();
        let subjects = (0..FOUNDATION_PROFILE.finality_quorum).collect::<Vec<_>>();
        let mut carriers = subjects
            .iter()
            .map(|subject_position| {
                let intent = prepared_success
                    .state_output_intent(*subject_position)
                    .unwrap();
                let certificate = signed_state_output_certificate(intent, &fixture, 0x61);
                direct_mpc_preprocessing_source_endorsement_carrier_bytes(
                    *subject_position,
                    &certificate,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let wrong_intent = prepared_burn.state_output_intent(subjects[0]).unwrap();
        let wrong_certificate = signed_state_output_certificate(wrong_intent, &fixture, 0x62);
        carriers[0] = direct_mpc_preprocessing_source_endorsement_carrier_bytes(
            subjects[0],
            &wrong_certificate,
        )
        .unwrap();
        let wrong_state_terminal =
            direct_mpc_preprocessing_source_terminal_bytes(prepared_success, &carriers).unwrap();
        assert!(matches!(
            verify_direct_mpc_preprocessing_source_terminal(
                &fixture.action_context,
                &fixture.roster,
                Some(success_candidate),
                Some(&wrong_state_terminal),
            ),
            Err(DirectMpcPreprocessingSourceTerminalError::State(_))
        ));
    }

    #[test]
    fn every_two_source_quorums_share_an_honest_stable_subject() {
        let (fixture, source, evidence) = source_and_evidence();
        let prepared_success = prepare_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            DirectMpcPreprocessingSourceOutcomeCandidate::Success(&source),
        )
        .unwrap();
        let prepared_burn = prepare_direct_mpc_preprocessing_source_terminal(
            &fixture.action_context,
            &fixture.roster,
            DirectMpcPreprocessingSourceOutcomeCandidate::Burn(&evidence),
        )
        .unwrap();
        let quorums = combinations(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.finality_quorum,
        );
        for first in &quorums {
            for second in &quorums {
                let intersection = first
                    .iter()
                    .copied()
                    .filter(|position| second.contains(position))
                    .collect::<Vec<_>>();
                assert!(intersection.len() > usize::from(FOUNDATION_PROFILE.active_fault_bound));
                for subject_position in intersection {
                    assert_eq!(
                        prepared_success
                            .state_output_intent(subject_position)
                            .unwrap()
                            .state_key_identity(),
                        prepared_burn
                            .state_output_intent(subject_position)
                            .unwrap()
                            .state_key_identity()
                    );
                }
            }
        }
    }

    fn source_and_evidence() -> (
        SeedMailboxTestFixture320,
        VerifiedDirectMpcOneAndPreprocessingSource,
        VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
    ) {
        let parameter_identity =
            direct_mpc_one_and_preprocessing_source_parameter_identity().unwrap();
        let (fixture, receipt_terminal, _joined_seed_masters) =
            verified_one_and_source_and_joined_custody(parameter_identity);
        let source =
            verify_direct_mpc_one_and_preprocessing_source(&fixture.roster, &receipt_terminal)
                .unwrap();
        let mut inconsistent_payload = fixture.payload_bytes.to_vec();
        inconsistent_payload[0] ^= 0x80;
        let sealed = seal_mailbox_stream(
            &fixture,
            fixture.recipient_position,
            &fixture.descriptor_bytes,
            &inconsistent_payload,
            [0xa1; 32],
            0xa3,
        );
        let encrypted_chunks = sealed
            .encrypted_chunks
            .iter()
            .map(|chunk| chunk.as_slice())
            .collect::<Vec<_>>();
        let evidence =
            verify_pseudorandom_zero_sharing_seed_mailbox_authenticated_inconsistency_320(
                &fixture.root_terminal,
                &fixture.roster,
                fixture.sender_position,
                fixture.recipient_position,
                &fixture.descriptor_bytes,
                &sealed.header_bytes,
                &sealed.manifest_bytes,
                &sealed.signature_envelope_bytes,
                &encrypted_chunks,
                &sealed.authenticated_encryption_key,
            )
            .unwrap();
        (fixture, source, evidence)
    }

    fn terminal_bytes(
        prepared: PreparedDirectMpcPreprocessingSourceTerminal,
        fixture: &SeedMailboxTestFixture320,
        subject_positions: &[u16],
        marker: u8,
    ) -> Vec<u8> {
        let carriers = subject_positions
            .iter()
            .map(|subject_position| {
                let intent = prepared.state_output_intent(*subject_position).unwrap();
                let certificate = signed_state_output_certificate(intent, fixture, marker);
                direct_mpc_preprocessing_source_endorsement_carrier_bytes(
                    *subject_position,
                    &certificate,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        direct_mpc_preprocessing_source_terminal_bytes(prepared, &carriers).unwrap()
    }

    fn signed_state_output_certificate(
        intent: StateOutputIntent,
        fixture: &SeedMailboxTestFixture320,
        marker: u8,
    ) -> Vec<u8> {
        let witness_positions = (0..FOUNDATION_PROFILE.participant_count)
            .filter(|position| *position != intent.subject_position())
            .take(usize::from(FOUNDATION_PROFILE.state_witness_quorum))
            .collect::<Vec<_>>();
        let witness_envelopes = witness_positions
            .iter()
            .map(|witness_position| {
                let body = StateWitnessAuthorizationBody::new(intent, *witness_position).unwrap();
                let body_bytes = body.canonical_bytes().unwrap();
                let signature = sign(
                    &fixture.signing_keys[usize::from(*witness_position)],
                    *witness_position,
                    &body_bytes,
                    STATE_WITNESS_SIGNATURE_CONTEXT,
                    marker,
                );
                encode_domain_tuple(
                    STATE_WITNESS_ENVELOPE_DOMAIN,
                    vec![
                        CanonicalItem::variable_bytes(body_bytes).unwrap(),
                        CanonicalItem::fixed_bytes(signature).unwrap(),
                    ],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let witness_references = witness_envelopes
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let witness_certificate_identity =
            state_witness_certificate_identity(intent, &witness_references).unwrap();
        let subject_body =
            StateSubjectAuthorizationBody::new(intent, witness_certificate_identity).unwrap();
        let subject_body_bytes = subject_body.canonical_bytes().unwrap();
        let subject_signature = sign(
            &fixture.signing_keys[usize::from(intent.subject_position())],
            intent.subject_position(),
            &subject_body_bytes,
            STATE_SUBJECT_SIGNATURE_CONTEXT,
            marker,
        );
        let mut items = Vec::with_capacity(witness_envelopes.len() + 3);
        items.push(CanonicalItem::variable_bytes(intent.canonical_bytes().unwrap()).unwrap());
        for envelope in witness_envelopes {
            items.push(CanonicalItem::variable_bytes(envelope).unwrap());
        }
        items.push(CanonicalItem::variable_bytes(subject_body_bytes).unwrap());
        items.push(CanonicalItem::fixed_bytes(subject_signature).unwrap());
        encode_domain_tuple(STATE_OUTPUT_CERTIFICATE_DOMAIN, items).unwrap()
    }

    fn sign(
        signing_key: &ml_dsa_65::PrivateKey,
        signer_position: u16,
        message: &[u8],
        context: &[u8],
        marker: u8,
    ) -> [u8; ml_dsa_65::SIG_LEN] {
        let randomness = hash_foundation_tuple_512(
            TEST_SIGNATURE_RANDOMNESS_DOMAIN,
            &[
                CanonicalItem::unsigned16(signer_position),
                CanonicalItem::unsigned16(u16::from(marker)),
                CanonicalItem::variable_bytes(context).unwrap(),
                CanonicalItem::variable_bytes(message).unwrap(),
            ],
        )
        .unwrap();
        signing_key
            .try_sign_with_seed(
                &randomness.as_bytes()[..32].try_into().unwrap(),
                message,
                context,
            )
            .unwrap()
    }

    fn combinations(participant_count: u16, quorum: u16) -> Vec<Vec<u16>> {
        fn collect(
            next: u16,
            participant_count: u16,
            remaining: usize,
            current: &mut Vec<u16>,
            output: &mut Vec<Vec<u16>>,
        ) {
            if remaining == 0 {
                output.push(current.clone());
                return;
            }
            for position in next..participant_count {
                if usize::from(participant_count - position) < remaining {
                    break;
                }
                current.push(position);
                collect(
                    position + 1,
                    participant_count,
                    remaining - 1,
                    current,
                    output,
                );
                current.pop();
            }
        }

        let mut output = Vec::new();
        collect(
            0,
            participant_count,
            usize::from(quorum),
            &mut Vec::new(),
            &mut output,
        );
        output
    }
}
