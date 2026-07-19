//! Canonical application-statement schemas for the selected proof suite.

use crate::{
    bgv::{
        evaluator::{
            candidate_evidence::EvaluatorCandidateInput, program::selected_evaluator_program_set,
        },
        target_decryption::selected_target_partial_decryption_stream_byte_length,
    },
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings, StreamDescriptor,
        selected_sharing_data_prime_coordinates, selected_target_data_prime_coordinates,
    },
};

const ROUND_ONE_SOURCE_ROOT_PAIR_SCHEMA_IDENTIFIER: u16 = 0x1219;
const EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER: u16 = 0x121a;
const GALOIS_KEY_SHARE_ENTRY_SCHEMA_IDENTIFIER: u16 = 0x121d;
const APPLICATION_STATEMENT_SCHEMA_VERSION: u16 = 1;
const GALOIS_KEY_SHARE_STATEMENT_SCHEMA_VERSION: u16 = 2;
const SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION: u32 = 0;

const fn selected_application_statement_schema_version(schema_identifier: u16) -> u16 {
    if schema_identifier
        == ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
    {
        GALOIS_KEY_SHARE_STATEMENT_SCHEMA_VERSION
    } else {
        APPLICATION_STATEMENT_SCHEMA_VERSION
    }
}

fn selected_target_share_root_count() -> Result<usize, SelectedApplicationStatementError> {
    selected_target_data_prime_coordinates()
        .map(|coordinates| coordinates.len())
        .map_err(|_| SelectedApplicationStatementError::InvalidProfile)
}

fn selected_sharing_limb_count() -> Result<usize, SelectedApplicationStatementError> {
    selected_sharing_data_prime_coordinates()
        .map(|coordinates| coordinates.len())
        .map_err(|_| SelectedApplicationStatementError::InvalidProfile)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedApplicationStatementError {
    CanonicalEncoding,
    WrongSchema,
    WrongTypeOrLength,
    WrongValue,
    InvalidProfile,
    CountOverflow,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SelectedApplicationStatementContext {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    schedule_position: Option<u32>,
    top_count: Option<u16>,
}

impl SelectedApplicationStatementContext {
    pub(crate) const fn new(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        schedule_position: Option<u32>,
        top_count: Option<u16>,
    ) -> Self {
        Self {
            protocol_version,
            suite_identifier,
            schedule_position,
            top_count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StatementFieldShape {
    ExactUnsigned16(u16),
    RosterPosition,
    ExactUnsigned32(u32),
    Unsigned64,
    Hash,
    ExactHash([u8; Hash512::BYTE_LENGTH]),
    ParticipantIdentity,
    HashList(usize),
    RoundOneSourceRootPairs(usize),
    GaloisKeyShareEntries,
    EvaluatorKeyAggregateEntries(Vec<SelectedEvaluatorEntryPosition>),
    StreamDescriptor { exact_total_byte_length: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedEvaluatorEntryKind {
    Relinearization {
        catalog_level: usize,
    },
    Galois {
        galois_element: usize,
        catalog_level: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorEntryPosition {
    key_kind: SelectedEvaluatorEntryKind,
    schedule_position: u32,
}

impl SelectedEvaluatorEntryPosition {
    pub(crate) const fn key_kind(self) -> SelectedEvaluatorEntryKind {
        self.key_kind
    }

    pub(crate) const fn schedule_position(self) -> u32 {
        self.schedule_position
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorAggregateEntryRoots {
    entry_ordinal: u32,
    position: SelectedEvaluatorEntryPosition,
    source_component_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    runtime_component_root: [u8; Hash512::BYTE_LENGTH],
    auxiliary_component_root: [u8; Hash512::BYTE_LENGTH],
}

pub(crate) struct SelectedEvaluatorAggregateEntryInput<'input> {
    source_component_roots: &'input [[u8; Hash512::BYTE_LENGTH]],
    runtime_component_root: [u8; Hash512::BYTE_LENGTH],
    auxiliary_component_root: [u8; Hash512::BYTE_LENGTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRelinearizationRoundOneAggregateStatement {
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    ordered_source_root_pairs: Box<[[[u8; Hash512::BYTE_LENGTH]; 2]]>,
    aggregate_left_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_right_root: [u8; Hash512::BYTE_LENGTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedSameSecretStatement {
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    ordered_degree_zero_commitment_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
}

impl SelectedSameSecretStatement {
    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) fn ordered_degree_zero_commitment_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_degree_zero_commitment_roots
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedPublicKeyShareStatement {
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    public_key_share_root: [u8; Hash512::BYTE_LENGTH],
}

impl SelectedPublicKeyShareStatement {
    pub(crate) const fn setup_proof_context_hash(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn participant_identity(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn anchor_commitment_roots(self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) const fn public_key_share_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_key_share_root
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRelinearizationRoundOneStatement {
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    round_one_right_root: [u8; Hash512::BYTE_LENGTH],
}

impl SelectedRelinearizationRoundOneStatement {
    pub(crate) const fn setup_proof_context_hash(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn participant_identity(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn schedule_position(self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) const fn round_one_left_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.round_one_left_root
    }

    pub(crate) const fn round_one_right_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.round_one_right_root
    }
}

impl SelectedRelinearizationRoundOneAggregateStatement {
    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn schedule_position(&self) -> u32 {
        self.schedule_position
    }

    pub(crate) fn ordered_source_root_pairs(&self) -> &[[[u8; Hash512::BYTE_LENGTH]; 2]] {
        &self.ordered_source_root_pairs
    }

    pub(crate) const fn aggregate_left_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_left_root
    }

    pub(crate) const fn aggregate_right_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_right_root
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedRelinearizationRoundTwoStatement {
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    round_one_right_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_round_one_right_root: [u8; Hash512::BYTE_LENGTH],
    contribution_root: [u8; Hash512::BYTE_LENGTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedGaloisKeyShareStatement {
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    batch_schedule_position: u32,
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    ordered_contribution_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedCollectivePublicKeyAggregateStatement {
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_public_key_share_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    collective_public_key_root: [u8; Hash512::BYTE_LENGTH],
    collective_public_key_full_object_digest: [u8; Hash512::BYTE_LENGTH],
}

impl SelectedCollectivePublicKeyAggregateStatement {
    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) fn ordered_public_key_share_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_public_key_share_roots
    }

    pub(crate) const fn collective_public_key_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.collective_public_key_root
    }

    pub(crate) const fn collective_public_key_full_object_digest(
        &self,
    ) -> [u8; Hash512::BYTE_LENGTH] {
        self.collective_public_key_full_object_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedAggregateThresholdShareStatement {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    recipient_input_root: [u8; Hash512::BYTE_LENGTH],
    ordered_source_share_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_aggregate_threshold_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedVssShareLinkageStatement {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    ordered_coefficient_material_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_recipient_share_material_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedBallotValidityStatement {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    producer_sequence: u64,
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    ballot_ciphertext_full_object_digest: [u8; Hash512::BYTE_LENGTH],
}

impl SelectedBallotValidityStatement {
    pub(crate) const fn protocol_version(self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(crate) const fn participant_identity(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn producer_sequence(self) -> u64 {
        self.producer_sequence
    }

    pub(crate) const fn verified_setup_source_hash(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.verified_setup_source_hash
    }

    pub(crate) const fn ballot_ciphertext_full_object_digest(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ballot_ciphertext_full_object_digest
    }
}

impl SelectedAggregateThresholdShareStatement {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn recipient_input_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.recipient_input_root
    }

    pub(crate) fn ordered_source_share_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_source_share_roots
    }

    pub(crate) fn ordered_aggregate_threshold_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_aggregate_threshold_roots
    }
}

impl SelectedVssShareLinkageStatement {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(crate) const fn public_setup_seed(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.public_setup_seed
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) fn ordered_coefficient_material_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_coefficient_material_roots
    }

    pub(crate) fn ordered_recipient_share_material_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_recipient_share_material_roots
    }
}

impl SelectedGaloisKeyShareStatement {
    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn participant_identity(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn batch_schedule_position(&self) -> u32 {
        self.batch_schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(&self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) fn ordered_contribution_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_contribution_roots
    }
}

impl SelectedRelinearizationRoundTwoStatement {
    pub(crate) const fn setup_proof_context_hash(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn participant_identity(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn schedule_position(self) -> u32 {
        self.schedule_position
    }

    pub(crate) const fn anchor_commitment_roots(self) -> [[u8; Hash512::BYTE_LENGTH]; 3] {
        self.anchor_commitment_roots
    }

    pub(crate) const fn round_one_left_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.round_one_left_root
    }

    pub(crate) const fn round_one_right_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.round_one_right_root
    }

    pub(crate) const fn aggregate_round_one_left_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_round_one_left_root
    }

    pub(crate) const fn aggregate_round_one_right_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.aggregate_round_one_right_root
    }

    pub(crate) const fn contribution_root(self) -> [u8; Hash512::BYTE_LENGTH] {
        self.contribution_root
    }
}

fn selected_galois_key_share_schedule_positions()
-> Result<Vec<u32>, SelectedApplicationStatementError> {
    let selected_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
    if selected_candidate.galois_key_schedule.is_empty() {
        return Err(SelectedApplicationStatementError::InvalidProfile);
    }
    selected_candidate
        .galois_key_schedule
        .iter()
        .enumerate()
        .map(|(schedule_position, _)| {
            u32::try_from(schedule_position)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)
        })
        .collect()
}

fn selected_relinearization_statement_schedule_position()
-> Result<u32, SelectedApplicationStatementError> {
    let selected_positions = selected_evaluator_relinearization_entry_positions()?;
    let [selected_position] = selected_positions.as_slice() else {
        return Err(SelectedApplicationStatementError::InvalidProfile);
    };
    Ok(selected_position.schedule_position())
}

impl<'input> SelectedEvaluatorAggregateEntryInput<'input> {
    pub(crate) const fn new(
        source_component_roots: &'input [[u8; Hash512::BYTE_LENGTH]],
        runtime_component_root: [u8; Hash512::BYTE_LENGTH],
        auxiliary_component_root: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            source_component_roots,
            runtime_component_root,
            auxiliary_component_root,
        }
    }
}

impl SelectedEvaluatorAggregateEntryRoots {
    pub(crate) const fn entry_ordinal(&self) -> u32 {
        self.entry_ordinal
    }

    pub(crate) const fn position(&self) -> SelectedEvaluatorEntryPosition {
        self.position
    }

    pub(crate) fn source_component_roots(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.source_component_roots
    }

    pub(crate) const fn runtime_component_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.runtime_component_root
    }

    pub(crate) const fn auxiliary_component_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.auxiliary_component_root
    }
}

pub(crate) fn decode_selected_application_statement(
    canonical_bytes: &[u8],
    expected_schema_identifier: u16,
    context: SelectedApplicationStatementContext,
) -> Result<CanonicalTuple, SelectedApplicationStatementError> {
    let statement = CanonicalTuple::decode(canonical_bytes, &CanonicalDecodeLimits::default())
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    validate_selected_application_statement(&statement, expected_schema_identifier, context)?;
    if statement
        .encode()
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?
        != canonical_bytes
    {
        return Err(SelectedApplicationStatementError::CanonicalEncoding);
    }
    Ok(statement)
}

pub(crate) fn decode_selected_collective_public_key_aggregate_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedCollectivePublicKeyAggregateStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    Ok(SelectedCollectivePublicKeyAggregateStatement {
        setup_proof_context_hash: read_hash(&statement.items[0])?,
        ordered_public_key_share_roots: read_hash_list_values(
            &statement.items[1],
            usize::from(FOUNDATION_PROFILE.participant_count),
        )?
        .into_boxed_slice(),
        collective_public_key_root: read_hash(&statement.items[2])?,
        collective_public_key_full_object_digest: read_hash(&statement.items[3])?,
    })
}

pub(crate) fn decode_selected_same_secret_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedSameSecretStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    let anchor_commitment_roots = read_hash_list_values(&statement.items[4], 3)?
        .try_into()
        .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?;
    Ok(SelectedSameSecretStatement {
        setup_proof_context_hash: read_hash(&statement.items[0])?,
        participant_identity: read_participant_identity(&statement.items[1])?,
        roster_position: read_unsigned16(&statement.items[2])?,
        ordered_degree_zero_commitment_roots: read_hash_list_values(
            &statement.items[3],
            selected_sharing_limb_count()?,
        )?
        .into_boxed_slice(),
        anchor_commitment_roots,
    })
}

pub(crate) fn decode_selected_public_key_share_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedPublicKeyShareStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    let anchor_commitment_roots = read_hash_list_values(&statement.items[3], 3)?
        .try_into()
        .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?;
    Ok(SelectedPublicKeyShareStatement {
        setup_proof_context_hash: read_hash(&statement.items[0])?,
        participant_identity: read_participant_identity(&statement.items[1])?,
        roster_position: read_unsigned16(&statement.items[2])?,
        anchor_commitment_roots,
        public_key_share_root: read_hash(&statement.items[4])?,
    })
}

pub(crate) fn decode_selected_aggregate_threshold_share_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedAggregateThresholdShareStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    Ok(SelectedAggregateThresholdShareStatement {
        protocol_version: read_unsigned16(&statement.items[0])?,
        suite_identifier: read_hash(&statement.items[1])?,
        ceremony_context_hash: read_hash(&statement.items[2])?,
        action_context_hash: read_hash(&statement.items[3])?,
        roster_hash: read_hash(&statement.items[4])?,
        participant_identity: read_participant_identity(&statement.items[5])?,
        roster_position: read_unsigned16(&statement.items[6])?,
        recipient_input_root: read_hash(&statement.items[7])?,
        ordered_source_share_roots: read_hash_list_values(
            &statement.items[8],
            vss_recipient_share_material_root_count()?,
        )?
        .into_boxed_slice(),
        ordered_aggregate_threshold_roots: read_hash_list_values(
            &statement.items[9],
            selected_sharing_limb_count()?,
        )?
        .into_boxed_slice(),
    })
}

pub(crate) fn decode_selected_vss_share_linkage_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedVssShareLinkageStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    Ok(SelectedVssShareLinkageStatement {
        protocol_version: read_unsigned16(&statement.items[0])?,
        suite_identifier: read_hash(&statement.items[1])?,
        ceremony_context_hash: read_hash(&statement.items[2])?,
        action_context_hash: read_hash(&statement.items[3])?,
        roster_hash: read_hash(&statement.items[4])?,
        public_setup_seed: read_hash(&statement.items[5])?,
        participant_identity: read_participant_identity(&statement.items[6])?,
        roster_position: read_unsigned16(&statement.items[7])?,
        ordered_coefficient_material_roots: read_hash_list_values(
            &statement.items[8],
            vss_coefficient_material_root_count()?,
        )?
        .into_boxed_slice(),
        ordered_recipient_share_material_roots: read_hash_list_values(
            &statement.items[9],
            vss_recipient_share_material_root_count()?,
        )?
        .into_boxed_slice(),
    })
}

pub(crate) fn decode_selected_ballot_validity_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedBallotValidityStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    Ok(SelectedBallotValidityStatement {
        protocol_version: read_unsigned16(&statement.items[0])?,
        suite_identifier: read_hash(&statement.items[1])?,
        ceremony_context_hash: read_hash(&statement.items[2])?,
        action_context_hash: read_hash(&statement.items[3])?,
        roster_hash: read_hash(&statement.items[4])?,
        participant_identity: read_participant_identity(&statement.items[5])?,
        producer_sequence: read_unsigned64(&statement.items[6])?,
        verified_setup_source_hash: read_hash(&statement.items[7])?,
        ballot_ciphertext_full_object_digest: read_hash(&statement.items[8])?,
    })
}

pub(crate) fn decode_selected_relinearization_round_two_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedRelinearizationRoundTwoStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    let anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3] =
        read_hash_list_values(&statement.items[4], 3)?
            .try_into()
            .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?;
    Ok(SelectedRelinearizationRoundTwoStatement {
        setup_proof_context_hash: read_hash(&statement.items[0])?,
        participant_identity: read_participant_identity(&statement.items[1])?,
        roster_position: read_unsigned16(&statement.items[2])?,
        schedule_position: read_unsigned32(&statement.items[3])?,
        anchor_commitment_roots,
        round_one_left_root: read_hash(&statement.items[5])?,
        round_one_right_root: read_hash(&statement.items[6])?,
        aggregate_round_one_left_root: read_hash(&statement.items[7])?,
        aggregate_round_one_right_root: read_hash(&statement.items[8])?,
        contribution_root: read_hash(&statement.items[9])?,
    })
}

pub(crate) fn decode_selected_relinearization_round_one_aggregate_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedRelinearizationRoundOneAggregateStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    let ordered_source_root_pairs = decode_nested_tuple_list(
        &statement.items[2],
        usize::from(FOUNDATION_PROFILE.participant_count),
    )?
    .into_iter()
    .map(|pair| {
        if pair.schema_identifier != ROUND_ONE_SOURCE_ROOT_PAIR_SCHEMA_IDENTIFIER
            || pair.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
            || pair.items.len() != 2
        {
            return Err(SelectedApplicationStatementError::WrongSchema);
        }
        Ok([read_hash(&pair.items[0])?, read_hash(&pair.items[1])?])
    })
    .collect::<Result<Vec<_>, _>>()?;
    Ok(SelectedRelinearizationRoundOneAggregateStatement {
        setup_proof_context_hash: read_hash(&statement.items[0])?,
        schedule_position: read_unsigned32(&statement.items[1])?,
        ordered_source_root_pairs: ordered_source_root_pairs.into_boxed_slice(),
        aggregate_left_root: read_hash(&statement.items[3])?,
        aggregate_right_root: read_hash(&statement.items[4])?,
    })
}

pub(crate) fn decode_selected_relinearization_round_one_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedRelinearizationRoundOneStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    let anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3] =
        read_hash_list_values(&statement.items[4], 3)?
            .try_into()
            .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?;
    Ok(SelectedRelinearizationRoundOneStatement {
        setup_proof_context_hash: read_hash(&statement.items[0])?,
        participant_identity: read_participant_identity(&statement.items[1])?,
        roster_position: read_unsigned16(&statement.items[2])?,
        schedule_position: read_unsigned32(&statement.items[3])?,
        anchor_commitment_roots,
        round_one_left_root: read_hash(&statement.items[5])?,
        round_one_right_root: read_hash(&statement.items[6])?,
    })
}

pub(crate) fn decode_selected_galois_key_share_statement(
    canonical_bytes: &[u8],
    context: SelectedApplicationStatementContext,
) -> Result<SelectedGaloisKeyShareStatement, SelectedApplicationStatementError> {
    let statement = decode_selected_application_statement(
        canonical_bytes,
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        context,
    )?;
    let anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3] =
        read_hash_list_values(&statement.items[4], 3)?
            .try_into()
            .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?;
    Ok(SelectedGaloisKeyShareStatement {
        setup_proof_context_hash: read_hash(&statement.items[0])?,
        participant_identity: read_participant_identity(&statement.items[1])?,
        roster_position: read_unsigned16(&statement.items[2])?,
        batch_schedule_position: read_unsigned32(&statement.items[3])?,
        anchor_commitment_roots,
        ordered_contribution_roots: decode_galois_key_share_entries(&statement.items[5])?
            .into_boxed_slice(),
    })
}

pub(crate) fn canonical_selected_application_statement_for_ceiling(
    schema_identifier: u16,
    context: SelectedApplicationStatementContext,
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    let fields = selected_statement_field_shapes(schema_identifier, context)?;
    let items = fields
        .iter()
        .map(canonical_item_for_statement_field)
        .collect::<Result<Vec<_>, _>>()?;
    let canonical_bytes = CanonicalTuple::new(
        schema_identifier,
        selected_application_statement_schema_version(schema_identifier),
        items,
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_application_statement(&canonical_bytes, schema_identifier, context)?;
    Ok(canonical_bytes)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn canonical_selected_ballot_validity_statement(
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    producer_sequence: u64,
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    ballot_ciphertext_full_object_digest: [u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    let context =
        SelectedApplicationStatementContext::new(protocol_version, suite_identifier, None, None);
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(protocol_version),
            CanonicalItem::hash512(suite_identifier),
            CanonicalItem::hash512(ceremony_context_hash),
            CanonicalItem::hash512(action_context_hash),
            CanonicalItem::hash512(roster_hash),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned64(producer_sequence),
            CanonicalItem::hash512(verified_setup_source_hash),
            CanonicalItem::hash512(ballot_ciphertext_full_object_digest),
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_ballot_validity_statement(&canonical_bytes, context)?;
    Ok(canonical_bytes)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn canonical_selected_vss_share_linkage_statement(
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    ordered_coefficient_material_roots: &[[u8; Hash512::BYTE_LENGTH]],
    ordered_recipient_share_material_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    let context =
        SelectedApplicationStatementContext::new(protocol_version, suite_identifier, None, None);
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(protocol_version),
            CanonicalItem::hash512(suite_identifier),
            CanonicalItem::hash512(ceremony_context_hash),
            CanonicalItem::hash512(action_context_hash),
            CanonicalItem::hash512(roster_hash),
            CanonicalItem::hash512(public_setup_seed),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned16(roster_position),
            canonical_hash_list_values(ordered_coefficient_material_roots)?,
            canonical_hash_list_values(ordered_recipient_share_material_roots)?,
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_vss_share_linkage_statement(&canonical_bytes, context)?;
    Ok(canonical_bytes)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn canonical_selected_aggregate_threshold_share_statement(
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    recipient_input_root: [u8; Hash512::BYTE_LENGTH],
    ordered_source_share_roots: &[[u8; Hash512::BYTE_LENGTH]],
    ordered_aggregate_threshold_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if roster_position >= FOUNDATION_PROFILE.participant_count
        || ordered_source_share_roots.len() != vss_recipient_share_material_root_count()?
        || ordered_aggregate_threshold_roots.len() != selected_sharing_limb_count()?
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let context =
        SelectedApplicationStatementContext::new(protocol_version, suite_identifier, None, None);
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(protocol_version),
            CanonicalItem::hash512(suite_identifier),
            CanonicalItem::hash512(ceremony_context_hash),
            CanonicalItem::hash512(action_context_hash),
            CanonicalItem::hash512(roster_hash),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned16(roster_position),
            CanonicalItem::hash512(recipient_input_root),
            canonical_hash_list_values(ordered_source_share_roots)?,
            canonical_hash_list_values(ordered_aggregate_threshold_roots)?,
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_aggregate_threshold_share_statement(&canonical_bytes, context)?;
    Ok(canonical_bytes)
}

pub(crate) fn canonical_selected_same_secret_statement(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    ordered_degree_zero_commitment_roots: &[[u8; Hash512::BYTE_LENGTH]],
    anchor_commitment_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if roster_position >= FOUNDATION_PROFILE.participant_count
        || ordered_degree_zero_commitment_roots.len() != selected_sharing_limb_count()?
        || anchor_commitment_roots.len() != 3
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(setup_proof_context_hash),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned16(roster_position),
            canonical_hash_list_values(ordered_degree_zero_commitment_roots)?,
            canonical_hash_list_values(anchor_commitment_roots)?,
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_same_secret_statement(
        &canonical_bytes,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            None,
            None,
        ),
    )?;
    Ok(canonical_bytes)
}

pub(crate) fn canonical_selected_public_key_share_statement(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    anchor_commitment_roots: &[[u8; Hash512::BYTE_LENGTH]],
    public_key_share_root: [u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if roster_position >= FOUNDATION_PROFILE.participant_count || anchor_commitment_roots.len() != 3
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(setup_proof_context_hash),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned16(roster_position),
            canonical_hash_list_values(anchor_commitment_roots)?,
            CanonicalItem::hash512(public_key_share_root),
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_public_key_share_statement(
        &canonical_bytes,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            None,
            None,
        ),
    )?;
    Ok(canonical_bytes)
}

pub(crate) fn canonical_selected_collective_public_key_aggregate_statement(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_public_key_share_roots: &[[u8; Hash512::BYTE_LENGTH]],
    collective_public_key_root: [u8; Hash512::BYTE_LENGTH],
    collective_public_key_full_object_digest: [u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if ordered_public_key_share_roots.len() != usize::from(FOUNDATION_PROFILE.participant_count) {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(setup_proof_context_hash),
            canonical_hash_list_values(ordered_public_key_share_roots)?,
            CanonicalItem::hash512(collective_public_key_root),
            CanonicalItem::hash512(collective_public_key_full_object_digest),
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_collective_public_key_aggregate_statement(
        &canonical_bytes,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            None,
            None,
        ),
    )?;
    Ok(canonical_bytes)
}

pub(crate) fn canonical_selected_galois_key_share_statement(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    batch_schedule_position: u32,
    anchor_commitment_roots: &[[u8; Hash512::BYTE_LENGTH]],
    ordered_contribution_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if batch_schedule_position != SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION {
        return Err(SelectedApplicationStatementError::InvalidProfile);
    }
    if roster_position >= FOUNDATION_PROFILE.participant_count {
        return Err(SelectedApplicationStatementError::WrongValue);
    }
    let selected_schedule_positions = selected_galois_key_share_schedule_positions()?;
    if anchor_commitment_roots.len() != 3
        || ordered_contribution_roots.len() != selected_schedule_positions.len()
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        GALOIS_KEY_SHARE_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(setup_proof_context_hash),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned16(roster_position),
            CanonicalItem::unsigned32(batch_schedule_position),
            canonical_hash_list_values(anchor_commitment_roots)?,
            canonical_galois_key_share_entries(ordered_contribution_roots)?,
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_application_statement(
        &canonical_bytes,
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(batch_schedule_position),
            None,
        ),
    )?;
    Ok(canonical_bytes)
}

pub(crate) fn canonical_selected_relinearization_round_one_aggregate_statement(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    ordered_source_root_pairs: &[[[u8; Hash512::BYTE_LENGTH]; 2]],
    aggregate_left_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_right_root: [u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if ordered_source_root_pairs.len() != usize::from(FOUNDATION_PROFILE.participant_count) {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let source_pair_items = ordered_source_root_pairs
        .iter()
        .map(|[left_root, right_root]| {
            CanonicalItem::nested_tuple(&CanonicalTuple::new(
                ROUND_ONE_SOURCE_ROOT_PAIR_SCHEMA_IDENTIFIER,
                APPLICATION_STATEMENT_SCHEMA_VERSION,
                vec![
                    CanonicalItem::hash512(*left_root),
                    CanonicalItem::hash512(*right_root),
                ],
            ))
            .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(setup_proof_context_hash),
            CanonicalItem::unsigned32(schedule_position),
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &source_pair_items)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
            CanonicalItem::hash512(aggregate_left_root),
            CanonicalItem::hash512(aggregate_right_root),
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_relinearization_round_one_aggregate_statement(
        &canonical_bytes,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(schedule_position),
            None,
        ),
    )?;
    Ok(canonical_bytes)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn canonical_selected_relinearization_round_one_statement(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: &[[u8; Hash512::BYTE_LENGTH]],
    round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    round_one_right_root: [u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if schedule_position != selected_relinearization_statement_schedule_position()? {
        return Err(SelectedApplicationStatementError::InvalidProfile);
    }
    if roster_position >= FOUNDATION_PROFILE.participant_count {
        return Err(SelectedApplicationStatementError::WrongValue);
    }
    if anchor_commitment_roots.len() != 3 {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(setup_proof_context_hash),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned16(roster_position),
            CanonicalItem::unsigned32(schedule_position),
            canonical_hash_list_values(anchor_commitment_roots)?,
            CanonicalItem::hash512(round_one_left_root),
            CanonicalItem::hash512(round_one_right_root),
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_relinearization_round_one_statement(
        &canonical_bytes,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(schedule_position),
            None,
        ),
    )?;
    Ok(canonical_bytes)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn canonical_selected_relinearization_round_two_statement(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    anchor_commitment_roots: &[[u8; Hash512::BYTE_LENGTH]],
    round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    round_one_right_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_round_one_left_root: [u8; Hash512::BYTE_LENGTH],
    aggregate_round_one_right_root: [u8; Hash512::BYTE_LENGTH],
    contribution_root: [u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if schedule_position != selected_relinearization_statement_schedule_position()? {
        return Err(SelectedApplicationStatementError::InvalidProfile);
    }
    if roster_position >= FOUNDATION_PROFILE.participant_count {
        return Err(SelectedApplicationStatementError::WrongValue);
    }
    if anchor_commitment_roots.len() != 3 {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(setup_proof_context_hash),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned16(roster_position),
            CanonicalItem::unsigned32(schedule_position),
            canonical_hash_list_values(anchor_commitment_roots)?,
            CanonicalItem::hash512(round_one_left_root),
            CanonicalItem::hash512(round_one_right_root),
            CanonicalItem::hash512(aggregate_round_one_left_root),
            CanonicalItem::hash512(aggregate_round_one_right_root),
            CanonicalItem::hash512(contribution_root),
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_relinearization_round_two_statement(
        &canonical_bytes,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(schedule_position),
            None,
        ),
    )?;
    Ok(canonical_bytes)
}

pub(crate) fn canonical_selected_evaluator_aggregate_statement(
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    top_count: u16,
    ordered_entries: &[SelectedEvaluatorAggregateEntryInput<'_>],
    evaluator_key_store_digest: [u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    let positions = selected_evaluator_entry_positions(top_count)?;
    if ordered_entries.len() != positions.len() || ordered_entries.is_empty() {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let entry_items = positions
        .iter()
        .zip(ordered_entries)
        .map(|(position, entry)| {
            if entry.source_component_roots.len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
            {
                return Err(SelectedApplicationStatementError::WrongTypeOrLength);
            }
            let source_roots = entry
                .source_component_roots
                .iter()
                .copied()
                .map(CanonicalItem::hash512)
                .collect::<Vec<_>>();
            let aggregate_roots = [
                CanonicalItem::hash512(entry.runtime_component_root),
                CanonicalItem::hash512(entry.auxiliary_component_root),
            ];
            CanonicalItem::nested_tuple(&CanonicalTuple::new(
                EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER,
                APPLICATION_STATEMENT_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(position.schedule_position),
                    CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &source_roots)
                        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
                    CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &aggregate_roots)
                        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
                ],
            ))
            .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(setup_proof_context_hash),
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &entry_items)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
            CanonicalItem::hash512(evaluator_key_store_digest),
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_application_statement(
        &canonical_bytes,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            None,
            Some(top_count),
        ),
    )?;
    Ok(canonical_bytes)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn canonical_selected_target_share_statement(
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    finality_hash: [u8; Hash512::BYTE_LENGTH],
    reservation_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    ordered_aggregate_threshold_roots: &[[u8; Hash512::BYTE_LENGTH]],
    target_identifier_descriptor: &StreamDescriptor,
    target_order_descriptor: &StreamDescriptor,
) -> Result<Vec<u8>, SelectedApplicationStatementError> {
    if roster_position >= FOUNDATION_PROFILE.participant_count
        || ordered_aggregate_threshold_roots.len() != selected_target_share_root_count()?
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let canonical_bytes = CanonicalTuple::new(
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        APPLICATION_STATEMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(protocol_version),
            CanonicalItem::hash512(suite_identifier),
            CanonicalItem::hash512(ceremony_context_hash),
            CanonicalItem::hash512(action_context_hash),
            CanonicalItem::hash512(roster_hash),
            CanonicalItem::hash512(verified_setup_source_hash),
            CanonicalItem::hash512(finality_hash),
            CanonicalItem::hash512(reservation_intent_object_hash),
            CanonicalItem::participant_identity(participant_identity),
            CanonicalItem::unsigned16(roster_position),
            canonical_hash_list_values(ordered_aggregate_threshold_roots)?,
            canonical_stream_descriptor_value(target_identifier_descriptor)?,
            canonical_stream_descriptor_value(target_order_descriptor)?,
        ],
    )
    .encode()
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    decode_selected_application_statement(
        &canonical_bytes,
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(protocol_version, suite_identifier, None, None),
    )?;
    Ok(canonical_bytes)
}

fn canonical_stream_descriptor_value(
    descriptor: &StreamDescriptor,
) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    let canonical_descriptor = CanonicalTuple::decode(
        &descriptor
            .encode()
            .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    CanonicalItem::nested_tuple(&canonical_descriptor)
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
}

fn validate_selected_application_statement(
    statement: &CanonicalTuple,
    expected_schema_identifier: u16,
    context: SelectedApplicationStatementContext,
) -> Result<(), SelectedApplicationStatementError> {
    if statement.schema_identifier != expected_schema_identifier
        || statement.schema_version
            != selected_application_statement_schema_version(expected_schema_identifier)
    {
        return Err(SelectedApplicationStatementError::WrongSchema);
    }
    let fields = selected_statement_field_shapes(expected_schema_identifier, context)?;
    if statement.items.len() != fields.len() {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    for (item, field) in statement.items.iter().zip(fields.iter()) {
        validate_statement_field(item, field)?;
    }
    Ok(())
}

fn selected_statement_field_shapes(
    schema_identifier: u16,
    context: SelectedApplicationStatementContext,
) -> Result<Vec<StatementFieldShape>, SelectedApplicationStatementError> {
    let hash = StatementFieldShape::Hash;
    let exact_suite = StatementFieldShape::ExactHash(context.suite_identifier);
    let participant = StatementFieldShape::ParticipantIdentity;
    let roster_position = StatementFieldShape::RosterPosition;
    let protocol_version = StatementFieldShape::ExactUnsigned16(context.protocol_version);
    let schedule_position = || {
        context
            .schedule_position
            .map(StatementFieldShape::ExactUnsigned32)
            .ok_or(SelectedApplicationStatementError::InvalidProfile)
    };
    let top_count = || {
        context
            .top_count
            .filter(|top_count| (1..=FOUNDATION_PROFILE.option_count).contains(top_count))
            .ok_or(SelectedApplicationStatementError::InvalidProfile)
    };
    let require_no_schedule = || {
        if context.schedule_position.is_some() {
            Err(SelectedApplicationStatementError::InvalidProfile)
        } else {
            Ok(())
        }
    };
    let require_no_top_count = || {
        if context.top_count.is_some() {
            Err(SelectedApplicationStatementError::InvalidProfile)
        } else {
            Ok(())
        }
    };

    let fields = match schema_identifier {
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                protocol_version,
                exact_suite,
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::HashList(vss_coefficient_material_root_count()?),
                StatementFieldShape::HashList(vss_recipient_share_material_root_count()?),
            ]
        }
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                protocol_version,
                exact_suite,
                hash.clone(),
                hash.clone(),
                hash.clone(),
                participant,
                roster_position,
                hash.clone(),
                StatementFieldShape::HashList(vss_recipient_share_material_root_count()?),
                StatementFieldShape::HashList(selected_sharing_limb_count()?),
            ]
        }
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::HashList(selected_sharing_limb_count()?),
                StatementFieldShape::HashList(3),
            ]
        }
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::HashList(3),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                hash.clone(),
                StatementFieldShape::HashList(usize::from(
                    FOUNDATION_PROFILE.participant_count,
                )),
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                schedule_position()?,
                StatementFieldShape::HashList(3),
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_top_count()?;
            vec![
                hash.clone(),
                schedule_position()?,
                StatementFieldShape::RoundOneSourceRootPairs(usize::from(
                    FOUNDATION_PROFILE.participant_count,
                )),
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_top_count()?;
            vec![
                hash.clone(),
                participant,
                roster_position,
                schedule_position()?,
                StatementFieldShape::HashList(3),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_top_count()?;
            let batch_schedule_position = context
                .schedule_position
                .ok_or(SelectedApplicationStatementError::InvalidProfile)?;
            if batch_schedule_position != SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION {
                return Err(SelectedApplicationStatementError::InvalidProfile);
            }
            vec![
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::ExactUnsigned32(batch_schedule_position),
                StatementFieldShape::HashList(3),
                StatementFieldShape::GaloisKeyShareEntries,
            ]
        }
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            vec![
                hash.clone(),
                StatementFieldShape::EvaluatorKeyAggregateEntries(
                    selected_evaluator_entry_positions(top_count()?)?,
                ),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            vec![
                protocol_version,
                exact_suite,
                hash.clone(),
                hash.clone(),
                hash.clone(),
                participant,
                StatementFieldShape::Unsigned64,
                hash.clone(),
                hash.clone(),
            ]
        }
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
            require_no_schedule()?;
            require_no_top_count()?;
            let target_stream_byte_length = u64::try_from(
                selected_target_partial_decryption_stream_byte_length()
                    .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?,
            )
            .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
            vec![
                protocol_version,
                exact_suite,
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                hash.clone(),
                participant,
                roster_position,
                StatementFieldShape::HashList(selected_target_share_root_count()?),
                StatementFieldShape::StreamDescriptor {
                    exact_total_byte_length: target_stream_byte_length,
                },
                StatementFieldShape::StreamDescriptor {
                    exact_total_byte_length: target_stream_byte_length,
                },
            ]
        }
        _ => return Err(SelectedApplicationStatementError::WrongSchema),
    };
    Ok(fields)
}

pub(crate) fn selected_evaluator_entry_positions(
    top_count: u16,
) -> Result<Vec<SelectedEvaluatorEntryPosition>, SelectedApplicationStatementError> {
    let key_positions = selected_evaluator_program_set()
        .and_then(|program| program.key_positions())
        .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
    let stream = key_positions
        .streams()
        .get(
            usize::from(top_count)
                .checked_sub(1)
                .ok_or(SelectedApplicationStatementError::InvalidProfile)?,
        )
        .filter(|stream| stream.top_count() == top_count)
        .ok_or(SelectedApplicationStatementError::InvalidProfile)?;
    let mut positions = Vec::new();
    positions
        .try_reserve_exact(
            stream
                .relinearization_catalog_levels()
                .len()
                .checked_add(stream.galois_catalog_positions().len())
                .ok_or(SelectedApplicationStatementError::CountOverflow)?,
        )
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    for level in stream.relinearization_catalog_levels() {
        let catalog_position = key_positions
            .relinearization_catalog_levels()
            .binary_search(level)
            .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
        positions.push(SelectedEvaluatorEntryPosition {
            key_kind: SelectedEvaluatorEntryKind::Relinearization {
                catalog_level: *level,
            },
            schedule_position: u32::try_from(catalog_position)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        });
    }
    for position in stream.galois_catalog_positions() {
        let catalog_position = key_positions
            .galois_catalog_positions()
            .binary_search(position)
            .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
        positions.push(SelectedEvaluatorEntryPosition {
            key_kind: SelectedEvaluatorEntryKind::Galois {
                galois_element: position.galois_element(),
                catalog_level: position.catalog_level(),
            },
            schedule_position: u32::try_from(catalog_position)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        });
    }
    Ok(positions)
}

/// Exact ordered Galois evaluator positions fixed by the selected suite.
///
/// This is deliberately independent of the action-selected evaluator stream:
/// setup generation covers the complete suite-fixed Galois schedule, while
/// `selected_evaluator_entry_positions` selects the entries used by one
/// action's `top_count`.
pub(crate) fn selected_evaluator_galois_entry_positions()
-> Result<Vec<SelectedEvaluatorEntryPosition>, SelectedApplicationStatementError> {
    let selected_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
    if selected_candidate.galois_key_schedule.is_empty() {
        return Err(SelectedApplicationStatementError::InvalidProfile);
    }
    let mut positions = Vec::new();
    positions
        .try_reserve_exact(selected_candidate.galois_key_schedule.len())
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    for (schedule_position, (galois_element, catalog_level)) in selected_candidate
        .galois_key_schedule
        .into_iter()
        .enumerate()
    {
        positions.push(SelectedEvaluatorEntryPosition {
            key_kind: SelectedEvaluatorEntryKind::Galois {
                galois_element,
                catalog_level,
            },
            schedule_position: u32::try_from(schedule_position)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        });
    }
    Ok(positions)
}

/// Exact ordered relinearization evaluator positions fixed by the selected
/// suite, independent of the subset used by any one action.
pub(crate) fn selected_evaluator_relinearization_entry_positions()
-> Result<Vec<SelectedEvaluatorEntryPosition>, SelectedApplicationStatementError> {
    let selected_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;
    if selected_candidate.relinearization_levels.is_empty() {
        return Err(SelectedApplicationStatementError::InvalidProfile);
    }
    let mut positions = Vec::new();
    positions
        .try_reserve_exact(selected_candidate.relinearization_levels.len())
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    for (schedule_position, catalog_level) in selected_candidate
        .relinearization_levels
        .into_iter()
        .enumerate()
    {
        positions.push(SelectedEvaluatorEntryPosition {
            key_kind: SelectedEvaluatorEntryKind::Relinearization { catalog_level },
            schedule_position: u32::try_from(schedule_position)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        });
    }
    Ok(positions)
}

pub(crate) fn selected_evaluator_entry_position(
    top_count: u16,
    entry_ordinal: u32,
) -> Result<SelectedEvaluatorEntryPosition, SelectedApplicationStatementError> {
    selected_evaluator_entry_positions(top_count)?
        .get(
            usize::try_from(entry_ordinal)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        )
        .copied()
        .ok_or(SelectedApplicationStatementError::InvalidProfile)
}

pub(crate) fn selected_galois_key_share_contribution_roots(
    statement: &CanonicalTuple,
) -> Result<Vec<[u8; Hash512::BYTE_LENGTH]>, SelectedApplicationStatementError> {
    validate_selected_application_statement(
        statement,
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION),
            None,
        ),
    )?;
    decode_galois_key_share_entries(&statement.items[5])
}

pub(crate) fn selected_evaluator_aggregate_entry_roots(
    statement: &CanonicalTuple,
    top_count: u16,
    entry_ordinal: u32,
) -> Result<SelectedEvaluatorAggregateEntryRoots, SelectedApplicationStatementError> {
    selected_evaluator_aggregate_entry_roots_in_order(statement, top_count)?
        .get(
            usize::try_from(entry_ordinal)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
        )
        .cloned()
        .ok_or(SelectedApplicationStatementError::InvalidProfile)
}

pub(crate) fn selected_evaluator_aggregate_entry_roots_in_order(
    statement: &CanonicalTuple,
    top_count: u16,
) -> Result<Vec<SelectedEvaluatorAggregateEntryRoots>, SelectedApplicationStatementError> {
    if statement.schema_identifier
        != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        || statement.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
        || statement.items.len() != 3
    {
        return Err(SelectedApplicationStatementError::WrongSchema);
    }
    let positions = selected_evaluator_entry_positions(top_count)?;
    let entries = decode_nested_tuple_list(&statement.items[1], positions.len())?;
    entries
        .iter()
        .zip(positions)
        .enumerate()
        .map(|(entry_ordinal, (entry, position))| {
            if entry.schema_identifier != EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER
                || entry.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
                || entry.items.len() != 3
                || read_unsigned32(&entry.items[0])? != position.schedule_position
            {
                return Err(SelectedApplicationStatementError::WrongSchema);
            }
            let source_component_roots = read_hash_list_values(
                &entry.items[1],
                usize::from(FOUNDATION_PROFILE.participant_count),
            )?;
            let aggregate_roots = read_hash_list_values(&entry.items[2], 2)?;
            Ok(SelectedEvaluatorAggregateEntryRoots {
                entry_ordinal: u32::try_from(entry_ordinal)
                    .map_err(|_| SelectedApplicationStatementError::CountOverflow)?,
                position,
                source_component_roots: source_component_roots.into_boxed_slice(),
                runtime_component_root: aggregate_roots[0],
                auxiliary_component_root: aggregate_roots[1],
            })
        })
        .collect()
}

fn vss_coefficient_material_root_count() -> Result<usize, SelectedApplicationStatementError> {
    selected_sharing_limb_count()?
        .checked_mul(usize::from(FOUNDATION_PROFILE.reconstruction_threshold))
        .ok_or(SelectedApplicationStatementError::CountOverflow)
}

fn vss_recipient_share_material_root_count() -> Result<usize, SelectedApplicationStatementError> {
    selected_sharing_limb_count()?
        .checked_mul(usize::from(FOUNDATION_PROFILE.participant_count))
        .ok_or(SelectedApplicationStatementError::CountOverflow)
}

fn canonical_item_for_statement_field(
    field: &StatementFieldShape,
) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    match field {
        StatementFieldShape::ExactUnsigned16(value) => Ok(CanonicalItem::unsigned16(*value)),
        StatementFieldShape::RosterPosition => Ok(CanonicalItem::unsigned16(0)),
        StatementFieldShape::ExactUnsigned32(value) => Ok(CanonicalItem::unsigned32(*value)),
        StatementFieldShape::Unsigned64 => Ok(CanonicalItem::unsigned64(0)),
        StatementFieldShape::Hash => Ok(CanonicalItem::hash512([0; Hash512::BYTE_LENGTH])),
        StatementFieldShape::ExactHash(value) => Ok(CanonicalItem::hash512(*value)),
        StatementFieldShape::ParticipantIdentity => Ok(CanonicalItem::participant_identity(
            [0; Hash512::BYTE_LENGTH],
        )),
        StatementFieldShape::HashList(count) => canonical_hash_list(*count),
        StatementFieldShape::RoundOneSourceRootPairs(count) => {
            let items = (0..*count)
                .map(|_| {
                    CanonicalItem::nested_tuple(&CanonicalTuple::new(
                        ROUND_ONE_SOURCE_ROOT_PAIR_SCHEMA_IDENTIFIER,
                        APPLICATION_STATEMENT_SCHEMA_VERSION,
                        vec![
                            CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]),
                            CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]),
                        ],
                    ))
                    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
                })
                .collect::<Result<Vec<_>, _>>()?;
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &items)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
        }
        StatementFieldShape::GaloisKeyShareEntries => {
            let placeholder_roots = vec![
                [0; Hash512::BYTE_LENGTH];
                selected_galois_key_share_schedule_positions()?.len()
            ];
            canonical_galois_key_share_entries(&placeholder_roots)
        }
        StatementFieldShape::EvaluatorKeyAggregateEntries(positions) => {
            let items = positions
                .iter()
                .map(|position| {
                    let tuple = CanonicalTuple::new(
                        EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER,
                        APPLICATION_STATEMENT_SCHEMA_VERSION,
                        vec![
                            CanonicalItem::unsigned32(position.schedule_position),
                            canonical_hash_list(usize::from(FOUNDATION_PROFILE.participant_count))?,
                            canonical_hash_list(2)?,
                        ],
                    );
                    CanonicalItem::nested_tuple(&tuple)
                        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
                })
                .collect::<Result<Vec<_>, _>>()?;
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &items)
                .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
        }
        StatementFieldShape::StreamDescriptor {
            exact_total_byte_length,
        } => canonical_stream_descriptor_item(*exact_total_byte_length),
    }
}

fn validate_statement_field(
    item: &CanonicalItem,
    field: &StatementFieldShape,
) -> Result<(), SelectedApplicationStatementError> {
    match field {
        StatementFieldShape::ExactUnsigned16(expected) => {
            if read_unsigned16(item)? != *expected {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
        StatementFieldShape::RosterPosition => {
            if read_unsigned16(item)? >= FOUNDATION_PROFILE.participant_count {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
        StatementFieldShape::ExactUnsigned32(expected) => {
            if read_unsigned32(item)? != *expected {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
        StatementFieldShape::Unsigned64 => {
            require_fixed_item(item, CanonicalItemType::Unsigned64, 8)?;
        }
        StatementFieldShape::Hash => {
            require_fixed_item(item, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
        }
        StatementFieldShape::ExactHash(expected) => {
            require_fixed_item(item, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
            if item.canonical_bytes() != expected {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
        StatementFieldShape::ParticipantIdentity => {
            require_fixed_item(
                item,
                CanonicalItemType::ParticipantIdentity,
                Hash512::BYTE_LENGTH,
            )?;
        }
        StatementFieldShape::HashList(expected_count) => {
            validate_hash_list(item, *expected_count)?;
        }
        StatementFieldShape::RoundOneSourceRootPairs(expected_count) => {
            let tuples = decode_nested_tuple_list(item, *expected_count)?;
            for tuple in tuples {
                if tuple.schema_identifier != ROUND_ONE_SOURCE_ROOT_PAIR_SCHEMA_IDENTIFIER
                    || tuple.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
                    || tuple.items.len() != 2
                {
                    return Err(SelectedApplicationStatementError::WrongSchema);
                }
                for root in &tuple.items {
                    require_fixed_item(root, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
                }
            }
        }
        StatementFieldShape::GaloisKeyShareEntries => {
            decode_galois_key_share_entries(item)?;
        }
        StatementFieldShape::EvaluatorKeyAggregateEntries(positions) => {
            let tuples = decode_nested_tuple_list(item, positions.len())?;
            for (tuple, position) in tuples.iter().zip(positions.iter()) {
                if tuple.schema_identifier != EVALUATOR_KEY_AGGREGATE_ENTRY_SCHEMA_IDENTIFIER
                    || tuple.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
                    || tuple.items.len() != 3
                {
                    return Err(SelectedApplicationStatementError::WrongSchema);
                }
                if read_unsigned32(&tuple.items[0])? != position.schedule_position {
                    return Err(SelectedApplicationStatementError::WrongValue);
                }
                validate_hash_list(
                    &tuple.items[1],
                    usize::from(FOUNDATION_PROFILE.participant_count),
                )?;
                // Runtime B is the only aggregated/proved component. The
                // second root is the linked RKG A or verifier-derived Galois A.
                validate_hash_list(&tuple.items[2], 2)?;
            }
        }
        StatementFieldShape::StreamDescriptor {
            exact_total_byte_length,
        } => {
            require_item_type(item, CanonicalItemType::NestedTuple)?;
            let descriptor =
                StreamDescriptor::decode(item.canonical_bytes(), &CanonicalDecodeLimits::default())
                    .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?;
            if descriptor.total_byte_length != *exact_total_byte_length {
                return Err(SelectedApplicationStatementError::WrongValue);
            }
        }
    }
    Ok(())
}

fn canonical_hash_list(count: usize) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    let items = vec![CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]); count];
    CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &items)
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
}

fn canonical_hash_list_values(
    values: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    let items = values
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &items)
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
}

fn canonical_galois_key_share_entries(
    ordered_contribution_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    let selected_schedule_positions = selected_galois_key_share_schedule_positions()?;
    if ordered_contribution_roots.len() != selected_schedule_positions.len() {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let entries = ordered_contribution_roots
        .iter()
        .copied()
        .zip(selected_schedule_positions)
        .map(|(contribution_root, schedule_position)| {
            CanonicalItem::nested_tuple(&CanonicalTuple::new(
                GALOIS_KEY_SHARE_ENTRY_SCHEMA_IDENTIFIER,
                APPLICATION_STATEMENT_SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(schedule_position),
                    CanonicalItem::hash512(contribution_root),
                ],
            ))
            .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &entries)
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
}

fn decode_galois_key_share_entries(
    item: &CanonicalItem,
) -> Result<Vec<[u8; Hash512::BYTE_LENGTH]>, SelectedApplicationStatementError> {
    let selected_schedule_positions = selected_galois_key_share_schedule_positions()?;
    let entries = decode_nested_tuple_list(item, selected_schedule_positions.len())?;
    let mut contribution_roots = Vec::new();
    contribution_roots
        .try_reserve_exact(selected_schedule_positions.len())
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    for (expected_schedule_position, entry) in
        selected_schedule_positions.into_iter().zip(entries.iter())
    {
        if entry.schema_identifier != GALOIS_KEY_SHARE_ENTRY_SCHEMA_IDENTIFIER
            || entry.schema_version != APPLICATION_STATEMENT_SCHEMA_VERSION
            || entry.items.len() != 2
        {
            return Err(SelectedApplicationStatementError::WrongSchema);
        }
        if read_unsigned32(&entry.items[0])? != expected_schedule_position {
            return Err(SelectedApplicationStatementError::WrongValue);
        }
        require_fixed_item(
            &entry.items[1],
            CanonicalItemType::Hash512,
            Hash512::BYTE_LENGTH,
        )?;
        contribution_roots.push(
            entry.items[1]
                .canonical_bytes()
                .try_into()
                .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?,
        );
    }
    Ok(contribution_roots)
}

fn canonical_stream_descriptor_item(
    total_byte_length: u64,
) -> Result<CanonicalItem, SelectedApplicationStatementError> {
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    let chunk_count = total_byte_length
        .checked_sub(1)
        .and_then(|length| length.checked_div(chunk_byte_length))
        .and_then(|count| count.checked_add(1))
        .ok_or(SelectedApplicationStatementError::CountOverflow)?;
    let descriptor = StreamDescriptor::new(
        total_byte_length,
        vec![
            Hash512::from_bytes([0; Hash512::BYTE_LENGTH]);
            usize::try_from(chunk_count)
                .map_err(|_| SelectedApplicationStatementError::CountOverflow)?
        ],
        Hash512::from_bytes([0; Hash512::BYTE_LENGTH]),
    )
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    let descriptor_tuple = CanonicalTuple::decode(
        &descriptor
            .encode()
            .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
    CanonicalItem::nested_tuple(&descriptor_tuple)
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)
}

fn require_item_type(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
) -> Result<(), SelectedApplicationStatementError> {
    if item.item_type() != expected_type {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    Ok(())
}

fn require_fixed_item(
    item: &CanonicalItem,
    expected_type: CanonicalItemType,
    expected_byte_length: usize,
) -> Result<(), SelectedApplicationStatementError> {
    require_item_type(item, expected_type)?;
    if item.canonical_bytes().len() != expected_byte_length {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    Ok(())
}

fn read_unsigned16(item: &CanonicalItem) -> Result<u16, SelectedApplicationStatementError> {
    require_fixed_item(item, CanonicalItemType::Unsigned16, 2)?;
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?,
    ))
}

fn read_unsigned32(item: &CanonicalItem) -> Result<u32, SelectedApplicationStatementError> {
    require_fixed_item(item, CanonicalItemType::Unsigned32, 4)?;
    Ok(u32::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?,
    ))
}

fn read_unsigned64(item: &CanonicalItem) -> Result<u64, SelectedApplicationStatementError> {
    require_fixed_item(item, CanonicalItemType::Unsigned64, 8)?;
    Ok(u64::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)?,
    ))
}

fn read_hash(
    item: &CanonicalItem,
) -> Result<[u8; Hash512::BYTE_LENGTH], SelectedApplicationStatementError> {
    require_fixed_item(item, CanonicalItemType::Hash512, Hash512::BYTE_LENGTH)?;
    item.canonical_bytes()
        .try_into()
        .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)
}

fn read_participant_identity(
    item: &CanonicalItem,
) -> Result<[u8; Hash512::BYTE_LENGTH], SelectedApplicationStatementError> {
    require_fixed_item(
        item,
        CanonicalItemType::ParticipantIdentity,
        Hash512::BYTE_LENGTH,
    )?;
    item.canonical_bytes()
        .try_into()
        .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)
}

fn validate_hash_list(
    item: &CanonicalItem,
    expected_count: usize,
) -> Result<(), SelectedApplicationStatementError> {
    let (count, payload) = read_list_header(item, CanonicalItemType::Hash512)?;
    if count != expected_count
        || payload.len()
            != count
                .checked_mul(Hash512::BYTE_LENGTH)
                .ok_or(SelectedApplicationStatementError::CountOverflow)?
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    Ok(())
}

fn read_hash_list_values(
    item: &CanonicalItem,
    expected_count: usize,
) -> Result<Vec<[u8; Hash512::BYTE_LENGTH]>, SelectedApplicationStatementError> {
    validate_hash_list(item, expected_count)?;
    let (_, payload) = read_list_header(item, CanonicalItemType::Hash512)?;
    payload
        .chunks_exact(Hash512::BYTE_LENGTH)
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| SelectedApplicationStatementError::WrongTypeOrLength)
        })
        .collect()
}

fn decode_nested_tuple_list(
    item: &CanonicalItem,
    expected_count: usize,
) -> Result<Vec<CanonicalTuple>, SelectedApplicationStatementError> {
    let (count, payload) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if count != expected_count {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let mut tuples = Vec::new();
    tuples
        .try_reserve_exact(count)
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    let mut offset = 0_usize;
    for _ in 0..count {
        let tuple_byte_length = encoded_tuple_byte_length(
            payload
                .get(offset..)
                .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?,
        )?;
        let next_offset = offset
            .checked_add(tuple_byte_length)
            .ok_or(SelectedApplicationStatementError::CountOverflow)?;
        let tuple = CanonicalTuple::decode(
            payload
                .get(offset..next_offset)
                .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?,
            &CanonicalDecodeLimits::default(),
        )
        .map_err(|_| SelectedApplicationStatementError::CanonicalEncoding)?;
        tuples.push(tuple);
        offset = next_offset;
    }
    if offset != payload.len() {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    Ok(tuples)
}

fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
) -> Result<(usize, &[u8]), SelectedApplicationStatementError> {
    require_item_type(item, CanonicalItemType::HomogeneousList)?;
    let bytes = item.canonical_bytes();
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_element_type.canonical_code()
    {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let count = usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    Ok((count, &bytes[6..]))
}

fn encoded_tuple_byte_length(bytes: &[u8]) -> Result<usize, SelectedApplicationStatementError> {
    if bytes.len() < 8 {
        return Err(SelectedApplicationStatementError::WrongTypeOrLength);
    }
    let item_count = usize::try_from(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let header = bytes
            .get(offset..offset + 6)
            .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?;
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([header[0], header[1]]))
            .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?;
        let item_byte_length = usize::try_from(u32::from_le_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .map_err(|_| SelectedApplicationStatementError::CountOverflow)?;
        offset = offset
            .checked_add(6)
            .and_then(|value| value.checked_add(item_byte_length))
            .filter(|value| *value <= bytes.len())
            .ok_or(SelectedApplicationStatementError::WrongTypeOrLength)?;
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_partial_descriptor(seed: u8, total_byte_length: u64) -> StreamDescriptor {
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length as u64;
        let chunk_count = usize::try_from(1 + (total_byte_length - 1) / chunk_byte_length)
            .expect("target chunk count fits usize");
        StreamDescriptor::new(
            total_byte_length,
            (0..chunk_count)
                .map(|chunk_index| Hash512::from_bytes([seed.wrapping_add(chunk_index as u8); 64]))
                .collect(),
            Hash512::from_bytes([seed.wrapping_add(0x40); 64]),
        )
        .expect("target descriptor is structurally valid")
    }

    fn selected_galois_key_share_entry_count() -> usize {
        selected_galois_key_share_schedule_positions()
            .expect("selected Galois key-share schedule")
            .len()
    }

    #[test]
    fn typed_vss_statement_retains_the_exact_all_limb_inventory_and_public_seed() {
        let suite_identifier = [0x21; Hash512::BYTE_LENGTH];
        let coefficient_root_count =
            vss_coefficient_material_root_count().expect("selected coefficient root count");
        let recipient_root_count =
            vss_recipient_share_material_root_count().expect("selected recipient root count");
        let ordered_coefficient_roots = (0..coefficient_root_count)
            .map(|root_ordinal| [root_ordinal as u8; Hash512::BYTE_LENGTH])
            .collect::<Vec<_>>();
        let ordered_recipient_roots = (0..recipient_root_count)
            .map(|root_ordinal| [0x80_u8.wrapping_add(root_ordinal as u8); Hash512::BYTE_LENGTH])
            .collect::<Vec<_>>();
        let canonical_bytes = canonical_selected_vss_share_linkage_statement(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            [0x22; Hash512::BYTE_LENGTH],
            [0x23; Hash512::BYTE_LENGTH],
            [0x24; Hash512::BYTE_LENGTH],
            [0x25; Hash512::BYTE_LENGTH],
            [0x26; Hash512::BYTE_LENGTH],
            FOUNDATION_PROFILE.participant_count - 1,
            &ordered_coefficient_roots,
            &ordered_recipient_roots,
        )
        .expect("canonical VSS statement encodes and validates");
        let decoded = decode_selected_vss_share_linkage_statement(
            &canonical_bytes,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                suite_identifier,
                None,
                None,
            ),
        )
        .expect("VSS statement decodes");

        assert_eq!(
            coefficient_root_count,
            selected_sharing_limb_count().expect("selected sharing limb count")
                * usize::from(FOUNDATION_PROFILE.reconstruction_threshold)
        );
        assert_eq!(
            recipient_root_count,
            selected_sharing_limb_count().expect("selected sharing limb count")
                * usize::from(FOUNDATION_PROFILE.participant_count)
        );
        assert_eq!(decoded.public_setup_seed(), [0x25; Hash512::BYTE_LENGTH]);
        assert_eq!(
            decoded.ordered_coefficient_material_roots(),
            ordered_coefficient_roots
        );
        assert_eq!(
            decoded.ordered_recipient_share_material_roots(),
            ordered_recipient_roots
        );

        assert!(matches!(
            canonical_selected_vss_share_linkage_statement(
                FOUNDATION_PROFILE.protocol_version,
                suite_identifier,
                [0x22; Hash512::BYTE_LENGTH],
                [0x23; Hash512::BYTE_LENGTH],
                [0x24; Hash512::BYTE_LENGTH],
                [0x25; Hash512::BYTE_LENGTH],
                [0x26; Hash512::BYTE_LENGTH],
                FOUNDATION_PROFILE.participant_count - 1,
                &ordered_coefficient_roots[..ordered_coefficient_roots.len() - 1],
                &ordered_recipient_roots,
            ),
            Err(SelectedApplicationStatementError::WrongTypeOrLength)
        ));
    }

    #[test]
    fn typed_collective_public_key_statement_retains_the_proof_bound_root_and_digest() {
        let ordered_share_roots = (0..FOUNDATION_PROFILE.participant_count)
            .map(|participant_ordinal| [0x20_u8.wrapping_add(participant_ordinal as u8); 64])
            .collect::<Vec<_>>();
        let canonical_bytes = CanonicalTuple::new(
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            APPLICATION_STATEMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512([0x11; 64]),
                canonical_hash_list_values(&ordered_share_roots)
                    .expect("public-key share roots"),
                CanonicalItem::hash512([0x41; 64]),
                CanonicalItem::hash512([0x42; 64]),
            ],
        )
        .encode()
        .expect("collective public-key statement");
        let statement = decode_selected_collective_public_key_aggregate_statement(
            &canonical_bytes,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0x51; 64],
                None,
                None,
            ),
        )
        .expect("selected collective public-key statement");
        assert_eq!(statement.setup_proof_context_hash(), [0x11; 64]);
        assert_eq!(
            statement.ordered_public_key_share_roots(),
            ordered_share_roots
        );
        assert_eq!(statement.collective_public_key_root(), [0x41; 64]);
        assert_eq!(
            statement.collective_public_key_full_object_digest(),
            [0x42; 64]
        );

        let incomplete_statement = CanonicalTuple::new(
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            APPLICATION_STATEMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512([0x11; 64]),
                canonical_hash_list_values(
                    &ordered_share_roots[..ordered_share_roots.len() - 1],
                )
                .expect("incomplete public-key share roots"),
                CanonicalItem::hash512([0x41; 64]),
                CanonicalItem::hash512([0x42; 64]),
            ],
        )
        .encode()
        .expect("incomplete collective public-key statement");
        assert_eq!(
            decode_selected_collective_public_key_aggregate_statement(
                &incomplete_statement,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0x51; 64],
                    None,
                    None,
                ),
            ),
            Err(SelectedApplicationStatementError::WrongTypeOrLength)
        );
    }

    #[test]
    fn typed_aggregate_threshold_statement_retains_every_release_binding() {
        let suite_identifier = [0x12; 64];
        let ordered_source_roots = (0..vss_recipient_share_material_root_count()
            .expect("selected source root count"))
            .map(|root_ordinal| [0x30_u8.wrapping_add(root_ordinal as u8); 64])
            .collect::<Vec<_>>();
        let ordered_aggregate_roots = (0..selected_sharing_limb_count()
            .expect("selected sharing limb count"))
            .map(|modulus_ordinal| [0x80_u8.wrapping_add(modulus_ordinal as u8); 64])
            .collect::<Vec<_>>();
        let canonical_bytes = canonical_selected_aggregate_threshold_share_statement(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            [0x21; 64],
            [0x22; 64],
            [0x23; 64],
            [0x24; 64],
            FOUNDATION_PROFILE.participant_count - 1,
            [0x25; 64],
            &ordered_source_roots,
            &ordered_aggregate_roots,
        )
        .expect("aggregate threshold-share statement");
        let statement = decode_selected_aggregate_threshold_share_statement(
            &canonical_bytes,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                suite_identifier,
                None,
                None,
            ),
        )
        .expect("selected aggregate threshold-share statement");
        assert_eq!(
            statement.protocol_version(),
            FOUNDATION_PROFILE.protocol_version
        );
        assert_eq!(statement.suite_identifier(), suite_identifier);
        assert_eq!(statement.ceremony_context_hash(), [0x21; 64]);
        assert_eq!(statement.action_context_hash(), [0x22; 64]);
        assert_eq!(statement.roster_hash(), [0x23; 64]);
        assert_eq!(statement.participant_identity(), [0x24; 64]);
        assert_eq!(
            statement.roster_position(),
            FOUNDATION_PROFILE.participant_count - 1
        );
        assert_eq!(statement.recipient_input_root(), [0x25; 64]);
        assert_eq!(statement.ordered_source_share_roots(), ordered_source_roots);
        assert_eq!(
            statement.ordered_aggregate_threshold_roots(),
            ordered_aggregate_roots
        );

        assert_eq!(
            decode_selected_aggregate_threshold_share_statement(
                &canonical_bytes,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0x13; 64],
                    None,
                    None,
                ),
            ),
            Err(SelectedApplicationStatementError::WrongValue)
        );

        assert!(matches!(
            canonical_selected_aggregate_threshold_share_statement(
                FOUNDATION_PROFILE.protocol_version,
                suite_identifier,
                [0x21; 64],
                [0x22; 64],
                [0x23; 64],
                [0x24; 64],
                FOUNDATION_PROFILE.participant_count - 1,
                [0x25; 64],
                &ordered_source_roots[..ordered_source_roots.len() - 1],
                &ordered_aggregate_roots,
            ),
            Err(SelectedApplicationStatementError::WrongTypeOrLength)
        ));
        assert!(matches!(
            canonical_selected_aggregate_threshold_share_statement(
                FOUNDATION_PROFILE.protocol_version,
                suite_identifier,
                [0x21; 64],
                [0x22; 64],
                [0x23; 64],
                [0x24; 64],
                FOUNDATION_PROFILE.participant_count,
                [0x25; 64],
                &ordered_source_roots,
                &ordered_aggregate_roots,
            ),
            Err(SelectedApplicationStatementError::WrongTypeOrLength)
        ));
    }

    #[test]
    fn typed_target_share_statement_binds_active_release_roots_and_exact_streams() {
        let target_byte_length = u64::try_from(
            selected_target_partial_decryption_stream_byte_length()
                .expect("selected target stream length"),
        )
        .expect("selected target stream length fits u64");
        let target_identifier_descriptor = target_partial_descriptor(0x61, target_byte_length);
        let target_order_descriptor = target_partial_descriptor(0x71, target_byte_length);
        let target_root_count = selected_target_share_root_count()
            .expect("selected target root count resolves from suite coordinates");
        let ordered_roots = (0..target_root_count)
            .map(|modulus_index| [0x80_u8.wrapping_add(modulus_index as u8); 64])
            .collect::<Vec<_>>();
        let canonical_bytes = canonical_selected_target_share_statement(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; 64],
            [0x21; 64],
            [0x22; 64],
            [0x23; 64],
            [0x24; 64],
            [0x25; 64],
            [0x26; 64],
            [0x27; 64],
            FOUNDATION_PROFILE.participant_count - 1,
            &ordered_roots,
            &target_identifier_descriptor,
            &target_order_descriptor,
        )
        .expect("typed target-share statement");
        let decoded = decode_selected_application_statement(
            &canonical_bytes,
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0x11; 64],
                None,
                None,
            ),
        )
        .expect("typed target-share statement decodes");
        assert_eq!(decoded.items.len(), 13);
        assert_eq!(
            read_hash_list_values(&decoded.items[10], target_root_count),
            Ok(ordered_roots.clone())
        );

        let changed_finality = canonical_selected_target_share_statement(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; 64],
            [0x21; 64],
            [0x22; 64],
            [0x23; 64],
            [0x24; 64],
            [0x35; 64],
            [0x26; 64],
            [0x27; 64],
            FOUNDATION_PROFILE.participant_count - 1,
            &ordered_roots,
            &target_identifier_descriptor,
            &target_order_descriptor,
        )
        .expect("changed finality statement");
        assert_ne!(canonical_bytes, changed_finality);

        let mut changed_roots = ordered_roots.clone();
        changed_roots[2][0] ^= 0x01;
        let changed_root_statement = canonical_selected_target_share_statement(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; 64],
            [0x21; 64],
            [0x22; 64],
            [0x23; 64],
            [0x24; 64],
            [0x25; 64],
            [0x26; 64],
            [0x27; 64],
            FOUNDATION_PROFILE.participant_count - 1,
            &changed_roots,
            &target_identifier_descriptor,
            &target_order_descriptor,
        )
        .expect("changed active root statement");
        assert_ne!(canonical_bytes, changed_root_statement);

        let mut reordered_roots = ordered_roots.clone();
        reordered_roots.swap(1, 2);
        let reordered_root_statement = canonical_selected_target_share_statement(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; 64],
            [0x21; 64],
            [0x22; 64],
            [0x23; 64],
            [0x24; 64],
            [0x25; 64],
            [0x26; 64],
            [0x27; 64],
            FOUNDATION_PROFILE.participant_count - 1,
            &reordered_roots,
            &target_identifier_descriptor,
            &target_order_descriptor,
        )
        .expect("reordered active root statement");
        assert_ne!(canonical_bytes, reordered_root_statement);

        assert!(
            canonical_selected_target_share_statement(
                FOUNDATION_PROFILE.protocol_version,
                [0x11; 64],
                [0x21; 64],
                [0x22; 64],
                [0x23; 64],
                [0x24; 64],
                [0x25; 64],
                [0x26; 64],
                [0x27; 64],
                0,
                &ordered_roots[..ordered_roots.len() - 1],
                &target_identifier_descriptor,
                &target_order_descriptor,
            )
            .is_err(),
            "a short active-root list must refuse",
        );
        let mut extended_roots = ordered_roots.clone();
        extended_roots.push([0xff; 64]);
        assert!(
            canonical_selected_target_share_statement(
                FOUNDATION_PROFILE.protocol_version,
                [0x11; 64],
                [0x21; 64],
                [0x22; 64],
                [0x23; 64],
                [0x24; 64],
                [0x25; 64],
                [0x26; 64],
                [0x27; 64],
                0,
                &extended_roots,
                &target_identifier_descriptor,
                &target_order_descriptor,
            )
            .is_err(),
            "an extended active-root list must refuse",
        );
        let wrong_length_descriptor = target_partial_descriptor(0x61, target_byte_length + 1);
        assert!(
            canonical_selected_target_share_statement(
                FOUNDATION_PROFILE.protocol_version,
                [0x11; 64],
                [0x21; 64],
                [0x22; 64],
                [0x23; 64],
                [0x24; 64],
                [0x25; 64],
                [0x26; 64],
                [0x27; 64],
                0,
                &ordered_roots,
                &wrong_length_descriptor,
                &target_order_descriptor,
            )
            .is_err(),
            "a non-selected target stream length must refuse",
        );
    }

    #[test]
    fn relinearization_round_two_constructor_retains_each_cross_round_binding() {
        let schedule_position = selected_relinearization_statement_schedule_position()
            .expect("selected relinearization position");
        let wrong_schedule_position = schedule_position
            .checked_add(1)
            .expect("selected schedule position has a successor");
        let anchor_commitment_roots = [
            [0x15; Hash512::BYTE_LENGTH],
            [0x16; Hash512::BYTE_LENGTH],
            [0x17; Hash512::BYTE_LENGTH],
        ];
        let canonical_bytes = canonical_selected_relinearization_round_two_statement(
            [0x11; Hash512::BYTE_LENGTH],
            [0x12; Hash512::BYTE_LENGTH],
            FOUNDATION_PROFILE.participant_count - 1,
            schedule_position,
            &anchor_commitment_roots,
            [0x21; Hash512::BYTE_LENGTH],
            [0x22; Hash512::BYTE_LENGTH],
            [0x23; Hash512::BYTE_LENGTH],
            [0x24; Hash512::BYTE_LENGTH],
            [0x25; Hash512::BYTE_LENGTH],
        )
        .expect("canonical round-two statement");
        let context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x31; Hash512::BYTE_LENGTH],
            Some(schedule_position),
            None,
        );

        let decoded =
            decode_selected_relinearization_round_two_statement(&canonical_bytes, context)
                .expect("selected round-two statement");
        assert_eq!(
            decoded.setup_proof_context_hash(),
            [0x11; Hash512::BYTE_LENGTH]
        );
        assert_eq!(decoded.participant_identity(), [0x12; Hash512::BYTE_LENGTH]);
        assert_eq!(
            decoded.roster_position(),
            FOUNDATION_PROFILE.participant_count - 1
        );
        assert_eq!(decoded.schedule_position(), schedule_position);
        assert_eq!(decoded.anchor_commitment_roots(), anchor_commitment_roots);
        assert_eq!(decoded.round_one_left_root(), [0x21; Hash512::BYTE_LENGTH]);
        assert_eq!(decoded.round_one_right_root(), [0x22; Hash512::BYTE_LENGTH]);
        assert_eq!(
            decoded.aggregate_round_one_left_root(),
            [0x23; Hash512::BYTE_LENGTH]
        );
        assert_eq!(
            decoded.aggregate_round_one_right_root(),
            [0x24; Hash512::BYTE_LENGTH]
        );
        assert_eq!(decoded.contribution_root(), [0x25; Hash512::BYTE_LENGTH]);

        let wrong_schedule_context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x31; Hash512::BYTE_LENGTH],
            Some(wrong_schedule_position),
            None,
        );
        assert_eq!(
            decode_selected_relinearization_round_two_statement(
                &canonical_bytes,
                wrong_schedule_context,
            ),
            Err(SelectedApplicationStatementError::WrongValue)
        );

        assert_eq!(
            canonical_selected_relinearization_round_two_statement(
                [0x11; Hash512::BYTE_LENGTH],
                [0x12; Hash512::BYTE_LENGTH],
                FOUNDATION_PROFILE.participant_count - 1,
                wrong_schedule_position,
                &anchor_commitment_roots,
                [0x21; Hash512::BYTE_LENGTH],
                [0x22; Hash512::BYTE_LENGTH],
                [0x23; Hash512::BYTE_LENGTH],
                [0x24; Hash512::BYTE_LENGTH],
                [0x25; Hash512::BYTE_LENGTH],
            ),
            Err(SelectedApplicationStatementError::InvalidProfile)
        );
        assert_eq!(
            canonical_selected_relinearization_round_two_statement(
                [0x11; Hash512::BYTE_LENGTH],
                [0x12; Hash512::BYTE_LENGTH],
                FOUNDATION_PROFILE.participant_count - 1,
                schedule_position,
                &anchor_commitment_roots[..2],
                [0x21; Hash512::BYTE_LENGTH],
                [0x22; Hash512::BYTE_LENGTH],
                [0x23; Hash512::BYTE_LENGTH],
                [0x24; Hash512::BYTE_LENGTH],
                [0x25; Hash512::BYTE_LENGTH],
            ),
            Err(SelectedApplicationStatementError::WrongTypeOrLength)
        );

        let mut reordered_statement =
            CanonicalTuple::decode(&canonical_bytes, &CanonicalDecodeLimits::default())
                .expect("canonical round-two statement decodes as a tuple");
        reordered_statement.items.swap(1, 2);
        let reordered_bytes = reordered_statement
            .encode()
            .expect("reordered round-two tuple remains canonically encodable");
        assert_eq!(
            decode_selected_relinearization_round_two_statement(&reordered_bytes, context),
            Err(SelectedApplicationStatementError::WrongTypeOrLength)
        );
    }

    #[test]
    fn every_supported_statement_schema_uses_the_single_statement_owner() {
        let cases = [
            (
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
            ),
            (
                ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
            ),
            (
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
            ),
            (
                ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
            ),
            (
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                Some(FOUNDATION_PROFILE.option_count),
            ),
            (
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
            (
                ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
            ),
        ];
        for (schema_identifier, schedule_position, top_count) in cases {
            let context = SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0x5a; Hash512::BYTE_LENGTH],
                schedule_position,
                top_count,
            );
            let bytes =
                canonical_selected_application_statement_for_ceiling(schema_identifier, context)
                    .expect("statement encodes");
            let decoded = decode_selected_application_statement(&bytes, schema_identifier, context)
                .expect("statement decodes");
            assert_eq!(decoded.encode().expect("statement re-encodes"), bytes);
        }
    }

    #[test]
    fn selected_statement_decoder_rejects_truncation_and_wrong_context() {
        let context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x31; Hash512::BYTE_LENGTH],
            None,
            None,
        );
        let bytes = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("ballot statement");
        for truncated_length in [0, 1, 7, bytes.len() - 1] {
            assert!(
                decode_selected_application_statement(
                    &bytes[..truncated_length],
                    ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                    context,
                )
                .is_err()
            );
        }
        assert!(
            decode_selected_application_statement(
                &bytes,
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0x32; Hash512::BYTE_LENGTH],
                    None,
                    None,
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn ballot_statement_binds_exact_owner_setup_and_ciphertext() {
        let protocol_version = FOUNDATION_PROFILE.protocol_version;
        let suite_identifier = [0x31; Hash512::BYTE_LENGTH];
        let ceremony_context_hash = [0x32; Hash512::BYTE_LENGTH];
        let action_context_hash = [0x33; Hash512::BYTE_LENGTH];
        let roster_hash = [0x34; Hash512::BYTE_LENGTH];
        let participant_identity = [0x35; Hash512::BYTE_LENGTH];
        let producer_sequence = 0x0102_0304_0506_0708;
        let verified_setup_source_hash = [0x36; Hash512::BYTE_LENGTH];
        let ballot_ciphertext_full_object_digest = [0x37; Hash512::BYTE_LENGTH];
        let canonical_bytes = canonical_selected_ballot_validity_statement(
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            participant_identity,
            producer_sequence,
            verified_setup_source_hash,
            ballot_ciphertext_full_object_digest,
        )
        .expect("ballot statement encodes");
        let context = SelectedApplicationStatementContext::new(
            protocol_version,
            suite_identifier,
            None,
            None,
        );
        let statement = decode_selected_ballot_validity_statement(&canonical_bytes, context)
            .expect("ballot statement decodes");
        assert_eq!(statement.protocol_version(), protocol_version);
        assert_eq!(statement.suite_identifier(), suite_identifier);
        assert_eq!(statement.ceremony_context_hash(), ceremony_context_hash);
        assert_eq!(statement.action_context_hash(), action_context_hash);
        assert_eq!(statement.roster_hash(), roster_hash);
        assert_eq!(statement.participant_identity(), participant_identity);
        assert_eq!(statement.producer_sequence(), producer_sequence);
        assert_eq!(
            statement.verified_setup_source_hash(),
            verified_setup_source_hash
        );
        assert_eq!(
            statement.ballot_ciphertext_full_object_digest(),
            ballot_ciphertext_full_object_digest
        );

        let changed_ciphertext_statement = canonical_selected_ballot_validity_statement(
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            participant_identity,
            producer_sequence,
            verified_setup_source_hash,
            [0x38; Hash512::BYTE_LENGTH],
        )
        .expect("changed ballot statement encodes");
        assert_ne!(canonical_bytes, changed_ciphertext_statement);
    }

    #[test]
    fn galois_statement_uses_one_selected_batch_with_all_contribution_roots() {
        let context = selected_galois_statement_context();
        let bytes = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("Galois statement");
        let statement = decode_selected_application_statement(
            &bytes,
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("Galois statement decodes");
        assert_eq!(
            statement.schema_version,
            GALOIS_KEY_SHARE_STATEMENT_SCHEMA_VERSION
        );
        assert_eq!(read_unsigned32(&statement.items[3]), Ok(0));
        let selected_entry_count = selected_galois_key_share_entry_count();
        let entries = decode_nested_tuple_list(&statement.items[5], selected_entry_count)
            .expect("Galois entry list");
        assert_eq!(entries.len(), selected_entry_count);
        for (expected_schedule_position, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry.schema_identifier,
                GALOIS_KEY_SHARE_ENTRY_SCHEMA_IDENTIFIER
            );
            assert_eq!(entry.schema_version, APPLICATION_STATEMENT_SCHEMA_VERSION);
            assert_eq!(entry.items.len(), 2);
            assert_eq!(
                read_unsigned32(&entry.items[0]),
                Ok(u32::try_from(expected_schedule_position).expect("schedule position fits u32"))
            );
            assert_eq!(entry.items[1].item_type(), CanonicalItemType::Hash512);
        }

        assert_eq!(
            canonical_selected_application_statement_for_ceiling(
                ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0; Hash512::BYTE_LENGTH],
                    Some(1),
                    None,
                ),
            )
            .err(),
            Some(SelectedApplicationStatementError::InvalidProfile),
        );
    }

    #[test]
    fn galois_statement_rejects_the_aliased_version_one_batch_shape() {
        let context = selected_galois_statement_context();
        let bytes = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("Galois statement");
        let mut version_one_statement =
            CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("canonical Galois statement");
        version_one_statement.schema_version = APPLICATION_STATEMENT_SCHEMA_VERSION;
        let version_one_bytes = version_one_statement
            .encode()
            .expect("version-one alias encodes canonically");

        assert_galois_statement_error(
            &version_one_bytes,
            context,
            SelectedApplicationStatementError::WrongSchema,
        );
    }

    #[test]
    fn typed_galois_statement_constructor_and_extractor_bind_all_selected_roots() {
        let anchor_commitment_roots = [
            [0x31; Hash512::BYTE_LENGTH],
            [0x32; Hash512::BYTE_LENGTH],
            [0x33; Hash512::BYTE_LENGTH],
        ];
        let selected_entry_count = selected_galois_key_share_entry_count();
        let ordered_contribution_roots = (0..selected_entry_count)
            .map(|schedule_position| {
                [u8::try_from(schedule_position + 0x40)
                    .expect("selected schedule position fits u8");
                    Hash512::BYTE_LENGTH]
            })
            .collect::<Vec<_>>();
        let bytes = canonical_selected_galois_key_share_statement(
            [0x21; Hash512::BYTE_LENGTH],
            [0x22; Hash512::BYTE_LENGTH],
            FOUNDATION_PROFILE.participant_count - 1,
            SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION,
            &anchor_commitment_roots,
            &ordered_contribution_roots,
        )
        .expect("typed Galois statement");
        let statement = decode_selected_application_statement(
            &bytes,
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            selected_galois_statement_context(),
        )
        .expect("typed Galois statement decodes");
        assert_eq!(
            selected_galois_key_share_contribution_roots(&statement),
            Ok(ordered_contribution_roots.clone())
        );
        let typed_statement =
            decode_selected_galois_key_share_statement(&bytes, selected_galois_statement_context())
                .expect("typed Galois statement decodes");
        assert_eq!(
            typed_statement.setup_proof_context_hash(),
            [0x21; Hash512::BYTE_LENGTH]
        );
        assert_eq!(
            typed_statement.participant_identity(),
            [0x22; Hash512::BYTE_LENGTH]
        );
        assert_eq!(
            typed_statement.roster_position(),
            FOUNDATION_PROFILE.participant_count - 1
        );
        assert_eq!(
            typed_statement.batch_schedule_position(),
            SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION
        );
        assert_eq!(
            typed_statement.anchor_commitment_roots(),
            anchor_commitment_roots
        );
        assert_eq!(
            typed_statement.ordered_contribution_roots(),
            ordered_contribution_roots
        );

        assert_eq!(
            canonical_selected_galois_key_share_statement(
                [0x21; Hash512::BYTE_LENGTH],
                [0x22; Hash512::BYTE_LENGTH],
                FOUNDATION_PROFILE.participant_count,
                SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION,
                &anchor_commitment_roots,
                &ordered_contribution_roots,
            )
            .err(),
            Some(SelectedApplicationStatementError::WrongValue),
        );
        assert_eq!(
            canonical_selected_galois_key_share_statement(
                [0x21; Hash512::BYTE_LENGTH],
                [0x22; Hash512::BYTE_LENGTH],
                0,
                1,
                &anchor_commitment_roots,
                &ordered_contribution_roots,
            )
            .err(),
            Some(SelectedApplicationStatementError::InvalidProfile),
        );
        let mut extra_roots = ordered_contribution_roots.clone();
        extra_roots.push([0x99; Hash512::BYTE_LENGTH]);
        for invalid_roots in [
            &ordered_contribution_roots[..selected_entry_count - 1],
            extra_roots.as_slice(),
        ] {
            assert_eq!(
                canonical_selected_galois_key_share_statement(
                    [0x21; Hash512::BYTE_LENGTH],
                    [0x22; Hash512::BYTE_LENGTH],
                    0,
                    SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION,
                    &anchor_commitment_roots,
                    invalid_roots,
                )
                .err(),
                Some(SelectedApplicationStatementError::WrongTypeOrLength),
            );
        }
    }

    #[test]
    fn galois_statement_rejects_incomplete_extra_duplicate_reordered_and_malformed_entries() {
        let context = selected_galois_statement_context();
        let bytes = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("Galois statement");
        let statement = CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default())
            .expect("canonical Galois statement");
        let entries =
            decode_nested_tuple_list(&statement.items[5], selected_galois_key_share_entry_count())
                .expect("Galois entry list");

        assert_galois_statement_error(
            &replace_galois_entries(&statement, &entries[..entries.len() - 1]),
            context,
            SelectedApplicationStatementError::WrongTypeOrLength,
        );

        let mut extra_entries = entries.clone();
        extra_entries.push(entries[0].clone());
        assert_galois_statement_error(
            &replace_galois_entries(&statement, &extra_entries),
            context,
            SelectedApplicationStatementError::WrongTypeOrLength,
        );

        let mut reordered_entries = entries.clone();
        reordered_entries.swap(1, 2);
        assert_galois_statement_error(
            &replace_galois_entries(&statement, &reordered_entries),
            context,
            SelectedApplicationStatementError::WrongValue,
        );

        let mut duplicate_position_entries = entries.clone();
        duplicate_position_entries[2].items[0] = CanonicalItem::unsigned32(1);
        assert_galois_statement_error(
            &replace_galois_entries(&statement, &duplicate_position_entries),
            context,
            SelectedApplicationStatementError::WrongValue,
        );

        let mut wrong_schema_entries = entries.clone();
        wrong_schema_entries[2].schema_identifier ^= 1;
        assert_galois_statement_error(
            &replace_galois_entries(&statement, &wrong_schema_entries),
            context,
            SelectedApplicationStatementError::WrongSchema,
        );

        let mut wrong_version_entries = entries.clone();
        wrong_version_entries[2].schema_version += 1;
        assert_galois_statement_error(
            &replace_galois_entries(&statement, &wrong_version_entries),
            context,
            SelectedApplicationStatementError::WrongSchema,
        );

        let mut wrong_root_type_entries = entries.clone();
        wrong_root_type_entries[2].items[1] = CanonicalItem::unsigned64(0);
        assert_galois_statement_error(
            &replace_galois_entries(&statement, &wrong_root_type_entries),
            context,
            SelectedApplicationStatementError::WrongTypeOrLength,
        );

        for wrong_entry_list in [
            CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]),
            canonical_hash_list(selected_galois_key_share_entry_count())
                .expect("hash list encodes"),
        ] {
            let mut wrong_list_type_statement = statement.clone();
            wrong_list_type_statement.items[5] = wrong_entry_list;
            assert_galois_statement_error(
                &wrong_list_type_statement
                    .encode()
                    .expect("statement encodes"),
                context,
                SelectedApplicationStatementError::WrongTypeOrLength,
            );
        }
    }

    #[test]
    fn evaluator_statement_uses_segment_local_catalog_positions() {
        let context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            None,
            Some(FOUNDATION_PROFILE.option_count),
        );
        let bytes = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("complete evaluator statement");
        let tuple = decode_selected_application_statement(
            &bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("complete evaluator statement decodes");
        let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .expect("selected positions");
        let entries = decode_nested_tuple_list(&tuple.items[1], positions.len())
            .expect("complete entry list");
        assert_eq!(entries.len(), positions.len());
        for (entry, position) in entries.iter().zip(&positions) {
            assert_eq!(entry.items.len(), 3);
            assert_eq!(
                read_unsigned32(&entry.items[0]),
                Ok(position.schedule_position())
            );
        }
        assert_eq!(read_unsigned32(&entries[0].items[0]), Ok(0));
        assert_eq!(read_unsigned32(&entries[1].items[0]), Ok(0));
        assert_eq!(read_unsigned32(&entries[3].items[0]), Ok(2));
        assert!(
            canonical_selected_application_statement_for_ceiling(
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0; Hash512::BYTE_LENGTH],
                    Some(0),
                    Some(FOUNDATION_PROFILE.option_count),
                ),
            )
            .is_err()
        );
        assert!(
            canonical_selected_application_statement_for_ceiling(
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0; Hash512::BYTE_LENGTH],
                    None,
                    None,
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn evaluator_statement_decoder_rejects_incomplete_reordered_and_wrong_catalog_entries() {
        let context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            None,
            Some(FOUNDATION_PROFILE.option_count),
        );
        let bytes = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            context,
        )
        .expect("evaluator statement");
        let tuple = CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default())
            .expect("canonical statement");
        let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .expect("selected positions");
        let entries =
            decode_nested_tuple_list(&tuple.items[1], positions.len()).expect("entry list");

        let incomplete = replace_evaluator_entries(&tuple, &entries[..entries.len() - 1]);
        assert_eq!(
            decode_selected_application_statement(
                &incomplete,
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                context,
            )
            .err(),
            Some(SelectedApplicationStatementError::WrongTypeOrLength),
        );

        let mut reordered_entries = entries.clone();
        reordered_entries.swap(1, 2);
        let reordered = replace_evaluator_entries(&tuple, &reordered_entries);
        assert_eq!(
            decode_selected_application_statement(
                &reordered,
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                context,
            )
            .err(),
            Some(SelectedApplicationStatementError::WrongValue),
        );

        let mut wrong_position_entries = entries;
        wrong_position_entries[3].items[0] = CanonicalItem::unsigned32(1);
        let wrong_position = replace_evaluator_entries(&tuple, &wrong_position_entries);
        assert_eq!(
            decode_selected_application_statement(
                &wrong_position,
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                context,
            )
            .err(),
            Some(SelectedApplicationStatementError::WrongValue),
        );
    }

    #[test]
    fn typed_evaluator_statement_constructor_owns_the_selected_entry_order() {
        let source_roots = (0..FOUNDATION_PROFILE.participant_count)
            .map(|participant_index| [participant_index as u8; Hash512::BYTE_LENGTH])
            .collect::<Vec<_>>();
        let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .expect("selected positions");
        let entries = positions
            .iter()
            .enumerate()
            .map(|(entry_ordinal, _)| {
                SelectedEvaluatorAggregateEntryInput::new(
                    &source_roots,
                    [0x40_u8.wrapping_add(entry_ordinal as u8); Hash512::BYTE_LENGTH],
                    [0x80_u8.wrapping_add(entry_ordinal as u8); Hash512::BYTE_LENGTH],
                )
            })
            .collect::<Vec<_>>();
        let bytes = canonical_selected_evaluator_aggregate_statement(
            [0x21; Hash512::BYTE_LENGTH],
            FOUNDATION_PROFILE.option_count,
            &entries,
            [0x22; Hash512::BYTE_LENGTH],
        )
        .expect("typed evaluator statement");
        let decoded = decode_selected_application_statement(
            &bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0; Hash512::BYTE_LENGTH],
                None,
                Some(FOUNDATION_PROFILE.option_count),
            ),
        )
        .expect("typed statement decodes");
        let last_entry_ordinal =
            u32::try_from(positions.len() - 1).expect("selected evaluator entry count fits u32");
        let last_position = positions
            .last()
            .expect("the selected evaluator list is non-empty");
        let decoded_entry = selected_evaluator_aggregate_entry_roots(
            &decoded,
            FOUNDATION_PROFILE.option_count,
            last_entry_ordinal,
        )
        .expect("typed roots");
        assert_eq!(decoded_entry.entry_ordinal(), last_entry_ordinal);
        assert_eq!(decoded_entry.position(), *last_position);
        assert_eq!(decoded_entry.source_component_roots(), source_roots);
        let last_entry_byte =
            u8::try_from(last_entry_ordinal).expect("entry ordinal fits one test byte");
        assert_eq!(
            decoded_entry.runtime_component_root(),
            [0x40_u8.wrapping_add(last_entry_byte); 64]
        );
        assert_eq!(
            decoded_entry.auxiliary_component_root(),
            [0x80_u8.wrapping_add(last_entry_byte); 64]
        );

        let mut reordered_source_roots = source_roots.clone();
        let final_source_ordinal = reordered_source_roots.len() - 1;
        reordered_source_roots.swap(0, final_source_ordinal);
        let reordered_entries = positions
            .iter()
            .enumerate()
            .map(|(entry_ordinal, _)| {
                let entry_byte =
                    u8::try_from(entry_ordinal).expect("entry ordinal fits one test byte");
                SelectedEvaluatorAggregateEntryInput::new(
                    &reordered_source_roots,
                    [0x40_u8.wrapping_add(entry_byte); Hash512::BYTE_LENGTH],
                    [0x80_u8.wrapping_add(entry_byte); Hash512::BYTE_LENGTH],
                )
            })
            .collect::<Vec<_>>();
        let reordered_bytes = canonical_selected_evaluator_aggregate_statement(
            [0x21; Hash512::BYTE_LENGTH],
            FOUNDATION_PROFILE.option_count,
            &reordered_entries,
            [0x22; Hash512::BYTE_LENGTH],
        )
        .expect("reordered source list remains canonical but has a distinct binding");
        assert_ne!(reordered_bytes, bytes);
        let reordered_statement = decode_selected_application_statement(
            &reordered_bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0; Hash512::BYTE_LENGTH],
                None,
                Some(FOUNDATION_PROFILE.option_count),
            ),
        )
        .expect("reordered statement decodes");
        assert_eq!(
            selected_evaluator_aggregate_entry_roots(
                &reordered_statement,
                FOUNDATION_PROFILE.option_count,
                0,
            )
            .expect("reordered roots")
            .source_component_roots(),
            reordered_source_roots
        );

        assert!(
            canonical_selected_evaluator_aggregate_statement(
                [0x21; Hash512::BYTE_LENGTH],
                FOUNDATION_PROFILE.option_count,
                &entries[..entries.len() - 1],
                [0x22; Hash512::BYTE_LENGTH],
            )
            .is_err()
        );
    }

    #[test]
    fn typed_relinearization_round_one_statements_preserve_exact_source_order() {
        let setup_proof_context_hash = [0x19; Hash512::BYTE_LENGTH];
        let schedule_position = selected_relinearization_statement_schedule_position()
            .expect("selected relinearization position");
        let wrong_schedule_position = schedule_position
            .checked_add(1)
            .expect("selected schedule position has a successor");
        let source_root_pairs = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                let root_byte = u8::try_from(roster_position)
                    .expect("selected roster position fits one test byte");
                [
                    [root_byte; Hash512::BYTE_LENGTH],
                    [root_byte.wrapping_add(0x40); Hash512::BYTE_LENGTH],
                ]
            })
            .collect::<Vec<_>>();
        let aggregate_bytes = canonical_selected_relinearization_round_one_aggregate_statement(
            setup_proof_context_hash,
            schedule_position,
            &source_root_pairs,
            [0x81; Hash512::BYTE_LENGTH],
            [0x82; Hash512::BYTE_LENGTH],
        )
        .expect("typed round-one aggregate statement");
        let aggregate = decode_selected_relinearization_round_one_aggregate_statement(
            &aggregate_bytes,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0; Hash512::BYTE_LENGTH],
                Some(schedule_position),
                None,
            ),
        )
        .expect("typed round-one aggregate decodes");
        assert_eq!(
            aggregate.setup_proof_context_hash(),
            setup_proof_context_hash
        );
        assert_eq!(aggregate.schedule_position(), schedule_position);
        assert_eq!(aggregate.ordered_source_root_pairs(), source_root_pairs);
        assert_eq!(aggregate.aggregate_left_root(), [0x81; 64]);
        assert_eq!(aggregate.aggregate_right_root(), [0x82; 64]);

        let anchor_commitment_roots = [
            [0x31; Hash512::BYTE_LENGTH],
            [0x32; Hash512::BYTE_LENGTH],
            [0x33; Hash512::BYTE_LENGTH],
        ];
        let participant_bytes = canonical_selected_relinearization_round_one_statement(
            setup_proof_context_hash,
            [0x23; Hash512::BYTE_LENGTH],
            3,
            schedule_position,
            &anchor_commitment_roots,
            source_root_pairs[3][0],
            source_root_pairs[3][1],
        )
        .expect("typed participant round-one statement");
        let participant = decode_selected_relinearization_round_one_statement(
            &participant_bytes,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0; Hash512::BYTE_LENGTH],
                Some(schedule_position),
                None,
            ),
        )
        .expect("typed participant round-one decodes");
        assert_eq!(participant.participant_identity(), [0x23; 64]);
        assert_eq!(participant.roster_position(), 3);
        assert_eq!(
            participant.anchor_commitment_roots(),
            [[0x31; 64], [0x32; 64], [0x33; 64]]
        );
        assert_eq!(participant.round_one_left_root(), source_root_pairs[3][0]);
        assert_eq!(participant.round_one_right_root(), source_root_pairs[3][1]);
        assert_eq!(
            canonical_selected_relinearization_round_one_statement(
                setup_proof_context_hash,
                [0x23; Hash512::BYTE_LENGTH],
                3,
                wrong_schedule_position,
                &anchor_commitment_roots,
                source_root_pairs[3][0],
                source_root_pairs[3][1],
            ),
            Err(SelectedApplicationStatementError::InvalidProfile)
        );
        assert_eq!(
            canonical_selected_relinearization_round_one_statement(
                setup_proof_context_hash,
                [0x23; Hash512::BYTE_LENGTH],
                3,
                schedule_position,
                &anchor_commitment_roots[..2],
                source_root_pairs[3][0],
                source_root_pairs[3][1],
            ),
            Err(SelectedApplicationStatementError::WrongTypeOrLength)
        );

        let mut reordered_pairs = source_root_pairs.clone();
        reordered_pairs.swap(2, 7);
        let reordered_bytes = canonical_selected_relinearization_round_one_aggregate_statement(
            setup_proof_context_hash,
            schedule_position,
            &reordered_pairs,
            [0x81; Hash512::BYTE_LENGTH],
            [0x82; Hash512::BYTE_LENGTH],
        )
        .expect("reordered round-one aggregate remains canonical");
        assert_ne!(reordered_bytes, aggregate_bytes);
    }

    #[test]
    fn compact_setup_statement_decoders_retain_exact_common_witness_roots() {
        let suite_identifier = [0x51; Hash512::BYTE_LENGTH];
        let context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier,
            None,
            None,
        );
        let setup_proof_context_hash = [0x61; Hash512::BYTE_LENGTH];
        let participant_identity = [0x62; Hash512::BYTE_LENGTH];
        let degree_zero_roots = (0..selected_sharing_limb_count()
            .expect("selected sharing limb count"))
            .map(|ordinal| [0x70_u8.wrapping_add(ordinal as u8); Hash512::BYTE_LENGTH])
            .collect::<Vec<_>>();
        let anchor_roots = [
            [0x81; Hash512::BYTE_LENGTH],
            [0x82; Hash512::BYTE_LENGTH],
            [0x83; Hash512::BYTE_LENGTH],
        ];
        let same_secret_bytes = CanonicalTuple::new(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            APPLICATION_STATEMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(setup_proof_context_hash),
                CanonicalItem::participant_identity(participant_identity),
                CanonicalItem::unsigned16(4),
                canonical_hash_list_values(&degree_zero_roots).expect("degree-zero roots encode"),
                canonical_hash_list_values(&anchor_roots).expect("anchor roots encode"),
            ],
        )
        .encode()
        .expect("same-secret statement encodes");
        let same_secret = decode_selected_same_secret_statement(&same_secret_bytes, context)
            .expect("same-secret statement decodes");
        assert_eq!(
            same_secret.setup_proof_context_hash(),
            setup_proof_context_hash
        );
        assert_eq!(same_secret.participant_identity(), participant_identity);
        assert_eq!(same_secret.roster_position(), 4);
        assert_eq!(
            same_secret.ordered_degree_zero_commitment_roots(),
            degree_zero_roots
        );
        assert_eq!(same_secret.anchor_commitment_roots(), anchor_roots);

        let public_key_share_root = [0x91; Hash512::BYTE_LENGTH];
        let public_key_share_bytes = CanonicalTuple::new(
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            APPLICATION_STATEMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(setup_proof_context_hash),
                CanonicalItem::participant_identity(participant_identity),
                CanonicalItem::unsigned16(4),
                canonical_hash_list_values(&anchor_roots).expect("anchor roots encode"),
                CanonicalItem::hash512(public_key_share_root),
            ],
        )
        .encode()
        .expect("public-key share statement encodes");
        let public_key_share =
            decode_selected_public_key_share_statement(&public_key_share_bytes, context)
                .expect("public-key share statement decodes");
        assert_eq!(
            public_key_share.setup_proof_context_hash(),
            setup_proof_context_hash
        );
        assert_eq!(
            public_key_share.participant_identity(),
            participant_identity
        );
        assert_eq!(public_key_share.roster_position(), 4);
        assert_eq!(public_key_share.anchor_commitment_roots(), anchor_roots);
        assert_eq!(
            public_key_share.public_key_share_root(),
            public_key_share_root
        );

        let incomplete_same_secret = CanonicalTuple::new(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            APPLICATION_STATEMENT_SCHEMA_VERSION,
            vec![
                CanonicalItem::hash512(setup_proof_context_hash),
                CanonicalItem::participant_identity(participant_identity),
                CanonicalItem::unsigned16(4),
                canonical_hash_list_values(&degree_zero_roots[..degree_zero_roots.len() - 1])
                    .expect("incomplete roots encode"),
                canonical_hash_list_values(&anchor_roots).expect("anchor roots encode"),
            ],
        )
        .encode()
        .expect("incomplete statement encodes");
        assert_eq!(
            decode_selected_same_secret_statement(&incomplete_same_secret, context),
            Err(SelectedApplicationStatementError::WrongTypeOrLength)
        );
    }

    fn selected_galois_statement_context() -> SelectedApplicationStatementContext {
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION),
            None,
        )
    }

    fn assert_galois_statement_error(
        canonical_statement_bytes: &[u8],
        context: SelectedApplicationStatementContext,
        expected_error: SelectedApplicationStatementError,
    ) {
        assert_eq!(
            decode_selected_application_statement(
                canonical_statement_bytes,
                ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                context,
            )
            .err(),
            Some(expected_error),
        );
    }

    fn replace_galois_entries(statement: &CanonicalTuple, entries: &[CanonicalTuple]) -> Vec<u8> {
        let entry_items = entries
            .iter()
            .map(|entry| CanonicalItem::nested_tuple(entry).expect("entry encodes"))
            .collect::<Vec<_>>();
        let mut mutated = statement.clone();
        mutated.items[5] =
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &entry_items)
                .expect("Galois entry list encodes");
        mutated.encode().expect("Galois statement encodes")
    }

    fn replace_evaluator_entries(
        statement: &CanonicalTuple,
        entries: &[CanonicalTuple],
    ) -> Vec<u8> {
        let entry_items = entries
            .iter()
            .map(|entry| CanonicalItem::nested_tuple(entry).expect("entry encodes"))
            .collect::<Vec<_>>();
        let mut mutated = statement.clone();
        mutated.items[1] =
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &entry_items)
                .expect("entry list encodes");
        mutated.encode().expect("statement encodes")
    }
}
