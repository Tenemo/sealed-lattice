use std::{cell::RefCell, collections::HashMap, rc::Rc};

use fips203::{
    ml_kem_768,
    traits::{Encaps, SerDes},
};
use zeroize::Zeroizing;

use super::board_ingestion_runtime::VerifiedBoardApplicationSource;
use super::local_storage_runtime::{
    LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH, open_action_randomness_root,
    seal_action_randomness_root,
};
use super::runtime_input::RuntimeInputReader as InputReader;
use super::state_runtime::{
    STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VerifiedStateReservationRuntimeBinding,
    verified_state_reservation_binding,
};
use super::{
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionPrivateRandomness, ActionRandomnessDerivationInput,
    ActionRandomnessRoot, CanonicalDecodeLimits, FOUNDATION_PROFILE, FoundationObjectType, Hash512,
    LOCAL_RECORD_NONCE_BYTE_LENGTH, LocalStorageBinding, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH,
    ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH, OrdinaryProofCoinInput, ParticipantIdentity,
    PersistentProofCoinInput, PersistentProofWitnessCoinBinding,
    PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
    PrivateRandomnessKmacInputClassAccounting, ProofApplicationSlot,
    ProofApplicationSlotCeilings as ProofFamilyIdentifiers, RefusalReason, Roster,
    StateCapabilityKind, private_randomness_stream_block_count_for_byte_length,
};

const COMMAND_OPEN: u32 = 1;
const COMMAND_CLOSE: u32 = 2;
const COMMAND_SETUP_MAILBOX_ENCAPSULATE: u32 = 3;
const COMMAND_ORDINARY_PROOF_ATTEMPT: u32 = 5;
const COMMAND_TARGET_RELEASE_ATTEMPT: u32 = 6;
const COMMAND_FRESH_BALLOT_ATTEMPT: u32 = 7;
const COMMAND_CREATE_AND_SEAL: u32 = 8;
const COMMAND_OPEN_SEALED: u32 = 9;
const COMMAND_SETUP_ACTION_RANDOMNESS_AUTHORIZATION: u32 = 10;
const COMMAND_VALIDATE_SETUP_MAILBOX_SOURCE_KEYS: u32 = 11;
const COMMAND_SETUP_MAILBOX_SIGNATURE_HEDGE: u32 = 12;
const COMMAND_SETUP_OBJECT_SIGNATURE_HEDGE: u32 = 16;

const HANDLE_BYTE_LENGTH: usize = 4;
const HASH_BYTE_LENGTH: usize = 64;
const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_ACTIVE_SESSION_COUNT: usize = 256;

const SUCCESSFUL_SETUP_SIGNED_OBJECT_TYPES: [FoundationObjectType; 5] = [
    FoundationObjectType::SetupIntent,
    FoundationObjectType::PublicRandomnessCommitment,
    FoundationObjectType::PublicRandomnessReveal,
    FoundationObjectType::PublicSetupRecord,
    FoundationObjectType::PrivateShareAcceptance,
];

/// Source-owned count for setup mailbox coins and signature hedges on the
/// successful selected setup path. Complaint signing is an alternative
/// terminal path and is not added to the successful-path ceiling.
pub(crate) fn selected_setup_transport_private_randomness_kmac_input_accounting()
-> Option<PrivateRandomnessKmacInputClassAccounting> {
    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let directed_mailbox_count =
        participant_count.checked_mul(participant_count.checked_sub(1)?)?;
    let one_short_stream_block_count = private_randomness_stream_block_count_for_byte_length(
        u64::try_from(ATTEMPT_IDENTIFIER_BYTE_LENGTH).ok()?,
    )?;
    let mailbox_stream_block_count =
        directed_mailbox_count.checked_mul(one_short_stream_block_count.checked_mul(3)?)?;
    let setup_object_signature_stream_block_count = participant_count
        .checked_mul(u64::try_from(SUCCESSFUL_SETUP_SIGNED_OBJECT_TYPES.len()).ok()?)?;
    PrivateRandomnessKmacInputClassAccounting::checked_new(
        0,
        0,
        mailbox_stream_block_count.checked_add(setup_object_signature_stream_block_count)?,
        0,
    )
}

pub(crate) const ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT: u32 = 0x0001_0000;
pub(crate) const ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE: u32 = 0x0001_0001;

type RuntimeResult<Value> = Result<Value, u32>;

/// Authenticated, exact checkpoint position retained by the browser-owned
/// action worker. There is deliberately no constructor from copied checkpoint
/// fields; the checkpoint authority will mint this source after authenticating
/// the durable record and exact continuation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedCheckpointContinuationSource {
    checkpoint_lineage_identifier: [u8; 32],
    checkpoint_schedule_digest: Hash512,
    next_event_index: u64,
    cumulative_event_digest: Hash512,
}

impl AuthenticatedCheckpointContinuationSource {
    /// Marks the beginning of one locally owned proof attempt before its
    /// generation binding can derive the exact checkpoint genesis digest.
    /// The zero cumulative digest is an internal construction marker only;
    /// it is replaced by the binding-derived genesis before a worker starts
    /// and is never accepted as an authenticated resumed position.
    pub(crate) const fn for_fresh_common_proof_attempt(
        checkpoint_lineage_identifier: [u8; 32],
        checkpoint_schedule_digest: Hash512,
    ) -> Self {
        Self {
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
            next_event_index: 0,
            cumulative_event_digest: Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
        }
    }

    /// Constructs the continuation authority decoded from one checkpoint that
    /// the browser-owned custody path has already authenticated. This remains
    /// crate-private so transported fields cannot construct prover authority
    /// through the generated-WASM command surface.
    pub(crate) const fn from_authenticated_common_proof_checkpoint(
        checkpoint_lineage_identifier: [u8; 32],
        checkpoint_schedule_digest: Hash512,
        next_event_index: u64,
        cumulative_event_digest: Hash512,
    ) -> Self {
        Self {
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
            next_event_index,
            cumulative_event_digest,
        }
    }

    pub(crate) const fn checkpoint_lineage_identifier(&self) -> [u8; 32] {
        self.checkpoint_lineage_identifier
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        self.checkpoint_schedule_digest
    }

    pub(crate) const fn next_event_index(&self) -> u64 {
        self.next_event_index
    }

    pub(crate) const fn cumulative_event_digest(&self) -> Hash512 {
        self.cumulative_event_digest
    }
}

/// Opaque local prover-attempt source retained only after the worker joins its
/// private randomness reservation, exact proof slot, selected proof profile,
/// and authenticated checkpoint continuation. It authorizes generation for
/// this browser's reserved attempt only; it cannot authorize verification of
/// a public proof. Copied slot hashes, attempt identifiers, decoder output, and
/// caller accounting cannot construct it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedActionProofAttemptSource {
    attempt_identifier: PrivateRandomnessAttemptIdentifier,
    application_slot: ProofApplicationSlot,
    application_slot_hash: Hash512,
    application_statement_schema_identifier: u16,
    application_statement_hash: Hash512,
    expected_proof_byte_length: u64,
    expected_query_count: u32,
    checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
}

impl PreparedActionProofAttemptSource {
    pub(crate) const fn attempt_identifier(&self) -> [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        *self.attempt_identifier.as_bytes()
    }

    pub(crate) const fn private_randomness_attempt_identifier(
        &self,
    ) -> PrivateRandomnessAttemptIdentifier {
        self.attempt_identifier
    }

    pub(crate) const fn application_slot(&self) -> ProofApplicationSlot {
        self.application_slot
    }

    pub(crate) const fn application_slot_hash(&self) -> Hash512 {
        self.application_slot_hash
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn application_statement_hash(&self) -> Hash512 {
        self.application_statement_hash
    }

    pub(crate) const fn expected_proof_byte_length(&self) -> u64 {
        self.expected_proof_byte_length
    }

    pub(crate) const fn expected_query_count(&self) -> u32 {
        self.expected_query_count
    }

    pub(crate) const fn checkpoint_continuation(
        &self,
    ) -> &AuthenticatedCheckpointContinuationSource {
        &self.checkpoint_continuation
    }
}

/// A reset-safe prepared attempt after the family owner has streamed the
/// exact canonical semantic witness into the browser-owned proof-coin KMAC.
/// Only this type can authorize persistent common-proof generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WitnessBoundPreparedActionProofAttemptSource {
    prepared_source: PreparedActionProofAttemptSource,
    attempt_identifier: PrivateRandomnessAttemptIdentifier,
}

impl WitnessBoundPreparedActionProofAttemptSource {
    pub(crate) const fn attempt_identifier(&self) -> [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        *self.attempt_identifier.as_bytes()
    }

    pub(crate) const fn private_randomness_attempt_identifier(
        &self,
    ) -> PrivateRandomnessAttemptIdentifier {
        self.attempt_identifier
    }

    pub(crate) const fn application_slot(&self) -> ProofApplicationSlot {
        self.prepared_source.application_slot()
    }

    pub(crate) const fn application_slot_hash(&self) -> Hash512 {
        self.prepared_source.application_slot_hash()
    }

    pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
        self.prepared_source
            .application_statement_schema_identifier()
    }

    pub(crate) const fn application_statement_hash(&self) -> Hash512 {
        self.prepared_source.application_statement_hash()
    }

    pub(crate) const fn expected_proof_byte_length(&self) -> u64 {
        self.prepared_source.expected_proof_byte_length()
    }

    pub(crate) const fn expected_query_count(&self) -> u32 {
        self.prepared_source.expected_query_count()
    }

    pub(crate) const fn checkpoint_continuation(
        &self,
    ) -> &AuthenticatedCheckpointContinuationSource {
        self.prepared_source.checkpoint_continuation()
    }
}

pub(crate) fn bind_prepared_action_proof_attempt_to_canonical_witness(
    prepared_source: PreparedActionProofAttemptSource,
    binding: PersistentProofWitnessCoinBinding,
) -> Result<WitnessBoundPreparedActionProofAttemptSource, super::FoundationSchemaError> {
    let input = binding.input();
    if input.application_slot() != prepared_source.application_slot()
        || input.application_statement_hash() != prepared_source.application_statement_hash()
        || binding.preparation_identifier() != prepared_source.attempt_identifier
    {
        return Err(super::FoundationSchemaError::new(
            RefusalReason::WrongContext,
            "canonical proof witness binding does not match the prepared attempt",
        ));
    }
    Ok(WitnessBoundPreparedActionProofAttemptSource {
        prepared_source,
        attempt_identifier: binding.finish()?,
    })
}

/// Resolves one live reset-safe or target-release proof attempt from retained
/// randomness, a positively verified state reservation, and a verifier-owned
/// board object. The canonical application statement is bound separately by
/// its recomputed hash; later family-specific relation owners consume the same
/// board object hash when installing their exact statement trees.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_prepared_action_proof_attempt_source(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    board_source: &VerifiedBoardApplicationSource,
    application_slot: ProofApplicationSlot,
    application_statement_hash: Hash512,
    expected_proof_byte_length: u64,
    expected_query_count: u32,
    checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
) -> RuntimeResult<PreparedActionProofAttemptSource> {
    if expected_proof_byte_length == 0 || expected_query_count == 0 {
        return Err(RefusalReason::OutsideSupportedProfile.canonical_code() as u32);
    }
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(action_randomness_handle)?;
        let derivation = randomness.derivation_input();
        if board_source.suite_identifier() != derivation.suite_identifier()
            || board_source.ceremony_context_hash() != derivation.ceremony_context_hash()
            || board_source.action_context_hash() != derivation.action_context_hash()
            || application_slot.suite_identifier() != derivation.suite_identifier()
            || application_slot.ceremony_context_hash() != derivation.ceremony_context_hash()
            || application_slot.action_context_hash() != derivation.action_context_hash()
            || application_slot.roster_position() != board_source.producer_roster_position()
            || application_slot
                .producer_sequence()
                .is_some_and(|sequence| sequence != board_source.producer_sequence())
        {
            return Err(RefusalReason::WrongContext.canonical_code() as u32);
        }

        let statement_schema_identifier =
            application_slot.application_statement_schema_identifier();
        require_matching_reservation(
            randomness,
            verified_reservation_binding,
            persistent_proof_reservation_kind(statement_schema_identifier)?,
        )?;
        let input = PersistentProofCoinInput::new(application_slot, application_statement_hash)
            .map_err(schema_status)?;
        let attempt_identifier = randomness
            .persistent_proof_preparation_identifier(&input)
            .map_err(schema_status)?;
        Ok(PreparedActionProofAttemptSource {
            attempt_identifier,
            application_slot,
            application_slot_hash: application_slot.hash().map_err(schema_status)?,
            application_statement_schema_identifier: statement_schema_identifier,
            application_statement_hash,
            expected_proof_byte_length,
            expected_query_count,
            checkpoint_continuation,
        })
    })
}

/// Resolves one locally owned reset-safe attempt for a collective setup proof
/// whose canonical application slot has no producer coordinates. The live
/// action key and its positively verified state reservation still belong to
/// the participant performing the proof; that local ownership is deliberately
/// absent from the public proof slot.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_prepared_collective_action_proof_attempt_source(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    application_slot: ProofApplicationSlot,
    application_statement_hash: Hash512,
    expected_proof_byte_length: u64,
    expected_query_count: u32,
    checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
) -> RuntimeResult<PreparedActionProofAttemptSource> {
    if application_slot.application_statement_schema_identifier()
        != ProofFamilyIdentifiers::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        || application_slot.roster_position().is_some()
        || application_slot.schedule_position().is_some()
        || application_slot.producer_sequence().is_some()
        || expected_proof_byte_length == 0
        || expected_query_count == 0
    {
        return Err(RefusalReason::OutsideSupportedProfile.canonical_code() as u32);
    }
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(action_randomness_handle)?;
        let derivation = randomness.derivation_input();
        if application_slot.suite_identifier() != derivation.suite_identifier()
            || application_slot.ceremony_context_hash() != derivation.ceremony_context_hash()
            || application_slot.action_context_hash() != derivation.action_context_hash()
        {
            return Err(RefusalReason::WrongContext.canonical_code() as u32);
        }
        require_matching_reservation(
            randomness,
            verified_reservation_binding,
            StateCapabilityKind::SetupActionRandomnessRoot,
        )?;
        let input = PersistentProofCoinInput::new(application_slot, application_statement_hash)
            .map_err(schema_status)?;
        let attempt_identifier = randomness
            .persistent_proof_preparation_identifier(&input)
            .map_err(schema_status)?;
        Ok(PreparedActionProofAttemptSource {
            attempt_identifier,
            application_slot,
            application_slot_hash: application_slot.hash().map_err(schema_status)?,
            application_statement_schema_identifier:
                ProofFamilyIdentifiers::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            application_statement_hash,
            expected_proof_byte_length,
            expected_query_count,
            checkpoint_continuation,
        })
    })
}

/// Resolves one ordinary ballot proof attempt from live browser-owned
/// randomness and the exact typed coin input already joined by the ballot
/// family. Unlike reset-safe setup and target-release families, an ordinary
/// ballot proof does not consume a state reservation or depend on a final
/// board object that would contain its own proof descriptor.
pub(crate) fn resolve_prepared_ordinary_proof_attempt_source(
    action_private_randomness: &ActionPrivateRandomness,
    proof_coin_input: OrdinaryProofCoinInput,
    expected_proof_byte_length: u64,
    expected_query_count: u32,
    checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedActionProofAttemptSource, super::FoundationSchemaError> {
    let application_slot = proof_coin_input.application_slot();
    let application_statement_hash = proof_coin_input.application_statement_hash();
    if application_slot.application_statement_schema_identifier()
        != ProofFamilyIdentifiers::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
        || expected_proof_byte_length == 0
        || expected_query_count == 0
        || application_statement_hash.into_bytes() == [0_u8; HASH_BYTE_LENGTH]
    {
        return Err(super::FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "ordinary proof attempt is outside the selected ballot profile",
        ));
    }
    let derivation = action_private_randomness.derivation_input();
    if application_slot.suite_identifier() != derivation.suite_identifier()
        || application_slot.ceremony_context_hash() != derivation.ceremony_context_hash()
        || application_slot.action_context_hash() != derivation.action_context_hash()
        || application_slot.roster_position().is_none()
        || application_slot.schedule_position().is_some()
        || application_slot.producer_sequence().is_none()
    {
        return Err(super::FoundationSchemaError::new(
            RefusalReason::WrongContext,
            "ordinary proof attempt and action randomness contexts differ",
        ));
    }
    let attempt_identifier =
        action_private_randomness.ordinary_proof_attempt_identifier(&proof_coin_input)?;
    Ok(PreparedActionProofAttemptSource {
        attempt_identifier,
        application_slot,
        application_slot_hash: application_slot.hash()?,
        application_statement_schema_identifier:
            ProofFamilyIdentifiers::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        application_statement_hash,
        expected_proof_byte_length,
        expected_query_count,
        checkpoint_continuation,
    })
}

struct ValidatedSetupRoster {
    mailbox_encapsulation_keys: Vec<(
        ParticipantIdentity,
        [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH],
    )>,
    participant_identities: Vec<ParticipantIdentity>,
    roster_hash: Hash512,
}

#[derive(Default)]
struct ActionRandomnessRegistry {
    next_handle: u32,
    sessions: HashMap<u32, Rc<ActionPrivateRandomness>>,
    setup_rosters: HashMap<u32, ValidatedSetupRoster>,
}

impl ActionRandomnessRegistry {
    fn open(&mut self, randomness: ActionPrivateRandomness) -> RuntimeResult<u32> {
        if self.sessions.len() >= MAXIMUM_ACTIVE_SESSION_COUNT {
            return Err(ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT);
        }
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT)?;
        self.sessions.insert(self.next_handle, Rc::new(randomness));
        Ok(self.next_handle)
    }

    fn get(&self, handle: u32) -> RuntimeResult<&ActionPrivateRandomness> {
        self.sessions
            .get(&handle)
            .map(Rc::as_ref)
            .ok_or(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE)
    }

    fn close(&mut self, handle: u32) -> RuntimeResult<()> {
        let closed = self
            .sessions
            .remove(&handle)
            .map(|_| ())
            .ok_or(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE);
        if closed.is_ok() {
            self.setup_rosters.remove(&handle);
        }
        closed
    }

    fn retain_setup_roster(
        &mut self,
        handle: u32,
        roster: ValidatedSetupRoster,
    ) -> RuntimeResult<()> {
        if !self.sessions.contains_key(&handle) {
            return Err(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE);
        }
        self.setup_rosters.insert(handle, roster);
        Ok(())
    }

    fn setup_mailbox_recipient_key(
        &self,
        handle: u32,
        roster_hash: Hash512,
        recipient_participant_identity: ParticipantIdentity,
    ) -> RuntimeResult<[u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH]> {
        let roster = self
            .setup_rosters
            .get(&handle)
            .ok_or(RefusalReason::WrongContext.canonical_code() as u32)?;
        if roster.roster_hash != roster_hash {
            return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
        }
        roster
            .mailbox_encapsulation_keys
            .iter()
            .find_map(|(participant_identity, key)| {
                (*participant_identity == recipient_participant_identity).then_some(*key)
            })
            .ok_or(RefusalReason::WrongContext.canonical_code() as u32)
    }

    fn setup_source_matches_roster_position(
        &self,
        handle: u32,
        roster_hash: Hash512,
        source_roster_position: u16,
        expected_source_identity: ParticipantIdentity,
    ) -> RuntimeResult<()> {
        let roster = self
            .setup_rosters
            .get(&handle)
            .ok_or(RefusalReason::MissingPrerequisite.canonical_code() as u32)?;
        if roster.roster_hash != roster_hash {
            return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
        }
        if roster
            .participant_identities
            .get(usize::from(source_roster_position))
            != Some(&expected_source_identity)
        {
            return Err(RefusalReason::WrongContext.canonical_code() as u32);
        }
        Ok(())
    }
}

thread_local! {
    static ACTION_RANDOMNESS_REGISTRY: RefCell<ActionRandomnessRegistry> =
        RefCell::new(ActionRandomnessRegistry::default());
}

#[derive(Clone, Copy)]
pub(crate) struct SetupActionRandomnessReservationSource {
    authorization_hash: Hash512,
    derivation_input: ActionRandomnessDerivationInput,
}

impl SetupActionRandomnessReservationSource {
    pub(crate) const fn authorization_hash(self) -> Hash512 {
        self.authorization_hash
    }

    pub(crate) const fn derivation_input(self) -> ActionRandomnessDerivationInput {
        self.derivation_input
    }
}

pub(crate) fn resolve_setup_action_randomness_reservation_source(
    action_randomness_handle: u32,
    roster_hash: Hash512,
) -> RuntimeResult<SetupActionRandomnessReservationSource> {
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(action_randomness_handle)?;
        Ok(SetupActionRandomnessReservationSource {
            authorization_hash: randomness
                .setup_action_randomness_authorization(roster_hash)
                .map_err(schema_status)?,
            derivation_input: randomness.derivation_input(),
        })
    })
}

/// Retains one live browser-owned action-randomness source for a deferred
/// exact-family operation. The returned process-local source shares custody
/// with the action session and exposes no root, stream key, or serialized
/// secret material.
pub(crate) fn retain_action_private_randomness_for_exact_family(
    action_randomness_handle: u32,
) -> RuntimeResult<Rc<ActionPrivateRandomness>> {
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        registry
            .borrow()
            .sessions
            .get(&action_randomness_handle)
            .cloned()
            .ok_or(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE)
    })
}

pub(crate) fn run_action_randomness_command(command: u32, input: &[u8]) -> RuntimeResult<Vec<u8>> {
    match command {
        COMMAND_OPEN => open(input),
        COMMAND_CLOSE => close(input),
        COMMAND_SETUP_MAILBOX_ENCAPSULATE => setup_mailbox_encapsulate(input),
        COMMAND_SETUP_MAILBOX_SIGNATURE_HEDGE => setup_mailbox_signature_hedge(input),
        COMMAND_SETUP_OBJECT_SIGNATURE_HEDGE => setup_object_signature_hedge(input),
        COMMAND_ORDINARY_PROOF_ATTEMPT => ordinary_proof_attempt(input),
        COMMAND_TARGET_RELEASE_ATTEMPT => target_release_attempt(input),
        COMMAND_FRESH_BALLOT_ATTEMPT => fresh_ballot_attempt(input),
        COMMAND_CREATE_AND_SEAL => create_and_seal(input),
        COMMAND_OPEN_SEALED => open_sealed(input),
        COMMAND_SETUP_ACTION_RANDOMNESS_AUTHORIZATION => {
            setup_action_randomness_authorization(input)
        }
        COMMAND_VALIDATE_SETUP_MAILBOX_SOURCE_KEYS => validate_setup_mailbox_source_keys(input),
        _ => Err(malformed_status()),
    }
}

fn open(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let root = Zeroizing::new(reader.read_array::<ACTION_RANDOMNESS_ROOT_BYTE_LENGTH>()?);
    let derivation_input = read_derivation_input(&mut reader)?;
    reader.finish()?;
    let randomness = ActionRandomnessRoot::from_injected_bytes(root)
        .derive(derivation_input)
        .map_err(schema_status)?;
    let commitment = randomness.action_randomness_commitment();
    let handle =
        ACTION_RANDOMNESS_REGISTRY.with(|registry| registry.borrow_mut().open(randomness))?;
    let mut output = Vec::with_capacity(HANDLE_BYTE_LENGTH + HASH_BYTE_LENGTH);
    output.extend_from_slice(&handle.to_le_bytes());
    output.extend_from_slice(commitment.as_bytes());
    Ok(output)
}

fn create_and_seal(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let storage_handle = reader.read_u32()?;
    let storage_capability = reader.read_array::<LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH>()?;
    let root = Zeroizing::new(reader.read_array::<ACTION_RANDOMNESS_ROOT_BYTE_LENGTH>()?);
    let derivation_input = read_derivation_input(&mut reader)?;
    let record_version = reader.read_u64()?;
    let predecessor_record_hash = read_optional_hash(&mut reader)?;
    let nonce = reader.read_array::<LOCAL_RECORD_NONCE_BYTE_LENGTH>()?;
    reader.finish()?;

    let binding = storage_binding(derivation_input);
    let randomness = ActionRandomnessRoot::from_injected_bytes(root)
        .derive(derivation_input)
        .map_err(schema_status)?;
    let commitment = randomness.action_randomness_commitment();
    let handle =
        ACTION_RANDOMNESS_REGISTRY.with(|registry| registry.borrow_mut().open(randomness))?;
    let sealed_envelope = ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        seal_action_randomness_root(
            storage_handle,
            &storage_capability,
            binding,
            commitment,
            record_version,
            predecessor_record_hash,
            nonce,
            randomness.root(),
        )
    });
    let sealed_envelope = match sealed_envelope {
        Ok(envelope) => envelope,
        Err(status) => {
            ACTION_RANDOMNESS_REGISTRY.with(|registry| {
                let _ = registry.borrow_mut().close(handle);
            });
            return Err(status);
        }
    };
    let mut output =
        Vec::with_capacity(HANDLE_BYTE_LENGTH + HASH_BYTE_LENGTH + sealed_envelope.len());
    output.extend_from_slice(&handle.to_le_bytes());
    output.extend_from_slice(commitment.as_bytes());
    output.extend_from_slice(&sealed_envelope);
    Ok(output)
}

fn setup_action_randomness_authorization(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let canonical_roster_bytes = reader.read_remaining();
    if canonical_roster_bytes.is_empty() {
        return Err(malformed_status());
    }
    let roster = Roster::decode(canonical_roster_bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_status)?;
    roster
        .require_selected_profile_size()
        .map_err(schema_status)?;
    let roster_hash = roster.roster_hash().map_err(schema_status)?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        let participant_identity = randomness.derivation_input().participant_identity();
        let participant_is_in_roster = roster.entries.iter().any(|entry| {
            entry
                .participant_identity()
                .is_ok_and(|identity| identity == participant_identity)
        });
        if !participant_is_in_roster {
            return Err(RefusalReason::WrongContext.canonical_code() as u32);
        }
        Ok(randomness
            .setup_action_randomness_authorization(roster_hash)
            .map_err(schema_status)?
            .as_bytes()
            .to_vec())
    })
}

fn validate_setup_mailbox_source_keys(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let supplied_signing_verification_key =
        reader.read_array::<ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH>()?;
    let supplied_mailbox_encapsulation_key =
        reader.read_array::<ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH>()?;
    let canonical_roster_bytes = reader.read_remaining();
    if canonical_roster_bytes.is_empty() {
        return Err(malformed_status());
    }
    let roster = Roster::decode(canonical_roster_bytes, &CanonicalDecodeLimits::default())
        .map_err(schema_status)?;
    roster
        .require_selected_profile_size()
        .map_err(schema_status)?;
    let roster_hash = roster.roster_hash().map_err(schema_status)?;

    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let randomness = registry.get(handle)?;
        require_matching_setup_action_randomness_reservation(
            randomness,
            reservation_binding,
            roster_hash,
        )?;
        let expected_participant_identity = randomness.derivation_input().participant_identity();
        let mut source_keys_match = false;
        let mut mailbox_encapsulation_keys = Vec::with_capacity(roster.entries.len());
        let mut participant_identities = Vec::with_capacity(roster.entries.len());
        for entry in &roster.entries {
            let participant_identity = entry.participant_identity().map_err(schema_status)?;
            participant_identities.push(participant_identity);
            mailbox_encapsulation_keys
                .push((participant_identity, entry.mailbox_encapsulation_key));
            if participant_identity == expected_participant_identity {
                source_keys_match = entry.signing_verification_key
                    == supplied_signing_verification_key
                    && entry.mailbox_encapsulation_key == supplied_mailbox_encapsulation_key;
            }
        }
        if !source_keys_match {
            return Err(RefusalReason::WrongContext.canonical_code() as u32);
        }
        registry.retain_setup_roster(
            handle,
            ValidatedSetupRoster {
                mailbox_encapsulation_keys,
                participant_identities,
                roster_hash,
            },
        )?;
        Ok(roster_hash.as_bytes().to_vec())
    })
}

fn open_sealed(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let storage_handle = reader.read_u32()?;
    let storage_capability = reader.read_array::<LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH>()?;
    let expected_commitment = Hash512::from_bytes(reader.read_array()?);
    let derivation_input = read_derivation_input(&mut reader)?;
    let record_version = reader.read_u64()?;
    let predecessor_record_hash = read_optional_hash(&mut reader)?;
    let canonical_envelope = reader.read_remaining();
    let root = open_action_randomness_root(
        storage_handle,
        &storage_capability,
        storage_binding(derivation_input),
        expected_commitment,
        record_version,
        predecessor_record_hash,
        canonical_envelope,
    )?;
    let randomness = ActionRandomnessRoot::from_injected_bytes(root)
        .derive(derivation_input)
        .map_err(schema_status)?;
    if randomness.action_randomness_commitment() != expected_commitment {
        return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
    }
    let handle =
        ACTION_RANDOMNESS_REGISTRY.with(|registry| registry.borrow_mut().open(randomness))?;
    let mut output = Vec::with_capacity(HANDLE_BYTE_LENGTH + HASH_BYTE_LENGTH);
    output.extend_from_slice(&handle.to_le_bytes());
    output.extend_from_slice(expected_commitment.as_bytes());
    Ok(output)
}

fn close(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let handle = read_handle_only(input)?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| registry.borrow_mut().close(handle))?;
    Ok(Vec::new())
}

fn setup_mailbox_encapsulate(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let roster_hash = Hash512::from_bytes(reader.read_array()?);
    let setup_mailbox_slot_hash = Hash512::from_bytes(reader.read_array()?);
    let recipient_participant_identity = ParticipantIdentity::from_bytes(reader.read_array()?);
    let recipient_encapsulation_key_bytes = reader.read_array::<{ ml_kem_768::EK_LEN }>()?;
    reader.finish()?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        require_matching_setup_action_randomness_reservation(
            randomness,
            reservation_binding,
            roster_hash,
        )?;
        let frozen_recipient_encapsulation_key = registry.setup_mailbox_recipient_key(
            handle,
            roster_hash,
            recipient_participant_identity,
        )?;
        if recipient_encapsulation_key_bytes != frozen_recipient_encapsulation_key {
            return Err(RefusalReason::WrongContext.canonical_code() as u32);
        }
        let attempt_identifier = randomness.setup_attempt_identifier();
        let mut envelope_attempt_stream = randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_mailbox(1).map_err(schema_status)?,
                setup_mailbox_slot_hash,
                attempt_identifier,
            )
            .map_err(schema_status)?;
        let mut encapsulation_coin_stream = randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_mailbox(2).map_err(schema_status)?,
                setup_mailbox_slot_hash,
                attempt_identifier,
            )
            .map_err(schema_status)?;
        let mut envelope_attempt_identifier = [0u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH];
        envelope_attempt_stream
            .fill_bytes(&mut envelope_attempt_identifier)
            .map_err(schema_status)?;
        let mut encapsulation_coins = Zeroizing::new([0u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        encapsulation_coin_stream
            .fill_bytes(encapsulation_coins.as_mut())
            .map_err(schema_status)?;
        let recipient_encapsulation_key =
            ml_kem_768::EncapsKey::try_from_bytes(frozen_recipient_encapsulation_key)
                .map_err(|_| RefusalReason::WrongTypeOrLength.canonical_code() as u32)?;
        let (shared_secret, ciphertext) =
            recipient_encapsulation_key.encaps_from_seed(&encapsulation_coins);
        let shared_secret = Zeroizing::new(shared_secret.into_bytes());
        let ciphertext = ciphertext.into_bytes();
        let mut output = Vec::with_capacity(
            ATTEMPT_IDENTIFIER_BYTE_LENGTH + ml_kem_768::CT_LEN + fips203::SSK_LEN,
        );
        output.extend_from_slice(&envelope_attempt_identifier);
        output.extend_from_slice(&ciphertext);
        output.extend_from_slice(shared_secret.as_ref());
        Ok(output)
    })
}

fn setup_mailbox_signature_hedge(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let roster_hash = Hash512::from_bytes(reader.read_array()?);
    let envelope_hash = Hash512::from_bytes(reader.read_array()?);
    reader.finish()?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        require_matching_setup_action_randomness_reservation(
            randomness,
            reservation_binding,
            roster_hash,
        )?;
        let retained_roster = registry
            .setup_rosters
            .get(&handle)
            .ok_or(RefusalReason::MissingPrerequisite.canonical_code() as u32)?;
        if retained_roster.roster_hash != roster_hash {
            return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
        }

        let attempt_identifier = randomness.setup_attempt_identifier();
        let mut signature_hedge_stream = randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_mailbox(3).map_err(schema_status)?,
                envelope_hash,
                attempt_identifier,
            )
            .map_err(schema_status)?;
        let mut signature_hedge = Zeroizing::new([0u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        signature_hedge_stream
            .fill_bytes(signature_hedge.as_mut())
            .map_err(schema_status)?;
        Ok(signature_hedge.as_ref().to_vec())
    })
}

fn setup_object_signature_hedge(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let roster_hash = Hash512::from_bytes(reader.read_array()?);
    let signature_message_hash = Hash512::from_bytes(reader.read_array()?);
    reader.finish()?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        require_matching_setup_action_randomness_reservation(
            randomness,
            reservation_binding,
            roster_hash,
        )?;
        let retained_roster = registry
            .setup_rosters
            .get(&handle)
            .ok_or(RefusalReason::MissingPrerequisite.canonical_code() as u32)?;
        if retained_roster.roster_hash != roster_hash {
            return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
        }

        let mut signature_hedge_stream = randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_source(4).map_err(schema_status)?,
                signature_message_hash,
                randomness.setup_attempt_identifier(),
            )
            .map_err(schema_status)?;
        let mut signature_hedge = Zeroizing::new([0u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        signature_hedge_stream
            .fill_bytes(signature_hedge.as_mut())
            .map_err(schema_status)?;
        Ok(signature_hedge.as_ref().to_vec())
    })
}

fn ordinary_proof_attempt(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let roster_position = reader.read_u16()?;
    let producer_sequence = reader.read_u64()?;
    let application_statement_hash = Hash512::from_bytes(reader.read_array()?);
    let attempt_nonce = Zeroizing::new(reader.read_array::<ATTEMPT_IDENTIFIER_BYTE_LENGTH>()?);
    reader.finish()?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        let derivation = randomness.derivation_input();
        let slot = ProofApplicationSlot::new(
            derivation.suite_identifier(),
            derivation.ceremony_context_hash(),
            derivation.action_context_hash(),
            0x1302,
            Some(roster_position),
            None,
            Some(producer_sequence),
        )
        .map_err(schema_status)?;
        let coin_input =
            OrdinaryProofCoinInput::new(slot, application_statement_hash, *attempt_nonce)
                .map_err(schema_status)?;
        let attempt = randomness
            .ordinary_proof_attempt_identifier(&coin_input)
            .map_err(schema_status)?;
        let mut output = slot_and_attempt_output(slot, attempt.as_bytes())?;
        output.extend_from_slice(attempt_nonce.as_ref());
        Ok(output)
    })
}

fn target_release_attempt(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let roster_position = reader.read_u16()?;
    reader.finish()?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        require_matching_reservation(
            randomness,
            reservation_binding,
            StateCapabilityKind::TargetRelease,
        )?;
        let derivation = randomness.derivation_input();
        let slot = ProofApplicationSlot::new(
            derivation.suite_identifier(),
            derivation.ceremony_context_hash(),
            derivation.action_context_hash(),
            0x1621,
            Some(roster_position),
            None,
            None,
        )
        .map_err(schema_status)?;
        let attempt = randomness
            .target_release_attempt_identifier(slot)
            .map_err(schema_status)?;
        slot_and_attempt_output(slot, attempt.as_bytes())
    })
}

fn fresh_ballot_attempt(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let injected_attempt = Zeroizing::new(reader.read_array::<ATTEMPT_IDENTIFIER_BYTE_LENGTH>()?);
    reader.finish()?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        Ok(randomness
            .ballot_encryption_attempt_identifier(injected_attempt)
            .as_bytes()
            .to_vec())
    })
}

fn slot_and_attempt_output(
    slot: ProofApplicationSlot,
    attempt_identifier: &[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
) -> RuntimeResult<Vec<u8>> {
    let slot_hash = slot.hash().map_err(schema_status)?;
    let mut output = Vec::with_capacity(HASH_BYTE_LENGTH + ATTEMPT_IDENTIFIER_BYTE_LENGTH);
    output.extend_from_slice(slot_hash.as_bytes());
    output.extend_from_slice(attempt_identifier);
    Ok(output)
}

fn read_derivation_input(
    reader: &mut InputReader<'_>,
) -> RuntimeResult<ActionRandomnessDerivationInput> {
    Ok(ActionRandomnessDerivationInput::new(
        Hash512::from_bytes(reader.read_array()?),
        Hash512::from_bytes(reader.read_array()?),
        Hash512::from_bytes(reader.read_array()?),
        ParticipantIdentity::from_bytes(reader.read_array()?),
    ))
}

fn storage_binding(derivation_input: ActionRandomnessDerivationInput) -> LocalStorageBinding {
    LocalStorageBinding::new(
        derivation_input.suite_identifier(),
        derivation_input.ceremony_context_hash(),
        derivation_input.action_context_hash(),
        derivation_input.participant_identity(),
    )
}

fn read_optional_hash(reader: &mut InputReader<'_>) -> RuntimeResult<Option<Hash512>> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(Hash512::from_bytes(reader.read_array()?))),
        _ => Err(malformed_status()),
    }
}

fn read_verified_reservation_binding(
    reader: &mut InputReader<'_>,
) -> RuntimeResult<VerifiedStateReservationRuntimeBinding> {
    let session_handle = reader.read_u32()?;
    let capability = reader.read_array::<STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>()?;
    let verified_reservation_handle = reader.read_u32()?;
    verified_state_reservation_binding(session_handle, &capability, verified_reservation_handle)
}

fn persistent_proof_reservation_kind(
    statement_schema_identifier: u16,
) -> RuntimeResult<StateCapabilityKind> {
    match statement_schema_identifier {
        ProofFamilyIdentifiers::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofFamilyIdentifiers::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofFamilyIdentifiers::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        | ProofFamilyIdentifiers::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofFamilyIdentifiers::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofFamilyIdentifiers::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
        | ProofFamilyIdentifiers::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofFamilyIdentifiers::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            Ok(StateCapabilityKind::SetupActionRandomnessRoot)
        }
        ProofFamilyIdentifiers::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
            Ok(StateCapabilityKind::TargetRelease)
        }
        _ => Err(RefusalReason::WrongTypeOrLength.canonical_code() as u32),
    }
}

fn require_matching_reservation(
    randomness: &ActionPrivateRandomness,
    verified_binding: VerifiedStateReservationRuntimeBinding,
    expected_capability_kind: StateCapabilityKind,
) -> RuntimeResult<()> {
    let binding = verified_binding.durable_binding;
    let derivation = randomness.derivation_input();
    if binding.capability_kind() != expected_capability_kind {
        return Err(RefusalReason::WrongTypeOrLength.canonical_code() as u32);
    }
    if binding.suite_id() != derivation.suite_identifier()
        || binding.ceremony_context_hash() != derivation.ceremony_context_hash()
        || binding.action_context_hash() != derivation.action_context_hash()
        || binding.subject_participant_id() != derivation.participant_identity()
    {
        return Err(RefusalReason::WrongContext.canonical_code() as u32);
    }
    Ok(())
}

fn require_matching_setup_action_randomness_reservation(
    randomness: &ActionPrivateRandomness,
    verified_binding: VerifiedStateReservationRuntimeBinding,
    roster_hash: Hash512,
) -> RuntimeResult<()> {
    require_matching_reservation(
        randomness,
        verified_binding,
        StateCapabilityKind::SetupActionRandomnessRoot,
    )?;
    let expected_authorization = randomness
        .setup_action_randomness_authorization(roster_hash)
        .map_err(schema_status)?;
    if verified_binding.authorization_hash != expected_authorization {
        return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
    }
    Ok(())
}

fn read_handle_only(input: &[u8]) -> RuntimeResult<u32> {
    if input.len() != HANDLE_BYTE_LENGTH {
        return Err(malformed_status());
    }
    Ok(u32::from_le_bytes(
        input.try_into().map_err(|_| malformed_status())?,
    ))
}

const fn malformed_status() -> u32 {
    RefusalReason::MalformedEncoding.canonical_code() as u32
}

fn schema_status(error: super::FoundationSchemaError) -> u32 {
    error.refusal_reason.canonical_code() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::local_storage_runtime::{
        LOCAL_STORAGE_ROOT_COMMAND_COMMIT, LOCAL_STORAGE_ROOT_COMMAND_RESET,
        LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW, run_local_storage_root_command,
    };

    fn open_input() -> Vec<u8> {
        let mut input = vec![0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH];
        input.extend_from_slice(&[0x11; HASH_BYTE_LENGTH]);
        input.extend_from_slice(&[0x22; HASH_BYTE_LENGTH]);
        input.extend_from_slice(&[0x33; HASH_BYTE_LENGTH]);
        input.extend_from_slice(&[0x44; HASH_BYTE_LENGTH]);
        input
    }

    fn fixed_lowercase_hex<const BYTE_LENGTH: usize>(value: &str) -> [u8; BYTE_LENGTH] {
        assert_eq!(value.len(), BYTE_LENGTH * 2);
        let mut output = [0u8; BYTE_LENGTH];
        for (byte_index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let digit = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("test vector is lowercase hexadecimal"),
            };
            output[byte_index] = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        output
    }

    fn fixed_action_randomness() -> ActionPrivateRandomness {
        ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(ActionRandomnessDerivationInput::new(
            Hash512::from_bytes([0x11; HASH_BYTE_LENGTH]),
            Hash512::from_bytes([0x22; HASH_BYTE_LENGTH]),
            Hash512::from_bytes([0x33; HASH_BYTE_LENGTH]),
            ParticipantIdentity::from_bytes([0x44; HASH_BYTE_LENGTH]),
        ))
        .expect("fixed action randomness derives")
    }

    #[test]
    fn witness_binding_refuses_a_different_action_randomness_key() {
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes([0x11; HASH_BYTE_LENGTH]),
            Hash512::from_bytes([0x22; HASH_BYTE_LENGTH]),
            Hash512::from_bytes([0x33; HASH_BYTE_LENGTH]),
            0x1211,
            Some(2),
            None,
            None,
        )
        .expect("persistent proof slot is valid");
        let application_statement_hash = Hash512::from_bytes([0x66; HASH_BYTE_LENGTH]);
        let proof_coin_input =
            PersistentProofCoinInput::new(application_slot, application_statement_hash)
                .expect("persistent proof coin input is valid");
        let prepared_action_randomness = fixed_action_randomness();
        let prepared_source = PreparedActionProofAttemptSource {
            attempt_identifier: prepared_action_randomness
                .persistent_proof_preparation_identifier(&proof_coin_input)
                .expect("persistent proof preparation identifier derives"),
            application_slot,
            application_slot_hash: application_slot
                .hash()
                .expect("persistent proof slot hashes"),
            application_statement_schema_identifier: 0x1211,
            application_statement_hash,
            expected_proof_byte_length: 1,
            expected_query_count: 1,
            checkpoint_continuation:
                AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                    [0x77; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
                    Hash512::from_bytes([0x88; HASH_BYTE_LENGTH]),
                ),
        };
        let bind_witness = |action_randomness: &ActionPrivateRandomness| {
            let mut binding = action_randomness
                .begin_persistent_proof_witness_coin_binding(&proof_coin_input)
                .expect("persistent witness binding starts");
            binding
                .absorb_canonical_bytes(b"sealed-lattice/test/canonical-semantic-witness/v1")
                .expect("canonical witness is absorbed");
            binding
        };

        bind_prepared_action_proof_attempt_to_canonical_witness(
            prepared_source,
            bind_witness(&prepared_action_randomness),
        )
        .expect("the prepared action key authorizes its witness binding");

        let different_action_randomness = ActionRandomnessRoot::from_injected_bytes(
            Zeroizing::new([0x6b; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]),
        )
        .derive(ActionRandomnessDerivationInput::new(
            Hash512::from_bytes([0x11; HASH_BYTE_LENGTH]),
            Hash512::from_bytes([0x22; HASH_BYTE_LENGTH]),
            Hash512::from_bytes([0x33; HASH_BYTE_LENGTH]),
            ParticipantIdentity::from_bytes([0x44; HASH_BYTE_LENGTH]),
        ))
        .expect("different action randomness derives for the same public context");
        let error = bind_prepared_action_proof_attempt_to_canonical_witness(
            prepared_source,
            bind_witness(&different_action_randomness),
        )
        .expect_err("a different action key cannot bind the prepared attempt");
        assert_eq!(error.refusal_reason, RefusalReason::WrongContext);
    }

    #[test]
    fn runtime_keeps_action_keys_opaque_and_returns_only_the_commitment() {
        let opened = run_action_randomness_command(COMMAND_OPEN, &open_input())
            .expect("action randomness opens");
        assert_eq!(opened.len(), HANDLE_BYTE_LENGTH + HASH_BYTE_LENGTH);
        assert_eq!(
            &opened[HANDLE_BYTE_LENGTH..],
            &fixed_lowercase_hex::<HASH_BYTE_LENGTH>(concat!(
                "358a1f0d923ca0ee03d6a5ddd4dd1bcd49c1c0d71e66e3e82e575097aba76d5f",
                "ce106820325f0459528e341511ebacfb872a42d6ae7e2e1ed5ab12b3b079d12e",
            )),
        );
        let handle = u32::from_le_bytes(opened[..HANDLE_BYTE_LENGTH].try_into().unwrap());
        run_action_randomness_command(COMMAND_CLOSE, &handle.to_le_bytes())
            .expect("session closes");
        assert_eq!(
            run_action_randomness_command(COMMAND_CLOSE, &handle.to_le_bytes()),
            Err(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE),
        );
    }

    #[test]
    fn runtime_matches_ordinary_proof_and_ballot_attempt_vectors() {
        let opened = run_action_randomness_command(COMMAND_OPEN, &open_input())
            .expect("action randomness opens");
        let handle = u32::from_le_bytes(opened[..HANDLE_BYTE_LENGTH].try_into().unwrap());

        let mut ordinary_input = handle.to_le_bytes().to_vec();
        ordinary_input.extend_from_slice(&2_u16.to_le_bytes());
        ordinary_input.extend_from_slice(&19_u64.to_le_bytes());
        ordinary_input.extend_from_slice(&[0x66; HASH_BYTE_LENGTH]);
        ordinary_input.extend_from_slice(&[0x70; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        assert_eq!(
            run_action_randomness_command(COMMAND_ORDINARY_PROOF_ATTEMPT, &ordinary_input)
                .expect("ordinary proof attempt derives"),
            [
                fixed_lowercase_hex::<HASH_BYTE_LENGTH>(concat!(
                    "f50cfe10a74b5b8aa9415cc29e117cfcb9502cf3761f1446cb33d7bb435cd0b8",
                    "449574d8c5f76c88701f308eda1b6f5875e14bdd7b3f429eab1c5d331d7b7fed",
                ))
                .as_slice(),
                fixed_lowercase_hex::<ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                    "c8a28cfe1918292c8e10281e260b03d728082c1de7504da1826856b6b1ad1925",
                )
                .as_slice(),
                &[0x70; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
            ]
            .concat(),
        );

        let mut fresh_ballot_input = handle.to_le_bytes().to_vec();
        fresh_ballot_input.extend_from_slice(&[0x91; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        assert_eq!(
            run_action_randomness_command(COMMAND_FRESH_BALLOT_ATTEMPT, &fresh_ballot_input)
                .expect("fresh ballot attempt begins"),
            [0x91; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
        );

        run_action_randomness_command(COMMAND_CLOSE, &handle.to_le_bytes())
            .expect("session closes");
    }

    #[test]
    fn runtime_refuses_wrong_closed_operation_shapes() {
        assert_eq!(
            run_action_randomness_command(COMMAND_OPEN, &open_input()[..319]),
            Err(malformed_status()),
        );
        assert_eq!(
            run_action_randomness_command(99, &[]),
            Err(malformed_status()),
        );
    }

    #[test]
    fn sealed_action_root_reopens_without_returning_plaintext() {
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_RESET, &[])
            .expect("storage registry resets");
        let storage_capability = [0xc1; LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH];
        let mut staged_input = storage_capability.to_vec();
        staged_input.extend_from_slice(&[0x11; HASH_BYTE_LENGTH]);
        staged_input.extend_from_slice(&[0x22; HASH_BYTE_LENGTH]);
        staged_input.extend_from_slice(&[0x33; HASH_BYTE_LENGTH]);
        staged_input.extend_from_slice(&[0x44; HASH_BYTE_LENGTH]);
        staged_input.extend_from_slice(&[0x82; 48]);
        let staged =
            run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW, &staged_input)
                .expect("storage root stages");
        let storage_handle = u32::from_le_bytes(staged[..HANDLE_BYTE_LENGTH].try_into().unwrap());
        let mut commit_input = storage_handle.to_le_bytes().to_vec();
        commit_input.extend_from_slice(&storage_capability);
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_COMMIT, &commit_input)
            .expect("storage root commits");

        let opened = run_action_randomness_command(COMMAND_OPEN, &open_input())
            .expect("action root opens before sealing");
        let created_handle = u32::from_le_bytes(opened[..HANDLE_BYTE_LENGTH].try_into().unwrap());
        let commitment = Hash512::from_bytes(
            opened[HANDLE_BYTE_LENGTH..]
                .try_into()
                .expect("commitment has the expected length"),
        );
        let envelope = seal_action_randomness_root(
            storage_handle,
            &storage_capability,
            LocalStorageBinding::new(
                Hash512::from_bytes([0x11; HASH_BYTE_LENGTH]),
                Hash512::from_bytes([0x22; HASH_BYTE_LENGTH]),
                Hash512::from_bytes([0x33; HASH_BYTE_LENGTH]),
                ParticipantIdentity::from_bytes([0x44; HASH_BYTE_LENGTH]),
            ),
            commitment,
            0,
            None,
            [0xe3; LOCAL_RECORD_NONCE_BYTE_LENGTH],
            &[0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        )
        .expect("action root seals through the closed storage path");

        let mut record_suffix = Vec::with_capacity(17);
        record_suffix.extend_from_slice(&0_u64.to_le_bytes());
        record_suffix.push(0);
        assert!(
            !envelope
                .windows(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH)
                .any(|window| { window == [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH] })
        );
        let mut first_attempt_input = created_handle.to_le_bytes().to_vec();
        first_attempt_input.extend_from_slice(&[0xa5; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        let first_attempt =
            run_action_randomness_command(COMMAND_FRESH_BALLOT_ATTEMPT, &first_attempt_input)
                .expect("created session accepts a fresh attempt identifier");
        run_action_randomness_command(COMMAND_CLOSE, &created_handle.to_le_bytes())
            .expect("created session closes");

        let mut reopen_input = storage_handle.to_le_bytes().to_vec();
        reopen_input.extend_from_slice(&storage_capability);
        reopen_input.extend_from_slice(commitment.as_bytes());
        reopen_input.extend_from_slice(&open_input()[ACTION_RANDOMNESS_ROOT_BYTE_LENGTH..]);
        reopen_input.extend_from_slice(&record_suffix);
        reopen_input.extend_from_slice(&envelope);
        let reopened = run_action_randomness_command(COMMAND_OPEN_SEALED, &reopen_input)
            .expect("sealed action root reopens");
        assert_eq!(&reopened[HANDLE_BYTE_LENGTH..], commitment.as_bytes());
        let reopened_handle =
            u32::from_le_bytes(reopened[..HANDLE_BYTE_LENGTH].try_into().unwrap());
        let mut reopened_attempt_input = reopened_handle.to_le_bytes().to_vec();
        reopened_attempt_input.extend_from_slice(&[0xa5; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        assert_eq!(
            run_action_randomness_command(COMMAND_FRESH_BALLOT_ATTEMPT, &reopened_attempt_input,)
                .expect("reopened session accepts the same fresh attempt identifier"),
            first_attempt,
        );

        let mut tampered_reopen = reopen_input.clone();
        let last_byte = tampered_reopen.last_mut().expect("envelope is nonempty");
        *last_byte ^= 0x01;
        assert!(run_action_randomness_command(COMMAND_OPEN_SEALED, &tampered_reopen).is_err());
        assert_eq!(
            seal_action_randomness_root(
                storage_handle,
                &storage_capability,
                LocalStorageBinding::new(
                    Hash512::from_bytes([0x11; HASH_BYTE_LENGTH]),
                    Hash512::from_bytes([0x22; HASH_BYTE_LENGTH]),
                    Hash512::from_bytes([0x33; HASH_BYTE_LENGTH]),
                    ParticipantIdentity::from_bytes([0x44; HASH_BYTE_LENGTH]),
                ),
                commitment,
                0,
                None,
                [0xe4; LOCAL_RECORD_NONCE_BYTE_LENGTH],
                &[0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
            ),
            Err(RefusalReason::ConsumedState.canonical_code() as u32),
        );
        run_action_randomness_command(COMMAND_CLOSE, &reopened_handle.to_le_bytes())
            .expect("reopened session closes");
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_RESET, &[])
            .expect("storage registry resets after test");
    }
}
