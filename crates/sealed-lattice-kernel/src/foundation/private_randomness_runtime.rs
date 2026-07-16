use std::{cell::RefCell, collections::HashMap};

use fips203::{
    ml_kem_768,
    traits::{Encaps, SerDes},
};
use zeroize::Zeroizing;

use crate::bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE};
use crate::bgv::setup::{
    SETUP_COMMITMENT_HIDING_ERROR_WIDTH, SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, compute_setup_commitment_from_typed_opening,
    setup_commitment_worker_response_bytes,
};

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
    ActionRandomnessRoot, CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512,
    LOCAL_RECORD_NONCE_BYTE_LENGTH, LocalStorageBinding, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH,
    ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH, OrdinaryProofCoinInput, ParticipantIdentity,
    PersistentProofCoinInput, PrivateRandomnessDomain, ProofApplicationSlot, RefusalReason, Roster,
    SetupStructuredCommitmentOpeningContext, StateCapabilityKind,
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
const COMMAND_CREATE_STRUCTURED_COMMITMENT_OPENING: u32 = 13;
const COMMAND_RELEASE_STRUCTURED_COMMITMENT_OPENING: u32 = 14;
const COMMAND_COMPUTE_STRUCTURED_COMMITMENT: u32 = 15;
const COMMAND_SETUP_OBJECT_SIGNATURE_HEDGE: u32 = 16;

const HANDLE_BYTE_LENGTH: usize = 4;
const HASH_BYTE_LENGTH: usize = 64;
const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_ACTIVE_SESSION_COUNT: usize = 256;
const MAXIMUM_RETAINED_STRUCTURED_COMMITMENT_OPENING_COUNT: usize = 256;
const MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 64;

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
    attempt_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    application_slot: ProofApplicationSlot,
    application_slot_hash: Hash512,
    application_statement_schema_identifier: u16,
    application_statement_hash: Hash512,
    board_object_hash: Hash512,
    expected_proof_byte_length: u64,
    expected_query_count: u32,
    checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
}

impl PreparedActionProofAttemptSource {
    pub(crate) const fn attempt_identifier(&self) -> [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
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

    pub(crate) const fn board_object_hash(&self) -> Hash512 {
        self.board_object_hash
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
        let attempt_identifier = if statement_schema_identifier == 0x1621 {
            randomness
                .target_release_attempt_identifier(application_slot)
                .map_err(schema_status)?
        } else {
            let input = PersistentProofCoinInput::new(application_slot, application_statement_hash)
                .map_err(schema_status)?;
            randomness
                .persistent_proof_attempt_identifier(&input)
                .map_err(schema_status)?
        };
        Ok(PreparedActionProofAttemptSource {
            attempt_identifier: *attempt_identifier.as_bytes(),
            application_slot,
            application_slot_hash: application_slot.hash().map_err(schema_status)?,
            application_statement_schema_identifier: statement_schema_identifier,
            application_statement_hash,
            board_object_hash: board_source.object_hash(),
            expected_proof_byte_length,
            expected_query_count,
            checkpoint_continuation,
        })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StructuredCommitmentOpeningSlot {
    source_setup_intent_object_hash: Hash512,
    source_rns_limb_index: u16,
    shamir_coefficient_index: u16,
    commitment_data_prime_index: u16,
}

struct RetainedStructuredCommitmentOpening {
    hiding_secret_polynomials: Vec<Zeroizing<Vec<i8>>>,
    hiding_error_polynomials: Vec<Zeroizing<Vec<i8>>>,
    opening_handle: u32,
}

impl RetainedStructuredCommitmentOpening {
    fn has_expected_shape(&self) -> bool {
        self.hiding_secret_polynomials.len() == SETUP_COMMITMENT_HIDING_SECRET_WIDTH
            && self.hiding_error_polynomials.len() == SETUP_COMMITMENT_HIDING_ERROR_WIDTH
            && self
                .hiding_secret_polynomials
                .iter()
                .chain(&self.hiding_error_polynomials)
                .all(|polynomial| polynomial.len() == POLYNOMIAL_DEGREE)
    }
}

#[derive(Default)]
struct ActionRandomnessRegistry {
    next_handle: u32,
    next_structured_commitment_opening_handle: u32,
    sessions: HashMap<u32, ActionPrivateRandomness>,
    setup_rosters: HashMap<u32, ValidatedSetupRoster>,
    structured_commitment_opening_locations: HashMap<u32, (u32, StructuredCommitmentOpeningSlot)>,
    structured_commitment_openings:
        HashMap<u32, HashMap<StructuredCommitmentOpeningSlot, RetainedStructuredCommitmentOpening>>,
    structured_commitment_setup_intent_hashes: HashMap<u32, Hash512>,
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
        self.sessions.insert(self.next_handle, randomness);
        Ok(self.next_handle)
    }

    fn get(&self, handle: u32) -> RuntimeResult<&ActionPrivateRandomness> {
        self.sessions
            .get(&handle)
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
            self.structured_commitment_setup_intent_hashes
                .remove(&handle);
            if let Some(openings) = self.structured_commitment_openings.remove(&handle) {
                for opening in openings.values() {
                    self.structured_commitment_opening_locations
                        .remove(&opening.opening_handle);
                }
            }
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

    fn retain_structured_commitment_opening(
        &mut self,
        action_randomness_handle: u32,
        slot: StructuredCommitmentOpeningSlot,
        mut opening: RetainedStructuredCommitmentOpening,
    ) -> RuntimeResult<u32> {
        if !self.sessions.contains_key(&action_randomness_handle) {
            return Err(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE);
        }
        if let Some(pinned_hash) = self
            .structured_commitment_setup_intent_hashes
            .get(&action_randomness_handle)
        {
            if *pinned_hash != slot.source_setup_intent_object_hash {
                return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
            }
        } else {
            self.structured_commitment_setup_intent_hashes.insert(
                action_randomness_handle,
                slot.source_setup_intent_object_hash,
            );
        }
        if let Some(retained) = self
            .structured_commitment_openings
            .get(&action_randomness_handle)
            .and_then(|openings| openings.get(&slot))
        {
            if !retained.has_expected_shape() {
                return Err(RefusalReason::ConsumedState.canonical_code() as u32);
            }
            return Ok(retained.opening_handle);
        }
        if self.structured_commitment_opening_locations.len()
            >= MAXIMUM_RETAINED_STRUCTURED_COMMITMENT_OPENING_COUNT
        {
            return Err(ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT);
        }
        self.next_structured_commitment_opening_handle = self
            .next_structured_commitment_opening_handle
            .checked_add(1)
            .ok_or(ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT)?;
        opening.opening_handle = self.next_structured_commitment_opening_handle;
        self.structured_commitment_opening_locations
            .insert(opening.opening_handle, (action_randomness_handle, slot));
        self.structured_commitment_openings
            .entry(action_randomness_handle)
            .or_default()
            .insert(slot, opening);
        Ok(self.next_structured_commitment_opening_handle)
    }

    fn existing_structured_commitment_opening_handles(
        &self,
        action_randomness_handle: u32,
        slots: &[StructuredCommitmentOpeningSlot],
    ) -> RuntimeResult<Vec<Option<u32>>> {
        if !self.sessions.contains_key(&action_randomness_handle) {
            return Err(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE);
        }
        let Some(first_slot) = slots.first() else {
            return Err(RefusalReason::MissingPrerequisite.canonical_code() as u32);
        };
        if slots.iter().any(|slot| {
            slot.source_setup_intent_object_hash != first_slot.source_setup_intent_object_hash
        }) || self
            .structured_commitment_setup_intent_hashes
            .get(&action_randomness_handle)
            .is_some_and(|pinned_hash| *pinned_hash != first_slot.source_setup_intent_object_hash)
        {
            return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
        }
        let mut handles = Vec::with_capacity(slots.len());
        let mut fresh_opening_count = 0usize;
        for slot in slots {
            if let Some(retained) = self
                .structured_commitment_openings
                .get(&action_randomness_handle)
                .and_then(|openings| openings.get(slot))
            {
                if !retained.has_expected_shape() {
                    return Err(RefusalReason::ConsumedState.canonical_code() as u32);
                }
                handles.push(Some(retained.opening_handle));
            } else {
                fresh_opening_count = fresh_opening_count
                    .checked_add(1)
                    .ok_or(ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT)?;
                handles.push(None);
            }
        }
        if self
            .structured_commitment_opening_locations
            .len()
            .checked_add(fresh_opening_count)
            .is_none_or(|opening_count| {
                opening_count > MAXIMUM_RETAINED_STRUCTURED_COMMITMENT_OPENING_COUNT
            })
            || self
                .next_structured_commitment_opening_handle
                .checked_add(
                    u32::try_from(fresh_opening_count)
                        .map_err(|_| ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT)?,
                )
                .is_none()
        {
            return Err(ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT);
        }
        Ok(handles)
    }

    fn release_structured_commitment_opening(
        &mut self,
        action_randomness_handle: u32,
        opening_handle: u32,
    ) -> RuntimeResult<()> {
        let Some((owner_handle, slot)) = self
            .structured_commitment_opening_locations
            .get(&opening_handle)
            .copied()
        else {
            return Err(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE);
        };
        if owner_handle != action_randomness_handle {
            return Err(RefusalReason::WrongContext.canonical_code() as u32);
        }
        self.structured_commitment_opening_locations
            .remove(&opening_handle);
        let openings = self
            .structured_commitment_openings
            .get_mut(&action_randomness_handle)
            .ok_or(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE)?;
        openings
            .remove(&slot)
            .ok_or(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE)?;
        if openings.is_empty() {
            self.structured_commitment_openings
                .remove(&action_randomness_handle);
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

pub(crate) fn run_action_randomness_command(command: u32, input: &[u8]) -> RuntimeResult<Vec<u8>> {
    match command {
        COMMAND_OPEN => open(input),
        COMMAND_CLOSE => close(input),
        COMMAND_SETUP_MAILBOX_ENCAPSULATE => setup_mailbox_encapsulate(input),
        COMMAND_SETUP_MAILBOX_SIGNATURE_HEDGE => setup_mailbox_signature_hedge(input),
        COMMAND_CREATE_STRUCTURED_COMMITMENT_OPENING => create_structured_commitment_opening(input),
        COMMAND_RELEASE_STRUCTURED_COMMITMENT_OPENING => {
            release_structured_commitment_opening(input)
        }
        COMMAND_COMPUTE_STRUCTURED_COMMITMENT => compute_structured_commitment(input),
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

fn create_structured_commitment_opening(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let action_randomness_handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let roster_hash = Hash512::from_bytes(reader.read_array()?);
    let source_roster_position = reader.read_u16()?;
    let source_setup_intent_object_hash = Hash512::from_bytes(reader.read_array()?);
    let source_rns_limb_index = reader.read_u16()?;
    let shamir_coefficient_index = reader.read_u16()?;
    reader.finish()?;

    let source_rns_limb_position = usize::from(source_rns_limb_index);
    if source_rns_limb_position >= DATA_PRIMES.len()
        || shamir_coefficient_index >= FOUNDATION_PROFILE.reconstruction_threshold
    {
        return Err(RefusalReason::WrongTypeOrLength.canonical_code() as u32);
    }
    let slots = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .copied()
        .map(|commitment_data_prime_index| {
            Ok(StructuredCommitmentOpeningSlot {
                source_setup_intent_object_hash,
                source_rns_limb_index,
                shamir_coefficient_index,
                commitment_data_prime_index: u16::try_from(commitment_data_prime_index)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile.canonical_code() as u32)?,
            })
        })
        .collect::<RuntimeResult<Vec<_>>>()?;

    let existing_handles = ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(action_randomness_handle)?;
        require_matching_setup_action_randomness_reservation(
            randomness,
            reservation_binding,
            roster_hash,
        )?;
        registry.setup_source_matches_roster_position(
            action_randomness_handle,
            roster_hash,
            source_roster_position,
            randomness.derivation_input().participant_identity(),
        )?;
        registry.existing_structured_commitment_opening_handles(action_randomness_handle, &slots)
    })?;
    if existing_handles.iter().all(Option::is_some) {
        let mut output = Vec::with_capacity(HANDLE_BYTE_LENGTH * existing_handles.len());
        for existing_handle in existing_handles {
            let handle =
                existing_handle.ok_or(RefusalReason::ConsumedState.canonical_code() as u32)?;
            output.extend_from_slice(&handle.to_le_bytes());
        }
        return Ok(output);
    }

    let fresh_openings = ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(action_randomness_handle)?;
        slots
            .iter()
            .copied()
            .zip(existing_handles.iter())
            .filter_map(|(slot, existing_handle)| existing_handle.is_none().then_some(slot))
            .map(|slot| {
                Ok((
                    slot,
                    derive_structured_commitment_opening(randomness, slot)?,
                ))
            })
            .collect::<RuntimeResult<Vec<_>>>()
    })?;
    let fresh_handles = ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        fresh_openings
            .into_iter()
            .map(|(slot, opening)| {
                registry.retain_structured_commitment_opening(
                    action_randomness_handle,
                    slot,
                    opening,
                )
            })
            .collect::<RuntimeResult<Vec<_>>>()
    })?;
    let mut fresh_handle_iterator = fresh_handles.into_iter();
    let mut output = Vec::with_capacity(HANDLE_BYTE_LENGTH * existing_handles.len());
    for existing_handle in existing_handles {
        let handle = match existing_handle {
            Some(handle) => handle,
            None => fresh_handle_iterator
                .next()
                .ok_or(RefusalReason::ConsumedState.canonical_code() as u32)?,
        };
        output.extend_from_slice(&handle.to_le_bytes());
    }
    if fresh_handle_iterator.next().is_some() {
        return Err(RefusalReason::ConsumedState.canonical_code() as u32);
    }
    Ok(output)
}

fn release_structured_commitment_opening(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let action_randomness_handle = reader.read_u32()?;
    let opening_handle = reader.read_u32()?;
    reader.finish()?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .release_structured_commitment_opening(action_randomness_handle, opening_handle)
    })?;
    Ok(Vec::new())
}

fn derive_structured_commitment_opening(
    randomness: &ActionPrivateRandomness,
    slot: StructuredCommitmentOpeningSlot,
) -> RuntimeResult<RetainedStructuredCommitmentOpening> {
    let attempt_identifier = randomness.setup_attempt_identifier();
    let mut hiding_secret_polynomials = Vec::with_capacity(SETUP_COMMITMENT_HIDING_SECRET_WIDTH);
    for component_ordinal in 0..SETUP_COMMITMENT_HIDING_SECRET_WIDTH {
        let context = SetupStructuredCommitmentOpeningContext::new(
            slot.source_setup_intent_object_hash,
            slot.source_rns_limb_index,
            slot.shamir_coefficient_index,
            slot.commitment_data_prime_index,
            11,
            u16::try_from(component_ordinal).map_err(|_| malformed_status())?,
        )
        .map_err(schema_status)?;
        let mut stream = randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_suite_distribution(11).map_err(schema_status)?,
                context.hash().map_err(schema_status)?,
                attempt_identifier,
            )
            .map_err(schema_status)?;
        let mut polynomial = Zeroizing::new(Vec::with_capacity(POLYNOMIAL_DEGREE));
        for _ in 0..POLYNOMIAL_DEGREE {
            polynomial.push(
                stream
                    .sample_centered_ternary(MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT)
                    .map_err(schema_status)?,
            );
        }
        hiding_secret_polynomials.push(polynomial);
    }

    let mut hiding_error_polynomials = Vec::with_capacity(SETUP_COMMITMENT_HIDING_ERROR_WIDTH);
    for component_ordinal in 0..SETUP_COMMITMENT_HIDING_ERROR_WIDTH {
        let context = SetupStructuredCommitmentOpeningContext::new(
            slot.source_setup_intent_object_hash,
            slot.source_rns_limb_index,
            slot.shamir_coefficient_index,
            slot.commitment_data_prime_index,
            12,
            u16::try_from(component_ordinal).map_err(|_| malformed_status())?,
        )
        .map_err(schema_status)?;
        let mut stream = randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_suite_distribution(12).map_err(schema_status)?,
                context.hash().map_err(schema_status)?,
                attempt_identifier,
            )
            .map_err(schema_status)?;
        let mut polynomial = Zeroizing::new(Vec::with_capacity(POLYNOMIAL_DEGREE));
        for _ in 0..POLYNOMIAL_DEGREE {
            let coefficient = stream.sample_centered_binomial(2).map_err(schema_status)?;
            polynomial.push(
                i8::try_from(coefficient).map_err(|_| {
                    RefusalReason::InvalidArithmeticRelation.canonical_code() as u32
                })?,
            );
        }
        hiding_error_polynomials.push(polynomial);
    }

    Ok(RetainedStructuredCommitmentOpening {
        hiding_secret_polynomials,
        hiding_error_polynomials,
        opening_handle: 0,
    })
}

fn compute_structured_commitment(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let action_randomness_handle = reader.read_u32()?;
    let public_matrix_seed_hash = Hash512::from_bytes(reader.read_array()?);
    let mut opening_handles = [0_u32; SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()];
    for opening_handle in &mut opening_handles {
        *opening_handle = reader.read_u32()?;
    }
    let message_coefficient_count =
        usize::try_from(reader.read_u32()?).map_err(|_| malformed_status())?;
    if message_coefficient_count != POLYNOMIAL_DEGREE {
        return Err(RefusalReason::WrongTypeOrLength.canonical_code() as u32);
    }
    let mut message_coefficients = Vec::with_capacity(message_coefficient_count);
    for _ in 0..message_coefficient_count {
        message_coefficients.push(u128::from(reader.read_u64()?));
    }
    reader.finish()?;

    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        registry.get(action_randomness_handle)?;
        let mut common_slot = None;
        let mut randomness_by_commitment_limb =
            Vec::with_capacity(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len());
        for (commitment_limb_position, opening_handle) in
            opening_handles.iter().copied().enumerate()
        {
            let (owner_handle, slot) = registry
                .structured_commitment_opening_locations
                .get(&opening_handle)
                .copied()
                .ok_or(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE)?;
            if owner_handle != action_randomness_handle
                || usize::from(slot.commitment_data_prime_index)
                    != SETUP_COMMITMENT_MODULUS_LIMB_INDICES[commitment_limb_position]
            {
                return Err(RefusalReason::WrongContext.canonical_code() as u32);
            }
            if let Some(expected_slot) = common_slot {
                let expected_slot: StructuredCommitmentOpeningSlot = expected_slot;
                if slot.source_setup_intent_object_hash
                    != expected_slot.source_setup_intent_object_hash
                    || slot.source_rns_limb_index != expected_slot.source_rns_limb_index
                    || slot.shamir_coefficient_index != expected_slot.shamir_coefficient_index
                {
                    return Err(RefusalReason::WrongContext.canonical_code() as u32);
                }
            } else {
                common_slot = Some(slot);
            }
            let retained = registry
                .structured_commitment_openings
                .get(&action_randomness_handle)
                .and_then(|openings| openings.get(&slot))
                .ok_or(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE)?;
            if !retained.has_expected_shape() {
                return Err(RefusalReason::ConsumedState.canonical_code() as u32);
            }
            randomness_by_commitment_limb.push(
                retained
                    .hiding_secret_polynomials
                    .iter()
                    .chain(&retained.hiding_error_polynomials)
                    .map(|polynomial| {
                        polynomial
                            .iter()
                            .copied()
                            .map(i128::from)
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            );
        }
        let slot = common_slot.ok_or(RefusalReason::MissingPrerequisite.canonical_code() as u32)?;
        let commitment = compute_setup_commitment_from_typed_opening(
            &public_matrix_seed_hash.to_lowercase_hex(),
            usize::from(slot.source_rns_limb_index),
            u64::from(slot.shamir_coefficient_index),
            &message_coefficients,
            &randomness_by_commitment_limb,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation.canonical_code() as u32)?;
        setup_commitment_worker_response_bytes(&commitment)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation.canonical_code() as u32)
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
        0x2110 | 0x2111 | 0x1211 | 0x1212 | 0x1214 | 0x1216 | 0x1217 => {
            Ok(StateCapabilityKind::SetupActionRandomnessRoot)
        }
        0x1621 => Ok(StateCapabilityKind::TargetRelease),
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
    fn structured_commitment_opening_derivation_is_reset_safe_and_uses_exact_supports() {
        let randomness = fixed_action_randomness();
        let slot = StructuredCommitmentOpeningSlot {
            source_setup_intent_object_hash: Hash512::from_bytes([0x71; HASH_BYTE_LENGTH]),
            source_rns_limb_index: 4,
            shamir_coefficient_index: 2,
            commitment_data_prime_index: 1,
        };
        let first = derive_structured_commitment_opening(&randomness, slot)
            .expect("first structured opening derives");
        let replay = derive_structured_commitment_opening(&randomness, slot)
            .expect("same structured opening re-derives after reset");

        assert!(first.has_expected_shape());
        assert_eq!(
            first.hiding_secret_polynomials,
            replay.hiding_secret_polynomials
        );
        assert_eq!(
            first.hiding_error_polynomials,
            replay.hiding_error_polynomials
        );
        assert!(
            first
                .hiding_secret_polynomials
                .iter()
                .flat_map(|polynomial| polynomial.iter())
                .all(|coefficient| (-1..=1).contains(coefficient))
        );
        assert!(
            first
                .hiding_error_polynomials
                .iter()
                .flat_map(|polynomial| polynomial.iter())
                .all(|coefficient| (-2..=2).contains(coefficient))
        );
        assert!(
            first
                .hiding_error_polynomials
                .iter()
                .flat_map(|polynomial| polynomial.iter())
                .any(|coefficient| coefficient.unsigned_abs() == 2),
            "eta-two output must not collapse to the legacy ternary profile",
        );

        let changed_prime = derive_structured_commitment_opening(
            &randomness,
            StructuredCommitmentOpeningSlot {
                commitment_data_prime_index: 2,
                ..slot
            },
        )
        .expect("changed commitment-prime opening derives");
        assert_ne!(
            first.hiding_secret_polynomials,
            changed_prime.hiding_secret_polynomials
        );
        assert_ne!(
            first.hiding_error_polynomials,
            changed_prime.hiding_error_polynomials
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
