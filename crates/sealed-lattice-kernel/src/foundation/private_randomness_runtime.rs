use std::{cell::RefCell, collections::HashMap};

use fips203::{
    ml_kem_768,
    traits::{Encaps, SerDes},
};
use zeroize::Zeroizing;

use super::local_storage_runtime::{
    LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH, open_action_randomness_root,
    seal_action_randomness_root,
};
use super::state_runtime::{
    STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VerifiedStateReservationRuntimeBinding,
    verified_state_reservation_binding,
};
use super::{
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionPrivateRandomness, ActionRandomnessDerivationInput,
    ActionRandomnessRoot, CanonicalDecodeLimits, Hash512, LOCAL_RECORD_NONCE_BYTE_LENGTH,
    LocalStorageBinding, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH,
    ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH, OrdinaryProofCoinInput, ParticipantIdentity,
    PersistentProofCoinInput, PrivateRandomnessDomain, ProofApplicationSlot, RefusalReason, Roster,
    StateCapabilityKind,
};

const COMMAND_OPEN: u32 = 1;
const COMMAND_CLOSE: u32 = 2;
const COMMAND_SETUP_MAILBOX_ENCAPSULATE: u32 = 3;
const COMMAND_SETUP_MAILBOX_SIGNATURE_HEDGE: u32 = 4;
const COMMAND_PERSISTENT_PROOF_ATTEMPT: u32 = 5;
const COMMAND_ORDINARY_PROOF_ATTEMPT: u32 = 6;
const COMMAND_TARGET_RELEASE_ATTEMPT: u32 = 7;
const COMMAND_FRESH_BALLOT_ATTEMPT: u32 = 8;
const COMMAND_CREATE_AND_SEAL: u32 = 9;
const COMMAND_OPEN_SEALED: u32 = 10;
const COMMAND_SETUP_ACTION_RANDOMNESS_AUTHORIZATION: u32 = 11;
const COMMAND_VALIDATE_SETUP_MAILBOX_SOURCE_KEYS: u32 = 12;

const HANDLE_BYTE_LENGTH: usize = 4;
const HASH_BYTE_LENGTH: usize = 64;
const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_ACTIVE_SESSION_COUNT: usize = 256;

pub(crate) const ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT: u32 = 0x0001_0000;
pub(crate) const ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE: u32 = 0x0001_0001;

type RuntimeResult<Value> = Result<Value, u32>;

struct ValidatedSetupMailboxRoster {
    mailbox_encapsulation_keys:
        Vec<(ParticipantIdentity, [u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH])>,
    roster_hash: Hash512,
}

#[derive(Default)]
struct ActionRandomnessRegistry {
    next_handle: u32,
    sessions: HashMap<u32, ActionPrivateRandomness>,
    setup_mailbox_rosters: HashMap<u32, ValidatedSetupMailboxRoster>,
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
            self.setup_mailbox_rosters.remove(&handle);
        }
        closed
    }

    fn retain_setup_mailbox_roster(
        &mut self,
        handle: u32,
        roster: ValidatedSetupMailboxRoster,
    ) -> RuntimeResult<()> {
        if !self.sessions.contains_key(&handle) {
            return Err(ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE);
        }
        self.setup_mailbox_rosters.insert(handle, roster);
        Ok(())
    }

    fn setup_mailbox_recipient_key(
        &self,
        handle: u32,
        roster_hash: Hash512,
        recipient_participant_identity: ParticipantIdentity,
    ) -> RuntimeResult<[u8; ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH]> {
        let roster = self
            .setup_mailbox_rosters
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
}

thread_local! {
    static ACTION_RANDOMNESS_REGISTRY: RefCell<ActionRandomnessRegistry> =
        RefCell::new(ActionRandomnessRegistry::default());
}

struct InputReader<'input> {
    bytes: &'input [u8],
    offset: usize,
}

impl<'input> InputReader<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_array<const BYTE_LENGTH: usize>(&mut self) -> RuntimeResult<[u8; BYTE_LENGTH]> {
        let end = self
            .offset
            .checked_add(BYTE_LENGTH)
            .ok_or_else(malformed_status)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(malformed_status)?;
        self.offset = end;
        bytes.try_into().map_err(|_| malformed_status())
    }

    fn read_u8(&mut self) -> RuntimeResult<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> RuntimeResult<u16> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> RuntimeResult<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> RuntimeResult<u64> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_remaining(&mut self) -> &'input [u8] {
        let remaining = &self.bytes[self.offset..];
        self.offset = self.bytes.len();
        remaining
    }

    fn finish(self) -> RuntimeResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(malformed_status())
        }
    }
}

pub(crate) fn run_action_randomness_command(
    command: u32,
    input: &[u8],
) -> RuntimeResult<Vec<u8>> {
    match command {
        COMMAND_OPEN => open(input),
        COMMAND_CLOSE => close(input),
        COMMAND_SETUP_MAILBOX_ENCAPSULATE => setup_mailbox_encapsulate(input),
        COMMAND_SETUP_MAILBOX_SIGNATURE_HEDGE => setup_mailbox_signature_hedge(input),
        COMMAND_PERSISTENT_PROOF_ATTEMPT => persistent_proof_attempt(input),
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
    let handle = ACTION_RANDOMNESS_REGISTRY.with(|registry| registry.borrow_mut().open(randomness))?;
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
    let creation_recovery_epoch = reader.read_u64()?;
    let predecessor_record_hash = read_optional_hash(&mut reader)?;
    let nonce = reader.read_array::<LOCAL_RECORD_NONCE_BYTE_LENGTH>()?;
    reader.finish()?;

    let binding = storage_binding(derivation_input);
    let randomness = ActionRandomnessRoot::from_injected_bytes(root)
        .derive(derivation_input)
        .map_err(schema_status)?;
    let commitment = randomness.action_randomness_commitment();
    let handle = ACTION_RANDOMNESS_REGISTRY.with(|registry| registry.borrow_mut().open(randomness))?;
    let sealed_envelope = ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        seal_action_randomness_root(
            storage_handle,
            &storage_capability,
            binding,
            commitment,
            record_version,
            creation_recovery_epoch,
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
    let mut output = Vec::with_capacity(HANDLE_BYTE_LENGTH + HASH_BYTE_LENGTH + sealed_envelope.len());
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
        for entry in &roster.entries {
            let participant_identity = entry.participant_identity().map_err(schema_status)?;
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
        registry.retain_setup_mailbox_roster(
            handle,
            ValidatedSetupMailboxRoster {
                mailbox_encapsulation_keys,
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
    let creation_recovery_epoch = reader.read_u64()?;
    let predecessor_record_hash = read_optional_hash(&mut reader)?;
    let canonical_envelope = reader.read_remaining();
    let root = open_action_randomness_root(
        storage_handle,
        &storage_capability,
        storage_binding(derivation_input),
        expected_commitment,
        record_version,
        creation_recovery_epoch,
        predecessor_record_hash,
        canonical_envelope,
    )?;
    let randomness = ActionRandomnessRoot::from_injected_bytes(root)
        .derive(derivation_input)
        .map_err(schema_status)?;
    if randomness.action_randomness_commitment() != expected_commitment {
        return Err(RefusalReason::WrongHashOrRoot.canonical_code() as u32);
    }
    let handle = ACTION_RANDOMNESS_REGISTRY.with(|registry| registry.borrow_mut().open(randomness))?;
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
        let mut envelope_attempt_identifier =
            [0u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH];
        envelope_attempt_stream
            .fill_bytes(&mut envelope_attempt_identifier)
            .map_err(schema_status)?;
        let mut encapsulation_coins =
            Zeroizing::new([0u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        encapsulation_coin_stream
            .fill_bytes(encapsulation_coins.as_mut())
            .map_err(schema_status)?;
        let recipient_encapsulation_key = ml_kem_768::EncapsKey::try_from_bytes(
            frozen_recipient_encapsulation_key,
        )
        .map_err(|_| RefusalReason::WrongTypeOrLength.canonical_code() as u32)?;
        let (shared_secret, ciphertext) =
            recipient_encapsulation_key.encaps_from_seed(encapsulation_coins.as_ref());
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
        let mut stream = randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_mailbox(3).map_err(schema_status)?,
                envelope_hash,
                randomness.setup_attempt_identifier(),
            )
            .map_err(schema_status)?;
        let mut output = Zeroizing::new(vec![0u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        stream.fill_bytes(&mut output).map_err(schema_status)?;
        Ok(core::mem::take(&mut *output))
    })
}

fn persistent_proof_attempt(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let statement_schema_identifier = reader.read_u16()?;
    let roster_position = reader.read_u16()?;
    let schedule_position = match reader.read_u8()? {
        0 => None,
        1 => Some(reader.read_u32()?),
        _ => return Err(malformed_status()),
    };
    let application_statement_hash = Hash512::from_bytes(reader.read_array()?);
    reader.finish()?;
    ACTION_RANDOMNESS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let randomness = registry.get(handle)?;
        require_matching_reservation(
            randomness,
            reservation_binding,
            persistent_proof_reservation_kind(statement_schema_identifier)?,
        )?;
        let derivation = randomness.derivation_input();
        let slot = ProofApplicationSlot::new(
            derivation.suite_identifier(),
            derivation.ceremony_context_hash(),
            derivation.action_context_hash(),
            statement_schema_identifier,
            Some(roster_position),
            schedule_position,
            None,
        )
        .map_err(schema_status)?;
        let input = PersistentProofCoinInput::new(slot, application_statement_hash)
            .map_err(schema_status)?;
        let attempt = randomness
            .persistent_proof_attempt_identifier(&input)
            .map_err(schema_status)?;
        slot_and_attempt_output(slot, attempt.as_bytes())
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
        let coin_input = OrdinaryProofCoinInput::new(
            slot,
            application_statement_hash,
            *attempt_nonce,
        )
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
    verified_state_reservation_binding(
        session_handle,
        &capability,
        verified_reservation_handle,
    )
}

fn persistent_proof_reservation_kind(
    statement_schema_identifier: u16,
) -> RuntimeResult<StateCapabilityKind> {
    match statement_schema_identifier {
        0x2110 => Ok(StateCapabilityKind::SetupPublicSeedBranch),
        0x2111 | 0x1211 | 0x1212 | 0x1214 | 0x1217 => {
            Ok(StateCapabilityKind::SetupDealerSetBranch)
        }
        0x1216 => Ok(StateCapabilityKind::SetupRkgRoundOneBranch),
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
        let staged = run_local_storage_root_command(
            LOCAL_STORAGE_ROOT_COMMAND_STAGE_NEW,
            &staged_input,
        )
        .expect("storage root stages");
        let storage_handle = u32::from_le_bytes(staged[..HANDLE_BYTE_LENGTH].try_into().unwrap());
        let mut commit_input = storage_handle.to_le_bytes().to_vec();
        commit_input.extend_from_slice(&storage_capability);
        commit_input.extend_from_slice(&[0xd2; 32]);
        run_local_storage_root_command(LOCAL_STORAGE_ROOT_COMMAND_COMMIT, &commit_input)
            .expect("storage root commits");

        let opened = run_action_randomness_command(COMMAND_OPEN, &open_input())
            .expect("action root opens before sealing");
        let created_handle =
            u32::from_le_bytes(opened[..HANDLE_BYTE_LENGTH].try_into().unwrap());
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
            0,
            None,
            [0xe3; LOCAL_RECORD_NONCE_BYTE_LENGTH],
            &[0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        )
        .expect("action root seals through the closed storage path");

        let mut record_suffix = Vec::with_capacity(17);
        record_suffix.extend_from_slice(&0_u64.to_le_bytes());
        record_suffix.extend_from_slice(&0_u64.to_le_bytes());
        record_suffix.push(0);
        assert!(!envelope.windows(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH).any(|window| {
            window == [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH]
        }));
        let mut first_attempt_input = created_handle.to_le_bytes().to_vec();
        first_attempt_input.extend_from_slice(&[0xa5; ATTEMPT_IDENTIFIER_BYTE_LENGTH]);
        let first_attempt = run_action_randomness_command(
            COMMAND_FRESH_BALLOT_ATTEMPT,
            &first_attempt_input,
        )
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
            run_action_randomness_command(
                COMMAND_FRESH_BALLOT_ATTEMPT,
                &reopened_attempt_input,
            )
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
