use std::{cell::RefCell, collections::HashMap};

use zeroize::Zeroizing;

use crate::bgv::setup::{
    SetupGenerationDealerPublicRecordSource, resolve_setup_generation_dealer_public_record_source,
};

use super::board_ingestion::{
    DEALER_PUBLIC_RECORD_PAYLOAD_SCHEMA_IDENTIFIER, FOUNDATION_SCHEMA_VERSION,
    PUBLIC_RANDOMNESS_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
    PUBLIC_RANDOMNESS_REVEAL_PAYLOAD_SCHEMA_IDENTIFIER, SETUP_INTENT_PAYLOAD_SCHEMA_IDENTIFIER,
};
use super::board_ingestion_runtime::{
    BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VerifiedBoardApplicationSource,
    resolve_verified_board_application_sources,
};
use super::private_randomness_runtime::with_authenticated_setup_object_source;
use super::runtime_input::{RuntimeInputReader as InputReader, refusal_status};
use super::state_runtime::{
    STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, verified_state_reservation_binding,
};
use super::{
    ActionPrivateRandomness, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, FOUNDATION_PROFILE, FoundationObjectType, Hash512,
    ML_DSA_65_SIGNATURE_BYTE_LENGTH, ObjectEnvelope, ParticipantIdentity, PrivateRandomnessDomain,
    RefusalReason, Roster, SignedCarrier, StreamDescriptor, VerifiedStateReservationRuntimeBinding,
    hash_foundation_tuple_512, signature_message,
};

pub(crate) const COMMAND_PREPARE_SETUP_INTENT_CARRIER: u32 = 17;
pub(crate) const COMMAND_PREPARE_PUBLIC_RANDOMNESS_COMMITMENT_CARRIER: u32 = 18;
pub(crate) const COMMAND_PREPARE_PUBLIC_RANDOMNESS_REVEAL_CARRIER: u32 = 19;
pub(crate) const COMMAND_FINISH_SETUP_TRANSCRIPT_CARRIER: u32 = 20;
pub(crate) const COMMAND_CANCEL_SETUP_TRANSCRIPT_CARRIER: u32 = 21;
pub(crate) const COMMAND_PREPARE_DEALER_PUBLIC_RECORD_CARRIER: u32 = 22;

const HANDLE_BYTE_LENGTH: usize = size_of::<u32>();
const PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH: usize = 32;
const PREPARED_CARRIER_DESCRIPTION_BYTE_LENGTH: usize = HANDLE_BYTE_LENGTH + Hash512::BYTE_LENGTH;
const MAXIMUM_PREPARED_CARRIER_COUNT: usize = 64;
const PUBLIC_RANDOMNESS_COMMITMENT_DOMAIN: &str =
    "sealed-lattice/setup/public-randomness-commitment/v1";
const PUBLIC_RANDOMNESS_PRIVATE_SOURCE_DOMAIN: &str =
    "sealed-lattice/setup/public-randomness-private-source/v1";

type RuntimeResult<Value> = Result<Value, u32>;

#[derive(Clone)]
struct PreparedSetupTranscriptCarrier {
    envelope: ObjectEnvelope,
    roster: Roster,
}

#[derive(Default)]
struct PreparedSetupTranscriptCarrierRegistry {
    next_handle: u32,
    records: HashMap<u32, PreparedSetupTranscriptCarrier>,
}

impl PreparedSetupTranscriptCarrierRegistry {
    fn retain(&mut self, record: PreparedSetupTranscriptCarrier) -> RuntimeResult<u32> {
        if self.records.len() >= MAXIMUM_PREPARED_CARRIER_COUNT {
            return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
        }
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        self.records.insert(self.next_handle, record);
        Ok(self.next_handle)
    }

    fn get(&self, handle: u32) -> RuntimeResult<&PreparedSetupTranscriptCarrier> {
        self.records
            .get(&handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
    }

    fn remove(&mut self, handle: u32) -> RuntimeResult<PreparedSetupTranscriptCarrier> {
        self.records
            .remove(&handle)
            .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))
    }
}

thread_local! {
    static PREPARED_CARRIER_REGISTRY: RefCell<PreparedSetupTranscriptCarrierRegistry> =
        RefCell::new(PreparedSetupTranscriptCarrierRegistry::default());
}

pub(crate) fn run_setup_transcript_command(command: u32, input: &[u8]) -> RuntimeResult<Vec<u8>> {
    match command {
        COMMAND_PREPARE_SETUP_INTENT_CARRIER => prepare_setup_intent(input),
        COMMAND_PREPARE_PUBLIC_RANDOMNESS_COMMITMENT_CARRIER => {
            prepare_public_randomness_commitment(input)
        }
        COMMAND_PREPARE_PUBLIC_RANDOMNESS_REVEAL_CARRIER => prepare_public_randomness_reveal(input),
        COMMAND_PREPARE_DEALER_PUBLIC_RECORD_CARRIER => prepare_dealer_public_record(input),
        COMMAND_FINISH_SETUP_TRANSCRIPT_CARRIER => finish_prepared_carrier(input),
        COMMAND_CANCEL_SETUP_TRANSCRIPT_CARRIER => cancel_prepared_carrier(input),
        _ => Err(refusal_status(RefusalReason::MalformedEncoding)),
    }
}

fn prepare_dealer_public_record(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let action_randomness_handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let setup_generation_authority_handle = reader.read_u32()?;
    let share_linkage_proof = StreamDescriptor::decode(
        reader.read_length_prefixed_bytes()?,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(codec_status)?;
    let ordered_recipient_envelope_hashes = (0..FOUNDATION_PROFILE.participant_count)
        .map(|_| reader.read_array().map(Hash512::from_bytes))
        .collect::<RuntimeResult<Vec<_>>>()?;
    reader.finish()?;

    with_authenticated_setup_object_source(
        action_randomness_handle,
        reservation_binding,
        |randomness, roster, roster_hash, source_roster_position| {
            let source = resolve_setup_generation_dealer_public_record_source(
                setup_generation_authority_handle,
                randomness,
                roster,
                roster_hash,
                source_roster_position,
                &ordered_recipient_envelope_hashes,
                &share_linkage_proof,
            )
            .map_err(refusal_status)?;
            let payload = encode_dealer_public_record_payload(&source)?;
            retain_prepared_carrier(
                ObjectEnvelope {
                    suite_id: source.suite_identifier(),
                    object_type: FoundationObjectType::PublicSetupRecord,
                    ceremony_context_hash: source.ceremony_context_hash(),
                    action_context_hash: source.action_context_hash(),
                    producer_participant_id: Some(source.participant_identity()),
                    producer_sequence: 0,
                    ordered_prerequisite_hashes: vec![source.public_setup_seed()],
                    payload_bytes: payload,
                },
                roster,
                roster_hash,
            )
        },
    )
}

fn encode_dealer_public_record_payload(
    source: &SetupGenerationDealerPublicRecordSource,
) -> RuntimeResult<Vec<u8>> {
    CanonicalTuple::new(
        DEALER_PUBLIC_RECORD_PAYLOAD_SCHEMA_IDENTIFIER,
        FOUNDATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(source.roster_position()),
            canonical_hash_list(source.ordered_coefficient_material_roots())?,
            canonical_hash_list(source.ordered_recipient_share_material_roots())?,
            canonical_hash_list(source.ordered_recipient_envelope_hashes())?,
            canonical_stream_descriptor_item(source.share_linkage_proof())?,
        ],
    )
    .encode()
    .map_err(codec_status)
}

fn canonical_stream_descriptor_item(descriptor: &StreamDescriptor) -> RuntimeResult<CanonicalItem> {
    let descriptor_tuple = descriptor.canonical_tuple().map_err(codec_status)?;
    CanonicalItem::nested_tuple(&descriptor_tuple).map_err(codec_status)
}

fn canonical_hash_list(hashes: &[Hash512]) -> RuntimeResult<CanonicalItem> {
    let items = hashes
        .iter()
        .map(|hash| CanonicalItem::hash512(hash.into_bytes()))
        .collect::<Vec<_>>();
    CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &items).map_err(codec_status)
}

fn prepare_setup_intent(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let action_randomness_handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    reader.finish()?;

    with_authenticated_setup_object_source(
        action_randomness_handle,
        reservation_binding,
        |randomness, roster, roster_hash, _source_roster_position| {
            let derivation = randomness.derivation_input();
            let payload = CanonicalTuple::new(
                SETUP_INTENT_PAYLOAD_SCHEMA_IDENTIFIER,
                FOUNDATION_SCHEMA_VERSION,
                vec![CanonicalItem::hash512(
                    randomness.action_randomness_commitment().into_bytes(),
                )],
            )
            .encode()
            .map_err(codec_status)?;
            retain_prepared_carrier(
                ObjectEnvelope {
                    suite_id: derivation.suite_identifier(),
                    object_type: FoundationObjectType::SetupIntent,
                    ceremony_context_hash: derivation.ceremony_context_hash(),
                    action_context_hash: derivation.action_context_hash(),
                    producer_participant_id: Some(derivation.participant_identity()),
                    producer_sequence: 0,
                    ordered_prerequisite_hashes: Vec::new(),
                    payload_bytes: payload,
                },
                roster,
                roster_hash,
            )
        },
    )
}

fn prepare_public_randomness_commitment(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let action_randomness_handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let board_session_handle = reader.read_u32()?;
    let board_capability = reader.read_array::<BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>()?;
    let setup_intent_handles = decode_handle_list(reader.read_remaining())?;

    let setup_intent_sources = resolve_verified_board_application_sources(
        board_session_handle,
        &board_capability,
        &setup_intent_handles,
    )?;
    with_authenticated_setup_object_source(
        action_randomness_handle,
        reservation_binding,
        |randomness, roster, roster_hash, source_roster_position| {
            let ordered_setup_intent_hashes = validate_ordered_setup_intents(
                randomness,
                roster,
                roster_hash,
                source_roster_position,
                &setup_intent_sources,
            )?;
            let derivation = randomness.derivation_input();
            let (contribution, salt) = derive_private_public_randomness_source(
                randomness,
                roster_hash,
                &ordered_setup_intent_hashes,
            )?;
            let contribution_commitment = derive_public_randomness_contribution_commitment(
                derivation.suite_identifier(),
                derivation.ceremony_context_hash(),
                derivation.action_context_hash(),
                derivation.participant_identity(),
                *contribution,
                *salt,
            )
            .map_err(codec_status)?;
            let payload = CanonicalTuple::new(
                PUBLIC_RANDOMNESS_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
                FOUNDATION_SCHEMA_VERSION,
                vec![CanonicalItem::hash512(contribution_commitment.into_bytes())],
            )
            .encode()
            .map_err(codec_status)?;
            retain_prepared_carrier(
                ObjectEnvelope {
                    suite_id: derivation.suite_identifier(),
                    object_type: FoundationObjectType::PublicRandomnessCommitment,
                    ceremony_context_hash: derivation.ceremony_context_hash(),
                    action_context_hash: derivation.action_context_hash(),
                    producer_participant_id: Some(derivation.participant_identity()),
                    producer_sequence: 0,
                    ordered_prerequisite_hashes: ordered_setup_intent_hashes,
                    payload_bytes: payload,
                },
                roster,
                roster_hash,
            )
        },
    )
}

fn prepare_public_randomness_reveal(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let action_randomness_handle = reader.read_u32()?;
    let reservation_binding = read_verified_reservation_binding(&mut reader)?;
    let board_session_handle = reader.read_u32()?;
    let board_capability = reader.read_array::<BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>()?;
    let setup_intent_handle = reader.read_u32()?;
    let commitment_handle = reader.read_u32()?;
    reader.finish()?;

    let sources = resolve_verified_board_application_sources(
        board_session_handle,
        &board_capability,
        &[setup_intent_handle, commitment_handle],
    )?;
    let [setup_intent_source, commitment_source] =
        <[VerifiedBoardApplicationSource; 2]>::try_from(sources)
            .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
    with_authenticated_setup_object_source(
        action_randomness_handle,
        reservation_binding,
        |randomness, roster, roster_hash, source_roster_position| {
            let ordered_setup_intent_hashes = validate_reveal_sources(
                randomness,
                roster,
                roster_hash,
                source_roster_position,
                &setup_intent_source,
                &commitment_source,
            )?;
            let derivation = randomness.derivation_input();
            let (contribution, salt) = derive_private_public_randomness_source(
                randomness,
                roster_hash,
                &ordered_setup_intent_hashes,
            )?;
            let expected_commitment = derive_public_randomness_contribution_commitment(
                derivation.suite_identifier(),
                derivation.ceremony_context_hash(),
                derivation.action_context_hash(),
                derivation.participant_identity(),
                *contribution,
                *salt,
            )
            .map_err(codec_status)?;
            let commitment_payload = commitment_source
                .public_randomness_commitment_payload()
                .map_err(refusal_status)?;
            if commitment_payload.contribution_commitment() != expected_commitment {
                return Err(refusal_status(RefusalReason::WrongHashOrRoot));
            }
            let mut contribution_and_salt = [0_u8; Hash512::BYTE_LENGTH];
            contribution_and_salt[..PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH]
                .copy_from_slice(contribution.as_ref());
            contribution_and_salt[PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH..]
                .copy_from_slice(salt.as_ref());
            let payload = CanonicalTuple::new(
                PUBLIC_RANDOMNESS_REVEAL_PAYLOAD_SCHEMA_IDENTIFIER,
                FOUNDATION_SCHEMA_VERSION,
                vec![
                    CanonicalItem::hash512(commitment_source.object_hash().into_bytes()),
                    CanonicalItem::fixed_bytes(contribution_and_salt).map_err(codec_status)?,
                ],
            )
            .encode()
            .map_err(codec_status)?;
            retain_prepared_carrier(
                ObjectEnvelope {
                    suite_id: derivation.suite_identifier(),
                    object_type: FoundationObjectType::PublicRandomnessReveal,
                    ceremony_context_hash: derivation.ceremony_context_hash(),
                    action_context_hash: derivation.action_context_hash(),
                    producer_participant_id: Some(derivation.participant_identity()),
                    producer_sequence: 0,
                    ordered_prerequisite_hashes: Vec::new(),
                    payload_bytes: payload,
                },
                roster,
                roster_hash,
            )
        },
    )
}

fn validate_ordered_setup_intents(
    randomness: &ActionPrivateRandomness,
    roster: &Roster,
    roster_hash: Hash512,
    source_roster_position: u16,
    setup_intent_sources: &[VerifiedBoardApplicationSource],
) -> RuntimeResult<Vec<Hash512>> {
    if setup_intent_sources.len() != roster.entries.len() {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let derivation = randomness.derivation_input();
    let mut hashes = Vec::with_capacity(setup_intent_sources.len());
    for (roster_position, (source, roster_entry)) in
        setup_intent_sources.iter().zip(&roster.entries).enumerate()
    {
        let expected_roster_position = u16::try_from(roster_position)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        let expected_identity = roster_entry.participant_identity().map_err(codec_status)?;
        require_source_coordinate(
            source,
            ExpectedSetupSourceCoordinate {
                object_type: FoundationObjectType::SetupIntent,
                suite_identifier: derivation.suite_identifier(),
                ceremony_context_hash: derivation.ceremony_context_hash(),
                action_context_hash: derivation.action_context_hash(),
                roster_hash,
                roster_position: expected_roster_position,
                participant_identity: expected_identity,
            },
        )?;
        if expected_roster_position == source_roster_position
            && source
                .setup_intent_payload()
                .map_err(refusal_status)?
                .action_randomness_commitment()
                != randomness.action_randomness_commitment()
        {
            return Err(refusal_status(RefusalReason::WrongHashOrRoot));
        }
        hashes.push(source.object_hash());
    }
    Ok(hashes)
}

fn validate_reveal_sources(
    randomness: &ActionPrivateRandomness,
    roster: &Roster,
    roster_hash: Hash512,
    source_roster_position: u16,
    setup_intent_source: &VerifiedBoardApplicationSource,
    commitment_source: &VerifiedBoardApplicationSource,
) -> RuntimeResult<Vec<Hash512>> {
    let derivation = randomness.derivation_input();
    let roster_entry = roster
        .entries
        .get(usize::from(source_roster_position))
        .ok_or_else(|| refusal_status(RefusalReason::WrongContext))?;
    let expected_identity = roster_entry.participant_identity().map_err(codec_status)?;
    require_source_coordinate(
        setup_intent_source,
        ExpectedSetupSourceCoordinate {
            object_type: FoundationObjectType::SetupIntent,
            suite_identifier: derivation.suite_identifier(),
            ceremony_context_hash: derivation.ceremony_context_hash(),
            action_context_hash: derivation.action_context_hash(),
            roster_hash,
            roster_position: source_roster_position,
            participant_identity: expected_identity,
        },
    )?;
    if setup_intent_source
        .setup_intent_payload()
        .map_err(refusal_status)?
        .action_randomness_commitment()
        != randomness.action_randomness_commitment()
    {
        return Err(refusal_status(RefusalReason::WrongHashOrRoot));
    }
    require_source_coordinate(
        commitment_source,
        ExpectedSetupSourceCoordinate {
            object_type: FoundationObjectType::PublicRandomnessCommitment,
            suite_identifier: derivation.suite_identifier(),
            ceremony_context_hash: derivation.ceremony_context_hash(),
            action_context_hash: derivation.action_context_hash(),
            roster_hash,
            roster_position: source_roster_position,
            participant_identity: expected_identity,
        },
    )?;
    let ordered_setup_intent_hashes = commitment_source
        .public_randomness_commitment_payload()
        .map_err(refusal_status)?
        .ordered_setup_intent_object_hashes()
        .to_vec();
    if ordered_setup_intent_hashes.len() != roster.entries.len()
        || ordered_setup_intent_hashes.get(usize::from(source_roster_position))
            != Some(&setup_intent_source.object_hash())
    {
        return Err(refusal_status(RefusalReason::WrongHashOrRoot));
    }
    Ok(ordered_setup_intent_hashes)
}

#[derive(Clone, Copy)]
struct ExpectedSetupSourceCoordinate {
    object_type: FoundationObjectType,
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    roster_position: u16,
    participant_identity: ParticipantIdentity,
}

fn require_source_coordinate(
    source: &VerifiedBoardApplicationSource,
    expected: ExpectedSetupSourceCoordinate,
) -> RuntimeResult<()> {
    if source.object_type() != expected.object_type
        || source.suite_identifier() != expected.suite_identifier
        || source.ceremony_context_hash() != expected.ceremony_context_hash
        || source.action_context_hash() != expected.action_context_hash
        || source.roster_hash() != expected.roster_hash
        || source.producer_roster_position() != Some(expected.roster_position)
        || source.producer_participant_identity() != Some(expected.participant_identity)
        || source.producer_sequence() != 0
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }
    Ok(())
}

type PrivatePublicRandomnessSourcePair = (
    Zeroizing<[u8; PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH]>,
    Zeroizing<[u8; PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH]>,
);

fn derive_private_public_randomness_source(
    randomness: &ActionPrivateRandomness,
    roster_hash: Hash512,
    ordered_setup_intent_hashes: &[Hash512],
) -> RuntimeResult<PrivatePublicRandomnessSourcePair> {
    let derivation = randomness.derivation_input();
    let hash_items = ordered_setup_intent_hashes
        .iter()
        .map(|hash| CanonicalItem::hash512(hash.into_bytes()))
        .collect::<Vec<_>>();
    let source_context_hash = hash_foundation_tuple_512(
        PUBLIC_RANDOMNESS_PRIVATE_SOURCE_DOMAIN,
        &[
            CanonicalItem::hash512(derivation.suite_identifier().into_bytes()),
            CanonicalItem::hash512(derivation.ceremony_context_hash().into_bytes()),
            CanonicalItem::hash512(derivation.action_context_hash().into_bytes()),
            CanonicalItem::hash512(roster_hash.into_bytes()),
            CanonicalItem::participant_identity(derivation.participant_identity().into_bytes()),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &hash_items)
                .map_err(codec_status)?,
        ],
    )
    .map_err(codec_status)?;
    let attempt_identifier = randomness.setup_attempt_identifier();
    let mut contribution_stream = randomness
        .begin_stream(
            PrivateRandomnessDomain::setup_source(1).map_err(codec_status)?,
            source_context_hash,
            attempt_identifier,
        )
        .map_err(codec_status)?;
    let mut salt_stream = randomness
        .begin_stream(
            PrivateRandomnessDomain::setup_source(2).map_err(codec_status)?,
            source_context_hash,
            attempt_identifier,
        )
        .map_err(codec_status)?;
    let mut contribution = Zeroizing::new([0_u8; PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH]);
    let mut salt = Zeroizing::new([0_u8; PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH]);
    contribution_stream
        .fill_bytes(contribution.as_mut())
        .map_err(codec_status)?;
    salt_stream
        .fill_bytes(salt.as_mut())
        .map_err(codec_status)?;
    Ok((contribution, salt))
}

pub(crate) fn derive_public_randomness_contribution_commitment(
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_identity: ParticipantIdentity,
    contribution: [u8; PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH],
    salt: [u8; PUBLIC_RANDOMNESS_COMPONENT_BYTE_LENGTH],
) -> Result<Hash512, super::FoundationSchemaError> {
    hash_foundation_tuple_512(
        PUBLIC_RANDOMNESS_COMMITMENT_DOMAIN,
        &[
            CanonicalItem::hash512(suite_identifier.into_bytes()),
            CanonicalItem::hash512(ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(action_context_hash.into_bytes()),
            CanonicalItem::participant_identity(participant_identity.into_bytes()),
            CanonicalItem::fixed_bytes(contribution)?,
            CanonicalItem::fixed_bytes(salt)?,
        ],
    )
    .map_err(Into::into)
}

fn retain_prepared_carrier(
    envelope: ObjectEnvelope,
    roster: &Roster,
    roster_hash: Hash512,
) -> RuntimeResult<Vec<u8>> {
    let message = signature_message(&envelope, roster_hash).map_err(codec_status)?;
    let handle = PREPARED_CARRIER_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .retain(PreparedSetupTranscriptCarrier {
                envelope,
                roster: roster.clone(),
            })
    })?;
    let mut output = Vec::with_capacity(PREPARED_CARRIER_DESCRIPTION_BYTE_LENGTH);
    output.extend_from_slice(&handle.to_le_bytes());
    output.extend_from_slice(message.as_bytes());
    Ok(output)
}

fn finish_prepared_carrier(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    let signature = reader.read_array::<ML_DSA_65_SIGNATURE_BYTE_LENGTH>()?;
    reader.finish()?;
    let carrier = PREPARED_CARRIER_REGISTRY.with(|registry| -> RuntimeResult<SignedCarrier> {
        let registry = registry.borrow();
        let record = registry.get(handle)?;
        let carrier = SignedCarrier {
            envelope: record.envelope.clone(),
            signature,
        };
        carrier
            .verify_signature(&record.roster)
            .into_result()
            .map_err(refusal_status)?;
        Ok(carrier)
    })?;
    let encoded = carrier.encode().map_err(codec_status)?;
    PREPARED_CARRIER_REGISTRY.with(|registry| registry.borrow_mut().remove(handle).map(drop))?;
    Ok(encoded)
}

fn cancel_prepared_carrier(input: &[u8]) -> RuntimeResult<Vec<u8>> {
    let mut reader = InputReader::new(input);
    let handle = reader.read_u32()?;
    reader.finish()?;
    PREPARED_CARRIER_REGISTRY.with(|registry| registry.borrow_mut().remove(handle).map(drop))?;
    Ok(Vec::new())
}

fn read_verified_reservation_binding(
    reader: &mut InputReader<'_>,
) -> RuntimeResult<VerifiedStateReservationRuntimeBinding> {
    let session_handle = reader.read_u32()?;
    let capability = reader.read_array::<STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>()?;
    let verified_reservation_handle = reader.read_u32()?;
    verified_state_reservation_binding(session_handle, &capability, verified_reservation_handle)
}

fn decode_handle_list(bytes: &[u8]) -> RuntimeResult<Vec<u32>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(HANDLE_BYTE_LENGTH) {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    }
    bytes
        .chunks_exact(HANDLE_BYTE_LENGTH)
        .map(|chunk| {
            let handle = u32::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))?,
            );
            if handle == 0 {
                return Err(refusal_status(RefusalReason::WrongTypeOrLength));
            }
            Ok(handle)
        })
        .collect()
}

fn codec_status(error: impl Into<super::FoundationSchemaError>) -> u32 {
    refusal_status(error.into().refusal_reason)
}
