use fips204::{ml_dsa_65, traits::Signer};

use super::*;
use crate::pre_evaluation_finality::{
    StateOutputIntent, StateSubjectAuthorizationBody, StateWitnessAuthorizationBody,
    state_witness_certificate_identity,
};
use crate::{
    foundation::{
        ActionDefinition, BoardPolicy, CanonicalItem, FOUNDATION_PROFILE, Manifest,
        OptionDefinition, StabilizedDisplayText, hash_foundation_tuple_512,
    },
    tally_preparation::{
        PreprocessingSourceInconsistencyFixture320, SeedMailboxTestFixture320,
        direct_mpc_one_and_preprocessing_source_parameter_identity,
        preprocessing_source_inconsistency_fixture_320,
        preprocessing_source_joined_custody_fixture_320,
    },
};

const TEST_SIGNATURE_RANDOMNESS_DOMAIN: &str =
    "sealed-lattice/test/direct-mpc-preprocessing-source-state-kernel-signature-randomness";

#[test]
fn state_authorization_body_lengths_are_fixed() {
    let intent = StateOutputIntent::new_with_namespace(
        Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x12; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x13; Hash512::BYTE_LENGTH]),
        FOUNDATION_PROFILE.participant_count,
        "direct-mpc-preprocessing-source-terminal",
        0,
        Hash512::from_bytes([0x14; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x15; Hash512::BYTE_LENGTH]),
    )
    .unwrap();
    let witness = StateWitnessAuthorizationBody::new(intent, 1)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let subject = StateSubjectAuthorizationBody::new(
        intent,
        Hash512::from_bytes([0x16; Hash512::BYTE_LENGTH]),
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    assert_eq!(witness.len(), 170);
    assert_eq!(subject.len(), 240);
}

struct ResponseCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ResponseCursor<'a> {
    fn new(bytes: &'a [u8], expected_status: u8) -> Self {
        assert_eq!(&bytes[..4], RESPONSE_MAGIC);
        assert_eq!(
            u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            CODEC_VERSION
        );
        assert_eq!(bytes[6], expected_status);
        Self { bytes, offset: 7 }
    }

    fn read_unsigned8(&mut self) -> u8 {
        let value = self.bytes[self.offset];
        self.offset += 1;
        value
    }

    fn read_unsigned16(&mut self) -> u16 {
        let value =
            u16::from_le_bytes(self.bytes[self.offset..self.offset + 2].try_into().unwrap());
        self.offset += 2;
        value
    }

    fn read_unsigned32(&mut self) -> u32 {
        let value =
            u32::from_le_bytes(self.bytes[self.offset..self.offset + 4].try_into().unwrap());
        self.offset += 4;
        value
    }

    fn read_exact(&mut self, byte_length: usize) -> &'a [u8] {
        let value = &self.bytes[self.offset..self.offset + byte_length];
        self.offset += byte_length;
        value
    }

    fn read_bounded(&mut self) -> &'a [u8] {
        let byte_length = self.read_unsigned32() as usize;
        self.read_exact(byte_length)
    }

    fn require_complete(&self) {
        assert_eq!(self.offset, self.bytes.len());
    }
}

fn append_unsigned16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_unsigned32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
}

fn append_bounded(bytes: &mut Vec<u8>, value: &[u8]) {
    append_unsigned32(bytes, value.len());
    bytes.extend_from_slice(value);
}

fn append_optional(bytes: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            bytes.push(1);
            append_bounded(bytes, value);
        }
        None => bytes.push(0),
    }
}

fn request_header(operation: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    bytes.push(operation);
    bytes
}

fn test_manifest() -> Manifest {
    Manifest::new(
        StabilizedDisplayText::from_ingress_utf8(b"Seed source fixture").unwrap(),
        (0..FOUNDATION_PROFILE.option_count)
            .map(|option_position| {
                OptionDefinition::new(
                    option_position,
                    format!("option-{option_position}"),
                    StabilizedDisplayText::from_ingress_utf8(
                        format!("Option {option_position}").as_bytes(),
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}

fn append_foundation(bytes: &mut Vec<u8>, fixture: &SeedMailboxTestFixture320) {
    bytes.extend_from_slice(fixture.action_context.suite_id().as_bytes());
    append_bounded(bytes, &test_manifest().encode().unwrap());
    append_bounded(bytes, &fixture.roster.encode().unwrap());
    append_bounded(bytes, b"seed-source-fixture-27");
    append_bounded(bytes, b"seed-source-action-27");
    append_bounded(
        bytes,
        &ActionDefinition::new(1, 1_800_000_000_000)
            .unwrap()
            .encode()
            .unwrap(),
    );
    append_bounded(
        bytes,
        &BoardPolicy::new("board.example".to_owned())
            .unwrap()
            .encode()
            .unwrap(),
    );
}

fn append_authentication_scope(bytes: &mut Vec<u8>, fixture: &SeedMailboxTestFixture320) {
    bytes.extend_from_slice(fixture.parameter_identity.as_bytes());
    bytes.extend_from_slice(fixture.preparation_context.identity().as_bytes());
    bytes.extend_from_slice(fixture.root_terminal.identity().unwrap().as_bytes());
    append_unsigned16(bytes, 0);
    append_unsigned16(bytes, FOUNDATION_PROFILE.participant_count);
    append_unsigned16(bytes, fixture.recipient_position);
}

fn burned_authentication_record(fixture: &PreprocessingSourceInconsistencyFixture320) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(AUTHENTICATION_RECORD_MAGIC);
    append_unsigned16(&mut bytes, AUTHENTICATION_RECORD_VERSION);
    bytes.push(BURNED_AUTHENTICATION_RECORD);
    append_authentication_scope(&mut bytes, &fixture.owner);
    append_bounded(&mut bytes, &fixture.canonical_open_request_bytes);
    bytes.push(AUTHENTICATED_DELIVERY_INCONSISTENCY_REASON);
    append_unsigned16(&mut bytes, fixture.sender_position);
    append_unsigned16(&mut bytes, fixture.recipient_position);
    bytes.extend_from_slice(&fixture.disclosed_authenticated_encryption_key);
    bytes.extend_from_slice(fixture.evidence_identity.as_bytes());
    bytes
}

fn selected_authentication_record(fixture: &PreprocessingSourceInconsistencyFixture320) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(AUTHENTICATION_RECORD_MAGIC);
    append_unsigned16(&mut bytes, AUTHENTICATION_RECORD_VERSION);
    bytes.push(SELECTED_AUTHENTICATION_RECORD);
    append_authentication_scope(&mut bytes, &fixture.owner);
    append_bounded(&mut bytes, &fixture.canonical_open_request_bytes);
    bytes
}

fn joined_authentication_record(
    fixture: &SeedMailboxTestFixture320,
    receipt_terminal_identity: Hash512,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(AUTHENTICATION_RECORD_MAGIC);
    append_unsigned16(&mut bytes, AUTHENTICATION_RECORD_VERSION);
    bytes.push(JOINED_AUTHENTICATION_RECORD);
    append_authentication_scope(&mut bytes, fixture);
    bytes.extend_from_slice(receipt_terminal_identity.as_bytes());
    bytes
}

fn open_request(
    fixture: &SeedMailboxTestFixture320,
    authentication_record_bytes: &[u8],
    joined_custody_record_bytes: Option<&[u8]>,
    public_inconsistency_carrier_bytes: Option<&[u8]>,
) -> Vec<u8> {
    let mut bytes = request_header(OPEN_OUTCOME_OPERATION);
    append_foundation(&mut bytes, fixture);
    append_bounded(&mut bytes, authentication_record_bytes);
    append_optional(&mut bytes, joined_custody_record_bytes);
    append_optional(&mut bytes, public_inconsistency_carrier_bytes);
    bytes
}

fn failure_code(response: &[u8]) -> u16 {
    let mut cursor = ResponseCursor::new(response, FAILURE_STATUS);
    let code = cursor.read_unsigned16();
    cursor.require_complete();
    code
}

fn parse_open_response(response: &[u8], expected_outcome: u8) -> (u32, Vec<u8>) {
    let mut cursor = ResponseCursor::new(response, OPEN_OUTCOME_STATUS);
    let handle = cursor.read_unsigned32();
    assert_eq!(cursor.read_unsigned8(), expected_outcome);
    assert!(cursor.read_unsigned16() < FOUNDATION_PROFILE.participant_count);
    cursor.read_exact(Hash512::BYTE_LENGTH);
    assert!(!cursor.read_bounded().is_empty());
    let public_inconsistency_carrier_bytes = cursor.read_bounded().to_vec();
    cursor.require_complete();
    (handle, public_inconsistency_carrier_bytes)
}

fn sign(
    signing_key: &ml_dsa_65::PrivateKey,
    signer_position: u16,
    message: &[u8],
    signature_context: &[u8],
    marker: u8,
) -> [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH] {
    let randomness = hash_foundation_tuple_512(
        TEST_SIGNATURE_RANDOMNESS_DOMAIN,
        &[
            CanonicalItem::unsigned16(signer_position),
            CanonicalItem::unsigned16(u16::from(marker)),
            CanonicalItem::variable_bytes(signature_context).unwrap(),
            CanonicalItem::variable_bytes(message).unwrap(),
        ],
    )
    .unwrap();
    signing_key
        .try_sign_with_seed(
            &randomness.as_bytes()[..32].try_into().unwrap(),
            message,
            signature_context,
        )
        .unwrap()
}

fn witness_envelope(
    intent: StateOutputIntent,
    fixture: &SeedMailboxTestFixture320,
    witness_position: u16,
    marker: u8,
) -> Vec<u8> {
    let body = StateWitnessAuthorizationBody::new(intent, witness_position).unwrap();
    let body_bytes = body.canonical_bytes().unwrap();
    let signature = sign(
        &fixture.signing_keys[usize::from(witness_position)],
        witness_position,
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
}

fn state_output_certificate(
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
        .map(|position| witness_envelope(intent, fixture, *position, marker))
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

fn request_with_handle(operation: u8, handle: u32) -> Vec<u8> {
    let mut bytes = request_header(operation);
    bytes.extend_from_slice(&handle.to_le_bytes());
    bytes
}

#[test]
fn actual_predecessors_drive_state_messages_public_burn_and_exact_terminal_replay() {
    clear_direct_mpc_preprocessing_source_state_context_for_test();
    let parameter_identity = direct_mpc_one_and_preprocessing_source_parameter_identity().unwrap();
    let inconsistency = preprocessing_source_inconsistency_fixture_320(parameter_identity, 0);
    let authentication_record = burned_authentication_record(&inconsistency);
    let open_request_bytes = open_request(&inconsistency.owner, &authentication_record, None, None);
    let open_response = run_direct_mpc_preprocessing_source_state_kernel(&open_request_bytes);
    let (handle, public_inconsistency_carrier_bytes) =
        parse_open_response(&open_response, BURN_OUTCOME);
    assert!(!public_inconsistency_carrier_bytes.is_empty());

    let evidence = verify_pseudorandom_zero_sharing_seed_recipient_authenticated_inconsistency_320(
        &inconsistency.canonical_open_request_bytes,
        inconsistency.sender_position,
        inconsistency.recipient_position,
        inconsistency.disclosed_authenticated_encryption_key,
        inconsistency.evidence_identity,
    )
    .unwrap();
    let prepared = prepare_direct_mpc_preprocessing_source_terminal(
        &inconsistency.owner.action_context,
        &inconsistency.owner.roster,
        DirectMpcPreprocessingSourceOutcomeCandidate::Burn(&evidence),
    )
    .unwrap();

    let mut prepare_witness = request_with_handle(PREPARE_WITNESS_OPERATION, handle);
    append_unsigned16(&mut prepare_witness, 1);
    let prepared_witness_response =
        run_direct_mpc_preprocessing_source_state_kernel(&prepare_witness);
    let mut prepared_witness =
        ResponseCursor::new(&prepared_witness_response, PREPARED_WITNESS_STATUS);
    assert_eq!(
        prepared_witness.read_exact(Hash512::BYTE_LENGTH),
        prepared
            .state_output_intent(1)
            .unwrap()
            .state_key_identity()
            .as_bytes()
    );
    assert!(!prepared_witness.read_bounded().is_empty());
    let witness_body_bytes = prepared_witness.read_bounded().to_vec();
    assert_eq!(
        prepared_witness.read_bounded(),
        inconsistency.owner.roster.entries[0]
            .signing_verification_key
            .as_slice()
    );
    prepared_witness.require_complete();
    let witness_signature = sign(
        &inconsistency.owner.signing_keys[0],
        0,
        &witness_body_bytes,
        STATE_WITNESS_SIGNATURE_CONTEXT,
        0x31,
    );
    let mut complete_witness = request_with_handle(COMPLETE_WITNESS_OPERATION, handle);
    append_unsigned16(&mut complete_witness, 1);
    append_bounded(&mut complete_witness, &witness_body_bytes);
    complete_witness.extend_from_slice(&witness_signature);
    let completed_witness_response =
        run_direct_mpc_preprocessing_source_state_kernel(&complete_witness);
    let mut completed_witness =
        ResponseCursor::new(&completed_witness_response, COMPLETED_WITNESS_STATUS);
    completed_witness.read_exact(Hash512::BYTE_LENGTH);
    assert!(!completed_witness.read_bounded().is_empty());
    completed_witness.require_complete();

    let subject_intent = prepared.state_output_intent(0).unwrap();
    let witness_envelopes = (1..=FOUNDATION_PROFILE.state_witness_quorum)
        .map(|position| witness_envelope(subject_intent, &inconsistency.owner, position, 0x41))
        .collect::<Vec<_>>();
    let mut prepare_subject = request_with_handle(PREPARE_SUBJECT_OPERATION, handle);
    append_unsigned16(
        &mut prepare_subject,
        u16::try_from(witness_envelopes.len()).unwrap(),
    );
    for envelope in &witness_envelopes {
        append_bounded(&mut prepare_subject, envelope);
    }
    let prepared_subject_response =
        run_direct_mpc_preprocessing_source_state_kernel(&prepare_subject);
    let mut prepared_subject =
        ResponseCursor::new(&prepared_subject_response, PREPARED_SUBJECT_STATUS);
    assert_eq!(
        prepared_subject.read_exact(Hash512::BYTE_LENGTH),
        subject_intent.state_key_identity().as_bytes()
    );
    assert_eq!(
        prepared_subject.read_bounded(),
        subject_intent.canonical_bytes().unwrap()
    );
    let subject_body_bytes = prepared_subject.read_bounded().to_vec();
    assert_eq!(
        prepared_subject.read_bounded(),
        inconsistency.owner.roster.entries[0]
            .signing_verification_key
            .as_slice()
    );
    prepared_subject.require_complete();
    let subject_signature = sign(
        &inconsistency.owner.signing_keys[0],
        0,
        &subject_body_bytes,
        STATE_SUBJECT_SIGNATURE_CONTEXT,
        0x51,
    );
    let mut complete_subject = request_with_handle(COMPLETE_SUBJECT_OPERATION, handle);
    append_unsigned16(
        &mut complete_subject,
        u16::try_from(witness_envelopes.len()).unwrap(),
    );
    for envelope in &witness_envelopes {
        append_bounded(&mut complete_subject, envelope);
    }
    append_bounded(&mut complete_subject, &subject_body_bytes);
    complete_subject.extend_from_slice(&subject_signature);
    let completed_subject_response =
        run_direct_mpc_preprocessing_source_state_kernel(&complete_subject);
    let mut completed_subject =
        ResponseCursor::new(&completed_subject_response, COMPLETED_SUBJECT_STATUS);
    completed_subject.read_exact(Hash512::BYTE_LENGTH);
    let first_carrier = completed_subject.read_bounded().to_vec();
    completed_subject.require_complete();

    let mut carriers = vec![first_carrier];
    for subject_position in 1..FOUNDATION_PROFILE.finality_quorum {
        carriers.push(
            direct_mpc_preprocessing_source_endorsement_carrier_bytes(
                subject_position,
                &state_output_certificate(
                    prepared.state_output_intent(subject_position).unwrap(),
                    &inconsistency.owner,
                    0x61,
                ),
            )
            .unwrap(),
        );
    }
    let mut create_terminal = request_with_handle(CREATE_TERMINAL_OPERATION, handle);
    append_unsigned16(&mut create_terminal, u16::try_from(carriers.len()).unwrap());
    for carrier in &carriers {
        append_bounded(&mut create_terminal, carrier);
    }
    let terminal_response_bytes =
        run_direct_mpc_preprocessing_source_state_kernel(&create_terminal);
    let mut terminal_response = ResponseCursor::new(&terminal_response_bytes, TERMINAL_STATUS);
    assert_eq!(terminal_response.read_unsigned8(), BURN_OUTCOME);
    terminal_response.read_exact(Hash512::BYTE_LENGTH * 2);
    let terminal_bytes = terminal_response.read_bounded().to_vec();
    terminal_response.require_complete();

    let mut validate_terminal = request_with_handle(VALIDATE_TERMINAL_OPERATION, handle);
    append_bounded(&mut validate_terminal, &terminal_bytes);
    let validate_terminal_response =
        run_direct_mpc_preprocessing_source_state_kernel(&validate_terminal);
    assert_eq!(
        validate_terminal_response.as_slice(),
        terminal_response_bytes.as_slice()
    );

    let subject_position = FOUNDATION_PROFILE.finality_quorum;
    let extra_carrier = direct_mpc_preprocessing_source_endorsement_carrier_bytes(
        subject_position,
        &state_output_certificate(
            prepared.state_output_intent(subject_position).unwrap(),
            &inconsistency.owner,
            0x71,
        ),
    )
    .unwrap();
    let mut appended_carriers = carriers.clone();
    appended_carriers.push(extra_carrier);
    let appended_terminal =
        direct_mpc_preprocessing_source_terminal_bytes(prepared, &appended_carriers).unwrap();
    let mut validate_appended = request_with_handle(VALIDATE_TERMINAL_OPERATION, handle);
    append_bounded(&mut validate_appended, &appended_terminal);
    let validate_appended_response =
        run_direct_mpc_preprocessing_source_state_kernel(&validate_appended);
    assert_eq!(
        failure_code(&validate_appended_response),
        DirectMpcPreprocessingSourceStateKernelError::ConsumedState.response_code()
    );

    let close = request_with_handle(CLOSE_OUTCOME_OPERATION, handle);
    let close_response = run_direct_mpc_preprocessing_source_state_kernel(&close);
    ResponseCursor::new(&close_response, CLOSED_OUTCOME_STATUS).require_complete();

    let selected_record = selected_authentication_record(&inconsistency);
    let pending_request = open_request(&inconsistency.owner, &selected_record, None, None);
    let pending = run_direct_mpc_preprocessing_source_state_kernel(&pending_request);
    ResponseCursor::new(&pending, PENDING_OUTCOME_STATUS).require_complete();

    let joined = preprocessing_source_joined_custody_fixture_320(parameter_identity);
    let joined_record =
        joined_authentication_record(&joined.owner, joined.receipt_terminal_identity);
    let success_open_request = open_request(
        &joined.owner,
        &joined_record,
        Some(&joined.joined_record_bytes),
        None,
    );
    let success_open = run_direct_mpc_preprocessing_source_state_kernel(&success_open_request);
    let (success_handle, no_public_carrier) = parse_open_response(&success_open, SUCCESS_OUTCOME);
    assert!(no_public_carrier.is_empty());
    let close_success = request_with_handle(CLOSE_OUTCOME_OPERATION, success_handle);
    let close_success_response = run_direct_mpc_preprocessing_source_state_kernel(&close_success);
    ResponseCursor::new(&close_success_response, CLOSED_OUTCOME_STATUS).require_complete();

    let burn_from_public_carrier_request = open_request(
        &joined.owner,
        &joined_record,
        Some(&joined.joined_record_bytes),
        Some(&public_inconsistency_carrier_bytes),
    );
    let burn_from_public_carrier =
        run_direct_mpc_preprocessing_source_state_kernel(&burn_from_public_carrier_request);
    let (public_burn_handle, repeated_public_carrier) =
        parse_open_response(&burn_from_public_carrier, BURN_OUTCOME);
    assert_eq!(repeated_public_carrier, public_inconsistency_carrier_bytes);
    let close_public_burn = request_with_handle(CLOSE_OUTCOME_OPERATION, public_burn_handle);
    let close_public_burn_response =
        run_direct_mpc_preprocessing_source_state_kernel(&close_public_burn);
    ResponseCursor::new(&close_public_burn_response, CLOSED_OUTCOME_STATUS).require_complete();

    let mut wrong_foundation_request =
        open_request(&inconsistency.owner, &authentication_record, None, None);
    wrong_foundation_request[7] ^= 0x80;
    let wrong_foundation_response =
        run_direct_mpc_preprocessing_source_state_kernel(&wrong_foundation_request);
    assert_eq!(
        failure_code(&wrong_foundation_response),
        DirectMpcPreprocessingSourceStateKernelError::WrongContext.response_code()
    );

    if let Some(output_directory) =
        std::env::var_os("SEALED_LATTICE_DIRECT_MPC_SOURCE_STATE_FIXTURE_DIRECTORY")
    {
        let output_directory = std::path::PathBuf::from(output_directory);
        std::fs::create_dir_all(&output_directory).unwrap();
        for (sequence, request, response) in [
            (1, open_request_bytes.as_slice(), open_response.as_slice()),
            (
                2,
                prepare_witness.as_slice(),
                prepared_witness_response.as_slice(),
            ),
            (
                3,
                complete_witness.as_slice(),
                completed_witness_response.as_slice(),
            ),
            (
                4,
                prepare_subject.as_slice(),
                prepared_subject_response.as_slice(),
            ),
            (
                5,
                complete_subject.as_slice(),
                completed_subject_response.as_slice(),
            ),
            (
                6,
                create_terminal.as_slice(),
                terminal_response_bytes.as_slice(),
            ),
            (
                7,
                validate_terminal.as_slice(),
                validate_terminal_response.as_slice(),
            ),
            (
                8,
                validate_appended.as_slice(),
                validate_appended_response.as_slice(),
            ),
            (9, close.as_slice(), close_response.as_slice()),
            (10, pending_request.as_slice(), pending.as_slice()),
            (11, success_open_request.as_slice(), success_open.as_slice()),
            (
                12,
                close_success.as_slice(),
                close_success_response.as_slice(),
            ),
            (
                13,
                burn_from_public_carrier_request.as_slice(),
                burn_from_public_carrier.as_slice(),
            ),
            (
                14,
                close_public_burn.as_slice(),
                close_public_burn_response.as_slice(),
            ),
            (
                15,
                wrong_foundation_request.as_slice(),
                wrong_foundation_response.as_slice(),
            ),
        ] {
            std::fs::write(
                output_directory.join(format!("{sequence:02}-request.bin")),
                request,
            )
            .unwrap();
            std::fs::write(
                output_directory.join(format!("{sequence:02}-response.bin")),
                response,
            )
            .unwrap();
        }
    }
}
