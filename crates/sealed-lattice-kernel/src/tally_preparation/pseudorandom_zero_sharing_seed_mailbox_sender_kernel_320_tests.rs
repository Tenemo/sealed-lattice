use fips204::traits::Signer;

use crate::foundation::{FOUNDATION_PROFILE, Hash512};

use super::{
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        SeedMailboxTestFixture320, seed_mailbox_test_fixture_320,
    },
    pseudorandom_zero_sharing_seed_mailbox_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_CONTEXT,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        PseudorandomZeroSharingSeedMailboxVerifier320,
        pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length,
    },
    pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320::{
        clear_pseudorandom_zero_sharing_seed_mailbox_sender_contexts_for_test_320,
        response_signature_body_byte_length_for_test_320,
        run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320,
    },
};

const CODEC_VERSION: u16 = 1;
const OPEN_CONTEXT_OPERATION: u8 = 1;
const PREPARE_CARRIER_OPERATION: u8 = 2;
const COMPLETE_CARRIER_OPERATION: u8 = 3;
const VALIDATE_CARRIER_OPERATION: u8 = 4;
const CLOSE_CONTEXT_OPERATION: u8 = 5;
const FAILURE_STATUS: u8 = 0;
const OPEN_CONTEXT_STATUS: u8 = 1;
const PREPARED_CARRIER_STATUS: u8 = 2;
const COMPLETE_CARRIER_STATUS: u8 = 3;
const VALIDATION_STATUS: u8 = 4;
const CLOSED_CONTEXT_STATUS: u8 = 5;

struct PreparedCarrierBytes320 {
    header_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
    signature_body_bytes: Vec<u8>,
    encrypted_chunks: Vec<Vec<u8>>,
}

struct CompleteCarrierBytes320 {
    header_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
    signature_envelope_bytes: Vec<u8>,
    encrypted_chunks: Vec<Vec<u8>>,
}

struct ResponseCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ResponseCursor<'a> {
    fn new(bytes: &'a [u8], expected_status: u8) -> Self {
        assert!(bytes.len() >= 7);
        assert_eq!(&bytes[..4], b"SLMR");
        assert_eq!(
            u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            CODEC_VERSION
        );
        assert_eq!(bytes[6], expected_status);
        Self { bytes, offset: 7 }
    }

    fn read_unsigned16(&mut self) -> u16 {
        let value =
            u16::from_le_bytes(self.bytes[self.offset..self.offset + 2].try_into().unwrap());
        self.offset += 2;
        value
    }

    fn read_unsigned32(&mut self) -> usize {
        let value =
            u32::from_le_bytes(self.bytes[self.offset..self.offset + 4].try_into().unwrap());
        self.offset += 4;
        usize::try_from(value).unwrap()
    }

    fn read_exact(&mut self, byte_length: usize) -> Vec<u8> {
        let value = self.bytes[self.offset..self.offset + byte_length].to_vec();
        self.offset += byte_length;
        value
    }

    fn read_bounded(&mut self) -> Vec<u8> {
        let byte_length = self.read_unsigned32();
        self.read_exact(byte_length)
    }

    fn read_chunks(&mut self) -> Vec<Vec<u8>> {
        let count = usize::from(self.read_unsigned16());
        (0..count).map(|_| self.read_bounded()).collect()
    }

    fn require_complete(self) {
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

fn request_header(operation: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SLMQ");
    append_unsigned16(&mut bytes, CODEC_VERSION);
    bytes.push(operation);
    bytes
}

fn open_request(fixture: &SeedMailboxTestFixture320) -> Vec<u8> {
    let mut bytes = request_header(OPEN_CONTEXT_OPERATION);
    bytes.extend_from_slice(fixture.parameter_identity.as_bytes());
    append_unsigned16(&mut bytes, fixture.sender_position);
    append_bounded(&mut bytes, &fixture.preparation_context.canonical_bytes());
    append_bounded(&mut bytes, &fixture.roster.encode().unwrap());
    append_unsigned16(
        &mut bytes,
        u16::try_from(fixture.root_authorization_packages.len()).unwrap(),
    );
    for package in &fixture.root_authorization_packages {
        append_bounded(&mut bytes, &package.root_body_bytes);
        append_bounded(&mut bytes, &package.reservation_certificate_bytes);
        append_bounded(&mut bytes, &package.exact_output_certificate_bytes);
        append_bounded(&mut bytes, &package.contributor_signature_envelope_bytes);
    }
    append_bounded(&mut bytes, &fixture.root_terminal_certificate_bytes);
    bytes
}

fn open_context(fixture: &SeedMailboxTestFixture320) -> u32 {
    let response =
        run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&open_request(fixture));
    let mut cursor = ResponseCursor::new(&response, OPEN_CONTEXT_STATUS);
    let handle = u32::try_from(cursor.read_unsigned32()).unwrap();
    let verification_key = cursor.read_exact(
        fixture.roster.entries[usize::from(fixture.sender_position)]
            .signing_verification_key
            .len(),
    );
    assert_eq!(
        verification_key,
        fixture.roster.entries[usize::from(fixture.sender_position)].signing_verification_key
    );
    cursor.require_complete();
    handle
}

fn append_stream_context(
    bytes: &mut Vec<u8>,
    fixture: &SeedMailboxTestFixture320,
    parameter_identity: Hash512,
) {
    bytes.extend_from_slice(parameter_identity.as_bytes());
    append_unsigned16(bytes, FOUNDATION_PROFILE.participant_count);
    append_unsigned16(bytes, 0);
    bytes.extend_from_slice(fixture.preparation_context.identity().as_bytes());
    bytes.extend_from_slice(fixture.root_terminal.identity().unwrap().as_bytes());
    append_unsigned16(bytes, fixture.sender_position);
    append_unsigned16(bytes, fixture.recipient_position);
}

fn prepare_request(
    fixture: &SeedMailboxTestFixture320,
    handle: u32,
    parameter_identity: Hash512,
    encapsulation_randomness: [u8; 32],
) -> Vec<u8> {
    let mut bytes = request_header(PREPARE_CARRIER_OPERATION);
    append_unsigned32(&mut bytes, usize::try_from(handle).unwrap());
    append_stream_context(&mut bytes, fixture, parameter_identity);
    append_bounded(&mut bytes, &fixture.descriptor_bytes);
    bytes.extend_from_slice(&encapsulation_randomness);
    append_bounded(&mut bytes, &fixture.payload_bytes);
    bytes
}

fn parse_prepared_response(response: &[u8]) -> PreparedCarrierBytes320 {
    let mut cursor = ResponseCursor::new(response, PREPARED_CARRIER_STATUS);
    let prepared = PreparedCarrierBytes320 {
        header_bytes: cursor.read_bounded(),
        manifest_bytes: cursor.read_bounded(),
        signature_body_bytes: cursor.read_bounded(),
        encrypted_chunks: cursor.read_chunks(),
    };
    cursor.require_complete();
    prepared
}

fn complete_request(
    fixture: &SeedMailboxTestFixture320,
    handle: u32,
    prepared: &PreparedCarrierBytes320,
    signature: &[u8],
) -> Vec<u8> {
    let mut bytes = request_header(COMPLETE_CARRIER_OPERATION);
    append_unsigned32(&mut bytes, usize::try_from(handle).unwrap());
    append_stream_context(&mut bytes, fixture, fixture.parameter_identity);
    append_bounded(&mut bytes, &fixture.descriptor_bytes);
    append_bounded(&mut bytes, &prepared.header_bytes);
    append_bounded(&mut bytes, &prepared.manifest_bytes);
    append_unsigned16(
        &mut bytes,
        u16::try_from(prepared.encrypted_chunks.len()).unwrap(),
    );
    for encrypted_chunk in &prepared.encrypted_chunks {
        append_bounded(&mut bytes, encrypted_chunk);
    }
    bytes.extend_from_slice(signature);
    bytes
}

fn parse_complete_response(response: &[u8]) -> CompleteCarrierBytes320 {
    let mut cursor = ResponseCursor::new(response, COMPLETE_CARRIER_STATUS);
    let carrier = CompleteCarrierBytes320 {
        header_bytes: cursor.read_bounded(),
        manifest_bytes: cursor.read_bounded(),
        signature_envelope_bytes: cursor.read_bounded(),
        encrypted_chunks: cursor.read_chunks(),
    };
    cursor.require_complete();
    carrier
}

fn validate_request(
    fixture: &SeedMailboxTestFixture320,
    handle: u32,
    carrier: &CompleteCarrierBytes320,
    total_carrier_byte_length_adjustment: isize,
) -> Vec<u8> {
    let mut bytes = request_header(VALIDATE_CARRIER_OPERATION);
    append_unsigned32(&mut bytes, usize::try_from(handle).unwrap());
    append_stream_context(&mut bytes, fixture, fixture.parameter_identity);
    append_bounded(&mut bytes, &fixture.descriptor_bytes);
    append_unsigned32(&mut bytes, fixture.payload_bytes.len());
    let total_carrier_byte_length = carrier.header_bytes.len()
        + carrier.manifest_bytes.len()
        + carrier.signature_envelope_bytes.len()
        + carrier.encrypted_chunks.iter().map(Vec::len).sum::<usize>();
    append_unsigned32(
        &mut bytes,
        total_carrier_byte_length
            .checked_add_signed(total_carrier_byte_length_adjustment)
            .unwrap(),
    );
    append_unsigned32(&mut bytes, carrier.header_bytes.len());
    append_unsigned32(&mut bytes, carrier.manifest_bytes.len());
    append_unsigned32(&mut bytes, carrier.signature_envelope_bytes.len());
    append_unsigned16(
        &mut bytes,
        u16::try_from(carrier.encrypted_chunks.len()).unwrap(),
    );
    for encrypted_chunk in &carrier.encrypted_chunks {
        append_unsigned32(&mut bytes, encrypted_chunk.len());
    }
    append_bounded(&mut bytes, &carrier.header_bytes);
    append_bounded(&mut bytes, &carrier.manifest_bytes);
    append_bounded(&mut bytes, &carrier.signature_envelope_bytes);
    append_unsigned16(
        &mut bytes,
        u16::try_from(carrier.encrypted_chunks.len()).unwrap(),
    );
    for encrypted_chunk in &carrier.encrypted_chunks {
        append_bounded(&mut bytes, encrypted_chunk);
    }
    bytes
}

fn sign_prepared(
    fixture: &SeedMailboxTestFixture320,
    prepared: &PreparedCarrierBytes320,
    randomness: [u8; 32],
) -> Vec<u8> {
    fixture.signing_keys[usize::from(fixture.sender_position)]
        .try_sign_with_seed(
            &randomness,
            &prepared.signature_body_bytes,
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_CONTEXT,
        )
        .unwrap()
        .to_vec()
}

fn failure_code(response: &[u8]) -> u16 {
    let mut cursor = ResponseCursor::new(response, FAILURE_STATUS);
    let code = cursor.read_unsigned16();
    cursor.require_complete();
    code
}

#[test]
fn completion_sender_context_produces_replays_and_verifies_exact_carrier() {
    clear_pseudorandom_zero_sharing_seed_mailbox_sender_contexts_for_test_320();
    let fixture = seed_mailbox_test_fixture_320(2, 7);
    let handle = open_context(&fixture);
    let prepare_bytes = prepare_request(&fixture, handle, fixture.parameter_identity, [0x91; 32]);
    let first_prepared_response =
        run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&prepare_bytes);
    let second_prepared_response =
        run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&prepare_bytes);
    assert_eq!(first_prepared_response, second_prepared_response);
    let prepared = parse_prepared_response(&first_prepared_response);
    assert_eq!(
        prepared.signature_body_bytes.len(),
        response_signature_body_byte_length_for_test_320()
    );
    assert_eq!(
        prepared.header_bytes.len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH
    );
    assert_eq!(prepared.encrypted_chunks.len(), 1);
    let signature = sign_prepared(&fixture, &prepared, [0xa1; 32]);
    let complete_response = run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(
        &complete_request(&fixture, handle, &prepared, &signature),
    );
    let carrier = parse_complete_response(&complete_response);
    assert_eq!(
        carrier.manifest_bytes.len(),
        pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length(1).unwrap()
    );
    assert_eq!(
        carrier.signature_envelope_bytes.len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH
    );
    let validation_response = run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(
        &validate_request(&fixture, handle, &carrier, 0),
    );
    ResponseCursor::new(&validation_response, VALIDATION_STATUS).require_complete();

    let mut recipient_verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new(
        &fixture.root_terminal,
        &fixture.roster,
        fixture.sender_position,
        fixture.recipient_position,
        &carrier.header_bytes,
        &carrier.manifest_bytes,
        &carrier.signature_envelope_bytes,
        &fixture.mailbox_decapsulation_keys[usize::from(fixture.recipient_position)],
    )
    .unwrap();
    for encrypted_chunk in &carrier.encrypted_chunks {
        recipient_verifier
            .absorb_next_encrypted_chunk(encrypted_chunk)
            .unwrap();
    }
    let authenticated_delivery = recipient_verifier.finish().unwrap();
    assert_eq!(
        authenticated_delivery
            .delivery()
            .descriptor()
            .sender_position(),
        fixture.sender_position
    );

    let mut close_request = request_header(CLOSE_CONTEXT_OPERATION);
    append_unsigned32(&mut close_request, usize::try_from(handle).unwrap());
    let close_response =
        run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&close_request);
    ResponseCursor::new(&close_response, CLOSED_CONTEXT_STATUS).require_complete();
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&validate_request(
                &fixture, handle, &carrier, 0
            ))
        ),
        7
    );
}

#[test]
fn sender_kernel_refuses_wrong_context_signature_chunk_and_geometry() {
    clear_pseudorandom_zero_sharing_seed_mailbox_sender_contexts_for_test_320();
    let fixture = seed_mailbox_test_fixture_320(1, 8);
    let handle = open_context(&fixture);
    let mut wrong_parameter = fixture.parameter_identity.into_bytes();
    wrong_parameter[0] ^= 1;
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&prepare_request(
                &fixture,
                handle,
                Hash512::from_bytes(wrong_parameter),
                [0x31; 32]
            ))
        ),
        3
    );

    let prepared = parse_prepared_response(
        &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&prepare_request(
            &fixture,
            handle,
            fixture.parameter_identity,
            [0x31; 32],
        )),
    );
    let mut wrong_signature = sign_prepared(&fixture, &prepared, [0x41; 32]);
    wrong_signature[17] ^= 1;
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&complete_request(
                &fixture,
                handle,
                &prepared,
                &wrong_signature
            ))
        ),
        8
    );

    let signature = sign_prepared(&fixture, &prepared, [0x41; 32]);
    let mut carrier = parse_complete_response(
        &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&complete_request(
            &fixture, handle, &prepared, &signature,
        )),
    );
    carrier.encrypted_chunks[0][13] ^= 1;
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&validate_request(
                &fixture, handle, &carrier, 0
            ))
        ),
        6
    );
    carrier.encrypted_chunks[0][13] ^= 1;
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&validate_request(
                &fixture, handle, &carrier, 1
            ))
        ),
        6
    );
}

#[test]
fn sender_kernel_refuses_malformed_or_alternate_public_contexts() {
    clear_pseudorandom_zero_sharing_seed_mailbox_sender_contexts_for_test_320();
    let fixture = seed_mailbox_test_fixture_320(0, 9);
    let mut malformed_request = open_request(&fixture);
    malformed_request.push(0);
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&malformed_request)
        ),
        1
    );
    let mut wrong_terminal = open_request(&fixture);
    let terminal_byte_position =
        wrong_terminal.len() - fixture.root_terminal_certificate_bytes.len();
    wrong_terminal[terminal_byte_position + 31] ^= 1;
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&wrong_terminal)
        ),
        4
    );
    let mut truncated = open_request(&fixture);
    truncated.pop();
    assert_eq!(
        failure_code(&run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&truncated)),
        1
    );

    let handle = open_context(&fixture);
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&open_request(&fixture))
        ),
        2
    );
    let mut close_request = request_header(CLOSE_CONTEXT_OPERATION);
    append_unsigned32(&mut close_request, usize::try_from(handle).unwrap());
    ResponseCursor::new(
        &run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(&close_request),
        CLOSED_CONTEXT_STATUS,
    )
    .require_complete();
}
