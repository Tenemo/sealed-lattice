use fips203::{
    ml_kem_768,
    traits::{Decaps, SerDes as KemSerDes},
};
use fips204::traits::Signer;

use crate::foundation::{FOUNDATION_PROFILE, Hash512};

use super::{
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        SeedMailboxTestFixture320, seed_mailbox_test_fixture_320,
        seed_mailbox_test_fixture_with_parameter_identity_320,
    },
    pseudorandom_zero_sharing_seed_mailbox_320::{
        ML_KEM_768_CIPHERTEXT_BYTE_LENGTH,
        verify_pseudorandom_zero_sharing_seed_mailbox_authenticated_inconsistency_320,
    },
    pseudorandom_zero_sharing_seed_mailbox_320_tests::{
        SealedMailboxTestStream320, seal_mailbox_stream,
    },
    pseudorandom_zero_sharing_seed_receipt_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    },
    pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320::{
        clear_pseudorandom_zero_sharing_seed_recipient_receipt_contexts_for_test_320,
        run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320,
    },
};

const REQUEST_MAGIC: &[u8; 4] = b"SLRQ";
const RESPONSE_MAGIC: &[u8; 4] = b"SLRR";
const CODEC_VERSION: u16 = 1;
const OPEN_CONTEXT_OPERATION: u8 = 1;
const COMPLETE_AUTHENTICATION_OPERATION: u8 = 2;
const COMPLETE_RECEIPT_OPERATION: u8 = 3;
const VALIDATE_RECEIPT_OPERATION: u8 = 4;
const CLOSE_CONTEXT_OPERATION: u8 = 5;
const OPEN_CONTEXT_STATUS: u8 = 1;
const AUTHENTICATED_INVENTORY_STATUS: u8 = 2;
const COMPLETE_RECEIPT_STATUS: u8 = 3;
const VALIDATION_STATUS: u8 = 4;
const CLOSED_CONTEXT_STATUS: u8 = 5;
const AUTHENTICATED_INCONSISTENCY_STATUS: u8 = 6;
const RESPONSE_HEADER_BYTE_LENGTH: usize = 7;

struct RecipientReceiptKernelFixture320 {
    owner: SeedMailboxTestFixture320,
    streams: Vec<SealedMailboxTestStream320>,
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
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    bytes.push(operation);
    bytes
}

fn assert_status(response: &[u8], expected_status: u8) {
    assert_eq!(&response[..4], RESPONSE_MAGIC);
    assert_eq!(u16::from_le_bytes(response[4..6].try_into().unwrap()), 1);
    assert_eq!(response[6], expected_status);
}

fn failure_code(response: &[u8]) -> u16 {
    assert_status(response, 0);
    assert_eq!(response.len(), 9);
    u16::from_le_bytes(response[7..9].try_into().unwrap())
}

fn fixture(recipient_position: u16, carrier_marker: u8) -> RecipientReceiptKernelFixture320 {
    let first_sender_position = if recipient_position == 0 { 1 } else { 0 };
    let owner = seed_mailbox_test_fixture_320(first_sender_position, recipient_position);
    fixture_from_owner(owner, recipient_position, carrier_marker)
}

fn fixture_from_owner(
    owner: SeedMailboxTestFixture320,
    recipient_position: u16,
    carrier_marker: u8,
) -> RecipientReceiptKernelFixture320 {
    let parameter_identity = owner.parameter_identity;
    let first_sender_position = owner.sender_position;
    let streams = (0..FOUNDATION_PROFILE.participant_count)
        .filter(|sender_position| *sender_position != recipient_position)
        .map(|sender_position| {
            let sender_fixture;
            let fixture = if sender_position == first_sender_position {
                &owner
            } else {
                sender_fixture = seed_mailbox_test_fixture_with_parameter_identity_320(
                    sender_position,
                    recipient_position,
                    parameter_identity,
                );
                assert_eq!(
                    sender_fixture.root_terminal.identity().unwrap(),
                    owner.root_terminal.identity().unwrap()
                );
                &sender_fixture
            };
            let marker = carrier_marker.wrapping_add(sender_position as u8);
            seal_mailbox_stream(
                fixture,
                recipient_position,
                &fixture.descriptor_bytes,
                &fixture.payload_bytes,
                [marker; 32],
                marker.wrapping_add(0x20),
            )
        })
        .collect();
    RecipientReceiptKernelFixture320 { owner, streams }
}

fn encode_open_request(fixture: &RecipientReceiptKernelFixture320) -> Vec<u8> {
    let mut bytes = request_header(OPEN_CONTEXT_OPERATION);
    bytes.extend_from_slice(fixture.owner.parameter_identity.as_bytes());
    append_unsigned16(&mut bytes, fixture.owner.recipient_position);
    append_bounded(
        &mut bytes,
        &fixture.owner.preparation_context.canonical_bytes(),
    );
    append_bounded(&mut bytes, &fixture.owner.roster.encode().unwrap());
    append_unsigned16(
        &mut bytes,
        u16::try_from(fixture.owner.root_authorization_packages.len()).unwrap(),
    );
    for package in &fixture.owner.root_authorization_packages {
        append_bounded(&mut bytes, &package.root_body_bytes);
        append_bounded(&mut bytes, &package.reservation_certificate_bytes);
        append_bounded(&mut bytes, &package.exact_output_certificate_bytes);
        append_bounded(&mut bytes, &package.contributor_signature_envelope_bytes);
    }
    append_bounded(&mut bytes, &fixture.owner.root_terminal_certificate_bytes);
    append_unsigned16(&mut bytes, u16::try_from(fixture.streams.len()).unwrap());
    for (stream, sender_position) in fixture.streams.iter().zip(
        (0..FOUNDATION_PROFILE.participant_count)
            .filter(|sender_position| *sender_position != fixture.owner.recipient_position),
    ) {
        append_unsigned16(&mut bytes, sender_position);
        append_bounded(&mut bytes, &stream.header_bytes);
        append_bounded(&mut bytes, &stream.manifest_bytes);
        append_bounded(&mut bytes, &stream.signature_envelope_bytes);
        append_unsigned16(
            &mut bytes,
            u16::try_from(stream.encrypted_chunks.len()).unwrap(),
        );
        for chunk in &stream.encrypted_chunks {
            append_bounded(&mut bytes, chunk);
        }
    }
    bytes
}

fn open_context(
    fixture: &RecipientReceiptKernelFixture320,
) -> (u32, Vec<[u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH]>) {
    let response = run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320(
        &encode_open_request(fixture),
    );
    assert_status(&response, OPEN_CONTEXT_STATUS);
    let mut offset = RESPONSE_HEADER_BYTE_LENGTH;
    let handle = u32::from_le_bytes(response[offset..offset + 4].try_into().unwrap());
    offset += 4;
    assert_eq!(
        &response[offset..offset + Hash512::BYTE_LENGTH],
        fixture.owner.parameter_identity.as_bytes()
    );
    offset += Hash512::BYTE_LENGTH;
    assert_eq!(
        &response[offset..offset + Hash512::BYTE_LENGTH],
        fixture.owner.preparation_context.identity().as_bytes()
    );
    offset += Hash512::BYTE_LENGTH;
    assert_eq!(
        &response[offset..offset + Hash512::BYTE_LENGTH],
        fixture.owner.root_terminal.identity().unwrap().as_bytes()
    );
    offset += Hash512::BYTE_LENGTH;
    assert_eq!(
        u16::from_le_bytes(response[offset..offset + 2].try_into().unwrap()),
        0
    );
    offset += 2;
    assert_eq!(
        u16::from_le_bytes(response[offset..offset + 2].try_into().unwrap()),
        FOUNDATION_PROFILE.participant_count
    );
    offset += 2;
    assert_eq!(
        u16::from_le_bytes(response[offset..offset + 2].try_into().unwrap()),
        fixture.owner.recipient_position
    );
    offset += 2 + 1_952 + 1_184;
    let ciphertext_count = usize::from(u16::from_le_bytes(
        response[offset..offset + 2].try_into().unwrap(),
    ));
    offset += 2;
    assert_eq!(ciphertext_count, fixture.streams.len());
    let ciphertexts = (0..ciphertext_count)
        .map(|_| {
            let ciphertext = response[offset..offset + ML_KEM_768_CIPHERTEXT_BYTE_LENGTH]
                .try_into()
                .unwrap();
            offset += ML_KEM_768_CIPHERTEXT_BYTE_LENGTH;
            ciphertext
        })
        .collect();
    assert_eq!(offset, response.len());
    (handle, ciphertexts)
}

fn shared_secrets(
    fixture: &RecipientReceiptKernelFixture320,
    ciphertexts: &[[u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH]],
) -> Vec<[u8; 32]> {
    let key =
        &fixture.owner.mailbox_decapsulation_keys[usize::from(fixture.owner.recipient_position)];
    ciphertexts
        .iter()
        .map(|ciphertext_bytes| {
            let ciphertext = ml_kem_768::CipherText::try_from_bytes(*ciphertext_bytes).unwrap();
            key.try_decaps(&ciphertext).unwrap().into_bytes()
        })
        .collect()
}

fn complete_authentication(handle: u32, shared_secrets: &[[u8; 32]]) -> Vec<u8> {
    let mut request = request_header(COMPLETE_AUTHENTICATION_OPERATION);
    request.extend_from_slice(&handle.to_le_bytes());
    append_unsigned16(&mut request, u16::try_from(shared_secrets.len()).unwrap());
    for shared_secret in shared_secrets {
        request.extend_from_slice(shared_secret);
    }
    run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320(&request).to_vec()
}

fn parse_receipt_body(prepared_payload: &[u8]) -> &[u8] {
    let mut offset = 0;
    let inventory_body_length =
        u32::from_le_bytes(prepared_payload[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4 + inventory_body_length + Hash512::BYTE_LENGTH;
    let segment_count = usize::from(u16::from_le_bytes(
        prepared_payload[offset..offset + 2].try_into().unwrap(),
    ));
    offset += 2;
    for _ in 0..segment_count {
        let segment_length =
            u32::from_le_bytes(prepared_payload[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + segment_length;
    }
    let receipt_body_length =
        u32::from_le_bytes(prepared_payload[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    assert_eq!(
        receipt_body_length,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH
    );
    &prepared_payload[offset..offset + receipt_body_length]
}

fn complete_receipt(
    fixture: &RecipientReceiptKernelFixture320,
    handle: u32,
    prepared_payload: &[u8],
    signature_marker: u8,
) -> Vec<u8> {
    let signature = fixture.owner.signing_keys[usize::from(fixture.owner.recipient_position)]
        .try_sign_with_seed(
            &[signature_marker; 32],
            parse_receipt_body(prepared_payload),
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    let mut request = request_header(COMPLETE_RECEIPT_OPERATION);
    request.extend_from_slice(&handle.to_le_bytes());
    request.extend_from_slice(prepared_payload);
    request.extend_from_slice(&signature);
    run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320(&request).to_vec()
}

fn read_bounded_response(response: &[u8], expected_status: u8) -> &[u8] {
    assert_status(response, expected_status);
    let byte_length = u32::from_le_bytes(response[7..11].try_into().unwrap()) as usize;
    assert_eq!(response.len(), 11 + byte_length);
    &response[11..]
}

fn validation_context_bytes(fixture: &RecipientReceiptKernelFixture320) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(fixture.owner.parameter_identity.as_bytes());
    append_unsigned16(&mut bytes, FOUNDATION_PROFILE.participant_count);
    append_unsigned16(&mut bytes, 0);
    bytes.extend_from_slice(fixture.owner.preparation_context.identity().as_bytes());
    append_unsigned16(&mut bytes, fixture.owner.recipient_position);
    bytes.extend_from_slice(fixture.owner.root_terminal.identity().unwrap().as_bytes());
    bytes
}

#[test]
fn recipient_receipt_kernel_authenticates_every_mailbox_before_signing() {
    clear_pseudorandom_zero_sharing_seed_recipient_receipt_contexts_for_test_320();
    let fixture = fixture(6, 0x31);
    let (handle, ciphertexts) = open_context(&fixture);
    let secrets = shared_secrets(&fixture, &ciphertexts);
    let authenticated_response = complete_authentication(handle, &secrets);
    assert_status(&authenticated_response, AUTHENTICATED_INVENTORY_STATUS);
    let prepared_payload = &authenticated_response[RESPONSE_HEADER_BYTE_LENGTH..];
    assert_eq!(parse_receipt_body(prepared_payload).len(), 374);

    let first_complete_response = complete_receipt(&fixture, handle, prepared_payload, 0x71);
    let first_envelope = read_bounded_response(&first_complete_response, COMPLETE_RECEIPT_STATUS);
    assert_eq!(
        first_envelope.len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH
    );
    let alternate_complete_response = complete_receipt(&fixture, handle, prepared_payload, 0x73);
    let alternate_envelope =
        read_bounded_response(&alternate_complete_response, COMPLETE_RECEIPT_STATUS);
    assert_ne!(first_envelope, alternate_envelope);

    let mut validation_request = request_header(VALIDATE_RECEIPT_OPERATION);
    validation_request.extend_from_slice(&handle.to_le_bytes());
    validation_request.extend_from_slice(&validation_context_bytes(&fixture));
    validation_request.extend_from_slice(prepared_payload);
    validation_request.push(1);
    append_bounded(&mut validation_request, first_envelope);
    let validation_response =
        run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320(&validation_request);
    assert_status(&validation_response, VALIDATION_STATUS);
    assert_eq!(validation_response.len(), RESPONSE_HEADER_BYTE_LENGTH);

    let mut close_request = request_header(CLOSE_CONTEXT_OPERATION);
    close_request.extend_from_slice(&handle.to_le_bytes());
    let close_response =
        run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320(&close_request);
    assert_status(&close_response, CLOSED_CONTEXT_STATUS);
    assert_eq!(close_response.len(), RESPONSE_HEADER_BYTE_LENGTH);
}

#[test]
fn recipient_receipt_kernel_refuses_reordering_and_consumes_failed_authentication() {
    clear_pseudorandom_zero_sharing_seed_recipient_receipt_contexts_for_test_320();
    let fixture = fixture(5, 0x41);
    let mut reordered_request = encode_open_request(&fixture);
    let carrier_start = {
        let mut offset = 7 + 64 + 2;
        for _ in 0..2 {
            let length =
                u32::from_le_bytes(reordered_request[offset..offset + 4].try_into().unwrap())
                    as usize;
            offset += 4 + length;
        }
        let package_count = usize::from(u16::from_le_bytes(
            reordered_request[offset..offset + 2].try_into().unwrap(),
        ));
        offset += 2;
        for _ in 0..package_count * 4 {
            let length =
                u32::from_le_bytes(reordered_request[offset..offset + 4].try_into().unwrap())
                    as usize;
            offset += 4 + length;
        }
        let terminal_length =
            u32::from_le_bytes(reordered_request[offset..offset + 4].try_into().unwrap()) as usize;
        offset + 4 + terminal_length + 2
    };
    reordered_request[carrier_start..carrier_start + 2].copy_from_slice(&9_u16.to_le_bytes());
    assert_eq!(
        failure_code(
            &run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320(&reordered_request)
        ),
        4
    );

    let (handle, ciphertexts) = open_context(&fixture);
    let mut secrets = shared_secrets(&fixture, &ciphertexts);
    let malformed_count = complete_authentication(handle, &secrets[..secrets.len() - 1]);
    assert_eq!(failure_code(&malformed_count), 1);
    secrets[3][0] ^= 0x80;
    let refused = complete_authentication(handle, &secrets);
    assert_eq!(failure_code(&refused), 9);
    let repeated_completion =
        complete_authentication(handle, &shared_secrets(&fixture, &ciphertexts));
    assert_eq!(failure_code(&repeated_completion), 7);
}

#[test]
fn recipient_receipt_kernel_discloses_only_publicly_verifiable_plaintext_inconsistency() {
    clear_pseudorandom_zero_sharing_seed_recipient_receipt_contexts_for_test_320();
    let mut fixture = fixture(5, 0x51);
    let mut changed_payload = fixture.owner.payload_bytes.to_vec();
    changed_payload[0] ^= 0x80;
    fixture.streams[0] = seal_mailbox_stream(
        &fixture.owner,
        fixture.owner.recipient_position,
        &fixture.owner.descriptor_bytes,
        &changed_payload,
        [0x91; 32],
        0x93,
    );
    let (handle, ciphertexts) = open_context(&fixture);
    let secrets = shared_secrets(&fixture, &ciphertexts);
    let response = complete_authentication(handle, &secrets);
    assert_status(&response, AUTHENTICATED_INCONSISTENCY_STATUS);
    assert_eq!(
        response.len(),
        RESPONSE_HEADER_BYTE_LENGTH + 2 + 2 + 32 + 64
    );
    let mut offset = RESPONSE_HEADER_BYTE_LENGTH;
    let sender_position = u16::from_le_bytes(response[offset..offset + 2].try_into().unwrap());
    offset += 2;
    let recipient_position = u16::from_le_bytes(response[offset..offset + 2].try_into().unwrap());
    offset += 2;
    let disclosed_key: [u8; 32] = response[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let evidence_identity = Hash512::from_bytes(response[offset..offset + 64].try_into().unwrap());
    offset += 64;
    assert_eq!(offset, response.len());
    assert_eq!(sender_position, fixture.owner.sender_position);
    assert_eq!(recipient_position, fixture.owner.recipient_position);
    assert_eq!(
        disclosed_key,
        fixture.streams[0].authenticated_encryption_key
    );

    let encrypted_chunk_references = fixture.streams[0]
        .encrypted_chunks
        .iter()
        .map(|chunk| chunk.as_slice())
        .collect::<Vec<_>>();
    let verified = verify_pseudorandom_zero_sharing_seed_mailbox_authenticated_inconsistency_320(
        &fixture.owner.root_terminal,
        &fixture.owner.roster,
        sender_position,
        recipient_position,
        &fixture.owner.descriptor_bytes,
        &fixture.streams[0].header_bytes,
        &fixture.streams[0].manifest_bytes,
        &fixture.streams[0].signature_envelope_bytes,
        &encrypted_chunk_references,
        &disclosed_key,
    )
    .unwrap();
    assert_eq!(verified.identity(), evidence_identity);

    assert_eq!(failure_code(&complete_authentication(handle, &secrets)), 7);
}
