use fips204::traits::Signer;
use zeroize::Zeroizing;

use super::{
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        SeedMailboxTestFixture320, seed_mailbox_test_fixture_320,
    },
    pseudorandom_zero_sharing_seed_master_custody_320_tests::encode_receipt_custody_record,
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
    },
    pseudorandom_zero_sharing_seed_receipt_terminal_320_tests::signed_receipt_envelopes_from_authenticated_deliveries,
    pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320::{
        clear_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_contexts_for_test_320,
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320,
    },
};

const CODEC_VERSION: u16 = 1;
const ENDORSER_POSITION: u16 = 0;
const RESPONSE_HEADER_BYTE_LENGTH: usize = 7;

struct TerminalEndorsementKernelFixture320 {
    owner: SeedMailboxTestFixture320,
    receipt_custody_record_bytes: Zeroizing<Vec<u8>>,
    receipt_envelopes: Vec<Vec<u8>>,
    alternate_receipt_envelopes: Vec<Vec<u8>>,
}

impl TerminalEndorsementKernelFixture320 {
    fn open_request_bytes(&self, receipt_envelopes: &[Vec<u8>]) -> Zeroizing<Vec<u8>> {
        let mut bytes = request_header(1);
        bytes.extend_from_slice(self.owner.parameter_identity.as_bytes());
        append_unsigned16(&mut bytes, ENDORSER_POSITION);
        append_bounded_bytes(
            &mut bytes,
            &self.owner.preparation_context.canonical_bytes(),
        );
        append_bounded_bytes(&mut bytes, &self.owner.roster.encode().unwrap());
        append_unsigned16(
            &mut bytes,
            self.owner.root_authorization_packages.len() as u16,
        );
        for package in &self.owner.root_authorization_packages {
            append_bounded_bytes(&mut bytes, &package.root_body_bytes);
            append_bounded_bytes(&mut bytes, &package.reservation_certificate_bytes);
            append_bounded_bytes(&mut bytes, &package.exact_output_certificate_bytes);
            append_bounded_bytes(&mut bytes, &package.contributor_signature_envelope_bytes);
        }
        append_bounded_bytes(&mut bytes, &self.owner.root_terminal_certificate_bytes);
        append_unsigned16(&mut bytes, receipt_envelopes.len() as u16);
        for receipt_envelope_bytes in receipt_envelopes {
            append_bounded_bytes(&mut bytes, receipt_envelope_bytes);
        }
        bytes.extend_from_slice(self.owner.parameter_identity.as_bytes());
        bytes.extend_from_slice(self.owner.preparation_context.identity().as_bytes());
        bytes.extend_from_slice(self.owner.root_terminal.identity().unwrap().as_bytes());
        append_unsigned16(&mut bytes, 0);
        append_unsigned16(
            &mut bytes,
            self.owner.preparation_context.participant_count(),
        );
        append_unsigned16(&mut bytes, ENDORSER_POSITION);
        append_bounded_bytes(&mut bytes, &self.receipt_custody_record_bytes);
        bytes
    }
}

#[test]
fn terminal_endorsement_kernel_reverifies_local_receipt_and_completes_one_carrier() {
    clear_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_contexts_for_test_320();
    let fixture = terminal_endorsement_kernel_fixture();
    let open_response = run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
        &fixture.open_request_bytes(&fixture.receipt_envelopes),
    );
    assert_response_status(&open_response, 1);
    assert_eq!(open_response.len(), RESPONSE_HEADER_BYTE_LENGTH + 4 + 1_952);
    let handle = read_unsigned32(&open_response, RESPONSE_HEADER_BYTE_LENGTH) as u32;
    assert_ne!(handle, 0);
    assert_eq!(
        &open_response[RESPONSE_HEADER_BYTE_LENGTH + 4..],
        &fixture.owner.roster.entries[0].signing_verification_key
    );

    let second_open = run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
        &fixture.open_request_bytes(&fixture.receipt_envelopes),
    );
    assert_failure_code(&second_open, 2);

    let prepare_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &handle_request(2, handle),
        );
    assert_response_status(&prepare_response, 2);
    let prepared_inventory_bytes = &prepare_response[RESPONSE_HEADER_BYTE_LENGTH..];
    let authorization_body_byte_length = read_unsigned32(prepared_inventory_bytes, 0);
    let authorization_body_bytes = &prepared_inventory_bytes
        [size_of::<u32>()..size_of::<u32>() + authorization_body_byte_length];
    let signature = fixture.owner.signing_keys[0]
        .try_sign_with_seed(
            &[0xa7; 32],
            authorization_body_bytes,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
        )
        .unwrap();

    let mut complete_request = handle_request(3, handle);
    complete_request.extend_from_slice(prepared_inventory_bytes);
    complete_request.extend_from_slice(&signature);
    let complete_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &complete_request,
        );
    assert_response_status(&complete_response, 3);
    let endorsement_envelope_byte_length =
        read_unsigned32(&complete_response, RESPONSE_HEADER_BYTE_LENGTH);
    assert_eq!(
        endorsement_envelope_byte_length,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH
    );
    let endorsement_envelope_bytes =
        &complete_response[RESPONSE_HEADER_BYTE_LENGTH + size_of::<u32>()..];
    assert_eq!(
        endorsement_envelope_bytes.len(),
        endorsement_envelope_byte_length
    );

    let validation_context_bytes = validation_context_bytes(&fixture.owner);
    let mut validate_request = handle_request(4, handle);
    validate_request.extend_from_slice(&validation_context_bytes);
    validate_request.extend_from_slice(prepared_inventory_bytes);
    validate_request.push(1);
    append_bounded_bytes(&mut validate_request, endorsement_envelope_bytes);
    let validate_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &validate_request,
        );
    assert_response_status(&validate_response, 4);

    let mut changed_prepared_inventory = prepared_inventory_bytes.to_vec();
    let last_byte = changed_prepared_inventory.len() - 1;
    changed_prepared_inventory[last_byte] ^= 1;
    let mut changed_validation_request = handle_request(4, handle);
    changed_validation_request.extend_from_slice(&validation_context_bytes);
    changed_validation_request.extend_from_slice(&changed_prepared_inventory);
    changed_validation_request.push(0);
    let changed_validation_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &changed_validation_request,
        );
    assert_failure_code(&changed_validation_response, 6);

    let close_response = run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
        &handle_request(5, handle),
    );
    assert_response_status(&close_response, 5);
    let closed_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &handle_request(2, handle),
        );
    assert_failure_code(&closed_response, 7);
}

#[test]
fn terminal_endorsement_kernel_refuses_alternate_carriers_and_malformed_scope() {
    clear_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_contexts_for_test_320();
    let fixture = terminal_endorsement_kernel_fixture();
    let alternate_carrier_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &fixture.open_request_bytes(&fixture.alternate_receipt_envelopes),
        );
    assert_failure_code(&alternate_carrier_response, 4);

    let mut wrong_context_request = fixture.open_request_bytes(&fixture.receipt_envelopes);
    let receipt_context_offset = receipt_context_offset(&wrong_context_request);
    wrong_context_request[receipt_context_offset] ^= 1;
    let wrong_context_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &wrong_context_request,
        );
    assert_failure_code(&wrong_context_response, 3);

    let mut malformed_request = fixture.open_request_bytes(&fixture.receipt_envelopes);
    malformed_request.push(0);
    let malformed_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &malformed_request,
        );
    assert_failure_code(&malformed_response, 1);

    let mut changed_record_request = fixture.open_request_bytes(&fixture.receipt_envelopes);
    let last_byte = changed_record_request.len() - 1;
    changed_record_request[last_byte] ^= 1;
    let changed_record_response =
        run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
            &changed_record_request,
        );
    assert_failure_code(&changed_record_response, 5);
}

fn terminal_endorsement_kernel_fixture() -> TerminalEndorsementKernelFixture320 {
    let owner = seed_mailbox_test_fixture_320(1, ENDORSER_POSITION);
    let (receipt_envelopes, alternate_receipt_envelopes, retained_receipt) =
        signed_receipt_envelopes_from_authenticated_deliveries(0x31, 0x41, 0x51);
    let receipt_custody_record_bytes =
        encode_receipt_custody_record(&owner, &retained_receipt, &receipt_envelopes[0]);
    TerminalEndorsementKernelFixture320 {
        owner,
        receipt_custody_record_bytes,
        receipt_envelopes,
        alternate_receipt_envelopes,
    }
}

fn request_header(operation: u8) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"SLTQ");
    append_unsigned16(&mut bytes, CODEC_VERSION);
    bytes.push(operation);
    bytes
}

fn handle_request(operation: u8, handle: u32) -> Zeroizing<Vec<u8>> {
    let mut bytes = request_header(operation);
    bytes.extend_from_slice(&handle.to_le_bytes());
    bytes
}

fn validation_context_bytes(owner: &SeedMailboxTestFixture320) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(owner.parameter_identity.as_bytes());
    append_unsigned16(&mut bytes, owner.preparation_context.participant_count());
    append_unsigned16(&mut bytes, 0);
    bytes.extend_from_slice(owner.preparation_context.identity().as_bytes());
    append_unsigned16(&mut bytes, ENDORSER_POSITION);
    bytes.extend_from_slice(owner.root_terminal.identity().unwrap().as_bytes());
    bytes
}

fn receipt_context_offset(request: &[u8]) -> usize {
    let mut offset = 7 + 64 + 2;
    offset = skip_bounded(request, offset);
    offset = skip_bounded(request, offset);
    let root_package_count = read_unsigned16(request, offset);
    offset += 2;
    for _ in 0..root_package_count {
        for _ in 0..4 {
            offset = skip_bounded(request, offset);
        }
    }
    offset = skip_bounded(request, offset);
    let receipt_count = read_unsigned16(request, offset);
    offset += 2;
    for _ in 0..receipt_count {
        offset = skip_bounded(request, offset);
    }
    offset
}

fn skip_bounded(bytes: &[u8], offset: usize) -> usize {
    offset + size_of::<u32>() + read_unsigned32(bytes, offset)
}

fn append_bounded_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_le_bytes());
    output.extend_from_slice(value);
}

fn append_unsigned16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_unsigned16(bytes: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes(
        bytes[offset..offset + 2].try_into().unwrap(),
    ))
}

fn read_unsigned32(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

fn assert_response_status(response: &[u8], status: u8) {
    assert_eq!(&response[..4], b"SLTP");
    assert_eq!(&response[4..6], &CODEC_VERSION.to_le_bytes());
    assert_eq!(response[6], status);
}

fn assert_failure_code(response: &[u8], code: u16) {
    assert_response_status(response, 0);
    assert_eq!(response.len(), RESPONSE_HEADER_BYTE_LENGTH + 2);
    assert_eq!(u16::from_le_bytes(response[7..9].try_into().unwrap()), code);
}
