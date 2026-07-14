#![no_main]

use libfuzzer_sys::fuzz_target;
use sealed_lattice_kernel::foundation::{
    ACTION_DEFINITION_SCHEMA_IDENTIFIER, ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
    ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER, ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER,
    BOARD_POLICY_SCHEMA_IDENTIFIER, CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER,
    CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER, CanonicalDecodeLimits, CanonicalTuple,
    DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
    DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER,
    IncrementalCanonicalTupleDecoder, LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER, LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER, MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER, MANIFEST_SCHEMA_IDENTIFIER,
    OBJECT_ENVELOPE_SCHEMA_IDENTIFIER, OPTION_DEFINITION_SCHEMA_IDENTIFIER,
    ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
    PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER, PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER,
    RANDOM_CURSOR_SCHEMA_IDENTIFIER, ROSTER_ENTRY_SCHEMA_IDENTIFIER, ROSTER_SCHEMA_IDENTIFIER,
    RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER, RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER,
    RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER, SIGNED_CARRIER_SCHEMA_IDENTIFIER,
    SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER, STATE_CERTIFICATE_SCHEMA_IDENTIFIER,
    STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER, STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER,
    STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER, STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER,
    STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
    STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER, STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
    SUITE_RECORD_SCHEMA_IDENTIFIER,
};
use sealed_lattice_kernel::run_transcript_core_command;

const FOUNDATION_SCHEMA_IDENTIFIERS: [u16; 40] = [
    OBJECT_ENVELOPE_SCHEMA_IDENTIFIER,
    SIGNED_CARRIER_SCHEMA_IDENTIFIER,
    PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER,
    MANIFEST_SCHEMA_IDENTIFIER,
    OPTION_DEFINITION_SCHEMA_IDENTIFIER,
    ACTION_DEFINITION_SCHEMA_IDENTIFIER,
    BOARD_POLICY_SCHEMA_IDENTIFIER,
    ROSTER_ENTRY_SCHEMA_IDENTIFIER,
    ROSTER_SCHEMA_IDENTIFIER,
    DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER,
    ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER,
    SUITE_RECORD_SCHEMA_IDENTIFIER,
    MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
    MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER,
    DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER,
    STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER,
    DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER,
    ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
    PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
    PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
    ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER,
    ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
    STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER,
    STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
    STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER,
    STATE_CERTIFICATE_SCHEMA_IDENTIFIER,
    STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER,
    STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
    RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER,
    RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER,
    RANDOM_CURSOR_SCHEMA_IDENTIFIER,
    CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER,
    CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER,
    RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER,
];

const MAXIMUM_FUZZED_CANONICAL_BYTE_LENGTH: usize = 4_096;

fn encode_lowercase_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        encoded.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fuzz_target!(|input: &[u8]| {
    // Exercise the complete public command parser as well as the canonical-byte
    // decoder selected by a hostile schema and payload. Both calls must return a
    // bounded success or typed refusal and must never panic or abort.
    let _ = run_transcript_core_command(input);

    if input.is_empty() {
        return;
    }

    let schema_identifier =
        FOUNDATION_SCHEMA_IDENTIFIERS[usize::from(input[0]) % FOUNDATION_SCHEMA_IDENTIFIERS.len()];
    let canonical_bytes = &input[1..input.len().min(MAXIMUM_FUZZED_CANONICAL_BYTE_LENGTH + 1)];
    let command = format!(
        "{{\"command\":\"ValidateCanonicalFoundationValue\",\"schemaIdentifier\":{schema_identifier},\"canonicalBytesHex\":\"{}\"}}",
        encode_lowercase_hex(canonical_bytes),
    );
    let _ = run_transcript_core_command(command.as_bytes());

    let fragment_byte_length = 1 + usize::from(input[0] % 31);
    let canonical_byte_chunks_hex = canonical_bytes
        .chunks(fragment_byte_length)
        .map(|chunk| format!("\"{}\"", encode_lowercase_hex(chunk)))
        .collect::<Vec<_>>()
        .join(",");
    let fragmented_command = format!(
        "{{\"command\":\"ValidateCanonicalFoundationValue\",\"schemaIdentifier\":{schema_identifier},\"canonicalByteLength\":{},\"canonicalByteChunksHex\":[{canonical_byte_chunks_hex}]}}",
        canonical_bytes.len(),
    );
    let _ = run_transcript_core_command(fragmented_command.as_bytes());

    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_FUZZED_CANONICAL_BYTE_LENGTH,
        maximum_item_count: 256,
        maximum_item_byte_length: MAXIMUM_FUZZED_CANONICAL_BYTE_LENGTH,
        maximum_nesting_depth: 16,
        maximum_cumulative_work_byte_length: MAXIMUM_FUZZED_CANONICAL_BYTE_LENGTH * 4,
        maximum_cumulative_allocation_byte_length: MAXIMUM_FUZZED_CANONICAL_BYTE_LENGTH * 4,
    };
    let flat_result = CanonicalTuple::decode(canonical_bytes, &limits);
    let incremental_result = IncrementalCanonicalTupleDecoder::new(canonical_bytes.len(), &limits)
        .and_then(|mut decoder| {
            for fragment in canonical_bytes.chunks(fragment_byte_length) {
                decoder.absorb(fragment)?;
            }
            decoder.finish()
        });
    match (flat_result, incremental_result) {
        (Ok(flat), Ok(incremental)) => assert_eq!(flat, incremental),
        (Ok(_), Err(error)) => {
            panic!("incremental decoding refused a flat-decoder success: {error}")
        }
        (Err(_), Ok(_)) => panic!("incremental decoding accepted a flat-decoder refusal"),
        (Err(_), Err(_)) => {}
    }

    // Proof-profile sets are suite artifacts rather than foundation values,
    // so exercise their dedicated bounded command without extending the
    // foundation schema registry. The small cap is hostile-parser coverage;
    // it is not the accepted size limit for a valid profile artifact.
    let proof_profile_command = format!(
        "{{\"command\":\"ValidateProofProfileSet\",\"canonicalBytesHex\":\"{}\"}}",
        encode_lowercase_hex(canonical_bytes),
    );
    let _ = run_transcript_core_command(proof_profile_command.as_bytes());
});
