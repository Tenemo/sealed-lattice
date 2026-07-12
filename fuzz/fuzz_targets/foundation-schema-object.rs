#![no_main]

use libfuzzer_sys::fuzz_target;
use sealed_lattice_kernel::run_transcript_core_command;

const MAXIMUM_CANONICAL_OBJECT_BYTE_LENGTH: usize = 1_572_865;
const MAXIMUM_SEEDED_MUTATION_COUNT: usize = 4_096;

const RAW_BYTES_ITEM: u16 = 0x0001;
const ASCII_ITEM: u16 = 0x0002;
const UNSIGNED_16_ITEM: u16 = 0x0003;
const UNSIGNED_32_ITEM: u16 = 0x0004;
const UNSIGNED_64_ITEM: u16 = 0x0005;
const HASH_512_ITEM: u16 = 0x0006;
const PARTICIPANT_IDENTITY_ITEM: u16 = 0x0007;
const DISPLAY_TEXT_ITEM: u16 = 0x000c;
const HOMOGENEOUS_LIST_ITEM: u16 = 0x000e;

fn canonical_item(item_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6 + payload.len());
    bytes.extend_from_slice(&item_type.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("fuzz seed item length fits u32")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes
}

fn canonical_tuple(schema_identifier: u16, items: &[Vec<u8>]) -> Vec<u8> {
    let item_byte_length = items.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(8 + item_byte_length);
    bytes.extend_from_slice(&schema_identifier.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(items.len())
            .expect("fuzz seed item count fits u32")
            .to_le_bytes(),
    );
    for item in items {
        bytes.extend_from_slice(item);
    }
    bytes
}

fn variable_bytes(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + payload.len());
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("fuzz seed variable-byte length fits u32")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes
}

fn hash_item(byte: u8) -> Vec<u8> {
    canonical_item(HASH_512_ITEM, &[byte; 64])
}

fn participant_identity_item(byte: u8) -> Vec<u8> {
    canonical_item(PARTICIPANT_IDENTITY_ITEM, &[byte; 64])
}

fn unsigned_16_item(value: u16) -> Vec<u8> {
    canonical_item(UNSIGNED_16_ITEM, &value.to_le_bytes())
}

fn unsigned_32_item(value: u32) -> Vec<u8> {
    canonical_item(UNSIGNED_32_ITEM, &value.to_le_bytes())
}

fn unsigned_64_item(value: u64) -> Vec<u8> {
    canonical_item(UNSIGNED_64_ITEM, &value.to_le_bytes())
}

fn text_item(item_type: u16, value: &str) -> Vec<u8> {
    canonical_item(item_type, &variable_bytes(value.as_bytes()))
}

fn empty_hash_list_item() -> Vec<u8> {
    let mut payload = Vec::with_capacity(6);
    payload.extend_from_slice(&HASH_512_ITEM.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    canonical_item(HOMOGENEOUS_LIST_ITEM, &payload)
}

fn representative_seed_objects() -> Vec<Vec<u8>> {
    vec![
        canonical_tuple(
            0x0111,
            &[
                unsigned_16_item(0),
                text_item(ASCII_ITEM, "canonical-option"),
                text_item(DISPLAY_TEXT_ITEM, "Canonical option"),
            ],
        ),
        canonical_tuple(
            0x0200,
            &[
                text_item(ASCII_ITEM, "sealed-lattice/mailbox/key-schedule/v1"),
                unsigned_16_item(1),
                hash_item(1),
                hash_item(2),
                hash_item(3),
                hash_item(4),
                participant_identity_item(5),
                participant_identity_item(6),
                unsigned_64_item(7),
                canonical_item(RAW_BYTES_ITEM, &[8; 32]),
                text_item(ASCII_ITEM, "source-to-recipient"),
                unsigned_16_item(1),
                unsigned_16_item(1),
                hash_item(9),
                empty_hash_list_item(),
                hash_item(10),
            ],
        ),
        canonical_tuple(0x0303, &[hash_item(11)]),
        canonical_tuple(0x1610, &[unsigned_16_item(1), hash_item(12)]),
        canonical_tuple(
            0x1800,
            &[unsigned_64_item(0), empty_hash_list_item(), hash_item(13)],
        ),
        canonical_tuple(0x1806, &[unsigned_16_item(1), unsigned_16_item(2)]),
        canonical_tuple(
            0x0106,
            &[unsigned_32_item(3), unsigned_64_item(4), hash_item(14)],
        ),
        canonical_tuple(
            0x2203,
            &[
                unsigned_16_item(0),
                unsigned_32_item(4),
                unsigned_64_item(3),
                unsigned_16_item(2),
                unsigned_32_item(8),
                unsigned_32_item(4),
                unsigned_16_item(2),
            ],
        ),
    ]
}

fn seeded_candidate(input: &[u8]) -> Vec<u8> {
    let seeds = representative_seed_objects();
    let seed_selector = input.get(1).copied().unwrap_or(0);
    let mut candidate = seeds[usize::from(seed_selector) % seeds.len()].clone();

    match input.first().copied().unwrap_or(0) % 4 {
        0 => input.get(1..).unwrap_or_default().to_vec(),
        1 => {
            for mutation in input
                .get(2..)
                .unwrap_or_default()
                .chunks(3)
                .take(MAXIMUM_SEEDED_MUTATION_COUNT)
            {
                if candidate.is_empty() || mutation.len() < 3 {
                    break;
                }
                let byte_index =
                    (usize::from(mutation[0]) << 8 | usize::from(mutation[1])) % candidate.len();
                candidate[byte_index] ^= mutation[2];
            }
            candidate
        }
        2 => {
            let suffix = input.get(2..).unwrap_or_default();
            let retained_suffix_length = suffix
                .len()
                .min(MAXIMUM_CANONICAL_OBJECT_BYTE_LENGTH - candidate.len());
            candidate.extend_from_slice(&suffix[..retained_suffix_length]);
            candidate
        }
        _ => {
            let requested_length = input
                .get(2..4)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map(u16::from_le_bytes)
                .map(usize::from)
                .unwrap_or(0);
            candidate.truncate(requested_length.min(candidate.len()));
            candidate
        }
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fuzz_target!(|input: &[u8]| {
    if input.len() > MAXIMUM_CANONICAL_OBJECT_BYTE_LENGTH {
        return;
    }
    let candidate = seeded_candidate(input);
    let request = format!(
        "{{\"command\":\"ValidateFoundationSchemaObject\",\"canonicalObjectHex\":\"{}\"}}",
        lowercase_hex(&candidate),
    );

    let _response = run_transcript_core_command(request.as_bytes());
});
