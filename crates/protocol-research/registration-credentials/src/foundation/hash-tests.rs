use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::*;

#[test]
fn hash_uses_exact_typed_tuple_framing() {
    let items = [
        CanonicalItem::unsigned16(0x0201),
        CanonicalItem::variable_bytes([7, 8, 9]).expect("raw bytes fit u32"),
    ];
    let actual = hash_foundation_tuple_512("sealed-lattice/test/hash/v1", &items)
        .expect("hash input is valid");

    let mut expected_frame = Vec::new();
    expected_frame.extend_from_slice(&0x0001_u16.to_le_bytes());
    expected_frame.extend_from_slice(&1_u16.to_le_bytes());
    expected_frame.extend_from_slice(&3_u32.to_le_bytes());
    let domain = b"sealed-lattice/test/hash/v1";
    expected_frame.extend_from_slice(&0x02_u16.to_le_bytes());
    expected_frame.extend_from_slice(&((domain.len() + 4) as u32).to_le_bytes());
    expected_frame.extend_from_slice(&(domain.len() as u32).to_le_bytes());
    expected_frame.extend_from_slice(domain);
    expected_frame.extend_from_slice(&0x03_u16.to_le_bytes());
    expected_frame.extend_from_slice(&2_u32.to_le_bytes());
    expected_frame.extend_from_slice(&0x0201_u16.to_le_bytes());
    expected_frame.extend_from_slice(&0x01_u16.to_le_bytes());
    expected_frame.extend_from_slice(&7_u32.to_le_bytes());
    expected_frame.extend_from_slice(&3_u32.to_le_bytes());
    expected_frame.extend_from_slice(&[7, 8, 9]);

    let mut hasher = Shake256::default();
    hasher.update(&expected_frame);
    let mut reader = hasher.finalize_xof();
    let mut expected = [0u8; 64];
    reader.read(&mut expected);
    assert_eq!(actual, Hash512::from_bytes(expected));
    assert_eq!(actual.to_lowercase_hex().len(), 128);
}

#[test]
fn streaming_variable_bytes_hash_matches_one_shot_for_every_fragmentation() {
    let prefix_items = [
        CanonicalItem::hash512([0x31; 64]),
        CanonicalItem::nonempty_ascii("proof/1216/query-openings").expect("test tag"),
    ];
    let payload = (0_u16..=1024)
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let mut one_shot_items = prefix_items.to_vec();
    one_shot_items.push(CanonicalItem::variable_bytes(&payload).expect("bounded test payload"));
    let expected =
        hash_foundation_tuple_512("sealed-lattice/proof/transcript/absorb/v1", &one_shot_items)
            .expect("one-shot hash");

    for fragment_byte_length in [1, 3, 63, 64, 65, 511, payload.len()] {
        let mut streaming = StreamingFoundationTupleHash512::new_variable_bytes(
            "sealed-lattice/proof/transcript/absorb/v1",
            &prefix_items,
            payload.len(),
        )
        .expect("streaming hash initializes");
        for fragment in payload.chunks(fragment_byte_length) {
            streaming.absorb(fragment).expect("fragment fits");
        }
        assert_eq!(streaming.finalize().expect("payload is complete"), expected);
    }
}

#[test]
fn streaming_variable_bytes_hash_rejects_overrun_and_incomplete_payloads() {
    let mut overrun = StreamingFoundationTupleHash512::new_variable_bytes(
        "sealed-lattice/test/streaming-hash/v1",
        &[],
        2,
    )
    .expect("stream initializes");
    assert_eq!(
        overrun.absorb(&[1, 2, 3]),
        Err(StreamingFoundationHashError::PayloadOverrun),
    );

    let mut incomplete = StreamingFoundationTupleHash512::new_variable_bytes(
        "sealed-lattice/test/streaming-hash/v1",
        &[],
        2,
    )
    .expect("stream initializes");
    incomplete.absorb(&[1]).expect("prefix fits");
    assert_eq!(
        incomplete.finalize(),
        Err(StreamingFoundationHashError::PayloadIncomplete),
    );
}

#[test]
fn domain_and_item_boundaries_cannot_alias() {
    let first = hash_foundation_tuple_512(
        "sealed-lattice/test/a",
        &[CanonicalItem::variable_bytes(b"bc").expect("raw bytes")],
    )
    .expect("hash");
    let second = hash_foundation_tuple_512(
        "sealed-lattice/test/ab",
        &[CanonicalItem::variable_bytes(b"c").expect("raw bytes")],
    )
    .expect("hash");
    let split = hash_foundation_tuple_512(
        "sealed-lattice/test/a",
        &[
            CanonicalItem::variable_bytes(b"b").expect("raw bytes"),
            CanonicalItem::variable_bytes(b"c").expect("raw bytes"),
        ],
    )
    .expect("hash");
    assert_ne!(first, second);
    assert_ne!(first, split);
    assert_ne!(second, split);
}

#[test]
fn empty_or_non_printable_domains_refuse() {
    assert!(hash_foundation_tuple_512("", &[]).is_err());
    assert!(hash_foundation_tuple_512("sealed-lattice/test\n", &[]).is_err());
}
