use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
        FOUNDATION_PROFILE, Hash512,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    replicated_key_ceremony::{
        ReplicatedRandomSharingKey, ReplicatedRandomSharingKeyCoordinate,
        ReplicatedRandomSharingKeyPurpose, combine_replicated_random_sharing_key,
        create_replicated_key_component,
    },
    replicated_sharing_field_stream::{
        REPLICATED_SHARING_FIELD_STREAM_DOMAIN, ReplicatedSharingFieldStreamPurpose,
        generate_replicated_sharing_field_chunk, replicated_sharing_field_chunk_count,
        replicated_sharing_field_chunk_preimage_byte_length,
    },
};

#[test]
fn chunk_generation_uses_the_normative_boundary_and_exact_field_mapping() {
    let context = completion_context(11);
    let coordinate = random_coordinate(context);
    let key = combined_key(coordinate, 17);
    let fields_per_chunk = FOUNDATION_PROFILE.stream_chunk_byte_length / 32;
    let total_field_count = u64::try_from(fields_per_chunk + 1).unwrap();

    assert_eq!(
        replicated_sharing_field_chunk_count(total_field_count).unwrap(),
        2
    );
    let first_chunk = generate_replicated_sharing_field_chunk(
        &key,
        ReplicatedSharingFieldStreamPurpose::IndependentTripleLeft,
        total_field_count,
        0,
    )
    .unwrap();
    assert_eq!(first_chunk.first_field_index(), 0);
    assert_eq!(first_chunk.field_count(), fields_per_chunk as u64);
    assert_eq!(
        first_chunk.byte_length(),
        FOUNDATION_PROFILE.stream_chunk_byte_length
    );
    assert_ne!(
        first_chunk.field_element(0).unwrap(),
        first_chunk.field_element(1).unwrap()
    );

    let final_chunk = generate_replicated_sharing_field_chunk(
        &key,
        ReplicatedSharingFieldStreamPurpose::IndependentTripleLeft,
        total_field_count,
        1,
    )
    .unwrap();
    assert_eq!(final_chunk.first_field_index(), fields_per_chunk as u64);
    assert_eq!(final_chunk.field_count(), 1);
    assert_eq!(final_chunk.byte_length(), 32);
    assert!(matches!(
        final_chunk.field_element(1),
        Err(TallyPreparationError::ReplicatedSharingFieldPositionOutOfRange { .. })
    ));
    assert!(matches!(
        generate_replicated_sharing_field_chunk(
            &key,
            ReplicatedSharingFieldStreamPurpose::IndependentTripleLeft,
            total_field_count,
            2,
        ),
        Err(TallyPreparationError::ReplicatedSharingFieldChunkOutOfRange { .. })
    ));
}

#[test]
fn field_stream_matches_the_independent_foundation_tuple_and_shake() {
    let context = completion_context(23);
    let coordinate = random_coordinate(context);
    let key = combined_key(coordinate, 29);
    let purpose = ReplicatedSharingFieldStreamPurpose::AuthenticationTripleRight;
    let total_field_count = 41;
    let chunk =
        generate_replicated_sharing_field_chunk(&key, purpose, total_field_count, 0).unwrap();

    let items = vec![
        CanonicalItem::fixed_bytes(key.as_bytes()).unwrap(),
        CanonicalItem::variable_bytes(coordinate.canonical_bytes()).unwrap(),
        CanonicalItem::unsigned16(purpose as u16),
        CanonicalItem::unsigned64(total_field_count),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(total_field_count),
        CanonicalItem::unsigned64(32),
        CanonicalItem::unsigned64(total_field_count * 32),
    ];
    let mut framed_items = Vec::with_capacity(items.len() + 1);
    framed_items
        .push(CanonicalItem::nonempty_ascii(REPLICATED_SHARING_FIELD_STREAM_DOMAIN).unwrap());
    framed_items.extend_from_slice(&items);
    let preimage = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        framed_items,
    )
    .encode()
    .unwrap();
    let mut hasher = Shake256::default();
    hasher.update(&preimage);
    let mut expected_bytes = vec![0_u8; usize::try_from(total_field_count * 32).unwrap()];
    hasher.finalize_xof().read(&mut expected_bytes);

    for field_position in 0..total_field_count {
        let start = usize::try_from(field_position * 32).unwrap();
        let expected =
            super::BinaryFieldElement256::from_canonical_bytes(&expected_bytes[start..start + 32])
                .unwrap();
        assert_eq!(chunk.field_element(field_position).unwrap(), expected);
    }
    assert_eq!(
        replicated_sharing_field_chunk_preimage_byte_length(
            coordinate,
            purpose,
            total_field_count,
            0,
        )
        .unwrap(),
        preimage.len() as u64
    );
}

#[test]
fn queries_separate_keys_coordinates_purposes_lengths_and_chunks() {
    let context = completion_context(37);
    let coordinate = random_coordinate(context);
    let alternate_coordinate = ReplicatedRandomSharingKeyCoordinate::all(context).unwrap()[4];
    let key = combined_key(coordinate, 41);
    let alternate_key = combined_key(alternate_coordinate, 41);
    let fields_per_chunk = FOUNDATION_PROFILE.stream_chunk_byte_length as u64 / 32;
    let total_field_count = fields_per_chunk + 7;

    let baseline = generate_replicated_sharing_field_chunk(
        &key,
        ReplicatedSharingFieldStreamPurpose::OrdinaryTripleLeft,
        total_field_count,
        0,
    )
    .unwrap()
    .field_element(0)
    .unwrap();
    let changed_key = generate_replicated_sharing_field_chunk(
        &alternate_key,
        ReplicatedSharingFieldStreamPurpose::OrdinaryTripleLeft,
        total_field_count,
        0,
    )
    .unwrap()
    .field_element(0)
    .unwrap();
    let changed_purpose = generate_replicated_sharing_field_chunk(
        &key,
        ReplicatedSharingFieldStreamPurpose::OrdinaryTripleRight,
        total_field_count,
        0,
    )
    .unwrap()
    .field_element(0)
    .unwrap();
    let changed_length = generate_replicated_sharing_field_chunk(
        &key,
        ReplicatedSharingFieldStreamPurpose::OrdinaryTripleLeft,
        total_field_count + 1,
        0,
    )
    .unwrap()
    .field_element(0)
    .unwrap();
    let changed_chunk = generate_replicated_sharing_field_chunk(
        &key,
        ReplicatedSharingFieldStreamPurpose::OrdinaryTripleLeft,
        total_field_count,
        1,
    )
    .unwrap()
    .field_element(0)
    .unwrap();

    assert_ne!(baseline, changed_key);
    assert_ne!(baseline, changed_purpose);
    assert_ne!(baseline, changed_length);
    assert_ne!(baseline, changed_chunk);
}

#[test]
fn random_and_zero_key_purposes_cannot_be_crossed() {
    let context = completion_context(47);
    let random_key = combined_key(random_coordinate(context), 53);
    let zero_coordinate = ReplicatedRandomSharingKeyCoordinate::all(context)
        .unwrap()
        .into_iter()
        .find(|coordinate| {
            matches!(
                coordinate.purpose(),
                ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing { .. }
            )
        })
        .unwrap();
    let zero_key = combined_key(zero_coordinate, 59);

    assert!(matches!(
        generate_replicated_sharing_field_chunk(
            &random_key,
            ReplicatedSharingFieldStreamPurpose::IndependentTripleDegreeDoubleZeroMask,
            1,
            0,
        ),
        Err(TallyPreparationError::ReplicatedSharingFieldPurposeMismatch)
    ));
    assert!(matches!(
        generate_replicated_sharing_field_chunk(
            &zero_key,
            ReplicatedSharingFieldStreamPurpose::IndependentTripleLeft,
            1,
            0,
        ),
        Err(TallyPreparationError::ReplicatedSharingFieldPurposeMismatch)
    ));
    assert!(matches!(
        replicated_sharing_field_chunk_count(0),
        Err(TallyPreparationError::ReplicatedSharingFieldCountZero)
    ));
}

#[test]
fn shake256_matches_the_fips_empty_string_answer_and_non_byte_truncation() {
    let expected = decode_hex(concat!(
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
    ));
    let mut hasher = Shake256::default();
    hasher.update(&[]);
    let mut actual = [0_u8; 64];
    hasher.finalize_xof().read(&mut actual);
    assert_eq!(actual.as_slice(), expected);

    let mut truncated = actual[..2].to_vec();
    let used_final_byte_bit_count = 13 % 8;
    let used_final_byte_mask = (1_u8 << used_final_byte_bit_count) - 1;
    *truncated.last_mut().unwrap() &= used_final_byte_mask;
    assert_eq!(truncated, [0x46, 0x19]);
    assert_eq!(truncated[1] & !used_final_byte_mask, 0);
}

fn random_coordinate(context: TallyPreparationContext) -> ReplicatedRandomSharingKeyCoordinate {
    ReplicatedRandomSharingKeyCoordinate::all(context)
        .unwrap()
        .into_iter()
        .find(|coordinate| {
            matches!(
                coordinate.purpose(),
                ReplicatedRandomSharingKeyPurpose::RandomSharing
            )
        })
        .unwrap()
}

fn combined_key(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    seed: u8,
) -> ReplicatedRandomSharingKey {
    let mut commitments = Vec::new();
    let mut openings = Vec::new();
    for contributor_position in coordinate.member_positions().unwrap() {
        let component = core::array::from_fn(|byte_position| {
            seed.wrapping_add((contributor_position as u8).wrapping_mul(31))
                .wrapping_add((byte_position as u8).wrapping_mul(17))
        });
        let (commitment, opening) =
            create_replicated_key_component(coordinate, contributor_position, component).unwrap();
        commitments.push(commitment);
        openings.push(opening);
    }
    combine_replicated_random_sharing_key(coordinate, &commitments, &openings).unwrap()
}

fn completion_context(attempt_byte: u8) -> TallyPreparationContext {
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    TallyPreparationContext::new(
        Hash512::from_bytes([17_u8; 64]),
        Hash512::from_bytes([29_u8; 64]),
        [attempt_byte; 32],
        &circuit,
    )
    .unwrap()
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("test vector contains non-hexadecimal input"),
    }
}
