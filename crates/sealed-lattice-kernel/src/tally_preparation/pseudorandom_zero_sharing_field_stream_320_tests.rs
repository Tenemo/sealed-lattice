use std::collections::HashSet;

use tiny_keccak::{CShake, Hasher, Kmac, Xof};

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
        FOUNDATION_PROFILE, Hash512,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    pseudorandom_zero_sharing_field_stream_320::{
        PSEUDORANDOM_FIELD_STREAM_CUSTOMIZATION,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH,
        PseudorandomZeroSharingFieldStreamCoordinate320, expand_pseudorandom_field_kmacxof256,
        generate_pseudorandom_zero_sharing_field_chunk_320,
        pseudorandom_zero_sharing_field_chunk_count,
        pseudorandom_zero_sharing_field_elements_per_chunk,
    },
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

const COMPLETION_ZERO_SHARING_COUNT: u64 = 33_346;

#[test]
fn tiny_keccak_kmac256_matches_the_published_nist_sample() {
    let key = core::array::from_fn::<_, 32, _>(|position| 0x40_u8 + position as u8);
    let mut kmac = Kmac::v256(&key, b"My Tagged Application");
    kmac.update(&[0x00, 0x01, 0x02, 0x03]);
    let mut actual = [0_u8; 64];
    kmac.finalize(&mut actual);

    let expected = decode_hex(concat!(
        "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7",
        "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
    ));
    assert_eq!(actual.as_slice(), expected);
}

#[test]
fn candidate_kmacxof256_matches_an_external_known_answer() {
    let key = core::array::from_fn::<_, PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH, _>(
        |position| position as u8,
    );
    let message = (0xa0_u8..=0xdf).collect::<Vec<_>>();
    let actual = expand_pseudorandom_field_kmacxof256(&key, &message, 80);
    let expected = decode_hex(concat!(
        "3beccf62e360825db560ff335f86557832807160846ee303e02cc080179da478f",
        "fa6eab412513de62a7c15ad2b5571b3e499c299a0899a2e5b8753fcc104f1ecf",
        "cb956512e9005ab1bd9dbf5b3223797",
    ));

    assert_eq!(actual.as_slice(), expected);
}

#[test]
fn candidate_kmacxof256_matches_independent_sp800_185_framing_and_fragmented_squeeze() {
    let key = core::array::from_fn::<_, PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH, _>(
        |position| 0x91_u8.wrapping_add((position as u8).wrapping_mul(17)),
    );
    let message = (0_u8..=193)
        .map(|value| value.wrapping_mul(29).wrapping_add(7))
        .collect::<Vec<_>>();
    let actual = expand_pseudorandom_field_kmacxof256(&key, &message, 173);
    let expected = independently_expand_kmacxof256(&key, &message, 173, &[1, 16, 73, 83]);

    assert_eq!(actual.as_slice(), expected);
}

#[test]
fn canonical_query_binds_the_complete_public_stream_coordinate() {
    let context = completion_context(11);
    let subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[1, 4, 8],
    )
    .unwrap();
    let parameter_identity = Hash512::from_bytes([23_u8; 64]);
    let catalog_identity = Hash512::from_bytes([37_u8; 64]);
    let coordinate = PseudorandomZeroSharingFieldStreamCoordinate320::new(
        parameter_identity,
        context,
        catalog_identity,
        subset,
        2,
        COMPLETION_ZERO_SHARING_COUNT,
    )
    .unwrap();

    let expected = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::hash512(parameter_identity.into_bytes()),
            CanonicalItem::hash512(context.identity().into_bytes()),
            CanonicalItem::unsigned16(0),
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned16(FOUNDATION_PROFILE.participant_count),
            CanonicalItem::unsigned32(subset.excluded_position_mask()),
            CanonicalItem::hash512(catalog_identity.into_bytes()),
            CanonicalItem::unsigned16(2),
            CanonicalItem::unsigned64(COMPLETION_ZERO_SHARING_COUNT),
            CanonicalItem::unsigned64(1),
            CanonicalItem::unsigned64(7_132),
        ],
    )
    .encode()
    .unwrap();

    assert_eq!(coordinate.canonical_query_bytes(1).unwrap(), expected);
}

#[test]
fn generated_chunk_matches_independent_kmacxof_and_field_mapping() {
    let context = completion_context(41);
    let subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[2, 5, 9],
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingFieldStreamCoordinate320::new(
        Hash512::from_bytes([43_u8; 64]),
        context,
        Hash512::from_bytes([47_u8; 64]),
        subset,
        1,
        19,
    )
    .unwrap();
    let subset_master =
        core::array::from_fn(|position| 0x61_u8.wrapping_add((position as u8).wrapping_mul(11)));
    let query = coordinate.canonical_query_bytes(0).unwrap();
    let expected =
        independently_expand_kmacxof256(&subset_master, &query, 19 * 40, &[17, 211, 532]);
    let chunk =
        generate_pseudorandom_zero_sharing_field_chunk_320(&subset_master, coordinate, 0).unwrap();

    assert_eq!(chunk.first_field_index(), 0);
    assert_eq!(chunk.field_count(), 19);
    assert_eq!(chunk.bytes(), expected);
    for field_position in 0..19 {
        let start = usize::try_from(field_position * 40).unwrap();
        assert_eq!(
            chunk
                .field_element(field_position)
                .unwrap()
                .canonical_bytes(),
            expected[start..start + 40],
        );
    }
}

#[test]
fn completion_stream_uses_two_restartable_one_megabyte_bounded_chunks() {
    let context = completion_context(53);
    let subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[3, 6, 9],
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingFieldStreamCoordinate320::new(
        Hash512::from_bytes([59_u8; 64]),
        context,
        Hash512::from_bytes([61_u8; 64]),
        subset,
        0,
        COMPLETION_ZERO_SHARING_COUNT,
    )
    .unwrap();
    let subset_master = [67_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH];

    assert_eq!(
        pseudorandom_zero_sharing_field_elements_per_chunk().unwrap(),
        26_214
    );
    assert_eq!(coordinate.chunk_count().unwrap(), 2);
    assert_eq!(
        pseudorandom_zero_sharing_field_chunk_count(COMPLETION_ZERO_SHARING_COUNT).unwrap(),
        2
    );

    let first_chunk =
        generate_pseudorandom_zero_sharing_field_chunk_320(&subset_master, coordinate, 0).unwrap();
    assert_eq!(first_chunk.first_field_index(), 0);
    assert_eq!(first_chunk.field_count(), 26_214);
    assert_eq!(first_chunk.byte_length(), 1_048_560);

    let final_chunk =
        generate_pseudorandom_zero_sharing_field_chunk_320(&subset_master, coordinate, 1).unwrap();
    assert_eq!(final_chunk.first_field_index(), 26_214);
    assert_eq!(final_chunk.field_count(), 7_132);
    assert_eq!(final_chunk.byte_length(), 285_280);
    assert!(matches!(
        final_chunk.field_element(7_132),
        Err(TallyPreparationError::PseudorandomZeroSharingFieldStreamPositionOutOfRange { .. })
    ));
}

#[test]
fn completion_participant_has_exactly_504_unique_subset_basis_chunk_queries() {
    let context = completion_context(71);
    let parameter_identity = Hash512::from_bytes([73_u8; 64]);
    let catalog_identity = Hash512::from_bytes([79_u8; 64]);
    let subsets = ReplicatedRandomSharingSubset::iter(FOUNDATION_PROFILE.participant_count)
        .unwrap()
        .filter(|subset| subset.contains(0).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(subsets.len(), 84);

    let mut queries = HashSet::new();
    for subset in subsets {
        for basis_position in 0..subset.active_fault_bound() {
            let coordinate = PseudorandomZeroSharingFieldStreamCoordinate320::new(
                parameter_identity,
                context,
                catalog_identity,
                subset,
                basis_position,
                COMPLETION_ZERO_SHARING_COUNT,
            )
            .unwrap();
            assert_eq!(coordinate.chunk_count().unwrap(), 2);
            for chunk_index in 0..2 {
                assert!(queries.insert(coordinate.canonical_query_bytes(chunk_index).unwrap()));
            }
        }
    }

    assert_eq!(queries.len(), 504);
}

#[test]
fn query_changes_for_every_independent_coordinate_dimension() {
    let context = completion_context(83);
    let alternate_context = completion_context(89);
    let subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[1, 3, 5],
    )
    .unwrap();
    let alternate_subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[1, 3, 6],
    )
    .unwrap();
    let field_count = pseudorandom_zero_sharing_field_elements_per_chunk().unwrap() + 1;
    let baseline_parameter_identity = Hash512::from_bytes([97_u8; 64]);
    let baseline_catalog_identity = Hash512::from_bytes([101_u8; 64]);
    let baseline = PseudorandomZeroSharingFieldStreamCoordinate320::new(
        baseline_parameter_identity,
        context,
        baseline_catalog_identity,
        subset,
        0,
        field_count,
    )
    .unwrap()
    .canonical_query_bytes(0)
    .unwrap();
    let variants = [
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            Hash512::from_bytes([103_u8; 64]),
            context,
            baseline_catalog_identity,
            subset,
            0,
            field_count,
        )
        .unwrap()
        .canonical_query_bytes(0)
        .unwrap(),
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            baseline_parameter_identity,
            alternate_context,
            baseline_catalog_identity,
            subset,
            0,
            field_count,
        )
        .unwrap()
        .canonical_query_bytes(0)
        .unwrap(),
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            baseline_parameter_identity,
            context,
            Hash512::from_bytes([107_u8; 64]),
            subset,
            0,
            field_count,
        )
        .unwrap()
        .canonical_query_bytes(0)
        .unwrap(),
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            baseline_parameter_identity,
            context,
            baseline_catalog_identity,
            alternate_subset,
            0,
            field_count,
        )
        .unwrap()
        .canonical_query_bytes(0)
        .unwrap(),
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            baseline_parameter_identity,
            context,
            baseline_catalog_identity,
            subset,
            1,
            field_count,
        )
        .unwrap()
        .canonical_query_bytes(0)
        .unwrap(),
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            baseline_parameter_identity,
            context,
            baseline_catalog_identity,
            subset,
            0,
            field_count + 1,
        )
        .unwrap()
        .canonical_query_bytes(0)
        .unwrap(),
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            baseline_parameter_identity,
            context,
            baseline_catalog_identity,
            subset,
            0,
            field_count,
        )
        .unwrap()
        .canonical_query_bytes(1)
        .unwrap(),
    ];

    for variant in variants {
        assert_ne!(variant, baseline);
    }
}

#[test]
fn malformed_context_basis_length_chunk_and_position_are_refused() {
    let context = completion_context(109);
    let completion_subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[2, 4, 6],
    )
    .unwrap();
    let different_roster_subset =
        ReplicatedRandomSharingSubset::from_excluded_positions(7, &[1, 3]).unwrap();
    let parameter_identity = Hash512::from_bytes([113_u8; 64]);
    let catalog_identity = Hash512::from_bytes([127_u8; 64]);

    assert_eq!(
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            parameter_identity,
            context,
            catalog_identity,
            different_roster_subset,
            0,
            1,
        ),
        Err(
            TallyPreparationError::PseudorandomZeroSharingFieldStreamSubsetParticipantCountMismatch {
                subset_participant_count: 7,
                context_participant_count: FOUNDATION_PROFILE.participant_count,
            }
        )
    );
    assert_eq!(
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            parameter_identity,
            context,
            catalog_identity,
            completion_subset,
            3,
            1,
        ),
        Err(
            TallyPreparationError::PseudorandomZeroSharingFieldStreamBasisPositionOutOfRange {
                basis_position: 3,
                active_fault_bound: 3,
            }
        )
    );
    assert_eq!(
        PseudorandomZeroSharingFieldStreamCoordinate320::new(
            parameter_identity,
            context,
            catalog_identity,
            completion_subset,
            0,
            0,
        ),
        Err(TallyPreparationError::PseudorandomZeroSharingFieldCountZero)
    );

    let coordinate = PseudorandomZeroSharingFieldStreamCoordinate320::new(
        parameter_identity,
        context,
        catalog_identity,
        completion_subset,
        0,
        1,
    )
    .unwrap();
    assert!(matches!(
        coordinate.canonical_query_bytes(1),
        Err(
            TallyPreparationError::PseudorandomZeroSharingFieldStreamChunkOutOfRange {
                chunk_index: 1,
                chunk_count: 1,
            }
        )
    ));
    assert!(matches!(
        generate_pseudorandom_zero_sharing_field_chunk_320(
            &[131_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH],
            coordinate,
            1,
        ),
        Err(TallyPreparationError::PseudorandomZeroSharingFieldStreamChunkOutOfRange { .. })
    ));
    assert!(matches!(
        pseudorandom_zero_sharing_field_chunk_count(0),
        Err(TallyPreparationError::PseudorandomZeroSharingFieldCountZero)
    ));
}

#[test]
fn chunk_debug_output_redacts_generated_bytes() {
    let context = completion_context(137);
    let subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[0, 2, 7],
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingFieldStreamCoordinate320::new(
        Hash512::from_bytes([139_u8; 64]),
        context,
        Hash512::from_bytes([149_u8; 64]),
        subset,
        0,
        2,
    )
    .unwrap();
    let chunk = generate_pseudorandom_zero_sharing_field_chunk_320(
        &[151_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH],
        coordinate,
        0,
    )
    .unwrap();
    let debug_output = format!("{chunk:?}");

    assert!(debug_output.contains("[redacted]"));
    assert!(!debug_output.contains(&format!("{:02x?}", chunk.bytes())));
}

fn independently_expand_kmacxof256(
    key: &[u8],
    message: &[u8],
    output_byte_length: usize,
    squeeze_lengths: &[usize],
) -> Vec<u8> {
    assert_eq!(squeeze_lengths.iter().sum::<usize>(), output_byte_length);
    let encoded_key = encode_string(key);
    let padded_key = bytepad(&encoded_key, 136);
    let mut cshake = CShake::v256(b"KMAC", PSEUDORANDOM_FIELD_STREAM_CUSTOMIZATION);
    cshake.update(&padded_key);
    cshake.update(message);
    cshake.update(&right_encode(0));

    let mut output = vec![0_u8; output_byte_length];
    let mut output_offset = 0;
    for squeeze_length in squeeze_lengths {
        let next_offset = output_offset + squeeze_length;
        cshake.squeeze(&mut output[output_offset..next_offset]);
        output_offset = next_offset;
    }
    output
}

fn encode_string(bytes: &[u8]) -> Vec<u8> {
    let bit_length = u64::try_from(bytes.len()).unwrap().checked_mul(8).unwrap();
    let mut encoded = left_encode(bit_length);
    encoded.extend_from_slice(bytes);
    encoded
}

fn bytepad(bytes: &[u8], block_byte_length: u64) -> Vec<u8> {
    let mut padded = left_encode(block_byte_length);
    padded.extend_from_slice(bytes);
    let block_byte_length = usize::try_from(block_byte_length).unwrap();
    let remainder = padded.len() % block_byte_length;
    if remainder != 0 {
        padded.resize(padded.len() + block_byte_length - remainder, 0);
    }
    padded
}

fn left_encode(value: u64) -> Vec<u8> {
    let value_bytes = value.to_be_bytes();
    let first_used_position = value_bytes
        .iter()
        .position(|value_byte| *value_byte != 0)
        .unwrap_or(value_bytes.len() - 1);
    let used_bytes = &value_bytes[first_used_position..];
    let mut encoded = Vec::with_capacity(used_bytes.len() + 1);
    encoded.push(u8::try_from(used_bytes.len()).unwrap());
    encoded.extend_from_slice(used_bytes);
    encoded
}

fn right_encode(value: u64) -> Vec<u8> {
    let value_bytes = value.to_be_bytes();
    let first_used_position = value_bytes
        .iter()
        .position(|value_byte| *value_byte != 0)
        .unwrap_or(value_bytes.len() - 1);
    let used_bytes = &value_bytes[first_used_position..];
    let mut encoded = Vec::with_capacity(used_bytes.len() + 1);
    encoded.extend_from_slice(used_bytes);
    encoded.push(u8::try_from(used_bytes.len()).unwrap());
    encoded
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
        Hash512::from_bytes([157_u8; 64]),
        Hash512::from_bytes([163_u8; 64]),
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
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hexadecimal digit"),
    }
}
