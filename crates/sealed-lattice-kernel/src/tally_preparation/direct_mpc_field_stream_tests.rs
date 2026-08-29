use std::collections::HashSet;

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use tiny_keccak::{CShake, Hasher, Xof};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
    FOUNDATION_PROFILE, Hash512,
};

use super::{
    direct_mpc_candidate_compiler::DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH,
    direct_mpc_field_stream::{
        DIRECT_MPC_FIELD_STREAM_CUSTOMIZATION, DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH,
        DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH, DirectMpcFieldStreamCoordinate,
        DirectMpcFieldStreamError, DirectMpcFieldStreamKind,
        direct_mpc_field_stream_elements_per_chunk,
        expand_direct_mpc_field_stream_kmacxof256_for_test, generate_direct_mpc_field_stream_chunk,
    },
    direct_mpc_prime_field::DIRECT_MPC_PRIME_FIELD_MODULUS,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

#[test]
fn canonical_query_is_the_exact_302_byte_production_coordinate() {
    let subset = subset(&[1, 4, 8]);
    let candidate_identity = hash(0x11);
    let preparation_context_identity = hash(0x22);
    let seed_terminal_identity = hash(0x33);
    let coordinate = DirectMpcFieldStreamCoordinate::new(
        candidate_identity,
        preparation_context_identity,
        seed_terminal_identity,
        DirectMpcFieldStreamKind::DegreeSixZeroBasis,
        subset,
        2,
        9_925,
    )
    .unwrap();
    let actual = coordinate.canonical_query_bytes(0).unwrap();
    let expected = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::hash512(candidate_identity.into_bytes()),
            CanonicalItem::hash512(preparation_context_identity.into_bytes()),
            CanonicalItem::hash512(seed_terminal_identity.into_bytes()),
            CanonicalItem::unsigned16(0),
            CanonicalItem::unsigned16(2),
            CanonicalItem::unsigned16(FOUNDATION_PROFILE.participant_count),
            CanonicalItem::unsigned32(subset.excluded_position_mask()),
            CanonicalItem::unsigned16(2),
            CanonicalItem::unsigned64(9_925),
            CanonicalItem::unsigned64(0),
            CanonicalItem::unsigned64(9_925),
        ],
    )
    .encode()
    .unwrap();

    assert_eq!(actual, expected);
    assert_eq!(actual.len(), DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH);
}

#[test]
fn kmacxof_matches_independent_sp800_185_framing_and_fragmented_squeeze() {
    let key = core::array::from_fn::<_, DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH, _>(|position| {
        0x31_u8.wrapping_add((position as u8).wrapping_mul(19))
    });
    let message = (0_u16..302)
        .map(|value| (value as u8).wrapping_mul(37).wrapping_add(5))
        .collect::<Vec<_>>();
    let actual = expand_direct_mpc_field_stream_kmacxof256_for_test(&key, &message, 173);
    let expected = independently_expand_kmacxof256(&key, &message, 173, &[1, 16, 73, 83]);

    assert_eq!(actual.as_slice(), expected);
}

#[test]
fn generated_samples_reduce_as_little_endian_256_bit_integers() {
    let coordinate = DirectMpcFieldStreamCoordinate::new(
        hash(0x41),
        hash(0x52),
        hash(0x63),
        DirectMpcFieldStreamKind::OrdinaryDegreeThree,
        subset(&[2, 5, 9]),
        0,
        19,
    )
    .unwrap();
    let key =
        core::array::from_fn(|position| 0x71_u8.wrapping_add((position as u8).wrapping_mul(7)));
    let query = coordinate.canonical_query_bytes(0).unwrap();
    let samples = independently_expand_kmacxof256(
        &key,
        &query,
        19 * DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH as usize,
        &[17, 211, 380],
    );
    let chunk = generate_direct_mpc_field_stream_chunk(&key, coordinate, 0).unwrap();

    assert_eq!(chunk.first_field_index(), 0);
    assert_eq!(chunk.field_count(), 19);
    assert_eq!(chunk.sample_byte_length(), samples.len());
    for (position, sample) in samples
        .chunks_exact(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH as usize)
        .enumerate()
    {
        let expected = (BigUint::from_bytes_le(sample)
            % BigUint::from(DIRECT_MPC_PRIME_FIELD_MODULUS))
        .to_u32()
        .unwrap();
        assert_eq!(
            chunk
                .field_element(position as u64)
                .unwrap()
                .canonical_u32(),
            expected
        );
    }
}

#[test]
fn all_completion_stream_queries_are_distinct_and_single_chunk() {
    let subsets = ReplicatedRandomSharingSubset::iter(FOUNDATION_PROFILE.participant_count)
        .unwrap()
        .filter(|candidate| candidate.contains(0).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(subsets.len(), 84);
    let mut queries = HashSet::new();
    for subset in subsets {
        let ordinary = DirectMpcFieldStreamCoordinate::new(
            hash(0x81),
            hash(0x82),
            hash(0x83),
            DirectMpcFieldStreamKind::OrdinaryDegreeThree,
            subset,
            0,
            30_175,
        )
        .unwrap();
        assert_eq!(ordinary.chunk_count().unwrap(), 1);
        assert!(queries.insert(ordinary.canonical_query_bytes(0).unwrap()));
        for basis_position in 0..subset.active_fault_bound() {
            let zero = DirectMpcFieldStreamCoordinate::new(
                hash(0x81),
                hash(0x82),
                hash(0x83),
                DirectMpcFieldStreamKind::DegreeSixZeroBasis,
                subset,
                basis_position,
                9_925,
            )
            .unwrap();
            assert_eq!(zero.chunk_count().unwrap(), 1);
            assert!(queries.insert(zero.canonical_query_bytes(0).unwrap()));
        }
    }
    assert_eq!(queries.len(), 336);
    assert_eq!(
        direct_mpc_field_stream_elements_per_chunk().unwrap(),
        32_768
    );
}

#[test]
fn malformed_basis_count_and_chunk_coordinates_are_refused() {
    let subset = subset(&[1, 4, 8]);
    assert_eq!(
        DirectMpcFieldStreamCoordinate::new(
            hash(1),
            hash(2),
            hash(3),
            DirectMpcFieldStreamKind::OrdinaryDegreeThree,
            subset,
            1,
            1,
        ),
        Err(DirectMpcFieldStreamError::OrdinaryBasisPositionNonzero { basis_position: 1 })
    );
    assert_eq!(
        DirectMpcFieldStreamCoordinate::new(
            hash(1),
            hash(2),
            hash(3),
            DirectMpcFieldStreamKind::DegreeSixZeroBasis,
            subset,
            3,
            1,
        ),
        Err(DirectMpcFieldStreamError::ZeroBasisPositionOutOfRange {
            basis_position: 3,
            active_fault_bound: 3,
        })
    );
    let coordinate = DirectMpcFieldStreamCoordinate::new(
        hash(1),
        hash(2),
        hash(3),
        DirectMpcFieldStreamKind::OrdinaryDegreeThree,
        subset,
        0,
        1,
    )
    .unwrap();
    assert!(matches!(
        coordinate.canonical_query_bytes(1),
        Err(DirectMpcFieldStreamError::ChunkIndexOutOfRange { .. })
    ));
    assert!(matches!(
        generate_direct_mpc_field_stream_chunk(&[0x55; 40], coordinate, 1),
        Err(DirectMpcFieldStreamError::ChunkIndexOutOfRange { .. })
    ));
}

fn subset(excluded_positions: &[u16]) -> ReplicatedRandomSharingSubset {
    ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        excluded_positions,
    )
    .unwrap()
}

fn hash(marker: u8) -> Hash512 {
    Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
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
    let mut cshake = CShake::v256(b"KMAC", DIRECT_MPC_FIELD_STREAM_CUSTOMIZATION);
    cshake.update(&padded_key);
    cshake.update(message);
    cshake.update(&right_encode(0));
    let mut output = vec![0_u8; output_byte_length];
    let mut offset = 0;
    for squeeze_length in squeeze_lengths {
        let end = offset + squeeze_length;
        cshake.squeeze(&mut output[offset..end]);
        offset = end;
    }
    output
}

fn encode_string(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = left_encode((bytes.len() * 8) as u64);
    encoded.extend_from_slice(bytes);
    encoded
}

fn bytepad(bytes: &[u8], block_byte_length: u64) -> Vec<u8> {
    let mut padded = left_encode(block_byte_length);
    padded.extend_from_slice(bytes);
    let block_byte_length = block_byte_length as usize;
    let remainder = padded.len() % block_byte_length;
    if remainder != 0 {
        padded.resize(padded.len() + block_byte_length - remainder, 0);
    }
    padded
}

fn left_encode(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|value_byte| *value_byte != 0)
        .unwrap_or(bytes.len() - 1);
    let used = &bytes[first..];
    let mut encoded = vec![used.len() as u8];
    encoded.extend_from_slice(used);
    encoded
}

fn right_encode(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|value_byte| *value_byte != 0)
        .unwrap_or(bytes.len() - 1);
    let used = &bytes[first..];
    let mut encoded = used.to_vec();
    encoded.push(used.len() as u8);
    encoded
}
