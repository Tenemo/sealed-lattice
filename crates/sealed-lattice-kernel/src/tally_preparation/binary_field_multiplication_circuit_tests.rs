use super::{
    BinaryFieldElement256,
    binary_field_multiplication_circuit::{
        CompiledBinaryFieldMultiplicationCircuit, karatsuba_conjunction_count,
    },
};

#[test]
fn karatsuba_circuit_matches_scalar_field_multiplication() {
    let circuit = CompiledBinaryFieldMultiplicationCircuit::compile().unwrap();
    let cases = multiplication_cases();

    for (left_bytes, right_bytes) in cases {
        let left = BinaryFieldElement256::from_canonical_bytes(&left_bytes).unwrap();
        let right = BinaryFieldElement256::from_canonical_bytes(&right_bytes).unwrap();
        assert_eq!(circuit.multiply(left, right).unwrap(), left.multiply(right));
        assert_eq!(circuit.multiply(right, left).unwrap(), right.multiply(left));
    }
}

#[test]
fn karatsuba_circuit_has_the_mechanically_derived_conjunction_count() {
    let circuit = CompiledBinaryFieldMultiplicationCircuit::compile().unwrap();

    assert_eq!(karatsuba_conjunction_count().unwrap(), 6_561);
    assert_eq!(circuit.conjunction_count(), 6_561);
    assert!(circuit.exclusive_or_count() > circuit.conjunction_count());
}

fn multiplication_cases() -> Vec<([u8; 32], [u8; 32])> {
    let mut cases = vec![
        ([0_u8; 32], [0_u8; 32]),
        (single_bit(0), single_bit(0)),
        (single_bit(255), single_bit(1)),
        (single_bit(255), single_bit(255)),
        ([u8::MAX; 32], [u8::MAX; 32]),
        ([0xAA_u8; 32], [0x55_u8; 32]),
    ];
    for sample_index in 0..64_u64 {
        cases.push((
            deterministic_bytes(sample_index, 0x243F_6A88_85A3_08D3),
            deterministic_bytes(sample_index, 0x1319_8A2E_0370_7344),
        ));
    }
    cases
}

fn single_bit(bit_position: usize) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[bit_position / u8::BITS as usize] = 1_u8 << (bit_position % u8::BITS as usize);
    bytes
}

fn deterministic_bytes(sample_index: u64, domain: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    let mut state = sample_index ^ domain;
    for byte_chunk in bytes.chunks_exact_mut(8) {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^= mixed >> 31;
        byte_chunk.copy_from_slice(&mixed.to_le_bytes());
    }
    bytes
}
