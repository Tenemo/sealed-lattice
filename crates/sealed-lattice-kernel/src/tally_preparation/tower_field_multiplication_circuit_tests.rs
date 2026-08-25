use std::sync::OnceLock;

use super::{
    BinaryFieldElement256,
    tower_field_multiplication_circuit::{
        CompiledTowerFieldMultiplicationCircuit, tower_field_multiplication_conjunction_count,
        tower_field_multiplication_exclusive_or_count,
    },
};

static COMPILED_CIRCUIT: OnceLock<CompiledTowerFieldMultiplicationCircuit> = OnceLock::new();

#[test]
fn tower_interpolation_circuit_has_the_derived_conjunction_geometry() {
    let circuit = compiled_circuit();

    assert_eq!(tower_field_multiplication_conjunction_count(), 1_701);
    assert_eq!(tower_field_multiplication_exclusive_or_count(), 198_048);
    assert_eq!(circuit.conjunction_count(), 1_701);
    assert_eq!(circuit.distinct_input_linear_form_count(), 1_701);
    assert_eq!(circuit.exclusive_or_count(), 198_048);
    assert_eq!(circuit.input_linear_window_width(), 8);
    assert_eq!(circuit.output_linear_window_width(), 9);
}

#[test]
fn tower_interpolation_circuit_matches_the_independent_scalar_field_owner() {
    let circuit = compiled_circuit();
    let reduction_boundary = BinaryFieldElement256::from_canonical_bytes(&{
        let mut bytes = [0_u8; 32];
        bytes[31] = 0x80;
        bytes
    })
    .unwrap();
    let maximum = BinaryFieldElement256::from_canonical_bytes(&[0xff_u8; 32]).unwrap();
    let alternating_low = BinaryFieldElement256::from_canonical_bytes(&[0x55_u8; 32]).unwrap();
    let alternating_high = BinaryFieldElement256::from_canonical_bytes(&[0xaa_u8; 32]).unwrap();
    let ascending =
        BinaryFieldElement256::from_canonical_bytes(&(0_u8..32_u8).collect::<Vec<_>>()).unwrap();
    let descending =
        BinaryFieldElement256::from_canonical_bytes(&(0_u8..32_u8).rev().collect::<Vec<_>>())
            .unwrap();
    let deterministic_inputs = (0_u8..24_u8)
        .map(|input_position| {
            let bytes: [u8; BinaryFieldElement256::CANONICAL_BYTE_LENGTH] =
                core::array::from_fn(|byte_position| {
                    input_position
                        .wrapping_mul(97)
                        .wrapping_add((byte_position as u8).wrapping_mul(53))
                        .rotate_left(u32::from(input_position % 7))
                });
            BinaryFieldElement256::from_canonical_bytes(&bytes).unwrap()
        })
        .collect::<Vec<_>>();

    let fixed_cases = [
        (BinaryFieldElement256::ZERO, BinaryFieldElement256::ZERO),
        (BinaryFieldElement256::ZERO, maximum),
        (BinaryFieldElement256::ONE, maximum),
        (maximum, BinaryFieldElement256::ONE),
        (reduction_boundary, reduction_boundary),
        (maximum, maximum),
        (alternating_low, alternating_high),
        (ascending, descending),
        (descending, ascending),
    ];
    for (left, right) in fixed_cases {
        assert_eq!(circuit.multiply(left, right).unwrap(), left.multiply(right));
    }
    for (left_position, left) in deterministic_inputs.iter().copied().enumerate() {
        for right in deterministic_inputs
            .iter()
            .copied()
            .skip(left_position % deterministic_inputs.len())
            .take(5)
        {
            assert_eq!(circuit.multiply(left, right).unwrap(), left.multiply(right));
            assert_eq!(circuit.multiply(right, left).unwrap(), right.multiply(left));
        }
    }
}

fn compiled_circuit() -> &'static CompiledTowerFieldMultiplicationCircuit {
    COMPILED_CIRCUIT.get_or_init(|| {
        CompiledTowerFieldMultiplicationCircuit::compile()
            .expect("the fixed tower multiplication circuit must compile")
    })
}
