use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::binary_ring_packed_mpc_evaluation_floor::{
    BinaryRingPackedMpcCircuitEvaluationFloor, BinaryRingPackedMpcEvaluationFloor,
    BinaryRingPackingParameters,
};

#[test]
fn completion_profile_reproduces_both_binary_ring_evaluation_floors() {
    let floor = BinaryRingPackedMpcEvaluationFloor::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(floor.participant_count, 10);
    assert_eq!(floor.active_fault_bound, 3);
    assert!(floor.source_theorem_exact_roster_shape);
    assert_eq!(
        floor.packing,
        BinaryRingPackingParameters {
            packed_value_count: 3,
            extension_degree: 5,
            residue_field_cardinality: 32,
        }
    );
    assert_eq!(floor.remote_evaluation_bit_count_per_binary_gate, 36);
    assert_eq!(
        floor.shared_offset,
        BinaryRingPackedMpcCircuitEvaluationFloor {
            full_field_multiplication_count: 368_990,
            bit_by_field_multiplication_count: 355_440,
            bit_multiplication_count: 2_962,
            current_scalar_field_multiplication_conjunction_count: 65_536,
            current_scalar_binary_conjunction_count: 24_273_124_242,
            current_scalar_evaluation_bit_length: 873_832_472_712,
            current_scalar_evaluation_byte_length: 109_229_059_089,
            minimum_maximum_participant_current_scalar_upload_byte_length: 10_922_905_909,
            karatsuba_field_multiplication_conjunction_count: 6_561,
            karatsuba_binary_conjunction_count: 2_511_938_992,
            karatsuba_evaluation_bit_length: 90_429_803_712,
            karatsuba_evaluation_byte_length: 11_303_725_464,
            minimum_maximum_participant_karatsuba_upload_byte_length: 1_130_372_547,
            tower_field_multiplication_conjunction_count: 1_701,
            tower_field_multiplication_exclusive_or_count: 198_048,
            tower_binary_conjunction_count: 718_647_592,
            tower_binary_exclusive_or_count: 73_077_731_520,
            tower_binary_gate_count: 73_796_379_112,
            tower_evaluation_bit_length: 2_656_669_648_032,
            tower_evaluation_byte_length: 332_083_706_004,
            minimum_maximum_participant_tower_upload_byte_length: 33_208_370_601,
            bilinear_field_multiplication_conjunction_floor: 511,
            bilinear_binary_conjunction_floor: 279_549_492,
            bilinear_evaluation_bit_length_floor: 10_063_781_712,
            bilinear_evaluation_byte_length_floor: 1_257_972_714,
            minimum_maximum_participant_bilinear_upload_byte_length_floor: 125_797_272,
        }
    );
    assert_eq!(
        floor.independent_label,
        BinaryRingPackedMpcCircuitEvaluationFloor {
            full_field_multiplication_count: 536_230,
            bit_by_field_multiplication_count: 857_160,
            bit_multiplication_count: 2_962,
            current_scalar_field_multiplication_conjunction_count: 65_536,
            current_scalar_binary_conjunction_count: 35_361_805_202,
            current_scalar_evaluation_bit_length: 1_273_024_987_272,
            current_scalar_evaluation_byte_length: 159_128_123_409,
            minimum_maximum_participant_current_scalar_upload_byte_length: 15_912_812_341,
            karatsuba_field_multiplication_conjunction_count: 6_561,
            karatsuba_binary_conjunction_count: 3_737_640_952,
            karatsuba_evaluation_bit_length: 134_555_074_272,
            karatsuba_evaluation_byte_length: 16_819_384_284,
            minimum_maximum_participant_karatsuba_upload_byte_length: 1_681_938_429,
            tower_field_multiplication_conjunction_count: 1_701,
            tower_field_multiplication_exclusive_or_count: 198_048,
            tower_binary_conjunction_count: 1_131_563_152,
            tower_binary_exclusive_or_count: 106_199_279_040,
            tower_binary_gate_count: 107_330_842_192,
            tower_evaluation_bit_length: 3_863_910_318_912,
            tower_evaluation_byte_length: 482_988_789_864,
            minimum_maximum_participant_tower_upload_byte_length: 48_298_878_987,
            bilinear_field_multiplication_conjunction_floor: 511,
            bilinear_binary_conjunction_floor: 493_449_452,
            bilinear_evaluation_bit_length_floor: 17_764_180_272,
            bilinear_evaluation_byte_length_floor: 2_220_522_534,
            minimum_maximum_participant_bilinear_upload_byte_length_floor: 222_052_254,
        }
    );
}

#[test]
fn every_admitted_shape_uses_an_explicit_large_enough_residue_field() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let floor = BinaryRingPackedMpcEvaluationFloor::derive(&circuit).unwrap();

                assert!(floor.packing.residue_field_cardinality > u64::from(participant_count) * 2);
                assert_eq!(
                    floor.source_theorem_exact_roster_shape,
                    participant_count == roster_parameters.active_fault_bound * 3 + 1
                );
                assert_circuit_floor_is_consistent(
                    floor.shared_offset,
                    floor.remote_evaluation_bit_count_per_binary_gate,
                    floor.participant_count,
                );
                assert_circuit_floor_is_consistent(
                    floor.independent_label,
                    floor.remote_evaluation_bit_count_per_binary_gate,
                    floor.participant_count,
                );
                assert!(
                    floor
                        .independent_label
                        .current_scalar_evaluation_byte_length
                        > floor.shared_offset.current_scalar_evaluation_byte_length
                );
                assert!(
                    floor
                        .independent_label
                        .bilinear_evaluation_byte_length_floor
                        > floor.shared_offset.bilinear_evaluation_byte_length_floor
                );
            }
        }
    }
}

fn assert_circuit_floor_is_consistent(
    circuit_floor: BinaryRingPackedMpcCircuitEvaluationFloor,
    remote_evaluation_bit_count_per_binary_gate: u64,
    participant_count: u64,
) {
    assert_eq!(
        circuit_floor.current_scalar_evaluation_bit_length,
        circuit_floor.current_scalar_binary_conjunction_count
            * remote_evaluation_bit_count_per_binary_gate
    );
    assert_eq!(
        circuit_floor.bilinear_evaluation_bit_length_floor,
        circuit_floor.bilinear_binary_conjunction_floor
            * remote_evaluation_bit_count_per_binary_gate
    );
    assert!(
        circuit_floor.current_scalar_evaluation_byte_length
            > circuit_floor.karatsuba_evaluation_byte_length
    );
    assert!(
        circuit_floor.karatsuba_evaluation_byte_length
            > circuit_floor.bilinear_evaluation_byte_length_floor
    );
    assert!(
        circuit_floor.tower_evaluation_byte_length
            > circuit_floor.current_scalar_evaluation_byte_length
    );
    assert_eq!(
        circuit_floor.karatsuba_evaluation_bit_length,
        circuit_floor.karatsuba_binary_conjunction_count
            * remote_evaluation_bit_count_per_binary_gate
    );
    assert_eq!(
        circuit_floor.tower_binary_gate_count,
        circuit_floor.tower_binary_conjunction_count
            + circuit_floor.tower_binary_exclusive_or_count
    );
    assert_eq!(
        circuit_floor.tower_evaluation_bit_length,
        circuit_floor.tower_binary_gate_count * remote_evaluation_bit_count_per_binary_gate
    );
    assert_eq!(
        circuit_floor.minimum_maximum_participant_current_scalar_upload_byte_length,
        circuit_floor
            .current_scalar_evaluation_byte_length
            .div_ceil(participant_count)
    );
    assert_eq!(
        circuit_floor.minimum_maximum_participant_karatsuba_upload_byte_length,
        circuit_floor
            .karatsuba_evaluation_byte_length
            .div_ceil(participant_count)
    );
    assert_eq!(
        circuit_floor.minimum_maximum_participant_tower_upload_byte_length,
        circuit_floor
            .tower_evaluation_byte_length
            .div_ceil(participant_count)
    );
    assert_eq!(
        circuit_floor.minimum_maximum_participant_bilinear_upload_byte_length_floor,
        circuit_floor
            .bilinear_evaluation_byte_length_floor
            .div_ceil(participant_count)
    );
}

fn completion_profile_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
}
