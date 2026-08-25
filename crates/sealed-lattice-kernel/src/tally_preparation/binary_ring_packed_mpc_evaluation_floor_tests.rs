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
            full_field_multiplication_count: 967_590,
            bit_by_field_multiplication_count: 650_640,
            bit_multiplication_count: 5_422,
            current_scalar_field_multiplication_conjunction_count: 65_536,
            current_scalar_binary_conjunction_count: 63_578_547_502,
            current_scalar_evaluation_bit_length: 2_288_827_710_072,
            current_scalar_evaluation_byte_length: 286_103_463_759,
            minimum_maximum_participant_current_scalar_upload_byte_length: 28_610_346_376,
            karatsuba_field_multiplication_conjunction_count: 6_561,
            karatsuba_binary_conjunction_count: 6_514_927_252,
            karatsuba_evaluation_bit_length: 234_537_381_072,
            karatsuba_evaluation_byte_length: 29_317_172_634,
            minimum_maximum_participant_karatsuba_upload_byte_length: 2_931_717_264,
            tower_field_multiplication_conjunction_count: 1_701,
            tower_field_multiplication_exclusive_or_count: 198_048,
            tower_binary_conjunction_count: 1_812_439_852,
            tower_binary_exclusive_or_count: 191_629_264_320,
            tower_binary_gate_count: 193_441_704_172,
            tower_evaluation_bit_length: 6_963_901_350_192,
            tower_evaluation_byte_length: 870_487_668_774,
            minimum_maximum_participant_tower_upload_byte_length: 87_048_766_878,
            bilinear_field_multiplication_conjunction_floor: 511,
            bilinear_binary_conjunction_floor: 661_007_752,
            bilinear_evaluation_bit_length_floor: 23_796_279_072,
            bilinear_evaluation_byte_length_floor: 2_974_534_884,
            minimum_maximum_participant_bilinear_upload_byte_length_floor: 297_453_489,
        }
    );
    assert_eq!(
        floor.independent_label,
        BinaryRingPackedMpcCircuitEvaluationFloor {
            full_field_multiplication_count: 1_238_430,
            bit_by_field_multiplication_count: 1_463_160,
            bit_multiplication_count: 5_422,
            current_scalar_field_multiplication_conjunction_count: 65_536,
            current_scalar_binary_conjunction_count: 81_536_322_862,
            current_scalar_evaluation_bit_length: 2_935_307_623_032,
            current_scalar_evaluation_byte_length: 366_913_452_879,
            minimum_maximum_participant_current_scalar_upload_byte_length: 36_691_345_288,
            karatsuba_field_multiplication_conjunction_count: 6_561,
            karatsuba_binary_conjunction_count: 8_499_913_612,
            karatsuba_evaluation_bit_length: 305_996_890_032,
            karatsuba_evaluation_byte_length: 38_249_611_254,
            minimum_maximum_participant_karatsuba_upload_byte_length: 3_824_961_126,
            tower_field_multiplication_conjunction_count: 1_701,
            tower_field_multiplication_exclusive_or_count: 198_048,
            tower_binary_conjunction_count: 2_481_143_812,
            tower_binary_exclusive_or_count: 245_268_584_640,
            tower_binary_gate_count: 247_749_728_452,
            tower_evaluation_bit_length: 8_918_990_224_272,
            tower_evaluation_byte_length: 1_114_873_778_034,
            minimum_maximum_participant_tower_upload_byte_length: 111_487_377_804,
            bilinear_field_multiplication_conjunction_floor: 511,
            bilinear_binary_conjunction_floor: 1_007_412_112,
            bilinear_evaluation_bit_length_floor: 36_266_836_032,
            bilinear_evaluation_byte_length_floor: 4_533_354_504,
            minimum_maximum_participant_bilinear_upload_byte_length_floor: 453_335_451,
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
