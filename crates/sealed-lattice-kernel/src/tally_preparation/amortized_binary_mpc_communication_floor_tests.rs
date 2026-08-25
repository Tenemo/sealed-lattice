use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::amortized_binary_mpc_communication_floor::{
    AmortizedBinaryMpcCircuitCommunicationFloor, AmortizedBinaryMpcCommunicationFloor,
    BinaryCircuitAmortizationParameters,
};

#[test]
fn completion_profile_reproduces_both_amortized_binary_mpc_floors() {
    let floor =
        AmortizedBinaryMpcCommunicationFloor::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(floor.participant_count, 10);
    assert_eq!(floor.active_fault_bound, 3);
    assert_eq!(floor.robust_reconstruction_batch_size, 4);
    assert_eq!(
        floor.amortization,
        BinaryCircuitAmortizationParameters {
            packed_value_count: 3,
            extension_degree: 5,
            extension_field_cardinality: 32,
        }
    );
    assert_eq!(
        floor.public_reconstruction_remote_field_elements_per_batch,
        180
    );
    assert_eq!(floor.random_subspace_outputs_per_batch, 20);
    assert_eq!(floor.random_subspace_remote_field_elements_per_batch, 1_440);
    assert_eq!(
        floor.shared_offset,
        AmortizedBinaryMpcCircuitCommunicationFloor {
            binary_conjunction_count: 1_812_439_852,
            packed_multiplication_count: 604_146_618,
            public_reconstruction_batch_count: 151_036_655,
            random_subspace_generation_batch_count: 30_207_331,
            public_reconstruction_remote_field_element_count: 27_186_597_900,
            random_subspace_generation_remote_field_element_count: 43_498_556_640,
            known_remote_field_element_count: 70_685_154_540,
            known_remote_bit_length: 353_425_772_700,
            known_remote_byte_length: 44_178_221_588,
            minimum_maximum_participant_upload_byte_length: 4_417_822_159,
        }
    );
    assert_eq!(
        floor.independent_label,
        AmortizedBinaryMpcCircuitCommunicationFloor {
            binary_conjunction_count: 2_481_143_812,
            packed_multiplication_count: 827_047_938,
            public_reconstruction_batch_count: 206_761_985,
            random_subspace_generation_batch_count: 41_352_397,
            public_reconstruction_remote_field_element_count: 37_217_157_300,
            random_subspace_generation_remote_field_element_count: 59_547_451_680,
            known_remote_field_element_count: 96_764_608_980,
            known_remote_bit_length: 483_823_044_900,
            known_remote_byte_length: 60_477_880_613,
            minimum_maximum_participant_upload_byte_length: 6_047_788_062,
        }
    );
}

#[test]
fn every_admitted_shape_has_valid_amortization_and_consistent_counts() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let floor = AmortizedBinaryMpcCommunicationFloor::derive(&circuit).unwrap();

                assert!(
                    floor.amortization.extension_field_cardinality
                        > u64::from(participant_count) * 2
                );
                assert_eq!(
                    floor.robust_reconstruction_batch_size,
                    floor.participant_count - floor.active_fault_bound * 2
                );
                assert_circuit_floor_is_consistent(floor.shared_offset, floor);
                assert_circuit_floor_is_consistent(floor.independent_label, floor);
                assert!(
                    floor.independent_label.known_remote_byte_length
                        > floor.shared_offset.known_remote_byte_length
                );
            }
        }
    }
}

fn assert_circuit_floor_is_consistent(
    circuit_floor: AmortizedBinaryMpcCircuitCommunicationFloor,
    floor: AmortizedBinaryMpcCommunicationFloor,
) {
    assert_eq!(
        circuit_floor.packed_multiplication_count,
        circuit_floor
            .binary_conjunction_count
            .div_ceil(floor.amortization.packed_value_count)
    );
    assert_eq!(
        circuit_floor.public_reconstruction_batch_count,
        circuit_floor
            .packed_multiplication_count
            .div_ceil(floor.robust_reconstruction_batch_size)
    );
    assert_eq!(
        circuit_floor.random_subspace_generation_batch_count,
        circuit_floor
            .packed_multiplication_count
            .div_ceil(floor.random_subspace_outputs_per_batch)
    );
    assert_eq!(
        circuit_floor.known_remote_field_element_count,
        circuit_floor.public_reconstruction_remote_field_element_count
            + circuit_floor.random_subspace_generation_remote_field_element_count
    );
    assert_eq!(
        circuit_floor.known_remote_bit_length,
        circuit_floor.known_remote_field_element_count * floor.amortization.extension_degree
    );
    assert_eq!(
        circuit_floor.minimum_maximum_participant_upload_byte_length,
        circuit_floor
            .known_remote_byte_length
            .div_ceil(floor.participant_count)
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
