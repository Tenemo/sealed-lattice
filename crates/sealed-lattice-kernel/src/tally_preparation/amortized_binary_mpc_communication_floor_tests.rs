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
            binary_conjunction_count: 718_647_592,
            packed_multiplication_count: 239_549_198,
            public_reconstruction_batch_count: 59_887_300,
            random_subspace_generation_batch_count: 11_977_460,
            public_reconstruction_remote_field_element_count: 10_779_714_000,
            random_subspace_generation_remote_field_element_count: 17_247_542_400,
            known_remote_field_element_count: 28_027_256_400,
            known_remote_bit_length: 140_136_282_000,
            known_remote_byte_length: 17_517_035_250,
            minimum_maximum_participant_upload_byte_length: 1_751_703_525,
        }
    );
    assert_eq!(
        floor.independent_label,
        AmortizedBinaryMpcCircuitCommunicationFloor {
            binary_conjunction_count: 1_131_563_152,
            packed_multiplication_count: 377_187_718,
            public_reconstruction_batch_count: 94_296_930,
            random_subspace_generation_batch_count: 18_859_386,
            public_reconstruction_remote_field_element_count: 16_973_447_400,
            random_subspace_generation_remote_field_element_count: 27_157_515_840,
            known_remote_field_element_count: 44_130_963_240,
            known_remote_bit_length: 220_654_816_200,
            known_remote_byte_length: 27_581_852_025,
            minimum_maximum_participant_upload_byte_length: 2_758_185_203,
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
