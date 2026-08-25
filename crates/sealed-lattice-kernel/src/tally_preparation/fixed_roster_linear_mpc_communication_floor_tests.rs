use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::fixed_roster_linear_mpc_communication_floor::{
    FixedRosterLinearMpcCircuitFloor, FixedRosterLinearMpcCommunicationFloor,
};

#[test]
fn completion_profile_reproduces_the_fixed_roster_accepted_path_floor() {
    let floor =
        FixedRosterLinearMpcCommunicationFloor::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(floor.participant_count, 10);
    assert_eq!(floor.active_fault_bound, 3);
    assert_eq!(floor.multiplication_batch_size, 4);
    assert_eq!(floor.field_element_byte_length, 32);
    assert_eq!(
        floor.triple_sharing_distribution_field_element_count_per_invocation,
        270
    );
    assert_eq!(
        floor.triple_sharing_check_field_element_count_per_invocation,
        162
    );
    assert_eq!(floor.triple_sharing_field_element_count_per_invocation, 432);
    assert_eq!(
        floor.batched_reconstruction_field_element_count_per_invocation,
        180
    );
    assert_eq!(
        floor.multiplication_tuple_generation_field_element_count_per_segment,
        1_476
    );
    assert_eq!(
        floor.evaluation_exchange_field_element_count_per_segment,
        144
    );
    assert_eq!(floor.consistency_check_field_element_count_per_segment, 126);
    assert_eq!(
        floor.reconstruction_check_field_element_count_per_segment,
        360
    );
    assert_eq!(floor.known_remote_field_element_count_per_segment, 2_106);
    assert_eq!(floor.known_fault_detection_bit_length_per_segment, 270);
    assert_eq!(
        floor.shared_offset,
        FixedRosterLinearMpcCircuitFloor {
            multiplication_count: 1_630_304,
            segment_count: 407_576,
            padded_multiplication_count: 1_630_304,
            known_remote_field_element_count: 858_355_056,
            known_remote_byte_length: 27_467_361_792,
            minimum_maximum_participant_upload_byte_length: 2_746_736_180,
            known_fault_detection_bit_length: 110_045_520,
        }
    );
    assert_eq!(
        floor.independent_label,
        FixedRosterLinearMpcCircuitFloor {
            multiplication_count: 2_720_923,
            segment_count: 680_231,
            padded_multiplication_count: 2_720_924,
            known_remote_field_element_count: 1_432_566_486,
            known_remote_byte_length: 45_842_127_552,
            minimum_maximum_participant_upload_byte_length: 4_584_212_756,
            known_fault_detection_bit_length: 183_662_370,
        }
    );
}

#[test]
fn every_admitted_shape_uses_the_fixed_roster_batch_and_pads_by_less_than_one_batch() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        let expected_batch_size =
            u64::from(participant_count - 2 * roster_parameters.active_fault_bound);
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let floor = FixedRosterLinearMpcCommunicationFloor::derive(&circuit).unwrap();

                assert_eq!(floor.multiplication_batch_size, expected_batch_size);
                assert_circuit_floor_is_consistent(
                    floor.shared_offset,
                    floor.multiplication_batch_size,
                    floor.known_remote_field_element_count_per_segment,
                    floor.known_fault_detection_bit_length_per_segment,
                    floor.field_element_byte_length,
                    floor.participant_count,
                );
                assert_circuit_floor_is_consistent(
                    floor.independent_label,
                    floor.multiplication_batch_size,
                    floor.known_remote_field_element_count_per_segment,
                    floor.known_fault_detection_bit_length_per_segment,
                    floor.field_element_byte_length,
                    floor.participant_count,
                );
                assert!(
                    floor.independent_label.known_remote_byte_length
                        > floor.shared_offset.known_remote_byte_length
                );
            }
        }
    }
}

fn assert_circuit_floor_is_consistent(
    circuit_floor: FixedRosterLinearMpcCircuitFloor,
    multiplication_batch_size: u64,
    field_element_count_per_segment: u64,
    fault_detection_bit_length_per_segment: u64,
    field_element_byte_length: u64,
    participant_count: u64,
) {
    assert!(circuit_floor.multiplication_count > 0);
    assert!(circuit_floor.padded_multiplication_count >= circuit_floor.multiplication_count);
    assert!(
        circuit_floor.padded_multiplication_count - circuit_floor.multiplication_count
            < multiplication_batch_size
    );
    assert_eq!(
        circuit_floor.padded_multiplication_count,
        circuit_floor.segment_count * multiplication_batch_size
    );
    assert_eq!(
        circuit_floor.known_remote_field_element_count,
        circuit_floor.segment_count * field_element_count_per_segment
    );
    assert_eq!(
        circuit_floor.known_remote_byte_length,
        circuit_floor.known_remote_field_element_count * field_element_byte_length
    );
    assert_eq!(
        circuit_floor.known_fault_detection_bit_length,
        circuit_floor.segment_count * fault_detection_bit_length_per_segment
    );
    assert!(
        circuit_floor.minimum_maximum_participant_upload_byte_length * participant_count
            >= circuit_floor.known_remote_byte_length
    );
    assert!(
        (circuit_floor.minimum_maximum_participant_upload_byte_length - 1) * participant_count
            < circuit_floor.known_remote_byte_length
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
