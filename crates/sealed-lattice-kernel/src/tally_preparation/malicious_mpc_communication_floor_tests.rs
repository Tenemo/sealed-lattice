use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::malicious_mpc_communication_floor::PerfectMpcCommunicationFloor;

#[test]
fn completion_profile_reproduces_the_perfect_mpc_share_material_floors() {
    let floor = PerfectMpcCommunicationFloor::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(
        floor,
        PerfectMpcCommunicationFloor {
            participant_count: 10,
            active_fault_bound: 3,
            field_element_byte_length: 32,
            result_share_separate_slice_field_element_count: 8,
            verification_share_separate_slice_field_element_count: 11,
            separate_slice_field_element_count_per_output_and_recipient: 19,
            overlap_deduplicated_field_element_count_per_output_and_recipient: 17,
            compact_field_element_count_per_output_and_recipient: 16,
            direct_logical_output_count: 1_630_304,
            first_layer_logical_output_count: 287_050,
            second_layer_logical_output_count: 1_084_400,
            maximal_layer_logical_output_count: 1_371_450,
            direct_separate_slice_remote_byte_length: 89_210_234_880,
            direct_compact_remote_byte_length: 75_124_408_320,
            maximal_layer_separate_slice_remote_byte_length: 75_045_744_000,
            maximal_layer_compact_remote_byte_length: 63_196_416_000,
            maximal_layer_compact_remote_byte_length_per_participant: 6_319_641_600,
            independent_label_direct_logical_output_count: 2_720_923,
            independent_label_first_layer_logical_output_count: 294_309,
            independent_label_second_layer_logical_output_count: 2_438_600,
            independent_label_maximal_layer_logical_output_count: 2_732_909,
            independent_label_direct_compact_remote_byte_length: 125_380_131_840,
            independent_label_maximal_layer_compact_remote_byte_length: 125_932_446_720,
            independent_label_maximal_layer_compact_remote_byte_length_per_participant:
                12_593_244_672,
        }
    );
}

#[test]
fn every_admitted_shape_uses_the_roster_fault_formula_and_lossless_slice_deductions() {
    let mut observed_layer_batching_reduction = false;
    let mut observed_layer_batching_increase = false;

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
                let floor = PerfectMpcCommunicationFloor::derive(&circuit).unwrap();
                let active_fault_bound = u64::from(roster_parameters.active_fault_bound);

                assert_eq!(floor.active_fault_bound, active_fault_bound);
                assert_eq!(
                    floor.result_share_separate_slice_field_element_count,
                    2 * (active_fault_bound + 1)
                );
                assert_eq!(
                    floor.verification_share_separate_slice_field_element_count,
                    (2 * active_fault_bound + 1) + (active_fault_bound + 1)
                );
                assert_eq!(
                    floor.overlap_deduplicated_field_element_count_per_output_and_recipient + 2,
                    floor.separate_slice_field_element_count_per_output_and_recipient
                );
                assert_eq!(
                    floor.compact_field_element_count_per_output_and_recipient + 1,
                    floor.overlap_deduplicated_field_element_count_per_output_and_recipient
                );
                assert!(
                    floor.direct_compact_remote_byte_length
                        <= floor.direct_separate_slice_remote_byte_length
                );
                let remote_dealer_recipient_pair_count =
                    floor.participant_count * (floor.participant_count - 1);
                assert_eq!(
                    floor.direct_compact_remote_byte_length,
                    floor.direct_logical_output_count
                        * floor.compact_field_element_count_per_output_and_recipient
                        * remote_dealer_recipient_pair_count
                        * floor.field_element_byte_length
                );
                assert_eq!(
                    floor.maximal_layer_compact_remote_byte_length,
                    floor.maximal_layer_logical_output_count
                        * floor.compact_field_element_count_per_output_and_recipient
                        * remote_dealer_recipient_pair_count
                        * floor.field_element_byte_length
                );
                assert_eq!(
                    floor.maximal_layer_compact_remote_byte_length,
                    floor.maximal_layer_compact_remote_byte_length_per_participant
                        * u64::from(participant_count)
                );

                observed_layer_batching_reduction |= floor.maximal_layer_compact_remote_byte_length
                    < floor.direct_compact_remote_byte_length;
                observed_layer_batching_increase |= floor.maximal_layer_compact_remote_byte_length
                    > floor.direct_compact_remote_byte_length;
            }
        }
    }

    assert!(observed_layer_batching_reduction);
    assert!(observed_layer_batching_increase);
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
