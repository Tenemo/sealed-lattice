use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    fixed_roster_beaver_mpc_resource_floor::{
        FixedRosterBeaverMpcResourceFloor, FixedRosterBeaverMpcScheduleFloor,
    },
    preparation_arithmetic_graph::PreparationArithmeticGraph,
    replicated_random_sharing::ReplicatedRandomSharingGeometry,
};

#[test]
fn completion_profile_reproduces_both_beaver_multiplication_schedules() {
    let floor = FixedRosterBeaverMpcResourceFloor::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(
        floor,
        FixedRosterBeaverMpcResourceFloor {
            participant_count: 10,
            active_fault_bound: 3,
            field_element_byte_length: 32,
            multiplication_count: 730_764,
            authenticated_tag_multiplication_count: 368_990,
            ordinary_multiplication_count: 361_774,
            common_authentication_coefficient_group_count: 40,
            independent_authentication_key_field_element_count: 573_980,
            common_coefficient_authentication_key_field_element_count: 205_030,
            replicated_key_count: 480,
            replicated_key_count_per_participant: 336,
            replicated_key_byte_length: 64,
            replicated_key_persistent_byte_length_per_participant: 21_504,
            private_key_component_delivery_byte_length: 1_290_240,
            private_key_component_upload_byte_length_per_participant: 129_024,
            private_key_component_download_byte_length_per_participant: 129_024,
            key_ceremony_component_peak_byte_length_per_participant: 150_528,
            triple_reduction_opening_count: 730_764,
            triple_reduction_public_field_element_count: 7_307_640,
            triple_reduction_public_byte_length: 233_844_480,
            triple_reduction_upload_byte_length_per_participant: 23_384_448,
            independent_authentication: FixedRosterBeaverMpcScheduleFloor {
                degree_three_random_sharing_instance_count: 2_192_292,
                degree_six_zero_sharing_component_count: 2_192_292,
                pseudorandom_field_output_count_per_participant: 368_305_056,
                pseudorandom_field_output_byte_length_per_participant: 11_785_761_792,
                retained_triple_field_element_count_per_participant: 2_192_292,
                retained_triple_byte_length_per_participant: 70_153_344,
                online_opening_count: 1_461_528,
                online_public_field_element_count: 14_615_280,
                online_public_byte_length: 467_688_960,
                online_upload_byte_length_per_participant: 46_768_896,
                combined_public_field_element_count: 21_922_920,
                combined_public_byte_length: 701_533_440,
                combined_upload_byte_length_per_participant: 70_153_344,
            },
            common_coefficient_authentication: FixedRosterBeaverMpcScheduleFloor {
                degree_three_random_sharing_instance_count: 1_823_342,
                degree_six_zero_sharing_component_count: 2_192_292,
                pseudorandom_field_output_count_per_participant: 337_313_256,
                pseudorandom_field_output_byte_length_per_participant: 10_794_024_192,
                retained_triple_field_element_count_per_participant: 1_823_342,
                retained_triple_byte_length_per_participant: 58_346_944,
                online_opening_count: 1_092_578,
                online_public_field_element_count: 10_925_780,
                online_public_byte_length: 349_624_960,
                online_upload_byte_length_per_participant: 34_962_496,
                combined_public_field_element_count: 18_233_420,
                combined_public_byte_length: 583_469_440,
                combined_upload_byte_length_per_participant: 58_346_944,
            },
        }
    );
}

#[test]
fn every_admitted_shape_rederives_each_schedule_from_its_canonical_owners() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let arithmetic_graph = PreparationArithmeticGraph::derive(&circuit).unwrap();
                let sharing_geometry =
                    ReplicatedRandomSharingGeometry::derive(participant_count).unwrap();
                let floor = FixedRosterBeaverMpcResourceFloor::derive(&circuit).unwrap();

                assert_eq!(floor.participant_count, u64::from(participant_count));
                assert_eq!(
                    floor.multiplication_count,
                    arithmetic_graph.total_multiplication_count
                );
                assert_eq!(
                    floor.authenticated_tag_multiplication_count,
                    arithmetic_graph.authenticated_tag_multiplication_count
                );
                assert_eq!(
                    floor.common_authentication_coefficient_group_count,
                    u64::from(participant_count)
                        * (1 + arithmetic_graph.label_body_field_limb_count)
                );
                assert_eq!(
                    floor.triple_reduction_public_field_element_count,
                    floor.multiplication_count * floor.participant_count
                );
                assert_eq!(
                    floor.private_key_component_delivery_byte_length,
                    sharing_geometry.remote_key_component_byte_length
                );
                assert_schedule_is_consistent(floor.independent_authentication, floor);
                assert_schedule_is_consistent(floor.common_coefficient_authentication, floor);
                assert!(
                    floor
                        .common_coefficient_authentication
                        .combined_public_byte_length
                        < floor.independent_authentication.combined_public_byte_length
                );
                assert!(
                    floor
                        .common_coefficient_authentication
                        .pseudorandom_field_output_byte_length_per_participant
                        < floor
                            .independent_authentication
                            .pseudorandom_field_output_byte_length_per_participant
                );
            }
        }
    }
}

fn assert_schedule_is_consistent(
    schedule: FixedRosterBeaverMpcScheduleFloor,
    floor: FixedRosterBeaverMpcResourceFloor,
) {
    assert_eq!(
        schedule.degree_six_zero_sharing_component_count,
        floor.multiplication_count * floor.active_fault_bound
    );
    assert_eq!(
        schedule.retained_triple_field_element_count_per_participant,
        schedule.degree_three_random_sharing_instance_count
    );
    assert_eq!(
        schedule.retained_triple_byte_length_per_participant,
        schedule.retained_triple_field_element_count_per_participant
            * floor.field_element_byte_length
    );
    assert_eq!(
        schedule.online_public_field_element_count,
        schedule.online_opening_count * floor.participant_count
    );
    assert_eq!(
        schedule.online_public_byte_length,
        schedule.online_public_field_element_count * floor.field_element_byte_length
    );
    assert_eq!(
        schedule.combined_public_field_element_count,
        floor.triple_reduction_public_field_element_count
            + schedule.online_public_field_element_count
    );
    assert_eq!(
        schedule.combined_public_byte_length,
        floor.triple_reduction_public_byte_length + schedule.online_public_byte_length
    );
    assert_eq!(
        schedule.combined_upload_byte_length_per_participant * floor.participant_count,
        schedule.combined_public_byte_length
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
