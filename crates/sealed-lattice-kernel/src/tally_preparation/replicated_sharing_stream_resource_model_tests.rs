use crate::{
    foundation::FOUNDATION_PROFILE,
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    fixed_roster_beaver_mpc_resource_floor::FixedRosterBeaverMpcResourceFloor,
    replicated_key_ceremony::{REPLICATED_KEY_ARTIFACT_VERSION, REPLICATED_KEY_COORDINATE_MAGIC},
    replicated_sharing_field_stream::REPLICATED_SHARING_FIELD_STREAM_DOMAIN,
    replicated_sharing_stream_resource_model::{
        ReplicatedSharingFieldStreamResourceModel, ReplicatedSharingFieldStreamScheduleModel,
    },
};

#[test]
fn completion_profile_reproduces_the_exact_chunked_stream_census() {
    let model =
        ReplicatedSharingFieldStreamResourceModel::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(
        model,
        ReplicatedSharingFieldStreamResourceModel {
            participant_count: 10,
            field_element_byte_length: 32,
            field_element_count_per_full_chunk: 32_768,
            configured_chunk_byte_length: 1_048_576,
            independent_authentication: ReplicatedSharingFieldStreamScheduleModel {
                field_stream_count_per_participant: 504,
                naive_per_field_xof_invocation_count_per_participant: 821_673_216,
                chunked_xof_invocation_count_per_participant: 25_200,
                total_chunked_xof_invocation_count: 252_000,
                field_output_count_per_participant: 821_673_216,
                field_output_byte_length_per_participant: 26_293_542_912,
                total_field_output_byte_length: 262_935_429_120,
                minimum_absorbed_query_byte_length_per_participant: 9_275_700,
                maximum_absorbed_query_byte_length_per_participant: 9_280_200,
                total_absorbed_query_byte_length: 92_788_500,
                maximum_single_query_byte_length: 369,
                maximum_single_output_byte_length: 1_048_576,
                maximum_chunk_boundary_recomputation_byte_length: 1_048_576,
            },
            common_coefficient_authentication: ReplicatedSharingFieldStreamScheduleModel {
                field_stream_count_per_participant: 1_008,
                naive_per_field_xof_invocation_count_per_participant: 740_399_016,
                chunked_xof_invocation_count_per_participant: 23_268,
                total_chunked_xof_invocation_count: 232_680,
                field_output_count_per_participant: 740_399_016,
                field_output_byte_length_per_participant: 23_692_768_512,
                total_field_output_byte_length: 236_927_685_120,
                minimum_absorbed_query_byte_length_per_participant: 8_565_781,
                maximum_absorbed_query_byte_length_per_participant: 8_569_936,
                total_absorbed_query_byte_length: 85_686_895,
                maximum_single_query_byte_length: 369,
                maximum_single_output_byte_length: 1_048_576,
                maximum_chunk_boundary_recomputation_byte_length: 1_048_576,
            },
        }
    );
}

#[test]
fn independent_completion_derivation_matches_each_production_schedule() {
    let circuit = completion_profile_circuit();
    let production = ReplicatedSharingFieldStreamResourceModel::derive(&circuit).unwrap();
    let beaver_floor = FixedRosterBeaverMpcResourceFloor::derive(&circuit).unwrap();
    let independent = independently_derive_completion_schedule_inputs();

    assert_eq!(independent.participant_count, production.participant_count);
    assert_eq!(independent.maximum_query_byte_length, 369);
    assert_eq!(
        independent.independent_absorbed_query_bytes,
        production
            .independent_authentication
            .total_absorbed_query_byte_length
    );
    assert_eq!(
        independent.common_absorbed_query_bytes,
        production
            .common_coefficient_authentication
            .total_absorbed_query_byte_length
    );
    assert_eq!(
        independent.independent_xof_calls_per_participant,
        production
            .independent_authentication
            .chunked_xof_invocation_count_per_participant
    );
    assert_eq!(
        independent.common_xof_calls_per_participant,
        production
            .common_coefficient_authentication
            .chunked_xof_invocation_count_per_participant
    );
    assert_eq!(
        production
            .independent_authentication
            .field_output_count_per_participant,
        beaver_floor
            .independent_authentication
            .pseudorandom_field_output_count_per_participant
    );
    assert_eq!(
        production
            .common_coefficient_authentication
            .field_output_count_per_participant,
        beaver_floor
            .common_coefficient_authentication
            .pseudorandom_field_output_count_per_participant
    );
}

#[derive(Debug, Clone, Copy)]
struct IndependentCompletionScheduleInputs {
    participant_count: u64,
    independent_xof_calls_per_participant: u64,
    common_xof_calls_per_participant: u64,
    independent_absorbed_query_bytes: u64,
    common_absorbed_query_bytes: u64,
    maximum_query_byte_length: u64,
}

fn independently_derive_completion_schedule_inputs() -> IndependentCompletionScheduleInputs {
    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    let active_fault_bound = u64::from(FOUNDATION_PROFILE.active_fault_bound);
    assert_eq!((participant_count, active_fault_bound), (10, 3));
    let independent_chunk_count = 50_u64;
    let ordinary_chunk_count = 21_u64;
    let authentication_chunk_count = 30_u64;
    let common_coefficient_chunk_count = 1_u64;
    let independent_random_calls_per_subset = 3 * independent_chunk_count;
    let independent_zero_calls_per_subset = active_fault_bound * independent_chunk_count;
    let common_random_calls_per_subset =
        3 * ordinary_chunk_count + 2 * authentication_chunk_count + common_coefficient_chunk_count;
    let common_zero_calls_per_subset =
        active_fault_bound * (ordinary_chunk_count + authentication_chunk_count);
    let mut independent_absorbed_query_bytes = 0_u64;
    let mut common_absorbed_query_bytes = 0_u64;
    let mut independent_calls_by_participant = vec![0_u64; participant_count as usize];
    let mut common_calls_by_participant = vec![0_u64; participant_count as usize];
    let mut maximum_query_byte_length = 0_u64;

    for excluded_mask in 0_u32..(1_u32 << participant_count) {
        if u64::from(excluded_mask.count_ones()) != active_fault_bound {
            continue;
        }
        let random_coordinate_byte_length =
            independent_coordinate_byte_length(participant_count, u64::from(excluded_mask), false);
        let zero_coordinate_byte_length =
            independent_coordinate_byte_length(participant_count, u64::from(excluded_mask), true);
        let random_query_byte_length = independent_query_byte_length(random_coordinate_byte_length);
        let zero_query_byte_length = independent_query_byte_length(zero_coordinate_byte_length);
        maximum_query_byte_length = maximum_query_byte_length
            .max(random_query_byte_length)
            .max(zero_query_byte_length);

        for participant_position in 0..participant_count {
            if excluded_mask & (1_u32 << participant_position) != 0 {
                continue;
            }
            let independent_calls =
                independent_random_calls_per_subset + independent_zero_calls_per_subset;
            let common_calls = common_random_calls_per_subset + common_zero_calls_per_subset;
            independent_calls_by_participant[participant_position as usize] += independent_calls;
            common_calls_by_participant[participant_position as usize] += common_calls;
            independent_absorbed_query_bytes += random_query_byte_length
                * independent_random_calls_per_subset
                + zero_query_byte_length * independent_zero_calls_per_subset;
            common_absorbed_query_bytes += random_query_byte_length
                * common_random_calls_per_subset
                + zero_query_byte_length * common_zero_calls_per_subset;
        }
    }

    IndependentCompletionScheduleInputs {
        participant_count,
        independent_xof_calls_per_participant: uniform(&independent_calls_by_participant),
        common_xof_calls_per_participant: uniform(&common_calls_by_participant),
        independent_absorbed_query_bytes,
        common_absorbed_query_bytes,
        maximum_query_byte_length,
    }
}

fn independent_coordinate_byte_length(
    participant_count: u64,
    excluded_mask: u64,
    degree_double_zero_key: bool,
) -> u64 {
    framed_length(REPLICATED_KEY_COORDINATE_MAGIC.len() as u64)
        + varuint_length(REPLICATED_KEY_ARTIFACT_VERSION)
        + framed_length(64)
        + varuint_length(participant_count)
        + varuint_length(excluded_mask)
        + varuint_length(if degree_double_zero_key { 2 } else { 1 })
        + u64::from(degree_double_zero_key)
}

fn independent_query_byte_length(coordinate_byte_length: u64) -> u64 {
    let tuple_header_byte_length = 8_u64;
    let item_count = 10_u64;
    let item_header_byte_length = 6_u64;
    let domain_payload_byte_length = 4 + REPLICATED_SHARING_FIELD_STREAM_DOMAIN.len() as u64;
    let key_payload_byte_length = 64_u64;
    let coordinate_payload_byte_length = 4 + coordinate_byte_length;
    let purpose_payload_byte_length = 2_u64;
    let unsigned64_payload_byte_length = 6 * 8_u64;
    tuple_header_byte_length
        + item_count * item_header_byte_length
        + domain_payload_byte_length
        + key_payload_byte_length
        + coordinate_payload_byte_length
        + purpose_payload_byte_length
        + unsigned64_payload_byte_length
}

fn framed_length(byte_length: u64) -> u64 {
    varuint_length(byte_length) + byte_length
}

fn varuint_length(mut value: u64) -> u64 {
    let mut byte_length = 1_u64;
    while value >= 128 {
        value >>= 7;
        byte_length += 1;
    }
    byte_length
}

fn uniform(values: &[u64]) -> u64 {
    let first = values[0];
    assert!(values.iter().all(|value| *value == first));
    first
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
