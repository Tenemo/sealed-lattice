use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile},
};

use super::garbled_resource_model::GarbledTallyResourceLowerBound;

#[test]
fn completion_profile_reproduces_the_corrected_known_lower_bound() {
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    let derived = GarbledTallyResourceLowerBound::derive(&circuit).unwrap();

    assert_eq!(
        derived,
        GarbledTallyResourceLowerBound {
            participant_count: 10,
            reconstruction_threshold: 4,
            input_bit_count: 1_230,
            conjunction_gate_count: 5_422,
            public_output_bit_count: 1,
            private_result_bit_count: 40,
            fresh_label_wire_count: 6_652,
            and_row_count: 21_688,
            garbling_output_bit_length_per_call: 6_410,
            garbling_output_byte_length_per_call: 802,
            garbling_output_padding_bit_count_per_call: 6,
            garbling_hash_call_count: 216_880,
            evaluation_hash_call_count: 54_220,
            garbling_share_byte_length_per_participant: 17_393_776,
            all_garbling_share_byte_length: 173_937_760,
            final_garbled_circuit_byte_length: 17_393_776,
            label_commitment_count: 133_040,
            label_commitment_byte_length: 8_514_560,
            label_share_record_count: 246_000,
            scalar_share_record_count: 229_590,
            total_share_record_count: 475_590,
            label_share_value_field_element_count: 738_000,
            scalar_share_value_field_element_count: 229_590,
            total_share_value_field_element_count: 967_590,
            dkac_verification_key_field_element_count: 1_443_180,
            dkac_tag_generation_field_multiplication_count: 967_590,
            raw_label_share_storage_byte_length: 23_616_000,
            raw_scalar_share_storage_byte_length: 7_346_880,
            raw_share_storage_byte_length: 30_962_880,
            dkac_commitment_byte_length: 30_437_760,
            dkac_salt_byte_length: 45_656_640,
            dkac_tag_byte_length: 15_218_880,
            dkac_verification_key_byte_length: 46_181_760,
            required_active_label_opening_record_count: 49_200,
            required_scalar_opening_record_count: 26_772,
            required_authenticated_opening_record_count: 75_972,
            required_authenticated_opening_value_field_element_count: 174_372,
            maximum_active_label_opening_record_count: 123_000,
            maximum_scalar_opening_record_count: 66_930,
            maximum_authenticated_opening_record_count: 189_930,
            maximum_authenticated_opening_value_field_element_count: 435_930,
            active_label_opening_upper_bound_byte_length: 11_020_800,
            input_mask_opening_upper_bound_byte_length: 787_200,
            active_row_opening_byte_length: 3_470_080,
            private_result_release_opening_byte_length: 25_600,
            public_nonempty_mask_opening_byte_length: 640,
            static_public_lower_bound_byte_length: 276_465_616,
            online_public_lower_bound_byte_length: 15_304_320,
            combined_known_public_lower_bound_byte_length: 291_769_936,
        }
    );
}

#[test]
fn independent_completion_inventory_rederives_every_composed_total() {
    let participant_count = 10_u64;
    let release_threshold = 4_u64;
    let input_bit_count = 1_230_u64;
    let conjunction_gate_count = 5_422_u64;
    let output_bit_count = 41_u64;
    let private_result_bit_count = 40_u64;
    let fresh_label_wire_count = input_bit_count + conjunction_gate_count;
    let and_row_count = conjunction_gate_count * 4;
    let garbling_output_byte_length = (participant_count * 641).div_ceil(8);
    let label_commitment_count = 2 * fresh_label_wire_count * participant_count;
    let label_record_count = 2 * input_bit_count * participant_count * participant_count;
    let scalar_record_count = input_bit_count * participant_count
        + and_row_count * participant_count
        + output_bit_count * participant_count;
    let total_record_count = label_record_count + scalar_record_count;
    let label_value_field_element_count = label_record_count * 3;
    let total_value_field_element_count = label_value_field_element_count + scalar_record_count;
    let verification_key_field_element_count = label_record_count * 4 + scalar_record_count * 2;
    let required_label_opening_count = input_bit_count * participant_count * release_threshold;
    let required_scalar_opening_count =
        (input_bit_count + conjunction_gate_count + output_bit_count) * release_threshold;
    let maximum_label_opening_count = input_bit_count * participant_count * participant_count;
    let maximum_scalar_opening_count =
        (input_bit_count + conjunction_gate_count + output_bit_count) * participant_count;
    let raw_share_storage = label_record_count * 96 + scalar_record_count * 32;
    let static_public = participant_count * and_row_count * garbling_output_byte_length
        + and_row_count * garbling_output_byte_length
        + label_commitment_count * 64
        + total_record_count * 64
        + label_record_count * 128
        + scalar_record_count * 64;
    let online_public = input_bit_count * participant_count * release_threshold * (96 + 32 + 96)
        + input_bit_count * release_threshold * (32 + 32 + 96)
        + conjunction_gate_count * release_threshold * (32 + 32 + 96)
        + private_result_bit_count * release_threshold * (32 + 32 + 96)
        + release_threshold * (32 + 32 + 96);

    assert_eq!(raw_share_storage, 30_962_880);
    assert_eq!(total_value_field_element_count, 967_590);
    assert_eq!(verification_key_field_element_count, 1_443_180);
    assert_eq!(required_label_opening_count, 49_200);
    assert_eq!(required_scalar_opening_count, 26_772);
    assert_eq!(
        required_label_opening_count * 3 + required_scalar_opening_count,
        174_372
    );
    assert_eq!(maximum_label_opening_count, 123_000);
    assert_eq!(maximum_scalar_opening_count, 66_930);
    assert_eq!(
        maximum_label_opening_count * 3 + maximum_scalar_opening_count,
        435_930
    );
    assert_eq!(static_public, 276_465_616);
    assert_eq!(online_public, 15_304_320);
    assert_eq!(static_public + online_public, 291_769_936);
}

#[test]
fn resource_formulas_follow_every_admitted_circuit_shape_and_roster_formula() {
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
                let derived = GarbledTallyResourceLowerBound::derive(&circuit).unwrap();
                let independently_counted_conjunctions = circuit
                    .operations()
                    .iter()
                    .filter(|operation| matches!(operation, BooleanOperation::Conjunction { .. }))
                    .count() as u64;
                let independently_counted_private_outputs = circuit
                    .ordered_option_position_wires()
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>()
                    as u64;

                assert_eq!(derived.participant_count, u64::from(participant_count));
                assert_eq!(
                    derived.reconstruction_threshold,
                    u64::from(roster_parameters.reconstruction_threshold)
                );
                assert_eq!(
                    derived.conjunction_gate_count,
                    independently_counted_conjunctions
                );
                assert_eq!(
                    derived.private_result_bit_count,
                    independently_counted_private_outputs
                );
                assert_eq!(
                    derived.garbling_output_byte_length_per_call,
                    (u64::from(participant_count) * 641).div_ceil(8)
                );
                assert_eq!(
                    derived.raw_label_share_storage_byte_length,
                    derived.label_share_record_count * 96
                );
                assert_eq!(
                    derived.total_share_value_field_element_count,
                    derived.label_share_record_count * 3 + derived.scalar_share_record_count
                );
                assert_eq!(
                    derived.dkac_verification_key_field_element_count,
                    derived.label_share_record_count * 4 + derived.scalar_share_record_count * 2
                );
                assert_eq!(
                    derived.required_authenticated_opening_record_count,
                    derived.required_active_label_opening_record_count
                        + derived.required_scalar_opening_record_count
                );
                assert_eq!(
                    derived.maximum_authenticated_opening_record_count,
                    derived.maximum_active_label_opening_record_count
                        + derived.maximum_scalar_opening_record_count
                );
                assert_eq!(
                    derived.combined_known_public_lower_bound_byte_length,
                    derived.static_public_lower_bound_byte_length
                        + derived.online_public_lower_bound_byte_length
                );
            }
        }
    }
}
