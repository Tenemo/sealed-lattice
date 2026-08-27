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
            input_bit_count: 410,
            conjunction_gate_count: 2_962,
            public_output_bit_count: 1,
            private_result_bit_count: 40,
            fresh_label_wire_count: 3_372,
            and_row_count: 11_848,
            garbling_output_bit_length_per_call: 6_410,
            garbling_output_byte_length_per_call: 802,
            garbling_output_padding_bit_count_per_call: 6,
            garbling_hash_call_count: 118_480,
            evaluation_hash_call_count: 29_620,
            garbling_share_byte_length_per_participant: 9_502_096,
            all_garbling_share_byte_length: 95_020_960,
            final_garbled_circuit_byte_length: 9_502_096,
            label_commitment_count: 67_440,
            label_commitment_byte_length: 4_316_160,
            label_share_record_count: 82_000,
            scalar_share_record_count: 122_990,
            total_share_record_count: 204_990,
            label_share_value_field_element_count: 246_000,
            scalar_share_value_field_element_count: 122_990,
            total_share_value_field_element_count: 368_990,
            dkac_verification_key_field_element_count: 573_980,
            dkac_tag_generation_field_multiplication_count: 368_990,
            raw_label_share_storage_byte_length: 7_872_000,
            raw_scalar_share_storage_byte_length: 3_935_680,
            raw_share_storage_byte_length: 11_807_680,
            dkac_commitment_byte_length: 13_119_360,
            dkac_salt_byte_length: 19_679_040,
            dkac_tag_byte_length: 6_559_680,
            dkac_verification_key_byte_length: 18_367_360,
            required_active_label_opening_record_count: 16_400,
            required_scalar_opening_record_count: 13_652,
            required_authenticated_opening_record_count: 30_052,
            required_authenticated_opening_value_field_element_count: 62_852,
            maximum_active_label_opening_record_count: 41_000,
            maximum_scalar_opening_record_count: 34_130,
            maximum_authenticated_opening_record_count: 75_130,
            maximum_authenticated_opening_value_field_element_count: 157_130,
            active_label_opening_upper_bound_byte_length: 3_673_600,
            input_mask_opening_upper_bound_byte_length: 262_400,
            active_row_opening_byte_length: 1_895_680,
            private_result_release_opening_byte_length: 25_600,
            public_nonempty_mask_opening_byte_length: 640,
            static_public_lower_bound_byte_length: 140_325_936,
            online_public_lower_bound_byte_length: 5_857_920,
            combined_known_public_lower_bound_byte_length: 146_183_856,
        }
    );
}

#[test]
fn independent_completion_inventory_rederives_every_composed_total() {
    let participant_count = 10_u64;
    let release_threshold = 4_u64;
    let input_bit_count = 410_u64;
    let conjunction_gate_count = 2_962_u64;
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

    assert_eq!(raw_share_storage, 11_807_680);
    assert_eq!(total_value_field_element_count, 368_990);
    assert_eq!(verification_key_field_element_count, 573_980);
    assert_eq!(required_label_opening_count, 16_400);
    assert_eq!(required_scalar_opening_count, 13_652);
    assert_eq!(
        required_label_opening_count * 3 + required_scalar_opening_count,
        62_852
    );
    assert_eq!(maximum_label_opening_count, 41_000);
    assert_eq!(maximum_scalar_opening_count, 34_130);
    assert_eq!(
        maximum_label_opening_count * 3 + maximum_scalar_opening_count,
        157_130
    );
    assert_eq!(static_public, 140_325_936);
    assert_eq!(online_public, 5_857_920);
    assert_eq!(static_public + online_public, 146_183_856);
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
