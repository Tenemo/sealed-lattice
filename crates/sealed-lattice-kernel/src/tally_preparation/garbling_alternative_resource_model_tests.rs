use crate::{
    foundation::{
        DECLARED_ADVERSARIAL_QUERY_BUDGET, FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::garbling_alternative_resource_model::{
    IndependentLabelGarblingResourceLowerBound, SaltedLabelCommitmentRepairLowerBound,
};

#[test]
fn completion_profile_reproduces_the_salted_commitment_repair_delta() {
    let repair =
        SaltedLabelCommitmentRepairLowerBound::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(
        repair,
        SaltedLabelCommitmentRepairLowerBound {
            label_commitment_count: 133_040,
            active_label_salt_opening_count: 66_520,
            selected_salt_bit_length: 640,
            selected_salt_byte_length: 80,
            private_salt_storage_byte_length: 10_643_200,
            active_salt_opening_byte_length: 5_321_600,
            combined_known_public_lower_bound_with_salts_byte_length: 297_091_536,
            short_salt_bit_length: 256,
            declared_adversarial_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            conditional_advantage_numerator: 4 * DECLARED_ADVERSARIAL_QUERY_BUDGET,
            short_salt_conditional_strict_power_of_two_bound_exponent: 46,
            selected_salt_conditional_strict_power_of_two_bound_exponent: 238,
        }
    );
}

#[test]
fn completion_profile_reproduces_the_independent_label_baseline() {
    let derived =
        IndependentLabelGarblingResourceLowerBound::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(
        derived,
        IndependentLabelGarblingResourceLowerBound {
            participant_count: 10,
            reconstruction_threshold: 4,
            input_bit_count: 1_230,
            conjunction_gate_count: 5_422,
            exclusive_or_gate_count: 6_283,
            negation_gate_count: 976,
            binary_gate_count: 11_705,
            evaluated_gate_count: 12_681,
            paid_gate_row_count: 48_772,
            constant_activation_vector_count: 2,
            total_labeled_wire_count: 13_913,
            public_output_bit_count: 1,
            private_result_bit_count: 40,
            garbling_output_bit_length_per_call: 6_410,
            garbling_output_byte_length_per_call: 802,
            garbling_generation_call_count: 487_720,
            garbling_evaluation_call_count: 126_810,
            garbling_share_byte_length_per_participant: 39_115_144,
            all_garbling_share_byte_length: 391_151_440,
            paid_garbled_row_byte_length: 39_115_144,
            constant_activation_vector_byte_length: 1_604,
            final_garbled_circuit_byte_length: 39_116_748,
            label_commitment_count: 278_260,
            label_commitment_byte_length: 17_808_640,
            label_share_record_count: 246_000,
            scalar_share_record_count: 500_430,
            total_share_record_count: 746_430,
            total_share_value_field_element_count: 1_238_430,
            dkac_verification_key_field_element_count: 1_984_860,
            dkac_tag_generation_field_multiplication_count: 1_238_430,
            raw_label_share_storage_byte_length: 23_616_000,
            raw_scalar_share_storage_byte_length: 16_013_760,
            raw_share_storage_byte_length: 39_629_760,
            dkac_commitment_byte_length: 47_771_520,
            dkac_salt_byte_length: 71_657_280,
            dkac_tag_byte_length: 23_885_760,
            dkac_verification_key_byte_length: 63_515_520,
            active_label_opening_upper_bound_byte_length: 11_020_800,
            input_mask_opening_upper_bound_byte_length: 787_200,
            active_row_opening_byte_length: 8_115_840,
            private_result_release_opening_byte_length: 25_600,
            public_nonempty_mask_opening_byte_length: 640,
            static_public_lower_bound_byte_length: 559_363_868,
            online_public_lower_bound_byte_length: 19_950_080,
            combined_known_public_lower_bound_byte_length: 579_313_948,
        }
    );
}

#[test]
fn alternative_formulas_follow_every_admitted_shape() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let geometry = circuit.geometry();
                let independent =
                    IndependentLabelGarblingResourceLowerBound::derive(&circuit).unwrap();
                let salted = SaltedLabelCommitmentRepairLowerBound::derive(&circuit).unwrap();

                assert_eq!(
                    independent.binary_gate_count,
                    geometry.conjunction_gate_count as u64
                        + geometry.exclusive_or_gate_count as u64
                );
                assert_eq!(
                    independent.evaluated_gate_count,
                    independent.binary_gate_count + geometry.negation_gate_count as u64
                );
                assert_eq!(
                    independent.paid_gate_row_count,
                    independent.binary_gate_count * 4 + geometry.negation_gate_count as u64 * 2
                );
                assert_eq!(
                    independent.final_garbled_circuit_byte_length,
                    independent.paid_garbled_row_byte_length
                        + independent.constant_activation_vector_byte_length
                );
                assert_eq!(
                    independent.combined_known_public_lower_bound_byte_length,
                    independent.static_public_lower_bound_byte_length
                        + independent.online_public_lower_bound_byte_length
                );
                assert_eq!(
                    salted.active_label_salt_opening_count * 2,
                    salted.label_commitment_count
                );
                assert_eq!(
                    salted.combined_known_public_lower_bound_with_salts_byte_length
                        - salted.active_salt_opening_byte_length,
                    super::garbled_resource_model::GarbledTallyResourceLowerBound::derive(&circuit)
                        .unwrap()
                        .combined_known_public_lower_bound_byte_length
                );
            }
        }
    }
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
