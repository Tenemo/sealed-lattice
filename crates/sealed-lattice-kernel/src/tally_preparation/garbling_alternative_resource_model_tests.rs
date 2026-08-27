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
            label_commitment_count: 67_440,
            active_label_salt_opening_count: 33_720,
            selected_salt_bit_length: 640,
            selected_salt_byte_length: 80,
            private_salt_storage_byte_length: 5_395_200,
            active_salt_opening_byte_length: 2_697_600,
            combined_known_public_lower_bound_with_salts_byte_length: 148_881_456,
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
            input_bit_count: 410,
            conjunction_gate_count: 2_962,
            exclusive_or_gate_count: 3_803,
            negation_gate_count: 756,
            binary_gate_count: 6_765,
            evaluated_gate_count: 7_521,
            paid_gate_row_count: 28_572,
            constant_activation_vector_count: 2,
            total_labeled_wire_count: 7_933,
            public_output_bit_count: 1,
            private_result_bit_count: 40,
            garbling_output_bit_length_per_call: 6_410,
            garbling_output_byte_length_per_call: 802,
            garbling_generation_call_count: 285_720,
            garbling_evaluation_call_count: 75_210,
            garbling_share_byte_length_per_participant: 22_914_744,
            all_garbling_share_byte_length: 229_147_440,
            paid_garbled_row_byte_length: 22_914_744,
            constant_activation_vector_byte_length: 1_604,
            final_garbled_circuit_byte_length: 22_916_348,
            label_commitment_count: 158_660,
            label_commitment_byte_length: 10_154_240,
            label_share_record_count: 82_000,
            scalar_share_record_count: 290_230,
            total_share_record_count: 372_230,
            total_share_value_field_element_count: 536_230,
            dkac_verification_key_field_element_count: 908_460,
            dkac_tag_generation_field_multiplication_count: 536_230,
            raw_label_share_storage_byte_length: 7_872_000,
            raw_scalar_share_storage_byte_length: 9_287_360,
            raw_share_storage_byte_length: 17_159_360,
            dkac_commitment_byte_length: 23_822_720,
            dkac_salt_byte_length: 35_734_080,
            dkac_tag_byte_length: 11_911_360,
            dkac_verification_key_byte_length: 29_070_720,
            active_label_opening_upper_bound_byte_length: 3_673_600,
            input_mask_opening_upper_bound_byte_length: 262_400,
            active_row_opening_byte_length: 4_813_440,
            private_result_release_opening_byte_length: 25_600,
            public_nonempty_mask_opening_byte_length: 640,
            static_public_lower_bound_byte_length: 315_111_468,
            online_public_lower_bound_byte_length: 8_775_680,
            combined_known_public_lower_bound_byte_length: 323_887_148,
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
