use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    tally_circuit::{
        BooleanOperation, CompiledTallyCircuit, OutputRekeyedTallyCircuit, TallyCircuitProfile,
    },
};

use super::garbling_alternative_resource_model::{
    FullGarblingVerificationFieldMpcLowerBound, IndependentLabelGarblingResourceLowerBound,
};

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
            output_rekey_operation_count: 51,
            binary_gate_count: 6_765,
            unary_gate_count: 807,
            evaluated_gate_count: 7_572,
            paid_gate_row_count: 28_674,
            constant_activation_vector_count: 2,
            total_labeled_wire_count: 7_984,
            public_output_bit_count: 11,
            private_result_bit_count: 40,
            garbling_output_bit_length_per_call: 6_410,
            garbling_output_byte_length_per_call: 802,
            garbling_generation_call_count: 286_740,
            garbling_evaluation_call_count: 75_720,
            garbling_share_byte_length_per_participant: 22_996_548,
            all_garbling_share_byte_length: 229_965_480,
            paid_garbled_row_byte_length: 22_996_548,
            constant_activation_vector_byte_length: 1_604,
            final_garbled_circuit_byte_length: 22_998_152,
            label_commitment_count: 159_680,
            label_commitment_byte_length: 10_219_520,
            label_share_record_count: 82_000,
            scalar_share_record_count: 291_350,
            total_share_record_count: 373_350,
            total_share_value_field_element_count: 537_350,
            dkac_verification_key_field_element_count: 910_700,
            dkac_tag_generation_field_multiplication_count: 537_350,
            raw_label_share_storage_byte_length: 7_872_000,
            raw_scalar_share_storage_byte_length: 9_323_200,
            raw_share_storage_byte_length: 17_195_200,
            dkac_commitment_byte_length: 23_894_400,
            dkac_salt_byte_length: 35_841_600,
            dkac_tag_byte_length: 11_947_200,
            dkac_verification_key_byte_length: 29_142_400,
            active_label_opening_upper_bound_byte_length: 3_673_600,
            input_mask_opening_upper_bound_byte_length: 262_400,
            active_row_opening_byte_length: 4_846_080,
            private_result_release_opening_byte_length: 25_600,
            public_nonempty_mask_opening_byte_length: 7_040,
            static_public_lower_bound_byte_length: 316_219_952,
            online_public_lower_bound_byte_length: 8_814_720,
            combined_known_public_lower_bound_byte_length: 325_034_672,
        }
    );
}

#[test]
fn completion_profile_rejects_full_fixed_permutation_verification_through_field_mpc() {
    let circuit = completion_profile_circuit();
    let rejection = FullGarblingVerificationFieldMpcLowerBound::derive(&circuit).unwrap();
    let independently_derived_canonical_stream_bound =
        u64::from(u32::MAX) - u64::try_from(size_of::<u32>()).unwrap();

    assert_eq!(
        rejection,
        FullGarblingVerificationFieldMpcLowerBound {
            garbling_generation_call_count: 286_740,
            minimum_fixed_permutation_count: 286_740,
            nonlinear_bit_multiplication_count_per_permutation: 38_400,
            nonlinear_bit_multiplication_count: 11_010_816_000,
            field_evaluation_byte_length: 40,
            minimum_opening_upload_byte_length_per_participant: 440_432_640_000,
            maximum_canonical_transport_stream_byte_length:
                independently_derived_canonical_stream_bound,
            violates_canonical_transport_stream_bound: true,
        }
    );

    let output_rekeyed = OutputRekeyedTallyCircuit::compile(circuit.profile()).unwrap();
    let independently_reproduced_paid_row_count = circuit
        .operations()
        .iter()
        .map(|operation| match operation {
            BooleanOperation::Constant(_) => 0_u64,
            BooleanOperation::ExclusiveOr { .. } | BooleanOperation::Conjunction { .. } => 4,
            BooleanOperation::Negation { .. } => 2,
        })
        .sum::<u64>()
        + u64::try_from(output_rekeyed.output_rekey_operations().len()).unwrap() * 2;
    let independently_reproduced_generation_call_count =
        independently_reproduced_paid_row_count * u64::from(circuit.profile().participant_count());
    let independently_reproduced_nonlinear_bit_multiplication_count =
        independently_reproduced_generation_call_count * 24 * 1_600;
    let independently_reproduced_opening_upload_byte_length =
        independently_reproduced_nonlinear_bit_multiplication_count * 40;

    assert_eq!(
        rejection.garbling_generation_call_count,
        independently_reproduced_generation_call_count
    );
    assert_eq!(
        rejection.nonlinear_bit_multiplication_count,
        independently_reproduced_nonlinear_bit_multiplication_count
    );
    assert_eq!(
        rejection.minimum_opening_upload_byte_length_per_participant,
        independently_reproduced_opening_upload_byte_length
    );
    assert_eq!(
        rejection.maximum_canonical_transport_stream_byte_length,
        independently_derived_canonical_stream_bound
    );
    assert!(
        independently_reproduced_opening_upload_byte_length
            > independently_derived_canonical_stream_bound
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
                let core_geometry = circuit.geometry();
                let output_rekeyed = OutputRekeyedTallyCircuit::compile(circuit.profile()).unwrap();
                let geometry = output_rekeyed.geometry();
                let independent =
                    IndependentLabelGarblingResourceLowerBound::derive(&circuit).unwrap();

                assert_eq!(
                    independent.binary_gate_count,
                    core_geometry.conjunction_gate_count as u64
                        + core_geometry.exclusive_or_gate_count as u64
                );
                assert_eq!(
                    independent.unary_gate_count,
                    core_geometry.negation_gate_count as u64
                        + geometry.output_rekey_operation_count as u64
                );
                assert_eq!(
                    independent.evaluated_gate_count,
                    geometry.active_gate_count as u64
                );
                assert_eq!(
                    independent.paid_gate_row_count,
                    independent.binary_gate_count * 4 + independent.unary_gate_count * 2
                );
                assert_eq!(
                    independent.total_labeled_wire_count,
                    geometry.total_wire_count as u64
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
