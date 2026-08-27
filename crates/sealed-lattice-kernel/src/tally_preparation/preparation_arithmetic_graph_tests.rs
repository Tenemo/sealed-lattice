use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::preparation_arithmetic_graph::{
    PreparationArithmeticGraph, PreparationMultiplicationFamily,
    PreparationMultiplicationFamilyGeometry,
};

#[test]
fn completion_profile_reproduces_the_ideal_preparation_arithmetic_graph() {
    let graph = PreparationArithmeticGraph::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(
        graph,
        PreparationArithmeticGraph {
            participant_count: 10,
            fresh_semantic_mask_count: 3_372,
            conjunction_gate_count: 2_962,
            and_row_count: 11_848,
            output_mask_count: 41,
            label_body_field_limb_count: 3,
            label_body_random_byte_length: 2_697_600,
            offset_body_random_byte_length: 800,
            label_body_shamir_secret_count: 8_200,
            label_limb_shamir_secret_count: 24_600,
            scalar_shamir_secret_count: 12_299,
            shamir_random_coefficient_field_element_count: 110_697,
            shamir_random_coefficient_byte_length: 3_542_304,
            additive_correlation_free_component_count: 1_066_320,
            additive_correlation_correction_component_count: 118_480,
            additive_correlation_component_count: 1_184_800,
            additive_correlation_free_body_random_byte_length: 85_305_600,
            additive_correlation_free_point_bit_count: 1_066_320,
            additive_correlation_encoded_byte_length: 95_020_960,
            authenticated_record_count: 204_990,
            authenticated_record_value_field_element_count: 368_990,
            authenticated_key_field_element_count: 573_980,
            authenticated_key_byte_length: 18_367_360,
            authenticated_salt_byte_length: 19_679_040,
            mask_bitness_multiplication_count: 3_372,
            mask_product_multiplication_count: 2_962,
            row_offset_limb_multiplication_count: 355_440,
            label_share_tag_multiplication_count: 246_000,
            input_mask_share_tag_multiplication_count: 4_100,
            row_bit_share_tag_multiplication_count: 118_480,
            output_mask_share_tag_multiplication_count: 410,
            authenticated_tag_multiplication_count: 368_990,
            first_layer_authenticated_tag_multiplication_count: 250_510,
            second_layer_authenticated_tag_multiplication_count: 118_480,
            first_layer_authenticated_tag_output_count: 86_510,
            second_layer_authenticated_tag_output_count: 118_480,
            first_layer_multiplication_count: 256_844,
            second_layer_multiplication_count: 473_920,
            total_multiplication_count: 730_764,
            multiplicative_depth: 2,
            first_layer_public_zero_check_count: 3_372,
            first_layer_derived_row_value_count: 11_848,
            second_layer_row_offset_output_field_element_count: 355_440,
            one_field_share_per_participant_lower_bound_byte_length: 233_844_480,
        }
    );
    assert_eq!(
        graph.multiplication_families(),
        [
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::SemanticMaskBitness,
                multiplicative_layer: 1,
                operation_count: 3_372,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::ConjunctionMaskProduct,
                multiplicative_layer: 1,
                operation_count: 2_962,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::LabelShareTagLimbProduct,
                multiplicative_layer: 1,
                operation_count: 246_000,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::InputMaskShareTagProduct,
                multiplicative_layer: 1,
                operation_count: 4_100,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::OutputMaskShareTagProduct,
                multiplicative_layer: 1,
                operation_count: 410,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::RowOffsetLimbProduct,
                multiplicative_layer: 2,
                operation_count: 355_440,
                consumes_layer_one_derived_value: true,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::RowBitShareTagProduct,
                multiplicative_layer: 2,
                operation_count: 118_480,
                consumes_layer_one_derived_value: true,
            },
        ]
    );
}

#[test]
fn every_admitted_circuit_shape_rederives_the_operation_families() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let graph = PreparationArithmeticGraph::derive(&circuit).unwrap();
                let independently_counted_conjunctions = circuit
                    .operations()
                    .iter()
                    .filter(|operation| {
                        matches!(
                            operation,
                            crate::tally_circuit::BooleanOperation::Conjunction { .. }
                        )
                    })
                    .count() as u64;
                let family_total = graph
                    .multiplication_families()
                    .iter()
                    .map(|family| family.operation_count)
                    .sum::<u64>();

                assert_eq!(
                    graph.conjunction_gate_count,
                    independently_counted_conjunctions
                );
                assert_eq!(graph.and_row_count, independently_counted_conjunctions * 4);
                assert_eq!(
                    graph.row_offset_limb_multiplication_count,
                    graph.and_row_count * u64::from(participant_count) * 3
                );
                assert_eq!(
                    graph.authenticated_tag_multiplication_count,
                    graph.authenticated_record_value_field_element_count
                );
                assert_eq!(family_total, graph.total_multiplication_count);
                assert_eq!(
                    graph.first_layer_authenticated_tag_multiplication_count
                        + graph.second_layer_authenticated_tag_multiplication_count,
                    graph.authenticated_tag_multiplication_count
                );
                assert_eq!(
                    graph.first_layer_authenticated_tag_output_count
                        + graph.second_layer_authenticated_tag_output_count,
                    graph.authenticated_record_count
                );
                assert_eq!(
                    graph.first_layer_multiplication_count
                        + graph.second_layer_multiplication_count,
                    graph.total_multiplication_count
                );
                assert_eq!(
                    graph.one_field_share_per_participant_lower_bound_byte_length,
                    graph.total_multiplication_count * u64::from(participant_count) * 32
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
