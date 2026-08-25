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
            fresh_semantic_mask_count: 6_652,
            conjunction_gate_count: 5_422,
            and_row_count: 21_688,
            output_mask_count: 41,
            label_body_field_limb_count: 3,
            label_body_random_byte_length: 5_321_600,
            offset_body_random_byte_length: 800,
            label_body_shamir_secret_count: 24_600,
            label_limb_shamir_secret_count: 73_800,
            scalar_shamir_secret_count: 22_959,
            shamir_random_coefficient_field_element_count: 290_277,
            shamir_random_coefficient_byte_length: 9_288_864,
            additive_correlation_free_component_count: 1_951_920,
            additive_correlation_correction_component_count: 216_880,
            additive_correlation_component_count: 2_168_800,
            additive_correlation_free_body_random_byte_length: 156_153_600,
            additive_correlation_free_point_bit_count: 1_951_920,
            additive_correlation_encoded_byte_length: 173_937_760,
            authenticated_record_count: 475_590,
            authenticated_record_value_field_element_count: 967_590,
            authenticated_key_field_element_count: 1_443_180,
            authenticated_key_byte_length: 46_181_760,
            authenticated_salt_byte_length: 45_656_640,
            mask_bitness_multiplication_count: 6_652,
            mask_product_multiplication_count: 5_422,
            row_offset_limb_multiplication_count: 650_640,
            label_share_tag_multiplication_count: 738_000,
            input_mask_share_tag_multiplication_count: 12_300,
            row_bit_share_tag_multiplication_count: 216_880,
            output_mask_share_tag_multiplication_count: 410,
            authenticated_tag_multiplication_count: 967_590,
            first_layer_authenticated_tag_multiplication_count: 750_710,
            second_layer_authenticated_tag_multiplication_count: 216_880,
            first_layer_authenticated_tag_output_count: 258_710,
            second_layer_authenticated_tag_output_count: 216_880,
            first_layer_multiplication_count: 762_784,
            second_layer_multiplication_count: 867_520,
            total_multiplication_count: 1_630_304,
            multiplicative_depth: 2,
            first_layer_public_zero_check_count: 6_652,
            first_layer_derived_row_value_count: 21_688,
            second_layer_row_offset_output_field_element_count: 650_640,
            one_field_share_per_participant_lower_bound_byte_length: 521_697_280,
        }
    );
    assert_eq!(
        graph.multiplication_families(),
        [
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::SemanticMaskBitness,
                multiplicative_layer: 1,
                operation_count: 6_652,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::ConjunctionMaskProduct,
                multiplicative_layer: 1,
                operation_count: 5_422,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::LabelShareTagLimbProduct,
                multiplicative_layer: 1,
                operation_count: 738_000,
                consumes_layer_one_derived_value: false,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::InputMaskShareTagProduct,
                multiplicative_layer: 1,
                operation_count: 12_300,
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
                operation_count: 650_640,
                consumes_layer_one_derived_value: true,
            },
            PreparationMultiplicationFamilyGeometry {
                family: PreparationMultiplicationFamily::RowBitShareTagProduct,
                multiplicative_layer: 2,
                operation_count: 216_880,
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
