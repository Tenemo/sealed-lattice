//! Production-derived lower bounds used to gate compact family compilation.
//!
//! These diagnostics deliberately do not mint a suite identity, theorem
//! premise, proof, verifier result, or accepted capability.

use crate::foundation::ProofApplicationSlotCeilings;

use super::compact_cfw_external::{CompactCfwExternalPlanError, CompactCfwExternalStorageCatalog};
use super::compact_cfw_geometry::CompactCfwGeometry;
use super::compact_proof_contract::selected_compact_public_key_proof_contract;
use super::external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH;
use super::relation_plan::{
    compile_galois_key_share_relation_with_source_layout,
    compile_relinearization_round_one_relation_with_source_layout,
    compile_relinearization_round_two_relation_with_source_layout,
};
use super::selected_profile::{
    selected_galois_key_share_relation_plan_input, selected_relation_plan_check_context,
    selected_relinearization_relation_plan_inputs,
};
use super::{PROOF_CHALLENGE_EXTENSION_DEGREE, ProofExternalMemoryError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactFamilyQuotientLowerBound {
    application_statement_schema_identifier: u16,
    ring_degree: u64,
    semantic_modular_quotient_ring_vector_count: u64,
    actual_witness_element_count_lower_bound: u64,
    padded_witness_element_count_lower_bound: u64,
    cfw_matrix_dimension_lower_bound: u64,
    cfw_external_peak_stored_byte_length_lower_bound: u64,
    cfw_external_total_written_byte_length_lower_bound: u64,
    cfw_external_total_read_byte_length_lower_bound: u64,
    cfw_external_object_lifecycle_count_lower_bound: u64,
}

fn derive_quotient_only_lower_bound(
    application_statement_schema_identifier: u16,
    ring_degree: u64,
    semantic_modular_quotient_ring_vector_count: u64,
) -> CompactFamilyQuotientLowerBound {
    let actual_witness_element_count_lower_bound = ring_degree
        .checked_mul(semantic_modular_quotient_ring_vector_count)
        .expect("the selected quotient-only witness element count fits u64");
    let padded_witness_element_count_lower_bound = actual_witness_element_count_lower_bound
        .checked_next_power_of_two()
        .expect("the selected quotient-only witness padding fits u64");
    let witness_length = usize::try_from(padded_witness_element_count_lower_bound)
        .expect("the selected quotient-only witness length fits usize");
    let cfw_geometry = CompactCfwGeometry::derive(witness_length)
        .expect("the quotient-only lower-bound CFW geometry derives");
    let extension_element_byte_length = u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
        .expect("the challenge extension degree fits u64")
        .checked_mul(8)
        .expect("the challenge extension element byte length fits u64");
    let padded_witness_element_count_lower_bound_minus_one =
        padded_witness_element_count_lower_bound
            .checked_sub(1)
            .expect("the padded quotient-only witness is non-empty");
    let written_extension_element_count = padded_witness_element_count_lower_bound
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .and_then(|count| count.checked_mul(3))
        .expect("the quotient-only CFW write count fits u64");
    let read_extension_element_count = padded_witness_element_count_lower_bound_minus_one
        .checked_mul(2)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_mul(3))
        .expect("the quotient-only CFW read count fits u64");
    let peak_stored_extension_element_count = padded_witness_element_count_lower_bound
        .checked_mul(7)
        .and_then(|count| count.checked_div(2))
        .expect("the quotient-only CFW peak count fits u64");
    CompactFamilyQuotientLowerBound {
        application_statement_schema_identifier,
        ring_degree,
        semantic_modular_quotient_ring_vector_count,
        actual_witness_element_count_lower_bound,
        padded_witness_element_count_lower_bound,
        cfw_matrix_dimension_lower_bound: u64::try_from(cfw_geometry.r1cs_row_count())
            .expect("the selected quotient-only matrix dimension fits u64"),
        cfw_external_peak_stored_byte_length_lower_bound: peak_stored_extension_element_count
            .checked_mul(extension_element_byte_length)
            .expect("the quotient-only CFW peak byte length fits u64"),
        cfw_external_total_written_byte_length_lower_bound: written_extension_element_count
            .checked_mul(extension_element_byte_length)
            .expect("the quotient-only CFW write byte length fits u64"),
        cfw_external_total_read_byte_length_lower_bound: read_extension_element_count
            .checked_mul(extension_element_byte_length)
            .expect("the quotient-only CFW read byte length fits u64"),
        cfw_external_object_lifecycle_count_lower_bound: u64::from(
            padded_witness_element_count_lower_bound.ilog2() + 1,
        )
        .checked_mul(3)
        .expect("the quotient-only CFW object lifecycle count fits u64"),
    }
}

#[test]
fn selected_evaluator_key_quotients_cross_the_compact_external_storage_bound() {
    let (round_one_input, round_two_input) = selected_relinearization_relation_plan_inputs()
        .expect("the selected relinearization relation inputs derive");
    let round_one_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected round-one relation context derives");
    let round_two_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected round-two relation context derives");
    let round_one = compile_relinearization_round_one_relation_with_source_layout(
        &round_one_input,
        &round_one_context,
    )
    .expect("the selected round-one relation compiles from production inputs");
    let round_two = compile_relinearization_round_two_relation_with_source_layout(
        &round_two_input,
        &round_two_context,
    )
    .expect("the selected round-two relation compiles from production inputs");

    let galois_input = selected_galois_key_share_relation_plan_input()
        .expect("the selected Galois relation input derives");
    let galois_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected Galois relation context derives");
    let galois =
        compile_galois_key_share_relation_with_source_layout(&galois_input, &galois_context)
            .expect("the selected Galois relation compiles from production inputs");

    let lower_bounds = [
        derive_quotient_only_lower_bound(
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
            round_one_input.geometry.ring_degree,
            round_one
                .semantic_modular_quotient_ring_vector_count()
                .expect("the round-one quotient count derives"),
        ),
        derive_quotient_only_lower_bound(
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
            round_two_input.geometry.ring_degree,
            round_two
                .semantic_modular_quotient_ring_vector_count()
                .expect("the round-two quotient count derives"),
        ),
        derive_quotient_only_lower_bound(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            galois_input.geometry.ring_degree,
            galois
                .semantic_modular_quotient_ring_vector_count()
                .expect("the Galois quotient count derives"),
        ),
    ];

    println!(
        "schema,ring-degree,semantic-quotient-vectors,actual-elements-lower-bound,padded-elements-lower-bound,matrix-dimension-lower-bound,external-peak-lower-bound,external-written-lower-bound,external-read-lower-bound,object-lifecycles-lower-bound"
    );
    for lower_bound in lower_bounds {
        println!(
            "{},{},{},{},{},{},{},{},{},{}",
            lower_bound.application_statement_schema_identifier,
            lower_bound.ring_degree,
            lower_bound.semantic_modular_quotient_ring_vector_count,
            lower_bound.actual_witness_element_count_lower_bound,
            lower_bound.padded_witness_element_count_lower_bound,
            lower_bound.cfw_matrix_dimension_lower_bound,
            lower_bound.cfw_external_peak_stored_byte_length_lower_bound,
            lower_bound.cfw_external_total_written_byte_length_lower_bound,
            lower_bound.cfw_external_total_read_byte_length_lower_bound,
            lower_bound.cfw_external_object_lifecycle_count_lower_bound,
        );
    }

    assert_eq!(lower_bounds[0].ring_degree, 32_768);
    assert_eq!(lower_bounds[1].ring_degree, 32_768);
    assert_eq!(lower_bounds[2].ring_degree, 32_768);
    assert_eq!(
        lower_bounds,
        [
            CompactFamilyQuotientLowerBound {
                application_statement_schema_identifier:
                    ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                ring_degree: 32_768,
                semantic_modular_quotient_ring_vector_count: 422,
                actual_witness_element_count_lower_bound: 13_828_096,
                padded_witness_element_count_lower_bound: 16_777_216,
                cfw_matrix_dimension_lower_bound: 33_554_432,
                cfw_external_peak_stored_byte_length_lower_bound: 2_348_810_240,
                cfw_external_total_written_byte_length_lower_bound: 4_026_531_720,
                cfw_external_total_read_byte_length_lower_bound: 8_053_063_200,
                cfw_external_object_lifecycle_count_lower_bound: 75,
            },
            CompactFamilyQuotientLowerBound {
                application_statement_schema_identifier:
                    ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                ring_degree: 32_768,
                semantic_modular_quotient_ring_vector_count: 630,
                actual_witness_element_count_lower_bound: 20_643_840,
                padded_witness_element_count_lower_bound: 33_554_432,
                cfw_matrix_dimension_lower_bound: 67_108_864,
                cfw_external_peak_stored_byte_length_lower_bound: 4_697_620_480,
                cfw_external_total_written_byte_length_lower_bound: 8_053_063_560,
                cfw_external_total_read_byte_length_lower_bound: 16_106_126_880,
                cfw_external_object_lifecycle_count_lower_bound: 78,
            },
            CompactFamilyQuotientLowerBound {
                application_statement_schema_identifier:
                    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                ring_degree: 32_768,
                semantic_modular_quotient_ring_vector_count: 738,
                actual_witness_element_count_lower_bound: 24_182_784,
                padded_witness_element_count_lower_bound: 33_554_432,
                cfw_matrix_dimension_lower_bound: 67_108_864,
                cfw_external_peak_stored_byte_length_lower_bound: 4_697_620_480,
                cfw_external_total_written_byte_length_lower_bound: 8_053_063_560,
                cfw_external_total_read_byte_length_lower_bound: 16_106_126_880,
                cfw_external_object_lifecycle_count_lower_bound: 78,
            },
        ]
    );
    assert!(
        lower_bounds[1].semantic_modular_quotient_ring_vector_count
            > lower_bounds[0].semantic_modular_quotient_ring_vector_count
    );
    assert!(
        lower_bounds[0].cfw_external_peak_stored_byte_length_lower_bound
            > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
    );
    assert!(
        lower_bounds[1].cfw_external_peak_stored_byte_length_lower_bound
            > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
    );
    assert!(
        lower_bounds[2].cfw_external_peak_stored_byte_length_lower_bound
            > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
    );
    for lower_bound in lower_bounds {
        let geometry = CompactCfwGeometry::derive(
            usize::try_from(lower_bound.padded_witness_element_count_lower_bound)
                .expect("the quotient-only padded length fits usize"),
        )
        .expect("the quotient-only CFW geometry derives");
        assert_eq!(
            CompactCfwExternalStorageCatalog::derive(geometry).unwrap_err(),
            CompactCfwExternalPlanError::ExternalMemory(
                ProofExternalMemoryError::ResourceLimitExceeded
            )
        );
    }

    let within_bound_geometry =
        CompactCfwGeometry::derive(1_usize << 22).expect("the reference-size CFW geometry derives");
    let within_bound_storage = CompactCfwExternalStorageCatalog::derive(within_bound_geometry)
        .expect("the reference-size CFW storage catalog derives");
    let within_bound_accounting = derive_quotient_only_lower_bound(0, 1, 1_u64 << 22);
    assert_eq!(
        within_bound_accounting.cfw_external_peak_stored_byte_length_lower_bound,
        within_bound_storage.peak_stored_byte_length()
    );
    assert_eq!(
        within_bound_accounting.cfw_external_total_written_byte_length_lower_bound,
        within_bound_storage.total_written_byte_length()
    );
    assert_eq!(
        within_bound_accounting.cfw_external_total_read_byte_length_lower_bound,
        within_bound_storage.total_read_byte_length()
    );
    assert_eq!(
        within_bound_accounting.cfw_external_object_lifecycle_count_lower_bound,
        within_bound_storage.object_lifecycle_count()
    );

    let over_bound_geometry = CompactCfwGeometry::derive(1_usize << 23)
        .expect("the next witness power-of-two CFW geometry derives");
    assert_eq!(
        CompactCfwExternalStorageCatalog::derive(over_bound_geometry).unwrap_err(),
        CompactCfwExternalPlanError::ExternalMemory(
            ProofExternalMemoryError::ResourceLimitExceeded
        )
    );
    let maximum_current_cfw_ring_vector_count = (1_u64 << 22) / 32_768;
    assert_eq!(maximum_current_cfw_ring_vector_count, 128);
    let quotient_only_packet_count_lower_bounds = lower_bounds.map(|lower_bound| {
        lower_bound
            .semantic_modular_quotient_ring_vector_count
            .div_ceil(maximum_current_cfw_ring_vector_count)
    });
    assert_eq!(quotient_only_packet_count_lower_bounds, [4, 5, 6]);

    let reference_contract = selected_compact_public_key_proof_contract()
        .expect("the selected compact public-key contract derives");
    let reference_relation = reference_contract.verifier_inputs().relation;
    let quotient_vector_count = reference_relation.quotient_vector_count();
    let shifted_ternary_vector_count = reference_relation.shifted_ternary_vector_count();
    let shifted_eta_two_vector_count = 1_u64;
    let current_lookup_mandated_vector_count = quotient_vector_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(shifted_ternary_vector_count))
        .and_then(|count| count.checked_add(shifted_eta_two_vector_count))
        .expect("the reference lookup-mandated witness count fits u64");
    assert_eq!(reference_relation.witness_ring_vector_count(), 86);
    assert_eq!(quotient_vector_count, 29);
    assert_eq!(
        reference_relation.quotient_lookup_table_ring_vector_count(),
        4
    );
    assert_eq!(shifted_ternary_vector_count, 10);
    assert_eq!(current_lookup_mandated_vector_count, 69);
    assert!(current_lookup_mandated_vector_count > 64);
    println!(
        "reference-witness-vectors,total=86,modular-quotients=29,lookup-multiplicities=4,shifted-ternary=10,shifted-eta-two=1,small-set-products=13,lookup-inverses=29,current-lookup-mandated-minimum=69,power-of-two-cliff-maximum=64"
    );
}
