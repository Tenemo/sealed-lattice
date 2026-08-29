use crate::{foundation::FOUNDATION_PROFILE, tally_circuit::TallyCircuitProfile};

use super::{
    direct_mpc_candidate_carrier::{
        DirectMpcCarrierCompilerError, compile_direct_mpc_candidate_carrier_ledger,
    },
    direct_mpc_candidate_compiler::compile_direct_mpc_candidate,
};

fn completion_profile(top_count: u16) -> TallyCircuitProfile {
    TallyCircuitProfile::new(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.option_count,
        top_count,
    )
    .unwrap()
}

#[test]
fn completion_carriers_and_static_resource_screen_are_production_derived() {
    let candidate = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    let ledger = compile_direct_mpc_candidate_carrier_ledger(&candidate).unwrap();

    assert_eq!(ledger.maximum_success.submission_count, 10);
    assert_eq!(ledger.maximum_success.interaction_round_count, 31);
    assert_eq!(ledger.maximum_success.public_message_count, 291);
    assert_eq!(ledger.maximum_success.private_message_count, 180);
    assert_eq!(
        ledger.maximum_success.public_raw_field_element_count,
        302_030
    );
    assert_eq!(ledger.one_submission.private_message_count, 99);
    assert_eq!(
        ledger.one_submission.public_raw_field_element_count,
        298_430
    );
    assert_eq!(ledger.all_abstention.public_message_count, 47);
    assert_eq!(ledger.all_abstention.private_message_count, 90);
    assert_eq!(ledger.all_abstention.public_raw_field_element_count, 99_250);
    assert_eq!(ledger.maximum_success.public_carrier_byte_length, 2_343_749);
    assert_eq!(
        ledger.maximum_success.private_carrier_byte_length,
        1_744_830
    );
    assert_eq!(
        ledger.maximum_success.complete_roster_transfer_byte_length,
        4_088_579
    );
    assert_eq!(
        ledger
            .maximum_success
            .maximum_participant_download_byte_length,
        2_518_232
    );
    assert_eq!(
        ledger
            .maximum_success
            .maximum_participant_upload_byte_length,
        412_409
    );
    assert_eq!(
        ledger.maximum_success.maximum_single_carrier_byte_length,
        33_589
    );
    assert_eq!(
        ledger
            .maximum_success
            .checkpoint_boundary_count_per_participant,
        367
    );
    assert_eq!(ledger.checkpoint.checkpoint_state_byte_length, 190_403);
    assert_eq!(
        ledger
            .checkpoint
            .retained_and_staged_stored_value_capacity_byte_length,
        387_786
    );
    assert_eq!(
        ledger.live_set.persistent_storage_with_repair_byte_length,
        3_442_071
    );
    assert_eq!(
        ledger.live_set.candidate_owned_wasm_live_set_byte_length,
        1_470_965
    );
    assert_eq!(
        ledger
            .live_set
            .candidate_owned_javascript_live_set_byte_length,
        2_287_555
    );
    assert_eq!(
        ledger
            .live_set
            .candidate_owned_browser_private_live_set_byte_length,
        3_758_520
    );
    assert_eq!(
        ledger.submitted_ballot_declaration_carrier_byte_length
            - ledger.abstaining_ballot_declaration_carrier_byte_length,
        400 * 64
    );
    assert!(
        ledger.seed_private_carrier_byte_length > ledger.ballot_source_private_carrier_byte_length
    );
    ledger.require_within_static_bounds().unwrap();
}

#[test]
fn every_completion_top_count_changes_only_its_derived_result_and_state_tail() {
    let first = compile_direct_mpc_candidate_carrier_ledger(
        &compile_direct_mpc_candidate(completion_profile(1)).unwrap(),
    )
    .unwrap();
    let tenth = compile_direct_mpc_candidate_carrier_ledger(
        &compile_direct_mpc_candidate(completion_profile(10)).unwrap(),
    )
    .unwrap();

    assert_eq!(
        tenth.maximum_success.public_raw_field_element_count
            - first.maximum_success.public_raw_field_element_count,
        90
    );
    assert_eq!(
        tenth.maximum_success.public_carrier_byte_length
            - first.maximum_success.public_carrier_byte_length,
        270
    );
    assert_eq!(
        tenth.checkpoint.checkpoint_state_byte_length
            - first.checkpoint.checkpoint_state_byte_length,
        27
    );
    assert_eq!(
        tenth.maximum_success.public_message_count,
        first.maximum_success.public_message_count
    );
    assert_eq!(
        tenth.maximum_success.private_carrier_byte_length,
        first.maximum_success.private_carrier_byte_length
    );
}

#[test]
fn fixed_function_census_closes_sampling_and_chunk_loss_bounds() {
    let candidate = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    let candidate_resource = candidate.resource_model().unwrap();
    let ledger = compile_direct_mpc_candidate_carrier_ledger(&candidate).unwrap();
    let fixed = ledger.fixed_function;

    let independently_counted_unique_samples = candidate_resource.random_degree_three_sharing_count
        * candidate_resource.authorized_subset_count
        + candidate_resource.random_degree_six_zero_sharing_count
            * candidate_resource.authorized_subset_count
            * candidate_resource.active_fault_bound
        + candidate_resource.validation_challenge_coefficient_count;
    assert_eq!(
        fixed.unique_field_sample_count,
        independently_counted_unique_samples
    );
    assert_eq!(fixed.unique_field_sample_count, 7_197_200);
    assert_eq!(fixed.aggregate_field_sampling_security_bits, 233);
    assert_eq!(fixed.field_stream_query_byte_length, 302);
    assert_eq!(fixed.kmacxof256_query_count_per_participant, 336);
    assert_eq!(
        fixed.kmacxof256_absorbed_byte_length_per_participant,
        336 * 680
    );
    assert_eq!(
        fixed.kmacxof256_permutation_count_per_participant,
        1_186_416
    );
    assert_eq!(
        fixed.validation_cshakexof256_permutation_count_per_participant,
        755
    );
    assert_eq!(fixed.maximum_uninterrupted_permutation_count, 7_104);
    assert_eq!(fixed.maximum_uninterrupted_field_reduction_count, 30_175);
    assert_eq!(
        fixed.maximum_lost_or_replayed_xof_output_byte_length,
        30_175 * 32
    );
    assert_eq!(
        fixed.prss_basis_precomputation_field_multiplication_count_per_participant,
        756
    );
    assert_eq!(
        fixed.prss_weight_field_multiplication_count_per_participant,
        5_035_800
    );
    assert_eq!(
        fixed.prss_accumulation_field_addition_count_per_participant,
        4_995_700
    );
    assert_eq!(
        fixed.maximum_field_multiplication_count_per_participant,
        5_937_140
    );
    assert_eq!(
        fixed.all_abstention_field_multiplication_count_per_participant,
        5_324_381
    );
    assert_eq!(fixed.seed_commitment_hash_preimage_byte_length, 352);
    assert_eq!(fixed.ballot_share_commitment_hash_preimage_byte_length, 321);
    assert_eq!(
        fixed.maximum_transcript_leaf_hash_preimage_byte_length,
        33_669
    );
    assert_eq!(fixed.maximum_round_root_hash_preimage_byte_length, 717);
    assert_eq!(fixed.transcript_leaf_hash_count_per_participant, 291);
    assert_eq!(fixed.private_carrier_hash_count_per_participant, 72);
    assert_eq!(fixed.round_root_hash_count_per_participant, 31);
    assert_eq!(fixed.computation_target_hash_count_per_participant, 1);
    assert_eq!(fixed.foundation_hash_call_count_per_participant, 2_979);
    assert_eq!(fixed.computation_target_hash_preimage_byte_length, 555);
}

#[test]
fn checkpoint_capacity_matches_the_authenticated_store_overlap_formula() {
    let candidate = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    let ledger = compile_direct_mpc_candidate_carrier_ledger(&candidate).unwrap();
    let checkpoint = ledger.checkpoint;
    let simultaneous_logical_records = checkpoint.checkpoint_chunk_count * 2 + 2;
    let independently_counted_capacity = checkpoint.checkpoint_state_byte_length * 2
        + checkpoint.checkpoint_chunk_count * 54 * 2
        + (checkpoint.canonical_manifest_byte_length + 38 + 54) * 2
        + (checkpoint.journal_plaintext_byte_length + 54) * 2
        + simultaneous_logical_records * 256;
    assert_eq!(
        checkpoint.retained_and_staged_stored_value_capacity_byte_length,
        independently_counted_capacity
    );
    assert_eq!(checkpoint.checkpoint_chunk_count, 1);
    assert_eq!(checkpoint.state_stream_descriptor_byte_length, 168);
    assert_eq!(checkpoint.deterministic_cursor_byte_length, 130);
    assert_eq!(checkpoint.canonical_manifest_byte_length, 1_178);
    assert_eq!(checkpoint.journal_plaintext_byte_length, 1_600);
    assert_eq!(checkpoint.maximum_owned_record_count, 10);
    assert_eq!(checkpoint.seal_call_count_per_publication, 3);
    assert_eq!(
        checkpoint.cumulative_sealed_plaintext_byte_length_per_participant,
        70_911_373
    );
    assert_eq!(checkpoint.cold_restart_traffic_byte_length, 191_727);
}

#[test]
fn fault_paths_never_create_a_retry_or_corrected_continuation() {
    let candidate = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    let ledger = compile_direct_mpc_candidate_carrier_ledger(&candidate).unwrap();

    assert_eq!(
        ledger.withholding.public_message_count,
        ledger.maximum_success.public_message_count - 8
    );
    assert_eq!(
        ledger.withholding.public_raw_field_element_count,
        ledger.maximum_success.public_raw_field_element_count - 10
    );
    assert_eq!(
        ledger.authenticated_burn.public_message_count,
        ledger.maximum_success.public_message_count
    );
    assert_eq!(
        ledger.rollback_retirement.public_message_count,
        ledger.maximum_success.public_message_count
    );
    assert_eq!(
        ledger.authenticated_burn.private_carrier_byte_length,
        ledger.maximum_success.private_carrier_byte_length
    );
    assert_eq!(
        ledger.rollback_retirement.private_carrier_byte_length,
        ledger.maximum_success.private_carrier_byte_length
    );
}

#[test]
fn static_screen_refuses_one_over_resource_and_one_under_security_boundaries() {
    let candidate = compile_direct_mpc_candidate(completion_profile(10)).unwrap();
    let baseline = compile_direct_mpc_candidate_carrier_ledger(&candidate).unwrap();

    let mut oversized = baseline.clone();
    oversized.maximum_success.public_carrier_byte_length = 2_147_483_649;
    assert_eq!(
        oversized.require_within_static_bounds(),
        Err(DirectMpcCarrierCompilerError::ResourceBoundExceeded {
            resource: "public corpus",
            actual: 2_147_483_649,
            bound: 2_147_483_648,
        })
    );

    let mut undersized_security = baseline;
    undersized_security
        .fixed_function
        .aggregate_field_sampling_security_bits = 127;
    assert_eq!(
        undersized_security.require_within_static_bounds(),
        Err(DirectMpcCarrierCompilerError::SecurityTargetNotMet {
            actual_bits: 127,
            required_bits: 128,
        })
    );
}
