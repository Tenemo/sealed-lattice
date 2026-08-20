import type { ActiveLocalRunLog } from './local-run-log.js';
import { vssFusedRadix51ProjectionOwnerCaseIdentifiers } from './primitive-measurement-evidence.js';
import type { CommandInvocation } from './run-command.js';
import { heavyRustKernelTestNamePrefix } from './rust-kernel-test-arguments.js';
import {
    collectRustKernelTestInventory,
    type RustTestInventoryEntry,
} from './rust-test-inventory.js';

export const fullProfileEvidenceRustTests = [
    'bgv::evaluator::program::executor::semantic_tests::encrypted_evaluator_matches_direct_stable_top_k_across_covering_matrix',
    'bgv::evaluator::program::executor::semantic_tests::production_evaluator_execution_releases_four_threshold_shares',
    'bgv::proof_suite::prover::relation_columns::requested_pre_challenge_source_column_tests::selected_pre_challenge_source_column_catalog_matches_exact_family_geometry',
    'bgv::proof_suite::row_code_whir::construction_plan::tests::every_selected_variant_has_complete_descriptor_derived_geometry',
    'bgv::proof_suite::row_code_whir::same_secret_source_manifest::tests::selected_family_manifests_bind_each_candidate_specific_material_catalog',
    'bgv::proof_suite::selected_profile::tests::selected_non_native_identity_counts_are_independently_minimal',
    'bgv::proof_suite::selected_profile::tests::selected_profile_has_the_complete_relation_and_root_inventory',
    'bgv::setup::collective_setup_security_evidence::collective_setup_security_production_authority_exports_for_refresh',
    'bgv::setup::collective_setup_security_evidence::collective_setup_security_production_authority_closes_complete_evidence',
    'foundation::selected_suite::tests::candidate_suite_gate_derives_one_complete_canonical_record',
    'foundation::suite_artifact_preflight::tests::candidate_suite_artifacts_pass_semantic_preflight_and_refuse_mutations',
] as const;

const primitiveMeasurementRustTestCases = [
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::selected_bounded_lane_dft_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::selected_salted_phase_leaf_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::selected_private_leaf_salt_derivation_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::selected_five_level_digest_carry_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::selected_vss_source_replay_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::selected_authenticated_scratch_record_codec_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::selected_vss_checkpoint_opening_lane_dfts_emit_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::selected_vss_production_weighted_source_replay_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::vss_relation_replay_candidate_retained_group_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::vss_relation_replay_candidate_row_lane_stripe_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::vss_fused_bound_range_candidate_retained_group_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::vss_fused_bound_range_candidate_row_lane_stripe_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::ring_native_proof_field_ntt_round_trip_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::compact_logarithmic_derivative_inverse_chunk_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::compact_lookup_full_stripe_transform_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::compact_lookup_salted_leaf_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::compact_lookup_incremental_stripe_root_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::wide_key_switch_fixed_width_crt_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::compact_quintic_public_main_code_root_pass_emits_measurement',
    'bgv::proof_suite::row_code_whir::primitive_measurements::tests::compact_quintic_post_vss_main_code_root_pass_emits_measurement',
].map((testName, testIndex) =>
    Object.freeze({ caseIdentifier: testIndex + 1, testName }),
);

const primitiveMeasurementRustTests = Object.freeze(
    primitiveMeasurementRustTestCases.map(({ testName }) => testName),
);

export const vssFusedRadix51ProjectionOwnerRustFilter =
    'vss_fused_bound_range_projection_owners';
const vssFusedRadix51ProjectionOwnerCaseIdentifierSet = new Set<number>(
    vssFusedRadix51ProjectionOwnerCaseIdentifiers,
);

export const resolvePrimitiveMeasurementRustTestCases = (
    focusedFilter: string,
): readonly (typeof primitiveMeasurementRustTestCases)[number][] =>
    focusedFilter === vssFusedRadix51ProjectionOwnerRustFilter
        ? primitiveMeasurementRustTestCases.filter(({ caseIdentifier }) =>
              vssFusedRadix51ProjectionOwnerCaseIdentifierSet.has(
                  caseIdentifier,
              ),
          )
        : primitiveMeasurementRustTestCases.filter(({ testName }) =>
              testName.includes(focusedFilter),
          );

export const measurementRustTests = [
    'bgv::proof_suite::resource_accounting_evidence::tests::selected_candidate_static_resource_accounting_emits_run_attachment',
    ...primitiveMeasurementRustTests,
] as const;

export const phaseLivenessEvidenceRustTests = [
    'bgv::proof_suite::collective_public_key_runtime::tests::selected_collective_public_key_accounting_separates_live_memory_storage_and_traffic',
    'bgv::proof_suite::phase_liveness_accounting::tests::construction_driven_phase_liveness_closes_every_selected_variant',
    'bgv::proof_suite::resource_accounting_evidence::tests::selected_candidate_static_resource_accounting_closes_every_missing_carrier',
    'bgv::proof_suite::resource_accounting_evidence::tests::static_resource_accounting_rejects_mutated_proof_and_frontier_totals',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::active_evaluator_proof_accounting_reconciles_every_wire_section',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::candidate_specific_evaluator_rows_account_for_the_complete_key_catalog',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::checkpoint_and_external_memory_geometry_closes_for_every_variant',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::complete_action_accounting_reconciles_all_exact_roster_slots',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::coordinate_derived_compact_frontiers_cover_every_opening_section',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::first_relinearization_round_schedule_has_bounded_candidate_runtime_geometry',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::runtime_limits_match_the_common_authenticated_stream_bound',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::selected_row_code_whir_accounting_records_every_soft_variance_and_absolute_headroom',
] as const;

export const proofEvidenceRustTests = [
    'bgv::proof_suite::row_code_whir::exact_same_secret::tests::exact_same_secret_checkpoint_phases_are_self_owned',
    'bgv::proof_suite::row_code_whir::exact_same_secret::runtime_evidence_tests::exact_vss_prerequisite_proof_round_trip',
    'bgv::proof_suite::row_code_whir::exact_same_secret::runtime_evidence_tests::exact_aggregate_wide_same_secret_proof_round_trip',
] as const;

export const theoremEvidenceRustTests = [
    'bgv::proof_suite::row_code_whir::aggregate_wide_hiding::tests::aggregate_wide_masking_certificate_refuses_every_load_bearing_mutation',
    'bgv::proof_suite::row_code_whir::aggregate_wide_hiding::tests::selected_aggregate_wide_masking_certificate_closes_every_generic_obligation',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::production_construction_views_bind_every_physical_masking_map',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::public_only_construction_has_physical_coverage_without_dummy_mask_sources',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::ballot_construction_views_bind_the_compact_physical_masking_map',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::production_aggregate_wide_views_bind_every_affine_and_nonlinear_catalog',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::production_row_pad_hybrid_refuses_256_bit_secret_prefixes',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::production_private_leaf_salt_prf_binds_every_clean_and_replayed_derivation',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::public_key_share_schema_0x1212_derives_from_its_production_geometry',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::all_exact_ten_production_identities_have_construction_view_accounting',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::width_64_same_secret_through_rkg_round_one_aggregate_have_complete_geometry_certificates',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::width_64_relinearization_round_two_and_galois_share_have_complete_geometry_certificates',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::evaluator_width_64_top_count_one_has_a_complete_geometry_certificate',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::evaluator_width_64_top_counts_two_through_seven_have_complete_geometry_certificates',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::evaluator_width_64_top_counts_eight_through_selected_option_count_have_complete_geometry_certificates',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::every_width_8_construction_identity_has_a_complete_geometry_certificate',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::vss_share_linkage_has_a_complete_geometry_certificate',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::aggregate_threshold_share_has_a_complete_deterministic_geometry_certificate',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::relinearization_round_one_uses_the_maximum_shared_bound_agreement',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::a_256_bit_transition_chain_refuses_a_uniform_512_bit_oracle_denominator',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::deployed_streaming_leaf_chain_uses_uniform_512_bit_oracle_outputs',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::transcript_sampler_catalogs_every_fixed_512_bit_oracle_answer',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::exact_transported_proof_catalog_binds_every_production_section',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::every_exact_ten_production_geometry_has_a_plan_bound_transport_correspondence',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::persistent_committed_material_masks_cover_each_producer_and_joint_consumer_view',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::cms19_whole_state_and_database_support_are_exact_and_mutation_sensitive',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::ballot_width_eight_has_complete_semantic_state_and_database_support',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::one_transition_collision_propagates_through_the_shared_suffix_and_final_digest',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::selected_nonlinear_commitment_binding_covers_every_root_and_shared_query',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::selected_nonlinear_commitment_privacy_counts_every_deployed_hash_call',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::selected_same_secret_affine_masking_composition_is_exact_and_hostile_mutations_refuse',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::selected_same_secret_affine_image_plan_accounts_for_conditioned_production_shapes',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::selected_same_secret_simulation_plan_accounts_for_shared_queries_and_nonlinear_views',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::generated_selected_whir_failure_partition_is_exact_and_mutation_sensitive',
    'bgv::proof_suite::row_code_whir::construction_plan::theorem_certificate::independent_unique_decoder_and_explicit_constraint_filter_cover_hostile_words',
] as const;

type FocusedRustLane =
    | 'rust-full-profile-evidence'
    | 'rust-kernel-fast'
    | 'rust-kernel-heavy'
    | 'rust-measurements'
    | 'rust-phase-liveness-evidence'
    | 'rust-proof-evidence'
    | 'rust-theorem-evidence';

export const focusedRustLaneScripts = {
    'rust-full-profile-evidence': 'test:rust:kernel:full-profile-evidence',
    'rust-kernel-fast': 'test:rust:kernel',
    'rust-kernel-heavy': 'test:rust:kernel:heavy',
    'rust-measurements': 'test:rust:kernel:measurements',
    'rust-phase-liveness-evidence': 'test:rust:kernel:phase-liveness-evidence',
    'rust-proof-evidence': 'test:rust:kernel:proof-evidence',
    'rust-theorem-evidence': 'test:rust:kernel:theorem-evidence',
} as const satisfies Record<FocusedRustLane, string>;

const fullProfileTestSet = new Set<string>(fullProfileEvidenceRustTests);
const measurementTestSet = new Set<string>(measurementRustTests);
const phaseLivenessEvidenceTestSet = new Set<string>(
    phaseLivenessEvidenceRustTests,
);
const proofEvidenceTestSet = new Set<string>(proofEvidenceRustTests);
const theoremEvidenceTestSet = new Set<string>(theoremEvidenceRustTests);
const lanesForTest = (test: RustTestInventoryEntry): FocusedRustLane[] => {
    const lanes: FocusedRustLane[] = [];
    if (test.testName.includes(heavyRustKernelTestNamePrefix)) {
        lanes.push('rust-kernel-heavy');
    }
    if (fullProfileTestSet.has(test.testName)) {
        lanes.push('rust-full-profile-evidence');
    }
    if (measurementTestSet.has(test.testName)) {
        lanes.push('rust-measurements');
    }
    if (phaseLivenessEvidenceTestSet.has(test.testName)) {
        lanes.push('rust-phase-liveness-evidence');
    }
    if (proofEvidenceTestSet.has(test.testName)) {
        lanes.push('rust-proof-evidence');
    }
    if (theoremEvidenceTestSet.has(test.testName)) {
        lanes.push('rust-theorem-evidence');
    }
    if (!test.ignored) {
        lanes.push('rust-kernel-fast');
    }

    return lanes;
};

export const validateCompleteRustLaneOwnership = (
    tests: readonly RustTestInventoryEntry[],
): void => {
    if (tests.length === 0) {
        throw new Error('The complete Rust kernel test inventory is empty.');
    }

    for (const test of tests) {
        const lanes = lanesForTest(test);
        if (lanes.length === 1) {
            continue;
        }
        if (lanes.length === 0) {
            throw new Error(
                `Ignored Rust test ${test.testName} belongs to no guarded Rust lane.`,
            );
        }
        throw new Error(
            `Rust test ${test.testName} belongs to multiple Rust lanes: ${lanes.map((lane) => focusedRustLaneScripts[lane]).join(', ')}.`,
        );
    }
};

export const validateFocusedRustLaneSelection = (input: {
    readonly lane: FocusedRustLane;
    readonly testFilter: string;
    readonly tests: readonly RustTestInventoryEntry[];
}): void => {
    const requestedScript = focusedRustLaneScripts[input.lane];
    if (input.tests.length === 0) {
        throw new Error(
            `${requestedScript} filter ${input.testFilter} selects zero tests.`,
        );
    }

    for (const test of input.tests) {
        const lanes = lanesForTest(test);
        if (lanes.length === 1 && lanes[0] === input.lane) {
            continue;
        }
        if (lanes.length > 1) {
            throw new Error(
                `${requestedScript} filter ${input.testFilter} selects ${test.testName}, which belongs to multiple Rust lanes: ${lanes.map((lane) => focusedRustLaneScripts[lane]).join(', ')}.`,
            );
        }
        const correctScript =
            lanes.length === 0
                ? 'a dedicated guarded command'
                : focusedRustLaneScripts[lanes[0]];
        throw new Error(
            `${requestedScript} filter ${input.testFilter} selects ${test.testName}, which belongs to ${correctScript}.`,
        );
    }
};

export const verifyFocusedRustLaneSelection = async (input: {
    readonly cargoFeatures?: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly inventoryCommandTransform?: (
        command: CommandInvocation,
    ) => CommandInvocation;
    readonly lane: FocusedRustLane;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
    readonly useReleaseProfile?: boolean;
}): Promise<void> => {
    const completeTestInventory = await collectRustKernelTestInventory({
        ...(input.cargoFeatures === undefined
            ? {}
            : { cargoFeatures: input.cargoFeatures }),
        environment: input.environment,
        ...(input.inventoryCommandTransform === undefined
            ? {}
            : {
                  inventoryCommandTransform: input.inventoryCommandTransform,
              }),
        runLog: input.runLog,
        useReleaseProfile: input.useReleaseProfile,
    });
    validateCompleteRustLaneOwnership(completeTestInventory);
    validateFocusedRustLaneSelection({
        lane: input.lane,
        testFilter: input.testFilter,
        tests: completeTestInventory.filter((test) =>
            test.testName.includes(input.testFilter),
        ),
    });
};

export const verifyCompleteRustLaneOwnership = async (input: {
    readonly cargoFeatures?: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly inventoryCommandTransform?: (
        command: CommandInvocation,
    ) => CommandInvocation;
    readonly runLog?: ActiveLocalRunLog;
    readonly useReleaseProfile?: boolean;
}): Promise<void> => {
    validateCompleteRustLaneOwnership(
        await collectRustKernelTestInventory(input),
    );
};
