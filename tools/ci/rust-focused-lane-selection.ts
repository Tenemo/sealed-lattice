import type { ActiveLocalRunLog } from './local-run-log.js';
import { heavyRustKernelTestNamePrefix } from './rust-kernel-test-arguments.js';
import {
    collectFocusedRustKernelTestInventory,
    type RustTestInventoryEntry,
} from './rust-test-inventory.js';

export const fullProfileEvidenceRustTests = [
    'bgv::target_decryption::tests::evaluator_replay::prototype_profile_evaluator_replay_matches_plaintext_oracle_and_binds_target_roots',
] as const;

export const measurementRustTests = [
    'bgv::evaluator::noise_recurrence::tests::selected_evaluator_depth_drop_allocation_search_reports_exact_candidates',
    'bgv::evaluator::noise_recurrence::tests::selected_evaluator_joint_topology_parallel_prefix_reports_guarded_peak',
    'bgv::evaluator::noise_recurrence::tests::selected_evaluator_joint_topology_search_reports_exact_pareto',
    'bgv::evaluator::noise_recurrence::tests::prospective_28_prime_p5_b7_exhaustive_search_reports_exact_finalists',
    'bgv::evaluator::noise_recurrence::tests::target_heavy_block_balanced_six_special_seven_data_block_search_reports_exact_finalists',
    'bgv::evaluator::noise_recurrence::tests::six_special_six_data_block_early_preparation_drop_candidate_reports_exact_bounds',
    'bgv::evaluator::noise_recurrence::tests::six_special_six_data_block_pairwise_ballot_candidate_reports_exact_bounds',
    'bgv::evaluator::noise_recurrence::tests::six_special_seven_data_block_minimum_three_pre_comparison_drop_search_reports_exact_finalists',
    'bgv::evaluator::noise_recurrence::tests::six_special_seven_data_block_prime_order_beam_search_reports_exact_candidates',
    'bgv::evaluator::top_k::tests::level_budget_probe::production_rank_lookup_level_budget_measurement',
] as const;

type FocusedRustLane =
    | 'rust-full-profile-evidence'
    | 'rust-kernel-fast'
    | 'rust-kernel-heavy'
    | 'rust-measurements';

export const focusedRustLaneScripts = {
    'rust-full-profile-evidence': 'test:rust:kernel:full-profile-evidence',
    'rust-kernel-fast': 'test:rust:kernel',
    'rust-kernel-heavy': 'test:rust:kernel:heavy',
    'rust-measurements': 'test:rust:kernel:measurements',
} as const satisfies Record<FocusedRustLane, string>;

const fullProfileTestSet = new Set<string>(fullProfileEvidenceRustTests);
const measurementTestSet = new Set<string>(measurementRustTests);

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
    if (!test.ignored && lanes.length === 0) {
        lanes.push('rust-kernel-fast');
    }

    return lanes;
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
                `${requestedScript} filter ${input.testFilter} selects ${test.testName}, which belongs to multiple guarded groups: ${lanes.map((lane) => focusedRustLaneScripts[lane]).join(', ')}.`,
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
    readonly environment?: NodeJS.ProcessEnv;
    readonly lane: FocusedRustLane;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
}): Promise<void> => {
    validateFocusedRustLaneSelection({
        lane: input.lane,
        testFilter: input.testFilter,
        tests: await collectFocusedRustKernelTestInventory({
            environment: input.environment,
            runLog: input.runLog,
            testFilter: input.testFilter,
        }),
    });
};
