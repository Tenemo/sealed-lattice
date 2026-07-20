import type { ActiveLocalRunLog } from './local-run-log.js';
import { heavyRustKernelTestNamePrefix } from './rust-kernel-test-arguments.js';
import {
    collectFocusedRustKernelTestInventory,
    type RustTestInventoryEntry,
} from './rust-test-inventory.js';

export const fullProfileEvidenceRustTests = [
    'foundation::selected_suite::tests::candidate_suite_gate_derives_one_complete_canonical_record',
] as const;

export const measurementRustTests = [
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::selected_candidate_packed_deep_fri_resource_inventory_derives_every_variant',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::runtime_limits_match_resource_ceilings_for_every_selected_variant',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::exact_variant_rows_reconcile_transport_frontiers_memory_and_copies',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::complete_action_accounting_derives_all_physical_proof_slots',
    'bgv::proof_suite::selected_accounting::resource_accounting::tests::report_one_mixed_galois_batch_against_two_level_shards',
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
    if (!test.ignored) {
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
