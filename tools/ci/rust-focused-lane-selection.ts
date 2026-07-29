import type { ActiveLocalRunLog } from './local-run-log.js';
import { heavyRustKernelTestNamePrefix } from './rust-kernel-test-arguments.js';
import {
    collectRustKernelTestInventory,
    type RustTestInventoryEntry,
} from './rust-test-inventory.js';

export const fullProfileEvidenceRustTests = [
    'bgv::evaluator::program::executor::semantic_tests::encrypted_evaluator_matches_direct_stable_top_k_across_covering_matrix',
    'bgv::evaluator::program::executor::semantic_tests::production_evaluator_execution_releases_four_threshold_shares',
    'bgv::setup::collective_setup_security_evidence::print_collective_setup_security_production_authority',
    'foundation::selected_suite::tests::candidate_suite_gate_derives_one_complete_canonical_record',
] as const;

export const measurementRustTests = [
    'bgv::proof_suite::resource_accounting_evidence::tests::selected_candidate_static_resource_accounting_emits_run_attachment',
] as const;

export const phaseLivenessEvidenceRustTests = [
    'bgv::proof_suite::resource_accounting_evidence::tests::selected_candidate_static_resource_accounting_closes_every_missing_carrier',
] as const;

type FocusedRustLane =
    | 'rust-full-profile-evidence'
    | 'rust-kernel-fast'
    | 'rust-kernel-heavy'
    | 'rust-measurements'
    | 'rust-phase-liveness-evidence';

export const focusedRustLaneScripts = {
    'rust-full-profile-evidence': 'test:rust:kernel:full-profile-evidence',
    'rust-kernel-fast': 'test:rust:kernel',
    'rust-kernel-heavy': 'test:rust:kernel:heavy',
    'rust-measurements': 'test:rust:kernel:measurements',
    'rust-phase-liveness-evidence': 'test:rust:kernel:phase-liveness-evidence',
} as const satisfies Record<FocusedRustLane, string>;

const fullProfileTestSet = new Set<string>(fullProfileEvidenceRustTests);
const measurementTestSet = new Set<string>(measurementRustTests);
const phaseLivenessEvidenceTestSet = new Set<string>(
    phaseLivenessEvidenceRustTests,
);
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
    readonly environment?: NodeJS.ProcessEnv;
    readonly lane: FocusedRustLane;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
}): Promise<void> => {
    const completeTestInventory = await collectRustKernelTestInventory({
        environment: input.environment,
        runLog: input.runLog,
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
    readonly environment?: NodeJS.ProcessEnv;
    readonly runLog?: ActiveLocalRunLog;
}): Promise<void> => {
    validateCompleteRustLaneOwnership(
        await collectRustKernelTestInventory(input),
    );
};
