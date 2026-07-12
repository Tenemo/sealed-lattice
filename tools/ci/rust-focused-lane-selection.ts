import type { ActiveLocalRunLog } from './local-run-log.js';
import {
    acceptedSetupTestModulePattern,
    heavyRustKernelTestNamePrefix,
} from './rust-kernel-test-arguments.js';
import {
    collectFocusedRustKernelTestInventory,
    type RustTestInventoryEntry,
} from './rust-test-inventory.js';

export const fullProfileEvidenceRustTests = [
    'bgv::setup::tests::private_vss::private_vss_share_envelope_verifier_accepts_foundation_roster_succinct_private_share_proofs',
    'bgv::target_decryption::tests::replay_release::foundation_profile_replay_target_release_matches_plaintext_oracle',
] as const;

export const measurementRustTests = [
    'bgv::evaluator::top_k::tests::level_budget_probe::lagrange_cleared_l1_worst_case',
    'bgv::evaluator::top_k::tests::level_budget_probe::level_budget_rank_lookup_noise_probe',
    'bgv::evaluator::top_k::tests::level_budget_probe::natural_exit_headroom_by_handoff_level',
    'bgv::evaluator::top_k::tests::level_budget_probe::rank_lookup_terminal_by_k',
    'bgv::setup::limb_group_key_switch_atom::family_backend::bench::round_one_key_prover_cost',
] as const;

type FocusedRustLane =
    | 'rust-accepted-setup'
    | 'rust-full-profile-evidence'
    | 'rust-kernel-fast'
    | 'rust-kernel-heavy'
    | 'rust-measurements';

export const focusedRustLaneScripts = {
    'rust-accepted-setup': 'test:rust:kernel:accepted-setup',
    'rust-full-profile-evidence': 'test:rust:kernel:full-profile-evidence',
    'rust-kernel-fast': 'test:rust:kernel',
    'rust-kernel-heavy': 'test:rust:kernel:heavy',
    'rust-measurements': 'test:rust:kernel:measurements',
} as const satisfies Record<FocusedRustLane, string>;

const fullProfileTestSet = new Set<string>(fullProfileEvidenceRustTests);
const measurementTestSet = new Set<string>(measurementRustTests);

const lanesForTest = (test: RustTestInventoryEntry): FocusedRustLane[] => {
    const lanes: FocusedRustLane[] = [];
    if (test.testName.startsWith(`${acceptedSetupTestModulePattern}::`)) {
        lanes.push('rust-accepted-setup');
    }
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
