const nodeTestTimeoutMs = 60_000;
const nodeKernelHeavyTestTimeoutMs = 15 * 60_000;
const nodeKernelVeryHeavyTestTimeoutMs = 60 * 60_000;
export const nodeHookTimeoutMs = 240_000;

type TestAutomationClass = 'local-and-ci' | 'ci' | 'manual';

export const canonicalTestLaneValues = [
    'node-fast',
    'node-protocol',
    'node-kernel-fast',
    'node-kernel-heavy',
    'browser',
    'rust-kernel-fast',
    'rust-kernel-heavy',
    'rust-accepted-setup',
    'rust-full-profile-evidence',
    'rust-measurements',
    'rust-process-memory-guard',
    'foundation-parser-fuzzing',
    'lattigo-arithmetic-oracle',
] as const;

export type CanonicalTestLane = (typeof canonicalTestLaneValues)[number];

type CanonicalTestLaneDefinition = {
    readonly automation: TestAutomationClass;
    readonly rootScript: string;
};

export const canonicalTestLaneDefinitions = {
    'node-fast': {
        automation: 'local-and-ci',
        rootScript: 'test:node:fast',
    },
    'node-protocol': {
        automation: 'ci',
        rootScript: 'test:node:protocol',
    },
    'node-kernel-fast': {
        automation: 'local-and-ci',
        rootScript: 'test:node:kernel:fast',
    },
    'node-kernel-heavy': {
        automation: 'ci',
        rootScript: 'test:node:kernel:heavy',
    },
    browser: { automation: 'ci', rootScript: 'test:browser' },
    'rust-kernel-fast': {
        automation: 'local-and-ci',
        rootScript: 'test:rust:kernel',
    },
    'rust-kernel-heavy': {
        automation: 'ci',
        rootScript: 'test:rust:kernel:heavy',
    },
    'rust-accepted-setup': {
        automation: 'ci',
        rootScript: 'test:rust:kernel:accepted-setup',
    },
    'rust-full-profile-evidence': {
        automation: 'manual',
        rootScript: 'test:rust:kernel:full-profile-evidence',
    },
    'rust-measurements': {
        automation: 'manual',
        rootScript: 'test:rust:kernel:measurements',
    },
    'rust-process-memory-guard': {
        automation: 'local-and-ci',
        rootScript: 'test:rust:process-memory-guard',
    },
    'foundation-parser-fuzzing': {
        automation: 'manual',
        rootScript: 'test:fuzz:foundation-schema-object',
    },
    'lattigo-arithmetic-oracle': {
        automation: 'manual',
        rootScript: 'test:lattigo-oracle',
    },
} as const satisfies Record<CanonicalTestLane, CanonicalTestLaneDefinition>;

export const aggregateTestScripts = [
    'test',
    'test:node',
    'test:node:kernel',
] as const;

export const testUtilityScripts = ['test:lanes:verify'] as const;

export const nodeTestLaneValues = [
    'fast',
    'protocol',
    'kernel-fast',
    'kernel-heavy',
] as const;

export type NodeTestLane = (typeof nodeTestLaneValues)[number];
type TestLaneGroup = Extract<
    CanonicalTestLane,
    | 'browser'
    | 'node-fast'
    | 'node-kernel-fast'
    | 'node-kernel-heavy'
    | 'node-protocol'
>;

type NodeTestProjectDefinition = {
    readonly commandDescription?: string;
    readonly exclude?: readonly string[];
    readonly fileParallelism?: boolean;
    readonly include: readonly string[];
    readonly projectName: string;
    readonly testTimeout: number;
};

const protocolNodeTestGlobs = [
    'packages/protocol/tests/node/**/*.test.ts',
] as const;

const kernelNodeTestGlobs = [
    'packages/wasm/tests/node/**/*.kernel.test.ts',
    'tests/node/**/*.kernel.test.ts',
] as const;

const heavyKernelNodeTestGlobs = [
    'packages/wasm/tests/node/transcript-core-kernel/bgv-collective-setup/**/*.kernel.test.ts',
] as const;

export const nodeTestLaneDefinitions = {
    fast: {
        commandDescription: 'Run fast Node tests',
        exclude: [...protocolNodeTestGlobs, ...kernelNodeTestGlobs],
        include: [
            'packages/*/tests/node/**/*.test.ts',
            'tests/node/**/*.test.ts',
        ],
        projectName: 'node',
        testTimeout: nodeTestTimeoutMs,
    },
    protocol: {
        commandDescription: 'Run protocol Node tests',
        include: protocolNodeTestGlobs,
        projectName: 'node-protocol',
        testTimeout: nodeKernelHeavyTestTimeoutMs,
    },
    'kernel-fast': {
        commandDescription: 'Run fast kernel Node tests',
        exclude: heavyKernelNodeTestGlobs,
        fileParallelism: false,
        include: kernelNodeTestGlobs,
        projectName: 'node-kernel-fast',
        testTimeout: nodeKernelHeavyTestTimeoutMs,
    },
    'kernel-heavy': {
        commandDescription: 'Run heavy kernel Node tests',
        fileParallelism: false,
        include: heavyKernelNodeTestGlobs,
        projectName: 'node-kernel-heavy',
        testTimeout: nodeKernelVeryHeavyTestTimeoutMs,
    },
} as const satisfies Record<NodeTestLane, NodeTestProjectDefinition>;

export const nodeTestProjectDefinitions = [
    ...nodeTestLaneValues.map((lane) => nodeTestLaneDefinitions[lane]),
] as const;

export const defaultNodeTestLanes = [
    ...nodeTestLaneValues,
] as const satisfies readonly NodeTestLane[];

type BrowserTestLane = 'desktop' | 'mobile';

type BrowserTestLaneDefinition = {
    readonly include: readonly string[];
    readonly projectName: string;
};

export const browserTestLaneDefinitions = {
    desktop: {
        include: ['packages/*/tests/browser/**/*.browser.test.ts'],
        projectName: 'browser-desktop',
    },
    mobile: {
        include: ['packages/*/tests/browser/**/*.browser.test.ts'],
        projectName: 'browser-mobile',
    },
} as const satisfies Record<BrowserTestLane, BrowserTestLaneDefinition>;

const acceptedSetupRustTestModule = 'bgv::setup::tests::accepted_setup';
const heavyRustKernelTestNameMarker = 'heavy_rust_kernel_';

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

export const rustKernelManualTestLanes = {
    'rust-full-profile-evidence': fullProfileEvidenceRustTests,
    'rust-measurements': measurementRustTests,
} as const satisfies Partial<Record<CanonicalTestLane, readonly string[]>>;

export const fuzzTargetDefinitions = {
    'foundation-schema-object': {
        cargoManifestPath: 'fuzz/Cargo.toml',
        lane: 'foundation-parser-fuzzing',
        sourcePath: 'fuzz/fuzz_targets/foundation-schema-object.rs',
    },
} as const;

export const externalOracleDefinitions = {
    'lattigo-arithmetic-oracle': {
        lane: 'lattigo-arithmetic-oracle',
        rootScript: 'test:lattigo-oracle',
        runnerPath: 'tools/lattigo-oracle/run-lattigo-oracle.ts',
    },
} as const;

export const expectedOwnedTestCounts = {
    browser: 14,
    'foundation-parser-fuzzing': 1,
    'lattigo-arithmetic-oracle': 1,
    'node-fast': 35,
    'node-kernel-fast': 14,
    'node-kernel-heavy': 4,
    'node-protocol': 28,
    'rust-accepted-setup': 47,
    'rust-full-profile-evidence': 2,
    'rust-kernel-fast': 546,
    'rust-kernel-heavy': 5,
    'rust-measurements': 5,
    'rust-process-memory-guard': 7,
} as const satisfies Record<CanonicalTestLane, number>;

const normalizeRelativeTestPath = (filePath: string): string =>
    filePath.replace(/\\/gu, '/');

export const testLaneGroupsForRelativePath = (
    filePath: string,
): readonly TestLaneGroup[] => {
    const relativePath = normalizeRelativeTestPath(filePath);
    const laneGroups: TestLaneGroup[] = [];

    if (!relativePath.endsWith('.test.ts')) {
        return laneGroups;
    }

    if (
        relativePath.startsWith('packages/') &&
        relativePath.includes('/tests/browser/') &&
        relativePath.endsWith('.browser.test.ts')
    ) {
        laneGroups.push('browser');
    }

    if (relativePath.startsWith('packages/protocol/tests/node/')) {
        laneGroups.push('node-protocol');
    } else if (
        relativePath.startsWith(
            'packages/wasm/tests/node/transcript-core-kernel/bgv-collective-setup/',
        ) &&
        relativePath.endsWith('.kernel.test.ts')
    ) {
        laneGroups.push('node-kernel-heavy');
    } else if (
        relativePath.startsWith('packages/wasm/tests/node/') &&
        relativePath.endsWith('.kernel.test.ts')
    ) {
        laneGroups.push('node-kernel-fast');
    } else if (
        relativePath.startsWith('tests/node/') &&
        relativePath.endsWith('.kernel.test.ts')
    ) {
        laneGroups.push('node-kernel-fast');
    } else if (
        relativePath.startsWith('tests/node/') ||
        (relativePath.startsWith('packages/') &&
            relativePath.includes('/tests/node/'))
    ) {
        laneGroups.push('node-fast');
    }

    return laneGroups;
};

export const rustTestLanesForInventoryEntry = (input: {
    readonly ignored: boolean;
    readonly packageName: string;
    readonly testName: string;
}): readonly CanonicalTestLane[] => {
    if (input.packageName === 'sealed-lattice-process-memory-guard') {
        return ['rust-process-memory-guard'];
    }
    if (input.packageName !== 'sealed-lattice-kernel') {
        return [];
    }

    const lanes: CanonicalTestLane[] = [];
    if (input.testName.startsWith(`${acceptedSetupRustTestModule}::`)) {
        lanes.push('rust-accepted-setup');
    }
    if (fullProfileEvidenceRustTests.includes(input.testName as never)) {
        lanes.push('rust-full-profile-evidence');
    }
    if (measurementRustTests.includes(input.testName as never)) {
        lanes.push('rust-measurements');
    }
    if (input.testName.includes(heavyRustKernelTestNameMarker)) {
        lanes.push('rust-kernel-heavy');
    }
    if (lanes.length === 0 && !input.ignored) {
        lanes.push('rust-kernel-fast');
    }

    return lanes;
};
