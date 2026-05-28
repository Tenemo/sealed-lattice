export const nodeTestTimeoutMs = 60_000;
export const nodeKernelHeavyTestTimeoutMs = 15 * 60_000;
export const proofBenchmarkTestTimeoutMs = 60 * 60_000;
export const nodeHookTimeoutMs = 240_000;

export const nodeTestLaneValues = [
    'fast',
    'relation-heavy',
    'proof-input-heavy',
    'kernel-remaining',
    'kernel-aggregate',
] as const;

export type NodeTestLane = (typeof nodeTestLaneValues)[number];

type NodeTestProjectDefinition = {
    readonly commandDescription?: string;
    readonly exclude?: readonly string[];
    readonly fileParallelism?: boolean;
    readonly include: readonly string[];
    readonly projectName: string;
    readonly testTimeout: number;
};

const protocolProofInputNodeTestGlobs = [
    'packages/protocol/tests/node/**/*.protocol-proof-input.test.ts',
] as const;

const protocolRelationNodeTestGlobs = [
    'packages/protocol/tests/node/**/*.protocol-relation.test.ts',
] as const;

const protocolHeavyNodeTestGlobs = [
    ...protocolProofInputNodeTestGlobs,
    ...protocolRelationNodeTestGlobs,
] as const;

const kernelAggregateNodeTestGlobs = [
    'packages/wasm/tests/node/**/*.kernel-aggregate.test.ts',
] as const;

const kernelRemainingNodeTestGlobs = [
    'packages/wasm/tests/node/**/*.kernel.test.ts',
    'tests/node/**/*.kernel.test.ts',
] as const;

const kernelHeavyNodeTestGlobs = [
    ...kernelAggregateNodeTestGlobs,
    ...kernelRemainingNodeTestGlobs,
] as const;

export const nodeTestLaneDefinitions = {
    fast: {
        commandDescription: 'Run fast Node tests',
        exclude: [...protocolHeavyNodeTestGlobs, ...kernelHeavyNodeTestGlobs],
        include: [
            'packages/*/tests/node/**/*.test.ts',
            'tests/node/**/*.test.ts',
        ],
        projectName: 'node',
        testTimeout: nodeTestTimeoutMs,
    },
    'relation-heavy': {
        commandDescription: 'Run relation-heavy Node tests',
        include: protocolRelationNodeTestGlobs,
        projectName: 'node-relation-heavy',
        testTimeout: nodeKernelHeavyTestTimeoutMs,
    },
    'proof-input-heavy': {
        commandDescription: 'Run proof-input-heavy Node tests',
        include: protocolProofInputNodeTestGlobs,
        projectName: 'node-proof-input-heavy',
        testTimeout: nodeKernelHeavyTestTimeoutMs,
    },
    'kernel-remaining': {
        commandDescription: 'Run remaining heavy Node kernel tests',
        include: kernelRemainingNodeTestGlobs,
        projectName: 'node-kernel-remaining',
        testTimeout: nodeKernelHeavyTestTimeoutMs,
    },
    'kernel-aggregate': {
        commandDescription: 'Run aggregate heavy Node kernel tests',
        include: kernelAggregateNodeTestGlobs,
        projectName: 'node-kernel-aggregate',
        testTimeout: nodeKernelHeavyTestTimeoutMs,
    },
} as const satisfies Record<NodeTestLane, NodeTestProjectDefinition>;

export const nodeAggregateProjectDefinitions = {
    protocol: {
        include: protocolHeavyNodeTestGlobs,
        projectName: 'node-protocol',
        testTimeout: nodeKernelHeavyTestTimeoutMs,
    },
    kernel: {
        include: kernelHeavyNodeTestGlobs,
        projectName: 'node-kernel',
        testTimeout: nodeKernelHeavyTestTimeoutMs,
    },
} as const satisfies Record<string, NodeTestProjectDefinition>;

export const nodeTestProjectDefinitions = [
    nodeTestLaneDefinitions.fast,
    nodeAggregateProjectDefinitions.protocol,
    nodeTestLaneDefinitions['proof-input-heavy'],
    nodeTestLaneDefinitions['relation-heavy'],
    nodeAggregateProjectDefinitions.kernel,
    nodeTestLaneDefinitions['kernel-aggregate'],
    nodeTestLaneDefinitions['kernel-remaining'],
] as const;

export const defaultNodeTestLanes = [
    'fast',
    'relation-heavy',
    'proof-input-heavy',
    'kernel-remaining',
    'kernel-aggregate',
] as const satisfies readonly NodeTestLane[];

export const browserTestLaneValues = ['desktop', 'mobile'] as const;

export type BrowserTestLane = (typeof browserTestLaneValues)[number];

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

export const proofBenchmarkLaneValues = [
    'node',
    'desktop',
    'mobile-throttled',
] as const;

export type ProofBenchmarkLane = (typeof proofBenchmarkLaneValues)[number];

type ProofBenchmarkLaneDefinition = {
    readonly commandDescription: string;
    readonly fileParallelism: false;
    readonly include: readonly string[];
    readonly projectName: string;
    readonly testTimeout: number;
};

const browserProofBenchmarkTestGlobs = [
    'packages/wasm/tests/browser/**/*.browser.benchmark.ts',
] as const;

export const proofBenchmarkLaneDefinitions = {
    node: {
        commandDescription: 'Run node proof benchmark',
        fileParallelism: false,
        include: ['packages/wasm/tests/node/**/*.benchmark.ts'],
        projectName: 'node-proof-benchmark',
        testTimeout: proofBenchmarkTestTimeoutMs,
    },
    desktop: {
        commandDescription: 'Run desktop proof benchmark',
        fileParallelism: false,
        include: browserProofBenchmarkTestGlobs,
        projectName: 'browser-desktop-proof-benchmark',
        testTimeout: proofBenchmarkTestTimeoutMs,
    },
    'mobile-throttled': {
        commandDescription:
            'Run manually throttled mobile Chromium proof benchmark',
        fileParallelism: false,
        include: browserProofBenchmarkTestGlobs,
        projectName: 'browser-mobile-throttled-proof-benchmark',
        testTimeout: proofBenchmarkTestTimeoutMs,
    },
} as const satisfies Record<ProofBenchmarkLane, ProofBenchmarkLaneDefinition>;

export const defaultProofBenchmarkLanes = [
    'node',
    'desktop',
] as const satisfies readonly ProofBenchmarkLane[];
