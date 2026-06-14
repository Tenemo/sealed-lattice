export const nodeTestTimeoutMs = 60_000;
export const nodeKernelHeavyTestTimeoutMs = 15 * 60_000;
export const nodeKernelVeryHeavyTestTimeoutMs = 60 * 60_000;
export const nodeHookTimeoutMs = 240_000;

export const nodeTestLaneValues = [
    'fast',
    'protocol',
    'kernel',
    'kernel-heavy',
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

const protocolNodeTestGlobs = [
    'packages/protocol/tests/node/**/*.test.ts',
] as const;

const kernelNodeTestGlobs = [
    'packages/wasm/tests/node/**/*.kernel.test.ts',
    'tests/node/**/*.kernel.test.ts',
] as const;

const heavyKernelNodeTestGlobs = [
    'packages/wasm/tests/node/transcript-core-kernel/bgv-collective-setup.kernel.test.ts',
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
    kernel: {
        commandDescription: 'Run kernel Node tests',
        exclude: heavyKernelNodeTestGlobs,
        fileParallelism: false,
        include: kernelNodeTestGlobs,
        projectName: 'node-kernel',
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
    nodeTestLaneDefinitions.fast,
    nodeTestLaneDefinitions.protocol,
    nodeTestLaneDefinitions.kernel,
    nodeTestLaneDefinitions['kernel-heavy'],
] as const;

export const defaultNodeTestLanes = [
    'fast',
    'protocol',
    'kernel',
    'kernel-heavy',
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
