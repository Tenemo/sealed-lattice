const nodeTestTimeoutMs = 60_000;
const nodeKernelHeavyTestTimeoutMs = 15 * 60_000;
const nodeKernelVeryHeavyTestTimeoutMs = 60 * 60_000;
export const nodeHookTimeoutMs = 240_000;

export const nodeTestLaneValues = [
    'fast',
    'protocol',
    'kernel-fast',
    'kernel-heavy',
] as const;

export type NodeTestLane = (typeof nodeTestLaneValues)[number];
type TestLaneGroup =
    | 'browser'
    | 'node-fast'
    | 'node-kernel-fast'
    | 'node-kernel-heavy'
    | 'node-protocol';

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
