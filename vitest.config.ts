import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';
import type { BrowserInstanceOption } from 'vitest/node';

const repoRoot = path.dirname(fileURLToPath(import.meta.url));
const resolveFromRepoRoot = (...segments: string[]): string =>
    path.resolve(repoRoot, ...segments);
const resolveAliasDirectoryFromRepoRoot = (...segments: string[]): string =>
    `${resolveFromRepoRoot(...segments).replace(/\\/g, '/')}/`;

const nodeTestTimeoutMs = 60_000;
const nodeKernelHeavyTestTimeoutMs = 15 * 60_000;
const proofBenchmarkTestTimeoutMs = 60 * 60_000;
const nodeHookTimeoutMs = 240_000;
const browserApiHost = '127.0.0.1';
const desktopBrowserApiPort = 64_115;
const mobileBrowserApiPort = 64_116;
const desktopProofBenchmarkBrowserApiPort = 64_117;
const mobileThrottledProofBenchmarkBrowserApiPort = 64_118;
const nodeTestIncludes = [
    'packages/*/tests/node/**/*.test.ts',
    'tests/node/**/*.test.ts',
] satisfies string[];
const nodeProofBenchmarkTestIncludes = [
    'packages/wasm/tests/node/ballot-privacy-proof-benchmarks.benchmark.ts',
    'packages/wasm/tests/node/transcript-core-kernel/mandatory-profile-proof-record.test.ts',
] satisfies string[];
const browserProofBenchmarkTestIncludes = [
    'packages/wasm/tests/browser/ballot-privacy-proof-benchmarks.browser.benchmark.ts',
] satisfies string[];
const nodeHeavyTestIncludes = [
    'packages/protocol/tests/node/ballot-privacy-proof-record-generation-input.test.ts',
    'packages/protocol/tests/node/ballot-privacy-relation-backend-lowering/**/*.test.ts',
] satisfies string[];
const nodeKernelHeavyTestIncludes = [
    'packages/wasm/tests/node/transcript-core-kernel/ballot-proof-generation.test.ts',
    'packages/wasm/tests/node/transcript-core-kernel/ballot-proof-rejection.test.ts',
    'packages/wasm/tests/node/transcript-core-kernel/component-bundle-rejection.test.ts',
    'packages/wasm/tests/node/transcript-core-kernel/core-kernel-and-fixtures.test.ts',
    'packages/wasm/tests/node/transcript-core-kernel/kernel-memory-and-loader.test.ts',
    'packages/wasm/tests/node/transcript-core-kernel/receiver-key-proofs.test.ts',
    'packages/wasm/tests/node/canonical-error-codes-parity.test.ts',
    'packages/testkit/tests/node/transcript-core-fixtures.test.ts',
    'tests/node/digest-namespace-parity.test.ts',
] satisfies string[];

const nodeProject = {
    environment: 'node',
    testTimeout: nodeTestTimeoutMs,
    hookTimeout: nodeHookTimeoutMs,
} as const;

const nodeKernelHeavyProject = {
    environment: 'node',
    testTimeout: nodeKernelHeavyTestTimeoutMs,
    hookTimeout: nodeHookTimeoutMs,
} as const;

const nodeHeavyProject = {
    environment: 'node',
    testTimeout: nodeKernelHeavyTestTimeoutMs,
    hookTimeout: nodeHookTimeoutMs,
} as const;

const nodeProofBenchmarkProject = {
    environment: 'node',
    fileParallelism: false,
    testTimeout: proofBenchmarkTestTimeoutMs,
    hookTimeout: nodeHookTimeoutMs,
} as const;

const mobileContextOptions = {
    'Pixel 5': {
        userAgent:
            'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.15 Mobile Safari/537.36',
        viewport: {
            width: 393,
            height: 727,
        },
        screen: {
            width: 393,
            height: 851,
        },
        deviceScaleFactor: 2.75,
        isMobile: true,
        hasTouch: true,
    },
    'iPhone 12': {
        userAgent:
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1',
        viewport: {
            width: 390,
            height: 664,
        },
        screen: {
            width: 390,
            height: 844,
        },
        deviceScaleFactor: 3,
        isMobile: true,
        hasTouch: true,
    },
} as const;

const desktopProofBenchmarkContextOptions = {
    userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.15 Safari/537.36',
    viewport: {
        width: 1280,
        height: 720,
    },
    screen: {
        width: 1280,
        height: 720,
    },
    deviceScaleFactor: 1,
    isMobile: false,
    hasTouch: false,
} as const;

const desktopBrowserInstances: BrowserInstanceOption[] = [
    { browser: 'chromium', name: 'chromium-desktop' },
    { browser: 'firefox', name: 'firefox-desktop' },
    { browser: 'webkit', name: 'webkit-desktop' },
];

const mobileBrowserInstances: BrowserInstanceOption[] = [
    {
        browser: 'chromium',
        name: 'chromium-mobile',
        provider: playwright({
            contextOptions: mobileContextOptions['Pixel 5'],
        }),
    },
    {
        browser: 'webkit',
        name: 'webkit-mobile',
        provider: playwright({
            contextOptions: mobileContextOptions['iPhone 12'],
        }),
    },
];

const desktopProofBenchmarkBrowserInstances: BrowserInstanceOption[] = [
    {
        browser: 'chromium',
        name: 'chromium-desktop-proof-benchmark',
        provider: playwright({
            contextOptions: desktopProofBenchmarkContextOptions,
        }),
    },
];

const repoRootAliases = [
    {
        find: 'sealed-lattice',
        replacement: resolveFromRepoRoot('packages', 'sdk', 'dist', 'index.js'),
    },
    {
        find: '@sealed-lattice/types',
        replacement: resolveFromRepoRoot(
            'packages',
            'types',
            'src',
            'index.ts',
        ),
    },
    {
        find: '@sealed-lattice/protocol',
        replacement: resolveFromRepoRoot(
            'packages',
            'protocol',
            'src',
            'index.ts',
        ),
    },
    {
        find: '@sealed-lattice/crypto',
        replacement: resolveFromRepoRoot(
            'packages',
            'crypto',
            'src',
            'index.ts',
        ),
    },
    {
        find: '@sealed-lattice/wasm',
        replacement: resolveFromRepoRoot('packages', 'wasm', 'src', 'index.ts'),
    },
    {
        find: '@sealed-lattice/testkit',
        replacement: resolveFromRepoRoot(
            'packages',
            'testkit',
            'src',
            'index.ts',
        ),
    },
    {
        find: /^#packages\/(.*)$/,
        replacement: `${resolveAliasDirectoryFromRepoRoot('packages')}$1`,
    },
    {
        find: /^#test-vectors\/(.*)$/,
        replacement: `${resolveAliasDirectoryFromRepoRoot('test-vectors')}$1`,
    },
    {
        find: /^#tests\/(.*)$/,
        replacement: `${resolveAliasDirectoryFromRepoRoot('tests')}$1`,
    },
    {
        find: /^#tools\/(.*)$/,
        replacement: `${resolveAliasDirectoryFromRepoRoot('tools')}$1`,
    },
];
const repoRootResolve = {
    alias: repoRootAliases,
};

const mobileThrottledProofBenchmarkBrowserInstances: BrowserInstanceOption[] = [
    {
        browser: 'chromium',
        name: 'chromium-mobile-throttled-proof-benchmark',
        provider: playwright({
            contextOptions: mobileContextOptions['Pixel 5'],
        }),
    },
];

type BrowserProjectInput = {
    readonly name: string;
    readonly include: string[];
    readonly apiPort: number;
    readonly instances: BrowserInstanceOption[];
    readonly provider?: ReturnType<typeof playwright>;
    readonly fileParallelism?: boolean;
    readonly testTimeout?: number;
    readonly hookTimeout?: number;
};

type BrowserProject = {
    readonly resolve: typeof repoRootResolve;
    readonly test: {
        readonly name: string;
        readonly include: string[];
        readonly fileParallelism?: boolean;
        readonly testTimeout?: number;
        readonly hookTimeout?: number;
        readonly browser: {
            readonly enabled: true;
            readonly api: {
                readonly host: string;
                readonly port: number;
                readonly strictPort: false;
            };
            readonly provider: ReturnType<typeof playwright>;
            readonly headless: true;
            readonly instances: BrowserInstanceOption[];
        };
    };
};

const makeBrowserProject = ({
    name,
    include,
    apiPort,
    instances,
    provider = playwright(),
    fileParallelism,
    testTimeout,
    hookTimeout,
}: BrowserProjectInput): BrowserProject => ({
    resolve: repoRootResolve,
    test: {
        name,
        include,
        ...(fileParallelism === undefined ? {} : { fileParallelism }),
        ...(testTimeout === undefined ? {} : { testTimeout }),
        ...(hookTimeout === undefined ? {} : { hookTimeout }),
        browser: {
            enabled: true,
            api: {
                host: browserApiHost,
                port: apiPort,
                strictPort: false,
            },
            provider,
            headless: true,
            instances,
        },
    },
});

export default defineConfig({
    resolve: {
        alias: repoRootAliases,
    },
    test: {
        alias: repoRootAliases,
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json-summary', 'lcov'],
            reportsDirectory: './coverage',
            include: [
                'packages/*/src/**/*.ts',
                'tools/**/*.ts',
                'tools/**/*.mts',
                'tools/**/*.mjs',
            ],
            exclude: ['packages/*/src/**/*.d.ts'],
        },
        projects: [
            {
                resolve: repoRootResolve,
                test: {
                    name: 'node',
                    include: nodeTestIncludes,
                    exclude: [
                        ...nodeHeavyTestIncludes,
                        ...nodeKernelHeavyTestIncludes,
                        ...nodeProofBenchmarkTestIncludes,
                    ],
                    ...nodeProject,
                },
            },
            {
                resolve: repoRootResolve,
                test: {
                    name: 'node-heavy',
                    include: nodeHeavyTestIncludes,
                    ...nodeHeavyProject,
                },
            },
            {
                resolve: repoRootResolve,
                test: {
                    name: 'node-kernel-heavy',
                    include: nodeKernelHeavyTestIncludes,
                    ...nodeKernelHeavyProject,
                },
            },
            {
                resolve: repoRootResolve,
                test: {
                    name: 'node-proof-benchmark',
                    include: nodeProofBenchmarkTestIncludes,
                    ...nodeProofBenchmarkProject,
                },
            },
            makeBrowserProject({
                name: 'browser-desktop',
                include: ['packages/*/tests/browser/**/*.browser.test.ts'],
                apiPort: desktopBrowserApiPort,
                instances: desktopBrowserInstances,
            }),
            makeBrowserProject({
                name: 'browser-mobile',
                include: ['packages/*/tests/browser/**/*.browser.test.ts'],
                apiPort: mobileBrowserApiPort,
                instances: mobileBrowserInstances,
            }),
            makeBrowserProject({
                name: 'browser-desktop-proof-benchmark',
                include: browserProofBenchmarkTestIncludes,
                apiPort: desktopProofBenchmarkBrowserApiPort,
                instances: desktopProofBenchmarkBrowserInstances,
                fileParallelism: false,
                testTimeout: proofBenchmarkTestTimeoutMs,
                hookTimeout: nodeHookTimeoutMs,
            }),
            makeBrowserProject({
                name: 'browser-mobile-throttled-proof-benchmark',
                include: browserProofBenchmarkTestIncludes,
                apiPort: mobileThrottledProofBenchmarkBrowserApiPort,
                instances: mobileThrottledProofBenchmarkBrowserInstances,
                fileParallelism: false,
                testTimeout: proofBenchmarkTestTimeoutMs,
                hookTimeout: nodeHookTimeoutMs,
            }),
        ],
    },
});
