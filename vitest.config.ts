import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { playwright } from '@vitest/browser-playwright';
import type { PluginOption } from 'vite';
import { defineConfig, type UserWorkspaceConfig } from 'vitest/config';
import type { BrowserCommand, BrowserInstanceOption } from 'vitest/node';

import {
    browserTestLaneDefinitions,
    nodeHookTimeoutMs,
    nodeTestProjectDefinitions,
    proofBenchmarkLaneDefinitions,
} from './tools/ci/test-lanes.js';

const repoRoot = path.dirname(fileURLToPath(import.meta.url));
const resolveFromRepoRoot = (...segments: string[]): string =>
    path.resolve(repoRoot, ...segments);

const browserServerHost = '127.0.0.1';

const publicPackageEntryPoint = resolveFromRepoRoot(
    'packages',
    'sdk',
    'dist',
    'index.js',
);

const publicPackageAlias = {
    find: 'sealed-lattice',
    replacement: publicPackageEntryPoint,
} as const;

const rootPrivateAliases = [
    {
        find: '#test-vectors',
        replacement: resolveFromRepoRoot('test-vectors'),
    },
] as const;

const publicPackageTestResolve = {
    alias: [publicPackageAlias, ...rootPrivateAliases],
    tsconfigPaths: true,
} as const;

const createPublicPackageResolutionPlugin = (): PluginOption => ({
    name: 'sealed-lattice-public-package-resolution',
    enforce: 'pre' as const,
    resolveId(source: string): string | null {
        return source === publicPackageAlias.find
            ? publicPackageEntryPoint
            : null;
    },
});

const copyGlobs = (globs: readonly string[]): string[] => [...globs];

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

// Browser proof-benchmark lanes run in headless Chromium, where Vitest forwards
// browser console only to a TTY/UI and not to the piped stdout the local run log
// tees. This node-side command lets browser benchmarks push their report lines
// straight to stdout so they are captured under logs/ like the node lane.
const writeBenchmarkLogLine: BrowserCommand<[string]> = (_context, line) => {
    process.stdout.write(`${line}\n`);
};

const benchmarkBrowserCommands: Record<string, BrowserCommand<[string]>> = {
    writeBenchmarkLogLine,
};

type NodeProjectInput = {
    readonly disableConsoleIntercept?: boolean;
    readonly exclude?: readonly string[];
    readonly fileParallelism?: boolean;
    readonly include: readonly string[];
    readonly projectName: string;
    readonly testTimeout: number;
};

const makeNodeProject = ({
    disableConsoleIntercept,
    exclude,
    fileParallelism,
    include,
    projectName,
    testTimeout,
}: NodeProjectInput): UserWorkspaceConfig => ({
    plugins: [createPublicPackageResolutionPlugin()],
    resolve: publicPackageTestResolve,
    test: {
        name: projectName,
        include: copyGlobs(include),
        ...(exclude === undefined ? {} : { exclude: copyGlobs(exclude) }),
        environment: 'node',
        ...(fileParallelism === undefined ? {} : { fileParallelism }),
        ...(disableConsoleIntercept === undefined
            ? {}
            : { disableConsoleIntercept }),
        testTimeout,
        hookTimeout: nodeHookTimeoutMs,
    },
});

type BrowserProjectInput = {
    readonly commands?: Record<string, BrowserCommand<[string]>>;
    readonly fileParallelism?: boolean;
    readonly hookTimeout?: number;
    readonly include: readonly string[];
    readonly instances: BrowserInstanceOption[];
    readonly projectName: string;
    readonly provider?: ReturnType<typeof playwright>;
    readonly testTimeout?: number;
};

const makeBrowserProject = ({
    commands,
    fileParallelism,
    hookTimeout,
    include,
    instances,
    projectName,
    provider = playwright(),
    testTimeout,
}: BrowserProjectInput): UserWorkspaceConfig => ({
    plugins: [createPublicPackageResolutionPlugin()],
    resolve: publicPackageTestResolve,
    test: {
        name: projectName,
        include: copyGlobs(include),
        ...(fileParallelism === undefined ? {} : { fileParallelism }),
        ...(testTimeout === undefined ? {} : { testTimeout }),
        ...(hookTimeout === undefined ? {} : { hookTimeout }),
        browser: {
            enabled: true,
            api: {
                host: browserServerHost,
                strictPort: false,
            },
            provider,
            headless: true,
            instances,
            ...(commands === undefined ? {} : { commands }),
        },
    },
});

export default defineConfig({
    plugins: [createPublicPackageResolutionPlugin()],
    resolve: publicPackageTestResolve,
    test: {
        alias: [publicPackageAlias, ...rootPrivateAliases],
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
            ...nodeTestProjectDefinitions.map((projectDefinition) =>
                makeNodeProject(projectDefinition),
            ),
            makeNodeProject({
                ...proofBenchmarkLaneDefinitions.node,
                disableConsoleIntercept: true,
            }),
            makeBrowserProject({
                ...browserTestLaneDefinitions.desktop,
                instances: desktopBrowserInstances,
            }),
            makeBrowserProject({
                ...browserTestLaneDefinitions.mobile,
                instances: mobileBrowserInstances,
            }),
            makeBrowserProject({
                ...proofBenchmarkLaneDefinitions.desktop,
                instances: desktopProofBenchmarkBrowserInstances,
                hookTimeout: nodeHookTimeoutMs,
                commands: benchmarkBrowserCommands,
            }),
        ],
    },
});
