import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { playwright } from '@vitest/browser-playwright';
import type { PluginOption } from 'vite';
import { defineConfig, type UserWorkspaceConfig } from 'vitest/config';
import type { BrowserInstanceOption } from 'vitest/node';

import {
    browserTestLaneDefinitions,
    nodeHookTimeoutMs,
    nodeTestProjectDefinitions,
} from './tools/ci/test-lanes.js';

const repoRoot = path.dirname(fileURLToPath(import.meta.url));
const resolveFromRepoRoot = (...segments: string[]): string =>
    path.resolve(repoRoot, ...segments);

const browserServerHost = '127.0.0.1';
// Without an explicit port, vitest's browser server auto-selects one that, on
// Windows hosts running Hyper-V or WSL, can land in a reserved excluded range
// (for example 62744-65187 or 50000-50059) where bind fails with EACCES.
// strictPort: false only falls through on EADDRINUSE, not EACCES, so the run
// dies instead of retrying. Pin a base port in the registered range, below the
// 49152+ ephemeral port range Windows reserves; strictPort: false still increments it
// for concurrent browser lanes and clones.
const browserServerBasePort = 41000;

const browserOptimizedDependencies = [
    '@noble/hashes/hkdf.js',
    '@noble/hashes/sha2.js',
    '@noble/hashes/utils.js',
    '@noble/post-quantum/ml-kem.js',
] as const;

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
        find: '#tests',
        replacement: resolveFromRepoRoot('tests'),
    },
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
    readonly include: readonly string[];
    readonly instances: BrowserInstanceOption[];
    readonly projectName: string;
    readonly provider?: ReturnType<typeof playwright>;
};

const makeBrowserProject = ({
    include,
    instances,
    projectName,
    provider = playwright(),
}: BrowserProjectInput): UserWorkspaceConfig => ({
    plugins: [createPublicPackageResolutionPlugin()],
    resolve: publicPackageTestResolve,
    test: {
        name: projectName,
        include: copyGlobs(include),
        browser: {
            enabled: true,
            api: {
                host: browserServerHost,
                port: browserServerBasePort,
                strictPort: false,
            },
            provider,
            headless: true,
            instances,
        },
    },
});

export default defineConfig({
    plugins: [createPublicPackageResolutionPlugin()],
    optimizeDeps: {
        include: [...browserOptimizedDependencies],
    },
    resolve: publicPackageTestResolve,
    test: {
        alias: [publicPackageAlias, ...rootPrivateAliases],
        projects: [
            ...nodeTestProjectDefinitions.map((projectDefinition) =>
                makeNodeProject(projectDefinition),
            ),
            makeBrowserProject({
                ...browserTestLaneDefinitions.desktop,
                instances: desktopBrowserInstances,
            }),
            makeBrowserProject({
                ...browserTestLaneDefinitions.mobile,
                instances: mobileBrowserInstances,
            }),
        ],
    },
});
