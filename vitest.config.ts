import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { playwright } from '@vitest/browser-playwright';
import { defineConfig, type UserWorkspaceConfig } from 'vitest/config';
import type { BrowserInstanceOption } from 'vitest/node';

import { resolveTestDiagnosticPaths } from './tools/ci/test-diagnostic-environment.js';
import { VitestDiagnosticReporter } from './tools/ci/vitest-diagnostic-reporter.js';

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
const nodeHookTimeoutMs = 240_000;
const nodeTestTimeoutMs = 60_000;
const nodeKernelTestTimeoutMs = 15 * 60_000;

const kernelNodeTestGlobs = [
    'packages/wasm/tests/node/**/*.kernel.test.ts',
    'tests/node/**/*.kernel.test.ts',
] as const;
const nodeTestProjectDefinitions = [
    {
        exclude: [...kernelNodeTestGlobs],
        include: [
            'packages/*/tests/node/**/*.test.ts',
            'tests/node/**/*.test.ts',
        ],
        projectName: 'node',
        testTimeout: nodeTestTimeoutMs,
    },
    {
        fileParallelism: false,
        include: kernelNodeTestGlobs,
        projectName: 'node-kernel-fast',
        testTimeout: nodeKernelTestTimeoutMs,
    },
] as const;

const desktopBrowserTestGlobs = [
    'packages/*/tests/browser/**/*.browser.test.ts',
] as const;
const testDiagnosticPaths = resolveTestDiagnosticPaths();
const testAttachmentDirectoryPath = testDiagnosticPaths.attachmentDirectoryPath;
const testResultFilePath = testDiagnosticPaths.resultFilePath;
const nodeDiagnosticReportArguments =
    testDiagnosticPaths.diagnosticReportDirectoryPath === undefined
        ? []
        : [
              '--report-on-fatalerror',
              '--report-uncaught-exception',
              '--report-exclude-env',
              '--report-exclude-network',
              `--report-directory=${testDiagnosticPaths.diagnosticReportDirectoryPath}`,
              `--report-filename=node-report-${testDiagnosticPaths.projectLabel}-%p-%t.json`,
          ];
for (const diagnosticDirectoryPath of [
    testAttachmentDirectoryPath,
    testDiagnosticPaths.diagnosticReportDirectoryPath,
    testResultFilePath === undefined
        ? undefined
        : path.dirname(testResultFilePath),
]) {
    if (diagnosticDirectoryPath !== undefined) {
        mkdirSync(diagnosticDirectoryPath, { recursive: true });
    }
}

const rootPrivateAliases = [
    {
        find: '#packages',
        replacement: resolveFromRepoRoot('packages'),
    },
    {
        find: '#tests',
        replacement: resolveFromRepoRoot('tests'),
    },
    {
        find: '#test-vectors',
        replacement: resolveFromRepoRoot('test-vectors'),
    },
] as const;

const testResolve = {
    alias: rootPrivateAliases,
    tsconfigPaths: true,
} as const;

const desktopBrowserInstances: BrowserInstanceOption[] = [
    {
        browser: 'chromium',
        name: 'chromium-desktop',
    },
];

type NodeProjectInput = {
    readonly exclude?: readonly string[];
    readonly fileParallelism?: boolean;
    readonly include: readonly string[];
    readonly projectName: string;
    readonly testTimeout: number;
};

const makeNodeProject = ({
    exclude,
    fileParallelism,
    include,
    projectName,
    testTimeout,
}: NodeProjectInput): UserWorkspaceConfig => ({
    resolve: testResolve,
    test: {
        name: projectName,
        include: [...include],
        ...(exclude === undefined ? {} : { exclude: [...exclude] }),
        environment: 'node',
        ...(nodeDiagnosticReportArguments.length === 0
            ? {}
            : { execArgv: nodeDiagnosticReportArguments }),
        ...(fileParallelism === undefined ? {} : { fileParallelism }),
        testTimeout,
        hookTimeout: nodeHookTimeoutMs,
    },
});

type BrowserProjectInput = {
    readonly include: readonly string[];
    readonly instances: BrowserInstanceOption[];
    readonly projectName: string;
};

const makeBrowserProject = ({
    include,
    instances,
    projectName,
}: BrowserProjectInput): UserWorkspaceConfig => {
    const projectAttachmentDirectoryPath =
        testAttachmentDirectoryPath === undefined
            ? undefined
            : path.join(testAttachmentDirectoryPath, projectName);
    return {
        resolve: testResolve,
        test: {
            name: projectName,
            include: [...include],
            // Each real-WASM browser file can instantiate a large kernel and
            // create workers. Keep the canonical Chromium lane serialized so
            // concurrent files cannot inflate the measured working set.
            fileParallelism: false,
            ...(nodeDiagnosticReportArguments.length === 0
                ? {}
                : { execArgv: nodeDiagnosticReportArguments }),
            browser: {
                enabled: true,
                api: {
                    host: browserServerHost,
                    port: browserServerBasePort,
                    strictPort: false,
                },
                provider: playwright(),
                headless: true,
                instances,
                // Playwright writes active .network chunks to one project-level
                // directory before Vitest can add worker identity. Routine
                // coverage therefore keeps tracing off. Each manual evidence
                // command selects one isolated instance.
                trace: 'off' as const,
                ...(projectAttachmentDirectoryPath === undefined
                    ? {}
                    : {
                          screenshotDirectory: path.join(
                              projectAttachmentDirectoryPath,
                              'screenshots',
                          ),
                          screenshotFailures: true,
                      }),
            },
        },
    };
};

export default defineConfig({
    resolve: testResolve,
    test: {
        ...(testResultFilePath === undefined
            ? {
                  reporters: [
                      'default' as const,
                      ...(process.env.GITHUB_ACTIONS === 'true'
                          ? (['github-actions'] as const)
                          : []),
                      new VitestDiagnosticReporter(),
                  ],
              }
            : {
                  outputFile: { json: testResultFilePath },
                  reporters: [
                      'default' as const,
                      ...(process.env.GITHUB_ACTIONS === 'true'
                          ? (['github-actions'] as const)
                          : []),
                      'json' as const,
                      new VitestDiagnosticReporter(),
                  ],
              }),
        projects: [
            ...nodeTestProjectDefinitions.map((projectDefinition) =>
                makeNodeProject(projectDefinition),
            ),
            makeBrowserProject({
                include: desktopBrowserTestGlobs,
                instances: desktopBrowserInstances,
                projectName: 'browser-desktop',
            }),
        ],
    },
});
