import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
    type ActiveLocalRunLog,
} from './local-run-log.js';
import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommandsInSeries,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';

// `passed` and `failed` are a lane's own result; `stopped` means a sibling lane
// failed first and this lane was killed before it could finish.
type LaneStatus = 'failed' | 'passed' | 'stopped';

// A validation lane is a named group of commands that run in series with one
// another. Lanes run concurrently, so the Rust toolchain lane keeps `cargo fmt`,
// `cargo clippy`, and `cargo test` sequential (they share one native `target/`
// build lock and reuse each other's dependency artifacts) while every
// independent check overlaps it.
type ValidationLane = {
    readonly commands: readonly CommandInvocation[];
    readonly name: string;
};

type ValidationLaneResult = {
    readonly durationMilliseconds: number;
    readonly exitCode: number;
    readonly name: string;
    readonly status: LaneStatus;
};

const parseCheckArguments = (commandArguments: readonly string[]): void => {
    if (commandArguments.length > 0) {
        throw new Error('Usage: run-check.ts [--no-run-log].');
    }
};

const createCargoCommand = (
    description: string,
    commandArguments: readonly string[],
    logFileSlug: string,
): CommandInvocation => ({
    args: commandArguments,
    command: 'cargo',
    description,
    logFileSlug,
});

const createPackageManagerLane = (
    packageManagerRunner: PackageManagerRunner,
    name: string,
    logFileSlug: string,
    commandArguments: readonly string[],
): ValidationLane => ({
    commands: [
        createPackageManagerCommand(name, commandArguments, {
            logFileSlug,
            packageManagerRunner,
        }),
    ],
    name,
});

// The gating lanes run first, in series. The workspace build emits every
// `dist/` artifact and compiles the Rust kernel to WebAssembly (holding the
// cargo build lock); the type-check also emits declarations. Keeping both ahead
// of the parallel phase means no lane writes `dist/` while the test lanes import
// it, and no `cargo` lane competes with the WebAssembly build for `target/`. A
// failure here makes the rest pointless, so the run stops immediately.
const buildGatingLanes = (
    packageManagerRunner: PackageManagerRunner,
): readonly ValidationLane[] => [
    createPackageManagerLane(
        packageManagerRunner,
        'Build workspace packages',
        'build',
        ['run', 'build'],
    ),
    createPackageManagerLane(
        packageManagerRunner,
        'Type-check workspace',
        'tsc',
        ['run', 'tsc'],
    ),
];

// Every remaining check runs concurrently against the built output. The Rust
// lane is the only one that stays internally serial, because `cargo clippy` and
// `cargo test` share the native `target/` build lock. The commit gate runs only
// the fast Node test project; the heavier protocol and kernel Node projects and
// the Playwright browser projects stay in `pnpm run test:node` and
// `pnpm run test:browser` for pre-push verification.
const buildParallelLanes = (
    packageManagerRunner: PackageManagerRunner,
): readonly ValidationLane[] => {
    const lane = (
        name: string,
        logFileSlug: string,
        commandArguments: readonly string[],
    ): ValidationLane =>
        createPackageManagerLane(
            packageManagerRunner,
            name,
            logFileSlug,
            commandArguments,
        );

    return [
        lane('Lint', 'lint', ['run', 'lint']),
        lane('Verify public API surface', 'api-surface', [
            'exec',
            'tsx',
            './tools/ci/verify-api-snapshot.ts',
        ]),
        lane('Verify public package policy', 'package-policy', [
            'exec',
            'tsx',
            './tools/ci/verify-public-package-policy.ts',
        ]),
        lane('Check package boundaries', 'package-boundaries', [
            'exec',
            'tsx',
            './tools/ci/check-package-boundaries.ts',
        ]),
        lane('Verify test vectors', 'test-vectors', ['run', 'vectors']),
        lane('Knip unused-code scan', 'knip', ['exec', 'knip']),
        {
            commands: [
                createCargoCommand(
                    'cargo fmt --check',
                    ['fmt', '--check', '-p', 'sealed-lattice-kernel'],
                    'cargo-fmt',
                ),
                createCargoCommand(
                    'cargo clippy',
                    [
                        'clippy',
                        '--workspace',
                        '--all-targets',
                        '--all-features',
                        '--',
                        '-D',
                        'warnings',
                    ],
                    'cargo-clippy',
                ),
                createCargoCommand(
                    'cargo test',
                    ['test', '--workspace'],
                    'cargo-test',
                ),
            ],
            name: 'Rust kernel (fmt, clippy, test)',
        },
        lane('Node tests (fast)', 'vitest-node', [
            'exec',
            'vitest',
            '--project',
            'node',
            '--run',
        ]),
    ];
};

const runGatingLane = async (
    lane: ValidationLane,
    runLog: ActiveLocalRunLog | undefined,
): Promise<ValidationLaneResult> => {
    const startedAtMilliseconds = performance.now();
    const exitCode = await runCommandsInSeries(lane.commands, { runLog });

    return {
        durationMilliseconds: Math.round(
            performance.now() - startedAtMilliseconds,
        ),
        exitCode,
        name: lane.name,
        status: exitCode === 0 ? 'passed' : 'failed',
    };
};

const runParallelLane = async (
    lane: ValidationLane,
    runLog: ActiveLocalRunLog | undefined,
    abortController: AbortController,
): Promise<ValidationLaneResult> => {
    const startedAtMilliseconds = performance.now();
    const exitCode = await runCommandsInSeries(lane.commands, {
        runLog,
        signal: abortController.signal,
    });
    const durationMilliseconds = Math.round(
        performance.now() - startedAtMilliseconds,
    );

    if (exitCode === 0) {
        return {
            durationMilliseconds,
            exitCode,
            name: lane.name,
            status: 'passed',
        };
    }
    if (abortController.signal.aborted) {
        return {
            durationMilliseconds,
            exitCode,
            name: lane.name,
            status: 'stopped',
        };
    }

    // This lane failed on its own. Abort so every other still-running lane is
    // killed instead of grinding to completion behind a known failure.
    abortController.abort();

    return {
        durationMilliseconds,
        exitCode,
        name: lane.name,
        status: 'failed',
    };
};

const statusLabels: Readonly<Record<LaneStatus, string>> = {
    failed: 'FAIL',
    passed: 'PASS',
    stopped: 'STOP',
};

const formatDurationSeconds = (durationMilliseconds: number): string =>
    `${(durationMilliseconds / 1000).toFixed(1)}s`;

const printValidationSummary = (
    results: readonly ValidationLaneResult[],
    runLog: ActiveLocalRunLog | undefined,
): void => {
    console.log('\nValidation summary');
    for (const result of results) {
        const duration = formatDurationSeconds(
            result.durationMilliseconds,
        ).padStart(8);
        console.log(
            `  ${statusLabels[result.status]}  ${duration}  ${result.name}`,
        );
    }

    const failedResults = results.filter(
        (result) => result.status === 'failed',
    );
    const stoppedCount = results.filter(
        (result) => result.status === 'stopped',
    ).length;
    if (failedResults.length === 0) {
        console.log('\nAll validation lanes passed.');

        return;
    }

    const stoppedNote =
        stoppedCount > 0
            ? ` (${stoppedCount} other lane(s) stopped early)`
            : '';
    console.log(
        `\nFailed: ${failedResults
            .map((result) => result.name)
            .join(', ')}${stoppedNote}.`,
    );
    if (runLog !== undefined) {
        console.log(`Per-lane logs: ${runLog.runDirectoryPath}`);
    }
};

const overallExitCode = (results: readonly ValidationLaneResult[]): number => {
    const failingResult =
        results.find((result) => result.status === 'failed') ??
        results.find((result) => result.status === 'stopped');

    return failingResult ? failingResult.exitCode || 1 : 0;
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    parseCheckArguments(commandArguments);
    const packageManagerRunner = resolvePackageManagerRunner();
    const gatingLanes = buildGatingLanes(packageManagerRunner);
    const parallelLanes = buildParallelLanes(packageManagerRunner);
    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: [...gatingLanes, ...parallelLanes].map(
                  (lane) => lane.name,
              ),
              scriptName: 'check',
          });

    try {
        const results: ValidationLaneResult[] = [];

        for (const lane of gatingLanes) {
            const result = await runGatingLane(lane, runLog);
            results.push(result);
            if (result.exitCode !== 0) {
                printValidationSummary(results, runLog);
                process.exitCode = result.exitCode;

                return;
            }
        }

        const abortController = new AbortController();
        const parallelResults = await Promise.all(
            parallelLanes.map((lane) =>
                runParallelLane(lane, runLog, abortController),
            ),
        );
        results.push(
            ...[...parallelResults].sort(
                (first, second) =>
                    second.durationMilliseconds - first.durationMilliseconds,
            ),
        );
        printValidationSummary(results, runLog);
        process.exitCode = overallExitCode(results);
    } finally {
        await runLog?.finish({ exitCode: currentProcessExitCode() });
    }
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}
