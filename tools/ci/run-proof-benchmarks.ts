import { pathToFileURL } from 'node:url';

import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommand,
    runCommandsInParallel,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';

type ProofBenchmarkLane = 'desktop' | 'mobile-throttled' | 'node';

const defaultProofBenchmarkLanes: readonly ProofBenchmarkLane[] = [
    'node',
    'desktop',
];

const proofBenchmarkProjectByLane = {
    desktop: 'browser-desktop-proof-benchmark',
    'mobile-throttled': 'browser-mobile-throttled-proof-benchmark',
    node: 'node-proof-benchmark',
} as const;

export const parseRequestedProofBenchmarkLanes = (
    commandLineArguments: readonly string[],
): readonly ProofBenchmarkLane[] => {
    if (commandLineArguments.length === 0) {
        return defaultProofBenchmarkLanes;
    }
    if (
        commandLineArguments.length !== 2 ||
        commandLineArguments[0] !== '--only'
    ) {
        throw new Error('Usage: run-proof-benchmarks.ts [--only lane].');
    }

    const lane = commandLineArguments[1];
    if (lane !== 'desktop' && lane !== 'mobile-throttled' && lane !== 'node') {
        throw new Error(`Unsupported proof benchmark lane: ${lane}`);
    }

    return [lane];
};

export const buildProofBenchmarkCommands = (
    input: {
        readonly lanes?: readonly ProofBenchmarkLane[];
        readonly packageManagerRunner?: PackageManagerRunner;
    } = {},
): readonly CommandInvocation[] => {
    const packageManagerRunner =
        input.packageManagerRunner ?? resolvePackageManagerRunner();
    const lanes = input.lanes ?? defaultProofBenchmarkLanes;
    const buildCommand = (
        description: string,
        commandArguments: readonly string[],
    ): CommandInvocation =>
        createPackageManagerCommand(description, commandArguments, {
            packageManagerRunner,
        });

    return [
        buildCommand('Build workspace packages', ['run', 'build']),
        ...lanes.map((lane) =>
            buildCommand(
                lane === 'mobile-throttled'
                    ? 'Run manually throttled mobile Chromium proof benchmark'
                    : `Run ${lane} proof benchmark`,
                [
                    'exec',
                    'vitest',
                    '--project',
                    proofBenchmarkProjectByLane[lane],
                    '--run',
                ],
            ),
        ),
    ];
};

export const runProofBenchmarkCommands = async (
    invocations: readonly CommandInvocation[],
): Promise<number> => {
    const [buildCommand, ...benchmarkCommands] = invocations;
    if (buildCommand === undefined) {
        return 0;
    }

    const buildExitCode = runCommand(buildCommand);
    if (buildExitCode !== 0) {
        return buildExitCode;
    }

    return runCommandsInParallel(benchmarkCommands);
};

const main = async (): Promise<void> => {
    process.exitCode = await runProofBenchmarkCommands(
        buildProofBenchmarkCommands({
            lanes: parseRequestedProofBenchmarkLanes(process.argv.slice(2)),
        }),
    );
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}
