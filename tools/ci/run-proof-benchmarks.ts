import { pathToFileURL } from 'node:url';

import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommand,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';
import {
    defaultProofBenchmarkLanes,
    proofBenchmarkLaneDefinitions,
    proofBenchmarkLaneValues,
    type ProofBenchmarkLane,
} from './test-lanes.js';

const isProofBenchmarkLane = (lane: string): lane is ProofBenchmarkLane =>
    proofBenchmarkLaneValues.some((supportedLane) => supportedLane === lane);

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
    if (lane === undefined || !isProofBenchmarkLane(lane)) {
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
        ...lanes.map((lane) => {
            const laneDefinition = proofBenchmarkLaneDefinitions[lane];

            return buildCommand(laneDefinition.commandDescription, [
                'exec',
                'vitest',
                '--project',
                laneDefinition.projectName,
                '--run',
            ]);
        }),
    ];
};

export const runProofBenchmarkCommands = (
    invocations: readonly CommandInvocation[],
): number => {
    const [buildCommand, ...benchmarkCommands] = invocations;
    if (buildCommand === undefined) {
        return 0;
    }

    const buildExitCode = runCommand(buildCommand);
    if (buildExitCode !== 0) {
        return buildExitCode;
    }

    for (const benchmarkCommand of benchmarkCommands) {
        const benchmarkExitCode = runCommand(benchmarkCommand);
        if (benchmarkExitCode !== 0) {
            return benchmarkExitCode;
        }
    }

    return 0;
};

const main = (): void => {
    process.exitCode = runProofBenchmarkCommands(
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
