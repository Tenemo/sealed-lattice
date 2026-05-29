import { pathToFileURL } from 'node:url';

import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommandsInParallel,
    runCommandsInSeries,
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

    return lanes.map((lane) => {
        const laneDefinition = proofBenchmarkLaneDefinitions[lane];

        return createPackageManagerCommand(
            laneDefinition.commandDescription,
            [
                'exec',
                'vitest',
                '--project',
                laneDefinition.projectName,
                '--run',
            ],
            {
                logFileSlug: laneDefinition.projectName,
                packageManagerRunner,
            },
        );
    });
};

const buildWorkspaceBuildCommand = (
    packageManagerRunner: PackageManagerRunner,
): CommandInvocation =>
    createPackageManagerCommand('Build workspace packages', ['run', 'build'], {
        logFileSlug: 'build',
        packageManagerRunner,
    });

const proofBenchmarkScriptNames: Record<ProofBenchmarkLane, string> = {
    desktop: 'test:proof-benchmark:browser:desktop',
    node: 'test:proof-benchmark:node',
};

const proofBenchmarkScriptName = (
    lanes: readonly ProofBenchmarkLane[],
): string =>
    lanes.length === 1
        ? (proofBenchmarkScriptNames[lanes[0]] ?? 'test:proof-benchmark')
        : 'test:proof-benchmark';

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    const lanes = parseRequestedProofBenchmarkLanes(commandArguments);
    const packageManagerRunner = resolvePackageManagerRunner();
    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes,
              scriptName: proofBenchmarkScriptName(lanes),
          });

    try {
        const buildExitCode = await runCommandsInSeries(
            [buildWorkspaceBuildCommand(packageManagerRunner)],
            { runLog },
        );
        if (buildExitCode !== 0) {
            process.exitCode = buildExitCode;

            return;
        }
        process.exitCode = await runCommandsInParallel(
            buildProofBenchmarkCommands({ lanes, packageManagerRunner }),
            { runLog },
        );
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
