import {
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import { type CommandInvocation } from './run-command.js';
import {
    buildVitestProjectCommand,
    runWorkspaceBuildThenParallelCommands,
} from './run-vitest-lanes.js';
import {
    defaultProofBenchmarkLanes,
    proofBenchmarkLaneDefinitions,
    proofBenchmarkLaneValues,
    type ProofBenchmarkLane,
} from './test-lanes.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

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

        return buildVitestProjectCommand({
            commandDescription: laneDefinition.commandDescription,
            packageManagerRunner,
            projectName: laneDefinition.projectName,
        });
    });
};

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
    await runWorkspaceBuildThenParallelCommands({
        buildCommands: (packageManagerRunner) =>
            buildProofBenchmarkCommands({ lanes, packageManagerRunner }),
        commandLineArguments: rawArguments,
        lanes,
        scriptName: proofBenchmarkScriptName(lanes),
        shouldCreateRunLog: !runLogDisabledByArguments(rawArguments),
    });
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
