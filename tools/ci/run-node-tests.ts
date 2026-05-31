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
    defaultNodeTestLanes,
    nodeTestLaneDefinitions,
    nodeTestLaneValues,
    type NodeTestLane,
} from './test-lanes.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const isNodeTestLane = (lane: string): lane is NodeTestLane =>
    nodeTestLaneValues.some((supportedLane) => supportedLane === lane);

export const parseRequestedNodeTestLanes = (
    commandArguments: readonly string[],
): readonly NodeTestLane[] => {
    if (commandArguments.length === 0) {
        return defaultNodeTestLanes;
    }
    if (commandArguments.length !== 2 || commandArguments[0] !== '--only') {
        throw new Error('Usage: run-node-tests.ts [--only lane].');
    }

    const requestedLaneList = commandArguments[1]
        ?.split(',')
        .map((lane) => lane.trim())
        .filter((lane) => lane.length > 0);
    if (requestedLaneList === undefined || requestedLaneList.length === 0) {
        throw new Error('At least one Node test lane is required.');
    }
    const requestedLanes: NodeTestLane[] = [];
    for (const requestedLane of requestedLaneList) {
        if (!isNodeTestLane(requestedLane)) {
            throw new Error(`Unsupported Node test lane: ${requestedLane}`);
        }
        requestedLanes.push(requestedLane);
    }

    return requestedLanes;
};

export const buildNodeTestCommands = (
    input: {
        readonly lanes?: readonly NodeTestLane[];
        readonly packageManagerRunner?: PackageManagerRunner;
    } = {},
): readonly CommandInvocation[] => {
    const packageManagerRunner =
        input.packageManagerRunner ?? resolvePackageManagerRunner();
    const lanes = input.lanes ?? defaultNodeTestLanes;
    const buildCommand = (lane: NodeTestLane): CommandInvocation => {
        const laneDefinition = nodeTestLaneDefinitions[lane];

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
    };

    return lanes.map((lane) => buildCommand(lane));
};

const buildWorkspaceBuildCommand = (
    packageManagerRunner: PackageManagerRunner,
): CommandInvocation =>
    createPackageManagerCommand('Build workspace packages', ['run', 'build'], {
        logFileSlug: 'build',
        packageManagerRunner,
    });

const nodeTestScriptName = (lanes: readonly NodeTestLane[]): string =>
    lanes.length === 1 ? `test:node:${lanes[0]}` : 'test:node';

const nodeTestRunShouldLog = (
    lanes: readonly NodeTestLane[],
    commandArguments: readonly string[],
): boolean =>
    !runLogDisabledByArguments(commandArguments) &&
    lanes.some((lane) => lane !== 'fast');

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    const lanes = parseRequestedNodeTestLanes(commandArguments);
    const packageManagerRunner = resolvePackageManagerRunner();
    const runLog = nodeTestRunShouldLog(lanes, rawArguments)
        ? await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes,
              scriptName: nodeTestScriptName(lanes),
          })
        : undefined;

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
            buildNodeTestCommands({
                lanes,
                packageManagerRunner,
            }),
            { runLog },
        );
    } finally {
        await runLog?.finish({ exitCode: currentProcessExitCode() });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
