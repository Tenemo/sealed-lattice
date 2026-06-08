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

        return buildVitestProjectCommand({
            commandDescription: laneDefinition.commandDescription,
            packageManagerRunner,
            projectName: laneDefinition.projectName,
        });
    };

    return lanes.map((lane) => buildCommand(lane));
};

const nodeTestScriptName = (lanes: readonly NodeTestLane[]): string =>
    lanes.length === 1
        ? `test:node:${lanes[0].replace('-', ':')}`
        : 'test:node';

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
    await runWorkspaceBuildThenParallelCommands({
        buildCommands: (packageManagerRunner) =>
            buildNodeTestCommands({ lanes, packageManagerRunner }),
        commandLineArguments: rawArguments,
        lanes,
        scriptName: nodeTestScriptName(lanes),
        shouldCreateRunLog: nodeTestRunShouldLog(lanes, rawArguments),
    });
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
