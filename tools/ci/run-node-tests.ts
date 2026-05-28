import { pathToFileURL } from 'node:url';

import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommandsInParallel,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';
import {
    defaultNodeTestLanes,
    nodeTestLaneDefinitions,
    nodeTestLaneValues,
    type NodeTestLane,
} from './test-lanes.js';

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
                packageManagerRunner,
            },
        );
    };

    return lanes.map((lane) => buildCommand(lane));
};

const main = async (): Promise<void> => {
    process.exitCode = await runCommandsInParallel(
        buildNodeTestCommands({
            lanes: parseRequestedNodeTestLanes(process.argv.slice(2)),
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
