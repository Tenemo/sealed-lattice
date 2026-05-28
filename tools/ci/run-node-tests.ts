import { pathToFileURL } from 'node:url';

import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommandsInParallel,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';

export const nodeTestLaneValues = ['fast', 'protocol', 'kernel'] as const;

export type NodeTestLane = (typeof nodeTestLaneValues)[number];

const defaultNodeTestLanes = nodeTestLaneValues;

const nodeTestLaneProjectNames = {
    fast: 'node',
    protocol: 'node-protocol',
    kernel: 'node-kernel',
} as const satisfies Record<NodeTestLane, string>;

const nodeTestLaneDescriptions = {
    fast: 'Run fast Node tests',
    protocol: 'Run protocol Node tests',
    kernel: 'Run heavy Node kernel tests',
} as const satisfies Record<NodeTestLane, string>;

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

    const requestedLane = commandArguments[1]?.trim();
    if (requestedLane === undefined || requestedLane.length === 0) {
        throw new Error('At least one Node test lane is required.');
    }
    if (!isNodeTestLane(requestedLane)) {
        throw new Error(`Unsupported Node test lane: ${requestedLane}`);
    }

    return [requestedLane];
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
    const buildCommand = (lane: NodeTestLane): CommandInvocation =>
        createPackageManagerCommand(
            nodeTestLaneDescriptions[lane],
            [
                'exec',
                'vitest',
                '--project',
                nodeTestLaneProjectNames[lane],
                '--run',
            ],
            {
                packageManagerRunner,
            },
        );

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
