import { pathToFileURL } from 'node:url';

import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommands,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';

export const nodeTestLaneValues = [
    'fast',
    'relation-heavy',
    'proof-input-heavy',
    'kernel-remaining',
    'kernel-aggregate',
] as const;

export type NodeTestLane = (typeof nodeTestLaneValues)[number];

const defaultNodeTestLanes = nodeTestLaneValues;

const nodeTestLaneProjectNames = {
    fast: 'node',
    'relation-heavy': 'node-relation-heavy',
    'proof-input-heavy': 'node-proof-input-heavy',
    'kernel-remaining': 'node-kernel-remaining',
    'kernel-aggregate': 'node-kernel-aggregate',
} as const satisfies Record<NodeTestLane, string>;

const nodeTestLaneDescriptions = {
    fast: 'Run fast Node tests',
    'relation-heavy': 'Run relation-heavy Node tests',
    'proof-input-heavy': 'Run proof-input-heavy Node tests',
    'kernel-remaining': 'Run remaining heavy Node kernel tests',
    'kernel-aggregate': 'Run aggregate heavy Node kernel tests',
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
        throw new Error('Usage: run-node-tests.ts [--only lane[,lane...]].');
    }

    const requestedLanes = commandArguments[1]
        ?.split(',')
        .map((lane) => lane.trim())
        .filter((lane) => lane.length > 0);
    if (requestedLanes === undefined || requestedLanes.length === 0) {
        throw new Error('At least one Node test lane is required.');
    }

    const uniqueLanes: NodeTestLane[] = [];
    for (const requestedLane of requestedLanes) {
        if (!isNodeTestLane(requestedLane)) {
            throw new Error(`Unsupported Node test lane: ${requestedLane}`);
        }
        if (!uniqueLanes.includes(requestedLane)) {
            uniqueLanes.push(requestedLane);
        }
    }

    return uniqueLanes;
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

const main = (): void => {
    process.exitCode = runCommands(
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
    main();
}
