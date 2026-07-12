import path from 'node:path';

import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import { type CommandInvocation } from './run-command.js';
import {
    buildVitestProjectCommand,
    buildVitestProjectsCommand,
    runWorkspaceBuildThenParallelCommands,
} from './run-vitest-lanes.js';
import {
    defaultNodeTestLanes,
    nodeTestLaneDefinitions,
    nodeTestLaneValues,
    type NodeTestLane,
} from './test-lanes.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const kernelNodeTestLanes = ['kernel-fast', 'kernel-heavy'] as const;
const wasm32GuardAddressSpaceReservationBytes = 8 * 1024 ** 3;
const internalWasmKernelNodeTestLanes = new Set<NodeTestLane>(
    kernelNodeTestLanes,
);

let nodeKernelHeavyProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getNodeKernelHeavyProcessMemoryGuard = (): ProcessMemoryGuard => {
    nodeKernelHeavyProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription: 'Node kernel heavy tests',
        // V8 reserves an inaccessible 8 GiB guard mapping for wasm32 linear
        // memory. Linux RLIMIT_AS counts that nonresident mapping, so the guard
        // admits it separately while RLIMIT_DATA retains the allocation limit.
        virtualAddressSpaceAllowanceBytes:
            wasm32GuardAddressSpaceReservationBytes,
    });

    return nodeKernelHeavyProcessMemoryGuard;
};

const isNodeTestLane = (lane: string): lane is NodeTestLane =>
    nodeTestLaneValues.some((supportedLane) => supportedLane === lane);

const expandNodeTestLane = (
    requestedLane: string,
): readonly NodeTestLane[] | undefined => {
    if (requestedLane === 'kernel') {
        return kernelNodeTestLanes;
    }
    if (isNodeTestLane(requestedLane)) {
        return [requestedLane];
    }

    return undefined;
};

export const parseRequestedNodeTestLanes = (
    commandArguments: readonly string[],
): readonly NodeTestLane[] => {
    if (commandArguments.length === 0) {
        return defaultNodeTestLanes;
    }

    const requestedLaneList = commandArguments
        .flatMap((argument) => argument.split(','))
        .map((lane) => lane.trim())
        .filter((lane) => lane.length > 0);
    if (requestedLaneList.length === 0) {
        throw new Error('At least one Node test lane is required.');
    }
    const requestedLanes: NodeTestLane[] = [];
    const requestedLaneSet = new Set<NodeTestLane>();
    for (const requestedLane of requestedLaneList) {
        const expandedLanes = expandNodeTestLane(requestedLane);
        if (expandedLanes === undefined) {
            throw new Error(`Unsupported Node test lane: ${requestedLane}`);
        }
        for (const expandedLane of expandedLanes) {
            if (requestedLaneSet.has(expandedLane)) {
                throw new Error(
                    `Node test lane requested more than once: ${expandedLane}`,
                );
            }
            requestedLaneSet.add(expandedLane);
            requestedLanes.push(expandedLane);
        }
    }

    return requestedLanes;
};

export const buildNodeTestCommands = (
    input: {
        readonly lanes?: readonly NodeTestLane[];
        readonly packageManagerRunner?: PackageManagerRunner;
        readonly runDirectoryPath?: string;
    } = {},
): readonly CommandInvocation[] => {
    const packageManagerRunner =
        input.packageManagerRunner ?? resolvePackageManagerRunner();
    const lanes = input.lanes ?? defaultNodeTestLanes;
    if (new Set(lanes).size !== lanes.length) {
        throw new Error('Node test commands require distinct lanes.');
    }
    const guardCommandWhenHeavyLaneIsIncluded = (
        command: CommandInvocation,
        commandLanes: readonly NodeTestLane[],
    ): CommandInvocation => {
        if (!commandLanes.includes('kernel-heavy')) {
            return command;
        }
        const processMemoryGuard = getNodeKernelHeavyProcessMemoryGuard();
        const guardedCommand = processMemoryGuard.guardCommand(command);

        return input.runDirectoryPath === undefined
            ? guardedCommand
            : processMemoryGuard.addDiagnostics(
                  guardedCommand,
                  path.join(
                      input.runDirectoryPath,
                      'resources',
                      `process-memory-guard-${commandLanes.join('-')}.jsonl`,
                  ),
              );
    };
    const buildCommand = (lane: NodeTestLane): CommandInvocation => {
        const laneDefinition = nodeTestLaneDefinitions[lane];

        return guardCommandWhenHeavyLaneIsIncluded(
            buildVitestProjectCommand({
                commandDescription: laneDefinition.commandDescription,
                packageManagerRunner,
                projectName: laneDefinition.projectName,
                runDirectoryPath: input.runDirectoryPath,
            }),
            [lane],
        );
    };
    const requestedKernelLanes = lanes.filter((lane) =>
        internalWasmKernelNodeTestLanes.has(lane),
    );
    const requestedKernelLaneSet = new Set(requestedKernelLanes);
    const nonKernelCommands = lanes
        .filter((lane) => !internalWasmKernelNodeTestLanes.has(lane))
        .map((lane) => buildCommand(lane));
    if (kernelNodeTestLanes.every((lane) => requestedKernelLaneSet.has(lane))) {
        return [
            ...nonKernelCommands,
            guardCommandWhenHeavyLaneIsIncluded(
                buildVitestProjectsCommand({
                    commandDescription: 'Run kernel Node tests',
                    packageManagerRunner,
                    projectNames: kernelNodeTestLanes.map(
                        (lane) => nodeTestLaneDefinitions[lane].projectName,
                    ),
                    runDirectoryPath: input.runDirectoryPath,
                }),
                requestedKernelLanes,
            ),
        ];
    }

    return [...nonKernelCommands, ...requestedKernelLanes.map(buildCommand)];
};

export const buildNodeTestExtraGateCommands = (input: {
    readonly lanes: readonly NodeTestLane[];
}): readonly CommandInvocation[] => [
    ...(input.lanes.includes('kernel-heavy')
        ? [getNodeKernelHeavyProcessMemoryGuard().buildVerificationCommand()]
        : []),
];

const nodeTestScriptName = (lanes: readonly NodeTestLane[]): string => {
    if (
        lanes.length === kernelNodeTestLanes.length &&
        kernelNodeTestLanes.every((lane, index) => lanes[index] === lane)
    ) {
        return 'test:node:kernel';
    }

    return lanes.length === 1
        ? `test:node:${lanes[0].replace('-', ':')}`
        : 'test:node';
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    let resolvedLanes: readonly NodeTestLane[] | undefined;
    let laneParsingError: Error | undefined;
    try {
        resolvedLanes = parseRequestedNodeTestLanes(rawArguments);
    } catch (error) {
        laneParsingError =
            error instanceof Error
                ? error
                : Object.assign(
                      new Error(
                          'Node test lane parsing threw a non-Error value.',
                      ),
                      { cause: error },
                  );
    }
    const resolveLanes = (): readonly NodeTestLane[] => {
        if (laneParsingError !== undefined) {
            throw laneParsingError;
        }
        if (resolvedLanes === undefined) {
            throw new Error('Node test lane parsing produced no result.');
        }
        return resolvedLanes;
    };
    await runWorkspaceBuildThenParallelCommands({
        buildCommands: (packageManagerRunner, runDirectoryPath) =>
            buildNodeTestCommands({
                lanes: resolveLanes(),
                packageManagerRunner,
                runDirectoryPath,
            }),
        commandLineArguments: rawArguments,
        extraGateCommands: () =>
            buildNodeTestExtraGateCommands({
                lanes: resolveLanes(),
            }),
        lanes: resolvedLanes ?? ['Node tests'],
        scriptName:
            resolvedLanes === undefined
                ? 'test:node'
                : nodeTestScriptName(resolvedLanes),
    });
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
