import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    createPackageManagerCommand,
    type CommandInvocation,
} from './run-command.js';
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
const internalWasmKernelNodeTestLanes = new Set<NodeTestLane>(
    kernelNodeTestLanes,
);

let nodeKernelHeavyProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getNodeKernelHeavyProcessMemoryGuard = (): ProcessMemoryGuard => {
    nodeKernelHeavyProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription: 'Node kernel heavy tests',
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
    for (const requestedLane of requestedLaneList) {
        const expandedLanes = expandNodeTestLane(requestedLane);
        if (expandedLanes === undefined) {
            throw new Error(`Unsupported Node test lane: ${requestedLane}`);
        }
        requestedLanes.push(...expandedLanes);
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
    const guardCommandWhenHeavyLaneIsIncluded = (
        command: CommandInvocation,
        commandLanes: readonly NodeTestLane[],
    ): CommandInvocation =>
        commandLanes.includes('kernel-heavy')
            ? getNodeKernelHeavyProcessMemoryGuard().guardCommand(command)
            : command;
    const buildCommand = (lane: NodeTestLane): CommandInvocation => {
        const laneDefinition = nodeTestLaneDefinitions[lane];

        return guardCommandWhenHeavyLaneIsIncluded(
            buildVitestProjectCommand({
                commandDescription: laneDefinition.commandDescription,
                packageManagerRunner,
                projectName: laneDefinition.projectName,
            }),
            [lane],
        );
    };
    const requestedKernelLanes = lanes.filter((lane) =>
        internalWasmKernelNodeTestLanes.has(lane),
    );
    const nonKernelCommands = lanes
        .filter((lane) => !internalWasmKernelNodeTestLanes.has(lane))
        .map((lane) => buildCommand(lane));
    if (requestedKernelLanes.length === kernelNodeTestLanes.length) {
        return [
            ...nonKernelCommands,
            guardCommandWhenHeavyLaneIsIncluded(
                buildVitestProjectsCommand({
                    commandDescription: 'Run kernel Node tests',
                    packageManagerRunner,
                    projectNames: kernelNodeTestLanes.map(
                        (lane) => nodeTestLaneDefinitions[lane].projectName,
                    ),
                }),
                requestedKernelLanes,
            ),
        ];
    }

    return [...nonKernelCommands, ...requestedKernelLanes.map(buildCommand)];
};

const nodeTestLanesNeedInternalWasmKernel = (
    lanes: readonly NodeTestLane[],
): boolean => lanes.some((lane) => internalWasmKernelNodeTestLanes.has(lane));

const buildInternalWasmKernelCommand = (
    packageManagerRunner: PackageManagerRunner,
): CommandInvocation =>
    createPackageManagerCommand(
        'Build internal WASM kernel artifact',
        ['--filter', '@sealed-lattice/wasm', 'run', 'build:wasm'],
        {
            logFileSlug: 'build-internal-wasm-kernel',
            packageManagerRunner,
        },
    );

export const buildNodeTestExtraGateCommands = (input: {
    readonly lanes: readonly NodeTestLane[];
    readonly packageManagerRunner: PackageManagerRunner;
}): readonly CommandInvocation[] => [
    ...(input.lanes.includes('kernel-heavy')
        ? [getNodeKernelHeavyProcessMemoryGuard().buildVerificationCommand()]
        : []),
    ...(nodeTestLanesNeedInternalWasmKernel(input.lanes)
        ? [buildInternalWasmKernelCommand(input.packageManagerRunner)]
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
    const lanes = parseRequestedNodeTestLanes(rawArguments);
    await runWorkspaceBuildThenParallelCommands({
        buildCommands: (packageManagerRunner) =>
            buildNodeTestCommands({ lanes, packageManagerRunner }),
        commandLineArguments: rawArguments,
        extraGateCommands: (packageManagerRunner) =>
            buildNodeTestExtraGateCommands({
                lanes,
                packageManagerRunner,
            }),
        lanes,
        scriptName: nodeTestScriptName(lanes),
    });
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
