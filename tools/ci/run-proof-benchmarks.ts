import { pathToFileURL } from 'node:url';

import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommands,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';

type ProofBenchmarkLane = 'desktop' | 'mobile-throttled' | 'node';

const defaultProofBenchmarkLanes: readonly ProofBenchmarkLane[] = [
    'node',
    'desktop',
];

const proofBenchmarkProjectByLane = {
    desktop: 'browser-desktop-proof-benchmark',
    'mobile-throttled': 'browser-mobile-throttled-proof-benchmark',
    node: 'node-proof-benchmark',
} as const;

const mobileThrottleEnvironmentVariableName =
    'VITE_SEALED_LATTICE_ENABLE_THROTTLED_MOBILE_BENCHMARK';

const fullPowerBenchmarkEnvironment = (): NodeJS.ProcessEnv => {
    const environment = { ...process.env };
    delete environment[mobileThrottleEnvironmentVariableName];

    return environment;
};

export const parseRequestedProofBenchmarkLanes = (
    commandLineArguments: readonly string[],
): readonly ProofBenchmarkLane[] => {
    const lanes: ProofBenchmarkLane[] = [];

    for (let argumentIndex = 0; argumentIndex < commandLineArguments.length; ) {
        const argument = commandLineArguments[argumentIndex];
        if (argument !== '--only') {
            throw new Error(`Unknown proof benchmark argument: ${argument}`);
        }

        const lane = commandLineArguments[argumentIndex + 1];
        if (
            lane !== 'desktop' &&
            lane !== 'mobile-throttled' &&
            lane !== 'node'
        ) {
            throw new Error(`Unsupported proof benchmark lane: ${lane}`);
        }

        lanes.push(lane);
        argumentIndex += 2;
    }

    return lanes.length === 0 ? defaultProofBenchmarkLanes : lanes;
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
        env: NodeJS.ProcessEnv = process.env,
    ): CommandInvocation =>
        createPackageManagerCommand(description, commandArguments, {
            env,
            packageManagerRunner,
        });

    return [
        buildCommand('Build workspace packages', ['run', 'build']),
        ...lanes.map((lane) =>
            buildCommand(
                lane === 'mobile-throttled'
                    ? 'Run manually throttled mobile Chromium proof benchmark'
                    : `Run ${lane} proof benchmark`,
                [
                    'exec',
                    'vitest',
                    '--project',
                    proofBenchmarkProjectByLane[lane],
                    '--run',
                ],
                lane === 'mobile-throttled'
                    ? {
                          ...process.env,
                          [mobileThrottleEnvironmentVariableName]: '1',
                      }
                    : fullPowerBenchmarkEnvironment(),
            ),
        ),
    ];
};

const main = (): void => {
    process.exitCode = runCommands(
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
    main();
}
