import path from 'node:path';

import {
    buildGuardedRustKernelCommand,
    buildGuardedRustEnvironment,
    runGuardedRustKernelCommands,
} from './guarded-rust-kernel-runner.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    focusedRustLaneScripts,
    fullProfileEvidenceRustTests,
    measurementRustTests,
    phaseLivenessEvidenceRustTests,
    verifyFocusedRustLaneSelection,
} from './rust-focused-lane-selection.js';
import { normalizeRustTestFilter } from './rust-kernel-test-arguments.js';

const manualRustKernelTests = {
    'rust-full-profile-evidence': fullProfileEvidenceRustTests,
    'rust-measurements': measurementRustTests,
    'rust-phase-liveness-evidence': phaseLivenessEvidenceRustTests,
} as const;

type ManualRustKernelLane = keyof typeof manualRustKernelTests;

const laneLabels = {
    'rust-full-profile-evidence': 'Rust full-profile evidence',
    'rust-measurements': 'Rust measurements',
    'rust-phase-liveness-evidence': 'Rust phase-liveness evidence',
} as const satisfies Record<ManualRustKernelLane, string>;

type ManualRustLaneSelectionVerifier = (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly lane: ManualRustKernelLane;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
}) => Promise<void>;

const resolveManualRustKernelTestFilters = (input: {
    readonly configuredTestNames: readonly string[];
    readonly focusedFilter?: string;
    readonly lane: ManualRustKernelLane;
}): readonly string[] => {
    const requestedScript = focusedRustLaneScripts[input.lane];
    if (input.configuredTestNames.length === 0) {
        throw new Error(`${requestedScript} has no configured Rust tests.`);
    }
    const focusedFilter = input.focusedFilter;
    if (focusedFilter === undefined) {
        return input.configuredTestNames;
    }
    if (focusedFilter === '') {
        throw new Error(`${requestedScript} requires a non-empty filter.`);
    }
    if (
        !input.configuredTestNames.some((testName) =>
            testName.includes(focusedFilter),
        )
    ) {
        throw new Error(
            `${requestedScript} filter ${focusedFilter} selects zero configured Rust tests.`,
        );
    }

    return [focusedFilter];
};

export const preflightAndRunManualRustKernelLane = async (input: {
    readonly configuredTestNames: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly focusedFilter?: string;
    readonly lane: ManualRustKernelLane;
    readonly runGuardedCommands: (
        testFilters: readonly string[],
    ) => Promise<void>;
    readonly runLog?: ActiveLocalRunLog;
    readonly verifyLaneSelection?: ManualRustLaneSelectionVerifier;
}): Promise<void> => {
    const testFilters = resolveManualRustKernelTestFilters({
        configuredTestNames: input.configuredTestNames,
        ...(input.focusedFilter === undefined
            ? {}
            : { focusedFilter: input.focusedFilter }),
        lane: input.lane,
    });

    const verifyLaneSelection =
        input.verifyLaneSelection ?? verifyFocusedRustLaneSelection;
    for (const testFilter of testFilters) {
        await verifyLaneSelection({
            ...(input.environment === undefined
                ? {}
                : { environment: input.environment }),
            lane: input.lane,
            ...(input.runLog === undefined ? {} : { runLog: input.runLog }),
            testFilter,
        });
    }

    await input.runGuardedCommands(testFilters);
};

const parseArguments = (
    commandArguments: readonly string[],
): {
    readonly focusedFilter?: string;
    readonly lane: ManualRustKernelLane;
} => {
    const [rawLane, ...remainingArguments] = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (!(rawLane !== undefined && rawLane in manualRustKernelTests)) {
        throw new Error(
            'The guarded manual Rust runner requires lane rust-full-profile-evidence, rust-measurements, or rust-phase-liveness-evidence.',
        );
    }
    const lane = rawLane as ManualRustKernelLane;
    const positionalArguments: string[] = [];
    for (const argument of remainingArguments) {
        if (argument.startsWith('-')) {
            throw new Error(`Unknown argument ${argument}.`);
        }
        positionalArguments.push(argument);
    }
    if (positionalArguments.length > 1) {
        throw new Error(
            `${focusedRustLaneScripts[lane]} accepts one optional test or module filter.`,
        );
    }
    const focusedFilter =
        positionalArguments.length === 0
            ? undefined
            : normalizeRustTestFilter(positionalArguments[0] ?? '');
    if (focusedFilter === '') {
        throw new Error(
            `${focusedRustLaneScripts[lane]} requires a non-empty filter.`,
        );
    }

    return { focusedFilter, lane };
};

export const runRustKernelManualTests = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const requestedLane = rawArguments.find((argument) => argument !== '--');
    const diagnosticLane =
        requestedLane !== undefined && requestedLane in manualRustKernelTests
            ? (requestedLane as ManualRustKernelLane)
            : undefined;
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: [
                diagnosticLane === undefined
                    ? 'Guarded manual Rust kernel'
                    : laneLabels[diagnosticLane],
            ],
            scriptName:
                diagnosticLane === undefined
                    ? 'test:rust:kernel:manual'
                    : focusedRustLaneScripts[diagnosticLane],
        },
        async (runLog) => {
            const parsed = parseArguments(rawArguments);
            const label = laneLabels[parsed.lane];
            const targetDirectoryPath = path.resolve(
                process.cwd(),
                'target',
                `${parsed.lane}-${parsed.focusedFilter === undefined ? 'accelerated' : 'focused'}`,
            );
            const environment = buildGuardedRustEnvironment({
                targetDirectoryPath,
            });
            await preflightAndRunManualRustKernelLane({
                configuredTestNames: manualRustKernelTests[parsed.lane],
                environment,
                ...(parsed.focusedFilter === undefined
                    ? {}
                    : { focusedFilter: parsed.focusedFilter }),
                lane: parsed.lane,
                runGuardedCommands: async (testFilters) => {
                    const commands = testFilters.map((testFilter) => ({
                        builtCommand: buildGuardedRustKernelCommand(
                            testFilter,
                            {
                                logFileSlug: `cargo-test-${parsed.lane}`,
                                progressLabel: parsed.lane,
                                runName: label,
                                targetDirectoryPath,
                            },
                        ),
                        expectedTestFilter: testFilter,
                    }));
                    await runGuardedRustKernelCommands({
                        commands,
                        laneLabel: `${label}${
                            parsed.focusedFilter === undefined ? '' : ' focused'
                        }`,
                        runLog,
                    });
                },
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runRustKernelManualTests();
}
