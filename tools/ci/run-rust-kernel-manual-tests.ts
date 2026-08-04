import { readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
    buildGuardedRustKernelCommand,
    buildGuardedRustEnvironment,
    guardRustKernelCommand,
    runGuardedRustKernelCommands,
    verifyGuardedRustProcessMemoryGuardCommand,
} from './guarded-rust-kernel-runner.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import { parseReleaseNativePrimitiveMeasurementOutput } from './primitive-measurement-evidence.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';
import {
    focusedRustLaneScripts,
    fullProfileEvidenceRustTests,
    measurementRustTests,
    phaseLivenessEvidenceRustTests,
    primitiveMeasurementRustTests,
    theoremEvidenceRustTests,
    verifyFocusedRustLaneSelection,
} from './rust-focused-lane-selection.js';
import { normalizeRustTestFilter } from './rust-kernel-test-arguments.js';

const manualRustKernelTests = {
    'rust-full-profile-evidence': fullProfileEvidenceRustTests,
    'rust-measurements': measurementRustTests,
    'rust-phase-liveness-evidence': phaseLivenessEvidenceRustTests,
    'rust-theorem-evidence': theoremEvidenceRustTests,
} as const;

type ManualRustKernelLane = keyof typeof manualRustKernelTests;

const laneLabels = {
    'rust-full-profile-evidence': 'Rust full-profile evidence',
    'rust-measurements': 'Rust measurements',
    'rust-phase-liveness-evidence': 'Rust phase-liveness evidence',
    'rust-theorem-evidence': 'Rust theorem evidence',
} as const satisfies Record<ManualRustKernelLane, string>;

const laneCargoFeatures = {
    'rust-full-profile-evidence': [],
    'rust-measurements': ['primitive-measurement-evidence'],
    'rust-phase-liveness-evidence': [],
    'rust-theorem-evidence': ['theorem-evidence'],
} as const satisfies Record<ManualRustKernelLane, readonly string[]>;

type ManualRustLaneSelectionVerifier = (input: {
    readonly cargoFeatures?: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly inventoryCommandTransform?: (
        command: CommandInvocation,
    ) => CommandInvocation;
    readonly lane: ManualRustKernelLane;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
    readonly useReleaseProfile?: boolean;
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
    readonly cargoFeatures?: readonly string[];
    readonly configuredTestNames: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly focusedFilter?: string;
    readonly inventoryCommandTransform?: (
        command: CommandInvocation,
    ) => CommandInvocation;
    readonly lane: ManualRustKernelLane;
    readonly runGuardedCommands: (
        testFilters: readonly string[],
    ) => Promise<void>;
    readonly runLog?: ActiveLocalRunLog;
    readonly useReleaseProfile?: boolean;
    readonly verifyLaneSelection?: ManualRustLaneSelectionVerifier;
}): Promise<void> => {
    const testFilters = resolveManualRustKernelTestFilters({
        configuredTestNames: input.configuredTestNames,
        ...(input.focusedFilter === undefined
            ? {}
            : { focusedFilter: input.focusedFilter }),
        lane: input.lane,
    });

    if (input.focusedFilter === undefined) {
        const verifyLaneSelection =
            input.verifyLaneSelection ?? verifyFocusedRustLaneSelection;
        for (const testFilter of testFilters) {
            await verifyLaneSelection({
                ...(input.cargoFeatures === undefined
                    ? {}
                    : { cargoFeatures: input.cargoFeatures }),
                ...(input.environment === undefined
                    ? {}
                    : { environment: input.environment }),
                ...(input.inventoryCommandTransform === undefined
                    ? {}
                    : {
                          inventoryCommandTransform:
                              input.inventoryCommandTransform,
                      }),
                lane: input.lane,
                ...(input.runLog === undefined ? {} : { runLog: input.runLog }),
                testFilter,
                ...(input.useReleaseProfile === undefined
                    ? {}
                    : { useReleaseProfile: input.useReleaseProfile }),
            });
        }
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
            'The guarded manual Rust runner requires lane rust-full-profile-evidence, rust-measurements, rust-phase-liveness-evidence, or rust-theorem-evidence.',
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
            const processMemoryGuardVerificationExitCode =
                await runCommandsInSeries(
                    [verifyGuardedRustProcessMemoryGuardCommand()],
                    { outputMode: 'inherit', runLog },
                );
            if (processMemoryGuardVerificationExitCode !== 0) {
                process.exitCode = processMemoryGuardVerificationExitCode;
                return;
            }
            let inventoryCommandOrdinal = 0;
            const inventoryCommandTransform = (
                command: CommandInvocation,
            ): CommandInvocation => {
                inventoryCommandOrdinal += 1;
                return guardRustKernelCommand(
                    command,
                    undefined,
                    path.join(
                        runLog.runDirectoryPath,
                        'resources',
                        `process-memory-guard-rust-inventory-${String(inventoryCommandOrdinal).padStart(2, '0')}.jsonl`,
                    ),
                );
            };
            await preflightAndRunManualRustKernelLane({
                cargoFeatures: laneCargoFeatures[parsed.lane],
                configuredTestNames: manualRustKernelTests[parsed.lane],
                environment,
                ...(parsed.focusedFilter === undefined
                    ? {}
                    : { focusedFilter: parsed.focusedFilter }),
                inventoryCommandTransform,
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
                                cargoFeatures: laneCargoFeatures[parsed.lane],
                                useReleaseProfile:
                                    parsed.lane === 'rust-measurements',
                            },
                        ),
                        expectedTestFilter: testFilter,
                    }));
                    await runGuardedRustKernelCommands({
                        commands,
                        laneLabel: `${label}${
                            parsed.focusedFilter === undefined ? '' : ' focused'
                        }`,
                        processMemoryGuardAlreadyVerified: true,
                        runLog,
                    });
                },
                runLog,
                useReleaseProfile: parsed.lane === 'rust-measurements',
            });
            if (parsed.lane === 'rust-measurements') {
                const focusedFilter = parsed.focusedFilter;
                const expectedFocusedCaseIdentifiers =
                    focusedFilter === undefined
                        ? undefined
                        : primitiveMeasurementRustTests
                              .map((testName, testIndex) => ({
                                  caseIdentifier: testIndex + 1,
                                  testName,
                              }))
                              .filter(({ testName }) =>
                                  testName.includes(focusedFilter),
                              )
                              .map(({ caseIdentifier }) => caseIdentifier);
                const evidence = parseReleaseNativePrimitiveMeasurementOutput(
                    await readFile(
                        path.join(runLog.runDirectoryPath, 'output.log'),
                        'utf8',
                    ),
                    parsed.focusedFilter === undefined,
                    expectedFocusedCaseIdentifiers,
                );
                const attachmentDirectoryPath = path.join(
                    runLog.runDirectoryPath,
                    'attachments',
                    'primitive-measurements',
                );
                await mkdir(attachmentDirectoryPath, { recursive: true });
                const attachmentFilePath = path.join(
                    attachmentDirectoryPath,
                    parsed.focusedFilter === undefined
                        ? 'release-native-primitive-measurements.json'
                        : expectedFocusedCaseIdentifiers?.length === 1
                          ? 'release-native-focused-primitive-measurement.json'
                          : 'release-native-focused-primitive-measurements.json',
                );
                await writeFile(
                    attachmentFilePath,
                    `${JSON.stringify(evidence, undefined, 2)}\n`,
                    'utf8',
                );
                runLog.writeEvent({
                    details: {
                        attachmentFilePath,
                        caseIdentifiers: evidence.primitiveCases.map(
                            (record) => record.caseIdentifier,
                        ),
                    },
                    eventType:
                        'release-native-primitive-measurement-evidence-written',
                });
            }
        },
    );
};

if (import.meta.main) {
    void runRustKernelManualTests();
}
