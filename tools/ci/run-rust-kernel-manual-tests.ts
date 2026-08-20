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
    proofEvidenceRustTests,
    resolvePrimitiveMeasurementRustTestCases,
    theoremEvidenceRustTests,
    vssPrerequisiteProofEvidenceRustTest,
    vssFusedRadix51ProjectionOwnerRustFilter,
    verifyFocusedRustLaneSelection,
} from './rust-focused-lane-selection.js';
import { normalizeRustTestFilter } from './rust-kernel-test-arguments.js';

const manualRustKernelTests = {
    'rust-full-profile-evidence': fullProfileEvidenceRustTests,
    'rust-measurements': measurementRustTests,
    'rust-phase-liveness-evidence': phaseLivenessEvidenceRustTests,
    'rust-proof-evidence': proofEvidenceRustTests,
    'rust-theorem-evidence': theoremEvidenceRustTests,
} as const;

export type ManualRustKernelLane = keyof typeof manualRustKernelTests;

export const rustProofEvidenceCheckpointResumeEnvironmentVariable =
    'SEALED_LATTICE_RUST_PROOF_EVIDENCE_CHECKPOINT_RESUME';
export const rustProofEvidenceStopAfterQuotientConstraintCheckpointEnvironmentVariable =
    'SEALED_LATTICE_RUST_PROOF_EVIDENCE_STOP_AFTER_QUOTIENT_CONSTRAINT_CHECKPOINT';
export const stopAfterQuotientConstraintCheckpointArgument =
    '--stop-after-quotient-constraint-checkpoint';
export const controlledQuotientConstraintCheckpointStopOutputPrefix =
    'sealed-lattice-controlled-quotient-constraint-checkpoint-stop ';

export type ControlledQuotientConstraintCheckpointStopRecord = {
    readonly authenticatedAfterWrite: true;
    readonly cancellationCompleted: true;
    readonly checkpointByteLength: number;
    readonly completedConstraintCount: number;
    readonly elapsedMilliseconds: number;
    readonly familyIdentifier: 'selected-vss-prerequisite-proof';
    readonly maximumDeclaredExternalMemoryByteLength: number;
    readonly resumedFromAuthenticatedBoundary: number | null;
    readonly standardCheckpointCount: number;
};

const laneLabels = {
    'rust-full-profile-evidence': 'Rust full-profile evidence',
    'rust-measurements': 'Rust measurements',
    'rust-phase-liveness-evidence': 'Rust phase-liveness evidence',
    'rust-proof-evidence': 'Rust proof evidence',
    'rust-theorem-evidence': 'Rust theorem evidence',
} as const satisfies Record<ManualRustKernelLane, string>;

const laneCargoFeatures = {
    'rust-full-profile-evidence': [],
    'rust-measurements': ['primitive-measurement-evidence'],
    'rust-phase-liveness-evidence': [],
    'rust-proof-evidence': [],
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
    if (
        new Set(input.configuredTestNames).size !==
        input.configuredTestNames.length
    ) {
        throw new Error(
            `${requestedScript} has duplicate configured Rust tests.`,
        );
    }
    const focusedFilter = input.focusedFilter;
    if (focusedFilter === undefined) {
        return input.configuredTestNames;
    }
    if (focusedFilter === '') {
        throw new Error(`${requestedScript} requires a non-empty filter.`);
    }
    if (
        input.lane === 'rust-measurements' &&
        focusedFilter === vssFusedRadix51ProjectionOwnerRustFilter
    ) {
        const selectedTests = resolvePrimitiveMeasurementRustTestCases(
            focusedFilter,
        ).map(({ testName }) => testName);
        if (
            selectedTests.length === 0 ||
            selectedTests.some(
                (testName) => !input.configuredTestNames.includes(testName),
            )
        ) {
            throw new Error(
                `${requestedScript} projection-owner filter is absent from the exact registry.`,
            );
        }
        return selectedTests;
    }
    const selectedTests = input.configuredTestNames.filter((testName) =>
        testName.includes(focusedFilter),
    );
    if (selectedTests.length === 0) {
        throw new Error(
            `${requestedScript} filter ${focusedFilter} selects zero configured Rust tests.`,
        );
    }

    return selectedTests;
};

export const buildManualRustKernelEnvironment = (input: {
    readonly baseEnvironment?: NodeJS.ProcessEnv;
    readonly lane: ManualRustKernelLane;
    readonly stopAfterQuotientConstraintCheckpoint?: boolean;
    readonly targetDirectoryPath: string;
}): NodeJS.ProcessEnv => {
    const baseEnvironment = { ...(input.baseEnvironment ?? process.env) };
    delete baseEnvironment[
        rustProofEvidenceCheckpointResumeEnvironmentVariable
    ];
    delete baseEnvironment[
        rustProofEvidenceStopAfterQuotientConstraintCheckpointEnvironmentVariable
    ];
    if (
        input.stopAfterQuotientConstraintCheckpoint === true &&
        input.lane !== 'rust-proof-evidence'
    ) {
        throw new Error(
            'Only the Rust proof-evidence lane may stop after a quotient-constraint checkpoint.',
        );
    }
    if (input.lane === 'rust-proof-evidence') {
        baseEnvironment[rustProofEvidenceCheckpointResumeEnvironmentVariable] =
            '1';
        baseEnvironment.SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE = '1';
        if (input.stopAfterQuotientConstraintCheckpoint === true) {
            baseEnvironment[
                rustProofEvidenceStopAfterQuotientConstraintCheckpointEnvironmentVariable
            ] = '1';
        }
    }

    return buildGuardedRustEnvironment({
        baseEnvironment,
        targetDirectoryPath: input.targetDirectoryPath,
    });
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

export const parseManualRustKernelArguments = (
    commandArguments: readonly string[],
): {
    readonly focusedFilter?: string;
    readonly lane: ManualRustKernelLane;
    readonly stopAfterQuotientConstraintCheckpoint: boolean;
} => {
    const [rawLane, ...remainingArguments] = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (!(rawLane !== undefined && rawLane in manualRustKernelTests)) {
        throw new Error(
            'The guarded manual Rust runner requires lane rust-full-profile-evidence, rust-measurements, rust-phase-liveness-evidence, rust-proof-evidence, or rust-theorem-evidence.',
        );
    }
    const lane = rawLane as ManualRustKernelLane;
    const positionalArguments: string[] = [];
    let stopAfterQuotientConstraintCheckpoint = false;
    for (const argument of remainingArguments) {
        if (argument === stopAfterQuotientConstraintCheckpointArgument) {
            if (stopAfterQuotientConstraintCheckpoint) {
                throw new Error(
                    `${stopAfterQuotientConstraintCheckpointArgument} may appear only once.`,
                );
            }
            stopAfterQuotientConstraintCheckpoint = true;
            continue;
        }
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

    const selectedTestFilters = resolveManualRustKernelTestFilters({
        configuredTestNames: manualRustKernelTests[lane],
        ...(focusedFilter === undefined ? {} : { focusedFilter }),
        lane,
    });
    if (
        stopAfterQuotientConstraintCheckpoint &&
        (lane !== 'rust-proof-evidence' ||
            selectedTestFilters.length !== 1 ||
            selectedTestFilters[0] !== vssPrerequisiteProofEvidenceRustTest)
    ) {
        throw new Error(
            `${stopAfterQuotientConstraintCheckpointArgument} requires the focused production VSS prerequisite proof.`,
        );
    }

    return {
        focusedFilter,
        lane,
        stopAfterQuotientConstraintCheckpoint,
    };
};

const requireNonnegativeSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new Error(
            `Controlled quotient-constraint checkpoint stop field ${fieldName} must be a nonnegative safe integer.`,
        );
    }
    return value;
};

export const parseControlledQuotientConstraintCheckpointStopOutput = (
    output: string,
): ControlledQuotientConstraintCheckpointStopRecord => {
    const matchingLines = output
        .split(/\r?\n/u)
        .filter((line) =>
            line.includes(
                controlledQuotientConstraintCheckpointStopOutputPrefix,
            ),
        );
    if (matchingLines.length !== 1) {
        throw new Error(
            'A controlled quotient-constraint checkpoint stop must emit exactly one terminal record.',
        );
    }
    const matchingLine = matchingLines[0] ?? '';
    const recordStart = matchingLine.indexOf(
        controlledQuotientConstraintCheckpointStopOutputPrefix,
    );
    const encodedRecord = matchingLine
        .slice(
            recordStart +
                controlledQuotientConstraintCheckpointStopOutputPrefix.length,
        )
        .trim();
    let decodedRecord: unknown;
    try {
        decodedRecord = JSON.parse(encodedRecord);
    } catch {
        throw new Error(
            'The controlled quotient-constraint checkpoint stop record is not JSON.',
        );
    }
    if (
        decodedRecord === null ||
        typeof decodedRecord !== 'object' ||
        Array.isArray(decodedRecord)
    ) {
        throw new Error(
            'The controlled quotient-constraint checkpoint stop record must be an object.',
        );
    }
    const record = decodedRecord as Record<string, unknown>;
    const exactFieldNames = [
        'authenticatedAfterWrite',
        'cancellationCompleted',
        'checkpointByteLength',
        'completedConstraintCount',
        'elapsedMilliseconds',
        'familyIdentifier',
        'maximumDeclaredExternalMemoryByteLength',
        'resumedFromAuthenticatedBoundary',
        'standardCheckpointCount',
    ];
    if (
        Object.keys(record).sort().join('\n') !==
        [...exactFieldNames].sort().join('\n')
    ) {
        throw new Error(
            'The controlled quotient-constraint checkpoint stop record has the wrong fields.',
        );
    }
    if (
        record.authenticatedAfterWrite !== true ||
        record.cancellationCompleted !== true ||
        record.familyIdentifier !== 'selected-vss-prerequisite-proof'
    ) {
        throw new Error(
            'The controlled quotient-constraint checkpoint stop record has the wrong terminal classification.',
        );
    }
    const completedConstraintCount = requireNonnegativeSafeInteger(
        record.completedConstraintCount,
        'completedConstraintCount',
    );
    const checkpointByteLength = requireNonnegativeSafeInteger(
        record.checkpointByteLength,
        'checkpointByteLength',
    );
    if (completedConstraintCount === 0 || checkpointByteLength === 0) {
        throw new Error(
            'The controlled quotient-constraint checkpoint stop record must identify a nonempty completed checkpoint.',
        );
    }
    const resumedFromAuthenticatedBoundary =
        record.resumedFromAuthenticatedBoundary === null
            ? null
            : requireNonnegativeSafeInteger(
                  record.resumedFromAuthenticatedBoundary,
                  'resumedFromAuthenticatedBoundary',
              );
    return {
        authenticatedAfterWrite: true,
        cancellationCompleted: true,
        checkpointByteLength,
        completedConstraintCount,
        elapsedMilliseconds: requireNonnegativeSafeInteger(
            record.elapsedMilliseconds,
            'elapsedMilliseconds',
        ),
        familyIdentifier: 'selected-vss-prerequisite-proof',
        maximumDeclaredExternalMemoryByteLength: requireNonnegativeSafeInteger(
            record.maximumDeclaredExternalMemoryByteLength,
            'maximumDeclaredExternalMemoryByteLength',
        ),
        resumedFromAuthenticatedBoundary,
        standardCheckpointCount: requireNonnegativeSafeInteger(
            record.standardCheckpointCount,
            'standardCheckpointCount',
        ),
    };
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
            const parsed = parseManualRustKernelArguments(rawArguments);
            const label = laneLabels[parsed.lane];
            const targetDirectoryPath = path.resolve(
                process.cwd(),
                'target',
                `${parsed.lane}-${parsed.focusedFilter === undefined ? 'accelerated' : 'focused'}`,
            );
            const environment = buildManualRustKernelEnvironment({
                lane: parsed.lane,
                stopAfterQuotientConstraintCheckpoint:
                    parsed.stopAfterQuotientConstraintCheckpoint,
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
                                baseEnvironment: environment,
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
            if (parsed.stopAfterQuotientConstraintCheckpoint) {
                const controlledStopRecord =
                    parseControlledQuotientConstraintCheckpointStopOutput(
                        await readFile(
                            path.join(runLog.runDirectoryPath, 'output.log'),
                            'utf8',
                        ),
                    );
                const attachmentDirectoryPath = path.join(
                    runLog.runDirectoryPath,
                    'attachments',
                    'quotient-constraint-checkpoints',
                );
                await mkdir(attachmentDirectoryPath, { recursive: true });
                const attachmentFilePath = path.join(
                    attachmentDirectoryPath,
                    'controlled-stop.json',
                );
                await writeFile(
                    attachmentFilePath,
                    `${JSON.stringify(controlledStopRecord, undefined, 2)}\n`,
                    'utf8',
                );
                runLog.writeEvent({
                    details: {
                        attachmentFilePath,
                        ...controlledStopRecord,
                    },
                    eventType:
                        'controlled-quotient-constraint-checkpoint-stop-completed',
                });
            }
            if (parsed.lane === 'rust-measurements') {
                const focusedFilter = parsed.focusedFilter;
                const expectedFocusedCaseIdentifiers =
                    focusedFilter === undefined
                        ? undefined
                        : resolvePrimitiveMeasurementRustTestCases(
                              focusedFilter,
                          ).map(({ caseIdentifier }) => caseIdentifier);
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
