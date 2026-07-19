import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { normalizeTranscriptCoreKernelBytesForHash } from '../../packages/wasm/src/transcript-core-bridge.js';
import {
    parseDesktopBrowserProofMeasurementRecord,
    type DesktopBrowserProofExecutionKind,
    type DesktopBrowserProofMeasurementRecord,
} from '../../tests/support/desktop-browser-proof-measurement.js';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { createProcessMemoryGuard } from './process-memory-guard.js';
import {
    createPackageManagerCommand,
    runCommandsInSeries,
} from './run-command.js';

const laneLabel = 'Desktop Chromium proof evidence';
const testProjectLabel = 'desktop-browser-proof-evidence';
const browserEvidenceTestFile =
    'packages/wasm/tests/browser/selected-proof-runtime-evidence.manual.browser.test.ts';
const processMemoryGuardDiagnosticFileName =
    'process-memory-guard-desktop-browser-proof-evidence.jsonl';
const processedWasmKernelPath = path.resolve(
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const publicSdkWasmKernelPath = path.resolve(
    'packages',
    'sdk',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const expectedWasmSha256EnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_PROOF_EXPECTED_WASM_SHA256_HEX';

const absoluteResourceBounds = Object.freeze({
    copiedBufferByteLength: 8_388_608,
    externalScratchByteLength: 1_073_741_824,
    proofByteLength: 268_435_456,
    transportStreamByteLength: 4_294_967_291,
    wasmLinearMemoryByteLength: 671_088_640,
});

const softPlanningTargets = Object.freeze({
    browserProcessIncreaseByteLength: 671_088_640,
    copiedBufferByteLength: 1_572_864,
    externalScratchByteLength: 268_435_456,
    proofByteLength: 5_242_880,
    wasmLinearMemoryByteLength: 402_653_184,
});

const requiredCaseExecutionKinds = Object.freeze({
    'aggregate-threshold-share-generation': 'fresh-generation',
    'aggregate-threshold-share-verification': 'verification',
    'ballot-validity-generation': 'fresh-generation',
    'ballot-validity-verification': 'verification',
    'evaluator-key-aggregate-generation': 'fresh-generation',
    'evaluator-key-aggregate-verification': 'verification',
    'evaluator-replay-maximum-stream': 'replay',
    'galois-key-share-batch-generation-fresh': 'fresh-generation',
    'galois-key-share-batch-generation-resumed': 'resumed-generation',
    'galois-key-share-batch-verification': 'verification',
    'vss-share-linkage-generation-fresh': 'fresh-generation',
    'vss-share-linkage-generation-resumed': 'resumed-generation',
    'vss-share-linkage-verification': 'verification',
} satisfies Readonly<Record<string, DesktopBrowserProofExecutionKind>>);
const requiredCaseIdentifiers = Object.freeze(
    Object.keys(requiredCaseExecutionKinds),
);

type JsonRecord = Readonly<Record<string, unknown>>;

const requirePositiveMeasuredBytes = (
    value: number,
    fieldName: string,
    caseIdentifier: string,
): void => {
    if (value === 0) {
        throw new Error(
            `Desktop Chromium proof evidence reported zero ${fieldName} for ${caseIdentifier}.`,
        );
    }
};

const requireAtMostAbsoluteBound = (
    value: number,
    bound: number,
    fieldName: string,
    caseIdentifier: string,
): void => {
    if (value > bound) {
        throw new Error(
            `Desktop Chromium proof evidence exceeded the absolute ${fieldName} bound for ${caseIdentifier}: ${String(value)} > ${String(bound)} bytes.`,
        );
    }
};

const validateMeasurementResourceBounds = (
    measurement: DesktopBrowserProofMeasurementRecord,
): void => {
    requirePositiveMeasuredBytes(
        measurement.canonicalInputByteLength,
        'canonical input',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.copiedBufferPeakByteLength,
        absoluteResourceBounds.copiedBufferByteLength,
        'single copied-buffer',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.externalScratchPeakByteLength,
        absoluteResourceBounds.externalScratchByteLength,
        'external-scratch peak',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.wasmLinearMemoryPeakByteLength,
        absoluteResourceBounds.wasmLinearMemoryByteLength,
        'WebAssembly linear-memory peak',
        measurement.caseIdentifier,
    );

    if (
        measurement.executionKind === 'fresh-generation' ||
        measurement.executionKind === 'resumed-generation'
    ) {
        requirePositiveMeasuredBytes(
            measurement.canonicalOutputByteLength,
            'canonical proof output',
            measurement.caseIdentifier,
        );
        requireAtMostAbsoluteBound(
            measurement.canonicalOutputByteLength,
            absoluteResourceBounds.proofByteLength,
            'proof-stream',
            measurement.caseIdentifier,
        );
        return;
    }
    if (measurement.executionKind === 'verification') {
        if (measurement.canonicalOutputByteLength !== 0) {
            throw new Error(
                `Desktop Chromium proof verification reported a canonical output artifact for ${measurement.caseIdentifier}.`,
            );
        }
        requireAtMostAbsoluteBound(
            measurement.canonicalInputByteLength,
            absoluteResourceBounds.proofByteLength,
            'proof-stream',
            measurement.caseIdentifier,
        );
        return;
    }
    requirePositiveMeasuredBytes(
        measurement.canonicalOutputByteLength,
        'canonical replay output',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.canonicalInputByteLength,
        absoluteResourceBounds.transportStreamByteLength,
        'transport-stream',
        measurement.caseIdentifier,
    );
    requireAtMostAbsoluteBound(
        measurement.canonicalOutputByteLength,
        absoluteResourceBounds.transportStreamByteLength,
        'transport-stream',
        measurement.caseIdentifier,
    );
};

const readJsonLines = async (
    filePath: string,
): Promise<readonly JsonRecord[]> => {
    const text = await readFile(filePath, 'utf8');
    return text
        .split(/\r?\n/u)
        .filter((line) => line.length > 0)
        .map((line, lineIndex) => {
            const value = JSON.parse(line) as unknown;
            if (
                typeof value !== 'object' ||
                value === null ||
                Array.isArray(value)
            ) {
                throw new Error(
                    `${filePath} line ${String(lineIndex + 1)} is not a JSON object.`,
                );
            }
            return value as JsonRecord;
        });
};

const optionalSafeInteger = (
    record: JsonRecord,
    fieldName: string,
): number | undefined => {
    const value = record[fieldName];
    return Number.isSafeInteger(value) && Number(value) >= 0
        ? Number(value)
        : undefined;
};

const maximumObservedValue = (
    records: readonly JsonRecord[],
    fieldName: string,
): number | undefined => {
    const observations = records.flatMap((record) => {
        const value = optionalSafeInteger(record, fieldName);
        return value === undefined ? [] : [value];
    });
    return observations.length === 0 ? undefined : Math.max(...observations);
};

const nearestBaselineValue = (
    records: readonly JsonRecord[],
    fieldName: string,
    startedAtUnixMilliseconds: number,
): number | undefined => {
    return records
        .filter(
            (record) =>
                optionalSafeInteger(record, 'recordedAtUnixMilliseconds') !==
                    undefined &&
                Number(record.recordedAtUnixMilliseconds) <=
                    startedAtUnixMilliseconds,
        )
        .sort(
            (left, right) =>
                Number(right.recordedAtUnixMilliseconds) -
                Number(left.recordedAtUnixMilliseconds),
        )
        .map((record) => optionalSafeInteger(record, fieldName))
        .find((value) => value !== undefined);
};

const optionalIncrease = (
    peak: number | undefined,
    baseline: number | undefined,
): number | undefined =>
    peak === undefined || baseline === undefined
        ? undefined
        : Math.max(0, peak - baseline);

const planningVariance = (value: number, target: number) =>
    Object.freeze({
        overageByteLength: Math.max(0, value - target),
        ratio: value / target,
        targetByteLength: target,
        valueByteLength: value,
    });

export const validateDesktopBrowserProofMeasurementEvents = (
    testEvents: readonly JsonRecord[],
    expectedBindings?: Readonly<{
        wasmSha256Hex: string;
    }>,
): readonly DesktopBrowserProofMeasurementRecord[] => {
    const measurementEvents = testEvents.filter(
        (event) => event.event === 'desktop-browser-proof-measurement',
    );
    for (const measurementEvent of measurementEvents) {
        if (measurementEvent.browser !== true) {
            throw new Error(
                'Desktop Chromium proof evidence included a non-browser measurement.',
            );
        }
    }
    const measurements = measurementEvents.map((event) =>
        parseDesktopBrowserProofMeasurementRecord(event),
    );
    const measurementsByCaseIdentifier = new Map<
        string,
        Map<number, DesktopBrowserProofMeasurementRecord>
    >();
    for (const measurement of measurements) {
        const expectedExecutionKind = (
            requiredCaseExecutionKinds as Readonly<
                Partial<Record<string, DesktopBrowserProofExecutionKind>>
            >
        )[measurement.caseIdentifier];
        if (expectedExecutionKind === undefined) {
            throw new Error(
                `Desktop Chromium proof evidence reported an unexpected case: ${measurement.caseIdentifier}.`,
            );
        }
        let caseMeasurements = measurementsByCaseIdentifier.get(
            measurement.caseIdentifier,
        );
        if (caseMeasurements === undefined) {
            caseMeasurements = new Map();
            measurementsByCaseIdentifier.set(
                measurement.caseIdentifier,
                caseMeasurements,
            );
        }
        if (caseMeasurements.has(measurement.runOrdinal)) {
            throw new Error(
                `Desktop Chromium proof evidence reported the same run ordinal more than once for ${measurement.caseIdentifier}: ${String(measurement.runOrdinal)}.`,
            );
        }
        if (measurement.executionKind !== expectedExecutionKind) {
            throw new Error(
                `Desktop Chromium proof evidence reported ${measurement.caseIdentifier} as ${measurement.executionKind}, expected ${expectedExecutionKind}.`,
            );
        }
        validateMeasurementResourceBounds(measurement);
        caseMeasurements.set(measurement.runOrdinal, measurement);
    }
    const missingCaseIdentifiers = requiredCaseIdentifiers.filter(
        (caseIdentifier) => !measurementsByCaseIdentifier.has(caseIdentifier),
    );
    if (missingCaseIdentifiers.length > 0) {
        throw new Error(
            `Desktop Chromium proof evidence omitted required cases: ${missingCaseIdentifiers.join(', ')}.`,
        );
    }
    for (const [
        caseIdentifier,
        caseMeasurements,
    ] of measurementsByCaseIdentifier) {
        const orderedRunOrdinals = [...caseMeasurements.keys()].sort(
            (left, right) => left - right,
        );
        if (
            orderedRunOrdinals.some(
                (runOrdinal, runIndex) => runOrdinal !== runIndex + 1,
            )
        ) {
            throw new Error(
                `Desktop Chromium proof-evidence run ordinals must be contiguous from one for ${caseIdentifier}.`,
            );
        }
    }
    const observedSuiteIdentifiers = new Set(
        measurements.map((measurement) => measurement.suiteId),
    );
    const observedWasmHashes = new Set(
        measurements.map((measurement) => measurement.wasmSha256Hex),
    );
    if (observedSuiteIdentifiers.size !== 1 || observedWasmHashes.size !== 1) {
        throw new Error(
            'Desktop Chromium proof evidence did not use one exact suite and one exact processed WebAssembly module.',
        );
    }
    if (
        expectedBindings !== undefined &&
        !observedWasmHashes.has(expectedBindings.wasmSha256Hex)
    ) {
        throw new Error(
            'Desktop Chromium proof evidence did not use the normalized processed WebAssembly module produced by this build.',
        );
    }
    return measurements;
};

const deriveProcessedWasmSha256Hex = async (): Promise<string> => {
    const [producerBytes, publicSdkBytes] = await Promise.all([
        readFile(processedWasmKernelPath),
        readFile(publicSdkWasmKernelPath),
    ]);
    if (!producerBytes.equals(publicSdkBytes)) {
        throw new Error(
            'The public SDK WebAssembly module differs from the processed producer artifact.',
        );
    }
    return createHash('sha256')
        .update(normalizeTranscriptCoreKernelBytesForHash(producerBytes))
        .digest('hex');
};

const recordResourceWindows = async (input: {
    expectedWasmSha256Hex: string;
    processMemoryDiagnosticPath: string;
    runLog: ActiveLocalRunLog;
    testEventPath: string;
}): Promise<void> => {
    const [testEvents, memoryEvents] = await Promise.all([
        readJsonLines(input.testEventPath),
        readJsonLines(input.processMemoryDiagnosticPath),
    ]);
    const measurements = validateDesktopBrowserProofMeasurementEvents(
        testEvents,
        { wasmSha256Hex: input.expectedWasmSha256Hex },
    );

    for (const measurement of measurements) {
        const windowSamples = memoryEvents.filter((event) => {
            if (event.eventType !== 'resource-sample') {
                return false;
            }
            const recordedAtUnixMilliseconds = optionalSafeInteger(
                event,
                'recordedAtUnixMilliseconds',
            );
            return (
                recordedAtUnixMilliseconds !== undefined &&
                recordedAtUnixMilliseconds >=
                    measurement.startedAtUnixMilliseconds &&
                recordedAtUnixMilliseconds <=
                    measurement.finishedAtUnixMilliseconds
            );
        });
        const processTreeBaselineByteLength = nearestBaselineValue(
            memoryEvents,
            'processTreeResidentMemoryBytes',
            measurement.startedAtUnixMilliseconds,
        );
        const processTreePeakByteLength = maximumObservedValue(
            windowSamples,
            'processTreeResidentMemoryBytes',
        );
        const backendBaselineByteLength = nearestBaselineValue(
            memoryEvents,
            'backendCurrentMemoryBytes',
            measurement.startedAtUnixMilliseconds,
        );
        const backendPeakByteLength = maximumObservedValue(
            windowSamples,
            'backendCurrentMemoryBytes',
        );
        const processTreePeakIncreaseByteLength = optionalIncrease(
            processTreePeakByteLength,
            processTreeBaselineByteLength,
        );
        const measuredProofByteLength =
            measurement.executionKind === 'fresh-generation' ||
            measurement.executionKind === 'resumed-generation'
                ? measurement.canonicalOutputByteLength
                : measurement.executionKind === 'verification'
                  ? measurement.canonicalInputByteLength
                  : undefined;
        input.runLog.writeEvent({
            details: {
                caseIdentifier: measurement.caseIdentifier,
                executionKind: measurement.executionKind,
                resourceSampleCount: windowSamples.length,
                softPlanningVariances: {
                    copiedBuffer: planningVariance(
                        measurement.copiedBufferPeakByteLength,
                        softPlanningTargets.copiedBufferByteLength,
                    ),
                    externalScratch: planningVariance(
                        measurement.externalScratchPeakByteLength,
                        softPlanningTargets.externalScratchByteLength,
                    ),
                    wasmLinearMemory: planningVariance(
                        measurement.wasmLinearMemoryPeakByteLength,
                        softPlanningTargets.wasmLinearMemoryByteLength,
                    ),
                    ...(measuredProofByteLength === undefined
                        ? {}
                        : {
                              proof: planningVariance(
                                  measuredProofByteLength,
                                  softPlanningTargets.proofByteLength,
                              ),
                          }),
                    ...(processTreePeakIncreaseByteLength === undefined
                        ? {}
                        : {
                              browserProcessIncrease: planningVariance(
                                  processTreePeakIncreaseByteLength,
                                  softPlanningTargets.browserProcessIncreaseByteLength,
                              ),
                          }),
                },
                suiteId: measurement.suiteId,
                wasmSha256Hex: measurement.wasmSha256Hex,
                ...(backendBaselineByteLength === undefined
                    ? {}
                    : { backendBaselineByteLength }),
                ...(backendPeakByteLength === undefined
                    ? {}
                    : { backendPeakByteLength }),
                ...(optionalIncrease(
                    backendPeakByteLength,
                    backendBaselineByteLength,
                ) === undefined
                    ? {}
                    : {
                          backendPeakIncreaseByteLength: optionalIncrease(
                              backendPeakByteLength,
                              backendBaselineByteLength,
                          ),
                      }),
                ...(processTreeBaselineByteLength === undefined
                    ? {}
                    : { processTreeBaselineByteLength }),
                ...(processTreePeakByteLength === undefined
                    ? {}
                    : { processTreePeakByteLength }),
                ...(processTreePeakIncreaseByteLength === undefined
                    ? {}
                    : {
                          processTreePeakIncreaseByteLength,
                      }),
            },
            eventType: 'desktop-browser-proof-resource-window',
        });
    }
};

export const runDesktopBrowserProofEvidence = async (): Promise<void> => {
    const rawArguments = process.argv
        .slice(2)
        .filter((argument) => argument !== '--');
    if (rawArguments.length > 0) {
        throw new Error(
            'The desktop Chromium proof-evidence runner accepts no arguments.',
        );
    }
    await runWithLocalRunLog(
        {
            commandLineArguments: process.argv.slice(2),
            lanes: [laneLabel],
            scriptName: 'test:browser:proof-evidence',
        },
        async (runLog) => {
            const packageManagerRunner = resolvePackageManagerRunner();
            const processMemoryGuard = createProcessMemoryGuard({
                insufficientFreeMemoryRunDescription:
                    'Desktop Chromium proof evidence',
            });
            const commandEnvironment: NodeJS.ProcessEnv = {
                ...process.env,
                SEALED_LATTICE_TEST_PROJECT_LABEL: testProjectLabel,
            };
            const buildCommand = createPackageManagerCommand(
                'build the processed release WebAssembly workspace',
                ['run', 'build'],
                {
                    env: commandEnvironment,
                    logFileSlug: 'build-desktop-browser-proof-evidence',
                    packageManagerRunner,
                },
            );
            let exitCode = await runCommandsInSeries([buildCommand], {
                outputMode: 'inherit',
                runLog,
            });
            if (exitCode !== 0) {
                process.exitCode = exitCode;
                return;
            }

            const expectedWasmSha256Hex = await deriveProcessedWasmSha256Hex();
            commandEnvironment[expectedWasmSha256EnvironmentVariable] =
                expectedWasmSha256Hex;

            await withLocalHeavyLaneLease({
                action: async () => {
                    exitCode = await runCommandsInSeries(
                        [processMemoryGuard.buildVerificationCommand()],
                        { outputMode: 'inherit', runLog },
                    );
                    if (exitCode !== 0) {
                        return;
                    }
                    const processMemoryDiagnosticPath = path.join(
                        runLog.runDirectoryPath,
                        'resources',
                        processMemoryGuardDiagnosticFileName,
                    );
                    const testEventPath = path.join(
                        runLog.runDirectoryPath,
                        'tests',
                        `${testProjectLabel}.jsonl`,
                    );
                    const browserCommand = createPackageManagerCommand(
                        'run the manual desktop Chromium proof evidence',
                        [
                            'exec',
                            'vitest',
                            '--project',
                            'chromium-desktop-proof-evidence',
                            '--run',
                            browserEvidenceTestFile,
                        ],
                        {
                            env: commandEnvironment,
                            logFileSlug:
                                'vitest-desktop-browser-proof-evidence',
                            packageManagerRunner,
                        },
                    );
                    exitCode = await runCommandsInSeries(
                        [
                            processMemoryGuard.guardCommand(browserCommand, {
                                diagnosticsPath: processMemoryDiagnosticPath,
                            }),
                        ],
                        { outputMode: 'inherit', runLog },
                    );
                    if (exitCode !== 0) {
                        return;
                    }
                    await recordResourceWindows({
                        expectedWasmSha256Hex,
                        processMemoryDiagnosticPath,
                        runLog,
                        testEventPath,
                    });
                },
                laneLabel,
                runLog,
            });
            process.exitCode = exitCode;
        },
    );
};

if (import.meta.main) {
    void runDesktopBrowserProofEvidence();
}
