import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { runWithLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    createPackageManagerCommand,
    runCommandsInSeries,
    type CommandInvocation,
} from './run-command.js';

import { requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-case-identifier';
import { validateDesktopBrowserEvaluatorReplayMeasurement } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-worker-protocol';
import { persistProductionDesktopBrowserMeasurementResult } from '#packages/protocol/tests/support/production-desktop-browser-measurement-result';

const browserMeasurementProjectLabel = 'chromium-desktop-measurements';
const selectedCaseEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_BROWSER_EVALUATOR_REPLAY_MEASUREMENT_CASE_IDENTIFIER';
const measurementTestPath =
    'packages/protocol/tests/manual/production-evaluator-replay.browser.measurement.test.ts';

type ProcessMemoryDiagnosticRecord = Readonly<{
    eventType?: unknown;
    observedPeakProcessTreeResidentMemoryBytes?: unknown;
    processTreeResidentMemoryBytes?: unknown;
}>;

type DesktopBrowserEvaluatorReplayProcessMemoryMeasurement = Readonly<{
    baselineProcessTreeResidentMemoryBytes: number;
    caseIdentifier: string;
    measurementScope: 'isolated-desktop-chromium-process-tree';
    observedPeakProcessTreeResidentMemoryBytes: number;
    processTreeResidentMemoryIncreaseBytes: number;
}>;

type ParsedArguments = Readonly<{
    caseIdentifiers: readonly string[];
}>;

let processMemoryGuard: ProcessMemoryGuard | undefined;

const getProcessMemoryGuard = (): ProcessMemoryGuard => {
    processMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription:
            'Desktop-browser evaluator-replay measurements',
    });
    return processMemoryGuard;
};

const requireResidentByteLength = (
    value: unknown,
    fieldName: string,
): number => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new Error(
            `Process-memory diagnostics contain an invalid ${fieldName}.`,
        );
    }
    return Number(value);
};

const parseDiagnosticRecord = (
    line: string,
    lineNumber: number,
): ProcessMemoryDiagnosticRecord => {
    let value: unknown;
    try {
        value = JSON.parse(line);
    } catch (error) {
        throw Object.assign(
            new Error(
                `Process-memory diagnostics line ${lineNumber} is not valid JSON.`,
            ),
            { cause: error },
        );
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(
            `Process-memory diagnostics line ${lineNumber} is not an object.`,
        );
    }
    return value;
};

export const deriveDesktopBrowserEvaluatorReplayProcessMemoryMeasurement = (
    diagnosticJsonLines: string,
    caseIdentifier: string,
): DesktopBrowserEvaluatorReplayProcessMemoryMeasurement => {
    const requiredCaseIdentifier =
        requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
            caseIdentifier,
        );
    const records = diagnosticJsonLines
        .split(/\r\n|\n|\r/u)
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .map((line, lineIndex) => parseDiagnosticRecord(line, lineIndex + 1));
    const resourceSamples = records.filter(
        (record) => record.eventType === 'resource-sample',
    );
    const firstResidentSample = resourceSamples.find(
        (record) =>
            record.processTreeResidentMemoryBytes !== null &&
            record.processTreeResidentMemoryBytes !== undefined,
    )?.processTreeResidentMemoryBytes;
    if (firstResidentSample === undefined) {
        throw new Error(
            'Process-memory diagnostics contain no process-tree resident-memory sample.',
        );
    }
    const baselineProcessTreeResidentMemoryBytes = requireResidentByteLength(
        firstResidentSample,
        'baseline process-tree resident byte length',
    );

    let childExitRecord: ProcessMemoryDiagnosticRecord | undefined;
    for (const record of records) {
        if (record.eventType === 'child-exited') {
            childExitRecord = record;
        }
    }
    if (childExitRecord === undefined) {
        throw new Error(
            'Process-memory diagnostics contain no completed guarded child record.',
        );
    }
    const observedPeakProcessTreeResidentMemoryBytes =
        requireResidentByteLength(
            childExitRecord.observedPeakProcessTreeResidentMemoryBytes,
            'observed peak process-tree resident byte length',
        );
    if (
        observedPeakProcessTreeResidentMemoryBytes <
        baselineProcessTreeResidentMemoryBytes
    ) {
        throw new Error(
            'Process-memory diagnostics report a peak below the baseline sample.',
        );
    }

    return Object.freeze({
        baselineProcessTreeResidentMemoryBytes,
        caseIdentifier: requiredCaseIdentifier,
        measurementScope: 'isolated-desktop-chromium-process-tree' as const,
        observedPeakProcessTreeResidentMemoryBytes,
        processTreeResidentMemoryIncreaseBytes:
            observedPeakProcessTreeResidentMemoryBytes -
            baselineProcessTreeResidentMemoryBytes,
    });
};

export const parseDesktopBrowserEvaluatorReplayMeasurementArguments = (
    rawArguments: readonly string[],
): ParsedArguments => {
    const caseIdentifiers: string[] = [];
    const observedCaseIdentifiers = new Set<string>();
    for (let argumentIndex = 0; argumentIndex < rawArguments.length; ) {
        const argument = rawArguments[argumentIndex];
        if (argument === '--') {
            argumentIndex += 1;
            continue;
        }
        if (argument !== '--case-identifier') {
            throw new Error(
                `test:browser:evaluator-replay-measurements received an unsupported argument: ${argument ?? '<missing>'}.`,
            );
        }
        const caseIdentifier =
            requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
                rawArguments[argumentIndex + 1],
            );
        if (observedCaseIdentifiers.has(caseIdentifier)) {
            throw new Error(
                `test:browser:evaluator-replay-measurements received a duplicate case identifier: ${caseIdentifier}.`,
            );
        }
        observedCaseIdentifiers.add(caseIdentifier);
        caseIdentifiers.push(caseIdentifier);
        argumentIndex += 2;
    }
    if (caseIdentifiers.length === 0) {
        throw new Error(
            'test:browser:evaluator-replay-measurements requires at least one --case-identifier argument.',
        );
    }
    return Object.freeze({ caseIdentifiers: Object.freeze(caseIdentifiers) });
};

export const desktopBrowserEvaluatorReplayMeasurementArtifactNames = (
    caseIdentifier: string,
): Readonly<{
    diagnosticsFileName: string;
    operationMeasurementFileName: string;
    processMemoryMeasurementFileName: string;
}> => {
    const requiredCaseIdentifier =
        requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
            caseIdentifier,
        );
    return Object.freeze({
        diagnosticsFileName: `process-memory-guard-browser-desktop-evaluator-replay-${requiredCaseIdentifier}.jsonl`,
        operationMeasurementFileName: `desktop-browser-evaluator-replay-${requiredCaseIdentifier}-measurement.json`,
        processMemoryMeasurementFileName: `desktop-browser-evaluator-replay-process-memory-${requiredCaseIdentifier}.json`,
    });
};

export const desktopBrowserEvaluatorReplayMeasurementCommandIdentifier = (
    caseIdentifier: string,
): string =>
    `vitest-browser-desktop-evaluator-replay-${requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(caseIdentifier)}`;

export const buildDesktopBrowserEvaluatorReplayMeasurementCommand = (
    diagnosticsPath: string,
    caseIdentifier: string,
): CommandInvocation => {
    const requiredCaseIdentifier =
        requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
            caseIdentifier,
        );
    const measurementCommand = createPackageManagerCommand(
        `measure production evaluator replay ${requiredCaseIdentifier} in isolated desktop Chromium`,
        [
            'exec',
            'vitest',
            '--project',
            browserMeasurementProjectLabel,
            '--run',
            measurementTestPath,
        ],
        {
            env: {
                ...process.env,
                SEALED_LATTICE_TEST_PROJECT_LABEL:
                    browserMeasurementProjectLabel,
                [selectedCaseEnvironmentVariable]: requiredCaseIdentifier,
            },
            logFileSlug:
                desktopBrowserEvaluatorReplayMeasurementCommandIdentifier(
                    requiredCaseIdentifier,
                ),
        },
    );
    return getProcessMemoryGuard().guardCommand(measurementCommand, {
        diagnosticsPath,
    });
};

export const buildDesktopBrowserEvaluatorReplayMeasurementGuardVerificationCommand =
    (): CommandInvocation => getProcessMemoryGuard().buildVerificationCommand();

export const runDesktopBrowserEvaluatorReplayMeasurements =
    async (): Promise<void> => {
        const rawArguments = process.argv.slice(2);
        const parsedArguments =
            parseDesktopBrowserEvaluatorReplayMeasurementArguments(
                rawArguments,
            );

        await runWithLocalRunLog(
            {
                commandLineArguments: rawArguments,
                lanes: parsedArguments.caseIdentifiers.map(
                    (caseIdentifier) =>
                        `Desktop-browser evaluator-replay measurement ${caseIdentifier}`,
                ),
                scriptName: 'test:browser:evaluator-replay-measurements',
            },
            async (runLog) => {
                const buildExitCode = await runCommandsInSeries(
                    [
                        createPackageManagerCommand(
                            'build production browser artifacts',
                            ['run', 'build'],
                            {
                                logFileSlug:
                                    'build-browser-evaluator-replay-measurements',
                            },
                        ),
                        buildDesktopBrowserEvaluatorReplayMeasurementGuardVerificationCommand(),
                    ],
                    { outputMode: 'inherit', runLog },
                );
                if (buildExitCode !== 0) {
                    process.exitCode = buildExitCode;
                    return;
                }

                const measurementDirectoryPath = path.join(
                    runLog.runDirectoryPath,
                    'measurements',
                );
                await mkdir(measurementDirectoryPath, { recursive: true });
                for (const caseIdentifier of parsedArguments.caseIdentifiers) {
                    const selectedArtifactNames =
                        desktopBrowserEvaluatorReplayMeasurementArtifactNames(
                            caseIdentifier,
                        );
                    const diagnosticsPath = path.join(
                        runLog.runDirectoryPath,
                        'resources',
                        selectedArtifactNames.diagnosticsFileName,
                    );
                    const measurementExitCode = await runCommandsInSeries(
                        [
                            buildDesktopBrowserEvaluatorReplayMeasurementCommand(
                                diagnosticsPath,
                                caseIdentifier,
                            ),
                        ],
                        { outputMode: 'inherit', runLog },
                    );
                    if (measurementExitCode !== 0) {
                        process.exitCode = measurementExitCode;
                        return;
                    }
                    const operationMeasurementPath = path.join(
                        measurementDirectoryPath,
                        selectedArtifactNames.operationMeasurementFileName,
                    );
                    await persistProductionDesktopBrowserMeasurementResult({
                        caseIdentifier,
                        commandIdentifier:
                            desktopBrowserEvaluatorReplayMeasurementCommandIdentifier(
                                caseIdentifier,
                            ),
                        outputLogText: await readFile(
                            path.join(runLog.runDirectoryPath, 'output.log'),
                            'utf8',
                        ),
                        validateMeasurement:
                            validateDesktopBrowserEvaluatorReplayMeasurement,
                        writeMeasurementJson: (measurementJson) =>
                            writeFile(
                                operationMeasurementPath,
                                measurementJson,
                                { encoding: 'utf8', flag: 'wx' },
                            ),
                    });
                    runLog.writeEvent({
                        details: {
                            caseIdentifier,
                            measurementPath: operationMeasurementPath,
                        },
                        eventType:
                            'desktop-browser-evaluator-replay-operation-measured',
                    });
                    const measurement =
                        deriveDesktopBrowserEvaluatorReplayProcessMemoryMeasurement(
                            await readFile(diagnosticsPath, 'utf8'),
                            caseIdentifier,
                        );
                    const processMemoryMeasurementPath = path.join(
                        measurementDirectoryPath,
                        selectedArtifactNames.processMemoryMeasurementFileName,
                    );
                    await writeFile(
                        processMemoryMeasurementPath,
                        `${JSON.stringify(measurement, undefined, 2)}\n`,
                        { encoding: 'utf8', flag: 'wx' },
                    );
                    runLog.writeEvent({
                        details: {
                            ...measurement,
                            measurementPath: processMemoryMeasurementPath,
                            protocolAcceptanceBound: false,
                        },
                        eventType:
                            'desktop-browser-evaluator-replay-process-memory-measured',
                    });
                    console.info(JSON.stringify(measurement));
                }
            },
        );
    };

if (import.meta.main) {
    void runDesktopBrowserEvaluatorReplayMeasurements();
}
