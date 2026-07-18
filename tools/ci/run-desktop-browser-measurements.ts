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

import { requireDesktopBrowserCommonProofMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-case-identifier';
import { validateDesktopBrowserCommonProofMeasurement } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-worker-protocol';
import { persistProductionDesktopBrowserMeasurementResult } from '#packages/protocol/tests/support/production-desktop-browser-measurement-result';

const browserMeasurementProjectLabel = 'chromium-desktop-measurements';
const selectedCaseEnvironmentVariable =
    'VITE_SEALED_LATTICE_DESKTOP_BROWSER_COMMON_PROOF_MEASUREMENT_CASE_IDENTIFIER';
const measurementTestPath =
    'packages/protocol/tests/manual/production-common-proof.browser.measurement.test.ts';

type ProcessMemoryDiagnosticRecord = Readonly<{
    eventType?: unknown;
    observedPeakProcessTreeResidentMemoryBytes?: unknown;
    processTreeResidentMemoryBytes?: unknown;
}>;

export type DesktopBrowserProcessMemoryMeasurement = Readonly<{
    baselineProcessTreeResidentMemoryBytes: number;
    caseIdentifier: string;
    measurementScope: 'isolated-desktop-chromium-process-tree';
    observedPeakProcessTreeResidentMemoryBytes: number;
    processTreeResidentMemoryIncreaseBytes: number;
}>;

export type ParsedDesktopBrowserMeasurementArguments = Readonly<{
    caseIdentifiers: readonly string[];
}>;

export type DesktopBrowserMeasurementArtifactNames = Readonly<{
    diagnosticsFileName: string;
    operationMeasurementFileName: string;
    processMemoryMeasurementFileName: string;
}>;

let desktopBrowserMeasurementProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getDesktopBrowserMeasurementProcessMemoryGuard =
    (): ProcessMemoryGuard => {
        desktopBrowserMeasurementProcessMemoryGuard ??=
            createProcessMemoryGuard({
                insufficientFreeMemoryRunDescription:
                    'Desktop-browser proof measurements',
            });

        return desktopBrowserMeasurementProcessMemoryGuard;
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

export const deriveDesktopBrowserProcessMemoryMeasurement = (
    diagnosticJsonLines: string,
    caseIdentifier: string,
): DesktopBrowserProcessMemoryMeasurement => {
    const requiredCaseIdentifier =
        requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
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
        measurementScope: 'isolated-desktop-chromium-process-tree',
        observedPeakProcessTreeResidentMemoryBytes,
        processTreeResidentMemoryIncreaseBytes:
            observedPeakProcessTreeResidentMemoryBytes -
            baselineProcessTreeResidentMemoryBytes,
    });
};

export const parseDesktopBrowserMeasurementArguments = (
    rawArguments: readonly string[],
): ParsedDesktopBrowserMeasurementArguments => {
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
                `test:browser:measurements received an unsupported argument: ${argument ?? '<missing>'}.`,
            );
        }
        const caseIdentifier =
            requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
                rawArguments[argumentIndex + 1],
            );
        if (observedCaseIdentifiers.has(caseIdentifier)) {
            throw new Error(
                `test:browser:measurements received a duplicate case identifier: ${caseIdentifier}.`,
            );
        }
        observedCaseIdentifiers.add(caseIdentifier);
        caseIdentifiers.push(caseIdentifier);
        argumentIndex += 2;
    }

    if (caseIdentifiers.length === 0) {
        throw new Error(
            'test:browser:measurements requires at least one --case-identifier argument.',
        );
    }
    return Object.freeze({ caseIdentifiers: Object.freeze(caseIdentifiers) });
};

export const desktopBrowserMeasurementArtifactNames = (
    caseIdentifier: string,
): DesktopBrowserMeasurementArtifactNames => {
    const requiredCaseIdentifier =
        requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
            caseIdentifier,
        );
    return Object.freeze({
        diagnosticsFileName: `process-memory-guard-browser-desktop-measurements-${requiredCaseIdentifier}.jsonl`,
        operationMeasurementFileName: `desktop-browser-common-proof-${requiredCaseIdentifier}-measurement.json`,
        processMemoryMeasurementFileName: `desktop-browser-process-memory-${requiredCaseIdentifier}.json`,
    });
};

export const desktopBrowserMeasurementCommandIdentifier = (
    caseIdentifier: string,
): string =>
    `vitest-browser-desktop-measurements-${requireDesktopBrowserCommonProofMeasurementCaseIdentifier(caseIdentifier)}`;

export const buildDesktopBrowserMeasurementCommand = (
    diagnosticsPath: string,
    caseIdentifier: string,
): CommandInvocation => {
    const requiredCaseIdentifier =
        requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
            caseIdentifier,
        );
    const measurementCommand = createPackageManagerCommand(
        `measure production common proof ${requiredCaseIdentifier} in isolated desktop Chromium`,
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
            logFileSlug: desktopBrowserMeasurementCommandIdentifier(
                requiredCaseIdentifier,
            ),
        },
    );

    return getDesktopBrowserMeasurementProcessMemoryGuard().guardCommand(
        measurementCommand,
        { diagnosticsPath },
    );
};

export const buildDesktopBrowserMeasurementGuardVerificationCommand =
    (): CommandInvocation =>
        getDesktopBrowserMeasurementProcessMemoryGuard().buildVerificationCommand();

export const runDesktopBrowserMeasurements = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const parsedArguments =
        parseDesktopBrowserMeasurementArguments(rawArguments);

    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: parsedArguments.caseIdentifiers.map(
                (caseIdentifier) =>
                    `Desktop-browser measurement ${caseIdentifier}`,
            ),
            scriptName: 'test:browser:measurements',
        },
        async (runLog) => {
            const buildExitCode = await runCommandsInSeries(
                [
                    createPackageManagerCommand(
                        'build production browser artifacts',
                        ['run', 'build'],
                        { logFileSlug: 'build-browser-measurements' },
                    ),
                    buildDesktopBrowserMeasurementGuardVerificationCommand(),
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
                const artifactNames =
                    desktopBrowserMeasurementArtifactNames(caseIdentifier);
                const diagnosticsPath = path.join(
                    runLog.runDirectoryPath,
                    'resources',
                    artifactNames.diagnosticsFileName,
                );
                const measurementExitCode = await runCommandsInSeries(
                    [
                        buildDesktopBrowserMeasurementCommand(
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
                    artifactNames.operationMeasurementFileName,
                );
                await persistProductionDesktopBrowserMeasurementResult({
                    caseIdentifier,
                    commandIdentifier:
                        desktopBrowserMeasurementCommandIdentifier(
                            caseIdentifier,
                        ),
                    outputLogText: await readFile(
                        path.join(runLog.runDirectoryPath, 'output.log'),
                        'utf8',
                    ),
                    validateMeasurement:
                        validateDesktopBrowserCommonProofMeasurement,
                    writeMeasurementJson: (measurementJson) =>
                        writeFile(
                            operationMeasurementPath,
                            `${measurementJson}\n`,
                            { encoding: 'utf8', flag: 'wx' },
                        ),
                });
                runLog.writeEvent({
                    details: {
                        caseIdentifier,
                        measurementPath: operationMeasurementPath,
                    },
                    eventType:
                        'desktop-browser-common-proof-operation-measured',
                });
                const measurement =
                    deriveDesktopBrowserProcessMemoryMeasurement(
                        await readFile(diagnosticsPath, 'utf8'),
                        caseIdentifier,
                    );
                const measurementPath = path.join(
                    measurementDirectoryPath,
                    artifactNames.processMemoryMeasurementFileName,
                );
                await writeFile(
                    measurementPath,
                    `${JSON.stringify(measurement, undefined, 2)}\n`,
                    { encoding: 'utf8', flag: 'wx' },
                );
                runLog.writeEvent({
                    details: {
                        ...measurement,
                        measurementPath,
                        protocolAcceptanceBound: false,
                    },
                    eventType: 'desktop-browser-process-memory-measured',
                });
                console.info(JSON.stringify(measurement));
            }
        },
    );
};

if (import.meta.main) {
    void runDesktopBrowserMeasurements();
}
