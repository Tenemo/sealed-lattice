import { readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { runWithLocalRunLog } from './local-run-log.js';
import {
    assembleDesktopBrowserPrimitiveMeasurementEvidence,
    primitiveMeasurementBaseCaseIdentifiers,
    primitiveMeasurementSupplementalCaseIdentifiers,
    validateDesktopBrowserFocusedPrimitiveMeasurementBundle,
    validateDesktopBrowserPrimitiveMeasurementBaseBundle,
    validateReleaseNativePrimitiveMeasurementEvidence,
} from './primitive-measurement-evidence.js';
import { deriveVssBaseMaterializationProjection } from './vss-base-materialization-projection.js';

const parseJsonFile = async (filePath: string): Promise<unknown> => {
    return JSON.parse(await readFile(filePath, 'utf8')) as unknown;
};

export const runVssBaseMaterializationProjection = async (): Promise<void> => {
    const commandArguments = process.argv
        .slice(2)
        .filter((argument) => argument !== '--');
    await runWithLocalRunLog(
        {
            commandLineArguments: commandArguments,
            lanes: ['VSS base materialization projection'],
            scriptName: 'test:evidence:vss-base-materialization-projection',
        },
        async (runLog) => {
            const [
                nativeEvidenceArgument,
                browserBaseEvidenceArgument,
                chromiumCaseFiveEvidenceArgument,
                firefoxCaseFiveEvidenceArgument,
                chromiumCaseEightEvidenceArgument,
                firefoxCaseEightEvidenceArgument,
            ] = commandArguments;
            if (
                nativeEvidenceArgument === undefined ||
                browserBaseEvidenceArgument === undefined ||
                chromiumCaseFiveEvidenceArgument === undefined ||
                firefoxCaseFiveEvidenceArgument === undefined ||
                chromiumCaseEightEvidenceArgument === undefined ||
                firefoxCaseEightEvidenceArgument === undefined ||
                commandArguments.length !== 6
            ) {
                throw new Error(
                    'The VSS base-materialization projection requires native, preserved browser base, and Chromium and Firefox case-5 and case-8 evidence paths.',
                );
            }
            const nativeEvidencePath = path.resolve(
                process.cwd(),
                nativeEvidenceArgument,
            );
            const nativeEvidence =
                validateReleaseNativePrimitiveMeasurementEvidence(
                    await parseJsonFile(nativeEvidencePath),
                    true,
                );
            const browserBaseBundle =
                validateDesktopBrowserPrimitiveMeasurementBaseBundle(
                    await parseJsonFile(
                        path.resolve(
                            process.cwd(),
                            browserBaseEvidenceArgument,
                        ),
                    ),
                );
            if (
                browserBaseBundle.browserEvidence.length !== 2 ||
                browserBaseBundle.browserEvidence[0]?.browserEngine !==
                    'chromium' ||
                browserBaseBundle.browserEvidence[1]?.browserEngine !==
                    'firefox'
            ) {
                throw new Error(
                    'The browser primitive base bundle must contain Chromium and Firefox in canonical order.',
                );
            }
            const focusedSpecifications = [
                {
                    argument: chromiumCaseFiveEvidenceArgument,
                    browserEngine: 'chromium',
                    caseIdentifier: 5,
                },
                {
                    argument: firefoxCaseFiveEvidenceArgument,
                    browserEngine: 'firefox',
                    caseIdentifier: 5,
                },
                {
                    argument: chromiumCaseEightEvidenceArgument,
                    browserEngine: 'chromium',
                    caseIdentifier: 8,
                },
                {
                    argument: firefoxCaseEightEvidenceArgument,
                    browserEngine: 'firefox',
                    caseIdentifier: 8,
                },
            ] as const;
            const focusedMeasurements = await Promise.all(
                focusedSpecifications.map(async (specification) => {
                    const bundle =
                        validateDesktopBrowserFocusedPrimitiveMeasurementBundle(
                            await parseJsonFile(
                                path.resolve(
                                    process.cwd(),
                                    specification.argument,
                                ),
                            ),
                            specification.caseIdentifier,
                        );
                    const evidence = bundle.focusedPrimitiveEvidence[0];
                    if (
                        bundle.focusedPrimitiveEvidence.length !== 1 ||
                        evidence?.browserEngine !== specification.browserEngine
                    ) {
                        throw new Error(
                            `Focused case ${String(specification.caseIdentifier)} evidence lacks ${specification.browserEngine}.`,
                        );
                    }
                    return Object.freeze({ bundle, evidence });
                }),
            );
            const wasmIdentities = new Set(
                focusedMeasurements.map(
                    ({ bundle }) =>
                        `${bundle.measurementWasm.byteLength}:${bundle.measurementWasm.normalizedSha256Hex}:${bundle.measurementWasm.rawSha256Hex}`,
                ),
            );
            if (wasmIdentities.size !== 1) {
                throw new Error(
                    'Focused desktop-browser primitive measurements use different WASM artifacts.',
                );
            }
            const browserEvidence = browserBaseBundle.browserEvidence.map(
                (baseEvidence) => {
                    const supplementalEvidence = focusedMeasurements
                        .map((measurement) => measurement.evidence)
                        .filter(
                            (evidence) =>
                                evidence.browserEngine ===
                                baseEvidence.browserEngine,
                        )
                        .sort(
                            (left, right) =>
                                left.primitiveCase.record.caseIdentifier -
                                right.primitiveCase.record.caseIdentifier,
                        );
                    if (
                        supplementalEvidence.length !==
                        primitiveMeasurementSupplementalCaseIdentifiers.length
                    ) {
                        throw new Error(
                            'Focused browser evidence lacks one supplemental case for a base-bundle engine.',
                        );
                    }
                    return assembleDesktopBrowserPrimitiveMeasurementEvidence({
                        baseEvidence,
                        supplementalEvidence,
                    });
                },
            );
            const focusedMeasurementWasm =
                focusedMeasurements[0]?.bundle.measurementWasm;
            if (focusedMeasurementWasm === undefined) {
                throw new Error('Focused browser WASM identity is absent.');
            }
            const projection = deriveVssBaseMaterializationProjection({
                browserEvidence,
                nativeEvidence,
            });
            const attachmentDirectoryPath = path.join(
                runLog.runDirectoryPath,
                'attachments',
                'primitive-measurements',
            );
            await mkdir(attachmentDirectoryPath, { recursive: true });
            const attachmentFilePath = path.join(
                attachmentDirectoryPath,
                'selected-vss-base-materialization-projection.json',
            );
            await writeFile(
                attachmentFilePath,
                `${JSON.stringify(
                    {
                        measurementWasmSources: [
                            {
                                caseIdentifiers:
                                    primitiveMeasurementBaseCaseIdentifiers,
                                measurementWasm:
                                    browserBaseBundle.measurementWasm,
                            },
                            {
                                caseIdentifiers:
                                    primitiveMeasurementSupplementalCaseIdentifiers,
                                measurementWasm: focusedMeasurementWasm,
                            },
                        ],
                        projection,
                        schemaVersion: 2,
                    },
                    undefined,
                    2,
                )}\n`,
                'utf8',
            );
            runLog.writeEvent({
                details: {
                    attachmentFilePath,
                    selectedCheckpointLevel: projection.selectedCheckpointLevel,
                },
                eventType: 'vss-base-materialization-projection-written',
            });
            runLog.writeCombinedOutput(
                `Selected VSS base-materialization projection completed; evidence: ${attachmentFilePath}\n`,
            );
        },
    );
};

if (import.meta.main) {
    void runVssBaseMaterializationProjection();
}
