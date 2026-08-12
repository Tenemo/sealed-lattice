import { readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { runWithLocalRunLog } from './local-run-log.js';
import {
    validateDesktopBrowserFocusedPrimitiveMeasurementBundle,
    validateDesktopBrowserPrimitiveMeasurementBundle,
    validateReleaseNativePrimitiveMeasurementEvidence,
    vssFusedRadix51ProjectionOwnerCaseIdentifiers,
} from './primitive-measurement-evidence.js';
import {
    deriveVssBaseMaterializationProjection,
    deriveVssFusedRadix51OwnerProjection,
} from './vss-base-materialization-projection.js';

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
            if (commandArguments[0] === 'fused-radix-51-owners') {
                const [, nativeEvidenceArgument, chromiumEvidenceArgument] =
                    commandArguments;
                if (
                    nativeEvidenceArgument === undefined ||
                    chromiumEvidenceArgument === undefined ||
                    commandArguments.length !== 3
                ) {
                    throw new Error(
                        'The focused fused radix-51 projection requires one native owner set and one Chromium owner bundle.',
                    );
                }
                const nativeEvidence =
                    validateReleaseNativePrimitiveMeasurementEvidence(
                        await parseJsonFile(
                            path.resolve(process.cwd(), nativeEvidenceArgument),
                        ),
                        false,
                        vssFusedRadix51ProjectionOwnerCaseIdentifiers,
                    );
                const browserBundle =
                    validateDesktopBrowserFocusedPrimitiveMeasurementBundle(
                        await parseJsonFile(
                            path.resolve(
                                process.cwd(),
                                chromiumEvidenceArgument,
                            ),
                        ),
                        vssFusedRadix51ProjectionOwnerCaseIdentifiers,
                    );
                if (
                    browserBundle.focusedPrimitiveEvidence[0]?.browserEngine !==
                    'chromium'
                ) {
                    throw new Error(
                        'The focused fused radix-51 browser owner set is not Chromium evidence.',
                    );
                }
                const projection = deriveVssFusedRadix51OwnerProjection({
                    browserEvidence: browserBundle.focusedPrimitiveEvidence,
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
                    'vss-fused-radix-51-owner-projection.json',
                );
                await writeFile(
                    attachmentFilePath,
                    `${JSON.stringify(
                        {
                            measurementWasm: browserBundle.measurementWasm,
                            projection,
                            schemaVersion: 1,
                        },
                        undefined,
                        2,
                    )}\n`,
                    'utf8',
                );
                runLog.writeEvent({
                    details: { attachmentFilePath },
                    eventType: 'vss-fused-radix-51-owner-projection-written',
                });
                runLog.writeCombinedOutput(
                    `Focused VSS fused radix-51 owner projection completed; evidence: ${attachmentFilePath}\n`,
                );
                return;
            }
            const [nativeEvidenceArgument, browserEvidenceArgument] =
                commandArguments;
            if (
                nativeEvidenceArgument === undefined ||
                browserEvidenceArgument === undefined ||
                commandArguments.length !== 2
            ) {
                throw new Error(
                    'The VSS base-materialization projection requires one complete native catalog and one complete Chromium catalog from a single WASM build.',
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
            const browserBundle =
                validateDesktopBrowserPrimitiveMeasurementBundle(
                    await parseJsonFile(
                        path.resolve(process.cwd(), browserEvidenceArgument),
                    ),
                );
            if (
                browserBundle.browserEvidence.length !== 1 ||
                browserBundle.browserEvidence[0]?.browserEngine !== 'chromium'
            ) {
                throw new Error(
                    'The browser primitive bundle must contain exactly one complete Chromium catalog.',
                );
            }
            const projection = deriveVssBaseMaterializationProjection({
                browserEvidence: browserBundle.browserEvidence,
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
                        measurementWasm: browserBundle.measurementWasm,
                        projection,
                        schemaVersion: 3,
                    },
                    undefined,
                    2,
                )}\n`,
                'utf8',
            );
            runLog.writeEvent({
                details: {
                    attachmentFilePath,
                    modeledCheckpointLevel: projection.modeledCheckpointLevel,
                },
                eventType: 'vss-base-materialization-projection-written',
            });
            runLog.writeCombinedOutput(
                `Modeled VSS base-materialization projection completed; evidence: ${attachmentFilePath}\n`,
            );
        },
    );
};

if (import.meta.main) {
    void runVssBaseMaterializationProjection();
}
