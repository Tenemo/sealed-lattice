import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { verifyCompactPublicKeyAlgebraicallyInClosedWorker } from '#packages/wasm/src/common-proof-worker-runtime';
import {
    generateCompactPublicKeyReferenceInClosedWorker,
    type GeneratedCompactPublicKeyReferenceProof,
} from '#packages/wasm/src/index';
import {
    instantiateTranscriptCoreKernelCommandRuntime,
    normalizeTranscriptCoreKernelBytesForHash,
} from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import { openCompactPublicKeyProductionGenerationFixture } from '#packages/wasm/tests/support/compact-public-key-production-generation-fixture';
import {
    openFileBackedCommonProofExternalMemory,
    type FileBackedCommonProofExternalMemory,
    type FileBackedCommonProofExternalMemoryLogicalUsage,
    type FileBackedCommonProofExternalMemoryPhysicalAccounting,
} from '#packages/wasm/tests/support/file-backed-common-proof-external-memory';
import {
    compactPublicKeyWasmProofEvidenceOutputPathEnvironmentVariable,
    compactPublicKeyWasmProofEvidenceTemporaryDirectoryEnvironmentVariable,
} from '#tools/ci/run-node-kernel-proof-evidence';

const maximumWorkUnitCountPerPoll = 4_096;
const progressReportIntervalMilliseconds = 30_000;
const memorySampleInterval = 32;
const wasmArtifactPath = path.resolve(
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);

type ProcessMemoryObservation = Readonly<{
    arrayBuffers: number;
    external: number;
    heapTotal: number;
    heapUsed: number;
    residentSet: number;
}>;

type ProgressObservation = Readonly<{
    durationMilliseconds: number;
    maximumProcessMemory: ProcessMemoryObservation;
    maximumCooperativeYieldIntervalMilliseconds: number;
    maximumWasmMemoryByteLength?: number;
    yieldCount: number;
}>;

class CompactPublicKeyWasmEvidenceCleanupError extends Error {
    public override readonly name = 'CompactPublicKeyWasmEvidenceCleanupError';

    public constructor(
        public readonly operationFailure: unknown,
        public readonly cleanupFailures: readonly unknown[],
    ) {
        super(
            'Compact public-key scalar WASM evidence failed and could not release every development-evidence owner.',
        );
    }
}

class CompactPublicKeyWasmEvidenceNonErrorFailure extends Error {
    public override readonly name =
        'CompactPublicKeyWasmEvidenceNonErrorFailure';

    public constructor(public readonly operationFailure: unknown) {
        super(
            'Compact public-key scalar WASM evidence failed with a non-error value.',
        );
    }
}

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const sha512Hex = (bytes: Uint8Array): string =>
    createHash('sha512').update(bytes).digest('hex');

const observeProcessMemory = (): ProcessMemoryObservation => {
    const memory = process.memoryUsage();
    return Object.freeze({
        arrayBuffers: memory.arrayBuffers,
        external: memory.external,
        heapTotal: memory.heapTotal,
        heapUsed: memory.heapUsed,
        residentSet: memory.rss,
    });
};

const maximumProcessMemory = (
    previous: ProcessMemoryObservation,
    next: ProcessMemoryObservation,
): ProcessMemoryObservation =>
    Object.freeze({
        arrayBuffers: Math.max(previous.arrayBuffers, next.arrayBuffers),
        external: Math.max(previous.external, next.external),
        heapTotal: Math.max(previous.heapTotal, next.heapTotal),
        heapUsed: Math.max(previous.heapUsed, next.heapUsed),
        residentSet: Math.max(previous.residentSet, next.residentSet),
    });

const beginProgressObservation = (input: {
    label: string;
    wasmMemoryByteLength?: () => number;
}): Readonly<{
    finish(): ProgressObservation;
    yieldControl(): Promise<void>;
}> => {
    const startedAt = performance.now();
    let lastYieldAt = startedAt;
    let lastReportAt = startedAt;
    let maximumMemory = observeProcessMemory();
    let maximumCooperativeYieldIntervalMilliseconds = 0;
    let maximumWasmMemoryByteLength = input.wasmMemoryByteLength?.();
    let yieldCount = 0;

    const observeYieldInterval = (now: number): void => {
        maximumCooperativeYieldIntervalMilliseconds = Math.max(
            maximumCooperativeYieldIntervalMilliseconds,
            now - lastYieldAt,
        );
        lastYieldAt = now;
    };

    const sampleMemory = (): void => {
        maximumMemory = maximumProcessMemory(
            maximumMemory,
            observeProcessMemory(),
        );
        const wasmMemoryByteLength = input.wasmMemoryByteLength?.();
        if (wasmMemoryByteLength !== undefined) {
            maximumWasmMemoryByteLength = Math.max(
                maximumWasmMemoryByteLength ?? 0,
                wasmMemoryByteLength,
            );
        }
    };

    return Object.freeze({
        finish: (): ProgressObservation => {
            const finishedAt = performance.now();
            observeYieldInterval(finishedAt);
            sampleMemory();
            return Object.freeze({
                durationMilliseconds: finishedAt - startedAt,
                maximumProcessMemory: maximumMemory,
                maximumCooperativeYieldIntervalMilliseconds,
                ...(maximumWasmMemoryByteLength === undefined
                    ? {}
                    : { maximumWasmMemoryByteLength }),
                yieldCount,
            });
        },
        yieldControl: async (): Promise<void> => {
            yieldCount += 1;
            const now = performance.now();
            observeYieldInterval(now);
            if (yieldCount % memorySampleInterval === 0) {
                sampleMemory();
            }
            if (now - lastReportAt >= progressReportIntervalMilliseconds) {
                const memory = observeProcessMemory();
                console.log(
                    `${input.label} remains live after ${String(yieldCount)} bounded yields; process RSS ${String(memory.residentSet)} bytes.`,
                );
                lastReportAt = now;
            }
            await new Promise<void>((resolve) => {
                setImmediate(resolve);
            });
        },
    });
};

type NestedEvidenceFailure = Partial<{
    abortFailure: unknown;
    cleanupFailure: unknown;
    cleanupFailures: readonly unknown[];
    failureCause: unknown;
    operationFailure: unknown;
}>;

const evidenceFailureRecord = (
    failure: unknown,
    depth = 0,
): Readonly<Record<string, unknown>> => {
    if (typeof failure !== 'object' || failure === null) {
        return Object.freeze({ failureKind: typeof failure });
    }
    if (depth >= 8) {
        return Object.freeze({
            ...(failure instanceof Error
                ? { message: failure.message, name: failure.name }
                : { failureKind: 'object' }),
            nestedFailureDepthLimitReached: true,
        });
    }
    const nestedFailure = failure as NestedEvidenceFailure;
    const nestedRecords: Record<string, unknown> = {};
    for (const propertyName of [
        'operationFailure',
        'cleanupFailure',
        'failureCause',
        'abortFailure',
    ] as const) {
        const propertyValue = nestedFailure[propertyName];
        if (propertyValue !== undefined) {
            nestedRecords[propertyName] = evidenceFailureRecord(
                propertyValue,
                depth + 1,
            );
        }
    }
    if (Array.isArray(nestedFailure.cleanupFailures)) {
        nestedRecords.cleanupFailures = nestedFailure.cleanupFailures.map(
            (cleanupFailure) =>
                evidenceFailureRecord(cleanupFailure, depth + 1),
        );
    }
    return Object.freeze({
        ...(failure instanceof Error
            ? {
                  message: failure.message,
                  name: failure.name,
                  ...(failure.stack === undefined
                      ? {}
                      : { stack: failure.stack }),
              }
            : { failureKind: 'object' }),
        ...nestedRecords,
    });
};

const logicalUsageRecord = (
    usage: FileBackedCommonProofExternalMemoryLogicalUsage,
): Readonly<Record<string, string>> =>
    Object.freeze({
        deletedObjectLifecycleCount:
            usage.deletedObjectLifecycleCount.toString(),
        peakStoredByteLength: usage.peakStoredByteLength.toString(),
        totalReadByteLength: usage.totalReadByteLength.toString(),
        totalWrittenByteLength: usage.totalWrittenByteLength.toString(),
        transactionCount: usage.transactionCount.toString(),
    });

const physicalAccountingRecord = (
    accounting: FileBackedCommonProofExternalMemoryPhysicalAccounting,
): Readonly<Record<string, number | string>> =>
    Object.freeze({
        copyOnWriteByteLength: accounting.copyOnWriteByteLength.toString(),
        copyOnWriteCount: accounting.copyOnWriteCount.toString(),
        currentDeclaredByteLength:
            accounting.currentDeclaredByteLength.toString(),
        liveObjectCount: accounting.liveObjectCount,
        maximumDeclaredByteLength:
            accounting.maximumDeclaredByteLength.toString(),
        physicalDeleteCount: accounting.physicalDeleteCount.toString(),
        physicalFileCreateCount: accounting.physicalFileCreateCount.toString(),
        physicalReadByteLength: accounting.physicalReadByteLength.toString(),
        physicalReadCount: accounting.physicalReadCount.toString(),
        physicalSealCount: accounting.physicalSealCount.toString(),
        physicalWriteByteLength: accounting.physicalWriteByteLength.toString(),
        physicalWriteCount: accounting.physicalWriteCount.toString(),
    });

const workerAccountingRecord = (
    accounting: GeneratedCompactPublicKeyReferenceProof['externalMemoryAccounting']['worker'],
): Readonly<Record<string, number | string>> =>
    Object.freeze({
        browserToWasmStorageResponseByteLength:
            accounting.browserToWasmStorageResponseByteLength.toString(),
        browserToWasmStorageResponseCount:
            accounting.browserToWasmStorageResponseCount.toString(),
        canonicalOutputCopyByteLength:
            accounting.canonicalOutputCopyByteLength.toString(),
        canonicalOutputCopyCount:
            accounting.canonicalOutputCopyCount.toString(),
        finalWasmMemoryByteLength: accounting.finalWasmMemoryByteLength,
        initialWasmMemoryByteLength: accounting.initialWasmMemoryByteLength,
        maximumWasmMemoryByteLength: accounting.maximumWasmMemoryByteLength,
        readResultTransferByteLength:
            accounting.readResultTransferByteLength.toString(),
        readResultTransferCount: accounting.readResultTransferCount.toString(),
        wasmToBrowserStorageRequestByteLength:
            accounting.wasmToBrowserStorageRequestByteLength.toString(),
        wasmToBrowserStorageRequestCount:
            accounting.wasmToBrowserStorageRequestCount.toString(),
    });

const requireEnvironmentPath = (
    environmentVariable: string,
    label: string,
): string => {
    const value = process.env[environmentVariable];
    if (value === undefined || value.length === 0 || !path.isAbsolute(value)) {
        throw new Error(`${label} must be supplied as an absolute path.`);
    }
    return path.resolve(value);
};

const releaseEvidenceOwners = async (input: {
    fixture: Awaited<
        ReturnType<typeof openCompactPublicKeyProductionGenerationFixture>
    >;
    operationFailure?: unknown;
    stores: ReadonlyMap<string, FileBackedCommonProofExternalMemory>;
}): Promise<void> => {
    const cleanupFailures: unknown[] = [];
    try {
        await input.fixture.close();
    } catch (error) {
        cleanupFailures.push(error);
    }
    for (const storage of [...input.stores.values()].reverse()) {
        try {
            await storage.close();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CompactPublicKeyWasmEvidenceCleanupError(
            input.operationFailure,
            Object.freeze([...cleanupFailures]),
        );
    }
};

describe('Compact public-key scalar WASM proof evidence', () => {
    it('generates canonical reference bytes and verifies the same bytes in a fresh scalar instance', async () => {
        const evidencePath = requireEnvironmentPath(
            compactPublicKeyWasmProofEvidenceOutputPathEnvironmentVariable,
            'The compact public-key scalar WASM evidence output path',
        );
        const temporaryDirectoryPath = requireEnvironmentPath(
            compactPublicKeyWasmProofEvidenceTemporaryDirectoryEnvironmentVariable,
            'The compact public-key scalar WASM temporary directory',
        );
        const wasmBytes = await readFile(wasmArtifactPath);
        const rawWasmSha256Hex = createHash('sha256')
            .update(wasmBytes)
            .digest('hex');
        const normalizedWasmSha256Hex = createHash('sha256')
            .update(normalizeTranscriptCoreKernelBytesForHash(wasmBytes))
            .digest('hex');
        const fixtureStartedAt = performance.now();
        const fixture = await openCompactPublicKeyProductionGenerationFixture({
            expectedKernelSha256Hex: normalizedWasmSha256Hex,
        });
        const fixtureDurationMilliseconds =
            performance.now() - fixtureStartedAt;
        const stores = new Map<
            'cfw' | 'responseTrees',
            FileBackedCommonProofExternalMemory
        >();
        let generated: GeneratedCompactPublicKeyReferenceProof | undefined;
        let operationFailure: unknown;
        let generationProgress: ProgressObservation | undefined;
        let storageEvidence:
            | Readonly<
                  Record<
                      'cfw' | 'responseTrees',
                      Readonly<{
                          logical: Readonly<Record<string, string>>;
                          physical: Readonly<Record<string, number | string>>;
                      }>
                  >
              >
            | undefined;
        try {
            const progress = beginProgressObservation({
                label: 'Compact public-key scalar WASM generation',
            });
            generated = await generateCompactPublicKeyReferenceInClosedWorker({
                checkpointLineageIdentifier: new Uint8Array(32).fill(0x71),
                kernel: fixture.kernel,
                maximumWorkUnitCountPerPoll,
                openExternalMemory: async ({
                    runtimeBindingHash,
                    storageOwner,
                }) => {
                    if (stores.has(storageOwner)) {
                        throw new Error(
                            `Compact public-key generation reopened storage owner ${storageOwner}.`,
                        );
                    }
                    const storage =
                        await openFileBackedCommonProofExternalMemory({
                            directoryPath: path.join(
                                temporaryDirectoryPath,
                                storageOwner,
                            ),
                            runtimeBindingHash,
                        });
                    stores.set(storageOwner, storage);
                    return storage;
                },
                orderedPublicRandomnessCommitmentObjects:
                    fixture.orderedPublicRandomnessCommitmentObjects,
                orderedPublicRandomnessRevealObjects:
                    fixture.orderedPublicRandomnessRevealObjects,
                orderedSetupIntentObjects: fixture.orderedSetupIntentObjects,
                productionOperationIdentifiers:
                    fixture.productionOperationIdentifiers,
                setupIntentObject: fixture.setupIntentObject,
                workerKernel: fixture.workerKernel,
                yieldControl: progress.yieldControl,
            });
            generationProgress = progress.finish();
            expect([...stores.keys()].sort()).toEqual(['cfw', 'responseTrees']);
            for (const storageOwner of ['cfw', 'responseTrees'] as const) {
                const storage = stores.get(storageOwner);
                expect(storage).toBeDefined();
                const logical = storage!.copyLogicalUsage();
                const kernelUsage =
                    generated.externalMemoryAccounting[storageOwner]
                        .actualUsage;
                expect(logical).toEqual(kernelUsage);
                expect(
                    generated.externalMemoryAccounting[storageOwner]
                        .browserStorage,
                ).toBeUndefined();
                const physical = storage!.copyPhysicalAccounting();
                expect(physical.currentDeclaredByteLength).toBe(0n);
                expect(physical.liveObjectCount).toBe(0);
            }
            storageEvidence = Object.freeze({
                cfw: Object.freeze({
                    logical: logicalUsageRecord(
                        stores.get('cfw')!.copyLogicalUsage(),
                    ),
                    physical: physicalAccountingRecord(
                        stores.get('cfw')!.copyPhysicalAccounting(),
                    ),
                }),
                responseTrees: Object.freeze({
                    logical: logicalUsageRecord(
                        stores.get('responseTrees')!.copyLogicalUsage(),
                    ),
                    physical: physicalAccountingRecord(
                        stores.get('responseTrees')!.copyPhysicalAccounting(),
                    ),
                }),
            });
        } catch (error) {
            operationFailure = error;
            console.error(
                `Compact public-key scalar WASM generation failure: ${JSON.stringify(evidenceFailureRecord(error))}`,
            );
        }
        await releaseEvidenceOwners({
            fixture,
            ...(operationFailure === undefined ? {} : { operationFailure }),
            stores,
        });
        if (operationFailure !== undefined) {
            if (operationFailure instanceof Error) {
                throw operationFailure;
            }
            throw new CompactPublicKeyWasmEvidenceNonErrorFailure(
                operationFailure,
            );
        }
        if (
            generated === undefined ||
            generationProgress === undefined ||
            storageEvidence === undefined
        ) {
            throw new Error(
                'Compact public-key scalar WASM generation returned incomplete evidence.',
            );
        }

        try {
            const proofSha512Hex = sha512Hex(generated.canonicalProofBytes);
            const publicInputSha512Hex = sha512Hex(
                generated.canonicalPublicInputBytes,
            );
            const observedSafeBoundaryOrdinals = [
                ...generated.observedSafeBoundaryOrdinals,
            ];
            expect(observedSafeBoundaryOrdinals.length).toBeGreaterThan(0);
            expect(
                [...observedSafeBoundaryOrdinals].sort(
                    (left, right) => left - right,
                ),
            ).toEqual(observedSafeBoundaryOrdinals);
            expect(new Set(observedSafeBoundaryOrdinals).size).toBe(
                observedSafeBoundaryOrdinals.length,
            );
            const artifactEvidence = Object.freeze({
                classification: 'scalar release WASM development evidence',
                normalizedSha256Hex: normalizedWasmSha256Hex,
                rawSha256Hex: rawWasmSha256Hex,
            });
            const generationEvidence = Object.freeze({
                canonicalProof: Object.freeze({
                    byteLength: generated.canonicalProofBytes.byteLength,
                    sha512Hex: proofSha512Hex,
                }),
                canonicalPublicInput: Object.freeze({
                    byteLength: generated.canonicalPublicInputBytes.byteLength,
                    sha512Hex: publicInputSha512Hex,
                }),
                maximumWorkUnitCountPerPoll,
                observedSafeBoundaryOrdinals,
                progress: generationProgress,
                storage: storageEvidence,
                transportBindings: Object.freeze({
                    applicationStatementHash: bytesToHex(
                        generated.transportBindings.applicationStatementHash,
                    ),
                    manifestHash: bytesToHex(
                        generated.transportBindings.manifestHash,
                    ),
                    relationPlanHash: bytesToHex(
                        generated.transportBindings.relationPlanHash,
                    ),
                    suiteIdentifier: bytesToHex(
                        generated.transportBindings.suiteIdentifier,
                    ),
                }),
                worker: workerAccountingRecord(
                    generated.externalMemoryAccounting.worker,
                ),
            });
            const generationEvidencePath = path.join(
                path.dirname(evidencePath),
                `${path.basename(evidencePath, path.extname(evidencePath))}-generation.json`,
            );
            await mkdir(path.dirname(evidencePath), { recursive: true });
            await writeFile(
                generationEvidencePath,
                `${JSON.stringify(
                    {
                        artifact: artifactEvidence,
                        fixtureDurationMilliseconds,
                        generation: generationEvidence,
                        phase: 'generation complete; verification not claimed',
                        schemaVersion: 1,
                    },
                    undefined,
                    2,
                )}\n`,
                { encoding: 'utf8', flag: 'wx' },
            );

            const verifierRuntime =
                await instantiateTranscriptCoreKernelCommandRuntime(
                    pathToFileURL(wasmArtifactPath),
                    {
                        expectedKernelSha256Hex: normalizedWasmSha256Hex,
                    },
                );
            const verificationProgress = beginProgressObservation({
                label: 'Compact public-key scalar WASM verification',
                wasmMemoryByteLength: () =>
                    verifierRuntime.memory.buffer.byteLength,
            });
            const sameByteVerification =
                await verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                    verifierRuntime,
                    {
                        bindings: generated.transportBindings,
                        proofBytes: generated.canonicalProofBytes,
                        publicInputBytes: generated.canonicalPublicInputBytes,
                    },
                    {
                        maximumWorkUnitCountPerPoll,
                        yieldControl: verificationProgress.yieldControl,
                    },
                );
            const completedVerificationProgress = verificationProgress.finish();
            expect(sameByteVerification).toEqual({
                isValid: true,
                value: undefined,
            });

            const hostileProofBytes = generated.canonicalProofBytes.slice();
            hostileProofBytes[0] ^= 0x01;
            const hostileVerifierRuntime =
                await instantiateTranscriptCoreKernelCommandRuntime(
                    pathToFileURL(wasmArtifactPath),
                    {
                        expectedKernelSha256Hex: normalizedWasmSha256Hex,
                    },
                );
            let hostileVerification;
            try {
                hostileVerification =
                    await verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                        hostileVerifierRuntime,
                        {
                            bindings: generated.transportBindings,
                            proofBytes: hostileProofBytes,
                            publicInputBytes:
                                generated.canonicalPublicInputBytes,
                        },
                        { maximumWorkUnitCountPerPoll },
                    );
            } finally {
                hostileProofBytes.fill(0);
            }
            expect(hostileVerification.isValid).toBe(false);

            const evidenceRecord = Object.freeze({
                artifact: artifactEvidence,
                fixtureDurationMilliseconds,
                generation: generationEvidence,
                hostileVerification: Object.freeze({
                    isValid: hostileVerification.isValid,
                    ...('refusalReason' in hostileVerification
                        ? {
                              refusalReason: hostileVerification.refusalReason,
                          }
                        : {}),
                    mutation:
                        'The first canonical proof framing byte was changed.',
                }),
                sameByteVerification: Object.freeze({
                    freshWasmInstance: true,
                    isValid: sameByteVerification.isValid,
                    progress: completedVerificationProgress,
                    scope: 'Canonical transport plus complete algebraic CFW and WHIR verification; source correspondence and workflow capability are not claimed by this record.',
                }),
                schemaVersion: 1,
            });
            await writeFile(
                evidencePath,
                `${JSON.stringify(evidenceRecord, undefined, 2)}\n`,
                { encoding: 'utf8', flag: 'wx' },
            );
            console.log(
                `Compact public-key scalar WASM proof evidence completed with proof SHA-512 ${proofSha512Hex}.`,
            );
        } finally {
            generated.canonicalProofBytes.fill(0);
            generated.canonicalPublicInputBytes.fill(0);
            generated.transportBindings.applicationStatementHash.fill(0);
            generated.transportBindings.manifestHash.fill(0);
            generated.transportBindings.relationPlanHash.fill(0);
            generated.transportBindings.suiteIdentifier.fill(0);
        }
    });
});
