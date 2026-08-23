import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { verifyCompactPublicKeyAlgebraicallyInClosedWorker } from '#packages/wasm/src/common-proof-worker-runtime';
import {
    generateCompactPublicKeyReferenceInClosedWorker,
    type CompactPublicKeyGenerationOperationObservation,
    type CompactPublicKeyGenerationOperationOwnerIdentifier,
    type CompactPublicKeyGenerationRuntimeStageIdentifier,
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
    lastYieldToCompletionMilliseconds?: number;
    maximumProcessMemory: ProcessMemoryObservation;
    maximumBetweenYieldIntervalMilliseconds: number;
    maximumCooperativeYieldIntervalMilliseconds: number;
    maximumWasmMemoryByteLength?: number;
    startToFirstYieldMilliseconds?: number;
    yieldCount: number;
}>;

type CompactPublicKeyGenerationOperationPollKind = NonNullable<
    CompactPublicKeyGenerationOperationObservation['pollKind']
>;
type CompactPublicKeyGenerationOperationStorageOwner = NonNullable<
    CompactPublicKeyGenerationOperationObservation['storageOwner']
>;

type GenerationOperationSummary = Readonly<{
    firstStartedAtOffsetMilliseconds: number;
    generationStageIdentifier?: CompactPublicKeyGenerationRuntimeStageIdentifier;
    lastFinishedAtOffsetMilliseconds: number;
    maximumCompletedWorkUnitCount?: number;
    maximumDurationMilliseconds: number;
    maximumFirstOrdinal?: number;
    minimumFirstOrdinal?: number;
    observationCount: number;
    operationOwnerIdentifier: CompactPublicKeyGenerationOperationOwnerIdentifier;
    pollKind?: CompactPublicKeyGenerationOperationPollKind;
    precedingGenerationStageIdentifier?: CompactPublicKeyGenerationRuntimeStageIdentifier;
    storageOwner?: CompactPublicKeyGenerationOperationStorageOwner;
    totalDurationMilliseconds: number;
}>;

type GenerationOperationTimingObservation = Readonly<{
    longestCompletedOperation: Readonly<{
        checkpointSafeBoundaryOrdinal?: number;
        completedWorkUnitCount?: number;
        durationMilliseconds: number;
        finishedAtOffsetMilliseconds: number;
        firstOrdinal?: number;
        generationStageIdentifier?: CompactPublicKeyGenerationRuntimeStageIdentifier;
        operationOwnerIdentifier: CompactPublicKeyGenerationOperationOwnerIdentifier;
        pollKind?: CompactPublicKeyGenerationOperationPollKind;
        precedingGenerationStageIdentifier?: CompactPublicKeyGenerationRuntimeStageIdentifier;
        startedAtOffsetMilliseconds: number;
        storageOwner?: CompactPublicKeyGenerationOperationStorageOwner;
    }>;
    operationSummaries: readonly GenerationOperationSummary[];
    totalObservationCount: number;
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
    startedAtMilliseconds?: number;
    wasmMemoryByteLength?: () => number;
}): Readonly<{
    finish(): ProgressObservation;
    yieldControl(): Promise<void>;
}> => {
    const startedAtMilliseconds =
        input.startedAtMilliseconds ?? performance.now();
    let activeSegmentStartedAtMilliseconds = startedAtMilliseconds;
    let lastReportAtMilliseconds = startedAtMilliseconds;
    let maximumMemory = observeProcessMemory();
    let maximumBetweenYieldIntervalMilliseconds = 0;
    let maximumCooperativeYieldIntervalMilliseconds = 0;
    let maximumWasmMemoryByteLength = input.wasmMemoryByteLength?.();
    let startToFirstYieldMilliseconds: number | undefined;
    let yieldCount = 0;

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
            const finishedAtMilliseconds = performance.now();
            const lastActiveIntervalMilliseconds =
                finishedAtMilliseconds - activeSegmentStartedAtMilliseconds;
            maximumCooperativeYieldIntervalMilliseconds = Math.max(
                maximumCooperativeYieldIntervalMilliseconds,
                lastActiveIntervalMilliseconds,
            );
            sampleMemory();
            return Object.freeze({
                durationMilliseconds:
                    finishedAtMilliseconds - startedAtMilliseconds,
                ...(yieldCount === 0
                    ? {}
                    : {
                          lastYieldToCompletionMilliseconds:
                              lastActiveIntervalMilliseconds,
                      }),
                maximumProcessMemory: maximumMemory,
                maximumBetweenYieldIntervalMilliseconds,
                maximumCooperativeYieldIntervalMilliseconds,
                ...(maximumWasmMemoryByteLength === undefined
                    ? {}
                    : { maximumWasmMemoryByteLength }),
                ...(startToFirstYieldMilliseconds === undefined
                    ? {}
                    : { startToFirstYieldMilliseconds }),
                yieldCount,
            });
        },
        yieldControl: async (): Promise<void> => {
            const yieldedAtMilliseconds = performance.now();
            const activeIntervalMilliseconds =
                yieldedAtMilliseconds - activeSegmentStartedAtMilliseconds;
            if (yieldCount === 0) {
                startToFirstYieldMilliseconds = activeIntervalMilliseconds;
            } else {
                maximumBetweenYieldIntervalMilliseconds = Math.max(
                    maximumBetweenYieldIntervalMilliseconds,
                    activeIntervalMilliseconds,
                );
            }
            maximumCooperativeYieldIntervalMilliseconds = Math.max(
                maximumCooperativeYieldIntervalMilliseconds,
                activeIntervalMilliseconds,
            );
            yieldCount += 1;
            if (yieldCount % memorySampleInterval === 0) {
                sampleMemory();
            }
            if (
                yieldedAtMilliseconds - lastReportAtMilliseconds >=
                progressReportIntervalMilliseconds
            ) {
                const memory = observeProcessMemory();
                console.log(
                    `${input.label} remains live after ${String(yieldCount)} bounded yields; process RSS ${String(memory.residentSet)} bytes.`,
                );
                lastReportAtMilliseconds = yieldedAtMilliseconds;
            }
            await new Promise<void>((resolve) => {
                setImmediate(resolve);
            });
            activeSegmentStartedAtMilliseconds = performance.now();
        },
    });
};

type MutableGenerationOperationSummary = {
    firstStartedAtOffsetMilliseconds: number;
    generationStageIdentifier?: CompactPublicKeyGenerationRuntimeStageIdentifier;
    lastFinishedAtOffsetMilliseconds: number;
    maximumCompletedWorkUnitCount?: number;
    maximumDurationMilliseconds: number;
    maximumFirstOrdinal?: number;
    minimumFirstOrdinal?: number;
    observationCount: number;
    operationOwnerIdentifier: CompactPublicKeyGenerationOperationOwnerIdentifier;
    pollKind?: CompactPublicKeyGenerationOperationPollKind;
    precedingGenerationStageIdentifier?: CompactPublicKeyGenerationRuntimeStageIdentifier;
    storageOwner?: CompactPublicKeyGenerationOperationStorageOwner;
    totalDurationMilliseconds: number;
};

const operationOwnerOrdinal: Readonly<
    Record<CompactPublicKeyGenerationOperationOwnerIdentifier, number>
> = Object.freeze({
    'setup-generation-authorization': 1,
    'reference-board-authorization': 2,
    'setup-intent-authorization': 3,
    'kernel-preparation': 4,
    'kernel-poll': 5,
    'storage-request-copy-and-decode': 6,
    'storage-open': 7,
    'storage-transaction': 8,
    'storage-response-encode-and-supply': 9,
    'storage-request-cleanup': 10,
    'external-memory-accounting-copy': 11,
    'transport-bindings-copy': 12,
    'canonical-public-input-copy': 13,
    'canonical-proof-copy': 14,
    'selected-suite-release': 15,
    'kernel-release': 16,
    'kernel-cancellation': 17,
});

const generationStageOrdinal: Readonly<
    Record<CompactPublicKeyGenerationRuntimeStageIdentifier, number>
> = Object.freeze({
    'source-loading': 1,
    'family-materialization': 2,
    'post-lookup-response': 3,
    'cross-epoch-response': 4,
    cfw: 5,
    'pre-challenge-whir-sumcheck': 6,
    'pre-challenge-whir-code-switch': 7,
    'pre-challenge-whir-next-sumcheck-preparation': 8,
    'pre-challenge-whir-base-fresh-response': 9,
    'pre-challenge-whir-base-blinded-response': 10,
    'main-whir-initial-preparation': 11,
    'main-whir-sumcheck': 12,
    'main-whir-code-switch': 13,
    'main-whir-next-sumcheck-preparation': 14,
    'main-whir-base-fresh-response': 15,
    'main-whir-base-blinded-response': 16,
});

const pollKindOrdinal: Readonly<
    Record<CompactPublicKeyGenerationOperationPollKind, number>
> = Object.freeze({
    progress: 1,
    'storage-request-ready': 2,
    complete: 3,
});

const storageOwnerOrdinal: Readonly<
    Record<CompactPublicKeyGenerationOperationStorageOwner, number>
> = Object.freeze({
    responseTrees: 1,
    cfw: 2,
});

const generationOperationSummaryKey = (
    observation: CompactPublicKeyGenerationOperationObservation,
): number => {
    const pollKind =
        observation.pollKind === undefined
            ? 0
            : pollKindOrdinal[observation.pollKind];
    const generationStage =
        observation.generationStageIdentifier === undefined
            ? 0
            : generationStageOrdinal[observation.generationStageIdentifier];
    const precedingGenerationStage =
        observation.precedingGenerationStageIdentifier === undefined
            ? 0
            : generationStageOrdinal[
                  observation.precedingGenerationStageIdentifier
              ];
    const storageOwner =
        observation.storageOwner === undefined
            ? 0
            : storageOwnerOrdinal[observation.storageOwner];
    const ownerAndPollOrdinal =
        operationOwnerOrdinal[observation.operationOwnerIdentifier] * 4 +
        pollKind;
    const ownerPollAndStageOrdinal = ownerAndPollOrdinal * 17 + generationStage;
    const ownerPollAndBothStagesOrdinal =
        ownerPollAndStageOrdinal * 17 + precedingGenerationStage;
    return ownerPollAndBothStagesOrdinal * 3 + storageOwner;
};

const beginGenerationOperationTimingObservation = (input: {
    startedAtMilliseconds: number;
}): Readonly<{
    finish(): GenerationOperationTimingObservation;
    observeOperation(
        observation: CompactPublicKeyGenerationOperationObservation,
    ): void;
}> => {
    const summaries = new Map<number, MutableGenerationOperationSummary>();
    let longestCompletedOperation:
        | GenerationOperationTimingObservation['longestCompletedOperation']
        | undefined;
    let totalObservationCount = 0;

    return Object.freeze({
        finish: (): GenerationOperationTimingObservation => {
            if (longestCompletedOperation === undefined) {
                throw new Error(
                    'Compact public-key generation emitted no operation timing observations.',
                );
            }
            const operationSummaries = [...summaries.entries()]
                .sort(([leftKey], [rightKey]) => leftKey - rightKey)
                .map(([, summary]) => Object.freeze({ ...summary }));
            return Object.freeze({
                longestCompletedOperation,
                operationSummaries: Object.freeze(operationSummaries),
                totalObservationCount,
            });
        },
        observeOperation: (
            observation: CompactPublicKeyGenerationOperationObservation,
        ): void => {
            const startedAtOffsetMilliseconds =
                observation.startedAtMilliseconds - input.startedAtMilliseconds;
            const finishedAtOffsetMilliseconds =
                observation.finishedAtMilliseconds -
                input.startedAtMilliseconds;
            const summaryKey = generationOperationSummaryKey(observation);
            const existingSummary = summaries.get(summaryKey);
            if (existingSummary === undefined) {
                summaries.set(summaryKey, {
                    firstStartedAtOffsetMilliseconds:
                        startedAtOffsetMilliseconds,
                    ...(observation.generationStageIdentifier === undefined
                        ? {}
                        : {
                              generationStageIdentifier:
                                  observation.generationStageIdentifier,
                          }),
                    lastFinishedAtOffsetMilliseconds:
                        finishedAtOffsetMilliseconds,
                    ...(observation.completedWorkUnitCount === undefined
                        ? {}
                        : {
                              maximumCompletedWorkUnitCount:
                                  observation.completedWorkUnitCount,
                          }),
                    maximumDurationMilliseconds:
                        observation.durationMilliseconds,
                    ...(observation.firstOrdinal === undefined
                        ? {}
                        : {
                              maximumFirstOrdinal: observation.firstOrdinal,
                              minimumFirstOrdinal: observation.firstOrdinal,
                          }),
                    observationCount: 1,
                    operationOwnerIdentifier:
                        observation.operationOwnerIdentifier,
                    ...(observation.pollKind === undefined
                        ? {}
                        : { pollKind: observation.pollKind }),
                    ...(observation.precedingGenerationStageIdentifier ===
                    undefined
                        ? {}
                        : {
                              precedingGenerationStageIdentifier:
                                  observation.precedingGenerationStageIdentifier,
                          }),
                    ...(observation.storageOwner === undefined
                        ? {}
                        : { storageOwner: observation.storageOwner }),
                    totalDurationMilliseconds: observation.durationMilliseconds,
                });
            } else {
                existingSummary.firstStartedAtOffsetMilliseconds = Math.min(
                    existingSummary.firstStartedAtOffsetMilliseconds,
                    startedAtOffsetMilliseconds,
                );
                existingSummary.lastFinishedAtOffsetMilliseconds = Math.max(
                    existingSummary.lastFinishedAtOffsetMilliseconds,
                    finishedAtOffsetMilliseconds,
                );
                existingSummary.maximumDurationMilliseconds = Math.max(
                    existingSummary.maximumDurationMilliseconds,
                    observation.durationMilliseconds,
                );
                existingSummary.observationCount += 1;
                existingSummary.totalDurationMilliseconds +=
                    observation.durationMilliseconds;
                if (observation.completedWorkUnitCount !== undefined) {
                    existingSummary.maximumCompletedWorkUnitCount = Math.max(
                        existingSummary.maximumCompletedWorkUnitCount ?? 0,
                        observation.completedWorkUnitCount,
                    );
                }
                if (observation.firstOrdinal !== undefined) {
                    existingSummary.minimumFirstOrdinal = Math.min(
                        existingSummary.minimumFirstOrdinal ??
                            observation.firstOrdinal,
                        observation.firstOrdinal,
                    );
                    existingSummary.maximumFirstOrdinal = Math.max(
                        existingSummary.maximumFirstOrdinal ??
                            observation.firstOrdinal,
                        observation.firstOrdinal,
                    );
                }
            }
            totalObservationCount += 1;
            if (
                longestCompletedOperation === undefined ||
                observation.durationMilliseconds >
                    longestCompletedOperation.durationMilliseconds
            ) {
                longestCompletedOperation = Object.freeze({
                    ...(observation.checkpointSafeBoundaryOrdinal === undefined
                        ? {}
                        : {
                              checkpointSafeBoundaryOrdinal:
                                  observation.checkpointSafeBoundaryOrdinal,
                          }),
                    ...(observation.completedWorkUnitCount === undefined
                        ? {}
                        : {
                              completedWorkUnitCount:
                                  observation.completedWorkUnitCount,
                          }),
                    durationMilliseconds: observation.durationMilliseconds,
                    finishedAtOffsetMilliseconds,
                    ...(observation.firstOrdinal === undefined
                        ? {}
                        : { firstOrdinal: observation.firstOrdinal }),
                    ...(observation.generationStageIdentifier === undefined
                        ? {}
                        : {
                              generationStageIdentifier:
                                  observation.generationStageIdentifier,
                          }),
                    operationOwnerIdentifier:
                        observation.operationOwnerIdentifier,
                    ...(observation.pollKind === undefined
                        ? {}
                        : { pollKind: observation.pollKind }),
                    ...(observation.precedingGenerationStageIdentifier ===
                    undefined
                        ? {}
                        : {
                              precedingGenerationStageIdentifier:
                                  observation.precedingGenerationStageIdentifier,
                          }),
                    startedAtOffsetMilliseconds,
                    ...(observation.storageOwner === undefined
                        ? {}
                        : { storageOwner: observation.storageOwner }),
                });
            }
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
        let generationOperationTiming:
            | GenerationOperationTimingObservation
            | undefined;
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
            const generationStartedAtMilliseconds = performance.now();
            const progress = beginProgressObservation({
                label: 'Compact public-key scalar WASM generation',
                startedAtMilliseconds: generationStartedAtMilliseconds,
            });
            const operationTiming = beginGenerationOperationTimingObservation({
                startedAtMilliseconds: generationStartedAtMilliseconds,
            });
            generated = await generateCompactPublicKeyReferenceInClosedWorker({
                checkpointLineageIdentifier: new Uint8Array(32).fill(0x71),
                kernel: fixture.kernel,
                maximumWorkUnitCountPerPoll,
                observeOperation: operationTiming.observeOperation,
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
            generationOperationTiming = operationTiming.finish();
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
            generationOperationTiming === undefined ||
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
                operationTiming: generationOperationTiming,
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
                        schemaVersion: 2,
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
                schemaVersion: 2,
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
