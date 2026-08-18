import {
    deriveCommonProofAttemptLogicalRecordPrefix,
    openCommonProofBrowserCustody,
    type CommonProofBrowserCustody,
} from '../../packages/protocol/src/runtime/common-proof-browser-custody.js';
import {
    openIndexedDbUntrustedStorageAdapter,
    type IndexedDbUntrustedStorageAdapter,
} from '../../packages/protocol/src/runtime/indexed-db-untrusted-storage-adapter.js';
import {
    openUntrustedStorageTransactionStore,
    type UntrustedStorageAuthenticatedRepairProtection,
    type UntrustedStorageExclusiveCapacityReservation,
} from '../../packages/protocol/src/runtime/untrusted-storage-transaction-store.js';
import {
    commonProofExternalMemoryRecordCount,
    commonProofLiveObjectCount,
    commonProofScratchByteLength,
} from '../../packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store/records.js';
import { commonProofStorageCapacityProfile } from '../../packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store.js';

import type {
    CompactCfwBrowserMemorySample,
    CompactCfwCommitLatencyDistribution,
    CompactCfwStorageDiagnosticSchedule,
    CompactCfwTransactionKind,
    DesktopBrowserCompactCfwStorageDiagnosticEvidence,
} from './compact-cfw-storage-diagnostic-evidence.js';
import {
    readCompactCfwStorageDiagnosticSchedule,
    runDesktopBrowserPrimitiveCase,
} from './desktop-browser-primitive-measurement-page.js';

import type { BrowserActionStorageWorkerKernel } from '#packages/types/src/index.js';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
    type CommonProofExternalMemoryOperation,
    type CommonProofExternalMemoryReadResult,
    type CommonProofExternalMemoryRequest,
} from '#packages/wasm/src/index.js';

const applicationStatementSchemaIdentifier = 0x1217;
const transactionLifetimeMilliseconds = 120_000;
const repairHeadAllowanceByteLength = 1_048_576;
const repairHeadAllowanceRecordCount = 8;
const hashByteLength = 64;
const identifierByteLength = 32;
const readVerificationPositionCount = 17;
const fnv64Prime = 0x0000_0100_0000_01b3n;
const unsigned64Mask = 0xffff_ffff_ffff_ffffn;

type LatencyCatalog = Record<CompactCfwTransactionKind, number[]>;

const binding = Object.freeze({
    actionContextHash: new Uint8Array(hashByteLength).fill(0x11),
    ceremonyContextHash: new Uint8Array(hashByteLength).fill(0x22),
    participantId: new Uint8Array(hashByteLength).fill(0x33),
    suiteId: new Uint8Array(hashByteLength).fill(0x44),
});
const actionRandomnessCommitment = new Uint8Array(hashByteLength).fill(0x55);
const commonProofRuntimeBindingHash = new Uint8Array(hashByteLength).fill(0x66);
const proofAttemptLineageIdentifier = new Uint8Array(identifierByteLength).fill(
    0x77,
);
const commonProofEnvironmentIdentifier = new Uint8Array(
    identifierByteLength,
).fill(0x99);
const runtimeBuildManifestHash = new Uint8Array(hashByteLength).fill(0xaa);
const diagnosticReservationByteLength =
    commonProofStorageCapacityProfile.maximumAdditionalStoredValueByteLength +
    commonProofStorageCapacityProfile.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength;

const copyToArrayBufferView = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => {
    const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
    copy.set(bytes);
    return copy;
};

const deleteDatabase = (databaseName: string): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(databaseName);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ??
                        new Error(
                            'Compact CFW diagnostic IndexedDB deletion failed.',
                        ),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () =>
                reject(
                    new Error(
                        'Compact CFW diagnostic IndexedDB deletion was blocked by a leaked connection.',
                    ),
                ),
            { once: true },
        );
    });

const copyStorageEstimate = async () => {
    const estimate = await navigator.storage.estimate();
    return Object.freeze({
        ...(estimate.quota === undefined ? {} : { quota: estimate.quota }),
        ...(estimate.usage === undefined ? {} : { usage: estimate.usage }),
    });
};

const copyJavascriptHeapByteLength = (): number | undefined => {
    const memory = (
        performance as Performance & {
            readonly memory?: { readonly usedJSHeapSize?: number };
        }
    ).memory;
    return memory?.usedJSHeapSize;
};

const captureMemoryAndStorageSample = async (
    sampleLabel: string,
): Promise<CompactCfwBrowserMemorySample> => {
    const javascriptHeapByteLength = copyJavascriptHeapByteLength();
    return Object.freeze({
        ...(javascriptHeapByteLength === undefined
            ? {}
            : { javascriptHeapByteLength }),
        sampleLabel,
        storageEstimate: await copyStorageEstimate(),
    });
};

const describeFailure = (failure: unknown): string =>
    failure instanceof Error
        ? `${failure.name}: ${failure.message}`
        : String(failure);

const createWorkerRepairProtection = async (
    workerKernel: BrowserActionStorageWorkerKernel,
): Promise<
    Readonly<{
        close(): Promise<void>;
        protection: UntrustedStorageAuthenticatedRepairProtection;
    }>
> => {
    const opened = await workerKernel.openActiveAuthenticatedRepairProtection({
        namespace: 'compact-cfw-storage-diagnostic',
        runtimeBuildManifestHash: runtimeBuildManifestHash.slice(),
    });
    const sessionIdentifier = opened.repairProtectionSessionIdentifier;
    return Object.freeze({
        close: () =>
            workerKernel.closeAuthenticatedRepairProtection(sessionIdentifier),
        protection: Object.freeze({
            deriveDigest: (sealedHeadBytes: Uint8Array) =>
                workerKernel.deriveAuthenticatedRepairHeadDigest({
                    repairProtectionSessionIdentifier: sessionIdentifier,
                    sealedHeadBytes: copyToArrayBufferView(sealedHeadBytes),
                }),
            open: (sealedHeadBytes: Uint8Array) =>
                workerKernel.openAuthenticatedRepairHead({
                    canonicalEnvelope: copyToArrayBufferView(sealedHeadBytes),
                    repairProtectionSessionIdentifier: sessionIdentifier,
                }),
            repairIdentity: opened.repairIdentity.slice(),
            seal: (headPlaintext: Uint8Array) =>
                workerKernel.sealAuthenticatedRepairHead({
                    plaintext: copyToArrayBufferView(headPlaintext),
                    repairProtectionSessionIdentifier: sessionIdentifier,
                }),
        }),
    });
};

const percentile = (
    sortedValues: readonly number[],
    fraction: number,
): number => {
    const index = Math.min(
        sortedValues.length - 1,
        Math.max(0, Math.ceil(fraction * sortedValues.length) - 1),
    );
    return sortedValues[index] ?? 0;
};

const summarizeLatencies = (
    values: readonly number[],
): CompactCfwCommitLatencyDistribution => {
    if (values.length === 0 || values.some((value) => value < 0)) {
        throw new Error(
            'Compact CFW diagnostic cannot summarize an empty or negative latency sample.',
        );
    }
    const sortedValues = [...values].sort((left, right) => left - right);
    const totalMilliseconds = values.reduce((total, value) => total + value, 0);
    return Object.freeze({
        count: values.length,
        maximumMilliseconds: sortedValues[sortedValues.length - 1] ?? 0,
        meanMilliseconds: totalMilliseconds / values.length,
        minimumMilliseconds: sortedValues[0] ?? 0,
        percentile50Milliseconds: percentile(sortedValues, 0.5),
        percentile90Milliseconds: percentile(sortedValues, 0.9),
        percentile95Milliseconds: percentile(sortedValues, 0.95),
        percentile99Milliseconds: percentile(sortedValues, 0.99),
        totalMilliseconds,
    });
};

const makeObjectPattern = (
    objectOrdinal: number,
    byteLength: number,
): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(new ArrayBuffer(byteLength));
    for (let byteOrdinal = 0; byteOrdinal < byteLength; byteOrdinal += 1) {
        bytes[byteOrdinal] =
            (byteOrdinal * 37 + objectOrdinal * 17 + 11) & 0xff;
    }
    return bytes;
};

const expectedPatternByte = (
    objectOrdinal: number,
    absoluteByteOffset: number,
): number => (absoluteByteOffset * 37 + objectOrdinal * 17 + 11) & 0xff;

const mixChecksum = (checksum: bigint, value: number): bigint =>
    ((checksum ^ BigInt(value >>> 0)) * fnv64Prime) & unsigned64Mask;

const verifyReadResult = (
    result: CommonProofExternalMemoryReadResult,
    expectedObjectOrdinal: number,
    expectedOffset: number,
    checksum: bigint,
): bigint => {
    if (
        result.objectOrdinal !== expectedObjectOrdinal ||
        result.offset !== BigInt(expectedOffset) ||
        result.bytes.byteLength === 0
    ) {
        throw new Error(
            'Compact CFW diagnostic received a mismatched storage read.',
        );
    }
    let nextChecksum = mixChecksum(checksum, expectedObjectOrdinal);
    nextChecksum = mixChecksum(nextChecksum, expectedOffset);
    nextChecksum = mixChecksum(nextChecksum, result.bytes.byteLength);
    const finalByteOrdinal = result.bytes.byteLength - 1;
    for (
        let positionOrdinal = 0;
        positionOrdinal < readVerificationPositionCount;
        positionOrdinal += 1
    ) {
        const byteOrdinal = Math.floor(
            (finalByteOrdinal * positionOrdinal) /
                (readVerificationPositionCount - 1),
        );
        const observed = result.bytes[byteOrdinal];
        const expected = expectedPatternByte(
            expectedObjectOrdinal,
            expectedOffset + byteOrdinal,
        );
        if (observed !== expected) {
            throw new Error(
                `Compact CFW diagnostic read changed object ${String(expectedObjectOrdinal)} at byte ${String(expectedOffset + byteOrdinal)}.`,
            );
        }
        nextChecksum = mixChecksum(nextChecksum, observed);
    }
    return nextChecksum;
};

const createRequestFactory = (
    schedule: CompactCfwStorageDiagnosticSchedule,
) => {
    let requestSequence = 0n;
    return (
        operation: CommonProofExternalMemoryOperation,
    ): CommonProofExternalMemoryRequest => {
        requestSequence += 1n;
        const requestDigest = new Uint8Array(hashByteLength);
        new DataView(requestDigest.buffer).setBigUint64(
            0,
            requestSequence,
            true,
        );
        return Object.freeze({
            maximumOperationCount: 1,
            maximumPayloadByteLength: BigInt(schedule.streamChunkByteLength),
            operations: Object.freeze([operation]),
            requestDigest,
            requestSequence,
            runtimeBindingHash: commonProofRuntimeBindingHash.slice(),
        });
    };
};

const createOperation = (
    objectOrdinal: number,
    exactByteLength: number,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        exactByteLength: BigInt(exactByteLength),
        objectOrdinal,
        operationIndex: 0,
        operationKind: 'create',
        protection: 'secret-authenticated-encryption',
    });

const appendOperation = (
    objectOrdinal: number,
    expectedOffset: number,
    bytes: Uint8Array<ArrayBuffer>,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        bytes,
        expectedOffset: BigInt(expectedOffset),
        objectOrdinal,
        operationIndex: 0,
        operationKind: 'append',
    });

const sealOperation = (
    objectOrdinal: number,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        objectOrdinal,
        operationIndex: 0,
        operationKind: 'seal',
    });

const readOperation = (
    objectOrdinal: number,
    offset: number,
    byteLength: number,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        byteLength,
        objectOrdinal,
        offset: BigInt(offset),
        operationIndex: 0,
        operationKind: 'read',
    });

const deleteOperation = (
    objectOrdinal: number,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        objectOrdinal,
        operationIndex: 0,
        operationKind: 'delete',
    });

const executeStorageSchedule = async (input: {
    custody: CommonProofBrowserCustody;
    memoryAndStorageSamples: CompactCfwBrowserMemorySample[];
    schedule: CompactCfwStorageDiagnosticSchedule;
}): Promise<
    Readonly<{
        commitLatencyByTransactionKind: Readonly<
            Record<
                CompactCfwTransactionKind,
                CompactCfwCommitLatencyDistribution
            >
        >;
        observedReadByteLength: number;
        observedReadChecksumHex: string;
        observedTransactionCount: number;
        observedWrittenByteLength: number;
    }>
> => {
    const latencyCatalog: LatencyCatalog = {
        append: [],
        create: [],
        delete: [],
        read: [],
        seal: [],
    };
    const makeRequest = createRequestFactory(input.schedule);
    let observedTransactionCount = 0;
    let observedWrittenByteLength = 0;
    let observedReadByteLength = 0;
    let observedReadChecksum = 0xcbf2_9ce4_8422_2325n;

    const execute = async (
        transactionKind: CompactCfwTransactionKind,
        operation: CommonProofExternalMemoryOperation,
    ): Promise<readonly CommonProofExternalMemoryReadResult[]> => {
        const request = makeRequest(operation);
        const startedAt = performance.now();
        try {
            const results =
                await input.custody.externalMemory.executeTransaction(request);
            latencyCatalog[transactionKind].push(performance.now() - startedAt);
            observedTransactionCount += 1;
            if (observedTransactionCount % 128 === 0) {
                console.info(
                    `Compact CFW storage diagnostic completed ${String(observedTransactionCount)} of ${String(input.schedule.totalTransactionCount)} transactions.`,
                );
            }
            return results;
        } finally {
            request.requestDigest.fill(0);
            request.runtimeBindingHash.fill(0);
        }
    };

    const readObjectChunk = async (
        objectOrdinal: number,
        byteOffset: number,
        byteLength: number,
    ): Promise<void> => {
        const results = await execute(
            'read',
            readOperation(objectOrdinal, byteOffset, byteLength),
        );
        if (results.length !== 1 || results[0] === undefined) {
            throw new Error(
                'Compact CFW diagnostic storage read returned the wrong result count.',
            );
        }
        observedReadChecksum = verifyReadResult(
            results[0],
            objectOrdinal,
            byteOffset,
            observedReadChecksum,
        );
        observedReadByteLength += results[0].bytes.byteLength;
        results[0].bytes.fill(0);
    };

    const firstRound = input.schedule.rounds[0];
    if (firstRound === undefined) {
        throw new Error('Compact CFW diagnostic schedule has no first round.');
    }
    const firstRoundPatterns: Uint8Array<ArrayBuffer>[] = [];
    for (
        let matrixOrdinal = 0;
        matrixOrdinal < input.schedule.matrixCount;
        matrixOrdinal += 1
    ) {
        await execute(
            'create',
            createOperation(matrixOrdinal, firstRound.outputObjectByteLength),
        );
        firstRoundPatterns.push(
            makeObjectPattern(
                matrixOrdinal,
                Math.min(
                    firstRound.outputObjectByteLength,
                    input.schedule.streamChunkByteLength,
                ),
            ),
        );
    }
    for (
        let byteOffset = 0;
        byteOffset < firstRound.outputObjectByteLength;
        byteOffset += input.schedule.streamChunkByteLength
    ) {
        const chunkByteLength = Math.min(
            input.schedule.streamChunkByteLength,
            firstRound.outputObjectByteLength - byteOffset,
        );
        for (
            let matrixOrdinal = 0;
            matrixOrdinal < input.schedule.matrixCount;
            matrixOrdinal += 1
        ) {
            const bytes = firstRoundPatterns[matrixOrdinal]?.slice(
                0,
                chunkByteLength,
            );
            if (bytes === undefined) {
                throw new Error(
                    'Compact CFW diagnostic lost a first-round payload pattern.',
                );
            }
            await execute(
                'append',
                appendOperation(matrixOrdinal, byteOffset, bytes),
            );
            observedWrittenByteLength += chunkByteLength;
            if (bytes.byteLength !== 0) {
                bytes.fill(0);
            }
        }
    }
    for (const pattern of firstRoundPatterns) {
        pattern.fill(0);
    }
    for (
        let matrixOrdinal = 0;
        matrixOrdinal < input.schedule.matrixCount;
        matrixOrdinal += 1
    ) {
        await execute('seal', sealOperation(matrixOrdinal));
    }
    input.memoryAndStorageSamples.push(
        await captureMemoryAndStorageSample('after-round-0'),
    );

    for (
        let roundOrdinal = 1;
        roundOrdinal < input.schedule.roundCount;
        roundOrdinal += 1
    ) {
        const precedingRound = input.schedule.rounds[roundOrdinal - 1];
        const round = input.schedule.rounds[roundOrdinal];
        if (precedingRound === undefined || round === undefined) {
            throw new Error(
                'Compact CFW diagnostic schedule lost a recursive round.',
            );
        }
        for (
            let byteOffset = 0;
            byteOffset < precedingRound.outputObjectByteLength;
            byteOffset += input.schedule.streamChunkByteLength
        ) {
            const chunkByteLength = Math.min(
                input.schedule.streamChunkByteLength,
                precedingRound.outputObjectByteLength - byteOffset,
            );
            for (
                let matrixOrdinal = 0;
                matrixOrdinal < input.schedule.matrixCount;
                matrixOrdinal += 1
            ) {
                const inputObjectOrdinal =
                    (roundOrdinal - 1) * input.schedule.matrixCount +
                    matrixOrdinal;
                await readObjectChunk(
                    inputObjectOrdinal,
                    byteOffset,
                    chunkByteLength,
                );
            }
        }

        for (
            let matrixOrdinal = 0;
            matrixOrdinal < input.schedule.matrixCount;
            matrixOrdinal += 1
        ) {
            const inputObjectOrdinal =
                (roundOrdinal - 1) * input.schedule.matrixCount + matrixOrdinal;
            const outputObjectOrdinal =
                roundOrdinal * input.schedule.matrixCount + matrixOrdinal;
            await execute(
                'create',
                createOperation(
                    outputObjectOrdinal,
                    round.outputObjectByteLength,
                ),
            );
            const outputPattern = makeObjectPattern(
                outputObjectOrdinal,
                Math.min(
                    round.outputObjectByteLength,
                    input.schedule.streamChunkByteLength,
                ),
            );
            let inputByteOffset = 0;
            let outputByteOffset = 0;
            while (inputByteOffset < precedingRound.outputObjectByteLength) {
                for (
                    let foldReadOrdinal = 0;
                    foldReadOrdinal < 2 &&
                    inputByteOffset < precedingRound.outputObjectByteLength;
                    foldReadOrdinal += 1
                ) {
                    const readByteLength = Math.min(
                        input.schedule.streamChunkByteLength,
                        precedingRound.outputObjectByteLength - inputByteOffset,
                    );
                    await readObjectChunk(
                        inputObjectOrdinal,
                        inputByteOffset,
                        readByteLength,
                    );
                    inputByteOffset += readByteLength;
                }
                const appendByteLength = Math.min(
                    input.schedule.streamChunkByteLength,
                    round.outputObjectByteLength - outputByteOffset,
                );
                const bytes = outputPattern.slice(0, appendByteLength);
                await execute(
                    'append',
                    appendOperation(
                        outputObjectOrdinal,
                        outputByteOffset,
                        bytes,
                    ),
                );
                observedWrittenByteLength += appendByteLength;
                outputByteOffset += appendByteLength;
                if (bytes.byteLength !== 0) {
                    bytes.fill(0);
                }
            }
            outputPattern.fill(0);
            if (outputByteOffset !== round.outputObjectByteLength) {
                throw new Error(
                    'Compact CFW diagnostic fold produced the wrong stored byte length.',
                );
            }
            await execute('seal', sealOperation(outputObjectOrdinal));
            await execute('delete', deleteOperation(inputObjectOrdinal));
        }
        input.memoryAndStorageSamples.push(
            await captureMemoryAndStorageSample(
                `after-round-${String(roundOrdinal)}`,
            ),
        );
        console.info(
            `Compact CFW storage diagnostic completed round ${String(roundOrdinal)} of ${String(input.schedule.roundCount - 1)}.`,
        );
    }

    const finalRoundOrdinal = input.schedule.roundCount - 1;
    for (
        let matrixOrdinal = 0;
        matrixOrdinal < input.schedule.matrixCount;
        matrixOrdinal += 1
    ) {
        await execute(
            'delete',
            deleteOperation(
                finalRoundOrdinal * input.schedule.matrixCount + matrixOrdinal,
            ),
        );
    }
    input.memoryAndStorageSamples.push(
        await captureMemoryAndStorageSample('after-final-deletes'),
    );

    return Object.freeze({
        commitLatencyByTransactionKind: Object.freeze({
            append: summarizeLatencies(latencyCatalog.append),
            create: summarizeLatencies(latencyCatalog.create),
            delete: summarizeLatencies(latencyCatalog.delete),
            read: summarizeLatencies(latencyCatalog.read),
            seal: summarizeLatencies(latencyCatalog.seal),
        }),
        observedReadByteLength,
        observedReadChecksumHex: observedReadChecksum
            .toString(16)
            .padStart(16, '0'),
        observedTransactionCount,
        observedWrittenByteLength,
    });
};

export const runDesktopBrowserCompactCfwStorageDiagnostic = async (input: {
    browserEngine: 'chromium';
    wasmUrl: string;
}): Promise<DesktopBrowserCompactCfwStorageDiagnosticEvidence> => {
    const response = await fetch(input.wasmUrl, { cache: 'no-store' });
    if (!response.ok) {
        throw new Error(
            `Compact CFW diagnostic WASM fetch failed with ${String(response.status)}.`,
        );
    }
    const wasmBytes = await response.arrayBuffer();
    if (wasmBytes.byteLength === 0) {
        throw new Error('Compact CFW diagnostic WASM artifact is empty.');
    }
    const schedule = await readCompactCfwStorageDiagnosticSchedule(wasmBytes);
    const primitiveCases = Object.freeze([
        await runDesktopBrowserPrimitiveCase(wasmBytes, 1),
        await runDesktopBrowserPrimitiveCase(wasmBytes, 2),
    ] as const);
    const randomBytes = crypto.getRandomValues(new Uint8Array(16));
    const databaseName = `sealed-lattice-compact-cfw-diagnostic-${Array.from(
        randomBytes,
        (byte) => byte.toString(16).padStart(2, '0'),
    ).join('')}`;
    randomBytes.fill(0);

    const memoryAndStorageSamples: CompactCfwBrowserMemorySample[] = [
        await captureMemoryAndStorageSample('before-open'),
    ];
    const initialEstimate = memoryAndStorageSamples[0]?.storageEstimate;
    if (
        initialEstimate?.quota !== undefined &&
        initialEstimate.usage !== undefined &&
        initialEstimate.quota - initialEstimate.usage <
            diagnosticReservationByteLength
    ) {
        throw new Error(
            'Compact CFW diagnostic origin quota cannot contain the production storage reservation.',
        );
    }

    let adapter: IndexedDbUntrustedStorageAdapter | undefined;
    let capacityReservation:
        | UntrustedStorageExclusiveCapacityReservation
        | undefined;
    let custody: CommonProofBrowserCustody | undefined;
    let workerKernel: BrowserActionStorageWorkerKernel | undefined;
    let repairProtection:
        | Awaited<ReturnType<typeof createWorkerRepairProtection>>
        | undefined;
    let workerRootActive = false;
    let custodyOwnsReservation = false;
    let evidence: DesktopBrowserCompactCfwStorageDiagnosticEvidence | undefined;
    let primaryFailure: unknown;
    const totalStartedAt = performance.now();
    try {
        workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        await workerKernel.createAndStageDeviceWrappingState({ binding });
        await workerKernel.commitStagedActionStorageRoot();
        workerRootActive = true;
        repairProtection = await createWorkerRepairProtection(workerKernel);
        adapter = await openIndexedDbUntrustedStorageAdapter({ databaseName });
        const openedStore = await openUntrustedStorageTransactionStore({
            adapter,
            authenticatedRepairProtection: repairProtection.protection,
            limits: {
                maximumActiveTransactionCount: 1,
                maximumLeaseByteLength:
                    commonProofStorageCapacityProfile.maximumLeaseByteLength,
                maximumLeaseCountPerTransaction:
                    commonProofStorageCapacityProfile.maximumLeaseCountPerTransaction,
                maximumOwnedRecordCount:
                    commonProofStorageCapacityProfile.maximumAdditionalOwnedRecordCount +
                    repairHeadAllowanceRecordCount,
                maximumStoredValueByteLength:
                    diagnosticReservationByteLength +
                    repairHeadAllowanceByteLength,
                maximumTransactionByteLength:
                    commonProofStorageCapacityProfile.maximumTransactionByteLength,
                maximumTransactionLifetimeMilliseconds:
                    transactionLifetimeMilliseconds,
            },
            namespace: 'compact-cfw-storage-diagnostic',
        });
        const attemptLogicalRecordPrefix =
            deriveCommonProofAttemptLogicalRecordPrefix({
                commonProofEnvironmentIdentifier,
                commonProofRuntimeBindingHash,
                proofAttemptLineageIdentifier,
            });
        capacityReservation = await openedStore.store.reserveExclusiveCapacity({
            initialLogicalRecordKeyPrefixes: [attemptLogicalRecordPrefix],
            maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength:
                commonProofStorageCapacityProfile.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength,
            maximumAdditionalOwnedRecordCount:
                commonProofStorageCapacityProfile.maximumAdditionalOwnedRecordCount,
            maximumAdditionalStoredValueByteLength:
                commonProofStorageCapacityProfile.maximumAdditionalStoredValueByteLength,
            maximumDeletionBatchRecordCount: 64,
        });
        custody = openCommonProofBrowserCustody({
            actionRandomnessCommitment,
            applicationStatementSchemaIdentifier,
            capacityReservation,
            commonProofEnvironmentIdentifier,
            commonProofRuntimeBindingHash,
            limits: {
                maximumExternalMemoryByteLength: commonProofScratchByteLength,
                maximumExternalMemoryObjectCount: commonProofLiveObjectCount,
                maximumExternalMemoryRecordCount:
                    commonProofExternalMemoryRecordCount,
                transactionLifetimeMilliseconds,
            },
            proofAttemptLineageIdentifier,
            store: openedStore.store,
            workerKernel,
        });
        custodyOwnsReservation = true;
        memoryAndStorageSamples.push(
            await captureMemoryAndStorageSample('after-open'),
        );
        const observed = await executeStorageSchedule({
            custody,
            memoryAndStorageSamples,
            schedule,
        });
        const physicalStorageAccountingBeforeCleanup =
            custody.copyPhysicalStorageAccounting();
        await custody.retire();
        const physicalStorageAccountingAfterCleanup =
            custody.copyPhysicalStorageAccounting();
        memoryAndStorageSamples.push(
            await captureMemoryAndStorageSample('after-custody-cleanup'),
        );
        evidence = Object.freeze({
            browserEngine: input.browserEngine,
            browserUserAgent: navigator.userAgent,
            commitLatencyByTransactionKind:
                observed.commitLatencyByTransactionKind,
            evidenceScope:
                'nonqualifying-desktop-chromium-development-diagnostic',
            memoryAndStorageSamples: Object.freeze(memoryAndStorageSamples),
            observedReadByteLength: observed.observedReadByteLength,
            observedReadChecksumHex: observed.observedReadChecksumHex,
            observedTransactionCount: observed.observedTransactionCount,
            observedWrittenByteLength: observed.observedWrittenByteLength,
            physicalStorageAccountingAfterCleanup,
            physicalStorageAccountingBeforeCleanup,
            primitiveCases,
            schedule,
            schemaVersion: 1,
            totalElapsedMilliseconds: performance.now() - totalStartedAt,
        });
    } catch (error) {
        primaryFailure = error;
    }

    const cleanupFailures: unknown[] = [];
    if (custody !== undefined && evidence === undefined) {
        try {
            await custody.retire();
        } catch (error) {
            cleanupFailures.push(error);
        }
    } else if (capacityReservation !== undefined && !custodyOwnsReservation) {
        try {
            await capacityReservation.release();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (repairProtection !== undefined) {
        try {
            await repairProtection.close();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (workerKernel !== undefined && workerRootActive) {
        try {
            await workerKernel.destroyActiveActionStorageRoot();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (adapter !== undefined) {
        try {
            await adapter.close();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    try {
        await deleteDatabase(databaseName);
    } catch (error) {
        cleanupFailures.push(error);
    }
    if (primaryFailure !== undefined || cleanupFailures.length !== 0) {
        throw new Error(
            `Compact CFW browser storage diagnostic failed: ${[
                ...(primaryFailure === undefined
                    ? []
                    : [`primary=${describeFailure(primaryFailure)}`]),
                ...cleanupFailures.map(
                    (failure, failureOrdinal) =>
                        `cleanup[${String(failureOrdinal)}]=${describeFailure(failure)}`,
                ),
            ].join('; ')}.`,
        );
    }
    if (evidence === undefined) {
        throw new Error(
            'Compact CFW browser storage diagnostic completed without evidence.',
        );
    }
    return evidence;
};
